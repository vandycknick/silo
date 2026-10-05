package supervision

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"golang.org/x/sys/unix"
)

const loginService = "org.freedesktop.login1"
const loginInterface = "org.freedesktop.login1.Manager"
const loginPath dbus.ObjectPath = "/org/freedesktop/login1"

type Inhibitor struct {
	conn              *dbus.Conn
	owner             string
	signals           chan *dbus.Signal
	mu                sync.Mutex
	fd                *os.File
	maxDelay          time.Duration
	budget            time.Duration
	subscribedAt      time.Time
	receipts          <-chan loginEvent
	snapshotSequence  dbus.Sequence
	current           shutdownEpisode
	timer             *time.Timer
	completedRevision uint64
	closed            bool
}

// Acquire uses the real system bus and authenticates its unique login1 owner.
// Subscribe first, acquire the FD, then read PreparingForShutdown to close the
// startup race. Callers must handle an already-preparing host immediately.
func Acquire(ctx context.Context, c config.Config) (*Inhibitor, bool, error) {
	conn, err := dbus.SystemBusPrivate(dbus.WithContext(ctx), dbus.WithSignalHandler(dbus.NewSequentialSignalHandler()))
	if err != nil {
		return nil, false, errors.New("system bus unavailable")
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if err = conn.Auth(nil); err != nil {
		return nil, false, errors.New("system bus authentication failed")
	}
	if err = conn.Hello(); err != nil {
		return nil, false, errors.New("system bus hello failed")
	}
	i := &Inhibitor{conn: conn, signals: make(chan *dbus.Signal, 32)}
	defer func() {
		if !ok {
			i.Release()
		}
	}()
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err = conn.BusObject().CallWithContext(call, "org.freedesktop.DBus.GetNameOwner", 0, loginService).Store(&i.owner); err != nil {
		return nil, false, errors.New("logind unavailable")
	}
	conn.Signal(i.signals)
	i.subscribedAt = time.Now()
	i.receipts = i.events(ctx)
	if err = conn.AddMatchSignalContext(call, dbus.WithMatchSender(i.owner), dbus.WithMatchObjectPath(loginPath), dbus.WithMatchInterface(loginInterface), dbus.WithMatchMember("PrepareForShutdown")); err != nil {
		return nil, false, errors.New("logind subscription failed")
	}
	if err = conn.AddMatchSignalContext(call, dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchInterface("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, loginService)); err != nil {
		return nil, false, errors.New("logind owner subscription failed")
	}
	var delay dbus.Variant
	if err = i.property(call, "InhibitDelayMaxUSec", &delay); err != nil {
		return nil, false, err
	}
	usec, valid := delay.Value().(uint64)
	if !valid || usec == 0 || usec > uint64(time.Hour/time.Microsecond) {
		return nil, false, errors.New("logind delay budget invalid")
	}
	i.maxDelay = time.Duration(usec) * time.Microsecond
	i.budget = StopBudget(c.Shutdown.StopBudget.Duration, i.maxDelay, c.Shutdown.Margin.Duration)
	if i.budget <= 0 {
		return nil, false, errors.New("logind delay window insufficient")
	}
	i.mu.Lock()
	i.current = shutdownEpisode{phase: episodeAcquiring, deadline: i.subscribedAt.Add(i.budget)}
	i.mu.Unlock()
	if err = i.reacquire(call); err != nil {
		return nil, false, err
	}
	preparing, sequence, err := i.preparingSnapshot(call)
	if err != nil {
		return nil, false, err
	}
	i.snapshotSequence = sequence
	i.mu.Lock()
	held := i.fd != nil
	if held && !preparing {
		i.current = shutdownEpisode{phase: episodeIdle, sequence: sequence}
		i.applyDeadlineLocked()
	}
	i.mu.Unlock()
	if !held {
		return nil, false, errors.New("logind acquisition exceeded shutdown delay window")
	}
	ok = true
	return i, preparing, nil
}
func (i *Inhibitor) property(ctx context.Context, name string, out *dbus.Variant) error {
	if err := i.conn.Object(i.owner, loginPath).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, loginInterface, name).Store(out); err != nil {
		return errors.New("logind property unavailable")
	}
	return nil
}
func (i *Inhibitor) Preparing(ctx context.Context) (bool, error) {
	b, _, err := i.preparingSnapshot(ctx)
	return b, err
}
func (i *Inhibitor) preparingSnapshot(ctx context.Context) (bool, dbus.Sequence, error) {
	var v dbus.Variant
	call := i.conn.Object(i.owner, loginPath).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, loginInterface, "PreparingForShutdown")
	if err := call.Store(&v); err != nil {
		return false, dbus.NoSequence, errors.New("logind shutdown property unavailable")
	}
	b, ok := v.Value().(bool)
	if !ok || call.ResponseSequence == dbus.NoSequence {
		return false, dbus.NoSequence, errors.New("logind shutdown property invalid")
	}
	return b, call.ResponseSequence, nil
}
func (i *Inhibitor) reacquire(ctx context.Context) error {
	i.mu.Lock()
	held := i.fd != nil
	i.mu.Unlock()
	if held {
		return nil
	}
	var fd dbus.UnixFD
	if err := i.conn.Object(i.owner, loginPath).CallWithContext(ctx, loginInterface+".Inhibit", 0, "shutdown", "silo-taild", "stop managed VMs", "delay").Store(&fd); err != nil {
		return errors.New("logind delay inhibitor denied")
	}
	file := os.NewFile(uintptr(fd), "logind-inhibitor")
	if file == nil {
		return errors.New("logind inhibitor FD invalid")
	}
	unix.CloseOnExec(int(fd))
	return i.installFD(ctx, file)
}
func (i *Inhibitor) Release() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closeFDLocked()
}
func (i *Inhibitor) Close() {
	i.mu.Lock()
	i.closed = true
	if i.current.cancel != nil {
		i.current.cancel()
	}
	if i.timer != nil {
		i.timer.Stop()
	}
	i.closeFDLocked()
	i.mu.Unlock()
	if i.conn != nil {
		_ = i.conn.Close()
	}
}

type loginEvent struct {
	signal   *dbus.Signal
	received time.Time
	shutdown context.Context
	cancel   context.CancelFunc
	revision uint64
}

// ownerChanged reports the bus announcing that login1 changed hands.
func (e loginEvent) ownerChanged() bool {
	sig := e.signal
	return sig != nil && sig.Sender == "org.freedesktop.DBus" && sig.Name == "org.freedesktop.DBus.NameOwnerChanged" && len(sig.Body) == 3 && sig.Body[0] == loginService
}

// Timestamp receipt independently of marker sync/recovery calls. Otherwise a
// queued signal could accidentally receive a fresh window when finally handled.
func (i *Inhibitor) events(ctx context.Context) <-chan loginEvent {
	out := make(chan loginEvent, 32)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-i.conn.Context().Done():
				return
			case sig, ok := <-i.signals:
				if !ok {
					return
				}
				event := loginEvent{signal: sig, received: time.Now()}
				select {
				case out <- event:
				case <-ctx.Done():
					return
				case <-i.conn.Context().Done():
					return
				}
			}
		}
	}()
	return out
}

func StopBudget(requested, maxDelay, margin time.Duration) time.Duration {
	return max(time.Duration(0), min(requested, maxDelay-margin))
}

// Sequence is the connection receive order, not the sender's serial number.
// The property reply supersedes all historical transitions through its sequence.
type startupOrder struct {
	sequence  dbus.Sequence
	preparing bool
}

func (o *startupOrder) accept(signal *dbus.Signal, owner string) (bool, bool) {
	if signal == nil || signal.Sender != owner || signal.Path != loginPath || signal.Name != loginInterface+".PrepareForShutdown" || len(signal.Body) != 1 || signal.Sequence <= o.sequence {
		return false, false
	}
	value, valid := signal.Body[0].(bool)
	if !valid {
		return false, false
	}
	o.sequence = signal.Sequence
	if value == o.preparing {
		return value, false
	}
	o.preparing = value
	return value, true
}

// admitEvents runs before any startup marker/helper recovery. Receipt arms FD
// release and seals/cancels process-local admission without doing filesystem I/O.
func (i *Inhibitor) admitEvents(ctx context.Context, preparing bool, gate *state.ShutdownGate, interrupt func()) <-chan loginEvent {
	out := make(chan loginEvent, 1)
	publish := func(event loginEvent) {
		select {
		case out <- event:
		default:
			select {
			case <-out:
			default:
			}
			out <- event
		}
	}
	arm := func(event loginEvent) loginEvent {
		episode := i.transition(ctx, event, true, i.budget, gate)
		event.shutdown, event.cancel, event.revision = episode.ctx, episode.cancel, episode.revision
		interrupt()
		return event
	}
	if preparing {
		event := arm(loginEvent{received: i.subscribedAt})
		publish(event)
	}
	go func() {
		defer close(out)
		order := startupOrder{sequence: i.snapshotSequence, preparing: preparing}
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-i.receipts:
				if !ok {
					return
				}
				ownerChange := event.ownerChanged()
				value, accepted := order.accept(event.signal, i.owner)
				if !accepted && !ownerChange {
					continue
				}
				if accepted {
					if value {
						event = arm(event)
					} else {
						i.transition(ctx, event, false, i.budget, gate)
					}
				}
				publish(event)
				if ownerChange {
					return
				}
			}
		}
	}()
	return out
}

func (i *Inhibitor) Start(ctx context.Context, c config.Config, r *runtime.Runtime, preparing bool, gate *state.ShutdownGate, interrupt func(), resume func(), jobsDrained func() <-chan struct{}, log *slog.Logger) {
	events := i.admitEvents(ctx, preparing, gate, interrupt)
	go i.watch(ctx, c, r, events, gate, resume, jobsDrained, log)
}

// Watch remains responsive to cancellation and bus loss even while a native
// call is blocked. FD release is independent of native completion.
func (i *Inhibitor) watch(ctx context.Context, c config.Config, r *runtime.Runtime, events <-chan loginEvent, gate *state.ShutdownGate, resume func(), jobsDrained func() <-chan struct{}, log *slog.Logger) {
	defer i.Close()
	coordinator := episodeCoordinator{}
	var acquisition <-chan error
	for {
		coordinator.retire()
		current := i.snapshot()
		// Restore inhibition independently of old native drain. The reply may
		// arrive in a different episode; installFD applies that current state.
		if acquisition == nil && i.needsFD() {
			result := make(chan error, 1)
			acquisition = result
			go func() {
				call, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				result <- i.reacquire(call)
			}()
		}
		if coordinator.canSweep(current) {
			coordinator.sweptRevision = current.revision
			coordinator.work = i.stopEpisode(ctx, c, r, current, gate, jobsDrained, log)
		} else if acquisition == nil && coordinator.canRecover(current) {
			// Cancellation of an episode that never swept still needs a fresh
			// job/helper drain. All older stop workers have already retired.
			call, cancel := context.WithTimeout(ctx, 2*time.Second)
			jobs := jobsDrained()
			select {
			case <-jobs:
			case <-call.Done():
				cancel()
				coordinator.work = jobs
				continue
			}
			pending, pe := i.Preparing(call)
			host, hostErr := SystemState(call)
			helperErr := state.WaitShutdownHelpers(call, c.Home)
			cancel()
			if pe != nil || hostErr != nil || helperErr != nil || host == "stopping" && !pending {
				log.Error("shutdown cancellation recovery failed; admission sealed")
				return
			}
			if !pending {
				cleared, clearError := i.recoverEpisode(c.Home, current, gate)
				if clearError != nil {
					log.Error("shutdown marker cleanup failed; admission sealed")
					return
				}
				if cleared {
					resume()
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-i.conn.Context().Done():
			log.Error("system bus lost; shutdown protection unavailable")
			return
		case <-coordinator.work:
			coordinator.retire()
		case err := <-acquisition:
			acquisition = nil
			if err != nil {
				log.Error("inhibitor reacquisition failed; admission remains sealed")
				return
			}
		case event, ok := <-events:
			if !ok {
				log.Error("system bus signals lost; shutdown protection unavailable")
				return
			}
			if event.ownerChanged() {
				log.Error("logind owner changed; shutdown protection unavailable")
				return
			}
		}
	}
}

func (i *Inhibitor) stopEpisode(parent context.Context, c config.Config, r *runtime.Runtime, episode shutdownEpisode, gate *state.ShutdownGate, jobsDrained func() <-chan struct{}, log *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := gate.Mark(c.Home); err != nil {
			log.Error("shutdown marker write failed; memory admission sealed and jobs cancelled; cross-process durable protection unavailable")
		}
		result, err := StopAll(episode.ctx, r)
		jobs := jobsDrained()
		firstDrained := result.Drained
		var secondDrained <-chan struct{}
		select {
		case <-jobs:
			current := i.snapshot()
			if episode.ctx.Err() == nil && current.phase == episodePreparing && current.revision == episode.revision {
				second, secondError := StopAll(episode.ctx, r)
				result.Issued += second.Issued
				result.Finished += second.Finished
				result.Failed += second.Failed
				secondDrained = second.Drained
				err = errors.Join(err, secondError)
			}
		case <-episode.ctx.Done():
			err = errors.Join(err, episode.ctx.Err())
		}
		i.completeStops(episode.revision)
		log.Info("host shutdown VM stops", "issued", result.Issued, "finished", result.Finished, "failed", result.Failed, "complete", err == nil)
		// Context expiration reports incomplete native work, but does not retire
		// that worker. Admission cannot recover until these channels really close.
		select {
		case <-firstDrained:
		case <-parent.Done():
			return
		}
		select {
		case <-jobs:
		case <-parent.Done():
			return
		}
		if secondDrained != nil {
			select {
			case <-secondDrained:
			case <-parent.Done():
				return
			}
		}
		if err := state.WaitShutdownHelpers(parent, c.Home); err != nil {
			return
		}
	}()
	return done
}
