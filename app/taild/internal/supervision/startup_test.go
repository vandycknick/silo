package supervision

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/units"
	"golang.org/x/sys/unix"
)

// Explicit ordered D-Bus domain messages, not a fake bus and not a claim of
// live login1 signal qualification. Sequence uses godbus's actual public type.
func orderedSignal(sequence dbus.Sequence, preparing bool) *dbus.Signal {
	return &dbus.Signal{Sender: ":1.42", Path: loginPath, Name: loginInterface + ".PrepareForShutdown", Sequence: sequence, Body: []any{preparing}}
}

func TestStartupSnapshotSupersedesHistoricalTrueFalse(t *testing.T) {
	order := startupOrder{sequence: 10, preparing: false}
	for _, sig := range []*dbus.Signal{orderedSignal(8, true), orderedSignal(9, false), orderedSignal(10, true)} {
		if _, accepted := order.accept(sig, ":1.42"); accepted {
			t.Fatal("historical shutdown replayed", sig.Sequence)
		}
	}
	if value, accepted := order.accept(orderedSignal(11, true), ":1.42"); !value || !accepted {
		t.Fatal("post-snapshot true discarded")
	}
	if _, accepted := order.accept(orderedSignal(12, true), ":1.42"); accepted {
		t.Fatal("duplicate true replayed")
	}
	if value, accepted := order.accept(orderedSignal(13, false), ":1.42"); value || !accepted {
		t.Fatal("post-snapshot false discarded")
	}
	if _, accepted := order.accept(orderedSignal(11, true), ":1.42"); accepted {
		t.Fatal("out-of-order historical true replayed")
	}
	foreign := orderedSignal(14, true)
	foreign.Sender = ":1.99"
	if _, accepted := order.accept(foreign, ":1.42"); accepted {
		t.Fatal("foreign sender accepted")
	}
}

func TestReceiptDeadlineAndMemorySealWhileStartupHelperRecoveryBlocked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := config.Defaults()
	c.Home = t.TempDir()
	c.Shutdown.StopBudget = units.Duration{Duration: 100 * time.Millisecond}
	fd, err := state.LockShutdownHelper(c.Home)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	recovery := make(chan error, 1)
	go func() { recovery <- state.WaitShutdownHelpers(ctx, c.Home) }()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	receipts := make(chan loginEvent, 4)
	i := &Inhibitor{owner: ":1.42", fd: writer, maxDelay: time.Second, receipts: receipts, snapshotSequence: 10}
	gate := &state.ShutdownGate{}
	registry := jobs.New(ctx, 2)
	registry.Shutdown = gate
	started, interrupted := make(chan struct{}), make(chan struct{})
	if _, err := registry.Submit("create", "waiting", "user:1", func(ctx context.Context, _ func(string)) error {
		close(started)
		<-ctx.Done()
		close(interrupted)
		return ctx.Err()
	}); err != nil {
		t.Fatal(err)
	}
	<-started
	events := i.admitEvents(ctx, c, false, gate, func() { registry.InterruptIf(func() bool { return true }) })
	receipts <- loginEvent{signal: orderedSignal(8, true), received: time.Now().Add(-time.Second)}
	receipts <- loginEvent{signal: orderedSignal(9, false), received: time.Now().Add(-time.Second)}
	// The actual deadline is already 50ms old when intake consumes this event.
	received := time.Now().Add(-50 * time.Millisecond)
	receipts <- loginEvent{signal: orderedSignal(11, true), received: received}
	select {
	case event := <-events:
		if event.signal.Sequence != 11 || !gate.Pending() || gate.Revision() != 1 {
			t.Fatal("history replayed or latch not authoritative")
		}
		deadline, ok := event.shutdown.Deadline()
		if !ok || !deadline.Equal(received.Add(100*time.Millisecond)) {
			t.Fatal("receipt window extended", deadline)
		}
	case <-ctx.Done():
		t.Fatal("event intake blocked on helper recovery")
	}
	select {
	case <-interrupted:
	case <-ctx.Done():
		t.Fatal("job not directly interrupted")
	}
	eof := make(chan error, 1)
	go func() { var b [1]byte; _, err := reader.Read(b[:]); eof <- err }()
	select {
	case err := <-eof:
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("FD held beyond receipt budget")
	}
	select {
	case err := <-recovery:
		t.Fatal("helper recovery was not blocked", err)
	default:
	}
	if !gate.Pending() {
		t.Fatal("deadline incorrectly cleared admission")
	}
	cancel()
	<-recovery
}
