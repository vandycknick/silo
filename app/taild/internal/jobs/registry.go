// Package jobs owns the daemon operation lifetime, independently of sessions.
package jobs

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/metrics"
	"github.com/vandycknick/silo/app/taild/internal/state"
)

type Operation struct {
	ID        string             `json:"id"`
	Kind      string             `json:"kind"`
	VM        string             `json:"vm"`
	Principal identity.Principal `json:"principal"`
	State     string             `json:"state"`
	Started   time.Time          `json:"started"`
	Finished  *time.Time         `json:"finished,omitempty"`
	Progress  []string           `json:"progress"`
	Error     *authz.Error       `json:"error,omitempty"`
}
type entry struct {
	op      Operation
	changed chan struct{}
	cancel  context.CancelFunc
}
type lock struct {
	token chan struct{}
	refs  int
}

// Registry starts empty on restart; durable machine records are the recovery truth.
type Registry struct {
	Shutdown  *state.ShutdownGate
	Metrics   *metrics.Metrics
	mu        sync.Mutex
	closing   bool
	paused    bool
	Admission func() bool
	wg        sync.WaitGroup
	ctx       context.Context
	limit     int
	active    int
	entries   map[string]*entry
	locks     map[string]*lock
}

func New(ctx context.Context, limit int) *Registry {
	return &Registry{ctx: ctx, limit: limit, entries: make(map[string]*entry), locks: make(map[string]*lock)}
}

// newID encodes a 48-bit Unix millisecond timestamp plus 80 crypto-random bits,
// with the two leading zero bits required by the canonical ULID representation.
func newID(now time.Time) (string, error) {
	var raw [16]byte
	ms := now.UnixMilli()
	if ms < 0 || ms >= 1<<48 {
		return "", errors.New("ULID timestamp out of range")
	}
	for i := 5; i >= 0; i-- {
		raw[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", err
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var out [26]byte
	for i := range out {
		v := byte(0)
		for j := range 5 {
			bit := i*5 + j - 2
			v <<= 1
			if bit >= 0 {
				v |= (raw[bit/8] >> (7 - bit%8)) & 1
			}
		}
		out[i] = alphabet[v]
	}
	return "op_" + string(out[:]), nil
}

func clone(op Operation) Operation {
	op.Progress = slices.Clone(op.Progress)
	if op.Error != nil {
		e := *op.Error
		op.Error = &e
	}
	if op.Finished != nil {
		t := *op.Finished
		op.Finished = &t
	}
	return op
}
func (r *Registry) prune(now time.Time) {
	for id, e := range r.entries {
		if e.op.Finished != nil && now.Sub(*e.op.Finished) >= 24*time.Hour {
			delete(r.entries, id)
		}
	}
}
func (r *Registry) Submit(kind, vm string, owner identity.Principal, run func(context.Context, func(string)) error) (Operation, error) {
	return r.SubmitFinalized(kind, vm, owner, run, nil)
}

// SubmitFinalized releases admission resources before publishing completion,
// including rejection and cancellation before the callback can execute.
func (r *Registry) SubmitFinalized(kind, vm string, owner identity.Principal, run func(context.Context, func(string)) error, finalize func()) (op Operation, err error) {
	accepted := false
	defer func() {
		if !accepted && finalize != nil {
			finalize()
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.paused || r.Shutdown.Pending() || r.ctx.Err() != nil || r.Admission != nil && !r.Admission() {
		return Operation{}, &authz.Error{Code: "unavailable", Message: "daemon is shutting down", Exit: 9}
	}
	if r.active >= r.limit {
		return Operation{}, &authz.Error{Code: "limit", Message: "operation admission limit reached", Exit: 6}
	}
	id, err := newID(time.Now())
	if err != nil {
		return Operation{}, err
	}
	r.prune(time.Now())
	e := &entry{op: Operation{ID: id, Kind: kind, VM: vm, Principal: owner, State: "queued", Started: time.Now().UTC(), Progress: []string{}}, changed: make(chan struct{})}
	ctx, cancel := context.WithCancel(r.ctx)
	e.cancel = cancel
	r.entries[id] = e
	lockKey := vm
	if kind == "create" {
		lockKey = id
	}
	l := r.acquireLocked(lockKey)
	r.active++
	r.Metrics.Job(1)
	r.wg.Add(1)
	accepted = true
	go func() {
		defer r.wg.Done()
		defer cancel()
		var err error
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-l.token:
			r.update(e, func(op *Operation) { op.State = "running" })
			err = run(ctx, func(line string) {
				r.update(e, func(op *Operation) {
					if len(line) > 1024 {
						line = line[:1024]
					}
					if len(op.Progress) == 128 {
						op.Progress = op.Progress[1:]
					}
					op.Progress = append(op.Progress, line)
				})
			})
			if ctx.Err() != nil {
				err = &authz.Error{Code: "unavailable", Message: "daemon operation interrupted; inspect VM state", Exit: 9}
			}
			l.token <- struct{}{}
		}
		if finalize != nil {
			finalize()
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		e.op.State = "succeeded"
		if err != nil {
			e.op.State = "failed"
			var categorized *authz.Error
			if errors.As(err, &categorized) {
				failed := *categorized
				e.op.Error = &failed
			} else {
				e.op.Error = &authz.Error{Code: "unavailable", Message: "operation failed; inspect VM state", Exit: 9}
			}
		}
		now := time.Now().UTC()
		e.op.Finished = &now
		e.cancel = nil
		r.Metrics.Operation(kind, e.op.State, now.Sub(e.op.Started))
		r.Metrics.Job(-1)
		close(e.changed)
		e.changed = nil
		r.active--
		r.releaseLocked(lockKey, l)
	}()
	return clone(e.op), nil
}

// Per-VM locks are reference counted so a key disappears with its last user.
func (r *Registry) acquireLocked(key string) *lock {
	l := r.locks[key]
	if l == nil {
		l = &lock{token: make(chan struct{}, 1)}
		l.token <- struct{}{}
		r.locks[key] = l
	}
	l.refs++
	return l
}

func (r *Registry) releaseLocked(key string, l *lock) {
	l.refs--
	if l.refs == 0 {
		delete(r.locks, key)
	}
}
func (r *Registry) update(e *entry, f func(*Operation)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(&e.op)
	close(e.changed)
	e.changed = make(chan struct{})
}

// WithVM serializes the boot portion of create with operations on the newly
// durable ID, which does not exist when create is admitted by exact name.
func (r *Registry) WithVM(ctx context.Context, id string, run func() error) error {
	r.mu.Lock()
	l := r.acquireLocked(id)
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.releaseLocked(id, l)
		r.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.token:
		defer func() { l.token <- struct{}{} }()
		return run()
	}
}
func (r *Registry) List(peer identity.Peer) []Operation {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(time.Now())
	out := []Operation{}
	for _, e := range r.entries {
		if peer.Owns(e.op.Principal) {
			out = append(out, clone(e.op))
		}
	}
	slices.SortFunc(out, func(a, b Operation) int { return a.Started.Compare(b.Started) })
	return out
}

// Observe subscribes to state changes. Closing an observer never cancels work.
func (r *Registry) Observe(peer identity.Peer, id string) (Operation, <-chan struct{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(time.Now())
	e := r.entries[id]
	if e == nil || !peer.Owns(e.op.Principal) {
		return Operation{}, nil, &authz.Error{Code: "not_found", Message: "operation not found", Exit: 3}
	}
	return clone(e.op), e.changed, nil
}

func (r *Registry) Seal() {
	r.mu.Lock()
	r.closing = true
	r.mu.Unlock()
}
func (r *Registry) Resume() { r.mu.Lock(); r.paused = false; r.mu.Unlock() }

// InterruptIf cancels existing work without poisoning future admission after a
// cancelled host shutdown. Synchronous native work still requires real drain.
func (r *Registry) InterruptIf(shutdown func() bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !shutdown() {
		return
	}
	r.paused = true
	for _, e := range r.entries {
		if e.cancel != nil {
			e.cancel()
		}
	}
}
func (r *Registry) Wait(ctx context.Context) error {
	r.Seal()
	done := r.Drained()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Registry) Drained() <-chan struct{} {
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	return done
}
