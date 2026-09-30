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
}
type lock struct {
	token chan struct{}
	refs  int
}

// Registry starts empty on restart; durable machine records are the recovery truth.
type Registry struct {
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
	ctx     context.Context
	limit   int
	active  int
	entries map[string]*entry
	locks   map[string]*lock
}

func New(ctx context.Context, limit int) *Registry {
	return &Registry{ctx: ctx, limit: limit}
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
		for j := 0; j < 5; j++ {
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx == nil {
		r.ctx = context.Background()
	}
	if r.limit <= 0 {
		r.limit = 64
	}
	if r.closing || r.ctx.Err() != nil {
		return Operation{}, &authz.Error{Code: "unavailable", Message: "daemon is shutting down", Exit: 9}
	}
	if r.active >= r.limit {
		return Operation{}, &authz.Error{Code: "limit", Message: "operation admission limit reached", Exit: 6}
	}
	id, err := newID(time.Now())
	if err != nil {
		return Operation{}, err
	}
	if r.entries == nil {
		r.entries = make(map[string]*entry)
		r.locks = make(map[string]*lock)
	}
	r.prune(time.Now())
	e := &entry{op: Operation{ID: id, Kind: kind, VM: vm, Principal: owner, State: "queued", Started: time.Now().UTC(), Progress: []string{}}, changed: make(chan struct{})}
	r.entries[id] = e
	lockKey := vm
	if kind == "create" {
		lockKey = id
	}
	l := r.locks[lockKey]
	if l == nil {
		l = &lock{token: make(chan struct{}, 1)}
		l.token <- struct{}{}
		r.locks[lockKey] = l
	}
	l.refs++
	r.active++
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		var err error
		select {
		case <-r.ctx.Done():
			err = r.ctx.Err()
		case <-l.token:
			r.update(e, func(op *Operation) { op.State = "running" })
			err = run(r.ctx, func(line string) {
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
			l.token <- struct{}{}
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		e.op.State = "succeeded"
		if err != nil {
			e.op.State = "failed"
			var categorized *authz.Error
			if errors.As(err, &categorized) {
				copy := *categorized
				e.op.Error = &copy
			} else {
				e.op.Error = &authz.Error{Code: "unavailable", Message: "operation failed; inspect VM state", Exit: 9}
			}
		}
		now := time.Now().UTC()
		e.op.Finished = &now
		close(e.changed)
		e.changed = nil
		r.active--
		l.refs--
		if l.refs == 0 {
			delete(r.locks, lockKey)
		}
	}()
	return clone(e.op), nil
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
	l := r.locks[id]
	if l == nil {
		l = &lock{token: make(chan struct{}, 1)}
		l.token <- struct{}{}
		r.locks[id] = l
	}
	l.refs++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(r.locks, id)
		}
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
func (r *Registry) Wait(ctx context.Context) error {
	r.Seal()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
