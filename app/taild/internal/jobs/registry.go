// Package jobs owns the daemon operation lifetime, independently of sessions.
package jobs

import (
	"context"
	"sync"
)

// Registry starts empty on every restart. Phase 11 adds operation execution.
type Registry struct {
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
}

func (r *Registry) Wait(ctx context.Context) error {
	r.mu.Lock()
	r.closing = true
	r.mu.Unlock()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
