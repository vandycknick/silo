package packet

import (
	"context"
	"sync"
)

// FlowTracker prevents new flows during shutdown and waits for active flows to
// finish before the session is forced closed.
type FlowTracker struct {
	mu       sync.Mutex
	draining bool
	active   int
	drained  chan struct{}
}

func NewFlowTracker() *FlowTracker {
	return &FlowTracker{drained: make(chan struct{})}
}

func (t *FlowTracker) Start() bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.draining {
		return false
	}
	t.active++
	return true
}

func (t *FlowTracker) Done() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active == 0 {
		return
	}
	t.active--
	if t.draining && t.active == 0 {
		close(t.drained)
	}
}

func (t *FlowTracker) BeginDrain() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.draining {
		return
	}
	t.draining = true
	if t.active == 0 {
		close(t.drained)
	}
}

func (t *FlowTracker) Wait(ctx context.Context) error {
	if t == nil {
		return nil
	}
	t.BeginDrain()
	select {
	case <-t.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
