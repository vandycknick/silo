package jobs

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestFinalizerRunsForCancellationBeforeCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := New(ctx, 4)
	entered, hold := make(chan struct{}), make(chan struct{})
	_, err := r.Submit("hold", "vm", "user:1", func(context.Context, func(string)) error { close(entered); <-hold; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer close(hold)
	<-entered
	var called atomic.Bool
	finalized := make(chan struct{})
	_, err = r.SubmitResult("set", "vm", "user:1", func(context.Context, func(string)) (*Completion, error) { called.Store(true); return nil, nil }, func() { close(finalized) })
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-finalized:
	case <-time.After(5 * time.Second):
		t.Fatal("queued cancellation did not finalize")
	}
	if called.Load() {
		t.Fatal("cancelled queued callback ran")
	}
}
