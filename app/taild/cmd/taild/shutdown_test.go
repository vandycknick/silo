package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRuntimeCloseRequiresBothDrainsAndRemainingBudget(t *testing.T) {
	for _, test := range []struct {
		name         string
		session, job error
		expired      bool
	}{
		{"session-in-flight", context.DeadlineExceeded, nil, false},
		{"job-in-flight", nil, context.DeadlineExceeded, false},
		{"budget-exhausted", nil, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.expired {
				cancel()
			}
			called := false
			err := closeRuntimeAfterDrain(ctx, test.session, test.job, func() error { called = true; return nil })
			if called || !errors.Is(err, errRuntimeCleanupIncomplete) {
				t.Fatalf("close=%v cleanup=%v", called, err)
			}
		})
	}
	file, e := os.CreateTemp(t.TempDir(), "handle")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = closeRuntimeAfterDrain(ctx, nil, nil, file.Close); e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write([]byte("closed")); !errors.Is(e, os.ErrClosed) {
		t.Fatal("drained handle was not closed", e)
	}
}

func TestRuntimeCloseDeadlineDoesNotWaitForHeldLibraryLock(t *testing.T) {
	// Actual RWMutex contention models a synchronous library call retaining
	// a runtime read lock. The close worker must not extend the caller's budget.
	var lock sync.RWMutex
	lock.RLock()
	entered, finished := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := closeRuntimeAfterDrain(ctx, nil, nil, func() error { close(entered); lock.Lock(); lock.Unlock(); close(finished); return nil })
	lock.RUnlock()
	if !errors.Is(err, errRuntimeCleanupIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocking close reported full cleanup", err)
	}
	select {
	case <-entered:
	default:
		t.Fatal("close worker was not launched")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("released close worker did not finish")
	}
}
