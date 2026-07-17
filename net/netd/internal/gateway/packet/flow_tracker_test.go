package packet

import (
	"context"
	"testing"
	"time"
)

func TestFlowTrackerDrainsActiveFlowsAndRejectsNewFlows(t *testing.T) {
	tracker := NewFlowTracker()
	if !tracker.Start() {
		t.Fatal("first flow was rejected")
	}

	tracker.BeginDrain()
	if tracker.Start() {
		t.Fatal("flow was accepted after draining started")
	}

	done := make(chan error, 1)
	go func() {
		done <- tracker.Wait(context.Background())
	}()

	select {
	case <-done:
		t.Fatal("drain completed while a flow was active")
	case <-time.After(10 * time.Millisecond):
	}

	tracker.Done()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for flow drain")
	}
}

func TestFlowTrackerWaitHonorsDeadline(t *testing.T) {
	tracker := NewFlowTracker()
	if !tracker.Start() {
		t.Fatal("flow was rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := tracker.Wait(ctx); err == nil {
		t.Fatal("expected drain deadline error")
	}
	tracker.Done()
}
