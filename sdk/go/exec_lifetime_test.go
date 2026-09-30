package silo

import (
	"sync"
	"testing"
)

func TestClosedExecutionInputAndControls(t *testing.T) {
	var zero ExecutionSession
	if zero.Stdin() != nil {
		t.Fatal("zero execution returned input")
	}
	session := &ExecutionSession{closed: true}
	if session.Stdin() != nil {
		t.Fatal("closed execution returned input")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := session.Cancel(); !IsErrorKind(e, ErrorClosed) {
				t.Errorf("cancel: %v", e)
			}
			if e := session.CloseRequests(); !IsErrorKind(e, ErrorClosed) {
				t.Errorf("close requests: %v", e)
			}
			if e := session.Close(); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
}
