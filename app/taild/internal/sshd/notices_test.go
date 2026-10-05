package sshd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type noticeOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *noticeOutput) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(b)
}
func (w *noticeOutput) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

func TestNoticePreservesTypedInputAndDefersOutsidePrompt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	out := &noticeOutput{}
	editor := newTerminalInput(ctx, newInput(ctx, r), out, 80, 24)
	if editor.notice("must be deferred\n") {
		t.Fatal("notice outside prompt")
	}
	done := make(chan string, 1)
	go func() {
		line, err := editor.ReadPrompt("silo> ", 1024)
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		done <- line
	}()
	if _, err := io.WriteString(w, "sho"); err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(out.String(), "sho") {
		select {
		case <-ctx.Done():
			t.Fatal("input was not echoed")
		case <-time.After(time.Millisecond):
		}
	}
	if !editor.notice("Tailscale login required for dev\n  https://login.tailscale.com/a/example\n") {
		t.Fatal("notice not shown")
	}
	if _, err := io.WriteString(w, "w dev\r"); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-done:
		if line != "show dev" {
			t.Fatal("notice altered input", line, out.String())
		}
	case <-ctx.Done():
		t.Fatal("editor blocked")
	}
	if editor.notice("must be deferred\n") {
		t.Fatal("notice after input handoff")
	}
	if strings.Count(out.String(), "Tailscale login required") != 1 || strings.Contains(out.String(), "must be deferred") {
		t.Fatal(out.String())
	}
}
