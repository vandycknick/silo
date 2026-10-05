package service

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
)

func TestRealMarkerFailureStillDeniesSynchronousMutations(t *testing.T) {
	s := actualService(t)
	s.Shutdown = &state.ShutdownGate{}
	c := domainCaller(s, "user:1")
	s.Shutdown.Seal()
	// Real filesystem failure: PrivateDir rejects this existing nonprivate
	// directory. No marker exists, and no system bus or SDK error is invented.
	dir := filepath.Join(s.Config.Home, "taild")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if err := s.Shutdown.Mark(s.Config.Home); err == nil {
		t.Fatal("marker write unexpectedly succeeded")
	}
	if state.ShutdownPending(s.Config.Home) {
		t.Fatal("test did not isolate the memory-only seal")
	}
	for _, action := range []identity.Action{identity.Create, identity.Start, identity.Exec, identity.Shell, identity.TemplateManage} {
		if err := s.Authorize(c.Peer, action, nil); err == nil || Categorize(err).Exit != 9 {
			t.Errorf("%s admitted without durable marker: %v", action, err)
		}
	}
	if _, err := s.Create(context.Background(), c, CreateRequest{Name: "sealed", NoStart: true}); err == nil || Categorize(err).Exit != 9 {
		t.Error("create admitted", err)
	}
}

func TestActualSDKCreateInterruptedByMemoryGateWhenMarkerWriteFails(t *testing.T) {
	s := actualService(t)
	s.Shutdown = &state.ShutdownGate{}
	s.Jobs.Shutdown = s.Shutdown
	c := domainCaller(s, "user:1")
	registry := testfixture.OCIRegistry(t, "")
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	registry.BeforeManifest = func() { enteredOnce.Do(func() { close(entered); <-release }) }
	op, err := s.Create(context.Background(), c, CreateRequest{Name: "interrupted"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("actual SDK OCI request did not reach local registry")
	}
	dir := filepath.Join(s.Config.Home, "taild")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	// Same order as authenticated intake: memory seal and direct cancellation
	// precede filesystem work. This is a domain boundary, not a fake login1 bus.
	s.Shutdown.Seal()
	s.Jobs.InterruptIf(func() bool { return true })
	if err := s.Shutdown.Mark(s.Config.Home); err == nil {
		t.Fatal("real marker filesystem failure missing")
	}
	if state.ShutdownPending(s.Config.Home) {
		t.Fatal("unexpected durable marker")
	}
	if _, err := s.Create(context.Background(), c, CreateRequest{Name: "new"}); err == nil || Categorize(err).Exit != 9 {
		t.Fatal("new create admitted", err)
	}
	for _, action := range []identity.Action{identity.Exec, identity.Shell, identity.TemplateManage} {
		if err := s.Authorize(c.Peer, action, nil); err == nil || Categorize(err).Exit != 9 {
			t.Fatal("synchronous mutation admitted", action, err)
		}
	}
	releaseOnce.Do(func() { close(release) })
	finished := daemon.WaitOperation(t, s.Jobs, c.Peer, op, nil)
	if finished.Error == nil || finished.Error.Exit != 9 {
		t.Fatal("in-flight create was not interrupted", finished)
	}
	entries, err := s.Runtime.SDK.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name == "interrupted" {
			t.Fatal("interrupted create materialized/booted a VM", entry)
		}
	}
	s.createMu.Lock()
	if len(s.pending) != 0 || len(s.diskPending) != 0 {
		t.Error("interrupted create leaked reservations")
	}
	s.createMu.Unlock()
	if !s.Shutdown.Pending() {
		t.Fatal("filesystem failure or job drain cleared protective latch")
	}
}
