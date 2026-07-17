package session

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/config"
	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func TestSessionShutdownStopsVirtualNetwork(t *testing.T) {
	s := newTestSession(t)
	server, client := net.Pipe()
	defer client.Close()
	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(context.Background(), server)
	}()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error during shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session Run did not stop")
	}
}

func TestSessionRunAfterCloseClosesConnection(t *testing.T) {
	s := newTestSession(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer client.Close()
	if err := s.Run(context.Background(), server); err != nil {
		t.Fatalf("Run returned error after Close: %v", err)
	}
	if _, err := client.Write([]byte("probe")); err == nil {
		t.Fatal("connection remained open after closed session rejected Run")
	}
}

func newTestSession(t *testing.T) *Session {
	t.Helper()
	cfg, err := config.Parse([]string{"--listen-vfkit", "unixgram://" + filepath.Join(t.TempDir(), "net.sock")})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Spec{VMID: "vm-test", NetworkID: "net-test", Stack: cfg.Stack, Policy: policy.Default()}, Shared{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
