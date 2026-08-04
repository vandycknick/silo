package session

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/config"
	"github.com/vandycknick/silo/net/netd/internal/logfile"
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

func TestSessionCloseSyncsAndClosesCapture(t *testing.T) {
	dir := t.TempDir()
	capturePath := filepath.Join(dir, "capture.pcap")
	runtimeDirectory := testDirectory(t, dir)
	capture, err := runtimeDirectory.OpenTruncate("capture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(testConfigArgs(dir))
	if err != nil {
		_ = logfile.SyncClose(capture)
		t.Fatal(err)
	}
	s, err := New(Spec{
		VMID:        "vm-test",
		RunID:       "run-test",
		NetworkID:   "net-test",
		CaptureFile: capture,
		Stack:       cfg.Stack,
		Policy:      policy.Default(),
	}, Shared{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := capture.Sync(); err == nil {
		t.Fatal("expected capture file to be closed with the session")
	}
	info, err := os.Stat(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("capture mode = %04o, want 0600", got)
	}
}

func newTestSession(t *testing.T) *Session {
	t.Helper()
	cfg, err := config.Parse(testConfigArgs(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Spec{VMID: "vm-test", RunID: "run-test", NetworkID: "net-test", Stack: cfg.Stack, Policy: policy.Default()}, Shared{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testConfigArgs(dir string) []string {
	return []string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
		"--log-dir-fd", "3",
		"--runtime-dir-fd", "4",
		"--log-file", "netd.log",
		"--audit-log-file", "audit.jsonl",
		"--vm-id", "vm-test",
		"--run-id", "run-test",
		"--network-id", "net-test",
	}
}

func testDirectory(t *testing.T, path string) *logfile.Directory {
	t.Helper()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := logfile.OpenDirectory(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Error(err)
		}
	})
	return directory
}
