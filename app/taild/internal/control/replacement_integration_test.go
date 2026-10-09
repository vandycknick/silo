package control

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Requires real silod, not a gRPC echo fixture. Run actual-daemon packages -p1
// under an idle dedicated UID with explicit installed runtime/bin directories.
func TestActualAdmittedTransportRefusesReplacement(t *testing.T) {
	if os.Getenv("SILO_TEST_CONTROL_REPLACEMENT") != "1" {
		t.Skip("requires explicit real-daemon replacement admission")
	}
	bin, runtimeDir := os.Getenv("SILO_TEST_BIN_DIR"), os.Getenv("SILO_RUNTIME_DIR")
	if !filepath.IsAbs(bin) || !filepath.IsAbs(runtimeDir) {
		t.Fatal("absolute SILO_TEST_BIN_DIR and SILO_RUNTIME_DIR required")
	}
	lock, err := os.OpenFile(fmt.Sprintf("/tmp/silo-control-fixture-%d.lock", os.Getuid()), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("actual-daemon packages require -p1 and an idle UID", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if exec.Command("pgrep", "-u", fmt.Sprint(os.Getuid()), "-x", "silod").Run() == nil {
		t.Fatal("live silod; use idle dedicated UID")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := fmt.Sprintf("/tmp/silo-%d/silod/control.sock", os.Getuid())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	start := func() (*Client, *daemonv1.DaemonStatus, func()) {
		cmd := exec.Command(filepath.Join(bin, "silod"), "--system-enabled=false", "--tailscale-enabled=false")
		cmd.Env = []string{"HOME=" + root, "SILO_HOME=" + filepath.Join(root, "state"), "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "PATH=" + os.Getenv("PATH"), "SILO_RUNTIME_DIR=" + runtimeDir}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = cmd.Process.Signal(unix.SIGTERM)
			select {
			case err := <-exited:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(80 * time.Second):
				_ = cmd.Process.Kill()
				<-exited
				t.Error("daemon shutdown exceeded bound")
			}
		}
		t.Cleanup(stop)
		for {
			client, err := New(endpoint, "")
			if err == nil {
				probe, done := context.WithTimeout(ctx, time.Second)
				status, probeErr := client.Daemon.GetStatus(probe, &emptypb.Empty{})
				if probeErr == nil && status.Core == daemonv1.CorePhase_CORE_PHASE_READY {
					_, probeErr = client.Admit(probe, silo.Version, status.Generation, string(status.Home), string(status.ConfigDir))
					done()
					if probeErr != nil {
						_ = client.Close()
						t.Fatal(probeErr)
					}
					t.Cleanup(func() { _ = client.Close() })
					return client, status, stop
				}
				done()
				_ = client.Close()
			}
			select {
			case <-ctx.Done():
				t.Fatal("daemon readiness", ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	first, oldStatus, stop := start()
	stop()
	replacement, newStatus, _ := start()
	if oldStatus.Generation == newStatus.Generation {
		t.Fatal("replacement reused generation")
	}
	call, done := context.WithTimeout(ctx, 2*time.Second)
	defer done()
	if _, err := first.Daemon.GetStatus(call, &emptypb.Empty{}); err == nil {
		t.Fatal("old admitted transport reached replacement daemon")
	}
	if _, err := replacement.Daemon.GetStatus(ctx, &emptypb.Empty{}); err != nil {
		t.Fatal("replacement was not actually reachable", err)
	}
}
