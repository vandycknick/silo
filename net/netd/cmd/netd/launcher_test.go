package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestManagedWorkerIsAdoptedAndExitsOnOwnerEOF(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "netd")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	for _, failStartup := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "startup-error"}[failStartup], func(t *testing.T) {
			// Unix socket pathname limits on macOS are shorter than testing.TempDir paths.
			root, err := os.MkdirTemp("/tmp", "netd-test-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			logs, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer logs.Close()
			runtimeDir, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer runtimeDir.Close()
			reportR, reportW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reportR.Close()
			defer reportW.Close()
			exitR, exitW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer exitR.Close()
			defer exitW.Close()
			endpoint := filepath.Join(root, "netd.sock")
			if failStartup {
				endpoint = filepath.Join(root, "absent", "netd.sock")
			}
			args := []string{"--daemonize", "--log-dir-fd=3", "--runtime-dir-fd=4", "--startup-fd=5", "--exit-fd=6",
				"--listen-vfkit=unixgram://" + endpoint, "--log-file=netd.log", "--audit-log-file=audit.log", "--pid-file=netd.pid",
				"--vm-id=test-vm", "--run-id=test-run", "--network-id=test-network"}
			launcher := exec.Command(binary, args...)
			launcher.ExtraFiles = []*os.File{logs, runtimeDir, reportW, exitR}
			if output, err := launcher.CombinedOutput(); err != nil {
				t.Fatalf("launcher: %v\n%s", err, output)
			}
			_ = reportW.Close()
			_ = exitR.Close()
			if err := reportR.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var report startupReport
			if err := json.NewDecoder(reportR).Decode(&report); err != nil {
				t.Fatal(err)
			}
			if report.PID == launcher.Process.Pid || report.PID <= 0 {
				t.Fatalf("worker identity: %+v", report)
			}
			if report.Ready == failStartup {
				t.Fatalf("startup outcome: %+v", report)
			}
			if report.RunID != "test-run" || report.NetworkID != "test-network" {
				t.Fatalf("generation: %+v", report)
			}
			var status unix.WaitStatus
			if _, err := unix.Wait4(report.PID, &status, unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
				t.Fatalf("worker must not belong to long-lived caller: %v", err)
			}
			if !failStartup {
				if err := syscall.Kill(report.PID, 0); err != nil {
					t.Fatalf("worker died with launcher: %v", err)
				}
				_ = exitW.Close()
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				err := syscall.Kill(report.PID, 0)
				if errors.Is(err, syscall.ESRCH) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("worker %d was not exited/reaped: %v", report.PID, err)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

func TestOwnerPipeValidationAndCancellation(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if err := validatePipe(int(write.Fd()), unix.O_RDONLY); err == nil {
		t.Fatal("accepted writer as reader")
	}
	file, err := os.CreateTemp(t.TempDir(), "not-pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validatePipe(int(file.Fd()), unix.O_RDONLY); err == nil {
		t.Fatal("accepted regular file")
	}
	// The watcher owns its descriptor, use a duplicate for this test.
	fd, err := unix.Dup(int(read.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	cancelled := make(chan struct{}, 1)
	stop, err := watchOwner(fd, func() { cancelled <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("owner EOF not observed")
	}
	stop()
}
