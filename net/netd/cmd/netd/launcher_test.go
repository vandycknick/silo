package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/credentials"
	"golang.org/x/sys/unix"
)

func TestManagedWorkerIsAdoptedAndExitsOnOwnerEOF(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "netd")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	for _, mode := range []string{"ready", "startup-error", "secrets-error", "tls-ready", "tls-missing", "tls-mismatch", "tls-partial", "tls-malformed"} {
		failStartup := mode != "ready" && mode != "tls-ready"
		t.Run(mode, func(t *testing.T) {
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
			secretsR, secretsW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer secretsR.Close()
			defer secretsW.Close()
			secretsPipe, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", secretsR.Fd()))
			endpoint := filepath.Join(root, "netd.sock")
			if mode == "startup-error" {
				endpoint = filepath.Join(root, "absent", "netd.sock")
			}
			// Use input fd8 to prove the launcher remaps, without consuming, to fd7.
			args := []string{"--daemonize", "--log-dir-fd=3", "--runtime-dir-fd=4", "--startup-fd=5", "--exit-fd=6", "--secrets-fd=8",
				"--listen-vfkit=unixgram://" + endpoint, "--log-file=netd.log", "--audit-log-file=audit.log", "--pid-file=netd.pid",
				"--vm-id=test-vm", "--run-id=test-run", "--network-id=test-network"}
			if strings.HasPrefix(mode, "tls-") {
				policyPath := filepath.Join(root, "policy.json")
				if err := os.WriteFile(policyPath, []byte(`{"version":1,"endpoints":[{"kind":"https","name":"local","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["localhost"]}]}`), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--policy-file="+policyPath)
			}
			launcher := exec.Command(binary, args...)
			launcher.Env = append(os.Environ(), "SILO_NET_LEGACY=must-not-inherit")
			launcher.ExtraFiles = []*os.File{logs, runtimeDir, reportW, exitR, logs, secretsR}
			if output, err := launcher.CombinedOutput(); err != nil {
				t.Fatalf("launcher: %v\n%s", err, output)
			}
			_ = secretsR.Close()
			// Maximum-sized JSON with padding exercises spawn-first delivery and
			// proves the final worker waited for the complete frame plus EOF.
			body := `{"version":1,"secrets":[]}`
			if strings.HasPrefix(mode, "tls-") && mode != "tls-missing" {
				certificate, key := tlsStartupPair(t)
				if mode == "tls-mismatch" {
					_, key = tlsStartupPair(t)
				}
				if mode == "tls-malformed" {
					certificate = []byte("malformed")
				}
				body = fmt.Sprintf(`{"version":1,"secrets":[{"name":"silo.tls_ca.certificate","value":%q},{"name":"silo.tls_ca.private_key","value":%q}]}`, base64.StdEncoding.EncodeToString(certificate), base64.StdEncoding.EncodeToString(key))
				if mode == "tls-partial" {
					body = fmt.Sprintf(`{"version":1,"secrets":[{"name":"silo.tls_ca.certificate","value":%q}]}`, base64.StdEncoding.EncodeToString(certificate))
				}
			}
			body += strings.Repeat(" ", credentials.MaxSecretsBody-len(body))
			if mode == "secrets-error" {
				body = `{"version":1,"secrets":[],"unknown":true}`
			}
			if err := secretsW.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(secretsW, "Content-Length: %d\r\n\r\n%s", len(body), body); err != nil {
				t.Fatal(err)
			}
			_ = secretsW.Close()
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
			if mode == "secrets-error" && !strings.Contains(report.Error, "invalid secrets JSON") {
				t.Fatal("worker did not report secrets failure")
			}
			if strings.HasPrefix(mode, "tls-") && mode != "tls-ready" {
				if (mode == "tls-missing" || mode == "tls-partial") && !strings.Contains(report.Error, "silo.tls_ca.certificate") {
					t.Fatal("worker did not fail closed on missing TLS CA")
				}
				if _, err := os.Stat(endpoint); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("listener opened before TLS source validation")
				}
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
				if runtime.GOOS == "linux" {
					environment, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", report.PID))
					if err != nil {
						t.Fatalf("read actual worker environment: %v", err)
					}
					if strings.Contains(string(environment), "SILO_NET_") {
						t.Fatal("worker inherited legacy environment")
					}
				} else {
					t.Log("actual worker /proc environment inspection is Linux-only")
				}
				if secretsPipe != "" {
					entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", report.PID))
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						target, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", report.PID, entry.Name()))
						if target == secretsPipe {
							t.Fatal("worker left secrets pipe open")
						}
					}
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

func TestLegacyEnvironmentSanitizerPreservesAWS(t *testing.T) {
	clean := sanitizedEnvironment([]string{"HOME=/tmp/home", "AWS_PROFILE=production", "SILO_NET_SECRET_X=secret", "SILO_NET_OAUTH_REFRESH_AUTH=grant", "OTHER=value"})
	if strings.Join(clean, "\n") != "HOME=/tmp/home\nAWS_PROFILE=production\nOTHER=value" {
		t.Fatal("sanitizer changed unrelated environment")
	}
	t.Setenv("SILO_NET_LEGACY_TEST", "value")
	if err := sanitizeLegacyEnvironment(); err != nil {
		t.Fatal(err)
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "SILO_NET_") {
			t.Fatal("legacy environment remains")
		}
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
