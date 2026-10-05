//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestNativeKVMGuestUserRootAndOptIn(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required")
	}
	source := testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true)
	cli := testfixture.Path(t, "SILO_TEST_CLI", false)
	for _, variant := range []string{"rescue-root", "explicit-nickvd", "uid-conflict", "no-cat", "no-shell", "no-sh-stored"} {
		t.Run(variant, func(t *testing.T) {
			rootfs := source
			var user *silo.GuestUser
			if variant == "rescue-root" {
				rootfs = t.TempDir()
				if err := os.CopyFS(rootfs, os.DirFS(source)); err != nil {
					t.Fatal(err)
				}
				// cat is the real current rescue multicall executable in this fixture.
				applet, err := os.ReadFile(filepath.Join(rootfs, "bin/cat"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootfs, "bin/sh"), applet, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(rootfs, "bin/bash")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootfs, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				user = &silo.GuestUser{Name: "nickvd", UID: 1000, GID: 1000, Home: "/home/nickvd"}
			}
			if variant == "uid-conflict" {
				rootfs = t.TempDir()
				if err := os.CopyFS(rootfs, os.DirFS(source)); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootfs, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/bash\nexisting:x:1000:1000:existing:/home/existing:/bin/bash\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "no-cat" || variant == "no-shell" {
				user = nil
				rootfs = t.TempDir()
				if err := os.CopyFS(rootfs, os.DirFS(source)); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{"bin/cat", "usr/bin/cat", "bin/bash"} {
					if err := os.Remove(filepath.Join(rootfs, path)); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
				if variant == "no-shell" {
					if err := os.Remove(filepath.Join(rootfs, "bin/sh")); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.MkdirAll(filepath.Join(rootfs, "srv/existing"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootfs, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/sh\nexisting:x:1200:1200:existing:/srv/existing:/bin/sh\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootfs, "etc/group"), []byte("root:x:0:\nexisting:x:1200:\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "no-sh-stored" {
				user = &silo.GuestUser{Name: "nickvd", UID: 1000, GID: 1000, Home: "/home/nickvd"}
				rootfs = t.TempDir()
				if err := os.CopyFS(rootfs, os.DirFS(source)); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(rootfs, "bin/sh")); err != nil {
					t.Fatal(err)
				}
			}
			registry := testfixture.OCIRegistry(t, rootfs)
			c := config.Defaults()
			c.Home = t.TempDir()
			c.RuntimeRoot = testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
			c.VM.Defaults = config.Resources{CPUs: 1, Memory: 1 << 30, Disk: 1 << 30}
			c.VM.DefaultImage = registry.Reference
			c.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			r, err := runtime.Open(ctx, c, "guest-user-kvm")
			if err != nil {
				t.Fatal(err)
			}
			audit, err := state.OpenAudit(c.Home, 1<<20, 2)
			if err != nil {
				t.Fatal(err)
			}
			defer audit.Close()
			s := &service.Service{Runtime: r, Audit: audit, Config: c, Jobs: jobs.New(ctx, 8)}
			defer func() {
				cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
				defer done()
				cancel()
				_ = s.Jobs.Wait(cleanup)
				m, err := s.Runtime.SDK.Machine(cleanup, variant)
				if err == nil {
					_, _ = m.StopWith(cleanup, silo.StopOptions{Force: true, Timeout: time.Second})
					_ = m.Remove(cleanup)
					_ = m.Close()
				}
				_ = s.Runtime.Close()
			}()
			caller := principal(t, c, "user:7")
			op, err := s.Create(ctx, caller, service.CreateRequest{Name: variant, GuestUser: user, NoStart: variant == "uid-conflict" || variant == "no-shell" || variant == "no-sh-stored"})
			if variant == "no-shell" || variant == "no-sh-stored" {
				success(t, s, caller, op, err)
				m, err := r.SDK.Machine(ctx, variant)
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				if _, err := m.Start(ctx); err != nil {
					t.Fatal(err)
				}
				_, _ = m.WaitReady(ctx, 10*time.Second)
				var out bytes.Buffer
				code, err := s.Exec(ctx, caller, variant, service.ExecRequest{Program: "/bin/id", Args: []string{"-u"}}, service.IO{Stdout: &out})
				want := "0\n"
				if user != nil {
					want = "1000\n"
				}
				if code != 0 || err != nil || out.String() != want {
					t.Fatal("binary exec requires unrelated shell", code, err, out.String())
				}
				if user != nil {
					out.Reset()
					code, err = s.Exec(ctx, caller, variant, service.ExecRequest{Program: "/bin/bash", Args: []string{"-c", `printf 'HOME=%s SHELL=%s\n' "$HOME" "$SHELL"; pwd`}}, service.IO{Stdout: &out})
					if code != 0 || err != nil || out.String() != "HOME=/home/nickvd SHELL=/bin/bash\n/home/nickvd\n" {
						t.Fatal("stored fallback environment", code, err, out.String())
					}
				}
				code, err = s.Exec(ctx, caller, variant, service.ExecRequest{Program: "/missing-command"}, service.IO{})
				if code != 127 || err == nil {
					t.Fatal("missing command not native launch failure", code, err)
				}
				code, err = s.Exec(ctx, caller, variant, service.ExecRequest{User: "unknown-user", Program: "/bin/id"}, service.IO{})
				if code != 126 || err == nil {
					t.Fatal("unknown user masked by fallback", code, err)
				}
				return
			}
			if variant == "uid-conflict" {
				success(t, s, caller, op, err)
				m, err := r.SDK.Machine(ctx, variant)
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				if _, err := m.Start(ctx); err != nil {
					t.Fatal(err)
				}
				_, _ = m.WaitReady(ctx, 20*time.Second)
				d, err := m.Inspect(ctx)
				if err != nil || d.ProvisionReport == nil {
					t.Fatal("missing actual provisioning failure", d, err)
				}
				failed := false
				for _, step := range d.ProvisionReport.Steps {
					if step.ID == "users" && step.Status == "failed" {
						failed = true
					}
				}
				if !failed {
					t.Fatalf("conflicting UID did not fail user provisioning: %+v", d.ProvisionReport)
				}
				out, err := m.Exec(ctx, "/bin/cat", []string{"/etc/passwd"}, silo.WithExecUser("root"))
				if err != nil || out.Stdout() != "root:x:0:0:root:/root:/bin/bash\nexisting:x:1000:1000:existing:/home/existing:/bin/bash\n" {
					t.Fatal("conflicting account was mutated", err, out)
				}
				return
			}
			success(t, s, caller, op, err)
			m, err := r.SDK.Machine(ctx, variant)
			if err != nil {
				t.Fatal(err)
			}
			d, err := m.Inspect(ctx)
			_ = m.Close()
			if err != nil {
				t.Fatal(err)
			}
			if user == nil && d.GuestUser != nil || user != nil && (d.GuestUser == nil || *d.GuestUser != *user) {
				t.Fatal(d.GuestUser)
			}
			wantUID, wantHome, wantShell := "0", "/root", "/bin/sh"
			if user != nil {
				wantUID, wantHome, wantShell = "1000", user.Home, "/bin/bash"
			}
			proof := `echo F2_UID; /bin/id -u; echo F2_HOME=$HOME; echo F2_CWD; pwd; echo F2_SHELL=$SHELL`
			check := func(selector, uid, home, shell string) {
				t.Helper()
				var out bytes.Buffer
				code, err := s.Exec(ctx, caller, variant, service.ExecRequest{User: selector, Program: "/bin/sh", Args: []string{"-c", proof}}, service.IO{Stdout: &out})
				for _, token := range []string{"F2_UID\n" + uid + "\n", "F2_HOME=" + home, "F2_CWD\n" + home, "F2_SHELL=" + shell} {
					if code != 0 || err != nil || !strings.Contains(out.String(), token) {
						t.Fatalf("exec %s: %d %v %q missing %s", selector, code, err, out.String(), token)
					}
				}
				out.Reset()
				code, err = s.Shell(ctx, caller, variant, selector, service.IO{Stdin: strings.NewReader(proof + "\nexit\n"), Stdout: &out, Terminal: service.Terminal{Present: true, Window: service.Window{Rows: 24, Columns: 80}}})
				for _, token := range []string{"F2_UID\n" + uid + "\n", "F2_HOME=" + home, "F2_CWD\n" + home, "F2_SHELL=" + shell} {
					if code != 0 || err != nil || !strings.Contains(strings.ReplaceAll(out.String(), "\r\n", "\n"), token) {
						t.Fatalf("shell %s: %d %v %q missing %s", selector, code, err, out.String(), token)
					}
				}
			}
			check("", wantUID, wantHome, wantShell)
			if variant == "no-cat" {
				check("existing", "1200", "/srv/existing", "/bin/sh")
				for _, path := range []string{"/bin/cat", "/usr/bin/cat"} {
					code, err := s.Exec(ctx, caller, variant, service.ExecRequest{Program: path}, service.IO{})
					if code != 127 || err == nil {
						t.Fatal("cat unexpectedly exists in guest", path, code, err)
					}
				}
			}
			if user != nil {
				check("root", "0", "/root", "/bin/bash")
			}
			if variant == "rescue-root" {
				var passwd bytes.Buffer
				code, err := s.Exec(ctx, caller, variant, service.ExecRequest{Program: "/bin/cat", Args: []string{"/etc/passwd"}}, service.IO{Stdout: &passwd})
				if code != 0 || err != nil || passwd.String() != "root:x:0:0:root:/root:/bin/sh\n" {
					t.Fatal("automatic account mutation", code, err, passwd.String())
				}
				command := exec.CommandContext(ctx, cli, "shell", variant)
				command.Env = append(os.Environ(), "SILO_HOME="+c.Home, "SILO_RUNTIME_DIR="+c.RuntimeRoot)
				command.Stdin = strings.NewReader("echo F2_CERT_ROOT=$HOME\necho F2_CERT_UID; /bin/id -u\nexit\n")
				out, err := command.CombinedOutput()
				text := strings.ReplaceAll(string(out), "\r\n", "\n")
				if err != nil || !strings.Contains(text, "F2_CERT_ROOT=/root") || !strings.Contains(text, "F2_CERT_UID\n0\n") {
					t.Fatalf("CLI certificate root session: %v %s", err, out)
				}
			}
			op, err = s.Restart(ctx, caller, variant)
			success(t, s, caller, op, err)
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			r, err = runtime.Open(ctx, c, "guest-user-kvm")
			if err != nil {
				t.Fatal(err)
			}
			s.Runtime = r
			check("", wantUID, wantHome, wantShell)
			v, err := s.Show(ctx, caller.Peer, variant)
			if err != nil || v.DefaultUser != map[bool]string{true: "nickvd", false: "root"}[user != nil] {
				t.Fatal(v.DefaultUser, err)
			}
		})
	}
}
