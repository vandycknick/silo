package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

type removalOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *removalOutput) Write(b []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(b)
}
func (o *removalOutput) text() string { o.mu.Lock(); defer o.mu.Unlock(); return o.buf.String() }

// Keep OpenSSH's stdin pipe open until after the prompt, proving a normal
// non-PTY session accepts live replies rather than relying on buffered EOF.
type removalClient struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	out        bytes.Buffer
	diagnostic removalOutput
	done       chan error
}

func openRemovalClient(t *testing.T, ctx context.Context, address, command string) *removalClient {
	t.Helper()
	path, e := exec.LookPath("ssh")
	if e != nil {
		testfixture.Unavailable(t, "OpenSSH ssh is required")
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	c := &removalClient{done: make(chan error, 1)}
	c.cmd = exec.CommandContext(ctx, path, "-F", "/dev/null", "-T", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "PreferredAuthentications=none", "-p", port, "explicit-domain@"+host, command)
	c.stdin, e = c.cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	c.cmd.Stdout, c.cmd.Stderr = &c.out, &c.diagnostic
	if e := c.cmd.Start(); e != nil {
		t.Fatal(e)
	}
	go func() { c.done <- c.cmd.Wait() }()
	t.Cleanup(func() { _ = c.stdin.Close(); _ = c.cmd.Process.Kill() })
	return c
}

func (c *removalClient) send(t *testing.T, answer string) {
	t.Helper()
	if _, e := io.WriteString(c.stdin, answer); e != nil {
		t.Fatal(e)
	}
}

func (c *removalClient) prompt(t *testing.T, text string, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Count(c.diagnostic.text(), text) >= count {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("prompt missing", c.diagnostic.text())
}

func (c *removalClient) exit(t *testing.T, want int, jsonResult bool) {
	t.Helper()
	select {
	case e := <-c.done:
		code := 0
		if e != nil {
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatal(e)
			}
			code = exit.ExitCode()
		}
		if code != want {
			t.Fatalf("exit %d, want %d: %s", code, want, c.diagnostic.text())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("OpenSSH did not exit", c.diagnostic.text())
	}
	if jsonResult {
		var result struct {
			OK    bool           `json:"ok"`
			Error *responseError `json:"error"`
		}
		if e := json.Unmarshal(c.out.Bytes(), &result); e != nil {
			t.Fatal("stdout is not one JSON envelope", c.out.String(), e)
		}
		if result.OK != (want == 0) || want == 2 && (result.Error == nil || result.Error.Code != "cancelled") {
			t.Fatal(c.out.String())
		}
	} else if c.out.Len() != 0 {
		t.Fatal("human output leaked onto stdout", c.out.String())
	}
}

func removalDispatch(t *testing.T, ctx context.Context, s *service.Service, caller service.Caller, command string, want int) {
	t.Helper()
	var diagnostic bytes.Buffer
	if code := DispatchSession(ctx, s, caller, command, service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != want {
		t.Fatal(command, code, diagnostic.String())
	}
}

func TestRemovalOpenSSHNativeDecisions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, caller, _ := nativeService(t, ctx, "removal-decisions", "user:7")
	address := terminalSSHServer(t, s, caller)
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	before := len(s.Jobs.List(caller.Peer))
	prompt := "Remove VM 'devbox'? [y/N] "
	for _, tc := range []struct {
		name, answer string
		eof          bool
	}{
		{"no", "no\n", false}, {"n", " N \n", false}, {"enter", "\n", false},
		{"ctrl-c", "\x03", false}, {"eof", "", true}, {"partial-eof", "yes", true},
		{"invalid-no", "maybe\nNO\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := openRemovalClient(t, ctx, address, "rm devbox --json")
			c.prompt(t, prompt, 1)
			if tc.answer != "" {
				c.send(t, tc.answer)
			}
			if tc.eof {
				_ = c.stdin.Close()
			}
			c.exit(t, 2, true)
			if _, e := s.Show(ctx, caller.Peer, "devbox"); e != nil {
				t.Fatal("negative reply changed VM", e)
			}
			if len(s.Jobs.List(caller.Peer)) != before {
				t.Fatal("negative reply submitted operation")
			}
		})
	}
	t.Run("nil-input-json", func(t *testing.T) {
		var out, diagnostic bytes.Buffer
		if code := DispatchSession(ctx, s, caller, "rm devbox --json", service.IO{Stdout: &out, Stderr: &diagnostic}); code != 2 {
			t.Fatal(code)
		}
		var result response
		if e := json.Unmarshal(out.Bytes(), &result); e != nil || result.OK || result.Error == nil || result.Error.Code != "cancelled" {
			t.Fatal(out.String(), e)
		}
	})
	t.Run("disconnect", func(t *testing.T) {
		c := openRemovalClient(t, ctx, address, "rm devbox")
		c.prompt(t, prompt, 1)
		_ = c.cmd.Process.Kill()
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			t.Fatal("client did not disconnect")
		}
		// A subsequent real session also proves the server is still usable.
		out, _, code := sshPipeCommand(t, address, "show devbox --json", nil, false)
		if code != 0 || !json.Valid(out) || len(s.Jobs.List(caller.Peer)) != before {
			t.Fatal("disconnect changed VM/jobs", code, string(out))
		}
	})
	t.Run("reprompt-yes", func(t *testing.T) {
		c := openRemovalClient(t, ctx, address, "rm devbox --json")
		c.prompt(t, prompt, 1)
		c.send(t, "maybe\n")
		c.prompt(t, prompt, 2)
		c.send(t, " \tYeS \n")
		c.exit(t, 0, true)
		if _, e := s.Show(ctx, caller.Peer, "devbox"); e == nil || service.Categorize(e).Exit != 3 {
			t.Fatal("yes did not remove real VM", e)
		}
	})
	t.Run("yes-skips-live-stdin", func(t *testing.T) {
		removalDispatch(t, ctx, s, caller, "create --name unattended --no-start", 0)
		c := openRemovalClient(t, ctx, address, "rm unattended --yes --json")
		c.exit(t, 0, true) // stdin remains open and receives no bytes.
		if strings.Contains(c.diagnostic.text(), "[y/N]") {
			t.Fatal(c.diagnostic.text())
		}
		removalDispatch(t, ctx, s, caller, "create --name untouched-input --no-start", 0)
		var consumed, diagnostic bytes.Buffer
		streams := service.IO{Stdin: io.TeeReader(strings.NewReader("no\n"), &consumed), Stdout: io.Discard, Stderr: &diagnostic}
		if code := DispatchSession(ctx, s, caller, "rm untouched-input --yes", streams); code != 0 || consumed.Len() != 0 || strings.Contains(diagnostic.String(), "[y/N]") {
			t.Fatal("--yes touched command stdin or prompted", code, consumed.String(), diagnostic.String())
		}
	})
}

func TestRemovalOpenSSHNativePreflightAndIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, caller, _ := nativeService(t, ctx, "removal-preflight", "user:7")
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	var revoked atomic.Bool
	peer := caller.Peer
	caller.Resolve = func(ctx context.Context) (identity.Peer, error) {
		p := peer
		if revoked.Load() {
			p.Permissions.Actions = nil
		}
		return p, ctx.Err()
	}
	address := terminalSSHServer(t, s, caller)
	absent := openRemovalClient(t, ctx, address, "rm absent --json")
	absent.exit(t, 3, true)
	if strings.Contains(absent.diagnostic.text(), "[y/N]") {
		t.Fatal("not-found prompted", absent.diagnostic.text())
	}
	invalid := openRemovalClient(t, ctx, address, "rm bad/name")
	invalid.exit(t, 2, false)
	if strings.Contains(invalid.diagnostic.text(), "[y/N]") {
		t.Fatal("invalid reference prompted", invalid.diagnostic.text())
	}
	other := caller
	other.Peer.Principals = []identity.Principal{"user:8"}
	other.Resolve = func(ctx context.Context) (identity.Peer, error) { return other.Peer, ctx.Err() }
	c := openRemovalClient(t, ctx, terminalSSHServer(t, s, other), "rm devbox --json")
	c.exit(t, 3, true)
	if strings.Contains(c.diagnostic.text(), "devbox") {
		t.Fatal("invisible VM leaked", c.diagnostic.text())
	}
	revoked.Store(true)
	c = openRemovalClient(t, ctx, address, "rm devbox --json")
	c.exit(t, 4, true)
	if strings.Contains(c.diagnostic.text(), "[y/N]") {
		t.Fatal("revoked preflight prompted")
	}
	revoked.Store(false)
	c = openRemovalClient(t, ctx, address, "rm devbox --json")
	c.prompt(t, "Remove VM 'devbox'? [y/N] ", 1)
	revoked.Store(true)
	c.send(t, "yes\n")
	c.exit(t, 4, true)
	if _, e := s.Show(ctx, peer, "devbox"); e != nil {
		t.Fatal("revocation deleted VM", e)
	}
	// Deletion must not require vm.read just to ask for consent.
	onlyDelete := caller
	onlyDelete.Peer.Permissions.Actions = []identity.Action{identity.Delete}
	onlyDelete.Resolve = func(ctx context.Context) (identity.Peer, error) { return onlyDelete.Peer, ctx.Err() }
	c = openRemovalClient(t, ctx, terminalSSHServer(t, s, onlyDelete), "rm devbox --json")
	c.prompt(t, "Remove VM 'devbox'? [y/N] ", 1)
	c.send(t, "n\n")
	c.exit(t, 2, true)
	changedIdentity := caller
	changedIdentity.Resolve = func(ctx context.Context) (identity.Peer, error) {
		p := peer
		p.NodeID += "-changed"
		return p, ctx.Err()
	}
	c = openRemovalClient(t, ctx, terminalSSHServer(t, s, changedIdentity), "rm devbox --json")
	c.exit(t, 4, true)
	if strings.Contains(c.diagnostic.text(), "[y/N]") {
		t.Fatal("changed identity prompted")
	}
}

func TestRemovalOpenSSHNativePinnedID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, caller, _ := nativeService(t, ctx, "removal-pin", "user:7")
	address := terminalSSHServer(t, s, caller)
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	original, e := s.Show(ctx, caller.Peer, "devbox")
	if e != nil {
		t.Fatal(e)
	}
	c := openRemovalClient(t, ctx, address, "rm devbox --json")
	c.prompt(t, "Remove VM 'devbox'? [y/N] ", 1)
	// A genuine SDK rename and replacement while the prompt is blocked proves
	// neither a native handle nor a per-VM operation lock is retained.
	m, e := s.Runtime.SDK.Machine(ctx, original.ID)
	if e != nil {
		t.Fatal(e)
	}
	d, e := m.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	name := "renamed"
	d.Labels[runtime.NameLabel] = name
	_, e = m.Update(ctx, silo.MachineUpdate{Name: &name, Labels: &d.Labels})
	_ = m.Close()
	if e != nil {
		t.Fatal("real SDK rename blocked/failed", e)
	}
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	replacement, e := s.Show(ctx, caller.Peer, "devbox")
	if e != nil || replacement.ID == original.ID {
		t.Fatal(replacement, e)
	}
	c.send(t, "y\n")
	c.exit(t, 0, true)
	if _, e := s.Show(ctx, caller.Peer, original.ID); e == nil || service.Categorize(e).Exit != 3 {
		t.Fatal("original ID not deleted", e)
	}
	if vm, e := s.Show(ctx, caller.Peer, "devbox"); e != nil || vm.ID != replacement.ID {
		t.Fatal("replacement was deleted", vm, e)
	}
	c = openRemovalClient(t, ctx, address, "rm devbox --json")
	c.prompt(t, "Remove VM 'devbox'? [y/N] ", 1)
	removalDispatch(t, ctx, s, caller, "rm devbox --yes", 0)
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	c.send(t, "yes\n")
	c.exit(t, 3, true)
	if _, e := s.Show(ctx, caller.Peer, "devbox"); e != nil {
		t.Fatal("recreated VM was deleted", e)
	}
}

func TestRemovalOpenSSHNativePTY(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, caller, _ := nativeService(t, ctx, "removal-pty", "user:7")
	address := terminalSSHServer(t, s, caller)
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	for _, answer := range []string{"\x03", "\x04", "no\r"} {
		c := openTerminalClient(t, address, "rm devbox")
		c.wait(t, "Remove VM 'devbox'? [y/N] ", 1)
		c.send(t, answer)
		select {
		case e := <-c.done:
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 2 {
				t.Fatal(e, c.text())
			}
		case <-time.After(10 * time.Second):
			t.Fatal("PTY cancellation hung", c.text())
		}
		if _, e := s.Show(ctx, caller.Peer, "devbox"); e != nil {
			t.Fatal(e)
		}
	}
	c := openTerminalClient(t, address, "rm devbox")
	c.wait(t, "Remove VM 'devbox'? [y/N] ", 1)
	c.send(t, "maybe\r")
	c.wait(t, "Remove VM 'devbox'? [y/N] ", 2)
	c.send(t, "ye界\x7fs\r")
	c.exit(t)
	if _, e := s.Show(ctx, caller.Peer, "devbox"); e == nil || service.Categorize(e).Exit != 3 {
		t.Fatal("edited PTY yes did not remove VM", e)
	}
}

func TestRemovalOpenSSHNativeRunningForce(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		testfixture.Unavailable(t, "running removal requires SILO_E2E_KVM=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	s, caller, _ := nativeService(t, ctx, "removal-running", "user:7")
	registry := testfixture.OCIRegistry(t, testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true))
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	var stopRevoked atomic.Bool
	peer := caller.Peer
	caller.Resolve = func(ctx context.Context) (identity.Peer, error) {
		p := peer
		if stopRevoked.Load() {
			p.Permissions.Actions = []identity.Action{identity.Delete}
		}
		return p, ctx.Err()
	}
	address := terminalSSHServer(t, s, caller)
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	// The VM becomes running while a stopped-VM confirmation is pending.
	c := openRemovalClient(t, ctx, address, "rm devbox --json")
	c.prompt(t, "Remove VM 'devbox'? [y/N] ", 1)
	removalDispatch(t, ctx, s, caller, "start devbox", 0)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		m, e := s.Runtime.SDK.Machine(cleanup, "devbox")
		if e == nil {
			_, _ = m.StopWith(cleanup, silo.StopOptions{Force: true, Timeout: time.Second})
			_ = m.Close()
		}
	})
	m, e := s.Runtime.SDK.Machine(ctx, "devbox")
	if e != nil {
		t.Fatal(e)
	}
	before, e := m.Inspect(ctx)
	_ = m.Close()
	if e != nil || before.RunID == nil {
		t.Fatal(before, e)
	}
	c.send(t, "yes\n")
	c.exit(t, 5, true)
	c = openRemovalClient(t, ctx, address, "rm devbox --json")
	c.exit(t, 5, true)
	if strings.Contains(c.diagnostic.text(), "[y/N]") {
		t.Fatal("running without force prompted")
	}
	noStop := caller
	noStop.Peer.Permissions.Actions = []identity.Action{identity.Delete}
	noStop.Resolve = func(ctx context.Context) (identity.Peer, error) { return noStop.Peer, ctx.Err() }
	c = openRemovalClient(t, ctx, terminalSSHServer(t, s, noStop), "rm devbox --force --json")
	c.exit(t, 4, true)
	if strings.Contains(c.diagnostic.text(), "[y/N]") {
		t.Fatal("missing stop permission prompted")
	}
	for _, answer := range []string{"n\n", "\x03"} {
		c = openRemovalClient(t, ctx, address, "rm devbox --force --json")
		c.prompt(t, "Stop and remove VM 'devbox'? [y/N] ", 1)
		c.send(t, answer)
		c.exit(t, 2, true)
	}
	c = openRemovalClient(t, ctx, address, "rm devbox --force --json")
	c.prompt(t, "Stop and remove VM 'devbox'? [y/N] ", 1)
	stopRevoked.Store(true)
	c.send(t, "yes\n")
	c.exit(t, 4, true)
	stopRevoked.Store(false)
	m, e = s.Runtime.SDK.Machine(ctx, "devbox")
	if e != nil {
		t.Fatal(e)
	}
	after, e := m.Inspect(ctx)
	_ = m.Close()
	if e != nil || after.Status.Kind != silo.MachineStatusRunning || after.RunID == nil || *after.RunID != *before.RunID {
		t.Fatal("negative reply stopped/restarted VM", after, e)
	}
	c = openRemovalClient(t, ctx, address, "rm devbox --force --json")
	c.prompt(t, "Stop and remove VM 'devbox'? [y/N] ", 1)
	c.send(t, "YES\n")
	c.exit(t, 0, true)
	if _, e := s.Show(ctx, caller.Peer, "devbox"); e == nil || service.Categorize(e).Exit != 3 {
		t.Fatal("force yes did not remove VM", e)
	}
}
