package sshd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/creack/pty"
	gliderssh "github.com/tailscale/gliderssh"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
	"golang.org/x/crypto/ssh"
)

// These sessions use the actual upstream PTY metadata/emulation, not an OS PTY
// on the server. Identity is explicit below WhoIs, just like local SDK tests.
func terminalSSHServer(t *testing.T, svc *service.Service, caller service.Caller) string {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	srv := &gliderssh.Server{Handler: func(session gliderssh.Session) {
		defer session.Close()
		ctx, cancel := context.WithCancel(session.Context())
		defer cancel()
		p, windows, present := session.Pty()
		converted := make(chan service.Window, 1)
		closeSession := func() { _ = session.Close() }
		streams := terminalStreams(ctx, session, service.IO{
			Stdout:   sessionOutput{ctx, session, closeSession},
			Stderr:   sessionOutput{ctx, session.Stderr(), closeSession},
			Terminal: service.Terminal{Present: present, Term: p.Term, Windows: converted, Window: service.Window{Rows: uint16(p.Window.Height), Columns: uint16(p.Window.Width)}},
		})
		// Drain actual upstream requests through close with production fanout.
		go func() {
			defer close(converted)
			for w := range windows {
				terminalResize(streams, converted, w.Width, w.Height)
			}
		}()
		code := 2
		if session.RawCommand() != "" {
			code = DispatchSession(ctx, svc, caller, session.RawCommand(), streams)
		} else if present {
			code = Lobby(ctx, svc, caller, streams)
		}
		_ = session.Exit(code)
	}}
	srv.AddHostKey(signer)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("SSH server did not stop")
		}
	})
	return ln.Addr().String()
}

type terminalClient struct {
	master   *os.File
	process  *os.Process
	mu       sync.Mutex
	output   bytes.Buffer
	done     chan error
	readDone chan struct{}
}

// A new read enables paste mode before its prompt. Resize repainting may repeat
// prompt text, but does not enable paste mode or begin another input read.
const lobbyPrompt = "\x1b[?2004hsilo> "

func openTerminalClient(t *testing.T, address, command string) *terminalClient {
	t.Helper()
	path, args := testfixture.OpenSSH(t, address, true, command)
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	master, e := pty.StartWithSize(cmd, &pty.Winsize{Rows: 30, Cols: 120})
	if e != nil {
		t.Fatal(e)
	}
	c := &terminalClient{master: master, process: cmd.Process, done: make(chan error, 1), readDone: make(chan struct{})}
	go func() {
		defer close(c.readDone)
		buf := make([]byte, 4096)
		for {
			n, e := master.Read(buf)
			c.mu.Lock()
			_, _ = c.output.Write(buf[:n])
			c.mu.Unlock()
			if e != nil {
				return
			}
		}
	}()
	go func() { c.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = master.Close()
		select {
		case <-c.readDone:
		case <-time.After(5 * time.Second):
			t.Error("PTY reader did not join")
		}
	})
	return c
}

func (c *terminalClient) text() string { c.mu.Lock(); defer c.mu.Unlock(); return c.output.String() }
func (c *terminalClient) send(t *testing.T, s string) {
	t.Helper()
	if _, e := io.WriteString(c.master, s); e != nil {
		t.Fatal(e)
	}
}
func (c *terminalClient) wait(t *testing.T, substring string, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Count(c.text(), substring) >= count {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing %q x%d in %q", substring, count, c.text())
}
func (c *terminalClient) exit(t *testing.T) {
	t.Helper()
	select {
	case e := <-c.done:
		if e != nil {
			t.Fatal(e, c.text())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OpenSSH did not exit", c.text())
	}
	select {
	case <-c.readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("PTY output did not drain")
	}
}

func assertTerminalNewlines(t *testing.T, text string) {
	t.Helper()
	if strings.Contains(text, "\r\r\n") {
		t.Fatalf("double CR: %q", text)
	}
	for i, b := range []byte(text) {
		if b == '\n' && (i == 0 || text[i-1] != '\r') {
			t.Fatalf("staircase LF: %q", text)
		}
	}
}

func TestTerminalOpenSSHFirstContactAndEditing(t *testing.T) {
	audit := offlineAudit(t)
	svc := &service.Service{Audit: audit, Capability: "test-capability"}
	caller := service.Caller{Peer: identity.Peer{Principals: []identity.Principal{"user:7"}, NodeID: "explicit-domain-terminal", ObservedAt: time.Now(), Permissions: identity.Permissions{Reason: "No capability grants access"}}}
	peer := caller.Peer
	caller.Resolve = func(ctx context.Context) (identity.Peer, error) { return peer, ctx.Err() }
	address := terminalSSHServer(t, svc, caller)
	c := openTerminalClient(t, address, "")
	c.wait(t, lobbyPrompt, 1)
	first := c.text()
	if first != lobbyPrompt {
		t.Fatal("entry must contain only the prompt", first)
	}
	assertTerminalNewlines(t, first)
	time.Sleep(120 * time.Millisecond)
	if c.text() != first {
		t.Fatal("idle output/prompt spin", c.text())
	}
	if e := pty.Setsize(c.master, &pty.Winsize{Rows: 25, Cols: 90}); e != nil {
		t.Fatal(e)
	}
	if e := c.process.Signal(syscall.SIGWINCH); e != nil {
		t.Fatal(e)
	}
	// Both backspace encodings delete a whole unicode character. Arrows edit
	// at the cursor; history recalls the corrected command, not escape bytes.
	c.send(t, "whoam界\x7fi\r")
	c.wait(t, "User:", 1)
	c.wait(t, lobbyPrompt, 2)
	c.send(t, "\x1b[A\n")
	c.wait(t, "User:", 2)
	c.wait(t, lobbyPrompt, 3)
	c.send(t, "whoamé\bi\x1b[D\x04i\r\n")
	c.wait(t, "User:", 3)
	c.wait(t, lobbyPrompt, 4)
	// CR and split CRLF cause precisely one new prompt each.
	c.send(t, "\r")
	c.wait(t, lobbyPrompt, 5)
	c.send(t, "\n")
	time.Sleep(100 * time.Millisecond)
	if strings.Count(c.text(), lobbyPrompt) != 5 {
		t.Fatal("split CRLF created an extra prompt", c.text())
	}
	// Several empty inputs still produce one prompt per physical submission.
	c.send(t, "\r\n\r\n\n")
	c.wait(t, lobbyPrompt, 8)
	c.send(t, "help\x1b[D\x1b[")
	c.send(t, "\x03")
	c.wait(t, lobbyPrompt, 9)
	if strings.Count(c.text(), "manage your VMs") != 0 {
		t.Fatal("Ctrl-C dispatched line", c.text())
	}
	// Bracketed paste cannot submit either command until explicit Enter.
	c.send(t, "\x1b[200~whoami\r\nhelp\x03\x1b[201~")
	time.Sleep(100 * time.Millisecond)
	if strings.Count(c.text(), lobbyPrompt) != 9 {
		t.Fatal("paste executed commands", c.text())
	}
	c.send(t, "\x03")
	c.wait(t, lobbyPrompt, 10)
	c.send(t, "\x1b[200~whoami\nhelp\x1b[201~\r")
	c.wait(t, lobbyPrompt, 11)
	if strings.Count(c.text(), "User:") != 3 || strings.Count(c.text(), "manage your VMs") != 0 {
		t.Fatal("multiline paste executed separate commands", c.text())
	}
	c.send(t, "\x04")
	c.exit(t)
	assertTerminalNewlines(t, c.text())
	if strings.Contains(c.text(), "unknown command") {
		t.Fatal("editing dispatched literal controls", c.text())
	}
	for _, command := range []string{"whoami", "help"} {
		one := openTerminalClient(t, address, command)
		one.exit(t)
		assertTerminalNewlines(t, one.text())
		if !strings.Contains(one.text(), map[string]string{"whoami": "User:", "help": "manage your VMs"}[command]) {
			t.Fatal(one.text())
		}
	}
	// Exercise the review's history-overflow case through the production lobby
	// on a genuine OpenSSH local PTY. The overflow must never reach dispatch.
	overflow := openTerminalClient(t, address, "")
	overflow.wait(t, lobbyPrompt, 1)
	overflow.send(t, "whoami"+strings.Repeat(" ", 4089)+"\r")
	overflow.wait(t, "User:", 1)
	overflow.wait(t, lobbyPrompt, 2)
	overflow.send(t, "\x1b[Axx\r")
	select {
	case e := <-overflow.done:
		var exit *exec.ExitError
		if !errors.As(e, &exit) || exit.ExitCode() != 255 {
			t.Fatal("overflow did not reject submission", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("overflow submission hung")
	}
	select {
	case <-overflow.readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("overflow PTY did not drain")
	}
	if strings.Count(overflow.text(), "User:") != 1 || strings.Contains(overflow.text(), "Error:") {
		t.Fatal("overflow reached dispatch", overflow.text())
	}
}

func TestTerminalHandoffAndBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	input := newInput(ctx, strings.NewReader("exec vm -- cat\r\n\x00\xff\x03\x1b[A\r\n"))
	editor := newTerminalInput(ctx, input, &humanWriter{out: &out}, 80, 24)
	line, e := editor.ReadPrompt("", 16384)
	if e != nil || line != "exec vm -- cat" {
		t.Fatal(line, e)
	}
	beforeResize := out.String()
	converted := make(chan service.Window, 1)
	terminalResize(service.IO{Stdin: editor}, converted, 112, 37)
	if next := <-converted; next.Rows != 37 || next.Columns != 112 {
		t.Fatal("resize shape", next)
	}
	if out.String() != beforeResize {
		t.Fatal("idle/guest resize repainted a daemon prompt", out.String())
	}
	raw, e := io.ReadAll(input.Reader(ctx))
	if e != nil || !bytes.Equal(raw, []byte("\x00\xff\x03\x1b[A\r\n")) {
		t.Fatalf("guest bytes lost/edited: %x %v", raw, e)
	}
	for _, data := range []string{strings.Repeat("x", 5000) + "\r", "\x1b[200~" + strings.Repeat("x", 5000) + "\x1b[201~\r", "\x1b]title\x07whoami\r", "\xffwhoami\r"} {
		input := newInput(ctx, strings.NewReader(data))
		editor := newTerminalInput(ctx, input, io.Discard, 80, 24)
		if line, e := editor.ReadPrompt("", 16384); e == nil || line != "" {
			t.Fatal("unsafe/truncated input accepted", line, e)
		}
	}
	input = newInput(ctx, strings.NewReader("whoami\r\rhelp\x03\x1b[A\r"))
	editor = newTerminalInput(ctx, input, io.Discard, 80, 24)
	for i, want := range []string{"whoami", "", "", "whoami"} {
		line, e := editor.ReadPrompt("", 4096)
		if line != want || (i == 2 && !errors.Is(e, errLineCanceled)) || (i != 2 && e != nil) {
			t.Fatal("history after empty/canceled line", i, line, e)
		}
	}
}

func TestTerminalHistoryEffectiveLineBounds(t *testing.T) {
	for _, tc := range []struct {
		name, seed, append string
		limit              int
		overflow           bool
	}{
		{"ascii-below", strings.Repeat("a", 4095), "", 16384, false},
		{"ascii-exact", strings.Repeat("a", 4095), "x", 16384, false},
		{"ascii-above", strings.Repeat("a", 4095), "xx", 16384, true},
		{"unicode-runes-below", strings.Repeat("界", 4095), "", 16384, false},
		{"unicode-runes-exact", strings.Repeat("界", 4095), "界", 16384, false},
		{"unicode-runes-above", strings.Repeat("界", 4095), "界界", 16384, true},
		{"unicode-bytes-below", strings.Repeat("é", 2047), "x", 4096, false},
		{"unicode-bytes-exact", strings.Repeat("é", 2047), "xx", 4096, false},
		{"unicode-bytes-above", strings.Repeat("é", 2047), "xxx", 4096, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			input := newInput(ctx, strings.NewReader(tc.seed+"\r\x1b[A"+tc.append+"\r"))
			editor := newTerminalInput(ctx, input, io.Discard, 120, 30)
			if line, e := editor.ReadPrompt("", tc.limit); e != nil || line != tc.seed {
				t.Fatal("seed", len(line), e)
			}
			line, e := editor.ReadPrompt("", tc.limit)
			if tc.overflow {
				if e == nil || line != "" {
					t.Fatalf("overflow dispatched %d bytes/%d runes: %v", len(line), utf8.RuneCountInString(line), e)
				}
				if editor.terminal.History.Len() != 1 {
					t.Fatal("overflow polluted history")
				}
			} else if e != nil || line != tc.seed+tc.append {
				t.Fatal("effective line changed", len(line), e)
			}
		})
	}
	t.Run("multiple recalls and cancellations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		seed := strings.Repeat("a", 4095)
		data := "first\r" + seed + "\rlatest\r\x1b[A\x1b[A\x03\x1b[A\x1b[Axx\x7f\r\x1b[A\r"
		editor := newTerminalInput(ctx, newInput(ctx, strings.NewReader(data)), io.Discard, 120, 30)
		for _, want := range []string{"first", seed, "latest"} {
			if line, e := editor.ReadPrompt("", 16384); e != nil || line != want {
				t.Fatal(len(line), e)
			}
		}
		if line, e := editor.ReadPrompt("", 16384); line != "" || !errors.Is(e, errLineCanceled) {
			t.Fatal("recall cancellation", line, e)
		}
		if line, e := editor.ReadPrompt("", 16384); line != "" || e == nil {
			t.Fatal("shortening after overflow dispatched prefix", len(line), e)
		}
		if line, e := editor.ReadPrompt("", 16384); line != "latest" || e != nil {
			t.Fatal("canceled/overflow history replay", line, e)
		}
	})
}

func TestTerminalHumanWriterBoundaries(t *testing.T) {
	var out bytes.Buffer
	w := &humanWriter{out: &out}
	for _, s := range []string{"first\nsecond\r", "\nthird\r\n"} {
		if _, e := io.WriteString(w, s); e != nil {
			t.Fatal(e)
		}
	}
	if out.String() != "first\r\nsecond\r\nthird\r\n" {
		t.Fatal(out.String())
	}
	r, wpipe := io.Pipe()
	_ = r.Close()
	if _, e := (&humanWriter{out: wpipe}).Write([]byte("text\n")); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal(e)
	}
}

func TestTerminalReadWriteErrorsAndCancellation(t *testing.T) {
	t.Run("read error never dispatches partial input", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		src, producer := io.Pipe()
		defer src.Close()
		readError := errors.New("transport read failed")
		go func() { _, _ = io.WriteString(producer, "whoami"); _ = producer.CloseWithError(readError) }()
		editor := newTerminalInput(ctx, newInput(ctx, src), io.Discard, 80, 24)
		if line, e := editor.ReadPrompt("", 4096); line != "" || !errors.Is(e, readError) {
			t.Fatal(line, e)
		}
	})
	t.Run("broken real output pipe", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		drain, output := io.Pipe()
		_ = drain.Close()
		defer output.Close()
		editor := newTerminalInput(ctx, newInput(ctx, strings.NewReader("whoami\r")), output, 80, 24)
		if line, e := editor.ReadPrompt("", 4096); line != "" || !errors.Is(e, io.ErrClosedPipe) {
			t.Fatal(line, e)
		}
	})
	t.Run("cancellation interrupts blocked read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		src, producer := io.Pipe()
		defer src.Close()
		defer producer.Close()
		editor := newTerminalInput(ctx, newInput(ctx, src), io.Discard, 80, 24)
		done := make(chan error, 1)
		go func() { _, e := editor.ReadPrompt("", 4096); done <- e }()
		cancel()
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
		case <-time.After(time.Second):
			t.Fatal("canceled editor read hung")
		}
	})
}

func sshPipeCommand(t *testing.T, address, command string, stdin []byte, terminal bool) ([]byte, []byte, int) {
	t.Helper()
	path, args := testfixture.OpenSSH(t, address, terminal, command)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	e := cmd.Run()
	code := 0
	if e != nil {
		var exit *exec.ExitError
		if !errors.As(e, &exit) {
			t.Fatal(e)
		}
		code = exit.ExitCode()
	}
	if ctx.Err() != nil {
		t.Fatal("OpenSSH pipe command timed out")
	}
	return out.Bytes(), diagnostic.Bytes(), code
}

func sshPTYLobbyInput(t *testing.T, address string, input []byte) {
	t.Helper()
	raw, e := net.DialTimeout("tcp", address, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	if e := raw.SetDeadline(time.Now().Add(30 * time.Second)); e != nil {
		t.Fatal(e)
	}
	conn, channels, requests, e := ssh.NewClientConn(raw, address, &ssh.ClientConfig{User: "explicit-test-domain", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if e != nil {
		t.Fatal(e)
	}
	client := ssh.NewClient(conn, channels, requests)
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	if e := session.RequestPty("xterm-256color", 30, 120, ssh.TerminalModes{}); e != nil {
		t.Fatal(e)
	}
	var out, diagnostic bytes.Buffer
	session.Stdin = bytes.NewReader(input)
	session.Stdout, session.Stderr = &out, &diagnostic
	if e := session.Shell(); e != nil {
		t.Fatal(e)
	}
	if e := session.Wait(); e != nil {
		t.Fatal("real PTY lobby input", e, diagnostic.String())
	}
}

func TestTerminalOpenSSHActualSDKInventoryConfirmationAndGuest(t *testing.T) {
	rootfs := testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true)
	registry := testfixture.OCIRegistry(t, rootfs)
	cfg := daemon.Config(t, registry)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	n := daemon.Open(t, cfg, "terminal-native", 8)
	r := n.Runtime
	svc := &service.Service{Runtime: r, Audit: n.Audit, Jobs: n.Jobs, Config: cfg}
	peer := daemon.Peer(cfg, "explicit-domain-native-terminal", "user:7")
	caller := service.Caller{Peer: peer, Resolve: func(ctx context.Context) (identity.Peer, error) { return peer, ctx.Err() }}
	address := terminalSSHServer(t, svc, caller)
	var diagnostic bytes.Buffer
	beforeCreate := time.Now().Truncate(time.Second)
	if code := DispatchSession(ctx, svc, caller, "create "+registry.Reference+" --name terminal-vm --no-start", service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	view, e := svc.Show(ctx, peer, "terminal-vm")
	if e != nil {
		t.Fatal(e)
	}
	if view.Created.Before(beforeCreate) || view.Created.After(time.Now()) {
		t.Fatalf("actual native creation date outside current wall-clock window: %s", view.Created)
	}
	for _, command := range []string{"whoami", "help", "ls", "show terminal-vm"} {
		one := openTerminalClient(t, address, command)
		one.exit(t)
		assertTerminalNewlines(t, one.text())
		if command == "ls" && !strings.Contains(one.text(), "terminal-vm") {
			t.Fatal("real inventory absent", one.text())
		}
		if command == "ls" && !regexp.MustCompile(`terminal-vm[^\r\n]+(Less than a second ago|[0-9]+ seconds ago|About a minute ago)`).MatchString(one.text()) {
			t.Fatal("actual terminal inventory creation age is stale", one.text())
		}
		if command == "show terminal-vm" && !strings.Contains(one.text(), "Created: "+view.Created.UTC().Format("2006-01-02 15:04:05 UTC")) {
			t.Fatal("actual terminal creation date missing", one.text())
		}
		// Capture the same real PTY-request session's extended stderr without
		// any client OS terminal output processing that could hide bare LFs.
		var expected bytes.Buffer
		if code := DispatchSession(ctx, svc, caller, command, service.IO{Stdout: io.Discard, Stderr: &expected}); code != 0 {
			t.Fatal(code)
		}
		out, errOut, code := sshPipeCommand(t, address, command, nil, true)
		want := strings.ReplaceAll(expected.String(), "\n", "\r\n")
		if code != 0 || len(out) != 0 || string(errOut) != want {
			t.Fatalf("PTY human stderr bytes: %s %d %q %q, want %q", command, code, out, errOut, want)
		}
	}
	for _, command := range []string{"ls --json", "whoami --json", "unknown-command --json"} {
		var wantOut, wantErr bytes.Buffer
		wantCode := DispatchSession(ctx, svc, caller, command, service.IO{Stdout: &wantOut, Stderr: &wantErr})
		out, errOut, code := sshPipeCommand(t, address, command, nil, false)
		if code != wantCode || !bytes.Equal(out, wantOut.Bytes()) || !bytes.Equal(errOut, wantErr.Bytes()) {
			t.Fatalf("non-PTY bytes changed for %s: %d %q %q, want %d %q %q", command, code, out, errOut, wantCode, wantOut.Bytes(), wantErr.Bytes())
		}
	}
	// The real rm command uses readLineLimit. It must share the editor even
	// for exec requests, where the lobby has never read a command line.
	one := openTerminalClient(t, address, "rm terminal-vm")
	one.wait(t, "Remove VM 'terminal-vm'? [y/N] ", 1)
	one.send(t, "ye界\x7fs\r\n")
	one.exit(t)
	assertTerminalNewlines(t, one.text())
	if !strings.Contains(one.text(), "ye界") {
		t.Fatal("confirmation was not echoed", one.text())
	}
	if _, e := svc.Show(ctx, peer, "terminal-vm"); e == nil || service.Categorize(e).Exit != 3 {
		t.Fatal("actual confirmation did not remove VM", e)
	}
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("inventory and confirmation passed; guest handoff requires SILO_E2E_KVM=1")
	}
	payload := "#!/bin/sh\nexit 0\n#" + strings.Repeat("x", 5000) + "\r\n# controls:\x03\x04\x08\x7f\t\x1b[200~paste\x1b[201~\r\n"
	for _, mode := range []string{"exec", "lobby"} {
		name := "userdata-" + mode
		command := "create " + registry.Reference + " --name " + name + " --no-start --userdata -"
		if mode == "exec" {
			out, errOut, code := sshPipeCommand(t, address, command, []byte(payload), true)
			if code != 0 || len(out) != 0 || bytes.Contains(errOut, []byte("\x1b[?2004h")) {
				t.Fatalf("raw userdata entered editor: %d %q %q", code, out, errOut)
			}
		} else {
			sshPTYLobbyInput(t, address, []byte(command+"\r\n"+payload))
		}
		view, e := svc.Show(ctx, peer, name)
		if e != nil || view.State != silo.MachineStatusStopped {
			t.Fatal("userdata create must remain stopped", view, e)
		}
		started, e := r.Control.Start(ctx, view.ID)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := r.Control.WaitReady(ctx, view.ID, started.RunID, 20*time.Second); e != nil {
			t.Fatal(e)
		}
		var actual, guestErr bytes.Buffer
		code, e := svc.Exec(ctx, caller, name, service.ExecRequest{Program: "/bin/cat", Args: []string{"/var/lib/silo-agent/userdata.sh"}}, service.IO{Stdout: &actual, Stderr: &guestErr})
		if code != 0 || e != nil || actual.String() != payload {
			t.Fatalf("guest userdata changed (%s): %d %v %q, want %q", mode, code, e, actual.String(), payload)
		}
		_, e = r.Control.Stop(ctx, view.ID, &started.RunID, silo.StopOptions{Force: true, Timeout: time.Second})
		if e != nil {
			t.Fatal(e)
		}
	}
	diagnostic.Reset()
	if code := DispatchSession(ctx, svc, caller, "create "+registry.Reference+" --name terminal-guest", service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	lobby := openTerminalClient(t, address, "")
	lobby.wait(t, lobbyPrompt, 1)
	// One transport write contains the command and immediate guest bytes.
	// The guest receives the bytes after CRLF untouched, without editor echo.
	lobby.send(t, "exec terminal-guest -- /bin/sh -c 'read line; printf \"GUEST:%s\\n\" \"$line\"'\r\nretained-immediate\n")
	lobby.wait(t, "GUEST:retained-immediate\r\n", 1)
	lobby.wait(t, lobbyPrompt, 2)
	lobby.send(t, "\x04")
	lobby.exit(t)
	assertTerminalNewlines(t, lobby.text())
	if strings.Count(lobby.text(), "retained-immediate") != 1 {
		t.Fatal("guest input echoed by editor or replayed", lobby.text())
	}
	command := `exec terminal-guest -- /bin/sh -c 'printf "\000\377\015\012"; printf "\000\377\015\012" >&2'`
	out, errOut, code := sshPipeCommand(t, address, command, nil, false)
	want := []byte{0, 255, 13, 10}
	if code != 0 || !bytes.Equal(out, want) || !bytes.Equal(errOut, want) {
		t.Fatalf("raw guest binary streams changed: %d %x %x", code, out, errOut)
	}
}
