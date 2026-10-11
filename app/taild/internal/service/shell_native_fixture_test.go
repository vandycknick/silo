package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	silo "github.com/vandycknick/silo/sdk/go"
	"golang.org/x/term"
	"google.golang.org/protobuf/types/known/emptypb"
)

func qualifyIndependentShell(t *testing.T) {
	t.Helper()
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required")
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	kvm.Close()
	disk := os.Getenv("SILO_TEST_DISK_IMAGE")
	if !filepath.IsAbs(disk) {
		t.Fatal("SILO_TEST_DISK_IMAGE must name an absolute disposable ext4 fixture")
	}
	if _, err := os.Stat(disk); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	s, sdk := actualNativeService(t)
	caller := domainCaller(s, "user:7")
	userdata := `#!/bin/sh
set -eu
for binary in systemctl systemd-run timeout cat; do command -v "$binary"; done
test -x /usr/lib/systemd/system-generators/systemd-ssh-generator
test -x /usr/sbin/sshd
timeout 15 /bin/sh -c 'until timeout 1 systemctl show --property=Version >/dev/null 2>&1; do sleep 0.2; done'
timeout 5 systemctl daemon-reload
timeout 5 systemctl start sshd-vsock.socket
timeout 5 systemctl is-active --quiet sshd-vsock.socket
`
	m, err := sdk.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("independent-shell"), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithVsock(true), silo.WithMachineNetwork(silo.NoNetwork()), silo.WithGuestUser("silo", 1000, 1000, "/home/silo"), silo.WithUserdata(userdata), silo.WithLabels(map[string]string{runtime.OwnerLabel: "user:7", runtime.NameLabel: "independent-shell", runtime.InstanceLabel: s.Runtime.Instance, runtime.ModeLabel: "none"}))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		d, err := m.Inspect(cleanup)
		if err == nil {
			_, err = s.Runtime.Control.Stop(cleanup, m.ID(), d.RunID, silo.StopOptions{Force: true, Timeout: time.Second})
		}
		if err != nil {
			t.Error("fixture stop:", err)
			return
		}
		if err := s.Runtime.Control.Remove(cleanup, m.ID()); err != nil {
			t.Error("fixture remove:", err)
		}
	}()
	if _, err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := m.WaitReady(ctx, 35*time.Second); err != nil {
		t.Fatal(err)
	}
	literal, err := m.Exec(ctx, "/usr/bin/printf", []string{"%s", "$HOME"})
	if err != nil || literal.Stdout() != "$HOME" {
		t.Fatal(literal, err)
	}
	script, err := m.ExecScript(ctx, "printf '%s' \"$((6*7))\"")
	if err != nil || script.Stdout() != "42" {
		t.Fatal(script, err)
	}
	session, err := m.Spawn(ctx, "/bin/cat", nil, silo.WithExecStdinPipe())
	if err != nil {
		t.Fatal(err)
	}
	var cat bytes.Buffer
	for {
		event, err := session.Recv(ctx)
		if err != nil {
			session.Close()
			t.Fatal(err)
		}
		if event.Kind == silo.ExecutionEventStarted {
			stdin := session.Stdin()
			if stdin == nil {
				t.Fatal("Started without stdin")
			}
			if _, err := stdin.WriteContext(ctx, []byte("literal cat\n")); err != nil {
				t.Fatal(err)
			}
			if err := stdin.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if event.Kind == silo.ExecutionEventStdout {
			cat.Write(event.Data)
		}
		if event.Kind == silo.ExecutionEventTerminal {
			if event.Result == nil || event.Result.Code == nil || *event.Result.Code != 0 {
				t.Fatal(event.Result)
			}
			break
		}
	}
	session.Close()
	if cat.String() != "literal cat\n" {
		t.Fatal(cat.String())
	}
	shell := func(user, command string) string {
		t.Helper()
		var output bytes.Buffer
		code, err := s.Shell(ctx, caller, m.ID(), user, IO{Stdin: strings.NewReader(command + "\n"), Stdout: &output, Stderr: &output, Terminal: Terminal{Present: true, Window: Window{37, 119}, Term: "xterm-256color"}})
		if err != nil || code != 7 {
			t.Fatalf("shell %s: code=%d error=%v output=%q", user, code, err, output.String())
		}
		return output.String()
	}
	proof := `printf 'USER=%s HOME=%s TERM=%s SIZE=' "$USER" "$HOME" "$TERM"; stty size; exit 7`
	if out := shell("", proof); !strings.Contains(out, "USER=silo HOME=/home/silo TERM=xterm-256color SIZE=37 119") {
		t.Fatal(out)
	}
	// sshd's PTY merges guest fd1/fd2; verify both exact payloads without
	// pretending VM PTY output can prove SSH ExtendedData separation.
	bulk := shell("", `printf '\nBULK_BEGIN\n'; head -c 131073 /dev/zero | tr '\000' x; head -c 131079 /dev/zero | tr '\000' y >&2; printf '\nBULK_END\n'; exit 7`)
	normalized := strings.ReplaceAll(bulk, "\r\n", "\n")
	begin := strings.Index(normalized, "\nBULK_BEGIN\n")
	end := strings.Index(normalized, "\nBULK_END\n")
	if begin < 0 || end < begin || normalized[begin+len("\nBULK_BEGIN\n"):end] != strings.Repeat("x", 131073)+strings.Repeat("y", 131079) {
		t.Fatal("shell buffered stdout/stderr were not drained exactly")
	}
	var blockedOutput bytes.Buffer
	blockedCode, blockedErr := s.Shell(ctx, caller, m.ID(), "", IO{
		Input: func(inputCtx context.Context) io.Reader {
			return io.MultiReader(strings.NewReader("printf '%s\\n' blocked-input-complete; exit 7\n"), fileContextReader{ctx: inputCtx, reader: fixtureBlockedInput{}})
		},
		Stdout: &blockedOutput, Stderr: &blockedOutput, Terminal: Terminal{Present: true, Window: Window{37, 119}, Term: "xterm-256color"},
	})
	if blockedErr != nil || blockedCode != 7 || !strings.Contains(blockedOutput.String(), "blocked-input-complete") {
		t.Fatal(blockedCode, blockedErr, blockedOutput.String())
	}
	// Two EOT bytes plus SSH channel EOF do not guarantee arbitrary login
	// shells exit: a shell may change canonical/readline modes during startup.
	// Preserve the protocol policy and bound this case with caller cancellation.
	emptyCtx, cancelEmpty := context.WithTimeout(ctx, 2*time.Second)
	emptyCode, emptyErr := s.Shell(emptyCtx, caller, m.ID(), "", IO{Stdout: io.Discard, Stderr: io.Discard, Terminal: Terminal{Present: true, Window: Window{37, 119}, Term: "xterm-256color"}})
	emptyCanceled := emptyCtx.Err() != nil
	cancelEmpty()
	if emptyErr != nil && !emptyCanceled {
		t.Fatal("empty-input shell failed before cancellation", emptyCode, emptyErr)
	}
	for i := range 50 {
		output := shell("", `printf 'REPEAT=%s\n' "$((6*7))"; exit 7`)
		if !strings.Contains(output, "REPEAT=42") {
			t.Fatalf("repeat %d: %q", i, output)
		}
	}
	qualifyServiceShellSinks(t, ctx, s, caller, m.ID())
	root := fixtureRepositoryRoot(t)
	goExample := filepath.Join(t.TempDir(), "shell-example")
	run := func(name string, args ...string) string {
		t.Helper()
		child, stop := context.WithTimeout(ctx, 25*time.Second)
		defer stop()
		cmd := exec.CommandContext(child, name, args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "SILO_HOME="+s.Config.Home)
		output, err := cmd.CombinedOutput()
		expected := 0
		if name == filepath.Join(root, "target/debug/examples/execution") || name == goExample || (name == "node" && len(args) > 0 && args[0] == "sdk/node/examples/shell.mjs") {
			expected = 7
		}
		actual := 0
		if err != nil {
			var exited *exec.ExitError
			if !errors.As(err, &exited) {
				t.Fatalf("%s %v: %v\n%s", name, args, err, output)
			}
			actual = exited.ExitCode()
		}
		if actual != expected {
			t.Fatalf("%s %v: exit=%d expected=%d\n%s", name, args, actual, expected, output)
		}
		return string(output)
	}
	rust := filepath.Join(root, "target/debug/examples/execution")
	rustRun := func() {
		out := run(rust, m.ID(), "embedded-shell")
		if !strings.Contains(out, "embedded:silo") || !strings.Contains(out, "7") {
			t.Fatal(out)
		}
	}
	rustRun()
	run("node", "sdk/node/tests/integration/shell-smoke.mjs", s.Config.Home, m.ID(), "all")
	run("go", "-C", "sdk/go", "build", "-o", goExample, "./examples/shell")
	run(goExample, m.ID())
	run("node", "sdk/node/examples/shell.mjs", m.ID())
	// Find the real process and arm recovery before stopping it. This executes
	// through the independently owned SSH listener, never guest identity RPC.
	pause := `pid=; for p in /proc/[0-9]*; do test "$(cat "$p/comm" 2>/dev/null)" = silo-agent && pid=${p##*/} && break; done; test -n "$pid"; printf '%s' "$pid" >/run/silo-shell-agent-pid; systemd-run --quiet --unit=silo-shell-resume --on-active=90s /bin/kill -CONT "$pid"; kill -STOP "$pid"; grep '^State:.*T' /proc/$pid/status; exit 7`
	if out := shell("root", pause); !strings.Contains(out, "State:") {
		t.Fatal(out)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		var out bytes.Buffer
		_, err := m.Shell(cleanup, silo.WithSSHUser("root"), silo.WithShellAttachment(silo.SSHShellAttachment{Rows: 24, Columns: 80, Input: func(context.Context) io.Reader {
			return strings.NewReader("kill -CONT $(cat /run/silo-shell-agent-pid); exit\n")
		}, Stdout: finiteShellWriter{&out}, Stderr: finiteShellWriter{&out}}))
		if err != nil {
			t.Error("resume:", err, out.String())
		}
	}()
	deadline := time.NewTimer(40 * time.Second)
	defer deadline.Stop()
	for {
		d, err := m.Inspect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if d.Status.Kind != silo.MachineStatusRunning {
			t.Fatal(d.Status)
		}
		if d.Status.Ready != nil && !*d.Status.Ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatal("agent health did not expire")
		case <-time.After(250 * time.Millisecond):
		}
	}
	stoppedProof := `grep '^State:.*T' /proc/$(cat /run/silo-shell-agent-pid)/status; ` + proof
	if out := shell("", stoppedProof); !strings.Contains(out, "USER=silo HOME=/home/silo TERM=xterm-256color SIZE=37 119") || !strings.Contains(out, "State:") {
		t.Fatal(out)
	}
	run("node", "sdk/node/tests/integration/shell-smoke.mjs", s.Config.Home, m.ID(), "ssh-only")
	rustRun()
	qualifyShellCLI(t, ctx, s, m.ID())
	qualifyShellCancellation(t, ctx, m)
}

func fixtureRepositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "sdk/node/package.json")); err == nil {
			return root
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("repository root not found")
		}
		root = parent
	}
}

func qualifyShellCLI(t *testing.T, ctx context.Context, s *Service, id string) {
	t.Helper()
	cli := os.Getenv("SILO_TEST_CLI")
	if cli == "" {
		t.Fatal("SILO_TEST_CLI required")
	}
	manager, err := s.Runtime.Control.Daemon.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	child, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	cmd := exec.CommandContext(child, cli, "shell", id)
	cmd.Env = append(os.Environ(), "HOME="+string(manager.Home), "SILO_HOME="+string(manager.Home), "XDG_CONFIG_HOME="+filepath.Dir(string(manager.ConfigDir)))
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := pty.Setsize(master, &pty.Winsize{Rows: 37, Cols: 119}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	drained := make(chan struct{})
	go func() { defer close(drained); io.Copy(&output, master) }()
	// Wait until the CLI has taken raw-terminal ownership, so its initial
	// terminal transition cannot flush the command queued by this fixture.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, stateErr := term.GetState(int(slave.Fd()))
		if stateErr != nil {
			t.Fatal(stateErr)
		}
		if !reflect.DeepEqual(before, current) {
			break
		}
		select {
		case <-child.Done():
			_ = cmd.Wait()
			slave.Close()
			<-drained
			t.Fatalf("CLI did not acquire raw terminal: %v %q", child.Err(), output.String())
		case <-ticker.C:
		}
	}
	if _, err := master.Write([]byte("printf 'CLI_COMPUTED=%s\\n' \"$((21*2))\"; exit 7\n")); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	after, stateErr := term.GetState(int(slave.Fd()))
	slave.Close()
	<-drained
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 7 {
		t.Fatalf("CLI: %v %q", err, output.String())
	}
	if !strings.Contains(output.String(), "CLI_COMPUTED=42") {
		t.Fatal(output.String())
	}
	if stateErr != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("CLI terminal restoration", stateErr)
	}
}

func qualifyShellCancellation(t *testing.T, ctx context.Context, m *silo.Machine) {
	t.Helper()
	active, cancel := context.WithCancel(ctx)
	defer cancel()
	started := make(chan struct{})
	result := make(chan error, 1)
	firstOutput := &fixtureShellObserver{marker: "FIRST_READY=42", observed: started}
	go func() {
		_, err := m.Shell(active, silo.WithShellAttachment(silo.SSHShellAttachment{
			Rows: 24, Columns: 80,
			Input: func(input context.Context) io.Reader {
				return io.MultiReader(strings.NewReader("printf 'FIRST_READY=%s\\n' \"$((6*7))\"\n"), fileContextReader{ctx: input, reader: fixtureBlockedInput{}})
			},
			Stdout: firstOutput, Stderr: firstOutput,
		}))
		result <- err
	}()
	select {
	case <-started:
	case err := <-result:
		t.Fatal("first shell did not become usable", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	secondOutput := &fixtureShellObserver{marker: "SECOND_READY=42", onObserved: cancel}
	status, err := m.Shell(ctx, silo.WithShellAttachment(silo.SSHShellAttachment{
		Rows: 24, Columns: 80,
		Input: func(context.Context) io.Reader {
			return strings.NewReader("printf 'SECOND_READY=%s\\n' \"$((6*7))\"; sleep 0.1; exit 7\n")
		},
		Stdout: secondOutput, Stderr: secondOutput,
	}))
	if err != nil || status.Code != 7 || !secondOutput.seen {
		t.Fatal("second shell did not survive first cancellation", status, err, secondOutput.output.String())
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled shell succeeded")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var out bytes.Buffer
	status, err = m.Shell(ctx, silo.WithShellAttachment(silo.SSHShellAttachment{Rows: 24, Columns: 80, Input: func(context.Context) io.Reader { return strings.NewReader("exit 7\n") }, Stdout: finiteShellWriter{&out}, Stderr: finiteShellWriter{&out}}))
	if err != nil || status.Code != 7 {
		t.Fatal(status, err)
	}
}

type fixtureBlockedInput struct{}

func (fixtureBlockedInput) ReadContext(ctx context.Context, p []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

// SDK serializes stdout/stderr callbacks, including when both use this writer.
// Markers contain computed guest output so input echo cannot signal readiness.
type fixtureShellObserver struct {
	marker     string
	observed   chan struct{}
	onObserved func()
	output     bytes.Buffer
	seen       bool
}

func (w *fixtureShellObserver) WriteContext(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := w.output.Write(p)
	if !w.seen && strings.Contains(w.output.String(), w.marker) {
		w.seen = true
		if w.observed != nil {
			close(w.observed)
		}
		if w.onObserved != nil {
			w.onObserved()
		}
	}
	return n, err
}

func qualifyServiceShellSinks(t *testing.T, parent context.Context, s *Service, caller Caller, id string) {
	t.Helper()
	t.Run("sink-failure-with-output-backpressure", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parent, 8*time.Second)
		defer cancel()
		sentinel := errors.New("fixture sink failed")
		entered, release := make(chan struct{}), make(chan struct{})
		writer := &fixtureGatedShellWriter{marker: "FLOOD_READY=42", entered: entered, release: release, failure: sentinel}
		result := make(chan error, 1)
		windows := make(chan Window, 1)
		go func() {
			_, err := s.Shell(ctx, caller, id, "", IO{
				Input: func(inputCtx context.Context) io.Reader {
					return io.MultiReader(strings.NewReader("printf 'FLOOD_READY=%s\\n' \"$((6*7))\"; while :; do head -c 262144 /dev/zero | tr '\\000' x; done\n"), fileContextReader{ctx: inputCtx, reader: fixtureBlockedInput{}})
				},
				Stdout: writer, Stderr: writer,
				Terminal: Terminal{Present: true, Window: Window{37, 119}, Term: "xterm-256color", Windows: windows},
			})
			result <- err
		}()
		select {
		case <-entered:
		case err := <-result:
			t.Fatal("shell failed before sink gate", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		windows <- Window{38, 120}
		// Hold the cooperative sink while the unbounded real guest producer fills
		// the bounded native output transport; then fail the pending sink call.
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
		close(release)
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("sink failure was lost")
			}
		case <-ctx.Done():
			t.Fatal("sink failure did not join shell", ctx.Err())
		}
	})
	t.Run("cancel-final-output-delivery", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parent, 8*time.Second)
		defer cancel()
		entered := make(chan struct{})
		writer := &fixtureGatedShellWriter{marker: "DRAIN_DONE=42", entered: entered}
		result := make(chan error, 1)
		go func() {
			_, err := s.Shell(ctx, caller, id, "", IO{
				Input: func(inputCtx context.Context) io.Reader {
					return io.MultiReader(strings.NewReader("head -c 131073 /dev/zero | tr '\\000' x; head -c 131079 /dev/zero | tr '\\000' y >&2; printf '\\nDRAIN_DONE=%s\\n' \"$((6*7))\"; exit 7\n"), fileContextReader{ctx: inputCtx, reader: fixtureBlockedInput{}})
				},
				Stdout: writer, Stderr: writer, Terminal: Terminal{Present: true, Window: Window{37, 119}, Term: "xterm-256color"},
			})
			result <- err
		}()
		select {
		case <-entered:
		case err := <-result:
			t.Fatal("shell completed before final sink gate", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if !strings.Contains(writer.output.String(), strings.Repeat("x", 131073)+strings.Repeat("y", 131079)) {
			cancel()
			t.Fatal("final sink did not receive exact guest stdout/stderr")
		}
		cancel()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("output cancellation was lost")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancelled output sink did not join shell")
		}
	})
	// A failed/cancelled attachment must not close a borrowed outer transport or
	// poison the machine's next independently authenticated shell.
	var output bytes.Buffer
	code, err := s.Shell(parent, caller, id, "", IO{Stdin: strings.NewReader("printf 'RECONNECT=%s\\n' \"$((6*7))\"; exit 7\n"), Stdout: &output, Stderr: &output, Terminal: Terminal{Present: true, Window: Window{37, 119}, Term: "xterm-256color"}})
	if err != nil || code != 7 || !strings.Contains(output.String(), "RECONNECT=42") {
		t.Fatal(code, err, output.String())
	}
}

type fixtureGatedShellWriter struct {
	marker  string
	entered chan struct{}
	release <-chan struct{}
	failure error
	output  bytes.Buffer
	gated   bool
}

func (w *fixtureGatedShellWriter) Write([]byte) (int, error) {
	return 0, errors.New("plain Write must not be used for shell output")
}
func (w *fixtureGatedShellWriter) WriteContext(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := w.output.Write(p)
	if !w.gated && strings.Contains(w.output.String(), w.marker) {
		w.gated = true
		close(w.entered)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-w.release:
		}
		if w.failure != nil {
			return 0, w.failure
		}
	}
	return n, err
}
