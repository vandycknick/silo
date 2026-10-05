//go:build e2e

// These tests use explicit principal/capability INPUT below authentication,
// actual service commands, public SDK/native bridge, OCI and KVM. They do not
// emulate WhoIs or qualify registered tailnet identity.
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
)

// principal is explicit domain identity below WhoIs, never a tailnet peer.
func principal(c config.Config, owner identity.Principal) service.Caller {
	peer := daemon.Peer(c, "explicit-native-input-"+string(owner), owner)
	return service.Caller{Peer: peer, Resolve: func(ctx context.Context) (identity.Peer, error) { return peer, ctx.Err() }}
}
func TestNativeKVMServiceLifecyclePTYAndReopen(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required")
	}
	rootfs := testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true)
	kvm, e := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	_ = kvm.Close()
	registry := testfixture.OCIRegistry(t, rootfs)
	c := daemon.Config(t, registry)
	c.VM.Defaults.Memory = 1 << 30
	audit, e := state.OpenAudit(c.Home, 1<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	r, e := runtime.Open(context.Background(), c, "native-e2e")
	if e != nil {
		t.Fatal(e)
	}
	jobctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &service.Service{Runtime: r, Audit: audit, Jobs: jobs.New(jobctx, 16), Config: c}
	// Only this isolated home is ever cleaned. The shared generated fixtures are
	// read-only sources, and no user/previous-phase machine is opened.
	defer func() {
		ctx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		cancel()
		_ = s.Jobs.Wait(ctx)
		entries, _ := s.Runtime.SDK.Inventory(ctx)
		for _, entry := range entries {
			m, e := s.Runtime.SDK.Machine(ctx, entry.ID)
			if e == nil {
				_, _ = m.StopWith(ctx, silo.StopOptions{Force: true, Timeout: time.Second})
				_ = m.Remove(ctx)
				_ = m.Close()
			}
		}
		_ = s.Runtime.Close()
	}()
	one, two := principal(c, "user:11"), principal(c, "user:22")
	ctx := context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	registry.BeforeManifest = func() { first.Do(func() { close(entered); <-release }) }
	observer, disconnect := context.WithCancel(ctx)
	observerDone := make(chan int, 1)
	var observerOut, observerErr lockedBuffer
	go func() {
		observerDone <- sshd.DispatchSession(observer, s, one, "create --name native-one --provision-user silo:1000:1000:/home/silo", service.IO{Stdout: &observerOut, Stderr: &observerErr})
	}()
	select {
	case <-entered:
	case code := <-observerDone:
		t.Fatalf("create observer exited early %d %s", code, observerErr.String())
	case <-time.After(20 * time.Second):
		t.Fatal("native registry not reached")
	}
	ops := s.Jobs.List(one.Peer)
	if len(ops) != 1 {
		t.Fatal(ops)
	}
	op := ops[0]
	disconnect()
	select {
	case code := <-observerDone:
		if code != 255 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("operation observer did not detach")
	}
	close(release)
	daemon.Succeeded(t, s.Jobs, one.Peer, op, nil)
	op, e = s.Create(ctx, two, service.CreateRequest{Name: "native-two", NoStart: true})
	daemon.Succeeded(t, s.Jobs, two.Peer, op, e)
	for _, caller := range []service.Caller{one, two} {
		v, e := s.List(ctx, caller.Peer)
		if e != nil || len(v) != 1 {
			t.Fatal(v, e)
		}
	}
	var inventoryJSON, inventoryHuman bytes.Buffer
	if code := sshd.DispatchSession(ctx, s, one, "list --json", service.IO{Stdout: &inventoryJSON, Stderr: &inventoryHuman}); code != 0 || !strings.Contains(inventoryJSON.String(), "native-one") || strings.Contains(inventoryJSON.String(), "native-two") {
		t.Fatal("native CLI list isolation", code, inventoryJSON.String())
	}
	who, e := s.WhoAmI(one.Peer)
	if e != nil || len(who.Peer.Principals) != 1 || who.Peer.Principals[0] != "user:11" {
		t.Fatal(who, e)
	}
	ci := principal(c, "tag:ci")
	ci.Peer.Permissions.Actions = []identity.Action{identity.Create, identity.Read, identity.Exec}
	ci.Resolve = func(ctx context.Context) (identity.Peer, error) { return ci.Peer, ctx.Err() }
	op, e = s.Create(ctx, ci, service.CreateRequest{Name: "native-ci"})
	daemon.Succeeded(t, s.Jobs, ci.Peer, op, e)
	if code, e := s.Shell(ctx, ci, "native-ci", "", service.IO{Stdout: io.Discard, Stderr: io.Discard, Terminal: service.Terminal{Present: true, Window: service.Window{Rows: 24, Columns: 80}}}); code != 4 || service.Categorize(e).Exit != 4 {
		t.Fatal("create/read/exec-only principal got shell", code, e)
	}
	if code, e := s.Exec(ctx, ci, "native-ci", service.ExecRequest{Program: "/bin/id", Args: []string{"-u"}}, service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 0 || e != nil {
		t.Fatal("create/read/exec principal exec denied", code, e)
	}
	ci.Peer.Permissions.Actions = append(ci.Peer.Permissions.Actions, identity.Delete, identity.Stop)
	op, e = s.Remove(ctx, ci, "native-ci", service.RemoveRequest{Force: true})
	daemon.Succeeded(t, s.Jobs, ci.Peer, op, e)
	if _, e = s.Show(ctx, two.Peer, "native-one"); service.Categorize(e).Exit != 3 {
		t.Fatal("positive-user isolation failed", e)
	}
	var out, errout bytes.Buffer
	code, e := s.Exec(ctx, one, "native-one", service.ExecRequest{Program: "/bin/bash", Args: []string{"-c", `printf 'env=%s uid=' "$SILO_NATIVE_ENV"; id -u; printf 'guest-stderr' >&2; printf 'cwd=%s\n' "$PWD"`}, Env: map[string]string{"SILO_NATIVE_ENV": "guest-only"}, Directory: "/home/silo"}, service.IO{Stdout: &out, Stderr: &errout})
	if e != nil || code != 0 || !strings.Contains(out.String(), "env=guest-only uid=1000") || !strings.Contains(out.String(), "cwd=/home/silo") || errout.String() != "guest-stderr" {
		t.Fatalf("exec code %d err %v stdout %q stderr %q", code, e, out.String(), errout.String())
	}
	if os.Getenv("SILO_NATIVE_ENV") != "" {
		t.Fatal("guest environment escaped to host")
	}
	var shell bytes.Buffer
	code, e = s.Shell(ctx, one, "native-one", "", service.IO{Stdin: strings.NewReader("stty size\nprintf 'TERM=%s\\n' \"$TERM\"\nid -u\nexit 3\n"), Stdout: &shell, Stderr: io.Discard, Terminal: service.Terminal{Present: true, Window: service.Window{Rows: 37, Columns: 119}, Term: "s11-terminal"}})
	if e != nil || code != 3 || !strings.Contains(shell.String(), "37 119") || !strings.Contains(shell.String(), "TERM=s11-terminal") {
		t.Fatalf("shell %d %v %q", code, e, shell.String())
	}
	if code, e = s.Shell(ctx, one, "native-one", "", service.IO{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard, Terminal: service.Terminal{Present: true, Window: service.Window{Rows: 24, Columns: 80}}}); e != nil || code != 0 {
		t.Fatal("PTY stdin EOF did not end login shell", code, e)
	}
	if code, e = s.Exec(ctx, one, "native-one", service.ExecRequest{Program: "/no-such-guest-program"}, service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 127 || service.Categorize(e).Exit != 127 {
		t.Fatal("guest command category", code, e)
	}
	if code, e = s.Shell(ctx, one, "native-one", "", service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 2 || service.Categorize(e).Exit != 2 {
		t.Fatal("non-PTY shell accepted")
	}
	probeControls(t, s, one, "native-one")
	probePTYEOF(t, s, one, "native-one")
	probeOutputFailures(t, s, one, "native-one")
	probeSDKLazyStdin(t, s, "native-one")
	probeStreamAuthorization(t, s, one, "native-one")
	op, e = s.Remove(ctx, one, "native-one", service.RemoveRequest{})
	v := daemon.WaitOperation(t, s.Jobs, one.Peer, op, e)
	if v.Error == nil || v.Error.Exit != 5 {
		t.Fatal("running rm accepted", v)
	}
	if code := sshd.DispatchSession(ctx, s, one, "rm native-one", service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 5 {
		t.Fatal("unattended running rm category", code)
	}
	var logs bytes.Buffer
	if e = s.Logs(ctx, one, "native-one", service.LogsRequest{Source: silo.MachineLogSerial}, &logs); e != nil || logs.Len() == 0 || logs.Len() > 4<<20 || strings.Contains(logs.String(), c.Home) {
		t.Fatal("unsafe/empty native logs", e, logs.Len())
	}
	// Genuine drain, native handle close, constructor reopen. A VM's run ID must
	// survive unchanged, not just return to the same high-level Running state.
	m, e := r.SDK.Machine(ctx, "native-one")
	if e != nil {
		t.Fatal(e)
	}
	before, e := m.Inspect(ctx)
	_ = m.Close()
	if e != nil || before.RunID == nil {
		t.Fatal(e)
	}
	drain, done := context.WithTimeout(ctx, 90*time.Second)
	if e = s.Jobs.Wait(drain); e != nil {
		t.Fatal(e)
	}
	done()
	cancel()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = runtime.Open(ctx, c, "native-e2e")
	if e != nil {
		t.Fatal(e)
	}
	jobctx, cancel = context.WithCancel(ctx)
	defer cancel()
	s = &service.Service{Runtime: r, Audit: audit, Jobs: jobs.New(jobctx, 16), Config: c}
	m, e = r.SDK.Machine(ctx, "native-one")
	if e != nil {
		t.Fatal(e)
	}
	after, e := m.Inspect(ctx)
	_ = m.Close()
	if e != nil || after.RunID == nil || *before.RunID != *after.RunID || after.Status.Kind != silo.MachineStatusRunning {
		t.Fatalf("reopen changed VM %+v %v", after, e)
	}
	t.Logf("unchanged running VM ID=%s run=%s", after.ID, *after.RunID)
	if len(s.Jobs.List(one.Peer)) != 0 {
		t.Fatal("operation registry survived restart")
	}
	beforeGoroutines := goruntime.NumGoroutine()
	for i := 0; i < 50; i++ {
		code, e = s.Shell(ctx, one, "native-one", "", service.IO{Stdin: strings.NewReader("exit 3\n"), Stdout: io.Discard, Stderr: io.Discard, Terminal: service.Terminal{Present: true, Window: service.Window{Rows: 24, Columns: 80}}})
		if e != nil || code != 3 {
			t.Fatalf("shell %d: %d %v", i, code, e)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := goruntime.NumGoroutine(); n > beforeGoroutines+8 {
		t.Fatalf("50-shell goroutine growth %d -> %d", beforeGoroutines, n)
	}
	probeLostExecution(t, s, one, "native-one")
	op, e = s.Stop(ctx, one, "native-one", service.StopRequest{Force: true, Timeout: time.Second})
	daemon.Succeeded(t, s.Jobs, one.Peer, op, e)
	name := "native-renamed"
	memory := silo.Mebibytes(768)
	disk := silo.Gibibytes(2)
	op, e = s.Set(ctx, one, "native-one", service.SetRequest{Name: &name, Memory: &memory, Disk: &disk})
	daemon.Succeeded(t, s.Jobs, one.Peer, op, e)
	show, e := s.Show(ctx, one.Peer, name)
	if e != nil || show.Memory != memory.Bytes() || show.Disk != disk.Bytes() {
		t.Fatal(show, e)
	}
	op, e = s.Start(ctx, one, name)
	daemon.Succeeded(t, s.Jobs, one.Peer, op, e)
	op, e = s.Restart(ctx, one, name)
	daemon.Succeeded(t, s.Jobs, one.Peer, op, e)
	// Actual grammar, JSON envelope and guest -- delimiter on the same native service.
	var jsonOut, human bytes.Buffer
	if code = sshd.DispatchSession(ctx, s, one, "show "+name+" --json", service.IO{Stdout: &jsonOut, Stderr: &human}); code != 0 || !strings.Contains(jsonOut.String(), `"ok":true`) {
		t.Fatal(code, jsonOut.String(), human.String())
	}
	out.Reset()
	errout.Reset()
	if code = sshd.DispatchSession(ctx, s, one, "exec "+name+" -e VALUE=literal -- /bin/bash -c 'printf \"%s\" \"$VALUE\"'", service.IO{Stdout: &out, Stderr: &errout}); code != 0 || out.String() != "literal" {
		t.Fatal(code, out.String(), errout.String())
	}
	op, e = s.Remove(ctx, one, name, service.RemoveRequest{Force: true})
	daemon.Succeeded(t, s.Jobs, one.Peer, op, e)
	if code := sshd.DispatchSession(ctx, s, two, "--yes rm native-two", service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 0 {
		t.Fatal("global --yes unattended remove", code)
	}
	if list, e := s.List(ctx, one.Peer); e != nil || len(list) != 0 {
		t.Fatal(list, e)
	}
	t.Log(fmt.Sprintf("real local OCI registry requests=%d, no internet or tailnet used", registry.Requests.Load()))
}

// The native receive pump writes while the test waits for real guest output.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
func (w *lockedBuffer) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

type executionResult struct {
	code int
	err  error
}

func probePTYEOF(t *testing.T, s *service.Service, c service.Caller, ref string) {
	t.Helper()
	for _, test := range []struct{ name, input, script, want string }{
		{"unterminated-canonical-cat", "hello", "stty -echo; printf READY; exec /bin/cat", "READYhello"},
		{"empty-canonical-cat", "", "stty -echo; printf READY; exec /bin/cat", "READY"},
		{"raw-mode-literal-eot", "", "stty raw -echo; printf READY; IFS= read -r -N 2 value; printf '%s' \"$value\"", "READY\x04\x04"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			var out lockedBuffer
			done := make(chan executionResult, 1)
			go func() {
				code, e := s.Exec(ctx, c, ref, service.ExecRequest{TTY: true, Program: "/bin/bash", Args: []string{"-c", test.script}}, service.IO{Input: pipeInput(reader), Stdout: &out, Stderr: io.Discard, Terminal: service.Terminal{Present: true, Window: service.Window{Rows: 24, Columns: 80}}})
				done <- executionResult{code, e}
			}()
			guestOutput(t, &out, "READY")
			if test.input != "" {
				if _, e := io.WriteString(writer, test.input); e != nil {
					t.Fatal(e)
				}
			}
			if e := writer.Close(); e != nil {
				t.Fatal(e)
			}
			select {
			case result := <-done:
				if result.code != 0 || result.err != nil || out.String() != test.want {
					t.Fatalf("PTY EOF %+v output %q want %q", result, out.String(), test.want)
				}
			case <-ctx.Done():
				t.Fatal("PTY EOF did not finish bounded execution", out.String())
			}
		})
	}
}

func probeOutputFailures(t *testing.T, s *service.Service, c service.Caller, ref string) {
	t.Helper()
	for _, output := range []string{"stdout", "stderr"} {
		t.Run("broken-"+output, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			inputReader, inputWriter := io.Pipe()
			defer inputReader.Close()
			defer inputWriter.Close()
			outputReader, outputWriter := io.Pipe()
			_ = outputReader.Close()
			defer outputWriter.Close()
			streams := service.IO{Input: pipeInput(inputReader), Stdout: io.Discard, Stderr: io.Discard}
			script := "printf guest-output; read -r"
			if output == "stdout" {
				streams.Stdout = outputWriter
			} else {
				streams.Stderr = outputWriter
				script = "printf guest-output >&2; read -r"
			}
			code, e := s.Exec(ctx, c, ref, service.ExecRequest{Program: "/bin/bash", Args: []string{"-c", script}}, streams)
			if code != 255 || e == nil || service.Categorize(e).Exit != 255 {
				t.Fatal("service remapped output failure", code, e)
			}
			// The same real broken pipe crosses dispatch; its raw OS error must not
			// be recategorized as service-unavailable 9 or expose native diagnostics.
			command := "exec " + ref + " -- /bin/bash -c '" + script + "'"
			if code = sshd.DispatchSession(ctx, s, c, command, streams); code != 255 {
				t.Fatal("dispatch remapped output failure", code)
			}
			if v, e := s.Show(ctx, c.Peer, ref); e != nil || v.State != silo.MachineStatusRunning {
				t.Fatal("output failure stopped VM", v, e)
			}
		})
	}
}

func guestOutput(t *testing.T, w *lockedBuffer, text string) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if strings.Contains(w.String(), text) {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("guest output missing %q: %s", text, w.String())
		case <-ticker.C:
		}
	}
}
func pipeInput(reader *io.PipeReader) func(context.Context) io.Reader {
	return func(ctx context.Context) io.Reader {
		context.AfterFunc(ctx, func() { _ = reader.CloseWithError(ctx.Err()) })
		return reader
	}
}
func probeControls(t *testing.T, s *service.Service, c service.Caller, ref string) {
	t.Helper()
	ctx := context.Background()
	reader, writer := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	var out lockedBuffer
	windows := make(chan service.Window, 1)
	done := make(chan executionResult, 1)
	go func() {
		code, e := s.Exec(ctx, c, ref, service.ExecRequest{TTY: true, Program: "/bin/bash", Args: []string{"-c", "stty size; printf READY; read -r; stty size; exit 3"}}, service.IO{Input: pipeInput(reader), Stdout: &out, Stderr: io.Discard, Terminal: service.Terminal{Present: true, Window: service.Window{Rows: 31, Columns: 97}, Windows: windows}})
		done <- executionResult{code, e}
	}()
	guestOutput(t, &out, "READY")
	windows <- service.Window{Rows: 41, Columns: 123}
	time.Sleep(100 * time.Millisecond)
	if _, e := io.WriteString(writer, "\n"); e != nil {
		t.Fatal(e)
	}
	select {
	case result := <-done:
		if result.err != nil || result.code != 3 || !strings.Contains(out.String(), "31 97") || !strings.Contains(out.String(), "41 123") {
			t.Fatalf("resize result %+v %q", result, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("resize execution hung")
	}
	reader, writer = io.Pipe()
	defer writer.Close()
	defer reader.Close()
	out = lockedBuffer{}
	signals := make(chan uint32, 1)
	go func() {
		code, e := s.Exec(ctx, c, ref, service.ExecRequest{Program: "/bin/bash", Args: []string{"-c", "trap 'exit 42' TERM; printf READY; read -r"}}, service.IO{Input: pipeInput(reader), Stdout: &out, Stderr: io.Discard, Terminal: service.Terminal{Signals: signals}})
		done <- executionResult{code, e}
	}()
	guestOutput(t, &out, "READY")
	signals <- 15
	select {
	case result := <-done:
		if result.err != nil || result.code != 42 {
			t.Fatalf("signal %+v", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("signal execution hung")
	}
	reader, writer = io.Pipe()
	defer writer.Close()
	defer reader.Close()
	out = lockedBuffer{}
	session, disconnect := context.WithCancel(ctx)
	go func() {
		code, e := s.Exec(session, c, ref, service.ExecRequest{Program: "/bin/bash", Args: []string{"-c", "printf READY; read -r"}}, service.IO{Input: pipeInput(reader), Stdout: &out, Stderr: io.Discard})
		done <- executionResult{code, e}
	}()
	guestOutput(t, &out, "READY")
	disconnect()
	select {
	case result := <-done:
		if result.code != 255 {
			t.Fatalf("disconnect %+v", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("disconnected execution did not cancel")
	}
	if v, e := s.Show(ctx, c.Peer, ref); e != nil || v.State != silo.MachineStatusRunning {
		t.Fatal("session disconnect stopped VM", v, e)
	}
}
func probeStreamAuthorization(t *testing.T, s *service.Service, c service.Caller, ref string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var out lockedBuffer
	done := make(chan executionResult, 1)
	revoked := c
	var execChecks atomic.Int32
	revoked.Resolve = func(ctx context.Context) (identity.Peer, error) {
		p := c.Peer
		if execChecks.Add(1) > 1 {
			p.Permissions.Actions = []identity.Action{identity.Read}
		}
		return p, ctx.Err()
	}
	go func() {
		code, e := s.Exec(ctx, revoked, ref, service.ExecRequest{Program: "/bin/bash", Args: []string{"-c", "printf READY; read -r"}}, service.IO{Input: pipeInput(reader), Stdout: &out, Stderr: io.Discard})
		done <- executionResult{code, e}
	}()
	guestOutput(t, &out, "READY")
	logsCaller := c
	var logChecks atomic.Int32
	logsCaller.Resolve = func(ctx context.Context) (identity.Peer, error) {
		p := c.Peer
		if logChecks.Add(1) > 1 {
			p.Permissions.Actions = nil
		}
		return p, ctx.Err()
	}
	logsDone := make(chan error, 1)
	go func() {
		logsDone <- s.Logs(ctx, logsCaller, ref, service.LogsRequest{Follow: true, Source: silo.MachineLogSerial}, io.Discard)
	}()
	select {
	case result := <-done:
		if result.code != 4 || service.Categorize(result.err).Exit != 4 || execChecks.Load() < 2 {
			t.Fatalf("30s exec revocation %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("exec fresh authorization did not close stream")
	}
	select {
	case e := <-logsDone:
		if service.Categorize(e).Exit != 4 || logChecks.Load() < 2 {
			t.Fatal("30s log revocation", e)
		}
	case <-ctx.Done():
		t.Fatal("log fresh authorization did not close stream")
	}
	if v, e := s.Show(context.Background(), c.Peer, ref); e != nil || v.State != silo.MachineStatusRunning {
		t.Fatal("stream denial stopped VM", v, e)
	}
}

func probeLostExecution(t *testing.T, s *service.Service, c service.Caller, ref string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var out lockedBuffer
	done := make(chan executionResult, 1)
	go func() {
		code, e := s.Exec(ctx, c, ref, service.ExecRequest{Program: "/bin/bash", Args: []string{"-c", "printf READY; read -r"}}, service.IO{Input: pipeInput(reader), Stdout: &out, Stderr: io.Discard})
		done <- executionResult{code, e}
	}()
	guestOutput(t, &out, "READY")
	op, e := s.Stop(ctx, c, ref, service.StopRequest{Force: true, Timeout: time.Second})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, e)
	select {
	case result := <-done:
		if result.code != 255 || result.err == nil {
			t.Fatalf("lost execution %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("lost execution did not finish")
	}
	op, e = s.Start(ctx, c, ref)
	daemon.Succeeded(t, s.Jobs, c.Peer, op, e)
}

func probeSDKLazyStdin(t *testing.T, s *service.Service, ref string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, e := s.Runtime.SDK.Machine(ctx, ref)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	exec, e := m.Spawn(ctx, "/bin/bash", []string{"-c", `read -r value; printf '%s' "$value"`}, silo.WithExecStdinPipe())
	if e != nil {
		t.Fatal(e)
	}
	defer exec.Close()
	if exec.Stdin() != nil {
		t.Fatal("input available before Started was received")
	}
	var out bytes.Buffer
	for {
		event, e := exec.Recv(ctx)
		if e != nil {
			t.Fatal(e)
		}
		switch event.Kind {
		case silo.ExecutionEventStarted:
			input := exec.Stdin()
			if input == nil {
				t.Fatal("early nil input was cached permanently")
			}
			if _, e = input.WriteContext(ctx, []byte("lazy-native-input\n")); e != nil {
				t.Fatal(e)
			}
			if e = input.Close(); e != nil {
				t.Fatal(e)
			}
		case silo.ExecutionEventStdout:
			_, _ = out.Write(event.Data)
		case silo.ExecutionEventTerminal:
			if event.Result == nil || event.Result.Code == nil || *event.Result.Code != 0 || out.String() != "lazy-native-input" {
				t.Fatal(event.Result, out.String())
			}
			var wg sync.WaitGroup
			for range 20 {
				wg.Add(1)
				go func() { defer wg.Done(); _ = exec.Cancel(); _ = exec.CloseRequests() }()
			}
			_ = exec.Close()
			wg.Wait()
			return
		}
	}
}
