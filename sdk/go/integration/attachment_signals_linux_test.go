//go:build silo_e2e && linux

package integration_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
	"github.com/vandycknick/silo/sdk/go/integration/signaldiagnostic"
	"golang.org/x/sys/unix"
)

// Each attached client is a real child with a controlling host PTY. All clients
// use the public SDK and the same isolated, running KVM guest.
func TestGoSDKAttachmentSignalsKVM(t *testing.T) {
	if mode := os.Getenv("SILO_ATTACHMENT_CHILD"); mode != "" {
		attachmentChild(t, mode)
		return
	}
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required")
	}
	disk, root := os.Getenv("SILO_TEST_LOCAL_DISK"), os.Getenv("SILO_TEST_RUNTIME_ROOT")
	if disk == "" || root == "" {
		t.Fatal("prepared local disk and runtime root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	home := t.TempDir()
	r, err := silo.Open(ctx, silo.WithHome(home), silo.WithRuntimeRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	policy, err := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{DefaultAction: silo.NetworkDeny})
	if err != nil {
		t.Fatal(err)
	}
	m, err := r.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("attachment-signals"), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithRootDiskSize(silo.Gibibytes(1)), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		_, _ = m.StopWith(cleanup, silo.StopOptions{Force: true, Timeout: time.Second})
		_ = m.Remove(cleanup)
	}()
	if _, err = m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitForReady(t, ctx, m)
	for round := 0; round < 2; round++ {
		for _, mode := range []string{"attach-int", "attach-term", "attach-ctrlc", "attach-resize", "attach-cancel", "shell-int", "shell-term", "shell-ctrlc", "shell-resize", "shell-cancel", "shell-detach"} {
			t.Run(fmt.Sprintf("%d/%s", round, mode), func(t *testing.T) {
				runAttachmentPTY(t, home, m.ID(), mode)
			})
		}
	}
	for _, mode := range []string{"attach-ignored-hup", "attach-ignored-int", "shell-ignored-hup", "shell-ignored-int", "attach-default-int", "shell-default-int"} {
		t.Run(mode, func(t *testing.T) { runAttachmentPTY(t, home, m.ID(), mode) })
	}
	output, err := m.Exec(ctx, "/bin/true", nil)
	if err != nil || output.Result().Code == nil || *output.Result().Code != 0 {
		t.Fatalf("VM stopped by attachment cleanup: %v", err)
	}
}

func attachmentChild(t *testing.T, mode string) {
	if strings.Contains(mode, "-default-") {
		// Runs after runtime/profile/terminal cleanup, with no SDK or app subscriber.
		defer func() {
			fmt.Println("DEFAULT_SIGNAL_RESTORED")
			if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Second)
			t.Fatal("default SIGINT termination was suppressed after attachment")
		}()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control := os.NewFile(3, "attachment-cancel")
	defer control.Close()
	if strings.Contains(mode, "-ignored-") {
		for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT} {
			action, err := signaldiagnostic.Query(sig)
			if err != nil || action.Handler != 1 {
				t.Fatalf("SIG_IGN was not inherited before runtime build: %v %+v %v", sig, action, err)
			}
		}
	}
	go func() {
		var b [1]byte
		for {
			if n, _ := control.Read(b[:]); n == 0 {
				return
			}
			if b[0] == 'q' {
				queryAttachmentActions(t, "REGISTERED")
				fmt.Println("ACTION_REGISTERED_DONE")
			} else {
				cancel()
				return
			}
		}
	}()
	r, err := silo.Open(ctx, silo.WithHome(os.Getenv("SILO_ATTACHMENT_HOME")), silo.WithRuntimeRoot(os.Getenv("SILO_TEST_RUNTIME_ROOT")))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m, err := r.Machine(ctx, os.Getenv("SILO_ATTACHMENT_MACHINE"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	profile, err := os.Create(os.Getenv("SILO_ATTACHMENT_PROFILE"))
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	if err = pprof.StartCPUProfile(profile); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var v uint64 = 1
			for !stop.Load() {
				for j := 0; j < 100000; j++ {
					v = v*1664525 + 1013904223
				}
				if v == 0 {
					runtime.Gosched()
				}
			}
		}()
	}
	defer func() { stop.Store(true); workers.Wait(); pprof.StopCPUProfile() }()
	if strings.Contains(mode, "-ignored-") || strings.Contains(mode, "-default-") {
		exerciseInheritedAttachments(t, ctx, m, mode)
		fmt.Println("ATTACHMENT_DONE")
		return
	}
	app := make(chan os.Signal, 16)
	signal.Notify(app, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(app)
	untouched := []syscall.Signal{syscall.SIGURG, syscall.SIGPROF, syscall.SIGPIPE, syscall.SIGCHLD, syscall.SIGSEGV, syscall.SIGBUS, syscall.SIGFPE}
	before := make(map[syscall.Signal]signaldiagnostic.Action)
	for _, sig := range untouched {
		action, e := signaldiagnostic.Query(sig)
		if e != nil {
			t.Fatal(e)
		}
		before[sig] = action
	}
	forwarded := []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH}
	for _, sig := range forwarded {
		action, e := signaldiagnostic.Query(sig)
		if e != nil {
			t.Fatal(e)
		}
		fmt.Printf("ACTION_BEFORE signal=%d flags=%#x handler=%#x mask=%#x\n", sig, action.Flags, action.Handler, action.Mask)
		if action.Flags&signaldiagnostic.OnStack == 0 {
			t.Fatalf("previous Go action lacks alternate stack: %d", sig)
		}
	}
	if strings.HasPrefix(mode, "attach-") {
		script := "trap 'printf INT_OK; exit 42' INT; trap 'printf TERM_OK; exit 43' TERM; printf GUEST_READY; while :; do :; done"
		if mode == "attach-resize" {
			script = "trap 'stty size; exit 0' WINCH; printf GUEST_READY; while :; do :; done"
		}
		result, e := m.Attach(ctx, "/bin/bash", []string{"-c", script})
		if mode == "attach-cancel" {
			if !silo.IsErrorKind(e, silo.ErrorCancelled) {
				t.Fatalf("cancel: %v", e)
			}
		} else {
			want := uint32(42)
			if mode == "attach-term" {
				want = 43
			}
			if mode == "attach-resize" {
				want = 0
			}
			if e != nil || result.Code == nil || *result.Code != want {
				t.Fatalf("Attach: %#v %v, want %d", result, e, want)
			}
		}
		// Exercise scoped Go subscriptions in the same process after normal
		// and cancelled calls, with preemption and CPU profiling still active.
		for i := 0; i < 10; i++ {
			result, e = m.Attach(context.Background(), "/bin/true", nil)
			if e != nil || result.Code == nil || *result.Code != 0 {
				t.Fatalf("repeated Attach: %#v %v", result, e)
			}
		}
	} else {
		result, e := m.AttachShell(ctx, silo.WithSSHTerm("xterm"))
		if mode == "shell-cancel" {
			if !silo.IsErrorKind(e, silo.ErrorCancelled) {
				t.Fatalf("shell cancel: %v", e)
			}
		} else {
			want := int32(42)
			if mode == "shell-term" {
				want = 43
			}
			if mode == "shell-detach" || mode == "shell-resize" {
				want = 0
			}
			if e != nil || result.Code != want {
				t.Fatalf("AttachShell: %#v %v, want %d", result, e, want)
			}
		}
		for i := 0; i < 3; i++ {
			fmt.Printf("SHELL_REPEAT_%d\n", i)
			result, e = m.AttachShell(context.Background(), silo.WithSSHTerm("xterm"))
			if e != nil || result.Code != 0 {
				t.Fatalf("repeated AttachShell: %#v %v", result, e)
			}
		}
	}
	if strings.HasSuffix(mode, "-int") || strings.HasSuffix(mode, "-term") {
		select {
		case <-app:
		case <-time.After(time.Second):
			t.Fatal("existing application subscriber missed forwarded signal")
		}
	}
	for _, sig := range forwarded {
		action, e := signaldiagnostic.Query(sig)
		if e != nil {
			t.Fatal(e)
		}
		fmt.Printf("ACTION_AFTER_DROP signal=%d flags=%#x handler=%#x mask=%#x\n", sig, action.Flags, action.Handler, action.Mask)
		if action.Flags&signaldiagnostic.OnStack == 0 {
			t.Fatalf("retained native action lacks alternate stack: %d", sig)
		}
	}
	for _, sig := range untouched {
		action, e := signaldiagnostic.Query(sig)
		if e != nil || action != before[sig] {
			t.Fatalf("runtime signal %d changed: before=%+v after=%+v err=%v", sig, before[sig], action, e)
		}
	}
	fmt.Println("ATTACHMENT_DONE")
}

func runAttachmentPTY(t *testing.T, home, id, mode string) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "pty-master")
	defer master.Close()
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	original, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	profile := filepath.Join(t.TempDir(), "cpu.pprof")
	childctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childctx, os.Args[0], "-test.run=^TestGoSDKAttachmentSignalsKVM$", "-test.v")
	if strings.Contains(mode, "-ignored-") {
		cmd = exec.CommandContext(childctx, "/bin/bash", "-c", `trap '' HUP INT; exec "$@"`, "silo-signal-child", os.Args[0], "-test.run=^TestGoSDKAttachmentSignalsKVM$", "-test.v")
	}
	cmd.Env = append(os.Environ(), "SILO_ATTACHMENT_CHILD="+mode, "SILO_ATTACHMENT_HOME="+home, "SILO_ATTACHMENT_MACHINE="+id, "SILO_ATTACHMENT_PROFILE="+profile, "GOMAXPROCS=2")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.ExtraFiles = []*os.File{reader}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	chunks := make(chan string, 128)
	go func() {
		defer close(chunks)
		buffer := make([]byte, 4096)
		for {
			n, e := master.Read(buffer)
			if n > 0 {
				select {
				case chunks <- string(buffer[:n]):
				case <-childctx.Done():
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()
	var output string
	waitAfter := func(marker string, offset int) {
		t.Helper()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		for !strings.Contains(output[offset:], marker) {
			select {
			case chunk, ok := <-chunks:
				if !ok {
					t.Fatalf("PTY closed before %q: %s", marker, output)
				}
				output += chunk
			case <-deadline.C:
				t.Fatalf("waiting for %q: %s", marker, output)
			}
		}
	}
	wait := func(marker string) { waitAfter(marker, 0) }
	if strings.Contains(mode, "-ignored-") || strings.Contains(mode, "-default-") {
		for round := 0; round < 3; round++ {
			marker := fmt.Sprintf("INHERITED_ROUND_%d", round)
			wait(marker)
			offset := strings.Index(output, marker) + len(marker)
			if strings.HasPrefix(mode, "shell-") {
				waitAfter("$ ", offset)
				if _, err = io.WriteString(master, fmt.Sprintf("stty -echo; trap 'printf HUP_OK; exit 44' HUP; trap 'printf INT_OK; exit 42' INT; printf 'GUEST_READY_%%s' %d; while :; do :; done\n", round)); err != nil {
					t.Fatal(err)
				}
			}
			wait(fmt.Sprintf("GUEST_READY_%d", round))
			if _, err = writer.Write([]byte{'q'}); err != nil {
				t.Fatal(err)
			}
			waitAfter("ACTION_REGISTERED_DONE", offset)
			sig := syscall.SIGINT
			if strings.HasSuffix(mode, "-hup") {
				sig = syscall.SIGHUP
			}
			if err = cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			wait(fmt.Sprintf("INHERITED_FINISHED_%d", round))
		}
		wait("ATTACHMENT_DONE")
		err = cmd.Wait()
		if strings.Contains(mode, "-default-") {
			if err == nil {
				t.Fatal("default SIGINT did not terminate the child")
			}
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !(status.Signaled() && status.Signal() == syscall.SIGINT || status.ExitStatus() == 2) {
				t.Fatalf("unexpected default termination: %v\n%s", err, output)
			}
		} else if err != nil {
			t.Fatalf("inherited child: %v\n%s", err, output)
		}
		t.Logf("inherited/default signal evidence:\n%s", output)
		verifyAttachmentPTY(t, original, slave, profile)
		return
	}
	if strings.HasPrefix(mode, "shell-") {
		wait("$ ")
		script := "trap 'printf INT_OK; exit 42' INT; trap 'printf TERM_OK; exit 43' TERM; printf GUEST_READY; while :; do :; done\n"
		if mode == "shell-resize" {
			script = "trap 'stty size; exit 0' WINCH; printf GUEST_READY; while :; do :; done\n"
		}
		// Disable echo so readiness cannot match the command before it executes.
		if _, err = io.WriteString(master, "stty -echo; printf 'SETUP_%s\\n' DONE\n"); err != nil {
			t.Fatal(err)
		}
		wait("SETUP_DONE")
		if _, err = io.WriteString(master, script); err != nil {
			t.Fatal(err)
		}
	}
	wait("GUEST_READY")
	// Guest output proves native registration is complete. The control descriptor
	// requests a read-only query while the child is blocked in public Attach.
	if _, err = writer.Write([]byte{'q'}); err != nil {
		t.Fatal(err)
	}
	wait("ACTION_REGISTERED_DONE")
	switch {
	case strings.HasSuffix(mode, "-int"):
		err = cmd.Process.Signal(syscall.SIGINT)
	case strings.HasSuffix(mode, "-term"):
		err = cmd.Process.Signal(syscall.SIGTERM)
	case strings.HasSuffix(mode, "-ctrlc"):
		_, err = master.Write([]byte{3})
	case strings.HasSuffix(mode, "-resize"):
		err = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 41, Col: 123})
		if err == nil {
			err = cmd.Process.Signal(syscall.SIGWINCH)
		}
	case strings.HasSuffix(mode, "-cancel"):
		_, err = writer.Write([]byte{1})
	case strings.HasSuffix(mode, "-detach"):
		_, err = master.Write([]byte{0x1d})
	}
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(mode, "shell-") {
		for i := 0; i < 3; i++ {
			marker := fmt.Sprintf("SHELL_REPEAT_%d", i)
			wait(marker)
			offset := strings.Index(output, marker) + len(marker)
			waitAfter("$ ", offset)
			if _, err = io.WriteString(master, "exit 0\n"); err != nil {
				t.Fatal(err)
			}
		}
	}
	wait("ATTACHMENT_DONE")
	if err = cmd.Wait(); err != nil {
		t.Fatalf("child: %v\n%s", err, output)
	}
	if mode == "attach-int" {
		t.Logf("child sigaction evidence:\n%s", output)
	}
	if strings.HasSuffix(mode, "-resize") && !strings.Contains(output, "41 123") {
		t.Fatalf("resize not delivered: %s", output)
	}
	if strings.HasSuffix(mode, "-int") || strings.HasSuffix(mode, "-ctrlc") {
		if !strings.Contains(output, "INT_OK") {
			t.Fatalf("INT not delivered: %s", output)
		}
	}
	if strings.HasSuffix(mode, "-term") && !strings.Contains(output, "TERM_OK") {
		t.Fatalf("TERM not delivered: %s", output)
	}
	verifyAttachmentPTY(t, original, slave, profile)
}

func verifyAttachmentPTY(t *testing.T, original *unix.Termios, slave *os.File, profile string) {
	t.Helper()
	restored, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	// glibc tcsetattr expands the kernel's implicit input baud (CIBAUD=0)
	// into the equivalent explicit output baud. Compare that normalized value.
	wantCflag := original.Cflag
	if wantCflag&unix.CIBAUD == 0 {
		wantCflag |= (wantCflag & unix.CBAUD) << 16
	}
	if err != nil || restored.Iflag != original.Iflag || restored.Oflag != original.Oflag || restored.Cflag != wantCflag || restored.Lflag != original.Lflag || restored.Cc != original.Cc {
		t.Fatalf("host terminal not restored: %v before=%+v after=%+v", err, original, restored)
	}
	info, err := os.Stat(profile)
	if err != nil || info.Size() == 0 {
		t.Fatalf("CPU profiling failed: %v", err)
	}
}

func queryAttachmentActions(t *testing.T, phase string) {
	t.Helper()
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH} {
		action, err := signaldiagnostic.Query(sig)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("ACTION_%s signal=%d flags=%#x handler=%#x mask=%#x\n", phase, sig, action.Flags, action.Handler, action.Mask)
		if action.Flags&signaldiagnostic.OnStack == 0 {
			t.Fatalf("%s action lacks alternate stack: %d", phase, sig)
		}
	}
}

func exerciseInheritedAttachments(t *testing.T, ctx context.Context, m *silo.Machine, mode string) {
	t.Helper()
	ignored := strings.Contains(mode, "-ignored-")
	for round := 0; round < 3; round++ {
		for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT} {
			action, err := signaldiagnostic.Query(sig)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("INHERITED_IDLE round=%d signal=%d flags=%#x handler=%#x\n", round, sig, action.Flags, action.Handler)
			if (action.Handler == 1) != ignored {
				t.Fatalf("round %d: inherited disposition not restored for %v", round, sig)
			}
			if !ignored && action.Flags&signaldiagnostic.OnStack == 0 {
				t.Fatal("default Go handler lost SA_ONSTACK")
			}
		}
		fmt.Printf("INHERITED_ROUND_%d\n", round)
		want := uint32(42)
		if strings.HasSuffix(mode, "-hup") {
			want = 44
		}
		if strings.HasPrefix(mode, "attach-") {
			result, err := m.Attach(ctx, "/bin/bash", []string{"-c", fmt.Sprintf("trap 'printf HUP_OK; exit 44' HUP; trap 'printf INT_OK; exit 42' INT; printf GUEST_READY_%d; while :; do :; done", round)})
			if err != nil || result.Code == nil || *result.Code != want {
				t.Fatalf("inherited Attach round %d: %#v %v", round, result, err)
			}
		} else {
			result, err := m.AttachShell(ctx, silo.WithSSHTerm("xterm"))
			if err != nil || result.Code != int32(want) {
				t.Fatalf("inherited AttachShell round %d: %#v %v", round, result, err)
			}
		}
		fmt.Printf("INHERITED_FINISHED_%d\n", round)
	}
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT} {
		action, err := signaldiagnostic.Query(sig)
		if err != nil || (action.Handler == 1) != ignored {
			t.Fatalf("final ignored disposition not restored for %v", sig)
		}
	}
}
