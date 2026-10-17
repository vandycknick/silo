//go:build silo_e2e

package integration_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
)

// These cases share the actual disposable guest owned by the Linux KVM signal
// fixture. They exercise cgo and libvm's SSH transport, not a substituted operation.
func exerciseSuppliedShell(t *testing.T, parent context.Context, m *silo.Machine) {
	t.Helper()
	t.Run("bounded-output-and-blocked-input", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parent, 15*time.Second)
		defer cancel()
		var output memoryShellWriter
		var inputScope context.Context
		controls := make(chan silo.SSHShellControl, 1)
		controls <- silo.SSHShellControl{Kind: silo.SSHShellResize, Rows: 37, Columns: 119}
		close(controls)
		status, err := m.Shell(ctx, silo.WithSSHTerm("xterm-256color"), silo.WithShellAttachment(silo.SSHShellAttachment{
			Rows: 37, Columns: 119, Controls: controls, Stdout: &output, Stderr: &output,
			Input: func(inputCtx context.Context) io.Reader {
				inputScope = inputCtx
				return &commandThenWait{ctx: inputCtx, command: strings.NewReader("stty -echo -onlcr; printf '\\036'; head -c 131073 /dev/zero | tr '\\000' A; head -c 131079 /dev/zero | tr '\\000' B >&2; printf '\\037'; exit 7\n")}
			},
		}))
		if inputScope == nil || inputScope.Err() == nil {
			t.Fatal("input scope not stopped after native success")
		}
		if err != nil || status.Code != 7 {
			t.Fatalf("status=%+v err=%v", status, err)
		}
		start, end := bytes.IndexByte(output.Bytes(), 0x1e), bytes.IndexByte(output.Bytes(), 0x1f)
		expected := append(bytes.Repeat([]byte("A"), 131073), bytes.Repeat([]byte("B"), 131079)...)
		if start < 0 || end <= start || !bytes.Equal(output.Bytes()[start+1:end], expected) {
			t.Fatalf("final output differs (%d bytes)", output.Len())
		}
		if ctx.Err() != nil {
			t.Fatal("success canceled caller context")
		}
	})
	t.Run("sink-failure-cancels-blocked-native-output", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parent, 15*time.Second)
		defer cancel()
		failure := errors.New("sink failed")
		_, err := m.Shell(ctx, silo.WithShellAttachment(silo.SSHShellAttachment{Rows: 24, Columns: 80,
			Input:  func(context.Context) io.Reader { return strings.NewReader("while :; do printf 0123456789; done\n") },
			Stdout: failingShellWriter{failure}, Stderr: failingShellWriter{failure},
		}))
		if !errors.Is(err, failure) {
			t.Fatalf("first pump failure lost: %v", err)
		}
	})
	t.Run("cancel-during-output-callback-and-reconnect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(parent)
		entered := make(chan struct{}, 1)
		result := make(chan error, 1)
		go func() {
			_, err := m.Shell(ctx, silo.WithShellAttachment(silo.SSHShellAttachment{Rows: 24, Columns: 80,
				Input:  func(context.Context) io.Reader { return strings.NewReader("printf output; exit 7\n") },
				Stdout: waitingShellWriter{entered}, Stderr: waitingShellWriter{entered},
			}))
			result <- err
		}()
		select {
		case <-entered:
		case <-time.After(15 * time.Second):
			cancel()
			t.Fatal("output callback never started")
		}
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancel failed to join callbacks/native shell")
		}
		reconnectCtx, stop := context.WithTimeout(parent, 10*time.Second)
		defer stop()
		status, err := m.Shell(reconnectCtx, silo.WithShellAttachment(silo.SSHShellAttachment{Rows: 24, Columns: 80, Input: func(context.Context) io.Reader { return strings.NewReader("exit 7\n") }}))
		if err != nil || status.Code != 7 {
			t.Fatalf("reconnect: %+v %v", status, err)
		}
	})
}

type memoryShellWriter struct{ bytes.Buffer }

func (w *memoryShellWriter) WriteContext(_ context.Context, b []byte) (int, error) { return w.Write(b) }

type failingShellWriter struct{ err error }

func (w failingShellWriter) WriteContext(context.Context, []byte) (int, error) { return 0, w.err }

type waitingShellWriter struct{ entered chan struct{} }

func (w waitingShellWriter) WriteContext(ctx context.Context, _ []byte) (int, error) {
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

type commandThenWait struct {
	ctx     context.Context
	command *strings.Reader
}

func (r *commandThenWait) Read(b []byte) (int, error) {
	if r.command.Len() != 0 {
		n, _ := r.command.Read(b)
		return n, nil
	}
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}
