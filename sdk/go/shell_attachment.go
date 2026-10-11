package silo

import (
	"context"
	"errors"
	"io"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

// SSHShellWriter delivers one stream's bytes. WriteContext must return when ctx
// is canceled. Calls to the stdout and stderr writers are serialized, so both
// fields may safely refer to one non-thread-safe writer. Cross-stream order is
// unspecified. See examples/shell for finite, nonblocking memory I/O.
type SSHShellWriter interface {
	WriteContext(context.Context, []byte) (int, error)
}

type SSHShellControlKind string

const (
	SSHShellResize     SSHShellControlKind = "resize"
	SSHShellSendSignal SSHShellControlKind = "signal"
)

// SSHShellSignal uses Linux guest signal numbers, independent of the host OS.
type SSHShellSignal uint32

const (
	SSHShellHUP  SSHShellSignal = 1
	SSHShellINT  SSHShellSignal = 2
	SSHShellQUIT SSHShellSignal = 3
	SSHShellILL  SSHShellSignal = 4
	SSHShellABRT SSHShellSignal = 6
	SSHShellFPE  SSHShellSignal = 8
	SSHShellKILL SSHShellSignal = 9
	SSHShellUSR1 SSHShellSignal = 10
	SSHShellSEGV SSHShellSignal = 11
	SSHShellUSR2 SSHShellSignal = 12
	SSHShellPIPE SSHShellSignal = 13
	SSHShellALRM SSHShellSignal = 14
	SSHShellTERM SSHShellSignal = 15
)

type SSHShellControl struct {
	Kind          SSHShellControlKind
	Rows, Columns uint16
	Signal        SSHShellSignal
}

// SSHShellAttachment supplies owned-per-call I/O without host terminal effects.
// Input is called once with the input/control child context. Its reader MUST
// unblock when that context is canceled; arbitrary blocking io.Reader syscalls
// cannot be interrupted by the SDK. Nil Input means EOF, nil writers discard,
// and nil Controls disables controls. Dimensions must be positive. Shell does
// not close borrowed outer SSH sessions or process stdio. Native success stops
// input/control but drains output before canceling its separate context.
// See examples/shell for a finite-reader attachment.
type SSHShellAttachment struct {
	Input         func(context.Context) io.Reader
	Stdout        SSHShellWriter
	Stderr        SSHShellWriter
	Rows, Columns uint16
	Controls      <-chan SSHShellControl
}

// WithShellAttachment selects supplied, one-call SSH I/O instead of the local
// terminal adapter. It cannot be combined with WithSSHDetachKeys. See examples/shell.
func WithShellAttachment(attachment SSHShellAttachment) SSHShellOption {
	return func(c *sshShellConfig) { c.attachment = &attachment }
}

func validateShellAttachment(a SSHShellAttachment) error {
	if a.Rows == 0 || a.Columns == 0 {
		return newError(ErrorInvalidArgument, "", "SSH attachment rows and columns must be positive")
	}
	return nil
}
func validateShellControl(c SSHShellControl) error {
	switch c.Kind {
	case SSHShellResize:
		if c.Rows != 0 && c.Columns != 0 {
			return nil
		}
	case SSHShellSendSignal:
		switch c.Signal {
		case SSHShellHUP, SSHShellINT, SSHShellQUIT, SSHShellILL, SSHShellABRT, SSHShellFPE, SSHShellKILL, SSHShellUSR1, SSHShellSEGV, SSHShellUSR2, SSHShellPIPE, SSHShellALRM, SSHShellTERM:
			return nil
		}
	}
	return newError(ErrorInvalidArgument, "", "invalid SSH shell control")
}

func suppliedShell(ctx context.Context, machine *ffi.Machine, request []byte, a SSHShellAttachment) ([]byte, error) {
	token, err := ffi.NewAttachmentCancellation()
	if err != nil {
		return nil, fromNativeError(err)
	}
	defer token.Close()
	handle, err := machine.NewSshAttachment(token, a.Rows, a.Columns)
	if err != nil {
		return nil, fromNativeError(err)
	}
	defer handle.Close()
	inputCtx, stopInput := context.WithCancel(ctx)
	defer stopInput()
	outputCtx, stopOutput := context.WithCancel(ctx)
	defer stopOutput()
	type completion struct {
		native bool
		data   []byte
		err    error
	}
	completed := make(chan completion, 5)
	// One gate protects callbacks, not native reads: both bounded pipes must drain
	// concurrently to avoid a full stderr pipe blocking stdout (or vice versa).
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	go func() {
		data, err := machine.Shell(request, token, handle)
		completed <- completion{native: true, data: data, err: fromNativeError(err)}
	}()
	go func() { completed <- completion{err: shellInput(inputCtx, handle, a.Input)} }()
	go func() { completed <- completion{err: shellControls(inputCtx, handle, a.Controls)} }()
	go func() { completed <- completion{err: shellOutput(outputCtx, handle, false, a.Stdout, gate)} }()
	go func() { completed <- completion{err: shellOutput(outputCtx, handle, true, a.Stderr, gate)} }()
	var data []byte
	var first error
	parentDone := ctx.Done()
	for remaining := 5; remaining > 0; {
		select {
		case <-parentDone:
			parentDone = nil
			if first == nil {
				first = contextError(ctx.Err())
			}
			_ = token.Cancel()
			stopInput()
			stopOutput()
		case result := <-completed:
			remaining--
			if result.native {
				data = result.data
				if result.err == nil {
					stopInput()
				}
			}
			if result.err != nil && first == nil {
				first = result.err
				_ = token.Cancel()
				stopInput()
				stopOutput()
			}
		}
	}
	if first != nil {
		return nil, first
	}
	// Parent cancellation is still relevant if it raced the final completion.
	if ctx.Err() != nil {
		return nil, contextError(ctx.Err())
	}
	return data, nil
}

func shellInput(ctx context.Context, h *ffi.SshAttachment, factory func(context.Context) io.Reader) error {
	if ctx.Err() != nil {
		return nil
	}
	var reader io.Reader
	if factory != nil {
		reader = factory(ctx)
	}
	if reader == nil {
		return shellInputError(ctx, h.CloseStdin())
	}
	buffer := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			if writeErr := h.Write(buffer[:n]); writeErr != nil {
				if ctx.Err() == nil && err != nil && !errors.Is(err, io.EOF) {
					return err
				}
				return shellInputError(ctx, writeErr)
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return shellInputError(ctx, h.CloseStdin())
			}
			return err
		}
	}
}
func shellInputError(ctx context.Context, err error) error {
	err = fromNativeError(err)
	// Native completion closes input/control before publishing status. Its actual
	// success or failure is supervised separately, including cancellation errors.
	if ctx.Err() != nil || IsErrorKind(err, ErrorClosed) || IsErrorKind(err, ErrorCancelled) {
		return nil
	}
	return err
}
func shellControls(ctx context.Context, h *ffi.SshAttachment, controls <-chan SSHShellControl) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case c, ok := <-controls:
			if !ok {
				return nil
			}
			if err := validateShellControl(c); err != nil {
				return err
			}
			var err error
			if c.Kind == SSHShellResize {
				err = h.Resize(c.Rows, c.Columns)
			} else {
				err = h.Signal(uint32(c.Signal))
			}
			if err != nil {
				return shellInputError(ctx, err)
			}
		}
	}
}
func shellOutput(ctx context.Context, h *ffi.SshAttachment, stderr bool, writer SSHShellWriter, gate chan struct{}) error {
	for {
		data, eof, err := h.Read(stderr)
		if err != nil {
			err = fromNativeError(err)
			// Native failure wakes pipe readers before publishing its actual error.
			// Let that result preserve the root cause instead of a secondary wakeup.
			if ctx.Err() != nil || IsErrorKind(err, ErrorCancelled) {
				return nil
			}
			return err
		}
		if len(data) > 0 && writer != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-gate:
			}
			n, err := writer.WriteContext(ctx, data)
			gate <- struct{}{}
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				return err
			}
			if n != len(data) {
				return io.ErrShortWrite
			}
		}
		if eof {
			return nil
		}
	}
}
