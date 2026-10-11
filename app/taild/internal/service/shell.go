package service

import (
	"bytes"
	"context"
	"io"
	"strings"

	silo "github.com/vandycknick/silo/sdk/go"
)

// finiteShellWriter adapts only nonblocking, in-memory outputs. Production
// transports must supply WriteContext; a plain blocking Write is not cancellable.
type finiteShellWriter struct{ io.Writer }

func (w finiteShellWriter) WriteContext(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return w.Write(p)
}

func shellWriter(w io.Writer) (silo.SSHShellWriter, error) {
	if w == nil || w == io.Discard {
		return finiteShellWriter{io.Discard}, nil
	}
	if writer, ok := w.(ContextWriter); ok {
		return writer, nil
	}
	switch w.(type) {
	case *bytes.Buffer, *strings.Builder:
		return finiteShellWriter{w}, nil
	default:
		return nil, failure("usage", "shell output requires a cancellation-aware writer", 2)
	}
}

func shellInput(ctx context.Context, source io.Reader) io.Reader {
	if source == nil {
		return strings.NewReader("")
	}
	if r, ok := source.(interface {
		ReadContext(context.Context, []byte) (int, error)
	}); ok {
		return fileContextReader{ctx: ctx, reader: r}
	}
	return source // Only explicitly finite readers are accepted by sshShell.
}

// eofAdapter preserves data-plus-EOF ordering and appends two EOT bytes exactly
// once after genuine EOF. Cancellation and read failures never fabricate EOF.
type shellEOFReader struct {
	ctx   context.Context
	input io.Reader
	eof   bool
	eot   int
}

func eofAdapter(ctx context.Context, input io.Reader) io.Reader {
	return &shellEOFReader{ctx: ctx, input: input}
}

func (r *shellEOFReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if !r.eof {
		n, err := r.input.Read(p)
		if err != io.EOF {
			return n, err
		}
		if canceled := r.ctx.Err(); canceled != nil {
			return n, canceled
		}
		r.eof = true
		if n > 0 {
			return n, nil
		}
	}
	if r.eot == 2 {
		return 0, io.EOF
	}
	n := min(len(p), 2-r.eot)
	for i := range n {
		p[i] = 4
	}
	r.eot += n
	return n, nil
}

func (s *Service) sshShell(ctx context.Context, m *silo.Machine, user string, streams IO) (int, error) {
	w := streams.Terminal.Window
	term := streams.Terminal.Term
	stdout, err := shellWriter(streams.Stdout)
	if err != nil {
		return 2, err
	}
	stderr, err := shellWriter(streams.Stderr)
	if err != nil {
		return 2, err
	}
	if streams.Input == nil && streams.Stdin != nil {
		if _, ok := streams.Stdin.(interface {
			ReadContext(context.Context, []byte) (int, error)
		}); !ok {
			switch streams.Stdin.(type) {
			case *strings.Reader, *bytes.Reader, *bytes.Buffer:
			default:
				return 2, failure("usage", "shell input requires a cancellation-aware reader", 2)
			}
		}
	}
	controls := make(chan silo.SSHShellControl)
	var controlsDone chan struct{}
	attachment := silo.SSHShellAttachment{
		Rows: w.Rows, Columns: w.Columns, Stdout: stdout, Stderr: stderr, Controls: controls,
		Input: func(inputCtx context.Context) io.Reader {
			controlsDone = make(chan struct{})
			go func() {
				defer close(controlsDone)
				defer close(controls)
				windows, signals := streams.Terminal.Windows, streams.Terminal.Signals
				for windows != nil || signals != nil {
					var control silo.SSHShellControl
					select {
					case <-inputCtx.Done():
						return
					case size, ok := <-windows:
						if !ok {
							windows = nil
							continue
						}
						if size.Rows == 0 || size.Columns == 0 {
							continue
						}
						control = silo.SSHShellControl{Kind: silo.SSHShellResize, Rows: size.Rows, Columns: size.Columns}
					case signal, ok := <-signals:
						if !ok {
							signals = nil
							continue
						}
						control = silo.SSHShellControl{Kind: silo.SSHShellSendSignal, Signal: silo.SSHShellSignal(signal)}
					}
					select {
					case <-inputCtx.Done():
						return
					case controls <- control:
					}
				}
			}()
			input := shellInput(inputCtx, streams.Stdin)
			if streams.Input != nil {
				input = streams.Input(inputCtx)
				if input == nil {
					input = strings.NewReader("")
				}
			}
			return eofAdapter(inputCtx, input)
		},
	}
	s.Runtime.Metrics.Handle("exec", 1)
	defer s.Runtime.Metrics.Handle("exec", -1)
	status, err := m.Shell(ctx, silo.WithSSHUser(user), silo.WithSSHTerm(term), silo.WithShellAttachment(attachment))
	if controlsDone != nil {
		<-controlsDone
	}
	if err != nil {
		return Categorize(err).Exit, Categorize(err)
	}
	return int(status.Code), nil
}
