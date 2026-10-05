package sshd

import (
	"context"
	"io"
	"sync"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

// SSH writes may block on peer flow control. A stream authorization failure
// must close the channel even if that peer has stopped consuming output.
type sessionOutput struct {
	parent context.Context
	out    io.Writer
	close  func()
}

func normalizeHuman(streams service.IO) service.IO {
	if streams.Human == nil {
		streams.Human = streams.Stderr
	}
	if streams.Terminal.Present {
		if _, ok := streams.Human.(*humanWriter); !ok {
			streams.Human = &humanWriter{out: streams.Human}
		}
	}
	return streams
}

// Only daemon-owned text passes through here. In particular, SSH's stdout
// already has upstream PTY translation, while extended-data stderr does not.
type humanWriter struct {
	mu  sync.Mutex
	out io.Writer
	cr  bool
}

func (w *humanWriter) Write(data []byte) (int, error) {
	return w.write(nil, data)
}

func (w *humanWriter) WriteContext(ctx context.Context, data []byte) (int, error) {
	return w.write(ctx, data)
}

func (w *humanWriter) write(ctx context.Context, data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	buf := make([]byte, 0, len(data)+16)
	for _, b := range data {
		if b == '\n' && !w.cr {
			buf = append(buf, '\r')
		}
		buf = append(buf, b)
		w.cr = b == '\r'
	}
	var n int
	var err error
	if out, ok := w.out.(interface {
		WriteContext(context.Context, []byte) (int, error)
	}); ok && ctx != nil {
		n, err = out.WriteContext(ctx, buf)
	} else {
		n, err = w.out.Write(buf)
	}
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (w sessionOutput) Write(data []byte) (int, error) { return w.WriteContext(w.parent, data) }
func (w sessionOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); w.close() })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	n, e := w.out.Write(data)
	if e == nil && n != len(data) {
		e = io.ErrShortWrite
	}
	if e != nil {
		w.close()
	}
	return n, e
}
