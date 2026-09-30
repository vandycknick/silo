package sshd

import (
	"context"
	"io"
)

// SSH writes may block on peer flow control. A stream authorization failure
// must close the channel even if that peer has stopped consuming output.
type sessionOutput struct {
	parent context.Context
	out    io.Writer
	close  func()
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
	return w.out.Write(data)
}
