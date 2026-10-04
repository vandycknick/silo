package sshd

import (
	"context"
	"io"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

// sessionPrompt asks the peer one line the way this session can: through the
// line editor on a PTY, otherwise a raw bounded read on the shared stream that
// keeps the CRLF boundary and treats ^C/^D as cancellation.
func sessionPrompt(streams service.IO) func(context.Context, string, int) (string, error) {
	if streams.Stdin == nil || streams.HumanWriter() == nil {
		return nil
	}
	return func(ctx context.Context, prompt string, limit int) (string, error) {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		if editor, ok := streams.Stdin.(*terminalInput); ok {
			previous := editor.r.ctx
			editor.r.ctx = ctx
			defer func() { editor.r.ctx = previous }()
			return editor.ReadPrompt(prompt, limit)
		}
		if n, e := io.WriteString(streams.HumanWriter(), prompt); e != nil {
			return "", e
		} else if n != len(prompt) {
			return "", io.ErrShortWrite
		}
		read := streams.Stdin.Read
		afterCR := func() {}
		if r, ok := streams.Stdin.(contextualInput); ok {
			r = contextualInput{ctx, r.input}
			r.input.mu.Lock()
			defer r.input.mu.Unlock()
			read = r.readLocked
			afterCR = func() { r.input.skipLF = true }
		}
		return scanLine(limit, func(b []byte) (int, error) {
			n, e := read(b)
			if n > 0 && (b[0] == 3 || b[0] == 4) {
				return 0, errLineCanceled
			}
			return n, e
		}, afterCR)
	}
}
