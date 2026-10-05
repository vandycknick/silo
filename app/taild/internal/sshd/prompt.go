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
		if r, ok := streams.Stdin.(contextualInput); ok {
			return contextualInput{ctx, r.input}.ReadLine(limit)
		}
		return scanLine(limit, streams.Stdin.Read, func() {})
	}
}
