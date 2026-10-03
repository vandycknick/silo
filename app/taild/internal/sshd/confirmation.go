package sshd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func confirmRemoval(ctx context.Context, streams service.IO, target service.RemovalTarget) bool {
	if streams.Stdin == nil {
		return false
	}
	verb := "Remove"
	if target.Running {
		verb = "Stop and remove"
	}
	prompt := fmt.Sprintf("%s VM '%s'? [y/N] ", verb, target.Name)
	for ctx.Err() == nil {
		line, e := removalPrompt(streams.Stdin, humanOutput(streams), prompt)
		if e != nil || ctx.Err() != nil {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true
		case "", "n", "no":
			return false
		}
	}
	return false
}

func removalPrompt(src io.Reader, out io.Writer, prompt string) (string, error) {
	if editor, ok := src.(interface {
		ReadPrompt(string, int) (string, error)
	}); ok {
		return editor.ReadPrompt(prompt, 1024)
	}
	if _, e := io.WriteString(out, prompt); e != nil {
		return "", e
	}
	read := src.Read
	afterCR := func() {}
	// Preserve the shared stream's CRLF boundary without editor read-ahead.
	if r, ok := src.(contextualInput); ok {
		r.input.mu.Lock()
		defer r.input.mu.Unlock()
		read = r.readLocked
		afterCR = func() { r.input.skipLF = true }
	}
	return scanLine(1024, func(b []byte) (int, error) {
		n, e := read(b)
		if n > 0 && (b[0] == 3 || b[0] == 4) {
			return 0, errLineCanceled
		}
		return n, e
	}, afterCR)
}
