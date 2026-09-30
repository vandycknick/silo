package sshd

import (
	"context"
	"io"
	"sync"
)

type inputChunk struct {
	data []byte
	err  error
}

// One bounded transport read pump serves both command lines and guest input.
// Per-command readers can stop without closing the SSH channel or competing
// with the prompt for reads after guest execution finishes.
type sessionInput struct {
	mu      sync.Mutex
	chunks  chan inputChunk
	pending []byte
	err     error
	skipLF  bool
}

func newInput(ctx context.Context, src io.Reader) *sessionInput {
	s := &sessionInput{chunks: make(chan inputChunk, 1)}
	go func() {
		defer close(s.chunks)
		for {
			buf := make([]byte, 16384)
			n, e := src.Read(buf)
			select {
			case <-ctx.Done():
				return
			case s.chunks <- inputChunk{buf[:n], e}:
			}
			if e != nil {
				return
			}
		}
	}()
	return s
}

type contextualInput struct {
	ctx   context.Context
	input *sessionInput
}

func (s *sessionInput) Reader(ctx context.Context) io.Reader { return contextualInput{ctx, s} }
func (r contextualInput) Read(buf []byte) (int, error) {
	s := r.input
	s.mu.Lock()
	defer s.mu.Unlock()
	return r.readLocked(buf)
}

func (r contextualInput) readLocked(buf []byte) (int, error) {
	s := r.input
	if len(buf) == 0 {
		return 0, nil
	}
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	for {
		for len(s.pending) == 0 && s.err == nil {
			select {
			case <-r.ctx.Done():
				return 0, r.ctx.Err()
			case chunk, ok := <-s.chunks:
				if !ok {
					s.err = io.EOF
				} else {
					s.pending = chunk.data
					s.err = chunk.err
				}
			}
		}
		if len(s.pending) == 0 {
			return 0, s.err
		}
		if s.skipLF {
			s.skipLF = false
			if s.pending[0] == '\n' {
				s.pending = s.pending[1:]
				continue
			}
		}
		n := copy(buf, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
}

// The optional LF belongs to the shared stream, not to a temporary command
// reader. CR-only input returns immediately; the next line or guest data read
// consumes a following LF exactly once, even across chunks/readers.
func (r contextualInput) ReadLine(limit int) (string, error) {
	r.input.mu.Lock()
	defer r.input.mu.Unlock()
	return scanLine(limit, r.readLocked, func() { r.input.skipLF = true })
}

func readLine(src io.Reader) (string, error) { return readLineLimit(src, 16384) }
func readLineLimit(src io.Reader, limit int) (string, error) {
	if reader, ok := src.(interface{ ReadLine(int) (string, error) }); ok {
		return reader.ReadLine(limit)
	}
	return scanLine(limit, src.Read, func() {})
}

func scanLine(limit int, read func([]byte) (int, error), afterCR func()) (string, error) {
	buf := make([]byte, 0, 128)
	var one [1]byte
	for len(buf) <= limit {
		n, e := read(one[:])
		if n > 0 {
			if one[0] == '\r' {
				afterCR()
				return string(buf), nil
			}
			if one[0] == '\n' {
				return string(buf), nil
			}
			buf = append(buf, one[0])
		}
		if e != nil {
			return "", e
		}
	}
	return "", usage()
}
