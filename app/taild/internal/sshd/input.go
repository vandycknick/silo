package sshd

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/commands"
	"golang.org/x/term"
)

type inputChunk struct {
	data []byte
	err  error
}

var errLineCanceled = errors.New("terminal line canceled")

// terminalInput gives x/term exactly one byte at a time. Its private read-ahead
// can then contain only an incomplete key, never bytes belonging to the guest.
// All transport reads still go through sessionInput's bounded, single pump.
type terminalInput struct {
	ctx           context.Context
	r             contextualInput
	out           io.Writer
	terminal      *term.Terminal
	writeErr      error
	errMu         sync.Mutex
	queued        []byte
	paste         bool
	consumed      int
	canceled      bool
	lineErr       error
	lineLimit     int
	sizeMu        sync.Mutex
	width, height int
	editing       bool
}

func newTerminalInput(ctx context.Context, input *sessionInput, out io.Writer, width, height int) *terminalInput {
	if width <= 0 || height <= 0 {
		width, height = 80, 24
	}
	t := &terminalInput{ctx: ctx, r: contextualInput{ctx, input}, out: out, width: width, height: height}
	t.terminal = term.NewTerminal(t, "")
	t.terminal.History = commandHistory{History: t.terminal.History, input: t}
	t.terminal.AutoCompleteCallback = t.checkInsertion
	if width > 0 && height > 0 {
		_ = t.terminal.SetSize(width, height)
	}
	return t
}

// Keep x/term's bounded history, omitting empty/canceled lines and repeats.
type commandHistory struct {
	term.History
	input *terminalInput
}

func (h commandHistory) Add(line string) {
	if h.input.lineErr != nil || h.input.canceled || strings.TrimSpace(line) == "" {
		return
	}
	if h.Len() != 0 && h.At(0) == line {
		return
	}
	h.History.Add(line)
}

// x/term invokes this public hook with the full edited line before inserting
// printable keys, including after history recall. Refuse insertion before its
// private 4096-rune ceiling can silently drop input, and poison this submission
// even if later edits shorten the line. Cursor/editing remain owned by x/term.
func (t *terminalInput) checkInsertion(line string, pos int, key rune) (string, int, bool) {
	if key >= 32 && utf8.ValidRune(key) && (utf8.RuneCountInString(line) >= 4096 || len(line)+utf8.RuneLen(key) > t.lineLimit) {
		t.lineErr = commands.Usage()
		return line, pos, true
	}
	return "", 0, false
}

func (t *terminalInput) Write(p []byte) (int, error) {
	var n int
	var e error
	if out, ok := t.out.(interface {
		WriteContext(context.Context, []byte) (int, error)
	}); ok {
		ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
		defer cancel()
		n, e = out.WriteContext(ctx, p)
	} else {
		n, e = t.out.Write(p)
	}
	if e == nil && n != len(p) {
		e = io.ErrShortWrite
	}
	if e != nil {
		t.errMu.Lock()
		t.writeErr = e
		t.errMu.Unlock()
	}
	return n, e
}

func (t *terminalInput) outputError() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.writeErr
}

func (t *terminalInput) byte() (byte, error) {
	var b [1]byte
	_, e := io.ReadFull(t.r, b[:])
	t.consumed++
	// Bound control/paste activity independently of the effective edited line.
	if t.consumed > 65536 {
		return 0, commands.Usage()
	}
	return b[0], e
}

func (t *terminalInput) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
keys:
	for {
		if e := t.outputError(); e != nil {
			return 0, e
		}
		if len(t.queued) != 0 {
			p[0] = t.queued[0]
			t.queued = t.queued[1:]
			return 1, nil
		}
		b, e := t.byte()
		if e != nil {
			return 0, e
		}
		if b == 27 {
			// Consume complete escape keys before x/term sees them. Unknown
			// terminal controls are discarded, rather than becoming commands.
			seq := []byte{b}
			b, e = t.byte()
			if e != nil {
				return 0, e
			}
			seq = append(seq, b)
			if b == 3 && !t.paste {
				t.cancelLine()
				continue
			}
			if b == 4 && !t.paste {
				t.queued = []byte{4}
				continue
			}
			if b != '[' && b != 'O' {
				return 0, commands.Usage()
			}
			for len(seq) < 64 {
				b, e = t.byte()
				if e != nil {
					return 0, e
				}
				seq = append(seq, b)
				if b == 3 && !t.paste {
					t.cancelLine()
					continue keys
				}
				if b == 4 && !t.paste {
					t.queued = []byte{4}
					continue keys
				}
				if b < 32 || b > 126 {
					return 0, commands.Usage()
				}
				if b >= 0x40 && b <= 0x7e {
					break
				}
			}
			if len(seq) == 64 {
				return 0, commands.Usage()
			}
			switch string(seq) {
			case "\x1b[200~":
				t.paste = true
			case "\x1b[201~":
				t.paste = false
			case "\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D", "\x1b[H", "\x1b[F", "\x1b[3~", "\x1bOA", "\x1bOB", "\x1bOC", "\x1bOD", "\x1bOH", "\x1bOF":
				if !t.paste {
					if seq[1] == 'O' {
						seq[1] = '['
					}
					t.queued = seq
				}
			}
			continue
		}
		if b >= utf8.RuneSelf {
			seq := []byte{b}
			for !utf8.FullRune(seq) {
				b, e = t.byte()
				if e != nil {
					return 0, e
				}
				seq = append(seq, b)
			}
			r, size := utf8.DecodeRune(seq)
			if r == utf8.RuneError {
				if size == 1 {
					return 0, commands.Usage()
				}
				// x/term uses RuneError as its incomplete-key sentinel. Keep a
				// literal replacement character from filling its private buffer.
				seq = []byte{'?'}
			}
			if unicode.IsControl(r) {
				continue
			}
			t.queued = seq
			continue
		}
		if t.paste {
			// Pasted newlines are text, not submission. An explicit Enter after
			// the closing bracket is required. Pasted controls cannot edit/exit.
			if b == '\r' || b == '\n' || b == '\t' {
				b = ' '
			}
			if b < 32 || b == 127 {
				continue
			}
		} else {
			if b == 3 {
				// Clear and submit an empty editor line, then report cancellation
				// to the lobby. Keep x/term history and cursor/resize state.
				t.cancelLine()
				continue
			}
			if b == '\r' {
				t.r.input.mu.Lock()
				t.r.input.skipLF = true
				t.r.input.mu.Unlock()
			}
		}
		p[0] = b
		return 1, nil
	}
}

func (t *terminalInput) cancelLine() {
	t.canceled = true
	t.queued = []byte{5, 21, '\r'}
}

func (t *terminalInput) resize(width, height int) {
	t.sizeMu.Lock()
	defer t.sizeMu.Unlock()
	t.width, t.height = width, height
	if t.editing {
		_ = t.terminal.SetSize(width, height)
	}
}

func (t *terminalInput) ReadLine(limit int) (string, error) {
	return t.ReadPrompt("", limit)
}

func (t *terminalInput) ReadPrompt(prompt string, limit int) (string, error) {
	t.sizeMu.Lock()
	t.terminal.SetPrompt(prompt)
	_ = t.terminal.SetSize(t.width, t.height)
	t.editing = true
	t.sizeMu.Unlock()
	defer func() {
		t.sizeMu.Lock()
		t.editing = false
		t.terminal.SetPrompt("")
		t.sizeMu.Unlock()
	}()
	t.consumed = 0
	t.canceled = false
	t.lineErr = nil
	t.lineLimit = limit
	// Enable only while the daemon owns input, then release terminal mode
	// before guest handoff. The adapter flattens pasted newlines to text.
	if _, e := io.WriteString(t, "\x1b[?2004h"); e != nil {
		return "", e
	}
	line, e := t.terminal.ReadLine()
	if _, err := io.WriteString(t, "\x1b[?2004l"); err != nil {
		return "", err
	}
	if e := t.outputError(); e != nil {
		return "", e
	}
	if t.lineErr != nil {
		return "", t.lineErr
	}
	if t.canceled {
		t.canceled = false
		if e != nil {
			return "", e
		}
		return "", errLineCanceled
	}
	if len(line) > limit {
		return "", commands.Usage()
	}
	if e != nil {
		return "", e
	}
	return line, e
}

func terminalStreams(ctx context.Context, src io.Reader, streams service.IO) service.IO {
	input := newInput(ctx, src)
	streams.Input = input.Reader
	streams.Stdin = input.Reader(ctx)
	if streams.Human == nil {
		streams.Human = streams.Stderr
		if streams.Terminal.Present {
			streams.Human = &humanWriter{out: streams.Stderr}
		}
	}
	if streams.Terminal.Present {
		w := streams.Terminal.Window
		streams.Stdin = newTerminalInput(ctx, input, streams.Human, int(w.Columns), int(w.Rows))
	}
	streams.Prompt = sessionPrompt(streams)
	return streams
}

func terminalResize(streams service.IO, converted chan service.Window, width, height int) {
	if width <= 0 || width > 65535 || height <= 0 || height > 65535 {
		return
	}
	if editor, ok := streams.Stdin.(*terminalInput); ok {
		editor.resize(width, height)
	}
	next := service.Window{Rows: uint16(height), Columns: uint16(width)}
	select {
	case converted <- next:
	default:
		select {
		case <-converted:
		default:
		}
		select {
		case converted <- next:
		default:
		}
	}
}

// Lobby is the production interactive front end below WhoIs authentication.
// Local SSH tests supply an explicit domain caller at this same boundary.
func Lobby(ctx context.Context, s *service.Service, caller service.Caller, streams service.IO) int {
	streams = normalizeHuman(streams)
	if streams.Prompt == nil {
		streams.Prompt = sessionPrompt(streams)
	}
	if failure := service.Categorize(s.CheckIdentity(caller.Peer)); failure != nil {
		return respond(&commands.Context{Context: ctx, Streams: streams}, commands.Result{}, failure)
	}
	if streams.Prompt == nil {
		return 0
	}
	notices := &lobbyNotices{seen: map[string]string{}}
	streams.ApprovalShown = func(vm, url string) { notices.seen[vm] = url }
	for {
		line, e := notices.prompt(ctx, s, caller, streams)
		if errors.Is(e, errLineCanceled) {
			continue
		}
		if errors.Is(e, io.EOF) {
			return 0
		}
		if e != nil {
			return 255
		}
		line = strings.TrimSpace(line)
		if line == "exit" {
			return 0
		}
		if line == "" {
			continue
		}
		peer, e := caller.Fresh(ctx)
		if e != nil || peer.NodeID != caller.Peer.NodeID {
			return 4
		}
		caller.Peer = peer
		if code := DispatchSession(ctx, s, caller, line, streams); code == 255 {
			return code
		}
	}
}

// One bounded transport read pump serves both command lines and guest input.
// Per-command readers can stop without closing the SSH channel or competing
// with the prompt for reads after guest execution finishes.
type sessionInput struct {
	start   func()
	mu      sync.Mutex
	chunks  chan inputChunk
	pending []byte
	err     error
	skipLF  bool
}

func newInput(ctx context.Context, src io.Reader) *sessionInput {
	s := &sessionInput{chunks: make(chan inputChunk, 1)}
	s.start = func() {
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
	}
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
	if s.start != nil {
		start := s.start
		s.start = nil
		start()
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
	return "", commands.Usage()
}
