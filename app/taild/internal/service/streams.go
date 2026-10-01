package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	silo "github.com/vandycknick/silo/sdk/go"
)

type Window struct{ Rows, Columns uint16 }
type Terminal struct {
	Present bool
	Window  Window
	Term    string
	Windows <-chan Window
	Signals <-chan uint32
}
type ExecRequest struct {
	User, Directory string
	Env             map[string]string
	TTY             bool
	Program         string
	Args            []string
}
type IO struct {
	Stdin          io.Reader
	Input          func(context.Context) io.Reader
	Stdout, Stderr io.Writer
	Terminal       Terminal
}

type contextualWriter interface {
	WriteContext(context.Context, []byte) (int, error)
}

func writeContext(ctx context.Context, out io.Writer, data []byte) (int, error) {
	if writer, ok := out.(contextualWriter); ok {
		return writer.WriteContext(ctx, data)
	}
	return out.Write(data)
}

func (s *Service) streamContext(parent context.Context, c Caller, ref string, action identity.Action) (context.Context, context.CancelFunc, func() error) {
	ctx, cancel := context.WithCancel(parent)
	var mu sync.Mutex
	var denied error
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p, e := c.Fresh(ctx)
				if e == nil {
					m, _, err := s.machine(ctx, p, ref, action)
					e = err
					if m != nil {
						s.Runtime.CloseMachine(m)
					}
				}
				if e != nil {
					mu.Lock()
					denied = e
					mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel, func() error { cancel(); <-done; mu.Lock(); defer mu.Unlock(); return denied }
}
func (s *Service) Shell(ctx context.Context, c Caller, ref, user string, streams IO) (int, error) {
	if !streams.Terminal.Present {
		return 2, failure("usage", "shell requires a PTY; use ssh -t", 2)
	}
	// Managed guest provisioning selects /bin/bash for the configured account.
	return s.execute(ctx, c, ref, identity.Shell, ExecRequest{User: user, TTY: true, Program: "/bin/bash", Args: []string{"-l"}}, streams)
}
func (s *Service) Exec(ctx context.Context, c Caller, ref string, q ExecRequest, streams IO) (int, error) {
	return s.execute(ctx, c, ref, identity.Exec, q, streams)
}
func (s *Service) execute(parent context.Context, c Caller, ref string, action identity.Action, q ExecRequest, streams IO) (code int, err error) {
	if streams.Stdout == nil {
		streams.Stdout = io.Discard
	}
	if streams.Stderr == nil {
		streams.Stderr = io.Discard
	}
	if q.Program == "" || len(q.Program) > 4096 || strings.ContainsRune(q.Program, 0) || len(q.Args) > 256 || len(q.Env) > 64 || !text(q.User) || !text(q.Directory) {
		return 2, failure("usage", "invalid execution request", 2)
	}
	for _, arg := range q.Args {
		if len(arg) > 16384 || strings.ContainsRune(arg, 0) {
			return 2, failure("usage", "invalid guest argument", 2)
		}
	}
	for k, v := range q.Env {
		if !envKey(k) || len(v) > 16384 || strings.ContainsRune(v, 0) {
			return 2, failure("usage", "invalid guest environment", 2)
		}
	}
	if q.TTY && !streams.Terminal.Present {
		return 2, failure("usage", "-t requires a PTY; use ssh -t", 2)
	}
	p, e := c.Fresh(parent)
	if e != nil {
		return 4, e
	}
	m, d, e := s.machine(parent, p, ref, action)
	if e != nil {
		return Categorize(e).Exit, e
	}
	defer s.Runtime.CloseMachine(m)
	if d.Status.Kind != silo.MachineStatusRunning {
		return 5, failure("conflict", "VM must be running", 5)
	}
	ctx, cancel, recheck := s.streamContext(parent, c, d.ID, action)
	defer cancel()
	defer func() {
		if denied := recheck(); denied != nil {
			code = Categorize(denied).Exit
			err = denied
		}
	}()
	if q.User == "" {
		if d.GuestUser != nil {
			q.User = d.GuestUser.Name
		} else {
			q.User = s.Config.VM.GuestUser.Name
		}
	}
	if action == identity.Shell && d.GuestUser != nil && q.User == d.GuestUser.Name {
		q.Directory = d.GuestUser.Home
		q.Env = map[string]string{"HOME": d.GuestUser.Home, "USER": q.User, "LOGNAME": q.User, "SHELL": "/bin/bash"}
	}
	opts := []silo.ExecOption{silo.WithExecUser(q.User), silo.WithExecTTY(q.TTY), silo.WithExecWorkingDirectory(q.Directory), silo.WithExecEnv(maps.Clone(q.Env)), silo.WithExecStdinPipe()}
	if q.TTY {
		w := streams.Terminal.Window
		if w.Rows == 0 || w.Columns == 0 {
			return 2, failure("usage", "invalid initial PTY size", 2)
		}
		term := streams.Terminal.Term
		if term == "" {
			term = "xterm-256color"
		}
		if len(term) > 128 || !text(term) {
			return 2, failure("usage", "invalid TERM", 2)
		}
		opts = append(opts, silo.WithExecInitialPTYSize(w.Rows, w.Columns), silo.WithExecTerm(term))
	}
	exec, e := m.Spawn(ctx, q.Program, q.Args, opts...)
	if e != nil {
		return Categorize(e).Exit, Categorize(e)
	}
	s.Runtime.Metrics.Handle("exec", 1)
	defer func() { _ = exec.Close(); s.Runtime.Metrics.Handle("exec", -1) }()
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(cancelDone); _ = exec.Cancel() })
	defer func() {
		if !stop() {
			<-cancelDone
		}
	}()
	// The transport closes its input on disconnect. Native cancellation affects
	// this execution only, never the machine supervisor.
	if streams.Input != nil {
		streams.Stdin = streams.Input(ctx)
	}
	inputDone := make(chan struct{})
	// PTYs have no pipe EOF. Two EOTs flush an unterminated canonical line and
	// then signal EOF on the empty line. Raw PTYs receive two literal EOT bytes;
	// their process/cancellation controls lifetime. Never issue pipe Close there.
	started := make(chan struct{})
	startedOnce := false
	if streams.Stdin != nil {
		go func() {
			defer close(inputDone)
			select {
			case <-ctx.Done():
				return
			case <-started:
			}
			stdin := exec.Stdin()
			if stdin == nil {
				return
			}
			buf := make([]byte, 16384)
			for {
				n, e := streams.Stdin.Read(buf)
				if n > 0 {
					if _, err := stdin.WriteContext(ctx, buf[:n]); err != nil {
						break
					}
				}
				if e != nil {
					if q.TTY && errors.Is(e, io.EOF) {
						_, _ = stdin.WriteContext(ctx, []byte{4, 4})
					}
					break
				}
			}
			if !q.TTY {
				_ = stdin.Close()
			}
		}()
	} else {
		go func() {
			defer close(inputDone)
			select {
			case <-ctx.Done():
				return
			case <-started:
			}
			if stdin := exec.Stdin(); stdin != nil {
				if q.TTY {
					_, _ = stdin.WriteContext(ctx, []byte{4, 4})
				} else {
					_ = stdin.Close()
				}
			}
		}()
	}
	defer func() {
		cancel()
		_ = exec.Cancel()
		if streams.Input != nil || streams.Stdin == nil {
			<-inputDone
		}
	}()
	controlsDone := make(chan struct{})
	defer func() { cancel(); <-controlsDone }()
	go func() {
		defer close(controlsDone)
		select {
		case <-ctx.Done():
			return
		case <-started:
		}
		windows, signals := streams.Terminal.Windows, streams.Terminal.Signals
		for {
			select {
			case <-ctx.Done():
				return
			case w, ok := <-windows:
				if !ok {
					windows = nil
					continue
				}
				if q.TTY {
					_ = exec.ResizePTY(ctx, w.Rows, w.Columns)
				}
			case sig, ok := <-signals:
				if !ok {
					signals = nil
					continue
				}
				_ = exec.Signal(ctx, sig)
			}
		}
	}()
	for {
		event, e := exec.Recv(ctx)
		if e != nil {
			return 255, failure("unavailable", "guest execution stream lost", 255)
		}
		switch event.Kind {
		case silo.ExecutionEventStarted:
			if !startedOnce {
				close(started)
				startedOnce = true
			}
		case silo.ExecutionEventStdout, silo.ExecutionEventTerminalOutput:
			if _, e = writeContext(ctx, streams.Stdout, event.Data); e != nil {
				return 255, failure("transport", "guest output transport failed", 255)
			}
		case silo.ExecutionEventStderr:
			if _, e = writeContext(ctx, streams.Stderr, event.Data); e != nil {
				return 255, failure("transport", "guest output transport failed", 255)
			}
		case silo.ExecutionEventTerminal:
			if event.Result == nil {
				return 255, failure("unavailable", "guest execution result missing", 255)
			}
			r := event.Result
			switch r.Kind {
			case silo.ExecutionResultExited:
				if r.Code != nil {
					return int(*r.Code), nil
				}
			case silo.ExecutionResultSignaled:
				if r.Signal != nil {
					return min(255, 128+int(*r.Signal)), nil
				}
			case silo.ExecutionResultLaunchFailed:
				if r.LaunchFailure != nil && r.LaunchFailure.Reason == silo.LaunchFailureCommandNotFound {
					return 127, failure("guest_launch", "guest command not found", 127)
				}
				return 126, failure("guest_launch", "guest process could not launch", 126)
			case silo.ExecutionResultLost:
				return 255, failure("unavailable", "guest execution lost", 255)
			}
			return 255, failure("unavailable", "guest execution result invalid", 255)
		}
	}
}
func envKey(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i, c := range s {
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

type LogsRequest struct {
	Follow bool
	Source silo.MachineLogSource
	Output silo.MachineLogOutput
}

const logLimit = 4 << 20

func redact(line string) string {
	// Redact host-path-shaped and credential-shaped diagnostic fields. Never
	// expose SDK errors or state/credential file content through this endpoint.
	paths := regexp.MustCompile(`/[^\s"'<>]+`)
	secrets := regexp.MustCompile(`(?i)(tskey-|token|secret|password|authorization|authkey|credential|private.?key)`)
	lines := strings.Split(line, "\n")
	for i, v := range lines {
		if secrets.MatchString(v) {
			lines[i] = "[credential diagnostic redacted]"
		} else {
			lines[i] = paths.ReplaceAllString(v, "[path]")
		}
	}
	return strings.Join(lines, "\n")
}
func (s *Service) Logs(parent context.Context, c Caller, ref string, q LogsRequest, out io.Writer) (err error) {
	if q.Source == "" {
		q.Source = silo.MachineLogSerial
	}
	switch q.Source {
	case silo.MachineLogMonitor, silo.MachineLogSerial, silo.MachineLogExec, silo.MachineLogNetwork, silo.MachineLogNetworkAudit:
	default:
		return failure("usage", "invalid log stream", 2)
	}
	if q.Output != "" && q.Output != silo.MachineLogStdout && q.Output != silo.MachineLogStderr {
		return failure("usage", "invalid log output filter", 2)
	}
	p, e := c.Fresh(parent)
	if e != nil {
		return e
	}
	m, d, e := s.machine(parent, p, ref, identity.Logs)
	if e != nil {
		return e
	}
	defer s.Runtime.CloseMachine(m)
	ctx, cancel, recheck := s.streamContext(parent, c, d.ID, identity.Logs)
	defer cancel()
	defer func() {
		if denied := recheck(); denied != nil {
			err = denied
		}
	}()
	stream, e := m.Logs(ctx, q.Source, silo.MachineLogOptions{})
	if e != nil {
		return Categorize(e)
	}
	s.Runtime.Metrics.Handle("logs", 1)
	var tail []byte
	var historical uint64
	truncated := false
	for {
		chunk, e := stream.Recv(ctx)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			_ = stream.Close()
			s.Runtime.Metrics.Handle("logs", -1)
			return Categorize(e)
		}
		historical += uint64(len(chunk.Data))
		if q.Output != "" && q.Output != chunk.Output {
			continue
		}
		data := chunk.Data
		if len(data) >= logLimit {
			truncated = true
			tail = append(tail[:0], data[len(data)-logLimit:]...)
		} else {
			if len(tail)+len(data) > logLimit {
				truncated = true
				tail = tail[len(tail)+len(data)-logLimit:]
			}
			tail = append(tail, data...)
		}
	}
	_ = stream.Close()
	s.Runtime.Metrics.Handle("logs", -1)
	if truncated {
		if i := strings.IndexByte(string(tail), '\n'); i >= 0 {
			tail = tail[i+1:]
		} else {
			tail = nil
		}
	}
	var pending []byte
	if q.Follow {
		if i := bytes.LastIndexByte(tail, '\n'); i >= 0 {
			pending = append([]byte(nil), tail[i+1:]...)
			tail = tail[:i+1]
		} else {
			pending = tail
			tail = nil
		}
	}
	if _, e = writeContext(ctx, out, []byte(redact(string(tail)))); e != nil {
		return e
	}
	if !q.Follow {
		return nil
	}
	stream, e = m.Logs(ctx, q.Source, silo.MachineLogOptions{Follow: true})
	if e != nil {
		return Categorize(e)
	}
	s.Runtime.Metrics.Handle("logs", 1)
	defer func() { _ = stream.Close(); s.Runtime.Metrics.Handle("logs", -1) }()
	// Follow reopens at the beginning. Skip the snapshot already observed, then
	// redact complete bounded lines, including credentials split across chunks.
	line := pending
	discard := len(line) > 65536
	if discard {
		line = nil
	}
	for {
		chunk, e := stream.Recv(ctx)
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			return Categorize(e)
		}
		data := chunk.Data
		if historical > 0 {
			skip := min(historical, uint64(len(data)))
			historical -= skip
			data = data[skip:]
		}
		if q.Output != "" && q.Output != chunk.Output {
			continue
		}
		for _, b := range data {
			if b == '\n' {
				if !discard {
					if _, e = writeContext(ctx, out, []byte(redact(string(line))+"\n")); e != nil {
						return e
					}
				} else {
					if _, e = writeContext(ctx, out, []byte("[oversized log line omitted]\n")); e != nil {
						return e
					}
				}
				line = line[:0]
				discard = false
			} else if len(line) < 65536 && !discard {
				line = append(line, b)
			} else {
				line = line[:0]
				discard = true
			}
		}
	}
}
