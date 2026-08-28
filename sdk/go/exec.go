package silo

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"sync"
	"time"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

type execConfig struct {
	Program        string            `json:"program,omitempty"`
	Script         string            `json:"script,omitempty"`
	Args           []string          `json:"args,omitempty"`
	AdditionalArgs []string          `json:"additional_args,omitempty"`
	CWD            string            `json:"cwd,omitempty"`
	User           string            `json:"user,omitempty"`
	Env            map[string]string `json:"env"`
	TimeoutMillis  *uint64           `json:"timeout_millis,omitempty"`
	Stdin          []byte            `json:"stdin,omitempty"`
	PipeStdin      bool              `json:"pipe_stdin"`
	TTY            *bool             `json:"tty,omitempty"`
	error          error
}
type ExecOption func(*execConfig)

func WithExecAdditionalArgs(args ...string) ExecOption {
	return func(c *execConfig) { c.AdditionalArgs = append([]string(nil), args...) }
}
func WithExecWorkingDirectory(path string) ExecOption { return func(c *execConfig) { c.CWD = path } }
func WithExecUser(user string) ExecOption             { return func(c *execConfig) { c.User = user } }
func WithExecEnv(env map[string]string) ExecOption {
	return func(c *execConfig) {
		c.Env = maps.Clone(env)
		if c.Env == nil {
			c.Env = make(map[string]string)
		}
	}
}
func WithExecTimeout(timeout time.Duration) ExecOption {
	return func(c *execConfig) {
		if timeout <= 0 {
			c.error = newError(ErrorInvalidArgument, "", "execution timeout must be positive")
			return
		}
		value := uint64(timeout / time.Millisecond)
		if timeout%time.Millisecond != 0 {
			value++
		}
		c.TimeoutMillis = &value
	}
}
func WithExecStdin(data []byte) ExecOption {
	return func(c *execConfig) {
		if c.PipeStdin {
			c.error = newError(ErrorInvalidArgument, "", "execution stdin bytes and pipe mode are mutually exclusive")
			return
		}
		c.Stdin = append([]byte(nil), data...)
	}
}
func WithExecStdinPipe() ExecOption {
	return func(c *execConfig) {
		if c.Stdin != nil {
			c.error = newError(ErrorInvalidArgument, "", "execution stdin bytes and pipe mode are mutually exclusive")
			return
		}
		c.PipeStdin = true
	}
}
func WithExecTTY(enabled bool) ExecOption { return func(c *execConfig) { c.TTY = &enabled } }

func executionRequest(program string, args []string, opts []ExecOption) ([]byte, error) {
	if program == "" {
		return nil, newError(ErrorInvalidArgument, "", "program must not be empty")
	}
	config := execConfig{Program: program, Args: append([]string(nil), args...), Env: map[string]string{}}
	for _, option := range opts {
		if option == nil {
			return nil, newError(ErrorInvalidArgument, "", "execution option must not be nil")
		}
		option(&config)
	}
	if config.error != nil {
		return nil, config.error
	}
	return json.Marshal(config)
}
func shellRequest(script string, opts []ExecOption) ([]byte, error) {
	if script == "" {
		return nil, newError(ErrorInvalidArgument, "", "script must not be empty")
	}
	data, err := executionRequest("shell", nil, opts)
	if err != nil {
		return nil, err
	}
	var config execConfig
	if err = json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	config.Program = ""
	config.Script = script
	return json.Marshal(config)
}

// ExecutionOutput contains exact output bytes and the terminal execution result.
type ExecutionOutput struct {
	result                   ExecutionResult
	stdout, stderr, terminal []byte
}

func (o *ExecutionOutput) Result() ExecutionResult {
	result := o.result
	if result.Code != nil {
		value := *result.Code
		result.Code = &value
	}
	if result.Signal != nil {
		value := *result.Signal
		result.Signal = &value
	}
	if result.LaunchFailure != nil {
		value := *result.LaunchFailure
		result.LaunchFailure = &value
	}
	if result.Lost != nil {
		value := *result.Lost
		result.Lost = &value
	}
	return result
}
func (o *ExecutionOutput) StdoutBytes() []byte         { return append([]byte(nil), o.stdout...) }
func (o *ExecutionOutput) StderrBytes() []byte         { return append([]byte(nil), o.stderr...) }
func (o *ExecutionOutput) TerminalOutputBytes() []byte { return append([]byte(nil), o.terminal...) }
func (o *ExecutionOutput) Stdout() string              { return string(o.stdout) }
func (o *ExecutionOutput) Stderr() string              { return string(o.stderr) }
func (o *ExecutionOutput) TerminalOutput() string      { return string(o.terminal) }

type resultWire struct {
	Kind    ExecutionResultKind `json:"kind"`
	Code    *uint32             `json:"code"`
	Signal  *uint32             `json:"signal"`
	Reason  *string             `json:"reason"`
	Message *string             `json:"message"`
}
type eventWire struct {
	Kind   ExecutionEventKind `json:"kind"`
	Result *resultWire        `json:"result"`
}

func decodeResult(w resultWire) ExecutionResult {
	r := ExecutionResult{Kind: w.Kind, Code: w.Code, Signal: w.Signal}
	message := ""
	if w.Message != nil {
		message = *w.Message
	}
	if w.Reason != nil {
		if w.Kind == ExecutionResultLaunchFailed {
			r.LaunchFailure = &ExecutionLaunchFailure{Reason: ExecutionLaunchFailureReason(*w.Reason), Message: message}
		} else if w.Kind == ExecutionResultLost {
			r.Lost = &ExecutionLost{Reason: ExecutionLostReason(*w.Reason), Message: message}
		}
	}
	return r
}
func decodeOutput(data *ffi.ExecutionOutput) (*ExecutionOutput, error) {
	var result resultWire
	if err := json.Unmarshal(data.Result, &result); err != nil {
		return nil, newError(ErrorUnknown, "", "decode execution result: "+err.Error())
	}
	return &ExecutionOutput{
		result:   decodeResult(result),
		stdout:   append([]byte(nil), data.Stdout...),
		stderr:   append([]byte(nil), data.Stderr...),
		terminal: append([]byte(nil), data.TerminalOutput...),
	}, nil
}

func (m *Machine) Exec(ctx context.Context, program string, args []string, opts ...ExecOption) (*ExecutionOutput, error) {
	request, err := executionRequest(program, args, opts)
	if err != nil {
		return nil, err
	}
	return m.collected(ctx, request, false)
}
func (m *Machine) Shell(ctx context.Context, script string, opts ...ExecOption) (*ExecutionOutput, error) {
	request, err := shellRequest(script, opts)
	if err != nil {
		return nil, err
	}
	return m.collected(ctx, request, true)
}
func (m *Machine) collected(ctx context.Context, request []byte, shell bool) (*ExecutionOutput, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return nil, newError(ErrorClosed, "", "machine is closed")
	}
	var data *ffi.ExecutionOutput
	var err error
	if shell {
		data, err = m.native.Shell(request)
	} else {
		data, err = m.native.Exec(request)
	}
	if err != nil {
		return nil, fromNativeError(err)
	}
	return decodeOutput(data)
}
func (m *Machine) Spawn(ctx context.Context, program string, args []string, opts ...ExecOption) (*ExecutionSession, error) {
	request, err := executionRequest(program, args, opts)
	if err != nil {
		return nil, err
	}
	if err = validateContext(ctx); err != nil {
		return nil, err
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return nil, newError(ErrorClosed, "", "machine is closed")
	}
	native, err := m.native.Spawn(request)
	if err != nil {
		return nil, fromNativeError(err)
	}
	stdin, err := native.Stdin()
	if err != nil {
		native.Close()
		return nil, fromNativeError(err)
	}
	session := &ExecutionSession{native: native}
	if stdin != nil {
		session.stdin = &ExecutionStdin{native: stdin}
	}
	return session, nil
}

// ExecutionSession is a bidirectional structured execution. Recv, Wait, and Collect must not overlap.
type ExecutionSession struct {
	mutex    sync.RWMutex
	native   *ffi.Execution
	stdin    *ExecutionStdin
	closed   bool
	receiver sync.Mutex
}

func (s *ExecutionSession) Stdin() *ExecutionStdin {
	if s == nil {
		return nil
	}
	return s.stdin
}
func (s *ExecutionSession) Recv(ctx context.Context) (*ExecutionEvent, error) {
	type receive struct {
		event *ffi.ExecutionEvent
		eof   bool
	}
	result, err := sessionCall(s, ctx, func(native *ffi.Execution) (receive, error) {
		event, eof, err := native.Recv()
		return receive{event: event, eof: eof}, err
	})
	if err != nil {
		return nil, err
	}
	if result.eof {
		return nil, io.EOF
	}
	var wire eventWire
	if err = json.Unmarshal(result.event.Metadata, &wire); err != nil {
		return nil, newError(ErrorUnknown, "", "decode execution event: "+err.Error())
	}
	event := &ExecutionEvent{Kind: wire.Kind, Data: append([]byte(nil), result.event.Data...)}
	if wire.Result != nil {
		value := decodeResult(*wire.Result)
		event.Result = &value
	}
	return event, nil
}

func (s *ExecutionSession) Wait(ctx context.Context) (ExecutionResult, error) {
	data, err := sessionCall(s, ctx, func(native *ffi.Execution) ([]byte, error) {
		return native.Wait()
	})
	if err != nil {
		return ExecutionResult{}, err
	}
	var wire resultWire
	if err = json.Unmarshal(data, &wire); err != nil {
		return ExecutionResult{}, newError(ErrorUnknown, "", "decode execution result: "+err.Error())
	}
	return decodeResult(wire), nil
}

func (s *ExecutionSession) Collect(ctx context.Context) (*ExecutionOutput, error) {
	data, err := sessionCall(s, ctx, func(native *ffi.Execution) (*ffi.ExecutionOutput, error) {
		return native.Collect()
	})
	if err != nil {
		return nil, err
	}
	return decodeOutput(data)
}

func sessionCall[T any](s *ExecutionSession, ctx context.Context, call func(*ffi.Execution) (T, error)) (T, error) {
	var zero T
	if err := validateContext(ctx); err != nil {
		return zero, err
	}
	if !s.receiver.TryLock() {
		return zero, newError(ErrorInvalidArgument, "", "execution session already has an active receiver")
	}
	defer s.receiver.Unlock()
	s.mutex.RLock()
	if s.closed {
		s.mutex.RUnlock()
		return zero, newError(ErrorClosed, "", "execution session is closed")
	}
	native := s.native
	s.mutex.RUnlock()
	type callResult struct {
		value T
		err   error
	}
	done := make(chan callResult, 1)
	go func() {
		value, err := call(native)
		done <- callResult{value: value, err: err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			return zero, fromNativeError(result.err)
		}
		return result.value, nil
	case <-ctx.Done():
		_ = native.Cancel()
		<-done
		return zero, contextError(ctx.Err())
	}
}
func (s *ExecutionSession) Signal(ctx context.Context, signal uint32) error {
	return s.control(ctx, func() error { return s.native.Signal(signal) })
}
func (s *ExecutionSession) ResizePTY(ctx context.Context, rows, columns uint16) error {
	if rows == 0 || columns == 0 {
		return newError(ErrorInvalidArgument, "", "PTY rows and columns must be positive")
	}
	return s.control(ctx, func() error { return s.native.ResizePTY(rows, columns) })
}
func (s *ExecutionSession) control(ctx context.Context, call func() error) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s.closed {
		return newError(ErrorClosed, "", "execution session is closed")
	}
	return fromNativeError(call())
}
func (s *ExecutionSession) CloseRequests() error {
	return s.control(context.Background(), s.native.CloseRequests)
}
func (s *ExecutionSession) Cancel() error { return s.control(context.Background(), s.native.Cancel) }
func (s *ExecutionSession) Close() error {
	if s == nil {
		return nil
	}
	s.mutex.RLock()
	if s.closed {
		s.mutex.RUnlock()
		return nil
	}
	native := s.native
	_ = native.Cancel()
	s.mutex.RUnlock()

	s.receiver.Lock()
	defer s.receiver.Unlock()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	if s.stdin != nil {
		_ = s.stdin.Close()
	}
	native.Close()
	s.native = nil
	s.closed = true
	return nil
}

// ExecutionStdin implements io.WriteCloser for pipe or PTY input.
type ExecutionStdin struct {
	mutex  sync.Mutex
	native *ffi.Stdin
	closed bool
}

func (s *ExecutionStdin) Write(data []byte) (int, error) {
	return s.WriteContext(context.Background(), data)
}
func (s *ExecutionStdin) WriteContext(ctx context.Context, data []byte) (int, error) {
	if err := validateContext(ctx); err != nil {
		return 0, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return 0, newError(ErrorClosed, "", "execution stdin is closed")
	}
	if err := s.native.Write(data); err != nil {
		return 0, fromNativeError(err)
	}
	return len(data), nil
}
func (s *ExecutionStdin) Close() error {
	if s == nil {
		return nil
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	err := fromNativeError(s.native.CloseInput())
	s.native.Free()
	s.native = nil
	s.closed = true
	return err
}

type sshShellConfig struct {
	CWD          string            `json:"cwd,omitempty"`
	User         string            `json:"user,omitempty"`
	Env          map[string]string `json:"env"`
	Term         string            `json:"term,omitempty"`
	DetachKeys   string            `json:"detach_keys,omitempty"`
	ForwardAgent *bool             `json:"forward_agent,omitempty"`
}
type SSHShellOption func(*sshShellConfig)

func WithSSHWorkingDirectory(path string) SSHShellOption {
	return func(c *sshShellConfig) { c.CWD = path }
}
func WithSSHUser(user string) SSHShellOption { return func(c *sshShellConfig) { c.User = user } }
func WithSSHEnv(env map[string]string) SSHShellOption {
	return func(c *sshShellConfig) {
		c.Env = maps.Clone(env)
		if c.Env == nil {
			c.Env = make(map[string]string)
		}
	}
}
func WithSSHTerm(term string) SSHShellOption { return func(c *sshShellConfig) { c.Term = term } }
func WithSSHDetachKeys(keys string) SSHShellOption {
	return func(c *sshShellConfig) { c.DetachKeys = keys }
}
func WithSSHAgentForwarding(enabled bool) SSHShellOption {
	return func(c *sshShellConfig) { c.ForwardAgent = &enabled }
}
func (m *Machine) Attach(ctx context.Context, program string, args []string, opts ...ExecOption) (ExecutionResult, error) {
	request, err := executionRequest(program, args, opts)
	if err != nil {
		return ExecutionResult{}, err
	}
	if err = validateContext(ctx); err != nil {
		return ExecutionResult{}, err
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return ExecutionResult{}, newError(ErrorClosed, "", "machine is closed")
	}
	data, err := m.native.Attach(request)
	if err != nil {
		return ExecutionResult{}, fromNativeError(err)
	}
	var wire resultWire
	if err = json.Unmarshal(data, &wire); err != nil {
		return ExecutionResult{}, err
	}
	return decodeResult(wire), nil
}
func (m *Machine) AttachShell(ctx context.Context, opts ...SSHShellOption) (SSHExitStatus, error) {
	if err := validateContext(ctx); err != nil {
		return SSHExitStatus{}, err
	}
	config := sshShellConfig{Env: map[string]string{}}
	for _, option := range opts {
		if option == nil {
			return SSHExitStatus{}, newError(ErrorInvalidArgument, "", "SSH option must not be nil")
		}
		option(&config)
	}
	request, err := json.Marshal(config)
	if err != nil {
		return SSHExitStatus{}, err
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return SSHExitStatus{}, newError(ErrorClosed, "", "machine is closed")
	}
	data, err := m.native.AttachShell(request)
	if err != nil {
		return SSHExitStatus{}, fromNativeError(err)
	}
	var result SSHExitStatus
	err = json.Unmarshal(data, &result)
	return result, err
}
