package silo

import (
	"context"
	"encoding/json"
	"github.com/vandycknick/silo/sdk/go/internal/ffi"
	"io"
	"sync"
)

type MachineLogSource string

const (
	MachineLogMonitor      MachineLogSource = "monitor"
	MachineLogSerial       MachineLogSource = "serial"
	MachineLogExec         MachineLogSource = "exec"
	MachineLogNetwork      MachineLogSource = "network"
	MachineLogNetworkAudit MachineLogSource = "network_audit"
)

type MachineLogOptions struct{ Follow bool }
type MachineLogOutput string

const (
	MachineLogStdout MachineLogOutput = "stdout"
	MachineLogStderr MachineLogOutput = "stderr"
)

type MachineLogChunk struct {
	Output MachineLogOutput `json:"output"`
	Data   []byte           `json:"data"`
}

func (m *Machine) Logs(ctx context.Context, source MachineLogSource, options MachineLogOptions) (*MachineLogStream, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	switch source {
	case MachineLogMonitor, MachineLogSerial, MachineLogExec, MachineLogNetwork, MachineLogNetworkAudit:
	default:
		return nil, newError(ErrorInvalidArgument, "", "unsupported machine log source")
	}
	request, _ := json.Marshal(struct {
		Source MachineLogSource `json:"source"`
		Follow bool             `json:"follow"`
	}{source, options.Follow})
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return nil, newError(ErrorClosed, "", "machine is closed")
	}
	native, err := m.native.Logs(request)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return &MachineLogStream{native: native}, nil
}

// MachineLogStream reads one persisted semantic log source. Only one Recv may run at a time.
type MachineLogStream struct {
	mutex    sync.RWMutex
	receiver sync.Mutex
	native   *ffi.Log
	closed   bool
}

func (s *MachineLogStream) Recv(ctx context.Context) (*MachineLogChunk, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if !s.receiver.TryLock() {
		return nil, newError(ErrorInvalidArgument, "", "machine log stream already has an active receiver")
	}
	defer s.receiver.Unlock()
	s.mutex.RLock()
	if s.closed {
		s.mutex.RUnlock()
		return nil, newError(ErrorClosed, "", "machine log stream is closed")
	}
	native := s.native
	s.mutex.RUnlock()
	done := make(chan struct {
		data *ffi.LogChunk
		eof  bool
		err  error
	}, 1)
	go func() {
		data, eof, err := native.Recv()
		done <- struct {
			data *ffi.LogChunk
			eof  bool
			err  error
		}{data, eof, err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			return nil, fromNativeError(result.err)
		}
		if result.eof {
			return nil, io.EOF
		}
		var output MachineLogOutput
		switch result.data.Output {
		case 1:
			output = MachineLogStdout
		case 2:
			output = MachineLogStderr
		default:
			return nil, newError(ErrorUnknown, "", "native log stream returned an unknown output channel")
		}
		return &MachineLogChunk{Output: output, Data: append([]byte(nil), result.data.Data...)}, nil
	case <-ctx.Done():
		_ = native.CloseStream()
		<-done
		return nil, contextError(ctx.Err())
	}
}
func (s *MachineLogStream) Close() error {
	if s == nil {
		return nil
	}
	s.mutex.RLock()
	if s.closed {
		s.mutex.RUnlock()
		return nil
	}
	native := s.native
	err := fromNativeError(native.CloseStream())
	s.mutex.RUnlock()

	s.receiver.Lock()
	defer s.receiver.Unlock()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	native.Free()
	s.native = nil
	s.closed = true
	return err
}
