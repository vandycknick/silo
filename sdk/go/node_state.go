package silo

import (
	"context"
	"github.com/vandycknick/silo/sdk/go/internal/ffi"
	"sync"
)

// NodeStateLease excludes native Start, Remove and Update across processes.
// Inspect remains available. Close before Start. A lease does not stop a VM.
// Crash-left node transactions remain fenced after Close; a recovery owner must
// validate and finish them under a lease before lifecycle mutations resume.
type NodeStateLease struct {
	mu     sync.Mutex
	native *ffi.NodeStateLease
}

func (m *Machine) LeaseNodeState(ctx context.Context) (*NodeStateLease, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return nil, newError(ErrorClosed, "", "machine is closed")
	}
	lease, err := m.native.LeaseNodeState()
	if err != nil {
		return nil, fromNativeError(err)
	}
	return &NodeStateLease{native: lease}, nil
}
func (lease *NodeStateLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.native != nil {
		lease.native.Close()
		lease.native = nil
	}
	return nil
}
