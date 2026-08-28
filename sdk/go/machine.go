package silo

import (
	"context"
	"sync"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

// Machine is a handle to persisted machine state. It is safe for concurrent control calls except
// where a stream or execution method documents a narrower contract.
type Machine struct {
	mutex  sync.RWMutex
	native *ffi.Machine
	id     string
	closed bool
}

func newMachine(native *ffi.Machine) (*Machine, error) {
	id, err := native.ID()
	if err != nil {
		native.Close()
		return nil, fromNativeError(err)
	}
	return &Machine{native: native, id: id}, nil
}

// ID returns the stable machine ID. It remains available after Close.
func (machine *Machine) ID() string {
	if machine == nil {
		return ""
	}
	return machine.id
}

// Inspect returns a point-in-time snapshot of persisted configuration and runtime state.
func (machine *Machine) Inspect(ctx context.Context) (*MachineData, error) {
	return machine.dataOperation(ctx, "inspect")
}

// Start boots the machine without pulling or rematerializing its image.
func (machine *Machine) Start(ctx context.Context) (*MachineData, error) {
	return machine.dataOperation(ctx, "start")
}

// Stop gracefully stops the machine.
func (machine *Machine) Stop(ctx context.Context) (*MachineData, error) {
	return machine.dataOperation(ctx, "stop")
}

func (machine *Machine) dataOperation(ctx context.Context, operation string) (*MachineData, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	machine.mutex.RLock()
	defer machine.mutex.RUnlock()
	if machine.closed {
		return nil, newError(ErrorClosed, "", "machine is closed")
	}
	var data []byte
	var err error
	switch operation {
	case "inspect":
		data, err = machine.native.Inspect()
	case "start":
		data, err = machine.native.Start()
	case "stop":
		data, err = machine.native.Stop()
	default:
		return nil, newError(ErrorInvalidArgument, "", "unknown machine operation")
	}
	if err != nil {
		return nil, fromNativeError(err)
	}
	return decodeMachineData(data)
}

// Remove removes persisted machine state and closes this handle after success.
func (machine *Machine) Remove(ctx context.Context) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	machine.mutex.Lock()
	defer machine.mutex.Unlock()
	if machine.closed {
		return newError(ErrorClosed, "", "machine is closed")
	}
	if err := machine.native.Remove(); err != nil {
		return fromNativeError(err)
	}
	machine.native.Close()
	machine.native = nil
	machine.closed = true
	return nil
}

// Close releases this binding handle. It does not stop or remove the machine.
func (machine *Machine) Close() error {
	if machine == nil {
		return nil
	}
	machine.mutex.Lock()
	defer machine.mutex.Unlock()
	if machine.closed {
		return nil
	}
	machine.closed = true
	machine.native.Close()
	machine.native = nil
	return nil
}
