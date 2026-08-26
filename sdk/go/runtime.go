package silo

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

// Runtime is the entry point for daemonless local machine management.
// It is safe for concurrent use. Close waits for active calls and is idempotent.
type Runtime struct {
	mutex  sync.RWMutex
	native *ffi.Runtime
	closed bool
}

// Open opens a local libvm runtime. It never downloads or installs runtime components.
func Open(ctx context.Context, opts ...RuntimeOption) (*Runtime, error) {
	if ctx == nil {
		return nil, newError(ErrorInvalidArgument, "", "context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	config := runtimeConfig{}
	for _, option := range opts {
		if option == nil {
			return nil, newError(ErrorInvalidArgument, "", "runtime option must not be nil")
		}
		option(&config)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	request, err := json.Marshal(config)
	if err != nil {
		return nil, newError(ErrorInvalidArgument, "", "encode runtime options: "+err.Error())
	}
	if err := ffi.Load(Version, ffiABIVersion); err != nil {
		return nil, fromNativeError(err)
	}
	native, err := ffi.OpenRuntime(request)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return &Runtime{native: native}, nil
}

// Close releases this runtime handle. Existing machine handles retain their native runtime context.
func (runtime *Runtime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	if runtime.closed {
		return nil
	}
	runtime.closed = true
	runtime.native.Close()
	runtime.native = nil
	return nil
}

// CreateMachine materializes an OCI or local disk image and persists a stopped machine.
func (runtime *Runtime) CreateMachine(ctx context.Context, source ImageSource, opts ...MachineOption) (*Machine, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if source.config.Kind == "oci" && source.config.Reference == "" {
		return nil, newError(ErrorInvalidArgument, "", "OCI image reference must not be empty")
	}
	if source.config.Kind == "disk" && source.config.Path == "" {
		return nil, newError(ErrorInvalidArgument, "", "disk image path must not be empty")
	}
	if source.config.Kind != "oci" && source.config.Kind != "disk" {
		return nil, newError(ErrorInvalidArgument, "", "invalid image source")
	}
	config := machineConfig{Source: source.config, Labels: make(map[string]string), Metadata: make(map[string]string)}
	for _, option := range opts {
		if option == nil {
			return nil, newError(ErrorInvalidArgument, "", "machine option must not be nil")
		}
		option(&config)
	}
	if config.error != nil {
		return nil, config.error
	}
	request, err := json.Marshal(config)
	if err != nil {
		return nil, newError(ErrorInvalidArgument, "", "encode machine options: "+err.Error())
	}
	runtime.mutex.RLock()
	defer runtime.mutex.RUnlock()
	if runtime.closed {
		return nil, newError(ErrorClosed, "", "runtime is closed")
	}
	native, err := runtime.native.CreateMachine(request)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return newMachine(native)
}

// Machine looks up a machine by name, full ID, or unambiguous ID prefix.
func (runtime *Runtime) Machine(ctx context.Context, reference string) (*Machine, error) {
	if err := validateContextAndString(ctx, "reference", reference); err != nil {
		return nil, err
	}
	runtime.mutex.RLock()
	defer runtime.mutex.RUnlock()
	if runtime.closed {
		return nil, newError(ErrorClosed, "", "runtime is closed")
	}
	native, err := runtime.native.Machine(reference)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return newMachine(native)
}

// Machines lists handles for every machine known to this runtime.
func (runtime *Runtime) Machines(ctx context.Context) ([]*Machine, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	runtime.mutex.RLock()
	defer runtime.mutex.RUnlock()
	if runtime.closed {
		return nil, newError(ErrorClosed, "", "runtime is closed")
	}
	nativeMachines, err := runtime.native.Machines()
	if err != nil {
		return nil, fromNativeError(err)
	}
	machines := make([]*Machine, 0, len(nativeMachines))
	for index, native := range nativeMachines {
		machine, machineErr := newMachine(native)
		if machineErr != nil {
			for _, opened := range machines {
				_ = opened.Close()
			}
			for _, unopened := range nativeMachines[index+1:] {
				unopened.Close()
			}
			return nil, machineErr
		}
		machines = append(machines, machine)
	}
	return machines, nil
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return newError(ErrorInvalidArgument, "", "context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return contextError(err)
	}
	return nil
}

func validateContextAndString(ctx context.Context, name, value string) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if value == "" {
		return newError(ErrorInvalidArgument, "", name+" must not be empty")
	}
	return nil
}
