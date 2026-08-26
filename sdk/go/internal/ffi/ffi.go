//go:build cgo && (linux || darwin)

package ffi

/*
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// NativeError is a structured failure returned by the Rust bridge.
// ABIMismatchError reports an incompatible bridge ABI or SDK version.
type ABIMismatchError struct{ Message string }

func (e *ABIMismatchError) Error() string { return e.Message }

// NativeError is a structured failure returned by the Rust bridge.
type NativeError struct {
	Variant string
	Message string
}

func (e *NativeError) Error() string { return e.Message }

// Runtime owns one native libvm runtime handle.
type Runtime struct{ pointer *C.silo_runtime }

// Machine owns one native libvm machine handle.
type Machine struct{ pointer *C.silo_machine }

// Execution owns one native structured execution session.
type Execution struct{ pointer *C.silo_execution }

// Stdin owns one native execution input handle.
type Stdin struct{ pointer *C.silo_stdin }

// Log owns one native persisted log stream.
type Log struct{ pointer *C.silo_log }

// ExecutionOutput contains copied native output buffers.
type ExecutionOutput struct {
	Result         []byte
	Stdout         []byte
	Stderr         []byte
	TerminalOutput []byte
}

// ExecutionEvent contains copied event metadata and raw data.
type ExecutionEvent struct {
	Metadata []byte
	Data     []byte
}

// LogChunk contains one copied raw persisted-log chunk.
type LogChunk struct {
	Output uint32
	Data   []byte
}

func load(path, expectedVersion string, expectedABI uint32) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	if message := C.bridge_load(cPath); message != nil {
		value := C.GoString(message)
		C.bridge_string_free(message)
		return fmt.Errorf("load native Silo bridge: %s", value)
	}
	if actual := uint32(C.bridge_abi_version()); actual != expectedABI {
		return &ABIMismatchError{Message: fmt.Sprintf("native Silo bridge ABI is %d, SDK requires %d", actual, expectedABI)}
	}
	if actual := C.GoString(C.bridge_sdk_version()); actual != expectedVersion {
		return &ABIMismatchError{Message: fmt.Sprintf("native Silo bridge version is %q, SDK requires %q", actual, expectedVersion)}
	}
	return nil
}

func openRuntime(request []byte) (*Runtime, error) {
	var output *C.silo_runtime
	errorValue := C.bridge_runtime_open(bytePointer(request), C.size_t(len(request)), &output)
	if err := takeError(errorValue); err != nil {
		return nil, err
	}
	if output == nil {
		return nil, fmt.Errorf("native Silo bridge returned a nil runtime")
	}
	return &Runtime{pointer: output}, nil
}

func (runtime *Runtime) Close() {
	if runtime == nil || runtime.pointer == nil {
		return
	}
	C.bridge_runtime_free(runtime.pointer)
	runtime.pointer = nil
}

func (runtime *Runtime) CreateMachine(request []byte) (*Machine, error) {
	var output *C.silo_machine
	errorValue := C.bridge_runtime_machine_create(runtime.pointer, bytePointer(request), C.size_t(len(request)), &output)
	if err := takeError(errorValue); err != nil {
		return nil, err
	}
	if output == nil {
		return nil, fmt.Errorf("native Silo bridge returned a nil machine")
	}
	return &Machine{pointer: output}, nil
}

func (runtime *Runtime) Machine(reference string) (*Machine, error) {
	bytes := []byte(reference)
	var output *C.silo_machine
	errorValue := C.bridge_runtime_machine_get(runtime.pointer, bytePointer(bytes), C.size_t(len(bytes)), &output)
	if err := takeError(errorValue); err != nil {
		return nil, err
	}
	if output == nil {
		return nil, fmt.Errorf("native Silo bridge returned a nil machine")
	}
	return &Machine{pointer: output}, nil
}

func (runtime *Runtime) ImageCall(request []byte) ([]byte, error) {
	var output C.silo_buffer
	if err := takeError(C.bridge_images_call(runtime.pointer, bytePointer(request), C.size_t(len(request)), &output)); err != nil {
		return nil, err
	}
	return copyBuffer(output), nil
}

func (runtime *Runtime) Machines() ([]*Machine, error) {
	var output C.silo_machine_handle_list
	errorValue := C.bridge_runtime_machines(runtime.pointer, &output)
	if err := takeError(errorValue); err != nil {
		return nil, err
	}
	defer C.bridge_machine_handle_list_free(output)
	machines := make([]*Machine, 0, int(output.len))
	for index := C.size_t(0); index < output.len; index++ {
		pointer := C.bridge_machine_handle_list_at(&output, index)
		if pointer == nil {
			for _, machine := range machines {
				machine.Close()
			}
			return nil, fmt.Errorf("native Silo bridge returned a nil machine at index %d", index)
		}
		machines = append(machines, &Machine{pointer: pointer})
	}
	return machines, nil
}

func (machine *Machine) ID() (string, error) {
	var output C.silo_buffer
	errorValue := C.bridge_machine_id(machine.pointer, &output)
	if err := takeError(errorValue); err != nil {
		return "", err
	}
	bytes := copyBuffer(output)
	return string(bytes), nil
}

func (machine *Machine) Inspect() ([]byte, error) {
	var output C.silo_buffer
	if err := takeError(C.bridge_machine_inspect(machine.pointer, &output)); err != nil {
		return nil, err
	}
	return copyBuffer(output), nil
}

func (machine *Machine) Start() ([]byte, error) {
	var output C.silo_buffer
	if err := takeError(C.bridge_machine_start(machine.pointer, &output)); err != nil {
		return nil, err
	}
	return copyBuffer(output), nil
}

func (machine *Machine) Stop() ([]byte, error) {
	var output C.silo_buffer
	if err := takeError(C.bridge_machine_stop(machine.pointer, &output)); err != nil {
		return nil, err
	}
	return copyBuffer(output), nil
}

func (machine *Machine) Exec(request []byte) (*ExecutionOutput, error) {
	var output C.silo_execution_output
	if err := takeError(C.bridge_machine_exec(machine.pointer, bytePointer(request), C.size_t(len(request)), &output)); err != nil {
		return nil, err
	}
	return copyExecutionOutput(output), nil
}
func (machine *Machine) Shell(request []byte) (*ExecutionOutput, error) {
	var output C.silo_execution_output
	if err := takeError(C.bridge_machine_shell(machine.pointer, bytePointer(request), C.size_t(len(request)), &output)); err != nil {
		return nil, err
	}
	return copyExecutionOutput(output), nil
}
func (machine *Machine) Spawn(request []byte) (*Execution, error) {
	var output *C.silo_execution
	if err := takeError(C.bridge_machine_spawn(machine.pointer, bytePointer(request), C.size_t(len(request)), &output)); err != nil {
		return nil, err
	}
	if output == nil {
		return nil, fmt.Errorf("native Silo bridge returned a nil execution session")
	}
	return &Execution{pointer: output}, nil
}
func (machine *Machine) Attach(request []byte) ([]byte, error) {
	var output C.silo_buffer
	if err := takeError(C.bridge_machine_attach(machine.pointer, bytePointer(request), C.size_t(len(request)), &output)); err != nil {
		return nil, err
	}
	return copyBuffer(output), nil
}
func (machine *Machine) AttachShell(request []byte) ([]byte, error) {
	var output C.silo_buffer
	if err := takeError(C.bridge_machine_attach_shell(machine.pointer, bytePointer(request), C.size_t(len(request)), &output)); err != nil {
		return nil, err
	}
	return copyBuffer(output), nil
}

func (machine *Machine) Logs(request []byte) (*Log, error) {
	var output *C.silo_log
	if err := takeError(C.bridge_machine_logs(machine.pointer, bytePointer(request), C.size_t(len(request)), &output)); err != nil {
		return nil, err
	}
	if output == nil {
		return nil, fmt.Errorf("native Silo bridge returned a nil log stream")
	}
	return &Log{pointer: output}, nil
}

func (machine *Machine) Remove() error {
	return takeError(C.bridge_machine_remove(machine.pointer))
}

func (machine *Machine) Close() {
	if machine == nil || machine.pointer == nil {
		return
	}
	C.bridge_machine_free(machine.pointer)
	machine.pointer = nil
}

func (execution *Execution) Recv() (*ExecutionEvent, bool, error) {
	var output C.silo_execution_event
	var eof C._Bool
	if err := takeError(C.bridge_execution_recv(execution.pointer, &output, &eof)); err != nil {
		return nil, false, err
	}
	return &ExecutionEvent{Metadata: copyBuffer(output.metadata), Data: copyBuffer(output.data)}, bool(eof), nil
}
func (execution *Execution) Wait() ([]byte, error) {
	var output C.silo_buffer
	if err := takeError(C.bridge_execution_wait(execution.pointer, &output)); err != nil {
		return nil, err
	}
	return copyBuffer(output), nil
}
func (execution *Execution) Collect() (*ExecutionOutput, error) {
	var output C.silo_execution_output
	if err := takeError(C.bridge_execution_collect(execution.pointer, &output)); err != nil {
		return nil, err
	}
	return copyExecutionOutput(output), nil
}
func (execution *Execution) Stdin() (*Stdin, error) {
	var output *C.silo_stdin
	if err := takeError(C.bridge_execution_stdin(execution.pointer, &output)); err != nil {
		return nil, err
	}
	if output == nil {
		return nil, nil
	}
	return &Stdin{pointer: output}, nil
}
func (execution *Execution) Signal(signal uint32) error {
	return takeError(C.bridge_execution_signal(execution.pointer, C.uint32_t(signal)))
}
func (execution *Execution) ResizePTY(rows, columns uint16) error {
	return takeError(C.bridge_execution_resize_pty(execution.pointer, C.uint16_t(rows), C.uint16_t(columns)))
}
func (execution *Execution) CloseRequests() error {
	return takeError(C.bridge_execution_close_requests(execution.pointer))
}
func (execution *Execution) Cancel() error {
	return takeError(C.bridge_execution_cancel(execution.pointer))
}
func (execution *Execution) Close() {
	if execution != nil && execution.pointer != nil {
		C.bridge_execution_free(execution.pointer)
		execution.pointer = nil
	}
}
func (stdin *Stdin) Write(data []byte) error {
	return takeError(C.bridge_stdin_write(stdin.pointer, bytePointer(data), C.size_t(len(data))))
}
func (stdin *Stdin) CloseInput() error { return takeError(C.bridge_stdin_close(stdin.pointer)) }
func (log *Log) Recv() (*LogChunk, bool, error) {
	var output C.silo_log_chunk
	var eof C._Bool
	if err := takeError(C.bridge_log_recv(log.pointer, &output, &eof)); err != nil {
		return nil, false, err
	}
	return &LogChunk{Output: uint32(output.output), Data: copyBuffer(output.data)}, bool(eof), nil
}
func (log *Log) CloseStream() error { return takeError(C.bridge_log_close(log.pointer)) }
func (log *Log) Free() {
	if log != nil && log.pointer != nil {
		C.bridge_log_free(log.pointer)
		log.pointer = nil
	}
}

func (stdin *Stdin) Free() {
	if stdin != nil && stdin.pointer != nil {
		C.bridge_stdin_free(stdin.pointer)
		stdin.pointer = nil
	}
}

// BuildNetworkPolicy validates and canonicalizes one policy request.
func BuildNetworkPolicy(request []byte) ([]byte, error) {
	var output C.silo_buffer
	if err := takeError(C.bridge_network_policy_build(bytePointer(request), C.size_t(len(request)), &output)); err != nil {
		return nil, err
	}
	return copyBuffer(output), nil
}

func takeError(value *C.silo_error) error {
	if value == nil {
		return nil
	}
	defer C.bridge_error_free(value)
	return &NativeError{Variant: C.GoString(value.variant), Message: C.GoString(value.message)}
}

func copyExecutionOutput(value C.silo_execution_output) *ExecutionOutput {
	return &ExecutionOutput{
		Result:         copyBuffer(value.result),
		Stdout:         copyBuffer(value.stdout_data),
		Stderr:         copyBuffer(value.stderr_data),
		TerminalOutput: copyBuffer(value.terminal_output),
	}
}

func copyBuffer(value C.silo_buffer) []byte {
	defer C.bridge_buffer_free(value)
	if value.ptr == nil || value.len == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(value.ptr)), int(value.len))...)
}

func bytePointer(value []byte) *C.uint8_t {
	if len(value) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&value[0]))
}
