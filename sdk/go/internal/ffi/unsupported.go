//go:build !cgo || (!linux && !darwin)

package ffi

// This intentionally produces a direct compile-time diagnostic on unsupported builds.
var _ = SILO_GO_SDK_REQUIRES_CGO_ENABLED_1_ON_LINUX_OR_DARWIN

type NativeError struct{ Variant, Message string }

func (e *NativeError) Error() string { return e.Message }

type ABIMismatchError struct{ Message string }

func (e *ABIMismatchError) Error() string { return e.Message }

type Runtime struct{}
type Machine struct{}
type Execution struct{}
type Stdin struct{}
type Log struct{}
type ExecutionOutput struct{ Result, Stdout, Stderr, TerminalOutput []byte }
type ExecutionEvent struct{ Metadata, Data []byte }
type LogChunk struct {
	Output uint32
	Data   []byte
}

func Load(string, uint32) error                         { return nil }
func OpenRuntime([]byte) (*Runtime, error)              { return nil, nil }
func BuildNetworkPolicy([]byte) ([]byte, error)         { return nil, nil }
func (*Runtime) Close()                                 {}
func (*Runtime) CreateMachine([]byte) (*Machine, error) { return nil, nil }
func (*Runtime) Machine(string) (*Machine, error)       { return nil, nil }
func (*Runtime) Machines() ([]*Machine, error)          { return nil, nil }
func (*Runtime) ImageCall([]byte) ([]byte, error)       { return nil, nil }
func (*Machine) ID() (string, error)                    { return "", nil }
func (*Machine) Inspect() ([]byte, error)               { return nil, nil }
func (*Machine) Start() ([]byte, error)                 { return nil, nil }
func (*Machine) Stop() ([]byte, error)                  { return nil, nil }
func (*Machine) Exec([]byte) (*ExecutionOutput, error)  { return nil, nil }
func (*Machine) Shell([]byte) (*ExecutionOutput, error) { return nil, nil }
func (*Machine) Spawn([]byte) (*Execution, error)       { return nil, nil }
func (*Machine) Attach([]byte) ([]byte, error)          { return nil, nil }
func (*Machine) AttachShell([]byte) ([]byte, error)     { return nil, nil }
func (*Machine) Logs([]byte) (*Log, error)              { return nil, nil }
func (*Machine) Remove() error                          { return nil }
func (*Machine) Close()                                 {}
func (*Execution) Recv() (*ExecutionEvent, bool, error) { return nil, false, nil }
func (*Execution) Wait() ([]byte, error)                { return nil, nil }
func (*Execution) Collect() (*ExecutionOutput, error)   { return nil, nil }
func (*Execution) Stdin() (*Stdin, error)               { return nil, nil }
func (*Execution) Signal(uint32) error                  { return nil }
func (*Execution) ResizePTY(uint16, uint16) error       { return nil }
func (*Execution) CloseRequests() error                 { return nil }
func (*Execution) Cancel() error                        { return nil }
func (*Execution) Close()                               {}
func (*Stdin) Write([]byte) error                       { return nil }
func (*Stdin) CloseInput() error                        { return nil }
func (*Stdin) Free()                                    {}
func (*Log) Recv() (*LogChunk, bool, error)             { return nil, false, nil }
func (*Log) CloseStream() error                         { return nil }
func (*Log) Free()                                      {}
