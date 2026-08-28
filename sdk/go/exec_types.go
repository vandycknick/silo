package silo

// ExecutionEventKind identifies a structured guest execution event.
type ExecutionEventKind string

const (
	ExecutionEventAccepted       ExecutionEventKind = "accepted"
	ExecutionEventStarted        ExecutionEventKind = "started"
	ExecutionEventStdout         ExecutionEventKind = "stdout"
	ExecutionEventStderr         ExecutionEventKind = "stderr"
	ExecutionEventTerminalOutput ExecutionEventKind = "terminal_output"
	ExecutionEventTerminal       ExecutionEventKind = "terminal"
)

type ExecutionResultKind string

const (
	ExecutionResultExited       ExecutionResultKind = "exited"
	ExecutionResultSignaled     ExecutionResultKind = "signaled"
	ExecutionResultLaunchFailed ExecutionResultKind = "launch_failed"
	ExecutionResultLost         ExecutionResultKind = "lost"
)

type ExecutionLaunchFailureReason string
type ExecutionLostReason string

const (
	LaunchFailureUnspecified                  ExecutionLaunchFailureReason = "unspecified"
	LaunchFailureCommandNotFound              ExecutionLaunchFailureReason = "command_not_found"
	LaunchFailureInvalidProcessSpec           ExecutionLaunchFailureReason = "invalid_process_spec"
	LaunchFailureWorkingDirectoryNotFound     ExecutionLaunchFailureReason = "working_directory_not_found"
	LaunchFailureWorkingDirectoryNotDirectory ExecutionLaunchFailureReason = "working_directory_not_directory"
	LaunchFailureInvalidIdentity              ExecutionLaunchFailureReason = "invalid_identity"
	LaunchFailureIdentityNotFound             ExecutionLaunchFailureReason = "identity_not_found"
	LaunchFailurePermissionDenied             ExecutionLaunchFailureReason = "permission_denied"
	LaunchFailureSpawnFailed                  ExecutionLaunchFailureReason = "spawn_failed"
	LaunchFailureCancelledBeforeStart         ExecutionLaunchFailureReason = "cancelled_before_start"
	ExecutionLostUnspecified                  ExecutionLostReason          = "unspecified"
	ExecutionLostAgentInstanceReplaced        ExecutionLostReason          = "agent_instance_replaced"
	ExecutionLostAgentBootReplaced            ExecutionLostReason          = "agent_boot_replaced"
	ExecutionLostAgentUnavailable             ExecutionLostReason          = "agent_unavailable"
	ExecutionLostGuestStream                  ExecutionLostReason          = "guest_stream_lost"
	ExecutionLostVMStopped                    ExecutionLostReason          = "vm_stopped"
	ExecutionLostVMMonExited                  ExecutionLostReason          = "vmmon_exited"
)

type ExecutionLaunchFailure struct {
	Reason  ExecutionLaunchFailureReason
	Message string
}
type ExecutionLost struct {
	Reason  ExecutionLostReason
	Message string
}
type ExecutionResult struct {
	Kind          ExecutionResultKind
	Code          *uint32
	Signal        *uint32
	LaunchFailure *ExecutionLaunchFailure
	Lost          *ExecutionLost
}
type ExecutionEvent struct {
	Kind   ExecutionEventKind
	Data   []byte
	Result *ExecutionResult
}
type SSHExitStatus struct {
	Code    int32 `json:"code"`
	Success bool  `json:"success"`
}
