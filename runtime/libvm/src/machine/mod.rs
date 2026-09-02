mod builder;
mod config;
mod forward;
mod guest;
mod handle;
mod inspect;
mod lifecycle;
mod lifecycle_options;
mod logs;
mod memory;
mod mounts;
mod name_generator;
mod process;
mod reference;
pub(crate) mod root_disk;
mod session;
mod start;
mod streams;
mod update;
mod vsock;

pub use builder::MachineBuilder;
pub use forward::{
    MachineForwardErrorDetail, MachineForwardHold, MachineForwardOwner, MachineForwardState,
    MachineForwardStatus,
};
pub use guest::{GuestBuilder, MachineAgent, MachineGuestConfig, MachineUserConfig};
pub use handle::Machine;
pub use inspect::{
    MachineBootMode, MachineBootReport, MachineData, MachineProvisionFailurePolicy,
    MachineProvisionReport, MachineProvisionStatus, MachineProvisionStepReport,
    MachineProvisionStepStatus, MachineRootfs, MachineStatus,
};
pub use lifecycle_options::{
    MachineExit, MachineExitOutcome, MachineKillOptions, MachineRunId, MachineStart,
    MachineStopOptions, MachineWaitOptions, DEFAULT_MACHINE_WAIT_TIMEOUT,
};
pub use logs::{
    MachineLogChunk, MachineLogOptions, MachineLogOutput, MachineLogSource, MachineLogStream,
};
pub use memory::Memory;
pub use mounts::resolve_mount_location;
pub use process::{MachineRetention, ProcessConfig};
pub use reference::MachineRef;
pub(crate) use session::launch_failure_reason;
pub use session::{
    ExecutionControl, ExecutionEvent, ExecutionLaunchFailure, ExecutionLaunchFailureReason,
    ExecutionLost, ExecutionLostReason, ExecutionOptions, ExecutionOptionsBuilder, ExecutionOutput,
    ExecutionResult, ExecutionSession, ExecutionStdin, SshExitStatus, SshShellOptions,
    SshShellOptionsBuilder, StdinMode,
};
pub use start::{
    EgressCredentials, EgressSecret, Entrypoint, HostCommand, LaunchCredentials,
    MachineStartOptions, OAuthRefreshHook,
};
pub use streams::{
    FileWriteDisposition, MachineAgentConnection, MachineAgentConnectionState,
    MachineAgentIdentity, MachineAgentMetricReport, MachineAgentMetricsObservation,
    MachineAgentProvisionFailurePolicy, MachineAgentProvisionStepStatus,
    MachineAgentProvisioningStepReport, MachineAgentStatus, MachineAgentStatusObservation,
    MachineAgentStatusReport, MachineAgentStatusState, MachineBlockDeviceMetrics,
    MachineByteStream, MachineCpuMetrics, MachineDirectoryCreateDisposition, MachineDirectoryPage,
    MachineEnabledAgent, MachineEntryKind, MachineFileDownload, MachineFileEntry,
    MachineFileUploadOptions, MachineFilesystemMetrics, MachineFreshness, MachineGuestBootMode,
    MachineGuestBootReport, MachineLoadAverageMetrics, MachineMemoryMetrics, MachineMetricSnapshot,
    MachineMetrics, MachineMonitorSnapshot, MachineMonitorStatus, MachineNetworkInterfaceMetrics,
    MachineProvisionOverallStatus, MachineProvisioningReport, MachineReadiness,
    MachineReadinessOutcome, MachineReadinessReason, MachineReadinessState, MachineStaleReason,
    MachineSystemInfo, MachineVmSnapshot, MachineVmState,
};
pub use update::{MachineUpdate, MachineUserUpdate, NetworkPolicyUpdate};

pub(crate) use name_generator::generate_machine_name;
pub(crate) use reference::{validate_machine_name, MachineRefKind};
