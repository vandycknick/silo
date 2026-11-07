mod builder;
mod config;
mod forward;
mod guest;
mod handle;
mod inspect;
mod lifecycle;
mod lifecycle_options;
pub(crate) mod live;
pub(crate) mod live_capture;
pub(crate) mod live_fork;
pub(crate) mod live_operations;
mod logs;
mod memory;
mod mounts;
mod name_generator;
mod node_status;
mod process;
mod reference;
pub(crate) mod restore;
pub(crate) mod root_disk;
pub(crate) mod root_storage;
mod secrets;
mod session;
mod start;
pub(crate) mod stopped;
#[cfg(all(test, target_os = "linux"))]
mod stopped_storage;
mod streams;
mod update;
mod vsock;

pub use builder::{MachineBuilder, RootProfile};
pub use forward::{
    MachineForwardErrorDetail, MachineForwardScope, MachineForwardSession, MachineForwardState,
    MachineForwardStatus,
};
pub use guest::{GuestBuilder, MachineAgent, MachineGuestConfig, MachineUserConfig};
pub use handle::Machine;
pub use inspect::{
    MachineBootMode, MachineBootReport, MachineData, MachineInventoryEntry, MachineIssue,
    MachineIssueComponent, MachineObservation, MachineProvisionFailurePolicy,
    MachineProvisionReport, MachineProvisionStatus, MachineProvisionStepReport,
    MachineProvisionStepStatus, MachineRootfs, MachineStatus, MachineTailscale,
};
pub use lifecycle_options::{
    MachineExit, MachineExitOutcome, MachineKillOptions, MachineRunId, MachineStart,
    MachineStopOptions, MachineWaitOptions, DEFAULT_MACHINE_WAIT_TIMEOUT,
};
pub use live::{require_live_operation, LiveObservationReader, MachineLiveObservation};
pub use live_capture::{
    LiveCaptureSource, LiveCaptureSummary, LiveSnapshot, LiveSnapshotOptions, MachineCapture,
    MachineCaptureStage,
};
pub use logs::{
    MachineLogChunk, MachineLogOptions, MachineLogOutput, MachineLogSource, MachineLogStream,
};
pub use memory::Memory;
pub use mounts::resolve_mount_location;
pub use node_status::{
    MachineNetworkObservation, MachineNetworkObservationIssue, MachineNodeObservation,
    MachineNodeState, MachineNodeStatus,
};
pub use process::{MachineRetention, ProcessConfig};
pub use reference::validate_new_machine_name;
pub use reference::MachineRef;
pub use session::host::AttachmentSignal;
pub(crate) use session::launch_failure_reason;
pub use session::ssh::{
    SshExitStatus, SshShellAttachment, SshShellControl, SshShellOptions, SshShellOptionsBuilder,
    SshShellSignal,
};
pub use session::{
    ExecutionControl, ExecutionEvent, ExecutionLaunchFailure, ExecutionLaunchFailureReason,
    ExecutionLost, ExecutionLostReason, ExecutionOptions, ExecutionOptionsBuilder, ExecutionOutput,
    ExecutionResult, ExecutionSession, ExecutionStdin, StdinMode,
};
pub(crate) use start::SecretProvider;
pub use start::{
    EgressCredentials, EgressSecret, Entrypoint, HostCommand, LaunchCredentials,
    MachineStartOptions,
};
pub use stopped::{
    preflight_recover_checkpoint_disks, preflight_restore_snapshot, preflight_stopped,
    ExternalResourceKey, ExternalResourceMapping, ExternalResourcePolicy,
    ExternalResourceRequirement, ForkOptions, PrivateWriteAllowance, RecoverDisksOptions,
    RestoreMemoryPolicy, RestoreOptions, RestoreResourcePolicy, SnapshotConfiguration,
    SnapshotOptions,
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
    MachineGuestBootReport, MachineHostMemoryReclaim, MachineHostMemoryReclaimBacking,
    MachineHostMemoryReclaimQualification, MachineHostMemoryReclaimReason,
    MachineLoadAverageMetrics, MachineMemoryMetrics, MachineMemoryReclaimReport,
    MachineMetricSnapshot, MachineMetrics, MachineMonitorSnapshot, MachineMonitorStatus,
    MachineNetworkInterfaceMetrics, MachineProvisionOverallStatus, MachineProvisioningReport,
    MachineReadiness, MachineReadinessOutcome, MachineReadinessReason, MachineReadinessState,
    MachineRootStorageKind, MachineRootStorageMetrics, MachineSshBackend, MachineSshListenerReport,
    MachineStaleReason, MachineSystemInfo, MachineTemporaryDirectoryKind,
    MachineTemporaryDirectoryMetrics, MachineVmSnapshot, MachineVmState,
};
pub use update::{GuestPublishUpdate, MachineUpdate, MachineUserUpdate, NetworkPolicyUpdate};

pub(crate) use name_generator::generate_machine_name;
pub(crate) use reference::{validate_machine_name, MachineRefKind};
