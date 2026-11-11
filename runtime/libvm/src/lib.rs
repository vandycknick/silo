#![doc = include_str!("../README.md")]

mod constants;
mod error;
mod guest_agent;
pub mod handoff;
pub mod host;
pub mod host_input;
mod image;
mod initramfs_overlay;
mod lock_manager;
mod machine;
mod network;
pub mod node_state;
mod owned_boot_assets;
mod paths;
pub mod planning;
mod runtime;
mod secrets;
pub use crate::secrets::SecretScopePolicy;
mod ssh_ca;
pub mod storage;
mod store;
mod supervisor;
mod utils;

pub use crate::error::LibVmError;
pub use crate::image::ext4_admission::Ext4Rejection;
pub use crate::image::import::{AdmittedDiskImport, DiskImportError, ForeignContainer};
pub use crate::image::import_types::{
    BootAssetSelection, BootAssetsUpdate, DiskImportBoot, DiskImportFacts, DiskImportRequest,
    ImageContainerKind, ImageProvenance, ImportRootSelection, ManagedImageInfo, ManagedSourceId,
    ManagedSourceInfo, ManagedSourceRef, RawConversionKey, RawConversionOptions, RootCandidate,
    RootSelectionFailed,
};
pub use crate::machine::live_fork::{
    ForkCaptureOutcome, ForkChildOutcome, ForkChildResult, ForkDestination, ForkFailurePhase,
    ForkSourceOutcome, ForkStage, LiveForkChild, LiveForkOptions, LiveForkResult,
    DEFAULT_LIVE_FORK_MAX_CHILDREN,
};
pub use crate::machine::{
    preflight_recover_checkpoint_disks, preflight_restore_snapshot, preflight_stopped,
    validate_new_machine_name, ExternalResourceKey, ExternalResourceMapping,
    ExternalResourcePolicy, ExternalResourceRequirement, ForkOptions, RecoverDisksOptions,
    RestoreOptions, SnapshotConfiguration, SnapshotOptions,
};
pub use crate::machine::{
    require_live_operation, LiveCaptureSource, LiveCaptureSummary, LiveObservationReader,
    LiveSnapshot, LiveSnapshotOptions, MachineCapture, MachineCaptureStage, MachineLiveObservation,
};
pub use crate::owned_boot_assets::{
    BootAssetError, DirectKernelRejected, DirectKernelRejection, OwnedOverlayBoot,
};
pub use crate::runtime::boot_assets::{AdmissionRemedy, SourceFamily};
pub use crate::runtime::{
    require_host_live_operation, LiveCapabilityQuery, ResolvedBackendSelection,
};
pub use crate::storage::identity::{ImageId, ObjectDigest, SnapshotId};
pub use crate::store::live_store::MachineLifecycle;
pub use crate::store::models::image::{ImageRecord, ImageRecordKind};
pub use crate::store::models::storage::{
    BackendRequirement, BootBinding, BootFileRole, BootProfile, DirectCommandLinePolicy,
    DiskOwnership, DiskStorage, EfiFirmware, Ext4Profile, ExternalResource, GuestArchitecture,
    IncludedDisk, LinuxPlatform, MachineOwnership, MachineRoot, MachineStorageRecord, OverlayLower,
    OverlayProfile, PartitionTable, PrivatePath, RawLayout, RootFilesystem, RootSelector,
    StorageOperationKind, StorageOperationRecord, StorageOperationState, StorageProfile,
    StorageStopOutcome, TemporaryDirectoryPolicy, Translation,
};
pub use crate::store::models::{MachineId, MachineIdParseError};
pub use crate::store::snapshot_store::{
    CaptureNamingOutcome, SnapshotCaptureKindName, SnapshotCaptureProvenance, SnapshotInfo,
    SnapshotRef, SnapshotStore,
};
pub use vm_spec::restore::{RestoreEnvironmentVariable, RestoreHook};
pub use vm_spec::{live, BlockId, DiskFormat};
pub mod policy_secrets;
pub use crate::image::transport::{
    ArtifactAcquireReport, ArtifactAcquireRequest, ArtifactEncoding, ArtifactInspection,
    ArtifactPublishReport, ArtifactPublishRequest, ArtifactPurpose, ArtifactRootFamily,
    ArtifactTrust, CheckpointPublication, PublisherAuthentication,
};
pub use crate::image::{
    ImageBuilder, ImageCacheState, ImageDetail, ImageHandle, ImageLayerDetail, ImageProgress,
    ImageProgressReceiver, ImageProgressSender, ImagePruneReport, ImagePullOptions,
    ImagePullPolicy, ImageRemoveOptions, ImageResolveOptions, ImageSource, ImageSourceKind, Images,
    OciImageConfigMetadata, Platform, RegistryAction, RegistryPolicy, RegistryRule,
    ResolvedOciImage,
};
pub use crate::machine::{
    resolve_mount_location, AttachmentSignal, EgressCredentials, EgressSecret, Entrypoint,
    ExecutionControl, ExecutionEvent, ExecutionLaunchFailure, ExecutionLaunchFailureReason,
    ExecutionLost, ExecutionLostReason, ExecutionOptions, ExecutionOptionsBuilder, ExecutionOutput,
    ExecutionResult, ExecutionSession, ExecutionStdin, FileWriteDisposition, GuestBuilder,
    GuestPublishUpdate, HostCommand, LaunchCredentials, Machine, MachineAgent,
    MachineAgentConnection, MachineAgentConnectionState, MachineAgentIdentity,
    MachineAgentMetricReport, MachineAgentMetricsObservation, MachineAgentProvisionFailurePolicy,
    MachineAgentProvisionStepStatus, MachineAgentProvisioningStepReport, MachineAgentStatus,
    MachineAgentStatusObservation, MachineAgentStatusReport, MachineAgentStatusState,
    MachineBlockDeviceMetrics, MachineBootMode, MachineBootReport, MachineBuilder,
    MachineByteStream, MachineCpuMetrics, MachineData, MachineDirectoryCreateDisposition,
    MachineDirectoryPage, MachineDurability, MachineEnabledAgent, MachineEntryKind, MachineExit,
    MachineExitOutcome, MachineFileDownload, MachineFileEntry, MachineFileUploadOptions,
    MachineFilesystemMetrics, MachineForwardErrorDetail, MachineForwardScope,
    MachineForwardSession, MachineForwardState, MachineForwardStatus, MachineFreshness,
    MachineGuestBootMode, MachineGuestBootReport, MachineGuestConfig, MachineHostMemoryReclaim,
    MachineHostMemoryReclaimBacking, MachineHostMemoryReclaimQualification,
    MachineHostMemoryReclaimReason, MachineInventoryEntry, MachineIssue, MachineIssueComponent,
    MachineKillOptions, MachineLoadAverageMetrics, MachineLogChunk, MachineLogOptions,
    MachineLogOutput, MachineLogSource, MachineLogStream, MachineMemoryMetrics,
    MachineMemoryReclaimReport, MachineMetricSnapshot, MachineMetrics, MachineMonitorSnapshot,
    MachineMonitorStatus, MachineNetworkInterfaceMetrics, MachineNetworkObservation,
    MachineNetworkObservationIssue, MachineNodeObservation, MachineNodeState, MachineNodeStatus,
    MachineObservation, MachineProvisionFailurePolicy, MachineProvisionOverallStatus,
    MachineProvisionReport, MachineProvisionStatus, MachineProvisionStepReport,
    MachineProvisionStepStatus, MachineProvisioningReport, MachineReadiness,
    MachineReadinessOutcome, MachineReadinessReason, MachineReadinessState, MachineRef,
    MachineRetention, MachineRootStorageKind, MachineRootStorageMetrics, MachineRootfs,
    MachineRunId, MachineSshBackend, MachineSshListenerReport, MachineStaleReason, MachineStart,
    MachineStartOptions, MachineStatus, MachineStopOptions, MachineSystemInfo, MachineTailscale,
    MachineTemporaryDirectoryKind, MachineTemporaryDirectoryMetrics, MachineUpdate,
    MachineUserConfig, MachineUserUpdate, MachineVmSnapshot, MachineVmState, MachineWaitOptions,
    Memory, NetworkPolicyUpdate, ProcessConfig, RawDiskExport, RawDiskExportKind,
    RawDiskExportOptions, SshExitStatus, SshShellAttachment, SshShellControl, SshShellOptions,
    SshShellOptionsBuilder, SshShellSignal, StdinMode, DEFAULT_MACHINE_WAIT_TIMEOUT,
};
pub use crate::network::{
    GuestPublish, MachineNetworkBuilder, MachineNetworkConfig, NetworkBuilder, NetworkDefinition,
    NetworkDriver, NetworkTopology, PublishBind,
};
pub use crate::paths::HostPaths;
pub use crate::runtime::{
    NetdRuntimeConfig, ReadOnlyRuntime, ResolvedRuntimeComponents, Runtime, RuntimeBuilder,
    RuntimeConfig, RuntimeNetworkingConfig, VirtBackendOverride,
};
pub use crate::supervisor::DEFAULT_GUEST_READINESS_TIMEOUT;
pub use forward_spec::{
    Address as ForwardAddress, Direction as ForwardDirection, Endpoint as ForwardEndpoint, Forward,
    ForwardShape, UnixMode,
};
pub use silo_policy::{
    ForwardCertificateProvider, ForwardProtocol, ForwardTls, NetworkAuditBuilder,
    NetworkCredential, NetworkCredentialBuilder, NetworkEndpointBuilder, NetworkForwardBuilder,
    NetworkPolicy, NetworkPolicyBuildError, NetworkPolicyBuilder, NetworkRuleBuilder,
    NetworkSecretAlternative, NetworkSecretKind, NetworkSecretRequirement, NetworkSecretSlot,
    PolicyLoadError, TailscaleTunnelBuilder,
};
