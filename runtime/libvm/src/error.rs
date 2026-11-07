use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LibVmError {
    #[error("{operation} unsupported: {reason} (backend={backend}, lane={lane})")]
    LiveOperationUnsupported {
        operation: vm_spec::live::LiveOperation,
        backend: vm_spec::live::LiveBackend,
        lane: vm_spec::live::LiveLane,
        reason: vm_spec::live::LiveUnsupportedReason,
    },
    #[error("live capability discovery failed: {message}")]
    LiveDiscovery { message: String },
    #[error("live capability protocol failed: {message}")]
    LiveProtocol { message: String },
    #[error("live observation for {reference} failed: {message}")]
    LiveObservation { reference: String, message: String },
    /// A retained capture produced no admissible checkpoint or is still owned
    /// by its run. The capture identity, reservation and staging are retained.
    #[error("live capture {capture_id}: {message}")]
    LiveCapture { capture_id: String, message: String },
    #[error("live fork {operation_id}: {message}")]
    LiveFork {
        operation_id: String,
        message: String,
    },
    #[error("live fork {operation_id} was not found")]
    LiveForkNotFound { operation_id: String },

    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),
    #[error(transparent)]
    OverlayBootQualification(#[from] crate::boot_qualification::OverlayBootQualificationError),
    /// A raw root's selected kernel bytes do not establish its direct profile.
    #[error(transparent)]
    DirectKernelRejected(#[from] Box<crate::boot_qualification::DirectKernelRejected>),
    #[error("backend {backend:?} does not support development flat overlay roots")]
    OverlayBackendUnsupported { backend: vm_spec::live::LiveBackend },
    #[error("boot admission rejected {source_family:?}/{root_profile:?} on {effective_backend:?}: requires {requirement:?}; remedy: {remedy:?}")]
    BackendAdmissionRejected {
        source_family: crate::runtime::boot_assets::SourceFamily,
        root_profile: crate::StorageProfile,
        requirement: crate::BackendRequirement,
        effective_backend: vm_spec::live::LiveBackend,
        remedy: crate::runtime::boot_assets::AdmissionRemedy,
    },
    #[error("required translation is unavailable: {reason}")]
    TranslationUnavailable { reason: String },
    #[error("boot assets require acquisition of immutable object {missing}")]
    BootAssetsAcquisitionRequired {
        missing: crate::storage::identity::ObjectDigest,
    },
    #[error("base initramfs {actual} has no admitted schema-2 bootstrap ABI; select the packaged base {expected}")]
    BootBundleAbiUnsupported {
        expected: crate::storage::identity::ObjectDigest,
        actual: crate::storage::identity::ObjectDigest,
    },
    #[error("root selection {:?} failed: {}", .0.requested, .0.reason)]
    RootSelectionFailed(Box<crate::image::import_types::RootSelectionFailed>),
    #[error(transparent)]
    DiskImport(#[from] Box<crate::image::import::DiskImportError>),
    #[error("development flat overlay roots cannot be published or snapshotted")]
    FlatOverlayPublicationUnsupported,
    /// Names the failing artifact boundary (config, table, transfer map,
    /// chunk, object, record, provenance) and the stable identity involved.
    #[error("VM artifact {boundary} rejected: {message}")]
    ArtifactInvalid {
        boundary: &'static str,
        message: String,
    },
    #[error(transparent)]
    ArtifactWire(#[from] oci::vm_artifact::Error),
    #[error("approved VM artifact index {expected} differs from resolved index {actual}")]
    ArtifactTrustMismatch { expected: String, actual: String },
    #[error("signature-required VM artifact policy has no configured signature verifier; digest approval cannot substitute for publisher authentication")]
    ArtifactSignatureProviderUnavailable,
    #[error("checkpoint publication to {destination} requires an acknowledgement naming exactly that destination: disks and RAM export secrets and deleted-data remnants")]
    CheckpointPublicationNotAcknowledged { destination: String },
    #[error("format private overlay upper: {0}")]
    UpperFormat(#[from] disk_image::ext4::FormatError),
    #[error(transparent)]
    Changeset(#[from] oci::changeset::ChangesetError),
    #[error(transparent)]
    Namespace(#[from] oci::changeset::namespace::NamespaceError),
    #[error("blocking storage worker failed: {0}")]
    Task(#[from] tokio::task::JoinError),

    #[error("invalid {record} storage record: {message}")]
    InvalidStorageRecord {
        record: &'static str,
        message: String,
    },

    #[error("image removal would invalidate machine {machine} dependency {path}")]
    CacheDependency { machine: String, path: PathBuf },

    #[error("incompatible state database; reinstall Silo and explicitly wipe its state before retrying: {source}")]
    StateDatabaseIncompatible {
        #[source]
        source: sqlx::migrate::MigrateError,
    },
    #[error("network secret slot {slot:?}, store key {key:?}: {code}")]
    SecretResolution {
        slot: String,
        key: String,
        code: String,
    },
    #[error("missing required network secret material for {reference}: {requirements:?}; store keys {keys:?}")]
    MissingNetworkSecrets {
        reference: String,
        requirements: Vec<crate::NetworkSecretRequirement>,
        policy: Box<crate::NetworkPolicy>,
        keys: Vec<String>,
    },
    #[error("could not resolve the Silo home from SILO_HOME or HOME")]
    HomeUnavailable,

    #[error("could not resolve the Silo config directory from XDG_CONFIG_HOME or HOME")]
    ConfigDirUnavailable,

    #[error("environment variable {name} must be an absolute path, got {path}")]
    RelativeEnvironmentPath { name: &'static str, path: PathBuf },

    #[error("invalid SILO_VIRT_BACKEND value {value:?}; expected krun or vz")]
    InvalidVirtBackendOverride { value: String },

    #[error("invalid Silo run root {path}: {message}")]
    InvalidRunRoot { path: PathBuf, message: String },

    #[error("invalid machine-owned filesystem object {path}: {message}")]
    InvalidOwnedPath { path: PathBuf, message: String },

    #[error("invalid machine name {name:?}: {reason}")]
    InvalidMachineName { name: String, reason: String },

    #[error("invalid machine id prefix {prefix:?}: {reason}")]
    InvalidMachineIdPrefix { prefix: String, reason: String },

    #[error("machine {name:?} already exists")]
    MachineAlreadyExists { name: String },

    #[error("failed to generate a unique machine name after {attempts} attempts")]
    MachineNameGenerationFailed { attempts: u32 },

    #[error("machine {reference} not found")]
    MachineNotFound { reference: String },

    #[error("image {reference} not found")]
    ImageNotFound { reference: String },

    #[error("image {reference} is still pinned by {machine_count} machine(s)")]
    ImageInUse {
        reference: String,
        machine_count: u64,
    },

    #[error("image pull policy {policy:?} does not apply to {source_kind:?} image sources")]
    ImagePullPolicyUnsupported {
        policy: crate::ImagePullPolicy,
        source_kind: crate::ImageSourceKind,
    },

    #[error("image operation for {reference} failed")]
    Image {
        reference: String,
        #[source]
        source: oci::OciError,
    },

    #[error("{message}")]
    ImageReferenceRejected { reference: String, message: String },

    #[error("machine {id} already exists")]
    MachineIdAlreadyExists { id: String },

    #[error("machine {reference} is already running")]
    MachineAlreadyRunning { reference: String },

    #[error("machine {reference} is not running")]
    MachineNotRunning { reference: String },

    #[error("machine {reference} run {requested} is no longer current")]
    MachineStaleGeneration {
        reference: String,
        requested: crate::MachineRunId,
        current: Option<crate::MachineRunId>,
    },

    #[error("machine {reference} does not provide {log_source:?} logs")]
    MachineLogSourceUnavailable {
        reference: String,
        log_source: crate::machine::MachineLogSource,
    },

    #[error("monitor connection for {reference} failed: {message}")]
    MonitorConnection { reference: String, message: String },

    #[error("monitor protocol for {reference} failed: {message}")]
    MonitorProtocol { reference: String, message: String },

    /// The guest filesystem reported that a requested path does not exist.
    #[error("guest path for {reference} not found: {message}")]
    GuestPathNotFound { reference: String, message: String },

    #[error("forward request for {reference} was rejected ({grpc_code:?}, {detail:?}): {reason}")]
    ForwardRejected {
        reference: String,
        grpc_code: tonic::Code,
        detail: Option<crate::MachineForwardErrorDetail>,
        reason: String,
    },

    #[error("guest session for {reference} failed: {message}")]
    GuestSession { reference: String, message: String },

    #[error("machine preparation for {reference} failed: {message}")]
    MachinePreparationFailed { reference: String, message: String },

    #[error("machine start failed: {primary}; cleanup also failed: {cleanup}")]
    MachineStartCleanupFailed { primary: String, cleanup: String },

    #[error("entrypoint {failure}")]
    EntrypointLaunchFailed {
        failure: crate::machine::ExecutionLaunchFailure,
    },

    #[error("network runtime for {reference} failed: {message}")]
    NetworkRuntime { reference: String, message: String },

    #[error("silo-vmm executable not found; checked {searched}")]
    VmMonExecutableNotFound { searched: String },

    #[error("silo-vmm executable path is not a file: {path}")]
    VmMonExecutableInvalid { path: PathBuf },

    #[error("invalid runtime component input from {input}: {message}")]
    RuntimeComponentInvalid { input: String, message: String },

    #[error(
        "could not resolve a complete Silo runtime; missing or invalid components: {considered}. Expected {expected_layouts}.{guidance}"
    )]
    RuntimeComponentsNotFound {
        considered: String,
        expected_layouts: String,
        guidance: String,
    },

    #[error("boot asset {asset} not found; checked {checked}")]
    BootAssetNotFound {
        asset: &'static str,
        checked: String,
    },

    #[error("boot asset {asset} path is not a file: {path}")]
    BootAssetInvalid { asset: &'static str, path: PathBuf },

    #[error("invalid create request for machine {name:?}: {reason}")]
    InvalidCreateRequest { name: String, reason: String },

    #[error("invalid update for machine {reference:?}: {reason}")]
    InvalidMachineUpdate { reference: String, reason: String },

    #[error("invalid machine configuration for {reference:?}: {reason}")]
    InvalidMachineConfig { reference: String, reason: String },

    #[error("unsupported host architecture {arch:?}")]
    UnsupportedHostArchitecture { arch: String },

    #[error("machine {id} metadata is missing required field {field}")]
    CorruptState { id: String, field: &'static str },

    #[error("failed to serialize VmSpec for machine {name:?}")]
    VmSpecSerializeFailed {
        name: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to load VmSpec for machine {id} from {path}")]
    VmSpecLoadFailed {
        id: String,
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("ambiguous machine id prefix {prefix:?} matched {count} machines")]
    AmbiguousIdPrefix { prefix: String, count: usize },

    #[error("failed to decode state field {field}: {message}")]
    StateDecode {
        field: &'static str,
        message: String,
    },

    #[error("state database config mismatch for {field}: expected {expected:?}, found {actual:?}")]
    StateDatabaseConfigMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error(transparent)]
    Database(#[from] sqlx::Error),

    #[error(transparent)]
    DatabaseMigration(#[from] sqlx::migrate::MigrateError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("root disk operation failed: {message}")]
    RootDisk { message: String },
}

impl LibVmError {
    /// Only used at an individual machine's observation boundary. Database-wide
    /// failures must never be downgraded to a machine warning.
    pub(crate) fn is_machine_observation_error(&self) -> bool {
        matches!(
            self,
            Self::Io(_)
                | Self::InvalidOwnedPath { .. }
                | Self::CorruptState { .. }
                | Self::StateDecode { .. }
                | Self::InvalidStorageRecord { .. }
                | Self::Storage(crate::storage::StorageError::Bound(_))
                | Self::NetworkRuntime { .. }
                | Self::MonitorConnection { .. }
                | Self::MonitorProtocol { .. }
                | Self::InvalidMachineConfig { .. }
                | Self::Database(sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_))
        )
    }

    /// Returns the stable Rust variant name for language bindings.
    ///
    /// This match deliberately remains exhaustive so adding an error variant
    /// cannot silently degrade a binding to message parsing or an unknown kind.
    pub fn variant(&self) -> &'static str {
        match self {
            Self::LiveOperationUnsupported { .. } => "LiveOperationUnsupported",
            Self::LiveDiscovery { .. } => "LiveDiscovery",
            Self::LiveProtocol { .. } => "LiveProtocol",
            Self::LiveObservation { .. } => "LiveObservation",
            Self::LiveCapture { .. } => "LiveCapture",
            Self::LiveFork { .. } => "LiveFork",
            Self::LiveForkNotFound { .. } => "LiveForkNotFound",
            Self::Storage(_) => "Storage",
            Self::OverlayBootQualification(_) => "OverlayBootQualification",
            Self::DirectKernelRejected(_) => "DirectKernelRejected",
            Self::OverlayBackendUnsupported { .. } => "OverlayBackendUnsupported",
            Self::BackendAdmissionRejected { .. } => "BackendAdmissionRejected",
            Self::TranslationUnavailable { .. } => "TranslationUnavailable",
            Self::BootAssetsAcquisitionRequired { .. } => "BootAssetsAcquisitionRequired",
            Self::BootBundleAbiUnsupported { .. } => "BootBundleAbiUnsupported",
            Self::RootSelectionFailed(_) => "RootSelectionFailed",
            Self::DiskImport(_) => "DiskImport",
            Self::FlatOverlayPublicationUnsupported => "FlatOverlayPublicationUnsupported",
            Self::ArtifactInvalid { .. } => "ArtifactInvalid",
            Self::ArtifactWire(_) => "ArtifactWire",
            Self::ArtifactTrustMismatch { .. } => "ArtifactTrustMismatch",
            Self::ArtifactSignatureProviderUnavailable => "ArtifactSignatureProviderUnavailable",
            Self::CheckpointPublicationNotAcknowledged { .. } => {
                "CheckpointPublicationNotAcknowledged"
            }
            Self::UpperFormat(_) => "UpperFormat",
            Self::Changeset(_) => "Changeset",
            Self::Namespace(_) => "Namespace",
            Self::Task(_) => "Task",
            Self::InvalidStorageRecord { .. } => "InvalidStorageRecord",
            Self::CacheDependency { .. } => "CacheDependency",
            Self::StateDatabaseIncompatible { .. } => "StateDatabaseIncompatible",
            Self::SecretResolution { .. } => "SecretResolution",
            Self::MissingNetworkSecrets { .. } => "MissingNetworkSecrets",
            Self::HomeUnavailable => "HomeUnavailable",
            Self::ConfigDirUnavailable => "ConfigDirUnavailable",
            Self::RelativeEnvironmentPath { .. } => "RelativeEnvironmentPath",
            Self::InvalidVirtBackendOverride { .. } => "InvalidVirtBackendOverride",
            Self::InvalidRunRoot { .. } => "InvalidRunRoot",
            Self::InvalidOwnedPath { .. } => "InvalidOwnedPath",
            Self::InvalidMachineName { .. } => "InvalidMachineName",
            Self::InvalidMachineIdPrefix { .. } => "InvalidMachineIdPrefix",
            Self::MachineAlreadyExists { .. } => "MachineAlreadyExists",
            Self::MachineNameGenerationFailed { .. } => "MachineNameGenerationFailed",
            Self::MachineNotFound { .. } => "MachineNotFound",
            Self::ImageNotFound { .. } => "ImageNotFound",
            Self::ImageInUse { .. } => "ImageInUse",
            Self::ImagePullPolicyUnsupported { .. } => "ImagePullPolicyUnsupported",
            Self::Image { .. } => "Image",
            Self::ImageReferenceRejected { .. } => "ImageReferenceRejected",
            Self::MachineIdAlreadyExists { .. } => "MachineIdAlreadyExists",
            Self::MachineAlreadyRunning { .. } => "MachineAlreadyRunning",
            Self::MachineNotRunning { .. } => "MachineNotRunning",
            Self::MachineStaleGeneration { .. } => "MachineStaleGeneration",
            Self::MachineLogSourceUnavailable { .. } => "MachineLogSourceUnavailable",
            Self::MonitorConnection { .. } => "MonitorConnection",
            Self::MonitorProtocol { .. } => "MonitorProtocol",
            Self::GuestPathNotFound { .. } => "GuestPathNotFound",
            Self::ForwardRejected { .. } => "ForwardRejected",
            Self::GuestSession { .. } => "GuestSession",
            Self::MachinePreparationFailed { .. } => "MachinePreparationFailed",
            Self::MachineStartCleanupFailed { .. } => "MachineStartCleanupFailed",
            Self::EntrypointLaunchFailed { .. } => "EntrypointLaunchFailed",
            Self::NetworkRuntime { .. } => "NetworkRuntime",
            Self::VmMonExecutableNotFound { .. } => "VmMonExecutableNotFound",
            Self::VmMonExecutableInvalid { .. } => "VmMonExecutableInvalid",
            Self::RuntimeComponentInvalid { .. } => "RuntimeComponentInvalid",
            Self::RuntimeComponentsNotFound { .. } => "RuntimeComponentsNotFound",
            Self::BootAssetNotFound { .. } => "BootAssetNotFound",
            Self::BootAssetInvalid { .. } => "BootAssetInvalid",
            Self::InvalidCreateRequest { .. } => "InvalidCreateRequest",
            Self::InvalidMachineUpdate { .. } => "InvalidMachineUpdate",
            Self::InvalidMachineConfig { .. } => "InvalidMachineConfig",
            Self::UnsupportedHostArchitecture { .. } => "UnsupportedHostArchitecture",
            Self::CorruptState { .. } => "CorruptState",
            Self::VmSpecSerializeFailed { .. } => "VmSpecSerializeFailed",
            Self::VmSpecLoadFailed { .. } => "VmSpecLoadFailed",
            Self::AmbiguousIdPrefix { .. } => "AmbiguousIdPrefix",
            Self::StateDecode { .. } => "StateDecode",
            Self::StateDatabaseConfigMismatch { .. } => "StateDatabaseConfigMismatch",
            Self::Database(_) => "Database",
            Self::DatabaseMigration(_) => "DatabaseMigration",
            Self::Io(_) => "Io",
            Self::RootDisk { .. } => "RootDisk",
        }
    }
}

impl From<crate::machine::root_disk::RootDiskError> for LibVmError {
    fn from(source: crate::machine::root_disk::RootDiskError) -> Self {
        Self::RootDisk {
            message: source.to_string(),
        }
    }
}
