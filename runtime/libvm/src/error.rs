use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LibVmError {
    #[error("could not resolve Silo data directory from XDG_DATA_HOME or HOME")]
    DataDirUnavailable,

    #[error("could not resolve Silo state directory from XDG_STATE_HOME or HOME")]
    StateDirUnavailable,

    #[error("could not resolve Silo config directory from XDG_CONFIG_HOME or HOME")]
    ConfigDirUnavailable,

    #[error("environment variable {name} must be an absolute path, got {path}")]
    RelativeEnvironmentPath { name: &'static str, path: PathBuf },

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

    #[error("could not canonicalize local disk {path}: {source}")]
    LocalDiskCanonicalize {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not inspect local disk {path}: {source}")]
    LocalDiskMetadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("local disk {path} is invalid: path must point to a regular file")]
    LocalDiskNotRegularFile { path: PathBuf },

    #[error("could not read local disk {path}: {source}")]
    LocalDiskUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("image operation for {reference} failed")]
    Image {
        reference: String,
        #[source]
        source: oci::OciError,
    },

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

    #[error("vmmon executable not found; checked {searched}")]
    VmMonExecutableNotFound { searched: String },

    #[error("vmmon executable path is not a file: {path}")]
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
    /// Returns the stable Rust variant name for language bindings.
    ///
    /// This match deliberately remains exhaustive so adding an error variant
    /// cannot silently degrade a binding to message parsing or an unknown kind.
    pub fn variant(&self) -> &'static str {
        match self {
            Self::DataDirUnavailable => "DataDirUnavailable",
            Self::StateDirUnavailable => "StateDirUnavailable",
            Self::ConfigDirUnavailable => "ConfigDirUnavailable",
            Self::RelativeEnvironmentPath { .. } => "RelativeEnvironmentPath",
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
            Self::LocalDiskCanonicalize { .. } => "LocalDiskCanonicalize",
            Self::LocalDiskMetadata { .. } => "LocalDiskMetadata",
            Self::LocalDiskNotRegularFile { .. } => "LocalDiskNotRegularFile",
            Self::LocalDiskUnreadable { .. } => "LocalDiskUnreadable",
            Self::Image { .. } => "Image",
            Self::MachineIdAlreadyExists { .. } => "MachineIdAlreadyExists",
            Self::MachineAlreadyRunning { .. } => "MachineAlreadyRunning",
            Self::MachineNotRunning { .. } => "MachineNotRunning",
            Self::MachineStaleGeneration { .. } => "MachineStaleGeneration",
            Self::MachineLogSourceUnavailable { .. } => "MachineLogSourceUnavailable",
            Self::MonitorConnection { .. } => "MonitorConnection",
            Self::MonitorProtocol { .. } => "MonitorProtocol",
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
