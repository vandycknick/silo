use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LibVmError {
    #[error("could not resolve Bento data directory from XDG_DATA_HOME or HOME")]
    DataDirUnavailable,

    #[error("could not resolve Bento config directory from XDG_CONFIG_HOME or HOME")]
    ConfigDirUnavailable,

    #[error("environment variable {name} must be an absolute path, got {path}")]
    RelativeEnvironmentPath { name: &'static str, path: PathBuf },

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

    #[error("image operation for {reference} failed")]
    Image {
        reference: String,
        #[source]
        source: ocidisk::OciDiskError,
    },

    #[error("machine {id} already exists")]
    MachineIdAlreadyExists { id: String },

    #[error("machine {reference} is already running")]
    MachineAlreadyRunning { reference: String },

    #[error("machine {reference} is not running")]
    MachineNotRunning { reference: String },

    #[error("monitor connection for {reference} failed: {message}")]
    MonitorConnection { reference: String, message: String },

    #[error("monitor protocol for {reference} failed: {message}")]
    MonitorProtocol { reference: String, message: String },

    #[error("guest session for {reference} failed: {message}")]
    GuestSession { reference: String, message: String },

    #[error("machine preparation for {reference} failed: {message}")]
    MachinePreparationFailed { reference: String, message: String },

    #[error("network runtime for {reference} failed: {message}")]
    NetworkRuntime { reference: String, message: String },

    #[error("vmmon executable not found; checked {searched}")]
    VmMonExecutableNotFound { searched: String },

    #[error("vmmon executable path is not a file: {path}")]
    VmMonExecutableInvalid { path: PathBuf },

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

impl From<crate::machine::root_disk::RootDiskError> for LibVmError {
    fn from(source: crate::machine::root_disk::RootDiskError) -> Self {
        Self::RootDisk {
            message: source.to_string(),
        }
    }
}
