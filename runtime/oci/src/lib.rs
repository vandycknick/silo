pub mod artifact_registry;
pub mod changeset;
mod digest;
mod error;
mod flat_ext4;
mod lock;
mod platform;
mod policy;
mod progress;
mod registry;
mod store;
pub mod vm_artifact;

pub use crate::error::{OciError, OciResult};
pub use crate::platform::Platform;
pub use crate::policy::{RegistryAction, RegistryPolicy, RegistryRule};
pub use crate::progress::{ProgressEvent, ProgressReporter};
pub use crate::registry::{ImageConfig, ResolvedImage};
pub use crate::store::{
    Materialization, MaterializeOptions, OciMaterializer, RootfsLayerMetadata, RootfsMetadata,
    StagedRootfs, StagingOperation,
};
