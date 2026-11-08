pub mod artifact_registry;
pub mod changeset;
pub mod composition;
mod digest;
pub mod erofs;
mod error;
mod flat_ext4;
mod lock;
pub mod overlay_flatten;
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
    MaterializeOptions, OciMaterializer, RootfsLayerMetadata, RootfsMetadata, StagingOperation,
};
