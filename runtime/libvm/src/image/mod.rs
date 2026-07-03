use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::runtime::Runtime;
use crate::LibVmError;

pub use ocidisk::{ImageProgress, ImageProgressReceiver, ImageProgressSender};

/// Source used to create a machine root disk.
///
/// `ImageSource` describes user intent, not the final disk that the virtual
/// machine boots. `MachineBuilder::create` materializes this source immediately
/// into a machine-local root disk. Later `Machine::start` calls only boot that
/// already-created disk and never pull or re-resolve images.
///
/// Strings passed to `MachineBuilder::image` are always OCI references. Local
/// paths are intentionally explicit:
///
/// ```rust,no_run
/// use libvm::{ImageSource, Runtime};
///
/// # async fn example(runtime: Runtime) -> Result<(), libvm::LibVmError> {
/// let oci = runtime.machine().image("ubuntu:24.04").create().await?;
/// let disk = runtime
///     .machine()
///     .image_source(ImageSource::disk("./rootfs.raw"))
///     .create()
///     .await?;
/// # let _ = (oci, disk);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// Pull and materialize an OCI image reference.
    Oci(String),
    /// Clone or copy an existing local disk image into the machine directory.
    Disk(PathBuf),
    /// Convert an uncompressed rootfs tar archive into an ext4 image.
    Tar(PathBuf),
}

impl ImageSource {
    /// Creates an OCI image source.
    pub fn oci(reference: impl Into<String>) -> Self {
        Self::Oci(reference.into())
    }

    /// Creates a local disk image source.
    pub fn disk(path: impl Into<PathBuf>) -> Self {
        Self::Disk(path.into())
    }

    /// Creates an uncompressed rootfs tar source.
    pub fn tar(path: impl Into<PathBuf>) -> Self {
        Self::Tar(path.into())
    }

    pub(crate) fn kind(&self) -> ImageSourceKind {
        match self {
            Self::Oci(_) => ImageSourceKind::Oci,
            Self::Disk(_) => ImageSourceKind::Disk,
            Self::Tar(_) => ImageSourceKind::Tar,
        }
    }

    pub(crate) fn source_reference(&self) -> String {
        match self {
            Self::Oci(reference) => reference.clone(),
            Self::Disk(path) | Self::Tar(path) => path.display().to_string(),
        }
    }

    pub(crate) fn cache_reference(&self) -> String {
        match self {
            Self::Oci(reference) => reference.clone(),
            Self::Disk(path) => format!("disk:{}", path.display()),
            Self::Tar(path) => format!("tar:{}", path.display()),
        }
    }
}

/// Stable source kind recorded for a materialized machine image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSourceKind {
    /// The machine was created from an OCI image reference.
    Oci,
    /// The machine was created from a caller-owned local disk image.
    Disk,
    /// The machine was created from an uncompressed rootfs tar archive.
    Tar,
}

impl ImageSourceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Oci => "oci",
            Self::Disk => "disk",
            Self::Tar => "tar",
        }
    }
}

/// Builder used by `MachineBuilder::image_with` for explicit image selection.
#[derive(Debug, Default, Clone)]
pub struct ImageBuilder {
    source: Option<ImageSource>,
}

impl ImageBuilder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Selects an OCI image reference.
    pub fn oci(mut self, reference: impl Into<String>) -> Self {
        self.source = Some(ImageSource::oci(reference));
        self
    }

    /// Selects a local disk image.
    pub fn disk(mut self, path: impl Into<PathBuf>) -> Self {
        self.source = Some(ImageSource::disk(path));
        self
    }

    /// Selects an uncompressed rootfs tar archive.
    pub fn tar(mut self, path: impl Into<PathBuf>) -> Self {
        self.source = Some(ImageSource::tar(path));
        self
    }

    pub(crate) fn finish(self) -> Option<ImageSource> {
        self.source
    }
}

/// Policy used when libvm materializes an OCI image.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ImagePullPolicy {
    /// Use a locally cached image when present, otherwise pull it.
    #[default]
    IfMissing,
    /// Resolve the reference and refresh the cache before use.
    Always,
    /// Require an already-cached image and fail without network access.
    Never,
}

/// Options for explicit `Runtime::images().pull_with` calls.
#[derive(Debug, Clone, Default)]
pub struct ImagePullOptions {
    /// Optional policy override for this operation.
    pub policy: Option<ImagePullPolicy>,
}

/// Options for removing image references.
#[derive(Debug, Clone, Default)]
pub struct ImageRemoveOptions {
    /// Remove a reference even when machines still pin its manifest.
    pub force: bool,
}

/// Lightweight image row returned by list and get operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageHandle {
    /// User-facing image reference, for example `ubuntu:24.04`.
    pub reference: String,
    /// Immutable image ID for the resolved artifact.
    pub image_id: String,
    /// Resolved OCI manifest digest when this is an OCI image.
    pub manifest_digest: Option<String>,
    /// Platform operating system.
    pub platform_os: String,
    /// Platform CPU architecture.
    pub platform_architecture: String,
    /// Optional platform variant.
    pub platform_variant: Option<String>,
    /// Size of the materialized rootfs artifact in bytes when known.
    pub size_bytes: Option<u64>,
    /// Unix timestamp for when the reference was first recorded.
    pub created_at: i64,
    /// Unix timestamp for when the reference last changed.
    pub updated_at: i64,
    /// Unix timestamp for the last use, when known.
    pub last_used_at: Option<i64>,
}

/// Full image details returned by inspect operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageDetail {
    /// Basic image reference metadata.
    pub handle: ImageHandle,
    /// Ordered OCI layers. Tar and disk sources currently have no layer rows.
    pub layers: Vec<ImageLayerDetail>,
}

/// One OCI layer belonging to an image manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageLayerDetail {
    /// Digest of the compressed registry blob.
    pub blob_digest: String,
    /// Digest of the uncompressed filesystem diff.
    pub diff_id: String,
    /// OCI media type.
    pub media_type: String,
    /// Compressed blob size in bytes when known.
    pub compressed_size_bytes: Option<u64>,
    /// Uncompressed layer size in bytes when known.
    pub uncompressed_size_bytes: Option<u64>,
    /// Layer position in the manifest.
    pub position: i64,
}

/// Result of pruning unreferenced image records and artifacts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImagePruneReport {
    /// Number of image references removed.
    pub references_removed: u64,
    /// Number of materialized rootfs artifact records removed.
    pub artifacts_removed: u64,
    /// Number of bytes removed from disk when known.
    pub bytes_removed: u64,
}

/// Runtime-scoped image management namespace.
///
/// Image operations share the same data directory, pull policy, progress sender,
/// and datastore as machine creation. Pulling an image through this namespace
/// warms the same cache that `Runtime::machine().image(...).create()` uses.
#[derive(Debug, Clone)]
pub struct Images {
    runtime: Runtime,
}

impl Images {
    pub(crate) fn new(runtime: Runtime) -> Self {
        Self { runtime }
    }

    /// Pulls or reuses an OCI image reference according to the runtime policy.
    pub async fn pull(&self, reference: impl Into<String>) -> Result<ImageHandle, LibVmError> {
        self.pull_with(reference, ImagePullOptions::default()).await
    }

    /// Pulls or reuses an OCI image reference with an operation-specific policy.
    pub async fn pull_with(
        &self,
        reference: impl Into<String>,
        options: ImagePullOptions,
    ) -> Result<ImageHandle, LibVmError> {
        let reference = reference.into();
        let runtime = match options.policy {
            Some(policy) => self.runtime.clone().with_image_pull_policy(policy),
            None => self.runtime.clone(),
        };
        let image = runtime
            .materialize_image(&ImageSource::oci(reference.clone()))
            .await?;
        runtime
            .image_handle(&image.image_ref)
            .await?
            .ok_or(LibVmError::ImageNotFound {
                reference: image.image_ref,
            })
    }

    /// Returns a cached image reference without pulling.
    pub async fn get(&self, reference: &str) -> Result<Option<ImageHandle>, LibVmError> {
        self.runtime.image_handle(reference).await
    }

    /// Lists known image references.
    pub async fn list(&self) -> Result<Vec<ImageHandle>, LibVmError> {
        self.runtime.list_image_handles().await
    }

    /// Returns image details for a cached reference.
    pub async fn inspect(&self, reference: &str) -> Result<Option<ImageDetail>, LibVmError> {
        self.runtime.image_detail(reference).await
    }

    /// Removes an image reference when no machine pins its manifest.
    pub async fn remove(&self, reference: &str) -> Result<(), LibVmError> {
        self.remove_with(reference, ImageRemoveOptions::default())
            .await
    }

    /// Removes an image reference with explicit options.
    pub async fn remove_with(
        &self,
        reference: &str,
        options: ImageRemoveOptions,
    ) -> Result<(), LibVmError> {
        self.runtime.remove_image(reference, options).await
    }

    /// Prunes image metadata and artifacts that no machine references.
    pub async fn prune(&self) -> Result<ImagePruneReport, LibVmError> {
        self.runtime.prune_images().await
    }
}

pub(crate) struct MaterializedImage {
    pub(crate) rootfs_path: PathBuf,
    pub(crate) image_ref: String,
    pub(crate) source_kind: ImageSourceKind,
    pub(crate) source_reference: String,
    pub(crate) image_id: Option<String>,
    pub(crate) manifest_digest: Option<String>,
    pub(crate) size_bytes: u64,
}
