use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(crate) mod convert;
pub(crate) mod ext4_admission;
pub(crate) mod import;
pub(crate) mod import_types;
pub(crate) mod local_disk;
pub(crate) mod oci;
pub(crate) mod progress;

use crate::runtime::Runtime;
use crate::LibVmError;

pub use ::oci::ImageConfig as OciImageConfigMetadata;
pub use ::oci::Platform;
pub use ::oci::{RegistryAction, RegistryPolicy, RegistryRule};
pub use progress::{ImageProgress, ImageProgressReceiver, ImageProgressSender};

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
    /// Import a quiesced caller-owned disk with explicit boot metadata.
    Disk(import_types::DiskImportRequest),
    /// Acquire an immutable managed image or complete snapshot.
    Managed(import_types::ManagedSourceRef),
}

impl ImageSource {
    /// Creates an OCI image source.
    pub fn oci(reference: impl Into<String>) -> Self {
        Self::Oci(reference.into())
    }

    /// Creates a local disk image source.
    pub fn disk(path: impl Into<PathBuf>) -> Self {
        Self::Disk(import_types::DiskImportRequest {
            path: path.into(),
            boot: import_types::DiskImportBoot::LinuxDirect {
                platform: crate::LinuxPlatform {
                    architecture: if cfg!(target_arch = "aarch64") {
                        crate::GuestArchitecture::Arm64
                    } else {
                        crate::GuestArchitecture::Amd64
                    },
                    variant: None,
                },
                root: import_types::ImportRootSelection::WholeDisk,
                assets: import_types::BootAssetSelection::Packaged,
            },
            alias: None,
        })
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
    /// The machine was created from an immutable managed image.
    Managed,
}

impl ImageSourceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Oci => "oci",
            Self::Disk => "disk",
            Self::Managed => "managed",
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

/// Options for read-only `Runtime::images().resolve_with` calls.
#[derive(Debug, Clone, Default)]
pub struct ImageResolveOptions {
    /// Optional policy override for this operation.
    pub policy: Option<ImagePullPolicy>,
    /// Requested Linux userspace platform; absence selects the host platform.
    pub platform: Option<crate::LinuxPlatform>,
}

/// Whether the resolved immutable image already has a complete local rootfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageCacheState {
    /// The selected manifest has a complete rootfs in the local cache.
    Complete,
    /// The selected manifest must be materialized before it can be used.
    Missing,
}

/// An immutable OCI image selection that can be materialized without resolving again.
///
/// Values are created by `Images::resolve` and retain private registry resolution
/// data when needed for a later `MachineBuilder::resolved_image` call.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolvedOciImage {
    /// Canonical OCI reference requested by the caller.
    pub requested_reference: String,
    /// Digest-pinned OCI reference selected for the requested platform.
    pub selected_reference: String,
    /// Digest of the selected OCI image manifest.
    pub manifest_digest: String,
    /// Digest of the selected OCI image configuration.
    pub config_digest: String,
    /// Execution defaults declared by the OCI image configuration.
    pub config: OciImageConfigMetadata,
    /// Platform selected for this image.
    pub platform: Platform,
    /// Whether the selected identity is already completely cached.
    pub cache_state: ImageCacheState,
    pub(crate) materialization: ResolvedOciImageMaterialization,
}

#[derive(Debug, Clone)]
pub(crate) enum ResolvedOciImageMaterialization {
    Cached,
    Registry(Box<::oci::ResolvedImage>),
}

/// Options for removing image references.
#[derive(Debug, Clone, Default)]
pub struct ImageRemoveOptions {
    /// Reserved override for records with actual shared storage dependencies.
    pub force: bool,
}

/// Lightweight image row returned by list and get operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageHandle {
    /// OCI reference requested by the caller, for example `ubuntu:24.04`.
    pub requested_reference: String,
    /// Digest-pinned OCI reference selected for the host platform.
    pub selected_reference: String,
    /// Immutable OCI manifest digest selected for this reference.
    pub selected_manifest_digest: String,
    /// Digest of the OCI image configuration document.
    pub config_digest: String,
    /// Immutable image ID for the resolved artifact.
    pub image_id: String,
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
    /// OCI image configuration metadata. Optional collection fields preserve the
    /// distinction between an absent field and an explicitly empty value.
    /// `StopSignal` is inspection-only; it does not alter `Machine::stop`.
    pub config: OciImageConfigMetadata,
    /// Ordered OCI layers.
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

    fn managed_store(
        &self,
    ) -> Result<crate::store::managed_image_store::ManagedImageStore, LibVmError> {
        Ok(
            crate::store::managed_image_store::ManagedImageStore::from_store(std::sync::Arc::new(
                self.runtime.native_store()?,
            )),
        )
    }

    /// Resolves an untyped digest without preferring images over snapshots.
    pub async fn resolve_managed_digest(
        &self,
        digest: &crate::ObjectDigest,
    ) -> Result<crate::ManagedSourceId, LibVmError> {
        self.managed_store()?.resolve_digest(*digest).await
    }

    /// Inspects canonical managed metadata without changing retention.
    pub async fn inspect_managed(
        &self,
        source: &crate::ManagedSourceRef,
    ) -> Result<crate::ManagedSourceInfo, LibVmError> {
        self.managed_store()?.inspect(source).await
    }

    /// Lists retained managed image and snapshot metadata.
    pub async fn list_managed(&self) -> Result<Vec<crate::ManagedSourceInfo>, LibVmError> {
        self.managed_store()?.list().await
    }

    /// Names an existing managed source in the shared alias namespace.
    pub async fn add_alias(
        &self,
        source: &crate::ManagedSourceRef,
        alias: &str,
    ) -> Result<crate::ManagedSourceInfo, LibVmError> {
        self.managed_store()?.add_alias(source, alias).await
    }

    /// Removes an alias without releasing its target's independent retention.
    pub async fn remove_alias(&self, alias: &str) -> Result<bool, LibVmError> {
        self.managed_store()?.remove_alias(alias).await
    }

    /// Releases explicit retention; other aliases, machines and consumers remain roots.
    pub async fn release_retention(
        &self,
        source: &crate::ManagedSourceRef,
    ) -> Result<bool, LibVmError> {
        self.managed_store()?.release_retention(source).await
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
            .image_handle(&image.requested_reference)
            .await?
            .ok_or(LibVmError::ImageNotFound {
                reference: image.requested_reference,
            })
    }

    /// Resolves an OCI reference according to the runtime pull policy without
    /// writing cache or datastore state.
    pub async fn resolve(
        &self,
        reference: impl Into<String>,
    ) -> Result<ResolvedOciImage, LibVmError> {
        self.resolve_with(reference, ImageResolveOptions::default())
            .await
    }

    /// Resolves an OCI reference with an operation-specific policy without
    /// materializing or updating image state.
    pub async fn resolve_with(
        &self,
        reference: impl Into<String>,
        options: ImageResolveOptions,
    ) -> Result<ResolvedOciImage, LibVmError> {
        let policy = options.policy.unwrap_or(self.runtime.image_pull_policy());
        self.runtime
            .resolve_oci_image(reference.into(), policy, options.platform.as_ref())
            .await
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

    /// Removes an image reference; independent private machine roots are unaffected.
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

    /// Prunes unreferenced image metadata and bytes not retained by active operations.
    pub async fn prune(&self) -> Result<ImagePruneReport, LibVmError> {
        self.runtime.prune_images().await
    }
}

pub(crate) struct MaterializedImage {
    pub(crate) rootfs_path: PathBuf,
    pub(crate) stream: Option<crate::storage::identity::StreamId>,
    pub(crate) requested_reference: String,
    pub(crate) selected_reference: Option<String>,
    pub(crate) source_kind: ImageSourceKind,
    pub(crate) image_id: Option<String>,
    pub(crate) manifest_digest: Option<String>,
    pub(crate) config_digest: Option<String>,
    pub(crate) size_bytes: u64,
    pub(crate) platform: Platform,
    pub(crate) managed: Option<crate::store::managed_image_store::ManagedImageConsumer>,
    pub(crate) authenticated: Option<crate::storage::stream::AuthenticatedStream>,
    pub(crate) _lease: Option<crate::storage::locks::StorageLock>,
}
