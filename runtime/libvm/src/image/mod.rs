use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(crate) mod convert;
pub(crate) mod ext4_admission;
pub(crate) mod import;
pub(crate) mod import_types;
pub(crate) mod local_disk;
pub(crate) mod oci;
pub(crate) mod progress;
pub(crate) mod transport;

use crate::image::import_types::{ImageInfo, ImageRef, ImageRemoval};
use crate::runtime::Runtime;
use crate::LibVmError;

pub use crate::image::progress::{
    ImageProgress, ImageProgressLayer, ImageProgressReceiver, ImageProgressSender,
};
pub use ::oci::ImageConfig as OciImageConfigMetadata;
pub use ::oci::Platform;
pub use ::oci::{RegistryAction, RegistryPolicy, RegistryRule};

/// Source used to create a machine root disk. Images only: a snapshot is
/// restored with `Runtime::restore`, never created from.
///
/// `ImageSource` describes user intent, not the final disk that the virtual
/// machine boots. `MachineBuilder::create` materializes this source immediately
/// into a machine-local root disk. Later `Machine::start` calls only boot that
/// already-created disk and never pull or re-resolve images.
///
/// Strings passed to `MachineBuilder::image` resolve like `silo create`: a
/// local image name, a cached reference, a unique id prefix, then a pull
/// (short references expand via `search_registries`; a Silo image artifact
/// becomes a stored image). Local paths are intentionally explicit:
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
    /// Resolve a reference: local name, cached or pullable OCI reference,
    /// Silo image artifact or unique id prefix.
    Oci(String),
    /// Import a quiesced caller-owned disk with explicit boot metadata.
    Disk(import_types::DiskImportRequest),
    /// Use an existing local image (stored or cached OCI) without pulling.
    Stored(import_types::ImageRef),
}

impl ImageSource {
    /// Creates a reference image source.
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
            name: None,
        })
    }
}

/// Stable source kind recorded for a materialized machine image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSourceKind {
    /// The machine was created from a cached OCI image.
    Oci,
    /// The machine was created from a caller-owned local disk image.
    Disk,
    /// The machine was created from a stored raw image.
    Stored,
}

impl ImageSourceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Oci => "oci",
            Self::Disk => "disk",
            Self::Stored => "stored",
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

/// When `create`, `run`, `restore` and `image pull` contact a registry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PullPolicy {
    /// Use a local record when present, otherwise pull it.
    #[default]
    IfMissing,
    /// Resolve the reference again and pull; a moved tag moves its name.
    Always,
    /// Use local records only and fail without network access.
    Never,
}

/// Options for explicit `Runtime::images().pull_with` calls.
#[derive(Debug, Clone, Default)]
pub struct ImagePullOptions {
    /// Optional policy override for this operation.
    pub policy: Option<PullPolicy>,
}

/// Options for read-only `Runtime::images().resolve_with` calls.
#[derive(Debug, Clone, Default)]
pub struct ImageResolveOptions {
    /// Optional policy override for this operation.
    pub policy: Option<PullPolicy>,
    /// Requested Linux userspace platform; absence selects the host platform.
    pub platform: Option<crate::LinuxPlatform>,
}

/// Whether the resolved immutable image already has a retained local
/// layered composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageCacheState {
    /// The selected manifest has a retained composition in the local cache.
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

/// A create/pull reference resolved to a source of known family.
pub(crate) enum ResolvedImageReference {
    Oci(Box<ResolvedOciImage>),
    /// A stored image, by the name it matched (or its id) and its id.
    Stored {
        reference: import_types::ImageRef,
        id: crate::ImageId,
    },
}

/// One OCI layer belonging to an image manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Result of pruning unnamed, unused images and unreferenced bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImagePruneReport {
    /// Number of image records removed (cached OCI and stored).
    pub images_removed: u64,
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

    fn store(&self) -> Result<std::sync::Arc<crate::store::Store>, LibVmError> {
        Ok(std::sync::Arc::new(self.runtime.native_store()?))
    }

    /// Pulls or reuses an image reference according to the runtime policy.
    /// See [`Images::pull_with`].
    pub async fn pull(&self, reference: impl Into<String>) -> Result<ImageInfo, LibVmError> {
        self.pull_with(reference, ImagePullOptions::default()).await
    }

    /// Pulls or reuses an image reference. A local name or a locally stored
    /// expansion is reused unless the policy is `Always`. A registry OCI
    /// container image is cached as layers; a Silo image artifact becomes a
    /// stored image; a Silo snapshot artifact is refused before any payload
    /// is fetched (`ArtifactIsSnapshot`). The pulled record gets the canonical
    /// reference as a name, moved from any previous record.
    pub async fn pull_with(
        &self,
        reference: impl Into<String>,
        options: ImagePullOptions,
    ) -> Result<ImageInfo, LibVmError> {
        let reference = reference.into();
        let pull = options.policy.unwrap_or(self.runtime.image_pull_policy());
        let image = match self
            .runtime
            .resolve_image_reference(&reference, None, pull)
            .await?
        {
            ResolvedImageReference::Stored { id, .. } => {
                crate::store::image_store::LocalImage::Stored(id)
            }
            ResolvedImageReference::Oci(resolved) => {
                let image = self
                    .runtime
                    .materialize_resolved_oci_image(&resolved)
                    .await?;
                let id = image
                    .image_id
                    .as_deref()
                    .ok_or_else(|| {
                        crate::machine::root_storage::invalid("pulled OCI image has no id")
                    })?
                    .parse()
                    .map_err(|error: crate::storage::identity::IdentityError| {
                        crate::machine::root_storage::invalid(error.to_string())
                    })?;
                crate::store::image_store::LocalImage::Oci(id)
            }
        };
        let store = self.store()?;
        let mut connection = store.pool.acquire().await?;
        crate::store::image_store::image_info(&mut connection, image, &reference).await
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

    /// Lists every local image: cached OCI images, then stored images.
    pub async fn list(&self) -> Result<Vec<ImageInfo>, LibVmError> {
        let store = self.store()?;
        let mut images = {
            let mut connection = store.pool.acquire().await?;
            crate::store::image_store::list_oci_images(&mut connection)
                .await?
                .into_iter()
                .map(|info| ImageInfo::Oci(Box::new(info)))
                .collect::<Vec<_>>()
        };
        images.extend(
            crate::store::stored_image_store::StoredImageStore::from_store(store.clone())
                .list()
                .await?
                .into_iter()
                .map(|info| ImageInfo::Stored(Box::new(info))),
        );
        order_images(&store.pool, &mut images).await?;
        Ok(images)
    }

    /// Inspects one local image by name, registry reference (expanded via
    /// `search_registries`), id or unique id prefix. Never pulls.
    pub async fn inspect(&self, reference: &ImageRef) -> Result<ImageInfo, LibVmError> {
        let local = self.runtime.resolve_local_image(reference).await?;
        let crate::resolve::LocalRecord::Image(image) = local.record else {
            return Err(LibVmError::SnapshotIsNotAnImage {
                reference: reference.to_string(),
            });
        };
        let store = self.store()?;
        let mut connection = store.pool.acquire().await?;
        crate::store::image_store::image_info(&mut connection, image, &reference.to_string()).await
    }

    /// Docker tag semantics: a name removes that name, and the image once no
    /// name remains; an id (or unique prefix) removes the image and all its
    /// names. Machines created from it are unaffected.
    pub async fn remove(&self, reference: &ImageRef) -> Result<ImageRemoval, LibVmError> {
        let local = self.runtime.resolve_local_image(reference).await?;
        let crate::resolve::LocalRecord::Image(image) = local.record else {
            return Err(LibVmError::SnapshotIsNotAnImage {
                reference: reference.to_string(),
            });
        };
        self.store()?
            .remove_image(image, local.name.as_deref())
            .await
    }

    /// Removes unnamed images no machine or operation uses, then collects
    /// bytes no longer referenced.
    pub async fn prune(&self) -> Result<ImagePruneReport, LibVmError> {
        crate::store::ImageStore::prune_images(self.store()?.as_ref()).await
    }
}

/// The root an image source contributes to a new machine.
pub(crate) enum MaterializedRoot {
    /// Whole authenticated raw disk bytes, copied into the machine.
    Raw {
        size_bytes: u64,
        authenticated: crate::storage::stream::AuthenticatedStream,
    },
    /// An OCI selection's leased exact layered composition; never copied.
    Layered(Box<crate::store::composition_store::HeldComposition>),
}

pub(crate) struct MaterializedImage {
    pub(crate) root: MaterializedRoot,
    pub(crate) requested_reference: String,
    pub(crate) selected_reference: Option<String>,
    pub(crate) source_kind: ImageSourceKind,
    pub(crate) image_id: Option<String>,
    pub(crate) manifest_digest: Option<String>,
    pub(crate) config_digest: Option<String>,
    pub(crate) platform: Platform,
    pub(crate) managed: Option<crate::store::stored_image_store::StoredImageConsumer>,
    pub(crate) _lease: Option<crate::storage::locks::StorageLock>,
}

async fn order_images(pool: &sqlx::SqlitePool, images: &mut [ImageInfo]) -> Result<(), LibVmError> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT id,created_at FROM storage_image UNION ALL SELECT image_id,created_at FROM image_composition_artifact",
    ).fetch_all(pool).await?;
    let created = rows
        .into_iter()
        .map(|(id, time)| id.parse::<crate::ImageId>().map(|id| (id, time)))
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()
        .map_err(crate::storage::StorageError::from)?;
    images.sort_unstable_by(|left, right| {
        created
            .get(&right.id())
            .cmp(&created.get(&left.id()))
            .then_with(|| left.names().cmp(right.names()))
            .then_with(|| left.id().cmp(&right.id()))
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn image_list_orders_real_store_creation_times_then_names() {
        let (temporary, images, mut record, operation, lease) =
            crate::store::stored_image_store::tests::fixture().await;
        let store = crate::store::Store::open(&temporary.path().join("home/state.db"))
            .await
            .unwrap();
        let first = images
            .publish_owned(
                record.clone(),
                operation,
                lease,
                Some("old".into()),
                Vec::new(),
                None,
            )
            .await
            .unwrap();
        let mut listed = vec![crate::ImageInfo::Stored(Box::new(first))];
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        for name in ["z", "a"] {
            record.process.command = Some(vec![name.into()]);
            let (streams, objects) = record.content_dependencies().unwrap();
            let (operation, lease) = store
                .begin_stopped_operation(
                    "import",
                    &streams.into_iter().collect::<Vec<_>>(),
                    &objects.into_iter().collect::<Vec<_>>(),
                )
                .await
                .unwrap();
            crate::storage::pool::StoragePool::open(&temporary.path().join("home/images"))
                .unwrap()
                .create_operation_with_lease(operation, lease.duplicate().unwrap())
                .unwrap();
            let info = images
                .publish_owned(
                    record.clone(),
                    operation,
                    lease,
                    Some(name.into()),
                    Vec::new(),
                    None,
                )
                .await
                .unwrap();
            listed.push(crate::ImageInfo::Stored(Box::new(info)));
        }
        crate::image::order_images(store.test_pool(), &mut listed)
            .await
            .unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|image| image.names()[0].as_str())
                .collect::<Vec<_>>(),
            ["a", "z", "old"]
        );
    }
}
