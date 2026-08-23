use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use containerregistry_image::MediaType;
use flate2::read::GzDecoder;
use futures_util::{stream, StreamExt, TryStreamExt};
use oci_client::client::{BlobResponse, SizedStream};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::digest::Sha256Digest;
use crate::ext4_writer::Ext4Writer;
use crate::layer::apply_layer;
use crate::lock::FileLock;
use crate::progress::{ProgressEvent, ProgressReporter};
use crate::registry::{ImageConfig, RegistryClient, ResolvedImage, ResolvedLayer};
use crate::{OciError, OciResult, Platform};

const BLOBS_DIR_NAME: &str = "blobs";
const METADATA_VERSION: u32 = 2;
const DEFAULT_ROOTFS_SIZE_BYTES: u64 = 512 * 1024 * 1024;
const INDEX_FILE_NAME: &str = "index.json";
const INDEX_VERSION: u32 = 1;
const MANIFESTS_DIR_NAME: &str = "manifests";
const METADATA_FILE_NAME: &str = "metadata.json";
const PROGRESS_STEP_BYTES: u64 = 256 * 1024;
const ROOTFS_FILE_NAME: &str = "rootfs.img";
const ROOTFS_FILESYSTEM: &str = "ext4";
const STAGING_DIR_NAME: &str = ".staging";
const TMP_DIR_NAME: &str = "tmp";

#[derive(Debug, Clone)]
pub struct MaterializeOptions {
    pub platform: Platform,
    pub materialization: Materialization,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Materialization {
    FlatExt4 { size_bytes: u64 },
}

impl MaterializeOptions {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            materialization: Materialization::FlatExt4 {
                size_bytes: DEFAULT_ROOTFS_SIZE_BYTES,
            },
        }
    }

    pub fn for_host() -> OciResult<Self> {
        Ok(Self::new(Platform::host()?))
    }

    pub fn with_flat_ext4_size_bytes(mut self, size_bytes: u64) -> Self {
        self.materialization = Materialization::FlatExt4 { size_bytes };
        self
    }
}

#[derive(Debug, Clone)]
pub struct FlatExt4Artifact {
    pub path: PathBuf,
    pub requested_reference: String,
    pub image_id: String,
    pub manifest_digest: String,
    pub platform: Platform,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PublishedRootfs {
    FlatExt4(FlatExt4Artifact),
}

impl PublishedRootfs {
    pub fn flat_ext4(&self) -> &FlatExt4Artifact {
        match self {
            Self::FlatExt4(artifact) => artifact,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StoredRootfsImageSource {
    OciRegistry,
    Disk,
}

#[derive(Debug, Clone)]
pub struct ImageStore {
    root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreIndex {
    version: u32,
    #[serde(default)]
    tags: BTreeMap<String, TagRecord>,
}

impl Default for StoreIndex {
    fn default() -> Self {
        Self {
            version: INDEX_VERSION,
            tags: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TagRecord {
    image_ref: String,
    platform: Platform,
    manifest_digest: String,
    updated_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootfsMetadata {
    pub version: u32,
    pub image_ref: String,
    pub image_id: String,
    pub requested_reference: String,
    pub selected_reference: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub config: ImageConfig,
    pub layers: Vec<RootfsLayerMetadata>,
    pub platform: Platform,
    pub filesystem: String,
    pub rootfs_file: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRootfsImageMetadata {
    version: u32,
    image_ref: String,
    image_id: String,
    source: StoredRootfsImageSource,
    requested_reference: String,
    selected_reference: String,
    manifest_digest: String,
    config_digest: String,
    config: ImageConfig,
    layers: Vec<RootfsLayerMetadata>,
    platform: Platform,
    filesystem: String,
    rootfs_file: String,
    created_at_unix: i64,
}

impl From<StoredRootfsImageMetadata> for RootfsMetadata {
    fn from(metadata: StoredRootfsImageMetadata) -> Self {
        Self {
            version: metadata.version,
            image_ref: metadata.image_ref,
            image_id: metadata.image_id,
            requested_reference: metadata.requested_reference,
            selected_reference: metadata.selected_reference,
            manifest_digest: metadata.manifest_digest,
            config_digest: metadata.config_digest,
            config: metadata.config,
            layers: metadata.layers,
            platform: metadata.platform,
            filesystem: metadata.filesystem,
            rootfs_file: metadata.rootfs_file,
            created_at_unix: metadata.created_at_unix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootfsLayerMetadata {
    #[serde(rename = "digest")]
    pub blob_digest: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub diff_id: String,
}

type ImageMetadata = StoredRootfsImageMetadata;
type ImageLayerMetadata = RootfsLayerMetadata;

impl From<&ResolvedLayer> for RootfsLayerMetadata {
    fn from(layer: &ResolvedLayer) -> Self {
        Self {
            blob_digest: layer.digest.clone(),
            media_type: layer.media_type.clone(),
            size_bytes: layer.size_bytes,
            diff_id: layer.diff_id.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestMetadata {
    version: u32,
    requested_reference: String,
    selected_reference: String,
    manifest_digest: String,
    config_digest: String,
    config: ImageConfig,
    platform: Platform,
    layers: Vec<ImageLayerMetadata>,
    resolved_at_unix: i64,
}

struct LayerBlob {
    index: usize,
    layer: ResolvedLayer,
    path: PathBuf,
}

struct LayerDownloadRequest<'a> {
    registry: &'a RegistryClient,
    reference: &'a oci_client::Reference,
    image_ref: &'a str,
    layer: &'a ResolvedLayer,
    index: usize,
    total: usize,
    progress: Option<&'a ProgressReporter>,
}

struct ImageMetadataInput<'a> {
    resolved: &'a ResolvedImage,
}

struct LayerStreamWrite<'a> {
    path: &'a Path,
    stream: SizedStream,
    append: bool,
    start_offset: u64,
    layer: &'a ResolvedLayer,
    index: usize,
    total: usize,
    progress: Option<&'a ProgressReporter>,
}

impl ImageStore {
    pub fn open(root: impl AsRef<Path>) -> OciResult<Self> {
        Ok(Self {
            root: root.as_ref().to_path_buf(),
        })
    }

    /// Resolves an OCI registry reference to the selected platform without writing to the store.
    pub async fn resolve(
        &self,
        image_ref: &str,
        platform: &Platform,
        progress: Option<ProgressReporter>,
    ) -> OciResult<ResolvedImage> {
        self.resolve_remote_oci(image_ref, platform, progress.as_ref())
            .await
    }

    /// Materializes a previously resolved OCI image into the local rootfs cache.
    pub async fn materialize(
        &self,
        resolved: &ResolvedImage,
        options: &MaterializeOptions,
        progress: Option<ProgressReporter>,
    ) -> OciResult<PublishedRootfs> {
        if resolved.platform != options.platform {
            return Err(OciError::PlatformMismatch {
                reference: resolved.requested_reference.clone(),
                requested: options.platform.to_string(),
                actual: resolved.platform.to_string(),
            });
        }
        let registry = RegistryClient::new()?;
        registry
            .authenticate_pull(&resolved.reference, &resolved.requested_reference)
            .await?;
        self.materialize_resolved_oci(&registry, resolved, options, progress.as_ref())
            .await
    }

    /// Pulls or reuses an OCI registry reference.
    pub async fn get_or_create(
        &self,
        image_ref: &str,
        options: &MaterializeOptions,
        progress: Option<ProgressReporter>,
    ) -> OciResult<PublishedRootfs> {
        self.get_or_create_remote_oci(image_ref, options, progress.as_ref())
            .await
    }

    /// Returns a cached OCI registry reference.
    pub fn get_cached(
        &self,
        image_ref: &str,
        options: &MaterializeOptions,
    ) -> OciResult<Option<PublishedRootfs>> {
        self.cached_remote_oci(image_ref, options)
    }

    /// Removes the mutable tag mapping for an OCI reference without deleting its artifact.
    /// Digest-pinned references have no mutable mapping and return `false`.
    pub fn remove_reference(&self, image_ref: &str, platform: &Platform) -> OciResult<bool> {
        let reference = RegistryClient::parse_reference(image_ref)?;
        if reference.digest().is_some() {
            return Ok(false);
        }

        let canonical_ref = reference.to_string();
        let _index_lock = FileLock::exclusive(&self.index_lock_path())?;
        let mut index = self.read_index()?;
        let removed = index
            .tags
            .remove(&tag_key(&canonical_ref, platform))
            .is_some();
        if removed {
            self.write_index(&index)?;
        }
        Ok(removed)
    }

    pub fn metadata(&self, image: &PublishedRootfs) -> OciResult<RootfsMetadata> {
        let image = image.flat_ext4();
        let Some(dir) = image.path.parent() else {
            return Err(OciError::CorruptCacheEntry {
                path: image.path.clone(),
                reason: "rootfs path has no parent directory".to_string(),
            });
        };

        Ok(read_metadata(&dir.join(METADATA_FILE_NAME))?.into())
    }

    async fn get_or_create_remote_oci(
        &self,
        image_ref: &str,
        options: &MaterializeOptions,
        progress: Option<&ProgressReporter>,
    ) -> OciResult<PublishedRootfs> {
        let resolved = self
            .resolve_remote_oci(image_ref, &options.platform, progress)
            .await?;
        self.materialize(&resolved, options, progress.cloned())
            .await
    }

    async fn resolve_remote_oci(
        &self,
        image_ref: &str,
        platform: &Platform,
        progress: Option<&ProgressReporter>,
    ) -> OciResult<ResolvedImage> {
        let reference = RegistryClient::parse_reference(image_ref)?;
        let canonical_ref = reference.to_string();
        emit_progress(
            progress,
            ProgressEvent::ResolvingManifest {
                image_ref: canonical_ref.clone(),
            },
        );
        let resolved = RegistryClient::new()?
            .resolve_manifest(&reference, platform)
            .await?;
        emit_progress(
            progress,
            ProgressEvent::ResolvedManifest {
                image_ref: canonical_ref,
                manifest_digest: resolved.manifest_digest.clone(),
                layer_count: resolved.layers.len(),
                total_download_bytes: total_download_bytes(&resolved.layers),
            },
        );
        Ok(resolved)
    }

    async fn materialize_resolved_oci(
        &self,
        registry: &RegistryClient,
        resolved: &ResolvedImage,
        options: &MaterializeOptions,
        progress: Option<&ProgressReporter>,
    ) -> OciResult<PublishedRootfs> {
        fs::create_dir_all(&self.root)?;
        let maps_to_tag = RegistryClient::parse_reference(&resolved.requested_reference)?
            .digest()
            .is_none();
        let image_ref = &resolved.requested_reference;

        let _image_lock = FileLock::exclusive(
            &self.image_lock_path(&resolved.manifest_digest, &options.platform)?,
        )?;
        self.write_manifest_metadata(resolved)?;

        emit_progress(
            progress,
            ProgressEvent::CheckingCache {
                image_ref: image_ref.to_string(),
            },
        );
        if let Some(image) =
            self.cached_image(image_ref, &resolved.manifest_digest, &options.platform)?
        {
            emit_progress(
                progress,
                ProgressEvent::CacheHit {
                    image_ref: image_ref.to_string(),
                },
            );
            if maps_to_tag {
                self.update_tag_mapping(image_ref, &options.platform, &resolved.manifest_digest)?;
            }
            return Ok(image);
        }
        emit_progress(
            progress,
            ProgressEvent::CacheMiss {
                image_ref: image_ref.to_string(),
            },
        );

        let image = self
            .create_rootfs(registry, image_ref, resolved, options, progress)
            .await?;
        if maps_to_tag {
            self.update_tag_mapping(image_ref, &options.platform, &resolved.manifest_digest)?;
        }
        Ok(image)
    }

    fn cached_remote_oci(
        &self,
        image_ref: &str,
        options: &MaterializeOptions,
    ) -> OciResult<Option<PublishedRootfs>> {
        let reference = RegistryClient::parse_reference(image_ref)?;
        let canonical_ref = reference.to_string();
        let Some(digest) = reference.digest() else {
            let index = self.read_index()?;
            let Some(tag) = index.tags.get(&tag_key(&canonical_ref, &options.platform)) else {
                return Ok(None);
            };
            return self.cached_image(&canonical_ref, &tag.manifest_digest, &options.platform);
        };

        self.cached_image(&canonical_ref, digest, &options.platform)
    }

    async fn create_rootfs(
        &self,
        registry: &RegistryClient,
        image_ref: &str,
        resolved: &ResolvedImage,
        options: &MaterializeOptions,
        progress: Option<&ProgressReporter>,
    ) -> OciResult<PublishedRootfs> {
        let image_id = &resolved.manifest_digest;
        let final_dir = self.image_dir(image_id, &options.platform)?;
        if final_dir.exists() {
            if let Some(image) = self.cached_image(image_ref, image_id, &options.platform)? {
                emit_progress(
                    progress,
                    ProgressEvent::CacheHit {
                        image_ref: image_ref.to_string(),
                    },
                );
                return Ok(image);
            }
        }

        let blobs = self
            .ensure_layer_blobs(registry, image_ref, resolved, progress)
            .await?;
        let staging = StagingDir::create(&self.root)?;
        let stage_rootfs = staging.path().join(ROOTFS_FILE_NAME);
        let Materialization::FlatExt4 { size_bytes } = options.materialization;
        let mut writer = Ext4Writer::create(&stage_rootfs, size_bytes)?;

        let total = blobs.len();
        for blob in &blobs {
            emit_progress(
                progress,
                ProgressEvent::ApplyingLayer {
                    index: blob.index,
                    total,
                    digest: Some(blob.layer.digest.clone()),
                },
            );
            let reader = layer_reader_from_path(&blob.layer.media_type, &blob.path)?;
            apply_layer(reader, &mut writer)?;
        }

        emit_progress(progress, ProgressEvent::MaterializingRootfs);
        writer.finish()?;
        emit_progress(progress, ProgressEvent::PublishingRootfs);
        self.write_metadata(staging.path(), ImageMetadataInput { resolved })?;

        if let Some(parent) = final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        if final_dir.exists() {
            if let Some(image) = self.cached_image(image_ref, image_id, &options.platform)? {
                emit_progress(
                    progress,
                    ProgressEvent::CacheHit {
                        image_ref: image_ref.to_string(),
                    },
                );
                return Ok(image);
            }
        }
        fs::rename(staging.path(), &final_dir)?;
        staging.disarm();

        Ok(PublishedRootfs::FlatExt4(FlatExt4Artifact {
            path: final_dir.join(ROOTFS_FILE_NAME),
            requested_reference: image_ref.to_string(),
            image_id: image_id.to_string(),
            manifest_digest: resolved.manifest_digest.clone(),
            platform: options.platform.clone(),
        }))
    }

    async fn ensure_layer_blobs(
        &self,
        registry: &RegistryClient,
        image_ref: &str,
        resolved: &ResolvedImage,
        progress: Option<&ProgressReporter>,
    ) -> OciResult<Vec<LayerBlob>> {
        let total = resolved.layers.len();
        let concurrency = layer_download_concurrency(total);
        let progress = progress.cloned();
        let reference = &resolved.reference;

        let mut downloads = stream::iter(resolved.layers.iter().cloned().enumerate())
            .map(|(index, layer)| {
                let progress = progress.clone();
                async move {
                    let layer_index = index + 1;
                    let path = self
                        .get_or_download_layer(LayerDownloadRequest {
                            registry,
                            reference,
                            image_ref,
                            layer: &layer,
                            index: layer_index,
                            total,
                            progress: progress.as_ref(),
                        })
                        .await?;
                    Ok::<_, OciError>(LayerBlob {
                        index: layer_index,
                        layer,
                        path,
                    })
                }
            })
            .buffer_unordered(concurrency);

        let mut blobs = Vec::with_capacity(total);
        while let Some(blob) = downloads.next().await {
            blobs.push(blob?);
        }
        blobs.sort_by_key(|blob| blob.index);
        Ok(blobs)
    }

    async fn get_or_download_layer(&self, request: LayerDownloadRequest<'_>) -> OciResult<PathBuf> {
        let LayerDownloadRequest {
            registry,
            reference,
            image_ref,
            layer,
            index,
            total,
            progress,
        } = request;
        let blob_path = self.blob_path(&layer.digest)?;
        let part_path = self.blob_part_path(&layer.digest)?;
        let _lock = FileLock::exclusive(&self.blob_lock_path(&layer.digest)?)?;

        if verified_blob_exists(&blob_path, &layer.digest)? {
            emit_progress(
                progress,
                ProgressEvent::LayerDownloadSkipped {
                    index,
                    total,
                    digest: layer.digest.clone(),
                },
            );
            return Ok(blob_path);
        }
        remove_file_if_exists(&blob_path)?;

        if let Some(parent) = blob_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = part_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut offset = partial_download_offset(&part_path, layer)?;
        if offset == layer.size_bytes && layer_digest_matches(&part_path, &layer.digest)? {
            emit_progress(
                progress,
                ProgressEvent::LayerDownloadVerifying {
                    index,
                    total,
                    digest: layer.digest.clone(),
                },
            );
            promote_layer_part(&part_path, &blob_path)?;
            emit_progress(
                progress,
                ProgressEvent::LayerDownloadFinished {
                    index,
                    total,
                    digest: layer.digest.clone(),
                },
            );
            return Ok(blob_path);
        }
        if offset == layer.size_bytes {
            remove_file_if_exists(&part_path)?;
            offset = 0;
        }

        emit_progress(
            progress,
            ProgressEvent::LayerDownloadStarted {
                index,
                total,
                digest: layer.digest.clone(),
                size_bytes: Some(layer.size_bytes),
            },
        );
        if offset > 0 {
            emit_progress(
                progress,
                ProgressEvent::LayerDownloadProgress {
                    index,
                    total,
                    digest: layer.digest.clone(),
                    downloaded_bytes: offset,
                    size_bytes: Some(layer.size_bytes),
                },
            );
        }

        let (stream, append, start_offset) = if offset > 0 {
            match registry
                .pull_layer_stream_partial(
                    reference,
                    layer,
                    image_ref,
                    offset,
                    Some(layer.size_bytes.saturating_sub(offset)),
                )
                .await?
            {
                BlobResponse::Partial(stream) => (stream, true, offset),
                BlobResponse::Full(stream) => {
                    remove_file_if_exists(&part_path)?;
                    (stream, false, 0)
                }
            }
        } else {
            (
                registry
                    .pull_layer_stream(reference, layer, image_ref)
                    .await?,
                false,
                0,
            )
        };

        write_layer_stream(LayerStreamWrite {
            path: &part_path,
            stream,
            append,
            start_offset,
            layer,
            index,
            total,
            progress,
        })
        .await?;
        emit_progress(
            progress,
            ProgressEvent::LayerDownloadVerifying {
                index,
                total,
                digest: layer.digest.clone(),
            },
        );
        verify_layer_file(&part_path, layer)?;
        promote_layer_part(&part_path, &blob_path)?;
        emit_progress(
            progress,
            ProgressEvent::LayerDownloadFinished {
                index,
                total,
                digest: layer.digest.clone(),
            },
        );
        Ok(blob_path)
    }

    fn cached_image(
        &self,
        image_ref: &str,
        image_id: &str,
        platform: &Platform,
    ) -> OciResult<Option<PublishedRootfs>> {
        let dir = self.image_dir(image_id, platform)?;
        if !dir.exists() {
            return Ok(None);
        }

        let rootfs_path = dir.join(ROOTFS_FILE_NAME);
        if !rootfs_path.is_file() {
            return Err(OciError::CorruptCacheEntry {
                path: dir,
                reason: format!("missing {ROOTFS_FILE_NAME}"),
            });
        }

        let metadata_path = dir.join(METADATA_FILE_NAME);
        let metadata = read_metadata(&metadata_path)?;
        if metadata.version != METADATA_VERSION {
            return Err(OciError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata version {} does not match expected version {METADATA_VERSION}",
                    metadata.version
                ),
            });
        }
        if metadata.image_id != image_id {
            return Err(OciError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata image id {} does not match cache image id {image_id}",
                    metadata.image_id
                ),
            });
        }
        if metadata.manifest_digest != image_id {
            return Err(OciError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata manifest digest {} does not match cache image id {image_id}",
                    metadata.manifest_digest
                ),
            });
        }
        if metadata.source != StoredRootfsImageSource::OciRegistry {
            return Err(OciError::CorruptCacheEntry {
                path: metadata_path,
                reason: "metadata source is not oci-registry".to_string(),
            });
        }
        if metadata.platform != *platform {
            return Err(OciError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata platform {} does not match cache platform {platform}",
                    metadata.platform
                ),
            });
        }
        if metadata.filesystem != ROOTFS_FILESYSTEM {
            return Err(OciError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata filesystem {} does not match expected {ROOTFS_FILESYSTEM}",
                    metadata.filesystem
                ),
            });
        }
        if metadata.rootfs_file != ROOTFS_FILE_NAME {
            return Err(OciError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!("metadata rootfs file is {}", metadata.rootfs_file),
            });
        }
        Ok(Some(PublishedRootfs::FlatExt4(FlatExt4Artifact {
            path: rootfs_path,
            requested_reference: image_ref.to_string(),
            image_id: image_id.to_string(),
            manifest_digest: metadata.manifest_digest,
            platform: platform.clone(),
        })))
    }

    fn image_dir(&self, image_id: &str, platform: &Platform) -> OciResult<PathBuf> {
        Ok(self
            .root
            .join(image_id_path_component(image_id)?)
            .join(platform.cache_key()))
    }

    fn image_lock_path(&self, image_id: &str, platform: &Platform) -> OciResult<PathBuf> {
        Ok(self.root.join(TMP_DIR_NAME).join(format!(
            "image-{}-{}.lock",
            image_id_path_component(image_id)?,
            platform.cache_key()
        )))
    }

    fn index_lock_path(&self) -> PathBuf {
        self.root.join(TMP_DIR_NAME).join("index.lock")
    }

    fn blob_path(&self, digest: &str) -> OciResult<PathBuf> {
        let (algorithm, encoded) = digest_path_components(digest)?;
        Ok(self.root.join(BLOBS_DIR_NAME).join(algorithm).join(encoded))
    }

    fn blob_part_path(&self, digest: &str) -> OciResult<PathBuf> {
        let (algorithm, encoded) = digest_path_components(digest)?;
        Ok(self
            .root
            .join(TMP_DIR_NAME)
            .join(format!("{}-{}.part", algorithm, encoded)))
    }

    fn blob_lock_path(&self, digest: &str) -> OciResult<PathBuf> {
        let (algorithm, encoded) = digest_path_components(digest)?;
        Ok(self
            .root
            .join(TMP_DIR_NAME)
            .join(format!("{}-{}.download.lock", algorithm, encoded)))
    }

    fn manifest_dir(&self, manifest_digest: &str) -> OciResult<PathBuf> {
        Ok(self
            .root
            .join(MANIFESTS_DIR_NAME)
            .join(image_id_path_component(manifest_digest)?))
    }

    fn write_metadata(&self, dir: &Path, input: ImageMetadataInput<'_>) -> OciResult<()> {
        let resolved = input.resolved;
        let metadata = ImageMetadata {
            version: METADATA_VERSION,
            image_ref: resolved.requested_reference.clone(),
            image_id: resolved.manifest_digest.clone(),
            source: StoredRootfsImageSource::OciRegistry,
            requested_reference: resolved.requested_reference.clone(),
            selected_reference: resolved.selected_reference.clone(),
            manifest_digest: resolved.manifest_digest.clone(),
            config_digest: resolved.config_digest.clone(),
            config: resolved.config.clone(),
            layers: resolved
                .layers
                .iter()
                .map(ImageLayerMetadata::from)
                .collect(),
            platform: resolved.platform.clone(),
            filesystem: ROOTFS_FILESYSTEM.to_string(),
            rootfs_file: ROOTFS_FILE_NAME.to_string(),
            created_at_unix: now_unix(),
        };
        let data = serde_json::to_vec_pretty(&metadata)?;
        fs::write(dir.join(METADATA_FILE_NAME), data)?;
        Ok(())
    }

    fn write_manifest_metadata(&self, resolved: &ResolvedImage) -> OciResult<()> {
        let dir = self.manifest_dir(&resolved.manifest_digest)?;
        fs::create_dir_all(&dir)?;
        let metadata = ManifestMetadata {
            version: METADATA_VERSION,
            requested_reference: resolved.requested_reference.clone(),
            selected_reference: resolved.selected_reference.clone(),
            manifest_digest: resolved.manifest_digest.clone(),
            config_digest: resolved.config_digest.clone(),
            config: resolved.config.clone(),
            platform: resolved.platform.clone(),
            layers: resolved
                .layers
                .iter()
                .map(ImageLayerMetadata::from)
                .collect(),
            resolved_at_unix: now_unix(),
        };
        let path = dir.join(METADATA_FILE_NAME);
        write_json_atomically(&path, &metadata)
    }

    fn update_tag_mapping(
        &self,
        image_ref: &str,
        platform: &Platform,
        manifest_digest: &str,
    ) -> OciResult<()> {
        let _index_lock = FileLock::exclusive(&self.index_lock_path())?;
        let mut index = self.read_index()?;
        index.tags.insert(
            tag_key(image_ref, platform),
            TagRecord {
                image_ref: image_ref.to_string(),
                platform: platform.clone(),
                manifest_digest: manifest_digest.to_string(),
                updated_at_unix: now_unix(),
            },
        );
        self.write_index(&index)
    }

    fn read_index(&self) -> OciResult<StoreIndex> {
        let path = self.root.join(INDEX_FILE_NAME);
        match fs::read(&path) {
            Ok(data) => {
                let index = serde_json::from_slice::<StoreIndex>(&data).map_err(|err| {
                    OciError::CorruptCacheEntry {
                        path: path.clone(),
                        reason: err.to_string(),
                    }
                })?;
                if index.version != INDEX_VERSION {
                    return Err(OciError::CorruptCacheEntry {
                        path,
                        reason: format!(
                            "index version {} does not match expected version {INDEX_VERSION}",
                            index.version
                        ),
                    });
                }
                Ok(index)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(StoreIndex::default()),
            Err(err) => Err(err.into()),
        }
    }

    fn write_index(&self, index: &StoreIndex) -> OciResult<()> {
        fs::create_dir_all(&self.root)?;
        let path = self.root.join(INDEX_FILE_NAME);
        write_json_atomically(&path, index)
    }
}

fn write_json_atomically(path: &Path, value: &impl Serialize) -> OciResult<()> {
    let data = serde_json::to_vec_pretty(value)?;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::other(format!(
            "cache metadata path {} has no parent",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::other(format!(
            "cache metadata path {} has no file name",
            path.display()
        ))
    })?;

    for attempt in 0..1024_u32 {
        let temp_path = parent.join(format!(
            ".{}.{}-{}-{attempt}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            now_unix_nanos()
        ));
        let mut file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };
        let write_result = (|| -> std::io::Result<()> {
            file.write_all(&data)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, path)
        })();
        if let Err(err) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(err.into());
        }
        return Ok(());
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "could not create an owned cache temporary file for {}",
            path.display()
        ),
    )
    .into())
}

fn emit_progress(progress: Option<&ProgressReporter>, event: ProgressEvent) {
    if let Some(progress) = progress {
        progress.report(event);
    }
}

fn total_download_bytes(layers: &[ResolvedLayer]) -> Option<u64> {
    layers
        .iter()
        .try_fold(0_u64, |total, layer| total.checked_add(layer.size_bytes))
}

fn layer_download_concurrency(layer_count: usize) -> usize {
    if layer_count == 0 {
        return 1;
    }
    let host_limit = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .saturating_mul(2)
        .clamp(4, 16);
    layer_count.min(host_limit)
}

async fn write_layer_stream(request: LayerStreamWrite<'_>) -> OciResult<()> {
    let LayerStreamWrite {
        path,
        mut stream,
        append,
        start_offset,
        layer,
        index,
        total,
        progress,
    } = request;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(path)
        .await?;
    let mut downloaded = start_offset;
    let mut last_progress = start_offset;

    while let Some(chunk) = stream.try_next().await? {
        file.write_all(&chunk).await?;
        downloaded = downloaded.saturating_add(chunk.len() as u64);
        if downloaded.saturating_sub(last_progress) >= PROGRESS_STEP_BYTES
            || downloaded >= layer.size_bytes
        {
            emit_progress(
                progress,
                ProgressEvent::LayerDownloadProgress {
                    index,
                    total,
                    digest: layer.digest.clone(),
                    downloaded_bytes: downloaded,
                    size_bytes: Some(layer.size_bytes),
                },
            );
            last_progress = downloaded;
        }
    }
    file.flush().await?;
    drop(file);

    let actual = fs::metadata(path)?.len();
    if actual != layer.size_bytes {
        remove_file_if_exists(path)?;
        return Err(OciError::LayerSizeMismatch {
            digest: layer.digest.clone(),
            path: path.to_path_buf(),
            expected: layer.size_bytes,
            actual,
        });
    }
    Ok(())
}

fn partial_download_offset(path: &Path, layer: &ResolvedLayer) -> OciResult<u64> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err.into()),
    };

    let size = metadata.len();
    if size > layer.size_bytes {
        remove_file_if_exists(path)?;
        return Ok(0);
    }
    Ok(size)
}

fn verified_blob_exists(path: &Path, digest: &str) -> OciResult<bool> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    if !metadata.is_file() {
        remove_file_if_exists(path)?;
        return Ok(false);
    }
    if layer_digest_matches(path, digest)? {
        return Ok(true);
    }
    remove_file_if_exists(path)?;
    Ok(false)
}

fn verify_layer_file(path: &Path, layer: &ResolvedLayer) -> OciResult<()> {
    let actual_size = fs::metadata(path)?.len();
    if actual_size != layer.size_bytes {
        remove_file_if_exists(path)?;
        return Err(OciError::LayerSizeMismatch {
            digest: layer.digest.clone(),
            path: path.to_path_buf(),
            expected: layer.size_bytes,
            actual: actual_size,
        });
    }

    let actual_digest = sha256_file(path)?;
    let expected_digest = Sha256Digest::parse(&layer.digest)?;
    if actual_digest != expected_digest {
        remove_file_if_exists(path)?;
        return Err(OciError::LayerDigestMismatch {
            digest: layer.digest.clone(),
            path: path.to_path_buf(),
            actual: actual_digest.hex(),
        });
    }
    Ok(())
}

fn layer_digest_matches(path: &Path, digest: &str) -> OciResult<bool> {
    let actual_digest = sha256_file(path)?;
    let expected_digest = Sha256Digest::parse(digest)?;
    Ok(actual_digest == expected_digest)
}

fn promote_layer_part(part_path: &Path, blob_path: &Path) -> OciResult<()> {
    if let Some(parent) = blob_path.parent() {
        fs::create_dir_all(parent)?;
    }
    remove_file_if_exists(blob_path)?;
    fs::rename(part_path, blob_path)?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> OciResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn read_metadata(path: &Path) -> OciResult<ImageMetadata> {
    let data = fs::read(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            OciError::CorruptCacheEntry {
                path: path.to_path_buf(),
                reason: "metadata file is missing".to_string(),
            }
        } else {
            OciError::Io(err)
        }
    })?;
    serde_json::from_slice(&data).map_err(|err| OciError::CorruptCacheEntry {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn layer_reader_from_path(media_type: &str, path: &Path) -> OciResult<Box<dyn Read>> {
    let media_type =
        MediaType::from_str(media_type).map_err(|err| OciError::UnsupportedLayerMediaType {
            media_type: format!("{media_type}: {err}"),
        })?;
    let file = fs::File::open(path)?;
    layer_reader_from_read(&media_type, BufReader::new(file))
}

fn layer_reader_from_read(
    media_type: &MediaType,
    reader: impl Read + 'static,
) -> OciResult<Box<dyn Read>> {
    match media_type {
        MediaType::OciLayer | MediaType::OciLayerNondistributable => Ok(Box::new(reader)),
        MediaType::OciLayerGzip
        | MediaType::DockerLayerGzip
        | MediaType::OciLayerNondistributableGzip => Ok(Box::new(GzDecoder::new(reader))),
        MediaType::OciLayerZstd | MediaType::OciLayerNondistributableZstd => {
            Ok(Box::new(zstd::Decoder::new(reader)?))
        }
        MediaType::Other(value) if value == "application/vnd.docker.image.rootfs.diff.tar" => {
            Ok(Box::new(reader))
        }
        other => Err(OciError::UnsupportedLayerMediaType {
            media_type: other.as_str().to_string(),
        }),
    }
}

fn digest_path_components(digest: &str) -> OciResult<(&'static str, String)> {
    Ok(("sha256", Sha256Digest::parse(digest)?.hex()))
}

fn sha256_file(path: &Path) -> OciResult<Sha256Digest> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Sha256Digest::from_hash(hasher.finalize().into()))
}

#[cfg(test)]
fn sha256_bytes(bytes: &[u8]) -> String {
    Sha256Digest::from_bytes(bytes).hex()
}

fn image_id_path_component(image_id: &str) -> OciResult<String> {
    let (algorithm, encoded) = Sha256Digest::cache_components(image_id)?;
    Ok(format!("{algorithm}-{encoded}"))
}

fn tag_key(image_ref: &str, platform: &Platform) -> String {
    format!("{}|{}", image_ref, platform.cache_key())
}

fn now_unix() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    seconds.min(i64::MAX as u64) as i64
}

struct StagingDir {
    path: PathBuf,
    armed: bool,
}

impl StagingDir {
    fn create(root: &Path) -> OciResult<Self> {
        let parent = root.join(STAGING_DIR_NAME);
        fs::create_dir_all(&parent)?;
        let path = parent.join(format!("{}-{}", std::process::id(), now_unix_nanos()));
        fs::create_dir(&path)?;
        Ok(Self { path, armed: true })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::sync::{Arc, Barrier};

    use crate::registry::ResolvedLayer;
    use crate::store::{
        digest_path_components, image_id_path_component, layer_download_concurrency,
        layer_reader_from_path, sha256_bytes, tag_key, verify_layer_file, ImageMetadata,
        ImageStore, MaterializeOptions, StoredRootfsImageSource, INDEX_FILE_NAME,
        METADATA_FILE_NAME, METADATA_VERSION, ROOTFS_FILESYSTEM, ROOTFS_FILE_NAME,
    };
    use crate::{FlatExt4Artifact, ImageConfig, OciError, Platform, PublishedRootfs};

    const HISTORICAL_CACHE_METADATA_V2: &[u8] =
        include_bytes!("../testdata/cache-metadata-v2.json");
    const HISTORICAL_STORE_INDEX_V1: &[u8] = include_bytes!("../testdata/store-index-v1.json");
    const TEST_IMAGE_ID: &str =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn image_id_and_platform_define_cache_path() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let path = store
            .image_dir(TEST_IMAGE_ID, &Platform::linux_amd64())
            .expect("cache path");

        assert_eq!(
            path,
            temp.path()
                .join(format!("sha256-{}/linux-amd64", "d".repeat(64)))
        );
    }

    #[test]
    fn uppercase_image_id_preserves_existing_cache_path_spelling() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let image_id = format!("sha256:{}", "AB".repeat(32));
        let path = store
            .image_dir(&image_id, &Platform::linux_amd64())
            .expect("cache path");

        assert_eq!(
            path,
            temp.path()
                .join(format!("sha256-{}/linux-amd64", "AB".repeat(32)))
        );
    }

    #[test]
    fn validates_existing_cache_metadata() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_arm64();
        let dir = store
            .image_dir(TEST_IMAGE_ID, &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_vec_pretty(&ImageMetadata {
                version: METADATA_VERSION,
                image_ref: "index.docker.io/library/alpine:latest".to_string(),
                image_id: TEST_IMAGE_ID.to_string(),
                source: StoredRootfsImageSource::OciRegistry,
                requested_reference: "index.docker.io/library/alpine:latest".to_string(),
                selected_reference: format!("index.docker.io/library/alpine@{TEST_IMAGE_ID}"),
                manifest_digest: TEST_IMAGE_ID.to_string(),
                config_digest: "sha256:config".to_string(),
                config: ImageConfig {
                    entrypoint: Some(vec!["/bin/init".to_string()]),
                    cmd: Some(Vec::new()),
                    env: Some(vec!["PATH=/usr/bin".to_string()]),
                    working_dir: Some("".to_string()),
                    user: Some("1000".to_string()),
                    labels: Some(Default::default()),
                    stop_signal: Some("SIGTERM".to_string()),
                },
                layers: Vec::new(),
                platform: platform.clone(),
                filesystem: ROOTFS_FILESYSTEM.to_string(),
                rootfs_file: ROOTFS_FILE_NAME.to_string(),
                created_at_unix: 1,
            })
            .expect("serialize metadata"),
        )
        .expect("write metadata");

        let image = store
            .cached_image(
                "index.docker.io/library/alpine:latest",
                TEST_IMAGE_ID,
                &platform,
            )
            .expect("cache validation")
            .expect("cache hit");

        assert!(matches!(
            image,
            PublishedRootfs::FlatExt4(FlatExt4Artifact {
                ref path,
                ref requested_reference,
                ref image_id,
                platform: ref image_platform,
                ..
            }) if path == &dir.join(ROOTFS_FILE_NAME)
                && requested_reference == "index.docker.io/library/alpine:latest"
                && image_id == TEST_IMAGE_ID
                && image_platform == &platform
        ));
        let metadata = store.metadata(&image).expect("read metadata");
        assert_eq!(
            metadata.selected_reference,
            format!("index.docker.io/library/alpine@{TEST_IMAGE_ID}")
        );
        assert_eq!(
            metadata.config.entrypoint,
            Some(vec!["/bin/init".to_string()])
        );
        assert_eq!(metadata.config.cmd, Some(Vec::new()));
        assert_eq!(metadata.config.working_dir.as_deref(), Some(""));
        assert_eq!(metadata.config.labels, Some(Default::default()));
    }

    #[test]
    fn reads_historical_cache_metadata_v2_without_schema_drift() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let image_id = "sha256:4d4f7f6821da902de46af93c73ed48c25e923fae1c762985953269c1b02de8ea";
        let dir = store.image_dir(image_id, &platform).expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"rootfs").expect("write rootfs");
        std::fs::write(dir.join("metadata.json"), HISTORICAL_CACHE_METADATA_V2)
            .expect("write historical metadata");

        let image = store
            .cached_image(
                "registry.example.test/team/demo:stable",
                image_id,
                &platform,
            )
            .expect("read historical cache metadata")
            .expect("cache hit");
        let metadata = store.metadata(&image).expect("read historical metadata");

        assert_eq!(metadata.version, METADATA_VERSION);
        assert_eq!(metadata.image_id, image_id);
        assert_eq!(metadata.config.working_dir.as_deref(), Some("/workspace"));
        assert_eq!(metadata.layers.len(), 1);
        assert_eq!(
            metadata.layers[0].media_type,
            "application/vnd.oci.image.layer.v1.tar+gzip"
        );
    }

    #[test]
    fn private_metadata_source_accepts_the_legacy_disk_value() {
        let mut metadata = serde_json::from_slice::<ImageMetadata>(HISTORICAL_CACHE_METADATA_V2)
            .expect("read historical metadata");
        metadata.source = StoredRootfsImageSource::Disk;
        let stored = serde_json::to_vec(&metadata).expect("serialize historical disk metadata");
        let decoded = serde_json::from_slice::<ImageMetadata>(&stored)
            .expect("read historical disk metadata");

        assert_eq!(decoded.source, StoredRootfsImageSource::Disk);
    }

    #[test]
    fn reads_historical_store_index_v1_without_schema_drift() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        std::fs::write(temp.path().join("index.json"), HISTORICAL_STORE_INDEX_V1)
            .expect("write historical index");

        let index = store.read_index().expect("read historical index");
        let tag = index
            .tags
            .get("registry.example.test/team/demo:stable|linux-amd64")
            .expect("historical tag");

        assert_eq!(index.version, 1);
        assert_eq!(tag.platform, Platform::linux_amd64());
        assert_eq!(
            tag.manifest_digest,
            "sha256:4d4f7f6821da902de46af93c73ed48c25e923fae1c762985953269c1b02de8ea"
        );
    }

    #[test]
    fn historical_index_and_metadata_resolve_as_one_cache_entry() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let options = MaterializeOptions::new(Platform::linux_amd64());
        let image_id = "sha256:4d4f7f6821da902de46af93c73ed48c25e923fae1c762985953269c1b02de8ea";
        let dir = store
            .image_dir(image_id, &options.platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(temp.path().join(INDEX_FILE_NAME), HISTORICAL_STORE_INDEX_V1)
            .expect("write historical index");
        std::fs::write(dir.join(METADATA_FILE_NAME), HISTORICAL_CACHE_METADATA_V2)
            .expect("write historical metadata");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"rootfs").expect("write rootfs");

        let rootfs = store
            .get_cached("registry.example.test/team/demo:stable", &options)
            .expect("read historical cache")
            .expect("historical cache hit");

        assert_eq!(rootfs.flat_ext4().image_id, image_id);
        assert_eq!(
            rootfs.flat_ext4().requested_reference,
            "registry.example.test/team/demo:stable"
        );
    }

    #[test]
    fn layer_readers_decode_supported_media_types_from_files() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let payload = b"layer contents from a real compressed file\n";
        let raw_path = temp.path().join("layer.tar");
        let gzip_path = temp.path().join("layer.tar.gz");
        let zstd_path = temp.path().join("layer.tar.zst");
        std::fs::write(&raw_path, payload).expect("write raw layer");

        let gzip_file = std::fs::File::create(&gzip_path).expect("create gzip layer");
        let mut gzip = flate2::write::GzEncoder::new(gzip_file, flate2::Compression::default());
        std::io::Write::write_all(&mut gzip, payload).expect("compress gzip layer");
        gzip.finish().expect("finish gzip layer");

        let zstd = zstd::stream::encode_all(payload.as_slice(), 0).expect("compress zstd layer");
        std::fs::write(&zstd_path, zstd).expect("write zstd layer");

        for (media_type, path) in [
            ("application/vnd.oci.image.layer.v1.tar", &raw_path),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar",
                &raw_path,
            ),
            ("application/vnd.docker.image.rootfs.diff.tar", &raw_path),
            ("application/vnd.oci.image.layer.v1.tar+gzip", &gzip_path),
            (
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                &gzip_path,
            ),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                &gzip_path,
            ),
            ("application/vnd.oci.image.layer.v1.tar+zstd", &zstd_path),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
                &zstd_path,
            ),
        ] {
            let mut decoded = Vec::new();
            layer_reader_from_path(media_type, path)
                .expect("supported layer media type")
                .read_to_end(&mut decoded)
                .expect("read layer contents");
            assert_eq!(decoded, payload, "{media_type}");
        }
    }

    #[test]
    fn layer_reader_rejects_unsupported_media_type() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("layer.tar");
        std::fs::write(&path, b"layer").expect("write layer");

        let err = match layer_reader_from_path("application/vnd.example.layer.v1.tar", &path) {
            Ok(_) => panic!("unsupported layer media type should fail"),
            Err(err) => err,
        };

        assert!(matches!(err, OciError::UnsupportedLayerMediaType { .. }));
    }

    #[test]
    fn corrupt_cache_metadata_is_reported() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let dir = store
            .image_dir(TEST_IMAGE_ID, &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(dir.join("metadata.json"), b"not json").expect("write metadata");

        let err = store
            .cached_image("alpine:latest", TEST_IMAGE_ID, &platform)
            .expect_err("corrupt metadata should fail");

        assert!(err.to_string().contains("corrupt"));
    }

    #[test]
    fn cache_metadata_manifest_must_match_its_image_id() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let mut metadata = serde_json::from_slice::<ImageMetadata>(HISTORICAL_CACHE_METADATA_V2)
            .expect("read historical metadata");
        let image_id = metadata.image_id.clone();
        metadata.manifest_digest = format!("sha256:{}", "ff".repeat(32));
        let dir = store.image_dir(&image_id, &platform).expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"rootfs").expect("write rootfs");
        std::fs::write(
            dir.join(METADATA_FILE_NAME),
            serde_json::to_vec(&metadata).expect("serialize metadata"),
        )
        .expect("write metadata");

        let err = store
            .cached_image(
                "registry.example.test/team/demo:stable",
                &image_id,
                &platform,
            )
            .expect_err("mismatched manifest should fail");

        assert!(err.to_string().contains("metadata manifest digest"));
    }

    #[test]
    fn rejects_cache_metadata_from_the_previous_schema() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let dir = store
            .image_dir(TEST_IMAGE_ID, &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(
            dir.join("metadata.json"),
            r#"{
                "version": 1,
                "image_ref": "index.docker.io/library/alpine:latest",
                "image_id": "sha256:def456",
                "source": "oci-registry",
                "requested_reference": "index.docker.io/library/alpine:latest",
                "selected_reference": "index.docker.io/library/alpine@sha256:def456",
                "manifest_digest": "sha256:def456",
                "config_digest": "sha256:config",
                "config": {},
                "layers": [],
                "platform": { "os": "linux", "architecture": "amd64" },
                "filesystem": "ext4",
                "rootfs_file": "rootfs.img",
                "created_at_unix": 1
            }"#,
        )
        .expect("write metadata");

        let err = store
            .cached_image(
                "index.docker.io/library/alpine:latest",
                TEST_IMAGE_ID,
                &platform,
            )
            .expect_err("v1 metadata should fail");

        assert!(err.to_string().contains("metadata version 1"));
    }

    #[test]
    fn cache_metadata_filesystem_mismatch_is_reported() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let dir = store
            .image_dir(TEST_IMAGE_ID, &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_vec_pretty(&ImageMetadata {
                version: METADATA_VERSION,
                image_ref: "index.docker.io/library/alpine:latest".to_string(),
                image_id: TEST_IMAGE_ID.to_string(),
                source: StoredRootfsImageSource::OciRegistry,
                requested_reference: "index.docker.io/library/alpine:latest".to_string(),
                selected_reference: format!("index.docker.io/library/alpine@{TEST_IMAGE_ID}"),
                manifest_digest: TEST_IMAGE_ID.to_string(),
                config_digest: "sha256:config".to_string(),
                config: ImageConfig::default(),
                layers: Vec::new(),
                platform: platform.clone(),
                filesystem: "xfs".to_string(),
                rootfs_file: ROOTFS_FILE_NAME.to_string(),
                created_at_unix: 1,
            })
            .expect("serialize metadata"),
        )
        .expect("write metadata");

        let err = store
            .cached_image(
                "index.docker.io/library/alpine:latest",
                TEST_IMAGE_ID,
                &platform,
            )
            .expect_err("filesystem mismatch should fail");

        assert!(err.to_string().contains("metadata filesystem"));
    }

    #[test]
    fn image_id_path_rejects_invalid_id() {
        let err = image_id_path_component("not-an-id").expect_err("image id should fail");

        assert!(err.to_string().contains("only sha256"));
    }

    #[test]
    fn digest_path_components_rejects_non_sha256_digests() {
        let err = digest_path_components("sha512:abc").expect_err("digest should fail");

        assert!(err.to_string().contains("only sha256"));
    }

    #[test]
    fn blob_cache_paths_are_content_addressed() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let digest = format!("sha256:{}", sha256_bytes(b"layer"));
        let encoded = digest.strip_prefix("sha256:").expect("digest prefix");

        assert_eq!(
            store.blob_path(&digest).expect("blob path"),
            temp.path().join("blobs/sha256").join(encoded)
        );
        assert_eq!(
            store.blob_part_path(&digest).expect("part path"),
            temp.path().join(format!("tmp/sha256-{encoded}.part"))
        );
        assert_eq!(
            store.blob_lock_path(&digest).expect("lock path"),
            temp.path()
                .join(format!("tmp/sha256-{encoded}.download.lock"))
        );
    }

    #[test]
    fn uppercase_blob_digest_uses_the_existing_lowercase_cache_path() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let digest = format!("sha256:{}", "AB".repeat(32));
        let encoded = "ab".repeat(32);

        assert_eq!(
            store.blob_path(&digest).expect("blob path"),
            temp.path().join("blobs/sha256").join(&encoded)
        );
        assert_eq!(
            store.blob_part_path(&digest).expect("part path"),
            temp.path().join(format!("tmp/sha256-{encoded}.part"))
        );
        assert_eq!(
            store.blob_lock_path(&digest).expect("lock path"),
            temp.path()
                .join(format!("tmp/sha256-{encoded}.download.lock"))
        );
    }

    #[test]
    fn layer_download_concurrency_matches_dynamic_bounds() {
        assert_eq!(layer_download_concurrency(0), 1);
        assert_eq!(layer_download_concurrency(2), 2);
        let high = layer_download_concurrency(128);
        assert!((4..=16).contains(&high));
    }

    #[test]
    fn layer_digest_mismatch_removes_partial_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("layer.part");
        std::fs::write(&path, b"wrong").expect("write layer");
        let layer = ResolvedLayer {
            digest: format!("sha256:{}", sha256_bytes(b"right")),
            media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
            size_bytes: 5,
            diff_id: "sha256:diff".to_string(),
        };

        let err = verify_layer_file(&path, &layer).expect_err("digest mismatch should fail");

        assert!(err.to_string().contains("has digest"));
        assert!(!path.exists());
    }

    #[test]
    fn layer_digest_accepts_matching_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("layer.part");
        std::fs::write(&path, b"right").expect("write layer");
        let layer = ResolvedLayer {
            digest: format!("sha256:{}", sha256_bytes(b"right")),
            media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
            size_bytes: 5,
            diff_id: "sha256:diff".to_string(),
        };

        verify_layer_file(&path, &layer).expect("matching digest should pass");

        assert!(path.exists());
    }

    #[test]
    fn concurrent_tag_updates_preserve_every_mapping() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let thread_count = 16;
        let barrier = Arc::new(Barrier::new(thread_count));

        std::thread::scope(|scope| {
            let mut threads = Vec::with_capacity(thread_count);
            for index in 0..thread_count {
                let root = temp.path().to_path_buf();
                let barrier = Arc::clone(&barrier);
                threads.push(scope.spawn(move || {
                    let store = ImageStore::open(root).expect("open store");
                    let reference = format!("example.test/demo-{index}:latest");
                    let digest = format!("sha256:{index:064x}");
                    barrier.wait();
                    store
                        .update_tag_mapping(&reference, &Platform::linux_amd64(), &digest)
                        .expect("update tag mapping");
                }));
            }
            for thread in threads {
                thread.join().expect("join tag update");
            }
        });

        let store = ImageStore::open(temp.path()).expect("open store");
        let index = store.read_index().expect("read shared index");
        assert_eq!(index.tags.len(), thread_count);
        for entry in 0..thread_count {
            let key = tag_key(
                &format!("example.test/demo-{entry}:latest"),
                &Platform::linux_amd64(),
            );
            assert_eq!(
                index
                    .tags
                    .get(&key)
                    .map(|record| record.manifest_digest.as_str()),
                Some(format!("sha256:{entry:064x}").as_str())
            );
        }
    }
}
