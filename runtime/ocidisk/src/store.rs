use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{BufReader, Cursor, Read};
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

use crate::ext4_writer::Ext4Writer;
use crate::layer::apply_layer;
use crate::lock::FileLock;
use crate::oci_archive::read_oci_archive;
use crate::platform::sanitize_component;
use crate::progress::{ImageProgress, ImageProgressSender};
use crate::registry::{RegistryClient, ResolvedLayer, ResolvedManifest};
use crate::source::ImageSource;
use crate::{OciDiskError, OciDiskResult, Platform};

const BLOBS_DIR_NAME: &str = "blobs";
const METADATA_VERSION: u32 = 1;
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
pub struct RootfsOptions {
    pub platform: Platform,
    pub disk_size_bytes: u64,
}

impl RootfsOptions {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            disk_size_bytes: DEFAULT_ROOTFS_SIZE_BYTES,
        }
    }

    pub fn for_host() -> OciDiskResult<Self> {
        Ok(Self::new(Platform::host()?))
    }

    pub fn with_disk_size_bytes(mut self, disk_size_bytes: u64) -> Self {
        self.disk_size_bytes = disk_size_bytes;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsImage {
    pub path: PathBuf,
    pub image_ref: String,
    pub image_id: String,
    pub platform: Platform,
    pub source: RootfsImageSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootfsImageSource {
    OciRegistry,
    Disk,
    Tar,
    OciArchive,
}

impl Display for RootfsImageSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OciRegistry => write!(f, "oci-registry"),
            Self::Disk => write!(f, "disk"),
            Self::Tar => write!(f, "tar"),
            Self::OciArchive => write!(f, "oci-archive"),
        }
    }
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
pub struct RootfsImageMetadata {
    pub version: u32,
    pub image_ref: String,
    pub image_id: String,
    pub source: RootfsImageSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<RootfsImageLayerMetadata>,
    pub platform: Platform,
    pub filesystem: String,
    pub rootfs_file: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootfsImageLayerMetadata {
    #[serde(rename = "digest")]
    pub blob_digest: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub diff_id: String,
}

type ImageMetadata = RootfsImageMetadata;
type ImageLayerMetadata = RootfsImageLayerMetadata;

impl From<&ResolvedLayer> for RootfsImageLayerMetadata {
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
    image_ref: String,
    resolved_reference: String,
    manifest_digest: String,
    config_digest: String,
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
    progress: Option<&'a ImageProgressSender>,
}

struct ImageMetadataInput<'a> {
    image_ref: &'a str,
    image_id: &'a str,
    source: RootfsImageSource,
    manifest_digest: Option<&'a str>,
    config_digest: Option<&'a str>,
    layers: &'a [ImageLayerMetadata],
    platform: &'a Platform,
}

struct LayerStreamWrite<'a> {
    path: &'a Path,
    stream: SizedStream,
    append: bool,
    start_offset: u64,
    layer: &'a ResolvedLayer,
    index: usize,
    total: usize,
    progress: Option<&'a ImageProgressSender>,
}

impl ImageStore {
    pub fn open(root: impl AsRef<Path>) -> OciDiskResult<Self> {
        Ok(Self {
            root: root.as_ref().to_path_buf(),
        })
    }

    pub async fn get_or_create(
        &self,
        image_ref: &str,
        options: RootfsOptions,
        progress: Option<ImageProgressSender>,
    ) -> OciDiskResult<RootfsImage> {
        match ImageSource::parse(image_ref)? {
            ImageSource::RemoteOci(image_ref) => {
                self.get_or_create_remote_oci(&image_ref, options, progress.as_ref())
                    .await
            }
            ImageSource::LocalDisk(path) => {
                self.local_disk(image_ref, path, options, progress.as_ref())
            }
            ImageSource::RootfsTar(path) => {
                self.get_or_create_rootfs_tar(image_ref, path, options, progress.as_ref())
            }
            ImageSource::OciArchive(path) => {
                self.get_or_create_oci_archive(image_ref, path, options, progress.as_ref())
            }
        }
    }

    pub fn get_cached(
        &self,
        image_ref: &str,
        options: RootfsOptions,
    ) -> OciDiskResult<Option<RootfsImage>> {
        match ImageSource::parse(image_ref)? {
            ImageSource::RemoteOci(image_ref) => self.cached_remote_oci(&image_ref, &options),
            ImageSource::LocalDisk(path) => {
                self.local_disk(image_ref, path, options, None).map(Some)
            }
            ImageSource::RootfsTar(path) => self.cached_rootfs_tar(image_ref, path, &options),
            ImageSource::OciArchive(_) => Ok(None),
        }
    }

    /// Pulls or reuses an OCI registry reference without applying local-source prefix syntax.
    pub async fn get_or_create_oci(
        &self,
        image_ref: &str,
        options: RootfsOptions,
        progress: Option<ImageProgressSender>,
    ) -> OciDiskResult<RootfsImage> {
        self.get_or_create_remote_oci(image_ref, options, progress.as_ref())
            .await
    }

    /// Returns a cached OCI registry reference without applying local-source prefix syntax.
    pub fn get_cached_oci(
        &self,
        image_ref: &str,
        options: RootfsOptions,
    ) -> OciDiskResult<Option<RootfsImage>> {
        self.cached_remote_oci(image_ref, &options)
    }

    pub fn rootfs_metadata(
        &self,
        image: &RootfsImage,
    ) -> OciDiskResult<Option<RootfsImageMetadata>> {
        if image.source == RootfsImageSource::Disk {
            return Ok(None);
        }

        let Some(dir) = image.path.parent() else {
            return Err(OciDiskError::CorruptCacheEntry {
                path: image.path.clone(),
                reason: "rootfs path has no parent directory".to_string(),
            });
        };

        Ok(Some(read_metadata(&dir.join(METADATA_FILE_NAME))?))
    }

    async fn get_or_create_remote_oci(
        &self,
        image_ref: &str,
        options: RootfsOptions,
        progress: Option<&ImageProgressSender>,
    ) -> OciDiskResult<RootfsImage> {
        fs::create_dir_all(&self.root)?;

        let reference = RegistryClient::parse_reference(image_ref)?;
        let canonical_ref = reference.to_string();
        let maps_to_tag = reference.digest().is_none();
        let registry = RegistryClient::new()?;
        emit_progress(
            progress,
            ImageProgress::ResolvingManifest {
                image_ref: canonical_ref.clone(),
            },
        );
        let resolved = registry
            .resolve_manifest(&reference, &options.platform)
            .await?;
        emit_progress(
            progress,
            ImageProgress::ResolvedManifest {
                image_ref: canonical_ref.clone(),
                manifest_digest: resolved.manifest_digest.clone(),
                layer_count: resolved.layers.len(),
                total_download_bytes: total_download_bytes(&resolved.layers),
            },
        );

        let _image_lock = FileLock::exclusive(
            &self.image_lock_path(&resolved.manifest_digest, &options.platform)?,
        )?;
        self.write_manifest_metadata(&canonical_ref, &resolved, &options.platform)?;

        emit_progress(
            progress,
            ImageProgress::CheckingCache {
                image_ref: canonical_ref.clone(),
            },
        );
        if let Some(image) = self.cached_image(
            &canonical_ref,
            &resolved.manifest_digest,
            &options.platform,
            RootfsImageSource::OciRegistry,
        )? {
            emit_progress(
                progress,
                ImageProgress::CacheHit {
                    image_ref: canonical_ref.clone(),
                },
            );
            if maps_to_tag {
                self.update_tag_mapping(
                    &canonical_ref,
                    &options.platform,
                    &resolved.manifest_digest,
                )?;
            }
            return Ok(image);
        }
        emit_progress(
            progress,
            ImageProgress::CacheMiss {
                image_ref: canonical_ref.clone(),
            },
        );

        let image = self
            .create_rootfs(&registry, &canonical_ref, &resolved, &options, progress)
            .await?;
        if maps_to_tag {
            self.update_tag_mapping(&canonical_ref, &options.platform, &resolved.manifest_digest)?;
        }
        Ok(image)
    }

    fn cached_remote_oci(
        &self,
        image_ref: &str,
        options: &RootfsOptions,
    ) -> OciDiskResult<Option<RootfsImage>> {
        let reference = RegistryClient::parse_reference(image_ref)?;
        let canonical_ref = reference.to_string();
        let Some(digest) = reference.digest() else {
            let index = self.read_index()?;
            let Some(tag) = index.tags.get(&tag_key(&canonical_ref, &options.platform)) else {
                return Ok(None);
            };
            return self.cached_image(
                &canonical_ref,
                &tag.manifest_digest,
                &options.platform,
                RootfsImageSource::OciRegistry,
            );
        };

        self.cached_image(
            &canonical_ref,
            digest,
            &options.platform,
            RootfsImageSource::OciRegistry,
        )
    }

    async fn create_rootfs(
        &self,
        registry: &RegistryClient,
        image_ref: &str,
        resolved: &ResolvedManifest,
        options: &RootfsOptions,
        progress: Option<&ImageProgressSender>,
    ) -> OciDiskResult<RootfsImage> {
        let image_id = &resolved.manifest_digest;
        let final_dir = self.image_dir(image_id, &options.platform)?;
        if final_dir.exists() {
            if let Some(image) = self.cached_image(
                image_ref,
                image_id,
                &options.platform,
                RootfsImageSource::OciRegistry,
            )? {
                emit_progress(
                    progress,
                    ImageProgress::CacheHit {
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
        let mut writer = Ext4Writer::create(&stage_rootfs, options.disk_size_bytes)?;

        let total = blobs.len();
        for blob in &blobs {
            emit_progress(
                progress,
                ImageProgress::ApplyingLayer {
                    index: blob.index,
                    total,
                    digest: Some(blob.layer.digest.clone()),
                },
            );
            let reader = layer_reader_from_path(&blob.layer.media_type, &blob.path)?;
            apply_layer(reader, &mut writer)?;
        }

        emit_progress(progress, ImageProgress::WritingExt4);
        writer.finish()?;
        emit_progress(progress, ImageProgress::SavingBaseImage);
        let layers = resolved
            .layers
            .iter()
            .map(ImageLayerMetadata::from)
            .collect::<Vec<_>>();
        self.write_metadata(
            staging.path(),
            ImageMetadataInput {
                image_ref,
                image_id,
                source: RootfsImageSource::OciRegistry,
                manifest_digest: Some(&resolved.manifest_digest),
                config_digest: Some(&resolved.config_digest),
                layers: &layers,
                platform: &options.platform,
            },
        )?;

        if let Some(parent) = final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        if final_dir.exists() {
            if let Some(image) = self.cached_image(
                image_ref,
                image_id,
                &options.platform,
                RootfsImageSource::OciRegistry,
            )? {
                emit_progress(
                    progress,
                    ImageProgress::CacheHit {
                        image_ref: image_ref.to_string(),
                    },
                );
                return Ok(image);
            }
        }
        fs::rename(staging.path(), &final_dir)?;
        staging.disarm();

        Ok(RootfsImage {
            path: final_dir.join(ROOTFS_FILE_NAME),
            image_ref: image_ref.to_string(),
            image_id: image_id.to_string(),
            platform: options.platform.clone(),
            source: RootfsImageSource::OciRegistry,
        })
    }

    fn local_disk(
        &self,
        image_ref: &str,
        path: PathBuf,
        options: RootfsOptions,
        progress: Option<&ImageProgressSender>,
    ) -> OciDiskResult<RootfsImage> {
        emit_progress(
            progress,
            ImageProgress::UsingLocalDisk {
                image_ref: image_ref.to_string(),
            },
        );
        let path = canonical_local_file(image_ref, &path)?;
        let image_id = format!(
            "local-disk-sha256:{}",
            sha256_bytes(path.to_string_lossy().as_bytes())
        );
        Ok(RootfsImage {
            path,
            image_ref: image_ref.to_string(),
            image_id,
            platform: options.platform,
            source: RootfsImageSource::Disk,
        })
    }

    fn get_or_create_rootfs_tar(
        &self,
        image_ref: &str,
        path: PathBuf,
        options: RootfsOptions,
        progress: Option<&ImageProgressSender>,
    ) -> OciDiskResult<RootfsImage> {
        fs::create_dir_all(&self.root)?;
        let path = canonical_local_file(image_ref, &path)?;
        reject_known_tar_compression(image_ref, &path)?;
        emit_progress(
            progress,
            ImageProgress::HashingSource {
                image_ref: image_ref.to_string(),
            },
        );
        let image_id = format!("tar-sha256:{}", sha256_file(&path)?);

        emit_progress(
            progress,
            ImageProgress::CheckingCache {
                image_ref: image_ref.to_string(),
            },
        );
        if let Some(image) = self.cached_image(
            image_ref,
            &image_id,
            &options.platform,
            RootfsImageSource::Tar,
        )? {
            emit_progress(
                progress,
                ImageProgress::CacheHit {
                    image_ref: image_ref.to_string(),
                },
            );
            return Ok(image);
        }
        emit_progress(
            progress,
            ImageProgress::CacheMiss {
                image_ref: image_ref.to_string(),
            },
        );

        let final_dir = self.image_dir(&image_id, &options.platform)?;
        let staging = StagingDir::create(&self.root)?;
        let stage_rootfs = staging.path().join(ROOTFS_FILE_NAME);
        let mut writer = Ext4Writer::create(&stage_rootfs, options.disk_size_bytes)?;
        let file = fs::File::open(&path)?;
        emit_progress(
            progress,
            ImageProgress::ApplyingLayer {
                index: 1,
                total: 1,
                digest: None,
            },
        );
        apply_layer(file, &mut writer)?;
        emit_progress(progress, ImageProgress::WritingExt4);
        writer.finish()?;
        emit_progress(progress, ImageProgress::SavingBaseImage);
        self.write_metadata(
            staging.path(),
            ImageMetadataInput {
                image_ref,
                image_id: &image_id,
                source: RootfsImageSource::Tar,
                manifest_digest: None,
                config_digest: None,
                layers: &[],
                platform: &options.platform,
            },
        )?;

        if let Some(parent) = final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        if final_dir.exists() {
            if let Some(image) = self.cached_image(
                image_ref,
                &image_id,
                &options.platform,
                RootfsImageSource::Tar,
            )? {
                emit_progress(
                    progress,
                    ImageProgress::CacheHit {
                        image_ref: image_ref.to_string(),
                    },
                );
                return Ok(image);
            }
        }
        fs::rename(staging.path(), &final_dir)?;
        staging.disarm();

        Ok(RootfsImage {
            path: final_dir.join(ROOTFS_FILE_NAME),
            image_ref: image_ref.to_string(),
            image_id,
            platform: options.platform,
            source: RootfsImageSource::Tar,
        })
    }

    fn cached_rootfs_tar(
        &self,
        image_ref: &str,
        path: PathBuf,
        options: &RootfsOptions,
    ) -> OciDiskResult<Option<RootfsImage>> {
        let path = canonical_local_file(image_ref, &path)?;
        reject_known_tar_compression(image_ref, &path)?;
        let image_id = format!("tar-sha256:{}", sha256_file(&path)?);
        self.cached_image(
            image_ref,
            &image_id,
            &options.platform,
            RootfsImageSource::Tar,
        )
    }

    fn get_or_create_oci_archive(
        &self,
        image_ref: &str,
        path: PathBuf,
        options: RootfsOptions,
        progress: Option<&ImageProgressSender>,
    ) -> OciDiskResult<RootfsImage> {
        fs::create_dir_all(&self.root)?;
        let path = canonical_local_file(image_ref, &path)?;
        emit_progress(
            progress,
            ImageProgress::ReadingArchive {
                image_ref: image_ref.to_string(),
            },
        );
        let archive = read_oci_archive(&path, image_ref, &options.platform)?;
        let image_id = archive.manifest_digest.clone();

        emit_progress(
            progress,
            ImageProgress::CheckingCache {
                image_ref: image_ref.to_string(),
            },
        );
        if let Some(image) = self.cached_image(
            image_ref,
            &image_id,
            &options.platform,
            RootfsImageSource::OciArchive,
        )? {
            emit_progress(
                progress,
                ImageProgress::CacheHit {
                    image_ref: image_ref.to_string(),
                },
            );
            return Ok(image);
        }
        emit_progress(
            progress,
            ImageProgress::CacheMiss {
                image_ref: image_ref.to_string(),
            },
        );

        let final_dir = self.image_dir(&image_id, &options.platform)?;
        let staging = StagingDir::create(&self.root)?;
        let stage_rootfs = staging.path().join(ROOTFS_FILE_NAME);
        let mut writer = Ext4Writer::create(&stage_rootfs, options.disk_size_bytes)?;
        let total = archive.layers.len();
        for (index, layer) in archive.layers.into_iter().enumerate() {
            emit_progress(
                progress,
                ImageProgress::ApplyingLayer {
                    index: index + 1,
                    total,
                    digest: None,
                },
            );
            let reader = layer_reader(&layer.media_type, layer.bytes)?;
            apply_layer(reader, &mut writer)?;
        }
        emit_progress(progress, ImageProgress::WritingExt4);
        writer.finish()?;
        emit_progress(progress, ImageProgress::SavingBaseImage);
        self.write_metadata(
            staging.path(),
            ImageMetadataInput {
                image_ref,
                image_id: &image_id,
                source: RootfsImageSource::OciArchive,
                manifest_digest: Some(&archive.manifest_digest),
                config_digest: Some(&archive.config_digest),
                layers: &[],
                platform: &options.platform,
            },
        )?;

        if let Some(parent) = final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        if final_dir.exists() {
            if let Some(image) = self.cached_image(
                image_ref,
                &image_id,
                &options.platform,
                RootfsImageSource::OciArchive,
            )? {
                emit_progress(
                    progress,
                    ImageProgress::CacheHit {
                        image_ref: image_ref.to_string(),
                    },
                );
                return Ok(image);
            }
        }
        fs::rename(staging.path(), &final_dir)?;
        staging.disarm();

        Ok(RootfsImage {
            path: final_dir.join(ROOTFS_FILE_NAME),
            image_ref: image_ref.to_string(),
            image_id,
            platform: options.platform,
            source: RootfsImageSource::OciArchive,
        })
    }

    async fn ensure_layer_blobs(
        &self,
        registry: &RegistryClient,
        image_ref: &str,
        resolved: &ResolvedManifest,
        progress: Option<&ImageProgressSender>,
    ) -> OciDiskResult<Vec<LayerBlob>> {
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
                    Ok::<_, OciDiskError>(LayerBlob {
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

    async fn get_or_download_layer(
        &self,
        request: LayerDownloadRequest<'_>,
    ) -> OciDiskResult<PathBuf> {
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
                ImageProgress::LayerDownloadSkipped {
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
                ImageProgress::LayerDownloadVerifying {
                    index,
                    total,
                    digest: layer.digest.clone(),
                },
            );
            promote_layer_part(&part_path, &blob_path)?;
            emit_progress(
                progress,
                ImageProgress::LayerDownloadFinished {
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
            ImageProgress::LayerDownloadStarted {
                index,
                total,
                digest: layer.digest.clone(),
                size_bytes: Some(layer.size_bytes),
            },
        );
        if offset > 0 {
            emit_progress(
                progress,
                ImageProgress::LayerDownloadProgress {
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
            ImageProgress::LayerDownloadVerifying {
                index,
                total,
                digest: layer.digest.clone(),
            },
        );
        verify_layer_file(&part_path, layer)?;
        promote_layer_part(&part_path, &blob_path)?;
        emit_progress(
            progress,
            ImageProgress::LayerDownloadFinished {
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
        source: RootfsImageSource,
    ) -> OciDiskResult<Option<RootfsImage>> {
        let dir = self.image_dir(image_id, platform)?;
        if !dir.exists() {
            return Ok(None);
        }

        let rootfs_path = dir.join(ROOTFS_FILE_NAME);
        if !rootfs_path.is_file() {
            return Err(OciDiskError::CorruptCacheEntry {
                path: dir,
                reason: format!("missing {ROOTFS_FILE_NAME}"),
            });
        }

        let metadata_path = dir.join(METADATA_FILE_NAME);
        let metadata = read_metadata(&metadata_path)?;
        if metadata.version != METADATA_VERSION {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata version {} does not match expected version {METADATA_VERSION}",
                    metadata.version
                ),
            });
        }
        if metadata.image_id != image_id {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata image id {} does not match cache image id {image_id}",
                    metadata.image_id
                ),
            });
        }
        if metadata.source != source {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata source {} does not match cache source {source}",
                    metadata.source
                ),
            });
        }
        if metadata.platform != *platform {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata platform {} does not match cache platform {platform}",
                    metadata.platform
                ),
            });
        }
        if metadata.filesystem != ROOTFS_FILESYSTEM {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata filesystem {} does not match expected {ROOTFS_FILESYSTEM}",
                    metadata.filesystem
                ),
            });
        }
        if metadata.rootfs_file != ROOTFS_FILE_NAME {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!("metadata rootfs file is {}", metadata.rootfs_file),
            });
        }
        Ok(Some(RootfsImage {
            path: rootfs_path,
            image_ref: image_ref.to_string(),
            image_id: image_id.to_string(),
            platform: platform.clone(),
            source,
        }))
    }

    fn image_dir(&self, image_id: &str, platform: &Platform) -> OciDiskResult<PathBuf> {
        Ok(self
            .root
            .join(image_id_path_component(image_id)?)
            .join(platform.cache_key()))
    }

    fn image_lock_path(&self, image_id: &str, platform: &Platform) -> OciDiskResult<PathBuf> {
        Ok(self.root.join(TMP_DIR_NAME).join(format!(
            "image-{}-{}.lock",
            image_id_path_component(image_id)?,
            platform.cache_key()
        )))
    }

    fn blob_path(&self, digest: &str) -> OciDiskResult<PathBuf> {
        let (algorithm, encoded) = digest_path_components(digest)?;
        Ok(self.root.join(BLOBS_DIR_NAME).join(algorithm).join(encoded))
    }

    fn blob_part_path(&self, digest: &str) -> OciDiskResult<PathBuf> {
        let (algorithm, encoded) = digest_path_components(digest)?;
        Ok(self
            .root
            .join(TMP_DIR_NAME)
            .join(format!("{}-{}.part", algorithm, encoded)))
    }

    fn blob_lock_path(&self, digest: &str) -> OciDiskResult<PathBuf> {
        let (algorithm, encoded) = digest_path_components(digest)?;
        Ok(self
            .root
            .join(TMP_DIR_NAME)
            .join(format!("{}-{}.download.lock", algorithm, encoded)))
    }

    fn manifest_dir(&self, manifest_digest: &str) -> OciDiskResult<PathBuf> {
        Ok(self
            .root
            .join(MANIFESTS_DIR_NAME)
            .join(image_id_path_component(manifest_digest)?))
    }

    fn write_metadata(&self, dir: &Path, input: ImageMetadataInput<'_>) -> OciDiskResult<()> {
        let metadata = ImageMetadata {
            version: METADATA_VERSION,
            image_ref: input.image_ref.to_string(),
            image_id: input.image_id.to_string(),
            source: input.source,
            manifest_digest: input.manifest_digest.map(str::to_string),
            config_digest: input.config_digest.map(str::to_string),
            layers: input.layers.to_vec(),
            platform: input.platform.clone(),
            filesystem: ROOTFS_FILESYSTEM.to_string(),
            rootfs_file: ROOTFS_FILE_NAME.to_string(),
            created_at_unix: now_unix(),
        };
        let data = serde_json::to_vec_pretty(&metadata)?;
        fs::write(dir.join(METADATA_FILE_NAME), data)?;
        Ok(())
    }

    fn write_manifest_metadata(
        &self,
        image_ref: &str,
        resolved: &ResolvedManifest,
        platform: &Platform,
    ) -> OciDiskResult<()> {
        let dir = self.manifest_dir(&resolved.manifest_digest)?;
        fs::create_dir_all(&dir)?;
        let metadata = ManifestMetadata {
            version: METADATA_VERSION,
            image_ref: image_ref.to_string(),
            resolved_reference: resolved.reference.to_string(),
            manifest_digest: resolved.manifest_digest.clone(),
            config_digest: resolved.config_digest.clone(),
            platform: platform.clone(),
            layers: resolved
                .layers
                .iter()
                .map(ImageLayerMetadata::from)
                .collect(),
            resolved_at_unix: now_unix(),
        };
        let path = dir.join(METADATA_FILE_NAME);
        let temp_path = dir.join(format!("{METADATA_FILE_NAME}.tmp"));
        fs::write(&temp_path, serde_json::to_vec_pretty(&metadata)?)?;
        fs::rename(temp_path, path)?;
        Ok(())
    }

    fn update_tag_mapping(
        &self,
        image_ref: &str,
        platform: &Platform,
        manifest_digest: &str,
    ) -> OciDiskResult<()> {
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

    fn read_index(&self) -> OciDiskResult<StoreIndex> {
        let path = self.root.join(INDEX_FILE_NAME);
        match fs::read(&path) {
            Ok(data) => {
                let index = serde_json::from_slice::<StoreIndex>(&data).map_err(|err| {
                    OciDiskError::CorruptCacheEntry {
                        path: path.clone(),
                        reason: err.to_string(),
                    }
                })?;
                if index.version != INDEX_VERSION {
                    return Err(OciDiskError::CorruptCacheEntry {
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

    fn write_index(&self, index: &StoreIndex) -> OciDiskResult<()> {
        fs::create_dir_all(&self.root)?;
        let path = self.root.join(INDEX_FILE_NAME);
        let temp_path = self.root.join(format!("{INDEX_FILE_NAME}.tmp"));
        fs::write(&temp_path, serde_json::to_vec_pretty(index)?)?;
        fs::rename(temp_path, path)?;
        Ok(())
    }
}

fn emit_progress(progress: Option<&ImageProgressSender>, event: ImageProgress) {
    if let Some(progress) = progress {
        progress.send(event);
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

async fn write_layer_stream(request: LayerStreamWrite<'_>) -> OciDiskResult<()> {
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
                ImageProgress::LayerDownloadProgress {
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
        return Err(OciDiskError::LayerSizeMismatch {
            digest: layer.digest.clone(),
            path: path.to_path_buf(),
            expected: layer.size_bytes,
            actual,
        });
    }
    Ok(())
}

fn partial_download_offset(path: &Path, layer: &ResolvedLayer) -> OciDiskResult<u64> {
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

fn verified_blob_exists(path: &Path, digest: &str) -> OciDiskResult<bool> {
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

fn verify_layer_file(path: &Path, layer: &ResolvedLayer) -> OciDiskResult<()> {
    let actual_size = fs::metadata(path)?.len();
    if actual_size != layer.size_bytes {
        remove_file_if_exists(path)?;
        return Err(OciDiskError::LayerSizeMismatch {
            digest: layer.digest.clone(),
            path: path.to_path_buf(),
            expected: layer.size_bytes,
            actual: actual_size,
        });
    }

    let actual_digest = sha256_file(path)?;
    let (_, expected_digest) = digest_path_components(&layer.digest)?;
    if actual_digest != expected_digest {
        remove_file_if_exists(path)?;
        return Err(OciDiskError::LayerDigestMismatch {
            digest: layer.digest.clone(),
            path: path.to_path_buf(),
            actual: actual_digest,
        });
    }
    Ok(())
}

fn layer_digest_matches(path: &Path, digest: &str) -> OciDiskResult<bool> {
    let actual_digest = sha256_file(path)?;
    let (_, expected_digest) = digest_path_components(digest)?;
    Ok(actual_digest == expected_digest)
}

fn promote_layer_part(part_path: &Path, blob_path: &Path) -> OciDiskResult<()> {
    if let Some(parent) = blob_path.parent() {
        fs::create_dir_all(parent)?;
    }
    remove_file_if_exists(blob_path)?;
    fs::rename(part_path, blob_path)?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> OciDiskResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn read_metadata(path: &Path) -> OciDiskResult<ImageMetadata> {
    let data = fs::read(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            OciDiskError::CorruptCacheEntry {
                path: path.to_path_buf(),
                reason: "metadata file is missing".to_string(),
            }
        } else {
            OciDiskError::Io(err)
        }
    })?;
    serde_json::from_slice(&data).map_err(|err| OciDiskError::CorruptCacheEntry {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn layer_reader(media_type: &MediaType, bytes: Vec<u8>) -> OciDiskResult<Box<dyn Read>> {
    layer_reader_from_read(media_type, Cursor::new(bytes))
}

fn layer_reader_from_path(media_type: &str, path: &Path) -> OciDiskResult<Box<dyn Read>> {
    let media_type =
        MediaType::from_str(media_type).map_err(|err| OciDiskError::UnsupportedLayerMediaType {
            media_type: format!("{media_type}: {err}"),
        })?;
    let file = fs::File::open(path)?;
    layer_reader_from_read(&media_type, BufReader::new(file))
}

fn layer_reader_from_read(
    media_type: &MediaType,
    reader: impl Read + 'static,
) -> OciDiskResult<Box<dyn Read>> {
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
        other => Err(OciDiskError::UnsupportedLayerMediaType {
            media_type: other.as_str().to_string(),
        }),
    }
}

fn digest_path_components(digest: &str) -> OciDiskResult<(String, String)> {
    let Some((algorithm, encoded)) = digest.split_once(':') else {
        return Err(OciDiskError::InvalidDigest {
            digest: digest.to_string(),
            message: "digest must contain an algorithm and encoded value".to_string(),
        });
    };
    if algorithm != "sha256" {
        return Err(OciDiskError::UnsupportedDigestAlgorithm {
            digest: digest.to_string(),
        });
    }
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(OciDiskError::InvalidDigest {
            digest: digest.to_string(),
            message: "sha256 digests must be 64 hexadecimal characters".to_string(),
        });
    }
    Ok((
        sanitize_component(algorithm),
        sanitize_component(&encoded.to_ascii_lowercase()),
    ))
}

fn canonical_local_file(reference: &str, path: &Path) -> OciDiskResult<PathBuf> {
    let canonical = path
        .canonicalize()
        .map_err(|err| OciDiskError::LocalImageSource {
            reference: reference.to_string(),
            path: path.to_path_buf(),
            message: err.to_string(),
        })?;
    let metadata = canonical
        .metadata()
        .map_err(|err| OciDiskError::LocalImageSource {
            reference: reference.to_string(),
            path: canonical.clone(),
            message: err.to_string(),
        })?;
    if !metadata.is_file() {
        return Err(OciDiskError::LocalImageSource {
            reference: reference.to_string(),
            path: canonical,
            message: "path must point to a regular file".to_string(),
        });
    }
    Ok(canonical)
}

fn reject_known_tar_compression(reference: &str, path: &Path) -> OciDiskResult<()> {
    let mut file = fs::File::open(path)?;
    let mut magic = [0_u8; 6];
    let read = file.read(&mut magic)?;
    let compression = if read >= 2 && magic[..2] == [0x1f, 0x8b] {
        Some("gzip")
    } else if read >= 4 && magic[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        Some("zstd")
    } else if read >= 6 && magic == [0xfd, b'7', b'z', b'X', b'Z', 0x00] {
        Some("xz")
    } else {
        None
    };

    if let Some(compression) = compression {
        return Err(OciDiskError::UnsupportedTarCompression {
            reference: reference.to_string(),
            path: path.to_path_buf(),
            compression,
        });
    }

    Ok(())
}

fn sha256_file(path: &Path) -> OciDiskResult<String> {
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
    Ok(hex_digest(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(&hasher.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn image_id_path_component(image_id: &str) -> OciDiskResult<String> {
    let Some((algorithm, encoded)) = image_id.split_once(':') else {
        return Err(OciDiskError::CorruptCacheEntry {
            path: PathBuf::from(image_id),
            reason: "image id must contain a kind and value".to_string(),
        });
    };
    if algorithm.is_empty() || encoded.is_empty() {
        return Err(OciDiskError::CorruptCacheEntry {
            path: PathBuf::from(image_id),
            reason: "image id kind and value must be non-empty".to_string(),
        });
    }
    Ok(format!(
        "{}-{}",
        sanitize_component(algorithm),
        sanitize_component(encoded)
    ))
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
    fn create(root: &Path) -> OciDiskResult<Self> {
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
    use std::io::{Cursor, Read};

    use ext4::Reader;
    use tar::{Builder, Header};

    use crate::progress::ImageProgressSender;
    use crate::registry::ResolvedLayer;
    use crate::store::{
        digest_path_components, image_id_path_component, layer_download_concurrency, sha256_bytes,
        verify_layer_file, ImageMetadata, ImageProgress, ImageStore, RootfsImageSource,
        RootfsOptions, METADATA_VERSION, ROOTFS_FILESYSTEM, ROOTFS_FILE_NAME,
    };
    use crate::{Platform, RootfsImage};

    #[test]
    fn image_id_and_platform_define_cache_path() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let path = store
            .image_dir("sha256:abc123", &Platform::linux_amd64())
            .expect("cache path");

        assert_eq!(path, temp.path().join("sha256-abc123/linux-amd64"));
    }

    #[test]
    fn validates_existing_cache_metadata() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_arm64();
        let dir = store
            .image_dir("sha256:def456", &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_vec_pretty(&ImageMetadata {
                version: METADATA_VERSION,
                image_ref: "index.docker.io/library/alpine:latest".to_string(),
                image_id: "sha256:def456".to_string(),
                source: RootfsImageSource::OciRegistry,
                manifest_digest: Some("sha256:def456".to_string()),
                config_digest: Some("sha256:config".to_string()),
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
                "sha256:def456",
                &platform,
                RootfsImageSource::OciRegistry,
            )
            .expect("cache validation")
            .expect("cache hit");

        assert_eq!(
            image,
            RootfsImage {
                path: dir.join(ROOTFS_FILE_NAME),
                image_ref: "index.docker.io/library/alpine:latest".to_string(),
                image_id: "sha256:def456".to_string(),
                platform,
                source: RootfsImageSource::OciRegistry,
            }
        );
    }

    #[test]
    fn corrupt_cache_metadata_is_reported() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let dir = store
            .image_dir("sha256:def456", &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(dir.join("metadata.json"), b"not json").expect("write metadata");

        let err = store
            .cached_image(
                "alpine:latest",
                "sha256:def456",
                &platform,
                RootfsImageSource::OciRegistry,
            )
            .expect_err("corrupt metadata should fail");

        assert!(err.to_string().contains("corrupt"));
    }

    #[test]
    fn cache_metadata_filesystem_mismatch_is_reported() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let dir = store
            .image_dir("sha256:def456", &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_vec_pretty(&ImageMetadata {
                version: METADATA_VERSION,
                image_ref: "index.docker.io/library/alpine:latest".to_string(),
                image_id: "sha256:def456".to_string(),
                source: RootfsImageSource::OciRegistry,
                manifest_digest: Some("sha256:def456".to_string()),
                config_digest: Some("sha256:config".to_string()),
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
                "sha256:def456",
                &platform,
                RootfsImageSource::OciRegistry,
            )
            .expect_err("filesystem mismatch should fail");

        assert!(err.to_string().contains("metadata filesystem"));
    }

    #[test]
    fn image_id_path_rejects_invalid_id() {
        let err = image_id_path_component("not-an-id").expect_err("image id should fail");

        assert!(err.to_string().contains("image id must contain"));
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
    fn disk_source_uses_local_file_directly_without_creating_cache() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let cache = temp.path().join("cache");
        let disk = temp.path().join("rootfs.img");
        std::fs::write(&disk, b"disk").expect("write disk");
        let store = ImageStore::open(&cache).expect("open store");
        let image = store
            .local_disk(
                &format!("disk:{}", disk.display()),
                disk.clone(),
                RootfsOptions::new(Platform::linux_amd64()),
                None,
            )
            .expect("local disk");

        assert_eq!(image.path, disk.canonicalize().expect("canonical disk"));
        assert_eq!(image.source, RootfsImageSource::Disk);
        assert!(!cache.exists());
    }

    #[test]
    fn explicit_oci_cache_lookup_does_not_parse_local_source_prefixes() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let image = store
            .get_cached_oci(
                "disk:5000/repo:tag",
                RootfsOptions::new(Platform::linux_amd64()),
            )
            .expect("lookup OCI cache");

        assert!(image.is_none());
    }

    #[test]
    fn rootfs_tar_converts_to_cached_ext4() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let tar_path = temp.path().join("rootfs.tar");
        std::fs::write(&tar_path, tar_file("etc/os-release", b"NAME=Silo\n")).expect("write tar");
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");
        let image = store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path,
                RootfsOptions::new(Platform::linux_amd64()).with_disk_size_bytes(64 * 1024 * 1024),
                None,
            )
            .expect("convert tar");

        assert_eq!(image.source, RootfsImageSource::Tar);
        assert!(image.image_id.starts_with("tar-sha256:"));
        assert_eq!(
            image.path.file_name().and_then(|name| name.to_str()),
            Some("rootfs.img")
        );
        let mut reader = Reader::new(&image.path).expect("open ext4");
        let bytes = reader
            .read_file("/etc/os-release", 0, Some(64))
            .expect("read converted file");
        assert_eq!(bytes, b"NAME=Silo\n");
    }

    #[test]
    fn rootfs_tar_reports_cache_build_progress() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let tar_path = temp.path().join("rootfs.tar");
        std::fs::write(&tar_path, tar_file("etc/progress", b"tick")).expect("write tar");
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");
        let (progress, mut progress_events) = ImageProgressSender::channel(16);

        store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path,
                RootfsOptions::new(Platform::linux_amd64()).with_disk_size_bytes(64 * 1024 * 1024),
                Some(&progress),
            )
            .expect("convert tar");
        drop(progress);

        let mut events = Vec::new();
        while let Ok(event) = progress_events.try_recv() {
            events.push(progress_label(event));
        }
        assert_eq!(
            events,
            vec![
                "hash-source",
                "check-cache",
                "cache-miss",
                "apply-layer-1/1",
                "write-ext4",
                "save-base-image",
            ]
        );
    }

    #[test]
    fn rootfs_tar_reuses_content_cache() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let tar_path = temp.path().join("rootfs.tar");
        std::fs::write(&tar_path, tar_file("etc/issue", b"one")).expect("write tar");
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");
        let options =
            RootfsOptions::new(Platform::linux_amd64()).with_disk_size_bytes(64 * 1024 * 1024);

        let first = store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path.clone(),
                options.clone(),
                None,
            )
            .expect("first convert");
        let second = store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path,
                options,
                None,
            )
            .expect("second convert");

        assert_eq!(first.path, second.path);
        assert_eq!(first.image_id, second.image_id);
    }

    #[test]
    fn rootfs_tar_can_grow_past_requested_size() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let tar_path = temp.path().join("rootfs.tar");
        write_sparse_tar_file(&tar_path, "var/lib/payload", 9 * 1024 * 1024);

        let store = ImageStore::open(temp.path().join("cache")).expect("open store");
        let options =
            RootfsOptions::new(Platform::linux_amd64()).with_disk_size_bytes(8 * 1024 * 1024);

        let image = store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path,
                options,
                None,
            )
            .expect("convert oversized tar");

        let mut reader = Reader::new(&image.path).expect("open grown ext4");
        let bytes = reader
            .read_file("/var/lib/payload", 0, Some(16))
            .expect("read grown payload");
        assert_eq!(bytes, vec![0u8; 16]);
    }

    #[test]
    fn rootfs_tar_rejects_known_compression() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let tar_path = temp.path().join("rootfs.tar.gz");
        std::fs::write(&tar_path, [0x1f, 0x8b, 0, 0]).expect("write gzip magic");
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");

        let err = store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path,
                RootfsOptions::new(Platform::linux_amd64()),
                None,
            )
            .expect_err("compressed tar should fail");

        assert!(err.to_string().contains("only plain tar"));
    }

    #[test]
    fn oci_archive_converts_selected_platform() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let archive_path = temp.path().join("image.tar");
        write_oci_archive(&archive_path, "amd64", tar_file("etc/arch", b"amd64"));
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");
        let image = store
            .get_or_create_oci_archive(
                &format!("oci:{}", archive_path.display()),
                archive_path,
                RootfsOptions::new(Platform::linux_amd64()).with_disk_size_bytes(64 * 1024 * 1024),
                None,
            )
            .expect("convert oci archive");

        assert_eq!(image.source, RootfsImageSource::OciArchive);
        let mut reader = Reader::new(&image.path).expect("open ext4");
        let bytes = reader
            .read_file("/etc/arch", 0, Some(64))
            .expect("read converted file");
        assert_eq!(bytes, b"amd64");
    }

    fn tar_file(path: &str, data: &[u8]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_path(path).expect("set path");
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(data.to_vec()))
            .expect("append file");
        builder.into_inner().expect("finish tar")
    }

    fn write_sparse_tar_file(path: &std::path::Path, member_path: &str, size: u64) {
        let file = std::fs::File::create(path).expect("create tar");
        let mut builder = Builder::new(file);
        let mut header = Header::new_gnu();
        header.set_path(member_path).expect("set path");
        header.set_size(size);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append(&header, std::io::repeat(0).take(size))
            .expect("append sparse payload");
        builder.finish().expect("finish tar");
    }

    fn write_oci_archive(path: &std::path::Path, architecture: &str, layer: Vec<u8>) {
        let config = format!(
            r#"{{"architecture":"{architecture}","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}}}}"#
        )
        .into_bytes();
        let config_digest = format!("sha256:{}", sha256_bytes(&config));
        let layer_digest = format!("sha256:{}", sha256_bytes(&layer));
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{config_size}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{layer_size}}}]}}"#,
            config_size = config.len(),
            layer_size = layer.len()
        )
        .into_bytes();
        let manifest_digest = format!("sha256:{}", sha256_bytes(&manifest));
        let index = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{manifest_size},"platform":{{"architecture":"{architecture}","os":"linux"}}}}]}}"#,
            manifest_size = manifest.len()
        )
        .into_bytes();

        let mut builder = Builder::new(Vec::new());
        append_archive_file(&mut builder, "index.json", &index);
        append_blob(&mut builder, &config_digest, &config);
        append_blob(&mut builder, &layer_digest, &layer);
        append_blob(&mut builder, &manifest_digest, &manifest);
        let data = builder.into_inner().expect("finish oci archive");
        std::fs::write(path, data).expect("write oci archive");
    }

    fn append_blob(builder: &mut Builder<Vec<u8>>, digest: &str, data: &[u8]) {
        let (algorithm, encoded) = digest.split_once(':').expect("digest shape");
        append_archive_file(builder, &format!("blobs/{algorithm}/{encoded}"), data);
    }

    fn append_archive_file(builder: &mut Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_path(path).expect("set path");
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(data.to_vec()))
            .expect("append archive file");
    }

    fn progress_label(event: ImageProgress) -> String {
        match event {
            ImageProgress::ResolvingManifest { .. } => "resolve-manifest".to_string(),
            ImageProgress::HashingSource { .. } => "hash-source".to_string(),
            ImageProgress::ReadingArchive { .. } => "read-archive".to_string(),
            ImageProgress::CheckingCache { .. } => "check-cache".to_string(),
            ImageProgress::CacheHit { .. } => "cache-hit".to_string(),
            ImageProgress::CacheMiss { .. } => "cache-miss".to_string(),
            ImageProgress::UsingLocalDisk { .. } => "use-local-disk".to_string(),
            ImageProgress::ResolvedManifest { .. } => "resolved-manifest".to_string(),
            ImageProgress::LayerDownloadStarted { index, total, .. } => {
                format!("download-start-{index}/{total}")
            }
            ImageProgress::LayerDownloadProgress { index, total, .. } => {
                format!("download-progress-{index}/{total}")
            }
            ImageProgress::LayerDownloadVerifying { index, total, .. } => {
                format!("download-verify-{index}/{total}")
            }
            ImageProgress::LayerDownloadFinished { index, total, .. } => {
                format!("download-finish-{index}/{total}")
            }
            ImageProgress::LayerDownloadSkipped { index, total, .. } => {
                format!("download-skip-{index}/{total}")
            }
            ImageProgress::ApplyingLayer { index, total, .. } => {
                format!("apply-layer-{index}/{total}")
            }
            ImageProgress::WritingExt4 => "write-ext4".to_string(),
            ImageProgress::SavingBaseImage => "save-base-image".to_string(),
            ImageProgress::Complete => "complete".to_string(),
        }
    }
}
