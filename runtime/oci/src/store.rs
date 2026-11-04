use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{stream, StreamExt, TryStreamExt};
use oci_client::client::{BlobResponse, SizedStream};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::changeset::{ChangesetLimits, LayerInput};
use crate::digest::Sha256Digest;
use crate::lock::FileLock;
use crate::progress::{ProgressEvent, ProgressReporter};
use crate::registry::{ImageConfig, RegistryClient, ResolvedImage, ResolvedLayer};
use crate::{OciError, OciResult, Platform, RegistryPolicy};

const BLOBS_DIR_NAME: &str = "source-blobs";
const DEFAULT_ROOTFS_SIZE_BYTES: u64 = 512 * 1024 * 1024;
const PROGRESS_STEP_BYTES: u64 = 256 * 1024;
const ROOTFS_FILE_NAME: &str = "root.raw";
const TMP_DIR_NAME: &str = "tmp";

#[derive(Debug, Clone)]
pub struct MaterializeOptions {
    pub platform: Platform,
    pub materialization: Materialization,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Materialization {
    /// The requested size is a minimum. Final geometry also includes all live
    /// composed inode data and the formatter's required filesystem metadata.
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

/// Verified OCI metadata accompanying staged bytes. Never persisted by OCI.
#[derive(Debug, Clone)]
pub struct RootfsMetadata {
    pub requested_reference: String,
    pub selected_reference: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub config: ImageConfig,
    pub layers: Vec<RootfsLayerMetadata>,
    pub platform: Platform,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct RootfsLayerMetadata {
    pub blob_digest: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub diff_id: String,
}

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

/// An owned staging directory, removed on failure, cancellation, or drop.
#[derive(Debug)]
pub struct StagedRootfs {
    pub path: PathBuf,
    pub metadata: RootfsMetadata,
    _staging: StagingDir,
}

/// Caller-allocated key for disposable staging, not a retained storage operation.
#[derive(Debug, Clone)]
pub struct StagingOperation(String);

impl TryFrom<String> for StagingOperation {
    type Error = OciError;

    fn try_from(value: String) -> OciResult<Self> {
        let valid = value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                }
            });
        if !valid {
            return Err(OciError::InvalidOperationId { value });
        }
        Ok(Self(value))
    }
}

/// Registry acquisition and flattening, with no mutable image catalog.
#[derive(Debug, Clone)]
pub struct OciMaterializer {
    root: PathBuf,
    policy: RegistryPolicy,
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

impl OciMaterializer {
    pub fn open(root: impl AsRef<Path>, policy: RegistryPolicy) -> OciResult<Self> {
        Ok(Self {
            root: root.as_ref().to_path_buf(),
            policy,
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

    /// Flattens a verified resolution into owned temporary bytes for libvm publication.
    pub async fn materialize(
        &self,
        resolved: &ResolvedImage,
        options: &MaterializeOptions,
        operation: &StagingOperation,
        progress: Option<ProgressReporter>,
    ) -> OciResult<StagedRootfs> {
        if resolved.platform != options.platform {
            return Err(OciError::PlatformMismatch {
                reference: resolved.requested_reference.clone(),
                requested: options.platform.to_string(),
                actual: resolved.platform.to_string(),
            });
        }
        let Materialization::FlatExt4 { size_bytes } = options.materialization;
        if resolved.layers.len() > 1024
            || size_bytes == 0
            || size_bytes > 1024 * 1024 * 1024 * 1024
            || size_bytes % 512 != 0
        {
            return Err(OciError::ImageConfig {
                reference: resolved.requested_reference.clone(),
                message:
                    "materialization exceeds the layer/stream bounds or has invalid disk geometry"
                        .into(),
            });
        }
        self.policy.check(&resolved.reference)?;
        let registry = RegistryClient::new()?;
        registry
            .authenticate_pull(&resolved.reference, &resolved.requested_reference)
            .await?;
        self.create_rootfs(
            &registry,
            &resolved.requested_reference,
            resolved,
            options,
            operation,
            progress.as_ref(),
        )
        .await
    }

    /// Acquire and structurally verify one ordered layer occurrence. Publication
    /// and parent-dependent composition remain the caller's responsibility.
    pub async fn ingest_changeset(
        &self,
        resolved: &ResolvedImage,
        layer_index: usize,
        operation: &StagingOperation,
        limits: &crate::changeset::ChangesetLimits,
        progress: Option<ProgressReporter>,
    ) -> OciResult<crate::changeset::StagedChangeset> {
        limits.validate()?;
        if resolved.layers.len() as u64 > limits.max_layers {
            return Err(crate::changeset::ChangesetError::Limit {
                resource: "layer occurrences",
                actual: resolved.layers.len() as u64,
                maximum: limits.max_layers,
            }
            .into());
        }
        let layer = resolved.layers.get(layer_index).ok_or_else(|| {
            crate::changeset::ChangesetError::Invalid(
                "layer occurrence index outside manifest".into(),
            )
        })?;
        self.policy.check(&resolved.reference)?;
        let registry = RegistryClient::new()?;
        registry
            .authenticate_pull(&resolved.reference, &resolved.requested_reference)
            .await?;
        let path = self
            .get_or_download_layer(LayerDownloadRequest {
                registry: &registry,
                reference: &resolved.reference,
                image_ref: &resolved.requested_reference,
                layer,
                index: layer_index + 1,
                total: resolved.layers.len(),
                progress: progress.as_ref(),
            })
            .await?;
        let input = layer_input(layer)?;
        let root = self.root.clone();
        let operation = operation.clone();
        let limits = *limits;
        tokio::task::spawn_blocking(move || {
            crate::changeset::ingest_layer(&path, &input, &root, &operation, &limits)
        })
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?
        .map_err(OciError::from)
    }

    async fn resolve_remote_oci(
        &self,
        image_ref: &str,
        platform: &Platform,
        progress: Option<&ProgressReporter>,
    ) -> OciResult<ResolvedImage> {
        let mut denied = None;
        let mut missed = None;
        for reference in self.policy.candidates(image_ref)? {
            if let Err(err) = self.policy.check(&reference) {
                denied.get_or_insert(err);
                continue;
            }
            let canonical_ref = reference.to_string();
            emit_progress(
                progress,
                ProgressEvent::ResolvingManifest {
                    image_ref: canonical_ref.clone(),
                },
            );
            let resolved = match RegistryClient::new()?
                .resolve_manifest(&reference, platform)
                .await
            {
                Ok(resolved) => resolved,
                Err(err) if err.is_search_miss() => {
                    missed = Some(err);
                    continue;
                }
                Err(err) => return Err(err),
            };
            emit_progress(
                progress,
                ProgressEvent::ResolvedManifest {
                    image_ref: canonical_ref,
                    manifest_digest: resolved.manifest_digest.clone(),
                    layer_count: resolved.layers.len(),
                    total_download_bytes: total_download_bytes(&resolved.layers),
                },
            );
            return Ok(resolved);
        }
        Err(missed
            .or(denied)
            .unwrap_or_else(|| OciError::InvalidReference {
                reference: image_ref.to_string(),
                message: "no candidate references".to_string(),
            }))
    }

    async fn create_rootfs(
        &self,
        registry: &RegistryClient,
        image_ref: &str,
        resolved: &ResolvedImage,
        options: &MaterializeOptions,
        operation: &StagingOperation,
        progress: Option<&ProgressReporter>,
    ) -> OciResult<StagedRootfs> {
        let blobs = self
            .ensure_layer_blobs(registry, image_ref, resolved, progress)
            .await?;
        let metadata = RootfsMetadata {
            requested_reference: resolved.requested_reference.clone(),
            selected_reference: resolved.selected_reference.clone(),
            manifest_digest: resolved.manifest_digest.clone(),
            config_digest: resolved.config_digest.clone(),
            config: resolved.config.clone(),
            layers: resolved
                .layers
                .iter()
                .map(RootfsLayerMetadata::from)
                .collect(),
            platform: resolved.platform.clone(),
            created_at_unix: now_unix(),
        };
        let root = self.root.clone();
        let operation = operation.clone();
        let progress = progress.cloned();
        let Materialization::FlatExt4 { size_bytes } = options.materialization;
        // Retained fresh flat creation also hashes/decodes large layer files.
        // Keep that work, its temporary publication lock and cleanup on the worker.
        tokio::task::spawn_blocking(move || {
            let staging = StagingDir::create(&root, &operation)?;
            let stage_rootfs = staging.path().join(ROOTFS_FILE_NAME);
            let limits = ChangesetLimits::default();
            let mut composer = crate::changeset::namespace::NamespaceComposer::new(&limits)?;
            let mut packs = Vec::new();
            let total = blobs.len();
            for (occurrence, blob) in blobs.iter().enumerate() {
                emit_progress(
                    progress.as_ref(),
                    ProgressEvent::ApplyingLayer {
                        index: blob.index,
                        total,
                        digest: Some(blob.layer.digest.clone()),
                    },
                );
                let layer = crate::changeset::ingest_layer(
                    &blob.path,
                    &layer_input(&blob.layer)?,
                    &staging.path().join("layers").join(blob.index.to_string()),
                    &operation,
                    &limits,
                )?;
                composer = composer.apply(layer.changeset())?;
                crate::changeset::limits::reserve_vec(&mut packs, 1)?;
                packs.push(Some(layer.scope(&staging, occurrence)?));
                for body in composer.reclaimed_bodies() {
                    let slot = packs.get_mut(body.entry.layer as usize).ok_or_else(|| {
                        crate::changeset::ChangesetError::Invalid(
                            "reclaimed body has no layer occurrence".into(),
                        )
                    })?;
                    let pack = slot.as_mut().ok_or_else(|| {
                        crate::changeset::ChangesetError::Invalid(
                            "reclaimed body has no live payload pack".into(),
                        )
                    })?;
                    if !pack.discard(body.entry.ordinal) {
                        return Err(crate::changeset::ChangesetError::Invalid(
                            "reclaimed body has no admitted payload".into(),
                        )
                        .into());
                    }
                    if pack.is_empty() {
                        *slot = None;
                    }
                }
                if let Some(slot) = packs
                    .last_mut()
                    .filter(|slot| slot.as_ref().is_some_and(|pack| pack.is_empty()))
                {
                    *slot = None;
                }
            }
            let namespace = composer.finish();
            emit_progress(progress.as_ref(), ProgressEvent::MaterializingRootfs);
            crate::flat_ext4::render(&stage_rootfs, &namespace, &packs, size_bytes)?;
            drop(packs);
            Ok(StagedRootfs {
                path: stage_rootfs,
                metadata,
                _staging: staging,
            })
        })
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?
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
        let lock_path = self.blob_lock_path(&layer.digest)?;
        let digest = layer.digest.clone();
        let expected_size = layer.size_bytes;
        // Each blocking verifier owns the publication lock until it finishes,
        // including when its awaiting async task is cancelled.
        let (lock, blob_path, digest, cached) = tokio::task::spawn_blocking(move || {
            let lock = FileLock::exclusive(&lock_path)?;
            let cached = verified_blob_exists(&blob_path, &digest, expected_size)?;
            Ok::<_, OciError>((lock, blob_path, digest, cached))
        })
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))??;

        if cached {
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
            create_private_dirs(parent)?;
        }
        if let Some(parent) = part_path.parent() {
            create_private_dirs(parent)?;
        }

        let mut offset = partial_download_offset(&part_path, layer)?;
        let (lock, part_path, digest, complete_part_matches) = if offset == layer.size_bytes {
            tokio::task::spawn_blocking(move || {
                let matches = layer_digest_matches(&part_path, &digest);
                (lock, part_path, digest, matches)
            })
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
        } else {
            (lock, part_path, digest, Ok(false))
        };
        if complete_part_matches? {
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
        let (_lock, part_path) = tokio::task::spawn_blocking(move || {
            verify_layer_file(&part_path, &digest, expected_size)?;
            Ok::<_, OciError>((lock, part_path))
        })
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))??;
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
            .join("locks/publication")
            .join(format!("source-{}-{}.lock", algorithm, encoded)))
    }
}

fn create_private_dirs(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
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
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .await?;
    let mut downloaded = start_offset;
    let mut last_progress = start_offset;

    while let Some(chunk) = stream.try_next().await? {
        let actual = downloaded.saturating_add(chunk.len() as u64);
        if actual > layer.size_bytes {
            drop(file);
            remove_file_if_exists(path)?;
            return Err(OciError::LayerSizeMismatch {
                digest: layer.digest.clone(),
                path: path.to_path_buf(),
                expected: layer.size_bytes,
                actual,
            });
        }
        file.write_all(&chunk).await?;
        downloaded = actual;
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
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err.into()),
    };
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "partial OCI input is not a regular file",
        )
        .into());
    }

    let size = metadata.len();
    if size > layer.size_bytes {
        remove_file_if_exists(path)?;
        return Ok(0);
    }
    Ok(size)
}

fn verified_blob_exists(path: &Path, digest: &str, expected_size: u64) -> OciResult<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    if !metadata.is_file() {
        remove_file_if_exists(path)?;
        return Ok(false);
    }
    if metadata.len() != expected_size {
        return Err(OciError::LayerSizeMismatch {
            digest: digest.into(),
            path: path.into(),
            expected: expected_size,
            actual: metadata.len(),
        });
    }
    if layer_digest_matches(path, digest)? {
        return Ok(true);
    }
    remove_file_if_exists(path)?;
    Ok(false)
}

fn verify_layer_file(path: &Path, digest: &str, expected_size: u64) -> OciResult<()> {
    let actual_size = fs::metadata(path)?.len();
    if actual_size != expected_size {
        remove_file_if_exists(path)?;
        return Err(OciError::LayerSizeMismatch {
            digest: digest.into(),
            path: path.to_path_buf(),
            expected: expected_size,
            actual: actual_size,
        });
    }

    let actual_digest = sha256_file(path)?;
    let expected_digest = Sha256Digest::parse(digest)?;
    if actual_digest != expected_digest {
        remove_file_if_exists(path)?;
        return Err(OciError::LayerDigestMismatch {
            digest: digest.into(),
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
        create_private_dirs(parent)?;
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

fn layer_input(layer: &ResolvedLayer) -> OciResult<LayerInput> {
    Ok(LayerInput {
        blob_digest: layer.digest.parse()?,
        media_type: layer.media_type.clone(),
        size_bytes: layer.size_bytes,
        diff_id: layer.diff_id.parse()?,
    })
}

fn digest_path_components(digest: &str) -> OciResult<(&'static str, String)> {
    Ok(("sha256", Sha256Digest::parse(digest)?.hex()))
}

fn open_source_blob(path: &Path) -> OciResult<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OCI input is not a regular file",
        )
        .into());
    }
    Ok(file)
}

fn sha256_file(path: &Path) -> OciResult<Sha256Digest> {
    let mut file = open_source_blob(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
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

fn now_unix() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    seconds.min(i64::MAX as u64) as i64
}

#[derive(Debug)]
pub(crate) struct StagingDir {
    path: PathBuf,
    _lease: FileLock,
}

impl StagingDir {
    pub(crate) fn create(root: &Path, operation: &StagingOperation) -> OciResult<Self> {
        use std::os::unix::fs::DirBuilderExt;
        // OCI owns only unpublished temporary bytes. Canonical generation
        // leases and durable semantic roots belong to the runtime catalog.
        let name = format!("stage-{}", operation.0);
        let lease = FileLock::shared(&root.join("locks/publication").join(format!("{name}.lock")))?;
        let parent = root.join(TMP_DIR_NAME);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)?;
        let path = parent.join(&name);
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self {
            path,
            _lease: lease,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use crate::registry::ResolvedLayer;
    use crate::store::{
        digest_path_components, layer_download_concurrency, sha256_bytes, verified_blob_exists,
        verify_layer_file, OciMaterializer, StagingDir,
    };
    use crate::{OciError, Platform, RegistryAction, RegistryPolicy};
    use std::io::Read;

    fn operation(index: u64) -> crate::StagingOperation {
        crate::StagingOperation::try_from(format!("00000000-0000-4000-8000-{index:012x}")).unwrap()
    }

    fn append_test_file(builder: &mut tar::Builder<Vec<u8>>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }

    fn test_tar(path: &str, bytes: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        append_test_file(&mut builder, path, bytes);
        builder.into_inner().unwrap()
    }

    fn materialize_cached_layers(
        root: &std::path::Path,
        layers: Vec<(&str, Vec<u8>, Option<String>)>,
        minimum_size: u64,
    ) -> crate::OciResult<crate::StagedRootfs> {
        let producer = OciMaterializer::open(root, RegistryPolicy::default()).unwrap();
        let reference = "example.invalid/flat:fixture";
        let layers = layers
            .into_iter()
            .map(|(media_type, bytes, diff_id)| {
                let digest = format!("sha256:{}", sha256_bytes(&bytes));
                let blob = producer.blob_path(&digest).unwrap();
                std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
                std::fs::write(&blob, &bytes).unwrap();
                ResolvedLayer {
                    diff_id: diff_id.unwrap_or_else(|| digest.clone()),
                    digest,
                    media_type: media_type.into(),
                    size_bytes: bytes.len() as u64,
                }
            })
            .collect();
        let resolved = crate::registry::ResolvedImage {
            requested_reference: reference.into(),
            selected_reference: reference.into(),
            manifest_digest: format!("sha256:{}", sha256_bytes(b"fixture manifest")),
            config_digest: format!("sha256:{}", sha256_bytes(b"fixture config")),
            config: crate::registry::ImageConfig::default(),
            platform: Platform::linux_amd64(),
            reference: crate::registry::RegistryClient::parse_reference(reference).unwrap(),
            layers,
        };
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(
                producer.create_rootfs(
                    &crate::registry::RegistryClient::new().unwrap(),
                    reference,
                    &resolved,
                    &crate::MaterializeOptions::new(Platform::linux_amd64())
                        .with_flat_ext4_size_bytes(minimum_size),
                    &operation(101),
                    None,
                ),
            )
    }

    fn flat_inode_xattrs(
        image: &std::path::Path,
        inode: &disk_image::ext4::types::Inode,
    ) -> std::collections::BTreeMap<(u8, Vec<u8>), Vec<u8>> {
        use std::io::{Seek, SeekFrom};

        fn entries(
            bytes: &[u8],
            mut offset: usize,
            value_base: usize,
            output: &mut std::collections::BTreeMap<(u8, Vec<u8>), Vec<u8>>,
        ) {
            assert_eq!(&bytes[..4], &0xea02_0000_u32.to_le_bytes());
            while bytes[offset..offset + 4] != [0; 4] {
                let name_length = usize::from(bytes[offset]);
                let index = bytes[offset + 1];
                let value_offset = usize::from(u16::from_le_bytes(
                    bytes[offset + 2..offset + 4].try_into().unwrap(),
                ));
                let value_length =
                    u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
                let name = bytes[offset + 16..offset + 16 + name_length].to_vec();
                let start = value_base + value_offset;
                assert!(output
                    .insert((index, name), bytes[start..start + value_length].to_vec())
                    .is_none());
                offset += (16 + name_length + 3) & !3;
            }
        }

        let mut result = std::collections::BTreeMap::new();
        if inode.inline_xattrs[..4] != [0; 4] {
            entries(&inode.inline_xattrs, 4, 4, &mut result);
        }
        let block = u64::from(inode.xattr_block_lo) | (u64::from(inode.xattr_block_hi) << 32);
        if block != 0 {
            let mut file = std::fs::File::open(image).unwrap();
            file.seek(SeekFrom::Start(block * 4096)).unwrap();
            let mut bytes = [0; 4096];
            file.read_exact(&mut bytes).unwrap();
            entries(&bytes, 32, 0, &mut result);
        }
        result
    }

    #[test]
    fn production_flat_materialization_preserves_acl_capability_and_hardlink_metadata() {
        use base64::Engine;
        use std::io::Cursor;

        let temp = tempfile::tempdir().unwrap();
        let mut archive = tar::Builder::new(Vec::new());
        let near_limit = vec![b'x'; 2750];
        archive
            .append_pax_extensions([
                ("SCHILY.xattr.user.near-limit", near_limit.as_slice()),
                (
                    "SCHILY.acl.access",
                    b"user::rw-,user:1234:r--,group::r--,mask::r--,other::r--".as_slice(),
                ),
            ])
            .unwrap();
        let mut file = tar::Header::new_gnu();
        file.set_mode(0o644);
        file.set_uid(0);
        file.set_gid(0);
        file.set_mtime(42);
        file.set_size(b"original-hardlink\n".len() as u64);
        file.set_cksum();
        archive
            .append_data(
                &mut file,
                "overlay-fixture/a",
                Cursor::new(b"original-hardlink\n"),
            )
            .unwrap();
        let mut link = tar::Header::new_gnu();
        link.set_mode(0o700);
        link.set_uid(99);
        link.set_gid(98);
        link.set_mtime(17);
        link.set_size(0);
        link.set_entry_type(tar::EntryType::Link);
        archive
            .append_link(&mut link, "overlay-fixture/b", "overlay-fixture/a")
            .unwrap();
        let capability = [1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let capability_text = base64::engine::general_purpose::STANDARD.encode(capability);
        archive
            .append_pax_extensions([(
                "LIBARCHIVE.xattr.security.capability",
                capability_text.as_bytes(),
            )])
            .unwrap();
        file.set_size(b"capability".len() as u64);
        file.set_cksum();
        archive
            .append_data(
                &mut file,
                "overlay-fixture/capability",
                Cursor::new(b"capability"),
            )
            .unwrap();
        let bytes = archive.into_inner().unwrap();
        let staged = materialize_cached_layers(
            temp.path(),
            vec![("application/vnd.oci.image.layer.v1.tar", bytes, None)],
            64 * 1024 * 1024,
        )
        .unwrap();
        let mut reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
        let node = reader.tree().lookup(b"/overlay-fixture/a").unwrap();
        let number = reader.tree().node(node).inode;
        let inode = reader.get_inode(number).unwrap();
        let attrs = flat_inode_xattrs(&staged.path, &inode);
        assert_eq!(
            attrs.get(&(1, b"near-limit".to_vec())),
            Some(&near_limit),
            "production-created lower must retain the source user xattr"
        );
        // ext4's on-disk ACL v1 has short object records, unlike the Linux API
        // xattr v2 retained by the normalized changeset.
        let disk_acl = vec![
            1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 4, 0, 210, 4, 0, 0, 4, 0, 4, 0, 16, 0, 4, 0, 32, 0, 4, 0,
        ];
        assert_eq!(attrs.get(&(2, Vec::new())), Some(&disk_acl));
        assert_eq!(
            reader.hardlinks.get(b"overlay-fixture/b".as_slice()),
            Some(&number)
        );
        assert_eq!(inode.links_count, 2);
        assert_eq!(inode.mode & 0o7777, 0o644);
        assert_eq!(inode.uid_full(), 0);
        assert_eq!(inode.gid_full(), 0);
        assert_eq!(inode.mtime, 42);
        assert_eq!(
            reader.read_file("/overlay-fixture/a", 0, None).unwrap(),
            b"original-hardlink\n"
        );
        let node = reader
            .tree()
            .lookup(b"/overlay-fixture/capability")
            .unwrap();
        let number = reader.tree().node(node).inode;
        let inode = reader.get_inode(number).unwrap();
        assert_eq!(
            flat_inode_xattrs(&staged.path, &inode).get(&(6, b"capability".to_vec())),
            Some(&capability.to_vec())
        );
    }

    #[test]
    fn production_flat_materialization_composes_whiteouts_aliases_and_source_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let mut lower = tar::Builder::new(Vec::new());
        append_test_file(&mut lower, "d/old", b"old");
        append_test_file(&mut lower, "d/keep", b"keep");
        append_test_file(&mut lower, "target", b"original");
        let mut link = tar::Header::new_gnu();
        link.set_mode(0o777);
        link.set_uid(0);
        link.set_gid(0);
        link.set_mtime(1);
        link.set_size(0);
        link.set_entry_type(tar::EntryType::Link);
        lower.append_link(&mut link, "alias", "target").unwrap();
        let mut link = tar::Header::new_gnu();
        link.set_mode(0o777);
        link.set_uid(0);
        link.set_gid(0);
        link.set_mtime(1);
        link.set_size(0);
        link.set_entry_type(tar::EntryType::Symlink);
        lower.append_link(&mut link, "dirlink", "d").unwrap();
        let mut upper = tar::Builder::new(Vec::new());
        // Markers apply to untouched lower objects, not this layer's new ones.
        append_test_file(&mut upper, "dirlink/new", b"new");
        append_test_file(&mut upper, "d/.wh..wh..opq", b"");
        append_test_file(&mut upper, "d/.wh.old", b"");
        append_test_file(&mut upper, "target", b"replacement");
        upper
            .append_pax_extensions([
                ("SCHILY.xattr.user.root", b"\0\xff".as_slice()),
                ("mtime", b"2147483648.123456789".as_slice()),
            ])
            .unwrap();
        let mut directory = tar::Header::new_gnu();
        directory.set_entry_type(tar::EntryType::Directory);
        directory.set_mode(0o710);
        directory.set_uid(54);
        directory.set_gid(56);
        directory.set_mtime(2);
        directory.set_size(0);
        directory.set_cksum();
        upper
            .append_data(&mut directory, ".", std::io::empty())
            .unwrap();
        let mut owned = tar::Header::new_gnu();
        owned.set_mode(0o6754);
        owned.set_uid(0x1234_5678);
        owned.set_gid(0x9abc_def0);
        owned.set_mtime(7);
        owned.set_size(5);
        owned.set_cksum();
        upper
            .append_data(&mut owned, "d/owned", b"owned".as_slice())
            .unwrap();
        upper
            .append_pax_extensions([("SCHILY.xattr.user.directory", b"final".as_slice())])
            .unwrap();
        directory.set_mode(0o750);
        directory.set_uid(68);
        directory.set_gid(69);
        directory.set_mtime(9);
        directory.set_cksum();
        upper
            .append_data(&mut directory, "d", std::io::empty())
            .unwrap();
        let staged = materialize_cached_layers(
            temp.path(),
            vec![
                (
                    "application/vnd.oci.image.layer.v1.tar",
                    lower.into_inner().unwrap(),
                    None,
                ),
                (
                    "application/vnd.oci.image.layer.v1.tar",
                    upper.into_inner().unwrap(),
                    None,
                ),
            ],
            64 * 1024 * 1024,
        )
        .unwrap();
        let mut reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
        assert!(!reader.exists("d/old"));
        assert!(!reader.exists("d/keep"));
        assert!(!reader.exists("lost+found"));
        assert_eq!(reader.read_file("d/new", 0, None).unwrap(), b"new");
        assert_eq!(reader.read_file("dirlink/new", 0, None).unwrap(), b"new");
        assert_eq!(reader.read_file("alias", 0, None).unwrap(), b"original");
        assert_eq!(reader.read_file("target", 0, None).unwrap(), b"replacement");
        assert_ne!(
            reader.stat("alias").unwrap().0,
            reader.stat("target").unwrap().0
        );
        let inode = reader.stat("d/owned").unwrap().1;
        assert_eq!(inode.mode & 0o7777, 0o6754);
        assert_eq!(inode.uid_full(), 0x1234_5678);
        assert_eq!(inode.gid_full(), 0x9abc_def0);
        assert_eq!(inode.mtime, 7);
        let root = reader.stat("/").unwrap().1;
        assert_eq!(root.mode & 0o7777, 0o710);
        assert_eq!(root.uid_full(), 54);
        assert_eq!(root.gid_full(), 56);
        assert_eq!(root.mtime, 0x8000_0000);
        assert_eq!(root.mtime_extra, (123_456_789 << 2) | 1);
        assert_eq!(
            flat_inode_xattrs(&staged.path, &root).get(&(1, b"root".to_vec())),
            Some(&vec![0, 255])
        );
        let directory = reader.stat("d").unwrap().1;
        assert_eq!(directory.mode & 0o7777, 0o750);
        assert_eq!(directory.uid_full(), 68);
        assert_eq!(directory.gid_full(), 69);
        assert_eq!(directory.mtime, 9);
        assert_eq!(
            flat_inode_xattrs(&staged.path, &directory).get(&(1, b"directory".to_vec())),
            Some(&b"final".to_vec())
        );
    }

    #[test]
    fn production_flat_materialization_preserves_raw_names_targets_and_special_inodes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::path::PathBuf;

        let temp = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("LIBARCHIVE.xattr.user.%FF", b"AP8K".as_slice())])
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_size(3);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                PathBuf::from(OsString::from_vec(b"raw-\xff".to_vec())),
                b"raw".as_slice(),
            )
            .unwrap();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_path("symlink").unwrap();
        header.set_link_name_literal(b"raw-\xff").unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
        for (path, kind, major, minor) in [
            ("char", tar::EntryType::Char, 0xfff, 0xfffff),
            ("block", tar::EntryType::Block, 0xabc, 0xcdef),
            ("fifo", tar::EntryType::Fifo, 0, 0),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o600);
            header.set_uid(23);
            header.set_gid(24);
            header.set_mtime(3);
            header.set_size(0);
            header.set_entry_type(kind);
            header.set_device_major(major).unwrap();
            header.set_device_minor(minor).unwrap();
            header.set_cksum();
            builder
                .append_data(&mut header, path, std::io::empty())
                .unwrap();
        }
        builder
            .append_pax_extensions([("SCHILY.filetype", b"socket".as_slice())])
            .unwrap();
        append_test_file(&mut builder, "socket", b"");
        let staged = materialize_cached_layers(
            temp.path(),
            vec![(
                "application/vnd.oci.image.layer.v1.tar",
                builder.into_inner().unwrap(),
                None,
            )],
            64 * 1024 * 1024,
        )
        .unwrap();
        let mut reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
        assert_eq!(reader.read_file(b"raw-\xff", 0, None).unwrap(), b"raw");
        assert_eq!(reader.read_link("symlink").unwrap(), b"raw-\xff");
        assert_eq!(reader.read_file("symlink", 0, None).unwrap(), b"raw");
        assert_eq!(
            reader
                .xattrs(b"raw-\xff")
                .unwrap()
                .get(b"user.\xff".as_slice()),
            Some(&vec![0, 255, 10])
        );
        for (path, kind, major, minor) in [
            ("char", 0o020000, 0xfff_u32, 0xfffff_u32),
            ("block", 0o060000, 0xabc, 0xcdef),
        ] {
            let inode = reader.stat_no_follow(path).unwrap().1;
            assert_eq!(inode.mode, kind | 0o600);
            assert_eq!(inode.uid_full(), 23);
            assert_eq!(inode.gid_full(), 24);
            let encoded = u32::from_le_bytes(inode.block[4..8].try_into().unwrap());
            assert_eq!(inode.block[..4], [0; 4]);
            assert_eq!(
                encoded,
                (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
            );
        }
        assert_eq!(reader.stat_no_follow("fifo").unwrap().1.mode, 0o010600);
        assert_eq!(reader.stat_no_follow("socket").unwrap().1.mode, 0o140644);
    }

    #[test]
    fn production_flat_materialization_preserves_sparse_logical_bytes_without_allocating_holes() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let length = 256 * 1024 * 1024 + 17;
        let size = length.to_string();
        let map = format!("0,1,{},1", length - 1);
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([
                ("GNU.sparse.size", size.as_bytes()),
                ("GNU.sparse.numblocks", b"2".as_slice()),
                ("GNU.sparse.map", map.as_bytes()),
            ])
            .unwrap();
        append_test_file(&mut builder, "sparse", b"AB");
        let staged = materialize_cached_layers(
            temp.path(),
            vec![(
                "application/vnd.oci.image.layer.v1.tar",
                builder.into_inner().unwrap(),
                None,
            )],
            64 * 1024 * 1024,
        )
        .unwrap();
        let metadata = std::fs::metadata(&staged.path).unwrap();
        assert!(
            metadata.len() < length as u64,
            "sizing uses stored data, not the logical hole"
        );
        assert!(metadata.blocks() * 512 < 32 * 1024 * 1024);
        let mut reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
        let inode = reader.stat("sparse").unwrap().1;
        assert_eq!(inode.file_size(), length as u64);
        assert_eq!(reader.read_file("sparse", 0, Some(2)).unwrap(), b"A\0");
        assert_eq!(
            reader
                .read_file("sparse", length as u64 - 2, Some(2))
                .unwrap(),
            b"\0B"
        );
        assert_eq!(
            reader
                .read_file("sparse", 128 * 1024 * 1024, Some(4096))
                .unwrap(),
            vec![0; 4096]
        );
    }

    #[test]
    fn production_flat_materialization_rejects_malformed_layers_and_forward_links_atomically() {
        let mut malformed = Vec::new();
        for (key, value) in [
            ("path", b"../escape".as_slice()),
            ("path", b"nul\0suffix".as_slice()),
            ("SCHILY.xattr.trusted.overlay.opaque", b"y".as_slice()),
        ] {
            let mut builder = tar::Builder::new(Vec::new());
            builder.append_pax_extensions([(key, value)]).unwrap();
            append_test_file(&mut builder, "placeholder", b"x");
            malformed.push(builder.into_inner().unwrap());
        }
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("linkpath", b"target\0suffix".as_slice())])
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o777);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        builder.append_link(&mut header, "link", "target").unwrap();
        malformed.push(builder.into_inner().unwrap());
        malformed.push(test_tar(".wh.", b""));
        let mut builder = tar::Builder::new(Vec::new());
        header.set_entry_type(tar::EntryType::Link);
        builder.append_link(&mut header, "link", "target").unwrap();
        append_test_file(&mut builder, "target", b"x");
        malformed.push(builder.into_inner().unwrap());
        for bytes in malformed {
            let temp = tempfile::tempdir().unwrap();
            let result = materialize_cached_layers(
                temp.path(),
                vec![("application/vnd.oci.image.layer.v1.tar", bytes, None)],
                64 * 1024 * 1024,
            );
            assert!(matches!(
                result,
                Err(OciError::Changeset(_)) | Err(OciError::Namespace(_))
            ));
            assert!(!temp
                .path()
                .join("tmp")
                .join(format!("stage-{}", operation(101).0))
                .exists());
            assert!(!temp.path().join("escape").exists());
        }
    }

    #[test]
    fn source_blob_paths_are_content_addressed() {
        let temp = tempfile::tempdir().unwrap();
        let producer = OciMaterializer::open(temp.path(), RegistryPolicy::default()).unwrap();
        let hash = sha256_bytes(b"layer");
        assert_eq!(
            producer.blob_path(&format!("sha256:{hash}")).unwrap(),
            temp.path().join("source-blobs/sha256").join(hash)
        );
        assert!(digest_path_components("sha512:bad").is_err());
    }

    #[test]
    fn corrupt_source_blob_is_removed_before_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("blob");
        std::fs::write(&path, b"wrong").unwrap();
        assert!(
            !verified_blob_exists(&path, &format!("sha256:{}", sha256_bytes(b"right")), 5).unwrap()
        );
        assert!(!path.exists());
    }

    #[test]
    fn staging_cleanup_does_not_remove_other_operations() {
        let temp = tempfile::tempdir().unwrap();
        let first = StagingDir::create(temp.path(), &operation(1)).unwrap();
        let second = StagingDir::create(temp.path(), &operation(2)).unwrap();
        let path = first.path().to_owned();
        std::fs::write(path.join("root.raw"), b"staged").unwrap();
        drop(first);
        assert!(!path.exists());
        assert!(second.path().is_dir());
    }

    #[test]
    fn denied_resolution_does_not_create_local_state_or_contact_registry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent");
        let policy =
            RegistryPolicy::new(RegistryAction::Deny, vec!["docker.io".into()], vec![]).unwrap();
        let producer = OciMaterializer::open(&root, policy).unwrap();
        let result = futures_util::FutureExt::now_or_never(producer.resolve(
            "example.test/demo:latest",
            &Platform::linux_amd64(),
            None,
        ))
        .expect("policy rejection must complete synchronously");
        assert!(result.is_err());
        assert!(!root.exists());
    }

    #[test]
    fn production_flat_materialization_decodes_all_supported_media_types() {
        use std::io::Write;

        let payload = b"layer contents from a real compressed file\n";
        let raw = test_tar("contents", payload);
        let diff_id = format!("sha256:{}", sha256_bytes(&raw));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).unwrap();
        let gzip = encoder.finish().unwrap();
        let zstd = zstd::stream::encode_all(raw.as_slice(), 0).unwrap();
        for (media_type, bytes) in [
            ("application/vnd.oci.image.layer.v1.tar", &raw),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar",
                &raw,
            ),
            ("application/vnd.docker.image.rootfs.diff.tar", &raw),
            ("application/vnd.oci.image.layer.v1.tar+gzip", &gzip),
            ("application/vnd.docker.image.rootfs.diff.tar.gzip", &gzip),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                &gzip,
            ),
            ("application/vnd.oci.image.layer.v1.tar+zstd", &zstd),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
                &zstd,
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let staged = materialize_cached_layers(
                temp.path(),
                vec![(media_type, bytes.clone(), Some(diff_id.clone()))],
                64 * 1024 * 1024,
            )
            .unwrap();
            let mut reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
            assert_eq!(
                reader.read_file("contents", 0, None).unwrap(),
                payload,
                "{media_type}"
            );
        }
    }

    #[test]
    fn production_flat_materialization_rejects_unsupported_media_type_and_cleans_staging() {
        let temp = tempfile::tempdir().unwrap();
        let result = materialize_cached_layers(
            temp.path(),
            vec![(
                "application/vnd.example.layer.v1.tar",
                test_tar("contents", b"x"),
                None,
            )],
            64 * 1024 * 1024,
        );
        assert!(matches!(
            result,
            Err(OciError::Changeset(
                crate::changeset::ChangesetError::Unsupported(_)
            ))
        ));
        assert!(!temp
            .path()
            .join("tmp")
            .join(format!("stage-{}", operation(101).0))
            .exists());
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

        let err = verify_layer_file(&path, &layer.digest, layer.size_bytes)
            .expect_err("digest mismatch should fail");

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

        verify_layer_file(&path, &layer.digest, layer.size_bytes)
            .expect("matching digest should pass");

        assert!(path.exists());
    }

    #[test]
    fn production_flat_materialization_hashes_padding_and_every_gzip_member() {
        use std::io::Write;

        let padding = vec![0_u8; 2048];
        let suffix = vec![0_u8; 1024];
        let mut decoded = padding.clone();
        decoded.extend_from_slice(&suffix);
        let mut compressed = Vec::new();
        for bytes in [padding.as_slice(), suffix.as_slice()] {
            let mut member =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            member.write_all(bytes).unwrap();
            compressed.extend(member.finish().unwrap());
        }
        let temp = tempfile::tempdir().unwrap();
        let staged = materialize_cached_layers(
            temp.path(),
            vec![(
                "application/vnd.oci.image.layer.v1.tar+gzip",
                compressed.clone(),
                Some(format!("sha256:{}", sha256_bytes(&decoded))),
            )],
            64 * 1024 * 1024,
        )
        .unwrap();
        drop(staged);
        let result = materialize_cached_layers(
            temp.path(),
            vec![(
                "application/vnd.oci.image.layer.v1.tar+gzip",
                compressed,
                Some(format!("sha256:{}", sha256_bytes(&padding))),
            )],
            64 * 1024 * 1024,
        );
        assert!(matches!(
            result,
            Err(OciError::Changeset(
                crate::changeset::ChangesetError::Invalid(_)
            ))
        ));
        assert!(!temp
            .path()
            .join("tmp")
            .join(format!("stage-{}", operation(101).0))
            .exists());
    }

    #[test]
    fn source_symlinks_cannot_redirect_cache_reads_or_partial_writes() {
        let temp = tempfile::tempdir().unwrap();
        let external = temp.path().join("external");
        let link = temp.path().join("layer.part");
        std::fs::write(&external, b"right").unwrap();
        std::os::unix::fs::symlink(&external, &link).unwrap();
        let layer = ResolvedLayer {
            digest: format!("sha256:{}", sha256_bytes(b"right")),
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            size_bytes: 5,
            diff_id: format!("sha256:{}", sha256_bytes(b"right")),
        };
        assert!(crate::store::partial_download_offset(&link, &layer).is_err());
        assert!(crate::store::open_source_blob(&link).is_err());
        assert!(!verified_blob_exists(&link, &layer.digest, layer.size_bytes).unwrap());
        assert_eq!(std::fs::read(&external).unwrap(), b"right");
        assert!(!link.exists());
    }

    #[test]
    fn invalid_flatten_geometry_fails_before_registry_or_staging() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent");
        let producer = OciMaterializer::open(&root, RegistryPolicy::default()).unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        let reference = format!("example.invalid/demo@{digest}");
        let image = crate::ResolvedImage {
            requested_reference: reference.clone(),
            selected_reference: reference.clone(),
            manifest_digest: digest.clone(),
            config_digest: digest,
            config: crate::ImageConfig::default(),
            platform: Platform::linux_amd64(),
            reference: reference.parse().unwrap(),
            layers: Vec::new(),
        };
        for size in [0, 513, (1_u64 << 40) + 512] {
            let options = crate::MaterializeOptions::new(Platform::linux_amd64())
                .with_flat_ext4_size_bytes(size);
            let result = futures_util::FutureExt::now_or_never(producer.materialize(
                &image,
                &options,
                &operation(1),
                None,
            ))
            .expect("invalid geometry cannot wait on a registry");
            assert!(matches!(result, Err(OciError::ImageConfig { .. })));
        }
        assert!(!root.exists());
    }
    #[test]
    fn cached_source_requires_exact_descriptor_size_even_when_digest_matches() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("blob");
        std::fs::write(&path, b"right").unwrap();
        let digest = format!("sha256:{}", sha256_bytes(b"right"));
        assert!(matches!(
            verified_blob_exists(&path, &digest, 4),
            Err(OciError::LayerSizeMismatch {
                expected: 4,
                actual: 5,
                ..
            })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"right");
        assert!(verified_blob_exists(&path, &digest, 5).unwrap());
    }

    #[test]
    fn staged_bytes_hold_only_a_temporary_publication_lock() {
        use nix::fcntl::{Flock, FlockArg};
        let temp = tempfile::tempdir().unwrap();
        let operation = operation(1);
        let staging = StagingDir::create(temp.path(), &operation).unwrap();
        assert!(!temp.path().join("locks/leases").exists());
        let path = temp
            .path()
            .join("locks/publication")
            .join(format!("stage-{}.lock", operation.0));
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(Flock::lock(contender, FlockArg::LockExclusiveNonblock).is_err());
        drop(staging);
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert!(Flock::lock(contender, FlockArg::LockExclusiveNonblock).is_ok());
        for invalid in ["../escape", "00000000-0000-4000-8000-00000000000A"] {
            assert!(crate::StagingOperation::try_from(invalid.to_string()).is_err());
        }
    }

    #[test]
    fn source_blob_checksum_and_verification_fit_a_small_thread_stack() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("blob");
        let bytes = vec![0x5a; 128 * 1024 + 113];
        std::fs::write(&path, &bytes).unwrap();
        let digest = crate::digest::Sha256Digest::from_bytes(&bytes).to_string();
        let size = bytes.len() as u64;
        let empty = temp.path().join("empty");
        std::fs::write(&empty, []).unwrap();
        let empty_digest = crate::digest::Sha256Digest::from_bytes(&[]).to_string();
        std::thread::Builder::new()
            .name("small-stack-source-verification".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                assert!(verified_blob_exists(&path, &digest, size).unwrap());
                verify_layer_file(&path, &digest, size).unwrap();
                assert!(crate::store::layer_digest_matches(&path, &digest).unwrap());
                assert!(verified_blob_exists(&empty, &empty_digest, 0).unwrap());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn cancelled_source_verification_waiter_does_not_release_worker_publication_lock() {
        use nix::fcntl::{Flock, FlockArg};
        use std::sync::mpsc;
        use std::time::Duration;
        struct NotifyOnDrop(Option<tokio::sync::oneshot::Sender<bool>>, bool);
        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(self.1);
                }
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let bytes = vec![0x5a; 2 * 1024 * 1024 + 113];
        std::fs::write(&source, &bytes).unwrap();
        let digest = crate::digest::Sha256Digest::from_bytes(&bytes).to_string();
        let size = bytes.len() as u64;
        let lock_path = temp.path().join("locks/publication/source.lock");
        let worker_lock = lock_path.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let waiter = tokio::spawn(async move {
                tokio::task::spawn_blocking(move || {
                    let _lock = crate::lock::FileLock::exclusive(&worker_lock).unwrap();
                    // Deterministically pause the real verification worker
                    // after lock acquisition, before its full-file checksum.
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    let result = crate::store::verified_blob_exists(&source, &digest, size);
                    let verified = matches!(&result, Ok(true));
                    (result, NotifyOnDrop(Some(done_tx), verified))
                })
                .await
            });
            // A blocking receive here would prevent this current-thread
            // runtime from ever polling the waiter that launches the worker.
            started_rx.await.unwrap();
            waiter.abort();
            assert!(matches!(waiter.await,Err(error) if error.is_cancelled()));
            let contender = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .unwrap();
            assert!(Flock::lock(contender, FlockArg::LockExclusiveNonblock).is_err());
            release_tx.send(()).unwrap();
            assert!(done_rx.await.unwrap());
            let contender = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .unwrap();
            let _exclusive = Flock::lock(contender, FlockArg::LockExclusiveNonblock).unwrap();
        });
    }

    #[test]
    fn production_flat_materialization_handles_empty_inputs_without_leaking_scoped_packs() {
        for layers in [
            Vec::new(),
            vec![(
                "application/vnd.oci.image.layer.v1.tar",
                vec![0; 1024],
                None,
            )],
        ] {
            let temp = tempfile::tempdir().unwrap();
            let staged = materialize_cached_layers(temp.path(), layers, 64 * 1024 * 1024).unwrap();
            let mut reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
            assert!(reader.list_dir("/").unwrap().is_empty());
            let root = reader.stat("/").unwrap().1;
            assert_eq!(root.mode & 0o7777, 0o755);
            assert_eq!(root.mtime, 0);
            let directory = staged.path.parent().unwrap();
            assert!(!std::fs::read_dir(directory).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b"layer-")
            }));
            let root_path = staged.path.clone();
            drop(staged);
            assert!(!root_path.exists());
        }
    }

    #[test]
    fn production_flat_materialization_refuses_unrepresentable_symlinks_after_normalized_admission()
    {
        for length in [4095, 4096] {
            let temp = tempfile::tempdir().unwrap();
            let target = vec![b't'; length];
            let mut builder = tar::Builder::new(Vec::new());
            builder
                .append_pax_extensions([("linkpath", target.as_slice())])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o777);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1);
            header.set_size(0);
            builder
                .append_link(&mut header, "link", "placeholder")
                .unwrap();
            let bytes = builder.into_inner().unwrap();
            let source = temp.path().join("source.tar");
            std::fs::write(&source, &bytes).unwrap();
            let digest = crate::changeset::ContentDigest::of_bytes(&bytes);
            let admitted = crate::changeset::ingest_layer(
                &source,
                &crate::changeset::LayerInput {
                    blob_digest: digest,
                    media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                    size_bytes: bytes.len() as u64,
                    diff_id: digest,
                },
                &temp.path().join("normalized"),
                &operation(101),
                &crate::changeset::ChangesetLimits::default(),
            )
            .unwrap();
            assert!(
                matches!(
                    &admitted.changeset().entries[0].kind,
                    crate::changeset::EntryKind::Symlink { target: actual } if actual == &target
                ),
                "normalized admission retains both boundary inputs unchanged"
            );
            drop(admitted);
            let result = materialize_cached_layers(
                temp.path(),
                vec![("application/vnd.oci.image.layer.v1.tar", bytes, None)],
                64 * 1024 * 1024,
            );
            if length == 4095 {
                let staged = result.unwrap();
                let mut reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
                assert_eq!(reader.read_link("link").unwrap(), target);
                drop(staged);
            } else {
                assert!(matches!(result, Err(OciError::FlatExt4 { .. })));
            }
            assert!(!temp
                .path()
                .join("tmp")
                .join(format!("stage-{}", operation(101).0))
                .exists());
        }
    }
}
