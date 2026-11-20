use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use futures_util::{stream, StreamExt, TryStreamExt};
use oci_client::client::{BlobResponse, SizedStream};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::changeset::LayerInput;
use crate::digest::Sha256Digest;
use crate::lock::FileLock;
use crate::progress::{ProgressEvent, ProgressReporter};
use crate::registry::{ImageConfig, RegistryClient, ResolvedImage, ResolvedLayer};
use crate::{OciError, OciResult, Platform, RegistryPolicy};

const BLOBS_DIR_NAME: &str = "source-blobs";
const PROGRESS_STEP_BYTES: u64 = 256 * 1024;
const TMP_DIR_NAME: &str = "tmp";
// Matches Docker's default max-concurrent-downloads.
const MAX_CONCURRENT_DOWNLOADS: usize = 3;

#[derive(Debug, Clone)]
pub struct MaterializeOptions {
    pub platform: Platform,
}

impl MaterializeOptions {
    pub fn new(platform: Platform) -> Self {
        Self { platform }
    }

    pub fn for_host() -> OciResult<Self> {
        Ok(Self::new(Platform::host()?))
    }
}

/// Verified OCI metadata accompanying retained layers. Never persisted by OCI.
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

/// Registry resolution and verified layer acquisition, with no mutable image catalog.
#[derive(Debug, Clone)]
pub struct OciMaterializer {
    root: PathBuf,
    policy: RegistryPolicy,
}

/// One pull's verified compressed blobs. Drive `prefetch` alongside ordered
/// `ingest_changeset` calls; dropping those futures cancels every download.
pub struct LayerDownloads<'a> {
    producer: &'a OciMaterializer,
    resolved: &'a ResolvedImage,
    limits: crate::changeset::ChangesetLimits,
    progress: Option<ProgressReporter>,
    paths: BTreeMap<String, tokio::sync::watch::Sender<Option<PathBuf>>>,
}

impl LayerDownloads<'_> {
    /// Fetch selected occurrences in ascending order, at most three at once.
    /// A repeated compressed digest shares one verified file and event sequence.
    pub async fn prefetch(&self, indices: &[usize]) -> OciResult<()> {
        self.prefetch_with_registry(indices, &RegistryClient::new()?)
            .await
    }

    async fn prefetch_with_registry(
        &self,
        indices: &[usize],
        registry: &RegistryClient,
    ) -> OciResult<()> {
        let mut indices = indices.to_vec();
        indices.sort_unstable();
        indices.dedup();
        let mut digests = BTreeSet::new();
        let mut selected = Vec::new();
        for index in indices {
            let layer = self.layer(index)?;
            if digests.insert(&layer.digest) {
                selected.push(index);
            }
        }
        if selected.is_empty() {
            return Ok(());
        }
        registry
            .authenticate_pull(&self.resolved.reference, &self.resolved.requested_reference)
            .await?;
        let mut downloads = stream::iter(selected)
            .map(|index| async move {
                let layer = self.layer(index)?;
                let path = self
                    .producer
                    .get_or_download_layer(LayerDownloadRequest {
                        registry,
                        reference: &self.resolved.reference,
                        image_ref: &self.resolved.requested_reference,
                        layer,
                        index: index + 1,
                        total: self.resolved.layers.len(),
                        progress: self.progress.as_ref(),
                    })
                    .await?;
                if let Some(sender) = self.paths.get(&layer.digest) {
                    sender.send_replace(Some(path));
                }
                Ok::<_, OciError>(())
            })
            .buffer_unordered(MAX_CONCURRENT_DOWNLOADS);
        while downloads.try_next().await?.is_some() {}
        Ok(())
    }

    /// Wait for a verified blob without fetching or emitting more events.
    pub async fn ready(&self, index: usize) -> OciResult<PathBuf> {
        let layer = self.layer(index)?;
        let sender = self.paths.get(&layer.digest).ok_or_else(|| {
            crate::changeset::ChangesetError::Invalid("layer download slot is absent".into())
        })?;
        let mut receiver = sender.subscribe();
        let value = receiver
            .wait_for(Option::is_some)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        value.clone().ok_or_else(|| {
            crate::changeset::ChangesetError::Invalid("layer download path is absent".into()).into()
        })
    }

    /// Structurally verify an already fetched layer. Retention and composition
    /// remain the caller's responsibility; retries reuse the same source file.
    pub async fn ingest_changeset(
        &self,
        index: usize,
        operation: &StagingOperation,
    ) -> OciResult<crate::changeset::StagedChangeset> {
        let path = self.ready(index).await?;
        let input = layer_input(self.layer(index)?)?;
        let root = self.producer.root.clone();
        let operation = operation.clone();
        let limits = self.limits;
        tokio::task::spawn_blocking(move || {
            crate::changeset::ingest_layer(&path, &input, &root, &operation, &limits)
        })
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?
        .map_err(OciError::from)
    }

    fn layer(&self, index: usize) -> OciResult<&ResolvedLayer> {
        self.resolved.layers.get(index).ok_or_else(|| {
            crate::changeset::ChangesetError::Invalid(
                "layer occurrence index outside manifest".into(),
            )
            .into()
        })
    }
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

    /// Prepare a pull after its source blobs have been pinned by the caller.
    /// Only indices passed to `prefetch` are downloaded.
    pub fn layer_downloads<'a>(
        &'a self,
        resolved: &'a ResolvedImage,
        limits: &crate::changeset::ChangesetLimits,
        progress: Option<ProgressReporter>,
    ) -> OciResult<LayerDownloads<'a>> {
        limits.validate()?;
        if resolved.layers.len() as u64 > limits.max_layers {
            return Err(crate::changeset::ChangesetError::Limit {
                resource: "layer occurrences",
                actual: resolved.layers.len() as u64,
                maximum: limits.max_layers,
            }
            .into());
        }
        self.policy.check(&resolved.reference)?;
        let mut paths = BTreeMap::new();
        for layer in &resolved.layers {
            paths
                .entry(layer.digest.clone())
                .or_insert_with(|| tokio::sync::watch::channel(None).0);
        }
        Ok(LayerDownloads {
            producer: self,
            resolved,
            limits: *limits,
            progress,
            paths,
        })
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
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use crate::progress::{ProgressEvent, ProgressReporter};
    use crate::registry::ResolvedLayer;
    use crate::registry::{ImageConfig, RegistryClient, ResolvedImage};
    use crate::store::{
        digest_path_components, sha256_bytes, verified_blob_exists, verify_layer_file,
        OciMaterializer, StagingDir,
    };
    use crate::{OciError, Platform, RegistryAction, RegistryPolicy};

    fn operation(index: u64) -> crate::StagingOperation {
        crate::StagingOperation::try_from(format!("00000000-0000-4000-8000-{index:012x}")).unwrap()
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

    struct RegistryFixture {
        address: std::net::SocketAddr,
        state: Arc<RegistryState>,
        server: Option<std::thread::JoinHandle<()>>,
    }

    struct RegistryState {
        blobs: Vec<Vec<u8>>,
        requested: Mutex<Vec<usize>>,
        gates: Vec<(Mutex<bool>, Condvar)>,
        active: AtomicUsize,
        maximum: AtomicUsize,
        authentications: AtomicUsize,
        stop: AtomicBool,
        failing: Option<usize>,
    }

    impl RegistryFixture {
        fn new(count: usize, failing: Option<usize>) -> Self {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let blobs = (0..count)
                .map(|index| {
                    let data = vec![index as u8; 300 * 1024];
                    let mut archive = tar::Builder::new(Vec::new());
                    let mut header = tar::Header::new_gnu();
                    header.set_size(data.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_mtime(0);
                    header.set_cksum();
                    archive
                        .append_data(&mut header, format!("layer-{index}"), data.as_slice())
                        .unwrap();
                    archive.into_inner().unwrap()
                })
                .collect();
            let state = Arc::new(RegistryState {
                blobs,
                requested: Mutex::new(Vec::new()),
                gates: (0..count)
                    .map(|_| (Mutex::new(false), Condvar::new()))
                    .collect(),
                active: AtomicUsize::new(0),
                maximum: AtomicUsize::new(0),
                authentications: AtomicUsize::new(0),
                stop: AtomicBool::new(false),
                failing,
            });
            let serving = Arc::clone(&state);
            let server = std::thread::spawn(move || {
                let mut workers = Vec::new();
                while !serving.stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            let state = Arc::clone(&serving);
                            workers.push(std::thread::spawn(move || {
                                Self::respond(socket, address, &state);
                            }));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("registry accept: {error}"),
                    }
                }
                for worker in workers {
                    worker.join().unwrap();
                }
            });
            Self {
                address,
                state,
                server: Some(server),
            }
        }

        fn respond(
            mut socket: std::net::TcpStream,
            address: std::net::SocketAddr,
            state: &RegistryState,
        ) {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let read = match socket.read(&mut buffer) {
                    Ok(read) => read,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        return
                    }
                    Err(error) => panic!("registry request: {error}"),
                };
                if read == 0 {
                    // Cancellation can close an accepted connection before a
                    // complete request has reached the registry.
                    return;
                }
                assert!(request.len() + read <= 16384);
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8(request).unwrap();
            let target = request.split_whitespace().nth(1).unwrap();
            if target == "/v2/" {
                state.authentications.fetch_add(1, Ordering::SeqCst);
                write!(socket, "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\nWWW-Authenticate: Bearer realm=\"http://{address}/token\",service=\"fixture\"\r\n\r\n").unwrap();
                return;
            }
            if target.starts_with("/token?") {
                let token = br#"{"token":"fixture-token"}"#;
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    token.len()
                )
                .unwrap();
                socket.write_all(token).unwrap();
                return;
            }
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer "));
            let digest = target.rsplit('/').next().unwrap();
            let index = state
                .blobs
                .iter()
                .position(|blob| format!("sha256:{}", sha256_bytes(blob)) == digest)
                .expect("requested blob belongs to fixture");
            let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
            state.maximum.fetch_max(active, Ordering::SeqCst);
            state.requested.lock().unwrap().push(index);
            let blob = &state.blobs[index];
            if state.failing != Some(index)
                && (write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    blob.len()
                )
                .is_err()
                    || socket.write_all(&blob[..256 * 1024]).is_err())
            {
                state.active.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            let (gate, changed) = &state.gates[index];
            let (released, timeout) = changed
                .wait_timeout_while(gate.lock().unwrap(), Duration::from_secs(5), |released| {
                    !*released
                })
                .unwrap();
            assert!(!timeout.timed_out(), "registry response was never released");
            assert!(*released);
            if state.failing == Some(index) {
                let _ = socket.write_all(b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 12\r\n\r\nlayer failed");
            } else {
                let _ = socket.write_all(&blob[256 * 1024..]);
            }
            state.active.fetch_sub(1, Ordering::SeqCst);
        }

        fn release(&self, index: usize) {
            let (gate, changed) = &self.state.gates[index];
            *gate.lock().unwrap() = true;
            changed.notify_all();
        }

        fn client(&self) -> RegistryClient {
            RegistryClient {
                client: oci_client::Client::new(oci_client::client::ClientConfig {
                    protocol: oci_client::client::ClientProtocol::Http,
                    ..Default::default()
                }),
            }
        }

        fn resolved(&self) -> ResolvedImage {
            let reference =
                RegistryClient::parse_reference(&format!("{}/fixture:latest", self.address))
                    .unwrap();
            ResolvedImage {
                requested_reference: reference.to_string(),
                selected_reference: reference.to_string(),
                manifest_digest: format!("sha256:{}", "1".repeat(64)),
                config_digest: format!("sha256:{}", "2".repeat(64)),
                config: ImageConfig::default(),
                platform: Platform::linux_amd64(),
                reference,
                layers: self
                    .state
                    .blobs
                    .iter()
                    .map(|blob| {
                        let digest = format!("sha256:{}", sha256_bytes(blob));
                        ResolvedLayer {
                            digest: digest.clone(),
                            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                            size_bytes: blob.len() as u64,
                            diff_id: digest,
                        }
                    })
                    .collect(),
            }
        }
    }

    impl Drop for RegistryFixture {
        fn drop(&mut self) {
            self.state.stop.store(true, Ordering::SeqCst);
            for index in 0..self.state.blobs.len() {
                self.release(index);
            }
            if let Some(server) = self.server.take() {
                server.join().unwrap();
            }
        }
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "condition did not become true");
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn pull_downloads_three_at_once_authenticates_once_and_overlaps_ordered_unpack() {
        let registry = RegistryFixture::new(6, None);
        let temp = tempfile::tempdir().unwrap();
        let producer = OciMaterializer::open(temp.path(), RegistryPolicy::default()).unwrap();
        let mut resolved = registry.resolved();
        resolved.layers.push(resolved.layers[0].clone());
        let events = Arc::new(Mutex::new(Vec::new()));
        let reported = Arc::clone(&events);
        let progress = ProgressReporter::new(move |event| reported.lock().unwrap().push(event));
        let downloads = producer
            .layer_downloads(
                &resolved,
                &crate::changeset::ChangesetLimits::default(),
                Some(progress),
            )
            .unwrap();
        let client = registry.client();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let ordered = async {
                    until(|| registry.state.requested.lock().unwrap().len() == 3).await;
                    let mut initial = registry.state.requested.lock().unwrap().clone();
                    initial.sort_unstable();
                    assert_eq!(initial, vec![0, 1, 2]);
                    assert_eq!(registry.state.maximum.load(Ordering::SeqCst), 3);
                    registry.release(0);
                    let first = downloads.ingest_changeset(0, &operation(1)).await.unwrap();
                    assert_eq!(
                        first.changeset().diff_id.to_string(),
                        resolved.layers[0].diff_id
                    );
                    assert!(
                        registry.state.active.load(Ordering::SeqCst) >= 2,
                        "later downloads remain in flight during the first unpack"
                    );
                    for index in 1..5 {
                        registry.release(index);
                    }
                    let mut unpacked = vec![0];
                    for index in 1..5 {
                        let staged = downloads
                            .ingest_changeset(index, &operation(index as u64 + 1))
                            .await
                            .unwrap();
                        assert_eq!(
                            staged.changeset().diff_id.to_string(),
                            resolved.layers[index].diff_id
                        );
                        unpacked.push(index);
                    }
                    assert_eq!(unpacked, vec![0, 1, 2, 3, 4]);
                    assert_eq!(
                        downloads.ready(6).await.unwrap(),
                        downloads.ready(0).await.unwrap()
                    );
                };
                let (result, ()) = tokio::join!(
                    downloads.prefetch_with_registry(&[6, 4, 3, 2, 1, 0], &client),
                    ordered
                );
                result.unwrap();
            });
        assert_eq!(registry.state.authentications.load(Ordering::SeqCst), 1);
        assert_eq!(registry.state.maximum.load(Ordering::SeqCst), 3);
        let mut requested = registry.state.requested.lock().unwrap().clone();
        requested.sort_unstable();
        assert_eq!(
            requested,
            vec![0, 1, 2, 3, 4],
            "omitted retained blob and repeat are not fetched"
        );
        let events = events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ProgressEvent::LayerDownloadFinished { .. }))
                .count(),
            5
        );
        assert!(!events
            .iter()
            .any(|event| matches!(event, ProgressEvent::LayerDownloadSkipped { .. })));
    }

    #[test]
    fn failed_prefetch_cancels_other_downloads_and_preserves_resumable_files() {
        let registry = RegistryFixture::new(4, Some(1));
        let temp = tempfile::tempdir().unwrap();
        let producer = OciMaterializer::open(temp.path(), RegistryPolicy::default()).unwrap();
        let resolved = registry.resolved();
        let downloads = producer
            .layer_downloads(
                &resolved,
                &crate::changeset::ChangesetLimits::default(),
                None,
            )
            .unwrap();
        let client = registry.client();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let control = async {
                    until(|| registry.state.requested.lock().unwrap().len() == 3).await;
                    registry.release(0);
                    downloads.ready(0).await.unwrap();
                    until(|| {
                        producer
                            .blob_part_path(&resolved.layers[2].digest)
                            .unwrap()
                            .metadata()
                            .is_ok_and(|metadata| metadata.len() >= 256 * 1024)
                    })
                    .await;
                    registry.release(1);
                    std::future::pending::<crate::OciResult<()>>().await
                };
                let error = tokio::try_join!(
                    downloads.prefetch_with_registry(&[0, 1, 2, 3], &client),
                    control
                )
                .unwrap_err();
                let OciError::Registry {
                    source: oci_client::errors::OciDistributionError::RequestError(source),
                    ..
                } = error
                else {
                    panic!("expected the failed layer's HTTP error, got {error:?}");
                };
                assert_eq!(source.status().map(|status| status.as_u16()), Some(500));
                assert!(source
                    .url()
                    .unwrap()
                    .path()
                    .ends_with(&resolved.layers[1].digest));
                assert!(producer
                    .blob_path(&resolved.layers[0].digest)
                    .unwrap()
                    .is_file());
                let part = producer.blob_part_path(&resolved.layers[2].digest).unwrap();
                assert_eq!(
                    std::fs::read(&part).unwrap(),
                    registry.state.blobs[2][..256 * 1024]
                );
                let length = std::fs::metadata(&part).unwrap().len();
                registry.release(2);
                until(|| registry.state.active.load(Ordering::SeqCst) <= 1).await;
                for _ in 0..10 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(
                    std::fs::metadata(&part).unwrap().len(),
                    length,
                    "cancelled downloads no longer consume response bytes"
                );
            });
    }
}
