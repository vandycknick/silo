//! OCI VM artifact publication and acquisition (ADR 0014 "OCI VM Artifact
//! And Chunked Distribution"). The registry adapter moves exact bytes; this
//! module owns semantic export, verified import and the orchestration around
//! them. Images publish publicly; snapshot publication is crate-private until
//! snapshot push has an encryption design.
//!
//! RAM and disk identities authenticate sparse Merkle maps, exact lengths and
//! identity-unit profiles independently of the 8 MiB transport payloads.
//! Import hashes decoded identity units before accepting the declared root.
//! Small state objects retain whole-byte hashes.
//!
//! Admission: before any payload is fetched, an acquisition reserves its
//! logical worst-case disk peak (cache, decoded staging and catalog copies)
//! on the shared cross-home ledger; export admits its complete unique stream
//! closure, boot streams included, before publishing any representation.
//!
//! Resume: acquisition stages encoded blobs in the shared, operation-pinned
//! transport cache keyed by digest. A retried pull of the same index rehashes
//! every cached blob before reuse and fetches only missing or invalid ones;
//! decoded streams are always rebuilt into fresh zero-filled staging. A
//! retried push reuses the retained representation registered by the first
//! attempt, so it reproduces the exact graph bytes, and the registry skips
//! blobs it already holds with matching digest and length.
//!
//! Layered roots retain canonical composition and per-occurrence layer records,
//! index-page closure, whole-byte fsmeta, and pack streams alongside the private
//! upper. Fsmeta is chunked only for transport: its permanent identity/backing is
//! an object, never another concatenated-lower or whole-fsmeta stream. Both
//! directions authenticate the complete retained EROFS graph without invoking a
//! source registry or encoder; optional OCI reconstruction belongs to handoff
//! preparation and must match these exact retained identities.
use std::collections::BTreeSet;
use std::sync::Arc;

use oci::artifact_registry::{ArtifactRegistry, ArtifactResolution};
use oci::vm_artifact::codec::ChunkEncoding;
use oci::vm_artifact::graph::{Descriptor, VerifiedVmGraph};
use serde::{Deserialize, Serialize};

use crate::image::import_types::{ImageRef, StoredImageInfo};
use crate::image::oci::image_error;
use crate::image::transport::blobs::StagedBlobs;
use crate::image::transport::closure::object;
use crate::image::transport::export::{prepare_artifact_export, ExportSource, PreparedVmArtifact};
use crate::image::transport::import::{
    acquisition_space_charge, verify_imported_artifact, ImportStaging,
};
use crate::image::transport::receipt::ResolvedIndex;
use crate::resolve::Kind;
use crate::storage::identity::{ImageId, ObjectDigest, SnapshotId};
use crate::storage::pool::{OperationPaths, StoragePool};
use crate::store::models::storage::GuestArchitecture;
use crate::store::snapshot_store::{SnapshotInfo, SnapshotRef, SnapshotStore};
use crate::store::Store;
use crate::LibVmError;

pub(crate) mod blobs;
pub(crate) mod closure;
pub(crate) mod export;
pub(crate) mod identity;
pub(crate) mod import;
pub(crate) mod provenance;
pub(crate) mod receipt;

pub(crate) use crate::image::transport::import::{VerifiedContent, VerifiedImportedArtifact};

/// Chunk representation chosen for a publication. Stream identity is the
/// same either way; only encoded blob digests and the index digest differ.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactEncoding {
    /// One independent zstd frame per chunk when smaller than raw.
    #[default]
    Zstd,
    /// Raw chunk bytes only.
    Raw,
}

/// The content a VM artifact carries: one image or one snapshot, by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum ArtifactContent {
    Image(ImageId),
    Snapshot(SnapshotId),
}

/// The local record an acquisition committed.
pub(crate) enum AcquiredContent {
    Image(Box<StoredImageInfo>),
    Snapshot(Box<SnapshotInfo>),
}

/// Publish one stored image as an OCI VM artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactPublishRequest {
    pub image: ImageRef,
    /// `registry/repository[:tag]`; a digest form is rejected.
    pub destination: String,
    pub encoding: ArtifactEncoding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactPublishReport {
    pub repository: String,
    /// Immutable index digest. A tag, when present, was written last and is
    /// only the value observed at publication time.
    pub index_digest: ObjectDigest,
    pub tag: Option<String>,
    pub content: ArtifactContent,
}

/// Acquire a Silo image artifact into a stored image. The canonical
/// reference becomes a name of the image; `name` adds a local name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactAcquireRequest {
    pub reference: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactAcquireReport {
    pub image: StoredImageInfo,
    pub repository: String,
    pub index_digest: ObjectDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRootFamily {
    OpaqueRaw,
    LinuxOverlay,
}

/// Bounded, structurally verified but untrusted metadata. Nothing is
/// retained or booted by inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactInspection {
    pub repository: String,
    pub index_digest: ObjectDigest,
    pub content: ArtifactContent,
    pub root: ArtifactRootFamily,
    pub guest_architecture: GuestArchitecture,
    /// Whether the snapshot includes memory; always false for images.
    pub memory: bool,
}

/// One verified acquisition and where it came from.
struct Acquisition {
    content: AcquiredContent,
    repository: String,
    index_digest: ObjectDigest,
}

impl crate::image::Images {
    /// Resolve and verify an artifact's metadata graph without payload
    /// acquisition or any local state change.
    pub async fn inspect_artifact(
        &self,
        reference: &str,
    ) -> Result<ArtifactInspection, LibVmError> {
        let registry = self.artifact_registry(reference)?;
        let (canonical, resolution) = self.resolve_artifact(&registry, reference).await?;
        let graph = registry
            .inspect(&resolution)
            .await
            .map_err(|error| image_error(&canonical, error))?;
        Ok(inspection(&resolution, graph.config()))
    }

    /// Acquire a Silo image artifact into a stored image. A snapshot
    /// artifact is refused before any payload is fetched.
    pub async fn acquire_artifact(
        &self,
        request: ArtifactAcquireRequest,
    ) -> Result<ArtifactAcquireReport, LibVmError> {
        let acquisition = self
            .acquire(request.reference, Kind::Image, request.name)
            .await?;
        let AcquiredContent::Image(image) = acquisition.content else {
            return Err(blobs::invalid("config", "acquired content is not an image"));
        };
        Ok(ArtifactAcquireReport {
            image: *image,
            repository: acquisition.repository,
            index_digest: acquisition.index_digest,
        })
    }

    /// Acquire a Silo snapshot artifact for `Runtime::restore`. An image
    /// artifact is refused before any payload is fetched.
    pub(crate) async fn acquire_snapshot_artifact(
        &self,
        reference: String,
    ) -> Result<SnapshotInfo, LibVmError> {
        let acquisition = self.acquire(reference, Kind::Snapshot, None).await?;
        let AcquiredContent::Snapshot(snapshot) = acquisition.content else {
            return Err(blobs::invalid(
                "config",
                "acquired content is not a snapshot",
            ));
        };
        Ok(*snapshot)
    }

    async fn acquire(
        &self,
        reference: String,
        kind: Kind,
        name: Option<String>,
    ) -> Result<Acquisition, LibVmError> {
        // Cache and verification workers may outlive the caller's future.
        // Keep their operation owner through publication and cleanup.
        let images = self.clone();
        tokio::spawn(async move { images.acquire_owned(&reference, kind, name).await }).await?
    }

    async fn acquire_owned(
        &self,
        reference: &str,
        kind: Kind,
        name: Option<String>,
    ) -> Result<Acquisition, LibVmError> {
        if let Some(name) = &name {
            crate::store::names::validate_name(name)?;
        }
        let registry = self.artifact_registry(reference)?;
        let (canonical, resolution) = self.resolve_artifact(&registry, reference).await?;
        let index_digest = object(resolution.digest());
        let repository = resolution.repository();
        let resolved = ResolvedIndex::new(&repository, index_digest)?;
        let graph = registry
            .inspect(&resolution)
            .await
            .map_err(|error| image_error(&canonical, error))?;
        // The content kind is checked before any payload is fetched.
        match (kind, graph.config().content.kind) {
            (Kind::Image, oci::vm_artifact::wire::ContentKind::Image)
            | (Kind::Snapshot, oci::vm_artifact::wire::ContentKind::Snapshot) => {}
            (Kind::Image, oci::vm_artifact::wire::ContentKind::Snapshot) => {
                return Err(LibVmError::ArtifactIsSnapshot {
                    reference: reference.to_owned(),
                })
            }
            (Kind::Snapshot, oci::vm_artifact::wire::ContentKind::Image) => {
                return Err(LibVmError::ArtifactIsImage {
                    reference: reference.to_owned(),
                })
            }
        }
        let store = Arc::new(self.runtime.native_store()?);
        let images = self.runtime.local_images_dir().to_path_buf();
        let pool = StoragePool::open(&images)?;
        let result = async {
            let operation = begin_acquisition(&store, &pool, &graph).await?;
            let operation_id = operation.id;
            let cache = StagedBlobs::transport_cache(&images)?;
            for payload in graph.inventory().values().copied() {
                let probe = cache.try_clone()?;
                if tokio::task::spawn_blocking(move || probe.contains(&payload)).await?? {
                    continue;
                }
                let bytes = registry
                    .fetch_blob(&resolution, &Descriptor::from_payload(payload))
                    .await
                    .map_err(|error| image_error(&canonical, error))?;
                let writer = cache.try_clone()?;
                tokio::task::spawn_blocking(move || writer.insert(&payload, &bytes)).await??;
            }
            let acquired_at = unix_ms()?;
            let staging = ImportStaging {
                operation,
                store: store.clone(),
                blobs: cache,
            };
            let verified = tokio::task::spawn_blocking(move || {
                verify_imported_artifact(&graph, &resolved, acquired_at, staging)
            })
            .await??;
            commit_acquisition(&store, operation_id, verified, canonical.clone(), name).await
        }
        .await;
        let content = settle(&store, &pool, result).await?;
        Ok(Acquisition {
            content,
            repository,
            index_digest,
        })
    }

    /// The first `search_registries` expansion of `reference` that resolves
    /// to a VM artifact index, with the canonical reference it resolved as.
    async fn resolve_artifact(
        &self,
        registry: &ArtifactRegistry,
        reference: &str,
    ) -> Result<(String, ArtifactResolution), LibVmError> {
        let candidates = self
            .runtime
            .registry_policy()
            .candidates(reference)
            .map_err(|error| image_error(reference, error))?;
        let mut first_error = None;
        for candidate in candidates {
            let candidate = candidate.to_string();
            match registry.resolve(&candidate).await {
                Ok(resolution) => return Ok((candidate, resolution)),
                Err(error) => {
                    first_error.get_or_insert_with(|| image_error(&candidate, error));
                }
            }
        }
        Err(first_error.unwrap_or_else(|| LibVmError::ImageNotFound {
            reference: reference.to_owned(),
        }))
    }

    /// Publish a stored image as one fixed exact encoding.
    pub async fn publish_artifact(
        &self,
        request: ArtifactPublishRequest,
    ) -> Result<ArtifactPublishReport, LibVmError> {
        let local = self.runtime.resolve_local_image(&request.image).await?;
        let crate::resolve::LocalRecord::Image(crate::store::image_store::LocalImage::Stored(id)) =
            local.record
        else {
            return Err(LibVmError::InvalidRequest {
                message: format!(
                    "{} is a cached OCI image; only stored images can be published as VM artifacts",
                    request.image
                ),
            });
        };
        let images = self.clone();
        tokio::spawn(async move {
            images
                .publish_owned(
                    PublishSource::Image(id),
                    &request.destination,
                    request.encoding,
                )
                .await
        })
        .await?
    }

    /// Publish a snapshot. Crate-private: snapshot push stays unreachable
    /// for SDK and daemon callers until it has an encryption design for
    /// disks and memory (DESIGN section 9); tests exercise the exporter.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "snapshot push is reachable from tests only")
    )]
    pub(crate) async fn publish_snapshot_artifact(
        &self,
        snapshot: SnapshotRef,
        destination: String,
        encoding: ArtifactEncoding,
    ) -> Result<ArtifactPublishReport, LibVmError> {
        let images = self.clone();
        tokio::spawn(async move {
            images
                .publish_owned(PublishSource::Snapshot(snapshot), &destination, encoding)
                .await
        })
        .await?
    }

    async fn publish_owned(
        &self,
        source: PublishSource,
        destination: &str,
        encoding: ArtifactEncoding,
    ) -> Result<ArtifactPublishReport, LibVmError> {
        let (repository, tag) = parse_destination(destination)?;
        let registry = self.artifact_registry(destination)?;
        let store = Arc::new(self.runtime.native_store()?);
        let source = match source {
            PublishSource::Image(id) => ExportSource::Image(Box::new(
                crate::store::stored_image_store::StoredImageStore::from_store(store.clone())
                    .consume(id)
                    .await?,
            )),
            PublishSource::Snapshot(reference) => ExportSource::Snapshot(Box::new(
                SnapshotStore::from_store(store.clone())
                    .consume(&reference)
                    .await?,
            )),
        };
        let pool = StoragePool::open(self.runtime.local_images_dir())?;
        let encoding = match encoding {
            ArtifactEncoding::Zstd => ChunkEncoding::Zstd,
            ArtifactEncoding::Raw => ChunkEncoding::Raw,
        };
        let result = async {
            let worker_store = store.clone();
            let runtime = tokio::runtime::Handle::current();
            let prepared = tokio::task::spawn_blocking(move || {
                prepare_artifact_export(source, &worker_store, &runtime, encoding)
            })
            .await??;
            let index_digest = push(
                &registry,
                destination,
                &repository,
                tag.as_deref(),
                &prepared,
            )
            .await?;
            Ok::<_, LibVmError>((index_digest, prepared.content))
        }
        .await;
        let (index_digest, content) = settle(&store, &pool, result).await?;
        Ok(ArtifactPublishReport {
            repository,
            index_digest,
            tag,
            content,
        })
    }

    fn artifact_registry(&self, reference: &str) -> Result<ArtifactRegistry, LibVmError> {
        ArtifactRegistry::new(self.runtime.registry_policy().clone())
            .map_err(|error| image_error(reference, error))
    }
}

/// What `publish_owned` exports.
enum PublishSource {
    Image(ImageId),
    Snapshot(SnapshotRef),
}

/// Register an acquisition and admit its complete worst-case disk peak on the
/// shared cross-home ledger before any payload is fetched, cached or decoded,
/// then pin every cache input. The reservation belongs to the operation: a
/// committed acquisition releases it once every copy exists; a failed or
/// abandoned one keeps it until operation recovery retires both together,
/// so a still-running detached worker never loses its charge.
async fn begin_acquisition(
    store: &Store,
    pool: &StoragePool,
    graph: &VerifiedVmGraph,
) -> Result<OperationPaths, LibVmError> {
    let charge = acquisition_space_charge(graph)?;
    let (operation_id, lease) = store.begin_stopped_operation("import", &[], &[]).await?;
    let operation = pool.create_operation_with_lease(operation_id, lease)?;
    store.reserve_import_space(operation_id, charge).await?;
    let digests = graph
        .inventory()
        .keys()
        .map(|digest| object(*digest))
        .collect::<Vec<_>>();
    store
        .pin_cache_inputs(
            operation_id,
            crate::store::stream_representation::CacheKind::Transport,
            &digests,
        )
        .await?;
    Ok(operation)
}

/// Commit a verified acquisition, then release its peak reservation. The
/// commit's operation owner stays alive until the release has completed.
async fn commit_acquisition(
    store: &Store,
    operation: uuid::Uuid,
    verified: VerifiedImportedArtifact,
    reference: String,
    name: Option<String>,
) -> Result<AcquiredContent, LibVmError> {
    let committed =
        crate::store::artifact_store::commit_imported_artifact(verified, reference, name).await?;
    store.release_import_space(operation).await?;
    Ok(committed.content)
}

/// Upload blobs, then child manifests by digest, then the index by digest and
/// finally the optional tag, all in the destination repository.
async fn push(
    registry: &ArtifactRegistry,
    destination: &str,
    repository: &str,
    tag: Option<&str>,
    prepared: &PreparedVmArtifact,
) -> Result<ObjectDigest, LibVmError> {
    let error = |error: oci::OciError| image_error(destination, error);
    let graph = &prepared.graph;
    let mut pushed = BTreeSet::new();
    for record in &graph.records {
        if pushed.insert(record.reference.digest) {
            registry
                .push_blob(repository, record.reference.digest, record.bytes.clone())
                .await
                .map_err(error)?;
        }
    }
    let payloads = prepared.payloads();
    for payload in graph.payloads.iter().copied() {
        if !pushed.insert(payload.digest) {
            continue;
        }
        let reader = payloads.clone();
        let bytes = tokio::task::spawn_blocking(move || reader.read(&payload)).await??;
        registry
            .push_blob(repository, payload.digest, bytes)
            .await
            .map_err(error)?;
    }
    for blob in [&graph.config, &graph.empty] {
        if pushed.insert(blob.descriptor.digest) {
            registry
                .push_blob(repository, blob.descriptor.digest, blob.bytes.clone())
                .await
                .map_err(error)?;
        }
    }
    for child in &graph.children {
        registry
            .push_manifest(
                &format!("{repository}@{}", child.descriptor.digest),
                child.bytes.clone(),
            )
            .await
            .map_err(error)?;
    }
    let digest = registry
        .push_manifest(
            &format!("{repository}@{}", graph.index.descriptor.digest),
            graph.index.bytes.clone(),
        )
        .await
        .map_err(error)?;
    if digest != graph.index.descriptor.digest {
        return Err(blobs::invalid(
            "index",
            "registry index digest differs from the encoding",
        ));
    }
    if let Some(tag) = tag {
        let tagged = registry
            .push_manifest(&format!("{repository}:{tag}"), graph.index.bytes.clone())
            .await
            .map_err(error)?;
        if tagged != digest {
            return Err(blobs::invalid(
                "index",
                "tagged index differs from the pushed digest",
            ));
        }
    }
    Ok(object(digest))
}

/// A failed operation's lease has closed; settle its journal through existing
/// recovery instead of leaking pins, preserving the primary failure.
async fn settle<T>(
    store: &Store,
    pool: &StoragePool,
    result: Result<T, LibVmError>,
) -> Result<T, LibVmError> {
    match result {
        Ok(value) => Ok(value),
        Err(primary) => match store.retire_abandoned_storage_operations(pool).await {
            Ok(_) => Err(primary),
            Err(cleanup) => Err(LibVmError::MachineStartCleanupFailed {
                primary: primary.to_string(),
                cleanup: cleanup.to_string(),
            }),
        },
    }
}

fn inspection(
    resolution: &ArtifactResolution,
    config: &oci::vm_artifact::wire::VmArtifactConfig,
) -> ArtifactInspection {
    use oci::vm_artifact::wire;
    let id = *config.content.id.as_bytes();
    let content = match config.content.kind {
        wire::ContentKind::Image => ArtifactContent::Image(ImageId::from_sha256(id)),
        wire::ContentKind::Snapshot => ArtifactContent::Snapshot(SnapshotId::from_sha256(id)),
    };
    ArtifactInspection {
        repository: resolution.repository(),
        index_digest: object(resolution.digest()),
        content,
        root: match config.root {
            wire::Root::OpaqueRaw => ArtifactRootFamily::OpaqueRaw,
            wire::Root::LinuxErofsOverlay => ArtifactRootFamily::LinuxOverlay,
        },
        guest_architecture: match config.guest_platform.architecture {
            wire::Architecture::Amd64 => GuestArchitecture::Amd64,
            wire::Architecture::Arm64 => GuestArchitecture::Arm64,
        },
        memory: config.memory.is_some(),
    }
}

/// Split `repository[:tag]`. A tag is the suffix after the last colon that
/// follows the last slash (a registry port is not a tag). Digests are refused:
/// publication produces the digest, it cannot be requested.
fn parse_destination(destination: &str) -> Result<(String, Option<String>), LibVmError> {
    let rejected = |message: &str| LibVmError::ImageReferenceRejected {
        reference: destination.into(),
        message: message.into(),
    };
    if destination.contains('@') {
        return Err(rejected("publication destination must not name a digest"));
    }
    let slash = destination.rfind('/');
    let (repository, tag) = match destination.rfind(':') {
        Some(colon) if slash.is_none_or(|slash| colon > slash) => (
            &destination[..colon],
            Some(destination[colon + 1..].to_owned()),
        ),
        _ => (destination, None),
    };
    if repository.is_empty() || repository.starts_with('/') || repository.ends_with('/') {
        return Err(rejected("publication destination needs a repository"));
    }
    if repository
        .split_once('/')
        .is_some_and(|(_, path)| path.contains(':'))
    {
        return Err(rejected("repository path must not contain a colon"));
    }
    if let Some(tag) = &tag {
        let mut bytes = tag.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !valid_first
            || tag.len() > 128
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err(rejected("publication tag is not a valid OCI tag"));
        }
    }
    Ok((repository.to_owned(), tag))
}

fn unix_ms() -> Result<u64, LibVmError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| blobs::invalid("receipt", error))?;
    u64::try_from(elapsed.as_millis()).map_err(|error| blobs::invalid("receipt", error))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::FileExt;
    use std::sync::Arc;

    use oci::changeset::model::ContentDigest;
    use oci::vm_artifact::codec::ChunkEncoding;
    use oci::vm_artifact::graph::{
        encode_vm_graph, verify_vm_graph, EncodedVmGraph, VerifiedVmGraph,
    };
    use oci::vm_artifact::wire::{
        decode_record, decode_vm_config, encode_object_table, encode_stream_table, encode_transfer,
        verify_transfer, ChunkEntry, ObjectBinding, ObjectTablePage, ObjectTableRoot,
        PayloadMediaType, RecordBlob, StreamBinding, StreamTablePage, StreamTableRoot,
        TransferRoot, VmArtifactConfig, CHUNK_SIZE, MAX_STREAM_BYTES,
    };

    use crate::image::transport::blobs::StagedBlobs;
    use crate::image::transport::closure::{
        canonical_map_bytes, content, identity, object, Semantic, SemanticRecord,
    };
    use crate::image::transport::export::{
        prepare_artifact_export, ExportSource, PayloadReader, PreparedVmArtifact,
    };
    use crate::image::transport::import::{
        acquisition_space_charge, verify_imported_artifact, ImportStaging, VerifiedContent,
        VerifiedImportedArtifact,
    };
    use crate::image::transport::receipt::ResolvedIndex;
    use crate::image::transport::{
        begin_acquisition, commit_acquisition, parse_destination, AcquiredContent,
    };
    use crate::paths::{LocalPaths, OwnedDirectory};
    use crate::storage::identity::{ImageId, ObjectDigest};
    use crate::storage::map::{AuthenticatedMap, MapNodeWriter};
    use crate::storage::pool::StoragePool;
    use crate::store::artifact_store::commit_imported_artifact;
    use crate::store::models::image::{ImageRecord, ImageRecordKind};
    use crate::store::models::snapshot::SnapshotStream;
    use crate::store::snapshot_store::SnapshotRef;
    use crate::store::stored_image_store::StoredImageStore;
    use crate::store::Store;
    use crate::LibVmError;
    use vm_spec::capture::Sha256Digest;
    use vm_spec::stream_map::{
        build_sorted, ChunkSize, PresentChunk, StreamNode, StreamRole, StreamRoot,
    };

    pub(crate) const REPOSITORY: &str = "registry.example/team/vm";
    /// The canonical reference an acquisition commits as the record's name.
    pub(crate) const REFERENCE: &str = "registry.example/team/vm:v1";

    /// Exact bytes of one encoding, as a registry would serve them.
    pub(crate) struct Transfer {
        pub(crate) index: Vec<u8>,
        pub(crate) blobs: BTreeMap<ContentDigest, Vec<u8>>,
    }

    pub(crate) fn transfer(graph: &EncodedVmGraph, staged: &PayloadReader) -> Transfer {
        let mut blobs = BTreeMap::new();
        for blob in graph.children.iter().chain([&graph.config, &graph.empty]) {
            blobs.insert(blob.descriptor.digest, blob.bytes.clone());
        }
        for record in &graph.records {
            blobs.insert(record.reference.digest, record.bytes.clone());
        }
        for payload in &graph.payloads {
            if let std::collections::btree_map::Entry::Vacant(entry) = blobs.entry(payload.digest) {
                entry.insert(staged.read(payload).unwrap());
            }
        }
        Transfer {
            index: graph.index.bytes.clone(),
            blobs,
        }
    }

    pub(crate) fn verified_graph(transfer: &Transfer) -> VerifiedVmGraph {
        verify_vm_graph(&transfer.index, |descriptor| {
            transfer
                .blobs
                .get(&descriptor.digest)
                .cloned()
                .ok_or_else(|| {
                    oci::vm_artifact::Error::MissingMetadata(Box::new(descriptor.clone()))
                })
        })
        .unwrap()
    }

    pub(crate) async fn export(
        store: Arc<Store>,
        source: ExportSource,
        encoding: ChunkEncoding,
    ) -> PreparedVmArtifact {
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            prepare_artifact_export(source, &store, &runtime, encoding)
        })
        .await
        .unwrap()
        .unwrap()
    }

    pub(crate) async fn home() -> (tempfile::TempDir, Arc<Store>) {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        (temp, Arc::new(store))
    }

    /// Register an acquisition exactly as a pull does (disk-space admission,
    /// cache pins) and place every inventory blob in the destination's
    /// shared transport cache.
    pub(crate) async fn stage(destination: &Arc<Store>, transfer: &Transfer) -> ImportStaging {
        let graph = verified_graph(transfer);
        let pool = StoragePool::open(destination.images_path()).unwrap();
        let operation = begin_acquisition(destination, &pool, &graph).await.unwrap();
        let blobs = cache(destination);
        for payload in graph.inventory().values() {
            if !blobs.contains(payload).unwrap() {
                blobs
                    .insert(payload, &transfer.blobs[&payload.digest])
                    .unwrap();
            }
        }
        ImportStaging {
            operation,
            store: destination.clone(),
            blobs,
        }
    }

    pub(crate) fn cache(store: &Store) -> StagedBlobs {
        StagedBlobs::transport_cache(store.images_path()).unwrap()
    }

    /// Verify `transfer` as acquired from [`REPOSITORY`] after resolving the
    /// index `resolved`.
    pub(crate) async fn verify(
        transfer: &Transfer,
        staging: ImportStaging,
        resolved: ObjectDigest,
    ) -> Result<VerifiedImportedArtifact, LibVmError> {
        let graph = verified_graph(transfer);
        let resolved = ResolvedIndex::new(REPOSITORY, resolved)?;
        tokio::task::spawn_blocking(move || {
            verify_imported_artifact(&graph, &resolved, 1_700_000_000_000, staging)
        })
        .await
        .unwrap()
    }

    pub(crate) fn index_digest(transfer: &Transfer) -> ObjectDigest {
        ObjectDigest::of_bytes(&transfer.index)
    }

    pub(crate) async fn database(store: &Store) -> sqlx::SqlitePool {
        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(store.home_path().join("state.db"))
                    .read_only(true),
            )
            .await
            .unwrap()
    }

    pub(crate) async fn count(pool: &sqlx::SqlitePool, query: &'static str) -> i64 {
        sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
    }

    /// The disk bytes `operation` holds on the shared reservation ledger.
    async fn reservation(store: &Store, operation: uuid::Uuid) -> Option<u64> {
        let document = store.capture_budget_document(operation).await.ok()?;
        let inventory: crate::store::restore::CaptureBudgetInventory =
            serde_json::from_str(&document).unwrap();
        Some(
            inventory
                .capture_disks
                .iter()
                .map(|charge| charge.bytes)
                .sum(),
        )
    }

    /// Whether the cross-home ledger file of `operation` exists.
    fn ledger_holds(store: &Store, operation: uuid::Uuid) -> bool {
        let suffix = format!("{operation}.json");
        std::fs::read_dir(store.home_path().join("resource-budget"))
            .unwrap()
            .any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(&suffix)
            })
    }

    fn record_bytes(graph: &EncodedVmGraph, digest: ContentDigest) -> Vec<u8> {
        graph
            .records
            .iter()
            .find(|record| record.reference.digest == digest)
            .unwrap()
            .bytes
            .clone()
    }

    /// Rows of an exported stream table and the digests of its records.
    fn stream_rows(
        graph: &EncodedVmGraph,
        root: ContentDigest,
    ) -> (Vec<StreamBinding>, Vec<ContentDigest>) {
        let table: StreamTableRoot = decode_record(&record_bytes(graph, root)).unwrap();
        let mut digests = vec![root];
        let mut rows = Vec::new();
        for page in &table.pages {
            digests.push(page.digest);
            let page: StreamTablePage = decode_record(&record_bytes(graph, page.digest)).unwrap();
            rows.extend(page.entries);
        }
        (rows, digests)
    }

    /// Rows of an exported object table and the digests of its records.
    fn object_rows(
        graph: &EncodedVmGraph,
        root: ContentDigest,
    ) -> (Vec<ObjectBinding>, Vec<ContentDigest>) {
        let table: ObjectTableRoot = decode_record(&record_bytes(graph, root)).unwrap();
        let mut digests = vec![root];
        let mut rows = Vec::new();
        for page in &table.pages {
            digests.push(page.digest);
            let page: ObjectTablePage = decode_record(&record_bytes(graph, page.digest)).unwrap();
            rows.extend(page.entries);
        }
        (rows, digests)
    }

    /// Chunk entries of one exported stream row and its transfer records.
    fn transfer_entries(
        graph: &EncodedVmGraph,
        row: &StreamBinding,
    ) -> (Vec<ChunkEntry>, Vec<ContentDigest>) {
        let root: TransferRoot = decode_record(&record_bytes(graph, row.transport.digest)).unwrap();
        let entries = verify_transfer(&root, |digest| {
            Ok::<_, oci::vm_artifact::Error>(record_bytes(graph, digest))
        })
        .unwrap();
        let mut digests = vec![row.transport.digest];
        digests.extend(root.pages.iter().copied());
        (entries, digests)
    }

    fn direct(record: &RecordBlob) -> ObjectBinding {
        ObjectBinding::Direct {
            object: record.reference.digest,
            size: record.reference.size,
            payload: oci::vm_artifact::wire::PayloadRef {
                media_type: if record.bytes.starts_with(b"silo:stream") {
                    PayloadMediaType::StreamMap
                } else {
                    PayloadMediaType::Record
                },
                digest: record.reference.digest,
                size: record.reference.size,
            },
        }
    }

    /// Re-encode both tables, the config and the graph around replaced rows.
    /// The inventory is exactly what the result references: `records`, the
    /// encoded chunks its transfer maps name and non-record direct payloads,
    /// so only importer semantics, never graph structure, can reject it.
    fn finish(
        graph: &EncodedVmGraph,
        mut config: VmArtifactConfig,
        mut streams: Vec<StreamBinding>,
        mut objects: Vec<ObjectBinding>,
        mut records: Vec<RecordBlob>,
    ) -> EncodedVmGraph {
        streams.sort_by_key(|row| row.stream);
        objects.sort_by_key(|row| row.object());
        let stream_table = encode_stream_table(&streams).unwrap();
        let object_table = encode_object_table(&objects).unwrap();
        config.streams = stream_table.root.reference;
        config.objects = object_table.root.reference;
        for table in [stream_table, object_table] {
            records.push(table.root);
            records.extend(table.pages);
        }
        let held: BTreeMap<ContentDigest, &[u8]> = records
            .iter()
            .map(|record| (record.reference.digest, record.bytes.as_slice()))
            .collect();
        let mut referenced = BTreeSet::new();
        for row in &streams {
            let root: TransferRoot = decode_record(held[&row.transport.digest]).unwrap();
            let entries = verify_transfer(&root, |digest| {
                Ok::<_, oci::vm_artifact::Error>(held[&digest].to_vec())
            })
            .unwrap();
            for entry in entries {
                if let ChunkEntry::Data { encoded, .. } = entry {
                    referenced.insert(encoded.digest);
                }
            }
        }
        for row in &objects {
            if let ObjectBinding::Direct { payload, .. } = row {
                referenced.insert(payload.digest);
            }
        }
        let mut bulk = graph
            .payloads
            .iter()
            .copied()
            .filter(|payload| {
                payload.media_type != PayloadMediaType::Record
                    && referenced.contains(&payload.digest)
            })
            .map(|payload| (payload.digest, payload))
            .collect::<BTreeMap<_, _>>();
        for row in &objects {
            if let ObjectBinding::Direct { payload, .. } = row {
                if payload.media_type != PayloadMediaType::Record {
                    bulk.insert(payload.digest, *payload);
                }
            }
        }
        encode_vm_graph(&config, &records, &bulk.into_values().collect::<Vec<_>>()).unwrap()
    }

    /// Add `count` structurally valid all-zero streams of the maximum stream
    /// length. Zero entries carry no payload, so the graph claims terabytes
    /// of decoded staging without one bulk byte behind it.
    fn with_zero_streams(graph: &EncodedVmGraph, count: usize) -> EncodedVmGraph {
        let config = decode_vm_config(&graph.config.bytes).unwrap();
        let (mut streams, mut replaced) = stream_rows(graph, config.streams.digest);
        let (mut objects, object_tables) = object_rows(graph, config.objects.digest);
        replaced.extend(object_tables);
        let mut records = graph
            .records
            .iter()
            .filter(|record| !replaced.contains(&record.reference.digest))
            .cloned()
            .collect::<Vec<_>>();
        let zeros =
            vec![ChunkEntry::Zero { length: CHUNK_SIZE }; (MAX_STREAM_BYTES / CHUNK_SIZE) as usize];
        for index in 0..count {
            let length = MAX_STREAM_BYTES - index as u64 * CHUNK_SIZE;
            let map = RecordBlob::new(
                StreamRoot::empty(length, ChunkSize::DISK)
                    .unwrap()
                    .canonical_bytes()
                    .unwrap(),
            )
            .unwrap();
            let stream = oci::changeset::model::StreamIdentity::from_sha256(
                *map.reference.digest.as_bytes(),
            );
            let transport = encode_transfer(
                stream,
                length,
                &zeros[..length.div_ceil(CHUNK_SIZE) as usize],
            )
            .unwrap();
            objects.push(direct(&map));
            streams.push(StreamBinding {
                stream,
                length,
                map: map.reference.digest,
                chunk_size: CHUNK_SIZE,
                transport: transport.root.reference,
            });
            records.push(map);
            records.push(transport.root);
            records.extend(transport.pages);
        }
        finish(graph, config, streams, objects, records)
    }

    fn map_from_entries(length: u64, entries: &[ChunkEntry]) -> AuthenticatedMap {
        let mut nodes = MapNodeWriter::new().unwrap();
        let root = build_sorted(
            length,
            ChunkSize::DISK,
            entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| match entry {
                    ChunkEntry::Data { digest, .. } => Some(Ok(PresentChunk {
                        index: index as u64,
                        digest: Sha256Digest::from_bytes(*digest.as_bytes()),
                    })),
                    ChunkEntry::Zero { .. } => None,
                }),
            &mut nodes,
        )
        .unwrap();
        nodes
            .finish(root, StreamRole::Disk, None)
            .unwrap()
            .into_map()
    }

    fn map_digests(graph: &EncodedVmGraph, digest: ObjectDigest) -> Vec<ContentDigest> {
        let root = StreamRoot::decode(&record_bytes(graph, content(digest))).unwrap();
        let mut result = Vec::new();
        let mut pending = root
            .tree_digest()
            .map(|digest| vec![(digest, 4)])
            .unwrap_or_default();
        while let Some((digest, height)) = pending.pop() {
            let digest = ContentDigest::from_sha256(*digest.as_bytes());
            result.push(digest);
            let node = StreamNode::decode(&record_bytes(graph, digest), height).unwrap();
            if height > 0 {
                pending.extend(node.entries().map(|(_, child)| (child, height - 1)));
            }
        }
        result
    }

    /// Rewrite an exported image's root transfer with `forge`, then derive
    /// its canonical map, image record, both tables, config and index from
    /// the forged claims, as a hostile publisher would. Only decoded chunk
    /// correlation can tell the result from an honest artifact.
    fn forge_root_transfer(
        graph: &EncodedVmGraph,
        forge: impl FnOnce(&mut [ChunkEntry]),
    ) -> EncodedVmGraph {
        let mut config = decode_vm_config(&graph.config.bytes).unwrap();
        let semantic = Semantic::decode(
            config.content.kind,
            record_bytes(graph, config.content.record.digest),
        )
        .unwrap();
        let honest_record = content(semantic.digest);
        let SemanticRecord::Image(mut record) = semantic.record else {
            panic!("image artifact expected");
        };
        let honest = record.root.stream.clone();
        let (mut streams, mut replaced) = stream_rows(graph, config.streams.digest);
        let (mut objects, object_tables) = object_rows(graph, config.objects.digest);
        replaced.extend(object_tables);
        replaced.push(honest_record);
        replaced.push(content(honest.map));
        replaced.extend(map_digests(graph, honest.map));
        let position = streams
            .iter()
            .position(|row| row.stream == identity(honest.stream))
            .unwrap();
        let row = streams.remove(position);
        let (mut entries, transfer_records) = transfer_entries(graph, &row);
        replaced.extend(transfer_records);
        forge(&mut entries);
        let map = map_from_entries(honest.length, &entries);
        let (map_root, map_nodes) = canonical_map_bytes(&map).unwrap();
        let map_root = RecordBlob::new(map_root).unwrap();
        let map_nodes = map_nodes
            .into_iter()
            .map(|page| RecordBlob::new(page).unwrap())
            .collect::<Vec<_>>();
        record.root.stream = SnapshotStream {
            stream: map.id(),
            map: object(map_root.reference.digest),
            chunk_size: CHUNK_SIZE,
            length: honest.length,
        };
        let forged = Semantic::image(*record).unwrap();
        config.content = forged.content_ref();
        let transport = encode_transfer(identity(map.id()), honest.length, &entries).unwrap();
        streams.push(StreamBinding {
            stream: identity(map.id()),
            length: honest.length,
            map: map_root.reference.digest,
            chunk_size: CHUNK_SIZE,
            transport: transport.root.reference,
        });
        objects.retain(|row| !replaced.contains(&row.object()));
        let mut records = graph
            .records
            .iter()
            .filter(|record| !replaced.contains(&record.reference.digest))
            .cloned()
            .collect::<Vec<_>>();
        for blob in [RecordBlob::new(forged.bytes).unwrap(), map_root]
            .into_iter()
            .chain(map_nodes)
        {
            objects.push(direct(&blob));
            records.push(blob);
        }
        records.push(transport.root);
        records.extend(transport.pages);
        finish(graph, config, streams, objects, records)
    }

    /// Build a real retained EROFS graph from the admitted pack/index corpus.
    /// Repeating one layer deliberately retains two occurrence slots, not two
    /// physical payload copies.
    pub(crate) async fn layered_image() -> (
        tempfile::TempDir,
        Arc<Store>,
        StoredImageStore,
        ImageId,
        ImageRecord,
    ) {
        let (temp, store) = home().await;
        let (images, id, record) = layered_image_in(store.clone()).await;
        (temp, store, images, id, record)
    }

    pub(crate) async fn layered_image_in(
        store: Arc<Store>,
    ) -> (StoredImageStore, ImageId, ImageRecord) {
        use crate::store::models::snapshot::{
            SnapshotComposition, SnapshotLayer, SnapshotRootProfile,
        };
        let pool = StoragePool::open(store.images_path()).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let paths = pool
            .create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../oci/testdata/changesets/metadata-producers/silo-artifacts/case-0007/layer-0000",
        );
        let recipe_bytes = std::fs::read(fixture.join("recipe.json")).unwrap();
        let recipe_value: serde_json::Value = serde_json::from_slice(&recipe_bytes).unwrap();
        let diff_id: ContentDigest =
            serde_json::from_value(recipe_value["diffId"].clone()).unwrap();
        let index = std::fs::read(fixture.join("index.json")).unwrap();
        let changeset = oci::changeset::decode_index(
            &index,
            |digest| {
                Ok(std::fs::read(
                    fixture.join(format!("{}.json", object(digest).hex())),
                )?)
            },
            diff_id,
            &oci::changeset::ChangesetLimits::default(),
        )
        .unwrap();
        let (pack, roots) = pool
            .publish_stream_for_catalog(&fixture.join("payload.pack"))
            .unwrap();
        store
            .pin_published_storage_dependencies(operation, &[pack.id], &[])
            .await
            .unwrap();
        drop(roots);
        let pack_map =
            crate::store::snapshot_store::publish_map(&pool, &store, operation, &pack.map)
                .await
                .unwrap();
        let layer_recipe = oci::changeset::LayerRecipe { diff_id };
        let layer_result = oci::changeset::LayerResult {
            recipe: layer_recipe.id().unwrap(),
            pack_stream: identity(pack.id),
            pack_length: pack.length,
            index_root: ContentDigest::of_bytes(&index),
        };
        let index = oci::changeset::index::encode_index(
            &changeset,
            &oci::changeset::ChangesetLimits::default(),
        )
        .unwrap();
        assert_eq!(index.root.digest, layer_result.index_root);
        let recipe_digest = publish_fixture_object(
            &store,
            &pool,
            operation,
            &layer_recipe.canonical_bytes().unwrap(),
        )
        .await;
        let result_digest = publish_fixture_object(
            &store,
            &pool,
            operation,
            &layer_result.canonical_bytes().unwrap(),
        )
        .await;
        let root_digest = publish_fixture_object(&store, &pool, operation, &index.root.bytes).await;
        let mut index_pages = Vec::new();
        for page in index.pages {
            index_pages.push(publish_fixture_object(&store, &pool, operation, &page.bytes).await);
        }
        index_pages.sort();
        let pack_file = pool.open_stream(&pack.id).unwrap();
        let occurrence = oci::erofs::Layer {
            result: &layer_result,
            changeset: &changeset,
            pack: &pack_file,
        };
        let occurrences = [occurrence, occurrence];
        let recipe = oci::composition::CompositionRecipe::from_layers(
            oci::Platform::linux_amd64(),
            &occurrences,
        )
        .unwrap();
        let fsmeta_path = paths.temporary.join("fsmeta");
        let mut fsmeta = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&fsmeta_path)
            .unwrap();
        let composed =
            crate::storage::composition::compose(&recipe, &occurrences, &mut fsmeta).unwrap();
        let (published, roots) = pool
            .publish_object_file_for_catalog(fsmeta, &paths.temporary)
            .unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[published.digest])
            .await
            .unwrap();
        drop(roots);
        let graph = SnapshotComposition {
            result: crate::storage::identity::LowerResultId::from_composition(
                composed.result.id().unwrap(),
            ),
            record: publish_fixture_object(
                &store,
                &pool,
                operation,
                &composed.result.canonical_bytes().unwrap(),
            )
            .await,
            recipe: publish_fixture_object(
                &store,
                &pool,
                operation,
                &recipe.canonical_bytes().unwrap(),
            )
            .await,
            fsmeta: published.digest,
            layers: vec![
                SnapshotLayer {
                    recipe: recipe_digest,
                    result: result_digest,
                    index_root: root_digest,
                    index_pages,
                    pack: pack_map,
                };
                2
            ],
        };
        crate::store::layer_store::LayerStore::open(store.home_path())
            .await
            .unwrap()
            .publish_snapshot_composition(operation, &graph)
            .await
            .unwrap();
        let upper_path = paths.temporary.join("upper.raw");
        let upper = disk_image::ext4::upper::format_upper(
            &upper_path,
            rootfs_spec::upper_geometry::UpperCapacity::new(64 << 20).unwrap(),
        )
        .unwrap();
        let (upper_stream, roots) = pool.publish_stream_for_catalog(&upper_path).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[upper_stream.id], &[])
            .await
            .unwrap();
        drop(roots);
        let upper_map =
            crate::store::snapshot_store::publish_map(&pool, &store, operation, &upper_stream.map)
                .await
                .unwrap();
        let kernel =
            publish_fixture_object(&store, &pool, operation, b"layered fixture boot bytes").await;
        let mut snapshot =
            crate::store::models::snapshot::tests::record(upper_map.stream, upper_map.map, kernel);
        snapshot.root.stream = upper_map;
        snapshot.root.geometry.length = 64 << 20;
        snapshot.root.profile = SnapshotRootProfile::LinuxOverlay {
            lower: Box::new(graph),
            lower_geometry: vm_spec::DiskGeometry {
                length: composed.result.lower_length,
                logical_sector_size: 512,
            },
            lower_filesystem_uuid: uuid::Uuid::from_bytes(composed.result.fsmeta.uuid),
            upper_uuid: upper.uuid,
            ext4_profile: crate::Ext4Profile::SiloUpperExt4V1,
            overlay_profile: crate::OverlayProfile::SiloOverlayV1,
            temporary_directory: crate::TemporaryDirectoryPolicy::DiskBacked,
        };
        let crate::BootProfile::LinuxDirect { root_selector, .. } = &mut snapshot.boot else {
            panic!("Linux direct fixture");
        };
        *root_selector = crate::RootSelector::ManagedOverlay;
        let record = ImageRecord {
            schema: 2,
            kind: ImageRecordKind::Image,
            root: snapshot.root,
            boot: snapshot.boot,
            process: crate::ProcessConfig::default(),
        };
        let images = StoredImageStore::from_store(store.clone());
        let info = images
            .publish_owned(record.clone(), operation, lease, None, Vec::new(), None)
            .await
            .unwrap();
        (images, info.id, record)
    }

    #[tokio::test]
    async fn stopped_layered_snapshot_roundtrips_its_graph_and_private_upper() {
        let (_home, source, _images, _, image) = layered_image().await;
        let crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { kernel, .. },
            ..
        } = &image.boot
        else {
            panic!("pinned fixture");
        };
        let mut record = crate::store::models::snapshot::tests::record(
            image.root.stream.stream,
            image.root.stream.map,
            *kernel,
        );
        record.root = image.root;
        record.boot = image.boot;
        let crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay {
            lower,
            lower_geometry,
            ..
        } = &record.root.profile
        else {
            panic!("layered fixture");
        };
        record.configuration.spec.storage = Some(vm_spec::Storage {
            disks: vec![
                crate::machine::root_storage::disk(
                    "captured-disk-0",
                    vm_spec::DiskRole::RootLower,
                    lower_geometry.length,
                    "silo-root-lower".into(),
                )
                .unwrap(),
                crate::machine::root_storage::disk(
                    "captured-disk-1",
                    vm_spec::DiskRole::RootUpper,
                    record.root.geometry.length,
                    "silo-root-upper".into(),
                )
                .unwrap(),
            ],
        });
        let (streams, objects) = record.content_dependencies().unwrap();
        let (operation, lease) = source
            .begin_stopped_operation(
                "snapshot",
                &streams.into_iter().collect::<Vec<_>>(),
                &objects.into_iter().collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        source
            .pin_operation_lowers(operation, &[lower.result])
            .await
            .unwrap();
        let pool = StoragePool::open(source.images_path()).unwrap();
        let _paths = pool
            .create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let snapshots = crate::store::snapshot_store::SnapshotStore::from_store(source.clone());
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let prepared = export(
            source,
            ExportSource::Snapshot(Box::new(consumer)),
            ChunkEncoding::Zstd,
        )
        .await;
        let transfer = transfer(&prepared.graph, &prepared.payloads());
        let (_home, destination) = home().await;
        let verified = verify(
            &transfer,
            stage(&destination, &transfer).await,
            index_digest(&transfer),
        )
        .await
        .unwrap();
        let commit = commit_imported_artifact(verified, REFERENCE.into(), None)
            .await
            .unwrap();
        assert!(
            matches!(&commit.content, AcquiredContent::Snapshot(imported)
                if imported.id == info.id && imported.names == [REFERENCE])
        );
        let imported = crate::store::snapshot_store::SnapshotStore::from_store(destination.clone());
        let consumer = imported.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        assert_eq!(consumer.record, record);
        assert_eq!(consumer.record.streams().count(), 3);
    }

    async fn publish_fixture_object(
        store: &Store,
        pool: &StoragePool,
        operation: uuid::Uuid,
        bytes: &[u8],
    ) -> ObjectDigest {
        let input =
            crate::store::snapshot_store::RecordInput::new(store.images_path(), operation, bytes)
                .unwrap();
        let (object, roots) = pool.publish_object_for_catalog(&input.path()).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[object.digest])
            .await
            .unwrap();
        drop(roots);
        object.digest
    }

    #[tokio::test]
    async fn layered_exact_artifacts_roundtrip_without_producer_paths() {
        let (producer, source, images, id, record) = layered_image().await;
        let prepared = export(
            source.clone(),
            ExportSource::Image(Box::new(images.consume(id).await.unwrap())),
            ChunkEncoding::Raw,
        )
        .await;
        let transfer = transfer(&prepared.graph, &prepared.payloads());
        let crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay { lower, .. } =
            &record.root.profile
        else {
            panic!("layered fixture");
        };
        let graph = verified_graph(&transfer);
        let fsmeta_stream = graph
            .objects()
            .iter()
            .find_map(|object| match object {
                ObjectBinding::Stream { object, stream, .. }
                    if *object == content(lower.fsmeta) =>
                {
                    Some(crate::image::transport::closure::stream_id(*stream))
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(lower.layers.len(), 2);
        assert_eq!(lower.layers[0], lower.layers[1]);
        let lower_stream = lower
            .authenticate(|digest, maximum| {
                Ok(StoragePool::open(source.images_path())?.read_object(digest, maximum)?)
            })
            .unwrap()
            .result
            .lower_stream;
        drop(prepared);
        drop(images);
        drop(source);
        producer.close().unwrap();
        let (_home, destination) = home().await;
        let verified = verify(
            &transfer,
            stage(&destination, &transfer).await,
            index_digest(&transfer),
        )
        .await
        .unwrap();
        let committed = commit_imported_artifact(verified, REFERENCE.into(), Some("local".into()))
            .await
            .unwrap();
        let AcquiredContent::Image(imported) = &committed.content else {
            panic!("image import produced another kind");
        };
        assert_eq!(imported.id, id);
        let mut names = imported.names.clone();
        names.sort();
        assert_eq!(names, ["local", REFERENCE]);
        let pool = StoragePool::open(destination.images_path()).unwrap();
        assert!(pool.object_path(&lower.fsmeta).is_file());
        assert!(!pool.stream_path(&fsmeta_stream).exists());
        assert!(!pool
            .stream_path(&crate::image::transport::closure::stream_id(lower_stream))
            .exists());
        let imported = StoredImageStore::from_store(destination.clone());
        let retained = imported.consume(id).await.unwrap();
        assert_eq!(retained.info.record, record);
        let republished = export(
            destination,
            ExportSource::Image(Box::new(retained)),
            ChunkEncoding::Raw,
        )
        .await;
        assert_eq!(republished.graph.index.bytes, transfer.index);
    }

    /// A fully valid OCI transport graph whose semantic record makes a
    /// different claim about the same authenticated retained object graph.
    fn forge_layered_claim(
        graph: &EncodedVmGraph,
        mutate: impl FnOnce(&mut ImageRecord),
    ) -> EncodedVmGraph {
        let mut config = decode_vm_config(&graph.config.bytes).unwrap();
        let semantic = Semantic::decode(
            config.content.kind,
            record_bytes(graph, config.content.record.digest),
        )
        .unwrap();
        let old = content(semantic.digest);
        let SemanticRecord::Image(mut record) = semantic.record else {
            panic!("image fixture");
        };
        mutate(&mut record);
        let forged = Semantic::image(*record).unwrap();
        config.content = forged.content_ref();
        let (streams, mut replaced) = stream_rows(graph, config.streams.digest);
        let (mut objects, object_tables) = object_rows(graph, config.objects.digest);
        replaced.extend(object_tables);
        replaced.push(old);
        objects.retain(|row| row.object() != old);
        let mut records = graph
            .records
            .iter()
            .filter(|record| !replaced.contains(&record.reference.digest))
            .cloned()
            .collect::<Vec<_>>();
        let record = RecordBlob::new(forged.bytes).unwrap();
        objects.push(direct(&record));
        records.push(record);
        finish(graph, config, streams, objects, records)
    }

    #[tokio::test]
    async fn closed_layered_graph_rejects_grafted_indexes_results_and_root_uuids() {
        let (_home, source, images, id, _) = layered_image().await;
        let prepared = export(
            source,
            ExportSource::Image(Box::new(images.consume(id).await.unwrap())),
            ChunkEncoding::Raw,
        )
        .await;
        for case in 0..4 {
            let forged = forge_layered_claim(&prepared.graph, |record| {
                let crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay {
                    lower,
                    lower_filesystem_uuid,
                    upper_uuid,
                    ..
                } = &mut record.root.profile
                else {
                    panic!("layered fixture");
                };
                match case {
                    0 => *lower_filesystem_uuid = uuid::Uuid::new_v4(),
                    1 => *upper_uuid = uuid::Uuid::new_v4(),
                    2 => lower.layers[0].index_root = lower.layers[0].recipe,
                    3 => lower.layers[0].result = lower.layers[0].recipe,
                    _ => unreachable!(),
                }
            });
            let transfer = transfer(&forged, &prepared.payloads());
            let (_home, destination) = home().await;
            let staging = stage(&destination, &transfer).await;
            assert!(
                verify(&transfer, staging, index_digest(&transfer))
                    .await
                    .is_err(),
                "case {case}"
            );
            assert_eq!(
                count(
                    &database(&destination).await,
                    "SELECT count(*) FROM storage_image"
                )
                .await,
                0
            );
            assert_eq!(
                count(
                    &database(&destination).await,
                    "SELECT count(*) FROM storage_snapshot"
                )
                .await,
                0
            );
        }
    }

    const TAIL_BYTES: usize = 1 << 20;

    /// A published image whose root repeats one full nonzero chunk and ends
    /// with a short tail cut from those same bytes.
    async fn repeated_chunk_image() -> (
        tempfile::TempDir,
        Arc<Store>,
        StoredImageStore,
        ImageId,
        ImageRecord,
        Vec<u8>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new(&LocalPaths::new(temp.path().join("home")))
                .await
                .unwrap(),
        );
        let pool = StoragePool::open(store.images_path()).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        pool.create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let chunk = (0..CHUNK_SIZE)
            .map(|index| (index % 251) as u8 + 1)
            .collect::<Vec<_>>();
        let mut disk = chunk.clone();
        disk.extend_from_slice(&chunk);
        disk.extend_from_slice(&chunk[..TAIL_BYTES]);
        let path = temp.path().join("root.raw");
        std::fs::write(&path, &disk).unwrap();
        let (stream, roots) = pool.publish_stream_for_catalog(&path).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[stream.id], &[])
            .await
            .unwrap();
        drop(roots);
        let map = crate::store::snapshot_store::publish_map(&pool, &store, operation, &stream.map)
            .await
            .unwrap();
        let kernel = temp.path().join("kernel");
        std::fs::write(&kernel, b"repeated chunk boot fixture").unwrap();
        let (kernel, roots) = pool.publish_object_for_catalog(&kernel).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[kernel.digest])
            .await
            .unwrap();
        drop(roots);
        let snapshot =
            crate::store::models::snapshot::tests::record(stream.id, map.map, kernel.digest);
        let mut record = ImageRecord {
            schema: 2,
            kind: ImageRecordKind::Image,
            root: snapshot.root,
            boot: snapshot.boot,
            process: crate::ProcessConfig::default(),
        };
        record.root.geometry.length = map.length;
        record.root.stream = map;
        let images = StoredImageStore::from_store(store.clone());
        let info = images
            .publish_owned(record.clone(), operation, lease, None, Vec::new(), None)
            .await
            .unwrap();
        (temp, store, images, info.id, record, disk)
    }

    /// Re-encode `graph` with a mutated config and optional surplus object
    /// rows, keeping every other byte. Used to prove the importer's semantic
    /// checks, not the graph layer's, reject a well-formed contradiction.
    fn reencode(
        graph: &EncodedVmGraph,
        mutate: impl FnOnce(&mut VmArtifactConfig),
        surplus: Vec<RecordBlob>,
    ) -> EncodedVmGraph {
        let mut config = decode_vm_config(&graph.config.bytes).unwrap();
        let record = |digest: ContentDigest| {
            graph
                .records
                .iter()
                .find(|record| record.reference.digest == digest)
                .unwrap()
                .bytes
                .clone()
        };
        let root: ObjectTableRoot = decode_record(&record(config.objects.digest)).unwrap();
        let mut rows = Vec::new();
        let mut table = vec![config.objects.digest];
        for page in &root.pages {
            table.push(page.digest);
            let page: ObjectTablePage = decode_record(&record(page.digest)).unwrap();
            rows.extend(page.entries);
        }
        for extra in &surplus {
            rows.push(ObjectBinding::Direct {
                object: extra.reference.digest,
                size: extra.reference.size,
                payload: extra.reference.payload(),
            });
        }
        rows.sort_by_key(|row| row.object());
        let encoded = encode_object_table(&rows).unwrap();
        config.objects = encoded.root.reference;
        mutate(&mut config);
        let mut records = graph
            .records
            .iter()
            .filter(|record| !table.contains(&record.reference.digest))
            .cloned()
            .collect::<Vec<_>>();
        records.push(encoded.root);
        records.extend(encoded.pages);
        records.extend(surplus);
        // `graph.payloads` is the whole inventory, records included. Pass
        // only bulk payloads so replaced table records do not linger as
        // unreferenced inventory; every kept record travels in `records`.
        let bulk = graph
            .payloads
            .iter()
            .filter(|payload| payload.media_type != PayloadMediaType::Record)
            .copied()
            .collect::<Vec<_>>();
        encode_vm_graph(&config, &records, &bulk).unwrap()
    }

    #[tokio::test]
    async fn image_round_trip_keeps_identity_across_encodings_with_one_receipt_each() {
        let (temp, images, record, operation, lease) =
            crate::store::stored_image_store::tests::fixture().await;
        let info = images
            .publish_owned(record.clone(), operation, lease, None, Vec::new(), None)
            .await
            .unwrap();
        let source = Arc::new(
            Store::new(&LocalPaths::new(temp.path().join("home")))
                .await
                .unwrap(),
        );
        let mut transfers = Vec::new();
        for encoding in [ChunkEncoding::Zstd, ChunkEncoding::Raw, ChunkEncoding::Zstd] {
            let consumer = images.consume(info.id).await.unwrap();
            let prepared = export(
                source.clone(),
                ExportSource::Image(Box::new(consumer)),
                encoding,
            )
            .await;
            assert_eq!(prepared.content, crate::ArtifactContent::Image(info.id));
            transfers.push(transfer(&prepared.graph, &prepared.payloads()));
        }
        // Encoding changes the index digest, never the canonical identity.
        assert_ne!(index_digest(&transfers[0]), index_digest(&transfers[1]));
        // A repeated publication reuses the registered representation and
        // reproduces the exact graph bytes.
        assert_eq!(transfers[0].index, transfers[2].index);
        assert_eq!(transfers[0].blobs, transfers[2].blobs);
        let (_destination_temp, destination) = home().await;
        for transfer in &transfers {
            let staging = stage(&destination, transfer).await;
            let operation = staging.operation.id;
            assert!(reservation(&destination, operation).await.is_some());
            let verified = verify(transfer, staging, index_digest(transfer))
                .await
                .unwrap();
            let committed =
                commit_acquisition(&destination, operation, verified, REFERENCE.into(), None)
                    .await
                    .unwrap();
            // Every copy exists: the committed pull no longer holds its peak.
            assert_eq!(reservation(&destination, operation).await, None);
            assert!(!ledger_holds(&destination, operation));
            let AcquiredContent::Image(imported) = &committed else {
                panic!("image import produced another kind");
            };
            assert_eq!(imported.id, info.id);
            assert_eq!(imported.record, record);
            assert_eq!(imported.names, [REFERENCE]);
        }
        let catalog = database(&destination).await;
        let bytes: Vec<u8> =
            sqlx::query_scalar("SELECT record_bytes FROM storage_image WHERE id=?1")
                .bind(info.id.to_string())
                .fetch_one(&catalog)
                .await
                .unwrap();
        assert_eq!(bytes, record.canonical_bytes().unwrap());
        assert_eq!(
            count(
                &catalog,
                "SELECT COUNT(DISTINCT index_digest) FROM managed_artifact_acquisition"
            )
            .await,
            2
        );
        assert_eq!(
            count(
                &catalog,
                "SELECT COUNT(*) FROM storage_operation WHERE kind='capture'"
            )
            .await,
            0
        );
        // The imported image is consumable from the destination's own pool.
        let destination_images =
            crate::store::stored_image_store::StoredImageStore::from_store(destination.clone());
        let consumer = destination_images.consume(info.id).await.unwrap();
        assert_eq!(consumer.info.record, record);
    }

    #[tokio::test]
    async fn stopped_snapshot_rejects_contradictions_and_resumes_from_rehashed_cache() {
        let (_temp, snapshots, record, operation, _lease) =
            crate::store::snapshot_store::tests::fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let prepared = export(
            snapshots.store.clone(),
            ExportSource::Snapshot(Box::new(consumer)),
            ChunkEncoding::Zstd,
        )
        .await;
        assert_eq!(prepared.content, crate::ArtifactContent::Snapshot(info.id));
        let staged = prepared.payloads();
        let good = transfer(&prepared.graph, &staged);
        let (_destination_temp, destination) = home().await;

        // An index other than the one resolution observed is never admitted.
        let staging = stage(&destination, &good).await;
        assert!(matches!(
            verify(&good, staging, ObjectDigest::of_bytes(b"other index")).await,
            Err(LibVmError::ArtifactInvalid { .. })
        ));

        // A well-formed config that contradicts the canonical record.
        let lying = transfer(
            &reencode(
                &prepared.graph,
                |config| {
                    config.guest_platform.architecture = oci::vm_artifact::wire::Architecture::Arm64
                },
                Vec::new(),
            ),
            &staged,
        );
        let staging = stage(&destination, &lying).await;
        let error = verify(&lying, staging, index_digest(&lying))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(
                error,
                LibVmError::ArtifactInvalid {
                    boundary: "config",
                    ..
                }
            ),
            "{error}"
        );

        // A surplus descriptor-backed object is not retained semantic authority.
        let surplus = transfer(
            &reencode(
                &prepared.graph,
                |_| {},
                vec![RecordBlob::new(b"{\"unrelated\":true}".to_vec()).unwrap()],
            ),
            &staged,
        );
        let staging = stage(&destination, &surplus).await;
        let error = verify(&surplus, staging, index_digest(&surplus))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(
                error,
                LibVmError::ArtifactInvalid {
                    boundary: "object table",
                    ..
                }
            ),
            "{error}"
        );

        // A cached chunk corrupted after staging fails decode verification;
        // the retry rehashes, replaces it and then admits identical content.
        let staging = stage(&destination, &good).await;
        let chunk = prepared
            .graph
            .payloads
            .iter()
            .find(|payload| {
                matches!(
                    payload.media_type,
                    oci::vm_artifact::wire::PayloadMediaType::ZstdChunk
                        | oci::vm_artifact::wire::PayloadMediaType::RawChunk
                )
            })
            .copied()
            .unwrap();
        let path = destination
            .images_path()
            .join("transport/sha256")
            .join(&chunk.digest.to_string()[7..]);
        let mut corrupt = good.blobs[&chunk.digest].clone();
        corrupt[0] ^= 0xff;
        std::fs::write(&path, &corrupt).unwrap();
        assert!(verify(&good, staging, index_digest(&good)).await.is_err());
        let staging = stage(&destination, &good).await;
        assert_eq!(std::fs::read(&path).unwrap(), good.blobs[&chunk.digest]);
        let verified = verify(&good, staging, index_digest(&good)).await.unwrap();
        let parts = verified.into_parts();
        let VerifiedContent::SnapshotWithoutMemory { id, bytes, .. } = &parts.content else {
            panic!("snapshot without memory expected");
        };
        assert_eq!(*id, info.id);
        assert_eq!(*bytes, record.canonical_bytes().unwrap());
        assert_eq!(parts.index_digest, index_digest(&good));
        assert_eq!(parts.receipt.index_digest, index_digest(&good));
        assert_eq!(parts.receipt.repository, REPOSITORY);
        assert_eq!(parts.index_bytes, good.index);
        for stream in record.streams() {
            let held = &parts.streams[&stream.stream];
            assert_eq!(held.canonical_map, stream.map);
            assert_eq!(held.map.id(), stream.stream);
        }
        let (_, objects) = record.content_dependencies().unwrap();
        let mut expected = objects;
        expected.insert(info.record_digest);
        assert!(expected
            .iter()
            .all(|digest| parts.objects.contains_key(digest)));
    }

    #[tokio::test]
    async fn snapshot_with_memory_imports_portable_seal_without_local_capture_authority() {
        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let changes = std::fs::read(
            directory
                .path()
                .join(vm_spec::capture::CAPTURE_RAM_CHANGES_FILE),
        )
        .unwrap();
        let changes_digest = ObjectDigest::of_bytes(&changes);
        let capture = fixture.reservation.record.capture_id;
        let info = fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let source_record = consumer.record.clone();
        let prepared = export(
            fixture.snapshots.store.clone(),
            ExportSource::Snapshot(Box::new(consumer)),
            ChunkEncoding::Zstd,
        )
        .await;
        assert_eq!(prepared.content, crate::ArtifactContent::Snapshot(info.id));
        let config = decode_vm_config(&prepared.graph.config.bytes).unwrap();
        assert!(config.memory.is_some());
        assert!(config.provenance().is_some());
        let good = transfer(&prepared.graph, &prepared.payloads());
        // Blob digests measure the transported encoding at export, independently
        // of RAM and disk Merkle identities in the capture inventory.
        let (rows, _) = stream_rows(&prepared.graph, config.streams.digest);
        for row in &rows {
            for entry in transfer_entries(&prepared.graph, row).0 {
                if let ChunkEntry::Data { encoded, .. } = entry {
                    let bytes = &good.blobs[&encoded.digest];
                    assert_eq!(ContentDigest::of_bytes(bytes), encoded.digest);
                    assert_eq!(bytes.len() as u64, encoded.size);
                }
            }
        }
        // Ingest refuses bytes that differ from their transported blob digest,
        // even when the semantic stream identity and resolved index match.
        let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
            &source_record.memory
        else {
            panic!("snapshot with memory expected");
        };
        let ram = rows
            .iter()
            .find(|row| row.stream == identity(execution.memory.stream))
            .unwrap();
        let ram_blob = transfer_entries(&prepared.graph, ram)
            .0
            .into_iter()
            .find_map(|entry| match entry {
                ChunkEntry::Data { encoded, .. } => Some(encoded),
                ChunkEntry::Zero { .. } => None,
            })
            .unwrap();
        let (_corrupt_temp, corrupt_destination) = home().await;
        let corrupt_staging = stage(&corrupt_destination, &good).await;
        let path = corrupt_destination
            .images_path()
            .join("transport/sha256")
            .join(object(ram_blob.digest).hex());
        let mut corrupted = good.blobs[&ram_blob.digest].clone();
        corrupted[0] ^= 0xff;
        std::fs::write(path, corrupted).unwrap();
        assert!(verify(&good, corrupt_staging, index_digest(&good))
            .await
            .is_err());
        let (_destination_temp, destination) = home().await;
        let staging = stage(&destination, &good).await;
        let verified = verify(&good, staging, index_digest(&good)).await.unwrap();
        let committed = commit_imported_artifact(verified, REFERENCE.into(), None)
            .await
            .unwrap();
        let AcquiredContent::Snapshot(imported) = &committed.content else {
            panic!("snapshot import produced another kind");
        };
        assert_eq!(imported.id, info.id);
        assert!(imported.provenance.is_empty());
        drop(committed);
        let pool = StoragePool::open(destination.images_path()).unwrap();
        destination
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(
            pool.read_object(&changes_digest, changes.len() as u64)
                .unwrap(),
            changes
        );
        let catalog = database(&destination).await;
        let bytes: Vec<u8> =
            sqlx::query_scalar("SELECT record_bytes FROM storage_snapshot WHERE id=?1")
                .bind(info.id.to_string())
                .fetch_one(&catalog)
                .await
                .unwrap();
        assert_eq!(bytes, source_record.canonical_bytes().unwrap());
        for (query, expected) in [
            ("SELECT COUNT(*) FROM snapshot_imported_capture", 1),
            ("SELECT COUNT(*) FROM snapshot_capture_change", 1),
            ("SELECT COUNT(*) FROM snapshot_capture_provenance", 0),
            ("SELECT COUNT(*) FROM managed_artifact_acquisition", 1),
            (
                "SELECT COUNT(*) FROM storage_operation WHERE kind='capture'",
                0,
            ),
        ] {
            assert_eq!(count(&catalog, query).await, expected, "{query}");
        }
        // Re-export of the imported snapshot uses its verified wrapper.
        let reconsumed =
            crate::store::snapshot_store::SnapshotStore::from_store(destination.clone())
                .consume(&SnapshotRef::Id(info.id))
                .await
                .unwrap();
        assert_eq!(reconsumed.imported_provenance().len(), 1);
        let again = export(
            destination.clone(),
            ExportSource::Snapshot(Box::new(reconsumed)),
            ChunkEncoding::Zstd,
        )
        .await;
        assert_eq!(
            decode_vm_config(&again.graph.config.bytes)
                .unwrap()
                .provenance(),
            config.provenance()
        );
    }

    #[test]
    fn destinations_split_tags_but_never_ports_or_digests() {
        assert_eq!(
            parse_destination("registry.example:5000/team/vm:v1").unwrap(),
            ("registry.example:5000/team/vm".into(), Some("v1".into()))
        );
        assert_eq!(
            parse_destination("registry.example:5000/team/vm").unwrap(),
            ("registry.example:5000/team/vm".into(), None)
        );
        for invalid in [
            "registry.example/vm@sha256:00",
            "registry.example/vm:",
            "registry.example/vm:-bad",
            "registry.example/vm:bad/tag",
            "",
            ":tag",
        ] {
            assert!(parse_destination(invalid).is_err(), "{invalid}");
        }
        assert!(parse_destination(&format!("r.example/vm:{}", "a".repeat(129))).is_err());
        assert!(parse_destination(&format!("r.example/vm:{}", "a".repeat(128))).is_ok());
    }

    /// The stopped-snapshot fixture, published and exported once as zstd.
    pub(crate) async fn stopped_export() -> (
        tempfile::TempDir,
        crate::storage::locks::StorageLock,
        PreparedVmArtifact,
    ) {
        let (temp, snapshots, record, operation, lease) =
            crate::store::snapshot_store::tests::fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let prepared = export(
            snapshots.store.clone(),
            ExportSource::Snapshot(Box::new(consumer)),
            ChunkEncoding::Zstd,
        )
        .await;
        (temp, lease, prepared)
    }

    #[tokio::test]
    async fn acquisition_admits_its_complete_peak_and_recovery_retires_it_with_its_owner() {
        let (_temp, _lease, prepared) = stopped_export().await;
        let good = transfer(&prepared.graph, &prepared.payloads());
        let graph = verified_graph(&good);
        let inventory: u64 = graph.inventory().values().map(|payload| payload.size).sum();
        let streams: u64 = graph.streams().iter().map(|row| row.length).sum();
        let objects: u64 = graph.objects().iter().map(ObjectBinding::size).sum();
        let identity_records: u64 = graph
            .streams()
            .iter()
            .map(|row| {
                row.length.div_ceil(row.chunk_size) * (std::mem::size_of::<u64>() + 32) as u64
            })
            .sum();
        let identity_maps: u64 = graph
            .streams()
            .iter()
            .map(|row| {
                vm_spec::stream_map::worst_case_map_bytes(
                    row.length,
                    ChunkSize::from_bytes(row.chunk_size).unwrap(),
                )
                .unwrap()
            })
            .sum();
        let receipt = crate::storage::limits::Resource::MetadataPageBytes.maximum();
        let charge = acquisition_space_charge(&graph).unwrap();
        // Admission covers decoded staging, identity construction scratch and
        // catalog copies, independently of sparsity and content deduplication.
        assert!(streams > 0 && objects > 0 && identity_records > 0 && identity_maps > 0);
        assert_eq!(
            charge,
            3 * inventory + 2 * streams + objects + identity_records + identity_maps + 2 * receipt
        );
        let (_destination_temp, destination) = home().await;
        let pool = StoragePool::open(destination.images_path()).unwrap();
        let catalog = database(&destination).await;
        let operation = begin_acquisition(&destination, &pool, &graph)
            .await
            .unwrap();
        let id = operation.id;
        assert_eq!(reservation(&destination, id).await, Some(charge));
        assert!(ledger_holds(&destination, id));
        assert_eq!(
            count(&catalog, "SELECT COUNT(*) FROM storage_operation_cache").await,
            graph.inventory().len() as i64
        );
        // A live, possibly detached, owner keeps its charge through recovery.
        destination
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(reservation(&destination, id).await, Some(charge));
        assert!(ledger_holds(&destination, id));
        // Once the owner is gone, recovery retires the charge, its ledger
        // entry and the cache pins together with the operation.
        drop(operation);
        destination
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(reservation(&destination, id).await, None);
        assert!(!ledger_holds(&destination, id));
        for query in [
            "SELECT COUNT(*) FROM storage_operation_cache",
            "SELECT COUNT(*) FROM capture_resource_reservation",
            "SELECT COUNT(*) FROM storage_operation",
        ] {
            assert_eq!(count(&catalog, query).await, 0, "{query}");
        }
    }

    #[tokio::test]
    async fn acquisition_capacity_refusal_precedes_every_payload_effect() {
        let (_temp, _lease, prepared) = stopped_export().await;
        // Structurally valid, but claims three more maximum all-zero streams.
        let huge = transfer(&with_zero_streams(&prepared.graph, 3), &prepared.payloads());
        let graph = verified_graph(&huge);
        let charge = acquisition_space_charge(&graph).unwrap();
        assert!(charge > 6 * MAX_STREAM_BYTES);
        let (_destination_temp, destination) = home().await;
        let pool = StoragePool::open(destination.images_path()).unwrap();
        let catalog = database(&destination).await;
        // A concurrently admitted copy peak on the same filesystem.
        let disk = OwnedDirectory::open_existing_root(destination.images_path())
            .unwrap()
            .unwrap();
        let filesystem = nix::sys::statvfs::fstatvfs(disk.fd()).unwrap();
        let available = filesystem
            .blocks_available()
            .checked_mul(filesystem.fragment_size())
            .unwrap();
        let blocked = available / 4 * 3;
        let (blocker, lease) = destination
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let _blocker = pool.create_operation_with_lease(blocker, lease).unwrap();
        destination
            .reserve_import_space(blocker, blocked)
            .await
            .unwrap();
        let error = begin_acquisition(&destination, &pool, &graph)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(
                &error,
                LibVmError::DiskImport(refusal)
                    if matches!(**refusal, crate::DiskImportError::Capacity { required, available }
                        if required == blocked + charge && required > available)
            ),
            "{error}"
        );
        // Refused before any bulk effect: no cached blob, no pin, no charge.
        assert!(
            std::fs::read_dir(destination.images_path().join("transport/sha256"))
                .unwrap()
                .next()
                .is_none()
        );
        assert_eq!(
            count(&catalog, "SELECT COUNT(*) FROM storage_operation_cache").await,
            0
        );
        assert_eq!(
            count(
                &catalog,
                "SELECT COUNT(*) FROM capture_resource_reservation"
            )
            .await,
            1
        );
        // Recovery retires the refused operation; the live blocker keeps its
        // reservation.
        destination
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(
            count(&catalog, "SELECT COUNT(*) FROM storage_operation").await,
            1
        );
        assert_eq!(reservation(&destination, blocker).await, Some(blocked));
    }

    #[tokio::test]
    async fn repeated_chunks_dedupe_but_contradictory_decoded_claims_fail_in_verification() {
        let (_temp, source, images, id, record, disk) = repeated_chunk_image().await;
        let consumer = images.consume(id).await.unwrap();
        let prepared = export(
            source.clone(),
            ExportSource::Image(Box::new(consumer)),
            ChunkEncoding::Zstd,
        )
        .await;
        let staged = prepared.payloads();
        let good = transfer(&prepared.graph, &staged);
        let config = decode_vm_config(&prepared.graph.config.bytes).unwrap();
        let (rows, _) = stream_rows(&prepared.graph, config.streams.digest);
        let root = rows
            .iter()
            .find(|row| row.stream == identity(record.root.stream.stream))
            .unwrap();
        let (entries, _) = transfer_entries(&prepared.graph, root);
        let [ChunkEntry::Data {
            digest: first,
            encoded: repeated,
            ..
        }, ChunkEntry::Data {
            digest: second,
            encoded: again,
            ..
        }, ChunkEntry::Data {
            length: tail,
            digest: tail_digest,
            encoded: tail_encoded,
        }] = entries.as_slice()
        else {
            panic!("two repeated full chunks and a tail expected: {entries:?}");
        };
        assert_eq!((first, repeated), (second, again));
        assert_ne!(repeated, tail_encoded);
        assert_eq!(*tail, TAIL_BYTES as u64);
        assert_eq!(*tail_digest, ContentDigest::of_bytes(&disk[..TAIL_BYTES]));
        assert!(
            repeated.size < *tail,
            "the full-chunk frame must fit the tail"
        );
        let repeated = *repeated;

        // A repeat asserting another decoded digest for the same frame.
        let forged_digest = transfer(
            &forge_root_transfer(&prepared.graph, |entries| {
                let ChunkEntry::Data { digest, .. } = &mut entries[1] else {
                    panic!("data chunk expected");
                };
                *digest = ContentDigest::of_bytes(b"forged decoded chunk");
            }),
            &staged,
        );
        // A short tail reusing the full-chunk frame: its prefix happens to be
        // the true tail, but the frame's content size is not the tail length.
        let forged_tail = transfer(
            &forge_root_transfer(&prepared.graph, |entries| {
                let ChunkEntry::Data { length, digest, .. } = entries[2].clone() else {
                    panic!("data chunk expected");
                };
                entries[2] = ChunkEntry::Data {
                    length,
                    digest,
                    encoded: repeated,
                };
            }),
            &staged,
        );
        let (_destination_temp, destination) = home().await;
        for forged in [&forged_digest, &forged_tail] {
            assert_ne!(forged.index, good.index);
            let staging = stage(&destination, forged).await;
            let error = verify(forged, staging, index_digest(forged))
                .await
                .err()
                .unwrap();
            assert!(
                matches!(
                    &error,
                    LibVmError::ArtifactInvalid { boundary: "chunk", message }
                        if message.contains("contradictory decoded assertions")
                ),
                "{error}"
            );
        }
        // Refused inside verification: nothing reached the canonical pool.
        for directory in ["objects/sha256", "streams/sha256"] {
            assert!(
                std::fs::read_dir(destination.images_path().join(directory))
                    .unwrap()
                    .next()
                    .is_none(),
                "{directory}"
            );
        }

        // The honest repeat decodes its frame once and copies exact bytes.
        let parts = verify(&good, stage(&destination, &good).await, index_digest(&good))
            .await
            .unwrap()
            .into_parts();
        let held = &parts.streams[&record.root.stream.stream];
        assert_eq!(
            *held.map,
            map_from_entries(
                disk.len() as u64,
                &[
                    ChunkEntry::Data {
                        length: CHUNK_SIZE,
                        digest: *first,
                        encoded: repeated
                    },
                    ChunkEntry::Data {
                        length: CHUNK_SIZE,
                        digest: *first,
                        encoded: repeated
                    },
                    ChunkEntry::Data {
                        length: *tail,
                        digest: *tail_digest,
                        encoded: *tail_encoded
                    },
                ]
            )
        );
        let mut chunks = vec![repeated.digest, tail_encoded.digest];
        chunks.sort();
        assert_eq!(
            held.transport
                .chunks
                .iter()
                .map(|chunk| chunk.digest)
                .collect::<Vec<_>>(),
            chunks
        );
        let mut bytes = vec![0; disk.len()];
        held.file.read_exact_at(&mut bytes, 0).unwrap();
        assert!(bytes == disk);
        drop(parts);
        let staging = stage(&destination, &good).await;
        let operation = staging.operation.id;
        let verified = verify(&good, staging, index_digest(&good)).await.unwrap();
        let imported =
            commit_acquisition(&destination, operation, verified, REFERENCE.into(), None)
                .await
                .unwrap();
        let AcquiredContent::Image(imported) = imported else {
            panic!("image import produced another kind");
        };
        assert_eq!(imported.id, id);
        assert_eq!(imported.record, record);
    }
}
