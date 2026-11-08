//! OCI acquisition into retained layered compositions.
//!
//! ```text
//! resolved(manifest, config, platform)
//!   lock(selection)
//!   ├─ catalog row ─► hold exact retained composition ─► record
//!   │                 (no OCI source, no encoder; missing bytes refuse)
//!   └─ miss ─► every ordered occurrence:
//!                retained recipe ─► reuse (no download)
//!                otherwise ──────► ingest_changeset ─► LayerStore::publish
//!              pin each result to the acquisition operation
//!            ─► compose_retained ─► image rows + image_composition_artifact
//! ```
//!
//! No whole-lower stream is ever written: the lower is the composition graph.
//! `prepare_exact_composition` rebuilds a received graph from local or OCI
//! layers and accepts it only if it reproduces the expected result exactly.

use std::future::Future;

use ::oci::changeset::{
    ChangesetLimits, ContentDigest, LayerRecipe, LayerResultId, StagedChangeset,
};
use ::oci::{MaterializeOptions, OciError, OciMaterializer, RootfsLayerMetadata, RootfsMetadata};
use serde::{Deserialize, Serialize};

use crate::image::{
    progress::oci_progress_reporter, ImageCacheState, ImageProgress, ImageProgressSender,
    ImageSourceKind, MaterializedImage, MaterializedRoot, ResolvedOciImage,
    ResolvedOciImageMaterialization,
};
use crate::storage::identity::{LowerResultId, ObjectDigest};
use crate::storage::pool::StoragePool;
use crate::store::composition_store::{HeldComposition, RetainedComposition};
use crate::store::layer_store::LayerStore;
use crate::store::models::snapshot::SnapshotComposition;
use crate::store::models::storage::{GuestArchitecture, LinuxPlatform};
use crate::store::models::{
    ImageCompositionArtifactRecord, ImageConfigRecord, ImageLayerRecord, ImageManifestLayerRecord,
    ImageManifestRecord, ImageRefRecord, MachineId, OciImageRecord,
};
use crate::store::{ImageStore, Store};
use crate::LibVmError;

pub(crate) fn image_error(reference: &str, source: OciError) -> LibVmError {
    match source {
        OciError::InvalidReference { .. }
        | OciError::RegistryPolicyDenied { .. }
        | OciError::VmArtifactRequiresAcquisition { .. } => LibVmError::ImageReferenceRejected {
            reference: reference.into(),
            message: source.to_string(),
        },
        source => LibVmError::Image {
            reference: reference.into(),
            source,
        },
    }
}

pub(crate) fn storage_error(error: crate::storage::StorageError) -> LibVmError {
    LibVmError::Storage(error)
}

fn invalid(message: impl std::fmt::Display) -> LibVmError {
    LibVmError::StateDecode {
        field: "image.composition",
        message: message.to_string(),
    }
}

/// The OCI spelling of an admitted Linux userspace platform.
pub(crate) fn oci_platform(platform: &LinuxPlatform) -> ::oci::Platform {
    ::oci::Platform {
        os: "linux".into(),
        architecture: match platform.architecture {
            GuestArchitecture::Amd64 => "amd64",
            GuestArchitecture::Arm64 => "arm64",
        }
        .into(),
        variant: platform.variant.clone(),
    }
}

pub(crate) fn cached_resolved_oci_image(
    image: &OciImageRecord,
    reference: String,
) -> ResolvedOciImage {
    ResolvedOciImage {
        requested_reference: reference,
        selected_reference: image.reference.selected_reference.clone(),
        manifest_digest: image.manifest.digest.clone(),
        config_digest: image.config.digest.clone(),
        config: image.config.metadata.clone(),
        platform: ::oci::Platform {
            os: image.manifest.platform_os.clone(),
            architecture: image.manifest.platform_architecture.clone(),
            variant: image.manifest.platform_variant.clone(),
        },
        cache_state: ImageCacheState::Complete,
        materialization: ResolvedOciImageMaterialization::Cached,
    }
}

pub(crate) async fn resolve_oci_image_from_registry(
    producer: &OciMaterializer,
    reference: String,
    options: MaterializeOptions,
    progress: Option<ImageProgressSender>,
) -> Result<ResolvedOciImage, LibVmError> {
    let image = producer
        .resolve(
            &reference,
            &options.platform,
            oci_progress_reporter(progress),
        )
        .await
        .map_err(|error| image_error(&reference, error))?;
    Ok(ResolvedOciImage {
        requested_reference: image.requested_reference.clone(),
        selected_reference: image.selected_reference.clone(),
        manifest_digest: image.manifest_digest.clone(),
        config_digest: image.config_digest.clone(),
        config: image.config.clone(),
        platform: image.platform.clone(),
        cache_state: ImageCacheState::Missing,
        materialization: ResolvedOciImageMaterialization::Registry(Box::new(image)),
    })
}

fn ensure_resolved_oci_identity(
    resolved: &ResolvedOciImage,
    image: &OciImageRecord,
) -> Result<(), LibVmError> {
    if image.reference.selected_reference == resolved.selected_reference
        && image.manifest.digest == resolved.manifest_digest
        && image.config.digest == resolved.config_digest
        && image.config.metadata == resolved.config
        && image.manifest.platform_os == resolved.platform.os
        && image.manifest.platform_architecture == resolved.platform.architecture
        && image.manifest.platform_variant == resolved.platform.variant
    {
        return Ok(());
    }
    Err(LibVmError::StateDecode {
        field: "resolved_oci_image",
        message: "materialized image does not match the resolved OCI identity".into(),
    })
}

/// One OCI selection's catalog record and its leased exact composition.
/// The held composition's consumer lease pins the lower, its layers, packs
/// and objects until dropped; machine creation records its own dependency
/// while holding it.
pub(crate) struct AcquiredComposition {
    pub(crate) record: OciImageRecord,
    pub(crate) held: HeldComposition,
}

pub(crate) fn materialized_image(
    acquired: AcquiredComposition,
    requested_reference: &str,
) -> MaterializedImage {
    let AcquiredComposition { record, held } = acquired;
    MaterializedImage {
        root: MaterializedRoot::Layered(Box::new(held)),
        requested_reference: requested_reference.into(),
        selected_reference: Some(record.reference.selected_reference),
        source_kind: ImageSourceKind::Oci,
        image_id: Some(record.manifest.image_id),
        manifest_digest: Some(record.manifest.digest),
        config_digest: Some(record.config.digest),
        platform: ::oci::Platform {
            os: record.manifest.platform_os,
            architecture: record.manifest.platform_architecture,
            variant: record.manifest.platform_variant,
        },
        managed: None,
        _lease: None,
    }
}

/// Serializes concurrent acquisitions of one selected identity so a second
/// caller reuses the first caller's layers instead of downloading them again.
fn acquisition_key(resolved: &ResolvedOciImage) -> Result<ObjectDigest, LibVmError> {
    let bytes = serde_json::to_vec(&(
        "oci-composition",
        &resolved.manifest_digest,
        &resolved.config_digest,
        &resolved.platform,
    ))
    .map_err(invalid)?;
    Ok(ObjectDigest::of_bytes(&bytes))
}

/// The catalog row may name only this exact retained composition.
fn check_image_lower(
    image: &OciImageRecord,
    retained: &RetainedComposition,
) -> Result<(), LibVmError> {
    let platform = &retained.recipe.platform;
    if retained.id != image.artifact.lower
        || retained.result.lower_length != image.artifact.lower_length
        || platform.os != image.manifest.platform_os
        || platform.architecture != image.manifest.platform_architecture
        || platform.variant != image.manifest.platform_variant
        || retained.layers.len() != image.manifest_layers.len()
    {
        return Err(invalid(
            "image catalog row contradicts its retained composition",
        ));
    }
    Ok(())
}

/// Acquire the layered composition of an already selected OCI identity.
///
/// Callers must run this inside a task that owns it to completion, never in
/// a caller-cancellable future: blocking ingest, publication and composition
/// workers keep running after a drop and own the acquisition lease.
pub(crate) async fn acquire_composition(
    store: &Store,
    producer: &OciMaterializer,
    progress: Option<&ImageProgressSender>,
    resolved: &ResolvedOciImage,
) -> Result<AcquiredComposition, LibVmError> {
    let key = acquisition_key(resolved)?;
    let pool = StoragePool::open(store.images_path())?;
    let _acquiring = tokio::task::spawn_blocking(move || pool.lock_publication(&key)).await??;
    let layers = LayerStore::from_store(store.clone());
    if let Some(mut image) = store
        .cached_oci_image(&resolved.selected_reference, &resolved.platform)
        .await?
    {
        ensure_resolved_oci_identity(resolved, &image)?;
        emit_cached_image_progress(progress, &resolved.requested_reference);
        // Exact retained bytes are authoritative; no source or encoder is used.
        let held = layers.hold_composition(image.artifact.lower).await?;
        check_image_lower(&image, held.retained())?;
        let now = crate::utils::now_unix();
        image.reference.requested_reference = resolved.requested_reference.clone();
        image.reference.last_used_at = Some(now);
        image.artifact.last_used_at = Some(now);
        store.save_oci_image(&image).await?;
        emit_image_progress_complete(progress);
        return Ok(AcquiredComposition {
            record: image,
            held,
        });
    }
    if let Some(progress) = progress {
        progress.send(ImageProgress::CheckingCache {
            image_ref: resolved.requested_reference.clone(),
        });
        progress.send(ImageProgress::CacheMiss {
            image_ref: resolved.requested_reference.clone(),
        });
    }
    let ResolvedOciImageMaterialization::Registry(image) = &resolved.materialization else {
        return Err(LibVmError::ImageNotFound {
            reference: resolved.selected_reference.clone(),
        });
    };
    let metadata = RootfsMetadata {
        requested_reference: resolved.requested_reference.clone(),
        selected_reference: image.selected_reference.clone(),
        manifest_digest: image.manifest_digest.clone(),
        config_digest: image.config_digest.clone(),
        config: image.config.clone(),
        layers: image.layer_metadata().collect(),
        platform: image.platform.clone(),
        created_at_unix: crate::utils::now_unix(),
    };
    let source_blobs = metadata
        .layers
        .iter()
        .map(|layer| layer.blob_digest.parse())
        .collect::<Result<Vec<ObjectDigest>, _>>()
        .map_err(|error| LibVmError::StateDecode {
            field: "image.source-blob",
            message: error.to_string(),
        })?;
    let operation = uuid::Uuid::new_v4();
    let _lease = store.begin_storage_operation(operation).await?;
    store.pin_source_blobs(operation, &source_blobs).await?;
    let limits = ChangesetLimits::default();
    let reference = resolved.requested_reference.as_str();
    let held = compose_layers(
        &layers,
        operation,
        metadata.platform.clone(),
        &metadata.layers,
        &limits,
        progress,
        |index| {
            let reporter = oci_progress_reporter(progress.cloned());
            async move {
                let staging = staging_operation(reference)?;
                producer
                    .ingest_changeset(image, index, &staging, &limits, reporter)
                    .await
                    .map_err(|error| image_error(reference, error))
            }
        },
    )
    .await?;
    let record = oci_image_record(&metadata, held.retained(), reference)?;
    ensure_resolved_oci_identity(resolved, &record)?;
    store.save_oci_image(&record).await?;
    emit_image_progress_complete(progress);
    Ok(AcquiredComposition { record, held })
}

fn staging_operation(reference: &str) -> Result<::oci::StagingOperation, LibVmError> {
    ::oci::StagingOperation::try_from(uuid::Uuid::new_v4().to_string())
        .map_err(|error| image_error(reference, error))
}

/// Retain every ordered occurrence as a layer result pinned to `operation`,
/// then compose (or reuse) their exact composition. Repeated diff IDs share
/// one retained result and remain separate occurrences.
async fn compose_layers<F, Fut>(
    layers: &LayerStore,
    operation: uuid::Uuid,
    platform: ::oci::Platform,
    descriptors: &[RootfsLayerMetadata],
    limits: &ChangesetLimits,
    progress: Option<&ImageProgressSender>,
    mut ingest: F,
) -> Result<HeldComposition, LibVmError>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<StagedChangeset, LibVmError>>,
{
    crate::storage::limits::Resource::LayerOccurrences
        .check(descriptors.len() as u64)
        .map_err(crate::storage::StorageError::from)?;
    let mut retained: Vec<(ContentDigest, LayerResultId)> = Vec::new();
    let mut occurrences = Vec::with_capacity(descriptors.len());
    for (index, descriptor) in descriptors.iter().enumerate() {
        let diff_id: ContentDigest = descriptor.diff_id.parse()?;
        if let Some((_, id)) = retained.iter().find(|(other, _)| *other == diff_id) {
            occurrences.push(*id);
            continue;
        }
        if let Some(progress) = progress {
            progress.send(ImageProgress::ApplyingLayer {
                index: index + 1,
                total: descriptors.len(),
                digest: Some(descriptor.blob_digest.clone()),
            });
        }
        let id = retain_layer(layers, operation, diff_id, limits, || ingest(index)).await?;
        retained.push((diff_id, id));
        occurrences.push(id);
    }
    if let Some(progress) = progress {
        progress.send(ImageProgress::MaterializingRootfs);
    }
    layers
        .compose_retained(platform, &occurrences, limits)
        .await
}

/// Reuse the retained result of `diff_id` (its pack and index are
/// authenticated) or ingest and publish it, then pin it to `operation`. A
/// result retired by a concurrent collector before the pin is acquired once
/// more; a second loss is an error, never an unpinned reference.
async fn retain_layer<F, Fut>(
    layers: &LayerStore,
    operation: uuid::Uuid,
    diff_id: ContentDigest,
    limits: &ChangesetLimits,
    mut ingest: F,
) -> Result<LayerResultId, LibVmError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<StagedChangeset, LibVmError>>,
{
    let recipe = LayerRecipe { diff_id }.id()?;
    for _ in 0..2 {
        let layer = match layers.find_recipe(recipe, limits).await? {
            Some(layer) => layer,
            None => layers.publish(ingest().await?, limits).await?,
        };
        if layer.recipe != recipe {
            return Err(invalid("retained layer contradicts its recipe"));
        }
        if layers
            .store
            .pin_operation_layers(operation, &[layer.id])
            .await?
        {
            return Ok(layer.id);
        }
    }
    Err(invalid(
        "layer result was retired concurrently before it could be pinned",
    ))
}

fn emit_cached_image_progress(progress: Option<&ImageProgressSender>, image_ref: &str) {
    let Some(progress) = progress else {
        return;
    };
    progress.send(ImageProgress::CheckingCache {
        image_ref: image_ref.to_string(),
    });
    progress.send(ImageProgress::CacheHit {
        image_ref: image_ref.to_string(),
    });
}

fn emit_image_progress_complete(progress: Option<&ImageProgressSender>) {
    if let Some(progress) = progress {
        progress.send(ImageProgress::Complete);
    }
}

pub(crate) fn oci_image_record(
    metadata: &RootfsMetadata,
    lower: &RetainedComposition,
    requested_reference: &str,
) -> Result<OciImageRecord, LibVmError> {
    let now = crate::utils::now_unix();
    let created_at = metadata.created_at_unix;
    let compressed_size = metadata
        .layers
        .iter()
        .try_fold(0_u64, |total, layer| total.checked_add(layer.size_bytes))
        .ok_or_else(|| LibVmError::StateDecode {
            field: "image.size",
            message: "compressed layer size sum overflows".into(),
        })?;
    let size = i64::try_from(compressed_size).map_err(|error| LibVmError::StateDecode {
        field: "image.size",
        message: error.to_string(),
    })?;
    let layers = metadata
        .layers
        .iter()
        .map(|layer| ImageLayerRecord {
            diff_id: layer.diff_id.clone(),
            blob_digest: layer.blob_digest.clone(),
            compressed_size_bytes: Some(layer.size_bytes),
            uncompressed_size_bytes: None,
            created_at,
            last_used_at: Some(now),
        })
        .collect();
    let manifest_layers = metadata
        .layers
        .iter()
        .enumerate()
        .map(|(position, layer)| {
            Ok(ImageManifestLayerRecord {
                manifest_digest: metadata.manifest_digest.clone(),
                layer_diff_id: layer.diff_id.clone(),
                layer_blob_digest: layer.blob_digest.clone(),
                media_type: layer.media_type.clone(),
                position: i64::try_from(position).map_err(|error| LibVmError::StateDecode {
                    field: "image.layer.position",
                    message: error.to_string(),
                })?,
            })
        })
        .collect::<Result<Vec<_>, LibVmError>>()?;
    let record = OciImageRecord {
        manifest: ImageManifestRecord {
            digest: metadata.manifest_digest.clone(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            image_id: metadata.manifest_digest.clone(),
            platform_os: metadata.platform.os.clone(),
            platform_architecture: metadata.platform.architecture.clone(),
            platform_variant: metadata.platform.variant.clone(),
            config_digest: Some(metadata.config_digest.clone()),
            layer_count: i64::try_from(metadata.layers.len()).map_err(|error| {
                LibVmError::StateDecode {
                    field: "image.layers",
                    message: error.to_string(),
                }
            })?,
            total_size_bytes: size,
            created_at,
            last_used_at: Some(now),
        },
        reference: ImageRefRecord {
            requested_reference: requested_reference.into(),
            selected_reference: metadata.selected_reference.clone(),
            manifest_digest: metadata.manifest_digest.clone(),
            image_id: metadata.manifest_digest.clone(),
            platform_os: metadata.platform.os.clone(),
            platform_architecture: metadata.platform.architecture.clone(),
            platform_variant: metadata.platform.variant.clone(),
            size_bytes: Some(lower.result.lower_length),
            created_at,
            updated_at: now,
            last_used_at: Some(now),
        },
        config: ImageConfigRecord {
            manifest_digest: metadata.manifest_digest.clone(),
            digest: metadata.config_digest.clone(),
            metadata: metadata.config.clone(),
            created_at,
        },
        layers,
        manifest_layers,
        artifact: ImageCompositionArtifactRecord {
            image_id: metadata.manifest_digest.clone(),
            manifest_digest: metadata.manifest_digest.clone(),
            config_digest: metadata.config_digest.clone(),
            platform_os: metadata.platform.os.clone(),
            platform_architecture: metadata.platform.architecture.clone(),
            platform_variant: metadata.platform.variant.clone(),
            lower: lower.id,
            lower_length: lower.result.lower_length,
            created_at,
            last_used_at: Some(now),
        },
    };
    check_image_lower(&record, lower)?;
    Ok(record)
}

/// Digest-pinned OCI provenance a destination may use to rebuild an exact
/// expected composition locally instead of receiving its packs and fsmeta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OciCompositionSource {
    pub(crate) selected_reference: String,
    pub(crate) manifest_digest: ObjectDigest,
    pub(crate) platform: LinuxPlatform,
}

/// The OCI provenance of a machine's layered root, if it was created from an
/// OCI selection. The platform is the retained composition's own platform.
pub(crate) async fn machine_composition_source(
    store: &Store,
    machine: MachineId,
) -> Result<Option<OciCompositionSource>, LibVmError> {
    let Some((selected_reference, manifest)) = store.oci_machine_provenance(machine).await? else {
        return Ok(None);
    };
    let Some(storage) = crate::store::MachineStore::machine_storage(store, machine).await? else {
        return Ok(None);
    };
    let crate::MachineRoot::LinuxOverlay { lower, .. } = &storage.root else {
        return Ok(None);
    };
    if selected_reference
        .rsplit_once('@')
        .map(|(_, digest)| digest)
        != Some(manifest.as_str())
    {
        return Err(invalid(
            "machine OCI provenance is not pinned to its manifest digest",
        ));
    }
    let manifest_digest = manifest.parse().map_err(invalid)?;
    let retained = LayerStore::from_store(store.clone())
        .retained_composition(lower.record())
        .await?;
    Ok(Some(OciCompositionSource {
        selected_reference,
        manifest_digest,
        platform: LinuxPlatform::from_oci(&retained.recipe.platform)?,
    }))
}

/// Reproduce an exact expected composition whose metadata objects are
/// already retained and pinned by `operation`. Locally retained layers are
/// used without contacting the source; missing layers are ingested from the
/// digest-pinned OCI source. Every layer must reproduce its expected result,
/// pack map and index closure, and the regenerated fsmeta must reproduce the
/// expected result byte for byte before the graph is registered. Any failure
/// leaves the caller's exact-artifact transfer as the only path.
pub(crate) async fn prepare_exact_composition(
    runtime: &crate::Runtime,
    operation: uuid::Uuid,
    expected: &SnapshotComposition,
    source: &OciCompositionSource,
) -> Result<LowerResultId, LibVmError> {
    let store = runtime.native_store()?;
    let producer = runtime
        .image_store()
        .map_err(|error| image_error(&source.selected_reference, error))?;
    let expected = expected.clone();
    let source = source.clone();
    let handle = tokio::runtime::Handle::current();
    // Owned to completion: regeneration writes and publishes fsmeta.
    tokio::task::spawn_blocking(move || {
        handle.block_on(async {
            let platform = oci_platform(&source.platform);
            let resolved = tokio::sync::OnceCell::new();
            let sources = SourceBlobPins::begin(&store).await?;
            let reference = source.selected_reference.as_str();
            prepare_exact(&store, operation, &expected, &platform, |index| {
                let (resolved, producer, source, platform, sources, store) =
                    (&resolved, &producer, &source, &platform, &sources, &store);
                async move {
                    let image = resolved
                        .get_or_try_init(|| resolve_source(producer, source, platform))
                        .await?;
                    sources.pin(store, image).await?;
                    let staging = staging_operation(reference)?;
                    producer
                        .ingest_changeset(image, index, &staging, &ChangesetLimits::default(), None)
                        .await
                        .map_err(|error| image_error(reference, error))
                }
            })
            .await
        })
    })
    .await?
}

/// A private acquisition operation pinning downloaded source blobs; layer
/// results and the lower are pinned to the caller's operation instead.
struct SourceBlobPins {
    operation: uuid::Uuid,
    _lease: crate::storage::locks::StorageLock,
}

impl SourceBlobPins {
    async fn begin(store: &Store) -> Result<Self, LibVmError> {
        let operation = uuid::Uuid::new_v4();
        Ok(Self {
            operation,
            _lease: store.begin_storage_operation(operation).await?,
        })
    }

    async fn pin(&self, store: &Store, image: &::oci::ResolvedImage) -> Result<(), LibVmError> {
        let blobs = image
            .layer_digests()
            .map(str::parse)
            .collect::<Result<Vec<ObjectDigest>, _>>()
            .map_err(invalid)?;
        store.pin_source_blobs(self.operation, &blobs).await
    }
}

/// Resolve the exact digest-pinned selection; any other manifest or platform
/// is a different source, never a substitute.
async fn resolve_source(
    producer: &OciMaterializer,
    source: &OciCompositionSource,
    platform: &::oci::Platform,
) -> Result<::oci::ResolvedImage, LibVmError> {
    let image = producer
        .resolve(&source.selected_reference, platform, None)
        .await
        .map_err(|error| image_error(&source.selected_reference, error))?;
    if image.manifest_digest != source.manifest_digest.to_string() || image.platform != *platform {
        return Err(invalid(
            "OCI source resolved to a different manifest or platform",
        ));
    }
    Ok(image)
}

async fn prepare_exact<F, Fut>(
    store: &Store,
    operation: uuid::Uuid,
    expected: &SnapshotComposition,
    platform: &::oci::Platform,
    mut ingest: F,
) -> Result<LowerResultId, LibVmError>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<StagedChangeset, LibVmError>>,
{
    let pool = StoragePool::open_existing(store.images_path())?
        .ok_or_else(|| invalid("immutable pool is absent"))?;
    let authenticated =
        expected.authenticate(|digest, maximum| Ok(pool.read_object(digest, maximum)?))?;
    if authenticated.recipe.platform != *platform {
        return Err(invalid(
            "OCI source platform differs from the expected composition",
        ));
    }
    let layers = LayerStore::from_store(store.clone());
    let limits = ChangesetLimits::default();
    let mut unique: Vec<(
        LayerResultId,
        crate::store::layer_store::PinnedLayer,
        std::fs::File,
    )> = Vec::new();
    let mut slots = Vec::with_capacity(expected.layers.len());
    for (index, (layer, facts)) in expected
        .layers
        .iter()
        .zip(&authenticated.layers)
        .enumerate()
    {
        let id = facts.result.id()?;
        if let Some(slot) = unique.iter().position(|(other, ..)| *other == id) {
            slots.push(slot);
            continue;
        }
        let retained = retain_layer(&layers, operation, facts.changeset.diff_id, &limits, || {
            ingest(index)
        })
        .await?;
        if retained != id {
            return Err(invalid(
                "local or OCI layer does not reproduce the expected layer result",
            ));
        }
        // Pinned by `operation`; pack bytes were authenticated by reuse or
        // publication and are hashed again by exact regeneration.
        let pinned = layers.load_pinned_layer(id, &limits, false).await?;
        if pinned.result != facts.result
            || pinned.recipe_digest != layer.recipe
            || pinned.result_digest != layer.result
            || pinned.index_root != layer.index_root
            || pinned.index_pages != layer.index_pages
            || pinned.pack != layer.pack
        {
            return Err(invalid(
                "reproduced layer closure differs from the expected graph",
            ));
        }
        let pack = pool.open_stream(&layer.pack.stream)?;
        slots.push(unique.len());
        unique.push((id, pinned, pack));
    }
    let refs = slots
        .iter()
        .filter_map(|slot| unique.get(*slot))
        .map(|(_, layer, pack)| ::oci::erofs::Layer {
            result: &layer.result,
            changeset: &layer.changeset,
            pack,
        })
        .collect::<Vec<_>>();
    if refs.len() != expected.layers.len() {
        return Err(invalid("expected occurrence lost its reproduced layer"));
    }
    let id = crate::store::composition_store::publish_regenerated(
        store,
        operation,
        expected,
        authenticated,
        &refs,
    )
    .await?;
    if id != expected.result {
        return Err(invalid("regenerated composition has a different identity"));
    }
    Ok(id)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::{Path, PathBuf};

    use oci::changeset::{ChangesetLimits, ContentDigest, LayerInput, StagedChangeset};

    use crate::image::oci::{
        acquire_composition, cached_resolved_oci_image, compose_layers, oci_image_record,
        prepare_exact, AcquiredComposition, OciCompositionSource,
    };
    use crate::storage::pool::StoragePool;
    use crate::store::composition_store::HeldComposition;
    use crate::store::layer_store::LayerStore;
    use crate::store::models::OciImageRecord;
    use crate::store::{ImageStore, Store};
    use crate::LibVmError;

    pub(crate) const MANIFEST: &str =
        "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    pub(crate) const CONFIG: &str =
        "sha256:6666666666666666666666666666666666666666666666666666666666666666";

    /// Original producer and generated tar layers from the changeset corpus.
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../oci/testdata/changesets")
            .join(name)
    }

    fn descriptor(name: &str) -> oci::RootfsLayerMetadata {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let digest = ContentDigest::of_bytes(&bytes).to_string();
        oci::RootfsLayerMetadata {
            blob_digest: digest.clone(),
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            size_bytes: bytes.len() as u64,
            diff_id: digest,
        }
    }

    fn ingest(store: &Store, name: &str) -> Result<StagedChangeset, LibVmError> {
        let descriptor = descriptor(name);
        Ok(oci::changeset::ingest_layer(
            &fixture(name),
            &LayerInput {
                blob_digest: descriptor.blob_digest.parse()?,
                media_type: descriptor.media_type,
                size_bytes: descriptor.size_bytes,
                diff_id: descriptor.diff_id.parse()?,
            },
            store.images_path(),
            &oci::StagingOperation::try_from(uuid::Uuid::new_v4().to_string()).unwrap(),
            &ChangesetLimits::default(),
        )?)
    }

    /// Two admitted metadata-bearing layers with distinct pack bytes, then a
    /// repeated first occurrence. The GNU file-00/01 specimens are intentional
    /// ambiguous-SCHILY rejection cases, not positive composition fixtures.
    pub(crate) const LAYERS: [&str; 3] = [
        "metadata-producers/gnu-tar-file-04.tar",
        "generated/metadata-raw-schily-names/layer-0.tar",
        "metadata-producers/gnu-tar-file-04.tar",
    ];

    /// Verified selection metadata of a [`LAYERS`] image on linux/amd64.
    pub(crate) fn metadata(reference: &str, manifest: &str) -> oci::RootfsMetadata {
        let repository = reference.split('@').next().unwrap();
        let repository = repository
            .rsplit_once(':')
            .map_or(repository, |(repository, _)| repository);
        oci::RootfsMetadata {
            requested_reference: reference.into(),
            selected_reference: format!("{repository}@{manifest}"),
            manifest_digest: manifest.into(),
            config_digest: CONFIG.into(),
            config: crate::image::OciImageConfigMetadata {
                cmd: Some(vec!["serve".into()]),
                ..Default::default()
            },
            layers: LAYERS.iter().map(|name| descriptor(name)).collect(),
            platform: oci::Platform::linux_amd64(),
            created_at_unix: 7,
        }
    }

    /// The ordinary miss path over the corpus layers `names` (in occurrence
    /// order) for linux/amd64, without registry traffic, held by its lease.
    pub(crate) async fn retained_lower(store: &Store, names: &[&str]) -> HeldComposition {
        compose_fixture(store, names, oci::Platform::linux_amd64()).await
    }

    async fn compose_fixture(
        store: &Store,
        names: &[&str],
        platform: oci::Platform,
    ) -> HeldComposition {
        let operation = uuid::Uuid::new_v4();
        let _lease = store.begin_storage_operation(operation).await.unwrap();
        let descriptors = names
            .iter()
            .map(|name| descriptor(name))
            .collect::<Vec<_>>();
        compose_layers(
            &LayerStore::from_store(store.clone()),
            operation,
            platform,
            &descriptors,
            &ChangesetLimits::default(),
            None,
            |index| std::future::ready(ingest(store, names[index])),
        )
        .await
        .unwrap()
    }

    /// A pulled image: the retained composition of [`LAYERS`] plus its rows.
    pub(crate) async fn cache_layered_image(
        store: &Store,
        reference: &str,
        manifest: &str,
    ) -> (OciImageRecord, AcquiredComposition) {
        cache_image(store, &metadata(reference, manifest)).await
    }

    /// Cache `metadata` (whose layers must be [`LAYERS`]) as a pulled image.
    pub(crate) async fn cache_image(
        store: &Store,
        metadata: &oci::RootfsMetadata,
    ) -> (OciImageRecord, AcquiredComposition) {
        let held = compose_fixture(store, &LAYERS, metadata.platform.clone()).await;
        let record =
            oci_image_record(metadata, held.retained(), &metadata.requested_reference).unwrap();
        store.save_oci_image(&record).await.unwrap();
        (record.clone(), AcquiredComposition { record, held })
    }

    async fn home() -> (tempfile::TempDir, Store) {
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::paths::LocalPaths::new(temp.path().join("home"));
        let store = Store::new(&paths).await.unwrap();
        (temp, store)
    }

    async fn count(store: &Store, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(store.test_pool())
            .await
            .unwrap()
    }

    fn producer(store: &Store) -> oci::OciMaterializer {
        oci::OciMaterializer::open(store.images_path(), oci::RegistryPolicy::default()).unwrap()
    }

    #[tokio::test]
    async fn shared_layers_retain_metadata_and_distinct_nonempty_packs() {
        let (_temp, store) = home().await;
        let first = ingest(&store, LAYERS[0]).unwrap();
        let second = ingest(&store, LAYERS[1]).unwrap();
        let file = first
            .changeset()
            .entries
            .iter()
            .find(|entry| entry.path == b"file-04")
            .unwrap();
        assert_eq!(
            (
                file.metadata.uid,
                file.metadata.gid,
                file.metadata.mode,
                file.metadata.mtime_seconds,
                file.metadata.mtime_nanos,
            ),
            (1000, 1000, 0o644, 1, 7)
        );
        assert_eq!(
            file.metadata.xattrs,
            vec![oci::changeset::Xattr {
                name: b"user.a b".to_vec(),
                value: b"\0\xff\n=".to_vec(),
            }]
        );
        let raw = second
            .changeset()
            .entries
            .iter()
            .find(|entry| entry.path == b"raw-names")
            .unwrap();
        assert_eq!(raw.metadata.xattrs.len(), 4);
        assert!(raw.metadata.xattrs.iter().any(|attribute| {
            attribute.name == b"user.\xff" && attribute.value == b"\0\xff\n="
        }));
        let first_pack = std::fs::read(first.pack_path()).unwrap();
        let second_pack = std::fs::read(second.pack_path()).unwrap();
        assert_eq!(&first_pack[..18], b"producer-original\n");
        assert_eq!(second_pack[0], b'R');
        assert_eq!(first_pack.len(), 4096);
        assert_eq!(second_pack.len(), 4096);
        assert_ne!(first_pack, second_pack);
    }

    #[tokio::test]
    async fn pull_retains_ordered_composition_graph_without_a_lower_stream() {
        let (_temp, store) = home().await;
        let reference = "example.test/app:1";
        let (record, acquired) = cache_layered_image(&store, reference, MANIFEST).await;
        let retained = acquired.held.retained().clone();
        assert_eq!(record.artifact.lower, retained.id);
        assert_eq!(record.artifact.lower_length, retained.result.lower_length);
        assert_eq!(retained.layers.len(), 3);
        assert_eq!(
            retained.layers[0], retained.layers[2],
            "repeat keeps its slot"
        );
        assert_ne!(retained.layers[0], retained.layers[1]);
        assert_eq!(count(&store, "SELECT COUNT(*) FROM layer_result").await, 2);
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM composition_layer").await,
            3
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM image_composition_artifact").await,
            1
        );
        // Only the two layer packs are streams: no whole lower, no fsmeta copy.
        let pool = StoragePool::open(store.images_path()).unwrap();
        let streams = pool.scan_streams().unwrap().count();
        assert_eq!(streams, 2);
        assert!(!pool
            .stream_path(&crate::storage::identity::StreamId::from_sha256(
                *retained.result.lower_stream.as_bytes()
            ))
            .exists());
        assert!(pool.object_path(&retained.fsmeta()).is_file());
        let cached = store
            .cached_oci_image(reference, &oci::Platform::linux_amd64())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cached.artifact, record.artifact);
        assert_eq!(cached.manifest_layers, record.manifest_layers);
    }

    #[tokio::test]
    async fn second_acquisition_reuses_retained_layers_and_composition() {
        let (_temp, store) = home().await;
        let (_, first) = cache_layered_image(&store, "example.test/app:1", MANIFEST).await;
        let other = format!("sha256:{}", "7".repeat(64));
        let metadata = metadata("example.test/other:1", &other);
        let operation = uuid::Uuid::new_v4();
        let _lease = store.begin_storage_operation(operation).await.unwrap();
        let held = compose_layers(
            &LayerStore::from_store(store.clone()),
            operation,
            metadata.platform.clone(),
            &metadata.layers,
            &ChangesetLimits::default(),
            None,
            |_| {
                std::future::ready(Err(LibVmError::ImageNotFound {
                    reference: "retained layers must not be fetched".into(),
                }))
            },
        )
        .await
        .unwrap();
        assert_eq!(held.retained(), first.held.retained());
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM composition_result").await,
            1
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM layer_result").await, 2);
    }

    #[tokio::test]
    async fn cached_acquisition_loads_exact_bytes_without_any_source() {
        let (_temp, store) = home().await;
        let reference = "example.test/app:1";
        let (record, first) = cache_layered_image(&store, reference, MANIFEST).await;
        let lower = first.held.retained().clone();
        drop(first);
        // A cached resolution carries no registry handle: success proves that
        // neither the OCI source nor a fresh encoding participated.
        let resolved = cached_resolved_oci_image(&record, reference.into());
        let acquired = acquire_composition(&store, &producer(&store), None, &resolved)
            .await
            .unwrap();
        assert_eq!(acquired.held.retained(), &lower);
        assert_eq!(acquired.record.artifact.lower, lower.id);
    }

    #[tokio::test]
    async fn corrupt_or_missing_retained_fsmeta_refuses_instead_of_regenerating() {
        for missing in [false, true] {
            let (_temp, store) = home().await;
            let reference = "example.test/app:1";
            let (record, first) = cache_layered_image(&store, reference, MANIFEST).await;
            let lower = first.held.retained().clone();
            drop(first);
            let pool = StoragePool::open(store.images_path()).unwrap();
            let path = pool.object_path(&lower.fsmeta());
            let mut bytes = std::fs::read(&path).unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
            if missing {
                std::fs::remove_file(&path).unwrap();
            } else {
                bytes[0] ^= 0xff;
                std::fs::write(&path, &bytes).unwrap();
            }
            let resolved = cached_resolved_oci_image(&record, reference.into());
            let error = acquire_composition(&store, &producer(&store), None, &resolved)
                .await
                .err()
                .expect("damaged retained fsmeta must refuse");
            if missing {
                assert!(
                    matches!(
                        error,
                        LibVmError::CompositionAcquisitionRequired { lower: id, .. } if id == lower.id
                    ),
                    "{error:?}"
                );
            }
            assert_eq!(
                count(&store, "SELECT COUNT(*) FROM composition_result").await,
                1
            );
        }
    }

    #[tokio::test]
    async fn prune_collects_an_unreferenced_graph_only_after_every_root_is_gone() {
        let (_temp, store) = home().await;
        let reference = "example.test/app:1";
        let (_, acquired) = cache_layered_image(&store, reference, MANIFEST).await;
        let lower = acquired.held.retained().clone();
        let pool = StoragePool::open(store.images_path()).unwrap();
        let packs = lower
            .result
            .packs
            .iter()
            .map(|range| {
                pool.stream_path(&crate::storage::identity::StreamId::from_sha256(
                    *range.stream.as_bytes(),
                ))
            })
            .collect::<Vec<_>>();
        let fsmeta = pool.object_path(&lower.fsmeta());

        // The image reference roots the graph.
        store.prune_images().await.unwrap();
        assert!(fsmeta.is_file() && packs.iter().all(|pack| pack.is_file()));

        store
            .remove_image(reference, crate::ImageRemoveOptions::default())
            .await
            .unwrap();
        // A live consumer lease still roots the lower, its layers and bytes.
        store.prune_images().await.unwrap();
        assert!(fsmeta.is_file() && packs.iter().all(|pack| pack.is_file()));
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM composition_result").await,
            1
        );

        drop(acquired);
        let report = store.prune_images().await.unwrap();
        assert_eq!(report.artifacts_removed, 1);
        assert!(!fsmeta.exists());
        assert!(packs.iter().all(|pack| !pack.exists()));
        for table in [
            "SELECT COUNT(*) FROM image_composition_artifact",
            "SELECT COUNT(*) FROM composition_result",
            "SELECT COUNT(*) FROM composition_layer",
            "SELECT COUNT(*) FROM layer_result",
            "SELECT COUNT(*) FROM image_manifest",
        ] {
            assert_eq!(count(&store, table).await, 0, "{table}");
        }
    }

    /// The graph of `source`'s cached image, its composition record objects
    /// copied into `destination` and pinned by a fresh staging operation, as
    /// a handoff destination holds them before preparation.
    async fn received_metadata(
        source: &Store,
        destination: &Store,
    ) -> (
        crate::store::models::snapshot::SnapshotComposition,
        uuid::Uuid,
        crate::storage::locks::StorageLock,
    ) {
        let (_, acquired) = cache_layered_image(source, "example.test/app:1", MANIFEST).await;
        let graph = LayerStore::from_store(source.clone())
            .snapshot_composition(acquired.held.retained().id)
            .await
            .unwrap();
        let operation = uuid::Uuid::new_v4();
        let lease = destination
            .begin_storage_operation(operation)
            .await
            .unwrap();
        let from = StoragePool::open(source.images_path()).unwrap();
        let into = StoragePool::open(destination.images_path()).unwrap();
        let mut objects = vec![graph.record, graph.recipe];
        for layer in &graph.layers {
            objects.extend([layer.recipe, layer.result, layer.index_root, layer.pack.map]);
            objects.extend(layer.index_pages.iter().copied());
            objects.extend(layer.pack.map_pages.iter().copied());
        }
        objects.sort();
        objects.dedup();
        for digest in objects {
            let bytes = from.read_object(&digest, 1 << 22).unwrap();
            let (object, roots, ()) = into
                .publish_produced_object_for_catalog(|file| {
                    std::io::Write::write_all(file, &bytes)?;
                    Ok::<_, crate::storage::StorageError>(())
                })
                .unwrap();
            assert_eq!(object.digest, digest);
            destination
                .pin_published_storage_dependencies(operation, &[], &[digest])
                .await
                .unwrap();
            drop(roots);
        }
        (graph, operation, lease)
    }

    #[tokio::test]
    async fn exact_preparation_reproduces_expected_graph_with_source_unavailable() {
        let (_a, source) = home().await;
        let (_b, destination) = home().await;
        let (graph, operation, _lease) = received_metadata(&source, &destination).await;
        // The destination already retains the layers (an earlier pull), but
        // not the composition, its fsmeta or any record of the source image.
        let layers = LayerStore::from_store(destination.clone());
        for name in &LAYERS[..2] {
            layers
                .publish(
                    ingest(&destination, name).unwrap(),
                    &ChangesetLimits::default(),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            count(&destination, "SELECT COUNT(*) FROM composition_result").await,
            0
        );
        let unavailable = |_: usize| {
            std::future::ready(Err(LibVmError::ImageNotFound {
                reference: "localhost:1/deleted/source".into(),
            }))
        };
        let id = prepare_exact(
            &destination,
            operation,
            &graph,
            &oci::Platform::linux_amd64(),
            unavailable,
        )
        .await
        .unwrap();
        assert_eq!(id, graph.result);
        let held = LayerStore::from_store(destination.clone())
            .hold_composition(id)
            .await
            .unwrap();
        assert_eq!(held.snapshot_composition().unwrap(), graph);
    }

    #[tokio::test]
    async fn exact_preparation_fetches_missing_layers_and_refuses_any_mismatch() {
        let (_a, source) = home().await;
        // Source layers ingested on demand reproduce the graph exactly.
        let (_b, destination) = home().await;
        let (graph, operation, _lease) = received_metadata(&source, &destination).await;
        let mut fetched = Vec::new();
        let id = prepare_exact(
            &destination,
            operation,
            &graph,
            &oci::Platform::linux_amd64(),
            |index| {
                fetched.push(index);
                std::future::ready(ingest(&destination, LAYERS[index]))
            },
        )
        .await
        .unwrap();
        assert_eq!(id, graph.result);
        assert_eq!(fetched, vec![0, 1], "a repeated occurrence is fetched once");

        // A source that yields different layer bytes never substitutes.
        let (_c, destination) = home().await;
        let (graph, operation, _lease) = received_metadata(&source, &destination).await;
        let wrong = prepare_exact(
            &destination,
            operation,
            &graph,
            &oci::Platform::linux_amd64(),
            |_| {
                std::future::ready(Ok(ingest(
                    &destination,
                    "metadata-producers/gnu-tar-file-05.tar",
                )
                .unwrap()))
            },
        )
        .await;
        assert!(wrong.is_err());
        assert_eq!(
            count(&destination, "SELECT COUNT(*) FROM composition_result").await,
            0
        );

        // A different platform is a different composition.
        let refused = prepare_exact(
            &destination,
            operation,
            &graph,
            &oci::Platform::linux_arm64(),
            |index| std::future::ready(ingest(&destination, LAYERS[index])),
        )
        .await;
        assert!(refused.is_err());
        assert_eq!(
            count(&destination, "SELECT COUNT(*) FROM composition_result").await,
            0
        );
    }

    #[test]
    fn composition_source_is_strict_wire() {
        let source = OciCompositionSource {
            selected_reference: format!("example.test/app@{MANIFEST}"),
            manifest_digest: MANIFEST.parse().unwrap(),
            platform: crate::store::models::storage::LinuxPlatform {
                architecture: crate::store::models::storage::GuestArchitecture::Arm64,
                variant: Some("v8".into()),
            },
        };
        let mut value = serde_json::to_value(&source).unwrap();
        assert_eq!(
            serde_json::from_value::<OciCompositionSource>(value.clone()).unwrap(),
            source
        );
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<OciCompositionSource>(value).is_err());
    }
}
