//! Source participant: observation, durable intent, the stopped cut and
//! bounded payload reads.
//!
//! The cut is not a copy. Under the lifecycle lock the ownership ledger
//! records `Reserved(op)`; afterwards no start, configuration change, removal
//! or offline write is admitted, so the stopped private files themselves are
//! the immutable cut. Every chunk served is re-hashed against the sealed map,
//! so a violated reservation can only fail a read, never send other bytes.
use std::collections::BTreeSet;
use std::os::unix::fs::FileExt;

use crate::handoff::chunks::ChunkIndex;
use crate::handoff::files::{DocumentName, OperationFiles};
use crate::handoff::plan::{
    invalid, ApprovedPlan, CaptureManifest, CaptureOffer, CapturedFile, ImmutableClosure,
    ImmutableObject, ImmutableStream, ManifestBody, ObservationBody, PayloadDescriptor,
    PayloadFrame, SourceExecution, SourceObservation, SourceStop, WritableFile, WritableRole,
    MAX_FRAME_BYTES,
};
use crate::handoff::types::{
    CaptureId, HandoffBinding, HandoffError, HandoffPhase, HandoffRecord, HandoffRole, OperationId,
    RuntimeId,
};
use crate::machine::stopped::{StoppedAdmission, StoppedStorageGuard};
use crate::paths::OwnedDirectory;
use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::pool::StoragePool;
use crate::store::models::MachineConfig;
use crate::store::Store;
use crate::{
    DiskStorage, ExternalResourcePolicy, LibVmError, MachineId, MachineOwnership, MachineRef,
    MachineStorageRecord, Runtime, SnapshotConfiguration,
};

/// Every writable role of a storage record, root first, then managed
/// writable disks by ordinal, with private path and logical length.
pub(crate) fn writable_files(
    storage: &MachineStorageRecord,
) -> Vec<(WritableRole, crate::PrivatePath, u64)> {
    let (root, length) = crate::machine::stopped::root_private(storage);
    let mut files = vec![(WritableRole::Root, root.clone(), length)];
    let mut disks = storage.disks.iter().collect::<Vec<_>>();
    disks.sort_by_key(|disk| disk.order);
    for disk in disks {
        if let DiskStorage::ManagedWritable { path, geometry } = &disk.storage {
            files.push((
                WritableRole::Disk { order: disk.order },
                path.clone(),
                geometry.length,
            ));
        }
    }
    files
}

/// The observation projection of a current record. A record reserved for
/// `reserved` is projected as owned, so capture can compare it to the plan.
pub(crate) async fn observation_body(
    runtime: &Runtime,
    runtime_id: RuntimeId,
    config: &MachineConfig,
    storage: &MachineStorageRecord,
    pool: &StoragePool,
    reserved: Option<OperationId>,
    execution: SourceExecution,
) -> Result<ObservationBody, LibVmError> {
    let mut storage = storage.clone();
    storage.disks.sort_by_key(|disk| disk.order);
    let own_reservation = reserved.is_some_and(|expected| {
        storage.ownership
            == MachineOwnership::Reserved {
                operation: expected,
            }
    });
    if own_reservation {
        storage.ownership = MachineOwnership::Owned;
    }
    // Stop evidence belongs to the cut (the manifest), not to admission: a
    // deliberate stop after reservation must not make the plan stale.
    storage.stop_outcome = crate::StorageStopOutcome::Unknown;
    storage.ownership.ensure_owned(config.id)?;
    crate::machine::stopped::validate_managed_attachments(&config.spec, &storage)?;
    crate::machine::stopped::validate_capture_shape(&storage, StoppedAdmission::Ordinary)?;
    if !matches!(
        &storage.boot,
        crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { .. },
            ..
        }
    ) {
        return Err(invalid(
            "handoff requires a pinned Linux direct boot bundle",
        ));
    }
    let external_requirements =
        crate::machine::stopped::external_requirements(&config.spec, &storage)?;
    let crate::store::cache_paths::PoolDependencies {
        mut streams,
        mut objects,
        ..
    } = crate::store::cache_paths::storage_pool_dependencies(&storage)?;
    let composition = match &storage.root {
        crate::MachineRoot::LinuxOverlay {
            lower: crate::OverlayLower::ErofsComposition { record, .. },
            ..
        } => Some(
            crate::store::layer_store::LayerStore::open(runtime.local_home())
                .await?
                .snapshot_composition(*record)
                .await?,
        ),
        crate::MachineRoot::OpaqueRaw { .. } => None,
    };
    if let Some(lower) = &composition {
        objects.extend(lower.objects());
        for layer in &lower.layers {
            objects.insert(layer.pack.map);
            objects.extend(layer.pack.map_pages.iter().copied());
            streams.insert(layer.pack.stream);
        }
    }
    let mut immutable = ImmutableClosure {
        oci_source: if composition.is_some() {
            crate::image::oci::machine_composition_source(&runtime.native_store()?, config.id)
                .await?
        } else {
            None
        },
        composition,
        objects: Vec::with_capacity(objects.len()),
        streams: Vec::with_capacity(streams.len()),
    };
    for digest in objects {
        let length = pool.open_object(&digest)?.metadata()?.len();
        immutable.objects.push(ImmutableObject { digest, length });
    }
    for stream in streams {
        let length = pool.open_stream(&stream)?.metadata()?.len();
        immutable.streams.push(ImmutableStream { stream, length });
    }
    let writable = writable_files(&storage)
        .into_iter()
        .map(|(role, _, length)| WritableFile { role, length })
        .collect();
    Ok(ObservationBody {
        schema: 1,
        runtime: runtime_id,
        machine: config.id,
        name: config.name.clone(),
        ownership_epoch: crate::handoff::types::OwnershipEpoch::new(storage.ownership_epoch)?,
        storage_generation: storage.storage_generation,
        execution,
        configuration: SnapshotConfiguration::capture(config)?,
        storage,
        external_requirements,
        immutable,
        writable,
    })
}

async fn source_execution(
    runtime: &Runtime,
    config: &MachineConfig,
    storage: &MachineStorageRecord,
) -> Result<SourceExecution, LibVmError> {
    let state = runtime.machine_state(config.id).await?;
    if state.status.is_live() {
        let run = state
            .run_id
            .as_deref()
            .ok_or_else(|| invalid("live source has no run identity"))?;
        let run = uuid::Uuid::parse_str(run).map_err(invalid)?;
        if run.is_nil() {
            return Err(invalid("live source has a nil run identity"));
        }
        return Ok(SourceExecution::Running { run });
    }
    let directory = OwnedDirectory::open_existing_root(&config.machine_dir)?
        .ok_or_else(|| invalid("source machine directory is missing"))?;
    let files = writable_files(storage)
        .into_iter()
        .map(|(_, path, length)| {
            let file = crate::machine::stopped::open_private(&directory, &path, length)?;
            Ok(crate::storage::identity_file::SourceFingerprint::new(
                &file.file.metadata()?,
            ))
        })
        .collect::<Result<Vec<_>, LibVmError>>()?;
    Ok(SourceExecution::Stopped { files })
}

pub(crate) async fn observe(
    runtime: &Runtime,
    reference: &MachineRef,
) -> Result<SourceObservation, LibVmError> {
    let store = runtime.native_store()?;
    let config = runtime.resolve_machine_config(reference).await?;
    let (_lifecycle, config) = runtime.lock_machine_config(config.id).await?;
    let storage = runtime.machine_storage_record(config.id).await?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    SourceObservation::new(
        observation_body(
            runtime,
            store.runtime_id().await?,
            &config,
            &storage,
            &pool,
            None,
            source_execution(runtime, &config, &storage).await?,
        )
        .await?,
    )
}

fn require_source(record: &HandoffRecord) -> Result<(), LibVmError> {
    if record.role != HandoffRole::Source {
        return Err(HandoffError::WrongRuntime.into());
    }
    Ok(())
}

/// The durable approved plan this participant bound to `operation`.
pub(crate) fn stored_plan(
    runtime: &Runtime,
    operation: OperationId,
) -> Result<ApprovedPlan, LibVmError> {
    let files = OperationFiles::existing(runtime.local_home(), operation)?;
    let document = files
        .load_document(DocumentName::Plan)?
        .ok_or(HandoffError::UnknownOperation { operation })?;
    let plan = ApprovedPlan::from_document(document)?;
    if plan.plan().operation() != operation {
        return Err(HandoffError::ReceiptMismatch.into());
    }
    Ok(plan)
}

/// Persist the plan, pin the exact immutable closure and its maps, then
/// record the source intent. The machine stays owned and may keep running.
pub(crate) async fn begin(
    runtime: &Runtime,
    store: &Store,
    plan: &ApprovedPlan,
    lease: &mut Option<crate::storage::locks::StorageLock>,
) -> Result<HandoffRecord, LibVmError> {
    let intent = plan.intent()?;
    if let Some(record) = store.get_handoff(intent.operation).await? {
        require_source(&record)?;
        if record.intent != intent {
            return Err(HandoffError::OperationConflict {
                operation: intent.operation,
            }
            .into());
        }
        if record.phase.is_terminal() {
            return Ok(record);
        }
    } else {
        let config = runtime
            .resolve_machine_config(&MachineRef::id(intent.source_machine))
            .await?;
        let (_lifecycle, config) = runtime.lock_machine_config(config.id).await?;
        let storage = runtime.machine_storage_record(config.id).await?;
        let pool = StoragePool::open(runtime.local_images_dir())?;
        if observation_body(
            runtime,
            store.runtime_id().await?,
            &config,
            &storage,
            &pool,
            None,
            source_execution(runtime, &config, &storage).await?,
        )
        .await?
            != plan.body().observation
        {
            return Err(HandoffError::AdmissionStale.into());
        }
    }
    let files = OperationFiles::create(runtime.local_home(), intent.operation)?;
    files.store_document(DocumentName::Plan, plan.document(), false)?;
    if lease.is_none() {
        *lease = Some(store.begin_handoff_storage(intent.operation).await?);
    }
    let closure = &plan.body().observation.immutable;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    {
        let _roots = pool.lock_roots_shared()?;
        let streams = closure
            .streams
            .iter()
            .map(|entry| entry.stream)
            .collect::<Vec<_>>();
        let objects = closure
            .objects
            .iter()
            .map(|entry| entry.digest)
            .collect::<Vec<_>>();
        store
            .pin_handoff_dependencies(intent.operation, &streams, &objects)
            .await?;
        if let Some(lower) = &closure.composition {
            store
                .pin_operation_lowers(intent.operation.as_uuid(), &[lower.result])
                .await?;
        }
    }
    for entry in &closure.objects {
        let file = pool.verify_object(&entry.digest)?;
        if file.metadata()?.len() != entry.length {
            return Err(HandoffError::AdmissionStale.into());
        }
    }
    for entry in &closure.streams {
        if files.has_map(&entry.stream)? {
            continue;
        }
        let map = pool.verify_stream(&entry.stream)?;
        if map.length() != entry.length {
            return Err(HandoffError::AdmissionStale.into());
        }
        files.store_map(&entry.stream, &map.canonical_bytes()?)?;
    }
    store.begin_handoff_source(&intent).await
}

/// Reserve under the lifecycle lock, optionally stop, then seal one cut.
/// A bound cut is replayed exactly; it is never recaptured.
pub(crate) async fn capture(
    runtime: &Runtime,
    store: &Store,
    plan: &ApprovedPlan,
    stop: SourceStop,
    lease: &mut Option<crate::storage::locks::StorageLock>,
) -> Result<CaptureOffer, LibVmError> {
    let intent = plan.intent()?;
    let operation = intent.operation;
    // Idempotent: re-establishes the plan, bulk root and maps after a restart
    // and returns terminal records untouched.
    let record = begin(runtime, store, plan, lease).await?;
    if let Some(binding) = &record.binding {
        let files = OperationFiles::existing(runtime.local_home(), operation)?;
        let manifest = files
            .load_document(DocumentName::Manifest)?
            .ok_or_else(|| invalid("bound capture manifest is missing"))?;
        return CaptureOffer::new(binding.clone(), CaptureManifest::from_document(manifest)?);
    }
    match record.phase {
        HandoffPhase::Intended | HandoffPhase::Reserved => {}
        HandoffPhase::Aborted => return Err(HandoffError::OperationAborted { operation }.into()),
        _ => return Err(HandoffError::InvalidState.into()),
    }
    let id = intent.source_machine;
    let running = {
        let (_lifecycle, config) = runtime.lock_machine_config(id).await?;
        let storage = runtime.machine_storage_record(id).await?;
        let pool = StoragePool::open(runtime.local_images_dir())?;
        let current = observation_body(
            runtime,
            intent.source_runtime,
            &config,
            &storage,
            &pool,
            Some(operation),
            if record.phase == HandoffPhase::Reserved {
                // This operation already fenced starts before its own stop.
                plan.body().observation.execution.clone()
            } else {
                source_execution(runtime, &config, &storage).await?
            },
        )
        .await?;
        if current != plan.body().observation {
            return Err(HandoffError::AdmissionStale.into());
        }
        let running = runtime
            .reconcile_machine_runtime_locked(&config)
            .await?
            .is_active();
        if running && stop == SourceStop::RequireStopped {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name,
            });
        }
        // The reservation commits while this lifecycle lock is held, so no
        // start can interleave between this check and the stopped cut.
        store.reserve_handoff_source(&intent).await?;
        running
    };
    if running {
        tracing::info!(machine = %id, %operation, "stopping reserved handoff source");
        crate::Machine::new(runtime.clone(), id).stop().await?;
    }
    let guard = crate::machine::stopped::admit_stopped(
        runtime,
        id,
        &ExternalResourcePolicy::RequireMappings,
        StoppedAdmission::Handoff(operation),
    )
    .await?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    if observation_body(
        runtime,
        intent.source_runtime,
        &guard.config,
        &guard.storage,
        &pool,
        Some(operation),
        plan.body().observation.execution.clone(),
    )
    .await?
        != plan.body().observation
    {
        return Err(HandoffError::AdmissionStale.into());
    }
    let manifest = seal_cut(runtime, plan, &guard).await?;
    let binding = HandoffBinding {
        intent,
        capture: manifest.capture(),
        capture_manifest_digest: manifest.document().digest(),
    };
    store.bind_handoff_capture(&binding).await?;
    drop(guard);
    CaptureOffer::new(binding, manifest)
}

/// Synchronize, hash and record every writable role while the stopped guard
/// still holds lifecycle and managed-disk locks. The unbound manifest never
/// left this participant, so a crashed earlier attempt may be replaced.
async fn seal_cut(
    runtime: &Runtime,
    plan: &ApprovedPlan,
    guard: &StoppedStorageGuard,
) -> Result<CaptureManifest, LibVmError> {
    let operation = plan.body().operation;
    let files = OperationFiles::create(runtime.local_home(), operation)?;
    let roles = writable_files(&guard.storage);
    if roles.len() != guard.files.len() {
        return Err(invalid("stopped guard does not hold every writable role"));
    }
    let mut captured = Vec::with_capacity(roles.len());
    for ((role, path, length), source) in roles.into_iter().zip(&guard.files) {
        if source.path != path || source.length != length {
            return Err(invalid("stopped guard role order contradicts the record"));
        }
        source.file.sync_all()?;
        let map = crate::storage::stream::StreamHasher::new()
            .hash_open_file(&source.file, length)?
            .map;
        let stream = map.id();
        files.store_map(&stream, &map.canonical_bytes()?)?;
        captured.push(CapturedFile {
            role,
            stream,
            length,
        });
    }
    let manifest = CaptureManifest::new(ManifestBody {
        schema: 1,
        capture: CaptureId::new(uuid::Uuid::new_v4())?,
        operation,
        approved_plan_digest: plan.digest(),
        stop_outcome: guard.storage.stop_outcome,
        files: captured,
    })?;
    manifest.body().check_plan(plan)?;
    files.store_document(DocumentName::Manifest, manifest.document(), true)?;
    Ok(manifest)
}

/// Everything a source may serve for one operation, built once per manifest.
pub(crate) struct SourceIndex {
    operation: OperationId,
    machine: MachineId,
    objects: std::collections::BTreeMap<ObjectDigest, u64>,
    streams: BTreeSet<StreamId>,
    /// Files: captured roles first (manifest order), then immutable streams.
    origins: Vec<ChunkOrigin>,
    chunks: ChunkIndex,
    pub(crate) captured: bool,
}

enum ChunkOrigin {
    Captured { role: WritableRole, length: u64 },
    Immutable { stream: StreamId },
}

impl SourceIndex {
    pub(crate) fn build(runtime: &Runtime, operation: OperationId) -> Result<Self, LibVmError> {
        let plan = stored_plan(runtime, operation)?;
        let files = OperationFiles::existing(runtime.local_home(), operation)?;
        let mut index = Self {
            operation,
            machine: plan.plan().source_machine(),
            objects: plan
                .body()
                .observation
                .immutable
                .objects
                .iter()
                .map(|entry| (entry.digest, entry.length))
                .collect(),
            streams: BTreeSet::new(),
            origins: Vec::new(),
            chunks: ChunkIndex::default(),
            captured: false,
        };
        if let Some(document) = files.load_document(DocumentName::Manifest)? {
            let manifest = CaptureManifest::from_document(document)?;
            manifest.body().check_plan(&plan)?;
            for file in &manifest.body().files {
                let map = files
                    .load_map(&file.stream)?
                    .ok_or_else(|| invalid("captured stream map is missing"))?;
                index.chunks.add(index.origins.len(), &map);
                index.origins.push(ChunkOrigin::Captured {
                    role: file.role,
                    length: file.length,
                });
                index.streams.insert(file.stream);
            }
            index.captured = true;
        }
        for entry in &plan.body().observation.immutable.streams {
            let map = files
                .load_map(&entry.stream)?
                .ok_or_else(|| invalid("immutable stream map is missing"))?;
            index.chunks.add(index.origins.len(), &map);
            index.origins.push(ChunkOrigin::Immutable {
                stream: entry.stream,
            });
            index.streams.insert(entry.stream);
        }
        Ok(index)
    }

    /// Verified bytes of one whole chunk named by this operation's closure.
    pub(crate) async fn chunk(
        &self,
        runtime: &Runtime,
        digest: &ObjectDigest,
        length: u64,
    ) -> Result<Vec<u8>, LibVmError> {
        let place = self
            .chunks
            .get(digest, length)
            .ok_or_else(|| invalid("chunk is not part of this handoff"))?;
        let origin = self
            .origins
            .get(place.file)
            .ok_or_else(|| invalid("chunk index names no source file"))?;
        let file = match origin {
            ChunkOrigin::Immutable { stream } => {
                StoragePool::open(runtime.local_images_dir())?.open_stream(stream)?
            }
            ChunkOrigin::Captured { role, length } => {
                let storage = runtime.machine_storage_record(self.machine).await?;
                if storage.ownership.is_owned() {
                    return Err(HandoffError::InvalidState.into());
                }
                let path = writable_files(&storage)
                    .into_iter()
                    .find(|(candidate, _, _)| candidate == role)
                    .map(|(_, path, _)| path)
                    .ok_or_else(|| invalid("captured role disappeared"))?;
                let config = runtime
                    .resolve_machine_config(&MachineRef::id(self.machine))
                    .await?;
                let directory = OwnedDirectory::open_existing_root(&config.machine_dir)?
                    .ok_or_else(|| invalid("source machine directory is missing"))?;
                crate::machine::stopped::open_private(&directory, &path, *length)?.file
            }
        };
        crate::handoff::chunks::read_verified(&file, place.offset, length, digest)?
            .ok_or_else(|| invalid("source chunk changed after the stopped cut"))
    }

    /// One bounded frame of a descriptor this operation is allowed to serve.
    pub(crate) async fn frame(
        &self,
        runtime: &Runtime,
        descriptor: PayloadDescriptor,
        offset: u64,
        max_bytes: u32,
        cached_chunk: Option<std::sync::Arc<Vec<u8>>>,
    ) -> Result<(PayloadFrame, Option<std::sync::Arc<Vec<u8>>>), LibVmError> {
        descriptor.validate()?;
        if max_bytes == 0 || max_bytes > MAX_FRAME_BYTES {
            return Err(invalid("frame size is outside 1..=1 MiB"));
        }
        let (bytes, total, chunk) = match descriptor {
            PayloadDescriptor::Object { digest, length } => {
                if self.objects.get(&digest) != Some(&length) {
                    return Err(invalid("object is not part of this handoff"));
                }
                let file = StoragePool::open(runtime.local_images_dir())?.open_object(&digest)?;
                if file.metadata()?.len() != length {
                    return Err(invalid("immutable object length changed"));
                }
                (range(&file, offset, max_bytes, length)?, length, None)
            }
            PayloadDescriptor::StreamMap { stream } => {
                if !self.streams.contains(&stream) {
                    return Err(invalid("stream map is not part of this handoff"));
                }
                let files = OperationFiles::existing(runtime.local_home(), self.operation)?;
                let file = files
                    .map_file(&stream)?
                    .ok_or_else(|| invalid("stream map is missing"))?;
                let total = file.metadata()?.len();
                (range(&file, offset, max_bytes, total)?, total, None)
            }
            PayloadDescriptor::Chunk { digest, length } => {
                if self.chunks.get(&digest, length).is_none() {
                    return Err(invalid("chunk is not part of this handoff"));
                }
                // Cache identity includes the full authorized descriptor.
                let bytes = match cached_chunk {
                    Some(bytes) => bytes,
                    None => std::sync::Arc::new(self.chunk(runtime, &digest, length).await?),
                };
                if bytes.len() as u64 != length {
                    return Err(invalid("cached chunk length differs from its descriptor"));
                }
                let start = usize::try_from(offset)
                    .ok()
                    .filter(|start| *start < bytes.len())
                    .ok_or_else(|| invalid("frame offset is outside the payload"))?;
                let end = (start + max_bytes as usize).min(bytes.len());
                let slice = bytes
                    .get(start..end)
                    .ok_or_else(|| invalid("frame range is outside the chunk"))?
                    .to_vec();
                (slice, length, Some(bytes))
            }
        };
        let end = offset + bytes.len() as u64 == total;
        Ok((
            PayloadFrame {
                bytes,
                total_length: total,
                end,
            },
            chunk,
        ))
    }
}

fn range(
    file: &std::fs::File,
    offset: u64,
    max_bytes: u32,
    total: u64,
) -> Result<Vec<u8>, LibVmError> {
    if offset >= total {
        return Err(invalid("frame offset is outside the payload"));
    }
    let length = (total - offset).min(u64::from(max_bytes)) as usize;
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, offset)?;
    Ok(bytes)
}
