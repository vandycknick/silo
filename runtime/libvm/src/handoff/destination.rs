//! Destination participant: preflight, missing-byte inventory, verified
//! payload publication, prepared private state and atomic publication.
//!
//! ```text
//!  receive ──► plan persisted, ledger Receiving, present closure pinned
//!  offer   ──► manifest persisted, binding fixed
//!  needs   ──► Object / StreamMap / Chunk descriptors not verifiably local;
//!              reused pool members count only once pinned under roots
//!  write   ──► staging/<uuid>.part ──verify──► pool object or maps/<hex>
//!  prepare ──► admission rechecked, missing immutable streams published,
//!              approved boot pinned, machines/<id>/handoff-<capture>-*.raw
//!              written, synced, verified, ledger Prepared
//!  commit  ──► admission rechecked, replaced generation recorded, then one
//!              ledger transaction publishes config/state/rootfs/storage
//!  terminal──► committed: replaced generation retired
//!              aborted:   prepared files and an unpublished machine removed
//!              (every replay of commit or abort repeats this idempotently)
//! ```
use std::collections::{BTreeSet, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use sha2::Digest;

use crate::handoff::chunks::{extents, ChunkIndex};
use crate::handoff::files::{DocumentName, OperationFiles};
use crate::handoff::plan::{
    boot_bundle, invalid, ApprovedPlan, BootSelection, CaptureManifest, CaptureOffer,
    DestinationRequest, HandoffPlan, HandoffProposal, NeedCursor, NeedsPage, PayloadDescriptor,
    PayloadReceipt, PlanBody, SourceObservation, TransferEstimate, WritableRole, MAX_FRAME_BYTES,
    MAX_PAGE_ENTRIES,
};
use crate::handoff::source::writable_files;
use crate::handoff::types::{
    CaptureId, CommitAuthorization, HandoffBinding, HandoffDecision, HandoffError, HandoffIntent,
    HandoffMode, HandoffPhase, HandoffRecord, HandoffRole, OperationId, PreparedReceipt, RuntimeId,
    TerminalReceipt,
};
use crate::paths::OwnedDirectory;
use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::pool::StoragePool;
use crate::storage::stream::{Chunk, StreamHasher, StreamMap};
use crate::store::handoff_payload_store::HandoffPublication;
use crate::store::models::{MachineConfig, MachineRootfsRecord};
use crate::store::Store;
use crate::{
    BootBinding, BootProfile, DiskStorage, GuestArchitecture, LibVmError, MachineId,
    MachineOwnership, MachineRoot, MachineStorageRecord, Runtime, Translation,
};

/// Kernel architecture of this host. A destination never boots another.
pub(crate) fn host_architecture() -> Result<GuestArchitecture, LibVmError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(GuestArchitecture::Amd64),
        "aarch64" => Ok(GuestArchitecture::Arm64),
        other => Err(invalid(format!("unsupported host architecture {other}"))),
    }
}

/// A fork's destination identity, derived once from the caller's operation
/// and this runtime so repeated preflight yields the same plan.
pub(crate) fn fork_machine_id(operation: OperationId, destination: RuntimeId) -> MachineId {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"silo-handoff-fork-v1\0");
    hasher.update(operation.as_uuid().as_bytes());
    hasher.update(destination.as_uuid().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    for (target, source) in bytes.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    MachineId::from(
        uuid::Builder::from_bytes(bytes)
            .with_variant(uuid::Variant::RFC4122)
            .with_version(uuid::Version::Custom)
            .into_uuid(),
    )
}

/// Prepared private file name of one role within the destination machine dir.
pub(crate) fn prepared_name(
    capture: CaptureId,
    role: WritableRole,
    storage: &MachineStorageRecord,
) -> String {
    match role {
        WritableRole::Root if matches!(storage.root, MachineRoot::LinuxOverlay { .. }) => {
            format!("handoff-{capture}-upper.raw")
        }
        WritableRole::Root => format!("handoff-{capture}-root.raw"),
        WritableRole::Disk { order } => format!("handoff-{capture}-disk-{order}.raw"),
    }
}

fn prepared_prefix(capture: CaptureId) -> String {
    format!("handoff-{capture}-")
}

/// The destination boot for a requested selection, admitted for this host.
pub(crate) fn destination_boot(
    runtime: &Runtime,
    store: &Store,
    source: &BootProfile,
    agent: bool,
    selection: BootSelection,
    pool: &StoragePool,
) -> Result<BootProfile, LibVmError> {
    let host = host_architecture()?;
    let BootProfile::LinuxDirect {
        userspace_platform,
        kernel_architecture,
        ..
    } = source
    else {
        return Err(invalid("handoff requires Linux direct boot"));
    };
    match selection {
        BootSelection::ExactRecorded => {
            if *kernel_architecture != host {
                return Err(invalid(
                    "exact recorded boot targets another kernel architecture; approve a complete destination bundle",
                ));
            }
            Ok(source.clone())
        }
        BootSelection::DestinationBundle { bundle } => {
            let derived = match (userspace_platform.architecture, host) {
                (user, kernel) if user == kernel => Translation::None,
                (GuestArchitecture::Amd64, GuestArchitecture::Arm64) => Translation::Rosetta,
                _ => {
                    return Err(invalid(
                        "no admitted translation runs this userspace on the destination kernel",
                    ))
                }
            };
            // An explicit source translation is replaced only by this approved
            // bundle's derived translation; the plan records both.
            let mut candidate = source.clone();
            if let BootProfile::LinuxDirect {
                kernel_architecture,
                translation,
                binding,
                ..
            } = &mut candidate
            {
                *kernel_architecture = host;
                *translation = derived;
                *binding = BootBinding::RuntimeSelected;
            }
            let binding = if pool.object_path(&bundle).is_file() {
                let bytes = pool.read_object(
                    &bundle,
                    crate::storage::limits::Resource::MetadataPageBytes.maximum(),
                )?;
                let binding = BootBinding::decode(&bytes)?;
                if binding.digest()? != bundle {
                    return Err(invalid("destination boot bundle is not canonical"));
                }
                binding
            } else {
                let context = runtime.captured_boot_context(pool, store, uuid::Uuid::nil());
                let packaged = crate::runtime::boot_assets::packaged_binding(
                    &candidate,
                    agent,
                    context.selection(),
                )?;
                if packaged.digest()? != bundle {
                    return Err(invalid(
                        "approved boot bundle is neither retained nor this runtime's packaged bundle",
                    ));
                }
                packaged
            };
            if !matches!(&binding, BootBinding::Pinned { architecture, .. } if *architecture == host)
            {
                return Err(invalid(
                    "approved boot bundle targets another kernel architecture",
                ));
            }
            if let BootProfile::LinuxDirect {
                binding: target, ..
            } = &mut candidate
            {
                *target = binding;
            }
            candidate.validate()?;
            Ok(candidate)
        }
    }
}

/// Read-only destination admission. Nothing is reserved or written.
pub(crate) async fn preflight(
    runtime: &Runtime,
    observation: &SourceObservation,
    request: &DestinationRequest,
) -> Result<HandoffProposal, LibVmError> {
    let store = runtime.native_store()?;
    let destination_runtime = store.runtime_id().await?;
    let source = observation.body();
    if source.runtime == destination_runtime {
        return Err(HandoffError::SameRuntime.into());
    }
    let destination_machine = match request.mode {
        HandoffMode::Relocate => source.machine,
        HandoffMode::Fork => fork_machine_id(request.operation, destination_runtime),
    };
    let name = request.name.clone().unwrap_or_else(|| source.name.clone());
    crate::validate_new_machine_name(&name)?;
    if let Some(existing) = runtime.machine_config(destination_machine).await? {
        let storage = runtime.machine_storage_record(existing.id).await?;
        match (&storage.ownership, request.mode) {
            (
                MachineOwnership::Relocated {
                    successor_runtime,
                    successor_epoch,
                    ..
                },
                HandoffMode::Relocate,
            ) if *successor_runtime == source.runtime
                && *successor_epoch == source.ownership_epoch => {}
            (MachineOwnership::Relocated { .. }, HandoffMode::Relocate) => {
                return Err(HandoffError::ReturnOwnerMismatch {
                    machine: destination_machine,
                }
                .into())
            }
            _ => {
                return Err(HandoffError::MachineIdConflict {
                    machine: destination_machine,
                }
                .into())
            }
        }
    }
    if let Some(named) = runtime.machine_config_by_name(&name).await? {
        if named.id != destination_machine {
            return Err(LibVmError::MachineAlreadyExists { name });
        }
    }
    let backend = runtime.effective_backend();
    crate::runtime::boot_assets::admit_create_source(
        crate::runtime::boot_assets::SourceFamily::ManagedImage,
        source.storage.profile,
        source.storage.backend,
        backend,
    )?;
    runtime.preflight_captured_lane(
        &source.storage,
        crate::runtime::boot_assets::CaptureLane::Stopped,
    )?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let selection = match request.boot_bundle {
        None => BootSelection::ExactRecorded,
        Some(bundle) => BootSelection::DestinationBundle { bundle },
    };
    let boot = destination_boot(
        runtime,
        &store,
        &source.storage.boot,
        source.configuration.guest.agent.enabled(),
        selection,
        &pool,
    )?;
    let mut configuration = source.configuration.clone();
    let external_requirements = crate::machine::stopped::apply_resources(
        &mut configuration,
        &source.external_requirements,
        &request.resources,
    )?;
    let plan = HandoffPlan::new(PlanBody {
        schema: 1,
        operation: request.operation,
        mode: request.mode,
        observation: source.clone(),
        observation_digest: observation.document().digest(),
        destination_runtime,
        destination_machine,
        destination_name: name,
        boot_selection: selection,
        boot,
        configuration,
        external_requirements,
        resources: request.resources.clone(),
    })?;
    admit_resources(runtime, plan.body()).await?;
    let (estimate, demand) = estimate(runtime, &pool, &plan)?;
    admit_space(demand.required(), estimate.available_bytes)?;
    Ok(HandoffProposal { plan, estimate })
}

/// Destination-local admission of the plan's external resources, network and
/// effective boot. Preflight runs it to propose; prepare and commit rerun it
/// against the saved approved plan, never replacing what was approved.
async fn admit_resources(runtime: &Runtime, body: &PlanBody) -> Result<(), LibVmError> {
    if let crate::ExternalResourcePolicy::Map { mappings } = &body.resources {
        for mapping in mappings {
            if std::fs::symlink_metadata(&mapping.path).is_err() {
                return Err(invalid(format!(
                    "destination mapping {} does not exist",
                    mapping.path.display()
                )));
            }
        }
    }
    let configuration = &body.configuration;
    crate::runtime::boot_assets::effective_boot_profile(
        &body.boot,
        &configuration.spec,
        runtime.effective_backend(),
    )?;
    runtime
        .validate_machine_network_config(&configuration.network)
        .await?;
    runtime.validate_tailscale_vsock(&configuration.network, &configuration.spec)?;
    Ok(())
}

/// The saved approved plan must still be admissible here. Any difference is
/// stale admission; the approved configuration and bundle are never replaced.
async fn readmit(runtime: &Runtime, plan: &ApprovedPlan) -> Result<(), LibVmError> {
    if let Err(error) = admit_resources(runtime, plan.body()).await {
        tracing::warn!(
            operation = %plan.plan().operation(),
            %error,
            "handoff destination admission is stale"
        );
        return Err(HandoffError::AdmissionStale.into());
    }
    Ok(())
}

/// Destination bytes that may be allocated at once, before maps are known.
///
/// ```text
///  received chunks (≤ writable + missing streams) stay pinned until the
///  terminal decision, while prepare writes
///    private copies          writable
///    rebuilt streams         missing streams, staged then copied into pool
///  plus one staged payload copied into the pool (largest object or chunk)
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SpaceDemand {
    writable: u64,
    missing_streams: u64,
    missing_objects: u64,
    largest_object: u64,
}

impl SpaceDemand {
    fn required(&self) -> u64 {
        let transient = self
            .largest_object
            .max(crate::storage::limits::CHUNK_SIZE as u64);
        self.writable
            .saturating_mul(2)
            .saturating_add(self.missing_streams.saturating_mul(3))
            .saturating_add(self.missing_objects)
            .saturating_add(transient)
    }
}

fn admit_space(required: u64, available: u64) -> Result<(), LibVmError> {
    if required > available {
        return Err(invalid(format!(
            "destination needs {required} bytes but has {available} available"
        )));
    }
    Ok(())
}

// statvfs field widths differ between Linux and Darwin.
#[allow(clippy::unnecessary_cast)]
fn available_bytes(runtime: &Runtime) -> Result<u64, LibVmError> {
    let stat = nix::sys::statvfs::statvfs(runtime.local_home()).map_err(std::io::Error::from)?;
    Ok((stat.blocks_available() as u64).saturating_mul(stat.fragment_size() as u64))
}

fn estimate(
    runtime: &Runtime,
    pool: &StoragePool,
    plan: &HandoffPlan,
) -> Result<(TransferEstimate, SpaceDemand), LibVmError> {
    let body = &plan.body().observation;
    let mut estimate = TransferEstimate {
        writable_bytes: body.writable.iter().map(|file| file.length).sum(),
        ..TransferEstimate::default()
    };
    let mut demand = SpaceDemand {
        writable: estimate.writable_bytes,
        ..SpaceDemand::default()
    };
    for object in &body.immutable.objects {
        estimate.immutable_bytes += object.length;
        if !pool.object_path(&object.digest).is_file() {
            estimate.missing_immutable_bytes += object.length;
            demand.missing_objects += object.length;
            demand.largest_object = demand.largest_object.max(object.length);
        }
    }
    for stream in &body.immutable.streams {
        estimate.immutable_bytes += stream.length;
        if !pool.stream_path(&stream.stream).is_file() {
            estimate.missing_immutable_bytes += stream.length;
            demand.missing_streams += stream.length;
        }
    }
    estimate.available_bytes = available_bytes(runtime)?;
    Ok((estimate, demand))
}

fn require_destination(record: &HandoffRecord) -> Result<(), LibVmError> {
    if record.role != HandoffRole::Destination {
        return Err(HandoffError::WrongRuntime.into());
    }
    Ok(())
}

/// Persist the plan, start the ledger record and pin the present closure.
pub(crate) async fn receive(
    runtime: &Runtime,
    store: &Store,
    plan: &ApprovedPlan,
    lease: &mut Option<crate::storage::locks::StorageLock>,
) -> Result<HandoffRecord, LibVmError> {
    let intent = plan.intent()?;
    if let Some(record) = store.get_handoff(intent.operation).await? {
        require_destination(&record)?;
        if record.intent != intent {
            return Err(HandoffError::OperationConflict {
                operation: intent.operation,
            }
            .into());
        }
        if record.phase.is_terminal() {
            return Ok(record);
        }
    }
    readmit(runtime, plan).await?;
    let files = OperationFiles::create(runtime.local_home(), intent.operation)?;
    files.store_document(DocumentName::Plan, plan.document(), false)?;
    if lease.is_none() {
        *lease = Some(store.begin_handoff_storage(intent.operation).await?);
    }
    let record = store.receive_handoff(&intent).await?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let closure = &plan.body().observation.immutable;
    let _roots = pool.lock_roots_shared()?;
    let streams = closure
        .streams
        .iter()
        .map(|entry| entry.stream)
        .filter(|stream| pool.stream_path(stream).is_file())
        .collect::<Vec<_>>();
    let objects = closure
        .objects
        .iter()
        .map(|entry| entry.digest)
        .filter(|digest| pool.object_path(digest).is_file())
        .collect::<Vec<_>>();
    store
        .pin_handoff_dependencies(intent.operation, &streams, &objects)
        .await?;
    Ok(record)
}

pub(crate) async fn offer(
    runtime: &Runtime,
    store: &Store,
    offer: &CaptureOffer,
) -> Result<HandoffRecord, LibVmError> {
    let operation = offer.binding().intent.operation;
    if let Some(record) = store.get_handoff(operation).await? {
        require_destination(&record)?;
        if record.phase.is_terminal() {
            if record.phase == HandoffPhase::Aborted {
                return Err(HandoffError::OperationAborted { operation }.into());
            }
            return Ok(record);
        }
    }
    let plan = crate::handoff::source::stored_plan(runtime, operation)?;
    if plan.intent()? != offer.binding().intent {
        return Err(HandoffError::ReceiptMismatch.into());
    }
    offer.manifest().body().check_plan(&plan)?;
    let files = OperationFiles::existing(runtime.local_home(), operation)?;
    files.store_document(DocumentName::Manifest, offer.manifest().document(), false)?;
    store.offer_handoff_capture(offer.binding()).await
}

/// Direct-return reuse: the prior-owner record's own private files.
pub(crate) struct PriorOwner {
    machine_dir: std::path::PathBuf,
    files: Vec<(crate::PrivatePath, u64)>,
    index: ChunkIndex,
}

impl PriorOwner {
    /// Only for a relocation whose destination holds the exact fenced prior
    /// owner the ledger admits. Unchanged chunks are verified when read.
    pub(crate) async fn load(
        runtime: &Runtime,
        plan: &ApprovedPlan,
    ) -> Result<Option<Self>, LibVmError> {
        let body = plan.body();
        if body.mode != HandoffMode::Relocate {
            return Ok(None);
        }
        let Some(config) = runtime.machine_config(body.destination_machine).await? else {
            return Ok(None);
        };
        let storage = runtime.machine_storage_record(config.id).await?;
        let MachineOwnership::Relocated {
            successor_runtime,
            successor_epoch,
            ..
        } = storage.ownership
        else {
            return Ok(None);
        };
        if successor_runtime != body.observation.runtime
            || successor_epoch != body.observation.ownership_epoch
        {
            return Ok(None);
        }
        let machine_dir = config.machine_dir.clone();
        let files = writable_files(&storage)
            .into_iter()
            .map(|(_, path, length)| (path, length))
            .collect::<Vec<_>>();
        let directory = match OwnedDirectory::open_existing_root(&machine_dir)? {
            Some(directory) => directory,
            None => return Ok(None),
        };
        let mut index = ChunkIndex::default();
        let mut retained = Vec::new();
        for (path, length) in files {
            // A missing or changed prior file is simply not a reuse source.
            let Ok(source) = crate::machine::stopped::open_private(&directory, &path, length)
            else {
                continue;
            };
            let map = StreamHasher::new()
                .hash_open_file(&source.file, length)?
                .map;
            index.add(retained.len(), &map);
            retained.push((path, length));
        }
        Ok(Some(Self {
            machine_dir,
            files: retained,
            index,
        }))
    }

    fn has(&self, digest: &ObjectDigest, length: u64) -> bool {
        self.index.get(digest, length).is_some()
    }

    fn read(&self, digest: &ObjectDigest, length: u64) -> Result<Option<Vec<u8>>, LibVmError> {
        let Some(place) = self.index.get(digest, length) else {
            return Ok(None);
        };
        let Some(directory) = OwnedDirectory::open_existing_root(&self.machine_dir)? else {
            return Ok(None);
        };
        let Some((path, file_length)) = self.files.get(place.file) else {
            return Ok(None);
        };
        let Ok(source) = crate::machine::stopped::open_private(&directory, path, *file_length)
        else {
            return Ok(None);
        };
        crate::handoff::chunks::read_verified(&source.file, place.offset, length, digest)
    }
}

/// The complete inventory of one operation for the current set of maps.
pub(crate) struct Inventory {
    key: InventoryKey,
    entries: Vec<PayloadDescriptor>,
    members: HashSet<PayloadDescriptor>,
    /// Streams already verified whole in the local pool.
    whole: BTreeSet<StreamId>,
}

/// What an inventory was built from: whether a manifest was offered and
/// which needed stream maps were present. Cheap to recompute (stat only).
#[derive(Debug, Clone, PartialEq, Eq)]
struct InventoryKey {
    manifest: bool,
    maps: BTreeSet<StreamId>,
}

/// Streams of the plan's closure and, once offered, the cut.
fn inventory_streams(
    plan: &ApprovedPlan,
    files: &OperationFiles,
) -> Result<(bool, Vec<StreamId>), LibVmError> {
    let mut streams = plan
        .body()
        .observation
        .immutable
        .streams
        .iter()
        .map(|entry| entry.stream)
        .collect::<Vec<_>>();
    let manifest = match files.load_document(DocumentName::Manifest)? {
        Some(document) => {
            let manifest = CaptureManifest::from_document(document)?;
            streams.extend(manifest.body().files.iter().map(|file| file.stream));
            true
        }
        None => false,
    };
    Ok((manifest, streams))
}

fn inventory_key(
    plan: &ApprovedPlan,
    files: &OperationFiles,
    whole: &BTreeSet<StreamId>,
) -> Result<(InventoryKey, Vec<StreamId>), LibVmError> {
    let (manifest, streams) = inventory_streams(plan, files)?;
    let mut maps = BTreeSet::new();
    for stream in &streams {
        if !whole.contains(stream) && files.has_map(stream)? {
            maps.insert(*stream);
        }
    }
    Ok((InventoryKey { manifest, maps }, streams))
}

impl Inventory {
    fn build(
        plan: &ApprovedPlan,
        files: &OperationFiles,
        whole: &BTreeSet<StreamId>,
    ) -> Result<Self, LibVmError> {
        let (key, streams) = inventory_key(plan, files, whole)?;
        let mut entries = Vec::new();
        for object in &plan.body().observation.immutable.objects {
            entries.push(PayloadDescriptor::Object {
                digest: object.digest,
                length: object.length,
            });
        }
        let mut loaded = Vec::new();
        for stream in &streams {
            if whole.contains(stream) {
                continue;
            }
            entries.push(PayloadDescriptor::StreamMap { stream: *stream });
            if key.maps.contains(stream) {
                loaded.push(
                    files
                        .load_map(stream)?
                        .ok_or_else(|| invalid("stream map disappeared"))?,
                );
            }
        }
        let mut seen = HashSet::new();
        for map in &loaded {
            for (_, length, chunk) in extents(map) {
                if let Chunk::Data(digest) = chunk {
                    if seen.insert(digest) {
                        entries.push(PayloadDescriptor::Chunk { digest, length });
                    }
                }
            }
        }
        let members = entries.iter().copied().collect();
        Ok(Self {
            key,
            entries,
            members,
            whole: whole.clone(),
        })
    }

    pub(crate) fn contains(&self, descriptor: &PayloadDescriptor) -> bool {
        self.members.contains(descriptor)
    }
}

/// Mutable destination knowledge cached across requests of one operation.
/// `verified` holds only objects already pinned by this operation's root.
pub(crate) struct DestinationState {
    pub(crate) inventory: Arc<Inventory>,
    pub(crate) prior: Option<Arc<PriorOwner>>,
    pub(crate) verified: HashSet<ObjectDigest>,
}

/// One inventory entry's local state. A pool object verified outside root
/// coordination is only a candidate until the same file is pinned.
enum Local {
    Satisfied,
    Missing,
    Candidate(Candidate),
}

struct Candidate {
    digest: ObjectDigest,
    fingerprint: crate::storage::identity_file::SourceFingerprint,
}

impl Candidate {
    /// Under shared roots: the verified file is still the published object.
    fn retained(&self, pool: &StoragePool) -> Result<bool, LibVmError> {
        match pool.open_object(&self.digest) {
            Ok(file) => Ok(crate::storage::identity_file::SourceFingerprint::new(
                &file.metadata()?,
            ) == self.fingerprint),
            Err(crate::storage::StorageError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl DestinationState {
    pub(crate) async fn load(
        runtime: &Runtime,
        operation: OperationId,
    ) -> Result<Self, LibVmError> {
        let plan = crate::handoff::source::stored_plan(runtime, operation)?;
        let files = OperationFiles::existing(runtime.local_home(), operation)?;
        let whole = retain_whole(runtime, operation, whole_streams(runtime, &plan)?).await?;
        Ok(Self {
            inventory: Arc::new(Inventory::build(&plan, &files, &whole)?),
            prior: PriorOwner::load(runtime, &plan).await?.map(Arc::new),
            verified: HashSet::new(),
        })
    }

    /// Rebuild only when the manifest or the present map set changed.
    pub(crate) fn refresh(
        &mut self,
        runtime: &Runtime,
        operation: OperationId,
    ) -> Result<(), LibVmError> {
        let plan = crate::handoff::source::stored_plan(runtime, operation)?;
        let files = OperationFiles::existing(runtime.local_home(), operation)?;
        let (key, _) = inventory_key(&plan, &files, &self.inventory.whole)?;
        if key != self.inventory.key {
            self.inventory = Arc::new(Inventory::build(&plan, &files, &self.inventory.whole)?);
        }
        Ok(())
    }

    /// Hashes outside root coordination; never caches an unpinned object.
    fn object_local(
        &self,
        pool: &StoragePool,
        digest: &ObjectDigest,
        length: u64,
    ) -> Result<Local, LibVmError> {
        if self.verified.contains(digest) {
            return Ok(Local::Satisfied);
        }
        match pool.verify_object(digest) {
            Ok(file) => {
                let metadata = file.metadata()?;
                Ok(if metadata.len() == length {
                    Local::Candidate(Candidate {
                        digest: *digest,
                        fingerprint: crate::storage::identity_file::SourceFingerprint::new(
                            &metadata,
                        ),
                    })
                } else {
                    Local::Missing
                })
            }
            Err(crate::storage::StorageError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(Local::Missing)
            }
            Err(crate::storage::StorageError::ContentMismatch(_)) => Ok(Local::Missing),
            Err(error) => Err(error.into()),
        }
    }

    /// Whether one inventory entry is satisfied locally.
    fn local(
        &self,
        pool: &StoragePool,
        files: &OperationFiles,
        descriptor: &PayloadDescriptor,
    ) -> Result<Local, LibVmError> {
        match *descriptor {
            PayloadDescriptor::Object { digest, length } => {
                self.object_local(pool, &digest, length)
            }
            PayloadDescriptor::StreamMap { stream } => Ok(if files.has_map(&stream)? {
                Local::Satisfied
            } else {
                Local::Missing
            }),
            PayloadDescriptor::Chunk { digest, length } => {
                if self
                    .prior
                    .as_ref()
                    .is_some_and(|prior| prior.has(&digest, length))
                {
                    return Ok(Local::Satisfied);
                }
                self.object_local(pool, &digest, length)
            }
        }
    }

    /// One page of unsatisfied descriptors starting at `cursor`. Candidates
    /// count toward the page bound, since a vanished one becomes a need.
    pub(crate) async fn needs(
        &mut self,
        runtime: &Runtime,
        store: &Store,
        operation: OperationId,
        cursor: Option<NeedCursor>,
        limit: u32,
    ) -> Result<NeedsPage, LibVmError> {
        if limit == 0 || limit > MAX_PAGE_ENTRIES {
            return Err(invalid("needs page limit is outside 1..=1024"));
        }
        self.refresh(runtime, operation)?;
        let inventory = self.inventory.clone();
        let start = usize::try_from(cursor.map_or(0, |cursor| cursor.0))
            .ok()
            .filter(|start| *start <= inventory.entries.len())
            .ok_or_else(|| invalid("needs cursor is outside the inventory"))?;
        let pool = StoragePool::open(runtime.local_images_dir())?;
        let files = OperationFiles::existing(runtime.local_home(), operation)?;
        let mut needs = Vec::new();
        let mut candidates = Vec::new();
        let mut index = start;
        while let Some(descriptor) = inventory.entries.get(index).copied() {
            if needs.len() + candidates.len() == limit as usize {
                break;
            }
            match self.local(&pool, &files, &descriptor)? {
                Local::Satisfied => {}
                Local::Missing => needs.push(descriptor),
                Local::Candidate(candidate) => candidates.push((descriptor, candidate)),
            }
            index += 1;
        }
        let vanished = self.retain(&pool, store, operation, candidates).await?;
        needs.extend(vanished);
        Ok(NeedsPage {
            needs,
            next: (index < inventory.entries.len()).then_some(NeedCursor(index as u64)),
        })
    }

    /// Recheck and pin candidates under one shared-roots hold, so collection
    /// can neither remove a reused object first nor between check and pin.
    /// Only pinned objects are cached; vanished ones are returned as needs.
    async fn retain(
        &mut self,
        pool: &StoragePool,
        store: &Store,
        operation: OperationId,
        candidates: Vec<(PayloadDescriptor, Candidate)>,
    ) -> Result<Vec<PayloadDescriptor>, LibVmError> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let _roots = pool.lock_roots_shared()?;
        let mut pins = Vec::new();
        let mut vanished = Vec::new();
        for (descriptor, candidate) in candidates {
            if candidate.retained(pool)? {
                pins.push(candidate.digest);
            } else {
                vanished.push(descriptor);
            }
        }
        if !pins.is_empty() {
            store
                .pin_handoff_dependencies(operation, &[], &pins)
                .await?;
            self.verified.extend(pins);
        }
        Ok(vanished)
    }

    /// Every unsatisfied descriptor; prepare requires none.
    async fn missing(
        &mut self,
        runtime: &Runtime,
        store: &Store,
        operation: OperationId,
    ) -> Result<usize, LibVmError> {
        let mut cursor = None;
        let mut missing = 0;
        loop {
            let page = self
                .needs(runtime, store, operation, cursor, MAX_PAGE_ENTRIES)
                .await?;
            missing += page.needs.len();
            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(missing),
            }
        }
    }

    /// Verified bytes of one chunk from a local source.
    fn chunk(
        &mut self,
        pool: &StoragePool,
        digest: &ObjectDigest,
        length: u64,
    ) -> Result<Vec<u8>, LibVmError> {
        if let Some(bytes) = self
            .prior
            .as_ref()
            .map(|prior| prior.read(digest, length))
            .transpose()?
            .flatten()
        {
            return Ok(bytes);
        }
        let bytes = pool.read_object(digest, length)?;
        if bytes.len() as u64 != length {
            return Err(invalid("chunk object length differs from its descriptor"));
        }
        Ok(bytes)
    }
}

/// Immutable streams verified whole in this pool, outside root coordination.
fn whole_streams(runtime: &Runtime, plan: &ApprovedPlan) -> Result<BTreeSet<StreamId>, LibVmError> {
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let mut whole = BTreeSet::new();
    for entry in &plan.body().observation.immutable.streams {
        if pool.stream_path(&entry.stream).is_file() {
            match pool.verify_stream(&entry.stream) {
                Ok(map) if map.length() == entry.length => {
                    whole.insert(entry.stream);
                }
                Ok(_) | Err(crate::storage::StorageError::ContentMismatch(_)) => {}
                Err(crate::storage::StorageError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(whole)
}

/// A verified whole stream counts only once pinned under shared roots; one
/// collected meanwhile is requested as a map and chunks instead.
async fn retain_whole(
    runtime: &Runtime,
    operation: OperationId,
    verified: BTreeSet<StreamId>,
) -> Result<BTreeSet<StreamId>, LibVmError> {
    if verified.is_empty() {
        return Ok(verified);
    }
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let store = runtime.native_store()?;
    let _roots = pool.lock_roots_shared()?;
    let retained = verified
        .into_iter()
        .filter(|stream| pool.stream_path(stream).is_file())
        .collect::<BTreeSet<_>>();
    let pins = retained.iter().copied().collect::<Vec<_>>();
    store
        .pin_handoff_dependencies(operation, &pins, &[])
        .await?;
    Ok(retained)
}

/// An open destination payload write. Partial bytes live only in staging;
/// dropping an unfinished writer discards them.
pub struct HandoffPayloadWriter {
    runtime: Runtime,
    operation: OperationId,
    descriptor: PayloadDescriptor,
    staging: OwnedDirectory,
    name: String,
    file: Option<std::fs::File>,
    written: u64,
    hasher: sha2::Sha256,
    finished: bool,
}

impl HandoffPayloadWriter {
    pub(crate) fn open(
        runtime: Runtime,
        operation: OperationId,
        descriptor: PayloadDescriptor,
    ) -> Result<Self, LibVmError> {
        descriptor.validate()?;
        let files = OperationFiles::existing(runtime.local_home(), operation)?;
        let staging = files.staging()?;
        let name = format!("{}.part", uuid::Uuid::new_v4());
        let file = crate::image::transport::blobs::create_private_file(&staging, &name)?;
        Ok(Self {
            runtime,
            operation,
            descriptor,
            staging,
            name,
            file: Some(file),
            written: 0,
            hasher: sha2::Sha256::new(),
            finished: false,
        })
    }

    pub fn descriptor(&self) -> PayloadDescriptor {
        self.descriptor
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Append one bounded, nonempty frame.
    pub fn write_frame(&mut self, bytes: &[u8]) -> Result<(), LibVmError> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES as usize {
            return Err(invalid("payload frame is empty or exceeds 1 MiB"));
        }
        let total = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= self.descriptor.max_length())
            .ok_or_else(|| invalid("payload exceeds its descriptor length"))?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| invalid("payload writer is closed"))?;
        file.write_all(bytes)?;
        self.hasher.update(bytes);
        self.written = total;
        Ok(())
    }

    /// Verify, publish durably and pin. Returns the verified byte count.
    /// Serialized with every transition by the operation lock, so a terminal
    /// release can never be followed by recreated maps, staging or pins.
    pub(crate) async fn finish_inner(mut self) -> Result<PayloadReceipt, LibVmError> {
        let store = self.runtime.native_store()?;
        let files = OperationFiles::existing(self.runtime.local_home(), self.operation)?;
        let _transition = files.lock()?;
        let record =
            store
                .get_handoff(self.operation)
                .await?
                .ok_or(HandoffError::UnknownOperation {
                    operation: self.operation,
                })?;
        require_destination(&record)?;
        match record.phase {
            HandoffPhase::Receiving => {}
            HandoffPhase::Aborted => {
                return Err(HandoffError::OperationAborted {
                    operation: self.operation,
                }
                .into())
            }
            _ => return Err(HandoffError::InvalidState.into()),
        }
        let mut file = self
            .file
            .take()
            .ok_or_else(|| invalid("payload writer is closed"))?;
        if let Some(length) = self.descriptor.exact_length() {
            if self.written != length {
                return Err(invalid("payload ended before its descriptor length"));
            }
        }
        file.sync_all()?;
        match self.descriptor {
            PayloadDescriptor::Object { digest, .. } | PayloadDescriptor::Chunk { digest, .. } => {
                let actual = ObjectDigest::from_sha256(self.hasher.clone().finalize().into());
                if actual != digest {
                    return Err(invalid("payload bytes do not match their digest"));
                }
                file.seek(SeekFrom::Start(0))?;
                let pool = StoragePool::open(self.runtime.local_images_dir())?;
                let path = self.staging.path().join(&self.name);
                let (published, roots) = pool.publish_object_file_for_catalog(file, &path)?;
                if published.digest != digest {
                    return Err(invalid("published payload differs from its digest"));
                }
                store
                    .pin_handoff_dependencies(self.operation, &[], &[digest])
                    .await?;
                drop(roots);
            }
            PayloadDescriptor::StreamMap { stream } => {
                let mut bytes = Vec::new();
                file.seek(SeekFrom::Start(0))?;
                file.take(self.written).read_to_end(&mut bytes)?;
                files.store_map(&stream, &bytes)?;
            }
        }
        self.staging.remove_tree(&self.name)?;
        self.finished = true;
        Ok(PayloadReceipt {
            descriptor: self.descriptor,
            bytes: self.written,
        })
    }
}

impl Drop for HandoffPayloadWriter {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        drop(self.file.take());
        if let Err(error) = self.staging.remove_tree(&self.name) {
            tracing::warn!(operation = %self.operation, %error, "discard partial handoff payload");
        }
    }
}

/// Build one stream's exact bytes into `file` from local verified sources.
fn assemble(
    state: &mut DestinationState,
    pool: &StoragePool,
    map: &StreamMap,
    file: &std::fs::File,
) -> Result<(), LibVmError> {
    file.set_len(map.length())?;
    for (offset, length, chunk) in extents(map) {
        if let Chunk::Data(digest) = chunk {
            let bytes = state.chunk(pool, &digest, length)?;
            file.write_all_at(&bytes, offset)?;
        }
    }
    file.sync_all()?;
    let rehashed = StreamHasher::new().hash_open_file(file, map.length())?.map;
    if rehashed != *map {
        return Err(invalid("assembled stream does not reproduce its map"));
    }
    Ok(())
}

/// Destination storage for this plan and cut. Deterministic, so commit can
/// recompute exactly what prepare wrote.
fn destination_storage(
    plan: &ApprovedPlan,
    manifest: &CaptureManifest,
    prior: Option<&MachineStorageRecord>,
) -> Result<MachineStorageRecord, LibVmError> {
    let body = plan.body();
    let intent = plan.intent()?;
    let mut storage = body.observation.storage.clone();
    let capture = manifest.capture();
    let template = storage.clone();
    let root_name = prepared_name(capture, WritableRole::Root, &template);
    match &mut storage.root {
        MachineRoot::OpaqueRaw { path, .. } => *path = crate::PrivatePath::new(root_name)?,
        MachineRoot::LinuxOverlay { upper, .. } => *upper = crate::PrivatePath::new(root_name)?,
    }
    for disk in &mut storage.disks {
        let order = disk.order;
        if let DiskStorage::ManagedWritable { path, .. } = &mut disk.storage {
            *path = crate::PrivatePath::new(prepared_name(
                capture,
                WritableRole::Disk { order },
                &template,
            ))?;
        }
        if body.mode == HandoffMode::Fork {
            disk.id = uuid::Uuid::new_v4();
        }
    }
    storage.boot = body.boot.clone();
    storage.external_requirements = body.external_requirements.clone();
    storage.stop_outcome = manifest.body().stop_outcome;
    storage.ownership = MachineOwnership::Owned;
    storage.ownership_epoch = intent.destination_epoch()?.get();
    storage.storage_generation = match body.mode {
        HandoffMode::Fork => 0,
        HandoffMode::Relocate => {
            let prior = prior.map_or(Some(0), |prior| prior.storage_generation.checked_add(1));
            prior
                .map(|prior| prior.max(body.observation.storage_generation))
                .ok_or_else(|| invalid("storage generation overflow"))?
        }
    };
    storage.operation = None;
    storage.image = None;
    storage.snapshot = None;
    storage.validate()?;
    Ok(storage)
}

fn machine_directory(runtime: &Runtime, machine: MachineId) -> Result<OwnedDirectory, LibVmError> {
    let path = crate::paths::machine_data_dir_in(runtime.local_home(), machine);
    let parent = path
        .parent()
        .ok_or_else(|| invalid("machine directory has no parent"))?;
    let directory = OwnedDirectory::open_root(parent)?.ensure_dir(&machine.to_string())?;
    directory.ensure_dir("captures")?;
    Ok(directory)
}

/// Verify the complete payload, publish missing immutable streams, pin the
/// approved boot and write durable private files. Never publishes a machine.
pub(crate) async fn prepare(
    runtime: &Runtime,
    store: &Store,
    state: &mut DestinationState,
    binding: &HandoffBinding,
) -> Result<PreparedReceipt, LibVmError> {
    let operation = binding.intent.operation;
    let record = store
        .get_handoff(operation)
        .await?
        .ok_or(HandoffError::UnknownOperation { operation })?;
    require_destination(&record)?;
    if record.phase == HandoffPhase::Aborted {
        return Err(HandoffError::OperationAborted { operation }.into());
    }
    if let Some(prepared) = &record.prepared {
        if prepared.binding != *binding {
            return Err(HandoffError::ReceiptMismatch.into());
        }
        return Ok(prepared.clone());
    }
    if record.binding.as_ref() != Some(binding) {
        return Err(HandoffError::ReceiptMismatch.into());
    }
    let plan = crate::handoff::source::stored_plan(runtime, operation)?;
    let files = OperationFiles::existing(runtime.local_home(), operation)?;
    let manifest = CaptureManifest::from_document(
        files
            .load_document(DocumentName::Manifest)?
            .ok_or_else(|| invalid("offered manifest is missing"))?,
    )?;
    if manifest.document().digest() != binding.capture_manifest_digest {
        return Err(HandoffError::ReceiptMismatch.into());
    }
    readmit(runtime, &plan).await?;
    let missing = state.missing(runtime, store, operation).await?;
    if missing != 0 {
        return Err(invalid(format!(
            "handoff payload is incomplete: {missing} descriptors missing"
        )));
    }
    let body = plan.body();
    let mut rebuilt = Vec::new();
    for entry in &body.observation.immutable.streams {
        // Whole streams were pinned when the destination state was loaded.
        if !state.inventory.whole.contains(&entry.stream) {
            let map = files
                .load_map(&entry.stream)?
                .ok_or_else(|| invalid("immutable stream map is missing"))?;
            rebuilt.push((entry.stream, map));
        }
    }
    let mut outputs = Vec::new();
    for captured in &manifest.body().files {
        let map = files
            .load_map(&captured.stream)?
            .ok_or_else(|| invalid("captured stream map is missing"))?;
        let name = prepared_name(manifest.capture(), captured.role, &body.observation.storage);
        outputs.push((name, captured.length, map));
    }
    admit_space(
        prepare_demand(runtime, body.destination_machine, &rebuilt, &outputs)?,
        available_bytes(runtime)?,
    )?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    // Immutable streams absent as whole files are rebuilt and published.
    for (stream, map) in &rebuilt {
        let staging = files.staging()?;
        let name = format!("{}.stream", uuid::Uuid::new_v4());
        let file = crate::image::transport::blobs::create_private_file(&staging, &name)?;
        let result = (|| {
            assemble(state, &pool, map, &file)?;
            Ok::<_, LibVmError>(pool.publish_stream_file_for_catalog(file, map.length())?)
        })();
        staging.remove_tree(&name)?;
        let (published, roots) = result?;
        if published.id != *stream {
            return Err(invalid(
                "rebuilt immutable stream differs from its identity",
            ));
        }
        store
            .pin_handoff_dependencies(operation, &[*stream], &[])
            .await?;
        drop(roots);
    }
    // Pin and qualify the approved boot tuple from this pool only.
    let prior = match runtime.machine_config(body.destination_machine).await? {
        Some(config) => Some(runtime.machine_storage_record(config.id).await?),
        None => None,
    };
    let mut storage = destination_storage(&plan, &manifest, prior.as_ref())?;
    let bundle = boot_bundle(&body.boot)?;
    // Boot pinning stages its canonical tuple under the pool's operation dir.
    OwnedDirectory::open_existing_root(&runtime.local_images_dir().join("tmp"))?
        .ok_or_else(|| invalid("pool staging root is missing"))?
        .ensure_dir(&operation.to_string())?;
    let context = runtime.captured_boot_context(&pool, store, operation.as_uuid());
    let selection = approved_selection(&body.boot, &pool, &context)?;
    let pinned =
        crate::runtime::boot_assets::pin_boot_selection(&storage, &selection, context).await?;
    if boot_bundle(&pinned)? != bundle {
        return Err(HandoffError::AdmissionStale.into());
    }
    storage.boot = pinned;
    // Private writable files, named by capture, beside any prior-owner files.
    let directory = machine_directory(runtime, body.destination_machine)?;
    for (name, length, map) in &outputs {
        if let Some(existing) = directory.open_file(name)? {
            let rehashed = StreamHasher::new()
                .hash_open_file(&existing, *length)
                .map(|scan| scan.map);
            if existing.metadata()?.len() == *length
                && rehashed.as_ref().is_ok_and(|rehashed| rehashed == map)
            {
                // Equal bytes may still be dirty pages of an interrupted
                // write; the prepared receipt promises durable data.
                existing.sync_all()?;
                continue;
            }
            directory.remove_tree(name)?;
        }
        let file = crate::image::transport::blobs::create_private_file(&directory, name)?;
        if let Err(error) = assemble(state, &pool, map, &file) {
            directory.remove_tree(name)?;
            return Err(error);
        }
    }
    directory.sync()?;
    store.prepare_handoff_destination(binding).await
}

/// Nonzero bytes of one stream; private outputs are written sparse.
fn data_bytes(map: &StreamMap) -> u64 {
    extents(map)
        .filter(|(_, _, chunk)| matches!(chunk, Chunk::Data(_)))
        .map(|(_, length, _)| length)
        .sum()
}

/// Bytes prepare may still allocate while every received chunk stays pinned:
/// each rebuilt stream is staged sparse and copied whole into the pool, and
/// each private file not already present is written sparse.
fn prepare_demand(
    runtime: &Runtime,
    machine: MachineId,
    rebuilt: &[(StreamId, StreamMap)],
    outputs: &[(String, u64, StreamMap)],
) -> Result<u64, LibVmError> {
    let existing = OwnedDirectory::open_existing_root(&crate::paths::machine_data_dir_in(
        runtime.local_home(),
        machine,
    ))?;
    let mut required = 0u64;
    for (_, map) in rebuilt {
        required = required
            .saturating_add(data_bytes(map))
            .saturating_add(map.length());
    }
    for (name, _, map) in outputs {
        let present = match &existing {
            Some(directory) => directory.open_file(name)?.is_some(),
            None => false,
        };
        if !present {
            required = required.saturating_add(data_bytes(map));
        }
    }
    Ok(required)
}

/// The selection that materializes exactly the approved tuple: the retained
/// bundle, else this runtime's packaged files with the approved agent choice.
/// Prepare still requires the pinned digest to equal the approved one.
fn approved_selection(
    boot: &BootProfile,
    pool: &StoragePool,
    context: &crate::runtime::boot_assets::CapturedBootContext<'_>,
) -> Result<crate::BootAssetSelection, LibVmError> {
    let bundle = boot_bundle(boot)?;
    if pool.object_path(&bundle).is_file() {
        return Ok(crate::BootAssetSelection::Exact { bundle });
    }
    let BootProfile::LinuxDirect {
        binding: BootBinding::Pinned { agent, .. },
        ..
    } = boot
    else {
        return Err(invalid("approved boot is not a pinned tuple"));
    };
    Ok(crate::BootAssetSelection::Files {
        kernel: context.default_kernel.to_path_buf(),
        base_initramfs: context.default_initramfs.to_path_buf(),
        agent: agent.is_some().then(|| context.default_agent.to_path_buf()),
    })
}

/// Publish the prepared machine in the ledger's commit transaction.
pub(crate) async fn commit(
    runtime: &Runtime,
    store: &Store,
    authorization: &CommitAuthorization,
) -> Result<TerminalReceipt, LibVmError> {
    let binding = &authorization.prepared.binding;
    let intent = &binding.intent;
    let operation = intent.operation;
    let record = store
        .get_handoff(operation)
        .await?
        .ok_or(HandoffError::UnknownOperation { operation })?;
    require_destination(&record)?;
    if let Some(terminal) = &record.terminal {
        return match terminal.decision {
            HandoffDecision::Committed
                if terminal.authorization.as_ref() == Some(authorization) =>
            {
                clean_terminal(runtime, store, terminal).await?;
                Ok(terminal.clone())
            }
            HandoffDecision::Committed => Err(HandoffError::ReceiptMismatch.into()),
            HandoffDecision::Aborted => {
                clean_terminal(runtime, store, terminal).await?;
                Err(HandoffError::OperationAborted { operation }.into())
            }
        };
    }
    let plan = crate::handoff::source::stored_plan(runtime, operation)?;
    let files = OperationFiles::existing(runtime.local_home(), operation)?;
    let manifest = CaptureManifest::from_document(
        files
            .load_document(DocumentName::Manifest)?
            .ok_or_else(|| invalid("offered manifest is missing"))?,
    )?;
    let machine = plan.body().destination_machine;
    let prior = match runtime.machine_config(machine).await? {
        Some(config) => {
            let storage = runtime.machine_storage_record(config.id).await?;
            Some((config, storage))
        }
        None => None,
    };
    let storage =
        destination_storage(&plan, &manifest, prior.as_ref().map(|(_, storage)| storage))?;
    let directory = machine_directory(runtime, machine)?;
    for (_, path, length) in writable_files(&storage) {
        crate::machine::stopped::open_private(&directory, &path, length)?;
    }
    readmit(runtime, &plan).await?;
    let (publication, lock, created_at) = match &prior {
        Some((config, previous)) => {
            CleanupAuthority::replaced(machine, &directory, previous, &storage)?.store(&files)?;
            (
                HandoffPublication::ReplacePriorOwner,
                None,
                config.created_at,
            )
        }
        None => {
            CleanupAuthority::Created {
                machine,
                directory: EntryIdentity::directory(&directory)?,
            }
            .store(&files)?;
            (
                HandoffPublication::Create,
                Some(runtime.allocate_machine_lock()?),
                crate::utils::now_unix(),
            )
        }
    };
    let result = publish(
        runtime,
        store,
        authorization,
        &plan,
        &storage,
        publication,
        prior.as_ref().map(|(config, _)| config.lock_id),
        lock.as_ref().map(|lock| lock.id()),
        created_at,
    )
    .await;
    match result {
        Ok(receipt) => {
            clean_terminal(runtime, store, &receipt).await?;
            Ok(receipt)
        }
        Err(error) => {
            // A failed or uncertain commit releases only creation-time
            // allocations once the catalog proves the machine absent.
            if publication == HandoffPublication::Create
                && matches!(runtime.machine_config(machine).await, Ok(None))
            {
                if let Some(lock) = lock {
                    if let Err(free) = lock.free() {
                        tracing::warn!(%machine, error = %free, "free handoff machine lock");
                    }
                }
                let scope = store
                    .discard_unpublished_handoff_machine(operation, machine, || {
                        delete_scope(runtime, machine)
                    })
                    .await;
                if let Err(delete) = scope {
                    tracing::warn!(%machine, error = %delete, "delete handoff SSH CA scope");
                }
            }
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish(
    runtime: &Runtime,
    store: &Store,
    authorization: &CommitAuthorization,
    plan: &ApprovedPlan,
    storage: &MachineStorageRecord,
    publication: HandoffPublication,
    prior_lock: Option<crate::lock_manager::LockId>,
    new_lock: Option<crate::lock_manager::LockId>,
    created_at: i64,
) -> Result<TerminalReceipt, LibVmError> {
    let body = plan.body();
    let machine = body.destination_machine;
    let machine_dir = crate::paths::machine_data_dir_in(runtime.local_home(), machine);
    let lock_id = prior_lock
        .or(new_lock)
        .ok_or_else(|| invalid("handoff publication has no machine lock"))?;
    let mut spec = body.configuration.spec.clone();
    crate::machine::stopped::project_child_disks(&mut spec, storage, runtime.local_images_dir())?;
    crate::ssh_ca::resolve(runtime.secret_store(), machine, true).map_err(|error| {
        LibVmError::MachinePreparationFailed {
            reference: body.destination_name.clone(),
            message: format!("create machine SSH CA: {error}"),
        }
    })?;
    crate::runtime::core::write_machine_config(&machine_dir, &body.destination_name, &spec)?;
    let (root, length) = crate::machine::stopped::root_private(storage);
    let now = crate::utils::now_unix();
    let config = MachineConfig {
        id: machine,
        lock_id,
        name: body.destination_name.clone(),
        spec,
        retention: body.configuration.retention,
        process: body.configuration.process.clone(),
        template_name: body.configuration.template_name.clone(),
        agent_mode: body.configuration.agent_mode.clone(),
        guest: body.configuration.guest.clone(),
        machine_dir: machine_dir.clone(),
        created_at,
        modified_at: now,
        image_ref: "stopped-handoff".to_owned(),
        root_disk_size: Some(length),
        labels: body.configuration.labels.clone(),
        metadata: body.configuration.metadata.clone(),
        network: body.configuration.network.clone(),
    };
    let rootfs = MachineRootfsRecord {
        machine_id: machine,
        source_kind: crate::ImageSourceKind::Disk,
        requested_reference: "stopped-handoff".to_owned(),
        selected_reference: None,
        manifest_digest: None,
        config_digest: None,
        image_id: None,
        root_disk_path: machine_dir.join(root.as_path()),
        root_disk_size_bytes: length,
        created_at: now,
    };
    let state = crate::runtime::core::stopped_machine_state(machine, None);
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let _roots = pool.lock_roots_shared()?;
    let mut commit = store
        .begin_handoff_destination_commit(authorization)
        .await?;
    if let Some(receipt) = commit.terminal_receipt().cloned() {
        commit.commit().await?;
        return Ok(receipt);
    }
    store
        .publish_handoff_machine(
            commit.transaction()?,
            publication,
            &config,
            &state,
            &rootfs,
            storage,
        )
        .await?;
    commit.commit().await
}

/// Device and inode of one cleanup target when its authority was recorded.
/// Cleanup removes only an entry that still has exactly this identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EntryIdentity {
    device: u64,
    inode: u64,
}

impl EntryIdentity {
    // stat field widths differ between Linux and Darwin.
    #[allow(clippy::unnecessary_cast)]
    fn of(stat: &nix::sys::stat::FileStat) -> Self {
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        }
    }

    fn directory(directory: &OwnedDirectory) -> Result<Self, LibVmError> {
        Ok(Self::of(
            &nix::sys::stat::fstat(directory.fd()).map_err(std::io::Error::from)?,
        ))
    }

    /// The identity currently named `name` in `parent`, never following links.
    fn entry(parent: &OwnedDirectory, name: &str) -> Result<Option<Self>, LibVmError> {
        match nix::sys::stat::fstatat(
            parent.fd(),
            std::path::Path::new(name),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => Ok(Some(Self::of(&stat))),
            Err(nix::errno::Errno::ENOENT) => Ok(None),
            Err(error) => Err(std::io::Error::from(error).into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplacedFile {
    path: crate::PrivatePath,
    identity: EntryIdentity,
}

/// Durable cleanup authority of one destination operation. Written before
/// any publication side effect, so a crash on either side of the commit
/// transaction can still find exactly what this operation may remove.
///
/// ```text
///  return commit ──► Replaced{dir, files} ──committed──► files removed ─┐
///  create commit ──► Created{dir}         ──aborted────► dir+scope gone ├► Retired
///                                          ──committed──► kept ─────────┘
/// ```
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum CleanupAuthority {
    /// A direct return replaces these prior-owner files of this directory.
    Replaced {
        machine: MachineId,
        directory: EntryIdentity,
        files: Vec<ReplacedFile>,
    },
    /// A creating commit may leave this directory and an SSH scope behind.
    Created {
        machine: MachineId,
        directory: EntryIdentity,
    },
    /// Cleanup finished; replays change nothing.
    Retired { machine: MachineId },
}

impl CleanupAuthority {
    fn machine(&self) -> MachineId {
        match self {
            Self::Replaced { machine, .. }
            | Self::Created { machine, .. }
            | Self::Retired { machine } => *machine,
        }
    }

    fn store(&self, files: &OperationFiles) -> Result<(), LibVmError> {
        files.store_cleanup(&serde_json::to_vec(self).map_err(invalid)?)
    }

    /// This operation's authority for `machine`, if any was recorded.
    fn load(files: &OperationFiles, machine: MachineId) -> Result<Option<Self>, LibVmError> {
        let Some(bytes) = files.load_cleanup()? else {
            return Ok(None);
        };
        let authority: Self = serde_json::from_slice(&bytes).map_err(invalid)?;
        if authority.machine() != machine {
            return Err(invalid("handoff cleanup record names another machine"));
        }
        Ok(Some(authority))
    }

    /// Bind the prior owner's files that `current` no longer selects.
    fn replaced(
        machine: MachineId,
        directory: &OwnedDirectory,
        previous: &MachineStorageRecord,
        current: &MachineStorageRecord,
    ) -> Result<Self, LibVmError> {
        let keep = private_names(current);
        let mut files = Vec::new();
        for path in private_names(previous) {
            if keep.contains(&path) {
                continue;
            }
            if let Some((parent, name)) = private_parent(directory, &path)? {
                if let Some(identity) = EntryIdentity::entry(&parent, &name)? {
                    files.push(ReplacedFile { path, identity });
                }
            }
        }
        Ok(Self::Replaced {
            machine,
            directory: EntryIdentity::directory(directory)?,
            files,
        })
    }
}

fn private_names(storage: &MachineStorageRecord) -> Vec<crate::PrivatePath> {
    writable_files(storage)
        .into_iter()
        .map(|(_, path, _)| path)
        .collect()
}

/// The existing directory holding `path`'s final component, and that name.
fn private_parent(
    directory: &OwnedDirectory,
    path: &crate::PrivatePath,
) -> Result<Option<(OwnedDirectory, String)>, LibVmError> {
    let mut names = path
        .as_path()
        .iter()
        .map(|part| {
            part.to_str()
                .ok_or_else(|| invalid("private path is not UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some(last) = names.pop() else {
        return Ok(None);
    };
    let mut parent = directory.try_clone()?;
    for name in names {
        match parent.open_dir(name)? {
            Some(next) => parent = next,
            None => return Ok(None),
        }
    }
    Ok(Some((parent, last.to_owned())))
}

/// Idempotent cleanup after a terminal decision, rerun by every replay.
async fn clean_terminal(
    runtime: &Runtime,
    store: &Store,
    receipt: &TerminalReceipt,
) -> Result<(), LibVmError> {
    let intent = &receipt.intent;
    match receipt.decision {
        HandoffDecision::Committed => {
            retire_replaced(runtime, intent.operation, intent.destination_machine).await
        }
        HandoffDecision::Aborted => match &receipt.binding {
            Some(binding) => {
                discard_aborted(
                    runtime,
                    store,
                    intent.operation,
                    intent.destination_machine,
                    binding.capture,
                )
                .await
            }
            // Nothing was offered, so nothing was prepared or published.
            None => Ok(()),
        },
    }
}

/// Remove the replaced files the current catalog record no longer selects,
/// only while the directory and each file keep their recorded identity.
async fn retire_replaced(
    runtime: &Runtime,
    operation: OperationId,
    machine: MachineId,
) -> Result<(), LibVmError> {
    let Some(files) = OperationFiles::open(runtime.local_home(), operation)? else {
        return Ok(());
    };
    let replaced = match CleanupAuthority::load(&files, machine)? {
        None | Some(CleanupAuthority::Retired { .. }) => return Ok(()),
        // A committed creation owns everything it created.
        Some(CleanupAuthority::Created { .. }) => None,
        Some(CleanupAuthority::Replaced {
            directory, files, ..
        }) => Some((directory, files)),
    };
    if let (Some((identity, replaced)), Some(_)) =
        (replaced, runtime.machine_config(machine).await?)
    {
        let keep = private_names(&runtime.machine_storage_record(machine).await?);
        let path = crate::paths::machine_data_dir_in(runtime.local_home(), machine);
        let directory = match OwnedDirectory::open_existing_root(&path)? {
            Some(directory) if EntryIdentity::directory(&directory)? == identity => Some(directory),
            // Absent or replaced: none of the recorded files can remain in it.
            _ => None,
        };
        if let Some(directory) = directory {
            for file in replaced.iter().filter(|file| !keep.contains(&file.path)) {
                if let Some((parent, name)) = private_parent(&directory, &file.path)? {
                    if EntryIdentity::entry(&parent, &name)? == Some(file.identity) {
                        parent.remove_tree(&name)?;
                        parent.sync()?;
                    }
                }
            }
        }
    }
    CleanupAuthority::Retired { machine }.store(&files)
}

/// Remove this operation's prepared files, then what a creating commit of
/// this operation left for a machine the catalog never published.
async fn discard_aborted(
    runtime: &Runtime,
    store: &Store,
    operation: OperationId,
    machine: MachineId,
    capture: CaptureId,
) -> Result<(), LibVmError> {
    let path = crate::paths::machine_data_dir_in(runtime.local_home(), machine);
    let directory = OwnedDirectory::open_existing_root(&path)?;
    if let Some(directory) = &directory {
        let prefix = prepared_prefix(capture);
        for entry in std::fs::read_dir(&path)? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str().filter(|name| name.starts_with(&prefix)) {
                directory.remove_tree(name)?;
            }
        }
        directory.sync()?;
    }
    let files = OperationFiles::open(runtime.local_home(), operation)?;
    let created = match &files {
        Some(files) => match CleanupAuthority::load(files, machine)? {
            Some(CleanupAuthority::Created { directory, .. }) => Some(directory),
            _ => None,
        },
        None => None,
    };
    let discarded = match (directory, created) {
        // The directory this operation's commit recorded: remove it and the
        // SSH scope that commit may have created.
        (Some(directory), Some(identity)) if EntryIdentity::directory(&directory)? == identity => {
            store
                .discard_unpublished_handoff_machine(operation, machine, || {
                    delete_scope(runtime, machine)?;
                    remove_machine_directory(&path, machine, &directory)
                })
                .await?
        }
        // Another directory now occupies the path; it is not ours to remove.
        (Some(_), Some(_)) => false,
        // Already removed by an earlier replay; the scope may remain.
        (None, Some(_)) => {
            store
                .discard_unpublished_handoff_machine(operation, machine, || {
                    delete_scope(runtime, machine)
                })
                .await?
        }
        // No commit started: only a directory prepare left empty goes.
        (Some(directory), None) => {
            if prepared_scaffold_only(&path)? {
                store
                    .discard_unpublished_handoff_machine(operation, machine, || {
                        remove_machine_directory(&path, machine, &directory)
                    })
                    .await?;
            }
            false
        }
        (None, None) => false,
    };
    if let (true, Some(files)) = (discarded, &files) {
        CleanupAuthority::Retired { machine }.store(files)?;
    }
    Ok(())
}

/// Whether the machine directory holds nothing but prepare's scaffolding.
fn prepared_scaffold_only(path: &std::path::Path) -> Result<bool, LibVmError> {
    for entry in std::fs::read_dir(path)? {
        if entry?.file_name() != "captures" {
            return Ok(false);
        }
    }
    Ok(true)
}

fn delete_scope(runtime: &Runtime, machine: MachineId) -> Result<(), LibVmError> {
    crate::ssh_ca::delete_scope(runtime.secret_store(), machine).map_err(std::io::Error::other)?;
    Ok(())
}

/// Remove exactly the held machine directory, verified against its entry.
fn remove_machine_directory(
    path: &std::path::Path,
    machine: MachineId,
    directory: &OwnedDirectory,
) -> Result<(), LibVmError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("machine directory has no parent"))?;
    let Some(parent) = OwnedDirectory::open_existing_root(parent)? else {
        return Ok(());
    };
    parent.remove_open_tree(&machine.to_string(), directory)?;
    parent.sync()
}

/// Durable abort, or the committed receipt if commit won, then the cleanup
/// that decision requires. Replays repeat the cleanup idempotently.
pub(crate) async fn abort(
    runtime: &Runtime,
    store: &Store,
    intent: &HandoffIntent,
) -> Result<TerminalReceipt, LibVmError> {
    let receipt = store.abort_handoff_destination(intent).await?;
    clean_terminal(runtime, store, &receipt).await?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use crate::handoff::destination::{admit_space, data_bytes, SpaceDemand};
    use crate::storage::limits::CHUNK_SIZE;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn space_admission_counts_every_simultaneous_copy() {
        let chunk = CHUNK_SIZE as u64;
        let writable = SpaceDemand {
            writable: 64 * MIB,
            ..SpaceDemand::default()
        };
        // Pinned received chunks and the private copy coexist, plus one
        // staged payload being copied into the pool.
        assert_eq!(writable.required(), 128 * MIB + chunk);
        // One copy of the disk fits; the concurrent copies do not.
        assert!(admit_space(writable.required(), 96 * MIB).is_err());
        admit_space(writable.required(), 128 * MIB + chunk).unwrap();
        assert!(admit_space(writable.required(), 128 * MIB + chunk - 1).is_err());

        // A missing stream keeps its chunks, its sparse staged rebuild and
        // its pool copy; a missing object is staged then copied once.
        let cold = SpaceDemand {
            writable: 64 * MIB,
            missing_streams: 32 * MIB,
            missing_objects: 40 * MIB,
            largest_object: 24 * MIB,
        };
        assert_eq!(cold.required(), 128 * MIB + 96 * MIB + 40 * MIB + 24 * MIB);
        let saturated = SpaceDemand {
            writable: u64::MAX,
            ..SpaceDemand::default()
        };
        assert_eq!(saturated.required(), u64::MAX);
    }

    #[test]
    fn sparse_private_outputs_charge_only_nonzero_chunks() {
        let chunk = CHUNK_SIZE;
        let mut bytes = vec![0u8; chunk * 3 + 4096];
        bytes[chunk + 7] = 1;
        bytes[chunk * 3 + 1] = 2;
        let map = crate::storage::stream::StreamHasher::new()
            .hash_reader(&bytes[..])
            .unwrap();
        assert_eq!(map.length(), bytes.len() as u64);
        assert_eq!(data_bytes(&map), CHUNK_SIZE as u64 + 4096);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn collected_reuse_candidate_becomes_a_need_and_is_never_cached() {
        use std::io::Write;

        use crate::handoff::destination::{DestinationState, Local};
        use crate::handoff::files::OperationFiles;
        use crate::handoff::plan::PayloadDescriptor;
        use crate::handoff::tests::{approve, operation, participant, request};
        use crate::handoff::types::HandoffMode;
        use crate::storage::pool::StoragePool;

        let a = participant().await;
        let b = participant().await;
        let machine = a.create_raw("collected").await;
        let op = operation();
        let plan = approve(&a, &b, machine, &request(op, HandoffMode::Relocate)).await;
        a.service.begin_source(&plan).await.unwrap();
        b.service.receive(&plan).await.unwrap();
        let store = b.runtime.native_store().unwrap();
        let pool = StoragePool::open(b.runtime.local_images_dir()).unwrap();
        let files = OperationFiles::existing(b.runtime.local_home(), op).unwrap();
        let bytes = b"chunk an earlier operation left unrooted";
        let publish = || {
            let mut source = tempfile::NamedTempFile::new().unwrap();
            source.write_all(bytes).unwrap();
            let (published, _roots) = pool.publish_object_for_catalog(source.path()).unwrap();
            published.digest
        };
        let digest = publish();
        let descriptor = PayloadDescriptor::Chunk {
            digest,
            length: bytes.len() as u64,
        };
        let mut state = DestinationState::load(&b.runtime, op).await.unwrap();
        let Local::Candidate(candidate) = state.local(&pool, &files, &descriptor).unwrap() else {
            panic!("a verified unpinned object must only be a candidate");
        };
        // Collection removes the object between verification and pinning.
        {
            let _roots = pool.lock_roots().unwrap();
            pool.remove_object(&digest).unwrap();
        }
        let vanished = state
            .retain(&pool, &store, op, vec![(descriptor, candidate)])
            .await
            .unwrap();
        assert_eq!(vanished, vec![descriptor]);
        assert!(!state.verified.contains(&digest));
        assert!(!store.handoff_pins_object(op, &digest).await.unwrap());
        assert!(matches!(
            state.local(&pool, &files, &descriptor).unwrap(),
            Local::Missing
        ));

        // Present again, the object is pinned under roots before it counts.
        assert_eq!(publish(), digest);
        let Local::Candidate(candidate) = state.local(&pool, &files, &descriptor).unwrap() else {
            panic!("a republished object must be verified again");
        };
        let vanished = state
            .retain(&pool, &store, op, vec![(descriptor, candidate)])
            .await
            .unwrap();
        assert!(vanished.is_empty());
        assert!(state.verified.contains(&digest));
        assert!(store.handoff_pins_object(op, &digest).await.unwrap());
        assert!(matches!(
            state.local(&pool, &files, &descriptor).unwrap(),
            Local::Satisfied
        ));
    }
}
