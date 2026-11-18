//! Immutable snapshot records and their names. A record exists until it is
//! removed; `snapshot_name` tags are independent of the image name table.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::paths::OwnedDirectory;
use crate::storage::identity::{ObjectDigest, SnapshotId, StreamId};
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
use crate::storage::stream::AuthenticatedStream;
use crate::store::models::snapshot::{invalid, SnapshotRecord, SnapshotStream};
use crate::store::Store;
use crate::LibVmError;

/// A snapshot by name or id. A name is a local name, a canonical registry
/// reference it was pulled as, or a unique id prefix of at least 3 hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum SnapshotRef {
    Name(String),
    Id(SnapshotId),
}
impl FromStr for SnapshotRef {
    type Err = LibVmError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.starts_with("fork:") {
            return Err(LibVmError::InvalidName {
                name: value.to_owned(),
                reason: "a local fork cut is not a snapshot; snapshot the child first",
            });
        }
        Ok(match crate::store::names::parse_reference(value)? {
            crate::store::names::Spelling::Id(id) => {
                Self::Id(SnapshotId::from_sha256(*id.as_bytes()))
            }
            crate::store::names::Spelling::Name(name) => Self::Name(name),
        })
    }
}
impl fmt::Display for SnapshotRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "{id}"),
            Self::Name(name) => f.write_str(name),
        }
    }
}

/// Whether a snapshot includes the machine's memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotMemory {
    /// Disks only; restore gives a stopped machine that boots normally.
    None,
    /// RAM, CPU and device state too; restore resumes a running machine.
    Included,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotCaptureProvenance {
    pub capture_id: Uuid,
    pub machine_id: Uuid,
    pub run_id: Uuid,
    pub evidence_digest: ObjectDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotInfo {
    pub id: SnapshotId,
    pub record_digest: ObjectDigest,
    pub memory: SnapshotMemory,
    pub provenance: Vec<SnapshotCaptureProvenance>,
    pub names: Vec<String>,
    pub created_at: i64,
    pub streams: Vec<SnapshotStreamSummary>,
}

/// What one `remove` call deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotRemoval {
    pub id: SnapshotId,
    /// Names removed by this call.
    pub names: Vec<String>,
    /// Whether the record itself was deleted. Its bytes are collected once
    /// no machine, operation or other record references them.
    pub record_removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotStreamSummary {
    pub role: SnapshotVerificationRole,
    pub stream: StreamId,
    pub map: ObjectDigest,
    pub length: u64,
    pub chunk_size: u64,
}

fn stream_summaries(record: &SnapshotRecord) -> Vec<SnapshotStreamSummary> {
    let mut result = Vec::new();
    let mut push = |role, content: &SnapshotStream| {
        result.push(SnapshotStreamSummary {
            role,
            stream: content.stream,
            map: content.map,
            length: content.length,
            chunk_size: content.chunk_size,
        })
    };
    if let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
        &record.memory
    {
        push(SnapshotVerificationRole::Ram, &execution.memory);
    }
    push(SnapshotVerificationRole::RootDisk, &record.root.stream);
    for disk in &record.disks {
        push(
            SnapshotVerificationRole::DataDisk { order: disk.order },
            &disk.content,
        );
    }
    if let Some(lower) = record.lower() {
        for layer in &lower.layers {
            push(SnapshotVerificationRole::Dependency, &layer.pack);
        }
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotVerificationReport {
    pub snapshot: SnapshotId,
    pub streams: u64,
    /// Unique logical bytes verified, including holes, state and metadata.
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotVerificationRole {
    Ram,
    Layout,
    Execution,
    Devices,
    RootDisk,
    DataDisk { order: u32 },
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotVerificationMember {
    Stream(StreamId),
    Object(ObjectDigest),
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotStructuralFailure {
    #[error("missing member")]
    Missing,
    #[error("truncated member: expected {expected} bytes, actual {actual}")]
    Truncated { expected: u64, actual: u64 },
    #[error("length mismatch: expected {expected} bytes, actual {actual}")]
    Length { expected: u64, actual: u64 },
    #[error("writable member (mode {mode:o})")]
    Writable { mode: u32 },
    #[error("member replaced or modified during verification")]
    Replaced,
    #[error("invalid member: {message}")]
    Invalid { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotVerificationError {
    #[error("{role:?} {member:?}: {failure}")]
    Structural {
        role: SnapshotVerificationRole,
        member: SnapshotVerificationMember,
        failure: SnapshotStructuralFailure,
    },
    #[error("{role:?} stream {stream} chunk {index} bytes {start}..{end}: expected {expected:?}, actual {actual:?}")]
    ChunkMismatch {
        role: SnapshotVerificationRole,
        stream: StreamId,
        index: u64,
        start: u64,
        end: u64,
        chunk_size: u64,
        expected: Box<vm_spec::stream_map::Chunk>,
        actual: Box<vm_spec::stream_map::Chunk>,
    },
    #[error(transparent)]
    MapNode(Box<SnapshotMapNodeFailure>),
    #[error("{role:?} object {object} ({length} bytes): expected {object}, actual {actual}")]
    ObjectMismatch {
        role: SnapshotVerificationRole,
        object: ObjectDigest,
        length: u64,
        actual: ObjectDigest,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("{role:?} stream {stream} node {node} height {height} indices {first_index}..{end_index} bytes {start}..{end}: {failure}")]
pub struct SnapshotMapNodeFailure {
    pub role: SnapshotVerificationRole,
    pub stream: StreamId,
    pub node: ObjectDigest,
    pub height: u8,
    pub first_index: u64,
    pub end_index: u64,
    pub start: u64,
    pub end: u64,
    pub failure: SnapshotStructuralFailure,
}

/// A captured snapshot is kept even when its optional requested name loses a race.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CaptureNamingOutcome {
    NameConflict { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureReservationRequest {
    pub machine_id: crate::store::models::MachineId,
    pub run_id: Uuid,
    pub capture_id: Uuid,
    pub configuration: vm_spec::capture::CaptureConfiguration,
    pub name: Option<String>,
    pub policy: vm_spec::lifecycle::CapturePolicy,
    pub dirty_crossover_percent: u8,
    pub resume_policy: vm_spec::lifecycle::CaptureResumePolicy,
    pub pause: vm_spec::capture::CapturePauseAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum CaptureState {
    Reserved,
    Sealed,
    Published { snapshot: SnapshotId },
    Released { snapshot: Option<SnapshotId> },
    Local { cut: Uuid },
    ReleasedLocal { cut: Uuid },
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum CaptureSourceOutcome {
    Known {
        record: vm_spec::capture::CaptureSourceRecord,
    },
    Unknown,
    Observed {
        continuation: vm_spec::capture::CaptureContinuation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureSpaceCharge {
    pub device: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureRecord {
    pub capture_id: Uuid,
    pub fork_operation_id: Option<Uuid>,
    pub machine_id: crate::store::models::MachineId,
    pub run_id: Uuid,
    pub launch_operation_id: Uuid,
    pub name: Option<String>,
    pub request: CaptureReservationRequest,
    pub plan: vm_spec::capture::CapturePlan,
    pub state: CaptureState,
    pub source_outcome: Option<CaptureSourceOutcome>,
    pub naming_outcome: Option<CaptureNamingOutcome>,
    pub configuration: crate::machine::stopped::SnapshotConfiguration,
    pub storage: crate::MachineStorageRecord,
    pub disk_charges: Vec<CaptureSpaceCharge>,
    pub publication_clones: BTreeSet<String>,
    /// Allocated bytes sampled from each writable source, keyed by attachment index.
    pub disk_allocations: BTreeMap<u32, u64>,
    pub reservation_bytes: u64,
    pub candidate: Option<SnapshotId>,
    pub captured_boot: Option<crate::BootProfile>,
    pub source_inodes: Vec<(u64, u64)>,
    pub evidence: Option<String>,
    pub discard: Option<CaptureDiscard>,
    pub dispatch_attempted: bool,
}

impl CaptureRecord {
    pub(crate) fn never_submitted(
        &self,
        result: Option<&vm_spec::lifecycle::LiveCommandResult>,
    ) -> bool {
        match result {
            Some(vm_spec::lifecycle::LiveCommandResult::Capture(
                vm_spec::lifecycle::CaptureOutcome::Rejected { .. },
            )) => true,
            None => !self.dispatch_attempted,
            Some(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureDiscard {
    pub parent: Option<(u64, u64)>,
    pub directory: Option<(u64, u64)>,
}

pub(crate) struct CaptureReservation {
    pub record: CaptureRecord,
    pub(crate) _lease: StorageLock,
}

#[derive(Clone)]
pub(crate) struct SnapshotStore {
    pub(crate) store: Arc<Store>,
}

pub(crate) struct SnapshotConsumer {
    pub info: SnapshotInfo,
    pub record: SnapshotRecord,
    pub operation_id: Uuid,
    closure: Option<AuthenticatedClosure>,
    imported: Vec<crate::store::artifact_store::ImportedCaptureRef>,
    pub lease: StorageLock,
    // A consumer outlives its collection handle and retains the same writable
    // catalog capability through actual blocking reads/copy/publication.
    _store: Arc<Store>,
}

/// The exact stream inodes `consume` hashed, held until its inputs are open.
/// A held descriptor pins its device/inode pair, so a fresh descriptor
/// with an equal fingerprint is that authenticated inode with unchanged bytes.
/// Restore uses this instead of opening and hashing the same members again.
pub(crate) struct AuthenticatedClosure {
    pub(crate) streams: BTreeMap<StreamId, AuthenticatedStream>,
}

impl SnapshotConsumer {
    pub(crate) fn imported_provenance(
        &self,
    ) -> &[crate::store::artifact_store::ImportedCaptureRef] {
        &self.imported
    }
    /// The held authenticated stream itself, rechecked against its hashed state.
    pub(crate) fn authenticated_stream(
        &self,
        stream: &StreamId,
        length: u64,
    ) -> Result<&AuthenticatedStream, LibVmError> {
        let held = self
            .closure()?
            .streams
            .get(stream)
            .ok_or_else(|| invalid("stream is outside the authenticated snapshot closure"))?;
        if held.length() != length {
            return Err(invalid(
                "authenticated snapshot stream geometry differs from its use",
            ));
        }
        bind_held(held.file(), held.fingerprint())?;
        Ok(held)
    }

    /// An independent open-file description of one authenticated stream, so
    /// sparse-copy extent seeks and native readers never share file offsets.
    /// Its fingerprint equals the held authenticated one when returned.
    pub(crate) fn open_stream(
        &self,
        pool: &StoragePool,
        stream: &StreamId,
        length: u64,
    ) -> Result<File, LibVmError> {
        let held = self.authenticated_stream(stream, length)?;
        let file = pool.open_stream(stream)?;
        bind_reopened(&file, held.fingerprint())?;
        Ok(file)
    }

    /// Retain the exact authenticated map with an independent source OFD.
    /// The map is shared without copying its chunk vector.
    pub(crate) fn open_copy_source(
        &self,
        pool: &StoragePool,
        stream: &StreamId,
        length: u64,
    ) -> Result<AuthenticatedStream, LibVmError> {
        let held = self.authenticated_stream(stream, length)?;
        Ok(held.reopen(pool.open_stream(stream)?)?)
    }

    /// Descriptors currently held for closure reuse, beyond the lease.
    pub(crate) fn retained_descriptors(&self) -> u64 {
        self.closure
            .as_ref()
            .map_or(0, |closure| closure.streams.len() as u64)
    }

    /// Close the held closure once every input has been opened. Reopened
    /// descriptors keep their own inodes; the lease keeps the closure pinned.
    /// Later reuse fails closed instead of reopening unauthenticated members.
    pub(crate) fn release_closure(&mut self) {
        self.closure = None;
    }

    fn closure(&self) -> Result<&AuthenticatedClosure, LibVmError> {
        self.closure
            .as_ref()
            .ok_or_else(|| invalid("authenticated snapshot closure handles were released"))
    }
}

pub(crate) fn bind_held(held: &File, fingerprint: SourceFingerprint) -> Result<(), LibVmError> {
    if SourceFingerprint::new(&held.metadata()?) != fingerprint {
        return Err(invalid(
            "authenticated snapshot closure member was modified",
        ));
    }
    Ok(())
}

pub(crate) fn bind_reopened(
    reopened: &File,
    fingerprint: SourceFingerprint,
) -> Result<(), LibVmError> {
    if SourceFingerprint::new(&reopened.metadata()?) != fingerprint {
        return Err(invalid(
            "authenticated snapshot closure member was replaced or modified",
        ));
    }
    Ok(())
}

/// Closure members whose descriptors a consumer holds. Live restore transfers
/// the small RAM root header as an FD; all other map roots and every descendant
/// remain lazy operation-owned metadata, not copy-input descriptors.
fn retained_members(
    record: &SnapshotRecord,
) -> Result<(BTreeSet<StreamId>, BTreeSet<ObjectDigest>), LibVmError> {
    let (streams, mut objects) = record.content_dependencies()?;
    for stream in record.streams() {
        objects.remove(&stream.map);
    }
    if let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
        &record.memory
    {
        objects.insert(execution.memory.map);
    }
    Ok((streams, objects))
}

impl SnapshotStore {
    pub(crate) fn from_store(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub(crate) async fn inspect(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotInfo, LibVmError> {
        let (_, info) = self.load_observed(reference).await?;
        Ok(info)
    }

    /// Pin a reference once and unconditionally reread its closure. Warm local
    /// receipts and producer capabilities are never verification authority.
    pub(crate) async fn verify(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotVerificationReport, LibVmError> {
        let snapshots = self.clone();
        let reference = reference.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let consumer =
                runtime.block_on(snapshots.consume_selected(&reference, false, false, false))?;
            let result = verify_snapshot_bytes(&snapshots, &consumer);
            let cleanup = runtime.block_on(
                snapshots
                    .store
                    .finish_stopped_operation(consumer.operation_id),
            );
            drop(consumer);
            match (result, cleanup) {
                (Err(primary), Err(cleanup)) => Err(LibVmError::MachineStartCleanupFailed {
                    primary: primary.to_string(),
                    cleanup: cleanup.to_string(),
                }),
                (Err(error), _) | (_, Err(error)) => Err(error),
                (Ok(report), Ok(())) => Ok(report),
            }
        })
        .await?
    }

    pub(crate) async fn list(&self) -> Result<Vec<SnapshotInfo>, LibVmError> {
        // Each discovery page is bounded. Immutable IDs provide a stable cursor;
        // concurrent removal can only omit an entry, never fabricate a record.
        let mut cursor = String::new();
        let mut snapshots = Vec::new();
        loop {
            let ids = sqlx::query_scalar::<_, String>(
                "SELECT id FROM storage_snapshot WHERE id>?1 ORDER BY id LIMIT 256",
            )
            .bind(&cursor)
            .fetch_all(&self.store.pool)
            .await?;
            if ids.is_empty() {
                break;
            }
            for id in ids {
                cursor = id.clone();
                let mut tx = self.store.pool.begin().await?;
                let id: SnapshotId = id.parse().map_err(invalid)?;
                let observed = if exists(&mut tx, id).await? {
                    Some(fetch_catalog(&mut tx, &SnapshotRef::Id(id)).await?)
                } else {
                    None
                };
                tx.commit().await?;
                if let Some(facts) = observed {
                    let (_, info) = authenticate_catalog(facts)?;
                    snapshots.push(info);
                }
            }
        }
        Ok(snapshots)
    }

    /// Docker tag semantics. A name removes that name, and the record once no
    /// name remains; an id (or id prefix) removes the record and all its
    /// names. Machines never depend on the record: bytes are collected only
    /// once nothing else references them.
    pub(crate) async fn remove(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotRemoval, LibVmError> {
        let pool = StoragePool::open(&self.store.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let named = match reference {
            SnapshotRef::Name(name) => named_snapshot(&mut tx, name).await?,
            SnapshotRef::Id(_) => None,
        };
        let removal = match named {
            Some(id) => {
                let SnapshotRef::Name(name) = reference else {
                    return Err(invalid("named removal lost its name"));
                };
                let remaining: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM snapshot_name WHERE snapshot_id=?1 AND name!=?2",
                )
                .bind(id.to_string())
                .bind(name)
                .fetch_one(&mut *tx)
                .await?;
                if remaining == 0 {
                    refuse_in_use(&mut tx, id, reference).await?;
                }
                sqlx::query("DELETE FROM snapshot_name WHERE name=?1")
                    .bind(name)
                    .execute(&mut *tx)
                    .await?;
                if remaining == 0 {
                    delete_record(&mut tx, id).await?;
                }
                SnapshotRemoval {
                    id,
                    names: vec![name.clone()],
                    record_removed: remaining == 0,
                }
            }
            None => {
                let id = resolve_snapshot(&mut tx, reference).await?;
                refuse_in_use(&mut tx, id, reference).await?;
                let names = sqlx::query_scalar::<_, String>(
                    "SELECT name FROM snapshot_name WHERE snapshot_id=?1 ORDER BY name",
                )
                .bind(id.to_string())
                .fetch_all(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM snapshot_name WHERE snapshot_id=?1")
                    .bind(id.to_string())
                    .execute(&mut *tx)
                    .await?;
                delete_record(&mut tx, id).await?;
                SnapshotRemoval {
                    id,
                    names,
                    record_removed: true,
                }
            }
        };
        tx.commit().await?;
        Ok(removal)
    }

    /// Called by the stopped blocking owner while it holds the original
    /// operation OFD. All slow authentication is outside roots/transactions.
    pub(crate) async fn publish(
        &self,
        record: &SnapshotRecord,
        operation_id: Uuid,
        name: Option<&str>,
    ) -> Result<SnapshotInfo, LibVmError> {
        self.publish_authenticated(
            record,
            operation_id,
            name,
            None,
            crate::storage::pool::PublicationLockPolicy::Wait,
        )
        .await
    }

    pub(crate) async fn publish_authenticated(
        &self,
        record: &SnapshotRecord,
        operation_id: Uuid,
        name: Option<&str>,
        inputs: Option<&crate::store::capture::VerifiedCapture>,
        lock_policy: crate::storage::pool::PublicationLockPolicy,
    ) -> Result<SnapshotInfo, LibVmError> {
        if matches!(
            record.memory,
            crate::store::models::snapshot::SnapshotMemoryState::Included { .. }
        ) != inputs.is_some()
        {
            return Err(invalid(
                "execution publication requires its retained capture verification owner",
            ));
        }
        if let Some(name) = name {
            crate::store::names::validate_name(name)?;
        }
        let bytes = record.canonical_bytes()?;
        let id = crate::store::models::snapshot::snapshot_id(&bytes);
        let digest = ObjectDigest::of_bytes(&bytes);
        let (streams, mut objects) = record.content_dependencies()?;
        objects.insert(digest);
        let pool =
            StoragePool::open(&self.store.images_dir)?.with_publication_lock_policy(lock_policy);
        let pool = if inputs.is_some() {
            pool.defer_publications()
        } else {
            pool
        };
        let capture = if matches!(
            record.memory,
            crate::store::models::snapshot::SnapshotMemoryState::Included { .. }
        ) {
            let capture = self
                .capture_reservation(operation_id)
                .await?
                .ok_or_else(|| invalid("execution snapshot has no capture owner"))?;
            let evidence = capture
                .evidence
                .as_deref()
                .map(str::as_bytes)
                .ok_or_else(|| invalid("execution snapshot has no authenticated seal"))?;
            let digest = ObjectDigest::of_bytes(evidence);
            require_operation_closure(
                &self.store,
                operation_id,
                &BTreeSet::new(),
                &BTreeSet::from([digest]),
                None,
            )
            .await?;
            pool.verify_object(&digest)?;
            if pool.read_object(&digest, vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64)?
                != evidence
            {
                return Err(invalid("capture provenance bytes changed"));
            }
            Some((digest, evidence.to_vec()))
        } else {
            None
        };
        // The record itself is new output, all other dependencies must already
        // be operation-pinned before opening their bytes.
        require_operation_closure(&self.store, operation_id, &streams, &objects, Some(digest))
            .await?;
        let mut fingerprints = match inputs {
            Some(inputs) => {
                verify_publication_closure(
                    &self.store,
                    &pool,
                    record,
                    inputs.publications(),
                    operation_id,
                )
                .await?
            }
            None => {
                verify_closure(
                    &pool,
                    record,
                    None,
                    false,
                    Arc::new(pool.existing_lease(operation_id)?),
                )?
                .0
            }
        };
        let input = RecordInput::new(&self.store.images_dir, operation_id, &bytes)?;
        let (published, roots) = pool.publish_object_for_catalog(&input.path())?;
        if published.digest != digest {
            return Err(invalid("published snapshot record digest mismatch"));
        }
        self.store
            .pin_published_storage_dependencies(operation_id, &[], &[digest])
            .await?;
        fingerprints.push((published.path.clone(), published.fingerprint));
        drop(roots);
        // Before a possibly uncertain SQL commit, persist its exact result ID.
        if capture.is_some() {
            self.update_capture(operation_id, move |capture| {
                if capture.candidate.is_some_and(|candidate| candidate != id) {
                    return Err(invalid("capture publication candidate changed"));
                }
                capture.candidate = Some(id);
                Ok(())
            })
            .await?;
        } else {
            self.store
                .preserve_snapshot_operation(operation_id, id)
                .await?;
        }
        let mut authenticated_objects = BTreeMap::new();
        for object in &objects {
            let path = pool.object_path(object);
            let fingerprint = fingerprints
                .iter()
                .find(|(member, _)| *member == path)
                .map(|(_, fingerprint)| *fingerprint)
                .ok_or_else(|| invalid("authenticated publication object has no fingerprint"))?;
            authenticated_objects.insert(*object, fingerprint);
        }
        if let Some((digest, _)) = &capture {
            let held = pool.open_object(digest)?;
            let fingerprint = SourceFingerprint::new(&held.metadata()?);
            let file = pool.verify_object(digest)?;
            bind_held(&file, fingerprint)?;
            bind_held(&held, fingerprint)?;
            authenticated_objects.insert(*digest, fingerprint);
            fingerprints.push((pool.object_path(digest), fingerprint));
        }
        let mut map_receipts = BTreeMap::new();
        if let Some(inputs) = inputs {
            for (stream, publication) in inputs.publications() {
                let content = record
                    .streams()
                    .find(|content| content.stream == *stream)
                    .ok_or_else(|| invalid("publication stream is outside snapshot"))?;
                map_receipts.insert(
                    *stream,
                    map_validation(
                        &pool,
                        content,
                        publication.map(),
                        publication.fingerprint(),
                        &authenticated_objects,
                    )?,
                );
            }
        }
        if inputs.is_some() {
            pool.sync_publications()?;
        }
        let _roots = pool.lock_roots_shared()?;
        recheck_closure(&fingerprints)?;
        if let Some(inputs) = inputs {
            inputs.recheck_registered(&self.store, operation_id)?;
            for publication in inputs.publications().values() {
                publication.recheck(&pool)?;
            }
        }
        require_operation_closure(&self.store, operation_id, &streams, &objects, None).await?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let existing =
            sqlx::query("SELECT record_digest,record_bytes FROM storage_snapshot WHERE id=?1")
                .bind(id.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(row) = existing {
            if row.try_get::<String, _>("record_digest")? != digest.to_string()
                || row.try_get::<Vec<u8>, _>("record_bytes")? != bytes
            {
                return Err(invalid("immutable snapshot identity contradiction"));
            }
            exact_catalog_dependencies(&mut tx, id, &streams, &objects).await?;
        } else {
            sqlx::query("INSERT INTO storage_snapshot(id,record_digest,record_bytes,created_at) VALUES(?1,?2,?3,?4)")
                .bind(id.to_string()).bind(digest.to_string()).bind(&bytes).bind(chrono::Utc::now().timestamp()).execute(&mut *tx).await?;
            for stream in &streams {
                sqlx::query(
                    "INSERT INTO snapshot_stream_dependency(snapshot_id,stream_id) VALUES(?1,?2)",
                )
                .bind(id.to_string())
                .bind(stream.to_string())
                .execute(&mut *tx)
                .await?;
            }
            for object in &objects {
                sqlx::query("INSERT INTO snapshot_object_dependency(snapshot_id,object_digest) VALUES(?1,?2)")
                    .bind(id.to_string()).bind(object.to_string()).execute(&mut *tx).await?;
            }
        }
        if let Some(inputs) = inputs {
            for (stream, publication) in inputs.publications() {
                publication.recheck(&pool)?;
                let [dev, ino, len, mode, ctime_sec, ctime_nsec] =
                    publication.fingerprint().verification_key();
                let receipt = map_receipts
                    .get(stream)
                    .ok_or_else(|| invalid("publication map receipt is missing"))?;
                sqlx::query(
                    "INSERT INTO verified_object(stream_sha256,dev,ino,len,mode,ctime_sec,ctime_nsec,map_receipt,verified_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(stream_sha256) DO UPDATE SET dev=excluded.dev,ino=excluded.ino,len=excluded.len,mode=excluded.mode,ctime_sec=excluded.ctime_sec,ctime_nsec=excluded.ctime_nsec,map_receipt=excluded.map_receipt,verified_at=excluded.verified_at",
                )
                .bind(stream.to_string()).bind(dev).bind(ino).bind(len).bind(mode)
                .bind(ctime_sec).bind(ctime_nsec).bind(receipt).execute(&mut *tx).await?;
            }
        }
        let mut naming_outcome = None;
        if let Some(name) = name {
            match insert_name(&mut tx, name, id).await {
                Ok(()) => {}
                Err(LibVmError::SnapshotNameConflict { name }) if capture.is_some() => {
                    naming_outcome = Some(CaptureNamingOutcome::NameConflict { name });
                }
                Err(error) => return Err(error),
            }
        }
        if let Some((evidence_digest, evidence)) = capture {
            let json: String = sqlx::query_scalar("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'")
                .bind(operation_id.to_string()).fetch_one(&mut *tx).await?;
            let mut capture = crate::store::capture::decode_record(&json)?;
            let plan_bytes = capture.plan.canonical_bytes().map_err(invalid)?;
            authenticate_capture_plan(&plan_bytes, &evidence, operation_id)?;
            let capture_evidence =
                vm_spec::capture::CaptureEvidence::decode(&evidence).map_err(invalid)?;
            let changes = capture_evidence
                .memory
                .as_ref()
                .ok_or_else(|| invalid("live capture provenance has no RAM change evidence"))?
                .changes
                .sha256;
            let changes = ObjectDigest::from_sha256(*changes.as_bytes());
            let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_object WHERE operation_id=?1 AND object_digest=?2)")
                .bind(operation_id.to_string()).bind(changes.to_string()).fetch_one(&mut *tx).await?;
            if !pinned {
                return Err(invalid(
                    "RAM change provenance was not retained before snapshot publication",
                ));
            }
            sqlx::query("INSERT INTO snapshot_capture_change(snapshot_id,changes_digest) VALUES(?1,?2) ON CONFLICT DO NOTHING")
                .bind(id.to_string()).bind(changes.to_string()).execute(&mut *tx).await?;
            let existing = sqlx::query("SELECT snapshot_id,evidence_digest,CASE WHEN typeof(evidence_bytes)='blob' AND length(evidence_bytes)<=?2 THEN evidence_bytes END AS evidence_bytes,CASE WHEN typeof(plan_bytes)='blob' AND length(plan_bytes)<=?2 THEN plan_bytes END AS plan_bytes FROM snapshot_capture_provenance WHERE capture_id=?1")
                .bind(operation_id.to_string()).bind(vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as i64)
                .fetch_optional(&mut *tx).await?;
            if let Some(existing) = existing {
                if existing.try_get::<String, _>("snapshot_id")? != id.to_string()
                    || existing.try_get::<String, _>("evidence_digest")?
                        != evidence_digest.to_string()
                    || existing
                        .try_get::<Option<Vec<u8>>, _>("evidence_bytes")?
                        .as_deref()
                        != Some(evidence.as_slice())
                    || existing
                        .try_get::<Option<Vec<u8>>, _>("plan_bytes")?
                        .as_deref()
                        != Some(plan_bytes.as_slice())
                {
                    return Err(invalid("immutable capture provenance contradiction"));
                }
            } else {
                sqlx::query("INSERT INTO snapshot_capture_provenance(capture_id,snapshot_id,evidence_digest,evidence_bytes,plan_bytes) VALUES(?1,?2,?3,?4,?5)")
                    .bind(operation_id.to_string()).bind(id.to_string()).bind(evidence_digest.to_string()).bind(evidence).bind(&plan_bytes).execute(&mut *tx).await?;
            }
            if capture.candidate != Some(id) {
                return Err(invalid("capture candidate changed before commit"));
            }
            capture.naming_outcome = naming_outcome;
            capture.state = match capture.state {
                CaptureState::Sealed => CaptureState::Published { snapshot: id },
                CaptureState::Published { snapshot } if snapshot == id => capture.state,
                CaptureState::Released {
                    snapshot: Some(snapshot),
                } if snapshot == id => capture.state,
                _ => {
                    return Err(invalid(
                        "capture publication cannot regress its durable state",
                    ))
                }
            };
            crate::store::capture::write_record(&mut tx, &capture).await?;
        } else {
            sqlx::query("UPDATE storage_operation SET state='staging',record_json=jsonb('{}') WHERE operation_id=?1 AND kind='snapshot' AND state='committing'")
                .bind(operation_id.to_string()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        // Pool publication has synchronized the files. Make the retained
        // snapshot and its closure power-loss durable before acknowledging it.
        self.store.checkpoint_catalog().await?;
        drop(_roots);
        self.inspect(&SnapshotRef::Id(id)).await
    }

    /// Register a fresh consumer and its exact closure atomically with resolving
    /// the public root. Artifact reads occur only after this transaction commits.
    pub(crate) async fn consume(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotConsumer, LibVmError> {
        self.consume_selected(reference, false, true, true).await
    }

    pub(crate) async fn consume_disks(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotConsumer, LibVmError> {
        self.consume_selected(reference, true, true, true).await
    }

    /// Pin catalog authority and materialize evicted streams without authenticating
    /// the full closure or constructing children.
    pub(crate) async fn consume_shape(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotConsumer, LibVmError> {
        self.consume_selected(reference, false, false, true).await
    }

    #[cfg(test)]
    pub(crate) async fn verify_closure_shape(
        &self,
        consumer: &SnapshotConsumer,
    ) -> Result<ShapeVerifiedClosure, LibVmError> {
        self.verify_closure_shape_with(consumer, &BTreeSet::new())
            .await
    }

    /// Inspection only needs RAM and read-only lower maps. Writable maps are
    /// completed concurrently with the native inspection process, before copy.
    pub(crate) async fn prepare_restore_shape(
        &self,
        consumer: &SnapshotConsumer,
    ) -> Result<RestoreInspectionShape, LibVmError> {
        let mut deferred = BTreeSet::from([consumer.record.root.stream.stream]);
        deferred.extend(
            consumer
                .record
                .disks
                .iter()
                .filter(|disk| disk.writable)
                .map(|disk| disk.content.stream),
        );
        if let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
            &consumer.record.memory
        {
            deferred.remove(&execution.memory.stream);
        }
        if let Some(lower) = consumer.record.lower() {
            for layer in &lower.layers {
                deferred.remove(&layer.pack.stream);
            }
        }
        let shape = self.verify_closure_shape_with(consumer, &deferred).await?;
        Ok(RestoreInspectionShape { shape })
    }

    async fn verify_closure_shape_with(
        &self,
        consumer: &SnapshotConsumer,
        deferred_maps: &BTreeSet<StreamId>,
    ) -> Result<ShapeVerifiedClosure, LibVmError> {
        consumer.record.validate()?;
        let pool = StoragePool::open(&self.store.images_dir)?;
        let (_, mut objects) = consumer.record.content_dependencies()?;
        let (_, retained) = retained_members(&consumer.record)?;
        objects.extend(
            consumer
                .info
                .provenance
                .iter()
                .map(|entry| entry.evidence_digest),
        );
        crate::storage::limits::preflight_fd_budget(
            2 * (objects.len() + consumer.record.streams().count()) as u64
                + retained.len() as u64
                + consumer.record.streams().count() as u64
                + 4,
        )
        .map_err(crate::storage::StorageError::from)?;
        let ram = match &consumer.record.memory {
            crate::store::models::snapshot::SnapshotMemoryState::Included { execution } => {
                let capture = self.restore_evidence(consumer, &pool)?;
                if execution.layout != execution.compatibility_profile.ram_layout {
                    return Err(invalid("snapshot layout contradicts compatibility profile"));
                }
                for (role, digest) in [
                    (vm_spec::capture::CaptureRole::Layout, execution.layout),
                    (
                        vm_spec::capture::CaptureRole::Execution,
                        execution.execution,
                    ),
                    (vm_spec::capture::CaptureRole::Devices, execution.devices),
                ] {
                    let entry = capture
                        .evidence
                        .inventory
                        .iter()
                        .find(|entry| entry.role == role)
                        .ok_or_else(|| invalid("capture inventory omitted a state role"))?;
                    if entry.sha256.as_ref().map(|digest| digest.as_bytes())
                        != Some(digest.as_bytes())
                    {
                        return Err(invalid(
                            "snapshot state identity contradicts capture inventory",
                        ));
                    }
                    let file = pool.open_object(&digest)?;
                    if file.metadata()?.len() != entry.length {
                        return Err(invalid(
                            "snapshot state length contradicts capture inventory",
                        ));
                    }
                }
                Some(execution.memory.stream)
            }
            _ => None,
        };
        let held_lower =
            if let crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay {
                lower,
                lower_geometry,
                lower_filesystem_uuid,
                ..
            } = &consumer.record.root.profile
            {
                let layers =
                    crate::store::layer_store::LayerStore::from_store((*self.store).clone());
                layers
                    .publish_local_composition(consumer.operation_id, lower)
                    .await?;
                let held = layers
                    .hold_lower(&crate::OverlayLower::ErofsComposition {
                        record: lower.result,
                        geometry: *lower_geometry,
                        filesystem_uuid: *lower_filesystem_uuid,
                    })
                    .await?;
                if held.snapshot_composition() != lower.as_ref() {
                    return Err(invalid("held lower differs from snapshot graph"));
                }
                Some(held)
            } else {
                None
            };
        let pin: Arc<dyn Send + Sync> = Arc::new(consumer.lease.duplicate()?);
        let mut cached = BTreeMap::new();
        let mut deferred = deferred_maps.clone();
        if let Some(held) = &held_lower {
            deferred.extend(held.maps.keys().copied());
        }
        for content in consumer.record.streams() {
            if held_lower
                .as_ref()
                .is_some_and(|held| held.maps.contains_key(&content.stream))
            {
                continue;
            }
            if let Some(receipt) =
                load_map_validation(&self.store, &pool, content, Arc::clone(&pin)).await?
            {
                deferred.insert(content.stream);
                cached.insert(content.stream, receipt);
            }
        }
        let mut shape = verify_artifact_shape(
            &pool,
            &consumer.record.canonical_bytes()?,
            &consumer.record.streams().collect::<Vec<_>>(),
            objects,
            retained,
            Some(consumer.info.record_digest),
            true,
            ram,
            &deferred,
            pin,
        )?;
        for (stream, receipt) in cached {
            shape.apply_map_validation(&pool, stream, receipt)?;
        }
        if let Some(held) = &held_lower {
            for (digest, expected) in held.metadata_states() {
                if shape.object_states.get(&digest) != Some(&expected) {
                    return Err(invalid(
                        "held lower metadata changed during shape validation",
                    ));
                }
            }
            shape
                .maps
                .extend(held.maps.iter().map(|(id, map)| (*id, Arc::clone(map))));
        }
        shape.held_lower = held_lower;
        shape.local_lower = consumer.record.lower().cloned();
        recheck_closure(&shape.fingerprints)?;
        Ok(shape)
    }

    /// Local restore only. Transport callers use the unconditional full path.
    pub(crate) async fn authenticate_closure_bytes(
        &self,
        mut shape: ShapeVerifiedClosure,
    ) -> Result<AuthenticatedClosure, LibVmError> {
        let store = self.store.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let pool = StoragePool::open(&store.images_dir)?;
            let mut warm = runtime.block_on(async {
                let mut warm = BTreeMap::new();
                for stream in shape.maps.keys() {
                    let file = pool.open_stream(stream)?;
                    let fingerprint = SourceFingerprint::new(&file.metadata()?);
                    bind_hashed(&file, shape.stream_states.get(stream))?;
                    let [dev, ino, len, mode, ctime_sec, ctime_nsec] = fingerprint.verification_key();
                    if mode & 0o7777 != 0o400 {
                        continue;
                    }
                    let matches: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM verified_object WHERE stream_sha256=?1 AND dev=?2 AND ino=?3 AND len=?4 AND mode=?5 AND ctime_sec=?6 AND ctime_nsec=?7)",
                    )
                    .bind(stream.to_string()).bind(dev).bind(ino).bind(len).bind(mode)
                    .bind(ctime_sec).bind(ctime_nsec).fetch_one(&store.pool).await?;
                    if matches {
                        warm.insert(*stream, fingerprint);
                    }
                }
                Ok::<_, LibVmError>(warm)
            })?;
            if shape.held_lower.is_none() {
                if let Some(expected) = &shape.local_lower {
                    let layers = crate::store::layer_store::LayerStore::from_store((*store).clone());
                    let retained = runtime.block_on(layers.retained_composition(expected.result))?;
                    let held = runtime.block_on(layers.hold_lower(&retained.overlay_lower()))?;
                    if held.snapshot_composition() != expected {
                        return Err(invalid("held lower differs from snapshot graph"));
                    }
                    shape.held_lower = Some(held);
                }
            }
            if let Some(held) = &shape.held_lower {
                held.recheck()?;
                for (digest, expected) in held.metadata_states() {
                    if shape.object_states.get(&digest) != Some(&expected) {
                        return Err(invalid("held lower metadata differs from snapshot inode"));
                    }
                }
                let graph = held.snapshot_composition();
                for object in graph.objects().chain(graph.layers.iter().map(|layer| layer.pack.map)) {
                    shape.objects.remove(&object);
                }
                for layer in &graph.layers {
                    let (_, fingerprint) = held.held_backing(crate::storage::vmdk::LowerBacking::Stream(layer.pack.stream))?;
                    if shape.stream_states.get(&layer.pack.stream) != Some(&fingerprint) {
                        return Err(invalid("held lower pack differs from snapshot inode"));
                    }
                    warm.insert(layer.pack.stream, fingerprint);
                }
                let (_, fingerprint) = held.held_backing(crate::storage::vmdk::LowerBacking::Object(graph.fsmeta))?;
                if shape.object_states.get(&graph.fsmeta) != Some(&fingerprint) {
                    return Err(invalid("held lower fsmeta differs from snapshot inode"));
                }
            }
            let closure = shape.authenticate(&pool, Some(&warm))?;
            runtime.block_on(async {
                for (stream, authenticated) in &closure.streams {
                    if (shape.receipt_maps.contains(stream) && shape.objects.is_empty())
                        || shape.held_lower.as_ref().is_some_and(|lower| lower.maps.contains_key(stream)) {
                        continue;
                    }
                    bind_held(authenticated.file(), authenticated.fingerprint())?;
                    let [dev, ino, len, mode, ctime_sec, ctime_nsec] =
                        authenticated.fingerprint().verification_key();
                    let content = shape.contents.iter().find(|content| content.stream == *stream)
                        .ok_or_else(|| invalid("authenticated stream is outside snapshot shape"))?;
                    let receipt = map_validation(&pool, content, authenticated.map(), authenticated.fingerprint(), &shape.object_states)?;
                    sqlx::query(
                        "INSERT INTO verified_object(stream_sha256,dev,ino,len,mode,ctime_sec,ctime_nsec,map_receipt,verified_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(stream_sha256) DO UPDATE SET dev=excluded.dev,ino=excluded.ino,len=excluded.len,mode=excluded.mode,ctime_sec=excluded.ctime_sec,ctime_nsec=excluded.ctime_nsec,map_receipt=excluded.map_receipt,verified_at=excluded.verified_at",
                    )
                    .bind(stream.to_string()).bind(dev).bind(ino).bind(len).bind(mode)
                    .bind(ctime_sec).bind(ctime_nsec).bind(receipt).execute(&store.pool).await?;
                }
                Ok::<_, LibVmError>(())
            })?;
            Ok(closure)
        })
        .await?
    }

    async fn consume_selected(
        &self,
        reference: &SnapshotRef,
        disks_only: bool,
        authenticate: bool,
        materialize: bool,
    ) -> Result<SnapshotConsumer, LibVmError> {
        let store = self.store.clone();
        let (record, observed) = self.load_observed(reference).await?;
        let bytes = record.canonical_bytes()?;
        let (streams, mut objects) = record.content_dependencies()?;
        objects.insert(observed.record_digest);
        let reference = reference.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let pool = StoragePool::open(&store.images_dir)?;
            let id = Uuid::new_v4();
            let result: Result<SnapshotConsumer, LibVmError> = (|| {
                let (info, lease, imported) = runtime.block_on(async {
                    let _roots = pool.lock_roots()?;
                    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
                    recheck_catalog(&mut tx, &reference, &observed, &bytes, &streams, &objects)
                        .await?;
                    let mut info =
                        catalog_info(&mut tx, observed.id, observed.record_digest).await?;
                    info.provenance = observed.provenance.clone();
                    let mut pinned_objects = objects.clone();
                    pinned_objects.extend(
                        info.provenance
                            .iter()
                            .map(|provenance| provenance.evidence_digest),
                    );
                    let imported = crate::store::artifact_store::imported_capture_refs(
                        &mut tx,
                        &observed.id.to_string(),
                    )
                    .await?;
                    for capture in &imported {
                        pinned_objects.extend([
                            capture.provenance_digest,
                            capture.evidence_digest,
                            capture.receipt_digest,
                        ]);
                    }
                    pinned_objects.extend(
                        crate::store::artifact_store::acquisition_objects(
                            &mut tx,
                            "snapshot",
                            &observed.id.to_string(),
                        )
                        .await?,
                    );
                    let lease = pool.lease(id)?;
                    Store::insert_stopped_operation(
                        &mut tx,
                        id,
                        "import",
                        &lease,
                        &streams.into_iter().collect::<Vec<_>>(),
                        &pinned_objects.into_iter().collect::<Vec<_>>(),
                    )
                    .await?;
                    tx.commit().await?;
                    Ok::<_, LibVmError>((info, lease, imported))
                })?;
                let contents = if disks_only {
                    record.storage_streams().collect::<Vec<_>>()
                } else {
                    record.streams().collect::<Vec<_>>()
                };
                for content in contents.iter().filter(|_| materialize) {
                    runtime.block_on(store.materialize_stream(id, content))?;
                }
                if !authenticate {
                    return Ok(SnapshotConsumer {
                        info,
                        record,
                        operation_id: id,
                        imported,
                        closure: None,
                        lease,
                        _store: store.clone(),
                    });
                }
                let (_, closure) = if disks_only {
                    let (_, objects) = record.storage_content_dependencies()?;
                    let mut retained = objects.clone();
                    for content in &contents {
                        retained.remove(&content.map);
                    }
                    verify_artifact_closure(
                        &pool,
                        &record.canonical_bytes()?,
                        &contents,
                        objects,
                        retained,
                        Some(info.record_digest),
                        true,
                        None,
                        Arc::new(lease.duplicate()?),
                    )?
                } else {
                    verify_closure(
                        &pool,
                        &record,
                        Some(info.record_digest),
                        true,
                        Arc::new(lease.duplicate()?),
                    )?
                };
                for provenance in &info.provenance {
                    pool.verify_object(&provenance.evidence_digest)?;
                }
                crate::store::restore::authenticate_imported_captures(
                    &pool, &record, info.id, &imported,
                )?;
                Ok(SnapshotConsumer {
                    info,
                    record,
                    operation_id: id,
                    imported,
                    closure: Some(closure),
                    lease,
                    _store: store.clone(),
                })
            })();
            match result {
                Ok(consumer) => Ok(consumer),
                Err(primary) => {
                    // The failed reader's lease has closed. Settle its exact
                    // journal outcome through existing recovery, including an
                    // uncertain registration COMMIT, rather than leaking pins.
                    if let Err(cleanup) =
                        runtime.block_on(store.retire_abandoned_storage_operations(&pool))
                    {
                        return Err(LibVmError::MachineStartCleanupFailed {
                            primary: primary.to_string(),
                            cleanup: cleanup.to_string(),
                        });
                    }
                    Err(primary)
                }
            }
        })
        .await?
    }

    async fn load_observed(
        &self,
        reference: &SnapshotRef,
    ) -> Result<(SnapshotRecord, SnapshotInfo), LibVmError> {
        let mut tx = self.store.pool.begin().await?;
        let facts = fetch_catalog(&mut tx, reference).await?;
        tx.commit().await?;
        authenticate_catalog(facts)
    }
}

/// Read-only admission examines current catalog facts, not immutable backing
/// bytes. The authoritative restore consumer subsequently pins and authenticates
/// the closure before opening it. Missing state never creates a pool or catalog.
pub(crate) async fn observe_snapshot_record(
    config: &crate::RuntimeConfig,
    reference: &SnapshotRef,
) -> Result<SnapshotRecord, LibVmError> {
    let home = config.resolve_home()?;
    let store = crate::store::observation::ObservationStore::open(&home.join("state.db")).await?;
    let record = store.snapshot_record(reference).await;
    store.close().await?;
    record
}

async fn exists(
    connection: &mut sqlx::SqliteConnection,
    id: SnapshotId,
) -> Result<bool, LibVmError> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_snapshot WHERE id=?1)")
            .bind(id.to_string())
            .fetch_one(connection)
            .await?,
    )
}

/// The snapshot an exact name tags, if any.
pub(crate) async fn named_snapshot(
    connection: &mut sqlx::SqliteConnection,
    name: &str,
) -> Result<Option<SnapshotId>, LibVmError> {
    sqlx::query_scalar::<_, String>("SELECT snapshot_id FROM snapshot_name WHERE name=?1")
        .bind(name)
        .fetch_optional(connection)
        .await?
        .map(|id| id.parse().map_err(invalid))
        .transpose()
}

/// Every snapshot whose id starts with `prefix` (hex, without `sha256:`),
/// bounded to two: one is a match, two is ambiguous.
pub(crate) async fn snapshot_prefix(
    connection: &mut sqlx::SqliteConnection,
    prefix: &str,
) -> Result<Vec<SnapshotId>, LibVmError> {
    sqlx::query_scalar::<_, String>(
        "SELECT id FROM storage_snapshot WHERE substr(id,8,length(?1))=?1 ORDER BY id LIMIT 2",
    )
    .bind(prefix)
    .fetch_all(connection)
    .await?
    .into_iter()
    .map(|id| id.parse().map_err(invalid))
    .collect()
}

/// Local resolution only: an exact name, then a full id, then a unique id
/// prefix. Registry expansion of short references belongs to the caller.
pub(crate) async fn resolve_snapshot(
    connection: &mut sqlx::SqliteConnection,
    reference: &SnapshotRef,
) -> Result<SnapshotId, LibVmError> {
    let not_found = || LibVmError::SnapshotNotFound {
        reference: reference.to_string(),
    };
    match reference {
        SnapshotRef::Id(id) => {
            if exists(connection, *id).await? {
                Ok(*id)
            } else {
                Err(not_found())
            }
        }
        SnapshotRef::Name(name) => {
            if let Some(id) = named_snapshot(connection, name).await? {
                return Ok(id);
            }
            let Some(prefix) = crate::store::names::id_prefix(name) else {
                return Err(not_found());
            };
            match snapshot_prefix(connection, prefix).await?.as_slice() {
                [id] => Ok(*id),
                [] => Err(not_found()),
                matches => Err(LibVmError::AmbiguousRecordPrefix {
                    prefix: prefix.to_owned(),
                    count: matches.len(),
                }),
            }
        }
    }
}

/// Add `name` to `id`. A name already naming another snapshot is refused.
pub(crate) async fn insert_name(
    connection: &mut sqlx::SqliteConnection,
    name: &str,
    id: SnapshotId,
) -> Result<(), LibVmError> {
    match named_snapshot(&mut *connection, name).await? {
        Some(existing) if existing == id => Ok(()),
        Some(_) => Err(LibVmError::SnapshotNameConflict {
            name: name.to_owned(),
        }),
        None => {
            sqlx::query("INSERT INTO snapshot_name(name,snapshot_id,updated_at) VALUES(?1,?2,?3)")
                .bind(name)
                .bind(id.to_string())
                .bind(chrono::Utc::now().timestamp())
                .execute(connection)
                .await?;
            Ok(())
        }
    }
}

/// Point a pulled registry reference at `id`, moving it from any previous
/// snapshot. The previous record stays, listed by id, until removed.
pub(crate) async fn move_name(
    connection: &mut sqlx::SqliteConnection,
    name: &str,
    id: SnapshotId,
) -> Result<(), LibVmError> {
    sqlx::query("INSERT INTO snapshot_name(name,snapshot_id,updated_at) VALUES(?1,?2,?3) ON CONFLICT(name) DO UPDATE SET snapshot_id=excluded.snapshot_id,updated_at=excluded.updated_at")
        .bind(name)
        .bind(id.to_string())
        .bind(chrono::Utc::now().timestamp())
        .execute(connection)
        .await?;
    Ok(())
}

/// An import still committing the record, or a capture still settling the
/// publication that names it as its candidate, owns the record for now.
async fn refuse_in_use(
    connection: &mut sqlx::SqliteConnection,
    id: SnapshotId,
    reference: &SnapshotRef,
) -> Result<(), LibVmError> {
    let in_use: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_managed WHERE managed_kind='snapshot' AND managed_id=?1) OR EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND json_extract(record_json,'$.candidate')=?1 AND json_extract(record_json,'$.state.state') IN ('reserved','sealed','published'))")
        .bind(id.to_string())
        .fetch_one(connection)
        .await?;
    if in_use {
        return Err(LibVmError::RecordInUse {
            reference: reference.to_string(),
        });
    }
    Ok(())
}

/// Dependencies, provenance and acquisitions cascade; names must be gone.
async fn delete_record(
    connection: &mut sqlx::SqliteConnection,
    id: SnapshotId,
) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM storage_snapshot WHERE id=?1")
        .bind(id.to_string())
        .execute(connection)
        .await?;
    Ok(())
}

struct CaptureProvenanceFact {
    capture: String,
    digest: String,
    evidence: Vec<u8>,
    plan: Vec<u8>,
}

/// Plain immutable catalog facts. Fetching performs no JSON decoding,
/// canonicalization, or content hashing while the read transaction is open.
pub(crate) struct CatalogSnapshotFacts {
    id: String,
    digest: String,
    bytes: Vec<u8>,
    created_at: i64,
    names: Vec<String>,
    streams: Vec<String>,
    objects: Vec<String>,
    provenance: Vec<CaptureProvenanceFact>,
}

pub(crate) async fn fetch_catalog(
    connection: &mut sqlx::SqliteConnection,
    reference: &SnapshotRef,
) -> Result<CatalogSnapshotFacts, LibVmError> {
    let id = resolve_snapshot(connection, reference).await?.to_string();
    let row = sqlx::query(
        "SELECT record_digest,record_bytes,created_at FROM storage_snapshot WHERE id=?1",
    )
    .bind(&id)
    .fetch_one(&mut *connection)
    .await?;
    let names =
        sqlx::query_scalar("SELECT name FROM snapshot_name WHERE snapshot_id=?1 ORDER BY name")
            .bind(&id)
            .fetch_all(&mut *connection)
            .await?;
    let streams = sqlx::query_scalar(
        "SELECT stream_id FROM snapshot_stream_dependency WHERE snapshot_id=?1 ORDER BY stream_id",
    )
    .bind(&id)
    .fetch_all(&mut *connection)
    .await?;
    let objects = sqlx::query_scalar("SELECT object_digest FROM snapshot_object_dependency WHERE snapshot_id=?1 ORDER BY object_digest")
        .bind(&id).fetch_all(&mut *connection).await?;
    let provenance = provenance_facts(connection, &id).await?;
    crate::store::artifact_store::acquisition_objects(connection, "snapshot", &id).await?;
    Ok(CatalogSnapshotFacts {
        id,
        digest: row.try_get("record_digest")?,
        bytes: row.try_get("record_bytes")?,
        created_at: row.try_get("created_at")?,
        names,
        streams,
        objects,
        provenance,
    })
}

/// Call only after the catalog read transaction has ended.
pub(crate) fn authenticate_catalog(
    facts: CatalogSnapshotFacts,
) -> Result<(SnapshotRecord, SnapshotInfo), LibVmError> {
    let id = facts.id.parse::<SnapshotId>().map_err(invalid)?;
    let digest = facts.digest.parse::<ObjectDigest>().map_err(invalid)?;
    let record = SnapshotRecord::decode(&facts.bytes)?;
    if record.canonical_bytes()? != facts.bytes
        || crate::store::models::snapshot::snapshot_id(&facts.bytes) != id
        || ObjectDigest::of_bytes(&facts.bytes) != digest
    {
        return Err(invalid("snapshot catalog identity contradiction"));
    }
    let (streams, mut objects) = record.content_dependencies()?;
    objects.insert(digest);
    let actual_streams = facts
        .streams
        .into_iter()
        .map(|value| value.parse().map_err(invalid))
        .collect::<Result<BTreeSet<StreamId>, _>>()?;
    let actual_objects = facts
        .objects
        .into_iter()
        .map(|value| value.parse().map_err(invalid))
        .collect::<Result<BTreeSet<ObjectDigest>, _>>()?;
    if streams != actual_streams || objects != actual_objects {
        return Err(invalid("snapshot dependency closure contradiction"));
    }
    for name in &facts.names {
        crate::store::names::validate_stored_name(name)?;
    }
    let memory = snapshot_memory(&record);
    let provenance = authenticate_provenance(facts.provenance)?;
    if memory == SnapshotMemory::None && !provenance.is_empty() {
        return Err(invalid(
            "snapshot without memory has live capture provenance",
        ));
    }
    let summaries = stream_summaries(&record);
    Ok((
        record,
        SnapshotInfo {
            id,
            record_digest: digest,
            memory,
            provenance,
            names: facts.names,
            created_at: facts.created_at,
            streams: summaries,
        },
    ))
}

async fn catalog_info(
    connection: &mut sqlx::SqliteConnection,
    id: SnapshotId,
    digest: ObjectDigest,
) -> Result<SnapshotInfo, LibVmError> {
    let row = sqlx::query("SELECT record_bytes,created_at FROM storage_snapshot WHERE id=?1")
        .bind(id.to_string())
        .fetch_one(&mut *connection)
        .await?;
    let names = sqlx::query_scalar::<_, String>(
        "SELECT name FROM snapshot_name WHERE snapshot_id=?1 ORDER BY name",
    )
    .bind(id.to_string())
    .fetch_all(&mut *connection)
    .await?;
    for name in &names {
        crate::store::names::validate_stored_name(name)?;
    }
    let record = SnapshotRecord::decode(&row.try_get::<Vec<u8>, _>("record_bytes")?)?;
    Ok(SnapshotInfo {
        id,
        record_digest: digest,
        provenance: Vec::new(),
        memory: snapshot_memory(&record),
        names,
        created_at: row.try_get("created_at")?,
        streams: stream_summaries(&record),
    })
}
async fn provenance_facts(
    connection: &mut sqlx::SqliteConnection,
    id: &str,
) -> Result<Vec<CaptureProvenanceFact>, LibVmError> {
    let rows = sqlx::query("SELECT capture_id,evidence_digest,CASE WHEN typeof(evidence_bytes)='blob' AND length(evidence_bytes)<=?2 THEN evidence_bytes END AS evidence_bytes,CASE WHEN typeof(plan_bytes)='blob' AND length(plan_bytes)<=?2 THEN plan_bytes END AS plan_bytes FROM snapshot_capture_provenance WHERE snapshot_id=?1 ORDER BY capture_id")
        .bind(id).bind(vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as i64)
        .fetch_all(connection).await?;
    rows.into_iter()
        .map(|row| {
            Ok(CaptureProvenanceFact {
                capture: row.try_get("capture_id")?,
                digest: row.try_get("evidence_digest")?,
                evidence: row
                    .try_get::<Option<Vec<u8>>, _>("evidence_bytes")?
                    .ok_or_else(|| {
                        invalid("capture evidence exceeds its bound or has invalid type")
                    })?,
                plan: row
                    .try_get::<Option<Vec<u8>>, _>("plan_bytes")?
                    .ok_or_else(|| invalid("capture plan exceeds its bound or has invalid type"))?,
            })
        })
        .collect()
}

/// Historical capture intent, retained with the evidence rather than a live
/// operation. This must never be used as a lease, pause or restore capability.
pub(crate) async fn capture_plan(
    store: &Store,
    snapshot: SnapshotId,
    capture: Uuid,
) -> Result<vm_spec::capture::CapturePlan, LibVmError> {
    let row = sqlx::query("SELECT evidence_digest,CASE WHEN typeof(evidence_bytes)='blob' AND length(evidence_bytes)<=?3 THEN evidence_bytes END AS evidence_bytes,CASE WHEN typeof(plan_bytes)='blob' AND length(plan_bytes)<=?3 THEN plan_bytes END AS plan_bytes FROM snapshot_capture_provenance WHERE snapshot_id=?1 AND capture_id=?2")
        .bind(snapshot.to_string()).bind(capture.to_string())
        .bind(vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as i64)
        .fetch_optional(&store.pool).await?
        .ok_or_else(|| invalid("snapshot capture lacks its retained exact plan"))?;
    let evidence = row
        .try_get::<Option<Vec<u8>>, _>("evidence_bytes")?
        .ok_or_else(|| invalid("capture evidence exceeds its bound or has invalid type"))?;
    if ObjectDigest::of_bytes(&evidence).to_string()
        != row.try_get::<String, _>("evidence_digest")?
    {
        return Err(invalid("snapshot capture evidence digest contradiction"));
    }
    let plan = row
        .try_get::<Option<Vec<u8>>, _>("plan_bytes")?
        .ok_or_else(|| invalid("capture plan exceeds its bound or has invalid type"))?;
    authenticate_capture_plan(&plan, &evidence, capture)
}

fn authenticate_capture_plan(
    plan_bytes: &[u8],
    evidence_bytes: &[u8],
    capture: Uuid,
) -> Result<vm_spec::capture::CapturePlan, LibVmError> {
    let plan = vm_spec::capture::CapturePlan::decode(plan_bytes).map_err(invalid)?;
    let evidence = vm_spec::capture::CaptureEvidence::decode(evidence_bytes).map_err(invalid)?;
    if plan.capture_id.to_string() != capture.to_string() || !evidence.is_sealed() {
        return Err(invalid(
            "retained capture plan or seal identity contradiction",
        ));
    }
    evidence
        .validate_against_plan(&plan, &vm_spec::capture::Sha256Digest::of_bytes(plan_bytes))
        .map_err(invalid)?;
    Ok(plan)
}

fn authenticate_provenance(
    facts: Vec<CaptureProvenanceFact>,
) -> Result<Vec<SnapshotCaptureProvenance>, LibVmError> {
    facts
        .into_iter()
        .map(
            |CaptureProvenanceFact {
                 capture,
                 digest,
                 evidence: bytes,
                 plan,
             }| {
                let evidence =
                    vm_spec::capture::CaptureEvidence::decode(&bytes).map_err(invalid)?;
                authenticate_capture_plan(&plan, &bytes, capture.parse().map_err(invalid)?)?;
                let digest: ObjectDigest = digest.parse().map_err(invalid)?;
                if !evidence.is_sealed()
                    || evidence.capture_id.to_string() != capture
                    || ObjectDigest::of_bytes(&bytes) != digest
                {
                    return Err(invalid("capture provenance identity contradiction"));
                }
                Ok(SnapshotCaptureProvenance {
                    capture_id: capture.parse().map_err(invalid)?,
                    machine_id: evidence.machine_id.to_string().parse().map_err(invalid)?,
                    run_id: evidence.run_id.to_string().parse().map_err(invalid)?,
                    evidence_digest: digest,
                })
            },
        )
        .collect()
}

pub(crate) fn snapshot_memory(record: &SnapshotRecord) -> SnapshotMemory {
    match &record.memory {
        crate::store::models::snapshot::SnapshotMemoryState::None { .. } => SnapshotMemory::None,
        crate::store::models::snapshot::SnapshotMemoryState::Included { .. } => {
            SnapshotMemory::Included
        }
    }
}

async fn exact_catalog_dependencies(
    connection: &mut sqlx::SqliteConnection,
    id: SnapshotId,
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
) -> Result<(), LibVmError> {
    let actual_streams = sqlx::query_scalar::<_, String>(
        "SELECT stream_id FROM snapshot_stream_dependency WHERE snapshot_id=?1",
    )
    .bind(id.to_string())
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|id| id.parse().map_err(invalid))
    .collect::<Result<BTreeSet<StreamId>, _>>()?;
    let actual_objects = sqlx::query_scalar::<_, String>(
        "SELECT object_digest FROM snapshot_object_dependency WHERE snapshot_id=?1",
    )
    .bind(id.to_string())
    .fetch_all(connection)
    .await?
    .into_iter()
    .map(|id| id.parse().map_err(invalid))
    .collect::<Result<BTreeSet<ObjectDigest>, _>>()?;
    if &actual_streams != streams || &actual_objects != objects {
        return Err(invalid("snapshot dependency closure contradiction"));
    }
    Ok(())
}

async fn recheck_catalog(
    connection: &mut sqlx::SqliteConnection,
    reference: &SnapshotRef,
    observed: &SnapshotInfo,
    bytes: &[u8],
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
) -> Result<(), LibVmError> {
    if resolve_snapshot(connection, reference).await? != observed.id {
        return Err(invalid(
            "snapshot root changed before consumer registration",
        ));
    }
    let row = sqlx::query("SELECT id,record_digest,record_bytes FROM storage_snapshot WHERE id=?1")
        .bind(observed.id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| invalid("snapshot root was removed before consumer registration"))?;
    if row.try_get::<String, _>("id")? != observed.id.to_string()
        || row.try_get::<String, _>("record_digest")? != observed.record_digest.to_string()
        || row.try_get::<Vec<u8>, _>("record_bytes")? != bytes
    {
        return Err(invalid(
            "snapshot root changed before consumer registration",
        ));
    }
    exact_catalog_dependencies(connection, observed.id, streams, objects).await
}

/// Identity hashing is metadata-only but still occurs outside root coordination.
/// Immutable catalog facts cannot be updated by any supported producer.
pub(crate) async fn check_snapshot_catalog(store: &Store) -> Result<(), LibVmError> {
    let mut cursor = String::new();
    loop {
        let mut tx = store.pool.begin().await?;
        let ids = sqlx::query_scalar::<_, String>(
            "SELECT id FROM storage_snapshot WHERE id>?1 ORDER BY id LIMIT 256",
        )
        .bind(&cursor)
        .fetch_all(&mut *tx)
        .await?;
        if ids.is_empty() {
            tx.commit().await?;
            break;
        }
        let mut observed = Vec::with_capacity(ids.len());
        for id in ids {
            cursor = id.clone();
            let facts =
                fetch_catalog(&mut tx, &SnapshotRef::Id(id.parse().map_err(invalid)?)).await?;
            let imported =
                crate::store::artifact_store::imported_capture_refs(&mut tx, &id).await?;
            observed.push((facts, imported));
        }
        tx.commit().await?;
        for (facts, imported) in observed {
            let (record, info) = authenticate_catalog(facts)?;
            if !imported.is_empty() {
                let pool = StoragePool::open_existing(&store.images_dir)?
                    .ok_or_else(|| invalid("imported snapshot pool is missing"))?;
                crate::store::restore::authenticate_imported_captures(
                    &pool, &record, info.id, &imported,
                )?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn require_operation_closure(
    store: &Store,
    operation: Uuid,
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
    pending: Option<ObjectDigest>,
) -> Result<(), LibVmError> {
    require_closure(
        store,
        operation,
        streams,
        objects,
        pending,
        ClosureUse::Publication,
    )
    .await
}

pub(crate) async fn require_consumer_closure(
    store: &Store,
    operation: Uuid,
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
) -> Result<(), LibVmError> {
    require_closure(
        store,
        operation,
        streams,
        objects,
        None,
        ClosureUse::Consumer,
    )
    .await
}

enum ClosureUse {
    Publication,
    Consumer,
}

async fn require_closure(
    store: &Store,
    operation: Uuid,
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
    pending: Option<ObjectDigest>,
    usage: ClosureUse,
) -> Result<(), LibVmError> {
    let mut tx = store.pool.begin().await?;
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND (?2=0 OR kind IN ('import','convert','snapshot','capture','update-boot-assets')) AND state IN ('staging','committing'))")
        .bind(operation.to_string()).bind(matches!(usage, ClosureUse::Publication))
        .fetch_one(&mut *tx).await?;
    if !active {
        return Err(invalid("snapshot has no active retained operation"));
    }
    let missing_stream: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM json_each(?2) e LEFT JOIN storage_operation_stream p ON p.operation_id=?1 AND p.stream_id=e.value WHERE p.stream_id IS NULL)")
        .bind(operation.to_string()).bind(serde_json::to_string(streams).map_err(invalid)?)
        .fetch_one(&mut *tx).await?;
    if missing_stream {
        return Err(invalid("snapshot stream was not pinned before access"));
    }
    let objects = objects
        .iter()
        .filter(|object| Some(**object) != pending)
        .collect::<Vec<_>>();
    let missing_object: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM json_each(?2) e LEFT JOIN storage_operation_object p ON p.operation_id=?1 AND p.object_digest=e.value WHERE p.object_digest IS NULL)")
        .bind(operation.to_string()).bind(serde_json::to_string(&objects).map_err(invalid)?)
        .fetch_one(&mut *tx).await?;
    if missing_object {
        return Err(invalid("snapshot object was not pinned before access"));
    }
    tx.commit().await?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapValidation {
    schema: u32,
    content: SnapshotStream,
    stream: SourceFingerprint,
    root: SourceFingerprint,
    objects: Vec<(ObjectDigest, SourceFingerprint)>,
}

struct HeldMapValidation {
    map: Arc<crate::storage::map::AuthenticatedMap>,
    stream: SourceFingerprint,
    metadata: (ObjectDigest, File, SourceFingerprint),
    objects: Vec<(ObjectDigest, SourceFingerprint)>,
}

impl SnapshotStore {
    pub(crate) async fn seed_map_receipt(
        &self,
        content: &SnapshotStream,
        publication: &crate::storage::pool::SealedStreamPublication,
    ) -> Result<(), LibVmError> {
        let pool = StoragePool::open(&self.store.images_dir)?;
        publication.recheck(&pool)?;
        save_map_receipt(
            &self.store,
            &pool,
            content,
            publication.map(),
            publication.fingerprint(),
        )
        .await
    }
}

impl Store {
    /// Transfer existing identified authority into a fork without a receipt-miss scan.
    pub(crate) async fn reuse_local_stream(
        &self,
        operation: Uuid,
        content: &SnapshotStream,
    ) -> Result<AuthenticatedStream, LibVmError> {
        require_consumer_closure(
            self,
            operation,
            &BTreeSet::from([content.stream]),
            &BTreeSet::from([content.map]),
        )
        .await?;
        let pool = StoragePool::open(self.images_path())?;
        let pin: Arc<dyn Send + Sync> = Arc::new(pool.existing_lease(operation)?);
        let receipt = load_map_validation(self, &pool, content, pin)
            .await?
            .ok_or_else(|| {
                invalid("fork read-only dependency lost its exact identified receipt")
            })?;
        Ok(AuthenticatedStream::from_verified_fingerprint(
            pool.open_stream(&content.stream)?,
            receipt.map,
            receipt.stream,
        )?)
    }
    pub(crate) async fn authenticate_local_stream(
        &self,
        operation: Uuid,
        content: &SnapshotStream,
    ) -> Result<AuthenticatedStream, LibVmError> {
        require_consumer_closure(
            self,
            operation,
            &BTreeSet::from([content.stream]),
            &BTreeSet::from([content.map]),
        )
        .await?;
        let pool = StoragePool::open(self.images_path())?;
        let pin: Arc<dyn Send + Sync> = Arc::new(pool.existing_lease(operation)?);
        let cached = load_map_validation(self, &pool, content, Arc::clone(&pin)).await?;
        let (map, fingerprint) = match cached {
            Some(receipt) => (receipt.map, receipt.stream),
            None => {
                let map = Arc::new(load_root_map(&pool, content, pin)?);
                let file = pool.open_stream(&content.stream)?;
                let before = SourceFingerprint::new(&file.metadata()?);
                crate::storage::stream::StreamHasher::new(map.chunk_size())
                    .verify_expected_map(&file, &map)
                    .map_err(invalid)?;
                bind_held(&file, before)?;
                save_map_receipt(self, &pool, content, &map, before).await?;
                (map, before)
            }
        };
        let file = pool.open_stream(&content.stream)?;
        Ok(AuthenticatedStream::from_verified_fingerprint(
            file,
            map,
            fingerprint,
        )?)
    }
}

async fn save_map_receipt(
    store: &Store,
    pool: &StoragePool,
    content: &SnapshotStream,
    map: &crate::storage::map::AuthenticatedMap,
    fingerprint: SourceFingerprint,
) -> Result<(), LibVmError> {
    let receipt = map_validation(pool, content, map, fingerprint, &BTreeMap::new())?;
    let [dev, ino, len, mode, ctime_sec, ctime_nsec] = fingerprint.verification_key();
    sqlx::query("INSERT INTO verified_object(stream_sha256,dev,ino,len,mode,ctime_sec,ctime_nsec,map_receipt,verified_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(stream_sha256) DO UPDATE SET dev=excluded.dev,ino=excluded.ino,len=excluded.len,mode=excluded.mode,ctime_sec=excluded.ctime_sec,ctime_nsec=excluded.ctime_nsec,map_receipt=excluded.map_receipt,verified_at=excluded.verified_at")
        .bind(content.stream.to_string()).bind(dev).bind(ino).bind(len).bind(mode)
        .bind(ctime_sec).bind(ctime_nsec).bind(receipt).execute(&store.pool).await?;
    Ok(())
}

fn map_validation(
    pool: &StoragePool,
    content: &SnapshotStream,
    map: &crate::storage::map::AuthenticatedMap,
    stream: SourceFingerprint,
    objects: &BTreeMap<ObjectDigest, SourceFingerprint>,
) -> Result<Vec<u8>, LibVmError> {
    if map.id() != content.stream
        || map.length() != content.length
        || map.chunk_size().bytes() != content.chunk_size
        || content.map.as_bytes() != content.stream.as_bytes()
    {
        return Err(invalid("map receipt contradicts its stream"));
    }
    let root_file = pool.open_object(&content.map)?;
    let root_fingerprint = SourceFingerprint::new(&root_file.metadata()?);
    let root = vm_spec::stream_map::StreamRoot::decode(
        &pool.read_object(&content.map, vm_spec::stream_map::MAX_ROOT_BYTES as u64)?,
    )
    .map_err(invalid)?;
    if &root != map.root() {
        return Err(invalid("map receipt contradicts retained root bytes"));
    }
    bind_held(&root_file, root_fingerprint)?;
    bind_held(&pool.open_stream(&content.stream)?, stream)?;
    for (digest, expected) in objects {
        bind_held(&pool.open_object(digest)?, *expected)?;
    }
    serde_json::to_vec(&MapValidation {
        schema: 1,
        content: content.clone(),
        stream,
        root: root_fingerprint,
        objects: objects
            .iter()
            .map(|(digest, fingerprint)| (*digest, *fingerprint))
            .collect(),
    })
    .map_err(invalid)
}

async fn load_map_validation(
    store: &Store,
    pool: &StoragePool,
    content: &SnapshotStream,
    pin: Arc<dyn Send + Sync>,
) -> Result<Option<HeldMapValidation>, LibVmError> {
    let file = pool.open_stream(&content.stream)?;
    let fingerprint = SourceFingerprint::new(&file.metadata()?);
    let [dev, ino, len, mode, ctime_sec, ctime_nsec] = fingerprint.verification_key();
    let bytes: Option<Vec<u8>> = sqlx::query_scalar("SELECT map_receipt FROM verified_object WHERE stream_sha256=?1 AND dev=?2 AND ino=?3 AND len=?4 AND mode=?5 AND ctime_sec=?6 AND ctime_nsec=?7 AND EXISTS(SELECT 1 FROM stream_map_root WHERE root_digest=?8)")
        .bind(content.stream.to_string()).bind(dev).bind(ino).bind(len).bind(mode)
        .bind(ctime_sec).bind(ctime_nsec).bind(content.map.to_string())
        .fetch_optional(&store.pool).await?.flatten();
    let Some(receipt) =
        bytes.and_then(|bytes| serde_json::from_slice::<MapValidation>(&bytes).ok())
    else {
        return Ok(None);
    };
    if receipt.schema != 1 || receipt.content != *content || receipt.stream != fingerprint {
        return Ok(None);
    }
    let root_file = pool.open_object(&content.map)?;
    if SourceFingerprint::new(&root_file.metadata()?) != receipt.root {
        return Ok(None);
    }
    let root = vm_spec::stream_map::StreamRoot::decode(
        &pool.read_object(&content.map, vm_spec::stream_map::MAX_ROOT_BYTES as u64)?,
    )
    .map_err(invalid)?;
    if root.id().as_bytes() != content.stream.as_bytes()
        || root.length() != content.length
        || root.chunk_size().bytes() != content.chunk_size
    {
        return Err(invalid("receipt root contradicts its stream"));
    }
    bind_held(&file, fingerprint)?;
    bind_held(&root_file, receipt.root)?;
    Ok(Some(HeldMapValidation {
        map: Arc::new(crate::storage::map::AuthenticatedMap::from_admitted_root(
            root,
            stream_role(content)?,
            pool.map_authority(pin)?,
        )?),
        stream: fingerprint,
        metadata: (content.map, root_file, receipt.root),
        objects: receipt.objects,
    }))
}
pub(crate) type ClosureFingerprints = Vec<(std::path::PathBuf, SourceFingerprint)>;

pub(crate) fn recheck_closure(
    fingerprints: &[(std::path::PathBuf, SourceFingerprint)],
) -> Result<(), LibVmError> {
    for (path, before) in fingerprints {
        if SourceFingerprint::new(&std::fs::symlink_metadata(path)?) != *before {
            return Err(invalid(
                "authenticated snapshot closure changed before publication",
            ));
        }
    }
    Ok(())
}

fn structural(
    role: &SnapshotVerificationRole,
    member: SnapshotVerificationMember,
    failure: SnapshotStructuralFailure,
) -> LibVmError {
    SnapshotVerificationError::Structural {
        role: role.clone(),
        member,
        failure,
    }
    .into()
}

fn verification_path(pool: &StoragePool, member: SnapshotVerificationMember) -> std::path::PathBuf {
    match member {
        SnapshotVerificationMember::Stream(stream) => pool.stream_path(&stream),
        SnapshotVerificationMember::Object(object) => pool.object_path(&object),
    }
}

fn open_verification_member(
    pool: &StoragePool,
    role: &SnapshotVerificationRole,
    member: SnapshotVerificationMember,
    length: Option<u64>,
) -> Result<(File, SourceFingerprint), LibVmError> {
    use std::os::unix::fs::MetadataExt;
    let path = verification_path(pool, member);
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
        structural(
            role,
            member,
            if error.kind() == std::io::ErrorKind::NotFound {
                SnapshotStructuralFailure::Missing
            } else {
                SnapshotStructuralFailure::Invalid {
                    message: error.to_string(),
                }
            },
        )
    })?;
    if !metadata.is_file() {
        return Err(structural(
            role,
            member,
            SnapshotStructuralFailure::Invalid {
                message: "member is not a regular file".into(),
            },
        ));
    }
    if metadata.mode() & 0o222 != 0 {
        return Err(structural(
            role,
            member,
            SnapshotStructuralFailure::Writable {
                mode: metadata.mode(),
            },
        ));
    }
    if let Some(expected) = length {
        let actual = metadata.len();
        if actual != expected {
            return Err(structural(
                role,
                member,
                if actual < expected {
                    SnapshotStructuralFailure::Truncated { expected, actual }
                } else {
                    SnapshotStructuralFailure::Length { expected, actual }
                },
            ));
        }
    }
    let before = SourceFingerprint::new(&metadata);
    let file = match member {
        SnapshotVerificationMember::Stream(stream) => pool.open_stream(&stream),
        SnapshotVerificationMember::Object(object) => pool.open_object(&object),
    }
    .map_err(|error| {
        structural(
            role,
            member,
            SnapshotStructuralFailure::Invalid {
                message: error.to_string(),
            },
        )
    })?;
    recheck_verification_member(pool, role, member, &file, before)?;
    Ok((file, before))
}

fn recheck_verification_member(
    pool: &StoragePool,
    role: &SnapshotVerificationRole,
    member: SnapshotVerificationMember,
    file: &File,
    before: SourceFingerprint,
) -> Result<(), LibVmError> {
    let held = file
        .metadata()
        .map(|metadata| SourceFingerprint::new(&metadata));
    let named = std::fs::symlink_metadata(verification_path(pool, member))
        .map(|metadata| SourceFingerprint::new(&metadata));
    if held.ok() != Some(before) || named.ok() != Some(before) {
        return Err(structural(
            role,
            member,
            SnapshotStructuralFailure::Replaced,
        ));
    }
    Ok(())
}

struct SnapshotByteVerifier<'a> {
    pool: &'a StoragePool,
    pin: Arc<dyn Send + Sync>,
    streams: BTreeSet<StreamId>,
    objects: BTreeSet<ObjectDigest>,
    report: SnapshotVerificationReport,
}

impl SnapshotByteVerifier<'_> {
    fn stream(
        &mut self,
        role: SnapshotVerificationRole,
        content: &SnapshotStream,
    ) -> Result<(), LibVmError> {
        if !self.streams.insert(content.stream) {
            return Ok(());
        }
        let member = SnapshotVerificationMember::Stream(content.stream);
        let (file, before) =
            open_verification_member(self.pool, &role, member, Some(content.length))?;
        let mut maps = BTreeMap::new();
        read_shape_maps(
            self.pool,
            std::iter::once(content),
            &mut maps,
            Arc::clone(&self.pin),
        )
        .map_err(|error| {
            structural(
                &role,
                member,
                SnapshotStructuralFailure::Invalid {
                    message: error.to_string(),
                },
            )
        })?;
        let map = maps
            .get(&content.stream)
            .ok_or_else(|| invalid("verification map is missing"))?;
        let result = crate::storage::stream::StreamHasher::new(map.chunk_size())
            .verify_expected_map(&file, map);
        recheck_verification_member(self.pool, &role, member, &file, before)?;
        result.map_err(|error| match error {
            crate::storage::stream::ExpectedMapError::ChunkMismatch {
                index,
                start,
                end,
                expected,
                actual,
                ..
            } => SnapshotVerificationError::ChunkMismatch {
                role: role.clone(),
                stream: content.stream,
                index,
                start,
                end,
                chunk_size: content.chunk_size,
                expected: Box::new(expected),
                actual: Box::new(actual),
            }
            .into(),
            crate::storage::stream::ExpectedMapError::Length { expected, actual } => structural(
                &role,
                member,
                if actual < expected {
                    SnapshotStructuralFailure::Truncated { expected, actual }
                } else {
                    SnapshotStructuralFailure::Length { expected, actual }
                },
            ),
            crate::storage::stream::ExpectedMapError::Changed => {
                structural(&role, member, SnapshotStructuralFailure::Replaced)
            }
            crate::storage::stream::ExpectedMapError::Storage(error) => structural(
                &role,
                member,
                SnapshotStructuralFailure::Invalid {
                    message: error.to_string(),
                },
            ),
            crate::storage::stream::ExpectedMapError::Metadata {
                digest,
                height,
                first_index,
                end_index,
                start,
                end,
                reason,
                ..
            } => SnapshotVerificationError::MapNode(Box::new(SnapshotMapNodeFailure {
                role: role.clone(),
                stream: content.stream,
                node: ObjectDigest::from_sha256(*digest.as_bytes()),
                height,
                first_index,
                end_index,
                start,
                end,
                failure: match std::fs::symlink_metadata(
                    self.pool
                        .object_path(&ObjectDigest::from_sha256(*digest.as_bytes())),
                ) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        SnapshotStructuralFailure::Missing
                    }
                    _ => SnapshotStructuralFailure::Invalid { message: reason },
                },
            }))
            .into(),
            crate::storage::stream::ExpectedMapError::Profile { expected, actual } => structural(
                &role,
                member,
                SnapshotStructuralFailure::Invalid {
                    message: format!(
                        "identity profile mismatch: expected {expected:?}, actual {actual:?}"
                    ),
                },
            ),
        })?;
        self.report.streams += 1;
        self.report.bytes += content.length;
        Ok(())
    }

    fn object(
        &mut self,
        role: SnapshotVerificationRole,
        object: ObjectDigest,
        length: Option<u64>,
    ) -> Result<(), LibVmError> {
        if !self.objects.insert(object) {
            return Ok(());
        }
        let member = SnapshotVerificationMember::Object(object);
        let (file, before) = open_verification_member(self.pool, &role, member, length)?;
        let length = file.metadata()?.len();
        let digest = crate::storage::stream::whole_file_sha256(&file);
        recheck_verification_member(self.pool, &role, member, &file, before)?;
        let digest = digest.map_err(|error| {
            structural(
                &role,
                member,
                SnapshotStructuralFailure::Invalid {
                    message: error.to_string(),
                },
            )
        })?;
        let actual = ObjectDigest::from_sha256(*digest.as_bytes());
        if actual != object {
            return Err(SnapshotVerificationError::ObjectMismatch {
                role,
                object,
                length,
                actual,
            }
            .into());
        }
        self.report.bytes += length;
        Ok(())
    }
}

fn verify_snapshot_bytes(
    snapshots: &SnapshotStore,
    consumer: &SnapshotConsumer,
) -> Result<SnapshotVerificationReport, LibVmError> {
    let pool = StoragePool::open(&snapshots.store.images_dir)?;
    let record = &consumer.record;
    let mut verifier = SnapshotByteVerifier {
        pool: &pool,
        pin: Arc::new(consumer.lease.duplicate()?),
        streams: BTreeSet::new(),
        objects: BTreeSet::new(),
        report: SnapshotVerificationReport {
            snapshot: consumer.info.id,
            streams: 0,
            bytes: 0,
        },
    };
    if let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
        &record.memory
    {
        verifier.stream(SnapshotVerificationRole::Ram, &execution.memory)?;
        let capture = snapshots.restore_evidence(consumer, &pool)?;
        for (role, capture_role, object) in [
            (
                SnapshotVerificationRole::Layout,
                vm_spec::capture::CaptureRole::Layout,
                execution.layout,
            ),
            (
                SnapshotVerificationRole::Execution,
                vm_spec::capture::CaptureRole::Execution,
                execution.execution,
            ),
            (
                SnapshotVerificationRole::Devices,
                vm_spec::capture::CaptureRole::Devices,
                execution.devices,
            ),
        ] {
            let entry = capture
                .evidence
                .inventory
                .iter()
                .find(|entry| entry.role == capture_role)
                .ok_or_else(|| invalid("capture inventory omitted state object"))?;
            if entry.sha256.as_ref().map(|digest| digest.as_bytes()) != Some(object.as_bytes()) {
                return Err(invalid("capture state identity contradicts snapshot"));
            }
            verifier.object(role, object, Some(entry.length))?;
        }
        let changes = &capture
            .evidence
            .memory
            .as_ref()
            .ok_or_else(|| invalid("capture provenance omitted RAM changes"))?
            .changes;
        verifier.object(
            SnapshotVerificationRole::Dependency,
            ObjectDigest::from_sha256(*changes.sha256.as_bytes()),
            Some(changes.byte_len),
        )?;
    }
    verifier.stream(SnapshotVerificationRole::RootDisk, &record.root.stream)?;
    for disk in &record.disks {
        verifier.stream(
            SnapshotVerificationRole::DataDisk { order: disk.order },
            &disk.content,
        )?;
    }
    for stream in record.streams() {
        verifier.stream(SnapshotVerificationRole::Dependency, stream)?;
    }
    let (_, mut objects) = record.content_dependencies()?;
    objects.insert(consumer.info.record_digest);
    objects.extend(
        consumer
            .info
            .provenance
            .iter()
            .map(|entry| entry.evidence_digest),
    );
    for imported in &consumer.imported {
        objects.extend([
            imported.provenance_digest,
            imported.evidence_digest,
            imported.receipt_digest,
            imported.changes_digest,
        ]);
    }
    for object in objects {
        verifier.object(SnapshotVerificationRole::Dependency, object, None)?;
    }
    if let Some(lower) = record.lower() {
        lower.authenticate(|digest, maximum| Ok(pool.read_object(digest, maximum)?))?;
    }
    Ok(verifier.report)
}

/// Verification is identical either way. With `retain`, the returned held
/// descriptors are the exact inodes hashed here, each bound to the path state
/// observed before hashing began; process descriptor admission for all of
/// them precedes the first open. Without it, each descriptor closes after use.
fn verify_closure(
    pool: &StoragePool,
    record: &SnapshotRecord,
    digest: Option<ObjectDigest>,
    retain: bool,
    pin: Arc<dyn Send + Sync>,
) -> Result<(ClosureFingerprints, AuthenticatedClosure), LibVmError> {
    let bytes = record.canonical_bytes()?;
    let (_, objects) = record.content_dependencies()?;
    let (_, retained_objects) = retained_members(record)?;
    let ram = match &record.memory {
        crate::store::models::snapshot::SnapshotMemoryState::Included { execution } if retain => {
            Some(execution.memory.stream)
        }
        _ => None,
    };
    verify_artifact_closure(
        pool,
        &bytes,
        &record.streams().collect::<Vec<_>>(),
        objects,
        retained_objects,
        digest,
        retain,
        ram,
        pin,
    )
}

/// Consume held producer authority only for the streams it actually published.
/// Replay has no capability and therefore authenticates every byte.
async fn verify_publication_closure(
    store: &Store,
    pool: &StoragePool,
    record: &SnapshotRecord,
    publications: &BTreeMap<StreamId, crate::storage::pool::SealedStreamPublication>,
    operation: Uuid,
) -> Result<ClosureFingerprints, LibVmError> {
    if publications.is_empty() {
        return Ok(verify_closure(
            pool,
            record,
            None,
            false,
            Arc::new(pool.existing_lease(operation)?),
        )?
        .0);
    }
    let bytes = record.canonical_bytes()?;
    let (_, objects) = record.content_dependencies()?;
    let (_, retained_objects) = retained_members(record)?;
    crate::storage::limits::preflight_fd_budget(
        2 * (objects.len() + record.streams().count()) as u64 + record.streams().count() as u64 + 4,
    )
    .map_err(crate::storage::StorageError::from)?;
    let lower = if let crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay {
        lower,
        lower_geometry,
        lower_filesystem_uuid,
        ..
    } = &record.root.profile
    {
        let held = crate::store::layer_store::LayerStore::from_store(store.clone())
            .hold_lower(&crate::OverlayLower::ErofsComposition {
                record: lower.result,
                geometry: *lower_geometry,
                filesystem_uuid: *lower_filesystem_uuid,
            })
            .await?;
        if held.snapshot_composition() != lower.as_ref() {
            return Err(invalid(
                "publication lower differs from retained composition",
            ));
        }
        Some(held)
    } else {
        None
    };
    let mut deferred: BTreeSet<_> = lower
        .as_ref()
        .map(|lower| lower.maps.keys().copied().collect())
        .unwrap_or_default();
    let pin: Arc<dyn Send + Sync> = Arc::new(pool.existing_lease(operation)?);
    let mut cached = BTreeMap::new();
    for content in record.streams() {
        if deferred.contains(&content.stream) {
            continue;
        }
        if let Some(receipt) = load_map_validation(store, pool, content, Arc::clone(&pin)).await? {
            deferred.insert(content.stream);
            cached.insert(content.stream, receipt);
        }
    }
    let mut shape = verify_artifact_shape(
        pool,
        &bytes,
        &record.streams().collect::<Vec<_>>(),
        objects,
        retained_objects,
        None,
        false,
        None,
        &deferred,
        pin,
    )?;
    for (stream, receipt) in cached {
        shape.apply_map_validation(pool, stream, receipt)?;
    }
    for (stream, publication) in publications {
        publication.recheck(pool)?;
        if shape.stream_map(stream)? != publication.map() {
            return Err(invalid("publication map differs from sealed producer map"));
        }
    }
    if let Some(lower) = &lower {
        lower.recheck()?;
        for (digest, expected) in lower.metadata_states() {
            if shape.object_states.get(&digest) != Some(&expected) {
                return Err(invalid(
                    "publication lower metadata changed during validation",
                ));
            }
            shape.objects.remove(&digest);
        }
        for layer in &lower.snapshot_composition().layers {
            let (_, fingerprint) = lower.held_backing(
                crate::storage::vmdk::LowerBacking::Stream(layer.pack.stream),
            )?;
            if shape.stream_states.get(&layer.pack.stream) != Some(&fingerprint) {
                return Err(invalid("publication lower pack changed during validation"));
            }
            shape
                .contents
                .retain(|content| content.stream != layer.pack.stream);
        }
    }
    shape
        .contents
        .retain(|content| !publications.contains_key(&content.stream));
    shape.authenticate(pool, None)?;
    if let Some(lower) = &lower {
        lower.recheck()?;
    }
    for publication in publications.values() {
        publication.recheck(pool)?;
    }
    Ok(shape.fingerprints)
}

/// A metadata-validated closure, with no stream-byte authentication authority.
/// Only root headers are eagerly read; node access authenticates bounded paths.
pub(crate) struct ShapeVerifiedClosure {
    contents: Vec<SnapshotStream>,
    maps: BTreeMap<StreamId, Arc<crate::storage::map::AuthenticatedMap>>,
    objects: BTreeSet<ObjectDigest>,
    object_pins: BTreeMap<ObjectDigest, File>,
    retain: bool,
    ram_stream: Option<StreamId>,
    fingerprints: ClosureFingerprints,
    stream_states: BTreeMap<StreamId, SourceFingerprint>,
    object_states: BTreeMap<ObjectDigest, SourceFingerprint>,
    local_lower: Option<crate::store::models::snapshot::SnapshotComposition>,
    held_lower: Option<crate::store::composition_store::LaunchLower>,
    receipt_pins: Vec<(File, SourceFingerprint)>,
    receipt_maps: BTreeSet<StreamId>,
    pin: Arc<dyn Send + Sync>,
}

pub(crate) struct RestoreInspectionShape {
    shape: ShapeVerifiedClosure,
}

impl RestoreInspectionShape {
    pub(crate) fn shape(&self) -> &ShapeVerifiedClosure {
        &self.shape
    }

    pub(crate) fn complete(
        mut self,
        images: &std::path::Path,
    ) -> Result<ShapeVerifiedClosure, LibVmError> {
        let pool = StoragePool::open(images)?;
        read_shape_maps(
            &pool,
            self.shape.contents.iter(),
            &mut self.shape.maps,
            Arc::clone(&self.shape.pin),
        )?;
        recheck_closure(&self.shape.fingerprints)?;
        Ok(self.shape)
    }
}

impl ShapeVerifiedClosure {
    fn apply_map_validation(
        &mut self,
        pool: &StoragePool,
        stream: StreamId,
        receipt: HeldMapValidation,
    ) -> Result<(), LibVmError> {
        if self.stream_states.get(&stream) != Some(&receipt.stream) {
            return Err(invalid(
                "receipt-backed stream changed during shape validation",
            ));
        }
        let (digest, file, expected) = receipt.metadata;
        if self.object_states.get(&digest) != Some(&expected) {
            return Err(invalid(
                "receipt-backed root changed during shape validation",
            ));
        }
        if self.objects.remove(&digest) && !self.object_pins.contains_key(&digest) {
            self.receipt_pins.push((file, expected));
        }
        for (digest, expected) in receipt.objects {
            if self.object_states.get(&digest) == Some(&expected) && self.objects.contains(&digest)
            {
                let file = pool.open_object(&digest)?;
                bind_held(&file, expected)?;
                self.objects.remove(&digest);
                self.receipt_pins.push((file, expected));
            }
        }
        self.maps.insert(stream, receipt.map);
        self.receipt_maps.insert(stream);
        Ok(())
    }

    /// Peak held descriptors: shape-pinned objects plus authenticated streams.
    pub(crate) fn retained_descriptors(&self) -> u64 {
        if self.retain {
            (self.stream_states.len() + self.object_pins.len() + self.receipt_pins.len()) as u64
                + self
                    .held_lower
                    .as_ref()
                    .map_or(0, |lower| lower.retained_descriptors())
        } else {
            0
        }
    }

    pub(crate) fn stream_map(
        &self,
        stream: &StreamId,
    ) -> Result<&crate::storage::map::AuthenticatedMap, LibVmError> {
        self.maps
            .get(stream)
            .map(Arc::as_ref)
            .ok_or_else(|| invalid("stream is outside the shape-verified closure"))
    }

    pub(crate) fn open_stream(
        &self,
        pool: &StoragePool,
        stream: &StreamId,
        length: u64,
    ) -> Result<File, LibVmError> {
        if self.stream_map(stream)?.length() != length {
            return Err(invalid(
                "shape-verified stream geometry differs from its use",
            ));
        }
        let file = pool.open_stream(stream)?;
        bind_hashed(&file, self.stream_states.get(stream))?;
        Ok(file)
    }

    /// Receipt-backed map for a copy that authenticates its writes. This does
    /// not replace joining `authenticate_closure_bytes` before child publication.
    pub(crate) fn open_copy_source(
        &self,
        pool: &StoragePool,
        stream: &StreamId,
        length: u64,
    ) -> Result<AuthenticatedStream, LibVmError> {
        let file = self.open_stream(pool, stream, length)?;
        let map = self
            .maps
            .get(stream)
            .ok_or_else(|| invalid("copy stream is outside the shape-verified closure"))?;
        let fingerprint = self
            .stream_states
            .get(stream)
            .ok_or_else(|| invalid("shape-verified copy stream has no fingerprint"))?;
        Ok(AuthenticatedStream::from_verified_fingerprint(
            file,
            Arc::clone(map),
            *fingerprint,
        )?)
    }

    pub(crate) fn open_object(
        &self,
        pool: &StoragePool,
        object: &ObjectDigest,
    ) -> Result<File, LibVmError> {
        let held = self
            .object_pins
            .get(object)
            .ok_or_else(|| invalid("object is outside the shape-verified retained roles"))?;
        bind_hashed(held, self.object_states.get(object))?;
        let file = pool.open_object(object)?;
        bind_hashed(&file, self.object_states.get(object))?;
        Ok(file)
    }

    fn authenticate(
        &self,
        pool: &StoragePool,
        warm: Option<&BTreeMap<StreamId, SourceFingerprint>>,
    ) -> Result<AuthenticatedClosure, LibVmError> {
        for (file, expected) in &self.receipt_pins {
            bind_held(file, *expected)?;
        }
        if let Some(lower) = &self.held_lower {
            lower.recheck()?;
        }
        let held = self.retained_descriptors();
        if self.retain {
            crate::storage::limits::preflight_fd_budget(held + 1)
                .map_err(crate::storage::StorageError::from)?;
        }
        let parallel = self
            .ram_stream
            .is_some_and(|ram| self.maps.contains_key(&ram))
            && admit_closure_lane(held);
        let contents = self.contents.iter().collect::<Vec<_>>();
        let closure = ClosureVerification {
            pool,
            contents: &contents,
            objects: &self.objects,
            retain: self.retain,
            ram_stream: self.ram_stream,
            stream_states: &self.stream_states,
            object_states: &self.object_states,
            maps: Some(&self.maps),
            warm,
            pin: &self.pin,
        }
        .authenticate(parallel)?;
        recheck_closure(&self.fingerprints)?;
        for (file, expected) in &self.receipt_pins {
            bind_held(file, *expected)?;
        }
        if let Some(lower) = &self.held_lower {
            lower.recheck()?;
        }
        Ok(closure)
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_artifact_shape(
    pool: &StoragePool,
    bytes: &[u8],
    contents: &[&SnapshotStream],
    mut objects: BTreeSet<ObjectDigest>,
    retained_objects: BTreeSet<ObjectDigest>,
    digest: Option<ObjectDigest>,
    retain: bool,
    ram_stream: Option<StreamId>,
    deferred_maps: &BTreeSet<StreamId>,
    pin: Arc<dyn Send + Sync>,
) -> Result<ShapeVerifiedClosure, LibVmError> {
    let record_digest = ObjectDigest::of_bytes(bytes);
    if digest.is_some_and(|digest| digest != record_digest) {
        return Err(invalid("snapshot object contradicts its catalog record"));
    }
    if digest.is_some() {
        objects.insert(record_digest);
    }
    // Complete presence/length checks precede even map metadata reads.
    let mut fingerprints = Vec::new();
    let mut stream_states = BTreeMap::new();
    for content in contents {
        let file = pool.open_stream(&content.stream)?;
        let metadata = file.metadata()?;
        if metadata.len() != content.length {
            return Err(invalid("snapshot stream length contradicts content"));
        }
        let before = SourceFingerprint::new(&metadata);
        if stream_states.insert(content.stream, before).is_none() {
            fingerprints.push((pool.stream_path(&content.stream), before));
        }
    }
    if retain {
        crate::storage::limits::preflight_fd_budget(
            (stream_states.len() + retained_objects.len()) as u64 + 1,
        )
        .map_err(crate::storage::StorageError::from)?;
    }
    let mut object_pins = BTreeMap::new();
    let mut object_states = BTreeMap::new();
    for object in objects
        .iter()
        .filter(|object| digest.is_some() || **object != record_digest)
    {
        let file = pool.open_object(object)?;
        let metadata = file.metadata()?;
        if *object == record_digest && metadata.len() != bytes.len() as u64 {
            return Err(invalid(
                "snapshot record length contradicts its catalog record",
            ));
        }
        let before = SourceFingerprint::new(&metadata);
        object_states.insert(*object, before);
        fingerprints.push((pool.object_path(object), before));
        if retain && retained_objects.contains(object) {
            object_pins.insert(*object, file);
        }
    }
    let mut maps = BTreeMap::new();
    read_shape_maps(
        pool,
        contents
            .iter()
            .copied()
            .filter(|content| !deferred_maps.contains(&content.stream)),
        &mut maps,
        Arc::clone(&pin),
    )?;
    recheck_closure(&fingerprints)?;
    Ok(ShapeVerifiedClosure {
        contents: contents.iter().map(|content| (*content).clone()).collect(),
        maps,
        objects,
        object_pins,
        retain,
        ram_stream,
        fingerprints,
        stream_states,
        local_lower: None,
        held_lower: None,
        receipt_pins: Vec::new(),
        receipt_maps: BTreeSet::new(),
        pin,
        object_states,
    })
}

fn read_shape_maps<'a>(
    pool: &StoragePool,
    contents: impl Iterator<Item = &'a SnapshotStream>,
    maps: &mut BTreeMap<StreamId, Arc<crate::storage::map::AuthenticatedMap>>,
    pin: Arc<dyn Send + Sync>,
) -> Result<(), LibVmError> {
    for content in contents {
        if maps.contains_key(&content.stream) {
            continue;
        }
        let map = load_root_map(pool, content, Arc::clone(&pin))?;
        maps.insert(content.stream, Arc::new(map));
    }
    Ok(())
}

fn stream_role(content: &SnapshotStream) -> Result<vm_spec::stream_map::StreamRole, LibVmError> {
    match content.chunk_size {
        65536 => Ok(vm_spec::stream_map::StreamRole::Ram),
        8388608 => Ok(vm_spec::stream_map::StreamRole::Disk),
        _ => Err(invalid("unsupported stream identity profile")),
    }
}

fn load_root_map(
    pool: &StoragePool,
    content: &SnapshotStream,
    pin: Arc<dyn Send + Sync>,
) -> Result<crate::storage::map::AuthenticatedMap, LibVmError> {
    let bytes = pool.read_object(&content.map, vm_spec::stream_map::MAX_ROOT_BYTES as u64)?;
    let root = vm_spec::stream_map::StreamRoot::decode(&bytes).map_err(invalid)?;
    if ObjectDigest::of_bytes(&bytes) != content.map
        || root.id().as_bytes() != content.stream.as_bytes()
        || root.length() != content.length
        || root.chunk_size().bytes() != content.chunk_size
    {
        return Err(invalid("snapshot root contradicts its semantic stream"));
    }
    Ok(crate::storage::map::AuthenticatedMap::from_admitted_root(
        root,
        stream_role(content)?,
        pool.map_authority(pin)?,
    )?)
}

/// Recovery, export and handoff authenticate every stream byte without receipts.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_artifact_closure(
    pool: &StoragePool,
    bytes: &[u8],
    contents: &[&SnapshotStream],
    objects: BTreeSet<ObjectDigest>,
    retained_objects: BTreeSet<ObjectDigest>,
    digest: Option<ObjectDigest>,
    retain: bool,
    ram_stream: Option<StreamId>,
    pin: Arc<dyn Send + Sync>,
) -> Result<(ClosureFingerprints, AuthenticatedClosure), LibVmError> {
    let shape = verify_artifact_shape(
        pool,
        bytes,
        contents,
        objects,
        retained_objects,
        digest,
        retain,
        ram_stream,
        &BTreeSet::new(),
        pin,
    )?;
    let closure = shape.authenticate(pool, None)?;
    Ok((shape.fingerprints, closure))
}

const CLOSURE_LANE_STACK_BYTES: usize = 1 << 20;

fn closure_lane_budget_fits(
    held_descriptors: u64,
    limits: crate::storage::limits::FileDescriptorLimits,
) -> bool {
    let Some(descriptors) = held_descriptors.checked_add(2) else {
        return false;
    };
    crate::storage::limits::check_fd_budget(descriptors, limits.soft, limits.hard).is_ok()
}

fn admit_closure_lane(held_descriptors: u64) -> bool {
    let admission = (|| -> Result<bool, LibVmError> {
        let descriptors = held_descriptors
            .checked_add(2)
            .ok_or_else(|| invalid("closure lane descriptor budget overflow"))?;
        let limits = crate::storage::limits::preflight_fd_budget(descriptors)
            .map_err(crate::storage::StorageError::from)?;
        Ok(closure_lane_budget_fits(held_descriptors, limits))
    })();
    match admission {
        Ok(admitted) => admitted,
        Err(error) => {
            tracing::debug!(%error, "optional closure authentication lane not admitted");
            false
        }
    }
}

#[derive(Clone, Copy)]
enum ClosureLane {
    All,
    Ram(StreamId),
    Other(StreamId),
}

struct ClosureVerification<'a> {
    pool: &'a StoragePool,
    contents: &'a [&'a SnapshotStream],
    objects: &'a BTreeSet<ObjectDigest>,
    retain: bool,
    ram_stream: Option<StreamId>,
    stream_states: &'a BTreeMap<StreamId, SourceFingerprint>,
    object_states: &'a BTreeMap<ObjectDigest, SourceFingerprint>,
    maps: Option<&'a BTreeMap<StreamId, Arc<crate::storage::map::AuthenticatedMap>>>,
    warm: Option<&'a BTreeMap<StreamId, SourceFingerprint>>,
    pin: &'a Arc<dyn Send + Sync>,
}

impl ClosureVerification<'_> {
    fn authenticate(&self, parallel: bool) -> Result<AuthenticatedClosure, LibVmError> {
        let Some((ram_index, ram)) =
            self.contents
                .iter()
                .enumerate()
                .find_map(|(index, content)| {
                    (Some(content.stream) == self.ram_stream).then_some((index, content.stream))
                })
        else {
            return self.members(ClosureLane::All).map_err(|(_, error)| error);
        };
        if !parallel {
            return self.members(ClosureLane::All).map_err(|(_, error)| error);
        }
        std::thread::scope(|scope| {
            let lane = match std::thread::Builder::new()
                .stack_size(CLOSURE_LANE_STACK_BYTES)
                .spawn_scoped(scope, || self.members(ClosureLane::Ram(ram)))
            {
                Ok(lane) => lane,
                Err(error) => {
                    tracing::debug!(%error, "optional closure authentication thread unavailable");
                    return self.members(ClosureLane::All).map_err(|(_, error)| error);
                }
            };
            let other = self.members(ClosureLane::Other(ram));
            let ram = match lane.join() {
                Ok(result) => result,
                Err(_) => Err((
                    ram_index,
                    std::io::Error::other("RAM authentication lane panicked").into(),
                )),
            };
            match (other, ram) {
                (Err((other_index, other)), Err((ram_index, ram))) => {
                    Err(if other_index < ram_index { other } else { ram })
                }
                (Err((_, error)), _) | (_, Err((_, error))) => Err(error),
                (Ok(mut other), Ok(ram)) => {
                    other.streams.extend(ram.streams);
                    Ok(other)
                }
            }
        })
    }

    fn members(&self, lane: ClosureLane) -> Result<AuthenticatedClosure, (usize, LibVmError)> {
        let mut closure = AuthenticatedClosure {
            streams: BTreeMap::new(),
        };
        let mut verified_streams = BTreeSet::new();
        for (index, content) in self.contents.iter().enumerate() {
            match lane {
                ClosureLane::Ram(ram) if content.stream != ram => continue,
                ClosureLane::Other(ram) if content.stream == ram => continue,
                _ => {}
            }
            let result = (|| -> Result<(), LibVmError> {
                let map = if let Some(maps) = self.maps {
                    Arc::clone(
                        maps.get(&content.stream)
                            .ok_or_else(|| invalid("closure map is missing"))?,
                    )
                } else {
                    Arc::new(load_root_map(self.pool, content, Arc::clone(self.pin))?)
                };
                if map.id() != content.stream || map.length() != content.length {
                    return Err(invalid("snapshot stream/map/backing contradiction"));
                }
                if verified_streams.insert(content.stream) {
                    let verified = match self.warm.and_then(|warm| warm.get(&content.stream)) {
                        Some(fingerprint) => AuthenticatedStream::from_verified_fingerprint(
                            self.pool.open_stream(&content.stream)?,
                            Arc::clone(&map),
                            *fingerprint,
                        )?,
                        None => {
                            let file = self.pool.open_stream(&content.stream)?;
                            crate::storage::stream::StreamHasher::new(map.chunk_size())
                                .verify_expected_map(&file, &map)
                                .map_err(|error| {
                                    invalid(format!("stream {}: {error}", content.stream))
                                })?;
                            let fingerprint = SourceFingerprint::new(&file.metadata()?);
                            AuthenticatedStream::from_verified_fingerprint(
                                file,
                                Arc::clone(&map),
                                fingerprint,
                            )?
                        }
                    };
                    if verified.map() != map.as_ref() {
                        return Err(invalid("snapshot stream/map/backing contradiction"));
                    }
                    bind_hashed(verified.file(), self.stream_states.get(&content.stream))?;
                    if self.retain {
                        closure.streams.insert(content.stream, verified);
                    }
                }
                Ok(())
            })();
            result.map_err(|error| (index, error))?;
        }
        if !matches!(lane, ClosureLane::Ram(_)) {
            let maps = self
                .contents
                .iter()
                .map(|stream| stream.map)
                .collect::<BTreeSet<_>>();
            for (index, object) in self.objects.iter().enumerate() {
                if maps.contains(object) {
                    continue;
                }
                let result = (|| -> Result<(), LibVmError> {
                    let file = self.pool.verify_object(object)?;
                    bind_hashed(&file, self.object_states.get(object))?;
                    Ok(())
                })();
                result.map_err(|error| (self.contents.len() + index, error))?;
            }
        }
        Ok(closure)
    }
}

/// Equal pre-hash and post-hash states (ctime cannot be forged by an owner)
/// bind the held descriptor's current bytes to the bytes just hashed.
fn bind_hashed(
    file: &File,
    before: Option<&SourceFingerprint>,
) -> Result<SourceFingerprint, LibVmError> {
    let current = SourceFingerprint::new(&file.metadata()?);
    if before != Some(&current) {
        return Err(invalid(
            "authenticated snapshot closure changed during verification",
        ));
    }
    Ok(current)
}

pub(crate) struct RecordInput {
    parent: OwnedDirectory,
    directory: OwnedDirectory,
    name: String,
}
impl RecordInput {
    pub(crate) fn new(images: &Path, operation: Uuid, bytes: &[u8]) -> Result<Self, LibVmError> {
        let parent =
            OwnedDirectory::open_existing_root(&images.join("tmp").join(operation.to_string()))?
                .ok_or_else(|| invalid("registered snapshot operation staging is missing"))?;
        let name = format!("snapshot-record-{}", Uuid::new_v4());
        let directory = parent
            .create_dir(&name)?
            .ok_or_else(|| invalid("record staging collision"))?;
        let input = Self {
            parent,
            directory,
            name,
        };
        input.directory.write_file("record", bytes)?;
        Ok(input)
    }
    pub(crate) fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("record")
    }
}
impl Drop for RecordInput {
    fn drop(&mut self) {
        if let Err(error) = self.parent.remove_tree(&self.name) {
            tracing::warn!(%error, "snapshot record input cleanup deferred");
        }
        if let Err(error) = self.parent.sync() {
            tracing::warn!(%error, "snapshot record input cleanup synchronization deferred");
        }
    }
}

pub(crate) async fn publish_map(
    pool: &StoragePool,
    store: &Store,
    operation: Uuid,
    map: &crate::storage::map::AuthenticatedMap,
) -> Result<SnapshotStream, LibVmError> {
    let map = store
        .admit_published_map_root(operation, map)
        .await?
        .into_map();
    store
        .pin_published_storage_dependencies(operation, &[map.id()], &[])
        .await?;
    let root = ObjectDigest::from_sha256(*map.id().as_bytes());
    if pool.read_object(&root, vm_spec::stream_map::MAX_ROOT_BYTES as u64)?
        != map.canonical_bytes()?
    {
        return Err(invalid(
            "published stream root changed before catalog transfer",
        ));
    }
    Ok(SnapshotStream {
        stream: map.id(),
        map: root,
        chunk_size: map.chunk_size().bytes(),
        length: map.length(),
    })
}
#[cfg(test)]
pub(crate) mod tests {
    use crate::paths::LocalPaths;
    use crate::storage::identity::ObjectDigest;
    use crate::storage::pool::StoragePool;
    use crate::store::models::snapshot::{tests::record, SnapshotRecord};
    use crate::store::snapshot_store::{SnapshotRef, SnapshotStore};
    use crate::store::Store;
    use std::io::{BufRead, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::Arc;

    #[cfg(target_os = "linux")]
    fn shape_map_for_test(
        pool: &StoragePool,
        consumer: &crate::store::snapshot_store::SnapshotConsumer,
        content: &crate::store::models::snapshot::SnapshotStream,
    ) -> crate::storage::map::AuthenticatedMap {
        crate::store::snapshot_store::load_root_map(
            pool,
            content,
            Arc::new(consumer.lease.duplicate().unwrap()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn shape_consumer_materializes_evicted_streams_under_its_lease() {
        let bytes = [7; 512];
        let (_temporary, store, record, info, owner, _) =
            crate::store::stream_representation::tests::retained_paginated(
                &bytes,
                oci::vm_artifact::wire::MAX_PAGE_ENTRIES,
            )
            .await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(store.evict_flat_materializations().await.unwrap(), 512);
        let path = pool.stream_path(&record.root.stream.stream);
        assert!(!path.exists());

        let snapshots = SnapshotStore::from_store(store.clone());
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        assert!(consumer.closure.is_none());
        assert!(path.exists(), "materialization must precede shape binding");
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        let source = shape
            .open_stream(&pool, &record.root.stream.stream, record.root.stream.length)
            .unwrap();
        assert_eq!(source.metadata().unwrap().len(), bytes.len() as u64);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(store.evict_flat_materializations().await.unwrap(), 0);
        let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_operation")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            operations, 1,
            "materialization must reuse the consumer lease"
        );
        let verified: i64 = sqlx::query_scalar("SELECT count(*) FROM verified_object")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            verified, 0,
            "shape consumption must not authenticate the closure"
        );
        drop(source);
        drop(shape);
        drop(consumer);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(store.evict_flat_materializations().await.unwrap(), 512);
        assert!(
            !path.exists(),
            "reconstructed flats remain disposable cache"
        );
    }

    #[tokio::test]
    async fn shape_consumer_rejects_missing_chunk_during_materialization() {
        let bytes = [7; 512];
        let (_temporary, store, record, info, owner, _) =
            crate::store::stream_representation::tests::retained_paginated(
                &bytes,
                oci::vm_artifact::wire::MAX_PAGE_ENTRIES,
            )
            .await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(store.evict_flat_materializations().await.unwrap(), 512);
        let chunk = pool.object_path(&ObjectDigest::of_bytes(&bytes));
        std::fs::remove_file(&chunk).unwrap();

        let error = SnapshotStore::from_store(store.clone())
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .err()
            .unwrap();
        assert!(matches!(
            &error,
            crate::LibVmError::Storage(crate::storage::StorageError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
        let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_operation")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(operations, 0, "failed consumers must release their roots");
    }

    #[tokio::test]
    async fn restore_inspection_shape_defers_writable_maps_and_completes_before_copy() {
        let (_temporary, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let inspection = snapshots.prepare_restore_shape(&consumer).await.unwrap();
        let stream = record.root.stream.stream;
        assert!(inspection.shape().stream_map(&stream).is_err());
        let held = inspection.shape().retained_descriptors();
        let shape = inspection.complete(&snapshots.store.images_dir).unwrap();
        assert_eq!(shape.stream_map(&stream).unwrap().id(), stream);
        assert_eq!(shape.retained_descriptors(), held);
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        assert!(shape
            .open_copy_source(&pool, &stream, record.root.stream.length)
            .is_ok());
    }

    #[tokio::test]
    async fn restore_inspection_shape_rejects_writable_map_changed_before_join() {
        use std::os::unix::fs::PermissionsExt;
        let (_temporary, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let inspection = snapshots.prepare_restore_shape(&consumer).await.unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let path = pool.object_path(&record.root.stream.map);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"malformed map").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(inspection.complete(&snapshots.store.images_dir).is_err());
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn watch_stream_reads(path: &std::path::Path) -> nix::sys::inotify::Inotify {
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        let watcher = Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK).unwrap();
        watcher.add_watch(path, AddWatchFlags::IN_ACCESS).unwrap();
        watcher
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn observed_stream_read(watcher: &nix::sys::inotify::Inotify) -> bool {
        match watcher.read_events() {
            Ok(events) => events.iter().any(|event| {
                event
                    .mask
                    .contains(nix::sys::inotify::AddWatchFlags::IN_ACCESS)
            }),
            Err(nix::errno::Errno::EAGAIN) => false,
            Err(error) => panic!("reading stream access observations: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_publication_seeds_ram_and_disk_receipts_for_first_restore() {
        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let snapshots = &fixture.snapshots;
        let info = snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
            &consumer.record.memory
        else {
            panic!("live fixture");
        };
        let ram = execution.memory.stream;
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let disk = consumer.record.root.stream.stream;
        let mut watchers = Vec::new();
        for stream in [ram, disk] {
            let receipts: i64 =
                sqlx::query_scalar("SELECT count(*) FROM verified_object WHERE stream_sha256=?1")
                    .bind(stream.to_string())
                    .fetch_one(&snapshots.store.pool)
                    .await
                    .unwrap();
            assert_eq!(receipts, 1, "held producer authority seeds local trust");
            watchers.push(watch_stream_reads(&pool.stream_path(&stream)));
            let content = consumer
                .record
                .streams()
                .find(|content| content.stream == stream)
                .unwrap();
            let map = shape_map_for_test(&pool, &consumer, content);
            for node in map.nodes() {
                watchers.push(watch_stream_reads(&pool.object_path(&node.unwrap().digest)));
            }
        }
        let (_, dependencies) = consumer.record.content_dependencies().unwrap();
        for object in dependencies {
            if !consumer
                .record
                .streams()
                .any(|content| content.map == object)
            {
                watchers.push(watch_stream_reads(&pool.object_path(&object)));
            }
        }
        for watcher in &watchers {
            observed_stream_read(watcher);
        }
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        assert_eq!(
            shape.stream_map(&ram).unwrap().root().id().as_bytes(),
            ram.as_bytes()
        );
        let mut publications = std::collections::BTreeMap::new();
        for content in consumer.record.streams() {
            let file = shape
                .open_stream(&pool, &content.stream, content.length)
                .unwrap();
            let fingerprint =
                crate::storage::identity_file::SourceFingerprint::new(&file.metadata().unwrap());
            let (publication, roots) = pool
                .publish_sealed_stream_for_catalog(
                    &file,
                    shape.stream_map(&content.stream).unwrap(),
                    Some(fingerprint),
                    crate::storage::pool::SealedStreamPublicationMode::CopyAllowed,
                )
                .unwrap();
            publications.insert(content.stream, publication);
            drop(roots);
        }
        crate::store::snapshot_store::verify_publication_closure(
            &snapshots.store,
            &pool,
            &consumer.record,
            &publications,
            consumer.operation_id,
        )
        .await
        .unwrap();
        drop(snapshots.authenticate_closure_bytes(shape).await.unwrap());
        for watcher in &watchers {
            assert!(
                !observed_stream_read(watcher),
                "first restore must not read RAM, disk, or retained maps"
            );
        }
        assert_eq!(execution.memory.map.as_bytes(), ram.as_bytes());
        drop(snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap());
        for watcher in &watchers {
            assert!(
                observed_stream_read(watcher),
                "transport must still authenticate bytes"
            );
        }
    }

    #[tokio::test]
    async fn live_publication_corruption_is_rejected_by_cold_restore_and_export() {
        use std::os::unix::fs::{FileExt, PermissionsExt};

        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let snapshots = &fixture.snapshots;
        let info = snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
            &consumer.record.memory
        else {
            panic!("live fixture");
        };
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let path = pool.stream_path(&execution.memory.stream);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all_at(&[0xff], execution.memory.length - 1)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            execution.memory.length
        );
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        let error = snapshots
            .authenticate_closure_bytes(shape)
            .await
            .err()
            .unwrap();
        let expected = vm_spec::capture::Sha256Digest::of_bytes(&[0x32; 4096]).to_string();
        let mut changed = [0x32; 4096];
        changed[4095] = 0xff;
        let actual = vm_spec::capture::Sha256Digest::of_bytes(&changed).to_string();
        assert!(
            matches!(&error, crate::LibVmError::InvalidStorageRecord { record: "snapshot", message }
            if message.contains(&execution.memory.stream.to_string())
                && message.contains("unit 65536 bytes chunk 0 bytes 0..4096")
                && message.contains(&expected) && message.contains(&actual)),
            "{error}"
        );
        assert!(snapshots.consume(&SnapshotRef::Id(info.id)).await.is_err());
        let receipts: i64 =
            sqlx::query_scalar("SELECT count(*) FROM verified_object WHERE stream_sha256=?1")
                .bind(execution.memory.stream.to_string())
                .fetch_one(&snapshots.store.pool)
                .await
                .unwrap();
        assert_eq!(
            receipts, 1,
            "failed authentication must not refresh the producer receipt"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_closure_shape_checks_state_length_without_reading_ram() {
        use crate::store::models::snapshot::SnapshotMemoryState;
        use std::os::unix::fs::PermissionsExt;

        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let snapshots = &fixture.snapshots;
        let info = snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let SnapshotMemoryState::Included { execution } = &consumer.record.memory else {
            panic!("live fixture");
        };
        let watcher = watch_stream_reads(&pool.stream_path(&execution.memory.stream));
        drop(snapshots.verify_closure_shape(&consumer).await.unwrap());
        assert!(!observed_stream_read(&watcher));
        let path = pool.object_path(&execution.devices);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(1)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let error = snapshots
            .verify_closure_shape(&consumer)
            .await
            .err()
            .unwrap();
        assert!(error
            .to_string()
            .contains("state length contradicts capture inventory"));
        assert!(!observed_stream_read(&watcher));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_closure_authentication_reuses_unchanged_stream_without_reading() {
        let (_temp, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let watcher = watch_stream_reads(&pool.stream_path(&record.root.stream.stream));
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        let receipt = shape
            .open_copy_source(&pool, &record.root.stream.stream, record.root.stream.length)
            .unwrap();
        assert_eq!(
            receipt.map(),
            shape.stream_map(&record.root.stream.stream).unwrap()
        );
        let held = shape.retained_descriptors();
        let object_pins = shape.object_pins.len() as u64;
        assert!(
            !observed_stream_read(&watcher),
            "shape must not read stream bytes"
        );
        let cold = snapshots.authenticate_closure_bytes(shape).await.unwrap();
        assert_eq!(held, cold.streams.len() as u64 + object_pins);
        drop(cold);
        assert!(
            observed_stream_read(&watcher),
            "cold authentication must read"
        );

        // Recreate the collection handle: reuse authority is real SQLite state,
        // not process-local memory or a previously held authenticated descriptor.
        let reopened = SnapshotStore::from_store(snapshots.store.clone());
        let shape = reopened.verify_closure_shape(&consumer).await.unwrap();
        let closure = reopened.authenticate_closure_bytes(shape).await.unwrap();
        assert_eq!(closure.streams.len(), 1);
        assert!(
            !observed_stream_read(&watcher),
            "warm authentication must not read"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM verified_object")
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);

        // The full consumer path used by transport must never consult warm rows.
        let transported = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        assert!(
            observed_stream_read(&watcher),
            "transport must authenticate every byte"
        );
        drop(transported);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_closure_authentication_rereads_after_touch_or_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let (_temp, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let path = pool.stream_path(&record.root.stream.stream);
        let watcher = watch_stream_reads(&path);
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        drop(snapshots.authenticate_closure_bytes(shape).await.unwrap());
        assert!(observed_stream_read(&watcher));

        for chmod in [false, true] {
            let before = crate::storage::identity_file::SourceFingerprint::new(
                &std::fs::metadata(&path).unwrap(),
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
            if chmod {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            } else {
                std::fs::File::open(&path)
                    .unwrap()
                    .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now()))
                    .unwrap();
            }
            let after = crate::storage::identity_file::SourceFingerprint::new(
                &std::fs::metadata(&path).unwrap(),
            );
            assert_ne!(before.verification_key(), after.verification_key());
            let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
            drop(snapshots.authenticate_closure_bytes(shape).await.unwrap());
            assert!(
                observed_stream_read(&watcher),
                "metadata changes require a full read"
            );
            let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
            drop(snapshots.authenticate_closure_bytes(shape).await.unwrap());
            assert!(
                !observed_stream_read(&watcher),
                "updated receipt must be reusable"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stale_verified_object_receipt_cannot_hide_changed_stream_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let (_temp, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let path = pool.stream_path(&record.root.stream.stream);
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        drop(snapshots.authenticate_closure_bytes(shape).await.unwrap());
        let old: (i64, i64) = sqlx::query_as(
            "SELECT ctime_sec,ctime_nsec FROM verified_object WHERE stream_sha256=?1",
        )
        .bind(record.root.stream.stream.to_string())
        .fetch_one(&snapshots.store.pool)
        .await
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [0x99; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let current = crate::storage::identity_file::SourceFingerprint::new(
            &std::fs::metadata(&path).unwrap(),
        )
        .verification_key();
        assert_ne!(old, (current[4], current[5]));
        let watcher = watch_stream_reads(&path);
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        let error = snapshots
            .authenticate_closure_bytes(shape)
            .await
            .err()
            .unwrap();
        let expected = vm_spec::capture::Sha256Digest::of_bytes(&[0x5a; 512]).to_string();
        let actual = vm_spec::capture::Sha256Digest::of_bytes(&[0x99; 512]).to_string();
        assert!(
            matches!(&error, crate::LibVmError::InvalidStorageRecord { record: "snapshot", message }
            if message.contains(&record.root.stream.stream.to_string())
                && message.contains("unit 8388608 bytes chunk 0 bytes 0..512")
                && message.contains(&expected) && message.contains(&actual)),
            "{error}"
        );
        assert!(observed_stream_read(&watcher));
        let stored: (i64, i64) = sqlx::query_as(
            "SELECT ctime_sec,ctime_nsec FROM verified_object WHERE stream_sha256=?1",
        )
        .bind(record.root.stream.stream.to_string())
        .fetch_one(&snapshots.store.pool)
        .await
        .unwrap();
        assert_eq!(stored, old, "failed authentication cannot refresh trust");
        // Silent same-ctime corruption is outside ADR 0021's local trust
        // boundary. Explicit verify, export and handoff ignore warm receipts.
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn closure_shape_rejects_missing_or_wrong_length_before_byte_reads() {
        use std::os::unix::fs::PermissionsExt;

        for missing in [false, true] {
            let (_temp, snapshots, record, operation, _lease) = fixture("snapshot").await;
            let info = snapshots.publish(&record, operation, None).await.unwrap();
            let consumer = snapshots
                .consume_shape(&SnapshotRef::Id(info.id))
                .await
                .unwrap();
            let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
            let path = pool.stream_path(&record.root.stream.stream);
            let watcher = watch_stream_reads(&path);
            let maps = watch_stream_reads(&pool.object_path(&record.root.stream.map));
            if missing {
                let crate::BootProfile::LinuxDirect {
                    binding: crate::BootBinding::Pinned { kernel, .. },
                    ..
                } = &record.boot
                else {
                    panic!("fixture boot is pinned");
                };
                std::fs::remove_file(pool.object_path(kernel)).unwrap();
            } else {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(513)
                    .unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
            assert!(snapshots.verify_closure_shape(&consumer).await.is_err());
            assert!(!observed_stream_read(&watcher));
            assert!(
                !observed_stream_read(&maps),
                "presence checks precede map metadata reads"
            );
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM verified_object")
                .fetch_one(&snapshots.store.pool)
                .await
                .unwrap();
            assert_eq!(count, 0);
        }
    }

    #[tokio::test]
    async fn retained_capture_plan_is_exact_and_rejects_a_different_request() {
        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
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
        let plan =
            crate::store::snapshot_store::capture_plan(&fixture.snapshots.store, info.id, capture)
                .await
                .unwrap();
        assert_eq!(plan, fixture.reservation.record.plan);
        let mut foreign = plan;
        foreign.dirty_crossover_percent += 1;
        let mut tx = fixture
            .snapshots
            .store
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .unwrap();
        let row: (String, Vec<u8>) = sqlx::query_as(
            "SELECT evidence_digest,evidence_bytes FROM snapshot_capture_provenance WHERE capture_id=?1",
        ).bind(capture.to_string()).fetch_one(&mut *tx).await.unwrap();
        sqlx::query("DELETE FROM snapshot_capture_provenance WHERE capture_id=?1")
            .bind(capture.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO snapshot_capture_provenance(capture_id,snapshot_id,evidence_digest,evidence_bytes,plan_bytes) VALUES(?1,?2,?3,?4,?5)")
            .bind(capture.to_string()).bind(info.id.to_string()).bind(row.0).bind(row.1)
            .bind(foreign.canonical_bytes().unwrap()).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        assert!(crate::store::snapshot_store::capture_plan(
            &fixture.snapshots.store,
            info.id,
            capture,
        )
        .await
        .is_err());
        assert!(fixture
            .snapshots
            .inspect(&SnapshotRef::Id(info.id))
            .await
            .is_err());
    }

    pub(crate) async fn fixture(
        kind: &str,
    ) -> (
        tempfile::TempDir,
        SnapshotStore,
        SnapshotRecord,
        uuid::Uuid,
        crate::storage::locks::StorageLock,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let (operation, lease) = store.begin_stopped_operation(kind, &[], &[]).await.unwrap();
        pool.create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let disk = temp.path().join("disk");
        std::fs::write(&disk, [0x5a; 512]).unwrap();
        let (stream, roots) = pool.publish_stream_for_catalog(&disk).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[stream.id], &[])
            .await
            .unwrap();
        drop(roots);
        let map = crate::store::snapshot_store::publish_map(&pool, &store, operation, &stream.map)
            .await
            .unwrap();
        let kernel_path = temp.path().join("kernel");
        std::fs::write(&kernel_path, b"exact boot fixture").unwrap();
        let (kernel, roots) = pool.publish_object_for_catalog(&kernel_path).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[kernel.digest])
            .await
            .unwrap();
        drop(roots);
        let mut record = record(stream.id, map.map, kernel.digest);
        record.root.stream = map;
        let crate::BootProfile::LinuxDirect { binding, .. } = &record.boot else {
            panic!("direct fixture")
        };
        let input = crate::store::snapshot_store::RecordInput::new(
            &store.images_dir,
            operation,
            &binding.canonical_bytes().unwrap(),
        )
        .unwrap();
        let (bundle, roots) = pool.publish_object_for_catalog(&input.path()).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[bundle.digest])
            .await
            .unwrap();
        drop(roots);
        (
            temp,
            SnapshotStore::from_store(Arc::new(store)),
            record,
            operation,
            lease,
        )
    }

    #[test]
    fn snapshot_references_are_bare_names_ids_or_registry_spellings() {
        let id = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            id.parse::<SnapshotRef>().unwrap(),
            SnapshotRef::Id(id.parse().unwrap())
        );
        for name in ["hello", "abc", "ghcr.io/team/app:1"] {
            let reference = name.parse::<SnapshotRef>().unwrap();
            assert_eq!(reference, SnapshotRef::Name(name.into()));
            assert_eq!(reference.to_string(), name);
        }
        assert_eq!(
            SnapshotRef::Id(id.parse().unwrap()).to_string(),
            id,
            "an id prints as its full spelling"
        );
        for invalid in ["", "sha256:abcd", "Hello", "a b", "fork:child"] {
            assert!(
                matches!(
                    invalid.parse::<SnapshotRef>(),
                    Err(crate::LibVmError::InvalidName { .. })
                ),
                "{invalid:?}"
            );
        }
    }

    /// A catalog row whose id starts with `prefix`, for prefix resolution.
    async fn forged_snapshot_row(snapshots: &SnapshotStore, id: &str) {
        sqlx::query("INSERT INTO storage_snapshot(id,record_digest,record_bytes,created_at) VALUES(?1,?1,?2,1)")
            .bind(id)
            .bind(br#"{"schema":1,"root":{"stream":{"chunkSize":8388608}}}"#.as_slice())
            .execute(&snapshots.store.pool)
            .await
            .unwrap();
    }

    async fn resolve(
        snapshots: &SnapshotStore,
        reference: &str,
    ) -> Result<crate::storage::identity::SnapshotId, crate::LibVmError> {
        let mut connection = snapshots.store.pool.acquire().await.unwrap();
        crate::store::snapshot_store::resolve_snapshot(
            &mut connection,
            &reference.parse::<SnapshotRef>().unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn snapshot_names_ids_and_unique_prefixes_resolve_and_ambiguous_prefixes_error() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots
            .publish(&record, operation, Some("hello"))
            .await
            .unwrap();
        assert_eq!(info.names, ["hello"]);
        let hex = info.id.to_string()["sha256:".len()..].to_owned();
        for reference in [
            "hello".to_owned(),
            info.id.to_string(),
            hex.clone(),
            hex[..3].to_owned(),
        ] {
            assert_eq!(resolve(&snapshots, &reference).await.unwrap(), info.id);
            assert_eq!(
                snapshots
                    .inspect(&reference.parse().unwrap())
                    .await
                    .unwrap()
                    .id,
                info.id,
                "{reference}"
            );
        }
        // Two characters never abbreviate an id; they are only a name.
        assert!(matches!(
            resolve(&snapshots, &hex[..2]).await,
            Err(crate::LibVmError::SnapshotNotFound { .. })
        ));
        let flipped = if hex.as_bytes()[3] == b'0' { '1' } else { '0' };
        let sibling = format!("sha256:{}{flipped}{}", &hex[..3], &hex[4..]);
        forged_snapshot_row(&snapshots, &sibling).await;
        assert!(matches!(
            resolve(&snapshots, &hex[..3]).await,
            Err(crate::LibVmError::AmbiguousRecordPrefix { prefix, count: 2 }) if prefix == hex[..3]
        ));
        assert_eq!(resolve(&snapshots, &hex[..4]).await.unwrap(), info.id);
        // An exact name wins over an id prefix that spells the same.
        let mut tx = snapshots.store.pool.begin().await.unwrap();
        crate::store::snapshot_store::insert_name(&mut tx, &hex[..3], info.id)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(resolve(&snapshots, &hex[..3]).await.unwrap(), info.id);
        assert!(matches!(
            resolve(&snapshots, "missing").await,
            Err(crate::LibVmError::SnapshotNotFound { reference }) if reference == "missing"
        ));
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
    }

    #[tokio::test]
    async fn snapshot_names_with_registry_syntax_or_taken_by_another_snapshot_are_refused() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        for name in ["hello:v2", "team/app", "Hello", ""] {
            assert!(
                matches!(
                    snapshots.publish(&record, operation, Some(name)).await,
                    Err(crate::LibVmError::InvalidName { .. })
                ),
                "{name:?}"
            );
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_snapshot")
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "an invalid name refuses before publication");
        let info = snapshots
            .publish(&record, operation, Some("taken"))
            .await
            .unwrap();
        let mut other = record.clone();
        other.memory = crate::store::models::snapshot::SnapshotMemoryState::None {
            stop_outcome: crate::StorageStopOutcome::Forced,
        };
        assert!(matches!(
            snapshots.publish(&other, operation, Some("taken")).await,
            Err(crate::LibVmError::SnapshotNameConflict { name }) if name == "taken"
        ));
        assert!(snapshots
            .inspect(&SnapshotRef::Id(other.id().unwrap()))
            .await
            .is_err());
        assert_eq!(
            snapshots
                .inspect(&SnapshotRef::Name("taken".into()))
                .await
                .unwrap()
                .id,
            info.id
        );
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
    }

    #[tokio::test]
    async fn snapshot_publication_requires_completed_catalog_checkpoint() {
        let (_temp, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let mut reader = snapshots.store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM storage_snapshot")
            .fetch_one(&mut *reader)
            .await
            .unwrap();

        for _ in 0..2 {
            let error = snapshots
                .publish(&record, operation, Some("power-loss-stable"))
                .await
                .unwrap_err();
            assert!(
                matches!(error, crate::LibVmError::DurabilityPending),
                "{error}"
            );
        }
        reader.rollback().await.unwrap();
        let info = snapshots
            .publish(&record, operation, Some("power-loss-stable"))
            .await
            .unwrap();
        assert_eq!(info.names, vec!["power-loss-stable".to_owned()]);
    }

    #[tokio::test]
    async fn snapshot_rm_name_removes_one_name_and_the_last_name_removes_the_record() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        assert!(info.names.is_empty());
        let same = snapshots
            .publish(&record, operation, Some("one"))
            .await
            .unwrap();
        assert_eq!(same.id, info.id);
        let named = snapshots
            .publish(&record, operation, Some("two"))
            .await
            .unwrap();
        assert_eq!(named.names, ["one", "two"]);
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
        let removal = snapshots
            .remove(&SnapshotRef::Name("one".into()))
            .await
            .unwrap();
        assert_eq!(
            removal,
            crate::SnapshotRemoval {
                id: info.id,
                names: vec!["one".into()],
                record_removed: false,
            }
        );
        assert!(matches!(
            snapshots.inspect(&SnapshotRef::Name("one".into())).await,
            Err(crate::LibVmError::SnapshotNotFound { .. })
        ));
        let remaining = snapshots
            .inspect(&SnapshotRef::Name("two".into()))
            .await
            .unwrap();
        assert_eq!(remaining.id, info.id);
        assert_eq!(remaining.names, ["two"]);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(snapshots.consume(&SnapshotRef::Id(info.id)).await.is_ok());
        let removal = snapshots
            .remove(&SnapshotRef::Name("two".into()))
            .await
            .unwrap();
        assert_eq!(removal.names, ["two"]);
        assert!(removal.record_removed);
        assert!(matches!(
            snapshots.inspect(&SnapshotRef::Id(info.id)).await,
            Err(crate::LibVmError::SnapshotNotFound { .. })
        ));
        assert!(snapshots.list().await.unwrap().is_empty());
        snapshots.store.recover_image_cache().await.unwrap();
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
        assert!(!pool.object_path(&info.record_digest).exists());
    }

    #[tokio::test]
    async fn snapshot_rm_id_or_prefix_removes_the_record_and_every_name() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let mut unnamed = record.clone();
        unnamed.memory = crate::store::models::snapshot::SnapshotMemoryState::None {
            stop_outcome: crate::StorageStopOutcome::Forced,
        };
        let kept = snapshots.publish(&unnamed, operation, None).await.unwrap();
        snapshots
            .publish(&record, operation, Some("b"))
            .await
            .unwrap();
        let info = snapshots
            .publish(&record, operation, Some("a"))
            .await
            .unwrap();
        assert_eq!(info.names, ["a", "b"]);
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
        let removal = snapshots.remove(&SnapshotRef::Id(info.id)).await.unwrap();
        assert_eq!(
            removal,
            crate::SnapshotRemoval {
                id: info.id,
                names: vec!["a".into(), "b".into()],
                record_removed: true,
            }
        );
        let names: i64 = sqlx::query_scalar("SELECT count(*) FROM snapshot_name")
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(names, 0);
        assert!(matches!(
            snapshots.remove(&SnapshotRef::Id(info.id)).await,
            Err(crate::LibVmError::SnapshotNotFound { .. })
        ));
        assert!(matches!(
            snapshots.remove(&SnapshotRef::Name("a".into())).await,
            Err(crate::LibVmError::SnapshotNotFound { .. })
        ));
        // An unnamed record is removed by an id prefix.
        let prefix = kept.id.to_string()["sha256:".len()..][..12].to_owned();
        let removal = snapshots.remove(&SnapshotRef::Name(prefix)).await.unwrap();
        assert_eq!(removal.id, kept.id);
        assert!(removal.names.is_empty() && removal.record_removed);
        assert!(snapshots.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn snapshot_removed_record_leaves_a_machine_using_its_bytes_intact() {
        use crate::store::MachineStore;
        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let snapshots = fixture.snapshots.clone();
        let capture = fixture.reservation.record.capture_id;
        let info = snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        snapshots
            .record_capture_source(
                capture,
                crate::store::snapshot_store::CaptureSourceOutcome::Unknown,
            )
            .await
            .unwrap();
        snapshots
            .finish_capture_release(capture, true)
            .await
            .unwrap();
        let config = fixture.config.clone();
        drop(fixture.reservation);
        drop(fixture.launch);
        // Retire the launch so only the machine itself roots its storage.
        let launches = snapshots
            .store
            .launch_storage_operations(config.id)
            .await
            .unwrap();
        let [launch] = launches.as_slice() else {
            panic!("one launch: {launches:?}");
        };
        let mut stopped = snapshots
            .store
            .machine_state(config.id)
            .await
            .unwrap()
            .unwrap();
        stopped.status = crate::store::models::MachineRuntimeState::Stopped;
        stopped.run_id = None;
        stopped.updated_at = 2;
        assert!(snapshots
            .store
            .try_retire_launch_storage(
                launch.operation_id,
                launch.run_id,
                launch.storage_generation,
                &stopped,
                crate::StorageStopOutcome::Unknown,
            )
            .await
            .unwrap());
        let storage = snapshots
            .store
            .machine_storage(config.id)
            .await
            .unwrap()
            .unwrap();
        let machine = crate::store::cache_paths::storage_pool_dependencies(&storage).unwrap();
        let consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let (streams, objects) = consumer.record.content_dependencies().unwrap();
        snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
        drop(consumer);
        let shared = objects
            .intersection(&machine.objects)
            .copied()
            .collect::<Vec<_>>();
        assert!(!shared.is_empty(), "the machine shares the snapshot's boot");

        let removal = snapshots.remove(&SnapshotRef::Id(info.id)).await.unwrap();
        assert!(removal.record_removed);
        snapshots.store.recover_image_cache().await.unwrap();
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(snapshots.inspect(&SnapshotRef::Id(info.id)).await.is_err());
        assert!(!pool.object_path(&info.record_digest).exists());
        assert_eq!(
            snapshots.store.machine_storage(config.id).await.unwrap(),
            Some(storage)
        );
        for object in &machine.objects {
            assert!(pool.verify_object(object).is_ok(), "{object}");
        }
        for stream in &machine.streams {
            assert!(pool.verify_stream(stream).is_ok(), "{stream}");
        }

        snapshots.store.remove_machine(&config).await.unwrap();
        std::fs::remove_dir_all(&config.machine_dir).unwrap();
        snapshots.store.recover_image_cache().await.unwrap();
        for object in &shared {
            assert!(!pool.object_path(object).exists(), "{object}");
        }
        for stream in streams.intersection(&machine.streams) {
            assert!(!pool.stream_path(stream).exists(), "{stream}");
        }
    }

    #[tokio::test]
    async fn snapshot_consumer_pins_precede_reads_and_survive_removal_and_inherited_ofd() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots
            .publish(&record, operation, Some("race"))
            .await
            .unwrap();
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
        let consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let inherited = consumer.lease.duplicate_inheritable().unwrap();
        let fd = inherited.as_raw_fd();
        let mut command = Command::new("sh");
        command
            .args(["-c", "printf 'ready\\n'; read ignored"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        // Only this intended child inherits the original operation OFD.
        unsafe {
            command.pre_exec(move || {
                let descriptor = std::os::fd::BorrowedFd::borrow_raw(fd);
                nix::fcntl::fcntl(
                    descriptor,
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
                )
                .map(|_| ())
                .map_err(std::io::Error::from)
            });
        }
        let mut child = command.spawn().unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "ready\n");
        drop(inherited);
        let consumer_id = consumer.operation_id;
        drop(consumer);
        let removal = snapshots
            .remove(&SnapshotRef::Name("race".into()))
            .await
            .unwrap();
        assert!(removal.record_removed);
        snapshots.store.recover_image_cache().await.unwrap();
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(pool.try_exclusive_lease(consumer_id).unwrap().is_none());
        assert_eq!(
            pool.verify_stream(&record.root.stream.stream)
                .unwrap()
                .length(),
            512
        );
        for object in record.dependencies().unwrap().1 {
            assert!(pool.verify_object(&object).is_ok());
        }
        child.stdin.take().unwrap().write_all(b"release\n").unwrap();
        assert!(child.wait().unwrap().success());
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
        assert!(!pool.object_path(&info.record_digest).exists());
    }

    #[tokio::test]
    async fn snapshot_consumer_reopens_only_its_held_authenticated_closure_inodes() {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
        let consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let stream = record.root.stream.stream;
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        // The consumer holds only the root stream. The shape pins the shared
        // kernel/initramfs object and its complete canonical bundle.
        assert_eq!(consumer.retained_descriptors(), 1);
        assert_eq!(shape.object_pins.len(), 2);
        assert_eq!(shape.retained_descriptors(), 3);
        let (streams, objects) = crate::store::snapshot_store::retained_members(&record).unwrap();
        assert_eq!(streams.len() as u64, consumer.retained_descriptors());
        assert_eq!(objects.len(), shape.object_pins.len());
        assert_eq!(
            (streams.len() + objects.len()) as u64,
            shape.retained_descriptors(),
        );
        assert_eq!(
            consumer.authenticated_stream(&stream, 512).unwrap().map(),
            &pool.verify_stream(&stream).unwrap()
        );
        let copy = consumer.open_copy_source(&pool, &stream, 512).unwrap();
        assert!(std::ptr::eq(
            copy.map(),
            consumer.authenticated_stream(&stream, 512).unwrap().map()
        ));
        let first = consumer.open_stream(&pool, &stream, 512).unwrap();
        let second = consumer.open_stream(&pool, &stream, 512).unwrap();
        let (left, right) = (first.metadata().unwrap(), second.metadata().unwrap());
        assert_eq!((left.dev(), left.ino()), (right.dev(), right.ino()));
        // Each use is its own open-file description: offsets never leak.
        let mut moved = &second;
        moved.seek(SeekFrom::Start(100)).unwrap();
        let mut untouched = &first;
        assert_eq!(untouched.stream_position().unwrap(), 0);
        // Geometry and closure membership are exact; no foreign pool stream.
        assert!(consumer.open_stream(&pool, &stream, 1024).is_err());
        let foreign = format!("sha256:{}", "ab".repeat(32)).parse().unwrap();
        assert!(consumer.open_stream(&pool, &foreign, 512).is_err());
        let crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { kernel, .. },
            ..
        } = &record.boot
        else {
            panic!("fixture boot is pinned");
        };
        let mut object = shape.open_object(&pool, kernel).unwrap();
        // Restore descriptors reuse the ObjectDigest as whole-file SHA-256.
        assert_eq!(
            crate::storage::stream::whole_file_sha256(&object).unwrap(),
            vm_spec::capture::Sha256Digest::from_bytes(*kernel.as_bytes())
        );
        let mut bytes = Vec::new();
        object.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"exact boot fixture");
        drop(object);
        // Root headers and the record are validated metadata, not copy inputs.
        for unretained in [&record.root.stream.map, &info.record_digest] {
            assert!(!shape.object_pins.contains_key(unretained));
            assert!(shape.open_object(&pool, unretained).is_err());
        }
        // Rewriting identical bytes in place changes the authenticated state.
        let path = pool.stream_path(&stream);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [0x5a; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(consumer.open_stream(&pool, &stream, 512).is_err());
        assert!(consumer.open_copy_source(&pool, &stream, 512).is_err());
        // Holding the shape pin prevents inode reuse; equal replacement bytes
        // still cannot inherit the shape's original fingerprint.
        let path = pool.object_path(kernel);
        let original = shape.object_pins.get(kernel).unwrap().metadata().unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"exact boot fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let replacement = std::fs::metadata(&path).unwrap();
        assert_ne!(
            (original.dev(), original.ino()),
            (replacement.dev(), replacement.ino()),
        );
        assert!(pool.verify_object(kernel).is_ok());
        assert!(shape.open_object(&pool, kernel).is_err());
        snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
        drop(shape);
        drop(consumer);
        // A fresh consumer authenticates the current bytes again. Releasing
        // its closure keeps already opened inputs and fails later reuse closed.
        let mut consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let mut kept = consumer.open_stream(&pool, &stream, 512).unwrap();
        let kept_copy = consumer.open_copy_source(&pool, &stream, 512).unwrap();
        consumer.release_closure();
        assert_eq!(consumer.retained_descriptors(), 0);
        assert!(consumer.open_stream(&pool, &stream, 512).is_err());
        assert!(consumer.open_copy_source(&pool, &stream, 512).is_err());
        let output = tempfile::tempfile().unwrap();
        let mut hasher =
            crate::storage::stream::StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK);
        hasher.copy_authenticated(&kept_copy, &output).unwrap();
        assert!(consumer.authenticated_stream(&stream, 512).is_err());
        let mut bytes = Vec::new();
        kept.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, [0x5a; 512]);
        snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn live_ram_stream_is_bound_to_held_and_reopened_inodes() {
        use std::os::unix::fs::PermissionsExt;

        use crate::store::models::snapshot::{
            SnapshotCompatibilityProfile, SnapshotExecution, SnapshotMemoryState,
        };
        use crate::store::snapshot_store::verify_closure;

        let (_temp, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let mut consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let source = pool.open_stream(&record.root.stream.stream).unwrap();
        let ram_map =
            crate::storage::stream::StreamHasher::new(vm_spec::stream_map::ChunkSize::RAM)
                .hash_open_file(&source, record.root.stream.length)
                .unwrap()
                .map;
        let (publication, roots) = pool
            .publish_sealed_stream_for_catalog(
                &source,
                &ram_map,
                None,
                crate::storage::pool::SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        let memory = crate::store::snapshot_store::publish_map(
            &pool,
            &snapshots.store,
            consumer.operation_id,
            publication.map(),
        )
        .await
        .unwrap();
        drop(roots);
        let crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { kernel, .. },
            ..
        } = &record.boot
        else {
            panic!("fixture boot is pinned");
        };
        consumer.record.memory = SnapshotMemoryState::Included {
            execution: Box::new(SnapshotExecution {
                memory: memory.clone(),
                layout: *kernel,
                execution: *kernel,
                devices: *kernel,
                compatibility_profile: SnapshotCompatibilityProfile {
                    live_state_schema: "silo.live-state/1".into(),
                    architecture: "x86_64".into(),
                    profile: *kernel,
                    topology: *kernel,
                    ram_layout: *kernel,
                },
            }),
        };
        let (_, unretained) = verify_closure(
            &pool,
            &consumer.record,
            None,
            false,
            Arc::new(consumer.lease.duplicate().unwrap()),
        )
        .unwrap();
        assert!(unretained.streams.is_empty());
        consumer.closure = Some(
            verify_closure(
                &pool,
                &consumer.record,
                None,
                true,
                Arc::new(consumer.lease.duplicate().unwrap()),
            )
            .unwrap()
            .1,
        );
        let file = consumer
            .open_stream(&pool, &memory.stream, memory.length)
            .unwrap();
        assert_eq!(
            consumer
                .authenticated_stream(&memory.stream, memory.length)
                .unwrap()
                .map()
                .id(),
            memory.stream,
        );
        assert_eq!(file.metadata().unwrap().len(), memory.length);
        assert!(consumer
            .open_stream(&pool, &memory.stream, memory.length + 1)
            .is_err());
        let foreign = ObjectDigest::of_bytes(b"foreign")
            .to_string()
            .parse()
            .unwrap();
        assert!(consumer
            .open_stream(&pool, &foreign, memory.length)
            .is_err());

        let path = pool.stream_path(&memory.stream);
        // Equal bytes at a replacement pathname cannot inherit held authority.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, [0x5a; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(consumer
            .open_stream(&pool, &memory.stream, memory.length)
            .is_err());
        consumer.closure = Some(
            verify_closure(
                &pool,
                &consumer.record,
                None,
                true,
                Arc::new(consumer.lease.duplicate().unwrap()),
            )
            .unwrap()
            .1,
        );
        // An in-place identical rewrite also invalidates the authenticated state.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [0x5a; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(consumer
            .open_stream(&pool, &memory.stream, memory.length)
            .is_err());
        consumer.closure = Some(
            verify_closure(
                &pool,
                &consumer.record,
                None,
                true,
                Arc::new(consumer.lease.duplicate().unwrap()),
            )
            .unwrap()
            .1,
        );
        let kept = consumer
            .open_stream(&pool, &memory.stream, memory.length)
            .unwrap();
        consumer.release_closure();
        assert_eq!(consumer.retained_descriptors(), 0);
        assert!(consumer
            .open_stream(&pool, &memory.stream, memory.length)
            .is_err());
        assert_eq!(kept.metadata().unwrap().len(), memory.length);
    }

    #[tokio::test]
    async fn snapshot_catalog_and_artifact_closure_reject_missing_extra_and_corrupt_members() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let map = record.root.stream.map;
        sqlx::query(
            "DELETE FROM snapshot_object_dependency WHERE snapshot_id=?1 AND object_digest=?2",
        )
        .bind(info.id.to_string())
        .bind(map.to_string())
        .execute(&snapshots.store.pool)
        .await
        .unwrap();
        assert!(snapshots.consume(&SnapshotRef::Id(info.id)).await.is_err());
        assert!(snapshots.store.recover_image_cache().await.is_err());
        sqlx::query(
            "INSERT INTO snapshot_object_dependency(snapshot_id,object_digest) VALUES(?1,?2)",
        )
        .bind(info.id.to_string())
        .bind(map.to_string())
        .execute(&snapshots.store.pool)
        .await
        .unwrap();
        let extra = ObjectDigest::of_bytes(b"unrelated");
        sqlx::query(
            "INSERT INTO snapshot_object_dependency(snapshot_id,object_digest) VALUES(?1,?2)",
        )
        .bind(info.id.to_string())
        .bind(extra.to_string())
        .execute(&snapshots.store.pool)
        .await
        .unwrap();
        assert!(snapshots.consume(&SnapshotRef::Id(info.id)).await.is_err());
        sqlx::query(
            "DELETE FROM snapshot_object_dependency WHERE snapshot_id=?1 AND object_digest=?2",
        )
        .bind(info.id.to_string())
        .bind(extra.to_string())
        .execute(&snapshots.store.pool)
        .await
        .unwrap();
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        let backing = pool.stream_path(&record.root.stream.stream);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&backing, [0x33; 512]).unwrap();
        std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(snapshots.consume(&SnapshotRef::Id(info.id)).await.is_err());
        std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&backing, [0x5a; 512]).unwrap();
        std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::remove_file(pool.object_path(&map)).unwrap();
        assert!(snapshots.consume(&SnapshotRef::Id(info.id)).await.is_err());
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
    }

    #[tokio::test]
    async fn snapshot_publication_requires_pins_and_name_collision_is_atomic() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots
            .publish(&record, operation, Some("stable"))
            .await
            .unwrap();
        let mut changed = record.clone();
        changed.memory = crate::store::models::snapshot::SnapshotMemoryState::None {
            stop_outcome: crate::StorageStopOutcome::Forced,
        };
        let changed_id = changed.id().unwrap();
        assert!(snapshots
            .publish(&changed, operation, Some("stable"))
            .await
            .is_err());
        assert!(snapshots
            .inspect(&SnapshotRef::Id(changed_id))
            .await
            .is_err());
        assert_eq!(
            snapshots
                .inspect(&SnapshotRef::Name("stable".into()))
                .await
                .unwrap()
                .id,
            info.id
        );
        let (empty, empty_lease) = snapshots
            .store
            .begin_stopped_operation("snapshot", &[], &[])
            .await
            .unwrap();
        assert!(snapshots.publish(&record, empty, None).await.is_err());
        snapshots
            .store
            .finish_stopped_operation(empty)
            .await
            .unwrap();
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop((lease, empty_lease));
    }

    #[tokio::test]
    async fn snapshot_distinct_records_share_content_and_last_root_allows_gc() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let first = snapshots.publish(&record, operation, None).await.unwrap();
        let mut second_record = record.clone();
        second_record.memory = crate::store::models::snapshot::SnapshotMemoryState::None {
            stop_outcome: crate::StorageStopOutcome::Forced,
        };
        let second = snapshots
            .publish(&second_record, operation, None)
            .await
            .unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(record.root.stream, second_record.root.stream);
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
        snapshots.remove(&SnapshotRef::Id(first.id)).await.unwrap();
        snapshots.store.recover_image_cache().await.unwrap();
        let consumer = snapshots
            .consume(&SnapshotRef::Id(second.id))
            .await
            .unwrap();
        assert_eq!(consumer.record, second_record);
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(!pool.object_path(&first.record_digest).exists());
        assert!(pool.verify_stream(&record.root.stream.stream).is_ok());
        snapshots.remove(&SnapshotRef::Id(second.id)).await.unwrap();
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(pool.verify_stream(&record.root.stream.stream).is_ok());
        snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
        drop(consumer);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
    }

    #[tokio::test]
    async fn snapshot_uncertain_machine_candidate_cleanup_requires_final_ofd_close() {
        let (_temp, snapshots, record, operation, lease) = fixture("fork").await;
        let candidate = crate::store::models::MachineId::new();
        let parent =
            crate::paths::OwnedDirectory::open_root(&snapshots.store.home.join("machines"))
                .unwrap();
        let directory = parent.create_dir(&candidate.to_string()).unwrap().unwrap();
        directory.write_file("root.raw", &[0x61; 512]).unwrap();
        snapshots
            .store
            .preserve_stopped_operation(operation, candidate)
            .await
            .unwrap();
        let secrets = silo_secrets::FileStore::new(&snapshots.store.home);
        crate::ssh_ca::resolve(&secrets, candidate, true).unwrap();
        let source = crate::store::models::MachineId::new();
        let source_public = crate::ssh_ca::resolve(&secrets, source, true)
            .unwrap()
            .public;
        let inherited = lease.duplicate().unwrap();
        drop(lease);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(directory.path().exists());
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(pool.verify_stream(&record.root.stream.stream).is_ok());
        drop(inherited);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(!directory.path().exists());
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
        assert!(crate::ssh_ca::resolve(&secrets, candidate, false).is_err());
        assert_eq!(
            crate::ssh_ca::resolve(&secrets, source, false)
                .unwrap()
                .public,
            source_public
        );
    }

    #[tokio::test]
    async fn snapshot_uncertain_machine_candidate_never_deletes_replaced_directory() {
        let (temp, snapshots, record, operation, lease) = fixture("fork").await;
        let candidate = crate::store::models::MachineId::new();
        let parent =
            crate::paths::OwnedDirectory::open_root(&snapshots.store.home.join("machines"))
                .unwrap();
        let directory = parent.create_dir(&candidate.to_string()).unwrap().unwrap();
        directory.write_file("root.raw", &[0x61; 512]).unwrap();
        snapshots
            .store
            .preserve_stopped_operation(operation, candidate)
            .await
            .unwrap();
        let moved = temp.path().join("original");
        std::fs::rename(directory.path(), &moved).unwrap();
        let replacement = parent.create_dir(&candidate.to_string()).unwrap().unwrap();
        replacement
            .write_file("user-data", b"not operation owned")
            .unwrap();
        drop(lease);
        assert!(snapshots.store.recover_image_cache().await.is_err());
        assert_eq!(
            std::fs::read(replacement.path().join("user-data")).unwrap(),
            b"not operation owned"
        );
        assert_eq!(std::fs::read(moved.join("root.raw")).unwrap(), [0x61; 512]);
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(pool.verify_stream(&record.root.stream.stream).is_ok());
    }

    #[tokio::test]
    async fn snapshot_uncertain_immutable_candidate_reconciles_without_private_cleanup() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        snapshots
            .store
            .preserve_snapshot_operation(operation, record.id().unwrap())
            .await
            .unwrap();
        drop(lease);
        snapshots.store.recover_image_cache().await.unwrap();
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
    }

    fn sharing_config(
        home: &std::path::Path,
        source: std::path::PathBuf,
    ) -> crate::store::models::MachineConfig {
        let id = crate::store::models::MachineId::new();
        let mut spec = vm_spec::VmSpec::current();
        spec.mounts.push(vm_spec::Mount {
            source,
            tag: "/shared".into(),
            read_only: false,
        });
        crate::store::models::MachineConfig {
            secret_scope: crate::SecretScopePolicy::default(),
            id,
            lock_id: crate::lock_manager::LockId::from(1),
            name: "cleanup-reference".into(),
            spec,
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            guest: crate::MachineGuestConfig::default(),
            machine_dir: crate::paths::machine_data_dir_in(home, id),
            created_at: 1,
            modified_at: 1,
            image_ref: "test".into(),
            root_disk_size: None,
            labels: Default::default(),
            metadata: Default::default(),
            network: crate::store::models::MachineNetworkConfig::default(),
        }
    }

    #[tokio::test]
    async fn snapshot_cleanup_detaches_before_slow_work_and_fences_new_references() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        use crate::store::MachineStore;
        let (temp, snapshots, _record, operation, lease) = fixture("fork").await;
        let machine = crate::store::models::MachineId::new();
        let parent =
            crate::paths::OwnedDirectory::open_root(&snapshots.store.home.join("machines"))
                .unwrap();
        let directory = parent.create_dir(&machine.to_string()).unwrap().unwrap();
        directory.write_file("root.raw", &[0x44; 512]).unwrap();
        snapshots
            .store
            .preserve_stopped_operation(operation, machine)
            .await
            .unwrap();
        let quarantine = parent.path().join(format!(".retiring-{operation}"));
        let alias = temp.path().join("future-quarantine");
        std::os::unix::fs::symlink(&quarantine, &alias).unwrap();
        let forbidden = sharing_config(&snapshots.store.home, alias);
        // A dangling symlink must not bypass reserved-namespace admission.
        assert!(crate::store::cache_paths::ConfigurationPaths::new(
            &forbidden,
            &snapshots.store.home
        )
        .is_err());
        let (hook, mut entered, release) = WorkerHook::new(WorkerPoint::CandidateDetached, false);
        let mut worker_store = snapshots.store.as_ref().clone();
        worker_store.layer_hook = Some(hook);
        let worker_store = Arc::new(worker_store);
        drop(lease);
        let worker = worker_store.clone();
        let recovering = tokio::spawn(async move { worker.recover_image_cache().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!directory.path().exists());
        assert_eq!(
            std::fs::read(quarantine.join("root.raw")).unwrap(),
            [0x44; 512]
        );
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        drop(
            pool.try_roots_shared()
                .unwrap()
                .expect("recursive cleanup does not hold roots"),
        );
        let mut writer = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            snapshots.store.pool.begin_with("BEGIN IMMEDIATE"),
        )
        .await
        .unwrap()
        .unwrap();
        sqlx::query("UPDATE db_config SET os=os WHERE id=1")
            .execute(&mut *writer)
            .await
            .unwrap();
        writer.commit().await.unwrap();
        let broad = sharing_config(&snapshots.store.home, parent.path().to_path_buf());
        assert!(matches!(
            snapshots.store.save_machine_config(&broad).await,
            Err(crate::LibVmError::CacheDependency { .. })
        ));
        let source = sharing_config(&snapshots.store.home, directory.path().to_path_buf());
        assert!(matches!(
            snapshots.store.save_machine_config(&source).await,
            Err(crate::LibVmError::CacheDependency { .. })
        ));
        let mut data = source.clone();
        data.spec.mounts.clear();
        let geometry = vm_spec::DiskGeometry {
            length: 512,
            logical_sector_size: 512,
        };
        data.spec.storage = Some(vm_spec::Storage {
            disks: vec![
                vm_spec::Disk {
                    path: data.machine_dir.join("root.raw"),
                    role: vm_spec::DiskRole::Root,
                    format: vm_spec::DiskFormat::Raw,
                    geometry,
                    block_id: vm_spec::BlockId::new("silo-root").unwrap(),
                    read_only: false,
                },
                vm_spec::Disk {
                    path: directory.path().join("root.raw"),
                    role: vm_spec::DiskRole::Data,
                    format: vm_spec::DiskFormat::Raw,
                    geometry,
                    block_id: vm_spec::BlockId::new("silo-data-0").unwrap(),
                    read_only: false,
                },
            ],
        });
        assert!(matches!(
            snapshots.store.save_machine_config(&data).await,
            Err(crate::LibVmError::CacheDependency { .. })
        ));
        let mut relative = data.clone();
        relative.machine_dir = temp.path().join("not-catalog-authority");
        relative.spec.storage.as_mut().unwrap().disks[1].path =
            format!("../{machine}/root.raw").into();
        assert!(matches!(
            snapshots.store.save_machine_config(&relative).await,
            Err(crate::LibVmError::CacheDependency { .. })
        ));
        assert!(snapshots
            .store
            .save_machine_config(&forbidden)
            .await
            .is_err());
        release.send(()).unwrap();
        recovering.await.unwrap().unwrap();
        assert!(!quarantine.exists());
        assert!(!directory.path().exists());
    }

    #[tokio::test]
    async fn snapshot_cleanup_rediscovery_survives_worker_failure_at_each_namespace_transition() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        for point in [
            WorkerPoint::CandidateAuthorized,
            WorkerPoint::CandidateDetached,
            WorkerPoint::CandidateRemoved,
        ] {
            let (_temp, snapshots, _record, operation, lease) = fixture("fork").await;
            let machine = crate::store::models::MachineId::new();
            let parent =
                crate::paths::OwnedDirectory::open_root(&snapshots.store.home.join("machines"))
                    .unwrap();
            let directory = parent.create_dir(&machine.to_string()).unwrap().unwrap();
            directory
                .write_file("partial-root.raw", &[0x55; 512])
                .unwrap();
            snapshots
                .store
                .preserve_stopped_operation(operation, machine)
                .await
                .unwrap();
            let secrets = silo_secrets::FileStore::new(&snapshots.store.home);
            crate::ssh_ca::resolve(&secrets, machine, true).unwrap();
            let (hook, _entered, _release) = WorkerHook::new(point, true);
            let mut worker = snapshots.store.as_ref().clone();
            worker.layer_hook = Some(hook);
            drop(lease);
            assert!(worker.recover_image_cache().await.is_err());
            let state: String =
                sqlx::query_scalar("SELECT state FROM storage_operation WHERE operation_id=?1")
                    .bind(operation.to_string())
                    .fetch_one(&snapshots.store.pool)
                    .await
                    .unwrap();
            assert_eq!(state, "cleaning");
            let quarantine = parent.path().join(format!(".retiring-{operation}"));
            match point {
                WorkerPoint::CandidateAuthorized => {
                    assert!(directory.path().exists());
                    assert!(!quarantine.exists());
                }
                WorkerPoint::CandidateDetached => {
                    assert!(!directory.path().exists());
                    assert!(quarantine.exists());
                }
                WorkerPoint::CandidateRemoved => {
                    assert!(!directory.path().exists());
                    assert!(!quarantine.exists());
                }
                _ => unreachable!(),
            }
            snapshots.store.recover_image_cache().await.unwrap();
            assert!(!directory.path().exists());
            assert!(!quarantine.exists());
            assert!(crate::ssh_ca::resolve(&secrets, machine, false).is_err());
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1)",
            )
            .bind(operation.to_string())
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
            assert!(!present);
        }
    }

    #[tokio::test]
    async fn snapshot_catalog_fetch_transports_plain_facts_before_json_authentication() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let id = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let mut value = serde_json::to_value(&record).unwrap();
        value["unknownField"] = serde_json::json!(true);
        let malformed = crate::store::models::snapshot::canonical_value(&value).unwrap();
        sqlx::query("INSERT INTO storage_snapshot(id,record_digest,record_bytes,created_at) VALUES(?1,?2,?3,1)")
            .bind(format!("{id}")).bind(ObjectDigest::of_bytes(&malformed).to_string()).bind(malformed.as_slice())
            .execute(&snapshots.store.pool).await.unwrap();
        let mut tx = snapshots.store.pool.begin().await.unwrap();
        let facts = crate::store::snapshot_store::fetch_catalog(&mut tx, &SnapshotRef::Id(id))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let mut writer = snapshots
            .store
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .unwrap();
        sqlx::query("UPDATE db_config SET os=os WHERE id=1")
            .execute(&mut *writer)
            .await
            .unwrap();
        writer.commit().await.unwrap();
        assert!(crate::store::snapshot_store::authenticate_catalog(facts).is_err());
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
    }

    #[tokio::test]
    async fn snapshot_preexisting_parent_mount_defers_before_quarantine_detach() {
        use crate::store::MachineStore;
        let (_temp, snapshots, _record, operation, lease) = fixture("fork").await;
        let machine = crate::store::models::MachineId::new();
        let parent =
            crate::paths::OwnedDirectory::open_root(&snapshots.store.home.join("machines"))
                .unwrap();
        let directory = parent.create_dir(&machine.to_string()).unwrap().unwrap();
        directory.write_file("root.raw", &[0x66; 512]).unwrap();
        snapshots
            .store
            .preserve_stopped_operation(operation, machine)
            .await
            .unwrap();
        let config = sharing_config(&snapshots.store.home, parent.path().to_path_buf());
        let state = crate::store::models::MachineState {
            machine_id: config.id,
            status: crate::store::models::MachineRuntimeState::Stopped,
            vmm_pid: None,
            started_at: None,
            run_id: None,
            last_error: None,
            updated_at: 1,
        };
        snapshots.store.add_machine(&config, &state).await.unwrap();
        drop(lease);
        let report = snapshots.store.recover_image_cache().await.unwrap();
        assert!(report.deferred.iter().any(|deferral| matches!(
            deferral,
            crate::store::models::CacheCleanupDeferral::ExternalDependency { .. }
        )));
        assert_eq!(
            std::fs::read(directory.path().join("root.raw")).unwrap(),
            [0x66; 512]
        );
        assert!(!parent
            .path()
            .join(format!(".retiring-{operation}"))
            .exists());
        let state: String =
            sqlx::query_scalar("SELECT state FROM storage_operation WHERE operation_id=?1")
                .bind(operation.to_string())
                .fetch_one(&snapshots.store.pool)
                .await
                .unwrap();
        assert_eq!(state, "committing");
        snapshots.store.remove_machine(&config).await.unwrap();
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(!directory.path().exists());
    }

    #[tokio::test]
    async fn snapshot_authenticated_facts_require_coordinated_root_recheck_before_pinning() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let reference = SnapshotRef::Id(info.id);
        let mut tx = snapshots.store.pool.begin().await.unwrap();
        let facts = crate::store::snapshot_store::fetch_catalog(&mut tx, &reference)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        snapshots.remove(&reference).await.unwrap();
        let (record, observed) = crate::store::snapshot_store::authenticate_catalog(facts).unwrap();
        let bytes = record.canonical_bytes().unwrap();
        let (streams, mut objects) = record.content_dependencies().unwrap();
        objects.insert(observed.record_digest);
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        let roots = pool.lock_roots().unwrap();
        let mut tx = snapshots
            .store
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .unwrap();
        assert!(crate::store::snapshot_store::recheck_catalog(
            &mut tx, &reference, &observed, &bytes, &streams, &objects
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        drop(roots);
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM storage_operation")
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
        assert!(snapshots.consume(&reference).await.is_err());
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM storage_operation")
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(before, after);
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
    }

    #[tokio::test]
    async fn snapshot_detached_cleanup_never_deletes_reused_source_or_quarantine_names() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        for replace_quarantine in [false, true] {
            let (temp, snapshots, record, operation, lease) = fixture("fork").await;
            let machine = crate::store::models::MachineId::new();
            let parent =
                crate::paths::OwnedDirectory::open_root(&snapshots.store.home.join("machines"))
                    .unwrap();
            let directory = parent.create_dir(&machine.to_string()).unwrap().unwrap();
            directory.write_file("root.raw", &[0x77; 512]).unwrap();
            snapshots
                .store
                .preserve_stopped_operation(operation, machine)
                .await
                .unwrap();
            let quarantine_name = format!(".retiring-{operation}");
            let quarantine = parent.path().join(&quarantine_name);
            let (hook, mut entered, release) =
                WorkerHook::new(WorkerPoint::CandidateDetached, false);
            let mut worker = snapshots.store.as_ref().clone();
            worker.layer_hook = Some(hook);
            drop(lease);
            let recovering = tokio::spawn(async move { worker.recover_image_cache().await });
            tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
                .await
                .unwrap()
                .unwrap();
            let saved = temp.path().join("saved-original");
            let replacement_name = if replace_quarantine {
                std::fs::rename(&quarantine, &saved).unwrap();
                quarantine_name
            } else {
                machine.to_string()
            };
            let replacement = parent.create_dir(&replacement_name).unwrap().unwrap();
            replacement
                .write_file("user-data", b"not cleanup-owned")
                .unwrap();
            release.send(()).unwrap();
            assert!(recovering.await.unwrap().is_err());
            assert_eq!(
                std::fs::read(replacement.path().join("user-data")).unwrap(),
                b"not cleanup-owned"
            );
            if replace_quarantine {
                assert_eq!(std::fs::read(saved.join("root.raw")).unwrap(), [0x77; 512]);
            } else {
                assert!(!quarantine.exists());
            }
            let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND state='cleaning')")
                .bind(operation.to_string()).fetch_one(&snapshots.store.pool).await.unwrap();
            assert!(present);
            let pool = StoragePool::open_existing(&snapshots.store.images_dir)
                .unwrap()
                .unwrap();
            assert!(pool.verify_stream(&record.root.stream.stream).is_ok());
        }
    }

    #[tokio::test]
    async fn snapshot_quarantine_spelling_is_reserved_before_symlink_resolution() {
        use crate::store::MachineStore;
        let (temp, snapshots, _record, operation, lease) = fixture("fork").await;
        let parent =
            crate::paths::OwnedDirectory::open_root(&snapshots.store.home.join("machines"))
                .unwrap();
        let external = temp.path().join("external");
        std::fs::create_dir(&external).unwrap();
        std::fs::create_dir(external.join("child")).unwrap();
        std::fs::write(external.join("keep"), b"external user data").unwrap();
        let name = format!(".retiring-{operation}");
        let reserved = parent.path().join(&name);
        std::os::unix::fs::symlink(&external, &reserved).unwrap();
        let alias = temp.path().join("machines-alias");
        std::os::unix::fs::symlink(parent.path(), &alias).unwrap();
        for path in [
            reserved.clone(),
            reserved.join("child"),
            parent.path().join(".").join(&name),
            alias.join(&name),
            std::path::PathBuf::from(format!("../{name}/child")),
        ] {
            let config = sharing_config(&snapshots.store.home, path);
            assert!(matches!(
                snapshots.store.save_machine_config(&config).await,
                Err(crate::LibVmError::InvalidStorageRecord { .. })
            ));
        }
        assert_eq!(
            std::fs::read(external.join("keep")).unwrap(),
            b"external user data"
        );
        assert!(std::fs::symlink_metadata(&reserved)
            .unwrap()
            .file_type()
            .is_symlink());
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
    }

    #[tokio::test]
    async fn snapshot_cleanup_rejects_replacement_after_held_directory_verification() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        let (temp, snapshots, record, operation, lease) = fixture("fork").await;
        let machine = crate::store::models::MachineId::new();
        let parent =
            crate::paths::OwnedDirectory::open_root(&snapshots.store.home.join("machines"))
                .unwrap();
        let directory = parent.create_dir(&machine.to_string()).unwrap().unwrap();
        directory.write_file("root.raw", &[0x2a; 512]).unwrap();
        snapshots
            .store
            .preserve_stopped_operation(operation, machine)
            .await
            .unwrap();
        let name = format!(".retiring-{operation}");
        let quarantine = parent.path().join(&name);
        let (hook, mut entered, release) =
            WorkerHook::new(WorkerPoint::CandidateDirectoryVerified, false);
        let mut worker = snapshots.store.as_ref().clone();
        worker.layer_hook = Some(hook);
        drop(lease);
        let recovering = tokio::spawn(async move { worker.recover_image_cache().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        // The worker has opened and authenticated the original directory FD.
        // Replace its pathname only now, before its recursive deletion begins.
        let saved = temp.path().join("saved-verified-directory");
        std::fs::rename(&quarantine, &saved).unwrap();
        let replacement = parent.create_dir(&name).unwrap().unwrap();
        replacement
            .write_file("keep", b"replacement user data")
            .unwrap();
        release.send(()).unwrap();
        assert!(recovering.await.unwrap().is_err());
        assert_eq!(
            std::fs::read(replacement.path().join("keep")).unwrap(),
            b"replacement user data"
        );
        assert_eq!(std::fs::read(saved.join("root.raw")).unwrap(), [0x2a; 512]);
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND state='cleaning')")
            .bind(operation.to_string()).fetch_one(&snapshots.store.pool).await.unwrap();
        assert!(pending);
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(pool.verify_stream(&record.root.stream.stream).is_ok());
    }

    fn authenticate_test_closure(
        pool: &StoragePool,
        contents: &[&crate::store::models::snapshot::SnapshotStream],
        objects: &std::collections::BTreeSet<ObjectDigest>,
        ram: crate::storage::identity::StreamId,
        parallel: bool,
        operation: uuid::Uuid,
    ) -> Result<crate::store::snapshot_store::AuthenticatedClosure, crate::LibVmError> {
        let stream_states = contents
            .iter()
            .map(|content| {
                let metadata =
                    std::fs::symlink_metadata(pool.stream_path(&content.stream)).unwrap();
                (
                    content.stream,
                    crate::storage::identity_file::SourceFingerprint::new(&metadata),
                )
            })
            .collect();
        let object_states = objects
            .iter()
            .map(|object| {
                let metadata = std::fs::symlink_metadata(pool.object_path(object)).unwrap();
                (
                    *object,
                    crate::storage::identity_file::SourceFingerprint::new(&metadata),
                )
            })
            .collect();
        let pin: Arc<dyn Send + Sync> = Arc::new(pool.existing_lease(operation).unwrap());
        crate::store::snapshot_store::ClosureVerification {
            pool,
            contents,
            objects,
            retain: true,
            ram_stream: Some(ram),
            stream_states: &stream_states,
            object_states: &object_states,
            maps: None,
            warm: None,
            pin: &pin,
        }
        .authenticate(parallel)
    }

    #[tokio::test]
    async fn closure_lanes_preserve_errors_member_order_and_serial_resource_fallback() {
        use std::os::unix::fs::PermissionsExt;

        use crate::storage::limits::{FileDescriptorLimits, FD_RESERVED_OVERHEAD};
        use crate::store::snapshot_store::{
            closure_lane_budget_fits, publish_map, verify_artifact_closure,
        };

        let (temp, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let input = temp.path().join("ram");
        std::fs::write(&input, [0x37; 512]).unwrap();
        let (ram, roots) = pool.publish_stream_for_catalog(&input).unwrap();
        snapshots
            .store
            .pin_published_storage_dependencies(operation, &[ram.id], &[])
            .await
            .unwrap();
        drop(roots);
        let ram = publish_map(&pool, &snapshots.store, operation, &ram.map)
            .await
            .unwrap();
        let upper = &record.root.stream;
        let mut objects = record.content_dependencies().unwrap().1;
        objects.insert(ram.map);
        let held = 2;
        let required = FD_RESERVED_OVERHEAD + held + 2;
        let limits = FileDescriptorLimits {
            soft: required,
            hard: required,
            required,
        };
        let parallel = closure_lane_budget_fits(held, limits);
        let descriptor_fallback = closure_lane_budget_fits(
            held,
            FileDescriptorLimits {
                soft: required - 1,
                hard: required - 1,
                required: required - 1,
            },
        );
        assert!(parallel);
        assert!(!descriptor_fallback);
        assert!(!closure_lane_budget_fits(u64::MAX, limits,));
        for mode in [parallel, descriptor_fallback] {
            let closure = authenticate_test_closure(
                &pool,
                &[upper, &ram, &ram],
                &objects,
                ram.stream,
                mode,
                operation,
            )
            .unwrap();
            assert_eq!(closure.streams.len(), 2);
            assert_eq!(
                closure.streams.get(&ram.stream).unwrap().map().id(),
                ram.stream
            );
            let mut contradiction = ram.clone();
            contradiction.length += 1;
            let error = authenticate_test_closure(
                &pool,
                &[upper, &ram, &contradiction],
                &objects,
                ram.stream,
                mode,
                operation,
            )
            .err()
            .unwrap();
            assert_eq!(
                error.to_string(),
                crate::store::models::snapshot::invalid(
                    "snapshot root contradicts its semantic stream",
                )
                .to_string(),
            );
        }

        for (bad_upper, bad_ram) in [(false, true), (true, false), (true, true)] {
            for (stream, byte) in [
                (upper.stream, if bad_upper { 0x91 } else { 0x5a }),
                (ram.stream, if bad_ram { 0x92 } else { 0x37 }),
            ] {
                let path = pool.stream_path(&stream);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::write(&path, [byte; 512]).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
            for contents in [[upper, &ram], [&ram, upper]] {
                let first_bad = contents
                    .iter()
                    .find(|content| {
                        (content.stream == upper.stream && bad_upper)
                            || (content.stream == ram.stream && bad_ram)
                    })
                    .unwrap();
                let expected = first_bad.stream.to_string();
                for mode in [parallel, descriptor_fallback] {
                    let error = authenticate_test_closure(
                        &pool, &contents, &objects, ram.stream, mode, operation,
                    )
                    .err()
                    .unwrap();
                    assert!(error.to_string().contains(&expected), "{error}");
                }
                let error = verify_artifact_closure(
                    &pool,
                    b"closure-lanes",
                    &contents,
                    objects.clone(),
                    std::collections::BTreeSet::new(),
                    None,
                    true,
                    Some(ram.stream),
                    Arc::new(pool.existing_lease(operation).unwrap()),
                )
                .err()
                .unwrap();
                assert!(error.to_string().contains(&expected), "{error}");
            }
        }
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
    }

    fn corrupt_member(path: &std::path::Path) {
        use std::os::unix::fs::{FileExt, PermissionsExt};
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .write_all_at(&[0xff], 0)
            .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
    }

    #[tokio::test]
    async fn explicit_verify_ignores_forged_receipts_and_checks_recorded_zeros() {
        use crate::store::snapshot_store::{SnapshotVerificationError, SnapshotVerificationRole};
        for zero in [false, true] {
            let (temporary, snapshots, mut record, operation, _lease) = fixture("snapshot").await;
            let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
            if zero {
                let source = temporary.path().join("zero-disk");
                std::fs::write(&source, [0; 512]).unwrap();
                let (stream, roots) = pool.publish_stream_for_catalog(&source).unwrap();
                snapshots
                    .store
                    .pin_published_storage_dependencies(operation, &[stream.id], &[])
                    .await
                    .unwrap();
                drop(roots);
                record.root.stream = crate::store::snapshot_store::publish_map(
                    &pool,
                    &snapshots.store,
                    operation,
                    &stream.map,
                )
                .await
                .unwrap();
            }
            let info = snapshots.publish(&record, operation, None).await.unwrap();
            let reference = SnapshotRef::Id(info.id);
            let report = snapshots.verify(&reference).await.unwrap();
            assert_eq!(report.snapshot, info.id);
            assert_eq!(report.streams, 1);
            assert!(report.bytes >= 512);
            let path = pool.stream_path(&record.root.stream.stream);
            corrupt_member(&path);
            let fingerprint = crate::storage::identity_file::SourceFingerprint::new(
                &std::fs::metadata(&path).unwrap(),
            );
            let [dev, ino, len, mode, ctime_sec, ctime_nsec] = fingerprint.verification_key();
            sqlx::query(
                "INSERT OR REPLACE INTO verified_object(stream_sha256,dev,ino,len,mode,ctime_sec,ctime_nsec,verified_at) VALUES(?1,?2,?3,?4,?5,?6,?7,'forged')",
            ).bind(record.root.stream.stream.to_string()).bind(dev).bind(ino).bind(len).bind(mode)
                .bind(ctime_sec).bind(ctime_nsec).execute(&snapshots.store.pool).await.unwrap();
            let error = snapshots.verify(&reference).await.unwrap_err();
            assert!(matches!(
                error,
                crate::LibVmError::SnapshotVerification(SnapshotVerificationError::ChunkMismatch {
                    role: SnapshotVerificationRole::RootDisk,
                    stream, index: 0, start: 0, end: 512, expected, ..
                }) if stream == record.root.stream.stream
                    && matches!(*expected, vm_spec::stream_map::Chunk::Zero) == zero
            ));
        }
    }

    #[tokio::test]
    async fn explicit_verify_names_structural_stream_failures() {
        use crate::store::snapshot_store::{
            SnapshotStructuralFailure, SnapshotVerificationError, SnapshotVerificationRole,
        };
        use std::os::unix::fs::PermissionsExt;
        for case in 0..3 {
            let (_temporary, snapshots, record, operation, _lease) = fixture("snapshot").await;
            let info = snapshots.publish(&record, operation, None).await.unwrap();
            let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
            let path = pool.stream_path(&record.root.stream.stream);
            match case {
                0 => std::fs::remove_file(&path).unwrap(),
                1 => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(511)
                        .unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                }
                _ => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap()
                }
            }
            let error = snapshots
                .verify(&SnapshotRef::Id(info.id))
                .await
                .unwrap_err();
            let crate::LibVmError::SnapshotVerification(SnapshotVerificationError::Structural {
                role: SnapshotVerificationRole::RootDisk,
                failure,
                ..
            }) = error
            else {
                panic!("{error}")
            };
            assert!(match case {
                0 => matches!(failure, SnapshotStructuralFailure::Missing),
                1 => matches!(
                    failure,
                    SnapshotStructuralFailure::Truncated {
                        expected: 512,
                        actual: 511
                    }
                ),
                _ => matches!(failure, SnapshotStructuralFailure::Writable { .. }),
            });
        }
    }

    #[tokio::test]
    async fn explicit_verify_reports_ram_before_state_and_disks_and_state_without_chunk() {
        use crate::store::snapshot_store::{SnapshotVerificationError, SnapshotVerificationRole};
        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let snapshots = &fixture.snapshots;
        let info = snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
            &consumer.record.memory
        else {
            panic!("live fixture")
        };
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let ram_path = pool.stream_path(&execution.memory.stream);
        let original_ram = std::fs::read(&ram_path).unwrap();
        for object in [execution.layout, execution.execution, execution.devices] {
            corrupt_member(&pool.object_path(&object));
        }
        corrupt_member(&pool.stream_path(&consumer.record.root.stream.stream));
        corrupt_member(&ram_path);
        assert!(matches!(
            snapshots
                .verify(&SnapshotRef::Id(info.id))
                .await
                .unwrap_err(),
            crate::LibVmError::SnapshotVerification(SnapshotVerificationError::ChunkMismatch {
                role: SnapshotVerificationRole::Ram,
                index: 0,
                ..
            })
        ));
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ram_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&ram_path, original_ram).unwrap();
        std::fs::set_permissions(&ram_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let length = std::fs::metadata(pool.object_path(&execution.layout))
            .unwrap()
            .len();
        assert!(matches!(
            snapshots.verify(&SnapshotRef::Id(info.id)).await.unwrap_err(),
            crate::LibVmError::SnapshotVerification(SnapshotVerificationError::ObjectMismatch {
                role: SnapshotVerificationRole::Layout, object, length: actual_length, ..
            }) if object == execution.layout && actual_length == length
        ));
    }

    #[tokio::test]
    async fn explicit_verify_rejects_replaced_held_member() {
        use crate::store::snapshot_store::{
            open_verification_member, recheck_verification_member, SnapshotStructuralFailure,
            SnapshotVerificationError, SnapshotVerificationMember, SnapshotVerificationRole,
        };
        use std::os::unix::fs::PermissionsExt;
        let (_temporary, snapshots, record, _operation, _lease) = fixture("snapshot").await;
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let role = SnapshotVerificationRole::RootDisk;
        let member = SnapshotVerificationMember::Stream(record.root.stream.stream);
        let (file, fingerprint) =
            open_verification_member(&pool, &role, member, Some(512)).unwrap();
        let path = pool.stream_path(&record.root.stream.stream);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, [0x5a; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            recheck_verification_member(&pool, &role, member, &file, fingerprint),
            Err(crate::LibVmError::SnapshotVerification(
                SnapshotVerificationError::Structural {
                    failure: SnapshotStructuralFailure::Replaced,
                    ..
                }
            ))
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_closure_reuses_composition_receipt_and_reauthenticates_replaced_pack() {
        use crate::store::snapshot_store::verify_artifact_shape;
        use std::collections::{BTreeMap, BTreeSet};
        use std::os::unix::fs::PermissionsExt;
        let (temporary, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let held =
            crate::store::storage::tests::retained_lower(&snapshots.store, temporary.path(), 0x47)
                .await;
        let graph = held.snapshot_composition().unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let pack = graph.layers[0].pack.stream;
        let pack_path = pool.stream_path(&pack);
        let fsmeta_path = pool.object_path(&graph.fsmeta);
        let pack_watch = watch_stream_reads(&pack_path);
        let fsmeta_watch = watch_stream_reads(&fsmeta_path);
        let mut contents = vec![&record.root.stream];
        contents.extend(graph.layers.iter().map(|layer| &layer.pack));
        let (_, mut objects) = record.content_dependencies().unwrap();
        objects.extend(graph.objects());
        for content in &contents {
            objects.insert(content.map);
        }
        let bytes = record.canonical_bytes().unwrap();
        let shape = || {
            let mut shape = verify_artifact_shape(
                &pool,
                &bytes,
                &contents,
                objects.clone(),
                BTreeSet::from([graph.fsmeta]),
                None,
                true,
                None,
                &BTreeSet::new(),
                Arc::new(pool.existing_lease(operation).unwrap()),
            )
            .unwrap();
            shape.local_lower = Some(graph.clone());
            shape
        };
        let closure = snapshots.authenticate_closure_bytes(shape()).await.unwrap();
        assert!(closure.streams.contains_key(&pack));
        assert!(
            !observed_stream_read(&pack_watch),
            "retained composition packs stay warm"
        );
        assert!(
            !observed_stream_read(&fsmeta_watch),
            "retained fsmeta stays warm"
        );
        drop(closure);
        let original = std::fs::read(&pack_path).unwrap();
        observed_stream_read(&pack_watch);
        std::fs::remove_file(&pack_path).unwrap();
        std::fs::write(&pack_path, original).unwrap();
        std::fs::set_permissions(&pack_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let replacement_watch = watch_stream_reads(&pack_path);
        let closure = snapshots.authenticate_closure_bytes(shape()).await.unwrap();
        assert!(
            observed_stream_read(&replacement_watch),
            "new inode requires full authentication"
        );
        assert!(closure.streams.contains_key(&pack));
        assert!(
            observed_stream_read(&fsmeta_watch),
            "receipt miss fully validates the composition"
        );
        let streams: BTreeMap<_, _> = closure
            .streams
            .iter()
            .map(|(stream, held)| (*stream, held.fingerprint()))
            .collect();
        assert_eq!(
            streams.get(&pack),
            Some(&crate::storage::identity_file::SourceFingerprint::new(
                &std::fs::metadata(pack_path).unwrap()
            )),
        );
    }

    #[test]
    fn verification_error_stays_small_enough_for_libvm_results() {
        assert!(
            std::mem::size_of::<crate::store::snapshot_store::SnapshotVerificationError>() <= 96
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn map_receipt_hits_skip_node_reads_and_changed_root_fingerprints_revalidate() {
        use std::os::unix::fs::PermissionsExt;
        let (_temporary, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        snapshots.authenticate_closure_bytes(shape).await.unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let stream = watch_stream_reads(&pool.stream_path(&record.root.stream.stream));
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        let maps = shape
            .stream_map(&record.root.stream.stream)
            .unwrap()
            .nodes()
            .map(|node| watch_stream_reads(&pool.object_path(&node.unwrap().digest)))
            .collect::<Vec<_>>();
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        snapshots.authenticate_closure_bytes(shape).await.unwrap();
        assert!(!observed_stream_read(&stream));
        assert!(maps.iter().all(|watcher| !observed_stream_read(watcher)));

        sqlx::query("UPDATE verified_object SET map_receipt=NULL WHERE stream_sha256=?1")
            .bind(record.root.stream.stream.to_string())
            .execute(&snapshots.store.pool)
            .await
            .unwrap();
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        snapshots.authenticate_closure_bytes(shape).await.unwrap();
        assert!(maps.iter().all(|watcher| !observed_stream_read(watcher)));
        assert!(!observed_stream_read(&stream));

        let path = pool.object_path(&record.root.stream.map);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
        snapshots.authenticate_closure_bytes(shape).await.unwrap();
        assert!(maps.iter().all(|watcher| !observed_stream_read(watcher)));
        assert!(!observed_stream_read(&stream));
        let length = std::fs::metadata(&path).unwrap().len() as usize;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![b'x'; length]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(snapshots.verify_closure_shape(&consumer).await.is_err());
    }

    #[tokio::test]
    async fn root_receipts_are_small_and_explicit_verify_names_corrupt_nodes() {
        use crate::store::snapshot_store::{SnapshotVerificationError, SnapshotVerificationRole};
        for height in 0..5 {
            let (_temporary, snapshots, record, operation, _lease) = fixture("snapshot").await;
            let info = snapshots.publish(&record, operation, None).await.unwrap();
            let consumer = snapshots
                .consume_shape(&SnapshotRef::Id(info.id))
                .await
                .unwrap();
            let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
            snapshots.authenticate_closure_bytes(shape).await.unwrap();
            let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
            let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
            let map = shape.stream_map(&record.root.stream.stream).unwrap();
            let node = map
                .nodes()
                .map(Result::unwrap)
                .find(|node| node.height == height)
                .unwrap();
            let receipt: Vec<u8> = sqlx::query_scalar(
                "SELECT map_receipt FROM verified_object WHERE stream_sha256=?1",
            )
            .bind(record.root.stream.stream.to_string())
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
            assert!(receipt.len() < 4096);
            let value: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
            assert_eq!(value["schema"], 1);
            assert!(value.get("chunks").is_none());
            corrupt_member(&pool.object_path(&node.digest));
            // Local shape admission does not stat or decode every descendant.
            snapshots.verify_closure_shape(&consumer).await.unwrap();
            let error = snapshots
                .verify(&SnapshotRef::Id(info.id))
                .await
                .unwrap_err();
            let crate::LibVmError::SnapshotVerification(SnapshotVerificationError::MapNode(
                failure,
            )) = error
            else {
                panic!("expected map node corruption");
            };
            assert_eq!(failure.role, SnapshotVerificationRole::RootDisk);
            assert_eq!(failure.node, node.digest);
            assert_eq!(failure.height, height);
        }
    }

    #[tokio::test]
    async fn explicit_verify_reports_corrupt_and_missing_ram_nodes_at_each_height() {
        use crate::store::snapshot_store::{
            SnapshotStructuralFailure, SnapshotVerificationError, SnapshotVerificationRole,
        };
        for height in 0..5 {
            let fixture = crate::store::capture::tests::fixture().await;
            let (directory, _) = crate::store::capture::tests::seal(&fixture);
            let snapshots = &fixture.snapshots;
            let info = snapshots
                .publish_capture(
                    fixture.reservation.record.capture_id,
                    directory.path(),
                    fixture.reservation.record.name.clone(),
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
                .unwrap();
            let consumer = snapshots
                .consume_shape(&SnapshotRef::Id(info.id))
                .await
                .unwrap();
            let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
                &consumer.record.memory
            else {
                panic!("live capture fixture");
            };
            let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
            let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
            let node = shape
                .stream_map(&execution.memory.stream)
                .unwrap()
                .nodes()
                .map(Result::unwrap)
                .find(|node| node.height == height)
                .unwrap();
            assert_eq!(execution.memory.chunk_size, 65536);
            let path = pool.object_path(&node.digest);
            corrupt_member(&path);
            let error = snapshots
                .verify(&SnapshotRef::Id(info.id))
                .await
                .unwrap_err();
            let crate::LibVmError::SnapshotVerification(SnapshotVerificationError::MapNode(
                failure,
            )) = error
            else {
                panic!("expected RAM map node corruption");
            };
            assert_eq!(failure.role, SnapshotVerificationRole::Ram);
            assert_eq!(failure.node, node.digest);
            assert_eq!(failure.height, height);
            std::fs::remove_file(&path).unwrap();
            let error = snapshots
                .verify(&SnapshotRef::Id(info.id))
                .await
                .unwrap_err();
            let crate::LibVmError::SnapshotVerification(SnapshotVerificationError::MapNode(
                failure,
            )) = error
            else {
                panic!("expected missing RAM map node");
            };
            assert_eq!(failure.role, SnapshotVerificationRole::Ram);
            assert_eq!(failure.node, node.digest);
            assert!(matches!(
                failure.failure,
                SnapshotStructuralFailure::Missing
            ));
        }
    }

    #[tokio::test]
    async fn read_consumer_pins_do_not_grant_publication_or_terminal_operation_authority() {
        use crate::store::snapshot_store::{require_consumer_closure, require_operation_closure};
        use std::collections::BTreeSet;

        let temporary = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temporary.path()))
            .await
            .unwrap();
        for kind in ["raw-export", "fork"] {
            let (operation, _lease) = store.begin_stopped_operation(kind, &[], &[]).await.unwrap();
            require_consumer_closure(&store, operation, &BTreeSet::new(), &BTreeSet::new())
                .await
                .unwrap();
            assert!(require_operation_closure(
                &store,
                operation,
                &BTreeSet::new(),
                &BTreeSet::new(),
                None,
            )
            .await
            .is_err());
            store.finish_stopped_operation(operation).await.unwrap();
            assert!(require_consumer_closure(
                &store,
                operation,
                &BTreeSet::new(),
                &BTreeSet::new(),
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn live_capture_restore_shape_retains_the_binary_ram_root_and_state_roles() {
        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let snapshots = &fixture.snapshots;
        let info = snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let inspection = snapshots.prepare_restore_shape(&consumer).await.unwrap();
        let shape = inspection.shape();
        let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
            &consumer.record.memory
        else {
            panic!("live capture fixture");
        };
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let ram = shape
            .open_stream(&pool, &execution.memory.stream, execution.memory.length)
            .unwrap();
        assert_eq!(ram.metadata().unwrap().len(), execution.memory.length);
        for object in [execution.layout, execution.execution, execution.devices] {
            shape.open_object(&pool, &object).unwrap();
        }
        let mut root_file = shape.open_object(&pool, &execution.memory.map).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut root_file, &mut bytes).unwrap();
        assert!(bytes.len() <= vm_spec::stream_map::MAX_ROOT_BYTES);
        assert_eq!(
            bytes,
            shape
                .stream_map(&execution.memory.stream)
                .unwrap()
                .canonical_bytes()
                .unwrap()
        );
        assert!(
            shape
                .open_object(&pool, &consumer.record.root.stream.map)
                .is_err(),
            "a disk root is not a native restore FD role"
        );
        let evidence = snapshots
            .restore_evidence(&consumer, &pool)
            .unwrap()
            .evidence;
        let changes = crate::storage::identity::ObjectDigest::from_sha256(
            *evidence.memory.as_ref().unwrap().changes.sha256.as_bytes(),
        );
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM storage_operation_object WHERE operation_id=?1 AND object_digest=?2)",
        ).bind(consumer.operation_id.to_string()).bind(changes.to_string())
            .fetch_one(&snapshots.store.pool).await.unwrap(),
            "restore consumer retains the change provenance independently of FD roles");
        assert!(
            shape.open_object(&pool, &changes).is_err(),
            "change provenance is not a native restore FD role"
        );
        let completed = inspection.complete(&snapshots.store.images_dir).unwrap();
        snapshots
            .authenticate_closure_bytes(completed)
            .await
            .unwrap();
    }

    #[test]
    fn local_fork_references_cannot_select_snapshot_authority() {
        let error = format!("fork:{}", uuid::Uuid::new_v4())
            .parse::<crate::SnapshotRef>()
            .unwrap_err();
        assert!(error.to_string().contains("snapshot the child first"));
    }
}
