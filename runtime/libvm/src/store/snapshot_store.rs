//! Immutable snapshot artifacts, shared image aliases, and independent retention.
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
use crate::storage::limits::Resource;
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
use crate::storage::stream::AuthenticatedStream;
use crate::store::models::snapshot::{invalid, SnapshotRecord, SnapshotStream};
use crate::store::Store;
use crate::LibVmError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRef {
    Id(SnapshotId),
    Image(String),
}
impl FromStr for SnapshotRef {
    type Err = LibVmError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value
            .strip_prefix("image:")
            .ok_or_else(|| invalid("expected image:NAME or image:sha256:HEX"))?;
        if value.starts_with("sha256:") {
            return value.parse().map(Self::Id).map_err(invalid);
        }
        validate_alias(value)?;
        Ok(Self::Image(value.to_owned()))
    }
}
impl fmt::Display for SnapshotRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "image:{id}"),
            Self::Image(name) => write!(f, "image:{name}"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotCaptureKindName {
    StoppedStorage,
    LiveExecution,
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
    pub capture_kind: SnapshotCaptureKindName,
    pub provenance: Vec<SnapshotCaptureProvenance>,
    pub retained: bool,
    pub aliases: Vec<String>,
    pub created_at: i64,
}

/// A checkpoint is retained even when its optional requested name loses a race.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CaptureNamingOutcome {
    AliasConflict { alias: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureReservationRequest {
    pub machine_id: crate::store::models::MachineId,
    pub run_id: Uuid,
    pub capture_id: Uuid,
    pub configuration: vm_spec::capture::CaptureConfiguration,
    pub alias: Option<String>,
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
    Local { cut: vm_spec::capture::Sha256Digest },
    ReleasedLocal { cut: vm_spec::capture::Sha256Digest },
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
    pub alias: Option<String>,
    pub request: CaptureReservationRequest,
    pub plan: vm_spec::capture::CapturePlan,
    pub state: CaptureState,
    pub source_outcome: Option<CaptureSourceOutcome>,
    pub naming_outcome: Option<CaptureNamingOutcome>,
    pub configuration: crate::machine::stopped::SnapshotConfiguration,
    pub storage: crate::MachineStorageRecord,
    pub disk_charges: Vec<CaptureSpaceCharge>,
    /// Allocated bytes sampled from each writable source, keyed by attachment index.
    pub disk_allocations: BTreeMap<u32, u64>,
    pub reservation_bytes: u64,
    pub candidate: Option<SnapshotId>,
    pub captured_boot: Option<crate::BootProfile>,
    pub source_inodes: Vec<(u64, u64)>,
    pub evidence: Option<String>,
}

pub(crate) struct CaptureReservation {
    pub record: CaptureRecord,
    pub(crate) _lease: StorageLock,
}

#[derive(Clone)]
pub struct SnapshotStore {
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

/// Closure members whose authenticated descriptors a consumer holds. Map roots
/// and pages are consumed through digest-checked reads only, so retention
/// stays bounded by record roles rather than stream length.
fn retained_members(
    record: &SnapshotRecord,
) -> Result<(BTreeSet<StreamId>, BTreeSet<ObjectDigest>), LibVmError> {
    let (streams, mut objects) = record.content_dependencies()?;
    for stream in record.streams() {
        objects.remove(&stream.map);
        for page in &stream.map_pages {
            objects.remove(page);
        }
    }
    Ok((streams, objects))
}

pub(crate) fn validate_alias(name: &str) -> Result<(), LibVmError> {
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid("image alias must be 1..128 ASCII letters/digits/dot/underscore/hyphen, beginning with a letter or digit"));
    }
    Ok(())
}

impl SnapshotStore {
    pub async fn open(home: &Path) -> Result<Self, LibVmError> {
        Ok(Self::from_store(Arc::new(
            Store::open(&home.join("state.db")).await?,
        )))
    }
    pub(crate) fn from_store(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub async fn inspect(&self, reference: &SnapshotRef) -> Result<SnapshotInfo, LibVmError> {
        let (_, info) = self.load_observed(reference).await?;
        Ok(info)
    }

    pub async fn list(&self) -> Result<Vec<SnapshotInfo>, LibVmError> {
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
                let reference = SnapshotRef::Id(id.parse().map_err(invalid)?);
                let observed = if exists(&mut tx, &reference).await? {
                    Some(fetch_catalog(&mut tx, &reference).await?)
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

    /// Unbinding a name leaves its independently retained image/snapshot intact.
    pub async fn remove_alias(&self, name: &str) -> Result<bool, LibVmError> {
        crate::store::managed_image_store::ManagedImageStore::from_store(self.store.clone())
            .remove_alias(name)
            .await
    }

    /// Release only the unnamed explicit retention root. Aliases keep rooting
    /// their artifact; no referenced bytes are recursively unlinked here.
    pub async fn release_retention(&self, reference: &SnapshotRef) -> Result<bool, LibVmError> {
        let collection = self.clone();
        let reference = reference.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(collection.release_retention_owned(&reference))
        })
        .await?
    }

    async fn release_retention_owned(&self, reference: &SnapshotRef) -> Result<bool, LibVmError> {
        let (record, observed) = self.load_observed(reference).await?;
        let bytes = record.canonical_bytes()?;
        let (streams, mut objects) = record.content_dependencies()?;
        objects.insert(observed.record_digest);
        let pool = StoragePool::open(&self.store.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        recheck_catalog(&mut tx, reference, &observed, &bytes, &streams, &objects).await?;
        let info = catalog_info(&mut tx, observed.id, observed.record_digest).await?;
        sqlx::query("UPDATE storage_snapshot SET retained=0 WHERE id=?1")
            .bind(info.id.to_string())
            .execute(&mut *tx)
            .await?;
        remove_unrooted(&mut tx, &info.id.to_string()).await?;
        tx.commit().await?;
        Ok(info.retained)
    }

    /// Called by the stopped blocking owner while it holds the original
    /// operation OFD. All slow authentication is outside roots/transactions.
    pub(crate) async fn publish(
        &self,
        record: &SnapshotRecord,
        operation_id: Uuid,
        alias: Option<&str>,
    ) -> Result<SnapshotInfo, LibVmError> {
        self.publish_authenticated(record, operation_id, alias, None)
            .await
    }

    pub(crate) async fn publish_authenticated(
        &self,
        record: &SnapshotRecord,
        operation_id: Uuid,
        alias: Option<&str>,
        inputs: Option<&crate::store::capture::VerifiedCapture>,
    ) -> Result<SnapshotInfo, LibVmError> {
        if matches!(
            record.capture,
            crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { .. }
        ) != inputs.is_some()
        {
            return Err(invalid(
                "execution publication requires its retained capture verification owner",
            ));
        }
        if let Some(name) = alias {
            validate_alias(name)?;
        }
        let bytes = record.canonical_bytes()?;
        let id = crate::store::models::snapshot::snapshot_id(&bytes);
        let digest = ObjectDigest::of_bytes(&bytes);
        let (streams, mut objects) = record.content_dependencies()?;
        objects.insert(digest);
        let pool = StoragePool::open(&self.store.images_dir)?;
        let capture = if matches!(
            record.capture,
            crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { .. }
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
        let (mut fingerprints, _) = match inputs {
            Some(inputs) => verify_publication_closure(&pool, record, inputs.published_ram()?)?,
            None => verify_closure(&pool, record, None, false)?,
        };
        let input = RecordInput::new(&self.store.images_dir, operation_id, &bytes)?;
        let (published, roots) = pool.publish_object_for_catalog(&input.path())?;
        if published.digest != digest {
            return Err(invalid("published snapshot record digest mismatch"));
        }
        self.store
            .pin_published_storage_dependencies(operation_id, &[], &[digest])
            .await?;
        fingerprints.push((
            published.path.clone(),
            crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
                &published.path,
            )?),
        ));
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
        let _roots = pool.lock_roots_shared()?;
        recheck_closure(&fingerprints)?;
        if let Some(inputs) = inputs {
            inputs.recheck_registered(&self.store, operation_id)?;
            inputs.published_ram()?.recheck(&pool)?;
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
            sqlx::query("UPDATE storage_snapshot SET retained=1 WHERE id=?1")
                .bind(id.to_string())
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query("INSERT INTO storage_snapshot(id,record_digest,record_bytes,retained,created_at) VALUES(?1,?2,?3,1,?4)")
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
        let mut naming_outcome = None;
        if let Some(alias) = alias {
            match crate::store::managed_image_store::insert_alias(
                &mut tx,
                alias,
                crate::image::import_types::ManagedSourceId::Snapshot(id),
            )
            .await
            {
                Ok(()) => {}
                Err(LibVmError::ImageAliasConflict { alias }) if capture.is_some() => {
                    naming_outcome = Some(CaptureNamingOutcome::AliasConflict { alias });
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
        // checkpoint and its closure power-loss durable before acknowledging it.
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
        self.consume_selected(reference, false, true).await
    }

    pub(crate) async fn consume_disks(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotConsumer, LibVmError> {
        self.consume_selected(reference, true, true).await
    }

    /// Pin catalog authority and materialize evicted streams without authenticating
    /// the full closure or constructing children.
    pub(crate) async fn consume_shape(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotConsumer, LibVmError> {
        self.consume_selected(reference, false, false).await
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
        if let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &consumer.record.capture
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
        let ram = match &consumer.record.capture {
            crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } => {
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
        let shape = verify_artifact_shape(
            &pool,
            &consumer.record.canonical_bytes()?,
            &consumer.record.streams().collect::<Vec<_>>(),
            objects,
            retained,
            Some(consumer.info.record_digest),
            true,
            ram,
            deferred_maps,
        )?;
        if let crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay {
            lower,
            lower_geometry,
            lower_filesystem_uuid,
            ..
        } = &consumer.record.root.profile
        {
            lower
                .authenticate(|digest, maximum| Ok(pool.read_object(digest, maximum)?))?
                .check_root_claims(lower_geometry, *lower_filesystem_uuid)?;
        }
        recheck_closure(&shape.fingerprints)?;
        Ok(shape)
    }

    /// Local restore only. Transport callers use the unconditional full path.
    pub(crate) async fn authenticate_closure_bytes(
        &self,
        shape: ShapeVerifiedClosure,
    ) -> Result<AuthenticatedClosure, LibVmError> {
        let store = self.store.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let pool = StoragePool::open(&store.images_dir)?;
            let warm = runtime.block_on(async {
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
            let closure = shape.authenticate(&pool, Some(&warm))?;
            runtime.block_on(async {
                for (stream, authenticated) in &closure.streams {
                    if warm.contains_key(stream) {
                        continue;
                    }
                    bind_held(authenticated.file(), authenticated.fingerprint())?;
                    let [dev, ino, len, mode, ctime_sec, ctime_nsec] =
                        authenticated.fingerprint().verification_key();
                    sqlx::query(
                        "INSERT INTO verified_object(stream_sha256,dev,ino,len,mode,ctime_sec,ctime_nsec,verified_at) VALUES(?1,?2,?3,?4,?5,?6,?7,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(stream_sha256) DO UPDATE SET dev=excluded.dev,ino=excluded.ino,len=excluded.len,mode=excluded.mode,ctime_sec=excluded.ctime_sec,ctime_nsec=excluded.ctime_nsec,verified_at=excluded.verified_at",
                    )
                    .bind(stream.to_string()).bind(dev).bind(ino).bind(len).bind(mode)
                    .bind(ctime_sec).bind(ctime_nsec).execute(&store.pool).await?;
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
                for content in &contents {
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
                        for page in &content.map_pages {
                            retained.remove(page);
                        }
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
                    )?
                } else {
                    verify_closure(&pool, &record, Some(info.record_digest), true)?
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
    reference: &SnapshotRef,
) -> Result<bool, LibVmError> {
    let (id, alias) = reference_parts(reference)?;
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_snapshot WHERE id=?1 OR id=(SELECT snapshot_id FROM image_alias WHERE name=?2))")
        .bind(id).bind(alias).fetch_one(connection).await?)
}
fn reference_parts(reference: &SnapshotRef) -> Result<(Option<String>, Option<&str>), LibVmError> {
    match reference {
        SnapshotRef::Id(id) => Ok((Some(id.to_string()), None)),
        SnapshotRef::Image(name) => {
            validate_alias(name)?;
            Ok((None, Some(name)))
        }
    }
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
    retained: i64,
    created_at: i64,
    aliases: Vec<String>,
    streams: Vec<String>,
    objects: Vec<String>,
    provenance: Vec<CaptureProvenanceFact>,
    capture_owned: bool,
}

pub(crate) async fn fetch_catalog(
    connection: &mut sqlx::SqliteConnection,
    reference: &SnapshotRef,
) -> Result<CatalogSnapshotFacts, LibVmError> {
    let (id, alias) = reference_parts(reference)?;
    let target = crate::store::managed_image_store::resolve_target(
        connection,
        &match reference {
            SnapshotRef::Id(id) => crate::image::import_types::ManagedSourceRef::Snapshot(*id),
            SnapshotRef::Image(alias) => {
                crate::image::import_types::ManagedSourceRef::Alias(alias.clone())
            }
        },
    )
    .await?;
    if !matches!(
        target,
        crate::image::import_types::ManagedSourceId::Snapshot(_)
    ) {
        return Err(invalid(
            "image requires image creation, not snapshot restore",
        ));
    }
    let row = sqlx::query("SELECT id,record_digest,record_bytes,retained,created_at,(EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND json_extract(record_json,'$.candidate')=storage_snapshot.id) OR EXISTS(SELECT 1 FROM storage_operation_managed WHERE managed_kind='snapshot' AND managed_id=storage_snapshot.id)) AS capture_owned FROM storage_snapshot WHERE id=?1 OR id=(SELECT snapshot_id FROM image_alias WHERE name=?2)")
        .bind(id).bind(alias).fetch_optional(&mut *connection).await?
        .ok_or_else(|| invalid(format!("snapshot {reference} does not exist")))?;
    let id: String = row.try_get("id")?;
    let aliases =
        sqlx::query_scalar("SELECT name FROM image_alias WHERE snapshot_id=?1 ORDER BY name")
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
        retained: row.try_get("retained")?,
        created_at: row.try_get("created_at")?,
        aliases,
        streams,
        objects,
        provenance,
        capture_owned: row.try_get("capture_owned")?,
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
    for alias in &facts.aliases {
        validate_alias(alias)?;
    }
    if !matches!(facts.retained, 0 | 1)
        || (facts.retained == 0 && facts.aliases.is_empty() && !facts.capture_owned)
    {
        return Err(invalid("snapshot has no public retention root"));
    }
    let capture_kind = capture_kind(&record);
    let provenance = authenticate_provenance(facts.provenance)?;
    if capture_kind == SnapshotCaptureKindName::StoppedStorage && !provenance.is_empty() {
        return Err(invalid("stopped snapshot has live capture provenance"));
    }
    Ok((
        record,
        SnapshotInfo {
            id,
            record_digest: digest,
            capture_kind,
            provenance,
            retained: facts.retained == 1,
            aliases: facts.aliases,
            created_at: facts.created_at,
        },
    ))
}

async fn catalog_info(
    connection: &mut sqlx::SqliteConnection,
    id: SnapshotId,
    digest: ObjectDigest,
) -> Result<SnapshotInfo, LibVmError> {
    let row = sqlx::query("SELECT retained,created_at,json_extract(CAST(record_bytes AS TEXT),'$.captureKind') AS capture_kind,(EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND json_extract(record_json,'$.candidate')=storage_snapshot.id) OR EXISTS(SELECT 1 FROM storage_operation_managed WHERE managed_kind='snapshot' AND managed_id=storage_snapshot.id)) AS capture_owned FROM storage_snapshot WHERE id=?1")
        .bind(id.to_string())
        .fetch_one(&mut *connection)
        .await?;
    let aliases = sqlx::query_scalar::<_, String>(
        "SELECT name FROM image_alias WHERE snapshot_id=?1 ORDER BY name",
    )
    .bind(id.to_string())
    .fetch_all(&mut *connection)
    .await?;
    for alias in &aliases {
        validate_alias(alias)?;
    }
    let retained: i64 = row.try_get("retained")?;
    if !matches!(retained, 0 | 1)
        || (retained == 0 && aliases.is_empty() && !row.try_get::<bool, _>("capture_owned")?)
    {
        return Err(invalid("snapshot has no public retention root"));
    }
    Ok(SnapshotInfo {
        id,
        record_digest: digest,
        provenance: Vec::new(),
        capture_kind: match row.try_get::<String, _>("capture_kind")?.as_str() {
            "stopped-storage" => SnapshotCaptureKindName::StoppedStorage,
            "live-execution" => SnapshotCaptureKindName::LiveExecution,
            _ => return Err(invalid("invalid snapshot capture kind")),
        },
        retained: retained == 1,
        aliases,
        created_at: row.try_get("created_at")?,
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

fn capture_kind(record: &SnapshotRecord) -> SnapshotCaptureKindName {
    match &record.capture {
        crate::store::models::snapshot::SnapshotCaptureKind::StoppedStorage { .. } => {
            SnapshotCaptureKindName::StoppedStorage
        }
        crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { .. } => {
            SnapshotCaptureKindName::LiveExecution
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
    let target = crate::store::managed_image_store::resolve_target(
        connection,
        &match reference {
            SnapshotRef::Id(id) => crate::image::import_types::ManagedSourceRef::Snapshot(*id),
            SnapshotRef::Image(alias) => {
                crate::image::import_types::ManagedSourceRef::Alias(alias.clone())
            }
        },
    )
    .await?;
    if target != crate::image::import_types::ManagedSourceId::Snapshot(observed.id) {
        return Err(invalid(
            "snapshot root changed before consumer registration",
        ));
    }
    let (id, alias) = reference_parts(reference)?;
    let row = sqlx::query("SELECT id,record_digest,record_bytes FROM storage_snapshot WHERE id=?1 OR id=(SELECT snapshot_id FROM image_alias WHERE name=?2)")
        .bind(id).bind(alias).fetch_optional(&mut *connection).await?
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
                    .ok_or_else(|| invalid("imported checkpoint pool is missing"))?;
                crate::store::restore::authenticate_imported_captures(
                    &pool, &record, info.id, &imported,
                )?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn remove_unrooted(
    connection: &mut sqlx::SqliteConnection,
    id: &str,
) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM storage_snapshot WHERE id=?1 AND retained=0 AND NOT EXISTS(SELECT 1 FROM image_alias WHERE snapshot_id=?1) AND NOT EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND json_extract(record_json,'$.candidate')=?1) AND NOT EXISTS(SELECT 1 FROM storage_operation_managed WHERE managed_kind='snapshot' AND managed_id=?1)")
        .bind(id).execute(connection).await?;
    Ok(())
}
pub(crate) async fn require_operation_closure(
    store: &Store,
    operation: Uuid,
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
    pending: Option<ObjectDigest>,
) -> Result<(), LibVmError> {
    let mut tx = store.pool.begin().await?;
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind IN ('import','convert','snapshot','capture','update-boot-assets') AND state IN ('staging','committing'))")
        .bind(operation.to_string()).fetch_one(&mut *tx).await?;
    if !active {
        return Err(invalid("snapshot has no active retained operation"));
    }
    for stream in streams {
        let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_stream WHERE operation_id=?1 AND stream_id=?2)")
            .bind(operation.to_string()).bind(stream.to_string()).fetch_one(&mut *tx).await?;
        if !pinned {
            return Err(invalid("snapshot stream was not pinned before access"));
        }
    }
    for object in objects {
        if Some(*object) == pending {
            continue;
        }
        let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_object WHERE operation_id=?1 AND object_digest=?2)")
            .bind(operation.to_string()).bind(object.to_string()).fetch_one(&mut *tx).await?;
        if !pinned {
            return Err(invalid("snapshot object was not pinned before access"));
        }
    }
    tx.commit().await?;
    Ok(())
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

/// Verification is identical either way. With `retain`, the returned held
/// descriptors are the exact inodes hashed here, each bound to the path state
/// observed before hashing began; process descriptor admission for all of
/// them precedes the first open. Without it, each descriptor closes after use.
fn verify_closure(
    pool: &StoragePool,
    record: &SnapshotRecord,
    digest: Option<ObjectDigest>,
    retain: bool,
) -> Result<(ClosureFingerprints, AuthenticatedClosure), LibVmError> {
    let bytes = record.canonical_bytes()?;
    let (_, objects) = record.content_dependencies()?;
    let (_, retained_objects) = retained_members(record)?;
    let ram = match &record.capture {
        crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution }
            if retain =>
        {
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
    )
}

/// Reuse only the pool-inode proof from this owned publication. Recovery creates
/// a fresh proof by authenticating publication bytes again; no proof is durable.
fn verify_publication_closure(
    pool: &StoragePool,
    record: &SnapshotRecord,
    ram: &crate::storage::pool::VerifiedRamPublication,
) -> Result<(ClosureFingerprints, AuthenticatedClosure), LibVmError> {
    let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
        &record.capture
    else {
        return Err(invalid("RAM publication proof requires a live checkpoint"));
    };
    let stream = ram.stream();
    if execution.memory.stream != stream.map().id() || execution.memory.length != stream.length() {
        return Err(invalid("RAM publication proof belongs to another stream"));
    }
    ram.recheck(pool)?;
    let bytes = record.canonical_bytes()?;
    let (_, objects) = record.content_dependencies()?;
    let (_, retained_objects) = retained_members(record)?;
    let shape = verify_artifact_shape(
        pool,
        &bytes,
        &record.streams().collect::<Vec<_>>(),
        objects,
        retained_objects,
        None,
        false,
        None,
        &BTreeSet::new(),
    )?;
    if shape.stream_map(&execution.memory.stream)? != stream.map() {
        return Err(invalid(
            "RAM publication map differs from authenticated pool bytes",
        ));
    }
    let warm = BTreeMap::from([(execution.memory.stream, stream.fingerprint())]);
    let closure = shape.authenticate(pool, Some(&warm))?;
    ram.recheck(pool)?;
    Ok((shape.fingerprints, closure))
}

/// A metadata-validated closure, with no stream-byte authentication authority.
/// Map roots/pages are bounded metadata and are authenticated while decoding.
pub(crate) struct ShapeVerifiedClosure {
    contents: Vec<SnapshotStream>,
    maps: BTreeMap<StreamId, Arc<crate::storage::stream::StreamMap>>,
    objects: BTreeSet<ObjectDigest>,
    object_pins: BTreeMap<ObjectDigest, File>,
    retain: bool,
    ram_stream: Option<StreamId>,
    fingerprints: ClosureFingerprints,
    stream_states: BTreeMap<StreamId, SourceFingerprint>,
    object_states: BTreeMap<ObjectDigest, SourceFingerprint>,
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
        read_shape_maps(&pool, self.shape.contents.iter(), &mut self.shape.maps)?;
        recheck_closure(&self.shape.fingerprints)?;
        Ok(self.shape)
    }
}

impl ShapeVerifiedClosure {
    /// Peak held descriptors: shape-pinned objects plus authenticated streams.
    pub(crate) fn retained_descriptors(&self) -> u64 {
        if self.retain {
            (self.stream_states.len() + self.object_pins.len()) as u64
        } else {
            0
        }
    }

    pub(crate) fn stream_map(
        &self,
        stream: &StreamId,
    ) -> Result<&crate::storage::stream::StreamMap, LibVmError> {
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
        }
        .authenticate(parallel)?;
        recheck_closure(&self.fingerprints)?;
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
        object_states,
    })
}

fn read_shape_maps<'a>(
    pool: &StoragePool,
    contents: impl Iterator<Item = &'a SnapshotStream>,
    maps: &mut BTreeMap<StreamId, Arc<crate::storage::stream::StreamMap>>,
) -> Result<(), LibVmError> {
    for content in contents {
        if maps.contains_key(&content.stream) {
            continue;
        }
        let root = crate::storage::map::StreamMapRoot::decode(
            &pool.read_object(&content.map, Resource::MetadataPageBytes.maximum())?,
        )?;
        if root.pages != content.map_pages
            || root.stream != content.stream
            || root.length != content.length
        {
            return Err(invalid("snapshot map root contradicts content"));
        }
        let map = root.read_map(pool)?;
        if map.id() != content.stream || map.length() != content.length {
            return Err(invalid("snapshot stream/map/backing contradiction"));
        }
        maps.insert(content.stream, Arc::new(map));
    }
    Ok(())
}

/// Publication, export and handoff always authenticate every stream byte.
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
    maps: Option<&'a BTreeMap<StreamId, Arc<crate::storage::stream::StreamMap>>>,
    warm: Option<&'a BTreeMap<StreamId, SourceFingerprint>>,
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
                    let root = crate::storage::map::StreamMapRoot::decode(
                        &self
                            .pool
                            .read_object(&content.map, Resource::MetadataPageBytes.maximum())?,
                    )?;
                    if root.pages != content.map_pages
                        || root.stream != content.stream
                        || root.length != content.length
                    {
                        return Err(invalid("snapshot map root contradicts content"));
                    }
                    Arc::new(root.read_map(self.pool)?)
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
                        None => self.pool.authenticate_stream_full(&content.stream)?,
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
    map: &crate::storage::stream::StreamMap,
) -> Result<SnapshotStream, LibVmError> {
    let parent = OwnedDirectory::open_existing_root(
        &store
            .home_path()
            .join("images/tmp")
            .join(operation.to_string()),
    )?
    .ok_or_else(|| invalid("registered capture staging is missing"))?;
    let name = format!("map-{}", Uuid::new_v4());
    let stage = parent
        .create_dir(&name)?
        .ok_or_else(|| invalid("map staging collision"))?;
    let mut map_pages = Vec::new();
    for (index, page) in crate::storage::map::pages(map).enumerate() {
        let name = format!("page-{index}");
        stage.write_file(&name, &page?)?;
        let (object, roots) = pool.publish_object_for_catalog(&stage.path().join(&name))?;
        store
            .pin_published_storage_dependencies(operation, &[], &[object.digest])
            .await?;
        map_pages.push(object.digest);
        drop(roots);
    }
    let root = crate::storage::map::StreamMapRoot::new(map, map_pages.clone())?;
    stage.write_file("record", &root.encode()?)?;
    let (object, roots) = pool.publish_object_for_catalog(&stage.path().join("record"))?;
    store
        .pin_published_storage_dependencies(operation, &[map.id()], &[object.digest])
        .await?;
    drop(roots);
    parent.remove_tree(&name)?;
    parent.sync()?;
    Ok(SnapshotStream {
        stream: map.id(),
        map: object.digest,
        map_pages,
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
    async fn live_closure_shape_checks_state_length_without_reading_ram() {
        use crate::store::models::snapshot::SnapshotCaptureKind;
        use std::os::unix::fs::PermissionsExt;

        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let snapshots = &fixture.snapshots;
        let info = snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.alias.clone(),
            )
            .await
            .unwrap();
        let consumer = snapshots
            .consume_shape(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let SnapshotCaptureKind::LiveExecution { execution } = &consumer.record.capture else {
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
        assert_eq!(
            error.to_string(),
            crate::storage::StorageError::ContentMismatch(path).to_string(),
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
        // boundary. Publication/export/handoff never trust this receipt.
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
                fixture.reservation.record.alias.clone(),
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
    fn snapshot_reference_has_only_shared_image_namespace() {
        for invalid in [
            "",
            "snapshot:name",
            "sha256:abcd",
            "image:",
            "image:../other",
            "image:a:b",
            "image:é",
        ] {
            assert!(invalid.parse::<SnapshotRef>().is_err(), "{invalid}");
        }
        for name in [
            "image:checkpoint",
            "image:Nightly_01.raw",
            "image:sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(name.parse::<SnapshotRef>().unwrap().to_string(), name);
        }
    }

    #[tokio::test]
    async fn checkpoint_publication_requires_completed_catalog_checkpoint() {
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
        assert!(info.retained);
        assert_eq!(info.aliases, vec!["power-loss-stable".to_owned()]);
    }

    #[tokio::test]
    async fn snapshot_unnamed_retention_aliases_and_shared_bytes_are_independent() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        assert!(info.retained);
        assert!(info.aliases.is_empty());
        let same = snapshots
            .publish(&record, operation, Some("one"))
            .await
            .unwrap();
        assert_eq!(same.id, info.id);
        snapshots
            .publish(&record, operation, Some("two"))
            .await
            .unwrap();
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(lease);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(snapshots.remove_alias("one").await.unwrap());
        assert!(
            snapshots
                .inspect(&SnapshotRef::Id(info.id))
                .await
                .unwrap()
                .retained
        );
        assert!(snapshots
            .release_retention(&SnapshotRef::Id(info.id))
            .await
            .unwrap());
        let remaining = snapshots
            .inspect(&SnapshotRef::Image("two".into()))
            .await
            .unwrap();
        assert!(!remaining.retained);
        assert_eq!(remaining.aliases, ["two"]);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(snapshots.consume(&SnapshotRef::Id(info.id)).await.is_ok());
        assert!(snapshots.remove_alias("two").await.unwrap());
        assert!(snapshots.inspect(&SnapshotRef::Id(info.id)).await.is_err());
        snapshots.store.recover_image_cache().await.unwrap();
        let pool = StoragePool::open_existing(&snapshots.store.images_dir)
            .unwrap()
            .unwrap();
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
        assert!(!pool.object_path(&info.record_digest).exists());
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
        let snapshot_ref = SnapshotRef::Id(info.id);
        let (removed, released) = tokio::join!(
            snapshots.remove_alias("race"),
            snapshots.release_retention(&snapshot_ref),
        );
        assert!(removed.unwrap());
        assert!(released.unwrap());
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
        // Map roots/pages and the record are digest-checked metadata, never
        // retained by the shape as reusable object descriptors.
        for unretained in record
            .root
            .stream
            .map_pages
            .iter()
            .chain([&record.root.stream.map, &info.record_digest])
        {
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
        let mut hasher = crate::storage::stream::StreamHasher::new();
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
            SnapshotCaptureKind, SnapshotCompatibilityProfile, SnapshotExecution,
        };
        use crate::store::snapshot_store::verify_closure;

        let (_temp, snapshots, record, operation, _lease) = fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let mut consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let memory = record.root.stream.clone();
        let crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { kernel, .. },
            ..
        } = &record.boot
        else {
            panic!("fixture boot is pinned");
        };
        // Reuse a disk stream as RAM: duplicate roles retain one inode/map.
        consumer.record.capture = SnapshotCaptureKind::LiveExecution {
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
        let (_, unretained) = verify_closure(&pool, &consumer.record, None, false).unwrap();
        assert!(unretained.streams.is_empty());
        consumer.closure = Some(
            verify_closure(&pool, &consumer.record, None, true)
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
            verify_closure(&pool, &consumer.record, None, true)
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
            verify_closure(&pool, &consumer.record, None, true)
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
    async fn snapshot_publication_requires_pins_and_alias_collision_is_atomic() {
        let (_temp, snapshots, record, operation, lease) = fixture("snapshot").await;
        let info = snapshots
            .publish(&record, operation, Some("stable"))
            .await
            .unwrap();
        let mut changed = record.clone();
        changed.capture = crate::store::models::snapshot::SnapshotCaptureKind::StoppedStorage {
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
                .inspect(&SnapshotRef::Image("stable".into()))
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
        second_record.capture =
            crate::store::models::snapshot::SnapshotCaptureKind::StoppedStorage {
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
        snapshots
            .release_retention(&SnapshotRef::Id(first.id))
            .await
            .unwrap();
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
        snapshots
            .release_retention(&SnapshotRef::Id(second.id))
            .await
            .unwrap();
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
        let (_temp, snapshots, _record, operation, lease) = fixture("snapshot").await;
        let id = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let malformed = b"{not json";
        sqlx::query("INSERT INTO storage_snapshot(id,record_digest,record_bytes,retained,created_at) VALUES(?1,?2,?3,1,1)")
            .bind(format!("{id}")).bind(ObjectDigest::of_bytes(malformed).to_string()).bind(malformed.as_slice())
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
        snapshots.release_retention(&reference).await.unwrap();
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
        }
        .authenticate(parallel)
    }

    #[tokio::test]
    async fn closure_lanes_preserve_errors_member_order_and_serial_resource_fallback() {
        use std::os::unix::fs::PermissionsExt;

        use crate::storage::limits::{FileDescriptorLimits, FD_RESERVED_OVERHEAD};
        use crate::storage::StorageError;
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
        objects.extend(ram.map_pages.iter().copied());
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
            let closure =
                authenticate_test_closure(&pool, &[upper, &ram, &ram], &objects, ram.stream, mode)
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
            )
            .err()
            .unwrap();
            assert_eq!(
                error.to_string(),
                crate::store::models::snapshot::invalid("snapshot map root contradicts content",)
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
                let expected = StorageError::ContentMismatch(pool.stream_path(&first_bad.stream));
                for mode in [parallel, descriptor_fallback] {
                    let error =
                        authenticate_test_closure(&pool, &contents, &objects, ram.stream, mode)
                            .err()
                            .unwrap();
                    assert_eq!(error.to_string(), expected.to_string());
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
                )
                .err()
                .unwrap();
                assert_eq!(error.to_string(), expected.to_string());
            }
        }
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
    }
}
