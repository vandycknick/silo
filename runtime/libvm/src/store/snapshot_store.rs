//! Immutable snapshot artifacts, shared image aliases, and independent retention.
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::paths::OwnedDirectory;
use crate::storage::identity::{ObjectDigest, SnapshotId, StreamId};
use crate::storage::limits::Resource;
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureReservationRequest {
    pub machine_id: crate::store::models::MachineId,
    pub run_id: Uuid,
    pub capture_id: Uuid,
    pub configuration: vm_spec::capture::CaptureConfiguration,
    pub alias: Option<String>,
    pub policy: vm_spec::lifecycle::CapturePolicy,
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
    pub machine_id: crate::store::models::MachineId,
    pub run_id: Uuid,
    pub launch_operation_id: Uuid,
    pub alias: Option<String>,
    pub request: CaptureReservationRequest,
    pub plan: vm_spec::capture::CapturePlan,
    pub state: CaptureState,
    pub source_outcome: Option<CaptureSourceOutcome>,
    pub configuration: crate::machine::stopped::SnapshotConfiguration,
    pub storage: crate::MachineStorageRecord,
    pub disk_charges: Vec<CaptureSpaceCharge>,
    pub reservation_bytes: u64,
    pub reservation_memory_bytes: u64,
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
    pub lease: StorageLock,
    // A consumer outlives its collection handle and retains the same writable
    // catalog capability through actual blocking reads/copy/publication.
    _store: Arc<Store>,
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

    /// Unbinding an image name never releases an independently retained snapshot.
    pub async fn remove_alias(&self, name: &str) -> Result<bool, LibVmError> {
        validate_alias(name)?;
        let collection = self.clone();
        let name = name.to_owned();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || runtime.block_on(collection.remove_alias_owned(&name)))
            .await?
    }

    async fn remove_alias_owned(&self, name: &str) -> Result<bool, LibVmError> {
        let pool = StoragePool::open(&self.store.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let id = sqlx::query_scalar::<_, String>(
            "DELETE FROM image_alias WHERE name=?1 RETURNING snapshot_id",
        )
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(id) = &id {
            remove_unrooted(&mut tx, id).await?;
        }
        tx.commit().await?;
        Ok(id.is_some())
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
        let (streams, mut objects) = record.content_dependencies();
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
        let (streams, mut objects) = record.content_dependencies();
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
        let mut fingerprints = verify_closure(&pool, record, None)?;
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
        if let Some(alias) = alias {
            let current = sqlx::query_scalar::<_, String>(
                "SELECT snapshot_id FROM image_alias WHERE name=?1",
            )
            .bind(alias)
            .fetch_optional(&mut *tx)
            .await?;
            if current
                .as_deref()
                .is_some_and(|current| current != id.to_string())
            {
                return Err(invalid("image alias already names a different artifact"));
            }
            sqlx::query("INSERT INTO image_alias(name,snapshot_id) VALUES(?1,?2) ON CONFLICT(name) DO NOTHING")
                .bind(alias).bind(id.to_string()).execute(&mut *tx).await?;
        }
        if let Some((evidence_digest, evidence)) = capture {
            let existing = sqlx::query("SELECT snapshot_id,evidence_digest,evidence_bytes FROM snapshot_capture_provenance WHERE capture_id=?1")
                .bind(operation_id.to_string()).fetch_optional(&mut *tx).await?;
            if let Some(existing) = existing {
                if existing.try_get::<String, _>("snapshot_id")? != id.to_string()
                    || existing.try_get::<String, _>("evidence_digest")?
                        != evidence_digest.to_string()
                    || existing.try_get::<Vec<u8>, _>("evidence_bytes")? != evidence
                {
                    return Err(invalid("immutable capture provenance contradiction"));
                }
            } else {
                sqlx::query("INSERT INTO snapshot_capture_provenance(capture_id,snapshot_id,evidence_digest,evidence_bytes) VALUES(?1,?2,?3,?4)")
                    .bind(operation_id.to_string()).bind(id.to_string()).bind(evidence_digest.to_string()).bind(evidence).execute(&mut *tx).await?;
            }
            let json: String = sqlx::query_scalar("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'")
                .bind(operation_id.to_string()).fetch_one(&mut *tx).await?;
            let mut capture = crate::store::capture::decode_record(&json)?;
            if capture.candidate != Some(id) {
                return Err(invalid("capture candidate changed before commit"));
            }
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
        drop(_roots);
        self.inspect(&SnapshotRef::Id(id)).await
    }

    /// Register a fresh consumer and its exact closure atomically with resolving
    /// the public root. Artifact reads occur only after this transaction commits.
    pub(crate) async fn consume(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotConsumer, LibVmError> {
        let store = self.store.clone();
        let (record, observed) = self.load_observed(reference).await?;
        let bytes = record.canonical_bytes()?;
        let (streams, mut objects) = record.content_dependencies();
        objects.insert(observed.record_digest);
        let reference = reference.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let pool = StoragePool::open(&store.images_dir)?;
            let id = Uuid::new_v4();
            let (info, lease) = runtime.block_on(async {
                let _roots = pool.lock_roots()?;
                let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
                recheck_catalog(&mut tx, &reference, &observed, &bytes, &streams, &objects).await?;
                let mut info = catalog_info(&mut tx, observed.id, observed.record_digest).await?;
                info.provenance = observed.provenance.clone();
                let mut pinned_objects = objects.clone();
                pinned_objects.extend(
                    info.provenance
                        .iter()
                        .map(|provenance| provenance.evidence_digest),
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
                Ok::<_, LibVmError>((info, lease))
            })?;
            verify_closure(&pool, &record, Some(info.record_digest))?;
            for provenance in &info.provenance {
                pool.verify_object(&provenance.evidence_digest)?;
            }
            Ok(SnapshotConsumer {
                info,
                record,
                operation_id: id,
                lease,
                _store: store,
            })
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
    provenance: Vec<(String, String, Vec<u8>)>,
    capture_owned: bool,
}

pub(crate) async fn fetch_catalog(
    connection: &mut sqlx::SqliteConnection,
    reference: &SnapshotRef,
) -> Result<CatalogSnapshotFacts, LibVmError> {
    let (id, alias) = reference_parts(reference)?;
    let row = sqlx::query("SELECT id,record_digest,record_bytes,retained,created_at,EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND json_extract(record_json,'$.candidate')=storage_snapshot.id) AS capture_owned FROM storage_snapshot WHERE id=?1 OR id=(SELECT snapshot_id FROM image_alias WHERE name=?2)")
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
    let (streams, mut objects) = record.content_dependencies();
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
    let row = sqlx::query("SELECT retained,created_at,json_extract(CAST(record_bytes AS TEXT),'$.captureKind') AS capture_kind,EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND json_extract(record_json,'$.candidate')=storage_snapshot.id) AS capture_owned FROM storage_snapshot WHERE id=?1")
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
) -> Result<Vec<(String, String, Vec<u8>)>, LibVmError> {
    let rows = sqlx::query("SELECT capture_id,evidence_digest,evidence_bytes FROM snapshot_capture_provenance WHERE snapshot_id=?1 ORDER BY capture_id")
        .bind(id).fetch_all(connection).await?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("capture_id")?,
                row.try_get("evidence_digest")?,
                row.try_get("evidence_bytes")?,
            ))
        })
        .collect()
}

fn authenticate_provenance(
    facts: Vec<(String, String, Vec<u8>)>,
) -> Result<Vec<SnapshotCaptureProvenance>, LibVmError> {
    facts
        .into_iter()
        .map(|(capture, digest, bytes)| {
            let evidence = vm_spec::capture::CaptureEvidence::decode(&bytes).map_err(invalid)?;
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
        })
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
            observed.push(
                fetch_catalog(&mut tx, &SnapshotRef::Id(id.parse().map_err(invalid)?)).await?,
            );
        }
        tx.commit().await?;
        for facts in observed {
            authenticate_catalog(facts)?;
        }
    }
    Ok(())
}

async fn remove_unrooted(
    connection: &mut sqlx::SqliteConnection,
    id: &str,
) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM storage_snapshot WHERE id=?1 AND retained=0 AND NOT EXISTS(SELECT 1 FROM image_alias WHERE snapshot_id=?1) AND NOT EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND json_extract(record_json,'$.candidate')=?1)")
        .bind(id).execute(connection).await?;
    Ok(())
}
async fn require_operation_closure(
    store: &Store,
    operation: Uuid,
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
    pending: Option<ObjectDigest>,
) -> Result<(), LibVmError> {
    let mut tx = store.pool.begin().await?;
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind IN ('snapshot','capture') AND state IN ('staging','committing'))")
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

type ClosureFingerprints = Vec<(
    std::path::PathBuf,
    crate::storage::identity_file::SourceFingerprint,
)>;

fn recheck_closure(fingerprints: &ClosureFingerprints) -> Result<(), LibVmError> {
    for (path, before) in fingerprints {
        if crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(path)?)
            != *before
        {
            return Err(invalid(
                "authenticated snapshot closure changed before publication",
            ));
        }
    }
    Ok(())
}

fn verify_closure(
    pool: &StoragePool,
    record: &SnapshotRecord,
    digest: Option<ObjectDigest>,
) -> Result<ClosureFingerprints, LibVmError> {
    let bytes = record.canonical_bytes()?;
    let record_digest = ObjectDigest::of_bytes(&bytes);
    let (streams, mut objects) = record.content_dependencies();
    if digest.is_some() {
        objects.insert(record_digest);
    }
    let mut fingerprints = Vec::with_capacity(streams.len() + objects.len());
    for path in streams.iter().map(|stream| pool.stream_path(stream)).chain(
        objects
            .iter()
            .filter(|object| digest.is_some() || **object != record_digest)
            .map(|object| pool.object_path(object)),
    ) {
        let before = crate::storage::identity_file::SourceFingerprint::new(
            &std::fs::symlink_metadata(&path)?,
        );
        fingerprints.push((path, before));
    }
    if let Some(digest) = digest {
        if digest != record_digest
            || pool.read_object(&digest, Resource::MetadataPageBytes.maximum())? != bytes
        {
            return Err(invalid("snapshot object contradicts its catalog record"));
        }
    }
    let mut verified_streams = BTreeSet::new();
    for content in record.streams() {
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
        if map.id() != content.stream
            || map.length() != content.length
            || (verified_streams.insert(content.stream)
                && pool.verify_stream(&content.stream)? != map)
        {
            return Err(invalid("snapshot stream/map/backing contradiction"));
        }
    }
    let maps = record
        .streams()
        .map(|stream| stream.map)
        .collect::<BTreeSet<_>>();
    for object in objects {
        if maps.contains(&object) || object == record_digest {
            continue;
        }
        pool.verify_object(&object)?;
    }
    recheck_closure(&fingerprints)?;
    Ok(fingerprints)
}
struct RecordInput {
    parent: OwnedDirectory,
    directory: OwnedDirectory,
    name: String,
}
impl RecordInput {
    fn new(images: &Path, operation: Uuid, bytes: &[u8]) -> Result<Self, LibVmError> {
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
    fn path(&self) -> std::path::PathBuf {
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
    map: crate::storage::stream::StreamMap,
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
    for (index, page) in crate::storage::map::pages(&map).enumerate() {
        let name = format!("page-{index}");
        stage.write_file(&name, &page?)?;
        let (object, roots) = pool.publish_object_for_catalog(&stage.path().join(&name))?;
        store
            .pin_published_storage_dependencies(operation, &[], &[object.digest])
            .await?;
        map_pages.push(object.digest);
        drop(roots);
    }
    let root = crate::storage::map::StreamMapRoot::new(&map, map_pages.clone())?;
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
mod tests {
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

    async fn fixture(
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
        let map = crate::store::snapshot_store::publish_map(&pool, &store, operation, stream.map)
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
        let (streams, mut objects) = record.content_dependencies();
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
}
