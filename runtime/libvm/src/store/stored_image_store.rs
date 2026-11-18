//! Canonical immutable stored images (imported, converted or pulled raw
//! images). Names live in the shared `image_name` table with cached OCI
//! images; snapshots have their own names. Slow reads run in the actual
//! lease-owning blocking worker. Root locks cover only catalog rechecks and
//! publication commits, never whole-stream hashing. Appendable history is
//! authenticated one bounded blob page at a time; names use 64-name pages.
//! Inspection/list responses admit at most the existing MetadataPageBytes and
//! MetadataPageEntries totals across stored images. They fail explicitly
//! rather than truncating; consumers and GC need no diagnostic aggregate and
//! can authenticate larger histories.
use std::collections::BTreeSet;
use std::fs::File;
use std::sync::Arc;

use sqlx::Row;
use uuid::Uuid;

use crate::image::import_types::{ImageProvenance, RawConversionKey, StoredImageInfo};
use crate::storage::identity::{ImageId, ObjectDigest, StreamId};
use crate::storage::limits::Resource;
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
use crate::storage::stream::AuthenticatedStream;
use crate::store::models::image::{image_id, ImageRecord};
use crate::store::models::snapshot::{canonical_value, decode_identity_value};
use crate::store::snapshot_store::{
    bind_held, bind_reopened, recheck_closure, require_operation_closure, verify_artifact_closure,
    AuthenticatedClosure, RecordInput,
};
use crate::store::Store;
use crate::LibVmError;

fn invalid(message: impl std::fmt::Display) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "stored-image",
        message: message.to_string(),
    }
}

#[derive(Clone)]
pub(crate) struct StoredImageStore {
    store: Arc<Store>,
}

/// Not Clone: the actual copying worker must own this complete capability.
/// Dropping a caller future cannot close the original operation OFD in that worker.
pub(crate) struct StoredImageConsumer {
    pub info: StoredImageRoot,
    pub operation_id: Uuid,
    _lease: StorageLock,
    closure: AuthenticatedClosure,
    _store: Arc<Store>,
}

impl StoredImageConsumer {
    pub(crate) fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub(crate) fn duplicate_lease(&self) -> Result<StorageLock, LibVmError> {
        Ok(self._lease.duplicate()?)
    }
    pub(crate) fn open_stream(&self, pool: &StoragePool) -> Result<File, LibVmError> {
        let stream = &self.info.record.root.stream;
        let held = self
            .closure
            .streams
            .get(&stream.stream)
            .ok_or_else(|| invalid("image root is outside authenticated closure"))?;
        if held.length() != stream.length {
            return Err(invalid("image root geometry changed"));
        }
        bind_held(held.file(), held.fingerprint())?;
        let file = pool.open_stream(&stream.stream)?;
        bind_reopened(&file, held.fingerprint())?;
        Ok(file)
    }

    pub(crate) fn open_copy_source(
        &self,
        pool: &StoragePool,
    ) -> Result<AuthenticatedStream, LibVmError> {
        let held = self
            .closure
            .streams
            .get(&self.info.record.root.stream.stream)
            .ok_or_else(|| invalid("image root is outside authenticated closure"))?;
        Ok(held.reopen(self.open_stream(pool)?)?)
    }
}

impl StoredImageStore {
    pub(crate) fn from_store(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub(crate) async fn inspect(&self, id: ImageId) -> Result<StoredImageInfo, LibVmError> {
        let mut tx = self.store.pool.begin().await?;
        let observed = fetch_image(&mut tx, id, Some(&mut InspectionBudget::default())).await?;
        tx.commit().await?;
        Ok(observed.into_info())
    }

    pub(crate) async fn list(&self) -> Result<Vec<StoredImageInfo>, LibVmError> {
        let mut cursor = String::new();
        let mut images = Vec::new();
        let mut budget = InspectionBudget::default();
        loop {
            let mut tx = self.store.pool.begin().await?;
            let ids = sqlx::query_scalar::<_, String>(
                "SELECT id FROM storage_image WHERE id>?1 ORDER BY id LIMIT 256",
            )
            .bind(&cursor)
            .fetch_all(&mut *tx)
            .await?;
            if ids.is_empty() {
                tx.commit().await?;
                break;
            }
            for id in ids {
                cursor = id.clone();
                let observed =
                    fetch_image(&mut tx, id.parse().map_err(invalid)?, Some(&mut budget)).await?;
                images.push(observed.into_info());
            }
            tx.commit().await?;
        }
        Ok(images)
    }

    async fn load_root(&self, id: ImageId) -> Result<StoredImageRoot, LibVmError> {
        let mut tx = self.store.pool.begin().await?;
        let observed = fetch_image(&mut tx, id, None).await?;
        tx.commit().await?;
        Ok(observed.root)
    }

    /// Already prepared raw/map and boot member inputs must be operation-pinned.
    /// This method takes the original OFD, so cancellation cannot revoke the
    /// worker during authentication, publication or an uncertain SQL commit.
    pub(crate) async fn publish_owned(
        &self,
        record: ImageRecord,
        operation_id: Uuid,
        lease: StorageLock,
        name: Option<String>,
        provenance: Vec<ImageProvenance>,
        conversion: Option<RawConversionKey>,
    ) -> Result<StoredImageInfo, LibVmError> {
        let collection = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            runtime.block_on(collection.publish(
                &record,
                operation_id,
                &_lease,
                name.as_deref(),
                provenance,
                conversion,
            ))
        })
        .await?
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish(
        &self,
        record: &ImageRecord,
        operation: Uuid,
        lease: &StorageLock,
        name: Option<&str>,
        provenance: Vec<ImageProvenance>,
        conversion: Option<RawConversionKey>,
    ) -> Result<StoredImageInfo, LibVmError> {
        if let Some(name) = name {
            crate::store::names::validate_name(name)?;
        }
        let bytes = record.canonical_bytes()?;
        #[cfg(test)]
        if let Some(hook) = &self.store.layer_hook {
            hook.hit(crate::store::layer_store::tests::WorkerPoint::Preparing)?;
        }
        if let Some(key) = &conversion {
            key.canonical_bytes()?;
            if !provenance.iter().any(|source| {
                source.container == crate::image::import_types::ImageContainerKind::Oci
                    && source.source_manifest == Some(key.source_manifest)
                    && source.source_config.is_some()
            }) {
                return Err(invalid(
                    "conversion key has no checked OCI source provenance",
                ));
            }
        }
        let id = image_id(&bytes);
        let digest = ObjectDigest::of_bytes(&bytes);
        let binding = record.boot_binding()?;
        let bundle_bytes = binding.canonical_bytes()?;
        let bundle = ObjectDigest::of_bytes(&bundle_bytes);
        let (streams, mut objects) = record.content_dependencies()?;
        // Only the two metadata outputs may be new. Every input is retained
        // before any byte authentication or publication begins.
        let mut inputs = objects.clone();
        inputs.remove(&bundle);
        require_operation_closure(&self.store, operation, &streams, &inputs, None).await?;
        let (device, inode) = lease.file_identity()?;
        let owner: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind IN ('import','convert') AND state='staging' AND file_device=?2 AND file_inode=?3)")
            .bind(operation.to_string()).bind(device.to_string()).bind(inode.to_string()).fetch_one(&self.store.pool).await?;
        if !owner {
            return Err(invalid(
                "image publication lacks its original operation lease",
            ));
        }
        let pool = StoragePool::open(&self.store.images_dir)?;
        let bundle_input = RecordInput::new(&self.store.images_dir, operation, &bundle_bytes)?;
        let (published_bundle, guard) = pool.publish_object_for_catalog(&bundle_input.path())?;
        if published_bundle.digest != bundle {
            return Err(invalid("boot bundle publication digest contradiction"));
        }
        self.store
            .pin_published_storage_dependencies(operation, &[], &[bundle])
            .await?;
        drop(guard);
        let mut retained_objects = objects.clone();
        retained_objects.remove(&record.root.stream.map);
        let (mut fingerprints, _closure) = verify_artifact_closure(
            &pool,
            &bytes,
            &[&record.root.stream],
            objects.clone(),
            retained_objects,
            None,
            true,
            None,
            Arc::new(lease.duplicate()?),
        )?;
        if pool.read_object(
            &bundle,
            crate::storage::limits::Resource::MetadataPageBytes.maximum(),
        )? != bundle_bytes
        {
            return Err(invalid("image bundle object contradicts its pinned tuple"));
        }
        let input = RecordInput::new(&self.store.images_dir, operation, &bytes)?;
        let (published, guard) = pool.publish_object_for_catalog(&input.path())?;
        if published.digest != digest {
            return Err(invalid("image record publication digest contradiction"));
        }
        self.store
            .pin_published_storage_dependencies(operation, &[], &[digest])
            .await?;
        fingerprints.push((
            published.path.clone(),
            crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
                &published.path,
            )?),
        ));
        drop(guard);
        objects.insert(digest);
        let provenance = provenance
            .into_iter()
            .map(|value| {
                validate_provenance_image(record, &value)?;
                let bytes = provenance_bytes(&value)?;
                Ok((ObjectDigest::of_bytes(&bytes), bytes))
            })
            .collect::<Result<Vec<_>, LibVmError>>()?;
        let conversion = conversion
            .map(|key| {
                let bytes = key.canonical_bytes()?;
                let crate::store::models::storage::BootProfile::LinuxDirect {
                    userspace_platform,
                    ..
                } = &record.boot
                else {
                    return Err(invalid("conversion result is not Linux direct"));
                };
                if &key.platform != userspace_platform
                    || record.root.layout != crate::store::models::storage::RawLayout::WholeDisk
                {
                    return Err(invalid(
                        "conversion key contradicts image platform or layout",
                    ));
                }
                Ok((ObjectDigest::of_bytes(&bytes), bytes))
            })
            .transpose()?;
        self.store.preserve_image_operation(operation, id).await?;
        #[cfg(test)]
        if let Some(hook) = &self.store.layer_hook {
            hook.hit(crate::store::layer_store::tests::WorkerPoint::BeforeRoots)?;
        }
        let _roots = pool.lock_roots_shared()?;
        recheck_closure(&fingerprints)?;
        require_operation_closure(&self.store, operation, &streams, &objects, None).await?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let existing =
            sqlx::query("SELECT record_digest,CASE WHEN length(CAST(record_bytes AS BLOB))<=?2 THEN record_bytes END AS bytes FROM storage_image WHERE id=?1")
                .bind(id.to_string())
                .bind(Resource::MetadataPageBytes.maximum() as i64)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(existing) = existing {
            if existing.try_get::<String, _>("record_digest")? != digest.to_string()
                || bounded_blob(&existing)? != bytes
            {
                return Err(invalid("immutable image identity contradiction"));
            }
            exact_dependencies(&mut tx, id, &streams, &objects).await?;
        } else {
            sqlx::query("INSERT INTO storage_image(id,record_digest,record_bytes,created_at) VALUES(?1,?2,?3,?4)")
                .bind(id.to_string()).bind(digest.to_string()).bind(&bytes).bind(chrono::Utc::now().timestamp()).execute(&mut *tx).await?;
            for stream in &streams {
                sqlx::query(
                    "INSERT INTO image_stream_dependency(image_id,stream_id) VALUES(?1,?2)",
                )
                .bind(id.to_string())
                .bind(stream.to_string())
                .execute(&mut *tx)
                .await?;
            }
            for object in &objects {
                sqlx::query(
                    "INSERT INTO image_object_dependency(image_id,object_digest) VALUES(?1,?2)",
                )
                .bind(id.to_string())
                .bind(object.to_string())
                .execute(&mut *tx)
                .await?;
            }
        }
        if let Some(name) = name {
            crate::store::image_store::insert_image_name(
                &mut tx,
                name,
                crate::store::image_store::LocalImage::Stored(id),
            )
            .await?;
        }
        for (digest, bytes) in provenance {
            let existing = sqlx::query(
                "SELECT CASE WHEN length(CAST(record_bytes AS BLOB))<=?3 THEN record_bytes END AS bytes FROM image_provenance WHERE image_id=?1 AND digest=?2",
            )
            .bind(id.to_string())
            .bind(digest.to_string())
            .bind(Resource::MetadataPageBytes.maximum() as i64)
            .fetch_optional(&mut *tx)
            .await?
            .map(|row| bounded_blob(&row))
            .transpose()?;
            if existing.as_ref().is_some_and(|existing| existing != &bytes) {
                return Err(invalid("immutable image provenance contradiction"));
            }
            sqlx::query("INSERT INTO image_provenance(image_id,digest,record_bytes) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING")
                .bind(id.to_string()).bind(digest.to_string()).bind(bytes).execute(&mut *tx).await?;
        }
        if let Some((key, bytes)) = conversion {
            let existing = sqlx::query(
                "SELECT image_id,CASE WHEN length(CAST(key_bytes AS BLOB))<=?2 THEN key_bytes END AS bytes FROM raw_conversion_result WHERE key_digest=?1",
            )
            .bind(key.to_string())
            .bind(Resource::MetadataPageBytes.maximum() as i64)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(existing) = existing {
                if existing.try_get::<String, _>("image_id")? != id.to_string()
                    || bounded_blob(&existing)? != bytes
                {
                    return Err(invalid(
                        "raw conversion key already names a different immutable result",
                    ));
                }
            } else {
                sqlx::query("INSERT INTO raw_conversion_result(key_digest,key_bytes,image_id) VALUES(?1,?2,?3)")
                    .bind(key.to_string()).bind(bytes).bind(id.to_string()).execute(&mut *tx).await?;
            }
        }
        let changed = sqlx::query("UPDATE storage_operation SET state='committed',record_json=jsonb('{}') WHERE operation_id=?1 AND kind IN ('import','convert') AND state='committing' AND json_extract(record_json,'$.candidateImageId')=?2")
            .bind(operation.to_string()).bind(id.to_string()).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(invalid("image publication candidate changed before commit"));
        }
        let observed = fetch_image(&mut tx, id, Some(&mut InspectionBudget::default())).await?;
        tx.commit().await?;
        drop(_roots);
        Ok(observed.into_info())
    }

    pub(crate) async fn consume(&self, id: ImageId) -> Result<StoredImageConsumer, LibVmError> {
        let observed = self.load_root(id).await?;
        let collection = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let result: Result<StoredImageConsumer, LibVmError> = runtime.block_on(async {
                let bytes = observed.record.canonical_bytes()?;
                let (streams, mut objects) = observed.record.content_dependencies()?;
                objects.insert(observed.record_digest);
                let pool = StoragePool::open(&collection.store.images_dir)?;
                let operation_id = Uuid::new_v4();
                let lease = {
                    let _roots = pool.lock_roots()?;
                    let mut tx = collection.store.pool.begin_with("BEGIN IMMEDIATE").await?;
                    recheck_image(&mut tx, &observed, &bytes, &streams, &objects).await?;
                    let acquisition = crate::store::artifact_store::acquisition_objects(
                        &mut tx,
                        "image",
                        &observed.id.to_string(),
                    )
                    .await?;
                    objects.extend(acquisition);
                    let lease = pool.lease(operation_id)?;
                    Store::insert_stopped_operation(
                        &mut tx,
                        operation_id,
                        "import",
                        &lease,
                        &streams.iter().copied().collect::<Vec<_>>(),
                        &objects.iter().copied().collect::<Vec<_>>(),
                    )
                    .await?;
                    tx.commit().await?;
                    lease
                };
                collection
                    .store
                    .materialize_stream(operation_id, &observed.record.root.stream)
                    .await?;
                #[cfg(test)]
                if let Some(hook) = &collection.store.layer_hook {
                    hook.hit(crate::store::layer_store::tests::WorkerPoint::AfterObject)?;
                }
                let mut retained_objects = observed.record.content_dependencies()?.1;
                retained_objects.remove(&observed.record_digest);
                retained_objects.remove(&observed.record.root.stream.map);
                let (_, closure) = verify_artifact_closure(
                    &pool,
                    &bytes,
                    &[&observed.record.root.stream],
                    objects,
                    retained_objects,
                    Some(observed.record_digest),
                    true,
                    None,
                    Arc::new(lease.duplicate()?),
                )?;
                let binding = observed.record.boot_binding()?;
                if pool.read_object(
                    &binding.digest()?,
                    crate::storage::limits::Resource::MetadataPageBytes.maximum(),
                )? != binding.canonical_bytes()?
                {
                    return Err(invalid("image bundle object contradicts its pinned tuple"));
                }
                Ok(StoredImageConsumer {
                    info: observed,
                    operation_id,
                    _lease: lease,
                    closure,
                    _store: collection.store.clone(),
                })
            });
            match result {
                Ok(consumer) => Ok(consumer),
                Err(primary) => {
                    let pool = StoragePool::open(&collection.store.images_dir)?;
                    if let Err(cleanup) = runtime
                        .block_on(collection.store.retire_abandoned_storage_operations(&pool))
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

    /// A retained mapping is authoritative, not a hint. Missing/corrupt content
    /// propagates as an error; it must never trigger a replacement flattening.
    pub(crate) async fn lookup_conversion(
        &self,
        key: &RawConversionKey,
    ) -> Result<Option<StoredImageConsumer>, LibVmError> {
        let bytes = key.canonical_bytes()?;
        let digest = ObjectDigest::of_bytes(&bytes);
        let mut tx = self.store.pool.begin().await?;
        let row =
            sqlx::query("SELECT image_id,CASE WHEN length(CAST(key_bytes AS BLOB))<=?2 THEN key_bytes END AS bytes FROM raw_conversion_result WHERE key_digest=?1")
                .bind(digest.to_string())
                .bind(Resource::MetadataPageBytes.maximum() as i64)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        let Some(row) = row else { return Ok(None) };
        if bounded_blob(&row)? != bytes {
            return Err(invalid("conversion key digest contradiction"));
        }
        let id: ImageId = row
            .try_get::<String, _>("image_id")?
            .parse()
            .map_err(invalid)?;
        let consumer = self.consume(id).await?;
        let crate::store::models::storage::BootProfile::LinuxDirect {
            userspace_platform, ..
        } = &consumer.info.record.boot
        else {
            return Err(invalid("conversion result is not Linux direct"));
        };
        if &key.platform != userspace_platform {
            return Err(invalid("conversion platform contradicts image"));
        }
        Ok(Some(consumer))
    }

    /// Tag an existing stored image with a new local name. A name already
    /// naming another image is refused; naming the same image again is a no-op.
    pub(crate) async fn add_name(
        &self,
        id: ImageId,
        name: &str,
    ) -> Result<StoredImageInfo, LibVmError> {
        crate::store::names::validate_name(name)?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        crate::store::image_store::insert_image_name(
            &mut tx,
            name,
            crate::store::image_store::LocalImage::Stored(id),
        )
        .await?;
        let observed = fetch_image(&mut tx, id, Some(&mut InspectionBudget::default())).await?;
        tx.commit().await?;
        Ok(observed.into_info())
    }
}

/// Canonical consumer authority deliberately excludes appendable diagnostics.
#[derive(Debug, Clone)]
pub(crate) struct StoredImageRoot {
    pub id: ImageId,
    pub record_digest: ObjectDigest,
    pub record: ImageRecord,
}

struct ImageObservation {
    root: StoredImageRoot,
    names: Vec<String>,
    provenance: Vec<ImageProvenance>,
}

impl ImageObservation {
    fn into_info(self) -> StoredImageInfo {
        StoredImageInfo {
            id: self.root.id,
            record_digest: self.root.record_digest,
            record: self.root.record,
            names: self.names,
            provenance: self.provenance,
        }
    }
}

/// Inspection admits one existing metadata page's encoded bytes and entries
/// across the entire response, not one allowance per appendable record.
#[derive(Default)]
struct InspectionBudget {
    bytes: u64,
    entries: u64,
}

impl InspectionBudget {
    fn charge(&mut self, bytes: u64) -> Result<(), LibVmError> {
        self.bytes = Resource::MetadataPageBytes
            .sum([self.bytes, bytes])
            .map_err(crate::storage::StorageError::from)?;
        self.entries = Resource::MetadataPageEntries
            .sum([self.entries, 1])
            .map_err(crate::storage::StorageError::from)?;
        Ok(())
    }
}

/// SQL guards keep oversized persisted values out of SQLx-owned allocations.
/// Each blob page contains one record (at most MetadataPageBytes); name pages
/// contain at most 64 names of at most 512 bytes. No history-sized state
/// survives a page unless the caller explicitly admits the bounded response.
async fn fetch_image(
    connection: &mut sqlx::SqliteConnection,
    id: ImageId,
    mut budget: Option<&mut InspectionBudget>,
) -> Result<ImageObservation, LibVmError> {
    let row = sqlx::query("SELECT record_digest,CASE WHEN length(CAST(record_bytes AS BLOB))<=?2 THEN record_bytes END AS bytes FROM storage_image WHERE id=?1")
        .bind(id.to_string())
        .bind(Resource::MetadataPageBytes.maximum() as i64)
        .fetch_optional(&mut *connection).await?
        .ok_or_else(|| LibVmError::ImageNotFound { reference: id.to_string() })?;
    let bytes = bounded_blob(&row)?;
    if let Some(budget) = budget.as_deref_mut() {
        budget.charge(bytes.len() as u64)?;
    }
    let record = ImageRecord::decode(&bytes)?;
    let digest: ObjectDigest = row
        .try_get::<String, _>("record_digest")?
        .parse()
        .map_err(invalid)?;
    if image_id(&bytes) != id || ObjectDigest::of_bytes(&bytes) != digest {
        return Err(invalid("image catalog identity contradiction"));
    }
    let (streams, mut objects) = record.content_dependencies()?;
    objects.insert(digest);
    exact_dependencies(connection, id, &streams, &objects).await?;
    crate::store::artifact_store::acquisition_objects(connection, "image", &id.to_string()).await?;
    let mut observation = ImageObservation {
        root: StoredImageRoot {
            id,
            record_digest: digest,
            record,
        },
        names: Vec::new(),
        provenance: Vec::new(),
    };
    let mut cursor = String::new();
    loop {
        let names = sqlx::query_scalar::<_, Option<String>>(
            "SELECT CASE WHEN length(CAST(name AS BLOB))<=512 THEN name END FROM image_name WHERE stored_image_id=?1 AND name>?2 ORDER BY name LIMIT 64",
        ).bind(id.to_string()).bind(&cursor).fetch_all(&mut *connection).await?;
        if names.is_empty() {
            break;
        }
        for name in names {
            let name = name.ok_or_else(|| invalid("oversized image name"))?;
            crate::store::names::validate_stored_name(&name)?;
            cursor = name.clone();
            if let Some(budget) = budget.as_deref_mut() {
                budget.charge(name.len() as u64)?;
                observation.names.push(name);
            }
        }
    }
    // Empty keys sort before the exclusive keyset cursors.
    let empty_key: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM image_name WHERE stored_image_id=?1 AND name='' UNION ALL SELECT 1 FROM image_provenance WHERE image_id=?1 AND digest='' UNION ALL SELECT 1 FROM raw_conversion_result WHERE image_id=?1 AND key_digest='')")
        .bind(id.to_string()).fetch_one(&mut *connection).await?;
    if empty_key {
        return Err(invalid("image has malformed metadata"));
    }
    let mut cursor = String::new();
    loop {
        let row = sqlx::query("SELECT CASE WHEN length(CAST(digest AS BLOB))=71 THEN digest END AS digest,CASE WHEN length(CAST(record_bytes AS BLOB))<=?3 THEN record_bytes END AS bytes FROM image_provenance WHERE image_id=?1 AND digest>?2 ORDER BY digest LIMIT 1")
            .bind(id.to_string()).bind(&cursor)
            .bind(Resource::MetadataPageBytes.maximum() as i64)
            .fetch_optional(&mut *connection).await?;
        let Some(row) = row else { break };
        let (digest, bytes) = metadata_page(&row)?;
        cursor = digest.to_string();
        if let Some(budget) = budget.as_deref_mut() {
            budget.charge(bytes.len() as u64)?;
        }
        let value = decode_identity_value(&bytes)?;
        let provenance: ImageProvenance = serde_json::from_value(value).map_err(invalid)?;
        if provenance_bytes(&provenance)? != bytes {
            return Err(invalid("image provenance is not closed current schema"));
        }
        validate_provenance_image(&observation.root.record, &provenance)?;
        if budget.is_some() {
            observation.provenance.push(provenance);
        }
    }
    let mut cursor = String::new();
    loop {
        let row = sqlx::query("SELECT CASE WHEN length(CAST(key_digest AS BLOB))=71 THEN key_digest END AS digest,CASE WHEN length(CAST(key_bytes AS BLOB))<=?3 THEN key_bytes END AS bytes FROM raw_conversion_result WHERE image_id=?1 AND key_digest>?2 ORDER BY key_digest LIMIT 1")
            .bind(id.to_string()).bind(&cursor)
            .bind(Resource::MetadataPageBytes.maximum() as i64)
            .fetch_optional(&mut *connection).await?;
        let Some(row) = row else { break };
        let (digest, bytes) = metadata_page(&row)?;
        cursor = digest.to_string();
        if let Some(budget) = budget.as_deref_mut() {
            budget.charge(bytes.len() as u64)?;
        }
        let key: RawConversionKey =
            serde_json::from_value(decode_identity_value(&bytes)?).map_err(invalid)?;
        let crate::BootProfile::LinuxDirect {
            userspace_platform, ..
        } = &observation.root.record.boot
        else {
            return Err(invalid("conversion image is not Linux direct"));
        };
        // Every provenance row above was authenticated in this same transaction.
        // Match against that catalog rather than retaining a history-sized set.
        let has_source: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM image_provenance WHERE image_id=?1 AND json_extract(record_bytes,'$.container')='oci' AND json_extract(record_bytes,'$.sourceManifest')=?2 AND json_extract(record_bytes,'$.sourceConfig') IS NOT NULL)")
            .bind(id.to_string()).bind(key.source_manifest.to_string())
            .fetch_one(&mut *connection).await?;
        if key.canonical_bytes()? != bytes
            || &key.platform != userspace_platform
            || observation.root.record.root.layout != crate::RawLayout::WholeDisk
            || !has_source
        {
            return Err(invalid(
                "conversion mapping contradicts its canonical key or image",
            ));
        }
    }
    Ok(observation)
}

fn bounded_blob(row: &sqlx::sqlite::SqliteRow) -> Result<Vec<u8>, LibVmError> {
    row.try_get::<Option<Vec<u8>>, _>("bytes")?
        .ok_or_else(|| invalid("persisted image metadata exceeds MetadataPageBytes"))
}

fn metadata_page(row: &sqlx::sqlite::SqliteRow) -> Result<(ObjectDigest, Vec<u8>), LibVmError> {
    let digest: ObjectDigest = row
        .try_get::<Option<String>, _>("digest")?
        .ok_or_else(|| invalid("invalid image metadata digest length"))?
        .parse()
        .map_err(invalid)?;
    let bytes = bounded_blob(row)?;
    if ObjectDigest::of_bytes(&bytes) != digest {
        return Err(invalid("image metadata digest contradiction"));
    }
    Ok((digest, bytes))
}

fn provenance_bytes(provenance: &ImageProvenance) -> Result<Vec<u8>, LibVmError> {
    match provenance.container {
        crate::image::import_types::ImageContainerKind::Oci
            if provenance.source_manifest.is_none()
                || provenance.source_config.is_none()
                || provenance.disk.is_some() =>
        {
            return Err(invalid(
                "OCI image provenance requires manifest/config and no disk observations",
            ));
        }
        crate::image::import_types::ImageContainerKind::Raw
        | crate::image::import_types::ImageContainerKind::Qcow2
            if provenance.source_manifest.is_some()
                || provenance.source_config.is_some()
                || provenance.disk.is_none() =>
        {
            return Err(invalid(
                "disk image provenance requires disk observations and no OCI identities",
            ));
        }
        _ => {}
    }
    if let Some(disk) = &provenance.disk {
        crate::storage::limits::validate_disk_length(disk.decoded_length)
            .map_err(crate::storage::StorageError::from)?;
        if disk.source_length == 0
            || (provenance.container == crate::image::import_types::ImageContainerKind::Raw
                && disk.source_length != disk.decoded_length)
        {
            return Err(invalid("disk provenance has inconsistent observed lengths"));
        }
        if let Some(candidate) = &disk.selected_root {
            let extent_end = candidate
                .first_lba
                .checked_add(candidate.length_lbas)
                .ok_or_else(|| invalid("observed root extent overflows"))?;
            let selector_valid = match &candidate.selector {
                crate::RootSelector::GptPartition { guid } => {
                    !guid.is_nil() && candidate.gpt_type.is_some() && candidate.mbr_type.is_none()
                }
                crate::RootSelector::MbrPartition { number } => {
                    (1..=4).contains(number)
                        && candidate.mbr_type.is_some()
                        && candidate.gpt_type.is_none()
                }
                _ => false,
            };
            if !selector_valid
                || candidate.length_lbas == 0
                || extent_end > disk.decoded_length / 512
            {
                return Err(invalid("disk provenance has an invalid observed partition"));
            }
        }
    }
    let bytes = canonical_value(&serde_json::to_value(provenance).map_err(invalid)?)?;
    crate::storage::limits::Resource::MetadataPageBytes
        .check(bytes.len() as u64)
        .map_err(crate::storage::StorageError::from)?;
    Ok(bytes)
}

fn validate_provenance_image(
    record: &ImageRecord,
    provenance: &ImageProvenance,
) -> Result<(), LibVmError> {
    if let Some(disk) = &provenance.disk {
        let crate::BootProfile::LinuxDirect { root_selector, .. } = &record.boot else {
            return Err(invalid("disk provenance requires direct boot image"));
        };
        let selector = disk
            .selected_root
            .as_ref()
            .map_or(&crate::RootSelector::WholeDisk, |root| &root.selector);
        if disk.decoded_length != record.root.geometry.length || selector != root_selector {
            return Err(invalid(
                "disk provenance contradicts image creation geometry or selection",
            ));
        }
    }
    Ok(())
}

async fn exact_dependencies(
    connection: &mut sqlx::SqliteConnection,
    id: ImageId,
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
) -> Result<(), LibVmError> {
    let counts = sqlx::query("SELECT (SELECT count(*) FROM image_stream_dependency WHERE image_id=?1) AS streams,(SELECT count(*) FROM image_object_dependency WHERE image_id=?1) AS objects")
        .bind(id.to_string()).fetch_one(&mut *connection).await?;
    if counts.try_get::<i64, _>("streams")? != streams.len() as i64
        || counts.try_get::<i64, _>("objects")? != objects.len() as i64
    {
        return Err(invalid("image dependency closure contradiction"));
    }
    let actual_streams = sqlx::query_scalar::<_, Option<String>>(
        "SELECT CASE WHEN length(CAST(stream_id AS BLOB))=71 THEN stream_id END FROM image_stream_dependency WHERE image_id=?1",
    )
    .bind(id.to_string())
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|id| id.ok_or_else(|| invalid("invalid image stream dependency length"))?.parse().map_err(invalid))
    .collect::<Result<BTreeSet<StreamId>, _>>()?;
    let actual_objects = sqlx::query_scalar::<_, Option<String>>(
        "SELECT CASE WHEN length(CAST(object_digest AS BLOB))=71 THEN object_digest END FROM image_object_dependency WHERE image_id=?1",
    )
    .bind(id.to_string())
    .fetch_all(connection)
    .await?
    .into_iter()
    .map(|id| id.ok_or_else(|| invalid("invalid image object dependency length"))?.parse().map_err(invalid))
    .collect::<Result<BTreeSet<ObjectDigest>, _>>()?;
    if &actual_streams != streams || &actual_objects != objects {
        return Err(invalid("image dependency closure contradiction"));
    }
    Ok(())
}

async fn recheck_image(
    connection: &mut sqlx::SqliteConnection,
    observed: &StoredImageRoot,
    bytes: &[u8],
    streams: &BTreeSet<StreamId>,
    objects: &BTreeSet<ObjectDigest>,
) -> Result<(), LibVmError> {
    let row = sqlx::query("SELECT record_digest,CASE WHEN length(CAST(record_bytes AS BLOB))<=?2 THEN record_bytes END AS bytes FROM storage_image WHERE id=?1")
        .bind(observed.id.to_string())
        .bind(Resource::MetadataPageBytes.maximum() as i64)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| invalid("image root was removed before consumer registration"))?;
    if row.try_get::<String, _>("record_digest")? != observed.record_digest.to_string()
        || bounded_blob(&row)? != bytes
    {
        return Err(invalid("image root changed before consumer registration"));
    }
    exact_dependencies(connection, observed.id, streams, objects).await
}

/// Fail closed before collectors interpret any image edge as reachability.
pub(crate) async fn check_image_catalog(store: &Store) -> Result<(), LibVmError> {
    let malformed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM image_name n WHERE (n.oci_image_id IS NOT NULL) + (n.stored_image_id IS NOT NULL) != 1 OR (n.stored_image_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM storage_image WHERE id=n.stored_image_id)) OR (n.oci_image_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM image_composition_artifact WHERE image_id=n.oci_image_id)) UNION ALL SELECT 1 FROM snapshot_name n WHERE NOT EXISTS(SELECT 1 FROM storage_snapshot WHERE id=n.snapshot_id) UNION ALL SELECT 1 FROM raw_conversion_result c WHERE NOT EXISTS(SELECT 1 FROM storage_image WHERE id=c.image_id))")
        .fetch_one(&store.pool).await?;
    if malformed {
        return Err(invalid("a name or conversion has a corrupt typed target"));
    }
    let mut cursor = String::new();
    loop {
        let mut tx = store.pool.begin().await?;
        let ids = sqlx::query_scalar::<_, String>(
            "SELECT id FROM storage_image WHERE id>?1 ORDER BY id LIMIT 256",
        )
        .bind(&cursor)
        .fetch_all(&mut *tx)
        .await?;
        if ids.is_empty() {
            tx.commit().await?;
            break;
        }
        for id in ids {
            cursor = id.clone();
            fetch_image(&mut tx, id.parse().map_err(invalid)?, None).await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

/// Read-only inspection: no pool/catalog initialization, byte reads or leases.
pub(crate) async fn stored_image_info(
    connection: &mut sqlx::SqliteConnection,
    id: ImageId,
) -> Result<StoredImageInfo, LibVmError> {
    Ok(
        fetch_image(connection, id, Some(&mut InspectionBudget::default()))
            .await?
            .into_info(),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use crate::image::import_types::{ImageContainerKind, ImageProvenance, RawConversionKey};
    use crate::paths::LocalPaths;
    use crate::storage::identity::ObjectDigest;
    use crate::storage::locks::StorageLock;
    use crate::storage::pool::StoragePool;
    use crate::store::image_store::LocalImage;
    use crate::store::models::image::{ImageRecord, ImageRecordKind};
    use crate::store::snapshot_store::{publish_map, SnapshotRef, SnapshotStore};
    use crate::store::stored_image_store::StoredImageStore;
    use crate::store::Store;

    pub(crate) async fn fixture() -> (
        tempfile::TempDir,
        StoredImageStore,
        ImageRecord,
        uuid::Uuid,
        StorageLock,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        pool.create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let disk = temp.path().join("input.raw");
        std::fs::write(&disk, [0x5a; 512]).unwrap();
        let (stream, roots) = pool.publish_stream_for_catalog(&disk).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[stream.id], &[])
            .await
            .unwrap();
        drop(roots);
        let map = publish_map(&pool, &store, operation, &stream.map)
            .await
            .unwrap();
        let kernel = temp.path().join("kernel");
        std::fs::write(&kernel, b"retained complete boot fixture").unwrap();
        let (kernel, roots) = pool.publish_object_for_catalog(&kernel).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[kernel.digest])
            .await
            .unwrap();
        drop(roots);
        let snapshot =
            crate::store::models::snapshot::tests::record(stream.id, map.map, kernel.digest);
        let mut record = ImageRecord {
            schema: 1,
            kind: ImageRecordKind::Image,
            root: snapshot.root,
            boot: snapshot.boot,
            process: crate::ProcessConfig::default(),
        };
        record.root.stream = map;
        (
            temp,
            StoredImageStore::from_store(Arc::new(store)),
            record,
            operation,
            lease,
        )
    }

    async fn operation(
        images: &StoredImageStore,
        record: &ImageRecord,
        kind: &str,
    ) -> (uuid::Uuid, StorageLock) {
        let (streams, objects) = record.content_dependencies().unwrap();
        let (id, lease) = images
            .store
            .begin_stopped_operation(
                kind,
                &streams.into_iter().collect::<Vec<_>>(),
                &objects.into_iter().collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        StoragePool::open(&images.store.images_dir)
            .unwrap()
            .create_operation_with_lease(id, lease.duplicate().unwrap())
            .unwrap();
        (id, lease)
    }

    fn provenance(container: ImageContainerKind, spelling: &str) -> ImageProvenance {
        ImageProvenance {
            container,
            source_digest: ObjectDigest::of_bytes(spelling.as_bytes()),
            source_spelling: spelling.into(),
            source_manifest: None,
            source_config: None,
            disk: Some(crate::image::import_types::DiskImportFacts {
                source_length: 512,
                decoded_length: 512,
                selected_root: None,
            }),
        }
    }

    fn conversion(record: &ImageRecord) -> (RawConversionKey, ImageProvenance) {
        let crate::BootProfile::LinuxDirect {
            userspace_platform, ..
        } = &record.boot
        else {
            panic!("direct fixture")
        };
        let manifest = ObjectDigest::of_bytes(b"selected manifest");
        (
            RawConversionKey {
                source_manifest: manifest,
                platform: userspace_platform.clone(),
                flattener_abi: "fixture-flattener-v1".into(),
            },
            ImageProvenance {
                container: ImageContainerKind::Oci,
                source_digest: manifest,
                source_spelling: "registry.example/root:latest".into(),
                source_manifest: Some(manifest),
                source_config: Some(ObjectDigest::of_bytes(b"selected config")),
                disk: None,
            },
        )
    }

    async fn named_image(images: &StoredImageStore, name: &str) -> Option<LocalImage> {
        let mut connection = images.store.pool.acquire().await.unwrap();
        crate::store::image_store::named_image(&mut connection, name)
            .await
            .unwrap()
    }

    /// The fixture record with another root length, hence another id.
    async fn other_record(
        images: &StoredImageStore,
        temporary: &std::path::Path,
        record: &ImageRecord,
        operation: uuid::Uuid,
    ) -> ImageRecord {
        let pool = StoragePool::open(&images.store.images_dir).unwrap();
        let path = temporary.join("other.raw");
        std::fs::write(&path, [0x5b; 1024]).unwrap();
        let (stream, roots) = pool.publish_stream_for_catalog(&path).unwrap();
        images
            .store
            .pin_published_storage_dependencies(operation, &[stream.id], &[])
            .await
            .unwrap();
        drop(roots);
        let mut other = record.clone();
        other.root.stream = publish_map(&pool, &images.store, operation, &stream.map)
            .await
            .unwrap();
        other.root.geometry.length = 1024;
        other
    }

    #[tokio::test]
    async fn publication_identity_provenance_names_and_conversion_are_independent() {
        let (_temp, images, record, id, lease) = fixture().await;
        let first = images
            .publish_owned(
                record.clone(),
                id,
                lease,
                Some("raw".into()),
                vec![provenance(ImageContainerKind::Raw, "/first.raw")],
                None,
            )
            .await
            .unwrap();
        let (id, lease) = operation(&images, &record, "import").await;
        let second = images
            .publish_owned(
                record.clone(),
                id,
                lease,
                Some("cloud".into()),
                vec![provenance(ImageContainerKind::Qcow2, "/same.qcow2")],
                None,
            )
            .await
            .unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(second.names, ["cloud", "raw"]);
        assert_eq!(second.provenance.len(), 2);
        assert_eq!(
            second.record_digest,
            ObjectDigest::of_bytes(&record.canonical_bytes().unwrap())
        );
        let (key, source) = conversion(&record);
        let (id, lease) = operation(&images, &record, "import").await;
        let converted = images
            .publish_owned(
                record.clone(),
                id,
                lease,
                None,
                vec![source],
                Some(key.clone()),
            )
            .await
            .unwrap();
        assert_eq!(converted.id, first.id);
        let hit = images.lookup_conversion(&key).await.unwrap().unwrap();
        assert_eq!(hit.info.record.boot, record.boot);
        assert_eq!(hit.info.id, first.id);
        drop(hit);
        let mut connection = images.store.pool.acquire().await.unwrap();
        assert_eq!(
            crate::store::image_store::image_by_id(
                &mut connection,
                first.record_digest.to_string().parse().unwrap()
            )
            .await
            .unwrap(),
            None,
            "a record digest is not an image id"
        );
        assert_eq!(
            crate::store::image_store::image_by_id(&mut connection, first.id)
                .await
                .unwrap(),
            Some(LocalImage::Stored(first.id))
        );
        drop(connection);
        assert_eq!(images.list().await.unwrap().len(), 1);
        let removal = images
            .store
            .remove_image(LocalImage::Stored(first.id), Some("raw"))
            .await
            .unwrap();
        assert!(!removal.record_removed);
        let info = images.inspect(first.id).await.unwrap();
        assert_eq!(info.names, ["cloud"]);
        assert_eq!(info.provenance.len(), 3);
        let removal = images
            .store
            .remove_image(LocalImage::Stored(info.id), None)
            .await
            .unwrap();
        assert_eq!(removal.names, ["cloud"]);
        assert!(removal.record_removed);
        assert!(matches!(
            images
                .store
                .remove_image(LocalImage::Stored(info.id), None)
                .await,
            Err(crate::LibVmError::ImageNotFound { .. })
        ));
        assert!(images.lookup_conversion(&key).await.unwrap().is_none());
        assert!(images.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn consumer_roots_survive_removal_and_both_collectors_until_last_ofd_closes() {
        let (_temp, images, record, id, lease) = fixture().await;
        let (key, source) = conversion(&record);
        let info = images
            .publish_owned(
                record.clone(),
                id,
                lease,
                Some("root".into()),
                vec![source],
                Some(key.clone()),
            )
            .await
            .unwrap();
        let consumer = images.consume(info.id).await.unwrap();
        let pool = StoragePool::open(&images.store.images_dir).unwrap();
        let mut file = consumer.open_stream(&pool).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, [0x5a; 512]);
        let copy = consumer.open_copy_source(&pool).unwrap();
        assert_eq!(copy.map().id(), record.root.stream.stream);
        let inherited = consumer._lease.duplicate().unwrap();
        let consumer_id = consumer.operation_id;
        drop(consumer);
        let removal = images
            .store
            .remove_image(LocalImage::Stored(info.id), Some("root"))
            .await
            .unwrap();
        assert!(removal.record_removed);
        assert!(matches!(
            images.inspect(info.id).await,
            Err(crate::LibVmError::ImageNotFound { .. })
        ));
        assert!(images.lookup_conversion(&key).await.unwrap().is_none());
        images.store.recover_image_cache().await.unwrap();
        assert!(pool.try_exclusive_lease(consumer_id).unwrap().is_none());
        assert!(pool.verify_stream(&record.root.stream.stream).is_ok());
        for object in record.content_dependencies().unwrap().1 {
            assert!(pool.verify_object(&object).is_ok());
        }
        assert!(pool.verify_object(&info.record_digest).is_ok());
        drop(inherited);
        drop(file);
        drop(copy);
        images.store.recover_image_cache().await.unwrap();
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
        assert!(!pool.object_path(&info.record_digest).exists());
        assert!(!pool
            .object_path(&record.boot_binding().unwrap().digest().unwrap())
            .exists());
    }

    #[tokio::test]
    async fn image_and_snapshot_names_coexist_and_each_resolves_only_to_its_kind() {
        let (_temp, images, record, id, lease) = fixture().await;
        let image = images
            .publish_owned(
                record.clone(),
                id,
                lease,
                Some("hello".into()),
                Vec::new(),
                None,
            )
            .await
            .unwrap();
        let snapshots = SnapshotStore::from_store(images.store.clone());
        let crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { kernel, .. },
            ..
        } = &record.boot
        else {
            panic!("direct fixture")
        };
        let mut snapshot = crate::store::models::snapshot::tests::record(
            record.root.stream.stream,
            record.root.stream.map,
            *kernel,
        );
        snapshot.root = record.root.clone();
        let (id, lease) = operation(&images, &record, "snapshot").await;
        let captured = snapshots
            .publish(&snapshot, id, Some("hello"))
            .await
            .unwrap();
        images.store.finish_stopped_operation(id).await.unwrap();
        drop(lease);
        assert_eq!(captured.names, ["hello"]);
        assert_eq!(images.inspect(image.id).await.unwrap().names, ["hello"]);
        assert_eq!(
            named_image(&images, "hello").await,
            Some(LocalImage::Stored(image.id))
        );
        assert_eq!(
            snapshots
                .inspect(&SnapshotRef::Name("hello".into()))
                .await
                .unwrap()
                .id,
            captured.id
        );
        // Ids never cross kinds either.
        let mut connection = images.store.pool.acquire().await.unwrap();
        assert_eq!(
            crate::store::image_store::image_by_id(
                &mut connection,
                captured.id.to_string().parse().unwrap()
            )
            .await
            .unwrap(),
            None
        );
        drop(connection);
        assert!(matches!(
            snapshots
                .inspect(&SnapshotRef::Id(image.id.to_string().parse().unwrap()))
                .await,
            Err(crate::LibVmError::SnapshotNotFound { .. })
        ));
        // Removing one kind's name leaves the other kind's name alone.
        let removal = snapshots
            .remove(&SnapshotRef::Name("hello".into()))
            .await
            .unwrap();
        assert_eq!(removal.id, captured.id);
        assert!(removal.record_removed);
        assert_eq!(
            named_image(&images, "hello").await,
            Some(LocalImage::Stored(image.id))
        );
        let removal = images
            .store
            .remove_image(LocalImage::Stored(image.id), Some("hello"))
            .await
            .unwrap();
        assert!(removal.record_removed);
        assert!(images.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn oci_and_stored_names_share_one_table_and_a_duplicate_is_refused() {
        let (_temp, images, record, id, lease) = fixture().await;
        let stored = images
            .publish_owned(record, id, lease, Some("hello".into()), Vec::new(), None)
            .await
            .unwrap();
        let held = crate::image::oci::tests::retained_lower(
            &images.store,
            &crate::image::oci::tests::LAYERS[..1],
        )
        .await;
        let oci = crate::store::image_store::tests::oci_image_record(held.retained());
        let oci_id = crate::store::image_store::tests::oci_id(&oci);
        crate::store::ImageStore::save_oci_image(images.store.as_ref(), &oci)
            .await
            .unwrap();
        let reference = crate::store::image_store::tests::REFERENCE;
        let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT name,oci_image_id,stored_image_id FROM image_name ORDER BY name",
        )
        .fetch_all(&images.store.pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            [
                (reference.to_owned(), Some(oci_id.to_string()), None),
                ("hello".to_owned(), None, Some(stored.id.to_string())),
            ]
        );
        let mut tx = images
            .store
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .unwrap();
        assert!(matches!(
            crate::store::image_store::insert_image_name(&mut tx, "hello", LocalImage::Oci(oci_id))
                .await,
            Err(crate::LibVmError::ImageNameConflict { name }) if name == "hello"
        ));
        assert!(matches!(
            crate::store::image_store::insert_image_name(
                &mut tx,
                reference,
                LocalImage::Stored(stored.id)
            )
            .await,
            Err(crate::LibVmError::ImageNameConflict { name }) if name == reference
        ));
        // Naming the same image again is a no-op.
        crate::store::image_store::insert_image_name(
            &mut tx,
            "hello",
            LocalImage::Stored(stored.id),
        )
        .await
        .unwrap();
        for (oci, stored) in [(None, None), (Some(oci_id), Some(stored.id))] {
            assert!(sqlx::query(
                "INSERT INTO image_name(name,oci_image_id,stored_image_id,updated_at) VALUES('both',?1,?2,0)"
            )
            .bind(oci.map(|id| id.to_string()))
            .bind(stored.map(|id| id.to_string()))
            .execute(&mut *tx)
            .await
            .is_err());
        }
        tx.commit().await.unwrap();
        assert!(matches!(
            images.add_name(stored.id, reference).await,
            Err(crate::LibVmError::InvalidName { .. })
        ));
        assert_eq!(
            images.add_name(stored.id, "world").await.unwrap().names,
            ["hello", "world"]
        );
        assert_eq!(
            named_image(&images, reference).await,
            Some(LocalImage::Oci(oci_id))
        );
        // A pulled stored artifact under the same reference moves the tag.
        let mut tx = images.store.pool.begin().await.unwrap();
        crate::store::image_store::move_image_name(
            &mut tx,
            reference,
            LocalImage::Stored(stored.id),
            3,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            named_image(&images, reference).await,
            Some(LocalImage::Stored(stored.id))
        );
        let mut connection = images.store.pool.acquire().await.unwrap();
        let cached = crate::store::image_store::list_oci_images(&mut connection)
            .await
            .unwrap();
        assert_eq!(cached.len(), 1);
        assert!(
            cached[0].names.is_empty(),
            "the cached image is left unnamed"
        );
    }

    #[tokio::test]
    async fn moved_tag_leaves_stored_image_listed_until_unused_and_pruned() {
        use crate::store::ImageStore;
        let (temp, images, record, id, lease) = fixture().await;
        let reference = "example.test/raw:1";
        let other = other_record(&images, temp.path(), &record, id).await;
        let old = images
            .publish_owned(record.clone(), id, lease, None, Vec::new(), None)
            .await
            .unwrap();
        let (id, lease) = operation(&images, &other, "import").await;
        let new = images
            .publish_owned(other, id, lease, None, Vec::new(), None)
            .await
            .unwrap();
        assert_ne!(old.id, new.id);
        for image in [old.id, new.id] {
            let mut tx = images.store.pool.begin().await.unwrap();
            crate::store::image_store::move_image_name(
                &mut tx,
                reference,
                LocalImage::Stored(image),
                1,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let listed = images.list().await.unwrap();
        let names = |id| {
            listed
                .iter()
                .find(|image| image.id == id)
                .map(|image| image.names.clone())
        };
        assert_eq!(names(old.id), Some(Vec::new()));
        assert_eq!(names(new.id), Some(vec![reference.to_owned()]));
        let paths = crate::paths::LocalPaths::new(images.store.home.clone());
        let machine = crate::store::storage::tests::machine_using_image(
            &images.store,
            &paths,
            crate::ImageSourceKind::Stored,
            old.id,
        )
        .await;
        assert_eq!(images.store.prune_images().await.unwrap().images_removed, 0);
        assert!(images.inspect(old.id).await.is_ok());
        crate::store::MachineStore::remove_machine(images.store.as_ref(), &machine)
            .await
            .unwrap();
        assert_eq!(images.store.prune_images().await.unwrap().images_removed, 1);
        assert!(matches!(
            images.inspect(old.id).await,
            Err(crate::LibVmError::ImageNotFound { .. })
        ));
        assert_eq!(images.inspect(new.id).await.unwrap().names, [reference]);
        let pool = StoragePool::open(&images.store.images_dir).unwrap();
        assert!(!pool.stream_path(&old.record.root.stream.stream).exists());
        assert!(pool.verify_stream(&new.record.root.stream.stream).is_ok());
    }

    #[tokio::test]
    async fn failed_publication_rolls_back_name_record_and_conversion_together() {
        let (_temp, images, record, id, lease) = fixture().await;
        let (key, source) = conversion(&record);
        sqlx::raw_sql("CREATE TRIGGER reject_image_name BEFORE INSERT ON image_name BEGIN SELECT RAISE(ABORT,'publication fixture rejection'); END;").execute(&images.store.pool).await.unwrap();
        let expected = record.id().unwrap();
        assert!(images
            .publish_owned(
                record.clone(),
                id,
                lease,
                Some("rejected".into()),
                vec![source],
                Some(key.clone())
            )
            .await
            .is_err());
        for (table, query) in [
            ("storage_image", "SELECT COUNT(*) FROM storage_image"),
            ("image_name", "SELECT COUNT(*) FROM image_name"),
            (
                "raw_conversion_result",
                "SELECT COUNT(*) FROM raw_conversion_result",
            ),
        ] {
            let count: i64 = sqlx::query_scalar(query)
                .fetch_one(&images.store.pool)
                .await
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
        let candidate: String = sqlx::query_scalar("SELECT json_extract(record_json,'$.candidateImageId') FROM storage_operation WHERE operation_id=?1").bind(id.to_string()).fetch_one(&images.store.pool).await.unwrap();
        assert_eq!(candidate, expected.to_string());
        images.store.recover_image_cache().await.unwrap();
        assert!(images.lookup_conversion(&key).await.unwrap().is_none());
        assert!(!StoragePool::open(&images.store.images_dir)
            .unwrap()
            .stream_path(&record.root.stream.stream)
            .exists());
    }

    #[tokio::test]
    async fn corruption_is_not_a_conversion_miss() {
        let (_temp, images, record, id, lease) = fixture().await;
        let (key, source) = conversion(&record);
        let info = images
            .publish_owned(
                record.clone(),
                id,
                lease,
                Some("checked".into()),
                vec![source],
                Some(key.clone()),
            )
            .await
            .unwrap();
        let extra = ObjectDigest::of_bytes(b"unrecorded edge");
        sqlx::query("INSERT INTO image_object_dependency(image_id,object_digest) VALUES(?1,?2)")
            .bind(info.id.to_string())
            .bind(extra.to_string())
            .execute(&images.store.pool)
            .await
            .unwrap();
        assert!(images.inspect(info.id).await.is_err());
        assert!(images.lookup_conversion(&key).await.is_err());
        sqlx::query("DELETE FROM image_object_dependency WHERE image_id=?1 AND object_digest=?2")
            .bind(info.id.to_string())
            .bind(extra.to_string())
            .execute(&images.store.pool)
            .await
            .unwrap();
        let pool = StoragePool::open(&images.store.images_dir).unwrap();
        let path = pool.object_path(&record.boot_binding().unwrap().digest().unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"corrupt bundle").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(images.lookup_conversion(&key).await.is_err());
    }

    #[tokio::test]
    async fn cancelled_publisher_keeps_original_operation_and_catalog_through_commit() {
        let (_temp, mut images, record, id, lease) = fixture().await;
        let (hook, mut entered, release) = crate::store::layer_store::tests::WorkerHook::new(
            crate::store::layer_store::tests::WorkerPoint::BeforeRoots,
            false,
        );
        Arc::get_mut(&mut images.store).unwrap().layer_hook = Some(hook);
        let publisher = images.clone();
        let expected = record.id().unwrap();
        let task = tokio::spawn(async move {
            publisher
                .publish_owned(record, id, lease, Some("detached".into()), Vec::new(), None)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let pool = StoragePool::open(&images.store.images_dir).unwrap();
        assert!(pool.try_exclusive_lease(id).unwrap().is_none());
        images.store.recover_image_cache().await.unwrap();
        assert!(pool.try_exclusive_lease(id).unwrap().is_none());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if images.inspect(expected).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        images.store.recover_image_cache().await.unwrap();
        assert_eq!(
            named_image(&images, "detached").await,
            Some(LocalImage::Stored(expected))
        );
    }

    #[tokio::test]
    async fn readonly_inspection_needs_no_pool_and_never_registers_a_consumer() {
        let (temp, images, record, id, lease) = fixture().await;
        let info = images
            .publish_owned(record, id, lease, Some("offline".into()), Vec::new(), None)
            .await
            .unwrap();
        let home = images.store.home.clone();
        images.store.pool.close().await;
        drop(images);
        std::fs::rename(home.join("images"), temp.path().join("retained-pool")).unwrap();
        let readonly = crate::store::ReadOnlyStore::open_if_exists(&home.join("state.db"))
            .await
            .unwrap()
            .unwrap();
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM storage_operation")
            .fetch_one(&readonly.pool)
            .await
            .unwrap();
        let mut connection = readonly.pool.acquire().await.unwrap();
        let image = crate::store::image_store::named_image(&mut connection, "offline")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(image, LocalImage::Stored(info.id));
        let observed = crate::store::image_store::image_info(&mut connection, image, "offline")
            .await
            .unwrap();
        assert_eq!(observed, crate::ImageInfo::Stored(Box::new(info.clone())));
        assert_eq!(
            crate::store::image_store::image_by_id(&mut connection, info.id)
                .await
                .unwrap(),
            Some(image)
        );
        drop(connection);
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM storage_operation")
            .fetch_one(&readonly.pool)
            .await
            .unwrap();
        assert_eq!(before, after);
        assert!(!home.join("images").exists());
        readonly.pool.close().await;
    }

    #[tokio::test]
    async fn cancelled_acquisition_keeps_registered_closure_until_real_reader_finishes() {
        let (_temp, mut images, record, id, lease) = fixture().await;
        let info = images
            .publish_owned(
                record.clone(),
                id,
                lease,
                Some("read".into()),
                Vec::new(),
                None,
            )
            .await
            .unwrap();
        let (hook, mut entered, release) = crate::store::layer_store::tests::WorkerHook::new(
            crate::store::layer_store::tests::WorkerPoint::AfterObject,
            false,
        );
        Arc::get_mut(&mut images.store).unwrap().layer_hook = Some(hook);
        let reader = images.clone();
        let task = tokio::spawn(async move {
            reader
                .consume(info.id)
                .await
                .map(|consumer| consumer.info.clone())
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        let operation: String = sqlx::query_scalar(
            "SELECT operation_id FROM storage_operation WHERE kind='import' AND state='staging'",
        )
        .fetch_one(&images.store.pool)
        .await
        .unwrap();
        let operation: uuid::Uuid = operation.parse().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let removal = images
            .store
            .remove_image(LocalImage::Stored(info.id), None)
            .await
            .unwrap();
        assert_eq!(removal.names, ["read"]);
        assert!(removal.record_removed);
        images.store.recover_image_cache().await.unwrap();
        let pool = StoragePool::open(&images.store.images_dir).unwrap();
        assert!(pool.try_exclusive_lease(operation).unwrap().is_none());
        assert!(pool.verify_stream(&record.root.stream.stream).is_ok());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if pool.try_exclusive_lease(operation).unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        images.store.recover_image_cache().await.unwrap();
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
    }

    #[tokio::test]
    async fn detached_publisher_retains_writable_catalog_after_last_public_handle_drops() {
        let (_temp, mut images, record, id, lease) = fixture().await;
        let home = images.store.home.clone();
        let expected = record.id().unwrap();
        let (hook, mut entered, release) = crate::store::layer_store::tests::WorkerHook::new(
            crate::store::layer_store::tests::WorkerPoint::BeforeRoots,
            false,
        );
        Arc::get_mut(&mut images.store).unwrap().layer_hook = Some(hook);
        let task = tokio::spawn(async move {
            images
                .publish_owned(
                    record,
                    id,
                    lease,
                    Some("owned-worker".into()),
                    Vec::new(),
                    None,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            crate::store::ReadOnlyStore::open_if_exists(&home.join("state.db"))
                .await
                .is_err()
        );
        assert!(StoragePool::open(&home.join("images"))
            .unwrap()
            .try_exclusive_lease(id)
            .unwrap()
            .is_none());
        release.send(()).unwrap();
        let readonly = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Ok(Some(store)) =
                    crate::store::ReadOnlyStore::open_if_exists(&home.join("state.db")).await
                {
                    break store;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let mut connection = readonly.pool.acquire().await.unwrap();
        assert_eq!(
            crate::store::image_store::named_image(&mut connection, "owned-worker")
                .await
                .unwrap(),
            Some(LocalImage::Stored(expected))
        );
        drop(connection);
        readonly.pool.close().await;
    }

    #[test]
    fn disk_and_oci_provenance_require_complete_noncontradictory_observations() {
        let mut raw = provenance(ImageContainerKind::Raw, "raw");
        assert!(crate::store::stored_image_store::provenance_bytes(&raw).is_ok());
        raw.disk.as_mut().unwrap().source_length += 1;
        assert!(crate::store::stored_image_store::provenance_bytes(&raw).is_err());
        raw.disk = None;
        assert!(crate::store::stored_image_store::provenance_bytes(&raw).is_err());
        raw = provenance(ImageContainerKind::Qcow2, "qcow2");
        raw.disk.as_mut().unwrap().selected_root =
            Some(crate::image::import_types::RootCandidate {
                selector: crate::RootSelector::MbrPartition { number: 4 },
                first_lba: 1,
                length_lbas: 1,
                gpt_type: None,
                mbr_type: Some(0x83),
                attributes: 0,
            });
        assert!(crate::store::stored_image_store::provenance_bytes(&raw).is_err());
        let mut oci = ImageProvenance {
            container: ImageContainerKind::Oci,
            source_digest: ObjectDigest::of_bytes(b"manifest"),
            source_spelling: "example/image:tag".into(),
            source_manifest: Some(ObjectDigest::of_bytes(b"manifest")),
            source_config: Some(ObjectDigest::of_bytes(b"config")),
            disk: None,
        };
        assert!(crate::store::stored_image_store::provenance_bytes(&oci).is_ok());
        oci.source_manifest = None;
        assert!(crate::store::stored_image_store::provenance_bytes(&oci).is_err());
    }

    #[tokio::test]
    async fn appendable_metadata_authenticates_every_page_on_consume_and_collect() {
        let (_temp, images, record, operation, lease) = fixture().await;
        let info = images
            .publish_owned(record.clone(), operation, lease, None, Vec::new(), None)
            .await
            .unwrap();
        let mut tx = images.store.pool.begin().await.unwrap();
        for index in 0..129 {
            let name = format!("page-{index:03}");
            sqlx::query("INSERT INTO image_name(name,stored_image_id,updated_at) VALUES(?1,?2,0)")
                .bind(&name)
                .bind(info.id.to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
            let (mut key, mut source) = conversion(&record);
            key.source_manifest = ObjectDigest::of_bytes(name.as_bytes());
            source.source_manifest = Some(key.source_manifest);
            source.source_digest = key.source_manifest;
            source.source_spelling = name;
            let bytes = crate::store::stored_image_store::provenance_bytes(&source).unwrap();
            sqlx::query(
                "INSERT INTO image_provenance(image_id,digest,record_bytes) VALUES(?1,?2,?3)",
            )
            .bind(info.id.to_string())
            .bind(ObjectDigest::of_bytes(&bytes).to_string())
            .bind(bytes)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO raw_conversion_result(key_digest,key_bytes,image_id) VALUES(?1,?2,?3)",
            )
            .bind(key.digest().unwrap().to_string())
            .bind(key.canonical_bytes().unwrap())
            .bind(info.id.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
        let reference = info.id;
        let inspected = images.inspect(reference).await.unwrap();
        assert_eq!(inspected.names.len(), 129);
        assert_eq!(inspected.provenance.len(), 129);
        let consumer = images.consume(reference).await.unwrap();
        assert_eq!(consumer.info.id, info.id);
        images.store.recover_image_cache().await.unwrap();
        images.store.recover_layer_objects().await.unwrap();
        drop(consumer);
        sqlx::query("INSERT INTO image_name(name,stored_image_id,updated_at) VALUES('zz invalid name',?1,0)")
            .bind(info.id.to_string())
            .execute(&images.store.pool)
            .await
            .unwrap();
        assert!(images.consume(reference).await.is_err());
        assert!(images.store.recover_image_cache().await.is_err());
        assert!(images.store.recover_layer_objects().await.is_err());
        sqlx::query("DELETE FROM image_name WHERE name='zz invalid name'")
            .execute(&images.store.pool)
            .await
            .unwrap();

        // A digest-valid final history entry still has to obey edge semantics.
        let mut bad = provenance(ImageContainerKind::Raw, "/invalid-geometry.raw");
        bad.disk.as_mut().unwrap().decoded_length = 1024;
        bad.disk.as_mut().unwrap().source_length = 1024;
        let bytes =
            crate::store::models::snapshot::canonical_value(&serde_json::to_value(bad).unwrap())
                .unwrap();
        sqlx::query("INSERT INTO image_provenance(image_id,digest,record_bytes) VALUES(?1,?2,?3)")
            .bind(info.id.to_string())
            .bind(ObjectDigest::of_bytes(&bytes).to_string())
            .bind(bytes)
            .execute(&images.store.pool)
            .await
            .unwrap();
        assert!(images.consume(reference).await.is_err());
        assert!(images.store.recover_image_cache().await.is_err());
        assert!(images.store.recover_layer_objects().await.is_err());
    }

    #[tokio::test]
    async fn inspection_admission_does_not_limit_consumer_or_collector_history() {
        let (_temp, images, record, operation, lease) = fixture().await;
        let info = images
            .publish_owned(record, operation, lease, None, Vec::new(), None)
            .await
            .unwrap();
        let mut tx = images.store.pool.begin().await.unwrap();
        // Root plus this many names exceeds the existing inspection entry budget.
        for index in 0..crate::storage::limits::Resource::MetadataPageEntries.maximum() {
            sqlx::query("INSERT INTO image_name(name,stored_image_id,updated_at) VALUES(?1,?2,0)")
                .bind(format!("bounded-{index:06}"))
                .bind(info.id.to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        let reference = info.id;
        assert!(images.inspect(reference).await.is_err());
        assert!(images.list().await.is_err());
        let consumer = images.consume(reference).await.unwrap();
        assert_eq!(consumer.info.id, info.id);
        images.store.recover_image_cache().await.unwrap();
        images.store.recover_layer_objects().await.unwrap();
        let removal = images
            .store
            .remove_image(LocalImage::Stored(reference), None)
            .await
            .unwrap();
        assert!(removal.record_removed);
        drop(consumer);
    }

    #[tokio::test]
    async fn inspection_byte_admission_does_not_limit_authenticated_history() {
        let (_temp, images, record, operation, lease) = fixture().await;
        let info = images
            .publish_owned(record, operation, lease, None, Vec::new(), None)
            .await
            .unwrap();
        for index in 0..2 {
            let spelling = format!(
                "{index}{}",
                "x".repeat(
                    crate::storage::limits::Resource::MetadataPageBytes.maximum() as usize / 2,
                )
            );
            let source = provenance(ImageContainerKind::Raw, &spelling);
            let bytes = crate::store::stored_image_store::provenance_bytes(&source).unwrap();
            sqlx::query(
                "INSERT INTO image_provenance(image_id,digest,record_bytes) VALUES(?1,?2,?3)",
            )
            .bind(info.id.to_string())
            .bind(ObjectDigest::of_bytes(&bytes).to_string())
            .bind(bytes)
            .execute(&images.store.pool)
            .await
            .unwrap();
        }
        let reference = info.id;
        assert!(images.inspect(reference).await.is_err());
        let consumer = images.consume(reference).await.unwrap();
        assert_eq!(consumer.info.id, info.id);
        images.store.recover_image_cache().await.unwrap();
        images.store.recover_layer_objects().await.unwrap();
    }

    #[tokio::test]
    async fn oversized_catalog_blobs_are_rejected_by_sql_before_decoding() {
        for table in ["image", "provenance", "conversion"] {
            let (_temp, images, record, operation, lease) = fixture().await;
            let info = images
                .publish_owned(record.clone(), operation, lease, None, Vec::new(), None)
                .await
                .unwrap();
            let oversized =
                crate::storage::limits::Resource::MetadataPageBytes.maximum() as i64 + 1;
            let mut target = info.id;
            match table {
                "image" => {
                    let mut oversized_record = serde_json::to_value(&record).unwrap();
                    oversized_record.as_object_mut().unwrap().insert(
                        "oversized".into(),
                        serde_json::Value::String("x".repeat(usize::try_from(oversized).unwrap())),
                    );
                    let bytes = serde_json::to_vec(&oversized_record).unwrap();
                    target = crate::store::models::image::image_id(&bytes);
                    sqlx::query("INSERT INTO storage_image(id,record_digest,record_bytes,created_at) VALUES(?1,?2,?3,0)")
                        .bind(target.to_string()).bind(ObjectDigest::of_bytes(&bytes).to_string())
                        .bind(bytes).execute(&images.store.pool).await.unwrap();
                }
                "provenance" => {
                    sqlx::query("INSERT INTO image_provenance(image_id,digest,record_bytes) VALUES(?1,?2,zeroblob(?3))")
                        .bind(info.id.to_string()).bind(ObjectDigest::of_bytes(b"provenance").to_string())
                        .bind(oversized).execute(&images.store.pool).await.unwrap();
                }
                "conversion" => {
                    let (key, _) = conversion(&record);
                    sqlx::query("INSERT INTO raw_conversion_result(image_id,key_digest,key_bytes) VALUES(?1,?2,zeroblob(?3))")
                        .bind(info.id.to_string()).bind(key.digest().unwrap().to_string())
                        .bind(oversized).execute(&images.store.pool).await.unwrap();
                    let error = images.lookup_conversion(&key).await.err().unwrap();
                    assert!(
                        error.to_string().contains("exceeds MetadataPageBytes"),
                        "{error}"
                    );
                }
                _ => unreachable!(),
            }
            let reference = target;
            let error = images.inspect(reference).await.unwrap_err();
            assert!(
                error.to_string().contains("exceeds MetadataPageBytes"),
                "{table}: {error}"
            );
            let error = images.consume(reference).await.err().unwrap();
            assert!(
                error.to_string().contains("exceeds MetadataPageBytes"),
                "{table}: {error}"
            );
            let error = images.store.recover_image_cache().await.unwrap_err();
            assert!(
                error.to_string().contains("exceeds MetadataPageBytes"),
                "{table}: {error}"
            );
            let error = images.store.recover_layer_objects().await.unwrap_err();
            assert!(
                error.to_string().contains("exceeds MetadataPageBytes"),
                "{table}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn shared_map_subtrees_survive_until_the_last_image_is_removed() {
        use std::io::Write;

        let (temporary, images, mut record, initial_operation, initial_lease) = fixture().await;
        let pool = StoragePool::open(&images.store.images_dir).unwrap();
        let mut initial = Some((initial_operation, initial_lease));
        let mut published = Vec::new();
        let mut node_sets = Vec::new();
        for length in [
            vm_spec::stream_map::ChunkSize::DISK.bytes(),
            2 * vm_spec::stream_map::ChunkSize::DISK.bytes(),
        ] {
            let (operation, lease) = match initial.take() {
                Some(initial) => initial,
                None => operation(&images, &record, "import").await,
            };
            let path = temporary.path().join(format!("root-{length}.raw"));
            let mut file = std::fs::File::create(&path).unwrap();
            file.set_len(length).unwrap();
            file.write_all(&[0x5a; 512]).unwrap();
            drop(file);
            let (stream, roots) = pool.publish_stream_for_catalog(&path).unwrap();
            images
                .store
                .pin_published_storage_dependencies(operation, &[stream.id], &[])
                .await
                .unwrap();
            drop(roots);
            let map = publish_map(&pool, &images.store, operation, &stream.map)
                .await
                .unwrap();
            let nodes = stream
                .map
                .nodes()
                .map(|node| node.unwrap().digest)
                .collect::<std::collections::BTreeSet<_>>();
            assert!(!nodes.is_empty());
            node_sets.push(nodes);
            record.root.stream = map;
            record.root.geometry.length = length;
            let info = images
                .publish_owned(record.clone(), operation, lease, None, Vec::new(), None)
                .await
                .unwrap();
            published.push(info);
        }
        assert_ne!(
            published[0].record.root.stream.map,
            published[1].record.root.stream.map
        );
        assert_eq!(
            node_sets[0], node_sets[1],
            "length-only roots share their entire tree"
        );
        for info in &published {
            let dependencies: Vec<String> = sqlx::query_scalar(
                "SELECT object_digest FROM image_object_dependency WHERE image_id=?1",
            )
            .bind(info.id.to_string())
            .fetch_all(&images.store.pool)
            .await
            .unwrap();
            assert!(dependencies.contains(&info.record.root.stream.map.to_string()));
            assert!(node_sets[0]
                .iter()
                .all(|node| !dependencies.contains(&node.to_string())));
        }
        images
            .store
            .remove_image(LocalImage::Stored(published[0].id), None)
            .await
            .unwrap();
        images.store.recover_image_cache().await.unwrap();
        assert!(!pool
            .object_path(&published[0].record.root.stream.map)
            .exists());
        for node in &node_sets[0] {
            pool.verify_object(node).unwrap();
        }
        let remaining = images.consume(published[1].id).await.unwrap();
        assert_eq!(
            remaining.info.record.root.stream,
            published[1].record.root.stream
        );
        drop(remaining);
        images
            .store
            .remove_image(LocalImage::Stored(published[1].id), None)
            .await
            .unwrap();
        images.store.recover_image_cache().await.unwrap();
        for node in &node_sets[0] {
            assert!(!pool.object_path(node).exists());
        }
        assert!(!pool
            .object_path(&published[1].record.root.stream.map)
            .exists());
    }
}
