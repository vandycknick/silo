use std::{collections::BTreeSet, path::Path};

use oci::changeset::{
    ChangesetLimits, ContentDigest, LayerChangeset, LayerRecipe, LayerRecipeId, LayerResult,
    LayerResultId, StagedChangeset,
};
use sqlx::Row;

#[cfg(test)]
use crate::store::layer_store::tests::WorkerPoint;
use crate::{
    storage::{
        identity::{ObjectDigest, StreamId},
        identity_file::SourceFingerprint,
        pool::StoragePool,
    },
    store::Store,
    LibVmError,
};

/// Explicit phase-2 ingest/publication/composition surface. Default roots remain flat.
#[derive(Clone)]
pub struct LayerStore {
    store: Store,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedLayer {
    pub id: LayerResultId,
    pub recipe: LayerRecipeId,
    pub pack_stream: StreamId,
    pub pack_length: u64,
    pub index_root: ContentDigest,
}
fn semantic(error: impl std::fmt::Display) -> LibVmError {
    LibVmError::StateDecode {
        field: "layer artifact",
        message: error.to_string(),
    }
}
fn object(digest: ContentDigest) -> Result<ObjectDigest, LibVmError> {
    digest.to_string().parse().map_err(semantic)
}
fn int(value: u64) -> Result<i64, LibVmError> {
    i64::try_from(value).map_err(semantic)
}

struct WorkerContext {
    _catalog: std::sync::Arc<crate::store::catalog_guard::CatalogGuard>,
    #[cfg(test)]
    hook: Option<std::sync::Arc<crate::store::layer_store::tests::WorkerHook>>,
}
impl Store {
    fn layer_worker_context(&self) -> WorkerContext {
        WorkerContext {
            _catalog: self.catalog.clone(),
            #[cfg(test)]
            hook: self.layer_hook.clone(),
        }
    }
}
#[cfg(test)]
impl WorkerContext {
    fn hit(&self, point: WorkerPoint) -> Result<(), LibVmError> {
        if let Some(hook) = &self.hook {
            hook.hit(point)
        } else {
            Ok(())
        }
    }
}
struct PublicationStaging(crate::storage::pool::OperationPaths);
impl PublicationStaging {
    fn temporary(&self) -> &Path {
        &self.0.temporary
    }
}
impl Drop for PublicationStaging {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0.temporary) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path=?self.0.temporary,%error,"layer staging cleanup deferred to recovery");
            }
        }
        if let Err(error) = std::fs::remove_dir(&self.0.durable) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path=?self.0.durable,%error,"empty layer operation directory cleanup failed");
            }
        }
    }
}
struct PublicationFacts {
    retained: RetainedLayer,
    diff_id: ContentDigest,
    recipe_bytes: Vec<u8>,
    result_bytes: Vec<u8>,
    recipe_digest: ObjectDigest,
    result_digest: ObjectDigest,
    dependencies: BTreeSet<ObjectDigest>,
}
struct PreparedLayer {
    facts: PublicationFacts,
    _roots: crate::storage::locks::StorageLock,
    _operation: PublicationStaging,
    _recipe_lock: crate::storage::locks::StorageLock,
    _staged: StagedChangeset,
}
impl LayerStore {
    pub async fn open(home: &Path) -> Result<Self, LibVmError> {
        Ok(Self {
            store: Store::open(&home.join("state.db")).await?,
        })
    }
    /// Successful ingestion is required; all validation completes before pool publication.
    pub async fn publish(
        &self,
        staged: StagedChangeset,
        limits: &ChangesetLimits,
    ) -> Result<RetainedLayer, LibVmError> {
        let store = self.store.clone();
        let runtime = tokio::runtime::Handle::current();
        let limits = *limits;
        let context = self.store.layer_worker_context();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let worker = tokio::task::spawn_blocking(move || {
            let operation_id = uuid::Uuid::new_v4();
            let lease = runtime.block_on(store.begin_storage_operation_inner(operation_id))?;
            let pool = StoragePool::open(&store.images_dir)?;
            let operation =
                PublicationStaging(pool.create_operation_with_lease(operation_id, lease)?);
            let PreparedLayer {
                facts,
                _roots,
                _operation,
                _recipe_lock,
                _staged,
            } = prepare(&store, staged, &limits, &context, &runtime, operation)?;
            // Only plain facts cross into the async caller. Filesystem-bearing
            // values and both capabilities remain on this worker through cleanup.
            let lifetime = (_roots, _operation, _recipe_lock, _staged);
            if ready_tx.send(facts).is_ok() {
                let _ = release_rx.blocking_recv();
            }
            #[cfg(test)]
            context.hit(WorkerPoint::Cleanup)?;
            drop(lifetime);
            Ok::<_, LibVmError>(())
        });
        let facts = match ready_rx.await {
            Ok(facts) => facts,
            Err(error) => {
                worker.await??;
                return Err(std::io::Error::other(error).into());
            }
        };
        let result = self.commit_layer(&facts).await;
        drop(release_tx);
        worker.await??;
        result
    }
    async fn commit_layer(&self, p: &PublicationFacts) -> Result<RetainedLayer, LibVmError> {
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("INSERT INTO layer_recipe(id,diff_id,record_digest,record_bytes) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO NOTHING")
            .bind(p.retained.recipe.to_string()).bind(p.diff_id.to_string()).bind(p.recipe_digest.to_string()).bind(&p.recipe_bytes).execute(&mut *tx).await?;
        let stored =
            sqlx::query("SELECT diff_id,record_digest,record_bytes FROM layer_recipe WHERE id=?1")
                .bind(p.retained.recipe.to_string())
                .fetch_one(&mut *tx)
                .await?;
        if stored.try_get::<Vec<u8>, _>("record_bytes")? != p.recipe_bytes
            || stored.try_get::<String, _>("diff_id")? != p.diff_id.to_string()
            || stored.try_get::<String, _>("record_digest")? != p.recipe_digest.to_string()
        {
            return Err(semantic("immutable recipe contradiction"));
        }
        let inserted=sqlx::query("INSERT INTO layer_result(id,recipe_id,pack_stream,pack_length,index_root,record_digest,record_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO NOTHING")
            .bind(p.retained.id.to_string()).bind(p.retained.recipe.to_string()).bind(p.retained.pack_stream.to_string()).bind(int(p.retained.pack_length)?).bind(p.retained.index_root.to_string()).bind(p.result_digest.to_string()).bind(&p.result_bytes).execute(&mut *tx).await?.rows_affected()!=0;
        let stored=sqlx::query("SELECT recipe_id,pack_stream,pack_length,index_root,record_digest,record_bytes FROM layer_result WHERE id=?1").bind(p.retained.id.to_string()).fetch_one(&mut *tx).await?;
        if stored.try_get::<Vec<u8>, _>("record_bytes")? != p.result_bytes
            || stored.try_get::<String, _>("recipe_id")? != p.retained.recipe.to_string()
            || stored.try_get::<String, _>("pack_stream")? != p.retained.pack_stream.to_string()
            || stored.try_get::<i64, _>("pack_length")? != int(p.retained.pack_length)?
            || stored.try_get::<String, _>("index_root")? != p.retained.index_root.to_string()
            || stored.try_get::<String, _>("record_digest")? != p.result_digest.to_string()
        {
            return Err(semantic("immutable result contradiction"));
        }
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT object_digest FROM layer_object_dependency WHERE result_id=?1",
        )
        .bind(p.retained.id.to_string())
        .fetch_all(&mut *tx)
        .await?;
        if !inserted
            && existing
                .iter()
                .map(|d| d.parse::<ObjectDigest>().map_err(semantic))
                .collect::<Result<BTreeSet<_>, _>>()?
                != p.dependencies
        {
            return Err(semantic("immutable dependency contradiction"));
        }
        for dependency in &p.dependencies {
            sqlx::query("INSERT INTO layer_object_dependency(result_id,object_digest) VALUES(?1,?2) ON CONFLICT DO NOTHING").bind(p.retained.id.to_string()).bind(dependency.to_string()).execute(&mut *tx).await?;
        }
        sqlx::query("DELETE FROM image_stream_gc WHERE stream_id=?1")
            .bind(p.retained.pack_stream.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(p.retained.clone())
    }
    /// Reuse a previously verified decoded recipe without fetching its source
    /// transport again. Retained pack/index bytes are authenticated before return.
    pub async fn find_recipe(
        &self,
        recipe: LayerRecipeId,
        limits: &ChangesetLimits,
    ) -> Result<Option<RetainedLayer>, LibVmError> {
        let Some(row) = sqlx::query(
            "SELECT id,pack_stream,pack_length,index_root FROM layer_result WHERE recipe_id=?1",
        )
        .bind(recipe.to_string())
        .fetch_optional(&self.store.pool)
        .await?
        else {
            return Ok(None);
        };
        let id: LayerResultId = row.try_get::<String, _>("id")?.parse()?;
        let layer = self.load(id, limits).await?;
        if (LayerRecipe {
            diff_id: layer.diff_id,
        })
        .id()?
            != recipe
        {
            return Err(semantic("recipe lookup identity contradiction"));
        }
        Ok(Some(RetainedLayer {
            id,
            recipe,
            pack_stream: row
                .try_get::<String, _>("pack_stream")?
                .parse()
                .map_err(semantic)?,
            pack_length: u64::try_from(row.try_get::<i64, _>("pack_length")?).map_err(semantic)?,
            index_root: row
                .try_get::<String, _>("index_root")?
                .parse()
                .map_err(semantic)?,
        }))
    }
    /// The owner is a verified manifest/config byte digest. Repeated results remain separate occurrences.
    pub async fn retain_occurrences(
        &self,
        owner: ContentDigest,
        results: &[LayerResultId],
    ) -> Result<(), LibVmError> {
        crate::storage::limits::Resource::LayerOccurrences
            .check(results.len() as u64)
            .map_err(|e| LibVmError::Storage(e.into()))?;
        let images = self.store.images_dir.clone();
        let context = self.store.layer_worker_context();
        let _roots = tokio::task::spawn_blocking(move || {
            let _context = context;
            StoragePool::open(&images)?.lock_roots_shared()
        })
        .await??;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let inserted=sqlx::query("INSERT INTO layer_occurrence_set(owner_digest,layer_count) VALUES(?1,?2) ON CONFLICT DO NOTHING").bind(owner.to_string()).bind(results.len() as i64).execute(&mut *tx).await?.rows_affected()!=0;
        let count: i64 = sqlx::query_scalar(
            "SELECT layer_count FROM layer_occurrence_set WHERE owner_digest=?1",
        )
        .bind(owner.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if count != results.len() as i64 {
            return Err(semantic("immutable occurrence count contradiction"));
        }
        if inserted {
            for (position, result) in results.iter().enumerate() {
                sqlx::query("INSERT INTO layer_occurrence(owner_digest,position,result_id) VALUES(?1,?2,?3)").bind(owner.to_string()).bind(position as i64).bind(result.to_string()).execute(&mut *tx).await?;
            }
        } else {
            let stored=sqlx::query("SELECT position,result_id FROM layer_occurrence WHERE owner_digest=?1 ORDER BY position").bind(owner.to_string()).fetch_all(&mut *tx).await?;
            if stored.len() != results.len() {
                return Err(semantic("immutable occurrence set contradiction"));
            }
            for (position, (row, result)) in stored.iter().zip(results).enumerate() {
                if row.try_get::<i64, _>("position")? != position as i64
                    || row.try_get::<String, _>("result_id")? != result.to_string()
                {
                    return Err(semantic("immutable ordered occurrence contradiction"));
                }
            }
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn occurrences(
        &self,
        owner: ContentDigest,
    ) -> Result<Vec<LayerResultId>, LibVmError> {
        let ids = sqlx::query_scalar::<_, String>(
            "SELECT result_id FROM layer_occurrence WHERE owner_digest=?1 ORDER BY position",
        )
        .bind(owner.to_string())
        .fetch_all(&self.store.pool)
        .await?;
        ids.into_iter()
            .map(|id| id.parse().map_err(LibVmError::Changeset))
            .collect()
    }
    /// Verify retained records, stream and all index pages without consulting source blobs.
    pub async fn load(
        &self,
        id: LayerResultId,
        limits: &ChangesetLimits,
    ) -> Result<LayerChangeset, LibVmError> {
        limits.validate()?;
        let row=sqlx::query("SELECT r.recipe_id,r.pack_stream,r.pack_length,r.index_root,r.record_digest,r.record_bytes,p.diff_id,p.record_digest AS recipe_digest,p.record_bytes AS recipe_bytes FROM layer_result r JOIN layer_recipe p ON p.id=r.recipe_id WHERE r.id=?1")
            .bind(id.to_string()).fetch_one(&self.store.pool).await?;
        let recipe: LayerRecipeId = row.try_get::<String, _>("recipe_id")?.parse()?;
        let diff_id: ContentDigest = row.try_get::<String, _>("diff_id")?.parse()?;
        let pack_stream: StreamId = row
            .try_get::<String, _>("pack_stream")?
            .parse()
            .map_err(semantic)?;
        let pack_length = u64::try_from(row.try_get::<i64, _>("pack_length")?).map_err(semantic)?;
        let index_root: ContentDigest = row.try_get::<String, _>("index_root")?.parse()?;
        if pack_length > limits.max_pack_bytes {
            return Err(oci::changeset::ChangesetError::Limit {
                resource: "pack bytes",
                actual: pack_length,
                maximum: limits.max_pack_bytes,
            }
            .into());
        }
        let recipe_record = LayerRecipe { diff_id };
        let recipe_bytes = recipe_record.canonical_bytes()?;
        let result_record = LayerResult {
            recipe,
            pack_stream: pack_stream.to_string().parse()?,
            pack_length,
            index_root,
        };
        let result_bytes = result_record.canonical_bytes()?;
        if recipe_record.id()? != recipe
            || result_record.id()? != id
            || recipe_bytes != row.try_get::<Vec<u8>, _>("recipe_bytes")?
            || result_bytes != row.try_get::<Vec<u8>, _>("record_bytes")?
            || ObjectDigest::of_bytes(&recipe_bytes).to_string()
                != row.try_get::<String, _>("recipe_digest")?
            || ObjectDigest::of_bytes(&result_bytes).to_string()
                != row.try_get::<String, _>("record_digest")?
        {
            return Err(semantic("retained identity record contradiction"));
        }
        let dependencies = sqlx::query_scalar::<_, String>(
            "SELECT object_digest FROM layer_object_dependency WHERE result_id=?1",
        )
        .bind(id.to_string())
        .fetch_all(&self.store.pool)
        .await?
        .into_iter()
        .map(|d| d.parse::<ObjectDigest>().map_err(semantic))
        .collect::<Result<BTreeSet<_>, _>>()?;
        let images = self.store.images_dir.clone();
        let limits = *limits;
        tokio::task::spawn_blocking(move || {
            let pool = StoragePool::open_existing(&images)?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "retained layer pool is absent",
                )
            })?;
            let map = pool.verify_stream(&pack_stream)?;
            if map.length() != pack_length {
                return Err(semantic("pack length contradiction"));
            }
            let mut observed = BTreeSet::new();
            for bytes in [&recipe_bytes, &result_bytes] {
                let digest = ObjectDigest::of_bytes(bytes);
                if pool.read_object(&digest, 65536)? != *bytes {
                    return Err(semantic("record object contradiction"));
                }
                observed.insert(digest);
            }
            let root_digest = object(index_root)?;
            observed.insert(root_digest);
            let root = pool.read_object(&root_digest, oci::changeset::limits::MAX_ROOT_BYTES)?;
            let mut page_error = None;
            let decoded = oci::changeset::decode_index(
                &root,
                |digest| {
                    let digest = object(digest).map_err(|error| {
                        oci::changeset::ChangesetError::Invalid(error.to_string())
                    })?;
                    observed.insert(digest);
                    match pool.read_object(&digest, limits.max_page_bytes) {
                        Ok(bytes) => Ok(bytes),
                        Err(error) => {
                            page_error = Some(error);
                            Err(oci::changeset::ChangesetError::Invalid(
                                "retained page storage failure".into(),
                            ))
                        }
                    }
                },
                diff_id,
                &limits,
            );
            if let Some(error) = page_error {
                return Err(LibVmError::Storage(error));
            }
            let layer = decoded?;
            if layer.pack_length != pack_length || observed != dependencies {
                return Err(semantic("index or dependency closure contradiction"));
            }
            Ok(layer)
        })
        .await?
    }
    pub async fn compose(
        &self,
        results: &[LayerResultId],
        limits: &ChangesetLimits,
    ) -> Result<oci::changeset::namespace::ValidatedNamespace, LibVmError> {
        limits.validate()?;
        if results.len() as u64 > limits.max_layers {
            return Err(oci::changeset::ChangesetError::Limit {
                resource: "composition layers",
                actual: results.len() as u64,
                maximum: limits.max_layers,
            }
            .into());
        }
        let mut layers = Vec::new();
        for id in results {
            layers.push(self.load(*id, limits).await?);
        }
        let limits = *limits;
        let context = self.store.layer_worker_context();
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            context.hit(WorkerPoint::Compose)?;
            let _context = context;
            oci::changeset::namespace::compose(&layers.iter().collect::<Vec<_>>(), &limits)
                .map_err(LibVmError::Namespace)
        })
        .await?
    }
    pub async fn recover(&self) -> Result<(), LibVmError> {
        self.store.recover_image_cache().await?;
        Ok(())
    }
}
fn prepare(
    store: &Store,
    staged: StagedChangeset,
    limits: &ChangesetLimits,
    context: &WorkerContext,
    runtime: &tokio::runtime::Handle,
    operation: PublicationStaging,
) -> Result<PreparedLayer, LibVmError> {
    // Encode all pages into leased staging before the first immutable write.
    #[cfg(test)]
    context.hit(WorkerPoint::Preparing)?;
    #[cfg(not(test))]
    let _ = context;
    let pool = StoragePool::open(&store.images_dir)?;
    let recipe = LayerRecipe {
        diff_id: staged.changeset().diff_id,
    };
    let recipe_id = recipe.id()?;
    let recipe_lock = pool.lock_publication(&recipe_id.to_string().parse().map_err(semantic)?)?;
    let mut staged_objects = BTreeSet::new();
    let index_root = {
        let mut stage_object =
            |value: oci::changeset::IndexObject| -> oci::changeset::ChangesetResult<()> {
                let name = value.digest.to_string();
                let name = name.strip_prefix("sha256:").ok_or_else(|| {
                    oci::changeset::ChangesetError::Invalid("invalid object digest".into())
                })?;
                if staged_objects.insert(value.digest) {
                    std::fs::write(operation.temporary().join(name), &value.bytes)?;
                }
                Ok(())
            };
        let root =
            oci::changeset::index::encode_index_to(staged.changeset(), limits, &mut stage_object)?;
        let digest = root.digest;
        stage_object(root)?;
        digest
    };
    // Stream identity comes exclusively from the existing stream-map implementation.
    let (stream, guard) = pool.publish_stream_for_catalog(staged.pack_path())?;
    runtime.block_on(store.pin_published_storage_dependencies(
        operation.0.id,
        &[stream.id],
        &[],
    ))?;
    let mut fingerprints = vec![(
        stream.path.clone(),
        SourceFingerprint::new(&std::fs::symlink_metadata(&stream.path)?),
    )];
    drop(guard);
    if stream.length != staged.changeset().pack_length {
        return Err(semantic("staged pack length contradiction"));
    }
    let recipe_bytes = recipe.canonical_bytes()?;
    let result = LayerResult {
        recipe: recipe_id,
        pack_stream: stream.id.to_string().parse()?,
        pack_length: stream.length,
        index_root,
    };
    let result_bytes = result.canonical_bytes()?;
    let recipe_digest = ObjectDigest::of_bytes(&recipe_bytes);
    let result_digest = ObjectDigest::of_bytes(&result_bytes);
    for bytes in [&recipe_bytes, &result_bytes] {
        let digest = ObjectDigest::of_bytes(bytes);
        std::fs::write(operation.temporary().join(digest.hex()), bytes)?;
        staged_objects.insert(digest.to_string().parse::<ContentDigest>()?);
    }
    let mut dependencies = BTreeSet::new();
    for digest in staged_objects {
        let expected = object(digest)?;
        let (published, guard) =
            pool.publish_object_for_catalog(&operation.temporary().join(expected.hex()))?;
        if published.digest != expected {
            return Err(semantic("staged index changed before publication"));
        }
        fingerprints.push((
            published.path.clone(),
            SourceFingerprint::new(&std::fs::symlink_metadata(&published.path)?),
        ));
        dependencies.insert(expected);
        runtime.block_on(store.pin_published_storage_dependencies(
            operation.0.id,
            &[],
            &[published.digest],
        ))?;
        drop(guard);
        #[cfg(test)]
        context.hit(WorkerPoint::AfterObject)?;
    }
    // Only cheap fingerprint checks and the catalog transaction run under roots.
    // Concurrent recovery may remove an uncommitted object, in which case fail closed.
    #[cfg(test)]
    context.hit(WorkerPoint::BeforeRoots)?;
    let roots = pool.lock_roots_shared()?;
    for (path, before) in fingerprints {
        if SourceFingerprint::new(&std::fs::symlink_metadata(path)?) != before {
            return Err(semantic("published closure changed before catalog commit"));
        }
    }
    Ok(PreparedLayer {
        facts: PublicationFacts {
            retained: RetainedLayer {
                id: result.id()?,
                recipe: recipe_id,
                pack_stream: stream.id,
                pack_length: stream.length,
                index_root,
            },
            diff_id: staged.changeset().diff_id,
            recipe_bytes,
            result_bytes,
            recipe_digest,
            result_digest,
            dependencies,
        },
        _roots: roots,
        _operation: operation,
        _recipe_lock: recipe_lock,
        _staged: staged,
    })
}
impl Store {
    pub(crate) async fn recover_layer_objects(&self) -> Result<(), LibVmError> {
        let store = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _context=store.layer_worker_context();
            // Store owns the explicit catalog capability even if its SQL pool
            // is explicitly closed while this detached worker is still running.
            // Writable recovery initializes empty coordination directories for
            // catalog/immutable-pool snapshots that deliberately omit them.
            // Read-side load/find_recipe retain their noncreating opener.
            let pool=StoragePool::open(&store.images_dir)?;
            runtime.block_on(store.retire_abandoned_storage_operations(&pool))?;
            let mut scan=pool.scan_objects()?;
            loop {
                let batch=scan.by_ref().take(256).collect::<Result<Vec<_>,_>>()?;
                if batch.is_empty() {break;}
                runtime.block_on(store.check_operation_recovery(&pool))?;
                runtime.block_on(crate::store::snapshot_store::check_snapshot_catalog(&store))?;
                let _roots=pool.lock_roots()?;
                runtime.block_on(async {
                    let mut tx=store.pool.begin_with("BEGIN IMMEDIATE").await?;
                    let machine_objects=crate::store::cache_paths::retained_machine_objects(&mut tx).await?;
                    let mut orphaned=Vec::new();
                    for digest in batch {
                        let retained:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM layer_object_dependency WHERE object_digest=?1 UNION ALL SELECT 1 FROM storage_operation_object WHERE object_digest=?1 UNION ALL SELECT 1 FROM snapshot_object_dependency WHERE object_digest=?1 UNION ALL SELECT 1 FROM snapshot_capture_provenance WHERE evidence_digest=?1)").bind(digest.to_string()).fetch_one(&mut *tx).await?;
                        if !retained && !machine_objects.contains(&digest) {orphaned.push(digest);}
                    }
                    let candidates=orphaned.iter().map(|digest|pool.object_path(digest)).collect::<Vec<_>>();
                    crate::store::ensure_cache_paths_unreferenced(&mut tx,&candidates,&store.home).await?;
                    #[cfg(test)]
                    _context.hit(WorkerPoint::RecoveryDelete)?;
                    for digest in orphaned {pool.remove_object(&digest)?;}
                    tx.commit().await?;
                    Ok::<_,LibVmError>(())
                })?;
            }
            Ok::<_,LibVmError>(())
        }).await?
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::storage::{pool::StoragePool, stream::StreamHasher, LayerStore};
    use oci::changeset::{
        ingest_layer, ChangesetLimits, ContentDigest, LayerInput, StagedChangeset,
    };
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum WorkerPoint {
        Preparing,
        AfterObject,
        BeforeRoots,
        Cleanup,
        RecoveryDelete,
        CandidateAuthorized,
        CandidateDetached,
        CandidateDirectoryVerified,
        CandidateRemoved,
        Compose,
    }
    #[derive(Debug)]
    pub(crate) struct WorkerHook {
        point: WorkerPoint,
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        panic: bool,
        fired: std::sync::atomic::AtomicBool,
    }
    impl WorkerHook {
        pub(crate) fn new(
            point: WorkerPoint,
            panic: bool,
        ) -> (
            std::sync::Arc<Self>,
            tokio::sync::mpsc::UnboundedReceiver<()>,
            std::sync::mpsc::Sender<()>,
        ) {
            let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
            let (release, suspended) = std::sync::mpsc::channel();
            (
                std::sync::Arc::new(Self {
                    point,
                    entered,
                    release: std::sync::Mutex::new(suspended),
                    panic,
                    fired: std::sync::atomic::AtomicBool::new(false),
                }),
                receiver,
                release,
            )
        }
        pub(crate) fn hit(&self, point: WorkerPoint) -> Result<(), crate::LibVmError> {
            if self.point == point && !self.fired.swap(true, std::sync::atomic::Ordering::AcqRel) {
                self.entered.send(()).map_err(std::io::Error::other)?;
                if self.panic {
                    panic!("injected blocking worker panic");
                }
                self.release
                    .lock()
                    .map_err(|error| std::io::Error::other(error.to_string()))?
                    .recv()
                    .map_err(std::io::Error::other)?;
            }
            Ok(())
        }
    }

    fn tar() -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..1].copy_from_slice(b"a");
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(b"00000000001\0");
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u64 = header.iter().map(|b| u64::from(*b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut bytes = header.to_vec();
        bytes.push(b'A');
        bytes.resize(2048, 0);
        bytes
    }
    fn staged(home: &Path, store: &LayerStore) -> StagedChangeset {
        staged_byte(home, store, b'A')
    }
    fn staged_byte(home: &Path, store: &LayerStore, byte: u8) -> StagedChangeset {
        let mut bytes = tar();
        bytes[512] = byte;
        let source = home.join("source.tar");
        fs::write(&source, &bytes).unwrap();
        let digest = ContentDigest::of_bytes(&bytes);
        let operation = oci::StagingOperation::try_from(uuid::Uuid::new_v4().to_string()).unwrap();
        StoragePool::open(&store.store.images_dir).unwrap();
        ingest_layer(
            &source,
            &LayerInput {
                blob_digest: digest,
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                size_bytes: bytes.len() as u64,
                diff_id: digest,
            },
            &store.store.images_dir,
            &operation,
            &ChangesetLimits::default(),
        )
        .unwrap()
    }
    async fn count(store: &LayerStore, table: &str) -> i64 {
        let sql = match table {
            "layer_recipe" => "SELECT COUNT(*) FROM layer_recipe",
            "layer_result" => "SELECT COUNT(*) FROM layer_result",
            "layer_object_dependency" => "SELECT COUNT(*) FROM layer_object_dependency",
            _ => panic!("unknown count fixture table"),
        };
        sqlx::query_scalar(sql)
            .fetch_one(&store.store.pool)
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn validation_failure_publishes_no_immutable_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let store = LayerStore::open(temp.path()).await.unwrap();
        let staged = staged(temp.path(), &store);
        assert!(matches!(
            store
                .publish(
                    staged,
                    &ChangesetLimits {
                        max_page_bytes: 16,
                        ..ChangesetLimits::default()
                    }
                )
                .await,
            Err(crate::LibVmError::Changeset(
                oci::changeset::ChangesetError::Limit { .. }
            ))
        ));
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        assert_eq!(pool.scan_streams().unwrap().count(), 0);
        assert_eq!(pool.scan_objects().unwrap().count(), 0);
        assert_eq!(count(&store, "layer_result").await, 0);
    }
    #[tokio::test]
    async fn catalog_abort_leaves_no_reachable_partial_layer_and_recovery_reaps_complete_objects() {
        let temp = tempfile::tempdir().unwrap();
        let store = LayerStore::open(temp.path()).await.unwrap();
        sqlx::raw_sql("CREATE TRIGGER reject_layer BEFORE INSERT ON layer_result BEGIN SELECT RAISE(ABORT,'injected catalog failure'); END;").execute(&store.store.pool).await.unwrap();
        assert!(matches!(
            store
                .publish(staged(temp.path(), &store), &ChangesetLimits::default())
                .await,
            Err(crate::LibVmError::Database(_))
        ));
        assert_eq!(count(&store, "layer_recipe").await, 0);
        assert_eq!(count(&store, "layer_result").await, 0);
        assert_eq!(count(&store, "layer_object_dependency").await, 0);
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        assert!(pool.scan_objects().unwrap().count() > 0);
        assert_eq!(pool.scan_streams().unwrap().count(), 1);
        store.recover().await.unwrap();
        assert_eq!(pool.scan_objects().unwrap().count(), 0);
        assert_eq!(pool.scan_streams().unwrap().count(), 0);
        sqlx::raw_sql("DROP TRIGGER reject_layer")
            .execute(&store.store.pool)
            .await
            .unwrap();
        let retained = store
            .publish(staged(temp.path(), &store), &ChangesetLimits::default())
            .await
            .unwrap();
        assert_eq!(count(&store, "layer_result").await, 1);
        store.recover().await.unwrap();
        assert_eq!(
            store
                .load(retained.id, &ChangesetLimits::default())
                .await
                .unwrap()
                .pack_length,
            4096
        );
    }
    #[tokio::test]
    async fn actual_pool_collision_fails_closed_without_catalog_reachability() {
        let temp = tempfile::tempdir().unwrap();
        let store = LayerStore::open(temp.path()).await.unwrap();
        let stage = staged(temp.path(), &store);
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        let map = StreamHasher::new()
            .hash_reader(&mut fs::File::open(stage.pack_path()).unwrap())
            .unwrap();
        let path = pool.stream_path(&map.id());
        fs::write(&path, b"wrong immutable bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            store.publish(stage, &ChangesetLimits::default()).await,
            Err(crate::LibVmError::Storage(
                crate::storage::StorageError::ContentMismatch(_)
            ))
        ));
        assert_eq!(count(&store, "layer_result").await, 0);
        assert_eq!(count(&store, "layer_object_dependency").await, 0);
        store.recover().await.unwrap();
        assert!(!path.exists());
    }
    #[tokio::test]
    async fn repeated_occurrences_are_immutable_and_source_free_reuse_survives_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let store = LayerStore::open(temp.path()).await.unwrap();
        let first = store
            .publish(staged(temp.path(), &store), &ChangesetLimits::default())
            .await
            .unwrap();
        let second = store
            .publish(staged(temp.path(), &store), &ChangesetLimits::default())
            .await
            .unwrap();
        assert_eq!(first, second);
        let owner = ContentDigest::of_bytes(b"manifest bytes");
        store
            .retain_occurrences(owner, &[first.id, first.id])
            .await
            .unwrap();
        assert_eq!(
            store.occurrences(owner).await.unwrap(),
            vec![first.id, first.id]
        );
        assert!(store.retain_occurrences(owner, &[first.id]).await.is_err());
        assert_eq!(
            store.occurrences(owner).await.unwrap(),
            vec![first.id, first.id]
        );
        fs::remove_file(temp.path().join("source.tar")).unwrap();
        store.store.pool.close().await;
        let reopened = LayerStore::open(temp.path()).await.unwrap();
        assert_eq!(
            reopened
                .find_recipe(first.recipe, &ChangesetLimits::default())
                .await
                .unwrap(),
            Some(first.clone())
        );
        let namespace = reopened
            .compose(&[first.id, first.id], &ChangesetLimits::default())
            .await
            .unwrap();
        assert!(namespace.inode_at(b"a").is_some());
        assert_eq!(count(&reopened, "layer_result").await, 1);
    }

    fn hook(
        store: &mut LayerStore,
        point: crate::store::layer_store::WorkerPoint,
        panic: bool,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (hook, receiver, release) =
            crate::store::layer_store::tests::WorkerHook::new(point, panic);
        store.store.layer_hook = Some(hook);
        (receiver, release)
    }
    async fn arrived(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
        tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
            .await
            .unwrap()
            .unwrap();
    }
    async fn heartbeat() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            tx.send(()).unwrap();
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
    }
    async fn exclusive_catalog(
        home: &Path,
    ) -> std::sync::Arc<crate::store::catalog_guard::CatalogGuard> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Ok(guard) = crate::store::catalog_guard::CatalogGuard::readonly(home) {
                    return guard;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }
    fn page_path(
        pool: &StoragePool,
        retained: &crate::storage::RetainedLayer,
    ) -> std::path::PathBuf {
        let digest = retained.index_root.to_string().parse().unwrap();
        let root: serde_json::Value =
            serde_json::from_slice(&pool.read_object(&digest, 65536).unwrap()).unwrap();
        pool.object_path(
            &root["pages"][0]["digest"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        )
    }
    fn overwrite(path: &Path, bytes: &[u8]) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }

    #[tokio::test]
    async fn unsafe_0444_collision_is_preserved_and_distinct_from_0400_content_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let store = LayerStore::open(temp.path()).await.unwrap();
        let stage = staged(temp.path(), &store);
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        let map = StreamHasher::new()
            .hash_reader(&mut fs::File::open(stage.pack_path()).unwrap())
            .unwrap();
        let path = pool.stream_path(&map.id());
        fs::write(&path, b"unsafe permissions").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(matches!(
            store.publish(stage, &ChangesetLimits::default()).await,
            Err(crate::LibVmError::Storage(
                crate::storage::StorageError::InvalidPath(_)
            ))
        ));
        assert!(matches!(
            store.recover().await,
            Err(crate::LibVmError::Storage(
                crate::storage::StorageError::InvalidPath(_)
            ))
        ));
        assert_eq!(fs::read(path).unwrap(), b"unsafe permissions");
        assert_eq!(count(&store, "layer_result").await, 0);
    }
    #[tokio::test]
    async fn same_count_occurrence_reordering_and_pending_gc_cannot_change_retention() {
        use crate::store::ImageStore;
        let temp = tempfile::tempdir().unwrap();
        let store = LayerStore::open(temp.path()).await.unwrap();
        let a = store
            .publish(
                staged_byte(temp.path(), &store, b'A'),
                &ChangesetLimits::default(),
            )
            .await
            .unwrap();
        let b = store
            .publish(
                staged_byte(temp.path(), &store, b'B'),
                &ChangesetLimits::default(),
            )
            .await
            .unwrap();
        let owner = ContentDigest::of_bytes(b"ordered ABA");
        store
            .retain_occurrences(owner, &[a.id, b.id, a.id])
            .await
            .unwrap();
        for wrong in [[a.id, a.id, b.id], [b.id, a.id, a.id]] {
            assert!(matches!(
                store.retain_occurrences(owner, &wrong).await,
                Err(crate::LibVmError::StateDecode { .. })
            ));
            assert_eq!(
                store.occurrences(owner).await.unwrap(),
                vec![a.id, b.id, a.id]
            );
        }
        sqlx::query("INSERT INTO image_stream_gc(stream_id,size_bytes) VALUES(?1,?2)")
            .bind(a.pack_stream.to_string())
            .bind(a.pack_length as i64)
            .execute(&store.store.pool)
            .await
            .unwrap();
        let report = store.store.prune_images().await.unwrap();
        assert_eq!(report.bytes_removed, 0);
        store.load(a.id, &ChangesetLimits::default()).await.unwrap();
        // An unreferenced flat artifact can share a retained layer stream. Its
        // catalog row is prunable, but neither GC gate may unlink the pack.
        sqlx::query("INSERT INTO image_manifest(digest,media_type,image_id,platform_os,platform_architecture,config_digest,layer_count,total_size_bytes,created_at) VALUES('fixture-manifest','fixture','fixture-image','linux','amd64','fixture-config',0,4096,0)").execute(&store.store.pool).await.unwrap();
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        sqlx::query("INSERT INTO image_rootfs_artifact(image_id,manifest_digest,config_digest,platform_os,platform_architecture,filesystem,rootfs_path,size_bytes,created_at,stream_id,conversion_abi) VALUES('fixture-image','fixture-manifest','fixture-config','linux','amd64','ext4',?1,?2,0,?3,?4)")
            .bind(pool.stream_path(&a.pack_stream).to_str().unwrap()).bind(a.pack_length as i64).bind(a.pack_stream.to_string()).bind(crate::image::oci::CONVERSION_ABI).execute(&store.store.pool).await.unwrap();
        let report = store.store.prune_images().await.unwrap();
        assert_eq!(report.artifacts_removed, 1);
        assert_eq!(report.bytes_removed, 0);
        assert!(pool.stream_path(&a.pack_stream).exists());
        store.load(a.id, &ChangesetLimits::default()).await.unwrap();
    }
    #[tokio::test]
    async fn source_free_consumer_authenticates_every_closure_member() {
        for member in ["pack", "recipe", "result", "root", "page"] {
            let temp = tempfile::tempdir().unwrap();
            let store = LayerStore::open(temp.path()).await.unwrap();
            let retained = store
                .publish(staged(temp.path(), &store), &ChangesetLimits::default())
                .await
                .unwrap();
            fs::remove_file(temp.path().join("source.tar")).unwrap();
            let pool = StoragePool::open(&store.store.images_dir).unwrap();
            let path = match member {
                "pack" => pool.stream_path(&retained.pack_stream),
                "root" => pool.object_path(&retained.index_root.to_string().parse().unwrap()),
                "page" => page_path(&pool, &retained),
                table => {
                    let (sql, id) = match table {
                        "recipe" => (
                            "SELECT record_digest FROM layer_recipe WHERE id=?1",
                            retained.recipe.to_string(),
                        ),
                        "result" => (
                            "SELECT record_digest FROM layer_result WHERE id=?1",
                            retained.id.to_string(),
                        ),
                        _ => panic!("unknown closure member"),
                    };
                    let digest: String = sqlx::query_scalar(sql)
                        .bind(id)
                        .fetch_one(&store.store.pool)
                        .await
                        .unwrap();
                    pool.object_path(&digest.parse().unwrap())
                }
            };
            let mut bytes = fs::read(&path).unwrap();
            bytes[0] ^= 1;
            overwrite(&path, &bytes);
            assert!(
                matches!(
                    store.load(retained.id, &ChangesetLimits::default()).await,
                    Err(crate::LibVmError::Storage(
                        crate::storage::StorageError::ContentMismatch(_)
                    ))
                ),
                "{member}"
            );
            assert!(
                store
                    .find_recipe(retained.recipe, &ChangesetLimits::default())
                    .await
                    .is_err(),
                "{member}"
            );
        }
    }
    #[tokio::test]
    async fn root_and_page_failures_preserve_the_same_concrete_storage_causes() {
        for member in ["root", "page"] {
            for failure in ["missing", "mode", "symlink"] {
                let temp = tempfile::tempdir().unwrap();
                let store = LayerStore::open(temp.path()).await.unwrap();
                let retained = store
                    .publish(staged(temp.path(), &store), &ChangesetLimits::default())
                    .await
                    .unwrap();
                let pool = StoragePool::open(&store.store.images_dir).unwrap();
                let path = if member == "root" {
                    pool.object_path(&retained.index_root.to_string().parse().unwrap())
                } else {
                    page_path(&pool, &retained)
                };
                match failure {
                    "mode" => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap()
                    }
                    "symlink" => {
                        let backup = temp.path().join("object-backup");
                        fs::rename(&path, &backup).unwrap();
                        std::os::unix::fs::symlink(backup, &path).unwrap();
                    }
                    _ => fs::remove_file(&path).unwrap(),
                }
                let error = store
                    .load(retained.id, &ChangesetLimits::default())
                    .await
                    .unwrap_err();
                match failure {
                    "mode" => assert!(matches!(
                        error,
                        crate::LibVmError::Storage(crate::storage::StorageError::InvalidPath(_))
                    )),
                    "missing" => assert!(
                        matches!(error,crate::LibVmError::Storage(crate::storage::StorageError::Io(error)) if error.kind()==std::io::ErrorKind::NotFound)
                    ),
                    _ => assert!(matches!(
                        error,
                        crate::LibVmError::Storage(crate::storage::StorageError::Io(_))
                    )),
                }
            }
        }
    }
    #[tokio::test]
    async fn catalog_corruption_is_rejected_without_repairing_immutable_facts() {
        for fault in ["missing-dependency", "extra-dependency", "recipe", "result"] {
            let temp = tempfile::tempdir().unwrap();
            let store = LayerStore::open(temp.path()).await.unwrap();
            let retained = store
                .publish(staged(temp.path(), &store), &ChangesetLimits::default())
                .await
                .unwrap();
            if fault == "missing-dependency" {
                sqlx::query(
                    "DELETE FROM layer_object_dependency WHERE result_id=?1 AND object_digest=?2",
                )
                .bind(retained.id.to_string())
                .bind(retained.index_root.to_string())
                .execute(&store.store.pool)
                .await
                .unwrap();
            } else if fault == "extra-dependency" {
                let source = temp.path().join("extra");
                fs::write(&source, b"extra object").unwrap();
                let extra = StoragePool::open(&store.store.images_dir)
                    .unwrap()
                    .publish_object(&source)
                    .unwrap();
                sqlx::query(
                    "INSERT INTO layer_object_dependency(result_id,object_digest) VALUES(?1,?2)",
                )
                .bind(retained.id.to_string())
                .bind(extra.digest.to_string())
                .execute(&store.store.pool)
                .await
                .unwrap();
            } else {
                let (drop_sql, update_sql) = match fault {
                    "recipe" => (
                        "DROP TRIGGER layer_recipe_immutable",
                        "UPDATE layer_recipe SET record_digest=?1 WHERE id=?2",
                    ),
                    "result" => (
                        "DROP TRIGGER layer_result_immutable",
                        "UPDATE layer_result SET record_digest=?1 WHERE id=?2",
                    ),
                    _ => panic!("unknown immutable corruption fixture"),
                };
                sqlx::raw_sql(drop_sql)
                    .execute(&store.store.pool)
                    .await
                    .unwrap();
                sqlx::query(update_sql)
                    .bind(ContentDigest::of_bytes(b"contradiction").to_string())
                    .bind(if fault == "recipe" {
                        retained.recipe.to_string()
                    } else {
                        retained.id.to_string()
                    })
                    .execute(&store.store.pool)
                    .await
                    .unwrap();
            }
            let before = count(&store, "layer_object_dependency").await;
            assert!(matches!(
                store.load(retained.id, &ChangesetLimits::default()).await,
                Err(crate::LibVmError::StateDecode { .. })
            ));
            assert!(matches!(
                store
                    .publish(staged(temp.path(), &store), &ChangesetLimits::default())
                    .await,
                Err(crate::LibVmError::StateDecode { .. })
            ));
            assert_eq!(count(&store, "layer_object_dependency").await, before);
            assert_eq!(count(&store, "layer_result").await, 1);
        }
    }
    #[tokio::test]
    async fn retained_load_never_recreates_missing_pool_structure() {
        let temp = tempfile::tempdir().unwrap();
        let store = LayerStore::open(temp.path()).await.unwrap();
        let retained = store
            .publish(staged(temp.path(), &store), &ChangesetLimits::default())
            .await
            .unwrap();
        let transport = store.store.images_dir.join("transport/sha256");
        fs::remove_dir(&transport).unwrap();
        let parent = transport.parent().unwrap();
        let before = fs::metadata(parent).unwrap().modified().unwrap();
        store
            .load(retained.id, &ChangesetLimits::default())
            .await
            .unwrap();
        store
            .find_recipe(retained.recipe, &ChangesetLimits::default())
            .await
            .unwrap()
            .unwrap();
        assert!(!transport.exists());
        assert_eq!(fs::metadata(parent).unwrap().modified().unwrap(), before);
        let objects = store.store.images_dir.join("objects/sha256");
        fs::rename(&objects, store.store.images_dir.join("objects/held")).unwrap();
        assert!(matches!(
            store.load(retained.id, &ChangesetLimits::default()).await,
            Err(crate::LibVmError::Storage(
                crate::storage::StorageError::InvalidPath(_)
            ))
        ));
        assert!(store
            .find_recipe(retained.recipe, &ChangesetLimits::default())
            .await
            .is_err());
        assert!(!objects.exists());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn detached_publication_retains_catalog_capability_after_cancel_and_pool_close() {
        use crate::store::layer_store::WorkerPoint;
        let temp = tempfile::tempdir().unwrap();
        let mut store = LayerStore::open(temp.path()).await.unwrap();
        let stage = staged(temp.path(), &store);
        let recipe = oci::changeset::LayerRecipe {
            diff_id: stage.changeset().diff_id,
        }
        .id()
        .unwrap();
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        let lock = pool
            .lock_publication(&recipe.to_string().parse().unwrap())
            .unwrap();
        let (mut entered, release) = hook(&mut store, WorkerPoint::Preparing, false);
        let publisher = store.clone();
        let task =
            tokio::spawn(
                async move { publisher.publish(stage, &ChangesetLimits::default()).await },
            );
        arrived(&mut entered).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        store.store.pool.close().await;
        drop(store);
        assert!(crate::store::catalog_guard::CatalogGuard::readonly(temp.path()).is_err());
        heartbeat().await;
        drop(lock);
        let guard = exclusive_catalog(temp.path()).await;
        drop(guard);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_and_many_occurrence_composition_leave_the_executor_responsive() {
        use crate::store::layer_store::WorkerPoint;
        let temp = tempfile::tempdir().unwrap();
        let mut store = LayerStore::open(temp.path()).await.unwrap();
        let stage = staged(temp.path(), &store);
        let (mut entered, release) = hook(&mut store, WorkerPoint::Cleanup, false);
        let publisher = store.clone();
        let task =
            tokio::spawn(
                async move { publisher.publish(stage, &ChangesetLimits::default()).await },
            );
        arrived(&mut entered).await;
        heartbeat().await;
        assert_eq!(count(&store, "layer_result").await, 1);
        release.send(()).unwrap();
        let retained = task.await.unwrap().unwrap();
        let (mut entered, release) = hook(&mut store, WorkerPoint::Compose, false);
        let composer = store.clone();
        let task = tokio::spawn(async move {
            composer
                .compose(&vec![retained.id; 1024], &ChangesetLimits::default())
                .await
        });
        arrived(&mut entered).await;
        heartbeat().await;
        release.send(()).unwrap();
        let namespace = task.await.unwrap().unwrap();
        assert_eq!(
            namespace.inode_at(b"a").unwrap().origin.unwrap().layer,
            1023
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_recovery_keeps_roots_and_catalog_through_actual_deletion() {
        use crate::store::layer_store::WorkerPoint;
        let temp = tempfile::tempdir().unwrap();
        let mut store = LayerStore::open(temp.path()).await.unwrap();
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        let source = temp.path().join("orphan");
        fs::write(&source, b"unretained object").unwrap();
        let orphan = pool.publish_object(&source).unwrap();
        let (mut entered, release) = hook(&mut store, WorkerPoint::RecoveryDelete, false);
        let recovery = store.clone();
        let task = tokio::spawn(async move { recovery.recover().await });
        arrived(&mut entered).await;
        heartbeat().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(pool.try_roots_shared().unwrap().is_none());
        let sql = store.store.pool.clone();
        let closing = tokio::spawn(async move {
            sql.close().await;
        });
        drop(store);
        assert!(crate::store::catalog_guard::CatalogGuard::readonly(temp.path()).is_err());
        assert!(orphan.path.exists());
        release.send(()).unwrap();
        closing.await.unwrap();
        let guard = exclusive_catalog(temp.path()).await;
        assert!(!orphan.path.exists());
        assert!(pool.try_roots_shared().unwrap().is_some());
        drop(guard);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_stream_gc_keeps_authorization_catalog_and_roots_until_unlink() {
        use crate::store::layer_store::WorkerPoint;
        let temp = tempfile::tempdir().unwrap();
        let mut store = LayerStore::open(temp.path()).await.unwrap();
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        let source = temp.path().join("orphan-stream");
        fs::write(&source, b"unretained stream").unwrap();
        let orphan = pool.publish_stream(&source).unwrap();
        let (mut entered, release) = hook(&mut store, WorkerPoint::RecoveryDelete, false);
        let recovery = store.clone();
        let task = tokio::spawn(async move { recovery.recover().await });
        arrived(&mut entered).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(pool.try_roots_shared().unwrap().is_none());
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM image_stream_gc WHERE stream_id=?1")
                .bind(orphan.id.to_string())
                .fetch_one(&store.store.pool)
                .await
                .unwrap();
        assert_eq!(pending, 1);
        let sql = store.store.pool.clone();
        let closing = tokio::spawn(async move {
            sql.close().await;
        });
        drop(store);
        assert!(crate::store::catalog_guard::CatalogGuard::readonly(temp.path()).is_err());
        assert!(orphan.path.exists());
        release.send(()).unwrap();
        closing.await.unwrap();
        let guard = exclusive_catalog(temp.path()).await;
        assert!(!orphan.path.exists());
        assert!(pool.try_roots_shared().unwrap().is_some());
        drop(guard);
    }
    #[tokio::test]
    async fn blocking_worker_panic_is_not_malformed_changeset_state() {
        use crate::store::layer_store::WorkerPoint;
        let temp = tempfile::tempdir().unwrap();
        let mut store = LayerStore::open(temp.path()).await.unwrap();
        let stage = staged(temp.path(), &store);
        let (_entered, _release) = hook(&mut store, WorkerPoint::Preparing, true);
        assert!(
            matches!(store.publish(stage,&ChangesetLimits::default()).await,Err(crate::LibVmError::Task(error)) if error.is_panic())
        );
    }
    #[tokio::test]
    async fn publication_rechecks_pack_page_and_root_not_just_last_published_file() {
        use crate::store::layer_store::WorkerPoint;
        for member in ["pack", "page", "root"] {
            let temp = tempfile::tempdir().unwrap();
            let mut store = LayerStore::open(temp.path()).await.unwrap();
            let stage = staged(temp.path(), &store);
            let (mut entered, release) = hook(&mut store, WorkerPoint::BeforeRoots, false);
            let publisher = store.clone();
            let task =
                tokio::spawn(
                    async move { publisher.publish(stage, &ChangesetLimits::default()).await },
                );
            arrived(&mut entered).await;
            let pool = StoragePool::open(&store.store.images_dir).unwrap();
            let path = if member == "pack" {
                let (id, _) = pool.scan_streams().unwrap().next().unwrap().unwrap();
                pool.stream_path(&id)
            } else {
                pool.scan_objects()
                    .unwrap()
                    .map(Result::unwrap)
                    .find_map(|digest| {
                        let value: serde_json::Value = serde_json::from_slice(
                            &pool.read_object(&digest, 4 * 1024 * 1024).unwrap(),
                        )
                        .unwrap();
                        let kind = if member == "root" {
                            "changeset-index"
                        } else {
                            "changeset-entry-page"
                        };
                        (value["kind"] == kind).then(|| pool.object_path(&digest))
                    })
                    .unwrap()
            };
            let bytes = fs::read(&path).unwrap();
            fs::rename(&path, temp.path().join("previous-closure-member")).unwrap();
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            release.send(()).unwrap();
            assert!(
                matches!(
                    task.await.unwrap(),
                    Err(crate::LibVmError::StateDecode { .. })
                ),
                "{member}"
            );
            assert_eq!(count(&store, "layer_result").await, 0);
            store.store.layer_hook = None;
            store.recover().await.unwrap();
            assert_eq!(pool.scan_objects().unwrap().count(), 0);
            assert_eq!(pool.scan_streams().unwrap().count(), 0);
        }
    }
    #[tokio::test]
    async fn real_recovery_between_first_object_and_catalog_commit_retains_published_dependencies()
    {
        use crate::store::layer_store::WorkerPoint;
        let temp = tempfile::tempdir().unwrap();
        let mut store = LayerStore::open(temp.path()).await.unwrap();
        let stage = staged(temp.path(), &store);
        let (mut entered, release) = hook(&mut store, WorkerPoint::AfterObject, false);
        let publisher = store.clone();
        let task =
            tokio::spawn(
                async move { publisher.publish(stage, &ChangesetLimits::default()).await },
            );
        arrived(&mut entered).await;
        store.recover().await.unwrap();
        release.send(()).unwrap();
        let retained = task.await.unwrap().unwrap();
        assert_eq!(count(&store, "layer_result").await, 1);
        assert!(count(&store, "layer_object_dependency").await > 0);
        store.store.layer_hook = None;
        store.recover().await.unwrap();
        store
            .load(retained.id, &ChangesetLimits::default())
            .await
            .unwrap();
        let pool = StoragePool::open(&store.store.images_dir).unwrap();
        assert!(pool.scan_objects().unwrap().count() > 0);
        assert_eq!(pool.scan_streams().unwrap().count(), 1);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_publication_cleanup_retains_catalog_until_staging_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = LayerStore::open(temp.path()).await.unwrap();
        let stage = staged(temp.path(), &store);
        let private = stage.pack_path().parent().unwrap().to_path_buf();
        let (mut entered, release) = hook(&mut store, WorkerPoint::Cleanup, false);
        let publisher = store.clone();
        let task =
            tokio::spawn(
                async move { publisher.publish(stage, &ChangesetLimits::default()).await },
            );
        arrived(&mut entered).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        store.store.pool.close().await;
        drop(store);
        assert!(private.exists());
        assert!(crate::store::catalog_guard::CatalogGuard::readonly(temp.path()).is_err());
        heartbeat().await;
        release.send(()).unwrap();
        let guard = exclusive_catalog(temp.path()).await;
        assert!(!private.exists());
        drop(guard);
    }
}
