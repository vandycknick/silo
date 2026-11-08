//! Retained layered lower compositions.
//!
//! ```text
//! machine_lower_dependency ─┐
//! image_composition_artifact├─► composition_result ─► composition_layer ─► layer_result
//! storage_operation_lower ──┘        │                  (ordered, repeats)   ├─ pack stream
//!                                    ├─ result/recipe record objects         ├─ pack map objects
//!                                    └─ fsmeta object (never a stream copy)  └─ index root/pages
//! ```
//!
//! The concatenated lower is never materialized: its logical stream identity
//! is recomputed by `storage::composition` over the held fsmeta object and pack
//! streams. Reuse authenticates exact retained bytes; regeneration is only ever
//! checked against an exact retained or expected result.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;

use oci::changeset::{ChangesetLimits, LayerResultId};
use oci::composition::{CompositionRecipe, CompositionResult, MAX_RECORD_BYTES};
use sqlx::Row;
use vm_spec::DiskGeometry;

use crate::storage::identity::{LowerResultId, ObjectDigest};
use crate::storage::pool::StoragePool;
use crate::storage::vmdk::LowerOccurrence;
use crate::storage::StorageError;
use crate::store::layer_store::{LayerReadOwner, LayerStore, PinnedLayer};
use crate::store::models::snapshot::{content_object, SnapshotComposition, SnapshotLayer};
use crate::store::Store;
use crate::{LibVmError, OverlayLower};

fn invalid(message: impl std::fmt::Display) -> LibVmError {
    LibVmError::StateDecode {
        field: "composition",
        message: message.to_string(),
    }
}

/// A missing retained file is an acquisition requirement for that lower,
/// never permission to regenerate or substitute another identity.
fn retained(lower: LowerResultId) -> impl Fn(StorageError) -> LibVmError {
    move |error| match error {
        StorageError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            LibVmError::CompositionAcquisitionRequired {
                lower,
                missing: io.to_string(),
            }
        }
        error => LibVmError::Storage(error),
    }
}

fn int(value: u64) -> Result<i64, LibVmError> {
    i64::try_from(value).map_err(invalid)
}

fn existing_pool(store: &Store) -> Result<StoragePool, LibVmError> {
    StoragePool::open_existing(&store.images_dir)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "retained composition pool is absent",
        )
        .into()
    })
}

/// Canonical rows of one retained composition, authenticated against their
/// retained record objects and each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedComposition {
    pub id: LowerResultId,
    pub recipe: CompositionRecipe,
    pub result: CompositionResult,
    pub recipe_digest: ObjectDigest,
    pub record_digest: ObjectDigest,
    /// Exact occurrence order, including repetitions.
    pub layers: Vec<LayerResultId>,
}

impl RetainedComposition {
    pub fn geometry(&self) -> DiskGeometry {
        DiskGeometry {
            length: self.result.lower_length,
            logical_sector_size: 512,
        }
    }

    pub fn filesystem_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.result.fsmeta.uuid)
    }

    pub fn fsmeta(&self) -> ObjectDigest {
        ObjectDigest::from_sha256(*self.result.fsmeta.digest.as_bytes())
    }

    /// The machine root lower whose derived claims equal this result.
    pub fn overlay_lower(&self) -> OverlayLower {
        OverlayLower::ErofsComposition {
            record: self.id,
            geometry: self.geometry(),
            filesystem_uuid: self.filesystem_uuid(),
        }
    }

    /// Persisted lower claims are admissible only for this exact result.
    pub(crate) fn check_lower(&self, lower: &OverlayLower) -> Result<(), LibVmError> {
        if self.overlay_lower() != *lower {
            return Err(invalid(
                "machine lower geometry or UUID contradicts its retained composition",
            ));
        }
        Ok(())
    }
}

/// An exact retained composition held for reading: one consumer lease pins
/// the lower, its layers, pack streams and objects; packs and fsmeta are held
/// descriptors that `storage::composition` authenticated.
pub struct HeldComposition {
    retained: RetainedComposition,
    unique: Vec<(PinnedLayer, File)>,
    occurrences: Vec<usize>,
    fsmeta: File,
    _owner: LayerReadOwner,
}

impl HeldComposition {
    pub fn retained(&self) -> &RetainedComposition {
        &self.retained
    }

    /// Ordered occurrences; repeats share one held pack descriptor.
    pub fn layers(&self) -> Vec<oci::erofs::Layer<'_>> {
        self.occurrences
            .iter()
            .filter_map(|index| self.unique.get(*index))
            .map(|(layer, pack)| oci::erofs::Layer {
                result: &layer.result,
                changeset: &layer.changeset,
                pack,
            })
            .collect()
    }

    pub fn fsmeta(&self) -> &File {
        &self.fsmeta
    }

    pub fn snapshot_composition(&self) -> Result<SnapshotComposition, LibVmError> {
        snapshot_graph(&self.retained, &self.unique, &self.occurrences)
    }
}

/// A leased launch closure: resolved, not yet hashed, VMDK occurrences
/// (fsmeta object first, then every pack occurrence). The launch path runs
/// the VMDK preflight and verification over these while holding the lease.
pub struct LaunchLower {
    pub occurrences: Vec<LowerOccurrence>,
    pub retained: RetainedComposition,
    _owner: LayerReadOwner,
}

fn snapshot_graph(
    retained: &RetainedComposition,
    unique: &[(PinnedLayer, File)],
    occurrences: &[usize],
) -> Result<SnapshotComposition, LibVmError> {
    let layers = occurrences
        .iter()
        .map(|index| {
            let (layer, _) = unique
                .get(*index)
                .ok_or_else(|| invalid("composition occurrence index is outside its layers"))?;
            Ok(SnapshotLayer {
                recipe: layer.recipe_digest,
                result: layer.result_digest,
                index_root: layer.index_root,
                index_pages: layer.index_pages.clone(),
                pack: layer.pack.clone(),
            })
        })
        .collect::<Result<Vec<_>, LibVmError>>()?;
    let graph = SnapshotComposition {
        result: retained.id,
        record: retained.record_digest,
        recipe: retained.recipe_digest,
        fsmeta: retained.fsmeta(),
        layers,
    };
    graph.validate_shape()?;
    Ok(graph)
}

/// Unique pinned layers plus the occurrence mapping, in occurrence order.
async fn pin_layers(
    layers: &LayerStore,
    pool: &StoragePool,
    occurrences: &[LayerResultId],
    limits: &ChangesetLimits,
) -> Result<(Vec<(PinnedLayer, File)>, Vec<usize>), LibVmError> {
    let mut ids: Vec<LayerResultId> = Vec::new();
    let mut unique = Vec::new();
    let mut mapping = Vec::with_capacity(occurrences.len());
    for id in occurrences {
        if let Some(index) = ids.iter().position(|other| other == id) {
            mapping.push(index);
            continue;
        }
        let pinned = layers.load_pinned_layer(*id, limits, false).await?;
        let pack = pool.open_stream(&pinned.pack.stream)?;
        mapping.push(unique.len());
        ids.push(*id);
        unique.push((pinned, pack));
    }
    Ok((unique, mapping))
}

fn layer_refs<'a>(
    unique: &'a [(PinnedLayer, File)],
    occurrences: &[usize],
) -> Vec<oci::erofs::Layer<'a>> {
    occurrences
        .iter()
        .filter_map(|index| unique.get(*index))
        .map(|(layer, pack)| oci::erofs::Layer {
            result: &layer.result,
            changeset: &layer.changeset,
            pack,
        })
        .collect()
}

/// Read and authenticate one composition's rows and record objects.
async fn read_retained(
    store: &Store,
    pool: &StoragePool,
    id: LowerResultId,
) -> Result<RetainedComposition, LibVmError> {
    let row = sqlx::query("SELECT r.recipe_id,r.fsmeta_digest,r.fsmeta_length,r.lower_stream,r.lower_length,r.record_digest,r.record_bytes,p.record_digest AS recipe_digest,p.record_bytes AS recipe_bytes FROM composition_result r JOIN composition_recipe p ON p.id=r.recipe_id WHERE r.id=?1")
        .bind(id.to_string())
        .fetch_optional(&store.pool)
        .await?
        .ok_or_else(|| LibVmError::CompositionAcquisitionRequired {
            lower: id,
            missing: "retained composition record".into(),
        })?;
    let recipe_bytes: Vec<u8> = row.try_get("recipe_bytes")?;
    let result_bytes: Vec<u8> = row.try_get("record_bytes")?;
    let recipe = CompositionRecipe::decode(&recipe_bytes).map_err(invalid)?;
    let result = CompositionResult::decode(&result_bytes).map_err(invalid)?;
    let recipe_digest = ObjectDigest::of_bytes(&recipe_bytes);
    let record_digest = ObjectDigest::of_bytes(&result_bytes);
    result.validate_recipe(&recipe).map_err(invalid)?;
    if LowerResultId::from_composition(result.id().map_err(invalid)?) != id
        || row.try_get::<String, _>("recipe_id")? != recipe.id().map_err(invalid)?.to_string()
        || row.try_get::<String, _>("recipe_digest")? != recipe_digest.to_string()
        || row.try_get::<String, _>("record_digest")? != record_digest.to_string()
        || row.try_get::<String, _>("fsmeta_digest")? != result.fsmeta.digest.to_string()
        || row.try_get::<i64, _>("fsmeta_length")? != int(result.fsmeta.length)?
        || row.try_get::<String, _>("lower_stream")? != result.lower_stream.to_string()
        || row.try_get::<i64, _>("lower_length")? != int(result.lower_length)?
    {
        return Err(invalid("composition catalog row contradicts its records"));
    }
    let rows = sqlx::query(
        "SELECT position,layer_result_id FROM composition_layer WHERE result_id=?1 ORDER BY position",
    )
    .bind(id.to_string())
    .fetch_all(&store.pool)
    .await?;
    let mut layers = Vec::with_capacity(rows.len());
    for (position, row) in rows.iter().enumerate() {
        if row.try_get::<i64, _>("position")? != int(position as u64)? {
            return Err(invalid("composition occurrences are not contiguous"));
        }
        layers.push(
            row.try_get::<String, _>("layer_result_id")?
                .parse::<LayerResultId>()?,
        );
    }
    if layers.len() != recipe.layers.len()
        || layers
            .iter()
            .zip(&recipe.layers)
            .any(|(layer, binding)| *layer != binding.result)
    {
        return Err(invalid("composition occurrences contradict its recipe"));
    }
    for (digest, bytes) in [
        (recipe_digest, &recipe_bytes),
        (record_digest, &result_bytes),
    ] {
        if pool
            .read_object(&digest, MAX_RECORD_BYTES as u64)
            .map_err(retained(id))?
            != *bytes
        {
            return Err(invalid("composition record object contradicts its row"));
        }
    }
    Ok(RetainedComposition {
        id,
        recipe,
        result,
        recipe_digest,
        record_digest,
        layers,
    })
}

/// Insert or compare the immutable composition rows and pin the lower to
/// `operation`, under shared roots coordination.
async fn commit_composition(
    store: &Store,
    pool: &StoragePool,
    operation: uuid::Uuid,
    retained: &RetainedComposition,
) -> Result<(), LibVmError> {
    let recipe_bytes = retained.recipe.canonical_bytes().map_err(invalid)?;
    let result_bytes = retained.result.canonical_bytes().map_err(invalid)?;
    let recipe_id = retained.recipe.id().map_err(invalid)?.to_string();
    let _roots = pool.lock_roots_shared()?;
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("INSERT INTO composition_recipe(id,record_digest,record_bytes) VALUES(?1,?2,?3) ON CONFLICT(id) DO NOTHING")
        .bind(&recipe_id).bind(retained.recipe_digest.to_string()).bind(&recipe_bytes).execute(&mut *tx).await?;
    let stored =
        sqlx::query("SELECT record_digest,record_bytes FROM composition_recipe WHERE id=?1")
            .bind(&recipe_id)
            .fetch_one(&mut *tx)
            .await?;
    if stored.try_get::<String, _>("record_digest")? != retained.recipe_digest.to_string()
        || stored.try_get::<Vec<u8>, _>("record_bytes")? != recipe_bytes
    {
        return Err(invalid("immutable composition recipe contradiction"));
    }
    let inserted = sqlx::query("INSERT INTO composition_result(id,recipe_id,fsmeta_digest,fsmeta_length,lower_stream,lower_length,record_digest,record_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO NOTHING")
        .bind(retained.id.to_string())
        .bind(&recipe_id)
        .bind(retained.result.fsmeta.digest.to_string())
        .bind(int(retained.result.fsmeta.length)?)
        .bind(retained.result.lower_stream.to_string())
        .bind(int(retained.result.lower_length)?)
        .bind(retained.record_digest.to_string())
        .bind(&result_bytes)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 0;
    let stored = sqlx::query(
        "SELECT recipe_id,record_digest,record_bytes FROM composition_result WHERE id=?1",
    )
    .bind(retained.id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    if stored.try_get::<String, _>("recipe_id")? != recipe_id
        || stored.try_get::<String, _>("record_digest")? != retained.record_digest.to_string()
        || stored.try_get::<Vec<u8>, _>("record_bytes")? != result_bytes
    {
        return Err(invalid("immutable composition result contradiction"));
    }
    if inserted {
        for (position, layer) in retained.layers.iter().enumerate() {
            sqlx::query("INSERT INTO composition_layer(result_id,position,layer_result_id) VALUES(?1,?2,?3)")
                .bind(retained.id.to_string()).bind(int(position as u64)?).bind(layer.to_string()).execute(&mut *tx).await?;
        }
    } else {
        let stored = sqlx::query_scalar::<_, String>(
            "SELECT layer_result_id FROM composition_layer WHERE result_id=?1 ORDER BY position",
        )
        .bind(retained.id.to_string())
        .fetch_all(&mut *tx)
        .await?;
        if stored
            != retained
                .layers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        {
            return Err(invalid("immutable composition occurrence contradiction"));
        }
    }
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND state='staging')",
    )
    .bind(operation.to_string())
    .fetch_one(&mut *tx)
    .await?;
    if !active {
        return Err(invalid("composition publication has no active operation"));
    }
    sqlx::query(
        "INSERT OR IGNORE INTO storage_operation_lower(operation_id,lower_id) VALUES(?1,?2)",
    )
    .bind(operation.to_string())
    .bind(retained.id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Publish one small canonical record object and pin it to `operation`.
async fn publish_record(
    store: &Store,
    pool: &StoragePool,
    operation: uuid::Uuid,
    bytes: &[u8],
) -> Result<ObjectDigest, LibVmError> {
    let (object, roots, ()) = pool.publish_produced_object_for_catalog(|file| {
        file.write_all(bytes)?;
        Ok::<_, StorageError>(())
    })?;
    if object.digest != ObjectDigest::of_bytes(bytes) {
        return Err(invalid("record object changed before publication"));
    }
    store
        .pin_published_storage_dependencies(operation, &[], &[object.digest])
        .await?;
    drop(roots);
    Ok(object.digest)
}

impl LayerStore {
    /// Reuse or publish the composition of `occurrences` for `platform`.
    /// Reuse requires the exact retained fsmeta to authenticate; a new result
    /// is encoded straight into pool staging and published as a byte object.
    pub async fn compose_retained(
        &self,
        platform: oci::Platform,
        occurrences: &[LayerResultId],
        limits: &ChangesetLimits,
    ) -> Result<HeldComposition, LibVmError> {
        limits.validate()?;
        crate::storage::limits::Resource::LayerOccurrences
            .check(occurrences.len() as u64)
            .map_err(StorageError::from)?;
        let store = self.clone();
        let occurrences = occurrences.to_vec();
        let limits = *limits;
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.compose_retained_owned(platform, occurrences, limits))
        })
        .await?
    }

    async fn compose_retained_owned(
        &self,
        platform: oci::Platform,
        occurrences: Vec<LayerResultId>,
        limits: ChangesetLimits,
    ) -> Result<HeldComposition, LibVmError> {
        let store = &self.store;
        let owner = self.begin_consumer(&occurrences, &[]).await?;
        let pool = existing_pool(store)?;
        let (unique, mapping) = pin_layers(self, &pool, &occurrences, &limits).await?;
        let layers = layer_refs(&unique, &mapping);
        let recipe = CompositionRecipe::from_layers(platform, &layers).map_err(invalid)?;
        let recipe_id = recipe.id().map_err(invalid)?;
        let _publication =
            pool.lock_publication(&ObjectDigest::of_bytes(recipe_id.to_string().as_bytes()))?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT id FROM composition_result WHERE recipe_id=?1")
                .bind(recipe_id.to_string())
                .fetch_optional(&store.pool)
                .await?;
        let (retained, fsmeta) = match existing {
            Some(id) => {
                let id: LowerResultId = id.parse().map_err(invalid)?;
                store.pin_operation_lowers(owner.operation, &[id]).await?;
                let retained = read_retained(store, &pool, id).await?;
                if retained.recipe != recipe || retained.layers != occurrences {
                    return Err(invalid(
                        "retained composition contradicts its recipe lookup",
                    ));
                }
                let fsmeta = pool
                    .open_object(&retained.fsmeta())
                    .map_err(self::retained(id))?;
                let loaded = crate::storage::composition::load_exact(
                    &recipe,
                    &layers,
                    &retained.result,
                    &fsmeta,
                )?;
                if loaded.result != retained.result {
                    return Err(invalid(
                        "retained fsmeta does not reproduce its exact result",
                    ));
                }
                (retained, fsmeta)
            }
            None => {
                let (object, roots, composed) =
                    pool.publish_produced_object_for_catalog(|file| {
                        crate::storage::composition::compose(&recipe, &layers, file)
                    })?;
                store
                    .pin_published_storage_dependencies(owner.operation, &[], &[object.digest])
                    .await?;
                drop(roots);
                if content_object(composed.result.fsmeta.digest)? != object.digest
                    || composed.result.fsmeta.length != object.length
                {
                    return Err(invalid("published fsmeta differs from its composition"));
                }
                let recipe_digest = publish_record(
                    store,
                    &pool,
                    owner.operation,
                    &recipe.canonical_bytes().map_err(invalid)?,
                )
                .await?;
                let record_digest = publish_record(
                    store,
                    &pool,
                    owner.operation,
                    &composed.result.canonical_bytes().map_err(invalid)?,
                )
                .await?;
                let retained = RetainedComposition {
                    id: LowerResultId::from_composition(composed.result.id().map_err(invalid)?),
                    recipe: recipe.clone(),
                    result: composed.result,
                    recipe_digest,
                    record_digest,
                    layers: occurrences.clone(),
                };
                commit_composition(store, &pool, owner.operation, &retained).await?;
                let fsmeta = pool.open_object(&object.digest)?;
                (retained, fsmeta)
            }
        };
        drop(layers);
        Ok(HeldComposition {
            retained,
            unique,
            occurrences: mapping,
            fsmeta,
            _owner: owner,
        })
    }

    /// Authenticated rows of one retained composition, without leasing.
    pub async fn retained_composition(
        &self,
        id: LowerResultId,
    ) -> Result<RetainedComposition, LibVmError> {
        let pool = existing_pool(&self.store)?;
        read_retained(&self.store, &pool, id).await
    }

    async fn retained_layers(&self, id: LowerResultId) -> Result<Vec<LayerResultId>, LibVmError> {
        let layers = sqlx::query_scalar::<_, String>(
            "SELECT layer_result_id FROM composition_layer WHERE result_id=?1 ORDER BY position",
        )
        .bind(id.to_string())
        .fetch_all(&self.store.pool)
        .await?;
        layers
            .into_iter()
            .map(|layer| layer.parse().map_err(LibVmError::Changeset))
            .collect()
    }

    /// Lease and authenticate an exact retained composition: every pack and
    /// fsmeta byte, all records and the logical lower identity. No encoder or
    /// OCI source participates.
    pub async fn hold_composition(&self, id: LowerResultId) -> Result<HeldComposition, LibVmError> {
        let store = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                let occurrences = store.retained_layers(id).await?;
                let owner = store.begin_consumer(&occurrences, &[id]).await?;
                let pool = existing_pool(&store.store)?;
                let retained = read_retained(&store.store, &pool, id).await?;
                let (unique, mapping) =
                    pin_layers(&store, &pool, &retained.layers, &ChangesetLimits::default())
                        .await?;
                let fsmeta = pool
                    .open_object(&retained.fsmeta())
                    .map_err(self::retained(id))?;
                let loaded = crate::storage::composition::load_exact(
                    &retained.recipe,
                    &layer_refs(&unique, &mapping),
                    &retained.result,
                    &fsmeta,
                )?;
                if loaded.result != retained.result {
                    return Err(invalid("retained composition failed exact loading"));
                }
                Ok(HeldComposition {
                    retained,
                    unique,
                    occurrences: mapping,
                    fsmeta,
                    _owner: owner,
                })
            })
        })
        .await?
    }

    /// Lease a machine lower for launch and resolve its VMDK occurrences.
    /// Records, indexes and pack maps are authenticated here; backing bytes
    /// are hashed by the caller's admitted VMDK plan verification.
    pub async fn launch_lower(&self, lower: &OverlayLower) -> Result<LaunchLower, LibVmError> {
        let store = self.clone();
        let lower = lower.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                let id = lower.record();
                let occurrences = store.retained_layers(id).await?;
                let owner = store.begin_consumer(&occurrences, &[id]).await?;
                let pool = existing_pool(&store.store)?;
                let retained = read_retained(&store.store, &pool, id).await?;
                retained.check_lower(&lower)?;
                let mut resolved = Vec::with_capacity(retained.layers.len() + 1);
                let fsmeta = pool
                    .lower_object_occurrence(&retained.fsmeta())
                    .map_err(self::retained(id))?;
                if fsmeta.length() != retained.result.fsmeta.length {
                    return Err(invalid("retained fsmeta length contradicts its result"));
                }
                resolved.push(fsmeta);
                let mut pinned: Vec<(LayerResultId, PinnedLayer)> = Vec::new();
                for (layer, range) in retained.layers.iter().zip(&retained.result.packs) {
                    let pack = match pinned.iter().find(|(other, _)| other == layer) {
                        Some((_, pinned)) => pinned.pack.clone(),
                        None => {
                            let layer_facts = store
                                .load_pinned_layer(*layer, &ChangesetLimits::default(), false)
                                .await?;
                            let pack = layer_facts.pack.clone();
                            pinned.push((*layer, layer_facts));
                            pack
                        }
                    };
                    if pack.stream.as_bytes() != range.stream.as_bytes()
                        || pack.length != range.length
                    {
                        return Err(invalid("layer pack contradicts its composition range"));
                    }
                    let occurrence = pool
                        .lower_occurrence(&pack.stream)
                        .map_err(self::retained(id))?;
                    resolved.push(occurrence);
                }
                Ok(LaunchLower {
                    occurrences: resolved,
                    retained,
                    _owner: owner,
                })
            })
        })
        .await?
    }

    /// Read the explicit closed graph without creating catalog state. The caller
    /// must retain its existing machine, capture, or consumer root throughout
    /// this observation. Pack streams are described from retained maps; no pack
    /// byte is read.
    pub async fn snapshot_composition(
        &self,
        id: LowerResultId,
    ) -> Result<SnapshotComposition, LibVmError> {
        let store = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                let pool = existing_pool(&store.store)?;
                let retained = read_retained(&store.store, &pool, id).await?;
                let mut unique: Vec<(LayerResultId, PinnedLayer)> = Vec::new();
                let mut layers = Vec::with_capacity(retained.layers.len());
                for layer in &retained.layers {
                    let index = match unique.iter().position(|(other, _)| other == layer) {
                        Some(index) => index,
                        None => {
                            unique.push((
                                *layer,
                                store
                                    .load_pinned_layer(*layer, &ChangesetLimits::default(), false)
                                    .await?,
                            ));
                            unique.len() - 1
                        }
                    };
                    let (_, pinned) = &unique[index];
                    layers.push(SnapshotLayer {
                        recipe: pinned.recipe_digest,
                        result: pinned.result_digest,
                        index_root: pinned.index_root,
                        index_pages: pinned.index_pages.clone(),
                        pack: pinned.pack.clone(),
                    });
                }
                let graph = SnapshotComposition {
                    result: id,
                    record: retained.record_digest,
                    recipe: retained.recipe_digest,
                    fsmeta: retained.fsmeta(),
                    layers,
                };
                graph.validate_shape()?;
                Ok(graph)
            })
        })
        .await?
    }

    /// Register a received or restored exact graph. Every object (including
    /// fsmeta and pack map pages) and every pack stream must already be in
    /// the pool, pinned by `operation`. The graph, fsmeta structure, pack
    /// bytes and logical lower identity are authenticated before any row is
    /// inserted; the lower is then pinned to `operation`. Idempotent.
    pub async fn publish_snapshot_composition(
        &self,
        operation: uuid::Uuid,
        lower: &SnapshotComposition,
    ) -> Result<LowerResultId, LibVmError> {
        let store = self.clone();
        let lower = lower.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.publish_snapshot_composition_owned(operation, lower))
        })
        .await?
    }

    async fn publish_snapshot_composition_owned(
        &self,
        operation: uuid::Uuid,
        lower: SnapshotComposition,
    ) -> Result<LowerResultId, LibVmError> {
        let store = &self.store;
        let pool = existing_pool(store)?;
        let id = lower.result;
        let authenticated = lower.authenticate(|digest, maximum| {
            pool.read_object(digest, maximum).map_err(retained(id))
        })?;
        // One held descriptor per unique pack; repeats share it, so the
        // descriptor peak is bounded by unique layers, not occurrences.
        let mut packs: Vec<(crate::store::models::snapshot::SnapshotStream, File)> = Vec::new();
        let mut slots = Vec::with_capacity(lower.layers.len());
        let mut layer_ids = Vec::with_capacity(lower.layers.len());
        for (layer, facts) in lower.layers.iter().zip(&authenticated.layers) {
            layer_ids.push(facts.result.id()?);
            if let Some(slot) = packs
                .iter()
                .position(|(stream, _)| stream.stream == layer.pack.stream)
            {
                if packs[slot].0 != layer.pack {
                    return Err(invalid("one pack stream has conflicting map descriptions"));
                }
                slots.push(slot);
                continue;
            }
            let map_root = crate::storage::map::StreamMapRoot::decode(
                &pool
                    .read_object(
                        &layer.pack.map,
                        crate::storage::limits::Resource::MetadataPageBytes.maximum(),
                    )
                    .map_err(retained(id))?,
            )?;
            if map_root.stream != layer.pack.stream
                || map_root.length != layer.pack.length
                || map_root.pages != layer.pack.map_pages
            {
                return Err(invalid("pack map root contradicts its snapshot stream"));
            }
            map_root.read_map(&pool).map_err(retained(id))?;
            slots.push(packs.len());
            packs.push((
                layer.pack.clone(),
                pool.open_stream(&layer.pack.stream).map_err(retained(id))?,
            ));
        }
        let refs = authenticated
            .layers
            .iter()
            .zip(&slots)
            .filter_map(|(layer, slot)| {
                packs.get(*slot).map(|(_, pack)| oci::erofs::Layer {
                    result: &layer.result,
                    changeset: &layer.changeset,
                    pack,
                })
            })
            .collect::<Vec<_>>();
        let fsmeta = pool.open_object(&lower.fsmeta).map_err(retained(id))?;
        let loaded = crate::storage::composition::load_exact(
            &authenticated.recipe,
            &refs,
            &authenticated.result,
            &fsmeta,
        )?;
        if loaded.result != authenticated.result {
            return Err(invalid("received composition failed exact loading"));
        }
        drop(refs);
        let mut committed = BTreeSet::new();
        for ((layer, facts), id) in lower
            .layers
            .iter()
            .zip(&authenticated.layers)
            .zip(&layer_ids)
        {
            if !committed.insert(*id) {
                continue;
            }
            let recipe_bytes = oci::changeset::LayerRecipe {
                diff_id: facts.changeset.diff_id,
            }
            .canonical_bytes()?;
            let result_bytes = facts.result.canonical_bytes()?;
            let mut dependencies =
                BTreeSet::from([layer.recipe, layer.result, layer.index_root, layer.pack.map]);
            dependencies.extend(layer.index_pages.iter().copied());
            dependencies.extend(layer.pack.map_pages.iter().copied());
            self.commit_layer(&crate::store::layer_store::PublicationFacts {
                retained: crate::store::layer_store::RetainedLayer {
                    id: *id,
                    recipe: facts.result.recipe,
                    pack_stream: layer.pack.stream,
                    pack_length: layer.pack.length,
                    pack_map: layer.pack.map,
                    index_root: facts.result.index_root,
                },
                diff_id: facts.changeset.diff_id,
                recipe_digest: ObjectDigest::of_bytes(&recipe_bytes),
                result_digest: ObjectDigest::of_bytes(&result_bytes),
                recipe_bytes,
                result_bytes,
                dependencies,
            })
            .await?;
        }
        let retained = RetainedComposition {
            id,
            recipe: authenticated.recipe,
            result: authenticated.result,
            recipe_digest: lower.recipe,
            record_digest: lower.record,
            layers: layer_ids,
        };
        commit_composition(store, &pool, operation, &retained).await?;
        Ok(id)
    }
}

/// Exact recomposition against an already authenticated expected graph.
/// `layers` are the caller's held, stream-authenticated occurrences whose
/// results equal the expected layer records. The regenerated fsmeta is
/// published only if it reproduces the expected result byte for byte.
pub(crate) async fn publish_regenerated(
    store: &Store,
    operation: uuid::Uuid,
    expected: &SnapshotComposition,
    authenticated: crate::store::models::snapshot::AuthenticatedComposition,
    layers: &[oci::erofs::Layer<'_>],
) -> Result<LowerResultId, LibVmError> {
    let pool = existing_pool(store)?;
    let (object, roots, regenerated) = pool.publish_produced_object_for_catalog(|file| {
        crate::storage::composition::regenerate_exact(
            &authenticated.recipe,
            layers,
            &authenticated.result,
            file,
        )
    })?;
    store
        .pin_published_storage_dependencies(operation, &[], &[object.digest])
        .await?;
    drop(roots);
    if object.digest != expected.fsmeta || regenerated.result != authenticated.result {
        return Err(invalid(
            "regenerated fsmeta differs from the expected result",
        ));
    }
    let layer_store = LayerStore::from_store(store.clone());
    layer_store
        .publish_snapshot_composition_owned(operation, expected.clone())
        .await
}

impl Store {
    /// DB-only pin of retained compositions to an active staging operation.
    pub(crate) async fn pin_operation_lowers(
        &self,
        operation: uuid::Uuid,
        lowers: &[LowerResultId],
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND state='staging')",
        )
        .bind(operation.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if !active {
            return Err(invalid("lower pin has no active registered operation"));
        }
        for lower in lowers {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM composition_result WHERE id=?1)")
                    .bind(lower.to_string())
                    .fetch_one(&mut *tx)
                    .await?;
            if !exists {
                return Err(LibVmError::CompositionAcquisitionRequired {
                    lower: *lower,
                    missing: "retained composition record".into(),
                });
            }
            sqlx::query("INSERT OR IGNORE INTO storage_operation_lower(operation_id,lower_id) VALUES(?1,?2)")
                .bind(operation.to_string()).bind(lower.to_string()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

/// Authenticate every retained composition row outside root coordination.
pub(crate) async fn check_composition_catalog(store: &Store) -> Result<(), LibVmError> {
    let pool = existing_pool(store)?;
    let mut cursor = String::new();
    loop {
        let ids = sqlx::query_scalar::<_, String>(
            "SELECT id FROM composition_result WHERE id>?1 ORDER BY id LIMIT 256",
        )
        .bind(&cursor)
        .fetch_all(&store.pool)
        .await?;
        if ids.is_empty() {
            return Ok(());
        }
        for id in ids {
            cursor.clone_from(&id);
            read_retained(store, &pool, id.parse().map_err(invalid)?).await?;
        }
    }
}

/// Retire composition rows that no machine, image cache entry or operation
/// roots. Their layers, fsmeta and record objects then become ordinary GC
/// candidates unless a snapshot or image closure still references them.
pub(crate) async fn retire_compositions(
    store: &Store,
    pool: &StoragePool,
) -> Result<(), LibVmError> {
    let mut cursor = String::new();
    loop {
        let ids = sqlx::query_scalar::<_, String>(
            "SELECT id FROM composition_result WHERE id>?1 ORDER BY id LIMIT 256",
        )
        .bind(&cursor)
        .fetch_all(&store.pool)
        .await?;
        if ids.is_empty() {
            break;
        }
        let _roots = pool.lock_roots()?;
        let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
        for id in ids {
            cursor.clone_from(&id);
            sqlx::query("DELETE FROM composition_result WHERE id=?1 AND NOT EXISTS(SELECT 1 FROM machine_lower_dependency WHERE lower_id=?1) AND NOT EXISTS(SELECT 1 FROM storage_operation_lower WHERE lower_id=?1) AND NOT EXISTS(SELECT 1 FROM image_composition_artifact WHERE lower_id=?1)")
                .bind(&id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
    }
    let _roots = pool.lock_roots()?;
    sqlx::query("DELETE FROM composition_recipe WHERE NOT EXISTS(SELECT 1 FROM composition_result r WHERE r.recipe_id=composition_recipe.id)")
        .execute(&store.pool)
        .await?;
    Ok(())
}
