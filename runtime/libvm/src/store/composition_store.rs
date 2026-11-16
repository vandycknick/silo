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
//! The concatenated lower is never materialized. Local validation receipts
//! bind canonical records to held immutable inodes. Receipt misses and all
//! transport admission authenticate the exact retained bytes. Failed validation
//! preserves existing receipts; changed fingerprints keep them unusable until
//! successful authentication replaces them.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use oci::changeset::{ChangesetLimits, LayerResultId};
use oci::composition::{CompositionRecipe, CompositionResult, MAX_RECORD_BYTES};
use sqlx::Row;
use vm_spec::DiskGeometry;

use crate::storage::composition::CompositionValidation;
use crate::storage::identity::{LowerResultId, ObjectDigest};
use crate::storage::pool::StoragePool;
use crate::storage::vmdk::{LowerBacking, LowerOccurrence};
use crate::storage::StorageError;
use crate::store::layer_store::{LayerReadOwner, LayerStore, PinnedLayer};
use crate::store::models::snapshot::{content_object, SnapshotComposition, SnapshotLayer};
use crate::store::Store;
use crate::{LibVmError, OverlayLower};

type HeldLayer = (PinnedLayer, Arc<File>);

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
    unique: Vec<HeldLayer>,
    occurrences: Vec<usize>,
    fsmeta: File,
    validation: CompositionValidation,
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

    pub(crate) fn recheck(&self) -> Result<(), LibVmError> {
        let current = CompositionValidation::capture(
            &self.retained.recipe,
            &self.retained.result,
            &self.layers(),
            &self.fsmeta,
        )?;
        if current != self.validation {
            return Err(invalid("held composition changed after validation"));
        }
        Ok(())
    }

    pub fn snapshot_composition(&self) -> Result<SnapshotComposition, LibVmError> {
        self.recheck()?;
        snapshot_graph(&self.retained, &self.unique, &self.occurrences)
    }
}

/// Resolved VMDK occurrences. Launch callers retain their generation lease
/// through startup; non-launch readers retain an independent consumer here.
pub struct LaunchLower {
    pub occurrences: Vec<LowerOccurrence>,
    pub retained: RetainedComposition,
    pub(crate) validation: CompositionValidation,
    graph: SnapshotComposition,
    unique: Vec<(crate::store::models::snapshot::SnapshotStream, Arc<File>)>,
    fsmeta: File,
    metadata: Vec<(
        ObjectDigest,
        File,
        crate::storage::identity_file::SourceFingerprint,
    )>,
    pub(crate) maps: std::collections::BTreeMap<
        crate::storage::identity::StreamId,
        Arc<crate::storage::stream::StreamMap>,
    >,
    _authority: LowerAuthority,
}

enum LowerAuthority {
    Launch,
    Consumer { _owner: LayerReadOwner },
    ExistingRoot,
}

impl LaunchLower {
    pub(crate) fn held_backing(
        &self,
        backing: LowerBacking,
    ) -> Result<(File, crate::storage::identity_file::SourceFingerprint), LibVmError> {
        let file = match backing {
            LowerBacking::Object(_) => &self.fsmeta,
            LowerBacking::Stream(id) => {
                &self
                    .unique
                    .iter()
                    .find(|(stream, _)| stream.stream == id)
                    .ok_or_else(|| invalid("pack is outside the held composition"))?
                    .1
            }
        };
        Ok((
            file.try_clone()?,
            self.validation.check_file(backing, file)?,
        ))
    }

    pub(crate) fn snapshot_composition(&self) -> &SnapshotComposition {
        &self.graph
    }

    pub(crate) fn metadata_states(
        &self,
    ) -> impl Iterator<
        Item = (
            ObjectDigest,
            crate::storage::identity_file::SourceFingerprint,
        ),
    > + '_ {
        self.metadata
            .iter()
            .map(|(digest, _, fingerprint)| (*digest, *fingerprint))
    }

    pub(crate) fn retained_descriptors(&self) -> u64 {
        (self.metadata.len() + self.unique.len() + 1) as u64
    }

    pub(crate) fn recheck(&self) -> Result<(), LibVmError> {
        self.validation
            .check_records(&self.retained.recipe, &self.retained.result)?;
        self.validation
            .check_file(LowerBacking::Object(self.retained.fsmeta()), &self.fsmeta)?;
        for (stream, file) in &self.unique {
            self.validation
                .check_file(LowerBacking::Stream(stream.stream), file)?;
        }
        for (_, file, expected) in &self.metadata {
            if crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?) != *expected
            {
                return Err(invalid("composition metadata changed after validation"));
            }
        }
        Ok(())
    }
}

fn snapshot_graph(
    retained: &RetainedComposition,
    unique: &[HeldLayer],
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
) -> Result<(Vec<HeldLayer>, Vec<usize>), LibVmError> {
    let mut ids: Vec<LayerResultId> = Vec::new();
    let mut unique = Vec::new();
    let mut mapping = Vec::with_capacity(occurrences.len());
    for id in occurrences {
        if let Some(index) = ids.iter().position(|other| other == id) {
            mapping.push(index);
            continue;
        }
        let pinned = layers.load_pinned_layer(*id, limits, false).await?;
        let pack = hold_pack(pool, &unique, &pinned)?;
        mapping.push(unique.len());
        ids.push(*id);
        unique.push((pinned, pack));
    }
    Ok((unique, mapping))
}

fn hold_pack(
    pool: &StoragePool,
    unique: &[HeldLayer],
    layer: &PinnedLayer,
) -> Result<Arc<File>, StorageError> {
    match unique
        .iter()
        .find(|(other, _)| other.pack.stream == layer.pack.stream)
    {
        Some((_, pack)) => Ok(Arc::clone(pack)),
        None => pool.open_stream(&layer.pack.stream).map(Arc::new),
    }
}

fn layer_refs<'a>(unique: &'a [HeldLayer], occurrences: &[usize]) -> Vec<oci::erofs::Layer<'a>> {
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

const COMPOSITION_VALIDATION_SCHEMA: i64 = 1;

async fn save_validation(
    store: &Store,
    id: LowerResultId,
    validation: &CompositionValidation,
) -> Result<(), LibVmError> {
    sqlx::query("INSERT INTO composition_validation(lower_id,schema,receipt) SELECT id,?2,?3 FROM composition_result WHERE id=?1 ON CONFLICT(lower_id,schema) DO UPDATE SET graph_receipt=CASE WHEN receipt=excluded.receipt THEN graph_receipt ELSE NULL END,receipt=excluded.receipt")
        .bind(id.to_string())
        .bind(COMPOSITION_VALIDATION_SCHEMA)
        .bind(serde_json::to_vec(validation).map_err(invalid)?)
        .execute(&store.pool).await?;
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphValidation {
    graph: SnapshotComposition,
    metadata: Vec<(
        ObjectDigest,
        crate::storage::identity_file::SourceFingerprint,
    )>,
    maps: Vec<(
        crate::storage::identity::StreamId,
        Vec<crate::storage::stream::Chunk>,
    )>,
}

fn graph_objects(graph: &SnapshotComposition) -> BTreeSet<ObjectDigest> {
    graph
        .objects()
        .chain(graph.layers.iter().flat_map(|layer| {
            std::iter::once(layer.pack.map).chain(layer.pack.map_pages.iter().copied())
        }))
        .collect()
}

async fn save_graph_validation(
    store: &Store,
    pool: &StoragePool,
    graph: &SnapshotComposition,
    validation: &CompositionValidation,
) -> Result<(), LibVmError> {
    crate::storage::limits::preflight_fd_budget(
        (graph_objects(graph).len() + graph.layers.len() + 2) as u64,
    )
    .map_err(StorageError::from)?;
    let mut held = Vec::new();
    for digest in graph_objects(graph) {
        let file = pool.open_object(&digest)?;
        let fingerprint = crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?);
        held.push((digest, file, fingerprint));
    }
    let authenticated =
        graph.authenticate(|digest, maximum| Ok(pool.read_object(digest, maximum)?))?;
    validation.check_records(&authenticated.recipe, &authenticated.result)?;
    let mut maps = std::collections::BTreeMap::new();
    for layer in &graph.layers {
        let root = crate::storage::map::StreamMapRoot::decode(&pool.read_object(
            &layer.pack.map,
            crate::storage::limits::Resource::MetadataPageBytes.maximum(),
        )?)?;
        if root.stream != layer.pack.stream
            || root.length != layer.pack.length
            || root.pages != layer.pack.map_pages
        {
            return Err(invalid("composition receipt map contradicts its graph"));
        }
        maps.insert(layer.pack.stream, root.read_map(pool)?.chunks().to_vec());
        validation.check_file(
            LowerBacking::Stream(layer.pack.stream),
            &pool.open_stream(&layer.pack.stream)?,
        )?;
    }
    validation.check_file(
        LowerBacking::Object(graph.fsmeta),
        &pool.open_object(&graph.fsmeta)?,
    )?;
    for (_, file, fingerprint) in &held {
        if crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?) != *fingerprint
        {
            return Err(invalid(
                "composition metadata changed during receipt creation",
            ));
        }
    }
    let receipt = GraphValidation {
        graph: graph.clone(),
        metadata: held
            .into_iter()
            .map(|(digest, _, fingerprint)| (digest, fingerprint))
            .collect(),
        maps: maps.into_iter().collect(),
    };
    sqlx::query("UPDATE composition_validation SET graph_receipt=?3 WHERE lower_id=?1 AND schema=?2 AND receipt=?4")
        .bind(graph.result.to_string()).bind(COMPOSITION_VALIDATION_SCHEMA)
        .bind(serde_json::to_vec(&receipt).map_err(invalid)?)
        .bind(serde_json::to_vec(validation).map_err(invalid)?)
        .execute(&store.pool).await?;
    Ok(())
}

async fn load_graph_validation(
    store: &Store,
    pool: &StoragePool,
    retained: &RetainedComposition,
    authority: &mut Option<LowerAuthority>,
) -> Result<Option<LaunchLower>, LibVmError> {
    let row = sqlx::query(
        "SELECT receipt,graph_receipt FROM composition_validation WHERE lower_id=?1 AND schema=?2",
    )
    .bind(retained.id.to_string())
    .bind(COMPOSITION_VALIDATION_SCHEMA)
    .fetch_optional(&store.pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let validation =
        serde_json::from_slice::<CompositionValidation>(&row.try_get::<Vec<u8>, _>("receipt")?);
    let graph = row
        .try_get::<Option<Vec<u8>>, _>("graph_receipt")?
        .and_then(|bytes| serde_json::from_slice::<GraphValidation>(&bytes).ok());
    let (Ok(validation), Some(receipt)) = (validation, graph) else {
        return Ok(None);
    };
    if validation
        .check_records(&retained.recipe, &retained.result)
        .is_err()
    {
        return Ok(None);
    }
    let graph = receipt.graph;
    if graph.result != retained.id
        || graph.recipe != retained.recipe_digest
        || graph.record != retained.record_digest
        || graph.fsmeta != retained.fsmeta()
        || graph.layers.len() != retained.layers.len()
    {
        return Ok(None);
    }
    let rows = sqlx::query("SELECT c.position,c.layer_result_id,r.recipe_id,r.pack_stream,r.pack_length,r.pack_map,r.index_root,r.record_digest,r.record_bytes,p.diff_id,p.record_digest AS recipe_digest,p.record_bytes AS recipe_bytes FROM composition_layer c JOIN layer_result r ON r.id=c.layer_result_id JOIN layer_recipe p ON p.id=r.recipe_id WHERE c.result_id=?1 ORDER BY c.position")
        .bind(retained.id.to_string()).fetch_all(&store.pool).await?;
    if rows.len() != graph.layers.len() {
        return Ok(None);
    }
    for (index, (row, layer)) in rows.iter().zip(&graph.layers).enumerate() {
        let binding = &retained.recipe.layers[index];
        let recipe_bytes = row.try_get::<Vec<u8>, _>("recipe_bytes")?;
        let recipe = oci::changeset::LayerRecipe {
            diff_id: crate::store::models::snapshot::decode_layer_recipe(&recipe_bytes)?,
        };
        if row.try_get::<String, _>("recipe_id")? != recipe.id()?.to_string()
            || row.try_get::<String, _>("diff_id")? != recipe.diff_id.to_string()
        {
            return Ok(None);
        }
        if row.try_get::<i64, _>("position")? != int(index as u64)?
            || row.try_get::<String, _>("layer_result_id")? != retained.layers[index].to_string()
            || row.try_get::<String, _>("record_digest")? != layer.result.to_string()
            || row.try_get::<String, _>("recipe_digest")? != layer.recipe.to_string()
            || ObjectDigest::of_bytes(&row.try_get::<Vec<u8>, _>("record_bytes")?) != layer.result
            || ObjectDigest::of_bytes(&recipe_bytes) != layer.recipe
            || row.try_get::<String, _>("pack_stream")? != layer.pack.stream.to_string()
            || row.try_get::<i64, _>("pack_length")? != int(layer.pack.length)?
            || row.try_get::<String, _>("pack_map")? != layer.pack.map.to_string()
            || row.try_get::<String, _>("index_root")? != binding.index_root.to_string()
            || content_object(binding.index_root)? != layer.index_root
        {
            return Ok(None);
        }
    }
    let dependencies = sqlx::query("SELECT DISTINCT d.result_id,d.object_digest FROM layer_object_dependency d JOIN composition_layer c ON c.layer_result_id=d.result_id WHERE c.result_id=?1")
        .bind(retained.id.to_string()).fetch_all(&store.pool).await?;
    let actual = dependencies
        .iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("result_id")?,
                row.try_get::<String, _>("object_digest")?,
            ))
        })
        .collect::<Result<BTreeSet<_>, sqlx::Error>>()?;
    let mut expected_dependencies = BTreeSet::new();
    for (id, layer) in retained.layers.iter().zip(&graph.layers) {
        for digest in [layer.recipe, layer.result, layer.index_root, layer.pack.map]
            .into_iter()
            .chain(layer.index_pages.iter().copied())
            .chain(layer.pack.map_pages.iter().copied())
        {
            expected_dependencies.insert((id.to_string(), digest.to_string()));
        }
    }
    if actual != expected_dependencies {
        return Ok(None);
    }
    let mut maps = std::collections::BTreeMap::new();
    for (id, chunks) in receipt.maps {
        let Some(layer) = graph.layers.iter().find(|layer| layer.pack.stream == id) else {
            return Ok(None);
        };
        let map =
            crate::storage::stream::StreamMap::from_validated_parts(layer.pack.length, chunks, id)?;
        if maps.insert(id, Arc::new(map)).is_some() {
            return Ok(None);
        }
    }
    if maps.len()
        != graph
            .layers
            .iter()
            .map(|layer| layer.pack.stream)
            .collect::<BTreeSet<_>>()
            .len()
    {
        return Ok(None);
    }
    let expected = graph_objects(&graph);
    if receipt
        .metadata
        .iter()
        .map(|(digest, _)| *digest)
        .collect::<BTreeSet<_>>()
        != expected
        || receipt.metadata.len() != expected.len()
    {
        return Ok(None);
    }
    crate::storage::limits::preflight_fd_budget((expected.len() + graph.layers.len() + 1) as u64)
        .map_err(StorageError::from)?;
    let mut metadata = Vec::with_capacity(expected.len());
    for (digest, expected) in receipt.metadata {
        let file = pool.open_object(&digest)?;
        if crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?) != expected {
            return Ok(None);
        }
        metadata.push((digest, file, expected));
    }
    let fsmeta = pool.open_object(&graph.fsmeta)?;
    if validation
        .check_file(LowerBacking::Object(graph.fsmeta), &fsmeta)
        .is_err()
    {
        return Ok(None);
    }
    let mut unique: Vec<(crate::store::models::snapshot::SnapshotStream, Arc<File>)> = Vec::new();
    let mut occurrences = vec![pool.lower_object_occurrence(&graph.fsmeta)?];
    for layer in &graph.layers {
        if !unique
            .iter()
            .any(|(stream, _)| stream.stream == layer.pack.stream)
        {
            let file = pool.open_stream(&layer.pack.stream)?;
            if validation
                .check_file(LowerBacking::Stream(layer.pack.stream), &file)
                .is_err()
            {
                return Ok(None);
            }
            unique.push((layer.pack.clone(), Arc::new(file)));
        }
        occurrences.push(pool.lower_occurrence(&layer.pack.stream)?);
    }
    let lower = LaunchLower {
        occurrences,
        retained: retained.clone(),
        validation,
        graph,
        unique,
        fsmeta,
        metadata,
        maps,
        _authority: authority
            .take()
            .ok_or_else(|| invalid("composition receipt has no retention authority"))?,
    };
    lower.recheck()?;
    Ok(Some(lower))
}

/// All byte work runs with held descriptors and leases, outside SQL/root locks.
async fn validate_composition(
    store: &Store,
    id: LowerResultId,
    recipe: &CompositionRecipe,
    result: &CompositionResult,
    layers: &[oci::erofs::Layer<'_>],
    fsmeta: &File,
    local: bool,
) -> Result<CompositionValidation, LibVmError> {
    let before = CompositionValidation::capture(recipe, result, layers, fsmeta)?;
    let receipt: Option<Vec<u8>> = if local {
        sqlx::query_scalar(
            "SELECT receipt FROM composition_validation WHERE lower_id=?1 AND schema=?2",
        )
        .bind(id.to_string())
        .bind(COMPOSITION_VALIDATION_SCHEMA)
        .fetch_optional(&store.pool)
        .await?
    } else {
        None
    };
    let hit = receipt
        .as_deref()
        .and_then(|bytes| serde_json::from_slice::<CompositionValidation>(bytes).ok())
        .is_some_and(|previous| previous == before);
    if !hit {
        let loaded = crate::storage::composition::load_exact(recipe, layers, result, fsmeta)?;
        if loaded.result != *result {
            return Err(invalid("retained composition failed exact loading"));
        }
    }
    if CompositionValidation::capture(recipe, result, layers, fsmeta)? != before {
        return Err(invalid("composition input changed during validation"));
    }
    if !hit {
        save_validation(store, id, &before).await?;
    }
    Ok(before)
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
        let (retained, fsmeta, validation) = match existing {
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
                let validation = validate_composition(
                    store,
                    id,
                    &recipe,
                    &retained.result,
                    &layers,
                    &fsmeta,
                    true,
                )
                .await?;
                (retained, fsmeta, validation)
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
                let fsmeta = pool.open_object(&object.digest)?;
                let validation = composed.published_validation(&recipe, &layers, &fsmeta)?;
                if crate::storage::identity_file::SourceFingerprint::new(&fsmeta.metadata()?)
                    != object.fingerprint
                {
                    return Err(invalid(
                        "published fsmeta inode changed before receipt seeding",
                    ));
                }
                validation.check_file(LowerBacking::Object(object.digest), &fsmeta)?;
                let retained = RetainedComposition {
                    id: LowerResultId::from_composition(composed.result.id().map_err(invalid)?),
                    recipe: recipe.clone(),
                    result: composed.result,
                    recipe_digest,
                    record_digest,
                    layers: occurrences.clone(),
                };
                commit_composition(store, &pool, owner.operation, &retained).await?;
                save_validation(store, retained.id, &validation).await?;
                (retained, fsmeta, validation)
            }
        };
        drop(layers);
        if load_graph_validation(
            store,
            &pool,
            &retained,
            &mut Some(LowerAuthority::ExistingRoot),
        )
        .await?
        .is_none()
        {
            save_graph_validation(
                store,
                &pool,
                &snapshot_graph(&retained, &unique, &mapping)?,
                &validation,
            )
            .await?;
        }
        Ok(HeldComposition {
            retained,
            unique,
            occurrences: mapping,
            fsmeta,
            validation,
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

    /// Lease an exact retained composition. Local receipts avoid payload reads;
    /// a miss authenticates every byte without invoking an encoder or OCI source.
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
                let validation = validate_composition(
                    &store.store,
                    id,
                    &retained.recipe,
                    &retained.result,
                    &layer_refs(&unique, &mapping),
                    &fsmeta,
                    true,
                )
                .await?;
                if load_graph_validation(
                    &store.store,
                    &pool,
                    &retained,
                    &mut Some(LowerAuthority::ExistingRoot),
                )
                .await?
                .is_none()
                {
                    save_graph_validation(
                        &store.store,
                        &pool,
                        &snapshot_graph(&retained, &unique, &mapping)?,
                        &validation,
                    )
                    .await?;
                }
                Ok(HeldComposition {
                    retained,
                    unique,
                    occurrences: mapping,
                    fsmeta,
                    validation,
                    _owner: owner,
                })
            })
        })
        .await?
    }

    /// Resolve a lower authorized by the exact existing launch generation.
    /// Canonical metadata and held inode validation precede descriptor handoff.
    pub(crate) async fn launch_lower(
        &self,
        lease: &crate::store::operation_store::LaunchStorageLease,
        storage: &crate::MachineStorageRecord,
    ) -> Result<LaunchLower, LibVmError> {
        if lease.storage_record() != storage {
            return Err(invalid(
                "launch lower differs from the leased storage generation",
            ));
        }
        let crate::MachineRoot::LinuxOverlay { lower, .. } = &storage.root else {
            return Err(invalid(
                "launch lower requires a layered storage generation",
            ));
        };
        let store = self.clone();
        let lower = lower.clone();
        let operation = lease.operation_id();
        let generation = int(lease.storage_record().storage_generation)?;
        let data_disks = storage.disks.len() as u64;
        let lease = lease.lock().duplicate()?;
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                let id = lower.record();
                let (device, inode) = lease.file_identity()?;
                let authorized: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM storage_operation o JOIN storage_operation_lower l USING(operation_id) WHERE o.operation_id=?1 AND o.kind='launch' AND o.storage_generation=?2 AND o.file_device=?3 AND o.file_inode=?4 AND l.lower_id=?5)",
                )
                .bind(operation.to_string())
                .bind(generation)
                .bind(device.to_string())
                .bind(inode.to_string())
                .bind(id.to_string())
                .fetch_one(&store.store.pool)
                .await?;
                if !authorized {
                    return Err(invalid("launch lease does not root this retained lower"));
                }
                let resolved = store.resolve_lower(&lower, LowerAuthority::Launch, data_disks).await;
                // Cancellation may drop the caller's typed lease while this
                // blocking worker runs. Keep its duplicate until authentication
                // completes, but do not obstruct failed-start reconciliation.
                drop(lease);
                resolved
            })
        })
        .await?
    }

    /// Non-launch readers (capture budgeting and cut verification) own an
    /// independent consumer, rather than borrowing a running generation.
    pub(crate) async fn hold_lower(&self, lower: &OverlayLower) -> Result<LaunchLower, LibVmError> {
        let store = self.clone();
        let lower = lower.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                let occurrences = store.retained_layers(lower.record()).await?;
                let owner = store
                    .begin_consumer(&occurrences, &[lower.record()])
                    .await?;
                store
                    .resolve_lower(&lower, LowerAuthority::Consumer { _owner: owner }, 0)
                    .await
            })
        })
        .await?
    }

    async fn resolve_lower(
        &self,
        lower: &OverlayLower,
        authority: LowerAuthority,
        data_disks: u64,
    ) -> Result<LaunchLower, LibVmError> {
        let id = lower.record();
        let pool = existing_pool(&self.store)?;
        let retained = read_retained(&self.store, &pool, id).await?;
        retained.check_lower(lower)?;
        let mut authority = Some(authority);
        if let Some(resolved) =
            load_graph_validation(&self.store, &pool, &retained, &mut authority).await?
        {
            crate::storage::vmdk::FlatLowerPlan::new(&resolved.occurrences)?
                .preflight(data_disks)?;
            return Ok(resolved);
        }
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
                    let layer_facts = self
                        .load_pinned_layer(*layer, &ChangesetLimits::default(), false)
                        .await?;
                    let pack = layer_facts.pack.clone();
                    pinned.push((*layer, layer_facts));
                    pack
                }
            };
            if pack.stream.as_bytes() != range.stream.as_bytes() || pack.length != range.length {
                return Err(invalid("layer pack contradicts its composition range"));
            }
            let occurrence = pool
                .lower_occurrence(&pack.stream)
                .map_err(self::retained(id))?;
            resolved.push(occurrence);
        }
        crate::storage::vmdk::FlatLowerPlan::new(&resolved)?.preflight(data_disks)?;
        let mapping = retained
            .layers
            .iter()
            .map(|id| {
                pinned
                    .iter()
                    .position(|(other, _)| other == id)
                    .ok_or_else(|| invalid("resolved composition lost a layer occurrence"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut unique = Vec::with_capacity(pinned.len());
        for (_, layer) in pinned {
            let file = hold_pack(&pool, &unique, &layer).map_err(self::retained(id))?;
            unique.push((layer, file));
        }
        let fsmeta = pool
            .open_object(&retained.fsmeta())
            .map_err(self::retained(id))?;
        let validation = validate_composition(
            &self.store,
            id,
            &retained.recipe,
            &retained.result,
            &layer_refs(&unique, &mapping),
            &fsmeta,
            true,
        )
        .await?;
        let graph = snapshot_graph(&retained, &unique, &mapping)?;
        save_graph_validation(&self.store, &pool, &graph, &validation).await?;
        load_graph_validation(&self.store, &pool, &retained, &mut authority)
            .await?
            .ok_or_else(|| invalid("newly validated composition lost its receipt"))
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
                if let Some(held) = load_graph_validation(
                    &store.store,
                    &pool,
                    &retained,
                    &mut Some(LowerAuthority::ExistingRoot),
                )
                .await?
                {
                    return Ok(held.graph);
                }
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
            runtime.block_on(store.publish_snapshot_composition_owned(operation, lower, false))
        })
        .await?
    }

    /// Same-host reuse only. Imported metadata can never supply a receipt.
    pub(crate) async fn publish_local_composition(
        &self,
        operation: uuid::Uuid,
        lower: &SnapshotComposition,
    ) -> Result<LowerResultId, LibVmError> {
        let store = self.clone();
        let lower = lower.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.publish_snapshot_composition_owned(operation, lower, true))
        })
        .await?
    }

    async fn publish_snapshot_composition_owned(
        &self,
        operation: uuid::Uuid,
        lower: SnapshotComposition,
        local: bool,
    ) -> Result<LowerResultId, LibVmError> {
        let store = &self.store;
        let pool = existing_pool(store)?;
        let id = lower.result;
        if local {
            let cached: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM composition_validation WHERE lower_id=?1 AND schema=?2 AND graph_receipt IS NOT NULL)")
                .bind(id.to_string()).bind(COMPOSITION_VALIDATION_SCHEMA).fetch_one(&store.pool).await?;
            if cached {
                let retained = read_retained(store, &pool, id).await?;
                if let Some(held) = load_graph_validation(
                    store,
                    &pool,
                    &retained,
                    &mut Some(LowerAuthority::ExistingRoot),
                )
                .await?
                {
                    if held.graph != lower {
                        return Err(invalid(
                            "local composition graph differs from its validation receipt",
                        ));
                    }
                    store.pin_operation_lowers(operation, &[id]).await?;
                    held.recheck()?;
                    return Ok(id);
                }
            }
        }
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
        let validation = validate_composition(
            store,
            id,
            &authenticated.recipe,
            &authenticated.result,
            &refs,
            &fsmeta,
            local,
        )
        .await?;
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
        save_validation(store, id, &validation).await?;
        save_graph_validation(store, &pool, &lower, &validation).await?;
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
        .publish_snapshot_composition_owned(operation, expected.clone(), false)
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

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs::File;
    use std::fs::{FileTimes, OpenOptions, Permissions};
    use std::os::unix::fs::{FileExt, PermissionsExt};
    use std::path::Path;

    use oci::changeset::{ChangesetLimits, ContentDigest, LayerInput};

    use crate::paths::LocalPaths;
    use crate::storage::pool::StoragePool;
    use crate::store::composition_store::HeldComposition;
    use crate::store::layer_store::LayerStore;
    use crate::store::Store;

    async fn fixture() -> (tempfile::TempDir, LocalPaths, Store, HeldComposition) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path().join("home"));
        let store = Store::new(&paths).await.unwrap();
        let first =
            crate::store::storage::tests::retained_lower(&store, temporary.path(), b'A').await;
        let layers = LayerStore::from_store(store.clone());
        let second = layers
            .publish(
                crate::store::layer_store::tests::staged_byte(temporary.path(), &layers, b'B'),
                &ChangesetLimits::default(),
            )
            .await
            .unwrap();
        let empty_path = temporary.path().join("empty.tar");
        let empty_bytes = [0u8; 1024];
        std::fs::write(&empty_path, empty_bytes).unwrap();
        let digest = ContentDigest::of_bytes(&empty_bytes);
        let staged = oci::changeset::ingest_layer(
            &empty_path,
            &LayerInput {
                blob_digest: digest,
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                size_bytes: empty_bytes.len() as u64,
                diff_id: digest,
            },
            paths.images_dir(),
            &oci::StagingOperation::try_from(uuid::Uuid::new_v4().to_string()).unwrap(),
            &ChangesetLimits::default(),
        )
        .unwrap();
        let empty = layers
            .publish(staged, &ChangesetLimits::default())
            .await
            .unwrap();
        let first_id = first.retained.layers[0];
        let held = layers
            .compose_retained(
                oci::Platform::host().unwrap(),
                &[first_id, empty.id, second.id, first_id, empty.id],
                &ChangesetLimits::default(),
            )
            .await
            .unwrap();
        (temporary, paths, store, held)
    }

    async fn receipt(store: &Store, held: &HeldComposition) -> Vec<u8> {
        sqlx::query_scalar(
            "SELECT receipt FROM composition_validation WHERE lower_id=?1 AND schema=1",
        )
        .bind(held.retained.id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
    }

    fn replace(path: &Path) {
        let bytes = std::fs::read(path).unwrap();
        let replacement = path.with_extension("replacement");
        std::fs::write(&replacement, bytes).unwrap();
        std::fs::set_permissions(&replacement, Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(replacement, path).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn watch(held: &HeldComposition, pool: &StoragePool) -> nix::sys::inotify::Inotify {
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        let events = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap();
        events
            .add_watch(
                &pool.object_path(&held.retained.fsmeta()),
                AddWatchFlags::IN_ACCESS,
            )
            .unwrap();
        for (layer, _) in &held.unique {
            events
                .add_watch(
                    &pool.stream_path(&layer.pack.stream),
                    AddWatchFlags::IN_ACCESS,
                )
                .unwrap();
        }
        events
    }

    #[cfg(target_os = "linux")]
    fn unread(events: &nix::sys::inotify::Inotify) {
        assert_eq!(events.read_events().unwrap_err(), nix::errno::Errno::EAGAIN);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn receipt_hits_skip_lower_bytes_across_create_restore_start_and_fork() {
        let (_temporary, paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        let id = held.retained.id;
        assert_eq!(held.layers().len(), 5);
        assert_eq!(held.unique.len(), 3);
        assert!(held.unique.iter().any(|(layer, _)| layer.pack.length == 0));
        assert!(!receipt(&store, &held).await.is_empty());
        let events = watch(&held, &pool);
        sqlx::query("DELETE FROM composition_validation WHERE lower_id=?1")
            .bind(id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let exact = layers.hold_composition(id).await.unwrap();
        assert!(!events.read_events().unwrap().is_empty());
        unread(&events);

        let reused = layers
            .compose_retained(
                held.retained.recipe.platform.clone(),
                &held.retained.layers,
                &ChangesetLimits::default(),
            )
            .await
            .unwrap();
        reused.recheck().unwrap();
        unread(&events);
        let graph = held.snapshot_composition().unwrap();
        layers
            .publish_local_composition(held._owner.operation, &graph)
            .await
            .unwrap();
        layers
            .hold_composition(id)
            .await
            .unwrap()
            .recheck()
            .unwrap();
        unread(&events);

        let (config, lease) =
            crate::store::storage::tests::leased_layered_machine(&store, &paths, &held).await;
        let launch = layers
            .launch_lower(&lease, lease.storage_record())
            .await
            .unwrap();
        let admitted = crate::storage::vmdk::FlatLowerPlan::new(&launch.occurrences)
            .unwrap()
            .preflight(0)
            .unwrap();
        let mut reordered = launch.occurrences.clone();
        reordered.swap(1, 2);
        assert!(crate::storage::vmdk::FlatLowerPlan::new(&reordered)
            .unwrap()
            .preflight(0)
            .unwrap()
            .verify_composition(&pool, &launch.validation)
            .is_err());
        admitted
            .verify_composition(&pool, &launch.validation)
            .unwrap();
        unread(&events);
        let fork = layers
            .hold_lower(&held.retained.overlay_lower())
            .await
            .unwrap();
        let configuration = crate::SnapshotConfiguration::capture(&config).unwrap();
        crate::machine::restore::verify_local_lower(
            &pool,
            lease.storage_record(),
            &configuration,
            Some(&fork),
        )
        .unwrap();
        unread(&events);

        // Imported/transported admission is unconditional even with a local receipt.
        layers
            .publish_snapshot_composition(held._owner.operation, &graph)
            .await
            .unwrap();
        assert!(!events.read_events().unwrap().is_empty());
        drop(exact);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn receipt_hit_works_with_descriptors_that_cannot_read_payloads() {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;

        let (_temporary, paths, store, mut held) = fixture().await;
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        held.fsmeta = File::from(
            open(
                &pool.object_path(&held.retained.fsmeta()),
                OFlag::O_PATH | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .unwrap(),
        );
        for (layer, file) in &mut held.unique {
            *file = std::sync::Arc::new(File::from(
                open(
                    &pool.stream_path(&layer.pack.stream),
                    OFlag::O_PATH | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .unwrap(),
            ));
        }
        held.recheck().unwrap();
        crate::store::composition_store::validate_composition(
            &store,
            held.retained.id,
            &held.retained.recipe,
            &held.retained.result,
            &held.layers(),
            &held.fsmeta,
            true,
        )
        .await
        .unwrap();
        sqlx::query("DELETE FROM composition_validation WHERE lower_id=?1")
            .bind(held.retained.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(crate::store::composition_store::validate_composition(
            &store,
            held.retained.id,
            &held.retained.recipe,
            &held.retained.result,
            &held.layers(),
            &held.fsmeta,
            true,
        )
        .await
        .is_err());
        LayerStore::from_store(store)
            .hold_composition(held.retained.id)
            .await
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn inode_replacement_and_chmod_reauthenticate_exact_bytes() {
        let (_temporary, paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        let pack = pool.stream_path(&held.unique[0].0.pack.stream);
        let original = receipt(&store, &held).await;
        replace(&pack);
        let events = watch(&held, &pool);
        let replaced = layers.hold_composition(held.retained.id).await.unwrap();
        assert!(!events.read_events().unwrap().is_empty());
        assert_ne!(receipt(&store, &held).await, original);
        assert!(held.recheck().is_err());
        replaced.recheck().unwrap();

        let original = receipt(&store, &replaced).await;
        std::fs::set_permissions(&pack, Permissions::from_mode(0o600)).unwrap();
        assert!(layers.hold_composition(held.retained.id).await.is_err());
        std::fs::set_permissions(&pack, Permissions::from_mode(0o400)).unwrap();
        let resealed = layers.hold_composition(held.retained.id).await.unwrap();
        assert_ne!(receipt(&store, &resealed).await, original);
        assert!(!events.read_events().unwrap().is_empty());

        let fsmeta = pool.object_path(&held.retained.fsmeta());
        let original = receipt(&store, &resealed).await;
        replace(&fsmeta);
        let events = watch(&resealed, &pool);
        let replaced = layers.hold_composition(held.retained.id).await.unwrap();
        assert!(!events.read_events().unwrap().is_empty());
        assert_ne!(receipt(&store, &replaced).await, original);
    }

    #[tokio::test]
    async fn refused_composition_preserves_receipts_without_authorizing_corrupt_retries() {
        let (_temporary, paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        let graph = held.snapshot_composition().unwrap();
        let lower = held.retained.overlay_lower();
        let receipt_query =
            "SELECT receipt,graph_receipt FROM composition_validation WHERE lower_id=?1 AND schema=1";
        let pack = pool.stream_path(&held.unique[0].0.pack.stream);
        let fsmeta = pool.object_path(&held.retained.fsmeta());
        for path in [&pack, &fsmeta] {
            let previous: (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(receipt_query)
                .bind(held.retained.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
            assert!(previous.1.is_some());
            let modified = std::fs::metadata(path).unwrap().modified().unwrap();
            std::fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            let mut byte = [0u8; 1];
            file.read_exact_at(&mut byte, 0).unwrap();
            file.write_all_at(&[byte[0] ^ 0xff], 0).unwrap();
            file.set_times(FileTimes::new().set_modified(modified))
                .unwrap();
            std::fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
            for _ in 0..2 {
                assert!(layers
                    .publish_local_composition(held._owner.operation, &graph)
                    .await
                    .is_err());
                assert!(layers.hold_lower(&lower).await.is_err());
                let unchanged: (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(receipt_query)
                    .bind(held.retained.id.to_string())
                    .fetch_one(&store.pool)
                    .await
                    .unwrap();
                assert_eq!(unchanged, previous);
            }
            assert!(held.recheck().is_err());
            file.write_all_at(&byte, 0).unwrap();
            drop(file);
            layers
                .publish_local_composition(held._owner.operation, &graph)
                .await
                .unwrap();
            let refreshed: (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(receipt_query)
                .bind(held.retained.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
            assert_ne!(refreshed.0, previous.0);
            assert!(refreshed.1.is_some());
            layers.hold_lower(&lower).await.unwrap().recheck().unwrap();
        }
        std::fs::remove_file(&pack).unwrap();
        assert!(layers.hold_composition(held.retained.id).await.is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn malformed_or_different_schema_receipts_fall_back_to_exact_validation() {
        let (_temporary, paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        let events = watch(&held, &pool);
        sqlx::query("UPDATE composition_validation SET schema=2 WHERE lower_id=?1")
            .bind(held.retained.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        layers.hold_composition(held.retained.id).await.unwrap();
        assert!(!events.read_events().unwrap().is_empty());
        sqlx::query("UPDATE composition_validation SET receipt=?2 WHERE lower_id=?1")
            .bind(held.retained.id.to_string())
            .bind(b"not a receipt".as_slice())
            .execute(&store.pool)
            .await
            .unwrap();
        layers.hold_composition(held.retained.id).await.unwrap();
        assert!(!events.read_events().unwrap().is_empty());
    }

    #[tokio::test]
    async fn corrupt_same_length_replacements_and_missing_fsmeta_never_regenerate() {
        let (_temporary, paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        for path in [
            pool.stream_path(&held.unique[0].0.pack.stream),
            pool.object_path(&held.retained.fsmeta()),
        ] {
            replace(&path);
            std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let mut byte = [0u8; 1];
            file.read_exact_at(&mut byte, 0).unwrap();
            file.write_all_at(&[byte[0] ^ 0xff], 0).unwrap();
            std::fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap();
            assert!(layers.hold_composition(held.retained.id).await.is_err());
            assert_eq!(
                layers.retained_composition(held.retained.id).await.unwrap(),
                held.retained
            );
            file.write_all_at(&byte, 0).unwrap();
            drop(file);
            layers.hold_composition(held.retained.id).await.unwrap();
        }
        std::fs::remove_file(pool.object_path(&held.retained.fsmeta())).unwrap();
        assert!(layers.hold_composition(held.retained.id).await.is_err());
    }

    #[tokio::test]
    async fn canonical_occurrence_order_is_not_authorized_by_a_receipt() {
        let (_temporary, _paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        sqlx::query("DELETE FROM composition_layer WHERE result_id=?1 AND position IN (0,1)")
            .bind(held.retained.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        for (position, layer) in [
            (0i64, held.retained.layers[1]),
            (1, held.retained.layers[0]),
        ] {
            sqlx::query("INSERT INTO composition_layer(result_id,position,layer_result_id) VALUES(?1,?2,?3)")
                .bind(held.retained.id.to_string()).bind(position).bind(layer.to_string())
                .execute(&store.pool).await.unwrap();
        }
        assert!(layers.hold_composition(held.retained.id).await.is_err());
        assert!(!receipt(&store, &held).await.is_empty());
    }

    #[tokio::test]
    async fn held_leases_survive_concurrent_gc_and_receipts_are_not_roots() {
        let (_temporary, paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        let id = held.retained.id;
        let fsmeta = pool.object_path(&held.retained.fsmeta());
        let (again, collected) =
            tokio::join!(layers.hold_composition(id), store.retire_layer_cache(),);
        collected.unwrap();
        let again = again.unwrap();
        held.recheck().unwrap();
        again.recheck().unwrap();
        assert!(fsmeta.exists());
        drop(held);
        drop(again);
        store.retire_layer_cache().await.unwrap();
        store.recover_layer_objects().await.unwrap();
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM composition_validation WHERE lower_id=?1")
                .bind(id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
        assert!(!fsmeta.exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn graph_receipt_hits_skip_index_maps_and_payloads_and_misses_revalidate() {
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        let (_temporary, paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        let graph = held.snapshot_composition().unwrap();
        let lower = held.retained.overlay_lower();
        let metadata = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap();
        for layer in &graph.layers {
            for digest in std::iter::once(layer.index_root)
                .chain(layer.index_pages.iter().copied())
                .chain(std::iter::once(layer.pack.map))
                .chain(layer.pack.map_pages.iter().copied())
            {
                metadata
                    .add_watch(&pool.object_path(&digest), AddWatchFlags::IN_ACCESS)
                    .unwrap();
            }
        }
        let payloads = watch(&held, &pool);
        let resolved = layers.hold_lower(&lower).await.unwrap();
        resolved.recheck().unwrap();
        assert_eq!(resolved.snapshot_composition(), &graph);
        assert_eq!(
            layers.snapshot_composition(graph.result).await.unwrap(),
            graph
        );
        layers
            .publish_local_composition(held._owner.operation, &graph)
            .await
            .unwrap();
        unread(&metadata);
        unread(&payloads);
        drop(resolved);

        sqlx::query("UPDATE composition_validation SET graph_receipt=NULL WHERE lower_id=?1")
            .bind(graph.result.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        layers.hold_lower(&lower).await.unwrap().recheck().unwrap();
        assert!(!metadata.read_events().unwrap().is_empty());
        unread(&payloads);

        let index = pool.object_path(&graph.layers[0].index_root);
        replace(&index);
        let replaced = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap();
        replaced
            .add_watch(&index, AddWatchFlags::IN_ACCESS)
            .unwrap();
        layers.hold_lower(&lower).await.unwrap().recheck().unwrap();
        assert!(!replaced.read_events().unwrap().is_empty());
        unread(&payloads);

        replace(&pool.stream_path(&graph.layers[0].pack.stream));
        let replaced_pack = watch(&held, &pool);
        layers.hold_lower(&lower).await.unwrap().recheck().unwrap();
        assert!(!replaced_pack.read_events().unwrap().is_empty());
        let _ = payloads.read_events();

        sqlx::query("DELETE FROM composition_validation WHERE lower_id=?1")
            .bind(graph.result.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        layers.hold_lower(&lower).await.unwrap().recheck().unwrap();
        assert!(!payloads.read_events().unwrap().is_empty());
        let length = std::fs::metadata(&index).unwrap().len() as usize;
        std::fs::set_permissions(&index, Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&index, vec![b'x'; length]).unwrap();
        std::fs::set_permissions(&index, Permissions::from_mode(0o400)).unwrap();
        assert!(layers.hold_lower(&lower).await.is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_snapshot_graph_rebuilds_retired_composition_catalog_with_full_authentication() {
        let (_temporary, paths, store, held) = fixture().await;
        let layers = LayerStore::from_store(store.clone());
        let pool = StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        let graph = held.snapshot_composition().unwrap();
        let events = watch(&held, &pool);
        sqlx::query("DELETE FROM storage_operation_lower WHERE lower_id=?1")
            .bind(graph.result.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM composition_result WHERE id=?1")
            .bind(graph.result.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let recovered = layers
            .publish_local_composition(held._owner.operation, &graph)
            .await
            .unwrap();
        assert_eq!(recovered, graph.result);
        assert!(!events.read_events().unwrap().is_empty());
        let lower = layers
            .hold_lower(&held.retained.overlay_lower())
            .await
            .unwrap();
        assert_eq!(lower.snapshot_composition(), &graph);
        lower.recheck().unwrap();
        unread(&events);
    }
}
