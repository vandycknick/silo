//! Atomic imported artifact publication. Remote capture provenance is never a
//! local capture reservation and never advances the source lifecycle journal.
use std::collections::BTreeSet;
use std::sync::Arc;

use sqlx::Row;

use crate::image::import_types::{ManagedSourceId, ManagedSourceInfo, ManagedSourceRef};
use crate::image::transport::{VerifiedContent, VerifiedImportedArtifact};
use crate::storage::identity::ObjectDigest;
use crate::storage::limits::Resource;
use crate::storage::pool::{OperationPaths, StoragePool};
use crate::store::managed_image_store::ManagedImageStore;
use crate::store::models::snapshot::invalid;
use crate::store::snapshot_store::{bind_held, recheck_closure, RecordInput};
use crate::store::stream_representation::{
    insert_representation, mark_flat_present, VerifiedStreamRepresentation,
};
use crate::store::Store;
use crate::LibVmError;

/// The acquisition owner remains alive until the caller has received its
/// durable explicit-retention result.
pub(crate) struct ImportedArtifactCommit {
    pub(crate) info: ManagedSourceInfo,
    _operation: OperationPaths,
    _store: Arc<Store>,
}

pub(crate) async fn commit_imported_artifact(
    artifact: VerifiedImportedArtifact,
    alias: Option<String>,
) -> Result<ImportedArtifactCommit, LibVmError> {
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || runtime.block_on(commit_owned(artifact, alias))).await?
}

async fn commit_owned(
    artifact: VerifiedImportedArtifact,
    alias: Option<String>,
) -> Result<ImportedArtifactCommit, LibVmError> {
    if let Some(alias) = &alias {
        crate::store::snapshot_store::validate_alias(alias)?;
    }
    let parts = artifact.into_parts();
    let store = &parts.store;
    let operation = parts.operation.id;
    let (device, inode) = parts.operation.lease_identity()?;
    let pool = StoragePool::open(&store.images_dir)?;
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='import' AND state='staging' AND file_device=?2 AND file_inode=?3)")
        .bind(operation.to_string()).bind(device.to_string()).bind(inode.to_string()).fetch_one(&store.pool).await?;
    if !active {
        return Err(invalid(
            "artifact commit lacks its original acquisition owner",
        ));
    }
    let mut fingerprints = Vec::new();
    for object in parts.objects.values() {
        bind_held(&object.file, object.fingerprint)?;
        let (published, roots) = pool.publish_object_file_for_catalog(
            object.file.try_clone()?,
            &parts.operation.temporary,
        )?;
        if published.digest != object.digest || published.length != object.size {
            return Err(invalid(
                "imported object publication identity contradiction",
            ));
        }
        store
            .pin_published_storage_dependencies(operation, &[], &[published.digest])
            .await?;
        fingerprints.push((
            published.path.clone(),
            crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
                published.path,
            )?),
        ));
        drop(roots);
    }
    let semantic_streams = match &parts.content {
        VerifiedContent::Image { record, .. } => record.content_dependencies()?.0,
        VerifiedContent::StoppedSnapshot { record, .. }
        | VerifiedContent::LiveCheckpoint { record, .. } => record.content_dependencies()?.0,
    };
    let mut representations = Vec::new();
    for stream in parts.streams.values() {
        let content = crate::store::models::snapshot::SnapshotStream {
            stream: stream.id,
            length: stream.length,
            map: stream.canonical_map,
            map_pages: stream.canonical_pages.clone(),
        };
        bind_held(&stream.file, stream.fingerprint)?;
        // Object-only transfer maps retain encoded chunks, not another
        // permanent whole-stream inode. In particular fsmeta remains one
        // ObjectDigest backing, irrespective of its chunked wire encoding.
        let flat = semantic_streams.contains(&stream.id);
        if flat {
            let (published, roots) =
                pool.publish_stream_file_for_catalog(stream.file.try_clone()?, stream.length)?;
            if published.id != stream.id || published.map != *stream.map {
                return Err(invalid(
                    "imported stream publication identity contradiction",
                ));
            }
            store
                .pin_published_storage_dependencies(operation, &[stream.id], &[])
                .await?;
            mark_flat_present(&mut *store.pool.acquire().await?, &content).await?;
            fingerprints.push((
                published.path.clone(),
                crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
                    published.path,
                )?),
            ));
            drop(roots);
        }
        for descriptor in &stream.transport.chunks {
            let (published, roots) = pool.publish_object_file_for_catalog(
                parts.blobs.open(&descriptor.digest)?,
                &parts.operation.temporary,
            )?;
            if published.digest.to_string() != descriptor.digest.to_string()
                || published.length != descriptor.size
            {
                return Err(invalid("imported encoded chunk publication mismatch"));
            }
            store
                .pin_published_storage_dependencies(operation, &[], &[published.digest])
                .await?;
            drop(roots);
        }
        for (expected, bytes) in
            std::iter::once((&stream.transport.root.0, &stream.transport.root.1)).chain(
                stream
                    .transport
                    .pages
                    .iter()
                    .map(|(digest, bytes)| (digest, bytes)),
            )
        {
            let input = RecordInput::new(&store.images_dir, operation, bytes)?;
            let (published, roots) = pool.publish_object_for_catalog(&input.path())?;
            if published.digest != *expected {
                return Err(invalid("imported transport record publication mismatch"));
            }
            store
                .pin_published_storage_dependencies(operation, &[], &[published.digest])
                .await?;
            drop(roots);
        }
        representations.push((
            VerifiedStreamRepresentation::verify(&pool, content, stream.transport.root.0)?
                .for_import(),
            flat,
        ));
    }
    let root = match &parts.content {
        VerifiedContent::Image { record, .. } => &record.root,
        VerifiedContent::StoppedSnapshot { record, .. }
        | VerifiedContent::LiveCheckpoint { record, .. } => &record.root,
    };
    if let crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay { lower, .. } =
        &root.profile
    {
        crate::store::layer_store::LayerStore::open(&store.home)
            .await?
            .publish_snapshot_composition(operation, lower)
            .await?;
    }
    let receipt_bytes = parts.receipt.canonical_bytes()?;
    let receipt_digest = ObjectDigest::of_bytes(&receipt_bytes);
    let input = RecordInput::new(&store.images_dir, operation, &receipt_bytes)?;
    let (receipt, roots) = pool.publish_object_for_catalog(&input.path())?;
    if receipt.digest != receipt_digest {
        return Err(invalid("acquisition receipt publication mismatch"));
    }
    store
        .pin_published_storage_dependencies(operation, &[], &[receipt_digest])
        .await?;
    fingerprints.push((
        receipt.path.clone(),
        crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
            receipt.path,
        )?),
    ));
    drop(roots);
    let (target, bytes, digest, streams, mut objects, capture) = match &parts.content {
        VerifiedContent::Image {
            id,
            record,
            bytes,
            digest,
        } => {
            let (streams, objects) = record.content_dependencies()?;
            (
                ManagedSourceId::Image(*id),
                bytes,
                *digest,
                streams,
                objects,
                None,
            )
        }
        VerifiedContent::StoppedSnapshot {
            id,
            record,
            bytes,
            digest,
        } => {
            let (streams, objects) = record.content_dependencies()?;
            (
                ManagedSourceId::Snapshot(*id),
                bytes,
                *digest,
                streams,
                objects,
                None,
            )
        }
        VerifiedContent::LiveCheckpoint {
            id,
            record,
            bytes,
            digest,
            capture,
        } => {
            let (streams, objects) = record.content_dependencies()?;
            (
                ManagedSourceId::Snapshot(*id),
                bytes,
                *digest,
                streams,
                objects,
                Some(capture),
            )
        }
    };
    objects.insert(digest);
    store
        .preserve_imported_operation(operation, target, parts.index_digest)
        .await?;
    let (kind, id) = match target {
        ManagedSourceId::Image(id) => ("image", id.to_string()),
        ManagedSourceId::Snapshot(id) => ("snapshot", id.to_string()),
    };
    // Preserve the exact immutable encoding alongside the local receipt. These
    // bytes are metadata, never substituted for canonical semantic identity.
    let encoding_bytes = encode_metadata([
        &parts.index_bytes,
        &parts.metadata_manifest_bytes,
        &parts.config_bytes,
    ])?;
    let _roots = pool.lock_roots_shared()?;
    recheck_closure(&fingerprints)?;
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let existing = sqlx::query(match target {
        ManagedSourceId::Image(_) => {
            "SELECT record_digest,record_bytes FROM storage_image WHERE id=?1"
        }
        ManagedSourceId::Snapshot(_) => {
            "SELECT record_digest,record_bytes FROM storage_snapshot WHERE id=?1"
        }
    })
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        if row.try_get::<String, _>("record_digest")? != digest.to_string()
            || row.try_get::<Vec<u8>, _>("record_bytes")? != *bytes
        {
            return Err(invalid("immutable imported managed identity contradiction"));
        }
        let actual_streams = sqlx::query_scalar::<_, String>(match target {
            ManagedSourceId::Image(_) => {
                "SELECT stream_id FROM image_stream_dependency WHERE image_id=?1"
            }
            ManagedSourceId::Snapshot(_) => {
                "SELECT stream_id FROM snapshot_stream_dependency WHERE snapshot_id=?1"
            }
        })
        .bind(&id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|v| v.parse().map_err(invalid))
        .collect::<Result<BTreeSet<crate::storage::identity::StreamId>, _>>()?;
        let actual_objects = sqlx::query_scalar::<_, String>(match target {
            ManagedSourceId::Image(_) => {
                "SELECT object_digest FROM image_object_dependency WHERE image_id=?1"
            }
            ManagedSourceId::Snapshot(_) => {
                "SELECT object_digest FROM snapshot_object_dependency WHERE snapshot_id=?1"
            }
        })
        .bind(&id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|v| v.parse().map_err(invalid))
        .collect::<Result<BTreeSet<ObjectDigest>, _>>()?;
        if actual_streams != streams || actual_objects != objects {
            return Err(invalid("imported semantic dependency contradiction"));
        }
        sqlx::query(match target {
            ManagedSourceId::Image(_) => "UPDATE storage_image SET retained=1 WHERE id=?1",
            ManagedSourceId::Snapshot(_) => "UPDATE storage_snapshot SET retained=1 WHERE id=?1",
        })
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query(match target {
            ManagedSourceId::Image(_) => "INSERT INTO storage_image(id,record_digest,record_bytes,retained,created_at) VALUES(?1,?2,?3,?4,?5)",
            ManagedSourceId::Snapshot(_) => "INSERT INTO storage_snapshot(id,record_digest,record_bytes,retained,created_at) VALUES(?1,?2,?3,?4,?5)",
        })
            .bind(&id).bind(digest.to_string()).bind(bytes).bind(true).bind(chrono::Utc::now().timestamp()).execute(&mut *tx).await?;
        for stream in &streams {
            sqlx::query(match target {
                ManagedSourceId::Image(_) => {
                    "INSERT INTO image_stream_dependency(image_id,stream_id) VALUES(?1,?2)"
                }
                ManagedSourceId::Snapshot(_) => {
                    "INSERT INTO snapshot_stream_dependency(snapshot_id,stream_id) VALUES(?1,?2)"
                }
            })
            .bind(&id)
            .bind(stream.to_string())
            .execute(&mut *tx)
            .await?;
        }
        for object in &objects {
            sqlx::query(match target {
                ManagedSourceId::Image(_) => "INSERT INTO image_object_dependency(image_id,object_digest) VALUES(?1,?2)",
                ManagedSourceId::Snapshot(_) => "INSERT INTO snapshot_object_dependency(snapshot_id,object_digest) VALUES(?1,?2)",
            })
            .bind(&id)
            .bind(object.to_string())
            .execute(&mut *tx)
            .await?;
        }
    }
    for (representation, flat) in &representations {
        insert_representation(&mut tx, representation, *flat).await?;
    }
    for stream in parts.streams.values() {
        let object = ObjectDigest::from_sha256(*stream.sha256.as_bytes());
        if parts.objects.contains_key(&object) {
            crate::store::stream_representation::insert_object_binding(&mut tx, object, stream.id)
                .await?;
        }
    }
    sqlx::query("INSERT OR IGNORE INTO storage_operation_managed(operation_id,managed_kind,managed_id) VALUES(?1,?2,?3)")
        .bind(operation.to_string()).bind(kind).bind(&id).execute(&mut *tx).await?;
    let provenance = capture.map(|capture| capture.provenance_digest);
    if let Some(capture) = capture {
        let existing = sqlx::query("SELECT evidence_digest,provenance_bytes FROM snapshot_imported_capture WHERE snapshot_id=?1 AND provenance_digest=?2")
            .bind(&id).bind(capture.provenance_digest.to_string()).fetch_optional(&mut *tx).await?;
        if let Some(existing) = existing {
            if existing.try_get::<String, _>("evidence_digest")?
                != capture.evidence_digest.to_string()
                || existing.try_get::<Vec<u8>, _>("provenance_bytes")? != capture.provenance_bytes
            {
                return Err(invalid("immutable imported capture contradiction"));
            }
        } else {
            sqlx::query("INSERT INTO snapshot_imported_capture(snapshot_id,provenance_digest,evidence_digest,provenance_bytes) VALUES(?1,?2,?3,?4)")
                .bind(&id).bind(capture.provenance_digest.to_string()).bind(capture.evidence_digest.to_string()).bind(&capture.provenance_bytes).execute(&mut *tx).await?;
        }
    }
    sqlx::query("INSERT INTO managed_artifact_acquisition(managed_kind,managed_id,index_digest,receipt_digest,receipt_bytes,provenance_digest,encoding_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT DO NOTHING")
        .bind(kind).bind(&id).bind(parts.index_digest.to_string()).bind(receipt_digest.to_string()).bind(&receipt_bytes).bind(provenance.map(|d|d.to_string())).bind(&encoding_bytes).execute(&mut *tx).await?;
    let row = sqlx::query("SELECT receipt_bytes,provenance_digest,encoding_bytes FROM managed_artifact_acquisition WHERE managed_kind=?1 AND managed_id=?2 AND index_digest=?3 AND receipt_digest=?4")
        .bind(kind).bind(&id).bind(parts.index_digest.to_string()).bind(receipt_digest.to_string()).fetch_one(&mut *tx).await?;
    if row.try_get::<Vec<u8>, _>("receipt_bytes")? != receipt_bytes
        || row.try_get::<Option<String>, _>("provenance_digest")?
            != provenance.map(|d| d.to_string())
        || row.try_get::<Vec<u8>, _>("encoding_bytes")? != encoding_bytes
    {
        return Err(invalid("immutable acquisition receipt contradiction"));
    }
    if let Some(alias) = alias {
        crate::store::managed_image_store::insert_alias(&mut tx, &alias, target).await?;
    }
    sqlx::query("UPDATE storage_operation SET state='staging',record_json=jsonb('{}') WHERE operation_id=?1 AND kind='import' AND state='committing'")
        .bind(operation.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    drop(_roots);
    let reference = match target {
        ManagedSourceId::Image(id) => ManagedSourceRef::Image(id),
        ManagedSourceId::Snapshot(id) => ManagedSourceRef::Snapshot(id),
    };
    let info = ManagedImageStore::from_store(parts.store.clone())
        .inspect(&reference)
        .await?;
    Ok(ImportedArtifactCommit {
        info,
        _operation: parts.operation,
        _store: parts.store,
    })
}

/// Exact catalog relationship, used by consumers and GC before trusting roots.
pub(crate) async fn acquisition_objects(
    connection: &mut sqlx::SqliteConnection,
    kind: &str,
    id: &str,
) -> Result<BTreeSet<ObjectDigest>, LibVmError> {
    let mut cursor = (String::new(), String::new());
    let mut objects = BTreeSet::new();
    loop {
        let rows = sqlx::query("SELECT index_digest,receipt_digest,CASE WHEN length(receipt_bytes)<=4194304 THEN receipt_bytes END AS receipt_bytes,provenance_digest,CASE WHEN length(encoding_bytes)<=12582936 THEN encoding_bytes END AS encoding_bytes FROM managed_artifact_acquisition WHERE managed_kind=?1 AND managed_id=?2 AND (index_digest,receipt_digest)>(?3,?4) ORDER BY index_digest,receipt_digest LIMIT 1")
            .bind(kind).bind(id).bind(&cursor.0).bind(&cursor.1).fetch_all(&mut *connection).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = (row.try_get("index_digest")?, row.try_get("receipt_digest")?);
            let bytes: Vec<u8> = row
                .try_get::<Option<Vec<u8>>, _>("receipt_bytes")?
                .ok_or_else(|| invalid("oversized acquisition receipt"))?;
            let receipt = crate::image::transport::trust::AcquisitionReceipt::decode(&bytes)?;
            let digest: ObjectDigest = cursor.1.parse().map_err(invalid)?;
            if receipt.canonical_bytes()? != bytes
                || ObjectDigest::of_bytes(&bytes) != digest
                || receipt.index_digest.to_string() != cursor.0
            {
                return Err(invalid(
                    "artifact acquisition receipt identity contradiction",
                ));
            }
            if objects.is_empty() {
                objects.insert(digest);
            }
            let provenance: Option<String> = row.try_get("provenance_digest")?;
            let encoding: Vec<u8> = row
                .try_get::<Option<Vec<u8>>, _>("encoding_bytes")?
                .ok_or_else(|| invalid("oversized acquisition encoding metadata"))?;
            authenticate_encoding(
                &encoding,
                receipt.index_digest,
                kind,
                id,
                provenance.as_deref(),
            )?;
            if let Some(provenance) = provenance {
                if kind != "snapshot" {
                    return Err(invalid("image has imported capture authority"));
                }
                let provenance_digest: ObjectDigest = provenance.parse().map_err(invalid)?;
                let capture = sqlx::query("SELECT evidence_digest,provenance_bytes FROM snapshot_imported_capture WHERE snapshot_id=?1 AND provenance_digest=?2")
                    .bind(id).bind(&provenance).fetch_one(&mut *connection).await?;
                let evidence: ObjectDigest = capture
                    .try_get::<String, _>("evidence_digest")?
                    .parse()
                    .map_err(invalid)?;
                let wrapper: Vec<u8> = capture.try_get("provenance_bytes")?;
                if ObjectDigest::of_bytes(&wrapper) != provenance_digest {
                    return Err(invalid("imported capture wrapper digest contradiction"));
                }
                objects.extend([provenance_digest, evidence]);
            }
        }
    }
    Ok(objects)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportedCaptureRef {
    pub(crate) provenance_digest: ObjectDigest,
    pub(crate) evidence_digest: ObjectDigest,
    pub(crate) receipt_digest: ObjectDigest,
    pub(crate) index_digest: ObjectDigest,
}

pub(crate) async fn imported_capture_refs(
    connection: &mut sqlx::SqliteConnection,
    id: &str,
) -> Result<Vec<ImportedCaptureRef>, LibVmError> {
    let mut refs = Vec::new();
    let mut cursor = String::new();
    loop {
        let rows = sqlx::query("SELECT provenance_digest,evidence_digest FROM snapshot_imported_capture WHERE snapshot_id=?1 AND provenance_digest>?2 ORDER BY provenance_digest LIMIT 1")
            .bind(id).bind(&cursor).fetch_all(&mut *connection).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = row.try_get("provenance_digest")?;
            let evidence = row
                .try_get::<String, _>("evidence_digest")?
                .parse()
                .map_err(invalid)?;
            let receipt = sqlx::query("SELECT index_digest,receipt_digest FROM managed_artifact_acquisition WHERE managed_kind='snapshot' AND managed_id=?1 AND provenance_digest=?2 ORDER BY index_digest,receipt_digest LIMIT 1")
                .bind(id).bind(&cursor).fetch_optional(&mut *connection).await?
                .ok_or_else(||invalid("imported capture lacks a bound acquisition receipt"))?;
            Resource::MetadataPageEntries
                .check(refs.len() as u64 + 1)
                .map_err(crate::storage::StorageError::from)?;
            refs.push(ImportedCaptureRef {
                provenance_digest: cursor.parse().map_err(invalid)?,
                evidence_digest: evidence,
                receipt_digest: receipt
                    .try_get::<String, _>("receipt_digest")?
                    .parse()
                    .map_err(invalid)?,
                index_digest: receipt
                    .try_get::<String, _>("index_digest")?
                    .parse()
                    .map_err(invalid)?,
            });
        }
    }
    Ok(refs)
}

pub(crate) async fn retire_unrooted_managed(
    store: &Store,
    pool: &StoragePool,
) -> Result<(), LibVmError> {
    for (kind, query) in [
        (
            "image",
            "SELECT id FROM storage_image WHERE id>?1 AND retained=0 ORDER BY id LIMIT 256",
        ),
        (
            "snapshot",
            "SELECT id FROM storage_snapshot WHERE id>?1 AND retained=0 ORDER BY id LIMIT 256",
        ),
    ] {
        let mut cursor = String::new();
        loop {
            let ids = sqlx::query_scalar::<_, String>(query)
                .bind(&cursor)
                .fetch_all(&store.pool)
                .await?;
            if ids.is_empty() {
                break;
            }
            for id in ids {
                cursor.clone_from(&id);
                let _roots = pool.lock_roots()?;
                let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
                if kind == "image" {
                    crate::store::managed_image_store::remove_unrooted_image(&mut tx, &id).await?;
                } else {
                    crate::store::snapshot_store::remove_unrooted(&mut tx, &id).await?;
                }
                tx.commit().await?;
            }
        }
    }
    Ok(())
}

fn encode_metadata(records: [&[u8]; 3]) -> Result<Vec<u8>, LibVmError> {
    let mut length = 24usize;
    for record in records {
        Resource::MetadataPageBytes
            .check(record.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        length = length
            .checked_add(record.len())
            .ok_or_else(|| invalid("encoding metadata length overflow"))?;
    }
    let mut bytes = Vec::with_capacity(length);
    for record in records {
        bytes.extend_from_slice(&(record.len() as u64).to_le_bytes());
    }
    for record in records {
        bytes.extend_from_slice(record);
    }
    Ok(bytes)
}

fn authenticate_encoding(
    bytes: &[u8],
    index_digest: ObjectDigest,
    kind: &str,
    id: &str,
    provenance: Option<&str>,
) -> Result<(), LibVmError> {
    let header = bytes
        .get(..24)
        .ok_or_else(|| invalid("truncated encoding metadata"))?;
    let mut remaining = &bytes[24..];
    let mut records = [&[][..]; 3];
    for (index, length) in header.chunks_exact(8).enumerate() {
        let length = u64::from_le_bytes(length.try_into().map_err(invalid)?);
        Resource::MetadataPageBytes
            .check(length)
            .map_err(crate::storage::StorageError::from)?;
        let length = usize::try_from(length).map_err(invalid)?;
        let record = remaining
            .get(..length)
            .ok_or_else(|| invalid("truncated encoding record"))?;
        records[index] = record;
        remaining = &remaining[length..];
    }
    if !remaining.is_empty() || ObjectDigest::of_bytes(records[0]) != index_digest {
        return Err(invalid("acquisition index identity contradiction"));
    }
    let index: serde_json::Value =
        oci::vm_artifact::wire::decode_record(records[0]).map_err(invalid)?;
    let child = index
        .get("manifests")
        .and_then(|v| v.as_array())
        .and_then(|v| v.first())
        .ok_or_else(|| invalid("acquisition index has no metadata child"))?;
    authenticate_descriptor(
        child,
        records[1],
        "application/vnd.oci.image.manifest.v1+json",
    )?;
    let metadata: serde_json::Value =
        oci::vm_artifact::wire::decode_record(records[1]).map_err(invalid)?;
    authenticate_descriptor(
        metadata
            .get("config")
            .ok_or_else(|| invalid("metadata child lacks config"))?,
        records[2],
        oci::vm_artifact::wire::CONFIG_MEDIA_TYPE,
    )?;
    let config = oci::vm_artifact::wire::decode_vm_config(records[2])?;
    let expected_kind = match config.content.kind {
        oci::vm_artifact::wire::ContentKind::Image => "image",
        oci::vm_artifact::wire::ContentKind::Snapshot => "snapshot",
    };
    if expected_kind != kind
        || config.content.id.to_string() != id
        || config
            .capture_provenance
            .map(|p| p.digest.to_string())
            .as_deref()
            != provenance
    {
        return Err(invalid(
            "acquisition receipt does not bind its managed content and capture provenance",
        ));
    }
    Ok(())
}

fn authenticate_descriptor(
    value: &serde_json::Value,
    bytes: &[u8],
    media: &str,
) -> Result<(), LibVmError> {
    let digest = value
        .get("digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid("encoding descriptor has no digest"))?
        .parse::<ObjectDigest>()
        .map_err(invalid)?;
    if digest != ObjectDigest::of_bytes(bytes)
        || value.get("size").and_then(|v| v.as_u64()) != Some(bytes.len() as u64)
        || value.get("mediaType").and_then(|v| v.as_str()) != Some(media)
    {
        return Err(invalid("acquisition encoding descriptor contradiction"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::image::transport::export::ExportSource;
    use crate::image::transport::tests::{
        export, home, index_digest, stage, transfer as copy_transfer, verify, Transfer,
    };
    use crate::storage::identity::{ObjectDigest, SnapshotId};
    use crate::storage::pool::StoragePool;
    use crate::store::artifact_store::commit_imported_artifact;
    use crate::store::artifact_store::{authenticate_encoding, encode_metadata};
    use crate::store::models::snapshot::SnapshotRecord;
    use crate::store::snapshot_store::{SnapshotRef, SnapshotStore};
    use crate::store::stream_representation::VerifiedStreamRepresentation;
    use oci::vm_artifact::codec::{ChunkEncoder, ChunkEncoding};

    async fn snapshot_transfer(
        bytes: &[u8],
        entries_per_page: usize,
        preserve_raw: bool,
    ) -> (
        tempfile::TempDir,
        Transfer,
        SnapshotRecord,
        SnapshotId,
        ObjectDigest,
    ) {
        let (temp, store, record, info, owner, root) =
            crate::store::stream_representation::tests::retained_paginated(bytes, entries_per_page)
                .await;
        if preserve_raw {
            let pool = StoragePool::open(&store.images_dir).unwrap();
            let verified =
                VerifiedStreamRepresentation::verify(&pool, record.root.stream.clone(), root)
                    .unwrap()
                    .for_encoding(ChunkEncoding::Zstd)
                    .unwrap();
            store
                .register_stream_representation(owner.id, &verified)
                .await
                .unwrap();
        }
        let consumer = SnapshotStore::from_store(store.clone())
            .consume(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let prepared = export(
            store,
            ExportSource::Snapshot(Box::new(consumer)),
            ChunkEncoding::Zstd,
        )
        .await;
        let transfer = copy_transfer(&prepared.graph, &prepared.payloads());
        (temp, transfer, record, info.id, root)
    }

    fn metadata(provenance: Option<ObjectDigest>) -> (Vec<u8>, ObjectDigest, String) {
        let id = ObjectDigest::of_bytes(b"canonical semantic record").to_string();
        let record = serde_json::json!({"digest":ObjectDigest::of_bytes(b"record"),"size":6});
        let live = provenance.is_some();
        let config=oci::vm_artifact::wire::canonical_bytes(&serde_json::json!({
            "schema":1,"kind":"vm-artifact","encoding":"silo-chunks-v1",
            "content":{"kind":"snapshot","id":id,"record":record},
            "purpose":"checkpoint","captureKind":if live{"live-execution"}else{"stopped-storage"},
            "rootFamily":"opaque-raw","backendRequirement":"raw-block",
            "guestPlatform":{"os":"linux","architecture":"amd64"},
            "minimumCapabilities":{"storageProfile":"opaque-raw-v1","bootAbi":"silo-direct-v1","liveRestore":live},
            "executionRequirements":if live {Some(serde_json::json!({"kind":"krun-v1","executionVersion":1,"executionAbi":1,"deviceVersion":1,
                "compatibilityProfile":{"liveStateSchema":"silo.live-state/1","architecture":"x86_64","profile":ObjectDigest::of_bytes(b"profile"),"topology":ObjectDigest::of_bytes(b"topology"),"ramLayout":ObjectDigest::of_bytes(b"layout")}}))}else{None},
            "streams":record,"objects":record,
            "captureProvenance":provenance.map(|digest|serde_json::json!({"digest":digest,"size":42}))
        })).unwrap();
        let child=oci::vm_artifact::wire::canonical_bytes(&serde_json::json!({
            "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.silo.vm.metadata.v1",
            "config":{"digest":ObjectDigest::of_bytes(&config),"size":config.len(),"mediaType":"application/vnd.silo.vm.config.v1+json"},"layers":[]
        })).unwrap();
        let index=oci::vm_artifact::wire::canonical_bytes(&serde_json::json!({
            "schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.silo.vm.v1",
            "manifests":[{"digest":ObjectDigest::of_bytes(&child),"size":child.len(),"mediaType":"application/vnd.oci.image.manifest.v1+json"}]
        })).unwrap();
        (
            encode_metadata([&index, &child, &config]).unwrap(),
            ObjectDigest::of_bytes(&index),
            id,
        )
    }

    #[test]
    fn acquisition_index_binds_exact_managed_identity_and_selected_portable_provenance() {
        let provenance = ObjectDigest::of_bytes(b"selected portable provenance");
        let (bytes, index, id) = metadata(Some(provenance));
        authenticate_encoding(
            &bytes,
            index,
            "snapshot",
            &id,
            Some(&provenance.to_string()),
        )
        .unwrap();
        for (kind, content, provenance) in [
            ("image", id.clone(), Some(provenance.to_string())),
            (
                "snapshot",
                ObjectDigest::of_bytes(b"other snapshot").to_string(),
                Some(provenance.to_string()),
            ),
            ("snapshot", id.clone(), None),
            (
                "snapshot",
                id.clone(),
                Some(ObjectDigest::of_bytes(b"appended unrelated provenance").to_string()),
            ),
        ] {
            assert!(
                authenticate_encoding(&bytes, index, kind, &content, provenance.as_deref())
                    .is_err()
            );
        }
        let (other, _, _) = metadata(None);
        assert!(authenticate_encoding(&other, index, "snapshot", &id, None).is_err());
        let mut truncated = bytes.clone();
        truncated.pop();
        assert!(authenticate_encoding(
            &truncated,
            index,
            "snapshot",
            &id,
            Some(&provenance.to_string())
        )
        .is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(authenticate_encoding(
            &trailing,
            index,
            "snapshot",
            &id,
            Some(&provenance.to_string())
        )
        .is_err());
    }

    #[tokio::test]
    async fn imported_snapshot_candidate_recovers_without_manufacturing_local_capture_authority() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            crate::store::Store::new(&crate::paths::LocalPaths::new(temp.path().join("home")))
                .await
                .unwrap();
        let pool = crate::storage::pool::StoragePool::open(&store.images_dir).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let owner = pool.create_operation_with_lease(operation, lease).unwrap();
        let id = SnapshotId::from_sha256([0x42; 32]);
        let index = ObjectDigest::of_bytes(b"immutable approved index");
        store
            .preserve_imported_operation(
                operation,
                crate::image::import_types::ManagedSourceId::Snapshot(id),
                index,
            )
            .await
            .unwrap();
        store.check_operation_recovery(&pool).await.unwrap();
        let json: String = sqlx::query_scalar(
            "SELECT json(record_json) FROM storage_operation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["candidateSnapshotId"], id.to_string());
        assert_eq!(value["candidateIndexDigest"], index.to_string());
        let captures: i64 =
            sqlx::query_scalar("SELECT count(*) FROM storage_operation WHERE kind='capture'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(captures, 0);
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_operation")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(operations, 0);
    }

    #[tokio::test]
    async fn repeated_import_after_flat_eviction_reestablishes_prunable_presence() {
        let (_source_temp, transfer, record, _id, _) = snapshot_transfer(&[7; 512], 1, true).await;
        let (_destination_temp, destination) = home().await;
        let pool = StoragePool::open(&destination.images_dir).unwrap();
        for _ in 0..2 {
            let staging = stage(&destination, &transfer).await;
            let verified = verify(&transfer, staging, index_digest(&transfer))
                .await
                .unwrap();
            let committed = commit_imported_artifact(verified, None).await.unwrap();
            assert!(pool.stream_path(&record.root.stream.stream).exists());
            let state: String =
                sqlx::query_scalar("SELECT flat_state FROM storage_stream WHERE stream_id=?1")
                    .bind(record.root.stream.stream.to_string())
                    .fetch_one(&destination.pool)
                    .await
                    .unwrap();
            assert_eq!(state, "present");
            drop(committed);
            destination
                .retire_abandoned_storage_operations(&pool)
                .await
                .unwrap();
            destination.evict_flat_materializations().await.unwrap();
            assert!(!pool.stream_path(&record.root.stream.stream).exists());
            let state: String =
                sqlx::query_scalar("SELECT flat_state FROM storage_stream WHERE stream_id=?1")
                    .bind(record.root.stream.stream.to_string())
                    .fetch_one(&destination.pool)
                    .await
                    .unwrap();
            assert_eq!(state, "absent");
        }
    }

    #[tokio::test]
    async fn imported_raw_fallback_and_zero_streams_reuse_exact_alternate_pages_for_zstd() {
        for zero in [false, true] {
            let mut state = 0x4d595df4d0f33173u64;
            let bytes = (0..crate::storage::limits::CHUNK_SIZE + 512)
                .map(|_| {
                    if zero {
                        return 0;
                    }
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect::<Vec<_>>();
            let mut encoder = ChunkEncoder::new(ChunkEncoding::Zstd).unwrap();
            for chunk in bytes.chunks(crate::storage::limits::CHUNK_SIZE) {
                let encoded = encoder.encode(chunk).unwrap();
                assert!(
                    matches!(
                        encoded.entry,
                        oci::vm_artifact::wire::ChunkEntry::Zero { .. }
                    ) || matches!(encoded.entry, oci::vm_artifact::wire::ChunkEntry::Data { encoded, .. }
                        if encoded.media_type == oci::vm_artifact::wire::PayloadMediaType::RawChunk)
                );
            }
            let (_source_temp, transfer, record, id, root) =
                snapshot_transfer(&bytes, 1, true).await;
            let (_destination_temp, destination) = home().await;
            let staging = stage(&destination, &transfer).await;
            let verified = verify(&transfer, staging, index_digest(&transfer))
                .await
                .unwrap();
            let _committed = commit_imported_artifact(verified, None).await.unwrap();
            let consumer = SnapshotStore::from_store(destination.clone())
                .consume(&SnapshotRef::Id(id))
                .await
                .unwrap();
            for encoding in [ChunkEncoding::Raw, ChunkEncoding::Zstd] {
                let retained = destination
                    .retained_stream_representation(
                        consumer.operation_id,
                        &record.root.stream,
                        encoding,
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(retained.root.0, root);
                assert_eq!(retained.pages.len(), 2);
                let default = oci::vm_artifact::wire::encode_transfer(
                    record.root.stream.stream.to_string().parse().unwrap(),
                    record.root.stream.length,
                    &retained.entries,
                )
                .unwrap();
                assert_ne!(default.root.reference.digest.to_string(), root.to_string());
                assert_eq!(
                    retained.root.1,
                    transfer.blobs[&root.to_string().parse().unwrap()]
                );
                for (digest, bytes) in retained.pages {
                    assert_eq!(bytes, transfer.blobs[&digest.to_string().parse().unwrap()]);
                }
            }
            let prepared = export(
                destination,
                ExportSource::Snapshot(Box::new(consumer)),
                ChunkEncoding::Zstd,
            )
            .await;
            let republished = copy_transfer(&prepared.graph, &prepared.payloads());
            assert_eq!(republished.index, transfer.index);
            assert_eq!(republished.blobs, transfer.blobs);
        }
    }

    #[tokio::test]
    async fn imported_compressed_stream_remains_ineligible_for_explicit_raw_policy() {
        let (_source_temp, transfer, record, id, _) = snapshot_transfer(&[7; 512], 1, false).await;
        let (_destination_temp, destination) = home().await;
        let staging = stage(&destination, &transfer).await;
        let verified = verify(&transfer, staging, index_digest(&transfer))
            .await
            .unwrap();
        let _committed = commit_imported_artifact(verified, None).await.unwrap();
        let consumer = SnapshotStore::from_store(destination.clone())
            .consume(&SnapshotRef::Id(id))
            .await
            .unwrap();
        let retained = destination
            .retained_stream_representation(
                consumer.operation_id,
                &record.root.stream,
                ChunkEncoding::Zstd,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(retained.entries.iter().any(|entry| matches!(entry,
            oci::vm_artifact::wire::ChunkEntry::Data { encoded, .. }
                if encoded.media_type == oci::vm_artifact::wire::PayloadMediaType::ZstdChunk)));
        assert!(destination
            .retained_stream_representation(
                consumer.operation_id,
                &record.root.stream,
                ChunkEncoding::Raw,
            )
            .await
            .unwrap()
            .is_none());
        let pool = StoragePool::open(&destination.images_dir).unwrap();
        assert!(VerifiedStreamRepresentation::verify(
            &pool,
            record.root.stream.clone(),
            retained.root.0
        )
        .unwrap()
        .for_encoding(ChunkEncoding::Raw)
        .is_err());
    }
}
