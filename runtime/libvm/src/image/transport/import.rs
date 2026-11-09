//! Verified import of one OCI VM artifact. Order of authority:
//!
//! ```text
//! approved index digest ──> verified graph (T1) ──> canonical record bytes
//!        │                                              │ derive
//!        │                                              v
//!        │                     config + stream/object table closure (exact sets)
//!        │                                              │
//!        └──> operation staging: decode every chunk, place, hash whole bytes,
//!             regenerate canonical maps, hash streamed objects, portable seal
//! ```
//!
//! Nothing here writes the catalog or the canonical pool. The result owns the
//! acquisition operation and hands measured facts and held files to the
//! catalog commit; it never fabricates a local capture.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use oci::changeset::model::ContentDigest;
use oci::vm_artifact::codec::decode_chunk;
use oci::vm_artifact::graph::VerifiedVmGraph;
use oci::vm_artifact::wire::{
    verify_transfer_to, ChunkEntry, ObjectBinding, PayloadRef, StreamBinding, CHUNK_SIZE,
};
use sha2::{Digest, Sha256};
use vm_spec::capture::Sha256Digest;

use crate::image::transport::blobs::{create_private_file, invalid, StagedBlobs};
use crate::image::transport::closure::{
    canonical_map_bytes, content, identity, object, stream_id, ObjectRole, Semantic, SemanticRecord,
};
use crate::image::transport::provenance::{
    verify_portable_binding, verify_portable_capture, MeasuredCapture,
};
use crate::image::transport::trust::{AcquisitionReceipt, ApprovedArtifactDigest};
use crate::paths::OwnedDirectory;
use crate::storage::identity::{ImageId, ObjectDigest, SnapshotId, StreamId};
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::pool::OperationPaths;
use crate::storage::stream::{write_sparse_at, Chunk, StreamMap};
use crate::store::models::image::ImageRecord;
use crate::store::models::snapshot::{SnapshotCaptureKind, SnapshotRecord};
use crate::store::Store;
use crate::LibVmError;

/// The verified semantic root of an import. Exact bytes and both identities
/// travel together so the catalog never reserializes a different identity.
#[derive(Debug)]
pub(crate) enum VerifiedContent {
    Image {
        id: ImageId,
        record: ImageRecord,
        bytes: Vec<u8>,
        digest: ObjectDigest,
    },
    StoppedSnapshot {
        id: SnapshotId,
        record: SnapshotRecord,
        bytes: Vec<u8>,
        digest: ObjectDigest,
    },
    LiveCheckpoint {
        id: SnapshotId,
        record: SnapshotRecord,
        bytes: Vec<u8>,
        digest: ObjectDigest,
        capture: VerifiedPortableCapture,
    },
}

/// Exact transported seal. Its wrapper and evidence bytes are also held as
/// direct objects; source IDs inside are historical provenance, never local
/// capture, launch or pause authority.
#[derive(Debug)]
pub(crate) struct VerifiedPortableCapture {
    pub(crate) provenance_digest: ObjectDigest,
    pub(crate) provenance_bytes: Vec<u8>,
    pub(crate) evidence_digest: ObjectDigest,
}

/// The selected transfer representation of one stream, retained so the
/// catalog can register it as a complete canonical representation.
#[derive(Debug)]
pub(crate) struct VerifiedTransport {
    pub(crate) root: (ObjectDigest, Vec<u8>),
    pub(crate) pages: Vec<(ObjectDigest, Vec<u8>)>,
    /// Unique encoded chunk descriptors, sorted by encoded digest.
    pub(crate) chunks: Vec<PayloadRef>,
}

/// One completely decoded, placed and hashed stream in operation staging.
#[derive(Debug)]
pub(crate) struct VerifiedStream {
    pub(crate) id: StreamId,
    pub(crate) length: u64,
    pub(crate) map: Arc<StreamMap>,
    pub(crate) canonical_map: ObjectDigest,
    pub(crate) canonical_pages: Vec<ObjectDigest>,
    pub(crate) file: File,
    pub(crate) fingerprint: SourceFingerprint,
    /// Whole decoded bytes, measured while placing them.
    pub(crate) sha256: Sha256Digest,
    pub(crate) transport: VerifiedTransport,
}

/// One authenticated whole-byte object and the held descriptor it was read
/// from: the staged blob for direct objects, the reconstructed stream for
/// streamed boot objects.
#[derive(Debug)]
pub(crate) struct VerifiedObject {
    pub(crate) digest: ObjectDigest,
    pub(crate) size: u64,
    pub(crate) file: File,
    pub(crate) fingerprint: SourceFingerprint,
}

/// Everything the catalog commit consumes. Only this module constructs it.
pub(crate) struct ImportedParts {
    pub(crate) operation: OperationPaths,
    pub(crate) store: Arc<Store>,
    pub(crate) blobs: StagedBlobs,
    pub(crate) index_bytes: Vec<u8>,
    pub(crate) index_digest: ObjectDigest,
    pub(crate) metadata_manifest_bytes: Vec<u8>,
    pub(crate) config_bytes: Vec<u8>,
    pub(crate) receipt: AcquisitionReceipt,
    pub(crate) content: VerifiedContent,
    pub(crate) streams: BTreeMap<StreamId, VerifiedStream>,
    pub(crate) objects: BTreeMap<ObjectDigest, VerifiedObject>,
}

/// Non-forgeable verified import result. Retains the acquisition operation
/// lease and writable store through every subsequent blocking step.
pub(crate) struct VerifiedImportedArtifact {
    parts: ImportedParts,
}

impl VerifiedImportedArtifact {
    pub(crate) fn into_parts(self) -> ImportedParts {
        self.parts
    }
}

/// Staging and ownership inputs of one acquisition operation.
pub(crate) struct ImportStaging {
    pub(crate) operation: OperationPaths,
    pub(crate) store: Arc<Store>,
    /// Every payload blob of `graph.inventory()`, fetched by the caller.
    pub(crate) blobs: StagedBlobs,
}

/// Verify one complete artifact against an explicit digest approval. Blocking:
/// run inside the worker that owns `staging` for the whole call.
pub(crate) fn verify_imported_artifact(
    graph: &VerifiedVmGraph,
    trust: &ApprovedArtifactDigest,
    approved_at_unix_ms: u64,
    staging: ImportStaging,
) -> Result<VerifiedImportedArtifact, LibVmError> {
    let index_digest = object(graph.index_digest());
    if trust.index_digest() != index_digest {
        return Err(LibVmError::ArtifactTrustMismatch {
            expected: trust.index_digest().to_string(),
            actual: index_digest.to_string(),
        });
    }
    let ImportStaging {
        operation,
        store,
        blobs,
    } = staging;
    let config = graph.config();
    let record_payload = config.content.record.payload();
    let semantic = Semantic::decode(config.content.kind, blobs.read(&record_payload)?)?;
    if semantic.content_ref() != config.content {
        return Err(invalid(
            "config",
            "content identity differs from the canonical record",
        ));
    }
    let provenance = match config.capture_provenance {
        Some(reference) => {
            let bytes = blobs.read(&reference.payload())?;
            let wrapper =
                crate::image::transport::provenance::PortableCaptureProvenanceV1::decode(&bytes)?;
            let evidence = blobs.read(&wrapper.evidence.payload())?;
            Some((bytes, evidence))
        }
        None => None,
    };
    let expected = semantic.config(config.streams, config.objects, config.capture_provenance)?;
    if &expected != config {
        return Err(invalid(
            "config",
            "VM config differs from the projection of its canonical record",
        ));
    }
    let roles = semantic.object_roles(provenance.as_ref().map(|(wrapper, evidence)| {
        (
            ObjectDigest::of_bytes(wrapper),
            ObjectDigest::of_bytes(evidence),
        )
    }))?;
    let plan = closure_plan(&semantic, roles, graph.streams(), graph.objects())?;
    crate::storage::limits::preflight_fd_budget(
        (plan.streams.len() + plan.objects.len()) as u64 + 2,
    )
    .map_err(crate::storage::StorageError::from)?;

    let temporary = OwnedDirectory::open_existing_root(&operation.temporary)?
        .ok_or_else(|| invalid("staging", "acquisition operation staging is missing"))?;
    let materialized = temporary.ensure_dir("streams")?;
    let mut streams = BTreeMap::new();
    for row in graph.streams() {
        let stream = materialize_stream(graph, &blobs, &materialized, row)?;
        streams.insert(stream.id, stream);
    }
    let mut objects = BTreeMap::new();
    for row in graph.objects() {
        let digest = object(row.object());
        let file = match row {
            ObjectBinding::Direct { payload, .. } => blobs.open_verified(payload)?,
            ObjectBinding::Stream { size, stream, .. } => {
                let id = stream_id(*stream);
                let held = streams.get(&id).ok_or_else(|| {
                    invalid("object table", format!("{digest} lacks stream {id}"))
                })?;
                // The whole reconstructed byte sequence must be the object;
                // a StreamId is never an ObjectDigest substitute.
                if held.length != *size || held.sha256.as_bytes() != digest.as_bytes() {
                    return Err(invalid(
                        "object",
                        format!("streamed object {digest} differs from its reconstructed bytes"),
                    ));
                }
                held.file.try_clone()?
            }
        };
        let size = file.metadata()?.len();
        if size != row.size() {
            return Err(invalid(
                "object",
                format!("{digest} length differs from its row"),
            ));
        }
        objects.insert(
            digest,
            VerifiedObject {
                digest,
                size,
                fingerprint: SourceFingerprint::new(&file.metadata()?),
                file,
            },
        );
    }
    semantic.authenticate_lower(
        |digest, maximum| {
            let held = objects
                .get(digest)
                .ok_or_else(|| invalid("composition", format!("missing object {digest}")))?;
            if held.size > maximum {
                return Err(invalid(
                    "composition",
                    format!("{digest} exceeds its record bound"),
                ));
            }
            let mut bytes =
                vec![0; usize::try_from(held.size).map_err(|error| invalid("composition", error))?];
            held.file.read_exact_at(&mut bytes, 0)?;
            Ok(bytes)
        },
        |digest| {
            objects
                .get(digest)
                .ok_or_else(|| invalid("composition", format!("missing object {digest}")))?
                .file
                .try_clone()
                .map_err(Into::into)
        },
        |stream| {
            streams
                .get(&stream.stream)
                .ok_or_else(|| invalid("composition", format!("missing pack {}", stream.stream)))?
                .file
                .try_clone()
                .map_err(Into::into)
        },
    )?;

    let content = match semantic.record {
        SemanticRecord::Image(record) => {
            let crate::image::import_types::ManagedSourceId::Image(id) = semantic.id else {
                return Err(invalid("record", "image identity kind mismatch"));
            };
            VerifiedContent::Image {
                id,
                record: *record,
                bytes: semantic.bytes,
                digest: semantic.digest,
            }
        }
        SemanticRecord::Snapshot(record) => {
            let crate::image::import_types::ManagedSourceId::Snapshot(id) = semantic.id else {
                return Err(invalid("record", "snapshot identity kind mismatch"));
            };
            match (&record.capture, provenance) {
                (SnapshotCaptureKind::StoppedStorage { .. }, None) => {
                    VerifiedContent::StoppedSnapshot {
                        id,
                        record: *record,
                        bytes: semantic.bytes,
                        digest: semantic.digest,
                    }
                }
                (SnapshotCaptureKind::LiveExecution { execution }, Some((wrapper, evidence))) => {
                    let binding = verify_portable_binding(&record, id, &wrapper, &evidence)?;
                    let layout = blobs.read(
                        &graph
                            .payload(content(execution.layout))
                            .copied()
                            .ok_or_else(|| invalid("object", "RAM layout lacks a payload"))?,
                    )?;
                    let held = |digest: &ObjectDigest| {
                        objects
                            .get(digest)
                            .map(|object: &VerifiedObject| &object.file)
                            .ok_or_else(|| invalid("object", format!("{digest} is not held")))
                    };
                    let stream_maps = streams
                        .values()
                        .map(|stream: &VerifiedStream| (stream.id, Arc::clone(&stream.map)))
                        .collect();
                    verify_portable_capture(
                        &record,
                        &binding,
                        &MeasuredCapture {
                            stream_maps: &stream_maps,
                            layout: &layout,
                            execution: held(&execution.execution)?,
                            devices: held(&execution.devices)?,
                        },
                    )?;
                    VerifiedContent::LiveCheckpoint {
                        id,
                        record: *record,
                        bytes: semantic.bytes,
                        digest: semantic.digest,
                        capture: VerifiedPortableCapture {
                            provenance_digest: binding.wrapper_digest,
                            provenance_bytes: wrapper,
                            evidence_digest: binding.evidence_digest,
                        },
                    }
                }
                _ => {
                    return Err(invalid(
                        "capture provenance",
                        "provenance presence contradicts the capture kind",
                    ))
                }
            }
        }
    };
    for held in objects.values() {
        if SourceFingerprint::new(&held.file.metadata()?) != held.fingerprint {
            return Err(invalid(
                "object",
                "staged object changed during verification",
            ));
        }
    }
    Ok(VerifiedImportedArtifact {
        parts: ImportedParts {
            operation,
            store,
            blobs,
            index_bytes: graph.index_bytes().to_vec(),
            index_digest,
            metadata_manifest_bytes: graph.metadata_manifest_bytes().to_vec(),
            config_bytes: graph.config_bytes().to_vec(),
            receipt: trust.receipt(approved_at_unix_ms),
            content,
            streams,
            objects,
        },
    })
}

/// Exact expected closure rows derived from the record, checked before any
/// bulk byte is touched.
pub(crate) struct ClosurePlan {
    pub(crate) streams: BTreeSet<StreamId>,
    pub(crate) objects: BTreeMap<ObjectDigest, ObjectRole>,
}

/// Compare the received tables with the record-derived closure: missing and
/// surplus rows, per-role representation, and every semantic stream's exact
/// length and canonical map pins.
pub(crate) fn closure_plan(
    semantic: &Semantic,
    mut roles: BTreeMap<ObjectDigest, ObjectRole>,
    stream_rows: &[StreamBinding],
    object_rows: &[ObjectBinding],
) -> Result<ClosurePlan, LibVmError> {
    let rows: BTreeMap<StreamId, &StreamBinding> = stream_rows
        .iter()
        .map(|row| (stream_id(row.stream), row))
        .collect();
    if rows.len() != stream_rows.len() {
        return Err(invalid("stream table", "repeated stream row"));
    }
    let mut expected_streams = BTreeSet::new();
    for stream in semantic.streams() {
        let row = rows.get(&stream.stream).ok_or_else(|| {
            invalid(
                "stream table",
                format!("semantic stream {} has no row", stream.stream),
            )
        })?;
        if row.length != stream.length
            || object(row.map) != stream.map
            || row.map_pages.len() != stream.map_pages.len()
            || row
                .map_pages
                .iter()
                .zip(&stream.map_pages)
                .any(|(left, right)| object(*left) != *right)
        {
            return Err(invalid(
                "stream table",
                format!(
                    "{} length or canonical map differs from the record",
                    stream.stream
                ),
            ));
        }
        expected_streams.insert(stream.stream);
    }
    // Streamed objects add their own stream rows and canonical map objects.
    for row in object_rows {
        if let ObjectBinding::Stream {
            object: digest,
            size,
            stream,
        } = row
        {
            let digest = object(*digest);
            if !matches!(
                roles.get(&digest),
                Some(ObjectRole::Streamed | ObjectRole::Fsmeta)
            ) {
                return Err(invalid(
                    "object table",
                    format!("{digest} is not an opaque streamed role"),
                ));
            }
            let id = stream_id(*stream);
            let binding = rows
                .get(&id)
                .ok_or_else(|| invalid("stream table", format!("object stream {id} has no row")))?;
            if binding.length != *size {
                return Err(invalid(
                    "stream table",
                    format!("object stream {id} length"),
                ));
            }
            expected_streams.insert(id);
            let metadata = ObjectRole::Record {
                maximum: crate::storage::limits::Resource::MetadataPageBytes.maximum(),
            };
            crate::image::transport::closure::add_role(&mut roles, object(binding.map), metadata)?;
            for page in &binding.map_pages {
                crate::image::transport::closure::add_role(&mut roles, object(*page), metadata)?;
            }
        }
    }
    if rows.keys().ne(expected_streams.iter()) {
        return Err(invalid("stream table", "missing or surplus stream rows"));
    }
    let received: BTreeMap<ObjectDigest, &ObjectBinding> = object_rows
        .iter()
        .map(|row| (object(row.object()), row))
        .collect();
    if received.keys().ne(roles.keys()) {
        return Err(invalid("object table", "missing or surplus object rows"));
    }
    for (digest, role) in &roles {
        let row = received
            .get(digest)
            .ok_or_else(|| invalid("object table", format!("{digest} has no row")))?;
        if row.size() > role.maximum() {
            return Err(invalid(
                "object table",
                format!("{digest} exceeds its role's byte bound"),
            ));
        }
        match (row, role.media()) {
            (ObjectBinding::Direct { payload, .. }, Some(media)) if payload.media_type == media => {
            }
            (ObjectBinding::Stream { .. }, None) => {}
            _ => {
                return Err(invalid(
                    "object table",
                    format!("{digest} uses the wrong representation for its role"),
                ))
            }
        }
    }
    Ok(ClosurePlan {
        streams: expected_streams,
        objects: roles,
    })
}

/// Logical worst-case disk peak of acquiring `graph`, charged before any
/// payload is fetched. Independent of holes, reflinks and deduplication:
/// every term below can coexist until the acquisition operation retires.
///
/// ```text
/// transport cache        Σ inventory payloads        fetched encoded blobs
/// decoded staging        Σ stream rows               zero-filled stream files
/// catalog publication    Σ stream rows               immutable stream copies
///                      + Σ object rows               direct and streamed objects
///                      + 2 × Σ inventory payloads    chunk copies; transport
///                                                    records staged, then copied
///                      + 2 × metadata page           receipt staged, then copied
/// ```
///
/// The verified graph's tables are exactly the import closure (checked by
/// `closure_plan` before decoding), so this charge needs no payload bytes.
pub(crate) fn acquisition_space_charge(graph: &VerifiedVmGraph) -> Result<u64, LibVmError> {
    fn total(mut sizes: impl Iterator<Item = u64>) -> Option<u64> {
        sizes.try_fold(0u64, u64::checked_add)
    }
    fn charge(graph: &VerifiedVmGraph) -> Option<u64> {
        let inventory = total(graph.inventory().values().map(|payload| payload.size))?;
        let streams = total(graph.streams().iter().map(|row| row.length))?;
        let objects = total(graph.objects().iter().map(ObjectBinding::size))?;
        let receipt = crate::storage::limits::Resource::MetadataPageBytes.maximum();
        inventory
            .checked_mul(3)?
            .checked_add(streams.checked_mul(2)?)?
            .checked_add(objects)?
            .checked_add(receipt.checked_mul(2)?)
    }
    charge(graph).ok_or_else(|| invalid("space reservation", "acquisition charge overflow"))
}

/// Decode and place every chunk of one stream into a new zero-filled staging
/// file. Zero entries stay holes. Repeated encoded blobs are decoded once and
/// copied from their first verified placement, but only when the repeat
/// asserts exactly the decoded digest, length and encoded descriptor that
/// the first decode authenticated (the catalog's representation rule).
fn materialize_stream(
    graph: &VerifiedVmGraph,
    blobs: &StagedBlobs,
    directory: &OwnedDirectory,
    row: &StreamBinding,
) -> Result<VerifiedStream, LibVmError> {
    let id = stream_id(row.stream);
    let root = graph
        .transfer(row.stream)
        .ok_or_else(|| invalid("transfer map", format!("{id} has no transfer root")))?;
    let root_bytes = blobs.read(&row.transport.payload())?;
    let file = create_private_file(directory, &id.hex())?;
    file.set_len(row.length)?;
    let count = usize::try_from(row.length.div_ceil(CHUNK_SIZE))
        .map_err(|error| invalid("transfer map", error))?;
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(count)
        .map_err(|error| invalid("transfer map", error))?;
    let mut hash = Sha256::new();
    let zeros = vec![0u8; CHUNK_SIZE as usize];
    let mut buffer = Vec::with_capacity(CHUNK_SIZE as usize);
    // Encoded digest -> first placement and the decoded facts it proved.
    let mut placed: HashMap<ContentDigest, (u64, (ContentDigest, u64, PayloadRef))> =
        HashMap::new();
    let mut encoded = BTreeMap::new();
    let mut transport_pages = Vec::new();
    // Errors raised inside the codec visitor keep their typed libvm form.
    let mut failure: Option<LibVmError> = None;
    let result = verify_transfer_to(
        root,
        |digest| {
            let payload = graph.payload(digest).copied().ok_or_else(|| {
                oci::vm_artifact::Error::Invalid(format!("transfer page {digest} lacks a payload"))
            })?;
            let bytes = blobs
                .read(&payload)
                .map_err(|error| oci::vm_artifact::Error::Invalid(error.to_string()))?;
            transport_pages.push((object(digest), bytes.clone()));
            Ok(bytes)
        },
        |index, entry| {
            let step = (|| -> Result<(), LibVmError> {
                let offset = index
                    .checked_mul(CHUNK_SIZE)
                    .ok_or_else(|| invalid("transfer map", "chunk offset overflow"))?;
                match &entry {
                    ChunkEntry::Zero { length } => {
                        hash.update(&zeros[..*length as usize]);
                        chunks.push(Chunk::Zero);
                    }
                    ChunkEntry::Data {
                        length,
                        digest,
                        encoded: descriptor,
                    } => {
                        buffer.clear();
                        let facts = (*digest, *length, *descriptor);
                        if let Some((first, proven)) = placed.get(&descriptor.digest) {
                            if *proven != facts {
                                return Err(invalid(
                                    "chunk",
                                    format!(
                                        "encoded chunk {} has contradictory decoded assertions",
                                        descriptor.digest
                                    ),
                                ));
                            }
                            buffer.resize(*length as usize, 0);
                            file.read_exact_at(&mut buffer, *first)?;
                        } else {
                            let reader = blobs.open(&descriptor.digest)?;
                            decode_chunk(&entry, reader, &mut buffer)?;
                            placed.insert(descriptor.digest, (offset, facts));
                        }
                        if buffer.len() as u64 != *length {
                            return Err(invalid("chunk", "decoded length differs from entry"));
                        }
                        write_sparse_at(&file, &buffer, offset)?;
                        hash.update(&buffer);
                        chunks.push(Chunk::Data(object(*digest)));
                        encoded.insert(descriptor.digest, *descriptor);
                    }
                }
                Ok(())
            })();
            step.map_err(|error| {
                let message = error.to_string();
                failure = Some(error);
                oci::vm_artifact::Error::Invalid(message)
            })
        },
    );
    if let Some(error) = failure {
        return Err(error);
    }
    result?;
    file.sync_all()?;
    let map = StreamMap::new(row.length, chunks)?;
    if map.id() != id {
        return Err(invalid(
            "transfer map",
            format!("decoded identity {} differs from stream {id}", map.id()),
        ));
    }
    // Regenerate the canonical local map: transport repagination may differ,
    // the canonical root/pages named by the semantic tables may not.
    let (canonical_root, canonical_page_bytes) = canonical_map_bytes(&map)?;
    let canonical_pages: Vec<ObjectDigest> = canonical_page_bytes
        .iter()
        .map(|page| ObjectDigest::of_bytes(page))
        .collect();
    let canonical_map = ObjectDigest::of_bytes(&canonical_root);
    if canonical_map != object(row.map)
        || canonical_pages.len() != row.map_pages.len()
        || canonical_pages
            .iter()
            .zip(&row.map_pages)
            .any(|(left, right)| *left != object(*right))
    {
        return Err(invalid(
            "stream table",
            format!("{id} canonical map differs from its regenerated local map"),
        ));
    }
    if root.stream != identity(id) || root.length != row.length {
        return Err(invalid(
            "transfer map",
            format!("{id} transfer root mismatch"),
        ));
    }
    let fingerprint = SourceFingerprint::new(&file.metadata()?);
    Ok(VerifiedStream {
        id,
        length: row.length,
        map: Arc::new(map),
        canonical_map,
        canonical_pages,
        fingerprint,
        file,
        sha256: Sha256Digest::from_bytes(hash.finalize().into()),
        transport: VerifiedTransport {
            root: (object(row.transport.digest), root_bytes),
            pages: transport_pages,
            chunks: encoded.into_values().collect(),
        },
    })
}
