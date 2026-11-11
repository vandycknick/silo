//! Prepared owned export of one managed image or snapshot. The consumer keeps
//! the authenticated closure pinned through encoding and upload; every byte
//! leaving the host is re-derived from that closure and checked against the
//! canonical record before it can become part of the fixed graph encoding.
//!
//! Each stream travels in one exact transfer representation. A complete
//! retained representation for the requested encoding is reused byte for byte
//! (ADR 0014: no repeated recompression), so a retried publication reproduces
//! the same graph. Only an unavailable representation is encoded, and it is
//! then registered as retained canonical content for the next publication.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use oci::changeset::model::ContentDigest;
use oci::vm_artifact::codec::{ChunkEncoder, ChunkEncoding};
use oci::vm_artifact::graph::{encode_vm_graph, EncodedVmGraph};
use oci::vm_artifact::wire::{
    encode_object_table, encode_stream_table, encode_transfer, ChunkEntry, EncodedTable,
    ObjectBinding, PayloadRef, RecordBlob, RecordRef, StreamBinding, CHUNK_SIZE,
    MAX_ARTIFACT_BYTES, MAX_STREAM_BYTES,
};
use tokio::runtime::Handle;
use uuid::Uuid;

use crate::image::import_types::ManagedSourceId;
use crate::image::transport::blobs::{invalid, StagedBlobs};
use crate::image::transport::closure::{
    canonical_map_bytes, content, identity, object, ObjectRole, Semantic,
};
use crate::image::transport::provenance::{build_local, verify_portable_binding};
use crate::paths::OwnedDirectory;
use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::limits::Resource;
use crate::storage::locks::StorageLock;
use crate::storage::pool::{OperationPaths, StoragePool};
use crate::storage::stream::{AuthenticatedStream, Chunk, StreamHasher, StreamMap};
use crate::store::managed_image_store::ManagedImageConsumer;
use crate::store::models::snapshot::SnapshotStream;
use crate::store::snapshot_store::{RecordInput, SnapshotConsumer};
use crate::store::stream_representation::VerifiedStreamRepresentation;
use crate::store::Store;
use crate::LibVmError;

/// The held managed source. Dropping it releases the closure lease, so the
/// prepared artifact owns it until upload has finished.
pub(crate) enum ExportSource {
    Image(Box<ManagedImageConsumer>),
    Snapshot(Box<SnapshotConsumer>),
}

impl ExportSource {
    fn semantic(&self) -> Result<Semantic, LibVmError> {
        let (semantic, digest) = match self {
            Self::Image(consumer) => (
                Semantic::image(consumer.info.record.clone())?,
                consumer.info.record_digest,
            ),
            Self::Snapshot(consumer) => (
                Semantic::snapshot(consumer.record.clone())?,
                consumer.info.record_digest,
            ),
        };
        if semantic.digest != digest {
            return Err(invalid(
                "record",
                "catalog record digest differs from its canonical bytes",
            ));
        }
        Ok(semantic)
    }

    /// The consumer's own operation and a duplicate of its original lease
    /// OFD: export staging and outputs never create a second owner.
    fn operation(&self) -> Result<(Uuid, StorageLock), LibVmError> {
        Ok(match self {
            Self::Image(consumer) => (consumer.operation_id(), consumer.duplicate_lease()?),
            Self::Snapshot(consumer) => (consumer.operation_id, consumer.lease.duplicate()?),
        })
    }

    fn open_stream(&self, pool: &StoragePool, stream: &SnapshotStream) -> Result<File, LibVmError> {
        match self {
            Self::Image(consumer) => {
                let root = &consumer.info.record.root;
                let member = root.stream == *stream
                    || matches!(
                        &root.profile,
                        crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay { lower, .. }
                            if lower.layers.iter().any(|layer| layer.pack == *stream)
                    );
                if !member {
                    return Err(invalid("record", "image exports only its semantic streams"));
                }
                let map = pool.verify_stream(&stream.stream)?;
                if map.length() != stream.length {
                    return Err(invalid("record", "image stream length mismatch"));
                }
                Ok(pool.open_stream(&stream.stream)?)
            }
            Self::Snapshot(consumer) => consumer.open_stream(pool, &stream.stream, stream.length),
        }
    }
}

/// One fixed exact encoding plus the held source behind it. Every bulk
/// payload of the graph is canonical pool content pinned by the source.
pub(crate) struct PreparedVmArtifact {
    pub(crate) graph: EncodedVmGraph,
    pub(crate) content: ManagedSourceId,
    pub(crate) live: bool,
    pub(crate) stopped_snapshot: bool,
    images: PathBuf,
    _operation: OperationPaths,
    _source: ExportSource,
}

impl PreparedVmArtifact {
    /// A reader that authenticates payload bytes by digest and size.
    pub(crate) fn payloads(&self) -> PayloadReader {
        PayloadReader {
            images: self.images.clone(),
        }
    }
}

/// Reads one bounded graph payload from the canonical pool, digest-checked.
#[derive(Clone)]
pub(crate) struct PayloadReader {
    images: PathBuf,
}

impl PayloadReader {
    pub(crate) fn read(&self, payload: &PayloadRef) -> Result<Vec<u8>, LibVmError> {
        payload.validate()?;
        let bytes =
            StoragePool::open(&self.images)?.read_object(&object(payload.digest), payload.size)?;
        if bytes.len() as u64 != payload.size {
            return Err(invalid(
                "payload",
                format!("{} length differs from its descriptor", payload.digest),
            ));
        }
        Ok(bytes)
    }
}

/// Encode the complete closure of `source`. Blocking: run in the worker that
/// owns `source`; `runtime` serves catalog calls from that worker.
pub(crate) fn prepare_artifact_export(
    source: ExportSource,
    store: &Store,
    runtime: &Handle,
    encoding: ChunkEncoding,
) -> Result<PreparedVmArtifact, LibVmError> {
    prepare_export_within(source, store, runtime, encoding, MAX_ARTIFACT_BYTES)
}

/// `prepare_artifact_export` against an explicit complete-closure stream
/// budget. The whole unique transport-stream closure, semantic streams plus
/// streamed byte objects, is planned and admitted before any chunk, map,
/// transfer record or representation is published or registered.
fn prepare_export_within(
    source: ExportSource,
    store: &Store,
    runtime: &Handle,
    encoding: ChunkEncoding,
    budget: u64,
) -> Result<PreparedVmArtifact, LibVmError> {
    let semantic = source.semantic()?;
    let images = store.images_path().to_path_buf();
    let pool = StoragePool::open(&images)?;
    let (operation_id, lease) = source.operation()?;
    let operation = pool.create_operation_with_lease(operation_id, lease)?;
    semantic.authenticate_lower(
        |digest, maximum| Ok(pool.read_object(digest, maximum)?),
        |digest| Ok(pool.open_object(digest)?),
        |stream| source.open_stream(&pool, stream),
    )?;
    let provenance = match &source {
        ExportSource::Snapshot(consumer) if semantic.live() => Some(select_provenance(
            consumer, &pool, &semantic, store, runtime,
        )?),
        _ => None,
    };
    let roles = semantic.object_roles(provenance.as_ref().map(|(wrapper, evidence)| {
        (
            ObjectDigest::of_bytes(wrapper),
            ObjectDigest::of_bytes(evidence),
        )
    }))?;
    let mut object_streams = plan_object_streams(&pool, &roles)?;
    check_transport_streams(
        semantic
            .streams()
            .into_iter()
            .map(|stream| (stream.stream, stream.length))
            .chain(
                object_streams
                    .values()
                    .map(|planned| (planned.stream.stream, planned.stream.length)),
            ),
        budget,
    )?;
    let temporary = OwnedDirectory::open_existing_root(&operation.temporary)?
        .ok_or_else(|| invalid("staging", "export operation staging is missing"))?;
    let staged = StagedBlobs::join(&temporary, "blobs")?;
    let mut builder = Builder {
        context: Context {
            store,
            runtime,
            pool: &pool,
            operation: operation_id,
            encoding,
            staged: &staged,
        },
        encoder: ChunkEncoder::new(encoding)?,
        records: Vec::new(),
        payloads: BTreeMap::new(),
        written: BTreeSet::new(),
        published: BTreeSet::new(),
        streams: BTreeMap::new(),
        objects: BTreeMap::new(),
        buffer: vec![0; CHUNK_SIZE as usize],
    };
    for stream in semantic.streams() {
        if builder.streams.contains_key(&stream.stream) {
            continue;
        }
        builder.add_stream(stream, || source.open_stream(&pool, stream))?;
    }
    for (digest, role) in &roles {
        match role {
            ObjectRole::Record { maximum } => {
                let bytes = if *digest == semantic.digest {
                    semantic.bytes.clone()
                } else if let Some(bytes) = provenance.as_ref().and_then(|(wrapper, evidence)| {
                    [wrapper, evidence]
                        .into_iter()
                        .find(|bytes| ObjectDigest::of_bytes(bytes) == *digest)
                }) {
                    bytes.clone()
                } else {
                    pool.read_object(digest, *maximum)?
                };
                builder.add_record_object(*digest, bytes, *maximum)?;
            }
            ObjectRole::Execution | ObjectRole::Devices => {
                let media = role
                    .media()
                    .ok_or_else(|| invalid("object", "native state lacks its media type"))?;
                let size = pool.verify_object(digest)?.metadata()?.len();
                if size > role.maximum() {
                    return Err(invalid(
                        "object",
                        format!("{digest} exceeds its role bound"),
                    ));
                }
                let payload = PayloadRef {
                    media_type: media,
                    digest: content(*digest),
                    size,
                };
                builder.payloads.insert(payload.digest, payload);
                builder.add_object_row(ObjectBinding::Direct {
                    object: payload.digest,
                    size,
                    payload,
                })?;
            }
            ObjectRole::Streamed | ObjectRole::Fsmeta => {
                builder.add_streamed_object(object_streams.remove(digest).ok_or_else(|| {
                    invalid("object", format!("{digest} object stream was not planned"))
                })?)?
            }
        }
    }
    let Builder {
        mut records,
        payloads,
        streams,
        objects,
        ..
    } = builder;
    let streams = encode_stream_table(&streams.into_values().collect::<Vec<_>>())?;
    let objects = encode_object_table(&objects.into_values().collect::<Vec<_>>())?;
    let config = semantic.config(
        streams.root.reference,
        objects.root.reference,
        provenance
            .as_ref()
            .map(|(wrapper, _)| RecordRef::of_bytes(wrapper)),
    )?;
    for table in [streams, objects] {
        records.push(table.root);
        records.extend(table.pages);
    }
    let graph = encode_vm_graph(
        &config,
        &records,
        &payloads.into_values().collect::<Vec<_>>(),
    )?;
    let stopped_snapshot = matches!(source, ExportSource::Snapshot(_)) && !semantic.live();
    Ok(PreparedVmArtifact {
        graph,
        content: semantic.id,
        live: semantic.live(),
        stopped_snapshot,
        images,
        _operation: operation,
        _source: source,
    })
}

/// One opaque byte object measured for transport in a single authenticated
/// pass: whole SHA-256 against its digest plus its stream map. Nothing is
/// published or pinned while planning.
struct ObjectStream {
    digest: ObjectDigest,
    source: AuthenticatedStream,
    stream: SnapshotStream,
    root: Vec<u8>,
    pages: Vec<Vec<u8>>,
}

fn plan_object_streams(
    pool: &StoragePool,
    roles: &BTreeMap<ObjectDigest, ObjectRole>,
) -> Result<BTreeMap<ObjectDigest, ObjectStream>, LibVmError> {
    let mut hasher = StreamHasher::new();
    let mut planned = BTreeMap::new();
    for (digest, role) in roles {
        if !matches!(role, ObjectRole::Streamed | ObjectRole::Fsmeta) {
            continue;
        }
        let file = pool.open_object(digest)?;
        let length = file.metadata()?.len();
        if length > role.maximum() {
            return Err(invalid(
                "object",
                format!("{digest} exceeds its role bound"),
            ));
        }
        let (source, sha256) = hasher.authenticate_with_sha256(file, length)?;
        if sha256.as_bytes() != digest.as_bytes() {
            return Err(invalid(
                "object",
                format!("{digest} differs from its pooled bytes"),
            ));
        }
        let (root, pages) = canonical_map_bytes(source.map())?;
        let stream = SnapshotStream {
            stream: source.map().id(),
            map: ObjectDigest::of_bytes(&root),
            map_pages: pages
                .iter()
                .map(|page| ObjectDigest::of_bytes(page))
                .collect(),
            length,
        };
        planned.insert(
            *digest,
            ObjectStream {
                digest: *digest,
                source,
                stream,
                root,
                pages,
            },
        );
    }
    Ok(planned)
}

/// Admit the complete unique transport-stream closure against `budget`.
/// Each distinct stream counts once, as in the final stream table; the
/// semantic record keeps its own role-counted bound independently.
fn check_transport_streams(
    streams: impl IntoIterator<Item = (StreamId, u64)>,
    budget: u64,
) -> Result<u64, LibVmError> {
    let mut unique = BTreeMap::new();
    for (stream, length) in streams {
        if length > MAX_STREAM_BYTES {
            return Err(invalid(
                "stream table",
                format!("{stream} exceeds the per-stream bound"),
            ));
        }
        if unique
            .insert(stream, length)
            .is_some_and(|previous| previous != length)
        {
            return Err(invalid(
                "stream table",
                format!("{stream} has contradictory lengths"),
            ));
        }
    }
    let total = unique
        .values()
        .try_fold(0u64, |total, length| total.checked_add(*length))
        .ok_or_else(|| invalid("stream table", "artifact stream budget overflow"))?;
    if total > budget {
        return Err(invalid(
            "stream table",
            format!(
                "complete transport closure of {} exceeds the {} artifact stream budget (short by {})",
                utils::format_storage_size(total),
                utils::format_storage_size(budget),
                utils::format_storage_size(total.saturating_sub(budget))
            ),
        ));
    }
    Ok(total)
}

/// Deterministically choose one fully verified seal. Every catalog-authenticated
/// candidate must verify: a malformed fact is corruption, not a skipped row.
fn select_provenance(
    consumer: &SnapshotConsumer,
    pool: &StoragePool,
    semantic: &Semantic,
    store: &Store,
    runtime: &Handle,
) -> Result<(Vec<u8>, Vec<u8>), LibVmError> {
    let record = semantic
        .snapshot_record()
        .ok_or_else(|| invalid("capture provenance", "provenance requires a snapshot"))?;
    let ManagedSourceId::Snapshot(id) = semantic.id else {
        return Err(invalid(
            "capture provenance",
            "provenance requires a snapshot",
        ));
    };
    let evidence_limit = vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64;
    let mut candidates = BTreeMap::new();
    for local in &consumer.info.provenance {
        let evidence = pool.read_object(&local.evidence_digest, evidence_limit)?;
        let plan = runtime.block_on(crate::store::snapshot_store::capture_plan(
            store,
            id,
            local.capture_id,
        ))?;
        let (binding, wrapper) = build_local(record, id, &evidence, &plan)?;
        let ids = [
            (binding.evidence.machine_id.as_str(), local.machine_id),
            (binding.evidence.run_id.as_str(), local.run_id),
            (binding.evidence.capture_id.as_str(), local.capture_id),
        ];
        if ids
            .iter()
            .any(|(evidence, catalog)| Uuid::parse_str(evidence).ok() != Some(*catalog))
        {
            return Err(invalid(
                "capture provenance",
                "local provenance row contradicts its sealed evidence",
            ));
        }
        candidates.insert(binding.wrapper_digest, (wrapper, evidence));
    }
    for imported in consumer.imported_provenance() {
        let wrapper = pool.read_object(
            &imported.provenance_digest,
            Resource::MetadataPageBytes.maximum(),
        )?;
        let evidence = pool.read_object(&imported.evidence_digest, evidence_limit)?;
        let binding = verify_portable_binding(record, id, &wrapper, &evidence)?;
        candidates.insert(binding.wrapper_digest, (wrapper, evidence));
    }
    candidates.into_values().next().ok_or_else(|| {
        invalid(
            "capture provenance",
            "live checkpoint has no authenticated capture provenance to export",
        )
    })
}

/// Shared catalog/pool context of one export worker.
struct Context<'a> {
    store: &'a Store,
    runtime: &'a Handle,
    pool: &'a StoragePool,
    operation: Uuid,
    encoding: ChunkEncoding,
    staged: &'a StagedBlobs,
}

impl Context<'_> {
    /// Publish exact bytes as canonical objects, pinned to the source
    /// operation while each publication guard is held.
    fn publish_record(&self, bytes: &[u8]) -> Result<ObjectDigest, LibVmError> {
        let input = RecordInput::new(self.store.images_path(), self.operation, bytes)?;
        let (published, roots) = self.pool.publish_object_for_catalog(&input.path())?;
        if published.digest != ObjectDigest::of_bytes(bytes) {
            return Err(invalid("record", "published record digest contradiction"));
        }
        self.runtime
            .block_on(self.store.pin_published_storage_dependencies(
                self.operation,
                &[],
                &[published.digest],
            ))?;
        drop(roots);
        Ok(published.digest)
    }

    fn publish_chunk(&self, payload: &PayloadRef) -> Result<(), LibVmError> {
        let file = self.staged.open_verified(payload)?;
        let (published, roots) = self
            .pool
            .publish_object_file_for_catalog(file, self.staged.path())?;
        if published.digest != object(payload.digest) || published.length != payload.size {
            return Err(invalid("chunk", "published chunk identity contradiction"));
        }
        self.runtime
            .block_on(self.store.pin_published_storage_dependencies(
                self.operation,
                &[],
                &[published.digest],
            ))?;
        drop(roots);
        Ok(())
    }
}

struct Builder<'a> {
    context: Context<'a>,
    encoder: ChunkEncoder,
    records: Vec<RecordBlob>,
    payloads: BTreeMap<ContentDigest, PayloadRef>,
    /// Encoded chunks already staged by this export.
    written: BTreeSet<ContentDigest>,
    /// Encoded chunks already published as canonical objects by this export.
    published: BTreeSet<ContentDigest>,
    streams: BTreeMap<StreamId, StreamBinding>,
    objects: BTreeMap<ObjectDigest, ObjectBinding>,
    buffer: Vec<u8>,
}

impl Builder<'_> {
    /// Select the retained representation for the requested encoding, or
    /// encode and register one. `open` is called only when encoding.
    fn add_stream(
        &mut self,
        stream: &SnapshotStream,
        open: impl FnOnce() -> Result<File, LibVmError>,
    ) -> Result<(), LibVmError> {
        let context = &self.context;
        let retained = context
            .runtime
            .block_on(context.store.retained_stream_representation(
                context.operation,
                stream,
                context.encoding,
            ))?;
        let (root, pages, entries) = match retained {
            Some(retained) => {
                let root = RecordBlob::new(retained.root.1)?;
                if object(root.reference.digest) != retained.root.0 {
                    return Err(invalid(
                        "transfer map",
                        "retained root digest contradiction",
                    ));
                }
                let mut pages = Vec::with_capacity(retained.pages.len());
                for (digest, bytes) in retained.pages {
                    let page = RecordBlob::new(bytes)?;
                    if object(page.reference.digest) != digest {
                        return Err(invalid(
                            "transfer map",
                            "retained page digest contradiction",
                        ));
                    }
                    pages.push(page);
                }
                (root, pages, retained.entries)
            }
            None => {
                let file = open()?;
                let entries = self.encode_stream(&file, stream.length)?;
                let table = encode_transfer(identity(stream.stream), stream.length, &entries)?;
                self.register(stream, &table, &entries)?;
                (table.root, table.pages, entries)
            }
        };
        self.add_stream_row(stream, root, pages, &entries)
    }

    /// Whole-byte objects travel through a temporary stream, measured once by
    /// planning. The stream is pinned to the source operation before any
    /// representation lookup.
    fn add_streamed_object(&mut self, object: ObjectStream) -> Result<(), LibVmError> {
        let ObjectStream {
            digest,
            source,
            stream,
            root,
            pages,
        } = object;
        let length = stream.length;
        let context = &self.context;
        context
            .runtime
            .block_on(context.store.pin_published_storage_dependencies(
                context.operation,
                &[stream.stream],
                &[],
            ))?;
        // The canonical map objects must exist before a representation of
        // this stream can be verified or registered against them.
        context.publish_record(&root)?;
        for page in &pages {
            context.publish_record(page)?;
        }
        if !self.streams.contains_key(&stream.stream) {
            let reopened = source.file().try_clone()?;
            self.add_stream(&stream, || Ok(reopened))?;
        }
        // No second whole-object hash: the selected representation projects
        // exactly the map measured together with this digest (checked on
        // registration and on the stream row), so the transported chunks
        // are those bytes. The measured inode must still be unchanged.
        if SourceFingerprint::new(&source.file().metadata()?) != source.fingerprint() {
            return Err(invalid(
                "object",
                format!("{digest} bytes changed while exporting"),
            ));
        }
        let context = &self.context;
        context
            .runtime
            .block_on(context.store.register_object_stream_representation(
                context.operation,
                digest,
                stream.stream,
            ))?;
        let metadata = Resource::MetadataPageBytes.maximum();
        self.add_record_object(stream.map, root, metadata)?;
        for page in pages {
            self.add_record_object(ObjectDigest::of_bytes(&page), page, metadata)?;
        }
        self.add_object_row(ObjectBinding::Stream {
            object: content(digest),
            size: length,
            stream: identity(stream.stream),
        })
    }

    /// Encode a held, authenticated source in one read. The canonical map is
    /// checked against the record when the row is added.
    fn encode_stream(&mut self, file: &File, length: u64) -> Result<Vec<ChunkEntry>, LibVmError> {
        let before = SourceFingerprint::new(&file.metadata()?);
        if file.metadata()?.len() != length {
            return Err(invalid("stream", "source length differs from its record"));
        }
        let count = usize::try_from(length.div_ceil(CHUNK_SIZE))
            .map_err(|error| invalid("stream", error))?;
        let mut entries = Vec::with_capacity(count);
        let mut offset = 0u64;
        while offset < length {
            let size = (length - offset).min(CHUNK_SIZE) as usize;
            let chunk = &mut self.buffer[..size];
            file.read_exact_at(chunk, offset)?;
            let encoded = self.encoder.encode(chunk)?;
            if let ChunkEntry::Data {
                encoded: payload, ..
            } = &encoded.entry
            {
                if self.written.insert(payload.digest) {
                    self.context.staged.insert(payload, &encoded.bytes)?;
                }
            }
            entries.push(encoded.entry);
            offset += size as u64;
        }
        if SourceFingerprint::new(&file.metadata()?) != before {
            return Err(invalid(
                "stream",
                "authenticated source changed while encoding",
            ));
        }
        Ok(entries)
    }

    /// Publish a newly encoded representation into the canonical pool and
    /// register it for the requested encoding policy.
    fn register(
        &mut self,
        stream: &SnapshotStream,
        table: &EncodedTable,
        entries: &[ChunkEntry],
    ) -> Result<(), LibVmError> {
        for entry in entries {
            if let ChunkEntry::Data { encoded, .. } = entry {
                if self.published.insert(encoded.digest) {
                    self.context.publish_chunk(encoded)?;
                }
            }
        }
        for record in table.pages.iter().chain(std::iter::once(&table.root)) {
            self.context.publish_record(&record.bytes)?;
        }
        let context = &self.context;
        let verified = VerifiedStreamRepresentation::verify(
            context.pool,
            stream.clone(),
            object(table.root.reference.digest),
        )?
        .for_encoding(context.encoding)?;
        context.runtime.block_on(
            context
                .store
                .register_stream_representation(context.operation, &verified),
        )
    }

    /// Check the transfer representation projects to exactly the canonical
    /// map named by the semantic stream, then add its row and payloads.
    fn add_stream_row(
        &mut self,
        stream: &SnapshotStream,
        root: RecordBlob,
        pages: Vec<RecordBlob>,
        entries: &[ChunkEntry],
    ) -> Result<(), LibVmError> {
        let mut chunks = Vec::with_capacity(entries.len());
        for entry in entries {
            match entry {
                ChunkEntry::Zero { .. } => chunks.push(Chunk::Zero),
                ChunkEntry::Data {
                    digest, encoded, ..
                } => {
                    chunks.push(Chunk::Data(object(*digest)));
                    self.payloads.insert(encoded.digest, *encoded);
                }
            }
        }
        let map = StreamMap::new(stream.length, chunks)?;
        let (canonical_root, canonical_pages) = canonical_map_bytes(&map)?;
        if map.id() != stream.stream
            || ObjectDigest::of_bytes(&canonical_root) != stream.map
            || canonical_pages.len() != stream.map_pages.len()
            || canonical_pages
                .iter()
                .zip(&stream.map_pages)
                .any(|(page, digest)| ObjectDigest::of_bytes(page) != *digest)
        {
            return Err(invalid(
                "stream table",
                format!(
                    "{} transfer representation differs from its canonical map",
                    stream.stream
                ),
            ));
        }
        let row = StreamBinding {
            stream: identity(stream.stream),
            length: stream.length,
            map: content(stream.map),
            map_pages: stream.map_pages.iter().map(|page| content(*page)).collect(),
            transport: root.reference,
        };
        self.records.push(root);
        self.records.extend(pages);
        self.streams.insert(stream.stream, row);
        Ok(())
    }

    fn add_record_object(
        &mut self,
        digest: ObjectDigest,
        bytes: Vec<u8>,
        maximum: u64,
    ) -> Result<(), LibVmError> {
        if bytes.len() as u64 > maximum || ObjectDigest::of_bytes(&bytes) != digest {
            return Err(invalid(
                "record",
                format!("{digest} exceeds its role bound"),
            ));
        }
        let record = RecordBlob::new(bytes)?;
        let payload = record.reference.payload();
        self.records.push(record);
        self.add_object_row(ObjectBinding::Direct {
            object: payload.digest,
            size: payload.size,
            payload,
        })
    }

    fn add_object_row(&mut self, row: ObjectBinding) -> Result<(), LibVmError> {
        let digest = object(row.object());
        match self.objects.get(&digest) {
            Some(existing) if *existing != row => Err(invalid(
                "object table",
                format!("{digest} has contradictory representations"),
            )),
            Some(_) => Ok(()),
            None => {
                self.objects.insert(digest, row);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;

    use oci::vm_artifact::codec::ChunkEncoding;
    use oci::vm_artifact::wire::{MAX_ARTIFACT_BYTES, MAX_STREAM_BYTES};

    use crate::image::transport::closure::Semantic;
    use crate::image::transport::export::{
        check_transport_streams, plan_object_streams, prepare_export_within, ExportSource,
        PreparedVmArtifact,
    };
    use crate::image::transport::tests::{count, database};
    use crate::storage::identity::{ObjectDigest, SnapshotId, StreamId};
    use crate::storage::pool::StoragePool;
    use crate::store::snapshot_store::{SnapshotRef, SnapshotStore};
    use crate::store::Store;
    use crate::LibVmError;

    fn stream(name: &str) -> StreamId {
        StreamId::from_sha256(*ObjectDigest::of_bytes(name.as_bytes()).as_bytes())
    }

    fn pooled_objects(store: &Store) -> BTreeSet<OsString> {
        std::fs::read_dir(store.images_path().join("objects/sha256"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect()
    }

    #[test]
    fn complete_transport_closure_counts_each_distinct_stream_once() {
        let disks = || (0..4).map(|index| (stream(&format!("disk {index}")), MAX_STREAM_BYTES));
        assert_eq!(
            check_transport_streams(disks(), MAX_ARTIFACT_BYTES).unwrap(),
            MAX_ARTIFACT_BYTES
        );
        // Repeated roles, and a boot stream identical to a disk, count once.
        let repeated = disks()
            .chain(disks())
            .chain([(stream("disk 0"), MAX_STREAM_BYTES)]);
        assert_eq!(
            check_transport_streams(repeated, MAX_ARTIFACT_BYTES).unwrap(),
            MAX_ARTIFACT_BYTES
        );
        // One more distinct boot byte exceeds the complete-closure bound.
        assert!(matches!(
            check_transport_streams(disks().chain([(stream("kernel"), 1)]), MAX_ARTIFACT_BYTES),
            Err(LibVmError::ArtifactInvalid {
                boundary: "stream table",
                ..
            })
        ));
        assert!(check_transport_streams(
            [(stream("oversized"), MAX_STREAM_BYTES + 1)],
            MAX_ARTIFACT_BYTES
        )
        .is_err());
        assert!(check_transport_streams(
            [(stream("same"), 1), (stream("same"), 2)],
            MAX_ARTIFACT_BYTES
        )
        .is_err());
    }

    async fn export_within(
        snapshots: &SnapshotStore,
        id: SnapshotId,
        budget: u64,
    ) -> Result<PreparedVmArtifact, LibVmError> {
        let consumer = snapshots.consume(&SnapshotRef::Id(id)).await.unwrap();
        let store = snapshots.store.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            prepare_export_within(
                ExportSource::Snapshot(Box::new(consumer)),
                &store,
                &runtime,
                ChunkEncoding::Zstd,
                budget,
            )
        })
        .await
        .unwrap()
    }

    /// Streamed boot objects join the complete closure: a budget the
    /// semantic streams alone fit is refused before any map, chunk, transfer
    /// record or representation is published, and the exact budget admits.
    #[tokio::test]
    async fn boot_streams_over_the_complete_budget_refuse_before_publication() {
        let (_temp, snapshots, record, operation, _lease) =
            crate::store::snapshot_store::tests::fixture("snapshot").await;
        let info = snapshots.publish(&record, operation, None).await.unwrap();
        let store = snapshots.store.clone();
        let pool = StoragePool::open(store.images_path()).unwrap();
        let semantic = record
            .streams()
            .map(|stream| (stream.stream, stream.length))
            .collect::<BTreeMap<_, _>>();
        let semantic_total = semantic.values().sum::<u64>();
        let roles = Semantic::snapshot(record.clone())
            .unwrap()
            .object_roles(None)
            .unwrap();
        let boot = plan_object_streams(&pool, &roles).unwrap();
        assert!(!boot.is_empty());
        let complete = check_transport_streams(
            semantic.into_iter().chain(
                boot.values()
                    .map(|planned| (planned.stream.stream, planned.stream.length)),
            ),
            MAX_ARTIFACT_BYTES,
        )
        .unwrap();
        assert!(complete > semantic_total);
        drop(boot);
        let catalog = database(&store).await;
        let representations = "SELECT COUNT(*) FROM stream_representation";
        let bindings = "SELECT COUNT(*) FROM object_stream_representation";
        let objects = pooled_objects(&store);
        let before = (
            count(&catalog, representations).await,
            count(&catalog, bindings).await,
        );
        for budget in [semantic_total, complete - 1] {
            let refused = export_within(&snapshots, info.id, budget).await;
            assert!(
                matches!(
                    refused,
                    Err(LibVmError::ArtifactInvalid {
                        boundary: "stream table",
                        ..
                    })
                ),
                "budget {budget}"
            );
            assert_eq!(pooled_objects(&store), objects, "budget {budget}");
            assert_eq!(
                (
                    count(&catalog, representations).await,
                    count(&catalog, bindings).await
                ),
                before,
                "budget {budget}"
            );
        }
        let prepared = export_within(&snapshots, info.id, complete).await.unwrap();
        assert!(prepared.stopped_snapshot);
        assert!(count(&catalog, bindings).await > before.1);
    }
}
