use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::changeset::model::{ContentDigest, StreamIdentity};
use crate::vm_artifact::wire::{
    self, ChunkEntry, GuestPlatform, ObjectBinding, ObjectTablePage, ObjectTableRoot,
    PayloadMediaType, PayloadRef, RecordBlob, RecordRef, StreamBinding, StreamTablePage,
    StreamTableRoot, TransferPage, TransferRoot, VmArtifactConfigV1, CHUNK_SIZE, CONFIG_MEDIA_TYPE,
    MAX_ARTIFACT_BYTES, MAX_METADATA_BYTES, MAX_PAGE_ENTRIES, MAX_STREAM_BYTES,
};
use crate::vm_artifact::{invalid, Error, Result};

pub const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const ARTIFACT_TYPE: &str = "application/vnd.silo.vm.v1";
pub const METADATA_ARTIFACT_TYPE: &str = "application/vnd.silo.vm.metadata.v1";
pub const PAYLOAD_ARTIFACT_TYPE: &str = "application/vnd.silo.vm.payloads.v1";
pub const EMPTY_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";

/// OCI descriptors, unlike closed Silo records, can carry standard optional
/// metadata. URLs are inert and never used for fetching by this module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: ContentDigest,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(
        default,
        rename = "os.version",
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
    #[serde(
        default,
        rename = "os.features",
        skip_serializing_if = "Option::is_none"
    )]
    pub os_features: Option<Vec<String>>,
}
impl Descriptor {
    pub fn new(media_type: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            media_type: media_type.into(),
            digest: ContentDigest::of_bytes(bytes),
            size: bytes.len() as u64,
            artifact_type: None,
            platform: None,
            annotations: None,
            urls: None,
            data: None,
        }
    }
    pub fn from_payload(payload: PayloadRef) -> Self {
        Self {
            media_type: payload.media_type.as_str().into(),
            digest: payload.digest,
            size: payload.size,
            artifact_type: None,
            platform: None,
            annotations: None,
            urls: None,
            data: None,
        }
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.size || ContentDigest::of_bytes(bytes) != self.digest {
            return Err(invalid("descriptor byte size/SHA256 mismatch"));
        }
        if let Some(data) = &self.data {
            use base64::Engine;
            let inline = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|_| invalid("invalid inline descriptor data"))?;
            if inline != bytes {
                return Err(invalid("inline descriptor data mismatch"));
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u32,
    media_type: String,
    artifact_type: String,
    manifests: Vec<Descriptor>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    media_type: String,
    artifact_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Debug)]
pub struct VerifiedVmGraph {
    index_bytes: Vec<u8>,
    index_digest: ContentDigest,
    config: VmArtifactConfigV1,
    config_bytes: Vec<u8>,
    metadata_manifest_bytes: Vec<u8>,
    inventory: BTreeMap<ContentDigest, PayloadRef>,
    streams: Vec<StreamBinding>,
    objects: Vec<ObjectBinding>,
    transfers: BTreeMap<StreamIdentity, TransferRoot>,
}
impl VerifiedVmGraph {
    pub fn index_bytes(&self) -> &[u8] {
        &self.index_bytes
    }
    pub fn index_digest(&self) -> ContentDigest {
        self.index_digest
    }
    pub fn config(&self) -> &VmArtifactConfigV1 {
        &self.config
    }
    pub fn config_bytes(&self) -> &[u8] {
        &self.config_bytes
    }
    pub fn metadata_manifest_bytes(&self) -> &[u8] {
        &self.metadata_manifest_bytes
    }
    pub fn inventory(&self) -> &BTreeMap<ContentDigest, PayloadRef> {
        &self.inventory
    }
    pub fn payload(&self, digest: ContentDigest) -> Option<&PayloadRef> {
        self.inventory.get(&digest)
    }
    pub fn streams(&self) -> &[StreamBinding] {
        &self.streams
    }
    pub fn objects(&self) -> &[ObjectBinding] {
        &self.objects
    }
    pub fn transfer(&self, stream: StreamIdentity) -> Option<&TransferRoot> {
        self.transfers.get(&stream)
    }
}

enum Task {
    Child(usize),
    Empty,
    Config,
    StreamsRoot,
    ObjectsRoot,
    StreamsPage,
    ObjectsPage,
    TransferRoot(StreamIdentity, u64),
    TransferPage(StreamIdentity),
}
struct Pending {
    descriptor: Descriptor,
    task: Task,
}

/// An incremental verifier: each metadata blob is consumed once, and transfer
/// pages are dropped after validation. Bulk payloads are never fetched here.
/// The caller retains operation-owned exact metadata bytes for later consumers.
pub struct GraphVerifier {
    index_bytes: Vec<u8>,
    index: Index,
    pending: VecDeque<Pending>,
    metadata_config: Option<Descriptor>,
    config: Option<VmArtifactConfigV1>,
    config_bytes: Vec<u8>,
    metadata_manifest_bytes: Vec<u8>,
    inventory: BTreeMap<ContentDigest, PayloadRef>,
    referenced: BTreeSet<ContentDigest>,
    previous_payload: Option<ContentDigest>,
    streams: Vec<StreamBinding>,
    objects: Vec<ObjectBinding>,
    stream_count: Option<u64>,
    object_count: Option<u64>,
    stream_bytes: u64,
    transfers: BTreeMap<StreamIdentity, TransferRoot>,
    transfer_counts: BTreeMap<StreamIdentity, u64>,
    failed: bool,
}
impl GraphVerifier {
    pub fn new(index_bytes: &[u8]) -> Result<Self> {
        let index: Index = wire::decode_record(index_bytes)?;
        if index.schema_version != 2
            || index.media_type != INDEX_MEDIA_TYPE
            || index.artifact_type != ARTIFACT_TYPE
            || index.manifests.is_empty()
            || index.manifests.len() > MAX_PAGE_ENTRIES + 1
        {
            return Err(invalid("invalid VM index type/schema/child count"));
        }
        let mut pending = VecDeque::new();
        let mut seen = BTreeSet::new();
        for (position, descriptor) in index.manifests.iter().enumerate() {
            if descriptor.media_type != MANIFEST_MEDIA_TYPE
                || descriptor.size > MAX_METADATA_BYTES as u64
                || !seen.insert(descriptor.digest)
            {
                return Err(invalid("invalid/duplicate child manifest descriptor"));
            }
            if position == 0 {
                if descriptor.platform.is_none() {
                    return Err(invalid("metadata descriptor lacks guest platform"));
                }
            } else if descriptor.platform.is_some() {
                return Err(invalid("payload child has platform"));
            }
            let expected_type = if position == 0 {
                METADATA_ARTIFACT_TYPE
            } else {
                PAYLOAD_ARTIFACT_TYPE
            };
            if descriptor
                .artifact_type
                .as_deref()
                .is_some_and(|kind| kind != expected_type)
            {
                return Err(invalid("contradictory child artifact type"));
            }
            pending.push_back(Pending {
                descriptor: descriptor.clone(),
                task: Task::Child(position),
            });
        }
        Ok(Self {
            index_bytes: index_bytes.to_vec(),
            index,
            pending,
            metadata_config: None,
            config: None,
            config_bytes: Vec::new(),
            metadata_manifest_bytes: Vec::new(),
            inventory: BTreeMap::new(),
            referenced: BTreeSet::new(),
            previous_payload: None,
            streams: Vec::new(),
            objects: Vec::new(),
            stream_count: None,
            object_count: None,
            stream_bytes: 0,
            transfers: BTreeMap::new(),
            transfer_counts: BTreeMap::new(),
            failed: false,
        })
    }
    pub fn next_descriptor(&self) -> Option<&Descriptor> {
        self.pending.front().map(|pending| &pending.descriptor)
    }
    pub fn accept_metadata(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed {
            return Err(invalid("graph verifier previously failed"));
        }
        let result = self.accept_metadata_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn accept_metadata_inner(&mut self, bytes: &[u8]) -> Result<()> {
        // Do not consume a work item until its exact descriptor has verified.
        let current = self
            .pending
            .front()
            .ok_or_else(|| invalid("no pending graph metadata"))?;
        if current.descriptor.size > MAX_METADATA_BYTES as u64 {
            return Err(invalid("metadata descriptor byte bound"));
        }
        current.descriptor.verify(bytes)?;
        let current = self
            .pending
            .pop_front()
            .ok_or_else(|| invalid("missing graph work item"))?;
        match current.task {
            Task::Child(position) => self.accept_child(position, bytes)?,
            Task::Empty => {
                if bytes != b"{}" {
                    return Err(invalid("OCI empty JSON must be exactly two bytes"));
                }
            }
            Task::Config => {
                let config = wire::decode_vm_config(bytes)?;
                let platform = self
                    .index
                    .manifests
                    .first()
                    .and_then(|descriptor| descriptor.platform.as_ref())
                    .ok_or_else(|| invalid("missing metadata platform"))?;
                if *platform != platform_for(&config.guest_platform)? {
                    return Err(invalid("metadata platform/config mismatch"));
                }
                self.require_payload(config.content.record.payload())?;
                if let Some(provenance) = config.capture_provenance {
                    self.require_payload(provenance.payload())?;
                }
                self.push_record(config.streams, Task::StreamsRoot)?;
                self.push_record(config.objects, Task::ObjectsRoot)?;
                self.config_bytes = bytes.to_vec();
                self.config = Some(config);
            }
            Task::StreamsRoot => {
                let root: StreamTableRoot = wire::decode_record(bytes)?;
                validate_table_root(
                    root.schema,
                    &root.kind,
                    "stream-table",
                    root.entries,
                    &root.pages,
                )?;
                self.stream_count = Some(root.entries);
                for reference in root.pages {
                    self.push_record(reference, Task::StreamsPage)?;
                }
            }
            Task::ObjectsRoot => {
                let root: ObjectTableRoot = wire::decode_record(bytes)?;
                validate_table_root(
                    root.schema,
                    &root.kind,
                    "object-table",
                    root.entries,
                    &root.pages,
                )?;
                self.object_count = Some(root.entries);
                for reference in root.pages {
                    self.push_record(reference, Task::ObjectsPage)?;
                }
            }
            Task::StreamsPage => {
                let page: StreamTablePage = wire::decode_record(bytes)?;
                validate_table_page(
                    page.schema,
                    &page.kind,
                    "stream-table-page",
                    page.first_entry,
                    page.entries.len(),
                    self.streams.len(),
                    self.stream_count,
                )?;
                for binding in page.entries {
                    if self
                        .streams
                        .last()
                        .is_some_and(|previous| previous.stream >= binding.stream)
                        || binding.length > MAX_STREAM_BYTES
                        || binding.map_pages.len() > MAX_PAGE_ENTRIES
                    {
                        return Err(invalid("stream table order/length/map-page bound"));
                    }
                    self.stream_bytes = self
                        .stream_bytes
                        .checked_add(binding.length)
                        .ok_or_else(|| invalid("stream budget overflow"))?;
                    if self.stream_bytes > MAX_ARTIFACT_BYTES {
                        return Err(invalid("artifact decoded stream budget"));
                    }
                    self.push_record(
                        binding.transport,
                        Task::TransferRoot(binding.stream, binding.length),
                    )?;
                    self.streams.push(binding);
                }
            }
            Task::ObjectsPage => {
                let page: ObjectTablePage = wire::decode_record(bytes)?;
                validate_table_page(
                    page.schema,
                    &page.kind,
                    "object-table-page",
                    page.first_entry,
                    page.entries.len(),
                    self.objects.len(),
                    self.object_count,
                )?;
                for binding in page.entries {
                    if self
                        .objects
                        .last()
                        .is_some_and(|previous| previous.object() >= binding.object())
                        || binding.size() > MAX_STREAM_BYTES
                    {
                        return Err(invalid("object table order/size"));
                    }
                    if let ObjectBinding::Direct {
                        object,
                        size,
                        payload,
                    } = &binding
                    {
                        if *object != payload.digest || *size != payload.size {
                            return Err(invalid("direct object/payload mismatch"));
                        }
                        if matches!(
                            payload.media_type,
                            PayloadMediaType::RawChunk | PayloadMediaType::ZstdChunk
                        ) {
                            return Err(invalid("direct object cannot use chunk media"));
                        }
                        self.require_payload(*payload)?;
                    }
                    self.objects.push(binding);
                }
            }
            Task::TransferRoot(stream, length) => {
                let root: TransferRoot = wire::decode_record(bytes)?;
                if root.schema != 1
                    || root.kind != "silo-chunks-v1"
                    || root.stream != stream
                    || root.length != length
                    || root.chunk_size != CHUNK_SIZE
                    || root.pages.len() > MAX_PAGE_ENTRIES
                {
                    return Err(invalid("invalid/mismatched transfer root"));
                }
                let count = length.div_ceil(CHUNK_SIZE);
                if root.pages.len() as u64 > count || root.pages.is_empty() != (count == 0) {
                    return Err(invalid("transfer root page coverage"));
                }
                let mut seen = BTreeSet::new();
                for digest in &root.pages {
                    if !seen.insert(*digest) {
                        return Err(invalid("duplicate transfer page"));
                    }
                    let payload = *self
                        .inventory
                        .get(digest)
                        .ok_or_else(|| invalid("transfer page lacks OCI descriptor"))?;
                    if payload.media_type != PayloadMediaType::Record {
                        return Err(invalid("transfer page media"));
                    }
                    self.push_record(
                        RecordRef {
                            digest: *digest,
                            size: payload.size,
                        },
                        Task::TransferPage(stream),
                    )?;
                }
                if self.transfers.insert(stream, root).is_some() {
                    return Err(invalid("multiple selected transfer roots"));
                }
                self.transfer_counts.insert(stream, 0);
            }
            Task::TransferPage(stream) => {
                let page: TransferPage = wire::decode_record(bytes)?;
                let root = self
                    .transfers
                    .get(&stream)
                    .ok_or_else(|| invalid("transfer page before root"))?;
                let mut count = *self
                    .transfer_counts
                    .get(&stream)
                    .ok_or_else(|| invalid("missing transfer coverage state"))?;
                let length = root.length;
                let expected = length.div_ceil(CHUNK_SIZE);
                if page.schema != 1
                    || page.kind != "silo-chunk-map"
                    || page.first_chunk != count
                    || page.entries.is_empty()
                    || page.entries.len() > MAX_PAGE_ENTRIES
                    || page.entries.len() as u64 > expected.saturating_sub(count)
                {
                    return Err(invalid("transfer page order/count"));
                }
                for entry in page.entries {
                    entry.validate()?;
                    let offset = count
                        .checked_mul(CHUNK_SIZE)
                        .ok_or_else(|| invalid("chunk offset overflow"))?;
                    if entry.length() != CHUNK_SIZE.min(length - offset) {
                        return Err(invalid("nonfinal short transfer chunk"));
                    }
                    if let ChunkEntry::Data { encoded, .. } = entry {
                        self.require_payload(encoded)?;
                    }
                    count += 1;
                }
                self.transfer_counts.insert(stream, count);
            }
        }
        Ok(())
    }
    fn accept_child(&mut self, position: usize, bytes: &[u8]) -> Result<()> {
        let manifest: Manifest = wire::decode_record(bytes)?;
        let expected_type = if position == 0 {
            METADATA_ARTIFACT_TYPE
        } else {
            PAYLOAD_ARTIFACT_TYPE
        };
        if manifest.schema_version != 2
            || manifest.media_type != MANIFEST_MEDIA_TYPE
            || manifest.artifact_type != expected_type
        {
            return Err(invalid("child manifest type/schema/depth"));
        }
        if position == 0 {
            if manifest.config.media_type != CONFIG_MEDIA_TYPE
                || manifest.config.size > MAX_METADATA_BYTES as u64
                || manifest.layers.len() != 1
                || !is_empty_descriptor(&manifest.layers[0])
            {
                return Err(invalid("metadata config/empty layer shape"));
            }
            self.metadata_config = Some(manifest.config);
            self.metadata_manifest_bytes = bytes.to_vec();
            self.pending.push_back(Pending {
                descriptor: manifest.layers[0].clone(),
                task: Task::Empty,
            });
        } else {
            if !is_empty_descriptor(&manifest.config)
                || manifest.layers.is_empty()
                || manifest.layers.len() > MAX_PAGE_ENTRIES
            {
                return Err(invalid("payload manifest config/layer count"));
            }
            manifest.config.verify(b"{}")?;
            for descriptor in manifest.layers {
                if descriptor.platform.is_some() || descriptor.artifact_type.is_some() {
                    return Err(invalid("payload descriptor has manifest metadata"));
                }
                let media_type: PayloadMediaType = serde_json::from_value(
                    serde_json::Value::String(descriptor.media_type.clone()),
                )?;
                let payload = PayloadRef {
                    media_type,
                    digest: descriptor.digest,
                    size: descriptor.size,
                };
                payload.validate()?;
                if self
                    .previous_payload
                    .is_some_and(|previous| previous >= payload.digest)
                {
                    return Err(invalid("payload inventory is not unique/sorted"));
                }
                // Inline bulk data is not an alternative acquisition route. If
                // present, authenticate it immediately without following URLs.
                if let Some(data) = &descriptor.data {
                    use base64::Engine;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(data)
                        .map_err(|_| invalid("invalid inline payload"))?;
                    descriptor.verify(&bytes)?;
                }
                self.previous_payload = Some(payload.digest);
                self.inventory.insert(payload.digest, payload);
            }
        }
        if position + 1 == self.index.manifests.len() {
            let descriptor = self
                .metadata_config
                .clone()
                .ok_or_else(|| invalid("missing metadata config"))?;
            self.pending.push_back(Pending {
                descriptor,
                task: Task::Config,
            });
        }
        Ok(())
    }
    fn require_payload(&mut self, payload: PayloadRef) -> Result<()> {
        payload.validate()?;
        if self.inventory.get(&payload.digest) != Some(&payload) {
            return Err(invalid(
                "reference missing/conflicting OCI payload descriptor",
            ));
        }
        self.referenced.insert(payload.digest);
        Ok(())
    }
    fn push_record(&mut self, reference: RecordRef, task: Task) -> Result<()> {
        self.require_payload(reference.payload())?;
        self.pending.push_back(Pending {
            descriptor: Descriptor::from_payload(reference.payload()),
            task,
        });
        Ok(())
    }
    pub fn finish(self) -> Result<VerifiedVmGraph> {
        if self.failed {
            return Err(invalid("graph verifier previously failed"));
        }
        if !self.pending.is_empty() {
            return Err(invalid("incomplete graph metadata verification"));
        }
        let config = self.config.ok_or_else(|| invalid("missing VM config"))?;
        if self.stream_count != Some(self.streams.len() as u64)
            || self.object_count != Some(self.objects.len() as u64)
        {
            return Err(invalid("table entry coverage mismatch"));
        }
        for (stream, root) in &self.transfers {
            if self.transfer_counts.get(stream).copied() != Some(root.length.div_ceil(CHUNK_SIZE)) {
                return Err(invalid("incomplete transport chunk coverage"));
            }
        }
        let objects: BTreeMap<_, _> = self
            .objects
            .iter()
            .map(|binding| (binding.object(), binding))
            .collect();
        for binding in &self.streams {
            for digest in std::iter::once(&binding.map).chain(&binding.map_pages) {
                if !matches!(
                    objects.get(digest),
                    Some(ObjectBinding::Direct {
                        payload: PayloadRef {
                            media_type: PayloadMediaType::Record,
                            ..
                        },
                        ..
                    })
                ) {
                    return Err(invalid("canonical map missing direct record binding"));
                }
            }
        }
        for binding in &self.objects {
            if let ObjectBinding::Stream { size, stream, .. } = binding {
                if self
                    .streams
                    .binary_search_by_key(stream, |binding| binding.stream)
                    .ok()
                    .and_then(|index| self.streams.get(index))
                    .is_none_or(|binding| binding.length != *size)
                {
                    return Err(invalid("streamed object lacks matching stream"));
                }
            }
        }
        for reference in [Some(config.content.record), config.capture_provenance]
            .into_iter()
            .flatten()
        {
            if !matches!(objects.get(&reference.digest), Some(ObjectBinding::Direct { size, payload: PayloadRef { media_type: PayloadMediaType::Record, .. }, .. }) if *size == reference.size)
            {
                return Err(invalid("semantic record/provenance missing object binding"));
            }
        }
        if self.referenced.len() != self.inventory.len() {
            return Err(invalid("unreferenced payload inventory entries"));
        }
        Ok(VerifiedVmGraph {
            index_digest: ContentDigest::of_bytes(&self.index_bytes),
            index_bytes: self.index_bytes,
            config,
            config_bytes: self.config_bytes,
            metadata_manifest_bytes: self.metadata_manifest_bytes,
            inventory: self.inventory,
            streams: self.streams,
            objects: self.objects,
            transfers: self.transfers,
        })
    }
}

pub fn verify_vm_graph(
    index_bytes: &[u8],
    mut fetch: impl FnMut(&Descriptor) -> Result<Vec<u8>>,
) -> Result<VerifiedVmGraph> {
    let mut verifier = GraphVerifier::new(index_bytes)?;
    while let Some(descriptor) = verifier.next_descriptor() {
        let bytes = fetch(descriptor)?;
        verifier.accept_metadata(&bytes)?;
    }
    verifier.finish()
}

fn validate_table_root(
    schema: u32,
    kind: &str,
    expected: &str,
    entries: u64,
    pages: &[RecordRef],
) -> Result<()> {
    if schema != 1
        || kind != expected
        || pages.len() > MAX_PAGE_ENTRIES
        || entries > (MAX_PAGE_ENTRIES * MAX_PAGE_ENTRIES) as u64
        || pages.is_empty() != (entries == 0)
        || pages.len() as u64 > entries
    {
        return Err(invalid("invalid table root bounds/count"));
    }
    let mut seen = BTreeSet::new();
    for reference in pages {
        reference.payload().validate()?;
        if !seen.insert(reference.digest) {
            return Err(invalid("repeated table page"));
        }
    }
    Ok(())
}
fn validate_table_page(
    schema: u32,
    kind: &str,
    expected: &str,
    first: u64,
    entries: usize,
    consumed: usize,
    total: Option<u64>,
) -> Result<()> {
    let total = total.ok_or_else(|| invalid("table page before root"))?;
    if schema != 1
        || kind != expected
        || first != consumed as u64
        || entries == 0
        || entries > MAX_PAGE_ENTRIES
        || entries as u64 > total.saturating_sub(consumed as u64)
    {
        return Err(invalid("table page ordering/count"));
    }
    Ok(())
}
fn empty_descriptor() -> Descriptor {
    Descriptor::new(EMPTY_MEDIA_TYPE, b"{}")
}
fn is_empty_descriptor(descriptor: &Descriptor) -> bool {
    descriptor.media_type == EMPTY_MEDIA_TYPE
        && descriptor.size == 2
        && descriptor.digest == ContentDigest::of_bytes(b"{}")
        && descriptor.platform.is_none()
        && descriptor.artifact_type.is_none()
}
fn platform_for(platform: &GuestPlatform) -> Result<Platform> {
    Ok(Platform {
        os: serde_json::from_value(serde_json::to_value(platform.os)?)?,
        architecture: serde_json::from_value(serde_json::to_value(platform.architecture)?)?,
        variant: None,
        os_version: None,
        os_features: None,
    })
}

#[derive(Debug, Clone)]
pub struct EncodedBlob {
    pub descriptor: Descriptor,
    pub bytes: Vec<u8>,
}
#[derive(Debug)]
pub struct EncodedVmGraph {
    pub index: EncodedBlob,
    pub children: Vec<EncodedBlob>,
    pub config: EncodedBlob,
    pub records: Vec<RecordBlob>,
    pub empty: EncodedBlob,
    pub payloads: Vec<PayloadRef>,
}

/// Build one fixed byte encoding. Caller-supplied payload descriptors must refer
/// to verified held bytes; the graph builder does not acquire or own bulk data.
pub fn encode_vm_graph(
    config: &VmArtifactConfigV1,
    records: &[RecordBlob],
    payloads: &[PayloadRef],
) -> Result<EncodedVmGraph> {
    config.validate()?;
    let config_bytes = wire::canonical_bytes(config)?;
    let config_blob = EncodedBlob {
        descriptor: Descriptor::new(CONFIG_MEDIA_TYPE, &config_bytes),
        bytes: config_bytes,
    };
    let mut inventory = BTreeMap::new();
    let mut record_bytes = BTreeMap::new();
    for record in records {
        record.reference.payload().validate()?;
        if record.reference != RecordRef::of_bytes(&record.bytes) {
            return Err(invalid("record bytes/reference mismatch"));
        }
        if let Some(previous) =
            record_bytes.insert(record.reference.digest, record.bytes.as_slice())
        {
            if previous != record.bytes {
                return Err(invalid("contradictory duplicate record"));
            }
        }
        insert_payload(&mut inventory, record.reference.payload())?;
    }
    for payload in payloads {
        insert_payload(&mut inventory, *payload)?;
    }
    let metadata = Manifest {
        schema_version: 2,
        media_type: MANIFEST_MEDIA_TYPE.into(),
        artifact_type: METADATA_ARTIFACT_TYPE.into(),
        config: config_blob.descriptor.clone(),
        layers: vec![empty_descriptor()],
    };
    let bytes = wire::canonical_bytes(&metadata)?;
    let mut children = vec![EncodedBlob {
        descriptor: Descriptor::new(MANIFEST_MEDIA_TYPE, &bytes),
        bytes,
    }];
    let mut layers = Vec::new();
    // Serialized descriptor size is exact. The empty manifest contains the two
    // brackets already, so each additional layer adds its bytes and a comma.
    let empty_manifest = Manifest {
        schema_version: 2,
        media_type: MANIFEST_MEDIA_TYPE.into(),
        artifact_type: PAYLOAD_ARTIFACT_TYPE.into(),
        config: empty_descriptor(),
        layers: Vec::new(),
    };
    let base_size = wire::canonical_bytes(&empty_manifest)?.len();
    let mut size = base_size;
    for payload in inventory.values() {
        let descriptor = Descriptor::from_payload(*payload);
        let descriptor_size = wire::canonical_bytes(&descriptor)?.len();
        let additional = descriptor_size + usize::from(!layers.is_empty());
        if !layers.is_empty()
            && (layers.len() == MAX_PAGE_ENTRIES || size + additional > MAX_METADATA_BYTES)
        {
            push_payload_child(&mut children, std::mem::take(&mut layers))?;
            size = base_size;
        }
        size += descriptor_size + usize::from(!layers.is_empty());
        layers.push(descriptor);
    }
    if !layers.is_empty() {
        push_payload_child(&mut children, layers)?;
    }
    let mut descriptors = Vec::with_capacity(children.len());
    for (position, child) in children.iter().enumerate() {
        let mut descriptor = child.descriptor.clone();
        descriptor.artifact_type = Some(
            if position == 0 {
                METADATA_ARTIFACT_TYPE
            } else {
                PAYLOAD_ARTIFACT_TYPE
            }
            .into(),
        );
        if position == 0 {
            descriptor.platform = Some(platform_for(&config.guest_platform)?);
        }
        descriptors.push(descriptor);
    }
    let index = Index {
        schema_version: 2,
        media_type: INDEX_MEDIA_TYPE.into(),
        artifact_type: ARTIFACT_TYPE.into(),
        manifests: descriptors,
    };
    let bytes = wire::canonical_bytes(&index)?;
    let index_blob = EncodedBlob {
        descriptor: Descriptor::new(INDEX_MEDIA_TYPE, &bytes),
        bytes,
    };
    // Run the same structural verifier without fetching bulk payloads. A record
    // absent from held metadata is an error, not an implicit network lookup.
    {
        let child_bytes: BTreeMap<_, _> = children
            .iter()
            .map(|child| (child.descriptor.digest, child.bytes.as_slice()))
            .collect();
        let mut verifier = GraphVerifier::new(&index_blob.bytes)?;
        while let Some(descriptor) = verifier.next_descriptor() {
            let bytes = if descriptor.digest == config_blob.descriptor.digest {
                config_blob.bytes.as_slice()
            } else if is_empty_descriptor(descriptor) {
                b"{}".as_slice()
            } else if let Some(bytes) = child_bytes.get(&descriptor.digest) {
                bytes
            } else {
                record_bytes
                    .get(&descriptor.digest)
                    .copied()
                    .ok_or_else(|| Error::MissingMetadata(Box::new(descriptor.clone())))?
            };
            verifier.accept_metadata(bytes)?;
        }
        verifier.finish()?;
    }
    Ok(EncodedVmGraph {
        index: index_blob,
        children,
        config: config_blob,
        records: records.to_vec(),
        empty: EncodedBlob {
            descriptor: empty_descriptor(),
            bytes: b"{}".to_vec(),
        },
        payloads: inventory.into_values().collect(),
    })
}
fn insert_payload(
    inventory: &mut BTreeMap<ContentDigest, PayloadRef>,
    payload: PayloadRef,
) -> Result<()> {
    payload.validate()?;
    if inventory
        .insert(payload.digest, payload)
        .is_some_and(|previous| previous != payload)
    {
        return Err(invalid("conflicting payload media/size for digest"));
    }
    Ok(())
}
fn push_payload_child(children: &mut Vec<EncodedBlob>, layers: Vec<Descriptor>) -> Result<()> {
    if children.len() > MAX_PAGE_ENTRIES {
        return Err(invalid("too many payload children"));
    }
    let manifest = Manifest {
        schema_version: 2,
        media_type: MANIFEST_MEDIA_TYPE.into(),
        artifact_type: PAYLOAD_ARTIFACT_TYPE.into(),
        config: empty_descriptor(),
        layers,
    };
    let bytes = wire::canonical_bytes(&manifest)?;
    children.push(EncodedBlob {
        descriptor: Descriptor::new(MANIFEST_MEDIA_TYPE, &bytes),
        bytes,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::changeset::model::{ContentDigest, StreamIdentity};
    use crate::vm_artifact::graph::{
        self, Descriptor, EncodedVmGraph, GraphVerifier, Index, Manifest, MANIFEST_MEDIA_TYPE,
        MAX_PAGE_ENTRIES,
    };
    use crate::vm_artifact::wire::{
        self, ChunkEntry, ObjectBinding, PayloadMediaType, PayloadRef, RecordBlob, StreamBinding,
        TransferRoot, VmArtifactConfigV1, CHUNK_SIZE,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    fn fixture(chunks: usize) -> (VmArtifactConfigV1, Vec<RecordBlob>, Vec<PayloadRef>) {
        let semantic = RecordBlob::new(br#"{"kind":"semantic-record"}"#.to_vec()).unwrap();
        let map = RecordBlob::new(br#"{"kind":"canonical-map"}"#.to_vec()).unwrap();
        let stream = StreamIdentity::from_sha256([9; 32]);
        let payloads: Vec<_> = (0..chunks)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                PayloadRef {
                    media_type: PayloadMediaType::RawChunk,
                    digest: ContentDigest::from_sha256(bytes),
                    size: CHUNK_SIZE,
                }
            })
            .collect();
        let entries: Vec<_> = payloads
            .iter()
            .map(|payload| ChunkEntry::Data {
                length: CHUNK_SIZE,
                digest: payload.digest,
                encoded: *payload,
            })
            .collect();
        let transfer = wire::encode_transfer(stream, chunks as u64 * CHUNK_SIZE, &entries).unwrap();
        let streams = wire::encode_stream_table(&[StreamBinding {
            stream,
            length: chunks as u64 * CHUNK_SIZE,
            map: map.reference.digest,
            map_pages: vec![],
            transport: transfer.root.reference,
        }])
        .unwrap();
        let mut bindings: Vec<_> = [&semantic, &map]
            .into_iter()
            .map(|record| ObjectBinding::Direct {
                object: record.reference.digest,
                size: record.reference.size,
                payload: record.reference.payload(),
            })
            .collect();
        bindings.sort_by_key(ObjectBinding::object);
        let objects = wire::encode_object_table(&bindings).unwrap();
        let config = wire::decode_vm_config(&serde_json::to_vec(&json!({
            "schema":1,"kind":"vm-artifact","encoding":"silo-chunks-v1",
            "content":{"kind":"image","id":ContentDigest::from_sha256([4;32]),"record":semantic.reference},
            "purpose":"image","captureKind":null,"rootFamily":"opaque-raw","backendRequirement":"raw-block",
            "guestPlatform":{"os":"linux","architecture":"amd64"},
            "minimumCapabilities":{"storageProfile":"opaque-raw-v1","bootAbi":"linux-direct-v1","liveRestore":false},
            "executionRequirements":null,"streams":streams.root.reference,"objects":objects.root.reference,"captureProvenance":null
        })).unwrap()).unwrap();
        let mut records = vec![semantic, map, transfer.root, streams.root, objects.root];
        records.extend(transfer.pages);
        records.extend(streams.pages);
        records.extend(objects.pages);
        (config, records, payloads)
    }
    fn metadata(graph: &EncodedVmGraph) -> BTreeMap<ContentDigest, Vec<u8>> {
        let mut bytes: BTreeMap<_, _> = graph
            .records
            .iter()
            .map(|record| (record.reference.digest, record.bytes.clone()))
            .collect();
        for blob in graph.children.iter().chain([&graph.config, &graph.empty]) {
            bytes.insert(blob.descriptor.digest, blob.bytes.clone());
        }
        bytes
    }
    #[test]
    fn deterministic_graph_exact_bytes_and_no_bulk_fetches() {
        let (config, records, payloads) = fixture(3);
        let encoded = graph::encode_vm_graph(&config, &records, &payloads).unwrap();
        let again = graph::encode_vm_graph(&config, &records, &payloads).unwrap();
        assert_eq!(encoded.index.bytes, again.index.bytes);
        let metadata = metadata(&encoded);
        let mut requests = 0;
        let verified = graph::verify_vm_graph(&encoded.index.bytes, |descriptor| {
            requests += 1;
            Ok(metadata
                .get(&descriptor.digest)
                .expect("only metadata is fetched")
                .clone())
        })
        .unwrap();
        assert!(requests > 3);
        assert_eq!(verified.index_bytes(), encoded.index.bytes);
        assert_eq!(verified.config_bytes(), encoded.config.bytes);
        assert_eq!(
            verified.metadata_manifest_bytes(),
            encoded.children[0].bytes
        );
        assert_eq!(verified.index_digest(), encoded.index.descriptor.digest);
        assert_eq!(verified.streams().len(), 1);
        assert_eq!(verified.objects().len(), 2);
        assert_eq!(verified.config(), &config);
        let mut padded = b" \n".to_vec();
        padded.extend_from_slice(&encoded.index.bytes);
        padded.push(b' ');
        let padded_verified = graph::verify_vm_graph(&padded, |descriptor| {
            Ok(metadata[&descriptor.digest].clone())
        })
        .unwrap();
        assert_eq!(padded_verified.index_bytes(), padded);
        assert_ne!(padded_verified.index_digest(), verified.index_digest());
    }
    #[test]
    fn incremental_cursor_rejects_partial_corrupt_and_recovered_error_states() {
        let (config, records, payloads) = fixture(1);
        let encoded = graph::encode_vm_graph(&config, &records, &payloads).unwrap();
        let metadata = metadata(&encoded);
        assert!(GraphVerifier::new(&encoded.index.bytes)
            .unwrap()
            .finish()
            .is_err());
        let mut cursor = GraphVerifier::new(&encoded.index.bytes).unwrap();
        let descriptor = cursor.next_descriptor().unwrap().clone();
        assert!(cursor.accept_metadata(b"wrong").is_err());
        assert!(cursor
            .accept_metadata(&metadata[&descriptor.digest])
            .is_err());
        assert!(cursor.finish().is_err());
    }
    #[test]
    fn descriptor_inventory_rejects_missing_extra_conflicting_and_wrong_media() {
        let (config, records, payloads) = fixture(1);
        assert!(graph::encode_vm_graph(&config, &records, &[]).is_err());
        let extra = PayloadRef {
            media_type: PayloadMediaType::Execution,
            digest: ContentDigest::of_bytes(b"unused"),
            size: 6,
        };
        let mut extras = payloads.clone();
        extras.push(extra);
        assert!(graph::encode_vm_graph(&config, &records, &extras).is_err());
        let mut conflicting = payloads.clone();
        let mut different = payloads[0];
        different.size -= 1;
        conflicting.push(different);
        assert!(graph::encode_vm_graph(&config, &records, &conflicting).is_err());
        let mut records = records;
        let canonical_map = records
            .iter()
            .find(|record| record.bytes == br#"{"kind":"canonical-map"}"#)
            .unwrap()
            .reference
            .digest;
        records.retain(|record| record.reference.digest != canonical_map);
        assert!(graph::encode_vm_graph(&config, &records, &payloads).is_err());
    }
    #[test]
    fn payload_manifest_partition_is_sorted_unique_and_bounded() {
        let (config, records, payloads) = fixture(MAX_PAGE_ENTRIES + 1);
        let encoded = graph::encode_vm_graph(&config, &records, &payloads).unwrap();
        assert_eq!(encoded.children.len(), 3);
        let mut previous = None;
        for child in encoded.children.iter().skip(1) {
            let manifest: Manifest = wire::decode_record(&child.bytes).unwrap();
            assert!(manifest.layers.len() <= MAX_PAGE_ENTRIES);
            for descriptor in manifest.layers {
                assert!(previous.is_none_or(|digest| digest < descriptor.digest));
                previous = Some(descriptor.digest);
            }
        }
    }
    #[test]
    fn index_admits_4097_children_but_not_an_extra_level_or_platform_payload() {
        let (config, records, payloads) = fixture(0);
        let encoded = graph::encode_vm_graph(&config, &records, &payloads).unwrap();
        let mut index: Index = wire::decode_record(&encoded.index.bytes).unwrap();
        let first = index.manifests[0].clone();
        index.manifests = vec![first];
        for number in 0..MAX_PAGE_ENTRIES {
            let mut descriptor = Descriptor::new(MANIFEST_MEDIA_TYPE, &number.to_be_bytes());
            descriptor.size = 1;
            index.manifests.push(descriptor);
        }
        assert!(GraphVerifier::new(&wire::canonical_bytes(&index).unwrap()).is_ok());
        let mut extra = Descriptor::new(MANIFEST_MEDIA_TYPE, b"extra");
        extra.size = 1;
        index.manifests.push(extra);
        assert!(GraphVerifier::new(&wire::canonical_bytes(&index).unwrap()).is_err());
        index.manifests.pop();
        index.manifests[1].media_type = graph::INDEX_MEDIA_TYPE.into();
        assert!(GraphVerifier::new(&wire::canonical_bytes(&index).unwrap()).is_err());
        index.manifests[1].media_type = MANIFEST_MEDIA_TYPE.into();
        index.manifests[1].platform = index.manifests[0].platform.clone();
        assert!(GraphVerifier::new(&wire::canonical_bytes(&index).unwrap()).is_err());
    }
    #[test]
    fn transfer_roots_are_retained_but_chunk_arrays_are_not() {
        let (config, records, payloads) = fixture(2);
        let encoded = graph::encode_vm_graph(&config, &records, &payloads).unwrap();
        let metadata = metadata(&encoded);
        let verified = graph::verify_vm_graph(&encoded.index.bytes, |descriptor| {
            Ok(metadata[&descriptor.digest].clone())
        })
        .unwrap();
        let stream = &verified.streams()[0];
        let root: &TransferRoot = verified.transfer(stream.stream).unwrap();
        let entries = wire::verify_transfer(root, |digest| Ok(metadata[&digest].clone())).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(root.length, 2 * CHUNK_SIZE);
    }
    #[test]
    fn empty_inline_and_descriptor_bytes_are_exact() {
        let mut descriptor = graph::empty_descriptor();
        descriptor.verify(b"{}").unwrap();
        assert!(descriptor.verify(b"{ }").is_err());
        descriptor.data = Some("eyB9".into());
        assert!(descriptor.verify(b"{}").is_err());
        assert_eq!(
            graph::empty_descriptor().digest.to_string(),
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
    #[test]
    fn table_roots_and_pages_enforce_every_count_boundary() {
        let reference = wire::RecordRef::of_bytes(b"page");
        assert!(graph::validate_table_root(1, "stream-table", "stream-table", 0, &[]).is_ok());
        assert!(
            graph::validate_table_root(1, "stream-table", "stream-table", 1, &[reference]).is_ok()
        );
        for (schema, kind, count, pages) in [
            (2, "stream-table", 1, vec![reference]),
            (1, "wrong", 1, vec![reference]),
            (1, "stream-table", 0, vec![reference]),
            (1, "stream-table", 1, vec![]),
            (1, "stream-table", 2, vec![reference, reference]),
            (1, "stream-table", 1, vec![reference; MAX_PAGE_ENTRIES + 1]),
        ] {
            assert!(
                graph::validate_table_root(schema, kind, "stream-table", count, &pages).is_err()
            );
        }
        assert!(graph::validate_table_page(
            1,
            "object-table-page",
            "object-table-page",
            0,
            1,
            0,
            Some(1)
        )
        .is_ok());
        assert!(graph::validate_table_page(
            1,
            "object-table-page",
            "object-table-page",
            0,
            MAX_PAGE_ENTRIES,
            0,
            Some(MAX_PAGE_ENTRIES as u64)
        )
        .is_ok());
        for (first, count, consumed, total) in [
            (0, 0, 0, Some(0)),
            (1, 1, 0, Some(2)),
            (0, MAX_PAGE_ENTRIES + 1, 0, Some(10000)),
            (0, 2, 0, Some(1)),
            (0, 1, 0, None),
        ] {
            assert!(graph::validate_table_page(
                1,
                "object-table-page",
                "object-table-page",
                first,
                count,
                consumed,
                total
            )
            .is_err());
        }
    }
}
