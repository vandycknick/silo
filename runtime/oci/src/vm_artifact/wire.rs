use std::{collections::BTreeSet, fmt};

use serde::{
    de::{DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::Value;

use crate::changeset::model::{ContentDigest, StreamIdentity};
use crate::vm_artifact::{invalid, Result};

pub const CHUNK_SIZE: u64 = 8 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PAGE_ENTRIES: usize = 4096;
pub const MAX_STREAM_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 4 * MAX_STREAM_BYTES;
pub const JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.silo.vm.config.v1+json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadMediaType {
    #[serde(rename = "application/vnd.silo.vm.record.v1+json")]
    Record,
    #[serde(rename = "application/vnd.silo.vm.chunk.v1")]
    RawChunk,
    #[serde(rename = "application/vnd.silo.vm.chunk.v1+zstd")]
    ZstdChunk,
    #[serde(rename = "application/vnd.silo.vm.execution.v1")]
    Execution,
    #[serde(rename = "application/vnd.silo.vm.device-state.v1")]
    DeviceState,
}
impl PayloadMediaType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Record => "application/vnd.silo.vm.record.v1+json",
            Self::RawChunk => "application/vnd.silo.vm.chunk.v1",
            Self::ZstdChunk => "application/vnd.silo.vm.chunk.v1+zstd",
            Self::Execution => "application/vnd.silo.vm.execution.v1",
            Self::DeviceState => "application/vnd.silo.vm.device-state.v1",
        }
    }
    pub const fn maximum_size(self) -> u64 {
        match self {
            Self::Record => MAX_METADATA_BYTES as u64,
            Self::RawChunk | Self::ZstdChunk => CHUNK_SIZE,
            Self::Execution => 16 * 1024 * 1024,
            Self::DeviceState => 32 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordRef {
    pub digest: ContentDigest,
    pub size: u64,
}
impl RecordRef {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self {
            digest: ContentDigest::of_bytes(bytes),
            size: bytes.len() as u64,
        }
    }
    pub fn payload(self) -> PayloadRef {
        PayloadRef {
            media_type: PayloadMediaType::Record,
            digest: self.digest,
            size: self.size,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadRef {
    pub media_type: PayloadMediaType,
    pub digest: ContentDigest,
    pub size: u64,
}
impl PayloadRef {
    pub fn validate(&self) -> Result<()> {
        if self.size > self.media_type.maximum_size() {
            return Err(invalid("payload exceeds media bound"));
        }
        Ok(())
    }
}

macro_rules! wire_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename = $wire)] $variant),+ }
    };
}
wire_enum!(ContentKind { Image => "image", Snapshot => "snapshot" });
wire_enum!(Purpose { Image => "image", Checkpoint => "checkpoint" });
wire_enum!(CaptureKind { StoppedStorage => "stopped-storage", LiveExecution => "live-execution" });
wire_enum!(RootFamily { OpaqueRaw => "opaque-raw", LinuxOverlay => "linux-overlay" });
wire_enum!(BackendRequirement { RawBlock => "raw-block", KrunOverlay => "krun-overlay" });
wire_enum!(StorageProfile { OpaqueRawV1 => "opaque-raw-v1", LinuxErofsOverlayV1 => "linux-erofs-overlay-v1" });
wire_enum!(GuestOs { Linux => "linux" });
wire_enum!(Architecture { Amd64 => "amd64", Arm64 => "arm64" });

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentRef {
    pub kind: ContentKind,
    pub id: ContentDigest,
    pub record: RecordRef,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestPlatform {
    pub os: GuestOs,
    pub architecture: Architecture,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MinimumCapabilities {
    pub storage_profile: StorageProfile,
    pub boot_abi: String,
    pub live_restore: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityProfile {
    pub live_state_schema: String,
    pub architecture: String,
    pub profile: ContentDigest,
    pub topology: ContentDigest,
    pub ram_layout: ContentDigest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionRequirements {
    pub kind: String,
    pub execution_version: u32,
    pub execution_abi: u32,
    pub device_version: u32,
    pub compatibility_profile: CompatibilityProfile,
}

fn required_nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmArtifactConfigV1 {
    pub schema: u32,
    pub kind: String,
    pub encoding: String,
    pub content: ContentRef,
    pub purpose: Purpose,
    #[serde(deserialize_with = "required_nullable")]
    pub capture_kind: Option<CaptureKind>,
    pub root_family: RootFamily,
    pub backend_requirement: BackendRequirement,
    pub guest_platform: GuestPlatform,
    pub minimum_capabilities: MinimumCapabilities,
    #[serde(deserialize_with = "required_nullable")]
    pub execution_requirements: Option<ExecutionRequirements>,
    pub streams: RecordRef,
    pub objects: RecordRef,
    #[serde(deserialize_with = "required_nullable")]
    pub capture_provenance: Option<RecordRef>,
}
impl VmArtifactConfigV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "vm-artifact" || self.encoding != "silo-chunks-v1" {
            return Err(invalid("unsupported config schema/kind/encoding"));
        }
        let live = self.capture_kind == Some(CaptureKind::LiveExecution);
        match (self.content.kind, self.purpose, self.capture_kind) {
            (ContentKind::Image, Purpose::Image, None)
            | (ContentKind::Snapshot, Purpose::Checkpoint, Some(_)) => {}
            _ => return Err(invalid("inconsistent content kind/purpose/capture kind")),
        }
        if live != self.execution_requirements.is_some()
            || live != self.capture_provenance.is_some()
            || live != self.minimum_capabilities.live_restore
        {
            return Err(invalid("inconsistent execution requirements/provenance"));
        }
        if let Some(requirements) = &self.execution_requirements {
            if requirements.kind != "krun-v1"
                || requirements.execution_version != 1
                || requirements.execution_abi != 1
                || requirements.device_version != 1
            {
                return Err(invalid("unsupported execution schema/ABI"));
            }
            let profile = &requirements.compatibility_profile;
            if profile.live_state_schema.is_empty()
                || profile.live_state_schema.len() > 256
                || profile.live_state_schema.contains('\0')
                || profile.architecture.is_empty()
                || profile.architecture.len() > 32
                || profile.architecture.contains('\0')
            {
                return Err(invalid("state schema or architecture byte bound"));
            }
        }
        match (
            self.root_family,
            self.backend_requirement,
            self.minimum_capabilities.storage_profile,
        ) {
            (RootFamily::OpaqueRaw, BackendRequirement::RawBlock, StorageProfile::OpaqueRawV1)
            | (
                RootFamily::LinuxOverlay,
                BackendRequirement::KrunOverlay,
                StorageProfile::LinuxErofsOverlayV1,
            ) => {}
            _ => return Err(invalid("inconsistent root/backend/storage profile")),
        }
        for reference in [
            Some(self.content.record),
            Some(self.streams),
            Some(self.objects),
            self.capture_provenance,
        ]
        .into_iter()
        .flatten()
        {
            reference.payload().validate()?;
        }
        if self.minimum_capabilities.boot_abi.is_empty() {
            return Err(invalid("empty boot ABI"));
        }
        Ok(())
    }
}
pub fn decode_vm_config(bytes: &[u8]) -> Result<VmArtifactConfigV1> {
    let value: Value = decode_record(bytes)?;
    if let Some(profile) = value
        .pointer("/minimumCapabilities/storageProfile")
        .and_then(Value::as_str)
    {
        if !matches!(profile, "opaque-raw-v1" | "linux-erofs-overlay-v1") {
            return Err(crate::vm_artifact::Error::IncompatibleStorageProfile {
                profile: profile.to_owned(),
            });
        }
    }
    let config: VmArtifactConfigV1 = serde_json::from_value(value)?;
    config.validate()?;
    Ok(config)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamBinding {
    pub stream: StreamIdentity,
    pub length: u64,
    pub map: ContentDigest,
    pub map_pages: Vec<ContentDigest>,
    pub transport: RecordRef,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ObjectBinding {
    Direct {
        object: ContentDigest,
        size: u64,
        payload: PayloadRef,
    },
    Stream {
        object: ContentDigest,
        size: u64,
        stream: StreamIdentity,
    },
}
impl ObjectBinding {
    pub fn object(&self) -> ContentDigest {
        match self {
            Self::Direct { object, .. } | Self::Stream { object, .. } => *object,
        }
    }
    pub fn size(&self) -> u64 {
        match self {
            Self::Direct { size, .. } | Self::Stream { size, .. } => *size,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamTableRoot {
    pub schema: u32,
    pub kind: String,
    pub entries: u64,
    pub pages: Vec<RecordRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamTablePage {
    pub schema: u32,
    pub kind: String,
    pub first_entry: u64,
    pub entries: Vec<StreamBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectTableRoot {
    pub schema: u32,
    pub kind: String,
    pub entries: u64,
    pub pages: Vec<RecordRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectTablePage {
    pub schema: u32,
    pub kind: String,
    pub first_entry: u64,
    pub entries: Vec<ObjectBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferRoot {
    pub schema: u32,
    pub kind: String,
    pub stream: StreamIdentity,
    pub length: u64,
    pub chunk_size: u64,
    pub pages: Vec<ContentDigest>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferPage {
    pub schema: u32,
    pub kind: String,
    pub first_chunk: u64,
    pub entries: Vec<ChunkEntry>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ChunkEntry {
    Zero {
        length: u64,
    },
    Data {
        length: u64,
        digest: ContentDigest,
        encoded: PayloadRef,
    },
}
impl ChunkEntry {
    pub fn length(&self) -> u64 {
        match self {
            Self::Zero { length } | Self::Data { length, .. } => *length,
        }
    }
    pub fn validate(&self) -> Result<()> {
        let length = self.length();
        if length == 0 || length > CHUNK_SIZE {
            return Err(invalid("chunk decoded length outside bounds"));
        }
        if let Self::Data {
            digest, encoded, ..
        } = self
        {
            encoded.validate()?;
            match encoded.media_type {
                PayloadMediaType::RawChunk
                    if encoded.size == length && encoded.digest == *digest => {}
                PayloadMediaType::ZstdChunk if encoded.size > 0 && encoded.size < length => {}
                _ => return Err(invalid("invalid chunk encoding/media/size/digest")),
            }
        }
        Ok(())
    }
}

pub fn verify_transfer(
    root: &TransferRoot,
    fetch_record: impl FnMut(ContentDigest) -> Result<Vec<u8>>,
) -> Result<Vec<ChunkEntry>> {
    let mut entries = Vec::new();
    verify_transfer_to(root, fetch_record, |_, entry| {
        entries.push(entry);
        Ok(())
    })?;
    Ok(entries)
}

/// Visit one admitted chunk at a time, retaining no whole-stream chunk array.
pub fn verify_transfer_to(
    root: &TransferRoot,
    mut fetch_record: impl FnMut(ContentDigest) -> Result<Vec<u8>>,
    mut visit: impl FnMut(u64, ChunkEntry) -> Result<()>,
) -> Result<()> {
    if root.schema != 1
        || root.kind != "silo-chunks-v1"
        || root.chunk_size != CHUNK_SIZE
        || root.length > MAX_STREAM_BYTES
        || root.pages.len() > MAX_PAGE_ENTRIES
    {
        return Err(invalid("invalid transfer root"));
    }
    let expected = root.length.div_ceil(CHUNK_SIZE);
    if root.pages.len() as u64 > expected || (root.pages.is_empty() != (expected == 0)) {
        return Err(invalid("transfer page coverage"));
    }
    let mut count = 0_u64;
    let mut seen = BTreeSet::new();
    for digest in &root.pages {
        if !seen.insert(*digest) {
            return Err(invalid("repeated transfer page"));
        }
        let bytes = fetch_record(*digest)?;
        if ContentDigest::of_bytes(&bytes) != *digest {
            return Err(invalid("transfer page digest mismatch"));
        }
        let page: TransferPage = decode_record(&bytes)?;
        if page.schema != 1
            || page.kind != "silo-chunk-map"
            || page.first_chunk != count
            || page.entries.is_empty()
            || page.entries.len() > MAX_PAGE_ENTRIES
            || page.entries.len() as u64 > expected.saturating_sub(count)
        {
            return Err(invalid("transfer page ordering/count"));
        }
        for entry in page.entries {
            entry.validate()?;
            let offset = count
                .checked_mul(CHUNK_SIZE)
                .ok_or_else(|| invalid("chunk offset overflow"))?;
            if entry.length() != CHUNK_SIZE.min(root.length - offset) {
                return Err(invalid("short/nonfinal transfer chunk"));
            }
            visit(count, entry)?;
            count += 1;
        }
    }
    if count != expected {
        return Err(invalid("incomplete transfer map"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBlob {
    pub reference: RecordRef,
    pub bytes: Vec<u8>,
}
impl RecordBlob {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(invalid("record byte bound"));
        }
        Ok(Self {
            reference: RecordRef::of_bytes(&bytes),
            bytes,
        })
    }
    pub fn encode(value: &impl Serialize) -> Result<Self> {
        Self::new(canonical_bytes(value)?)
    }
}

#[derive(Debug)]
pub struct EncodedTable {
    pub root: RecordBlob,
    pub pages: Vec<RecordBlob>,
}

pub fn encode_stream_table(entries: &[StreamBinding]) -> Result<EncodedTable> {
    let mut previous = None;
    let mut total = 0_u64;
    for entry in entries {
        if previous.is_some_and(|id| id >= entry.stream)
            || entry.length > MAX_STREAM_BYTES
            || entry.map_pages.len() > MAX_PAGE_ENTRIES
        {
            return Err(invalid("stream table order/bounds"));
        }
        entry.transport.payload().validate()?;
        total = total
            .checked_add(entry.length)
            .ok_or_else(|| invalid("stream budget overflow"))?;
        if total > MAX_ARTIFACT_BYTES {
            return Err(invalid("artifact stream budget"));
        }
        previous = Some(entry.stream);
    }
    let pages = paginate(entries, "stream-table-page", "firstEntry")?;
    let root = RecordBlob::encode(&StreamTableRoot {
        schema: 1,
        kind: "stream-table".into(),
        entries: entries.len() as u64,
        pages: pages.iter().map(|page| page.reference).collect(),
    })?;
    Ok(EncodedTable { root, pages })
}

pub fn encode_object_table(entries: &[ObjectBinding]) -> Result<EncodedTable> {
    let mut previous = None;
    for entry in entries {
        if previous.is_some_and(|id| id >= entry.object()) || entry.size() > MAX_STREAM_BYTES {
            return Err(invalid("object table order/bounds"));
        }
        if let ObjectBinding::Direct {
            object,
            size,
            payload,
        } = entry
        {
            payload.validate()?;
            if payload.digest != *object
                || payload.size != *size
                || matches!(
                    payload.media_type,
                    PayloadMediaType::RawChunk | PayloadMediaType::ZstdChunk
                )
            {
                return Err(invalid("direct object representation"));
            }
        }
        previous = Some(entry.object());
    }
    let pages = paginate(entries, "object-table-page", "firstEntry")?;
    let root = RecordBlob::encode(&ObjectTableRoot {
        schema: 1,
        kind: "object-table".into(),
        entries: entries.len() as u64,
        pages: pages.iter().map(|page| page.reference).collect(),
    })?;
    Ok(EncodedTable { root, pages })
}

pub fn encode_transfer(
    stream: StreamIdentity,
    length: u64,
    entries: &[ChunkEntry],
) -> Result<EncodedTable> {
    if length > MAX_STREAM_BYTES || entries.len() as u64 != length.div_ceil(CHUNK_SIZE) {
        return Err(invalid("transfer length/count"));
    }
    for (index, entry) in entries.iter().enumerate() {
        entry.validate()?;
        if entry.length() != CHUNK_SIZE.min(length - index as u64 * CHUNK_SIZE) {
            return Err(invalid("transfer chunk length"));
        }
    }
    let pages = paginate(entries, "silo-chunk-map", "firstChunk")?;
    let root = RecordBlob::encode(&TransferRoot {
        schema: 1,
        kind: "silo-chunks-v1".into(),
        stream,
        length,
        chunk_size: CHUNK_SIZE,
        pages: pages.iter().map(|page| page.reference.digest).collect(),
    })?;
    Ok(EncodedTable { root, pages })
}

fn page_value<T: Serialize>(
    entries: &[T],
    kind: &str,
    first_field: &str,
    first: usize,
) -> Result<Value> {
    let mut object = serde_json::Map::new();
    object.insert("schema".into(), Value::from(1));
    object.insert("kind".into(), Value::String(kind.into()));
    object.insert(first_field.into(), Value::from(first as u64));
    object.insert("entries".into(), serde_json::to_value(entries)?);
    Ok(Value::Object(object))
}

fn paginate<T: Serialize>(entries: &[T], kind: &str, first_field: &str) -> Result<Vec<RecordBlob>> {
    if entries.len() > MAX_PAGE_ENTRIES * MAX_PAGE_ENTRIES {
        return Err(invalid("table capacity bound"));
    }
    let mut pages = Vec::new();
    let mut first = 0;
    while first < entries.len() {
        let mut end = first;
        let mut size = canonical_bytes(&page_value(
            &entries[first..first],
            kind,
            first_field,
            first,
        )?)?
        .len();
        while let Some(entry) = entries.get(end) {
            let additional = canonical_bytes(entry)?.len() + usize::from(end != first);
            if end - first == MAX_PAGE_ENTRIES || size + additional > MAX_METADATA_BYTES {
                break;
            }
            size += additional;
            end += 1;
        }
        if end == first {
            return Err(invalid("one table entry exceeds page byte bound"));
        }
        pages.push(RecordBlob::encode(&page_value(
            &entries[first..end],
            kind,
            first_field,
            first,
        )?)?);
        if pages.len() > MAX_PAGE_ENTRIES {
            return Err(invalid("table root page count bound"));
        }
        first = end;
    }
    Ok(pages)
}

/// Strict JSON parsing also applies to opaque portable evidence without changing
/// its original byte spelling. Silo typed structs separately reject unknown fields.
pub fn strict_value(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(invalid("metadata byte bound"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}
pub fn decode_record<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_json::from_value(strict_value(bytes)?)?)
}
pub fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    // serde_json's default map is ordered lexicographically. These restricted
    // schemas contain only unsigned safe integers, strings, booleans and null.
    let value = serde_json::to_value(value)?;
    let bytes = serde_json::to_vec(&value)?;
    strict_value(&bytes)?;
    Ok(bytes)
}
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("closed bounded JSON")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                if v > JSON_SAFE_INTEGER_MAX {
                    return Err(E::custom("unsafe JSON integer"));
                }
                Ok(StrictValue(Value::from(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<Self::Value, E> {
                Err(E::custom("negative JSON integer"))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Err(E::custom("floating point JSON number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v.into())))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v)))
            }
            fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON field"));
                    }
                    values.insert(key, map.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        d.deserialize_any(StrictVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::changeset::model::{ContentDigest, StreamIdentity};
    use crate::vm_artifact::wire::{
        self, ChunkEntry, RecordBlob, RecordRef, TransferPage, TransferRoot, CHUNK_SIZE,
        MAX_METADATA_BYTES, MAX_PAGE_ENTRIES, MAX_STREAM_BYTES,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    fn config_value() -> serde_json::Value {
        let reference = RecordRef::of_bytes(b"record");
        json!({"schema":1,"kind":"vm-artifact","encoding":"silo-chunks-v1",
            "content":{"kind":"image","id":reference.digest,"record":reference},
            "purpose":"image","captureKind":null,"rootFamily":"opaque-raw","backendRequirement":"raw-block",
            "guestPlatform":{"os":"linux","architecture":"arm64"},
            "minimumCapabilities":{"storageProfile":"opaque-raw-v1","bootAbi":"linux-direct-v1","liveRestore":false},
            "executionRequirements":null,"streams":reference,"objects":reference,"captureProvenance":null})
    }

    #[test]
    fn erofs_profile_is_explicit_and_retired_profiles_have_typed_refusals() {
        let mut value = config_value();
        value["rootFamily"] = json!("linux-overlay");
        value["backendRequirement"] = json!("krun-overlay");
        value["minimumCapabilities"]["storageProfile"] = json!("linux-erofs-overlay-v1");
        assert!(wire::decode_vm_config(&wire::canonical_bytes(&value).unwrap()).is_ok());
        for profile in [
            "linux-overlay-v1",
            "linux-flat-overlay-v1",
            "future-overlay-v9",
        ] {
            value["minimumCapabilities"]["storageProfile"] = json!(profile);
            assert!(matches!(
                wire::decode_vm_config(&wire::canonical_bytes(&value).unwrap()),
                Err(crate::vm_artifact::Error::IncompatibleStorageProfile { profile: refused })
                    if refused == profile
            ));
        }
    }
    #[test]
    fn config_golden_and_required_nullable_closed_fields() {
        let value = config_value();
        let bytes = wire::canonical_bytes(&value).unwrap();
        let config = wire::decode_vm_config(&bytes).unwrap();
        assert_eq!(wire::canonical_bytes(&config).unwrap(), bytes);
        for field in [
            "schema",
            "captureKind",
            "executionRequirements",
            "captureProvenance",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                wire::decode_vm_config(&serde_json::to_vec(&missing).unwrap()).is_err(),
                "{field}"
            );
        }
        for (field, replacement) in [
            ("schema", json!(2)),
            ("rootFamily", json!("unknown")),
            ("backendRequirement", json!("krun-overlay")),
            ("captureKind", json!("live-execution")),
            ("extra", json!(true)),
        ] {
            let mut bad = value.clone();
            bad[field] = replacement;
            assert!(
                wire::decode_vm_config(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut bad = value;
        bad["guestPlatform"]["unexpected"] = json!(0);
        assert!(wire::decode_vm_config(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    #[test]
    fn live_requirements_use_state_schema_architecture_and_closed_versions() {
        let mut value = config_value();
        let digest = ContentDigest::of_bytes(b"pin");
        value["content"]["kind"] = json!("snapshot");
        value["purpose"] = json!("checkpoint");
        value["captureKind"] = json!("live-execution");
        value["minimumCapabilities"]["liveRestore"] = json!(true);
        value["captureProvenance"] = json!(RecordRef::of_bytes(b"provenance"));
        value["executionRequirements"] = json!({"kind":"krun-v1","executionVersion":1,"executionAbi":1,"deviceVersion":1,
            "compatibilityProfile":{"liveStateSchema":"silo.live-state/1","architecture":"x86_64","profile":digest,"topology":digest,"ramLayout":digest}});
        assert!(wire::decode_vm_config(&serde_json::to_vec(&value).unwrap()).is_ok());
        for schema in [json!(""), json!("x".repeat(257)), json!(false)] {
            let mut bad = value.clone();
            bad["executionRequirements"]["compatibilityProfile"]["liveStateSchema"] = schema;
            assert!(wire::decode_vm_config(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        for architecture in [json!(""), json!("x".repeat(33)), json!(false)] {
            let mut bad = value.clone();
            bad["executionRequirements"]["compatibilityProfile"]["architecture"] = architecture;
            assert!(wire::decode_vm_config(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        for field in ["executionVersion", "executionAbi", "deviceVersion"] {
            let mut bad = value.clone();
            bad["executionRequirements"][field] = json!(2);
            assert!(wire::decode_vm_config(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        for field in ["executionRequirements", "captureProvenance"] {
            let mut bad = value.clone();
            bad[field] = serde_json::Value::Null;
            assert!(wire::decode_vm_config(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
    #[test]
    fn strict_parser_rejects_duplicate_unsafe_numbers_and_depth() {
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":{"x":null,"x":null}}"#,
            br#"{"n":-1}"#,
            br#"{"n":-0}"#,
            br#"{"n":1.0}"#,
            br#"{"n":9007199254740992}"#,
            br#"{} {}"#,
        ] {
            assert!(wire::strict_value(bytes).is_err());
        }
        let deep = format!("{}null{}", "[".repeat(130), "]".repeat(130));
        assert!(wire::strict_value(deep.as_bytes()).is_err());
        assert!(wire::strict_value(&vec![b' '; MAX_METADATA_BYTES + 1]).is_err());
        let upper = format!(r#"{{"digest":"sha256:{}","size":0}}"#, "AB".repeat(32));
        assert!(wire::decode_record::<RecordRef>(upper.as_bytes()).is_err());
    }
    #[test]
    fn greedy_pages_split_at_exact_entry_and_byte_bounds() {
        let entries = vec![0_u64; MAX_PAGE_ENTRIES + 1];
        let pages = wire::paginate(&entries, "test-page", "firstEntry").unwrap();
        assert_eq!(pages.len(), 2);
        let first = wire::strict_value(&pages[0].bytes).unwrap();
        let second = wire::strict_value(&pages[1].bytes).unwrap();
        assert_eq!(first["entries"].as_array().unwrap().len(), MAX_PAGE_ENTRIES);
        assert_eq!(second["firstEntry"], MAX_PAGE_ENTRIES);
        let empty_size = wire::canonical_bytes(
            &wire::page_value::<String>(&[], "test-page", "firstEntry", 0).unwrap(),
        )
        .unwrap()
        .len();
        let item = "x".repeat(MAX_METADATA_BYTES - empty_size - 2);
        let pages = wire::paginate(&[item, "tail".into()], "test-page", "firstEntry").unwrap();
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].bytes.len(), MAX_METADATA_BYTES);
        assert!(
            wire::paginate(&["x".repeat(MAX_METADATA_BYTES)], "test-page", "firstEntry").is_err()
        );
    }
    #[test]
    fn empty_full_and_final_short_transfer_coverage() {
        let stream = StreamIdentity::from_sha256([7; 32]);
        for length in [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, MAX_STREAM_BYTES] {
            let count = length.div_ceil(CHUNK_SIZE);
            let entries: Vec<_> = (0..count)
                .map(|index| ChunkEntry::Zero {
                    length: CHUNK_SIZE.min(length - index * CHUNK_SIZE),
                })
                .collect();
            let encoded = wire::encode_transfer(stream, length, &entries).unwrap();
            let root: TransferRoot = wire::decode_record(&encoded.root.bytes).unwrap();
            let pages: BTreeMap<_, _> = encoded
                .pages
                .into_iter()
                .map(|page| (page.reference.digest, page.bytes))
                .collect();
            let decoded =
                wire::verify_transfer(&root, |digest| Ok(pages[&digest].clone())).unwrap();
            assert_eq!(decoded, entries);
        }
    }
    #[test]
    fn alternate_transfer_pagination_is_valid_but_gaps_overlaps_and_short_chunks_are_not() {
        let stream = StreamIdentity::from_sha256([7; 32]);
        let length = CHUNK_SIZE * 2 + 3;
        let entries = vec![
            ChunkEntry::Zero { length: CHUNK_SIZE },
            ChunkEntry::Zero { length: CHUNK_SIZE },
            ChunkEntry::Zero { length: 3 },
        ];
        for split in [1, 2] {
            let first = RecordBlob::encode(&TransferPage {
                schema: 1,
                kind: "silo-chunk-map".into(),
                first_chunk: 0,
                entries: entries[..split].to_vec(),
            })
            .unwrap();
            let last = RecordBlob::encode(&TransferPage {
                schema: 1,
                kind: "silo-chunk-map".into(),
                first_chunk: split as u64,
                entries: entries[split..].to_vec(),
            })
            .unwrap();
            let mut root = TransferRoot {
                schema: 1,
                kind: "silo-chunks-v1".into(),
                stream,
                length,
                chunk_size: CHUNK_SIZE,
                pages: vec![first.reference.digest, last.reference.digest],
            };
            assert_eq!(
                wire::verify_transfer(&root, |digest| Ok(if digest == first.reference.digest {
                    first.bytes.clone()
                } else {
                    last.bytes.clone()
                }))
                .unwrap(),
                entries
            );
            root.pages.push(last.reference.digest);
            assert!(wire::verify_transfer(&root, |digest| Ok(
                if digest == first.reference.digest {
                    first.bytes.clone()
                } else {
                    last.bytes.clone()
                }
            ))
            .is_err());
        }
        for (first_chunk, entries) in [
            (1, entries.clone()),
            (0, vec![]),
            (0, vec![ChunkEntry::Zero { length: 3 }; 3]),
            (0, vec![ChunkEntry::Zero { length: CHUNK_SIZE }; 4]),
        ] {
            let page = RecordBlob::encode(&TransferPage {
                schema: 1,
                kind: "silo-chunk-map".into(),
                first_chunk,
                entries,
            })
            .unwrap();
            let root = TransferRoot {
                schema: 1,
                kind: "silo-chunks-v1".into(),
                stream,
                length,
                chunk_size: CHUNK_SIZE,
                pages: vec![page.reference.digest],
            };
            assert!(wire::verify_transfer(&root, |_| Ok(page.bytes.clone())).is_err());
        }
        let root = TransferRoot {
            schema: 1,
            kind: "silo-chunks-v1".into(),
            stream,
            length,
            chunk_size: CHUNK_SIZE,
            pages: vec![ContentDigest::of_bytes(b"not page")],
        };
        assert!(wire::verify_transfer(&root, |_| Ok(b"{}".to_vec())).is_err());
    }
}
