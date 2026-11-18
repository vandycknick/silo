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
    #[serde(rename = "application/vnd.silo.vm.stream-map.v1")]
    StreamMap,
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
            Self::StreamMap => "application/vnd.silo.vm.stream-map.v1",
            Self::RawChunk => "application/vnd.silo.vm.chunk.v1",
            Self::ZstdChunk => "application/vnd.silo.vm.chunk.v1+zstd",
            Self::Execution => "application/vnd.silo.vm.execution.v1",
            Self::DeviceState => "application/vnd.silo.vm.device-state.v1",
        }
    }
    pub const fn maximum_size(self) -> u64 {
        match self {
            Self::Record => MAX_METADATA_BYTES as u64,
            Self::StreamMap => 2083,
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
wire_enum!(Root { OpaqueRaw => "opaque-raw", LinuxErofsOverlay => "linux-erofs-overlay" });
wire_enum!(Execution { KrunV1 => "krun-v1" });
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
pub struct CompatibilityProfile {
    pub live_state_schema: String,
    pub architecture: String,
    pub profile: ContentDigest,
    pub topology: ContentDigest,
    pub ram_layout: ContentDigest,
}
/// What restoring the memory of a snapshot requires, and the record that
/// proves how it was captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryRequirements {
    pub execution: Execution,
    pub execution_version: u32,
    pub execution_abi: u32,
    pub device_version: u32,
    pub compatibility_profile: CompatibilityProfile,
    pub provenance: RecordRef,
}

fn required_nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

/// The config blob of the metadata manifest. The normative description is
/// `docs/architecture/vm-artifact.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmArtifactConfig {
    pub schema: u32,
    pub kind: String,
    pub encoding: String,
    pub content: ContentRef,
    pub root: Root,
    pub guest_platform: GuestPlatform,
    pub boot_abi: String,
    /// Present exactly for a snapshot with memory.
    #[serde(deserialize_with = "required_nullable")]
    pub memory: Option<MemoryRequirements>,
    pub streams: RecordRef,
    pub objects: RecordRef,
}
impl VmArtifactConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "vm-artifact" || self.encoding != "silo-chunks-v1" {
            return Err(invalid(
                "unsupported artifact format: fresh-state v1 required",
            ));
        }
        if self.content.kind == ContentKind::Image && self.memory.is_some() {
            return Err(invalid("an image artifact cannot carry memory"));
        }
        if let Some(memory) = &self.memory {
            if memory.execution_version != 1
                || memory.execution_abi != 1
                || memory.device_version != 1
            {
                return Err(invalid("unsupported execution schema/ABI"));
            }
            let profile = &memory.compatibility_profile;
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
        for reference in [
            Some(self.content.record),
            Some(self.streams),
            Some(self.objects),
            self.provenance(),
        ]
        .into_iter()
        .flatten()
        {
            reference.payload().validate()?;
        }
        if self.boot_abi.is_empty() {
            return Err(invalid("empty boot ABI"));
        }
        Ok(())
    }

    /// The capture provenance record of a snapshot with memory.
    pub fn provenance(&self) -> Option<RecordRef> {
        self.memory.as_ref().map(|memory| memory.provenance)
    }
}
pub fn decode_vm_config(bytes: &[u8]) -> Result<VmArtifactConfig> {
    let value: Value = decode_record(bytes)?;
    if let Some(root) = value.get("root").and_then(Value::as_str) {
        if serde_json::from_value::<Root>(Value::from(root)).is_err() {
            return Err(crate::vm_artifact::Error::UnsupportedRoot {
                root: root.to_owned(),
            });
        }
    }
    let config: VmArtifactConfig = serde_json::from_value(value)?;
    config.validate()?;
    Ok(config)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamBinding {
    pub stream: StreamIdentity,
    pub length: u64,
    pub map: ContentDigest,
    pub chunk_size: u64,
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
            || !matches!(entry.chunk_size, 65536 | CHUNK_SIZE)
            || entry.map.as_bytes() != entry.stream.as_bytes()
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
        self, Architecture, ChunkEntry, CompatibilityProfile, ContentKind, ContentRef, Execution,
        GuestOs, GuestPlatform, MemoryRequirements, RecordBlob, RecordRef, Root, TransferPage,
        TransferRoot, VmArtifactConfig, CHUNK_SIZE, MAX_METADATA_BYTES, MAX_PAGE_ENTRIES,
        MAX_STREAM_BYTES,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    /// The normative specification. Its example configs must be the pretty
    /// form of the golden bytes below, so the document cannot drift from the
    /// encoder.
    const SPEC: &str = include_str!("../../../../docs/architecture/vm-artifact.md");
    const IMAGE_GOLDEN: &str = r#"{"bootAbi":"silo-direct-v1","content":{"id":"sha256:1111111111111111111111111111111111111111111111111111111111111111","kind":"image","record":{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":1874}},"encoding":"silo-chunks-v1","guestPlatform":{"architecture":"arm64","os":"linux"},"kind":"vm-artifact","memory":null,"objects":{"digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","size":655},"root":"linux-erofs-overlay","schema":1,"streams":{"digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","size":412}}"#;
    const SNAPSHOT_GOLDEN: &str = r#"{"bootAbi":"silo-direct-v1","content":{"id":"sha256:5555555555555555555555555555555555555555555555555555555555555555","kind":"snapshot","record":{"digest":"sha256:6666666666666666666666666666666666666666666666666666666666666666","size":2306}},"encoding":"silo-chunks-v1","guestPlatform":{"architecture":"amd64","os":"linux"},"kind":"vm-artifact","memory":{"compatibilityProfile":{"architecture":"x86_64","liveStateSchema":"silo.live-state/1","profile":"sha256:7777777777777777777777777777777777777777777777777777777777777777","ramLayout":"sha256:9999999999999999999999999999999999999999999999999999999999999999","topology":"sha256:8888888888888888888888888888888888888888888888888888888888888888"},"deviceVersion":1,"execution":"krun-v1","executionAbi":1,"executionVersion":1,"provenance":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2210}},"objects":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":1957},"root":"opaque-raw","schema":1,"streams":{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1203}}"#;

    fn reference(fill: u8, size: u64) -> RecordRef {
        RecordRef {
            digest: ContentDigest::from_sha256([fill; 32]),
            size,
        }
    }

    fn image_config() -> VmArtifactConfig {
        VmArtifactConfig {
            schema: 1,
            kind: "vm-artifact".into(),
            encoding: "silo-chunks-v1".into(),
            content: ContentRef {
                kind: ContentKind::Image,
                id: ContentDigest::from_sha256([0x11; 32]),
                record: reference(0x22, 1874),
            },
            root: Root::LinuxErofsOverlay,
            guest_platform: GuestPlatform {
                os: GuestOs::Linux,
                architecture: Architecture::Arm64,
            },
            boot_abi: "silo-direct-v1".into(),
            memory: None,
            streams: reference(0x33, 412),
            objects: reference(0x44, 655),
        }
    }

    fn snapshot_config() -> VmArtifactConfig {
        VmArtifactConfig {
            content: ContentRef {
                kind: ContentKind::Snapshot,
                id: ContentDigest::from_sha256([0x55; 32]),
                record: reference(0x66, 2306),
            },
            root: Root::OpaqueRaw,
            guest_platform: GuestPlatform {
                os: GuestOs::Linux,
                architecture: Architecture::Amd64,
            },
            memory: Some(MemoryRequirements {
                execution: Execution::KrunV1,
                execution_version: 1,
                execution_abi: 1,
                device_version: 1,
                compatibility_profile: CompatibilityProfile {
                    live_state_schema: "silo.live-state/1".into(),
                    architecture: "x86_64".into(),
                    profile: ContentDigest::from_sha256([0x77; 32]),
                    topology: ContentDigest::from_sha256([0x88; 32]),
                    ram_layout: ContentDigest::from_sha256([0x99; 32]),
                },
                provenance: reference(0xaa, 2210),
            }),
            streams: reference(0xbb, 1203),
            objects: reference(0xcc, 1957),
            ..image_config()
        }
    }

    fn value(config: &VmArtifactConfig) -> serde_json::Value {
        serde_json::to_value(config).unwrap()
    }

    fn decode(value: &serde_json::Value) -> crate::vm_artifact::Result<VmArtifactConfig> {
        wire::decode_vm_config(&serde_json::to_vec(value).unwrap())
    }

    /// The JSON block that follows `<!-- golden: NAME -->` in the spec.
    fn documented(name: &str) -> &'static str {
        let marker = format!("<!-- golden: {name} -->\n```json\n");
        let start = SPEC.find(&marker).expect("documented example") + marker.len();
        let end = start + SPEC[start..].find("```").expect("closed example");
        &SPEC[start..end]
    }

    #[test]
    fn golden_configs_are_canonical_and_documented_verbatim() {
        for (name, config, golden) in [
            ("image-config", image_config(), IMAGE_GOLDEN),
            ("snapshot-config", snapshot_config(), SNAPSHOT_GOLDEN),
        ] {
            assert_eq!(
                String::from_utf8(wire::canonical_bytes(&config).unwrap()).unwrap(),
                golden,
                "{name}"
            );
            assert_eq!(wire::decode_vm_config(golden.as_bytes()).unwrap(), config);
            let pretty =
                serde_json::to_string_pretty(&wire::strict_value(golden.as_bytes()).unwrap())
                    .unwrap();
            assert_eq!(documented(name), format!("{pretty}\n"), "{name}");
        }
    }

    #[test]
    fn unsupported_artifact_format_is_refused_clearly() {
        let mut value = value(&image_config());
        value["schema"] = json!(2);
        value["encoding"] = json!("silo-chunks-v2");
        let error = decode(&value).unwrap_err();
        assert!(error.to_string().contains("fresh-state v1 required"));
    }

    #[test]
    fn known_roots_decode_and_unknown_roots_have_typed_refusals() {
        let mut value = value(&image_config());
        for (spelling, root) in [
            ("opaque-raw", Root::OpaqueRaw),
            ("linux-erofs-overlay", Root::LinuxErofsOverlay),
        ] {
            value["root"] = json!(spelling);
            assert_eq!(decode(&value).unwrap().root, root);
        }
        for retired in [
            "linux-overlay",
            "opaque-raw-v1",
            "linux-erofs-overlay-v1",
            "future-root",
        ] {
            value["root"] = json!(retired);
            assert!(matches!(
                decode(&value),
                Err(crate::vm_artifact::Error::UnsupportedRoot { root }) if root == retired
            ));
        }
        value["root"] = json!(7);
        assert!(matches!(
            decode(&value),
            Err(crate::vm_artifact::Error::Json(_))
        ));
    }

    #[test]
    fn required_fields_and_unknown_fields_are_rejected_everywhere() {
        for config in [image_config(), snapshot_config()] {
            let value = value(&config);
            assert_eq!(decode(&value).unwrap(), config);
            for field in value.as_object().unwrap().keys() {
                let mut missing = value.clone();
                missing.as_object_mut().unwrap().remove(field);
                assert!(decode(&missing).is_err(), "{field}");
            }
            for retired in [
                "purpose",
                "captureKind",
                "rootFamily",
                "backendRequirement",
                "minimumCapabilities",
                "executionRequirements",
                "captureProvenance",
                "extra",
            ] {
                let mut bad = value.clone();
                bad[retired] = json!(null);
                assert!(decode(&bad).is_err(), "{retired}");
            }
            for nested in ["/content", "/content/record", "/guestPlatform", "/streams"] {
                let mut bad = value.clone();
                bad.pointer_mut(nested).unwrap()["unexpected"] = json!(0);
                assert!(decode(&bad).is_err(), "{nested}");
            }
        }
        let mut bad = value(&snapshot_config());
        for nested in [
            "/memory",
            "/memory/compatibilityProfile",
            "/memory/provenance",
        ] {
            let mut bad = bad.clone();
            bad.pointer_mut(nested).unwrap()["unexpected"] = json!(0);
            assert!(decode(&bad).is_err(), "{nested}");
        }
        bad["bootAbi"] = json!("");
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn an_image_config_with_memory_is_rejected() {
        let mut image = value(&image_config());
        image["memory"] = value(&snapshot_config())["memory"].clone();
        assert!(decode(&image)
            .unwrap_err()
            .to_string()
            .contains("an image artifact cannot carry memory"));
        let mut snapshot = value(&snapshot_config());
        snapshot["memory"] = json!(null);
        assert_eq!(decode(&snapshot).unwrap().provenance(), None);
    }

    #[test]
    fn a_snapshot_with_memory_requires_provenance() {
        let config = snapshot_config();
        assert_eq!(config.provenance(), Some(reference(0xaa, 2210)));
        let mut missing = value(&config);
        missing["memory"]
            .as_object_mut()
            .unwrap()
            .remove("provenance");
        assert!(decode(&missing).is_err());
        let mut null = value(&config);
        null["memory"]["provenance"] = json!(null);
        assert!(decode(&null).is_err());
    }

    #[test]
    fn memory_uses_a_closed_execution_set_versions_and_byte_bounds() {
        let value = value(&snapshot_config());
        for execution in [json!("krun-v2"), json!("vz-v1"), json!(""), json!(1)] {
            let mut bad = value.clone();
            bad["memory"]["execution"] = execution;
            assert!(decode(&bad).is_err());
        }
        for schema in [json!(""), json!("x".repeat(257)), json!(false)] {
            let mut bad = value.clone();
            bad["memory"]["compatibilityProfile"]["liveStateSchema"] = schema;
            assert!(decode(&bad).is_err());
        }
        for architecture in [json!(""), json!("x".repeat(33)), json!(false)] {
            let mut bad = value.clone();
            bad["memory"]["compatibilityProfile"]["architecture"] = architecture;
            assert!(decode(&bad).is_err());
        }
        for field in ["executionVersion", "executionAbi", "deviceVersion"] {
            let mut bad = value.clone();
            bad["memory"][field] = json!(2);
            assert!(decode(&bad).is_err());
        }
    }

    #[test]
    fn every_record_reference_is_within_the_record_bound() {
        let value = value(&snapshot_config());
        for pointer in [
            "/content/record",
            "/streams",
            "/objects",
            "/memory/provenance",
        ] {
            let mut at_bound = value.clone();
            at_bound.pointer_mut(pointer).unwrap()["size"] = json!(MAX_METADATA_BYTES);
            assert!(decode(&at_bound).is_ok(), "{pointer}");
            let mut over = value.clone();
            over.pointer_mut(pointer).unwrap()["size"] = json!(MAX_METADATA_BYTES + 1);
            assert!(decode(&over).is_err(), "{pointer}");
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
