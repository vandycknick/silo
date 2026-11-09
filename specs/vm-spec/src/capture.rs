//! ADR 0021 capture contract shared by libvm (planner, verifier and
//! publisher) and the monitor (sole writer of staging and evidence).
//!
//! ```text
//!   libvm ── CapturePlan ──► monitor ── request.json (canonical plan bytes)
//!                                     ├─ execution.state / devices.state
//!                                     ├─ memory.ram / memory-layout.json
//!                                     ├─ disks/<name>.raw (writable roles)
//!                                     ├─ vm.capture.json        (seal or failed)
//!                                     └─ vm.capture-source.json (continuation)
//! ```
//!
//! The plan is an identity record: closed, strict and canonical. Evidence and
//! continuation records are versioned by addition: unknown top-level fields
//! are ignored, missing, duplicate or malformed known fields are rejected.
use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::lifecycle::{
    CapturePolicy, CaptureResumePolicy, CurrentPause, Diagnostic, LiveFailure, LiveId, PauseOwner,
    PauseToken, VmLifecycleState,
};
use crate::{BlockId, DiskFormat, DiskGeometry, DiskRole, GuestOs, Storage, VmSpec};

/// Version of `request.json`, `vm.capture.json` and `vm.capture-source.json`.
pub const CAPTURE_RECORD_VERSION: u32 = 1;
/// Staging root below the machine data directory.
pub const CAPTURES_DIRECTORY: &str = "captures";
/// Writable disk captures below one capture directory.
pub const CAPTURE_DISKS_DIRECTORY: &str = "disks";
pub const CAPTURE_REQUEST_FILE: &str = "request.json";
pub const CAPTURE_EXECUTION_FILE: &str = "execution.state";
pub const CAPTURE_DEVICES_FILE: &str = "devices.state";
pub const CAPTURE_RAM_FILE: &str = "memory.ram";
pub const CAPTURE_LAYOUT_FILE: &str = "memory-layout.json";
pub const CAPTURE_RAM_MAP_FILE: &str = "memory.map.json";
/// Complete canonical RAM map bound.
pub const MAX_RAM_MAP_BYTES: usize =
    (MAX_CAPTURE_RAM_BYTES / STREAM_CHUNK_BYTES) as usize * 74 + 256;
pub const CAPTURE_EVIDENCE_FILE: &str = "vm.capture.json";
pub const CAPTURE_SOURCE_FILE: &str = "vm.capture-source.json";
/// The only temporary names a reader may find next to the records. A
/// temporary is never a record; it is left only by an interrupted write.
pub const CAPTURE_EVIDENCE_TEMPORARY_FILE: &str = ".vm.capture.json.tmp";
pub const CAPTURE_SOURCE_TEMPORARY_FILE: &str = ".vm.capture-source.json.tmp";
/// Upper bound for one JSON control record (plan, evidence, continuation).
pub const MAX_CAPTURE_RECORD_BYTES: usize = (1 << 20) + MAX_RAM_MAP_BYTES;
/// ADR 0021 `Resource Limits`: staged state and evidence allowance.
pub const CAPTURE_STATE_RESERVE_BYTES: u64 = 64 << 20;
/// ADR 0021 `Resource Limits`: metadata charge of a qualified clone.
pub const CAPTURE_CLONE_RESERVE_BYTES: u64 = 16 << 20;
/// ADR 0021 `Resource Limits`: RAM per captured machine.
pub const MAX_CAPTURE_RAM_BYTES: u64 = 1 << 40;
/// ADR 0014 stream identity chunk.
pub const STREAM_CHUNK_BYTES: u64 = 8 << 20;
/// ADR 0014 total logical stream admission bound.
pub const MAX_STREAM_BYTES: u64 = 4 << 40;
/// Bound for libvm's opaque read-only input identities.
pub const MAX_INPUT_IDENTITY_BYTES: usize = 256;
/// Native execution ABI's maximum producer binding, including build inputs.
pub const MAX_NATIVE_PRODUCER_BYTES: usize = 64 * 1024;

const MIB: u64 = 1 << 20;

/// Relative path of one capture directory below the machine data directory.
pub fn capture_directory(capture_id: &LiveId) -> String {
    format!("{CAPTURES_DIRECTORY}/{capture_id}")
}

fn invalid(message: impl Into<String>) -> String {
    message.into()
}

/// A known optional field must still be present (as `null` when absent).
fn required<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

/// `sha256:` followed by 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Sha256Digest {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex = value
            .strip_prefix("sha256:")
            .filter(|hex| hex.len() == 64)
            .ok_or_else(|| invalid("digest must be sha256: and 64 lowercase hex characters"))?;
        let mut bytes = [0u8; 32];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(invalid("digest must use lowercase hexadecimal")),
            };
            bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Exact zero classification without alignment requirements or scratch allocation.
pub fn is_all_zero(bytes: &[u8]) -> bool {
    let mut blocks = bytes.chunks_exact(64);
    for block in &mut blocks {
        let bits = block.chunks_exact(8).fold(0u64, |bits, word| {
            bits | u64::from_ne_bytes([
                word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
            ])
        });
        if bits != 0 {
            return false;
        }
    }
    blocks.remainder().iter().all(|byte| *byte == 0)
}

/// Streaming ADR 0014 `stream` identity: 8 MiB decoded chunks, `zero` only
/// for an entirely zero chunk, SHA-256 of `silo:stream:v1\n` followed by the
/// RFC 8785 canonical map. Holds no map, so a 1 TiB stream costs O(1) memory.
pub struct StreamIdentity {
    hash: Sha256,
    length: u64,
    chunks: u64,
    partial: bool,
}

impl Default for StreamIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamIdentity {
    pub fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(b"silo:stream:v1\n");
        hash.update(b"{\"chunkSize\":8388608,\"chunks\":[");
        Self {
            hash,
            length: 0,
            chunks: 0,
            partial: false,
        }
    }

    /// Feed the next decoded chunk. Every chunk but the last is exactly
    /// [`STREAM_CHUNK_BYTES`]; empty chunks do not exist.
    pub fn push_chunk(&mut self, bytes: &[u8]) -> Result<(), String> {
        let length = u64::try_from(bytes.len()).map_err(|_| invalid("chunk length overflow"))?;
        let digest = if is_all_zero(bytes) {
            None
        } else {
            Some(Sha256Digest::of_bytes(bytes))
        };
        self.push_digest(length, digest)
    }

    /// Feed an already classified chunk: `None` for an entirely zero chunk,
    /// otherwise the SHA-256 of its decoded bytes.
    pub fn push_digest(&mut self, length: u64, digest: Option<Sha256Digest>) -> Result<(), String> {
        if length == 0 || length > STREAM_CHUNK_BYTES || self.partial {
            return Err(invalid(
                "stream chunks are 1..=8 MiB and only the final chunk is short",
            ));
        }
        let total = self
            .length
            .checked_add(length)
            .filter(|total| *total <= MAX_STREAM_BYTES)
            .ok_or_else(|| invalid("stream exceeds its admitted length"))?;
        if self.chunks != 0 {
            self.hash.update(b",");
        }
        match digest {
            None => self.hash.update(b"\"zero\""),
            Some(digest) => self.hash.update(format!("\"{digest}\"").as_bytes()),
        }
        self.length = total;
        self.chunks += 1;
        self.partial = length < STREAM_CHUNK_BYTES;
        Ok(())
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn finish(mut self) -> Sha256Digest {
        self.hash.update(
            format!(
                "],\"kind\":\"stream\",\"length\":{},\"schema\":1}}",
                self.length
            )
            .as_bytes(),
        );
        Sha256Digest(self.hash.finalize().into())
    }
}

/// ADR 0014 complete canonical stream map. `None` denotes an entire zero chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMap {
    length: u64,
    chunks: Vec<Option<Sha256Digest>>,
}

impl StreamMap {
    pub fn new(length: u64, chunks: Vec<Option<Sha256Digest>>) -> Result<Self, String> {
        if length > MAX_STREAM_BYTES || chunks.len() as u64 != length.div_ceil(STREAM_CHUNK_BYTES) {
            return Err(invalid("stream map length or chunk count is invalid"));
        }
        Ok(Self { length, chunks })
    }

    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn chunks(&self) -> &[Option<Sha256Digest>] {
        &self.chunks
    }
    pub fn into_chunks(self) -> Vec<Option<Sha256Digest>> {
        self.chunks
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > (MAX_STREAM_BYTES / STREAM_CHUNK_BYTES) as usize * 74 + 256 {
            return Err(invalid("stream map exceeds its encoded bound"));
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Record {
            schema: u64,
            kind: String,
            length: u64,
            chunk_size: u64,
            #[serde(deserialize_with = "decode_map_chunks")]
            chunks: Vec<Option<Sha256Digest>>,
        }
        struct ObjectRecord;
        impl<'de> serde::de::Visitor<'de> for ObjectRecord {
            type Value = Record;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a stream map object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Record, A::Error> {
                Record::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let record = decoder
            .deserialize_map(ObjectRecord)
            .map_err(|error| error.to_string())?;
        decoder.end().map_err(|error| error.to_string())?;
        if record.schema != 1 || record.kind != "stream" || record.chunk_size != STREAM_CHUNK_BYTES
        {
            return Err(invalid("unsupported stream map schema, kind or chunk size"));
        }
        Self::new(record.length, record.chunks)
    }

    pub fn write_canonical(&self, mut output: impl std::io::Write) -> std::io::Result<()> {
        output.write_all(b"{\"chunkSize\":8388608,\"chunks\":[")?;
        for (index, chunk) in self.chunks.iter().enumerate() {
            if index != 0 {
                output.write_all(b",")?;
            }
            match chunk {
                None => output.write_all(b"\"zero\"")?,
                Some(digest) => write!(output, "\"{digest}\"")?,
            }
        }
        write!(
            output,
            "],\"kind\":\"stream\",\"length\":{},\"schema\":1}}",
            self.length
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        self.write_canonical(&mut bytes)
            .map_err(|error| error.to_string())?;
        Ok(bytes)
    }

    pub fn id(&self) -> Sha256Digest {
        let mut identity = StreamIdentity::new();
        let mut remaining = self.length;
        for digest in &self.chunks {
            // Constructor enforces the exact count and final range.
            let _ = identity.push_digest(remaining.min(STREAM_CHUNK_BYTES), *digest);
            remaining = remaining.saturating_sub(STREAM_CHUNK_BYTES);
        }
        identity.finish()
    }
}

fn decode_map_chunks<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<Option<Sha256Digest>>, D::Error> {
    struct Chunks;
    impl<'de> serde::de::Visitor<'de> for Chunks {
        type Value = Vec<Option<Sha256Digest>>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded array of zero or lowercase SHA-256 entries")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut chunks = Vec::new();
            while let Some(entry) = sequence.next_element::<String>()? {
                if chunks.len() as u64 == MAX_STREAM_BYTES / STREAM_CHUNK_BYTES {
                    return Err(serde::de::Error::custom("too many stream chunks"));
                }
                chunks.push(if entry == "zero" {
                    None
                } else {
                    Some(entry.parse().map_err(serde::de::Error::custom)?)
                });
            }
            Ok(chunks)
        }
    }
    decoder.deserialize_seq(Chunks)
}

/// Name of one writable disk capture: `disks/<name>.raw`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CaptureDiskName(String);

impl CaptureDiskName {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        Self::try_from(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn file_name(&self) -> String {
        format!("{}.raw", self.0)
    }
}

impl TryFrom<String> for CaptureDiskName {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let valid = (1..=32).contains(&bytes.len())
            && bytes[0].is_ascii_lowercase()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
        if valid {
            Ok(Self(value))
        } else {
            Err(invalid(
                "capture disk name must be 1..=32 of [a-z0-9-], starting with a letter",
            ))
        }
    }
}

impl From<CaptureDiskName> for String {
    fn from(value: CaptureDiskName) -> Self {
        value.0
    }
}

/// One named staged payload. Native payloads use their fixed relative paths;
/// `ram-map` selects the fixed `memory.map.json` sidecar, never an arbitrary path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CaptureRole {
    Execution,
    Devices,
    Ram,
    Layout,
    RamMap,
    Disk(CaptureDiskName),
    DiskMap(CaptureDiskName),
}

impl CaptureRole {
    pub fn relative_path(&self) -> String {
        match self {
            Self::Execution => CAPTURE_EXECUTION_FILE.into(),
            Self::Devices => CAPTURE_DEVICES_FILE.into(),
            Self::Ram => CAPTURE_RAM_FILE.into(),
            Self::Layout => CAPTURE_LAYOUT_FILE.into(),
            Self::RamMap => CAPTURE_RAM_MAP_FILE.into(),
            Self::Disk(name) => format!("{CAPTURE_DISKS_DIRECTORY}/{}", name.file_name()),
            Self::DiskMap(name) => format!("{CAPTURE_DISKS_DIRECTORY}/{}.map.json", name.as_str()),
        }
    }
}

impl FromStr for CaptureRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            CAPTURE_EXECUTION_FILE => Self::Execution,
            CAPTURE_DEVICES_FILE => Self::Devices,
            CAPTURE_RAM_FILE => Self::Ram,
            CAPTURE_LAYOUT_FILE => Self::Layout,
            "ram-map" => Self::RamMap,
            other => {
                let name = other
                    .strip_prefix(CAPTURE_DISKS_DIRECTORY)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .ok_or_else(|| invalid(format!("unknown capture role {other:?}")))?;
                if let Some(name) = name.strip_suffix(".raw") {
                    Self::Disk(CaptureDiskName::new(name)?)
                } else if let Some(name) = name.strip_suffix(".map.json") {
                    Self::DiskMap(CaptureDiskName::new(name)?)
                } else {
                    return Err(invalid(format!("unknown capture role {other:?}")));
                }
            }
        })
    }
}

impl Serialize for CaptureRole {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::RamMap => serializer.serialize_str("ram-map"),
            _ => serializer.serialize_str(&self.relative_path()),
        }
    }
}

impl<'de> Deserialize<'de> for CaptureRole {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Path-free disk attachment identity, in attachment order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureAttachment {
    pub block_id: BlockId,
    pub role: DiskRole,
    pub format: DiskFormat,
    pub geometry: DiskGeometry,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureShare {
    pub tag: String,
    pub read_only: bool,
}

/// The machine configuration and attachment inventory a capture binds. It is
/// the path-free projection of the launched `VmSpec`: host paths are never
/// identity, so moving `SILO_HOME` does not change it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureConfiguration {
    #[serde(deserialize_with = "required")]
    pub guest_os: Option<GuestOs>,
    pub cpus: u8,
    pub memory_mib: u32,
    pub nested_virtualization: bool,
    pub rosetta: bool,
    pub kernel_cmdline: Vec<String>,
    pub vsock: bool,
    pub attachments: Vec<CaptureAttachment>,
    pub shares: Vec<CaptureShare>,
}

impl CaptureConfiguration {
    /// Project exactly what the monitor launches: the same defaults apply on
    /// both sides because both call this function on the same spec bytes.
    pub fn from_spec(spec: &VmSpec) -> Result<Self, String> {
        let hardware = spec.hardware.as_ref();
        let configuration = Self {
            guest_os: spec.guest.as_ref().and_then(|guest| guest.os),
            cpus: hardware
                .and_then(|hardware| hardware.cpus)
                .unwrap_or(crate::DEFAULT_CPUS),
            memory_mib: hardware
                .and_then(|hardware| hardware.memory)
                .unwrap_or(crate::DEFAULT_MEMORY_MIB),
            nested_virtualization: hardware
                .and_then(|hardware| hardware.nested_virtualization)
                .unwrap_or(false),
            rosetta: hardware
                .and_then(|hardware| hardware.rosetta)
                .unwrap_or(false),
            kernel_cmdline: spec
                .boot
                .as_ref()
                .and_then(|boot| boot.kernel.as_ref())
                .map(|kernel| kernel.cmdline.clone())
                .unwrap_or_default(),
            vsock: crate::effective_vsock_enabled(spec.vsock.as_ref()),
            attachments: spec
                .storage
                .as_ref()
                .map(|storage| {
                    storage
                        .disks
                        .iter()
                        .map(|disk| CaptureAttachment {
                            block_id: disk.block_id.clone(),
                            role: disk.role,
                            format: disk.format,
                            geometry: disk.geometry,
                            read_only: disk.read_only,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            shares: spec
                .mounts
                .iter()
                .map(|mount| CaptureShare {
                    tag: mount.tag.clone(),
                    read_only: mount.read_only,
                })
                .collect(),
        };
        configuration.validate()?;
        Ok(configuration)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.cpus == 0 || self.memory_mib == 0 {
            return Err(invalid("capture configuration needs vCPUs and memory"));
        }
        if self.kernel_cmdline.len() > 1024
            || self
                .kernel_cmdline
                .iter()
                .any(|argument| argument.len() > 4096 || argument.contains('\0'))
        {
            return Err(invalid(
                "capture configuration kernel command line is unbounded",
            ));
        }
        for attachment in &self.attachments {
            crate::Disk::validate_attachment(
                attachment.role,
                attachment.format,
                attachment.geometry,
                &attachment.block_id,
                attachment.read_only,
            )?;
        }
        Storage::validate_attachment_sequence(
            self.attachments
                .iter()
                .map(|attachment| (attachment.role, &attachment.block_id)),
        )?;
        if self.shares.len() > 64
            || self.shares.iter().enumerate().any(|(index, share)| {
                share.tag.is_empty()
                    || share.tag.len() > crate::VIRTIOFS_TAG_MAX_BYTES
                    || share.tag.contains('\0')
                    || self.shares[..index]
                        .iter()
                        .any(|other| other.tag == share.tag)
            })
        {
            return Err(invalid("capture configuration shares are invalid"));
        }
        Ok(())
    }

    /// Canonical JSON: fixed field order, no whitespace, closed schema.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    /// `sha256("silo:capture-configuration:v1\n" || canonical bytes)`.
    pub fn digest(&self) -> Result<Sha256Digest, String> {
        let mut hash = Sha256::new();
        hash.update(b"silo:capture-configuration:v1\n");
        hash.update(self.canonical_bytes()?);
        Ok(Sha256Digest(hash.finalize().into()))
    }

    pub fn ram_bytes(&self) -> u64 {
        u64::from(self.memory_mib) * MIB
    }
}

/// How the capture obtains its cut. A borrowed user pause stays user-owned
/// and requires `preserve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    deny_unknown_fields
)]
pub enum CapturePauseAuthority {
    Acquire,
    Borrow {
        pause_operation_id: LiveId,
        token: PauseToken,
    },
}

/// Monitor clone/copy contract chosen by libvm's reservation. `Clone` was
/// reserved at the 16 MiB metadata charge: a clone failure fails the capture
/// rather than overrunning the reservation with a copy. `Copy` was reserved
/// at allocated bytes and uses clone when available, else a sparse copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureDiskCopy {
    Clone,
    Copy,
}

/// One included writable attachment, sealed into `disks/<name>.raw`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureDiskPlan {
    pub name: CaptureDiskName,
    pub attachment_index: u32,
    pub block_id: BlockId,
    pub length: u64,
    pub copy: CaptureDiskCopy,
}

/// One read-only attachment (composed lower, read-only data), bound by libvm's
/// immutable content identity and never copied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureReadOnlyInput {
    pub attachment_index: u32,
    pub block_id: BlockId,
    pub identity: String,
}

/// The run's inherited launch storage lease the capture is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureLaunchLease {
    pub operation_id: LiveId,
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureReservation {
    /// libvm's durable capture storage operation (charges and input pins).
    pub storage_operation_id: LiveId,
    pub launch_lease: CaptureLaunchLease,
    /// Reserved staging bytes before freeze (ADR 0021 formula, at least).
    pub staging_bytes: u64,
}

/// The complete immutable capture plan. `request.json` is exactly
/// [`CapturePlan::canonical_bytes`]; the capture ID is the Capture request
/// and operation ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturePlan {
    pub version: u32,
    pub machine_id: LiveId,
    pub run_id: LiveId,
    pub capture_id: LiveId,
    pub configuration: CaptureConfiguration,
    pub configuration_digest: Sha256Digest,
    pub policy: CapturePolicy,
    pub dirty_crossover_percent: u8,
    pub resume_policy: CaptureResumePolicy,
    pub pause: CapturePauseAuthority,
    pub ram_bytes: u64,
    pub disks: Vec<CaptureDiskPlan>,
    pub read_only_inputs: Vec<CaptureReadOnlyInput>,
    pub reservation: CaptureReservation,
}

impl CapturePlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CAPTURE_RECORD_VERSION {
            return Err(invalid("unsupported capture plan version"));
        }
        if !(1..=60).contains(&self.dirty_crossover_percent) {
            return Err(invalid("dirty crossover percent must be 1..=60"));
        }
        self.configuration.validate()?;
        if self.configuration.digest()? != self.configuration_digest {
            return Err(invalid(
                "capture plan configuration digest does not match its configuration",
            ));
        }
        if let CapturePauseAuthority::Borrow { token, .. } = &self.pause {
            if self.resume_policy != CaptureResumePolicy::Preserve {
                return Err(invalid(
                    "a capture that borrows a user pause must preserve it",
                ));
            }
            if token.owner != PauseOwner::User
                || token.machine_id != self.machine_id
                || token.run_id != self.run_id
            {
                return Err(invalid(
                    "a borrowed pause must be this run's user-owned token",
                ));
            }
        }
        if self.ram_bytes != self.configuration.ram_bytes()
            || self.ram_bytes == 0
            || self.ram_bytes > MAX_CAPTURE_RAM_BYTES
        {
            return Err(invalid(
                "capture RAM bytes must equal configured memory and stay within 1 TiB",
            ));
        }
        let mut disks = self.disks.iter();
        let mut inputs = self.read_only_inputs.iter();
        let mut names: Vec<&CaptureDiskName> = Vec::with_capacity(self.disks.len());
        let mut minimum = self
            .ram_bytes
            .checked_add(CAPTURE_STATE_RESERVE_BYTES)
            .ok_or_else(|| invalid("capture reservation overflow"))?;
        let mut stream_bytes = self.ram_bytes;
        for (index, attachment) in self.configuration.attachments.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| invalid("attachment index overflow"))?;
            if attachment.read_only {
                let input = inputs
                    .next()
                    .ok_or_else(|| invalid("read-only attachment lacks its input identity"))?;
                if input.attachment_index != index
                    || input.block_id != attachment.block_id
                    || input.identity.is_empty()
                    || input.identity.len() > MAX_INPUT_IDENTITY_BYTES
                    || !input.identity.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(invalid(
                        "read-only inputs must name every read-only attachment in order",
                    ));
                }
                continue;
            }
            let disk = disks
                .next()
                .ok_or_else(|| invalid("writable attachment lacks its capture role"))?;
            if disk.attachment_index != index
                || disk.block_id != attachment.block_id
                || disk.length != attachment.geometry.length
                || attachment.format != DiskFormat::Raw
            {
                return Err(invalid(
                    "capture disks must name every writable raw attachment in order",
                ));
            }
            if names.contains(&&disk.name) {
                return Err(invalid("capture disk names must be unique"));
            }
            names.push(&disk.name);
            let charge = match disk.copy {
                CaptureDiskCopy::Clone => CAPTURE_CLONE_RESERVE_BYTES,
                // Allocation is measured by the reservation; the logical
                // length is only an upper bound, so it is not required here.
                CaptureDiskCopy::Copy => 0,
            };
            minimum = minimum
                .checked_add(charge)
                .ok_or_else(|| invalid("capture reservation overflow"))?;
            stream_bytes = stream_bytes
                .checked_add(disk.length)
                .ok_or_else(|| invalid("capture stream overflow"))?;
        }
        if disks.next().is_some() || inputs.next().is_some() {
            return Err(invalid("capture plan names roles for absent attachments"));
        }
        if stream_bytes > MAX_STREAM_BYTES {
            return Err(invalid("capture closure exceeds 4 TiB of logical streams"));
        }
        if self.reservation.staging_bytes < minimum || self.reservation.launch_lease.inode == 0 {
            return Err(invalid(
                "capture reservation is below the staging minimum or lacks its launch lease",
            ));
        }
        Ok(())
    }

    /// Exact `request.json` bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    /// Strict closed decoding of `request.json`: canonical bytes only.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let plan = Self::parse_canonical(bytes)?;
        plan.validate()?;
        Ok(plan)
    }

    /// Closed canonical syntax only. Semantic validity is checked separately
    /// so the monitor can answer an invalid plan with a typed rejection.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CAPTURE_RECORD_BYTES {
            return Err(invalid("capture plan exceeds its bound"));
        }
        let plan: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if plan.canonical_bytes()? != bytes {
            return Err(invalid("capture plan bytes are not canonical"));
        }
        Ok(plan)
    }

    pub fn directory(&self) -> String {
        capture_directory(&self.capture_id)
    }

    /// The exact closed payload inventory of a coherent capture, in canonical
    /// order: execution, devices, RAM, layout, complete RAM map, then disks.
    pub fn roles(&self) -> Vec<CaptureRole> {
        let mut roles = vec![
            CaptureRole::Execution,
            CaptureRole::Devices,
            CaptureRole::Ram,
            CaptureRole::Layout,
            CaptureRole::RamMap,
        ];
        for disk in &self.disks {
            roles.push(CaptureRole::Disk(disk.name.clone()));
            roles.push(CaptureRole::DiskMap(disk.name.clone()));
        }
        roles
    }
}

/// Native execution/RAM binding, needed to authenticate the RAM image for
/// a later restore. Every 32-byte field is carried as a `sha256:` spelling of
/// the native bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureStateBinding {
    pub native_producer: String,
    pub silo_producer: Sha256Digest,
    pub profile: Sha256Digest,
    pub topology: Sha256Digest,
    pub ram_layout: Sha256Digest,
    pub source_run: LiveId,
    pub pause_generation: NonZeroU64,
    pub capture: LiveId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureFullReason {
    Requested,
    NoBaseline,
    BaselineToken,
    CoverageLost,
    DirtyCrossover,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureSeedMethod {
    Clone,
    #[default]
    Rebuild,
}

/// Native materialization and identity authentication costs, counted separately.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureMemoryStats {
    pub seed_method: CaptureSeedMethod,
    pub logical_bytes: u64,
    pub live_bytes_read: u64,
    pub baseline_bytes_read: u64,
    pub baseline_bytes_written: u64,
    pub overlay_bytes_written: u64,
    pub full_bytes_written: u64,
    pub layout_bytes_written: u64,
    pub baseline_hole_bytes: u64,
    pub zero_bytes_omitted: u64,
    pub explicit_zero_bytes_written: u64,
    pub extent_queries: u64,
    pub identity_bytes_hashed: u64,
    /// Always zero on local capture; byte SHA is reserved for transported blobs.
    pub whole_file_bytes_hashed: u64,
}

/// RAM layout and geometry of `memory.ram`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureMemoryEvidence {
    pub packed_length: u64,
    pub page_granule: u32,
    pub regions: u32,
    /// ADR 0014 canonical stream identity of `memory.ram`.
    pub ram_stream: Sha256Digest,
    pub binding: CaptureStateBinding,
    pub mode: CapturePolicy,
    #[serde(deserialize_with = "required")]
    pub baseline: Option<Sha256Digest>,
    #[serde(deserialize_with = "required")]
    pub full_reason: Option<CaptureFullReason>,
    /// One bit per 8 MiB chunk, least-significant bit first, zero tail padding.
    pub dirty_chunks: Vec<u8>,
    /// Writer-computed digests; clean incremental chunks are non-authoritative `None`.
    pub chunk_digests: Vec<Option<Sha256Digest>>,
    pub stats: CaptureMemoryStats,
}

impl CaptureMemoryEvidence {
    pub fn validate_capture(&self) -> Result<(), String> {
        if !self.page_granule.is_power_of_two()
            || self.page_granule < 4096
            || self.regions == 0
            || !self
                .packed_length
                .is_multiple_of(u64::from(self.page_granule))
            || u64::from(self.regions) > self.packed_length / u64::from(self.page_granule)
            || self.binding.native_producer.is_empty()
            || self.binding.native_producer.contains('\0')
            || self.binding.native_producer.len() > MAX_NATIVE_PRODUCER_BYTES
            || [
                self.binding.silo_producer,
                self.binding.profile,
                self.binding.topology,
                self.binding.ram_layout,
            ]
            .iter()
            .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
        {
            return Err(invalid(
                "RAM geometry or native producer binding is invalid",
            ));
        }
        validate_dirty_chunks(self.packed_length, &self.dirty_chunks)?;
        let count = self.packed_length.div_ceil(STREAM_CHUNK_BYTES) as usize;
        if self.chunk_digests.len() != count
            || self
                .chunk_digests
                .iter()
                .enumerate()
                .any(|(index, digest)| {
                    self.dirty_chunks[index / 8] & (1 << (index % 8)) == 0 && digest.is_some()
                })
        {
            return Err(invalid(
                "RAM receipt chunk count or clean chunk digest is invalid",
            ));
        }
        match self.mode {
            CapturePolicy::Full if self.baseline.is_some() || self.full_reason.is_none() => {
                return Err(invalid(
                    "full RAM capture requires a reason and no reused baseline",
                ));
            }
            CapturePolicy::Incremental if self.baseline.is_none() || self.full_reason.is_some() => {
                return Err(invalid(
                    "incremental RAM capture requires its exact baseline",
                ));
            }
            _ => {}
        }
        if self.mode == CapturePolicy::Full {
            if (0..count).any(|index| self.dirty_chunks[index / 8] & (1 << (index % 8)) == 0) {
                return Err(invalid("full RAM capture must affect every chunk"));
            }
            let mut identity = StreamIdentity::new();
            for (index, digest) in self.chunk_digests.iter().enumerate() {
                identity.push_digest(
                    (self.packed_length - index as u64 * STREAM_CHUNK_BYTES)
                        .min(STREAM_CHUNK_BYTES),
                    *digest,
                )?;
            }
            if identity.finish() != self.ram_stream {
                return Err(invalid(
                    "full RAM receipt identity differs from its chunk digests",
                ));
            }
        }
        let identity_bytes: u64 = (0..count)
            .filter(|index| self.dirty_chunks[index / 8] & (1 << (index % 8)) != 0)
            .map(|index| {
                (self.packed_length - index as u64 * STREAM_CHUNK_BYTES).min(STREAM_CHUNK_BYTES)
            })
            .sum();
        if self.stats.logical_bytes != self.packed_length
            || (self.stats.seed_method == CaptureSeedMethod::Clone
                && (self.mode != CapturePolicy::Incremental
                    || self.stats.baseline_bytes_read != 0
                    || self.stats.baseline_bytes_written != 0
                    || self.stats.baseline_hole_bytes != 0
                    || self.stats.extent_queries != 0))
            || self.stats.whole_file_bytes_hashed != 0
            || self.stats.identity_bytes_hashed != identity_bytes
            || self.stats.live_bytes_read > self.packed_length
            || self.stats.baseline_bytes_read > self.packed_length
            || self.stats.baseline_bytes_written > self.packed_length
            || self.stats.overlay_bytes_written > self.packed_length
            || self.stats.full_bytes_written > self.packed_length
            || self.stats.layout_bytes_written > 64 * 1024
        {
            return Err(invalid(
                "RAM authentication statistics differ from the complete stream",
            ));
        }
        Ok(())
    }
}

/// Validate exact dense coverage, including unused bits at the admitted 1 TiB bound.
pub fn validate_dirty_chunks(length: u64, bitmap: &[u8]) -> Result<(), String> {
    if length == 0 || length > MAX_CAPTURE_RAM_BYTES {
        return Err(invalid("RAM coverage length is outside its bound"));
    }
    let chunks = length.div_ceil(STREAM_CHUNK_BYTES) as usize;
    if bitmap.len() != chunks.div_ceil(8)
        || (!chunks.is_multiple_of(8)
            && bitmap.last().is_some_and(|last| *last >> (chunks % 8) != 0))
    {
        return Err(invalid("RAM chunk bitmap length or padding is invalid"));
    }
    Ok(())
}

pub fn full_dirty_chunks(length: u64) -> Result<Vec<u8>, String> {
    if length == 0 || length > MAX_CAPTURE_RAM_BYTES {
        return Err(invalid("RAM coverage length is outside its bound"));
    }
    let count = length.div_ceil(STREAM_CHUNK_BYTES) as usize;
    let mut bitmap = vec![u8::MAX; count.div_ceil(8)];
    if !count.is_multiple_of(8) {
        if let Some(last) = bitmap.last_mut() {
            *last = ((1u16 << (count % 8)) - 1) as u8;
        }
    }
    Ok(bitmap)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureInventoryEntry {
    pub role: CaptureRole,
    pub length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Sha256Digest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureRecordOutcome {
    Coherent,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapturePauseDisposition {
    Acquired,
    Borrowed,
}

/// `vm.capture.json`, version 1. A coherent record is the seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureEvidence {
    pub version: u32,
    pub machine_id: LiveId,
    pub run_id: LiveId,
    pub capture_id: LiveId,
    /// The cut token (historical); absent only when no pause was established.
    #[serde(deserialize_with = "required")]
    pub pause_token: Option<PauseToken>,
    #[serde(deserialize_with = "required")]
    pub pause_disposition: Option<CapturePauseDisposition>,
    #[serde(deserialize_with = "required")]
    pub freeze_epoch: Option<NonZeroU64>,
    /// The original guest freeze operation, which differs from this capture
    /// when borrowing a user-owned pause. Retained for source-free restore.
    #[serde(deserialize_with = "required")]
    pub freeze_operation_id: Option<LiveId>,
    pub configuration_digest: Sha256Digest,
    /// SHA-256 of the exact `request.json` bytes.
    pub request_digest: Sha256Digest,
    #[serde(deserialize_with = "required")]
    pub memory: Option<CaptureMemoryEvidence>,
    pub inventory: Vec<CaptureInventoryEntry>,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub capture_outcome: CaptureRecordOutcome,
    #[serde(deserialize_with = "required")]
    pub error: Option<Diagnostic>,
    pub workloads_frozen: bool,
    pub vcpus_paused: bool,
    pub devices_quiesced: bool,
    pub host_writers_drained: bool,
    pub host_flush_completed: bool,
    pub disk_copies_sealed: bool,
    pub memory_state_sealed: bool,
}

impl CaptureEvidence {
    pub fn facts(&self) -> [bool; 7] {
        [
            self.workloads_frozen,
            self.vcpus_paused,
            self.devices_quiesced,
            self.host_writers_drained,
            self.host_flush_completed,
            self.disk_copies_sealed,
            self.memory_state_sealed,
        ]
    }

    /// Additive decoding: unknown top-level fields are ignored, every known
    /// field is mandatory (an explicit `null` for absent options) and a
    /// duplicate key is rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CAPTURE_RECORD_BYTES {
            return Err(invalid("capture evidence exceeds its bound"));
        }
        let evidence: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn is_sealed(&self) -> bool {
        self.capture_outcome == CaptureRecordOutcome::Coherent && self.validate().is_ok()
    }

    /// Internal consistency. A coherent record needs all seven facts, a cut
    /// token, RAM geometry and a complete inventory; a failed record needs an
    /// error. A failed record is never a seal.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CAPTURE_RECORD_VERSION {
            return Err(invalid("unsupported capture evidence version"));
        }
        if let Some(token) = &self.pause_token {
            if token.machine_id != self.machine_id || token.run_id != self.run_id {
                return Err(invalid("capture evidence token belongs to another run"));
            }
        }
        if self.pause_token.is_some() != self.pause_disposition.is_some() {
            return Err(invalid(
                "capture pause token and disposition travel together",
            ));
        }
        if self.completed_at_unix_ms < self.started_at_unix_ms {
            return Err(invalid("capture completed before it started"));
        }
        match self.capture_outcome {
            CaptureRecordOutcome::Failed => {
                if self.error.is_none() {
                    return Err(invalid("a failed capture record carries its error"));
                }
                Ok(())
            }
            CaptureRecordOutcome::Coherent => {
                if self.error.is_some() || self.facts().contains(&false) {
                    return Err(invalid(
                        "a coherent capture has no error and all seven facts true",
                    ));
                }
                let (Some(token), Some(disposition), Some(_), Some(memory), Some(freeze_operation)) = (
                    &self.pause_token,
                    self.pause_disposition,
                    self.freeze_epoch,
                    &self.memory,
                    &self.freeze_operation_id,
                ) else {
                    return Err(invalid(
                        "a coherent capture binds its pause, freeze and RAM geometry",
                    ));
                };
                let expected_owner = match disposition {
                    CapturePauseDisposition::Acquired => PauseOwner::Capture {
                        operation_id: self.capture_id.clone(),
                    },
                    CapturePauseDisposition::Borrowed => PauseOwner::User,
                };
                if token.owner != expected_owner
                    || (disposition == CapturePauseDisposition::Acquired
                        && freeze_operation != &self.capture_id)
                    || memory.binding.pause_generation != token.generation
                    || memory.binding.capture != self.capture_id
                    || memory.binding.source_run != self.run_id
                    || memory.binding.native_producer.is_empty()
                    || memory.binding.native_producer.len() > MAX_NATIVE_PRODUCER_BYTES
                {
                    return Err(invalid("capture binding does not match its cut"));
                }
                memory.validate_capture()?;
                for role in [
                    CaptureRole::Execution,
                    CaptureRole::Devices,
                    CaptureRole::Ram,
                    CaptureRole::Layout,
                    CaptureRole::RamMap,
                ] {
                    if !self.inventory.iter().any(|entry| entry.role == role) {
                        return Err(invalid(
                            "coherent capture lacks a required complete output role",
                        ));
                    }
                }
                let mut state_bytes = 0u64;
                for (index, entry) in self.inventory.iter().enumerate() {
                    let stream = matches!(entry.role, CaptureRole::Ram | CaptureRole::Disk(_));
                    if entry.identity.is_some() != stream || entry.sha256.is_some() == stream {
                        return Err(invalid(
                            "stream roles require identity, small state requires sha256",
                        ));
                    }
                    if entry.role == CaptureRole::Ram && entry.identity != Some(memory.ram_stream) {
                        return Err(invalid(
                            "RAM inventory identity differs from its memory receipt",
                        ));
                    }
                    let paired = match &entry.role {
                        CaptureRole::Disk(name) => self.inventory.iter().any(|other| {
                            matches!(&other.role, CaptureRole::DiskMap(other) if other == name)
                        }),
                        CaptureRole::DiskMap(name) => self.inventory.iter().any(|other| {
                            matches!(&other.role, CaptureRole::Disk(other) if other == name)
                        }),
                        _ => true,
                    };
                    if !paired {
                        return Err(invalid(
                            "captured disk and its complete map must travel together",
                        ));
                    }
                    if self.inventory[..index]
                        .iter()
                        .any(|other| other.role == entry.role)
                    {
                        return Err(invalid("capture inventory repeats a role"));
                    }
                    let map_limit = match entry.role {
                        CaptureRole::RamMap => Some(MAX_RAM_MAP_BYTES as u64),
                        CaptureRole::DiskMap(_) => {
                            Some((MAX_STREAM_BYTES / STREAM_CHUNK_BYTES) * 74 + 256)
                        }
                        _ => None,
                    };
                    if map_limit.is_some_and(|limit| entry.length > limit) {
                        return Err(invalid("complete stream map exceeds its metadata bound"));
                    }
                    match &entry.role {
                        CaptureRole::Ram if entry.length != memory.packed_length => {
                            return Err(invalid("RAM length differs from its layout"));
                        }
                        CaptureRole::Execution
                        | CaptureRole::Devices
                        | CaptureRole::Layout
                        | CaptureRole::RamMap
                        | CaptureRole::DiskMap(_) => {
                            if entry.length == 0 {
                                return Err(invalid("captured state files are nonempty"));
                            }
                            state_bytes = state_bytes
                                .checked_add(entry.length)
                                .ok_or_else(|| invalid("state length overflow"))?;
                        }
                        _ => {}
                    }
                }
                if state_bytes > CAPTURE_STATE_RESERVE_BYTES {
                    return Err(invalid("captured state exceeds its reserve"));
                }
                Ok(())
            }
        }
    }

    /// Correlate a record with the exact plan and `request.json` bytes it
    /// claims. For a coherent record the inventory must be exactly the plan's
    /// closed role set, in order, with the planned disk lengths.
    pub fn validate_against_plan(
        &self,
        plan: &CapturePlan,
        request_digest: &Sha256Digest,
    ) -> Result<(), String> {
        self.validate()?;
        if self.machine_id != plan.machine_id
            || self.run_id != plan.run_id
            || self.capture_id != plan.capture_id
            || self.configuration_digest != plan.configuration_digest
            || &self.request_digest != request_digest
        {
            return Err(invalid("capture evidence belongs to another plan"));
        }
        if self.capture_outcome == CaptureRecordOutcome::Failed {
            return Ok(());
        }
        if self.memory.as_ref().is_some_and(|memory| {
            plan.policy == CapturePolicy::Full
                && (memory.mode != CapturePolicy::Full
                    || memory.full_reason != Some(CaptureFullReason::Requested))
        }) {
            return Err(invalid(
                "explicit full capture did not return the requested full mode",
            ));
        }
        if self.memory.as_ref().is_some_and(|memory| {
            plan.policy == CapturePolicy::Incremental
                && memory.full_reason == Some(CaptureFullReason::Requested)
        }) {
            return Err(invalid(
                "incremental request returned an explicit-full reason",
            ));
        }
        let expected_disposition = match &plan.pause {
            CapturePauseAuthority::Acquire => CapturePauseDisposition::Acquired,
            CapturePauseAuthority::Borrow {
                token,
                pause_operation_id,
            } => {
                if self.pause_token.as_ref() != Some(token)
                    || self.freeze_operation_id.as_ref() != Some(pause_operation_id)
                {
                    return Err(invalid("borrowed capture did not keep the user token"));
                }
                CapturePauseDisposition::Borrowed
            }
        };
        if self.pause_disposition != Some(expected_disposition) {
            return Err(invalid("capture pause disposition differs from its plan"));
        }
        let roles = plan.roles();
        if roles.len() != self.inventory.len()
            || roles
                .iter()
                .zip(&self.inventory)
                .any(|(role, entry)| role != &entry.role)
        {
            return Err(invalid("capture inventory differs from the plan's roles"));
        }
        for disk in &plan.disks {
            let role = CaptureRole::Disk(disk.name.clone());
            if !self
                .inventory
                .iter()
                .any(|entry| entry.role == role && entry.length == disk.length)
            {
                return Err(invalid("sealed disk length differs from its attachment"));
            }
        }
        if self
            .memory
            .as_ref()
            .is_some_and(|memory| memory.packed_length > plan.ram_bytes)
        {
            return Err(invalid("captured RAM exceeds the planned memory"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureSourceOutcome {
    Resumed,
    Preserved,
    ResumeFailed,
}

/// `vm.capture-source.json`, version 1: the source continuation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureSourceRecord {
    pub version: u32,
    pub machine_id: LiveId,
    pub run_id: LiveId,
    pub capture_id: LiveId,
    /// The cut token named by `vm.capture.json`.
    pub pause_token: PauseToken,
    pub source_outcome: CaptureSourceOutcome,
    #[serde(deserialize_with = "required")]
    pub error: Option<Diagnostic>,
    /// For `preserved`: the user-owned authority established by preservation.
    #[serde(deserialize_with = "required")]
    pub current_pause: Option<PauseToken>,
    pub completed_at_unix_ms: u64,
}

impl CaptureSourceRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CAPTURE_RECORD_BYTES {
            return Err(invalid("capture source record exceeds its bound"));
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        record.validate()?;
        Ok(record)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != CAPTURE_RECORD_VERSION {
            return Err(invalid("unsupported capture source record version"));
        }
        let same_run =
            |token: &PauseToken| token.machine_id == self.machine_id && token.run_id == self.run_id;
        if !same_run(&self.pause_token) {
            return Err(invalid("capture source token belongs to another run"));
        }
        match (self.source_outcome, &self.error, &self.current_pause) {
            (CaptureSourceOutcome::Resumed, None, None) => Ok(()),
            (CaptureSourceOutcome::Preserved, None, Some(current))
                if current.owner == PauseOwner::User
                    && same_run(current)
                    && current.generation >= self.pause_token.generation =>
            {
                Ok(())
            }
            (CaptureSourceOutcome::ResumeFailed, Some(_), _) => Ok(()),
            _ => Err(invalid(
                "capture source outcome, error and current pause are inconsistent",
            )),
        }
    }

    /// Correlate with the coherent or failed record of the same capture.
    pub fn validate_against(&self, evidence: &CaptureEvidence) -> Result<(), String> {
        self.validate()?;
        if self.machine_id != evidence.machine_id
            || self.run_id != evidence.run_id
            || self.capture_id != evidence.capture_id
            || evidence.pause_token.as_ref() != Some(&self.pause_token)
        {
            return Err(invalid("capture source record belongs to another capture"));
        }
        Ok(())
    }
}

/// Wire success of a Capture: `succeeded` and sealed are the same event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureSealed {
    pub capture_id: LiveId,
    /// SHA-256 of the exact completed `vm.capture.json` bytes.
    pub evidence_sha256: Sha256Digest,
    /// Historical cut token; never current Resume authority by itself.
    pub cut_token: PauseToken,
}

/// Source continuation, independent of the capture outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "status",
    deny_unknown_fields
)]
pub enum CaptureContinuation {
    /// Continuation has not finished (or not started).
    Pending,
    /// No pause was ever established: the source never left its state.
    Unchanged,
    Resumed {
        consumed_token: PauseToken,
        thawed_epoch: NonZeroU64,
    },
    /// The source stays paused under user authority (transferred or borrowed).
    Preserved { preserved: CurrentPause },
    ResumeFailed {
        failure: LiveFailure,
        /// Paused, Error, or stopping when stop preempted the continuation.
        state: VmLifecycleState,
    },
}

impl CaptureContinuation {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Preserved { preserved } if preserved.token.owner != PauseOwner::User => {
                Err(invalid("a preserved source is user-owned"))
            }
            Self::ResumeFailed { failure, .. } => failure.validate(),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureReleaseDisposition {
    /// libvm durably published the sealed closure.
    Published,
    /// libvm abandoned the result (failed, cancelled or refused).
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "status",
    deny_unknown_fields
)]
pub enum CaptureReleaseState {
    Retained,
    Released {
        disposition: CaptureReleaseDisposition,
        /// The live source still maps the accepted staging RAM as its
        /// dirty-tracking baseline; staging must not be removed.
        baseline_retained: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureEvidenceReference {
    pub outcome: CaptureRecordOutcome,
    pub sha256: Sha256Digest,
}

/// Capture-specific facts in `GetOperation` for a capture operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureObservation {
    pub continuation: CaptureContinuation,
    pub release: CaptureReleaseState,
    /// Present once `vm.capture.json` is complete.
    #[serde(deserialize_with = "required")]
    pub evidence: Option<CaptureEvidenceReference>,
    /// Present once a completed `vm.capture-source.json` exists.
    #[serde(deserialize_with = "required")]
    pub source_record_sha256: Option<Sha256Digest>,
}

impl CaptureObservation {
    pub fn validate(&self) -> Result<(), String> {
        self.continuation.validate()
    }
}

/// Successful ReleaseCapture; repeated release returns the same value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureReleased {
    pub operation_id: LiveId,
    pub disposition: CaptureReleaseDisposition,
    pub baseline_retained: bool,
    pub state: VmLifecycleState,
}

#[cfg(test)]
mod tests {
    use crate::capture::*;
    use crate::lifecycle::{LiveFailureCode, LiveStage};
    use crate::{Disk, Hardware, Mount};

    fn id(value: &str) -> LiveId {
        LiveId::parse(value).unwrap()
    }

    fn machine() -> LiveId {
        id("11111111-1111-4111-8111-111111111111")
    }

    fn run() -> LiveId {
        id("22222222-2222-4222-8222-222222222222")
    }

    fn capture() -> LiveId {
        id("33333333-3333-4333-8333-333333333333")
    }

    fn spec() -> VmSpec {
        VmSpec {
            hardware: Some(Hardware {
                cpus: Some(2),
                memory: Some(1024),
                nested_virtualization: None,
                rosetta: None,
            }),
            storage: Some(Storage {
                disks: vec![
                    Disk {
                        path: "lower.vmdk".into(),
                        role: DiskRole::RootLower,
                        format: DiskFormat::Vmdk,
                        geometry: DiskGeometry {
                            length: 1 << 30,
                            logical_sector_size: 512,
                        },
                        block_id: BlockId::new("silo-root-lower").unwrap(),
                        read_only: true,
                    },
                    Disk {
                        path: "upper.raw".into(),
                        role: DiskRole::RootUpper,
                        format: DiskFormat::Raw,
                        geometry: DiskGeometry {
                            length: 1 << 30,
                            logical_sector_size: 512,
                        },
                        block_id: BlockId::new("silo-root-upper").unwrap(),
                        read_only: false,
                    },
                    Disk {
                        path: "/abs/data.raw".into(),
                        role: DiskRole::Data,
                        format: DiskFormat::Raw,
                        geometry: DiskGeometry {
                            length: 1 << 20,
                            logical_sector_size: 512,
                        },
                        block_id: BlockId::new("data0").unwrap(),
                        read_only: false,
                    },
                ],
            }),
            ..VmSpec::current()
        }
    }

    fn user_token(generation: u64) -> PauseToken {
        PauseToken {
            machine_id: machine(),
            run_id: run(),
            generation: NonZeroU64::new(generation).unwrap(),
            owner: PauseOwner::User,
        }
    }

    fn plan() -> CapturePlan {
        let configuration = CaptureConfiguration::from_spec(&spec()).unwrap();
        CapturePlan {
            version: CAPTURE_RECORD_VERSION,
            machine_id: machine(),
            run_id: run(),
            capture_id: capture(),
            configuration_digest: configuration.digest().unwrap(),
            ram_bytes: configuration.ram_bytes(),
            configuration,
            policy: CapturePolicy::Full,
            dirty_crossover_percent: 60,
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            pause: CapturePauseAuthority::Acquire,
            disks: vec![
                CaptureDiskPlan {
                    name: CaptureDiskName::new("root-upper").unwrap(),
                    attachment_index: 1,
                    block_id: BlockId::new("silo-root-upper").unwrap(),
                    length: 1 << 30,
                    copy: CaptureDiskCopy::Copy,
                },
                CaptureDiskPlan {
                    name: CaptureDiskName::new("data0").unwrap(),
                    attachment_index: 2,
                    block_id: BlockId::new("data0").unwrap(),
                    length: 1 << 20,
                    copy: CaptureDiskCopy::Clone,
                },
            ],
            read_only_inputs: vec![CaptureReadOnlyInput {
                attachment_index: 0,
                block_id: BlockId::new("silo-root-lower").unwrap(),
                identity: format!("sha256:{}", "ab".repeat(32)),
            }],
            reservation: CaptureReservation {
                storage_operation_id: id("44444444-4444-4444-8444-444444444444"),
                launch_lease: CaptureLaunchLease {
                    operation_id: id("55555555-5555-4555-8555-555555555555"),
                    device: 7,
                    inode: 9,
                },
                staging_bytes: (1 << 30) + (64 << 20) + (16 << 20),
            },
        }
    }

    fn evidence(plan: &CapturePlan) -> CaptureEvidence {
        let token = PauseToken {
            owner: PauseOwner::Capture {
                operation_id: capture(),
            },
            ..user_token(3)
        };
        let digest = Sha256Digest::of_bytes(b"x");
        CaptureEvidence {
            version: CAPTURE_RECORD_VERSION,
            machine_id: machine(),
            run_id: run(),
            capture_id: capture(),
            pause_token: Some(token),
            pause_disposition: Some(CapturePauseDisposition::Acquired),
            freeze_epoch: NonZeroU64::new(4),
            freeze_operation_id: Some(capture()),
            configuration_digest: plan.configuration_digest,
            request_digest: Sha256Digest::of_bytes(&plan.canonical_bytes().unwrap()),
            memory: Some(CaptureMemoryEvidence {
                packed_length: 1 << 30,
                page_granule: 4096,
                regions: 1,
                ram_stream: StreamMap::new(1 << 30, vec![Some(digest); 128])
                    .unwrap()
                    .id(),
                binding: CaptureStateBinding {
                    native_producer: "libkrun".into(),
                    silo_producer: digest,
                    profile: digest,
                    topology: digest,
                    ram_layout: digest,
                    source_run: run(),
                    pause_generation: NonZeroU64::new(3).unwrap(),
                    capture: capture(),
                },
                mode: CapturePolicy::Full,
                baseline: None,
                full_reason: Some(CaptureFullReason::Requested),
                dirty_chunks: crate::capture::full_dirty_chunks(1 << 30).unwrap(),
                chunk_digests: vec![
                    Some(digest);
                    (1u64 << 30).div_ceil(STREAM_CHUNK_BYTES) as usize
                ],
                stats: CaptureMemoryStats {
                    logical_bytes: 1 << 30,
                    whole_file_bytes_hashed: 0,
                    identity_bytes_hashed: 1 << 30,
                    ..Default::default()
                },
            }),
            inventory: plan
                .roles()
                .into_iter()
                .map(|role| CaptureInventoryEntry {
                    length: match &role {
                        CaptureRole::Ram => 1 << 30,
                        CaptureRole::Disk(name) => {
                            plan.disks
                                .iter()
                                .find(|disk| &disk.name == name)
                                .unwrap()
                                .length
                        }
                        _ => 100,
                    },
                    sha256: (!matches!(role, CaptureRole::Ram | CaptureRole::Disk(_)))
                        .then_some(digest),
                    identity: match role {
                        CaptureRole::Ram => Some(
                            StreamMap::new(1 << 30, vec![Some(digest); 128])
                                .unwrap()
                                .id(),
                        ),
                        CaptureRole::Disk(_) => Some(digest),
                        _ => None,
                    },
                    role,
                })
                .collect(),
            started_at_unix_ms: 10,
            completed_at_unix_ms: 20,
            capture_outcome: CaptureRecordOutcome::Coherent,
            error: None,
            workloads_frozen: true,
            vcpus_paused: true,
            devices_quiesced: true,
            host_writers_drained: true,
            host_flush_completed: true,
            disk_copies_sealed: true,
            memory_state_sealed: true,
        }
    }

    #[test]
    fn digest_spelling_is_strict() {
        let digest = Sha256Digest::of_bytes(b"abc");
        assert_eq!(
            digest.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(digest.to_string().parse::<Sha256Digest>().unwrap(), digest);
        for bad in [
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned(),
            format!("sha256:{}", "AB".repeat(32)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("sha256:{}", "gg".repeat(32)),
        ] {
            assert!(bad.parse::<Sha256Digest>().is_err(), "{bad}");
        }
    }

    #[test]
    fn zero_classification_is_exact_at_every_word_block_and_tail_position() {
        assert!(is_all_zero(&[]));
        for full_blocks in 0..=2 {
            for tail in 0..=70 {
                let length = full_blocks * 64 + tail;
                for alignment in 0..8 {
                    let mut storage = vec![0u8; alignment + length];
                    let bytes = &mut storage[alignment..];
                    assert!(is_all_zero(bytes), "length={length}, alignment={alignment}");
                    for position in 0..length {
                        for value in [1, 0x80, 0xff] {
                            bytes[position] = value;
                            assert!(
                                !is_all_zero(bytes),
                                "length={length}, alignment={alignment}, position={position}, value={value}"
                            );
                        }
                        bytes[position] = 0;
                    }
                }
            }
        }
    }

    #[test]
    fn stream_identity_matches_the_canonical_adr0014_map() {
        let mut stream = StreamIdentity::new();
        let mut first = vec![0u8; STREAM_CHUNK_BYTES as usize];
        stream.push_chunk(&first).unwrap();
        first[17] = 1;
        stream.push_chunk(&first).unwrap();
        stream.push_chunk(&[0, 0, 7]).unwrap();
        assert!(
            stream.push_chunk(&[1]).is_err(),
            "nothing follows a short chunk"
        );
        let canonical = format!(
            "silo:stream:v1\n{{\"chunkSize\":8388608,\"chunks\":[\"zero\",\"{}\",\"{}\"],\"kind\":\"stream\",\"length\":{},\"schema\":1}}",
            Sha256Digest::of_bytes(&first),
            Sha256Digest::of_bytes(&[0, 0, 7]),
            2 * STREAM_CHUNK_BYTES + 3
        );
        assert_eq!(
            stream.finish(),
            Sha256Digest::of_bytes(canonical.as_bytes())
        );

        let empty = StreamIdentity::new().finish();
        assert_eq!(
            empty,
            Sha256Digest::of_bytes(
                b"silo:stream:v1\n{\"chunkSize\":8388608,\"chunks\":[],\"kind\":\"stream\",\"length\":0,\"schema\":1}"
            )
        );
        assert!(StreamIdentity::new().push_chunk(&[]).is_err());
    }

    #[test]
    fn roles_are_fixed_relative_paths() {
        for role in plan().roles() {
            let text = serde_json::to_string(&role).unwrap();
            assert_eq!(serde_json::from_str::<CaptureRole>(&text).unwrap(), role);
        }
        assert_eq!(
            CaptureRole::Disk(CaptureDiskName::new("root").unwrap()).relative_path(),
            "disks/root.raw"
        );
        for bad in [
            "\"request.json\"",
            "\"vm.capture.json\"",
            "\"disks/../x.raw\"",
            "\"disks/Root.raw\"",
            "\"disks/root.img\"",
            "\"/memory.ram\"",
        ] {
            assert!(serde_json::from_str::<CaptureRole>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn configuration_is_path_free_and_digest_stable() {
        let mut moved = spec();
        if let Some(storage) = moved.storage.as_mut() {
            for disk in &mut storage.disks {
                disk.path = format!("/elsewhere/{}", disk.path.display()).into();
            }
        }
        let original = CaptureConfiguration::from_spec(&spec()).unwrap();
        assert_eq!(CaptureConfiguration::from_spec(&moved).unwrap(), original);
        assert_eq!(original.digest().unwrap(), original.digest().unwrap());
        let mut resized = spec();
        resized.hardware.as_mut().unwrap().memory = Some(2048);
        assert_ne!(
            CaptureConfiguration::from_spec(&resized)
                .unwrap()
                .digest()
                .unwrap(),
            original.digest().unwrap()
        );
        let mut shared = spec();
        shared.mounts.push(Mount {
            source: "/a".into(),
            tag: "share".into(),
            read_only: true,
        });
        assert_ne!(
            CaptureConfiguration::from_spec(&shared).unwrap(),
            original,
            "a share is part of the attachment inventory"
        );
        let defaults = CaptureConfiguration::from_spec(&VmSpec::current()).unwrap();
        assert_eq!(defaults.cpus, crate::DEFAULT_CPUS);
        assert_eq!(defaults.memory_mib, crate::DEFAULT_MEMORY_MIB);
    }

    #[test]
    fn plan_round_trips_canonically_and_rejects_noncanonical_bytes() {
        let plan = plan();
        plan.validate().unwrap();
        let bytes = plan.canonical_bytes().unwrap();
        assert_eq!(CapturePlan::decode(&bytes).unwrap(), plan);
        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(&bytes);
        assert!(CapturePlan::decode(&spaced).is_err());
        let text = String::from_utf8(bytes).unwrap();
        let unknown = text.replacen('{', "{\"extra\":1,", 1);
        assert!(CapturePlan::decode(unknown.as_bytes()).is_err());
        let duplicate = text.replacen('{', "{\"version\":1,", 1);
        assert!(CapturePlan::decode(duplicate.as_bytes()).is_err());
        assert_eq!(plan.directory(), format!("captures/{}", capture()));
    }

    #[test]
    fn evidence_preserves_native_producer_through_its_abi_bound() {
        let mut record = evidence(&plan());
        for length in [
            8239,
            MAX_NATIVE_PRODUCER_BYTES,
            MAX_NATIVE_PRODUCER_BYTES + 1,
        ] {
            record.memory.as_mut().unwrap().binding.native_producer = "p".repeat(length);
            assert_eq!(
                record.validate().is_ok(),
                length <= MAX_NATIVE_PRODUCER_BYTES
            );
        }
    }

    #[test]
    fn plan_rejects_every_inconsistent_binding() {
        type PlanMutation = Box<dyn Fn(&mut CapturePlan)>;
        let mutations: Vec<PlanMutation> = vec![
            Box::new(|plan| plan.version = 2),
            Box::new(|plan| plan.configuration_digest = Sha256Digest::of_bytes(b"other")),
            Box::new(|plan| plan.ram_bytes += 4096),
            Box::new(|plan| plan.disks.swap(0, 1)),
            Box::new(|plan| {
                plan.disks.pop();
            }),
            Box::new(|plan| plan.disks[1].name = plan.disks[0].name.clone()),
            Box::new(|plan| plan.disks[0].length -= 512),
            Box::new(|plan| plan.disks[0].attachment_index = 0),
            Box::new(|plan| plan.read_only_inputs.clear()),
            Box::new(|plan| plan.read_only_inputs[0].identity.clear()),
            Box::new(|plan| plan.reservation.staging_bytes = 1),
            Box::new(|plan| plan.reservation.launch_lease.inode = 0),
            Box::new(|plan| {
                plan.pause = CapturePauseAuthority::Borrow {
                    pause_operation_id: capture(),
                    token: user_token(1),
                }
            }),
            Box::new(|plan| {
                plan.resume_policy = CaptureResumePolicy::Preserve;
                plan.pause = CapturePauseAuthority::Borrow {
                    pause_operation_id: capture(),
                    token: PauseToken {
                        owner: PauseOwner::Capture {
                            operation_id: capture(),
                        },
                        ..user_token(1)
                    },
                }
            }),
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut plan = plan();
            mutate(&mut plan);
            assert!(plan.validate().is_err(), "mutation {index}");
        }
        let mut borrowed = plan();
        borrowed.resume_policy = CaptureResumePolicy::Preserve;
        borrowed.pause = CapturePauseAuthority::Borrow {
            pause_operation_id: capture(),
            token: user_token(1),
        };
        borrowed.validate().unwrap();
    }

    #[test]
    fn coherent_evidence_requires_every_fact_and_the_exact_inventory() {
        let plan = plan();
        let request = Sha256Digest::of_bytes(&plan.canonical_bytes().unwrap());
        let sealed = evidence(&plan);
        sealed.validate_against_plan(&plan, &request).unwrap();
        assert!(sealed.is_sealed());
        let bytes = sealed.canonical_bytes().unwrap();
        assert_eq!(CaptureEvidence::decode(&bytes).unwrap(), sealed);

        for fact in 0..7 {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let name = [
                "workloadsFrozen",
                "vcpusPaused",
                "devicesQuiesced",
                "hostWritersDrained",
                "hostFlushCompleted",
                "diskCopiesSealed",
                "memoryStateSealed",
            ][fact];
            value[name] = serde_json::Value::Bool(false);
            assert!(CaptureEvidence::decode(&serde_json::to_vec(&value).unwrap()).is_err());
            value.as_object_mut().unwrap().remove(name);
            assert!(CaptureEvidence::decode(&serde_json::to_vec(&value).unwrap()).is_err());
            value[name] = serde_json::Value::from("true");
            assert!(CaptureEvidence::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let text = String::from_utf8(bytes.clone()).unwrap();
        let additive = text.replacen('{', "{\"futureField\":{\"x\":1},", 1);
        assert_eq!(
            CaptureEvidence::decode(additive.as_bytes()).unwrap(),
            sealed
        );
        let duplicate = text.replacen('{', "{\"vcpusPaused\":true,", 1);
        assert!(CaptureEvidence::decode(duplicate.as_bytes()).is_err());

        let mut missing_disk = sealed.clone();
        missing_disk.inventory.pop();
        assert!(missing_disk.validate_against_plan(&plan, &request).is_err());
        let mut reordered = sealed.clone();
        reordered.inventory.swap(0, 1);
        assert!(reordered.validate_against_plan(&plan, &request).is_err());
        let mut wrong_ram = sealed.clone();
        wrong_ram.inventory[2].length -= 4096;
        assert!(wrong_ram.validate().is_err());
        let mut foreign = sealed.clone();
        foreign.request_digest = Sha256Digest::of_bytes(b"other");
        assert!(foreign.validate_against_plan(&plan, &request).is_err());
        let mut wrong_owner = sealed.clone();
        wrong_owner.pause_token.as_mut().unwrap().owner = PauseOwner::User;
        assert!(wrong_owner.validate().is_err());
        let mut errored = sealed.clone();
        errored.error = Some(Diagnostic::new("x"));
        assert!(errored.validate().is_err());
    }

    #[test]
    fn failed_evidence_is_diagnostic_never_a_seal() {
        let plan = plan();
        let mut failed = evidence(&plan);
        failed.capture_outcome = CaptureRecordOutcome::Failed;
        failed.disk_copies_sealed = false;
        failed.memory = None;
        failed.inventory.clear();
        assert!(failed.validate().is_err(), "failed needs an error");
        failed.error = Some(Diagnostic::new("disk copy failed: ENOSPC"));
        failed.validate().unwrap();
        assert!(!failed.is_sealed());
        let mut all_true = evidence(&plan);
        all_true.capture_outcome = CaptureRecordOutcome::Failed;
        all_true.error = Some(Diagnostic::new("cancelled"));
        assert!(!all_true.is_sealed(), "facts never promote a failed record");
    }

    #[test]
    fn source_record_outcomes_are_consistent() {
        let plan = plan();
        let sealed = evidence(&plan);
        let cut = sealed.pause_token.clone().unwrap();
        let resumed = CaptureSourceRecord {
            version: CAPTURE_RECORD_VERSION,
            machine_id: machine(),
            run_id: run(),
            capture_id: capture(),
            pause_token: cut.clone(),
            source_outcome: CaptureSourceOutcome::Resumed,
            error: None,
            current_pause: None,
            completed_at_unix_ms: 30,
        };
        resumed.validate_against(&sealed).unwrap();
        let bytes = resumed.canonical_bytes().unwrap();
        assert_eq!(CaptureSourceRecord::decode(&bytes).unwrap(), resumed);
        let preserved = CaptureSourceRecord {
            source_outcome: CaptureSourceOutcome::Preserved,
            current_pause: Some(user_token(3)),
            ..resumed.clone()
        };
        preserved.validate().unwrap();
        let wrong = CaptureSourceRecord {
            current_pause: Some(user_token(2)),
            ..preserved.clone()
        };
        assert!(
            wrong.validate().is_err(),
            "preserved cannot be older than the cut"
        );
        let failed = CaptureSourceRecord {
            source_outcome: CaptureSourceOutcome::ResumeFailed,
            error: None,
            ..resumed.clone()
        };
        assert!(failed.validate().is_err());
        let mut foreign = resumed.clone();
        foreign.pause_token.generation = NonZeroU64::new(9).unwrap();
        assert!(foreign.validate_against(&sealed).is_err());
    }

    #[test]
    fn borrowed_seal_retains_the_original_freeze_operation_for_restore() {
        let mut plan = plan();
        let original_pause = id("44444444-4444-4444-8444-444444444444");
        plan.pause = CapturePauseAuthority::Borrow {
            pause_operation_id: original_pause.clone(),
            token: user_token(3),
        };
        plan.resume_policy = CaptureResumePolicy::Preserve;
        let mut seal = evidence(&plan);
        seal.pause_token = Some(user_token(3));
        seal.pause_disposition = Some(CapturePauseDisposition::Borrowed);
        seal.freeze_operation_id = Some(original_pause.clone());
        let request_digest = Sha256Digest::of_bytes(&plan.canonical_bytes().unwrap());
        seal.validate_against_plan(&plan, &request_digest).unwrap();
        let retained = CaptureEvidence::decode(&seal.canonical_bytes().unwrap()).unwrap();
        assert_eq!(retained.freeze_operation_id, Some(original_pause));
        seal.freeze_operation_id = Some(capture());
        assert!(seal.validate_against_plan(&plan, &request_digest).is_err());
        seal.freeze_operation_id = None;
        assert!(!seal.is_sealed());
    }

    fn restore_request() -> crate::restore::RestoreRequest {
        use crate::restore::{
            RestoreDescriptor, RestoreExtent, RestoreLower, RestoreObject, RestoreObjectRole,
            RestoreRequest,
        };
        let plan = plan();
        let evidence = evidence(&plan);
        let objects = RestoreObjectRole::ALL.map(|role| {
            let index = RestoreObjectRole::ALL
                .iter()
                .position(|value| *value == role)
                .unwrap();
            let entry = evidence
                .inventory
                .iter()
                .find(|entry| entry.role == role.capture_role())
                .unwrap();
            RestoreObject {
                role,
                fd: 3 + index as i32,
                file_device: 1,
                file_inode: 1 + index as u64,
                length: entry.length,
                identity: entry.identity.or(entry.sha256).unwrap(),
            }
        });
        RestoreRequest {
            version: 1,
            checkpoint: Sha256Digest::of_bytes(b"checkpoint"),
            activation_id: id("44444444-4444-4444-8444-444444444444"),
            freeze_operation_id: capture(),
            start_paused: true,
            configuration: plan.configuration.clone(),
            evidence,
            objects,
            ssh_trusted_ca: None,
            lowers: vec![RestoreLower {
                block_id: BlockId::new("silo-root-lower").unwrap(),
                descriptor: RestoreDescriptor {
                    fd: 8,
                    file_device: 1,
                    file_inode: 7,
                    length: 512,
                },
                extents: vec![RestoreExtent {
                    path: "/pool/lower".into(),
                    fd: 9,
                    file_device: 1,
                    file_inode: 8,
                    length: 1 << 30,
                }],
            }],
            network: None,
            hook: None,
        }
    }

    #[test]
    fn restore_inputs_reject_cross_role_aliases_and_cut_substitution() {
        let request = restore_request();
        request.validate().unwrap();
        let mut wrong = request.clone();
        wrong.objects[1].fd = wrong.objects[0].fd;
        assert!(wrong.validate().is_err());
        let mut wrong = request.clone();
        wrong.lowers[0].extents[0].file_inode = wrong.objects[0].file_inode;
        assert!(wrong.validate().is_err());
        let mut wrong = request.clone();
        wrong.objects[2].identity = Sha256Digest::of_bytes(b"other execution");
        assert!(wrong.validate().is_err());
        let mut wrong = request.clone();
        wrong.start_paused = false;
        assert!(wrong.validate().is_err());
        let mut wrong = request.clone();
        wrong.freeze_operation_id = request.activation_id.clone();
        assert!(wrong.validate().is_err());
        let mut wrong = request;
        wrong.lowers.clear();
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn inspection_requires_complete_exact_devices_without_imposing_envelope_order() {
        use crate::restore::{
            RestoreAdmittedDevice, RestoreDeviceKind as Kind, RestoreInspectionReport,
            RestoreInspectionRequest,
        };
        let request = RestoreInspectionRequest {
            version: 1,
            restore: restore_request(),
            network: false,
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let binding = &request.restore.evidence.memory.as_ref().unwrap().binding;
        let report = RestoreInspectionReport {
            version: 1,
            request: Sha256Digest::of_bytes(&bytes),
            checkpoint: request.restore.checkpoint,
            native_producer: binding.native_producer.clone(),
            silo_producer: binding.silo_producer,
            lane: crate::live::LiveLane::KvmX86_64,
            cpu_count: u32::from(request.restore.configuration.cpus),
            ram_bytes: request.restore.configuration.ram_bytes(),
            devices: [
                ("hvc0", Kind::Console),
                ("silo-root-lower", Kind::Block),
                ("silo-root-upper", Kind::Block),
                ("data0", Kind::Block),
                ("vsock", Kind::Vsock),
                ("rng", Kind::Rng),
                ("balloon", Kind::Balloon),
                ("silo-vmgenid", Kind::Generation),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (id, kind))| RestoreAdmittedDevice {
                configured_id: id.into(),
                kind,
                address: 0x1000 + index as u64 * 0x1000,
                irq: 32 + index as u32,
            })
            .collect(),
        };
        report.validate_against(&bytes, &request).unwrap();
        let mut reordered = report.clone();
        reordered.devices.reverse();
        reordered.validate_against(&bytes, &request).unwrap();
        let mut wrong = report.clone();
        wrong.devices.pop();
        assert!(wrong.validate_against(&bytes, &request).is_err());
        let mut wrong = report.clone();
        wrong.devices[0].kind = Kind::Network;
        assert!(wrong.validate_against(&bytes, &request).is_err());
        let mut wrong = report.clone();
        wrong.devices[3].configured_id = "other-data".into();
        assert!(wrong.validate_against(&bytes, &request).is_err());
        let mut wrong = report.clone();
        wrong.devices[1].irq = wrong.devices[0].irq;
        assert!(wrong.validate_against(&bytes, &request).is_err());
        let mut wrong = report;
        wrong.request = Sha256Digest::of_bytes(b"another inspection");
        assert!(wrong.validate_against(&bytes, &request).is_err());
    }

    #[test]
    fn continuation_wire_shapes_are_closed() {
        let preserved = CaptureContinuation::Preserved {
            preserved: CurrentPause {
                token: user_token(3),
                operation_id: capture(),
                freeze_epoch: NonZeroU64::new(4).unwrap(),
            },
        };
        preserved.validate().unwrap();
        let text = serde_json::to_string(&preserved).unwrap();
        assert!(text.contains("\"status\":\"preserved\""));
        assert_eq!(
            serde_json::from_str::<CaptureContinuation>(&text).unwrap(),
            preserved
        );
        let failed = CaptureContinuation::ResumeFailed {
            failure: LiveFailure::new(LiveFailureCode::ThawFailed, LiveStage::ResumeThaw, "x"),
            state: VmLifecycleState::Error,
        };
        assert!(failed.is_terminal());
        assert!(!CaptureContinuation::Pending.is_terminal());
    }

    #[test]
    fn complete_maps_share_identity_and_reject_malformed_encodings() {
        let digest = Sha256Digest::of_bytes(b"short final chunk");
        let map = StreamMap::new(STREAM_CHUNK_BYTES + 17, vec![None, Some(digest)]).unwrap();
        let mut identity = StreamIdentity::new();
        identity.push_digest(STREAM_CHUNK_BYTES, None).unwrap();
        identity.push_digest(17, Some(digest)).unwrap();
        assert_eq!(map.id(), identity.finish());
        let encoded = map.canonical_bytes().unwrap();
        assert_eq!(StreamMap::decode(&encoded).unwrap(), map);
        assert!(StreamMap::new(STREAM_CHUNK_BYTES + 1, vec![None]).is_err());
        for malformed in [
            br#"{"chunkSize":8388608,"chunks":[],"kind":"stream","length":1,"schema":1}"#.as_slice(),
            br#"{"chunkSize":8388608,"chunks":["zero"],"kind":"stream","length":1,"schema":1,"schema":1}"#,
            br#"{"chunkSize":4096,"chunks":["zero"],"kind":"stream","length":1,"schema":1}"#,
            br#"{"chunkSize":8388608,"chunks":[null],"kind":"stream","length":1,"schema":1}"#,
        ] { assert!(StreamMap::decode(malformed).is_err()); }
        assert_eq!(CaptureRole::RamMap.relative_path(), "memory.map.json");
        assert_eq!(
            "ram-map".parse::<CaptureRole>().unwrap(),
            CaptureRole::RamMap
        );
        assert_eq!(
            serde_json::to_string(&CaptureRole::RamMap).unwrap(),
            "\"ram-map\""
        );
        assert!("memory.map.json".parse::<CaptureRole>().is_err());
    }

    #[test]
    fn one_tib_ram_map_and_writer_receipt_fit_their_metadata_bounds() {
        let count = (MAX_CAPTURE_RAM_BYTES / STREAM_CHUNK_BYTES) as usize;
        let bitmap = full_dirty_chunks(MAX_CAPTURE_RAM_BYTES).unwrap();
        assert_eq!(bitmap.len(), 16384);
        validate_dirty_chunks(MAX_CAPTURE_RAM_BYTES, &bitmap).unwrap();
        assert!(validate_dirty_chunks(MAX_CAPTURE_RAM_BYTES, &bitmap[..bitmap.len() - 1]).is_err());
        assert!(validate_dirty_chunks(1, &[2]).is_err());
        assert!(full_dirty_chunks(0).is_err());
        assert!(full_dirty_chunks(MAX_CAPTURE_RAM_BYTES + 1).is_err());
        let map = StreamMap::new(
            MAX_CAPTURE_RAM_BYTES,
            vec![Some(Sha256Digest::of_bytes(b"chunk")); count],
        )
        .unwrap();
        let encoded = map.canonical_bytes().unwrap();
        assert!(encoded.len() > (1 << 20));
        assert!(encoded.len() < MAX_RAM_MAP_BYTES);
        assert!((MAX_RAM_MAP_BYTES as u64) < CAPTURE_STATE_RESERVE_BYTES);
        assert_eq!(StreamMap::decode(&encoded).unwrap(), map);
        let mut record = evidence(&plan());
        let memory = record.memory.as_mut().unwrap();
        memory.packed_length = MAX_CAPTURE_RAM_BYTES;
        memory.dirty_chunks = bitmap;
        memory.chunk_digests = map.chunks().to_vec();
        memory.ram_stream = map.id();
        memory.stats.logical_bytes = MAX_CAPTURE_RAM_BYTES;
        memory.stats.identity_bytes_hashed = MAX_CAPTURE_RAM_BYTES;
        record.inventory[2].length = MAX_CAPTURE_RAM_BYTES;
        record.inventory[2].identity = Some(map.id());
        record.inventory[4].length = encoded.len() as u64;
        let bytes = record.canonical_bytes().unwrap();
        assert!(bytes.len() < MAX_CAPTURE_RECORD_BYTES);
        CaptureEvidence::decode(&bytes).unwrap();
    }

    #[test]
    fn crossover_and_actual_mode_are_independent_validated_facts() {
        let mut plan = plan();
        for threshold in [0, 61, 255] {
            plan.dirty_crossover_percent = threshold;
            assert!(plan.validate().is_err());
        }
        for threshold in [1, 60] {
            plan.dirty_crossover_percent = threshold;
            plan.validate().unwrap();
        }
        let mut seal = evidence(&plan);
        seal.memory.as_ref().unwrap().validate_capture().unwrap();
        let mut memory = seal.memory.clone().unwrap();
        memory.mode = CapturePolicy::Incremental;
        memory.full_reason = None;
        assert!(memory.validate_capture().is_err());
        memory.baseline = Some(Sha256Digest::of_bytes(b"exact predecessor stream"));
        memory.validate_capture().unwrap();
        seal.memory = Some(memory.clone());
        assert!(seal
            .validate_against_plan(&plan, &seal.request_digest)
            .is_err());
        plan.policy = CapturePolicy::Incremental;
        seal.request_digest = Sha256Digest::of_bytes(&plan.canonical_bytes().unwrap());
        seal.validate_against_plan(&plan, &seal.request_digest)
            .unwrap();
        memory.stats.identity_bytes_hashed -= 1;
        assert!(memory.validate_capture().is_err());
        memory.stats.identity_bytes_hashed += 1;
        memory.page_granule = 0;
        assert!(memory.validate_capture().is_err());
    }

    #[test]
    fn capture_records_have_no_durability_mode() {
        let plan = plan();
        let bytes = plan.canonical_bytes().unwrap();
        assert_eq!(CapturePlan::decode(&bytes).unwrap(), plan);
        let record = evidence(&plan);
        record
            .validate_against_plan(&plan, &Sha256Digest::of_bytes(&bytes))
            .unwrap();
        let encoded = record.canonical_bytes().unwrap();
        assert_eq!(CaptureEvidence::decode(&encoded).unwrap(), record);
        for bytes in [&bytes, &encoded] {
            let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert!(value.get("cut").is_none());
        }
    }

    #[test]
    fn stream_inventory_and_restore_use_only_stream_identity() {
        let mut request = restore_request();
        request.validate().unwrap();
        let ram = request
            .evidence
            .inventory
            .iter()
            .find(|entry| entry.role == CaptureRole::Ram)
            .unwrap();
        let encoded = serde_json::to_value(ram).unwrap();
        assert!(encoded.get("sha256").is_none());
        assert!(encoded.get("identity").is_some());
        request.objects[0].identity = Sha256Digest::of_bytes(b"wrong stream");
        assert!(request.validate().is_err());
        let mut record = evidence(&plan());
        record.inventory[2].sha256 = Some(Sha256Digest::of_bytes(b"byte sha"));
        assert!(record.validate().is_err());
        let mut record = evidence(&plan());
        record.inventory[0].identity = record.inventory[0].sha256.take();
        assert!(record.validate().is_err());
    }
    #[test]
    fn memory_seed_method_is_required_and_has_exact_wire_values() {
        use crate::capture::{CaptureMemoryStats, CaptureSeedMethod};

        for (method, wire) in [
            (CaptureSeedMethod::Clone, "clone"),
            (CaptureSeedMethod::Rebuild, "rebuild"),
        ] {
            let stats = CaptureMemoryStats {
                seed_method: method,
                ..Default::default()
            };
            let mut value = serde_json::to_value(&stats).unwrap();
            assert_eq!(value["seedMethod"], wire);
            assert_eq!(
                serde_json::from_value::<CaptureMemoryStats>(value.clone()).unwrap(),
                stats
            );
            value.as_object_mut().unwrap().remove("seedMethod");
            assert!(serde_json::from_value::<CaptureMemoryStats>(value).is_err());
        }
    }

    #[test]
    fn clone_seed_requires_incremental_capture_without_baseline_io() {
        use crate::capture::CaptureSeedMethod;

        let mut memory = evidence(&plan()).memory.unwrap();
        memory.stats.seed_method = CaptureSeedMethod::Clone;
        assert!(memory.validate_capture().is_err());
        memory.mode = CapturePolicy::Incremental;
        memory.full_reason = None;
        memory.baseline = Some(Sha256Digest::of_bytes(b"predecessor"));
        memory.validate_capture().unwrap();
        memory.stats.baseline_bytes_read = 1;
        assert!(memory.validate_capture().is_err());
        memory.stats.baseline_bytes_read = 0;
        memory.stats.baseline_bytes_written = 1;
        assert!(memory.validate_capture().is_err());
    }
}
