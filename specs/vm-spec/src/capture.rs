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
pub const CAPTURE_RAM_MAP_FILE: &str = "memory.root";
pub const CAPTURE_RAM_CHANGES_FILE: &str = "memory.changes";
pub const CAPTURE_MAP_NODES_DIRECTORY: &str = "map-nodes";
pub const CAPTURE_EVIDENCE_FILE: &str = "vm.capture.json";
pub const CAPTURE_SOURCE_FILE: &str = "vm.capture-source.json";
/// Immutable cut retained before post-continuation disk identity completion.
pub const CAPTURE_CUT_FILE: &str = "vm.capture-cut.json";
pub const CAPTURE_CUT_TEMPORARY_FILE: &str = ".vm.capture-cut.json.tmp";
/// The only temporary names a reader may find next to the records. A
/// temporary is never a record; it is left only by an interrupted write.
pub const CAPTURE_EVIDENCE_TEMPORARY_FILE: &str = ".vm.capture.json.tmp";
pub const CAPTURE_SOURCE_TEMPORARY_FILE: &str = ".vm.capture-source.json.tmp";
/// Upper bound for one JSON control record (plan, evidence, continuation).
pub const MAX_CAPTURE_RECORD_BYTES: usize = (1 << 20) + MAX_DISK_TRACKING_BYTES;
/// ADR 0021 `Resource Limits`: staged state and evidence allowance.
pub const CAPTURE_STATE_RESERVE_BYTES: u64 = 64 << 20;
/// ADR 0021 `Resource Limits`: metadata charge of a qualified clone.
pub const CAPTURE_CLONE_RESERVE_BYTES: u64 = 16 << 20;
/// ADR 0021 `Resource Limits`: RAM per captured machine.
pub const MAX_CAPTURE_RAM_BYTES: u64 = 1 << 40;
/// Disk identity and disk tracking unit, independent of RAM identity.
pub const STREAM_CHUNK_BYTES: u64 = 8 << 20;
/// ADR 0014 total logical stream admission bound.
pub const MAX_STREAM_BYTES: u64 = 4 << 40;
/// Bound for libvm's opaque read-only input identities.
pub const MAX_INPUT_IDENTITY_BYTES: usize = 256;
/// Public native binding string bounds.
pub const MAX_LIVE_STATE_SCHEMA_BYTES: usize = 256;
pub const MAX_ARCHITECTURE_BYTES: usize = 32;

const MIB: u64 = 1 << 20;

/// Relative path of one capture directory below the machine data directory.
pub fn capture_directory(capture_id: &LiveId) -> String {
    format!("{CAPTURES_DIRECTORY}/{capture_id}")
}

fn invalid(message: impl Into<String>) -> String {
    message.into()
}

/// A known optional field must still be present (as `null` when absent).
pub(crate) fn required<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
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

/// A validated native change, independent of tree storage and retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRamChange {
    Data { index: u64, digest: Sha256Digest },
    Zero { first_index: u64, count: u64 },
}

/// Constant-memory reader authenticating the exact native change file.
/// Consumers must exhaust it to observe its length and digest verification.
pub struct RamChangeReader<R> {
    input: R,
    expected: CaptureRamChanges,
    hash: Sha256,
    remaining: u64,
    chunk_count: u64,
    previous_end: u64,
    previous_zero: bool,
    failed: bool,
}

impl<R: std::io::Read> RamChangeReader<R> {
    pub fn new(mut input: R, length: u64, expected: &CaptureRamChanges) -> std::io::Result<Self> {
        expected.validate(length).map_err(std::io::Error::other)?;
        let mut header = [0; 16];
        input.read_exact(&mut header)?;
        let coverage = match expected.coverage {
            CaptureRamCoverage::Full => 0,
            CaptureRamCoverage::Incremental => 1,
        };
        if &header[..8] != b"KRUNRAM\0"
            || header[8..10] != [1, 0]
            || header[10] != 16
            || header[11] != coverage
            || header[12..] != [0; 4]
        {
            return Err(std::io::Error::other(
                "invalid RAM changes header or identity profile",
            ));
        }
        let mut hash = Sha256::new();
        hash.update(header);
        Ok(Self {
            input,
            expected: expected.clone(),
            hash,
            remaining: expected.record_count,
            chunk_count: length.div_ceil(1 << 16),
            previous_end: 0,
            previous_zero: false,
            failed: false,
        })
    }

    fn read_next(&mut self) -> std::io::Result<Option<CaptureRamChange>> {
        if self.remaining == 0 {
            let mut extra = [0; 1];
            if self.input.read(&mut extra)? != 0 {
                return Err(std::io::Error::other("RAM changes has trailing bytes"));
            }
            let actual = Sha256Digest::from_bytes(self.hash.clone().finalize().into());
            if actual != self.expected.sha256 {
                return Err(std::io::Error::other("RAM changes digest mismatch"));
            }
            return Ok(None);
        }
        let mut bytes = [0; 56];
        self.input.read_exact(&mut bytes)?;
        self.hash.update(bytes);
        let integer = |slice: &[u8]| -> std::io::Result<u64> {
            let value: [u8; 8] = slice.try_into().map_err(std::io::Error::other)?;
            Ok(u64::from_le_bytes(value))
        };
        let first = integer(&bytes[..8])?;
        let count = integer(&bytes[8..16])?;
        let end = first
            .checked_add(count)
            .filter(|end| *end <= self.chunk_count);
        let zero = bytes[16] == 0;
        if count == 0
            || end.is_none()
            || first < self.previous_end
            || (zero && self.previous_zero && first == self.previous_end)
            || bytes[17..24] != [0; 7]
            || (zero
                && (bytes[24..] != [0; 32] || self.expected.coverage == CaptureRamCoverage::Full))
            || (!zero && (bytes[16] != 1 || count != 1 || bytes[24..] == [0; 32]))
        {
            return Err(std::io::Error::other(
                "RAM changes records are invalid, overlapping or unsorted",
            ));
        }
        self.previous_end =
            end.ok_or_else(|| std::io::Error::other("RAM changes range overflow"))?;
        self.previous_zero = zero;
        self.remaining -= 1;
        if zero {
            Ok(Some(CaptureRamChange::Zero {
                first_index: first,
                count,
            }))
        } else {
            let digest = bytes[24..].try_into().map_err(std::io::Error::other)?;
            Ok(Some(CaptureRamChange::Data {
                index: first,
                digest: Sha256Digest::from_bytes(digest),
            }))
        }
    }
}

impl<R: std::io::Read> Iterator for RamChangeReader<R> {
    type Item = std::io::Result<CaptureRamChange>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.read_next() {
            Ok(Some(change)) => Some(Ok(change)),
            Ok(None) => {
                self.failed = true;
                None
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
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
/// `ram-map` selects the fixed binary `memory.root`, never an arbitrary path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CaptureRole {
    Execution,
    Devices,
    Ram,
    Layout,
    RamMap,
    RamChanges,
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
            Self::RamChanges => CAPTURE_RAM_CHANGES_FILE.into(),
            Self::Disk(name) => format!("{CAPTURE_DISKS_DIRECTORY}/{}", name.file_name()),
            Self::DiskMap(name) => format!("{CAPTURE_DISKS_DIRECTORY}/{}.root", name.as_str()),
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
            CAPTURE_RAM_CHANGES_FILE => Self::RamChanges,
            other => {
                let name = other
                    .strip_prefix(CAPTURE_DISKS_DIRECTORY)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .ok_or_else(|| invalid(format!("unknown capture role {other:?}")))?;
                if let Some(name) = name.strip_suffix(".raw") {
                    Self::Disk(CaptureDiskName::new(name)?)
                } else if let Some(name) = name.strip_suffix(".root") {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiskIdentityState {
    Unknown,
    UnknownAfterFork,
    Identified { root: Sha256Digest },
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
    pub identity: DiskIdentityState,
    /// Only exclusively managed backing may inherit a tracked predecessor.
    pub tracking_eligible: bool,
    /// Immutable canonical map supplied under the launch storage authority.
    #[serde(deserialize_with = "required")]
    pub baseline_map: Option<String>,
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

/// Content authentication is independent of byte materialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureIdentityPolicy {
    None,
    Full,
    SinceAnchor,
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
    pub identity_policy: CaptureIdentityPolicy,
    pub dirty_crossover_percent: u8,
    pub resume_policy: CaptureResumePolicy,
    pub pause: CapturePauseAuthority,
    pub ram_bytes: u64,
    pub disks: Vec<CaptureDiskPlan>,
    pub read_only_inputs: Vec<CaptureReadOnlyInput>,
    pub reservation: CaptureReservation,
    #[serde(deserialize_with = "required")]
    pub map_node_store: Option<String>,
}

impl CapturePlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.identity_policy == CaptureIdentityPolicy::None && self.map_node_store.is_some() {
            return Err(invalid("owned fork capture cannot publish map nodes"));
        }
        if self
            .map_node_store
            .as_ref()
            .is_some_and(|path| path.len() > 4096 || !std::path::Path::new(path).is_absolute())
        {
            return Err(invalid("map node store path must be bounded and absolute"));
        }
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
            if disk
                .baseline_map
                .as_ref()
                .is_some_and(|path| path.len() > 4096 || !std::path::Path::new(path).is_absolute())
            {
                return Err(invalid(
                    "disk baseline map path is not bounded and absolute",
                ));
            }
            if disk.baseline_map.is_some()
                && !matches!(disk.identity, DiskIdentityState::Identified { .. })
            {
                return Err(invalid("disk map requires identified baseline authority"));
            }
            if !disk.tracking_eligible && disk.baseline_map.is_some() {
                return Err(invalid("external disk cannot carry baseline authority"));
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
        if self.identity_policy == CaptureIdentityPolicy::None {
            let mut roles = vec![
                CaptureRole::Execution,
                CaptureRole::Devices,
                CaptureRole::Ram,
                CaptureRole::Layout,
            ];
            roles.extend(
                self.disks
                    .iter()
                    .map(|disk| CaptureRole::Disk(disk.name.clone())),
            );
            return roles;
        }
        let mut roles = vec![
            CaptureRole::Execution,
            CaptureRole::Devices,
            CaptureRole::Ram,
            CaptureRole::Layout,
            CaptureRole::RamMap,
            CaptureRole::RamChanges,
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
    pub live_state_schema: String,
    pub architecture: String,
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureIdentityReadFallback {
    #[default]
    None,
    CoverageLost,
    BaselineMismatch,
    ExtentsUnavailable,
    ExtentLimit,
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
    /// Zero-valued bytes physically written by overlay writes, including mixed data.
    pub explicit_zero_bytes_written: u64,
    /// Complete zero runs successfully covered, whether omitted, punched, or written.
    pub zero_run_bytes_covered: u64,
    /// Covered zero bytes deallocated from a seeded output, never the baseline.
    pub zero_bytes_punched: u64,
    /// Live RAM bytes not read because cut metadata or B holes plus complete D prove zero.
    pub known_zero_bytes_skipped: u64,
    pub extent_queries: u64,
    pub identity_bytes_hashed: u64,
    /// Always zero on local capture; byte SHA is reserved for transported blobs.
    pub whole_file_bytes_hashed: u64,
    pub map_nodes_written: u64,
    pub identity_dirty_pages: u64,
    pub materialization_dirty_pages: u64,
    pub live_pages_classified: u64,
    pub identity_zero_bytes_filled: u64,
    pub full_identity_read_fallback: CaptureIdentityReadFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureRamCoverage {
    Full,
    Incremental,
}

/// Bounded binding to the native change file, never a per-chunk receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureRamChanges {
    pub byte_len: u64,
    pub sha256: Sha256Digest,
    pub record_count: u64,
    pub coverage: CaptureRamCoverage,
    #[serde(deserialize_with = "required")]
    pub baseline_stream: Option<Sha256Digest>,
}

impl CaptureRamChanges {
    pub fn validate(&self, length: u64) -> Result<(), String> {
        let count = length.div_ceil(1 << 16);
        if length == 0
            || length > MAX_CAPTURE_RAM_BYTES
            || self.record_count > count
            || self
                .record_count
                .checked_mul(56)
                .and_then(|bytes| bytes.checked_add(16))
                != Some(self.byte_len)
            || (self.coverage == CaptureRamCoverage::Full && self.baseline_stream.is_some())
            || (self.coverage == CaptureRamCoverage::Incremental && self.baseline_stream.is_none())
        {
            return Err(invalid(
                "RAM change summary has invalid length, count or coverage",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureIdentityFullReason {
    Requested,
    NoIdentifiedAnchor,
    UnknownAnchorAfterFork,
    CoverageLost,
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
    pub identity_policy: CaptureIdentityPolicy,
    #[serde(deserialize_with = "required")]
    pub identity_full_reason: Option<CaptureIdentityFullReason>,
    #[serde(deserialize_with = "required")]
    pub baseline: Option<Sha256Digest>,
    #[serde(deserialize_with = "required")]
    pub full_reason: Option<CaptureFullReason>,
    pub identity_chunk_bytes: u32,
    pub changes: CaptureRamChanges,
    pub stats: CaptureMemoryStats,
}

impl CaptureMemoryEvidence {
    pub fn validate_capture(&self) -> Result<(), String> {
        if !self.page_granule.is_power_of_two()
            || self.page_granule < 4096
            || self.regions == 0
            || self.page_granule > 65536
            || !self
                .packed_length
                .is_multiple_of(u64::from(self.page_granule))
            || u64::from(self.regions) > self.packed_length / u64::from(self.page_granule)
            || self.binding.live_state_schema.is_empty()
            || self.binding.live_state_schema.contains('\0')
            || self.binding.live_state_schema.len() > MAX_LIVE_STATE_SCHEMA_BYTES
            || self.binding.architecture.is_empty()
            || self.binding.architecture.contains('\0')
            || self.binding.architecture.len() > MAX_ARCHITECTURE_BYTES
            || [
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
        self.changes.validate(self.packed_length)?;
        if self.identity_chunk_bytes != 1 << 16
            || self.changes.baseline_stream != self.baseline
            || (self.identity_policy == CaptureIdentityPolicy::Full)
                != (self.changes.coverage == CaptureRamCoverage::Full)
            || self.identity_policy == CaptureIdentityPolicy::None
            || (self.identity_policy == CaptureIdentityPolicy::Full)
                != self.identity_full_reason.is_some()
        {
            return Err(invalid(
                "RAM change summary differs from its capture binding",
            ));
        }
        match self.mode {
            CapturePolicy::Full if self.full_reason.is_none() => {
                return Err(invalid(
                    "full RAM capture requires a reason and no reused baseline",
                ));
            }
            CapturePolicy::Incremental if self.full_reason.is_some() => {
                return Err(invalid(
                    "incremental RAM capture requires its exact baseline",
                ));
            }
            _ => {}
        }
        if self.stats.logical_bytes != self.packed_length
            || (self.stats.seed_method == CaptureSeedMethod::Clone
                && (self.mode != CapturePolicy::Incremental
                    || self.stats.baseline_bytes_written != 0))
            || self.stats.whole_file_bytes_hashed != 0
            || self.stats.identity_bytes_hashed > self.changes.record_count.saturating_mul(1 << 16)
            || self.stats.identity_bytes_hashed > self.packed_length
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

/// Host-local write coverage, independent of portable disk stream identity.
pub const DISK_TRACKING_VERSION: u32 = 1;
pub const MAX_DISK_TRACKING_BYTES: usize = 16 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiskTrackingInvalidReason {
    NeverArmed,
    Lost,
    Overflow,
    OutOfDeviceMutationSuspected,
}

/// `Some(baseline)` asserts a complete authenticated map and exclusive writer
/// ownership of this exact backing from constructor admission onwards.
/// `None` requires full immutable-cut authentication before baseline acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskTrackingSeed {
    pub version: u32,
    pub map_format: u32,
    pub chunk_shift: u8,
    pub role: DiskRole,
    pub attachment_index: u32,
    pub block_id: BlockId,
    pub file_device: u64,
    pub file_inode: u64,
    pub length: u64,
    pub chunk_size: u64,
    pub epoch: LiveId,
    /// Baseline stream identity, not a portable identity for this host binding.
    #[serde(deserialize_with = "required")]
    pub baseline: Option<Sha256Digest>,
}

impl DiskTrackingSeed {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != DISK_TRACKING_VERSION
            || self.map_format != 1
            || self.chunk_shift != 23
            || self.file_inode == 0
            || self.attachment_index >= 16
            || self.role == DiskRole::RootLower
            || self.length == 0
            || self.length > MAX_STREAM_BYTES
            || !self.length.is_multiple_of(512)
            || self.chunk_size != STREAM_CHUNK_BYTES
        {
            return Err(invalid(
                "disk tracking seed version, binding or geometry is invalid",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_DISK_TRACKING_BYTES {
            return Err(invalid("disk tracking seed exceeds its bound"));
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if value.canonical_bytes()? != bytes {
            return Err(invalid("disk tracking seed bytes are not canonical"));
        }
        Ok(value)
    }
}

/// Half-open identity-chunk range. Adjacent ranges must be coalesced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskDirtyRun {
    pub first_chunk: u64,
    pub chunk_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskGenerationToken {
    pub capture_id: LiveId,
    pub pause_generation: u64,
    pub epoch: LiveId,
    pub generation: u64,
    pub file_device: u64,
    pub file_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskTrackingReceipt {
    pub version: u32,
    pub seed: DiskTrackingSeed,
    pub token: DiskGenerationToken,
    pub runs: Vec<DiskDirtyRun>,
    pub dirty_chunks: u64,
    pub total_chunks: u64,
    #[serde(deserialize_with = "required")]
    pub invalid_reason: Option<DiskTrackingInvalidReason>,
}

impl DiskTrackingReceipt {
    pub fn validate(&self) -> Result<(), String> {
        self.seed.validate()?;
        if self.version != DISK_TRACKING_VERSION
            || self.token.epoch != self.seed.epoch
            || self.token.file_device != self.seed.file_device
            || self.token.file_inode != self.seed.file_inode
            || self.token.generation == 0
            || self.token.pause_generation == 0
            || self.total_chunks != self.seed.length.div_ceil(self.seed.chunk_size)
            || (self.seed.baseline.is_none() && self.invalid_reason.is_none())
        {
            return Err(invalid("disk generation binding or coverage is invalid"));
        }
        let mut previous_end = None;
        let mut count = 0u64;
        for run in &self.runs {
            let end = run
                .first_chunk
                .checked_add(run.chunk_count)
                .ok_or_else(|| invalid("disk dirty run overflows"))?;
            if run.chunk_count == 0
                || end > self.total_chunks
                || previous_end.is_some_and(|previous| run.first_chunk <= previous)
            {
                return Err(invalid("disk dirty runs are not bounded and coalesced"));
            }
            previous_end = Some(end);
            count = count
                .checked_add(run.chunk_count)
                .ok_or_else(|| invalid("disk dirty count overflows"))?;
        }
        if count != self.dirty_chunks {
            return Err(invalid("disk dirty count differs from runs"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_DISK_TRACKING_BYTES {
            return Err(invalid("disk tracking receipt exceeds its bound"));
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if value.canonical_bytes()? != bytes {
            return Err(invalid("disk tracking receipt bytes are not canonical"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiskGenerationSettlement {
    Commit { baseline: Sha256Digest },
    Abort,
}

/// Settlement is independent of RAM baseline acceptance and source resumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskTrackingSettlement {
    pub version: u32,
    pub block_id: BlockId,
    pub token: DiskGenerationToken,
    pub settlement: DiskGenerationSettlement,
}

impl DiskTrackingSettlement {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != DISK_TRACKING_VERSION
            || self.token.generation == 0
            || self.token.pause_generation == 0
            || self.token.file_inode == 0
        {
            return Err(invalid("disk settlement version or token is invalid"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_DISK_TRACKING_BYTES {
            return Err(invalid("disk settlement exceeds its bound"));
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if value.canonical_bytes()? != bytes {
            return Err(invalid("disk settlement bytes are not canonical"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiskFullScanReason {
    InvalidReceipt { reason: DiskTrackingInvalidReason },
    MissingBaseline,
    UnknownAnchorAfterFork,
    Untracked,
    CopyLane,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureDiskStats {
    pub name: CaptureDiskName,
    pub dirty_chunks: u64,
    pub total_chunks: u64,
    /// Decoded nonzero chunk bytes passed to SHA-256.
    pub bytes_hashed: u64,
    pub baseline_reused: bool,
    #[serde(deserialize_with = "required")]
    pub full_scan_reason: Option<DiskFullScanReason>,
}

/// Exact-file facts, identical to the storage source fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFingerprint {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub mode: u32,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

impl SourceFingerprint {
    pub fn validate(&self) -> Result<(), String> {
        if self.inode == 0
            || self.length == 0
            || self.length > MAX_STREAM_BYTES
            || self.mode & 0o170000 != 0o100000
            || self.mode & 0o222 != 0
            || !(0..1_000_000_000).contains(&self.modified_nanoseconds)
            || !(0..1_000_000_000).contains(&self.changed_nanoseconds)
        {
            return Err(invalid(
                "owned member has invalid immutable regular-file facts",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedCutMember {
    pub role: CaptureRole,
    pub fingerprint: SourceFingerprint,
    pub complete: bool,
}

/// Local ownership evidence, never portable content authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedLocalCut {
    pub version: u32,
    pub machine_id: LiveId,
    pub run_id: LiveId,
    pub capture_id: LiveId,
    pub freeze_operation_id: LiveId,
    pub freeze_epoch: NonZeroU64,
    pub configuration: CaptureConfiguration,
    pub binding: CaptureStateBinding,
    pub materialization_generation: NonZeroU64,
    pub predecessor_generation: u64,
    pub packed_length: u64,
    pub page_granule: u32,
    pub regions: u32,
    pub members: Vec<OwnedCutMember>,
    pub stats: CaptureMemoryStats,
}

/// Closed-writer facts used by the monitor to produce a local cut record.
pub struct OwnedCutCompletion {
    pub freeze_operation_id: LiveId,
    pub freeze_epoch: NonZeroU64,
    pub binding: CaptureStateBinding,
    pub materialization_generation: NonZeroU64,
    pub predecessor_generation: u64,
    pub packed_length: u64,
    pub page_granule: u32,
    pub regions: u32,
    pub members: Vec<OwnedCutMember>,
    pub stats: CaptureMemoryStats,
}

impl OwnedLocalCut {
    pub fn from_completed(
        plan: &CapturePlan,
        completion: OwnedCutCompletion,
    ) -> Result<Self, String> {
        let cut = Self {
            version: CAPTURE_RECORD_VERSION,
            machine_id: plan.machine_id.clone(),
            run_id: plan.run_id.clone(),
            capture_id: plan.capture_id.clone(),
            configuration: plan.configuration.clone(),
            freeze_operation_id: completion.freeze_operation_id,
            freeze_epoch: completion.freeze_epoch,
            binding: completion.binding,
            materialization_generation: completion.materialization_generation,
            predecessor_generation: completion.predecessor_generation,
            packed_length: completion.packed_length,
            page_granule: completion.page_granule,
            regions: completion.regions,
            members: completion.members,
            stats: completion.stats,
        };
        cut.validate_against_plan(plan)?;
        Ok(cut)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.configuration.validate()?;
        if self.version != CAPTURE_RECORD_VERSION
            || self.binding.source_run != self.run_id
            || self.binding.capture != self.capture_id
            || self.binding.live_state_schema.is_empty()
            || self.binding.live_state_schema.contains('\0')
            || self.binding.live_state_schema.len() > MAX_LIVE_STATE_SCHEMA_BYTES
            || self.binding.architecture.is_empty()
            || self.binding.architecture.contains('\0')
            || self.binding.architecture.len() > MAX_ARCHITECTURE_BYTES
            || self.predecessor_generation >= self.materialization_generation.get()
            || self.packed_length != self.configuration.ram_bytes()
            || self.packed_length == 0
            || self.packed_length > MAX_CAPTURE_RAM_BYTES
            || !self.page_granule.is_power_of_two()
            || !(4096..=65536).contains(&self.page_granule)
            || !self
                .packed_length
                .is_multiple_of(u64::from(self.page_granule))
            || self.regions == 0
            || self.regions > 512
            || u64::from(self.regions) > self.packed_length / u64::from(self.page_granule)
            || self.stats.materialization_dirty_pages
                > self.packed_length / u64::from(self.page_granule)
            || self.stats.identity_dirty_pages > self.packed_length / u64::from(self.page_granule)
            || self.stats.logical_bytes != self.packed_length
            || self.stats.identity_bytes_hashed != 0
            || self.stats.whole_file_bytes_hashed != 0
            || self.stats.map_nodes_written != 0
        {
            return Err(invalid(
                "owned cut has invalid binding, geometry, generation or identity work",
            ));
        }
        let mut writable = self
            .configuration
            .attachments
            .iter()
            .filter(|attachment| !attachment.read_only);
        if self.members.len() != 4 + writable.clone().count() {
            return Err(invalid(
                "owned cut does not cover its complete member inventory",
            ));
        }
        let native = [
            CaptureRole::Execution,
            CaptureRole::Devices,
            CaptureRole::Ram,
            CaptureRole::Layout,
        ];
        let mut inodes = std::collections::BTreeSet::new();
        let mut names = std::collections::HashSet::with_capacity(self.members.len());
        for (index, member) in self.members.iter().enumerate() {
            member.fingerprint.validate()?;
            if !member.complete
                || !inodes.insert((member.fingerprint.device, member.fingerprint.inode))
                || !names.insert(&member.role)
            {
                return Err(invalid("owned cut members must be complete and distinct"));
            }
            if index < native.len() {
                let maximum = match member.role {
                    CaptureRole::Execution => 16 << 20,
                    CaptureRole::Devices => 32 << 20,
                    CaptureRole::Layout => 64 << 10,
                    _ => MAX_CAPTURE_RAM_BYTES,
                };
                if member.role != native[index]
                    || member.fingerprint.length > maximum
                    || (member.role == CaptureRole::Ram
                        && member.fingerprint.length != self.packed_length)
                {
                    return Err(invalid(
                        "owned native members have invalid roles or lengths",
                    ));
                }
            } else if !matches!(member.role, CaptureRole::Disk(_))
                || writable.next().is_none_or(|attachment| {
                    member.fingerprint.length != attachment.geometry.length
                })
            {
                return Err(invalid("owned disk members have invalid roles or geometry"));
            }
        }
        Ok(())
    }

    pub fn validate_against_plan(&self, plan: &CapturePlan) -> Result<(), String> {
        self.validate()?;
        plan.validate()?;
        let freeze_matches = match &plan.pause {
            CapturePauseAuthority::Acquire => self.freeze_operation_id == plan.capture_id,
            CapturePauseAuthority::Borrow {
                token,
                pause_operation_id,
            } => {
                self.freeze_operation_id == *pause_operation_id
                    && self.binding.pause_generation == token.generation
            }
        };
        if plan.identity_policy != CaptureIdentityPolicy::None
            || !freeze_matches
            || self.machine_id != plan.machine_id
            || self.run_id != plan.run_id
            || self.capture_id != plan.capture_id
            || self.configuration != plan.configuration
            || self
                .members
                .iter()
                .map(|member| &member.role)
                .ne(plan.roles().iter())
        {
            return Err(invalid("owned cut differs from its exact fork plan"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CAPTURE_RECORD_BYTES {
            return Err(invalid("owned cut exceeds its record bound"));
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if value.canonical_bytes()? != bytes {
            return Err(invalid("owned cut bytes are not canonical"));
        }
        Ok(value)
    }
}

/// Operation-owned clone fingerprint, sampled after the last writer closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureDiskCut {
    pub name: CaptureDiskName,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub mode: u32,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
    #[serde(deserialize_with = "required")]
    pub tracking_receipt: Option<DiskTrackingReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureCutPhase {
    IdentityPending,
}

/// `vm.capture-cut.json` is never a seal. Its evidence keeps
/// `disk_copies_sealed` false and lacks exactly the pending clone/map roles.
/// Recovery completes those roles from retained bytes before setting the fact.
/// Pending clone receipts live beside their fingerprints; this partial evidence
/// retains only completed copy receipts. Coherent evidence reunites every disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureCutRecord {
    pub phase: CaptureCutPhase,
    pub evidence: CaptureEvidence,
    pub disks: Vec<CaptureDiskCut>,
}

impl CaptureCutRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CAPTURE_RECORD_BYTES {
            return Err(invalid("capture cut record exceeds its bound"));
        }
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn validate_against_plan(
        &self,
        plan: &CapturePlan,
        request_digest: &Sha256Digest,
    ) -> Result<(), String> {
        let evidence = &self.evidence;
        if evidence.version != CAPTURE_RECORD_VERSION
            || evidence.machine_id != plan.machine_id
            || evidence.run_id != plan.run_id
            || evidence.capture_id != plan.capture_id
            || evidence.configuration_digest != plan.configuration_digest
            || &evidence.request_digest != request_digest
            || evidence.capture_outcome != CaptureRecordOutcome::Coherent
            || evidence.error.is_some()
            || evidence.disk_copies_sealed
            || [
                evidence.workloads_frozen,
                evidence.vcpus_paused,
                evidence.devices_quiesced,
                evidence.host_writers_drained,
                evidence.host_flush_completed,
                evidence.memory_state_sealed,
            ]
            .contains(&false)
            || evidence.completed_at_unix_ms < evidence.started_at_unix_ms
            || self.disks.is_empty()
        {
            return Err(invalid(
                "pending identity cut does not bind its plan and immutable bytes",
            ));
        }
        let memory = evidence
            .memory
            .as_ref()
            .ok_or_else(|| invalid("cut lacks RAM evidence"))?;
        memory.validate_capture()?;
        if memory.packed_length > plan.ram_bytes
            || memory.binding.capture != plan.capture_id
            || memory.binding.source_run != plan.run_id
        {
            return Err(invalid("pending identity cut RAM differs from its plan"));
        }
        let token = evidence
            .pause_token
            .as_ref()
            .ok_or_else(|| invalid("cut lacks its pause"))?;
        if token.machine_id != plan.machine_id
            || token.run_id != plan.run_id
            || token.generation != memory.binding.pause_generation
            || evidence.freeze_epoch.is_none()
        {
            return Err(invalid("pending identity cut belongs to another pause"));
        }
        match &plan.pause {
            CapturePauseAuthority::Acquire
                if evidence.pause_disposition == Some(CapturePauseDisposition::Acquired)
                    && evidence.freeze_operation_id.as_ref() == Some(&plan.capture_id)
                    && token.owner
                        == (PauseOwner::Capture {
                            operation_id: plan.capture_id.clone(),
                        }) => {}
            CapturePauseAuthority::Borrow {
                token: expected,
                pause_operation_id,
            } if token == expected
                && evidence.pause_disposition == Some(CapturePauseDisposition::Borrowed)
                && evidence.freeze_operation_id.as_ref() == Some(pause_operation_id) => {}
            _ => return Err(invalid("pending identity cut changed pause authority")),
        }
        for (index, disk) in self.disks.iter().enumerate() {
            if disk.inode == 0
                || disk.mode & 0o177777 != 0o100600
                || self.disks[..index]
                    .iter()
                    .any(|other| other.name == disk.name)
                || !plan
                    .disks
                    .iter()
                    .any(|planned| planned.name == disk.name && planned.length == disk.length)
            {
                return Err(invalid("pending identity cut has an invalid disk owner"));
            }
            if let Some(receipt) = &disk.tracking_receipt {
                receipt.validate()?;
                let planned = plan
                    .disks
                    .iter()
                    .find(|planned| planned.name == disk.name)
                    .ok_or_else(|| invalid("disk receipt has no planned attachment"))?;
                let attachment = plan
                    .configuration
                    .attachments
                    .get(planned.attachment_index as usize)
                    .ok_or_else(|| invalid("disk receipt attachment is absent"))?;
                if receipt.token.capture_id != plan.capture_id
                    || receipt.token.pause_generation != token.generation.get()
                    || receipt.seed.attachment_index != planned.attachment_index
                    || receipt.seed.block_id != planned.block_id
                    || receipt.seed.role != attachment.role
                    || receipt.seed.length != disk.length
                    || (receipt.seed.file_device, receipt.seed.file_inode)
                        == (disk.device, disk.inode)
                {
                    return Err(invalid(
                        "disk tracking receipt differs from its immutable cut",
                    ));
                }
            }
        }
        let roles = plan
            .roles()
            .into_iter()
            .filter(|role| match role {
                CaptureRole::Disk(name) | CaptureRole::DiskMap(name) => {
                    !self.disks.iter().any(|disk| disk.name == *name)
                }
                _ => true,
            })
            .collect::<Vec<_>>();
        if roles.len() != evidence.inventory.len()
            || roles
                .iter()
                .zip(&evidence.inventory)
                .any(|(role, entry)| role != &entry.role)
        {
            return Err(invalid(
                "pending identity cut inventory differs from its plan",
            ));
        }
        Ok(())
    }
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
    pub disk_stats: Vec<CaptureDiskStats>,
    pub disk_tracking_receipts: Vec<DiskTrackingReceipt>,
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
                    || memory.binding.live_state_schema.is_empty()
                    || memory.binding.live_state_schema.len() > MAX_LIVE_STATE_SCHEMA_BYTES
                {
                    return Err(invalid("capture binding does not match its cut"));
                }
                memory.validate_capture()?;
                for (index, receipt) in self.disk_tracking_receipts.iter().enumerate() {
                    receipt.validate()?;
                    if receipt.token.capture_id != self.capture_id
                        || receipt.token.pause_generation != token.generation.get()
                        || self.disk_tracking_receipts[..index].iter().any(|other| {
                            other.seed.block_id == receipt.seed.block_id
                                || other.seed.attachment_index == receipt.seed.attachment_index
                        })
                    {
                        return Err(invalid(
                            "disk receipt differs from its unique capture pause",
                        ));
                    }
                }
                for (index, stats) in self.disk_stats.iter().enumerate() {
                    let disk = self
                        .inventory
                        .iter()
                        .find(|entry| entry.role == CaptureRole::Disk(stats.name.clone()))
                        .ok_or_else(|| invalid("disk statistics lack their sealed payload"))?;
                    if stats.total_chunks != disk.length.div_ceil(STREAM_CHUNK_BYTES)
                        || stats.dirty_chunks > stats.total_chunks
                        || stats.bytes_hashed > disk.length
                        || stats.baseline_reused != stats.full_scan_reason.is_none()
                        || self.disk_stats[..index]
                            .iter()
                            .any(|other| other.name == stats.name)
                    {
                        return Err(invalid("disk statistics have invalid geometry or lineage"));
                    }
                }
                for role in [
                    CaptureRole::Execution,
                    CaptureRole::Devices,
                    CaptureRole::Ram,
                    CaptureRole::Layout,
                    CaptureRole::RamMap,
                    CaptureRole::RamChanges,
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
                    if entry.role == CaptureRole::RamMap && entry.sha256 != Some(memory.ram_stream)
                    {
                        return Err(invalid("RAM root object differs from its stream identity"));
                    }
                    if entry.role == CaptureRole::RamChanges
                        && (entry.length != memory.changes.byte_len
                            || entry.sha256 != Some(memory.changes.sha256))
                    {
                        return Err(invalid(
                            "RAM changes object differs from its native summary",
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
                        CaptureRole::RamMap | CaptureRole::DiskMap(_) => {
                            Some(crate::stream_map::MAX_ROOT_BYTES as u64)
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
        if plan.identity_policy == CaptureIdentityPolicy::None {
            return Err(invalid(
                "owned local cut cannot produce identified capture evidence",
            ));
        }
        if self
            .memory
            .as_ref()
            .is_some_and(|memory| match plan.identity_policy {
                CaptureIdentityPolicy::None => true,
                CaptureIdentityPolicy::Full => {
                    memory.identity_policy != CaptureIdentityPolicy::Full
                }
                CaptureIdentityPolicy::SinceAnchor => {
                    memory.identity_policy != CaptureIdentityPolicy::SinceAnchor
                        && !matches!(
                            memory.identity_full_reason,
                            Some(
                                CaptureIdentityFullReason::NoIdentifiedAnchor
                                    | CaptureIdentityFullReason::UnknownAnchorAfterFork
                                    | CaptureIdentityFullReason::CoverageLost
                            )
                        )
                }
            })
        {
            return Err(invalid(
                "capture identity policy differs from its plan without a valid fallback",
            ));
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
        if (!self.disk_tracking_receipts.is_empty()
            && self.disk_tracking_receipts.len() != plan.disks.len())
            || (!self.disk_stats.is_empty() && self.disk_stats.len() != plan.disks.len())
        {
            return Err(invalid(
                "disk receipts or statistics do not cover the writable inventory",
            ));
        }
        for receipt in &self.disk_tracking_receipts {
            let planned = plan
                .disks
                .iter()
                .find(|disk| disk.block_id == receipt.seed.block_id)
                .ok_or_else(|| invalid("disk receipt attachment is not planned"))?;
            let attachment = plan
                .configuration
                .attachments
                .get(planned.attachment_index as usize)
                .ok_or_else(|| invalid("disk receipt configuration is missing"))?;
            if receipt.seed.attachment_index != planned.attachment_index
                || receipt.seed.length != planned.length
                || receipt.seed.role != attachment.role
            {
                return Err(invalid("disk receipt differs from its planned attachment"));
            }
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
            if !disk.tracking_eligible
                && self.disk_stats.iter().any(|stats| {
                    stats.name == disk.name
                        && (stats.baseline_reused
                            || stats.full_scan_reason != Some(DiskFullScanReason::External))
                })
            {
                return Err(invalid(
                    "external disk identity cannot inherit a tracked baseline",
                ));
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CaptureSuccess {
    Identified {
        sealed: CaptureSealed,
    },
    OwnedLocalCut {
        cut: Box<OwnedLocalCut>,
        cut_token: PauseToken,
    },
}

impl CaptureSuccess {
    pub fn capture_id(&self) -> &LiveId {
        match self {
            Self::Identified { sealed } => &sealed.capture_id,
            Self::OwnedLocalCut { cut, .. } => &cut.capture_id,
        }
    }

    pub fn cut_token(&self) -> &PauseToken {
        match self {
            Self::Identified { sealed } => &sealed.cut_token,
            Self::OwnedLocalCut { cut_token, .. } => cut_token,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Self::OwnedLocalCut { cut, cut_token } = self {
            cut.validate()?;
            if cut_token.machine_id != cut.machine_id
                || cut_token.run_id != cut.run_id
                || cut_token.generation != cut.binding.pause_generation
            {
                return Err(invalid("owned capture success belongs to another pause"));
            }
        }
        Ok(())
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CaptureRecordReference {
    Identified { evidence: CaptureEvidenceReference },
    OwnedLocalCut { cut: Box<OwnedLocalCut> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CaptureSourceReference {
    Identified {
        sha256: Sha256Digest,
    },
    OwnedLocalCut {
        capture_id: LiveId,
        outcome: CaptureSourceOutcome,
    },
}

/// Capture-specific facts in `GetOperation` for a capture operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureObservation {
    pub continuation: CaptureContinuation,
    pub release: CaptureReleaseState,
    /// Present once `vm.capture.json` is complete.
    #[serde(deserialize_with = "required")]
    pub evidence: Option<CaptureRecordReference>,
    /// Present once a completed `vm.capture-source.json` exists.
    #[serde(deserialize_with = "required")]
    pub source_record: Option<CaptureSourceReference>,
}

impl CaptureObservation {
    pub fn validate(&self) -> Result<(), String> {
        self.continuation.validate()?;
        if let Some(CaptureRecordReference::OwnedLocalCut { cut }) = &self.evidence {
            cut.validate()?;
            if self.source_record.as_ref().is_some_and(|source| {
                !matches!(
                    source, CaptureSourceReference::OwnedLocalCut { capture_id, .. }
                        if capture_id == &cut.capture_id
                )
            }) {
                return Err(invalid(
                    "owned cut has a foreign or identified source record",
                ));
            }
        } else if matches!(
            &self.evidence,
            Some(CaptureRecordReference::Identified { .. })
        ) && matches!(
            &self.source_record,
            Some(CaptureSourceReference::OwnedLocalCut { .. })
        ) {
            return Err(invalid("identified capture has an owned source reference"));
        }
        Ok(())
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
pub(crate) mod tests {
    use crate::capture::*;
    use crate::lifecycle::{LiveFailureCode, LiveStage};
    use crate::{Disk, Hardware, Mount};

    fn tracking_receipt() -> DiskTrackingReceipt {
        let seed = DiskTrackingSeed {
            version: DISK_TRACKING_VERSION,
            map_format: 1,
            chunk_shift: 23,
            role: DiskRole::RootUpper,
            attachment_index: 1,
            block_id: BlockId::new("silo-root-upper").unwrap(),
            file_device: 5,
            file_inode: 7,
            length: 2 * STREAM_CHUNK_BYTES + 512,
            chunk_size: STREAM_CHUNK_BYTES,
            epoch: run(),
            baseline: Some(Sha256Digest::of_bytes(b"baseline")),
        };
        DiskTrackingReceipt {
            version: DISK_TRACKING_VERSION,
            token: DiskGenerationToken {
                capture_id: capture(),
                pause_generation: 1,
                epoch: seed.epoch.clone(),
                generation: 1,
                file_device: seed.file_device,
                file_inode: seed.file_inode,
            },
            seed,
            runs: vec![DiskDirtyRun {
                first_chunk: 1,
                chunk_count: 2,
            }],
            dirty_chunks: 2,
            total_chunks: 3,
            invalid_reason: None,
        }
    }

    #[test]
    fn disk_tracking_contract_roundtrips_and_rejects_noncanonical_syntax() {
        let receipt = tracking_receipt();
        let bytes = receipt.canonical_bytes().unwrap();
        assert_eq!(DiskTrackingReceipt::decode(&bytes).unwrap(), receipt);
        let seed = &receipt.seed;
        assert_eq!(
            DiskTrackingSeed::decode(&seed.canonical_bytes().unwrap()).unwrap(),
            *seed
        );
        let json = String::from_utf8(bytes.clone()).unwrap();
        for malformed in [
            format!(" {json}"),
            format!("{json}\n"),
            json.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
            json.replacen("\"version\":1", "\"version\":1,\"future\":true", 1),
            json.replace(",\"invalidReason\":null", ""),
            json.replace(",\"baseline\":\"sha256:", ",\"baseline\":\"SHA256:"),
            json.replace("\"dirtyChunks\":2", "\"dirtyChunks\":2.0"),
            "[]".to_owned(),
        ] {
            assert!(
                DiskTrackingReceipt::decode(malformed.as_bytes()).is_err(),
                "{malformed}"
            );
        }
        assert!(DiskTrackingReceipt::decode(&vec![b' '; MAX_DISK_TRACKING_BYTES + 1]).is_err());
        let mut unknown = receipt.clone();
        unknown.seed.baseline = None;
        assert!(unknown.validate().is_err());
        for reason in [
            DiskTrackingInvalidReason::NeverArmed,
            DiskTrackingInvalidReason::Lost,
            DiskTrackingInvalidReason::Overflow,
            DiskTrackingInvalidReason::OutOfDeviceMutationSuspected,
        ] {
            unknown.invalid_reason = Some(reason);
            assert_eq!(
                DiskTrackingReceipt::decode(&unknown.canonical_bytes().unwrap()).unwrap(),
                unknown
            );
        }
    }

    #[test]
    fn disk_tracking_contract_checks_ranges_counts_and_binding() {
        for mutation in 0..21 {
            let mut value = tracking_receipt();
            match mutation {
                0 => value.version += 1,
                1 => value.seed.version += 1,
                2 => value.seed.file_inode = 0,
                3 => value.seed.length = 0,
                4 => value.seed.length = MAX_STREAM_BYTES + 512,
                5 => value.seed.chunk_size /= 2,
                6 => value.token.epoch = machine(),
                7 => value.token.generation = 0,
                8 => value.token.pause_generation = 0,
                9 => value.token.file_inode += 1,
                10 => value.total_chunks += 1,
                11 => value.dirty_chunks += 1,
                12 => value.runs[0].chunk_count = 0,
                13 => value.runs[0].first_chunk = u64::MAX,
                14 => value.runs[0].chunk_count = 3,
                15 => {
                    value.runs = vec![
                        DiskDirtyRun {
                            first_chunk: 0,
                            chunk_count: 1,
                        },
                        DiskDirtyRun {
                            first_chunk: 1,
                            chunk_count: 1,
                        },
                    ];
                }
                16 => value.runs.push(value.runs[0]),
                17 => value.seed.attachment_index = 16,
                18 => value.seed.role = DiskRole::RootLower,
                19 => value.seed.length += 1,
                _ => value.token.file_device += 1,
            }
            assert!(value.validate().is_err(), "mutation {mutation}");
        }
        let mut empty = tracking_receipt();
        empty.runs.clear();
        empty.dirty_chunks = 0;
        empty.validate().unwrap();
        let mut maximum = empty;
        maximum.seed.length = MAX_STREAM_BYTES;
        maximum.total_chunks = MAX_STREAM_BYTES / STREAM_CHUNK_BYTES;
        maximum.runs = vec![DiskDirtyRun {
            first_chunk: maximum.total_chunks - 1,
            chunk_count: 1,
        }];
        maximum.dirty_chunks = 1;
        maximum.validate().unwrap();
    }

    #[test]
    fn disk_tracking_settlement_is_closed_and_independent() {
        let receipt = tracking_receipt();
        for settlement in [
            DiskGenerationSettlement::Commit {
                baseline: Sha256Digest::of_bytes(b"new"),
            },
            DiskGenerationSettlement::Abort,
        ] {
            let value = DiskTrackingSettlement {
                version: DISK_TRACKING_VERSION,
                block_id: receipt.seed.block_id.clone(),
                token: receipt.token.clone(),
                settlement,
            };
            let bytes = value.canonical_bytes().unwrap();
            assert_eq!(DiskTrackingSettlement::decode(&bytes).unwrap(), value);
            let mut bad = value;
            bad.version += 1;
            assert!(bad.validate().is_err());
            let json = String::from_utf8(bytes).unwrap();
            assert!(DiskTrackingSettlement::decode(
                json.replace("\"outcome\":", "\"extra\":1,\"outcome\":")
                    .as_bytes()
            )
            .is_err());
        }
    }

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
            identity_policy: CaptureIdentityPolicy::Full,
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
                    identity: DiskIdentityState::Unknown,
                    baseline_map: None,
                    tracking_eligible: true,
                },
                CaptureDiskPlan {
                    name: CaptureDiskName::new("data0").unwrap(),
                    attachment_index: 2,
                    block_id: BlockId::new("data0").unwrap(),
                    length: 1 << 20,
                    copy: CaptureDiskCopy::Clone,
                    identity: DiskIdentityState::Unknown,
                    baseline_map: None,
                    tracking_eligible: true,
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
            map_node_store: None,
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
            disk_stats: Vec::new(),
            disk_tracking_receipts: Vec::new(),
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
                ram_stream: crate::stream_map::StreamRoot::empty(
                    1 << 30,
                    crate::stream_map::ChunkSize::RAM,
                )
                .unwrap()
                .id(),
                binding: CaptureStateBinding {
                    live_state_schema: "silo.live-state/1".into(),
                    architecture: "x86_64".into(),
                    profile: digest,
                    topology: digest,
                    ram_layout: digest,
                    source_run: run(),
                    pause_generation: NonZeroU64::new(3).unwrap(),
                    capture: capture(),
                },
                mode: CapturePolicy::Full,
                identity_policy: CaptureIdentityPolicy::Full,
                identity_full_reason: Some(CaptureIdentityFullReason::Requested),
                baseline: None,
                full_reason: Some(CaptureFullReason::Requested),
                identity_chunk_bytes: 1 << 16,
                changes: CaptureRamChanges {
                    byte_len: 16,
                    sha256: digest,
                    record_count: 0,
                    coverage: CaptureRamCoverage::Full,
                    baseline_stream: None,
                },
                stats: CaptureMemoryStats {
                    logical_bytes: 1 << 30,
                    whole_file_bytes_hashed: 0,
                    identity_bytes_hashed: 0,
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
                        CaptureRole::RamMap | CaptureRole::DiskMap(_) => 25,
                        CaptureRole::RamChanges => 16,
                        _ => 100,
                    },
                    sha256: match role {
                        CaptureRole::RamMap => Some(
                            crate::stream_map::StreamRoot::empty(
                                1 << 30,
                                crate::stream_map::ChunkSize::RAM,
                            )
                            .unwrap()
                            .id(),
                        ),
                        CaptureRole::Ram | CaptureRole::Disk(_) => None,
                        _ => Some(digest),
                    },
                    identity: match role {
                        CaptureRole::Ram => Some(
                            crate::stream_map::StreamRoot::empty(
                                1 << 30,
                                crate::stream_map::ChunkSize::RAM,
                            )
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
    fn evidence_preserves_state_schema_through_its_format_bound() {
        let mut record = evidence(&plan());
        for length in [
            1,
            MAX_LIVE_STATE_SCHEMA_BYTES,
            MAX_LIVE_STATE_SCHEMA_BYTES + 1,
        ] {
            record.memory.as_mut().unwrap().binding.live_state_schema = "p".repeat(length);
            assert_eq!(
                record.validate().is_ok(),
                length <= MAX_LIVE_STATE_SCHEMA_BYTES
            );
        }
    }

    #[test]
    fn evidence_requires_bounded_nonempty_schema_and_architecture() {
        for (schema, architecture) in [
            ("".to_string(), "x86_64".to_string()),
            ("silo.live-state/1\0".to_string(), "x86_64".to_string()),
            ("silo.live-state/1".to_string(), "".to_string()),
            ("silo.live-state/1".to_string(), "x86_64\0".to_string()),
            (
                "silo.live-state/1".to_string(),
                "a".repeat(MAX_ARCHITECTURE_BYTES + 1),
            ),
        ] {
            let mut record = evidence(&plan());
            let binding = &mut record.memory.as_mut().unwrap().binding;
            binding.live_state_schema = schema;
            binding.architecture = architecture;
            assert!(record.validate().is_err());
        }
        let record = evidence(&plan());
        let json = serde_json::to_value(record.memory.unwrap().binding).unwrap();
        assert_eq!(json["liveStateSchema"], "silo.live-state/1");
        assert_eq!(json["architecture"], "x86_64");
    }

    #[test]
    fn plan_rejects_every_inconsistent_binding() {
        type PlanMutation = Box<dyn Fn(&mut CapturePlan)>;
        let mutations: Vec<PlanMutation> = vec![
            Box::new(|plan| plan.version = CAPTURE_RECORD_VERSION + 1),
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
            RestoreAuthority, RestoreDescriptor, RestoreExtent, RestoreLower, RestoreObject,
            RestoreObjectAuthority, RestoreObjectRole, RestoreRequest,
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
                authority: RestoreObjectAuthority::Identified {
                    identity: entry.identity.or(entry.sha256).unwrap(),
                },
            }
        });
        RestoreRequest {
            disk_tracking_seeds: Vec::new(),
            map_node_store: None,
            version: crate::restore::RESTORE_REQUEST_VERSION,
            authority: RestoreAuthority::IdentifiedSnapshot {
                snapshot: Sha256Digest::of_bytes(b"snapshot"),
                evidence: Box::new(evidence),
            },
            activation_id: id("44444444-4444-4444-8444-444444444444"),
            freeze_operation_id: capture(),
            start_paused: true,
            configuration: plan.configuration.clone(),
            objects: objects.into(),
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
        wrong.objects[2].authority = crate::restore::RestoreObjectAuthority::Identified {
            identity: Sha256Digest::of_bytes(b"other execution"),
        };
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
            RestoreAdmittedDevice, RestoreAuthority, RestoreDeviceKind as Kind,
            RestoreInspectionReport, RestoreInspectionRequest, RestoreInspectionRequestBinding,
        };
        let mut request = RestoreInspectionRequest {
            version: crate::restore::RESTORE_INSPECTION_VERSION,
            restore: restore_request(),
            network: false,
        };
        let RestoreAuthority::IdentifiedSnapshot { evidence, .. } = &mut request.restore.authority
        else {
            panic!("identified restore fixture required")
        };
        evidence.memory.as_mut().unwrap().binding.live_state_schema = "silo.live-state/1".into();
        let bytes = serde_json::to_vec(&request).unwrap();
        let binding = request.restore.authority.binding().unwrap();
        let report = RestoreInspectionReport {
            version: crate::restore::RESTORE_INSPECTION_VERSION,
            request: RestoreInspectionRequestBinding::Identified {
                sha256: Sha256Digest::of_bytes(&bytes),
            },
            authority: request.restore.authority.reference(),
            live_state_schema: binding.live_state_schema.clone(),
            architecture: binding.architecture.clone(),
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
        wrong.live_state_schema = "silo.live-state/2".into();
        assert!(wrong.validate_against(&bytes, &request).is_err());
        let refusal = wrong.portability_refusal(&request).unwrap();
        assert_eq!(refusal.pin, "live-state-schema");
        assert_eq!(refusal.expected, "silo.live-state/2");
        assert_eq!(refusal.actual, "silo.live-state/1");
        let mut wrong = report.clone();
        wrong.architecture = "aarch64".into();
        assert!(wrong.validate_against(&bytes, &request).is_err());
        let refusal = wrong.portability_refusal(&request).unwrap();
        assert_eq!(refusal.pin, "architecture");
        assert_eq!(refusal.expected, "aarch64");
        assert_eq!(refusal.actual, "x86_64");
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
        wrong.request = RestoreInspectionRequestBinding::Identified {
            sha256: Sha256Digest::of_bytes(b"another inspection"),
        };
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
    fn binary_root_roles_reject_old_sidecars() {
        assert_eq!(CaptureRole::RamMap.relative_path(), "memory.root");
        assert_eq!(
            "ram-map".parse::<CaptureRole>().unwrap(),
            CaptureRole::RamMap
        );
        assert!("memory.map.json".parse::<CaptureRole>().is_err());
        assert!("disks/root.map.json".parse::<CaptureRole>().is_err());
        assert_eq!(
            "disks/root.root"
                .parse::<CaptureRole>()
                .unwrap()
                .relative_path(),
            "disks/root.root"
        );
    }

    #[test]
    fn one_tib_geometry_keeps_control_evidence_bounded() {
        let mut record = evidence(&plan());
        let before = record.canonical_bytes().unwrap().len();
        let memory = record.memory.as_mut().unwrap();
        memory.packed_length = MAX_CAPTURE_RAM_BYTES;
        let root = crate::stream_map::StreamRoot::empty(
            MAX_CAPTURE_RAM_BYTES,
            crate::stream_map::ChunkSize::RAM,
        )
        .unwrap();
        memory.ram_stream = root.id();
        memory.stats.logical_bytes = MAX_CAPTURE_RAM_BYTES;
        memory.stats.identity_bytes_hashed = 0;
        record.inventory[2].length = MAX_CAPTURE_RAM_BYTES;
        record.inventory[2].identity = Some(root.id());
        record.inventory[4].sha256 = Some(root.id());
        let bytes = record.canonical_bytes().unwrap();
        assert!(bytes.len() < before + 128);
        assert!(bytes.len() < 16 * 1024);
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
        memory.validate_capture().unwrap();
        memory.baseline = Some(Sha256Digest::of_bytes(b"exact predecessor stream"));
        memory.identity_policy = CaptureIdentityPolicy::SinceAnchor;
        memory.identity_full_reason = None;
        memory.changes.coverage = CaptureRamCoverage::Incremental;
        memory.changes.baseline_stream = memory.baseline;
        memory.validate_capture().unwrap();
        seal.memory = Some(memory.clone());
        assert!(seal
            .validate_against_plan(&plan, &seal.request_digest)
            .is_err());
        plan.policy = CapturePolicy::Incremental;
        plan.identity_policy = CaptureIdentityPolicy::SinceAnchor;
        seal.request_digest = Sha256Digest::of_bytes(&plan.canonical_bytes().unwrap());
        seal.validate_against_plan(&plan, &seal.request_digest)
            .unwrap();
        memory.stats.identity_bytes_hashed += 1;
        assert!(memory.validate_capture().is_err());
        memory.stats.identity_bytes_hashed -= 1;
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
        let crate::restore::RestoreAuthority::IdentifiedSnapshot {
            evidence: identified,
            ..
        } = &request.authority
        else {
            panic!("identified restore fixture required")
        };
        let ram = identified
            .inventory
            .iter()
            .find(|entry| entry.role == CaptureRole::Ram)
            .unwrap();
        let encoded = serde_json::to_value(ram).unwrap();
        assert!(encoded.get("sha256").is_none());
        assert!(encoded.get("identity").is_some());
        request.objects[0].authority = crate::restore::RestoreObjectAuthority::Identified {
            identity: Sha256Digest::of_bytes(b"wrong stream"),
        };
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
    fn memory_stats_have_exact_required_wire_fields() {
        let stats = CaptureMemoryStats {
            seed_method: crate::capture::CaptureSeedMethod::Rebuild,
            logical_bytes: 1,
            live_bytes_read: 2,
            baseline_bytes_read: 3,
            baseline_bytes_written: 4,
            overlay_bytes_written: 5,
            full_bytes_written: 6,
            layout_bytes_written: 7,
            baseline_hole_bytes: 8,
            zero_bytes_omitted: 9,
            explicit_zero_bytes_written: 10,
            zero_run_bytes_covered: 11,
            zero_bytes_punched: 12,
            known_zero_bytes_skipped: 13,
            extent_queries: 14,
            identity_bytes_hashed: 15,
            whole_file_bytes_hashed: 16,
            map_nodes_written: 17,
            identity_dirty_pages: 18,
            materialization_dirty_pages: 19,
            live_pages_classified: 20,
            identity_zero_bytes_filled: 21,
            full_identity_read_fallback:
                crate::capture::CaptureIdentityReadFallback::ExtentsUnavailable,
        };
        let value = serde_json::to_value(&stats).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "seedMethod": "rebuild",
                "logicalBytes": 1,
                "liveBytesRead": 2,
                "baselineBytesRead": 3,
                "baselineBytesWritten": 4,
                "overlayBytesWritten": 5,
                "fullBytesWritten": 6,
                "layoutBytesWritten": 7,
                "baselineHoleBytes": 8,
                "zeroBytesOmitted": 9,
                "explicitZeroBytesWritten": 10,
                "zeroRunBytesCovered": 11,
                "zeroBytesPunched": 12,
                "knownZeroBytesSkipped": 13,
                "extentQueries": 14,
                "identityBytesHashed": 15,
                "wholeFileBytesHashed": 16,
                "mapNodesWritten": 17,
                "identityDirtyPages": 18,
                "materializationDirtyPages": 19,
                "livePagesClassified": 20,
                "identityZeroBytesFilled": 21,
                "fullIdentityReadFallback": "extents-unavailable",
            })
        );
        assert_eq!(
            serde_json::from_value::<CaptureMemoryStats>(value.clone()).unwrap(),
            stats
        );
        for field in value.as_object().unwrap().keys() {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<CaptureMemoryStats>(missing).is_err(),
                "missing field {field}"
            );
        }
        let mut unknown = value.clone();
        unknown["unknown"] = serde_json::json!(0);
        assert!(serde_json::from_value::<CaptureMemoryStats>(unknown).is_err());
        for field in [
            "zeroRunBytesCovered",
            "zeroBytesPunched",
            "knownZeroBytesSkipped",
        ] {
            for invalid in [serde_json::json!(-1), serde_json::json!("4096")] {
                let mut malformed = value.clone();
                malformed[field] = invalid;
                assert!(serde_json::from_value::<CaptureMemoryStats>(malformed).is_err());
            }
        }
    }

    #[test]
    fn clone_seed_separates_identity_reads_from_materialization_writes() {
        use crate::capture::CaptureSeedMethod;

        let mut memory = evidence(&plan()).memory.unwrap();
        memory.stats.seed_method = CaptureSeedMethod::Clone;
        assert!(memory.validate_capture().is_err());
        memory.mode = CapturePolicy::Incremental;
        memory.full_reason = None;
        memory.baseline = Some(Sha256Digest::of_bytes(b"predecessor"));
        memory.identity_policy = CaptureIdentityPolicy::SinceAnchor;
        memory.identity_full_reason = None;
        memory.changes.coverage = CaptureRamCoverage::Incremental;
        memory.changes.baseline_stream = memory.baseline;
        memory.validate_capture().unwrap();
        memory.stats.baseline_bytes_read = 1;
        memory.validate_capture().unwrap();
        memory.stats.baseline_bytes_read = 0;
        memory.stats.baseline_bytes_written = 1;
        assert!(memory.validate_capture().is_err());
    }

    #[test]
    fn identity_pending_cut_is_not_a_seal_and_binds_exact_clone_owners() {
        let plan = plan();
        let mut partial = evidence(&plan);
        let disks = plan
            .disks
            .iter()
            .map(|disk| {
                let mut receipt = tracking_receipt();
                receipt.seed.length = disk.length;
                receipt.seed.attachment_index = disk.attachment_index;
                receipt.seed.block_id = disk.block_id.clone();
                receipt.seed.role =
                    plan.configuration.attachments[disk.attachment_index as usize].role;
                receipt.total_chunks = disk.length.div_ceil(STREAM_CHUNK_BYTES);
                receipt.runs = vec![DiskDirtyRun {
                    first_chunk: 0,
                    chunk_count: 1,
                }];
                receipt.dirty_chunks = 1;
                receipt.token.pause_generation =
                    partial.pause_token.as_ref().unwrap().generation.get();
                CaptureDiskCut {
                    tracking_receipt: Some(receipt),
                    name: disk.name.clone(),
                    device: 7,
                    inode: u64::from(disk.attachment_index) + 10,
                    length: disk.length,
                    mode: 0o100600,
                    changed_seconds: 10,
                    changed_nanoseconds: 20,
                }
            })
            .collect::<Vec<_>>();
        partial
            .inventory
            .retain(|entry| !matches!(entry.role, CaptureRole::Disk(_) | CaptureRole::DiskMap(_)));
        partial.disk_copies_sealed = false;
        let cut = CaptureCutRecord {
            phase: CaptureCutPhase::IdentityPending,
            evidence: partial,
            disks,
        };
        let request = Sha256Digest::of_bytes(&plan.canonical_bytes().unwrap());
        cut.validate_against_plan(&plan, &request).unwrap();
        assert!(!cut.evidence.is_sealed());
        assert!(CaptureEvidence::decode(&cut.evidence.canonical_bytes().unwrap()).is_err());
        let bytes = cut.canonical_bytes().unwrap();
        assert_eq!(CaptureCutRecord::decode(&bytes).unwrap(), cut);
        assert!(CaptureEvidence::decode(&bytes).is_err());
        for mutation in 0..11 {
            let mut bad = cut.clone();
            match mutation {
                0 => bad.disks[0].length += 512,
                1 => bad.disks[0].mode = 0o100644,
                2 => bad.disks.push(bad.disks[0].clone()),
                3 => bad.evidence.host_flush_completed = false,
                4 => {
                    bad.evidence.inventory.pop();
                }
                5 => bad.evidence.disk_copies_sealed = true,
                6 => {
                    bad.disks[0]
                        .tracking_receipt
                        .as_mut()
                        .unwrap()
                        .token
                        .capture_id = run()
                }
                7 => {
                    bad.disks[0]
                        .tracking_receipt
                        .as_mut()
                        .unwrap()
                        .seed
                        .block_id = BlockId::new("foreign").unwrap()
                }
                8 => {
                    bad.disks[0]
                        .tracking_receipt
                        .as_mut()
                        .unwrap()
                        .token
                        .pause_generation += 1
                }
                9 => {
                    let receipt = bad.disks[0].tracking_receipt.as_mut().unwrap();
                    receipt.runs[0].chunk_count = receipt.total_chunks + 1;
                }
                _ => bad.evidence.request_digest = Sha256Digest::of_bytes(b"foreign"),
            }
            assert!(bad.validate_against_plan(&plan, &request).is_err());
        }
    }

    #[test]
    fn external_capture_disks_cannot_carry_or_claim_baseline_authority() {
        let mut plan = plan();
        plan.disks[0].tracking_eligible = false;
        plan.validate().unwrap();
        plan.disks[0].baseline_map = Some("/private/baseline.root".into());
        assert!(plan.validate().is_err());
        plan.disks[0].baseline_map = None;
        let mut evidence = evidence(&plan);
        evidence.disk_stats = plan
            .disks
            .iter()
            .map(|disk| CaptureDiskStats {
                name: disk.name.clone(),
                dirty_chunks: 0,
                total_chunks: disk.length.div_ceil(STREAM_CHUNK_BYTES),
                bytes_hashed: 0,
                baseline_reused: false,
                full_scan_reason: Some(if disk.tracking_eligible {
                    DiskFullScanReason::MissingBaseline
                } else {
                    DiskFullScanReason::External
                }),
            })
            .collect();
        let request = Sha256Digest::of_bytes(&plan.canonical_bytes().unwrap());
        evidence.validate_against_plan(&plan, &request).unwrap();
        evidence.disk_stats[0].baseline_reused = true;
        evidence.disk_stats[0].full_scan_reason = None;
        assert!(evidence.validate_against_plan(&plan, &request).is_err());
        evidence.disk_stats[0].baseline_reused = false;
        evidence.disk_stats[0].full_scan_reason = Some(DiskFullScanReason::MissingBaseline);
        assert!(evidence.validate_against_plan(&plan, &request).is_err());
    }

    fn change_bytes(incremental: bool, records: &[(u64, u64, Option<Sha256Digest>)]) -> Vec<u8> {
        let mut bytes = b"KRUNRAM\0\x01\0\x10\0\0\0\0\0".to_vec();
        bytes[11] = u8::from(incremental);
        for &(first, count, digest) in records {
            bytes.extend(first.to_le_bytes());
            bytes.extend(count.to_le_bytes());
            bytes.push(u8::from(digest.is_some()));
            bytes.extend([0; 7]);
            bytes.extend(digest.map_or([0; 32], |digest| *digest.as_bytes()));
        }
        bytes
    }

    #[test]
    fn native_change_reader_authenticates_real_files_and_rejects_invalid_records() {
        let digest = Sha256Digest::of_bytes(b"nonzero");
        let length = 4 << 16;
        let valid = change_bytes(
            true,
            &[(0, 1, Some(digest)), (1, 2, None), (3, 1, Some(digest))],
        );
        let summary = |bytes: &[u8], count| CaptureRamChanges {
            byte_len: 16 + count * 56,
            sha256: Sha256Digest::of_bytes(bytes),
            record_count: count,
            coverage: CaptureRamCoverage::Incremental,
            baseline_stream: Some(digest),
        };
        let directory = std::env::temp_dir().join(format!(
            "silo-change-reader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let read = |bytes: &[u8], expected: &CaptureRamChanges| {
            let path = directory.join("changes");
            std::fs::write(&path, bytes).unwrap();
            RamChangeReader::new(std::fs::File::open(path).unwrap(), length, expected)
                .and_then(|reader| reader.collect::<std::io::Result<Vec<_>>>())
        };
        assert_eq!(read(&valid, &summary(&valid, 3)).unwrap().len(), 3);
        for truncated in [&valid[..8], &valid[..valid.len() - 1]] {
            assert!(read(truncated, &summary(&valid, 3)).is_err());
        }
        for records in [
            vec![(2, 1, Some(digest)), (1, 1, Some(digest))],
            vec![(0, 3, None), (2, 1, Some(digest))],
            vec![(0, 1, None), (1, 1, None)],
            vec![(0, 0, None)],
            vec![(4, 1, Some(digest))],
            vec![(u64::MAX, 2, None)],
        ] {
            let bytes = change_bytes(true, &records);
            assert!(read(&bytes, &summary(&bytes, records.len() as u64)).is_err());
        }
        for position in [8, 10, 11, 12, 16 + 17] {
            let mut bytes = valid.clone();
            bytes[position] ^= 0x40;
            assert!(read(&bytes, &summary(&bytes, 3)).is_err());
        }
        let mut changed = valid.clone();
        changed[16 + 24] ^= 1;
        assert!(read(&changed, &summary(&valid, 3)).is_err());
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(read(&trailing, &summary(&trailing, 3)).is_err());
        let empty = change_bytes(true, &[]);
        assert!(read(&empty, &summary(&empty, 0)).unwrap().is_empty());
        let mut full_summary = summary(&empty, 0);
        full_summary.coverage = CaptureRamCoverage::Full;
        full_summary.baseline_stream = None;
        let full_zero = change_bytes(false, &[(0, 4, None)]);
        full_summary.record_count = 1;
        full_summary.byte_len = full_zero.len() as u64;
        full_summary.sha256 = Sha256Digest::of_bytes(&full_zero);
        assert!(read(&full_zero, &full_summary).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    pub(crate) struct OwnedCutFixture {
        pub(crate) directory: std::path::PathBuf,
        pub(crate) cut: OwnedLocalCut,
        pub(crate) plan: CapturePlan,
    }

    impl Drop for OwnedCutFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    pub(crate) fn owned_cut_fixture(name: &str) -> OwnedCutFixture {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("silo-{name}-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(directory.join(CAPTURE_DISKS_DIRECTORY)).unwrap();
        let mut plan = plan();
        plan.identity_policy = CaptureIdentityPolicy::None;
        plan.map_node_store = None;
        let binding = evidence(&plan).memory.unwrap().binding;
        let members = plan
            .roles()
            .into_iter()
            .map(|role| {
                let length = match &role {
                    CaptureRole::Ram => plan.ram_bytes,
                    CaptureRole::Disk(name) => {
                        plan.disks
                            .iter()
                            .find(|disk| &disk.name == name)
                            .unwrap()
                            .length
                    }
                    _ => 100,
                };
                let path = directory.join(role.relative_path());
                let file = std::fs::File::create(&path).unwrap();
                file.set_len(length).unwrap();
                drop(file);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
                let metadata = std::fs::metadata(&path).unwrap();
                OwnedCutMember {
                    role,
                    complete: true,
                    fingerprint: SourceFingerprint {
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        length: metadata.len(),
                        mode: metadata.mode(),
                        modified_seconds: metadata.mtime(),
                        modified_nanoseconds: metadata.mtime_nsec(),
                        changed_seconds: metadata.ctime(),
                        changed_nanoseconds: metadata.ctime_nsec(),
                    },
                }
            })
            .collect();
        let cut = OwnedLocalCut {
            version: CAPTURE_RECORD_VERSION,
            machine_id: plan.machine_id.clone(),
            run_id: plan.run_id.clone(),
            capture_id: plan.capture_id.clone(),
            freeze_operation_id: plan.capture_id.clone(),
            freeze_epoch: NonZeroU64::new(1).unwrap(),
            configuration: plan.configuration.clone(),
            binding,
            materialization_generation: NonZeroU64::new(2).unwrap(),
            predecessor_generation: 1,
            packed_length: plan.ram_bytes,
            page_granule: 4096,
            regions: 1,
            members,
            stats: CaptureMemoryStats {
                logical_bytes: plan.ram_bytes,
                ..Default::default()
            },
        };
        cut.validate_against_plan(&plan).unwrap();
        OwnedCutFixture {
            directory,
            cut,
            plan,
        }
    }

    #[test]
    fn owned_cut_is_strict_complete_exact_file_evidence_without_content_authority() {
        let fixture = owned_cut_fixture("owned-cut-codec");
        let cut = &fixture.cut;
        let bytes = cut.canonical_bytes().unwrap();
        assert_eq!(OwnedLocalCut::decode(&bytes).unwrap(), *cut);
        assert!(serde_json::from_slice::<CaptureEvidence>(&bytes).is_err());
        let text = String::from_utf8(bytes).unwrap();
        for bad in [
            format!("{text}\n"),
            text.replacen('{', "{\"future\":true,", 1),
            text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
            text.replace("\"complete\":true", "\"complete\":false"),
            text.replace(
                "\"materializationGeneration\":2",
                "\"materializationGeneration\":0",
            ),
        ] {
            assert_ne!(bad, text);
            assert!(OwnedLocalCut::decode(bad.as_bytes()).is_err());
        }
        for mutation in 0..19 {
            let mut bad = cut.clone();
            match mutation {
                0 => bad.version -= 1,
                1 => bad.run_id = machine(),
                2 => bad.capture_id = machine(),
                3 => bad.predecessor_generation = bad.materialization_generation.get(),
                4 => bad.members[0].complete = false,
                5 => bad.members[0].role = CaptureRole::RamMap,
                6 => bad.members[0].fingerprint.inode = 0,
                7 => bad.members[0].fingerprint.mode |= 0o200,
                8 => bad.members[0].fingerprint.modified_nanoseconds = 1_000_000_000,
                9 => bad.members[0].fingerprint.changed_nanoseconds = -1,
                10 => bad.members.swap(0, 1),
                11 => {
                    bad.members.pop();
                }
                12 => bad.stats.identity_bytes_hashed = 1,
                13 => bad.stats.map_nodes_written = 1,
                14 => bad.stats.whole_file_bytes_hashed = 1,
                15 => bad.members[2].fingerprint.length -= 4096,
                16 => bad.members[1].fingerprint = bad.members[0].fingerprint.clone(),
                17 => bad.page_granule = 0,
                _ => bad.binding.live_state_schema.push('\0'),
            }
            assert!(bad.validate().is_err(), "mutation {mutation}");
        }
        let mut wrong_plan = fixture.plan.clone();
        wrong_plan.disks.swap(0, 1);
        assert!(cut.validate_against_plan(&wrong_plan).is_err());
        let mut foreign_freeze = cut.clone();
        foreign_freeze.freeze_operation_id = machine();
        foreign_freeze.validate().unwrap();
        assert!(foreign_freeze.validate_against_plan(&fixture.plan).is_err());
        let mut borrowed_plan = fixture.plan.clone();
        let generation = NonZeroU64::new(7).unwrap();
        borrowed_plan.pause = CapturePauseAuthority::Borrow {
            token: PauseToken {
                machine_id: cut.machine_id.clone(),
                run_id: cut.run_id.clone(),
                generation,
                owner: PauseOwner::User,
            },
            pause_operation_id: machine(),
        };
        borrowed_plan.resume_policy = CaptureResumePolicy::Preserve;
        foreign_freeze.binding.pause_generation = generation;
        foreign_freeze
            .validate_against_plan(&borrowed_plan)
            .unwrap();
        foreign_freeze.binding.pause_generation = NonZeroU64::MIN;
        assert!(foreign_freeze
            .validate_against_plan(&borrowed_plan)
            .is_err());
    }

    #[test]
    fn capture_success_keeps_owned_and_identified_journal_authorities_disjoint() {
        let fixture = owned_cut_fixture("owned-success-codec");
        let cut = fixture.cut.clone();
        let token = PauseToken {
            machine_id: cut.machine_id.clone(),
            run_id: cut.run_id.clone(),
            generation: cut.binding.pause_generation,
            owner: PauseOwner::Capture {
                operation_id: cut.capture_id.clone(),
            },
        };
        let success = CaptureSuccess::OwnedLocalCut {
            cut: Box::new(cut.clone()),
            cut_token: token,
        };
        success.validate().unwrap();
        let json = serde_json::to_value(&success).unwrap();
        assert_eq!(
            serde_json::from_value::<CaptureSuccess>(json.clone()).unwrap(),
            success
        );
        assert!(json.get("cutToken").is_some());
        assert!(json.get("cut_token").is_none());
        let mut snake_case = json.clone();
        let token = snake_case
            .as_object_mut()
            .unwrap()
            .remove("cutToken")
            .unwrap();
        snake_case["cut_token"] = token;
        assert!(serde_json::from_value::<CaptureSuccess>(snake_case).is_err());
        assert!(serde_json::from_value::<CaptureSealed>(json.clone()).is_err());
        let mut wrong = json;
        wrong["evidenceSha256"] = serde_json::json!(Sha256Digest::of_bytes(b"not owned authority"));
        assert!(serde_json::from_value::<CaptureSuccess>(wrong).is_err());
        let mut wrong = success.clone();
        if let CaptureSuccess::OwnedLocalCut { cut_token, .. } = &mut wrong {
            cut_token.generation = NonZeroU64::new(cut.binding.pause_generation.get() + 1).unwrap();
        }
        assert!(wrong.validate().is_err());
        let mut observation = CaptureObservation {
            continuation: CaptureContinuation::Pending,
            release: CaptureReleaseState::Retained,
            evidence: Some(CaptureRecordReference::OwnedLocalCut { cut: Box::new(cut) }),
            source_record: None,
        };
        observation.validate().unwrap();
        observation.source_record = Some(CaptureSourceReference::Identified {
            sha256: Sha256Digest::of_bytes(b"foreign identified source"),
        });
        assert!(observation.validate().is_err());
    }

    #[test]
    fn first_owned_child_snapshot_can_incrementally_materialize_full_identity() {
        let mut memory = evidence(&plan()).memory.unwrap();
        memory.mode = CapturePolicy::Incremental;
        memory.full_reason = None;
        memory.identity_full_reason = Some(CaptureIdentityFullReason::UnknownAnchorAfterFork);
        memory.stats.seed_method = CaptureSeedMethod::Clone;
        memory.stats.baseline_bytes_read = 65536;
        memory.validate_capture().unwrap();
        memory.identity_policy = CaptureIdentityPolicy::None;
        assert!(memory.validate_capture().is_err());
        memory.identity_policy = CaptureIdentityPolicy::SinceAnchor;
        assert!(memory.validate_capture().is_err());
    }
}
