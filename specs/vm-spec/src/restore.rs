//! Descriptor-only execution inputs for a fresh, paused restore attempt.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capture::{
    CaptureConfiguration, CaptureEvidence, CaptureRole, Sha256Digest, MAX_CAPTURE_RAM_BYTES,
};
use crate::lifecycle::LiveId;

pub const RESTORE_REQUEST_VERSION: u32 = 1;
pub const GENERATION_ACK_TIMEOUT_MS: u64 = 5_000;
pub const ACTIVATE_TIMEOUT_MS: u64 = 30_000;
pub const RESTORE_INSPECTION_VERSION: u32 = 1;
pub const MAX_RESTORE_INSPECTION_BYTES: usize = 1 << 20;
pub const MAX_RESTORE_LOWER_EXTENTS: usize = 1536;
pub const RESTORE_CONSOLE_ID: &str = "hvc0";
pub const RESTORE_VSOCK_ID: &str = "vsock";
pub const RESTORE_NETWORK_ID: &str = "net0";
pub const RESTORE_RNG_ID: &str = "rng";
pub const RESTORE_BALLOON_ID: &str = "balloon";
pub const RESTORE_GENERATION_ID: &str = "silo-vmgenid";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreObjectRole {
    Ram,
    Layout,
    Execution,
    Devices,
    RamMap,
}

impl RestoreObjectRole {
    pub const ALL: [Self; 5] = [
        Self::Ram,
        Self::Layout,
        Self::Execution,
        Self::Devices,
        Self::RamMap,
    ];

    pub const fn capture_role(self) -> CaptureRole {
        match self {
            Self::Ram => CaptureRole::Ram,
            Self::Layout => CaptureRole::Layout,
            Self::Execution => CaptureRole::Execution,
            Self::Devices => CaptureRole::Devices,
            Self::RamMap => CaptureRole::RamMap,
        }
    }

    pub const fn maximum_bytes(self) -> u64 {
        match self {
            Self::Ram => MAX_CAPTURE_RAM_BYTES,
            Self::Layout => 64 << 10,
            Self::Execution => 16 << 20,
            Self::Devices => 32 << 20,
            Self::RamMap => crate::capture::MAX_RAM_MAP_BYTES as u64,
        }
    }
}

/// The sender duplicates an already authenticated, leased immutable object.
/// Receivers must compare these facts with fstat and validate the complete FD
/// set before adopting any descriptor. Numbers here never authorize path opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreObject {
    pub role: RestoreObjectRole,
    pub fd: i32,
    pub file_device: u64,
    pub file_inode: u64,
    pub length: u64,
    /// RAM uses its canonical chunk-list stream identity. Small state objects
    /// use the whole-byte SHA-256 recorded for their role.
    pub identity: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreHook {
    pub argv: Vec<String>,
    pub environment: Vec<RestoreEnvironmentVariable>,
    pub working_directory: String,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreEnvironmentVariable {
    pub name: String,
    pub value: String,
}

/// Machine/run, forward policy and shutdown context are supplied by the
/// enclosing managed launch, never inherited from the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRequest {
    pub version: u32,
    pub checkpoint: Sha256Digest,
    pub activation_id: LiveId,
    pub freeze_operation_id: LiveId,
    pub start_paused: bool,
    pub configuration: CaptureConfiguration,
    pub evidence: CaptureEvidence,
    /// Exactly RAM, layout, execution, devices, complete RAM map, in that order.
    pub objects: [RestoreObject; 5],
    pub lowers: Vec<RestoreLower>,
    pub network: Option<RestoreNetwork>,
    /// Destination public SSH CA. Absent only during pre-allocation inspection.
    pub ssh_trusted_ca: Option<String>,
    pub hook: Option<RestoreHook>,
}

impl RestoreRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != RESTORE_REQUEST_VERSION || !self.start_paused {
            return Err("restore requires the current schema and startPaused=true".into());
        }
        self.configuration.validate()?;
        if !self.evidence.is_sealed() {
            return Err("restore requires a coherent capture seal".into());
        }
        if self.configuration.digest()? != self.evidence.configuration_digest {
            return Err("restore configuration differs from the captured cut".into());
        }
        if self.evidence.freeze_operation_id.as_ref() != Some(&self.freeze_operation_id) {
            return Err("restore freeze operation differs from the captured cut".into());
        }
        let mut descriptors = BTreeSet::new();
        let mut inodes = BTreeSet::new();
        for (object, expected) in self.objects.iter().zip(RestoreObjectRole::ALL) {
            if object.role != expected
                || object.fd < 3
                || !descriptors.insert(object.fd)
                || object.file_inode == 0
                || !inodes.insert((object.file_device, object.file_inode))
                || object.length == 0
                || object.length > object.role.maximum_bytes()
            {
                return Err("restore object roles, descriptors or geometry are invalid".into());
            }
            let inventory = self
                .evidence
                .inventory
                .iter()
                .find(|entry| entry.role == object.role.capture_role())
                .ok_or_else(|| "restore object is absent from the captured cut".to_string())?;
            let identity = match object.role {
                RestoreObjectRole::Ram => inventory.identity,
                _ => inventory.sha256,
            };
            if object.length != inventory.length || Some(object.identity) != identity {
                return Err("restore object identity differs from the captured cut".into());
            }
        }
        self.validate_lowers(&mut descriptors, &mut inodes)?;
        if let Some(network) = &self.network {
            network.validate()?;
        }
        if let Some(hook) = &self.hook {
            hook.validate()?;
        }
        Ok(())
    }
}

impl RestoreHook {
    pub fn validate(&self) -> Result<(), String> {
        if self.argv.is_empty()
            || self.argv.len() > 256
            || self.argv[0].is_empty()
            || self
                .argv
                .iter()
                .any(|value| value.len() > 4096 || value.contains('\0'))
            || self.environment.len() > 256
            || self.working_directory.len() > 4096
            || !self.working_directory.starts_with('/')
            || self.working_directory.contains('\0')
            || self.timeout_ms == 0
            || u64::from(self.timeout_ms) > ACTIVATE_TIMEOUT_MS
        {
            return Err("restore activation hook is invalid or exceeds its bound".into());
        }
        let mut names = BTreeSet::new();
        for variable in &self.environment {
            if variable.name.is_empty()
                || variable.name.len() > 256
                || variable.name.contains(['=', '\0'])
                || variable.value.len() > 4096
                || variable.value.contains('\0')
                || !names.insert(&variable.name)
            {
                return Err("restore activation hook environment is invalid".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreDescriptor {
    pub fd: i32,
    pub file_device: u64,
    pub file_inode: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreExtent {
    pub path: String,
    pub fd: i32,
    pub file_device: u64,
    pub file_inode: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreLower {
    pub block_id: crate::BlockId,
    pub descriptor: RestoreDescriptor,
    pub extents: Vec<RestoreExtent>,
}

impl RestoreRequest {
    fn validate_lowers(
        &self,
        descriptors: &mut BTreeSet<i32>,
        state_inodes: &mut BTreeSet<(u64, u64)>,
    ) -> Result<(), String> {
        let expected = self
            .configuration
            .attachments
            .iter()
            .filter(|attachment| attachment.format == crate::DiskFormat::Vmdk);
        if expected.clone().count() != self.lowers.len() {
            return Err("restore lower closure does not cover the VMDK attachments".into());
        }
        let mut extent_count = 0usize;
        for (lower, attachment) in self.lowers.iter().zip(expected) {
            let descriptor = &lower.descriptor;
            if lower.block_id != attachment.block_id
                || !attachment.read_only
                || descriptor.fd < 3
                || !descriptors.insert(descriptor.fd)
                || descriptor.file_inode == 0
                || !state_inodes.insert((descriptor.file_device, descriptor.file_inode))
                || descriptor.length == 0
                || descriptor.length > 2 << 20
                || lower.extents.is_empty()
            {
                return Err("restore VMDK descriptor identity is invalid".into());
            }
            extent_count = extent_count
                .checked_add(lower.extents.len())
                .ok_or_else(|| "restore extent count overflow".to_string())?;
            if extent_count > MAX_RESTORE_LOWER_EXTENTS {
                return Err("restore lower closure exceeds the extent bound".into());
            }
        }
        // Readonly extents may legitimately repeat an inode. None may alias a
        // state object or generated descriptor, and every FD has one owner.
        for lower in &self.lowers {
            let mut paths = BTreeSet::new();
            for extent in &lower.extents {
                let path = std::path::Path::new(&extent.path);
                if extent.fd < 3
                    || !descriptors.insert(extent.fd)
                    || extent.file_inode == 0
                    || state_inodes.contains(&(extent.file_device, extent.file_inode))
                    || extent.length == 0
                    || extent.length > crate::capture::MAX_STREAM_BYTES
                    || extent.path.len() > 4096
                    || extent.path.contains('\0')
                    || !path.is_absolute()
                    || path.components().any(|component| {
                        matches!(
                            component,
                            std::path::Component::ParentDir | std::path::Component::CurDir
                        )
                    })
                    || !paths.insert(&extent.path)
                {
                    return Err("restore lower extent identity or path is invalid".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreNetwork {
    pub mac: String,
    pub ipv4: std::net::Ipv4Addr,
    pub prefix_length: u8,
    pub gateway: std::net::Ipv4Addr,
    pub dns_servers: Vec<std::net::IpAddr>,
    pub dns_search: Vec<String>,
}

impl RestoreNetwork {
    pub fn validate(&self) -> Result<(), String> {
        let mut parts = self.mac.split(':');
        let mut octets = [0u8; 6];
        for octet in &mut octets {
            let Some(part) = parts.next() else {
                return Err("restore destination MAC is invalid".into());
            };
            if part.len() != 2
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("restore destination MAC must use lowercase hexadecimal".into());
            }
            *octet = u8::from_str_radix(part, 16).map_err(|error| error.to_string())?;
        }
        if parts.next().is_some()
            || octets == [0; 6]
            || octets[0] & 1 != 0
            || !(1..=30).contains(&self.prefix_length)
        {
            return Err("restore destination network identity is invalid".into());
        }
        let usable = |ip: std::net::Ipv4Addr| {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && ip != std::net::Ipv4Addr::BROADCAST
        };
        let mask = u32::MAX << (32 - self.prefix_length);
        let host_mask = !mask;
        let host = u32::from(self.ipv4);
        let gateway = u32::from(self.gateway);
        if !usable(self.ipv4)
            || !usable(self.gateway)
            || host == gateway
            || host & mask != gateway & mask
            || [host & host_mask, gateway & host_mask]
                .iter()
                .any(|value| *value == 0 || *value == host_mask)
            || self.dns_servers.len() > 8
            || self.dns_search.len() > 8
            || self
                .dns_servers
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
            || self.dns_search.iter().any(|name| {
                name.is_empty()
                    || name.len() > 253
                    || name
                        .bytes()
                        .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'.')
            })
        {
            return Err("restore destination IPv4 or DNS configuration is invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreInspectionRequest {
    pub version: u32,
    pub restore: RestoreRequest,
    pub network: bool,
}

impl RestoreInspectionRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != RESTORE_INSPECTION_VERSION
            || !self.restore.configuration.shares.is_empty()
            || self.restore.configuration.rosetta
        {
            return Err("unsupported restore inspection schema or device profile".into());
        }
        self.restore.validate()
    }

    pub fn expected_device_identities(&self) -> impl Iterator<Item = (&str, RestoreDeviceKind)> {
        std::iter::once((RESTORE_CONSOLE_ID, RestoreDeviceKind::Console))
            .chain(
                self.restore
                    .configuration
                    .attachments
                    .iter()
                    .map(|attachment| (attachment.block_id.as_str(), RestoreDeviceKind::Block)),
            )
            .chain(std::iter::once((
                RESTORE_VSOCK_ID,
                RestoreDeviceKind::Vsock,
            )))
            .chain(
                self.network
                    .then_some((RESTORE_NETWORK_ID, RestoreDeviceKind::Network)),
            )
            .chain([
                (RESTORE_RNG_ID, RestoreDeviceKind::Rng),
                (RESTORE_BALLOON_ID, RestoreDeviceKind::Balloon),
                (RESTORE_GENERATION_ID, RestoreDeviceKind::Generation),
            ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreDeviceKind {
    Block,
    Network,
    Vsock,
    Console,
    Rng,
    Balloon,
    Generation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreAdmittedDevice {
    pub configured_id: String,
    pub kind: RestoreDeviceKind,
    pub address: u64,
    pub irq: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreInspectionReport {
    pub version: u32,
    pub request: Sha256Digest,
    pub checkpoint: Sha256Digest,
    pub live_state_schema: String,
    pub architecture: String,
    pub lane: crate::live::LiveLane,
    pub cpu_count: u32,
    pub ram_bytes: u64,
    pub devices: Vec<RestoreAdmittedDevice>,
}

/// Bounded exact execution portability refusal, never RAM or secret contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestorePortabilityRefusal {
    pub pin: String,
    pub expected: String,
    pub actual: String,
    pub stage: String,
}

impl RestorePortabilityRefusal {
    pub fn new(
        pin: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        fn bounded(mut value: String) -> String {
            if value.len() > 4096 {
                let digest = Sha256Digest::of_bytes(value.as_bytes());
                let mut end = 3968;
                while !value.is_char_boundary(end) {
                    end -= 1;
                }
                value.truncate(end);
                value.push_str(&format!(" [complete:{digest}]"));
            }
            value
        }
        Self {
            pin: pin.into(),
            expected: bounded(expected.into()),
            actual: bounded(actual.into()),
            stage: "restore-preflight".into(),
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.stage != "restore-preflight"
            || self.pin.is_empty()
            || self.pin.len() > 128
            || self.expected.is_empty()
            || self.expected.len() > 16384
            || self.actual.is_empty()
            || self.actual.len() > 16384
            || [&self.pin, &self.expected, &self.actual]
                .iter()
                .any(|value| value.contains('\0'))
        {
            return Err("invalid bounded restore portability refusal".into());
        }
        Ok(())
    }
}
impl std::fmt::Display for RestorePortabilityRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {} expected {}, destination {}; no execution child started",
            self.stage, self.pin, self.expected, self.actual
        )
    }
}
impl std::error::Error for RestorePortabilityRefusal {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreInspectionFailure {
    pub version: u32,
    pub refusal: RestorePortabilityRefusal,
}
impl RestoreInspectionFailure {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != RESTORE_INSPECTION_VERSION {
            return Err("unsupported inspection failure version".into());
        }
        self.refusal.validate()
    }
}

impl RestoreInspectionReport {
    pub fn portability_refusal(
        &self,
        request: &RestoreInspectionRequest,
    ) -> Option<RestorePortabilityRefusal> {
        let memory = request.restore.evidence.memory.as_ref()?;
        let mismatch = |pin: &str, expected: String, actual: String| {
            (expected != actual).then(|| RestorePortabilityRefusal::new(pin, expected, actual))
        };
        mismatch(
            "live-state-schema",
            self.live_state_schema.clone(),
            memory.binding.live_state_schema.clone(),
        )
        .or_else(|| {
            mismatch(
                "architecture",
                self.architecture.clone(),
                memory.binding.architecture.clone(),
            )
        })
        .or_else(|| {
            mismatch(
                "topology.cpu-count",
                request.restore.configuration.cpus.to_string(),
                self.cpu_count.to_string(),
            )
        })
        .or_else(|| {
            mismatch(
                "ram-layout",
                request.restore.configuration.ram_bytes().to_string(),
                self.ram_bytes.to_string(),
            )
        })
        .or_else(|| {
            (self.lane == crate::live::LiveLane::NotApplicable).then(|| {
                RestorePortabilityRefusal::new(
                    "hypervisor",
                    "captured execution lane",
                    "unavailable",
                )
            })
        })
    }
    pub fn validate_against(
        &self,
        request_bytes: &[u8],
        request: &RestoreInspectionRequest,
    ) -> Result<(), String> {
        request.validate()?;
        if let Some(refusal) = self.portability_refusal(request) {
            return Err(refusal.to_string());
        }
        let memory = request
            .restore
            .evidence
            .memory
            .as_ref()
            .ok_or_else(|| "restore inspection lacks a memory binding".to_string())?;
        if request_bytes.len() > MAX_RESTORE_INSPECTION_BYTES
            || self.version != RESTORE_INSPECTION_VERSION
            || self.request != Sha256Digest::of_bytes(request_bytes)
            || self.checkpoint != request.restore.checkpoint
            || self.live_state_schema != memory.binding.live_state_schema
            || self.architecture != memory.binding.architecture
            || self.lane == crate::live::LiveLane::NotApplicable
            || self.cpu_count != u32::from(request.restore.configuration.cpus)
            || self.ram_bytes != request.restore.configuration.ram_bytes()
            || self.devices.is_empty()
            || self.devices.len() > 256
        {
            return Err("restore inspection report does not admit these exact inputs".into());
        }
        let mut identities = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        let mut irqs = BTreeSet::new();
        for device in &self.devices {
            if device.configured_id.is_empty()
                || device.configured_id.len() > 256
                || device.configured_id.contains('\0')
                || !identities.insert(&device.configured_id)
                || !addresses.insert(device.address)
                || !irqs.insert(device.irq)
            {
                return Err("restore inspection device routing is invalid".into());
            }
        }
        if self.devices.len() != request.expected_device_identities().count()
            || request.expected_device_identities().any(|(id, kind)| {
                !self
                    .devices
                    .iter()
                    .any(|device| device.configured_id == id && device.kind == kind)
            })
        {
            return Err(
                "restore inspection device inventory differs from the requested configuration"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::capture::Sha256Digest;
    use crate::restore::{
        RestoreInspectionFailure, RestorePortabilityRefusal, RESTORE_INSPECTION_VERSION,
    };

    #[test]
    fn portability_refusals_keep_exact_pin_and_bounded_complete_identity() {
        let value = "captured-state-".repeat(5000);
        let digest = Sha256Digest::of_bytes(value.as_bytes());
        let refusal =
            RestorePortabilityRefusal::new("live-state-schema", value, "destination-schema");
        refusal.validate().unwrap();
        assert!(refusal.expected.contains(&digest.to_string()));
        assert!(refusal.expected.len() <= 4096);
        assert!(refusal.to_string().contains("no execution child started"));
        let failure = RestoreInspectionFailure {
            version: RESTORE_INSPECTION_VERSION,
            refusal,
        };
        let bytes = serde_json::to_vec(&failure).unwrap();
        let decoded: RestoreInspectionFailure = serde_json::from_slice(&bytes).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, failure);
        let mut invalid = failure.clone();
        invalid.refusal.stage = "activation".into();
        assert!(invalid.validate().is_err());
        let mut invalid = failure;
        invalid.refusal.actual.clear();
        assert!(invalid.validate().is_err());
    }
}
