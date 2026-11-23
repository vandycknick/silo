//! Descriptor-only execution inputs for a fresh, paused restore attempt.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capture::{
    CaptureConfiguration, CaptureEvidence, CaptureRole, CaptureStateBinding, OwnedLocalCut,
    Sha256Digest, SourceFingerprint, MAX_CAPTURE_RAM_BYTES,
};
use crate::lifecycle::LiveId;

/// Identity policy is explicit. Missing or unknown purposes never preserve identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationPurpose {
    Clone,
    SameMachine,
}

impl ActivationPurpose {
    pub fn validate(
        self,
        source_machine_id: &LiveId,
        source_run_id: &LiveId,
        destination_machine_id: &LiveId,
        destination_run_id: &LiveId,
    ) -> Result<(), String> {
        if source_run_id == destination_run_id {
            return Err("activation requires a new run".into());
        }
        match self {
            Self::Clone if source_machine_id == destination_machine_id => {
                Err("clone activation requires a new machine".into())
            }
            Self::SameMachine if source_machine_id != destination_machine_id => {
                Err("same-machine activation requires the original machine".into())
            }
            _ => Ok(()),
        }
    }
}

pub const RESTORE_REQUEST_VERSION: u32 = 1;
pub const GENERATION_ACK_TIMEOUT_MS: u64 = 5_000;
pub const ACTIVATE_TIMEOUT_MS: u64 = 30_000;
pub const RESTORE_INSPECTION_VERSION: u32 = 1;
pub const MAX_RESTORE_INSPECTION_BYTES: usize =
    crate::capture::MAX_CAPTURE_RECORD_BYTES + (1 << 20);
pub const MAX_RESTORE_INSPECTION_REPORT_BYTES: usize = 2 * MAX_RESTORE_INSPECTION_BYTES + (1 << 20);
pub const MAX_RESTORE_LOWER_EXTENTS: usize = 1536;
pub const RESTORE_CONSOLE_ID: &str = "hvc0";
pub const RESTORE_VSOCK_ID: &str = "vsock";
pub const RESTORE_NETWORK_ID: &str = "net0";
pub const RESTORE_RNG_ID: &str = "rng";
pub const RESTORE_BALLOON_ID: &str = "balloon";
pub const RESTORE_GENERATION_ID: &str = "silo-vmgenid";

/// Destination-only seeds, rebound after authenticated private cloning/copying.
/// Neither source dirty bits nor source tracking epochs are restored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreDiskTrackingSeeds {
    pub version: u32,
    pub seeds: Vec<crate::capture::DiskTrackingSeed>,
}

impl RestoreDiskTrackingSeeds {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != crate::capture::DISK_TRACKING_VERSION || self.seeds.len() > 256 {
            return Err("restore disk seeds version or count is invalid".into());
        }
        let mut inodes = BTreeSet::new();
        let mut epochs = BTreeSet::new();
        let mut blocks = BTreeSet::new();
        let mut previous = None;
        for seed in &self.seeds {
            seed.validate()?;
            if seed.baseline.is_none()
                || !inodes.insert((seed.file_device, seed.file_inode))
                || !epochs.insert(seed.epoch.clone())
                || !blocks.insert(seed.block_id.clone())
                || previous.is_some_and(|index| seed.attachment_index <= index)
            {
                return Err(
                    "restore disk seeds lack unique authenticated destination bindings".into(),
                );
            }
            previous = Some(seed.attachment_index);
        }
        Ok(())
    }

    pub fn validate_against_configuration(
        &self,
        configuration: &CaptureConfiguration,
    ) -> Result<(), String> {
        self.validate()?;
        configuration.validate()?;
        let mut seeds = self.seeds.iter();
        for (index, attachment) in configuration.attachments.iter().enumerate() {
            if attachment.read_only {
                continue;
            }
            let seed = seeds.next().ok_or("restore disk seed is missing")?;
            if seed.attachment_index as usize != index
                || seed.block_id != attachment.block_id
                || seed.role != attachment.role
                || seed.length != attachment.geometry.length
                || attachment.format != crate::DiskFormat::Raw
            {
                return Err("restore disk seed differs from destination attachment".into());
            }
        }
        if seeds.next().is_some() {
            return Err("restore disk seed has no writable destination attachment".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::capture::MAX_DISK_TRACKING_BYTES {
            return Err("restore disk seeds exceed their bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if value.canonical_bytes()? != bytes {
            return Err("restore disk seed bytes are not canonical".into());
        }
        Ok(value)
    }
}

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
            Self::RamMap => crate::stream_map::MAX_ROOT_BYTES as u64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RestoreAuthority {
    IdentifiedSnapshot {
        snapshot: Sha256Digest,
        evidence: Box<CaptureEvidence>,
    },
    OwnedLocalCut {
        cut: Box<OwnedLocalCut>,
    },
    /// Private same-machine save, with original writable disks, never disk copies.
    Hibernation {
        cut: Box<crate::hibernate::HibernateCut>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RestoreReference {
    IdentifiedSnapshot { snapshot: Sha256Digest },
    OwnedLocalCut { capture_id: LiveId },
    Hibernation { save_id: LiveId },
}

impl RestoreAuthority {
    pub fn reference(&self) -> RestoreReference {
        match self {
            Self::IdentifiedSnapshot { snapshot, .. } => RestoreReference::IdentifiedSnapshot {
                snapshot: *snapshot,
            },
            Self::OwnedLocalCut { cut } => RestoreReference::OwnedLocalCut {
                capture_id: cut.capture_id.clone(),
            },
            Self::Hibernation { cut } => RestoreReference::Hibernation {
                save_id: cut.save_id.clone(),
            },
        }
    }

    pub fn binding(&self) -> Result<&CaptureStateBinding, String> {
        match self {
            Self::IdentifiedSnapshot { evidence, .. } => evidence
                .memory
                .as_ref()
                .map(|memory| &memory.binding)
                .ok_or_else(|| "identified restore lacks a memory binding".into()),
            Self::OwnedLocalCut { cut } => Ok(&cut.binding),
            Self::Hibernation { cut } => Ok(&cut.binding),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RestoreObjectAuthority {
    Identified {
        identity: Sha256Digest,
    },
    Owned {
        fingerprint: SourceFingerprint,
    },
    /// Reboot-stable durable facts; the object's device number binds this open
    /// descriptor only and is not compared with the save.
    Hibernation {
        file: crate::hibernate::HibernateFileBinding,
    },
}

/// The sender duplicates an admitted, leased immutable object under explicit
/// identified or owned authority. Receivers compare exact facts with fstat and
/// validate the complete FD set before adoption; numbers never authorize path opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreObject {
    pub role: RestoreObjectRole,
    pub fd: i32,
    pub file_device: u64,
    pub file_inode: u64,
    pub length: u64,
    pub authority: RestoreObjectAuthority,
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

/// Optional per-attachment seeds. Omitted attachments have unknown coverage.
pub fn validate_disk_tracking_seeds(
    seeds: &[crate::capture::DiskTrackingSeed],
    configuration: &CaptureConfiguration,
) -> Result<(), String> {
    let mut previous = None;
    let mut inodes = BTreeSet::new();
    let mut epochs = BTreeSet::new();
    for seed in seeds {
        seed.validate()?;
        let attachment = configuration
            .attachments
            .get(seed.attachment_index as usize)
            .ok_or("disk seed has no destination attachment")?;
        if previous.is_some_and(|index| seed.attachment_index <= index)
            || !inodes.insert((seed.file_device, seed.file_inode))
            || !epochs.insert(seed.epoch.clone())
            || attachment.read_only
            || attachment.format != crate::DiskFormat::Raw
            || seed.block_id != attachment.block_id
            || seed.role != attachment.role
            || seed.length != attachment.geometry.length
        {
            return Err("disk seed differs from its unique writable raw attachment".into());
        }
        previous = Some(seed.attachment_index);
    }
    Ok(())
}

/// Machine/run, forward policy and shutdown context are supplied by the
/// enclosing managed launch, never inherited from the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRequest {
    pub version: u32,
    pub purpose: ActivationPurpose,
    pub authority: RestoreAuthority,
    pub activation_id: LiveId,
    pub freeze_operation_id: LiveId,
    pub start_paused: bool,
    pub configuration: CaptureConfiguration,
    pub disk_tracking_seeds: Vec<crate::capture::DiskTrackingSeed>,
    #[serde(deserialize_with = "crate::capture::required")]
    pub map_node_store: Option<String>,
    /// RAM, layout, execution, devices, then a RAM map for identified authority only.
    pub objects: Vec<RestoreObject>,
    pub lowers: Vec<RestoreLower>,
    pub network: Option<RestoreNetwork>,
    /// Clone destination CA, or retained SameMachine trust. Wake may omit it.
    pub ssh_trusted_ca: Option<String>,
    pub hook: Option<RestoreHook>,
}

impl RestoreRequest {
    /// Validate the enclosing launch identities before constructing a VM.
    pub fn validate_activation(&self, machine_id: &LiveId, run_id: &LiveId) -> Result<(), String> {
        let source_machine = match &self.authority {
            RestoreAuthority::IdentifiedSnapshot { evidence, .. } => &evidence.machine_id,
            RestoreAuthority::OwnedLocalCut { cut } => &cut.machine_id,
            RestoreAuthority::Hibernation { cut } => &cut.machine_id,
        };
        self.purpose.validate(
            source_machine,
            &self.authority.binding()?.source_run,
            machine_id,
            run_id,
        )?;
        if self.purpose == ActivationPurpose::SameMachine && self.hook.is_some() {
            return Err("same-machine activation must not run a restore hook".into());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_with_destination_tracking(true)
    }

    /// Descriptor-only inspection precedes allocation of private child disks.
    /// Omitted seeds are permitted here only; supplied seeds must be complete.
    pub fn validate_for_inspection(&self) -> Result<(), String> {
        self.validate_with_destination_tracking(false)
    }

    fn validate_with_destination_tracking(
        &self,
        require_destination_seeds: bool,
    ) -> Result<(), String> {
        if self.version != RESTORE_REQUEST_VERSION || !self.start_paused {
            return Err("restore requires the current schema and startPaused=true".into());
        }
        if (self.purpose == ActivationPurpose::SameMachine)
            != matches!(self.authority, RestoreAuthority::Hibernation { .. })
        {
            return Err("wake requires hibernation authority and same-machine activation".into());
        }
        if self
            .map_node_store
            .as_ref()
            .is_some_and(|path| path.len() > 4096 || !std::path::Path::new(path).is_absolute())
        {
            return Err("restore map node store path must be bounded and absolute".into());
        }
        self.configuration.validate()?;
        validate_disk_tracking_seeds(&self.disk_tracking_seeds, &self.configuration)?;
        let expected_count = match &self.authority {
            RestoreAuthority::IdentifiedSnapshot { evidence, .. } => {
                evidence.validate()?;
                if !evidence.is_sealed()
                    || self.configuration.digest()? != evidence.configuration_digest
                    || evidence.freeze_operation_id.as_ref() != Some(&self.freeze_operation_id)
                {
                    return Err("restore requires the exact coherent identified capture".into());
                }
                5
            }
            RestoreAuthority::OwnedLocalCut { cut } => {
                cut.validate()?;
                if cut.configuration != self.configuration {
                    return Err(
                        "owned restore configuration differs from the captured execution pins"
                            .into(),
                    );
                }
                if cut.freeze_operation_id != self.freeze_operation_id {
                    return Err("owned restore freeze operation differs from the cut".into());
                }
                if self.map_node_store.is_some() {
                    return Err("owned restore must not carry an identified map node store".into());
                }
                if self
                    .disk_tracking_seeds
                    .iter()
                    .any(|seed| seed.baseline.is_some())
                {
                    return Err(
                        "owned restore destination seed carries an identified baseline".into(),
                    );
                }
                let writable = self
                    .configuration
                    .attachments
                    .iter()
                    .filter(|attachment| !attachment.read_only)
                    .count();
                if (require_destination_seeds || !self.disk_tracking_seeds.is_empty())
                    && self.disk_tracking_seeds.len() != writable
                {
                    return Err(format!(
                        "owned restore destination seed count {} differs from {} writable attachments",
                        self.disk_tracking_seeds.len(), writable
                    ));
                }
                if self.disk_tracking_seeds.iter().any(|seed| {
                    cut.members.iter().any(|member| {
                        member.fingerprint.device == seed.file_device
                            && member.fingerprint.inode == seed.file_inode
                    })
                }) {
                    return Err(
                        "owned restore writable destination inode aliases a cut member".into(),
                    );
                }
                4
            }
            RestoreAuthority::Hibernation { cut } => {
                cut.validate()?;
                if self.purpose != ActivationPurpose::SameMachine
                    || self.hook.is_some()
                    || cut.configuration != self.configuration
                    || cut.freeze_operation_id != self.freeze_operation_id
                    || self.map_node_store.is_some()
                    || self
                        .disk_tracking_seeds
                        .iter()
                        .any(|seed| seed.baseline.is_some())
                {
                    return Err("wake inputs differ from the saved execution configuration".into());
                }
                4
            }
        };
        if self.objects.len() != expected_count {
            return Err("restore object count does not match input authority".into());
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
            match (&self.authority, &object.authority) {
                (
                    RestoreAuthority::IdentifiedSnapshot { evidence, .. },
                    RestoreObjectAuthority::Identified { identity },
                ) => {
                    let inventory = evidence
                        .inventory
                        .iter()
                        .find(|entry| entry.role == object.role.capture_role())
                        .ok_or_else(|| {
                            "restore object is absent from the captured cut".to_string()
                        })?;
                    let expected = match object.role {
                        RestoreObjectRole::Ram => inventory.identity,
                        _ => inventory.sha256,
                    };
                    if object.length != inventory.length || Some(*identity) != expected {
                        return Err("restore identity differs from identified evidence".into());
                    }
                }
                (
                    RestoreAuthority::OwnedLocalCut { cut },
                    RestoreObjectAuthority::Owned { fingerprint },
                ) => {
                    fingerprint.validate()?;
                    let member = cut
                        .members
                        .iter()
                        .find(|member| member.role == object.role.capture_role())
                        .ok_or_else(|| "restore object is absent from the owned cut".to_string())?;
                    if fingerprint != &member.fingerprint
                        || object.length != fingerprint.length
                        || object.file_device != fingerprint.device
                        || object.file_inode != fingerprint.inode
                    {
                        return Err("restore exact-file facts differ from owned evidence".into());
                    }
                }
                (
                    RestoreAuthority::Hibernation { cut },
                    RestoreObjectAuthority::Hibernation { file },
                ) => {
                    let saved = cut
                        .saved_files
                        .get(match object.role {
                            RestoreObjectRole::Ram => 0,
                            RestoreObjectRole::Layout => 1,
                            RestoreObjectRole::Execution => 2,
                            RestoreObjectRole::Devices => 3,
                            RestoreObjectRole::RamMap => {
                                return Err("wake has no identified RAM map".into())
                            }
                        })
                        .ok_or("wake saved file is missing")?;
                    if file != &saved.file
                        || object.length != file.size
                        || object.file_inode != file.inode
                    {
                        return Err("wake object facts differ from the saved file".into());
                    }
                }
                _ => return Err("restore input authority cannot be downgraded or mixed".into()),
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
        self.restore.validate_for_inspection()
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
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RestoreInspectionRequestBinding {
    Identified { sha256: Sha256Digest },
    OwnedLocalCut { request: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreInspectionReport {
    pub version: u32,
    pub request: RestoreInspectionRequestBinding,
    pub authority: RestoreReference,
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
        let binding = request.restore.authority.binding().ok()?;
        let mismatch = |pin: &str, expected: String, actual: String| {
            (expected != actual).then(|| RestorePortabilityRefusal::new(pin, expected, actual))
        };
        mismatch(
            "live-state-schema",
            self.live_state_schema.clone(),
            binding.live_state_schema.clone(),
        )
        .or_else(|| {
            mismatch(
                "architecture",
                self.architecture.clone(),
                binding.architecture.clone(),
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
        let binding = request.restore.authority.binding()?;
        let request_matches = match (&self.request, &request.restore.authority) {
            (
                RestoreInspectionRequestBinding::Identified { sha256 },
                RestoreAuthority::IdentifiedSnapshot { .. },
            ) => *sha256 == Sha256Digest::of_bytes(request_bytes),
            (
                RestoreInspectionRequestBinding::OwnedLocalCut { request: exact },
                RestoreAuthority::OwnedLocalCut { .. } | RestoreAuthority::Hibernation { .. },
            ) => exact.as_bytes() == request_bytes,
            _ => false,
        };
        if request_bytes.len() > MAX_RESTORE_INSPECTION_BYTES
            || self.version != RESTORE_INSPECTION_VERSION
            || !request_matches
            || self.authority != request.restore.authority.reference()
            || self.live_state_schema != binding.live_state_schema
            || self.architecture != binding.architecture
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
    fn restore_disk_tracking_seeds_bind_every_destination_and_decode_strictly() {
        use crate::capture::{
            CaptureAttachment, CaptureConfiguration, DiskTrackingSeed, DISK_TRACKING_VERSION,
            STREAM_CHUNK_BYTES,
        };
        use crate::lifecycle::LiveId;
        use crate::restore::RestoreDiskTrackingSeeds;
        use crate::{BlockId, DiskFormat, DiskGeometry, DiskRole};
        let seed = DiskTrackingSeed {
            version: DISK_TRACKING_VERSION,
            map_format: 1,
            chunk_shift: 23,
            role: DiskRole::Root,
            attachment_index: 0,
            block_id: BlockId::new("root").unwrap(),
            file_device: 5,
            file_inode: 7,
            length: STREAM_CHUNK_BYTES + 512,
            chunk_size: STREAM_CHUNK_BYTES,
            epoch: LiveId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            baseline: Some(Sha256Digest::of_bytes(b"authenticated destination")),
        };
        let configuration = CaptureConfiguration {
            guest_os: None,
            cpus: 1,
            memory_mib: 512,
            nested_virtualization: false,
            rosetta: false,
            kernel_cmdline: Vec::new(),
            vsock: true,
            shares: Vec::new(),
            attachments: vec![CaptureAttachment {
                block_id: seed.block_id.clone(),
                role: seed.role,
                format: DiskFormat::Raw,
                geometry: DiskGeometry {
                    length: seed.length,
                    logical_sector_size: 512,
                },
                read_only: false,
            }],
        };
        let seeds = RestoreDiskTrackingSeeds {
            version: DISK_TRACKING_VERSION,
            seeds: vec![seed],
        };
        seeds
            .validate_against_configuration(&configuration)
            .unwrap();
        crate::restore::validate_disk_tracking_seeds(&[], &configuration).unwrap();
        crate::restore::validate_disk_tracking_seeds(&seeds.seeds, &configuration).unwrap();
        let mut unknown = seeds.seeds.clone();
        unknown[0].baseline = None;
        crate::restore::validate_disk_tracking_seeds(&unknown, &configuration).unwrap();
        let mut wrong = seeds.seeds.clone();
        wrong[0].block_id = BlockId::new("foreign").unwrap();
        assert!(crate::restore::validate_disk_tracking_seeds(&wrong, &configuration).is_err());
        let mut readonly = configuration.clone();
        readonly.attachments[0].read_only = true;
        assert!(crate::restore::validate_disk_tracking_seeds(&seeds.seeds, &readonly).is_err());
        let bytes = seeds.canonical_bytes().unwrap();
        assert_eq!(RestoreDiskTrackingSeeds::decode(&bytes).unwrap(), seeds);
        let json = String::from_utf8(bytes).unwrap();
        let mut duplicate_destination = seeds.clone();
        duplicate_destination.seeds.push(seeds.seeds[0].clone());
        for invalid in [
            format!("{json}\n"),
            json.replacen('{', "{\"unexpected\":0,", 1),
            json.replace(",\"mapFormat\":1", ""),
            json.replace("\"mapFormat\":1", "\"mapFormat\":2"),
            json.replace(",\"chunkShift\":23", ""),
            json.replace("\"chunkShift\":23", "\"chunkShift\":16"),
            serde_json::to_string(&duplicate_destination).unwrap(),
        ] {
            assert_ne!(invalid, json, "negative case must change the valid input");
            assert!(RestoreDiskTrackingSeeds::decode(invalid.as_bytes()).is_err());
        }
        for mutation in 0..8 {
            let mut bad = seeds.clone();
            match mutation {
                0 => bad.seeds.clear(),
                1 => bad.seeds[0].baseline = None,
                2 => bad.seeds[0].attachment_index += 1,
                3 => bad.seeds[0].block_id = BlockId::new("other").unwrap(),
                4 => bad.seeds[0].role = DiskRole::Data,
                5 => bad.seeds[0].length += 512,
                6 => bad.seeds.push(bad.seeds[0].clone()),
                _ => bad.version += 1,
            }
            assert!(
                bad.validate_against_configuration(&configuration).is_err(),
                "mutation {mutation}"
            );
        }
    }

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

    #[test]
    fn owned_restore_requires_complete_private_unknown_identity_inputs_and_never_downgrades() {
        use crate::capture::{DiskTrackingSeed, DISK_TRACKING_VERSION, STREAM_CHUNK_BYTES};
        use crate::restore::*;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let fixture = crate::capture::tests::owned_cut_fixture("restore-owned-authority");
        let cut = &fixture.cut;
        let mut held = Vec::new();
        let objects = RestoreObjectRole::ALL[..4]
            .iter()
            .copied()
            .map(|role| {
                let member = cut
                    .members
                    .iter()
                    .find(|member| member.role == role.capture_role())
                    .unwrap();
                let file = std::fs::File::open(fixture.directory.join(member.role.relative_path()))
                    .unwrap();
                let fd = file.as_raw_fd();
                held.push(file);
                RestoreObject {
                    role,
                    fd,
                    file_device: member.fingerprint.device,
                    file_inode: member.fingerprint.inode,
                    length: member.fingerprint.length,
                    authority: RestoreObjectAuthority::Owned {
                        fingerprint: member.fingerprint.clone(),
                    },
                }
            })
            .collect();
        let mut seeds = Vec::new();
        let mut lowers = Vec::new();
        for (index, attachment) in cut.configuration.attachments.iter().enumerate() {
            if attachment.read_only {
                if attachment.format == crate::DiskFormat::Vmdk {
                    let descriptor_path = fixture.directory.join(format!("lower-{index}.vmdk"));
                    let extent_path = fixture.directory.join(format!("lower-{index}.raw"));
                    std::fs::write(&descriptor_path, b"descriptor").unwrap();
                    let extent = std::fs::File::create(&extent_path).unwrap();
                    extent.set_len(attachment.geometry.length).unwrap();
                    drop(extent);
                    let descriptor = std::fs::File::open(&descriptor_path).unwrap();
                    let extent = std::fs::File::open(&extent_path).unwrap();
                    let metadata = descriptor.metadata().unwrap();
                    let extent_metadata = extent.metadata().unwrap();
                    lowers.push(RestoreLower {
                        block_id: attachment.block_id.clone(),
                        descriptor: RestoreDescriptor {
                            fd: descriptor.as_raw_fd(),
                            file_device: metadata.dev(),
                            file_inode: metadata.ino(),
                            length: metadata.len(),
                        },
                        extents: vec![RestoreExtent {
                            path: extent_path.to_str().unwrap().to_owned(),
                            fd: extent.as_raw_fd(),
                            file_device: extent_metadata.dev(),
                            file_inode: extent_metadata.ino(),
                            length: extent_metadata.len(),
                        }],
                    });
                    held.push(descriptor);
                    held.push(extent);
                }
            } else {
                let disk =
                    std::fs::File::create(fixture.directory.join(format!("child-{index}.raw")))
                        .unwrap();
                disk.set_len(attachment.geometry.length).unwrap();
                let metadata = disk.metadata().unwrap();
                seeds.push(DiskTrackingSeed {
                    version: DISK_TRACKING_VERSION,
                    map_format: 1,
                    chunk_shift: 23,
                    role: attachment.role,
                    attachment_index: index as u32,
                    block_id: attachment.block_id.clone(),
                    file_device: metadata.dev(),
                    file_inode: metadata.ino(),
                    length: metadata.len(),
                    chunk_size: STREAM_CHUNK_BYTES,
                    epoch: crate::lifecycle::LiveId::parse(&format!(
                        "00000000-0000-4000-8000-{index:012x}"
                    ))
                    .unwrap(),
                    baseline: None,
                });
                held.push(disk);
            }
        }
        let request = RestoreRequest {
            purpose: crate::restore::ActivationPurpose::Clone,
            version: RESTORE_REQUEST_VERSION,
            authority: RestoreAuthority::OwnedLocalCut {
                cut: Box::new(cut.clone()),
            },
            activation_id: cut.capture_id.clone(),
            freeze_operation_id: cut.freeze_operation_id.clone(),
            start_paused: true,
            configuration: cut.configuration.clone(),
            disk_tracking_seeds: seeds,
            map_node_store: None,
            objects,
            lowers,
            network: None,
            ssh_trusted_ca: None,
            hook: None,
        };
        request.validate().unwrap();
        let mut preallocation = request.clone();
        preallocation.disk_tracking_seeds.clear();
        preallocation.validate_for_inspection().unwrap();
        assert!(preallocation
            .validate()
            .unwrap_err()
            .contains("destination seed count"));
        RestoreInspectionRequest {
            version: RESTORE_INSPECTION_VERSION,
            restore: preallocation,
            network: false,
        }
        .validate()
        .unwrap();
        let mut wrong_configuration = request.clone();
        wrong_configuration.configuration.cpus += 1;
        assert!(wrong_configuration
            .validate_for_inspection()
            .unwrap_err()
            .contains("configuration"));
        let mut wrong_freeze = request.clone();
        wrong_freeze.freeze_operation_id =
            crate::lifecycle::LiveId::parse("88888888-8888-4888-8888-888888888888").unwrap();
        assert!(wrong_freeze
            .validate_for_inspection()
            .unwrap_err()
            .contains("freeze operation"));
        let bytes = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<RestoreRequest>(&bytes).unwrap(),
            request
        );
        for mutation in 0..7 {
            let mut bad = request.clone();
            match mutation {
                0 => {
                    bad.objects[0].authority = RestoreObjectAuthority::Identified {
                        identity: Sha256Digest::of_bytes(b"not an owned file capability"),
                    }
                }
                1 => bad.disk_tracking_seeds.clear(),
                2 => {
                    bad.disk_tracking_seeds[0].baseline =
                        Some(Sha256Digest::of_bytes(b"foreign root"))
                }
                3 => bad.objects[1].fd = bad.objects[0].fd,
                4 => {
                    if let RestoreObjectAuthority::Owned { fingerprint } =
                        &mut bad.objects[0].authority
                    {
                        fingerprint.modified_nanoseconds =
                            (fingerprint.modified_nanoseconds + 1) % 1_000_000_000;
                    }
                }
                5 => bad.map_node_store = Some("/private/maps".into()),
                _ => {
                    bad.disk_tracking_seeds[0].file_device = cut.members[4].fingerprint.device;
                    bad.disk_tracking_seeds[0].file_inode = cut.members[4].fingerprint.inode;
                }
            }
            assert!(bad.validate().is_err(), "mutation {mutation}");
        }
        let inspection = RestoreInspectionRequest {
            version: RESTORE_INSPECTION_VERSION,
            restore: request,
            network: false,
        };
        let bytes = serde_json::to_vec(&inspection).unwrap();
        let mut report = RestoreInspectionReport {
            version: RESTORE_INSPECTION_VERSION,
            request: RestoreInspectionRequestBinding::OwnedLocalCut {
                request: String::from_utf8(bytes.clone()).unwrap(),
            },
            authority: inspection.restore.authority.reference(),
            live_state_schema: cut.binding.live_state_schema.clone(),
            architecture: cut.binding.architecture.clone(),
            lane: crate::live::LiveLane::KvmX86_64,
            cpu_count: u32::from(cut.configuration.cpus),
            ram_bytes: cut.packed_length,
            devices: inspection
                .expected_device_identities()
                .enumerate()
                .map(|(index, (id, kind))| RestoreAdmittedDevice {
                    configured_id: id.into(),
                    kind,
                    address: (index as u64 + 1) * 4096,
                    irq: index as u32 + 1,
                })
                .collect(),
        };
        report.validate_against(&bytes, &inspection).unwrap();
        report.request = RestoreInspectionRequestBinding::Identified {
            sha256: Sha256Digest::of_bytes(&bytes),
        };
        assert!(report.validate_against(&bytes, &inspection).is_err());
        report.request = RestoreInspectionRequestBinding::OwnedLocalCut {
            request: format!("{} ", String::from_utf8(bytes.clone()).unwrap()),
        };
        assert!(report.validate_against(&bytes, &inspection).is_err());
        let mut unknown = serde_json::to_value(&inspection.restore).unwrap();
        unknown["authority"]["digest"] = serde_json::json!("not permitted");
        assert!(serde_json::from_value::<RestoreRequest>(unknown).is_err());
        drop(held);
    }
}
