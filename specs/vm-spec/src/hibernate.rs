//! Private, in-place saved execution authority (ADR 0023).
//!
//! The catalog, not these files, decides whether a save is available. Saved
//! files are read-only; writable disk bindings retain the machine's original
//! attachments. File facts ignore device numbers so remounts do not invalidate
//! an unchanged save. These facts detect replacement and metadata changes,
//! not silent bit rot. No disk copies or content hashes are produced.
//!
//! Capture uses `CaptureMode::Hibernate`; wake uses `ActivationPurpose::SameMachine`
//! and a new run ID. Construction must remain parked until a matching consume
//! authorization follows the durable single-use catalog commit. This module
//! defines the contract only, not catalog transitions or monitor execution.
use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::capture::{CaptureConfiguration, CaptureStateBinding, MAX_CAPTURE_RAM_BYTES};
use crate::lifecycle::LiveId;
use crate::{BlockId, DiskRole};

pub const HIBERNATE_CUT_VERSION: u32 = 1;

/// A save member or original writable disk no longer matches the durable cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HibernateFileMismatch {
    pub path: PathBuf,
}

impl std::fmt::Display for HibernateFileMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Saved file or disk {} changed; restore it unchanged or stop the machine with --force",
            self.path.display()
        )
    }
}

impl std::error::Error for HibernateFileMismatch {}

/// Whether the durable single-use authorization was accepted before failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WakeFailureBoundary {
    PreConsume,
    PostConsume,
}

#[derive(Debug)]
pub struct WakeFailure {
    pub boundary: WakeFailureBoundary,
    pub detail: String,
}

impl std::fmt::Display for WakeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.boundary {
            WakeFailureBoundary::PreConsume => write!(
                formatter,
                "wake failed before consume; the machine remains hibernated: {}",
                self.detail
            ),
            WakeFailureBoundary::PostConsume => write!(
                formatter,
                "wake failed after consume; the machine is stopped: {}",
                self.detail
            ),
        }
    }
}

impl std::error::Error for WakeFailure {}

/// Reboot-stable file facts. Device numbers are deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HibernateFileBinding {
    pub path: PathBuf,
    pub inode: u64,
    pub size: u64,
    pub mode: u32,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

impl HibernateFileBinding {
    pub fn validate(&self) -> Result<(), String> {
        if !self.path.is_absolute()
            || self.path.as_os_str().len() > 4095
            || self.path.as_os_str().as_encoded_bytes().contains(&0)
            || self.inode == 0
            || self.size == 0
            || self.mode & 0o170000 != 0o100000
            || !(0..1_000_000_000).contains(&self.modified_nanoseconds)
            || !(0..1_000_000_000).contains(&self.changed_nanoseconds)
        {
            return Err("saved file has invalid path or regular-file facts".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HibernateSavedFileRole {
    Memory,
    MemoryLayout,
    ExecutionState,
    DeviceState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HibernateSavedFile {
    pub role: HibernateSavedFileRole,
    pub file: HibernateFileBinding,
}

/// An original writable attachment, not an immutable snapshot member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HibernateDiskBinding {
    pub role: DiskRole,
    pub attachment_index: u32,
    pub block_id: BlockId,
    pub file: HibernateFileBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HibernateCut {
    pub version: u32,
    pub save_id: LiveId,
    pub machine_id: LiveId,
    pub ended_run_id: LiveId,
    pub freeze_operation_id: LiveId,
    pub freeze_epoch: NonZeroU64,
    pub configuration: CaptureConfiguration,
    pub binding: CaptureStateBinding,
    pub materialization_generation: NonZeroU64,
    pub predecessor_generation: u64,
    pub packed_length: u64,
    pub page_granule: u32,
    pub regions: u32,
    /// Memory, memory layout, execution state, device state, in that order.
    pub saved_files: [HibernateSavedFile; 4],
    pub writable_disks: Vec<HibernateDiskBinding>,
}

impl HibernateCut {
    pub fn validate(&self) -> Result<(), String> {
        self.configuration.validate()?;
        if self.version != HIBERNATE_CUT_VERSION
            || self.binding.source_run != self.ended_run_id
            || self.binding.capture != self.save_id
            || self.binding.live_state_schema.is_empty()
            || self.binding.live_state_schema.contains('\0')
            || self.binding.live_state_schema.len() > crate::capture::MAX_LIVE_STATE_SCHEMA_BYTES
            || self.binding.architecture.is_empty()
            || self.binding.architecture.contains('\0')
            || self.binding.architecture.len() > crate::capture::MAX_ARCHITECTURE_BYTES
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
        {
            return Err("hibernation cut has invalid execution binding or memory geometry".into());
        }
        let roles = [
            HibernateSavedFileRole::Memory,
            HibernateSavedFileRole::MemoryLayout,
            HibernateSavedFileRole::ExecutionState,
            HibernateSavedFileRole::DeviceState,
        ];
        let mut paths = BTreeSet::new();
        let mut inodes = BTreeSet::new();
        for (saved, role) in self.saved_files.iter().zip(roles) {
            saved.file.validate()?;
            let maximum = match role {
                HibernateSavedFileRole::Memory => self.packed_length,
                HibernateSavedFileRole::MemoryLayout => 64 << 10,
                HibernateSavedFileRole::ExecutionState => 16 << 20,
                HibernateSavedFileRole::DeviceState => 32 << 20,
            };
            if saved.role != role
                || saved.file.mode & 0o222 != 0
                || saved.file.size > maximum
                || (role == HibernateSavedFileRole::Memory && saved.file.size != self.packed_length)
                || !paths.insert(&saved.file.path)
                || !inodes.insert(saved.file.inode)
            {
                return Err(
                    "hibernation saved files must be complete, distinct and read-only".into(),
                );
            }
        }
        let writable = self
            .configuration
            .attachments
            .iter()
            .enumerate()
            .filter(|(_, attachment)| !attachment.read_only);
        if writable.clone().count() != self.writable_disks.len() {
            return Err("hibernation must bind every writable disk".into());
        }
        for (disk, (index, attachment)) in self.writable_disks.iter().zip(writable) {
            disk.file.validate()?;
            if usize::try_from(disk.attachment_index).ok() != Some(index)
                || disk.role != attachment.role
                || disk.block_id != attachment.block_id
                || disk.file.size != attachment.geometry.length
                || !paths.insert(&disk.file.path)
            {
                return Err("hibernation writable disk binding differs from its attachment".into());
            }
        }
        Ok(())
    }
}

/// The restored VM is constructed and parked before its first instruction.
/// The monitor MUST keep it parked until libvm durably consumes this save and
/// supplies the matching ConsumeAuthorization. Agent activation is too late.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestorePrepared {
    pub machine_id: LiveId,
    pub save_id: LiveId,
    pub new_run_id: LiveId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumeAuthorization {
    pub machine_id: LiveId,
    pub save_id: LiveId,
    pub new_run_id: LiveId,
}

impl RestorePrepared {
    pub fn validate_authorization(
        &self,
        authorization: &ConsumeAuthorization,
    ) -> Result<(), String> {
        if self.machine_id != authorization.machine_id
            || self.save_id != authorization.save_id
            || self.new_run_id != authorization.new_run_id
        {
            return Err(
                "wake authorization does not match the parked machine, save and run".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::capture::{
        CaptureAttachment, CaptureConfiguration, CaptureStateBinding, Sha256Digest,
    };
    use crate::hibernate::*;
    use crate::{BlockId, DiskFormat, DiskGeometry, DiskRole, VmSpec};

    fn id(n: u8) -> LiveId {
        LiveId::parse(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap()
    }
    fn file(n: u64, size: u64, mode: u32) -> HibernateFileBinding {
        HibernateFileBinding {
            path: PathBuf::from(format!("/machine/save/file-{n}")),
            inode: n,
            size,
            mode,
            modified_seconds: 10,
            modified_nanoseconds: 20,
            changed_seconds: 30,
            changed_nanoseconds: 40,
        }
    }
    fn cut() -> HibernateCut {
        let mut configuration = CaptureConfiguration::from_spec(&VmSpec::current()).unwrap();
        let block_id = BlockId::new("root").unwrap();
        configuration.attachments.push(CaptureAttachment {
            block_id: block_id.clone(),
            role: DiskRole::Root,
            format: DiskFormat::Raw,
            geometry: DiskGeometry {
                length: 4096,
                logical_sector_size: 512,
            },
            read_only: false,
        });
        let packed_length = configuration.ram_bytes();
        HibernateCut {
            version: HIBERNATE_CUT_VERSION,
            save_id: id(1),
            machine_id: id(2),
            ended_run_id: id(3),
            freeze_operation_id: id(4),
            freeze_epoch: NonZeroU64::new(1).unwrap(),
            configuration,
            binding: CaptureStateBinding {
                live_state_schema: "test-v1".into(),
                architecture: "x86_64".into(),
                profile: Sha256Digest::of_bytes(b"profile"),
                topology: Sha256Digest::of_bytes(b"topology"),
                ram_layout: Sha256Digest::of_bytes(b"layout"),
                source_run: id(3),
                pause_generation: NonZeroU64::new(1).unwrap(),
                capture: id(1),
            },
            materialization_generation: NonZeroU64::new(2).unwrap(),
            predecessor_generation: 1,
            packed_length,
            page_granule: 4096,
            regions: 1,
            saved_files: [
                HibernateSavedFile {
                    role: HibernateSavedFileRole::Memory,
                    file: file(1, packed_length, 0o100400),
                },
                HibernateSavedFile {
                    role: HibernateSavedFileRole::MemoryLayout,
                    file: file(2, 1024, 0o100400),
                },
                HibernateSavedFile {
                    role: HibernateSavedFileRole::ExecutionState,
                    file: file(3, 4096, 0o100400),
                },
                HibernateSavedFile {
                    role: HibernateSavedFileRole::DeviceState,
                    file: file(4, 4096, 0o100400),
                },
            ],
            writable_disks: vec![HibernateDiskBinding {
                role: DiskRole::Root,
                attachment_index: 0,
                block_id,
                file: file(5, 4096, 0o100600),
            }],
        }
    }

    #[test]
    fn hibernation_cut_roundtrips_with_in_place_writable_disks_and_no_device_number() {
        let cut = cut();
        cut.validate().unwrap();
        let json = serde_json::to_value(&cut).unwrap();
        assert!(json["savedFiles"][0]["file"].get("device").is_none());
        let decoded: HibernateCut = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(decoded, cut);
        decoded.validate().unwrap();
        let mut unknown = json;
        unknown["writableDisks"][0]["file"]["device"] = 7.into();
        assert!(serde_json::from_value::<HibernateCut>(unknown).is_err());
    }

    #[test]
    fn hibernation_cut_rejects_incomplete_replaced_or_malformed_file_inventory() {
        for mutation in 0..18 {
            let mut bad = cut();
            match mutation {
                0 => bad.version += 1,
                1 => bad.binding.source_run = id(9),
                2 => bad.binding.capture = id(9),
                3 => bad.saved_files[0].file.size -= 1,
                4 => bad.saved_files[1].role = HibernateSavedFileRole::Memory,
                5 => bad.saved_files[2].file.mode = 0o100600,
                6 => bad.saved_files[2].file.inode = 1,
                7 => bad.writable_disks.clear(),
                8 => bad.writable_disks[0].file.size += 512,
                9 => bad.writable_disks[0].attachment_index += 1,
                10 => bad.writable_disks[0].block_id = BlockId::new("foreign").unwrap(),
                11 => bad.writable_disks[0].file.modified_nanoseconds = -1,
                12 => bad.writable_disks[0].file.changed_nanoseconds = 1_000_000_000,
                13 => bad.writable_disks[0].file.path = PathBuf::from("relative"),
                14 => bad.writable_disks[0].file.inode = 0,
                15 => bad.saved_files[1].file.path = bad.saved_files[0].file.path.clone(),
                16 => bad.page_granule = 0,
                _ => bad.predecessor_generation = bad.materialization_generation.get(),
            }
            assert!(bad.validate().is_err(), "mutation {mutation}");
        }
    }
}
