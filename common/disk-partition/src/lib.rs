//! Bounded, disk-local partition facts shared by import and trusted guest init.
//!
//! The caller supplies a held decoded raw stream and its known 512-byte-sector
//! geometry. No paths, device discovery, filesystem inference, EBR traversal or
//! repair are performed. `None` means no meaningful table, never a corrupt GPT
//! fallback. Facts do not establish filesystem support or boot architecture.

#![no_std]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;
use uuid::Uuid;

/// Exact reads from the caller's held decoded raw stream or block device.
///
/// Implementations must fill the entire output or return an error. EOF must
/// never be represented by zero-filling the unread portion.
pub trait ReadAt {
    type Error;

    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error>;
}

#[cfg(feature = "std")]
impl<R: std::io::Read + std::io::Seek + ?Sized> ReadAt for R {
    type Error = std::io::Error;

    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.seek(std::io::SeekFrom::Start(offset))?;
        self.read_exact(output)
    }
}

pub const SECTOR_SIZE: u64 = 512;
pub const MAX_DISK_BYTES: u64 = 1 << 40;
pub const MAX_GPT_ENTRIES: u32 = 128;
/// Explicit admission bound, not a limit imposed by the GPT format.
pub const MAX_GPT_ENTRY_SIZE: u32 = 4096;
pub const MAX_GPT_METADATA_BYTES: u64 = MAX_GPT_ENTRIES as u64 * MAX_GPT_ENTRY_SIZE as u64;

/// DPS root *type* GUIDs, selected using declared userspace, not kernel/host ISA.
pub const DPS_ROOT_AMD64: Uuid = Uuid::from_u128(0x4f68bce3_e8cd_4db1_96e7_fbcaf984b709);
pub const DPS_ROOT_ARM64: Uuid = Uuid::from_u128(0xb921b045_1df0_41c3_af44_4c6f280d3fae);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    byte_length: u64,
}

impl Geometry {
    /// Validates geometry without an I/O error type to infer at the call site.
    /// The error's default type is `Infallible`, since this performs no reads.
    pub fn new(byte_length: u64) -> Result<Self, Error> {
        if byte_length == 0 || byte_length > MAX_DISK_BYTES || byte_length % SECTOR_SIZE != 0 {
            return Err(Error::InvalidGeometry { byte_length });
        }
        Ok(Self { byte_length })
    }

    pub fn byte_length(self) -> u64 {
        self.byte_length
    }

    pub fn sectors(self) -> u64 {
        self.byte_length / SECTOR_SIZE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMode {
    /// Both copies and protective MBR must describe the current capacity.
    StrictImport,
    /// Opaque growth does not relocate GPT. Validate both recorded copies at
    /// their original locations, accepting only additional trailing capacity.
    GuestBoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupPlacement {
    AtCapacity,
    BeforeExpandedEnd {
        backup_lba: u64,
        current_last_lba: u64,
    },
}

/// Inclusive sector range. Constructed only after validation against geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    first_lba: u64,
    last_lba: u64,
}

impl Extent {
    pub fn first_lba(self) -> u64 {
        self.first_lba
    }

    pub fn last_lba(self) -> u64 {
        self.last_lba
    }

    pub fn byte_offset(self) -> u64 {
        self.first_lba * SECTOR_SIZE
    }

    pub fn byte_length(self) -> u64 {
        (self.last_lba - self.first_lba + 1) * SECTOR_SIZE
    }

    fn overlaps(self, other: Self) -> bool {
        self.first_lba <= other.last_lba && other.first_lba <= self.last_lba
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPartition {
    slot: u32,
    type_guid: Uuid,
    unique_guid: Uuid,
    extent: Extent,
    attributes: u64,
}

impl GptPartition {
    /// One-based table entry index, without compacting unused entries.
    pub fn slot(self) -> u32 {
        self.slot
    }

    pub fn type_guid(self) -> Uuid {
        self.type_guid
    }

    pub fn unique_guid(self) -> Uuid {
        self.unique_guid
    }

    pub fn extent(self) -> Extent {
        self.extent
    }

    pub fn attributes(self) -> u64 {
        self.attributes
    }

    /// DPS semantics apply to DPS types; these helpers report bits, not policy.
    pub fn no_auto(self) -> bool {
        self.attributes & (1 << 63) != 0
    }

    pub fn read_only(self) -> bool {
        self.attributes & (1 << 60) != 0
    }

    pub fn growfs(self) -> bool {
        self.attributes & (1 << 59) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptTable {
    disk_guid: Uuid,
    usable: Extent,
    backup_placement: BackupPlacement,
    entry_count: u32,
    entry_size: u32,
    partitions: Vec<GptPartition>,
}

impl GptTable {
    pub fn disk_guid(&self) -> Uuid {
        self.disk_guid
    }

    pub fn usable(&self) -> Extent {
        self.usable
    }

    pub fn backup_placement(&self) -> BackupPlacement {
        self.backup_placement
    }

    pub fn entry_count(&self) -> u32 {
        self.entry_count
    }

    pub fn entry_size(&self) -> u32 {
        self.entry_size
    }

    pub fn partitions(&self) -> &[GptPartition] {
        &self.partitions
    }

    /// The unique partition GUID, not the type GUID or disk GUID. This table
    /// belongs to one attachment; identical GUIDs on another disk are irrelevant.
    pub fn find_unique_guid(&self, guid: Uuid) -> Result<&GptPartition, LookupError> {
        self.partitions
            .iter()
            .find(|partition| partition.unique_guid == guid)
            .ok_or(LookupError::GuidNotFound { guid })
    }

    /// Includes no-auto/read-only entries so diagnostics do not hide candidates.
    /// Callers map their declared userspace architecture to a DPS_ROOT constant.
    pub fn dps_candidates(&self, root_type: Uuid) -> impl Iterator<Item = &GptPartition> {
        self.partitions
            .iter()
            .filter(move |partition| partition.type_guid == root_type)
    }

    /// Silo's single-candidate rule, not DPS's firmware/first-partition algorithm.
    /// Read-only admission and filesystem probing remain caller responsibilities.
    pub fn select_dps_root(&self, root_type: Uuid) -> Result<&GptPartition, LookupError> {
        if root_type != DPS_ROOT_AMD64 && root_type != DPS_ROOT_ARM64 {
            return Err(LookupError::UnsupportedRootType { root_type });
        }
        let mut candidates = self.dps_candidates(root_type);
        match (candidates.next(), candidates.next()) {
            (Some(partition), None) if partition.no_auto() => Err(LookupError::NoAuto {
                partition: *partition,
            }),
            (Some(partition), None) => Ok(partition),
            _ => Err(LookupError::DpsCandidates {
                root_type,
                candidates: self.dps_candidates(root_type).copied().collect(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartition {
    slot: u8,
    partition_type: u8,
    extent: Extent,
}

impl MbrPartition {
    pub fn slot(self) -> u8 {
        self.slot
    }

    pub fn partition_type(self) -> u8 {
        self.partition_type
    }

    pub fn extent(self) -> Extent {
        self.extent
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbrTable {
    partitions: Vec<MbrPartition>,
}

impl MbrTable {
    pub fn partitions(&self) -> &[MbrPartition] {
        &self.partitions
    }

    pub fn find_primary_slot(&self, slot: u8) -> Result<&MbrPartition, LookupError> {
        if !(1..=4).contains(&slot) {
            return Err(LookupError::InvalidPrimarySlot { slot });
        }
        self.partitions
            .iter()
            .find(|partition| partition.slot == slot)
            .ok_or(LookupError::EmptyPrimarySlot { slot })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionTable {
    None,
    Gpt(GptTable),
    Mbr(MbrTable),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    GuidNotFound {
        guid: Uuid,
    },
    InvalidPrimarySlot {
        slot: u8,
    },
    EmptyPrimarySlot {
        slot: u8,
    },
    UnsupportedRootType {
        root_type: Uuid,
    },
    DpsCandidates {
        root_type: Uuid,
        candidates: Vec<GptPartition>,
    },
    NoAuto {
        partition: GptPartition,
    },
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuidNotFound { guid } => {
                write!(
                    f,
                    "unique partition GUID {guid} is not present on this disk"
                )
            }
            Self::InvalidPrimarySlot { slot } => write!(
                f,
                "MBR primary slot {slot} is outside 1..=4; logical partitions are unsupported"
            ),
            Self::EmptyPrimarySlot { slot } => {
                write!(f, "MBR primary slot {slot} is empty on this disk")
            }
            Self::UnsupportedRootType { root_type } => write!(
                f,
                "unsupported DPS root type {root_type}; declare amd64 or arm64 userspace"
            ),
            Self::DpsCandidates {
                root_type,
                candidates,
            } => write!(
                f,
                "DPS root type {root_type} requires exactly one candidate: {candidates:?}"
            ),
            Self::NoAuto { partition } => {
                write!(
                    f,
                    "DPS root candidate forbids automatic selection: {partition:?}"
                )
            }
        }
    }
}

impl core::error::Error for LookupError {}

/// A parsed table unsupported by Linux's direct-boot child-device profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectTableError {
    GptEntrySize { size: u32 },
}

impl fmt::Display for DirectTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GptEntrySize { size } => write!(
                f,
                "unsupported Linux direct-boot GPT entry size {size}; expected 128 bytes"
            ),
        }
    }
}

impl core::error::Error for DirectTableError {}

/// Checks kernel table support, not root selection or filesystem support.
///
/// Linux requires exactly 128-byte GPT entries; wider entries remain valid
/// generic parser facts. `None` passes this check, but is suitable only for a
/// caller's explicit whole-disk selector.
pub fn validate_linux_direct_table(table: &PartitionTable) -> Result<(), DirectTableError> {
    if let PartitionTable::Gpt(table) = table {
        if table.entry_size() != 128 {
            return Err(DirectTableError::GptEntrySize {
                size: table.entry_size(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableCopy {
    Primary,
    Backup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corruption {
    TruncatedField,
    MissingMbrSignature,
    MissingProtectiveMbr,
    InvalidProtectiveMbr,
    MissingGptSignature,
    InvalidHeader,
    InvalidHeaderPlacement,
    InvalidArrayPlacement,
    InvalidEntry,
    NilGuid,
    NonzeroReserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    HybridMbr,
    ExtendedMbr { slot: u8, partition_type: u8 },
    GptRevision { revision: u32 },
    GptEntryCount { count: u32 },
    GptEntrySize { size: u32 },
}

#[derive(Debug)]
pub enum Error<E = Infallible> {
    InvalidGeometry {
        byte_length: u64,
    },
    Io {
        offset: u64,
        source: E,
    },
    Corrupt(Corruption),
    Unsupported(Unsupported),
    HeaderCrc {
        copy: TableCopy,
    },
    ArrayCrc {
        copy: TableCopy,
    },
    ConflictingTables,
    BackupNotAtCapacity {
        backup_lba: u64,
        current_last_lba: u64,
    },
    OutOfRange {
        slot: u32,
    },
    Overlap {
        first_slot: u32,
        second_slot: u32,
    },
    DuplicateGuid {
        guid: Uuid,
        first_slot: u32,
        second_slot: u32,
    },
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGeometry { byte_length } => write!(
                f,
                "invalid 512-byte disk geometry: {byte_length} bytes (maximum 1 TiB)"
            ),
            Self::Io { offset, source } => {
                write!(f, "partition metadata I/O at byte {offset}: {source}")
            }
            Self::Corrupt(reason) => write!(f, "malformed partition table: {reason:?}"),
            Self::Unsupported(reason) => write!(f, "unsupported partition table: {reason:?}"),
            Self::HeaderCrc { copy } => write!(f, "{copy:?} GPT header CRC mismatch"),
            Self::ArrayCrc { copy } => write!(f, "{copy:?} GPT entry array CRC mismatch"),
            Self::ConflictingTables => f.write_str("primary and backup GPT tables conflict"),
            Self::BackupNotAtCapacity {
                backup_lba,
                current_last_lba,
            } => write!(
                f,
                "GPT backup at LBA {backup_lba}, expected current last LBA {current_last_lba}"
            ),
            Self::OutOfRange { slot } => write!(
                f,
                "partition slot {slot} has an empty, reversed or out-of-disk range"
            ),
            Self::Overlap {
                first_slot,
                second_slot,
            } => {
                write!(f, "partition slots {first_slot} and {second_slot} overlap")
            }
            Self::DuplicateGuid {
                guid,
                first_slot,
                second_slot,
            } => write!(
                f,
                "partition GUID {guid} repeats in slots {first_slot} and {second_slot}"
            ),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl<E> From<Corruption> for Error<E> {
    fn from(reason: Corruption) -> Self {
        Self::Corrupt(reason)
    }
}

/// Reads only bounded metadata from the caller's held source.
///
/// The std adapter leaves the cursor at the last metadata read; callers must
/// seek before reading filesystem data. A short read is an I/O error, never a
/// zero-filled sector or whole-disk result.
pub fn read_table<R: ReadAt + ?Sized>(
    source: &mut R,
    geometry: Geometry,
    mode: ReadMode,
) -> Result<PartitionTable, Error<R::Error>> {
    let mut mbr = [0; 512];
    read_at(source, geometry, 0, &mut mbr)?;
    let mut primary = [0; 512];
    if geometry.sectors() > 1 {
        read_at(source, geometry, SECTOR_SIZE, &mut primary)?;
    }
    let records = &mbr[446..510];
    let protective = records.chunks_exact(16).any(|record| record[4] == 0xee);
    let gpt_signature = &primary[..8] == b"EFI PART";
    let mbr_signature = mbr[510..] == [0x55, 0xaa];
    let meaningful = records
        .chunks_exact(16)
        .any(|record| record[4] != 0 || record[8..16].iter().any(|byte| *byte != 0));
    if !mbr_signature {
        if protective || gpt_signature || meaningful {
            return Err(Error::Corrupt(Corruption::MissingMbrSignature));
        }
        return Ok(PartitionTable::None);
    }
    if protective || gpt_signature {
        if !protective {
            return Err(Error::Corrupt(Corruption::MissingProtectiveMbr));
        }
        return read_gpt(source, geometry, mode, &mbr, primary).map(PartitionTable::Gpt);
    }
    if !meaningful {
        // A boot-sector trailer by itself is not evidence of a partition table.
        return Ok(PartitionTable::None);
    }
    read_mbr(&mbr, geometry).map(PartitionTable::Mbr)
}

fn read_mbr<E>(mbr: &[u8; 512], geometry: Geometry) -> Result<MbrTable, Error<E>> {
    let mut partitions: Vec<MbrPartition> = Vec::with_capacity(4);
    for (index, record) in mbr[446..510].chunks_exact(16).enumerate() {
        let slot = index as u8 + 1;
        let partition_type = record[4];
        let start = u64::from(le32(record, 8)?);
        let length = u64::from(le32(record, 12)?);
        if partition_type == 0 && start == 0 && length == 0 {
            continue;
        }
        if matches!(partition_type, 0x05 | 0x0f | 0x85) {
            return Err(Error::Unsupported(Unsupported::ExtendedMbr {
                slot,
                partition_type,
            }));
        }
        if partition_type == 0 || length == 0 {
            return Err(Error::Corrupt(Corruption::InvalidEntry));
        }
        let last = start.checked_add(length - 1).ok_or(Error::OutOfRange {
            slot: u32::from(slot),
        })?;
        let extent = checked_extent(start, last, 1, geometry.sectors() - 1, u32::from(slot))?;
        for previous in &partitions {
            if extent.overlaps(previous.extent) {
                return Err(Error::Overlap {
                    first_slot: u32::from(previous.slot),
                    second_slot: u32::from(slot),
                });
            }
        }
        partitions.push(MbrPartition {
            slot,
            partition_type,
            extent,
        });
    }
    Ok(MbrTable { partitions })
}

struct Header {
    bytes: [u8; 512],
    size: usize,
    alternate_lba: u64,
    disk_guid: Uuid,
    usable: Extent,
    array_lba: u64,
    entry_count: u32,
    entry_size: u32,
    array_crc: u32,
    reserved_sectors: u64,
}

fn read_gpt<R: ReadAt + ?Sized>(
    source: &mut R,
    geometry: Geometry,
    mode: ReadMode,
    mbr: &[u8; 512],
    primary_bytes: [u8; 512],
) -> Result<GptTable, Error<R::Error>> {
    let primary = parse_header(primary_bytes, 1, geometry, TableCopy::Primary)?;
    let backup_lba = primary.alternate_lba;
    if backup_lba <= 1 || backup_lba >= geometry.sectors() {
        return Err(Error::Corrupt(Corruption::InvalidHeaderPlacement));
    }
    let current_last_lba = geometry.sectors() - 1;
    let backup_placement = if backup_lba == current_last_lba {
        BackupPlacement::AtCapacity
    } else if mode == ReadMode::StrictImport {
        return Err(Error::BackupNotAtCapacity {
            backup_lba,
            current_last_lba,
        });
    } else {
        BackupPlacement::BeforeExpandedEnd {
            backup_lba,
            current_last_lba,
        }
    };
    validate_protective_mbr(mbr, backup_lba)?;
    let mut backup_bytes = [0; 512];
    read_at(
        source,
        geometry,
        backup_lba * SECTOR_SIZE,
        &mut backup_bytes,
    )?;
    let backup = parse_header(backup_bytes, backup_lba, geometry, TableCopy::Backup)?;
    if backup.alternate_lba != 1
        || primary.disk_guid != backup.disk_guid
        || primary.usable != backup.usable
        || primary.entry_count != backup.entry_count
        || primary.entry_size != backup.entry_size
        || primary.size != backup.size
        || primary.bytes[92..primary.size] != backup.bytes[92..backup.size]
    {
        return Err(Error::ConflictingTables);
    }
    let primary_end = primary
        .array_lba
        .checked_add(primary.reserved_sectors)
        .ok_or(Error::Corrupt(Corruption::InvalidArrayPlacement))?;
    let backup_end = backup
        .array_lba
        .checked_add(backup.reserved_sectors)
        .ok_or(Error::Corrupt(Corruption::InvalidArrayPlacement))?;
    if primary.array_lba < 2
        || primary_end > primary.usable.first_lba
        || backup.array_lba <= primary.usable.last_lba
        || backup_end > backup_lba
        || primary.usable.last_lba >= backup_lba
    {
        return Err(Error::Corrupt(Corruption::InvalidArrayPlacement));
    }
    let partitions = read_arrays(source, geometry, &primary, &backup)?;
    Ok(GptTable {
        disk_guid: primary.disk_guid,
        usable: primary.usable,
        backup_placement,
        entry_count: primary.entry_count,
        entry_size: primary.entry_size,
        partitions,
    })
}

fn validate_protective_mbr<E>(mbr: &[u8; 512], recorded_last_lba: u64) -> Result<(), Error<E>> {
    let mut protective_count = 0;
    for record in mbr[446..510].chunks_exact(16) {
        if record[4] == 0xee {
            protective_count += 1;
            let expected_length = recorded_last_lba.min(u64::from(u32::MAX));
            if le32(record, 8)? != 1 || u64::from(le32(record, 12)?) != expected_length {
                return Err(Error::Corrupt(Corruption::InvalidProtectiveMbr));
            }
        } else if record.iter().any(|byte| *byte != 0) {
            return Err(Error::Unsupported(Unsupported::HybridMbr));
        }
    }
    if protective_count != 1 {
        return Err(Error::Unsupported(Unsupported::HybridMbr));
    }
    Ok(())
}

fn parse_header<E>(
    bytes: [u8; 512],
    lba: u64,
    geometry: Geometry,
    copy: TableCopy,
) -> Result<Header, Error<E>> {
    if &bytes[..8] != b"EFI PART" {
        return Err(Error::Corrupt(Corruption::MissingGptSignature));
    }
    let revision = le32(&bytes, 8)?;
    if revision != 0x0001_0000 {
        return Err(Error::Unsupported(Unsupported::GptRevision { revision }));
    }
    let size = le32(&bytes, 12)? as usize;
    if !(92..=512).contains(&size) || le32(&bytes, 20)? != 0 {
        return Err(Error::Corrupt(Corruption::InvalidHeader));
    }
    if bytes[size..].iter().any(|byte| *byte != 0) {
        return Err(Error::Corrupt(Corruption::NonzeroReserved));
    }
    let mut crc = crc32_update(u32::MAX, &bytes[..16]);
    crc = crc32_update(crc, &[0; 4]);
    crc = crc32_update(crc, &bytes[20..size]);
    if !crc != le32(&bytes, 16)? {
        return Err(Error::HeaderCrc { copy });
    }
    if le64(&bytes, 24)? != lba {
        return Err(Error::Corrupt(Corruption::InvalidHeaderPlacement));
    }
    let disk_guid = guid(&bytes, 56)?;
    if disk_guid.is_nil() {
        return Err(Error::Corrupt(Corruption::NilGuid));
    }
    let usable = checked_extent(
        le64(&bytes, 40)?,
        le64(&bytes, 48)?,
        34,
        geometry.sectors() - 1,
        0,
    )?;
    let entry_count = le32(&bytes, 80)?;
    if entry_count == 0 || entry_count > MAX_GPT_ENTRIES {
        return Err(Error::Unsupported(Unsupported::GptEntryCount {
            count: entry_count,
        }));
    }
    let entry_size = le32(&bytes, 84)?;
    if !(128..=MAX_GPT_ENTRY_SIZE).contains(&entry_size) || !entry_size.is_power_of_two() {
        return Err(Error::Unsupported(Unsupported::GptEntrySize {
            size: entry_size,
        }));
    }
    // Both factors are bounded before multiplication, allocation or traversal.
    let array_bytes = u64::from(entry_count) * u64::from(entry_size);
    let reserved_sectors = array_bytes.max(16_384).div_ceil(SECTOR_SIZE);
    Ok(Header {
        alternate_lba: le64(&bytes, 32)?,
        disk_guid,
        usable,
        array_lba: le64(&bytes, 72)?,
        entry_count,
        entry_size,
        array_crc: le32(&bytes, 88)?,
        reserved_sectors,
        size,
        bytes,
    })
}

fn read_arrays<R: ReadAt + ?Sized>(
    source: &mut R,
    geometry: Geometry,
    primary: &Header,
    backup: &Header,
) -> Result<Vec<GptPartition>, Error<R::Error>> {
    let mut partitions: Vec<GptPartition> = Vec::with_capacity(primary.entry_count as usize);
    let mut primary_crc = u32::MAX;
    let mut backup_crc = u32::MAX;
    let mut conflicting = false;
    // Fixed buffers, independent of malicious declared entry stride/count.
    let mut first = [0; 128];
    let mut second = [0; 128];
    let primary_offset = primary.array_lba * SECTOR_SIZE;
    let backup_offset = backup.array_lba * SECTOR_SIZE;
    for index in 0..primary.entry_count {
        let entry_offset = u64::from(index) * u64::from(primary.entry_size);
        for chunk in 0..primary.entry_size / 128 {
            let offset = entry_offset + u64::from(chunk) * 128;
            read_at(source, geometry, primary_offset + offset, &mut first)?;
            read_at(source, geometry, backup_offset + offset, &mut second)?;
            primary_crc = crc32_update(primary_crc, &first);
            backup_crc = crc32_update(backup_crc, &second);
            conflicting |= first != second;
            if chunk != 0 {
                if first.iter().chain(&second).any(|byte| *byte != 0) {
                    return Err(Error::Corrupt(Corruption::NonzeroReserved));
                }
                continue;
            }
            let type_guid = guid(&first, 0)?;
            if type_guid.is_nil() {
                continue;
            }
            let slot = index + 1;
            let unique_guid = guid(&first, 16)?;
            if unique_guid.is_nil() {
                return Err(Error::Corrupt(Corruption::NilGuid));
            }
            let extent = checked_extent(
                le64(&first, 32)?,
                le64(&first, 40)?,
                primary.usable.first_lba,
                primary.usable.last_lba,
                slot,
            )?;
            let attributes = le64(&first, 48)?;
            if attributes & 0x0000_ffff_ffff_fff8 != 0 {
                return Err(Error::Corrupt(Corruption::NonzeroReserved));
            }
            for previous in &partitions {
                if previous.unique_guid == unique_guid {
                    return Err(Error::DuplicateGuid {
                        guid: unique_guid,
                        first_slot: previous.slot,
                        second_slot: slot,
                    });
                }
                if previous.extent.overlaps(extent) {
                    return Err(Error::Overlap {
                        first_slot: previous.slot,
                        second_slot: slot,
                    });
                }
            }
            partitions.push(GptPartition {
                slot,
                type_guid,
                unique_guid,
                extent,
                attributes,
            });
        }
    }
    if !primary_crc != primary.array_crc {
        return Err(Error::ArrayCrc {
            copy: TableCopy::Primary,
        });
    }
    if !backup_crc != backup.array_crc {
        return Err(Error::ArrayCrc {
            copy: TableCopy::Backup,
        });
    }
    if conflicting || primary.array_crc != backup.array_crc {
        return Err(Error::ConflictingTables);
    }
    Ok(partitions)
}

fn checked_extent<E>(
    first: u64,
    last: u64,
    minimum: u64,
    maximum: u64,
    slot: u32,
) -> Result<Extent, Error<E>> {
    if first < minimum || first > last || last > maximum {
        return Err(Error::OutOfRange { slot });
    }
    Ok(Extent {
        first_lba: first,
        last_lba: last,
    })
}

fn read_at<R: ReadAt + ?Sized>(
    source: &mut R,
    geometry: Geometry,
    offset: u64,
    bytes: &mut [u8],
) -> Result<(), Error<R::Error>> {
    let end = offset
        .checked_add(bytes.len() as u64)
        .ok_or(Error::Corrupt(Corruption::InvalidArrayPlacement))?;
    if end > geometry.byte_length {
        return Err(Error::Corrupt(Corruption::InvalidArrayPlacement));
    }
    source
        .read_exact_at(offset, bytes)
        .map_err(|source| Error::Io { offset, source })
}

fn field<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], Corruption> {
    bytes
        .get(start..start + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Corruption::TruncatedField)
}

fn le32(bytes: &[u8], start: usize) -> Result<u32, Corruption> {
    Ok(u32::from_le_bytes(field(bytes, start)?))
}

fn le64(bytes: &[u8], start: usize) -> Result<u64, Corruption> {
    Ok(u64::from_le_bytes(field(bytes, start)?))
}

fn guid(bytes: &[u8], start: usize) -> Result<Uuid, Corruption> {
    Ok(Uuid::from_bytes_le(field(bytes, start)?))
}

// GPT uses IEEE CRC-32 (not ext4's CRC-16 or CRC-32C). Like the existing
// ext4 checksum routine, keep a dependency-free reflected polynomial update.
fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};
    #[cfg(feature = "std")]
    use std::io::Cursor;

    use crate::{
        BackupPlacement, Corruption, DPS_ROOT_AMD64, DPS_ROOT_ARM64, DirectTableError, Error,
        Geometry, GptTable, LookupError, MAX_DISK_BYTES, MAX_GPT_ENTRY_SIZE,
        MAX_GPT_METADATA_BYTES, PartitionTable, ReadAt, ReadMode, TableCopy, Unsupported,
        crc32_update, guid, le32, le64, read_at, read_table, validate_linux_direct_table,
    };
    use uuid::Uuid;

    const ROOT_GUID: Uuid = Uuid::from_u128(0x01234567_89ab_cdef_0123_456789abcdef);
    const OTHER_GUID: Uuid = Uuid::from_u128(0xfedcba98_7654_3210_fedc_ba9876543210);
    const DATA_TYPE: Uuid = Uuid::from_u128(0x0fc63daf_8483_4772_8e79_3d69d8477de4);

    /// An actual in-memory source with a non-std, non-Display error. The corpus
    /// exercises the parser without requiring the std adapter's feature.
    struct SliceReader<'a>(&'a [u8]);

    #[derive(Debug, PartialEq, Eq)]
    struct ReadFailure {
        offset: u64,
        length: usize,
    }

    impl ReadAt for SliceReader<'_> {
        type Error = ReadFailure;

        fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            let bytes = usize::try_from(offset)
                .ok()
                .and_then(|start| start.checked_add(output.len()).map(|end| (start, end)))
                .and_then(|(start, end)| self.0.get(start..end))
                .ok_or(ReadFailure {
                    offset,
                    length: output.len(),
                })?;
            output.copy_from_slice(bytes);
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct Entry {
        slot: u32,
        kind: Uuid,
        unique: Uuid,
        first: u64,
        last: u64,
        attributes: u64,
    }

    fn root() -> Entry {
        Entry {
            slot: 1,
            kind: DPS_ROOT_AMD64,
            unique: ROOT_GUID,
            first: 40,
            last: 60,
            attributes: 0,
        }
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn header_crc(bytes: &mut [u8], lba: usize) {
        let start = lba * 512;
        let size = le32(bytes, start + 12).unwrap() as usize;
        put32(bytes, start + 16, 0);
        let crc = !crc32_update(u32::MAX, &bytes[start..start + size]);
        put32(bytes, start + 16, crc);
    }

    /// Entirely in-memory on-disk structures; no generated external fixtures.
    fn gpt(entries: &[Entry], count: u32, stride: u32) -> Vec<u8> {
        let array_bytes = count as usize * stride as usize;
        let reserved = array_bytes.max(16_384).div_ceil(512);
        let sectors = 2 * reserved + 256;
        let backup_lba = sectors - 1;
        let backup_array = backup_lba - reserved;
        let first_usable = (2 + reserved) as u64;
        let last_usable = (backup_array - 1) as u64;
        let mut bytes = vec![0; sectors * 512];
        bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
        bytes[450] = 0xee;
        put32(&mut bytes, 454, 1);
        put32(&mut bytes, 458, backup_lba as u32);
        for entry in entries {
            let offset = 2 * 512 + (entry.slot as usize - 1) * stride as usize;
            bytes[offset..offset + 16].copy_from_slice(&entry.kind.to_bytes_le());
            bytes[offset + 16..offset + 32].copy_from_slice(&entry.unique.to_bytes_le());
            put64(&mut bytes, offset + 32, entry.first);
            put64(&mut bytes, offset + 40, entry.last);
            put64(&mut bytes, offset + 48, entry.attributes);
        }
        bytes.copy_within(2 * 512..2 * 512 + array_bytes, backup_array * 512);
        let crc = !crc32_update(u32::MAX, &bytes[2 * 512..2 * 512 + array_bytes]);
        for (lba, alternate, array) in [(1, backup_lba, 2), (backup_lba, 1, backup_array)] {
            let start = lba * 512;
            bytes[start..start + 8].copy_from_slice(b"EFI PART");
            put32(&mut bytes, start + 8, 0x0001_0000);
            put32(&mut bytes, start + 12, 92);
            put64(&mut bytes, start + 24, lba as u64);
            put64(&mut bytes, start + 32, alternate as u64);
            put64(&mut bytes, start + 40, first_usable);
            put64(&mut bytes, start + 48, last_usable);
            bytes[start + 56..start + 72].copy_from_slice(&OTHER_GUID.to_bytes_le());
            put64(&mut bytes, start + 72, array as u64);
            put32(&mut bytes, start + 80, count);
            put32(&mut bytes, start + 84, stride);
            put32(&mut bytes, start + 88, crc);
            header_crc(&mut bytes, lba);
        }
        bytes
    }

    fn inspect(bytes: &[u8], mode: ReadMode) -> Result<PartitionTable, Error<ReadFailure>> {
        read_table(
            &mut SliceReader(bytes),
            Geometry::new(bytes.len() as u64).unwrap(),
            mode,
        )
    }

    fn table(bytes: &[u8]) -> GptTable {
        match inspect(bytes, ReadMode::StrictImport).unwrap() {
            PartitionTable::Gpt(table) => table,
            other => panic!("expected GPT, got {other:?}"),
        }
    }

    fn mbr(entries: &[(u8, u8, u32, u32)], sectors: usize) -> Vec<u8> {
        let mut bytes = vec![0; sectors * 512];
        bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
        for &(slot, kind, first, length) in entries {
            let offset = 446 + (slot as usize - 1) * 16;
            bytes[offset + 4] = kind;
            put32(&mut bytes, offset + 8, first);
            put32(&mut bytes, offset + 12, length);
        }
        bytes
    }

    fn recalculate_array_crc(bytes: &mut [u8], header_lba: usize) {
        let header = header_lba * 512;
        let array = le64(bytes, header + 72).unwrap() as usize * 512;
        let count = le32(bytes, header + 80).unwrap() as usize;
        let stride = le32(bytes, header + 84).unwrap() as usize;
        let crc = !crc32_update(u32::MAX, &bytes[array..array + count * stride]);
        put32(bytes, header + 88, crc);
        header_crc(bytes, header_lba);
    }

    #[test]
    fn ieee_crc_and_guid_byte_order_are_pinned() {
        assert_eq!(!crc32_update(u32::MAX, b"123456789"), 0xcbf4_3926);
        let amd64 = [
            0xe3, 0xbc, 0x68, 0x4f, 0xcd, 0xe8, 0xb1, 0x4d, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84,
            0xb7, 0x09,
        ];
        let arm64 = [
            0x45, 0xb0, 0x21, 0xb9, 0xf0, 0x1d, 0xc3, 0x41, 0xaf, 0x44, 0x4c, 0x6f, 0x28, 0x0d,
            0x3f, 0xae,
        ];
        assert_eq!(guid(&amd64, 0).unwrap(), DPS_ROOT_AMD64);
        assert_eq!(guid(&arm64, 0).unwrap(), DPS_ROOT_ARM64);
        assert_eq!(
            DPS_ROOT_AMD64.to_string(),
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
        );
        assert_eq!(
            DPS_ROOT_ARM64.to_string(),
            "b921b045-1df0-41c3-af44-4c6f280d3fae"
        );
    }

    #[test]
    fn geometry_rejects_empty_misaligned_and_oversized_streams() {
        for size in [0, 1, 511, 513, MAX_DISK_BYTES + 512, u64::MAX] {
            assert!(matches!(
                Geometry::new(size),
                Err(Error::InvalidGeometry { .. })
            ));
        }
        assert_eq!(Geometry::new(512).unwrap().sectors(), 1);
        assert_eq!(
            Geometry::new(MAX_DISK_BYTES).unwrap().byte_length(),
            MAX_DISK_BYTES
        );
    }

    #[test]
    fn empty_disk_and_boot_trailer_alone_are_not_partition_tables() {
        assert_eq!(
            inspect(&vec![0; 512], ReadMode::StrictImport).unwrap(),
            PartitionTable::None
        );
        let bytes = mbr(&[], 2);
        assert_eq!(
            inspect(&bytes, ReadMode::StrictImport).unwrap(),
            PartitionTable::None
        );
    }

    #[test]
    fn valid_gpt_has_disk_local_unique_identity_and_exact_extent() {
        let bytes = gpt(&[root()], 128, 128);
        let parsed = table(&bytes);
        let selected = parsed.find_unique_guid(ROOT_GUID).unwrap();
        assert_eq!(selected.slot(), 1);
        assert_eq!(selected.type_guid(), DPS_ROOT_AMD64);
        assert_eq!(selected.extent().first_lba(), 40);
        assert_eq!(selected.extent().last_lba(), 60);
        assert_eq!(selected.extent().byte_offset(), 40 * 512);
        assert_eq!(selected.extent().byte_length(), 21 * 512);
        assert_eq!(parsed.disk_guid(), OTHER_GUID);
        assert_eq!(parsed.usable().first_lba(), 34);
        assert_eq!(parsed.backup_placement(), BackupPlacement::AtCapacity);
        assert_eq!(parsed.entry_count(), 128);
        assert_eq!(parsed.entry_size(), 128);
        assert!(matches!(
            parsed.find_unique_guid(DPS_ROOT_AMD64),
            Err(LookupError::GuidNotFound { .. })
        ));
        // Exact copies may have identical GUIDs, but each lookup is disk-local.
        assert_eq!(table(&bytes).find_unique_guid(ROOT_GUID).unwrap(), selected);
    }

    #[test]
    fn declared_root_type_selects_userspace_not_host_or_kernel_architecture() {
        let arm = Entry {
            slot: 3,
            kind: DPS_ROOT_ARM64,
            unique: OTHER_GUID,
            first: 80,
            last: 100,
            ..root()
        };
        let parsed = table(&gpt(&[root(), arm], 128, 128));
        assert_eq!(
            parsed
                .select_dps_root(DPS_ROOT_AMD64)
                .unwrap()
                .unique_guid(),
            ROOT_GUID
        );
        assert_eq!(
            parsed
                .select_dps_root(DPS_ROOT_ARM64)
                .unwrap()
                .unique_guid(),
            OTHER_GUID
        );
        assert!(matches!(
            parsed.select_dps_root(DATA_TYPE),
            Err(LookupError::UnsupportedRootType { .. })
        ));
    }

    #[test]
    fn auto_zero_and_multiple_candidates_return_complete_diagnostics() {
        let empty = table(&gpt(&[], 128, 128));
        assert!(matches!(empty.select_dps_root(DPS_ROOT_AMD64),
            Err(LookupError::DpsCandidates { candidates, .. }) if candidates.is_empty()));
        let second = Entry {
            slot: 128,
            unique: OTHER_GUID,
            first: 80,
            last: 100,
            ..root()
        };
        let parsed = table(&gpt(&[root(), second], 128, 128));
        match parsed.select_dps_root(DPS_ROOT_AMD64) {
            Err(LookupError::DpsCandidates { candidates, .. }) => {
                assert_eq!(candidates.len(), 2);
                assert_eq!(candidates[0].unique_guid(), ROOT_GUID);
                assert_eq!(candidates[1].slot(), 128);
                assert_eq!(candidates[1].extent().first_lba(), 80);
            }
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn explicit_guid_allows_generic_data_without_auto_inference() {
        let parsed = table(&gpt(
            &[Entry {
                kind: DATA_TYPE,
                ..root()
            }],
            128,
            128,
        ));
        assert_eq!(
            parsed.find_unique_guid(ROOT_GUID).unwrap().type_guid(),
            DATA_TYPE
        );
        assert_eq!(parsed.dps_candidates(DPS_ROOT_AMD64).count(), 0);
    }

    #[test]
    fn dps_flags_are_reported_and_no_auto_does_not_hide_an_ambiguous_candidate() {
        let entry = Entry {
            attributes: (1 << 63) | (1 << 60) | (1 << 59),
            ..root()
        };
        let parsed = table(&gpt(&[entry], 128, 128));
        let selected = parsed.find_unique_guid(ROOT_GUID).unwrap();
        assert!(selected.no_auto());
        assert!(selected.read_only());
        assert!(selected.growfs());
        assert_eq!(selected.attributes(), entry.attributes);
        assert!(matches!(
            parsed.select_dps_root(DPS_ROOT_AMD64),
            Err(LookupError::NoAuto { .. })
        ));
        let second = Entry {
            slot: 2,
            unique: OTHER_GUID,
            first: 80,
            last: 90,
            ..root()
        };
        let parsed = table(&gpt(&[entry, second], 128, 128));
        assert!(matches!(parsed.select_dps_root(DPS_ROOT_AMD64),
            Err(LookupError::DpsCandidates { candidates, .. }) if candidates.len() == 2));
    }

    #[test]
    fn duplicate_and_nil_unique_guids_are_rejected() {
        let duplicate = Entry {
            slot: 2,
            first: 80,
            last: 100,
            ..root()
        };
        assert!(matches!(
            inspect(&gpt(&[root(), duplicate], 128, 128), ReadMode::StrictImport),
            Err(Error::DuplicateGuid {
                first_slot: 1,
                second_slot: 2,
                ..
            })
        ));
        assert!(matches!(
            inspect(
                &gpt(
                    &[Entry {
                        unique: Uuid::nil(),
                        ..root()
                    }],
                    128,
                    128
                ),
                ReadMode::StrictImport
            ),
            Err(Error::Corrupt(Corruption::NilGuid))
        ));
    }

    #[test]
    fn inclusive_ranges_allow_adjacency_but_not_overlap_or_outside_usable_space() {
        let adjacent = Entry {
            slot: 2,
            unique: OTHER_GUID,
            first: 61,
            last: 80,
            ..root()
        };
        assert_eq!(
            table(&gpt(&[root(), adjacent], 128, 128))
                .partitions()
                .len(),
            2
        );
        let overlapping = Entry {
            first: 60,
            ..adjacent
        };
        assert!(matches!(
            inspect(
                &gpt(&[root(), overlapping], 128, 128),
                ReadMode::StrictImport
            ),
            Err(Error::Overlap {
                first_slot: 1,
                second_slot: 2
            })
        ));
        for (first, last) in [(0, 60), (33, 60), (60, 40), (40, u64::MAX)] {
            assert!(matches!(
                inspect(
                    &gpt(
                        &[Entry {
                            first,
                            last,
                            ..root()
                        }],
                        128,
                        128
                    ),
                    ReadMode::StrictImport
                ),
                Err(Error::OutOfRange { slot: 1 })
            ));
        }
        assert_eq!(
            table(&gpt(
                &[Entry {
                    first: 34,
                    last: 34,
                    ..root()
                }],
                128,
                128
            ))
            .partitions()[0]
                .extent()
                .byte_length(),
            512
        );
    }

    #[test]
    fn both_header_crcs_are_required_without_recovery_fallback() {
        for (lba, copy) in [(1, TableCopy::Primary), (319, TableCopy::Backup)] {
            let mut bytes = gpt(&[root()], 128, 128);
            bytes[lba * 512 + 56] ^= 1;
            assert!(matches!(inspect(&bytes, ReadMode::StrictImport),
                Err(Error::HeaderCrc { copy: actual }) if actual == copy));
        }
    }

    #[test]
    fn both_array_crcs_are_required_and_padding_is_excluded() {
        for copy in [TableCopy::Primary, TableCopy::Backup] {
            let mut bytes = gpt(&[root()], 127, 128);
            let header = if copy == TableCopy::Primary {
                1
            } else {
                bytes.len() / 512 - 1
            };
            let array = le64(&bytes, header * 512 + 72).unwrap() as usize * 512;
            // Name bytes do not change selector structure but are CRC-covered.
            bytes[array + 56] ^= 1;
            assert!(matches!(inspect(&bytes, ReadMode::StrictImport),
                Err(Error::ArrayCrc { copy: actual }) if actual == copy));
        }
        let mut bytes = gpt(&[root()], 127, 128);
        let backup = bytes.len() / 512 - 1;
        for header in [1, backup] {
            let array = le64(&bytes, header * 512 + 72).unwrap() as usize * 512;
            bytes[array + 127 * 128] = 0xff;
        }
        assert_eq!(table(&bytes).partitions().len(), 1);
    }

    #[test]
    fn independently_valid_but_conflicting_arrays_and_headers_fail() {
        let mut bytes = gpt(&[root()], 128, 128);
        let backup = bytes.len() / 512 - 1;
        let array = le64(&bytes, backup * 512 + 72).unwrap() as usize * 512;
        bytes[array + 56] = b'x';
        recalculate_array_crc(&mut bytes, backup);
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::ConflictingTables)
        ));
        let mut bytes = gpt(&[root()], 128, 128);
        put64(&mut bytes, backup * 512 + 48, 200);
        header_crc(&mut bytes, backup);
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::ConflictingTables)
        ));
    }

    #[test]
    fn malformed_backup_is_rejected_even_when_primary_is_valid() {
        let original = gpt(&[root()], 128, 128);
        let backup = original.len() / 512 - 1;
        for (offset, value) in [(24, 1), (32, 2), (72, 2)] {
            let mut bytes = original.clone();
            put64(&mut bytes, backup * 512 + offset, value);
            header_crc(&mut bytes, backup);
            assert!(inspect(&bytes, ReadMode::StrictImport).is_err());
        }
        let mut bytes = original;
        bytes[backup * 512] = 0;
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::MissingGptSignature))
        ));
    }

    #[test]
    fn growth_policy_keeps_original_backup_but_never_ignores_its_corruption() {
        let mut bytes = gpt(&[root()], 128, 128);
        let old_last = bytes.len() / 512 - 1;
        bytes.resize(bytes.len() + 64 * 512, 0);
        assert!(matches!(inspect(&bytes, ReadMode::StrictImport),
            Err(Error::BackupNotAtCapacity { backup_lba, current_last_lba })
                if backup_lba == old_last as u64 && current_last_lba == old_last as u64 + 64));
        match inspect(&bytes, ReadMode::GuestBoot).unwrap() {
            PartitionTable::Gpt(parsed) => {
                assert_eq!(
                    parsed.backup_placement(),
                    BackupPlacement::BeforeExpandedEnd {
                        backup_lba: old_last as u64,
                        current_last_lba: old_last as u64 + 64,
                    }
                );
                assert_eq!(
                    parsed
                        .find_unique_guid(ROOT_GUID)
                        .unwrap()
                        .extent()
                        .last_lba(),
                    60
                );
            }
            other => panic!("expected GPT, got {other:?}"),
        }
        bytes[old_last * 512 + 56] ^= 1;
        assert!(matches!(
            inspect(&bytes, ReadMode::GuestBoot),
            Err(Error::HeaderCrc {
                copy: TableCopy::Backup
            })
        ));
    }

    #[test]
    fn guest_mode_rejects_truncated_capacity_and_conflicting_original_backup() {
        let mut bytes = gpt(&[root()], 128, 128);
        bytes.truncate(bytes.len() - 512);
        assert!(matches!(
            inspect(&bytes, ReadMode::GuestBoot),
            Err(Error::Corrupt(Corruption::InvalidHeaderPlacement))
        ));
        let mut bytes = gpt(&[root()], 128, 128);
        let backup = bytes.len() / 512 - 1;
        bytes.resize(bytes.len() + 512, 0);
        put64(&mut bytes, backup * 512 + 48, 200);
        header_crc(&mut bytes, backup);
        assert!(matches!(
            inspect(&bytes, ReadMode::GuestBoot),
            Err(Error::ConflictingTables)
        ));
    }

    #[test]
    fn gpt_entry_count_and_stride_are_bounded_before_traversal() {
        for count in [0, 129, u32::MAX] {
            let mut bytes = gpt(&[root()], 128, 128);
            put32(&mut bytes, 512 + 80, count);
            header_crc(&mut bytes, 1);
            assert!(matches!(inspect(&bytes, ReadMode::StrictImport),
                Err(Error::Unsupported(Unsupported::GptEntryCount { count: actual })) if actual == count));
        }
        for size in [0, 64, 129, 384, MAX_GPT_ENTRY_SIZE * 2, u32::MAX] {
            let mut bytes = gpt(&[root()], 128, 128);
            put32(&mut bytes, 512 + 84, size);
            header_crc(&mut bytes, 1);
            assert!(matches!(inspect(&bytes, ReadMode::StrictImport),
                Err(Error::Unsupported(Unsupported::GptEntrySize { size: actual })) if actual == size));
        }
        assert_eq!(MAX_GPT_METADATA_BYTES, 512 * 1024);
    }

    #[test]
    fn wider_entry_stride_preserves_slots_and_checks_reserved_extensions() {
        let entry = Entry {
            slot: 4,
            first: 80,
            last: 100,
            ..root()
        };
        let mut bytes = gpt(&[entry], 128, 256);
        let parsed = table(&bytes);
        assert_eq!(parsed.entry_size(), 256);
        assert_eq!(parsed.find_unique_guid(ROOT_GUID).unwrap().slot(), 4);
        // Fourth entry's extension, not a phantom fifth 128-byte entry.
        bytes[2 * 512 + 3 * 256 + 128] = 1;
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::NonzeroReserved))
        ));
        let max_entry = Entry {
            first: 1030,
            last: 1040,
            ..root()
        };
        assert_eq!(
            table(&gpt(&[max_entry], 128, MAX_GPT_ENTRY_SIZE)).entry_size(),
            MAX_GPT_ENTRY_SIZE
        );
    }

    #[test]
    fn array_placements_reject_header_data_overlap_and_integer_overflow() {
        for array_lba in [0, 1, 33, u64::MAX] {
            let mut bytes = gpt(&[root()], 128, 128);
            put64(&mut bytes, 512 + 72, array_lba);
            header_crc(&mut bytes, 1);
            assert!(matches!(
                inspect(&bytes, ReadMode::StrictImport),
                Err(Error::Corrupt(Corruption::InvalidArrayPlacement))
            ));
        }
        let mut bytes = gpt(&[root()], 1, 128);
        // Even a one-entry table needs the minimum 16 KiB reservation.
        put64(&mut bytes, 512 + 40, 3);
        header_crc(&mut bytes, 1);
        assert!(inspect(&bytes, ReadMode::StrictImport).is_err());
    }

    #[test]
    fn reserved_gpt_attribute_bits_fail_but_type_specific_flags_survive() {
        for bit in [3, 47] {
            assert!(matches!(
                inspect(
                    &gpt(
                        &[Entry {
                            attributes: 1 << bit,
                            ..root()
                        }],
                        128,
                        128
                    ),
                    ReadMode::StrictImport
                ),
                Err(Error::Corrupt(Corruption::NonzeroReserved))
            ));
        }
        let attributes = 7 | (1 << 48) | (1 << 63);
        assert_eq!(
            table(&gpt(
                &[Entry {
                    attributes,
                    ..root()
                }],
                128,
                128
            ))
            .find_unique_guid(ROOT_GUID)
            .unwrap()
            .attributes(),
            attributes
        );
    }

    #[test]
    fn protective_hybrid_missing_and_malformed_mbr_fail_closed() {
        let original = gpt(&[root()], 128, 128);
        let mut bytes = original.clone();
        bytes[466] = 0x83;
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Unsupported(Unsupported::HybridMbr))
        ));
        let mut bytes = original.clone();
        bytes[446..510].fill(0);
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::MissingProtectiveMbr))
        ));
        for (offset, value) in [(454, 2), (458, 1)] {
            let mut bytes = original.clone();
            put32(&mut bytes, offset, value);
            assert!(matches!(
                inspect(&bytes, ReadMode::StrictImport),
                Err(Error::Corrupt(Corruption::InvalidProtectiveMbr))
            ));
        }
        let mut bytes = original;
        bytes[510] = 0;
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::MissingMbrSignature))
        ));
    }

    #[test]
    fn invalid_gpt_revision_header_size_and_reserved_bytes_fail() {
        let original = gpt(&[root()], 128, 128);
        let mut bytes = original.clone();
        put32(&mut bytes, 512 + 8, 0x0002_0000);
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Unsupported(Unsupported::GptRevision { .. }))
        ));
        for size in [0, 91, 513, u32::MAX] {
            let mut bytes = original.clone();
            put32(&mut bytes, 512 + 12, size);
            assert!(matches!(
                inspect(&bytes, ReadMode::StrictImport),
                Err(Error::Corrupt(Corruption::InvalidHeader))
            ));
        }
        let mut bytes = original.clone();
        bytes[512 + 20] = 1;
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::InvalidHeader))
        ));
        let mut bytes = original;
        bytes[512 + 511] = 1;
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::NonzeroReserved))
        ));
    }

    #[test]
    fn mbr_slots_are_one_based_and_holes_are_never_compacted() {
        for entries in [
            vec![(1, 0x83, 1, 20), (4, 0x83, 50, 10)],
            vec![(4, 0x83, 50, 10)],
        ] {
            let bytes = mbr(&entries, 100);
            match inspect(&bytes, ReadMode::StrictImport).unwrap() {
                PartitionTable::Mbr(parsed) => {
                    assert_eq!(parsed.partitions().len(), entries.len());
                    let fourth = parsed.find_primary_slot(4).unwrap();
                    assert_eq!(fourth.slot(), 4);
                    assert_eq!(fourth.partition_type(), 0x83);
                    assert_eq!(fourth.extent().first_lba(), 50);
                    assert_eq!(fourth.extent().last_lba(), 59);
                    assert!(matches!(
                        parsed.find_primary_slot(2),
                        Err(LookupError::EmptyPrimarySlot { slot: 2 })
                    ));
                    for slot in [0, 5, 255] {
                        assert!(matches!(
                            parsed.find_primary_slot(slot),
                            Err(LookupError::InvalidPrimarySlot { .. })
                        ));
                    }
                }
                other => panic!("expected MBR, got {other:?}"),
            }
        }
    }

    #[test]
    fn mbr_extended_containers_are_unsupported_without_ebr_reads() {
        for kind in [0x05, 0x0f, 0x85] {
            let bytes = mbr(&[(4, kind, 10, 20)], 100);
            assert!(matches!(inspect(&bytes, ReadMode::StrictImport),
                Err(Error::Unsupported(Unsupported::ExtendedMbr { slot: 4, partition_type })) if partition_type == kind));
        }
    }

    #[test]
    fn mbr_overlap_empty_and_out_of_disk_ranges_fail() {
        assert!(matches!(
            inspect(
                &mbr(&[(1, 0x83, 1, 20), (4, 0x83, 20, 10)], 100),
                ReadMode::StrictImport
            ),
            Err(Error::Overlap {
                first_slot: 1,
                second_slot: 4
            })
        ));
        for (first, length) in [(0, 10), (99, 2), (u32::MAX, u32::MAX)] {
            assert!(matches!(
                inspect(
                    &mbr(&[(1, 0x83, first, length)], 100),
                    ReadMode::StrictImport
                ),
                Err(Error::OutOfRange { slot: 1 })
            ));
        }
        assert!(matches!(
            inspect(&mbr(&[(1, 0x83, 1, 0)], 100), ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::InvalidEntry))
        ));
        assert!(matches!(
            inspect(&mbr(&[(1, 0, 1, 10)], 100), ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::InvalidEntry))
        ));
        let mut bytes = mbr(&[(1, 0x83, 1, 10)], 100);
        bytes[511] = 0;
        assert!(matches!(
            inspect(&bytes, ReadMode::StrictImport),
            Err(Error::Corrupt(Corruption::MissingMbrSignature))
        ));
    }

    #[test]
    fn direct_table_policy_accepts_none_mbr_and_only_standard_width_gpt() {
        assert_eq!(validate_linux_direct_table(&PartitionTable::None), Ok(()));
        let primary = inspect(&mbr(&[(4, 0x83, 50, 10)], 100), ReadMode::StrictImport).unwrap();
        assert_eq!(validate_linux_direct_table(&primary), Ok(()));
        for stride in [128, 256, 512, 1024, 2048, MAX_GPT_ENTRY_SIZE] {
            for entries in [vec![], vec![root()]] {
                let bytes = gpt(&entries, 1, stride);
                for mode in [ReadMode::StrictImport, ReadMode::GuestBoot] {
                    let parsed = inspect(&bytes, mode).unwrap();
                    match &parsed {
                        PartitionTable::Gpt(table) => {
                            assert_eq!(table.entry_size(), stride);
                            assert_eq!(table.partitions().len(), entries.len());
                        }
                        other => panic!("expected GPT, got {other:?}"),
                    }
                    assert_eq!(
                        validate_linux_direct_table(&parsed),
                        if stride == 128 {
                            Ok(())
                        } else {
                            Err(DirectTableError::GptEntrySize { size: stride })
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn read_at_preserves_custom_errors_and_checks_geometry_before_source() {
        let bytes = gpt(&[root()], 128, 128);
        let geometry = Geometry::new(bytes.len() as u64).unwrap();
        for (length, offset) in [
            (0, 0),
            (511, 0),
            (1023, 512),
            (bytes.len() - 1, bytes.len() as u64 - 512),
        ] {
            let mut truncated = SliceReader(&bytes[..length]);
            let source: &mut dyn ReadAt<Error = ReadFailure> = &mut truncated;
            assert!(matches!(
                read_table(source, geometry, ReadMode::StrictImport),
                Err(Error::Io {
                    offset: actual,
                    source: ReadFailure { offset: source_offset, length: 512 },
                }) if actual == offset && source_offset == offset
            ));
        }

        let mut source = SliceReader(&bytes);
        let bounded = Geometry::new(512).unwrap();
        let mut output = [0; 512];
        read_at(&mut source, bounded, 0, &mut output).unwrap();
        assert_eq!(output, bytes[..512]);
        for offset in [1, 512, u64::MAX] {
            assert!(matches!(
                read_at(&mut source, bounded, offset, &mut output),
                Err(Error::Corrupt(Corruption::InvalidArrayPlacement))
            ));
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn std_adapter_seeks_existing_cursor_and_held_file() {
        let bytes = gpt(&[root()], 128, 128);
        let mut cursor = Cursor::new(&bytes);
        cursor.set_position(bytes.len() as u64);
        assert_eq!(
            read_table(
                &mut cursor,
                Geometry::new(bytes.len() as u64).unwrap(),
                ReadMode::StrictImport,
            )
            .unwrap(),
            inspect(&bytes, ReadMode::StrictImport).unwrap(),
        );

        let mut file = std::fs::File::open(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
        )
        .unwrap();
        let mut output = [0; 32];
        let source: &mut dyn ReadAt<Error = std::io::Error> = &mut file;
        source.read_exact_at(17, &mut output).unwrap();
        assert_eq!(output, include_bytes!("lib.rs")[17..49]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn short_metadata_reads_are_errors_not_synthetic_zeros() {
        let bytes = gpt(&[root()], 128, 128);
        let geometry = Geometry::new(bytes.len() as u64).unwrap();
        for length in [0, 511, 1023, bytes.len() - 1] {
            let error = read_table(
                &mut Cursor::new(&bytes[..length]),
                geometry,
                ReadMode::StrictImport,
            )
            .unwrap_err();
            assert!(
                matches!(error, Error::Io { source, .. } if source.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        }
    }
}
