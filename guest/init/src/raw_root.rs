//! Pure disk-local resolution of a bootstrap-selected opaque root.
//!
//! ```text
//! /sys/block/*/serial == "silo-root" (exactly one)
//!   -> held parent FD -> shared GuestBoot table parse + Linux table policy
//!   -> selector: whole disk | unique GPT GUID | original MBR primary slot
//!   -> kernel child *under that parent*: partition number, start, size, dev
//!   -> ext4 mount, mounted st_dev == resolved device
//! ```
//!
//! There is no global PARTUUID lookup, disk-order default, synthesized child
//! name or second table parser. Identical identities on other attachments are
//! irrelevant: only the named attachment's own table is consulted.

use alloc::vec::Vec;
use disk_partition::{Extent, PartitionTable, SECTOR_SIZE};
use rootfs_spec::{RawDeviceExpectation, RawSelector, RawSerial};

use crate::root_checks::{decimal, serial_matches, DeviceFacts};

/// Finds the single whole block device carrying the root attachment serial.
#[derive(Default)]
pub struct RootDiscovery {
    found: Option<Vec<u8>>,
}

impl RootDiscovery {
    pub fn observe(&mut self, name: &[u8], serial: &[u8]) -> Result<(), &'static str> {
        if !serial_matches(serial, RawSerial::Root.as_str().as_bytes()) {
            return Ok(());
        }
        if self.found.is_some() {
            return Err("raw: duplicate root attachment serial");
        }
        self.found = Some(name.to_vec());
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, &'static str> {
        self.found.ok_or("raw: missing root attachment serial")
    }
}

/// The table's facts for the selected partition, in 512-byte sectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionExpectation {
    /// Linux partition number: the one-based table slot, never compacted.
    pub number: u32,
    pub start_sector: u64,
    pub sectors: u64,
}

impl PartitionExpectation {
    fn from_extent(number: u32, extent: Extent) -> Self {
        Self {
            number,
            start_sector: extent.first_lba(),
            sectors: extent.byte_length() / SECTOR_SIZE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    WholeDisk,
    Partition(PartitionExpectation),
}

/// Applies the Linux direct-boot table policy, then requires the selector and
/// the parsed table kind to agree. A parse failure never reaches this point,
/// so a corrupt or unsupported table can never become a whole-disk root.
pub fn select(table: &PartitionTable, selector: RawSelector) -> Result<Selection, &'static str> {
    disk_partition::validate_linux_direct_table(table)
        .map_err(|_| "raw: partition table unsupported by the direct-boot kernel profile")?;
    match (selector, table) {
        (RawSelector::WholeDisk, PartitionTable::None) => Ok(Selection::WholeDisk),
        (RawSelector::WholeDisk, _) => Err("raw: whole-disk root carries a partition table"),
        (RawSelector::GptPartition { guid }, PartitionTable::Gpt(table)) => {
            let partition = table
                .find_unique_guid(uuid::Uuid::from_bytes(guid.bytes()))
                .map_err(|_| "raw: selected GPT partition GUID is absent")?;
            Ok(Selection::Partition(PartitionExpectation::from_extent(
                partition.slot(),
                partition.extent(),
            )))
        }
        (RawSelector::GptPartition { .. }, _) => Err("raw: GPT selector without a GPT"),
        (RawSelector::MbrPartition { number }, PartitionTable::Mbr(table)) => {
            let partition = table
                .find_primary_slot(number.get())
                .map_err(|_| "raw: selected MBR primary slot is empty")?;
            Ok(Selection::Partition(PartitionExpectation::from_extent(
                u32::from(partition.slot()),
                partition.extent(),
            )))
        }
        (RawSelector::MbrPartition { .. }, _) => Err("raw: MBR selector without an MBR"),
    }
}

/// The measured attachment must be exactly the bootstrap's effective launch
/// attachment, before any of its bytes are interpreted.
pub fn check_parent(
    expected: &RawDeviceExpectation,
    actual: DeviceFacts,
) -> Result<(), &'static str> {
    if expected.length_bytes != actual.length_bytes {
        return Err("raw: root attachment length mismatch");
    }
    if expected.logical_sector_size != actual.logical_sector_size {
        return Err("raw: root attachment sector size mismatch");
    }
    if expected.read_only != actual.read_only {
        return Err("raw: root attachment access mismatch");
    }
    Ok(())
}

/// Selects the kernel child of the root attachment by its sysfs `partition`
/// number. Children are enumerated under the parent's own sysfs directory.
pub struct ChildSearch {
    number: u32,
    found: Option<Vec<u8>>,
}

impl ChildSearch {
    pub fn new(number: u32) -> Self {
        Self {
            number,
            found: None,
        }
    }

    /// `partition` is the raw sysfs attribute of one child directory.
    pub fn observe(&mut self, name: &[u8], partition: &[u8]) -> Result<(), &'static str> {
        if decimal(partition)? != u64::from(self.number) {
            return Ok(());
        }
        if self.found.is_some() {
            return Err("raw: duplicate kernel partition number");
        }
        self.found = Some(name.to_vec());
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, &'static str> {
        self.found
            .ok_or("raw: kernel exposes no selected partition under the root attachment")
    }
}

/// Kernel facts for the selected child: sysfs `partition` and `start`, plus
/// the same block-special, sysfs and ioctl measurement used for the parent.
#[derive(Clone, Copy, Debug)]
pub struct ChildFacts {
    pub number: u32,
    pub start_sector: u64,
    pub device: DeviceFacts,
}

/// The kernel child must be the table's partition: same slot, same 512-byte
/// extent, distinct device number, inherited geometry and access.
pub fn check_child(
    expected: &RawDeviceExpectation,
    parent: DeviceFacts,
    selected: PartitionExpectation,
    child: ChildFacts,
) -> Result<(), &'static str> {
    if child.number != selected.number {
        return Err("raw: kernel partition number disagrees with the table");
    }
    let table_bytes = selected
        .sectors
        .checked_mul(SECTOR_SIZE)
        .ok_or("raw: partition extent overflow")?;
    if child.start_sector != selected.start_sector || child.device.length_bytes != table_bytes {
        return Err("raw: kernel partition extent disagrees with the table");
    }
    let end = selected
        .start_sector
        .checked_add(selected.sectors)
        .and_then(|sectors| sectors.checked_mul(SECTOR_SIZE))
        .ok_or("raw: partition extent overflow")?;
    if selected.sectors == 0 || end > parent.length_bytes {
        return Err("raw: partition extent outside the root attachment");
    }
    if child.device.number == parent.number {
        return Err("raw: partition aliases its root attachment");
    }
    if child.device.logical_sector_size != expected.logical_sector_size {
        return Err("raw: partition sector size mismatch");
    }
    if child.device.read_only != expected.read_only {
        return Err("raw: partition access mismatch");
    }
    Ok(())
}

/// ext4's `statfs` magic.
pub const EXT4_SUPER_MAGIC: u64 = 0xef53;

/// The mounted root must be served by the resolved device as ext4.
pub fn check_mounted_root(
    filesystem_magic: u64,
    mounted: (u32, u32),
    resolved: DeviceFacts,
) -> Result<(), &'static str> {
    if filesystem_magic != EXT4_SUPER_MAGIC {
        return Err("raw: mounted root is not ext4");
    }
    if mounted != (resolved.number.major, resolved.number.minor) {
        return Err("raw: mounted root device identity mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::raw_root::{
        check_child, check_mounted_root, check_parent, select, ChildFacts, ChildSearch,
        PartitionExpectation, RootDiscovery, Selection, EXT4_SUPER_MAGIC,
    };
    use crate::root_checks::DeviceFacts;
    use disk_partition::{read_table, Geometry, PartitionTable, ReadAt, ReadMode};
    use rootfs_spec::{
        MbrPartitionNumber, PartitionGuid, RawDeviceExpectation, RawSelector, RawSerial,
    };
    use std::vec;
    use std::vec::Vec;

    const DISK_SECTORS: u64 = 2048;
    const ROOT_GUID: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    const OTHER_GUID: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    /// Linux filesystem data type GUID, canonical bytes.
    const LINUX_DATA: [u8; 16] = [
        0x0f, 0xc6, 0x3d, 0xaf, 0x84, 0x83, 0x47, 0x72, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ];

    struct Image(Vec<u8>);

    impl ReadAt for Image {
        type Error = ();

        fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), ()> {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let bytes = self.0.get(start..start + output.len()).ok_or(())?;
            output.copy_from_slice(bytes);
            Ok(())
        }
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }

    /// GPT's on-disk mixed-endian GUID encoding of canonical bytes.
    fn mixed_endian(guid: [u8; 16]) -> [u8; 16] {
        let mut out = guid;
        out[..4].reverse();
        out[4..6].reverse();
        out[6..8].reverse();
        out
    }

    #[derive(Clone, Copy)]
    struct Entry {
        slot: usize,
        unique: [u8; 16],
        first: u64,
        last: u64,
    }

    fn protective_mbr(image: &mut [u8], sectors: u64) {
        let record = &mut image[446..462];
        record[4] = 0xee;
        record[8..12].copy_from_slice(&1u32.to_le_bytes());
        record[12..16].copy_from_slice(&((sectors - 1) as u32).to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xaa;
    }

    fn gpt_header(image: &mut [u8], lba: u64, alternate: u64, entries_lba: u64, array_crc: u32) {
        let start = lba as usize * 512;
        let header = &mut image[start..start + 92];
        header[..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[24..32].copy_from_slice(&lba.to_le_bytes());
        header[32..40].copy_from_slice(&alternate.to_le_bytes());
        header[40..48].copy_from_slice(&34u64.to_le_bytes());
        header[48..56].copy_from_slice(&(DISK_SECTORS - 34).to_le_bytes());
        header[56..72].copy_from_slice(&mixed_endian(OTHER_GUID));
        header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        header[80..84].copy_from_slice(&128u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        header[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let crc = crc32(header);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
    }

    /// A standards-shaped GPT built here, independently of the parser.
    fn gpt(entries: &[Entry]) -> Vec<u8> {
        let mut image = vec![0; DISK_SECTORS as usize * 512];
        protective_mbr(&mut image, DISK_SECTORS);
        let mut array = vec![0u8; 128 * 128];
        for entry in entries {
            let at = (entry.slot - 1) * 128;
            array[at..at + 16].copy_from_slice(&mixed_endian(LINUX_DATA));
            array[at + 16..at + 32].copy_from_slice(&mixed_endian(entry.unique));
            array[at + 32..at + 40].copy_from_slice(&entry.first.to_le_bytes());
            array[at + 40..at + 48].copy_from_slice(&entry.last.to_le_bytes());
        }
        let array_crc = crc32(&array);
        image[1024..1024 + array.len()].copy_from_slice(&array);
        let backup_entries = DISK_SECTORS - 33;
        let backup_at = backup_entries as usize * 512;
        image[backup_at..backup_at + array.len()].copy_from_slice(&array);
        gpt_header(&mut image, 1, DISK_SECTORS - 1, 2, array_crc);
        gpt_header(&mut image, DISK_SECTORS - 1, 1, backup_entries, array_crc);
        image
    }

    fn mbr(records: &[(usize, u8, u32, u32)]) -> Vec<u8> {
        let mut image = vec![0; DISK_SECTORS as usize * 512];
        for (slot, kind, start, length) in records {
            let record = &mut image[446 + (slot - 1) * 16..446 + slot * 16];
            record[4] = *kind;
            record[8..12].copy_from_slice(&start.to_le_bytes());
            record[12..16].copy_from_slice(&length.to_le_bytes());
        }
        image[510] = 0x55;
        image[511] = 0xaa;
        image
    }

    fn table(image: Vec<u8>) -> PartitionTable {
        let length = image.len() as u64;
        read_table(
            &mut Image(image),
            Geometry::new(length).unwrap(),
            ReadMode::GuestBoot,
        )
        .unwrap()
    }

    fn gpt_selector(guid: [u8; 16]) -> RawSelector {
        RawSelector::GptPartition {
            guid: PartitionGuid::new(guid).unwrap(),
        }
    }

    fn mbr_selector(number: u8) -> RawSelector {
        RawSelector::MbrPartition {
            number: MbrPartitionNumber::new(number).unwrap(),
        }
    }

    fn expectation() -> RawDeviceExpectation {
        RawDeviceExpectation {
            serial: RawSerial::Root,
            length_bytes: DISK_SECTORS * 512,
            logical_sector_size: 512,
            read_only: false,
        }
    }

    fn facts(major: u32, minor: u32, length_bytes: u64) -> DeviceFacts {
        DeviceFacts {
            number: rootfs_spec::DeviceNumber { major, minor },
            length_bytes,
            logical_sector_size: 512,
            read_only: false,
        }
    }

    #[test]
    fn root_serial_is_exact_unique_and_independent_of_attachment_order() {
        let root: (&[u8], &[u8]) = (b"vdb", b"silo-root\n");
        let data: (&[u8], &[u8]) = (b"vda", b"silo-data-0\n");
        for order in [[data, root], [root, data]] {
            let mut discovery = RootDiscovery::default();
            for (name, serial) in order {
                discovery.observe(name, serial).unwrap();
            }
            assert_eq!(discovery.finish().unwrap(), b"vdb");
        }
        let mut wrong = RootDiscovery::default();
        for serial in [
            b"silo-root-lower".as_slice(),
            b"silo-root-upper",
            b"silo-roo",
            b"silo-root ",
            b" silo-root",
            b"silo-root\r\n",
            b"SILO-ROOT",
        ] {
            wrong.observe(b"vdx", serial).unwrap();
        }
        assert_eq!(wrong.finish(), Err("raw: missing root attachment serial"));
        let mut duplicate = RootDiscovery::default();
        duplicate.observe(b"vda", b"silo-root").unwrap();
        assert_eq!(
            duplicate.observe(b"vdb", b"silo-root\n"),
            Err("raw: duplicate root attachment serial")
        );
    }

    #[test]
    fn whole_disk_selector_requires_absence_of_any_table() {
        let empty = table(vec![0; DISK_SECTORS as usize * 512]);
        assert_eq!(
            select(&empty, RawSelector::WholeDisk),
            Ok(Selection::WholeDisk)
        );
        // An ext4 superblock at 1024 is not a partition table.
        let mut ext4 = vec![0; DISK_SECTORS as usize * 512];
        ext4[1024 + 0x38..1024 + 0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
        assert_eq!(
            select(&table(ext4), RawSelector::WholeDisk),
            Ok(Selection::WholeDisk)
        );
        for partitioned in [
            table(gpt(&[Entry {
                slot: 1,
                unique: ROOT_GUID,
                first: 34,
                last: 1023,
            }])),
            table(mbr(&[(1, 0x83, 2048 / 4, 1024)])),
        ] {
            assert_eq!(
                select(&partitioned, RawSelector::WholeDisk),
                Err("raw: whole-disk root carries a partition table")
            );
        }
    }

    #[test]
    fn gpt_selector_uses_disk_local_unique_guid_and_sparse_original_slot() {
        let parsed = table(gpt(&[
            Entry {
                slot: 2,
                unique: OTHER_GUID,
                first: 34,
                last: 99,
            },
            Entry {
                slot: 7,
                unique: ROOT_GUID,
                first: 100,
                last: 1999,
            },
        ]));
        assert_eq!(
            select(&parsed, gpt_selector(ROOT_GUID)),
            Ok(Selection::Partition(PartitionExpectation {
                number: 7,
                start_sector: 100,
                sectors: 1900,
            }))
        );
        let mut absent = ROOT_GUID;
        absent[15] ^= 1;
        assert_eq!(
            select(&parsed, gpt_selector(absent)),
            Err("raw: selected GPT partition GUID is absent")
        );
        assert_eq!(
            select(&parsed, mbr_selector(1)),
            Err("raw: MBR selector without an MBR")
        );
        let empty = table(vec![0; DISK_SECTORS as usize * 512]);
        assert_eq!(
            select(&empty, gpt_selector(ROOT_GUID)),
            Err("raw: GPT selector without a GPT")
        );
    }

    #[test]
    fn canonical_bootstrap_guid_bytes_match_mixed_endian_disk_encoding() {
        let parsed = table(gpt(&[Entry {
            slot: 1,
            unique: ROOT_GUID,
            first: 34,
            last: 1023,
        }]));
        let PartitionTable::Gpt(gpt) = &parsed else {
            panic!("gpt");
        };
        let guid = PartitionGuid::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(guid.bytes(), ROOT_GUID);
        assert_eq!(
            gpt.partitions()[0].unique_guid(),
            uuid::Uuid::from_bytes(guid.bytes())
        );
        // The disk bytes really are mixed-endian, so a byte-for-byte copy of
        // the on-disk field would not select the partition.
        let on_disk = mixed_endian(ROOT_GUID);
        assert_ne!(on_disk, ROOT_GUID);
        assert_eq!(
            select(&parsed, gpt_selector(on_disk)),
            Err("raw: selected GPT partition GUID is absent")
        );
    }

    #[test]
    fn cloned_identity_on_another_attachment_is_irrelevant() {
        // A data disk with the same GUID is a separate table; only the named
        // attachment's own table is consulted.
        let root = table(gpt(&[Entry {
            slot: 3,
            unique: ROOT_GUID,
            first: 200,
            last: 399,
        }]));
        let clone = table(gpt(&[Entry {
            slot: 1,
            unique: ROOT_GUID,
            first: 34,
            last: 1999,
        }]));
        assert_eq!(
            select(&root, gpt_selector(ROOT_GUID)),
            Ok(Selection::Partition(PartitionExpectation {
                number: 3,
                start_sector: 200,
                sectors: 200,
            }))
        );
        assert_ne!(
            select(&clone, gpt_selector(ROOT_GUID)),
            select(&root, gpt_selector(ROOT_GUID))
        );
    }

    #[test]
    fn mbr_selector_uses_original_primary_slot_including_slot_four() {
        let parsed = table(mbr(&[(1, 0x83, 64, 64), (4, 0x83, 512, 1024)]));
        assert_eq!(
            select(&parsed, mbr_selector(4)),
            Ok(Selection::Partition(PartitionExpectation {
                number: 4,
                start_sector: 512,
                sectors: 1024,
            }))
        );
        // Slot 2 is empty: no compaction maps it onto the slot-4 entry.
        assert_eq!(
            select(&parsed, mbr_selector(2)),
            Err("raw: selected MBR primary slot is empty")
        );
        assert_eq!(
            select(&parsed, gpt_selector(ROOT_GUID)),
            Err("raw: GPT selector without a GPT")
        );
    }

    #[test]
    fn unsupported_entry_width_is_rejected_by_the_direct_boot_policy() {
        let mut image = gpt(&[]);
        // Rewrite both headers for 256-byte entries (64 entries, same array).
        let array_crc = crc32(&image[1024..1024 + 128 * 128]);
        for lba in [1, DISK_SECTORS - 1] {
            let start = lba as usize * 512;
            image[start + 80..start + 84].copy_from_slice(&64u32.to_le_bytes());
            image[start + 84..start + 88].copy_from_slice(&256u32.to_le_bytes());
            image[start + 88..start + 92].copy_from_slice(&array_crc.to_le_bytes());
            image[start + 16..start + 20].fill(0);
            let crc = crc32(&image[start..start + 92]);
            image[start + 16..start + 20].copy_from_slice(&crc.to_le_bytes());
        }
        let parsed = table(image);
        let PartitionTable::Gpt(gpt) = &parsed else {
            panic!("gpt");
        };
        assert_eq!(gpt.entry_size(), 256);
        for selector in [RawSelector::WholeDisk, gpt_selector(ROOT_GUID)] {
            assert_eq!(
                select(&parsed, selector),
                Err("raw: partition table unsupported by the direct-boot kernel profile")
            );
        }
    }

    #[test]
    fn recognized_corrupt_table_never_becomes_a_whole_disk_root() {
        let mut image = gpt(&[Entry {
            slot: 1,
            unique: ROOT_GUID,
            first: 34,
            last: 1023,
        }]);
        image[1024 + 40] ^= 1;
        let length = image.len() as u64;
        assert!(read_table(
            &mut Image(image),
            Geometry::new(length).unwrap(),
            ReadMode::GuestBoot,
        )
        .is_err());
        let mut truncated = Image(gpt(&[]));
        truncated.0.truncate(4096);
        assert!(read_table(
            &mut truncated,
            Geometry::new(DISK_SECTORS * 512).unwrap(),
            ReadMode::GuestBoot,
        )
        .is_err());
    }

    #[test]
    fn parent_must_match_effective_attachment_geometry_and_access() {
        let expected = expectation();
        let actual = facts(254, 0, DISK_SECTORS * 512);
        assert_eq!(check_parent(&expected, actual), Ok(()));
        assert!(check_parent(
            &expected,
            DeviceFacts {
                length_bytes: actual.length_bytes + 512,
                ..actual
            }
        )
        .is_err());
        assert!(check_parent(
            &expected,
            DeviceFacts {
                logical_sector_size: 4096,
                ..actual
            }
        )
        .is_err());
        assert!(check_parent(
            &expected,
            DeviceFacts {
                read_only: true,
                ..actual
            }
        )
        .is_err());
    }

    #[test]
    fn child_search_matches_number_under_parent_and_rejects_duplicates() {
        let mut search = ChildSearch::new(7);
        search.observe(b"vda1", b"1\n").unwrap();
        search.observe(b"vda7", b"7\n").unwrap();
        assert_eq!(search.finish().unwrap(), b"vda7");
        let mut missing = ChildSearch::new(4);
        missing.observe(b"vda1", b"1\n").unwrap();
        assert!(missing.finish().is_err());
        let mut duplicate = ChildSearch::new(1);
        duplicate.observe(b"vda1", b"1\n").unwrap();
        assert!(duplicate.observe(b"vdb1", b"1\n").is_err());
        assert!(ChildSearch::new(1).observe(b"vda1", b"one\n").is_err());
    }

    #[test]
    fn kernel_child_must_match_table_slot_extent_and_device() {
        let expected = expectation();
        let parent = facts(254, 0, DISK_SECTORS * 512);
        let selected = PartitionExpectation {
            number: 7,
            start_sector: 100,
            sectors: 1900,
        };
        let child = ChildFacts {
            number: 7,
            start_sector: 100,
            device: facts(254, 7, 1900 * 512),
        };
        assert_eq!(check_child(&expected, parent, selected, child), Ok(()));
        for mutated in [
            ChildFacts { number: 6, ..child },
            ChildFacts {
                start_sector: 101,
                ..child
            },
            ChildFacts {
                device: facts(254, 7, 1899 * 512),
                ..child
            },
            ChildFacts {
                device: facts(254, 0, 1900 * 512),
                ..child
            },
            ChildFacts {
                device: DeviceFacts {
                    read_only: true,
                    ..child.device
                },
                ..child
            },
            ChildFacts {
                device: DeviceFacts {
                    logical_sector_size: 4096,
                    ..child.device
                },
                ..child
            },
        ] {
            assert!(check_child(&expected, parent, selected, mutated).is_err());
        }
        let beyond = PartitionExpectation {
            start_sector: 200,
            ..selected
        };
        assert!(check_child(
            &expected,
            parent,
            beyond,
            ChildFacts {
                start_sector: 200,
                ..child
            }
        )
        .is_err());
    }

    #[test]
    fn mounted_root_must_be_ext4_on_the_resolved_device() {
        let resolved = facts(254, 7, 1900 * 512);
        assert_eq!(
            check_mounted_root(EXT4_SUPER_MAGIC, (254, 7), resolved),
            Ok(())
        );
        assert!(check_mounted_root(EXT4_SUPER_MAGIC, (254, 0), resolved).is_err());
        assert!(check_mounted_root(0x9123_683e, (254, 7), resolved).is_err());
    }
}
