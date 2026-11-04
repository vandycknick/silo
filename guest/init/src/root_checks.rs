//! Pure checks over measured devices and ext4 primary superblocks.
use rootfs_spec::upper_geometry::{self as profile, UpperCapacity, UpperGeometry};
use rootfs_spec::{DeviceExpectation, DeviceNumber};

#[derive(Clone, Copy, Debug)]
pub struct DeviceFacts {
    pub number: DeviceNumber,
    pub length_bytes: u64,
    pub logical_sector_size: u32,
    pub read_only: bool,
}

pub fn serial_matches(actual: &[u8], expected: &[u8]) -> bool {
    actual.strip_suffix(b"\n").unwrap_or(actual) == expected
}

#[derive(Default)]
pub struct SerialDiscovery {
    lower: bool,
    upper: bool,
}

impl SerialDiscovery {
    pub fn observe(
        &mut self,
        serial: &[u8],
    ) -> Result<Option<rootfs_spec::RootSerial>, &'static str> {
        use rootfs_spec::RootSerial;
        let (seen, role) = if serial_matches(serial, RootSerial::Lower.as_str().as_bytes()) {
            (&mut self.lower, RootSerial::Lower)
        } else if serial_matches(serial, RootSerial::Upper.as_str().as_bytes()) {
            (&mut self.upper, RootSerial::Upper)
        } else {
            return Ok(None);
        };
        if *seen {
            return Err(match role {
                RootSerial::Lower => "overlay: duplicate lower serial",
                RootSerial::Upper => "overlay: duplicate upper serial",
            });
        }
        *seen = true;
        Ok(Some(role))
    }

    pub fn finish(self) -> Result<(), &'static str> {
        if !self.lower {
            return Err("overlay: missing lower serial");
        }
        if !self.upper {
            return Err("overlay: missing upper serial");
        }
        Ok(())
    }
}

pub fn decimal(bytes: &[u8]) -> Result<u64, &'static str> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.is_empty() {
        return Err("overlay: empty sysfs integer");
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err("overlay: malformed sysfs integer");
        }
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(*byte - b'0')))
            .ok_or("overlay: sysfs integer overflow")?;
    }
    Ok(value)
}

pub fn check_device(expected: &DeviceExpectation, actual: DeviceFacts) -> Result<(), &'static str> {
    if expected.length_bytes != actual.length_bytes {
        return Err("overlay: device length mismatch");
    }
    if expected.logical_sector_size != actual.logical_sector_size {
        return Err("overlay: sector size mismatch");
    }
    if expected.read_only != actual.read_only {
        return Err("overlay: device read-only mismatch");
    }
    Ok(())
}

fn u16_at(bytes: &[u8; 1024], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn u32_at(bytes: &[u8; 1024], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub fn check_superblock(
    bytes: &[u8; 1024],
    expected: &DeviceExpectation,
    upper: bool,
) -> Result<u64, &'static str> {
    if u16_at(bytes, 0x38) != 0xef53 {
        return Err("overlay: ext4 magic mismatch");
    }
    if bytes[0x68..0x78] != expected.filesystem_uuid.bytes() {
        return Err("overlay: ext4 UUID mismatch");
    }
    if u32_at(bytes, 0x18) != 2 || u32_at(bytes, 0x14) != 0 || u32_at(bytes, 0x150) != 0 {
        return Err("overlay: unsupported ext4 block geometry");
    }
    let blocks = u64::from(u32_at(bytes, 4));
    let span = blocks
        .checked_mul(u64::from(profile::BLOCK_SIZE))
        .ok_or("overlay: ext4 span overflow")?;
    if span == 0 || span > expected.length_bytes {
        return Err("overlay: invalid ext4 span");
    }
    let compat = u32_at(bytes, 0x5c);
    let incompat = u32_at(bytes, 0x60);
    let ro = u32_at(bytes, 0x64);
    if incompat & !0x4 != profile::FEATURE_INCOMPAT
        || compat & !profile::FEATURE_COMPAT != 0
        || compat & 0x1c != 0x1c
        || ro & !profile::FEATURE_RO_COMPAT != 0
        || ro & 0x5b != 0x5b
    {
        return Err("overlay: unsupported ext4 features");
    }
    if u16_at(bytes, 0x3a) & 2 != 0 {
        return Err("overlay: ext4 error state");
    }
    if upper {
        if compat != profile::FEATURE_COMPAT
            || ro != profile::FEATURE_RO_COMPAT
            || u32_at(bytes, 0x20) != profile::BLOCKS_PER_GROUP
            || u32_at(bytes, 0x24) != profile::BLOCKS_PER_GROUP
            || u32_at(bytes, 0x28) != profile::INODES_PER_GROUP
            || u32::from(u16_at(bytes, 0x58)) != profile::INODE_SIZE
            || u32_at(bytes, 0xe0) != 8
            || u32_at(bytes, 0xe4) != 0
            || bytes[0x174] != profile::LOG_GROUPS_PER_FLEX
            || bytes[0xfc] != profile::HASH_VERSION
            || u32_at(bytes, 0x160) & 3 != profile::HASH_FLAGS
            || u16_at(bytes, 0x15c) != 32
            || u16_at(bytes, 0x15e) != 32
            || bytes[0xec..0xfc] != expected.filesystem_uuid.bytes()
        {
            return Err("overlay: upper ext4 profile mismatch");
        }
        let groups = blocks.div_ceil(u64::from(profile::BLOCKS_PER_GROUP));
        let descriptors = groups.div_ceil(u64::from(profile::DESCRIPTORS_PER_BLOCK));
        if descriptors > u64::from(profile::MAX_DESCRIPTOR_BLOCKS)
            || u64::from(u16_at(bytes, 0xce))
                != u64::from(profile::MAX_DESCRIPTOR_BLOCKS) - descriptors
        {
            return Err("overlay: upper resize reservation mismatch");
        }
    } else if incompat & 4 != 0 || u16_at(bytes, 0x3a) & 1 == 0 || u32_at(bytes, 0xe8) != 0 {
        return Err("overlay: lower requires journal recovery");
    }
    Ok(span)
}

pub fn check_achieved_span(backing: u64, observed: u64) -> Result<u64, &'static str> {
    let capacity = UpperCapacity::new(backing).map_err(|_| "overlay: invalid upper capacity")?;
    let geometry = UpperGeometry::for_capacity(capacity);
    if observed != geometry.filesystem_bytes {
        return Err("overlay: unexplained upper growth result");
    }
    Ok(geometry.unusable_tail_bytes)
}

/// Bounded ext4 extent-node decoding used for the actual journal inode.
pub fn extent_header(node: &[u8]) -> Result<(u16, usize), &'static str> {
    if node.len() < 24 {
        return Err("overlay: truncated journal extent node");
    }
    let word = |at| u16::from_le_bytes([node[at], node[at + 1]]);
    let entries = usize::from(word(2));
    let maximum = usize::from(word(4));
    let depth = word(6);
    if word(0) != 0xf30a
        || entries == 0
        || entries > maximum
        || maximum > (node.len() - 12) / 12
        || depth > 5
    {
        return Err("overlay: invalid journal extent header");
    }
    Ok((depth, entries))
}

pub fn extent_entry(node: &[u8], index: usize) -> Result<(u32, u64, u32), &'static str> {
    let (depth, entries) = extent_header(node)?;
    if index >= entries {
        return Err("overlay: journal extent entry outside node");
    }
    let at = 12 + index * 12;
    let word = |at| u16::from_le_bytes([node[at], node[at + 1]]);
    let dword = |at| u32::from_le_bytes([node[at], node[at + 1], node[at + 2], node[at + 3]]);
    let (physical, length) = if depth == 0 {
        let length = word(at + 4);
        if length == 0 || length > 32768 {
            return Err("overlay: uninitialized journal extent");
        }
        (
            u64::from(dword(at + 8)) | (u64::from(word(at + 6)) << 32),
            u32::from(length),
        )
    } else {
        (
            u64::from(dword(at + 4)) | (u64::from(word(at + 8)) << 32),
            0,
        )
    };
    Ok((dword(at), physical, length))
}

#[derive(Clone, Copy, Default)]
struct JournalExtent {
    physical: u64,
    blocks: u32,
}

/// The fixed formatter journal is at most 1 GiB, split at group/static-metadata
/// boundaries. Sixty-four records/nodes conservatively bound its complete map.
pub struct JournalMap {
    extents: [JournalExtent; 64],
    count: usize,
    nodes: [u64; 64],
    node_count: usize,
    pub next_logical: u32,
    pub blocks: u32,
    span_blocks: u64,
}
impl JournalMap {
    pub fn new(blocks: u32, span: u64) -> Result<Self, &'static str> {
        if !matches!(
            blocks,
            1024 | 4096 | 8192 | 16384 | 32768 | 65536 | 131072 | 262144
        ) || u64::from(blocks) * 4096 >= span
        {
            return Err("overlay: invalid actual journal inode length");
        }
        Ok(Self {
            extents: [JournalExtent::default(); 64],
            count: 0,
            nodes: [0; 64],
            node_count: 0,
            next_logical: 0,
            blocks,
            span_blocks: span / 4096,
        })
    }
    pub fn add_node(&mut self, physical: u64) -> Result<(), &'static str> {
        if self.node_count == self.nodes.len()
            || physical == 0
            || physical >= self.span_blocks
            || self.nodes[..self.node_count].contains(&physical)
        {
            return Err("overlay: invalid or cyclic journal index block");
        }
        self.nodes[self.node_count] = physical;
        self.node_count += 1;
        Ok(())
    }
    pub fn add_extent(
        &mut self,
        logical: u32,
        physical: u64,
        blocks: u32,
    ) -> Result<(), &'static str> {
        let end = physical
            .checked_add(u64::from(blocks))
            .ok_or("overlay: journal extent overflow")?;
        let logical_end = logical
            .checked_add(blocks)
            .ok_or("overlay: journal logical overflow")?;
        if self.count == self.extents.len()
            || logical != self.next_logical
            || blocks == 0
            || physical == 0
            || end > self.span_blocks
            || logical_end > self.blocks
        {
            return Err("overlay: journal extent outside exact inode map");
        }
        for previous in &self.extents[..self.count] {
            if physical < previous.physical + u64::from(previous.blocks) && previous.physical < end
            {
                return Err("overlay: overlapping journal extents");
            }
        }
        self.extents[self.count] = JournalExtent { physical, blocks };
        self.count += 1;
        self.next_logical = logical_end;
        Ok(())
    }
    pub fn finish(&self) -> Result<u64, &'static str> {
        if self.next_logical != self.blocks {
            return Err("overlay: incomplete journal inode map");
        }
        for extent in &self.extents[..self.count] {
            if self.nodes[..self.node_count].iter().any(|node| {
                *node >= extent.physical && *node < extent.physical + u64::from(extent.blocks)
            }) {
                return Err("overlay: journal data overlaps extent index");
            }
        }
        self.extents
            .first()
            .map(|extent| extent.physical)
            .ok_or("overlay: missing journal extent")
    }
}

pub fn check_journal(
    bytes: &[u8; 4096],
    expected: &DeviceExpectation,
    span: u64,
) -> Result<u32, &'static str> {
    let be = |at| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let blocks = be(0x10);
    if be(0) != 0xc03b3998
        || be(4) != 4
        || be(0x0c) != 4096
        || be(0x14) != 1
        || !matches!(
            blocks,
            1024 | 4096 | 8192 | 16384 | 32768 | 65536 | 131072 | 262144
        )
        || u64::from(blocks) * 4096 >= span
        || be(0x1c) >= blocks
        || be(0x20) != 0
        || be(0x24) != 0
        || be(0x28) & !1 != 0
        || be(0x2c) != 0
        || bytes[0x30..0x40] != expected.filesystem_uuid.bytes()
        || be(0x40) != 1
    {
        return Err("overlay: unsupported upper JBD2 profile");
    }
    // REVOKE is runtime state, like ext4 RECOVER, not a formatter feature.
    Ok(blocks)
}

pub fn check_journal_inode(inode: &[u8; 256], span: u64) -> Result<u32, &'static str> {
    let word = |at| u16::from_le_bytes([inode[at], inode[at + 1]]);
    let dword = |at| u32::from_le_bytes([inode[at], inode[at + 1], inode[at + 2], inode[at + 3]]);
    let bytes = u64::from(dword(4)) | (u64::from(dword(0x6c)) << 32);
    if word(0) != 0o100600
        || word(2) != 0
        || word(0x18) != 0
        || word(0x78) != 0
        || word(0x7a) != 0
        || word(0x1a) != 1
        || dword(0x20) != 0x80000
        || bytes % 4096 != 0
    {
        return Err("overlay: unsupported actual journal inode profile");
    }
    let blocks = u32::try_from(bytes / 4096).map_err(|_| "overlay: journal inode size overflow")?;
    JournalMap::new(blocks, span)?;
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use crate::root_checks::{
        check_achieved_span, check_device, check_superblock, decimal, serial_matches, DeviceFacts,
    };
    use rootfs_spec::{DeviceExpectation, DeviceNumber, FilesystemUuid, RootSerial};

    fn expectation() -> DeviceExpectation {
        DeviceExpectation {
            serial: RootSerial::Upper,
            length_bytes: 64 * 1024 * 1024,
            logical_sector_size: 512,
            read_only: false,
            filesystem_uuid: FilesystemUuid::new([1; 16]).unwrap(),
        }
    }
    fn put(bytes: &mut [u8; 1024], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn superblock() -> [u8; 1024] {
        let mut bytes = [0; 1024];
        bytes[0x38..0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
        put(&mut bytes, 4, 16384);
        put(&mut bytes, 0x18, 2);
        put(&mut bytes, 0x5c, 0x3c);
        put(&mut bytes, 0x60, 0x242);
        put(&mut bytes, 0x64, 0x7b);
        put(&mut bytes, 0x20, 32768);
        put(&mut bytes, 0x24, 32768);
        put(&mut bytes, 0x28, 8192);
        bytes[0x58..0x5a].copy_from_slice(&256u16.to_le_bytes());
        bytes[0xce..0xd0].copy_from_slice(&63u16.to_le_bytes());
        put(&mut bytes, 0xe0, 8);
        put(&mut bytes, 0x160, 1);
        bytes[0x15c..0x15e].copy_from_slice(&32u16.to_le_bytes());
        bytes[0x15e..0x160].copy_from_slice(&32u16.to_le_bytes());
        bytes[0x174] = 13;
        bytes[0xfc] = 1;
        bytes[0x68..0x78].fill(1);
        bytes[0xec..0xfc].fill(1);
        bytes
    }
    #[test]
    fn exact_serial_never_trims_or_matches_prefix() {
        assert!(serial_matches(b"silo-root-upper\n", b"silo-root-upper"));
        for wrong in [
            b" silo-root-upper".as_slice(),
            b"silo-root-uppe",
            b"silo-root-upper \n",
            b"silo-root-upper\r\n",
            b"silo-root-lower",
        ] {
            assert!(!serial_matches(wrong, b"silo-root-upper"));
        }
    }
    #[test]
    fn discovery_is_order_independent_but_missing_duplicate_truncated_fail() {
        use crate::root_checks::SerialDiscovery;
        for serials in [
            [b"silo-root-lower".as_slice(), b"silo-root-upper"],
            [b"silo-root-upper".as_slice(), b"silo-root-lower"],
        ] {
            let mut discovery = SerialDiscovery::default();
            for serial in serials {
                assert!(discovery.observe(serial).unwrap().is_some());
            }
            assert!(discovery.finish().is_ok());
        }
        let mut discovery = SerialDiscovery::default();
        assert!(discovery.observe(b"silo-root-lower").unwrap().is_some());
        assert!(discovery.observe(b"silo-root-lower").is_err());
        let mut discovery = SerialDiscovery::default();
        discovery.observe(b"silo-root-lower").unwrap();
        assert!(discovery.observe(b"silo-root-uppe").unwrap().is_none());
        assert!(discovery.finish().is_err());
    }
    #[test]
    fn device_length_mismatch_fails() {
        let facts = DeviceFacts {
            number: DeviceNumber {
                major: 254,
                minor: 0,
            },
            length_bytes: 64 * 1024 * 1024,
            logical_sector_size: 512,
            read_only: false,
        };
        assert!(check_device(&expectation(), facts).is_ok());
        let truncated = DeviceFacts {
            length_bytes: facts.length_bytes - 512,
            ..facts
        };
        assert_eq!(
            check_device(&expectation(), truncated),
            Err("overlay: device length mismatch")
        );
    }
    #[test]
    fn lower_sector_size_and_writable_access_fail_independently() {
        let mut expected = expectation();
        expected.serial = RootSerial::Lower;
        expected.read_only = true;
        let facts = DeviceFacts {
            number: DeviceNumber {
                major: 254,
                minor: 0,
            },
            length_bytes: expected.length_bytes,
            logical_sector_size: 512,
            read_only: true,
        };
        assert!(check_device(&expected, facts).is_ok());
        assert_eq!(
            check_device(
                &expected,
                DeviceFacts {
                    logical_sector_size: 4096,
                    ..facts
                }
            ),
            Err("overlay: sector size mismatch")
        );
        assert_eq!(
            check_device(
                &expected,
                DeviceFacts {
                    read_only: false,
                    ..facts
                }
            ),
            Err("overlay: device read-only mismatch")
        );
    }
    #[test]
    fn upper_sector_size_and_read_only_access_fail_independently() {
        let expected = expectation();
        let facts = DeviceFacts {
            number: DeviceNumber {
                major: 254,
                minor: 1,
            },
            length_bytes: expected.length_bytes,
            logical_sector_size: 512,
            read_only: false,
        };
        assert!(check_device(&expected, facts).is_ok());
        assert_eq!(
            check_device(
                &expected,
                DeviceFacts {
                    logical_sector_size: 4096,
                    ..facts
                }
            ),
            Err("overlay: sector size mismatch")
        );
        assert_eq!(
            check_device(
                &expected,
                DeviceFacts {
                    read_only: true,
                    ..facts
                }
            ),
            Err("overlay: device read-only mismatch")
        );
    }
    #[test]
    fn upper_recovery_allowed_but_wrong_uuid_and_features_reject() {
        let mut bytes = superblock();
        assert!(check_superblock(&bytes, &expectation(), true).is_ok());
        put(&mut bytes, 0x60, 0x246);
        assert!(check_superblock(&bytes, &expectation(), true).is_ok());
        bytes[0x68] = 2;
        assert!(check_superblock(&bytes, &expectation(), true).is_err());
        bytes[0x68] = 1;
        put(&mut bytes, 0x60, 0x252);
        assert!(check_superblock(&bytes, &expectation(), true).is_err());
    }
    #[test]
    fn swapped_files_under_correct_role_serials_fail_uuid_validation() {
        let mut lower_expected = expectation();
        lower_expected.serial = RootSerial::Lower;
        lower_expected.filesystem_uuid = FilesystemUuid::new([2; 16]).unwrap();
        lower_expected.read_only = true;
        let upper_bytes = superblock();
        assert!(check_superblock(&upper_bytes, &lower_expected, false).is_err());
        let mut lower_bytes = superblock();
        lower_bytes[0x68..0x78].fill(2);
        assert!(check_superblock(&lower_bytes, &expectation(), true).is_err());
    }
    #[test]
    fn dirty_lower_and_overlong_filesystem_reject() {
        let mut bytes = superblock();
        bytes[0x3a] = 1;
        assert!(check_superblock(&bytes, &expectation(), false).is_ok());
        put(&mut bytes, 0x60, 0x246);
        assert!(check_superblock(&bytes, &expectation(), false).is_err());
        put(&mut bytes, 0x60, 0x242);
        put(&mut bytes, 4, 32768);
        assert!(check_superblock(&bytes, &expectation(), true).is_err());
    }
    #[test]
    fn short_tail_is_explicit_and_undergrowth_rejected() {
        assert_eq!(
            check_achieved_span(128 * 1024 * 1024 + 4096, 128 * 1024 * 1024),
            Ok(4096)
        );
        assert!(check_achieved_span(256 * 1024 * 1024, 128 * 1024 * 1024).is_err());
        assert!(decimal(b"18446744073709551616").is_err());
        assert!(decimal(b"512 \n").is_err());
    }
    #[test]
    fn journal_profile_and_extent_bounds_fail_closed() {
        use crate::root_checks::{check_journal, extent_entry, extent_header};
        let mut node = [0u8; 60];
        node[..2].copy_from_slice(&0xf30au16.to_le_bytes());
        node[2..4].copy_from_slice(&1u16.to_le_bytes());
        node[4..6].copy_from_slice(&4u16.to_le_bytes());
        node[16..18].copy_from_slice(&1024u16.to_le_bytes());
        node[20..24].copy_from_slice(&100u32.to_le_bytes());
        assert_eq!(extent_header(&node), Ok((0, 1)));
        assert_eq!(extent_entry(&node, 0), Ok((0, 100, 1024)));
        assert!(extent_entry(&node, 1).is_err());
        node[6..8].copy_from_slice(&6u16.to_le_bytes());
        assert!(extent_header(&node).is_err());
        assert!(extent_header(&node[..12]).is_err());
        let mut journal = [0u8; 4096];
        for (offset, value) in [
            (0, 0xc03b3998u32),
            (4, 4),
            (0x0c, 4096),
            (0x10, 1024),
            (0x14, 1),
            (0x40, 1),
        ] {
            journal[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        journal[0x30..0x40].fill(1);
        assert!(check_journal(&journal, &expectation(), 64 * 1024 * 1024).is_ok());
        journal[0x28..0x2c].copy_from_slice(&1u32.to_be_bytes());
        assert!(check_journal(&journal, &expectation(), 64 * 1024 * 1024).is_ok());
        journal[0x28..0x2c].copy_from_slice(&2u32.to_be_bytes());
        assert!(check_journal(&journal, &expectation(), 64 * 1024 * 1024).is_err());
    }
    #[test]
    fn complete_actual_journal_map_rejects_holes_overlap_and_truncated_tail() {
        use crate::root_checks::JournalMap;
        let mut valid = JournalMap::new(1024, 64 * 1024 * 1024).unwrap();
        valid.add_node(20).unwrap();
        valid.add_extent(0, 100, 512).unwrap();
        valid.add_extent(512, 1000, 512).unwrap();
        assert_eq!(valid.finish(), Ok(100));
        let mut truncated = JournalMap::new(1024, 64 * 1024 * 1024).unwrap();
        truncated.add_extent(0, 100, 512).unwrap();
        assert!(truncated.finish().is_err());
        assert!(truncated.add_extent(513, 1000, 511).is_err());
        assert!(truncated.add_extent(512, 200, 512).is_err());
        assert!(truncated.add_extent(512, 16380, 512).is_err());
        let mut index_overlap = JournalMap::new(1024, 64 * 1024 * 1024).unwrap();
        index_overlap.add_node(100).unwrap();
        index_overlap.add_extent(0, 100, 1024).unwrap();
        assert!(index_overlap.finish().is_err());
    }
    #[test]
    fn actual_journal_inode_requires_extent_flag_and_admitted_length() {
        use crate::root_checks::check_journal_inode;
        let mut inode = [0; 256];
        inode[..2].copy_from_slice(&0o100600u16.to_le_bytes());
        inode[0x1a..0x1c].copy_from_slice(&1u16.to_le_bytes());
        inode[0x20..0x24].copy_from_slice(&0x80000u32.to_le_bytes());
        inode[4..8].copy_from_slice(&(1024u32 * 4096).to_le_bytes());
        assert_eq!(check_journal_inode(&inode, 64 * 1024 * 1024), Ok(1024));
        inode[0x20..0x24].fill(0);
        assert!(check_journal_inode(&inode, 64 * 1024 * 1024).is_err());
        inode[0x20..0x24].copy_from_slice(&0x80000u32.to_le_bytes());
        inode[4..8].copy_from_slice(&(1024u32 * 4096 - 4096).to_le_bytes());
        assert!(check_journal_inode(&inode, 64 * 1024 * 1024).is_err());
    }
    #[test]
    fn journal_extent_record_limit_accepts_64_and_refuses_65_without_truncation() {
        use crate::root_checks::JournalMap;
        let mut exact = JournalMap::new(1024, 64 * 1024 * 1024).unwrap();
        let mut over = JournalMap::new(4096, 64 * 1024 * 1024).unwrap();
        for index in 0..64 {
            let logical = index * 16;
            let physical = 1000 + u64::from(logical);
            exact.add_extent(logical, physical, 16).unwrap();
            over.add_extent(logical, physical, 16).unwrap();
        }
        assert_eq!(exact.finish(), Ok(1000));
        assert_eq!(over.next_logical, 1024);
        // This 65th record has valid contiguous geometry and no overlap. Only
        // the record bound refuses it, rather than silently dropping a tail.
        assert!(over.add_extent(1024, 2024, 16).is_err());
        assert_eq!(over.next_logical, 1024);
        assert!(over.finish().is_err());
    }
    #[test]
    fn journal_index_node_limit_is_inclusive_and_revisits_are_cycles() {
        use crate::root_checks::JournalMap;
        let mut map = JournalMap::new(1024, 64 * 1024 * 1024).unwrap();
        for physical in 100..164 {
            map.add_node(physical).unwrap();
        }
        map.add_extent(0, 1000, 1024).unwrap();
        assert_eq!(map.finish(), Ok(1000));
        assert!(map.add_node(164).is_err());
        assert_eq!(map.finish(), Ok(1000));
        let mut cyclic = JournalMap::new(1024, 64 * 1024 * 1024).unwrap();
        cyclic.add_node(40).unwrap();
        cyclic.add_node(41).unwrap();
        assert!(cyclic.add_node(40).is_err());
    }
    #[test]
    fn journal_extent_header_bounds_maximum_depth_and_node_capacity() {
        use crate::root_checks::extent_header;
        let mut root = [0u8; 60];
        root[..2].copy_from_slice(&0xf30au16.to_le_bytes());
        root[2..4].copy_from_slice(&4u16.to_le_bytes());
        root[4..6].copy_from_slice(&4u16.to_le_bytes());
        root[6..8].copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(extent_header(&root), Ok((5, 4)));
        root[6..8].copy_from_slice(&6u16.to_le_bytes());
        assert!(extent_header(&root).is_err());
        root[6..8].copy_from_slice(&5u16.to_le_bytes());
        root[2..4].copy_from_slice(&5u16.to_le_bytes());
        root[4..6].copy_from_slice(&5u16.to_le_bytes());
        assert!(extent_header(&root).is_err());
        let mut leaf = [0u8; 4096];
        leaf[..2].copy_from_slice(&0xf30au16.to_le_bytes());
        leaf[2..4].copy_from_slice(&340u16.to_le_bytes());
        leaf[4..6].copy_from_slice(&340u16.to_le_bytes());
        assert_eq!(extent_header(&leaf), Ok((0, 340)));
        leaf[2..4].copy_from_slice(&341u16.to_le_bytes());
        leaf[4..6].copy_from_slice(&341u16.to_le_bytes());
        assert!(extent_header(&leaf).is_err());
    }
}
