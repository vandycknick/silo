//! Fresh private uppers for `silo-upper-ext4-v1`.
//!
//! This profile is intentionally separate from the generic OCI materializer's
//! minimum-size/layout policy. It has no offline growth or publication API.

use std::path::Path;

use rootfs_spec::UpperProfile;
use rootfs_spec::upper_geometry::{UpperCapacity, UpperGeometry};
use uuid::Uuid;

use crate::ext4::constants::{file_mode, make_mode};
use crate::ext4::error::FormatResult;
use crate::ext4::formatter::Formatter;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormattedUpper {
    pub profile: UpperProfile,
    pub uuid: Uuid,
    pub backing_bytes: u64,
    pub filesystem_bytes: u64,
    pub unusable_tail_bytes: u64,
    /// Free filesystem blocks, not statvfs usable capacity or host allocation.
    pub initial_free_bytes: u64,
    pub initial_free_inodes: u64,
}

/// Create a new sparse 0600 file with a fresh random UUID and fixed profile.
///
/// Refuses existing files, including symlinks. Capacity is validated before any
/// file effects through `UpperCapacity`. The caller owns staging cleanup after
/// failure, synchronization and atomic publication; errors never remove a path
/// that another process could have replaced. Work/index state is created only
/// here, never reset on restart. Mounted statvfs supplies usable capacity later.
pub fn format_upper(path: &Path, capacity: UpperCapacity) -> FormatResult<FormattedUpper> {
    let geometry = UpperGeometry::for_capacity(capacity);
    let mut formatter = Formatter::new_upper(path, capacity)?;
    for (name, mode) in [("/upper", 0o755), ("/work", 0o700)] {
        formatter.create(
            name,
            make_mode(file_mode::S_IFDIR, mode),
            None,
            None,
            None,
            Some(0),
            Some(0),
            None,
            None,
        )?;
    }
    let (uuid, initial_free_bytes, initial_free_inodes) = formatter.finish()?;
    Ok(FormattedUpper {
        profile: UpperProfile::SiloUpperExt4V1,
        uuid,
        backing_bytes: geometry.backing_bytes,
        filesystem_bytes: geometry.filesystem_bytes,
        unusable_tail_bytes: geometry.unusable_tail_bytes,
        initial_free_bytes,
        initial_free_inodes,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    use rootfs_spec::upper_geometry::{self, UpperCapacity, UpperGeometry};

    use crate::ext4::Reader;
    use crate::ext4::checksum;
    use crate::ext4::constants::inode_flags;
    use crate::ext4::types::GroupDescriptor;
    use crate::ext4::upper::{FormattedUpper, format_upper};

    fn read_at(file: &mut File, offset: u64, bytes: &mut [u8]) {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(bytes).unwrap();
    }

    fn inspect(path: &std::path::Path, result: FormattedUpper) {
        let reader = Reader::new(path).unwrap();
        let sb = reader.superblock().clone();
        let geometry =
            UpperGeometry::for_capacity(UpperCapacity::new(result.backing_bytes).unwrap());
        assert_eq!(std::fs::metadata(path).unwrap().len(), result.backing_bytes);
        assert_eq!(sb.blocks_count_lo as u64 * 4096, result.filesystem_bytes);
        assert_eq!(
            result.filesystem_bytes + result.unusable_tail_bytes,
            result.backing_bytes
        );
        assert_eq!(sb.blocks_count_hi, 0);
        assert_eq!(sb.feature_compat, upper_geometry::FEATURE_COMPAT);
        assert_eq!(sb.feature_incompat, upper_geometry::FEATURE_INCOMPAT);
        assert_eq!(sb.feature_ro_compat, upper_geometry::FEATURE_RO_COMPAT);
        assert_eq!(sb.inodes_per_group, 8192);
        assert_eq!(sb.inode_size, 256);
        assert_eq!(sb.min_extra_isize, 32);
        assert_eq!(sb.want_extra_isize, 32);
        assert_eq!(sb.log_block_size, 2);
        assert_eq!(sb.blocks_per_group, 32768);
        assert_eq!(sb.log_groups_per_flex, 13);
        assert_eq!(sb.reserved_gdt_blocks as u32, geometry.reserved_gdt_blocks);
        assert_eq!(sb.uuid, *result.uuid.as_bytes());
        assert_eq!(result.uuid.get_version_num(), 4);
        assert_eq!(sb.def_hash_version, 1);
        assert_eq!(sb.flags, 1);
        for (index, seed) in sb.hash_seed.iter().enumerate() {
            assert_eq!(
                *seed,
                u32::from_le_bytes(sb.uuid[index * 4..index * 4 + 4].try_into().unwrap())
            );
        }
        assert_eq!(
            result.initial_free_bytes,
            sb.free_blocks_count_lo as u64 * 4096
        );
        assert_eq!(result.initial_free_inodes, sb.free_inodes_count as u64);
        assert_eq!(sb.inodes_count, geometry.groups * 8192);
        assert_eq!(sb.free_inodes_count, sb.inodes_count - 13);
        for (ino, mode) in [(2, 0o755), (11, 0o700), (12, 0o755), (13, 0o700)] {
            let inode = reader.get_inode(ino).unwrap();
            assert!(inode.is_dir());
            assert_eq!(inode.mode & 0o7777, mode);
            assert_eq!((inode.uid_full(), inode.gid_full()), (0, 0));
            assert_eq!(inode.flags & inode_flags::HASHED_INDEX, 0);
            assert_eq!(inode.extra_isize, 32);
            let entries = reader.children_of(ino).unwrap();
            if ino != 2 {
                assert_eq!(entries.len(), 2);
            } else {
                assert_eq!(entries.len(), 5);
                for (name, number) in [("lost+found", 11), ("upper", 12), ("work", 13)] {
                    assert!(
                        entries
                            .iter()
                            .any(|(entry, ino)| entry.as_slice() == name.as_bytes()
                                && *ino == number)
                    );
                }
            }
        }

        let mut file = File::open(path).unwrap();
        let mut table = vec![0; geometry.descriptor_blocks as usize * 4096];
        read_at(&mut file, 4096, &mut table);
        let mut bitmap = [0u8; 4096];
        let mut free_blocks = 0u64;
        let mut free_inodes = 0u64;
        let mut backup_groups = Vec::new();
        for group in 0..geometry.groups {
            let offset = group as usize * 32;
            let gd = GroupDescriptor::read_from(&table[offset..offset + 32]);
            assert_eq!(
                gd.checksum,
                checksum::group_descriptor(&sb.uuid, group, &gd)
            );
            let group_start = group as u64 * 32768;
            let blocks = (result.filesystem_bytes / 4096 - group_start).min(32768);
            for block in [
                gd.block_bitmap_lo,
                gd.inode_bitmap_lo,
                gd.inode_table_lo + 511,
            ] {
                assert!((block as u64) < result.filesystem_bytes / 4096);
            }
            read_at(&mut file, gd.block_bitmap_lo as u64 * 4096, &mut bitmap);
            let used: u64 = bitmap.iter().map(|byte| byte.count_ones() as u64).sum();
            assert_eq!(32768 - used, gd.free_blocks_count_lo as u64);
            for block in blocks..32768 {
                assert_ne!(bitmap[block as usize / 8] & (1 << (block % 8)), 0);
            }
            if upper_geometry::has_sparse_super(group) {
                for block in 0..65usize {
                    assert_ne!(bitmap[block / 8] & (1 << (block % 8)), 0);
                }
            }
            read_at(&mut file, gd.inode_bitmap_lo as u64 * 4096, &mut bitmap);
            let used: u64 = bitmap.iter().map(|byte| byte.count_ones() as u64).sum();
            assert_eq!(32768 - used, gd.free_inodes_count_lo as u64);
            assert!(bitmap[1024..].iter().all(|byte| *byte == 0xff));
            free_blocks += gd.free_blocks_count_lo as u64;
            free_inodes += gd.free_inodes_count_lo as u64;
            if group != 0 && upper_geometry::has_sparse_super(group) {
                backup_groups.push(group);
                let mut backup_sb = [0u8; 1024];
                read_at(&mut file, group_start * 4096, &mut backup_sb);
                assert_eq!(&backup_sb[0x68..0x78], &sb.uuid);
                assert_eq!(
                    u16::from_le_bytes(backup_sb[0x5a..0x5c].try_into().unwrap()),
                    group as u16
                );
                let mut backup_table = vec![0; table.len()];
                read_at(&mut file, (group_start + 1) * 4096, &mut backup_table);
                assert_eq!(backup_table, table);
            }
        }
        if result.unusable_tail_bytes != 0 {
            read_at(&mut file, result.backing_bytes - 4096, &mut bitmap);
            assert!(bitmap.iter().all(|byte| *byte == 0));
        }
        assert_eq!(free_blocks * 4096, result.initial_free_bytes);
        assert_eq!(free_inodes, result.initial_free_inodes);
        let resize = reader.get_inode(7).unwrap();
        assert_eq!(
            resize.blocks_lo,
            (1 + geometry.reserved_gdt_blocks * (1 + backup_groups.len() as u32)) * 8
        );
        let dind = u32::from_le_bytes(resize.block[52..56].try_into().unwrap());
        read_at(&mut file, dind as u64 * 4096, &mut bitmap);
        for index in 0..1024u32 {
            let pointer = u32::from_le_bytes(
                bitmap[index as usize * 4..index as usize * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            if index >= geometry.descriptor_blocks && index < 64 {
                assert_eq!(pointer, index + 1);
                let mut reserved = [0u8; 4096];
                read_at(&mut file, pointer as u64 * 4096, &mut reserved);
                for (index, group) in backup_groups.iter().enumerate() {
                    assert_eq!(
                        u32::from_le_bytes(reserved[index * 4..index * 4 + 4].try_into().unwrap()),
                        pointer + group * 32768
                    );
                }
                assert!(
                    reserved[backup_groups.len() * 4..]
                        .iter()
                        .all(|byte| *byte == 0)
                );
            } else {
                assert_eq!(pointer, 0);
            }
        }
        let journal = reader.get_inode(8).unwrap();
        let ranges = crate::ext4::extent::parse_extents(&journal, 4096, &mut file).unwrap();
        let first = ranges.first().unwrap().0;
        read_at(&mut file, first as u64 * 4096, &mut bitmap);
        assert_eq!(
            u32::from_be_bytes(bitmap[0..4].try_into().unwrap()),
            0xc03b3998
        );
        assert_eq!(u32::from_be_bytes(bitmap[4..8].try_into().unwrap()), 4);
        assert_eq!(u32::from_be_bytes(bitmap[12..16].try_into().unwrap()), 4096);
        let journal_blocks =
            crate::ext4::journal::default_journal_blocks(result.filesystem_bytes / 4096);
        assert_eq!(
            u32::from_be_bytes(bitmap[16..20].try_into().unwrap()),
            journal_blocks
        );
        assert_eq!(journal.file_size(), journal_blocks as u64 * 4096);
        assert_eq!(&bitmap[20..28], &[0, 0, 0, 1, 0, 0, 0, 1]);
        assert!(bitmap[28..48].iter().all(|byte| *byte == 0));
        assert_eq!(&bitmap[48..64], &sb.uuid);
        assert_eq!(&bitmap[64..68], &[0, 0, 0, 1]);
    }

    #[test]
    fn upper_minimum_partial_groups_and_short_tails() {
        let directory = tempfile::tempdir().unwrap();
        for bytes in [
            64 << 20,
            128 << 20,
            (128 << 20) + 4096,
            (128 << 20) + 580 * 4096,
            (128 << 20) + 581 * 4096,
            (256 << 20) + 515 * 4096,
            (256 << 20) + 516 * 4096,
            4u64 << 30,
            (16u64 << 30) + 4096,
            (16u64 << 30) + 516 * 4096,
        ] {
            let path = directory.path().join(format!("upper-{bytes}.raw"));
            let result = format_upper(&path, UpperCapacity::new(bytes).unwrap()).unwrap();
            inspect(&path, result);
        }
    }

    #[test]
    fn upper_one_tib_sparse_metadata_and_reservation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("upper.raw");
        let result = format_upper(&path, UpperCapacity::new(1u64 << 40).unwrap()).unwrap();
        inspect(&path, result);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert!(std::fs::metadata(&path).unwrap().blocks() * 512 < 256 << 20);
        }
    }

    #[test]
    fn upper_refuses_overwrite_and_symlinks_and_has_private_mode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("upper.raw");
        let capacity = UpperCapacity::new(64 << 20).unwrap();
        std::fs::write(&path, b"persistent work/index must survive").unwrap();
        assert!(format_upper(&path, capacity).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"persistent work/index must survive"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            let link = directory.path().join("link.raw");
            symlink(&path, &link).unwrap();
            assert!(format_upper(&link, capacity).is_err());
            let dangling = directory.path().join("dangling.raw");
            let absent = directory.path().join("absent.raw");
            symlink(&absent, &dangling).unwrap();
            assert!(format_upper(&dangling, capacity).is_err());
            assert!(!absent.exists());
            let first = directory.path().join("first.raw");
            let second = directory.path().join("second.raw");
            let a = format_upper(&first, capacity).unwrap();
            let b = format_upper(&second, capacity).unwrap();
            assert_ne!(a.uuid, b.uuid);
            assert_eq!(
                std::fs::metadata(&first).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
