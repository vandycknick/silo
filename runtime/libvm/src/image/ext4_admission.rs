//! Bounded ext4 root admission for imported raw disks.
//!
//! Reads exactly one superblock from the selected byte range of owned decoded
//! bytes. It never mounts, runs fsck or walks the filesystem: the admitted
//! guest kernel performs full validation at mount. This check rejects what the
//! pinned kernel profile cannot mount writable, so a runnable image is never
//! published for a filesystem that is certain to fail at boot.
//!
//! ```text
//!   selected range ──► [1024 pad][superblock 1024] ──► admit_superblock()
//!                       offset+1024, one exact read       magic, revision,
//!                                                         block geometry,
//!                                                         feature allowlist,
//!                                                         clean state, csum
//! ```

use std::fs::File;
use std::os::unix::fs::FileExt;

use disk_image::ext4::constants::{
    compat, incompat, ro_compat, SUPERBLOCK_MAGIC, SUPERBLOCK_OFFSET,
};

use crate::image::import::DiskImportError;
use crate::LibVmError;

const SUPERBLOCK_BYTES: usize = 1024;

/// Kernel 6.x `orphan_file` feature (EXT4_FEATURE_COMPAT_ORPHAN_FILE is the
/// compat flag; this ro_compat bit records a non-empty orphan file).
const RO_COMPAT_ORPHAN_PRESENT: u32 = 0x2_0000;

/// Writable-mount incompat features of the pinned workload kernel. Built-in
/// ext4 without fscrypt, unicode casefolding or the Lustre-only dirdata.
/// `RECOVER` is excluded: a source that needs journal replay was not quiesced.
const ADMITTED_INCOMPAT: u32 = incompat::FILETYPE
    | incompat::META_BG
    | incompat::EXTENTS
    | incompat::BIT64
    | incompat::MMP
    | incompat::FLEX_BG
    | incompat::EA_INODE
    | incompat::CSUM_SEED
    | incompat::LARGEDIR
    | incompat::INLINE_DATA;

/// Writable-mount ro_compat features of the pinned workload kernel. Quota,
/// project quota and verity are not configured; snapshot, replica, read-only
/// and shared-block filesystems are not writable roots.
const ADMITTED_RO_COMPAT: u32 = ro_compat::SPARSE_SUPER
    | ro_compat::LARGE_FILE
    | ro_compat::BTREE_DIR
    | ro_compat::HUGE_FILE
    | ro_compat::GDT_CSUM
    | ro_compat::DIR_NLINK
    | ro_compat::EXTRA_ISIZE
    | ro_compat::BIGALLOC
    | ro_compat::METADATA_CSUM;

const STATE_VALID: u16 = 0x1;
const STATE_ERROR: u16 = 0x2;
const CHECKSUM_TYPE_CRC32C: u8 = 1;
/// Admitted kernels use 4 KiB pages; ext4 rejects blocks larger than a page.
const MAX_LOG_BLOCK_SIZE: u32 = 2;

/// A selected root range that the pinned kernel cannot mount writable as ext4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Ext4Rejection {
    #[error("selected root range of {} cannot hold an ext4 superblock", utils::format_storage_size(*length))]
    RangeTooSmall { length: u64 },
    #[error("selected root range is not ext4 (superblock magic {magic:#06x})")]
    NotExt4 { magic: u16 },
    #[error("ext4 revision {revision} is not admitted; only dynamic revision 1 is")]
    Revision { revision: u32 },
    #[error("ext4 log block size {log_block_size} is not admitted; blocks must be 1-4 KiB")]
    BlockSize { log_block_size: u32 },
    #[error(
        "ext4 cluster size log {log_cluster_size} contradicts block size log {log_block_size}"
    )]
    ClusterSize {
        log_block_size: u32,
        log_cluster_size: u32,
    },
    #[error("ext4 first data block {first_data_block} contradicts the block size")]
    FirstDataBlock { first_data_block: u32 },
    #[error("ext4 inode size {} is not a power of two between 128 and the block size", utils::format_storage_size(u64::from(*inode_size)))]
    InodeSize { inode_size: u16 },
    #[error("ext4 incompatible features {features:#x} are not supported by the admitted kernel")]
    IncompatibleFeatures { features: u32 },
    #[error("ext4 read-only-compatible features {features:#x} prevent a writable admitted root")]
    ReadOnlyCompatibleFeatures { features: u32 },
    #[error("ext4 uses an external journal device")]
    ExternalJournal,
    #[error("ext4 declares a journal without a journal inode")]
    MissingJournalInode,
    #[error("ext4 needs journal or orphan recovery; unmount it cleanly before import")]
    NeedsRecovery,
    #[error("ext4 was not cleanly unmounted or recorded errors; run fsck offline before import")]
    NotClean,
    #[error("ext4 checksum type {checksum_type} is not crc32c")]
    ChecksumType { checksum_type: u8 },
    #[error("ext4 superblock checksum {stored:#010x} does not match {computed:#010x}")]
    Checksum { stored: u32, computed: u32 },
    #[error(
        "ext4 declares {}, larger than its {} root range",
        utils::format_storage_size(*filesystem_bytes),
        utils::format_storage_size(*range_bytes)
    )]
    Truncated {
        filesystem_bytes: u64,
        range_bytes: u64,
    },
}

/// Observed facts of an admitted superblock, not persisted identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ext4Facts {
    pub(crate) block_size: u32,
    pub(crate) blocks: u64,
}

/// Admit the ext4 filesystem at `[offset, offset + length)` of a held owned
/// decoded stream. Exactly one bounded positional read; the cursor is unused.
pub(crate) fn admit(file: &File, offset: u64, length: u64) -> Result<Ext4Facts, LibVmError> {
    let end = SUPERBLOCK_OFFSET + SUPERBLOCK_BYTES as u64;
    if length < end {
        return Err(DiskImportError::from(Ext4Rejection::RangeTooSmall { length }).into());
    }
    let position = offset
        .checked_add(SUPERBLOCK_OFFSET)
        .ok_or_else(|| std::io::Error::other("ext4 superblock offset overflow"))?;
    let mut superblock = [0; SUPERBLOCK_BYTES];
    file.read_exact_at(&mut superblock, position)?;
    Ok(admit_superblock(&superblock, length).map_err(DiskImportError::from)?)
}

/// Pure admission over one superblock and the byte length of its range.
pub(crate) fn admit_superblock(
    superblock: &[u8; SUPERBLOCK_BYTES],
    range_bytes: u64,
) -> Result<Ext4Facts, Ext4Rejection> {
    let magic = le16(superblock, 0x38);
    if magic != SUPERBLOCK_MAGIC {
        return Err(Ext4Rejection::NotExt4 { magic });
    }
    let revision = le32(superblock, 0x4c);
    if revision != 1 {
        return Err(Ext4Rejection::Revision { revision });
    }
    let feature_compat = le32(superblock, 0x5c);
    let feature_incompat = le32(superblock, 0x60);
    let feature_ro_compat = le32(superblock, 0x64);

    if feature_incompat & incompat::JOURNAL_DEV != 0 {
        return Err(Ext4Rejection::ExternalJournal);
    }
    if feature_incompat & incompat::RECOVER != 0
        || feature_ro_compat & RO_COMPAT_ORPHAN_PRESENT != 0
    {
        return Err(Ext4Rejection::NeedsRecovery);
    }
    let unadmitted = feature_incompat & !ADMITTED_INCOMPAT;
    if unadmitted != 0 {
        return Err(Ext4Rejection::IncompatibleFeatures {
            features: unadmitted,
        });
    }
    // orphan_file's ro_compat marker is only meaningful with its compat flag;
    // an empty orphan file is clean, a present one already failed above.
    let unadmitted = feature_ro_compat & !ADMITTED_RO_COMPAT;
    if unadmitted != 0 {
        return Err(Ext4Rejection::ReadOnlyCompatibleFeatures {
            features: unadmitted,
        });
    }
    if feature_compat & compat::HAS_JOURNAL != 0 && le32(superblock, 0xe0) == 0 {
        return Err(Ext4Rejection::MissingJournalInode);
    }

    let state = le16(superblock, 0x3a);
    if state & STATE_VALID == 0 || state & STATE_ERROR != 0 {
        return Err(Ext4Rejection::NotClean);
    }

    let log_block_size = le32(superblock, 0x18);
    if log_block_size > MAX_LOG_BLOCK_SIZE {
        return Err(Ext4Rejection::BlockSize { log_block_size });
    }
    let block_size = 1024_u32 << log_block_size;
    let log_cluster_size = le32(superblock, 0x1c);
    let bigalloc = feature_ro_compat & ro_compat::BIGALLOC != 0;
    if (!bigalloc && log_cluster_size != log_block_size)
        || (bigalloc && log_cluster_size < log_block_size)
    {
        return Err(Ext4Rejection::ClusterSize {
            log_block_size,
            log_cluster_size,
        });
    }
    let first_data_block = le32(superblock, 0x14);
    if first_data_block != u32::from(block_size == 1024) {
        return Err(Ext4Rejection::FirstDataBlock { first_data_block });
    }
    let inode_size = le16(superblock, 0x58);
    if !inode_size.is_power_of_two() || inode_size < 128 || u32::from(inode_size) > block_size {
        return Err(Ext4Rejection::InodeSize { inode_size });
    }

    if feature_ro_compat & ro_compat::METADATA_CSUM != 0 {
        let checksum_type = superblock[0x175];
        if checksum_type != CHECKSUM_TYPE_CRC32C {
            return Err(Ext4Rejection::ChecksumType { checksum_type });
        }
        let stored = le32(superblock, 0x3fc);
        // Linux stores the raw reflected CRC-32C update without final XOR.
        let computed = crc32c_update(u32::MAX, &superblock[..0x3fc]);
        if stored != computed {
            return Err(Ext4Rejection::Checksum { stored, computed });
        }
    }

    let mut blocks = u64::from(le32(superblock, 0x04));
    if feature_incompat & incompat::BIT64 != 0 {
        blocks |= u64::from(le32(superblock, 0x150)) << 32;
    }
    let filesystem_bytes = blocks
        .checked_mul(u64::from(block_size))
        .filter(|bytes| *bytes != 0)
        .ok_or(Ext4Rejection::Truncated {
            filesystem_bytes: u64::MAX,
            range_bytes,
        })?;
    if filesystem_bytes > range_bytes {
        return Err(Ext4Rejection::Truncated {
            filesystem_bytes,
            range_bytes,
        });
    }
    Ok(Ext4Facts { block_size, blocks })
}

fn le16(bytes: &[u8; SUPERBLOCK_BYTES], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le32(bytes: &[u8; SUPERBLOCK_BYTES], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Reflected CRC-32C (Castagnoli) update, bitwise like the other on-disk
/// checksum helpers. Only one 1020-byte superblock is ever checksummed.
fn crc32c_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use disk_image::ext4::constants::{incompat, ro_compat};

    use crate::image::ext4_admission::{
        admit, admit_superblock, crc32c_update, Ext4Facts, Ext4Rejection, SUPERBLOCK_BYTES,
    };
    use crate::image::import::DiskImportError;
    use crate::LibVmError;

    fn rejection(result: Result<Ext4Facts, LibVmError>) -> Ext4Rejection {
        match result {
            Err(LibVmError::DiskImport(error)) => match *error {
                DiskImportError::RootFilesystem(rejection) => rejection,
                other => panic!("unexpected import error {other:?}"),
            },
            other => panic!("expected ext4 rejection, got {other:?}"),
        }
    }

    fn formatted() -> (tempfile::TempDir, std::fs::File, u64) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("root.ext4");
        disk_image::ext4::Formatter::new(&path, 4096, 256 * 1024)
            .unwrap()
            .close()
            .unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let length = file.metadata().unwrap().len();
        (temp, file, length)
    }

    fn superblock(file: &std::fs::File) -> [u8; SUPERBLOCK_BYTES] {
        use std::os::unix::fs::FileExt;
        let mut bytes = [0; SUPERBLOCK_BYTES];
        file.read_exact_at(&mut bytes, 1024).unwrap();
        bytes
    }

    fn put32(bytes: &mut [u8; SUPERBLOCK_BYTES], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put16(bytes: &mut [u8; SUPERBLOCK_BYTES], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn get32(bytes: &[u8; SUPERBLOCK_BYTES], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn admits_silo_formatted_ext4_with_exact_facts() {
        let (_temp, file, length) = formatted();
        let facts = admit(&file, 0, length).unwrap();
        assert_eq!(facts.block_size, 4096);
        assert_eq!(facts.blocks * 4096, length);
    }

    #[test]
    fn crc32c_matches_the_castagnoli_check_vector() {
        // CRC-32C("123456789") = 0xe3069283 after the final inversion.
        assert_eq!(!crc32c_update(u32::MAX, b"123456789"), 0xe306_9283);
    }

    #[test]
    fn metadata_checksum_is_verified_not_trusted() {
        let (_temp, file, length) = formatted();
        let mut bytes = superblock(&file);
        let features = (get32(&bytes, 0x64) & !ro_compat::GDT_CSUM) | ro_compat::METADATA_CSUM;
        put32(&mut bytes, 0x64, features);
        bytes[0x175] = 1;
        let checksum = crc32c_update(u32::MAX, &bytes[..0x3fc]);
        put32(&mut bytes, 0x3fc, checksum);
        assert_eq!(
            admit_superblock(&bytes, length),
            Ok(Ext4Facts {
                block_size: 4096,
                blocks: length / 4096
            })
        );

        put32(&mut bytes, 0x3fc, checksum ^ 1);
        assert_eq!(
            admit_superblock(&bytes, length),
            Err(Ext4Rejection::Checksum {
                stored: checksum ^ 1,
                computed: checksum
            })
        );
        bytes[0x175] = 2;
        assert_eq!(
            admit_superblock(&bytes, length),
            Err(Ext4Rejection::ChecksumType { checksum_type: 2 })
        );
    }

    #[test]
    fn rejects_every_unadmitted_feature_and_state() {
        let (_temp, file, length) = formatted();
        let clean = superblock(&file);
        let incompat_base = get32(&clean, 0x60);
        let ro_base = get32(&clean, 0x64);
        use Patch::{U16, U32};
        let cases = [
            (
                vec![U16(0x38, 0x1234)],
                Ext4Rejection::NotExt4 { magic: 0x1234 },
            ),
            (vec![U32(0x4c, 0)], Ext4Rejection::Revision { revision: 0 }),
            (
                vec![U32(0x60, incompat_base | incompat::RECOVER)],
                Ext4Rejection::NeedsRecovery,
            ),
            (
                vec![U32(0x64, ro_base | 0x2_0000)],
                Ext4Rejection::NeedsRecovery,
            ),
            (
                vec![U32(0x60, incompat_base | incompat::JOURNAL_DEV)],
                Ext4Rejection::ExternalJournal,
            ),
            (
                vec![U32(0x60, incompat_base | incompat::ENCRYPT)],
                Ext4Rejection::IncompatibleFeatures {
                    features: incompat::ENCRYPT,
                },
            ),
            (
                vec![U32(0x60, incompat_base | 0x2_0000)],
                Ext4Rejection::IncompatibleFeatures { features: 0x2_0000 },
            ),
            (
                vec![U32(0x60, incompat_base | incompat::COMPRESSION)],
                Ext4Rejection::IncompatibleFeatures {
                    features: incompat::COMPRESSION,
                },
            ),
            (
                vec![U32(0x64, ro_base | ro_compat::READONLY)],
                Ext4Rejection::ReadOnlyCompatibleFeatures {
                    features: ro_compat::READONLY,
                },
            ),
            (
                vec![U32(0x64, ro_base | ro_compat::QUOTA)],
                Ext4Rejection::ReadOnlyCompatibleFeatures {
                    features: ro_compat::QUOTA,
                },
            ),
            (
                vec![U32(0x64, ro_base | 0x8000)],
                Ext4Rejection::ReadOnlyCompatibleFeatures { features: 0x8000 },
            ),
            (vec![U32(0xe0, 0)], Ext4Rejection::MissingJournalInode),
            (vec![U16(0x3a, 0)], Ext4Rejection::NotClean),
            (vec![U16(0x3a, 3)], Ext4Rejection::NotClean),
            (
                vec![U32(0x18, 3), U32(0x1c, 3)],
                Ext4Rejection::BlockSize { log_block_size: 3 },
            ),
            (
                vec![U32(0x1c, 4)],
                Ext4Rejection::ClusterSize {
                    log_block_size: 2,
                    log_cluster_size: 4,
                },
            ),
            (
                vec![U32(0x14, 1)],
                Ext4Rejection::FirstDataBlock {
                    first_data_block: 1,
                },
            ),
            (
                vec![U16(0x58, 96)],
                Ext4Rejection::InodeSize { inode_size: 96 },
            ),
        ];
        for (patches, expected) in cases {
            let mut bytes = clean;
            for patch in &patches {
                match *patch {
                    U16(offset, value) => put16(&mut bytes, offset, value),
                    U32(offset, value) => put32(&mut bytes, offset, value),
                }
            }
            assert_eq!(
                admit_superblock(&bytes, length),
                Err(expected),
                "{patches:?}"
            );
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum Patch {
        U16(usize, u16),
        U32(usize, u32),
    }

    #[test]
    fn rejects_filesystems_larger_than_their_range_and_tiny_ranges() {
        let (_temp, file, length) = formatted();
        assert_eq!(
            rejection(admit(&file, 0, length - 4096)),
            Ext4Rejection::Truncated {
                filesystem_bytes: length,
                range_bytes: length - 4096,
            }
        );
        assert_eq!(
            rejection(admit(&file, 0, 2047)),
            Ext4Rejection::RangeTooSmall { length: 2047 }
        );
        let mut bytes = superblock(&file);
        put32(&mut bytes, 0x04, 0);
        put32(&mut bytes, 0x150, 0);
        assert!(matches!(
            admit_superblock(&bytes, length),
            Err(Ext4Rejection::Truncated { .. })
        ));
    }

    #[test]
    fn reads_the_superblock_relative_to_the_selected_range() {
        let (source, _file, length) = formatted();
        let temp = tempfile::tempdir().unwrap();
        let shifted = temp.path().join("shifted");
        let mut bytes = vec![0; 1 << 20];
        bytes.extend(std::fs::read(source.path().join("root.ext4")).unwrap());
        std::fs::write(&shifted, bytes).unwrap();
        let shifted = std::fs::File::open(shifted).unwrap();
        assert!(admit(&shifted, 1 << 20, length).is_ok());
        assert!(matches!(
            rejection(admit(&shifted, 0, length)),
            Ext4Rejection::NotExt4 { .. }
        ));
    }
}
