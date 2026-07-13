//! JBD2 journal construction for newly formatted filesystems.

use uuid::Uuid;

pub(crate) const JOURNAL_INODE_NUMBER: u32 = 8;
pub(crate) const JOURNAL_BACKUP_BLOCKS: u8 = 1;

const JBD2_MAGIC_NUMBER: u32 = 0xC03B_3998;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_MIN_JOURNAL_BLOCKS: u32 = 1024;

/// Match e2fsprogs' journal-size ladder. The input is the initial filesystem
/// size in 4 KiB blocks.
pub(crate) fn default_journal_blocks(filesystem_blocks: u64) -> u32 {
    if filesystem_blocks < 32_768 {
        JBD2_MIN_JOURNAL_BLOCKS
    } else if filesystem_blocks < 256 * 1024 {
        4096
    } else if filesystem_blocks < 512 * 1024 {
        8192
    } else if filesystem_blocks < 4096 * 1024 {
        16_384
    } else if filesystem_blocks < 8192 * 1024 {
        32_768
    } else if filesystem_blocks < 16_384 * 1024 {
        65_536
    } else if filesystem_blocks < 32_768 * 1024 {
        131_072
    } else {
        262_144
    }
}

/// Build a clean JBD2 v2 superblock in one filesystem block.
pub(crate) fn superblock(block_size: u32, journal_blocks: u32, uuid: Uuid) -> Vec<u8> {
    let mut block = vec![0u8; block_size as usize];
    put_be32(&mut block, 0x00, JBD2_MAGIC_NUMBER);
    put_be32(&mut block, 0x04, JBD2_SUPERBLOCK_V2);
    put_be32(&mut block, 0x0C, block_size);
    put_be32(&mut block, 0x10, journal_blocks);
    put_be32(&mut block, 0x14, 1); // First usable log block.
    put_be32(&mut block, 0x18, 1); // First transaction sequence.
    block[0x30..0x40].copy_from_slice(uuid.as_bytes());
    put_be32(&mut block, 0x40, 1); // One filesystem uses this journal.
    block
}

fn put_be32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use crate::journal::{default_journal_blocks, superblock};

    use uuid::Uuid;

    #[test]
    fn journal_size_matches_e2fsprogs_ladder() {
        assert_eq!(default_journal_blocks(16_384), 1024);
        assert_eq!(default_journal_blocks(32_768), 4096);
        assert_eq!(default_journal_blocks(131_072), 4096);
        assert_eq!(default_journal_blocks(262_144), 8192);
        assert_eq!(default_journal_blocks(1_048_576), 16_384);
    }

    #[test]
    fn clean_superblock_uses_jbd2_big_endian_layout() {
        let uuid = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").expect("valid UUID");
        let block = superblock(4096, 4096, uuid);

        assert_eq!(&block[0x00..0x04], &0xC03B_3998u32.to_be_bytes());
        assert_eq!(&block[0x04..0x08], &4u32.to_be_bytes());
        assert_eq!(&block[0x0C..0x10], &4096u32.to_be_bytes());
        assert_eq!(&block[0x10..0x14], &4096u32.to_be_bytes());
        assert_eq!(&block[0x14..0x18], &1u32.to_be_bytes());
        assert_eq!(&block[0x18..0x1C], &1u32.to_be_bytes());
        assert_eq!(&block[0x1C..0x20], &[0; 4]);
        assert_eq!(&block[0x30..0x40], uuid.as_bytes());
        assert_eq!(&block[0x40..0x44], &1u32.to_be_bytes());
    }
}
