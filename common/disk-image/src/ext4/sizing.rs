//! Sufficient generic-formatter geometry from the final unique namespace.
//! This is not upper capacity, usable capacity, or logical sparse-file length.

use crate::ext4::constants::{EXT4_NAME_LEN, FileType, INODE_EXTRA_SIZE};
use crate::ext4::error::{FormatError, FormatResult};
use crate::ext4::xattr::XattrState;
use crate::ext4::{extent, journal, layout};

#[derive(Clone, Debug, Default)]
pub struct FormatSizing {
    inodes: u64,
    blocks: u64,
}

impl FormatSizing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Account each shared inode once, including root. `data_blocks` is the
    /// union of touched logical 4K blocks, not the logical length of holes.
    /// `extent_records` counts input ranges; physical splitting is budgeted here.
    pub fn add_inode(
        &mut self,
        mode: u16,
        data_blocks: u64,
        extent_records: u64,
        xattrs: &[(&[u8], &[u8])],
    ) -> FormatResult<()> {
        if FileType::from_mode(mode) == FileType::Unknown {
            return Err(FormatError::UnsupportedFiletype);
        }
        let attrs = XattrState::from_linux(0, xattrs, INODE_EXTRA_SIZE, 4096)?;
        let index_blocks = if data_blocks == 0 {
            0
        } else {
            // Input logical runs, 32768-block extent splitting, and physical
            // discontinuities across group-start system zones. A group has at
            // least 32768 - 1025 nonsystem blocks even at maximum GDT reserve.
            // Small files therefore do not each invent a whole index block.
            let records = extent_records
                .max(1)
                .min(data_blocks)
                .checked_add(data_blocks / 32768)
                .and_then(|count| count.checked_add(data_blocks.div_ceil(32768 - 1025)))
                .ok_or(FormatError::SizeOverflow)?;
            extent::metadata_blocks_for_records(records, 4096)? as u64
        };
        let added = data_blocks
            .checked_add(index_blocks)
            .and_then(|blocks| blocks.checked_add(u64::from(attrs.has_block())))
            .ok_or(FormatError::SizeOverflow)?;
        self.blocks = self
            .blocks
            .checked_add(added)
            .ok_or(FormatError::SizeOverflow)?;
        self.inodes = self
            .inodes
            .checked_add(1)
            .ok_or(FormatError::SizeOverflow)?;
        Ok(())
    }

    /// Account directory payload using the actual writer's four-byte record
    /// alignment and twelve-byte trailing terminator, including dot/dot-dot.
    /// Names include hardlink aliases but not implicit formatter lost+found.
    pub fn add_directory<'a>(
        &mut self,
        names: impl IntoIterator<Item = &'a [u8]>,
    ) -> FormatResult<()> {
        let mut blocks = 1u64;
        let mut left = 4096 - 24;
        for name in names {
            if name.is_empty()
                || name.len() > EXT4_NAME_LEN
                || name.contains(&0)
                || name.contains(&b'/')
            {
                return Err(FormatError::InvalidName(format!("{name:?}")));
            }
            let size = (name.len() + 8).next_multiple_of(4);
            if left < size + 12 {
                blocks = blocks.checked_add(1).ok_or(FormatError::SizeOverflow)?;
                left = 4096;
            }
            left -= size;
        }
        let records = 1 + blocks / 32768 + blocks.div_ceil(32768 - 1025);
        let indices = extent::metadata_blocks_for_records(records, 4096)? as u64;
        self.blocks = self
            .blocks
            .checked_add(blocks)
            .and_then(|count| count.checked_add(indices))
            .ok_or(FormatError::SizeOverflow)?;
        Ok(())
    }

    /// Whole-group minimum large enough for data, journal, classic GDT and
    /// backups, flex placement, inode tables and bitmaps. Generic optimization
    /// selects 8192..32768 inodes/group; budget its largest table (2048 blocks)
    /// and checks inode capacity at that choice. Optimization can only improve
    /// this bound; it is not an exact usable/free-capacity promise.
    pub fn minimum_size_bytes(&self) -> FormatResult<u64> {
        let inodes = self
            .inodes
            .checked_add(10)
            .ok_or(FormatError::SizeOverflow)?;
        let mut groups = inodes.div_ceil(32768).max(1);
        let payload = self
            .blocks
            .checked_add(2)
            .ok_or(FormatError::SizeOverflow)?; // lost+found + resize dind
        loop {
            if groups > 8192 {
                return Err(FormatError::InvalidSize {
                    size: groups.saturating_mul(128 << 20),
                    reason: "materialized lower exceeds 1 TiB",
                });
            }
            let descriptor_blocks = groups.div_ceil(128) as u32;
            let area = layout::generic_descriptor_area(descriptor_blocks, 4096) as u64;
            let backups = (0..groups as u32)
                .filter(|group| layout::has_sparse_super(*group))
                .count() as u64;
            let journal_blocks = journal::default_journal_blocks(groups * 32768) as u64;
            let journal_indices =
                extent::metadata_blocks_for_records(journal_blocks.div_ceil(32768) + 64, 4096)?
                    as u64;
            let needed = payload
                .checked_add(journal_blocks)
                .and_then(|blocks| blocks.checked_add(journal_indices))
                .and_then(|blocks| blocks.checked_add(groups * (2048 + 2)))
                .and_then(|blocks| blocks.checked_add(backups * (1 + area)))
                .ok_or(FormatError::SizeOverflow)?;
            let next = needed.div_ceil(32768).max(inodes.div_ceil(32768));
            if next <= groups {
                return Ok(groups * (128 << 20));
            }
            groups = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ext4::constants::file_mode;
    use crate::ext4::sizing::FormatSizing;

    #[test]
    fn dense_split_fixture_sizes_from_bytes_not_a_fixed_minimum() {
        let mut sizing = FormatSizing::new();
        sizing
            .add_inode(file_mode::S_IFDIR | 0o755, 0, 0, &[])
            .unwrap();
        sizing.add_directory([b"large".as_slice()]).unwrap();
        sizing
            .add_inode(file_mode::S_IFREG | 0o644, (2304u64 << 20) / 4096, 1, &[])
            .unwrap();
        let bytes = sizing.minimum_size_bytes().unwrap();
        assert!(bytes > 2304u64 << 20);
        assert!(bytes < 3u64 << 30);
    }

    #[test]
    fn sparse_logical_length_does_not_inflate_payload_budget() {
        let mut sizing = FormatSizing::new();
        sizing
            .add_inode(file_mode::S_IFREG | 0o644, 2, 2, &[])
            .unwrap();
        assert_eq!(sizing.minimum_size_bytes().unwrap(), 128 << 20);
        assert!(
            sizing
                .add_inode(file_mode::S_IFREG, u64::MAX, 1, &[])
                .is_err()
        );
    }
}
