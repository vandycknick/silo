// Core ext4 image formatter.
//
// Creates ext4 filesystem images from scratch using a single-pass sequential
// write strategy.  The public entry point is `Formatter::new()` followed by
// repeated `create()` / `link()` / `remove()` calls, finalized with `close()`.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rootfs_spec::upper_geometry::{self, UpperCapacity, UpperGeometry};
use uuid::Uuid;

use crate::ext4::checksum;
use crate::ext4::constants::*;
use crate::ext4::dir;
use crate::ext4::error::{FormatError, FormatResult};
use crate::ext4::extent;
use crate::ext4::file_tree::{BlockRange, FileTree, FileTreeNode};
use crate::ext4::input::{DeviceId, FileData, SparseData};
use crate::ext4::journal;
use crate::ext4::types::*;
use crate::ext4::xattr::XattrState;

/// Maximum bytes that fit in the ext4 superblock's `volume_name` field.
const VOLUME_NAME_LEN: usize = 16;
/// Reserved inode number used by ext2/3/4 for online-resize metadata.
const RESIZE_INODE_NUMBER: u32 = 7;
/// `i_block[13]` is the double-indirect block pointer in legacy inode layout.
const EXT2_DIND_BLOCK: usize = 13;
/// Number of direct block pointers before indirect pointers in legacy layout.
const EXT2_NDIR_BLOCKS: u64 = 12;

// ---------------------------------------------------------------------------
// FormatOptions
// ---------------------------------------------------------------------------

/// Parameters for creating a new ext4 image.
///
/// Construct via [`FormatOptions::new`] and layer on [`uuid`] / [`label`] as
/// needed. The resulting options are passed to [`Formatter::with_options`].
///
/// [`uuid`]: Self::uuid
/// [`label`]: Self::label
#[derive(Clone, Debug)]
pub struct FormatOptions {
    /// Block size in bytes. Only 4096 is currently accepted; the field is
    /// explicit so future versions can widen the accepted set without another
    /// API break.
    pub block_size: u32,
    /// Total size of the image file in bytes.
    pub size: u64,
    /// UUID written to the superblock. `None` picks a random v4 UUID at
    /// format time.
    pub uuid: Option<Uuid>,
    /// Volume label. Must be ≤ 16 bytes UTF-8 and contain no NUL bytes.
    /// `None` leaves the field zeroed.
    pub label: Option<String>,
}

impl FormatOptions {
    /// Create options for an image of the given size, with default
    /// `block_size = 4096`, random UUID, no label.
    pub fn new(size: u64) -> Self {
        Self {
            block_size: 4096,
            size,
            uuid: None,
            label: None,
        }
    }

    /// Set an explicit UUID instead of a randomly generated one.
    pub fn uuid(mut self, uuid: Uuid) -> Self {
        self.uuid = Some(uuid);
        self
    }

    /// Set the volume label.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

fn validate_label(label: &str) -> FormatResult<()> {
    if label.len() > VOLUME_NAME_LEN {
        return Err(FormatError::InvalidLabel(format!(
            "label {label:?} is {} bytes, ext4 limit is {VOLUME_NAME_LEN}",
            label.len()
        )));
    }
    if label.contains('\0') {
        return Err(FormatError::InvalidLabel(format!(
            "label {label:?} contains a NUL byte"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FileTimestamps
// ---------------------------------------------------------------------------

/// Timestamps to apply to a newly created inode.
///
/// Each pair is `(seconds_lo, extra)` in ext4 format -- the same layout
/// returned by `timestamp_now()`.
#[derive(Clone, Copy, Debug)]
pub struct FileTimestamps {
    pub access_lo: u32,
    pub access_hi: u32,
    pub modification_lo: u32,
    pub modification_hi: u32,
    pub creation_lo: u32,
    pub creation_hi: u32,
    pub now_lo: u32,
    pub now_hi: u32,
}

impl FileTimestamps {
    /// Encode a nonnegative Unix mtime using ext4's signed low seconds and
    /// two epoch bits. In particular, 2038..2106 needs the sign-carry epoch.
    pub fn from_mtime(seconds: u64, nanos: u32) -> FormatResult<Self> {
        if seconds > 0x3_7fff_ffff || nanos >= 1_000_000_000 {
            return Err(FormatError::InvalidMetadata("timestamp outside ext4 range"));
        }
        let lo = seconds as u32;
        let signed_low = lo as i32 as i64;
        let epoch = ((seconds as i64 - signed_low) >> 32) as u32;
        let extra = (nanos << 2) | epoch;
        Ok(Self {
            access_lo: lo,
            access_hi: extra,
            modification_lo: lo,
            modification_hi: extra,
            creation_lo: lo,
            creation_hi: extra,
            now_lo: lo,
            now_hi: extra,
        })
    }
}

impl Default for FileTimestamps {
    fn default() -> Self {
        let (lo, hi) = timestamp_now();
        Self {
            access_lo: lo,
            access_hi: hi,
            modification_lo: lo,
            modification_hi: hi,
            creation_lo: lo,
            creation_hi: hi,
            now_lo: lo,
            now_hi: hi,
        }
    }
}

// ---------------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------------

/// Single-pass ext4 image builder.
pub struct Formatter {
    file: File,
    block_size: u32,
    size: u64,
    inodes: Vec<Inode>,
    tree: FileTree,
    deleted_blocks: Vec<BlockRange>,
    /// Block ranges owned by inodes that still have links_count > 0 but
    /// whose original tree node has been detached.  Keyed by inode number.
    /// Used to reclaim blocks when the last hard-link reference is removed.
    deferred_blocks: HashMap<u32, Vec<BlockRange>>,
    /// UUID shared by ext4 metadata and the internal journal.
    uuid: Uuid,
    /// Volume label to copy into the superblock's `volume_name` field. Validated
    /// on construction.
    label: Option<String>,
    /// Present only for the fixed-capacity managed-upper entry point.
    upper_capacity: Option<UpperCapacity>,
    /// Physical primary/backup descriptor area reserved before journal/data.
    /// Appending data may consume this reservation, never enlarge it in place.
    allocated_descriptor_area_blocks: u32,
}

#[derive(Debug, Clone, Copy)]
struct FlexMetadataLayout {
    block_groups: u32,
    inode_table_offset: u32,
    bitmap_offset: u32,
    data_size: u32,
    total_groups: u32,
    gd_block_count: u32,
    gd_area_blocks: u32,
    size_bytes: u64,
}

impl Formatter {
    // -- Computed properties ------------------------------------------------

    #[inline]
    fn blocks_per_group(&self) -> u32 {
        self.block_size * 8
    }

    #[inline]
    fn max_inodes_per_group(&self) -> u32 {
        self.block_size * 8
    }

    #[inline]
    fn groups_per_descriptor_block(&self) -> u32 {
        self.block_size / 32
    }

    #[inline]
    fn block_count(&self) -> u32 {
        ((self.size - 1) / self.block_size as u64 + 1) as u32
    }

    #[inline]
    fn group_count(&self) -> u32 {
        (self.block_count() - 1) / self.blocks_per_group() + 1
    }

    #[inline]
    fn descriptor_blocks_for_groups(&self, groups: u32) -> u32 {
        (groups - 1) / self.groups_per_descriptor_block() + 1
    }

    #[inline]
    fn reserved_gdt_blocks_for_descriptor_blocks(&self, descriptor_blocks: u32) -> u32 {
        self.allocated_descriptor_area_blocks
            .saturating_sub(descriptor_blocks)
    }

    #[inline]
    fn group_descriptor_area_blocks_for_groups(&self, groups: u32) -> u32 {
        let descriptor_blocks = self.descriptor_blocks_for_groups(groups);
        descriptor_blocks + self.reserved_gdt_blocks_for_descriptor_blocks(descriptor_blocks)
    }

    #[inline]
    fn group_descriptor_blocks(&self) -> u32 {
        self.group_descriptor_area_blocks_for_groups(self.group_count())
    }

    #[inline]
    fn pos(&mut self) -> io::Result<u64> {
        self.file.stream_position()
    }

    #[inline]
    fn current_block(&mut self) -> io::Result<u32> {
        let block = self.pos()? / self.block_size as u64;
        u32::try_from(block).map_err(|_| io::Error::other("filesystem exceeds 32-bit block limit"))
    }

    fn seek_to_block(&mut self, block: u32) -> io::Result<()> {
        self.file
            .seek(SeekFrom::Start(block as u64 * self.block_size as u64))?;
        Ok(())
    }

    fn align_to_block(&mut self) -> io::Result<()> {
        let p = self.pos()?;
        if p % self.block_size as u64 != 0 {
            let blk = self
                .current_block()?
                .checked_add(1)
                .ok_or_else(|| io::Error::other("filesystem exceeds 32-bit block limit"))?;
            self.seek_to_block(blk)?;
        }
        Ok(())
    }

    #[inline]
    fn is_power_of(mut n: u32, base: u32) -> bool {
        if n < base {
            return false;
        }
        while n % base == 0 {
            n /= base;
        }
        n == 1
    }

    #[inline]
    fn has_sparse_super(group: u32) -> bool {
        group == 0
            || group == 1
            || Self::is_power_of(group, 3)
            || Self::is_power_of(group, 5)
            || Self::is_power_of(group, 7)
    }

    #[inline]
    fn has_sparse_super_backup(group: u32) -> bool {
        group != 0 && Self::has_sparse_super(group)
    }

    #[inline]
    fn static_metadata_blocks_in_group_for_area(&self, group: u32, gd_area_blocks: u32) -> u32 {
        if Self::has_sparse_super(group) {
            1 + gd_area_blocks
        } else {
            0
        }
    }

    #[inline]
    fn static_metadata_blocks_in_group(&self, group: u32) -> u32 {
        self.static_metadata_blocks_in_group_for_area(group, self.group_descriptor_blocks())
    }

    fn reserved_metadata_end_for_block(&self, block: u32) -> u32 {
        let group = block / self.blocks_per_group();
        let group_start = group * self.blocks_per_group();
        let metadata_blocks = self.static_metadata_blocks_in_group(group);
        let metadata_end = group_start + metadata_blocks;

        if block >= group_start && block < metadata_end {
            metadata_end
        } else {
            block
        }
    }

    fn skip_reserved_metadata_blocks(&mut self) -> io::Result<()> {
        if self.pos()? % self.block_size as u64 != 0 {
            return Ok(());
        }

        loop {
            let block = self.current_block()?;
            let next = self.reserved_metadata_end_for_block(block);
            if next == block {
                return Ok(());
            }
            self.seek_to_block(next)?;
        }
    }

    fn total_groups_for_data_end(&self, data_end: u64, minimum_disk_size_blocks: u32) -> u32 {
        let current_size_blocks = self.size.div_ceil(self.block_size as u64);
        let required_blocks = data_end
            .max(minimum_disk_size_blocks as u64)
            .max(current_size_blocks)
            .max(1);

        ((required_blocks - 1) / self.blocks_per_group() as u64 + 1) as u32
    }

    fn metadata_run_start_after_static_ranges(
        &self,
        mut start: u64,
        blocks: u64,
        total_groups: u32,
        gd_area_blocks: u32,
    ) -> u64 {
        loop {
            let end = start + blocks;
            let mut next_start = start;

            for group in 0..total_groups {
                let metadata_blocks =
                    self.static_metadata_blocks_in_group_for_area(group, gd_area_blocks) as u64;
                if metadata_blocks == 0 {
                    continue;
                }

                let group_start = group as u64 * self.blocks_per_group() as u64;
                let metadata_end = group_start + metadata_blocks;
                if block_ranges_overlap(start, end, group_start, metadata_end) {
                    next_start = metadata_end;
                    break;
                }
            }

            if next_start == start {
                return start;
            }
            start = next_start;
        }
    }

    fn flex_metadata_layout(
        &self,
        start_min: u32,
        mut block_groups: u32,
        inode_table_size_per_group: u32,
        minimum_disk_size_blocks: u32,
    ) -> FlexMetadataLayout {
        let mut start = start_min as u64;

        loop {
            let inode_table_blocks = block_groups as u64 * inode_table_size_per_group as u64;
            let metadata_blocks = inode_table_blocks + block_groups as u64 * 2;
            let data_end = start + metadata_blocks;
            let total_groups = self.total_groups_for_data_end(data_end, minimum_disk_size_blocks);
            let gd_area_blocks = self.group_descriptor_area_blocks_for_groups(total_groups);
            let adjusted_start = self.metadata_run_start_after_static_ranges(
                start,
                metadata_blocks,
                total_groups,
                gd_area_blocks,
            );
            let adjusted_data_end = adjusted_start + metadata_blocks;
            // Every group occupied by the shared run must use the shared
            // layout. Otherwise close() gives it overlapping local metadata.
            let adjusted_block_groups = block_groups
                .max(((adjusted_data_end - 1) / self.blocks_per_group() as u64 + 1) as u32);
            let adjusted_total_groups =
                self.total_groups_for_data_end(adjusted_data_end, minimum_disk_size_blocks);
            let adjusted_gd_area_blocks =
                self.group_descriptor_area_blocks_for_groups(adjusted_total_groups);

            if adjusted_start == start
                && adjusted_block_groups == block_groups
                && adjusted_total_groups == total_groups
                && adjusted_gd_area_blocks == gd_area_blocks
            {
                return FlexMetadataLayout {
                    block_groups: adjusted_block_groups,
                    inode_table_offset: adjusted_start as u32,
                    bitmap_offset: (adjusted_start + inode_table_blocks) as u32,
                    data_size: adjusted_data_end as u32,
                    total_groups: adjusted_total_groups,
                    gd_block_count: self.descriptor_blocks_for_groups(adjusted_total_groups),
                    gd_area_blocks: adjusted_gd_area_blocks,
                    size_bytes: adjusted_total_groups as u64
                        * self.blocks_per_group() as u64
                        * self.block_size as u64,
                };
            }

            start = adjusted_start;
            block_groups = adjusted_block_groups;
        }
    }

    fn free_ranges_before_shifted_metadata(
        &self,
        start: u32,
        end: u32,
        total_groups: u32,
        gd_area_blocks: u32,
    ) -> Vec<BlockRange> {
        let mut ranges = Vec::new();
        let mut cursor = start;

        while cursor < end {
            let group = cursor / self.blocks_per_group();
            if group >= total_groups {
                break;
            }

            let group_start = group * self.blocks_per_group();
            let group_end = group_start + self.blocks_per_group();
            let static_metadata_end = group_start
                + self
                    .static_metadata_blocks_in_group_for_area(group, gd_area_blocks)
                    .min(self.blocks_per_group());

            if cursor < static_metadata_end {
                cursor = static_metadata_end.min(end);
                continue;
            }

            let range_end = group_end.min(end);
            if cursor < range_end {
                ranges.push(BlockRange {
                    start: cursor,
                    end: range_end,
                });
            }
            cursor = range_end;
        }

        ranges
    }

    fn clear_block_range_from_bitmap(
        bitmap: &mut [u8],
        group_start: u32,
        group_end: u32,
        range: &BlockRange,
        used_blocks: &mut u32,
    ) {
        let start = range.start.max(group_start);
        let end = range.end.min(group_end);

        for block in start..end {
            let offset = block - group_start;
            let was_set = (bitmap[(offset / 8) as usize] >> (offset % 8)) & 1;
            bitmap[(offset / 8) as usize] &= !(1 << (offset % 8));
            if was_set != 0 {
                *used_blocks -= 1;
            }
        }
    }

    fn record_block_range(ranges: &mut Vec<BlockRange>, block: u32) {
        if let Some(last) = ranges.last_mut() {
            if block >= last.start && block < last.end {
                return;
            }
            if last.end == block {
                last.end += 1;
                return;
            }
        }

        ranges.push(BlockRange {
            start: block,
            end: block + 1,
        });
    }

    fn write_payload_bytes(
        &mut self,
        bytes: &[u8],
        ranges: &mut Vec<BlockRange>,
    ) -> io::Result<()> {
        let mut offset = 0usize;
        let block_size = self.block_size as usize;

        while offset < bytes.len() {
            self.skip_reserved_metadata_blocks()?;

            let block = self.current_block()?;
            let block_offset = (self.pos()? % self.block_size as u64) as usize;
            let writable = (block_size - block_offset).min(bytes.len() - offset);
            self.file.write_all(&bytes[offset..offset + writable])?;
            self.size = self.size.max(self.file.stream_position()?);
            Self::record_block_range(ranges, block);
            offset += writable;
        }

        Ok(())
    }

    fn write_payload_from_reader(
        &mut self,
        reader: &mut dyn Read,
        ranges: &mut Vec<BlockRange>,
    ) -> FormatResult<u64> {
        let mut size = 0u64;
        let mut buf = vec![0u8; self.block_size as usize];

        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > MAX_FILE_SIZE {
                return Err(FormatError::FileTooBig(size));
            }
            self.write_payload_bytes(&buf[..n], ranges)?;
        }

        Ok(size)
    }

    fn write_aligned_payload_bytes(&mut self, bytes: &[u8]) -> FormatResult<Vec<BlockRange>> {
        self.align_to_block()?;
        self.skip_reserved_metadata_blocks()?;
        let mut ranges = Vec::new();
        self.write_payload_bytes(bytes, &mut ranges)?;
        self.align_to_block()?;
        Ok(ranges)
    }

    fn allocate_sparse_blocks(&mut self, block_count: u32) -> FormatResult<Vec<BlockRange>> {
        self.align_to_block()?;
        let mut remaining = block_count;
        let mut ranges = Vec::new();

        while remaining > 0 {
            self.skip_reserved_metadata_blocks()?;
            let start = self.current_block()?;
            let group_end = (start / self.blocks_per_group() + 1)
                .checked_mul(self.blocks_per_group())
                .ok_or_else(|| io::Error::other("filesystem exceeds 32-bit block limit"))?;
            let count = remaining.min(group_end - start);
            let end = start
                .checked_add(count)
                .ok_or_else(|| io::Error::other("filesystem exceeds 32-bit block limit"))?;
            ranges.push(BlockRange { start, end });
            self.seek_to_block(end)?;
            remaining -= count;
        }

        Ok(ranges)
    }

    fn initialize_journal(&mut self) -> FormatResult<()> {
        let mut initial_blocks = self.size.div_ceil(self.block_size as u64);
        if self.upper_capacity.is_none() {
            initial_blocks = initial_blocks.max(self.blocks_per_group() as u64);
        }
        let journal_blocks = journal::default_journal_blocks(initial_blocks);
        let ranges = self.allocate_sparse_blocks(journal_blocks)?;
        let journal_start = ranges
            .first()
            .ok_or(FormatError::InsufficientSpaceForGroupDescriptorBlocks)?
            .start;

        let (time_lo, time_extra) = timestamp_now();
        let mut inode = Inode {
            mode: file_mode::S_IFREG | 0o600,
            links_count: 1,
            extra_isize: EXTRA_ISIZE,
            atime: time_lo,
            ctime: time_lo,
            mtime: time_lo,
            crtime: time_lo,
            atime_extra: time_extra,
            ctime_extra: time_extra,
            mtime_extra: time_extra,
            crtime_extra: time_extra,
            ..Inode::default()
        };
        inode.set_file_size(journal_blocks as u64 * self.block_size as u64);

        self.skip_reserved_metadata_blocks()?;
        let mut next_block = self.current_block()?;
        extent::write_extents(
            &mut inode,
            &ranges,
            self.block_size,
            &mut self.file,
            &mut next_block,
        )?;
        self.seek_to_block(next_block)?;
        self.inodes[(journal::JOURNAL_INODE_NUMBER - 1) as usize] = inode;

        let end_position = self.pos()?;
        self.seek_to_block(journal_start)?;
        self.file.write_all(&journal::superblock(
            self.block_size,
            journal_blocks,
            self.uuid,
        ))?;
        self.file.seek(SeekFrom::Start(end_position))?;
        Ok(())
    }

    fn assign_node_ranges(node: &mut FileTreeNode, ranges: &[BlockRange]) {
        node.blocks = ranges.first().copied();
        node.additional_blocks = ranges.iter().skip(1).copied().collect();
    }

    // -- Constructor -------------------------------------------------------

    /// Create a new formatter that writes an ext4 image to `path`.
    ///
    /// The file is truncated and re-created as a sparse file of `opts.size`
    /// bytes. The root directory (inode 2) and the `/lost+found` directory
    /// (required by e2fsck) are created automatically.
    ///
    /// Only `opts.block_size == 4096` is currently accepted; other values
    /// return [`FormatError::UnsupportedBlockSize`]. Labels are validated
    /// eagerly — an oversize or NUL-containing label returns
    /// [`FormatError::InvalidLabel`] before any file work happens.
    pub fn with_options(path: &Path, opts: FormatOptions) -> FormatResult<Self> {
        Self::construct(path, opts, None)
    }

    pub(crate) fn new_upper(path: &Path, capacity: UpperCapacity) -> FormatResult<Self> {
        Self::construct(path, FormatOptions::new(capacity.bytes()), Some(capacity))
    }

    fn construct(
        path: &Path,
        opts: FormatOptions,
        upper_capacity: Option<UpperCapacity>,
    ) -> FormatResult<Self> {
        // Only 4096-byte blocks are supported.  Supporting smaller block sizes
        // (1024, 2048) would require first_data_block=1 and different group
        // descriptor offset calculations throughout the formatter and reader.
        if opts.block_size != 4096 {
            return Err(FormatError::UnsupportedBlockSize(opts.block_size));
        }

        if opts.size == 0 {
            return Err(FormatError::InvalidSize {
                size: opts.size,
                reason: "size must be greater than zero",
            });
        }
        let blocks_per_group = opts.block_size * 8;
        let maximum_blocks = (u32::MAX / blocks_per_group) as u64 * blocks_per_group as u64;
        if opts.size.div_ceil(opts.block_size as u64) > maximum_blocks {
            return Err(FormatError::InvalidSize {
                size: opts.size,
                reason: "size exceeds the 32-bit block layout",
            });
        }

        if let Some(label) = &opts.label {
            validate_label(label)?;
        }

        let uuid = opts.uuid.unwrap_or_else(Uuid::new_v4);
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if upper_capacity.is_some() {
            options.create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
        } else {
            options.create(true).truncate(true);
        }
        let file = options.open(path)?;

        // Create a sparse file.
        file.set_len(opts.size)?;

        // Reserve the first 10 inodes (indices 0..9  =>  inode numbers 1..10).
        //   [0] = defective block inode  (empty / default)
        //   [1] = root inode             (inode 2)
        //   [2..9] = reserved            (empty / default)
        let mut inodes = Vec::with_capacity(16);
        inodes.push(Inode::default()); // inode 1 -- defective blocks
        inodes.push(Inode::root_inode()); // inode 2 -- root directory
        for _ in 2..10 {
            inodes.push(Inode::default()); // inodes 3..10
        }

        let tree = FileTree::new(ROOT_INODE, "/");
        let filesystem_size = upper_capacity.map_or(opts.size, |capacity| {
            UpperGeometry::for_capacity(capacity).filesystem_bytes
        });
        let initial_groups = crate::ext4::layout::group_count(
            filesystem_size.div_ceil(opts.block_size as u64),
            0,
            opts.block_size * 8,
        );
        let initial_descriptors =
            crate::ext4::layout::descriptor_blocks(initial_groups, opts.block_size, 32);
        let allocated_descriptor_area_blocks = if upper_capacity.is_some() {
            upper_geometry::MAX_DESCRIPTOR_BLOCKS
        } else {
            crate::ext4::layout::generic_descriptor_area(initial_descriptors, opts.block_size)
        };

        let mut fmt = Self {
            file,
            block_size: opts.block_size,
            size: filesystem_size,
            inodes,
            tree,
            deleted_blocks: Vec::new(),
            deferred_blocks: HashMap::new(),
            uuid,
            label: opts.label,
            upper_capacity,
            allocated_descriptor_area_blocks,
        };

        // Seek past the superblock (block 0) and the group descriptor table.
        let gdb = fmt.group_descriptor_blocks();
        fmt.seek_to_block(gdb + 1)?;

        fmt.initialize_journal()?;

        // /lost+found is required by e2fsck.
        fmt.create(
            "/lost+found",
            make_mode(file_mode::S_IFDIR, 0o700),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        Ok(fmt)
    }

    /// Create a new formatter with defaults for UUID (random) and label (empty).
    ///
    /// Thin shim over [`Formatter::with_options`] for the common case where
    /// only the image size matters. Callers that need a specific UUID or
    /// volume label should use `with_options` directly.
    pub fn new(path: &Path, block_size: u32, min_disk_size: u64) -> FormatResult<Self> {
        Self::with_options(
            path,
            FormatOptions {
                block_size,
                size: min_disk_size,
                uuid: None,
                label: None,
            },
        )
    }

    // -- create() ----------------------------------------------------------

    /// Create a file, directory, or symlink at `path`.
    ///
    /// Parent directories are created recursively with mode 0755, inheriting
    /// uid/gid from the nearest existing parent (like `mkdir -p`).
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        path: impl AsRef<[u8]>,
        mode: u16,
        link: Option<&[u8]>,
        ts: Option<FileTimestamps>,
        data: Option<FileData<'_>>,
        uid: Option<u32>,
        gid: Option<u32>,
        xattrs: Option<&[(&[u8], &[u8])]>,
        device: Option<DeviceId>,
    ) -> FormatResult<()> {
        let path = path.as_ref();
        validate_path_component_names(path)?;
        let kind = FileType::from_mode(mode);
        if kind == FileType::Unknown {
            return Err(FormatError::UnsupportedFiletype);
        }
        if is_link(mode) != link.is_some()
            || link.is_some_and(|target| target.is_empty() || target.contains(&0))
        {
            return Err(FormatError::InvalidLink(raw_path_buf(path)));
        }
        if let Some(target) = link {
            // Linux needs one terminating byte in the target's data block.
            if target.len() >= self.block_size as usize {
                return Err(FormatError::SymlinkTargetTooLong {
                    length: target.len() as u64,
                    maximum: self.block_size as u64 - 1,
                });
            }
        }
        if data.is_some() && !is_reg(mode) {
            return Err(FormatError::InvalidMetadata(
                "only regular files have data input",
            ));
        }
        let is_device = matches!(kind, FileType::Character | FileType::Block);
        if is_device != device.is_some() {
            return Err(FormatError::InvalidDevice);
        }
        let state = xattrs
            .map(|attrs| {
                XattrState::from_linux(
                    self.inodes.len() as u32 + 1,
                    attrs,
                    INODE_EXTRA_SIZE,
                    self.block_size,
                )
            })
            .transpose()?;
        if let Some(timestamps) = ts {
            validate_timestamps(timestamps)?;
        }

        if let Some(index) = self.tree.lookup(path) {
            let ino = self.tree.node(index).inode;
            if is_dir(mode) && self.inodes[(ino - 1) as usize].is_dir() {
                // Public create is authoritative, including root. Implicit
                // parent creation below never calls create on an existing dir.
                let mut inode = self.inodes[(ino - 1) as usize].clone();
                inode.mode = mode;
                if let Some(uid) = uid {
                    inode.set_uid(uid);
                }
                if let Some(gid) = gid {
                    inode.set_gid(gid);
                }
                if let Some(timestamps) = ts {
                    set_timestamps(&mut inode, timestamps);
                }
                if let Some(state) = state.as_ref() {
                    self.write_xattrs(&mut inode, state)?;
                }
                self.inodes[(ino - 1) as usize] = inode;
                return Ok(());
            }
            if is_dir(mode) {
                return Err(FormatError::NotDirectory(raw_path_buf(path)));
            }
            if self.inodes[(ino - 1) as usize].is_dir() && !is_link(mode) {
                return Err(FormatError::NotFile(raw_path_buf(path)));
            }
            self.remove(path)?;
        }

        let parent_path = parent_of(path);
        // Build missing ancestors top-down; each nested create has an existing
        // parent, so deep byte paths cannot exhaust the stack recursively.
        for end in 1..=parent_path.len() {
            if end != parent_path.len() && parent_path[end] != b'/' {
                continue;
            }
            let prefix = &parent_path[..end];
            if self.tree.lookup(prefix).is_none() {
                self.create(
                    prefix,
                    make_mode(file_mode::S_IFDIR, 0o755),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )?;
            }
        }
        let parent_idx = self
            .tree
            .lookup(parent_path)
            .ok_or_else(|| FormatError::NotFound(raw_path_buf(parent_path)))?;
        let parent_ino = self.tree.node(parent_idx).inode;
        let parent = &self.inodes[(parent_ino - 1) as usize];
        if !parent.is_dir() {
            return Err(FormatError::NotDirectory(raw_path_buf(parent_path)));
        }
        if is_dir(mode) && parent.links_count as u32 >= MAX_LINKS {
            return Err(FormatError::MaximumLinksExceeded(raw_path_buf(parent_path)));
        }
        let mut inode = Inode {
            mode,
            links_count: 1,
            extra_isize: EXTRA_ISIZE,
            flags: if is_reg(mode) || is_dir(mode) {
                inode_flags::HUGE_FILE
            } else {
                0
            },
            ..Inode::default()
        };
        inode.set_uid(uid.unwrap_or_else(|| parent.uid_full()));
        inode.set_gid(gid.unwrap_or_else(|| parent.gid_full()));
        set_timestamps(&mut inode, ts.unwrap_or_default());
        let mut ranges = Vec::new();
        if is_dir(mode) {
            inode.links_count = 2;
            self.inodes[(parent_ino - 1) as usize].links_count += 1;
        } else if let Some(target) = link {
            inode.set_file_size(target.len() as u64);
            if target.len() < INODE_BLOCK_SIZE {
                inode.block[..target.len()].copy_from_slice(target);
            } else {
                ranges = self.write_aligned_payload_bytes(target)?;
                let mapped = dense_map(&ranges)?;
                self.write_inode_map(&mut inode, &mapped, &mut ranges)?;
            }
        } else if is_reg(mode) {
            match data {
                Some(FileData::Dense(reader)) => {
                    self.align_to_block()?;
                    self.skip_reserved_metadata_blocks()?;
                    let length = self.write_payload_from_reader(reader, &mut ranges)?;
                    self.align_to_block()?;
                    inode.set_file_size(length);
                    let mapped = dense_map(&ranges)?;
                    self.write_inode_map(&mut inode, &mapped, &mut ranges)?;
                }
                Some(FileData::Sparse(data)) => {
                    let (mapped, physical) = self.write_sparse_data(data, &mut inode)?;
                    ranges = physical;
                    self.write_inode_map(&mut inode, &mapped, &mut ranges)?;
                }
                None => {}
            }
        } else if let Some(device) = device {
            device.write(&mut inode.block);
        }
        if let Some(state) = state.as_ref() {
            self.write_xattrs(&mut inode, state)?;
        }
        self.inodes.push(inode);
        let number = self.inodes.len() as u32;
        let mut node = FileTreeNode {
            inode: number,
            name: basename(path).to_vec(),
            children: Vec::new(),
            parent: None,
            blocks: None,
            additional_blocks: Vec::new(),
            link: None,
        };
        Self::assign_node_ranges(&mut node, &ranges);
        self.tree.add_child(parent_idx, node);
        Ok(())
    }

    fn write_xattrs(&mut self, inode: &mut Inode, state: &XattrState<'_>) -> FormatResult<()> {
        let old = inode.xattr_block_lo;
        let new = if state.has_block() {
            let bytes = state.write_block()?;
            self.write_aligned_payload_bytes(&bytes)?
                .first()
                .ok_or(FormatError::MalformedXattrBuffer)?
                .start
        } else {
            0
        };
        inode.inline_xattrs.fill(0);
        if state.has_inline() {
            inode.inline_xattrs.copy_from_slice(&state.write_inline()?);
        }
        let units = if inode.flags & inode_flags::HUGE_FILE != 0 {
            1
        } else {
            self.block_size / 512
        };
        if old != 0 {
            self.deleted_blocks.push(BlockRange {
                start: old,
                end: old + 1,
            });
            inode.blocks_lo =
                inode
                    .blocks_lo
                    .checked_sub(units)
                    .ok_or(FormatError::InvalidMetadata(
                        "invalid old xattr block count",
                    ))?;
        }
        if new != 0 {
            inode.blocks_lo = inode
                .blocks_lo
                .checked_add(units)
                .ok_or(FormatError::SizeOverflow)?;
        }
        inode.xattr_block_lo = new;
        Ok(())
    }

    fn write_inode_map(
        &mut self,
        inode: &mut Inode,
        mapped: &[extent::MappedExtent],
        physical: &mut Vec<BlockRange>,
    ) -> FormatResult<()> {
        self.align_to_block()?;
        self.skip_reserved_metadata_blocks()?;
        let before = self.current_block()?;
        let count = extent::metadata_blocks(mapped, self.block_size)?;
        let start = self.metadata_run_start_after_static_ranges(
            before as u64,
            count as u64,
            self.group_count(),
            self.group_descriptor_blocks(),
        ) as u32;
        let gaps = self.free_ranges_before_shifted_metadata(
            before,
            start,
            self.group_count(),
            self.group_descriptor_blocks(),
        );
        self.deleted_blocks.extend(gaps);
        let mut end = start;
        extent::write_mapped_extents(inode, mapped, self.block_size, &mut self.file, &mut end)?;
        if end != start {
            physical.push(BlockRange { start, end });
        }
        self.seek_to_block(end)?;
        self.size = self.size.max(end as u64 * self.block_size as u64);
        Ok(())
    }

    fn write_sparse_data(
        &mut self,
        data: SparseData<'_>,
        inode: &mut Inode,
    ) -> FormatResult<(Vec<extent::MappedExtent>, Vec<BlockRange>)> {
        if data.length > MAX_FILE_SIZE {
            return Err(FormatError::FileTooBig(data.length));
        }
        self.align_to_block()?;
        let mut mapped = Vec::new();
        let mut physical = Vec::new();
        let mut bytes = [0u8; 4096];
        let mut pending = None;
        let mut previous_end = 0u64;
        let mut eof_sentinel = false;
        for range in data.ranges {
            let end = range
                .offset
                .checked_add(range.length)
                .ok_or(FormatError::InvalidSparse("range overflow"))?;
            if eof_sentinel || range.offset < previous_end || end > data.length {
                return Err(FormatError::InvalidSparse(
                    "overlapping, unordered or out-of-file range",
                ));
            }
            if range.length == 0 {
                if range.offset != data.length {
                    return Err(FormatError::InvalidSparse("non-EOF empty range"));
                }
                eof_sentinel = true;
                continue;
            }
            previous_end = end;
            let mut position = range.offset;
            while position < end {
                let logical = (position / self.block_size as u64) as u32;
                if pending != Some(logical) {
                    if let Some(logical) = pending {
                        self.write_sparse_block(logical, &bytes, &mut mapped, &mut physical)?;
                    }
                    bytes.fill(0);
                    pending = Some(logical);
                }
                let offset = (position % self.block_size as u64) as usize;
                let count = ((end - position) as usize).min(bytes.len() - offset);
                data.reader.read_exact(&mut bytes[offset..offset + count])?;
                position += count as u64;
            }
        }
        if let Some(logical) = pending {
            self.write_sparse_block(logical, &bytes, &mut mapped, &mut physical)?;
        }
        let mut excess = [0u8; 1];
        if data.reader.read(&mut excess)? != 0 {
            return Err(FormatError::InvalidSparse("stored bytes exceed range map"));
        }
        inode.set_file_size(data.length);
        Ok((mapped, physical))
    }

    fn write_sparse_block(
        &mut self,
        logical: u32,
        bytes: &[u8; 4096],
        mapped: &mut Vec<extent::MappedExtent>,
        physical: &mut Vec<BlockRange>,
    ) -> FormatResult<()> {
        self.skip_reserved_metadata_blocks()?;
        let block = self.current_block()?;
        self.file.write_all(bytes)?;
        self.size = self.size.max(self.pos()?);
        Self::record_block_range(physical, block);
        if let Some(last) = mapped.last_mut() {
            if last.logical + last.length == logical && last.physical + last.length == block {
                last.length += 1;
                return Ok(());
            }
        }
        mapped.push(extent::MappedExtent {
            logical,
            physical: block,
            length: 1,
            unwritten: false,
        });
        Ok(())
    }

    // -- Query helpers for incremental writers -------------------------------

    /// Check whether `path` exists in the in-memory file tree.
    pub fn exists(&self, path: impl AsRef<[u8]>) -> bool {
        self.tree.lookup(path).is_some()
    }

    /// Check whether `path` exists and is a directory.
    pub fn is_dir(&self, path: impl AsRef<[u8]>) -> bool {
        if let Some(idx) = self.tree.lookup(path) {
            let ino = self.tree.node(idx).inode;
            self.inodes[(ino - 1) as usize].is_dir()
        } else {
            false
        }
    }

    /// List the names of immediate children of a directory (excluding `.`
    /// and `..`).  Returns an empty vec if `path` is not a directory.
    pub fn list_dir(&self, path: impl AsRef<[u8]>) -> Vec<Vec<u8>> {
        let Some(idx) = self.tree.lookup(path) else {
            return Vec::new();
        };
        self.tree
            .node(idx)
            .children
            .iter()
            .map(|&ci| self.tree.node(ci).name.clone())
            .collect()
    }

    /// Update the permission bits of an existing entry.
    pub fn set_permissions(&mut self, path: impl AsRef<[u8]>, mode: u16) -> FormatResult<()> {
        let path = path.as_ref();
        let idx = self
            .tree
            .lookup(path)
            .ok_or_else(|| FormatError::NotFound(raw_path_buf(path)))?;
        let ino = self.tree.node(idx).inode;
        let inode = &mut self.inodes[(ino - 1) as usize];
        // Preserve the file-type bits, replace the permission bits.
        inode.mode = (inode.mode & file_mode::TYPE_MASK) | (mode & !file_mode::TYPE_MASK);
        Ok(())
    }

    /// Update the owner uid/gid of an existing entry.
    pub fn set_owner(&mut self, path: impl AsRef<[u8]>, uid: u32, gid: u32) -> FormatResult<()> {
        let path = path.as_ref();
        let idx = self
            .tree
            .lookup(path)
            .ok_or_else(|| FormatError::NotFound(raw_path_buf(path)))?;
        let ino = self.tree.node(idx).inode;
        let inode = &mut self.inodes[(ino - 1) as usize];
        inode.set_uid(uid);
        inode.set_gid(gid);
        Ok(())
    }

    // -- link() ------------------------------------------------------------

    /// Create a hard link at `link_path` pointing to `target_path`.
    pub fn link(
        &mut self,
        link_path: impl AsRef<[u8]>,
        target_path: impl AsRef<[u8]>,
    ) -> FormatResult<()> {
        let link_path = link_path.as_ref();
        let target_path = target_path.as_ref();
        validate_path_component_names(link_path)?;
        validate_path_component_names(target_path)?;
        let target_buf = raw_path_buf(target_path);
        let target_idx = self
            .tree
            .lookup(target_path)
            .ok_or_else(|| FormatError::NotFound(target_buf.clone()))?;
        let target_inode_num = self.tree.node(target_idx).inode;
        let target_inode = &self.inodes[(target_inode_num - 1) as usize];

        if target_inode.is_dir() {
            return Err(FormatError::CannotHardlinkDirectory(target_buf));
        }

        let existing_target = self.tree.lookup(link_path).map(|idx| {
            let node = self.tree.node(idx);
            node.link.unwrap_or(node.inode)
        });
        if existing_target == Some(target_inode_num) {
            return Ok(());
        }

        let parent_path = parent_of(link_path);
        let parent_path_buf = raw_path_buf(parent_path);
        let parent_idx = self
            .tree
            .lookup(parent_path)
            .ok_or_else(|| FormatError::NotFound(parent_path_buf.clone()))?;
        if !self.inodes[(self.tree.node(parent_idx).inode - 1) as usize].is_dir() {
            return Err(FormatError::NotDirectory(parent_path_buf));
        }
        if target_inode.links_count as u32 >= MAX_LINKS {
            return Err(FormatError::MaximumLinksExceeded(target_buf));
        }

        // If the link path already exists, remove it after all validation so a
        // failed link creation cannot mutate the target inode's link count.
        if existing_target.is_some() {
            self.remove(link_path)?;
        }

        self.inodes[(target_inode_num - 1) as usize].links_count += 1;

        let link_node = FileTreeNode {
            inode: target_inode_num,
            name: basename(link_path).to_vec(),
            children: Vec::new(),
            parent: None,
            blocks: None,
            additional_blocks: Vec::new(),
            link: Some(target_inode_num),
        };
        self.tree.add_child(parent_idx, link_node);

        Ok(())
    }

    // -- removal ------------------------------------------------------------

    /// Remove the entry at `path` and all of its children.
    pub fn remove(&mut self, path: impl AsRef<[u8]>) -> FormatResult<()> {
        self.remove_inner(path.as_ref(), true)
    }

    /// Remove all children of the directory at `path`, preserving the directory.
    pub fn remove_children(&mut self, path: impl AsRef<[u8]>) -> FormatResult<()> {
        self.remove_inner(path.as_ref(), false)
    }

    fn remove_inner(&mut self, path: &[u8], remove_self: bool) -> FormatResult<()> {
        if remove_self && path.iter().all(|byte| *byte == b'/') {
            return Err(FormatError::InvalidMetadata(
                "cannot remove filesystem root",
            ));
        }
        let path_buf = raw_path_buf(path);
        let node_idx = match self.tree.lookup(path) {
            Some(idx) => idx,
            None => return Ok(()), // nothing to remove
        };

        let inode_num = self.tree.node(node_idx).inode;
        let inode_idx = (inode_num - 1) as usize;
        let linked_ino = self.tree.node(node_idx).link;
        let (target_ino, target_idx) = if let Some(linked_ino) = linked_ino {
            (linked_ino, (linked_ino - 1) as usize)
        } else {
            (inode_num, inode_idx)
        };
        let node_is_dir = linked_ino.is_none() && self.inodes[inode_idx].is_dir();

        if !remove_self && !node_is_dir {
            return Err(FormatError::NotDirectory(path_buf));
        }

        // Recursively remove children.
        let child_names: Vec<Vec<u8>> = self
            .tree
            .node(node_idx)
            .children
            .iter()
            .map(|&ci| self.tree.node(ci).name.clone())
            .collect();
        for child_name in child_names {
            let mut child_path = path.to_vec();
            if !child_path.ends_with(b"/") {
                child_path.push(b'/');
            }
            child_path.extend_from_slice(&child_name);
            self.remove(&child_path)?;
        }

        if !remove_self {
            return Ok(());
        }

        // Detach from parent and update parent's link count for directories.
        let parent_path = parent_of(path);
        if let Some(parent_idx) = self.tree.lookup(parent_path) {
            let parent_inode_num = self.tree.node(parent_idx).inode;
            if node_is_dir && self.inodes[(parent_inode_num - 1) as usize].links_count > 2 {
                self.inodes[(parent_inode_num - 1) as usize].links_count -= 1;
            }
            self.tree.remove_child(parent_idx, basename(path));
        }

        if target_ino > FIRST_INODE - 1 {
            if node_is_dir {
                self.inodes[target_idx].links_count = 0;
            } else if self.inodes[target_idx].links_count > 0 {
                self.inodes[target_idx].links_count -= 1;
            }

            // Collect block ranges from this tree node (if any).
            let node = self.tree.node(node_idx);
            let mut node_blocks: Vec<BlockRange> = Vec::new();
            if let Some(b) = node.blocks {
                if b.start != b.end {
                    node_blocks.push(b);
                }
            }
            for blk in &node.additional_blocks {
                node_blocks.push(*blk);
            }
            let xattr_block = self.inodes[target_idx].xattr_block_lo;

            if self.inodes[target_idx].links_count == 0 {
                // Last reference removed -- reclaim blocks and mark deleted.
                // Blocks may come from this node (if it is the original) or
                // from deferred_blocks (if the original was unlinked earlier
                // while hard links still existed).
                for blk in &node_blocks {
                    self.deleted_blocks.push(*blk);
                }
                if let Some(deferred) = self.deferred_blocks.remove(&target_ino) {
                    for blk in deferred {
                        self.deleted_blocks.push(blk);
                    }
                }
                if xattr_block != 0 {
                    self.deleted_blocks.push(BlockRange {
                        start: xattr_block,
                        end: xattr_block + 1,
                    });
                }

                let (now_lo, _) = timestamp_now();
                self.inodes[target_idx] = Inode::default();
                self.inodes[target_idx].dtime = now_lo;
            } else if !node_blocks.is_empty() {
                // The original node is being removed but the inode still has
                // remaining hard-link references.  Stash the block ranges so
                // they can be reclaimed when the last link is finally deleted.
                self.deferred_blocks
                    .entry(target_ino)
                    .or_default()
                    .extend(node_blocks);
            }
        }

        Ok(())
    }

    // -- close() -----------------------------------------------------------

    /// Finalize the ext4 image.
    ///
    /// Writes directory entries (BFS order), the inode table, block/inode
    /// bitmaps, group descriptors, and the superblock.  Consumes `self`.
    pub fn close(self) -> FormatResult<()> {
        self.finish().map(|_| ())
    }

    pub(crate) fn finish(mut self) -> FormatResult<(Uuid, u64, u64)> {
        // -- Step 1: BFS-commit directory entries --
        self.commit_directories()?;

        // -- Step 2: Allocate the resize inode's double-indirect block --
        let allocated_descriptor_area_blocks = self.allocated_descriptor_area_blocks;
        let resize_dind_block = self.allocate_resize_inode_dind_block()?;

        // -- Step 3: Optimize block group layout --
        if self.upper_capacity.is_none() {
            self.size = self.size.max(self.file.metadata()?.len());
        }
        let current_blk = self.current_block()?;
        let inode_count = self.inodes.len() as u32;
        let (block_groups, inodes_per_group) = if self.upper_capacity.is_some() {
            let inodes_per_group = upper_geometry::INODES_PER_GROUP;
            let data_blocks_per_group =
                self.blocks_per_group() - upper_geometry::INODE_TABLE_BLOCKS - 2;
            (
                current_blk
                    .div_ceil(data_blocks_per_group)
                    .max(inode_count.div_ceil(inodes_per_group)),
                inodes_per_group,
            )
        } else {
            self.optimize_block_group_layout(current_blk, inode_count)
        };
        self.align_to_block()?;
        let metadata_start = self.current_block()?;
        let inode_table_size_per_group = inodes_per_group * INODE_SIZE / self.block_size;

        // Ensure the disk is large enough.
        let minimum_disk_size = if self.upper_capacity.is_some() {
            self.block_count()
        } else if block_groups == 1 {
            self.blocks_per_group()
        } else {
            (block_groups - 1) * self.blocks_per_group() + 1
        };

        let mut layout = self.flex_metadata_layout(
            metadata_start,
            block_groups,
            inode_table_size_per_group,
            minimum_disk_size,
        );
        if let Some(capacity) = self.upper_capacity {
            let geometry = UpperGeometry::for_capacity(capacity);
            if layout.total_groups != geometry.groups
                || layout.data_size as u64 * self.block_size as u64 > geometry.filesystem_bytes
            {
                return Err(FormatError::InsufficientSpaceForGroupDescriptorBlocks);
            }
            layout.size_bytes = geometry.filesystem_bytes;
        }
        let block_groups = layout.block_groups;
        let inode_table_offset = layout.inode_table_offset;
        let expected_bitmap_offset = layout.bitmap_offset;
        let data_size = layout.data_size;

        if self.upper_capacity.is_none() && self.size != layout.size_bytes {
            let saved_pos = self.pos()?;
            self.size = layout.size_bytes;
            self.file.set_len(self.size)?;
            self.file.seek(SeekFrom::Start(saved_pos))?;
        }

        let total_groups_u32 = layout.total_groups;
        let gd_block_count = layout.gd_block_count;
        let gd_area_blocks = layout.gd_area_blocks;
        if gd_area_blocks > allocated_descriptor_area_blocks {
            return Err(FormatError::InsufficientSpaceForGroupDescriptorBlocks);
        }
        let metadata_gap_ranges = self.free_ranges_before_shifted_metadata(
            metadata_start,
            inode_table_offset,
            total_groups_u32,
            gd_area_blocks,
        );
        let reserved_gdt_blocks = gd_area_blocks - gd_block_count;
        let backup_groups = self.backup_groups(total_groups_u32);
        self.configure_resize_inode(
            resize_dind_block,
            reserved_gdt_blocks,
            backup_groups.len() as u32,
        );
        self.write_resize_inode_blocks(
            resize_dind_block,
            gd_block_count,
            reserved_gdt_blocks,
            &backup_groups,
        )?;

        // -- Step 4: Write inode table --
        self.seek_to_block(inode_table_offset)?;
        let inode_table_offset = self.commit_inode_table(block_groups, inodes_per_group)?;

        self.align_to_block()?;
        let bitmap_offset = self.current_block()?;
        if bitmap_offset != expected_bitmap_offset {
            return Err(FormatError::InsufficientSpaceForGroupDescriptorBlocks);
        }

        let mut total_used_blocks: u32 = 0;
        let mut total_used_inodes: u32 = 0;
        let mut group_descriptors = Vec::with_capacity(total_groups_u32 as usize);

        // Write bitmaps for groups that contain data.
        for group in 0..block_groups {
            let mut dirs: u32 = 0;
            let mut used_inodes: u32 = 0;
            let mut last_used_inode_index: u32 = 0;
            let mut used_blocks: u32 = 0;

            // Two bitmaps per group: block bitmap + inode bitmap, each one
            // block in size.
            let mut bitmap = vec![0u8; self.block_size as usize * 2];

            // -- Block bitmap --
            let group_start = group * self.blocks_per_group();
            let group_end = group_start + self.blocks_per_group();

            if group_end <= data_size {
                // Fully allocated group.
                for byte in bitmap[..self.block_size as usize].iter_mut() {
                    *byte = 0xFF;
                }
                used_blocks = self.blocks_per_group();
            } else if group_start < data_size {
                // Partially allocated group.
                let used = data_size - group_start;
                for i in 0..used {
                    bitmap[(i / 8) as usize] |= 1 << (i % 8);
                    used_blocks += 1;
                }
            }

            // Classic sparse-super groups reserve the group-start block for a
            // superblock copy and the following descriptor/reserved-GDT area.
            let metadata_blocks = self.static_metadata_blocks_in_group(group);
            for i in 0..metadata_blocks.min(self.blocks_per_group()) {
                let was_set = (bitmap[(i / 8) as usize] >> (i % 8)) & 1;
                bitmap[(i / 8) as usize] |= 1 << (i % 8);
                if was_set == 0 {
                    used_blocks += 1;
                }
            }

            // Mark deleted payloads and normal blocks skipped while shifting
            // flex metadata past sparse-super system zones as free.
            for freed in self.deleted_blocks.iter().chain(metadata_gap_ranges.iter()) {
                Self::clear_block_range_from_bitmap(
                    &mut bitmap[..self.block_size as usize],
                    group_start,
                    group_end,
                    freed,
                    &mut used_blocks,
                );
            }

            // -- Inode bitmap (stored in the second block of the pair) --
            let inode_bitmap_start = self.block_size as usize;
            for i in 0..inodes_per_group {
                let ino = 1 + group * inodes_per_group + i;
                if ino > self.inodes.len() as u32 {
                    continue;
                }
                let inode = &self.inodes[(ino - 1) as usize];
                // Reserved inodes (1..10) are always marked used.
                if ino > 10 && inode.links_count == 0 {
                    continue;
                }
                bitmap[inode_bitmap_start + (i / 8) as usize] |= 1 << (i % 8);
                used_inodes += 1;
                last_used_inode_index = i + 1;
                if inode.is_dir() {
                    dirs += 1;
                }
            }
            // Mark remaining inode-bitmap bits (past inodes_per_group) as occupied
            // so the kernel does not try to allocate them.
            for i in (inodes_per_group / 8)..self.block_size {
                bitmap[inode_bitmap_start + i as usize] = 0xFF;
            }

            let blocks_in_group = (self.block_count() - group_start).min(self.blocks_per_group());
            for i in blocks_in_group..self.blocks_per_group() {
                bitmap[(i / 8) as usize] |= 1 << (i % 8);
            }
            self.file.write_all(&bitmap)?;

            // -- Build group descriptor --
            let free_blocks = blocks_in_group.saturating_sub(used_blocks);
            let free_inodes = inodes_per_group - used_inodes;
            let itable_unused = inodes_per_group - last_used_inode_index;
            let block_bitmap_lo = bitmap_offset + 2 * group;
            let inode_bitmap_lo = block_bitmap_lo + 1;
            let inode_table_lo = (inode_table_offset as u32) + group * inode_table_size_per_group;
            group_descriptors.push(GroupDescriptor {
                block_bitmap_lo,
                inode_bitmap_lo,
                inode_table_lo,
                free_blocks_count_lo: free_blocks as u16,
                free_inodes_count_lo: free_inodes as u16,
                used_dirs_count_lo: dirs as u16,
                flags: 0,
                exclude_bitmap_lo: 0,
                block_bitmap_csum_lo: 0,
                inode_bitmap_csum_lo: 0,
                itable_unused_lo: itable_unused as u16,
                checksum: 0,
            });

            total_used_blocks += used_blocks;
            total_used_inodes += used_inodes;
        }

        // -- Step 5: Extra (empty) block groups beyond data --
        let empty_inode_bitmap = {
            let mut bm = vec![0xFFu8; self.blocks_per_group() as usize / 8];
            for i in 0..inodes_per_group as u16 {
                bm[(i / 8) as usize] &= !(1 << (i % 8));
            }
            bm
        };

        for group in block_groups..total_groups_u32 {
            let blocks_in_group = if group == total_groups_u32 - 1 {
                let rem = (self.size / self.block_size as u64) % self.blocks_per_group() as u64;
                if rem == 0 {
                    self.blocks_per_group()
                } else {
                    rem as u32
                }
            } else {
                self.blocks_per_group()
            };

            let group_start = group * self.blocks_per_group();
            let metadata_blocks = self
                .static_metadata_blocks_in_group(group)
                .min(blocks_in_group);
            let used_empty_blocks = metadata_blocks + inode_table_size_per_group + 2;
            let it_offset = group_start + metadata_blocks;
            let bb_offset = it_offset + inode_table_size_per_group;
            let ib_offset = bb_offset + 1;
            let free_blocks_count = blocks_in_group.saturating_sub(used_empty_blocks);
            let free_inodes_count = inodes_per_group;

            // BLOCK_UNINIT lets the bitmap be reconstructed on demand;
            // INODE_UNINIT, paired with itable_unused_lo, lets the entire
            // inode table be treated as uninitialized.  Together they let
            // resize2fs extend the filesystem without fallocating the new
            // inode tables -- a ~2 MiB-per-added-group cost on btrfs.
            let mut flags = bg_flags::INODE_UNINIT;
            if group != total_groups_u32 - 1 {
                flags |= bg_flags::BLOCK_UNINIT;
            }

            group_descriptors.push(GroupDescriptor {
                block_bitmap_lo: bb_offset,
                inode_bitmap_lo: ib_offset,
                inode_table_lo: it_offset,
                free_blocks_count_lo: free_blocks_count as u16,
                free_inodes_count_lo: free_inodes_count as u16,
                used_dirs_count_lo: 0,
                flags,
                exclude_bitmap_lo: 0,
                block_bitmap_csum_lo: 0,
                inode_bitmap_csum_lo: 0,
                itable_unused_lo: inodes_per_group as u16,
                checksum: 0,
            });

            total_used_blocks += used_empty_blocks.min(blocks_in_group);

            // Write block bitmap + inode bitmap at the right offset.
            self.seek_to_block(bb_offset)?;

            let mut block_bitmap = vec![0u8; self.blocks_per_group() as usize / 8];
            for i in 0..used_empty_blocks.min(blocks_in_group) {
                block_bitmap[(i / 8) as usize] |= 1 << (i % 8);
            }
            if group == total_groups_u32 - 1 && blocks_in_group < self.blocks_per_group() {
                // Last partial group: mark out-of-range blocks as used.
                for i in blocks_in_group..self.blocks_per_group() {
                    block_bitmap[(i / 8) as usize] |= 1 << (i % 8);
                }
            }
            self.file.write_all(&block_bitmap)?;
            self.file.write_all(&empty_inode_bitmap)?;
        }

        // Settle the UUID now so the group descriptor checksums and the
        // superblock agree on it.
        let uuid = self.uuid;
        let uuid_bytes = *uuid.as_bytes();

        // -- Step 6: Build group descriptor table --
        // With `gdt_csum`, each descriptor carries a CRC-16 over the
        // filesystem UUID, its group number, and the descriptor body.
        let mut gd_table_buf = vec![0u8; gd_block_count as usize * self.block_size as usize];
        for (group_nr, gd) in group_descriptors.iter_mut().enumerate() {
            gd.checksum = checksum::group_descriptor(&uuid_bytes, group_nr as u32, gd);
            let offset = group_nr * GroupDescriptor::SIZE;
            gd.write_to(&mut gd_table_buf[offset..offset + GroupDescriptor::SIZE]);
        }

        self.seek_to_block(1)?;
        self.file.write_all(&gd_table_buf)?;

        // -- Step 7: Write superblock --
        let computed_inodes = total_groups_u32 as u64 * inodes_per_group as u64;
        let blocks_count = self.size / self.block_size as u64;
        let total_free_blocks = blocks_count.saturating_sub(total_used_blocks as u64);
        let free_inodes = computed_inodes as u32 - total_used_inodes;

        let mut sb = SuperBlock {
            inodes_count: computed_inodes as u32,
            blocks_count_lo: blocks_count as u32,
            blocks_count_hi: (blocks_count >> 32) as u32,
            free_blocks_count_lo: total_free_blocks as u32,
            free_blocks_count_hi: (total_free_blocks >> 32) as u32,
            free_inodes_count: free_inodes,
            first_data_block: 0,
            ..Default::default()
        };
        // log_block_size = log2(block_size / 1024).  E.g. 1024->0, 2048->1, 4096->2.
        let log_bs = (self.block_size / 1024).trailing_zeros();
        sb.log_block_size = log_bs;
        sb.log_cluster_size = log_bs;
        sb.blocks_per_group = self.blocks_per_group();
        sb.clusters_per_group = self.blocks_per_group();
        sb.inodes_per_group = inodes_per_group;
        sb.magic = SUPERBLOCK_MAGIC;
        sb.state = 1; // cleanly unmounted
        sb.errors = 1; // continue on error
        sb.creator_os = 0; // Linux inode osd2 layout (uid/gid high bits, block counts).
        sb.rev_level = 1; // dynamic inode sizes
        sb.first_ino = FIRST_INODE;
        sb.lpf_ino = self
            .tree
            .lookup(b"/lost+found")
            .and_then(|index| {
                let number = self.tree.node(index).inode;
                self.inodes[(number - 1) as usize]
                    .is_dir()
                    .then_some(number)
            })
            .unwrap_or(0);
        sb.inode_size = INODE_SIZE as u16;
        sb.feature_compat = compat::HAS_JOURNAL | compat::EXT_ATTR | compat::RESIZE_INODE;
        sb.feature_incompat = incompat::FILETYPE | incompat::EXTENTS | incompat::FLEX_BG;
        sb.feature_ro_compat = ro_compat::LARGE_FILE
            | ro_compat::HUGE_FILE
            | ro_compat::SPARSE_SUPER
            | ro_compat::EXTRA_ISIZE
            // `gdt_csum` (group-descriptor CRC-16) is what makes resize2fs
            // honour BG_*_UNINIT flags on the new groups it creates -- and
            // therefore skip the per-group fallocate that otherwise burns
            // ~2 MiB per added block group on btrfs.
            | ro_compat::GDT_CSUM;
        sb.reserved_gdt_blocks = reserved_gdt_blocks as u16;
        sb.min_extra_isize = EXTRA_ISIZE;
        sb.want_extra_isize = EXTRA_ISIZE;
        sb.log_groups_per_flex = 31;
        sb.uuid = uuid_bytes;
        sb.journal_inum = journal::JOURNAL_INODE_NUMBER;
        sb.journal_backup_type = journal::JOURNAL_BACKUP_BLOCKS;
        let journal_inode = &self.inodes[(journal::JOURNAL_INODE_NUMBER - 1) as usize];
        if self.upper_capacity.is_some() {
            sb.feature_compat = upper_geometry::FEATURE_COMPAT;
            sb.feature_incompat = upper_geometry::FEATURE_INCOMPAT;
            sb.feature_ro_compat = upper_geometry::FEATURE_RO_COMPAT;
            sb.log_groups_per_flex = upper_geometry::LOG_GROUPS_PER_FLEX;
            sb.def_hash_version = upper_geometry::HASH_VERSION;
            sb.flags = upper_geometry::HASH_FLAGS;
            for (seed, bytes) in sb.hash_seed.iter_mut().zip(uuid_bytes.chunks_exact(4)) {
                *seed = u32::from_le_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| io::Error::other("invalid UUID word"))?,
                );
            }
        }
        for (index, chunk) in journal_inode.block.chunks_exact(4).enumerate() {
            sb.journal_blocks[index] = u32::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| io::Error::other("invalid journal inode block field"))?,
            );
        }
        sb.journal_blocks[15] = journal_inode.size_hi;
        sb.journal_blocks[16] = journal_inode.size_lo;
        if let Some(label) = &self.label {
            let bytes = label.as_bytes();
            sb.volume_name[..bytes.len()].copy_from_slice(bytes);
        }

        // Write: 1024 zero bytes (boot sector) + superblock + 2048 zero bytes.
        self.seek_to_block(0)?;
        self.file.write_all(&[0u8; 1024])?;
        let mut sb_buf = [0u8; SUPERBLOCK_SIZE];
        sb.write_to(&mut sb_buf);
        self.file.write_all(&sb_buf)?;
        self.file.write_all(&[0u8; 2048])?;

        // Classic sparse-super groups carry backup superblocks and descriptor
        // tables. The reserved-GDT blocks after each backup table stay sparse,
        // but are marked allocated and referenced by inode 7 for online grow.
        for group in &backup_groups {
            let group_start = group * self.blocks_per_group();

            let mut backup_sb = sb.clone();
            backup_sb.block_group_nr = *group as u16;
            backup_sb.write_to(&mut sb_buf);

            self.seek_to_block(group_start)?;
            self.file.write_all(&sb_buf)?;

            self.seek_to_block(group_start + 1)?;
            self.file.write_all(&gd_table_buf)?;
        }

        self.file.flush()?;
        Ok((
            uuid,
            total_free_blocks * self.block_size as u64,
            free_inodes as u64,
        ))
    }

    // Private helpers
    // -----------------------------------------------------------------------

    /// BFS-walk the file tree and write directory entries for every directory
    /// inode.  Updates each directory inode's size and extent tree.
    fn commit_directories(&mut self) -> FormatResult<()> {
        // Collect BFS order: (parent_idx_opt, node_idx).
        let mut queue: std::collections::VecDeque<(Option<usize>, usize)> =
            std::collections::VecDeque::new();
        queue.push_back((None, self.tree.root()));

        let mut bfs_order: Vec<(Option<usize>, usize)> = Vec::new();
        while let Some((parent, node)) = queue.pop_front() {
            bfs_order.push((parent, node));
            // Skip hardlink nodes (no children to descend into).
            if self.tree.node(node).link.is_some() {
                continue;
            }
            let children: Vec<usize> = self.tree.node(node).children.clone();
            for &child in &children {
                queue.push_back((Some(node), child));
            }
        }

        // Commit each directory.
        for (parent_opt, node_idx) in bfs_order {
            let inode_num = self.tree.node(node_idx).inode;
            let inode = &self.inodes[(inode_num - 1) as usize];

            if inode.links_count == 0 {
                continue;
            }
            if self.tree.node(node_idx).link.is_some() {
                continue;
            }
            if !inode.is_dir() {
                continue;
            }

            let mut dir_buf = Vec::new();
            let mut left = self.block_size as i32;

            // Write "." entry.
            dir::write_dir_entry(
                &mut dir_buf,
                ".",
                inode_num,
                self.inodes[(inode_num - 1) as usize].mode,
                None,
                None,
                self.block_size,
                &mut left,
            )?;

            // Write ".." entry.
            let parent_ino = match parent_opt {
                Some(pidx) => self.tree.node(pidx).inode,
                None => inode_num, // root's ".." points to itself
            };
            dir::write_dir_entry(
                &mut dir_buf,
                "..",
                parent_ino,
                self.inodes[(parent_ino - 1) as usize].mode,
                None,
                None,
                self.block_size,
                &mut left,
            )?;

            // Sort children by inode number for e2fsck compatibility.
            let mut sorted_children: Vec<usize> = self.tree.node(node_idx).children.clone();
            sorted_children.sort_by_key(|&ci| self.tree.node(ci).inode);

            for &child_idx in &sorted_children {
                let child_ino = self.tree.node(child_idx).inode;
                let child_name = self.tree.node(child_idx).name.clone();

                // Check that the inode has links (not deleted).
                let effective_ino;
                let effective_mode;
                if let Some(linked_ino) = self.tree.node(child_idx).link {
                    if self.inodes[(linked_ino - 1) as usize].links_count == 0 {
                        continue;
                    }
                    effective_ino = linked_ino;
                    effective_mode = self.inodes[(linked_ino - 1) as usize].mode;
                } else {
                    if self.inodes[(child_ino - 1) as usize].links_count == 0 {
                        continue;
                    }
                    effective_ino = child_ino;
                    effective_mode = self.inodes[(child_ino - 1) as usize].mode;
                }

                let (link_inode, link_mode) = if self.tree.node(child_idx).link.is_some() {
                    (Some(effective_ino), Some(effective_mode))
                } else {
                    (None, None)
                };

                dir::write_dir_entry(
                    &mut dir_buf,
                    &child_name,
                    child_ino,
                    self.inodes[(child_ino.max(1) - 1) as usize].mode,
                    link_inode,
                    link_mode,
                    self.block_size,
                    &mut left,
                )?;
            }

            dir::finish_dir_entry_block(&mut dir_buf, &mut left, self.block_size)?;

            let mut ranges = self.write_aligned_payload_bytes(&dir_buf)?;
            let size = dir_buf.len() as u64;
            let mut inode = self.inodes[(inode_num - 1) as usize].clone();
            inode.set_file_size(size);
            let mapped = dense_map(&ranges)?;
            self.write_inode_map(&mut inode, &mapped, &mut ranges)?;
            self.inodes[(inode_num - 1) as usize] = inode;
            Self::assign_node_ranges(self.tree.node_mut(node_idx), &ranges);
        }

        Ok(())
    }

    /// Write all inodes sequentially, padding to fill inode tables for all
    /// block groups.
    fn commit_inode_table(
        &mut self,
        block_groups: u32,
        inodes_per_group: u32,
    ) -> FormatResult<u64> {
        self.align_to_block()?;
        let inode_table_offset = self.pos()? / self.block_size as u64;

        // Write the actual inodes.
        let mut inode_buf = [0u8; Inode::SIZE];
        for inode in &self.inodes {
            inode.write_to(&mut inode_buf);
            self.file.write_all(&inode_buf)?;
        }

        // Pad the rest of the table with zeros.
        let table_size = INODE_SIZE as u64 * block_groups as u64 * inodes_per_group as u64;
        let written = self.inodes.len() as u64 * INODE_SIZE as u64;
        let rest = table_size - written;
        if rest > 0 {
            let zero_block = vec![0u8; self.block_size as usize];
            let full_blocks = rest / self.block_size as u64;
            for _ in 0..full_blocks {
                self.file.write_all(&zero_block)?;
            }
            let remainder = (rest % self.block_size as u64) as usize;
            if remainder > 0 {
                self.file.write_all(&vec![0u8; remainder])?;
            }
        }

        Ok(inode_table_offset)
    }

    fn allocate_resize_inode_dind_block(&mut self) -> FormatResult<u32> {
        let zero_block = vec![0u8; self.block_size as usize];
        let ranges = self.write_aligned_payload_bytes(&zero_block)?;
        let range = ranges
            .first()
            .ok_or(FormatError::InsufficientSpaceForGroupDescriptorBlocks)?;
        Ok(range.start)
    }

    fn configure_resize_inode(
        &mut self,
        dind_block: u32,
        reserved_gdt_blocks: u32,
        backup_group_count: u32,
    ) {
        let (time_lo, time_extra) = timestamp_now();
        let addr_per_block = (self.block_size / 4) as u64;
        let inode_size = (addr_per_block * addr_per_block + addr_per_block + EXT2_NDIR_BLOCKS)
            * self.block_size as u64;
        let owned_blocks = 1 + reserved_gdt_blocks * (1 + backup_group_count);

        let mut inode = Inode {
            mode: file_mode::S_IFREG | 0o600,
            links_count: 1,
            extra_isize: EXTRA_ISIZE,
            atime: time_lo,
            ctime: time_lo,
            mtime: time_lo,
            crtime: time_lo,
            atime_extra: time_extra,
            ctime_extra: time_extra,
            mtime_extra: time_extra,
            crtime_extra: time_extra,
            ..Inode::default()
        };
        inode.set_file_size(inode_size);
        inode.blocks_lo = owned_blocks * (self.block_size / 512);
        let offset = EXT2_DIND_BLOCK * 4;
        inode.block[offset..offset + 4].copy_from_slice(&dind_block.to_le_bytes());

        self.inodes[(RESIZE_INODE_NUMBER - 1) as usize] = inode;
    }

    fn backup_groups(&self, total_groups: u32) -> Vec<u32> {
        (1..total_groups)
            .filter(|group| Self::has_sparse_super_backup(*group))
            .collect()
    }

    fn write_resize_inode_blocks(
        &mut self,
        dind_block: u32,
        descriptor_blocks: u32,
        reserved_gdt_blocks: u32,
        backup_groups: &[u32],
    ) -> FormatResult<()> {
        let mut dind_buf = vec![0u8; self.block_size as usize];
        let blocks_per_group = self.blocks_per_group();

        for rsv_off in 0..reserved_gdt_blocks {
            let gdt_blk = 1 + descriptor_blocks + rsv_off;
            let dind_index = descriptor_blocks + rsv_off;
            let dind_offset = dind_index as usize * 4;
            dind_buf[dind_offset..dind_offset + 4].copy_from_slice(&gdt_blk.to_le_bytes());

            let mut gdt_buf = vec![0u8; self.block_size as usize];
            for (idx, group) in backup_groups.iter().enumerate() {
                let backup_gdt_block = gdt_blk + group * blocks_per_group;
                let offset = idx * 4;
                gdt_buf[offset..offset + 4].copy_from_slice(&backup_gdt_block.to_le_bytes());
            }

            self.seek_to_block(gdt_blk)?;
            self.file.write_all(&gdt_buf)?;
        }

        self.seek_to_block(dind_block)?;
        self.file.write_all(&dind_buf)?;
        self.seek_to_block(dind_block + 1)?;
        Ok(())
    }

    /// Find the (block_groups, inodes_per_group) pair that minimizes the
    /// number of block groups needed to hold all inodes and all data blocks.
    fn optimize_block_group_layout(&self, blocks: u32, inodes: u32) -> (u32, u32) {
        let group_count = |blocks: u32, inodes: u32, ipg: u32| -> u32 {
            let inode_blocks_per_group = ipg * INODE_SIZE / self.block_size;
            // 2 blocks reserved for bitmaps.
            let data_blocks_per_group = self.blocks_per_group() - inode_blocks_per_group - 2;
            // Ensure enough groups for all the inodes.
            let min_blocks = (inodes.saturating_sub(1)) / ipg * data_blocks_per_group + 1;
            let effective_blocks = blocks.max(min_blocks);
            effective_blocks.div_ceil(data_blocks_per_group)
        };

        let inc = (self.block_size * 512 / INODE_SIZE) as usize;
        let mut best_groups = u32::MAX;
        let mut best_ipg: u32 = inc as u32;

        let mut ipg = inc;
        while ipg <= self.max_inodes_per_group() as usize {
            let g = group_count(blocks, inodes, ipg as u32);
            if g < best_groups {
                best_groups = g;
                best_ipg = ipg as u32;
            }
            ipg += inc;
        }

        (best_groups, best_ipg)
    }
}

// ---------------------------------------------------------------------------
// Free-standing helpers
// ---------------------------------------------------------------------------

#[inline]
fn block_ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// Reject path components that cannot be represented in ext4 dir entries.
fn validate_path_component_names(path: &[u8]) -> FormatResult<()> {
    if path.contains(&0) {
        return Err(FormatError::InvalidPathEncoding(format!("{path:?}")));
    }
    for name in path.split(|byte| *byte == b'/') {
        if name == b"." || name == b".." {
            return Err(FormatError::InvalidPathEncoding(format!("{path:?}")));
        }
        if name.len() > EXT4_NAME_LEN {
            return Err(FormatError::InvalidName(match std::str::from_utf8(name) {
                Ok(name) => name.to_owned(),
                Err(_) => format!("{name:?}"),
            }));
        }
    }
    Ok(())
}

fn raw_path_buf(path: &[u8]) -> std::path::PathBuf {
    std::path::PathBuf::from(std::ffi::OsStr::from_bytes(path))
}

fn parent_of(path: &[u8]) -> &[u8] {
    let end = path
        .iter()
        .rposition(|byte| *byte != b'/')
        .map_or(0, |index| index + 1);
    let trimmed = &path[..end];
    match trimmed.iter().rposition(|byte| *byte == b'/') {
        Some(0) | None => b"/",
        Some(position) => &trimmed[..position],
    }
}

fn basename(path: &[u8]) -> &[u8] {
    let end = path
        .iter()
        .rposition(|byte| *byte != b'/')
        .map_or(0, |index| index + 1);
    if end == 0 {
        return b"/";
    }
    let trimmed = &path[..end];
    match trimmed.iter().rposition(|byte| *byte == b'/') {
        Some(position) => &trimmed[position + 1..],
        None => trimmed,
    }
}

fn set_timestamps(inode: &mut Inode, ts: FileTimestamps) {
    inode.atime = ts.access_lo;
    inode.atime_extra = ts.access_hi;
    inode.mtime = ts.modification_lo;
    inode.mtime_extra = ts.modification_hi;
    inode.ctime = ts.now_lo;
    inode.ctime_extra = ts.now_hi;
    inode.crtime = ts.creation_lo;
    inode.crtime_extra = ts.creation_hi;
}

fn validate_timestamps(ts: FileTimestamps) -> FormatResult<()> {
    if [ts.access_hi, ts.modification_hi, ts.creation_hi, ts.now_hi]
        .into_iter()
        .any(|extra| extra >> 2 >= 1_000_000_000)
    {
        return Err(FormatError::InvalidMetadata(
            "invalid ext4 timestamp nanoseconds",
        ));
    }
    Ok(())
}

fn dense_map(ranges: &[BlockRange]) -> FormatResult<Vec<extent::MappedExtent>> {
    let mut logical = 0u32;
    let mut mapped = Vec::with_capacity(ranges.len());
    for range in ranges {
        let length = range
            .end
            .checked_sub(range.start)
            .ok_or(FormatError::SizeOverflow)?;
        mapped.push(extent::MappedExtent {
            logical,
            physical: range.start,
            length,
            unwritten: false,
        });
        logical = logical
            .checked_add(length)
            .ok_or(FormatError::SizeOverflow)?;
    }
    Ok(mapped)
}

#[cfg(test)]
mod tests {
    use crate::ext4::formatter::*;

    #[test]
    fn test_parent_of() {
        assert_eq!(parent_of(b"/"), b"/");
        assert_eq!(parent_of(b"/foo"), b"/");
        assert_eq!(parent_of(b"/foo/bar"), b"/foo");
        assert_eq!(parent_of(b"/a/b/c"), b"/a/b");
    }

    #[test]
    fn test_basename() {
        assert_eq!(basename(b"/"), b"/");
        assert_eq!(basename(b"/foo"), b"foo");
        assert_eq!(basename(b"/foo/bar"), b"bar");
        assert_eq!(basename(b"/a/b/c"), b"c");
    }

    #[test]
    fn test_formatter_new_and_close() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let fmt = Formatter::new(&path, 4096, 256 * 1024).unwrap();
        fmt.close().unwrap();

        // The file should exist and have non-zero size.
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.len() > 0);
    }

    #[test]
    fn close_preserves_payloads_written_past_requested_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let mut fmt = Formatter::new(&path, 4096, 128 * 1024 * 1024).unwrap();

        // Simulate regular file payloads filling the requested size and pushing
        // the directory payload region into the next block group without paying
        // the test cost of writing a large tarball.
        let root_directory_block = fmt.blocks_per_group() + 100;
        fmt.seek_to_block(root_directory_block).unwrap();

        fmt.close().unwrap();

        let mut reader = crate::ext4::Reader::new(&path).unwrap();
        let root_entries = reader.children_of(ROOT_INODE).unwrap();
        assert!(root_entries.iter().any(|(name, _)| name == b"."));
        assert!(root_entries.iter().any(|(name, _)| name == b".."));
        assert!(root_entries.iter().any(|(name, _)| name == b"lost+found"));
    }

    #[test]
    fn flex_metadata_does_not_overlap_sparse_super_system_zones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let mut fmt = Formatter::new(&path, 4096, 768 * 1024 * 1024).unwrap();

        // Push the final inode-table/bitmap run near the group-5 sparse-super
        // backup area without writing a huge fixture. Linux rejects overlapping
        // system zones during ext4_setup_system_zone().
        let root_directory_block = 5 * fmt.blocks_per_group() - 64;
        fmt.seek_to_block(root_directory_block).unwrap();
        fmt.close().unwrap();

        let mut reader = crate::ext4::Reader::new(&path).unwrap();
        let sb = reader.superblock().clone();
        let block_size = 1024u64 * (1 << sb.log_block_size);
        let group_count = (sb.blocks_count_lo - 1) / sb.blocks_per_group + 1;
        let groups_per_descriptor_block = block_size as u32 / GroupDescriptor::SIZE as u32;
        let descriptor_blocks = (group_count - 1) / groups_per_descriptor_block + 1;
        let static_metadata_blocks = 1 + descriptor_blocks + sb.reserved_gdt_blocks as u32;
        let inode_table_blocks = sb.inodes_per_group * INODE_SIZE / block_size as u32;

        assert!(group_count >= 6, "test image must reach sparse group 5");

        for group in 0..group_count {
            let gd = reader.get_group_descriptor(group).unwrap();
            let metadata_ranges = [
                ("block bitmap", gd.block_bitmap_lo, gd.block_bitmap_lo + 1),
                ("inode bitmap", gd.inode_bitmap_lo, gd.inode_bitmap_lo + 1),
                (
                    "inode table",
                    gd.inode_table_lo,
                    gd.inode_table_lo + inode_table_blocks,
                ),
            ];

            for protected_group in 0..group_count {
                if !Formatter::has_sparse_super(protected_group) {
                    continue;
                }

                let protected_start = protected_group * sb.blocks_per_group;
                let protected_end = protected_start + static_metadata_blocks;

                for (name, start, end) in metadata_ranges {
                    assert!(
                        !block_ranges_overlap(
                            start as u64,
                            end as u64,
                            protected_start as u64,
                            protected_end as u64
                        ),
                        "group {group} {name} range {start}..{end} overlaps sparse-super system zone {protected_start}..{protected_end} in group {protected_group}",
                    );
                }
            }
        }

        let mut image = std::fs::File::open(&path).unwrap();
        let skipped_gap_block = 5 * sb.blocks_per_group - 1;
        let skipped_gap_group = skipped_gap_block / sb.blocks_per_group;
        let skipped_gap_gd = reader.get_group_descriptor(skipped_gap_group).unwrap();
        let mut skipped_gap_bitmap = vec![0u8; block_size as usize];
        image
            .seek(SeekFrom::Start(
                skipped_gap_gd.block_bitmap_lo as u64 * block_size,
            ))
            .unwrap();
        image.read_exact(&mut skipped_gap_bitmap).unwrap();
        let skipped_gap_bit = skipped_gap_block % sb.blocks_per_group;
        assert_eq!(
            skipped_gap_bitmap[(skipped_gap_bit / 8) as usize] & (1u8 << (skipped_gap_bit % 8)),
            0,
            "normal block {skipped_gap_block} skipped before group 5's sparse-super zone must remain free",
        );

        let protected_gd = reader.get_group_descriptor(5).unwrap();
        let mut protected_bitmap = vec![0u8; block_size as usize];
        image
            .seek(SeekFrom::Start(
                protected_gd.block_bitmap_lo as u64 * block_size,
            ))
            .unwrap();
        image.read_exact(&mut protected_bitmap).unwrap();
        assert_ne!(
            protected_bitmap[0] & 1,
            0,
            "group 5 sparse-super block must stay allocated",
        );
    }

    #[test]
    fn flex_metadata_relocation_promotes_overlapped_extra_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let mut fmt = Formatter::new(&path, 4096, 256 * 1024).unwrap();
        let blocks_per_group = fmt.blocks_per_group();
        let initial_block_groups = 82;
        let initial_inodes_per_group = 8192;
        let initial_inode_table_blocks = initial_inodes_per_group * INODE_SIZE / fmt.block_size;
        let data_blocks_per_group = blocks_per_group - initial_inode_table_blocks - 2;
        let metadata_start = initial_block_groups * data_blocks_per_group;

        let (block_groups, inodes_per_group) =
            fmt.optimize_block_group_layout(metadata_start, fmt.inodes.len() as u32);
        assert_eq!(block_groups, initial_block_groups);
        assert_eq!(inodes_per_group, initial_inodes_per_group);

        let inode_table_size_per_group = inodes_per_group * INODE_SIZE / fmt.block_size;
        let unshifted_metadata_end =
            metadata_start + block_groups * (inode_table_size_per_group + 2);
        assert_eq!(
            unshifted_metadata_end,
            block_groups * blocks_per_group,
            "the shared metadata run must initially end at the group-82 boundary",
        );

        // Keep one genuinely empty group after the group promoted by relocation.
        fmt.size = 84u64 * blocks_per_group as u64 * fmt.block_size as u64;
        let minimum_disk_size = (block_groups - 1) * blocks_per_group + 1;
        let layout = fmt.flex_metadata_layout(
            metadata_start,
            block_groups,
            inode_table_size_per_group,
            minimum_disk_size,
        );

        assert!(
            layout.inode_table_offset > metadata_start,
            "group 81's sparse-super zone must shift the shared metadata run",
        );
        assert_eq!(
            layout.block_groups, 83,
            "the group crossed by the shifted shared run must be promoted",
        );
        assert_eq!(layout.total_groups, 84);

        let first_extra_group_start = layout.block_groups * blocks_per_group;
        let first_extra_metadata_end = first_extra_group_start
            + fmt.static_metadata_blocks_in_group_for_area(
                layout.block_groups,
                layout.gd_area_blocks,
            )
            + inode_table_size_per_group
            + 2;
        assert!(
            !block_ranges_overlap(
                layout.inode_table_offset as u64,
                layout.data_size as u64,
                first_extra_group_start as u64,
                first_extra_metadata_end as u64,
            ),
            "shared metadata must not overlap the first extra group's local metadata",
        );
    }

    #[test]
    fn test_create_file_and_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let mut fmt = Formatter::new(&path, 4096, 1024 * 1024).unwrap();

        // Create a nested directory.
        fmt.create(
            "/etc",
            make_mode(file_mode::S_IFDIR, 0o755),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        // Create a regular file with content.
        let data = b"hello world\n";
        let mut cursor = std::io::Cursor::new(&data[..]);
        fmt.create(
            "/etc/motd",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(crate::ext4::FileData::Dense(&mut cursor)),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        // Create a symlink.
        fmt.create(
            "/etc/motd.link",
            make_mode(file_mode::S_IFLNK, 0o777),
            Some("motd".as_bytes()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        fmt.close().unwrap();
    }

    #[test]
    fn test_hard_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let mut fmt = Formatter::new(&path, 4096, 1024 * 1024).unwrap();

        let data = b"content";
        let mut cursor = std::io::Cursor::new(&data[..]);
        fmt.create(
            "/file",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(crate::ext4::FileData::Dense(&mut cursor)),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        fmt.link("/hardlink", "/file").unwrap();
        fmt.close().unwrap();
    }

    #[test]
    fn test_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let mut fmt = Formatter::new(&path, 4096, 1024 * 1024).unwrap();

        fmt.create(
            "/dir/nested",
            make_mode(file_mode::S_IFDIR, 0o755),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        fmt.remove("/dir").unwrap();
        fmt.close().unwrap();
    }

    #[test]
    fn test_mkdir_p_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let mut fmt = Formatter::new(&path, 4096, 1024 * 1024).unwrap();

        // Creating the same directory twice should succeed (mkdir -p semantics).
        fmt.create(
            "/var/log",
            make_mode(file_mode::S_IFDIR, 0o755),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        fmt.create(
            "/var/log",
            make_mode(file_mode::S_IFDIR, 0o755),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        fmt.close().unwrap();
    }

    #[test]
    fn test_large_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");
        let mut fmt = Formatter::new(&path, 4096, 4 * 1024 * 1024).unwrap();

        // Create a file larger than one block.
        let data = vec![0xABu8; 8192];
        let mut cursor = std::io::Cursor::new(&data[..]);
        fmt.create(
            "/big",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(crate::ext4::FileData::Dense(&mut cursor)),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        fmt.close().unwrap();
    }

    fn linux_acl() -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, permission, id) in [
            (1u16, 6u16, u32::MAX),
            (2, 4, 1001),
            (4, 4, u32::MAX),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&permission.to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn raw_namespace_and_all_inode_metadata_survive_the_ext4_boundary() {
        use crate::ext4::{DeviceId, FileData, Reader};
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("metadata.raw");
        let mut formatter = Formatter::new(&image, 4096, 128 << 20).unwrap();
        formatter.remove("/lost+found").unwrap();
        let time = FileTimestamps::from_mtime(2_147_483_648, 987_654_321).unwrap();
        let acl = linux_acl();
        let large = vec![0x93; 2750];
        let capability = [1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let attrs = [
            (b"user.raw\xff".as_slice(), large.as_slice()),
            (b"security.capability", capability.as_slice()),
            (b"system.posix_acl_access", acl.as_slice()),
        ];
        formatter
            .create(
                "/",
                file_mode::S_IFDIR | 0o751,
                None,
                Some(time),
                None,
                Some(100_000),
                Some(200_000),
                Some(&[(b"user.root", b"\0root\xff")]),
                None,
            )
            .unwrap();
        formatter
            .create(
                b"/dir \xff",
                file_mode::S_IFDIR | 0o750,
                None,
                Some(time),
                None,
                Some(100_001),
                Some(200_001),
                Some(&[(b"system.posix_acl_default", &acl)]),
                None,
            )
            .unwrap();
        formatter
            .create(
                b"/dir \xff/f \xfe",
                file_mode::S_IFREG | 0o640,
                None,
                Some(time),
                Some(FileData::Dense(&mut b"payload".as_slice())),
                Some(100_002),
                Some(200_002),
                Some(&attrs),
                None,
            )
            .unwrap();
        formatter.link(b"/alias\xfd", b"/dir \xff/f \xfe").unwrap();
        formatter.link(b"/alias2\xfc", b"/alias\xfd").unwrap();
        formatter
            .create(
                b"/link\xfb",
                file_mode::S_IFLNK | 0o777,
                Some(b"dir \xff/f \xfe"),
                Some(time),
                None,
                Some(100_003),
                Some(200_003),
                Some(&[(b"user.link", b"exact\0\xff")]),
                None,
            )
            .unwrap();
        for (path, mode, device) in [
            (b"/fifo".as_slice(), file_mode::S_IFIFO, None),
            (b"/socket", file_mode::S_IFSOCK, None),
            (
                b"/char",
                file_mode::S_IFCHR,
                Some(DeviceId::new(4095, 0xfffff).unwrap()),
            ),
            (
                b"/block",
                file_mode::S_IFBLK,
                Some(DeviceId::new(4094, 0x80001).unwrap()),
            ),
        ] {
            formatter
                .create(
                    path,
                    mode | 0o640,
                    None,
                    Some(time),
                    None,
                    Some(123),
                    Some(456),
                    None,
                    device,
                )
                .unwrap();
        }
        formatter.close().unwrap();
        let mut reader = Reader::new(&image).unwrap();
        assert!(!reader.exists("/lost+found"));
        assert_eq!(reader.read_link(b"/link\xfb").unwrap(), b"dir \xff/f \xfe");
        assert_eq!(reader.read_file(b"/link\xfb", 0, None).unwrap(), b"payload");
        let (ino, inode) = reader.stat(b"/dir \xff/f \xfe").unwrap();
        assert_eq!(reader.stat(b"/alias\xfd").unwrap().0, ino);
        assert_eq!(reader.stat(b"/alias2\xfc").unwrap().0, ino);
        assert_eq!(inode.links_count, 3);
        assert_eq!(
            (inode.uid_full(), inode.gid_full(), inode.mode),
            (100_002, 200_002, file_mode::S_IFREG | 0o640)
        );
        assert_eq!(
            (inode.mtime, inode.mtime_extra),
            (0x8000_0000, (987_654_321 << 2) | 1)
        );
        let actual = reader.xattrs(b"/dir \xff/f \xfe").unwrap();
        for (name, value) in attrs {
            assert_eq!(actual.get(name).unwrap(), value);
        }
        assert_eq!(actual.len(), 3, "no synthesized sentinel attributes");
        assert_eq!(
            reader
                .xattrs(b"/dir \xff")
                .unwrap()
                .get(b"system.posix_acl_default".as_slice())
                .unwrap(),
            &acl
        );
        assert_eq!(
            reader
                .xattrs(b"/link\xfb")
                .unwrap()
                .get(b"user.link".as_slice())
                .unwrap(),
            b"exact\0\xff"
        );
        let root = reader.stat("/").unwrap().1;
        assert_eq!(
            (root.uid_full(), root.gid_full(), root.mode & 0o7777),
            (100_000, 200_000, 0o751)
        );
        assert_eq!(
            (root.mtime, root.mtime_extra),
            (time.modification_lo, time.modification_hi)
        );
        assert_eq!(
            reader
                .xattrs("/")
                .unwrap()
                .get(b"user.root".as_slice())
                .unwrap(),
            b"\0root\xff"
        );
        let character = reader.stat("/char").unwrap().1;
        assert_eq!(character.flags, 0);
        assert_eq!(&character.block[4..8], &u32::MAX.to_le_bytes());
        for (path, mode) in [
            ("/fifo", file_mode::S_IFIFO),
            ("/socket", file_mode::S_IFSOCK),
            ("/char", file_mode::S_IFCHR),
            ("/block", file_mode::S_IFBLK),
        ] {
            let inode = reader.stat(path).unwrap().1;
            assert_eq!(inode.mode & file_mode::TYPE_MASK, mode);
            assert_eq!(
                (inode.uid_full(), inode.gid_full(), inode.blocks_lo),
                (123, 456, 0)
            );
        }
    }

    #[test]
    fn sparse_files_preserve_unaligned_ranges_and_one_tib_holes_without_scanning() {
        use crate::ext4::{FileData, FileRange, Reader, SparseData};
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("sparse.raw");
        let mut formatter = Formatter::new(&image, 4096, 128 << 20).unwrap();
        let length = 1u64 << 40;
        let mut ranges = [
            FileRange {
                offset: 1,
                length: 3,
            },
            FileRange {
                offset: 8,
                length: 2,
            },
            FileRange {
                offset: 4095,
                length: 3,
            },
            FileRange {
                offset: length - 4,
                length: 4,
            },
            FileRange {
                offset: length,
                length: 0,
            },
        ]
        .into_iter();
        let mut stored = b"abcdefghTAIL".as_slice();
        formatter
            .create(
                "/sparse",
                file_mode::S_IFREG | 0o644,
                None,
                None,
                Some(FileData::Sparse(SparseData {
                    reader: &mut stored,
                    length,
                    ranges: &mut ranges,
                })),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let mut no_ranges = std::iter::empty();
        formatter
            .create(
                "/hole",
                file_mode::S_IFREG | 0o644,
                None,
                None,
                Some(FileData::Sparse(SparseData {
                    reader: &mut std::io::empty(),
                    length,
                    ranges: &mut no_ranges,
                })),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        formatter.close().unwrap();
        let mut reader = Reader::new(&image).unwrap();
        let inode = reader.stat("/sparse").unwrap().1;
        assert_eq!(inode.file_size(), length);
        assert_eq!(inode.blocks_lo, 3);
        assert_eq!(
            reader.read_file("/sparse", 0, Some(12)).unwrap(),
            b"\0abc\0\0\0\0de\0\0"
        );
        assert_eq!(
            reader.read_file("/sparse", 4093, Some(7)).unwrap(),
            b"\0\0fgh\0\0"
        );
        assert_eq!(
            reader.read_file("/sparse", length - 4, Some(10)).unwrap(),
            b"TAIL"
        );
        assert_eq!(
            reader.read_file("/hole", length - 16, Some(16)).unwrap(),
            [0; 16]
        );
        assert_eq!(reader.stat("/hole").unwrap().1.blocks_lo, 0);
        assert_eq!(std::fs::metadata(image).unwrap().len(), 128 << 20);
    }

    #[test]
    fn rejects_malformed_sparse_maps_and_metadata_without_publication() {
        use crate::ext4::{DeviceId, FileData, FileRange, SparseData};
        for ranges in [
            vec![
                FileRange {
                    offset: 2,
                    length: 3,
                },
                FileRange {
                    offset: 4,
                    length: 1,
                },
            ],
            vec![FileRange {
                offset: u64::MAX,
                length: 2,
            }],
            vec![FileRange {
                offset: 0,
                length: 0,
            }],
            vec![FileRange {
                offset: 9,
                length: 2,
            }],
        ] {
            let directory = tempfile::tempdir().unwrap();
            let image = directory.path().join("bad.raw");
            let mut formatter = Formatter::new(&image, 4096, 128 << 20).unwrap();
            let mut ranges = ranges.into_iter();
            let mut data = std::io::repeat(0).take(4);
            assert!(
                formatter
                    .create(
                        "/bad",
                        file_mode::S_IFREG | 0o600,
                        None,
                        None,
                        Some(FileData::Sparse(SparseData {
                            reader: &mut data,
                            length: 10,
                            ranges: &mut ranges
                        })),
                        None,
                        None,
                        None,
                        None
                    )
                    .is_err()
            );
            assert!(!formatter.exists("/bad"));
        }
        assert!(DeviceId::new(4096, 0).is_err());
        assert!(DeviceId::new(0, 1 << 20).is_err());
        assert!(FileTimestamps::from_mtime(0x3_8000_0000, 0).is_err());
        assert!(FileTimestamps::from_mtime(0, 1_000_000_000).is_err());
        for seconds in [
            0,
            2_147_483_647,
            2_147_483_648,
            4_294_967_295,
            4_294_967_296,
            0x3_7fff_ffff,
        ] {
            let ts = FileTimestamps::from_mtime(seconds, 123).unwrap();
            let decoded =
                ts.modification_lo as i32 as i64 + (((ts.modification_hi & 3) as i64) << 32);
            assert_eq!(decoded as u64, seconds);
            assert_eq!(ts.modification_hi >> 2, 123);
        }
    }

    #[test]
    fn sparse_index_nodes_never_overlap_backup_superblock_or_gdt() {
        use crate::ext4::{FileData, FileRange, Reader, SparseData};
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("backup-boundary.raw");
        let mut formatter = Formatter::new(&image, 4096, 256 << 20).unwrap();
        let before = formatter.current_block().unwrap();
        let data_start = 32768 - 2003;
        formatter.deleted_blocks.push(BlockRange {
            start: before,
            end: data_start,
        });
        formatter.seek_to_block(data_start).unwrap();
        let stored = vec![0x9d; 2000 * 4096];
        let mut ranges = (0..2000).map(|index| FileRange {
            offset: index * 3 * 4096,
            length: 4096,
        });
        formatter
            .create(
                "/sparse",
                file_mode::S_IFREG | 0o644,
                None,
                None,
                Some(FileData::Sparse(SparseData {
                    reader: &mut stored.as_slice(),
                    length: 6000 * 4096,
                    ranges: &mut ranges,
                })),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        formatter.close().unwrap();
        let mut reader = Reader::new(&image).unwrap();
        for index in [0, 339, 340, 1360, 1999] {
            assert_eq!(
                reader
                    .read_file("/sparse", index * 3 * 4096, Some(32))
                    .unwrap(),
                [0x9d; 32]
            );
        }
        let mut file = std::fs::File::open(image).unwrap();
        let mut primary = [0u8; 4096];
        let mut backup = [0u8; 4096];
        file.seek(SeekFrom::Start(4096)).unwrap();
        file.read_exact(&mut primary).unwrap();
        file.seek(SeekFrom::Start((32768 + 1) * 4096)).unwrap();
        file.read_exact(&mut backup).unwrap();
        assert_eq!(primary, backup);
    }

    fn journal_prefix(formatter: &mut Formatter) -> (u64, [u8; 4096]) {
        let position = formatter.pos().unwrap();
        let journal = formatter.inodes[(journal::JOURNAL_INODE_NUMBER - 1) as usize].clone();
        let extents = extent::parse_extents(&journal, 4096, &mut formatter.file).unwrap();
        let offset = extents.first().unwrap().0 as u64 * 4096;
        let mut bytes = [0u8; 4096];
        formatter.file.seek(SeekFrom::Start(offset)).unwrap();
        formatter.file.read_exact(&mut bytes).unwrap();
        formatter.file.seek(SeekFrom::Start(position)).unwrap();
        assert_eq!(&bytes[..4], &0xc03b3998u32.to_be_bytes());
        (offset, bytes)
    }

    fn assert_journal_unchanged(expected: &[u8], observed: &[u8]) {
        assert_eq!(observed.len(), expected.len());
        if let Some(index) = expected
            .iter()
            .zip(observed)
            .position(|(before, after)| before != after)
        {
            assert_eq!(
                observed[index], expected[index],
                "journal prefix changed at byte {index}"
            );
        }
    }

    #[test]
    fn generic_append_consumes_actual_gdt_reservation_without_overwriting_journal() {
        use crate::ext4::{FileData, Reader};
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("descriptor-transition.raw");
        let mut formatter = Formatter::new(&image, 4096, 128 << 20).unwrap();
        let (journal_offset, original_journal) = journal_prefix(&mut formatter);
        let initial_area = formatter.group_descriptor_blocks();
        let before = formatter.current_block().unwrap();
        let target = (16u64 << 30) / 4096 + 100;
        // Existing payload APIs admit growth beyond the initial minimum. Place
        // a real tail file sparsely, freeing only the skipped nonsystem blocks.
        let groups = target.div_ceil(32768) as u32;
        let gaps = formatter.free_ranges_before_shifted_metadata(
            before,
            target as u32,
            groups,
            initial_area,
        );
        formatter.deleted_blocks.extend(gaps);
        formatter.seek_to_block(target as u32).unwrap();
        formatter
            .create(
                "/tail",
                file_mode::S_IFREG | 0o600,
                None,
                None,
                Some(FileData::Dense(&mut b"tail".as_slice())),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        formatter.close().unwrap();
        let mut reader = Reader::new(&image).unwrap();
        assert!(reader.superblock().blocks_count_lo as u64 * 4096 > 16u64 << 30);
        assert_eq!(reader.read_file("/tail", 0, None).unwrap(), b"tail");
        let mut file = File::open(image).unwrap();
        let mut observed = [0; 4096];
        file.seek(SeekFrom::Start(journal_offset)).unwrap();
        file.read_exact(&mut observed).unwrap();
        assert_journal_unchanged(&original_journal, &observed);
    }

    #[test]
    fn generic_append_refuses_exhausted_initial_gdt_area_without_journal_mutation() {
        use crate::ext4::FileData;
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("descriptor-exhausted.raw");
        let mut formatter = Formatter::new(&image, 4096, 128 << 20).unwrap();
        let (journal_offset, original_journal) = journal_prefix(&mut formatter);
        formatter
            .seek_to_block(((512u64 << 30) / 4096 + 100) as u32)
            .unwrap();
        formatter
            .create(
                "/tail",
                file_mode::S_IFREG | 0o600,
                None,
                None,
                Some(FileData::Dense(&mut b"tail".as_slice())),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(matches!(
            formatter.close(),
            Err(FormatError::InsufficientSpaceForGroupDescriptorBlocks)
        ));
        let mut file = File::open(image).unwrap();
        let mut observed = [0; 4096];
        file.seek(SeekFrom::Start(journal_offset)).unwrap();
        file.read_exact(&mut observed).unwrap();
        assert_journal_unchanged(&original_journal, &observed);
    }

    #[test]
    fn symlink_limit_rejects_before_overwrite_or_parent_creation() {
        use crate::ext4::Reader;
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("symlink-limit.raw");
        let mut formatter = Formatter::new(&image, 4096, 128 << 20).unwrap();
        let accepted = vec![b't'; 4095];
        formatter
            .create(
                "/link",
                file_mode::S_IFLNK | 0o777,
                Some(&accepted),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let position = formatter.pos().unwrap();
        let inodes = formatter.inodes.len();
        let rejected = vec![b't'; 4096];
        for path in ["/link", "/absent/rejected"] {
            assert!(matches!(
                formatter.create(
                    path,
                    file_mode::S_IFLNK | 0o777,
                    Some(&rejected),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None
                ),
                Err(FormatError::SymlinkTargetTooLong {
                    length: 4096,
                    maximum: 4095
                })
            ));
        }
        assert_eq!(formatter.pos().unwrap(), position);
        assert_eq!(formatter.inodes.len(), inodes);
        assert!(!formatter.exists("/absent"));
        formatter.close().unwrap();
        assert_eq!(
            Reader::new(&image).unwrap().read_link("/link").unwrap(),
            accepted
        );
    }
}
