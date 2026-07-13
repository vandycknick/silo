//! Offline grow-only resizer for filesystems produced by this crate.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::checksum;
use crate::constants::{self, bg_flags, compat, file_mode, incompat, ro_compat};
use crate::error::{ResizeError, ResizeResult};
use crate::extent;
use crate::journal;
use crate::layout;
use crate::types::{GroupDescriptor, Inode, SUPERBLOCK_SIZE, SuperBlock};

const BLOCK_SIZE: u32 = 4096;
const BLOCKS_PER_GROUP: u32 = BLOCK_SIZE * 8;
const DESCRIPTOR_SIZE: u32 = GroupDescriptor::SIZE as u32;
const RESIZE_INODE_NUMBER: u32 = 7;
const EXT2_DIND_BLOCK: usize = 13;
const EXT4_VALID_FS: u16 = 0x0001;
const EXT4_ERROR_FS: u16 = 0x0002;

const EXPECTED_COMPAT: u32 = compat::HAS_JOURNAL | compat::EXT_ATTR | compat::RESIZE_INODE;
const EXPECTED_INCOMPAT: u32 = incompat::FILETYPE | incompat::EXTENTS | incompat::FLEX_BG;
const EXPECTED_RO_COMPAT: u32 = ro_compat::SPARSE_SUPER
    | ro_compat::LARGE_FILE
    | ro_compat::HUGE_FILE
    | ro_compat::GDT_CSUM
    | ro_compat::EXTRA_ISIZE;

/// Result of a successful grow operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrowOutcome {
    pub old_blocks: u64,
    pub new_blocks: u64,
    pub old_groups: u32,
    pub new_groups: u32,
}

impl GrowOutcome {
    pub fn changed(self) -> bool {
        self.old_blocks != self.new_blocks
    }
}

struct ParsedImage {
    superblock: SuperBlock,
    descriptors: Vec<GroupDescriptor>,
    descriptor_span: u32,
    groups: u32,
    blocks: u64,
    inode_table_blocks: u32,
    resize_inode: Inode,
    resize_inode_offset: u64,
    resize_dind_block: u32,
}

struct BitmapWrite {
    block: u32,
    bytes: Vec<u8>,
}

struct GrowPlan {
    outcome: GrowOutcome,
    backing_size: u64,
    error_superblock: SuperBlock,
    final_superblock: SuperBlock,
    gdt: Vec<u8>,
    bitmap_writes: Vec<BitmapWrite>,
    resize_inode: Inode,
    resize_inode_offset: u64,
    resize_dind_block: u32,
    resize_dind: Vec<u8>,
    reserved_gdt_writes: Vec<BitmapWrite>,
    backup_groups: Vec<u32>,
}

/// Grow an unmounted Silo ext4 image to the requested block-aligned size.
///
/// The backing file may already be larger than the filesystem. The operation
/// never shrinks either the filesystem or the backing file.
pub fn grow_image(path: &Path, new_size_bytes: u64) -> ResizeResult<GrowOutcome> {
    if new_size_bytes % BLOCK_SIZE as u64 != 0 {
        return Err(ResizeError::UnalignedSize(new_size_bytes));
    }

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let image = parse_image(&mut file)?;
    let plan = plan_grow(&mut file, image, new_size_bytes)?;
    if !plan.outcome.changed() {
        if file.metadata()?.len() < plan.backing_size {
            file.set_len(plan.backing_size)?;
        }
        return Ok(plan.outcome);
    }

    apply_plan(&mut file, plan)
}

fn parse_image(file: &mut File) -> ResizeResult<ParsedImage> {
    let mut sb_buf = [0u8; SUPERBLOCK_SIZE];
    read_at(file, constants::SUPERBLOCK_OFFSET, &mut sb_buf)?;
    let superblock = SuperBlock::read_from(&sb_buf);

    if superblock.magic != constants::SUPERBLOCK_MAGIC {
        return Err(ResizeError::Corrupt("invalid superblock magic"));
    }
    if superblock.log_block_size != 2
        || superblock.first_data_block != 0
        || superblock.blocks_per_group != BLOCKS_PER_GROUP
        || superblock.clusters_per_group != BLOCKS_PER_GROUP
        || superblock.inode_size != constants::INODE_SIZE as u16
    {
        return Err(ResizeError::Unsupported("unsupported filesystem geometry"));
    }
    if superblock.feature_compat != EXPECTED_COMPAT {
        return Err(ResizeError::Unsupported(
            "unexpected compatible feature set",
        ));
    }
    if superblock.feature_incompat & incompat::RECOVER != 0 {
        return Err(ResizeError::RequiresRecovery);
    }
    if superblock.feature_incompat != EXPECTED_INCOMPAT {
        return Err(ResizeError::Unsupported(
            "unexpected incompatible feature set",
        ));
    }
    if superblock.feature_ro_compat != EXPECTED_RO_COMPAT {
        return Err(ResizeError::Unsupported(
            "unexpected read-only compatible feature set",
        ));
    }
    if superblock.state & EXT4_VALID_FS == 0 || superblock.state & EXT4_ERROR_FS != 0 {
        return Err(ResizeError::Corrupt("filesystem is not clean"));
    }
    if superblock.last_orphan != 0 {
        return Err(ResizeError::RequiresRecovery);
    }
    if superblock.journal_inum != journal::JOURNAL_INODE_NUMBER || superblock.journal_dev != 0 {
        return Err(ResizeError::Unsupported("unsupported journal location"));
    }
    if superblock.reserved_gdt_blocks == 0 {
        return Err(ResizeError::Unsupported(
            "filesystem has no reserved GDT capacity",
        ));
    }

    let blocks = superblock.blocks_count_lo as u64;
    if superblock.blocks_count_hi != 0 || blocks == 0 {
        return Err(ResizeError::Unsupported(
            "64-bit block counts are unsupported",
        ));
    }
    let filesystem_bytes = blocks
        .checked_mul(BLOCK_SIZE as u64)
        .ok_or(ResizeError::Corrupt("filesystem size overflows u64"))?;
    if file.metadata()?.len() < filesystem_bytes {
        return Err(ResizeError::Corrupt(
            "backing file is shorter than the filesystem",
        ));
    }

    let groups = layout::group_count(blocks, 0, BLOCKS_PER_GROUP);
    if groups == 0
        || groups
            .checked_mul(superblock.inodes_per_group)
            .ok_or(ResizeError::Corrupt("inode count overflows"))?
            != superblock.inodes_count
    {
        return Err(ResizeError::Corrupt("inconsistent group or inode count"));
    }
    let descriptor_blocks = layout::descriptor_blocks(groups, BLOCK_SIZE, DESCRIPTOR_SIZE);
    let descriptor_span = descriptor_blocks
        .checked_add(superblock.reserved_gdt_blocks as u32)
        .ok_or(ResizeError::Corrupt("resize inode GDT span overflows"))?;
    if descriptor_span > BLOCK_SIZE / 4 {
        return Err(ResizeError::Corrupt(
            "resize inode GDT span exceeds double-indirect block",
        ));
    }
    let mut gdt = vec![0u8; descriptor_blocks as usize * BLOCK_SIZE as usize];
    read_at(file, BLOCK_SIZE as u64, &mut gdt)?;
    let mut descriptors = Vec::with_capacity(groups as usize);
    for group in 0..groups {
        let offset = group as usize * GroupDescriptor::SIZE;
        let descriptor = GroupDescriptor::read_from(&gdt[offset..offset + GroupDescriptor::SIZE]);
        if checksum::group_descriptor(&superblock.uuid, group, &descriptor) != descriptor.checksum {
            return Err(ResizeError::Corrupt("group descriptor checksum mismatch"));
        }
        validate_descriptor(&descriptor, blocks, superblock.inodes_per_group)?;
        descriptors.push(descriptor);
    }

    let inode_table_blocks = superblock
        .inodes_per_group
        .checked_mul(superblock.inode_size as u32)
        .ok_or(ResizeError::Corrupt("inode table size overflows"))?
        / BLOCK_SIZE;
    if inode_table_blocks == 0 {
        return Err(ResizeError::Corrupt("inode table is empty"));
    }

    let resize_inode_offset = inode_offset(&descriptors, &superblock, RESIZE_INODE_NUMBER)?;
    let resize_inode = read_inode_at(file, resize_inode_offset)?;
    let resize_dind_block = validate_resize_inode(
        file,
        &superblock,
        descriptor_blocks,
        descriptor_span,
        groups,
        &resize_inode,
    )?;
    validate_clean_journal(file, &descriptors, &superblock)?;

    Ok(ParsedImage {
        superblock,
        descriptors,
        descriptor_span,
        groups,
        blocks,
        inode_table_blocks,
        resize_inode,
        resize_inode_offset,
        resize_dind_block,
    })
}

fn validate_descriptor(
    descriptor: &GroupDescriptor,
    blocks: u64,
    inodes_per_group: u32,
) -> ResizeResult<()> {
    let inode_table_blocks =
        inodes_per_group as u64 * constants::INODE_SIZE as u64 / BLOCK_SIZE as u64;
    let block_bitmap = descriptor.block_bitmap_lo as u64;
    let inode_bitmap = descriptor.inode_bitmap_lo as u64;
    let inode_table = descriptor.inode_table_lo as u64;
    if block_bitmap >= blocks
        || inode_bitmap >= blocks
        || inode_table >= blocks
        || inode_table + inode_table_blocks > blocks
    {
        return Err(ResizeError::Corrupt(
            "group metadata lies outside the filesystem",
        ));
    }
    Ok(())
}

fn validate_resize_inode(
    file: &mut File,
    superblock: &SuperBlock,
    descriptor_blocks: u32,
    descriptor_span: u32,
    groups: u32,
    inode: &Inode,
) -> ResizeResult<u32> {
    if inode.mode & file_mode::TYPE_MASK != file_mode::S_IFREG
        || inode.links_count != 1
        || inode.flags != 0
    {
        return Err(ResizeError::Corrupt("invalid resize inode"));
    }
    let dind_offset = EXT2_DIND_BLOCK * 4;
    let dind_block = u32::from_le_bytes(
        inode.block[dind_offset..dind_offset + 4]
            .try_into()
            .map_err(|_| ResizeError::Corrupt("invalid resize inode block field"))?,
    );
    if dind_block == 0 || dind_block as u64 >= superblock.blocks_count_lo as u64 {
        return Err(ResizeError::Corrupt(
            "invalid resize inode double-indirect block",
        ));
    }

    let mut dind = vec![0u8; BLOCK_SIZE as usize];
    read_block(file, dind_block, &mut dind)?;
    let backup_groups = backup_groups(groups);
    for index in descriptor_blocks..descriptor_span {
        let expected = 1 + index;
        if get_le32(&dind, index as usize * 4) != expected {
            return Err(ResizeError::Corrupt("resize inode GDT pointer mismatch"));
        }
        let mut pointers = vec![0u8; BLOCK_SIZE as usize];
        read_block(file, expected, &mut pointers)?;
        for (backup_index, group) in backup_groups.iter().enumerate() {
            let expected_backup = expected
                .checked_add(group.saturating_mul(BLOCKS_PER_GROUP))
                .ok_or(ResizeError::Corrupt("backup GDT pointer overflows"))?;
            if get_le32(&pointers, backup_index * 4) != expected_backup {
                return Err(ResizeError::Corrupt("resize inode backup pointer mismatch"));
            }
        }
    }
    Ok(dind_block)
}

fn validate_clean_journal(
    file: &mut File,
    descriptors: &[GroupDescriptor],
    superblock: &SuperBlock,
) -> ResizeResult<()> {
    let offset = inode_offset(descriptors, superblock, journal::JOURNAL_INODE_NUMBER)?;
    let inode = read_inode_at(file, offset)?;
    if inode.mode & file_mode::TYPE_MASK != file_mode::S_IFREG
        || inode.links_count == 0
        || inode.flags & constants::inode_flags::EXTENTS == 0
    {
        return Err(ResizeError::Corrupt("invalid journal inode"));
    }
    let ranges = extent::parse_extents(&inode, BLOCK_SIZE as u64, file)
        .map_err(|_| ResizeError::Corrupt("invalid journal extents"))?;
    let mapped_blocks: u64 = ranges.iter().map(|(start, end)| (end - start) as u64).sum();
    let journal_blocks = inode.file_size() / BLOCK_SIZE as u64;
    if journal_blocks < 1024 || mapped_blocks < journal_blocks {
        return Err(ResizeError::Corrupt("journal is not fully allocated"));
    }
    let first_block = ranges
        .first()
        .ok_or(ResizeError::Corrupt("journal has no blocks"))?
        .0;
    let mut block = vec![0u8; BLOCK_SIZE as usize];
    read_block(file, first_block, &mut block)?;
    let maximum_journal_blocks = get_be32(&block, 0x10) as u64;
    let first_journal_block = get_be32(&block, 0x14) as u64;
    if get_be32(&block, 0x00) != 0xC03B_3998
        || get_be32(&block, 0x04) != 4
        || get_be32(&block, 0x0C) != BLOCK_SIZE
        || maximum_journal_blocks < 1024
        || maximum_journal_blocks > journal_blocks
        || first_journal_block == 0
        || first_journal_block >= maximum_journal_blocks
        || get_be32(&block, 0x40) != 1
        || block[0x30..0x40] != superblock.uuid
    {
        return Err(ResizeError::Corrupt("invalid JBD2 superblock"));
    }
    if get_be32(&block, 0x20) != 0 {
        return Err(ResizeError::Corrupt(
            "journal records an aborted transaction",
        ));
    }
    if get_be32(&block, 0x1C) != 0 {
        return Err(ResizeError::RequiresRecovery);
    }
    let compat_features = get_be32(&block, 0x24);
    let incompat_features = get_be32(&block, 0x28);
    if compat_features != 0 || incompat_features & !0x1 != 0 || get_be32(&block, 0x2C) != 0 {
        return Err(ResizeError::Unsupported("unsupported JBD2 feature set"));
    }
    Ok(())
}

fn plan_grow(file: &mut File, mut image: ParsedImage, backing_size: u64) -> ResizeResult<GrowPlan> {
    let requested_blocks = backing_size / BLOCK_SIZE as u64;
    if requested_blocks > u32::MAX as u64 {
        return Err(ResizeError::TooLarge {
            requested_blocks,
            maximum_blocks: u32::MAX as u64,
        });
    }
    if requested_blocks < image.blocks {
        return Err(ResizeError::ShrinkUnsupported {
            current_blocks: image.blocks,
            requested_blocks,
        });
    }

    let mut new_blocks = requested_blocks;
    let mut new_groups = layout::group_count(new_blocks, 0, BLOCKS_PER_GROUP);
    if new_groups > image.groups {
        let last_group = new_groups - 1;
        let blocks_in_last = new_blocks - last_group as u64 * BLOCKS_PER_GROUP as u64;
        if blocks_in_last != BLOCKS_PER_GROUP as u64 {
            let system_blocks = if layout::has_sparse_super(last_group) {
                1 + image.descriptor_span
            } else {
                0
            };
            let minimum = system_blocks + 2 + image.inode_table_blocks + 1;
            if blocks_in_last <= minimum as u64 {
                new_blocks = last_group as u64 * BLOCKS_PER_GROUP as u64;
                new_groups -= 1;
            }
        }
    }

    let outcome = GrowOutcome {
        old_blocks: image.blocks,
        new_blocks,
        old_groups: image.groups,
        new_groups,
    };
    let mut error_superblock = image.superblock.clone();
    error_superblock.state = EXT4_VALID_FS | EXT4_ERROR_FS;
    if !outcome.changed() {
        return Ok(GrowPlan {
            outcome,
            backing_size,
            error_superblock,
            final_superblock: image.superblock,
            gdt: Vec::new(),
            bitmap_writes: Vec::new(),
            resize_inode: image.resize_inode,
            resize_inode_offset: image.resize_inode_offset,
            resize_dind_block: image.resize_dind_block,
            resize_dind: Vec::new(),
            reserved_gdt_writes: Vec::new(),
            backup_groups: Vec::new(),
        });
    }

    let new_descriptor_blocks = layout::descriptor_blocks(new_groups, BLOCK_SIZE, DESCRIPTOR_SIZE);
    let descriptor_span = image.descriptor_span;
    if new_descriptor_blocks > descriptor_span {
        return Err(ResizeError::GdtCapacityExceeded {
            required_descriptor_blocks: new_descriptor_blocks,
            available_descriptor_blocks: descriptor_span,
        });
    }
    let new_reserved_gdt = descriptor_span - new_descriptor_blocks;

    let mut bitmap_writes = Vec::new();
    let mut free_blocks_added = 0u64;
    if image.blocks % BLOCKS_PER_GROUP as u64 != 0 {
        let old_last_group = image.groups - 1;
        let group_end = (old_last_group as u64 + 1) * BLOCKS_PER_GROUP as u64;
        let expanded_end = new_blocks.min(group_end);
        if expanded_end > image.blocks {
            let descriptor = image
                .descriptors
                .get_mut(old_last_group as usize)
                .ok_or(ResizeError::Corrupt("missing final group descriptor"))?;
            if descriptor.flags & bg_flags::BLOCK_UNINIT != 0 {
                return Err(ResizeError::Corrupt(
                    "partial group has uninitialized bitmap",
                ));
            }
            let mut bitmap = vec![0u8; BLOCK_SIZE as usize];
            read_block(file, descriptor.block_bitmap_lo, &mut bitmap)?;
            let group_start = old_last_group as u64 * BLOCKS_PER_GROUP as u64;
            for block in image.blocks..expanded_end {
                clear_bit(&mut bitmap, (block - group_start) as u32);
            }
            let added = expanded_end - image.blocks;
            descriptor.free_blocks_count_lo = descriptor
                .free_blocks_count_lo
                .checked_add(added as u16)
                .ok_or(ResizeError::Corrupt("free block count overflows"))?;
            free_blocks_added += added;
            bitmap_writes.push(BitmapWrite {
                block: descriptor.block_bitmap_lo,
                bytes: bitmap,
            });
        }
    }

    for group in image.groups..new_groups {
        let group_start = group as u64 * BLOCKS_PER_GROUP as u64;
        let blocks_in_group = (new_blocks - group_start).min(BLOCKS_PER_GROUP as u64) as u32;
        let system_blocks = if layout::has_sparse_super(group) {
            1 + descriptor_span
        } else {
            0
        };
        let inode_table = group_start as u32 + system_blocks;
        let block_bitmap = inode_table + image.inode_table_blocks;
        let inode_bitmap = block_bitmap + 1;
        let used_blocks = system_blocks + image.inode_table_blocks + 2;
        if used_blocks >= blocks_in_group {
            return Err(ResizeError::Corrupt("new group is too small for metadata"));
        }

        let mut block_bitmap_bytes = vec![0u8; BLOCK_SIZE as usize];
        for block in 0..used_blocks {
            set_bit(&mut block_bitmap_bytes, block);
        }
        for block in blocks_in_group..BLOCKS_PER_GROUP {
            set_bit(&mut block_bitmap_bytes, block);
        }
        bitmap_writes.push(BitmapWrite {
            block: block_bitmap,
            bytes: block_bitmap_bytes,
        });

        let mut inode_bitmap_bytes = vec![0u8; BLOCK_SIZE as usize];
        for inode in image.superblock.inodes_per_group..BLOCKS_PER_GROUP {
            set_bit(&mut inode_bitmap_bytes, inode);
        }
        bitmap_writes.push(BitmapWrite {
            block: inode_bitmap,
            bytes: inode_bitmap_bytes,
        });

        let free_blocks = blocks_in_group - used_blocks;
        let mut flags = bg_flags::INODE_UNINIT;
        if group != new_groups - 1 {
            flags |= bg_flags::BLOCK_UNINIT;
        }
        image.descriptors.push(GroupDescriptor {
            block_bitmap_lo: block_bitmap,
            inode_bitmap_lo: inode_bitmap,
            inode_table_lo: inode_table,
            free_blocks_count_lo: free_blocks as u16,
            free_inodes_count_lo: image.superblock.inodes_per_group as u16,
            used_dirs_count_lo: 0,
            flags,
            exclude_bitmap_lo: 0,
            block_bitmap_csum_lo: 0,
            inode_bitmap_csum_lo: 0,
            itable_unused_lo: image.superblock.inodes_per_group as u16,
            checksum: 0,
        });
        free_blocks_added += free_blocks as u64;
    }

    let inode_count = new_groups as u64 * image.superblock.inodes_per_group as u64;
    if inode_count > u32::MAX as u64 {
        return Err(ResizeError::TooManyInodes);
    }

    let final_backup_groups = backup_groups(new_groups);
    let mut resize_dind = vec![0u8; BLOCK_SIZE as usize];
    let mut reserved_gdt_writes = Vec::new();
    for index in new_descriptor_blocks..descriptor_span {
        let primary = 1 + index;
        put_le32(&mut resize_dind, index as usize * 4, primary);
        let mut pointers = vec![0u8; BLOCK_SIZE as usize];
        for (backup_index, group) in final_backup_groups.iter().enumerate() {
            let backup = primary
                .checked_add(group.saturating_mul(BLOCKS_PER_GROUP))
                .ok_or(ResizeError::Corrupt("backup GDT pointer overflows"))?;
            put_le32(&mut pointers, backup_index * 4, backup);
        }
        reserved_gdt_writes.push(BitmapWrite {
            block: primary,
            bytes: pointers,
        });
    }

    let resize_owned_blocks =
        1u64 + new_reserved_gdt as u64 * (1 + final_backup_groups.len() as u64);
    image.resize_inode.blocks_lo =
        u32::try_from(resize_owned_blocks * (BLOCK_SIZE / 512) as u64)
            .map_err(|_| ResizeError::Corrupt("resize inode block count overflows"))?;

    let mut final_superblock = image.superblock.clone();
    final_superblock.blocks_count_lo = new_blocks as u32;
    final_superblock.free_blocks_count_lo = final_superblock
        .free_blocks_count_lo
        .checked_add(free_blocks_added as u32)
        .ok_or(ResizeError::Corrupt(
            "superblock free block count overflows",
        ))?;
    final_superblock.inodes_count = inode_count as u32;
    final_superblock.free_inodes_count = final_superblock
        .free_inodes_count
        .checked_add((new_groups - image.groups) * image.superblock.inodes_per_group)
        .ok_or(ResizeError::Corrupt(
            "superblock free inode count overflows",
        ))?;
    final_superblock.reserved_gdt_blocks = new_reserved_gdt as u16;
    final_superblock.state = EXT4_VALID_FS;

    let mut gdt = vec![0u8; new_descriptor_blocks as usize * BLOCK_SIZE as usize];
    for (group, descriptor) in image.descriptors.iter_mut().enumerate() {
        descriptor.checksum =
            checksum::group_descriptor(&final_superblock.uuid, group as u32, descriptor);
        let offset = group * GroupDescriptor::SIZE;
        descriptor.write_to(&mut gdt[offset..offset + GroupDescriptor::SIZE]);
    }

    Ok(GrowPlan {
        outcome,
        backing_size,
        error_superblock,
        final_superblock,
        gdt,
        bitmap_writes,
        resize_inode: image.resize_inode,
        resize_inode_offset: image.resize_inode_offset,
        resize_dind_block: image.resize_dind_block,
        resize_dind,
        reserved_gdt_writes,
        backup_groups: final_backup_groups,
    })
}

fn apply_plan(file: &mut File, plan: GrowPlan) -> ResizeResult<GrowOutcome> {
    if file.metadata()?.len() < plan.backing_size {
        file.set_len(plan.backing_size)?;
    }
    write_superblock(file, 0, &plan.error_superblock)?;
    file.sync_all()?;

    for write in &plan.bitmap_writes {
        write_block(file, write.block, &write.bytes)?;
    }
    write_block(file, plan.resize_dind_block, &plan.resize_dind)?;
    for write in &plan.reserved_gdt_writes {
        write_block(file, write.block, &write.bytes)?;
    }
    let mut inode_buf = [0u8; Inode::SIZE];
    plan.resize_inode.write_to(&mut inode_buf);
    write_at(file, plan.resize_inode_offset, &inode_buf)?;

    write_at(file, BLOCK_SIZE as u64, &plan.gdt)?;
    for group in &plan.backup_groups {
        let group_start = *group as u64 * BLOCKS_PER_GROUP as u64;
        write_at(file, (group_start + 1) * BLOCK_SIZE as u64, &plan.gdt)?;
        write_superblock(file, group_start, &plan.final_superblock)?;
    }
    file.sync_all()?;
    write_superblock(file, 0, &plan.final_superblock)?;
    file.sync_all()?;
    Ok(plan.outcome)
}

fn write_superblock(
    file: &mut File,
    group_start: u64,
    superblock: &SuperBlock,
) -> ResizeResult<()> {
    let mut sb = superblock.clone();
    sb.block_group_nr = (group_start / BLOCKS_PER_GROUP as u64) as u16;
    let mut buf = [0u8; SUPERBLOCK_SIZE];
    sb.write_to(&mut buf);
    let offset = if group_start == 0 {
        constants::SUPERBLOCK_OFFSET
    } else {
        group_start * BLOCK_SIZE as u64
    };
    write_at(file, offset, &buf)?;
    Ok(())
}

fn inode_offset(
    descriptors: &[GroupDescriptor],
    superblock: &SuperBlock,
    inode_number: u32,
) -> ResizeResult<u64> {
    let group = (inode_number - 1) / superblock.inodes_per_group;
    let index = (inode_number - 1) % superblock.inodes_per_group;
    let descriptor = descriptors
        .get(group as usize)
        .ok_or(ResizeError::Corrupt("inode group descriptor is missing"))?;
    Ok(descriptor.inode_table_lo as u64 * BLOCK_SIZE as u64
        + index as u64 * superblock.inode_size as u64)
}

fn read_inode_at(file: &mut File, offset: u64) -> ResizeResult<Inode> {
    let mut buf = [0u8; Inode::SIZE];
    read_at(file, offset, &mut buf)?;
    Ok(Inode::read_from(&buf))
}

fn backup_groups(groups: u32) -> Vec<u32> {
    (1..groups)
        .filter(|group| layout::has_sparse_super(*group))
        .collect()
}

fn read_block(file: &mut File, block: u32, buf: &mut [u8]) -> ResizeResult<()> {
    read_at(file, block as u64 * BLOCK_SIZE as u64, buf)
}

fn write_block(file: &mut File, block: u32, buf: &[u8]) -> ResizeResult<()> {
    write_at(file, block as u64 * BLOCK_SIZE as u64, buf)
}

fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> ResizeResult<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)?;
    Ok(())
}

fn write_at(file: &mut File, offset: u64, buf: &[u8]) -> ResizeResult<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(buf)?;
    Ok(())
}

fn get_le32(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn put_le32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn get_be32(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_be_bytes(bytes)
}

fn set_bit(bitmap: &mut [u8], bit: u32) {
    bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
}

fn clear_bit(bitmap: &mut [u8], bit: u32) {
    bitmap[(bit / 8) as usize] &= !(1 << (bit % 8));
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};

    use tempfile::tempdir;

    use crate::resizer::{BLOCK_SIZE, write_superblock};
    use crate::{Formatter, Reader, grow_image};

    #[test]
    fn grows_formatted_image_and_preserves_contents() {
        let dir = tempdir().expect("create temp directory");
        let path = dir.path().join("grow.ext4");
        let mut formatter = Formatter::new(&path, 4096, 256 * 1024).expect("create formatter");
        formatter
            .create(
                "/hello",
                crate::constants::make_mode(crate::constants::file_mode::S_IFREG, 0o644),
                None,
                None,
                Some(&mut "hello".as_bytes()),
                None,
                None,
                None,
            )
            .expect("create file");
        formatter.close().expect("finish image");

        let old_size = std::fs::metadata(&path).expect("image metadata").len();
        let target = old_size + 2 * 128 * 1024 * 1024;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open image")
            .set_len(target)
            .expect("extend backing file");

        let outcome = grow_image(&path, target).expect("grow filesystem");
        assert!(outcome.changed());
        assert_eq!(outcome.new_blocks * 4096, target);

        let mut reader = Reader::new(&path).expect("open grown image");
        assert_eq!(
            reader.read_file("/hello", 0, None).expect("read file"),
            b"hello"
        );
    }

    #[test]
    fn same_size_is_a_noop() {
        let dir = tempdir().expect("create temp directory");
        let path = dir.path().join("noop.ext4");
        Formatter::new(&path, 4096, 256 * 1024)
            .expect("create formatter")
            .close()
            .expect("finish image");
        let size = std::fs::metadata(&path).expect("image metadata").len();

        let outcome = grow_image(&path, size).expect("reconcile size");
        assert!(!outcome.changed());
    }

    #[test]
    fn refuses_dirty_journal_without_modifying_image() {
        let dir = tempdir().expect("create temp directory");
        let path = dir.path().join("dirty.ext4");
        Formatter::new(&path, 4096, 256 * 1024)
            .expect("create formatter")
            .close()
            .expect("finish image");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open image");
        let mut superblock = [0u8; 1024];
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.read_exact(&mut superblock).expect("read superblock");
        let incompat = u32::from_le_bytes(superblock[0x60..0x64].try_into().unwrap());
        superblock[0x60..0x64].copy_from_slice(&(incompat | 0x4).to_le_bytes());
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.write_all(&superblock).expect("write superblock");
        drop(file);
        let before_size = std::fs::metadata(&path).expect("image metadata").len();
        let mut before_superblock = [0u8; 1024];
        let mut file = std::fs::File::open(&path).expect("open image");
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.read_exact(&mut before_superblock)
            .expect("read superblock");

        let error = grow_image(&path, before_size + 128 * 1024 * 1024)
            .expect_err("dirty filesystem must require recovery");
        assert!(matches!(error, crate::error::ResizeError::RequiresRecovery));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before_size);
        let mut after_superblock = [0u8; 1024];
        let mut file = std::fs::File::open(&path).expect("open image");
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.read_exact(&mut after_superblock)
            .expect("read superblock");
        assert_eq!(after_superblock, before_superblock);
    }

    #[test]
    fn drops_final_group_that_cannot_hold_metadata() {
        let dir = tempdir().expect("create temp directory");
        let path = dir.path().join("partial.ext4");
        Formatter::new(&path, 4096, 256 * 1024)
            .expect("create formatter")
            .close()
            .expect("finish image");
        let old_size = std::fs::metadata(&path).expect("image metadata").len();
        let target = old_size + 4096;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open image")
            .set_len(target)
            .expect("extend backing file");

        let outcome = grow_image(&path, target).expect("reconcile filesystem");

        assert!(!outcome.changed());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), target);
    }

    #[test]
    fn consumes_reserved_gdt_block_at_descriptor_boundary() {
        let dir = tempdir().expect("create temp directory");
        let path = dir.path().join("gdt-boundary.ext4");
        let group_bytes = 128u64 * 1024 * 1024;
        Formatter::new(&path, 4096, 128 * group_bytes)
            .expect("create formatter")
            .close()
            .expect("finish image");
        let before = Reader::new(&path).expect("open image");
        assert_eq!(before.superblock().reserved_gdt_blocks, 31);
        let target = 129 * group_bytes;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open image")
            .set_len(target)
            .expect("extend backing file");

        let outcome = grow_image(&path, target).expect("grow across GDT boundary");
        let after = Reader::new(&path).expect("open grown image");

        assert_eq!(outcome.new_groups, 129);
        assert_eq!(after.superblock().reserved_gdt_blocks, 30);
        let mut after = after;
        let resize_inode = after.get_inode(7).expect("read resize inode");
        let dind_block = u32::from_le_bytes(resize_inode.block[52..56].try_into().unwrap());
        let mut file = std::fs::File::open(&path).expect("open image");
        let mut dind = vec![0u8; 4096];
        file.seek(SeekFrom::Start(dind_block as u64 * 4096))
            .expect("seek dind");
        file.read_exact(&mut dind).expect("read dind");
        assert_eq!(u32::from_le_bytes(dind[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(dind[8..12].try_into().unwrap()), 3);
    }

    #[test]
    fn rejects_target_beyond_32_bit_blocks_without_modifying_image() {
        let dir = tempdir().expect("create temp directory");
        let path = dir.path().join("too-large.ext4");
        Formatter::new(&path, 4096, 256 * 1024)
            .expect("create formatter")
            .close()
            .expect("finish image");
        let before_size = std::fs::metadata(&path).expect("image metadata").len();
        let mut before_superblock = [0u8; 1024];
        let mut file = std::fs::File::open(&path).expect("open image");
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.read_exact(&mut before_superblock)
            .expect("read superblock");

        let error =
            grow_image(&path, (u32::MAX as u64 + 1) * 4096).expect_err("oversized grow must fail");

        assert!(matches!(error, crate::error::ResizeError::TooLarge { .. }));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before_size);
        let mut after_superblock = [0u8; 1024];
        let mut file = std::fs::File::open(&path).expect("open image");
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.read_exact(&mut after_superblock)
            .expect("read superblock");
        assert_eq!(after_superblock, before_superblock);
    }

    #[test]
    fn rejects_reserved_gdt_span_larger_than_pointer_block() {
        let dir = tempdir().expect("create temp directory");
        let path = dir.path().join("oversized-gdt-span.ext4");
        Formatter::new(&path, 4096, 256 * 1024)
            .expect("create formatter")
            .close()
            .expect("finish image");
        let before_size = std::fs::metadata(&path).expect("image metadata").len();
        let mut superblock = Reader::new(&path).expect("open image").superblock().clone();
        superblock.reserved_gdt_blocks = (BLOCK_SIZE / 4) as u16;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open image");
        write_superblock(&mut file, 0, &superblock).expect("write malformed superblock");
        drop(file);

        let error = grow_image(&path, before_size + 128 * 1024 * 1024)
            .expect_err("oversized descriptor span must be rejected");

        assert!(matches!(
            error,
            crate::error::ResizeError::Corrupt(
                "resize inode GDT span exceeds double-indirect block"
            )
        ));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before_size);
    }
}
