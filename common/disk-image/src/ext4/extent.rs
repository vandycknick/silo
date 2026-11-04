//! Checked ext4 extent trees, including logical holes and multiple index levels.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::ext4::constants::*;
use crate::ext4::error::ReadError;
use crate::ext4::file_tree::BlockRange;
use crate::ext4::types::{ExtentHeader, ExtentIndex, ExtentLeaf, Inode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MappedExtent {
    pub logical: u32,
    pub physical: u32,
    pub length: u32,
    pub unwritten: bool,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid or overflowing ext4 extent map",
    )
}

fn leaves(ranges: &[MappedExtent]) -> io::Result<Vec<ExtentLeaf>> {
    let mut out = Vec::new();
    let mut previous_end = 0u32;
    for range in ranges {
        let end = range
            .logical
            .checked_add(range.length)
            .ok_or_else(invalid)?;
        range
            .physical
            .checked_add(range.length)
            .ok_or_else(invalid)?;
        if range.logical < previous_end || range.unwritten {
            return Err(invalid());
        }
        previous_end = end;
        let mut logical = range.logical;
        let mut physical = range.physical;
        let mut remaining = range.length;
        while remaining != 0 {
            let length = remaining.min(MAX_BLOCKS_PER_EXTENT);
            out.push(ExtentLeaf {
                block: logical,
                len: length as u16,
                start_hi: 0,
                start_lo: physical,
            });
            logical += length;
            physical += length;
            remaining -= length;
        }
    }
    Ok(out)
}

pub(crate) fn metadata_blocks(ranges: &[MappedExtent], block_size: u32) -> io::Result<u32> {
    let count = ranges.iter().try_fold(0u64, |count, range| {
        count
            .checked_add(range.length.div_ceil(MAX_BLOCKS_PER_EXTENT) as u64)
            .ok_or_else(invalid)
    })?;
    metadata_blocks_for_records(count, block_size)
}

pub(crate) fn metadata_blocks_for_records(mut count: u64, block_size: u32) -> io::Result<u32> {
    if block_size != 4096 {
        return Err(invalid());
    }
    let per_block = (block_size as u64 - 12) / 12;
    let mut blocks = 0u64;
    while count > 4 {
        count = count.div_ceil(per_block);
        blocks = blocks.checked_add(count).ok_or_else(invalid)?;
    }
    u32::try_from(blocks).map_err(|_| invalid())
}

/// Dense-file convenience: physical ranges describe consecutive logical data.
/// Sparse writes use the same tree builder with explicit logical block numbers.
pub fn write_extents<W: Write + Seek>(
    inode: &mut Inode,
    blocks: &[BlockRange],
    block_size: u32,
    writer: &mut W,
    current_block: &mut u32,
) -> io::Result<()> {
    let mut logical = 0u32;
    let mut mapped = Vec::with_capacity(blocks.len());
    for range in blocks {
        let length = range.end.checked_sub(range.start).ok_or_else(invalid)?;
        mapped.push(MappedExtent {
            logical,
            physical: range.start,
            length,
            unwritten: false,
        });
        logical = logical.checked_add(length).ok_or_else(invalid)?;
    }
    write_mapped_extents(inode, &mapped, block_size, writer, current_block)
}

/// Index blocks are placed consecutively at `current_block`. The formatter
/// reserves a run outside all superblock/GDT zones before calling this writer.
pub(crate) fn write_mapped_extents<W: Write + Seek>(
    inode: &mut Inode,
    ranges: &[MappedExtent],
    block_size: u32,
    writer: &mut W,
    current_block: &mut u32,
) -> io::Result<()> {
    if block_size != 4096 {
        return Err(invalid());
    }
    let entries = leaves(ranges)?;
    let data_blocks = ranges.iter().try_fold(0u64, |sum, range| {
        sum.checked_add(range.length as u64).ok_or_else(invalid)
    })?;
    if entries.is_empty() && inode.file_size() == 0 {
        return Ok(());
    }
    let per_block = (block_size as usize - 12) / 12;
    let initial_block = *current_block;
    let mut root = [0u8; INODE_BLOCK_SIZE];
    if entries.len() <= 4 {
        write_header(&mut root, entries.len(), 4, 0);
        for (index, entry) in entries.iter().enumerate() {
            entry.write_to(&mut root[12 + index * 12..12 + (index + 1) * 12]);
        }
    } else {
        let mut block = vec![0u8; block_size as usize];
        let mut indices = Vec::with_capacity(entries.len().div_ceil(per_block));
        for chunk in entries.chunks(per_block) {
            block.fill(0);
            write_header(&mut block, chunk.len(), per_block, 0);
            for (index, entry) in chunk.iter().enumerate() {
                entry.write_to(&mut block[12 + index * 12..12 + (index + 1) * 12]);
            }
            let physical = *current_block;
            *current_block = current_block.checked_add(1).ok_or_else(invalid)?;
            writer.seek(SeekFrom::Start(physical as u64 * block_size as u64))?;
            writer.write_all(&block)?;
            indices.push(ExtentIndex {
                block: chunk[0].block,
                leaf_lo: physical,
                leaf_hi: 0,
                unused: 0,
            });
        }
        let mut depth = 1u16;
        while indices.len() > 4 {
            let mut parents = Vec::with_capacity(indices.len().div_ceil(per_block));
            for chunk in indices.chunks(per_block) {
                block.fill(0);
                write_header(&mut block, chunk.len(), per_block, depth);
                for (index, entry) in chunk.iter().enumerate() {
                    entry.write_to(&mut block[12 + index * 12..12 + (index + 1) * 12]);
                }
                let physical = *current_block;
                *current_block = current_block.checked_add(1).ok_or_else(invalid)?;
                writer.seek(SeekFrom::Start(physical as u64 * block_size as u64))?;
                writer.write_all(&block)?;
                parents.push(ExtentIndex {
                    block: chunk[0].block,
                    leaf_lo: physical,
                    leaf_hi: 0,
                    unused: 0,
                });
            }
            indices = parents;
            depth = depth
                .checked_add(1)
                .filter(|depth| *depth <= 5)
                .ok_or_else(invalid)?;
        }
        write_header(&mut root, indices.len(), 4, depth);
        for (index, entry) in indices.iter().enumerate() {
            entry.write_to(&mut root[12 + index * 12..12 + (index + 1) * 12]);
        }
    }
    inode.block = root;
    let blocks = data_blocks + (*current_block - initial_block) as u64;
    let units = if inode.flags & inode_flags::HUGE_FILE != 0 {
        blocks
    } else {
        blocks * (block_size / 512) as u64
    };
    let previous = inode.blocks_lo as u64 | ((inode.blocks_hi as u64) << 32);
    let total = previous
        .checked_add(units)
        .filter(|total| *total < 1u64 << 48)
        .ok_or_else(invalid)?;
    inode.blocks_lo = total as u32;
    inode.blocks_hi = (total >> 32) as u16;
    inode.flags |= inode_flags::EXTENTS;
    Ok(())
}

fn write_header(bytes: &mut [u8], entries: usize, maximum: usize, depth: u16) {
    ExtentHeader {
        magic: EXTENT_HEADER_MAGIC,
        entries: entries as u16,
        max: maximum as u16,
        depth,
        generation: 0,
    }
    .write_to(&mut bytes[..12]);
}

/// Physical ownership projection, useful for directory payloads and journals.
/// File reads use `parse_mapped_extents` to preserve logical holes.
pub fn parse_extents<R: Read + Seek>(
    inode: &Inode,
    block_size: u64,
    reader: &mut R,
) -> Result<Vec<(u32, u32)>, ReadError> {
    Ok(parse_mapped_extents(inode, block_size, reader)?
        .into_iter()
        .map(|extent| (extent.physical, extent.physical + extent.length))
        .collect())
}

pub(crate) fn parse_mapped_extents<R: Read + Seek>(
    inode: &Inode,
    block_size: u64,
    reader: &mut R,
) -> Result<Vec<MappedExtent>, ReadError> {
    if inode.flags & inode_flags::EXTENTS == 0 {
        return Ok(Vec::new());
    }
    if block_size != 4096 {
        return Err(ReadError::InvalidExtents);
    }
    let header = ExtentHeader::read_from(&inode.block);
    let mut out = Vec::new();
    let logical_blocks = inode.file_size().div_ceil(block_size);
    if logical_blocks > MAX_FILE_SIZE / block_size {
        return Err(ReadError::InvalidExtents);
    }
    parse_node(
        &inode.block,
        header.depth,
        block_size,
        logical_blocks,
        reader,
        &mut out,
    )?;
    Ok(out)
}

fn parse_node<R: Read + Seek>(
    bytes: &[u8],
    depth: u16,
    block_size: u64,
    logical_blocks: u64,
    reader: &mut R,
    out: &mut Vec<MappedExtent>,
) -> Result<(), ReadError> {
    if bytes.len() < 12 || depth > 5 {
        return Err(ReadError::InvalidExtents);
    }
    let header = ExtentHeader::read_from(bytes);
    let capacity = (bytes.len() - 12) / 12;
    if header.magic != EXTENT_HEADER_MAGIC
        || header.depth != depth
        || header.max == 0
        || (depth != 0 && header.entries == 0)
        || header.entries > header.max
        || header.max as usize > capacity
        || header.entries as usize > capacity
    {
        return Err(ReadError::InvalidExtents);
    }
    let mut previous_key = None;
    for index in 0..header.entries as usize {
        let record = &bytes[12 + index * 12..12 + (index + 1) * 12];
        if depth == 0 {
            let leaf = ExtentLeaf::read_from(record);
            let length = if leaf.len > 0x8000 {
                leaf.len as u32 - 0x8000
            } else {
                leaf.len as u32
            };
            if leaf.start_hi != 0 || length == 0 || leaf.start_lo.checked_add(length).is_none() {
                return Err(ReadError::InvalidExtents);
            }
            let logical_end = leaf.block as u64 + length as u64;
            if logical_end > logical_blocks
                || out.last().is_some_and(|previous| {
                    previous.logical as u64 + previous.length as u64 > leaf.block as u64
                })
            {
                return Err(ReadError::InvalidExtents);
            }
            out.push(MappedExtent {
                logical: leaf.block,
                physical: leaf.start_lo,
                length,
                unwritten: leaf.len > 0x8000,
            });
        } else {
            let entry = ExtentIndex::read_from(record);
            if entry.leaf_hi != 0
                || entry.leaf_lo == 0
                || entry.block as u64 >= logical_blocks
                || previous_key.is_some_and(|key| key >= entry.block)
                || out.last().is_some_and(|previous| {
                    previous.logical as u64 + previous.length as u64 > entry.block as u64
                })
            {
                return Err(ReadError::InvalidExtents);
            }
            previous_key = Some(entry.block);
            let mut child = vec![0u8; block_size as usize];
            reader.seek(SeekFrom::Start(entry.leaf_lo as u64 * block_size))?;
            reader.read_exact(&mut child)?;
            let start = out.len();
            parse_node(&child, depth - 1, block_size, logical_blocks, reader, out)?;
            if out
                .get(start)
                .is_none_or(|extent| extent.logical != entry.block)
            {
                return Err(ReadError::InvalidExtents);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ext4::constants::*;
    use crate::ext4::extent::*;
    use crate::ext4::types::{ExtentHeader, Inode};
    use std::io::Cursor;

    #[test]
    fn test_inline_extents_roundtrip() {
        let mut inode = Inode::default();
        inode.set_file_size(10 * 4096);
        let mut writer = Cursor::new(Vec::new());
        let mut position = 100;
        write_extents(
            &mut inode,
            &[BlockRange { start: 50, end: 60 }],
            4096,
            &mut writer,
            &mut position,
        )
        .unwrap();
        assert!(writer.get_ref().is_empty());
        assert_eq!(
            parse_extents(&inode, 4096, &mut writer).unwrap(),
            vec![(50, 60)]
        );
    }

    #[test]
    fn test_inline_extents_non_contiguous_ranges() {
        let mut inode = Inode::default();
        inode.set_file_size(11 * 4096);
        let mut writer = Cursor::new(Vec::new());
        let mut position = 200;
        let ranges = [
            MappedExtent {
                logical: 1,
                physical: 50,
                length: 2,
                unwritten: false,
            },
            MappedExtent {
                logical: 8,
                physical: 100,
                length: 3,
                unwritten: false,
            },
        ];
        write_mapped_extents(&mut inode, &ranges, 4096, &mut writer, &mut position).unwrap();
        assert_eq!(
            parse_mapped_extents(&inode, 4096, &mut writer).unwrap(),
            ranges
        );
    }

    #[test]
    fn test_zero_blocks_is_noop() {
        let mut inode = Inode::default();
        write_extents(&mut inode, &[], 4096, &mut Cursor::new(Vec::new()), &mut 0).unwrap();
        assert_eq!(inode.flags & inode_flags::EXTENTS, 0);
    }

    #[test]
    fn test_depth1_extent_tree_roundtrip() {
        let mut inode = Inode::default();
        inode.set_file_size((MAX_BLOCKS_PER_EXTENT as u64 * 5 + 42) * 4096);
        let mut writer = tempfile::tempfile().unwrap();
        let mut position = MAX_BLOCKS_PER_EXTENT * 6;
        write_extents(
            &mut inode,
            &[BlockRange {
                start: 10,
                end: 10 + MAX_BLOCKS_PER_EXTENT * 5 + 42,
            }],
            4096,
            &mut writer,
            &mut position,
        )
        .unwrap();
        assert_eq!(ExtentHeader::read_from(&inode.block).depth, 1);
        let ranges = parse_extents(&inode, 4096, &mut writer).unwrap();
        assert_eq!(ranges.len(), 6);
        assert_eq!(ranges[5].1 - ranges[5].0, 42);
    }

    #[test]
    fn depth_two_sparse_extent_tree_roundtrips_without_panics() {
        let ranges: Vec<_> = (0..2000)
            .map(|index| MappedExtent {
                logical: index * 3,
                physical: index + 10,
                length: 1,
                unwritten: false,
            })
            .collect();
        let mut inode = Inode::default();
        inode.set_file_size(6000 * 4096);
        let mut writer = tempfile::tempfile().unwrap();
        let mut position = 3000;
        let predicted = metadata_blocks(&ranges, 4096).unwrap();
        write_mapped_extents(&mut inode, &ranges, 4096, &mut writer, &mut position).unwrap();
        assert_eq!(position - 3000, predicted);
        assert_eq!(ExtentHeader::read_from(&inode.block).depth, 2);
        assert_eq!(
            parse_mapped_extents(&inode, 4096, &mut writer).unwrap(),
            ranges
        );
        inode.block[6..8].copy_from_slice(&9u16.to_le_bytes());
        assert!(parse_mapped_extents(&inode, 4096, &mut writer).is_err());
    }
}
