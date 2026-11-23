//! Checked ext4 extent trees, including logical holes and multiple index levels.

use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::ext4::constants::*;
use crate::ext4::error::{ReadError, Structure, Unsupported};
use crate::ext4::file_tree::BlockRange;
use crate::ext4::types::{ExtentHeader, ExtentIndex, ExtentLeaf, Inode};

/// The only block size the reader implements.
const BLOCK_SIZE: usize = 4096;

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

/// Upper bound on leaf extents materialized for one inode (64 MiB of map).
/// Larger maps are refused as unsupported, never truncated.
pub const MAX_EXTENTS_PER_INODE: usize = 1 << 22;

/// Maximum extent tree depth admitted by Linux (`EXT4_MAX_EXTENT_DEPTH`).
const MAX_DEPTH: u16 = 5;

/// Validated logical-to-physical map of one extent tree.
#[derive(Debug, Default)]
pub(crate) struct ExtentMap {
    /// Leaf extents in strictly increasing, non-overlapping logical order.
    /// Extents beyond `i_size` (for example `FALLOC_FL_KEEP_SIZE`) are kept.
    pub extents: Vec<MappedExtent>,
    /// Index and leaf node blocks below the in-inode root.
    pub tree_blocks: u64,
}

impl ExtentMap {
    /// Allocated data blocks, written and unwritten.
    pub fn data_blocks(&self) -> u64 {
        self.extents.iter().map(|extent| extent.length as u64).sum()
    }
}

/// Walk and validate the extent tree rooted in `inode.block`.
///
/// Checks header magic/depth/capacity, strictly increasing keys, that each
/// index key equals its subtree's first extent, non-overlapping logical
/// order, physical ranges within `filesystem_blocks` (never block 0), and
/// that no node block is referenced twice (cycles or shared subtrees). Every
/// index entry must yield at least one extent, so visited nodes are bounded by
/// [`MAX_EXTENTS_PER_INODE`]. The caller checks the `EXTENTS` inode flag.
pub(crate) fn walk_extents(
    inode: &Inode,
    number: Option<u32>,
    filesystem_blocks: u64,
    read_block: &mut dyn FnMut(u32, &mut [u8]) -> io::Result<()>,
) -> Result<ExtentMap, ReadError> {
    let depth = ExtentHeader::read_from(&inode.block).depth;
    let mut walk = Walk {
        number,
        filesystem_blocks,
        read_block,
        map: ExtentMap::default(),
        visited: HashSet::new(),
    };
    if depth > MAX_DEPTH {
        return Err(walk.corrupt("extent tree is deeper than five levels"));
    }
    walk.node(&inode.block, depth)?;
    Ok(walk.map)
}

struct Walk<'a> {
    number: Option<u32>,
    filesystem_blocks: u64,
    read_block: &'a mut dyn FnMut(u32, &mut [u8]) -> io::Result<()>,
    map: ExtentMap,
    visited: HashSet<u32>,
}

impl Walk<'_> {
    fn corrupt(&self, reason: &'static str) -> ReadError {
        ReadError::corrupt(Structure::ExtentTree, self.number, reason)
    }

    fn previous_end(&self) -> u64 {
        self.map
            .extents
            .last()
            .map_or(0, |extent| extent.logical as u64 + extent.length as u64)
    }

    fn node(&mut self, bytes: &[u8], depth: u16) -> Result<(), ReadError> {
        let header = ExtentHeader::read_from(bytes);
        let capacity = (bytes.len() - ExtentHeader::SIZE) / ExtentLeaf::SIZE;
        if header.magic != EXTENT_HEADER_MAGIC {
            return Err(self.corrupt("bad extent header magic"));
        }
        if header.depth != depth {
            return Err(self.corrupt("extent node depth does not match its parent"));
        }
        if header.max == 0
            || header.max as usize > capacity
            || header.entries > header.max
            || (depth != 0 && header.entries == 0)
        {
            return Err(self.corrupt("invalid extent node entry count or capacity"));
        }
        let mut previous_key = None;
        for index in 0..header.entries as usize {
            let start = ExtentHeader::SIZE + index * ExtentLeaf::SIZE;
            let record = &bytes[start..start + ExtentLeaf::SIZE];
            if depth == 0 {
                self.leaf(ExtentLeaf::read_from(record))?;
                continue;
            }
            let entry = ExtentIndex::read_from(record);
            if entry.leaf_hi != 0
                || entry.leaf_lo == 0
                || entry.leaf_lo as u64 >= self.filesystem_blocks
            {
                return Err(self.corrupt("extent index points outside the filesystem"));
            }
            if previous_key.is_some_and(|key| key >= entry.block)
                || self.previous_end() > entry.block as u64
            {
                return Err(self.corrupt("extent index keys are not strictly increasing"));
            }
            previous_key = Some(entry.block);
            if !self.visited.insert(entry.leaf_lo) {
                return Err(self.corrupt("extent node block is referenced twice"));
            }
            self.map.tree_blocks += 1;
            let mut child = vec![0u8; BLOCK_SIZE];
            (self.read_block)(entry.leaf_lo, &mut child)?;
            let first = self.map.extents.len();
            self.node(&child, depth - 1)?;
            if self
                .map
                .extents
                .get(first)
                .is_none_or(|extent| extent.logical != entry.block)
            {
                return Err(self.corrupt("extent index key differs from its first extent"));
            }
        }
        Ok(())
    }

    fn leaf(&mut self, leaf: ExtentLeaf) -> Result<(), ReadError> {
        let (length, unwritten) = if leaf.len > MAX_BLOCKS_PER_EXTENT as u16 {
            (leaf.len as u32 - MAX_BLOCKS_PER_EXTENT, true)
        } else {
            (leaf.len as u32, false)
        };
        if length == 0 {
            return Err(self.corrupt("zero-length extent"));
        }
        if leaf.start_hi != 0
            || leaf.start_lo == 0
            || leaf.start_lo as u64 + length as u64 > self.filesystem_blocks
        {
            return Err(self.corrupt("extent maps blocks outside the filesystem"));
        }
        if leaf.block as u64 + length as u64 > 1 << 32 {
            return Err(self.corrupt("extent logical range overflows"));
        }
        if self.previous_end() > leaf.block as u64 {
            return Err(self.corrupt("extents overlap or are out of logical order"));
        }
        if self.map.extents.len() >= MAX_EXTENTS_PER_INODE {
            return Err(ReadError::Unsupported(Unsupported::TooManyExtents {
                inode: self.number.unwrap_or(0),
                limit: MAX_EXTENTS_PER_INODE,
            }));
        }
        self.map.extents.try_reserve(1).map_err(io::Error::other)?;
        self.map.extents.push(MappedExtent {
            logical: leaf.block,
            physical: leaf.start_lo,
            length,
            unwritten,
        });
        Ok(())
    }
}

/// Physical ownership projection of an extent-mapped inode, for directory
/// payloads and journals. Logical holes and unwritten state are dropped. An
/// inode without the `EXTENTS` flag is accepted only when its block map is
/// entirely empty; a populated indirect map is never reported as empty.
pub fn parse_extents<R: Read + Seek>(
    inode: &Inode,
    block_size: u64,
    reader: &mut R,
) -> Result<Vec<(u32, u32)>, ReadError> {
    if block_size != BLOCK_SIZE as u64 {
        return Err(ReadError::Unsupported(Unsupported::BlockSize(
            block_size.trailing_zeros().saturating_sub(10),
        )));
    }
    if inode.flags & inode_flags::EXTENTS == 0 {
        if inode.block.iter().all(|byte| *byte == 0) {
            return Ok(Vec::new());
        }
        return Err(ReadError::corrupt(
            Structure::ExtentTree,
            None,
            "populated block map without the EXTENTS flag",
        ));
    }
    let map = walk_extents(inode, None, 1 << 32, &mut |block, buffer| {
        reader.seek(SeekFrom::Start(block as u64 * BLOCK_SIZE as u64))?;
        reader.read_exact(buffer)
    })?;
    Ok(map
        .extents
        .into_iter()
        .map(|extent| (extent.physical, extent.physical + extent.length))
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::ext4::constants::*;
    use crate::ext4::error::{Corruption, ReadError, Structure, Unsupported};
    use crate::ext4::extent::*;
    use crate::ext4::types::{ExtentHeader, ExtentIndex, ExtentLeaf, Inode};
    use std::io::Cursor;

    fn walk<R: Read + Seek>(inode: &Inode, image: &mut R) -> Result<ExtentMap, ReadError> {
        walk_extents(inode, Some(42), 1 << 20, &mut |block, buffer| {
            image.seek(SeekFrom::Start(block as u64 * 4096))?;
            image.read_exact(buffer)
        })
    }

    fn leaf(logical: u32, raw_len: u16, physical: u32) -> [u8; 12] {
        let mut bytes = [0; 12];
        ExtentLeaf {
            block: logical,
            len: raw_len,
            start_hi: 0,
            start_lo: physical,
        }
        .write_to(&mut bytes);
        bytes
    }

    fn index(logical: u32, child: u32) -> [u8; 12] {
        let mut bytes = [0; 12];
        ExtentIndex {
            block: logical,
            leaf_lo: child,
            leaf_hi: 0,
            unused: 0,
        }
        .write_to(&mut bytes);
        bytes
    }

    fn node(size: usize, depth: u16, max: u16, records: &[[u8; 12]]) -> Vec<u8> {
        let mut bytes = vec![0; size];
        ExtentHeader {
            magic: EXTENT_HEADER_MAGIC,
            entries: records.len() as u16,
            max,
            depth,
            generation: 0,
        }
        .write_to(&mut bytes);
        for (slot, record) in records.iter().enumerate() {
            bytes[12 + slot * 12..24 + slot * 12].copy_from_slice(record);
        }
        bytes
    }

    fn root(depth: u16, records: &[[u8; 12]]) -> Inode {
        let mut inode = Inode {
            flags: inode_flags::EXTENTS,
            ..Inode::default()
        };
        inode
            .block
            .copy_from_slice(&node(INODE_BLOCK_SIZE, depth, 4, records));
        inode
    }

    fn image(blocks: &[(u32, Vec<u8>)]) -> Cursor<Vec<u8>> {
        let mut bytes = vec![0; 64 * 4096];
        for (block, content) in blocks {
            let start = *block as usize * 4096;
            bytes[start..start + content.len()].copy_from_slice(content);
        }
        Cursor::new(bytes)
    }

    fn reason(result: Result<ExtentMap, ReadError>) -> &'static str {
        match result {
            Err(ReadError::Corrupt(Corruption {
                structure: Structure::ExtentTree,
                inode: Some(42),
                reason,
            })) => reason,
            other => panic!("expected extent corruption, got {other:?}"),
        }
    }

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
        let map = walk(&inode, &mut writer).unwrap();
        assert_eq!(map.extents, ranges);
        assert_eq!((map.tree_blocks, map.data_blocks()), (0, 5));
    }

    #[test]
    fn test_zero_blocks_is_noop() {
        let mut inode = Inode::default();
        write_extents(&mut inode, &[], 4096, &mut Cursor::new(Vec::new()), &mut 0).unwrap();
        assert_eq!(inode.flags & inode_flags::EXTENTS, 0);
        assert!(
            parse_extents(&inode, 4096, &mut Cursor::new(Vec::new()))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn populated_block_map_is_never_reported_empty() {
        let mut inode = Inode::default();
        inode.block[0..4].copy_from_slice(&1234u32.to_le_bytes());
        assert!(matches!(
            parse_extents(&inode, 4096, &mut Cursor::new(Vec::new())),
            Err(ReadError::Corrupt(_))
        ));
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
        let map = walk(&inode, &mut writer).unwrap();
        assert_eq!(map.extents, ranges);
        assert_eq!(map.tree_blocks, predicted as u64);
        inode.block[6..8].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(
            reason(walk(&inode, &mut writer)),
            "extent tree is deeper than five levels"
        );
    }

    #[test]
    fn unwritten_full_length_and_beyond_eof_extents_are_exact() {
        let mut inode = root(
            0,
            &[
                leaf(0, 0x8000, 100),
                leaf(0x8000, 0x8000 + 3, 40_000),
                leaf(1 << 20, 1, 50_000),
            ],
        );
        inode.set_file_size(4096);
        let map = walk(&inode, &mut image(&[])).unwrap();
        assert_eq!(
            map.extents,
            [
                MappedExtent {
                    logical: 0,
                    physical: 100,
                    length: 0x8000,
                    unwritten: false,
                },
                MappedExtent {
                    logical: 0x8000,
                    physical: 40_000,
                    length: 3,
                    unwritten: true,
                },
                MappedExtent {
                    logical: 1 << 20,
                    physical: 50_000,
                    length: 1,
                    unwritten: false,
                },
            ]
        );
        assert_eq!(map.data_blocks(), 0x8000 + 4);
    }

    #[test]
    fn malformed_leaves_are_typed_corruption() {
        for (records, expected) in [
            (vec![leaf(0, 0, 10)], "zero-length extent"),
            (
                vec![leaf(0, 0x8000, 0)],
                "extent maps blocks outside the filesystem",
            ),
            (
                vec![leaf(0, 2, (1 << 20) - 1)],
                "extent maps blocks outside the filesystem",
            ),
            (
                vec![leaf(u32::MAX, 2, 10)],
                "extent logical range overflows",
            ),
            (
                vec![leaf(4, 2, 10), leaf(5, 1, 20)],
                "extents overlap or are out of logical order",
            ),
            (
                vec![leaf(4, 2, 10), leaf(1, 1, 20)],
                "extents overlap or are out of logical order",
            ),
        ] {
            assert_eq!(reason(walk(&root(0, &records), &mut image(&[]))), expected);
        }
        let mut bad_magic = root(0, &[leaf(0, 1, 10)]);
        bad_magic.block[0] ^= 1;
        assert_eq!(
            reason(walk(&bad_magic, &mut image(&[]))),
            "bad extent header magic"
        );
        let mut overfull = root(0, &[leaf(0, 1, 10)]);
        overfull.block[2..4].copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(
            reason(walk(&overfull, &mut image(&[]))),
            "invalid extent node entry count or capacity"
        );
        let mut oversized = root(0, &[leaf(0, 1, 10)]);
        oversized.block[4..6].copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(
            reason(walk(&oversized, &mut image(&[]))),
            "invalid extent node entry count or capacity"
        );
    }

    #[test]
    fn malformed_index_trees_are_typed_corruption() {
        let child = |records: &[[u8; 12]]| node(4096, 0, 340, records);
        // Two index entries sharing one subtree: a DAG/cycle, never re-walked.
        let shared = root(1, &[index(0, 5), index(10, 5)]);
        assert_eq!(
            reason(walk(&shared, &mut image(&[(5, child(&[leaf(0, 1, 30)]))]))),
            "extent node block is referenced twice"
        );
        let key_mismatch = root(1, &[index(0, 5)]);
        assert_eq!(
            reason(walk(
                &key_mismatch,
                &mut image(&[(5, child(&[leaf(3, 1, 30)]))])
            )),
            "extent index key differs from its first extent"
        );
        let empty_child = root(1, &[index(0, 5)]);
        assert_eq!(
            reason(walk(&empty_child, &mut image(&[(5, child(&[]))]))),
            "extent index key differs from its first extent"
        );
        let unordered = root(1, &[index(8, 5), index(2, 6)]);
        assert_eq!(
            reason(walk(
                &unordered,
                &mut image(&[(5, child(&[leaf(8, 1, 30)])), (6, child(&[leaf(2, 1, 31)]))])
            )),
            "extent index keys are not strictly increasing"
        );
        let overlapping = root(1, &[index(0, 5), index(2, 6)]);
        assert_eq!(
            reason(walk(
                &overlapping,
                &mut image(&[(5, child(&[leaf(0, 4, 30)])), (6, child(&[leaf(2, 1, 31)]))])
            )),
            "extent index keys are not strictly increasing"
        );
        let wrong_depth = root(1, &[index(0, 5)]);
        assert_eq!(
            reason(walk(
                &wrong_depth,
                &mut image(&[(5, node(4096, 1, 340, &[index(0, 6)]))])
            )),
            "extent node depth does not match its parent"
        );
        let outside = root(1, &[index(0, 1 << 20)]);
        assert_eq!(
            reason(walk(&outside, &mut image(&[]))),
            "extent index points outside the filesystem"
        );
        let null = root(1, &[index(0, 0)]);
        assert_eq!(
            reason(walk(&null, &mut image(&[]))),
            "extent index points outside the filesystem"
        );
        let valid = root(1, &[index(0, 5), index(9, 6)]);
        let map = walk(
            &valid,
            &mut image(&[
                (5, child(&[leaf(0, 2, 30), leaf(4, 1, 33)])),
                (6, child(&[leaf(9, 3, 40)])),
            ]),
        )
        .unwrap();
        assert_eq!(map.extents.len(), 3);
        assert_eq!((map.tree_blocks, map.data_blocks()), (2, 6));
    }

    #[test]
    fn extent_cap_is_an_unsupported_bound() {
        assert!(matches!(
            ReadError::Unsupported(Unsupported::TooManyExtents {
                inode: 1,
                limit: MAX_EXTENTS_PER_INODE
            }),
            ReadError::Unsupported(_)
        ));
        assert_eq!(MAX_EXTENTS_PER_INODE, 4_194_304);
    }
}
