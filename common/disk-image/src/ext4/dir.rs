// Directory entry writing (Formatter) and parsing (Reader).
//
// On-disk directory entries are variable-length records packed into blocks.
// Each entry has an 8-byte header (DirectoryEntry) followed by the name bytes
// and padding to a 4-byte boundary.

use crate::ext4::constants::*;
use crate::ext4::types::*;
use std::io::{self, Write};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Round `n` up to the next multiple of `align`.
#[inline]
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Determine the directory-entry file type from an inode mode.
fn dir_file_type(mode: u16) -> u8 {
    FileType::from_mode(mode) as u8
}

// ---------------------------------------------------------------------------
// Write path (Formatter)
// ---------------------------------------------------------------------------

/// Write a single directory entry.
///
/// `left` tracks the number of remaining bytes in the current directory block.
/// If there is not enough room for both this entry and a trailing terminator
/// (12 bytes minimum), the current block is finished first with a zero-inode
/// terminator before writing this entry at the start of a new block.
///
/// When `link_inode` is `Some`, the entry's inode number is taken from
/// `link_inode` and the file type is derived from `link_mode` (the target
/// inode's mode).  Otherwise, `inode` and `mode` are used directly.
#[allow(clippy::too_many_arguments)]
pub fn write_dir_entry<W: Write>(
    writer: &mut W,
    name: impl AsRef<[u8]>,
    inode: u32,
    mode: u16,
    link_inode: Option<u32>,
    link_mode: Option<u16>,
    block_size: u32,
    left: &mut i32,
) -> io::Result<()> {
    let name_bytes = name.as_ref();
    if name_bytes.is_empty()
        || name_bytes.len() > EXT4_NAME_LEN
        || name_bytes.contains(&0)
        || name_bytes.contains(&b'/')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ext4 directory name",
        ));
    }
    let entry_size = align_up(DirectoryEntry::SIZE + name_bytes.len(), 4);

    // Minimum trailing entry is 12 bytes (header 8 + 4 for alignment).
    let min_trailing = 12;

    // If the current block does not have room for this entry plus a trailing
    // terminator, finish the block first.
    if (*left as usize) < entry_size + min_trailing {
        finish_dir_entry_block(writer, left, block_size)?;
    }

    // Resolve inode number and file type for hard links.
    let actual_inode = link_inode.unwrap_or(inode);
    let actual_mode = link_mode.unwrap_or(mode);

    let entry = DirectoryEntry {
        inode: actual_inode,
        rec_len: entry_size as u16,
        name_len: name_bytes.len() as u8,
        file_type: dir_file_type(actual_mode),
    };

    let mut header_buf = [0u8; DirectoryEntry::SIZE];
    entry.write_to(&mut header_buf);
    writer.write_all(&header_buf)?;

    // Write name bytes.
    writer.write_all(name_bytes)?;

    // Write padding zeros to align to 4 bytes.
    let padding = entry_size - DirectoryEntry::SIZE - name_bytes.len();
    if padding > 0 {
        let zeros = [0u8; 4];
        writer.write_all(&zeros[..padding])?;
    }

    *left -= entry_size as i32;

    Ok(())
}

/// Finish the current directory entry block by writing a zero-inode terminator
/// entry that consumes all remaining space.
///
/// If `left` is already <= 0 (block boundary was exactly reached), reset
/// `left` to `block_size` and return without writing.
pub fn finish_dir_entry_block<W: Write>(
    writer: &mut W,
    left: &mut i32,
    block_size: u32,
) -> io::Result<()> {
    if *left <= 0 {
        *left = block_size as i32;
        return Ok(());
    }

    let remaining = *left as usize;

    // Write a terminator entry: inode=0, rec_len=remaining, name_len=0, file_type=0.
    let term = DirectoryEntry {
        inode: 0,
        rec_len: remaining as u16,
        name_len: 0,
        file_type: 0,
    };

    let mut header_buf = [0u8; DirectoryEntry::SIZE];
    term.write_to(&mut header_buf);
    writer.write_all(&header_buf)?;

    // Fill remaining bytes with zeros.
    let fill = remaining - DirectoryEntry::SIZE;
    if fill > 0 {
        let zeros = vec![0u8; fill];
        writer.write_all(&zeros)?;
    }

    *left = block_size as i32;

    Ok(())
}

// ---------------------------------------------------------------------------
// Read path (Reader)
// ---------------------------------------------------------------------------

/// The only directory block size the reader implements.
pub(crate) const DIR_BLOCK_SIZE: usize = 4096;

/// One live (`inode != 0`) entry of a directory block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawEntry<'a> {
    pub offset: usize,
    pub rec_len: usize,
    pub inode: u32,
    pub file_type: u8,
    pub name: &'a [u8],
}

/// Minimal record length of an entry with `name_len` name bytes.
fn record_length(name_len: usize) -> usize {
    align_up(DirectoryEntry::SIZE + name_len, 4)
}

/// Parse one directory block with Linux `__ext4_check_dir_entry` rules.
///
/// Records must tile the block exactly: `rec_len` at least 12, 4-aligned,
/// large enough for the name, inside the block and never leaving a tail too
/// short for another record. Live names are nonempty without `/` or NUL and
/// reference inodes within `inodes_count`. Deleted records (`inode == 0`),
/// including Linux's whole-block htree node headers, yield no entries.
pub(crate) fn parse_dir_block(
    block: &[u8],
    inodes_count: u32,
) -> Result<Vec<RawEntry<'_>>, &'static str> {
    if block.len() != DIR_BLOCK_SIZE {
        return Err("directory block has the wrong size");
    }
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < block.len() {
        if offset + DirectoryEntry::SIZE > block.len() {
            return Err("directory record header crosses the block end");
        }
        let entry = DirectoryEntry::read_from(&block[offset..]);
        let rec_len = entry.rec_len as usize;
        let next = offset + rec_len;
        if rec_len < record_length(1)
            || rec_len % 4 != 0
            || rec_len < record_length(entry.name_len as usize)
        {
            return Err("directory record length is invalid");
        }
        if next > block.len() || (next != block.len() && next > block.len() - record_length(1)) {
            return Err("directory record overruns the block");
        }
        if entry.inode > inodes_count {
            return Err("directory entry inode is out of range");
        }
        if entry.inode != 0 {
            let start = offset + DirectoryEntry::SIZE;
            let name = &block[start..start + entry.name_len as usize];
            if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
                return Err("directory entry name is invalid");
            }
            entries.push(RawEntry {
                offset,
                rec_len,
                inode: entry.inode,
                file_type: entry.file_type,
                name,
            });
        }
        offset = next;
    }
    Ok(entries)
}

/// One htree index record: `hash` is the lower bound key of `block`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DxEntry {
    pub hash: u32,
    pub block: u32,
}

/// Parsed `dx_root` header from logical block 0 of an indexed directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DxRoot {
    pub hash_version: u8,
    pub indirect_levels: u8,
    pub entries: Vec<DxEntry>,
}

const DX_ROOT_INFO: usize = 24;
const DX_ROOT_ENTRIES: usize = 32;
const DX_NODE_ENTRIES: usize = 8;
const DX_ENTRY_SIZE: usize = 8;
/// Upper four bits of an index block number are reserved (`EXT4_DX_BLOCK_MASK`).
const DX_BLOCK_MASK: u32 = 0x0fff_ffff;

/// Parse the `dx_root` of block 0. The caller has already validated block 0
/// as an ordinary directory block whose live entries are `.` and `..`.
pub(crate) fn parse_dx_root(block: &[u8]) -> Result<DxRoot, &'static str> {
    let dot = DirectoryEntry::read_from(&block[0..]);
    let dotdot = DirectoryEntry::read_from(&block[12..]);
    if dot.rec_len != 12 || dotdot.rec_len as usize != DIR_BLOCK_SIZE - 12 {
        return Err("htree root does not have the dx_root dot records");
    }
    let info = &block[DX_ROOT_INFO..DX_ROOT_ENTRIES];
    if info[..4] != [0; 4] || info[5] != 8 {
        return Err("htree root info is invalid");
    }
    Ok(DxRoot {
        hash_version: info[4],
        indirect_levels: info[6],
        entries: parse_dx_entries(block, DX_ROOT_ENTRIES)?,
    })
}

/// Parse an interior htree node: one empty record spanning the block followed
/// by a count/limit header and index entries.
pub(crate) fn parse_dx_node(block: &[u8]) -> Result<Vec<DxEntry>, &'static str> {
    let fake = DirectoryEntry::read_from(block);
    if fake.inode != 0 || fake.rec_len as usize != DIR_BLOCK_SIZE || fake.name_len != 0 {
        return Err("htree interior node does not start with an empty record");
    }
    parse_dx_entries(block, DX_NODE_ENTRIES)
}

fn parse_dx_entries(block: &[u8], base: usize) -> Result<Vec<DxEntry>, &'static str> {
    let word = |offset: usize| {
        u32::from_le_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ])
    };
    let limit = u16::from_le_bytes([block[base], block[base + 1]]) as usize;
    let count = u16::from_le_bytes([block[base + 2], block[base + 3]]) as usize;
    if limit != (DIR_BLOCK_SIZE - base) / DX_ENTRY_SIZE || count == 0 || count > limit {
        return Err("htree count or limit is invalid");
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = base + index * DX_ENTRY_SIZE;
        let block = word(offset + 4);
        if block & !DX_BLOCK_MASK != 0 {
            return Err("htree block pointer uses reserved bits");
        }
        entries.push(DxEntry {
            hash: if index == 0 { 0 } else { word(offset) },
            block,
        });
    }
    Ok(entries)
}

/// Directory hash algorithm of an indexed directory, with the filesystem's
/// char signedness applied (`hash_version + 3` when unsigned).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashVersion {
    Legacy,
    HalfMd4,
    Tea,
    LegacyUnsigned,
    HalfMd4Unsigned,
    TeaUnsigned,
}

impl HashVersion {
    /// Map a `dx_root` hash version and the superblock signedness. SipHash
    /// (casefold/encryption) and unknown versions are unsupported.
    pub fn from_root(version: u8, unsigned: bool) -> Option<Self> {
        Some(match (version, unsigned) {
            (0, false) => Self::Legacy,
            (1, false) => Self::HalfMd4,
            (2, false) => Self::Tea,
            (0, true) => Self::LegacyUnsigned,
            (1, true) => Self::HalfMd4Unsigned,
            (2, true) => Self::TeaUnsigned,
            _ => return None,
        })
    }

    fn unsigned(self) -> bool {
        matches!(
            self,
            Self::LegacyUnsigned | Self::HalfMd4Unsigned | Self::TeaUnsigned
        )
    }
}

const DEFAULT_SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// Linux `ext4fs_dirhash`: returns `(hash, minor_hash)`. The major hash has its
/// low (collision) bit cleared and never equals the 32-bit EOF marker.
pub fn dx_hash(version: HashVersion, seed: [u32; 4], name: &[u8]) -> (u32, u32) {
    let mut buf = if seed == [0; 4] { DEFAULT_SEED } else { seed };
    let unsigned = version.unsigned();
    let (hash, minor) = match version {
        HashVersion::Legacy | HashVersion::LegacyUnsigned => (legacy_hash(name, unsigned), 0),
        HashVersion::HalfMd4 | HashVersion::HalfMd4Unsigned => {
            let mut input = [0u32; 8];
            for start in (0..name.len()).step_by(32) {
                fill_hash_words(&name[start..], unsigned, &mut input);
                half_md4_transform(&mut buf, &input);
            }
            (buf[1], buf[2])
        }
        HashVersion::Tea | HashVersion::TeaUnsigned => {
            let mut input = [0u32; 4];
            for start in (0..name.len()).step_by(16) {
                fill_hash_words(&name[start..], unsigned, &mut input);
                tea_transform(&mut buf, &input);
            }
            (buf[0], buf[1])
        }
    };
    let mut hash = hash & !1;
    if hash == 0x7fff_ffff << 1 {
        hash = (0x7fff_ffff - 1) << 1;
    }
    (hash, minor)
}

fn hash_char(byte: u8, unsigned: bool) -> u32 {
    if unsigned {
        byte as u32
    } else {
        byte as i8 as i32 as u32
    }
}

/// Linux `str2hashbuf_{signed,unsigned}` over at most `out.len() * 4` bytes of
/// `rest`; every round pads with the remaining name length, not the chunk's.
fn fill_hash_words(rest: &[u8], unsigned: bool, out: &mut [u32]) {
    let length = rest.len() as u32;
    let mut pad = length | (length << 8);
    pad |= pad << 16;
    let mut value = pad;
    let mut word = 0;
    for (index, byte) in rest.iter().take(out.len() * 4).enumerate() {
        value = hash_char(*byte, unsigned).wrapping_add(value << 8);
        if index % 4 == 3 {
            out[word] = value;
            word += 1;
            value = pad;
        }
    }
    if word < out.len() {
        out[word] = value;
        word += 1;
    }
    for slot in out.iter_mut().skip(word) {
        *slot = pad;
    }
}

fn legacy_hash(name: &[u8], unsigned: bool) -> u32 {
    let (mut hash0, mut hash1) = (0x12a3_fe2du32, 0x37ab_e8f9u32);
    for byte in name {
        let mixed = (hash_char(*byte, unsigned) as i32).wrapping_mul(7_152_373) as u32;
        let mut hash = hash1.wrapping_add(hash0 ^ mixed);
        if hash & 0x8000_0000 != 0 {
            hash = hash.wrapping_sub(0x7fff_ffff);
        }
        hash1 = hash0;
        hash0 = hash;
    }
    hash0 << 1
}

fn tea_transform(buf: &mut [u32; 4], input: &[u32; 4]) {
    const DELTA: u32 = 0x9e37_79b9;
    let (mut b0, mut b1) = (buf[0], buf[1]);
    let (a, b, c, d) = (input[0], input[1], input[2], input[3]);
    let mut sum = 0u32;
    for _ in 0..16 {
        sum = sum.wrapping_add(DELTA);
        b0 = b0.wrapping_add(
            (b1 << 4).wrapping_add(a) ^ b1.wrapping_add(sum) ^ (b1 >> 5).wrapping_add(b),
        );
        b1 = b1.wrapping_add(
            (b0 << 4).wrapping_add(c) ^ b0.wrapping_add(sum) ^ (b0 >> 5).wrapping_add(d),
        );
    }
    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

fn half_md4_transform(buf: &mut [u32; 4], input: &[u32; 8]) {
    const K2: u32 = 0o13240474631;
    const K3: u32 = 0o15666365641;
    let f = |x: u32, y: u32, z: u32| z ^ (x & (y ^ z));
    let g = |x: u32, y: u32, z: u32| (x & y).wrapping_add((x ^ y) & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    let round = |function: &dyn Fn(u32, u32, u32) -> u32,
                 a: u32,
                 b: u32,
                 c: u32,
                 d: u32,
                 x: u32,
                 shift: u32| {
        a.wrapping_add(function(b, c, d))
            .wrapping_add(x)
            .rotate_left(shift)
    };
    let (mut a, mut b, mut c, mut d) = (buf[0], buf[1], buf[2], buf[3]);
    for (index, shift) in [
        (0, 3),
        (1, 7),
        (2, 11),
        (3, 19),
        (4, 3),
        (5, 7),
        (6, 11),
        (7, 19),
    ] {
        match index % 4 {
            0 => a = round(&f, a, b, c, d, input[index], shift),
            1 => d = round(&f, d, a, b, c, input[index], shift),
            2 => c = round(&f, c, d, a, b, input[index], shift),
            _ => b = round(&f, b, c, d, a, input[index], shift),
        }
    }
    for (slot, (index, shift)) in [
        (1, 3),
        (3, 5),
        (5, 9),
        (7, 13),
        (0, 3),
        (2, 5),
        (4, 9),
        (6, 13),
    ]
    .into_iter()
    .enumerate()
    {
        let x = input[index].wrapping_add(K2);
        match slot % 4 {
            0 => a = round(&g, a, b, c, d, x, shift),
            1 => d = round(&g, d, a, b, c, x, shift),
            2 => c = round(&g, c, d, a, b, x, shift),
            _ => b = round(&g, b, c, d, a, x, shift),
        }
    }
    for (slot, (index, shift)) in [
        (3, 3),
        (7, 9),
        (2, 11),
        (6, 15),
        (1, 3),
        (5, 9),
        (0, 11),
        (4, 15),
    ]
    .into_iter()
    .enumerate()
    {
        let x = input[index].wrapping_add(K3);
        match slot % 4 {
            0 => a = round(&h, a, b, c, d, x, shift),
            1 => d = round(&h, d, a, b, c, x, shift),
            2 => c = round(&h, c, d, a, b, x, shift),
            _ => b = round(&h, b, c, d, a, x, shift),
        }
    }
    buf[0] = buf[0].wrapping_add(a);
    buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c);
    buf[3] = buf[3].wrapping_add(d);
}

#[cfg(test)]
mod tests {
    use crate::ext4::constants::file_mode;
    use crate::ext4::dir::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4), 0);
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(4, 4), 4);
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(8, 4), 8);
        assert_eq!(align_up(9, 4), 12);
    }

    #[test]
    fn test_write_and_parse_dir_entries() {
        let block_size = 4096u32;
        let mut buf = Vec::new();
        let mut left = block_size as i32;

        // Write "." entry.
        write_dir_entry(
            &mut buf,
            ".",
            2,
            file_mode::S_IFDIR | 0o755,
            None,
            None,
            block_size,
            &mut left,
        )
        .unwrap();

        // Write ".." entry.
        write_dir_entry(
            &mut buf,
            "..",
            2,
            file_mode::S_IFDIR | 0o755,
            None,
            None,
            block_size,
            &mut left,
        )
        .unwrap();

        // Write a regular file entry.
        write_dir_entry(
            &mut buf,
            "hello.txt",
            11,
            file_mode::S_IFREG | 0o644,
            None,
            None,
            block_size,
            &mut left,
        )
        .unwrap();

        // Finish the block.
        finish_dir_entry_block(&mut buf, &mut left, block_size).unwrap();

        assert_eq!(buf.len(), block_size as usize);
        assert_eq!(left, block_size as i32);

        // Parse back.
        let entries: Vec<_> = parse_dir_block(&buf, 100)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name.to_vec(), entry.inode, entry.file_type))
            .collect();
        assert_eq!(
            entries,
            [
                (b".".to_vec(), 2, 2),
                (b"..".to_vec(), 2, 2),
                (b"hello.txt".to_vec(), 11, 1)
            ]
        );
    }

    #[test]
    fn test_finish_dir_entry_block_at_boundary() {
        let block_size = 4096u32;
        let mut buf = Vec::new();
        let mut left = 0i32;

        // Already at a block boundary -- should just reset `left`.
        finish_dir_entry_block(&mut buf, &mut left, block_size).unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(left, block_size as i32);
    }

    #[test]
    fn test_hard_link_entry() {
        let block_size = 4096u32;
        let mut buf = Vec::new();
        let mut left = block_size as i32;

        // Write a hard link entry: display name "link.txt", but pointing to inode 42
        // which is a regular file.
        write_dir_entry(
            &mut buf,
            "link.txt",
            99,
            file_mode::S_IFREG | 0o644,
            Some(42),
            Some(file_mode::S_IFREG | 0o644),
            block_size,
            &mut left,
        )
        .unwrap();

        finish_dir_entry_block(&mut buf, &mut left, block_size).unwrap();

        let entries = parse_dir_block(&buf, 100).unwrap();
        assert_eq!(entries.len(), 1);
        // The inode number should be the link target (42), not the original (99).
        assert_eq!(
            (entries[0].name, entries[0].inode),
            (b"link.txt".as_slice(), 42)
        );
    }

    fn record(block: &mut [u8], offset: usize, inode: u32, rec_len: u16, name: &[u8]) {
        DirectoryEntry {
            inode,
            rec_len,
            name_len: name.len() as u8,
            file_type: 1,
        }
        .write_to(&mut block[offset..]);
        block[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
    }

    #[test]
    fn malformed_directory_blocks_are_rejected_not_truncated() {
        assert_eq!(
            parse_dir_block(&[0u8; 4096], 100),
            Err("directory record length is invalid")
        );
        assert_eq!(
            parse_dir_block(&[0u8; 1024], 100),
            Err("directory block has the wrong size")
        );
        for (inode, rec_len, name, expected) in [
            (
                11,
                4094,
                b"a".as_slice(),
                "directory record length is invalid",
            ),
            (
                11,
                12,
                b"long-name".as_slice(),
                "directory record length is invalid",
            ),
            (11, 8, b"".as_slice(), "directory record length is invalid"),
            (
                11,
                4100,
                b"a".as_slice(),
                "directory record overruns the block",
            ),
            (
                11,
                4088,
                b"a".as_slice(),
                "directory record overruns the block",
            ),
            (
                101,
                4096,
                b"a".as_slice(),
                "directory entry inode is out of range",
            ),
            (
                11,
                4096,
                b"a/b".as_slice(),
                "directory entry name is invalid",
            ),
            (
                11,
                4096,
                b"a\0".as_slice(),
                "directory entry name is invalid",
            ),
            (11, 4096, b"".as_slice(), "directory entry name is invalid"),
        ] {
            let mut block = vec![0u8; 4096];
            record(&mut block, 0, inode, rec_len, name);
            assert_eq!(parse_dir_block(&block, 100), Err(expected), "{name:?}");
        }
        // A deleted leading record and an htree node header contribute nothing.
        let mut deleted = vec![0u8; 4096];
        record(&mut deleted, 0, 0, 24, b"gone");
        record(&mut deleted, 24, 12, 4072, b"kept");
        let entries = parse_dir_block(&deleted, 100).unwrap();
        assert_eq!((entries.len(), entries[0].name), (1, b"kept".as_slice()));
        let mut node = vec![0u8; 4096];
        record(&mut node, 0, 0, 4096, b"");
        assert!(parse_dir_block(&node, 100).unwrap().is_empty());
    }

    fn dx_root_block(limit: u16, entries: &[(u32, u32)]) -> Vec<u8> {
        let mut block = vec![0u8; 4096];
        record(&mut block, 0, 2, 12, b".");
        record(&mut block, 12, 2, 4084, b"..");
        block[28] = 1;
        block[29] = 8;
        block[32..34].copy_from_slice(&limit.to_le_bytes());
        block[34..36].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        for (index, (hash, child)) in entries.iter().enumerate() {
            let offset = 32 + index * 8;
            if index != 0 {
                block[offset..offset + 4].copy_from_slice(&hash.to_le_bytes());
            }
            block[offset + 4..offset + 8].copy_from_slice(&child.to_le_bytes());
        }
        block
    }

    #[test]
    fn dx_root_and_node_headers_are_strict() {
        let root = dx_root_block(508, &[(0, 1), (0x1000, 2)]);
        assert_eq!(parse_dir_block(&root, 100).unwrap().len(), 2);
        assert_eq!(
            parse_dx_root(&root).unwrap(),
            DxRoot {
                hash_version: 1,
                indirect_levels: 0,
                entries: vec![
                    DxEntry { hash: 0, block: 1 },
                    DxEntry {
                        hash: 0x1000,
                        block: 2
                    }
                ],
            }
        );
        assert_eq!(
            parse_dx_root(&dx_root_block(507, &[(0, 1)])),
            Err("htree count or limit is invalid")
        );
        assert_eq!(
            parse_dx_root(&dx_root_block(508, &[])),
            Err("htree count or limit is invalid")
        );
        assert_eq!(
            parse_dx_root(&dx_root_block(508, &[(0, 0x1000_0001)])),
            Err("htree block pointer uses reserved bits")
        );
        let mut reserved = dx_root_block(508, &[(0, 1)]);
        reserved[24] = 1;
        assert_eq!(parse_dx_root(&reserved), Err("htree root info is invalid"));
        let mut info_length = dx_root_block(508, &[(0, 1)]);
        info_length[29] = 16;
        assert_eq!(
            parse_dx_root(&info_length),
            Err("htree root info is invalid")
        );

        let mut node = vec![0u8; 4096];
        record(&mut node, 0, 0, 4096, b"");
        node[8..10].copy_from_slice(&511u16.to_le_bytes());
        node[10..12].copy_from_slice(&1u16.to_le_bytes());
        node[12..16].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            parse_dx_node(&node).unwrap(),
            vec![DxEntry { hash: 0, block: 7 }]
        );
        node[0] = 9;
        assert_eq!(
            parse_dx_node(&node),
            Err("htree interior node does not start with an empty record")
        );
    }

    /// Oracle: e2fsprogs 1.47.4 `ext2fs_dirhash`, with the exact raw bytes and
    /// lengths below, not names passed through lossy UTF-8 command transport.
    #[test]
    fn dx_hash_matches_libext2fs_vectors() {
        let long = b"\x80\x81\xfe\xff\xc3\xa9\xe2\x82\xac0123456789abcdefghijklmnopqrstuvwxyz";
        let names: [&[u8]; 3] = [b"abc", b"caf\xe9-\xff", long];
        let zero = [0u32; 4];
        let seeded = [0x3322_1100, 0x7766_5544, 0xbbaa_9988, 0xffee_ddcc];
        type HashVector = (HashVersion, [u32; 4], [(u32, u32); 3]);
        let vectors: [HashVector; 12] = [
            (
                HashVersion::Legacy,
                zero,
                [(0x75afd992, 0), (0xc0d75b08, 0), (0x65d042f6, 0)],
            ),
            (
                HashVersion::Legacy,
                seeded,
                [(0x75afd992, 0), (0xc0d75b08, 0), (0x65d042f6, 0)],
            ),
            (
                HashVersion::HalfMd4,
                zero,
                [
                    (0xd196a868, 0xc420eb28),
                    (0x24dafcbc, 0x86a9e77c),
                    (0xead67058, 0xfa2273be),
                ],
            ),
            (
                HashVersion::HalfMd4,
                seeded,
                [
                    (0xb1cd624a, 0x9519aec5),
                    (0xf14455b0, 0x8fed0964),
                    (0xd8f09c20, 0x779bc777),
                ],
            ),
            (
                HashVersion::Tea,
                zero,
                [
                    (0xb1435ec4, 0x3f7eaa0e),
                    (0xc6a50b34, 0x6bbab1cc),
                    (0x528f3a74, 0x793c12cb),
                ],
            ),
            (
                HashVersion::Tea,
                seeded,
                [
                    (0x2440311a, 0xc62c3fe6),
                    (0x7b42dd20, 0x58089f9e),
                    (0x591c275c, 0xafae1beb),
                ],
            ),
            (
                HashVersion::LegacyUnsigned,
                zero,
                [(0x75afd992, 0), (0xe149dcf2, 0), (0x686acbb2, 0)],
            ),
            (
                HashVersion::LegacyUnsigned,
                seeded,
                [(0x75afd992, 0), (0xe149dcf2, 0), (0x686acbb2, 0)],
            ),
            (
                HashVersion::HalfMd4Unsigned,
                zero,
                [
                    (0xd196a868, 0xc420eb28),
                    (0xfc2d8f1e, 0x4ad2e136),
                    (0xe45ef14c, 0x0fc167b2),
                ],
            ),
            (
                HashVersion::HalfMd4Unsigned,
                seeded,
                [
                    (0xb1cd624a, 0x9519aec5),
                    (0x8e5f877c, 0x3b01d819),
                    (0xea682704, 0x1bfeb83d),
                ],
            ),
            (
                HashVersion::TeaUnsigned,
                zero,
                [
                    (0xb1435ec4, 0x3f7eaa0e),
                    (0x7a105c82, 0xcccef755),
                    (0xdb6dbc56, 0x121712c6),
                ],
            ),
            (
                HashVersion::TeaUnsigned,
                seeded,
                [
                    (0x2440311a, 0xc62c3fe6),
                    (0xcd4ea8a8, 0x3834a785),
                    (0x0681b184, 0x1195a9d7),
                ],
            ),
        ];
        for (version, seed, expected) in vectors {
            for (name, expected) in names.iter().zip(expected) {
                assert_eq!(
                    dx_hash(version, seed, name),
                    expected,
                    "{version:?} {seed:x?} {name:?}"
                );
            }
        }
        assert_eq!(
            HashVersion::from_root(1, true),
            Some(HashVersion::HalfMd4Unsigned)
        );
        assert_eq!(HashVersion::from_root(6, false), None);
    }

    /// Raw-byte libext2fs 1.47.4 oracle around TEA's 16-byte and half-MD4's
    /// 32-byte chunks, plus empty input and ext4's maximum filename length.
    #[test]
    fn dx_hash_matches_libext2fs_chunk_boundaries() {
        let versions = [
            HashVersion::Legacy,
            HashVersion::HalfMd4,
            HashVersion::Tea,
            HashVersion::LegacyUnsigned,
            HashVersion::HalfMd4Unsigned,
            HashVersion::TeaUnsigned,
        ];
        let vectors = [
            (
                0,
                [
                    (0x2547fc5a, 0),
                    (0xefcdab88, 0x98badcfe),
                    (0x67452300, 0xefcdab89),
                    (0x2547fc5a, 0),
                    (0xefcdab88, 0x98badcfe),
                    (0x67452300, 0xefcdab89),
                ],
            ),
            (
                1,
                [
                    (0x26f2c94c, 0),
                    (0xae8e789e, 0xf88feddf),
                    (0x4c9e4a68, 0xd1de8ff7),
                    (0xb7bcdb4c, 0),
                    (0x6f46e5d6, 0x8298a36e),
                    (0x56476c30, 0x931808a5),
                ],
            ),
            (
                15,
                [
                    (0xca478e16, 0),
                    (0x74521256, 0x600b84dd),
                    (0x1283492e, 0x99bda294),
                    (0x29d7c242, 0),
                    (0x946edf58, 0xbcbf9090),
                    (0x5db52ea2, 0x7a7d08dc),
                ],
            ),
            (
                16,
                [
                    (0x3feacd9c, 0),
                    (0xcd9b77da, 0x2e5b89cb),
                    (0x9cf6b3f2, 0x129c530a),
                    (0xbb6236f0, 0),
                    (0xb7163566, 0xcc798d3d),
                    (0x43ddb00a, 0x79015152),
                ],
            ),
            (
                17,
                [
                    (0x69b33252, 0),
                    (0xaec1ae3a, 0x4dcc61d7),
                    (0xc1580c32, 0x7fe19fcc),
                    (0xeb7d2792, 0),
                    (0x98eb3254, 0x8c981bbd),
                    (0x04fed6b6, 0xa64c8b6a),
                ],
            ),
            (
                31,
                [
                    (0x6bc8d944, 0),
                    (0x98d51aae, 0xc1e5268e),
                    (0x182af610, 0x457febed),
                    (0xfeb6de22, 0),
                    (0xd3ec1e4a, 0x88f5749a),
                    (0xfc518abc, 0x1eadbde6),
                ],
            ),
            (
                32,
                [
                    (0x8b1c2dcc, 0),
                    (0x29503458, 0x96f7fbac),
                    (0x152dc2b0, 0x0e31fc0c),
                    (0x22dc4090, 0),
                    (0xc3865574, 0x0f666c84),
                    (0x009796fa, 0x6ebfa220),
                ],
            ),
            (
                33,
                [
                    (0x9102bed2, 0),
                    (0xd69eab84, 0xf25f6577),
                    (0x048f2316, 0xd06a6c68),
                    (0xa96ed0f4, 0),
                    (0x9585486c, 0x49f6a8e6),
                    (0x7db2f2d2, 0xb118da5b),
                ],
            ),
            (
                255,
                [
                    (0x2a13aa42, 0),
                    (0x26324b5c, 0xd1268c1b),
                    (0x6645a6a6, 0x9d7d8de6),
                    (0x97be28cc, 0),
                    (0x33329962, 0x72ca6048),
                    (0xe6833580, 0x17496eec),
                ],
            ),
        ];
        for (length, expected) in vectors {
            let name: Vec<u8> = (0..length).map(|i| 0x80 + (i % 0x80) as u8).collect();
            for (version, expected) in versions.into_iter().zip(expected) {
                assert_eq!(
                    dx_hash(version, [0; 4], &name),
                    expected,
                    "{version:?} length {length}"
                );
            }
        }
    }
}
