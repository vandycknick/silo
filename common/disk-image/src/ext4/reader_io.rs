//! Byte-preserving path resolution, positioned file bodies, symlinks and
//! Linux xattrs over a validated [`Reader`].

use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::os::unix::fs::FileExt;

use crate::ext4::constants::*;
use crate::ext4::error::{ReadError, ReadResult, Structure, Unsupported};
use crate::ext4::file_tree::InodeNumber;
use crate::ext4::reader::{BLOCK_BYTES, BodyExtent, FileBody, InodeKind, Live, Reader};
use crate::ext4::types::Inode;
use crate::ext4::xattr::ExtendedAttribute;

const MAX_SYMLINK_HOPS: usize = 40;
const XATTR_ENTRY_SIZE: usize = 16;
/// Linux `EXT4_XATTR_REFCOUNT_MAX`.
const XATTR_REFCOUNT_MAX: u32 = 1024;

fn diagnostic(path: &[u8]) -> String {
    format!("{path:?}")
}

impl Reader {
    pub fn exists(&self, path: impl AsRef<[u8]>) -> bool {
        self.resolve_path(path.as_ref(), true).is_ok()
    }

    pub fn stat(&self, path: impl AsRef<[u8]>) -> ReadResult<(InodeNumber, Inode)> {
        let live = self.resolve_path(path.as_ref(), true)?;
        Ok((live.number, live.raw))
    }

    pub fn stat_no_follow(&self, path: impl AsRef<[u8]>) -> ReadResult<(InodeNumber, Inode)> {
        let live = self.resolve_path(path.as_ref(), false)?;
        Ok((live.number, live.raw))
    }

    pub fn list_dir(&self, path: impl AsRef<[u8]>) -> ReadResult<Vec<Vec<u8>>> {
        let path = path.as_ref();
        let live = self.resolve_path(path, true)?;
        if live.kind != InodeKind::Directory {
            return Err(ReadError::NotADirectory(diagnostic(path)));
        }
        Ok(self
            .read_dir(live.number)?
            .entries
            .into_iter()
            .map(|entry| entry.name)
            .collect())
    }

    pub fn read_file(
        &self,
        path: impl AsRef<[u8]>,
        offset: u64,
        count: Option<usize>,
    ) -> ReadResult<Vec<u8>> {
        let body = self.regular_file(path.as_ref())?;
        let available = body.size.saturating_sub(offset);
        let count = available.min(count.map_or(u64::MAX, |count| count as u64));
        let count = usize::try_from(count).map_err(std::io::Error::other)?;
        let mut out = Vec::new();
        out.try_reserve_exact(count)?;
        out.resize(count, 0);
        self.read_at(&body, offset, &mut out)?;
        Ok(out)
    }

    pub fn read_file_into(
        &self,
        path: impl AsRef<[u8]>,
        buf: &mut [u8],
        offset: u64,
    ) -> ReadResult<usize> {
        let body = self.regular_file(path.as_ref())?;
        let count = body.size.saturating_sub(offset).min(buf.len() as u64) as usize;
        self.read_at(&body, offset, &mut buf[..count])?;
        Ok(count)
    }

    fn regular_file(&self, path: &[u8]) -> ReadResult<FileBody> {
        let live = self.resolve_path(path, true)?;
        match live.kind {
            InodeKind::Regular => self.live_body(&live),
            InodeKind::Directory => Err(ReadError::IsDirectory(diagnostic(path))),
            _ => Err(ReadError::NotAFile(diagnostic(path))),
        }
    }

    pub fn read_link(&self, path: impl AsRef<[u8]>) -> ReadResult<Vec<u8>> {
        let live = self.resolve_path(path.as_ref(), false)?;
        if live.kind != InodeKind::Symlink {
            return Err(ReadError::InvalidPath("not a symlink".into()));
        }
        self.live_symlink_target(&live)
    }

    /// Raw Linux xattr names/values of the named inode, without following the
    /// final symlink. POSIX ACL values are Linux API version 2, not disk v1.
    pub fn xattrs(&self, path: impl AsRef<[u8]>) -> ReadResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        let live = self.resolve_path(path.as_ref(), false)?;
        self.live_xattrs(&live)
    }

    /// Raw Linux xattrs of an allocated inode; see [`Reader::xattrs`].
    pub fn inode_xattrs(&self, number: InodeNumber) -> ReadResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.live_xattrs(&self.live(number)?)
    }

    /// Target bytes of a symlink inode.
    pub fn symlink_target(&self, number: InodeNumber) -> ReadResult<Vec<u8>> {
        let live = self.live(number)?;
        if live.kind != InodeKind::Symlink {
            return Err(ReadError::InvalidPath(format!(
                "inode {number} is not a symlink"
            )));
        }
        self.live_symlink_target(&live)
    }

    /// Validated stored-byte map of a regular file inode, including exact
    /// `i_blocks` accounting.
    pub fn file_body(&self, number: InodeNumber) -> ReadResult<FileBody> {
        let live = self.live(number)?;
        if live.kind != InodeKind::Regular {
            return Err(ReadError::NotAFile(format!("inode {number}")));
        }
        self.live_body(&live)
    }

    /// Fill `buf` with logical bytes `[offset, offset + buf.len())` of `body`
    /// using positioned reads. Holes and unwritten extents read as zeros. The
    /// range must lie within the file size.
    pub fn read_at(&self, body: &FileBody, offset: u64, buf: &mut [u8]) -> ReadResult<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|end| buf.is_empty() || *end <= body.size)
            .ok_or(ReadError::OutOfRange {
                inode: body.inode,
                offset,
                length: buf.len() as u64,
                size: body.size,
            })?;
        buf.fill(0);
        let first = body
            .extents
            .partition_point(|extent| extent.logical + extent.length <= offset);
        for extent in &body.extents[first..] {
            if extent.logical >= end {
                break;
            }
            let start = extent.logical.max(offset);
            let stop = (extent.logical + extent.length).min(end);
            self.file().read_exact_at(
                &mut buf[(start - offset) as usize..(stop - offset) as usize],
                extent.physical + start - extent.logical,
            )?;
        }
        Ok(())
    }

    /// A [`Read`] over the concatenated stored ranges of `body` in logical
    /// order: exactly [`FileBody::stored_bytes`] bytes, then end of stream.
    pub fn body_stream<'a>(&'a self, body: &'a FileBody) -> BodyStream<'a> {
        BodyStream {
            reader: self,
            extents: body.extents.iter(),
            position: 0,
            remaining: 0,
        }
    }

    pub(crate) fn live_body(&self, live: &Live) -> ReadResult<FileBody> {
        let map = self.data_map(live)?;
        let mut extents = Vec::new();
        for extent in map.extents.iter().filter(|extent| !extent.unwritten) {
            let logical = extent.logical as u64 * BLOCK_BYTES;
            if logical >= live.size {
                break;
            }
            extents.try_reserve(1)?;
            extents.push(BodyExtent {
                logical,
                physical: extent.physical as u64 * BLOCK_BYTES,
                length: (extent.length as u64 * BLOCK_BYTES).min(live.size - logical),
            });
        }
        Ok(FileBody {
            inode: live.number,
            size: live.size,
            extents,
        })
    }

    /// Fast symlinks (no `EXTENTS`, nothing charged but an xattr block) keep
    /// their target in `i_block`; slow symlinks map exactly logical block 0.
    /// Like e2fsck, the byte after the target must be NUL and the target must
    /// hold no NUL.
    pub(crate) fn live_symlink_target(&self, live: &Live) -> ReadResult<Vec<u8>> {
        let corrupt = |reason| ReadError::corrupt(Structure::Symlink, Some(live.number), reason);
        let size = live.size as usize;
        if size == 0 || size >= BLOCK_BYTES as usize {
            return Err(corrupt("symlink target length is invalid"));
        }
        let (target, tail) = if live.raw.flags & inode_flags::EXTENTS == 0 {
            if size >= INODE_BLOCK_SIZE {
                return Err(ReadError::Unsupported(Unsupported::BlockMappedInode(
                    live.number,
                )));
            }
            self.check_charge(live, 0)?;
            (live.raw.block[..size].to_vec(), live.raw.block[size])
        } else {
            let map = self.extent_map(live)?;
            let [extent] = map.extents.as_slice() else {
                return Err(corrupt("slow symlink does not map exactly one block"));
            };
            if extent.logical != 0 || extent.length != 1 || extent.unwritten {
                return Err(corrupt("slow symlink does not map exactly one block"));
            }
            self.check_charge(live, 1 + map.tree_blocks)?;
            let mut block = vec![0u8; BLOCK_BYTES as usize];
            self.file()
                .read_exact_at(&mut block, extent.physical as u64 * BLOCK_BYTES)?;
            let tail = block[size];
            block.truncate(size);
            (block, tail)
        };
        if target.contains(&0) || tail != 0 {
            return Err(corrupt("symlink target length disagrees with its bytes"));
        }
        Ok(target)
    }

    /// In-inode xattrs exist only behind the in-inode magic, as Linux reads
    /// them; an external block is validated like `ext4_xattr_check_block`.
    pub(crate) fn live_xattrs(&self, live: &Live) -> ReadResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut attrs = BTreeMap::new();
        let inline = &live.raw.inline_xattrs;
        if inline[..4] != [0; 4] {
            if inline[..4] != XATTR_HEADER_MAGIC.to_le_bytes() {
                return Err(xattr_corrupt(live.number, "bad in-inode xattr magic"));
            }
            parse_xattr_entries(&inline[4..], 0, live.number, &mut attrs)?;
        }
        if live.raw.xattr_block_lo != 0 {
            let mut block = vec![0u8; BLOCK_BYTES as usize];
            self.file()
                .read_exact_at(&mut block, live.raw.xattr_block_lo as u64 * BLOCK_BYTES)?;
            let word = |offset: usize| {
                u32::from_le_bytes([
                    block[offset],
                    block[offset + 1],
                    block[offset + 2],
                    block[offset + 3],
                ])
            };
            if word(0) != XATTR_HEADER_MAGIC || word(8) != 1 {
                return Err(xattr_corrupt(live.number, "bad xattr block header"));
            }
            if word(4) == 0 || word(4) > XATTR_REFCOUNT_MAX {
                return Err(xattr_corrupt(
                    live.number,
                    "bad xattr block reference count",
                ));
            }
            parse_xattr_entries(
                &block,
                XATTR_BLOCK_HEADER_SIZE as usize,
                live.number,
                &mut attrs,
            )?;
        }
        Ok(attrs)
    }

    fn resolve_path(&self, path: &[u8], follow_final: bool) -> ReadResult<Live> {
        if path.contains(&0) {
            return Err(ReadError::InvalidPath(diagnostic(path)));
        }
        let mut pending: VecDeque<Vec<u8>> = normalize_path(path).into();
        let mut current = ROOT_INODE;
        let mut parents = Vec::new();
        let mut hops = 0;
        while let Some(name) = pending.pop_front() {
            if name == b"." {
                continue;
            }
            if name == b".." {
                current = parents.pop().unwrap_or(ROOT_INODE);
                continue;
            }
            let directory = self.live(current)?;
            if directory.kind != InodeKind::Directory {
                return Err(ReadError::NotADirectory(diagnostic(&name)));
            }
            let entries = self.read_dir(current)?;
            let child = entries
                .entries
                .binary_search_by(|entry| entry.name.as_slice().cmp(&name))
                .map(|index| &entries.entries[index])
                .map_err(|_| ReadError::PathNotFound(diagnostic(&name)))?;
            let live = self.live(child.inode)?;
            if live.kind.file_type() != child.file_type {
                return Err(ReadError::corrupt(
                    Structure::Directory,
                    Some(current),
                    "entry file type differs from its inode",
                ));
            }
            if live.kind == InodeKind::Symlink && (follow_final || !pending.is_empty()) {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(ReadError::SymlinkLoop(diagnostic(path)));
                }
                let target = self.live_symlink_target(&live)?;
                if target.starts_with(b"/") {
                    current = ROOT_INODE;
                    parents.clear();
                }
                for component in normalize_path(&target).into_iter().rev() {
                    pending.push_front(component);
                }
            } else {
                parents.push(current);
                current = child.inode;
            }
        }
        self.live(current)
    }
}

/// Reader returned by [`Reader::body_stream`].
pub struct BodyStream<'a> {
    reader: &'a Reader,
    extents: std::slice::Iter<'a, BodyExtent>,
    position: u64,
    remaining: u64,
}

impl Read for BodyStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.remaining == 0 {
            let Some(extent) = self.extents.next() else {
                return Ok(0);
            };
            self.position = extent.physical;
            self.remaining = extent.length;
        }
        let count = buffer
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let read = self
            .reader
            .file()
            .read_at(&mut buffer[..count], self.position)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ext4 image ended inside a stored file range",
            ));
        }
        self.position += read as u64;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn xattr_corrupt(number: InodeNumber, reason: &'static str) -> ReadError {
    ReadError::corrupt(Structure::Xattr, Some(number), reason)
}

/// Parse xattr entries starting at `entry` within `bytes`; value offsets are
/// relative to the start of `bytes` (the first entry for in-inode storage,
/// the block for external storage).
fn parse_xattr_entries(
    bytes: &[u8],
    mut entry: usize,
    number: InodeNumber,
    attrs: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> ReadResult<()> {
    let corrupt = |reason| xattr_corrupt(number, reason);
    let mut earliest_value = bytes.len();
    loop {
        let terminator = bytes
            .get(entry..entry + 4)
            .ok_or_else(|| corrupt("xattr entries are not terminated"))?;
        if terminator == [0; 4] {
            return Ok(());
        }
        let header = bytes
            .get(entry..entry + XATTR_ENTRY_SIZE)
            .ok_or_else(|| corrupt("xattr entry crosses its area"))?;
        let name_len = header[0] as usize;
        let index = header[1];
        let value_offset = u16::from_le_bytes([header[2], header[3]]) as usize;
        let value_inode = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let size = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let suffix = bytes
            .get(entry + XATTR_ENTRY_SIZE..entry + XATTR_ENTRY_SIZE + name_len)
            .ok_or_else(|| corrupt("xattr name crosses its area"))?;
        if value_inode != 0 {
            return Err(ReadError::Unsupported(Unsupported::XattrValueInode(number)));
        }
        match (index, suffix) {
            (1 | 4 | 6, suffix) if !suffix.is_empty() => {}
            (2 | 3, []) => {}
            (1 | 2 | 3 | 4 | 6, _) => return Err(corrupt("xattr name does not fit its index")),
            (7, b"data") => return Err(ReadError::Unsupported(Unsupported::InlineData(number))),
            (index, _) => {
                return Err(ReadError::Unsupported(Unsupported::XattrNamespace {
                    inode: number,
                    index,
                }));
            }
        }
        if suffix.contains(&0) {
            return Err(corrupt("xattr name contains NUL"));
        }
        let name = ExtendedAttribute::decompress_name(index, suffix);
        if name.len() > EXT4_NAME_LEN {
            return Err(corrupt("xattr name is too long"));
        }
        let value = if size == 0 {
            &[][..]
        } else {
            if value_offset % 4 != 0 {
                return Err(corrupt("xattr value is not aligned"));
            }
            earliest_value = earliest_value.min(value_offset);
            value_offset
                .checked_add(size)
                .and_then(|end| bytes.get(value_offset..end))
                .ok_or_else(|| corrupt("xattr value crosses its area"))?
        };
        entry += (XATTR_ENTRY_SIZE + name_len).next_multiple_of(4);
        if entry + 4 > earliest_value {
            return Err(corrupt("xattr entries overlap their values"));
        }
        let value = if index == 2 || index == 3 {
            crate::ext4::acl::to_linux(value).map_err(|_| corrupt("invalid POSIX ACL"))?
        } else {
            value.to_vec()
        };
        if attrs.insert(name, value).is_some() {
            return Err(corrupt("duplicate xattr name"));
        }
    }
}

fn normalize_path(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|byte| *byte == b'/')
        .filter(|name| !name.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::ext4::reader_io::normalize_path;

    #[test]
    fn test_normalize_path_cases() {
        for (input, expected) in [
            (
                b"/etc/passwd".as_slice(),
                vec![b"etc".to_vec(), b"passwd".to_vec()],
            ),
            (b"//a///b//", vec![b"a".to_vec(), b"b".to_vec()]),
            (b"/a\xff/b ", vec![b"a\xff".to_vec(), b"b ".to_vec()]),
            (b"/", vec![]),
            (b"", vec![]),
        ] {
            assert_eq!(normalize_path(input), expected);
        }
    }
}
