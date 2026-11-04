//! Byte-preserving path, symlink, sparse-file and Linux-xattr access.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};

use crate::ext4::constants::*;
use crate::ext4::error::{ReadError, ReadResult};
use crate::ext4::extent;
use crate::ext4::file_tree::InodeNumber;
use crate::ext4::reader::Reader;
use crate::ext4::types::Inode;
use crate::ext4::xattr::ExtendedAttribute;

const MAX_SYMLINK_HOPS: usize = 40;

fn diagnostic(path: &[u8]) -> String {
    format!("{path:?}")
}

impl Reader {
    pub fn exists(&mut self, path: impl AsRef<[u8]>) -> bool {
        self.resolve_path(path.as_ref(), true).is_ok()
    }

    pub fn stat(&mut self, path: impl AsRef<[u8]>) -> ReadResult<(InodeNumber, Inode)> {
        self.resolve_path(path.as_ref(), true)
    }

    pub fn stat_no_follow(&mut self, path: impl AsRef<[u8]>) -> ReadResult<(InodeNumber, Inode)> {
        self.resolve_path(path.as_ref(), false)
    }

    pub fn list_dir(&mut self, path: impl AsRef<[u8]>) -> ReadResult<Vec<Vec<u8>>> {
        let path = path.as_ref();
        let (number, inode) = self.stat(path)?;
        if !inode.is_dir() {
            return Err(ReadError::NotADirectory(diagnostic(path)));
        }
        Ok(self
            .children_of(number)?
            .into_iter()
            .filter(|(name, _)| name != b"." && name != b"..")
            .map(|(name, _)| name)
            .collect())
    }

    pub fn read_file(
        &mut self,
        path: impl AsRef<[u8]>,
        offset: u64,
        count: Option<usize>,
    ) -> ReadResult<Vec<u8>> {
        let path = path.as_ref();
        let (number, inode) = self.regular_file(path)?;
        let available = inode.file_size().saturating_sub(offset);
        let count = available.min(count.map_or(u64::MAX, |count| count as u64));
        let count = usize::try_from(count).map_err(|_| ReadError::InvalidExtents)?;
        let mut out = Vec::new();
        out.try_reserve_exact(count)
            .map_err(std::io::Error::other)?;
        out.resize(count, 0);
        self.read_extents_into(number, offset, &mut out)?;
        Ok(out)
    }

    pub fn read_file_into(
        &mut self,
        path: impl AsRef<[u8]>,
        buf: &mut [u8],
        offset: u64,
    ) -> ReadResult<usize> {
        let (number, inode) = self.regular_file(path.as_ref())?;
        let count = inode
            .file_size()
            .saturating_sub(offset)
            .min(buf.len() as u64) as usize;
        self.read_extents_into(number, offset, &mut buf[..count])?;
        Ok(count)
    }

    fn regular_file(&mut self, path: &[u8]) -> ReadResult<(InodeNumber, Inode)> {
        let (number, inode) = self.stat(path)?;
        if inode.is_dir() {
            return Err(ReadError::IsDirectory(diagnostic(path)));
        }
        if !inode.is_reg() {
            return Err(ReadError::NotAFile(diagnostic(path)));
        }
        if inode.file_size() > MAX_FILE_SIZE {
            return Err(ReadError::InvalidExtents);
        }
        Ok((number, inode))
    }

    pub fn read_link(&mut self, path: impl AsRef<[u8]>) -> ReadResult<Vec<u8>> {
        let (number, inode) = self.stat_no_follow(path)?;
        if !inode.is_link() {
            return Err(ReadError::InvalidPath("not a symlink".into()));
        }
        self.read_symlink_target(&inode, number)
    }

    fn resolve_path(
        &mut self,
        path: &[u8],
        follow_final: bool,
    ) -> ReadResult<(InodeNumber, Inode)> {
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
            if !self.get_inode(current)?.is_dir() {
                return Err(ReadError::NotADirectory(diagnostic(&name)));
            }
            let child = self
                .children_of(current)?
                .into_iter()
                .find_map(|(entry, inode)| (entry == name).then_some(inode))
                .ok_or_else(|| ReadError::PathNotFound(diagnostic(&name)))?;
            let inode = self.get_inode(child)?;
            if inode.is_link() && (follow_final || !pending.is_empty()) {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(ReadError::SymlinkLoop(diagnostic(path)));
                }
                let target = self.read_symlink_target(&inode, child)?;
                if target.is_empty() || target.contains(&0) {
                    return Err(ReadError::InvalidPath(diagnostic(&target)));
                }
                if target.starts_with(b"/") {
                    current = ROOT_INODE;
                    parents.clear();
                }
                for component in normalize_path(&target).into_iter().rev() {
                    pending.push_front(component);
                }
            } else {
                parents.push(current);
                current = child;
            }
        }
        Ok((current, self.get_inode(current)?))
    }

    fn read_extents_into(
        &mut self,
        number: InodeNumber,
        start: u64,
        out: &mut [u8],
    ) -> ReadResult<()> {
        out.fill(0);
        if out.is_empty() {
            return Ok(());
        }
        let inode = self.get_inode(number)?;
        let block_size = self.block_size();
        let extents = extent::parse_mapped_extents(&inode, block_size, &mut self.file)?;
        let requested_end = start
            .checked_add(out.len() as u64)
            .ok_or(ReadError::InvalidExtents)?;
        let filesystem_blocks = self.superblock().blocks_count_lo as u64;
        for range in extents {
            if range.physical as u64 + range.length as u64 > filesystem_blocks {
                return Err(ReadError::InvalidExtents);
            }
            let logical = range.logical as u64 * block_size;
            let end = logical + range.length as u64 * block_size;
            if end <= start {
                continue;
            }
            if logical >= requested_end {
                break;
            }
            if range.unwritten {
                continue;
            }
            let first = logical.max(start);
            let last = end.min(requested_end);
            let offset = range.physical as u64 * block_size + first - logical;
            self.file.seek(SeekFrom::Start(offset))?;
            self.file
                .read_exact(&mut out[(first - start) as usize..(last - start) as usize])?;
        }
        Ok(())
    }

    fn read_symlink_target(&mut self, inode: &Inode, number: InodeNumber) -> ReadResult<Vec<u8>> {
        let length = usize::try_from(inode.file_size()).map_err(|_| ReadError::InvalidExtents)?;
        if length == 0 || length >= self.block_size() as usize {
            return Err(ReadError::InvalidExtents);
        }
        if length < INODE_BLOCK_SIZE && inode.flags & inode_flags::EXTENTS == 0 {
            return Ok(inode.block[..length].to_vec());
        }
        let mut out = vec![0; length];
        self.read_extents_into(number, 0, &mut out)?;
        Ok(out)
    }

    /// Return raw Linux xattr names/values on the named inode, without following
    /// the final symlink. POSIX ACL values are Linux API version 2, not disk v1.
    pub fn xattrs(&mut self, path: impl AsRef<[u8]>) -> ReadResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        let (_, inode) = self.stat_no_follow(path)?;
        let mut attrs = BTreeMap::new();
        if inode.inline_xattrs[..4] != [0; 4] {
            parse_xattr_area(&inode.inline_xattrs, 4, 4, &mut attrs)?;
        }
        if inode.xattr_block_hi != 0 {
            return Err(ReadError::InvalidXattrEntry);
        }
        if inode.xattr_block_lo != 0 {
            if inode.xattr_block_lo as u64 >= self.superblock().blocks_count_lo as u64 {
                return Err(ReadError::InvalidXattrEntry);
            }
            let mut block = vec![0; self.block_size() as usize];
            self.file.seek(SeekFrom::Start(
                inode.xattr_block_lo as u64 * self.block_size(),
            ))?;
            self.file.read_exact(&mut block)?;
            parse_xattr_area(&block, 32, 0, &mut attrs)?;
        }
        Ok(attrs)
    }
}

fn parse_xattr_area(
    bytes: &[u8],
    mut entry: usize,
    value_base: usize,
    attrs: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> ReadResult<()> {
    if bytes.len() < entry + 4 || bytes[..4] != XATTR_HEADER_MAGIC.to_le_bytes() {
        return Err(ReadError::InvalidXattrEntry);
    }
    let mut earliest_value = bytes.len();
    while entry + 4 <= bytes.len() {
        if bytes[entry..entry + 4] == [0; 4] {
            return Ok(());
        }
        let header = bytes
            .get(entry..entry + 16)
            .ok_or(ReadError::InvalidXattrEntry)?;
        let name_len = header[0] as usize;
        let suffix = bytes
            .get(entry + 16..entry + 16 + name_len)
            .ok_or(ReadError::InvalidXattrEntry)?;
        if suffix.contains(&0) || header[4..8] != [0; 4] {
            return Err(ReadError::InvalidXattrEntry);
        }
        let name = ExtendedAttribute::decompress_name(header[1], suffix);
        if name.is_empty() || name.len() > EXT4_NAME_LEN {
            return Err(ReadError::InvalidXattrEntry);
        }
        let offset = u16::from_le_bytes([header[2], header[3]]) as usize + value_base;
        let size = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let value = if size == 0 {
            &[][..]
        } else {
            earliest_value = earliest_value.min(offset);
            bytes
                .get(
                    offset
                        ..offset
                            .checked_add(size)
                            .ok_or(ReadError::InvalidXattrEntry)?,
                )
                .ok_or(ReadError::InvalidXattrEntry)?
        };
        entry += (16 + name_len).next_multiple_of(4);
        if entry + 4 > earliest_value {
            return Err(ReadError::InvalidXattrEntry);
        }
        let value = if name == b"system.posix_acl_access" || name == b"system.posix_acl_default" {
            crate::ext4::acl::to_linux(value).map_err(|_| ReadError::InvalidXattrEntry)?
        } else {
            value.to_vec()
        };
        if attrs.insert(name, value).is_some() {
            return Err(ReadError::InvalidXattrEntry);
        }
    }
    Err(ReadError::InvalidXattrEntry)
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
