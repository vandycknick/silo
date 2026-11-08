//! Encode only a final normalized namespace into a fresh ext4 image. No tar
//! parsing, layer mutation or overlay interpretation lives here: callers supply
//! a name-sorted tree plus the held body sources it references, and the same
//! sizing, alias and sparse-body rules apply to every producer.

use std::collections::{btree_map, BTreeMap};
use std::fs::File;
use std::io::Read;
use std::ops::Bound::{Included, Unbounded};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use disk_image::ext4::constants::file_mode;
use disk_image::ext4::file_tree::InodeNumber;
use disk_image::ext4::reader::FileBody;
use disk_image::ext4::{
    DeviceId, FileData, FileRange, FileTimestamps, FormatOptions, FormatSizing, Formatter, Reader,
    SparseData,
};

use crate::changeset::namespace::{
    BodyOrigin, InodeId, NamespaceInode, NamespaceKind, NamespaceName, ValidatedNamespace,
};
use crate::changeset::{ChangesetError, Metadata, PayloadRef, SparseRange};
use crate::{OciError, OciResult};

const BLOCK_SIZE: u64 = 4096;
const MAX_IMAGE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_XATTRS: usize = crate::changeset::limits::FORMAT_LIMITS.max_xattrs as usize;
pub(crate) const MAX_PATH_BYTES: usize =
    crate::changeset::limits::FORMAT_LIMITS.max_path_bytes as usize;
/// EXT4_LINK_MAX; a 65001st name of one non-directory inode is refused.
const MAX_LINKS: u32 = 65_000;

fn invalid(message: &'static str) -> OciError {
    ChangesetError::Invalid(message.into()).into()
}

/// Where a rendered regular inode's bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Body<'a> {
    /// An admitted extent of one ordered layer occurrence's payload pack.
    Pack(&'a BodyOrigin),
    /// A regular inode of a held, audited ext4 filesystem, read by position.
    Upper(InodeNumber),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind<'a> {
    Directory,
    Regular(Body<'a>),
    Symlink(&'a [u8]),
    CharacterDevice { major: u32, minor: u32 },
    BlockDevice { major: u32, minor: u32 },
    Fifo,
    Socket,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Node<'a> {
    pub kind: Kind<'a>,
    pub metadata: &'a Metadata,
    /// Names of this inode in the rendered tree, not the st_nlink convention.
    pub link_count: u32,
}

/// A name-sorted tree with stable inode identities. The empty path names the
/// root; every other name's parent is present and is a directory.
pub(crate) trait RenderTree {
    type Name;
    fn render_names(&self) -> &BTreeMap<Vec<u8>, Self::Name>;
    fn render_inode(name: &Self::Name) -> InodeId;
    fn render_node(&self, id: InodeId) -> OciResult<Node<'_>>;
    /// Every live inode exactly once.
    fn render_nodes(&self) -> impl Iterator<Item = Node<'_>>;
}

fn namespace_node(inode: &NamespaceInode) -> Node<'_> {
    let kind = match &inode.kind {
        NamespaceKind::Directory => Kind::Directory,
        NamespaceKind::Regular { body } => Kind::Regular(Body::Pack(body)),
        NamespaceKind::Symlink { target } => Kind::Symlink(target),
        NamespaceKind::CharacterDevice { major, minor } => Kind::CharacterDevice {
            major: *major,
            minor: *minor,
        },
        NamespaceKind::BlockDevice { major, minor } => Kind::BlockDevice {
            major: *major,
            minor: *minor,
        },
        NamespaceKind::Fifo => Kind::Fifo,
        NamespaceKind::Socket => Kind::Socket,
    };
    Node {
        kind,
        metadata: &inode.metadata,
        link_count: inode.link_count,
    }
}

impl RenderTree for ValidatedNamespace {
    type Name = NamespaceName;

    fn render_names(&self) -> &BTreeMap<Vec<u8>, NamespaceName> {
        self.names()
    }

    fn render_inode(name: &NamespaceName) -> InodeId {
        name.inode
    }

    fn render_node(&self, id: InodeId) -> OciResult<Node<'_>> {
        self.inodes()
            .get(&id)
            .map(namespace_node)
            .ok_or_else(|| invalid("namespace name has no live inode"))
    }

    fn render_nodes(&self) -> impl Iterator<Item = Node<'_>> {
        self.inodes().values().map(namespace_node)
    }
}

/// Every source a rendered tree may reference, plus optional cancellation.
#[derive(Clone, Copy)]
pub(crate) struct Sources<'a, 'p> {
    /// Held, caller-authenticated retained occurrences for `Body::Pack`.
    pub layers: &'a [crate::erofs::Layer<'p>],
    pub upper: Option<&'a Reader>,
    pub cancel: Option<&'a AtomicBool>,
}

impl<'a> Sources<'a, '_> {
    fn check_cancel(&self) -> OciResult<()> {
        if self
            .cancel
            .is_some_and(|cancel| cancel.load(Ordering::Acquire))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "fresh ext4 rendering was cancelled",
            )
            .into());
        }
        Ok(())
    }

    fn upper(&self) -> OciResult<&'a Reader> {
        self.upper
            .ok_or_else(|| invalid("tree references an upper body without an upper source"))
    }
}

fn mode(node: &Node<'_>) -> OciResult<u16> {
    let permissions = u16::try_from(node.metadata.mode)
        .ok()
        .filter(|mode| *mode & !0o7777 == 0)
        .ok_or_else(|| invalid("namespace permissions exceed the ext4 mode field"))?;
    let kind = match node.kind {
        Kind::Directory => file_mode::S_IFDIR,
        Kind::Regular(_) => file_mode::S_IFREG,
        Kind::Symlink(_) => file_mode::S_IFLNK,
        Kind::CharacterDevice { .. } => file_mode::S_IFCHR,
        Kind::BlockDevice { .. } => file_mode::S_IFBLK,
        Kind::Fifo => file_mode::S_IFIFO,
        Kind::Socket => file_mode::S_IFSOCK,
    };
    Ok(kind | permissions)
}

fn xattrs<'a>(
    metadata: &'a Metadata,
    slots: &mut [(&'a [u8], &'a [u8]); MAX_XATTRS],
) -> OciResult<usize> {
    if metadata.xattrs.len() > slots.len() {
        return Err(invalid(
            "namespace xattrs exceed the admitted Linux profile",
        ));
    }
    for (slot, attr) in slots.iter_mut().zip(&metadata.xattrs) {
        *slot = (&attr.name, &attr.value);
    }
    Ok(metadata.xattrs.len())
}

fn payload<'a>(
    layers: &'a [crate::erofs::Layer<'_>],
    body: &BodyOrigin,
) -> OciResult<&'a PayloadRef> {
    let (_, payload) = crate::erofs::plan::payload(layers, body)
        .map_err(|_| invalid("namespace body has no admitted retained payload"))?;
    if payload.pack_offset != body.pack_offset || payload.length != body.length {
        return Err(invalid(
            "namespace body differs from its admitted pack extent",
        ));
    }
    Ok(payload)
}

/// Count the union of touched filesystem blocks, not the logical holes between
/// sparse ranges. Several byte ranges can share one partially occupied block.
fn allocated_blocks(ranges: &[SparseRange]) -> OciResult<(u64, u64)> {
    let mut blocks = 0_u64;
    let mut records = 0_u64;
    let mut previous_end = 0_u64;
    for range in ranges {
        if range.length == 0 {
            continue;
        }
        let first = range.offset / BLOCK_SIZE;
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or_else(|| invalid("sparse extent end overflows"))?
            .div_ceil(BLOCK_SIZE);
        records = records
            .checked_add(1)
            .ok_or_else(|| invalid("sparse extent record count overflows"))?;
        if end > previous_end {
            blocks = blocks
                .checked_add(end - first.max(previous_end))
                .ok_or_else(|| invalid("allocated data block count overflows"))?;
            previous_end = end;
        }
    }
    Ok((blocks, records))
}

/// A direct-child view that skips whole descendant subtrees. Walking every
/// descendant again for every ancestor would otherwise multiply sizing work by
/// the admitted path depth. Search bounds borrow a short-lived stack buffer;
/// BTreeMap ranges retain only their own tree cursors. Parents longer than the
/// admitted path bound yield nothing; producers bound their paths first.
pub(crate) struct DirectChildren<'a, V> {
    names: &'a BTreeMap<Vec<u8>, V>,
    parent: &'a [u8],
    range: btree_map::Range<'a, Vec<u8>, V>,
}

impl<'a, V> DirectChildren<'a, V> {
    pub(crate) fn new(names: &'a BTreeMap<Vec<u8>, V>, parent: &'a [u8]) -> Self {
        let mut start = [0; MAX_PATH_BYTES + 1];
        let length = match parent.len() {
            0 => 0,
            length if length <= MAX_PATH_BYTES => {
                start[..length].copy_from_slice(parent);
                start[length] = b'/';
                length + 1
            }
            _ => {
                return Self {
                    names,
                    parent,
                    range: names.range::<[u8], _>((Included(parent), Included(parent))),
                }
            }
        };
        Self {
            names,
            parent,
            range: names.range::<[u8], _>((Included(&start[..length]), Unbounded)),
        }
    }
}

impl<'a, V> Iterator for DirectChildren<'a, V> {
    /// Direct-child component name and the child's map value.
    type Item = (&'a [u8], &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (path, value) = self.range.next()?;
            let relative = if self.parent.is_empty() {
                path.as_slice()
            } else {
                path.strip_prefix(self.parent)?.strip_prefix(b"/")?
            };
            if relative.is_empty() {
                continue;
            }
            if let Some(separator) = relative.iter().position(|byte| *byte == b'/') {
                // The exact direct name was encountered before its descendants.
                // Replace its slash with the next byte to skip only that subtree,
                // without skipping siblings such as `a-` between `a` and `a/b`.
                let end = path.len() - relative.len() + separator;
                let mut bound = [0; MAX_PATH_BYTES + 1];
                bound.get_mut(..end)?.copy_from_slice(path.get(..end)?);
                *bound.get_mut(end)? = b'/' + 1;
                self.range = self
                    .names
                    .range::<[u8], _>((Included(&bound[..=end]), Unbounded));
                continue;
            }
            return Some((relative, value));
        }
    }
}

fn pack_file<'a>(layers: &'a [crate::erofs::Layer<'_>], occurrence: u32) -> OciResult<&'a File> {
    layers
        .get(occurrence as usize)
        .map(|layer| layer.pack)
        .ok_or_else(|| invalid("namespace body has no retained payload pack"))
}

/// Empty normalized maps cover ordinary dense files and zero-range sparse
/// files. Discover only descriptor-bound allocated spans, clipped to this body.
/// A neighboring allocation can make the first block appear stored without
/// making the remaining logical hole dense. No content guessing participates.
fn pack_ranges(file: &File, body: &BodyOrigin, ranges: &mut Vec<SparseRange>) -> OciResult<()> {
    ranges.clear();
    let end = body
        .pack_offset
        .checked_add(body.length)
        .ok_or_else(|| invalid("payload body end overflows"))?;
    if end > file.metadata()?.len() {
        return Err(invalid("payload body exceeds its retained pack descriptor"));
    }
    let mut cursor = body.pack_offset;
    while cursor < end {
        let offset = i64::try_from(cursor)
            .map_err(|_| invalid("payload offset exceeds the host seek range"))?;
        let data = match nix::unistd::lseek(file, offset, nix::unistd::Whence::SeekData) {
            Ok(data) => u64::try_from(data)
                .map_err(|_| invalid("payload data map returned a negative offset"))?,
            Err(nix::errno::Errno::ENXIO) => break,
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        if data < cursor {
            return Err(invalid("payload data map did not advance within its body"));
        }
        if data >= end {
            break;
        }
        let offset = i64::try_from(data)
            .map_err(|_| invalid("payload data span exceeds the host seek range"))?;
        let hole = nix::unistd::lseek(file, offset, nix::unistd::Whence::SeekHole)
            .map_err(std::io::Error::from)?;
        let hole = u64::try_from(hole)
            .map_err(|_| invalid("payload hole map returned a negative offset"))?;
        if hole <= data {
            return Err(invalid(
                "payload hole map did not advance beyond stored bytes",
            ));
        }
        let clipped = hole.min(end);
        crate::changeset::limits::reserve_vec(ranges, 1)?;
        ranges.push(SparseRange {
            offset: data - body.pack_offset,
            length: clipped - data,
        });
        cursor = clipped;
    }
    Ok(())
}

/// Stored ranges of a pack body: the normalized map when it has one, otherwise
/// the descriptor's allocated spans.
fn pack_body_ranges(
    layers: &[crate::erofs::Layer<'_>],
    body: &BodyOrigin,
    ranges: &mut Vec<SparseRange>,
) -> OciResult<()> {
    let payload = payload(layers, body)?;
    if body.length == 0 {
        ranges.clear();
    } else if payload.sparse.is_empty() {
        pack_ranges(pack_file(layers, body.entry.layer)?, body, ranges)?;
    } else {
        ranges.clear();
        crate::changeset::limits::reserve_vec(ranges, payload.sparse.len())?;
        ranges.extend_from_slice(&payload.sparse);
    }
    Ok(())
}

/// The audited upper's own extent map; unwritten extents are holes.
fn upper_body_ranges(body: &FileBody, ranges: &mut Vec<SparseRange>) -> OciResult<()> {
    ranges.clear();
    for range in body.stored_ranges() {
        crate::changeset::limits::reserve_vec(ranges, 1)?;
        ranges.push(SparseRange {
            offset: range.offset,
            length: range.length,
        });
    }
    Ok(())
}

/// The normalized pack is zero-expanded and seekable. Supply only admitted
/// stored ranges to the sparse encoder, rather than reading its logical holes.
/// Positioned reads leave a shared retained descriptor's cursor untouched.
struct StoredRanges<'a> {
    file: &'a File,
    pack_offset: u64,
    ranges: std::slice::Iter<'a, SparseRange>,
    position: u64,
    remaining: u64,
}

impl<'a> StoredRanges<'a> {
    fn new(file: &'a File, pack_offset: u64, ranges: &'a [SparseRange]) -> Self {
        Self {
            file,
            pack_offset,
            ranges: ranges.iter(),
            position: 0,
            remaining: 0,
        }
    }
}

impl Read for StoredRanges<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.remaining == 0 {
            let Some(range) = self.ranges.next() else {
                return Ok(0);
            };
            self.position = self.pack_offset.checked_add(range.offset).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "payload pack offset overflows",
                )
            })?;
            self.remaining = range.length;
        }
        let count = buffer
            .len()
            .min(self.remaining.min(usize::MAX as u64) as usize);
        let read = self.file.read_at(&mut buffer[..count], self.position)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "payload pack ended inside an admitted stored range",
            ));
        }
        self.position += read as u64;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn image_size<T: RenderTree>(
    tree: &T,
    sources: &Sources<'_, '_>,
    minimum_size: u64,
) -> OciResult<u64> {
    let mut sizing = FormatSizing::new();
    let mut slots = [(b"".as_slice(), b"".as_slice()); MAX_XATTRS];
    let mut ranges = Vec::new();
    for node in tree.render_nodes() {
        sources.check_cancel()?;
        if node.link_count == 0 || node.link_count > MAX_LINKS {
            return Err(ChangesetError::Limit {
                resource: "ext4 inode links",
                actual: u64::from(node.link_count),
                maximum: u64::from(MAX_LINKS),
            }
            .into());
        }
        let (blocks, records) = match node.kind {
            Kind::Regular(Body::Pack(body)) => {
                pack_body_ranges(sources.layers, body, &mut ranges)?;
                allocated_blocks(&ranges)?
            }
            Kind::Regular(Body::Upper(inode)) => {
                let body = sources
                    .upper()?
                    .file_body(inode)
                    .map_err(OciError::upper_read)?;
                upper_body_ranges(&body, &mut ranges)?;
                allocated_blocks(&ranges)?
            }
            // The VFS and ext4 store at most PATH_MAX - 1 target bytes.
            Kind::Symlink(target) if target.len() >= 4096 => {
                return Err(ChangesetError::Limit {
                    resource: "ext4 symlink target bytes",
                    actual: target.len() as u64,
                    maximum: 4095,
                }
                .into());
            }
            Kind::Symlink(target) if target.len() >= 60 => {
                ((target.len() as u64).div_ceil(BLOCK_SIZE), 1)
            }
            _ => (0, 0),
        };
        let count = xattrs(node.metadata, &mut slots)?;
        sizing
            .add_inode(mode(&node)?, blocks, records, &slots[..count])
            .map_err(OciError::flat_ext4)?;
    }
    let names = tree.render_names();
    for (path, name) in names {
        if path.len() > MAX_PATH_BYTES {
            return Err(ChangesetError::Limit {
                resource: "rendered path bytes",
                actual: path.len() as u64,
                maximum: MAX_PATH_BYTES as u64,
            }
            .into());
        }
        if matches!(
            tree.render_node(T::render_inode(name))?.kind,
            Kind::Directory
        ) {
            // The writer has no DIR_NLINK: a directory's own st_nlink (2 plus
            // its subdirectories) must stay within EXT4_LINK_MAX.
            let mut subdirectories = 0_u32;
            for (_, child) in DirectChildren::new(names, path) {
                if matches!(
                    tree.render_node(T::render_inode(child))?.kind,
                    Kind::Directory
                ) {
                    subdirectories += 1;
                }
            }
            if subdirectories > MAX_LINKS - 2 {
                return Err(ChangesetError::Limit {
                    resource: "ext4 subdirectories",
                    actual: u64::from(subdirectories),
                    maximum: u64::from(MAX_LINKS - 2),
                }
                .into());
            }
            sizing
                .add_directory(DirectChildren::new(names, path).map(|(child, _)| child))
                .map_err(OciError::flat_ext4)?;
        }
    }
    let required = sizing.minimum_size_bytes().map_err(OciError::flat_ext4)?;
    let size = required.max(minimum_size);
    if size > MAX_IMAGE_BYTES {
        return Err(ChangesetError::Limit {
            resource: "flat ext4 image bytes",
            actual: size,
            maximum: MAX_IMAGE_BYTES,
        }
        .into());
    }
    Ok(size)
}

/// Fields shared by every created inode at one path.
struct Entry<'a> {
    path: &'a [u8],
    mode: u16,
    link: Option<&'a [u8]>,
    timestamps: FileTimestamps,
    metadata: &'a Metadata,
    xattrs: &'a [(&'a [u8], &'a [u8])],
    device: Option<DeviceId>,
}

fn create(
    formatter: &mut Formatter,
    entry: &Entry<'_>,
    data: Option<FileData<'_>>,
) -> OciResult<()> {
    formatter
        .create(
            entry.path,
            entry.mode,
            entry.link,
            Some(entry.timestamps),
            data,
            Some(entry.metadata.uid),
            Some(entry.metadata.gid),
            Some(entry.xattrs),
            entry.device,
        )
        .map_err(OciError::flat_ext4)
}

/// Dense when one stored range covers the whole body, otherwise sparse; the
/// reader must supply exactly the stored bytes and nothing more.
fn create_regular(
    formatter: &mut Formatter,
    entry: &Entry<'_>,
    length: u64,
    ranges: &[SparseRange],
    reader: &mut dyn Read,
) -> OciResult<()> {
    if length == 0 {
        if !ranges.is_empty() {
            return Err(invalid("empty regular body has stored ranges"));
        }
        return create(formatter, entry, None);
    }
    if matches!(ranges, [range] if range.offset == 0 && range.length == length) {
        create(formatter, entry, Some(FileData::Dense(&mut *reader)))?;
    } else {
        let mut stored = ranges
            .iter()
            .filter(|range| range.length != 0)
            .map(|range| FileRange {
                offset: range.offset,
                length: range.length,
            });
        create(
            formatter,
            entry,
            Some(FileData::Sparse(SparseData {
                reader: &mut *reader,
                length,
                ranges: &mut stored,
            })),
        )?;
    }
    let mut probe = [0_u8; 1];
    if reader.read(&mut probe)? != 0 {
        return Err(invalid(
            "regular body supplied bytes beyond its stored ranges",
        ));
    }
    Ok(())
}

/// Render `tree` as a fresh ext4 image at `path` and return its byte length.
/// Size and link bounds are checked before the output file is created.
pub(crate) fn render<T: RenderTree>(
    path: &Path,
    tree: &T,
    sources: &Sources<'_, '_>,
    minimum_size: u64,
) -> OciResult<u64> {
    let size = image_size(tree, sources, minimum_size)?;
    sources.check_cancel()?;
    let mut formatter =
        Formatter::with_options(path, FormatOptions::new(size)).map_err(OciError::flat_ext4)?;
    // Formatting scaffolding is not part of the composed namespace. An
    // explicitly supplied lost+found, of any admitted type, is rendered below.
    formatter
        .remove(b"/lost+found")
        .map_err(OciError::flat_ext4)?;
    let mut aliases = BTreeMap::new();
    let mut slots = [(b"".as_slice(), b"".as_slice()); MAX_XATTRS];
    let mut ranges = Vec::new();
    for (path, name) in tree.render_names() {
        sources.check_cancel()?;
        let id = T::render_inode(name);
        let node = tree.render_node(id)?;
        if node.link_count > 1 {
            if let Some(target) = aliases.get(&id) {
                formatter
                    .link(path.as_slice(), *target)
                    .map_err(OciError::flat_ext4)?;
                continue;
            }
            aliases.insert(id, path.as_slice());
        }
        let count = xattrs(node.metadata, &mut slots)?;
        let mut entry = Entry {
            path: if path.is_empty() {
                b"/".as_slice()
            } else {
                path.as_slice()
            },
            mode: mode(&node)?,
            link: None,
            timestamps: FileTimestamps::from_mtime(
                node.metadata.mtime_seconds,
                node.metadata.mtime_nanos,
            )
            .map_err(OciError::flat_ext4)?,
            metadata: node.metadata,
            xattrs: &slots[..count],
            device: None,
        };
        match node.kind {
            Kind::Regular(Body::Pack(body)) => {
                pack_body_ranges(sources.layers, body, &mut ranges)?;
                let file = if body.length == 0 {
                    None
                } else {
                    Some(pack_file(sources.layers, body.entry.layer)?)
                };
                match file {
                    Some(file) => create_regular(
                        &mut formatter,
                        &entry,
                        body.length,
                        &ranges,
                        &mut StoredRanges::new(file, body.pack_offset, &ranges),
                    )?,
                    None => {
                        create_regular(&mut formatter, &entry, 0, &ranges, &mut std::io::empty())?
                    }
                }
            }
            Kind::Regular(Body::Upper(inode)) => {
                let upper = sources.upper()?;
                let body = upper.file_body(inode).map_err(OciError::upper_read)?;
                upper_body_ranges(&body, &mut ranges)?;
                create_regular(
                    &mut formatter,
                    &entry,
                    body.size(),
                    &ranges,
                    &mut upper.body_stream(&body),
                )?;
            }
            Kind::Symlink(target) => {
                entry.link = Some(target);
                create(&mut formatter, &entry, None)?;
            }
            Kind::CharacterDevice { major, minor } | Kind::BlockDevice { major, minor } => {
                entry.device = Some(DeviceId::new(major, minor).map_err(OciError::flat_ext4)?);
                create(&mut formatter, &entry, None)?;
            }
            Kind::Directory | Kind::Fifo | Kind::Socket => {
                create(&mut formatter, &entry, None)?;
            }
        }
    }
    formatter.close().map_err(OciError::flat_ext4)?;
    Ok(size)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::{FileExt, MetadataExt};

    use crate::changeset::namespace::{compose, BodyOrigin, EntryOrigin};
    use crate::changeset::{
        ChangeEntry, ChangesetLimits, ContentDigest, EntryKind, LayerChangeset, Metadata,
        MetadataPresence, PayloadRef, SparseRange,
    };
    use crate::flat_ext4::{allocated_blocks, pack_ranges, DirectChildren, StoredRanges};

    #[test]
    fn sparse_sizing_counts_touched_block_union_without_logical_holes() {
        let payload = PayloadRef {
            pack_offset: 0,
            length: 12 * 1024 * 1024 * 1024,
            sparse: vec![
                SparseRange {
                    offset: 1,
                    length: 1,
                },
                SparseRange {
                    offset: 4,
                    length: 1,
                },
                SparseRange {
                    offset: 4096,
                    length: 1,
                },
                SparseRange {
                    offset: 12 * 1024 * 1024 * 1024 - 1,
                    length: 1,
                },
            ],
        };
        assert_eq!(allocated_blocks(&payload.sparse).unwrap(), (3, 4));
        let mut invalid = payload;
        invalid.sparse = vec![SparseRange {
            offset: u64::MAX,
            length: 1,
        }];
        assert!(allocated_blocks(&invalid.sparse).is_err());
    }

    #[test]
    fn direct_child_sizing_skips_descendants_without_skipping_punctuation_siblings() {
        let layer = LayerChangeset {
            diff_id: ContentDigest::of_bytes(b"directory fixture"),
            pack_length: 0,
            entries: [
                b"a".as_slice(),
                b"a-",
                b"a/x",
                b"a/x/z",
                b"a0",
                b"b",
                b"raw-\xff",
            ]
            .into_iter()
            .enumerate()
            .map(|(ordinal, path)| ChangeEntry {
                ordinal: ordinal as u64,
                path: path.to_vec(),
                kind: EntryKind::Directory,
                metadata: Metadata {
                    uid: 0,
                    gid: 0,
                    mode: 0o755,
                    mtime_seconds: 0,
                    mtime_nanos: 0,
                    xattrs: Vec::new(),
                },
                presence: MetadataPresence::default(),
            })
            .collect(),
        };
        let namespace = compose(&[&layer], &ChangesetLimits::default()).unwrap();
        let names = namespace.names();
        let children = |parent: &[u8]| {
            DirectChildren::new(names, parent)
                .map(|(name, _)| name.to_vec())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            children(b""),
            vec![
                b"a".to_vec(),
                b"a-".to_vec(),
                b"a0".to_vec(),
                b"b".to_vec(),
                b"raw-\xff".to_vec()
            ],
        );
        assert_eq!(children(b"a"), vec![b"x".to_vec()]);
        assert_eq!(children(b"a/x"), vec![b"z".to_vec()]);
        let overlong = vec![b'a'; crate::flat_ext4::MAX_PATH_BYTES + 1];
        assert!(children(overlong.as_slice()).is_empty());
    }

    #[test]
    fn retained_sparse_pack_reader_streams_only_stored_bytes_across_twelve_gibibyte_hole() {
        let temp = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(temp.path().join("payload.pack"))
            .unwrap();
        let length = 12 * 1024 * 1024 * 1024;
        file.set_len(length).unwrap();
        file.write_all_at(b"A", 0).unwrap();
        file.write_all_at(b"B", length - 1).unwrap();
        file.sync_all().unwrap();
        let ranges = [
            SparseRange {
                offset: 0,
                length: 1,
            },
            SparseRange {
                offset: length - 1,
                length: 1,
            },
        ];
        let mut reader = StoredRanges::new(&file, 0, &ranges);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"AB");
        assert!(file.metadata().unwrap().blocks() * 512 < 1024 * 1024);
    }

    #[test]
    fn empty_normalized_map_clips_neighbor_allocations_without_expanding_the_hole() {
        let temp = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(temp.path().join("payload.pack"))
            .unwrap();
        let body = BodyOrigin {
            entry: EntryOrigin {
                layer: 0,
                ordinal: 0,
            },
            pack_offset: 1,
            length: 12 * 1024 * 1024 * 1024,
        };
        file.set_len(body.pack_offset + body.length + 8192).unwrap();
        let mut ranges = Vec::new();
        pack_ranges(&file, &body, &mut ranges).unwrap();
        assert!(ranges.is_empty());
        // Deliberately share allocation granules at both body boundaries.
        file.write_all_at(b"A", 0).unwrap();
        file.write_all_at(b"B", body.pack_offset + body.length + 1)
            .unwrap();
        file.sync_all().unwrap();
        pack_ranges(&file, &body, &mut ranges).unwrap();
        assert!(!ranges.is_empty());
        let stored: u64 = ranges.iter().map(|range| range.length).sum();
        assert!(
            stored < 1024 * 1024,
            "boundary allocations cannot make a 12GiB hole dense"
        );
        assert!(ranges
            .iter()
            .all(|range| range.offset + range.length <= body.length));
        let mut reader = StoredRanges::new(&file, body.pack_offset, &ranges);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes.len() as u64, stored);
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "adjacent bytes outside the body never enter its stream"
        );
    }
}
