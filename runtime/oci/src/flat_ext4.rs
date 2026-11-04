//! Encode only the final Phase2 namespace; no tar parsing or layer mutation lives here.

use std::collections::{btree_map, BTreeMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::ops::Bound::{Included, Unbounded};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use disk_image::ext4::constants::file_mode;
use disk_image::ext4::{
    DeviceId, FileData, FileRange, FileTimestamps, FormatOptions, FormatSizing, Formatter,
    SparseData,
};

use crate::changeset::ingest::ScopedPack;
use crate::changeset::namespace::{
    BodyOrigin, NamespaceInode, NamespaceKind, NamespaceName, ValidatedNamespace,
};
use crate::changeset::{ChangesetError, Metadata, PayloadRef, SparseRange};
use crate::{OciError, OciResult};

const BLOCK_SIZE: u64 = 4096;
const MAX_IMAGE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_XATTRS: usize = crate::changeset::limits::FORMAT_LIMITS.max_xattrs as usize;
const MAX_PATH_BYTES: usize = crate::changeset::limits::FORMAT_LIMITS.max_path_bytes as usize;

fn invalid(message: &'static str) -> OciError {
    ChangesetError::Invalid(message.into()).into()
}

fn mode(inode: &NamespaceInode) -> OciResult<u16> {
    let permissions = u16::try_from(inode.metadata.mode)
        .map_err(|_| invalid("namespace permissions exceed the ext4 mode field"))?;
    let kind = match inode.kind {
        NamespaceKind::Directory => file_mode::S_IFDIR,
        NamespaceKind::Regular { .. } => file_mode::S_IFREG,
        NamespaceKind::Symlink { .. } => file_mode::S_IFLNK,
        NamespaceKind::CharacterDevice { .. } => file_mode::S_IFCHR,
        NamespaceKind::BlockDevice { .. } => file_mode::S_IFBLK,
        NamespaceKind::Fifo => file_mode::S_IFIFO,
        NamespaceKind::Socket => file_mode::S_IFSOCK,
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
    layers: &'a [Option<ScopedPack<'_>>],
    body: &BodyOrigin,
) -> OciResult<&'a PayloadRef> {
    let layer = layers
        .get(body.entry.layer as usize)
        .and_then(Option::as_ref)
        .ok_or_else(|| invalid("namespace body has no live layer occurrence"))?;
    let payload = layer
        .payload(body.entry.ordinal)
        .ok_or_else(|| invalid("namespace body has no admitted source payload"))?;
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
/// BTreeMap ranges retain only their own tree cursors.
struct DirectChildren<'a> {
    names: &'a BTreeMap<Vec<u8>, NamespaceName>,
    parent: &'a [u8],
    range: btree_map::Range<'a, Vec<u8>, NamespaceName>,
}

impl<'a> DirectChildren<'a> {
    fn new(namespace: &'a ValidatedNamespace, parent: &'a [u8]) -> Self {
        let names = namespace.names();
        let mut start = [0; MAX_PATH_BYTES + 1];
        start[..parent.len()].copy_from_slice(parent);
        let length = if parent.is_empty() {
            0
        } else {
            start[parent.len()] = b'/';
            parent.len() + 1
        };
        Self {
            names,
            parent,
            range: names.range::<[u8], _>((Included(&start[..length]), Unbounded)),
        }
    }
}

impl<'a> Iterator for DirectChildren<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (path, _) = self.range.next()?;
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
                bound[..end].copy_from_slice(&path[..end]);
                bound[end] = b'/' + 1;
                self.range = self
                    .names
                    .range::<[u8], _>((Included(&bound[..=end]), Unbounded));
                continue;
            }
            return Some(relative);
        }
    }
}

fn image_size(
    namespace: &ValidatedNamespace,
    layers: &[Option<ScopedPack<'_>>],
    minimum_size: u64,
) -> OciResult<u64> {
    let mut packs = PackFiles::default();
    let mut sizing = FormatSizing::new();
    let mut slots = [(b"".as_slice(), b"".as_slice()); MAX_XATTRS];
    let mut physical_ranges = Vec::new();
    for inode in namespace.inodes().values() {
        let (blocks, records) = match &inode.kind {
            NamespaceKind::Regular { body } => {
                let payload = payload(layers, body)?;
                if body.length != 0 && payload.sparse.is_empty() {
                    pack_ranges(
                        packs.file(body.entry.layer, layers)?,
                        body,
                        &mut physical_ranges,
                    )?;
                    allocated_blocks(&physical_ranges)?
                } else {
                    allocated_blocks(&payload.sparse)?
                }
            }
            NamespaceKind::Symlink { target } if target.len() >= 60 => {
                ((target.len() as u64).div_ceil(BLOCK_SIZE), 1)
            }
            _ => (0, 0),
        };
        let count = xattrs(&inode.metadata, &mut slots)?;
        sizing
            .add_inode(mode(inode)?, blocks, records, &slots[..count])
            .map_err(OciError::flat_ext4)?;
    }
    for (path, name) in namespace.names() {
        let inode = namespace
            .inodes()
            .get(&name.inode)
            .ok_or_else(|| invalid("namespace name has no live inode"))?;
        if matches!(inode.kind, NamespaceKind::Directory) {
            sizing
                .add_directory(DirectChildren::new(namespace, path))
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

#[derive(Default)]
struct PackFiles {
    current: Option<(u32, File)>,
}

impl PackFiles {
    fn file(&mut self, occurrence: u32, layers: &[Option<ScopedPack<'_>>]) -> OciResult<&mut File> {
        if self
            .current
            .as_ref()
            .is_none_or(|(index, _)| *index != occurrence)
        {
            let layer = layers
                .get(occurrence as usize)
                .and_then(Option::as_ref)
                .ok_or_else(|| invalid("namespace body has no retained payload pack"))?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(
                    nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits(),
                )
                .open(layer.pack_path())?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() != layer.pack_length() {
                return Err(invalid(
                    "private payload pack is not the admitted regular file",
                ));
            }
            self.current = Some((occurrence, file));
        }
        self.current
            .as_mut()
            .map(|(_, file)| file)
            .ok_or_else(|| invalid("retained payload pack was not opened"))
    }
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

enum BodyReader<'a> {
    Dense(std::io::Take<&'a mut File>),
    Sparse(StoredRanges<'a>),
}

/// The normalized pack is zero-expanded and seekable. Supply only admitted
/// stored ranges to the sparse encoder, rather than reading its logical holes.
struct StoredRanges<'a> {
    file: &'a mut File,
    pack_offset: u64,
    ranges: std::slice::Iter<'a, SparseRange>,
    remaining: u64,
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
            let offset = self.pack_offset.checked_add(range.offset).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "payload pack offset overflows",
                )
            })?;
            self.file.seek(SeekFrom::Start(offset))?;
            self.remaining = range.length;
        }
        let count = buffer
            .len()
            .min(self.remaining.min(usize::MAX as u64) as usize);
        let read = self.file.read(&mut buffer[..count])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "payload pack ended inside an admitted sparse range",
            ));
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

pub(crate) fn render(
    path: &Path,
    namespace: &ValidatedNamespace,
    layers: &[Option<ScopedPack<'_>>],
    minimum_size: u64,
) -> OciResult<()> {
    let size = image_size(namespace, layers, minimum_size)?;
    let mut formatter =
        Formatter::with_options(path, FormatOptions::new(size)).map_err(OciError::flat_ext4)?;
    // Formatting scaffolding is not part of the composed OCI namespace. An
    // explicitly supplied lost+found, of any admitted type, is rendered below.
    formatter
        .remove(b"/lost+found")
        .map_err(OciError::flat_ext4)?;
    let mut aliases = BTreeMap::new();
    let mut packs = PackFiles::default();
    let mut slots = [(b"".as_slice(), b"".as_slice()); MAX_XATTRS];
    let mut physical_ranges = Vec::new();
    for (path, name) in namespace.names() {
        let inode = namespace
            .inodes()
            .get(&name.inode)
            .ok_or_else(|| invalid("namespace name has no live inode"))?;
        if inode.link_count > 1 {
            if let Some(target) = aliases.get(&name.inode) {
                formatter
                    .link(path.as_slice(), *target)
                    .map_err(OciError::flat_ext4)?;
                continue;
            }
            aliases.insert(name.inode, path.as_slice());
        }
        let path = if path.is_empty() {
            b"/".as_slice()
        } else {
            path.as_slice()
        };
        let count = xattrs(&inode.metadata, &mut slots)?;
        let timestamps = Some(
            FileTimestamps::from_mtime(inode.metadata.mtime_seconds, inode.metadata.mtime_nanos)
                .map_err(OciError::flat_ext4)?,
        );
        let mut link = None;
        let mut device = None;
        let mut stored = None;
        let mut ranges = None;
        if let NamespaceKind::Symlink { target } = &inode.kind {
            link = Some(target.as_slice());
        }
        if let NamespaceKind::CharacterDevice { major, minor }
        | NamespaceKind::BlockDevice { major, minor } = &inode.kind
        {
            device = Some(DeviceId::new(*major, *minor).map_err(OciError::flat_ext4)?);
        }
        if let NamespaceKind::Regular { body } = &inode.kind {
            let payload = payload(layers, body)?;
            if body.length != 0 {
                let file = packs.file(body.entry.layer, layers)?;
                let source_ranges = if payload.sparse.is_empty() {
                    pack_ranges(file, body, &mut physical_ranges)?;
                    physical_ranges.as_slice()
                } else {
                    payload.sparse.as_slice()
                };
                stored = Some(
                    if matches!(source_ranges, [range] if range.offset == 0 && range.length == body.length)
                    {
                        file.seek(SeekFrom::Start(body.pack_offset))?;
                        BodyReader::Dense(file.take(body.length))
                    } else {
                        BodyReader::Sparse(StoredRanges {
                            file,
                            pack_offset: body.pack_offset,
                            ranges: source_ranges.iter(),
                            remaining: 0,
                        })
                    },
                );
                ranges = Some(source_ranges.iter().filter(|range| range.length != 0).map(
                    |range| FileRange {
                        offset: range.offset,
                        length: range.length,
                    },
                ));
            }
        }
        let data = match (&inode.kind, stored.as_mut(), ranges.as_mut()) {
            (NamespaceKind::Regular { body }, _, _) if body.length == 0 => None,
            (_, Some(BodyReader::Dense(reader)), _) => Some(FileData::Dense(reader)),
            (NamespaceKind::Regular { body }, Some(BodyReader::Sparse(reader)), Some(ranges)) => {
                Some(FileData::Sparse(SparseData {
                    reader,
                    length: body.length,
                    ranges,
                }))
            }
            (NamespaceKind::Regular { .. }, _, _) => {
                return Err(invalid("regular inode has no payload reader"))
            }
            _ => None,
        };
        formatter
            .create(
                path,
                mode(inode)?,
                link,
                timestamps,
                data,
                Some(inode.metadata.uid),
                Some(inode.metadata.gid),
                Some(&slots[..count]),
                device,
            )
            .map_err(OciError::flat_ext4)?;
        if matches!(&stored, Some(BodyReader::Dense(reader)) if reader.limit() != 0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "payload pack ended inside an admitted dense body",
            )
            .into());
        }
    }
    formatter.close().map_err(OciError::flat_ext4)
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
        assert_eq!(
            DirectChildren::new(&namespace, b"").collect::<Vec<_>>(),
            vec![b"a".as_slice(), b"a-", b"a0", b"b", b"raw-\xff"],
        );
        assert_eq!(
            DirectChildren::new(&namespace, b"a").collect::<Vec<_>>(),
            vec![b"x".as_slice()]
        );
        assert_eq!(
            DirectChildren::new(&namespace, b"a/x").collect::<Vec<_>>(),
            vec![b"z".as_slice()]
        );
    }

    #[test]
    fn retained_sparse_pack_reader_streams_only_stored_bytes_across_twelve_gibibyte_hole() {
        let temp = tempfile::tempdir().unwrap();
        let mut file = OpenOptions::new()
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
        let mut reader = StoredRanges {
            file: &mut file,
            pack_offset: 0,
            ranges: ranges.iter(),
            remaining: 0,
        };
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"AB");
        assert!(file.metadata().unwrap().blocks() * 512 < 1024 * 1024);
    }

    #[test]
    fn empty_normalized_map_clips_neighbor_allocations_without_expanding_the_hole() {
        let temp = tempfile::tempdir().unwrap();
        let mut file = OpenOptions::new()
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
        let mut reader = StoredRanges {
            file: &mut file,
            pack_offset: body.pack_offset,
            ranges: ranges.iter(),
            remaining: 0,
        };
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes.len() as u64, stored);
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "adjacent bytes outside the body never enter its stream"
        );
    }
}
