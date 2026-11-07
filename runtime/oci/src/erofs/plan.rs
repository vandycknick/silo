use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::changeset::index::{encode_index_to, LayerRecipe};
use crate::changeset::limits::{reserve_vec, FORMAT_LIMITS};
use crate::changeset::namespace::{
    compose, BodyOrigin, InodeId, NamespaceInode, NamespaceKind, ValidatedNamespace,
};
use crate::changeset::{ContentDigest, EntryKind, Metadata, PayloadRef};
use crate::erofs::{
    add, align, invalid, u32_field, zero_region, DeviceRange, Layer, Result, BLOCK_SIZE,
    MAX_FSMETA_BYTES, MAX_LOWER_BYTES,
};

pub(crate) struct Record<'a> {
    pub id: InodeId,
    pub inode: &'a NamespaceInode,
    pub offset: u64,
    pub nid: u64,
    pub xattr_size: u64,
    pub index_start: u64,
    pub end: u64,
    pub size: u64,
    pub data: u64,
    pub nlink: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct DirItem<'a> {
    pub name: &'a [u8],
    pub id: InodeId,
    pub file_type: u8,
}

pub(crate) struct Plan<'a> {
    pub records: Vec<Record<'a>>,
    pub positions: BTreeMap<InodeId, usize>,
    pub children: BTreeMap<InodeId, Vec<DirItem<'a>>>,
    pub parents: BTreeMap<InodeId, InodeId>,
    pub meta: u64,
    pub data_start: u64,
    pub length: u64,
    pub uuid: [u8; 16],
    pub ranges: Vec<DeviceRange>,
}

impl<'a> Plan<'a> {
    pub fn new(
        namespace: &'a ValidatedNamespace,
        layers: &[Layer<'_>],
        recipe_id: &str,
    ) -> Result<Self> {
        // Parsing enforces the fixed lowercase ASCII spelling used by UUID v8.
        let _: ContentDigest = recipe_id.parse()?;
        if layers.len() as u64 > FORMAT_LIMITS.max_layers {
            return Err(invalid("too many layer occurrences"));
        }
        let mut sources = Vec::new();
        reserve_vec(&mut sources, layers.len())?;
        let mut pack_bytes = 0;
        for layer in layers {
            layer.result.canonical_bytes()?;
            let root = encode_index_to(layer.changeset, &FORMAT_LIMITS, |_| Ok(()))?;
            if layer.result.recipe
                != (LayerRecipe {
                    diff_id: layer.changeset.diff_id,
                })
                .id()?
                || root.digest != layer.result.index_root
                || layer.result.pack_length != layer.changeset.pack_length
                || layer.pack.metadata()?.len() != layer.result.pack_length
            {
                return Err(invalid("layer result, index or exact pack length mismatch"));
            }
            pack_bytes = add(pack_bytes, layer.result.pack_length)?;
            if pack_bytes > MAX_LOWER_BYTES {
                return Err(invalid("logical lower exceeds 1 TiB"));
            }
            validate_pack(layer)?;
            sources.push(layer.changeset);
        }
        if compose(&sources, &FORMAT_LIMITS)? != *namespace {
            return Err(invalid(
                "namespace does not derive from supplied layer occurrences",
            ));
        }
        let root = namespace
            .names()
            .get(b"".as_slice())
            .ok_or_else(|| invalid("missing root"))?
            .inode;
        let mut children: BTreeMap<InodeId, Vec<DirItem<'a>>> = BTreeMap::new();
        let mut parents = BTreeMap::new();
        parents.insert(root, root);
        for (path, name) in namespace.names() {
            if path.is_empty() {
                continue;
            }
            let split = path.iter().rposition(|b| *b == b'/');
            let (parent_path, basename) = match split {
                Some(at) => (&path[..at], &path[at + 1..]),
                None => (b"".as_slice(), path.as_slice()),
            };
            let parent = namespace
                .names()
                .get(parent_path)
                .ok_or_else(|| invalid("missing parent"))?
                .inode;
            let inode = namespace
                .inodes()
                .get(&name.inode)
                .ok_or_else(|| invalid("missing inode"))?;
            let list = children.entry(parent).or_default();
            reserve_vec(list, 1)?;
            list.push(DirItem {
                name: basename,
                id: name.inode,
                file_type: file_type(&inode.kind),
            });
            if matches!(inode.kind, NamespaceKind::Directory)
                && parents.insert(name.inode, parent).is_some()
            {
                return Err(invalid("directory has multiple parents"));
            }
        }
        for list in children.values_mut() {
            list.sort_unstable_by(|a, b| a.name.cmp(b.name));
        }
        let meta = add(BLOCK_SIZE, align(layers.len() as u64 * 128, BLOCK_SIZE)?)?;
        let mut plan = Self {
            records: Vec::new(),
            positions: BTreeMap::new(),
            children,
            parents,
            meta,
            data_start: 0,
            length: 0,
            uuid: uuid(recipe_id),
            ranges: Vec::new(),
        };
        let mut pending = vec![root];
        let mut visited = BTreeSet::new();
        let mut offset = meta;
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            let inode = namespace
                .inodes()
                .get(&id)
                .ok_or_else(|| invalid("missing inode"))?;
            let xattr_size = xattr_size(&inode.metadata)?;
            let index_start = align(add(add(offset, 64)?, xattr_size)?, 8)?;
            let size = match &inode.kind {
                NamespaceKind::Regular { body } => {
                    payload(layers, body)?;
                    body.length
                }
                NamespaceKind::Directory => directory_size(plan.directory(id)?)?,
                NamespaceKind::Symlink { target } => target.len() as u64,
                _ => 0,
            };
            let end = align(
                match inode.kind {
                    NamespaceKind::Regular { .. } => {
                        add(index_start, size.div_ceil(BLOCK_SIZE) * 8)?
                    }
                    _ => add(add(offset, 64)?, xattr_size)?,
                },
                32,
            )?;
            if end > MAX_FSMETA_BYTES {
                return Err(invalid("fsmeta exceeds 4 GiB"));
            }
            let nlink = if matches!(inode.kind, NamespaceKind::Directory) {
                u32_field(
                    2 + plan
                        .children
                        .get(&id)
                        .map_or(0, |v| v.iter().filter(|c| c.file_type == 2).count() as u64),
                )?
            } else {
                inode.link_count
            };
            plan.positions.insert(id, plan.records.len());
            reserve_vec(&mut plan.records, 1)?;
            plan.records.push(Record {
                id,
                inode,
                offset,
                nid: (offset - meta) / 32,
                xattr_size,
                index_start,
                end,
                size,
                data: 0,
                nlink,
            });
            if matches!(inode.kind, NamespaceKind::Directory) {
                if let Some(list) = plan.children.get(&id) {
                    reserve_vec(&mut pending, list.len())?;
                    pending.extend(list.iter().rev().map(|c| c.id));
                }
            }
            offset = end;
        }
        if plan.records.len() != namespace.inodes().len() {
            return Err(invalid("unreachable inode"));
        }
        plan.data_start = align(offset, BLOCK_SIZE)?;
        offset = plan.data_start;
        for record in &mut plan.records {
            if matches!(
                record.inode.kind,
                NamespaceKind::Directory | NamespaceKind::Symlink { .. }
            ) {
                record.data = offset;
                offset = add(offset, align(record.size, BLOCK_SIZE)?)?;
            }
        }
        if offset > MAX_FSMETA_BYTES || add(offset, pack_bytes)? > MAX_LOWER_BYTES {
            return Err(invalid("fsmeta or logical lower exceeds format bounds"));
        }
        plan.length = offset;
        reserve_vec(&mut plan.ranges, layers.len())?;
        for layer in layers {
            plan.ranges.push(DeviceRange {
                stream: layer.result.pack_stream,
                offset,
                length: layer.result.pack_length,
            });
            offset = add(offset, layer.result.pack_length)?;
        }
        Ok(plan)
    }

    pub fn record(&self, id: InodeId) -> Result<&Record<'a>> {
        self.positions
            .get(&id)
            .and_then(|at| self.records.get(*at))
            .ok_or_else(|| invalid("unknown inode reference"))
    }

    pub fn directory(&self, id: InodeId) -> Result<Directory<'_>> {
        let parent = *self
            .parents
            .get(&id)
            .ok_or_else(|| invalid("missing directory parent"))?;
        Ok(Directory {
            children: self.children.get(&id).map_or(&[], Vec::as_slice),
            next: 0,
            dot: Some(id),
            dotdot: Some(parent),
        })
    }
}

/// Merge dots with byte-sorted children: `!` legitimately precedes `.`.
#[derive(Clone)]
pub(crate) struct Directory<'a> {
    children: &'a [DirItem<'a>],
    next: usize,
    dot: Option<InodeId>,
    dotdot: Option<InodeId>,
}
impl<'a> Iterator for Directory<'a> {
    type Item = DirItem<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let dot = self
            .dot
            .map(|id| DirItem {
                name: b".".as_slice(),
                id,
                file_type: 2,
            })
            .or_else(|| {
                self.dotdot.map(|id| DirItem {
                    name: b"..".as_slice(),
                    id,
                    file_type: 2,
                })
            });
        let child = self.children.get(self.next).copied();
        if let Some(entry) = child {
            if dot.is_none_or(|d| entry.name < d.name) {
                self.next += 1;
                return Some(entry);
            }
        }
        if self.dot.take().is_some() {
            return dot;
        }
        if self.dotdot.take().is_some() {
            return dot;
        }
        None
    }
}

pub(crate) fn directory_group(entries: Directory<'_>) -> (usize, usize) {
    let mut count = 0;
    let mut used = 0;
    for entry in entries {
        let next = used + 12 + entry.name.len();
        if next > BLOCK_SIZE as usize {
            break;
        }
        used = next;
        count += 1;
    }
    (count, used)
}

fn directory_size(mut entries: Directory<'_>) -> Result<u64> {
    let mut size = 0;
    loop {
        let (count, used) = directory_group(entries.clone());
        if count == 0 {
            return Err(invalid("empty directory block"));
        }
        for _ in 0..count {
            entries.next();
        }
        if entries.clone().next().is_none() {
            return add(size, used as u64);
        }
        size = add(size, BLOCK_SIZE)?;
    }
}

pub(crate) fn file_type(kind: &NamespaceKind) -> u8 {
    match kind {
        NamespaceKind::Regular { .. } => 1,
        NamespaceKind::Directory => 2,
        NamespaceKind::CharacterDevice { .. } => 3,
        NamespaceKind::BlockDevice { .. } => 4,
        NamespaceKind::Fifo => 5,
        NamespaceKind::Socket => 6,
        NamespaceKind::Symlink { .. } => 7,
    }
}

pub(crate) fn mode(inode: &NamespaceInode) -> u16 {
    let kind = match inode.kind {
        NamespaceKind::Regular { .. } => 0o100000,
        NamespaceKind::Directory => 0o040000,
        NamespaceKind::Symlink { .. } => 0o120000,
        NamespaceKind::CharacterDevice { .. } => 0o020000,
        NamespaceKind::BlockDevice { .. } => 0o060000,
        NamespaceKind::Fifo => 0o010000,
        NamespaceKind::Socket => 0o140000,
    };
    kind | inode.metadata.mode as u16
}

pub(crate) fn inode_union(record: &Record<'_>) -> Result<u32> {
    Ok(match record.inode.kind {
        NamespaceKind::Regular { .. } => 0x20,
        NamespaceKind::Directory | NamespaceKind::Symlink { .. } => {
            u32_field(record.data / BLOCK_SIZE)?
        }
        NamespaceKind::CharacterDevice { major, minor }
        | NamespaceKind::BlockDevice { major, minor } => {
            (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
        }
        _ => 0,
    })
}

pub(crate) fn xattr_name(name: &[u8]) -> Result<(u8, &[u8])> {
    if name == b"system.posix_acl_access" {
        return Ok((2, b""));
    }
    if name == b"system.posix_acl_default" {
        return Ok((3, b""));
    }
    for (prefix, index) in [
        (b"user.".as_slice(), 1),
        (b"trusted.".as_slice(), 4),
        (b"security.".as_slice(), 6),
    ] {
        if let Some(suffix) = name.strip_prefix(prefix) {
            return Ok((index, suffix));
        }
    }
    Err(invalid("unsupported xattr namespace"))
}

fn xattr_size(metadata: &Metadata) -> Result<u64> {
    if metadata.xattrs.is_empty() {
        return Ok(0);
    }
    let mut size = 12;
    for attr in &metadata.xattrs {
        let (_, suffix) = xattr_name(&attr.name)?;
        if suffix.len() > u8::MAX as usize || attr.value.len() > u16::MAX as usize {
            return Err(invalid("xattr field overflow"));
        }
        size = add(
            size,
            align(4 + suffix.len() as u64 + attr.value.len() as u64, 4)?,
        )?;
    }
    if size > 3072 {
        return Err(invalid("inline xattr body exceeds 3072 bytes"));
    }
    Ok(size)
}

pub(crate) fn payload<'a>(
    layers: &'a [Layer<'_>],
    body: &BodyOrigin,
) -> Result<(&'a File, &'a PayloadRef)> {
    let layer = layers
        .get(body.entry.layer as usize)
        .ok_or_else(|| invalid("unknown body occurrence"))?;
    let entry = layer
        .changeset
        .entries
        .get(usize::try_from(body.entry.ordinal).map_err(|_| invalid("body ordinal overflow"))?)
        .ok_or_else(|| invalid("unknown original body ordinal"))?;
    let EntryKind::Regular(expected) = &entry.kind else {
        return Err(invalid("body origin does not own a regular payload"));
    };
    if expected.pack_offset != body.pack_offset || expected.length != body.length {
        return Err(invalid("body does not match original payload ownership"));
    }
    Ok((layer.pack, expected))
}

use std::fs::File;
fn validate_pack(layer: &Layer<'_>) -> Result<()> {
    for entry in &layer.changeset.entries {
        let EntryKind::Regular(body) = &entry.kind else {
            continue;
        };
        let end = add(body.pack_offset, body.length)?;
        let padded = add(body.pack_offset, align(body.length, BLOCK_SIZE)?)?;
        if padded > layer.result.pack_length {
            return Err(invalid("body exceeds pack"));
        }
        if !body.sparse.is_empty() {
            let mut cursor = 0;
            for range in &body.sparse {
                zero_region(
                    layer.pack,
                    add(body.pack_offset, cursor)?,
                    add(body.pack_offset, range.offset)?,
                )?;
                cursor = add(range.offset, range.length)?;
            }
            zero_region(layer.pack, add(body.pack_offset, cursor)?, end)?;
        }
        zero_region(layer.pack, end, padded)?;
    }
    Ok(())
}

fn uuid(recipe: &str) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"silo-erofs-uuid-v1\n");
    hash.update(recipe.as_bytes());
    let digest = hash.finalize();
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}
