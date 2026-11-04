//! Pure OCI namespace composition. No host pathname or extraction APIs participate.
//!
//! Whiteout parents are resolved together against the untouched lower view,
//! then ordinary operations run in source order. Name bindings and live inodes
//! are separate, so replacing a hardlink target never changes existing aliases.
//! Body origins refer only to ordered layer occurrences and validated pack
//! extents; composition neither reads source blobs nor changes layer artifacts.
//! The live-name bound includes the root and all synthesized directories.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::changeset::{
    validate_layer, ChangeEntry, ChangesetError, ChangesetLimits, EntryKind, LayerChangeset,
    Metadata,
};

#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error(transparent)]
    Changeset(#[from] ChangesetError),
    #[error("parent is not a directory: {path:?}")]
    NotDirectory { path: Vec<u8> },
    #[error("dangling parent symlink at {path:?}")]
    DanglingParent { path: Vec<u8> },
    #[error("hardlink target is missing: {path:?}")]
    MissingHardlinkTarget { path: Vec<u8> },
    #[error("hardlink destination equals its resolved target: {path:?}")]
    SelfHardlink { path: Vec<u8> },
    #[error("hardlink target is a directory: {path:?}")]
    DirectoryHardlink { path: Vec<u8> },
    #[error("hardlink explicitly supplied xattr differs: {name:?}")]
    HardlinkMetadataMismatch { name: Vec<u8> },
}

type NamespaceResult<T> = Result<T, NamespaceError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InodeId(pub u64);

/// `layer` identifies an ordered occurrence, not a deduplicated layer result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryOrigin {
    pub layer: u32,
    pub ordinal: u64,
}

/// A validated extent in the zero-expanded logical payload pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyOrigin {
    pub entry: EntryOrigin,
    pub pack_offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceKind {
    Directory,
    Regular { body: BodyOrigin },
    Symlink { target: Vec<u8> },
    CharacterDevice { major: u32, minor: u32 },
    BlockDevice { major: u32, minor: u32 },
    Fifo,
    Socket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathProvenance {
    SyntheticRoot,
    SyntheticParent { entry: EntryOrigin },
    Explicit { entry: EntryOrigin },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceName {
    pub inode: InodeId,
    pub provenance: PathProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceInode {
    pub kind: NamespaceKind,
    pub metadata: Metadata,
    /// Number of names, not the host-specific directory st_nlink convention.
    pub link_count: u32,
    /// Original inode creation or explicit directory metadata origin.
    pub origin: Option<EntryOrigin>,
}

/// Names are sorted by raw bytes. The empty path names the merged root.
/// Unlinked inodes are reclaimed; storage is bounded by the live namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedNamespace {
    names: BTreeMap<Vec<u8>, NamespaceName>,
    inodes: BTreeMap<InodeId, NamespaceInode>,
}

impl ValidatedNamespace {
    pub fn names(&self) -> &BTreeMap<Vec<u8>, NamespaceName> {
        &self.names
    }

    pub fn inodes(&self) -> &BTreeMap<InodeId, NamespaceInode> {
        &self.inodes
    }

    pub fn inode_at(&self, path: &[u8]) -> Option<&NamespaceInode> {
        self.names
            .get(path)
            .and_then(|name| self.inodes.get(&name.inode))
    }
}

/// Compose reusable, parent-independent changesets in occurrence order.
/// Validation and all mutations are private until the complete tree succeeds.
pub fn compose(
    layers: &[&LayerChangeset],
    limits: &ChangesetLimits,
) -> NamespaceResult<ValidatedNamespace> {
    let mut composer = NamespaceComposer::new(limits)?;
    bound("composition layers", layers.len() as u64, limits.max_layers)?;
    for layer in layers {
        composer = composer.apply(layer)?;
    }
    Ok(composer.finish())
}

/// Owning incremental access to the same application kernel used by `compose`.
/// A failed application consumes the builder, so partially mutated state cannot
/// escape. Fresh flattening can discard each parsed layer as soon as it applies.
pub(crate) struct NamespaceComposer<'a> {
    inner: Composer<'a>,
    next_layer: u64,
}

impl<'a> NamespaceComposer<'a> {
    pub(crate) fn new(limits: &'a ChangesetLimits) -> NamespaceResult<Self> {
        limits.validate()?;
        let mut inner = Composer {
            tree: ValidatedNamespace {
                names: BTreeMap::new(),
                inodes: BTreeMap::new(),
            },
            next_inode: 0,
            limits,
            reclaimed: Vec::new(),
        };
        inner.create(
            Vec::new(),
            NamespaceKind::Directory,
            default_directory_metadata(),
            None,
            PathProvenance::SyntheticRoot,
        )?;
        Ok(Self {
            inner,
            next_layer: 0,
        })
    }

    pub(crate) fn apply(mut self, layer: &LayerChangeset) -> NamespaceResult<Self> {
        let count = self
            .next_layer
            .checked_add(1)
            .ok_or_else(|| invalid("layer occurrence count overflow"))?;
        bound("composition layers", count, self.inner.limits.max_layers)?;
        validate_layer(layer, self.inner.limits)?;
        let occurrence =
            u32::try_from(self.next_layer).map_err(|_| invalid("layer ordinal overflow"))?;
        self.inner.reclaimed.clear();
        self.inner.apply_layer(layer, occurrence)?;
        self.next_layer = count;
        Ok(self)
    }

    pub(crate) fn reclaimed_bodies(&self) -> &[BodyOrigin] {
        &self.inner.reclaimed
    }

    pub(crate) fn finish(self) -> ValidatedNamespace {
        self.inner.tree
    }
}

fn default_directory_metadata() -> Metadata {
    Metadata {
        uid: 0,
        gid: 0,
        mode: 0o755,
        mtime_seconds: 0,
        mtime_nanos: 0,
        xattrs: Vec::new(),
    }
}

fn invalid(message: &str) -> NamespaceError {
    ChangesetError::Invalid(message.to_owned()).into()
}

fn bound(resource: &'static str, actual: u64, maximum: u64) -> NamespaceResult<()> {
    if actual > maximum {
        return Err(ChangesetError::Limit {
            resource,
            actual,
            maximum,
        }
        .into());
    }
    Ok(())
}

struct Composer<'a> {
    tree: ValidatedNamespace,
    next_inode: u64,
    limits: &'a ChangesetLimits,
    reclaimed: Vec<BodyOrigin>,
}

#[derive(Clone, Copy)]
enum ParentMode {
    Create(EntryOrigin),
    Lookup,
}

struct Frame<'a> {
    bytes: Cow<'a, [u8]>,
    cursor: usize,
    symlink: bool,
}

impl Composer<'_> {
    fn inode(&self, path: &[u8]) -> NamespaceResult<Option<&NamespaceInode>> {
        self.tree
            .names
            .get(path)
            .map(|name| {
                self.tree
                    .inodes
                    .get(&name.inode)
                    .ok_or_else(|| invalid("namespace inode missing"))
            })
            .transpose()
    }

    fn apply_layer(&mut self, layer: &LayerChangeset, occurrence: u32) -> NamespaceResult<()> {
        // Resolve every marker before deleting anything. This is a snapshot view,
        // without copying the lower tree or keeping dead historical inodes.
        let mut deletions = BTreeSet::new();
        for entry in &layer.entries {
            if !matches!(entry.kind, EntryKind::Whiteout | EntryKind::Opaque) {
                continue;
            }
            let (parent, basename) = split_parent(&entry.path);
            let Some(mut path) = self.resolve_parent(parent, ParentMode::Lookup)? else {
                continue;
            };
            if matches!(entry.kind, EntryKind::Whiteout) {
                let target = basename
                    .strip_prefix(b".wh.")
                    .ok_or_else(|| invalid("invalid whiteout marker"))?;
                append_component(&mut path, target);
                self.check_path(&path)?;
                deletions.insert((path, false));
            } else {
                deletions.insert((path, true));
            }
        }
        for (path, children_only) in deletions {
            self.remove_tree(&path, children_only)?;
        }
        for entry in &layer.entries {
            if matches!(entry.kind, EntryKind::Whiteout | EntryKind::Opaque) {
                continue;
            }
            self.apply_entry(
                entry,
                EntryOrigin {
                    layer: occurrence,
                    ordinal: entry.ordinal,
                },
            )?;
        }
        Ok(())
    }

    fn apply_entry(&mut self, entry: &ChangeEntry, origin: EntryOrigin) -> NamespaceResult<()> {
        if matches!(entry.kind, EntryKind::RootDirectory) {
            let root = self
                .tree
                .names
                .get(b"".as_slice())
                .ok_or_else(|| invalid("namespace root missing"))?
                .inode;
            let inode = self
                .tree
                .inodes
                .get_mut(&root)
                .ok_or_else(|| invalid("namespace root inode missing"))?;
            inode.metadata = entry.metadata.clone();
            inode.origin = Some(origin);
            if let Some(name) = self.tree.names.get_mut(b"".as_slice()) {
                name.provenance = PathProvenance::Explicit { entry: origin };
            }
            return Ok(());
        }
        let (parent, basename) = split_parent(&entry.path);
        let mut path = self
            .resolve_parent(parent, ParentMode::Create(origin))?
            .ok_or_else(|| invalid("created parent is missing"))?;
        append_component(&mut path, basename);
        self.check_path(&path)?;
        if let EntryKind::Hardlink { target } = &entry.kind {
            return self.hardlink(path, target, entry, origin);
        }
        if matches!(entry.kind, EntryKind::Directory) {
            if let Some(name) = self.tree.names.get_mut(path.as_slice()) {
                let inode = self
                    .tree
                    .inodes
                    .get_mut(&name.inode)
                    .ok_or_else(|| invalid("directory inode missing"))?;
                if matches!(inode.kind, NamespaceKind::Directory) {
                    inode.metadata = entry.metadata.clone();
                    inode.origin = Some(origin);
                    name.provenance = PathProvenance::Explicit { entry: origin };
                    return Ok(());
                }
            }
        }
        let kind = match &entry.kind {
            EntryKind::Directory => NamespaceKind::Directory,
            EntryKind::Regular(body) => NamespaceKind::Regular {
                body: BodyOrigin {
                    entry: origin,
                    pack_offset: body.pack_offset,
                    length: body.length,
                },
            },
            EntryKind::Symlink { target } => NamespaceKind::Symlink {
                target: target.clone(),
            },
            EntryKind::CharacterDevice { major, minor } => NamespaceKind::CharacterDevice {
                major: *major,
                minor: *minor,
            },
            EntryKind::BlockDevice { major, minor } => NamespaceKind::BlockDevice {
                major: *major,
                minor: *minor,
            },
            EntryKind::Fifo => NamespaceKind::Fifo,
            EntryKind::Socket => NamespaceKind::Socket,
            _ => return Err(invalid("unexpected namespace operation")),
        };
        self.remove_tree(&path, false)?;
        self.create(
            path,
            kind,
            entry.metadata.clone(),
            Some(origin),
            PathProvenance::Explicit { entry: origin },
        )
    }

    fn hardlink(
        &mut self,
        path: Vec<u8>,
        target: &[u8],
        entry: &ChangeEntry,
        origin: EntryOrigin,
    ) -> NamespaceResult<()> {
        let (parent, basename) = split_parent(target);
        let Some(mut target_path) = self.resolve_parent(parent, ParentMode::Lookup)? else {
            return Err(NamespaceError::MissingHardlinkTarget {
                path: target.to_vec(),
            });
        };
        append_component(&mut target_path, basename);
        self.check_path(&target_path)?;
        if target_path == path {
            return Err(NamespaceError::SelfHardlink { path });
        }
        let target_id = self
            .tree
            .names
            .get(target_path.as_slice())
            .ok_or_else(|| NamespaceError::MissingHardlinkTarget {
                path: target_path.clone(),
            })?
            .inode;
        let inode = self
            .tree
            .inodes
            .get_mut(&target_id)
            .ok_or_else(|| invalid("hardlink inode missing"))?;
        if matches!(inode.kind, NamespaceKind::Directory) {
            return Err(NamespaceError::DirectoryHardlink { path: target_path });
        }
        for attr in &entry.metadata.xattrs {
            let explicit = match attr.name.as_slice() {
                b"system.posix_acl_access" => entry.presence.acl_access,
                b"system.posix_acl_default" => entry.presence.acl_default,
                _ => entry.presence.xattrs,
            };
            if explicit && !inode.metadata.xattrs.iter().any(|target| target == attr) {
                return Err(NamespaceError::HardlinkMetadataMismatch {
                    name: attr.name.clone(),
                });
            }
        }
        // Pin before unlinking: the target may itself be below the destination
        // directory being replaced. A name is not the inode's identity.
        inode.link_count = inode
            .link_count
            .checked_add(1)
            .ok_or_else(|| invalid("hardlink count overflow"))?;
        self.remove_tree(&path, false)?;
        let links = self
            .tree
            .inodes
            .get(&target_id)
            .ok_or_else(|| invalid("pinned inode missing"))?
            .link_count;
        bound(
            "hardlink names",
            u64::from(links),
            self.limits.max_hardlinks,
        )?;
        self.reserve_name()?;
        self.tree.names.insert(
            path,
            NamespaceName {
                inode: target_id,
                provenance: PathProvenance::Explicit { entry: origin },
            },
        );
        Ok(())
    }

    fn reserve_name(&self) -> NamespaceResult<()> {
        bound(
            "namespace entries",
            self.tree.names.len() as u64 + 1,
            self.limits.max_namespace_entries,
        )
    }

    fn create(
        &mut self,
        path: Vec<u8>,
        kind: NamespaceKind,
        metadata: Metadata,
        origin: Option<EntryOrigin>,
        provenance: PathProvenance,
    ) -> NamespaceResult<()> {
        self.reserve_name()?;
        let id = InodeId(self.next_inode);
        self.next_inode = self
            .next_inode
            .checked_add(1)
            .ok_or_else(|| invalid("inode identifier overflow"))?;
        self.tree.inodes.insert(
            id,
            NamespaceInode {
                kind,
                metadata,
                link_count: 1,
                origin,
            },
        );
        self.tree.names.insert(
            path,
            NamespaceName {
                inode: id,
                provenance,
            },
        );
        Ok(())
    }

    fn remove_name(&mut self, path: &[u8]) -> NamespaceResult<()> {
        let Some(name) = self.tree.names.remove(path) else {
            return Ok(());
        };
        let inode = self
            .tree
            .inodes
            .get_mut(&name.inode)
            .ok_or_else(|| invalid("unlinked inode missing"))?;
        inode.link_count = inode
            .link_count
            .checked_sub(1)
            .ok_or_else(|| invalid("inode name count underflow"))?;
        if inode.link_count == 0 {
            if let NamespaceKind::Regular { body } = &inode.kind {
                crate::changeset::limits::reserve_vec(&mut self.reclaimed, 1)?;
                self.reclaimed.push(*body);
            }
            self.tree.inodes.remove(&name.inode);
        }
        Ok(())
    }

    fn remove_tree(&mut self, path: &[u8], children_only: bool) -> NamespaceResult<()> {
        if !children_only {
            self.remove_name(path)?;
        }
        let mut prefix = path.to_vec();
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        loop {
            let next = self
                .tree
                .names
                .range::<[u8], _>((
                    std::ops::Bound::Included(prefix.as_slice()),
                    std::ops::Bound::Unbounded,
                ))
                .find(|(key, _)| !key.is_empty())
                .filter(|(key, _)| key.starts_with(&prefix))
                .map(|(key, _)| key.clone());
            let Some(next) = next else { break };
            self.remove_name(&next)?;
        }
        Ok(())
    }

    fn check_path(&self, path: &[u8]) -> NamespaceResult<()> {
        bound(
            "resolved path bytes",
            path.len() as u64,
            self.limits.max_path_bytes,
        )?;
        let mut depth = 0;
        for component in path
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty())
        {
            bound(
                "resolved component bytes",
                component.len() as u64,
                self.limits.max_component_bytes,
            )?;
            depth += 1;
        }
        bound("resolved path depth", depth, self.limits.max_depth)
    }

    fn check_expansion(&self, path: &[u8], frames: &[Frame<'_>]) -> NamespaceResult<()> {
        let mut bytes = path.len() as u64;
        let mut depth = if path.is_empty() {
            0
        } else {
            path.split(|byte| *byte == b'/').count() as u64
        };
        for frame in frames.iter().rev() {
            for component in frame.bytes[frame.cursor..]
                .split(|byte| *byte == b'/')
                .filter(|part| !part.is_empty())
            {
                bound(
                    "expanded component bytes",
                    component.len() as u64,
                    self.limits.max_component_bytes,
                )?;
                bytes += component.len() as u64 + u64::from(depth != 0);
                depth += 1;
            }
        }
        bound("expanded path bytes", bytes, self.limits.max_path_bytes)?;
        bound("expanded path depth", depth, self.limits.max_depth)
    }

    fn resolve_parent(
        &mut self,
        parent: &[u8],
        mode: ParentMode,
    ) -> NamespaceResult<Option<Vec<u8>>> {
        let mut path = Vec::new();
        let mut frames = vec![Frame {
            bytes: Cow::Borrowed(parent),
            cursor: 0,
            symlink: false,
        }];
        let mut hops = 0;
        while let Some(frame) = frames.last_mut() {
            let start = frame.cursor;
            if start == frame.bytes.len() {
                frames.pop();
                continue;
            }
            let end = match frame.bytes[start..].iter().position(|byte| *byte == b'/') {
                Some(relative) => start + relative,
                None => frame.bytes.len(),
            };
            frame.cursor = if end < frame.bytes.len() {
                end + 1
            } else {
                end
            };
            let component = &frame.bytes[start..end];
            if component.is_empty() || component == b"." {
                continue;
            }
            if component == b".." {
                pop_component(&mut path);
                continue;
            }
            let old_length = path.len();
            append_component(&mut path, component);
            self.check_path(&path)?;
            let through_symlink = frame.symlink;
            match self.inode(&path)? {
                Some(NamespaceInode {
                    kind: NamespaceKind::Directory,
                    ..
                }) => {}
                Some(NamespaceInode {
                    kind: NamespaceKind::Symlink { target },
                    ..
                }) => {
                    hops += 1;
                    bound("symlink hops", hops, self.limits.max_symlink_hops)?;
                    if target.is_empty() {
                        return Err(NamespaceError::DanglingParent { path });
                    }
                    let absolute = target.first() == Some(&b'/');
                    let target = target.clone();
                    path.truncate(if absolute { 0 } else { old_length });
                    frames.push(Frame {
                        bytes: Cow::Owned(target),
                        cursor: 0,
                        symlink: true,
                    });
                    self.check_expansion(&path, &frames)?;
                }
                Some(_) => return Err(NamespaceError::NotDirectory { path }),
                None if through_symlink => return Err(NamespaceError::DanglingParent { path }),
                None => match mode {
                    ParentMode::Lookup => return Ok(None),
                    ParentMode::Create(entry) => self.create(
                        path.clone(),
                        NamespaceKind::Directory,
                        default_directory_metadata(),
                        Some(entry),
                        PathProvenance::SyntheticParent { entry },
                    )?,
                },
            }
        }
        Ok(Some(path))
    }
}

fn split_parent(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(separator) => (&path[..separator], &path[separator + 1..]),
        None => (&[], path),
    }
}

fn append_component(path: &mut Vec<u8>, component: &[u8]) {
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(component);
}

fn pop_component(path: &mut Vec<u8>) {
    let length: usize = path
        .iter()
        .rposition(|byte| *byte == b'/')
        .unwrap_or_default();
    path.truncate(length);
}

#[cfg(test)]
mod tests {
    use crate::changeset::namespace::{
        compose, BodyOrigin, EntryOrigin, NamespaceComposer, NamespaceError, NamespaceKind,
        PathProvenance, ValidatedNamespace,
    };
    use crate::changeset::{
        ChangeEntry, ChangesetError, ChangesetLimits, ContentDigest, EntryKind, LayerChangeset,
        Metadata, MetadataPresence, PayloadRef, Xattr,
    };

    #[test]
    fn incremental_composition_reclaims_only_the_last_alias_and_matches_batch() {
        let limits = ChangesetLimits::default();
        let lower = layer(vec![file(b"target", 3), link(b"alias", b"target")]);
        let replace = layer(vec![file(b"target", 5)]);
        let delete_alias = layer(vec![whiteout(b".wh.alias")]);
        let delete_target = layer(vec![whiteout(b".wh.target")]);
        let composer = NamespaceComposer::new(&limits)
            .unwrap()
            .apply(&lower)
            .unwrap();
        assert!(composer.reclaimed_bodies().is_empty());
        let composer = composer.apply(&replace).unwrap();
        assert!(
            composer.reclaimed_bodies().is_empty(),
            "the old body still has an alias"
        );
        assert_eq!(
            composer.inner.tree,
            compose(&[&lower, &replace], &limits).unwrap()
        );
        let composer = composer.apply(&delete_alias).unwrap();
        assert_eq!(
            composer.reclaimed_bodies(),
            &[BodyOrigin {
                entry: EntryOrigin {
                    layer: 0,
                    ordinal: 0
                },
                pack_offset: 0,
                length: 3,
            }]
        );
        let composer = composer.apply(&delete_target).unwrap();
        assert_eq!(
            composer.reclaimed_bodies(),
            &[BodyOrigin {
                entry: EntryOrigin {
                    layer: 1,
                    ordinal: 0
                },
                pack_offset: 0,
                length: 5,
            }],
            "each application reports only that layer's newly dead bodies"
        );
        assert_eq!(
            composer.finish(),
            compose(&[&lower, &replace, &delete_alias, &delete_target], &limits).unwrap()
        );
    }

    #[test]
    fn incremental_composition_reports_replaced_bodies_from_the_current_occurrence() {
        let limits = ChangesetLimits::default();
        let source = layer(vec![file(b"d/child", 3), file(b"d", 5)]);
        let composer = NamespaceComposer::new(&limits)
            .unwrap()
            .apply(&source)
            .unwrap();
        assert_eq!(
            composer.reclaimed_bodies(),
            &[BodyOrigin {
                entry: EntryOrigin {
                    layer: 0,
                    ordinal: 0
                },
                pack_offset: 0,
                length: 3,
            }]
        );
        assert_eq!(composer.finish(), compose(&[&source], &limits).unwrap());
    }

    #[test]
    fn incremental_composition_enforces_the_existing_layer_occurrence_bound() {
        let limits = ChangesetLimits {
            max_layers: 1,
            ..ChangesetLimits::default()
        };
        let source = layer(vec![file(b"a", 1)]);
        let composer = NamespaceComposer::new(&limits)
            .unwrap()
            .apply(&source)
            .unwrap();
        assert!(matches!(
            composer.apply(&source),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "composition layers",
                actual: 2,
                maximum: 1,
            }))
        ));
    }

    fn metadata() -> Metadata {
        Metadata {
            uid: 12,
            gid: 34,
            mode: 0o644,
            mtime_seconds: 56,
            mtime_nanos: 789,
            xattrs: Vec::new(),
        }
    }

    fn entry(path: &[u8], kind: EntryKind) -> ChangeEntry {
        ChangeEntry {
            ordinal: 0,
            path: path.to_vec(),
            metadata: metadata(),
            presence: MetadataPresence::default(),
            kind,
        }
    }

    fn file(path: &[u8], length: u64) -> ChangeEntry {
        entry(
            path,
            EntryKind::Regular(PayloadRef {
                pack_offset: 0,
                length,
                sparse: Vec::new(),
            }),
        )
    }

    fn dir(path: &[u8]) -> ChangeEntry {
        entry(path, EntryKind::Directory)
    }
    fn symlink(path: &[u8], target: &[u8]) -> ChangeEntry {
        entry(
            path,
            EntryKind::Symlink {
                target: target.to_vec(),
            },
        )
    }
    fn link(path: &[u8], target: &[u8]) -> ChangeEntry {
        entry(
            path,
            EntryKind::Hardlink {
                target: target.to_vec(),
            },
        )
    }
    fn whiteout(path: &[u8]) -> ChangeEntry {
        entry(path, EntryKind::Whiteout)
    }
    fn opaque(path: &[u8]) -> ChangeEntry {
        entry(path, EntryKind::Opaque)
    }

    fn layer(mut entries: Vec<ChangeEntry>) -> LayerChangeset {
        let mut cursor = 0;
        for (ordinal, entry) in entries.iter_mut().enumerate() {
            entry.ordinal = ordinal as u64;
            if let EntryKind::Regular(body) = &mut entry.kind {
                body.pack_offset = cursor;
                cursor += body.length.div_ceil(4096) * 4096;
            }
        }
        LayerChangeset {
            diff_id: ContentDigest::of_bytes(b"namespace unit specimen"),
            pack_length: cursor,
            entries,
        }
    }

    fn tree(layers: &[&LayerChangeset]) -> ValidatedNamespace {
        compose(layers, &ChangesetLimits::default()).unwrap()
    }

    fn paths(tree: &ValidatedNamespace) -> Vec<&[u8]> {
        tree.names().keys().map(Vec::as_slice).collect()
    }

    fn body(tree: &ValidatedNamespace, path: &[u8]) -> BodyOrigin {
        match &tree.inode_at(path).unwrap().kind {
            NamespaceKind::Regular { body } => *body,
            other => panic!("not a regular file: {other:?}"),
        }
    }

    #[test]
    fn n01_empty_and_repeated_occurrences_keep_default_root() {
        let empty = layer(Vec::new());
        let tree = tree(&[&empty, &empty]);
        assert_eq!(paths(&tree), vec![b"".as_slice()]);
        let root = tree.inode_at(b"").unwrap();
        assert_eq!(
            (root.metadata.uid, root.metadata.gid, root.metadata.mode),
            (0, 0, 0o755)
        );
        assert_eq!(
            (root.metadata.mtime_seconds, root.metadata.mtime_nanos),
            (0, 0)
        );
        assert!(root.metadata.xattrs.is_empty());
        assert_eq!(
            tree.names()[b"".as_slice()].provenance,
            PathProvenance::SyntheticRoot
        );
        assert_eq!(empty.pack_length, 0);
    }

    #[test]
    fn n02_repeated_layer_replaces_by_occurrence() {
        let lower = layer(vec![file(b"a", 3)]);
        let upper = layer(vec![file(b"a", 7)]);
        let tree = tree(&[&lower, &upper, &upper]);
        assert_eq!(
            body(&tree, b"a"),
            BodyOrigin {
                entry: EntryOrigin {
                    layer: 2,
                    ordinal: 0
                },
                pack_offset: 0,
                length: 7
            }
        );
        assert_eq!(tree.inodes().len(), 2);
    }

    #[test]
    fn n03_n04_reverse_opaque_preserves_explicit_and_implicit_upper_ancestors() {
        let lower = layer(vec![file(b"a/b/c/bar", 1)]);
        for explicit in [false, true] {
            for reverse in [false, true] {
                let mut entries = Vec::new();
                if !reverse {
                    entries.push(opaque(b"a/.wh..wh..opq"));
                }
                if explicit {
                    entries.extend([dir(b"a"), dir(b"a/b"), dir(b"a/b/c")]);
                }
                entries.push(file(b"a/b/c/foo", 2));
                if reverse {
                    entries.push(opaque(b"a/.wh..wh..opq"));
                }
                let upper = layer(entries);
                let tree = tree(&[&lower, &upper]);
                assert_eq!(
                    paths(&tree),
                    vec![b"".as_slice(), b"a", b"a/b", b"a/b/c", b"a/b/c/foo"]
                );
                assert_eq!(body(&tree, b"a/b/c/foo").length, 2);
                assert_eq!(
                    tree.inode_at(b"a/b").unwrap().metadata.uid,
                    if explicit { 12 } else { 0 }
                );
            }
        }
        let lower = layer(vec![file(b"d/old", 1)]);
        for entries in [
            vec![file(b"d/new", 2), opaque(b"d/.wh..wh..opq")],
            vec![opaque(b"d/.wh..wh..opq"), file(b"d/new", 2)],
        ] {
            let upper = layer(entries);
            assert_eq!(
                paths(&tree(&[&lower, &upper])),
                vec![b"".as_slice(), b"d", b"d/new"]
            );
        }
    }

    #[test]
    fn root_opaque_removes_children_but_not_root_metadata() {
        let mut root = entry(b"", EntryKind::RootDirectory);
        root.metadata.uid = 99;
        let lower = layer(vec![root, file(b"a/b", 1)]);
        let upper = layer(vec![file(b"new", 2), opaque(b".wh..wh..opq")]);
        let tree = tree(&[&lower, &upper]);
        assert_eq!(paths(&tree), vec![b"".as_slice(), b"new"]);
        assert_eq!(tree.inode_at(b"").unwrap().metadata.uid, 99);
    }

    #[test]
    fn n05_reverse_explicit_whiteout_removes_only_lower_names() {
        let lower = layer(vec![file(b"a", 3)]);
        for entries in [
            vec![file(b"a", 4), whiteout(b".wh.a")],
            vec![whiteout(b".wh.a"), file(b"a", 4)],
        ] {
            let upper = layer(entries);
            let tree = tree(&[&lower, &upper]);
            assert_eq!(paths(&tree), vec![b"".as_slice(), b"a"]);
            assert_eq!(body(&tree, b"a").length, 4);
        }
    }

    #[test]
    fn n06_type_replacement_unlinks_descendants_and_never_follows_final_symlink() {
        let lower = layer(vec![file(b"d/child", 1), file(b"target", 2)]);
        for replacement in [file(b"d", 3), symlink(b"d", b"target")] {
            let upper = layer(vec![replacement]);
            let tree = tree(&[&lower, &upper]);
            assert_eq!(paths(&tree), vec![b"".as_slice(), b"d", b"target"]);
            assert_eq!(body(&tree, b"target").length, 2);
        }
        let lower = layer(vec![symlink(b"d", b"target"), file(b"target/child", 1)]);
        let upper = layer(vec![dir(b"d"), file(b"d/new", 2)]);
        let tree = tree(&[&lower, &upper]);
        assert!(matches!(
            tree.inode_at(b"d").unwrap().kind,
            NamespaceKind::Directory
        ));
        assert!(tree.inode_at(b"target/child").is_some());
        assert_eq!(body(&tree, b"d/new").length, 2);
    }

    #[test]
    fn n06_n07_directories_retain_children_and_explicit_metadata_wins() {
        let mut explicit = dir(b"p/q");
        explicit.metadata.uid = 7;
        explicit.metadata.mode = 0o700;
        explicit.metadata.mtime_seconds = 9;
        let upper = layer(vec![file(b"p/q/file", 1), explicit]);
        {
            let tree = tree(&[&upper]);
            let parent = tree.inode_at(b"p").unwrap();
            assert_eq!(
                (
                    parent.metadata.uid,
                    parent.metadata.gid,
                    parent.metadata.mode,
                    parent.metadata.mtime_seconds
                ),
                (0, 0, 0o755, 0)
            );
            let explicit = tree.inode_at(b"p/q").unwrap();
            assert_eq!(
                (
                    explicit.metadata.uid,
                    explicit.metadata.mode,
                    explicit.metadata.mtime_seconds
                ),
                (7, 0o700, 9)
            );
            assert!(tree.inode_at(b"p/q/file").is_some());
            assert_eq!(
                tree.names()[b"p".as_slice()].provenance,
                PathProvenance::SyntheticParent {
                    entry: EntryOrigin {
                        layer: 0,
                        ordinal: 0
                    }
                }
            );
            assert_eq!(
                tree.names()[b"p/q".as_slice()].provenance,
                PathProvenance::Explicit {
                    entry: EntryOrigin {
                        layer: 0,
                        ordinal: 1
                    }
                }
            );
        }
        let lower = layer(vec![dir(b"p"), file(b"p/old", 1)]);
        let upper = layer(vec![file(b"p/new", 1)]);
        let tree = tree(&[&lower, &upper]);
        assert_eq!(tree.inode_at(b"p").unwrap().metadata, metadata());
        assert!(tree.inode_at(b"p/old").is_some());
    }

    #[test]
    fn n08_n09_old_inode_survives_target_replacement_and_deletion() {
        let lower = layer(vec![file(b"a", 3)]);
        let upper = layer(vec![link(b"b", b"a"), link(b"c", b"b"), file(b"a", 7)]);
        let deletion = layer(vec![whiteout(b".wh.a")]);
        let before = tree(&[&lower, &upper]);
        assert_ne!(
            before.names()[b"a".as_slice()].inode,
            before.names()[b"b".as_slice()].inode
        );
        let tree = tree(&[&lower, &upper, &deletion]);
        assert_eq!(paths(&tree), vec![b"".as_slice(), b"b", b"c"]);
        assert_eq!(
            tree.names()[b"b".as_slice()].inode,
            tree.names()[b"c".as_slice()].inode
        );
        assert_eq!(tree.inode_at(b"b").unwrap().link_count, 2);
        assert_eq!(
            body(&tree, b"c"),
            BodyOrigin {
                entry: EntryOrigin {
                    layer: 0,
                    ordinal: 0
                },
                pack_offset: 0,
                length: 3
            }
        );
        assert_eq!(
            tree.names()[b"c".as_slice()].provenance,
            PathProvenance::Explicit {
                entry: EntryOrigin {
                    layer: 1,
                    ordinal: 1
                }
            }
        );
    }

    #[test]
    fn n10_n11_forward_missing_self_cycle_and_directory_links_fail_immediately() {
        for entries in [
            vec![link(b"b", b"a"), file(b"a", 1)],
            vec![link(b"a", b"b"), link(b"b", b"a")],
        ] {
            let layer = layer(entries);
            assert!(matches!(
                compose(&[&layer], &ChangesetLimits::default()),
                Err(NamespaceError::MissingHardlinkTarget { .. })
            ));
        }
        let lower = layer(vec![file(b"a", 1), dir(b"d")]);
        let upper = layer(vec![link(b"a", b"a")]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::SelfHardlink { .. })
        ));
        let upper = layer(vec![link(b"b", b"d")]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::DirectoryHardlink { .. })
        ));
    }

    #[test]
    fn n12_existing_alias_of_same_inode_is_not_self_link() {
        let lower = layer(vec![file(b"a", 1), link(b"b", b"a")]);
        let upper = layer(vec![link(b"b", b"a")]);
        let tree = tree(&[&lower, &upper]);
        assert_eq!(
            tree.names()[b"a".as_slice()].inode,
            tree.names()[b"b".as_slice()].inode
        );
        assert_eq!(tree.inode_at(b"a").unwrap().link_count, 2);
    }

    #[test]
    fn hardlink_binds_child_inode_before_replacing_its_parent_directory() {
        let lower = layer(vec![file(b"d/a", 5)]);
        let upper = layer(vec![link(b"d", b"d/a")]);
        let tree = tree(&[&lower, &upper]);
        assert_eq!(paths(&tree), vec![b"".as_slice(), b"d"]);
        assert_eq!(body(&tree, b"d").length, 5);
        assert_eq!(tree.inode_at(b"d").unwrap().link_count, 1);
    }

    #[test]
    fn n13_hardlink_final_symlink_is_not_followed_even_when_dangling() {
        let lower = layer(vec![symlink(b"s", b"missing")]);
        let upper = layer(vec![link(b"t", b"s")]);
        let tree = tree(&[&lower, &upper]);
        assert_eq!(
            tree.names()[b"s".as_slice()].inode,
            tree.names()[b"t".as_slice()].inode
        );
        assert_eq!(
            tree.inode_at(b"t").unwrap().kind,
            NamespaceKind::Symlink {
                target: b"missing".to_vec()
            }
        );
    }

    #[test]
    fn n14_n17_alias_collisions_apply_by_ordinal() {
        let lower = layer(vec![dir(b"usr/bin"), symlink(b"bin", b"usr/bin")]);
        for (entries, length) in [
            (vec![file(b"bin/x", 1), file(b"usr/bin/x", 2)], 2),
            (vec![file(b"usr/bin/x", 2), file(b"bin/x", 1)], 1),
        ] {
            let upper = layer(entries);
            let tree = tree(&[&lower, &upper]);
            assert_eq!(body(&tree, b"usr/bin/x").length, length);
            assert!(tree.inode_at(b"bin/x").is_none());
            assert!(matches!(
                tree.inode_at(b"bin").unwrap().kind,
                NamespaceKind::Symlink { .. }
            ));
        }
    }

    #[test]
    fn n15_absolute_relative_nested_and_root_clamped_targets() {
        let lower = layer(vec![
            dir(b"real/child"),
            symlink(b"a", b"/real"),
            symlink(b"real/b", b"child"),
            symlink(b"up", b"../../real"),
        ]);
        let upper = layer(vec![file(b"a/b/first", 1), file(b"up/second", 2)]);
        let tree = tree(&[&lower, &upper]);
        assert_eq!(body(&tree, b"real/child/first").length, 1);
        assert_eq!(body(&tree, b"real/second").length, 2);
    }

    #[test]
    fn n15_symlink_target_dotdot_is_not_lexically_collapsed() {
        let lower = layer(vec![
            dir(b"real/child"),
            symlink(b"x", b"real/child"),
            symlink(b"s", b"x/.."),
        ]);
        let upper = layer(vec![file(b"s/file", 1)]);
        let tree = tree(&[&lower, &upper]);
        assert!(tree.inode_at(b"real/file").is_some());
        assert!(tree.inode_at(b"file").is_none());
        let lower = layer(vec![symlink(b"s", b"missing/..")]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::DanglingParent { .. })
        ));
    }

    #[test]
    fn n15_exact_forty_hop_limit_and_loop_rejection() {
        let mut entries = vec![dir(b"d")];
        for index in 0..41 {
            let target = if index == 40 {
                b"d".to_vec()
            } else {
                format!("s{}", index + 1).into_bytes()
            };
            entries.push(symlink(format!("s{index}").as_bytes(), &target));
        }
        let lower = layer(entries);
        let accepted = layer(vec![file(b"s1/file", 1)]);
        assert!(tree(&[&lower, &accepted]).inode_at(b"d/file").is_some());
        let rejected = layer(vec![file(b"s0/file", 1)]);
        assert!(matches!(
            compose(&[&lower, &rejected], &ChangesetLimits::default()),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "symlink hops",
                actual: 41,
                maximum: 40
            }))
        ));
        let looped = layer(vec![symlink(b"loop", b"loop")]);
        let upper = layer(vec![file(b"loop/file", 1)]);
        assert!(matches!(
            compose(&[&looped, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "symlink hops",
                ..
            }))
        ));
    }

    #[test]
    fn n16_dangling_parent_is_not_repaired_but_ordinary_parent_is_created() {
        let lower = layer(vec![symlink(b"s", b"absent")]);
        let upper = layer(vec![file(b"s/child", 1)]);
        assert!(
            matches!(compose(&[&lower, &upper], &ChangesetLimits::default()), Err(NamespaceError::DanglingParent { path }) if path == b"absent")
        );
        let upper = layer(vec![file(b"absent/child", 1)]);
        assert!(tree(&[&lower, &upper]).inode_at(b"absent/child").is_some());
        let lower = layer(vec![file(b"notdir", 1)]);
        let upper = layer(vec![file(b"notdir/child", 1)]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::NotDirectory { .. })
        ));
    }

    #[test]
    fn n18_whiteout_parents_share_one_pre_layer_view() {
        let lower = layer(vec![
            file(b"old/x", 1),
            file(b"new/x", 2),
            symlink(b"d", b"old"),
        ]);
        // The first deletion removes the symlink used by the second marker.
        let upper = layer(vec![
            whiteout(b".wh.d"),
            whiteout(b"d/.wh.x"),
            symlink(b"d", b"new"),
        ]);
        let tree = tree(&[&lower, &upper]);
        assert!(tree.inode_at(b"old/x").is_none());
        assert!(tree.inode_at(b"new/x").is_some());
        assert_eq!(
            tree.inode_at(b"d").unwrap().kind,
            NamespaceKind::Symlink {
                target: b"new".to_vec()
            }
        );
    }

    #[test]
    fn n19_absent_whiteout_parent_does_not_synthesize_but_dangling_parent_fails() {
        let deletion = layer(vec![
            whiteout(b"absent/.wh.x"),
            whiteout(b".wh.absent"),
            opaque(b"other/.wh..wh..opq"),
        ]);
        assert_eq!(paths(&tree(&[&deletion])), vec![b"".as_slice()]);
        let lower = layer(vec![symlink(b"s", b"missing")]);
        let deletion = layer(vec![whiteout(b"s/.wh.x")]);
        assert!(matches!(
            compose(&[&lower, &deletion], &ChangesetLimits::default()),
            Err(NamespaceError::DanglingParent { .. })
        ));
    }

    #[test]
    fn m07_advisory_metadata_never_mutates_shared_inode_and_explicit_xattrs_must_agree() {
        let mut target = file(b"a", 1);
        target.metadata.xattrs.push(Xattr {
            name: b"user.binary".to_vec(),
            value: vec![0, 255, 10],
        });
        target.metadata.xattrs.push(Xattr {
            name: b"user.omitted".to_vec(),
            value: b"retained".to_vec(),
        });
        let target_metadata = target.metadata.clone();
        let lower = layer(vec![target]);
        let mut hardlink = link(b"b", b"a");
        hardlink.metadata.uid = 99;
        hardlink.metadata.mode = 0o777;
        hardlink.metadata.mtime_seconds = 123;
        hardlink.presence = MetadataPresence {
            uid: true,
            gid: true,
            mode: true,
            mtime: true,
            ..MetadataPresence::default()
        };
        let upper = layer(vec![hardlink.clone()]);
        let composed = tree(&[&lower, &upper]);
        assert_eq!(composed.inode_at(b"b").unwrap().metadata, target_metadata);
        hardlink.presence.xattrs = true;
        hardlink.metadata.xattrs = vec![target_metadata.xattrs[0].clone()];
        let upper = layer(vec![hardlink.clone()]);
        assert_eq!(
            tree(&[&lower, &upper]).inode_at(b"a").unwrap().metadata,
            target_metadata
        );
        hardlink.metadata.xattrs[0].value.push(1);
        let upper = layer(vec![hardlink]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::HardlinkMetadataMismatch { .. })
        ));
    }

    #[test]
    fn raw_byte_paths_and_special_inodes_are_neutral_facts() {
        let layer = layer(vec![
            file(b"\xff/file", 1),
            symlink(b"sym", b"\xfe"),
            entry(b"char", EntryKind::CharacterDevice { major: 1, minor: 3 }),
            entry(b"block", EntryKind::BlockDevice { major: 8, minor: 1 }),
            entry(b"fifo", EntryKind::Fifo),
            link(b"fifo2", b"fifo"),
            entry(b"socket", EntryKind::Socket),
        ]);
        let tree = tree(&[&layer]);
        assert!(tree.inode_at(b"\xff/file").is_some());
        assert_eq!(
            tree.inode_at(b"sym").unwrap().kind,
            NamespaceKind::Symlink { target: vec![254] }
        );
        assert_eq!(
            tree.inode_at(b"char").unwrap().kind,
            NamespaceKind::CharacterDevice { major: 1, minor: 3 }
        );
        assert_eq!(
            tree.inode_at(b"block").unwrap().kind,
            NamespaceKind::BlockDevice { major: 8, minor: 1 }
        );
        assert_eq!(tree.inode_at(b"fifo").unwrap().link_count, 2);
        assert_eq!(
            tree.inode_at(b"socket").unwrap().kind,
            NamespaceKind::Socket
        );
    }

    #[test]
    fn v11_occurrences_and_live_namespace_bounds_use_small_tightened_limits() {
        let empty = layer(Vec::new());
        let limits = ChangesetLimits {
            max_layers: 2,
            ..ChangesetLimits::default()
        };
        assert!(compose(&[&empty, &empty], &limits).is_ok());
        assert!(matches!(
            compose(&[&empty, &empty, &empty], &limits),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "composition layers",
                ..
            }))
        ));
        let limits = ChangesetLimits {
            max_namespace_entries: 3,
            ..ChangesetLimits::default()
        };
        let at = layer(vec![file(b"p/file", 1)]);
        assert_eq!(compose(&[&at], &limits).unwrap().names().len(), 3);
        let over = layer(vec![file(b"p/q/file", 1)]);
        assert!(matches!(
            compose(&[&over], &limits),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "namespace entries",
                ..
            }))
        ));
        let replacement = layer(vec![file(b"p", 2)]);
        let tree = compose(&[&at, &replacement], &limits).unwrap();
        assert_eq!(tree.names().len(), 2);
        assert_eq!(tree.inodes().len(), 2);
        let limits = ChangesetLimits {
            max_entries: 2,
            ..ChangesetLimits::default()
        };
        let at = layer(vec![file(b"a", 1), file(b"b", 1)]);
        assert!(compose(&[&at], &limits).is_ok());
        let over = layer(vec![file(b"a", 1), file(b"b", 1), file(b"c", 1)]);
        assert!(matches!(
            compose(&[&over], &limits),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "layer entries",
                actual: 3,
                maximum: 2
            }))
        ));
    }

    #[test]
    fn v11_actual_layer_occurrence_boundary_includes_repetitions() {
        let empty = layer(Vec::new());
        let mut occurrences = vec![&empty; 1024];
        assert!(compose(&occurrences, &ChangesetLimits::default()).is_ok());
        occurrences.push(&empty);
        assert!(matches!(
            compose(&occurrences, &ChangesetLimits::default()),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                actual: 1025,
                maximum: 1024,
                ..
            }))
        ));
    }

    #[test]
    fn v11_actual_depth_and_resolved_symlink_depth_boundaries() {
        let path = std::iter::repeat_n("d", 256).collect::<Vec<_>>().join("/");
        let at = layer(vec![file(path.as_bytes(), 1)]);
        assert!(tree(&[&at]).inode_at(path.as_bytes()).is_some());
        let over = layer(vec![file(format!("{path}/x").as_bytes(), 1)]);
        assert!(compose(&[&over], &ChangesetLimits::default()).is_err());
        let lower = layer(vec![dir(path.as_bytes()), symlink(b"s", path.as_bytes())]);
        let upper = layer(vec![file(b"s/x", 1)]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "resolved path depth",
                actual: 257,
                maximum: 256
            }))
        ));
    }

    #[test]
    fn v11_actual_path_and_component_boundaries_and_resolved_overflow() {
        let component = vec![b'x'; 255];
        let at = layer(vec![file(&component, 1)]);
        assert!(compose(&[&at], &ChangesetLimits::default()).is_ok());
        let over = layer(vec![file(&vec![b'x'; 256], 1)]);
        assert!(compose(&[&over], &ChangesetLimits::default()).is_err());
        let mut path = Vec::new();
        for _ in 0..16 {
            path.extend_from_slice(&component);
            path.push(b'/');
        }
        path.push(b'z');
        assert_eq!(path.len(), 4097);
        let over = layer(vec![file(&path, 1)]);
        assert!(compose(&[&over], &ChangesetLimits::default()).is_err());
        path.remove(0);
        let at = layer(vec![file(&path, 1)]);
        assert_eq!(path.len(), 4096);
        assert!(compose(&[&at], &ChangesetLimits::default()).is_ok());
        let lower = layer(vec![dir(&path), symlink(b"s", &path)]);
        let upper = layer(vec![file(b"s/x", 1)]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "resolved path bytes",
                ..
            }))
        ));
    }

    #[test]
    fn v12_hardlink_bound_counts_names_not_operations() {
        let limits = ChangesetLimits {
            max_hardlinks: 2,
            ..ChangesetLimits::default()
        };
        let lower = layer(vec![file(b"a", 1), link(b"b", b"a")]);
        let replacement = layer(vec![link(b"b", b"a")]);
        assert!(compose(&[&lower, &replacement], &limits).is_ok());
        let upper = layer(vec![link(b"c", b"a")]);
        assert!(matches!(
            compose(&[&lower, &upper], &limits),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "hardlink names",
                actual: 3,
                maximum: 2
            }))
        ));
        let deletion = layer(vec![whiteout(b".wh.b"), link(b"c", b"a")]);
        assert_eq!(
            compose(&[&lower, &deletion], &limits)
                .unwrap()
                .inode_at(b"a")
                .unwrap()
                .link_count,
            2
        );
    }

    #[test]
    fn v15_identical_reusable_artifact_composes_under_two_different_parents() {
        let first = layer(vec![file(b"a", 3), dir(b"one"), symlink(b"s", b"one")]);
        let second = layer(vec![file(b"a", 9), dir(b"two"), symlink(b"s", b"two")]);
        let upper = layer(vec![link(b"b", b"a"), file(b"s/child", 2)]);
        let retained_artifact = upper.clone();
        let first_tree = tree(&[&first, &upper]);
        let second_tree = tree(&[&second, &upper]);
        assert_eq!(upper, retained_artifact);
        assert_eq!(body(&first_tree, b"b").length, 3);
        assert_eq!(body(&second_tree, b"b").length, 9);
        assert!(first_tree.inode_at(b"one/child").is_some());
        assert!(second_tree.inode_at(b"two/child").is_some());
        assert_eq!(
            body(&first_tree, b"one/child"),
            body(&second_tree, b"two/child")
        );
    }

    #[test]
    fn m07_explicit_acl_presence_compares_values_without_clearing_omitted_acl() {
        let acl = |named_permission: u16| {
            let mut bytes = 2_u32.to_le_bytes().to_vec();
            for (tag, permission, id) in [
                (1_u16, 6_u16, u32::MAX),
                (2, named_permission, 42),
                (4, 4, u32::MAX),
                (16, 4, u32::MAX),
                (32, 4, u32::MAX),
            ] {
                bytes.extend(tag.to_le_bytes());
                bytes.extend(permission.to_le_bytes());
                bytes.extend(id.to_le_bytes());
            }
            Xattr {
                name: b"system.posix_acl_access".to_vec(),
                value: bytes,
            }
        };
        let mut target = file(b"a", 1);
        target.metadata.xattrs.push(acl(4));
        let lower = layer(vec![target]);
        let omitted = layer(vec![link(b"b", b"a")]);
        assert_eq!(
            tree(&[&lower, &omitted])
                .inode_at(b"b")
                .unwrap()
                .metadata
                .xattrs,
            vec![acl(4)]
        );
        let mut supplied = link(b"b", b"a");
        supplied.metadata.mode = 0o777;
        supplied.presence.acl_access = true;
        supplied.metadata.xattrs.push(acl(4));
        let equal = layer(vec![supplied.clone()]);
        assert!(compose(&[&lower, &equal], &ChangesetLimits::default()).is_ok());
        supplied.metadata.xattrs[0] = acl(2);
        let different = layer(vec![supplied]);
        assert!(matches!(
            compose(&[&lower, &different], &ChangesetLimits::default()),
            Err(NamespaceError::HardlinkMetadataMismatch { .. })
        ));
    }

    #[test]
    fn hardlink_targets_are_root_relative_and_their_parents_follow_symlinks() {
        let lower = layer(vec![
            file(b"a", 3),
            file(b"p/a", 9),
            dir(b"real"),
            symlink(b"s", b"real"),
        ]);
        let upper = layer(vec![
            link(b"p/b", b"a"),
            link(b"s/c", b"p/b"),
            link(b"other", b"s/c"),
        ]);
        let composed = tree(&[&lower, &upper]);
        for path in [b"p/b".as_slice(), b"real/c", b"other"] {
            assert_eq!(body(&composed, path).length, 3);
        }
        assert_eq!(composed.inode_at(b"a").unwrap().link_count, 4);
        let same_name = layer(vec![link(b"s/c", b"real/c")]);
        assert!(matches!(
            compose(&[&lower, &upper, &same_name], &ChangesetLimits::default()),
            Err(NamespaceError::SelfHardlink { .. })
        ));
    }

    #[test]
    fn v11_resolved_target_component_and_pending_expansion_are_bounded() {
        let lower = layer(vec![symlink(b"s", &vec![b'a'; 256])]);
        let upper = layer(vec![file(b"s/file", 1)]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "expanded component bytes",
                actual: 256,
                maximum: 255
            }))
        ));
        let lower = layer(vec![dir(b"a/b/c"), symlink(b"s", b"a/b/c")]);
        let upper = layer(vec![file(b"s/d/e", 1)]);
        let limits = ChangesetLimits {
            max_depth: 3,
            ..ChangesetLimits::default()
        };
        assert!(matches!(
            compose(&[&lower, &upper], &limits),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "expanded path depth",
                actual: 4,
                maximum: 3
            }))
        ));
    }

    #[test]
    fn v12_actual_64999_name_boundary_and_65000_rejection() {
        let mut entries = Vec::with_capacity(64_999);
        entries.push(file(b"a", 0));
        for index in 1..64_999 {
            entries.push(link(format!("n{index}").as_bytes(), b"a"));
        }
        let lower = layer(entries);
        let composed = tree(&[&lower]);
        assert_eq!(composed.inode_at(b"a").unwrap().link_count, 64_999);
        let upper = layer(vec![link(b"overflow", b"a")]);
        assert!(matches!(
            compose(&[&lower, &upper], &ChangesetLimits::default()),
            Err(NamespaceError::Changeset(ChangesetError::Limit {
                resource: "hardlink names",
                actual: 65_000,
                maximum: 64_999
            }))
        ));
    }
}
