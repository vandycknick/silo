//! Merge the exact lower namespace with an audited upper, as the admitted
//! OverlayFS profile presents it to the guest.
//!
//! ```text
//!  upper fs root ─┬─ upper/  merged root; origin = lower root
//!                 ├─ work/
//!                 │   ├─ work/   kernel scratch, discarded at mount
//!                 │   └─ index/  <hex(origin handle)> ─hardlink─► copied-up inode
//!                 └─ lost+found  (empty)
//! ```
//!
//! For each merged directory the upper entries win: a 0:0 character device
//! hides the name, an upper non-directory shadows any lower name, an upper
//! directory merges with the lower directory at the same path unless opaque.
//! Lower names without an upper entry stay visible; a lower non-directory
//! whose inode has an index entry resolves to that index inode, which is how
//! every surviving alias of a modified lower hardlink exposes the copy. The
//! persistent overlay link count of each index inode must equal the visible
//! names found here, otherwise the next mount would disagree with this tree.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

use disk_image::ext4::constants::ROOT_INODE;
use disk_image::ext4::file_tree::InodeNumber;
use disk_image::ext4::reader::{DirEntry, InodeKind, InodeMetadata};
use disk_image::ext4::Reader;

use crate::changeset::limits::FORMAT_LIMITS;
use crate::changeset::namespace::{InodeId, NamespaceInode, NamespaceKind, ValidatedNamespace};
use crate::changeset::{Metadata, Xattr};
use crate::erofs::handles::{ExportHandles, FidEncoding};
use crate::flat_ext4::{Body, DirectChildren, Kind, Node, RenderTree, MAX_PATH_BYTES};
use crate::overlay_flatten::handle;
use crate::overlay_flatten::{check_cancel, FlattenError, OverlayRefusal};
use crate::OciResult;

const OVERLAY_PREFIX: &[u8] = b"trusted.overlay.";

fn refuse(path: &[u8], reason: impl Into<Cow<'static, str>>) -> FlattenError {
    OverlayRefusal::new(path, reason).into()
}

/// Upper filesystem path for diagnostics.
fn upper_path(prefix: &[u8], merged: &[u8]) -> Vec<u8> {
    let mut path = prefix.to_vec();
    if !merged.is_empty() {
        path.push(b'/');
        path.extend_from_slice(merged);
    }
    path
}

fn is_whiteout(kind: &InodeKind) -> bool {
    matches!(kind, InodeKind::CharacterDevice(device) if device.major() == 0 && device.minor() == 0)
}

fn same_type(upper: &InodeKind, lower: &NamespaceKind) -> bool {
    matches!(
        (upper, lower),
        (InodeKind::Regular, NamespaceKind::Regular { .. })
            | (InodeKind::Directory, NamespaceKind::Directory)
            | (InodeKind::Symlink, NamespaceKind::Symlink { .. })
            | (
                InodeKind::CharacterDevice(_),
                NamespaceKind::CharacterDevice { .. }
            )
            | (InodeKind::BlockDevice(_), NamespaceKind::BlockDevice { .. })
            | (InodeKind::Fifo, NamespaceKind::Fifo)
            | (InodeKind::Socket, NamespaceKind::Socket)
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Directory,
    NonDirectory,
}

/// Admitted OverlayFS control xattrs of one upper inode; everything else in
/// `trusted.overlay.` (redirect, metacopy, protattr, uuid, xwhiteout, escaped
/// guest attributes, future names) is refused.
#[derive(Default)]
struct Controls {
    origin: Option<Vec<u8>>,
    nlink: Option<Vec<u8>>,
    opaque: bool,
}

fn split_controls(
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    role: Role,
    path: &[u8],
) -> Result<(Controls, Vec<Xattr>), FlattenError> {
    let mut controls = Controls::default();
    let mut visible = Vec::new();
    for (name, value) in xattrs {
        let Some(suffix) = name.strip_prefix(OVERLAY_PREFIX) else {
            crate::changeset::limits::reserve_vec(&mut visible, 1)
                .map_err(|error| refuse(path, error.to_string()))?;
            visible.push(Xattr { name, value });
            continue;
        };
        match (suffix, role) {
            (b"origin", _) if value.is_empty() => {
                return Err(refuse(path, "copy-up origin is recorded as unknown"));
            }
            (b"origin", _) => controls.origin = Some(value),
            (b"nlink", Role::NonDirectory) => controls.nlink = Some(value),
            (b"opaque", Role::Directory) if value == b"y" => controls.opaque = true,
            (b"impure", Role::Directory) if value == b"y" => {}
            (b"redirect", _) => {
                return Err(refuse(path, "redirects are outside redirect_dir=nofollow"));
            }
            (b"metacopy", _) => {
                return Err(refuse(
                    path,
                    "metadata-only copy-up is outside metacopy=off",
                ));
            }
            (b"protattr", _) => {
                return Err(refuse(
                    path,
                    "overlay-protected inode attributes are not representable",
                ));
            }
            (suffix, _) if suffix.starts_with(b"overlay.") => {
                return Err(refuse(
                    path,
                    "escaped guest trusted.overlay attributes are reserved",
                ));
            }
            _ => {
                return Err(refuse(
                    path,
                    format!(
                        "unadmitted overlay control {}",
                        String::from_utf8_lossy(&name)
                    ),
                ));
            }
        }
    }
    Ok((controls, visible))
}

/// Visible metadata must be exactly representable by the shared namespace
/// writer and pass the same admission as OCI-derived metadata.
fn upper_metadata(
    meta: &InodeMetadata,
    xattrs: Vec<Xattr>,
    directory: bool,
    path: &[u8],
) -> Result<Metadata, FlattenError> {
    if meta.flags != 0 {
        return Err(refuse(
            path,
            "inode attribute flags are not representable in the flattened namespace",
        ));
    }
    if meta.projid != 0 {
        return Err(refuse(path, "project quota identity is not representable"));
    }
    let mtime_seconds = u64::try_from(meta.mtime.seconds)
        .map_err(|_| refuse(path, "modification time precedes the epoch"))?;
    let metadata = Metadata {
        uid: meta.uid,
        gid: meta.gid,
        mode: u32::from(meta.permissions),
        mtime_seconds,
        mtime_nanos: meta.mtime.nanos,
        xattrs,
    };
    crate::changeset::metadata::validate_metadata(&metadata, directory, &FORMAT_LIMITS).map_err(
        |error| {
            refuse(
                path,
                format!("visible metadata is outside the admitted profile: {error}"),
            )
        },
    )?;
    Ok(metadata)
}

enum UpperContent {
    Directory,
    Regular,
    Symlink(Vec<u8>),
    CharacterDevice { major: u32, minor: u32 },
    BlockDevice { major: u32, minor: u32 },
    Fifo,
    Socket,
}

enum MergedInode<'l> {
    Lower {
        inode: &'l NamespaceInode,
        link_count: u32,
    },
    Upper {
        number: InodeNumber,
        content: UpperContent,
        metadata: Metadata,
        link_count: u32,
    },
}

impl MergedInode<'_> {
    fn link_count_mut(&mut self) -> &mut u32 {
        match self {
            Self::Lower { link_count, .. } | Self::Upper { link_count, .. } => link_count,
        }
    }

    fn link_count(&self) -> u32 {
        match self {
            Self::Lower { link_count, .. } | Self::Upper { link_count, .. } => *link_count,
        }
    }

    fn node(&self) -> Node<'_> {
        match self {
            Self::Lower { inode, link_count } => {
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
                    link_count: *link_count,
                }
            }
            Self::Upper {
                number,
                content,
                metadata,
                link_count,
            } => Node {
                kind: match content {
                    UpperContent::Directory => Kind::Directory,
                    UpperContent::Regular => Kind::Regular(Body::Upper(*number)),
                    UpperContent::Symlink(target) => Kind::Symlink(target),
                    UpperContent::CharacterDevice { major, minor } => Kind::CharacterDevice {
                        major: *major,
                        minor: *minor,
                    },
                    UpperContent::BlockDevice { major, minor } => Kind::BlockDevice {
                        major: *major,
                        minor: *minor,
                    },
                    UpperContent::Fifo => Kind::Fifo,
                    UpperContent::Socket => Kind::Socket,
                },
                metadata,
                link_count: *link_count,
            },
        }
    }
}

/// The guest-visible namespace, ready for the shared fresh-ext4 writer.
pub(crate) struct MergedTree<'l> {
    names: BTreeMap<Vec<u8>, InodeId>,
    inodes: BTreeMap<InodeId, MergedInode<'l>>,
}

impl RenderTree for MergedTree<'_> {
    type Name = InodeId;

    fn render_names(&self) -> &BTreeMap<Vec<u8>, InodeId> {
        &self.names
    }

    fn render_inode(name: &InodeId) -> InodeId {
        *name
    }

    fn render_node(&self, id: InodeId) -> OciResult<Node<'_>> {
        self.inodes.get(&id).map(MergedInode::node).ok_or_else(|| {
            crate::changeset::ChangesetError::Invalid("merged name has no inode".into()).into()
        })
    }

    fn render_nodes(&self) -> impl Iterator<Item = Node<'_>> {
        self.inodes.values().map(MergedInode::node)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Identity {
    Lower(InodeId),
    Upper(InodeNumber),
}

struct IndexEntry {
    inode: InodeNumber,
    name: Vec<u8>,
    nlink: Option<Vec<u8>>,
}

struct Frame {
    path: Vec<u8>,
    upper: Option<InodeNumber>,
    /// The lower directory at `path` participates (merged or lower-only).
    lower: bool,
}

/// Located upper layout: `None` index means the overlay was never mounted.
struct Layout {
    upper: InodeNumber,
    index: Option<InodeNumber>,
}

struct Merger<'l, 'r> {
    lower: &'l ValidatedNamespace,
    handles: &'l ExportHandles,
    reader: &'r Reader,
    cancel: &'r AtomicBool,
    encoding: Option<FidEncoding>,
    /// Lower hardlinked inode -> index entry (non-directory, link count > 1).
    index: BTreeMap<InodeId, IndexEntry>,
    index_inodes: BTreeMap<InodeNumber, InodeId>,
    identities: BTreeMap<Identity, InodeId>,
    tree: MergedTree<'l>,
}

pub(crate) fn merge<'l>(
    lower: &'l ValidatedNamespace,
    handles: &'l ExportHandles,
    reader: &Reader,
    cancel: &AtomicBool,
) -> Result<MergedTree<'l>, FlattenError> {
    let mut merger = Merger {
        lower,
        handles,
        reader,
        cancel,
        encoding: None,
        index: BTreeMap::new(),
        index_inodes: BTreeMap::new(),
        identities: BTreeMap::new(),
        tree: MergedTree {
            names: BTreeMap::new(),
            inodes: BTreeMap::new(),
        },
    };
    let layout = merger.layout()?;
    if let Some(index) = layout.index {
        merger.read_index(index)?;
    }
    merger.walk(layout.upper)?;
    merger.check_index_links()?;
    Ok(merger.tree)
}

impl<'l> Merger<'l, '_> {
    fn directory_entry(
        &self,
        entries: &[DirEntry],
        name: &[u8],
        path: &[u8],
    ) -> Result<Option<InodeNumber>, FlattenError> {
        let Some(entry) = entries.iter().find(|entry| entry.name == name) else {
            return Ok(None);
        };
        if !matches!(
            self.reader.metadata(entry.inode)?.kind,
            InodeKind::Directory
        ) {
            return Err(refuse(path, "overlay layout entry is not a directory"));
        }
        Ok(Some(entry.inode))
    }

    fn layout(&mut self) -> Result<Layout, FlattenError> {
        let root = self.reader.read_dir(ROOT_INODE)?.entries;
        if let Some(entry) = root
            .iter()
            .find(|entry| !matches!(entry.name.as_slice(), b"upper" | b"work" | b"lost+found"))
        {
            return Err(refuse(
                &entry.name,
                "unexpected entry in the upper filesystem root",
            ));
        }
        if let Some(found) = self.directory_entry(&root, b"lost+found", b"lost+found")? {
            if !self.reader.read_dir(found)?.entries.is_empty() {
                return Err(refuse(
                    b"lost+found",
                    "recovered orphans are outside the admitted state",
                ));
            }
        }
        let upper = self
            .directory_entry(&root, b"upper", b"upper")?
            .ok_or_else(|| refuse(b"upper", "upper directory is missing"))?;
        let work = self
            .directory_entry(&root, b"work", b"work")?
            .ok_or_else(|| refuse(b"work", "work directory is missing"))?;
        let work_entries = self.reader.read_dir(work)?.entries;
        if let Some(entry) = work_entries
            .iter()
            .find(|entry| !matches!(entry.name.as_slice(), b"work" | b"index"))
        {
            return Err(refuse(
                &upper_path(b"work", &entry.name),
                "unexpected entry in the work directory",
            ));
        }
        self.overlay_free(work, b"work")?;
        let scratch = self.directory_entry(&work_entries, b"work", b"work/work")?;
        let index = self.directory_entry(&work_entries, b"index", b"work/index")?;
        let upper_meta = self.reader.metadata(upper)?;
        let (controls, _) =
            split_controls(self.reader.inode_xattrs(upper)?, Role::Directory, b"upper")?;
        if controls.opaque {
            return Err(refuse(b"upper", "the upper root is never opaque"));
        }
        match (scratch, index) {
            (None, None) => {
                // Never mounted: format_upper's empty upper/ and work/ only.
                if controls.origin.is_some() || !self.reader.read_dir(upper)?.entries.is_empty() {
                    return Err(refuse(
                        b"upper",
                        "upper content exists without a mounted index",
                    ));
                }
            }
            (Some(scratch), Some(index)) => {
                if self.reader.lookup(scratch, b"incompat")?.is_some() {
                    return Err(refuse(
                        b"work/work/incompat",
                        "incompatible overlay features were used",
                    ));
                }
                let origin = controls
                    .origin
                    .ok_or_else(|| refuse(b"upper", "mounted upper root lacks its lower origin"))?;
                let (encoding, inode) = handle::lower_origin(&origin, self.handles, None)
                    .map_err(|reason| refuse(b"upper", reason))?;
                let root = self
                    .lower
                    .names()
                    .get(b"".as_slice())
                    .ok_or_else(|| refuse(b"upper", "lower namespace has no root"))?;
                if inode != root.inode {
                    return Err(refuse(b"upper", "upper root origin is not the lower root"));
                }
                self.encoding = Some(encoding);
                let mut bound = None;
                for (name, value) in self.reader.inode_xattrs(index)? {
                    match name.strip_prefix(OVERLAY_PREFIX) {
                        Some(b"upper") => bound = Some(value),
                        Some(_) => {
                            return Err(refuse(
                                b"work/index",
                                "unadmitted overlay control on the index directory",
                            ));
                        }
                        None => {}
                    }
                }
                let bound = bound.ok_or_else(|| {
                    refuse(
                        b"work/index",
                        "index directory is not bound to an upper root",
                    )
                })?;
                handle::upper_root(&bound, self.reader.uuid(), upper, upper_meta.generation)
                    .map_err(|reason| refuse(b"work/index", reason))?;
            }
            _ => {
                return Err(refuse(
                    b"work",
                    "work and index directories are not both present",
                ))
            }
        }
        Ok(Layout { upper, index })
    }

    fn overlay_free(&self, inode: InodeNumber, path: &[u8]) -> Result<(), FlattenError> {
        if self
            .reader
            .inode_xattrs(inode)?
            .keys()
            .any(|name| name.starts_with(OVERLAY_PREFIX))
        {
            return Err(refuse(path, "unexpected overlay control"));
        }
        Ok(())
    }

    fn read_index(&mut self, index: InodeNumber) -> Result<(), FlattenError> {
        let lower = self.lower;
        for entry in self.reader.read_dir(index)?.entries {
            check_cancel(self.cancel)?;
            // `#`-prefixed temporaries (and the shared whiteout) are discarded
            // by the next mount and never participate in lookup.
            if entry.name.first() == Some(&b'#') {
                continue;
            }
            let path = upper_path(b"work/index", &entry.name);
            let mut bytes = [0; 255];
            let handle_bytes = handle::index_name(&entry.name, &mut bytes)
                .ok_or_else(|| refuse(&path, "index name is not a canonical handle"))?;
            let (_, origin) = handle::lower_origin(handle_bytes, self.handles, self.encoding)
                .map_err(|reason| refuse(&path, reason))?;
            let meta = self.reader.metadata(entry.inode)?;
            if is_whiteout(&meta.kind) {
                return Err(refuse(&path, "whiteout index entries require nfs_export"));
            }
            if matches!(meta.kind, InodeKind::Directory) {
                return Err(refuse(&path, "directory index entries require nfs_export"));
            }
            let lower_inode = lower
                .inodes()
                .get(&origin)
                .ok_or_else(|| refuse(&path, "index origin has no lower inode"))?;
            if lower_inode.link_count < 2 {
                return Err(refuse(
                    &path,
                    "index entry for a lower inode with one name requires nfs_export",
                ));
            }
            if !same_type(&meta.kind, &lower_inode.kind) {
                return Err(refuse(
                    &path,
                    "index entry type differs from its lower origin",
                ));
            }
            let (controls, _) = split_controls(
                self.reader.inode_xattrs(entry.inode)?,
                Role::NonDirectory,
                &path,
            )?;
            if controls.origin.as_deref() != Some(handle_bytes) {
                return Err(refuse(&path, "index entry origin differs from its name"));
            }
            if self.index_inodes.insert(entry.inode, origin).is_some() {
                return Err(refuse(&path, "one upper inode indexes two lower inodes"));
            }
            let indexed = IndexEntry {
                inode: entry.inode,
                name: path,
                nlink: controls.nlink,
            };
            if let Some(previous) = self.index.insert(origin, indexed) {
                return Err(refuse(
                    &previous.name,
                    "two index entries name one lower inode",
                ));
            }
        }
        Ok(())
    }

    fn insert(
        &mut self,
        identity: Identity,
        inode: MergedInode<'l>,
    ) -> Result<InodeId, FlattenError> {
        let id = InodeId(self.identities.len() as u64);
        if self.identities.insert(identity, id).is_some() {
            return Err(refuse(b"upper", "one inode was merged twice"));
        }
        self.tree.inodes.insert(id, inode);
        Ok(id)
    }

    fn add_name(&mut self, path: Vec<u8>, id: InodeId) -> Result<(), FlattenError> {
        if self.tree.names.len() as u64 >= FORMAT_LIMITS.max_namespace_entries {
            return Err(refuse(
                &upper_path(b"upper", &path),
                "merged namespace exceeds the admitted live-name bound",
            ));
        }
        let inode = self
            .tree
            .inodes
            .get_mut(&id)
            .ok_or_else(|| refuse(b"upper", "merged name has no inode"))?;
        let count = inode.link_count_mut();
        *count = count
            .checked_add(1)
            .ok_or_else(|| refuse(&path, "link count overflows"))?;
        if self.tree.names.insert(path, id).is_some() {
            return Err(refuse(b"upper", "one merged path was produced twice"));
        }
        Ok(())
    }

    /// The merged inode for an upper non-directory, built once per ext4 inode
    /// whether it is reached by an upper name or through its index entry.
    fn upper_inode(&mut self, number: InodeNumber, path: &[u8]) -> Result<InodeId, FlattenError> {
        if let Some(id) = self.identities.get(&Identity::Upper(number)) {
            return Ok(*id);
        }
        let meta = self.reader.metadata(number)?;
        let content = match meta.kind {
            InodeKind::Regular => UpperContent::Regular,
            InodeKind::Symlink => {
                let target = self.reader.symlink_target(number)?;
                if target.is_empty()
                    || target.contains(&0)
                    || target.len() as u64 > FORMAT_LIMITS.max_path_bytes
                {
                    return Err(refuse(
                        path,
                        "symlink target is outside the admitted profile",
                    ));
                }
                UpperContent::Symlink(target)
            }
            InodeKind::CharacterDevice(device) => UpperContent::CharacterDevice {
                major: device.major(),
                minor: device.minor(),
            },
            InodeKind::BlockDevice(device) => UpperContent::BlockDevice {
                major: device.major(),
                minor: device.minor(),
            },
            InodeKind::Fifo => UpperContent::Fifo,
            InodeKind::Socket => UpperContent::Socket,
            InodeKind::Directory => {
                return Err(refuse(path, "directory reached as a non-directory alias"));
            }
        };
        let (controls, visible) =
            split_controls(self.reader.inode_xattrs(number)?, Role::NonDirectory, path)?;
        let indexed = self.index_inodes.get(&number).copied();
        if let Some(origin) = &controls.origin {
            let (_, origin) = handle::lower_origin(origin, self.handles, self.encoding)
                .map_err(|reason| refuse(path, reason))?;
            if self.encoding.is_none() {
                return Err(refuse(
                    path,
                    "copy-up origin exists without a mounted index",
                ));
            }
            let lower = self
                .lower
                .inodes()
                .get(&origin)
                .ok_or_else(|| refuse(path, "origin has no lower inode"))?;
            if !same_type(&meta.kind, &lower.kind) {
                return Err(refuse(
                    path,
                    "copied-up inode type differs from its lower origin",
                ));
            }
            if lower.link_count > 1 && indexed != Some(origin) {
                return Err(refuse(
                    path,
                    "copied-up lower hardlink is not its index inode",
                ));
            }
        } else if indexed.is_some() {
            return Err(refuse(path, "index inode lacks its origin"));
        }
        if controls.nlink.is_some() && indexed.is_none() {
            return Err(refuse(
                path,
                "persistent overlay link count on an unindexed inode",
            ));
        }
        let metadata = upper_metadata(&meta, visible, false, path)?;
        self.insert(
            Identity::Upper(number),
            MergedInode::Upper {
                number,
                content,
                metadata,
                link_count: 0,
            },
        )
    }

    fn child_path(parent: &[u8], name: &[u8]) -> Result<Vec<u8>, FlattenError> {
        if name.is_empty()
            || name.contains(&b'/')
            || name.contains(&0)
            || matches!(name, b"." | b"..")
        {
            return Err(refuse(
                &upper_path(b"upper", parent),
                "invalid directory entry name",
            ));
        }
        let length = parent.len() + usize::from(!parent.is_empty()) + name.len();
        if length > MAX_PATH_BYTES {
            return Err(refuse(
                &upper_path(b"upper", parent),
                "merged path exceeds the admitted path bound",
            ));
        }
        let mut path = Vec::with_capacity(length);
        path.extend_from_slice(parent);
        if !parent.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name);
        Ok(path)
    }

    fn walk(&mut self, upper_root: InodeNumber) -> Result<(), FlattenError> {
        let lower = self.lower;
        let root_meta = self.reader.metadata(upper_root)?;
        let (_, visible) = split_controls(
            self.reader.inode_xattrs(upper_root)?,
            Role::Directory,
            b"upper",
        )?;
        let metadata = upper_metadata(&root_meta, visible, true, b"upper")?;
        let root = self.insert(
            Identity::Upper(upper_root),
            MergedInode::Upper {
                number: upper_root,
                content: UpperContent::Directory,
                metadata,
                link_count: 0,
            },
        )?;
        self.add_name(Vec::new(), root)?;
        let mut stack = vec![Frame {
            path: Vec::new(),
            upper: Some(upper_root),
            lower: true,
        }];
        while let Some(frame) = stack.pop() {
            check_cancel(self.cancel)?;
            let entries = match frame.upper {
                Some(directory) => self.reader.read_dir(directory)?.entries,
                None => Vec::new(),
            };
            for entry in &entries {
                let path = Self::child_path(&frame.path, &entry.name)?;
                self.upper_entry(&frame, entry, path, &mut stack)?;
            }
            if !frame.lower {
                continue;
            }
            for (name, child) in DirectChildren::new(lower.names(), &frame.path) {
                if entries
                    .binary_search_by(|entry| entry.name.as_slice().cmp(name))
                    .is_ok()
                {
                    continue;
                }
                let path = Self::child_path(&frame.path, name)?;
                let inode = lower
                    .inodes()
                    .get(&child.inode)
                    .ok_or_else(|| refuse(&path, "lower name has no inode"))?;
                let id = match (&inode.kind, self.index.get(&child.inode)) {
                    (_, Some(indexed)) => {
                        let (number, name) = (indexed.inode, indexed.name.clone());
                        self.upper_inode(number, &name)?
                    }
                    (NamespaceKind::Directory, None) => {
                        let id = self.insert(
                            Identity::Lower(child.inode),
                            MergedInode::Lower {
                                inode,
                                link_count: 0,
                            },
                        )?;
                        stack.push(Frame {
                            path: path.clone(),
                            upper: None,
                            lower: true,
                        });
                        id
                    }
                    (_, None) => match self.identities.get(&Identity::Lower(child.inode)) {
                        Some(id) => *id,
                        None => self.insert(
                            Identity::Lower(child.inode),
                            MergedInode::Lower {
                                inode,
                                link_count: 0,
                            },
                        )?,
                    },
                };
                self.add_name(path, id)?;
            }
        }
        Ok(())
    }

    fn upper_entry(
        &mut self,
        frame: &Frame,
        entry: &DirEntry,
        path: Vec<u8>,
        stack: &mut Vec<Frame>,
    ) -> Result<(), FlattenError> {
        let diagnostic = upper_path(b"upper", &path);
        let meta = self.reader.metadata(entry.inode)?;
        if is_whiteout(&meta.kind) {
            // Hides the name in every lower layer; carries no controls.
            return self.overlay_free(entry.inode, &diagnostic);
        }
        if !matches!(meta.kind, InodeKind::Directory) {
            let id = self.upper_inode(entry.inode, &diagnostic)?;
            return self.add_name(path, id);
        }
        let (controls, visible) = split_controls(
            self.reader.inode_xattrs(entry.inode)?,
            Role::Directory,
            &diagnostic,
        )?;
        let lower_directory = if frame.lower {
            self.lower
                .names()
                .get(&path)
                .map(|name| name.inode)
                .filter(|inode| {
                    self.lower
                        .inodes()
                        .get(inode)
                        .is_some_and(|inode| matches!(inode.kind, NamespaceKind::Directory))
                })
        } else {
            None
        };
        let merged = match (controls.opaque, lower_directory, controls.origin) {
            (true, _, Some(_)) => {
                return Err(refuse(
                    &diagnostic,
                    "opaque directory records a copy-up origin",
                ));
            }
            (true, _, None) => false,
            (false, Some(expected), Some(origin)) => {
                let (_, origin) = handle::lower_origin(&origin, self.handles, self.encoding)
                    .map_err(|reason| refuse(&diagnostic, reason))?;
                if origin != expected {
                    return Err(refuse(
                        &diagnostic,
                        "merged directory origin is not the lower directory at its path",
                    ));
                }
                true
            }
            (false, Some(_), None) => {
                return Err(refuse(
                    &diagnostic,
                    "upper directory merges a lower directory without a copy-up origin",
                ));
            }
            (false, None, Some(_)) => {
                return Err(refuse(
                    &diagnostic,
                    "directory origin names no lower directory at its path",
                ));
            }
            (false, None, None) => false,
        };
        let metadata = upper_metadata(&meta, visible, true, &diagnostic)?;
        let id = self.insert(
            Identity::Upper(entry.inode),
            MergedInode::Upper {
                number: entry.inode,
                content: UpperContent::Directory,
                metadata,
                link_count: 0,
            },
        )?;
        self.add_name(path.clone(), id)?;
        stack.push(Frame {
            path,
            upper: Some(entry.inode),
            lower: merged,
        });
        Ok(())
    }

    /// Each index inode's persistent overlay link count (relative to the lower
    /// or upper real inode) must equal the visible aliases found by the walk.
    /// A count of zero or less with no other upper link is an orphan the next
    /// mount discards, which is consistent only if nothing is visible.
    fn check_index_links(&self) -> Result<(), FlattenError> {
        for (origin, entry) in &self.index {
            let visible = self
                .identities
                .get(&Identity::Upper(entry.inode))
                .and_then(|id| self.tree.inodes.get(id))
                .map_or(0, MergedInode::link_count);
            let lower_links = self
                .lower
                .inodes()
                .get(origin)
                .map_or(0, |inode| inode.link_count);
            let upper_links = self.reader.metadata(entry.inode)?.links;
            let persistent = entry
                .nlink
                .as_deref()
                .and_then(|value| persistent_links(value, lower_links, upper_links));
            let consistent = match persistent {
                Some(count) if count > 0 => u64::try_from(count).ok() == Some(u64::from(visible)),
                _ => visible == 0 && upper_links == 1,
            };
            if !consistent {
                return Err(refuse(
                    &entry.name,
                    "persistent overlay link count disagrees with the visible aliases",
                ));
            }
        }
        Ok(())
    }
}

/// `ovl_get_nlink`: `L` or `U`, a sign, and a decimal `int` difference.
fn persistent_links(value: &[u8], lower_links: u32, upper_links: u16) -> Option<i64> {
    let (&base, rest) = value.split_first()?;
    let (&sign, digits) = rest.split_first()?;
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let magnitude = std::str::from_utf8(digits).ok()?.parse::<i64>().ok()?;
    let difference = match sign {
        b'+' => magnitude,
        b'-' => -magnitude,
        _ => return None,
    };
    i32::try_from(difference).ok()?;
    let base = match base {
        b'L' => i64::from(lower_links),
        b'U' => i64::from(upper_links),
        _ => return None,
    };
    Some(base + difference)
}

#[cfg(test)]
mod tests {
    use crate::overlay_flatten::merge::persistent_links;

    #[test]
    fn persistent_link_counts_follow_the_kernel_spelling() {
        assert_eq!(persistent_links(b"L+0", 3, 2), Some(3));
        assert_eq!(persistent_links(b"U+1", 3, 2), Some(3));
        assert_eq!(persistent_links(b"U-1", 3, 1), Some(0));
        assert_eq!(persistent_links(b"L-3", 3, 1), Some(0));
        for invalid in [
            b"".as_slice(),
            b"L",
            b"L+",
            b"X+1",
            b"L*1",
            b"L+1x",
            b"L+ 1",
            b"U+99999999999",
            b"U+2147483648",
        ] {
            assert_eq!(persistent_links(invalid, 3, 2), None, "{invalid:?}");
        }
    }
}
