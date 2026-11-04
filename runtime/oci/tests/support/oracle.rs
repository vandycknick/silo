//! Deliberately independent fixture semantics. This module imports no OCI code.
use std::collections::{BTreeMap, VecDeque};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attribute {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_seconds: u64,
    pub mtime_nanos: u32,
    pub xattrs: Vec<Attribute>,
}

impl Default for Stat {
    fn default() -> Self {
        Self {
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_seconds: 0,
            mtime_nanos: 0,
            xattrs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Directory,
    File(Vec<u8>),
    Symlink(Vec<u8>),
    Character(u32, u32),
    Block(u32, u32),
    Fifo,
    Socket,
}

#[derive(Clone, Debug)]
pub enum Action {
    Put(Object),
    Link(Vec<u8>),
    Remove,
    Opaque,
}

#[derive(Clone, Copy, Debug)]
pub enum SparseEncoding {
    OldGnu,
    Pax00,
    Pax01,
    Pax10,
}

#[derive(Clone, Debug)]
pub struct SparseSpec {
    pub encoding: SparseEncoding,
    pub ranges: Vec<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Default)]
pub enum XattrWire {
    #[default]
    Schily,
    Libarchive,
}

#[derive(Clone, Debug, Default)]
pub struct WireMetadata {
    pub xattrs: XattrWire,
    pub access_acl: Option<Vec<u8>>,
    pub default_acl: Option<Vec<u8>>,
    pub rht_selinux: bool,
}

#[derive(Clone, Debug)]
pub struct Operation {
    pub path: Vec<u8>,
    pub stat: Stat,
    pub action: Action,
    pub explicit_attrs: bool,
    pub sparse: Option<SparseSpec>,
    pub wire: WireMetadata,
}

impl Operation {
    pub fn file(path: &[u8], body: &[u8]) -> Self {
        Self::put(path, Object::File(body.to_vec()))
    }
    pub fn put(path: &[u8], object: Object) -> Self {
        Self {
            path: path.to_vec(),
            stat: Stat::default(),
            action: Action::Put(object),
            explicit_attrs: false,
            sparse: None,
            wire: WireMetadata::default(),
        }
    }
    pub fn link(path: &[u8], target: &[u8]) -> Self {
        Self {
            path: path.to_vec(),
            stat: Stat::default(),
            action: Action::Link(target.to_vec()),
            explicit_attrs: false,
            sparse: None,
            wire: WireMetadata::default(),
        }
    }
    pub fn remove(path: &[u8]) -> Self {
        Self {
            path: path.to_vec(),
            stat: Stat::default(),
            action: Action::Remove,
            explicit_attrs: false,
            sparse: None,
            wire: WireMetadata::default(),
        }
    }
    pub fn opaque(path: &[u8]) -> Self {
        Self {
            path: path.to_vec(),
            stat: Stat::default(),
            action: Action::Opaque,
            explicit_attrs: false,
            sparse: None,
            wire: WireMetadata::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub path: String,
    pub kind: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_seconds: u64,
    pub mtime_nanos: u32,
    pub xattrs: Vec<Attribute>,
    pub length: Option<u64>,
    pub content: Option<String>,
    pub target: Option<String>,
    pub device_major: Option<u32>,
    pub device_minor: Option<u32>,
    pub group: Option<String>,
    pub links: Option<u32>,
}

pub fn bytes(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}
pub fn hash(raw: &[u8]) -> String {
    digest_text(&Sha256::digest(raw))
}
pub fn digest_text(raw: &[u8]) -> String {
    let hex = raw
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

#[derive(Clone)]
struct Node {
    object: Object,
    stat: Stat,
}

/// Names and inodes are different tables, including hardlinked special nodes.
#[derive(Clone)]
pub struct Tree {
    names: BTreeMap<Vec<u8>, usize>,
    nodes: Vec<Node>,
}

impl Default for Tree {
    fn default() -> Self {
        Self {
            names: BTreeMap::from([(Vec::new(), 0)]),
            nodes: vec![Node {
                object: Object::Directory,
                stat: Stat::default(),
            }],
        }
    }
}

fn pieces(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .map(<[u8]>::to_vec)
        .collect()
}

fn joined(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.join(&b'/')
}

fn normalized(path: &[u8]) -> Result<Vec<u8>, String> {
    if path.is_empty()
        || path.first() == Some(&b'/')
        || path.contains(&0)
        || path.split(|byte| *byte == b'/').any(|part| part == b"..")
    {
        return Err("invalid source path".into());
    }
    let parts = pieces(path);
    if path.len() > 4096 || parts.len() > 256 || parts.iter().any(|part| part.len() > 255) {
        return Err("source path bound".into());
    }
    Ok(joined(&parts))
}

impl Tree {
    fn allocate(&mut self, path: Vec<u8>, object: Object, stat: Stat) {
        let id = self.nodes.len();
        self.nodes.push(Node { object, stat });
        self.names.insert(path, id);
    }

    fn erase(&mut self, path: &[u8], include_self: bool) {
        self.names.retain(|name, _| {
            !(include_self && name == path
                || name.len() > path.len()
                    && (path.is_empty()
                        || name.starts_with(path) && name.get(path.len()) == Some(&b'/')))
        });
    }

    // This interpreter consumes a queue, not the production resolver. A barrier
    // marks every symlink expansion: absent components before it are dangling,
    // not candidates for synthetic directories.
    fn directory(&mut self, input: &[u8], synthesize: bool) -> Result<Option<Vec<u8>>, String> {
        #[derive(Clone)]
        enum Step {
            Name(Vec<u8>),
            EndLink,
        }
        let mut todo: VecDeque<Step> = pieces(input).into_iter().map(Step::Name).collect();
        let mut stack = Vec::<Vec<u8>>::new();
        let mut active_links = 0_u32;
        let mut hops = 0_u32;
        while let Some(step) = todo.pop_front() {
            let part = match step {
                Step::EndLink => {
                    active_links -= 1;
                    continue;
                }
                Step::Name(part) => part,
            };
            if part == b".." {
                stack.pop();
                continue;
            }
            stack.push(part);
            let path = joined(&stack);
            if stack.len() > 256 || path.len() > 4096 || stack.iter().any(|part| part.len() > 255) {
                return Err("resolved path bound".into());
            }
            let object = self.names.get(&path).map(|id| &self.nodes[*id].object);
            match object {
                Some(Object::Directory) => (),
                Some(Object::Symlink(target)) => {
                    hops += 1;
                    if hops > 40 {
                        return Err("symlink hop bound".into());
                    }
                    stack.pop();
                    if target.first() == Some(&b'/') {
                        stack.clear();
                    }
                    if target.is_empty() {
                        return Err("empty parent symlink".into());
                    }
                    active_links += 1;
                    todo.push_front(Step::EndLink);
                    for part in pieces(target).into_iter().rev() {
                        todo.push_front(Step::Name(part));
                    }
                    let mut depth = stack.len();
                    let mut expanded =
                        stack.iter().map(Vec::len).sum::<usize>() + depth.saturating_sub(1);
                    for step in &todo {
                        if let Step::Name(part) = step {
                            if part.len() > 255 {
                                return Err("expanded component bound".into());
                            }
                            expanded += part.len() + usize::from(depth != 0);
                            depth += 1;
                        }
                    }
                    if depth > 256 || expanded > 4096 {
                        return Err("expanded path bound".into());
                    }
                }
                Some(_) => return Err("non-directory parent".into()),
                None if synthesize && active_links == 0 => {
                    self.allocate(path, Object::Directory, Stat::default())
                }
                None if active_links != 0 => return Err("dangling parent symlink".into()),
                None => return Ok(None),
            }
        }
        Ok(Some(joined(&stack)))
    }

    fn destination(&mut self, path: &[u8], create: bool) -> Result<Option<Vec<u8>>, String> {
        if path.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let split = path.iter().rposition(|byte| *byte == b'/');
        let (parent, base) = split.map_or((&b""[..], path), |at| (&path[..at], &path[at + 1..]));
        let Some(mut resolved) = self.directory(parent, create)? else {
            return Ok(None);
        };
        if !resolved.is_empty() {
            resolved.push(b'/');
        }
        resolved.extend_from_slice(base);
        if resolved.len() > 4096 || resolved.split(|byte| *byte == b'/').count() > 256 {
            return Err("resolved destination bound".into());
        }
        Ok(Some(resolved))
    }

    pub fn apply(&mut self, operations: &[Operation]) -> Result<(), String> {
        let mut unique = BTreeMap::new();
        let mut normalized_ops = Vec::new();
        for operation in operations {
            // The approved exception is an entry spelling, not a general path
            // normalization rule. In particular hardlink targets still pass
            // through strict normalized() below and cannot use absolute `/`.
            let path = if operation.path == b"/"
                && matches!(operation.action, Action::Put(Object::Directory))
            {
                Vec::new()
            } else {
                normalized(&operation.path)?
            };
            if unique.insert(path.clone(), ()).is_some() {
                return Err("duplicate source name".into());
            }
            normalized_ops.push((path, operation));
        }
        // Resolve every deletion before mutating names: this is the same lower
        // view for every marker, without copying historical inode bodies.
        let mut removals = Vec::new();
        for (path, operation) in &normalized_ops {
            match operation.action {
                Action::Remove => {
                    let split = path.iter().rposition(|byte| *byte == b'/');
                    let (parent, base) = split.map_or((&b""[..], path.as_slice()), |at| {
                        (&path[..at], &path[at + 1..])
                    });
                    let name = base.strip_prefix(b".wh.").ok_or("bad whiteout")?;
                    if name.is_empty() || name == b"." || name == b".." {
                        return Err("bad whiteout name".into());
                    }
                    if let Some(mut parent) = self.directory(parent, false)? {
                        if !parent.is_empty() {
                            parent.push(b'/');
                        }
                        parent.extend_from_slice(name);
                        removals.push((parent, true));
                    }
                }
                Action::Opaque => {
                    let split = path.iter().rposition(|byte| *byte == b'/');
                    let parent = split.map_or(&b""[..], |at| &path[..at]);
                    if let Some(parent) = self.directory(parent, false)? {
                        removals.push((parent, false));
                    }
                }
                _ => (),
            }
        }
        for (path, include_self) in removals {
            self.erase(&path, include_self);
        }
        for (source, operation) in normalized_ops {
            if matches!(operation.action, Action::Remove | Action::Opaque) {
                continue;
            }
            let path = self
                .destination(&source, true)?
                .ok_or("missing destination parent")?;
            match &operation.action {
                Action::Link(target) => {
                    let target = normalized(target)?;
                    let target = self
                        .destination(&target, false)?
                        .ok_or("missing link parent")?;
                    if path == target {
                        return Err("self hardlink".into());
                    }
                    let inode = *self.names.get(&target).ok_or("missing link target")?;
                    let node = &self.nodes[inode];
                    if node.object == Object::Directory {
                        return Err("directory hardlink".into());
                    }
                    if operation.explicit_attrs
                        && operation
                            .stat
                            .xattrs
                            .iter()
                            .any(|attr| !node.stat.xattrs.contains(attr))
                    {
                        return Err("hardlink xattr conflict".into());
                    }
                    self.erase(&path, true);
                    self.names.insert(path, inode);
                }
                Action::Put(object) => {
                    if let Some(inode) = self.names.get(&path).copied() {
                        if *object == Object::Directory
                            && self.nodes[inode].object == Object::Directory
                        {
                            self.nodes[inode].stat = operation.stat.clone();
                            continue;
                        }
                    }
                    if path.is_empty() && *object != Object::Directory {
                        return Err("non-directory root".into());
                    }
                    self.erase(&path, true);
                    self.allocate(path, object.clone(), operation.stat.clone());
                }
                _ => (),
            }
        }
        Ok(())
    }

    pub fn listing(&self) -> Vec<Row> {
        let mut groups: BTreeMap<usize, Vec<&Vec<u8>>> = BTreeMap::new();
        for (name, inode) in &self.names {
            groups.entry(*inode).or_default().push(name);
        }
        self.names
            .iter()
            .map(|(name, inode)| {
                let node = &self.nodes[*inode];
                let (kind, length, content, target, major, minor) = match &node.object {
                    Object::Directory => ("directory", None, None, None, None, None),
                    Object::File(body) => (
                        "regular",
                        Some(body.len() as u64),
                        Some(hash(body)),
                        None,
                        None,
                        None,
                    ),
                    Object::Symlink(target) => {
                        ("symlink", None, None, Some(bytes(target)), None, None)
                    }
                    Object::Character(major, minor) => (
                        "character-device",
                        None,
                        None,
                        None,
                        Some(*major),
                        Some(*minor),
                    ),
                    Object::Block(major, minor) => {
                        ("block-device", None, None, None, Some(*major), Some(*minor))
                    }
                    Object::Fifo => ("fifo", None, None, None, None, None),
                    Object::Socket => ("socket", None, None, None, None, None),
                };
                let members = &groups[inode];
                let (group, links) = if node.object == Object::Directory {
                    (None, None)
                } else {
                    (Some(bytes(members[0])), Some(members.len() as u32))
                };
                Row {
                    path: bytes(name),
                    kind: kind.into(),
                    mode: node.stat.mode,
                    uid: node.stat.uid,
                    gid: node.stat.gid,
                    mtime_seconds: node.stat.mtime_seconds,
                    mtime_nanos: node.stat.mtime_nanos,
                    xattrs: node.stat.xattrs.clone(),
                    length,
                    content,
                    target,
                    device_major: major,
                    device_minor: minor,
                    group,
                    links,
                }
            })
            .collect()
    }
}

pub fn compare(expected: &[Row], actual: &[Row]) -> Result<(), String> {
    if expected == actual {
        return Ok(());
    }
    let at = expected
        .iter()
        .zip(actual)
        .position(|(left, right)| left != right)
        .unwrap_or(expected.len().min(actual.len()));
    Err(format!(
        "listing differs at row {at}: expected {:?}; actual {:?}",
        expected.get(at),
        actual.get(at)
    ))
}
