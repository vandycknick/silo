//! Lazy authenticated stream roots and operation-owned staged Merkle nodes.
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

use vm_spec::capture::Sha256Digest;
use vm_spec::stream_map::{
    Chunk, ChunkChange, ChunkSize, MapError, NodeSink, NodeSource, PresentChunk,
    PresentChunkCursor, StreamNode, StreamRole, StreamRoot, MAX_NODE_BYTES, ROOT_HEIGHT,
};

use crate::paths::OwnedDirectory;
use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::StorageError;

/// Implementations own the operation/root pin that protects readable nodes.
pub trait MapAuthority: Send + Sync {
    fn read_node(
        &self,
        digest: Sha256Digest,
        output: &mut [u8; MAX_NODE_BYTES],
    ) -> Result<usize, MapError>;
    fn node_height(&self, _digest: ObjectDigest) -> Option<u8> {
        None
    }
    fn open_node(&self, _digest: ObjectDigest) -> Result<Option<File>, MapError> {
        Ok(None)
    }
}

pub(crate) fn read_node_file(
    file: std::io::Result<File>,
    digest: Sha256Digest,
    output: &mut [u8; MAX_NODE_BYTES],
) -> Result<usize, MapError> {
    let mut file = match file {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(MapError::MissingNode(digest))
        }
        result => result?,
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(MapError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "map node is not a regular file",
        )));
    }
    let length = usize::try_from(metadata.len()).map_err(|_| MapError::ArithmeticOverflow)?;
    if length > MAX_NODE_BYTES {
        return Err(MapError::NodeTooLarge(length));
    }
    file.read_exact(&mut output[..length])?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(MapError::NodeTooLarge(length + 1));
    }
    Ok(length)
}

/// Pool authority never resolves its directory pathname again.
pub(crate) struct PoolMapAuthority {
    pub directory: OwnedDirectory,
    pub pin: Arc<dyn Send + Sync>,
}
impl MapAuthority for PoolMapAuthority {
    fn read_node(
        &self,
        digest: Sha256Digest,
        output: &mut [u8; MAX_NODE_BYTES],
    ) -> Result<usize, MapError> {
        let _pin = &self.pin;
        let name = ObjectDigest::from_sha256(*digest.as_bytes()).hex();
        let file = crate::storage::pool::existing(&self.directory, &name)
            .map_err(|error| match error {
                StorageError::Io(error) => MapError::Io(error),
                error => MapError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
            })?
            .ok_or(MapError::MissingNode(digest))?;
        read_node_file(Ok(file), digest, output)
    }
}

// Fresh bytes occupy one anonymous inode. Adopted capture nodes stay in their
// operation-owned directory until publication, without a second disk reservation.
#[derive(Clone, Copy)]
enum NodeLocation {
    Spool {
        offset: u64,
        length: usize,
        height: u8,
    },
    Directory {
        height: u8,
    },
}
struct NodeBatch {
    file: File,
    directory: Option<OwnedDirectory>,
    offsets: HashMap<ObjectDigest, NodeLocation>,
    nodes: Vec<ObjectDigest>,
    predecessor: Option<AuthenticatedMap>,
    fallback: Option<Arc<dyn MapAuthority>>,
}
impl MapAuthority for NodeBatch {
    fn read_node(
        &self,
        digest: Sha256Digest,
        output: &mut [u8; MAX_NODE_BYTES],
    ) -> Result<usize, MapError> {
        let object = ObjectDigest::from_sha256(*digest.as_bytes());
        if let Some(location) = self.offsets.get(&object) {
            return match *location {
                NodeLocation::Spool { offset, length, .. } => {
                    self.file.read_exact_at(&mut output[..length], offset)?;
                    Ok(length)
                }
                NodeLocation::Directory { .. } => {
                    let directory = self
                        .directory
                        .as_ref()
                        .ok_or(MapError::MissingNode(digest))?;
                    let file = nix::fcntl::openat(
                        directory.fd(),
                        object.hex().as_str(),
                        nix::fcntl::OFlag::O_RDONLY
                            | nix::fcntl::OFlag::O_NOFOLLOW
                            | nix::fcntl::OFlag::O_CLOEXEC
                            | nix::fcntl::OFlag::O_NONBLOCK,
                        nix::sys::stat::Mode::empty(),
                    )
                    .map(File::from)
                    .map_err(std::io::Error::from);
                    read_node_file(file, digest, output)
                }
            };
        }
        if let Some(map) = &self.predecessor {
            return map.authority.read_node(digest, output);
        }
        match &self.fallback {
            Some(source) => source.read_node(digest, output),
            None => Err(MapError::MissingNode(digest)),
        }
    }
    fn node_height(&self, digest: ObjectDigest) -> Option<u8> {
        self.offsets.get(&digest).map(|location| match location {
            NodeLocation::Spool { height, .. } | NodeLocation::Directory { height } => *height,
        })
    }
    fn open_node(&self, digest: ObjectDigest) -> Result<Option<File>, MapError> {
        if !matches!(
            self.offsets.get(&digest),
            Some(NodeLocation::Directory { .. })
        ) {
            return Ok(None);
        }
        let directory =
            self.directory
                .as_ref()
                .ok_or(MapError::MissingNode(Sha256Digest::from_bytes(
                    *digest.as_bytes(),
                )))?;
        let file = directory
            .open_capture_payload(&digest.hex())
            .map_err(|error| {
                MapError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            })?
            .ok_or(MapError::MissingNode(Sha256Digest::from_bytes(
                *digest.as_bytes(),
            )))?;
        Ok(Some(file))
    }
}

#[derive(Clone)]
pub struct AuthenticatedMap {
    root: StreamRoot,
    role: StreamRole,
    authority: Arc<dyn MapAuthority>,
    staged: Option<Arc<NodeBatch>>,
}
impl std::fmt::Debug for AuthenticatedMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedMap")
            .field("root", &self.root)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}
impl PartialEq for AuthenticatedMap {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}
impl Eq for AuthenticatedMap {}
impl AuthenticatedMap {
    pub fn from_root(
        root: StreamRoot,
        role: StreamRole,
        authority: Arc<dyn MapAuthority>,
    ) -> Result<Self, StorageError> {
        let map = Self::from_admitted_root(root, role, authority)?;
        map.root.validate_boundary(&mut map.node_source())?;
        Ok(map)
    }
    /// Only previously admitted immutable graph authority may use this lane.
    pub fn from_admitted_root(
        root: StreamRoot,
        role: StreamRole,
        authority: Arc<dyn MapAuthority>,
    ) -> Result<Self, StorageError> {
        root.validate_role(role)?;
        Ok(Self {
            root,
            role,
            authority,
            staged: None,
        })
    }
    pub fn with_role(&self, role: StreamRole) -> Result<Self, StorageError> {
        self.root.validate_role(role)?;
        let mut map = self.clone();
        map.role = role;
        Ok(map)
    }
    pub fn with_root(&self, root: StreamRoot, role: StreamRole) -> Result<Self, StorageError> {
        root.validate_role(role)?;
        let mut map = self.clone();
        map.root = root;
        map.role = role;
        root.validate_boundary(&mut map.node_source())?;
        Ok(map)
    }
    pub fn root(&self) -> &StreamRoot {
        &self.root
    }
    pub fn id(&self) -> StreamId {
        StreamId::from_sha256(*self.root.id().as_bytes())
    }
    pub fn length(&self) -> u64 {
        self.root.length()
    }
    pub fn chunk_size(&self) -> ChunkSize {
        self.root.chunk_size()
    }
    pub fn role(&self) -> StreamRole {
        self.role
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StorageError> {
        Ok(self.root.canonical_bytes()?)
    }
    pub fn write_canonical(&self, output: impl Write) -> Result<(), StorageError> {
        Ok(self.root.write_canonical(output)?)
    }
    pub fn node_source(&self) -> MapNodeReader {
        MapNodeReader {
            authority: Arc::clone(&self.authority),
            cache: VecDeque::new(),
        }
    }
    pub fn lookup(&self, index: u64) -> Result<Chunk, StorageError> {
        Ok(self.root.lookup(index, &mut self.node_source())?)
    }
    pub fn present_chunks(&self) -> impl Iterator<Item = Result<PresentChunk, StorageError>> {
        MapPresentChunks {
            cursor: self.root.present_chunk_cursor(),
            source: self.node_source(),
            done: false,
        }
    }
    pub fn update_sorted(
        &self,
        changes: impl IntoIterator<Item = Result<ChunkChange, MapError>>,
        sink: &mut MapNodeWriter,
    ) -> Result<ProducedMap, StorageError> {
        let root = self
            .root
            .update_sorted(changes, &mut self.node_source(), sink)?;
        sink.take()?.finish(root, self.role, Some(self.clone()))
    }
    /// Full traversal is reserved for transport and explicit authentication.
    pub fn nodes(&self) -> impl Iterator<Item = Result<MapNodeObject, StorageError>> {
        MapNodes {
            source: self.node_source(),
            pending: self
                .root
                .tree_digest()
                .map(|digest| vec![(digest, ROOT_HEIGHT)])
                .unwrap_or_default(),
            seen: HashSet::new(),
        }
    }
    pub(crate) fn staged_nodes(
        &self,
        output: &mut Vec<(ObjectDigest, Arc<dyn MapAuthority>)>,
        batches: &mut HashSet<usize>,
    ) {
        if let Some(batch) = &self.staged {
            if !batches.insert(Arc::as_ptr(batch) as usize) {
                return;
            }
            if let Some(predecessor) = &batch.predecessor {
                predecessor.staged_nodes(output, batches);
            }
            let authority: Arc<dyn MapAuthority> = batch.clone();
            output.extend(
                batch
                    .nodes
                    .iter()
                    .map(|digest| (*digest, Arc::clone(&authority))),
            );
        }
    }
}

/// A bounded cache belongs to one traversal, never to global state.
pub struct MapNodeReader {
    authority: Arc<dyn MapAuthority>,
    cache: VecDeque<(Sha256Digest, Vec<u8>)>,
}
impl NodeSource for MapNodeReader {
    fn read_node(
        &mut self,
        digest: Sha256Digest,
        output: &mut [u8; MAX_NODE_BYTES],
    ) -> Result<usize, MapError> {
        if let Some((_, bytes)) = self.cache.iter().find(|(key, _)| *key == digest) {
            output[..bytes.len()].copy_from_slice(bytes);
            return Ok(bytes.len());
        }
        let length = self.authority.read_node(digest, output)?;
        let bytes = output.get(..length).ok_or(MapError::NodeTooLarge(length))?;
        let actual = Sha256Digest::of_bytes(bytes);
        if actual != digest {
            return Err(MapError::DigestMismatch {
                expected: digest,
                actual,
            });
        }
        if self.cache.len() == 64 {
            self.cache.pop_front();
        }
        self.cache.push_back((digest, bytes.to_vec()));
        Ok(length)
    }
}

struct MapPresentChunks {
    cursor: PresentChunkCursor,
    source: MapNodeReader,
    done: bool,
}
impl Iterator for MapPresentChunks {
    type Item = Result<PresentChunk, StorageError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.cursor.next_chunk(&mut self.source) {
            Ok(Some(chunk)) => Some(Ok(chunk)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error.into()))
            }
        }
    }
}

pub struct MapNodeObject {
    pub digest: ObjectDigest,
    pub height: u8,
    pub bytes: Vec<u8>,
    pub children: Vec<(u8, ObjectDigest)>,
}
struct MapNodes {
    source: MapNodeReader,
    pending: Vec<(Sha256Digest, u8)>,
    seen: HashSet<Sha256Digest>,
}
impl Iterator for MapNodes {
    type Item = Result<MapNodeObject, StorageError>;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some((digest, height)) = self.pending.pop() {
            if !self.seen.insert(digest) {
                continue;
            }
            let result = (|| {
                let mut buffer = [0; MAX_NODE_BYTES];
                let length = self.source.read_node(digest, &mut buffer)?;
                let node = StreamNode::decode(&buffer[..length], height)?;
                let children: Vec<_> = if height == 0 {
                    Vec::new()
                } else {
                    node.entries()
                        .map(|(slot, digest)| (slot, ObjectDigest::from_sha256(*digest.as_bytes())))
                        .collect()
                };
                if height != 0 {
                    self.pending
                        .extend(node.entries().map(|(_, digest)| (digest, height - 1)));
                }
                Ok(MapNodeObject {
                    digest: ObjectDigest::from_sha256(*digest.as_bytes()),
                    height,
                    bytes: buffer[..length].to_vec(),
                    children,
                })
            })();
            if result.is_err() {
                self.pending.clear();
            }
            return Some(result);
        }
        None
    }
}

pub struct MapNodeWriter {
    file: File,
    directory: Option<OwnedDirectory>,
    offsets: HashMap<ObjectDigest, NodeLocation>,
    nodes: Vec<ObjectDigest>,
    offset: u64,
    fallback: Option<Arc<dyn MapAuthority>>,
}
impl MapNodeWriter {
    pub fn new() -> Result<Self, StorageError> {
        Ok(Self {
            file: anonymous_file()?,
            directory: None,
            offsets: HashMap::new(),
            nodes: Vec::new(),
            offset: 0,
            fallback: None,
        })
    }
    pub fn with_authority(mut self, authority: Arc<dyn MapAuthority>) -> Self {
        self.fallback = Some(authority);
        self
    }
    pub(crate) fn scratch(&self) -> Result<File, StorageError> {
        anonymous_file()
    }
    pub fn adopt_directory(path: &Path) -> Result<Self, StorageError> {
        let directory = OwnedDirectory::open_existing_root(path)
            .map_err(|error| StorageError::InvalidPath(error.to_string()))?
            .ok_or_else(|| StorageError::InvalidPath("missing staged map node directory".into()))?;
        let mut writer = Self::new()?;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF8 map node name")
            })?;
            let digest: ObjectDigest = format!("sha256:{name}").parse()?;
            let file = directory
                .open_capture_payload(name)
                .map_err(|error| StorageError::InvalidPath(error.to_string()))?
                .ok_or_else(|| StorageError::InvalidPath("staged node disappeared".into()))?;
            let mut header = [0; 27];
            file.read_exact_at(&mut header, 0)?;
            let height = if header.starts_with(b"silo:stream-map:leaf:v1\n") {
                0
            } else if header.starts_with(b"silo:stream-map:branch:v1\n")
                && (1..=ROOT_HEIGHT).contains(&header[26])
            {
                header[26]
            } else {
                return Err(MapError::InvalidMagic.into());
            };
            writer
                .offsets
                .insert(digest, NodeLocation::Directory { height });
            writer.nodes.push(digest);
        }
        writer.directory = Some(directory);
        Ok(writer)
    }
    fn take(&mut self) -> Result<Self, StorageError> {
        Ok(std::mem::replace(self, Self::new()?))
    }
    pub fn finish(
        self,
        root: StreamRoot,
        role: StreamRole,
        predecessor: Option<AuthenticatedMap>,
    ) -> Result<ProducedMap, StorageError> {
        root.validate_role(role)?;
        let batch = Arc::new(NodeBatch {
            file: self.file,
            directory: self.directory,
            offsets: self.offsets,
            nodes: self.nodes,
            predecessor: predecessor.clone(),
            fallback: self.fallback,
        });
        let authority: Arc<dyn MapAuthority> = batch.clone();
        let map = AuthenticatedMap {
            root,
            role,
            authority,
            staged: Some(batch),
        };
        if predecessor.as_ref().is_none_or(|before| {
            before.length() != root.length() || before.chunk_size() != root.chunk_size()
        }) {
            root.validate_boundary(&mut map.node_source())?;
        }
        Ok(ProducedMap { map, predecessor })
    }
}
impl NodeSink for MapNodeWriter {
    fn write_node(&mut self, bytes: &[u8]) -> Result<Sha256Digest, MapError> {
        if bytes.len() > MAX_NODE_BYTES {
            return Err(MapError::NodeTooLarge(bytes.len()));
        }
        let height = if bytes.starts_with(b"silo:stream-map:leaf:v1\n") {
            0
        } else {
            *bytes.get(26).ok_or(MapError::Truncated)?
        };
        StreamNode::decode(bytes, height)?;
        let digest = Sha256Digest::of_bytes(bytes);
        let object = ObjectDigest::from_sha256(*digest.as_bytes());
        if !self.offsets.contains_key(&object) {
            self.file.write_all_at(bytes, self.offset)?;
            self.offsets.insert(
                object,
                NodeLocation::Spool {
                    offset: self.offset,
                    length: bytes.len(),
                    height,
                },
            );
            self.offset = self
                .offset
                .checked_add(bytes.len() as u64)
                .ok_or(MapError::ArithmeticOverflow)?;
            self.nodes.push(object);
        }
        Ok(digest)
    }
}

#[cfg(target_os = "linux")]
fn anonymous_file() -> Result<File, StorageError> {
    match nix::fcntl::open(
        std::env::temp_dir().as_path(),
        nix::fcntl::OFlag::O_TMPFILE | nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    ) {
        Ok(fd) => Ok(File::from(fd)),
        Err(
            nix::errno::Errno::EOPNOTSUPP | nix::errno::Errno::EINVAL | nix::errno::Errno::EISDIR,
        ) => unlinked_file(),
        Err(error) => Err(error.into()),
    }
}
#[cfg(not(target_os = "linux"))]
fn anonymous_file() -> Result<File, StorageError> {
    unlinked_file()
}
fn unlinked_file() -> Result<File, StorageError> {
    let path = std::env::temp_dir().join(format!("silo-map-{}", uuid::Uuid::new_v4()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    std::fs::remove_file(path)?;
    Ok(file)
}

pub struct ProducedMap {
    pub map: AuthenticatedMap,
    pub predecessor: Option<AuthenticatedMap>,
}
impl ProducedMap {
    pub fn new_nodes(&self) -> &[ObjectDigest] {
        self.map
            .staged
            .as_ref()
            .map_or(&[], |batch| batch.nodes.as_slice())
    }
    pub fn into_map(self) -> AuthenticatedMap {
        self.map
    }
}

pub struct PublishedMapNode {
    pub digest: ObjectDigest,
    pub height: Option<u8>,
    pub children: Vec<(u8, ObjectDigest)>,
}

#[cfg(test)]
mod tests {
    use crate::storage::identity::ObjectDigest;
    use crate::storage::map::{AuthenticatedMap, MapAuthority, MapNodeWriter};
    use crate::storage::pool::StoragePool;
    use crate::storage::stream::{ExpectedMapError, StreamHasher};
    use crate::storage::StorageError;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    use vm_spec::capture::Sha256Digest;
    use vm_spec::stream_map::{
        Chunk, ChunkChange, ChunkSize, MapError, StreamRole, MAX_NODE_BYTES,
    };

    struct CountReads {
        inner: Arc<dyn MapAuthority>,
        reads: Arc<AtomicU64>,
    }
    impl MapAuthority for CountReads {
        fn read_node(
            &self,
            digest: Sha256Digest,
            output: &mut [u8; MAX_NODE_BYTES],
        ) -> Result<usize, MapError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.read_node(digest, output)
        }
    }

    #[test]
    fn sparse_update_work_is_changed_paths_not_length_or_history() {
        for length in [30u64 << 30, 500u64 << 30, 1u64 << 40] {
            for historical in [1, 128] {
                let source = tempfile::tempfile().unwrap();
                source.set_len(length).unwrap();
                for index in 0..historical {
                    source
                        .write_all_at(
                            &[1 + (index % 251) as u8],
                            index * 65 * ChunkSize::RAM.bytes(),
                        )
                        .unwrap();
                }
                let baseline = StreamHasher::new(ChunkSize::RAM)
                    .hash_open_file(&source, length)
                    .unwrap()
                    .map;
                let reads = Arc::new(AtomicU64::new(0));
                let counted = AuthenticatedMap::from_admitted_root(
                    *baseline.root(),
                    StreamRole::Ram,
                    Arc::new(CountReads {
                        inner: Arc::clone(&baseline.authority),
                        reads: Arc::clone(&reads),
                    }),
                )
                .unwrap();
                let unchanged = counted
                    .update_sorted([], &mut MapNodeWriter::new().unwrap())
                    .unwrap();
                assert_eq!(unchanged.map.id(), baseline.id());
                assert!(unchanged.new_nodes().is_empty());
                assert_eq!(reads.load(Ordering::Relaxed), 0);
                let digest = Sha256Digest::of_bytes(&vec![0x7f; ChunkSize::RAM.bytes() as usize]);
                let changed = counted
                    .update_sorted(
                        [Ok(ChunkChange {
                            index: 0,
                            value: Chunk::Data(digest),
                        })],
                        &mut MapNodeWriter::new().unwrap(),
                    )
                    .unwrap();
                assert!(reads.load(Ordering::Relaxed) <= 5);
                assert!(changed.new_nodes().len() <= 5);
                assert_eq!(changed.map.lookup(0).unwrap(), Chunk::Data(digest));
                source
                    .write_all_at(&vec![0x7f; ChunkSize::RAM.bytes() as usize], 0)
                    .unwrap();
                let rebuilt = StreamHasher::new(ChunkSize::RAM)
                    .hash_open_file(&source, length)
                    .unwrap()
                    .map;
                assert_eq!(changed.map, rebuilt);
            }
        }
    }

    #[test]
    fn publication_deduplicates_nodes_and_root_without_replacing_inodes() {
        let directory = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&directory.path().join("images")).unwrap();
        let map = StreamHasher::new(ChunkSize::RAM)
            .hash_reader(b"one short tail".as_slice())
            .unwrap();
        let (first, first_guard) = pool.publish_map_for_catalog(&map).unwrap();
        assert_eq!(first.len(), 6);
        let inodes: Vec<_> = first
            .iter()
            .map(|node| {
                std::fs::metadata(pool.object_path(&node.digest))
                    .unwrap()
                    .ino()
            })
            .collect();
        let (second, second_guard) = pool.publish_map_for_catalog(&map).unwrap();
        assert_eq!(first.len(), second.len());
        for (node, inode) in second.iter().zip(inodes) {
            assert_eq!(
                std::fs::metadata(pool.object_path(&node.digest))
                    .unwrap()
                    .ino(),
                inode
            );
        }
        let authority = pool
            .map_authority(Arc::new(pool.lock_roots_shared().unwrap()))
            .unwrap();
        let admitted = pool
            .load_map(
                ObjectDigest::from_sha256(*map.id().as_bytes()),
                StreamRole::Ram,
                authority,
            )
            .unwrap();
        assert_eq!(admitted, map);
        assert_eq!(admitted.lookup(0).unwrap(), map.lookup(0).unwrap());
        drop((first_guard, second_guard));
    }

    #[test]
    fn corrupt_and_missing_real_nodes_report_digest_height_and_coverage() {
        for height in 0..5 {
            for missing in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let pool = StoragePool::open(&directory.path().join("images")).unwrap();
                let source = tempfile::tempfile().unwrap();
                source.write_all_at(b"nonzero", 0).unwrap();
                let map = StreamHasher::new(ChunkSize::RAM)
                    .hash_open_file(&source, 7)
                    .unwrap()
                    .map;
                let (_nodes, _guard) = pool.publish_map_for_catalog(&map).unwrap();
                let target = map
                    .nodes()
                    .map(Result::unwrap)
                    .find(|node| node.height == height)
                    .unwrap();
                let path = pool.object_path(&target.digest);
                let authority = pool
                    .map_authority(Arc::new(pool.lock_roots_shared().unwrap()))
                    .unwrap();
                let admitted =
                    AuthenticatedMap::from_admitted_root(*map.root(), StreamRole::Ram, authority)
                        .unwrap();
                if missing {
                    std::fs::remove_file(&path).unwrap();
                } else {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .write_all_at(&[0xff], 0)
                        .unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                }
                assert!(
                    matches!(admitted.lookup(0), Err(StorageError::Map(MapError::Node { digest, height: actual, first_index: 0, end_index: 1, source })) if actual == height && digest.as_bytes() == target.digest.as_bytes() && if missing { matches!(*source, MapError::MissingNode(_)) } else { matches!(*source, MapError::DigestMismatch { .. }) })
                );
                assert!(
                    matches!(StreamHasher::new(ChunkSize::RAM).verify_expected_map(&source, &admitted), Err(ExpectedMapError::Metadata { height: actual, start: 0, end: 7, .. }) if actual == height)
                );
            }
        }
    }

    #[test]
    fn wrong_role_profile_is_rejected_before_node_access() {
        let map = StreamHasher::new(ChunkSize::DISK)
            .hash_reader(b"bytes".as_slice())
            .unwrap();
        assert!(matches!(
            AuthenticatedMap::from_admitted_root(
                *map.root(),
                StreamRole::Ram,
                Arc::clone(&map.authority)
            ),
            Err(StorageError::Map(MapError::ProfileMismatch { .. }))
        ));
        let source = tempfile::tempfile().unwrap();
        source.write_all_at(b"bytes", 0).unwrap();
        assert!(matches!(
            StreamHasher::new(ChunkSize::RAM).verify_expected_map(&source, &map),
            Err(ExpectedMapError::Profile { .. })
        ));
    }
    #[test]
    fn distinct_roots_share_staged_node_authority_without_copying() {
        let ram = StreamHasher::new(ChunkSize::RAM)
            .hash_reader(b"shared short tail".as_slice())
            .unwrap();
        let root = vm_spec::stream_map::StreamRoot::new(
            ram.length(),
            ChunkSize::DISK,
            ram.root().tree_digest(),
        )
        .unwrap();
        let disk = ram.with_root(root, StreamRole::Disk).unwrap();
        assert!(Arc::ptr_eq(&ram.authority, &disk.authority));
        assert!(Arc::ptr_eq(
            ram.staged.as_ref().unwrap(),
            disk.staged.as_ref().unwrap()
        ));
        assert_eq!(ram.lookup(0).unwrap(), disk.lookup(0).unwrap());
        assert_ne!(ram.id(), disk.id());
    }
    #[test]
    fn adopted_capture_nodes_do_not_allocate_a_second_metadata_spool() {
        let directory = tempfile::tempdir().unwrap();
        let original = StreamHasher::new(ChunkSize::RAM)
            .hash_reader(b"capture node bytes".as_slice())
            .unwrap();
        for node in original.nodes() {
            let node = node.unwrap();
            std::fs::write(directory.path().join(node.digest.hex()), node.bytes).unwrap();
            std::fs::set_permissions(
                directory.path().join(node.digest.hex()),
                std::fs::Permissions::from_mode(0o400),
            )
            .unwrap();
        }
        let writer = MapNodeWriter::adopt_directory(directory.path()).unwrap();
        assert_eq!(writer.file.metadata().unwrap().len(), 0);
        assert!(writer.directory.is_some());
        let produced = writer
            .finish(*original.root(), StreamRole::Ram, None)
            .unwrap();
        assert_eq!(produced.new_nodes().len(), 5);
        assert_eq!(produced.map.lookup(0).unwrap(), original.lookup(0).unwrap());
        assert_eq!(
            produced
                .map
                .staged
                .as_ref()
                .unwrap()
                .file
                .metadata()
                .unwrap()
                .len(),
            0
        );
        let pool_directory = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&pool_directory.path().join("images")).unwrap();
        let (nodes, _roots) = pool.publish_map_for_catalog(&produced.map).unwrap();
        assert_eq!(nodes.len(), 6);
    }
}
