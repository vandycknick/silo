//! Canonical stream-map v2: fixed-depth, 64-way sparse Merkle maps.
//!
//! All integers are unsigned little-endian; digests are raw SHA-256 bytes.
//! Bit zero is the lowest slot. Digests follow set bits in ascending slot order.
//!
//! ```text
//! root (25 or 57 bytes)
//! +----------------------+-------------+------------+--------------+-------------+
//! | "silo:stream:v2\n" 15 | shift: u8   | length:u64 | present: u8  | digest: 32? |
//! +----------------------+-------------+------------+--------------+-------------+
//! branch (35 + 32 * popcount bytes, at most 2083)
//! +---------------------------------+------------+-------------+---------------+
//! | "silo:stream-map:branch:v2\n" 26 | height: u8 | bitmap: u64 | child digests |
//! +---------------------------------+------------+-------------+---------------+
//! leaf (32 + 32 * popcount bytes, at most 2080)
//! +-------------------------------+-------------+-------------------------------+
//! | "silo:stream-map:leaf:v2\n" 24 | bitmap: u64 | raw decoded-byte SHA digests  |
//! +-------------------------------+-------------+-------------------------------+
//! ```
//!
//! Heights are always 4, 3, 2, 1, 0, even for one chunk. Absent slots mean zero,
//! never missing storage. Empty nodes and explicit default-subtree references
//! are forbidden. The root authenticates length and chunk shift, not role.
//! [`StreamRole`] is an external admission policy, not another identity field.
//!
//! Nodes do not encode indices or tail lengths: standalone decoding cannot
//! validate those facts. Traversals validate position against their root;
//! [`StreamRoot::classify_chunk`] validates exact decoded lengths and zeros.
//! Digest-only construction requires the caller's byte-admission authority.
//! In particular, a digest cannot prove that bytes are nonzero. A zero-valued
//! 32-byte digest is nevertheless rejected as an invalid present value.
//!
//! Construction and updates hold at most five 64-slot nodes. Updates preserve
//! geometry and rebuild each touched ancestor once, child first. A failed
//! input/store operation can leave unreferenced staged nodes; the caller owns
//! their cleanup and publication transaction. Sources must represent immutable
//! content-addressed storage. An admitted predecessor supplies authority for
//! unvisited subtrees; use [`PresentChunks`] to authenticate an entire import.
//! No operation here owns node retention, payload storage, or dirty coverage.

use std::fmt;
use std::io::{self, Write};
use std::ops::Range;

use sha2::{Digest, Sha256};

use crate::capture::{is_all_zero, Sha256Digest};

pub const FANOUT: usize = 64;
pub const TREE_DEPTH: u8 = 5;
pub const ROOT_HEIGHT: u8 = TREE_DEPTH - 1;
pub const MAX_INDICES: u64 = 1 << 30;
pub const MAX_STREAM_BYTES: u64 = 4 << 40;
pub const MAX_RAM_BYTES: u64 = 1 << 40;
pub const MAX_TRANSPORT_BYTES: u64 = 1 << 40;
pub const MAX_LEAF_BYTES: usize = 2080;
pub const MAX_NODE_BYTES: usize = 2083;
pub const EMPTY_ROOT_BYTES: usize = 25;
pub const MAX_ROOT_BYTES: usize = 57;

const ROOT_PREFIX: &[u8] = b"silo:stream:v2\n";
const LEAF_PREFIX: &[u8] = b"silo:stream-map:leaf:v2\n";
const BRANCH_PREFIX: &[u8] = b"silo:stream-map:branch:v2\n";

/// Closed errors, including storage I/O without erasing its cause.
#[derive(Debug)]
pub enum MapError {
    Io(io::Error),
    Node {
        digest: Sha256Digest,
        height: u8,
        first_index: u64,
        end_index: u64,
        source: Box<MapError>,
    },
    InvalidMagic,
    InvalidChunkShift(u8),
    LengthLimit {
        length: u64,
        maximum: u64,
    },
    InvalidTreeFlag(u8),
    EmptyStreamWithTree,
    Truncated,
    TrailingBytes,
    InvalidHeight(u8),
    WrongHeight {
        expected: u8,
        actual: u8,
    },
    EmptyNode,
    ZeroDigest,
    ExplicitDefault {
        height: u8,
    },
    InvalidSlot(u8),
    DuplicateIndex(u64),
    UnsortedIndex {
        previous: u64,
        next: u64,
    },
    IndexOutOfRange {
        index: u64,
        count: u64,
    },
    ArithmeticOverflow,
    DigestMismatch {
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    MissingNode(Sha256Digest),
    TailLength {
        index: u64,
        expected: u64,
        actual: u64,
    },
    ProfileMismatch {
        expected: ChunkSize,
        actual: ChunkSize,
    },
    ChunkMismatch {
        index: u64,
        expected: Chunk,
        actual: Chunk,
    },
    NodeTooLarge(usize),
}

impl fmt::Display for MapError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "map I/O: {error}"),
            Self::Node {
                digest,
                height,
                first_index,
                end_index,
                source,
            } => write!(
                output,
                "map node {digest} height {height} indices {first_index}..{end_index}: {source}"
            ),
            Self::InvalidMagic => output.write_str("invalid stream-map domain or version"),
            Self::InvalidChunkShift(shift) => write!(output, "invalid chunk shift {shift}"),
            Self::LengthLimit { length, maximum } => {
                write!(output, "length {length} exceeds {maximum}")
            }
            Self::InvalidTreeFlag(flag) => write!(output, "invalid tree-present flag {flag}"),
            Self::EmptyStreamWithTree => output.write_str("empty stream has a tree"),
            Self::Truncated => output.write_str("truncated stream-map record"),
            Self::TrailingBytes => output.write_str("trailing stream-map bytes"),
            Self::InvalidHeight(height) => write!(output, "invalid node height {height}"),
            Self::WrongHeight { expected, actual } => {
                write!(output, "expected height {expected}, got {actual}")
            }
            Self::EmptyNode => output.write_str("stored node is empty"),
            Self::ZeroDigest => output.write_str("present entry has a zero-valued digest"),
            Self::ExplicitDefault { height } => {
                write!(output, "explicit default subtree at height {height}")
            }
            Self::InvalidSlot(slot) => write!(output, "invalid node slot {slot}"),
            Self::DuplicateIndex(index) => write!(output, "duplicate index {index}"),
            Self::UnsortedIndex { previous, next } => {
                write!(output, "index {next} follows {previous} out of order")
            }
            Self::IndexOutOfRange { index, count } => {
                write!(output, "index {index} outside 0..{count}")
            }
            Self::ArithmeticOverflow => output.write_str("stream-map arithmetic overflow"),
            Self::DigestMismatch { expected, actual } => write!(
                output,
                "node digest mismatch: expected {expected}, got {actual}"
            ),
            Self::MissingNode(digest) => write!(output, "missing map node {digest}"),
            Self::TailLength {
                index,
                expected,
                actual,
            } => write!(
                output,
                "chunk {index} requires {expected} bytes, got {actual}"
            ),
            Self::ProfileMismatch { expected, actual } => write!(
                output,
                "expected chunk shift {}, got {}",
                expected.shift(),
                actual.shift()
            ),
            Self::ChunkMismatch {
                index,
                expected,
                actual,
            } => write!(
                output,
                "chunk {index} mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::NodeTooLarge(length) => {
                write!(output, "node length {length} exceeds {MAX_NODE_BYTES}")
            }
        }
    }
}

impl std::error::Error for MapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Node { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for MapError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Validated identity geometry. The binary codec admits shifts 12 through 23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSize(u8);

impl ChunkSize {
    pub const RAM: Self = Self(16);
    pub const DISK: Self = Self(23);

    pub fn from_bytes(bytes: u64) -> Result<Self, MapError> {
        if !bytes.is_power_of_two() {
            return Err(MapError::InvalidChunkShift(0));
        }
        Self::from_shift(bytes.trailing_zeros() as u8)
    }
    pub fn from_shift(shift: u8) -> Result<Self, MapError> {
        if !(12..=23).contains(&shift) {
            return Err(MapError::InvalidChunkShift(shift));
        }
        Ok(Self(shift))
    }

    pub const fn shift(self) -> u8 {
        self.0
    }

    pub const fn bytes(self) -> u64 {
        1u64 << self.0
    }
}

/// Initial role policy. Role is intentionally not serialized in a map root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Ram,
    Disk,
    Pack,
    Lower,
    ObjectTransport,
}

impl StreamRole {
    pub const fn chunk_size(self) -> ChunkSize {
        match self {
            Self::Ram => ChunkSize::RAM,
            Self::Disk | Self::Pack | Self::Lower | Self::ObjectTransport => ChunkSize::DISK,
        }
    }
}

/// Semantic chunk value, not a reference to a retained payload object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chunk {
    Zero,
    Data(Sha256Digest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentChunk {
    pub index: u64,
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkChange {
    pub index: u64,
    pub value: Chunk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkDifference {
    pub index: u64,
    pub before: Chunk,
    pub after: Chunk,
}

/// Immutable authenticated header. Constructors do not admit its node closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRoot {
    length: u64,
    chunk_size: ChunkSize,
    tree: Option<Sha256Digest>,
}

impl StreamRoot {
    pub fn new(
        length: u64,
        chunk_size: ChunkSize,
        tree: Option<Sha256Digest>,
    ) -> Result<Self, MapError> {
        index_range(length, chunk_size)?;
        if let Some(digest) = tree {
            if length == 0 {
                return Err(MapError::EmptyStreamWithTree);
            }
            validate_digest(digest)?;
            reject_default(digest, ROOT_HEIGHT)?;
        }
        Ok(Self {
            length,
            chunk_size,
            tree,
        })
    }

    pub fn empty(length: u64, chunk_size: ChunkSize) -> Result<Self, MapError> {
        Self::new(length, chunk_size, None)
    }

    pub const fn length(&self) -> u64 {
        self.length
    }

    pub const fn chunk_size(&self) -> ChunkSize {
        self.chunk_size
    }

    pub const fn tree_digest(&self) -> Option<Sha256Digest> {
        self.tree
    }

    pub fn chunk_count(&self) -> u64 {
        self.length.div_ceil(self.chunk_size.bytes())
    }

    pub fn validate_role(&self, role: StreamRole) -> Result<(), MapError> {
        let expected = role.chunk_size();
        if self.chunk_size != expected {
            return Err(MapError::ProfileMismatch {
                expected,
                actual: self.chunk_size,
            });
        }
        let maximum = match role {
            StreamRole::Ram => MAX_RAM_BYTES,
            StreamRole::ObjectTransport => MAX_TRANSPORT_BYTES,
            _ => MAX_STREAM_BYTES,
        };
        check_length(self.length, maximum)
    }

    /// Transport admission is a separate limit even for disk/RAM roles.
    pub fn validate_transport(&self) -> Result<(), MapError> {
        check_length(self.length, MAX_TRANSPORT_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MapError> {
        let mut input = Decoder::new(bytes);
        input.prefix(ROOT_PREFIX)?;
        let chunk_size = ChunkSize::from_shift(input.byte()?)?;
        let length = input.u64()?;
        let tree = match input.byte()? {
            0 => None,
            1 => Some(input.digest()?),
            flag => return Err(MapError::InvalidTreeFlag(flag)),
        };
        input.finish()?;
        Self::new(length, chunk_size, tree)
    }

    pub fn write_canonical(&self, mut output: impl Write) -> Result<(), MapError> {
        output.write_all(ROOT_PREFIX)?;
        output.write_all(&[self.chunk_size.shift()])?;
        output.write_all(&self.length.to_le_bytes())?;
        output.write_all(&[u8::from(self.tree.is_some())])?;
        if let Some(digest) = self.tree {
            output.write_all(digest.as_bytes())?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MapError> {
        let mut bytes = Vec::with_capacity(MAX_ROOT_BYTES);
        self.write_canonical(&mut bytes)?;
        Ok(bytes)
    }

    pub fn id(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(ROOT_PREFIX);
        hash.update([self.chunk_size.shift()]);
        hash.update(self.length.to_le_bytes());
        hash.update([u8::from(self.tree.is_some())]);
        if let Some(digest) = self.tree {
            hash.update(digest.as_bytes());
        }
        Sha256Digest::from_bytes(hash.finalize().into())
    }

    pub fn chunk_range(&self, index: u64) -> Result<Range<u64>, MapError> {
        check_index(index, self.chunk_count())?;
        let start = index
            .checked_mul(self.chunk_size.bytes())
            .ok_or(MapError::ArithmeticOverflow)?;
        let end = start
            .checked_add(self.chunk_size.bytes())
            .ok_or(MapError::ArithmeticOverflow)?
            .min(self.length);
        Ok(start..end)
    }

    /// Classifies actual decoded bytes, enforcing short-tail geometry first.
    pub fn classify_chunk(&self, index: u64, bytes: &[u8]) -> Result<Chunk, MapError> {
        let range = self.chunk_range(index)?;
        let expected = range.end - range.start;
        let actual = u64::try_from(bytes.len()).map_err(|_| MapError::ArithmeticOverflow)?;
        if actual != expected {
            return Err(MapError::TailLength {
                index,
                expected,
                actual,
            });
        }
        if is_all_zero(bytes) {
            Ok(Chunk::Zero)
        } else {
            let digest = Sha256Digest::of_bytes(bytes);
            validate_digest(digest)?;
            Ok(Chunk::Data(digest))
        }
    }

    /// Admit a claimed value against actual decoded bytes. In particular, a
    /// claimed SHA-256 of zero bytes is rejected: zero must be implicit.
    pub fn verify_chunk(&self, index: u64, expected: Chunk, bytes: &[u8]) -> Result<(), MapError> {
        let actual = self.classify_chunk(index, bytes)?;
        if actual != expected {
            return Err(MapError::ChunkMismatch {
                index,
                expected,
                actual,
            });
        }
        Ok(())
    }

    pub fn lookup(&self, index: u64, source: &mut impl NodeSource) -> Result<Chunk, MapError> {
        check_index(index, self.chunk_count())?;
        let mut digest = self.tree;
        let mut base = 0;
        for height in (0..TREE_DEPTH).rev() {
            let Some(present) = digest else {
                return Ok(Chunk::Zero);
            };
            let node = read_node(source, present, height, base, self.chunk_count())?;
            let slot = slot_at(index, height);
            digest = node.entry(slot);
            if height == 0 {
                return Ok(chunk_value(digest));
            }
            base = child_base(base, height, slot)?;
        }
        Ok(Chunk::Zero)
    }

    /// Checks the unique end-boundary path. Other siblings require previously
    /// admitted authority; a fresh import must traverse `present_chunks` too.
    pub fn validate_boundary(&self, source: &mut impl NodeSource) -> Result<(), MapError> {
        if self.chunk_count() != 0 {
            self.lookup(self.chunk_count() - 1, source)?;
        }
        Ok(())
    }

    pub fn present_chunks<'a>(&self, source: &'a mut impl NodeSource) -> PresentChunks<'a> {
        self.present_chunks_from(0, source)
    }

    pub fn present_chunks_from<'a>(
        &self,
        first: u64,
        source: &'a mut impl NodeSource,
    ) -> PresentChunks<'a> {
        let mut cursor = self.present_chunk_cursor();
        cursor.first = first;
        PresentChunks { cursor, source }
    }

    pub fn present_chunk_cursor(&self) -> PresentChunkCursor {
        PresentChunkCursor {
            root: *self,
            stack: Vec::with_capacity(usize::from(TREE_DEPTH)),
            started: false,
            failed: false,
            first: 0,
            end: self.chunk_count(),
        }
    }

    pub fn zero_range_changes<'a>(
        &self,
        first: u64,
        count: u64,
        source: &'a mut impl NodeSource,
    ) -> Result<ZeroRangeChanges<'a>, MapError> {
        let end = first
            .checked_add(count)
            .ok_or(MapError::ArithmeticOverflow)?;
        if end > self.chunk_count() {
            return Err(MapError::IndexOutOfRange {
                index: end,
                count: self.chunk_count(),
            });
        }
        let mut chunks = self.present_chunks_from(first, source);
        chunks.cursor.end = end;
        Ok(ZeroRangeChanges { chunks })
    }

    /// Sorted unique changes only. Geometry is unchanged; resize needs explicit
    /// tail reauthentication and is deliberately not an implicit update.
    pub fn update_sorted(
        &self,
        changes: impl IntoIterator<Item = Result<ChunkChange, MapError>>,
        source: &mut impl NodeSource,
        sink: &mut impl NodeSink,
    ) -> Result<Self, MapError> {
        let mut editor = Editor {
            root: *self,
            cursor: ChangeCursor::new(changes.into_iter(), self.chunk_count())?,
            source: Some(source),
            sink,
        };
        if editor.cursor.next.is_none() {
            return Ok(*self);
        }
        let tree = editor.subtree(ROOT_HEIGHT, 0, self.tree)?;
        Self::new(self.length, self.chunk_size, tree)
    }
}

/// Stored pages have fixed-size scratch and no unbounded child collection.
/// Height zero identifies a leaf; heights one through four identify branches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamNode {
    height: u8,
    slots: [Option<Sha256Digest>; FANOUT],
}

impl StreamNode {
    /// Entries must be unique, sorted slots. Repeated digest values at distinct
    /// slots are legal, including identical child subtrees.
    pub fn new(
        height: u8,
        entries: impl IntoIterator<Item = (u8, Sha256Digest)>,
    ) -> Result<Self, MapError> {
        check_height(height)?;
        let mut node = Self::empty(height);
        let mut previous = None;
        for (slot, digest) in entries {
            if usize::from(slot) >= FANOUT {
                return Err(MapError::InvalidSlot(slot));
            }
            check_order(previous, u64::from(slot))?;
            node.set(slot, Some(digest))?;
            previous = Some(u64::from(slot));
        }
        if node.is_empty() {
            return Err(MapError::EmptyNode);
        }
        Ok(node)
    }

    pub const fn height(&self) -> u8 {
        self.height
    }

    pub fn bitmap(&self) -> u64 {
        self.entries()
            .fold(0, |bitmap, (slot, _)| bitmap | (1u64 << slot))
    }

    pub fn entries(&self) -> impl Iterator<Item = (u8, Sha256Digest)> + '_ {
        self.slots
            .iter()
            .zip(0u8..64)
            .filter_map(|(digest, slot)| digest.map(|digest| (slot, digest)))
    }

    pub fn entry(&self, slot: u8) -> Option<Sha256Digest> {
        self.slots.get(usize::from(slot)).copied().flatten()
    }

    pub fn decode(bytes: &[u8], expected_height: u8) -> Result<Self, MapError> {
        check_height(expected_height)?;
        if bytes.len() > MAX_NODE_BYTES {
            return Err(MapError::NodeTooLarge(bytes.len()));
        }
        let mut input = Decoder::new(bytes);
        let height = if bytes.starts_with(LEAF_PREFIX) {
            input.prefix(LEAF_PREFIX)?;
            0
        } else {
            input.prefix(BRANCH_PREFIX)?;
            let height = input.byte()?;
            if height == 0 {
                return Err(MapError::InvalidHeight(height));
            }
            check_height(height)?;
            height
        };
        if height != expected_height {
            return Err(MapError::WrongHeight {
                expected: expected_height,
                actual: height,
            });
        }
        let bitmap = input.u64()?;
        if bitmap == 0 {
            return Err(MapError::EmptyNode);
        }
        let mut node = Self::empty(height);
        for slot in 0u8..64 {
            if bitmap & (1u64 << slot) != 0 {
                node.set(slot, Some(input.digest()?))?;
            }
        }
        input.finish()?;
        Ok(node)
    }

    pub fn write_canonical(&self, mut output: impl Write) -> Result<(), MapError> {
        if self.is_empty() {
            return Err(MapError::EmptyNode);
        }
        if self.height == 0 {
            output.write_all(LEAF_PREFIX)?;
        } else {
            output.write_all(BRANCH_PREFIX)?;
            output.write_all(&[self.height])?;
        }
        output.write_all(&self.bitmap().to_le_bytes())?;
        for (_, digest) in self.entries() {
            output.write_all(digest.as_bytes())?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MapError> {
        let mut bytes = Vec::with_capacity(MAX_NODE_BYTES);
        self.write_canonical(&mut bytes)?;
        Ok(bytes)
    }

    fn empty(height: u8) -> Self {
        Self {
            height,
            slots: [None; FANOUT],
        }
    }

    fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    fn set(&mut self, slot: u8, digest: Option<Sha256Digest>) -> Result<(), MapError> {
        if let Some(digest) = digest {
            validate_digest(digest)?;
            if self.height != 0 {
                reject_default(digest, self.height - 1)?;
            }
        }
        let entry = self
            .slots
            .get_mut(usize::from(slot))
            .ok_or(MapError::InvalidSlot(slot))?;
        *entry = digest;
        Ok(())
    }

    fn validate_range(&self, base: u64, count: u64) -> Result<(), MapError> {
        for (slot, _) in self.entries() {
            check_index(child_base(base, self.height, slot)?, count)?;
        }
        Ok(())
    }
}

/// Read immutable canonical bytes into caller-owned, bounded scratch. Return
/// the exact stored length, or `NodeTooLarge`; never truncate an oversized node.
pub trait NodeSource {
    fn read_node(
        &mut self,
        digest: Sha256Digest,
        output: &mut [u8; MAX_NODE_BYTES],
    ) -> Result<usize, MapError>;
}

/// Publish one canonical node child-first. The codec checks the returned digest
/// against the bytes it supplied. Payload digests are not passed to this sink.
pub trait NodeSink {
    fn write_node(&mut self, bytes: &[u8]) -> Result<Sha256Digest, MapError>;
}

/// Full streaming frontier construction from admitted, ordered present chunks.
/// Missing ranges are implicit zero. No node source or stream-length allocation.
pub fn build_sorted(
    length: u64,
    chunk_size: ChunkSize,
    chunks: impl IntoIterator<Item = Result<PresentChunk, MapError>>,
    sink: &mut impl NodeSink,
) -> Result<StreamRoot, MapError> {
    let root = StreamRoot::empty(length, chunk_size)?;
    let changes = chunks.into_iter().map(|entry| {
        entry.map(|entry| ChunkChange {
            index: entry.index,
            value: Chunk::Data(entry.digest),
        })
    });
    let mut editor = Editor {
        root,
        cursor: ChangeCursor::new(changes, root.chunk_count())?,
        source: None,
        sink,
    };
    let tree = if editor.cursor.next.is_some() {
        editor.subtree(ROOT_HEIGHT, 0, None)?
    } else {
        None
    };
    StreamRoot::new(length, chunk_size, tree)
}

/// Valid identity-index range, with all admission arithmetic checked.
pub fn index_range(length: u64, chunk_size: ChunkSize) -> Result<Range<u64>, MapError> {
    check_length(length, MAX_STREAM_BYTES)?;
    let count = length
        .checked_add(chunk_size.bytes() - 1)
        .ok_or(MapError::ArithmeticOverflow)?
        / chunk_size.bytes();
    if count > MAX_INDICES {
        return Err(MapError::IndexOutOfRange {
            index: count,
            count: MAX_INDICES,
        });
    }
    Ok(0..count)
}

/// Dense upper bound on stored nodes, excluding the root object and dedup.
pub fn worst_case_node_count(length: u64, chunk_size: ChunkSize) -> Result<u64, MapError> {
    let mut width = index_range(length, chunk_size)?.end;
    let mut total = 0u64;
    for _ in 0..TREE_DEPTH {
        width = width.checked_add(63).ok_or(MapError::ArithmeticOverflow)? / 64;
        total = total
            .checked_add(width)
            .ok_or(MapError::ArithmeticOverflow)?;
    }
    Ok(total)
}

/// Conservative byte admission including a root, before object-store overhead.
pub fn worst_case_map_bytes(length: u64, chunk_size: ChunkSize) -> Result<u64, MapError> {
    worst_case_node_count(length, chunk_size)?
        .checked_mul(MAX_NODE_BYTES as u64)
        .and_then(|bytes| bytes.checked_add(MAX_ROOT_BYTES as u64))
        .ok_or(MapError::ArithmeticOverflow)
}

/// Conceptual default hashes. These bytes are never published as stored nodes.
/// Golden constants avoid rehashing default nodes on every accessed entry.
pub fn default_digest(height: u8) -> Result<Sha256Digest, MapError> {
    let bytes = match height {
        0 => [
            0x3b, 0xe8, 0x3e, 0xc3, 0xd9, 0xd6, 0x34, 0xa7, 0x51, 0xb6, 0x11, 0x3d, 0x59, 0x08,
            0xa4, 0x16, 0xcb, 0x39, 0x82, 0x7b, 0x68, 0x68, 0x74, 0x44, 0xb9, 0xae, 0x30, 0x0c,
            0x28, 0x55, 0x07, 0xca,
        ],
        1 => [
            0xca, 0xc0, 0x5d, 0x16, 0xcc, 0xaf, 0x3e, 0x4a, 0x21, 0x9c, 0x9e, 0x26, 0x63, 0xb2,
            0x6e, 0xc5, 0xe2, 0xf6, 0xf3, 0xdd, 0x86, 0x61, 0xe6, 0xaf, 0x4d, 0x50, 0x52, 0x15,
            0x7e, 0x53, 0x3c, 0x85,
        ],
        2 => [
            0x17, 0x02, 0xb3, 0xfd, 0x4f, 0x16, 0x7c, 0x8a, 0xd4, 0x90, 0x97, 0x06, 0xff, 0x9b,
            0xed, 0xd3, 0xdd, 0x36, 0x65, 0x68, 0xfb, 0x61, 0xce, 0xda, 0xca, 0xa9, 0x21, 0x79,
            0x0c, 0x4b, 0x84, 0x8f,
        ],
        3 => [
            0x43, 0xd4, 0xd2, 0xa9, 0x52, 0xe7, 0x19, 0xcc, 0x57, 0x4b, 0x80, 0xff, 0x59, 0x27,
            0xe6, 0xae, 0xc5, 0xc5, 0xad, 0x3b, 0x0f, 0xb4, 0x72, 0xe4, 0x76, 0x14, 0xde, 0x6f,
            0xa4, 0x11, 0xf1, 0xd9,
        ],
        4 => [
            0xba, 0xe1, 0xce, 0x1a, 0x9f, 0x92, 0x98, 0x88, 0xf1, 0x65, 0xaf, 0xdc, 0x1d, 0xd0,
            0x25, 0xe6, 0xb0, 0x79, 0x22, 0x3b, 0xde, 0x18, 0x46, 0x3c, 0x02, 0x4b, 0x7d, 0x21,
            0xb4, 0xfc, 0x56, 0xe9,
        ],
        _ => return Err(MapError::InvalidHeight(height)),
    };
    Ok(Sha256Digest::from_bytes(bytes))
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], MapError> {
        let value = self.remaining.get(..length).ok_or(MapError::Truncated)?;
        self.remaining = self.remaining.get(length..).ok_or(MapError::Truncated)?;
        Ok(value)
    }

    fn prefix(&mut self, prefix: &[u8]) -> Result<(), MapError> {
        if self.take(prefix.len())? != prefix {
            return Err(MapError::InvalidMagic);
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, MapError> {
        self.take(1)?.first().copied().ok_or(MapError::Truncated)
    }

    fn u64(&mut self) -> Result<u64, MapError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| MapError::Truncated)?,
        ))
    }

    fn digest(&mut self) -> Result<Sha256Digest, MapError> {
        Ok(Sha256Digest::from_bytes(
            self.take(32)?.try_into().map_err(|_| MapError::Truncated)?,
        ))
    }

    fn finish(self) -> Result<(), MapError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(MapError::TrailingBytes)
        }
    }
}

fn check_height(height: u8) -> Result<(), MapError> {
    if height >= TREE_DEPTH {
        Err(MapError::InvalidHeight(height))
    } else {
        Ok(())
    }
}

fn check_length(length: u64, maximum: u64) -> Result<(), MapError> {
    if length > maximum {
        Err(MapError::LengthLimit { length, maximum })
    } else {
        Ok(())
    }
}

fn check_index(index: u64, count: u64) -> Result<(), MapError> {
    if index >= count {
        Err(MapError::IndexOutOfRange { index, count })
    } else {
        Ok(())
    }
}

fn check_order(previous: Option<u64>, next: u64) -> Result<(), MapError> {
    match previous {
        Some(previous) if previous == next => Err(MapError::DuplicateIndex(next)),
        Some(previous) if previous > next => Err(MapError::UnsortedIndex { previous, next }),
        _ => Ok(()),
    }
}

fn validate_digest(digest: Sha256Digest) -> Result<(), MapError> {
    if digest.as_bytes().iter().all(|byte| *byte == 0) {
        Err(MapError::ZeroDigest)
    } else {
        Ok(())
    }
}

fn reject_default(digest: Sha256Digest, height: u8) -> Result<(), MapError> {
    if digest == default_digest(height)? {
        Err(MapError::ExplicitDefault { height })
    } else {
        Ok(())
    }
}

fn slot_at(index: u64, height: u8) -> u8 {
    ((index >> (6 * u32::from(height))) & 63) as u8
}

fn child_base(base: u64, height: u8, slot: u8) -> Result<u64, MapError> {
    let width = 1u64
        .checked_shl(6 * u32::from(height))
        .ok_or(MapError::ArithmeticOverflow)?;
    let offset = width
        .checked_mul(u64::from(slot))
        .ok_or(MapError::ArithmeticOverflow)?;
    base.checked_add(offset).ok_or(MapError::ArithmeticOverflow)
}

fn chunk_value(digest: Option<Sha256Digest>) -> Chunk {
    digest.map_or(Chunk::Zero, Chunk::Data)
}

fn read_node(
    source: &mut dyn NodeSource,
    digest: Sha256Digest,
    height: u8,
    base: u64,
    count: u64,
) -> Result<StreamNode, MapError> {
    let result = (|| {
        let mut bytes = [0u8; MAX_NODE_BYTES];
        let length = source.read_node(digest, &mut bytes)?;
        let bytes = bytes.get(..length).ok_or(MapError::NodeTooLarge(length))?;
        let actual = Sha256Digest::of_bytes(bytes);
        if actual != digest {
            return Err(MapError::DigestMismatch {
                expected: digest,
                actual,
            });
        }
        let node = StreamNode::decode(bytes, height)?;
        node.validate_range(base, count)?;
        Ok(node)
    })();
    result.map_err(|source| MapError::Node {
        digest,
        height,
        first_index: base,
        end_index: base
            .saturating_add(1u64 << (6 * u32::from(height + 1)))
            .min(count),
        source: Box::new(source),
    })
}

struct ChangeCursor<I> {
    input: I,
    next: Option<ChunkChange>,
    previous: Option<u64>,
    count: u64,
}

impl<I: Iterator<Item = Result<ChunkChange, MapError>>> ChangeCursor<I> {
    fn new(input: I, count: u64) -> Result<Self, MapError> {
        let mut cursor = Self {
            input,
            next: None,
            previous: None,
            count,
        };
        cursor.advance()?;
        Ok(cursor)
    }

    fn advance(&mut self) -> Result<(), MapError> {
        self.next = self.input.next().transpose()?;
        if let Some(change) = self.next {
            check_index(change.index, self.count)?;
            check_order(self.previous, change.index)?;
            if let Chunk::Data(digest) = change.value {
                validate_digest(digest)?;
            }
            self.previous = Some(change.index);
        }
        Ok(())
    }
}

struct Editor<'a, I, W> {
    root: StreamRoot,
    cursor: ChangeCursor<I>,
    source: Option<&'a mut dyn NodeSource>,
    sink: &'a mut W,
}

impl<I: Iterator<Item = Result<ChunkChange, MapError>>, W: NodeSink> Editor<'_, I, W> {
    fn subtree(
        &mut self,
        height: u8,
        base: u64,
        old: Option<Sha256Digest>,
    ) -> Result<Option<Sha256Digest>, MapError> {
        let mut node = match old {
            Some(digest) => {
                let source = self
                    .source
                    .as_deref_mut()
                    .ok_or(MapError::MissingNode(digest))?;
                read_node(source, digest, height, base, self.root.chunk_count())?
            }
            None => StreamNode::empty(height),
        };
        let end = base
            .checked_add(
                1u64.checked_shl(6 * (u32::from(height) + 1))
                    .ok_or(MapError::ArithmeticOverflow)?,
            )
            .ok_or(MapError::ArithmeticOverflow)?;
        while let Some(change) = self.cursor.next.filter(|change| change.index < end) {
            let slot = slot_at(change.index, height);
            let value = if height == 0 {
                self.cursor.advance()?;
                match change.value {
                    Chunk::Zero => None,
                    Chunk::Data(digest) => Some(digest),
                }
            } else {
                self.subtree(
                    height - 1,
                    child_base(base, height, slot)?,
                    node.entry(slot),
                )?
            };
            node.set(slot, value)?;
        }
        if node.is_empty() {
            return Ok(None);
        }
        let mut storage = [0u8; MAX_NODE_BYTES];
        let mut output = io::Cursor::new(storage.as_mut_slice());
        node.write_canonical(&mut output)?;
        let length =
            usize::try_from(output.position()).map_err(|_| MapError::ArithmeticOverflow)?;
        let bytes = storage
            .get(..length)
            .ok_or(MapError::NodeTooLarge(length))?;
        let digest = Sha256Digest::of_bytes(bytes);
        if Some(digest) != old {
            let actual = self.sink.write_node(bytes)?;
            if actual != digest {
                return Err(MapError::DigestMismatch {
                    expected: digest,
                    actual,
                });
            }
        }
        Ok(Some(digest))
    }
}

struct WalkFrame {
    node: StreamNode,
    base: u64,
    next_slot: u8,
}

/// Ordered, fallible, fused traversal of present chunks. Each visited node is
/// hash-checked, structurally decoded and range-checked before using its values.
pub struct PresentChunks<'a> {
    cursor: PresentChunkCursor,
    source: &'a mut dyn NodeSource,
}

/// Owned traversal state; the caller supplies its retained source at each step.
pub struct PresentChunkCursor {
    root: StreamRoot,
    stack: Vec<WalkFrame>,
    started: bool,
    failed: bool,
    first: u64,
    end: u64,
}

impl PresentChunkCursor {
    pub fn next_chunk(
        &mut self,
        source: &mut dyn NodeSource,
    ) -> Result<Option<PresentChunk>, MapError> {
        if self.failed {
            return Ok(None);
        }
        let result = self.advance(source);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn advance(&mut self, source: &mut dyn NodeSource) -> Result<Option<PresentChunk>, MapError> {
        if self.first >= self.end {
            return Ok(None);
        }
        if !self.started {
            self.started = true;
            if let Some(digest) = self.root.tree {
                let node = read_node(source, digest, ROOT_HEIGHT, 0, self.root.chunk_count())?;
                self.stack.push(WalkFrame {
                    node,
                    base: 0,
                    next_slot: 0,
                });
            }
        }
        while let Some(mut frame) = self.stack.pop() {
            let next = frame
                .node
                .entries()
                .find(|(slot, _)| *slot >= frame.next_slot);
            let Some((slot, digest)) = next else { continue };
            let height = frame.node.height;
            let base = child_base(frame.base, height, slot)?;
            frame.next_slot = slot + 1;
            self.stack.push(frame);
            let width = 1u64 << (6 * u32::from(height));
            if base >= self.end || base + width <= self.first {
                continue;
            }
            if height == 0 {
                return Ok(Some(PresentChunk {
                    index: base,
                    digest,
                }));
            }
            let node = read_node(source, digest, height - 1, base, self.root.chunk_count())?;
            self.stack.push(WalkFrame {
                node,
                base,
                next_slot: 0,
            });
        }
        Ok(None)
    }
}

impl Iterator for PresentChunks<'_> {
    type Item = Result<PresentChunk, MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.cursor.next_chunk(self.source) {
            Ok(Some(chunk)) => Some(Ok(chunk)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

impl std::iter::FusedIterator for PresentChunks<'_> {}

pub struct ZeroRangeChanges<'a> {
    chunks: PresentChunks<'a>,
}
impl Iterator for ZeroRangeChanges<'_> {
    type Item = Result<ChunkChange, MapError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.chunks.next().map(|chunk| {
            chunk.map(|chunk| ChunkChange {
                index: chunk.index,
                value: Chunk::Zero,
            })
        })
    }
}

struct DiffFrame {
    before: Option<StreamNode>,
    after: Option<StreamNode>,
    height: u8,
    base: u64,
    next_slot: u8,
}

/// Ordered differences in chunk values. Profiles must match; lengths may differ.
/// Length itself remains a root-level difference, not a fictitious chunk edit.
/// Equal subtree digests are never read, even with different source stores.
pub struct MapDiff<'a> {
    before: StreamRoot,
    after: StreamRoot,
    before_source: &'a mut dyn NodeSource,
    after_source: &'a mut dyn NodeSource,
    stack: Vec<DiffFrame>,
    started: bool,
    failed: bool,
}

pub fn diff<'a>(
    before: &StreamRoot,
    after: &StreamRoot,
    before_source: &'a mut impl NodeSource,
    after_source: &'a mut impl NodeSource,
) -> Result<MapDiff<'a>, MapError> {
    if before.chunk_size != after.chunk_size {
        return Err(MapError::ProfileMismatch {
            expected: before.chunk_size,
            actual: after.chunk_size,
        });
    }
    Ok(MapDiff {
        before: *before,
        after: *after,
        before_source,
        after_source,
        stack: Vec::with_capacity(usize::from(TREE_DEPTH)),
        started: false,
        failed: false,
    })
}

impl MapDiff<'_> {
    fn push_pair(
        &mut self,
        before: Option<Sha256Digest>,
        after: Option<Sha256Digest>,
        height: u8,
        base: u64,
    ) -> Result<(), MapError> {
        if before == after {
            return Ok(());
        }
        let before = before
            .map(|digest| {
                read_node(
                    self.before_source,
                    digest,
                    height,
                    base,
                    self.before.chunk_count(),
                )
            })
            .transpose()?;
        let after = after
            .map(|digest| {
                read_node(
                    self.after_source,
                    digest,
                    height,
                    base,
                    self.after.chunk_count(),
                )
            })
            .transpose()?;
        self.stack.push(DiffFrame {
            before,
            after,
            height,
            base,
            next_slot: 0,
        });
        Ok(())
    }

    fn next_difference(&mut self) -> Result<Option<ChunkDifference>, MapError> {
        if !self.started {
            self.started = true;
            self.push_pair(self.before.tree, self.after.tree, ROOT_HEIGHT, 0)?;
        }
        while let Some(mut frame) = self.stack.pop() {
            let mut found = None;
            for slot in frame.next_slot..64 {
                let before = frame.before.as_ref().and_then(|node| node.entry(slot));
                let after = frame.after.as_ref().and_then(|node| node.entry(slot));
                if before != after {
                    found = Some((slot, before, after));
                    break;
                }
            }
            let Some((slot, before, after)) = found else {
                continue;
            };
            let height = frame.height;
            let base = child_base(frame.base, height, slot)?;
            frame.next_slot = slot + 1;
            self.stack.push(frame);
            if height == 0 {
                return Ok(Some(ChunkDifference {
                    index: base,
                    before: chunk_value(before),
                    after: chunk_value(after),
                }));
            }
            self.push_pair(before, after, height - 1, base)?;
        }
        Ok(None)
    }
}

impl Iterator for MapDiff<'_> {
    type Item = Result<ChunkDifference, MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.next_difference() {
            Ok(Some(difference)) => Some(Ok(difference)),
            Ok(None) => None,
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

impl std::iter::FusedIterator for MapDiff<'_> {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::capture::Sha256Digest;
    use crate::stream_map::{
        build_sorted, default_digest, diff, index_range, worst_case_map_bytes,
        worst_case_node_count, Chunk, ChunkChange, ChunkSize, MapError, NodeSink, NodeSource,
        PresentChunk, StreamNode, StreamRole, StreamRoot, MAX_NODE_BYTES, MAX_RAM_BYTES,
        MAX_STREAM_BYTES, MAX_TRANSPORT_BYTES, TREE_DEPTH,
    };

    /// A real content-addressed in-memory store for pure codec unit tests.
    /// Reads and writes use the actual canonical bytes and SHA-256 keys.
    #[derive(Clone, Default)]
    struct NodeStore {
        bytes: BTreeMap<Sha256Digest, Vec<u8>>,
        reads: usize,
        writes: usize,
    }

    impl NodeSource for NodeStore {
        fn read_node(
            &mut self,
            digest: Sha256Digest,
            output: &mut [u8; MAX_NODE_BYTES],
        ) -> Result<usize, MapError> {
            self.reads += 1;
            let bytes = self
                .bytes
                .get(&digest)
                .ok_or(MapError::MissingNode(digest))?;
            let destination = output
                .get_mut(..bytes.len())
                .ok_or(MapError::NodeTooLarge(bytes.len()))?;
            destination.copy_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    impl NodeSink for NodeStore {
        fn write_node(&mut self, bytes: &[u8]) -> Result<Sha256Digest, MapError> {
            self.writes += 1;
            let digest = Sha256Digest::of_bytes(bytes);
            self.bytes.insert(digest, bytes.to_vec());
            Ok(digest)
        }
    }

    fn hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(hex(value).try_into().unwrap())
    }

    const X: &str = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881";
    const Y: &str = "a1fce4363854ff888cff4b8e7875d600c2682390412a8cf79b37d0b11148b0fa";

    fn rebuild(
        length: u64,
        entries: &BTreeMap<u64, Sha256Digest>,
        store: &mut NodeStore,
    ) -> StreamRoot {
        build_sorted(
            length,
            ChunkSize::RAM,
            entries
                .iter()
                .map(|(&index, &digest)| Ok(PresentChunk { index, digest })),
            store,
        )
        .unwrap()
    }

    fn apply(
        root: &StreamRoot,
        changes: impl IntoIterator<Item = ChunkChange>,
        store: &mut NodeStore,
    ) -> StreamRoot {
        let mut source = store.clone();
        root.update_sorted(changes.into_iter().map(Ok), &mut source, store)
            .unwrap()
    }

    #[test]
    fn literal_root_goldens_and_round_trip() {
        // Digest tokens are raw SHA256(b"x") and SHA256(b"y"). The fixtures
        // exercise metadata encoding; byte admission is tested separately.
        let x = digest(X);
        let y = digest(Y);
        let fixtures = [
            (
                0,
                BTreeMap::new(),
                "73696c6f3a73747265616d3a76320a10000000000000000000",
                "8105ecb94483de323a5b839ea425e11e2270d9b5ae54fe5ab72ee75beed03f02",
            ),
            (
                65536,
                BTreeMap::from([(0, x)]),
                "73696c6f3a73747265616d3a76320a1000000100000000000126dd4dfd51286c68e6238ff529a4e138403b26e1aad67fbc20048ece2b56e725",
                "4818ad50def4269ccd34fb9357556125719b71ce5b4913f003c3ad256c0ab446",
            ),
            (
                1,
                BTreeMap::from([(0, x)]),
                "73696c6f3a73747265616d3a76320a1001000000000000000126dd4dfd51286c68e6238ff529a4e138403b26e1aad67fbc20048ece2b56e725",
                "f7a4122273a42a3ba069df9e80635c0caa6294d74ca8ef945f44cd6fe272383d",
            ),
            (
                (64u64.pow(4) + 1) * 65536,
                BTreeMap::from([(0, x), (64u64.pow(4), y)]),
                "73696c6f3a73747265616d3a76320a100000010000010000018ed9e2d4b20c9eb7a261a4d95228080e6766b6dd23e57720925181fd7370511f",
                "4f2ea9606cc10bf37b9f292a4ff5f581106f9a36aa84faa84d3d2336626f50f8",
            ),
            (
                64 * 65536,
                (0..64).map(|index| (index, x)).collect(),
                "73696c6f3a73747265616d3a76320a1000004000000000000196c308f544c9830e2091de3bc71d6fb4e959cbbecb33c3e0e01341d283fb1bab",
                "6a6c20a86bf8872c857ff7e62c898e175a8e290e843608445768bbe55ba8552f",
            ),
        ];
        for (length, chunks, root_hex, id_hex) in fixtures {
            let mut store = NodeStore::default();
            let root = rebuild(length, &chunks, &mut store);
            let expected = hex(root_hex);
            assert_eq!(root.canonical_bytes().unwrap(), expected);
            assert_eq!(root.id(), digest(id_hex));
            assert_eq!(Sha256Digest::of_bytes(&expected), root.id());
            let decoded = StreamRoot::decode(&expected).unwrap();
            assert_eq!(decoded, root);
            assert_eq!(decoded.canonical_bytes().unwrap(), expected);
            let present = root
                .present_chunks(&mut store)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(
                present,
                chunks
                    .into_iter()
                    .map(|(index, digest)| PresentChunk { index, digest })
                    .collect::<Vec<_>>()
            );
            for bytes in store.bytes.values() {
                let height = if bytes.starts_with(b"silo:stream-map:leaf:v2\n") {
                    0
                } else {
                    bytes[26]
                };
                let node = StreamNode::decode(bytes, height).unwrap();
                assert_eq!(&node.canonical_bytes().unwrap(), bytes);
            }
        }
    }

    #[test]
    fn literal_leaf_goldens() {
        let single = hex(concat!(
            "73696c6f3a73747265616d2d6d61703a6c6561663a76320a0100000000000000",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
        ));
        assert_eq!(
            StreamNode::new(0, [(0, digest(X))])
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            single
        );
        assert_eq!(
            StreamNode::decode(&single, 0)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            single
        );
        // The dense vector is its literal all-bits-set header and exactly 64
        // copies of the literal digest, not bytes emitted by the codec.
        let dense = hex(concat!(
            "73696c6f3a73747265616d2d6d61703a6c6561663a76320affffffffffffffff",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
        ));
        assert_eq!(dense.len(), 2080);
        assert_eq!(
            StreamNode::new(0, (0..64).map(|slot| (slot, digest(X))))
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            dense
        );
        assert_eq!(
            StreamNode::decode(&dense, 0)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            dense
        );
    }

    #[test]
    fn defaults_match_exact_domain_bytes() {
        for height in 0..TREE_DEPTH {
            let mut bytes = if height == 0 {
                b"silo:stream-map:leaf:v2\n".to_vec()
            } else {
                let mut bytes = b"silo:stream-map:branch:v2\n".to_vec();
                bytes.push(height);
                bytes
            };
            bytes.extend(0u64.to_le_bytes());
            assert_eq!(
                default_digest(height).unwrap(),
                Sha256Digest::of_bytes(&bytes)
            );
            assert!(matches!(
                StreamNode::decode(&bytes, height),
                Err(MapError::EmptyNode)
            ));
        }
        assert!(matches!(default_digest(5), Err(MapError::InvalidHeight(5))));
    }

    #[test]
    fn roots_reject_noncanonical_records() {
        let good = hex("73696c6f3a73747265616d3a76320a10000000000000000000");
        for end in 0..good.len() {
            assert!(StreamRoot::decode(&good[..end]).is_err());
        }
        let mut wrong = good.clone();
        wrong[0] ^= 1;
        assert!(matches!(
            StreamRoot::decode(&wrong),
            Err(MapError::InvalidMagic)
        ));
        let mut old_version = good.clone();
        old_version[13] = b'1';
        assert!(matches!(
            StreamRoot::decode(&old_version),
            Err(MapError::InvalidMagic)
        ));
        assert!(StreamRoot::decode(b"{\"schema\":1,\"kind\":\"stream\"}").is_err());
        for shift in [0, 11, 24, 255] {
            let mut wrong = good.clone();
            wrong[15] = shift;
            assert!(matches!(
                StreamRoot::decode(&wrong),
                Err(MapError::InvalidChunkShift(_))
            ));
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(
            StreamRoot::decode(&trailing),
            Err(MapError::TrailingBytes)
        ));
        let mut flag = good.clone();
        flag[24] = 2;
        assert!(matches!(
            StreamRoot::decode(&flag),
            Err(MapError::InvalidTreeFlag(2))
        ));
        let mut missing = good.clone();
        missing[24] = 1;
        assert!(matches!(
            StreamRoot::decode(&missing),
            Err(MapError::Truncated)
        ));
        missing.extend(hex(X));
        assert!(matches!(
            StreamRoot::decode(&missing),
            Err(MapError::EmptyStreamWithTree)
        ));
        missing[16] = 1;
        missing[25..].fill(0);
        assert!(matches!(
            StreamRoot::decode(&missing),
            Err(MapError::ZeroDigest)
        ));
        missing[25..].copy_from_slice(default_digest(4).unwrap().as_bytes());
        assert!(matches!(
            StreamRoot::decode(&missing),
            Err(MapError::ExplicitDefault { height: 4 })
        ));
        let mut too_long = good;
        too_long[16..24].copy_from_slice(&(MAX_STREAM_BYTES + 1).to_le_bytes());
        assert!(matches!(
            StreamRoot::decode(&too_long),
            Err(MapError::LengthLimit { .. })
        ));
    }

    #[test]
    fn nodes_reject_noncanonical_records_and_ordered_inputs() {
        let good = StreamNode::new(0, [(0, digest(X))])
            .unwrap()
            .canonical_bytes()
            .unwrap();
        for end in 0..good.len() {
            assert!(StreamNode::decode(&good[..end], 0).is_err());
        }
        let mut wrong = good.clone();
        wrong[0] ^= 1;
        assert!(matches!(
            StreamNode::decode(&wrong, 0),
            Err(MapError::InvalidMagic)
        ));
        wrong = good.clone();
        wrong[22] = b'1';
        assert!(matches!(
            StreamNode::decode(&wrong, 0),
            Err(MapError::InvalidMagic)
        ));
        assert!(matches!(
            StreamNode::decode(&good, 1),
            Err(MapError::WrongHeight { .. })
        ));
        assert!(matches!(
            StreamNode::decode(&good, 5),
            Err(MapError::InvalidHeight(5))
        ));
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(
            StreamNode::decode(&trailing, 0),
            Err(MapError::TrailingBytes)
        ));
        let mut bitmap_count = good.clone();
        bitmap_count[24] = 3;
        assert!(matches!(
            StreamNode::decode(&bitmap_count, 0),
            Err(MapError::Truncated)
        ));
        let mut zero = good.clone();
        zero[32..].fill(0);
        assert!(matches!(
            StreamNode::decode(&zero, 0),
            Err(MapError::ZeroDigest)
        ));
        let mut branch = StreamNode::new(1, [(0, digest(X))])
            .unwrap()
            .canonical_bytes()
            .unwrap();
        branch[26] = 0;
        assert!(matches!(
            StreamNode::decode(&branch, 1),
            Err(MapError::InvalidHeight(0))
        ));
        branch[26] = 5;
        assert!(matches!(
            StreamNode::decode(&branch, 1),
            Err(MapError::InvalidHeight(5))
        ));
        branch[26] = 2;
        assert!(matches!(
            StreamNode::decode(&branch, 1),
            Err(MapError::WrongHeight { .. })
        ));
        for height in 1..TREE_DEPTH {
            let mut branch = StreamNode::new(height, [(0, digest(X))])
                .unwrap()
                .canonical_bytes()
                .unwrap();
            branch[35..].copy_from_slice(default_digest(height - 1).unwrap().as_bytes());
            assert!(matches!(
                StreamNode::decode(&branch, height),
                Err(MapError::ExplicitDefault { .. })
            ));
        }
        assert!(matches!(
            StreamNode::decode(&vec![0; MAX_NODE_BYTES + 1], 0),
            Err(MapError::NodeTooLarge(_))
        ));
        assert!(matches!(StreamNode::new(0, []), Err(MapError::EmptyNode)));
        assert!(matches!(
            StreamNode::new(0, [(64, digest(X))]),
            Err(MapError::InvalidSlot(64))
        ));
        assert!(matches!(
            StreamNode::new(0, [(1, digest(X)), (1, digest(Y))]),
            Err(MapError::DuplicateIndex(1))
        ));
        assert!(matches!(
            StreamNode::new(0, [(2, digest(X)), (1, digest(Y))]),
            Err(MapError::UnsortedIndex { .. })
        ));
        // Bitmap packing has no explicit index field to reorder. Swapping two
        // digest values creates another valid logical page, not an alternative
        // encoding of the same page. Equal values at different slots are valid.
        assert!(StreamNode::new(0, [(0, digest(X)), (1, digest(X))]).is_ok());
    }

    #[test]
    fn profiles_lengths_tail_and_admission_bounds() {
        for shift in 12..=23 {
            let size = ChunkSize::from_shift(shift).unwrap();
            let root = StreamRoot::empty(MAX_STREAM_BYTES, size).unwrap();
            assert_eq!(root.chunk_size().shift(), shift);
            assert_eq!(
                StreamRoot::decode(&root.canonical_bytes().unwrap()).unwrap(),
                root
            );
        }
        assert!(ChunkSize::from_shift(11).is_err());
        assert!(ChunkSize::from_shift(24).is_err());
        assert!(index_range(u64::MAX, ChunkSize::RAM).is_err());
        assert_eq!(index_range(0, ChunkSize::RAM).unwrap(), 0..0);
        assert_eq!(index_range(65537, ChunkSize::RAM).unwrap(), 0..2);
        assert_eq!(worst_case_node_count(0, ChunkSize::RAM).unwrap(), 0);
        assert_eq!(worst_case_node_count(1, ChunkSize::RAM).unwrap(), 5);
        assert_eq!(
            worst_case_node_count(64 * 65536, ChunkSize::RAM).unwrap(),
            5
        );
        assert_eq!(
            worst_case_node_count(65 * 65536, ChunkSize::RAM).unwrap(),
            6
        );
        assert_eq!(
            worst_case_node_count(MAX_RAM_BYTES, ChunkSize::RAM).unwrap(),
            266306
        );
        assert_eq!(
            worst_case_map_bytes(1, ChunkSize::RAM).unwrap(),
            5 * 2083 + 57
        );
        assert!(worst_case_node_count(MAX_STREAM_BYTES + 1, ChunkSize::RAM).is_err());
        let ram = StreamRoot::empty(MAX_RAM_BYTES + 1, ChunkSize::RAM).unwrap();
        assert!(matches!(
            ram.validate_role(StreamRole::Ram),
            Err(MapError::LengthLimit { .. })
        ));
        assert!(StreamRoot::empty(1, ChunkSize::DISK)
            .unwrap()
            .validate_role(StreamRole::Ram)
            .is_err());
        for role in [
            StreamRole::Disk,
            StreamRole::Pack,
            StreamRole::Lower,
            StreamRole::ObjectTransport,
        ] {
            assert_eq!(role.chunk_size(), ChunkSize::DISK);
            StreamRoot::empty(1, role.chunk_size())
                .unwrap()
                .validate_role(role)
                .unwrap();
        }
        let disk = StreamRoot::empty(MAX_TRANSPORT_BYTES + 1, ChunkSize::DISK).unwrap();
        assert!(disk.validate_role(StreamRole::Disk).is_ok());
        assert!(disk.validate_transport().is_err());
        assert!(disk.validate_role(StreamRole::ObjectTransport).is_err());
        let root = StreamRoot::empty(65537, ChunkSize::RAM).unwrap();
        assert_eq!(root.chunk_range(1).unwrap(), 65536..65537);
        assert_eq!(
            root.classify_chunk(1, b"x").unwrap(),
            Chunk::Data(digest(X))
        );
        assert_eq!(root.classify_chunk(1, &[0]).unwrap(), Chunk::Zero);
        assert!(matches!(
            root.classify_chunk(0, b"x"),
            Err(MapError::TailLength { index: 0, .. })
        ));
        assert!(matches!(
            root.classify_chunk(1, b""),
            Err(MapError::TailLength { .. })
        ));
        assert!(matches!(
            root.classify_chunk(1, b"xx"),
            Err(MapError::TailLength { .. })
        ));
        assert!(matches!(
            root.classify_chunk(2, b"x"),
            Err(MapError::IndexOutOfRange { .. })
        ));
        root.verify_chunk(1, Chunk::Data(digest(X)), b"x").unwrap();
        root.verify_chunk(1, Chunk::Zero, &[0]).unwrap();
        assert!(matches!(
            root.verify_chunk(1, Chunk::Data(Sha256Digest::of_bytes(&[0])), &[0]),
            Err(MapError::ChunkMismatch {
                actual: Chunk::Zero,
                ..
            })
        ));
        assert!(matches!(
            root.verify_chunk(1, Chunk::Zero, b"x"),
            Err(MapError::ChunkMismatch {
                actual: Chunk::Data(_),
                ..
            })
        ));
        let bytes = b"x";
        let mut ids = Vec::new();
        for profile in [ChunkSize::RAM, ChunkSize::DISK] {
            let empty = StreamRoot::empty(1, profile).unwrap();
            let Chunk::Data(digest) = empty.classify_chunk(0, bytes).unwrap() else {
                panic!()
            };
            let mut store = NodeStore::default();
            ids.push(
                build_sorted(
                    1,
                    profile,
                    [Ok(PresentChunk { index: 0, digest })],
                    &mut store,
                )
                .unwrap()
                .id(),
            );
        }
        assert_ne!(ids[0], ids[1]);
        assert_ne!(
            StreamRoot::empty(0, ChunkSize::RAM).unwrap().id(),
            StreamRoot::empty(1, ChunkSize::RAM).unwrap().id()
        );
    }

    #[test]
    fn lookup_sparse_boundaries_and_empty_ranges() {
        let mut store = NodeStore::default();
        let indices = [0, 63, 64, 4095, 4096, (1 << 24) - 1];
        let entries = indices
            .into_iter()
            .map(|index| (index, digest(X)))
            .collect();
        let root = rebuild(MAX_RAM_BYTES, &entries, &mut store);
        for index in indices {
            store.reads = 0;
            assert_eq!(
                root.lookup(index, &mut store).unwrap(),
                Chunk::Data(digest(X))
            );
            assert_eq!(store.reads, usize::from(TREE_DEPTH));
        }
        assert_eq!(root.lookup(65, &mut store).unwrap(), Chunk::Zero);
        assert!(matches!(
            root.lookup(1 << 24, &mut store),
            Err(MapError::IndexOutOfRange { .. })
        ));
        root.validate_boundary(&mut store).unwrap();
        let zero = StreamRoot::empty(MAX_RAM_BYTES, ChunkSize::RAM).unwrap();
        store.reads = 0;
        assert_eq!(zero.lookup(0, &mut store).unwrap(), Chunk::Zero);
        assert_eq!(store.reads, 0);
        assert!(StreamRoot::empty(0, ChunkSize::RAM)
            .unwrap()
            .lookup(0, &mut store)
            .is_err());
    }

    fn tree_with_bad_node(bad_height: u8, bad: &[u8], store: &mut NodeStore) -> StreamRoot {
        let mut child = store.write_node(bad).unwrap();
        for height in (bad_height + 1)..TREE_DEPTH {
            let bytes = StreamNode::new(height, [(0, child)])
                .unwrap()
                .canonical_bytes()
                .unwrap();
            child = store.write_node(&bytes).unwrap();
        }
        StreamRoot::new(65536, ChunkSize::RAM, Some(child)).unwrap()
    }

    #[test]
    fn range_checks_reject_high_leaf_bits_and_out_of_range_branches() {
        for height in 0..TREE_DEPTH {
            let mut store = NodeStore::default();
            let bad = StreamNode::new(height, [(1, digest(X))])
                .unwrap()
                .canonical_bytes()
                .unwrap();
            let root = tree_with_bad_node(height, &bad, &mut store);
            assert!(matches!(
                root.lookup(0, &mut store),
                Err(MapError::Node { source, .. }) if matches!(*source, MapError::IndexOutOfRange { .. })
            ));
            assert!(matches!(
                root.present_chunks(&mut store).next(),
                Some(Err(MapError::Node { source, .. })) if matches!(*source, MapError::IndexOutOfRange { .. })
            ));
            let mut sink = NodeStore::default();
            assert!(matches!(
                root.update_sorted(
                    [Ok(ChunkChange {
                        index: 0,
                        value: Chunk::Zero
                    })],
                    &mut store,
                    &mut sink
                ),
                Err(MapError::Node { source, .. }) if matches!(*source, MapError::IndexOutOfRange { .. })
            ));
        }
    }

    #[test]
    fn corrupt_missing_wrong_height_and_noncanonical_nodes_fail_at_every_height() {
        let mut clean = NodeStore::default();
        let root = rebuild(65536, &BTreeMap::from([(0, digest(X))]), &mut clean);
        for height in 0..TREE_DEPTH {
            let target = clean
                .bytes
                .iter()
                .find_map(|(&digest, bytes)| {
                    let actual = if bytes.starts_with(b"silo:stream-map:leaf:v2\n") {
                        0
                    } else {
                        bytes[26]
                    };
                    (actual == height).then_some(digest)
                })
                .unwrap();
            let mut corrupt = clean.clone();
            corrupt.bytes.get_mut(&target).unwrap()[0] ^= 1;
            assert!(matches!(
                root.lookup(0, &mut corrupt),
                Err(MapError::Node { height: actual_height, source, .. }) if actual_height == height && matches!(*source, MapError::DigestMismatch { .. })
            ));
            let mut missing = clean.clone();
            missing.bytes.remove(&target);
            assert!(matches!(
                root.lookup(0, &mut missing),
                Err(MapError::Node { height: actual_height, source, .. }) if actual_height == height && matches!(*source, MapError::MissingNode(_))
            ));
            let mut invalid_bytes = clean.bytes[&target].clone();
            invalid_bytes.push(0);
            let mut invalid = NodeStore::default();
            let invalid_root = tree_with_bad_node(height, &invalid_bytes, &mut invalid);
            assert!(matches!(
                invalid_root.lookup(0, &mut invalid),
                Err(MapError::Node { source, .. }) if matches!(*source, MapError::TrailingBytes)
            ));
            let wrong_height = if height == 0 { 1 } else { 0 };
            let bad = StreamNode::new(wrong_height, [(0, digest(X))])
                .unwrap()
                .canonical_bytes()
                .unwrap();
            let mut invalid = NodeStore::default();
            let invalid_root = tree_with_bad_node(height, &bad, &mut invalid);
            assert!(matches!(
                invalid_root.lookup(0, &mut invalid),
                Err(MapError::Node { source, .. }) if matches!(*source, MapError::WrongHeight { .. })
            ));
        }
        let mut corrupt = clean.clone();
        let tree = root.tree_digest().unwrap();
        corrupt.bytes.get_mut(&tree).unwrap()[0] ^= 1;
        let mut walk = root.present_chunks(&mut corrupt);
        assert!(walk.next().unwrap().is_err());
        assert!(walk.next().is_none());
    }

    #[test]
    fn sorted_streams_reject_duplicates_order_range_zero_digests_and_input_errors() {
        let mut source = NodeStore::default();
        let root = StreamRoot::empty(65536 * 100, ChunkSize::RAM).unwrap();
        let mut sink = NodeStore::default();
        let change = |index| ChunkChange {
            index,
            value: Chunk::Data(digest(X)),
        };
        assert!(matches!(
            root.update_sorted([Ok(change(1)), Ok(change(1))], &mut source, &mut sink),
            Err(MapError::DuplicateIndex(1))
        ));
        assert!(matches!(
            root.update_sorted([Ok(change(2)), Ok(change(1))], &mut source, &mut sink),
            Err(MapError::UnsortedIndex { .. })
        ));
        assert!(matches!(
            root.update_sorted([Ok(change(100))], &mut source, &mut sink),
            Err(MapError::IndexOutOfRange { .. })
        ));
        assert!(matches!(
            root.update_sorted(
                [Ok(ChunkChange {
                    index: 0,
                    value: Chunk::Data(Sha256Digest::from_bytes([0; 32]))
                })],
                &mut source,
                &mut sink
            ),
            Err(MapError::ZeroDigest)
        ));
        assert!(matches!(
            root.update_sorted([Err(MapError::ArithmeticOverflow)], &mut source, &mut sink),
            Err(MapError::ArithmeticOverflow)
        ));
        assert!(matches!(
            build_sorted(
                65536,
                ChunkSize::RAM,
                [Ok(PresentChunk {
                    index: 1,
                    digest: digest(X)
                })],
                &mut sink
            ),
            Err(MapError::IndexOutOfRange { .. })
        ));
        assert!(matches!(
            build_sorted(
                65536,
                ChunkSize::RAM,
                [
                    Ok(PresentChunk {
                        index: 0,
                        digest: digest(X)
                    }),
                    Ok(PresentChunk {
                        index: 0,
                        digest: digest(Y)
                    })
                ],
                &mut sink
            ),
            Err(MapError::DuplicateIndex(0))
        ));
    }

    // xorshift64 with a fixed nonzero seed; no external random dependency.
    fn random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn deterministic_random_updates_equal_rebuild_and_have_depth_bounded_work() {
        let length = MAX_RAM_BYTES;
        let mut store = NodeStore::default();
        let mut root = StreamRoot::empty(length, ChunkSize::RAM).unwrap();
        let mut content = BTreeMap::new();
        let mut state = 0x4d59_5df4_d0f3_3173;
        for round in 0..80 {
            let mut changes = BTreeMap::new();
            for _ in 0..(1 + random(&mut state) % 40) {
                let index = if round % 2 == 0 {
                    random(&mut state) % 128
                } else {
                    random(&mut state) % root.chunk_count()
                };
                let value = if random(&mut state).is_multiple_of(3) {
                    Chunk::Zero
                } else {
                    Chunk::Data(Sha256Digest::of_bytes(&random(&mut state).to_le_bytes()))
                };
                changes.insert(index, value);
            }
            let count = changes.len();
            for (&index, &value) in &changes {
                match value {
                    Chunk::Zero => {
                        content.remove(&index);
                    }
                    Chunk::Data(digest) => {
                        content.insert(index, digest);
                    }
                }
            }
            let mut source = store.clone();
            source.reads = 0;
            store.writes = 0;
            root = root
                .update_sorted(
                    changes
                        .into_iter()
                        .map(|(index, value)| Ok(ChunkChange { index, value })),
                    &mut source,
                    &mut store,
                )
                .unwrap();
            assert!(source.reads <= count * usize::from(TREE_DEPTH));
            assert!(store.writes <= count * usize::from(TREE_DEPTH));
            let mut rebuilt_store = NodeStore::default();
            let rebuilt = rebuild(length, &content, &mut rebuilt_store);
            assert_eq!(root, rebuilt);
            assert_eq!(
                root.canonical_bytes().unwrap(),
                rebuilt.canonical_bytes().unwrap()
            );
            let enumerated = root
                .present_chunks(&mut store)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(
                enumerated,
                content
                    .iter()
                    .map(|(&index, &digest)| PresentChunk { index, digest })
                    .collect::<Vec<_>>()
            );
        }
        let all_clear = content.keys().copied().map(|index| ChunkChange {
            index,
            value: Chunk::Zero,
        });
        let cleared = apply(&root, all_clear, &mut store);
        assert_eq!(cleared, StreamRoot::empty(length, ChunkSize::RAM).unwrap());
    }

    #[test]
    fn shared_paths_are_built_once_and_unchanged_values_publish_nothing() {
        let mut store = NodeStore::default();
        let root = rebuild(
            128 * 65536,
            &BTreeMap::from([(0, digest(X)), (1, digest(Y))]),
            &mut store,
        );
        assert_eq!(store.writes, 5);
        let mut source = store.clone();
        source.reads = 0;
        store.writes = 0;
        let changed = root
            .update_sorted(
                [
                    Ok(ChunkChange {
                        index: 0,
                        value: Chunk::Data(digest(Y)),
                    }),
                    Ok(ChunkChange {
                        index: 1,
                        value: Chunk::Data(digest(X)),
                    }),
                ],
                &mut source,
                &mut store,
            )
            .unwrap();
        assert_eq!(source.reads, 5);
        assert_eq!(store.writes, 5);
        source = store.clone();
        source.reads = 0;
        store.writes = 0;
        let unchanged = changed
            .update_sorted(
                [
                    Ok(ChunkChange {
                        index: 0,
                        value: Chunk::Data(digest(Y)),
                    }),
                    Ok(ChunkChange {
                        index: 2,
                        value: Chunk::Zero,
                    }),
                ],
                &mut source,
                &mut store,
            )
            .unwrap();
        assert_eq!(unchanged, changed);
        assert_eq!(source.reads, 5);
        assert_eq!(store.writes, 0);
        source.reads = 0;
        let empty = changed.update_sorted([], &mut source, &mut store).unwrap();
        assert_eq!(empty, changed);
        assert_eq!(source.reads, 0);
        assert_eq!(store.writes, 0);
        // Two distinct leaf pages still rebuild their shared ancestors once.
        source = store.clone();
        source.reads = 0;
        store.writes = 0;
        changed
            .update_sorted(
                [
                    Ok(ChunkChange {
                        index: 0,
                        value: Chunk::Data(digest(X)),
                    }),
                    Ok(ChunkChange {
                        index: 64,
                        value: Chunk::Data(digest(X)),
                    }),
                ],
                &mut source,
                &mut store,
            )
            .unwrap();
        assert_eq!(source.reads, 5);
        assert_eq!(store.writes, 6);
    }

    #[test]
    fn fixed_changes_do_not_depend_on_length_or_historical_population() {
        for length in [30u64 << 30, 500u64 << 30, 1u64 << 40] {
            for population in [1, 64, 1024] {
                let mut store = NodeStore::default();
                let content = (0..population).map(|index| (index, digest(X))).collect();
                let root = rebuild(length, &content, &mut store);
                let mut source = store.clone();
                source.reads = 0;
                store.writes = 0;
                root.update_sorted(
                    [Ok(ChunkChange {
                        index: 0,
                        value: Chunk::Data(digest(Y)),
                    })],
                    &mut source,
                    &mut store,
                )
                .unwrap();
                assert_eq!(source.reads, 5);
                assert_eq!(store.writes, 5);
            }
        }
    }

    #[test]
    fn diff_skips_equal_subtrees_and_reports_ordered_real_changes() {
        let mut before_store = NodeStore::default();
        let length = (64u64.pow(4) + 1) * 65536;
        let before = rebuild(
            length,
            &BTreeMap::from([(0, digest(X)), (64, digest(X)), (64u64.pow(4), digest(Y))]),
            &mut before_store,
        );
        let mut after_store = before_store.clone();
        let after = apply(
            &before,
            [
                ChunkChange {
                    index: 0,
                    value: Chunk::Zero,
                },
                ChunkChange {
                    index: 64,
                    value: Chunk::Data(digest(Y)),
                },
                ChunkChange {
                    index: 65,
                    value: Chunk::Data(digest(X)),
                },
            ],
            &mut after_store,
        );
        before_store.reads = 0;
        after_store.reads = 0;
        let same = diff(&before, &before, &mut before_store, &mut after_store)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(same.is_empty());
        assert_eq!(before_store.reads + after_store.reads, 0);
        let differences = diff(&before, &after, &mut before_store, &mut after_store)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            differences
                .iter()
                .map(|difference| difference.index)
                .collect::<Vec<_>>(),
            [0, 64, 65]
        );
        assert_eq!(differences[0].before, Chunk::Data(digest(X)));
        assert_eq!(differences[0].after, Chunk::Zero);
        assert_eq!(differences[1].before, Chunk::Data(digest(X)));
        assert_eq!(differences[1].after, Chunk::Data(digest(Y)));
        assert_eq!(differences[2].before, Chunk::Zero);
        assert_eq!(differences[2].after, Chunk::Data(digest(X)));
        // Root + one shared-prefix branch at each internal height + two leaves.
        // The different top-level subtree is never followed.
        assert_eq!(before_store.reads, 6);
        assert_eq!(after_store.reads, 5);
        let zero = StreamRoot::empty(length, ChunkSize::RAM).unwrap();
        let added = diff(&zero, &before, &mut NodeStore::default(), &mut before_store)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            added.iter().map(|entry| entry.index).collect::<Vec<_>>(),
            [0, 64, 64u64.pow(4)]
        );
        let different_profile = StreamRoot::empty(length, ChunkSize::DISK).unwrap();
        assert!(diff(
            &before,
            &different_profile,
            &mut before_store,
            &mut after_store
        )
        .is_err());
        // Length-only changes with the same subtree require no node reads.
        let longer = StreamRoot::new(length + 1, ChunkSize::RAM, before.tree_digest()).unwrap();
        before_store.reads = 0;
        after_store.reads = 0;
        assert!(diff(&before, &longer, &mut before_store, &mut after_store)
            .unwrap()
            .next()
            .is_none());
        assert_eq!(before_store.reads + after_store.reads, 0);
    }

    #[test]
    fn canonical_writers_propagate_real_short_buffer_errors() {
        let root = StreamRoot::empty(0, ChunkSize::RAM).unwrap();
        let mut short = [0u8; 24];
        assert!(matches!(
            root.write_canonical(short.as_mut_slice()),
            Err(MapError::Io(_))
        ));
        let leaf = StreamNode::new(0, [(0, digest(X))]).unwrap();
        let mut short = [0u8; 63];
        assert!(matches!(
            leaf.write_canonical(short.as_mut_slice()),
            Err(MapError::Io(_))
        ));
    }

    #[test]
    fn actual_byte_changes_zeroing_and_short_tail_match_rebuild() {
        let length = 2 * 65536 + 7;
        let geometry = StreamRoot::empty(length, ChunkSize::RAM).unwrap();
        let mut content = vec![0u8; length as usize];
        content[0] = 1;
        content[65536 + 100] = 2;
        content[2 * 65536 + 6] = 3;
        let entries = content
            .chunks(65536)
            .enumerate()
            .filter_map(|(index, bytes)| {
                match geometry.classify_chunk(index as u64, bytes).unwrap() {
                    Chunk::Data(digest) => Some((index as u64, digest)),
                    Chunk::Zero => None,
                }
            })
            .collect();
        let mut store = NodeStore::default();
        let before = rebuild(length, &entries, &mut store);
        content[..65536].fill(0);
        content[65536 + 101] = 4;
        content[2 * 65536 + 6] = 0;
        let changes = content
            .chunks(65536)
            .enumerate()
            .map(|(index, bytes)| ChunkChange {
                index: index as u64,
                value: geometry.classify_chunk(index as u64, bytes).unwrap(),
            })
            .collect::<Vec<_>>();
        let after = apply(&before, changes, &mut store);
        let entries = content
            .chunks(65536)
            .enumerate()
            .filter_map(|(index, bytes)| {
                match geometry.classify_chunk(index as u64, bytes).unwrap() {
                    Chunk::Data(digest) => Some((index as u64, digest)),
                    Chunk::Zero => None,
                }
            })
            .collect();
        let rebuilt = rebuild(length, &entries, &mut NodeStore::default());
        assert_eq!(after, rebuilt);
        assert_eq!(after.lookup(0, &mut store).unwrap(), Chunk::Zero);
        assert_eq!(after.lookup(2, &mut store).unwrap(), Chunk::Zero);
    }

    #[test]
    fn zero_ranges_skip_absent_indices_and_unrelated_populated_subtrees() {
        let mut store = NodeStore::default();
        let entries = BTreeMap::from([(0, digest(X)), (64, digest(Y)), (1 << 20, digest(X))]);
        let root = rebuild(MAX_RAM_BYTES, &entries, &mut store);
        store.reads = 0;
        let changes = root
            .zero_range_changes(0, 65, &mut store)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            changes,
            vec![
                ChunkChange {
                    index: 0,
                    value: Chunk::Zero
                },
                ChunkChange {
                    index: 64,
                    value: Chunk::Zero
                }
            ]
        );
        assert!(store.reads <= 6);
        store.reads = 0;
        assert!(root
            .zero_range_changes(1, 0, &mut store)
            .unwrap()
            .next()
            .is_none());
        assert_eq!(store.reads, 0);
        assert!(root.zero_range_changes(u64::MAX, 2, &mut store).is_err());
        assert!(root
            .zero_range_changes(root.chunk_count(), 1, &mut store)
            .is_err());
        let mut cursor = root.present_chunk_cursor();
        let mut seen = Vec::new();
        while let Some(chunk) = cursor.next_chunk(&mut store).unwrap() {
            seen.push(chunk.index);
        }
        assert_eq!(seen, vec![0, 64, 1 << 20]);
        assert!(cursor.next_chunk(&mut store).unwrap().is_none());
    }
}
