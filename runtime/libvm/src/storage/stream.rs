//! Canonical 8 MiB stream identity and bounded sparse file capture.
//!
//! File scans use one chunk buffer and one monotonic extent cursor. Ordinary
//! scans do no byte hashing proportional to hole length; optional whole-file
//! SHA-256 also feeds logical holes without reading them from the filesystem.
//! Streaming copies authenticate their source chunks while writing; durability
//! and publication belong to the caller.

use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut, Range};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::sync::Arc;

use nix::errno::Errno;
use nix::fcntl::{fcntl, open, FcntlArg, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{lseek, Whence};
use sha2::{Digest, Sha256};
use vm_spec::capture::Sha256Digest;

use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::limits::{Resource, CHUNK_SIZE};
use crate::storage::StorageError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chunk {
    Zero,
    Data(ObjectDigest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMap {
    length: u64,
    chunks: Vec<Chunk>,
}

impl StreamMap {
    pub fn new(length: u64, chunks: Vec<Chunk>) -> Result<Self, StorageError> {
        Resource::ArtifactStreamBytes.check(length)?;
        let expected = length.div_ceil(CHUNK_SIZE as u64);
        if chunks.len() as u64 != expected {
            return Err(StorageError::ChunkCount {
                expected,
                actual: chunks.len() as u64,
            });
        }
        Ok(Self { length, chunks })
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    /// Decode only the bounded current record. Duplicate, unknown and missing
    /// fields, noninteger numbers and noncanonical digest spellings are errors.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let map = vm_spec::capture::StreamMap::decode(bytes).map_err(invalid_data)?;
        let length = map.length();
        Self::new(
            length,
            map.into_chunks()
                .into_iter()
                .map(|chunk| match chunk {
                    None => Chunk::Zero,
                    Some(digest) => Chunk::Data(ObjectDigest::from_sha256(*digest.as_bytes())),
                })
                .collect(),
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StorageError> {
        let mut bytes = Vec::new();
        self.write_canonical(&mut bytes)?;
        Ok(bytes)
    }

    pub fn id(&self) -> StreamId {
        let mut identity = vm_spec::capture::StreamIdentity::new();
        let mut remaining = self.length;
        for chunk in &self.chunks {
            let digest = match chunk {
                Chunk::Zero => None,
                Chunk::Data(digest) => Some(vm_spec::capture::Sha256Digest::from_bytes(
                    *digest.as_bytes(),
                )),
            };
            // StreamMap::new and every scanner enforce the same chunk count,
            // final-chunk length and 4 TiB bound, so this feed cannot fail.
            let _ = identity.push_digest(remaining.min(CHUNK_SIZE as u64), digest);
            remaining = remaining.saturating_sub(CHUNK_SIZE as u64);
        }
        StreamId::from_sha256(*identity.finish().as_bytes())
    }

    /// RFC 8785 serialization for this closed schema, not a general JSON encoder.
    ///
    /// All property names and string values are ASCII, so UTF-16 property sorting
    /// gives exactly chunkSize, chunks, kind, length, schema. The only admitted
    /// strings are fixed literals or validated lowercase digest text and require
    /// no escaping. Integers are nonnegative and bounded by 4 TiB (below 2^53-1),
    /// for which decimal integer formatting is identical to ECMAScript/JCS number
    /// serialization. No user keys, Unicode, floats or duplicate keys are admitted.
    pub fn write_canonical(&self, mut output: impl Write) -> io::Result<()> {
        output.write_all(b"{\"chunkSize\":8388608,\"chunks\":[")?;
        for (index, chunk) in self.chunks.iter().enumerate() {
            if index != 0 {
                output.write_all(b",")?;
            }
            match chunk {
                Chunk::Zero => output.write_all(b"\"zero\"")?,
                Chunk::Data(digest) => write!(output, "\"{digest}\"")?,
            }
        }
        write!(
            output,
            "],\"kind\":\"stream\",\"length\":{},\"schema\":1}}",
            self.length
        )
    }
}

/// Costs of one file scan, not the logical file length or bytes sent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StreamStats {
    pub bytes_read: u64,
    /// Complete nonzero chunks hashed, including their interior zero regions.
    pub logical_bytes_hashed: u64,
    /// Logical bytes fed to the optional whole-file SHA, including holes.
    pub whole_bytes_hashed: u64,
    /// Host-reported allocation (st_blocks * 512), not logical length.
    pub allocated_bytes: u64,
    pub extent_queries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamScan {
    pub map: StreamMap,
    pub stats: StreamStats,
}

/// An operation-scoped stream map, inseparable from its held inode. Receipt
/// constructors require the caller to supply trusted map authority; byte
/// authentication must complete before publishing or starting the consumer.
pub(crate) struct AuthenticatedStream {
    file: File,
    fingerprint: SourceFingerprint,
    map: Arc<StreamMap>,
}

impl AuthenticatedStream {
    /// Adopt a structurally verified receipt while byte authentication runs
    /// concurrently. This does not independently authenticate the file's bytes.
    pub(crate) fn from_receipt(file: File, map: StreamMap) -> Result<Self, StorageError> {
        let fingerprint = SourceFingerprint::new(&file.metadata()?);
        Self::from_verified_fingerprint(file, Arc::new(map), fingerprint)
    }

    /// Reuse authentication authority for the exact inode state supplied by
    /// the caller, without reading its bytes again.
    pub(crate) fn from_verified_fingerprint(
        file: File,
        map: Arc<StreamMap>,
        fingerprint: SourceFingerprint,
    ) -> Result<Self, StorageError> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() != map.length()
            || SourceFingerprint::new(&metadata) != fingerprint
        {
            return Err(invalid_data("verified stream fingerprint or geometry changed").into());
        }
        Ok(Self {
            file,
            fingerprint,
            map,
        })
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn fingerprint(&self) -> SourceFingerprint {
        self.fingerprint
    }

    pub(crate) fn map(&self) -> &StreamMap {
        &self.map
    }

    pub(crate) fn length(&self) -> u64 {
        self.map.length()
    }

    pub(crate) fn reopen(&self, file: File) -> Result<Self, StorageError> {
        if SourceFingerprint::new(&self.file.metadata()?) != self.fingerprint
            || SourceFingerprint::new(&file.metadata()?) != self.fingerprint
        {
            return Err(invalid_data("authenticated stream was replaced or modified").into());
        }
        Ok(Self {
            file,
            fingerprint: self.fingerprint,
            map: Arc::clone(&self.map),
        })
    }

    /// Only the owner of an authenticated rename/permission transition may
    /// refresh ctime. An inode, length or mtime change still fails closed.
    pub(crate) fn refresh_after_owned_metadata_change(&mut self) -> Result<(), StorageError> {
        let metadata = self.file.metadata()?;
        if !self
            .fingerprint
            .same_contents_after_metadata_change(&metadata)
        {
            return Err(
                invalid_data("authenticated stream changed during owned transition").into(),
            );
        }
        self.fingerprint = SourceFingerprint::new(&metadata);
        Ok(())
    }
}

/// Whole-byte authentication, independent of stream chunk identity.
pub(crate) fn whole_file_sha256(file: &File) -> Result<Sha256Digest, StorageError> {
    let mut buffer = [0u8; 64 << 10];
    let mut offset = 0;
    let mut hash = Sha256::new();
    loop {
        let count = file.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyWriteback {
    Buffered,
    Direct,
}

const COPY_BLOCK_SIZE: usize = 4096;

#[repr(C, align(4096))]
#[derive(Clone)]
struct AlignedBlock([u8; COPY_BLOCK_SIZE]);

struct ChunkBuffer(Vec<AlignedBlock>);

impl Deref for ChunkBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // AlignedBlock has exactly one initialized 4096-byte array and no
        // padding. The vector owns contiguous blocks for this borrow.
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!((*self.0.as_ptr()).0).cast::<u8>(),
                self.0.len() * COPY_BLOCK_SIZE,
            )
        }
    }
}

impl DerefMut for ChunkBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        // The exclusive vector borrow also exclusively owns all block bytes.
        unsafe {
            std::slice::from_raw_parts_mut(
                std::ptr::addr_of_mut!((*self.0.as_mut_ptr()).0).cast::<u8>(),
                self.0.len() * COPY_BLOCK_SIZE,
            )
        }
    }
}

/// Reuses one fixed 8 MiB allocation across chunks and successive streams.
/// The decoded map is bounded by the 4 TiB artifact admission bound.
pub struct StreamHasher {
    buffer: ChunkBuffer,
    writeback: CopyWriteback,
}

impl Default for StreamHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamHasher {
    pub fn new() -> Self {
        Self::with_writeback(CopyWriteback::Buffered)
    }

    pub(crate) fn with_writeback(writeback: CopyWriteback) -> Self {
        Self {
            buffer: ChunkBuffer(vec![
                AlignedBlock([0; COPY_BLOCK_SIZE]);
                CHUNK_SIZE / COPY_BLOCK_SIZE
            ]),
            writeback,
        }
    }

    pub fn hash_file(&mut self, path: &Path) -> Result<StreamMap, StorageError> {
        let file = open_regular_source(path)?;
        let before = SourceFingerprint::new(&file.metadata()?);
        let scan = self.hash_open_file(&file, file.metadata()?.len())?;
        if before != SourceFingerprint::new(&file.metadata()?) {
            return Err(StorageError::SourceChanged(path.to_path_buf()));
        }
        Ok(scan.map)
    }

    pub fn hash_reader(&mut self, reader: impl Read) -> Result<StreamMap, StorageError> {
        self.scan(reader)
    }

    /// Scan exactly the admitted length of a held regular source descriptor.
    /// The caller must exclude writers. Extent queries change the descriptor's
    /// seek position, but all byte I/O is positional and independent of it.
    pub fn hash_open_file(
        &mut self,
        source: &File,
        length: u64,
    ) -> Result<StreamScan, StorageError> {
        self.scan_file(source, length, None, Extents::new(source, length), None)
    }

    /// Compute both identities in one extent-aware logical pass. Whole-file
    /// SHA includes every logical zero and the exact final tail, unlike the
    /// domain-separated stream identity. Ordinary stream scans do not do this
    /// extra hashing.
    pub fn hash_open_file_with_sha256(
        &mut self,
        source: &File,
        length: u64,
    ) -> Result<(StreamScan, Sha256Digest), StorageError> {
        let mut sha256 = Sha256::new();
        let scan = self.scan_file(
            source,
            length,
            None,
            Extents::new(source, length),
            Some(&mut sha256),
        )?;
        Ok((scan, Sha256Digest::from_bytes(sha256.finalize().into())))
    }

    pub(crate) fn authenticate(
        &mut self,
        file: File,
        length: u64,
    ) -> Result<AuthenticatedStream, StorageError> {
        let fingerprint = SourceFingerprint::new(&file.metadata()?);
        let scan = self.hash_open_file(&file, length)?;
        if SourceFingerprint::new(&file.metadata()?) != fingerprint {
            return Err(invalid_data("stream changed during authentication").into());
        }
        Ok(AuthenticatedStream {
            file,
            fingerprint,
            map: Arc::new(scan.map),
        })
    }

    pub(crate) fn authenticate_with_sha256(
        &mut self,
        file: File,
        length: u64,
    ) -> Result<(AuthenticatedStream, Sha256Digest), StorageError> {
        let fingerprint = SourceFingerprint::new(&file.metadata()?);
        let (scan, sha256) = self.hash_open_file_with_sha256(&file, length)?;
        if SourceFingerprint::new(&file.metadata()?) != fingerprint {
            return Err(invalid_data("stream changed during authentication").into());
        }
        Ok((
            AuthenticatedStream {
                file,
                fingerprint,
                map: Arc::new(scan.map),
            },
            sha256,
        ))
    }

    /// Compare the copy-time canonical chunk map with the recorded source map.
    /// Read every data extent, including map-zero chunks, so changed source
    /// bytes cannot be silently omitted. The completed output is not re-read.
    pub(crate) fn copy_authenticated(
        &mut self,
        source: &AuthenticatedStream,
        output: &File,
    ) -> Result<StreamScan, StorageError> {
        let metadata = source.file().metadata()?;
        if SourceFingerprint::new(&metadata) != source.fingerprint() {
            return Err(invalid_data("authenticated copy source changed").into());
        }
        validate_copy_output(&metadata, output)?;
        let scan = self.scan_file(
            source.file(),
            source.length(),
            Some(output),
            Extents::new(source.file(), source.length()),
            None,
        )?;
        if scan.map != *source.map() {
            return Err(
                invalid_data("copy-time stream chunks do not match source identity").into(),
            );
        }
        if SourceFingerprint::new(&source.file().metadata()?) != source.fingerprint() {
            return Err(invalid_data("stream source changed during copy").into());
        }
        output.set_len(source.length())?;
        Ok(scan)
    }

    /// Copy to a fresh staging file and compute the canonical map while writing.
    /// File/directory synchronization and publication belong to the caller.
    pub fn copy_file_and_hash(
        &mut self,
        source: &File,
        length: u64,
        output: &File,
    ) -> Result<StreamScan, StorageError> {
        let source_metadata = source.metadata()?;
        validate_copy_output(&source_metadata, output)?;
        let scan = self.scan_file(
            source,
            length,
            Some(output),
            Extents::new(source, length),
            None,
        )?;
        // A trailing hole does not otherwise extend the completed file.
        output.set_len(length)?;
        if SourceFingerprint::new(&source_metadata) != SourceFingerprint::new(&source.metadata()?) {
            return Err(invalid_data("stream source changed during copy").into());
        }
        Ok(scan)
    }

    fn scan_file(
        &mut self,
        source: &File,
        length: u64,
        output: Option<&File>,
        mut extents: Extents<'_>,
        mut sha256: Option<&mut Sha256>,
    ) -> Result<StreamScan, StorageError> {
        let mut output = output
            .map(|file| CopyOutput::new(file, self.writeback))
            .transpose()?;
        Resource::ArtifactStreamBytes.check(length)?;
        let metadata = source.metadata()?;
        if !metadata.is_file() || metadata.len() != length {
            return Err(invalid_data("stream source type or admitted length changed").into());
        }
        let source_flags = OFlag::from_bits_truncate(fcntl(source, FcntlArg::F_GETFL)?);
        if source_flags & OFlag::O_ACCMODE == OFlag::O_WRONLY {
            return Err(invalid_data("stream source requires read access").into());
        }
        let fingerprint = SourceFingerprint::new(&metadata);
        let mut stats = StreamStats {
            allocated_bytes: metadata
                .blocks()
                .checked_mul(512)
                .ok_or_else(|| invalid_data("allocated stream length overflow"))?,
            ..StreamStats::default()
        };
        let mut data = extents.next(0)?;
        let mut chunks = Vec::with_capacity(length.div_ceil(CHUNK_SIZE as u64) as usize);
        let mut offset = 0;
        while offset < length {
            let end = (offset + CHUNK_SIZE as u64).min(length);
            if data.as_ref().is_none_or(|range| range.start >= end) {
                if let Some(sha256) = sha256.as_mut() {
                    let bytes = &mut self.buffer[..(end - offset) as usize];
                    bytes.fill(0);
                    sha256.update(&*bytes);
                    stats.whole_bytes_hashed += bytes.len() as u64;
                }
                chunks.push(Chunk::Zero);
                offset = end;
                continue;
            }
            let logical_length = (end - offset) as usize;
            let buffer_length = if output.as_ref().is_some_and(|output| output.direct) {
                logical_length.div_ceil(COPY_BLOCK_SIZE) * COPY_BLOCK_SIZE
            } else {
                logical_length
            };
            let bytes = &mut self.buffer[..buffer_length];
            bytes.fill(0);
            while let Some(range) = data.as_ref() {
                if range.start >= end {
                    break;
                }
                let start = range.start;
                let read_end = range.end.min(end);
                let extent_end = range.end;
                read_exact_at(
                    source,
                    &mut bytes[(start - offset) as usize..(read_end - offset) as usize],
                    start,
                )?;
                stats.bytes_read += read_end - start;
                data = if read_end == extent_end {
                    extents.next(read_end)?
                } else {
                    Some(read_end..extent_end)
                };
            }
            if let Some(sha256) = sha256.as_mut() {
                sha256.update(&bytes[..logical_length]);
                stats.whole_bytes_hashed += logical_length as u64;
            }
            let chunk = classify_chunk(&bytes[..logical_length]);
            if matches!(chunk, Chunk::Data(_)) {
                stats.logical_bytes_hashed += logical_length as u64;
                if let Some(output) = output.as_mut() {
                    output.write(bytes, offset)?;
                    #[cfg(target_os = "linux")]
                    if !output.direct {
                        if let Err(error) = start_writeback(output.file, offset, end - offset) {
                            tracing::debug!(%error, offset, length = end - offset, "start private copy writeback");
                        }
                    }
                }
            }
            chunks.push(chunk);
            offset = end;
        }
        if let Some(output) = output {
            output.finish()?;
        }
        if fingerprint != SourceFingerprint::new(&source.metadata()?) {
            return Err(invalid_data("stream source changed during scan").into());
        }
        stats.extent_queries = extents.queries;
        Ok(StreamScan {
            map: StreamMap::new(length, chunks)?,
            stats,
        })
    }

    // Short reads accumulate into the same canonical logical chunk.
    fn scan(&mut self, mut reader: impl Read) -> Result<StreamMap, StorageError> {
        let mut length = 0_u64;
        let mut chunks = Vec::new();
        loop {
            let mut filled = 0;
            while filled < self.buffer.len() {
                match reader.read(&mut self.buffer[filled..]) {
                    Ok(0) => break,
                    Ok(count) => filled += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            if filled == 0 {
                break;
            }
            length = Resource::ArtifactStreamBytes.sum([length, filled as u64])?;
            chunks.push(classify_chunk(&self.buffer[..filled]));
        }
        StreamMap::new(length, chunks)
    }
}

fn validate_copy_output(source: &std::fs::Metadata, output: &File) -> Result<(), StorageError> {
    let metadata = output.metadata()?;
    let flags = OFlag::from_bits_truncate(fcntl(output, FcntlArg::F_GETFL)?);
    if flags.contains(OFlag::O_APPEND) || flags & OFlag::O_ACCMODE == OFlag::O_RDONLY {
        return Err(invalid_data("stream output requires non-append write access").into());
    }
    if !metadata.is_file()
        || metadata.len() != 0
        || (source.dev(), source.ino()) == (metadata.dev(), metadata.ino())
    {
        return Err(invalid_data("stream output must be a distinct empty regular file").into());
    }
    Ok(())
}

fn classify_chunk(bytes: &[u8]) -> Chunk {
    if vm_spec::capture::is_all_zero(bytes) {
        Chunk::Zero
    } else {
        Chunk::Data(ObjectDigest::of_bytes(bytes))
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Keeps only the current extent. Each successful query advances past at
/// least one byte, so traversal is bounded by the fixed admitted length.
struct Extents<'a> {
    file: &'a File,
    length: u64,
    supported: bool,
    queries: u64,
}

impl<'a> Extents<'a> {
    fn new(file: &'a File, length: u64) -> Self {
        Self {
            file,
            length,
            supported: true,
            queries: 0,
        }
    }

    fn next(&mut self, offset: u64) -> io::Result<Option<Range<u64>>> {
        if offset >= self.length {
            return Ok(None);
        }
        if !self.supported {
            return Ok(Some(offset..self.length));
        }
        let data = match self.seek(offset, Whence::SeekData) {
            Ok(data) => data,
            Err(Errno::ENXIO) => return Ok(None),
            Err(error) if extent_unsupported(error) => {
                self.supported = false;
                return Ok(Some(offset..self.length));
            }
            Err(error) => return Err(error.into()),
        };
        if data < offset || data >= self.length {
            return Err(invalid_data("SEEK_DATA returned an out-of-bounds extent"));
        }
        let hole = match self.seek(data, Whence::SeekHole) {
            Ok(hole) => hole,
            Err(error) if extent_unsupported(error) => {
                self.supported = false;
                // Read the entire unknown interval, including preceding zeros.
                return Ok(Some(offset..self.length));
            }
            Err(error) => return Err(error.into()),
        };
        if hole <= data || hole > self.length {
            return Err(invalid_data(
                "SEEK_HOLE returned a nonprogressing or out-of-bounds extent",
            ));
        }
        Ok(Some(data..hole))
    }

    fn seek(&mut self, offset: u64, whence: Whence) -> Result<u64, Errno> {
        let offset = i64::try_from(offset).map_err(|_| Errno::EOVERFLOW)?;
        loop {
            self.queries += 1;
            match lseek(self.file, offset, whence) {
                Ok(value) => return u64::try_from(value).map_err(|_| Errno::EOVERFLOW),
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

fn extent_unsupported(error: Errno) -> bool {
    matches!(error, Errno::EINVAL | Errno::EOPNOTSUPP)
}

fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !bytes.is_empty() {
        match file.read_at(bytes, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short stream source",
                ))
            }
            Ok(count) => {
                offset = offset
                    .checked_add(count as u64)
                    .ok_or_else(|| invalid_data("stream read offset overflow"))?;
                bytes = &mut bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_exact_at(file: &File, mut bytes: &[u8], mut offset: u64) -> io::Result<()> {
    while !bytes.is_empty() {
        match file.write_at(bytes, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "zero stream write",
                ))
            }
            Ok(count) => {
                offset = offset
                    .checked_add(count as u64)
                    .ok_or_else(|| invalid_data("stream write offset overflow"))?;
                bytes = &bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn start_writeback(file: &File, offset: u64, length: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let offset = i64::try_from(offset).map_err(|_| invalid_data("writeback offset overflow"))?;
    let length = i64::try_from(length).map_err(|_| invalid_data("writeback length overflow"))?;
    // nix has no sync_file_range wrapper. This only hints writeback, not durability.
    // SAFETY: the held descriptor and checked ranges remain valid for this call.
    let result = unsafe {
        libc::sync_file_range(
            file.as_raw_fd(),
            offset,
            length,
            libc::SYNC_FILE_RANGE_WRITE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct CopyOutput<'a> {
    file: &'a File,
    original_flags: OFlag,
    configured: bool,
    direct: bool,
}

impl<'a> CopyOutput<'a> {
    fn new(file: &'a File, writeback: CopyWriteback) -> io::Result<Self> {
        let original_flags = if writeback == CopyWriteback::Direct {
            OFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFL)?)
        } else {
            OFlag::empty()
        };
        let direct = if writeback == CopyWriteback::Direct {
            match set_direct(file, original_flags, true) {
                Ok(()) => true,
                Err(error) if error.raw_os_error() == Some(Errno::EINVAL as i32) => false,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        Ok(Self {
            file,
            original_flags,
            configured: direct,
            direct,
        })
    }

    fn write(&mut self, bytes: &[u8], offset: u64) -> io::Result<()> {
        match write_sparse_at(self.file, bytes, offset) {
            Err(error) if self.direct && error.raw_os_error() == Some(Errno::EINVAL as i32) => {
                // Retry the same bytes at the same offsets. A partial direct
                // write cannot change the chunk identity or omit its suffix.
                set_direct(self.file, self.original_flags, false)?;
                self.direct = false;
                write_sparse_at(self.file, bytes, offset)
            }
            result => result,
        }
    }

    fn finish(mut self) -> io::Result<()> {
        if self.configured {
            restore_copy_flags(self.file, self.original_flags)?;
            self.configured = false;
        }
        Ok(())
    }
}

impl Drop for CopyOutput<'_> {
    fn drop(&mut self) {
        if self.configured {
            if let Err(error) = restore_copy_flags(self.file, self.original_flags) {
                tracing::warn!(%error, "restore private copy descriptor flags");
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn set_direct(file: &File, flags: OFlag, enabled: bool) -> io::Result<()> {
    let flags = if enabled {
        flags | OFlag::O_DIRECT
    } else {
        flags & !OFlag::O_DIRECT
    };
    fcntl(file, FcntlArg::F_SETFL(flags))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_copy_flags(file: &File, flags: OFlag) -> io::Result<()> {
    fcntl(file, FcntlArg::F_SETFL(flags))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_direct(file: &File, _flags: OFlag, enabled: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // nix has no F_NOCACHE argument. This controls only our fresh private file.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, i32::from(enabled)) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn restore_copy_flags(file: &File, flags: OFlag) -> io::Result<()> {
    set_direct(file, flags, false)
}

pub(crate) fn write_sparse_at(file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
    // Bounded subchunk runs avoid materializing 8 MiB for a single tiny write.
    // Adjacent nonzero blocks share one write; allocation granularity remains
    // a host-filesystem fact, not part of logical stream identity.
    const BLOCK: usize = 4096;
    let mut run = None;
    for (index, block) in bytes.chunks(BLOCK).enumerate() {
        let start = index * BLOCK;
        if !vm_spec::capture::is_all_zero(block) {
            if run.is_none() {
                run = Some(start);
            }
        } else if let Some(first) = run.take() {
            write_exact_at(file, &bytes[first..start], offset + first as u64)?;
        }
    }
    if let Some(first) = run {
        write_exact_at(file, &bytes[first..], offset + first as u64)?;
    }
    Ok(())
}

pub(crate) fn open_regular_source(path: &Path) -> Result<File, StorageError> {
    let file = File::from(open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        return Err(StorageError::NotRegular(path.to_path_buf()));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{FileExt, MetadataExt};

    use sha2::{Digest, Sha256};

    use crate::storage::identity::ObjectDigest;
    use crate::storage::limits::CHUNK_SIZE;
    use crate::storage::stream::{
        read_exact_at, write_exact_at, AuthenticatedStream, Chunk, Extents, StreamHasher, StreamMap,
    };
    use crate::storage::StorageError;

    #[test]
    fn empty_stream_has_exact_jcs_and_domain_separated_identity() {
        let map = StreamHasher::new().hash_reader(&b""[..]).unwrap();
        let expected =
            b"{\"chunkSize\":8388608,\"chunks\":[],\"kind\":\"stream\",\"length\":0,\"schema\":1}";
        let mut canonical = Vec::new();
        map.write_canonical(&mut canonical).unwrap();
        assert_eq!(canonical, expected);
        let mut hash = Sha256::new();
        hash.update(b"silo:stream:v1\n");
        hash.update(expected);
        assert_eq!(
            map.id().to_string(),
            ObjectDigest::from_sha256(hash.finalize().into()).to_string()
        );
        assert_eq!(
            map.id().to_string(),
            "sha256:192b20355cf58aabc1ad0e56920978ddafc4563a62e8074d7b276e94990f741e"
        );
        assert_ne!(
            map.id().to_string(),
            ObjectDigest::of_bytes(expected).to_string()
        );
        assert_ne!(
            map.id().to_string(),
            ObjectDigest::of_bytes(b"").to_string()
        );
    }

    #[test]
    fn fixed_schema_jcs_vectors_cover_data_and_zero_values() {
        let mut hasher = StreamHasher::new();
        assert_eq!(
            hasher.hash_reader(&[0][..]).unwrap().id().to_string(),
            "sha256:d4c6dbfe1fb7e9dd71187064b171abd82da93c63ec89527933825dcad6caa286"
        );
        assert_eq!(
            hasher.hash_reader(&b"abc"[..]).unwrap().id().to_string(),
            "sha256:008c32bed56a222e714747dafa5eff7e2191b87799eabf3d8b11fbb0eb4e057e"
        );
        let length = 4 * 1024_u64.pow(4);
        let map = StreamMap::new(length, vec![Chunk::Zero; 524288]).unwrap();
        let mut canonical = Vec::new();
        map.write_canonical(&mut canonical).unwrap();
        assert!(
            canonical.ends_with(b"],\"kind\":\"stream\",\"length\":4398046511104,\"schema\":1}")
        );
        let value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(value["length"].as_u64(), Some(length));
        assert_eq!(value["chunks"].as_array().unwrap().len(), 524288);
    }

    #[test]
    fn hashes_whole_chunks_including_zero_regions_and_final_tail() {
        let mut bytes = vec![0; 2 * CHUNK_SIZE + 3];
        bytes[CHUNK_SIZE + 17] = 9;
        bytes[2 * CHUNK_SIZE + 2] = 7;
        let map = StreamHasher::new().hash_reader(&bytes[..]).unwrap();
        assert_eq!(map.length(), bytes.len() as u64);
        assert_eq!(
            map.chunks(),
            &[
                Chunk::Zero,
                Chunk::Data(ObjectDigest::of_bytes(&bytes[CHUNK_SIZE..2 * CHUNK_SIZE])),
                Chunk::Data(ObjectDigest::of_bytes(&[0, 0, 7])),
            ]
        );
        let mut canonical = Vec::new();
        map.write_canonical(&mut canonical).unwrap();
        let expected = format!("{{\"chunkSize\":8388608,\"chunks\":[\"zero\",\"{}\",\"{}\"],\"kind\":\"stream\",\"length\":{},\"schema\":1}}", ObjectDigest::of_bytes(&bytes[CHUNK_SIZE..2 * CHUNK_SIZE]), ObjectDigest::of_bytes(&[0, 0, 7]), bytes.len());
        assert_eq!(canonical, expected.as_bytes());
        let exact = StreamHasher::new()
            .hash_reader(&bytes[..2 * CHUNK_SIZE])
            .unwrap();
        assert_eq!(exact.chunks().len(), 2);
        let zero_tail = StreamHasher::new()
            .hash_reader(&bytes[..CHUNK_SIZE + 1])
            .unwrap();
        assert_eq!(zero_tail.chunks(), &[Chunk::Zero, Chunk::Zero]);
        assert_ne!(exact.id(), zero_tail.id());
    }

    #[test]
    fn short_real_reads_do_not_create_short_nonfinal_chunks() {
        let bytes = vec![5; CHUNK_SIZE + 19];
        // Chain's first slice forces a 17-byte read before the remaining bytes.
        let mut hasher = StreamHasher::new();
        let expected = hasher.hash_reader(&bytes[..]).unwrap();
        let actual = hasher
            .hash_reader((&bytes[..17]).chain(&bytes[17..]))
            .unwrap();
        assert_eq!(actual, expected);
        assert!(matches!(
            StreamMap::new(1, vec![]),
            Err(StorageError::ChunkCount { .. })
        ));
        assert!(StreamMap::new(0, vec![Chunk::Zero]).is_err());
        assert!(StreamMap::new(4 * 1024_u64.pow(4) + 1, vec![]).is_err());
    }

    #[test]
    fn sparse_and_allocated_zeros_have_identical_maps() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        let sparse = dir.path().join("sparse");
        let allocated = dir.path().join("allocated");
        let length = CHUNK_SIZE as u64 + 3;
        let mut file = std::fs::File::create(&sparse).unwrap();
        file.set_len(length).unwrap();
        file.seek(SeekFrom::Start(CHUNK_SIZE as u64 + 2)).unwrap();
        file.write_all(&[1]).unwrap();
        let mut bytes = vec![0; length as usize];
        bytes[length as usize - 1] = 1;
        std::fs::write(&allocated, bytes).unwrap();
        let mut hasher = StreamHasher::new();
        assert_eq!(
            hasher.hash_file(&sparse).unwrap(),
            hasher.hash_file(&allocated).unwrap()
        );
        assert!(hasher.hash_file(dir.path()).is_err());
    }

    #[test]
    fn fused_sha_matches_logical_bytes_for_sparse_mixed_chunks_holes_and_tails() {
        let mut hasher = StreamHasher::new();
        for length in [0, 1, CHUNK_SIZE, 2 * CHUNK_SIZE + 19] {
            for nonzero in [false, true] {
                let source = tempfile::tempfile().unwrap();
                source.set_len(length as u64).unwrap();
                let mut bytes = vec![0; length];
                if nonzero && length > 0 {
                    bytes[0] = 5;
                    bytes[length - 1] = 7;
                    source.write_all_at(&[5], 0).unwrap();
                    source.write_all_at(&[7], length as u64 - 1).unwrap();
                }
                let (fused, sha256) = hasher
                    .hash_open_file_with_sha256(&source, length as u64)
                    .unwrap();
                let ordinary = hasher.hash_open_file(&source, length as u64).unwrap();
                let expected = hasher.hash_reader(bytes.as_slice()).unwrap();
                assert_eq!(fused.map, expected);
                assert_eq!(ordinary.map, expected);
                assert_eq!(fused.stats.bytes_read, ordinary.stats.bytes_read);
                assert_eq!(fused.stats.extent_queries, ordinary.stats.extent_queries);
                assert_eq!(fused.stats.whole_bytes_hashed, length as u64);
                assert_eq!(ordinary.stats.whole_bytes_hashed, 0);
                assert_eq!(sha256, vm_spec::capture::Sha256Digest::of_bytes(&bytes));
                assert_ne!(fused.map.id().as_bytes(), sha256.as_bytes());
                if length > CHUNK_SIZE && nonzero {
                    assert_eq!(fused.map.chunks()[1], Chunk::Zero);
                }
            }
        }
    }

    #[test]
    fn strict_stream_map_decode_preserves_identity_and_rejects_invalid_records() {
        let map = StreamHasher::new().hash_reader(b"abc".as_slice()).unwrap();
        let canonical = map.canonical_bytes().unwrap();
        assert_eq!(StreamMap::decode(&canonical).unwrap(), map);
        assert_ne!(
            ObjectDigest::of_bytes(&canonical).to_string(),
            map.id().to_string()
        );
        let empty = r#"{"schema":1,"kind":"stream","length":0,"chunkSize":8388608,"chunks":[]}"#;
        assert_eq!(StreamMap::decode(empty.as_bytes()).unwrap().length(), 0);
        for invalid in [
            empty.replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
            empty.replace("\"chunks\":[]", "\"chunks\":[],\"extra\":0"),
            empty.replace("\"kind\":\"stream\",", ""),
            empty.replace("\"schema\":1", "\"schema\":2"),
            empty.replace("\"kind\":\"stream\"", "\"kind\":\"snapshot\""),
            empty.replace("8388608", "4096"),
            empty.replace("\"length\":0", "\"length\":0.0"),
            empty.replace("\"length\":0", "\"length\":-1"),
            empty.replace("\"length\":0", "\"length\":9007199254740992"),
            empty.replace("\"chunks\":[]", "\"chunks\":[\"zero\"]"),
            empty.replace("\"length\":0", "\"length\":1"),
            empty.replace("\"length\":0", "\"length\":4398046511105"),
            empty.replace("\"chunks\":[]", "\"chunks\":[null]"),
            format!("{empty} trailing"),
        ] {
            assert!(StreamMap::decode(invalid.as_bytes()).is_err(), "{invalid}");
        }
        for entry in [
            "ZERO".to_owned(),
            format!("sha512:{}", "0".repeat(64)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "0".repeat(63)),
        ] {
            let invalid = format!(
                "{{\"schema\":1,\"kind\":\"stream\",\"length\":1,\"chunkSize\":8388608,\"chunks\":[\"{entry}\"]}}"
            );
            assert!(StreamMap::decode(invalid.as_bytes()).is_err());
        }
        let maximum = StreamMap::new(4 * 1024_u64.pow(4), vec![Chunk::Zero; 524288]).unwrap();
        assert_eq!(
            StreamMap::decode(&maximum.canonical_bytes().unwrap()).unwrap(),
            maximum,
        );
        let oversized = vec![b' '; 524288 * 74 + 257];
        assert!(StreamMap::decode(&oversized).is_err());
    }

    #[test]
    fn positional_sparse_copy_matches_independent_bytes_with_unaligned_short_tail() {
        let mut source = tempfile::tempfile().unwrap();
        let output = tempfile::tempfile().unwrap();
        let mut bytes = vec![0; 3 * CHUNK_SIZE + 19];
        bytes[17..24].copy_from_slice(b"head123");
        bytes[CHUNK_SIZE - 3..CHUNK_SIZE + 4].copy_from_slice(b"crossed");
        bytes[2 * CHUNK_SIZE + 4095] = 9;
        bytes[3 * CHUNK_SIZE + 18] = 7;
        // Real allocated zeros and nonzero data; no fabricated extent replies.
        source.write_all(&bytes).unwrap();
        source.seek(SeekFrom::Start(123)).unwrap();
        let mut hasher = StreamHasher::new();
        let expected = hasher.hash_reader(bytes.as_slice()).unwrap();
        let scan = hasher
            .copy_file_and_hash(&source, bytes.len() as u64, &output)
            .unwrap();
        assert_eq!(scan.map, expected);
        assert_eq!(scan.stats.logical_bytes_hashed, bytes.len() as u64);
        assert_eq!(output.metadata().unwrap().len(), bytes.len() as u64);
        assert!(output.metadata().unwrap().blocks() * 512 < CHUNK_SIZE as u64);
        let mut actual = vec![0; bytes.len()];
        output.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, bytes);
        let mut original = Vec::new();
        source.seek(SeekFrom::Start(0)).unwrap();
        source.read_to_end(&mut original).unwrap();
        assert_eq!(original, bytes);
        assert_eq!(
            hasher
                .hash_open_file(&output, bytes.len() as u64)
                .unwrap()
                .map,
            expected
        );
    }

    #[test]
    fn empty_zero_and_trailing_hole_outputs_have_exact_lengths_and_maps() {
        let mut hasher = StreamHasher::new();
        for length in [0, 1, CHUNK_SIZE as u64, CHUNK_SIZE as u64 + 3] {
            let source = tempfile::tempfile().unwrap();
            source.set_len(length).unwrap();
            let output = tempfile::tempfile().unwrap();
            let scan = hasher.copy_file_and_hash(&source, length, &output).unwrap();
            assert_eq!(output.metadata().unwrap().len(), length);
            assert_eq!(scan.map.length(), length);
            assert!(scan.map.chunks().iter().all(|chunk| *chunk == Chunk::Zero));
            assert_eq!(scan.stats.logical_bytes_hashed, 0);
            assert_eq!(output.metadata().unwrap().blocks(), 0);
        }
        let source = tempfile::tempfile().unwrap();
        source.set_len(2 * CHUNK_SIZE as u64 + 3).unwrap();
        source.write_all_at(b"abc", 17).unwrap();
        let output = tempfile::tempfile().unwrap();
        let scan = hasher
            .copy_file_and_hash(&source, 2 * CHUNK_SIZE as u64 + 3, &output)
            .unwrap();
        assert_eq!(&scan.map.chunks()[1..], &[Chunk::Zero, Chunk::Zero]);
        assert_eq!(output.metadata().unwrap().len(), 2 * CHUNK_SIZE as u64 + 3);
    }

    #[test]
    fn one_tib_sparse_copy_has_bounded_reads_hashes_extents_and_allocation() {
        let source = tempfile::tempfile().unwrap();
        let output = tempfile::tempfile().unwrap();
        let length = 1024_u64.pow(4);
        source.set_len(length).unwrap();
        let writes: [(u64, &[u8]); 3] = [
            (17, b"first"),
            (512 * 1024_u64.pow(3) + 31, b"middle"),
            (length - 7, b"last123"),
        ];
        for (offset, bytes) in writes {
            source.write_all_at(bytes, offset).unwrap();
        }
        source.sync_all().unwrap();
        // Preflight the real extent lane before scanning a huge logical file.
        // Conservative/unsupported reporting fails boundedly, never reads 1 TiB.
        let mut extents = Extents::new(&source, length);
        let mut cursor = 0;
        let mut reported = 0;
        while let Some(range) = extents.next(cursor).unwrap() {
            reported += range.end - range.start;
            assert!(
                reported < 1024 * 1024,
                "1 TiB fixture needs a hole-reporting filesystem"
            );
            cursor = range.end;
        }
        let mut expected = vec![Chunk::Zero; (length / CHUNK_SIZE as u64) as usize];
        for (offset, bytes) in writes {
            let mut chunk = vec![0; CHUNK_SIZE];
            let local = (offset % CHUNK_SIZE as u64) as usize;
            chunk[local..local + bytes.len()].copy_from_slice(bytes);
            expected[(offset / CHUNK_SIZE as u64) as usize] =
                Chunk::Data(ObjectDigest::of_bytes(&chunk));
        }
        let expected = StreamMap::new(length, expected).unwrap();
        let scan = StreamHasher::new()
            .copy_file_and_hash(&source, length, &output)
            .unwrap();
        assert_eq!(scan.map, expected);
        assert!(scan.stats.bytes_read < 1024 * 1024);
        assert_eq!(scan.stats.logical_bytes_hashed, 3 * CHUNK_SIZE as u64);
        assert!(scan.stats.allocated_bytes < 1024 * 1024);
        assert!(scan.stats.extent_queries <= 16);
        assert_eq!(output.metadata().unwrap().len(), length);
        for (offset, bytes) in writes {
            let mut actual = vec![0; bytes.len()];
            output.read_exact_at(&mut actual, offset).unwrap();
            assert_eq!(actual, bytes);
        }
    }

    #[test]
    fn exact_file_io_rejects_short_sources_bad_access_and_existing_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        std::fs::write(&path, b"abc").unwrap();
        let source = File::open(&path).unwrap();
        let mut bytes = [0; 5];
        let error = read_exact_at(&source, &mut bytes, 0).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(&bytes[..3], b"abc");
        assert!(write_exact_at(&source, b"no", 0).is_err());
        let write_only = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(read_exact_at(&write_only, &mut [0; 3], 0).is_err());
        assert!(StreamHasher::new().hash_open_file(&write_only, 3).is_err());
        assert!(StreamHasher::new()
            .hash_open_file_with_sha256(&write_only, 3)
            .is_err());
        let output = tempfile::tempfile().unwrap();
        output.write_all_at(b"owned", 0).unwrap();
        let mut hasher = StreamHasher::new();
        assert!(hasher.copy_file_and_hash(&source, 3, &output).is_err());
        assert!(hasher.copy_file_and_hash(&source, 3, &source).is_err());
        assert!(hasher.hash_open_file(&source, 2).is_err());
        assert!(hasher.hash_open_file(&source, 4).is_err());
        assert!(hasher.hash_open_file_with_sha256(&source, 2).is_err());
        assert!(hasher.hash_open_file_with_sha256(&source, 4).is_err());
        let mut retained = [0; 5];
        output.read_exact_at(&mut retained, 0).unwrap();
        assert_eq!(&retained, b"owned");
        let fresh = tempfile::tempfile().unwrap();
        let copied = hasher.copy_file_and_hash(&source, 3, &fresh).unwrap();
        assert_eq!(
            copied.map.chunks(),
            &[Chunk::Data(ObjectDigest::of_bytes(b"abc"))]
        );
        let mut actual = [0; 3];
        fresh.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(&actual, b"abc");
    }

    #[test]
    fn unknown_extents_read_actual_bytes_and_preserve_zero_identity() {
        let source = tempfile::tempfile().unwrap();
        let length = CHUNK_SIZE as u64 + 23;
        source.set_len(length).unwrap();
        source
            .write_all_at(b"not a hole", CHUNK_SIZE as u64 + 7)
            .unwrap();
        let mut extents = Extents::new(&source, length);
        // Disable the optimization, not file I/O: this exercises the same
        // all-data cursor selected by a real unsupported extent syscall.
        extents.supported = false;
        let scan = StreamHasher::new()
            .scan_file(&source, length, None, extents, None)
            .unwrap();
        assert_eq!(scan.stats.bytes_read, length);
        assert_eq!(scan.stats.logical_bytes_hashed, 23);
        assert_eq!(scan.stats.extent_queries, 0);
        assert_eq!(scan.map.chunks()[0], Chunk::Zero);
        let mut tail = [0; 23];
        tail[7..17].copy_from_slice(b"not a hole");
        assert_eq!(
            scan.map.chunks()[1],
            Chunk::Data(ObjectDigest::of_bytes(&tail))
        );
        assert_eq!(
            scan.map,
            StreamHasher::new()
                .hash_open_file(&source, length)
                .unwrap()
                .map
        );
        let mut extents = Extents::new(&source, length);
        extents.supported = false;
        let mut sha256 = Sha256::new();
        let fused = StreamHasher::new()
            .scan_file(&source, length, None, extents, Some(&mut sha256))
            .unwrap();
        let mut expected = vec![0; length as usize];
        expected[CHUNK_SIZE..].copy_from_slice(&tail);
        assert_eq!(fused.map, scan.map);
        assert_eq!(fused.stats.bytes_read, length);
        assert_eq!(fused.stats.whole_bytes_hashed, length);
        assert_eq!(
            vm_spec::capture::Sha256Digest::from_bytes(sha256.finalize().into()),
            vm_spec::capture::Sha256Digest::of_bytes(&expected)
        );
    }

    #[test]
    fn only_unsupported_extent_errors_allow_byte_scan_fallback() {
        use crate::storage::stream::extent_unsupported;
        use nix::errno::Errno;
        assert!(extent_unsupported(Errno::EINVAL));
        assert!(extent_unsupported(Errno::EOPNOTSUPP));
        for error in [
            Errno::EIO,
            Errno::EBADF,
            Errno::EOVERFLOW,
            Errno::EACCES,
            Errno::EPERM,
            Errno::ENOSPC,
            Errno::EDQUOT,
            Errno::ENXIO,
        ] {
            assert!(!extent_unsupported(error));
        }
    }

    #[test]
    fn map_decoder_requires_an_object_and_bounds_decoded_chunk_count() {
        assert!(StreamMap::decode(br#"[1,"stream",0,8388608,[]]"#).is_err());
        assert!(StreamMap::decode(b"").is_err());
        let chunks = "\"zero\",".repeat(524288) + "\"zero\"";
        let record = format!(
            "{{\"schema\":1,\"kind\":\"stream\",\"length\":4398046511104,\"chunkSize\":8388608,\"chunks\":[{chunks}]}}"
        );
        assert!(StreamMap::decode(record.as_bytes()).is_err());
    }

    #[test]
    fn authenticated_copy_shares_map_but_reopens_offsets_and_verifies_sparse_output() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        let source = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let length = 2 * CHUNK_SIZE as u64 + 19;
        source.set_len(length).unwrap();
        source.write_all_at(b"head", 17).unwrap();
        source.write_all_at(b"tail", length - 4).unwrap();
        let mut hasher = StreamHasher::new();
        let authenticated = hasher.authenticate(source, length).unwrap();
        let reopened = authenticated.reopen(File::open(&path).unwrap()).unwrap();
        assert!(std::sync::Arc::ptr_eq(&authenticated.map, &reopened.map));
        let mut original_position = authenticated.file();
        original_position.seek(SeekFrom::Start(123)).unwrap();
        let mut reopened_position = reopened.file();
        assert_eq!(reopened_position.stream_position().unwrap(), 0);
        let output = tempfile::tempfile().unwrap();
        let scan = hasher.copy_authenticated(&reopened, &output).unwrap();
        assert_eq!(scan.stats.logical_bytes_hashed, CHUNK_SIZE as u64 + 19);
        assert_eq!(scan.stats.whole_bytes_hashed, 0);
        assert_eq!(output.metadata().unwrap().len(), length);
        assert!(output.metadata().unwrap().blocks() * 512 < CHUNK_SIZE as u64);
        assert_eq!(
            hasher.hash_open_file(&output, length).unwrap().map,
            *authenticated.map()
        );
        let mut actual = vec![0; length as usize];
        output.read_exact_at(&mut actual, 0).unwrap();
        let mut expected = vec![0; length as usize];
        expected[17..21].copy_from_slice(b"head");
        expected[length as usize - 4..].copy_from_slice(b"tail");
        assert_eq!(actual, expected);
        assert_eq!(original_position.stream_position().unwrap(), 123);
    }

    #[test]
    fn authenticated_copy_zero_lengths_and_holes_still_verify_exact_outputs() {
        let mut hasher = StreamHasher::new();
        for length in [0, 1, CHUNK_SIZE as u64, CHUNK_SIZE as u64 + 3] {
            let source = tempfile::tempfile().unwrap();
            source.set_len(length).unwrap();
            let authenticated = hasher.authenticate(source, length).unwrap();
            let output = tempfile::tempfile().unwrap();
            let scan = hasher.copy_authenticated(&authenticated, &output).unwrap();
            assert_eq!(scan.stats.logical_bytes_hashed, 0);
            assert_eq!(output.metadata().unwrap().len(), length);
            assert_eq!(output.metadata().unwrap().blocks(), 0);
        }
    }

    #[test]
    fn authenticated_copy_rejects_wrong_maps_after_copy_and_changed_sources_before_copy() {
        let mut hasher = StreamHasher::new();
        let source = tempfile::tempfile().unwrap();
        source.write_all_at(b"abc", 0).unwrap();
        let mut authenticated = hasher.authenticate(source, 3).unwrap();
        // Inject contradictory authority only inside this unit test. Even a
        // map-zero chunk cannot suppress reading/copying real source extents.
        authenticated.map = std::sync::Arc::new(StreamMap::new(3, vec![Chunk::Zero]).unwrap());
        let output = tempfile::tempfile().unwrap();
        let error = hasher
            .copy_authenticated(&authenticated, &output)
            .unwrap_err();
        assert!(error.to_string().contains("copy-time stream chunks"));
        let mut bytes = [0; 3];
        output.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"abc");

        let source = tempfile::tempfile().unwrap();
        source.write_all_at(b"abc", 0).unwrap();
        let authenticated = hasher.authenticate(source, 3).unwrap();
        let occupied = tempfile::tempfile().unwrap();
        occupied.write_all_at(b"owned", 0).unwrap();
        assert!(hasher
            .copy_authenticated(&authenticated, &occupied)
            .is_err());
        assert!(hasher
            .copy_authenticated(&authenticated, authenticated.file())
            .is_err());
        let read_only_path = tempfile::NamedTempFile::new().unwrap();
        assert!(hasher
            .copy_authenticated(&authenticated, &File::open(read_only_path.path()).unwrap())
            .is_err());
        authenticated.file().set_len(2).unwrap();
        let empty = tempfile::tempfile().unwrap();
        assert!(hasher.copy_authenticated(&authenticated, &empty).is_err());
        assert_eq!(empty.metadata().unwrap().len(), 0);
    }

    #[test]
    fn receipt_copy_rejects_corrupt_source_without_reading_output() {
        let mut hasher = StreamHasher::new();
        let source = tempfile::tempfile().unwrap();
        source.write_all_at(b"original", 0).unwrap();
        let expected = hasher.hash_open_file(&source, 8).unwrap().map;
        source.write_all_at(b"corrupt!", 0).unwrap();
        let receipt = AuthenticatedStream::from_receipt(source, expected).unwrap();
        let directory = tempfile::tempdir().unwrap();
        // An output read-back would fail with EBADF, not an identity mismatch.
        let output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.path().join("private"))
            .unwrap();
        let error = hasher.copy_authenticated(&receipt, &output).unwrap_err();
        assert!(error.to_string().contains("copy-time stream chunks"));
        let good = hasher.hash_open_file(receipt.file(), 8).unwrap().map;
        let receipt =
            AuthenticatedStream::from_receipt(receipt.file().try_clone().unwrap(), good).unwrap();
        let output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.path().join("good"))
            .unwrap();
        assert!(hasher.copy_authenticated(&receipt, &output).is_ok());
    }

    #[test]
    fn trusted_stream_constructors_bind_exact_inode_state_and_geometry() {
        use std::sync::Arc;

        use crate::storage::identity_file::SourceFingerprint;

        let file = tempfile::tempfile().unwrap();
        file.write_all_at(b"abc", 0).unwrap();
        let map = Arc::new(StreamHasher::new().hash_open_file(&file, 3).unwrap().map);
        let fingerprint = SourceFingerprint::new(&file.metadata().unwrap());
        let held = AuthenticatedStream::from_verified_fingerprint(
            file.try_clone().unwrap(),
            Arc::clone(&map),
            fingerprint,
        )
        .unwrap();
        assert_eq!(held.map(), map.as_ref());
        let other = tempfile::tempfile().unwrap();
        other.write_all_at(b"abc", 0).unwrap();
        assert!(AuthenticatedStream::from_verified_fingerprint(
            other,
            Arc::clone(&map),
            fingerprint,
        )
        .is_err());
        let wrong_length = StreamMap::new(2, vec![Chunk::Zero]).unwrap();
        assert!(
            AuthenticatedStream::from_receipt(file.try_clone().unwrap(), wrong_length,).is_err()
        );
        file.set_len(4).unwrap();
        assert!(AuthenticatedStream::from_verified_fingerprint(file, map, fingerprint).is_err());
    }

    #[test]
    fn authenticated_source_reopen_and_owned_metadata_refresh_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        std::fs::write(&path, b"abc").unwrap();
        let mut hasher = StreamHasher::new();
        let mut authenticated = hasher.authenticate(File::open(&path).unwrap(), 3).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(authenticated.reopen(File::open(&path).unwrap()).is_err());
        authenticated.refresh_after_owned_metadata_change().unwrap();
        let renamed = directory.path().join("renamed");
        std::fs::rename(&path, &renamed).unwrap();
        authenticated.refresh_after_owned_metadata_change().unwrap();
        assert!(authenticated.reopen(File::open(&renamed).unwrap()).is_ok());
        std::fs::write(&path, b"abc").unwrap();
        assert!(authenticated.reopen(File::open(&path).unwrap()).is_err());
        std::fs::set_permissions(&renamed, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&renamed, b"changed").unwrap();
        assert!(authenticated.refresh_after_owned_metadata_change().is_err());
        assert!(authenticated.reopen(File::open(&renamed).unwrap()).is_err());
    }
    #[test]
    fn direct_copy_keeps_exact_chunk_identity_sparse_tails_and_descriptor_flags() {
        use crate::storage::stream::CopyWriteback;
        use nix::fcntl::{fcntl, FcntlArg};

        let mut hasher = StreamHasher::with_writeback(CopyWriteback::Direct);
        assert!((hasher.buffer.as_ptr() as usize).is_multiple_of(4096));
        assert_eq!(hasher.buffer.len(), CHUNK_SIZE);
        for length in [0, 1, 4095, 4096, 4097, CHUNK_SIZE + 19] {
            let mut bytes = vec![0; length];
            if length != 0 {
                bytes[0] = 0x41;
                bytes[length - 1] = 0x42;
            }
            let source = tempfile::tempfile().unwrap();
            source.write_all_at(&bytes, 0).unwrap();
            let expected = StreamHasher::new().hash_reader(bytes.as_slice()).unwrap();
            let receipt = AuthenticatedStream::from_receipt(source, expected.clone()).unwrap();
            let output = tempfile::tempfile().unwrap();
            let flags = fcntl(&output, FcntlArg::F_GETFL).unwrap();
            let scan = hasher.copy_authenticated(&receipt, &output).unwrap();
            assert_eq!(scan.map, expected);
            assert_eq!(scan.stats.whole_bytes_hashed, 0);
            assert_eq!(output.metadata().unwrap().len(), length as u64);
            assert_eq!(fcntl(&output, FcntlArg::F_GETFL).unwrap(), flags);
            let mut actual = vec![0; length];
            output.read_exact_at(&mut actual, 0).unwrap();
            assert_eq!(actual, bytes);
        }
    }

    #[test]
    fn direct_copy_retries_real_unaligned_einval_and_restores_flags() {
        use crate::storage::stream::{CopyOutput, CopyWriteback};
        use nix::fcntl::{fcntl, FcntlArg};

        let output = tempfile::tempfile().unwrap();
        let flags = fcntl(&output, FcntlArg::F_GETFL).unwrap();
        let mut writer = CopyOutput::new(&output, CopyWriteback::Direct).unwrap();
        let rejected = output
            .write_at(b"probe", 1)
            .is_err_and(|error| error.raw_os_error() == Some(nix::errno::Errno::EINVAL as i32));
        writer.write(b"retry", 1).unwrap();
        if rejected {
            assert!(!writer.direct);
        }
        writer.finish().unwrap();
        assert_eq!(fcntl(&output, FcntlArg::F_GETFL).unwrap(), flags);
        let mut bytes = [0; 6];
        output.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"\0retry");
    }

    #[test]
    fn direct_copy_corruption_still_fails_without_retaining_direct_descriptor_flags() {
        use crate::storage::stream::CopyWriteback;
        use nix::fcntl::{fcntl, FcntlArg};

        let source = tempfile::tempfile().unwrap();
        source.write_all_at(b"original", 0).unwrap();
        let map = StreamHasher::new().hash_open_file(&source, 8).unwrap().map;
        source.write_all_at(b"corrupt!", 0).unwrap();
        let receipt = AuthenticatedStream::from_receipt(source, map).unwrap();
        let output = tempfile::tempfile().unwrap();
        let flags = fcntl(&output, FcntlArg::F_GETFL).unwrap();
        let error = StreamHasher::with_writeback(CopyWriteback::Direct)
            .copy_authenticated(&receipt, &output)
            .unwrap_err();
        assert!(error.to_string().contains("copy-time stream chunks"));
        assert_eq!(fcntl(&output, FcntlArg::F_GETFL).unwrap(), flags);
    }
}
