//! Canonical 8 MiB stream identity and bounded sparse file capture.
//!
//! File scans use one chunk buffer and one monotonic extent cursor, with no
//! allocation or byte scan proportional to hole length. Unknown extent support
//! reads actual bytes. Only complete nonzero logical chunks incur SHA-256 work.
//! Streaming output is independently authenticated before the caller syncs and
//! publishes it; allocation, physical reads and logical hashing are separate costs.

use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::Range;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{fcntl, open, FcntlArg, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{lseek, Whence};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

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
        const MAX_CHUNKS: usize =
            (Resource::ArtifactStreamBytes.maximum() / CHUNK_SIZE as u64) as usize;
        // The largest canonical entry is a quoted SHA-256 digest and a comma.
        // A little framing allowance also permits bounded JSON whitespace.
        if bytes.len() > MAX_CHUNKS * 74 + 256 {
            return Err(invalid_data("stream map exceeds its encoded size bound").into());
        }
        if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
            return Err(invalid_data("stream map must be a JSON object").into());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Record {
            schema: u64,
            kind: String,
            length: u64,
            chunk_size: u64,
            #[serde(deserialize_with = "decode_chunks")]
            chunks: Vec<Chunk>,
        }
        let record: Record = serde_json::from_slice(bytes)
            .map_err(|error| invalid_data(format!("invalid stream map: {error}")))?;
        if record.schema != 1 || record.kind != "stream" || record.chunk_size != CHUNK_SIZE as u64 {
            return Err(invalid_data("unsupported stream map schema, kind or chunk size").into());
        }
        Self::new(record.length, record.chunks)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StorageError> {
        let mut bytes = Vec::new();
        self.write_canonical(&mut bytes)?;
        Ok(bytes)
    }

    pub fn id(&self) -> StreamId {
        let mut digest = CanonicalHash(Sha256::new());
        digest.0.update(b"silo:stream:v1\n");
        // CanonicalHash writes only into SHA-256 and cannot return an I/O error.
        let _ = self.write_canonical(&mut digest);
        StreamId::from_sha256(digest.0.finalize().into())
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

fn decode_chunks<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<Chunk>, D::Error> {
    struct Chunks;
    impl<'de> Visitor<'de> for Chunks {
        type Value = Vec<Chunk>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded array of zero or lowercase SHA-256 chunk entries")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let maximum = Resource::ArtifactStreamBytes.maximum() / CHUNK_SIZE as u64;
            let mut chunks = Vec::new();
            while let Some(entry) = sequence.next_element::<String>()? {
                if chunks.len() as u64 == maximum {
                    return Err(de::Error::custom("too many stream chunks"));
                }
                chunks.push(if entry == "zero" {
                    Chunk::Zero
                } else {
                    Chunk::Data(entry.parse().map_err(de::Error::custom)?)
                });
            }
            Ok(chunks)
        }
    }
    decoder.deserialize_seq(Chunks)
}

/// Costs of one file scan, not the logical file length or bytes sent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StreamStats {
    pub bytes_read: u64,
    /// Complete nonzero chunks hashed, including their interior zero regions.
    pub logical_bytes_hashed: u64,
    /// Host-reported allocation (st_blocks * 512), not logical length.
    pub allocated_bytes: u64,
    pub extent_queries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamScan {
    pub map: StreamMap,
    pub stats: StreamStats,
    /// Independent completed-output scan for streaming copies.
    pub verification_stats: Option<StreamStats>,
}

struct CanonicalHash(Sha256);

impl Write for CanonicalHash {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reuses one fixed 8 MiB allocation across chunks and successive streams.
/// The decoded map is bounded by the 4 TiB artifact admission bound.
pub struct StreamHasher {
    buffer: Vec<u8>,
}

impl Default for StreamHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamHasher {
    pub fn new() -> Self {
        Self {
            buffer: vec![0; CHUNK_SIZE],
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
        self.scan_file(source, length, None, Extents::new(source, length))
    }

    /// Copy to a fresh empty read/write staging file, then independently scan
    /// the completed output and compare the complete logical map and length.
    /// File/directory synchronization and publication belong to the caller.
    pub fn copy_file_and_hash(
        &mut self,
        source: &File,
        length: u64,
        output: &File,
    ) -> Result<StreamScan, StorageError> {
        let source_metadata = source.metadata()?;
        let output_metadata = output.metadata()?;
        let output_flags = OFlag::from_bits_truncate(fcntl(output, FcntlArg::F_GETFL)?);
        if output_flags.contains(OFlag::O_APPEND)
            || output_flags & OFlag::O_ACCMODE != OFlag::O_RDWR
        {
            return Err(invalid_data("stream output requires non-append read/write access").into());
        }
        if !output_metadata.is_file()
            || output_metadata.len() != 0
            || (source_metadata.dev(), source_metadata.ino())
                == (output_metadata.dev(), output_metadata.ino())
        {
            return Err(invalid_data("stream output must be a distinct empty regular file").into());
        }
        let mut scan =
            self.scan_file(source, length, Some(output), Extents::new(source, length))?;
        // A trailing hole does not otherwise extend the completed file.
        output.set_len(length)?;
        let verification = self.hash_open_file(output, length)?;
        if verification.map != scan.map {
            return Err(invalid_data("completed stream output does not match source map").into());
        }
        if SourceFingerprint::new(&source_metadata) != SourceFingerprint::new(&source.metadata()?) {
            return Err(invalid_data("stream source changed during output verification").into());
        }
        scan.verification_stats = Some(verification.stats);
        Ok(scan)
    }

    fn scan_file(
        &mut self,
        source: &File,
        length: u64,
        output: Option<&File>,
        mut extents: Extents<'_>,
    ) -> Result<StreamScan, StorageError> {
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
                chunks.push(Chunk::Zero);
                offset = end;
                continue;
            }
            let bytes = &mut self.buffer[..(end - offset) as usize];
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
            let chunk = classify_chunk(bytes);
            if matches!(chunk, Chunk::Data(_)) {
                stats.logical_bytes_hashed += bytes.len() as u64;
                if let Some(output) = output {
                    write_sparse_at(output, bytes, offset)?;
                }
            }
            chunks.push(chunk);
            offset = end;
        }
        if fingerprint != SourceFingerprint::new(&source.metadata()?) {
            return Err(invalid_data("stream source changed during scan").into());
        }
        stats.extent_queries = extents.queries;
        Ok(StreamScan {
            map: StreamMap::new(length, chunks)?,
            stats,
            verification_stats: None,
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

fn classify_chunk(bytes: &[u8]) -> Chunk {
    if bytes.iter().all(|byte| *byte == 0) {
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

fn write_sparse_at(file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
    // Bounded subchunk runs avoid materializing 8 MiB for a single tiny write.
    // Adjacent nonzero blocks share one write; allocation granularity remains
    // a host-filesystem fact, not part of logical stream identity.
    const BLOCK: usize = 4096;
    let mut run = None;
    for (index, block) in bytes.chunks(BLOCK).enumerate() {
        let start = index * BLOCK;
        if block.iter().any(|byte| *byte != 0) {
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
        read_exact_at, write_exact_at, Chunk, Extents, StreamHasher, StreamMap,
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
        assert!(scan.verification_stats.is_some());
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
            assert_eq!(scan.verification_stats.unwrap().logical_bytes_hashed, 0);
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
        let verified = scan.verification_stats.unwrap();
        assert!(verified.bytes_read < 1024 * 1024);
        assert_eq!(verified.logical_bytes_hashed, 3 * CHUNK_SIZE as u64);
        assert!(verified.allocated_bytes < 1024 * 1024);
        assert!(verified.extent_queries <= 16);
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
        let output = tempfile::tempfile().unwrap();
        output.write_all_at(b"owned", 0).unwrap();
        let mut hasher = StreamHasher::new();
        assert!(hasher.copy_file_and_hash(&source, 3, &output).is_err());
        assert!(hasher.copy_file_and_hash(&source, 3, &source).is_err());
        assert!(hasher.hash_open_file(&source, 2).is_err());
        assert!(hasher.hash_open_file(&source, 4).is_err());
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
            .scan_file(&source, length, None, extents)
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
}
