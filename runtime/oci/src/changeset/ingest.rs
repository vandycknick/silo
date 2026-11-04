use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use containerregistry_image::MediaType;
use flate2::read::MultiGzDecoder;
use sha2::{Digest, Sha256};

use crate::changeset::pack::{allocated_bytes, ensure_space, PackWriter};
use crate::changeset::{
    validate_layer, ChangesetError, ChangesetLimits, ChangesetResult, ContentDigest, EntryKind,
    LayerChangeset, PayloadRef,
};
use crate::store::StagingDir;
use crate::StagingOperation;

/// Transport and decoded identities are independent assertions. Neither is
/// inferred from the other, a filename, or the tar end marker.
#[derive(Debug, Clone)]
pub struct LayerInput {
    pub blob_digest: ContentDigest,
    pub media_type: String,
    pub size_bytes: u64,
    pub diff_id: ContentDigest,
}

/// This value can only be created after true compression EOF, both identity
/// checks, bounded tar admission and full index validation. Dropping it removes
/// all private bytes and releases the operation lease, including on cancellation.
#[derive(Debug)]
pub struct StagedChangeset {
    changeset: LayerChangeset,
    pack_path: PathBuf,
    _staging: StagingDir,
}

impl StagedChangeset {
    pub fn changeset(&self) -> &LayerChangeset {
        &self.changeset
    }
    pub fn pack_path(&self) -> &Path {
        &self.pack_path
    }
    pub fn pack_length(&self) -> u64 {
        self.changeset.pack_length
    }

    /// Transfer verified input into its enclosing flatten operation without
    /// retaining one independent lease descriptor per layer.
    pub(crate) fn scope<'a>(
        self,
        parent: &'a StagingDir,
        occurrence: usize,
    ) -> ChangesetResult<ScopedPack<'a>> {
        let count = self
            .changeset
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, EntryKind::Regular(_)))
            .count();
        let reserve = (count as u64)
            .checked_mul(std::mem::size_of::<(u64, PayloadRef)>() as u64)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(|| {
                ChangesetError::Invalid("live payload metadata reservation overflows".into())
            })?;
        crate::changeset::limits::memory_preflight(reserve)?;
        let pack_path = parent.path().join(format!("layer-{occurrence}.pack"));
        let Self {
            changeset,
            pack_path: source_path,
            _staging: child_staging,
        } = self;
        let length = changeset.pack_length;
        let mut payloads = BTreeMap::new();
        for entry in changeset.entries {
            if let EntryKind::Regular(payload) = entry.kind {
                payloads.insert(entry.ordinal, payload);
            }
        }
        // Same private filesystem: atomic no-replace, with no payload copy.
        std::fs::hard_link(source_path, &pack_path)?;
        drop(child_staging);
        Ok(ScopedPack {
            payloads,
            length,
            pack_path,
            _parent: parent,
        })
    }
}

pub(crate) struct ScopedPack<'a> {
    payloads: BTreeMap<u64, PayloadRef>,
    length: u64,
    pack_path: PathBuf,
    _parent: &'a StagingDir,
}

impl ScopedPack<'_> {
    pub(crate) fn payload(&self, ordinal: u64) -> Option<&PayloadRef> {
        self.payloads.get(&ordinal)
    }

    pub(crate) fn discard(&mut self, ordinal: u64) -> bool {
        self.payloads.remove(&ordinal).is_some()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    pub(crate) fn pack_path(&self) -> &Path {
        &self.pack_path
    }

    pub(crate) fn pack_length(&self) -> u64 {
        self.length
    }
}

impl Drop for ScopedPack<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.pack_path);
    }
}

struct TransportReader {
    file: File,
    hash: Sha256,
    length: u64,
    maximum: u64,
}

impl Read for TransportReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.file.read(buffer)?;
        self.length = self.length.checked_add(count as u64).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "transport length overflow")
        })?;
        if self.length > self.maximum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transport exceeds descriptor size",
            ));
        }
        self.hash.update(&buffer[..count]);
        Ok(count)
    }
}

fn decoder<'a>(media_type: &str, reader: impl Read + 'a) -> ChangesetResult<Box<dyn Read + 'a>> {
    let media = MediaType::from_str(media_type)
        .map_err(|_| ChangesetError::Unsupported(format!("layer media type {media_type}")))?;
    match media {
        MediaType::OciLayer | MediaType::OciLayerNondistributable => Ok(Box::new(reader)),
        MediaType::OciLayerGzip
        | MediaType::DockerLayerGzip
        | MediaType::OciLayerNondistributableGzip => Ok(Box::new(MultiGzDecoder::new(reader))),
        MediaType::OciLayerZstd | MediaType::OciLayerNondistributableZstd => {
            let mut decoder = zstd::Decoder::new(reader)?;
            decoder.window_log_max(23)?;
            Ok(Box::new(decoder))
        }
        MediaType::Other(value) if value == "application/vnd.docker.image.rootfs.diff.tar" => {
            Ok(Box::new(reader))
        }
        _ => Err(ChangesetError::Unsupported(format!(
            "layer media type {media_type}"
        ))),
    }
}

/// Blocking, bounded-memory ingestion. Async callers must run this entire
/// operation on a blocking worker, not hash large source files on an executor.
pub fn ingest_layer(
    source: &Path,
    input: &LayerInput,
    staging_root: &Path,
    operation: &StagingOperation,
    limits: &ChangesetLimits,
) -> ChangesetResult<StagedChangeset> {
    limits.validate()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(source)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ChangesetError::Invalid(
            "layer source is not a regular file".into(),
        ));
    }
    if metadata.len() != input.size_bytes {
        return Err(ChangesetError::Invalid(format!(
            "descriptor size mismatch: expected {}, actual {}",
            input.size_bytes,
            metadata.len()
        )));
    }
    let staging = StagingDir::create(staging_root, operation).map_err(|error| match error {
        crate::OciError::Io(source) => ChangesetError::Io(source),
        other => ChangesetError::Invalid(other.to_string()),
    })?;
    ingest_staged(file, input, staging, limits)
}

fn ingest_staged(
    file: File,
    input: &LayerInput,
    staging: StagingDir,
    limits: &ChangesetLimits,
) -> ChangesetResult<StagedChangeset> {
    let spool_path = staging.path().join("decoded.tar");
    let mut spool = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&spool_path)?;
    let mut transport = TransportReader {
        file,
        hash: Sha256::new(),
        length: 0,
        maximum: input.size_bytes,
    };
    let mut decoded = decoder(
        &input.media_type,
        BufReader::with_capacity(16 * 1024, &mut transport),
    )?;
    let (length, actual) = spool_decoded(decoded.as_mut(), &mut spool, staging.path(), limits)?;
    drop(decoded);
    if transport.length != input.size_bytes {
        return Err(ChangesetError::Invalid(format!(
            "descriptor size mismatch: expected {}, consumed {}",
            input.size_bytes, transport.length
        )));
    }
    let actual_transport = digest(transport.hash);
    if actual_transport != input.blob_digest {
        return Err(ChangesetError::Invalid(format!(
            "descriptor digest mismatch: expected {}, actual {}",
            input.blob_digest, actual_transport
        )));
    }
    drop(transport.file);
    if actual != input.diff_id {
        return Err(ChangesetError::Invalid(format!(
            "decoded diff_id mismatch: expected {}, actual {}",
            input.diff_id, actual
        )));
    }
    spool.flush()?;
    spool.seek(SeekFrom::Start(0))?;
    let pack_path = staging.path().join("payload.pack");
    let mut pack = PackWriter::create(&pack_path, length, allocated_bytes(&spool)?, limits)?;
    let entries = crate::changeset::tar::parse(
        &mut BufReader::with_capacity(16 * 1024, &mut spool),
        &mut pack,
        limits,
    )?;
    let pack_length = pack.finish()?;
    let changeset = LayerChangeset {
        diff_id: actual,
        pack_length,
        entries,
    };
    validate_layer(&changeset, limits)?;
    drop(spool);
    std::fs::remove_file(spool_path)?;
    Ok(StagedChangeset {
        changeset,
        pack_path,
        _staging: staging,
    })
}

// Keep the copy buffer out of the decoder-construction and tar/pack frames.
// In particular, miniz_oxide's heap-state initializer still uses substantial
// temporary stack space in debug builds before returning its boxed state.
#[inline(never)]
fn spool_decoded(
    decoded: &mut dyn Read,
    spool: &mut File,
    staging_path: &Path,
    limits: &ChangesetLimits,
) -> ChangesetResult<(u64, ContentDigest)> {
    let mut hash = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    let mut next_space_check = 0_u64;
    loop {
        let count = decoded.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or_else(|| ChangesetError::Invalid("decoded layer length overflow".into()))?;
        if length > limits.max_expanded_bytes {
            return Err(ChangesetError::Limit {
                resource: "expanded layer bytes",
                actual: length,
                maximum: limits.max_expanded_bytes,
            });
        }
        if length >= next_space_check {
            let reservation = length
                .checked_mul(2)
                .ok_or_else(|| ChangesetError::Invalid("decoded reservation overflow".into()))?;
            ensure_space(
                staging_path,
                reservation.saturating_sub(allocated_bytes(spool)?),
            )?;
            next_space_check = length.saturating_add(8 * 1024 * 1024);
        }
        hash.update(&buffer[..count]);
        spool.write_all(&buffer[..count])?;
    }
    Ok((length, digest(hash)))
}

fn digest(hash: Sha256) -> ContentDigest {
    // ContentDigest's bytes constructor is deliberately the only shared hashing
    // primitive needed here; stream-map identity remains exclusively in libvm.
    ContentDigest::from_hash(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use crate::changeset::ingest::{ingest_layer, LayerInput, StagedChangeset};
    use crate::changeset::{
        ChangesetLimits, ChangesetResult, ContentDigest, EntryKind, SparseRange,
    };
    use crate::StagingOperation;
    use std::io::Write;

    fn operation() -> StagingOperation {
        "00000000-0000-4000-8000-000000000001"
            .to_string()
            .try_into()
            .unwrap()
    }

    fn member(name: &[u8], kind: u8, body: &[u8]) -> Vec<u8> {
        let mut header = ::tar::Header::new_ustar();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(body.len() as u64);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name);
        header.as_mut_bytes()[156] = kind;
        header.set_cksum();
        let mut bytes = header.as_bytes().to_vec();
        bytes.extend_from_slice(body);
        bytes.resize(bytes.len().div_ceil(512) * 512, 0);
        bytes
    }

    fn finish(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.extend([0; 1024]);
        bytes
    }

    fn pax(records: &[(&[u8], &[u8])], global: bool) -> Vec<u8> {
        let mut body = Vec::new();
        for (key, value) in records {
            let base = key.len() + value.len() + 3;
            let mut length = base + 1;
            loop {
                let actual = base + length.to_string().len();
                if actual == length {
                    break;
                }
                length = actual;
            }
            body.extend_from_slice(length.to_string().as_bytes());
            body.push(b' ');
            body.extend_from_slice(key);
            body.push(b'=');
            body.extend_from_slice(value);
            body.push(b'\n');
        }
        member(
            b"PaxHeaders/member",
            if global { b'g' } else { b'x' },
            &body,
        )
    }

    fn attempt(
        bytes: &[u8],
        decoded: &[u8],
        media: &str,
        limits: &ChangesetLimits,
    ) -> (tempfile::TempDir, ChangesetResult<StagedChangeset>) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, bytes).unwrap();
        let input = LayerInput {
            blob_digest: ContentDigest::of_bytes(bytes),
            media_type: media.to_string(),
            size_bytes: bytes.len() as u64,
            diff_id: ContentDigest::of_bytes(decoded),
        };
        let result = ingest_layer(&source, &input, dir.path(), &operation(), limits);
        if result.is_err() {
            assert_eq!(
                std::fs::read_dir(dir.path().join("tmp"))
                    .map(|items| items.count())
                    .unwrap_or(0),
                0,
                "failed ingest leaked publishable staging"
            );
        }
        (dir, result)
    }

    const RAW: &str = "application/vnd.oci.image.layer.v1.tar";
    const GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
    const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

    fn raw(bytes: &[u8]) -> (tempfile::TempDir, StagedChangeset) {
        let (dir, result) = attempt(bytes, bytes, RAW, &ChangesetLimits::default());
        (dir, result.unwrap())
    }

    #[test]
    fn scoped_pack_transfers_the_same_inode_and_releases_its_independent_staging_lock() {
        use nix::fcntl::{Flock, FlockArg};
        use std::os::unix::fs::MetadataExt;

        let bytes = finish(member(b"a", b'0', b"A"));
        let (dir, staged) = raw(&bytes);
        let original = staged.pack_path().to_owned();
        let before = std::fs::metadata(&original).unwrap();
        let parent_root = dir.path().join("flatten");
        let parent = crate::store::StagingDir::create(&parent_root, &operation()).unwrap();
        let scoped = staged.scope(&parent, 0).unwrap();
        let adopted = scoped.pack_path().to_owned();
        let after = std::fs::metadata(&adopted).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.nlink(), 1);
        assert!(!original.exists());
        assert_eq!(scoped.payload(0).unwrap().length, 1);
        let child_lease = std::fs::File::open(
            dir.path()
                .join("locks/publication/stage-00000000-0000-4000-8000-000000000001.lock"),
        )
        .unwrap();
        let _released = Flock::lock(child_lease, FlockArg::LockExclusiveNonblock).unwrap();
        let parent_lease = std::fs::File::open(
            parent_root.join("locks/publication/stage-00000000-0000-4000-8000-000000000001.lock"),
        )
        .unwrap();
        assert!(Flock::lock(parent_lease, FlockArg::LockExclusiveNonblock).is_err());
        drop(scoped);
        assert!(!adopted.exists());
        assert!(parent.path().is_dir());
    }

    #[test]
    fn scoped_pack_transfer_refuses_an_existing_name_without_copying_or_removing_it() {
        let bytes = finish(member(b"a", b'0', b"A"));
        let (dir, staged) = raw(&bytes);
        let original = staged.pack_path().to_owned();
        let parent =
            crate::store::StagingDir::create(&dir.path().join("flatten"), &operation()).unwrap();
        let destination = parent.path().join("layer-0.pack");
        std::fs::write(&destination, b"preserve").unwrap();
        let result = staged.scope(&parent, 0);
        assert!(
            matches!(result, Err(crate::changeset::ChangesetError::Io(error))
            if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::read(destination).unwrap(), b"preserve");
        assert!(!original.exists());
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn transport_size_digest_and_full_diff_id_are_independent_and_atomic() {
        let bytes = finish(member(b"a", b'0', b"A"));
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, &bytes).unwrap();
        let good = LayerInput {
            blob_digest: ContentDigest::of_bytes(&bytes),
            media_type: RAW.into(),
            size_bytes: bytes.len() as u64,
            diff_id: ContentDigest::of_bytes(&bytes),
        };
        for (field, bad) in [
            (
                "size",
                LayerInput {
                    size_bytes: good.size_bytes + 1,
                    ..good.clone()
                },
            ),
            (
                "descriptor digest",
                LayerInput {
                    blob_digest: ContentDigest::of_bytes(b"wrong"),
                    ..good.clone()
                },
            ),
            (
                "diff_id",
                LayerInput {
                    diff_id: ContentDigest::of_bytes(b"wrong"),
                    ..good.clone()
                },
            ),
        ] {
            let error = ingest_layer(
                &source,
                &bad,
                dir.path(),
                &operation(),
                &ChangesetLimits::default(),
            )
            .unwrap_err();
            assert!(error.to_string().contains(field), "{field}: {error}");
            assert!(!dir
                .path()
                .join("tmp/00000000-0000-4000-8000-000000000001")
                .exists());
        }
        let staged = ingest_layer(
            &source,
            &good,
            dir.path(),
            &operation(),
            &ChangesetLimits::default(),
        )
        .unwrap();
        let pack = staged.pack_path().to_path_buf();
        assert!(pack.exists());
        drop(staged);
        assert!(!pack.exists());
    }

    #[test]
    fn all_compression_members_frames_and_suffix_bytes_participate() {
        let mut bytes = finish(member(b"a", b'0', b"A"));
        let prefix = bytes.clone();
        bytes.extend(member(
            b"must-not-appear",
            b'0',
            b"malicious-looking suffix",
        ));
        bytes.extend_from_slice(b"\0nonzero trailing bytes");
        let mut gz = gzip(&bytes[..513]);
        gz.extend(gzip(&bytes[513..prefix.len()]));
        gz.extend(gzip(&bytes[prefix.len()..]));
        let mut zstd = zstd::stream::encode_all(&bytes[..513], 1).unwrap();
        // Legal skippable frames have no decoded output.
        zstd.extend_from_slice(&0x184d2a50_u32.to_le_bytes());
        zstd.extend_from_slice(&3_u32.to_le_bytes());
        zstd.extend_from_slice(b"xyz");
        zstd.extend(zstd::stream::encode_all(&bytes[513..], 1).unwrap());
        for (encoded, media) in [(&bytes, RAW), (&gz, GZIP), (&zstd, ZSTD)] {
            let (_dir, result) = attempt(encoded, &bytes, media, &ChangesetLimits::default());
            let result = result.unwrap();
            assert_eq!(result.changeset().diff_id, ContentDigest::of_bytes(&bytes));
            assert_eq!(result.changeset().entries.len(), 1);
            assert_eq!(result.changeset().entries[0].path, b"a");
            assert_eq!(std::fs::read(result.pack_path()).unwrap()[0], b'A');
            assert!(
                attempt(encoded, &prefix, media, &ChangesetLimits::default())
                    .1
                    .is_err()
            );
        }
    }

    #[test]
    fn compression_errors_after_tar_end_cannot_bypass_admission() {
        let bytes = finish(member(b"a", b'0', b""));
        let mut crc = gzip(&bytes);
        let end = crc.len();
        crc[end - 8] ^= 1;
        let mut second = gzip(&bytes);
        second.extend_from_slice(&[0x1f, 0x8b, 0x08]);
        let mut junk = gzip(&bytes);
        junk.extend_from_slice(b"not another gzip member");
        let mut zstd = zstd::stream::encode_all(bytes.as_slice(), 1).unwrap();
        zstd.extend(zstd::stream::encode_all(b"trailing-only frame".as_slice(), 1).unwrap());
        zstd.pop();
        let mut zstd_junk = zstd::stream::encode_all(bytes.as_slice(), 1).unwrap();
        zstd_junk.extend_from_slice(b"invalid frame suffix");
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.write_all(&bytes).unwrap();
        let mut zstd_crc = encoder.finish().unwrap();
        let last = zstd_crc.len() - 1;
        zstd_crc[last] ^= 1;
        for (encoded, media) in [
            (crc, GZIP),
            (second, GZIP),
            (junk, GZIP),
            (zstd, ZSTD),
            (zstd_junk, ZSTD),
            (zstd_crc, ZSTD),
        ] {
            assert!(
                attempt(&encoded, &bytes, media, &ChangesetLimits::default())
                    .1
                    .is_err()
            );
        }
    }

    #[test]
    fn raw_paths_root_links_whiteouts_and_numeric_metadata_remain_lossless() {
        let mut bytes = member(b".", b'5', b"");
        bytes.extend(pax(
            &[
                (b"uid", b"4294967294"),
                (b"gid", b"4294967294"),
                (b"mtime", b"15032385535.9999999999"),
            ],
            false,
        ));
        bytes.extend(member(b"raw-\xff", b'0', b"X"));
        let mut link = member(b"dangling", b'2', b"");
        link[157..162].copy_from_slice(b"raw-\xfe");
        checksum(&mut link);
        bytes.extend(link);
        let mut hardlink = member(b"cross-parent", b'1', b"");
        hardlink[157..164].copy_from_slice(b"lower/a");
        checksum(&mut hardlink);
        bytes.extend(hardlink);
        bytes.extend(member(b"d/.wh.a", b'0', b""));
        let (_dir, staged) = raw(&finish(bytes));
        let entries = &staged.changeset().entries;
        assert!(matches!(entries[0].kind, EntryKind::RootDirectory));
        assert_eq!(entries[1].path, b"raw-\xff");
        assert_eq!(entries[1].metadata.uid, 4294967294);
        assert_eq!(entries[1].metadata.mtime_seconds, 15032385535);
        assert_eq!(entries[1].metadata.mtime_nanos, 999999999);
        assert!(matches!(&entries[2].kind, EntryKind::Symlink { target } if target == b"raw-\xfe"));
        assert!(matches!(&entries[3].kind, EntryKind::Hardlink { target } if target == b"lower/a"));
        assert!(matches!(entries[4].kind, EntryKind::Whiteout));
        assert_eq!(staged.pack_length(), 4096);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.ordinal)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn exact_slash_directory_preserves_root_metadata_after_effective_path_resolution() {
        for (header_name, path_override) in [
            (b"/".as_slice(), None),
            (b"ignored".as_slice(), Some(b"/".as_slice())),
            (b"/ignored".as_slice(), Some(b"/".as_slice())),
            (b"/".as_slice(), Some(b".".as_slice())),
        ] {
            let mut records = vec![
                (b"mtime".as_slice(), b"7.123456789".as_slice()),
                (
                    b"SCHILY.xattr.user.root".as_slice(),
                    b"\0root\xff".as_slice(),
                ),
            ];
            if let Some(path) = path_override {
                records.push((b"path", path));
            }
            let mut bytes = pax(&records, false);
            let mut root = member(header_name, b'5', b"");
            root[100..108].copy_from_slice(b"0006755\0");
            root[108..116].copy_from_slice(b"0000173\0");
            root[116..124].copy_from_slice(b"0000710\0");
            checksum(&mut root);
            bytes.extend(root);
            bytes.extend(member(b"child", b'0', b"X"));
            let (_dir, staged) = raw(&finish(bytes));
            let entries = &staged.changeset().entries;
            assert_eq!(entries.len(), 2);
            let root = &entries[0];
            assert!(root.path.is_empty());
            assert_eq!(root.kind, EntryKind::RootDirectory);
            assert_eq!(root.ordinal, 0);
            assert_eq!(root.metadata.uid, 123);
            assert_eq!(root.metadata.gid, 456);
            assert_eq!(root.metadata.mode, 0o6755);
            assert_eq!(
                (root.metadata.mtime_seconds, root.metadata.mtime_nanos),
                (7, 123456789)
            );
            assert_eq!(root.metadata.xattrs.len(), 1);
            assert_eq!(root.metadata.xattrs[0].name, b"user.root");
            assert_eq!(root.metadata.xattrs[0].value, b"\0root\xff");
            assert!(root.presence.uid && root.presence.gid && root.presence.mode);
            assert!(root.presence.mtime && root.presence.xattrs);
            assert_eq!(entries[1].path, b"child");
            assert_eq!(entries[1].ordinal, 1);
            assert_eq!(staged.pack_length(), 4096);
        }
        for global in [false, true] {
            let mut bytes = pax(&[(b"path", b"/")], global);
            bytes.extend(member(b"ignored", b'5', b""));
            let (_dir, staged) = raw(&finish(bytes));
            assert_eq!(staged.changeset().entries[0].kind, EntryKind::RootDirectory);
            assert!(staged.changeset().entries[0].path.is_empty());
        }
        // An overriding relative path wins over the raw "/" spelling too.
        let mut bytes = pax(&[(b"path", b"relative")], false);
        bytes.extend(member(b"/", b'5', b""));
        let (_dir, staged) = raw(&finish(bytes));
        assert_eq!(staged.changeset().entries[0].kind, EntryKind::Directory);
        assert_eq!(staged.changeset().entries[0].path, b"relative");
    }

    #[test]
    fn slash_root_exception_does_not_admit_other_absolutes_or_link_targets() {
        fn rejects(bytes: Vec<u8>) {
            let bytes = finish(bytes);
            assert!(matches!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
                Err(crate::changeset::ChangesetError::Invalid(message))
                    if message == "empty, absolute or NUL-containing tar path"
            ));
        }
        for path in [b"//".as_slice(), b"/./", b"/.", b"/nix/", b"/file", b"/../"] {
            rejects(member(path, b'5', b""));
            let mut bytes = pax(&[(b"path", path)], false);
            bytes.extend(member(b"/", b'5', b""));
            rejects(bytes);
        }
        let mut nul = pax(&[(b"path", b"/\0")], false);
        nul.extend(member(b"/", b'5', b""));
        rejects(nul);
        for flag in [0, b'0', b'1', b'2', b'3', b'4', b'6'] {
            let mut entry = member(b"/", flag, b"");
            if matches!(flag, b'1' | b'2') {
                entry[157..163].copy_from_slice(b"target");
            }
            if matches!(flag, b'3' | b'4') {
                entry[329..337].copy_from_slice(b"0000001\0");
                entry[337..345].copy_from_slice(b"0000003\0");
            }
            checksum(&mut entry);
            rejects(entry);
        }
        let mut socket = pax(&[(b"SCHILY.filetype", b"socket")], false);
        socket.extend(member(b"/", b'0', b""));
        rejects(socket);
        let mut regular_override = pax(&[(b"path", b"/")], false);
        regular_override.extend(member(b"ordinary", b'0', b""));
        rejects(regular_override);
        for pax_target in [false, true] {
            let mut bytes = if pax_target {
                pax(&[(b"linkpath", b"/")], false)
            } else {
                Vec::new()
            };
            let mut link = member(b"hardlink", b'1', b"");
            if pax_target {
                link[157..163].copy_from_slice(b"target");
            } else {
                link[157] = b'/';
            }
            checksum(&mut link);
            bytes.extend(link);
            rejects(bytes);
        }
        // Absolute symlink targets remain guest data, not entry paths.
        let mut symlink = member(b"symlink", b'2', b"");
        symlink[157] = b'/';
        checksum(&mut symlink);
        let (_dir, staged) = raw(&finish(symlink));
        assert_eq!(
            staged.changeset().entries[0].kind,
            EntryKind::Symlink {
                target: b"/".to_vec()
            }
        );
    }

    #[test]
    fn slash_and_dot_root_spellings_share_duplicate_detection() {
        let mut cases = Vec::new();
        for (first, second) in [
            (b".".as_slice(), b"/".as_slice()),
            (b"/".as_slice(), b".".as_slice()),
            (b"/".as_slice(), b"/".as_slice()),
        ] {
            let mut bytes = member(first, b'5', b"");
            bytes.extend(member(second, b'5', b""));
            cases.push(bytes);
        }
        for (first, second) in [
            (b"/".as_slice(), b".".as_slice()),
            (b".", b"/"),
            (b"/", b"/"),
        ] {
            let mut bytes = pax(&[(b"path", first)], false);
            bytes.extend(member(b"first", b'5', b""));
            bytes.extend(pax(&[(b"path", second)], false));
            bytes.extend(member(b"second", b'5', b""));
            cases.push(bytes);
        }
        let mut global = pax(&[(b"path", b"/")], true);
        global.extend(member(b"first", b'5', b""));
        global.extend(member(b"second", b'5', b""));
        cases.push(global);
        for bytes in cases {
            let bytes = finish(bytes);
            assert!(matches!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
                Err(crate::changeset::ChangesetError::Invalid(message))
                    if message == "duplicate normalized tar path"
            ));
        }
    }

    fn checksum(member: &mut [u8]) {
        member[148..156].fill(b' ');
        let sum: u64 = member[..512].iter().map(|byte| u64::from(*byte)).sum();
        let encoded = format!("{sum:06o}\0 ");
        member[148..156].copy_from_slice(encoded.as_bytes());
    }

    #[test]
    fn invalid_names_whiteouts_ids_times_flags_and_types_fail_before_publish() {
        for name in [
            b"".as_slice(),
            b"/a",
            b"x/../y",
            b".",
            b"a\0b",
            b".wh.",
            b".wh..",
            b".wh...",
            b"d/.wh.a/file",
        ] {
            let bytes = finish(member(name, b'0', b""));
            assert!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                    .1
                    .is_err(),
                "{name:?}"
            );
        }
        let mut duplicates = member(b"./a//b", b'0', b"");
        duplicates.extend(member(b"a/b", b'0', b""));
        let bytes = finish(duplicates);
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
        for (key, value) in [
            (b"uid".as_slice(), b"4294967295".as_slice()),
            (b"gid", b"-1"),
            (b"uid", b"4294967296"),
            (b"mtime", b"-1"),
            (b"mtime", b"15032385536"),
            (b"SCHILY.fflags", b"immutable"),
            (b"SCHILY.acl.ace", b"unknown"),
            (b"GNU.sparse.major", b"9"),
        ] {
            let mut bytes = pax(&[(key, value)], false);
            bytes.extend(member(b"a", b'0', b""));
            let bytes = finish(bytes);
            assert!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                    .1
                    .is_err(),
                "{key:?}"
            );
        }
        for flag in [b's', b'7', b'V', b'X'] {
            let bytes = finish(member(b"a", flag, b""));
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        for (flag, body) in [(b'5', b"".as_slice()), (b'2', b""), (b'0', b"body")] {
            let bytes = finish(member(b".wh.a", flag, body));
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    #[test]
    fn redundant_unix_source_modes_preserve_metadata_and_reject_conflicts() {
        fn with_mode(mut bytes: Vec<u8>, mode: u64) -> Vec<u8> {
            bytes[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
            checksum(&mut bytes);
            bytes
        }
        // The first shape is the exact mode/type/name encoding in the pinned
        // Kaniko corpus's first source header: bin/, flag5, "0040755\0".
        let mut bytes = with_mode(member(b"bin/", b'5', b""), 0o040755);
        bytes.extend(with_mode(member(b"bin/tool", b'0', b"X"), 0o106755));
        let mut symlink = with_mode(member(b"bin/link", b'2', b""), 0o120777);
        symlink[157..161].copy_from_slice(b"tool");
        checksum(&mut symlink);
        bytes.extend(symlink);
        let (_dir, staged) = raw(&finish(bytes));
        let entries = &staged.changeset().entries;
        assert_eq!(entries[0].path, b"bin");
        assert_eq!(entries[0].kind, EntryKind::Directory);
        assert_eq!(entries[0].metadata.mode, 0o755);
        assert!(matches!(entries[1].kind, EntryKind::Regular(_)));
        assert_eq!(entries[1].metadata.mode, 0o6755);
        assert_eq!(
            entries[2].kind,
            EntryKind::Symlink {
                target: b"tool".to_vec()
            }
        );
        assert_eq!(entries[2].metadata.mode, 0o777);
        let mut expected_pack = vec![0; 4096];
        expected_pack[0] = b'X';
        assert_eq!(std::fs::read(staged.pack_path()).unwrap(), expected_pack);

        for (mode, message) in [
            (0o100755, "tar mode type conflicts with member type"),
            (0o200755, "unknown tar mode bits"),
            (0o030755, "unknown tar mode bits"),
        ] {
            let bytes = finish(with_mode(member(b"bin/", b'5', b""), mode));
            assert!(matches!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
                Err(crate::changeset::ChangesetError::Invalid(actual)) if actual == message
            ));
        }
        for source_type in [0o100000, 0o140000] {
            let mut bytes = pax(&[(b"SCHILY.filetype", b"socket")], false);
            bytes.extend(with_mode(member(b"s", b'0', b""), source_type | 0o1777));
            let (_dir, socket) = raw(&finish(bytes));
            assert_eq!(socket.changeset().entries[0].kind, EntryKind::Socket);
            assert_eq!(socket.changeset().entries[0].metadata.mode, 0o1777);
        }
        // A socket mode without the documented PAX representation cannot
        // invent a socket or be silently downgraded to an ordinary file.
        let bytes = finish(with_mode(member(b"s", b'0', b""), 0o140777));
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
    }

    #[test]
    fn star_fixed_timestamps_are_not_path_bytes_or_effective_mtime() {
        fn star_member(signature: bool) -> Vec<u8> {
            let mut bytes = member(b"socket", b'0', b"");
            bytes[345..351].copy_from_slice(b"parent");
            bytes[476..488].copy_from_slice(b"00000000001 ");
            bytes[488..500].copy_from_slice(b"15271562046 ");
            if signature {
                bytes[508..512].copy_from_slice(b"tar\0");
            }
            checksum(&mut bytes);
            bytes
        }
        let local = pax(
            &[(b"SCHILY.filetype", b"socket"), (b"mtime", b"1.000000007")],
            false,
        );
        for signature in [false, true] {
            let mut bytes = local.clone();
            bytes.extend(star_member(signature));
            let (_dir, staged) = raw(&finish(bytes));
            let socket = &staged.changeset().entries[0];
            assert_eq!(socket.path, b"parent/socket");
            assert_eq!(socket.kind, EntryKind::Socket);
            assert_eq!(
                (socket.metadata.mtime_seconds, socket.metadata.mtime_nanos),
                (1, 7)
            );
            assert_eq!(staged.pack_length(), 0);

            for (offset, replacement) in [
                (352, b'x'),
                (475, b'x'),
                (480, b'8'),
                (492, b'8'),
                (487, b'X'),
                (499, b'X'),
            ] {
                let mut malformed = star_member(signature);
                malformed[offset] = replacement;
                checksum(&mut malformed);
                let mut bytes = local.clone();
                bytes.extend(malformed);
                let bytes = finish(bytes);
                assert!(
                    matches!(
                        attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
                        Err(crate::changeset::ChangesetError::Invalid(_))
                    ),
                    "signature={signature}, byte={offset}"
                );
            }
        }
        // A real full-length ordinary USTAR prefix must not be shortened to
        // the star prefix merely because both formats share USTAR magic.
        let mut bytes = member(b"file", b'0', b"");
        bytes[345..500].fill(b'a');
        checksum(&mut bytes);
        let (_dir, ordinary) = raw(&finish(bytes));
        let expected = [vec![b'a'; 155], b"/file".to_vec()].concat();
        assert_eq!(ordinary.changeset().entries[0].path, expected);
    }

    #[test]
    fn star_global_provenance_is_nonpreserved_without_ignoring_unknown_metadata() {
        let provenance = [
            (
                b"SCHILY.release".as_slice(),
                b"star 1.7.0 (--) 2023/01/11".as_slice(),
            ),
            (b"SCHILY.archtype".as_slice(), b"exustar".as_slice()),
            (
                b"SCHILY.volhdr.dumpdate".as_slice(),
                b"1793516582.029143653".as_slice(),
            ),
            (b"SCHILY.volhdr.volno".as_slice(), b"1".as_slice()),
            (b"SCHILY.volhdr.blocksize".as_slice(), b"20".as_slice()),
        ];
        let mut filesystem = pax(
            &[(b"SCHILY.filetype", b"socket"), (b"mtime", b"1.000000007")],
            false,
        );
        filesystem.extend(member(b"socket", b'0', b""));
        let (_plain_dir, plain) = raw(&finish(filesystem.clone()));
        let mut bytes = pax(&provenance, true);
        bytes.extend(filesystem.clone());
        let (_dir, staged) = raw(&finish(bytes));
        assert_eq!(staged.changeset().entries, plain.changeset().entries);
        assert_ne!(staged.changeset().diff_id, plain.changeset().diff_id);
        assert_eq!(staged.pack_length(), 0);
        let socket = &staged.changeset().entries[0];
        assert_eq!(socket.kind, EntryKind::Socket);
        assert_eq!(
            (socket.metadata.mtime_seconds, socket.metadata.mtime_nanos),
            (1, 7)
        );
        assert_eq!(socket.metadata.mode, 0o644);
        assert!(socket.metadata.xattrs.is_empty());

        // The documented provenance fields are global-only, not a local
        // extension namespace whose per-inode metadata can disappear.
        for record in provenance {
            let mut bytes = pax(&[record], false);
            bytes.extend(filesystem.clone());
            let bytes = finish(bytes);
            assert!(matches!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
                Err(crate::changeset::ChangesetError::Unsupported(message))
                    if message == format!("PAX metadata keyword {}", String::from_utf8_lossy(record.0))
            ));
        }
        for key in [
            b"SCHILY.release.extra".as_slice(),
            b"SCHILY.archtype.extra",
            b"SCHILY.volhdr.future",
            b"SCHILY.volhdr.blockoff",
            b"SCHILY.fflags",
            b"SCHILY.acl.ace",
            b"SCHILY.realsize",
        ] {
            for global in [false, true] {
                let mut bytes = pax(&[(key, b"1")], global);
                bytes.extend(filesystem.clone());
                let bytes = finish(bytes);
                let expected = if key == b"SCHILY.acl.ace" {
                    "unsupported ACL metadata encoding".to_string()
                } else {
                    format!("PAX metadata keyword {}", String::from_utf8_lossy(key))
                };
                assert!(matches!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
                    Err(crate::changeset::ChangesetError::Unsupported(message))
                        if message == expected
                ));
            }
        }
        let mut malformed = pax(&[provenance[0]], true);
        let newline = malformed[512..]
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap();
        malformed[512 + newline] = b'X';
        malformed.extend(filesystem);
        let bytes = finish(malformed);
        assert!(matches!(
            attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
            Err(crate::changeset::ChangesetError::Invalid(_))
        ));
    }

    #[test]
    fn pax_global_local_size_overrides_long_names_and_binary_attrs_are_exact() {
        let mut bytes = pax(&[(b"uid", b"7"), (b"mtime", b"1")], true);
        bytes.extend(pax(
            &[
                (b"uid", b"8"),
                (b"size", b"3"),
                (b"SCHILY.xattr.user.binary", b"\0\n\xff"),
                (b"mtime", b"1.1234567899"),
            ],
            false,
        ));
        let mut overridden = member(b"a", b'0', b"ABC");
        overridden[124..136].copy_from_slice(b"00000000000\0");
        checksum(&mut overridden);
        bytes.extend(overridden);
        bytes.extend(member(b"LongName", b'L', b"./long/path\0"));
        bytes.extend(member(b"ignored", b'0', b"Z"));
        let (_dir, staged) = raw(&finish(bytes));
        let entries = &staged.changeset().entries;
        assert_eq!(entries[0].metadata.uid, 8);
        assert_eq!(entries[1].metadata.uid, 7);
        assert_eq!(entries[0].metadata.mtime_nanos, 123456789);
        assert_eq!(entries[0].metadata.xattrs[0].value, b"\0\n\xff");
        assert_eq!(entries[1].path, b"long/path");
        let pack = std::fs::read(staged.pack_path()).unwrap();
        assert_eq!(&pack[..3], b"ABC");
        assert_eq!(pack[4096], b'Z');
    }

    #[test]
    fn socket_pax_and_device_profiles_have_no_payload_and_no_host_extraction() {
        let mut bytes = pax(&[(b"SCHILY.filetype", b"socket")], false);
        bytes.extend(member(b"socket", b'0', b""));
        bytes.extend(member(b"fifo", b'6', b""));
        let mut device = member(b"null", b'3', b"");
        device[329..337].copy_from_slice(b"0000001\0");
        device[337..345].copy_from_slice(b"0000003\0");
        checksum(&mut device);
        bytes.extend(device);
        let mut device = member(b"block", b'4', b"");
        device[329..337].copy_from_slice(b"0000010\0");
        device[337..345].copy_from_slice(b"0000000\0");
        checksum(&mut device);
        bytes.extend(device);
        let (_dir, staged) = raw(&finish(bytes));
        assert!(matches!(
            staged.changeset().entries[0].kind,
            EntryKind::Socket
        ));
        assert!(matches!(
            staged.changeset().entries[1].kind,
            EntryKind::Fifo
        ));
        assert!(matches!(
            staged.changeset().entries[2].kind,
            EntryKind::CharacterDevice { major: 1, minor: 3 }
        ));
        assert!(matches!(
            staged.changeset().entries[3].kind,
            EntryKind::BlockDevice { major: 8, minor: 0 }
        ));
        assert_eq!(staged.pack_length(), 0);
        for (flag, body) in [(b'0', b"X".as_slice()), (b'5', b"")] {
            let mut bytes = pax(&[(b"SCHILY.filetype", b"socket")], false);
            bytes.extend(member(b"a", flag, body));
            let bytes = finish(bytes);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        for (major, minor) in [
            (b"4096".as_slice(), b"0".as_slice()),
            (b"1", b"1048576"),
            (b"-1", b"1"),
            (b"4294967296", b"1"),
        ] {
            let mut bytes = pax(
                &[(b"SCHILY.devmajor", major), (b"SCHILY.devminor", minor)],
                false,
            );
            bytes.extend(member(b"device", b'4', b""));
            let bytes = finish(bytes);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        let bytes = finish(member(b"reserved", b'3', b""));
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
    }

    fn sparse_pax(version: u8) -> Vec<u8> {
        let mut records = vec![
            (b"GNU.sparse.size".as_slice(), b"4097".as_slice()),
            (b"GNU.sparse.numblocks".as_slice(), b"1".as_slice()),
        ];
        if version == 0 {
            records.extend([
                (b"GNU.sparse.offset".as_slice(), b"4096".as_slice()),
                (b"GNU.sparse.numbytes".as_slice(), b"1".as_slice()),
            ]);
        } else {
            records.push((b"GNU.sparse.map", b"4096,1"));
        }
        let mut bytes = pax(&records, false);
        bytes.extend(member(b"sparse", b'0', b"X"));
        finish(bytes)
    }

    #[test]
    fn all_four_sparse_forms_produce_exact_logical_pack_and_source_ranges() {
        let mut old = member(b"sparse", b'S', b"X");
        old[257..265].copy_from_slice(b"ustar  \0");
        old[386..398].copy_from_slice(b"00000010000\0");
        old[398..410].copy_from_slice(b"00000000001\0");
        old[483..495].copy_from_slice(b"00000010001\0");
        checksum(&mut old);
        let mut map = b"1\n4096\n1\n".to_vec();
        map.resize(512, 0);
        map.push(b'X');
        let mut one = pax(
            &[
                (b"GNU.sparse.major", b"1"),
                (b"GNU.sparse.minor", b"0"),
                (b"GNU.sparse.realsize", b"4097"),
            ],
            false,
        );
        one.extend(member(b"sparse", b'0', &map));
        for bytes in [finish(old), sparse_pax(0), sparse_pax(1), finish(one)] {
            let (_dir, staged) = raw(&bytes);
            assert_eq!(staged.pack_length(), 8192);
            let mut expected = vec![0; 8192];
            expected[4096] = b'X';
            assert_eq!(std::fs::read(staged.pack_path()).unwrap(), expected);
            let EntryKind::Regular(body) = &staged.changeset().entries[0].kind else {
                panic!("not regular")
            };
            assert_eq!(body.length, 4097);
            assert_eq!(
                body.sparse,
                vec![SparseRange {
                    offset: 4096,
                    length: 1
                }]
            );
        }
    }

    #[test]
    fn malformed_sparse_maps_and_framing_never_return_staging() {
        for map in [
            b"4096".as_slice(),
            b"4096,2",
            b"4096,1,0,0",
            b"18446744073709551615,2",
            b"4097,1",
            b"0,2,1,1",
        ] {
            let mut bytes = pax(
                &[
                    (b"GNU.sparse.size", b"4097"),
                    (b"GNU.sparse.numblocks", b"1"),
                    (b"GNU.sparse.map", map),
                ],
                false,
            );
            bytes.extend(member(b"sparse", b'0', b"X"));
            let bytes = finish(bytes);
            assert!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                    .1
                    .is_err(),
                "{map:?}"
            );
        }
        let mut checksum_bad = finish(member(b"a", b'0', b"A"));
        checksum_bad[0] ^= 1;
        let short = member(b"a", b'0', b"A")[..512].to_vec();
        let mut bad_pax = member(b"pax", b'x', b"99999999999999999999 path=a\n");
        bad_pax.extend(member(b"a", b'0', b""));
        for bytes in [checksum_bad, short, finish(bad_pax), vec![0; 512]] {
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    #[test]
    fn tightened_bounds_are_enforced_on_actual_decoded_and_logical_bytes() {
        let bytes = finish(member(b"a", b'0', b"AB"));
        for media in [RAW, GZIP, ZSTD] {
            let encoded = match media {
                GZIP => gzip(&bytes),
                ZSTD => zstd::stream::encode_all(bytes.as_slice(), 1).unwrap(),
                _ => bytes.clone(),
            };
            let limits = ChangesetLimits {
                max_expanded_bytes: bytes.len() as u64,
                ..ChangesetLimits::default()
            };
            assert!(attempt(&encoded, &bytes, media, &limits).1.is_ok());
            let limits = ChangesetLimits {
                max_expanded_bytes: bytes.len() as u64 - 1,
                ..limits
            };
            assert!(attempt(&encoded, &bytes, media, &limits).1.is_err());
        }
        let limits = ChangesetLimits {
            max_file_bytes: 1,
            ..ChangesetLimits::default()
        };
        assert!(attempt(&bytes, &bytes, RAW, &limits).1.is_err());
        let sparse = sparse_pax(1);
        assert!(attempt(&sparse, &sparse, RAW, &limits).1.is_err());
        for limits in [
            ChangesetLimits {
                max_pack_bytes: 4095,
                ..ChangesetLimits::default()
            },
            ChangesetLimits {
                max_extension_bytes: 8,
                ..ChangesetLimits::default()
            },
        ] {
            assert!(attempt(&sparse, &sparse, RAW, &limits).1.is_err());
        }
    }

    #[test]
    fn full_ingest_fits_a_small_stack_and_repeated_artifacts_are_parent_independent() {
        let bytes = finish(member(b"a", b'0', &vec![0x5a; 256 * 1024 + 113]));
        let encoded = gzip(&bytes);
        std::thread::Builder::new()
            .name("changeset-ingest-small-stack".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let (_dir, one) = attempt(&encoded, &bytes, GZIP, &ChangesetLimits::default());
                let one = one.unwrap();
                let (_dir, two) = raw(&bytes);
                assert_eq!(one.changeset(), two.changeset());
                assert_eq!(
                    std::fs::read(one.pack_path()).unwrap(),
                    std::fs::read(two.pack_path()).unwrap()
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn zstd_window_limit_is_independent_from_decoded_output_limit() {
        let bytes = finish(member(b"a", b'0', b"A"));
        let frame = |window: u8| {
            let mut frame = 0xfd2fb528_u32.to_le_bytes().to_vec();
            frame.extend([0, window]); // no content-size field, explicit window
            let block = ((bytes.len() as u32) << 3) | 1; // raw final block
            frame.extend_from_slice(&block.to_le_bytes()[..3]);
            frame.extend_from_slice(&bytes);
            frame
        };
        let at = frame((23 - 10) << 3);
        assert!(attempt(&at, &bytes, ZSTD, &ChangesetLimits::default())
            .1
            .is_ok());
        let above = frame(((23 - 10) << 3) + 1);
        assert!(attempt(&above, &bytes, ZSTD, &ChangesetLimits::default())
            .1
            .is_err());
        let mut claim = 0xfd2fb528_u32.to_le_bytes().to_vec();
        claim.extend([0xc0, (23 - 10) << 3]); // eight-byte content-size claim
        claim.extend_from_slice(&(1_u64 << 40).to_le_bytes());
        let block = ((bytes.len() as u32) << 3) | 1;
        claim.extend_from_slice(&block.to_le_bytes()[..3]);
        claim.extend_from_slice(&bytes);
        assert!(attempt(&claim, &bytes, ZSTD, &ChangesetLimits::default())
            .1
            .is_err());
    }

    #[test]
    fn parser_metadata_matrix_preserves_acl_caps_labels_and_rejects_loss() {
        let mut capability = 0x02000001_u32.to_le_bytes().to_vec();
        capability.extend_from_slice(&[1, 0, 0, 0]);
        capability.extend([0; 12]);
        let acl = b"user::rw-,user:7:r--,group::r--,mask::r--,other::r--";
        let mut bytes = pax(
            &[
                (b"SCHILY.acl.access", acl),
                (b"SCHILY.xattr.security.capability", &capability),
                (
                    b"SCHILY.xattr.security.selinux",
                    b"system_u:object_r:container_file_t:s0\0",
                ),
                (b"SCHILY.xattr.trusted.admitted", b"\xff\0"),
                (b"SCHILY.xattr.user.empty", b""),
                (b"LIBARCHIVE.xattr.user.binary", b"AP8K"),
            ],
            false,
        );
        bytes.extend(member(b"a", b'0', b"A"));
        let (_dir, staged) = raw(&finish(bytes));
        let metadata = &staged.changeset().entries[0].metadata;
        assert_eq!(metadata.xattrs.len(), 6);
        assert!(metadata
            .xattrs
            .iter()
            .any(|a| a.name == b"user.empty" && a.value.is_empty()));
        assert!(metadata
            .xattrs
            .iter()
            .any(|a| a.name == b"user.binary" && a.value == b"\0\xff\n"));
        assert!(metadata
            .xattrs
            .iter()
            .any(|a| a.name == b"security.capability" && a.value == capability));
        assert!(staged.changeset().entries[0].presence.acl_access);
        let binary_acl = literal_access_acl();
        assert_eq!(
            metadata
                .xattrs
                .iter()
                .find(|a| a.name == b"system.posix_acl_access")
                .unwrap()
                .value,
            binary_acl
        );
        let mut equal = pax(
            &[
                (b"SCHILY.acl.access", acl),
                (b"SCHILY.xattr.system.posix_acl_access", &binary_acl),
            ],
            false,
        );
        equal.extend(member(b"a", b'0', b""));
        raw(&finish(equal));
        let mut wrong_acl = binary_acl.clone();
        wrong_acl[14] = 2; // named UID7 only, not owner/mask/other
        for binary in [&binary_acl, &wrong_acl] {
            let mut bytes = pax(&[(b"SCHILY.xattr.system.posix_acl_access", binary)], false);
            bytes.extend(member(b"a", b'0', b""));
            raw(&finish(bytes));
        }
        for records in [
            vec![
                (b"SCHILY.acl.access".as_slice(), acl.as_slice()),
                (
                    b"SCHILY.xattr.system.posix_acl_access".as_slice(),
                    wrong_acl.as_slice(),
                ),
            ],
            vec![
                (
                    b"SCHILY.xattr.system.posix_acl_access".as_slice(),
                    wrong_acl.as_slice(),
                ),
                (b"SCHILY.acl.access".as_slice(), acl.as_slice()),
            ],
        ] {
            let mut bytes = pax(&records, false);
            bytes.extend(member(b"a", b'0', b""));
            let bytes = finish(bytes);
            let error = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("conflicting xattr representations"),
                "{error}"
            );
        }
        for records in [
            vec![(b"SCHILY.xattr.security.ima".as_slice(), b"bad".as_slice())],
            vec![(
                b"SCHILY.xattr.user.overlay.opaque".as_slice(),
                b"y".as_slice(),
            )],
            vec![(
                b"SCHILY.xattr.trusted.overlay.metacopy".as_slice(),
                b"y".as_slice(),
            )],
            vec![(
                b"SCHILY.xattr.security.capability".as_slice(),
                b"bad".as_slice(),
            )],
            vec![(
                b"SCHILY.acl.default".as_slice(),
                b"user::rw-,group::r--,other::r--".as_slice(),
            )],
        ] {
            let mut bytes = pax(&records, false);
            bytes.extend(member(b"a", b'0', b""));
            let bytes = finish(bytes);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        let mut setid = member(b"a", b'0', b"");
        setid[100..108].copy_from_slice(b"0006755\0");
        checksum(&mut setid);
        let (_dir, staged) = raw(&finish(setid));
        assert_eq!(staged.changeset().entries[0].metadata.mode, 0o6755);
    }

    #[test]
    fn parser_xattr_and_path_boundaries_are_inclusive() {
        for length in [3044, 3045] {
            let value = vec![0; length];
            let mut bytes = pax(&[(b"SCHILY.xattr.user.a", &value)], false);
            bytes.extend(member(b"a", b'0', b""));
            let bytes = finish(bytes);
            assert_eq!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                    .1
                    .is_ok(),
                length == 3044
            );
        }
        for count in [64, 65] {
            let keys = (0..count)
                .map(|n| format!("SCHILY.xattr.user.{n:02}").into_bytes())
                .collect::<Vec<_>>();
            let records = keys
                .iter()
                .map(|key| (key.as_slice(), b"".as_slice()))
                .collect::<Vec<_>>();
            let mut bytes = pax(&records, false);
            bytes.extend(member(b"a", b'0', b""));
            let bytes = finish(bytes);
            assert_eq!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                    .1
                    .is_ok(),
                count == 64
            );
        }
        let mut path = Vec::new();
        for _ in 0..15 {
            path.extend(vec![b'a'; 255]);
            path.push(b'/');
        }
        path.extend(vec![b'b'; 254]);
        path.extend_from_slice(b"/c");
        assert_eq!(path.len(), 4096);
        for (name, accepted) in [
            (path.clone(), true),
            ([path, b"x".to_vec()].concat(), false),
            (vec![b'a'; 255], true),
            (vec![b'a'; 256], false),
            (vec![b"a".as_slice(); 256].join(b"/".as_slice()), true),
            (vec![b"a".as_slice(); 257].join(b"/".as_slice()), false),
        ] {
            let mut bytes = pax(&[(b"path", &name)], false);
            bytes.extend(member(b"ignored", b'0', b""));
            let bytes = finish(bytes);
            assert_eq!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                    .1
                    .is_ok(),
                accepted,
                "{} bytes",
                name.len()
            );
        }
        let mut bytes = member(b"a", b'0', b"");
        bytes.extend(member(b"b", b'0', b""));
        let bytes = finish(bytes);
        assert!(attempt(
            &bytes,
            &bytes,
            RAW,
            &ChangesetLimits {
                max_entries: 1,
                ..ChangesetLimits::default()
            }
        )
        .1
        .is_err());
    }

    #[test]
    fn sparse_continuations_all_holes_and_long_mtime_fractions_are_streamed() {
        let mut old = member(b"sparse", b'S', b"ABCDX");
        old[257..265].copy_from_slice(b"ustar  \0");
        old[482] = 1;
        for (index, offset) in [0, 1024, 2048, 3072].into_iter().enumerate() {
            let start = 386 + index * 24;
            old[start..start + 12].copy_from_slice(format!("{offset:011o}\0").as_bytes());
            old[start + 12..start + 24].copy_from_slice(b"00000000001\0");
        }
        old[483..495].copy_from_slice(b"00000010001\0");
        checksum(&mut old);
        let mut continuation = vec![0; 512];
        continuation[..12].copy_from_slice(b"00000010000\0");
        continuation[12..24].copy_from_slice(b"00000000001\0");
        let mut bytes = old[..512].to_vec();
        bytes.extend(continuation);
        bytes.extend_from_slice(&old[512..]);
        let (_dir, staged) = raw(&finish(bytes));
        assert_eq!(std::fs::read(staged.pack_path()).unwrap()[4096], b'X');
        let mut bytes = pax(
            &[
                (b"GNU.sparse.size", b"4097"),
                (b"GNU.sparse.numblocks", b"1"),
                (b"GNU.sparse.map", b"4097,0"),
            ],
            false,
        );
        bytes.extend(member(b"all-hole", b'0', b""));
        let (_dir, staged) = raw(&finish(bytes));
        assert_eq!(std::fs::read(staged.pack_path()).unwrap(), vec![0; 8192]);
        let mut time = b"1.123456789".to_vec();
        time.extend(vec![b'9'; 10000]);
        let mut bytes = pax(&[(b"mtime", &time)], false);
        bytes.extend(member(b"a", b'0', b""));
        let (_dir, staged) = raw(&finish(bytes));
        assert_eq!(
            staged.changeset().entries[0].metadata.mtime_nanos,
            123456789
        );
    }

    #[test]
    fn numeric_acl_names_and_overridden_header_fields_are_streamed_not_defaulted() {
        let mut owner = vec![b'0'; 10000];
        owner.push(b'7');
        let mut acl = b"user::rw-,user:".to_vec();
        acl.extend(vec![b'x'; 20000]);
        acl.extend_from_slice(b":r--:7,group::r--,mask::r--,other::r--");
        let mut bytes = pax(
            &[
                (b"path", b"effective"),
                (b"size", b"1"),
                (b"uid", &owner),
                (b"SCHILY.acl.access", &acl),
                (b"LIBARCHIVE.xattr.user.a", b"AP8"),
                (b"LIBARCHIVE.xattr.user.b", b"AP8="),
            ],
            false,
        );
        let mut item = member(b"bad", b'0', b"X");
        item[3..5].copy_from_slice(b"\0x");
        item[108..116].fill(b'x');
        item[124..136].fill(b'x');
        checksum(&mut item);
        bytes.extend(item);
        let (_dir, staged) = raw(&finish(bytes));
        let entry = &staged.changeset().entries[0];
        assert_eq!(entry.path, b"effective");
        assert_eq!(entry.metadata.uid, 7);
        assert_eq!(
            entry
                .metadata
                .xattrs
                .iter()
                .filter(|a| a.name.starts_with(b"user."))
                .map(|a| a.value.as_slice())
                .collect::<Vec<_>>(),
            vec![b"\0\xff".as_slice(); 2]
        );
        for range in [100..108, 108..116, 116..124, 136..148] {
            let mut item = member(b"a", b'0', b"");
            item[range].fill(0);
            checksum(&mut item);
            let bytes = finish(item);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    fn literal_access_acl() -> Vec<u8> {
        // Independently authored Linux UAPI version2 and LE records:
        // owner6, UID7 permission4, group4, mask4, other4.
        vec![
            2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 4, 0, 7, 0, 0, 0, 4, 0, 4, 0, 255,
            255, 255, 255, 16, 0, 4, 0, 255, 255, 255, 255, 32, 0, 4, 0, 255, 255, 255, 255,
        ]
    }

    fn metadata_archive(records: &[(&[u8], &[u8])], flag: u8) -> Vec<u8> {
        let mut bytes = pax(records, false);
        let mut item = member(b"a", flag, b"");
        if matches!(flag, b'1' | b'2') {
            item[157..162].copy_from_slice(b"lower");
        }
        if matches!(flag, b'3' | b'4') {
            item[329..337].copy_from_slice(b"0000001\0");
            item[337..345].copy_from_slice(b"0000003\0");
        }
        checksum(&mut item);
        bytes.extend(item);
        finish(bytes)
    }

    #[test]
    fn xattr_dialects_raw_names_and_strict_percent_escapes_have_exact_meaning() {
        for suffix in [
            b"user.a%3Db".as_slice(),
            b"user.a%25b",
            b"user.%20",
            b"user.%FF",
            b"user.%0a",
        ] {
            let mut key = b"SCHILY.xattr.".to_vec();
            key.extend_from_slice(suffix);
            let mut lib = b"LIBARCHIVE.xattr.".to_vec();
            lib.extend_from_slice(suffix);
            for records in [
                vec![(key.as_slice(), b"v".as_slice())],
                vec![
                    (key.as_slice(), b"v".as_slice()),
                    (lib.as_slice(), b"dg==".as_slice()),
                ],
            ] {
                let bytes = metadata_archive(&records, b'0');
                assert!(matches!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
                    Err(crate::changeset::ChangesetError::Unsupported(_))
                ));
            }
        }
        for (raw_name, encoded) in [
            (b"user.a b".as_slice(), b"user.a%20b".as_slice()),
            (b"user.\xc3\xa9", b"user.%C3%A9"),
            (b"user.\xff", b"user.%fF"),
            (b"user.a%41", b"user.a%2541"),
            (b"user.a+b", b"user.a+b"),
        ] {
            let mut key = b"SCHILY.xattr.".to_vec();
            key.extend_from_slice(raw_name);
            let mut lib = b"LIBARCHIVE.xattr.".to_vec();
            lib.extend_from_slice(encoded);
            let bytes = metadata_archive(&[(key.as_slice(), b"v"), (lib.as_slice(), b"dg")], b'0');
            let (_dir, staged) = raw(&bytes);
            assert_eq!(
                staged.changeset().entries[0].metadata.xattrs,
                vec![crate::changeset::Xattr {
                    name: raw_name.to_vec(),
                    value: b"v".to_vec()
                }]
            );
        }
        for (encoded, expected) in [
            (b"user.a%253Db".as_slice(), b"user.a%3Db".as_slice()),
            (b"user.%25", b"user.%"),
            (b"user.%3d", b"user.="),
            (b"user.%FF", b"user.\xff"),
        ] {
            let mut key = b"LIBARCHIVE.xattr.".to_vec();
            key.extend_from_slice(encoded);
            let bytes = metadata_archive(&[(key.as_slice(), b"")], b'0');
            let (_dir, staged) = raw(&bytes);
            assert_eq!(
                staged.changeset().entries[0].metadata.xattrs[0].name,
                expected
            );
        }
        for suffix in [
            b"user.%+1".as_slice(),
            b"user.%+A",
            b"user.%",
            b"user.%A",
            b"user.%GG",
            b"user.%00",
        ] {
            let mut key = b"LIBARCHIVE.xattr.".to_vec();
            key.extend_from_slice(suffix);
            let bytes = metadata_archive(&[(key.as_slice(), b"dg==")], b'0');
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        for length in [255, 256] {
            let name = [b"user.".as_slice(), vec![b'a'; length - 5].as_slice()].concat();
            for prefix in [b"SCHILY.xattr.".as_slice(), b"LIBARCHIVE.xattr."] {
                let key = [prefix, name.as_slice()].concat();
                let bytes = metadata_archive(&[(key.as_slice(), b"")], b'0');
                assert_eq!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                        .1
                        .is_ok(),
                    length == 255
                );
            }
        }
        for key in [
            b"SCHILY.xattr.user.".as_slice(),
            b"SCHILY.xattr.user.a\0b",
            b"unknown.\xff",
        ] {
            let bytes = metadata_archive(&[(key, b"")], b'0');
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    #[test]
    fn smack_labels_and_transmute_follow_linux_grammar_and_inode_type() {
        for key in [
            b"SCHILY.xattr.security.SMACK64".as_slice(),
            b"SCHILY.xattr.security.SMACK64EXEC",
            b"SCHILY.xattr.security.SMACK64MMAP",
        ] {
            for value in [b"a".to_vec(), vec![b'a'; 255]] {
                let bytes = metadata_archive(&[(key, &value)], b'0');
                let (_dir, staged) = raw(&bytes);
                assert_eq!(
                    staged.changeset().entries[0].metadata.xattrs[0].value,
                    value
                );
            }
            for value in [
                vec![],
                vec![b'a'; 256],
                b"-bad".to_vec(),
                b"\0".to_vec(),
                b"a\0suffix".to_vec(),
                b"a\0".to_vec(),
                b"a b".to_vec(),
                b"a/b".to_vec(),
                b"a\"b".to_vec(),
                b"a'b".to_vec(),
                b"a\\b".to_vec(),
                b"\xff".to_vec(),
            ] {
                let bytes = metadata_archive(&[(key, &value)], b'0');
                assert!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                        .1
                        .is_err(),
                    "{key:?} {value:?}"
                );
            }
            for special in [b"*".as_slice(), b"@"] {
                let bytes = metadata_archive(&[(key, special)], b'0');
                assert_eq!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                        .1
                        .is_ok(),
                    key == b"SCHILY.xattr.security.SMACK64"
                );
            }
        }
        let key = b"SCHILY.xattr.security.SMACK64TRANSMUTE".as_slice();
        for flag in [0, b'0', b'1', b'2', b'3', b'4', b'5', b'6'] {
            for value in [b"TRUE".as_slice(), b"TRUE\0", b"true", b""] {
                let bytes = metadata_archive(&[(key, value)], flag);
                assert_eq!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                        .1
                        .is_ok(),
                    flag == b'5' && value == b"TRUE"
                );
            }
        }
        let bytes = metadata_archive(&[(key, b"TRUE"), (b"SCHILY.filetype", b"socket")], b'0');
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
        let mut bytes = pax(&[(key, b"TRUE")], false);
        bytes.extend(member(b".", b'5', b""));
        raw(&finish(bytes));
    }

    #[test]
    fn acl_numeric_syntax_is_distinct_from_overflow_or_advisory_names() {
        for principal in [
            "4294967294",
            "4294967295",
            "4294967296",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            for kind in ["user", "group"] {
                for fourth in [None, Some(principal), Some("7")] {
                    let suffix = fourth.map(|id| format!(":{id}")).unwrap_or_default();
                    let acl = format!(
                        "user::rw-,{kind}:{principal}:r--{suffix},group::r--,mask::r--,other::r--"
                    );
                    let bytes = metadata_archive(&[(b"SCHILY.acl.access", acl.as_bytes())], b'0');
                    assert_eq!(
                        attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                            .1
                            .is_ok(),
                        principal == "4294967294" && fourth != Some("7"),
                        "{acl}"
                    );
                }
            }
        }
        for principal in [
            format!("{}7", "0".repeat(10000)),
            "account-name".into(),
            format!("{}name", "9".repeat(10000)),
        ] {
            let acl = format!("user::rw-,user:{principal}:r--:7,group::r--,mask::r--,other::r--");
            let bytes = metadata_archive(&[(b"SCHILY.acl.access", acl.as_bytes())], b'0');
            let (_dir, staged) = raw(&bytes);
            assert_eq!(
                staged.changeset().entries[0].metadata.xattrs[0].value,
                literal_access_acl()
            );
        }
        for id in ["4294967295", "4294967296", "18446744073709551616"] {
            let acl = format!("user::rw-,user:account:r--:{id},group::r--,mask::r--,other::r--");
            let bytes = metadata_archive(&[(b"SCHILY.acl.access", acl.as_bytes())], b'0');
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    #[test]
    fn capability_revision_flags_bits_lengths_and_root_ids_are_exact() {
        let key = b"SCHILY.xattr.security.capability".as_slice();
        let make = |revision: u32, effective: bool, permitted: u32, inherited: u32, root: u32| {
            let mut value = ((revision << 24) | u32::from(effective))
                .to_le_bytes()
                .to_vec();
            value.extend(1_u32.to_le_bytes());
            value.extend(0_u32.to_le_bytes());
            if revision != 1 {
                value.extend(permitted.to_le_bytes());
                value.extend(inherited.to_le_bytes());
            }
            if revision == 3 {
                value.extend(root.to_le_bytes());
            }
            value
        };
        for revision in [1, 2, 3] {
            for effective in [false, true] {
                for root in [0, 4294967294] {
                    let value = make(revision, effective, 0, 0, root);
                    let bytes = metadata_archive(&[(key, &value)], b'0');
                    let (_dir, staged) = raw(&bytes);
                    assert_eq!(
                        staged.changeset().entries[0].metadata.xattrs[0].value,
                        value
                    );
                    let mut longer = value.clone();
                    longer.push(0);
                    for truncated in [&value[..value.len() - 1], longer.as_slice()] {
                        let bytes = metadata_archive(&[(key, truncated)], b'0');
                        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                            .1
                            .is_err());
                    }
                }
            }
        }
        for (permitted, inherited, accepted) in [
            (256, 0, true),
            (0, 256, true),
            (512, 0, false),
            (0, 512, false),
        ] {
            let value = make(2, true, permitted, inherited, 0);
            let bytes = metadata_archive(&[(key, &value)], b'0');
            assert_eq!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                    .1
                    .is_ok(),
                accepted
            );
        }
        let mut flags = make(2, false, 0, 0, 0);
        flags[0] = 2;
        let mut revision = make(2, false, 0, 0, 0);
        revision[3] = 4;
        for value in [flags, revision, make(3, true, 0, 0, u32::MAX)] {
            let bytes = metadata_archive(&[(key, &value)], b'0');
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    #[test]
    fn literal_binary_acl_structure_default_mode_and_conflicts_are_independent() {
        let key = b"SCHILY.xattr.system.posix_acl_access".as_slice();
        let access = literal_access_acl();
        let default = vec![
            2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 4, 0, 0, 0, 255, 255, 255, 255, 32, 0, 0,
            0, 255, 255, 255, 255,
        ];
        let mut malformed = vec![access[..27].to_vec(), access[..29].to_vec()];
        for (index, value) in [(0, 3), (4, 3), (14, 8), (16, 255), (8, 0)] {
            let mut item = access.clone();
            item[index] = value;
            if index == 16 {
                item[16..20].fill(255);
            }
            if index == 8 {
                item[8..12].fill(0);
            }
            malformed.push(item);
        }
        let mut duplicate = access.clone();
        duplicate[20..28].copy_from_slice(&access[12..20]);
        malformed.push(duplicate);
        let mut order = access.clone();
        order[12..20].copy_from_slice(&access[20..28]);
        order[20..28].copy_from_slice(&access[12..20]);
        malformed.push(order);
        let mut missing = access.clone();
        missing.drain(4..12);
        malformed.push(missing);
        let mut no_mask = access.clone();
        no_mask.drain(28..36);
        malformed.push(no_mask);
        for value in malformed {
            let bytes = metadata_archive(&[(key, &value)], b'0');
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        for path in [b".".as_slice(), b"directory"] {
            let mut bytes = pax(
                &[
                    (b"SCHILY.acl.default", b"user::rwx,group::---,other::---"),
                    (b"SCHILY.xattr.system.posix_acl_default", &default),
                ],
                false,
            );
            bytes.extend(member(path, b'5', b""));
            let (_dir, staged) = raw(&finish(bytes));
            assert_eq!(
                staged.changeset().entries[0].metadata.xattrs[0].value,
                default
            );
        }
        let bytes = metadata_archive(
            &[(b"SCHILY.xattr.system.posix_acl_default", &default)],
            b'0',
        );
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
        let bytes = metadata_archive(&[(key, &default)], b'0');
        let error = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("ACL conflicts with permission mode"));
    }

    #[test]
    fn selinux_aliases_and_base64_representations_never_erase_differences() {
        let a = b"system_u:object_r:container_file_t:s0".as_slice();
        let b = b"system_u:object_r:container_file_t:s0\0".as_slice();
        for reverse in [false, true] {
            for global in [false, true] {
                for equal in [false, true] {
                    let mut records = [
                        (b"RHT.security.selinux".as_slice(), a),
                        (
                            b"SCHILY.xattr.security.selinux".as_slice(),
                            if equal { a } else { b },
                        ),
                    ];
                    if reverse {
                        records.reverse();
                    }
                    let bytes = if global {
                        let mut bytes = pax(&records[..1], true);
                        bytes.extend(pax(&records[1..], false));
                        bytes.extend(member(b"a", b'0', b""));
                        finish(bytes)
                    } else {
                        metadata_archive(&records, b'0')
                    };
                    let (_dir, result) = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default());
                    if equal {
                        assert_eq!(
                            result.unwrap().changeset().entries[0].metadata.xattrs,
                            vec![crate::changeset::Xattr {
                                name: b"security.selinux".to_vec(),
                                value: a.to_vec()
                            }]
                        );
                    } else {
                        assert!(result.unwrap_err().to_string().contains("conflicting"));
                    }
                }
            }
        }
        for encoded in [b"+/8=".as_slice(), b"+/8"] {
            let bytes = metadata_archive(&[(b"LIBARCHIVE.xattr.user.a", encoded)], b'0');
            let (_dir, staged) = raw(&bytes);
            assert_eq!(
                staged.changeset().entries[0].metadata.xattrs[0].value,
                b"\xfb\xff"
            );
        }
        for encoded in [
            b"-_8=".as_slice(),
            b"AQ=",
            b"AQ===",
            b"AQ==\n",
            b" AQ==",
            b"AB",
            b"AB==",
        ] {
            let bytes = metadata_archive(&[(b"LIBARCHIVE.xattr.user.a", encoded)], b'0');
            assert!(
                attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                    .1
                    .is_err(),
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn numeric_fixed_base256_pax_modes_times_and_device_boundaries_are_checked() {
        for field in [108..116, 116..124] {
            for id in [0_u64, 4294967294, 4294967295, 4294967296] {
                let mut item = member(b"a", b'0', b"");
                let mut binary = id.to_be_bytes();
                binary[0] |= 0x80;
                item[field.clone()].copy_from_slice(&binary);
                checksum(&mut item);
                let bytes = finish(item);
                let (_dir, result) = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default());
                if id <= 4294967294 {
                    let staged = result.unwrap();
                    let metadata = &staged.changeset().entries[0].metadata;
                    assert_eq!(
                        u64::from(if field.start == 108 {
                            metadata.uid
                        } else {
                            metadata.gid
                        }),
                        id
                    );
                } else {
                    assert!(result.is_err());
                }
            }
            let mut negative = member(b"a", b'0', b"");
            negative[field.clone()].fill(255);
            checksum(&mut negative);
            let bytes = finish(negative);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
            for id in [0, 0o77777777_u64] {
                let mut item = member(b"a", b'0', b"");
                item[field.clone()].copy_from_slice(format!("{id:08o}").as_bytes());
                checksum(&mut item);
                let (_dir, staged) = raw(&finish(item));
                let metadata = &staged.changeset().entries[0].metadata;
                assert_eq!(
                    u64::from(if field.start == 108 {
                        metadata.uid
                    } else {
                        metadata.gid
                    }),
                    id
                );
            }
        }
        for (mode, flag, accepted) in [
            (0, b'0', true),
            (0o7777, b'0', true),
            (0o6755, b'0', true),
            (0o1755, b'5', true),
            (0o10000, b'0', false),
        ] {
            let mut item = member(b"a", flag, b"");
            item[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
            checksum(&mut item);
            let bytes = finish(item);
            let (_dir, result) = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default());
            if accepted {
                assert_eq!(result.unwrap().changeset().entries[0].metadata.mode, mode);
            } else {
                assert!(result.is_err());
            }
        }
        for seconds in [0_u64, 15032385535, 15032385536, u64::MAX] {
            let mut item = member(b"a", b'0', b"");
            let mut field = [0; 12];
            field[4..].copy_from_slice(&seconds.to_be_bytes());
            field[0] = 0x80;
            item[136..148].copy_from_slice(&field);
            checksum(&mut item);
            let bytes = finish(item);
            let (_dir, result) = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default());
            if seconds <= 15032385535 {
                assert_eq!(
                    result.unwrap().changeset().entries[0]
                        .metadata
                        .mtime_seconds,
                    seconds
                );
            } else {
                assert!(result.is_err());
            }
        }
        for (time, seconds, nanos) in [
            (b"0".as_slice(), 0, 0),
            (b"1.1", 1, 100000000),
            (b"1.123456789", 1, 123456789),
            (b"1.1234567890", 1, 123456789),
            (b"1.000000000000", 1, 0),
            (b"15032385535.9999999999", 15032385535, 999999999),
        ] {
            let bytes = metadata_archive(&[(b"mtime", time)], b'0');
            let (_dir, staged) = raw(&bytes);
            let metadata = &staged.changeset().entries[0].metadata;
            assert_eq!(
                (metadata.mtime_seconds, metadata.mtime_nanos),
                (seconds, nanos)
            );
        }
        for time in [
            b"-1".as_slice(),
            b"15032385536",
            b"18446744073709551616",
            b"1.",
            b"1..0",
            b"1.123456789x",
        ] {
            let bytes = metadata_archive(&[(b"mtime", time)], b'0');
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        for (major, minor, character, accepted) in [
            (4095_u32, 1048575_u32, false, true),
            (1, 255, true, true),
            (1, 256, true, true),
            (0, 0, false, true),
            (0, 0, true, false),
        ] {
            // Independent Linux new_encode_dev/new_decode_dev equations.
            let encoded = (minor & 255) | (major << 8) | ((minor & !255) << 12);
            assert_eq!((encoded >> 8) & 4095, major);
            assert_eq!((encoded & 255) | ((encoded >> 12) & !255), minor);
            for pax_numbers in [false, true] {
                let major_text = major.to_string();
                let minor_text = minor.to_string();
                let mut bytes = if pax_numbers {
                    pax(
                        &[
                            (b"SCHILY.devmajor", major_text.as_bytes()),
                            (b"SCHILY.devminor", minor_text.as_bytes()),
                        ],
                        false,
                    )
                } else {
                    vec![]
                };
                let mut item = member(b"device", if character { b'3' } else { b'4' }, b"");
                if !pax_numbers {
                    item[329..337].copy_from_slice(format!("{major:07o}\0").as_bytes());
                    item[337..345].copy_from_slice(format!("{minor:07o}\0").as_bytes());
                    checksum(&mut item);
                }
                bytes.extend(item);
                let bytes = finish(bytes);
                assert_eq!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                        .1
                        .is_ok(),
                    accepted
                );
            }
        }
        let bytes = metadata_archive(&[(b"SCHILY.devmajor", b"1")], b'0');
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
    }

    #[test]
    fn socket_scope_resets_and_conflicting_wire_forms_fail_closed() {
        for flag in [0, b'0'] {
            let mut bytes = pax(&[(b"SCHILY.filetype", b"socket")], false);
            bytes.extend(member(b"socket", flag, b""));
            bytes.extend(member(b"ordinary", b'0', b""));
            let (_dir, staged) = raw(&finish(bytes));
            assert!(matches!(
                staged.changeset().entries[0].kind,
                EntryKind::Socket
            ));
            assert!(matches!(
                staged.changeset().entries[1].kind,
                EntryKind::Regular(_)
            ));
        }
        for flag in [b'1', b'2', b'3', b'4', b'5', b'6'] {
            let bytes = metadata_archive(&[(b"SCHILY.filetype", b"socket")], flag);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        let mut global = pax(&[(b"SCHILY.filetype", b"socket")], true);
        global.extend(member(b"a", b'0', b""));
        let bytes = finish(global);
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
        let bytes = metadata_archive(
            &[
                (b"SCHILY.filetype", b"socket"),
                (b"GNU.sparse.size", b"0"),
                (b"GNU.sparse.numblocks", b"0"),
                (b"GNU.sparse.map", b""),
            ],
            b'0',
        );
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
        let mut bytes = pax(&[(b"SCHILY.filetype", b"socket")], false);
        let mut item = member(b"a", b'0', b"");
        item[157..162].copy_from_slice(b"lower");
        checksum(&mut item);
        bytes.extend(item);
        let bytes = finish(bytes);
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
        let bytes = metadata_archive(&[(b"SCHILY.filetype", b"unknown")], b'0');
        assert!(matches!(
            attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
            Err(crate::changeset::ChangesetError::Unsupported(_))
        ));
    }

    #[test]
    fn local_pax_deletions_do_not_revive_fixed_or_global_scalars() {
        for payload in [b"8 path=\n".as_slice(), b"8 size=\n"] {
            let mut bytes = member(b"PAX", b'x', payload);
            bytes.extend(member(b"safe-header", b'0', b"X"));
            let bytes = finish(bytes);
            let error = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .unwrap_err();
            assert!(
                error.to_string().contains("deleted required PAX field"),
                "{error}"
            );
        }
        for key in [b"path".as_slice(), b"uid", b"gid", b"mtime", b"size"] {
            let bytes = metadata_archive(&[(key, b"")], b'0');
            let error = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .unwrap_err();
            assert!(
                error.to_string().contains("deleted required PAX field"),
                "{key:?}: {error}"
            );
        }
        for flag in [b'1', b'2'] {
            let bytes = metadata_archive(&[(b"linkpath", b"")], flag);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .unwrap_err()
                .to_string()
                .contains("deleted required PAX field linkpath"));
        }
        let mut bytes = pax(&[(b"path", b"global")], true);
        bytes.extend(member(b"PAX", b'x', b"8 path=\n"));
        bytes.extend(member(b"header", b'0', b""));
        let bytes = finish(bytes);
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .unwrap_err()
            .to_string()
            .contains("deleted required PAX field path"));
        for separate_headers in [false, true] {
            let mut bytes = pax(&[(b"uid", b"7")], true);
            if separate_headers {
                bytes.extend(pax(&[(b"path", b""), (b"uid", b"")], false));
                bytes.extend(pax(&[(b"path", b"effective"), (b"uid", b"8")], false));
            } else {
                bytes.extend(pax(
                    &[
                        (b"path", b""),
                        (b"path", b"effective"),
                        (b"uid", b""),
                        (b"uid", b"8"),
                    ],
                    false,
                ));
            }
            bytes.extend(member(b"header", b'0', b""));
            bytes.extend(member(b"next", b'0', b""));
            let (_dir, staged) = raw(&finish(bytes));
            let entries = &staged.changeset().entries;
            assert_eq!(entries[0].path, b"effective");
            assert_eq!(entries[0].metadata.uid, 8);
            assert_eq!(entries[1].metadata.uid, 7);
        }
        let mut bytes = pax(&[(b"uid", b"7")], true);
        bytes.extend(member(b"a", b'0', b""));
        bytes.extend(pax(&[(b"uid", b"")], true));
        bytes.extend(member(b"b", b'0', b""));
        let (_dir, staged) = raw(&finish(bytes));
        assert_eq!(staged.changeset().entries[0].metadata.uid, 7);
        assert_eq!(staged.changeset().entries[1].metadata.uid, 0);
        let mut bytes = pax(&[(b"path", b"global")], true);
        bytes.extend(member(b"a", b'0', b""));
        bytes.extend(pax(&[(b"path", b"")], true));
        bytes.extend(member(b"b", b'0', b""));
        let (_dir, staged) = raw(&finish(bytes));
        assert_eq!(staged.changeset().entries[0].path, b"global");
        assert_eq!(staged.changeset().entries[1].path, b"b");
    }

    #[test]
    fn sparse_limit_future_version_and_effective_eof_have_isolated_typed_causes() {
        let mut bytes = pax(
            &[
                (b"GNU.sparse.size", b"4"),
                (b"GNU.sparse.numblocks", b"2"),
                (b"GNU.sparse.map", b"0,1,2,1"),
            ],
            false,
        );
        bytes.extend(member(b"sparse", b'0', b"XY"));
        let bytes = finish(bytes);
        let limits = ChangesetLimits {
            max_sparse_ranges: 1,
            ..ChangesetLimits::default()
        };
        assert!(matches!(
            attempt(&bytes, &bytes, RAW, &limits).1,
            Err(crate::changeset::ChangesetError::Limit {
                resource: "sparse ranges",
                actual: 2,
                maximum: 1
            })
        ));
        let bytes = metadata_archive(
            &[
                (b"GNU.sparse.major", b"9"),
                (b"GNU.sparse.minor", b"0"),
                (b"GNU.sparse.realsize", b"0"),
            ],
            b'0',
        );
        assert!(
            matches!(attempt(&bytes,&bytes,RAW,&ChangesetLimits::default()).1,Err(crate::changeset::ChangesetError::Unsupported(message)) if message=="sparse wire version")
        );
        for (effective, accepted) in [(b"20".as_slice(), true), (b"10", false)] {
            let mut bytes = pax(
                &[
                    (b"GNU.sparse.size", b"1"),
                    (b"GNU.sparse.numblocks", b"1"),
                    (b"GNU.sparse.map", b"11,1"),
                    (b"GNU.sparse.size", effective),
                ],
                false,
            );
            bytes.extend(member(b"sparse", b'0', b"X"));
            let bytes = finish(bytes);
            let (_dir, result) = attempt(
                &bytes,
                &bytes,
                RAW,
                &ChangesetLimits {
                    max_file_bytes: 20,
                    ..ChangesetLimits::default()
                },
            );
            if accepted {
                let staged = result.unwrap();
                assert_eq!(std::fs::read(staged.pack_path()).unwrap()[11], b'X');
            } else {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("out-of-file sparse range"));
            }
        }
    }

    fn old_sparse_member(ranges: &[SparseRange], logical: u64, data: &[u8]) -> Vec<u8> {
        let mut item = member(b"sparse", b'S', data);
        item[257..265].copy_from_slice(b"ustar  \0");
        item[483..495].copy_from_slice(format!("{logical:011o}\0").as_bytes());
        for (index, range) in ranges.iter().take(4).enumerate() {
            let start = 386 + index * 24;
            item[start..start + 12].copy_from_slice(format!("{:011o}\0", range.offset).as_bytes());
            item[start + 12..start + 24]
                .copy_from_slice(format!("{:011o}\0", range.length).as_bytes());
        }
        item[482] = u8::from(ranges.len() > 4);
        checksum(&mut item);
        let mut bytes = item[..512].to_vec();
        let extras = ranges.get(4..).unwrap_or_default().chunks(21);
        let count = extras.len();
        for (block_index, chunk) in extras.enumerate() {
            let mut block = [0_u8; 512];
            for (index, range) in chunk.iter().enumerate() {
                let start = index * 24;
                block[start..start + 12]
                    .copy_from_slice(format!("{:011o}\0", range.offset).as_bytes());
                block[start + 12..start + 24]
                    .copy_from_slice(format!("{:011o}\0", range.length).as_bytes());
            }
            block[504] = u8::from(block_index + 1 < count);
            bytes.extend(block);
        }
        bytes.extend_from_slice(&item[512..]);
        bytes
    }

    fn sparse_wire(version: u8, ranges: &[SparseRange], logical: u64, data: &[u8]) -> Vec<u8> {
        if version == 0 {
            return old_sparse_member(ranges, logical, data);
        }
        let mut records = Vec::<(Vec<u8>, Vec<u8>)>::new();
        let mut body = data.to_vec();
        if version == 3 {
            records.extend([
                (b"GNU.sparse.major".to_vec(), b"1".to_vec()),
                (b"GNU.sparse.minor".to_vec(), b"0".to_vec()),
                (
                    b"GNU.sparse.realsize".to_vec(),
                    logical.to_string().into_bytes(),
                ),
            ]);
            let mut map = format!("{}\n", ranges.len()).into_bytes();
            for range in ranges {
                map.extend(format!("{}\n{}\n", range.offset, range.length).into_bytes());
            }
            map.resize(map.len().div_ceil(512) * 512, 0);
            map.extend_from_slice(data);
            body = map;
        } else {
            records.extend([
                (
                    b"GNU.sparse.size".to_vec(),
                    logical.to_string().into_bytes(),
                ),
                (
                    b"GNU.sparse.numblocks".to_vec(),
                    ranges.len().to_string().into_bytes(),
                ),
            ]);
            if version == 1 {
                for range in ranges {
                    records.push((
                        b"GNU.sparse.offset".to_vec(),
                        range.offset.to_string().into_bytes(),
                    ));
                    records.push((
                        b"GNU.sparse.numbytes".to_vec(),
                        range.length.to_string().into_bytes(),
                    ));
                }
            } else {
                let map = ranges
                    .iter()
                    .map(|r| format!("{},{}", r.offset, r.length))
                    .collect::<Vec<_>>()
                    .join(",");
                records.push((b"GNU.sparse.map".to_vec(), map.into_bytes()));
            }
        }
        let refs = records
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect::<Vec<_>>();
        let mut bytes = pax(&refs, false);
        bytes.extend(member(b"sparse", b'0', &body));
        bytes
    }

    #[test]
    fn all_sparse_forms_preserve_holes_zero_bodies_and_cross_block_data() {
        let cases = [
            (
                9000,
                vec![
                    SparseRange {
                        offset: 1,
                        length: 3,
                    },
                    SparseRange {
                        offset: 4094,
                        length: 4,
                    },
                    SparseRange {
                        offset: 8198,
                        length: 2,
                    },
                    SparseRange {
                        offset: 9000,
                        length: 0,
                    },
                ],
                b"abcdefghi".as_slice(),
            ),
            (
                9000,
                vec![SparseRange {
                    offset: 9000,
                    length: 0,
                }],
                b"".as_slice(),
            ),
            (
                0,
                vec![SparseRange {
                    offset: 0,
                    length: 0,
                }],
                b"".as_slice(),
            ),
        ];
        for version in 0..4 {
            for (logical, ranges, data) in &cases {
                let mut bytes = member(b"before", b'0', b"A");
                bytes.extend(member(b"empty", b'0', b""));
                bytes.extend(sparse_wire(version, ranges, *logical, data));
                bytes.extend(member(b"directory", b'5', b""));
                bytes.extend(member(b".wh.lower", b'0', b""));
                let mut link = member(b"link", b'1', b"");
                link[157..162].copy_from_slice(b"lower");
                checksum(&mut link);
                bytes.extend(link);
                bytes.extend(member(b"after", b'0', b"BC"));
                let (_dir, staged) = raw(&finish(bytes));
                let after = if *logical == 0 { 4096 } else { 16384 };
                let mut expected = vec![0; after + 4096];
                expected[0] = b'A';
                expected[after..after + 2].copy_from_slice(b"BC");
                if !data.is_empty() {
                    expected[4097..4100].copy_from_slice(b"abc");
                    expected[8190..8194].copy_from_slice(b"defg");
                    expected[12294..12296].copy_from_slice(b"hi");
                }
                assert_eq!(
                    std::fs::read(staged.pack_path()).unwrap(),
                    expected,
                    "version{version}, logical{logical}"
                );
            }
        }
    }

    #[test]
    fn old_gnu_crosses_two_continuations_and_rejects_each_corrupt_envelope() {
        let mut ranges = (0..26)
            .map(|index| SparseRange {
                offset: index * 400,
                length: 1,
            })
            .collect::<Vec<_>>();
        ranges.push(SparseRange {
            offset: 11000,
            length: 0,
        });
        let data = (b'A'..=b'Z').collect::<Vec<_>>();
        let wire = old_sparse_member(&ranges, 11000, &data);
        let (_dir, staged) = raw(&finish(wire.clone()));
        let mut expected = vec![0; 12288];
        for (index, value) in data.iter().enumerate() {
            expected[index * 400] = *value;
        }
        assert_eq!(std::fs::read(staged.pack_path()).unwrap(), expected);
        let mut bad_flag = wire.clone();
        bad_flag[482] = 2;
        checksum(&mut bad_flag);
        let mut bad_extra_flag = wire.clone();
        bad_extra_flag[512 + 504] = 2;
        let mut bad_padding = wire.clone();
        bad_padding[512 + 505] = 1;
        let mut unused = wire.clone();
        unused[410..434].fill(0);
        checksum(&mut unused);
        for bytes in [
            finish(bad_flag),
            finish(bad_extra_flag),
            finish(bad_padding),
            finish(unused),
            wire[..1124].to_vec(),
        ] {
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    #[test]
    fn effective_size_crosses_tar_blocks_without_changing_control_sizes() {
        let body = vec![b'X'; 513];
        let mut bytes = pax(&[(b"size", b"513"), (b"path", b"first")], false);
        bytes.extend(member(b"L", b'L', b"ignored-long-name\0"));
        let start = bytes.len();
        let mut first = member(b"header", b'0', &body);
        first[124..136].copy_from_slice(b"00000000000\0");
        checksum(&mut first);
        bytes.extend(first);
        bytes.extend(pax(
            &[(b"size", b"0"), (b"path", b"hard"), (b"linkpath", b"lower")],
            false,
        ));
        bytes.extend(member(b"K", b'K', b"ignored-long-target\0"));
        bytes.extend(member(b"L", b'L', b"ignored-destination\0"));
        bytes.extend(member(b"header", b'1', b""));
        bytes.extend(member(b"second", b'0', b"BC"));
        let full = finish(bytes);
        let (_dir, staged) = raw(&full);
        assert_eq!(
            staged
                .changeset()
                .entries
                .iter()
                .map(|e| e.path.as_slice())
                .collect::<Vec<_>>(),
            vec![b"first".as_slice(), b"hard", b"second"]
        );
        let mut expected = vec![0; 8192];
        expected[..513].fill(b'X');
        expected[4096..4098].copy_from_slice(b"BC");
        assert_eq!(std::fs::read(staged.pack_path()).unwrap(), expected);
        for removed in [start + 512 + 512, start + 512 + 1023] {
            let mut broken = full.clone();
            broken.remove(removed);
            assert!(attempt(&broken, &broken, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    #[test]
    fn pax_one_multiblock_map_has_discriminating_padding_counts_and_body_lengths() {
        let ranges = (0..100)
            .map(|index| SparseRange {
                offset: index * 2,
                length: 1,
            })
            .chain([SparseRange {
                offset: 230,
                length: 0,
            }])
            .collect::<Vec<_>>();
        let mut map = format!("{}\n", ranges.len()).into_bytes();
        for r in &ranges {
            map.extend(format!("{}\n{}\n", r.offset, r.length).into_bytes());
        }
        assert!(map.len() > 512);
        let raw_length = map.len();
        map.resize(map.len().div_ceil(512) * 512, 0);
        let data = (0..100_u8).collect::<Vec<_>>();
        let build = |map: &[u8], data: &[u8], size: Option<u64>| {
            let mut bytes = pax(
                &[
                    (b"GNU.sparse.major", b"1"),
                    (b"GNU.sparse.minor", b"0"),
                    (b"GNU.sparse.realsize", b"230"),
                ],
                false,
            );
            let mut body = map.to_vec();
            body.extend_from_slice(data);
            let mut item = member(b"sparse", b'0', &body);
            if let Some(size) = size {
                item[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
                checksum(&mut item);
            }
            bytes.extend(item);
            bytes.extend(member(b"next", b'0', b"Z"));
            finish(bytes)
        };
        let bytes = build(&map, &data, None);
        let (_dir, staged) = raw(&bytes);
        let pack = std::fs::read(staged.pack_path()).unwrap();
        let mut expected = vec![0; 8192];
        for (index, value) in data.iter().enumerate() {
            expected[index * 2] = *value;
        }
        expected[4096] = b'Z';
        assert_eq!(pack, expected);
        let mut padding = map.clone();
        padding[raw_length] = 1;
        let mut missing_newline = map.clone();
        missing_newline[raw_length - 1] = 0;
        let mut count = map.clone();
        count[..3].copy_from_slice(b"102");
        let mut overlap = map.clone();
        overlap[8] = b'0';
        let mut eof = map.clone();
        let at = eof.windows(7).position(|w| w == b"\n100\n1\n").unwrap();
        eof[at + 1..at + 4].copy_from_slice(b"999");
        for bytes in [
            build(&padding, &data, None),
            build(&missing_newline, &data, None),
            build(&count, &data, None),
            build(&overlap, &data, None),
            build(&eof, &data, None),
            build(&map, &data, Some(512)),
            build(&map, &data[..99], None),
            build(&map, &[data.as_slice(), b"X"].concat(), None),
        ] {
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }

    #[test]
    fn zstd_small_known_size_shortcut_and_frame_reset_obey_actual_memory_contract() {
        let decoded = vec![0; 1024];
        for window in [0x68, 0x69] {
            let mut frame = vec![
                0x28, 0xb5, 0x2f, 0xfd, 0x40, window, 0x00, 0x03, 0x01, 0x20, 0x00,
            ];
            frame.extend_from_slice(&decoded);
            assert!(attempt(&frame, &decoded, ZSTD, &ChangesetLimits::default())
                .1
                .is_ok());
        }
        let mut oversized = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x69, 0x01, 0x20, 0x00];
        oversized.extend_from_slice(&decoded);
        let mut combined = zstd::stream::encode_all(decoded.as_slice(), 1).unwrap();
        combined.extend_from_slice(&0x184d2a50_u32.to_le_bytes());
        combined.extend_from_slice(&3_u32.to_le_bytes());
        combined.extend_from_slice(b"xyz");
        combined.extend(oversized);
        let expected = [decoded.as_slice(), decoded.as_slice()].concat();
        assert!(
            attempt(&combined, &expected, ZSTD, &ChangesetLimits::default())
                .1
                .is_err()
        );
        let prefix = zstd::stream::encode_all(decoded.as_slice(), 1).unwrap();
        for suffix in [
            vec![0x50, 0x2a, 0x4d],
            vec![0x50, 0x2a, 0x4d, 0x18, 5, 0, 0, 0, b'x', b'y'],
        ] {
            let mut broken = prefix.clone();
            broken.extend(suffix);
            assert!(
                attempt(&broken, &decoded, ZSTD, &ChangesetLimits::default())
                    .1
                    .is_err()
            );
        }
    }

    #[test]
    fn cancelled_waiter_keeps_worker_staging_lock_through_success_and_failure() {
        use nix::fcntl::{Flock, FlockArg};
        use std::sync::mpsc;
        use std::time::Duration;
        struct NotifyOnDrop(Option<tokio::sync::oneshot::Sender<bool>>, bool);
        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(self.1);
                }
            }
        }
        for success in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source");
            let bytes = finish(member(b"a", b'0', b"X"));
            std::fs::write(&source, &bytes).unwrap();
            let input = LayerInput {
                blob_digest: ContentDigest::of_bytes(&bytes),
                media_type: RAW.into(),
                size_bytes: bytes.len() as u64,
                diff_id: if success {
                    ContentDigest::of_bytes(&bytes)
                } else {
                    ContentDigest::of_bytes(b"wrong")
                },
            };
            let root = dir.path().to_path_buf();
            let root_worker = root.clone();
            let op = operation();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let waiter = tokio::spawn(async move {
                    tokio::task::spawn_blocking(move || {
                        let staging = crate::store::StagingDir::create(&root_worker, &op).unwrap();
                        started_tx.send(staging.path().to_path_buf()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        let file = std::fs::File::open(source).unwrap();
                        let result = crate::changeset::ingest::ingest_staged(
                            file,
                            &input,
                            staging,
                            &ChangesetLimits::default(),
                        );
                        let completed = result.is_ok();
                        // Tuple fields drop left-to-right: notify only after
                        // the unclaimed result has released its real lease.
                        (result, NotifyOnDrop(Some(done_tx), completed))
                    })
                    .await
                });
                // Yield this current-thread runtime so the waiter can launch
                // its blocking worker before awaiting the worker's handshake.
                let staged_path = started_rx.await.unwrap();
                waiter.abort();
                assert!(matches!(waiter.await,Err(error) if error.is_cancelled()));
                assert!(staged_path.exists());
                let lease =
                    root.join("locks/publication/stage-00000000-0000-4000-8000-000000000001.lock");
                let contender = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&lease)
                    .unwrap();
                assert!(Flock::lock(contender, FlockArg::LockExclusiveNonblock).is_err());
                release_tx.send(()).unwrap();
                assert_eq!(done_rx.await.unwrap(), success);
                assert!(!staged_path.exists());
                let contender = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(lease)
                    .unwrap();
                let _exclusive = Flock::lock(contender, FlockArg::LockExclusiveNonblock).unwrap();
            });
        }
    }

    #[test]
    fn pax_ids_fixed_times_and_ignored_owner_names_do_not_default_or_wrap() {
        for key in [b"uid".as_slice(), b"gid"] {
            for (value, accepted) in [
                (b"0".as_slice(), true),
                (b"4294967294", true),
                (b"4294967295", false),
                (b"4294967296", false),
                (b"-1", false),
                (b"18446744073709551616", false),
            ] {
                let bytes = metadata_archive(&[(key, value)], b'0');
                let (_dir, result) = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default());
                if accepted {
                    let staged = result.unwrap();
                    let metadata = &staged.changeset().entries[0].metadata;
                    let actual = if key == b"uid" {
                        metadata.uid
                    } else {
                        metadata.gid
                    };
                    assert_eq!(actual.to_string().as_bytes(), value);
                } else {
                    assert!(result.is_err());
                }
            }
        }
        let mut bytes = pax(
            &[
                (b"uid", b"7"),
                (b"gid", b"8"),
                (b"uname", b"root"),
                (b"gname", b"nobody"),
            ],
            false,
        );
        let mut item = member(b"a", b'0', b"");
        item[108..124].fill(b'x');
        item[265..269].copy_from_slice(b"root");
        item[297..303].copy_from_slice(b"nobody");
        checksum(&mut item);
        bytes.extend(item);
        let (_dir, staged) = raw(&finish(bytes));
        assert_eq!(
            (
                staged.changeset().entries[0].metadata.uid,
                staged.changeset().entries[0].metadata.gid
            ),
            (7, 8)
        );
        for seconds in [0_u64, 15032385535] {
            let mut item = member(b"a", b'0', b"");
            item[136..148].copy_from_slice(format!("{seconds:012o}").as_bytes());
            checksum(&mut item);
            let (_dir, staged) = raw(&finish(item));
            assert_eq!(
                staged.changeset().entries[0].metadata.mtime_seconds,
                seconds
            );
        }
        let mut negative = member(b"a", b'0', b"");
        negative[136..148].fill(255);
        checksum(&mut negative);
        let mut overflow = member(b"a", b'0', b"");
        overflow[136..148].fill(0);
        overflow[136] = 0x80;
        overflow[139] = 1;
        checksum(&mut overflow);
        for item in [negative, overflow] {
            let bytes = finish(item);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
        let bytes = metadata_archive(&[(b"mtime", b"+1")], b'0');
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .is_err());
        for global in [false, true] {
            for key in [
                b"SCHILY.fflags".as_slice(),
                b"SCHILY.acl.ace",
                b"SCHILY.xattr.security.evm",
                b"SCHILY.xattr.system.nfs4_acl",
            ] {
                let mut bytes = pax(&[(key, b"unsupported")], global);
                bytes.extend(member(b"a", b'0', b""));
                let bytes = finish(bytes);
                assert!(matches!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default()).1,
                    Err(crate::changeset::ChangesetError::Unsupported(_))
                ));
            }
        }
        let bytes = metadata_archive(&[(b"SCHILY.xattr.user.raw", b"\0\xff\n=")], b'0');
        let (_dir, staged) = raw(&bytes);
        assert_eq!(
            staged.changeset().entries[0].metadata.xattrs[0].value,
            b"\0\xff\n="
        );
    }

    #[test]
    fn all_path_envelopes_share_byte_normalization_without_host_traversal() {
        for path in [b"a/../b".as_slice(), b"/a", b"a\0b", b"raw-\xff"] {
            let accepted = path == b"raw-\xff";
            let mut variants = vec![member(path, b'0', b"")];
            let mut pax_path = pax(&[(b"path", path)], false);
            pax_path.extend(member(b"header", b'0', b""));
            variants.push(pax_path);
            let mut long = member(b"L", b'L', &[path, b"\0"].concat());
            long.extend(member(b"header", b'0', b""));
            variants.push(long);
            for variant in variants {
                let bytes = finish(variant);
                assert_eq!(
                    attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                        .1
                        .is_ok(),
                    accepted,
                    "{path:?}"
                );
            }
        }
        for (prefix, accepted) in [
            (b"a/..".as_slice(), false),
            (b"/", false),
            (b"raw-\xff", true),
        ] {
            let mut item = member(b"b", b'0', b"");
            item[345..345 + prefix.len()].copy_from_slice(prefix);
            checksum(&mut item);
            let bytes = finish(item);
            let (_dir, result) = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default());
            assert_eq!(result.is_ok(), accepted);
            if accepted {
                assert_eq!(result.unwrap().changeset().entries[0].path, b"raw-\xff/b");
            }
        }
        let target = b"/../guest/\xff";
        let mut bytes = member(b"K", b'K', &[target.as_slice(), b"\0"].concat());
        bytes.extend(member(b"link", b'2', b""));
        let (_dir, staged) = raw(&finish(bytes));
        assert!(
            matches!(&staged.changeset().entries[0].kind,EntryKind::Symlink{target:value} if value==target)
        );
        let mut bytes = pax(&[(b"path", b"a//./b")], false);
        bytes.extend(member(b"first", b'0', b""));
        bytes.extend(member(b"a/b", b'0', b""));
        let bytes = finish(bytes);
        assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
            .1
            .unwrap_err()
            .to_string()
            .contains("duplicate normalized tar path"));
    }

    #[test]
    fn xattr_alias_overrides_and_global_deletions_preserve_every_effective_spelling() {
        let raw_key = b"SCHILY.xattr.user.a".as_slice();
        let encoded_key = b"LIBARCHIVE.xattr.user.a".as_slice();
        let conflict = metadata_archive(
            &[
                (raw_key, b"old"),
                (encoded_key, b"b2xk"),
                (encoded_key, b"bmV3"),
            ],
            b'0',
        );
        assert!(
            attempt(&conflict, &conflict, RAW, &ChangesetLimits::default())
                .1
                .unwrap_err()
                .to_string()
                .contains("conflicting xattr representations")
        );
        let repaired = metadata_archive(
            &[
                (raw_key, b"old"),
                (encoded_key, b"b2xk"),
                (raw_key, b"new"),
                (encoded_key, b"bmV3"),
            ],
            b'0',
        );
        let (_dir, staged) = raw(&repaired);
        assert_eq!(
            staged.changeset().entries[0].metadata.xattrs[0].value,
            b"new"
        );
        let mut bytes = pax(&[(raw_key, b"old"), (encoded_key, b"b2xk")], true);
        bytes.extend(pax(&[(encoded_key, b"")], true));
        bytes.extend(member(b"a", b'0', b""));
        bytes.extend(pax(&[(encoded_key, b"")], true));
        bytes.extend(member(b"b", b'0', b""));
        bytes.extend(pax(&[(raw_key, b"")], true));
        bytes.extend(member(b"c", b'0', b""));
        let (_dir, staged) = raw(&finish(bytes));
        let entries = &staged.changeset().entries;
        assert_eq!(entries[0].metadata.xattrs[0].value, b"old");
        assert_eq!(entries[1].metadata.xattrs[0].value, b"old");
        assert!(entries[2].metadata.xattrs.is_empty());
        for cover_all in [false, true] {
            let mut bytes = pax(&[(raw_key, b"old"), (encoded_key, b"b2xk")], true);
            if cover_all {
                bytes.extend(pax(&[(raw_key, b"new"), (encoded_key, b"bmV3")], false));
            } else {
                bytes.extend(pax(&[(raw_key, b"new")], false));
            }
            bytes.extend(member(b"a", b'0', b""));
            bytes.extend(member(b"b", b'0', b""));
            let bytes = finish(bytes);
            let (_dir, result) = attempt(&bytes, &bytes, RAW, &ChangesetLimits::default());
            if cover_all {
                let staged = result.unwrap();
                assert_eq!(
                    staged.changeset().entries[0].metadata.xattrs[0].value,
                    b"new"
                );
                assert_eq!(
                    staged.changeset().entries[1].metadata.xattrs[0].value,
                    b"old"
                );
            } else {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("conflicting xattr representations"));
            }
        }
        for key in [
            b"LIBARCHIVE.xattr.user.%00".as_slice(),
            b"SCHILY.xattr.security.evm",
        ] {
            let mut bytes = pax(&[(key, b"")], true);
            bytes.extend(member(b"a", b'0', b""));
            let bytes = finish(bytes);
            assert!(attempt(&bytes, &bytes, RAW, &ChangesetLimits::default())
                .1
                .is_err());
        }
    }
}
