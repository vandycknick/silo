//! Digest-addressed OCI blob staging: an operation-private export directory
//! or the shared, operation-pinned transport cache. A file name is only a
//! lookup key: every write and every reuse authenticates size and SHA-256, so
//! an interrupted download or a tampered staging file is never a cache hit.
//!
//! Probes never unlink. A requester's descriptor is not authority over bytes
//! another acquisition may hold pinned: a valid entry whose size contradicts
//! the descriptor rejects the descriptor, and an entry that does not hash to
//! its own name is only ever replaced by an atomic rename of verified bytes.
//! In the shared cache every replacement for one digest runs under that
//! digest's pool publication lock.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;

use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;
use oci::changeset::model::ContentDigest;
use oci::vm_artifact::wire::{PayloadMediaType, PayloadRef};
use sha2::{Digest, Sha256};

use crate::paths::OwnedDirectory;
use crate::storage::identity::ObjectDigest;
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
use crate::LibVmError;

const COPY_BUFFER_BYTES: usize = 1 << 20;

/// The largest descriptor size any payload media type admits. A staged file
/// longer than this cannot be any payload's authentic bytes.
const MAX_PAYLOAD_BYTES: u64 = max_payload_bytes();

const fn max_payload_bytes() -> u64 {
    let media = [
        PayloadMediaType::Record,
        PayloadMediaType::RawChunk,
        PayloadMediaType::ZstdChunk,
        PayloadMediaType::Execution,
        PayloadMediaType::DeviceState,
    ];
    let mut maximum = 0;
    let mut index = 0;
    while index < media.len() {
        let size = media[index].maximum_size();
        if size > maximum {
            maximum = size;
        }
        index += 1;
    }
    maximum
}

pub(crate) fn invalid(boundary: &'static str, message: impl std::fmt::Display) -> LibVmError {
    LibVmError::ArtifactInvalid {
        boundary,
        message: message.to_string(),
    }
}

/// Handle to one digest-addressed blob directory owned by Silo.
pub(crate) struct StagedBlobs {
    directory: OwnedDirectory,
    /// Present for the shared transport cache: the pool whose publication
    /// locks serialize replacement of one digest across acquisitions.
    publication: Option<Arc<StoragePool>>,
}

/// What a digest's staged file holds, judged against its own name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cached {
    Absent,
    /// Exactly the requested descriptor's bytes.
    Valid,
    /// Bytes that do not hash to the name: interrupted or tampered, never
    /// authentic content of any descriptor.
    Invalid,
}

impl StagedBlobs {
    /// Create or rejoin `name` below an owned parent directory. Only the one
    /// operation that owns the parent writes it, so no publication lock.
    pub(crate) fn join(parent: &OwnedDirectory, name: &str) -> Result<Self, LibVmError> {
        Ok(Self {
            directory: parent.ensure_dir(name)?,
            publication: None,
        })
    }

    /// The shared transport cache of the pool at `images`. Concurrent
    /// acquisitions publish into it; each digest's replacement is serialized.
    pub(crate) fn transport_cache(images: &Path) -> Result<Self, LibVmError> {
        let pool = StoragePool::open(images)?;
        Ok(Self {
            directory: OwnedDirectory::open_root(&images.join("transport"))?
                .ensure_dir("sha256")?,
            publication: Some(Arc::new(pool)),
        })
    }

    /// Diagnostic location of this directory; never reopened by path.
    pub(crate) fn path(&self) -> &std::path::Path {
        self.directory.path()
    }

    /// An independent handle to the same directory for another worker.
    pub(crate) fn try_clone(&self) -> Result<Self, LibVmError> {
        Ok(Self {
            directory: self.directory.try_clone()?,
            publication: self.publication.clone(),
        })
    }

    /// Store exact verified bytes. A valid entry is kept as is; an invalid
    /// one is atomically replaced, never unlinked, so a concurrent reader
    /// keeps whichever authentic inode it opened.
    pub(crate) fn insert(&self, payload: &PayloadRef, bytes: &[u8]) -> Result<(), LibVmError> {
        payload.validate()?;
        if bytes.len() as u64 != payload.size || ContentDigest::of_bytes(bytes) != payload.digest {
            return Err(invalid(
                "payload",
                format!("{} does not match its descriptor", payload.digest),
            ));
        }
        let _publisher = self.serialize(&payload.digest)?;
        match self.probe(payload)? {
            Cached::Valid => Ok(()),
            Cached::Absent | Cached::Invalid => self
                .directory
                .write_file_atomic(&name(&payload.digest), bytes),
        }
    }

    /// True only when the staged file is complete and authentic. A wrong or
    /// partial file stays until `insert` replaces it; a valid file whose size
    /// contradicts `payload` rejects the descriptor and survives untouched.
    pub(crate) fn contains(&self, payload: &PayloadRef) -> Result<bool, LibVmError> {
        Ok(self.probe(payload)? == Cached::Valid)
    }

    /// Read-only classification. Staged names only ever change by atomic
    /// rename, so the opened inode is complete whichever one it is.
    fn probe(&self, payload: &PayloadRef) -> Result<Cached, LibVmError> {
        payload.validate()?;
        let Some(mut file) = self.directory.open_file(&name(&payload.digest))? else {
            return Ok(Cached::Absent);
        };
        // Authenticate against the name, not the requester's claimed size.
        let (digest, length) = hash_file(&mut file, MAX_PAYLOAD_BYTES)?;
        if length > MAX_PAYLOAD_BYTES || digest != payload.digest {
            return Ok(Cached::Invalid);
        }
        if length != payload.size {
            return Err(invalid(
                "payload",
                format!(
                    "{} descriptor size {} contradicts its authenticated {length} cached bytes",
                    payload.digest, payload.size
                ),
            ));
        }
        Ok(Cached::Valid)
    }

    /// The shared cache's per-digest publication lock, derived in its own
    /// key domain so it never aliases a recipe or capture publication key.
    fn serialize(&self, digest: &ContentDigest) -> Result<Option<StorageLock>, LibVmError> {
        let Some(pool) = &self.publication else {
            return Ok(None);
        };
        Ok(Some(pool.lock_publication(&publication_key(digest))?))
    }

    /// A rewound descriptor of exactly the descriptor's authenticated bytes.
    pub(crate) fn open_verified(&self, payload: &PayloadRef) -> Result<File, LibVmError> {
        payload.validate()?;
        let mut file = self
            .directory
            .open_file(&name(&payload.digest))?
            .ok_or_else(|| invalid("payload", format!("{} is not staged", payload.digest)))?;
        let (digest, length) = hash_file(&mut file, payload.size)?;
        if digest != payload.digest || length != payload.size {
            return Err(invalid(
                "payload",
                format!("staged {} does not match its descriptor", payload.digest),
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    /// Unverified descriptor for a caller that authenticates while decoding
    /// (chunk decoding hashes all encoded bytes before decompression).
    pub(crate) fn open(&self, digest: &ContentDigest) -> Result<File, LibVmError> {
        self.directory
            .open_file(&name(digest))?
            .ok_or_else(|| invalid("payload", format!("{digest} is not staged")))
    }

    /// Bounded authenticated read of a small payload (records, native state).
    pub(crate) fn read(&self, payload: &PayloadRef) -> Result<Vec<u8>, LibVmError> {
        payload.validate()?;
        let mut file = self.open(&payload.digest)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(payload.size as usize)
            .map_err(|error| invalid("payload", error))?;
        (&mut file)
            .take(payload.size.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != payload.size || ContentDigest::of_bytes(&bytes) != payload.digest {
            return Err(invalid(
                "payload",
                format!("staged {} does not match its descriptor", payload.digest),
            ));
        }
        Ok(bytes)
    }

    #[cfg(test)]
    pub(crate) fn directory(&self) -> &OwnedDirectory {
        &self.directory
    }
}

fn publication_key(digest: &ContentDigest) -> ObjectDigest {
    ObjectDigest::of_bytes(format!("silo:transport-cache:{digest}").as_bytes())
}

/// Create one new private read-write file in an owned directory. `nix` has
/// no OwnedDirectory helper for an exclusive read-write create.
pub(crate) fn create_private_file(
    directory: &OwnedDirectory,
    name: &str,
) -> Result<File, LibVmError> {
    let fd = openat(
        directory.fd().as_fd(),
        name,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|error| invalid("staging", format!("create {name}: {error}")))?;
    Ok(File::from(fd))
}

fn name(digest: &ContentDigest) -> String {
    let mut hex = String::with_capacity(64);
    for byte in digest.as_bytes() {
        use std::fmt::Write as _;
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Hash at most `limit + 1` bytes from the start, so an overlong file is
/// detected without reading an unbounded amount.
fn hash_file(file: &mut File, limit: u64) -> Result<(ContentDigest, u64), LibVmError> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; COPY_BUFFER_BYTES];
    let mut length = 0u64;
    let mut reader = file.take(limit.saturating_add(1));
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        length += read as u64;
    }
    Ok((ContentDigest::from_sha256(hash.finalize().into()), length))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    use oci::changeset::model::ContentDigest;
    use oci::vm_artifact::wire::{PayloadMediaType, PayloadRef};

    use crate::image::transport::blobs::{publication_key, StagedBlobs};
    use crate::paths::OwnedDirectory;
    use crate::storage::pool::StoragePool;
    use crate::LibVmError;

    fn payload(bytes: &[u8]) -> PayloadRef {
        PayloadRef {
            media_type: PayloadMediaType::RawChunk,
            digest: ContentDigest::of_bytes(bytes),
            size: bytes.len() as u64,
        }
    }

    fn staging() -> (tempfile::TempDir, OwnedDirectory) {
        let temp = tempfile::tempdir().unwrap();
        let root = OwnedDirectory::open_root(&temp.path().join("operation")).unwrap();
        (temp, root)
    }

    fn shared() -> (tempfile::TempDir, std::path::PathBuf, StagedBlobs) {
        let temp = tempfile::tempdir().unwrap();
        let images = temp.path().join("images");
        let cache = StagedBlobs::transport_cache(&images).unwrap();
        (temp, images, cache)
    }

    fn name(reference: &PayloadRef) -> String {
        reference.digest.to_string()[7..].to_owned()
    }

    fn inode(cache: &StagedBlobs, reference: &PayloadRef) -> u64 {
        cache
            .directory()
            .open_file(&name(reference))
            .unwrap()
            .unwrap()
            .metadata()
            .unwrap()
            .ino()
    }

    #[test]
    fn insert_rejects_wrong_bytes_and_reuses_exact_bytes() {
        let (_temp, root) = staging();
        let blobs = StagedBlobs::join(&root, "blobs").unwrap();
        let reference = payload(b"chunk bytes");
        assert!(blobs.insert(&reference, b"chunk bytez").is_err());
        assert!(!blobs.contains(&reference).unwrap());
        blobs.insert(&reference, b"chunk bytes").unwrap();
        blobs.insert(&reference, b"chunk bytes").unwrap();
        assert_eq!(blobs.read(&reference).unwrap(), b"chunk bytes");
        let mut longer = reference;
        longer.size += 1;
        assert!(blobs.read(&longer).is_err());
        assert!(blobs.open_verified(&longer).is_err());
        // A contradictory descriptor is rejected; the authentic entry stays.
        assert!(matches!(
            blobs.contains(&longer),
            Err(LibVmError::ArtifactInvalid {
                boundary: "payload",
                ..
            })
        ));
        assert_eq!(blobs.read(&reference).unwrap(), b"chunk bytes");
    }

    #[test]
    fn tampered_or_truncated_staging_is_never_a_cache_hit() {
        let (_temp, root) = staging();
        let blobs = StagedBlobs::join(&root, "blobs").unwrap();
        let reference = payload(b"0123456789");
        blobs.insert(&reference, b"0123456789").unwrap();
        let name = name(&reference);
        blobs.directory().write_file(&name, b"01234").unwrap();
        assert!(blobs.read(&reference).is_err());
        assert!(blobs.open_verified(&reference).is_err());
        assert!(!blobs.contains(&reference).unwrap());
        // Invalid bytes are never a hit but are only replaced, not unlinked.
        let provisional = inode(&blobs, &reference);
        blobs.insert(&reference, b"0123456789").unwrap();
        assert!(blobs.contains(&reference).unwrap());
        assert_ne!(inode(&blobs, &reference), provisional);
        assert_eq!(blobs.read(&reference).unwrap(), b"0123456789");
        // Rejoining the same operation directory reuses only authentic bytes.
        let rejoined = StagedBlobs::join(&root, "blobs").unwrap();
        assert!(rejoined.contains(&reference).unwrap());
    }

    /// Pull A holds a valid pinned blob; pull B names the same digest with a
    /// wrong size. B is refused without touching A's entry or open input.
    #[test]
    fn shared_cache_keeps_a_valid_entry_against_contradictory_descriptors() {
        let (_temp, _images, first) = shared();
        let bytes = b"authentic transport chunk".to_vec();
        let reference = payload(&bytes);
        first.insert(&reference, &bytes).unwrap();
        let held = first.open_verified(&reference).unwrap();
        let installed = inode(&first, &reference);
        let second = first.try_clone().unwrap();
        for size in [reference.size - 1, reference.size + 1, 1] {
            let mut wrong = reference;
            wrong.size = size;
            assert!(matches!(
                second.contains(&wrong),
                Err(LibVmError::ArtifactInvalid {
                    boundary: "payload",
                    ..
                })
            ));
            assert!(second.insert(&wrong, &bytes).is_err());
        }
        assert_eq!(inode(&first, &reference), installed);
        assert_eq!(held.metadata().unwrap().ino(), installed);
        assert!(first.contains(&reference).unwrap());
        assert_eq!(first.read(&reference).unwrap(), bytes);
    }

    /// A probes an interrupted slot, B installs the verified replacement,
    /// then A publishes its own fetch. A's probe never removes anything and
    /// its late insert keeps B's inode, which A's reader then shares.
    #[test]
    fn shared_cache_probe_and_replacement_never_remove_a_concurrent_valid_inode() {
        let (_temp, _images, first) = shared();
        let second = first.try_clone().unwrap();
        let bytes = vec![0x42; 4096];
        let reference = payload(&bytes);
        first
            .directory()
            .write_file(&name(&reference), &bytes[..100])
            .unwrap();
        let provisional = inode(&first, &reference);
        assert!(!first.contains(&reference).unwrap());
        assert_eq!(inode(&first, &reference), provisional);
        second.insert(&reference, &bytes).unwrap();
        let installed = inode(&second, &reference);
        assert_ne!(installed, provisional);
        let reader = first.open_verified(&reference).unwrap();
        first.insert(&reference, &bytes).unwrap();
        assert_eq!(inode(&first, &reference), installed);
        assert_eq!(reader.metadata().unwrap().ino(), installed);
        assert_eq!(first.read(&reference).unwrap(), bytes);
    }

    /// Shared-cache replacement runs under the pool's per-digest publication
    /// lock: a writer cannot publish while another holder serializes it.
    #[test]
    fn shared_cache_publication_waits_for_the_digest_lock() {
        let (_temp, images, cache) = shared();
        let bytes = b"serialized publication".to_vec();
        let reference = payload(&bytes);
        let pool = StoragePool::open(&images).unwrap();
        let held = pool
            .lock_publication(&publication_key(&reference.digest))
            .unwrap();
        let writer = cache.try_clone().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            sender.send(writer.insert(&reference, &bytes)).unwrap();
        });
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(300)),
            Err(RecvTimeoutError::Timeout)
        ));
        assert!(cache
            .directory()
            .open_file(&name(&reference))
            .unwrap()
            .is_none());
        drop(held);
        receiver.recv().unwrap().unwrap();
        thread.join().unwrap();
        assert!(cache.contains(&reference).unwrap());
        // Operation-private staging has one owner and takes no pool lock.
        let (_private_temp, root) = staging();
        let private = StagedBlobs::join(&root, "blobs").unwrap();
        let other = payload(b"private");
        let _held = pool
            .lock_publication(&publication_key(&other.digest))
            .unwrap();
        private.insert(&other, b"private").unwrap();
        assert!(private.contains(&other).unwrap());
    }
}
