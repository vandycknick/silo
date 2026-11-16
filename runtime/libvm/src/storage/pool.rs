use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{openat, AtFlags, FlockArg, OFlag};
use nix::sys::stat::{fchmod, fstat, fstatat, Mode, SFlag};
use nix::unistd::geteuid;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::paths::OwnedDirectory;
use crate::storage::identity::{parse_hex, ObjectDigest, StreamId};
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::limits::Resource;
use crate::storage::locks::{self, StorageLock};
use crate::storage::stream::{
    open_regular_source, AuthenticatedStream, StreamHasher, StreamMap, StreamStats,
};
use crate::storage::StorageError;

pub struct PublishedStream {
    pub id: StreamId,
    pub length: u64,
    pub path: PathBuf,
    pub map: StreamMap,
}

/// Payload-copy authority granted by admission, not clone capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealedStreamPublicationMode {
    CloneRequired,
    CopyAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicationLockPolicy {
    Wait,
    Defer,
}

/// Process-local binding of a sealed producer map to the held published inode.
/// A fresh reflink relies on owned clone provenance, not independent byte
/// authentication. Only a held producer capability can seed restore trust.
pub(crate) struct SealedStreamPublication {
    file: File,
    map: StreamMap,
    fingerprint: SourceFingerprint,
    scan_stats: StreamStats,
}

impl SealedStreamPublication {
    pub(crate) fn map(&self) -> &StreamMap {
        &self.map
    }

    pub(crate) fn scan_stats(&self) -> StreamStats {
        self.scan_stats
    }

    pub(crate) fn fingerprint(&self) -> SourceFingerprint {
        self.fingerprint
    }

    pub(crate) fn recheck(&self, pool: &StoragePool) -> Result<(), StorageError> {
        if SourceFingerprint::new(&self.file.metadata()?) != self.fingerprint
            || SourceFingerprint::new(&pool.open_stream(&self.map.id())?.metadata()?)
                != self.fingerprint
        {
            return Err(StorageError::ContentMismatch(
                pool.stream_path(&self.map.id()),
            ));
        }
        Ok(())
    }
}

pub struct PublishedObject {
    pub digest: ObjectDigest,
    pub length: u64,
    pub path: PathBuf,
    pub(crate) fingerprint: SourceFingerprint,
}

/// The operation's durable recovery directory is separate from disposable bytes.
pub struct OperationPaths {
    pub id: Uuid,
    pub temporary: PathBuf,
    pub durable: PathBuf,
    _lease: StorageLock,
}

impl OperationPaths {
    pub(crate) fn lease_identity(&self) -> Result<(u64, u64), StorageError> {
        Ok(self._lease.file_identity()?)
    }
}

pub struct StoragePool {
    root: OwnedDirectory,
    objects: OwnedDirectory,
    streams: OwnedDirectory,
    temporary: OwnedDirectory,
    lock_directory: OwnedDirectory,
    publication: OwnedDirectory,
    leases: OwnedDirectory,
    defer_publication: bool,
    publication_lock_policy: PublicationLockPolicy,
}
/// Bounded-memory, metadata-only discovery of retained stream files. It never
/// opens backing bytes before launch admission. Catalog reachability is checked
/// later, outside this enumeration.
pub struct StreamScan<'a> {
    directory: &'a OwnedDirectory,
    entries: nix::dir::OwningIter,
}

impl Iterator for StreamScan<'_> {
    type Item = Result<(StreamId, u64), StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.entries.next()? {
                Ok(entry) => entry,
                Err(error) => return Some(Err(error.into())),
            };
            let bytes = match parse_hex(entry.file_name().to_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let name = match entry.file_name().to_str() {
                Ok(name) => name,
                Err(_) => continue,
            };
            match immutable_length(self.directory, name) {
                Ok(Some(length)) => {
                    return Some(Ok((StreamId::from_sha256(bytes), length)));
                }
                Ok(None) => continue,
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

/// Metadata-only discovery of immutable objects, including fsmeta lower
/// backings. Recovery enumeration must not open them before FD admission.
pub struct ObjectScan<'a> {
    directory: &'a OwnedDirectory,
    entries: nix::dir::OwningIter,
}
impl Iterator for ObjectScan<'_> {
    type Item = Result<ObjectDigest, StorageError>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.entries.next()? {
                Ok(entry) => entry,
                Err(error) => return Some(Err(error.into())),
            };
            let bytes = match parse_hex(entry.file_name().to_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let name = match entry.file_name().to_str() {
                Ok(name) => name,
                Err(_) => continue,
            };
            match immutable_length(self.directory, name) {
                Ok(Some(_)) => return Some(Ok(ObjectDigest::from_sha256(bytes))),
                Ok(None) => continue,
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

pub(crate) struct LeaseScan {
    entries: nix::dir::OwningIter,
}
impl Iterator for LeaseScan {
    type Item = Result<Uuid, StorageError>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.entries.next()? {
                Ok(entry) => entry,
                Err(error) => return Some(Err(error.into())),
            };
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            let Some(id) = name.strip_suffix(".lease") else {
                continue;
            };
            let operation = match Uuid::parse_str(id) {
                Ok(operation) => operation,
                Err(_) => {
                    return Some(Err(StorageError::InvalidPath(
                        "invalid operation lease name".into(),
                    )))
                }
            };
            let mut canonical = [0; 36];
            if operation.hyphenated().encode_lower(&mut canonical) != id {
                return Some(Err(StorageError::InvalidPath(
                    "noncanonical operation lease name".into(),
                )));
            }
            return Some(Ok(operation));
        }
    }
}
/// Discovery keeps one exclusive nonblocking lease per returned candidate.
pub struct TemporaryScan<'a> {
    pool: &'a StoragePool,
    entries: nix::dir::OwningIter,
}

/// Owns its directory descriptors and lease, so it can cross async/blocking
/// task boundaries and outlive the pool during dependency preflight.
pub struct AbandonedTemporary {
    parent: OwnedDirectory,
    directory: OwnedDirectory,
    name: String,
    _lease: StorageLock,
}

impl AbandonedTemporary {
    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Call only after checking persisted external dependencies against path().
    /// Dropping a candidate without removal leaves its bytes for a later retry.
    pub fn remove(self) -> Result<(), StorageError> {
        owned(self.parent.remove_tree(&self.name))?;
        owned(self.parent.sync())
    }
}

impl Iterator for TemporaryScan<'_> {
    type Item = Result<AbandonedTemporary, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.entries.next()? {
                Ok(entry) => entry,
                Err(error) => return Some(Err(error.into())),
            };
            let name = match entry.file_name().to_str() {
                Ok(name) => name,
                Err(_) => continue,
            };
            let staging = name.strip_prefix("stage-");
            let operation_name = staging.unwrap_or(name);
            let operation = match Uuid::parse_str(operation_name) {
                Ok(operation) => operation,
                Err(_) => continue,
            };
            let mut canonical = [0; 36];
            if operation.hyphenated().encode_lower(&mut canonical) != operation_name {
                continue;
            }
            let stat = match fstatat(self.pool.temporary.fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(Errno::ENOENT) => continue,
                Err(error) => return Some(Err(error.into())),
            };
            if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR {
                continue;
            }
            let probe = if staging.is_some() {
                locks::acquire_existing(
                    &self.pool.publication,
                    &format!("{name}.lock"),
                    FlockArg::LockExclusiveNonblock,
                )
            } else {
                self.pool.try_exclusive_lease(operation)
            };
            let lease = match probe {
                Ok(Some(lease)) => lease,
                Ok(None) => continue,
                Err(error) => return Some(Err(error)),
            };
            let directory = match owned(self.pool.temporary.open_dir(name)) {
                Ok(Some(directory)) => directory,
                Ok(None) => continue,
                Err(error) => return Some(Err(error)),
            };
            let parent = match owned(self.pool.temporary.try_clone()) {
                Ok(parent) => parent,
                Err(error) => return Some(Err(error)),
            };
            return Some(Ok(AbandonedTemporary {
                parent,
                directory,
                name: name.to_owned(),
                _lease: lease,
            }));
        }
    }
}

fn scan_directory(directory: &OwnedDirectory) -> Result<nix::dir::OwningIter, StorageError> {
    // Opening "." gives an independent directory cursor, unlike dup(), which
    // would share offsets between concurrent scans of the pool descriptor.
    Ok(nix::dir::Dir::openat(
        directory.fd(),
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?
    .into_iter())
}

fn owned<T>(result: Result<T, crate::LibVmError>) -> Result<T, StorageError> {
    result.map_err(|error| StorageError::InvalidPath(error.to_string()))
}

impl StoragePool {
    /// `images_dir` is the canonical images/ directory, not SILO_HOME itself.
    pub fn open(images_dir: &Path) -> Result<Self, StorageError> {
        let root = owned(OwnedDirectory::open_root(images_dir))?;
        if fstat(root.fd())?.st_mode & 0o7777 != 0o700 {
            return Err(StorageError::InvalidPath(format!(
                "{} must have mode 0700",
                images_dir.display()
            )));
        }
        let objects = owned(owned(root.ensure_dir("objects"))?.ensure_dir("sha256"))?;
        let streams = owned(owned(root.ensure_dir("streams"))?.ensure_dir("sha256"))?;
        for name in ["source-blobs", "transport"] {
            owned(owned(root.ensure_dir(name))?.ensure_dir("sha256"))?;
        }
        let temporary = owned(root.ensure_dir("tmp"))?;
        let lock_directory = owned(root.ensure_dir("locks"))?;
        let publication = owned(lock_directory.ensure_dir("publication"))?;
        let leases = owned(lock_directory.ensure_dir("leases"))?;
        Ok(Self {
            root,
            objects,
            streams,
            temporary,
            lock_directory,
            publication,
            leases,
            defer_publication: false,
            publication_lock_policy: PublicationLockPolicy::Wait,
        })
    }
    /// Open only an already-initialized pool, without creating any directory,
    /// lock file or staging entry. Missing pool roots return None.
    pub fn open_existing(images_dir: &Path) -> Result<Option<Self>, StorageError> {
        let Some(root) = owned(OwnedDirectory::open_existing_root(images_dir))? else {
            return Ok(None);
        };
        if fstat(root.fd())?.st_mode & 0o7777 != 0o700 {
            return Err(StorageError::InvalidPath(format!(
                "{} must have mode 0700",
                images_dir.display()
            )));
        }
        let required = |directory: &OwnedDirectory, name: &str| {
            owned(directory.open_dir(name))?.ok_or_else(|| {
                StorageError::InvalidPath(format!(
                    "missing pool directory {}",
                    directory.path().join(name).display()
                ))
            })
        };
        let objects = required(&required(&root, "objects")?, "sha256")?;
        let streams = required(&required(&root, "streams")?, "sha256")?;
        let temporary = required(&root, "tmp")?;
        let lock_directory = required(&root, "locks")?;
        let publication = required(&lock_directory, "publication")?;
        let leases = required(&lock_directory, "leases")?;
        Ok(Some(Self {
            root,
            objects,
            streams,
            temporary,
            lock_directory,
            publication,
            leases,
            defer_publication: false,
            publication_lock_policy: PublicationLockPolicy::Wait,
        }))
    }

    pub(crate) fn defer_publications(mut self) -> Self {
        self.defer_publication = true;
        self
    }

    pub(crate) fn with_publication_lock_policy(mut self, policy: PublicationLockPolicy) -> Self {
        self.publication_lock_policy = policy;
        self
    }

    pub(crate) fn sync_publications(&self) -> Result<(), StorageError> {
        owned(self.objects.sync())?;
        owned(self.streams.sync())?;
        owned(self.publication.sync())?;
        owned(self.temporary.sync())
    }

    fn publication_lock(&self, name: &str) -> Result<StorageLock, StorageError> {
        match self.publication_lock_policy {
            PublicationLockPolicy::Defer => {
                locks::acquire(&self.publication, name, FlockArg::LockExclusiveNonblock)?
                    .ok_or_else(|| StorageError::PublicationBusy {
                        resource: name.to_owned(),
                    })
            }
            PublicationLockPolicy::Wait if self.defer_publication => {
                locks::blocking_deferred(&self.publication, name, FlockArg::LockExclusive)
            }
            PublicationLockPolicy::Wait => {
                locks::blocking(&self.publication, name, FlockArg::LockExclusive)
            }
        }
    }

    /// Validate the immutable pool file and its identity without modifying state.
    pub fn verify_stream(&self, id: &StreamId) -> Result<StreamMap, StorageError> {
        let file = self.open_stream(id)?;
        let metadata = file.metadata()?;
        Resource::ArtifactStreamBytes.check(metadata.len())?;
        let before = SourceFingerprint::new(&metadata);
        let scan = StreamHasher::new().hash_open_file(&file, metadata.len())?;
        if scan.map.id() != *id || before != SourceFingerprint::new(&file.metadata()?) {
            return Err(StorageError::ContentMismatch(self.stream_path(id)));
        }
        Ok(scan.map)
    }

    /// Authenticate a stream through its pinned pool directory and return the
    /// exact hashed descriptor. A caller that later relies on it must bind its
    /// fingerprint to a state observed before this hash began.
    pub(crate) fn authenticate_stream_full(
        &self,
        id: &StreamId,
    ) -> Result<AuthenticatedStream, StorageError> {
        let file = self.open_stream(id)?;
        let length = file.metadata()?.len();
        Resource::ArtifactStreamBytes.check(length)?;
        let authenticated = StreamHasher::new().authenticate(file, length)?;
        if authenticated.map().id() != *id {
            return Err(StorageError::ContentMismatch(self.stream_path(id)));
        }
        Ok(authenticated)
    }

    /// Open a sealed stream through its retained parent. The caller must
    /// authenticate the descriptor, or bind it to an already authenticated
    /// held inode, before treating its bytes as that stream.
    pub(crate) fn open_stream(&self, id: &StreamId) -> Result<File, StorageError> {
        existing(&self.streams, &id.hex())?.ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("missing stream {}", self.stream_path(id).display()),
            ))
        })
    }

    pub fn object_path(&self, digest: &ObjectDigest) -> PathBuf {
        self.objects.path().join(digest.hex())
    }

    /// Record publication's content identity for metadata-only packaged-update discovery.
    pub(crate) fn record_boot_source(
        &self,
        fingerprint: SourceFingerprint,
        digest: ObjectDigest,
    ) -> Result<(), StorageError> {
        let key = serde_json::to_vec(&fingerprint)
            .map_err(|error| StorageError::InvalidPath(error.to_string()))?;
        let directory = owned(self.root.ensure_dir("boot-sources"))?;
        let bytes = serde_json::to_vec(&digest)
            .map_err(|error| StorageError::InvalidPath(error.to_string()))?;
        let key = ObjectDigest::of_bytes(&key).hex();
        if let Some(file) = owned(directory.open_file(&key))? {
            let mut previous = Vec::new();
            file.take(1025).read_to_end(&mut previous)?;
            if previous == bytes {
                return Ok(());
            }
        }
        owned(directory.write_file_atomic(&key, &bytes))
    }

    /// Unknown or changed installed files have no recorded replacement identity.
    pub(crate) fn boot_source_digest(
        &self,
        path: &Path,
    ) -> Result<Option<ObjectDigest>, StorageError> {
        let Some(directory) = owned(self.root.open_dir("boot-sources"))? else {
            return Ok(None);
        };
        let source = open_regular_source(path)?;
        let fingerprint = SourceFingerprint::new(&source.metadata()?);
        let key = serde_json::to_vec(&fingerprint)
            .map_err(|error| StorageError::InvalidPath(error.to_string()))?;
        let Some(file) = owned(directory.open_file(&ObjectDigest::of_bytes(&key).hex()))? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(1025).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 {
            return Err(StorageError::InvalidPath(
                "boot source receipt exceeds metadata bound".into(),
            ));
        }
        let digest: ObjectDigest = serde_json::from_slice(&bytes)
            .map_err(|error| StorageError::InvalidPath(error.to_string()))?;
        if existing(&self.objects, &digest.hex())?.is_none()
            || fingerprint != SourceFingerprint::new(&source.metadata()?)
        {
            return Ok(None);
        }
        Ok(Some(digest))
    }

    pub fn stream_path(&self, id: &StreamId) -> PathBuf {
        self.streams.path().join(id.hex())
    }

    /// Resolve immutable lower metadata without opening the backing file.
    /// Pinned pool directories reject symlinked parents; NOFOLLOW rejects a
    /// symlink leaf. Callers must retain the semantic closure while planning,
    /// then run resource preflight before `verify_stream` opens any backing.
    pub fn lower_occurrence(
        &self,
        id: &StreamId,
    ) -> Result<crate::storage::vmdk::LowerOccurrence, StorageError> {
        let name = id.hex();
        let path = self.streams.path().join(&name);
        let length = immutable_length(&self.streams, &name)?.ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("missing stream {}", path.display()),
            ))
        })?;
        Ok(crate::storage::vmdk::LowerOccurrence::resolved(
            crate::storage::vmdk::LowerBacking::Stream(*id),
            path,
            length,
        ))
    }

    /// Resolve an immutable byte-object lower occurrence (fsmeta) without
    /// opening it; the same pinned-directory/NOFOLLOW rules as streams apply.
    pub fn lower_object_occurrence(
        &self,
        digest: &ObjectDigest,
    ) -> Result<crate::storage::vmdk::LowerOccurrence, StorageError> {
        let name = digest.hex();
        let path = self.objects.path().join(&name);
        let length = immutable_length(&self.objects, &name)?.ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("missing object {}", path.display()),
            ))
        })?;
        Ok(crate::storage::vmdk::LowerOccurrence::resolved(
            crate::storage::vmdk::LowerBacking::Object(*digest),
            path,
            length,
        ))
    }

    pub fn scan_objects(&self) -> Result<ObjectScan<'_>, StorageError> {
        Ok(ObjectScan {
            directory: &self.objects,
            entries: scan_directory(&self.objects)?,
        })
    }

    /// Read one authenticated byte object after checking its allocation bound.
    pub fn read_object(
        &self,
        digest: &ObjectDigest,
        maximum: u64,
    ) -> Result<Vec<u8>, StorageError> {
        let path = self.object_path(digest);
        let mut file = existing(&self.objects, &digest.hex())?.ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing immutable object",
            ))
        })?;
        let length = file.metadata()?.len();
        if length > maximum {
            return Err(StorageError::InvalidPath(
                "immutable object exceeds read bound".into(),
            ));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length || ObjectDigest::of_bytes(&bytes) != *digest {
            return Err(StorageError::ContentMismatch(path));
        }
        Ok(bytes)
    }

    /// Authenticate a byte object through its pinned pool directory, using bounded
    /// memory. The caller retains its semantic closure; do not hash under roots.
    /// Return the same checked descriptor rewound for the consumer.
    pub(crate) fn verify_object(&self, digest: &ObjectDigest) -> Result<File, StorageError> {
        let path = self.object_path(digest);
        let mut file = self.open_object(digest)?;
        let metadata = file.metadata()?;
        let before = SourceFingerprint::new(&metadata);
        if copy_object(&mut file, &mut std::io::sink())? != (*digest, metadata.len())
            || before != SourceFingerprint::new(&file.metadata()?)
        {
            return Err(StorageError::ContentMismatch(path));
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    /// Open a sealed byte object through its retained parent. The caller must
    /// authenticate the held descriptor before treating its bytes as that digest.
    pub(crate) fn open_object(&self, digest: &ObjectDigest) -> Result<File, StorageError> {
        existing(&self.objects, &digest.hex())?.ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing immutable object",
            ))
        })
    }

    /// Caller holds exclusive root coordination and has checked catalog reachability.
    pub(crate) fn remove_object(&self, digest: &ObjectDigest) -> Result<(), StorageError> {
        if existing(&self.objects, &digest.hex())?.is_some() {
            owned(self.objects.remove_tree(&digest.hex()))?;
            owned(self.objects.sync())?;
        }
        Ok(())
    }

    /// Requires fresh SQL authorization under exclusive roots coordination.
    pub(crate) fn remove_stream(&self, id: &StreamId) -> Result<bool, StorageError> {
        let name = id.hex();
        if immutable_length(&self.streams, &name)?.is_none() {
            return Ok(false);
        }
        owned(self.streams.remove_tree(&name))?;
        owned(self.streams.sync())?;
        Ok(true)
    }
    /// Discovery only: callers check fresh SQLite roots under exclusive
    /// coordination and journal deletion after external-dependency validation.
    pub fn scan_streams(&self) -> Result<StreamScan<'_>, StorageError> {
        Ok(StreamScan {
            directory: &self.streams,
            entries: scan_directory(&self.streams)?,
        })
    }

    /// Scan outside roots. Each candidate retains its exclusive UUID lease
    /// through caller-side external-dependency preflight and optional removal.
    pub fn abandoned_temporary(&self) -> Result<TemporaryScan<'_>, StorageError> {
        Ok(TemporaryScan {
            pool: self,
            entries: scan_directory(&self.temporary)?,
        })
    }

    #[cfg(test)]
    fn reap_temporary(&self) -> Result<u64, StorageError> {
        let mut removed = 0;
        for candidate in self.abandoned_temporary()? {
            candidate?.remove()?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Hold only across root changes/deletion, never downloads or VM execution.
    pub fn lock_roots(&self) -> Result<StorageLock, StorageError> {
        locks::blocking(&self.lock_directory, "roots.lock", FlockArg::LockExclusive)
    }

    pub fn lock_roots_shared(&self) -> Result<StorageLock, StorageError> {
        locks::blocking(&self.lock_directory, "roots.lock", FlockArg::LockShared)
    }

    #[cfg(test)]
    pub(crate) fn try_roots_shared(&self) -> Result<Option<StorageLock>, StorageError> {
        locks::acquire(
            &self.lock_directory,
            "roots.lock",
            FlockArg::LockSharedNonblock,
        )
    }

    pub(crate) fn try_capture_publication(
        &self,
        capture: Uuid,
    ) -> Result<Option<StorageLock>, StorageError> {
        let key = crate::store::capture::capture_publication_key(capture);
        locks::acquire(
            &self.publication,
            &format!("recipe-{}.lock", key.hex()),
            FlockArg::LockExclusiveNonblock,
        )
    }

    /// Recipe inputs must already be verified before deriving this byte key.
    pub fn lock_publication(&self, key: &ObjectDigest) -> Result<StorageLock, StorageError> {
        self.publication_lock(&format!("recipe-{}.lock", key.hex()))
    }

    /// Fresh IDs only. A colliding or unsafe stable inode is never replaced.
    pub fn lease(&self, operation: Uuid) -> Result<StorageLock, StorageError> {
        locks::acquire_new(
            &self.leases,
            &format!("{operation}.lease"),
            FlockArg::LockSharedNonblock,
        )?
        .ok_or_else(|| StorageError::InvalidPath("fresh operation lease is busy".into()))
    }

    /// The caller must include the lease and its directory in its durability barrier.
    pub(crate) fn lease_deferred(&self, operation: Uuid) -> Result<StorageLock, StorageError> {
        locks::acquire_new_deferred(
            &self.leases,
            &format!("{operation}.lease"),
            FlockArg::LockSharedNonblock,
        )?
        .ok_or_else(|| StorageError::InvalidPath("fresh operation lease is busy".into()))
    }

    pub(crate) fn lease_directory(&self) -> Result<OwnedDirectory, StorageError> {
        self.leases
            .try_clone()
            .map_err(|error| StorageError::InvalidPath(error.to_string()))
    }

    /// Rejoin a registered operation without creating or replacing its lease.
    pub(crate) fn existing_lease(&self, operation: Uuid) -> Result<StorageLock, StorageError> {
        locks::acquire_existing(
            &self.leases,
            &format!("{operation}.lease"),
            FlockArg::LockSharedNonblock,
        )?
        .ok_or_else(|| StorageError::InvalidPath("registered operation is being retired".into()))
    }

    /// Never wait for a lease while holding root coordination.
    pub fn try_exclusive_lease(
        &self,
        operation: Uuid,
    ) -> Result<Option<StorageLock>, StorageError> {
        locks::acquire_existing(
            &self.leases,
            &format!("{operation}.lease"),
            FlockArg::LockExclusiveNonblock,
        )
    }

    // Native stat field types differ between Linux and Darwin.
    #[allow(clippy::unnecessary_cast)]
    pub(crate) fn operation_lease_identity(
        &self,
        operation: Uuid,
    ) -> Result<(u64, u64), StorageError> {
        let name = format!("{operation}.lease");
        let stat = fstatat(
            self.leases.fd(),
            name.as_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
            || stat.st_uid != geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
        {
            return Err(StorageError::InvalidPath(
                "unsafe stable operation lease".into(),
            ));
        }
        Ok((stat.st_dev as u64, stat.st_ino as u64))
    }

    /// Canonical lease inventory is traversed outside roots coordination.
    /// Busy unknown roots block all destructive recovery.
    pub(crate) fn scan_leases(&self) -> Result<LeaseScan, StorageError> {
        Ok(LeaseScan {
            entries: scan_directory(&self.leases)?,
        })
    }

    #[cfg(test)]
    pub fn create_operation(&self) -> Result<OperationPaths, StorageError> {
        let id = Uuid::new_v4();
        self.create_operation_with_lease(id, self.lease(id)?)
    }

    /// Caller owns the registered operation's original shared OFD.
    pub(crate) fn create_operation_with_lease(
        &self,
        id: Uuid,
        lease: StorageLock,
    ) -> Result<OperationPaths, StorageError> {
        self.create_operation_with_lease_sync(id, lease, true)
    }

    pub(crate) fn create_operation_with_lease_deferred(
        &self,
        id: Uuid,
        lease: StorageLock,
    ) -> Result<OperationPaths, StorageError> {
        self.create_operation_with_lease_sync(id, lease, false)
    }

    fn create_operation_with_lease_sync(
        &self,
        id: Uuid,
        lease: StorageLock,
        sync: bool,
    ) -> Result<OperationPaths, StorageError> {
        let home =
            self.root.path().parent().ok_or_else(|| {
                StorageError::InvalidPath("images directory has no parent".into())
            })?;
        let home = owned(OwnedDirectory::open_existing_root(home))?
            .ok_or_else(|| StorageError::InvalidPath("operation home disappeared".into()))?;
        let operations = owned(if sync {
            home.ensure_dir("operations")
        } else {
            home.ensure_dir_deferred("operations")
        })?;
        let name = id.to_string();
        let durable = owned(if sync {
            operations.create_dir(&name)
        } else {
            operations.create_dir_deferred(&name)
        })?
        .ok_or_else(|| StorageError::InvalidPath("operation ID collision".into()))?;
        let temporary = match owned(if sync {
            self.temporary.create_dir(&name)
        } else {
            self.temporary.create_dir_deferred(&name)
        }) {
            Ok(Some(directory)) => directory,
            result => {
                owned(operations.remove_tree(&name))?;
                return Err(match result {
                    Err(error) => error,
                    Ok(_) => StorageError::InvalidPath("operation staging ID collision".into()),
                });
            }
        };
        Ok(OperationPaths {
            id,
            temporary: temporary.path().to_path_buf(),
            durable: durable.path().to_path_buf(),
            _lease: lease,
        })
    }

    #[cfg(test)]
    /// Resolve the foreign source once; callers must quiesce external writers.
    /// Copies bytes into owned staging before assigning immutable identity.
    pub(crate) fn publish_stream(&self, source: &Path) -> Result<PublishedStream, StorageError> {
        self.publish_stream_for_catalog(source)
            .map(|(published, _guard)| published)
    }

    /// Hash/copy outside root coordination, then retain a short publication guard.
    /// Keep the returned guard until the stream's SQLite retention commit.
    pub fn publish_stream_for_catalog(
        &self,
        source: &Path,
    ) -> Result<(PublishedStream, StorageLock), StorageError> {
        let input = open_regular_source(source)?;
        let length = input.metadata()?.len();
        self.publish_stream_file_for_catalog(input, length)
    }

    /// Publish from an already admitted held descriptor and fixed logical length.
    /// The caller owns source quiescence and synchronization. No source path is
    /// resolved again; the file remains owned through copying and verification.
    pub fn publish_stream_file_for_catalog(
        &self,
        input: File,
        length: u64,
    ) -> Result<(PublishedStream, StorageLock), StorageError> {
        Resource::ArtifactStreamBytes.check(length)?;
        let metadata = input.metadata()?;
        if !metadata.is_file() || metadata.len() != length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stream publication source type or admitted length changed",
            )
            .into());
        }
        let (staging, file) = self.stage()?;
        let mut hasher = StreamHasher::new();
        let map = hasher.copy_file_and_hash(&input, length, &file)?.map;
        let id = map.id();
        seal(&file)?;
        let name = id.hex();
        let _publication = self.publication_lock(&format!("stream-{name}.lock"))?;
        let verified = if let Some(existing) = existing(&self.streams, &name)? {
            let before = SourceFingerprint::new(&existing.metadata()?);
            if existing.metadata()?.len() != map.length()
                || hasher.hash_open_file(&existing, map.length())?.map != map
                || before != SourceFingerprint::new(&existing.metadata()?)
            {
                return Err(StorageError::ContentMismatch(self.stream_path(&id)));
            }
            Some(before)
        } else {
            None
        };
        let roots = self.finish_publication(&self.streams, &staging, &name, verified)?;
        Ok((
            PublishedStream {
                id,
                length: map.length(),
                path: self.stream_path(&id),
                map,
            },
            roots,
        ))
    }

    /// Qualify one staging-filesystem/pool pair using bounded anonymous files.
    /// Probe bytes and namespace entries are never publication authority and
    /// need no durability. Actual streams still enforce CloneRequired.
    #[cfg(target_os = "linux")]
    pub(crate) fn qualify_capture_clone(
        &self,
        source: &OwnedDirectory,
    ) -> Result<bool, StorageError> {
        use std::os::unix::fs::FileExt;
        if fstat(source.fd())?.st_dev != fstat(self.temporary.fd())?.st_dev {
            return Ok(false);
        }
        let probe = |directory: &OwnedDirectory| -> Result<File, StorageError> {
            Ok(File::from(openat(
                directory.fd(),
                ".",
                OFlag::O_TMPFILE | OFlag::O_RDWR | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )?))
        };
        let input = probe(source)?;
        let output = probe(&self.temporary)?;
        input.write_all_at(&[0x51; 4096], 0)?;
        try_clone_stream(&input, &output)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn qualify_capture_clone(
        &self,
        _source: &OwnedDirectory,
    ) -> Result<bool, StorageError> {
        Ok(false)
    }

    /// Publish a closed, owned producer's sealed stream and canonical map.
    /// Reflinks carry producer identity; copies authenticate inline. Existing
    /// pool inodes require a matching verified receipt or full authentication.
    pub(crate) fn publish_sealed_stream_for_catalog(
        &self,
        input: &File,
        map: &StreamMap,
        verified_receipt: Option<SourceFingerprint>,
        mode: SealedStreamPublicationMode,
    ) -> Result<(SealedStreamPublication, StorageLock), StorageError> {
        let metadata = input.metadata()?;
        let before = SourceFingerprint::new(&metadata);
        let id = map.id();
        let name = id.hex();
        if !metadata.is_file() || metadata.len() != map.length() {
            return Err(StorageError::ContentMismatch(self.stream_path(&id)));
        }
        let _publication = self.publication_lock(&format!("stream-{name}.lock"))?;
        if let Some(file) = existing(&self.streams, &name)? {
            let fingerprint = SourceFingerprint::new(&file.metadata()?);
            if file.metadata()?.len() != map.length() {
                return Err(StorageError::ContentMismatch(self.stream_path(&id)));
            }
            let stats = if verified_receipt == Some(fingerprint) {
                StreamStats::default()
            } else {
                let scan = StreamHasher::new().hash_open_file(&file, map.length())?;
                if scan.map != *map {
                    return Err(StorageError::ContentMismatch(self.stream_path(&id)));
                }
                scan.stats
            };
            let roots = self.lock_roots_shared()?;
            if SourceFingerprint::new(&input.metadata()?) != before {
                return Err(StorageError::ContentMismatch(self.stream_path(&id)));
            }
            let publication = SealedStreamPublication {
                file,
                map: map.clone(),
                fingerprint,
                scan_stats: stats,
            };
            publication.recheck(self)?;
            return Ok((publication, roots));
        }
        let (staging, file) = self.stage()?;
        let (staging, file, published_map, stats) = if try_clone_stream(input, &file)? {
            (staging, file, map.clone(), StreamStats::default())
        } else {
            if mode == SealedStreamPublicationMode::CloneRequired {
                return Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "publication deferred: qualified clone unavailable; copy requires fresh admission",
                )));
            }
            drop(file);
            drop(staging);
            let (staging, file) = self.stage()?;
            let scan = StreamHasher::new().copy_file_and_hash(input, map.length(), &file)?;
            if scan.map != *map {
                return Err(StorageError::ContentMismatch(self.stream_path(&id)));
            }
            (staging, file, scan.map, scan.stats)
        };
        if SourceFingerprint::new(&input.metadata()?) != before
            || file.metadata()?.len() != map.length()
        {
            return Err(StorageError::ContentMismatch(self.stream_path(&id)));
        }
        seal(&file)?;
        let sealed = SourceFingerprint::new(&file.metadata()?);
        let roots = self.finish_publication(&self.streams, &staging, &name, None)?;
        let metadata = file.metadata()?;
        if !sealed.same_contents_after_metadata_change(&metadata) {
            return Err(StorageError::ContentMismatch(self.stream_path(&id)));
        }
        let publication = SealedStreamPublication {
            file,
            map: published_map,
            fingerprint: SourceFingerprint::new(&metadata),
            scan_stats: stats,
        };
        publication.recheck(self)?;
        Ok((publication, roots))
    }

    #[cfg(test)]
    pub(crate) fn publish_object(&self, source: &Path) -> Result<PublishedObject, StorageError> {
        self.publish_object_for_catalog(source)
            .map(|(published, _guard)| published)
    }

    /// Keep the returned guard through the object's catalog retention commit.
    pub fn publish_object_for_catalog(
        &self,
        source: &Path,
    ) -> Result<(PublishedObject, StorageLock), StorageError> {
        self.publish_object_file_for_catalog(open_regular_source(source)?, source)
    }

    /// Consume an already opened regular source. `source` is diagnostic only;
    /// publication never reopens it, so replacing that path cannot change bytes.
    /// The returned roots guard must cover registration of the object dependency.
    pub(crate) fn publish_object_file_for_catalog(
        &self,
        mut input: File,
        source: &Path,
    ) -> Result<(PublishedObject, StorageLock), StorageError> {
        if !input.metadata()?.is_file() {
            return Err(StorageError::NotRegular(source.to_path_buf()));
        }
        input.seek(SeekFrom::Start(0))?;
        let before = SourceFingerprint::new(&input.metadata()?);
        let (staging, mut file) = self.stage()?;
        let (digest, length) = copy_object(&mut input, &mut file)?;
        if before != SourceFingerprint::new(&input.metadata()?) {
            return Err(StorageError::SourceChanged(source.to_path_buf()));
        }
        seal(&file)?;
        let name = digest.hex();
        let _publication = self.publication_lock(&format!("object-{name}.lock"))?;
        let verified = if let Some(mut existing) = existing(&self.objects, &name)? {
            let before = SourceFingerprint::new(&existing.metadata()?);
            if copy_object(&mut existing, &mut std::io::sink())? != (digest, length)
                || before != SourceFingerprint::new(&existing.metadata()?)
            {
                return Err(StorageError::ContentMismatch(self.object_path(&digest)));
            }
            Some(before)
        } else {
            None
        };
        let sealed = SourceFingerprint::new(&file.metadata()?);
        let roots = self.finish_publication(&self.objects, &staging, &name, verified)?;
        let fingerprint = self.published_object_fingerprint(digest, &file, sealed, verified)?;
        Ok((
            PublishedObject {
                digest,
                length,
                path: self.object_path(&digest),
                fingerprint,
            },
            roots,
        ))
    }

    /// Produce a byte object directly into owned pool staging, then hash and
    /// publish that exact file; large objects (fsmeta) are never copied. The
    /// producer must leave the complete object in `file`. Staging is removed
    /// on any failure. Keep the guard through the catalog retention commit.
    pub(crate) fn publish_produced_object_for_catalog<T, E: From<StorageError>>(
        &self,
        produce: impl FnOnce(&mut File) -> Result<T, E>,
    ) -> Result<(PublishedObject, StorageLock, T), E> {
        let (staging, mut file) = self.stage()?;
        let output = produce(&mut file)?;
        let published = (|| {
            file.seek(SeekFrom::Start(0))?;
            let before = SourceFingerprint::new(&file.metadata()?);
            let (digest, length) = copy_object(&mut file, &mut std::io::sink())?;
            if before != SourceFingerprint::new(&file.metadata()?) {
                return Err(StorageError::SourceChanged(staging.directory.path().into()));
            }
            seal(&file)?;
            let name = digest.hex();
            let _publication = self.publication_lock(&format!("object-{name}.lock"))?;
            let verified = if let Some(mut existing) = existing(&self.objects, &name)? {
                let before = SourceFingerprint::new(&existing.metadata()?);
                if copy_object(&mut existing, &mut std::io::sink())? != (digest, length)
                    || before != SourceFingerprint::new(&existing.metadata()?)
                {
                    return Err(StorageError::ContentMismatch(self.object_path(&digest)));
                }
                Some(before)
            } else {
                None
            };
            let sealed = SourceFingerprint::new(&file.metadata()?);
            let roots = self.finish_publication(&self.objects, &staging, &name, verified)?;
            let fingerprint = self.published_object_fingerprint(digest, &file, sealed, verified)?;
            Ok((
                PublishedObject {
                    digest,
                    length,
                    path: self.object_path(&digest),
                    fingerprint,
                },
                roots,
            ))
        })()?;
        Ok((published.0, published.1, output))
    }

    fn published_object_fingerprint(
        &self,
        digest: ObjectDigest,
        file: &File,
        sealed: SourceFingerprint,
        verified: Option<SourceFingerprint>,
    ) -> Result<SourceFingerprint, StorageError> {
        let fingerprint = match verified {
            Some(fingerprint) => fingerprint,
            None => {
                let metadata = file.metadata()?;
                if !sealed.same_contents_after_metadata_change(&metadata) {
                    return Err(StorageError::ContentMismatch(self.object_path(&digest)));
                }
                SourceFingerprint::new(&metadata)
            }
        };
        if SourceFingerprint::new(&self.open_object(&digest)?.metadata()?) != fingerprint {
            return Err(StorageError::ContentMismatch(self.object_path(&digest)));
        }
        Ok(fingerprint)
    }

    fn finish_publication(
        &self,
        destination: &OwnedDirectory,
        staging: &Staging<'_>,
        name: &str,
        verified: Option<SourceFingerprint>,
    ) -> Result<StorageLock, StorageError> {
        let roots = self.lock_roots_shared()?;
        // GC may have removed the previously verified file while hashing. Recheck
        // its identity under coordination, but never perform a full scan here.
        if let Some(current) = existing(destination, name)? {
            if Some(SourceFingerprint::new(&current.metadata()?)) != verified {
                return Err(StorageError::ContentMismatch(destination.path().join(name)));
            }
        } else {
            rename_no_replace(&staging.directory, destination, name)?;
        }
        if !self.defer_publication {
            owned(destination.sync())?;
            owned(staging.directory.sync())?;
        }
        Ok(roots)
    }

    pub(crate) fn stage(&self) -> Result<(Staging<'_>, File), StorageError> {
        // These locks protect only unpublished disposable directories, not a
        // semantic closure. Canonical operation leases require catalog roots.
        let name = format!("stage-{}", Uuid::new_v4());
        let lease = if self.defer_publication {
            locks::acquire_new_deferred(
                &self.publication,
                &format!("{name}.lock"),
                FlockArg::LockSharedNonblock,
            )?
        } else {
            locks::acquire_new(
                &self.publication,
                &format!("{name}.lock"),
                FlockArg::LockSharedNonblock,
            )?
        }
        .ok_or_else(|| StorageError::InvalidPath("fresh staging lock is busy".into()))?;
        let directory = owned(if self.defer_publication {
            self.temporary.create_dir_deferred(&name)
        } else {
            self.temporary.create_dir(&name)
        })?
        .ok_or_else(|| StorageError::InvalidPath("staging ID collision".into()))?;
        let staging = Staging {
            parent: &self.temporary,
            directory,
            name,
            _lease: lease,
        };
        let fd = openat(
            staging.directory.fd(),
            "content",
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?;
        fchmod(&fd, Mode::S_IRUSR | Mode::S_IWUSR)?;
        Ok((staging, File::from(fd)))
    }
}

pub(crate) struct Staging<'a> {
    parent: &'a OwnedDirectory,
    directory: OwnedDirectory,
    name: String,
    _lease: StorageLock,
}

impl Staging<'_> {
    pub(crate) fn path(&self) -> PathBuf {
        self.directory.path().join("content")
    }
}

impl Drop for Staging<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.parent.remove_tree(&self.name) {
            tracing::warn!(%error, operation = %self.name, "failed to remove storage staging directory");
        }
    }
}
fn rename_no_replace(
    source: &OwnedDirectory,
    destination: &OwnedDirectory,
    name: &str,
) -> Result<(), StorageError> {
    rename_component_no_replace(source, "content", destination, name)
}

fn validate_publication_component(name: &str) -> Result<(), StorageError> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
        || name.as_bytes().contains(&0)
        || name.as_bytes().contains(&b'/')
    {
        return Err(StorageError::InvalidPath(
            "publication name is not one component".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn rename_component_no_replace(
    source: &OwnedDirectory,
    source_name: &str,
    destination: &OwnedDirectory,
    name: &str,
) -> Result<(), StorageError> {
    validate_publication_component(source_name)?;
    validate_publication_component(name)?;
    nix::fcntl::renameat2(
        source.fd(),
        source_name,
        destination.fd(),
        name,
        nix::fcntl::RenameFlags::RENAME_NOREPLACE,
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn rename_component_no_replace(
    source: &OwnedDirectory,
    source_name: &str,
    destination: &OwnedDirectory,
    name: &str,
) -> Result<(), StorageError> {
    use nix::NixPath;
    use std::os::fd::AsRawFd;
    validate_publication_component(source_name)?;
    validate_publication_component(name)?;

    // nix exposes no renameatx_np wrapper. RENAME_EXCL is the macOS atomic
    // no-replace rename, avoiding link/unlink's crash-persistent second name.
    // Both descriptors remain owned here and both C strings outlive the call.
    let result = source_name.with_nix_path(|source_name| {
        name.with_nix_path(|name| unsafe {
            libc::renameatx_np(
                source.fd().as_raw_fd(),
                source_name.as_ptr(),
                destination.fd().as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_EXCL,
            )
        })
    })??;
    if result == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn try_clone_stream(source: &File, destination: &File) -> Result<bool, StorageError> {
    use std::os::unix::fs::MetadataExt;

    use nix::fcntl::{fcntl, FcntlArg};

    let source_metadata = source.metadata()?;
    let destination_metadata = destination.metadata()?;
    let source_flags = OFlag::from_bits_truncate(fcntl(source, FcntlArg::F_GETFL)?);
    let destination_flags = OFlag::from_bits_truncate(fcntl(destination, FcntlArg::F_GETFL)?);
    // Qualify whole-file EINVAL as unsupported only for readable regular source
    // and writable, empty, distinct regular destination with no append mode.
    if !source_metadata.is_file()
        || !destination_metadata.is_file()
        || destination_metadata.len() != 0
        || (source_metadata.dev(), source_metadata.ino())
            == (destination_metadata.dev(), destination_metadata.ino())
        || source_flags & OFlag::O_ACCMODE == OFlag::O_WRONLY
        || destination_flags & OFlag::O_ACCMODE == OFlag::O_RDONLY
        || source_flags.contains(OFlag::O_APPEND)
        || destination_flags.contains(OFlag::O_APPEND)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "stream clone requires a readable source and distinct empty writable destination",
        )
        .into());
    }
    if source_metadata.dev() != destination_metadata.dev() {
        return Ok(false);
    }
    match crate::storage::clone::try_reflink(source, destination) {
        Ok(()) => Ok(true),
        Err(error) if crate::storage::clone::clone_error_allows_fallback(&error, true) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn try_clone_stream(_source: &File, _destination: &File) -> Result<bool, StorageError> {
    Ok(false)
}

fn seal(file: &File) -> Result<(), StorageError> {
    fchmod(file, Mode::S_IRUSR)?;
    file.sync_all()?;
    Ok(())
}

/// Metadata-only discovery must not authenticate/open lower bytes before start
/// admission. Missing leaves can disappear during cooperative GC enumeration.
fn immutable_length(directory: &OwnedDirectory, name: &str) -> Result<Option<u64>, StorageError> {
    let stat = match fstatat(directory.fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o400
        || stat.st_nlink != 1
        || stat.st_size < 0
    {
        return Err(StorageError::InvalidPath(format!(
            "invalid immutable file {}",
            directory.path().join(name).display()
        )));
    }
    Ok(Some(stat.st_size as u64))
}

fn existing(directory: &OwnedDirectory, name: &str) -> Result<Option<File>, StorageError> {
    let fd = match openat(
        directory.fd(),
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let stat = fstat(&fd)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o400
        || stat.st_nlink != 1
    {
        return Err(StorageError::InvalidPath(format!(
            "invalid immutable file {}",
            directory.path().join(name).display()
        )));
    }
    Ok(Some(File::from(fd)))
}

fn copy_object(
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(ObjectDigest, u64), StorageError> {
    let mut buffer = [0; 64 * 1024];
    let mut hash = Sha256::new();
    let mut length = 0;
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        length = Resource::JsonInteger.sum([length, count as u64])?;
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    Ok((ObjectDigest::from_sha256(hash.finalize().into()), length))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::FileExt;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::Arc;

    use crate::storage::identity::ObjectDigest;
    use crate::storage::pool::{SealedStreamPublicationMode, StoragePool};
    use crate::storage::stream::{StreamHasher, StreamMap};
    use crate::storage::StorageError;

    fn ram_tempdir() -> tempfile::TempDir {
        match std::env::var_os("SILO_TEST_COPY_DIR") {
            Some(path) => tempfile::tempdir_in(path).unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }

    #[cfg(target_os = "linux")]
    fn reflink_or_skip(source: &File, destination: &File) -> bool {
        let cloned = crate::storage::pool::try_clone_stream(source, destination).unwrap();
        if !cloned {
            eprintln!(
                "SKIPPED RAM reflink test: test tmpdir does not support whole-file reflinks; \
                 set SILO_TEST_COPY_DIR to a reflink-enabled Btrfs or XFS directory"
            );
        }
        cloned
    }

    #[test]
    fn publishes_distinct_immutable_forms_with_exact_bytes_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input");
        std::fs::write(&source, b"raw bytes\0\0").unwrap();
        let pool = StoragePool::open(&dir.path().join("images")).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let object = pool.publish_object(&source).unwrap();
        assert_eq!(std::fs::read(&stream.path).unwrap(), b"raw bytes\0\0");
        assert_eq!(std::fs::read(&object.path).unwrap(), b"raw bytes\0\0");
        assert_eq!(object.digest, ObjectDigest::of_bytes(b"raw bytes\0\0"));
        assert_eq!(
            stream.id,
            StreamHasher::new().hash_file(&source).unwrap().id()
        );
        assert_ne!(stream.id.to_string(), object.digest.to_string());
        assert_eq!(
            stream.path,
            dir.path()
                .join("images/streams/sha256")
                .join(stream.id.hex())
        );
        assert_eq!(
            object.path,
            dir.path()
                .join("images/objects/sha256")
                .join(object.digest.hex())
        );
        assert_eq!(
            std::fs::metadata(&stream.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        assert_eq!(
            std::fs::metadata(&source).unwrap().permissions().mode() & 0o200,
            0o200
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("images/tmp"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read_dir(dir.path().join("images/tmp"))
                .unwrap()
                .count(),
            0
        );
        let operation = pool.create_operation().unwrap();
        assert_eq!(
            operation.temporary,
            dir.path().join("images/tmp").join(operation.id.to_string())
        );
        assert_eq!(
            operation.durable,
            dir.path().join("operations").join(operation.id.to_string())
        );
        assert_eq!(
            std::fs::metadata(operation.durable)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn catalog_guard_bridges_publication_until_retention_commit() {
        use crate::storage::locks::acquire;
        use nix::fcntl::FlockArg;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input");
        std::fs::write(&source, b"retained").unwrap();
        let pool = StoragePool::open(&dir.path().join("images")).unwrap();
        let (_, guard) = pool.publish_stream_for_catalog(&source).unwrap();
        assert!(acquire(
            &pool.lock_directory,
            "roots.lock",
            FlockArg::LockExclusiveNonblock
        )
        .unwrap()
        .is_none());
        let duplicate = guard.duplicate().unwrap();
        drop(guard);
        assert!(acquire(
            &pool.lock_directory,
            "roots.lock",
            FlockArg::LockExclusiveNonblock
        )
        .unwrap()
        .is_none());
        drop(duplicate);
        assert!(acquire(
            &pool.lock_directory,
            "roots.lock",
            FlockArg::LockExclusiveNonblock
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn zero_only_and_zero_tail_publications_keep_the_entire_logical_length() {
        use crate::storage::limits::CHUNK_SIZE;
        use crate::storage::stream::Chunk;
        use std::io::{Seek, SeekFrom, Write};

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input");
        let mut file = std::fs::File::create(&source).unwrap();
        let length = CHUNK_SIZE as u64 + 19;
        file.set_len(length).unwrap();
        let pool = StoragePool::open(&dir.path().join("images")).unwrap();
        let zeros = pool.publish_stream(&source).unwrap();
        assert_eq!(std::fs::metadata(&zeros.path).unwrap().len(), length);
        assert_eq!(zeros.map.chunks(), &[Chunk::Zero, Chunk::Zero]);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[1]).unwrap();
        let tail = pool.publish_stream(&source).unwrap();
        assert_eq!(std::fs::metadata(&tail.path).unwrap().len(), length);
        assert_eq!(tail.map.chunks()[1], Chunk::Zero);
        assert_eq!(StreamHasher::new().hash_file(&tail.path).unwrap(), tail.map);
        assert_ne!(zeros.id, tail.id);
    }

    #[test]
    fn concurrent_publication_converges_without_replacing_inode() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input");
        std::fs::write(&source, vec![7; 12345]).unwrap();
        let pool = Arc::new(StoragePool::open(&dir.path().join("images")).unwrap());
        let first = pool.publish_stream(&source).unwrap();
        let inode = std::fs::metadata(&first.path).unwrap().ino();
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let source = source.clone();
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || pool.publish_stream(&source).unwrap().id)
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), first.id);
        }
        assert_eq!(std::fs::metadata(first.path).unwrap().ino(), inode);
    }

    #[test]
    fn no_replace_rename_preserves_existing_destination_and_staged_source() {
        use crate::storage::pool::{rename_no_replace, seal};
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input");
        std::fs::write(&source, b"original").unwrap();
        let pool = StoragePool::open(&dir.path().join("images")).unwrap();
        let original = pool.publish_object(&source).unwrap();
        let inode = std::fs::metadata(&original.path).unwrap().ino();
        let (staging, mut file) = pool.stage().unwrap();
        file.write_all(b"replacement").unwrap();
        seal(&file).unwrap();
        let error = rename_no_replace(&staging.directory, &pool.objects, &original.digest.hex())
            .unwrap_err();
        assert!(
            matches!(error, StorageError::Io(error) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::read(&original.path).unwrap(), b"original");
        assert_eq!(std::fs::metadata(&original.path).unwrap().ino(), inode);
        assert_eq!(
            std::fs::read(staging.directory.path().join("content")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn no_replace_rename_has_exactly_one_winner_without_advisory_locks() {
        use crate::storage::pool::{rename_no_replace, seal};
        use std::io::Write;
        use std::sync::Barrier;

        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(StoragePool::open(&dir.path().join("images")).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let name = ObjectDigest::of_bytes(b"contended destination").hex();
        let threads: Vec<_> = [&b"first"[..], &b"second"[..]]
            .into_iter()
            .map(|bytes| {
                let pool = Arc::clone(&pool);
                let barrier = Arc::clone(&barrier);
                let name = name.clone();
                std::thread::spawn(move || {
                    let (staging, mut file) = pool.stage().unwrap();
                    file.write_all(bytes).unwrap();
                    seal(&file).unwrap();
                    barrier.wait();
                    match rename_no_replace(&staging.directory, &pool.objects, &name) {
                        Ok(()) => Some(bytes),
                        Err(StorageError::Io(error))
                            if error.kind() == std::io::ErrorKind::AlreadyExists =>
                        {
                            None
                        }
                        Err(error) => panic!("unexpected publication error: {error}"),
                    }
                })
            })
            .collect();
        let winners: Vec<_> = threads
            .into_iter()
            .filter_map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(winners.len(), 1);
        assert_eq!(
            std::fs::read(pool.objects.path().join(name)).unwrap(),
            winners[0]
        );
        assert_eq!(std::fs::read_dir(pool.temporary.path()).unwrap().count(), 0);
    }

    fn run_recovery_probe(root: &std::path::Path, mode: &str) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::pool::tests::recovery_crash_probe",
                "--nocapture",
            ])
            .env("SILO_STORAGE_RECOVERY_ROOT", root)
            .env("SILO_STORAGE_RECOVERY_MODE", mode)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn recovery_crash_probe() {
        use std::io::Write;

        let Some(root) = std::env::var_os("SILO_STORAGE_RECOVERY_ROOT") else {
            return;
        };
        let pool = StoragePool::open(std::path::Path::new(&root)).unwrap();
        match std::env::var("SILO_STORAGE_RECOVERY_MODE")
            .unwrap()
            .as_str()
        {
            "staging" => {
                let (staging, mut file) = pool.stage().unwrap();
                file.write_all(b"interrupted staging").unwrap();
                file.sync_all().unwrap();
                staging.directory.sync().unwrap();
                // A real process exit releases kernel leases without Rust Drop.
                std::process::exit(0);
            }
            "published" => {
                let source = pool.root.path().parent().unwrap().join("orphan-source");
                std::fs::write(&source, b"published before SQL commit").unwrap();
                let (_published, _roots) = pool.publish_stream_for_catalog(&source).unwrap();
                std::process::exit(0);
            }
            mode => panic!("unknown recovery probe mode {mode}"),
        }
    }

    #[test]
    fn temporary_recovery_skips_active_leases_and_reaps_real_process_exit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("images");
        let pool = StoragePool::open(&root).unwrap();
        let (active, _file) = pool.stage().unwrap();
        let active_path = active.directory.path().to_path_buf();
        let unknown = pool.temporary.path().join("not-an-operation");
        std::fs::create_dir(&unknown).unwrap();
        let external = dir.path().join("external");
        std::fs::create_dir(&external).unwrap();
        std::fs::write(external.join("preserve"), b"external").unwrap();
        let link = pool.temporary.path().join(uuid::Uuid::new_v4().to_string());
        symlink(&external, &link).unwrap();
        run_recovery_probe(&root, "staging");
        assert_eq!(pool.reap_temporary().unwrap(), 1);
        assert!(active_path.is_dir());
        assert!(unknown.is_dir());
        assert!(link.is_symlink());
        assert_eq!(
            std::fs::read(external.join("preserve")).unwrap(),
            b"external"
        );
        assert_eq!(pool.reap_temporary().unwrap(), 0);
        drop(active);
        assert!(!active_path.exists());
    }

    #[test]
    fn operation_layout_holds_lease_before_recovery_can_reap_staging() {
        let dir = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&dir.path().join("images")).unwrap();
        let operation = pool.create_operation().unwrap();
        let temporary = operation.temporary.clone();
        let durable = operation.durable.clone();
        assert_eq!(pool.reap_temporary().unwrap(), 0);
        drop(operation);
        assert_eq!(pool.reap_temporary().unwrap(), 1);
        assert!(!temporary.exists());
        assert!(durable.is_dir());
    }

    #[test]
    fn bounded_scan_discovers_crash_orphans_and_preserves_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("images");
        let pool = StoragePool::open(&root).unwrap();
        run_recovery_probe(&root, "published");
        let unknown = pool.streams.path().join("not-a-stream-id");
        std::fs::write(&unknown, b"not managed stream bytes").unwrap();
        let expected = StreamHasher::new()
            .hash_file(&dir.path().join("orphan-source"))
            .unwrap();
        let mut first = pool.scan_streams().unwrap();
        let mut second = pool.scan_streams().unwrap();
        assert_eq!(
            first.next().unwrap().unwrap(),
            (expected.id(), expected.length())
        );
        assert_eq!(
            second.next().unwrap().unwrap(),
            (expected.id(), expected.length())
        );
        assert!(first.next().is_none());
        assert!(second.next().is_none());
        assert!(unknown.is_file());
        assert!(pool.stream_path(&expected.id()).is_file());
        // Stream discovery never performs deletion; the catalog GC journal and
        // external-dependency preflight decide whether an orphan is collectible.
        assert_eq!(pool.reap_temporary().unwrap(), 0);
    }

    #[test]
    fn readonly_open_and_verification_never_create_missing_pool_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("images");
        assert!(StoragePool::open_existing(&root).unwrap().is_none());
        assert!(!root.exists());
        let source = dir.path().join("input");
        std::fs::write(&source, b"verified retained bytes").unwrap();
        let pool = StoragePool::open(&root).unwrap();
        let published = pool.publish_stream(&source).unwrap();
        let lock_names = || {
            std::fs::read_dir(pool.lock_directory.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>()
        };
        let before = lock_names();
        let readonly = StoragePool::open_existing(&root).unwrap().unwrap();
        assert_eq!(
            readonly.verify_stream(&published.id).unwrap(),
            published.map
        );
        assert_eq!(lock_names(), before);
        drop(readonly);
        std::fs::remove_dir(pool.temporary.path()).unwrap();
        assert!(StoragePool::open_existing(&root).is_err());
        assert!(!pool.temporary.path().exists());
    }

    #[test]
    fn readonly_verification_enforces_immutable_permissions_links_and_exact_identity() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("images");
        let source = dir.path().join("input");
        std::fs::write(&source, b"retained").unwrap();
        let pool = StoragePool::open(&root).unwrap();
        let published = pool.publish_stream(&source).unwrap();
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(pool.verify_stream(&published.id).is_err());
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let alias = dir.path().join("hardlink");
        std::fs::hard_link(&published.path, &alias).unwrap();
        assert!(pool.verify_stream(&published.id).is_err());
        std::fs::remove_file(alias).unwrap();
        assert!(pool.verify_stream(&published.id).is_ok());
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&published.path, b"corrupted").unwrap();
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            pool.verify_stream(&published.id),
            Err(StorageError::ContentMismatch(_))
        ));
        std::fs::remove_file(&published.path).unwrap();
        symlink(&source, &published.path).unwrap();
        assert!(pool.verify_stream(&published.id).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"retained");
    }

    #[test]
    fn abandoned_candidate_lease_spans_preflight_and_drop_defers_removal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("images");
        let pool = StoragePool::open(&root).unwrap();
        run_recovery_probe(&root, "staging");
        let candidate = pool.abandoned_temporary().unwrap().next().unwrap().unwrap();
        let path = candidate.path().to_path_buf();
        assert!(pool.abandoned_temporary().unwrap().next().is_none());
        // A rejected external-resource preflight drops the capability without
        // deleting anything; another recovery attempt can retry it later.
        drop(candidate);
        assert!(path.is_dir());
        let retry = pool.abandoned_temporary().unwrap().next().unwrap().unwrap();
        assert_eq!(retry.path(), path.as_path());
        drop(pool);
        // Owned capabilities cross blocking-task boundaries and do not borrow
        // the pool while asynchronous catalog preflight is in flight.
        std::thread::spawn(move || retry.remove())
            .join()
            .unwrap()
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn refuses_symlinks_and_corruption_and_cleans_failed_staging() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input");
        std::fs::write(&source, b"bytes").unwrap();
        let pool = StoragePool::open(&dir.path().join("images")).unwrap();
        let alias = dir.path().join("alias");
        symlink(&source, &alias).unwrap();
        assert!(pool.publish_stream(&alias).is_err());
        assert!(pool.publish_object(dir.path()).is_err());
        let published = pool.publish_stream(&source).unwrap();
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&published.path, b"wrong").unwrap();
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            pool.publish_stream(&source),
            Err(StorageError::ContentMismatch(_))
        ));
        assert_eq!(
            std::fs::read_dir(dir.path().join("images/tmp"))
                .unwrap()
                .count(),
            0
        );
        std::fs::remove_file(&published.path).unwrap();
        symlink(&source, &published.path).unwrap();
        assert!(pool.publish_stream(&source).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"bytes");
    }

    #[test]
    fn sealed_ram_map_preserves_explicit_zero_and_short_final_chunk() {
        use crate::storage::stream::{Chunk, StreamMap};
        let dir = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&dir.path().join("images")).unwrap();
        let chunk_size = crate::storage::limits::CHUNK_SIZE;
        let mut old = vec![0x61; 2 * chunk_size + 3];
        let old_path = dir.path().join("baseline");
        std::fs::write(&old_path, &old).unwrap();
        let baseline = pool.publish_stream(&old_path).unwrap();
        old[chunk_size..2 * chunk_size].fill(0);
        old[2 * chunk_size..].copy_from_slice(&[0, 0, 7]);
        let candidate = dir.path().join("candidate");
        std::fs::write(&candidate, &old).unwrap();
        let map = StreamMap::new(
            old.len() as u64,
            vec![
                baseline.map.chunks()[0],
                Chunk::Zero,
                Chunk::Data(crate::storage::identity::ObjectDigest::of_bytes(&[0, 0, 7])),
            ],
        )
        .unwrap();
        let (published, roots) = pool
            .publish_sealed_stream_for_catalog(
                &std::fs::File::open(&candidate).unwrap(),
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        drop(roots);
        std::fs::remove_file(&baseline.path).unwrap();
        let id = published.map().id();
        assert_eq!(pool.verify_stream(&id).unwrap(), map);
        assert_eq!(std::fs::read(pool.stream_path(&id)).unwrap(), old);
        assert_eq!(map.chunks()[1], Chunk::Zero);
    }

    #[test]
    fn held_stream_publication_keeps_descriptor_authority_and_admitted_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        std::fs::write(&path, b"original").unwrap();
        let held = std::fs::File::open(&path).unwrap();
        std::fs::rename(&path, dir.path().join("old-source")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        let pool = StoragePool::open(&dir.path().join("images")).unwrap();
        let (published, guard) = pool.publish_stream_file_for_catalog(held, 8).unwrap();
        drop(guard);
        assert_eq!(std::fs::read(&published.path).unwrap(), b"original");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert_eq!(pool.verify_stream(&published.id).unwrap(), published.map);
        assert_eq!(
            published.id,
            StreamHasher::new()
                .hash_reader(b"original".as_slice())
                .unwrap()
                .id(),
        );
        assert!(pool
            .publish_stream_file_for_catalog(std::fs::File::open(&path).unwrap(), 8,)
            .is_err());
        assert_eq!(
            std::fs::read_dir(dir.path().join("images/tmp"))
                .unwrap()
                .count(),
            0,
        );
    }

    #[test]
    fn sealed_ram_publication_rejects_source_length_changes_and_cleans_staging() {
        let temporary = ram_tempdir();
        let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
        let source = temporary.path().join("ram");
        std::fs::write(&source, b"sealed RAM").unwrap();
        let map = StreamHasher::new().hash_file(&source).unwrap();
        let input = File::open(&source).unwrap();
        for bytes in [
            b"short".as_slice(),
            b"sealed RAM plus trailing bytes".as_slice(),
        ] {
            std::fs::write(&source, bytes).unwrap();
            assert!(matches!(
                pool.publish_sealed_stream_for_catalog(
                    &input,
                    &map,
                    None,
                    SealedStreamPublicationMode::CopyAllowed
                ),
                Err(StorageError::ContentMismatch(_))
            ));
            assert!(!pool.stream_path(&map.id()).exists());
            assert_eq!(std::fs::read_dir(pool.temporary.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn sealed_ram_dedup_authenticates_existing_stream_and_binding_rejects_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
        let source = temporary.path().join("ram");
        std::fs::write(&source, b"sealed RAM").unwrap();
        let map = StreamHasher::new()
            .hash_reader(b"sealed RAM".as_slice())
            .unwrap();
        let (proof, roots) = pool
            .publish_sealed_stream_for_catalog(
                &File::open(&source).unwrap(),
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        drop(roots);
        let path = pool.stream_path(&map.id());
        let (reused, roots) = pool
            .publish_sealed_stream_for_catalog(
                &File::open(&source).unwrap(),
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert!(reused.scan_stats().bytes_read >= map.length());
        assert_eq!(
            reused.file.metadata().unwrap().ino(),
            proof.file.metadata().unwrap().ino()
        );
        drop(roots);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"broken RAM").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(proof.recheck(&pool).is_err());
        assert!(
            pool.publish_sealed_stream_for_catalog(
                &File::open(&source).unwrap(),
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed
            )
            .is_err(),
            "a dedup hit must authenticate the preexisting bytes"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"sealed RAM").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            proof.recheck(&pool).is_err(),
            "identical bytes on a new inode are not this proof"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_ram_reflink_publishes_without_reading_ram() {
        let temporary = ram_tempdir();
        let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
        let bytes = vec![0x39; 2 * crate::storage::limits::CHUNK_SIZE + 3];
        let source = temporary.path().join("ram");
        std::fs::write(&source, &bytes).unwrap();
        let input = File::open(&source).unwrap();
        let map = StreamHasher::new().hash_reader(bytes.as_slice()).unwrap();
        let (staging, destination) = pool.stage().unwrap();
        if !reflink_or_skip(&input, &destination) {
            return;
        }
        drop(destination);
        drop(staging);
        let (publication, roots) = pool
            .publish_sealed_stream_for_catalog(
                &input,
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert_eq!(publication.map(), &map);
        assert_eq!(
            publication.scan_stats(),
            crate::storage::stream::StreamStats::default()
        );
        assert_ne!(
            publication.file.metadata().unwrap().ino(),
            input.metadata().unwrap().ino()
        );
        assert_eq!(publication.file.metadata().unwrap().mode() & 0o777, 0o400);
        publication.recheck(&pool).unwrap();
        assert_eq!(std::fs::read(pool.stream_path(&map.id())).unwrap(), bytes);
        drop(roots);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_ram_reflink_retains_producer_identity_until_explicit_authentication() {
        for zero in [false, true] {
            let temporary = ram_tempdir();
            let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
            let source = temporary.path().join("ram");
            let bytes = if zero {
                vec![0; 4096]
            } else {
                vec![0x39; 4096]
            };
            std::fs::write(&source, &bytes).unwrap();
            let map = StreamHasher::new().hash_reader(bytes.as_slice()).unwrap();
            let input = File::open(&source).unwrap();
            let (staging, destination) = pool.stage().unwrap();
            if !reflink_or_skip(&input, &destination) {
                return;
            }
            drop(destination);
            drop(staging);
            File::options()
                .write(true)
                .open(&source)
                .unwrap()
                .write_all_at(&[0xff], map.length() - 1)
                .unwrap();
            let (publication, roots) = pool
                .publish_sealed_stream_for_catalog(
                    &input,
                    &map,
                    None,
                    SealedStreamPublicationMode::CopyAllowed,
                )
                .unwrap();
            assert_eq!(publication.scan_stats().bytes_read, 0);
            publication.recheck(&pool).unwrap();
            drop(roots);
            assert!(matches!(
                pool.authenticate_stream_full(&map.id()),
                Err(StorageError::ContentMismatch(_))
            ));
        }
    }

    #[test]
    fn sealed_ram_copy_fallback_authenticates_and_cleans_staging() {
        let temporary = ram_tempdir();
        let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
        let source = temporary.path().join("ram");
        std::fs::write(&source, b"sealed RAM").unwrap();
        let input = File::open(&source).unwrap();
        let map = StreamHasher::new().hash_file(&source).unwrap();
        let (staging, destination) = pool.stage().unwrap();
        if crate::storage::pool::try_clone_stream(&input, &destination).unwrap() {
            eprintln!(
                "SKIPPED RAM copy fallback test: test tmpdir supports reflinks; \
                 set SILO_TEST_COPY_DIR to an ext4 directory"
            );
            return;
        }
        drop(destination);
        drop(staging);
        let (proof, roots) = pool
            .publish_sealed_stream_for_catalog(
                &input,
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert_eq!(proof.map(), &map);
        assert_eq!(proof.scan_stats().bytes_read, map.length());
        assert_eq!(
            std::fs::read(pool.stream_path(&map.id())).unwrap(),
            b"sealed RAM"
        );
        assert_eq!(proof.file.metadata().unwrap().mode() & 0o777, 0o400);
        proof.recheck(&pool).unwrap();
        drop(roots);
        std::fs::remove_file(pool.stream_path(&map.id())).unwrap();
        std::fs::write(&source, b"broken RAM").unwrap();
        assert!(pool
            .publish_sealed_stream_for_catalog(
                &input,
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed
            )
            .is_err());
        let zero_map =
            StreamMap::new(map.length(), vec![crate::storage::stream::Chunk::Zero]).unwrap();
        assert!(pool
            .publish_sealed_stream_for_catalog(
                &input,
                &zero_map,
                None,
                SealedStreamPublicationMode::CopyAllowed
            )
            .is_err());
        assert_eq!(std::fs::read_dir(pool.temporary.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires SILO_TEST_COPY_DIR and SILO_TEST_COPY_CROSS_DIR on different mounted filesystems"]
    fn sealed_ram_cross_filesystem_uses_copy_fallback() {
        let source_parent =
            std::env::var_os("SILO_TEST_COPY_DIR").expect("explicit source filesystem");
        let destination_parent =
            std::env::var_os("SILO_TEST_COPY_CROSS_DIR").expect("explicit other filesystem");
        let source_dir = tempfile::tempdir_in(source_parent).unwrap();
        let destination_dir = tempfile::tempdir_in(destination_parent).unwrap();
        let pool = StoragePool::open(&destination_dir.path().join("images")).unwrap();
        let source = source_dir.path().join("ram");
        std::fs::write(&source, b"cross-filesystem RAM").unwrap();
        let input = File::open(&source).unwrap();
        let map = StreamHasher::new().hash_file(&source).unwrap();
        let (staging, destination) = pool.stage().unwrap();
        assert_ne!(
            input.metadata().unwrap().dev(),
            destination.metadata().unwrap().dev()
        );
        assert!(!crate::storage::pool::try_clone_stream(&input, &destination).unwrap());
        drop(destination);
        drop(staging);
        let (proof, _roots) = pool
            .publish_sealed_stream_for_catalog(
                &input,
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert_eq!(proof.map(), &map);
        assert_eq!(proof.scan_stats().bytes_read, map.length());
        assert_eq!(
            std::fs::read(pool.stream_path(&map.id())).unwrap(),
            b"cross-filesystem RAM"
        );
        proof.recheck(&pool).unwrap();
        assert_eq!(std::fs::read_dir(pool.temporary.path()).unwrap().count(), 0);
    }

    #[test]
    fn sealed_ram_publication_preserves_empty_stream_identity() {
        let temporary = ram_tempdir();
        let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
        let source = temporary.path().join("ram");
        std::fs::write(&source, []).unwrap();
        let map = StreamMap::new(0, Vec::new()).unwrap();
        let (proof, _roots) = pool
            .publish_sealed_stream_for_catalog(
                &File::open(&source).unwrap(),
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert_eq!(proof.map(), &map);
        assert_eq!(proof.scan_stats().bytes_read, 0);
        assert_eq!(proof.file.metadata().unwrap().len(), 0);
        proof.recheck(&pool).unwrap();
        assert_eq!(std::fs::read_dir(pool.temporary.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_ram_clone_invalid_destination_is_fatal_not_fallback() {
        let temporary = ram_tempdir();
        let source = temporary.path().join("ram");
        let destination = temporary.path().join("readonly");
        std::fs::write(&source, b"sealed RAM").unwrap();
        std::fs::write(&destination, []).unwrap();
        let error = crate::storage::pool::try_clone_stream(
            &File::open(&source).unwrap(),
            &File::open(&destination).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StorageError::Io(error) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        assert_eq!(std::fs::read(&source).unwrap(), b"sealed RAM");
        assert_eq!(std::fs::read(&destination).unwrap(), b"");
    }

    #[test]
    fn sealed_disk_publication_reads_once_for_copy_and_never_for_reflink() {
        let temporary = ram_tempdir();
        let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
        let source = temporary.path().join("sealed-disk.raw");
        let bytes = vec![0x51; 8192];
        std::fs::write(&source, &bytes).unwrap();
        let input = File::open(&source).unwrap();
        let map = StreamHasher::new().hash_reader(bytes.as_slice()).unwrap();
        let (staging, probe) = pool.stage().unwrap();
        let reflink = crate::storage::pool::try_clone_stream(&input, &probe).unwrap();
        drop(probe);
        drop(staging);
        let (publication, roots) = pool
            .publish_sealed_stream_for_catalog(
                &input,
                &map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert_eq!(
            publication.scan_stats().bytes_read,
            if reflink { 0 } else { map.length() }
        );
        publication.recheck(&pool).unwrap();
        drop(roots);
        let fingerprint = publication.fingerprint();
        let (reused, roots) = pool
            .publish_sealed_stream_for_catalog(
                &input,
                &map,
                Some(fingerprint),
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert_eq!(reused.fingerprint(), fingerprint);
        assert_eq!(
            reused.scan_stats(),
            crate::storage::stream::StreamStats::default()
        );
        drop(roots);
        std::fs::set_permissions(
            pool.stream_path(&map.id()),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(pool.stream_path(&map.id()), vec![0x52; bytes.len()]).unwrap();
        std::fs::set_permissions(
            pool.stream_path(&map.id()),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        assert!(pool
            .publish_sealed_stream_for_catalog(
                &input,
                &map,
                Some(fingerprint),
                SealedStreamPublicationMode::CopyAllowed
            )
            .is_err());
        let next_source = temporary.path().join("distinct-sealed-disk.raw");
        let next_bytes = vec![0x53; bytes.len()];
        std::fs::write(&next_source, &next_bytes).unwrap();
        let next_map = StreamHasher::new()
            .hash_reader(next_bytes.as_slice())
            .unwrap();
        assert_ne!(next_map.id(), map.id());
        let (distinct, roots) = pool
            .publish_sealed_stream_for_catalog(
                &File::open(next_source).unwrap(),
                &next_map,
                None,
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert_eq!(
            distinct.scan_stats().bytes_read,
            if reflink { 0 } else { next_map.length() }
        );
        distinct.recheck(&pool).unwrap();
        drop(roots);
    }

    #[test]
    fn produced_object_fingerprint_binds_post_rename_and_authenticated_dedup() {
        use crate::storage::identity_file::SourceFingerprint;
        use std::io::Write;
        let temporary = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
        let bytes = b"owned fsmeta producer";
        let (produced, roots, ()) = pool
            .publish_produced_object_for_catalog::<_, StorageError>(|file| {
                file.write_all(bytes)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            produced.fingerprint,
            SourceFingerprint::new(
                &pool
                    .open_object(&produced.digest)
                    .unwrap()
                    .metadata()
                    .unwrap(),
            )
        );
        drop(roots);
        let source = temporary.path().join("fsmeta");
        std::fs::write(&source, bytes).unwrap();
        let (dedup, roots) = pool.publish_object_for_catalog(&source).unwrap();
        assert_eq!(dedup.fingerprint, produced.fingerprint);
        drop(roots);
        std::fs::remove_file(&dedup.path).unwrap();
        std::fs::write(&dedup.path, bytes).unwrap();
        std::fs::set_permissions(&dedup.path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_ne!(
            dedup.fingerprint,
            SourceFingerprint::new(&pool.open_object(&dedup.digest).unwrap().metadata().unwrap(),)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_reflink_emits_access_without_a_payload_scan() {
        use crate::store::snapshot_store::tests::{observed_stream_read, watch_stream_reads};
        let temporary = ram_tempdir();
        let path = temporary.path().join("clone-source");
        std::fs::write(&path, [0x39; 4096]).unwrap();
        let source = File::open(&path).unwrap();
        let destination = tempfile::tempfile_in(temporary.path()).unwrap();
        let watcher = watch_stream_reads(&path);
        if !reflink_or_skip(&source, &destination) {
            return;
        }
        assert!(
            observed_stream_read(&watcher),
            "FICLONE emits IN_ACCESS for {} even without read/pread",
            path.display()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_stream_receipt_hit_skips_staging_clone_and_payload_access() {
        use crate::storage::identity_file::SourceFingerprint;
        use crate::store::snapshot_store::tests::{observed_stream_read, watch_stream_reads};
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("source");
        std::fs::write(&input, [0x73; 4096]).unwrap();
        let pool = StoragePool::open(&temporary.path().join("images"))
            .unwrap()
            .defer_publications();
        let (published, roots) = pool.publish_stream_for_catalog(&input).unwrap();
        drop(roots);
        pool.sync_publications().unwrap();
        let source = File::open(&input).unwrap();
        let held = pool.open_stream(&published.id).unwrap();
        let fingerprint = SourceFingerprint::new(&held.metadata().unwrap());
        let staging = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap();
        staging
            .add_watch(pool.temporary.path(), AddWatchFlags::IN_CREATE)
            .unwrap();
        let input_reads = watch_stream_reads(&input);
        let retained_reads = watch_stream_reads(&published.path);
        let (reused, roots) = pool
            .publish_sealed_stream_for_catalog(
                &source,
                &published.map,
                Some(fingerprint),
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert_eq!(reused.fingerprint(), fingerprint);
        assert_eq!(
            reused.scan_stats(),
            crate::storage::stream::StreamStats::default()
        );
        assert!(!observed_stream_read(&input_reads));
        assert!(!observed_stream_read(&retained_reads));
        assert_eq!(
            staging.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN
        );
        drop(roots);
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let (authenticated, roots) = pool
            .publish_sealed_stream_for_catalog(
                &source,
                &published.map,
                Some(fingerprint),
                SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        assert!(authenticated.scan_stats().bytes_read > 0);
        assert!(observed_stream_read(&retained_reads));
        assert!(!observed_stream_read(&input_reads));
        assert_eq!(
            staging.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN
        );
        drop(roots);
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&published.path, [0x74; 4096]).unwrap();
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(pool
            .publish_sealed_stream_for_catalog(
                &source,
                &published.map,
                Some(fingerprint),
                SealedStreamPublicationMode::CopyAllowed
            )
            .is_err());
    }

    #[test]
    fn clone_qualified_publication_never_falls_back_to_an_unadmitted_copy() {
        let temporary = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&temporary.path().join("pool")).unwrap();
        let path = temporary.path().join("sealed.raw");
        let bytes = vec![0x53; 4096];
        std::fs::write(&path, &bytes).unwrap();
        let source = std::fs::File::open(&path).unwrap();
        let map = crate::storage::stream::StreamHasher::new()
            .hash_reader(bytes.as_slice())
            .unwrap();
        let probe = tempfile::tempfile_in(pool.temporary.path()).unwrap();
        let qualified = crate::storage::pool::try_clone_stream(&source, &probe).unwrap();
        let result = pool.publish_sealed_stream_for_catalog(
            &source,
            &map,
            None,
            SealedStreamPublicationMode::CloneRequired,
        );
        if qualified {
            let (publication, _roots) = result.unwrap();
            assert_eq!(publication.scan_stats().bytes_read, 0);
            publication.recheck(&pool).unwrap();
        } else {
            assert!(
                matches!(result, Err(crate::storage::StorageError::Io(error)) if error.kind() == std::io::ErrorKind::Unsupported)
            );
            assert!(!pool.stream_path(&map.id()).exists());
            let (publication, _roots) = pool
                .publish_sealed_stream_for_catalog(
                    &source,
                    &map,
                    None,
                    SealedStreamPublicationMode::CopyAllowed,
                )
                .unwrap();
            assert_eq!(publication.map(), &map);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capture_clone_qualification_does_not_touch_payloads_or_create_durable_staging() {
        use crate::store::snapshot_store::tests::{observed_stream_read, watch_stream_reads};
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        let temporary = ram_tempdir();
        let source =
            crate::paths::OwnedDirectory::open_root(&temporary.path().join("capture")).unwrap();
        source.write_file("memory.ram", &[0x71; 4096]).unwrap();
        let pool = StoragePool::open(&temporary.path().join("images")).unwrap();
        let payload = watch_stream_reads(&source.path().join("memory.ram"));
        let stages = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap();
        stages
            .add_watch(pool.temporary.path(), AddWatchFlags::IN_CREATE)
            .unwrap();
        stages
            .add_watch(pool.publication.path(), AddWatchFlags::IN_CREATE)
            .unwrap();
        let _supported = pool.qualify_capture_clone(&source).unwrap_or(false);
        assert!(!observed_stream_read(&payload));
        // Anonymous O_TMPFILE events, if exposed by the filesystem, are not
        // named stage directories or stable publication lock files.
        match stages.read_events() {
            Ok(events) => assert!(events.iter().all(|event| {
                event
                    .name
                    .as_ref()
                    .is_none_or(|name| !name.as_encoded_bytes().starts_with(b"stage-"))
            })),
            Err(error) => assert_eq!(error, nix::errno::Errno::EAGAIN),
        }
        assert!(std::fs::read_dir(pool.temporary.path())
            .unwrap()
            .next()
            .is_none());
        assert!(std::fs::read_dir(pool.publication.path())
            .unwrap()
            .next()
            .is_none());
    }
}
