use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use nix::fcntl::{fcntl, openat, AtFlags, FcntlArg, OFlag};
use nix::sys::stat::{fchmod, fstatat, Mode};
use nix::unistd::{geteuid, unlinkat, UnlinkatFlags};

use crate::paths::OwnedDirectory;
use crate::storage::identity::StreamId;
use crate::storage::identity_file::{FileIdentity, SourceFingerprint};
use crate::storage::stream::{AuthenticatedStream, StreamHasher, StreamScan, StreamStats};
use crate::storage::StorageError;

use thiserror::Error;
use utils::format_storage_size;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloneDiskMethod {
    #[cfg(target_os = "macos")]
    Clonefile,
    #[cfg(target_os = "linux")]
    Reflink,
    SparseCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootDiskResizeOutcome {
    OfflineComplete,
    GuestRequired,
}

#[derive(Debug, Error)]
pub(crate) enum RootDiskError {
    #[error(
        "refusing to shrink raw disk {path} from {} to {}",
        format_storage_size(*current_size),
        format_storage_size(*requested_size)
    )]
    RawDiskShrinkUnsupported {
        path: PathBuf,
        current_size: u64,
        requested_size: u64,
    },

    #[error("failed to grow ext4 filesystem in {path}")]
    Ext4 {
        path: PathBuf,
        #[source]
        source: disk_image::ext4::ResizeError,
    },

    #[error("failed to inspect ext4 filesystem in {path}")]
    Ext4Probe {
        path: PathBuf,
        #[source]
        source: disk_image::ext4::ReadError,
    },

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Qualification belongs to one retained operation, never a process-wide cache.
/// A pinned directory identity bounds reuse more narrowly than a device number.
pub(crate) struct CopyQualification {
    directories: Vec<QualifiedDirectory>,
    max_filesystems: usize,
}

struct QualifiedDirectory {
    _directory: OwnedDirectory,
    identity: FileIdentity,
    clone_supported: bool,
}

impl CopyQualification {
    pub(crate) fn new(max_filesystems: usize) -> Self {
        Self {
            directories: Vec::new(),
            max_filesystems,
        }
    }

    fn qualify(&mut self, directory: &OwnedDirectory) -> Result<bool, RootDiskError> {
        let metadata = File::from(directory.fd().try_clone()?).metadata()?;
        let identity = FileIdentity::from_metadata(&metadata);
        if let Some(qualified) = self
            .directories
            .iter()
            .find(|entry| entry.identity == identity)
        {
            return Ok(qualified.clone_supported);
        }
        if self.directories.len() >= self.max_filesystems {
            return Err(invalid_copy("operation copy qualification bound exceeded"));
        }
        let clone_supported = qualify_clone(directory)?;
        self.directories.push(QualifiedDirectory {
            _directory: directory.try_clone().map_err(owned_error)?,
            identity,
            clone_supported,
        });
        Ok(clone_supported)
    }
}

/// The content authority a private copy starts from. Both variants name an
/// exact held inode; only the authenticated one carries a canonical map.
#[derive(Clone, Copy)]
pub(crate) enum CopySource<'a> {
    /// Held under the caller's fences without content authority. A streaming
    /// copy derives the source map while copying, then verifies the output.
    Unscanned { file: &'a File, length: u64 },
    /// Byte-authenticated against its map. A streaming copy reuses that map
    /// and still independently scans and compares the completed output.
    Authenticated(&'a AuthenticatedStream),
}

impl<'a> CopySource<'a> {
    fn file(self) -> &'a File {
        match self {
            Self::Unscanned { file, .. } => file,
            Self::Authenticated(stream) => stream.file(),
        }
    }

    fn length(self) -> u64 {
        match self {
            Self::Unscanned { length, .. } => length,
            Self::Authenticated(stream) => stream.length(),
        }
    }
}

/// Work a streaming copy actually executed. Clones carry none: they rely on
/// the qualified kernel clone contract instead of an output scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CopyVerification {
    /// Canonical identity of the independently scanned completed output.
    pub(crate) stream: StreamId,
    /// Source traversal. `logical_bytes_hashed` is zero when an authenticated
    /// source map was reused instead of recomputed.
    pub(crate) source: StreamStats,
    /// Independent completed-output scan, never skipped.
    pub(crate) output: StreamStats,
}

impl CopyVerification {
    fn scanned(scan: StreamScan) -> Result<Self, RootDiskError> {
        Ok(Self {
            stream: scan.map.id(),
            source: scan.stats,
            output: scan
                .verification_stats
                .ok_or_else(|| invalid_copy("streaming copy omitted output verification"))?,
        })
    }
}

/// The file and its pinned parent travel with the actual blocking owner.
/// Drop only removes a still-owned private entry, never an existing collision.
pub(crate) struct PreparedPrivateCopy {
    file: File,
    directory: OwnedDirectory,
    name: String,
    method: CloneDiskMethod,
    verification: Option<CopyVerification>,
    preserve: bool,
}

impl PreparedPrivateCopy {
    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.directory.path().join(&self.name)
    }

    pub(crate) fn method(&self) -> CloneDiskMethod {
        self.method
    }

    pub(crate) fn verification(&self) -> Option<&CopyVerification> {
        self.verification.as_ref()
    }

    /// Once rename succeeds, a directory-sync error is an uncertain publication.
    /// Keep the complete candidate until catalog reconciliation authorizes removal.
    pub(crate) fn publish(
        &mut self,
        destination: OwnedDirectory,
        name: &str,
    ) -> Result<(), RootDiskError> {
        validate_component(name)?;
        validate_owned_entry(&self.directory, &self.name, &self.file)?;
        crate::storage::pool::rename_component_no_replace(
            &self.directory,
            &self.name,
            &destination,
            name,
        )?;
        let previous = std::mem::replace(&mut self.directory, destination);
        self.name = name.to_owned();
        self.preserve = true;
        self.directory.sync().map_err(owned_error)?;
        previous.sync().map_err(owned_error)?;
        Ok(())
    }

    pub(crate) fn begin_publication(&mut self) {
        self.preserve = true;
    }

    pub(crate) fn retain(mut self) {
        self.preserve = true;
    }

    /// Requires proof that the candidate has not become a catalog root.
    pub(crate) fn discard_unpublished(mut self) {
        self.preserve = false;
    }

    fn remove(&mut self) -> Result<(), RootDiskError> {
        validate_owned_entry(&self.directory, &self.name, &self.file)?;
        unlinkat(
            self.directory.fd(),
            self.name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(io::Error::from)?;
        self.preserve = true;
        self.directory.sync().map_err(owned_error)?;
        Ok(())
    }
}

impl Drop for PreparedPrivateCopy {
    fn drop(&mut self) {
        if !self.preserve {
            if let Err(error) = self.remove() {
                tracing::warn!(path = %self.path().display(), %error, "remove owned private copy");
            }
        }
    }
}

/// Copies exactly the admitted length from the held source, without reopening
/// its pathname. Callers own source synchronization, quiescence and profile.
/// No worker is spawned here: callers move all operation fences into the worker.
///
/// Streaming copies always scan the completed output and compare its complete
/// map with the source map. An authenticated source contributes its existing
/// map; it never waives the output scan, ownership, length, stability or sync.
pub(crate) fn copy_private(
    source: CopySource<'_>,
    staging: OwnedDirectory,
    name: &str,
    qualification: &mut CopyQualification,
) -> Result<PreparedPrivateCopy, RootDiskError> {
    validate_component(name)?;
    let file = source.file();
    let length = source.length();
    let before = validate_source(file, length)?;
    if let CopySource::Authenticated(stream) = source {
        if before != stream.fingerprint() {
            return Err(invalid_copy(
                "authenticated copy source changed after authentication",
            ));
        }
    }
    validate_staging(&staging)?;
    let source_device = file.metadata()?.dev();
    let destination_device = File::from(staging.fd().try_clone()?).metadata()?.dev();
    // A destination-local probe cannot qualify a cross-filesystem source.
    let clone_supported = source_device == destination_device && qualification.qualify(&staging)?;
    let mut prepared = if clone_supported {
        match clone_attempt(file, &staging, name)? {
            CloneAttempt::Complete(prepared) => prepared,
            CloneAttempt::Unsupported => new_private_file(staging, name)?,
        }
    } else {
        new_private_file(staging, name)?
    };
    if prepared.method == CloneDiskMethod::SparseCopy {
        let mut hasher = StreamHasher::new();
        prepared.verification = Some(match source {
            CopySource::Unscanned { file, length } => CopyVerification::scanned(
                hasher.copy_file_and_hash(file, length, &prepared.file)?,
            )?,
            CopySource::Authenticated(stream) => {
                let copy = hasher.copy_authenticated(stream, &prepared.file)?;
                CopyVerification {
                    stream: stream.map().id(),
                    source: copy.stats,
                    output: copy.verification_stats,
                }
            }
        });
    }
    validate_destination(file, &prepared.file, length)?;
    validate_owned_entry(&prepared.directory, &prepared.name, &prepared.file)?;
    prepared.file.sync_all()?;
    if before != SourceFingerprint::new(&file.metadata()?) {
        return Err(invalid_copy("source changed during private copy"));
    }
    Ok(prepared)
}

fn invalid_copy(message: &'static str) -> RootDiskError {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

fn owned_error(error: crate::LibVmError) -> io::Error {
    io::Error::other(error)
}

fn validate_component(name: &str) -> Result<(), RootDiskError> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || name.as_bytes().contains(&0)
        || name.as_bytes().contains(&b'/')
    {
        return Err(invalid_copy(
            "copy destination is not one fresh path component",
        ));
    }
    Ok(())
}

fn validate_staging(directory: &OwnedDirectory) -> Result<(), RootDiskError> {
    let metadata = File::from(directory.fd().try_clone()?).metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(invalid_copy(
            "copy staging directory is not private and owned",
        ));
    }
    Ok(())
}

fn validate_source(source: &File, length: u64) -> Result<SourceFingerprint, RootDiskError> {
    let metadata = source.metadata()?;
    let flags =
        OFlag::from_bits_truncate(fcntl(source, FcntlArg::F_GETFL).map_err(io::Error::from)?);
    if !metadata.is_file()
        || metadata.len() != length
        || metadata.nlink() != 1
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7022 != 0
        || metadata.mode() & 0o400 == 0
        || flags.contains(OFlag::O_WRONLY)
        || flags.contains(OFlag::O_APPEND)
    {
        return Err(invalid_copy(
            "copy source has invalid type, access, owner, mode, links or fixed length",
        ));
    }
    Ok(SourceFingerprint::new(&metadata))
}

fn validate_destination(
    source: &File,
    destination: &File,
    length: u64,
) -> Result<(), RootDiskError> {
    let metadata = destination.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() != length
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || FileIdentity::from_metadata(&source.metadata()?)
            == FileIdentity::from_metadata(&metadata)
    {
        return Err(invalid_copy(
            "clone produced invalid private destination metadata",
        ));
    }
    Ok(())
}

#[allow(clippy::unnecessary_cast)]
fn validate_owned_entry(
    directory: &OwnedDirectory,
    name: &str,
    file: &File,
) -> Result<(), RootDiskError> {
    let entry =
        fstatat(directory.fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    let metadata = file.metadata()?;
    if entry.st_dev as u64 != metadata.dev()
        || entry.st_ino as u64 != metadata.ino()
        || metadata.nlink() != 1
    {
        return Err(invalid_copy("owned copy entry was replaced or linked"));
    }
    Ok(())
}

fn new_private_file(
    directory: OwnedDirectory,
    name: &str,
) -> Result<PreparedPrivateCopy, RootDiskError> {
    let file = File::from(
        openat(
            directory.fd(),
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map_err(io::Error::from)?,
    );
    let prepared = PreparedPrivateCopy {
        file,
        directory,
        name: name.to_owned(),
        method: CloneDiskMethod::SparseCopy,
        verification: None,
        preserve: false,
    };
    fchmod(&prepared.file, Mode::S_IRUSR | Mode::S_IWUSR).map_err(io::Error::from)?;
    Ok(prepared)
}

enum CloneAttempt {
    Complete(PreparedPrivateCopy),
    Unsupported,
}

fn clone_error_allows_fallback(error: &io::Error, valid_whole_file: bool) -> bool {
    let Some(errno) = error.raw_os_error() else {
        return false;
    };
    if errno == libc::EOPNOTSUPP || errno == libc::ENOTSUP || errno == libc::EXDEV {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        errno == libc::ENOTTY || (errno == libc::EINVAL && valid_whole_file)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = valid_whole_file;
        errno == libc::ENOSYS
    }
}

#[cfg(target_os = "linux")]
fn clone_attempt(
    source: &File,
    directory: &OwnedDirectory,
    name: &str,
) -> Result<CloneAttempt, RootDiskError> {
    let mut prepared = new_private_file(directory.try_clone().map_err(owned_error)?, name)?;
    // All overloaded EINVAL preconditions are checked before the whole-file ioctl:
    // readable regular source, writable empty distinct regular destination, no
    // append mode, no offsets/range flags and same mounted-filesystem candidate.
    validate_source(source, source.metadata()?.len())?;
    validate_destination(source, &prepared.file, 0)?;
    match try_reflink(source, &prepared.file) {
        Ok(()) => {
            prepared.method = CloneDiskMethod::Reflink;
            Ok(CloneAttempt::Complete(prepared))
        }
        Err(error) if clone_error_allows_fallback(&error, true) => {
            // Never stream into a potentially partially cloned file.
            prepared.remove()?;
            Ok(CloneAttempt::Unsupported)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "macos")]
fn clone_attempt(
    source: &File,
    directory: &OwnedDirectory,
    name: &str,
) -> Result<CloneAttempt, RootDiskError> {
    match try_clonefile(source, directory, name) {
        Ok(()) => {
            let file = File::from(
                openat(
                    directory.fd(),
                    name,
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                    Mode::empty(),
                )
                .map_err(io::Error::from)?,
            );
            let mut prepared = PreparedPrivateCopy {
                file,
                directory: directory.try_clone().map_err(owned_error)?,
                name: name.to_owned(),
                method: CloneDiskMethod::Clonefile,
                verification: None,
                preserve: false,
            };
            let metadata = prepared.file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || FileIdentity::from_metadata(&metadata)
                    == FileIdentity::from_metadata(&source.metadata()?)
            {
                // Do not chmod a corrupt clone which aliases the source.
                prepared.preserve = true;
                return Err(invalid_copy("clone violated private inode isolation"));
            }
            fchmod(&prepared.file, Mode::S_IRUSR | Mode::S_IWUSR).map_err(io::Error::from)?;
            // An immutable 0400 source produces an initially read-only clone.
            // Make only the checked destination writable, then reopen its FD.
            let writable = File::from(
                openat(
                    directory.fd(),
                    name,
                    OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                    Mode::empty(),
                )
                .map_err(io::Error::from)?,
            );
            if FileIdentity::from_metadata(&writable.metadata()?)
                != FileIdentity::from_metadata(&metadata)
            {
                return Err(invalid_copy(
                    "clone destination changed while reopening writable",
                ));
            }
            prepared.file = writable;
            Ok(CloneAttempt::Complete(prepared))
        }
        Err(error) if clone_error_allows_fallback(&error, false) => {
            // fclonefileat atomically creates an absent destination. If a failed
            // call left an entry, stop instead of guessing that it is disposable.
            match fstatat(directory.fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
                Err(nix::errno::Errno::ENOENT) => Ok(CloneAttempt::Unsupported),
                Ok(_) => Err(invalid_copy("failed clone left an unexpected destination")),
                Err(error) => Err(io::Error::from(error).into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn qualify_clone(directory: &OwnedDirectory) -> Result<bool, RootDiskError> {
    // Bounded real files: data at prefix/middle/tail, holes, allocated zeros and
    // a distinct all-zero/trailing-hole fixture. No whole-disk qualification scan.
    let length = 128 * 1024 + 17;
    let mut expected = Vec::new();
    let mut actual = Vec::new();
    for all_zero in [false, true] {
        let source_name = format!("copy-probe-source-{}", uuid::Uuid::new_v4());
        let destination_name = format!("copy-probe-child-{}", uuid::Uuid::new_v4());
        let mut source =
            new_private_file(directory.try_clone().map_err(owned_error)?, &source_name)?;
        source.file.set_len(length)?;
        source.file.write_all_at(&[0; 4096], 16 * 1024)?;
        if !all_zero {
            source.file.write_all_at(b"prefix", 0)?;
            source.file.write_all_at(b"middle", 64 * 1024 + 3)?;
            source.file.write_all_at(b"tail", length - 4)?;
        }
        source.file.sync_all()?;
        let mut child = match clone_attempt(&source.file, directory, &destination_name)? {
            CloneAttempt::Complete(child) => child,
            CloneAttempt::Unsupported => {
                source.remove()?;
                return Ok(false);
            }
        };
        validate_destination(&source.file, &child.file, length)?;
        expected.resize(length as usize, 0);
        actual.resize(length as usize, 0);
        source.file.read_exact_at(&mut expected, 0)?;
        verify_probe_reopened(&mut child, &expected, &mut actual)?;
        source.file.write_all_at(b"parent mutation", 4096)?;
        source.file.sync_all()?;
        verify_probe_reopened(&mut child, &expected, &mut actual)?;
        child.file.write_all_at(b"child mutation", 8192)?;
        child.file.sync_all()?;
        expected[4096..4096 + 15].copy_from_slice(b"parent mutation");
        verify_probe_reopened(&mut source, &expected, &mut actual)?;
        expected[4096..4096 + 15].fill(0);
        expected[8192..8192 + 14].copy_from_slice(b"child mutation");
        verify_probe_reopened(&mut child, &expected, &mut actual)?;
        child.remove()?;
        source.remove()?;
    }
    Ok(true)
}

fn verify_probe_reopened(
    copy: &mut PreparedPrivateCopy,
    expected: &[u8],
    actual: &mut [u8],
) -> Result<(), RootDiskError> {
    // Reopen relative to the pinned directory rather than trusting display paths.
    let file = File::from(
        openat(
            copy.directory.fd(),
            copy.name.as_str(),
            OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    if FileIdentity::from_metadata(&file.metadata()?)
        != FileIdentity::from_metadata(&copy.file.metadata()?)
        || file.metadata()?.len() != expected.len() as u64
    {
        return Err(invalid_copy(
            "clone qualification reopen identity or length mismatch",
        ));
    }
    file.read_exact_at(actual, 0)?;
    if &*actual != expected {
        return Err(invalid_copy(
            "clone qualification data or bidirectional isolation failure",
        ));
    }
    // Close the old file description; subsequent mutations use the reopened FD.
    copy.file = file;
    Ok(())
}

pub(crate) fn resize_raw_disk(
    path: &Path,
    size_bytes: u64,
) -> Result<RootDiskResizeOutcome, RootDiskError> {
    let file = File::options().read(true).write(true).open(path)?;
    let current_size = file.metadata()?.len();
    if size_bytes < current_size {
        return Err(RootDiskError::RawDiskShrinkUnsupported {
            path: path.to_path_buf(),
            current_size,
            requested_size: size_bytes,
        });
    }

    let is_ext4 = match disk_image::ext4::probe(path) {
        Ok(disk_image::ext4::ProbeResult::Ext4) => true,
        Ok(disk_image::ext4::ProbeResult::NotExt4) => false,
        Err(source) => {
            return Err(RootDiskError::Ext4Probe {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    drop(file);

    let outcome = if is_ext4 {
        let filesystem_size = size_bytes - size_bytes % 4096;
        match disk_image::ext4::grow_image(path, filesystem_size) {
            Ok(_) => RootDiskResizeOutcome::OfflineComplete,
            Err(err) if err.can_fallback_online() => RootDiskResizeOutcome::GuestRequired,
            Err(source) => {
                return Err(RootDiskError::Ext4 {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    } else {
        RootDiskResizeOutcome::GuestRequired
    };

    let file = File::options().write(true).open(path)?;
    file.set_len(size_bytes)?;
    file.sync_all()?;
    Ok(outcome)
}

/// Owns a complete private upper generation. Before catalog publication Drop
/// removes it; after publication starts an uncertain outcome must retain it.
pub(crate) struct UpperReplacement {
    path: PathBuf,
    copy: PreparedPrivateCopy,
    previous: File,
    previous_directory: OwnedDirectory,
    previous_name: String,
}

impl UpperReplacement {
    pub(crate) fn prepare(
        source: &Path,
        destination: &Path,
        capacity: u64,
    ) -> Result<Self, crate::LibVmError> {
        rootfs_spec::upper_geometry::UpperCapacity::new(capacity)
            .map_err(|error| crate::machine::root_storage::invalid(error.to_string()))?;
        let source_file = crate::storage::stream::open_regular_source(source)?;
        let metadata = source_file.metadata()?;
        let length = metadata.len();
        validate_source(&source_file, length)?;
        if metadata.mode() & 0o7777 != 0o600 {
            return Err(crate::machine::root_storage::invalid(
                "replacement source is not private",
            ));
        }
        if capacity <= length {
            return Err(crate::machine::root_storage::invalid(
                "replacement upper growth must increase capacity",
            ));
        }
        let (previous_directory, previous_name) = existing_parent(source)?;
        validate_owned_entry(&previous_directory, &previous_name, &source_file)?;
        let (destination_directory, destination_name) = existing_parent(destination)?;
        let staging_name = format!("copy-upper-{}", uuid::Uuid::new_v4());
        let staging = destination_directory
            .create_dir(&staging_name)?
            .ok_or_else(|| crate::machine::root_storage::invalid("upper staging collision"))?;
        let result = (|| {
            source_file.sync_all()?;
            let mut copy = copy_private(
                CopySource::Unscanned {
                    file: &source_file,
                    length,
                },
                staging,
                "content",
                &mut CopyQualification::new(1),
            )?;
            // Preserve the old prefix, dirty journal and UUID. Only length changes;
            // init replays and grows the filesystem independently at the next boot.
            copy.file().set_len(capacity)?;
            copy.file().sync_all()?;
            copy.publish(destination_directory.try_clone()?, &destination_name)?;
            // Rename and directory sync completed; SQL publication has not begun.
            copy.preserve = false;
            Ok::<_, crate::LibVmError>(copy)
        })();
        destination_directory.remove_tree(&staging_name)?;
        destination_directory.sync()?;
        let copy = result?;
        Ok(Self {
            path: copy.path(),
            copy,
            previous: source_file,
            previous_directory,
            previous_name,
        })
    }

    pub(crate) fn begin_publication(&mut self) {
        // SQLx can finish COMMIT after cancellation. Preserve both generations.
        self.copy.begin_publication();
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Caller proved this generation unreferenced after a completed transaction.
    pub(crate) fn discard_unpublished(self) {
        self.copy.discard_unpublished();
    }

    pub(crate) fn commit(mut self) {
        self.copy.begin_publication();
        let result = (|| {
            validate_owned_entry(
                &self.previous_directory,
                &self.previous_name,
                &self.previous,
            )?;
            unlinkat(
                self.previous_directory.fd(),
                self.previous_name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            )
            .map_err(io::Error::from)?;
            self.previous_directory.sync().map_err(owned_error)?;
            Ok::<_, RootDiskError>(())
        })();
        if let Err(error) = result {
            tracing::warn!(path = %self.previous_directory.path().join(&self.previous_name).display(), %error, "remove replaced private upper");
        }
    }
}

fn existing_parent(path: &Path) -> Result<(OwnedDirectory, String), crate::LibVmError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            crate::machine::root_storage::invalid("private file has no UTF-8 component")
        })?;
    validate_component(name)?;
    let directory = OwnedDirectory::open_existing_root(parent)?
        .ok_or_else(|| crate::machine::root_storage::invalid("private file parent is absent"))?;
    Ok((directory, name.to_owned()))
}

#[cfg(target_os = "macos")]
fn try_clonefile(source: &File, destination: &OwnedDirectory, name: &str) -> io::Result<()> {
    use nix::NixPath;
    use std::os::fd::AsRawFd;

    // nix does not expose fclonefileat; unlike clonefile this consumes the held
    // source FD, so no second source pathname resolution can race admission.
    let rc = name
        .with_nix_path(|name| unsafe {
            libc::fclonefileat(
                source.as_raw_fd(),
                destination.fd().as_raw_fd(),
                name.as_ptr(),
                0,
            )
        })
        .map_err(io::Error::from)?;
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn try_reflink(source: &File, destination: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    const FICLONE: libc::c_ulong = 0x4004_9409;

    // nix does not expose a safe wrapper for the Linux FICLONE ioctl.
    // SAFETY: ioctl only reads the source file descriptor value and applies it
    // to the destination fd for the duration of this call.
    let rc = unsafe { libc::ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{symlink, FileExt, MetadataExt, PermissionsExt};
    use std::path::Path;

    use crate::machine::root_disk::{
        clone_error_allows_fallback, copy_private, resize_raw_disk, CloneDiskMethod,
        CopyQualification, CopySource, RootDiskError, RootDiskResizeOutcome,
    };
    use crate::paths::OwnedDirectory;

    fn copy_tempdir() -> tempfile::TempDir {
        match std::env::var_os("SILO_TEST_COPY_DIR") {
            Some(path) => tempfile::tempdir_in(path).unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }

    fn copy_to_path(source: &Path, destination: &Path) -> Result<CloneDiskMethod, RootDiskError> {
        let input = crate::storage::stream::open_regular_source(source)?;
        let length = input.metadata()?.len();
        input.sync_all()?;
        let parent = OwnedDirectory::open_root(destination.parent().unwrap())
            .map_err(std::io::Error::other)?;
        let stage_name = format!("test-copy-{}", uuid::Uuid::new_v4());
        let stage = parent
            .create_dir(&stage_name)
            .map_err(std::io::Error::other)?
            .unwrap();
        let result = (|| {
            let mut copy = copy_private(
                CopySource::Unscanned {
                    file: &input,
                    length,
                },
                stage,
                "content",
                &mut CopyQualification::new(1),
            )?;
            let method = copy.method();
            copy.publish(
                parent.try_clone().map_err(std::io::Error::other)?,
                destination.file_name().unwrap().to_str().unwrap(),
            )?;
            copy.retain();
            Ok(method)
        })();
        parent
            .remove_tree(&stage_name)
            .map_err(std::io::Error::other)?;
        parent.sync().map_err(std::io::Error::other)?;
        result
    }

    #[test]
    fn private_copy_copies_contents() {
        let temp = copy_tempdir();
        let source = temp.path().join("base.ext4");
        let destination = temp.path().join("instance/root.raw");
        fs::write(&source, b"disk").expect("write source");

        copy_to_path(&source, &destination).expect("clone or copy root disk");

        assert_eq!(fs::read(destination).expect("read destination"), b"disk");
    }

    #[test]
    fn immutable_source_becomes_a_private_writable_root_without_changing_source_mode() {
        let temp = copy_tempdir();
        let source = temp.path().join("immutable-stream");
        let destination = temp.path().join("machine/root.raw");
        fs::write(&source, [0x64; 512]).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o400)).unwrap();
        copy_to_path(&source, &destination).unwrap();
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        resize_raw_disk(&destination, 1024).unwrap();
        assert_eq!(fs::metadata(&destination).unwrap().len(), 1024);
        assert_eq!(fs::metadata(&source).unwrap().len(), 512);
    }

    #[test]
    fn private_copy_rejects_missing_source() {
        let temp = copy_tempdir();
        assert!(copy_to_path(
            &temp.path().join("missing.raw"),
            &temp.path().join("root.raw"),
        )
        .is_err());
    }

    #[test]
    fn resize_raw_disk_grows_sparse_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        disk_image::ext4::Formatter::new(&path, 4096, 256 * 1024)
            .expect("create ext4 image")
            .close()
            .expect("finish ext4 image");
        let old_size = fs::metadata(&path).expect("metadata").len();
        let new_size = old_size + 128 * 1024 * 1024;

        let outcome = resize_raw_disk(&path, new_size).expect("resize disk");

        assert_eq!(outcome, RootDiskResizeOutcome::OfflineComplete);
        assert_eq!(fs::metadata(&path).expect("metadata").len(), new_size);
        let reader = disk_image::ext4::Reader::new(&path).expect("open grown ext4 image");
        assert_eq!(reader.superblock().blocks_count_lo as u64 * 4096, new_size);
    }

    #[test]
    fn resize_raw_disk_refuses_shrink() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        fs::write(&path, b"disk").expect("write disk");

        let err = resize_raw_disk(&path, 1).expect_err("shrink should fail");

        assert!(matches!(
            err,
            RootDiskError::RawDiskShrinkUnsupported { .. }
        ));
    }

    #[test]
    fn resize_raw_disk_does_not_extend_ext4_after_fatal_validation_error() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        disk_image::ext4::Formatter::new(&path, 4096, 256 * 1024)
            .expect("create ext4 image")
            .close()
            .expect("finish ext4 image");
        let old_size = fs::metadata(&path).expect("metadata").len();
        let too_large = (u32::MAX as u64 + 1) * 4096;

        let error = resize_raw_disk(&path, too_large).expect_err("reject oversized ext4");

        assert!(matches!(
            error,
            RootDiskError::Ext4 {
                source: disk_image::ext4::ResizeError::TooLarge { .. },
                ..
            }
        ));
        assert_eq!(fs::metadata(&path).expect("metadata").len(), old_size);
    }

    #[test]
    fn resize_raw_disk_defers_non_ext4_filesystem_to_guest() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        fs::write(&path, b"not ext4").expect("write disk");

        let outcome = resize_raw_disk(&path, 4096).expect("extend non-ext4 disk");

        assert_eq!(outcome, RootDiskResizeOutcome::GuestRequired);
        assert_eq!(fs::metadata(&path).expect("metadata").len(), 4096);
        assert_eq!(&fs::read(&path).expect("read disk")[..8], b"not ext4");
    }

    #[test]
    fn resize_raw_disk_leaves_dirty_filesystem_for_online_recovery() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        disk_image::ext4::Formatter::new(&path, 4096, 256 * 1024)
            .expect("create ext4 image")
            .close()
            .expect("finish ext4 image");
        let old_size = fs::metadata(&path).expect("metadata").len();
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open image");
        let mut superblock = [0u8; 1024];
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.read_exact(&mut superblock).expect("read superblock");
        let incompat = u32::from_le_bytes(superblock[0x60..0x64].try_into().unwrap());
        superblock[0x60..0x64].copy_from_slice(&(incompat | 0x4).to_le_bytes());
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.write_all(&superblock).expect("write superblock");
        drop(file);
        let new_size = old_size + 128 * 1024 * 1024;

        let outcome = resize_raw_disk(&path, new_size).expect("defer resize to guest");

        assert_eq!(outcome, RootDiskResizeOutcome::GuestRequired);
        assert_eq!(fs::metadata(&path).expect("metadata").len(), new_size);
        let superblock =
            disk_image::ext4::read_superblock(&fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(superblock.blocks_count_lo as u64 * 4096, old_size);
        assert_ne!(superblock.feature_incompat & 0x4, 0);
    }

    #[test]
    fn vmdk_upper_growth_preserves_dirty_prefix_uuid_and_exact_backing_length() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("upper.raw");
        let replacement_path = temp.path().join("upper-next.raw");
        let old_length = 64 * 1024 * 1024;
        let formatted = disk_image::ext4::upper::format_upper(
            &source,
            rootfs_spec::upper_geometry::UpperCapacity::new(old_length).unwrap(),
        )
        .unwrap();
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        file.seek(SeekFrom::Start(1024 + 0x60)).unwrap();
        let mut incompat = [0; 4];
        file.read_exact(&mut incompat).unwrap();
        file.seek(SeekFrom::Start(1024 + 0x60)).unwrap();
        file.write_all(&(u32::from_le_bytes(incompat) | 4).to_le_bytes())
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        let old = crate::storage::stream::StreamHasher::new()
            .hash_file(&source)
            .unwrap();
        let requested = 128 * 1024 * 1024 + 4096;
        let replacement = crate::machine::root_disk::UpperReplacement::prepare(
            &source,
            &replacement_path,
            requested,
        )
        .unwrap();
        assert_eq!(fs::metadata(&replacement_path).unwrap().len(), requested);
        let prefix = crate::storage::stream::StreamHasher::new()
            .hash_reader(&mut fs::File::open(&replacement_path).unwrap().take(old_length))
            .unwrap();
        assert_eq!(old.id(), prefix.id());
        let superblock =
            disk_image::ext4::read_superblock(&fs::File::open(&replacement_path).unwrap()).unwrap();
        assert_eq!(uuid::Uuid::from_bytes(superblock.uuid), formatted.uuid);
        assert_ne!(superblock.feature_incompat & 4, 0);
        assert_eq!(
            superblock.blocks_count_lo as u64 * 4096,
            formatted.filesystem_bytes
        );
        replacement.commit();
        assert!(!source.exists());
        assert!(replacement_path.exists());
    }

    #[test]
    fn vmdk_upper_replacement_rollback_and_refusals_never_modify_old_generation() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("upper.raw");
        let path = temp.path().join("replacement.raw");
        let length = 64 * 1024 * 1024;
        disk_image::ext4::upper::format_upper(
            &source,
            rootfs_spec::upper_geometry::UpperCapacity::new(length).unwrap(),
        )
        .unwrap();
        let old = crate::storage::stream::StreamHasher::new()
            .hash_file(&source)
            .unwrap();
        assert!(crate::machine::root_disk::UpperReplacement::prepare(
            &source,
            &path,
            length - 4096
        )
        .is_err());
        assert!(!path.exists());
        {
            let _replacement =
                crate::machine::root_disk::UpperReplacement::prepare(&source, &path, length + 4096)
                    .unwrap();
            assert!(path.exists());
        }
        assert!(!path.exists());
        assert_eq!(
            crate::storage::stream::StreamHasher::new()
                .hash_file(&source)
                .unwrap()
                .id(),
            old.id()
        );
        fs::write(&path, b"do not replace").unwrap();
        assert!(crate::machine::root_disk::UpperReplacement::prepare(
            &source,
            &path,
            length + 4096
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"do not replace");
    }

    #[test]
    fn vmdk_private_copy_refuses_existing_destination_without_truncating_it() {
        let temp = copy_tempdir();
        let source = temp.path().join("source.raw");
        let destination = temp.path().join("owned-by-another-operation.raw");
        fs::write(&source, [0x41; 512]).unwrap();
        fs::write(&destination, b"preserve existing destination").unwrap();
        let error = copy_to_path(&source, &destination).unwrap_err();
        assert!(
            matches!(error, RootDiskError::Storage(crate::storage::StorageError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"preserve existing destination"
        );
        assert_eq!(fs::read(&source).unwrap(), [0x41; 512]);
    }

    #[test]
    fn vmdk_upper_uncertain_publication_drop_retains_both_generations() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("upper.raw");
        let candidate = temp.path().join("candidate.raw");
        let length = 64 * 1024 * 1024;
        disk_image::ext4::upper::format_upper(
            &source,
            rootfs_spec::upper_geometry::UpperCapacity::new(length).unwrap(),
        )
        .unwrap();
        let mut replacement = crate::machine::root_disk::UpperReplacement::prepare(
            &source,
            &candidate,
            length + 4096,
        )
        .unwrap();
        replacement.begin_publication();
        drop(replacement);
        assert_eq!(fs::metadata(&candidate).unwrap().len(), length + 4096);
        assert_eq!(fs::metadata(&source).unwrap().len(), length);
        let confirmed_rollback = temp.path().join("confirmed-rollback.raw");
        let mut replacement = crate::machine::root_disk::UpperReplacement::prepare(
            &source,
            &confirmed_rollback,
            length + 4096,
        )
        .unwrap();
        replacement.begin_publication();
        replacement.discard_unpublished();
        assert!(!confirmed_rollback.exists());
        assert!(source.exists());
        assert!(candidate.exists());
    }

    #[test]
    fn private_copy_real_source_and_two_children_are_bidirectionally_isolated() {
        let temp = copy_tempdir();
        let source = temp.path().join("source.raw");
        let input = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        let length = 16 * 1024 * 1024 + 17;
        input.set_len(length).unwrap();
        input.write_all_at(b"prefix", 0).unwrap();
        input.write_all_at(&[0; 4096], 16 * 1024).unwrap();
        input.write_all_at(b"middle", 8 * 1024 * 1024 + 3).unwrap();
        input.write_all_at(b"tail", length - 4).unwrap();
        input.sync_all().unwrap();
        let mut expected = vec![0; length as usize];
        input.read_exact_at(&mut expected, 0).unwrap();
        let staging = OwnedDirectory::open_root(&temp.path().join("staging")).unwrap();
        let mut qualification = CopyQualification::new(1);
        let first = copy_private(
            CopySource::Unscanned {
                file: &input,
                length,
            },
            staging.try_clone().unwrap(),
            "first",
            &mut qualification,
        )
        .unwrap();
        let second = copy_private(
            CopySource::Unscanned {
                file: &input,
                length,
            },
            staging.try_clone().unwrap(),
            "second",
            &mut qualification,
        )
        .unwrap();
        eprintln!(
            "copy filesystem device={} first={:?} second={:?}",
            input.metadata().unwrap().dev(),
            first.method(),
            second.method()
        );
        assert_eq!(fs::read(first.path()).unwrap(), expected);
        assert_eq!(fs::read(second.path()).unwrap(), expected);
        assert_ne!(
            input.metadata().unwrap().ino(),
            first.file().metadata().unwrap().ino()
        );
        assert_ne!(
            first.file().metadata().unwrap().ino(),
            second.file().metadata().unwrap().ino()
        );
        assert_eq!(first.file().metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(first.file().metadata().unwrap().nlink(), 1);
        if first.method() == CloneDiskMethod::SparseCopy {
            let verification = first.verification().unwrap();
            let expected_map = crate::storage::stream::StreamHasher::new()
                .hash_reader(&expected[..])
                .unwrap();
            assert_eq!(verification.stream, expected_map.id());
            assert!(verification.source.logical_bytes_hashed > 0);
            assert!(verification.output.logical_bytes_hashed > 0);
        } else {
            assert!(first.verification().is_none());
        }
        input.write_all_at(b"parent", 4096).unwrap();
        input.sync_all().unwrap();
        assert_eq!(fs::read(first.path()).unwrap(), expected);
        assert_eq!(fs::read(second.path()).unwrap(), expected);
        first.file().write_all_at(b"child-a", 8192).unwrap();
        first.file().sync_all().unwrap();
        second.file().write_all_at(b"child-b", 12288).unwrap();
        second.file().sync_all().unwrap();
        let mut source_expected = expected.clone();
        source_expected[4096..4102].copy_from_slice(b"parent");
        assert_eq!(fs::read(&source).unwrap(), source_expected);
        let mut first_expected = expected.clone();
        first_expected[8192..8199].copy_from_slice(b"child-a");
        assert_eq!(fs::read(first.path()).unwrap(), first_expected);
        expected[12288..12295].copy_from_slice(b"child-b");
        assert_eq!(fs::read(second.path()).unwrap(), expected);
    }

    #[test]
    fn private_copy_uses_held_source_and_pinned_directory_not_replaced_paths() {
        let temp = copy_tempdir();
        let source = temp.path().join("source");
        fs::write(&source, b"admitted inode").unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        fs::rename(&source, temp.path().join("old-source")).unwrap();
        fs::write(&source, b"replacement inode").unwrap();
        let stage_path = temp.path().join("stage");
        let stage = OwnedDirectory::open_root(&stage_path).unwrap();
        let moved = temp.path().join("moved-stage");
        fs::rename(&stage_path, &moved).unwrap();
        fs::create_dir(&stage_path).unwrap();
        let copy = copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 14,
            },
            stage,
            "content",
            &mut CopyQualification::new(1),
        )
        .unwrap();
        assert_eq!(fs::read(moved.join("content")).unwrap(), b"admitted inode");
        assert!(!stage_path.join("content").exists());
        drop(copy);
        assert!(!moved.join("content").exists());
        assert_eq!(fs::read(&source).unwrap(), b"replacement inode");
    }

    #[test]
    fn private_copy_rejects_changed_length_links_permissions_and_source_symlink() {
        let temp = copy_tempdir();
        let source = temp.path().join("source");
        fs::write(&source, b"source").unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        let stage = OwnedDirectory::open_root(&temp.path().join("stage")).unwrap();
        for length in [0, 5, 7] {
            assert!(copy_private(
                CopySource::Unscanned {
                    file: &input,
                    length
                },
                stage.try_clone().unwrap(),
                "content",
                &mut CopyQualification::new(1)
            )
            .is_err());
            assert!(!stage.path().join("content").exists());
        }
        fs::hard_link(&source, temp.path().join("alias")).unwrap();
        assert!(copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6
            },
            stage.try_clone().unwrap(),
            "content",
            &mut CopyQualification::new(1)
        )
        .is_err());
        fs::remove_file(temp.path().join("alias")).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6
            },
            stage.try_clone().unwrap(),
            "content",
            &mut CopyQualification::new(1)
        )
        .is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&source, temp.path().join("symlink")).unwrap();
        assert!(crate::storage::stream::open_regular_source(&temp.path().join("symlink")).is_err());
        assert!(!stage.path().join("content").exists());
    }

    #[test]
    fn private_copy_never_removes_existing_file_directory_or_symlink() {
        let temp = copy_tempdir();
        let source = temp.path().join("source");
        fs::write(&source, b"source").unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        let stage = OwnedDirectory::open_root(&temp.path().join("stage")).unwrap();
        fs::write(stage.path().join("file"), b"existing").unwrap();
        fs::create_dir(stage.path().join("directory")).unwrap();
        symlink(&source, stage.path().join("symlink")).unwrap();
        let mut qualification = CopyQualification::new(1);
        for name in ["file", "directory", "symlink"] {
            assert!(copy_private(
                CopySource::Unscanned {
                    file: &input,
                    length: 6
                },
                stage.try_clone().unwrap(),
                name,
                &mut qualification
            )
            .is_err());
        }
        assert_eq!(fs::read(stage.path().join("file")).unwrap(), b"existing");
        assert!(stage.path().join("directory").is_dir());
        assert!(fs::symlink_metadata(stage.path().join("symlink"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(source).unwrap(), b"source");
    }

    #[test]
    fn private_copy_publication_collision_and_uncertain_drop_preserve_ownership() {
        let temp = copy_tempdir();
        let source = temp.path().join("source");
        fs::write(&source, b"source").unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        let stage = OwnedDirectory::open_root(&temp.path().join("stage")).unwrap();
        let destination = OwnedDirectory::open_root(&temp.path().join("destination")).unwrap();
        fs::write(destination.path().join("root.raw"), b"another owner").unwrap();
        let mut copy = copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6,
            },
            stage.try_clone().unwrap(),
            "content",
            &mut CopyQualification::new(1),
        )
        .unwrap();
        assert!(copy
            .publish(destination.try_clone().unwrap(), "root.raw")
            .is_err());
        assert_eq!(
            fs::read(destination.path().join("root.raw")).unwrap(),
            b"another owner"
        );
        assert_eq!(fs::read(copy.path()).unwrap(), b"source");
        drop(copy);
        assert!(!stage.path().join("content").exists());
        let mut copy = copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6,
            },
            stage.try_clone().unwrap(),
            "content",
            &mut CopyQualification::new(1),
        )
        .unwrap();
        copy.publish(destination.try_clone().unwrap(), "new.raw")
            .unwrap();
        drop(copy);
        assert_eq!(
            fs::read(destination.path().join("new.raw")).unwrap(),
            b"source"
        );
        let mut copy = copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6,
            },
            stage.try_clone().unwrap(),
            "content",
            &mut CopyQualification::new(1),
        )
        .unwrap();
        copy.publish(destination.try_clone().unwrap(), "uncommitted.raw")
            .unwrap();
        copy.discard_unpublished();
        assert!(!destination.path().join("uncommitted.raw").exists());
    }

    #[test]
    fn private_copy_drop_refuses_to_remove_replaced_or_hardlinked_entry() {
        let temp = copy_tempdir();
        let source = temp.path().join("source");
        fs::write(&source, b"source").unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        let stage = OwnedDirectory::open_root(&temp.path().join("stage")).unwrap();
        let copy = copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6,
            },
            stage.try_clone().unwrap(),
            "content",
            &mut CopyQualification::new(1),
        )
        .unwrap();
        fs::rename(copy.path(), stage.path().join("moved")).unwrap();
        fs::write(copy.path(), b"replacement").unwrap();
        drop(copy);
        assert_eq!(
            fs::read(stage.path().join("content")).unwrap(),
            b"replacement"
        );
        assert_eq!(fs::read(stage.path().join("moved")).unwrap(), b"source");
        let copy = copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6,
            },
            stage.try_clone().unwrap(),
            "linked",
            &mut CopyQualification::new(1),
        )
        .unwrap();
        fs::hard_link(copy.path(), stage.path().join("alias")).unwrap();
        drop(copy);
        assert_eq!(fs::read(stage.path().join("linked")).unwrap(), b"source");
    }

    #[test]
    fn private_copy_qualification_is_bounded_and_not_global() {
        let temp = copy_tempdir();
        let source = temp.path().join("source");
        fs::write(&source, b"source").unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        let stage = OwnedDirectory::open_root(&temp.path().join("stage")).unwrap();
        let other = OwnedDirectory::open_root(&temp.path().join("other")).unwrap();
        let mut qualification = CopyQualification::new(1);
        drop(
            copy_private(
                CopySource::Unscanned {
                    file: &input,
                    length: 6,
                },
                stage.try_clone().unwrap(),
                "first",
                &mut qualification,
            )
            .unwrap(),
        );
        assert_eq!(qualification.directories.len(), 1);
        drop(
            copy_private(
                CopySource::Unscanned {
                    file: &input,
                    length: 6,
                },
                stage.try_clone().unwrap(),
                "second",
                &mut qualification,
            )
            .unwrap(),
        );
        assert_eq!(qualification.directories.len(), 1);
        assert!(copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6
            },
            other,
            "third",
            &mut qualification
        )
        .is_err());
        assert!(copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 6
            },
            stage,
            "fourth",
            &mut CopyQualification::new(0)
        )
        .is_err());
    }

    #[test]
    fn private_copy_clone_errno_matrix_only_admits_qualified_unsupported_errors() {
        use std::io::Error;
        for errno in [libc::EOPNOTSUPP, libc::ENOTSUP, libc::EXDEV] {
            assert!(clone_error_allows_fallback(
                &Error::from_raw_os_error(errno),
                false
            ));
        }
        for errno in [
            libc::ENOSPC,
            libc::EDQUOT,
            libc::EIO,
            libc::EACCES,
            libc::EPERM,
            libc::EROFS,
            libc::EBADF,
            libc::EEXIST,
            libc::ENOENT,
            libc::ENOTDIR,
            libc::EISDIR,
        ] {
            assert!(
                !clone_error_allows_fallback(&Error::from_raw_os_error(errno), true),
                "errno={errno}"
            );
        }
        assert!(!clone_error_allows_fallback(
            &Error::other("corrupt clone"),
            true
        ));
        assert!(!clone_error_allows_fallback(
            &Error::from_raw_os_error(libc::EINVAL),
            false
        ));
        #[cfg(target_os = "linux")]
        {
            assert!(clone_error_allows_fallback(
                &Error::from_raw_os_error(libc::EINVAL),
                true
            ));
            assert!(clone_error_allows_fallback(
                &Error::from_raw_os_error(libc::ENOTTY),
                false
            ));
            assert!(!clone_error_allows_fallback(
                &Error::from_raw_os_error(libc::ENOSYS),
                true
            ));
        }
        #[cfg(target_os = "macos")]
        {
            assert!(!clone_error_allows_fallback(
                &Error::from_raw_os_error(libc::EINVAL),
                true
            ));
            assert!(!clone_error_allows_fallback(
                &Error::from_raw_os_error(libc::ENOTTY),
                true
            ));
            assert!(clone_error_allows_fallback(
                &Error::from_raw_os_error(libc::ENOSYS),
                false
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_copy_real_invalid_clone_descriptor_is_fatal() {
        let temp = copy_tempdir();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::write(&source, b"source").unwrap();
        fs::write(&destination, b"unchanged").unwrap();
        let input = File::open(&source).unwrap();
        let read_only_output = File::open(&destination).unwrap();
        let error = crate::machine::root_disk::try_reflink(&input, &read_only_output).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        assert!(!clone_error_allows_fallback(&error, true));
        assert_eq!(fs::read(destination).unwrap(), b"unchanged");
    }

    #[tokio::test]
    async fn private_copy_cancelled_waiter_cannot_release_worker_files_or_ofd_fence() {
        use crate::storage::locks::{acquire, blocking};
        use nix::fcntl::FlockArg;
        let temp = copy_tempdir();
        let source = temp.path().join("source");
        fs::write(&source, b"source").unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        let stage = OwnedDirectory::open_root(&temp.path().join("stage")).unwrap();
        let locks = OwnedDirectory::open_root(&temp.path().join("locks")).unwrap();
        let lease = blocking(&locks, "operation.lease", FlockArg::LockShared).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let copy = copy_private(
                CopySource::Unscanned {
                    file: &input,
                    length: 6,
                },
                stage,
                "content",
                &mut CopyQualification::new(1),
            )
            .unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            assert_eq!(copy.file().metadata().unwrap().len(), 6);
            drop(copy);
            drop(input);
            drop(lease);
            done_tx.send(()).unwrap();
        });
        let waiter = tokio::spawn(async move { worker.await.unwrap() });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap();
        waiter.abort();
        let _ = waiter.await;
        assert!(temp.path().join("stage/content").exists());
        assert!(
            acquire(&locks, "operation.lease", FlockArg::LockExclusiveNonblock)
                .unwrap()
                .is_none()
        );
        release_tx.send(()).unwrap();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap();
        assert!(!temp.path().join("stage/content").exists());
        assert!(
            acquire(&locks, "operation.lease", FlockArg::LockExclusiveNonblock)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn private_copy_clone_probe_data_mismatch_is_fatal_not_unsupported() {
        let temp = copy_tempdir();
        let stage = OwnedDirectory::open_root(&temp.path().join("stage")).unwrap();
        let mut copy = crate::machine::root_disk::new_private_file(stage, "fixture").unwrap();
        copy.file().write_all_at(b"corrupt", 0).unwrap();
        copy.file().sync_all().unwrap();
        let mut actual = [0; 7];
        let error =
            crate::machine::root_disk::verify_probe_reopened(&mut copy, b"correct", &mut actual)
                .unwrap_err();
        assert!(matches!(error, RootDiskError::Io(error)
            if error.kind() == std::io::ErrorKind::InvalidData
                && !clone_error_allows_fallback(&error, true)));
    }

    #[test]
    fn private_copy_empty_platform_file_and_invalid_components() {
        let temp = copy_tempdir();
        let source = temp.path().join("empty-platform");
        fs::write(&source, []).unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        let stage = OwnedDirectory::open_root(&temp.path().join("stage")).unwrap();
        for name in [
            "",
            ".",
            "..",
            "/absolute",
            "nested/file",
            "trailing/",
            "file/.",
            "nul\0name",
        ] {
            assert!(copy_private(
                CopySource::Unscanned {
                    file: &input,
                    length: 0
                },
                stage.try_clone().unwrap(),
                name,
                &mut CopyQualification::new(1)
            )
            .is_err());
        }
        let copy = copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 0,
            },
            stage,
            "empty",
            &mut CopyQualification::new(1),
        )
        .unwrap();
        assert_eq!(copy.file().metadata().unwrap().len(), 0);
        assert!(fs::read(copy.path()).unwrap().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires SILO_TEST_COPY_DIR and SILO_TEST_COPY_CROSS_DIR on different mounted filesystems"]
    fn private_copy_real_cross_filesystem_streams_without_destination_local_qualification() {
        let source_parent =
            std::env::var_os("SILO_TEST_COPY_DIR").expect("explicit source filesystem");
        let destination_parent =
            std::env::var_os("SILO_TEST_COPY_CROSS_DIR").expect("explicit other filesystem");
        let source_dir = tempfile::tempdir_in(source_parent).unwrap();
        let destination_dir = tempfile::tempdir_in(destination_parent).unwrap();
        let source = source_dir.path().join("source");
        fs::write(&source, b"cross-filesystem bytes").unwrap();
        let input = crate::storage::stream::open_regular_source(&source).unwrap();
        let stage = OwnedDirectory::open_root(&destination_dir.path().join("stage")).unwrap();
        assert_ne!(
            input.metadata().unwrap().dev(),
            fs::metadata(stage.path()).unwrap().dev()
        );
        let mut qualification = CopyQualification::new(0);
        let copy = copy_private(
            CopySource::Unscanned {
                file: &input,
                length: 22,
            },
            stage,
            "content",
            &mut qualification,
        )
        .unwrap();
        assert_eq!(copy.method(), CloneDiskMethod::SparseCopy);
        assert!(qualification.directories.is_empty());
        assert_eq!(fs::read(copy.path()).unwrap(), b"cross-filesystem bytes");
        let verification = copy.verification().unwrap();
        assert_eq!(
            verification.stream,
            crate::storage::stream::StreamHasher::new()
                .hash_reader(&b"cross-filesystem bytes"[..])
                .unwrap()
                .id()
        );
        assert_eq!(verification.output.bytes_read, 22);
    }

    /// Three chunks: data prefix plus allocated zeros, a hole-only chunk and a
    /// short tail whose only data is mixed with zeros.
    fn authenticated_fixture(
        directory: &Path,
    ) -> (
        std::path::PathBuf,
        Vec<u8>,
        crate::storage::stream::AuthenticatedStream,
    ) {
        let path = directory.join("authenticated.raw");
        let file = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let chunk = crate::storage::limits::CHUNK_SIZE as u64;
        let length = 2 * chunk + 4099;
        file.set_len(length).unwrap();
        file.write_all_at(b"prefix", 0).unwrap();
        file.write_all_at(&[0; 8192], 4096).unwrap();
        file.write_all_at(b"tail", length - 4).unwrap();
        file.sync_all().unwrap();
        let mut expected = vec![0; length as usize];
        file.read_exact_at(&mut expected, 0).unwrap();
        drop(file);
        let stream = crate::storage::stream::StreamHasher::new()
            .authenticate(
                crate::storage::stream::open_regular_source(&path).unwrap(),
                length,
            )
            .unwrap();
        (path, expected, stream)
    }

    #[test]
    fn private_copy_authenticated_source_reuses_map_and_still_verifies_output() {
        let temp = copy_tempdir();
        let (source, expected, authenticated) = authenticated_fixture(temp.path());
        let staging = OwnedDirectory::open_root(&temp.path().join("staging")).unwrap();
        let mut qualification = CopyQualification::new(1);
        let copy = copy_private(
            CopySource::Authenticated(&authenticated),
            staging.try_clone().unwrap(),
            "child",
            &mut qualification,
        )
        .unwrap();
        assert_eq!(fs::read(copy.path()).unwrap(), expected);
        assert_eq!(
            copy.file().metadata().unwrap().len(),
            authenticated.length()
        );
        assert_ne!(
            copy.file().metadata().unwrap().ino(),
            fs::metadata(&source).unwrap().ino()
        );
        if copy.method() == CloneDiskMethod::SparseCopy {
            let verification = copy.verification().unwrap();
            assert_eq!(verification.stream, authenticated.map().id());
            // The authenticated map was reused, never recomputed from the
            // source, while the completed output was hashed independently.
            assert_eq!(verification.source.logical_bytes_hashed, 0);
            assert!(verification.source.bytes_read > 0);
            assert!(verification.output.logical_bytes_hashed > 0);
            assert_eq!(
                crate::storage::stream::StreamHasher::new()
                    .hash_open_file(copy.file(), authenticated.length())
                    .unwrap()
                    .map,
                *authenticated.map()
            );
        } else {
            assert!(copy.verification().is_none());
        }
        let unscanned = copy_private(
            CopySource::Unscanned {
                file: authenticated.file(),
                length: authenticated.length(),
            },
            staging,
            "scanned",
            &mut qualification,
        )
        .unwrap();
        assert_eq!(fs::read(unscanned.path()).unwrap(), expected);
        if let (Some(scanned), Some(reused)) = (unscanned.verification(), copy.verification()) {
            assert_eq!(scanned.stream, reused.stream);
            assert!(scanned.source.logical_bytes_hashed > 0);
        }
    }

    #[test]
    fn private_copy_authenticated_source_rejects_changes_after_authentication() {
        let temp = copy_tempdir();
        let (source, _, authenticated) = authenticated_fixture(temp.path());
        let staging = OwnedDirectory::open_root(&temp.path().join("staging")).unwrap();
        // Same length and inode; only the bytes behind the map changed.
        let writer = File::options().write(true).open(&source).unwrap();
        writer.write_all_at(b"PREFIX", 0).unwrap();
        writer.sync_all().unwrap();
        assert!(copy_private(
            CopySource::Authenticated(&authenticated),
            staging.try_clone().unwrap(),
            "changed",
            &mut CopyQualification::new(1),
        )
        .is_err());
        assert!(!staging.path().join("changed").exists());
        // A replaced inode at the same path cannot be bound to the old map.
        fs::remove_file(&source).unwrap();
        fs::write(&source, b"replacement").unwrap();
        assert!(authenticated
            .reopen(crate::storage::stream::open_regular_source(&source).unwrap())
            .is_err());
    }

    #[test]
    fn private_copy_authenticated_reopen_uses_an_independent_open_file_description() {
        let temp = copy_tempdir();
        let (source, expected, authenticated) = authenticated_fixture(temp.path());
        let mut held = authenticated.file();
        held.seek(SeekFrom::Start(17)).unwrap();
        let child = authenticated
            .reopen(crate::storage::stream::open_regular_source(&source).unwrap())
            .unwrap();
        assert_eq!(child.map().id(), authenticated.map().id());
        let staging = OwnedDirectory::open_root(&temp.path().join("staging")).unwrap();
        let mut qualification = CopyQualification::new(1);
        for name in ["first", "second"] {
            let copy = copy_private(
                CopySource::Authenticated(&child),
                staging.try_clone().unwrap(),
                name,
                &mut qualification,
            )
            .unwrap();
            assert_eq!(fs::read(copy.path()).unwrap(), expected);
        }
        // Extent seeks on the child's description never move the held one.
        assert_eq!(held.stream_position().unwrap(), 17);
    }
}
