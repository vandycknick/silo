//! Private capture staging under `--data-dir/captures/<capture-id>/`.
//!
//! Every path is resolved relative to a held directory descriptor, never by
//! re-resolving a pathname: the data directory is opened once, then each
//! component below it is created exclusively (`O_EXCL`/`mkdirat`) and opened
//! with `O_NOFOLLOW`. Directories are 0700 and files 0600, owned by the
//! monitor's euid. Records are written exactly once: temporary file, sync,
//! no-replace `linkat`, removal of the owned temporary name, single-link
//! check, directory sync. Nothing here ever unlinks a payload or a record.
//!
//! ```text
//!   data-dir ─► captures/ ─► <id>/ ─┬─ request.json (once, before freeze)
//!                                   ├─ execution.state devices.state
//!                                   ├─ memory.ram memory-layout.json
//!                                   ├─ disks/ ─► <name>.raw (clone or copy)
//!                                   ├─ vm.capture.json        (once)
//!                                   └─ vm.capture-source.json (once)
//! ```
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, fstat, mkdirat, Mode};
use nix::unistd::{fsync, ftruncate, geteuid, linkat, lseek, unlinkat, UnlinkatFlags, Whence};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use vm_spec::capture::{
    CaptureDiskCopy, CaptureRole, Sha256Digest, StreamIdentity, CAPTURES_DIRECTORY,
    CAPTURE_DISKS_DIRECTORY, CAPTURE_REQUEST_FILE, MAX_CAPTURE_RAM_BYTES, MAX_CAPTURE_RECORD_BYTES,
    STREAM_CHUNK_BYTES,
};
use vm_spec::lifecycle::LiveId;

/// Bounded copy buffer: one allocation per disk copy, never RAM-sized.
const COPY_BUFFER_BYTES: usize = 1 << 20;
/// Native canonical layouts are bounded at 64 KiB.
const MAX_LAYOUT_BYTES: u64 = 64 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn private_mode() -> Mode {
    Mode::S_IRUSR | Mode::S_IWUSR
}

fn private_directory_mode() -> Mode {
    Mode::S_IRWXU
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

/// The held directory must be a private directory of this euid.
fn validate_private_directory(directory: &OwnedFd, what: &str) -> io::Result<()> {
    let metadata = File::from(directory.try_clone()?).metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(invalid(format!("{what} is not a private 0700 directory")));
    }
    Ok(())
}

/// Create (or for the shared `captures` root, reuse) one private child
/// directory and return its held descriptor.
fn private_child(parent: &OwnedFd, name: &str, exclusive: bool) -> io::Result<OwnedFd> {
    match mkdirat(parent, name, private_directory_mode()) {
        Ok(()) => {}
        Err(Errno::EEXIST) if !exclusive => {}
        Err(error) => return Err(error.into()),
    }
    let child = openat(parent, name, directory_flags(), Mode::empty())?;
    // mkdirat honours the umask; the exact private mode is set explicitly.
    fchmod(&child, private_directory_mode())?;
    validate_private_directory(&child, name)?;
    Ok(child)
}

/// Facts of one opened regular staged file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileFacts {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) length: u64,
}

impl FileFacts {
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
        })
    }
}

/// Private regular file of this euid with one link and mode 0600.
fn validate_private_file(file: &File) -> io::Result<FileFacts> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(invalid(
            "staged file is not a private single-link 0600 regular file",
        ));
    }
    FileFacts::of(file)
}

fn same_inode(left: FileFacts, right: FileFacts) -> bool {
    (left.device, left.inode) == (right.device, right.inode)
}

/// The capture directory and its `disks/` child, held for the capture's
/// lifetime.
#[derive(Debug)]
pub(crate) struct CaptureStaging {
    directory: OwnedFd,
    disks: OwnedFd,
    path: PathBuf,
}

/// Outcome of a write-once record.
#[derive(Debug)]
pub(crate) enum RecordCommit {
    /// The final name is the single link of the written inode, the
    /// temporary name is gone and the directory is synchronized.
    Durable,
    /// Visible under its final name, but its completed single-link layout or
    /// its directory sync could not be established: neither durable success
    /// nor absence. The bytes are never overwritten or removed.
    Uncertain(io::Error),
}

/// A sealed disk role, synchronized and closed for writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiskCopyMethod {
    Clone,
    SparseCopy,
}

#[derive(Debug)]
pub(crate) enum DiskCopyError {
    Cancelled,
    /// `Clone` was reserved at the clone charge; a copy would overrun it.
    CloneRequired(io::Error),
    Io(io::Error),
}

impl std::fmt::Display for DiskCopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("disk copy cancelled"),
            Self::CloneRequired(error) => {
                write!(f, "reserved clone is unavailable for this disk: {error}")
            }
            Self::Io(error) => write!(f, "disk copy failed: {error}"),
        }
    }
}

impl From<io::Error> for DiskCopyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Errno> for DiskCopyError {
    fn from(error: Errno) -> Self {
        Self::Io(error.into())
    }
}

impl CaptureStaging {
    /// Create `captures/<id>/` and `disks/` exclusively. A pre-existing capture
    /// directory is never adopted.
    pub(crate) fn create(data_dir: &Path, capture: &LiveId) -> io::Result<Self> {
        let data = open(data_dir, directory_flags(), Mode::empty())?;
        let captures = private_child(&data, CAPTURES_DIRECTORY, false)?;
        fsync(&data)?;
        let directory = private_child(&captures, capture.as_str(), true)?;
        fsync(&captures)?;
        let disks = private_child(&directory, CAPTURE_DISKS_DIRECTORY, true)?;
        fsync(&directory)?;
        Ok(Self {
            directory,
            disks,
            path: data_dir.join(CAPTURES_DIRECTORY).join(capture.as_str()),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// `request.json`, exactly once and durable before any freeze.
    pub(crate) fn write_request(&self, bytes: &[u8]) -> io::Result<Sha256Digest> {
        let mut file = File::from(openat(
            &self.directory,
            CAPTURE_REQUEST_FILE,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&file, private_mode())?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fsync(&self.directory)?;
        Ok(Sha256Digest::of_bytes(bytes))
    }

    /// Allocated bytes of the private `request.json`, reopened read-only
    /// through the held directory.
    pub(crate) fn request_allocation(&self) -> io::Result<u64> {
        let file = File::from(openat(
            &self.directory,
            CAPTURE_REQUEST_FILE,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        validate_private_file(&file)?;
        Ok(file.metadata()?.blocks().saturating_mul(512))
    }

    /// A fresh, empty, private O_RDWR output for one native-written role.
    pub(crate) fn create_output(&self, role: &CaptureRole) -> io::Result<File> {
        let (directory, name) = self.locate(role);
        let file = File::from(openat(
            directory,
            name.as_str(),
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&file, private_mode())?;
        let facts = validate_private_file(&file)?;
        if facts.length != 0 {
            return Err(invalid("fresh capture output is not empty"));
        }
        Ok(file)
    }

    /// Reopen a staged role read-only through the held directory.
    pub(crate) fn open_sealed(&self, role: &CaptureRole) -> io::Result<(File, FileFacts)> {
        let (directory, name) = self.locate(role);
        let file = File::from(openat(
            directory,
            name.as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let facts = validate_private_file(&file)?;
        Ok((file, facts))
    }

    fn locate(&self, role: &CaptureRole) -> (&OwnedFd, String) {
        match role {
            CaptureRole::Disk(name) => (&self.disks, name.file_name()),
            other => (&self.directory, other.relative_path()),
        }
    }

    /// Seal one writable disk: clone or sparse-copy exactly `length` bytes
    /// from the held, paused source into a fresh private role, synchronize
    /// it and close the writer. Holes stay holes; all-zero data is not
    /// written into a fresh destination (which already reads as zeros).
    pub(crate) fn copy_disk(
        &self,
        role: &CaptureRole,
        source: &File,
        length: u64,
        copy: CaptureDiskCopy,
        cancel: &CancellationToken,
    ) -> Result<DiskCopyMethod, DiskCopyError> {
        let (_, name) = self.locate(role);
        let source_metadata = source.metadata()?;
        if !source_metadata.is_file() || source_metadata.len() != length {
            return Err(
                invalid("capture source is not a regular file of its planned length").into(),
            );
        }
        if cancel.is_cancelled() {
            return Err(DiskCopyError::Cancelled);
        }
        let method = match self.clone_disk(source, &name) {
            Ok(()) => DiskCopyMethod::Clone,
            Err(error) if clone_unsupported(&error) => match copy {
                CaptureDiskCopy::Clone => return Err(DiskCopyError::CloneRequired(error)),
                CaptureDiskCopy::Copy => {
                    self.sparse_copy(source, &name, length, cancel)?;
                    DiskCopyMethod::SparseCopy
                }
            },
            Err(error) => return Err(error.into()),
        };
        let (written, facts) = self.reopen_disk_writer(&name)?;
        if facts.length != length
            || (facts.device, facts.inode) == (source_metadata.dev(), source_metadata.ino())
        {
            return Err(invalid("sealed disk differs in length or aliases its source").into());
        }
        written.sync_all()?;
        drop(written);
        if source.metadata()?.len() != length {
            return Err(invalid("capture source changed length during its copy").into());
        }
        Ok(method)
    }

    fn reopen_disk_writer(&self, name: &str) -> io::Result<(File, FileFacts)> {
        let file = File::from(openat(
            &self.disks,
            name,
            OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        fchmod(&file, private_mode())?;
        let facts = validate_private_file(&file)?;
        Ok((file, facts))
    }

    #[cfg(target_os = "linux")]
    fn clone_disk(&self, source: &File, name: &str) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        const FICLONE: libc::c_ulong = 0x4004_9409;
        let destination = File::from(openat(
            &self.disks,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        // nix exposes no safe wrapper for the whole-file FICLONE ioctl; it only
        // reads the source descriptor number for the duration of the call.
        let rc = unsafe { libc::ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        drop(destination);
        // Never stream into a possibly partially cloned inode: the empty
        // destination this call created is replaced by a fresh one.
        unlinkat(&self.disks, name, UnlinkatFlags::NoRemoveDir)?;
        Err(error)
    }

    #[cfg(target_os = "macos")]
    fn clone_disk(&self, source: &File, name: &str) -> io::Result<()> {
        use nix::NixPath;
        use std::os::fd::AsRawFd;
        // nix does not expose fclonefileat; it consumes the held source
        // descriptor, so no source pathname is resolved again.
        let rc = name
            .with_nix_path(|name| unsafe {
                libc::fclonefileat(source.as_raw_fd(), self.disks.as_raw_fd(), name.as_ptr(), 0)
            })
            .map_err(io::Error::from)?;
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match nix::sys::stat::fstatat(&self.disks, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(Errno::ENOENT) => Err(error),
            Ok(_) => Err(invalid("failed clone left an unexpected destination")),
            Err(stat) => Err(stat.into()),
        }
    }

    fn sparse_copy(
        &self,
        source: &File,
        name: &str,
        length: u64,
        cancel: &CancellationToken,
    ) -> Result<(), DiskCopyError> {
        let destination = File::from(openat(
            &self.disks,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&destination, private_mode())?;
        let total = i64::try_from(length).map_err(|_| invalid("disk length overflow"))?;
        ftruncate(&destination, total)?;
        let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
        let mut offset = 0u64;
        while offset < length {
            if cancel.is_cancelled() {
                return Err(DiskCopyError::Cancelled);
            }
            let (data, end) = match next_extent(source, offset, length)? {
                Some(extent) => extent,
                None => break,
            };
            let mut position = data;
            while position < end {
                if cancel.is_cancelled() {
                    return Err(DiskCopyError::Cancelled);
                }
                let span = usize::try_from((end - position).min(COPY_BUFFER_BYTES as u64))
                    .map_err(|_| invalid("copy span overflow"))?;
                let chunk = &mut buffer[..span];
                source.read_exact_at(chunk, position)?;
                if chunk.iter().any(|byte| *byte != 0) {
                    destination.write_all_at(chunk, position)?;
                }
                position += span as u64;
            }
            offset = end;
        }
        destination.sync_all()?;
        Ok(())
    }

    /// Synchronize both held directories (entries of every staged role).
    pub(crate) fn sync_directories(&self) -> io::Result<()> {
        fsync(&self.disks)?;
        fsync(&self.directory)?;
        Ok(())
    }

    /// Allocated bytes of both held directories.
    pub(crate) fn directory_allocation(&self) -> io::Result<u64> {
        let mut total = 0u64;
        for directory in [&self.directory, &self.disks] {
            let stat = fstat(directory)?;
            let blocks = u64::try_from(stat.st_blocks).map_err(|_| invalid("negative blocks"))?;
            total = total.saturating_add(blocks.saturating_mul(512));
        }
        Ok(total)
    }

    /// Write one control record exactly once. An existing final name is
    /// never replaced. Failure before the link leaves no record; after the
    /// link the record is settled (with one bounded retry of the whole
    /// settlement), never removed.
    ///
    /// ```text
    ///   temporary ─write,fsync─► linkat(final) ─► settle: final is ours,
    ///   remove our temporary, single link, directory fsync ─► Durable
    ///                                   └─ cannot establish ─► Uncertain
    /// ```
    ///
    /// The record is bounded by [`MAX_CAPTURE_RECORD_BYTES`], the size the
    /// staging budget charges for it; a larger one is refused unwritten.
    pub(crate) fn commit_record(
        &self,
        name: &str,
        temporary: &str,
        bytes: &[u8],
    ) -> io::Result<RecordCommit> {
        if bytes.len() > MAX_CAPTURE_RECORD_BYTES {
            return Err(invalid("capture record exceeds its bound"));
        }
        // A failed exclusive create may name a pre-existing writer's file.
        // Retain failed temporaries for operation-owned cleanup, never unlink
        // a name whose ownership this attempt has not established.
        let identity = self.write_temporary(temporary, bytes)?;
        // linkat is the no-replace rename: EEXIST never overwrites a record.
        if let Err(error) = self.link_record(temporary, name) {
            if let Err(cleanup) = unlinkat(&self.directory, temporary, UnlinkatFlags::NoRemoveDir) {
                tracing::warn!(%cleanup, temporary, "could not remove a capture record temporary");
            }
            return Err(error);
        }
        // The final name is visible: from here no outcome removes it.
        match self.settle_record(name, temporary, identity) {
            Ok(()) => Ok(RecordCommit::Durable),
            Err(first) => {
                tracing::warn!(error = %first, name, "capture record is visible but unsettled; retrying settlement once");
                Ok(match self.settle_record(name, temporary, identity) {
                    Ok(()) => RecordCommit::Durable,
                    Err(_) => RecordCommit::Uncertain(first),
                })
            }
        }
    }

    /// Create, fill and synchronize the exclusive temporary record.
    fn write_temporary(&self, temporary: &str, bytes: &[u8]) -> io::Result<FileFacts> {
        let mut file = File::from(openat(
            &self.directory,
            temporary,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&file, private_mode())?;
        file.write_all(bytes)?;
        file.sync_all()?;
        FileFacts::of(&file)
    }

    fn link_record(&self, temporary: &str, name: &str) -> io::Result<()> {
        linkat(
            &self.directory,
            temporary,
            &self.directory,
            name,
            AtFlags::empty(),
        )
        .map_err(Into::into)
    }

    /// Establish the completed layout of a linked record, then make it
    /// durable: the final name holds exactly the written inode, the owned
    /// temporary name is absent (removed only while it still names that
    /// inode), the record has a single link, then the directory is synced.
    /// A directory sync never stands in for a removal that did not happen.
    fn settle_record(&self, name: &str, temporary: &str, identity: FileFacts) -> io::Result<()> {
        let record = self.open_entry(name)?;
        if !same_inode(FileFacts::of(&record)?, identity) {
            return Err(invalid(
                "the final record name does not hold the written record",
            ));
        }
        match self.open_entry(temporary) {
            Ok(file) => {
                if !same_inode(FileFacts::of(&file)?, identity) {
                    return Err(invalid(
                        "the temporary record name holds a file this commit does not own",
                    ));
                }
                unlinkat(&self.directory, temporary, UnlinkatFlags::NoRemoveDir)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        validate_private_file(&record)?;
        fsync(&self.directory)?;
        Ok(())
    }

    /// Open one existing entry of the capture directory without following
    /// links or blocking on special files.
    fn open_entry(&self, name: &str) -> io::Result<File> {
        Ok(File::from(openat(
            &self.directory,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?))
    }

    /// Read back one committed record through the held directory.
    #[cfg(test)]
    pub(crate) fn read_record(&self, name: &str) -> io::Result<Vec<u8>> {
        let file = File::from(openat(
            &self.directory,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let facts = validate_private_file(&file)?;
        let length = usize::try_from(facts.length).map_err(|_| invalid("record too large"))?;
        if length > MAX_CAPTURE_RECORD_BYTES {
            return Err(invalid("capture record exceeds its bound"));
        }
        let mut bytes = vec![0u8; length];
        file.read_exact_at(&mut bytes, 0)?;
        Ok(bytes)
    }
}

/// Unsupported clone operations may fall back to a copy; permission, I/O and
/// corruption errors never do.
fn clone_unsupported(error: &io::Error) -> bool {
    let Some(errno) = error.raw_os_error() else {
        return false;
    };
    if errno == libc::EOPNOTSUPP || errno == libc::ENOTSUP || errno == libc::EXDEV {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        errno == libc::ENOTTY || errno == libc::EINVAL
    }
    #[cfg(target_os = "macos")]
    {
        errno == libc::ENOSYS
    }
}

/// Next allocated extent at or after `offset`; filesystems without extent
/// support report the whole remaining range as data.
fn next_extent(source: &File, offset: u64, length: u64) -> io::Result<Option<(u64, u64)>> {
    let at = i64::try_from(offset).map_err(|_| invalid("copy offset overflow"))?;
    let data = match lseek(source.as_fd(), at, Whence::SeekData) {
        Ok(data) => u64::try_from(data).map_err(|_| invalid("negative data offset"))?,
        Err(Errno::ENXIO) => return Ok(None),
        Err(Errno::EINVAL | Errno::EOPNOTSUPP) => return Ok(Some((offset, length))),
        Err(error) => return Err(error.into()),
    };
    if data >= length {
        return Ok(None);
    }
    let from = i64::try_from(data).map_err(|_| invalid("copy offset overflow"))?;
    let hole = match lseek(source.as_fd(), from, Whence::SeekHole) {
        Ok(hole) => u64::try_from(hole).map_err(|_| invalid("negative hole offset"))?,
        Err(Errno::EINVAL | Errno::EOPNOTSUPP) => length,
        Err(error) => return Err(error.into()),
    };
    if hole <= data {
        return Err(invalid("SEEK_HOLE returned an extent before its data"));
    }
    Ok(Some((data, hole.min(length))))
}

/// Whole-file SHA-256 plus, for RAM, the ADR 0014 stream identity, in one
/// bounded sequential pass with a reusable 8 MiB buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HashedFile {
    pub(crate) length: u64,
    pub(crate) sha256: Sha256Digest,
    pub(crate) stream: Option<Sha256Digest>,
}

pub(crate) struct Hasher {
    buffer: Vec<u8>,
}

impl Hasher {
    pub(crate) fn new() -> Self {
        Self {
            buffer: vec![0u8; STREAM_CHUNK_BYTES as usize],
        }
    }

    pub(crate) fn hash(
        &mut self,
        file: &File,
        length: u64,
        stream: bool,
        cancel: &CancellationToken,
    ) -> io::Result<HashedFile> {
        use sha2::Digest as _;
        let mut whole = sha2::Sha256::new();
        let mut identity = stream.then(StreamIdentity::new);
        let mut offset = 0u64;
        while offset < length {
            if cancel.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "hashing cancelled",
                ));
            }
            let span = usize::try_from((length - offset).min(STREAM_CHUNK_BYTES))
                .map_err(|_| invalid("hash span overflow"))?;
            let chunk = &mut self.buffer[..span];
            file.read_exact_at(chunk, offset)?;
            whole.update(&*chunk);
            if let Some(identity) = identity.as_mut() {
                identity.push_chunk(chunk).map_err(invalid)?;
            }
            offset += span as u64;
        }
        if file.metadata()?.len() != length {
            return Err(invalid("staged file changed length while hashed"));
        }
        Ok(HashedFile {
            length,
            sha256: Sha256Digest::from_bytes(whole.finalize().into()),
            stream: identity.map(StreamIdentity::finish),
        })
    }
}

/// Geometry of the native canonical RAM layout (`memory-layout.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LayoutGeometry {
    pub(crate) packed_length: u64,
    pub(crate) page_granule: u32,
    pub(crate) regions: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawLayout {
    architecture: String,
    kind: String,
    packed_length: u64,
    page_granule: u32,
    regions: Vec<RawRegion>,
    schema: u64,
    #[allow(dead_code)] // Architecture-specific; validated by native on restore.
    topology: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRegion {
    guest_physical_address: u64,
    length: u64,
    stream_offset: u64,
}

/// Ordered, disjoint, granule-aligned regions packed contiguously from
/// offset zero; their sum is the packed RAM length.
pub(crate) fn parse_layout(bytes: &[u8]) -> io::Result<LayoutGeometry> {
    if bytes.len() as u64 > MAX_LAYOUT_BYTES {
        return Err(invalid("RAM layout exceeds its bound"));
    }
    let layout: RawLayout = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("invalid RAM layout: {error}")))?;
    if layout.kind != "ram-layout"
        || layout.schema != 1
        || !matches!(layout.architecture.as_str(), "x86_64" | "aarch64")
        || layout.regions.is_empty()
        || !layout.page_granule.is_power_of_two()
        || layout.page_granule < 4096
    {
        return Err(invalid(
            "unsupported RAM layout kind, schema, architecture or granule",
        ));
    }
    let granule = u64::from(layout.page_granule);
    let mut packed = 0u64;
    let mut previous_end = 0u64;
    for (index, region) in layout.regions.iter().enumerate() {
        let end = region
            .guest_physical_address
            .checked_add(region.length)
            .ok_or_else(|| invalid("RAM region overflows"))?;
        if region.length == 0
            || region.length % granule != 0
            || region.guest_physical_address % granule != 0
            || region.stream_offset != packed
            || (index != 0 && region.guest_physical_address < previous_end)
        {
            return Err(invalid(
                "RAM regions must be ordered, disjoint, aligned and packed",
            ));
        }
        previous_end = end;
        packed = packed
            .checked_add(region.length)
            .ok_or_else(|| invalid("packed RAM overflows"))?;
    }
    if packed != layout.packed_length || packed > MAX_CAPTURE_RAM_BYTES {
        return Err(invalid("RAM layout packed length differs from its regions"));
    }
    Ok(LayoutGeometry {
        packed_length: packed,
        page_granule: layout.page_granule,
        regions: u32::try_from(layout.regions.len()).map_err(|_| invalid("too many regions"))?,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    use tokio_util::sync::CancellationToken;
    use vm_spec::capture::{
        CaptureDiskCopy, CaptureDiskName, CaptureRole, Sha256Digest, StreamIdentity,
        CAPTURE_EVIDENCE_FILE, CAPTURE_EVIDENCE_TEMPORARY_FILE, CAPTURE_REQUEST_FILE,
        STREAM_CHUNK_BYTES,
    };
    use vm_spec::lifecycle::LiveId;

    use crate::live::staging::{
        parse_layout, CaptureStaging, DiskCopyError, DiskCopyMethod, FileFacts, Hasher,
        RecordCommit,
    };

    struct Root(PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn root() -> Root {
        let path = std::env::temp_dir().join(format!(
            "silo-staging-{:x}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Root(path)
    }

    fn capture() -> LiveId {
        LiveId::parse(&uuid::Uuid::new_v4().hyphenated().to_string()).unwrap()
    }

    fn disk(name: &str) -> CaptureRole {
        CaptureRole::Disk(CaptureDiskName::new(name).unwrap())
    }

    #[test]
    fn staging_is_private_exclusive_and_write_once() {
        let root = root();
        let id = capture();
        let staging = CaptureStaging::create(&root.0, &id).unwrap();
        for path in [
            root.0.join("captures"),
            staging.path().to_path_buf(),
            staging.path().join("disks"),
        ] {
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o7777, 0o700, "{}", path.display());
        }
        assert!(
            CaptureStaging::create(&root.0, &id).is_err(),
            "an existing capture directory is never adopted"
        );

        let digest = staging.write_request(b"{\"plan\":1}").unwrap();
        assert_eq!(digest, Sha256Digest::of_bytes(b"{\"plan\":1}"));
        assert!(
            staging.write_request(b"{}").is_err(),
            "request.json is written once"
        );
        let request = std::fs::metadata(staging.path().join(CAPTURE_REQUEST_FILE)).unwrap();
        assert_eq!(request.mode() & 0o7777, 0o600);

        let output = staging.create_output(&CaptureRole::Ram).unwrap();
        assert_eq!(output.metadata().unwrap().len(), 0);
        assert!(staging.create_output(&CaptureRole::Ram).is_err());

        assert!(matches!(
            staging
                .commit_record(
                    CAPTURE_EVIDENCE_FILE,
                    CAPTURE_EVIDENCE_TEMPORARY_FILE,
                    b"first"
                )
                .unwrap(),
            RecordCommit::Durable
        ));
        assert!(
            staging
                .commit_record(
                    CAPTURE_EVIDENCE_FILE,
                    CAPTURE_EVIDENCE_TEMPORARY_FILE,
                    b"second"
                )
                .is_err(),
            "a committed record is never replaced"
        );
        assert_eq!(
            staging.read_record(CAPTURE_EVIDENCE_FILE).unwrap(),
            b"first"
        );
        assert!(
            !staging
                .path()
                .join(CAPTURE_EVIDENCE_TEMPORARY_FILE)
                .exists(),
            "no temporary survives a commit or a refused commit"
        );
    }

    #[test]
    fn a_preexisting_record_temporary_is_not_removed_by_a_refused_commit() {
        let root = root();
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let temporary = staging.path().join(CAPTURE_EVIDENCE_TEMPORARY_FILE);
        std::fs::write(&temporary, b"retained writer").unwrap();
        assert!(staging
            .commit_record(
                CAPTURE_EVIDENCE_FILE,
                CAPTURE_EVIDENCE_TEMPORARY_FILE,
                b"replacement"
            )
            .is_err());
        assert_eq!(std::fs::read(temporary).unwrap(), b"retained writer");
        assert!(!staging.path().join(CAPTURE_EVIDENCE_FILE).exists());
    }

    #[test]
    fn staging_refuses_a_symlinked_or_shared_captures_root() {
        let shared = root();
        let root = root();
        let elsewhere = root.0.join("elsewhere");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&elsewhere)
            .unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.0.join("captures")).unwrap();
        assert!(CaptureStaging::create(&root.0, &capture()).is_err());

        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(shared.0.join("captures"))
            .unwrap();
        // The shared root is narrowed to 0700 rather than trusted as-is.
        let staging = CaptureStaging::create(&shared.0, &capture()).unwrap();
        let mode = std::fs::metadata(shared.0.join("captures")).unwrap().mode();
        assert_eq!(mode & 0o7777, 0o700);
        drop(staging);
    }

    fn source(root: &Root, name: &str, length: u64, writes: &[(u64, &[u8])]) -> File {
        let path = root.0.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        file.set_len(length).unwrap();
        for (offset, bytes) in writes {
            file.write_all_at(bytes, *offset).unwrap();
        }
        file.sync_all().unwrap();
        file
    }

    #[test]
    fn copy_preserves_bytes_isolates_inodes_and_keeps_holes() {
        let root = root();
        let length = 64 << 20;
        let file = source(
            &root,
            "data.raw",
            length,
            &[(0, b"head"), (33 << 20, b"middle"), (length - 4, b"tail")],
        );
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let role = disk("data0");
        let method = staging
            .copy_disk(
                &role,
                &file,
                length,
                CaptureDiskCopy::Copy,
                &CancellationToken::new(),
            )
            .unwrap();
        let (sealed, facts) = staging.open_sealed(&role).unwrap();
        assert_eq!(facts.length, length);
        assert_ne!(
            (facts.device, facts.inode),
            (
                file.metadata().unwrap().dev(),
                file.metadata().unwrap().ino()
            )
        );
        let mut hasher = Hasher::new();
        let cancel = CancellationToken::new();
        let left = hasher.hash(&file, length, false, &cancel).unwrap();
        let right = hasher.hash(&sealed, length, false, &cancel).unwrap();
        assert_eq!(left.sha256, right.sha256);
        if method == DiskCopyMethod::SparseCopy {
            assert!(
                sealed.metadata().unwrap().blocks() * 512 < length,
                "zero regions stay unallocated"
            );
        }
        // Raw isolation: a later source write never reaches the sealed role.
        file.write_all_at(b"after", 0).unwrap();
        let unchanged = hasher.hash(&sealed, length, false, &cancel).unwrap();
        assert_eq!(unchanged.sha256, right.sha256);
        assert!(
            staging
                .copy_disk(&role, &file, length, CaptureDiskCopy::Copy, &cancel)
                .is_err(),
            "a sealed role is never overwritten"
        );
    }

    #[test]
    fn copy_rejects_length_mismatch_and_honours_cancellation() {
        let root = root();
        let file = source(&root, "data.raw", 1 << 20, &[(0, b"x")]);
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        assert!(staging
            .copy_disk(
                &disk("short"),
                &file,
                2 << 20,
                CaptureDiskCopy::Copy,
                &CancellationToken::new()
            )
            .is_err());
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(
            staging.copy_disk(
                &disk("cancelled"),
                &file,
                1 << 20,
                CaptureDiskCopy::Copy,
                &cancel
            ),
            Err(DiskCopyError::Cancelled)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_clone_never_falls_back_to_a_copy() {
        let root = root();
        let file = source(&root, "data.raw", 1 << 20, &[(0, b"x")]);
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let role = disk("clone");
        match staging.copy_disk(
            &role,
            &file,
            1 << 20,
            CaptureDiskCopy::Clone,
            &CancellationToken::new(),
        ) {
            // Reflink-capable filesystem: a real clone.
            Ok(method) => assert_eq!(method, DiskCopyMethod::Clone),
            Err(DiskCopyError::CloneRequired(_)) => {
                assert!(
                    staging.open_sealed(&role).is_err(),
                    "no partial or copied destination remains"
                );
            }
            Err(other) => panic!("unexpected clone failure {other}"),
        }
    }

    #[test]
    fn hashing_computes_whole_file_and_stream_identity_in_one_pass() {
        let root = root();
        let length = 2 * STREAM_CHUNK_BYTES + 4096;
        let file = source(&root, "ram", length, &[(STREAM_CHUNK_BYTES + 5, b"page")]);
        let result = Hasher::new()
            .hash(&file, length, true, &CancellationToken::new())
            .unwrap();
        let mut bytes = vec![0u8; length as usize];
        file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(result.sha256, Sha256Digest::of_bytes(&bytes));
        let mut identity = StreamIdentity::new();
        for chunk in bytes.chunks(STREAM_CHUNK_BYTES as usize) {
            identity.push_chunk(chunk).unwrap();
        }
        assert_eq!(result.stream, Some(identity.finish()));
        assert!(Hasher::new()
            .hash(&file, length + 1, true, &CancellationToken::new())
            .is_err());
    }

    #[test]
    fn sealed_files_must_be_private_single_link_regular_files() {
        let root = root();
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let mut output = staging.create_output(&CaptureRole::Execution).unwrap();
        output.write_all(b"state").unwrap();
        drop(output);
        staging.open_sealed(&CaptureRole::Execution).unwrap();
        std::fs::hard_link(staging.path().join("execution.state"), root.0.join("alias")).unwrap();
        assert!(
            staging.open_sealed(&CaptureRole::Execution).is_err(),
            "a hard-linked role is refused"
        );
        let devices = staging.path().join("devices.state");
        let mut file = File::create(&devices).unwrap();
        file.write_all(b"x").unwrap();
        std::fs::set_permissions(&devices, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(staging.open_sealed(&CaptureRole::Devices).is_err());
        std::os::unix::fs::symlink(&devices, staging.path().join("memory.ram")).unwrap();
        assert!(staging.open_sealed(&CaptureRole::Ram).is_err());
    }

    #[test]
    fn layout_geometry_is_validated() {
        let valid = br#"{"architecture":"x86_64","kind":"ram-layout","packedLength":12288,"pageGranule":4096,"regions":[{"guestPhysicalAddress":0,"length":4096,"streamOffset":0},{"guestPhysicalAddress":4096,"length":8192,"streamOffset":4096}],"schema":1,"topology":{"ramBelowGap":12288}}"#;
        let geometry = parse_layout(valid).unwrap();
        assert_eq!(geometry.packed_length, 12288);
        assert_eq!(geometry.page_granule, 4096);
        assert_eq!(geometry.regions, 2);
        let text = std::str::from_utf8(valid).unwrap();
        for bad in [
            text.replace("\"packedLength\":12288", "\"packedLength\":8192"),
            text.replace("\"streamOffset\":4096", "\"streamOffset\":8192"),
            text.replace(
                "\"guestPhysicalAddress\":4096",
                "\"guestPhysicalAddress\":0",
            ),
            text.replace("\"length\":4096", "\"length\":100"),
            text.replace("\"pageGranule\":4096", "\"pageGranule\":3000"),
            text.replace("ram-layout", "other"),
            text.replace("\"schema\":1", "\"schema\":2"),
            text.replace("{\"architecture\"", "{\"extra\":1,\"architecture\""),
        ] {
            assert!(parse_layout(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    /// Both names linked to the synchronized record: exactly the state a
    /// failed temporary unlink after a successful `linkat` leaves behind.
    fn linked_with_temporary(staging: &CaptureStaging, bytes: &[u8]) -> FileFacts {
        let identity = staging
            .write_temporary(CAPTURE_EVIDENCE_TEMPORARY_FILE, bytes)
            .unwrap();
        staging
            .link_record(CAPTURE_EVIDENCE_TEMPORARY_FILE, CAPTURE_EVIDENCE_FILE)
            .unwrap();
        identity
    }

    fn links(staging: &CaptureStaging, name: &str) -> u64 {
        std::fs::symlink_metadata(staging.path().join(name))
            .unwrap()
            .nlink()
    }

    #[test]
    fn a_lingering_temporary_link_is_removed_before_the_record_is_durable() {
        let root = root();
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let identity = linked_with_temporary(&staging, b"sealed");
        assert_eq!(links(&staging, CAPTURE_EVIDENCE_FILE), 2);
        assert!(
            staging.read_record(CAPTURE_EVIDENCE_FILE).is_err(),
            "a two-link record is not a completed record, so a directory sync alone must never seal it"
        );

        staging
            .settle_record(
                CAPTURE_EVIDENCE_FILE,
                CAPTURE_EVIDENCE_TEMPORARY_FILE,
                identity,
            )
            .unwrap();
        assert!(!staging
            .path()
            .join(CAPTURE_EVIDENCE_TEMPORARY_FILE)
            .exists());
        assert_eq!(links(&staging, CAPTURE_EVIDENCE_FILE), 1);
        assert_eq!(
            staging.read_record(CAPTURE_EVIDENCE_FILE).unwrap(),
            b"sealed"
        );
        // The bounded retry of an already settled record (removal done,
        // only the sync failed) settles again without touching the record.
        staging
            .settle_record(
                CAPTURE_EVIDENCE_FILE,
                CAPTURE_EVIDENCE_TEMPORARY_FILE,
                identity,
            )
            .unwrap();
        assert_eq!(
            staging.read_record(CAPTURE_EVIDENCE_FILE).unwrap(),
            b"sealed"
        );
    }

    #[test]
    fn unestablished_record_layouts_stay_uncertain_and_untouched() {
        // The temporary name was replaced by a file this commit never wrote:
        // it is not removed, and the record is not declared durable.
        let root = root();
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let identity = linked_with_temporary(&staging, b"sealed");
        let temporary = staging.path().join(CAPTURE_EVIDENCE_TEMPORARY_FILE);
        std::fs::remove_file(&temporary).unwrap();
        std::fs::write(&temporary, b"foreign").unwrap();
        assert!(staging
            .settle_record(
                CAPTURE_EVIDENCE_FILE,
                CAPTURE_EVIDENCE_TEMPORARY_FILE,
                identity
            )
            .is_err());
        assert_eq!(std::fs::read(&temporary).unwrap(), b"foreign");
        assert_eq!(
            std::fs::read(staging.path().join(CAPTURE_EVIDENCE_FILE)).unwrap(),
            b"sealed"
        );

        // A third link keeps the record multiply linked after the owned
        // temporary is removed: still not a completed record.
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let identity = linked_with_temporary(&staging, b"sealed");
        std::fs::hard_link(
            staging.path().join(CAPTURE_EVIDENCE_FILE),
            staging.path().join("extra"),
        )
        .unwrap();
        assert!(staging
            .settle_record(
                CAPTURE_EVIDENCE_FILE,
                CAPTURE_EVIDENCE_TEMPORARY_FILE,
                identity
            )
            .is_err());
        assert_eq!(links(&staging, CAPTURE_EVIDENCE_FILE), 2);
        assert_eq!(
            std::fs::read(staging.path().join(CAPTURE_EVIDENCE_FILE)).unwrap(),
            b"sealed"
        );

        // The final name holds another inode: nothing is removed or claimed.
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let identity = staging
            .write_temporary(CAPTURE_EVIDENCE_TEMPORARY_FILE, b"sealed")
            .unwrap();
        std::fs::write(staging.path().join(CAPTURE_EVIDENCE_FILE), b"other").unwrap();
        assert!(staging
            .settle_record(
                CAPTURE_EVIDENCE_FILE,
                CAPTURE_EVIDENCE_TEMPORARY_FILE,
                identity
            )
            .is_err());
        assert_eq!(links(&staging, CAPTURE_EVIDENCE_TEMPORARY_FILE), 1);
        assert_eq!(
            std::fs::read(staging.path().join(CAPTURE_EVIDENCE_FILE)).unwrap(),
            b"other"
        );
    }

    #[test]
    fn a_committed_record_is_its_single_link() {
        let root = root();
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        assert!(matches!(
            staging
                .commit_record(
                    CAPTURE_EVIDENCE_FILE,
                    CAPTURE_EVIDENCE_TEMPORARY_FILE,
                    b"sealed"
                )
                .unwrap(),
            RecordCommit::Durable
        ));
        assert_eq!(links(&staging, CAPTURE_EVIDENCE_FILE), 1);
        assert!(!staging
            .path()
            .join(CAPTURE_EVIDENCE_TEMPORARY_FILE)
            .exists());
    }
}
