//! Private capture staging under `--data-dir/captures/<capture-id>/`.
//!
//! Every path is resolved relative to a held directory descriptor, never by
//! re-resolving a pathname: the data directory is opened once, then each
//! component below it is created exclusively (`O_EXCL`/`mkdirat`) and opened
//! with `O_NOFOLLOW`. Directories are 0700 and files 0600, owned by the
//! monitor's euid. Records use no-replace `linkat` and single-link settlement.
//! Capture writers close without durability barriers; publication belongs to libvm.
//! RAM identity comes from the worker receipt; disk copies hash while writing.
//! Reflink seals walk extents once, then classify and hash chunks in up to eight
//! scoped workers using positional reads. Only complete ordered maps are published.
//! On Linux, monitor-written output starts nonblocking writeback after each complete
//! 8 MiB region containing writes. Holes, short tails and reflinks need no hint;
//! hint failures never affect capture success or establish durability.
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
use std::ops::Range;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use nix::errno::Errno;
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, fstat, mkdirat, Mode};
use nix::unistd::{ftruncate, geteuid, linkat, lseek, unlinkat, UnlinkatFlags, Whence};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use vm_spec::capture::{
    CaptureDiskCopy, CaptureRole, Sha256Digest, StreamMap, CAPTURES_DIRECTORY,
    CAPTURE_DISKS_DIRECTORY, CAPTURE_REQUEST_FILE, MAX_CAPTURE_RAM_BYTES, MAX_CAPTURE_RECORD_BYTES,
    STREAM_CHUNK_BYTES,
};
use vm_spec::lifecycle::LiveId;

/// Bounded copy buffer: one allocation per disk copy, never RAM-sized.
const COPY_BUFFER_BYTES: usize = STREAM_CHUNK_BYTES as usize;
/// Native canonical layouts are bounded at 64 KiB.
const MAX_LAYOUT_BYTES: u64 = 64 * 1024;

/// Non-stream authentication needs no canonical 8 MiB chunk buffer.
const WHOLE_FILE_HASH_BUFFER_BYTES: usize = 1 << 20;

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
    /// The final name is the written inode's single link and the temporary is gone.
    Complete,
    /// Visible but single-link settlement could not be established.
    /// The bytes are never overwritten or removed.
    Uncertain(io::Error),
}

/// A disk role closed for writing.
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
        let directory = private_child(&captures, capture.as_str(), true)?;
        let disks = private_child(&directory, CAPTURE_DISKS_DIRECTORY, true)?;
        Ok(Self {
            directory,
            disks,
            path: data_dir.join(CAPTURES_DIRECTORY).join(capture.as_str()),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Write and close `request.json` exactly once.
    pub(crate) fn write_request(&self, bytes: &[u8]) -> io::Result<Sha256Digest> {
        let file = File::from(openat(
            &self.directory,
            CAPTURE_REQUEST_FILE,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&file, private_mode())?;
        StagingWriter::new(&file, start_writeback).write_all(bytes)?;
        drop(file);
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
            CaptureRole::DiskMap(name) => (&self.disks, format!("{}.map.json", name.as_str())),
            other => (&self.directory, other.relative_path()),
        }
    }

    /// Clone or sparse-copy exactly `length` bytes from the held paused source.
    /// Publish its chunk map and close writers.
    /// Holes stay holes; zero data is not written into a fresh destination.
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
        let (method, map) = match self.clone_disk(source, &name) {
            Ok(()) => {
                drop(self.reopen_disk_writer(&name)?);
                let (cloned, _) = self.open_sealed(role)?;
                (
                    DiskCopyMethod::Clone,
                    seal_disk_parallel(&cloned, length, cancel)?,
                )
            }
            Err(error) if clone_unsupported(&error) => match copy {
                CaptureDiskCopy::Clone => return Err(DiskCopyError::CloneRequired(error)),
                CaptureDiskCopy::Copy => (
                    DiskCopyMethod::SparseCopy,
                    self.sparse_copy(source, &name, length, cancel)?,
                ),
            },
            Err(error) => return Err(error.into()),
        };
        let (written, facts) = self.reopen_disk_writer(&name)?;
        if facts.length != length
            || (facts.device, facts.inode) == (source_metadata.dev(), source_metadata.ino())
        {
            return Err(invalid("sealed disk differs in length or aliases its source").into());
        }
        drop(written);
        if source.metadata()?.len() != length {
            return Err(invalid("capture source changed length during its copy").into());
        }
        let CaptureRole::Disk(disk) = role else {
            return Err(invalid("disk copy requires a disk role").into());
        };
        self.publish_map(&CaptureRole::DiskMap(disk.clone()), &map)?;
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
    ) -> Result<StreamMap, DiskCopyError> {
        let destination = File::from(openat(
            &self.disks,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&destination, private_mode())?;
        let total = i64::try_from(length).map_err(|_| invalid("disk length overflow"))?;
        ftruncate(&destination, total)?;
        let map = stream_disk(source, Some(&destination), length, cancel)?;
        Ok(map)
    }

    pub(crate) fn publish_map(&self, role: &CaptureRole, map: &StreamMap) -> io::Result<()> {
        let output = self.create_output(role)?;
        map.write_canonical(&mut StagingWriter::new(&output, start_writeback))?;
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
    ///   temporary ─write─► linkat(final) ─► settle: final is ours,
    ///   remove temporary, single link ─► Complete
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
            Ok(()) => Ok(RecordCommit::Complete),
            Err(first) => {
                tracing::warn!(error = %first, name, "capture record is visible but unsettled; retrying settlement once");
                Ok(match self.settle_record(name, temporary, identity) {
                    Ok(()) => RecordCommit::Complete,
                    Err(_) => RecordCommit::Uncertain(first),
                })
            }
        }
    }

    /// Create and fill the exclusive temporary.
    fn write_temporary(&self, temporary: &str, bytes: &[u8]) -> io::Result<FileFacts> {
        let file = File::from(openat(
            &self.directory,
            temporary,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&file, private_mode())?;
        StagingWriter::new(&file, start_writeback).write_all(bytes)?;
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

    /// Establish the completed layout: the final name holds the written inode,
    /// the owned temporary is absent and the record has a single link.
    fn settle_record(&self, name: &str, temporary: &str, identity: FileFacts) -> io::Result<()> {
        let record = self.open_entry(name)?;
        if !same_inode(FileFacts::of(&record)?, identity) {
            return Err(invalid(
                "the final record name does not hold the written record",
            ));
        }
        let metadata = record.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || !matches!(metadata.nlink(), 1 | 2)
        {
            return Err(invalid(
                "record settlement requires a private one- or two-link inode",
            ));
        }
        match self.open_entry(temporary) {
            Ok(file) => {
                if metadata.nlink() != 2 || file.metadata()?.nlink() != 2 {
                    return Err(invalid("record temporary is not the sole extra link"));
                }
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

fn start_writeback(file: &File, offset: u64, length: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let offset = i64::try_from(offset).map_err(|_| invalid("writeback offset overflow"))?;
        let length = i64::try_from(length).map_err(|_| invalid("writeback length overflow"))?;
        // nix does not expose sync_file_range; this hint borrows the held fd and
        // starts writeback only, without waiting for persistence.
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
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, offset, length);
        Ok(())
    }
}

/// A monotonic staging writer. Sparse copies explicitly finish each logical
/// chunk; sequential record/map writes finish regions as bytes are accepted.
struct StagingWriter<'a, F> {
    file: &'a File,
    writeback: F,
    offset: u64,
    dirty_start: Option<u64>,
    dirty_end: u64,
}

impl<'a, F: FnMut(&File, u64, u64) -> io::Result<()>> StagingWriter<'a, F> {
    fn new(file: &'a File, writeback: F) -> Self {
        Self {
            file,
            writeback,
            offset: 0,
            dirty_start: None,
            dirty_end: 0,
        }
    }

    fn written(&mut self, offset: u64, end: u64) {
        if end > offset {
            self.dirty_start.get_or_insert(offset);
            self.dirty_end = end;
        }
    }

    fn write_all_at(&mut self, bytes: &[u8], offset: u64) -> io::Result<()> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("staging write offset overflow"))?;
        self.file.write_all_at(bytes, offset)?;
        self.written(offset, end);
        Ok(())
    }

    fn complete_through(&mut self, end: u64) {
        while let Some(start) = self.dirty_start {
            let region = start / STREAM_CHUNK_BYTES * STREAM_CHUNK_BYTES;
            let Some(stop) = region.checked_add(STREAM_CHUNK_BYTES) else {
                break;
            };
            if stop > end {
                break;
            }
            if let Err(error) = (self.writeback)(self.file, region, STREAM_CHUNK_BYTES) {
                tracing::debug!(%error, offset = region, "capture staging writeback hint failed");
            }
            self.dirty_start = (stop < self.dirty_end).then_some(stop);
        }
    }
}

impl<F: FnMut(&File, u64, u64) -> io::Result<()>> Write for StagingWriter<'_, F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.file.write_at(bytes, self.offset)?;
        let end = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| invalid("staging write offset overflow"))?;
        self.written(self.offset, end);
        self.offset = end;
        self.complete_through(end);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Writes go directly to the file; publication owns durability barriers.
        Ok(())
    }
}

/// Only data-bearing chunks need a worker. Extent indices borrow the single
/// up-front walk, including extents spanning more than one logical chunk.
struct DiskChunkWork {
    index: usize,
    extents: Range<usize>,
    digest: Option<Sha256Digest>,
}

fn classify_disk_chunk(bytes: &[u8]) -> Option<Sha256Digest> {
    if vm_spec::capture::is_all_zero(bytes) {
        None
    } else {
        Some(Sha256Digest::of_bytes(bytes))
    }
}

/// Reflink sealing never writes. Read independent chunk ranges with pread,
/// keeping at most eight reusable chunk buffers and preserving map order.
fn seal_disk_parallel(
    source: &File,
    length: u64,
    cancel: &CancellationToken,
) -> Result<StreamMap, DiskCopyError> {
    let workers = std::thread::available_parallelism().map_or(1, |count| count.get().min(8));
    seal_disk_with_workers(source, length, cancel, workers)
}

fn seal_disk_with_workers(
    source: &File,
    length: u64,
    cancel: &CancellationToken,
    workers: usize,
) -> Result<StreamMap, DiskCopyError> {
    if cancel.is_cancelled() {
        return Err(DiskCopyError::Cancelled);
    }
    let mut extents = Vec::new();
    let mut offset = 0;
    while offset < length {
        if cancel.is_cancelled() {
            return Err(DiskCopyError::Cancelled);
        }
        let Some((data, end)) = next_extent(source, offset, length)? else {
            break;
        };
        extents.push((data, end));
        offset = end;
    }
    let mut chunks = vec![None; length.div_ceil(STREAM_CHUNK_BYTES) as usize];
    let mut work = Vec::new();
    let mut first = 0;
    let mut last = 0;
    for index in 0..chunks.len() {
        let offset = index as u64 * STREAM_CHUNK_BYTES;
        let end = (offset + STREAM_CHUNK_BYTES).min(length);
        while first < extents.len() && extents[first].1 <= offset {
            first += 1;
        }
        last = last.max(first);
        while last < extents.len() && extents[last].0 < end {
            last += 1;
        }
        if first < last {
            work.push(DiskChunkWork {
                index,
                extents: first..last,
                digest: None,
            });
        }
    }
    if !work.is_empty() {
        let failed = AtomicBool::new(false);
        let (errors, received) = mpsc::sync_channel(1);
        let report_error = |error| {
            if !failed.swap(true, Ordering::Relaxed) {
                // Only the first failing worker sends, so this cannot block.
                let _ = errors.send(error);
            }
        };
        let workers = workers.clamp(1, 8).min(work.len());
        let batch_size = work.len().div_ceil(workers);
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for batch in work.chunks_mut(batch_size) {
                let extents = &extents;
                let failed = &failed;
                let report_error = &report_error;
                match std::thread::Builder::new().spawn_scoped(scope, move || {
                    if let Err(error) =
                        hash_disk_chunks(source, length, batch, extents, cancel, failed)
                    {
                        report_error(error);
                    }
                }) {
                    Ok(handle) => handles.push(handle),
                    Err(error) => {
                        report_error(error.into());
                        break;
                    }
                }
            }
            for handle in handles {
                if handle.join().is_err() {
                    report_error(io::Error::other("disk seal worker panicked").into());
                }
            }
        });
        if let Ok(error) = received.try_recv() {
            return Err(error);
        }
    }
    if cancel.is_cancelled() {
        return Err(DiskCopyError::Cancelled);
    }
    if source.metadata()?.len() != length {
        return Err(invalid("disk changed length during capture").into());
    }
    for chunk in work {
        chunks[chunk.index] = chunk.digest;
    }
    StreamMap::new(length, chunks).map_err(|error| invalid(error).into())
}

fn hash_disk_chunks(
    source: &File,
    length: u64,
    work: &mut [DiskChunkWork],
    extents: &[(u64, u64)],
    cancel: &CancellationToken,
    failed: &AtomicBool,
) -> Result<(), DiskCopyError> {
    let mut buffer = vec![0u8; length.min(STREAM_CHUNK_BYTES) as usize];
    for entry in work {
        if failed.load(Ordering::Relaxed) {
            return Ok(());
        }
        if cancel.is_cancelled() {
            return Err(DiskCopyError::Cancelled);
        }
        let offset = entry.index as u64 * STREAM_CHUNK_BYTES;
        let end = (offset + STREAM_CHUNK_BYTES).min(length);
        let chunk = &mut buffer[..(end - offset) as usize];
        chunk.fill(0);
        for &(data, data_end) in &extents[entry.extents.clone()] {
            if failed.load(Ordering::Relaxed) {
                return Ok(());
            }
            if cancel.is_cancelled() {
                return Err(DiskCopyError::Cancelled);
            }
            let start = data.max(offset);
            let stop = data_end.min(end);
            source.read_exact_at(
                &mut chunk[(start - offset) as usize..(stop - offset) as usize],
                start,
            )?;
        }
        entry.digest = classify_disk_chunk(chunk);
    }
    Ok(())
}

/// Copy and classify each disk chunk once. Whole holes need no reads.
fn stream_disk(
    source: &File,
    destination: Option<&File>,
    length: u64,
    cancel: &CancellationToken,
) -> Result<StreamMap, DiskCopyError> {
    if cancel.is_cancelled() {
        return Err(DiskCopyError::Cancelled);
    }
    let mut destination = destination.map(|file| StagingWriter::new(file, start_writeback));
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let mut chunks = Vec::with_capacity(length.div_ceil(STREAM_CHUNK_BYTES) as usize);
    let mut extent = next_extent(source, 0, length)?;
    let mut offset = 0;
    while offset < length {
        if cancel.is_cancelled() {
            return Err(DiskCopyError::Cancelled);
        }
        let end = (offset + STREAM_CHUNK_BYTES).min(length);
        if extent.is_none_or(|(data, _)| data >= end) {
            chunks.push(None);
            offset = end;
            continue;
        }
        let chunk = &mut buffer[..(end - offset) as usize];
        chunk.fill(0);
        while let Some((data, data_end)) = extent {
            if data >= end {
                break;
            }
            let start = data.max(offset);
            let stop = data_end.min(end);
            let bytes = &mut chunk[(start - offset) as usize..(stop - offset) as usize];
            source.read_exact_at(bytes, start)?;
            if let Some(destination) = destination.as_mut() {
                if !vm_spec::capture::is_all_zero(bytes) {
                    destination.write_all_at(bytes, start)?;
                }
            }
            if data_end > end {
                break;
            }
            extent = next_extent(source, data_end, length)?;
        }
        if let Some(destination) = destination.as_mut() {
            destination.complete_through(end);
        }
        chunks.push(classify_disk_chunk(chunk));
        offset = end;
    }
    if source.metadata()?.len() != length {
        return Err(invalid("disk changed length during capture").into());
    }
    StreamMap::new(length, chunks).map_err(|error| invalid(error).into())
}

/// Resolve writer receipts without opening RAM.
pub(crate) fn assemble_ram_map(
    length: u64,
    dirty: &[u8],
    digests: &[Option<Sha256Digest>],
    baseline: Option<&StreamMap>,
) -> io::Result<StreamMap> {
    vm_spec::capture::validate_dirty_chunks(length, dirty).map_err(invalid)?;
    let count = length.div_ceil(STREAM_CHUNK_BYTES) as usize;
    if digests.len() != count || baseline.is_some_and(|map| map.length() != length) {
        return Err(invalid(
            "RAM receipt or baseline length differs from its layout",
        ));
    }
    let mut chunks = Vec::with_capacity(count);
    for (index, digest) in digests.iter().enumerate() {
        if dirty[index / 8] & (1 << (index % 8)) != 0 {
            chunks.push(*digest);
        } else {
            if digest.is_some() {
                return Err(invalid(
                    "clean RAM receipt carries a non-authoritative digest",
                ));
            }
            chunks.push(
                *baseline
                    .and_then(|map| map.chunks().get(index))
                    .ok_or_else(|| invalid("clean RAM chunk lacks its baseline"))?,
            );
        }
    }
    StreamMap::new(length, chunks).map_err(invalid)
}

/// Small state roles retain whole-file SHA-256 authentication.
pub(crate) fn hash_state(
    file: &File,
    length: u64,
    cancel: &CancellationToken,
) -> io::Result<Sha256Digest> {
    use sha2::Digest as _;
    let mut hash = sha2::Sha256::new();
    let mut buffer = vec![0; WHOLE_FILE_HASH_BUFFER_BYTES];
    let mut offset = 0;
    while offset < length {
        if cancel.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "state hashing cancelled",
            ));
        }
        let span = (length - offset).min(buffer.len() as u64) as usize;
        file.read_exact_at(&mut buffer[..span], offset)?;
        hash.update(&buffer[..span]);
        offset += span as u64;
    }
    if file.metadata()?.len() != length {
        return Err(invalid("state file changed length while hashed"));
    }
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
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
    magic: String,
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
        || layout.magic != "KRUNRAML"
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
        CaptureDiskCopy, CaptureDiskName, CaptureRole, Sha256Digest, StreamIdentity, StreamMap,
        CAPTURE_EVIDENCE_FILE, CAPTURE_EVIDENCE_TEMPORARY_FILE, CAPTURE_REQUEST_FILE,
        STREAM_CHUNK_BYTES,
    };
    use vm_spec::lifecycle::LiveId;

    use crate::live::staging::{
        assemble_ram_map, parse_layout, seal_disk_parallel, seal_disk_with_workers, stream_disk,
        CaptureStaging, DiskCopyError, DiskCopyMethod, FileFacts, RecordCommit, COPY_BUFFER_BYTES,
    };
    #[cfg(target_os = "linux")]
    use crate::live::staging::{start_writeback, StagingWriter};

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
            RecordCommit::Complete
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
        let cancel = CancellationToken::new();
        let left = independent_map(&file, length);
        let right = independent_map(&sealed, length);
        assert_eq!(left, right);
        let map_bytes = std::fs::read(staging.path().join("disks/data0.map.json")).unwrap();
        assert_eq!(StreamMap::decode(&map_bytes).unwrap(), left);
        if method == DiskCopyMethod::SparseCopy {
            assert!(
                sealed.metadata().unwrap().blocks() * 512 < length,
                "zero regions stay unallocated"
            );
        }
        // Raw isolation: a later source write never reaches the sealed role.
        file.write_all_at(b"after", 0).unwrap();
        assert_eq!(independent_map(&sealed, length), right);
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
        let valid = br#"{"architecture":"x86_64","kind":"ram-layout","magic":"KRUNRAML","packedLength":12288,"pageGranule":4096,"regions":[{"guestPhysicalAddress":0,"length":4096,"streamOffset":0},{"guestPhysicalAddress":4096,"length":8192,"streamOffset":4096}],"schema":1,"topology":{"ramBelowGap":12288}}"#;
        let geometry = parse_layout(valid).unwrap();
        assert_eq!(geometry.packed_length, 12288);
        assert_eq!(geometry.page_granule, 4096);
        assert_eq!(geometry.regions, 2);
        let text = std::str::from_utf8(valid).unwrap();
        for bad in [
            text.replace("KRUNRAML", "FOREIGN!"),
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

    /// Both names linked to the written record: exactly the state a
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
    fn a_lingering_temporary_link_is_removed_before_the_record_is_complete() {
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
        // it is not removed, and the record is not declared complete.
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

        // A foreign third link is refused before removing even the owned
        // temporary: only the exact two-name window may be settled.
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
        assert_eq!(links(&staging, CAPTURE_EVIDENCE_FILE), 3);
        assert_eq!(links(&staging, CAPTURE_EVIDENCE_TEMPORARY_FILE), 3);
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
            RecordCommit::Complete
        ));
        assert_eq!(links(&staging, CAPTURE_EVIDENCE_FILE), 1);
        assert!(!staging
            .path()
            .join(CAPTURE_EVIDENCE_TEMPORARY_FILE)
            .exists());
    }

    fn independent_map(file: &File, length: u64) -> StreamMap {
        let mut bytes = vec![0; length as usize];
        file.read_exact_at(&mut bytes, 0).unwrap();
        let chunks = bytes
            .chunks(STREAM_CHUNK_BYTES as usize)
            .map(|chunk| {
                (!vm_spec::capture::is_all_zero(chunk)).then(|| Sha256Digest::of_bytes(chunk))
            })
            .collect();
        let map = StreamMap::new(length, chunks).unwrap();
        let mut identity = StreamIdentity::new();
        for chunk in bytes.chunks(STREAM_CHUNK_BYTES as usize) {
            identity.push_chunk(chunk).unwrap();
        }
        assert_eq!(map.id(), identity.finish());
        map
    }

    #[test]
    fn full_ram_receipt_builds_map_without_a_file() {
        let length = 2 * STREAM_CHUNK_BYTES + 4096;
        let digests = [
            Some(Sha256Digest::of_bytes(b"first")),
            None,
            Some(Sha256Digest::of_bytes(b"tail")),
        ];
        let map = assemble_ram_map(length, &[0b111], &digests, None).unwrap();
        assert_eq!(map.length(), length);
        assert_eq!(map.chunks(), &digests);
        let mut identity = StreamIdentity::new();
        identity
            .push_digest(STREAM_CHUNK_BYTES, digests[0])
            .unwrap();
        identity.push_digest(STREAM_CHUNK_BYTES, None).unwrap();
        identity.push_digest(4096, digests[2]).unwrap();
        assert_eq!(map.id(), identity.finish());
        assert!(assemble_ram_map(length, &[0b110], &digests, None).is_err());
        assert!(assemble_ram_map(length, &[0b111], &digests[..2], None).is_err());
        assert!(assemble_ram_map(length, &[0b1000_0111], &digests, None).is_err());
    }

    #[test]
    fn incremental_ram_receipt_resolves_clean_zero_and_tail_chunks() {
        let length = 2 * STREAM_CHUNK_BYTES + 4096;
        let old = Some(Sha256Digest::of_bytes(b"baseline"));
        let tail = Some(Sha256Digest::of_bytes(b"new-tail"));
        let baseline = StreamMap::new(length, vec![old, old, old]).unwrap();
        let receipt = [None, None, tail];
        let map = assemble_ram_map(length, &[0b110], &receipt, Some(&baseline)).unwrap();
        assert_eq!(map.chunks(), &[old, None, tail]);
        let unchanged = assemble_ram_map(length, &[0], &[None; 3], Some(&map)).unwrap();
        assert_eq!(unchanged, map);
        assert!(assemble_ram_map(length, &[0b110], &[old, None, tail], Some(&baseline)).is_err());
        assert!(assemble_ram_map(length, &[0b110], &receipt, None).is_err());
        let short = StreamMap::new(STREAM_CHUNK_BYTES, vec![old]).unwrap();
        assert!(assemble_ram_map(length, &[0b110], &receipt, Some(&short)).is_err());
    }

    #[test]
    fn capture_writes_maps_and_a_single_link_record() {
        let root = root();
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        staging.write_request(b"request").unwrap();
        let map = StreamMap::new(4096, vec![None]).unwrap();
        staging.publish_map(&CaptureRole::RamMap, &map).unwrap();
        assert!(matches!(
            staging
                .commit_record(
                    CAPTURE_EVIDENCE_FILE,
                    CAPTURE_EVIDENCE_TEMPORARY_FILE,
                    b"fork-cut",
                )
                .unwrap(),
            RecordCommit::Complete
        ));
        assert_eq!(
            staging.read_record(CAPTURE_EVIDENCE_FILE).unwrap(),
            b"fork-cut"
        );
        assert_eq!(
            std::fs::read(staging.path().join("memory.map.json")).unwrap(),
            map.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn sparse_copy_identities_cover_empty_holes_crossings_and_data_tails() {
        let root = root();
        let chunk = STREAM_CHUNK_BYTES;
        type Writes<'a> = &'a [(u64, &'a [u8])];
        let cases: &[(u64, Writes)] = &[
            (0, &[]),
            (1, &[]),
            (70, &[]),
            (2 * chunk + 19, &[]),
            (2 * chunk + 19, &[(17, b"data before trailing hole")]),
            (
                4 * chunk + 19,
                &[
                    (chunk - 2, b"crosses a chunk boundary"),
                    (3 * chunk + 4097, b"mixed span"),
                    (4 * chunk + 15, b"tail"),
                ],
            ),
        ];
        for (index, (length, writes)) in cases.iter().enumerate() {
            let file = source(&root, &format!("source-{index}"), *length, writes);
            let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
            let map = staging
                .sparse_copy(&file, "data0.raw", *length, &CancellationToken::new())
                .unwrap();
            assert_eq!(map, independent_map(&file, *length), "case {index}");
            let (sealed, _) = staging.open_sealed(&disk("data0")).unwrap();
            assert_eq!(map, independent_map(&sealed, *length), "case {index}");
        }
    }

    #[test]
    fn sparse_copy_preserves_completed_runs_mixed_holes_and_short_tail() {
        let root = root();
        let length = 3 * STREAM_CHUNK_BYTES + 71;
        let data = vec![0x91; STREAM_CHUNK_BYTES as usize + 4096];
        let zeroes = vec![0; COPY_BUFFER_BYTES];
        drop(source(
            &root,
            "copy-source",
            length,
            &[
                (3, &data),
                (STREAM_CHUNK_BYTES + (2 << 20), &zeroes),
                (length - 3, b"end"),
            ],
        ));
        let file = File::open(root.0.join("copy-source")).unwrap();
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let map = staging
            .sparse_copy(&file, "data0.raw", length, &CancellationToken::new())
            .unwrap();
        let (sealed, facts) = staging.open_sealed(&disk("data0")).unwrap();
        assert_eq!(facts.length, length);
        assert_eq!(map, independent_map(&file, length));
        assert_eq!(map, independent_map(&sealed, length));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staging_writer_hints_completed_sparse_regions_once() {
        let root = root();
        let chunk = STREAM_CHUNK_BYTES;
        let length = 3 * chunk + 17;
        let output = source(&root, "hint-output", length, &[]);
        let mut calls = Vec::new();
        let mut writer = StagingWriter::new(&output, |file: &File, offset, length| {
            // Both extents must be written before this region is hinted.
            let mut tail = [0; 4];
            file.read_exact_at(&mut tail, offset + chunk - 4).unwrap();
            assert_eq!(&tail, b"last");
            calls.push((offset, length));
            start_writeback(file, offset, length)
        });
        writer.write_all_at(b"first", 13).unwrap();
        writer.complete_through(chunk - 1);
        writer.write_all_at(b"last", chunk - 4).unwrap();
        writer.complete_through(chunk);
        writer.write_all_at(b"middle", chunk + 4096).unwrap();
        writer.write_all_at(b"last", 2 * chunk - 4).unwrap();
        writer.complete_through(2 * chunk);
        // A completely sparse region and the final short tail need no hint.
        writer.complete_through(3 * chunk);
        writer.write_all_at(b"tail", length - 4).unwrap();
        writer.complete_through(length);
        assert_eq!(calls, vec![(0, chunk), (chunk, chunk)]);
        let mut head = [0; 5];
        output.read_exact_at(&mut head, 13).unwrap();
        assert_eq!(&head, b"first");
        let mut tail = [0; 4];
        output.read_exact_at(&mut tail, length - 4).unwrap();
        assert_eq!(&tail, b"tail");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staging_writer_hints_each_sequential_region_on_a_real_file() {
        let root = root();
        let chunk = STREAM_CHUNK_BYTES;
        let length = 2 * chunk + 17;
        let data = vec![0x73; length as usize];
        let mut input = source(&root, "hint-input", length, &[(0, &data)]);
        let output = source(&root, "hint-output", 0, &[]);
        let mut calls = Vec::new();
        let mut writer = StagingWriter::new(&output, |file: &File, offset, length| {
            let mut last = [0];
            file.read_exact_at(&mut last, offset + length - 1).unwrap();
            assert_eq!(last, [0x73], "region must be written before hinting");
            calls.push((offset, length));
            start_writeback(file, offset, length)
        });
        assert_eq!(std::io::copy(&mut input, &mut writer).unwrap(), length);
        writer.flush().unwrap();
        assert_eq!(calls, vec![(0, chunk), (chunk, chunk)]);
        assert_eq!(
            independent_map(&output, length),
            independent_map(&input, length)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staging_writer_ignores_syscall_einval_and_finishes_copy() {
        let root = root();
        let chunk = STREAM_CHUNK_BYTES;
        let length = 2 * chunk + 17;
        let data = vec![0x91; length as usize];
        let mut input = source(&root, "einval-input", length, &[(0, &data)]);
        let output = source(&root, "einval-output", 0, &[]);
        let mut calls = Vec::new();
        let mut writer = StagingWriter::new(&output, |file: &File, offset, length| {
            calls.push((offset, length));
            // The same syscall on this real tempfile rejects an overflowing
            // signed range. No filesystem or syscall result is mocked.
            let error = start_writeback(file, i64::MAX as u64, length).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(nix::errno::Errno::EINVAL as i32));
            Err(error)
        });
        assert_eq!(std::io::copy(&mut input, &mut writer).unwrap(), length);
        assert_eq!(calls, vec![(0, chunk), (chunk, chunk)]);
        assert_eq!(
            independent_map(&output, length),
            independent_map(&input, length)
        );
    }

    #[test]
    fn parallel_disk_seal_matches_sequential_and_copy_maps() {
        let root = root();
        let chunk = STREAM_CHUNK_BYTES;
        let length = 4 * chunk + 137;
        let zeros = [0; 4096];
        let data = vec![0x91; chunk as usize];
        let file = source(
            &root,
            "parallel-source",
            length,
            &[
                (13, b"head"),
                (4096, &zeros),
                (2 * chunk + 4096, &zeros),
                (3 * chunk, &data),
                (4 * chunk - 2, b"cross-boundary"),
                (length - 4, b"tail"),
            ],
        );
        let cancel = CancellationToken::new();
        let sequential = stream_disk(&file, None, length, &cancel).unwrap();
        assert_eq!(sequential, independent_map(&file, length));
        assert_eq!(sequential.chunks()[1], None, "whole hole is zero");
        assert_eq!(
            sequential.chunks()[2],
            None,
            "allocated zero pages are zero"
        );
        for workers in [1, 2, 8] {
            let parallel = seal_disk_with_workers(&file, length, &cancel, workers).unwrap();
            assert_eq!(parallel, sequential, "workers={workers}");
            assert_eq!(
                parallel.canonical_bytes().unwrap(),
                sequential.canonical_bytes().unwrap(),
                "workers={workers}"
            );
            assert_eq!(parallel.id(), sequential.id());
        }
        let output = source(&root, "parallel-copy", length, &[]);
        let copied = stream_disk(&file, Some(&output), length, &cancel).unwrap();
        assert_eq!(copied, sequential);
        assert_eq!(independent_map(&output, length), sequential);
    }

    #[test]
    fn parallel_disk_seal_handles_empty_and_one_chunk_files() {
        let root = root();
        let chunk = STREAM_CHUNK_BYTES;
        type Writes<'a> = &'a [(u64, &'a [u8])];
        let cases: &[(u64, Writes)] = &[
            (0, &[]),
            (chunk, &[]),
            (chunk, &[(4096, &[0; 4096])]),
            (chunk, &[(0, b"head"), (chunk - 4, b"tail")]),
            (17, &[]),
            (17, &[(13, b"tail")]),
            (3 * chunk + 17, &[]),
        ];
        for (index, (length, writes)) in cases.iter().enumerate() {
            let file = source(&root, &format!("small-seal-{index}"), *length, writes);
            let cancel = CancellationToken::new();
            let parallel = seal_disk_parallel(&file, *length, &cancel).unwrap();
            assert_eq!(parallel, independent_map(&file, *length), "case={index}");
            assert_eq!(
                parallel,
                stream_disk(&file, None, *length, &cancel).unwrap(),
                "case={index}"
            );
        }
    }

    #[test]
    fn parallel_disk_seal_propagates_worker_read_error_without_a_map() {
        let root = root();
        let chunk = STREAM_CHUNK_BYTES;
        let length = 3 * chunk;
        drop(source(
            &root,
            "unreadable-seal",
            length,
            &[(0, b"head"), (chunk, b"middle"), (2 * chunk, b"tail")],
        ));
        // Extent discovery works on this real write-only regular descriptor,
        // but each worker's positional read fails with EBADF.
        let file = OpenOptions::new()
            .write(true)
            .open(root.0.join("unreadable-seal"))
            .unwrap();
        let error =
            seal_disk_with_workers(&file, length, &CancellationToken::new(), 3).unwrap_err();
        let DiskCopyError::Io(error) = error else {
            panic!("expected worker read error, got {error}");
        };
        assert_eq!(error.raw_os_error(), Some(nix::errno::Errno::EBADF as i32));
    }

    #[test]
    fn parallel_disk_seal_honours_cancellation() {
        let root = root();
        let file = source(&root, "cancelled-seal", STREAM_CHUNK_BYTES, &[(0, b"head")]);
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(
            seal_disk_parallel(&file, STREAM_CHUNK_BYTES, &cancel),
            Err(DiskCopyError::Cancelled)
        ));
    }
}
