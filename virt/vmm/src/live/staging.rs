//! Private capture staging under `--data-dir/captures/<capture-id>/`.
//!
//! Every path is resolved relative to a held directory descriptor, never by
//! re-resolving a pathname: the data directory is opened once, then each
//! component below it is created exclusively (`O_EXCL`/`mkdirat`) and opened
//! with `O_NOFOLLOW`. Directories are 0700 and files 0600, owned by the
//! monitor's euid. Records use no-replace `linkat` and single-link settlement.
//! Capture writers close without durability barriers; publication belongs to libvm.
//! Snapshot RAM identity comes from the worker receipt; identified disk copies
//! hash while writing. Owned fork copies only bytes, never hashes or map nodes.
//! Snapshot reflinks are identified after continuation, using retained dirty
//! coverage or a complete allocated-extent scan when identity coverage is unknown.
//! On Linux, monitor-written output starts nonblocking writeback after each complete
//! 8 MiB region containing writes. Holes, short tails and reflinks need no hint;
//! hint failures never affect capture success or establish durability.
//!
//! ```text
//!   data-dir ─► captures/ ─► <id>/ ─┬─ request.json (once, before freeze)
//!                                   ├─ execution.state devices.state
//!                                   ├─ memory.ram memory-layout.json
//!                                   ├─ disks/ ─► <name>.raw (clone or copy)
//!                                   ├─ vm.capture-cut.json    (identity pending)
//!                                   ├─ vm.capture.json        (once)
//!                                   └─ vm.capture-source.json (once)
//! ```
use std::fs::File;
use std::io::{self, Write};
use std::ops::Range;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;

use nix::errno::Errno;
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, fstat, mkdirat, Mode};
use nix::unistd::{ftruncate, geteuid, linkat, lseek, unlinkat, UnlinkatFlags, Whence};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use vm_spec::capture::{
    CaptureDiskCopy, CaptureDiskStats, CaptureRole, DiskFullScanReason, DiskTrackingReceipt,
    Sha256Digest, CAPTURES_DIRECTORY, CAPTURE_DISKS_DIRECTORY, CAPTURE_REQUEST_FILE,
    MAX_CAPTURE_RAM_BYTES, MAX_CAPTURE_RECORD_BYTES, STREAM_CHUNK_BYTES,
};
use vm_spec::lifecycle::LiveId;
use vm_spec::stream_map::{
    build_sorted, Chunk, ChunkChange, ChunkSize, MapError, NodeSink, NodeSource, PresentChunk,
    StreamRoot, MAX_NODE_BYTES,
};

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
    nodes: std::sync::Arc<File>,
    retained_nodes: std::sync::Arc<File>,
    pool_nodes: std::sync::Mutex<Option<std::sync::Arc<File>>>,
    node_allocation: std::sync::Arc<AtomicU64>,
    node_count: std::sync::Arc<AtomicU64>,
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

pub(crate) fn hashed_map_bytes(map: &StreamRoot, nodes: &mut impl NodeSource) -> io::Result<u64> {
    map.present_chunks(nodes)
        .try_fold(0, |total, chunk| {
            let range = map.chunk_range(chunk?.index)?;
            Ok::<_, MapError>(total + range.end - range.start)
        })
        .map_err(io::Error::other)
}

#[derive(Debug, Clone)]
pub(crate) struct MapNodeFiles {
    retained: std::sync::Arc<File>,
    pool: Option<std::sync::Arc<File>>,
}
impl MapNodeFiles {
    pub(crate) fn open(path: &str) -> io::Result<Self> {
        let directory = std::sync::Arc::new(File::from(open(
            Path::new(path),
            directory_flags(),
            Mode::empty(),
        )?));
        Ok(Self {
            retained: directory,
            pool: None,
        })
    }
}

fn node_name(digest: Sha256Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(64);
    for byte in digest.as_bytes() {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 15)]));
    }
    name
}

impl NodeSource for MapNodeFiles {
    fn read_node(
        &mut self,
        digest: Sha256Digest,
        output: &mut [u8; MAX_NODE_BYTES],
    ) -> Result<usize, MapError> {
        let name = node_name(digest);
        for directory in std::iter::once(&self.retained).chain(self.pool.iter()) {
            match openat(
                directory.as_ref(),
                name.as_str(),
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => {
                    let file = File::from(fd);
                    let metadata = file.metadata()?;
                    if !metadata.is_file() {
                        return Err(MapError::Io(invalid("map node is not a regular file")));
                    }
                    if metadata.len() > MAX_NODE_BYTES as u64 {
                        return Err(MapError::NodeTooLarge(metadata.len() as usize));
                    }
                    let length = metadata.len() as usize;
                    file.read_exact_at(&mut output[..length], 0)?;
                    return Ok(length);
                }
                Err(Errno::ENOENT) => {}
                Err(error) => return Err(MapError::Io(error.into())),
            }
        }
        Err(MapError::MissingNode(digest))
    }
}

pub(crate) struct MapNodeWriter {
    staged: std::sync::Arc<File>,
    retained: std::sync::Arc<File>,
    allocation: std::sync::Arc<AtomicU64>,
    count: std::sync::Arc<AtomicU64>,
    retain_locally: bool,
}

impl NodeSink for MapNodeWriter {
    fn write_node(&mut self, bytes: &[u8]) -> Result<Sha256Digest, MapError> {
        if bytes.len() > MAX_NODE_BYTES {
            return Err(MapError::NodeTooLarge(bytes.len()));
        }
        let digest = Sha256Digest::of_bytes(bytes);
        let name = node_name(digest);
        match openat(
            self.staged.as_ref(),
            name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                fchmod(&file, private_mode()).map_err(io::Error::from)?;
                file.write_all_at(bytes, 0)?;
                self.count.fetch_add(1, Ordering::Relaxed);
                self.allocation.fetch_add(
                    file.metadata()?.blocks().saturating_mul(512),
                    Ordering::Relaxed,
                );
            }
            Err(Errno::EEXIST) => {
                let file = File::from(
                    openat(
                        self.staged.as_ref(),
                        name.as_str(),
                        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(io::Error::from)?,
                );
                let mut existing = [0; MAX_NODE_BYTES];
                if file.metadata()?.len() != bytes.len() as u64 {
                    return Err(MapError::Io(invalid(
                        "staged map node has a conflicting length",
                    )));
                }
                file.read_exact_at(&mut existing[..bytes.len()], 0)?;
                if &existing[..bytes.len()] != bytes {
                    return Err(MapError::DigestMismatch {
                        expected: digest,
                        actual: Sha256Digest::of_bytes(&existing[..bytes.len()]),
                    });
                }
            }
            Err(error) => return Err(MapError::Io(error.into())),
        }
        if !self.retain_locally {
            return Ok(digest);
        }
        match linkat(
            self.staged.as_ref(),
            name.as_str(),
            self.retained.as_ref(),
            name.as_str(),
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(Errno::EEXIST) => {
                let mut source = MapNodeFiles {
                    retained: self.retained.clone(),
                    pool: None,
                };
                let mut existing = [0; MAX_NODE_BYTES];
                let length = source.read_node(digest, &mut existing)?;
                if &existing[..length] != bytes {
                    return Err(MapError::DigestMismatch {
                        expected: digest,
                        actual: Sha256Digest::of_bytes(&existing[..length]),
                    });
                }
            }
            Err(error) => return Err(MapError::Io(error.into())),
        }
        Ok(digest)
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
        let nodes = private_child(
            &directory,
            vm_spec::capture::CAPTURE_MAP_NODES_DIRECTORY,
            true,
        )?;
        let retained_nodes =
            private_child(&data, vm_spec::capture::CAPTURE_MAP_NODES_DIRECTORY, false)?;
        Ok(Self {
            directory,
            disks,
            path: data_dir.join(CAPTURES_DIRECTORY).join(capture.as_str()),
            nodes: std::sync::Arc::new(File::from(nodes)),
            retained_nodes: std::sync::Arc::new(File::from(retained_nodes)),
            pool_nodes: std::sync::Mutex::new(None),
            node_allocation: std::sync::Arc::new(AtomicU64::new(0)),
            node_count: std::sync::Arc::new(AtomicU64::new(0)),
        })
    }
    pub(crate) fn set_node_store(&self, path: Option<&str>) -> io::Result<()> {
        let pool = path
            .map(|path| {
                open(Path::new(path), directory_flags(), Mode::empty())
                    .map(File::from)
                    .map(std::sync::Arc::new)
            })
            .transpose()?;
        *self
            .pool_nodes
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = pool;
        Ok(())
    }

    pub(crate) fn node_source(&self) -> MapNodeFiles {
        let pool = self
            .pool_nodes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        MapNodeFiles {
            retained: if pool.is_some() {
                self.nodes.clone()
            } else {
                self.retained_nodes.clone()
            },
            pool,
        }
    }

    pub(crate) fn node_sink(&self) -> MapNodeWriter {
        MapNodeWriter {
            staged: self.nodes.clone(),
            retained: self.retained_nodes.clone(),
            allocation: self.node_allocation.clone(),
            count: self.node_count.clone(),
            retain_locally: self
                .pool_nodes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_none(),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn map_nodes_written(&self) -> u64 {
        self.node_count.load(Ordering::Relaxed)
    }

    /// Write and close `request.json` exactly once.
    pub(crate) fn write_request(&self, bytes: &[u8]) -> io::Result<Sha256Digest> {
        self.write_owned_request(bytes)?;
        Ok(Sha256Digest::of_bytes(bytes))
    }

    pub(crate) fn write_owned_request(&self, bytes: &[u8]) -> io::Result<()> {
        let file = File::from(openat(
            &self.directory,
            CAPTURE_REQUEST_FILE,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&file, private_mode())?;
        StagingWriter::new(&file, start_writeback).write_all(bytes)?;
        drop(file);
        Ok(())
    }

    /// Allocated bytes of the private `request.json`, reopened read-only
    /// through the held directory.
    pub(crate) fn request_allocation(&self) -> io::Result<u64> {
        self.open_entry_allocation(CAPTURE_REQUEST_FILE)
    }

    pub(crate) fn open_entry_allocation(&self, name: &str) -> io::Result<u64> {
        let file = self.open_entry(name)?;
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

    pub(crate) fn seal_owned(&self, role: &CaptureRole) -> io::Result<(File, FileFacts)> {
        let (file, facts) = self.open_sealed(role)?;
        #[cfg(target_os = "linux")]
        crate::restore::inputs::reject_surviving_writer(&file)?;
        fchmod(&file, Mode::S_IRUSR)?;
        Ok((file, facts))
    }

    pub(crate) fn open_owned(&self, role: &CaptureRole) -> io::Result<(File, FileFacts)> {
        let (directory, name) = self.locate(role);
        let file = File::from(openat(
            directory,
            name.as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o400
            || metadata.nlink() != 1
        {
            return Err(invalid(
                "owned member is not a private immutable single-link regular file",
            ));
        }
        let facts = FileFacts::of(&file)?;
        Ok((file, facts))
    }

    fn locate(&self, role: &CaptureRole) -> (&OwnedFd, String) {
        match role {
            CaptureRole::Disk(name) => (&self.disks, name.file_name()),
            CaptureRole::DiskMap(name) => (&self.disks, format!("{}.root", name.as_str())),
            other => (&self.directory, other.relative_path()),
        }
    }

    /// Clone or sparse-copy exactly `length` bytes from the held paused source.
    /// Identified copies publish an inline map; owned copies never hash bytes.
    /// Holes stay holes; zero data is not written into a fresh destination.
    pub(crate) fn copy_disk(
        &self,
        role: &CaptureRole,
        source: &File,
        length: u64,
        copy: CaptureDiskCopy,
        identity: vm_spec::capture::CaptureIdentityPolicy,
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
            Ok(()) => (DiskCopyMethod::Clone, None),
            Err(error) if clone_unsupported(&error) => match copy {
                CaptureDiskCopy::Clone => return Err(DiskCopyError::CloneRequired(error)),
                CaptureDiskCopy::Copy => {
                    if identity == vm_spec::capture::CaptureIdentityPolicy::None {
                        self.sparse_copy_owned(source, &name, length, cancel)?;
                        (DiskCopyMethod::SparseCopy, None)
                    } else {
                        (
                            DiskCopyMethod::SparseCopy,
                            Some(self.sparse_copy(source, &name, length, cancel)?),
                        )
                    }
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
        drop(written);
        if source.metadata()?.len() != length {
            return Err(invalid("capture source changed length during its copy").into());
        }
        let CaptureRole::Disk(disk) = role else {
            return Err(invalid("disk copy requires a disk role").into());
        };
        if let Some(map) = map {
            self.publish_map(&CaptureRole::DiskMap(disk.clone()), &map)?;
        }
        Ok(method)
    }

    pub(crate) fn disk_cut(
        &self,
        name: &vm_spec::capture::CaptureDiskName,
    ) -> io::Result<vm_spec::capture::CaptureDiskCut> {
        let (file, facts) = self.open_sealed(&CaptureRole::Disk(name.clone()))?;
        let metadata = file.metadata()?;
        Ok(vm_spec::capture::CaptureDiskCut {
            name: name.clone(),
            device: facts.device,
            inode: facts.inode,
            length: facts.length,
            mode: metadata.mode(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            tracking_receipt: None,
        })
    }

    /// Hash immutable dirty chunks only when complete predecessor authority is held.
    pub(crate) fn complete_disk_identity(
        &self,
        cut: &vm_spec::capture::CaptureDiskCut,
        baseline: Option<&StreamRoot>,
        tracking_eligible: bool,
        cancel: &CancellationToken,
    ) -> Result<(StreamRoot, CaptureDiskStats), DiskCopyError> {
        let fingerprint = self.disk_cut(&cut.name)?;
        if (
            fingerprint.device,
            fingerprint.inode,
            fingerprint.length,
            fingerprint.mode,
            fingerprint.changed_seconds,
            fingerprint.changed_nanoseconds,
        ) != (
            cut.device,
            cut.inode,
            cut.length,
            cut.mode,
            cut.changed_seconds,
            cut.changed_nanoseconds,
        ) {
            return Err(invalid("retained disk clone changed before identity completion").into());
        }
        let (file, _) = self.open_sealed(&CaptureRole::Disk(cut.name.clone()))?;
        let (map, bytes_hashed, reason) = match cut.tracking_receipt.as_ref() {
            Some(receipt)
                if tracking_eligible
                    && receipt.validate().is_ok()
                    && receipt.invalid_reason.is_none()
                    && baseline.is_some_and(|map| {
                        map.length() == cut.length
                            && receipt.seed.length == cut.length
                            && Some(map.id()) == receipt.seed.baseline
                    }) =>
            {
                let baseline = baseline.ok_or_else(|| invalid("disk baseline is missing"))?;
                let (map, bytes) = seal_disk_incremental(
                    &file,
                    baseline,
                    receipt,
                    cancel,
                    &mut self.node_source(),
                    &mut self.node_sink(),
                )?;
                (map, bytes, None)
            }
            receipt => {
                let reason = if !tracking_eligible {
                    DiskFullScanReason::External
                } else {
                    match receipt {
                        Some(receipt) => match receipt.invalid_reason {
                            Some(reason) => DiskFullScanReason::InvalidReceipt { reason },
                            None if receipt.validate().is_err() => {
                                DiskFullScanReason::InvalidReceipt {
                                    reason: vm_spec::capture::DiskTrackingInvalidReason::Lost,
                                }
                            }
                            None => DiskFullScanReason::MissingBaseline,
                        },
                        None => DiskFullScanReason::Untracked,
                    }
                };
                let mut sink = self.node_sink();
                let (map, bytes) = seal_disk_parallel(&file, cut.length, cancel, &mut sink)?;
                (map, bytes, Some(reason))
            }
        };
        if self.disk_cut(&cut.name)? != fingerprint {
            return Err(invalid("retained disk clone changed during identity completion").into());
        }
        if cancel.is_cancelled() {
            return Err(DiskCopyError::Cancelled);
        }
        self.publish_map(&CaptureRole::DiskMap(cut.name.clone()), &map)?;
        let stats = CaptureDiskStats {
            name: cut.name.clone(),
            dirty_chunks: cut
                .tracking_receipt
                .as_ref()
                .map_or(0, |receipt| receipt.dirty_chunks),
            total_chunks: cut.length.div_ceil(STREAM_CHUNK_BYTES),
            bytes_hashed,
            baseline_reused: reason.is_none(),
            full_scan_reason: reason,
        };
        Ok((map, stats))
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
    ) -> Result<StreamRoot, DiskCopyError> {
        let destination = File::from(openat(
            &self.disks,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            private_mode(),
        )?);
        fchmod(&destination, private_mode())?;
        let total = i64::try_from(length).map_err(|_| invalid("disk length overflow"))?;
        ftruncate(&destination, total)?;
        let (map, _) = stream_disk(
            source,
            Some(&destination),
            length,
            cancel,
            &mut self.node_sink(),
        )?;
        Ok(map)
    }

    fn sparse_copy_owned(
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
        ftruncate(
            &destination,
            i64::try_from(length).map_err(|_| invalid("disk length overflow"))?,
        )?;
        copy_sparse_bytes(source, &destination, length, cancel)
    }

    pub(crate) fn publish_map(&self, role: &CaptureRole, map: &StreamRoot) -> io::Result<()> {
        let output = self.create_output(role)?;
        map.write_canonical(&mut StagingWriter::new(&output, start_writeback))
            .map_err(io::Error::other)?;
        Ok(())
    }

    /// Allocated bytes of both held directories.
    pub(crate) fn directory_allocation(&self) -> io::Result<u64> {
        let mut total = self.node_allocation.load(Ordering::Relaxed);
        for directory in [
            self.directory.as_fd(),
            self.disks.as_fd(),
            self.nodes.as_fd(),
        ] {
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

fn seal_disk_incremental(
    source: &File,
    baseline: &StreamRoot,
    receipt: &DiskTrackingReceipt,
    cancel: &CancellationToken,
    nodes: &mut impl NodeSource,
    sink: &mut impl NodeSink,
) -> Result<(StreamRoot, u64), DiskCopyError> {
    receipt.validate().map_err(invalid)?;
    if receipt.invalid_reason.is_some()
        || baseline.chunk_size() != ChunkSize::DISK
        || receipt.seed.length != baseline.length()
        || receipt.seed.baseline != Some(baseline.id())
        || source.metadata()?.len() != baseline.length()
    {
        return Err(invalid("disk predecessor authority differs from coverage").into());
    }
    if cancel.is_cancelled() {
        return Err(DiskCopyError::Cancelled);
    }
    let dirty = receipt
        .runs
        .iter()
        .flat_map(|run| run.first_chunk..run.first_chunk + run.chunk_count)
        .collect::<Vec<_>>();
    if dirty.is_empty() {
        return Ok((*baseline, 0));
    }
    // Same bound as the full scan: at most eight chunk buffers, one per worker.
    let workers = std::thread::available_parallelism()
        .map_or(1, |count| count.get().min(8))
        .min(dirty.len());
    let hash_batch =
        |batch: &[u64]| -> Result<Vec<(u64, Option<Sha256Digest>, u64)>, DiskCopyError> {
            let mut buffer = vec![0u8; baseline.length().min(STREAM_CHUNK_BYTES) as usize];
            let mut hashed = Vec::with_capacity(batch.len());
            for &index in batch {
                if cancel.is_cancelled() {
                    return Err(DiskCopyError::Cancelled);
                }
                let offset = index * STREAM_CHUNK_BYTES;
                let length = (baseline.length() - offset).min(STREAM_CHUNK_BYTES) as usize;
                let chunk = &mut buffer[..length];
                source.read_exact_at(chunk, offset)?;
                hashed.push((index, classify_disk_chunk(chunk), length as u64));
            }
            Ok(hashed)
        };
    let batches = std::thread::scope(|scope| {
        let handles = dirty
            .chunks(dirty.len().div_ceil(workers))
            .map(|batch| scope.spawn(|| hash_batch(batch)))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| DiskCopyError::from(invalid("disk identity worker panicked")))?
            })
            .collect::<Result<Vec<_>, DiskCopyError>>()
    })?;
    let mut bytes_hashed = 0;
    let changes = batches
        .into_iter()
        .flatten()
        .map(|(index, digest, length)| {
            if digest.is_some() {
                bytes_hashed += length;
            }
            Ok(ChunkChange {
                index,
                value: digest.map_or(Chunk::Zero, Chunk::Data),
            })
        });
    let root = baseline
        .update_sorted(changes, nodes, sink)
        .map_err(io::Error::other)?;
    Ok((root, bytes_hashed))
}

/// Reflink sealing never writes. Read independent chunk ranges with pread,
/// keeping at most eight reusable chunk buffers and preserving map order.
fn seal_disk_parallel(
    source: &File,
    length: u64,
    cancel: &CancellationToken,
    sink: &mut impl NodeSink,
) -> Result<(StreamRoot, u64), DiskCopyError> {
    let workers = std::thread::available_parallelism().map_or(1, |count| count.get().min(8));
    seal_disk_with_workers(source, length, cancel, workers, sink)
}

fn seal_disk_with_workers(
    source: &File,
    length: u64,
    cancel: &CancellationToken,
    workers: usize,
    sink: &mut impl NodeSink,
) -> Result<(StreamRoot, u64), DiskCopyError> {
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
    let mut work = Vec::new();
    let mut first = 0;
    let mut last = 0;
    let mut index = 0usize;
    while first < extents.len() {
        index = index.max((extents[first].0 / STREAM_CHUNK_BYTES) as usize);
        let offset = index as u64 * STREAM_CHUNK_BYTES;
        let end = (offset + STREAM_CHUNK_BYTES).min(length);
        while first < extents.len() && extents[first].1 <= offset {
            first += 1;
        }
        if first == extents.len() {
            break;
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
        index += 1;
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
    let mut bytes_hashed = 0;
    let present = work.into_iter().filter_map(|chunk| {
        chunk.digest.map(|digest| {
            bytes_hashed +=
                (length - chunk.index as u64 * STREAM_CHUNK_BYTES).min(STREAM_CHUNK_BYTES);
            Ok(PresentChunk {
                index: chunk.index as u64,
                digest,
            })
        })
    });
    let root = build_sorted(length, ChunkSize::DISK, present, sink).map_err(io::Error::other)?;
    Ok((root, bytes_hashed))
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

/// Copy only allocated bytes. No digest or map is constructed for local cuts.
fn copy_sparse_bytes(
    source: &File,
    destination: &File,
    length: u64,
    cancel: &CancellationToken,
) -> Result<(), DiskCopyError> {
    let mut buffer = vec![0u8; length.min(COPY_BUFFER_BYTES as u64) as usize];
    let mut destination = StagingWriter::new(destination, start_writeback);
    let mut offset = 0;
    while let Some((start, end)) = next_extent(source, offset, length)? {
        offset = start;
        while offset < end {
            if cancel.is_cancelled() {
                return Err(DiskCopyError::Cancelled);
            }
            let stop = (offset + COPY_BUFFER_BYTES as u64).min(end);
            let bytes = &mut buffer[..(stop - offset) as usize];
            source.read_exact_at(bytes, offset)?;
            if !vm_spec::capture::is_all_zero(bytes) {
                destination.write_all_at(bytes, offset)?;
            }
            destination.complete_through(stop);
            offset = stop;
        }
    }
    if cancel.is_cancelled() {
        return Err(DiskCopyError::Cancelled);
    }
    if source.metadata()?.len() != length {
        return Err(invalid("disk changed length during capture").into());
    }
    Ok(())
}
/// Copy and classify each disk chunk once. Whole holes need no reads.
fn stream_disk(
    source: &File,
    destination: Option<&File>,
    length: u64,
    cancel: &CancellationToken,
    sink: &mut impl NodeSink,
) -> Result<(StreamRoot, u64), DiskCopyError> {
    if cancel.is_cancelled() {
        return Err(DiskCopyError::Cancelled);
    }
    let mut destination = destination.map(|file| StagingWriter::new(file, start_writeback));
    let mut buffer = vec![0u8; length.min(COPY_BUFFER_BYTES as u64) as usize];
    let mut extent = next_extent(source, 0, length)?;
    let mut offset = 0;
    let mut bytes_hashed = 0;
    let present = std::iter::from_fn(|| {
        let mut next = || -> Result<Option<PresentChunk>, MapError> {
            while let Some((data, _)) = extent {
                if cancel.is_cancelled() {
                    return Err(MapError::Io(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "disk copy cancelled",
                    )));
                }
                offset = offset.max(data / STREAM_CHUNK_BYTES * STREAM_CHUNK_BYTES);
                let end = (offset + STREAM_CHUNK_BYTES).min(length);
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
                let index = offset / STREAM_CHUNK_BYTES;
                offset = end;
                if let Some(digest) = classify_disk_chunk(chunk) {
                    bytes_hashed += chunk.len() as u64;
                    return Ok(Some(PresentChunk { index, digest }));
                }
            }
            Ok(None)
        };
        match next() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    });
    let root = build_sorted(length, ChunkSize::DISK, present, sink).map_err(io::Error::other);
    if cancel.is_cancelled() {
        return Err(DiskCopyError::Cancelled);
    }
    let root = root?;
    if source.metadata()?.len() != length {
        return Err(invalid("disk changed length during capture").into());
    }
    Ok((root, bytes_hashed))
}

/// Resolve the authenticated native change stream without opening RAM.
pub(crate) fn assemble_ram_map(
    length: u64,
    changes: &File,
    summary: &vm_spec::capture::CaptureRamChanges,
    baseline: Option<&StreamRoot>,
    nodes: MapNodeFiles,
    sink: &mut impl NodeSink,
    cancel: &CancellationToken,
) -> io::Result<StreamRoot> {
    use vm_spec::capture::{CaptureRamChange, CaptureRamCoverage, RamChangeReader};
    if changes.metadata()?.len() != summary.byte_len {
        return Err(invalid(
            "RAM changes length differs from its native receipt",
        ));
    }
    let reader = RamChangeReader::new(std::io::BufReader::new(changes), length, summary)?;
    if summary.coverage == CaptureRamCoverage::Full {
        if baseline.is_some() {
            return Err(invalid("full RAM capture cannot inherit a baseline"));
        }
        let present = reader.map(|record| {
            if cancel.is_cancelled() {
                return Err(MapError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "RAM map assembly cancelled",
                )));
            }
            match record? {
                CaptureRamChange::Data { index, digest } => Ok(PresentChunk { index, digest }),
                CaptureRamChange::Zero { .. } => Err(MapError::Io(invalid(
                    "full RAM changes cannot contain zero records",
                ))),
            }
        });
        return build_sorted(length, ChunkSize::RAM, present, sink).map_err(io::Error::other);
    }
    let root = baseline.ok_or_else(|| invalid("incremental RAM changes lack their baseline"))?;
    if root.length() != length
        || root.chunk_size() != ChunkSize::RAM
        || summary.baseline_stream != Some(root.id())
    {
        return Err(invalid(
            "RAM changes differ from the retained baseline geometry or identity",
        ));
    }
    let mut zero_nodes = nodes.clone();
    let mut update_nodes = nodes;
    let mut reader = reader;
    let mut pending = 0..0;
    let changes = std::iter::from_fn(|| loop {
        if cancel.is_cancelled() {
            return Some(Err(MapError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "RAM map assembly cancelled",
            ))));
        }
        if pending.start < pending.end {
            let mut zeroes = match root.zero_range_changes(
                pending.start,
                pending.end - pending.start,
                &mut zero_nodes,
            ) {
                Ok(zeroes) => zeroes,
                Err(error) => return Some(Err(error)),
            };
            if let Some(change) = zeroes.next() {
                return Some(change.inspect(|change| {
                    pending.start = change.index + 1;
                }));
            }
            pending.start = pending.end;
        }
        match reader.next()? {
            Ok(CaptureRamChange::Data { index, digest }) => {
                return Some(Ok(ChunkChange {
                    index,
                    value: Chunk::Data(digest),
                }))
            }
            Ok(CaptureRamChange::Zero { first_index, count }) => {
                pending = first_index..first_index + count
            }
            Err(error) => return Some(Err(MapError::Io(error))),
        }
    });
    root.update_sorted(changes, &mut update_nodes, sink)
        .map_err(io::Error::other)
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
        CaptureDiskCopy, CaptureDiskName, CaptureRole, Sha256Digest, CAPTURE_EVIDENCE_FILE,
        CAPTURE_EVIDENCE_TEMPORARY_FILE, CAPTURE_REQUEST_FILE, STREAM_CHUNK_BYTES,
    };
    use vm_spec::lifecycle::LiveId;
    use vm_spec::stream_map::{
        build_sorted, Chunk, ChunkSize, MapError, NodeSource, PresentChunk, StreamRoot,
        MAX_NODE_BYTES,
    };

    use crate::live::staging::{
        assemble_ram_map, parse_layout, CaptureStaging, DiskCopyError, DiskCopyMethod, FileFacts,
        RecordCommit, COPY_BUFFER_BYTES,
    };
    #[cfg(target_os = "linux")]
    use crate::live::staging::{start_writeback, StagingWriter};

    #[derive(Debug)]
    struct Root(PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn root() -> Root {
        let base =
            std::env::var_os("SILO_TEST_COPY_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let path = base.join(format!(
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

    #[derive(Debug)]
    struct TestNodes {
        staging: CaptureStaging,
        parent: Option<std::sync::Arc<TestNodes>>,
        _directory: Root,
    }

    fn test_nodes(parent: Option<std::sync::Arc<TestNodes>>) -> std::sync::Arc<TestNodes> {
        let directory = root();
        let staging = CaptureStaging::create(&directory.0, &capture()).unwrap();
        std::sync::Arc::new(TestNodes {
            staging,
            parent,
            _directory: directory,
        })
    }

    #[derive(Clone)]
    struct TestSource(std::sync::Arc<TestNodes>);

    impl NodeSource for TestSource {
        fn read_node(
            &mut self,
            digest: Sha256Digest,
            bytes: &mut [u8; MAX_NODE_BYTES],
        ) -> Result<usize, MapError> {
            match self.0.staging.node_source().read_node(digest, bytes) {
                Err(MapError::MissingNode(_)) if self.0.parent.is_some() => {
                    let parent = self
                        .0
                        .parent
                        .as_ref()
                        .ok_or(MapError::MissingNode(digest))?;
                    TestSource(parent.clone()).read_node(digest, bytes)
                }
                result => result,
            }
        }
    }

    #[derive(Debug, Clone)]
    struct TestMap {
        root: StreamRoot,
        nodes: std::sync::Arc<TestNodes>,
    }

    impl std::ops::Deref for TestMap {
        type Target = StreamRoot;
        fn deref(&self) -> &StreamRoot {
            &self.root
        }
    }
    impl PartialEq for TestMap {
        fn eq(&self, other: &Self) -> bool {
            self.root == other.root
        }
    }
    impl PartialEq<TestMap> for StreamRoot {
        fn eq(&self, other: &TestMap) -> bool {
            *self == other.root
        }
    }
    impl PartialEq<StreamRoot> for TestMap {
        fn eq(&self, other: &StreamRoot) -> bool {
            self.root == *other
        }
    }
    impl TestMap {
        fn chunks(&self) -> Vec<Option<Sha256Digest>> {
            (0..self.root.chunk_count())
                .map(|index| {
                    match self
                        .root
                        .lookup(index, &mut TestSource(self.nodes.clone()))
                        .unwrap()
                    {
                        Chunk::Zero => None,
                        Chunk::Data(digest) => Some(digest),
                    }
                })
                .collect()
        }
    }

    fn seal_disk_with_workers(
        file: &File,
        length: u64,
        cancel: &CancellationToken,
        workers: usize,
    ) -> Result<TestMap, DiskCopyError> {
        let nodes = test_nodes(None);
        let (root, _) = crate::live::staging::seal_disk_with_workers(
            file,
            length,
            cancel,
            workers,
            &mut nodes.staging.node_sink(),
        )?;
        Ok(TestMap { root, nodes })
    }
    fn seal_disk_parallel(
        file: &File,
        length: u64,
        cancel: &CancellationToken,
    ) -> Result<TestMap, DiskCopyError> {
        seal_disk_with_workers(file, length, cancel, 8)
    }
    fn stream_disk(
        file: &File,
        output: Option<&File>,
        length: u64,
        cancel: &CancellationToken,
    ) -> Result<TestMap, DiskCopyError> {
        let nodes = test_nodes(None);
        let (root, _) = crate::live::staging::stream_disk(
            file,
            output,
            length,
            cancel,
            &mut nodes.staging.node_sink(),
        )?;
        Ok(TestMap { root, nodes })
    }
    fn seal_disk_incremental(
        file: &File,
        baseline: &TestMap,
        receipt: &vm_spec::capture::DiskTrackingReceipt,
        cancel: &CancellationToken,
    ) -> Result<(TestMap, u64), DiskCopyError> {
        let nodes = test_nodes(Some(baseline.nodes.clone()));
        let (root, bytes) = crate::live::staging::seal_disk_incremental(
            file,
            baseline,
            receipt,
            cancel,
            &mut TestSource(baseline.nodes.clone()),
            &mut nodes.staging.node_sink(),
        )?;
        Ok((TestMap { root, nodes }, bytes))
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
                vm_spec::capture::CaptureIdentityPolicy::Full,
                &CancellationToken::new(),
            )
            .unwrap();
        if method == DiskCopyMethod::Clone {
            let name = vm_spec::capture::CaptureDiskName::new("data0").unwrap();
            staging
                .complete_disk_identity(
                    &staging.disk_cut(&name).unwrap(),
                    None,
                    true,
                    &CancellationToken::new(),
                )
                .unwrap();
        }
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
        let map_bytes = std::fs::read(staging.path().join("disks/data0.root")).unwrap();
        assert_eq!(StreamRoot::decode(&map_bytes).unwrap(), left);
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
                .copy_disk(
                    &role,
                    &file,
                    length,
                    CaptureDiskCopy::Copy,
                    vm_spec::capture::CaptureIdentityPolicy::Full,
                    &cancel
                )
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
                vm_spec::capture::CaptureIdentityPolicy::Full,
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
                vm_spec::capture::CaptureIdentityPolicy::Full,
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
            vm_spec::capture::CaptureIdentityPolicy::Full,
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

    fn independent_map(file: &File, length: u64) -> TestMap {
        let mut bytes = vec![0; length as usize];
        file.read_exact_at(&mut bytes, 0).unwrap();
        let nodes = test_nodes(None);
        let present = bytes
            .chunks(STREAM_CHUNK_BYTES as usize)
            .enumerate()
            .filter(|(_, chunk)| !vm_spec::capture::is_all_zero(chunk))
            .map(|(index, chunk)| {
                Ok(PresentChunk {
                    index: index as u64,
                    digest: Sha256Digest::of_bytes(chunk),
                })
            });
        let root = build_sorted(
            length,
            ChunkSize::DISK,
            present,
            &mut nodes.staging.node_sink(),
        )
        .unwrap();
        TestMap { root, nodes }
    }

    #[test]
    fn reflink_cut_defers_identity_and_keeps_the_exact_cut_after_source_writes() {
        let root = root();
        let length = 3 * STREAM_CHUNK_BYTES + 17;
        let file = source(
            &root,
            "source.raw",
            length,
            &[
                (0, b"first"),
                (2 * STREAM_CHUNK_BYTES + 4096, b"mixed"),
                (length - 4, b"tail"),
            ],
        );
        let expected = independent_map(&file, length);
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let name = vm_spec::capture::CaptureDiskName::new("upper").unwrap();
        match staging.copy_disk(
            &CaptureRole::Disk(name.clone()),
            &file,
            length,
            CaptureDiskCopy::Clone,
            vm_spec::capture::CaptureIdentityPolicy::Full,
            &CancellationToken::new(),
        ) {
            Ok(DiskCopyMethod::Clone) => {}
            Err(DiskCopyError::CloneRequired(error)) => {
                eprintln!("skipping reflink cut test: FICLONE unavailable: {error}");
                return;
            }
            other => panic!("unexpected clone outcome: {other:?}"),
        }
        let cut = staging.disk_cut(&name).unwrap();
        assert!(
            !staging.path().join("disks/upper.root").exists(),
            "the in-pause clone must not construct or publish an identity map"
        );
        file.write_all_at(b"guest writes after continuation", 0)
            .unwrap();
        assert_ne!(independent_map(&file, length), expected);
        staging
            .complete_disk_identity(&cut, None, true, &CancellationToken::new())
            .unwrap();
        let (cloned, _) = staging
            .open_sealed(&CaptureRole::Disk(name.clone()))
            .unwrap();
        let (map, facts) = staging.open_sealed(&CaptureRole::DiskMap(name)).unwrap();
        let mut bytes = vec![0; facts.length as usize];
        map.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(StreamRoot::decode(&bytes).unwrap(), expected);
        assert_eq!(bytes, expected.canonical_bytes().unwrap());
        assert_eq!(independent_map(&cloned, length), expected);
    }

    #[test]
    fn reflink_identity_cancellation_never_publishes_a_partial_map() {
        let root = root();
        let length = 512 * STREAM_CHUNK_BYTES;
        let writes = (0..512)
            .map(|chunk| (chunk * STREAM_CHUNK_BYTES, b"x".as_slice()))
            .collect::<Vec<_>>();
        let file = source(&root, "source.raw", length, &writes);
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let name = vm_spec::capture::CaptureDiskName::new("upper").unwrap();
        match staging.copy_disk(
            &CaptureRole::Disk(name.clone()),
            &file,
            length,
            CaptureDiskCopy::Clone,
            vm_spec::capture::CaptureIdentityPolicy::Full,
            &CancellationToken::new(),
        ) {
            Ok(DiskCopyMethod::Clone) => {}
            Err(DiskCopyError::CloneRequired(error)) => {
                eprintln!("skipping reflink cancellation test: FICLONE unavailable: {error}");
                return;
            }
            other => panic!("unexpected clone outcome: {other:?}"),
        }
        let cut = staging.disk_cut(&name).unwrap();
        let cancel = CancellationToken::new();
        std::thread::scope(|scope| {
            let token = cancel.clone();
            let hash = scope.spawn(|| staging.complete_disk_identity(&cut, None, true, &cancel));
            scope.spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(10));
                token.cancel();
            });
            assert!(matches!(
                hash.join().unwrap(),
                Err(DiskCopyError::Cancelled)
            ));
        });
        assert!(!staging.path().join("disks/upper.root").exists());
        assert_eq!(staging.disk_cut(&name).unwrap(), cut);
    }

    #[test]
    fn sparse_copy_still_hashes_inline_without_identity_completion() {
        let root = root();
        let length = 2 * STREAM_CHUNK_BYTES + 7;
        let file = source(
            &root,
            "source.raw",
            length,
            &[(4096, b"data"), (length - 1, b"x")],
        );
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        let map = staging
            .sparse_copy(&file, "upper.raw", length, &CancellationToken::new())
            .unwrap();
        let (copied, _) = staging.open_sealed(&disk("upper")).unwrap();
        assert_eq!(map, independent_map(&file, length));
        assert_eq!(map, independent_map(&copied, length));
        assert!(copied.metadata().unwrap().blocks() * 512 < length);
    }

    fn ram_changes(
        staging: &CaptureStaging,
        name: &str,
        baseline: Option<Sha256Digest>,
        records: &[(u64, u64, Option<Sha256Digest>)],
    ) -> (File, vm_spec::capture::CaptureRamChanges) {
        use vm_spec::capture::{CaptureRamChanges, CaptureRamCoverage};
        let mut bytes = b"KRUNRAM\0\x01\0\x10\0\0\0\0\0".to_vec();
        bytes[11] = u8::from(baseline.is_some());
        for &(first, count, digest) in records {
            bytes.extend(first.to_le_bytes());
            bytes.extend(count.to_le_bytes());
            bytes.push(u8::from(digest.is_some()));
            bytes.extend([0; 7]);
            bytes.extend(digest.map_or([0; 32], |digest| *digest.as_bytes()));
        }
        let path = staging.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        let summary = CaptureRamChanges {
            byte_len: bytes.len() as u64,
            sha256: Sha256Digest::of_bytes(&bytes),
            record_count: records.len() as u64,
            coverage: if baseline.is_some() {
                CaptureRamCoverage::Incremental
            } else {
                CaptureRamCoverage::Full
            },
            baseline_stream: baseline,
        };
        (File::open(path).unwrap(), summary)
    }

    #[test]
    fn full_and_incremental_ram_files_equal_fresh_build_and_zero_runs_clear_chunks() {
        let directory = root();
        let staging = CaptureStaging::create(&directory.0, &capture()).unwrap();
        let length = 3 * ChunkSize::RAM.bytes() + 4096;
        let memory = source(
            &directory,
            "ram",
            length,
            &[(0, b"first"), (2 * ChunkSize::RAM.bytes(), b"last")],
        );
        let digest_at = |index: u64| {
            let mut bytes = vec![
                0;
                (length - index * ChunkSize::RAM.bytes()).min(ChunkSize::RAM.bytes())
                    as usize
            ];
            memory
                .read_exact_at(&mut bytes, index * ChunkSize::RAM.bytes())
                .unwrap();
            Sha256Digest::of_bytes(&bytes)
        };
        let (file, summary) = ram_changes(
            &staging,
            "full.changes",
            None,
            &[(0, 1, Some(digest_at(0))), (2, 1, Some(digest_at(2)))],
        );
        let full = assemble_ram_map(
            length,
            &file,
            &summary,
            None,
            staging.node_source(),
            &mut staging.node_sink(),
            &CancellationToken::new(),
        )
        .unwrap();
        memory
            .write_all_at(&vec![0; ChunkSize::RAM.bytes() as usize], 0)
            .unwrap();
        memory.write_all_at(b"new-tail", length - 8).unwrap();
        let next = CaptureStaging::create(&directory.0, &capture()).unwrap();
        let (file, summary) = ram_changes(
            &next,
            "incremental.changes",
            Some(full.id()),
            &[(0, 2, None), (3, 1, Some(digest_at(3)))],
        );
        let incremental = assemble_ram_map(
            length,
            &file,
            &summary,
            Some(&full),
            next.node_source(),
            &mut next.node_sink(),
            &CancellationToken::new(),
        )
        .unwrap();
        let fresh = CaptureStaging::create(&directory.0, &capture()).unwrap();
        let (file, summary) = ram_changes(
            &fresh,
            "fresh.changes",
            None,
            &[(2, 1, Some(digest_at(2))), (3, 1, Some(digest_at(3)))],
        );
        let expected = assemble_ram_map(
            length,
            &file,
            &summary,
            None,
            fresh.node_source(),
            &mut fresh.node_sink(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(incremental, expected);
        assert_eq!(
            incremental.lookup(0, &mut next.node_source()).unwrap(),
            Chunk::Zero
        );
        let idle = CaptureStaging::create(&directory.0, &capture()).unwrap();
        let (file, summary) = ram_changes(&idle, "idle.changes", Some(incremental.id()), &[]);
        let unchanged = assemble_ram_map(
            length,
            &file,
            &summary,
            Some(&incremental),
            idle.node_source(),
            &mut idle.node_sink(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(unchanged, incremental);
        assert_eq!(
            std::fs::read_dir(idle.path().join("map-nodes"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn capture_writes_maps_and_a_single_link_record() {
        let root = root();
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        staging.write_request(b"request").unwrap();
        let map = StreamRoot::empty(4096, ChunkSize::RAM).unwrap();
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
            std::fs::read(staging.path().join("memory.root")).unwrap(),
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

    fn tracking_receipt(
        file: &File,
        baseline: &TestMap,
        indices: &[u64],
    ) -> vm_spec::capture::DiskTrackingReceipt {
        use vm_spec::capture::{
            DiskDirtyRun, DiskGenerationToken, DiskTrackingReceipt, DiskTrackingSeed,
            DISK_TRACKING_VERSION,
        };
        let metadata = file.metadata().unwrap();
        let seed = DiskTrackingSeed {
            version: DISK_TRACKING_VERSION,
            map_format: 2,
            chunk_shift: 23,
            role: vm_spec::DiskRole::Root,
            attachment_index: 0,
            block_id: vm_spec::BlockId::new("root").unwrap(),
            file_device: metadata.dev(),
            file_inode: metadata.ino(),
            length: baseline.length(),
            chunk_size: STREAM_CHUNK_BYTES,
            epoch: capture(),
            baseline: Some(baseline.id()),
        };
        let mut runs: Vec<DiskDirtyRun> = Vec::new();
        for &index in indices {
            match runs.last_mut() {
                Some(run) if run.first_chunk + run.chunk_count == index => run.chunk_count += 1,
                _ => runs.push(DiskDirtyRun {
                    first_chunk: index,
                    chunk_count: 1,
                }),
            }
        }
        DiskTrackingReceipt {
            version: DISK_TRACKING_VERSION,
            token: DiskGenerationToken {
                capture_id: capture(),
                pause_generation: 1,
                epoch: seed.epoch.clone(),
                generation: 1,
                file_device: seed.file_device,
                file_inode: seed.file_inode,
            },
            seed,
            runs,
            dirty_chunks: indices.len() as u64,
            total_chunks: baseline.length().div_ceil(STREAM_CHUNK_BYTES),
            invalid_reason: None,
        }
    }

    #[test]
    fn incremental_disk_map_equals_full_hash_for_random_writes_zeroes_and_tail() {
        let root = root();
        let length = 6 * STREAM_CHUNK_BYTES + 512;
        let file = source(
            &root,
            "incremental.raw",
            length,
            &[
                (0, b"becomes zero"),
                (STREAM_CHUNK_BYTES, b"unchanged"),
                (2 * STREAM_CHUNK_BYTES, b"becomes zero"),
                (4 * STREAM_CHUNK_BYTES, b"also unchanged"),
                (length - 512, b"old tail"),
            ],
        );
        let baseline = independent_map(&file, length);
        let mut random = 0x71d9_0213_a943_ba65u64;
        let mut dirty = std::collections::BTreeSet::new();
        for _ in 0..48 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let index = [0, 2, 3, 6][random as usize % 4];
            let chunk_length = (length - index * STREAM_CHUNK_BYTES).min(STREAM_CHUNK_BYTES);
            let offset =
                index * STREAM_CHUNK_BYTES + (random.rotate_left(19) % (chunk_length - 31));
            file.write_all_at(&random.to_le_bytes().repeat(4), offset)
                .unwrap();
            dirty.insert(index);
        }
        file.write_all_at(b"known nonzero dirty chunk", 3 * STREAM_CHUNK_BYTES)
            .unwrap();
        dirty.extend([0, 2, 3, 6]);
        let zeros = vec![0; STREAM_CHUNK_BYTES as usize];
        file.write_all_at(&zeros, 0).unwrap();
        file.write_all_at(&zeros, 2 * STREAM_CHUNK_BYTES).unwrap();
        file.write_all_at(&[0; 512], length - 512).unwrap();
        let receipt = tracking_receipt(&file, &baseline, &dirty.into_iter().collect::<Vec<_>>());
        let (incremental, bytes_hashed) =
            seal_disk_incremental(&file, &baseline, &receipt, &CancellationToken::new()).unwrap();
        let full = independent_map(&file, length);
        assert_eq!(incremental, full);
        assert_eq!(
            incremental.canonical_bytes().unwrap(),
            full.canonical_bytes().unwrap()
        );
        assert_eq!(incremental.id(), full.id());
        assert_eq!(incremental.chunks()[0], None);
        assert_eq!(incremental.chunks()[2], None);
        assert_eq!(incremental.chunks()[6], None);
        assert_eq!(bytes_hashed, STREAM_CHUNK_BYTES);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn incremental_disk_map_hashes_actual_discarded_bytes() {
        let root = root();
        let length = 3 * STREAM_CHUNK_BYTES + 512;
        let file = source(
            &root,
            "discard.raw",
            length,
            &[
                (0, b"preserved"),
                (STREAM_CHUNK_BYTES, b"discarded"),
                (2 * STREAM_CHUNK_BYTES, b"partial chunk survives"),
                (2 * STREAM_CHUNK_BYTES + 8192, b"partial chunk discarded"),
                (length - 4, b"tail"),
            ],
        );
        let baseline = independent_map(&file, length);
        let flags = nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE
            | nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE;
        match nix::fcntl::fallocate(
            &file,
            flags,
            STREAM_CHUNK_BYTES as i64,
            STREAM_CHUNK_BYTES as i64,
        ) {
            Ok(()) => {}
            Err(nix::errno::Errno::EOPNOTSUPP | nix::errno::Errno::ENOSYS) => {
                eprintln!("skipping real discard test: filesystem does not support hole punching");
                return;
            }
            Err(error) => panic!("hole punch failed: {error}"),
        }
        nix::fcntl::fallocate(&file, flags, (2 * STREAM_CHUNK_BYTES + 4096) as i64, 8192).unwrap();
        let receipt = tracking_receipt(&file, &baseline, &[1, 2]);
        let (map, _) =
            seal_disk_incremental(&file, &baseline, &receipt, &CancellationToken::new()).unwrap();
        assert_eq!(map, independent_map(&file, length));
        assert_eq!(map.chunks()[1], None);
        assert!(map.chunks()[2].is_some());
    }

    #[test]
    fn empty_disk_generation_does_not_read_the_payload() {
        let root = root();
        let file = source(
            &root,
            "unchanged.raw",
            STREAM_CHUNK_BYTES + 512,
            &[(0, b"unchanged")],
        );
        let baseline = independent_map(&file, STREAM_CHUNK_BYTES + 512);
        let receipt = tracking_receipt(&file, &baseline, &[]);
        let write_only = OpenOptions::new()
            .write(true)
            .open(root.0.join("unchanged.raw"))
            .unwrap();
        let (map, bytes) =
            seal_disk_incremental(&write_only, &baseline, &receipt, &CancellationToken::new())
                .unwrap();
        assert_eq!(map, baseline);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn invalid_or_missing_disk_baseline_falls_back_to_full_clone_hash() {
        let root = root();
        let length = 2 * STREAM_CHUNK_BYTES + 512;
        let file = source(
            &root,
            "fallback.raw",
            length,
            &[(0, b"before"), (length - 4, b"tail")],
        );
        let baseline = independent_map(&file, length);
        file.write_all_at(b"changed without valid coverage", STREAM_CHUNK_BYTES)
            .unwrap();
        let expected = independent_map(&file, length);
        for case in 0..4 {
            let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
            let name = CaptureDiskName::new("upper").unwrap();
            let output = staging
                .create_output(&CaptureRole::Disk(name.clone()))
                .unwrap();
            output.set_len(length).unwrap();
            let mut bytes = vec![0; length as usize];
            file.read_exact_at(&mut bytes, 0).unwrap();
            output.write_all_at(&bytes, 0).unwrap();
            drop(output);
            let mut cut = staging.disk_cut(&name).unwrap();
            let mut receipt = tracking_receipt(&file, &baseline, &[]);
            if case == 0 {
                receipt.invalid_reason = Some(vm_spec::capture::DiskTrackingInvalidReason::Lost);
            } else if case == 2 {
                receipt.dirty_chunks = 1;
            }
            cut.tracking_receipt = Some(receipt);
            let supplied = (case != 1).then_some(&baseline.root);
            let (map, stats) = staging
                .complete_disk_identity(&cut, supplied, case != 3, &CancellationToken::new())
                .unwrap();
            assert_eq!(map, expected);
            assert!(!stats.baseline_reused);
            assert!(stats.full_scan_reason.is_some());
            if case == 3 {
                assert_eq!(
                    stats.full_scan_reason,
                    Some(vm_spec::capture::DiskFullScanReason::External)
                );
            }
            assert_eq!(stats.bytes_hashed, 2 * STREAM_CHUNK_BYTES + 512);
        }
    }

    #[test]
    fn tracked_reflink_identity_reads_the_cut_and_inherits_clean_chunks() {
        let root = root();
        let length = 3 * STREAM_CHUNK_BYTES + 512;
        let file = source(
            &root,
            "tracked.raw",
            length,
            &[
                (0, b"becomes zero"),
                (STREAM_CHUNK_BYTES, b"clean predecessor"),
                (2 * STREAM_CHUNK_BYTES, b"also clean"),
                (length - 4, b"tail"),
            ],
        );
        let baseline = independent_map(&file, length);
        file.write_all_at(&vec![0; STREAM_CHUNK_BYTES as usize], 0)
            .unwrap();
        file.write_all_at(b"changed tail", length - 16).unwrap();
        let receipt = tracking_receipt(&file, &baseline, &[0, 3]);
        let expected = independent_map(&file, length);
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        staging
            .set_node_store(Some(
                baseline
                    .nodes
                    .staging
                    .path()
                    .join("map-nodes")
                    .to_str()
                    .unwrap(),
            ))
            .unwrap();
        let name = CaptureDiskName::new("upper").unwrap();
        match staging.copy_disk(
            &CaptureRole::Disk(name.clone()),
            &file,
            length,
            CaptureDiskCopy::Clone,
            vm_spec::capture::CaptureIdentityPolicy::Full,
            &CancellationToken::new(),
        ) {
            Ok(DiskCopyMethod::Clone) => {}
            Err(DiskCopyError::CloneRequired(error)) => {
                eprintln!("skipping tracked reflink test: clone unavailable: {error}");
                return;
            }
            other => panic!("unexpected clone result: {other:?}"),
        }
        let mut cut = staging.disk_cut(&name).unwrap();
        cut.tracking_receipt = Some(receipt);
        file.write_all_at(b"post-cut source mutation", STREAM_CHUNK_BYTES)
            .unwrap();
        assert_ne!(independent_map(&file, length), expected);
        let (map, stats) = staging
            .complete_disk_identity(&cut, Some(&baseline), true, &CancellationToken::new())
            .unwrap();
        assert_eq!(map, expected);
        assert!(stats.baseline_reused);
        assert_eq!(stats.full_scan_reason, None);
        assert_eq!(stats.dirty_chunks, 2);
        assert_eq!(stats.total_chunks, 4);
        assert_eq!(stats.bytes_hashed, 512);
        let (stored, facts) = staging.open_sealed(&CaptureRole::DiskMap(name)).unwrap();
        let mut bytes = vec![0; facts.length as usize];
        stored.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, expected.canonical_bytes().unwrap());
    }
    #[test]
    fn owned_sparse_copy_preserves_bytes_without_map_output() {
        let root = root();
        let length = 3 * STREAM_CHUNK_BYTES + 4096;
        let file = source(
            &root,
            "source.raw",
            length,
            &[(4096, b"head"), (length - 4, b"tail")],
        );
        let staging = CaptureStaging::create(&root.0, &capture()).unwrap();
        staging
            .sparse_copy_owned(&file, "owned.raw", length, &CancellationToken::new())
            .unwrap();
        let (copied, facts) = staging.open_sealed(&disk("owned")).unwrap();
        assert_eq!(facts.length, length);
        let mut original = vec![0u8; length as usize];
        let mut actual = vec![0u8; length as usize];
        file.read_exact_at(&mut original, 0).unwrap();
        copied.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, original);
        assert_ne!(FileFacts::of(&file).unwrap().inode, facts.inode);
        assert_eq!(staging.map_nodes_written(), 0);
        assert_eq!(
            std::fs::read_dir(
                staging
                    .path()
                    .join(vm_spec::capture::CAPTURE_MAP_NODES_DIRECTORY)
            )
            .unwrap()
            .count(),
            0
        );
        assert!(!staging.path().join("disks/owned.root").exists());
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(
            staging.sparse_copy_owned(&file, "cancelled.raw", length, &cancel),
            Err(DiskCopyError::Cancelled)
        ));
    }
}
