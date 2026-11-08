use std::path::PathBuf;

/// Errors that can occur when reading an ext4 filesystem.
///
/// Callers distinguish three filesystem classes and never receive an
/// approximate answer instead of one of them:
///
/// - [`ReadError::RequiresRecovery`]: on-disk state is not clean; only the
///   kernel (journal replay, orphan cleanup) or fsck may make it readable.
/// - [`ReadError::Unsupported`]: a valid ext4 encoding this reader does not
///   implement, or a resource bound it refuses to exceed.
/// - [`ReadError::Corrupt`]: an inconsistent or malformed structure.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("file at path {0} not found")]
    NotFound(PathBuf),
    #[error("not an ext4 filesystem: missing superblock magic")]
    InvalidSuperBlock,
    #[error("ext4 filesystem requires kernel recovery before host reading: {0}")]
    RequiresRecovery(RecoveryReason),
    #[error("unsupported ext4 layout: {0}")]
    Unsupported(Unsupported),
    #[error("corrupt ext4 filesystem: {0}")]
    Corrupt(Corruption),
    #[error("read of {length} bytes at offset {offset} exceeds inode {inode} size {size}")]
    OutOfRange {
        inode: u32,
        offset: u64,
        length: u64,
        size: u64,
    },
    #[error("no such file or directory: {0}")]
    PathNotFound(String),
    #[error("not a regular file: {0}")]
    NotAFile(String),
    #[error("is a directory: {0}")]
    IsDirectory(String),
    #[error("not a directory: {0}")]
    NotADirectory(String),
    #[error("symlink loop while resolving: {0}")]
    SymlinkLoop(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ReadError {
    pub(crate) fn corrupt(structure: Structure, inode: Option<u32>, reason: &'static str) -> Self {
        Self::Corrupt(Corruption {
            structure,
            inode,
            reason,
        })
    }
}

/// Fallible metadata allocation failure surfaces as host out-of-memory I/O,
/// separately from format and corruption errors.
impl From<std::collections::TryReserveError> for ReadError {
    fn from(error: std::collections::TryReserveError) -> Self {
        Self::Io(std::io::Error::new(std::io::ErrorKind::OutOfMemory, error))
    }
}

/// On-disk state that only kernel recovery or fsck can resolve. The host never
/// replays the journal or repairs the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryReason {
    #[error("the journal needs recovery (RECOVER is set)")]
    JournalNeedsRecovery,
    #[error("the journal superblock records unreplayed transactions")]
    JournalNotEmpty,
    #[error("the journal recorded an abort (errno {0})")]
    JournalAborted(i32),
    #[error("the orphan inode list is not empty (first orphan inode {0})")]
    OrphanInodes(u32),
    #[error("the filesystem is not marked cleanly unmounted (state {0:#06x})")]
    NotCleanlyUnmounted(u16),
    #[error("the filesystem recorded errors (state {0:#06x}); run fsck")]
    RecordedErrors(u16),
}

/// Valid ext4 encodings outside the admitted reader profile, and resource
/// bounds the reader refuses to exceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unsupported {
    #[error(
        "features compat {compat:#x}, incompat {incompat:#x}, ro_compat {ro_compat:#x} are not implemented"
    )]
    Features {
        compat: u32,
        incompat: u32,
        ro_compat: u32,
    },
    #[error("required incompatible features {0:#x} are absent")]
    MissingFeatures(u32),
    #[error("superblock revision {0} (only dynamic revision 1)")]
    Revision(u32),
    #[error("creator OS {0} (only the Linux inode layout)")]
    CreatorOs(u32),
    #[error("log block size {0} (only 4096-byte blocks)")]
    BlockSize(u32),
    #[error("inode size {0} (only 256-byte inodes)")]
    InodeSize(u16),
    #[error("external or non-inode-8 journal")]
    ExternalJournal,
    #[error("inode {inode} uses inode flags {flags:#x}")]
    InodeFlags { inode: u32, flags: u32 },
    #[error("inode {inode} has extra inode size {extra_isize} (only 32)")]
    InodeExtraSize { inode: u32, extra_isize: u16 },
    #[error("inode {0} uses indirect block maps instead of extents")]
    BlockMappedInode(u32),
    #[error("inode {inode} size {size} exceeds the 1 TiB reader bound")]
    FileTooLarge { inode: u32, size: u64 },
    #[error("inode {inode} has more than {limit} extents")]
    TooManyExtents { inode: u32, limit: usize },
    #[error("directory inode {inode} has more than {limit} entries")]
    DirectoryTooLarge { inode: u32, limit: usize },
    #[error("directory inode {inode} uses hash version {version}")]
    HashVersion { inode: u32, version: u8 },
    #[error("indexed directory inode {0} but the superblock records no hash signedness")]
    HashSignedness(u32),
    #[error("inode {inode} uses xattr name index {index}")]
    XattrNamespace { inode: u32, index: u8 },
    #[error("inode {0} stores inline data (system.data)")]
    InlineData(u32),
    #[error("inode {0} stores an xattr value in an EA inode")]
    XattrValueInode(u32),
}

/// The ext4 structure in which a [`Corruption`] was detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Structure {
    Superblock,
    GroupDescriptor(u32),
    Journal,
    Inode,
    ExtentTree,
    Directory,
    HashIndex,
    Xattr,
    Symlink,
    Namespace,
}

/// A malformed or inconsistent on-disk structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Corruption {
    pub structure: Structure,
    pub inode: Option<u32>,
    pub reason: &'static str,
}

impl std::fmt::Display for Corruption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.structure)?;
        if let Some(inode) = self.inode {
            write!(f, " of inode {inode}")?;
        }
        write!(f, ": {}", self.reason)
    }
}

impl std::error::Error for Corruption {}

/// Errors that can occur when formatting an ext4 filesystem.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("{0} is not a directory")]
    NotDirectory(PathBuf),
    #[error("{0} is not a file")]
    NotFile(PathBuf),
    #[error("{0} not found")]
    NotFound(PathBuf),
    #[error("{0} already exists")]
    AlreadyExists(PathBuf),
    #[error("file type not supported")]
    UnsupportedFiletype,
    #[error("maximum links exceeded for path: {0}")]
    MaximumLinksExceeded(PathBuf),
    #[error("{0} exceeds max file size (1 TiB)")]
    FileTooBig(u64),
    #[error("'{0}' is an invalid link")]
    InvalidLink(PathBuf),
    #[error("'{0}' is an invalid name")]
    InvalidName(String),
    #[error("not enough space for trailing directory entry")]
    NoSpaceForTrailingDirEntry,
    #[error("not enough space for group descriptor blocks")]
    InsufficientSpaceForGroupDescriptorBlocks,
    #[error("cannot create hard links to directory target: {0}")]
    CannotHardlinkDirectory(PathBuf),
    #[error("unsupported block size {0} (only 4096 is supported)")]
    UnsupportedBlockSize(u32),
    #[error("invalid filesystem size {size}: {reason}")]
    InvalidSize { size: u64, reason: &'static str },
    #[error("invalid volume label: {0}")]
    InvalidLabel(String),
    #[error("cannot truncate file: {0}")]
    CannotTruncateFile(PathBuf),
    #[error("cannot create sparse file at {0}")]
    CannotCreateSparseFile(PathBuf),
    #[error("cannot resize fs to {0} bytes")]
    CannotResizeFs(u64),
    #[error("cannot fit xattr for inode {0}")]
    XattrInsufficientSpace(u32),
    #[error("malformed extended attribute buffer")]
    MalformedXattrBuffer,
    #[error("malformed POSIX ACL xattr")]
    MalformedAcl,
    #[error("invalid raw xattr name {0:?}")]
    InvalidXattrName(Vec<u8>),
    #[error("duplicate xattr name")]
    DuplicateXattr,
    #[error("device ID is outside Linux's 12-bit major / 20-bit minor encoding")]
    InvalidDevice,
    #[error("symlink target length {length} exceeds the ext4 maximum {maximum} bytes")]
    SymlinkTargetTooLong { length: u64, maximum: u64 },
    #[error("invalid inode metadata or content: {0}")]
    InvalidMetadata(&'static str),
    #[error("invalid sparse file ranges: {0}")]
    InvalidSparse(&'static str),
    #[error("filesystem size calculation overflow")]
    SizeOverflow,
    #[error("cannot convert string '{0}' to ASCII")]
    InvalidAsciiString(String),
    #[error("invalid ext4 path '{0}'")]
    InvalidPathEncoding(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Errors that can occur while growing an unmounted ext4 image.
#[derive(Debug, thiserror::Error)]
pub enum ResizeError {
    #[error("filesystem requires kernel journal recovery before offline resize")]
    RequiresRecovery,
    #[error("offline resize does not support this filesystem: {0}")]
    Unsupported(&'static str),
    #[error("invalid or corrupt ext4 filesystem: {0}")]
    Corrupt(&'static str),
    #[error("resize target {0} is not aligned to the 4096-byte filesystem block size")]
    UnalignedSize(u64),
    #[error(
        "refusing to shrink ext4 filesystem from {current_blocks} to {requested_blocks} blocks"
    )]
    ShrinkUnsupported {
        current_blocks: u64,
        requested_blocks: u64,
    },
    #[error(
        "resize needs {required_descriptor_blocks} descriptor blocks but only {available_descriptor_blocks} are available"
    )]
    GdtCapacityExceeded {
        required_descriptor_blocks: u32,
        available_descriptor_blocks: u32,
    },
    #[error("resize target {requested_blocks} exceeds the maximum {maximum_blocks} blocks")]
    TooLarge {
        requested_blocks: u64,
        maximum_blocks: u64,
    },
    #[error("resized filesystem would exceed the 32-bit inode count")]
    TooManyInodes,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ResizeError {
    /// Whether the image is unchanged and the mounted kernel resize path may
    /// safely handle this case instead.
    pub fn can_fallback_online(&self) -> bool {
        matches!(
            self,
            Self::RequiresRecovery | Self::Unsupported(_) | Self::GdtCapacityExceeded { .. }
        )
    }
}

pub type ReadResult<T> = std::result::Result<T, ReadError>;
pub type FormatResult<T> = std::result::Result<T, FormatError>;
pub type ResizeResult<T> = std::result::Result<T, ResizeError>;
