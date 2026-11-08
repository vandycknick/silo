//! Validated, read-only ext4 reader for host-side inspection of admitted
//! images, including uppers mutated by the guest kernel.
//!
//! ```text
//!   File (held fd, pread only) ──► superblock: magic, revision, geometry,
//!                                  admitted feature set
//!                               ──► clean state: RECOVER, state bits, orphans
//!                               ──► every group descriptor (gdt_csum, ranges)
//!                               ──► journal superblock: s_start == 0, no errno
//!   lazily, per request:
//!     inode ──► allocation bitmap, encoding flags, kind, times, i_blocks
//!     dir   ──► rec_len tiling, '.'/'..', names, htree structure and hashes
//!     body  ──► extent tree (depth, order, cycles, ranges) ──► positioned reads
//!   audit() ──► whole-namespace walk: link counts and inode census
//! ```
//!
//! Every answer is exact or a typed error: [`ReadError::RequiresRecovery`],
//! [`ReadError::Unsupported`] or [`ReadError::Corrupt`]. The journal is never
//! replayed and the image is never written.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

use rootfs_spec::upper_geometry::has_sparse_super;

use crate::ext4::checksum;
use crate::ext4::constants::*;
use crate::ext4::dir::{self, DIR_BLOCK_SIZE, DxEntry, HashVersion};
use crate::ext4::error::{ReadError, ReadResult, RecoveryReason, Structure, Unsupported};
use crate::ext4::extent::{self, ExtentMap};
use crate::ext4::file_tree::InodeNumber;
use crate::ext4::input::{DeviceId, FileRange};
use crate::ext4::types::*;

/// Bytes per filesystem block; the only block size the reader implements.
pub(crate) const BLOCK_BYTES: u64 = 4096;
const LOG_BLOCK_SIZE: u32 = 2;
const INODE_BYTES: u16 = 256;
const GOOD_OLD_FIRST_INODE: u32 = 11;
const DESCRIPTOR_BYTES: u64 = GroupDescriptor::SIZE as u64;
const JOURNAL_INODE: u32 = 8;
const JBD2_MAGIC: u32 = 0xC03B_3998;

/// Largest directory the reader materializes; the flattened namespace bound.
pub const MAX_DIRECTORY_ENTRIES: usize = 4_000_000;

const SUPPORTED_COMPAT: u32 =
    compat::HAS_JOURNAL | compat::EXT_ATTR | compat::RESIZE_INODE | compat::DIR_INDEX;
const SUPPORTED_INCOMPAT: u32 = incompat::FILETYPE | incompat::EXTENTS | incompat::FLEX_BG;
const REQUIRED_INCOMPAT: u32 = incompat::FILETYPE | incompat::EXTENTS;
const SUPPORTED_RO_COMPAT: u32 = ro_compat::SPARSE_SUPER
    | ro_compat::LARGE_FILE
    | ro_compat::HUGE_FILE
    | ro_compat::GDT_CSUM
    | ro_compat::DIR_NLINK
    | ro_compat::EXTRA_ISIZE;

/// Read and magic-check the primary superblock with one positioned read.
///
/// Performs no other validation, so it also serves callers that need only
/// superblock facts of a filesystem that may require recovery.
pub fn read_superblock(file: &File) -> ReadResult<SuperBlock> {
    let mut bytes = [0u8; SUPERBLOCK_SIZE];
    match file.read_exact_at(&mut bytes, SUPERBLOCK_OFFSET) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ReadError::InvalidSuperBlock);
        }
        Err(error) => return Err(error.into()),
    }
    let superblock = SuperBlock::read_from(&bytes);
    if superblock.magic != SUPERBLOCK_MAGIC {
        return Err(ReadError::InvalidSuperBlock);
    }
    Ok(superblock)
}

/// Seconds and nanoseconds of an ext4 extended timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}

/// Validated inode type; device numbers use Linux's encoding rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InodeKind {
    Regular,
    Directory,
    Symlink,
    CharacterDevice(DeviceId),
    BlockDevice(DeviceId),
    Fifo,
    Socket,
}

impl InodeKind {
    /// Directory-entry type for this inode kind.
    pub fn file_type(self) -> FileType {
        match self {
            Self::Regular => FileType::Regular,
            Self::Directory => FileType::Directory,
            Self::Symlink => FileType::SymbolicLink,
            Self::CharacterDevice(_) => FileType::Character,
            Self::BlockDevice(_) => FileType::Block,
            Self::Fifo => FileType::Fifo,
            Self::Socket => FileType::Socket,
        }
    }
}

/// Complete metadata of one validated, allocated inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InodeMetadata {
    pub number: InodeNumber,
    pub kind: InodeKind,
    /// Permission and set-id/sticky bits (`mode & 0o7777`).
    pub permissions: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// Raw `i_links_count`. A directory may record 1 under `DIR_NLINK` when
    /// its subdirectory count exceeded the ext4 link maximum.
    pub links: u16,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Timestamp,
    /// Only [`inode_flags::USER_ATTRIBUTES`] bits; encoding flags are consumed.
    pub flags: u32,
    pub generation: u32,
    pub projid: u32,
}

/// One live directory entry other than `.` and `..`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub inode: InodeNumber,
    pub file_type: FileType,
}

/// A validated directory: entries sorted by name bytes, without `.`/`..`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    pub inode: InodeNumber,
    /// Inode named by `..`.
    pub parent: InodeNumber,
    pub entries: Vec<DirEntry>,
}

impl Directory {
    pub fn lookup(&self, name: &[u8]) -> Option<InodeNumber> {
        self.entries
            .binary_search_by(|entry| entry.name.as_slice().cmp(name))
            .ok()
            .map(|index| self.entries[index].inode)
    }
}

/// Validated physical map of one regular file's stored bytes.
///
/// Holes and unwritten extents are absent and read as zeros. Extents beyond
/// `i_size` are clipped. Obtained from [`Reader::file_body`]; read with
/// [`Reader::read_at`] or [`Reader::body_stream`] without staging copies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileBody {
    pub(crate) inode: InodeNumber,
    pub(crate) size: u64,
    pub(crate) extents: Vec<BodyExtent>,
}

/// Initialized bytes `[logical, logical + length)` stored at `physical`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BodyExtent {
    pub logical: u64,
    pub physical: u64,
    pub length: u64,
}

impl FileBody {
    pub fn inode(&self) -> InodeNumber {
        self.inode
    }

    /// Logical file size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Ordered, disjoint, coalesced logical byte ranges of stored data.
    pub fn stored_ranges(&self) -> StoredRanges<'_> {
        StoredRanges {
            extents: self.extents.iter().peekable(),
        }
    }

    /// Total stored bytes, the exact length of [`Reader::body_stream`].
    pub fn stored_bytes(&self) -> u64 {
        self.extents.iter().map(|extent| extent.length).sum()
    }

    /// True when every logical byte is stored (no holes or unwritten ranges).
    pub fn is_dense(&self) -> bool {
        self.stored_bytes() == self.size
    }
}

/// Iterator returned by [`FileBody::stored_ranges`].
pub struct StoredRanges<'a> {
    extents: std::iter::Peekable<std::slice::Iter<'a, BodyExtent>>,
}

impl Iterator for StoredRanges<'_> {
    type Item = FileRange;

    fn next(&mut self) -> Option<FileRange> {
        let first = self.extents.next()?;
        let mut range = FileRange {
            offset: first.logical,
            length: first.length,
        };
        while let Some(next) = self
            .extents
            .next_if(|next| next.logical == range.offset + range.length)
        {
            range.length += next.length;
        }
        Some(range)
    }
}

/// Counts from a successful [`Reader::audit`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditSummary {
    pub directories: u64,
    pub regular_files: u64,
    pub symlinks: u64,
    pub special_files: u64,
    /// Directory entries other than `.` and `..`.
    pub names: u64,
}

#[derive(Clone, Copy, Debug)]
struct Geometry {
    blocks: u64,
    groups: u32,
    inodes: u32,
    inodes_per_group: u32,
    blocks_per_group: u32,
    first_inode: u32,
    /// Superblock, descriptor and reserved descriptor blocks of a backup group.
    superblock_zone: u64,
    inode_table_blocks: u64,
    sparse_super: bool,
    huge_file: bool,
    gdt_csum: bool,
    dir_index: bool,
    dir_nlink: bool,
    has_journal: bool,
    hash_unsigned: Option<bool>,
}

/// An allocated inode that passed encoding validation.
#[derive(Clone, Debug)]
pub(crate) struct Live {
    pub number: InodeNumber,
    pub raw: Inode,
    pub kind: InodeKind,
    pub size: u64,
}

/// Read-only ext4 filesystem reader over one held file descriptor.
///
/// Construction validates the superblock, admitted features, clean on-disk
/// state, every group descriptor and the journal superblock. All later reads
/// are positioned (`pread`), never move the descriptor's cursor, and take
/// `&self`.
pub struct Reader {
    file: File,
    superblock: SuperBlock,
    geometry: Geometry,
    groups: Vec<GroupDescriptor>,
}

impl Reader {
    /// Open the image at `path` read-only. See [`Reader::from_file`].
    pub fn new(path: &Path) -> ReadResult<Self> {
        let file = File::open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ReadError::NotFound(path.to_path_buf())
            } else {
                ReadError::Io(error)
            }
        })?;
        Self::from_file(file)
    }

    /// Validate and hold an already-open image descriptor.
    pub fn from_file(file: File) -> ReadResult<Self> {
        let superblock = read_superblock(&file)?;
        let geometry = Geometry::validate(&superblock, file.metadata()?.len())?;
        check_clean_state(&superblock)?;
        let groups = load_groups(&file, &superblock, &geometry)?;
        let reader = Self {
            file,
            superblock,
            geometry,
            groups,
        };
        reader.check_journal()?;
        Ok(reader)
    }

    /// Borrow the parsed superblock.
    pub fn superblock(&self) -> &SuperBlock {
        &self.superblock
    }

    /// Filesystem UUID.
    pub fn uuid(&self) -> [u8; 16] {
        self.superblock.uuid
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    /// A validated group descriptor.
    pub fn get_group_descriptor(&self, number: u32) -> ReadResult<GroupDescriptor> {
        self.groups.get(number as usize).cloned().ok_or_else(|| {
            ReadError::corrupt(
                Structure::GroupDescriptor(number),
                None,
                "group number out of range",
            )
        })
    }

    /// The raw on-disk inode without allocation or content validation, for
    /// diagnostics of reserved and deleted inodes. Namespace consumers use
    /// [`Reader::metadata`].
    pub fn get_inode(&self, number: InodeNumber) -> ReadResult<Inode> {
        let (group, index) = self.inode_location(number)?;
        let table = self.groups[group as usize].inode_table_lo as u64 * BLOCK_BYTES;
        let mut bytes = [0u8; INODE_BYTES as usize];
        self.file
            .read_exact_at(&mut bytes, table + index as u64 * INODE_BYTES as u64)?;
        Ok(Inode::read_from(&bytes))
    }

    /// Validated metadata of an allocated inode.
    pub fn metadata(&self, number: InodeNumber) -> ReadResult<InodeMetadata> {
        let live = self.live(number)?;
        let raw = &live.raw;
        let time = |base, extra| decode_time(base, extra, number);
        Ok(InodeMetadata {
            number,
            kind: live.kind,
            permissions: raw.mode & 0o7777,
            uid: raw.uid_full(),
            gid: raw.gid_full(),
            size: live.size,
            links: raw.links_count,
            atime: time(raw.atime, raw.atime_extra)?,
            mtime: time(raw.mtime, raw.mtime_extra)?,
            ctime: time(raw.ctime, raw.ctime_extra)?,
            crtime: time(raw.crtime, raw.crtime_extra)?,
            flags: raw.flags & inode_flags::USER_ATTRIBUTES,
            generation: raw.generation,
            projid: raw.projid,
        })
    }

    /// Validated entries of a directory inode.
    pub fn read_dir(&self, number: InodeNumber) -> ReadResult<Directory> {
        let live = self.live(number)?;
        if live.kind != InodeKind::Directory {
            return Err(ReadError::NotADirectory(format!("inode {number}")));
        }
        self.read_live_dir(&live)
    }

    /// Inode named `name` in directory `dir`, if any.
    pub fn lookup(&self, dir: InodeNumber, name: &[u8]) -> ReadResult<Option<InodeNumber>> {
        Ok(self.read_dir(dir)?.lookup(name))
    }

    /// Raw `(name, inode)` pairs of a directory including `.` and `..`,
    /// sorted by name.
    pub fn children_of(&self, number: InodeNumber) -> ReadResult<Vec<(Vec<u8>, InodeNumber)>> {
        let directory = self.read_dir(number)?;
        let mut children = Vec::new();
        children.try_reserve_exact(directory.entries.len() + 2)?;
        children.push((b".".to_vec(), number));
        children.push((b"..".to_vec(), directory.parent));
        children.extend(
            directory
                .entries
                .into_iter()
                .map(|entry| (entry.name, entry.inode)),
        );
        children.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(children)
    }

    /// Walk the whole namespace from the root and cross-check it.
    ///
    /// Beyond per-structure validation of every reachable inode (directory
    /// blocks and htree, extent maps and block accounting, symlinks, xattrs),
    /// this proves: every directory has exactly one name and a correct `..`;
    /// entry types match inodes; each non-directory has exactly `i_links_count`
    /// names; directory link counts match subdirectories (or `DIR_NLINK`'s 1);
    /// and every allocated non-reserved inode is reachable (no orphans).
    pub fn audit(&self) -> ReadResult<AuditSummary> {
        let namespace = |inode, reason| ReadError::corrupt(Structure::Namespace, inode, reason);
        let mut seen = InodeSet::new(&self.geometry);
        let mut shared: HashMap<InodeNumber, (u32, u32)> = HashMap::new();
        let mut summary = AuditSummary::default();
        let root = self.live(ROOT_INODE)?;
        if root.kind != InodeKind::Directory {
            return Err(namespace(Some(ROOT_INODE), "root inode is not a directory"));
        }
        self.check_content(&root)?;
        seen.insert(ROOT_INODE)?;
        summary.directories = 1;
        // The root is a reserved inode, counted with the reserved range below.
        let mut reachable = 0u64;
        let mut queue = VecDeque::from([(ROOT_INODE, ROOT_INODE, root.raw.links_count)]);
        while let Some((dir, parent, links)) = queue.pop_front() {
            let directory = self.read_dir(dir)?;
            if directory.parent != parent {
                return Err(namespace(
                    Some(dir),
                    "'..' does not name the parent directory",
                ));
            }
            let mut subdirectories = 0u64;
            for entry in &directory.entries {
                summary.names += 1;
                let child = self.live(entry.inode)?;
                if child.kind.file_type() != entry.file_type {
                    return Err(ReadError::corrupt(
                        Structure::Directory,
                        Some(dir),
                        "entry file type differs from its inode",
                    ));
                }
                if child.kind == InodeKind::Directory {
                    if !seen.insert(entry.inode)? {
                        return Err(namespace(
                            Some(entry.inode),
                            "directory has more than one name",
                        ));
                    }
                    self.check_content(&child)?;
                    subdirectories += 1;
                    summary.directories += 1;
                    reachable += 1;
                    queue.try_reserve(1)?;
                    queue.push_back((entry.inode, dir, child.raw.links_count));
                } else if seen.insert(entry.inode)? {
                    self.check_content(&child)?;
                    reachable += 1;
                    match child.kind {
                        InodeKind::Regular => summary.regular_files += 1,
                        InodeKind::Symlink => summary.symlinks += 1,
                        _ => summary.special_files += 1,
                    }
                    if child.raw.links_count > 1 {
                        shared.try_reserve(1)?;
                        shared.insert(entry.inode, (u32::from(child.raw.links_count), 1));
                    }
                } else {
                    let Some((expected, observed)) = shared.get_mut(&entry.inode) else {
                        return Err(namespace(
                            Some(entry.inode),
                            "inode has more names than links",
                        ));
                    };
                    *observed += 1;
                    if *observed > *expected {
                        return Err(namespace(
                            Some(entry.inode),
                            "inode has more names than links",
                        ));
                    }
                }
            }
            let nlink_overflow = links == 1 && self.geometry.dir_nlink;
            if !nlink_overflow && links as u64 != subdirectories + 2 {
                return Err(namespace(
                    Some(dir),
                    "directory link count does not match its subdirectories",
                ));
            }
        }
        if let Some((inode, _)) = shared
            .iter()
            .find(|(_, (expected, observed))| expected != observed)
        {
            return Err(namespace(Some(*inode), "inode has fewer names than links"));
        }
        let allocated = self.groups.iter().try_fold(0u64, |sum, group| {
            sum.checked_add(
                (self.geometry.inodes_per_group as u64)
                    .saturating_sub(group.free_inodes_count_lo as u64),
            )
        });
        let reserved = self.geometry.first_inode as u64 - 1;
        if allocated != Some(reachable + reserved) {
            return Err(namespace(
                None,
                "allocated inodes are not exactly the reachable namespace",
            ));
        }
        Ok(summary)
    }

    // -- Validation helpers ---------------------------------------------------

    fn inode_location(&self, number: InodeNumber) -> ReadResult<(u32, u32)> {
        if number == 0 || number > self.geometry.inodes {
            return Err(ReadError::corrupt(
                Structure::Inode,
                Some(number),
                "inode number is out of range",
            ));
        }
        let index = number - 1;
        Ok((
            index / self.geometry.inodes_per_group,
            index % self.geometry.inodes_per_group,
        ))
    }

    fn inode_allocated(&self, number: InodeNumber) -> ReadResult<bool> {
        let (group, index) = self.inode_location(number)?;
        let descriptor = &self.groups[group as usize];
        if self.geometry.gdt_csum {
            if descriptor.flags & bg_flags::INODE_UNINIT != 0 {
                return Ok(false);
            }
            let initialized = self.geometry.inodes_per_group - descriptor.itable_unused_lo as u32;
            if index >= initialized {
                return Ok(false);
            }
        }
        let mut byte = [0u8; 1];
        self.file.read_exact_at(
            &mut byte,
            descriptor.inode_bitmap_lo as u64 * BLOCK_BYTES + index as u64 / 8,
        )?;
        Ok(byte[0] & (1 << (index % 8)) != 0)
    }

    /// Validate an inode referenced by the namespace.
    pub(crate) fn live(&self, number: InodeNumber) -> ReadResult<Live> {
        let corrupt = |reason| ReadError::corrupt(Structure::Inode, Some(number), reason);
        if number != ROOT_INODE && number < self.geometry.first_inode {
            return Err(corrupt("reserved inode is referenced by the namespace"));
        }
        if !self.inode_allocated(number)? {
            return Err(corrupt("inode is not allocated"));
        }
        let raw = self.get_inode(number)?;
        if raw.links_count == 0 {
            return Err(corrupt("allocated inode has no links"));
        }
        if raw.dtime != 0 {
            return Err(corrupt("allocated inode has a deletion time"));
        }
        if raw.extra_isize != EXTRA_ISIZE {
            if raw.extra_isize % 4 != 0 || raw.extra_isize > INODE_BYTES - 128 {
                return Err(corrupt("extra inode size is invalid"));
            }
            return Err(ReadError::Unsupported(Unsupported::InodeExtraSize {
                inode: number,
                extra_isize: raw.extra_isize,
            }));
        }
        let unknown = raw.flags & !(inode_flags::USER_ATTRIBUTES | inode_flags::READER_ENCODING);
        if unknown != 0 {
            return Err(ReadError::Unsupported(Unsupported::InodeFlags {
                inode: number,
                flags: unknown,
            }));
        }
        let kind = match raw.mode & file_mode::TYPE_MASK {
            file_mode::S_IFREG => InodeKind::Regular,
            file_mode::S_IFDIR => InodeKind::Directory,
            file_mode::S_IFLNK => InodeKind::Symlink,
            file_mode::S_IFCHR => InodeKind::CharacterDevice(decode_device(&raw, number)?),
            file_mode::S_IFBLK => InodeKind::BlockDevice(decode_device(&raw, number)?),
            file_mode::S_IFIFO => InodeKind::Fifo,
            file_mode::S_IFSOCK => InodeKind::Socket,
            _ => return Err(corrupt("unknown file type")),
        };
        if raw.flags & inode_flags::HASHED_INDEX != 0 && kind != InodeKind::Directory {
            return Err(corrupt("hash index flag on a non-directory"));
        }
        let special = !matches!(
            kind,
            InodeKind::Regular | InodeKind::Directory | InodeKind::Symlink
        );
        if special && raw.flags & inode_flags::EXTENTS != 0 {
            return Err(corrupt("special inode has an extent tree"));
        }
        let size = if kind == InodeKind::Regular {
            raw.file_size()
        } else if raw.size_hi != 0 {
            return Err(corrupt("non-regular inode has a high size word"));
        } else {
            raw.size_lo as u64
        };
        if size > MAX_FILE_SIZE {
            return Err(ReadError::Unsupported(Unsupported::FileTooLarge {
                inode: number,
                size,
            }));
        }
        if raw.xattr_block_hi != 0
            || (raw.xattr_block_lo != 0 && raw.xattr_block_lo as u64 >= self.geometry.blocks)
        {
            return Err(ReadError::corrupt(
                Structure::Xattr,
                Some(number),
                "xattr block is outside the filesystem",
            ));
        }
        let live = Live {
            number,
            raw,
            kind,
            size,
        };
        if special {
            if size != 0 {
                return Err(corrupt("special inode has a nonzero size"));
            }
            if matches!(kind, InodeKind::Fifo | InodeKind::Socket)
                && live.raw.block.iter().any(|byte| *byte != 0)
            {
                return Err(corrupt("fifo or socket has block data"));
            }
            self.check_charge(&live, 0)?;
        }
        Ok(live)
    }

    /// `i_blocks` in filesystem blocks, as Linux `ext4_inode_blocks` reads it.
    fn charged_blocks(&self, raw: &Inode, number: InodeNumber) -> ReadResult<u64> {
        if self.geometry.huge_file {
            let count = raw.blocks_lo as u64 | (raw.blocks_hi as u64) << 32;
            if raw.flags & inode_flags::HUGE_FILE != 0 {
                return Ok(count);
            }
            return sectors_to_blocks(count, number);
        }
        sectors_to_blocks(raw.blocks_lo as u64, number)
    }

    /// Exact allocation arithmetic: `i_blocks` equals mapped data and tree
    /// blocks plus the charged external xattr block.
    pub(crate) fn check_charge(&self, live: &Live, mapped: u64) -> ReadResult<()> {
        let xattr = u64::from(live.raw.xattr_block_lo != 0);
        if self.charged_blocks(&live.raw, live.number)? != mapped + xattr {
            return Err(ReadError::corrupt(
                Structure::Inode,
                Some(live.number),
                "block count does not match the mapped blocks",
            ));
        }
        Ok(())
    }

    pub(crate) fn extent_map(&self, live: &Live) -> ReadResult<ExtentMap> {
        extent::walk_extents(
            &live.raw,
            Some(live.number),
            self.geometry.blocks,
            &mut |block, buffer| self.file.read_exact_at(buffer, block as u64 * BLOCK_BYTES),
        )
    }

    /// Validated extent map of a regular file or slow symlink; an inode
    /// without `EXTENTS` is accepted only when wholly empty.
    pub(crate) fn data_map(&self, live: &Live) -> ReadResult<ExtentMap> {
        let map = if live.raw.flags & inode_flags::EXTENTS != 0 {
            self.extent_map(live)?
        } else if live.size == 0 && live.raw.block.iter().all(|byte| *byte == 0) {
            ExtentMap::default()
        } else {
            return Err(ReadError::Unsupported(Unsupported::BlockMappedInode(
                live.number,
            )));
        };
        self.check_charge(live, map.data_blocks() + map.tree_blocks)?;
        Ok(map)
    }

    /// Validate the content an inode kind owns, as `audit` requires.
    fn check_content(&self, live: &Live) -> ReadResult<()> {
        match live.kind {
            InodeKind::Regular => {
                self.data_map(live)?;
            }
            InodeKind::Symlink => {
                self.live_symlink_target(live)?;
            }
            // Directory blocks are validated when the walk reads them;
            // special inodes are fully validated by `live`.
            _ => {}
        }
        self.live_xattrs(live)?;
        Ok(())
    }

    fn read_live_dir(&self, live: &Live) -> ReadResult<Directory> {
        let number = live.number;
        let corrupt = |reason| ReadError::corrupt(Structure::Directory, Some(number), reason);
        if live.raw.flags & inode_flags::EXTENTS == 0 {
            if live.raw.block.iter().any(|byte| *byte != 0) {
                return Err(ReadError::Unsupported(Unsupported::BlockMappedInode(
                    number,
                )));
            }
            return Err(corrupt("directory has no blocks"));
        }
        if live.size == 0 || live.size % BLOCK_BYTES != 0 {
            return Err(corrupt("directory size is not a positive block multiple"));
        }
        let blocks = live.size / BLOCK_BYTES;
        let map = self.extent_map(live)?;
        let mut next = 0u64;
        for extent in &map.extents {
            if extent.unwritten || extent.logical as u64 != next {
                return Err(corrupt("directory blocks are not one initialized run"));
            }
            next += extent.length as u64;
        }
        if next != blocks {
            return Err(corrupt("directory blocks do not match its size"));
        }
        self.check_charge(live, map.data_blocks() + map.tree_blocks)?;

        let indexed = self.geometry.dir_index && live.raw.flags & inode_flags::HASHED_INDEX != 0;
        let mut htree: Option<(HashVersion, Vec<DxEntry>, u8)> = None;
        let mut hash_ranges: Vec<Option<(u32, u32)>> = Vec::new();
        if indexed {
            hash_ranges.try_reserve_exact(blocks as usize)?;
            hash_ranges.resize(blocks as usize, None);
        }
        let mut entries = Vec::new();
        let mut parent = None;
        let mut block = vec![0u8; DIR_BLOCK_SIZE];
        let mut logical = 0usize;
        for extent in &map.extents {
            for offset in 0..extent.length as u64 {
                self.file
                    .read_exact_at(&mut block, (extent.physical as u64 + offset) * BLOCK_BYTES)?;
                let raw = dir::parse_dir_block(&block, self.geometry.inodes).map_err(corrupt)?;
                let mut named = raw.as_slice();
                if logical == 0 {
                    let (dot, dotdot) = match raw.as_slice() {
                        [dot, dotdot, ..] => (dot, dotdot),
                        _ => return Err(corrupt("first block lacks '.' and '..'")),
                    };
                    if dot.offset != 0
                        || dot.name != b"."
                        || dot.inode != number
                        || dot.file_type != FileType::Directory as u8
                    {
                        return Err(corrupt("first entry is not '.'"));
                    }
                    if dotdot.offset != dot.rec_len
                        || dotdot.name != b".."
                        || dotdot.file_type != FileType::Directory as u8
                    {
                        return Err(corrupt("second entry is not '..'"));
                    }
                    parent = Some(dotdot.inode);
                    named = &raw[2..];
                    if indexed {
                        htree = Some(self.htree_root(number, &block)?);
                        if !named.is_empty() {
                            return Err(ReadError::corrupt(
                                Structure::HashIndex,
                                Some(number),
                                "htree root block holds entries",
                            ));
                        }
                    }
                }
                for entry in named {
                    if entry.name == b"." || entry.name == b".." {
                        return Err(corrupt("misplaced '.' or '..' entry"));
                    }
                    let file_type = entry_file_type(entry.file_type)
                        .ok_or_else(|| corrupt("directory entry has an invalid file type"))?;
                    if entry.inode < self.geometry.first_inode {
                        return Err(corrupt("directory entry names a reserved inode"));
                    }
                    if let Some((version, _, _)) = &htree {
                        let (hash, _) =
                            dir::dx_hash(*version, self.superblock.hash_seed, entry.name);
                        let range = &mut hash_ranges[logical];
                        *range =
                            Some(range.map_or((hash, hash), |(low, high)| {
                                (low.min(hash), high.max(hash))
                            }));
                    }
                    if entries.len() >= MAX_DIRECTORY_ENTRIES {
                        return Err(ReadError::Unsupported(Unsupported::DirectoryTooLarge {
                            inode: number,
                            limit: MAX_DIRECTORY_ENTRIES,
                        }));
                    }
                    entries.try_reserve(1)?;
                    entries.push(DirEntry {
                        name: entry.name.to_vec(),
                        inode: entry.inode,
                        file_type,
                    });
                }
                logical += 1;
            }
        }
        let parent = parent.ok_or_else(|| corrupt("first block lacks '.' and '..'"))?;
        if parent != ROOT_INODE && (number == ROOT_INODE || parent < self.geometry.first_inode) {
            return Err(corrupt("'..' names an invalid inode"));
        }
        if let Some((_, root_entries, levels)) = htree {
            self.check_htree(number, &map, &root_entries, levels, &hash_ranges)?;
        }
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        if entries.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(corrupt("duplicate directory entry name"));
        }
        Ok(Directory {
            inode: number,
            parent,
            entries,
        })
    }

    fn htree_root(
        &self,
        number: InodeNumber,
        block: &[u8],
    ) -> ReadResult<(HashVersion, Vec<DxEntry>, u8)> {
        let root = dir::parse_dx_root(block)
            .map_err(|reason| ReadError::corrupt(Structure::HashIndex, Some(number), reason))?;
        let unsigned = self
            .geometry
            .hash_unsigned
            .ok_or(ReadError::Unsupported(Unsupported::HashSignedness(number)))?;
        let version = HashVersion::from_root(root.hash_version, unsigned).ok_or(
            ReadError::Unsupported(Unsupported::HashVersion {
                inode: number,
                version: root.hash_version,
            }),
        )?;
        if root.indirect_levels > 1 {
            return Err(ReadError::corrupt(
                Structure::HashIndex,
                Some(number),
                "htree is deeper than two levels",
            ));
        }
        Ok((version, root.entries, root.indirect_levels))
    }

    /// Prove the htree indexes every block exactly once and that each leaf's
    /// names hash into the key range Linux lookup would probe for them.
    fn check_htree(
        &self,
        number: InodeNumber,
        map: &ExtentMap,
        root: &[DxEntry],
        levels: u8,
        hash_ranges: &[Option<(u32, u32)>],
    ) -> ReadResult<()> {
        let mut referenced = Vec::new();
        referenced.try_reserve_exact(hash_ranges.len())?;
        referenced.resize(hash_ranges.len(), false);
        referenced[0] = true;
        let mut htree = HtreeCheck {
            reader: self,
            number,
            map,
            hash_ranges,
            referenced,
        };
        htree.node(root, 0, None, levels)?;
        if htree.referenced.iter().any(|seen| !seen) {
            return Err(ReadError::corrupt(
                Structure::HashIndex,
                Some(number),
                "directory block is not referenced by the htree",
            ));
        }
        Ok(())
    }

    fn check_journal(&self) -> ReadResult<()> {
        if !self.geometry.has_journal {
            return Ok(());
        }
        let corrupt = |reason| ReadError::corrupt(Structure::Journal, Some(JOURNAL_INODE), reason);
        let raw = self.get_inode(JOURNAL_INODE)?;
        if !raw.is_reg() || raw.flags & inode_flags::EXTENTS == 0 {
            return Err(corrupt(
                "journal inode is not an extent-mapped regular file",
            ));
        }
        let live = Live {
            number: JOURNAL_INODE,
            size: raw.file_size(),
            raw,
            kind: InodeKind::Regular,
        };
        let map = self.extent_map(&live)?;
        let first = map
            .extents
            .first()
            .filter(|extent| extent.logical == 0 && !extent.unwritten)
            .ok_or_else(|| corrupt("journal superblock is not mapped"))?;
        let mut header = [0u8; 0x24];
        self.file
            .read_exact_at(&mut header, first.physical as u64 * BLOCK_BYTES)?;
        let word = |offset: usize| {
            u32::from_be_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ])
        };
        if word(0) != JBD2_MAGIC || !matches!(word(4), 3 | 4) {
            return Err(corrupt("bad journal superblock magic or type"));
        }
        if word(0x0C) as u64 != BLOCK_BYTES
            || word(0x10) as u64 > live.size / BLOCK_BYTES
            || word(0x10) as u64 > map.data_blocks()
        {
            return Err(corrupt("journal geometry does not match its inode"));
        }
        if word(0x1C) != 0 {
            return Err(ReadError::RequiresRecovery(RecoveryReason::JournalNotEmpty));
        }
        let errno = word(0x20) as i32;
        if errno != 0 {
            return Err(ReadError::RequiresRecovery(RecoveryReason::JournalAborted(
                errno,
            )));
        }
        Ok(())
    }
}

struct HtreeCheck<'a> {
    reader: &'a Reader,
    number: InodeNumber,
    map: &'a ExtentMap,
    hash_ranges: &'a [Option<(u32, u32)>],
    referenced: Vec<bool>,
}

impl HtreeCheck<'_> {
    fn corrupt(&self, reason: &'static str) -> ReadError {
        ReadError::corrupt(Structure::HashIndex, Some(self.number), reason)
    }

    /// Check one index node covering hashes `>= lower` and below `upper` (a
    /// full key whose low bit marks a collision continuing past it).
    fn node(
        &mut self,
        entries: &[DxEntry],
        lower: u32,
        upper: Option<u32>,
        levels: u8,
    ) -> ReadResult<()> {
        let mut previous = lower;
        for (index, entry) in entries.iter().enumerate() {
            let child_lower = if index == 0 {
                lower
            } else {
                let key = entry.hash & !1;
                if key < previous || upper.is_some_and(|upper| key > upper & !1) {
                    return Err(self.corrupt("htree keys are out of order"));
                }
                previous = key;
                key
            };
            let child_upper = entries.get(index + 1).map(|next| next.hash).or(upper);
            let block = entry.block as usize;
            if block == 0 || block >= self.referenced.len() {
                return Err(self.corrupt("htree points outside the directory"));
            }
            if std::mem::replace(&mut self.referenced[block], true) {
                return Err(self.corrupt("htree references a block twice"));
            }
            if levels > 0 {
                let children = self.read_node(block as u64)?;
                self.node(&children, child_lower, child_upper, levels - 1)?;
                continue;
            }
            let Some((low, high)) = self.hash_ranges[block] else {
                continue;
            };
            let below_upper = match child_upper {
                None => true,
                Some(key) => high < key & !1 || (high == key & !1 && key & 1 != 0),
            };
            if low < child_lower || !below_upper {
                return Err(self.corrupt("htree leaf holds names outside its hash range"));
            }
        }
        Ok(())
    }

    fn read_node(&self, logical: u64) -> ReadResult<Vec<DxEntry>> {
        let extent = self
            .map
            .extents
            .iter()
            .find(|extent| {
                logical >= extent.logical as u64
                    && logical < extent.logical as u64 + extent.length as u64
            })
            .ok_or_else(|| self.corrupt("htree node block is not mapped"))?;
        let physical = extent.physical as u64 + logical - extent.logical as u64;
        let mut block = vec![0u8; DIR_BLOCK_SIZE];
        self.reader
            .file
            .read_exact_at(&mut block, physical * BLOCK_BYTES)?;
        if self.hash_ranges[logical as usize].is_some() {
            return Err(self.corrupt("htree interior node holds names"));
        }
        dir::parse_dx_node(&block).map_err(|reason| self.corrupt(reason))
    }
}

/// Lazily allocated per-group inode bitsets for the audit walk.
struct InodeSet {
    inodes_per_group: u32,
    groups: Vec<Vec<u64>>,
}

impl InodeSet {
    fn new(geometry: &Geometry) -> Self {
        Self {
            inodes_per_group: geometry.inodes_per_group,
            groups: (0..geometry.groups).map(|_| Vec::new()).collect(),
        }
    }

    /// Insert `number`; false when it was already present.
    fn insert(&mut self, number: InodeNumber) -> ReadResult<bool> {
        let index = number - 1;
        let words = &mut self.groups[(index / self.inodes_per_group) as usize];
        if words.is_empty() {
            let count = self.inodes_per_group.div_ceil(64) as usize;
            words.try_reserve_exact(count)?;
            words.resize(count, 0);
        }
        let bit = index % self.inodes_per_group;
        let word = &mut words[(bit / 64) as usize];
        let mask = 1u64 << (bit % 64);
        let fresh = *word & mask == 0;
        *word |= mask;
        Ok(fresh)
    }
}

impl Geometry {
    fn validate(superblock: &SuperBlock, image_bytes: u64) -> ReadResult<Self> {
        let corrupt = |reason| ReadError::corrupt(Structure::Superblock, None, reason);
        if superblock.rev_level != 1 {
            return Err(ReadError::Unsupported(Unsupported::Revision(
                superblock.rev_level,
            )));
        }
        if superblock.creator_os != 0 {
            return Err(ReadError::Unsupported(Unsupported::CreatorOs(
                superblock.creator_os,
            )));
        }
        if superblock.log_block_size != LOG_BLOCK_SIZE {
            return Err(ReadError::Unsupported(Unsupported::BlockSize(
                superblock.log_block_size,
            )));
        }
        let compat = superblock.feature_compat & !SUPPORTED_COMPAT;
        let incompat = superblock.feature_incompat & !(SUPPORTED_INCOMPAT | incompat::RECOVER);
        let ro_compat = superblock.feature_ro_compat & !SUPPORTED_RO_COMPAT;
        if compat | incompat | ro_compat != 0 {
            return Err(ReadError::Unsupported(Unsupported::Features {
                compat,
                incompat,
                ro_compat,
            }));
        }
        let missing = REQUIRED_INCOMPAT & !superblock.feature_incompat;
        if missing != 0 {
            return Err(ReadError::Unsupported(Unsupported::MissingFeatures(
                missing,
            )));
        }
        if superblock.inode_size != INODE_BYTES {
            return Err(ReadError::Unsupported(Unsupported::InodeSize(
                superblock.inode_size,
            )));
        }
        let has_journal = superblock.feature_compat & compat::HAS_JOURNAL != 0;
        if has_journal
            && (superblock.journal_inum != JOURNAL_INODE
                || superblock.journal_dev != 0
                || superblock.journal_uuid != [0; 16])
        {
            return Err(ReadError::Unsupported(Unsupported::ExternalJournal));
        }
        if superblock.log_cluster_size != superblock.log_block_size
            || superblock.clusters_per_group != superblock.blocks_per_group
        {
            return Err(corrupt("cluster geometry differs from block geometry"));
        }
        if superblock.first_data_block != 0 || superblock.blocks_count_hi != 0 {
            return Err(corrupt("block numbering is invalid for 4096-byte blocks"));
        }
        let blocks = superblock.blocks_count_lo as u64;
        let blocks_per_group = superblock.blocks_per_group;
        let inodes_per_group = superblock.inodes_per_group;
        if blocks == 0
            || !(8..=BLOCK_BYTES as u32 * 8).contains(&blocks_per_group)
            || blocks_per_group % 8 != 0
        {
            return Err(corrupt("block group geometry is invalid"));
        }
        let inodes_per_block = (BLOCK_BYTES / INODE_BYTES as u64) as u32;
        if inodes_per_group == 0
            || inodes_per_group > BLOCK_BYTES as u32 * 8
            || inodes_per_group % inodes_per_block != 0
        {
            return Err(corrupt("inodes per group is invalid"));
        }
        let groups = blocks.div_ceil(blocks_per_group as u64);
        if superblock.inodes_count as u64 != groups * inodes_per_group as u64 {
            return Err(corrupt("inode count does not match the group count"));
        }
        let groups = groups as u32;
        if superblock.first_ino < GOOD_OLD_FIRST_INODE
            || superblock.first_ino >= superblock.inodes_count
        {
            return Err(corrupt("first non-reserved inode is invalid"));
        }
        if superblock.reserved_gdt_blocks as u64 > BLOCK_BYTES / 4 {
            return Err(corrupt("reserved descriptor block count is too large"));
        }
        let descriptor_blocks = (groups as u64 * DESCRIPTOR_BYTES).div_ceil(BLOCK_BYTES);
        let superblock_zone = 1 + descriptor_blocks + superblock.reserved_gdt_blocks as u64;
        if superblock_zone >= blocks.min(blocks_per_group as u64) {
            return Err(corrupt("descriptor table does not fit in the first group"));
        }
        if image_bytes / BLOCK_BYTES < blocks {
            return Err(corrupt("filesystem extends past the end of the image"));
        }
        let flags = superblock.flags;
        let hash_unsigned = if flags & fs_flags::UNSIGNED_HASH != 0 {
            Some(true)
        } else if flags & fs_flags::SIGNED_HASH != 0 {
            Some(false)
        } else {
            None
        };
        let ro = superblock.feature_ro_compat;
        Ok(Self {
            blocks,
            groups,
            inodes: superblock.inodes_count,
            inodes_per_group,
            blocks_per_group,
            first_inode: superblock.first_ino,
            superblock_zone,
            inode_table_blocks: inodes_per_group as u64 / inodes_per_block as u64,
            sparse_super: ro & ro_compat::SPARSE_SUPER != 0,
            huge_file: ro & ro_compat::HUGE_FILE != 0,
            gdt_csum: ro & ro_compat::GDT_CSUM != 0,
            dir_index: superblock.feature_compat & compat::DIR_INDEX != 0,
            dir_nlink: ro & ro_compat::DIR_NLINK != 0,
            has_journal,
            hash_unsigned,
        })
    }

    fn has_superblock(&self, group: u64) -> bool {
        !self.sparse_super || u32::try_from(group).is_ok_and(has_sparse_super)
    }

    /// True when `[start, end)` overlaps a superblock/descriptor zone.
    fn overlaps_superblock_zone(&self, start: u64, end: u64) -> bool {
        let per_group = self.blocks_per_group as u64;
        (start / per_group..=(end - 1) / per_group).any(|group| {
            let zone = group * per_group;
            self.has_superblock(group) && start < zone + self.superblock_zone && end > zone
        })
    }
}

/// Dirty or unclean superblock state, checked before any other metadata.
fn check_clean_state(superblock: &SuperBlock) -> ReadResult<()> {
    if superblock.feature_incompat & incompat::RECOVER != 0 {
        return Err(ReadError::RequiresRecovery(
            RecoveryReason::JournalNeedsRecovery,
        ));
    }
    let state = superblock.state;
    if state & fs_state::ERROR != 0 {
        return Err(ReadError::RequiresRecovery(RecoveryReason::RecordedErrors(
            state,
        )));
    }
    if state & fs_state::VALID == 0 || state & fs_state::ORPHAN != 0 {
        return Err(ReadError::RequiresRecovery(
            RecoveryReason::NotCleanlyUnmounted(state),
        ));
    }
    if state & !(fs_state::VALID | fs_state::ERROR | fs_state::ORPHAN) != 0 {
        return Err(ReadError::corrupt(
            Structure::Superblock,
            None,
            "unknown filesystem state bits",
        ));
    }
    if superblock.last_orphan != 0 {
        return Err(ReadError::RequiresRecovery(RecoveryReason::OrphanInodes(
            superblock.last_orphan,
        )));
    }
    Ok(())
}

fn load_groups(
    file: &File,
    superblock: &SuperBlock,
    geometry: &Geometry,
) -> ReadResult<Vec<GroupDescriptor>> {
    let bytes = geometry.groups as usize * GroupDescriptor::SIZE;
    let mut table = Vec::new();
    table.try_reserve_exact(bytes)?;
    table.resize(bytes, 0u8);
    file.read_exact_at(&mut table, BLOCK_BYTES)?;
    let mut groups = Vec::new();
    groups.try_reserve_exact(geometry.groups as usize)?;
    for (number, chunk) in table.chunks_exact(GroupDescriptor::SIZE).enumerate() {
        let number = number as u32;
        let descriptor = GroupDescriptor::read_from(chunk);
        validate_group(superblock, geometry, number, &descriptor)?;
        groups.push(descriptor);
    }
    Ok(groups)
}

fn validate_group(
    superblock: &SuperBlock,
    geometry: &Geometry,
    number: u32,
    descriptor: &GroupDescriptor,
) -> ReadResult<()> {
    let corrupt = |reason| ReadError::corrupt(Structure::GroupDescriptor(number), None, reason);
    if geometry.gdt_csum
        && checksum::group_descriptor(&superblock.uuid, number, descriptor) != descriptor.checksum
    {
        return Err(corrupt("group descriptor checksum mismatch"));
    }
    if descriptor.flags
        & !(bg_flags::INODE_UNINIT | bg_flags::BLOCK_UNINIT | bg_flags::INODE_ZEROED)
        != 0
    {
        return Err(corrupt("unknown block group flags"));
    }
    for (start, count) in [
        (descriptor.block_bitmap_lo as u64, 1),
        (descriptor.inode_bitmap_lo as u64, 1),
        (
            descriptor.inode_table_lo as u64,
            geometry.inode_table_blocks,
        ),
    ] {
        let end = start + count;
        if start == 0 || end > geometry.blocks || geometry.overlaps_superblock_zone(start, end) {
            return Err(corrupt("group metadata is outside the usable filesystem"));
        }
    }
    let group_start = number as u64 * geometry.blocks_per_group as u64;
    let group_blocks = (geometry.blocks - group_start).min(geometry.blocks_per_group as u64);
    let free_inodes = descriptor.free_inodes_count_lo as u32;
    if descriptor.free_blocks_count_lo as u64 > group_blocks
        || free_inodes > geometry.inodes_per_group
        || descriptor.used_dirs_count_lo as u32 > geometry.inodes_per_group - free_inodes
        || (geometry.gdt_csum && descriptor.itable_unused_lo as u32 > free_inodes)
    {
        return Err(corrupt("group counters are inconsistent"));
    }
    Ok(())
}

fn sectors_to_blocks(sectors: u64, number: InodeNumber) -> ReadResult<u64> {
    let per_block = BLOCK_BYTES / 512;
    if sectors % per_block != 0 {
        return Err(ReadError::corrupt(
            Structure::Inode,
            Some(number),
            "block count is not a whole number of blocks",
        ));
    }
    Ok(sectors / per_block)
}

fn decode_time(base: u32, extra: u32, number: InodeNumber) -> ReadResult<Timestamp> {
    let nanos = extra >> 2;
    if nanos >= 1_000_000_000 {
        return Err(ReadError::corrupt(
            Structure::Inode,
            Some(number),
            "timestamp nanoseconds are out of range",
        ));
    }
    Ok(Timestamp {
        seconds: base as i32 as i64 + (((extra & 3) as i64) << 32),
        nanos,
    })
}

/// Linux `ext4_iget` device decoding: old 8:8 encoding in `i_block[0]`, else
/// `new_encode_dev` in `i_block[1]`. Unused words must be zero.
fn decode_device(raw: &Inode, number: InodeNumber) -> ReadResult<DeviceId> {
    let corrupt = || ReadError::corrupt(Structure::Inode, Some(number), "invalid device number");
    let word = |index: usize| {
        u32::from_le_bytes([
            raw.block[index * 4],
            raw.block[index * 4 + 1],
            raw.block[index * 4 + 2],
            raw.block[index * 4 + 3],
        ])
    };
    if raw.block[8..].iter().any(|byte| *byte != 0) {
        return Err(corrupt());
    }
    let (old, new) = (word(0), word(1));
    let (major, minor) = if old != 0 {
        if old > 0xffff || new != 0 {
            return Err(corrupt());
        }
        ((old >> 8) & 0xff, old & 0xff)
    } else {
        ((new & 0xfff00) >> 8, (new & 0xff) | ((new >> 12) & 0xfff00))
    };
    DeviceId::new(major, minor).map_err(|_| corrupt())
}

fn entry_file_type(raw: u8) -> Option<FileType> {
    Some(match raw {
        1 => FileType::Regular,
        2 => FileType::Directory,
        3 => FileType::Character,
        4 => FileType::Block,
        5 => FileType::Fifo,
        6 => FileType::Socket,
        7 => FileType::SymbolicLink,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::FileExt;
    use std::path::{Path, PathBuf};

    use crate::ext4::constants::*;
    use crate::ext4::dir::parse_dir_block;
    use crate::ext4::error::{
        Corruption, ReadError, ReadResult, RecoveryReason, Structure, Unsupported,
    };
    use crate::ext4::reader::{AuditSummary, InodeKind, Reader, Timestamp, read_superblock};
    use crate::ext4::types::{GroupDescriptor, Inode, SuperBlock};
    use crate::ext4::{DeviceId, FileData, FileRange, Formatter, SparseData, checksum, extent};

    type Mutation<T> = fn(&mut T);

    struct Image {
        _directory: tempfile::TempDir,
        path: PathBuf,
    }

    fn build(setup: impl FnOnce(&mut Formatter)) -> Image {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image.ext4");
        let mut formatter = Formatter::new(&path, 4096, 64 << 20).unwrap();
        setup(&mut formatter);
        formatter.close().unwrap();
        Image {
            _directory: directory,
            path,
        }
    }

    fn create(
        formatter: &mut Formatter,
        path: &str,
        mode: u16,
        data: Option<&[u8]>,
        link: Option<&[u8]>,
        xattrs: Option<&[(&[u8], &[u8])]>,
        device: Option<DeviceId>,
    ) {
        let mut bytes = data.unwrap_or_default();
        let contents = if data.is_some() {
            Some(FileData::Dense(&mut bytes))
        } else {
            None
        };
        formatter
            .create(path, mode, link, None, contents, None, None, xattrs, device)
            .unwrap();
    }

    fn pattern(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index * 31 % 251) as u8).collect()
    }

    const DENSE: usize = 3 * 4096 + 17;
    const SPARSE_LENGTH: u64 = 8 * 4096 + 100;

    fn fixture() -> Image {
        build(|formatter| {
            let reg = |permissions| make_mode(file_mode::S_IFREG, permissions);
            let chr = make_mode(file_mode::S_IFCHR, 0o600);
            create(
                formatter,
                "/dir",
                make_mode(file_mode::S_IFDIR, 0o750),
                None,
                None,
                None,
                None,
            );
            create(
                formatter,
                "/dir/dense",
                reg(0o644),
                Some(&pattern(DENSE)),
                None,
                None,
                None,
            );
            formatter.link("/dir/alias", "/dir/dense").unwrap();
            create(formatter, "/empty", reg(0o600), Some(b""), None, None, None);
            let symlink = make_mode(file_mode::S_IFLNK, 0o777);
            create(
                formatter,
                "/fast",
                symlink,
                None,
                Some(b"dir/dense"),
                None,
                None,
            );
            create(
                formatter,
                "/slow",
                symlink,
                None,
                Some(&[b'x'; 100]),
                None,
                None,
            );
            create(
                formatter,
                "/fifo",
                make_mode(file_mode::S_IFIFO, 0o600),
                None,
                None,
                None,
                None,
            );
            create(
                formatter,
                "/socket",
                make_mode(file_mode::S_IFSOCK, 0o600),
                None,
                None,
                None,
                None,
            );
            create(
                formatter,
                "/null",
                chr,
                None,
                None,
                None,
                Some(DeviceId::new(1, 3).unwrap()),
            );
            create(
                formatter,
                "/wide",
                chr,
                None,
                None,
                None,
                Some(DeviceId::new(4095, 0xfffff).unwrap()),
            );
            create(
                formatter,
                "/whiteout",
                chr,
                None,
                None,
                None,
                Some(DeviceId::new(0, 0).unwrap()),
            );
            let block = make_mode(file_mode::S_IFBLK, 0o600);
            create(
                formatter,
                "/disk",
                block,
                None,
                None,
                None,
                Some(DeviceId::new(8, 1).unwrap()),
            );
            let large = [7u8; 2000];
            let attrs: [(&[u8], &[u8]); 3] = [
                (b"user.small", b"v"),
                (b"user.large", &large),
                (b"trusted.overlay.origin", b"\x00\xfb\x21"),
            ];
            create(
                formatter,
                "/attrs",
                reg(0o644),
                Some(b"a"),
                None,
                Some(&attrs),
                None,
            );
            let xdata: [(&[u8], &[u8]); 1] = [(b"user.data", b"1")];
            create(
                formatter,
                "/xdata",
                reg(0o644),
                Some(b""),
                None,
                Some(&xdata),
                None,
            );
            let stored = [pattern(5000), pattern(4096)].concat();
            let mut stored = stored.as_slice();
            let mut ranges = [
                FileRange {
                    offset: 4096,
                    length: 5000,
                },
                FileRange {
                    offset: 5 * 4096,
                    length: 4096,
                },
            ]
            .into_iter();
            formatter
                .create(
                    "/sparse",
                    reg(0o644),
                    None,
                    None,
                    Some(FileData::Sparse(SparseData {
                        reader: &mut stored,
                        length: SPARSE_LENGTH,
                        ranges: &mut ranges,
                    })),
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();
        })
    }

    fn open(path: &Path) -> ReadResult<Reader> {
        Reader::new(path)
    }

    fn number(path: &Path, name: &str) -> u32 {
        open(path).unwrap().stat_no_follow(name).unwrap().0
    }

    fn writable(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    fn inode_offset(path: &Path, number: u32) -> u64 {
        let reader = open(path).unwrap();
        let per_group = reader.superblock().inodes_per_group;
        let group = reader
            .get_group_descriptor((number - 1) / per_group)
            .unwrap();
        group.inode_table_lo as u64 * 4096 + ((number - 1) % per_group) as u64 * 256
    }

    fn patch_inode(path: &Path, number: u32, change: impl FnOnce(&mut Inode)) {
        let offset = inode_offset(path, number);
        let file = writable(path);
        let mut bytes = [0u8; 256];
        file.read_exact_at(&mut bytes, offset).unwrap();
        let mut inode = Inode::read_from(&bytes);
        change(&mut inode);
        inode.write_to(&mut bytes);
        file.write_all_at(&bytes, offset).unwrap();
    }

    fn patch_superblock(path: &Path, change: impl FnOnce(&mut SuperBlock)) {
        let file = writable(path);
        let mut superblock = read_superblock(&file).unwrap();
        change(&mut superblock);
        let mut bytes = [0u8; 1024];
        superblock.write_to(&mut bytes);
        file.write_all_at(&bytes, 1024).unwrap();
    }

    fn patch_group(path: &Path, fix_checksum: bool, change: impl FnOnce(&mut GroupDescriptor)) {
        let file = writable(path);
        let uuid = read_superblock(&file).unwrap().uuid;
        let mut bytes = [0u8; 32];
        file.read_exact_at(&mut bytes, 4096).unwrap();
        let mut group = GroupDescriptor::read_from(&bytes);
        change(&mut group);
        if fix_checksum {
            group.checksum = checksum::group_descriptor(&uuid, 0, &group);
        }
        group.write_to(&mut bytes);
        file.write_all_at(&bytes, 4096).unwrap();
    }

    fn first_block(path: &Path, number: u32) -> u64 {
        let inode = open(path).unwrap().get_inode(number).unwrap();
        extent::parse_extents(&inode, 4096, &mut File::open(path).unwrap()).unwrap()[0].0 as u64
    }

    /// Byte offset of the named live entry in a directory's first block.
    fn entry_offset(path: &Path, directory: u32, name: &[u8]) -> u64 {
        let block = first_block(path, directory) * 4096;
        let mut bytes = vec![0u8; 4096];
        File::open(path)
            .unwrap()
            .read_exact_at(&mut bytes, block)
            .unwrap();
        let entry = parse_dir_block(&bytes, u32::MAX)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == name)
            .unwrap();
        block + entry.offset as u64
    }

    fn corruption<T>(result: ReadResult<T>) -> Corruption {
        match result {
            Err(ReadError::Corrupt(corruption)) => corruption,
            Err(other) => panic!("expected corruption, got {other:?}"),
            Ok(_) => panic!("expected corruption, got success"),
        }
    }

    fn unsupported<T>(result: ReadResult<T>) -> Unsupported {
        match result {
            Err(ReadError::Unsupported(unsupported)) => unsupported,
            Err(other) => panic!("expected unsupported, got {other:?}"),
            Ok(_) => panic!("expected unsupported, got success"),
        }
    }

    fn recovery<T>(result: ReadResult<T>) -> RecoveryReason {
        match result {
            Err(ReadError::RequiresRecovery(reason)) => reason,
            Err(other) => panic!("expected recovery, got {other:?}"),
            Ok(_) => panic!("expected recovery, got success"),
        }
    }

    #[test]
    fn fixture_audits_and_reads_exact_metadata_bodies_and_xattrs() {
        let image = fixture();
        let mut file = File::open(&image.path).unwrap();
        file.seek(SeekFrom::Start(12_345)).unwrap();
        let reader = Reader::from_file(file).unwrap();
        assert_eq!(
            reader.audit().unwrap(),
            AuditSummary {
                directories: 3,
                regular_files: 5,
                symlinks: 2,
                special_files: 6,
                names: 16,
            }
        );
        assert_eq!(reader.uuid(), reader.superblock().uuid);

        let root = reader.read_dir(ROOT_INODE).unwrap();
        assert_eq!(root.parent, ROOT_INODE);
        assert!(
            root.entries
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name)
        );
        let dir = root.lookup(b"dir").unwrap();
        let listing = reader.read_dir(dir).unwrap();
        assert_eq!(listing.parent, ROOT_INODE);
        let names: Vec<_> = listing
            .entries
            .iter()
            .map(|entry| entry.name.as_slice())
            .collect();
        assert_eq!(names, [b"alias".as_slice(), b"dense"]);
        assert_eq!(listing.entries[0].inode, listing.entries[1].inode);
        assert_eq!(listing.entries[0].file_type, FileType::Regular);
        assert_eq!(reader.lookup(dir, b"missing").unwrap(), None);
        assert!(matches!(
            reader.read_dir(listing.entries[0].inode),
            Err(ReadError::NotADirectory(_))
        ));

        let dense = listing.entries[1].inode;
        let metadata = reader.metadata(dense).unwrap();
        assert_eq!(metadata.kind, InodeKind::Regular);
        assert_eq!((metadata.size, metadata.links), (DENSE as u64, 2));
        assert_eq!(metadata.permissions, 0o644);
        assert_eq!(metadata.flags, 0);
        assert_eq!(reader.metadata(dir).unwrap().permissions, 0o750);
        let body = reader.file_body(dense).unwrap();
        assert!(body.is_dense());
        assert_eq!(
            body.stored_ranges().collect::<Vec<_>>(),
            [FileRange {
                offset: 0,
                length: DENSE as u64
            }]
        );
        let mut streamed = Vec::new();
        reader
            .body_stream(&body)
            .read_to_end(&mut streamed)
            .unwrap();
        assert_eq!(streamed, pattern(DENSE));
        let mut middle = [0u8; 100];
        reader.read_at(&body, 4090, &mut middle).unwrap();
        assert_eq!(middle.as_slice(), &pattern(DENSE)[4090..4190]);
        assert!(matches!(
            reader.read_at(&body, DENSE as u64 - 1, &mut middle),
            Err(ReadError::OutOfRange { .. })
        ));

        let empty = reader.file_body(root.lookup(b"empty").unwrap()).unwrap();
        assert_eq!((empty.size(), empty.stored_ranges().count()), (0, 0));
        assert!(empty.is_dense());

        assert_eq!(
            reader
                .symlink_target(root.lookup(b"fast").unwrap())
                .unwrap(),
            b"dir/dense"
        );
        assert_eq!(
            reader
                .symlink_target(root.lookup(b"slow").unwrap())
                .unwrap(),
            [b'x'; 100]
        );
        for (name, kind) in [
            ("fifo", InodeKind::Fifo),
            ("socket", InodeKind::Socket),
            (
                "null",
                InodeKind::CharacterDevice(DeviceId::new(1, 3).unwrap()),
            ),
            (
                "wide",
                InodeKind::CharacterDevice(DeviceId::new(4095, 0xfffff).unwrap()),
            ),
            (
                "whiteout",
                InodeKind::CharacterDevice(DeviceId::new(0, 0).unwrap()),
            ),
            ("disk", InodeKind::BlockDevice(DeviceId::new(8, 1).unwrap())),
        ] {
            let metadata = reader
                .metadata(root.lookup(name.as_bytes()).unwrap())
                .unwrap();
            assert_eq!((metadata.kind, metadata.size), (kind, 0), "{name}");
        }

        let attrs = root.lookup(b"attrs").unwrap();
        assert_ne!(reader.get_inode(attrs).unwrap().xattr_block_lo, 0);
        assert_eq!(
            reader.inode_xattrs(attrs).unwrap(),
            BTreeMap::from([
                (b"trusted.overlay.origin".to_vec(), b"\x00\xfb\x21".to_vec()),
                (b"user.large".to_vec(), vec![7u8; 2000]),
                (b"user.small".to_vec(), b"v".to_vec()),
            ])
        );
        assert_eq!(
            reader.xattrs("/attrs").unwrap(),
            reader.inode_xattrs(attrs).unwrap()
        );
        assert_eq!(reader.read_file("/fast", 0, None).unwrap(), pattern(DENSE));
        assert_eq!(
            reader.children_of(dir).unwrap()[..2],
            [(b".".to_vec(), dir), (b"..".to_vec(), ROOT_INODE)]
        );
        // Positioned reads never move the held descriptor's cursor.
        assert_eq!(reader.file().stream_position().unwrap(), 12_345);
    }

    #[test]
    fn sparse_unwritten_and_beyond_eof_bodies_are_exact() {
        let image = fixture();
        let reader = open(&image.path).unwrap();
        let sparse = reader.stat("/sparse").unwrap().0;
        let body = reader.file_body(sparse).unwrap();
        assert_eq!(body.size(), SPARSE_LENGTH);
        assert!(!body.is_dense());
        assert_eq!(
            body.stored_ranges().collect::<Vec<_>>(),
            [
                FileRange {
                    offset: 4096,
                    length: 8192
                },
                FileRange {
                    offset: 5 * 4096,
                    length: 4096
                },
            ]
        );
        let mut stream = Vec::new();
        reader.body_stream(&body).read_to_end(&mut stream).unwrap();
        assert_eq!(stream.len() as u64, body.stored_bytes());
        let mut expected = vec![0u8; SPARSE_LENGTH as usize];
        expected[4096..9096].copy_from_slice(&pattern(5000));
        expected[5 * 4096..6 * 4096].copy_from_slice(&pattern(4096));
        assert_eq!(stream[..8192], expected[4096..12288]);
        assert_eq!(stream[8192..], expected[5 * 4096..6 * 4096]);
        assert_eq!(reader.read_file("/sparse", 0, None).unwrap(), expected);
        drop(reader);

        // Unwritten extents read as zeros and are not stored ranges.
        let dense = number(&image.path, "/dir/dense");
        patch_inode(&image.path, dense, |inode| {
            let length = u16::from_le_bytes([inode.block[16], inode.block[17]]);
            inode.block[16..18].copy_from_slice(&(length + 0x8000).to_le_bytes());
        });
        let reader = open(&image.path).unwrap();
        let body = reader.file_body(dense).unwrap();
        assert_eq!(body.stored_ranges().count(), 0);
        assert_eq!(
            reader.read_file("/dir/dense", 0, None).unwrap(),
            vec![0; DENSE]
        );
        reader.audit().unwrap();
        drop(reader);

        // Allocation beyond i_size (FALLOC_FL_KEEP_SIZE) is admitted and clipped.
        patch_inode(&image.path, dense, |inode| {
            let length = u16::from_le_bytes([inode.block[16], inode.block[17]]);
            inode.block[16..18].copy_from_slice(&(length - 0x8000).to_le_bytes());
            inode.set_file_size(4000);
        });
        let reader = open(&image.path).unwrap();
        let body = reader.file_body(dense).unwrap();
        assert_eq!(
            body.stored_ranges().collect::<Vec<_>>(),
            [FileRange {
                offset: 0,
                length: 4000
            }]
        );
        assert_eq!(
            reader.read_file("/dir/dense", 0, None).unwrap(),
            pattern(DENSE)[..4000]
        );
        reader.audit().unwrap();
    }

    #[test]
    fn unsupported_features_are_refused_with_the_offending_bits() {
        let cases = [
            (0, incompat::INLINE_DATA, 0),
            (0, incompat::EA_INODE, 0),
            (0, incompat::BIT64, 0),
            (0, incompat::META_BG, 0),
            (0, incompat::MMP, 0),
            (0, incompat::CSUM_SEED, 0),
            (0, incompat::LARGEDIR, 0),
            (0, incompat::ENCRYPT, 0),
            (0, 0x2_0000, 0),
            (0, 0, ro_compat::METADATA_CSUM),
            (0, 0, ro_compat::BIGALLOC),
            (0, 0, ro_compat::QUOTA),
            (0, 0, ro_compat::PROJECT),
            (0, 0, ro_compat::READONLY),
            (0, 0, 0x8000),
            (compat::SPARSE_SUPER2, 0, 0),
            (0x400, 0, 0),
            (0x1000, 0, 0),
        ];
        for (compat_bits, incompat_bits, ro_bits) in cases {
            let image = fixture();
            patch_superblock(&image.path, |superblock| {
                superblock.feature_compat |= compat_bits;
                superblock.feature_incompat |= incompat_bits | incompat::RECOVER;
                superblock.feature_ro_compat |= ro_bits;
            });
            // Unsupported formats are reported even when also dirty.
            assert_eq!(
                unsupported(open(&image.path)),
                Unsupported::Features {
                    compat: compat_bits,
                    incompat: incompat_bits,
                    ro_compat: ro_bits,
                }
            );
        }
        let image = fixture();
        patch_superblock(&image.path, |superblock| {
            superblock.feature_incompat &= !incompat::EXTENTS;
        });
        assert_eq!(
            unsupported(open(&image.path)),
            Unsupported::MissingFeatures(incompat::EXTENTS)
        );
    }

    #[test]
    fn dirty_state_requires_recovery_before_any_read() {
        let cases: [(Mutation<SuperBlock>, RecoveryReason); 5] = [
            (
                |superblock| superblock.feature_incompat |= incompat::RECOVER,
                RecoveryReason::JournalNeedsRecovery,
            ),
            (
                |superblock| superblock.state = 3,
                RecoveryReason::RecordedErrors(3),
            ),
            (
                |superblock| superblock.state = 0,
                RecoveryReason::NotCleanlyUnmounted(0),
            ),
            (
                |superblock| superblock.state = 5,
                RecoveryReason::NotCleanlyUnmounted(5),
            ),
            (
                |superblock| superblock.last_orphan = 12,
                RecoveryReason::OrphanInodes(12),
            ),
        ];
        for (change, expected) in cases {
            let image = fixture();
            patch_superblock(&image.path, change);
            assert_eq!(recovery(open(&image.path)), expected);
            // Superblock facts stay readable for exact-copy callers.
            read_superblock(&File::open(&image.path).unwrap()).unwrap();
        }
        for (offset, value, expected) in [
            (0x1C, 7u32, RecoveryReason::JournalNotEmpty),
            (0x20, (-5i32) as u32, RecoveryReason::JournalAborted(-5)),
        ] {
            let image = fixture();
            let journal = first_block(&image.path, 8) * 4096;
            writable(&image.path)
                .write_all_at(&value.to_be_bytes(), journal + offset)
                .unwrap();
            assert_eq!(recovery(open(&image.path)), expected);
        }
        let image = fixture();
        let journal = first_block(&image.path, 8) * 4096;
        writable(&image.path)
            .write_all_at(&[0; 4], journal)
            .unwrap();
        assert_eq!(corruption(open(&image.path)).structure, Structure::Journal);
    }

    #[test]
    fn superblock_geometry_is_validated() {
        let unsupported_cases: [(Mutation<SuperBlock>, Unsupported); 5] = [
            (|sb| sb.rev_level = 0, Unsupported::Revision(0)),
            (|sb| sb.creator_os = 3, Unsupported::CreatorOs(3)),
            (|sb| sb.log_block_size = 0, Unsupported::BlockSize(0)),
            (|sb| sb.inode_size = 128, Unsupported::InodeSize(128)),
            (|sb| sb.journal_dev = 1, Unsupported::ExternalJournal),
        ];
        for (change, expected) in unsupported_cases {
            let image = fixture();
            patch_superblock(&image.path, change);
            assert_eq!(unsupported(open(&image.path)), expected);
        }
        let corrupt_cases: [(Mutation<SuperBlock>, &str); 6] = [
            (
                |sb| sb.inodes_count += 1,
                "inode count does not match the group count",
            ),
            (
                |sb| sb.first_data_block = 1,
                "block numbering is invalid for 4096-byte blocks",
            ),
            (
                |sb| sb.blocks_count_hi = 1,
                "block numbering is invalid for 4096-byte blocks",
            ),
            (
                |sb| sb.log_cluster_size = 3,
                "cluster geometry differs from block geometry",
            ),
            (|sb| sb.inodes_per_group = 17, "inodes per group is invalid"),
            (|sb| sb.first_ino = 3, "first non-reserved inode is invalid"),
        ];
        for (change, expected) in corrupt_cases {
            let image = fixture();
            patch_superblock(&image.path, change);
            let corruption = corruption(open(&image.path));
            assert_eq!(
                (corruption.structure, corruption.reason),
                (Structure::Superblock, expected)
            );
        }
        let image = fixture();
        let blocks = read_superblock(&File::open(&image.path).unwrap())
            .unwrap()
            .blocks_count_lo as u64;
        writable(&image.path).set_len(blocks * 4096 - 4096).unwrap();
        assert_eq!(
            corruption(open(&image.path)).reason,
            "filesystem extends past the end of the image"
        );
    }

    #[test]
    fn group_descriptors_are_validated() {
        let image = fixture();
        patch_group(&image.path, false, |group| group.free_blocks_count_lo ^= 1);
        let corrupt = corruption(open(&image.path));
        assert_eq!(
            (corrupt.structure, corrupt.reason),
            (
                Structure::GroupDescriptor(0),
                "group descriptor checksum mismatch"
            )
        );
        let cases: [(Mutation<GroupDescriptor>, &str); 4] = [
            (
                |group| group.inode_table_lo = 1,
                "group metadata is outside the usable filesystem",
            ),
            (
                |group| group.block_bitmap_lo = u32::MAX,
                "group metadata is outside the usable filesystem",
            ),
            (|group| group.flags |= 0x8, "unknown block group flags"),
            (
                |group| group.free_inodes_count_lo = u16::MAX,
                "group counters are inconsistent",
            ),
        ];
        for (change, expected) in cases {
            let image = fixture();
            patch_group(&image.path, true, change);
            assert_eq!(corruption(open(&image.path)).reason, expected);
        }
    }

    #[test]
    fn inode_encoding_allocation_and_accounting_are_validated() {
        let path_cases: [(&str, Mutation<Inode>); 8] = [
            ("/dir/dense", |inode| {
                inode.flags |= inode_flags::INLINE_DATA
            }),
            ("/dir/dense", |inode| inode.flags |= inode_flags::EA_INODE),
            ("/dir/dense", |inode| inode.flags |= inode_flags::ENCRYPTED),
            ("/dir/dense", |inode| inode.extra_isize = 64),
            ("/dir/dense", |inode| inode.flags &= !inode_flags::EXTENTS),
            ("/fast", |inode| inode.size_lo = 70),
            ("/dir/dense", |inode| inode.set_file_size(MAX_FILE_SIZE + 1)),
            ("/dir/dense", |inode| inode.flags |= 0x4000_0000),
        ];
        let expected = |inode: u32| {
            [
                Unsupported::InodeFlags {
                    inode,
                    flags: inode_flags::INLINE_DATA,
                },
                Unsupported::InodeFlags {
                    inode,
                    flags: inode_flags::EA_INODE,
                },
                Unsupported::InodeFlags {
                    inode,
                    flags: inode_flags::ENCRYPTED,
                },
                Unsupported::InodeExtraSize {
                    inode,
                    extra_isize: 64,
                },
                Unsupported::BlockMappedInode(inode),
                Unsupported::BlockMappedInode(inode),
                Unsupported::FileTooLarge {
                    inode,
                    size: MAX_FILE_SIZE + 1,
                },
                Unsupported::InodeFlags {
                    inode,
                    flags: 0x4000_0000,
                },
            ]
        };
        for (index, (path, change)) in path_cases.into_iter().enumerate() {
            let image = fixture();
            let inode = number(&image.path, path);
            patch_inode(&image.path, inode, change);
            let reader = open(&image.path).unwrap();
            let result = reader
                .metadata(inode)
                .and_then(|metadata| match metadata.kind {
                    InodeKind::Symlink => reader.symlink_target(inode).map(|_| ()),
                    _ => reader.file_body(inode).map(|_| ()),
                });
            assert_eq!(unsupported(result), expected(inode)[index], "{path}");
        }

        let corrupt_cases: [(&str, Mutation<Inode>, &str); 9] = [
            (
                "/dir/dense",
                |inode| inode.extra_isize = 30,
                "extra inode size is invalid",
            ),
            (
                "/dir/dense",
                |inode| inode.dtime = 5,
                "allocated inode has a deletion time",
            ),
            (
                "/dir/dense",
                |inode| inode.links_count = 0,
                "allocated inode has no links",
            ),
            (
                "/dir/dense",
                |inode| inode.blocks_lo += 1,
                "block count does not match the mapped blocks",
            ),
            (
                "/dir/dense",
                |inode| inode.mode = 0o644,
                "unknown file type",
            ),
            ("/null", |inode| inode.block[8] = 1, "invalid device number"),
            (
                "/null",
                |inode| inode.size_lo = 1,
                "special inode has a nonzero size",
            ),
            (
                "/fifo",
                |inode| inode.block[0] = 1,
                "fifo or socket has block data",
            ),
            (
                "/dir",
                |inode| inode.size_hi = 1,
                "non-regular inode has a high size word",
            ),
        ];
        for (path, change, expected) in corrupt_cases {
            let image = fixture();
            let inode = number(&image.path, path);
            patch_inode(&image.path, inode, change);
            let reader = open(&image.path).unwrap();
            let result = reader
                .metadata(inode)
                .and_then(|_| reader.file_body(inode).map(|_| ()));
            assert_eq!(corruption(result).reason, expected, "{path}");
        }

        let image = fixture();
        let dense = number(&image.path, "/dir/dense");
        patch_inode(&image.path, dense, |inode| {
            inode.mtime = u32::MAX;
            inode.mtime_extra = (5 << 2) | 1;
        });
        let reader = open(&image.path).unwrap();
        assert_eq!(
            reader.metadata(dense).unwrap().mtime,
            Timestamp {
                seconds: (1i64 << 32) - 1,
                nanos: 5
            }
        );
        drop(reader);
        patch_inode(&image.path, dense, |inode| {
            inode.mtime_extra = 1_000_000_000 << 2
        });
        assert_eq!(
            corruption(open(&image.path).unwrap().metadata(dense)).reason,
            "timestamp nanoseconds are out of range"
        );

        // An inode cleared from its allocation bitmap is never trusted.
        let image = fixture();
        let reader = open(&image.path).unwrap();
        let per_group = reader.superblock().inodes_per_group;
        let bitmap = reader
            .get_group_descriptor((dense - 1) / per_group)
            .unwrap();
        drop(reader);
        let index = (dense - 1) % per_group;
        let offset = bitmap.inode_bitmap_lo as u64 * 4096 + index as u64 / 8;
        let file = writable(&image.path);
        let mut byte = [0u8; 1];
        file.read_exact_at(&mut byte, offset).unwrap();
        file.write_all_at(&[byte[0] & !(1 << (index % 8))], offset)
            .unwrap();
        assert_eq!(
            corruption(open(&image.path).unwrap().stat("/dir/dense")).reason,
            "inode is not allocated"
        );
        assert_eq!(
            corruption(open(&image.path).unwrap().metadata(7)).reason,
            "reserved inode is referenced by the namespace"
        );
    }

    #[test]
    fn directory_corruption_is_typed() {
        let entry_cases: [(&str, u64, &[u8], &str); 4] = [
            (
                ".",
                4,
                &13u16.to_le_bytes(),
                "directory record length is invalid",
            ),
            ("alias", 8, b"dense", "duplicate directory entry name"),
            (
                "dense",
                0,
                &5u32.to_le_bytes(),
                "directory entry names a reserved inode",
            ),
            ("dense", 7, &[9], "directory entry has an invalid file type"),
        ];
        for (name, field, bytes, expected) in entry_cases {
            let image = fixture();
            let dir = number(&image.path, "/dir");
            let offset = entry_offset(&image.path, dir, name.as_bytes());
            writable(&image.path)
                .write_all_at(bytes, offset + field)
                .unwrap();
            let corrupt = corruption(open(&image.path).unwrap().read_dir(dir));
            assert_eq!(
                (corrupt.structure, corrupt.inode, corrupt.reason),
                (Structure::Directory, Some(dir), expected),
                "{name}"
            );
        }

        // Type disagreement between entry and inode is caught by lookups and audit.
        let image = fixture();
        let dir = number(&image.path, "/dir");
        let offset = entry_offset(&image.path, dir, b"dense");
        writable(&image.path)
            .write_all_at(&[2], offset + 7)
            .unwrap();
        let reader = open(&image.path).unwrap();
        assert_eq!(
            corruption(reader.stat("/dir/dense")).reason,
            "entry file type differs from its inode"
        );
        assert_eq!(
            corruption(reader.audit()).reason,
            "entry file type differs from its inode"
        );

        // A '..' naming another inode fails the namespace walk.
        let image = fixture();
        let dir = number(&image.path, "/dir");
        let dense = number(&image.path, "/dir/dense");
        let offset = entry_offset(&image.path, dir, b"..");
        writable(&image.path)
            .write_all_at(&dense.to_le_bytes(), offset)
            .unwrap();
        let corrupt = corruption(open(&image.path).unwrap().audit());
        assert_eq!(
            (corrupt.structure, corrupt.reason),
            (
                Structure::Namespace,
                "'..' does not name the parent directory"
            )
        );

        // A directory larger than its mapped blocks is never read partially.
        let image = fixture();
        let dir = number(&image.path, "/dir");
        patch_inode(&image.path, dir, |inode| inode.size_lo += 4096);
        assert_eq!(
            corruption(open(&image.path).unwrap().read_dir(dir)).reason,
            "directory blocks do not match its size"
        );
    }

    #[test]
    fn audit_detects_link_count_and_orphan_inconsistencies() {
        let cases: [(&str, Mutation<Inode>, &str); 3] = [
            (
                "/dir/dense",
                |inode| inode.links_count = 3,
                "inode has fewer names than links",
            ),
            (
                "/dir/dense",
                |inode| inode.links_count = 1,
                "inode has more names than links",
            ),
            (
                "/dir",
                |inode| inode.links_count = 3,
                "directory link count does not match its subdirectories",
            ),
        ];
        for (path, change, expected) in cases {
            let image = fixture();
            let inode = number(&image.path, path);
            patch_inode(&image.path, inode, change);
            let corrupt = corruption(open(&image.path).unwrap().audit());
            assert_eq!(
                (corrupt.structure, corrupt.reason),
                (Structure::Namespace, expected)
            );
        }
        // Unlinking a name without freeing its inode leaves an orphan.
        let image = fixture();
        let offset = entry_offset(&image.path, ROOT_INODE, b"empty");
        writable(&image.path).write_all_at(&[0; 4], offset).unwrap();
        let reader = open(&image.path).unwrap();
        assert!(!reader.exists("/empty"));
        assert_eq!(
            corruption(reader.audit()).reason,
            "allocated inodes are not exactly the reachable namespace"
        );
    }

    #[test]
    fn xattr_storage_is_validated() {
        let block_cases: [(u64, u32, &str); 3] = [
            (0, 0, "bad xattr block header"),
            (8, 2, "bad xattr block header"),
            (4, 0, "bad xattr block reference count"),
        ];
        for (field, value, expected) in block_cases {
            let image = fixture();
            let attrs = number(&image.path, "/attrs");
            let block = open(&image.path)
                .unwrap()
                .get_inode(attrs)
                .unwrap()
                .xattr_block_lo;
            writable(&image.path)
                .write_all_at(&value.to_le_bytes(), block as u64 * 4096 + field)
                .unwrap();
            let corrupt = corruption(open(&image.path).unwrap().inode_xattrs(attrs));
            assert_eq!(
                (corrupt.structure, corrupt.reason),
                (Structure::Xattr, expected)
            );
        }
        let image = fixture();
        let xdata = number(&image.path, "/xdata");
        assert_eq!(
            open(&image.path).unwrap().inode_xattrs(xdata).unwrap(),
            BTreeMap::from([(b"user.data".to_vec(), b"1".to_vec())])
        );
        let inline_cases: [(Mutation<Inode>, Unsupported); 3] = [
            (
                |inode| inode.inline_xattrs[5] = 7,
                Unsupported::InlineData(0),
            ),
            (
                |inode| inode.inline_xattrs[5] = 9,
                Unsupported::XattrNamespace { inode: 0, index: 9 },
            ),
            (
                |inode| inode.inline_xattrs[8] = 1,
                Unsupported::XattrValueInode(0),
            ),
        ];
        for (change, expected) in inline_cases {
            let image = fixture();
            patch_inode(&image.path, xdata, change);
            let expected = match expected {
                Unsupported::InlineData(_) => Unsupported::InlineData(xdata),
                Unsupported::XattrNamespace { index, .. } => Unsupported::XattrNamespace {
                    inode: xdata,
                    index,
                },
                _ => Unsupported::XattrValueInode(xdata),
            };
            assert_eq!(
                unsupported(open(&image.path).unwrap().inode_xattrs(xdata)),
                expected
            );
        }
        let image = fixture();
        patch_inode(&image.path, xdata, |inode| inode.inline_xattrs[0] ^= 1);
        assert_eq!(
            corruption(open(&image.path).unwrap().inode_xattrs(xdata)).reason,
            "bad in-inode xattr magic"
        );
    }

    #[test]
    fn symlink_length_must_match_its_bytes() {
        for (path, size, expected) in [
            ("/fast", 3, "symlink target length disagrees with its bytes"),
            ("/fast", 0, "symlink target length is invalid"),
            (
                "/slow",
                50,
                "symlink target length disagrees with its bytes",
            ),
            ("/slow", 4096, "symlink target length is invalid"),
        ] {
            let image = fixture();
            let inode = number(&image.path, path);
            patch_inode(&image.path, inode, |raw| raw.size_lo = size);
            let corrupt = corruption(open(&image.path).unwrap().symlink_target(inode));
            assert_eq!(
                (corrupt.structure, corrupt.reason),
                (Structure::Symlink, expected)
            );
        }
    }
}
