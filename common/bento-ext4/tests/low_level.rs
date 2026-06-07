// Low-level struct validation tests.
//
// Mirrors Apple's TestEXT4Format.swift pattern: format an image, then use the
// Reader's low-level APIs to verify on-disk structures (superblock, group
// descriptors, inodes, bitmaps) match expected values.

use bento_ext4::constants::*;
use bento_ext4::types::{GroupDescriptor, SuperBlock};
use bento_ext4::{Formatter, Reader, extent};
use std::io::{Read, Seek, SeekFrom};
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a formatter backed by a temporary file.
fn new_formatter() -> (Formatter, NamedTempFile) {
    let tmp = NamedTempFile::new().unwrap();
    let fmt = Formatter::new(tmp.path(), 4096, 256 * 1024).unwrap();
    (fmt, tmp)
}

/// Build the "standard" filesystem used by several tests:
///   /test/            directory
///   /test/foo/        directory
///   /test/foo/bar/    directory
///   /test/foo/bar/x   regular file, content "test", mode 0755
///   /x                hard link -> /test/foo/bar/x
///   /y                symlink   -> "test/foo" (relative)
fn build_standard_fs() -> (Reader, NamedTempFile) {
    let (mut fmt, tmp) = new_formatter();

    // Directories are auto-created by create(), but we explicitly create them
    // so the modes are deterministic.
    fmt.create(
        "/test",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    fmt.create(
        "/test/foo",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    fmt.create(
        "/test/foo/bar",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    // Regular file with content "test".
    fmt.create(
        "/test/foo/bar/x",
        make_mode(file_mode::S_IFREG, 0o755),
        None,
        None,
        Some(&mut "test".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    // Hard link: /x -> /test/foo/bar/x
    fmt.link("/x", "/test/foo/bar/x").unwrap();

    // Symlink: /y -> "test/foo"
    fmt.create(
        "/y",
        make_mode(file_mode::S_IFLNK, 0o777),
        Some("test/foo"),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    fmt.close().unwrap();
    let reader = Reader::new(tmp.path()).unwrap();
    (reader, tmp)
}

fn read_block(file: &mut std::fs::File, block: u32, block_size: u64) -> Vec<u8> {
    let mut buf = vec![0u8; block_size as usize];
    file.seek(SeekFrom::Start(block as u64 * block_size))
        .unwrap();
    file.read_exact(&mut buf).unwrap();
    buf
}

fn read_le_u32(buf: &[u8], index: usize) -> u32 {
    let offset = index * 4;
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

// ===========================================================================
// Test: superblock fields
// ===========================================================================

#[test]
fn test_superblock_fields() {
    let (reader, _tmp) = build_standard_fs();
    let sb = reader.superblock();

    // Magic number must be the ext4 signature.
    assert_eq!(sb.magic, SUPERBLOCK_MAGIC, "superblock magic mismatch");

    // log_block_size=2 means 1024 * (1 << 2) = 4096 bytes per block.
    assert_eq!(
        sb.log_block_size, 2,
        "expected log_block_size == 2 for 4K blocks"
    );

    // Standard blocks-per-group for 4K blocks.
    assert_eq!(sb.blocks_per_group, 32768, "blocks_per_group mismatch");

    // On-disk inode size.
    assert_eq!(sb.inode_size, 256, "inode_size mismatch");

    // First non-reserved inode.
    assert_eq!(sb.first_ino, FIRST_INODE, "first_ino must be 11");

    // Revision level 1 (dynamic).
    assert_eq!(sb.rev_level, 1, "expected EXT4_DYNAMIC_REV");

    // Compatible feature flags.
    assert_ne!(
        sb.feature_compat & compat::EXT_ATTR,
        0,
        "EXT_ATTR compat flag not set"
    );
    assert_ne!(
        sb.feature_compat & compat::RESIZE_INODE,
        0,
        "RESIZE_INODE compat flag not set"
    );
    assert_eq!(
        sb.feature_compat & compat::SPARSE_SUPER2,
        0,
        "SPARSE_SUPER2 prevents mounted online resize"
    );

    // Incompatible feature flags.
    assert_ne!(
        sb.feature_incompat & incompat::FILETYPE,
        0,
        "FILETYPE incompat flag not set"
    );
    assert_ne!(
        sb.feature_incompat & incompat::EXTENTS,
        0,
        "EXTENTS incompat flag not set"
    );
    assert_ne!(
        sb.feature_incompat & incompat::FLEX_BG,
        0,
        "FLEX_BG incompat flag not set"
    );

    // Read-only compatible feature flags.
    assert_ne!(
        sb.feature_ro_compat & ro_compat::LARGE_FILE,
        0,
        "LARGE_FILE ro_compat flag not set"
    );
    assert_ne!(
        sb.feature_ro_compat & ro_compat::HUGE_FILE,
        0,
        "HUGE_FILE ro_compat flag not set"
    );
    assert_ne!(
        sb.feature_ro_compat & ro_compat::SPARSE_SUPER,
        0,
        "SPARSE_SUPER ro_compat flag not set"
    );
    assert_ne!(
        sb.feature_ro_compat & ro_compat::EXTRA_ISIZE,
        0,
        "EXTRA_ISIZE ro_compat flag not set"
    );
    assert_ne!(
        sb.feature_ro_compat & ro_compat::GDT_CSUM,
        0,
        "GDT_CSUM ro_compat flag not set"
    );
    assert_ne!(
        sb.reserved_gdt_blocks, 0,
        "online-growable filesystems reserve GDT blocks"
    );

    // Filesystem state: 1 = cleanly unmounted.
    assert_eq!(sb.state, 1, "expected state == 1 (clean)");

    // Error behavior: 1 = continue on error.
    assert_eq!(sb.errors, 1, "expected errors == 1 (continue)");

    // Creator OS: 3 = FreeBSD (matches the formatter's output).
    assert_eq!(sb.creator_os, 3, "expected creator_os == 3 (FreeBSD)");

    // Sanity: free inodes must be less than total inodes.
    assert!(
        sb.free_inodes_count < sb.inodes_count,
        "free_inodes_count ({}) must be < inodes_count ({})",
        sb.free_inodes_count,
        sb.inodes_count,
    );

    // UUID must not be all zeros (the formatter generates a random UUID).
    assert!(
        sb.uuid.iter().any(|&b| b != 0),
        "uuid must not be all zeros"
    );
}

#[test]
fn test_resize_inode_and_backup_sparse_super_layout() {
    let tmp = NamedTempFile::new().unwrap();
    let fmt = Formatter::new(tmp.path(), 4096, 512 * 1024 * 1024).unwrap();
    fmt.close().unwrap();

    let mut reader = Reader::new(tmp.path()).unwrap();
    let sb = reader.superblock().clone();
    let block_size = 1024u64 * (1 << sb.log_block_size);

    let root_entries = reader.children_of(ROOT_INODE).unwrap();
    assert!(
        root_entries.iter().any(|(name, _)| name == "lost+found"),
        "root directory entries must survive final metadata writes"
    );

    let root_inode = reader.get_inode(ROOT_INODE).unwrap();
    let mut image = std::fs::File::open(tmp.path()).unwrap();
    let root_extents = extent::parse_extents(&root_inode, block_size, &mut image).unwrap();
    let (root_block, _) = root_extents
        .first()
        .copied()
        .expect("root directory must have a data block");
    let root_block = read_block(&mut image, root_block, block_size);
    assert!(
        root_block.iter().any(|byte| *byte != 0),
        "root directory data block must not be sparse zeroes"
    );

    let group_count = (sb.blocks_count_lo - 1) / sb.blocks_per_group + 1;
    let groups_per_descriptor_block = block_size as u32 / GroupDescriptor::SIZE as u32;
    let descriptor_blocks = (group_count - 1) / groups_per_descriptor_block + 1;
    let first_reserved_gdt_block = 1 + descriptor_blocks;

    assert!(group_count > 3, "test image must include backup groups");
    assert_ne!(sb.feature_compat & compat::RESIZE_INODE, 0);
    assert_ne!(sb.feature_ro_compat & ro_compat::SPARSE_SUPER, 0);
    assert_eq!(sb.feature_compat & compat::SPARSE_SUPER2, 0);
    assert!(sb.reserved_gdt_blocks > 0);

    let resize_inode = reader.get_inode(7).unwrap();
    assert_eq!(resize_inode.mode & file_mode::TYPE_MASK, file_mode::S_IFREG);
    assert_eq!(resize_inode.mode & 0o777, 0o600);
    assert_eq!(resize_inode.links_count, 1);

    let dind_offset = 13 * 4;
    let dind_block = u32::from_le_bytes(
        resize_inode.block[dind_offset..dind_offset + 4]
            .try_into()
            .unwrap(),
    );
    assert_ne!(
        dind_block, 0,
        "resize inode must own a double-indirect block"
    );

    let mut file = std::fs::File::open(tmp.path()).unwrap();
    let dind = read_block(&mut file, dind_block, block_size);
    assert_eq!(
        read_le_u32(&dind, descriptor_blocks as usize),
        first_reserved_gdt_block,
        "resize inode must reference the first reserved primary GDT block"
    );

    let primary_reserved = read_block(&mut file, first_reserved_gdt_block, block_size);
    assert_eq!(
        read_le_u32(&primary_reserved, 0),
        sb.blocks_per_group + first_reserved_gdt_block,
        "first backup pointer should target group 1"
    );
    assert_eq!(
        read_le_u32(&primary_reserved, 1),
        3 * sb.blocks_per_group + first_reserved_gdt_block,
        "second backup pointer should target group 3"
    );

    let mut backup_sb_buf = [0u8; SuperBlock::SIZE];
    file.seek(SeekFrom::Start(sb.blocks_per_group as u64 * block_size))
        .unwrap();
    file.read_exact(&mut backup_sb_buf).unwrap();
    let backup_sb = SuperBlock::read_from(&backup_sb_buf);
    assert_eq!(backup_sb.magic, SUPERBLOCK_MAGIC);
    assert_eq!(backup_sb.block_group_nr, 1);
    assert_eq!(backup_sb.feature_compat, sb.feature_compat);
    assert_eq!(backup_sb.feature_ro_compat, sb.feature_ro_compat);

    let primary_gd0 = reader.get_group_descriptor(0).unwrap();
    let backup_gdt = read_block(&mut file, sb.blocks_per_group + 1, block_size);
    let backup_gd0 = GroupDescriptor::read_from(&backup_gdt[..GroupDescriptor::SIZE]);
    assert_eq!(backup_gd0.block_bitmap_lo, primary_gd0.block_bitmap_lo);
    assert_eq!(backup_gd0.inode_bitmap_lo, primary_gd0.inode_bitmap_lo);
    assert_eq!(backup_gd0.inode_table_lo, primary_gd0.inode_table_lo);
    assert_eq!(backup_gd0.checksum, primary_gd0.checksum);
}

// ===========================================================================
// Test: group descriptor fields
// ===========================================================================

#[test]
fn test_group_descriptor_fields() {
    let (mut reader, _tmp) = build_standard_fs();
    let sb = reader.superblock().clone();
    let gd = reader.get_group_descriptor(0).unwrap();

    // Bitmap and inode table pointers must be valid (> 0).
    assert!(gd.block_bitmap_lo > 0, "block_bitmap_lo must be > 0");
    assert!(gd.inode_bitmap_lo > 0, "inode_bitmap_lo must be > 0");
    assert!(gd.inode_table_lo > 0, "inode_table_lo must be > 0");

    // Block and inode bitmaps are adjacent in the formatter's layout.
    assert_eq!(
        gd.inode_bitmap_lo,
        gd.block_bitmap_lo + 1,
        "inode bitmap should follow block bitmap"
    );

    // Free block count must not exceed blocks per group.
    assert!(
        (gd.free_blocks_count_lo as u32) <= sb.blocks_per_group,
        "free_blocks_count_lo ({}) exceeds blocks_per_group ({})",
        gd.free_blocks_count_lo,
        sb.blocks_per_group,
    );

    // Free inode count must be less than inodes per group (some are used).
    assert!(
        (gd.free_inodes_count_lo as u32) < sb.inodes_per_group,
        "free_inodes_count_lo ({}) must be < inodes_per_group ({})",
        gd.free_inodes_count_lo,
        sb.inodes_per_group,
    );

    // At least 5 directories: root, lost+found, test, foo, bar.
    assert!(
        gd.used_dirs_count_lo >= 5,
        "used_dirs_count_lo ({}) should be >= 5",
        gd.used_dirs_count_lo,
    );
}

// ===========================================================================
// Test: inode table via get_inode
// ===========================================================================

#[test]
fn test_inode_table_via_get_inode() {
    let (mut reader, _tmp) = build_standard_fs();

    // -- Root inode (2) -------------------------------------------------------
    let root = reader.get_inode(ROOT_INODE).unwrap();
    assert!(root.is_dir(), "root inode must be a directory");
    // Root links: . + .. + lost+found + test + x(hardlink entry) + y(symlink entry)
    // At minimum 4 (., .., and two subdirectories).
    assert!(
        root.links_count >= 4,
        "root links_count ({}) should be >= 4",
        root.links_count,
    );
    assert_eq!(
        root.mode & 0o777,
        0o755,
        "root permission bits should be 0755"
    );

    // -- lost+found inode (11) -----------------------------------------------
    let lf = reader.get_inode(LOST_AND_FOUND_INODE).unwrap();
    assert!(lf.is_dir(), "lost+found must be a directory");
    assert_eq!(
        lf.mode & 0o777,
        0o700,
        "lost+found permission bits should be 0700"
    );

    // -- /test/foo/bar/x (regular file) --------------------------------------
    let (x_ino, x_inode) = reader.stat("/test/foo/bar/x").unwrap();
    assert!(x_inode.is_reg(), "/test/foo/bar/x must be a regular file");
    assert_eq!(
        x_inode.file_size(),
        4,
        "/test/foo/bar/x should be 4 bytes (\"test\")"
    );
    // The file has a hard link at /x, so links_count == 2.
    assert_eq!(
        x_inode.links_count, 2,
        "/test/foo/bar/x links_count should be 2 (original + hardlink)"
    );

    // The hard link at /x must resolve to the same inode number.
    let (x_link_ino, _) = reader.stat("/x").unwrap();
    assert_eq!(
        x_ino, x_link_ino,
        "/x and /test/foo/bar/x must share the same inode"
    );

    // -- /y (symlink) --------------------------------------------------------
    let (_, y_inode) = reader.stat_no_follow("/y").unwrap();
    assert!(y_inode.is_link(), "/y must be a symbolic link");
    // "test/foo" is 8 bytes.
    assert_eq!(
        y_inode.file_size(),
        8,
        "/y symlink target size should be 8 (\"test/foo\")"
    );
    assert_eq!(y_inode.links_count, 1, "symlink links_count should be 1");
    // Fast symlinks (< 60 bytes) store the target inline in the block field,
    // so no EXTENTS flag and no allocated blocks.
    assert_eq!(
        y_inode.flags, 0,
        "fast symlink should have no inode flags (no EXTENTS)"
    );
    assert_eq!(
        y_inode.blocks_lo, 0,
        "fast symlink should use no data blocks"
    );
}

// ===========================================================================
// Test: block and inode bitmaps
// ===========================================================================

#[test]
fn test_block_and_inode_bitmaps() {
    let (mut reader, tmp) = build_standard_fs();
    let sb = reader.superblock().clone();
    let gd = reader.get_group_descriptor(0).unwrap();
    let block_size = 1024u64 * (1 << sb.log_block_size);

    // Open the raw image for bitmap reading.
    let mut file = std::fs::File::open(tmp.path()).unwrap();

    // -- Block bitmap ---------------------------------------------------------
    let block_bitmap_offset = gd.block_bitmap_lo as u64 * block_size;
    let block_bitmap_bytes = (sb.blocks_per_group / 8) as usize;
    let mut block_bitmap = vec![0u8; block_bitmap_bytes];
    file.seek(SeekFrom::Start(block_bitmap_offset)).unwrap();
    file.read_exact(&mut block_bitmap).unwrap();

    // Bit 0 must be set (block 0 is always used -- superblock area).
    assert_ne!(block_bitmap[0] & 0x01, 0, "block bitmap bit 0 must be set");

    // The bitmap should not be all zeros (some blocks are used) and not all
    // ones (not every block is allocated in a small image).
    assert!(
        block_bitmap.iter().any(|&b| b != 0),
        "block bitmap must not be all zeros"
    );
    assert!(
        block_bitmap.iter().any(|&b| b != 0xFF),
        "block bitmap must not be all ones"
    );

    // -- Inode bitmap ---------------------------------------------------------
    let inode_bitmap_offset = gd.inode_bitmap_lo as u64 * block_size;
    let inode_bitmap_bytes = (sb.inodes_per_group / 8) as usize;
    let mut inode_bitmap = vec![0u8; inode_bitmap_bytes];
    file.seek(SeekFrom::Start(inode_bitmap_offset)).unwrap();
    file.read_exact(&mut inode_bitmap).unwrap();

    // Reserved inodes 1-10 must all be allocated (bits 0-9 set).
    // Bits 0-7 are in byte 0, bits 8-9 are in byte 1.
    assert_eq!(
        inode_bitmap[0], 0xFF,
        "inode bitmap byte 0 must be 0xFF (inodes 1-8 reserved)"
    );
    assert_ne!(
        inode_bitmap[1] & 0x03,
        0,
        "inode bitmap bits 8-9 must be set (inodes 9-10 reserved)"
    );

    // Bit 10 must be set: inode 11 = lost+found.
    assert_ne!(
        inode_bitmap[1] & 0x04,
        0,
        "inode bitmap bit 10 must be set (inode 11 = lost+found)"
    );
}

// ===========================================================================
// Test: inode dtime after unlink
// ===========================================================================

#[test]
fn test_inode_dtime_after_unlink() {
    let (mut fmt, tmp) = new_formatter();

    // Create a file and note its inode number.
    fmt.create(
        "/victim.txt",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "delete me".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    // Stat the victim through the tree to learn its inode number.  We cannot
    // use Reader yet (the image is not finalized), so we rely on the fact
    // that create() allocates inodes sequentially.  lost+found is inode 11
    // (the first non-reserved), so the next file gets inode 12.
    let victim_ino: u32 = 12;

    // Unlink the victim.
    fmt.unlink("/victim.txt", false).unwrap();

    // Create another file so the victim's inode slot is not reused.
    fmt.create(
        "/keeper.txt",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "keep me".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    fmt.close().unwrap();

    let mut reader = Reader::new(tmp.path()).unwrap();
    let victim = reader.get_inode(victim_ino).unwrap();

    // After unlink the formatter zeros the inode but sets dtime.
    assert_eq!(
        victim.links_count, 0,
        "unlinked inode links_count must be 0"
    );
    assert_ne!(
        victim.dtime, 0,
        "unlinked inode dtime must be non-zero (deletion timestamp)"
    );
}

// ===========================================================================
// Test: hard link links_count
// ===========================================================================

#[test]
fn test_hardlink_links_count() {
    let (mut fmt, tmp) = new_formatter();

    fmt.create(
        "/original",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "data".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    fmt.link("/link1", "/original").unwrap();
    fmt.link("/link2", "/original").unwrap();

    fmt.close().unwrap();

    let mut reader = Reader::new(tmp.path()).unwrap();
    let (_, inode) = reader.stat("/original").unwrap();

    // Original file + 2 hard links = 3.
    assert_eq!(
        inode.links_count, 3,
        "original + 2 hard links should give links_count == 3"
    );
}

// ===========================================================================
// Test: directory links_count
// ===========================================================================

#[test]
fn test_directory_links_count() {
    let (mut fmt, tmp) = new_formatter();

    fmt.create(
        "/parent",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    fmt.create(
        "/parent/child1",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    fmt.create(
        "/parent/child2",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    fmt.close().unwrap();

    let mut reader = Reader::new(tmp.path()).unwrap();
    let (_, parent_inode) = reader.stat("/parent").unwrap();

    // A directory's links_count = 2 (. and ..) + number of child directories.
    // /parent has child1 and child2 -> links_count == 4.
    assert_eq!(
        parent_inode.links_count, 4,
        "/parent links_count should be 4 (. + .. + child1 + child2)"
    );
}

// ===========================================================================
// Test: create overwrite semantics
// ===========================================================================

#[test]
fn test_create_overwrite_semantics() {
    let (mut fmt, _tmp) = new_formatter();

    // Create /file as a regular file -- should succeed.
    fmt.create(
        "/file",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "v1".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    // Create /file again as a regular file -- should succeed (overwrite).
    fmt.create(
        "/file",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "v2".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    // Create /file as a directory -- should fail (it is a file, not a dir).
    let result = fmt.create(
        "/file",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(
        result.is_err(),
        "creating /file as directory over existing file should fail"
    );

    // Create /dir as a directory -- should succeed.
    fmt.create(
        "/dir",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    // Create /dir again as a directory -- should succeed (mkdir -p semantics).
    fmt.create(
        "/dir",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    // Create /dir as a regular file -- should fail (it is a dir).
    let result = fmt.create(
        "/dir",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "nope".as_bytes()),
        None,
        None,
        None,
    );
    assert!(
        result.is_err(),
        "creating /dir as file over existing directory should fail"
    );

    // Create /file2 as a regular file, then try to create /file2/sub as a
    // directory -- should fail because the parent is a file.
    fmt.create(
        "/file2",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "data".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    let result = fmt.create(
        "/file2/sub",
        make_mode(file_mode::S_IFDIR, 0o755),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(
        result.is_err(),
        "creating /file2/sub should fail because /file2 is a regular file"
    );
}
