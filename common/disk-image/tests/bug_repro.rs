// Minimal reproduction tests for 4 bugs reported by Codex.
// Each test is designed to trigger the specific bug if it exists.

use disk_image::ext4::constants::*;
use disk_image::ext4::{Formatter, Reader};
use tempfile::NamedTempFile;

fn new_formatter() -> (Formatter, NamedTempFile) {
    let tmp = NamedTempFile::new().unwrap();
    let fmt = Formatter::new(tmp.path(), 4096, 256 * 1024).unwrap();
    (fmt, tmp)
}

// ═══════════════════════════════════════════════════════════════════════
// Bug 1: removing the original path destroys inode still referenced by hardlink
//
// create("/original") -> link("/alias", "/original") -> remove("/original")
// Expected: /alias should still be readable with the original content.
// Bug claim: inode gets zeroed, /alias disappears.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bug1_remove_original_preserves_hardlink() {
    let (mut fmt, tmp) = new_formatter();

    fmt.create(
        "/original",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "hardlink content".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    fmt.link("/alias", "/original").unwrap();
    fmt.remove("/original").unwrap();
    fmt.close().unwrap();

    let mut reader = Reader::new(tmp.path()).unwrap();

    // /alias should still exist and be readable.
    assert!(
        reader.exists("/alias"),
        "/alias should exist after removing /original"
    );
    let data = reader.read_file("/alias", 0, None).unwrap();
    assert_eq!(
        &data, b"hardlink content",
        "/alias content should be intact"
    );

    // /original should be gone.
    assert!(!reader.exists("/original"), "/original should be gone");
}

// ═══════════════════════════════════════════════════════════════════════
// Bug 1b: deleting the last hardlink must reclaim the inode
//
// create("/original") -> link("/alias") -> remove("/original") -> remove("/alias")
// After both are gone, the inode should have links_count=0 and dtime!=0.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bug1b_last_hardlink_reclaims_inode() {
    let (mut fmt, tmp) = new_formatter();

    fmt.create(
        "/original",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "reclaim me".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    // Note the inode number before linking.
    fmt.link("/alias", "/original").unwrap();
    fmt.remove("/original").unwrap();
    fmt.remove("/alias").unwrap();

    // Create a dummy file so the image isn't trivially empty.
    fmt.create(
        "/dummy",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "keep".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    fmt.close().unwrap();

    let mut reader = Reader::new(tmp.path()).unwrap();

    assert!(!reader.exists("/original"));
    assert!(!reader.exists("/alias"));

    // The inode for the deleted file should be fully reclaimed:
    // links_count == 0 and dtime != 0.
    // Inode 11 = lost+found, 12 = original, 13 = dummy.
    let inode = reader.get_inode(12).unwrap();
    assert_eq!(
        inode.links_count, 0,
        "inode should have links_count=0 after full reclaim"
    );
    assert_ne!(inode.dtime, 0, "inode should have dtime set after reclaim");

    // Verify data blocks were also reclaimed by comparing free_blocks with
    // a baseline image that only creates /dummy (no create+delete cycle).
    let free_with_delete = {
        let sb = reader.superblock();
        sb.free_blocks_count_lo as u64 | ((sb.free_blocks_count_hi as u64) << 32)
    };

    let baseline_tmp = NamedTempFile::new().unwrap();
    let mut baseline = Formatter::new(baseline_tmp.path(), 4096, 256 * 1024).unwrap();
    baseline
        .create(
            "/dummy",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "keep".as_bytes()),
            None,
            None,
            None,
        )
        .unwrap();
    baseline.close().unwrap();
    let baseline_reader = Reader::new(baseline_tmp.path()).unwrap();
    let free_baseline = {
        let sb = baseline_reader.superblock();
        sb.free_blocks_count_lo as u64 | ((sb.free_blocks_count_hi as u64) << 32)
    };

    assert_eq!(
        free_with_delete, free_baseline,
        "free block count should match baseline (no block leak); got {free_with_delete} vs baseline {free_baseline}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Bug 1c: large-file hardlink reclaim with multiple block ranges
//
// A file large enough to span multiple extents stores block ranges in
// both `blocks` and `additional_blocks` on its tree node.  When the
// original path is removed first, all those ranges must be stashed in
// `deferred_blocks` and reclaimed when the last hard link is removed.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bug1c_large_file_hardlink_reclaim() {
    // 20 KiB file — spans 5 blocks with 4096-byte block size.
    let pattern: Vec<u8> = (0..20480u32).map(|i| (i % 251) as u8).collect();

    let (mut fmt, tmp) = new_formatter();

    fmt.create(
        "/bigfile",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut pattern.as_slice()),
        None,
        None,
        None,
    )
    .unwrap();

    fmt.link("/biglink", "/bigfile").unwrap();
    fmt.remove("/bigfile").unwrap();
    fmt.remove("/biglink").unwrap();

    fmt.create(
        "/dummy",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "x".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();

    fmt.close().unwrap();

    let mut reader = Reader::new(tmp.path()).unwrap();

    // Inode should be fully reclaimed.
    // lost+found=11, bigfile=12, dummy=13
    let inode = reader.get_inode(12).unwrap();
    assert_eq!(inode.links_count, 0);
    assert_ne!(inode.dtime, 0);

    // Free blocks should match a baseline with only /dummy.
    let free_with_delete = {
        let sb = reader.superblock();
        sb.free_blocks_count_lo as u64 | ((sb.free_blocks_count_hi as u64) << 32)
    };

    let baseline_tmp = NamedTempFile::new().unwrap();
    let mut baseline = Formatter::new(baseline_tmp.path(), 4096, 256 * 1024).unwrap();
    baseline
        .create(
            "/dummy",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "x".as_bytes()),
            None,
            None,
            None,
        )
        .unwrap();
    baseline.close().unwrap();
    let baseline_reader = Reader::new(baseline_tmp.path()).unwrap();
    let free_baseline = {
        let sb = baseline_reader.superblock();
        sb.free_blocks_count_lo as u64 | ((sb.free_blocks_count_hi as u64) << 32)
    };

    assert_eq!(
        free_with_delete, free_baseline,
        "all blocks from 20KiB file should be reclaimed; got {free_with_delete} vs baseline {free_baseline}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Bug 3: non-4096 block size produces broken image
//
// The formatter previously accepted arbitrary block sizes but hardcoded
// log_block_size=2 (4096) in the superblock, producing an internally
// contradictory image.  The fix restricts block_size to 4096 only.
//
// This test verifies:
// (a) non-4096 block sizes are rejected at construction time.
// (b) 4096 writes the correct log_block_size.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bug3_non_4096_block_size_rejected() {
    let tmp = NamedTempFile::new().unwrap();
    let result = Formatter::new(tmp.path(), 1024, 256 * 1024);
    assert!(
        result.is_err(),
        "non-4096 block size should return an error, not panic"
    );
}

#[test]
fn bug3_4096_block_size_writes_correct_log() {
    let (mut fmt, tmp) = new_formatter(); // uses 4096
    fmt.create(
        "/hello.txt",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "hello".as_bytes()),
        None,
        None,
        None,
    )
    .unwrap();
    fmt.close().unwrap();

    let reader = Reader::new(tmp.path()).unwrap();
    assert_eq!(reader.superblock().log_block_size, 2);
}

// ═══════════════════════════════════════════════════════════════════════
// Bug 4: recursive mkdir-p through existing symlink silently converts it
//
// If /foo is a symlink and we create("/foo/bar/file", S_IFREG, ...),
// the mkdir-p logic tries to ensure /foo exists as a directory. The
// "already exists + is_link" path at line 217 accepts it and overwrites
// the mode to S_IFDIR, destroying the symlink.
//
// Expected: error or proper handling.
// Bug claim: symlink silently turned into directory.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bug4_mkdir_p_through_symlink() {
    let (mut fmt, tmp) = new_formatter();

    // Create a real directory and a symlink pointing to it.
    fmt.create(
        "/real_dir",
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
        "/sym",
        make_mode(file_mode::S_IFLNK, 0o777),
        Some("/real_dir"),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    // Now create a file under /sym/... which triggers mkdir-p on /sym.
    // Since /sym is a symlink (not a directory), the formatter cannot create
    // a child under it and must return an error.  It must NOT silently
    // convert /sym from a symlink into a directory.
    let result = fmt.create(
        "/sym/child.txt",
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "data".as_bytes()),
        None,
        None,
        None,
    );
    assert!(result.is_err(), "creating under a symlink path should fail");

    fmt.close().unwrap();

    let mut reader = Reader::new(tmp.path()).unwrap();

    // /sym should still be a symlink, not a directory.
    let (_, sym_inode) = reader.stat_no_follow("/sym").unwrap();
    assert!(
        is_link(sym_inode.mode),
        "/sym should remain a symlink after mkdir-p, but mode = {:#06x} (is_dir={})",
        sym_inode.mode,
        is_dir(sym_inode.mode),
    );
}
