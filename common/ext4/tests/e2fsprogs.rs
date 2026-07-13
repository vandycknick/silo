#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use ext4::constants::{LOST_AND_FOUND_INODE, file_mode, make_mode};
use ext4::error::FormatError;
use ext4::{Formatter, Reader, grow_image};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate should live under the workspace root")
        .to_path_buf()
}

fn outside_workspace_tempdir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("e2fsprogs-")
        .tempdir_in(std::env::temp_dir())
        .expect("create temp dir outside workspace");
    let workspace = workspace_root().canonicalize().expect("workspace root");
    let temp_path = dir.path().canonicalize().expect("temp dir path");
    assert!(
        !temp_path.starts_with(&workspace),
        "test artifacts must be outside the workspace: {} is under {}",
        temp_path.display(),
        workspace.display(),
    );
    dir
}

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{program} {} failed with status {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        output.status,
        stdout,
        stderr,
    );

    stdout.into_owned()
}

fn create_test_image(dir: &Path) -> std::path::PathBuf {
    let image = dir.join("rootfs.img");

    let mut formatter = Formatter::new(&image, 4096, 512 * 1024 * 1024).unwrap();
    formatter
        .create(
            "/etc",
            make_mode(file_mode::S_IFDIR, 0o755),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    let content = vec![0x5Au8; 2 * 1024 * 1024];
    let mut reader = Cursor::new(content);
    formatter
        .create(
            "/etc/big-file",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut reader),
            None,
            None,
            None,
        )
        .unwrap();
    formatter.close().unwrap();

    image
}

#[test]
fn e2fsprogs_validates_and_resizes_generated_image() {
    let dir = outside_workspace_tempdir();
    let image = create_test_image(dir.path());
    let image_str = image.to_string_lossy();

    let tune2fs = run("tune2fs", &["-l", &image_str]);
    let features = tune2fs
        .lines()
        .find_map(|line| line.strip_prefix("Filesystem features:"))
        .expect("tune2fs output contains filesystem features");
    assert!(
        features
            .split_whitespace()
            .any(|feature| feature == "resize_inode"),
        "missing resize_inode in: {features}"
    );
    assert!(
        features
            .split_whitespace()
            .any(|feature| feature == "has_journal"),
        "missing has_journal in: {features}"
    );
    assert!(
        features
            .split_whitespace()
            .any(|feature| feature == "sparse_super"),
        "missing sparse_super in: {features}"
    );
    assert!(
        !features
            .split_whitespace()
            .any(|feature| feature == "sparse_super2"),
        "unexpected sparse_super2 in: {features}"
    );

    run("e2fsck", &["-fn", &image_str]);
    let journal = run("debugfs", &["-R", "stat <8>", &image_str]);
    assert!(
        journal.contains("Type: regular"),
        "invalid journal inode:\n{journal}"
    );
    assert!(
        journal.contains("Size: 16777216"),
        "unexpected journal size:\n{journal}"
    );

    std::fs::OpenOptions::new()
        .write(true)
        .open(&image)
        .unwrap()
        .set_len(1024 * 1024 * 1024)
        .unwrap();

    run("resize2fs", &[&image_str]);
    run("e2fsck", &["-fn", &image_str]);
}

#[test]
fn e2fsprogs_validates_pure_rust_offline_grow() {
    let dir = outside_workspace_tempdir();
    let image = create_test_image(dir.path());
    let image_str = image.to_string_lossy();
    let target = 1024 * 1024 * 1024;

    std::fs::OpenOptions::new()
        .write(true)
        .open(&image)
        .unwrap()
        .set_len(target)
        .unwrap();
    let outcome = grow_image(&image, target).expect("grow ext4 image in userspace");

    assert!(outcome.changed());
    assert_eq!(outcome.new_blocks * 4096, target);
    run("e2fsck", &["-fn", &image_str]);
    let header = run("dumpe2fs", &["-h", &image_str]);
    let block_count = header
        .lines()
        .find_map(|line| line.strip_prefix("Block count:"))
        .expect("dumpe2fs reports block count")
        .trim();
    assert_eq!(block_count, "262144");
    let mut reader = Reader::new(&image).expect("open grown image");
    assert_eq!(
        reader.read_file("/etc/big-file", 0, None).unwrap().len(),
        2 * 1024 * 1024
    );
}

#[test]
fn debugfs_reports_full_32_bit_owner_ids() {
    let dir = outside_workspace_tempdir();
    let image = dir.path().join("owners.img");

    let mut formatter = Formatter::new(&image, 4096, 256 * 1024).unwrap();
    formatter
        .create(
            "/owned",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "owned".as_bytes()),
            Some(100_000),
            Some(200_000),
            None,
        )
        .unwrap();
    formatter.close().unwrap();

    let image_str = image.to_string_lossy();
    run("e2fsck", &["-fn", &image_str]);
    let stat = run("debugfs", &["-R", "stat /owned", &image_str]);

    assert!(
        stat.contains("User: 100000"),
        "debugfs did not report the full 32-bit uid:\n{stat}"
    );
    assert!(
        stat.contains("Group: 200000"),
        "debugfs did not report the full 32-bit gid:\n{stat}"
    );
}

#[test]
fn e2fsck_validates_external_xattr_block() {
    let dir = outside_workspace_tempdir();
    let image = dir.path().join("xattrs.img");

    let mut formatter = Formatter::new(&image, 4096, 256 * 1024).unwrap();
    let mut xattrs = HashMap::new();
    xattrs.insert("user.small".to_string(), b"inline".to_vec());
    xattrs.insert("user.large".to_string(), vec![0xAB; 1024]);
    formatter
        .create(
            "/xattrs",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "xattrs".as_bytes()),
            None,
            None,
            Some(&xattrs),
        )
        .unwrap();
    formatter.close().unwrap();

    let image_str = image.to_string_lossy();
    run("e2fsck", &["-fn", &image_str]);
    let stat = run("debugfs", &["-R", "stat /xattrs", &image_str]);
    assert!(
        stat.contains("File ACL: ") && !stat.contains("File ACL: 0"),
        "large xattr should be stored in an external xattr block:\n{stat}"
    );
}

#[test]
fn e2fsck_validates_unlink_reclaims_external_xattr_block() {
    let dir = outside_workspace_tempdir();
    let image = dir.path().join("xattr-delete.img");

    let mut formatter = Formatter::new(&image, 4096, 256 * 1024).unwrap();
    let mut xattrs = HashMap::new();
    xattrs.insert("user.large".to_string(), vec![0xCD; 1024]);
    formatter
        .create(
            "/deleted-xattr",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "delete me".as_bytes()),
            None,
            None,
            Some(&xattrs),
        )
        .unwrap();
    formatter.unlink("/deleted-xattr", false).unwrap();
    formatter
        .create(
            "/kept",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "kept".as_bytes()),
            None,
            None,
            None,
        )
        .unwrap();
    formatter.close().unwrap();

    let image_str = image.to_string_lossy();
    run("e2fsck", &["-fn", &image_str]);
}

#[test]
fn e2fsck_validates_hardlink_external_xattr_delete() {
    let dir = outside_workspace_tempdir();
    let image = dir.path().join("xattr-hardlink-delete.img");

    let mut formatter = Formatter::new(&image, 4096, 256 * 1024).unwrap();
    let mut xattrs = HashMap::new();
    xattrs.insert("user.large".to_string(), vec![0xEF; 1024]);
    formatter
        .create(
            "/original",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "delete via hardlink".as_bytes()),
            None,
            None,
            Some(&xattrs),
        )
        .unwrap();
    formatter.link("/alias", "/original").unwrap();
    formatter.unlink("/original", false).unwrap();
    formatter.unlink("/alias", false).unwrap();
    formatter
        .create(
            "/kept",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "kept".as_bytes()),
            None,
            None,
            None,
        )
        .unwrap();
    formatter.close().unwrap();

    let image_str = image.to_string_lossy();
    run("e2fsck", &["-fn", &image_str]);
}

#[test]
fn initialized_group_records_unused_inode_table_tail() {
    let dir = outside_workspace_tempdir();
    let image = dir.path().join("itable-unused.img");

    let formatter = Formatter::new(&image, 4096, 256 * 1024).unwrap();
    formatter.close().unwrap();

    let mut reader = Reader::new(&image).unwrap();
    let sb = reader.superblock().clone();
    let gd0 = reader.get_group_descriptor(0).unwrap();

    let expected_unused = sb.inodes_per_group - LOST_AND_FOUND_INODE;
    assert_eq!(
        gd0.itable_unused_lo as u32, expected_unused,
        "bg_itable_unused_lo must describe the unused tail of the initialized inode table"
    );
}

#[test]
fn rejects_directory_entry_names_longer_than_ext4_allows() {
    let dir = outside_workspace_tempdir();
    let image = dir.path().join("long-name.img");
    let mut formatter = Formatter::new(&image, 4096, 256 * 1024).unwrap();
    let too_long = "a".repeat(256);
    let path = format!("/{too_long}");

    let result = formatter.create(
        &path,
        make_mode(file_mode::S_IFREG, 0o644),
        None,
        None,
        Some(&mut "nope".as_bytes()),
        None,
        None,
        None,
    );

    assert!(
        matches!(result, Err(FormatError::InvalidName(name)) if name == too_long),
        "256-byte path components must be rejected before writing a corrupt directory entry"
    );
}
