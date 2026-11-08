#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use disk_image::ext4::constants::{LOST_AND_FOUND_INODE, file_mode, make_mode};
use disk_image::ext4::error::FormatError;
use disk_image::ext4::{Formatter, Reader, grow_image};

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
            Some(disk_image::ext4::FileData::Dense(&mut reader)),
            None,
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
    let reader = Reader::new(&image).expect("open grown image");
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
            Some(disk_image::ext4::FileData::Dense(&mut "owned".as_bytes())),
            Some(100_000),
            Some(200_000),
            None,
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
            Some(disk_image::ext4::FileData::Dense(&mut "xattrs".as_bytes())),
            None,
            None,
            Some(
                &xattrs
                    .iter()
                    .map(|(name, value)| (name.as_bytes(), value.as_slice()))
                    .collect::<Vec<_>>(),
            ),
            None,
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
fn e2fsck_validates_removal_reclaims_external_xattr_block() {
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
            Some(disk_image::ext4::FileData::Dense(
                &mut "delete me".as_bytes(),
            )),
            None,
            None,
            Some(
                &xattrs
                    .iter()
                    .map(|(name, value)| (name.as_bytes(), value.as_slice()))
                    .collect::<Vec<_>>(),
            ),
            None,
        )
        .unwrap();
    formatter.remove("/deleted-xattr").unwrap();
    formatter
        .create(
            "/kept",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(disk_image::ext4::FileData::Dense(&mut "kept".as_bytes())),
            None,
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
            Some(disk_image::ext4::FileData::Dense(
                &mut "delete via hardlink".as_bytes(),
            )),
            None,
            None,
            Some(
                &xattrs
                    .iter()
                    .map(|(name, value)| (name.as_bytes(), value.as_slice()))
                    .collect::<Vec<_>>(),
            ),
            None,
        )
        .unwrap();
    formatter.link("/alias", "/original").unwrap();
    formatter.remove("/original").unwrap();
    formatter.remove("/alias").unwrap();
    formatter
        .create(
            "/kept",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(disk_image::ext4::FileData::Dense(&mut "kept".as_bytes())),
            None,
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

    let reader = Reader::new(&image).unwrap();
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
        Some(disk_image::ext4::FileData::Dense(&mut "nope".as_bytes())),
        None,
        None,
        None,
        None,
    );

    assert!(
        matches!(result, Err(FormatError::InvalidName(name)) if name == too_long),
        "256-byte path components must be rejected before writing a corrupt directory entry"
    );
}

#[test]
fn upper_e2fsprogs_independently_validates_fixed_profile_and_partial_groups() {
    use disk_image::ext4::upper::format_upper;
    use rootfs_spec::upper_geometry::UpperCapacity;

    let dir = outside_workspace_tempdir();
    let group = 128u64 << 20;
    let block = 4096u64;
    // Explicit kernel-inequality oracle, independent of UpperGeometry and
    // formatter-returned span: equality is excluded, the next block admitted.
    for (bytes, span, groups, reserved) in [
        (64 << 20, 64 << 20, 1, 63),
        (group, group, 1, 63),
        (group + block, group, 1, 63),
        (group + 579 * block, group, 1, 63),
        (group + 580 * block, group, 1, 63),
        (group + 581 * block, group + 581 * block, 2, 63),
        (2 * group + 514 * block, 2 * group, 2, 63),
        (2 * group + 515 * block, 2 * group, 2, 63),
        (2 * group + 516 * block, 2 * group + 516 * block, 3, 63),
        (3 * group + 580 * block, 3 * group, 3, 63),
        (3 * group + 581 * block, 3 * group + 581 * block, 4, 63),
        (4 << 30, 4 << 30, 32, 63),
        (16 << 30, 16 << 30, 128, 63),
        (128 * group + block, 128 * group, 128, 63),
        (128 * group + 515 * block, 128 * group, 128, 63),
        (
            128 * group + 516 * block,
            128 * group + 516 * block,
            129,
            62,
        ),
        (1 << 40, 1 << 40, 8192, 0),
    ] {
        let image = dir.path().join(format!("upper-{bytes}.raw"));
        let result = format_upper(&image, UpperCapacity::new(bytes).unwrap()).unwrap();
        let path = image.to_str().unwrap();
        // Recalculate with libext2fs, not the writer's checksum routine.
        // e2fsck exit status alone cannot prove checksums were already valid,
        // and repair mode may legitimately materialize lazy bitmaps.
        let descriptors_before = upper_gdt_snapshot(&image, groups);
        let primary = &descriptors_before.first().unwrap().1;
        for (offset, backup) in descriptors_before.iter().skip(1) {
            upper_assert_descriptor_bytes_equal(primary, backup, *offset);
        }
        upper_calculate_gdt_checksums(&image, groups);
        upper_assert_gdt_unchanged(&descriptors_before, &upper_gdt_snapshot(&image, groups));
        run("e2fsck", &["-fn", path]);
        let header = run("dumpe2fs", &["-h", path]);
        let field = |name: &str| {
            header
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap_or_else(|| panic!("missing {name} in {header}"))
                .trim()
        };
        assert_eq!(result.filesystem_bytes, span);
        assert_eq!(result.unusable_tail_bytes, bytes - span);
        assert_eq!(field("Block count:").parse::<u64>().unwrap() * 4096, span);
        assert_eq!(field("Inode count:").parse::<u64>().unwrap(), groups * 8192);
        let actual_reserved = header
            .lines()
            .find_map(|line| line.strip_prefix("Reserved GDT blocks:"))
            .map(|value| value.trim().parse::<u64>().unwrap())
            .unwrap_or(0);
        assert_eq!(actual_reserved, reserved);
        assert_eq!(
            field("Free blocks:").parse::<u64>().unwrap() * 4096,
            result.initial_free_bytes
        );
        assert_eq!(
            field("Free inodes:").parse::<u64>().unwrap(),
            result.initial_free_inodes
        );
        assert_eq!(field("Filesystem UUID:"), result.uuid.to_string());
        assert_eq!(field("Inodes per group:"), "8192");
        assert_eq!(field("Inode size:"), "256");
        assert_eq!(field("Flex block group size:"), "8192");
        assert_eq!(field("Default directory hash:"), "half_md4");
        let mut features: Vec<_> = field("Filesystem features:").split_whitespace().collect();
        features.sort_unstable();
        let mut expected = vec![
            "has_journal",
            "ext_attr",
            "resize_inode",
            "dir_index",
            "filetype",
            "extent",
            "flex_bg",
            "large_file",
            "huge_file",
            "sparse_super",
            "extra_isize",
            "uninit_bg",
            "dir_nlink",
        ];
        expected.sort_unstable();
        assert_eq!(features, expected);
        let resize_inode = run("debugfs", &["-R", "stat <7>", path]);
        assert!(resize_inode.contains("(DIND)"), "{resize_inode}");
        if reserved == 0 {
            let sectors: u64 = resize_inode
                .split_once("Blockcount:")
                .unwrap()
                .1
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(sectors, 8, "{resize_inode}");
        }
        for (directory, mode) in [
            ("/upper", "0755"),
            ("/work", "0700"),
            ("/lost+found", "0700"),
        ] {
            let stat = run("debugfs", &["-R", &format!("stat {directory}"), path]);
            assert!(stat.contains("Type: directory"), "{stat}");
            assert!(stat.contains(mode), "{stat}");
        }
        assert_eq!(std::fs::metadata(image).unwrap().len(), bytes);
    }
}

#[test]
fn upper_e2fsprogs_repairs_corrupt_gdt_only_on_disposable_copy() {
    use std::io::{Read, Seek, SeekFrom, Write};

    use disk_image::ext4::upper::format_upper;
    use rootfs_spec::upper_geometry::UpperCapacity;

    let dir = outside_workspace_tempdir();
    let image = dir.path().join("corrupt-upper.raw");
    format_upper(&image, UpperCapacity::new(64 << 20).unwrap()).unwrap();
    let healthy_descriptors = upper_gdt_snapshot(&image, 1);
    upper_calculate_gdt_checksums(&image, 1);
    upper_assert_gdt_unchanged(&healthy_descriptors, &upper_gdt_snapshot(&image, 1));
    run("e2fsck", &["-fn", image.to_str().unwrap()]);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&image)
        .unwrap();
    // Flip the primary descriptor checksum on a preserved source. Prove the
    // checker actually repairs a disposable copy, not merely prints a warning.
    let checksum_offset = 4096 + 30;
    file.seek(SeekFrom::Start(checksum_offset)).unwrap();
    let mut checksum = [0u8; 2];
    file.read_exact(&mut checksum).unwrap();
    let healthy_checksum = checksum;
    checksum[0] ^= 1;
    file.seek(SeekFrom::Start(checksum_offset)).unwrap();
    file.write_all(&checksum).unwrap();
    file.sync_all().unwrap();
    let corrupt_descriptors = upper_gdt_snapshot(&image, 1);
    let repair_copy = dir.path().join("repair-copy.raw");
    std::fs::copy(&image, &repair_copy).unwrap();
    upper_calculate_gdt_checksums(&repair_copy, 1);
    let mut repaired = std::fs::File::open(&repair_copy).unwrap();
    repaired.seek(SeekFrom::Start(checksum_offset)).unwrap();
    let mut repaired_checksum = [0u8; 2];
    repaired.read_exact(&mut repaired_checksum).unwrap();
    assert_eq!(
        repaired_checksum, healthy_checksum,
        "checker must actually restore the descriptor checksum"
    );
    upper_assert_gdt_unchanged(&healthy_descriptors, &upper_gdt_snapshot(&repair_copy, 1));
    // Actual correction defeats an unsupported/no-op batch command. A repeat
    // calculation and read-only consistency check must leave descriptors stable.
    let repaired_descriptors = upper_gdt_snapshot(&repair_copy, 1);
    upper_calculate_gdt_checksums(&repair_copy, 1);
    run("e2fsck", &["-fn", repair_copy.to_str().unwrap()]);
    upper_assert_gdt_unchanged(&repaired_descriptors, &upper_gdt_snapshot(&repair_copy, 1));
    file.seek(SeekFrom::Start(checksum_offset)).unwrap();
    let mut observed = [0u8; 2];
    file.read_exact(&mut observed).unwrap();
    assert_eq!(
        observed, checksum,
        "repairing the disposable copy must not repair the preserved source"
    );
    upper_assert_gdt_unchanged(&corrupt_descriptors, &upper_gdt_snapshot(&image, 1));
}

/// Independent classic sparse-super locations below the 8192-group maximum.
/// Neither these positions nor the expected group counts come from the writer
/// or shared geometry module. Snapshot active descriptor blocks including pad.
fn upper_gdt_snapshot(image: &Path, groups: u64) -> Vec<(u64, Vec<u8>)> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(image).unwrap();
    let mut snapshots = Vec::new();
    let table_bytes = groups.div_ceil(128) * 4096;
    for group in [
        0, 1, 3, 5, 7, 9, 25, 27, 49, 81, 125, 243, 343, 625, 729, 2187, 2401, 3125, 6561,
    ] {
        if group >= groups {
            break;
        }
        let offset = group * 128 * 1024 * 1024 + 4096;
        let mut bytes = vec![0; table_bytes as usize];
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(&mut bytes).unwrap();
        snapshots.push((offset, bytes));
    }
    snapshots
}

/// debugfs' checksum parser calls libext2fs ext2fs_group_desc_csum, independently
/// of our writer. Batch all groups so the maximum does not spawn 8192 processes.
/// The corrupted-copy control requires a real byte correction, not just status.
fn upper_calculate_gdt_checksums(image: &Path, groups: u64) {
    use std::fmt::Write;

    let commands_path = image.with_extension("gdt.commands");
    let mut commands = String::new();
    for group in 0..groups {
        writeln!(&mut commands, "set_bg {group} checksum calc").unwrap();
    }
    std::fs::write(&commands_path, commands).unwrap();
    run(
        "debugfs",
        &[
            "-w",
            "-f",
            commands_path.to_str().unwrap(),
            image.to_str().unwrap(),
        ],
    );
}

fn upper_assert_gdt_unchanged(expected: &[(u64, Vec<u8>)], observed: &[(u64, Vec<u8>)]) {
    assert_eq!(
        observed.len(),
        expected.len(),
        "descriptor-table count changed"
    );
    for ((expected_offset, expected_bytes), (observed_offset, observed_bytes)) in
        expected.iter().zip(observed)
    {
        assert_eq!(
            observed_offset, expected_offset,
            "descriptor-table location changed"
        );
        upper_assert_descriptor_bytes_equal(expected_bytes, observed_bytes, *expected_offset);
    }
}

fn upper_assert_descriptor_bytes_equal(expected: &[u8], observed: &[u8], table_offset: u64) {
    assert_eq!(
        observed.len(),
        expected.len(),
        "descriptor-table length at {table_offset}"
    );
    if let Some(index) = expected
        .iter()
        .zip(observed)
        .position(|(before, after)| before != after)
    {
        let field = match index % 32 {
            0..=3 => "block_bitmap",
            4..=7 => "inode_bitmap",
            8..=11 => "inode_table",
            12..=13 => "free_blocks_count",
            14..=15 => "free_inodes_count",
            16..=17 => "used_dirs_count",
            18..=19 => "flags",
            20..=23 => "exclude_bitmap",
            24..=25 => "block_bitmap_checksum",
            26..=27 => "inode_bitmap_checksum",
            28..=29 => "itable_unused",
            _ => "checksum",
        };
        assert_eq!(
            observed[index],
            expected[index],
            "GDT at byte {table_offset}, first changed group {}, field {field}, descriptor byte {}",
            index / 32,
            index % 32,
        );
    }
}

#[test]
fn metadata_acl_capability_special_inodes_and_sparse_trees_have_independent_oracles() {
    use disk_image::ext4::{DeviceId, FileData, FileRange, FileTimestamps, SparseData};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::ffi::OsStrExt;

    let dir = outside_workspace_tempdir();
    let image = dir.path().join("metadata.raw");
    let mut formatter = Formatter::new(&image, 4096, 128 << 20).unwrap();
    let timestamp = FileTimestamps::from_mtime(2_147_483_648, 123_456_789).unwrap();
    let mut acl_linux = 2u32.to_le_bytes().to_vec();
    let mut acl_disk = 1u32.to_le_bytes().to_vec();
    let mut acl_debugfs_v2 = 2u32.to_le_bytes().to_vec();
    for (tag, permission, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 4, 1001),
        (4, 4, u32::MAX),
        (16, 4, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        let mut entry = Vec::new();
        entry.extend_from_slice(&tag.to_le_bytes());
        entry.extend_from_slice(&permission.to_le_bytes());
        acl_disk.extend_from_slice(&entry);
        entry.extend_from_slice(&id.to_le_bytes());
        acl_linux.extend_from_slice(&entry);
        // libext2fs' API-v2 converter writes zero in undefined object IDs;
        // compare that independently documented representation explicitly.
        acl_debugfs_v2.extend_from_slice(&entry[..4]);
        let debugfs_id = if matches!(tag, 2 | 8) { id } else { 0u32 };
        acl_debugfs_v2.extend_from_slice(&debugfs_id.to_le_bytes());
        if tag == 2 {
            acl_disk.extend_from_slice(&id.to_le_bytes());
        }
    }
    let large = vec![0x91; 2750];
    let capability = [1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let attrs = [
        (b"user.probe".as_slice(), large.as_slice()),
        (b"security.capability", capability.as_slice()),
        (b"system.posix_acl_access", acl_linux.as_slice()),
        (b"user.raw\xff", b"opaque\0\xfe"),
    ];
    formatter
        .create(
            "/",
            file_mode::S_IFDIR | 0o750,
            None,
            Some(timestamp),
            None,
            Some(100_000),
            Some(200_000),
            Some(&[(b"user.root", b"root\0bytes")]),
            None,
        )
        .unwrap();
    formatter
        .create(
            "/metadata",
            file_mode::S_IFREG | 0o640,
            None,
            Some(timestamp),
            Some(FileData::Dense(&mut b"metadata".as_slice())),
            Some(100_001),
            Some(200_001),
            Some(&attrs),
            None,
        )
        .unwrap();
    formatter.link("/alias", "/metadata").unwrap();
    formatter
        .create(
            "/directory/child",
            file_mode::S_IFREG | 0o640,
            None,
            None,
            Some(FileData::Dense(&mut b"child".as_slice())),
            Some(0),
            Some(0),
            None,
            None,
        )
        .unwrap();
    formatter
        .create(
            "/directory",
            file_mode::S_IFDIR | 0o751,
            None,
            Some(timestamp),
            None,
            Some(100_003),
            Some(200_003),
            Some(&[(b"system.posix_acl_default", &acl_linux)]),
            None,
        )
        .unwrap();
    for (path, mode, device) in [
        ("/fifo", file_mode::S_IFIFO, None),
        ("/socket", file_mode::S_IFSOCK, None),
        (
            "/char",
            file_mode::S_IFCHR,
            Some(DeviceId::new(4095, 0xfffff).unwrap()),
        ),
        (
            "/block",
            file_mode::S_IFBLK,
            Some(DeviceId::new(4094, 0x80001).unwrap()),
        ),
        (
            "/small-char",
            file_mode::S_IFCHR,
            Some(DeviceId::new(1, 3).unwrap()),
        ),
    ] {
        formatter
            .create(
                path,
                mode | 0o600,
                None,
                Some(timestamp),
                None,
                Some(100_002),
                Some(200_002),
                None,
                device,
            )
            .unwrap();
    }
    let records = 2000usize;
    let mut stored = Vec::with_capacity(records * 4096);
    for index in 0..records {
        stored.extend(std::iter::repeat_n((index % 251 + 1) as u8, 4096));
    }
    let mut ranges = (0..records).map(|index| FileRange {
        offset: index as u64 * 3 * 4096,
        length: 4096,
    });
    formatter
        .create(
            "/sparse",
            file_mode::S_IFREG | 0o644,
            None,
            Some(timestamp),
            Some(FileData::Sparse(SparseData {
                reader: &mut stored.as_slice(),
                length: records as u64 * 3 * 4096,
                ranges: &mut ranges,
            })),
            Some(0),
            Some(0),
            None,
            None,
        )
        .unwrap();
    let mut hole_ranges = std::iter::empty();
    formatter
        .create(
            "/all-hole",
            file_mode::S_IFREG | 0o644,
            None,
            Some(timestamp),
            Some(FileData::Sparse(SparseData {
                reader: &mut std::io::empty(),
                length: 1u64 << 40,
                ranges: &mut hole_ranges,
            })),
            Some(0),
            Some(0),
            None,
            None,
        )
        .unwrap();
    let mut unaligned_ranges = [
        FileRange {
            offset: 1,
            length: 3,
        },
        FileRange {
            offset: 8,
            length: 2,
        },
        FileRange {
            offset: 4095,
            length: 3,
        },
    ]
    .into_iter();
    formatter
        .create(
            "/unaligned",
            file_mode::S_IFREG | 0o644,
            None,
            Some(timestamp),
            Some(FileData::Sparse(SparseData {
                reader: &mut b"abcdefgh".as_slice(),
                length: 8192,
                ranges: &mut unaligned_ranges,
            })),
            Some(0),
            Some(0),
            None,
            None,
        )
        .unwrap();
    formatter
        .create(
            b"/raw-dir \xff /file \xfe ",
            file_mode::S_IFREG | 0o600,
            None,
            Some(timestamp),
            Some(FileData::Dense(&mut b"raw\0payload\xfe".as_slice())),
            Some(0),
            Some(0),
            None,
            None,
        )
        .unwrap();
    let raw_target = b"raw-dir \xff /file \xfe ";
    formatter
        .create(
            "/raw-link",
            file_mode::S_IFLNK | 0o777,
            Some(raw_target),
            Some(timestamp),
            None,
            Some(0),
            Some(0),
            None,
            None,
        )
        .unwrap();
    let longest_target = vec![b't'; 4095];
    formatter
        .create(
            "/limit",
            file_mode::S_IFLNK | 0o777,
            Some(&longest_target),
            Some(timestamp),
            None,
            Some(0),
            Some(0),
            None,
            None,
        )
        .unwrap();
    let too_long = vec![b't'; 4096];
    for rejected_path in ["/limit", "/missing-parent/rejected"] {
        assert!(matches!(
            formatter.create(
                rejected_path,
                file_mode::S_IFLNK | 0o777,
                Some(&too_long),
                Some(timestamp),
                None,
                Some(0),
                Some(0),
                None,
                None
            ),
            Err(FormatError::SymlinkTargetTooLong {
                length: 4096,
                maximum: 4095
            })
        ));
    }
    assert!(!formatter.exists("/missing-parent"));
    formatter.close().unwrap();
    let path = image.to_str().unwrap();
    run("e2fsck", &["-fn", path]);
    let metadata_stat = run("debugfs", &["-R", "stat /metadata", path]);
    assert_debugfs_metadata(&metadata_stat, "regular", 0o640, 100_001, 200_001);
    assert_eq!(
        debugfs_stat_word(&metadata_stat, "Links:")
            .parse::<u64>()
            .unwrap(),
        2
    );
    assert_eq!(
        debugfs_stat_word(&metadata_stat, "Size:")
            .parse::<u64>()
            .unwrap(),
        8
    );
    let alias_stat = run("debugfs", &["-R", "stat /alias", path]);
    assert_debugfs_metadata(&alias_stat, "regular", 0o640, 100_001, 200_001);
    assert_eq!(
        debugfs_stat_word(&alias_stat, "Inode:"),
        debugfs_stat_word(&metadata_stat, "Inode:")
    );
    assert_eq!(debugfs_stat_word(&alias_stat, "Links:"), "2");
    let root_stat = run("debugfs", &["-R", "stat /", path]);
    assert_debugfs_metadata(&root_stat, "directory", 0o750, 100_000, 200_000);
    let directory_stat = run("debugfs", &["-R", "stat /directory", path]);
    assert_debugfs_metadata(&directory_stat, "directory", 0o751, 100_003, 200_003);
    for (entry, kind, device) in [
        ("/fifo", "FIFO", None),
        ("/socket", "socket", None),
        ("/char", "character special", Some("4095:1048575")),
        ("/block", "block special", Some("4094:524289")),
        ("/small-char", "character special", Some("01:03")),
    ] {
        let stat = run("debugfs", &["-R", &format!("stat {entry}"), path]);
        assert_debugfs_metadata(&stat, kind, 0o600, 100_002, 200_002);
        assert_eq!(debugfs_stat_word(&stat, "Blockcount:"), "0");
        if let Some(device) = device {
            assert_eq!(
                debugfs_stat_word(&stat, "Device major/minor number:"),
                device
            );
            if entry == "/small-char" {
                assert!(
                    !stat.contains("(New-style)"),
                    "small device must use the original i_block[0] encoding: {stat}"
                );
            }
        }
    }
    let hole_stat = run("debugfs", &["-R", "stat /all-hole", path]);
    assert_eq!(debugfs_stat_word(&hole_stat, "Size:"), "1099511627776");
    assert_eq!(debugfs_stat_word(&hole_stat, "Blockcount:"), "0");
    for logical in [0, 4096, (1u64 << 40) / 4096 - 1] {
        assert_eq!(
            run(
                "debugfs",
                &["-R", &format!("bmap /all-hole {logical}"), path]
            )
            .trim(),
            "0"
        );
    }
    for (name, expected) in [
        ("user.probe", large.as_slice()),
        ("security.capability", capability.as_slice()),
        ("system.posix_acl_access", acl_disk.as_slice()),
    ] {
        let output = dir.path().join(format!("{name}.bin"));
        // -r explicitly bypasses libext2fs' own ACL API conversion: assert the
        // actual disk-v1 bytes against the independent literal construction.
        run(
            "debugfs",
            &[
                "-R",
                &format!("ea_get -r -f \"{}\" /metadata {name}", output.display()),
                path,
            ],
        );
        assert_eq!(std::fs::read(output).unwrap(), expected, "{name}");
    }
    let root = dir.path().join("root-xattr.bin");
    run(
        "debugfs",
        &[
            "-R",
            &format!("ea_get -r -f \"{}\" / user.root", root.display()),
            path,
        ],
    );
    assert_eq!(std::fs::read(root).unwrap(), b"root\0bytes");
    let default_acl = dir.path().join("default-acl.bin");
    run(
        "debugfs",
        &[
            "-R",
            &format!(
                "ea_get -r -f \"{}\" /directory system.posix_acl_default",
                default_acl.display()
            ),
            path,
        ],
    );
    assert_eq!(std::fs::read(default_acl).unwrap(), acl_disk);
    for (entry, name) in [
        ("/metadata", "system.posix_acl_access"),
        ("/directory", "system.posix_acl_default"),
    ] {
        let output = dir.path().join(format!("{name}-v2.bin"));
        run(
            "debugfs",
            &[
                "-R",
                &format!("ea_get -f \"{}\" {entry} {name}", output.display()),
                path,
            ],
        );
        assert_eq!(std::fs::read(output).unwrap(), acl_debugfs_v2);
    }
    let raw_dump = dir.path().join("raw.dump");
    let commands = dir.path().join("raw.commands");
    let mut raw_command = b"dump \"/raw-dir \xff /file \xfe \" \"".to_vec();
    raw_command.extend_from_slice(raw_dump.as_os_str().as_bytes());
    raw_command.extend_from_slice(b"\"\n");
    let raw_xattr = dir.path().join("raw-xattr.bin");
    raw_command.extend_from_slice(b"ea_get -r -f \"");
    raw_command.extend_from_slice(raw_xattr.as_os_str().as_bytes());
    raw_command.extend_from_slice(b"\" /metadata \"user.raw\xff\"\n");
    std::fs::write(&commands, raw_command).unwrap();
    run("debugfs", &["-f", commands.to_str().unwrap(), path]);
    assert_eq!(std::fs::read(raw_dump).unwrap(), b"raw\0payload\xfe");
    assert_eq!(std::fs::read(raw_xattr).unwrap(), b"opaque\0\xfe");
    let links = dir.path().join("extracted-links");
    std::fs::create_dir(&links).unwrap();
    for entry in ["/raw-link", "/limit"] {
        run(
            "debugfs",
            &[
                "-R",
                &format!("rdump {entry} \"{}\"", links.display()),
                path,
            ],
        );
    }
    assert_eq!(
        std::fs::read_link(links.join("raw-link"))
            .unwrap()
            .as_os_str()
            .as_bytes(),
        raw_target
    );
    assert_eq!(
        std::fs::read_link(links.join("limit"))
            .unwrap()
            .as_os_str()
            .as_bytes(),
        longest_target
    );
    let limit_stat = run("debugfs", &["-R", "stat /limit", path]);
    assert_eq!(debugfs_stat_word(&limit_stat, "Size:"), "4095");
    let unaligned_dump = dir.path().join("unaligned.dump");
    run(
        "debugfs",
        &[
            "-R",
            &format!("dump /unaligned \"{}\"", unaligned_dump.display()),
            path,
        ],
    );
    let mut expected = vec![0; 8192];
    expected[1..4].copy_from_slice(b"abc");
    expected[8..10].copy_from_slice(b"de");
    expected[4095..4098].copy_from_slice(b"fgh");
    assert_eq!(std::fs::read(unaligned_dump).unwrap(), expected);
    let sparse_dump = dir.path().join("sparse.dump");
    run(
        "debugfs",
        &[
            "-R",
            &format!("dump /sparse \"{}\"", sparse_dump.display()),
            path,
        ],
    );
    let mut dumped = std::fs::File::open(sparse_dump).unwrap();
    let mut probe = [0u8; 32];
    for index in [0, 1, 999, records - 1] {
        dumped
            .seek(SeekFrom::Start(index as u64 * 3 * 4096))
            .unwrap();
        dumped.read_exact(&mut probe).unwrap();
        assert_eq!(probe, [(index % 251 + 1) as u8; 32]);
        dumped.seek(SeekFrom::Current(4096 - 32)).unwrap();
        dumped.read_exact(&mut probe).unwrap();
        assert_eq!(
            probe, [0; 32],
            "logical holes must not expose neighboring physical data"
        );
    }
}

fn debugfs_stat_word<'a>(stat: &'a str, field: &str) -> &'a str {
    stat.split_once(field)
        .unwrap_or_else(|| panic!("missing {field} in {stat}"))
        .1
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("empty {field} in {stat}"))
}

fn assert_debugfs_metadata(stat: &str, kind: &str, mode: u16, uid: u64, gid: u64) {
    let actual_kind = stat
        .split_once("Type:")
        .unwrap()
        .1
        .split_once("Mode:")
        .unwrap()
        .0
        .trim();
    assert_eq!(actual_kind, kind, "{stat}");
    assert_eq!(
        u16::from_str_radix(debugfs_stat_word(stat, "Mode:"), 8).unwrap(),
        mode,
        "{stat}"
    );
    assert_eq!(
        debugfs_stat_word(stat, "User:").parse::<u64>().unwrap(),
        uid,
        "{stat}"
    );
    assert_eq!(
        debugfs_stat_word(stat, "Group:").parse::<u64>().unwrap(),
        gid,
        "{stat}"
    );
    // Independent expected disk representation of 2038-01-19T03:14:08 plus
    // 123456789 ns: signed low seconds needs the extra epoch carry bit.
    for field in ["ctime:", "atime:", "mtime:", "crtime:"] {
        assert_eq!(
            debugfs_stat_word(stat, field),
            "0x80000000:1d6f3455",
            "{field}: {stat}"
        );
    }
}

/// Run an e2fsprogs repair/optimize pass: 0 (clean) or 1 (changed) succeed.
fn run_repair(program: &str, args: &[&str]) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "{program} {} failed with status {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

const FRAG_BLOCKS: usize = 4096;
const SMALL_ENTRIES: usize = 3000;
const DEEP_ENTRIES: usize = 12_000;

fn deep_name(index: usize) -> String {
    format!("{}-{index:05}", "n".repeat(190))
}

fn frag_expected() -> Vec<u8> {
    let mut bytes = vec![0u8; FRAG_BLOCKS * 4096];
    for (block, chunk) in bytes.chunks_mut(4096).enumerate() {
        if block % 2 == 0 {
            chunk.fill((block % 251) as u8 + 1);
        }
    }
    bytes
}

/// A `silo-upper-ext4-v1` image mutated by libext2fs rather than the Rust
/// formatter: indexed one- and two-level htree directories, a depth-2
/// fragmented extent tree, unwritten allocation beyond EOF, external xattrs,
/// a hardlink group and Linux special-file encodings. e2fsck must call it
/// clean before the reader sees it.
fn libext2fs_mutated_upper(dir: &Path) -> PathBuf {
    use disk_image::ext4::upper::format_upper;
    use rootfs_spec::upper_geometry::UpperCapacity;

    let image = dir.join("mutated-upper.raw");
    format_upper(&image, UpperCapacity::new(512 << 20).unwrap()).unwrap();
    let frag = dir.join("frag.bin");
    let mut source = frag_expected();
    for (block, chunk) in source.chunks_mut(4096).enumerate() {
        chunk.fill((block % 251) as u8 + 1);
    }
    std::fs::write(&frag, source).unwrap();
    let small = dir.join("small.txt");
    std::fs::write(&small, b"abc").unwrap();
    let xattr = dir.join("xattr.bin");
    std::fs::write(&xattr, vec![0x5au8; 3000]).unwrap();

    let mut commands = String::from("cd /upper\nmkdir small\ncd small\n");
    for index in 1..=SMALL_ENTRIES {
        commands.push_str(&format!("mknod entry-{index:05} p\n"));
    }
    commands.push_str("cd /upper\nmkdir deep\ncd deep\n");
    for index in 1..=DEEP_ENTRIES {
        commands.push_str(&format!("mknod {} p\n", deep_name(index)));
    }
    commands.push_str("cd /upper\n");
    commands.push_str(&format!("write {} frag\n", frag.display()));
    for block in (1..FRAG_BLOCKS).step_by(2) {
        commands.push_str(&format!("punch frag {block} {block}\n"));
    }
    commands.push_str(&format!(
        "write {} pre\nfallocate pre 4 15\n",
        small.display()
    ));
    commands.push_str(&format!("write {} attrs\n", small.display()));
    commands.push_str(&format!("ea_set -f {} attrs user.big\n", xattr.display()));
    commands.push_str("ea_set attrs trusted.overlay.origin abc\n");
    commands.push_str(&format!(
        "write {} orig\nln orig alias\nsif orig links_count 2\n",
        small.display()
    ));
    // debugfs mknod limits both numbers to 16 bits. Create a new-encoding
    // device first, then set its disk word to Linux's full 12:20-bit boundary.
    commands.push_str("mknod null c 1 3\nmknod wide c 4095 65535\n");
    commands.push_str("sif wide block[1] 0xffffffff\nmknod whiteout c 0 0\n");
    commands.push_str("mknod disk b 8 1\nmknod pipe p\nsymlink fast frag\n");
    commands.push_str(&format!("symlink slow {}\n", "x".repeat(100)));
    let script = dir.join("mutate.debugfs");
    std::fs::write(&script, commands).unwrap();
    let path = image.to_str().unwrap();
    run("debugfs", &["-w", "-f", script.to_str().unwrap(), path]);
    run_repair("e2fsck", &["-fyD", path]);
    run("e2fsck", &["-fn", path]);
    image
}

#[test]
fn reader_inspects_libext2fs_mutated_upper_exactly() {
    use disk_image::ext4::constants::inode_flags;
    use disk_image::ext4::reader::InodeKind;
    use disk_image::ext4::types::ExtentHeader;
    use disk_image::ext4::{DeviceId, FileRange};
    use std::io::Read;

    let dir = outside_workspace_tempdir();
    let image = libext2fs_mutated_upper(dir.path());
    let wide_stat = run(
        "debugfs",
        &["-R", "stat /upper/wide", image.to_str().unwrap()],
    );
    assert_eq!(
        debugfs_stat_word(&wide_stat, "Device major/minor number:"),
        "4095:1048575",
        "{wide_stat}"
    );
    let reader = Reader::new(&image).unwrap();
    let summary = reader.audit().unwrap();
    assert_eq!(
        summary.special_files,
        (SMALL_ENTRIES + DEEP_ENTRIES + 5) as u64
    );

    let upper = reader.stat_no_follow("/upper").unwrap().0;
    for (name, expected) in [
        (
            "small",
            (1..=SMALL_ENTRIES)
                .map(|i| format!("entry-{i:05}"))
                .collect::<Vec<_>>(),
        ),
        ("deep", (1..=DEEP_ENTRIES).map(deep_name).collect()),
    ] {
        let number = reader.lookup(upper, name.as_bytes()).unwrap().unwrap();
        let raw = reader.get_inode(number).unwrap();
        assert_ne!(
            raw.flags & inode_flags::HASHED_INDEX,
            0,
            "{name} must be indexed"
        );
        let names: Vec<_> = reader
            .read_dir(number)
            .unwrap()
            .entries
            .into_iter()
            .map(|entry| String::from_utf8(entry.name).unwrap())
            .collect();
        let mut expected = expected;
        expected.sort();
        assert_eq!(names, expected, "{name}");
    }
    // The two-level index is what the deep fixture exists for.
    let indirect = run(
        "debugfs",
        &["-R", "htree /upper/deep", image.to_str().unwrap()],
    );
    assert!(indirect.contains("Indirect levels: 1"), "{indirect}");

    let (frag, raw) = reader.stat_no_follow("/upper/frag").unwrap();
    assert!(ExtentHeader::read_from(&raw.block).depth >= 2);
    let body = reader.file_body(frag).unwrap();
    assert_eq!(body.size(), (FRAG_BLOCKS * 4096) as u64);
    let ranges: Vec<_> = body.stored_ranges().collect();
    assert_eq!(ranges.len(), FRAG_BLOCKS / 2);
    assert_eq!(
        ranges[1],
        FileRange {
            offset: 2 * 4096,
            length: 4096
        }
    );
    let expected = frag_expected();
    assert_eq!(reader.read_file("/upper/frag", 0, None).unwrap(), expected);
    let dumped = dir.path().join("frag.dump");
    run(
        "debugfs",
        &[
            "-R",
            &format!("dump /upper/frag {}", dumped.display()),
            image.to_str().unwrap(),
        ],
    );
    assert_eq!(std::fs::read(&dumped).unwrap(), expected);
    let mut stream = Vec::new();
    reader.body_stream(&body).read_to_end(&mut stream).unwrap();
    let stored: Vec<u8> = expected
        .chunks(4096)
        .step_by(2)
        .flatten()
        .copied()
        .collect();
    assert_eq!(stream, stored);

    let pre = reader.stat_no_follow("/upper/pre").unwrap().0;
    let body = reader.file_body(pre).unwrap();
    assert_eq!(
        body.stored_ranges().collect::<Vec<_>>(),
        [FileRange {
            offset: 0,
            length: 3
        }]
    );
    assert_eq!(reader.read_file("/upper/pre", 0, None).unwrap(), b"abc");

    let attrs = reader.xattrs("/upper/attrs").unwrap();
    assert_eq!(attrs.get(b"user.big".as_slice()), Some(&vec![0x5au8; 3000]));
    assert_eq!(
        attrs.get(b"trusted.overlay.origin".as_slice()),
        Some(&b"abc".to_vec())
    );
    assert_ne!(
        reader
            .stat_no_follow("/upper/attrs")
            .unwrap()
            .1
            .xattr_block_lo,
        0
    );

    let (orig, _) = reader.stat_no_follow("/upper/orig").unwrap();
    assert_eq!(reader.stat_no_follow("/upper/alias").unwrap().0, orig);
    assert_eq!(reader.metadata(orig).unwrap().links, 2);
    for (name, kind) in [
        (
            "null",
            InodeKind::CharacterDevice(DeviceId::new(1, 3).unwrap()),
        ),
        (
            "wide",
            InodeKind::CharacterDevice(DeviceId::new(4095, 1_048_575).unwrap()),
        ),
        (
            "whiteout",
            InodeKind::CharacterDevice(DeviceId::new(0, 0).unwrap()),
        ),
        ("disk", InodeKind::BlockDevice(DeviceId::new(8, 1).unwrap())),
        ("pipe", InodeKind::Fifo),
    ] {
        let number = reader.lookup(upper, name.as_bytes()).unwrap().unwrap();
        assert_eq!(reader.metadata(number).unwrap().kind, kind, "{name}");
    }
    assert_eq!(reader.read_link("/upper/fast").unwrap(), b"frag");
    assert_eq!(
        reader.read_link("/upper/slow").unwrap(),
        "x".repeat(100).as_bytes()
    );
}

#[test]
fn reader_refuses_dirty_libext2fs_journal_without_replaying_it() {
    use disk_image::ext4::error::{ReadError, RecoveryReason};

    let dir = outside_workspace_tempdir();
    let image = dir.path().join("dirty-upper.raw");
    disk_image::ext4::upper::format_upper(
        &image,
        rootfs_spec::upper_geometry::UpperCapacity::new(64 << 20).unwrap(),
    )
    .unwrap();
    let block = dir.path().join("block.bin");
    std::fs::write(&block, vec![0xa5u8; 4096]).unwrap();
    let script = dir.path().join("journal.debugfs");
    std::fs::write(&script, format!("jo\njw -b 300 {}\njc\n", block.display())).unwrap();
    let path = image.to_str().unwrap();
    run("debugfs", &["-w", "-f", script.to_str().unwrap(), path]);
    let before = std::fs::read(&image).unwrap();
    assert!(matches!(
        Reader::new(&image),
        Err(ReadError::RequiresRecovery(
            RecoveryReason::JournalNeedsRecovery
        ))
    ));
    // The superblock stays readable for exact-copy callers, and nothing is replayed.
    disk_image::ext4::read_superblock(&std::fs::File::open(&image).unwrap()).unwrap();
    assert_eq!(std::fs::read(&image).unwrap(), before);

    run("debugfs", &["-w", "-R", "feature -needs_recovery", path]);
    assert!(matches!(
        Reader::new(&image),
        Err(ReadError::RequiresRecovery(RecoveryReason::JournalNotEmpty))
    ));
}

#[test]
fn reader_refuses_unsupported_mke2fs_formats() {
    use disk_image::ext4::error::{ReadError, Unsupported};

    let dir = outside_workspace_tempdir();
    for (name, features, expected) in [
        (
            "csum.img",
            "metadata_csum,64bit,^orphan_file",
            (0u32, 0x80u32, 0x400u32),
        ),
        (
            "inline.img",
            "inline_data,^metadata_csum,^64bit,^orphan_file",
            (0, 0x8000, 0),
        ),
    ] {
        let image = dir.path().join(name);
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        let path = image.to_str().unwrap();
        run(
            "mke2fs",
            &["-q", "-F", "-t", "ext4", "-b", "4096", "-O", features, path],
        );
        match Reader::new(&image) {
            Err(ReadError::Unsupported(Unsupported::Features {
                compat,
                incompat,
                ro_compat,
            })) => {
                assert_eq!(compat & expected.0, expected.0, "{name}");
                assert_eq!(incompat & expected.1, expected.1, "{name}");
                assert_eq!(ro_compat & expected.2, expected.2, "{name}");
            }
            Err(other) => panic!("{name}: expected unsupported features, got {other:?}"),
            Ok(_) => panic!("{name}: unsupported format was accepted"),
        }
    }
}
