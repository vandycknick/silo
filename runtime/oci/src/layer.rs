use std::io::Read;
use std::path::{Component, Path};

use tar::Archive;

use crate::ext4_writer::Ext4Writer;
use crate::{OciError, OciResult};

pub(crate) fn apply_layer(reader: impl Read, writer: &mut Ext4Writer) -> OciResult<()> {
    let mut archive = Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.into_owned();
        let path = sanitize_entry_path(&raw_path)?;
        if path == "/" {
            continue;
        }

        if let Some(whiteout) = parse_whiteout(&path) {
            match whiteout {
                Whiteout::Delete(path) => writer.delete(&path)?,
                Whiteout::Opaque(path) => writer.clear_dir(&path)?,
            }
            continue;
        }

        let mode = entry.header().mode().unwrap_or(0o644);
        let uid = entry.header().uid().unwrap_or(0) as u32;
        let gid = entry.header().gid().unwrap_or(0) as u32;
        let entry_type = entry.header().entry_type();

        if entry_type.is_file() {
            writer.write_file(&path, mode, uid, gid, &mut entry)?;
        } else if entry_type.is_dir() {
            writer.mkdir_p(&path, mode, uid, gid)?;
        } else if entry_type.is_symlink() {
            let target = link_name(&entry, &path)?;
            writer.symlink(&path, &target, uid, gid)?;
        } else if entry_type.is_hard_link() {
            let target = link_name(&entry, &path)?;
            let target = sanitize_entry_path(Path::new(&target))?;
            writer.link(&path, &target)?;
        } else if entry_type.is_block_special()
            || entry_type.is_character_special()
            || entry_type.is_fifo()
        {
            tracing::debug!(path, "skipping tar entry type not supported by ext4");
        } else {
            tracing::debug!(path, "skipping unsupported tar entry type");
        }
    }

    Ok(())
}

fn link_name<R: Read>(entry: &tar::Entry<'_, R>, path: &str) -> OciResult<String> {
    let Some(target) = entry.link_name()? else {
        return Err(OciError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: String::new(),
            reason: "target is missing",
        });
    };
    let target = target.into_owned();
    let Some(target) = target.to_str() else {
        return Err(OciError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: target.to_string_lossy().into_owned(),
            reason: "target must be UTF-8",
        });
    };
    if target.contains('\0') {
        return Err(OciError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: target.to_string(),
            reason: "target must not contain NUL bytes",
        });
    }
    Ok(target.to_string())
}

fn sanitize_entry_path(path: &Path) -> OciResult<String> {
    let mut clean = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(invalid_tar_path(path, "path components must be UTF-8"));
                };
                if part.contains('\0') {
                    return Err(invalid_tar_path(path, "path must not contain NUL bytes"));
                }
                clean.push(part.to_string());
            }
            Component::ParentDir => {
                return Err(invalid_tar_path(path, "path must not contain '..'"))
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }

    if clean.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", clean.join("/")))
    }
}

fn invalid_tar_path(path: &Path, reason: &'static str) -> OciError {
    OciError::InvalidTarPath {
        path: path.to_string_lossy().into_owned(),
        reason,
    }
}

enum Whiteout {
    Delete(String),
    Opaque(String),
}

fn parse_whiteout(path: &str) -> Option<Whiteout> {
    let name = basename(path)?;
    if name == ".wh..wh..opq" {
        return Some(Whiteout::Opaque(parent_of(path).to_string()));
    }
    let deleted = name.strip_prefix(".wh.")?;
    if deleted.is_empty() {
        return None;
    }
    Some(Whiteout::Delete(join(parent_of(path), deleted)))
}

fn basename(path: &str) -> Option<&str> {
    path.rsplit('/').next().filter(|name| !name.is_empty())
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::Cursor;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use disk_image::ext4::Reader;
    use tar::{Builder, EntryType, Header};

    use crate::ext4_writer::Ext4Writer;
    use crate::layer::apply_layer;
    use crate::OciError;

    const IMAGE_SIZE: u64 = 64 * 1024 * 1024;

    fn tar_file(path: &str, data: &[u8]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        append_file(&mut builder, path, data);
        builder.into_inner().expect("finish tar")
    }

    fn append_file(builder: &mut Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_path(path).expect("set path");
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(data.to_vec()))
            .expect("append file");
    }

    fn append_directory(builder: &mut Builder<Vec<u8>>, path: &str) {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Directory);
        header.set_path(path).expect("set path");
        header.set_size(0);
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(Vec::new()))
            .expect("append directory");
    }

    fn append_file_with_raw_path(builder: &mut Builder<Vec<u8>>, path: &[u8], data: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(data.to_vec()))
            .expect("append file");
    }

    fn append_file_with_metadata(
        builder: &mut Builder<Vec<u8>>,
        path: &str,
        data: &[u8],
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
    ) {
        let mut header = Header::new_gnu();
        header.set_path(path).expect("set path");
        header.set_size(data.len() as u64);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_gid(gid);
        header.set_mtime(mtime);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(data.to_vec()))
            .expect("append file");
    }

    fn append_link(
        builder: &mut Builder<Vec<u8>>,
        path: &str,
        target: &str,
        entry_type: EntryType,
    ) {
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(0);
        builder
            .append_link(&mut header, path, target)
            .expect("append link");
    }

    fn append_special(builder: &mut Builder<Vec<u8>>, path: &str, entry_type: EntryType) {
        let mut header = Header::new_gnu();
        header.set_path(path).expect("set path");
        header.set_entry_type(entry_type);
        header.set_size(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(Vec::new()))
            .expect("append special entry");
    }

    fn new_writer() -> (tempfile::TempDir, PathBuf, Ext4Writer) {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        let writer = Ext4Writer::create(&path, IMAGE_SIZE).expect("create ext4");
        (temp, path, writer)
    }

    fn finish_and_open(writer: Ext4Writer, path: &std::path::Path) -> Reader {
        writer.finish().expect("finish ext4");
        Reader::new(path).expect("open ext4")
    }

    #[test]
    fn rejects_parent_traversal() {
        let (_temp, _, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        append_file_with_raw_path(&mut builder, b"../etc/passwd", b"root");
        let err = apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect_err("parent traversal should fail");

        assert!(matches!(
            err,
            OciError::InvalidTarPath {
                path,
                reason: "path must not contain '..'",
            } if path == "../etc/passwd"
        ));
    }

    #[test]
    fn whiteout_deletes_lower_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        let mut writer = Ext4Writer::create(&path, 64 * 1024 * 1024).expect("create ext4");
        apply_layer(Cursor::new(tar_file("etc/old", b"old")), &mut writer).expect("lower layer");
        apply_layer(Cursor::new(tar_file("etc/.wh.old", b"")), &mut writer).expect("upper layer");
        writer.finish().expect("finish ext4");

        let mut reader = Reader::new(&path).expect("open ext4");
        assert!(reader.read_file("/etc/old", 0, Some(16)).is_err());
    }

    #[test]
    fn opaque_whiteout_clears_directory_children() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        let mut writer = Ext4Writer::create(&path, IMAGE_SIZE).expect("create ext4");
        apply_layer(Cursor::new(tar_file("etc/lower", b"lower")), &mut writer)
            .expect("lower layer");
        let mut upper = Builder::new(Vec::new());
        append_file(&mut upper, "etc/.wh..wh..opq", b"");
        append_file(&mut upper, "etc/upper", b"upper");
        apply_layer(
            Cursor::new(upper.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect("upper layer");
        writer.finish().expect("finish ext4");

        let mut reader = Reader::new(&path).expect("open ext4");
        assert!(reader.read_file("/etc/lower", 0, Some(16)).is_err());
        assert_eq!(
            reader
                .read_file("/etc/upper", 0, Some(16))
                .expect("read upper"),
            b"upper"
        );
    }

    #[test]
    fn bare_whiteout_is_not_treated_as_a_whiteout() {
        let (_temp, path, mut writer) = new_writer();

        apply_layer(Cursor::new(tar_file("etc/.wh.", b"marker")), &mut writer)
            .expect("apply layer");
        let mut reader = finish_and_open(writer, &path);

        assert_eq!(
            reader
                .read_file("/etc/.wh.", 0, None)
                .expect("read bare whiteout"),
            b"marker"
        );
    }

    #[test]
    fn forward_hardlink_target_fails() {
        let (_temp, _, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        append_link(&mut builder, "link", "target", EntryType::Link);
        append_file(&mut builder, "target", b"contents");

        let err = apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect_err("forward hardlink should fail");

        assert!(matches!(err, OciError::FlatExt4 { .. }));
    }

    #[test]
    fn backward_hardlink_target_succeeds() {
        let (_temp, path, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        append_file(&mut builder, "target", b"contents");
        append_link(&mut builder, "link", "target", EntryType::Link);

        apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect("backward hardlink should succeed");
        let mut reader = finish_and_open(writer, &path);

        assert_eq!(
            reader.read_file("/link", 0, None).expect("read hardlink"),
            b"contents"
        );
        assert_eq!(
            reader.stat("/link").expect("stat hardlink").0,
            reader.stat("/target").expect("stat target").0
        );
    }

    #[test]
    fn applies_two_layer_rootfs() {
        let (_temp, path, mut writer) = new_writer();
        let mut lower = Builder::new(Vec::new());
        append_directory(&mut lower, "bin");
        append_file(&mut lower, "bin/sh", b"shell");
        append_link(&mut lower, "bin/shell", "sh", EntryType::Symlink);
        append_directory(&mut lower, "etc");
        append_file(&mut lower, "etc/hostname", b"lower");
        append_file(&mut lower, "etc/release", b"1.0\n");
        apply_layer(
            Cursor::new(lower.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect("apply lower layer");

        let mut upper = Builder::new(Vec::new());
        append_file(&mut upper, "etc/.wh.hostname", b"");
        append_file(&mut upper, "etc/release", b"2.0\n");
        append_file_with_metadata(&mut upper, "app/server", b"server", 0o755, 1000, 1000, 0);
        apply_layer(
            Cursor::new(upper.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect("apply upper layer");
        let mut reader = finish_and_open(writer, &path);

        assert!(!reader.exists("/etc/hostname"));
        assert_eq!(
            reader
                .read_file("/etc/release", 0, None)
                .expect("read release"),
            b"2.0\n"
        );
        assert_eq!(
            reader
                .read_file("/bin/shell", 0, None)
                .expect("read symlink"),
            b"shell"
        );
        let server = reader.stat("/app/server").expect("stat server").1;
        assert_eq!(server.mode & 0o7777, 0o755);
        assert_eq!(server.uid_full(), 1000);
        assert_eq!(server.gid_full(), 1000);
    }

    #[test]
    fn timestamps_use_the_current_formatter_time() {
        let (_temp, path, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        append_file_with_metadata(&mut builder, "dated", b"contents", 0o644, 0, 0, 1);
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs() as u32;

        apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect("apply layer");
        let mut reader = finish_and_open(writer, &path);
        let inode = reader.stat("/dated").expect("stat file").1;
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs() as u32;

        assert_ne!(inode.mtime, 1);
        assert_eq!(inode.atime, inode.mtime);
        assert_eq!(inode.ctime, inode.mtime);
        assert_eq!(inode.crtime, inode.mtime);
        assert!((before..=after).contains(&inode.mtime));
    }

    #[test]
    fn devices_and_fifos_are_skipped() {
        let (_temp, path, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        append_special(&mut builder, "dev/char", EntryType::Char);
        append_special(&mut builder, "dev/block", EntryType::Block);
        append_special(&mut builder, "dev/fifo", EntryType::Fifo);
        append_file(&mut builder, "kept", b"contents");

        apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect("apply layer");
        let mut reader = finish_and_open(writer, &path);

        assert!(!reader.exists("/dev/char"));
        assert!(!reader.exists("/dev/block"));
        assert!(!reader.exists("/dev/fifo"));
        assert_eq!(
            reader.read_file("/kept", 0, None).expect("read file"),
            b"contents"
        );
    }

    #[test]
    fn symlink_entries_are_not_hardlinks() {
        let (_temp, path, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        append_file(&mut builder, "target", b"contents");
        append_link(&mut builder, "link", "target", EntryType::Symlink);

        apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect("apply layer");
        let mut reader = finish_and_open(writer, &path);
        let link = reader.stat_no_follow("/link").expect("stat symlink");
        let target = reader.stat("/target").expect("stat target");

        assert!(link.1.is_link());
        assert_ne!(link.0, target.0);
        assert_eq!(link.1.mode & 0o777, 0o777);
        assert_eq!(
            reader.read_file("/link", 0, None).expect("follow symlink"),
            b"contents"
        );
    }

    #[test]
    fn rejects_non_utf8_symlink_target() {
        let (_temp, _, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Symlink);
        header.set_path("link").expect("set path");
        header
            .set_link_name_literal(b"target-\xff")
            .expect("set link target");
        header.set_size(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(Vec::new()))
            .expect("append symlink");

        let err = apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect_err("non-UTF-8 target should fail");

        assert!(matches!(
            err,
            OciError::InvalidSymlinkTarget {
                path,
                target,
                reason: "target must be UTF-8",
            } if path == "/link" && target == "target-\u{fffd}"
        ));
    }

    #[test]
    fn rejects_nul_symlink_target() {
        let (_temp, _, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        builder
            .append_pax_extensions([("linkpath", &b"target\0suffix"[..])])
            .expect("append PAX extension");
        append_link(&mut builder, "link", "target", EntryType::Symlink);

        let err = apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect_err("NUL target should fail");

        assert!(matches!(
            err,
            OciError::InvalidSymlinkTarget {
                path,
                target,
                reason: "target must not contain NUL bytes",
            } if path == "/link" && target == "target\0suffix"
        ));
    }

    #[test]
    fn rejects_non_utf8_entry_path() {
        let (_temp, _, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header
            .set_path(PathBuf::from(OsString::from_vec(b"non-utf8-\xff".to_vec())))
            .expect("set path");
        header.set_size(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(Vec::new()))
            .expect("append file");

        let err = apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect_err("non-UTF-8 path should fail");

        assert!(matches!(
            err,
            OciError::InvalidTarPath {
                path,
                reason: "path components must be UTF-8",
            } if path == "non-utf8-\u{fffd}"
        ));
    }

    #[test]
    fn rejects_nul_entry_path() {
        let (_temp, _, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        builder
            .append_pax_extensions([("path", &b"etc/nul\0suffix"[..])])
            .expect("append PAX extension");
        append_file(&mut builder, "placeholder", b"contents");

        let err = apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect_err("NUL path should fail");

        assert!(matches!(
            err,
            OciError::InvalidTarPath {
                path,
                reason: "path must not contain NUL bytes",
            } if path == "etc/nul\0suffix"
        ));
    }

    #[test]
    fn preserves_observable_file_ownership_and_mode_bits() {
        let (_temp, path, mut writer) = new_writer();
        let mut builder = Builder::new(Vec::new());
        append_file_with_metadata(
            &mut builder,
            "owned",
            b"contents",
            0o6754,
            0x1234_5678,
            0x9abc_def0,
            0,
        );

        apply_layer(
            Cursor::new(builder.into_inner().expect("finish tar")),
            &mut writer,
        )
        .expect("apply layer");
        let mut reader = finish_and_open(writer, &path);
        let inode = reader.stat("/owned").expect("stat file").1;

        assert_eq!(inode.mode & 0o7777, 0o6754);
        assert_eq!(inode.uid_full(), 0x1234_5678);
        assert_eq!(inode.gid_full(), 0x9abc_def0);
    }
}
