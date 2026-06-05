use std::io::Read;
use std::path::{Component, Path};

use tar::Archive;

use crate::ext4_writer::Ext4Writer;
use crate::{OciDiskError, OciDiskResult};

pub(crate) fn apply_layer(reader: impl Read, writer: &mut Ext4Writer) -> OciDiskResult<()> {
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
            tracing::debug!(path, "skipping tar entry type not supported by bento-ext4");
        } else {
            tracing::debug!(path, "skipping unsupported tar entry type");
        }
    }

    Ok(())
}

fn link_name<R: Read>(entry: &tar::Entry<'_, R>, path: &str) -> OciDiskResult<String> {
    let Some(target) = entry.link_name()? else {
        return Err(OciDiskError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: String::new(),
            reason: "target is missing",
        });
    };
    let target = target.into_owned();
    let Some(target) = target.to_str() else {
        return Err(OciDiskError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: target.to_string_lossy().into_owned(),
            reason: "target must be UTF-8",
        });
    };
    if target.contains('\0') {
        return Err(OciDiskError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: target.to_string(),
            reason: "target must not contain NUL bytes",
        });
    }
    Ok(target.to_string())
}

fn sanitize_entry_path(path: &Path) -> OciDiskResult<String> {
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

fn invalid_tar_path(path: &Path, reason: &'static str) -> OciDiskError {
    OciDiskError::InvalidTarPath {
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
    use std::io::Cursor;

    use bento_ext4::Reader;
    use tar::{Builder, Header};

    use crate::ext4_writer::Ext4Writer;
    use crate::layer::{apply_layer, sanitize_entry_path};

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

    #[test]
    fn rejects_parent_traversal() {
        let err = sanitize_entry_path(std::path::Path::new("../etc/passwd"))
            .expect_err("parent traversal should fail");

        assert!(err.to_string().contains("must not contain '..'"));
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
        let mut writer = Ext4Writer::create(&path, 64 * 1024 * 1024).expect("create ext4");
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
}
