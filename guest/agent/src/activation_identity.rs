//! Publish the restored generation before thawing image services.
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(crate) fn publish(destination_machine_id: &str, destination_run_id: &str) -> io::Result<()> {
    publish_at(Path::new("/"), destination_machine_id, destination_run_id)
}

fn publish_at(
    root: &Path,
    destination_machine_id: &str,
    destination_run_id: &str,
) -> io::Result<()> {
    // /run/silo is Silo's root-only state directory (root storage refuses any
    // other mode). Create it 0700 when absent and never change an existing one.
    let directory = root.join("run/silo");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    let temporary = directory.join(".generation.tmp");
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&temporary)?;
        writeln!(file, "{destination_run_id}")?;
        drop(file);
        fs::rename(&temporary, directory.join("generation"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;

    // A child must never thaw with its parent's identity (owner decision O2).
    rotate_machine_id(
        &root.join("etc/machine-id"),
        &root.join("run/machine-id"),
        destination_machine_id,
    )
}

fn rotate_machine_id(
    path: &Path,
    transient: &Path,
    destination_machine_id: &str,
) -> io::Result<()> {
    rotate_machine_id_at(path, transient, destination_machine_id).map_err(|error| {
        io::Error::new(error.kind(), format!("rotate {}: {error}", path.display()))
    })
}

fn rotate_machine_id_at(
    path: &Path,
    transient: &Path,
    destination_machine_id: &str,
) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "image machine-id {} is a symlink; refusing to follow it",
                path.display()
            ),
        ));
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "machine-id is not a regular file",
        ));
    }
    if metadata.len() == 0 {
        return Ok(());
    }
    let machine_id = parse_machine_id(destination_machine_id).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid destination machine-id {destination_machine_id:?}"),
        )
    })?;
    let mut file = match machine_id_writer(path) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(nix::errno::Errno::EROFS as i32) => {
            transient_machine_id_writer(path, transient)?
        }
        Err(error) => return Err(error),
    };
    // Keep the inode: a systemd transient machine-id is a read-only bind of
    // /run/machine-id. Writing its writable alias updates every mount reader;
    // systemd-machine-id-commit later persists this same value to /etc.
    file.set_len(0)?;
    writeln!(file, "{}", machine_id.simple())?;
    file.sync_all()
}

fn machine_id_writer(path: &Path) -> io::Result<fs::File> {
    let file = OpenOptions::new()
        .write(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

fn transient_machine_id_writer(path: &Path, transient: &Path) -> io::Result<fs::File> {
    let visible = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)?;
    let file = machine_id_writer(transient).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("open transient {}: {error}", transient.display()),
        )
    })?;
    let visible = visible.metadata()?;
    let backing = file.metadata()?;
    if !visible.is_file() || (visible.dev(), visible.ino()) != (backing.dev(), backing.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "read-only machine-id is not backed by transient {}",
                transient.display()
            ),
        ));
    }
    Ok(file)
}

fn parse_machine_id(value: &str) -> Option<uuid::Uuid> {
    let valid = match value.len() {
        32 => value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        36 => value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }),
        _ => false,
    };
    if !valid {
        return None;
    }
    uuid::Uuid::parse_str(value).ok()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use crate::activation_identity::{parse_machine_id, publish_at, transient_machine_id_writer};

    const MACHINE_ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn generation_is_created_and_atomically_replaced() {
        let root = tempfile::tempdir().unwrap();
        publish_at(root.path(), MACHINE_ID, "first-run").unwrap();
        let generation = root.path().join("run/silo/generation");
        let retained = fs::File::open(&generation).unwrap();
        assert_eq!(fs::read_to_string(&generation).unwrap(), "first-run\n");
        assert_eq!(
            fs::metadata(root.path().join("run/silo"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        publish_at(root.path(), MACHINE_ID, "second-run").unwrap();
        assert_eq!(fs::read_to_string(&generation).unwrap(), "second-run\n");
        assert_ne!(
            retained.metadata().unwrap().ino(),
            fs::metadata(&generation).unwrap().ino()
        );
        assert!(!root.path().join("run/silo/.generation.tmp").exists());
    }

    #[test]
    fn existing_state_directory_mode_is_never_changed() {
        // Root storage refuses a /run/silo that is not root-only; a looser
        // mode written during activation broke metrics in every child.
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("run/silo");
        fs::create_dir_all(&directory).unwrap();
        for mode in [0o700, 0o711] {
            fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
            publish_at(root.path(), MACHINE_ID, "run").unwrap();
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }

    #[test]
    fn nonempty_machine_id_is_rotated_in_place() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        let path = root.path().join("etc/machine-id");
        fs::write(&path, "old-machine-id-with-a-longer-value\n").unwrap();
        let retained = fs::File::open(&path).unwrap();
        publish_at(root.path(), MACHINE_ID, "run").unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("{MACHINE_ID}\n")
        );
        assert_eq!(
            retained.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
    }

    #[test]
    fn transient_alias_updates_existing_readers_without_replacing_the_inode() {
        let root = tempfile::tempdir().unwrap();
        let visible = root.path().join("visible");
        let transient = root.path().join("transient");
        fs::write(&transient, "old-machine-id-with-a-longer-value\n").unwrap();
        fs::hard_link(&transient, &visible).unwrap();
        let mut retained = fs::File::open(&visible).unwrap();
        let mut writer = transient_machine_id_writer(&visible, &transient).unwrap();
        writer.set_len(0).unwrap();
        writeln!(writer, "{MACHINE_ID}").unwrap();
        writer.sync_all().unwrap();
        let mut observed = String::new();
        retained.read_to_string(&mut observed).unwrap();
        assert_eq!(observed, format!("{MACHINE_ID}\n"));
        assert_eq!(fs::read_to_string(transient).unwrap(), observed);
    }

    #[test]
    fn transient_alias_requires_the_visible_inode_and_refuses_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let visible = root.path().join("visible");
        let transient = root.path().join("transient");
        fs::write(&visible, "source\n").unwrap();
        fs::write(&transient, "different\n").unwrap();
        let error = transient_machine_id_writer(&visible, &transient).unwrap_err();
        assert!(error.to_string().contains(&transient.display().to_string()));
        assert!(error.to_string().contains("not backed by"));
        fs::remove_file(&transient).unwrap();
        symlink(&visible, &transient).unwrap();
        assert!(transient_machine_id_writer(&visible, &transient).is_err());
        fs::remove_file(&transient).unwrap();
        fs::create_dir(&transient).unwrap();
        assert!(transient_machine_id_writer(&visible, &transient).is_err());
        fs::remove_dir(&transient).unwrap();
        assert!(transient_machine_id_writer(&visible, &transient).is_err());
        assert_eq!(fs::read_to_string(visible).unwrap(), "source\n");
    }

    #[test]
    fn nonregular_machine_id_reports_its_path_and_reason() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("etc/machine-id");
        fs::create_dir_all(&path).unwrap();
        let error = publish_at(root.path(), MACHINE_ID, "run").unwrap_err();
        assert!(error.to_string().contains(&path.display().to_string()));
        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn empty_and_missing_machine_id_keep_first_boot_semantics() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        let path = root.path().join("etc/machine-id");
        publish_at(root.path(), MACHINE_ID, "first").unwrap();
        assert!(!path.exists());
        fs::write(&path, "").unwrap();
        publish_at(root.path(), MACHINE_ID, "second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn symlink_machine_id_is_refused_without_following_it() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        let target = root.path().join("original-id");
        fs::write(&target, "original\n").unwrap();
        let path = root.path().join("etc/machine-id");
        symlink(&target, &path).unwrap();
        assert!(publish_at(root.path(), MACHINE_ID, "run").is_err());
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(target).unwrap(), "original\n");
    }

    #[test]
    fn hyphenated_machine_id_is_normalized_to_lowercase_hex() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        let path = root.path().join("etc/machine-id");
        fs::write(&path, "original\n").unwrap();
        publish_at(root.path(), "01234567-89AB-CDEF-0123-456789ABCDEF", "run").unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), format!("{MACHINE_ID}\n"));
    }

    #[test]
    fn invalid_destination_machine_ids_fail_activation_without_writing() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        let path = root.path().join("etc/machine-id");
        fs::write(&path, "original\n").unwrap();
        for invalid in [
            "",
            "not-a-machine-id",
            "0123456789abcdef0123456789abcdeg",
            "01234567_89ab-cdef-0123-456789abcdef",
            "{01234567-89ab-cdef-0123-456789abcdef}",
            "urn:uuid:01234567-89ab-cdef-0123-456789abcdef",
            "0123456789abcdef0123456789abcdef\n",
        ] {
            assert!(parse_machine_id(invalid).is_none());
            assert!(publish_at(root.path(), invalid, "run").is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
        }
    }

    #[test]
    fn unwritable_machine_id_fails_activation() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        let path = root.path().join("etc/machine-id");
        fs::write(&path, "original\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        if fs::OpenOptions::new().write(true).open(&path).is_ok() {
            // Running as root ignores the mode; nothing to prove here.
            return;
        }
        let error = publish_at(root.path(), MACHINE_ID, "run").unwrap_err();
        assert!(error.to_string().contains(&path.display().to_string()));
        assert!(error.to_string().contains("Permission denied"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
    }

    #[test]
    fn generation_failure_propagates_and_removes_temporary_file() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("run/silo/generation")).unwrap();
        assert!(publish_at(root.path(), MACHINE_ID, "run").is_err());
        assert!(!root.path().join("run/silo/.generation.tmp").exists());
    }
}
