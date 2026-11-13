//! Publish the restored generation before thawing image services.
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
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

    let path = root.join("etc/machine-id");
    if let Err(error) = rotate_machine_id(&path, destination_machine_id) {
        tracing::warn!(%error, path = %path.display(), "failed to rotate image machine-id");
    }
    Ok(())
}

fn rotate_machine_id(path: &Path, destination_machine_id: &str) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        tracing::warn!(path = %path.display(), "skipping symlink image machine-id");
        return Ok(());
    }
    if !metadata.is_file() || metadata.len() == 0 {
        return Ok(());
    }
    let Some(machine_id) = parse_machine_id(destination_machine_id) else {
        tracing::error!(
            destination_machine_id,
            "invalid destination machine-id; leaving image machine-id unchanged"
        );
        return Ok(());
    };
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Ok(());
    }
    // Truncate in place because systemd may bind-mount the machine-id file.
    file.set_len(0)?;
    writeln!(file, "{}", machine_id.simple())
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
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use crate::activation_identity::{parse_machine_id, publish_at};

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
    fn symlink_machine_id_is_not_followed() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        let target = root.path().join("original-id");
        fs::write(&target, "original\n").unwrap();
        let path = root.path().join("etc/machine-id");
        symlink(&target, &path).unwrap();
        publish_at(root.path(), MACHINE_ID, "run").unwrap();
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(target).unwrap(), "original\n");
        fs::remove_file(root.path().join("original-id")).unwrap();
        publish_at(root.path(), MACHINE_ID, "next").unwrap();
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
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
    fn invalid_machine_ids_are_skipped_without_blocking_generation() {
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
            publish_at(root.path(), invalid, "run").unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
            assert_eq!(
                fs::read_to_string(root.path().join("run/silo/generation")).unwrap(),
                "run\n"
            );
        }
    }

    #[test]
    fn generation_failure_propagates_and_removes_temporary_file() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("run/silo/generation")).unwrap();
        assert!(publish_at(root.path(), MACHINE_ID, "run").is_err());
        assert!(!root.path().join("run/silo/.generation.tmp").exists());
    }
}
