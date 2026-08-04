use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;

use eyre::Context;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode, SFlag};

pub(crate) fn open_append(path: &Path) -> eyre::Result<File> {
    let directory = open_parent(path)?;
    let name = path
        .file_name()
        .expect("open_parent validates the filename");

    let create_flags = OFlag::O_WRONLY
        | OFlag::O_APPEND
        | OFlag::O_CREAT
        | OFlag::O_EXCL
        | OFlag::O_NOFOLLOW
        | OFlag::O_CLOEXEC;
    let fd = match openat(
        &directory,
        name,
        create_flags,
        Mode::from_bits_retain(0o600),
    ) {
        Ok(fd) => {
            fchmod(&fd, Mode::from_bits_retain(0o600))
                .map_err(eyre::Report::from)
                .wrap_err_with(|| format!("set mode on {}", path.display()))?;
            fd
        }
        Err(nix::errno::Errno::EEXIST) => openat(
            &directory,
            name,
            OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("open existing {}", path.display()))?,
        Err(error) => {
            return Err(eyre::Report::from(error))
                .wrap_err_with(|| format!("create {}", path.display()));
        }
    };

    validate_regular_file(&fd, path, nix::unistd::geteuid().as_raw())?;
    Ok(File::from(fd))
}

pub(crate) fn write_private(path: &Path, contents: &[u8]) -> eyre::Result<()> {
    let directory = open_parent(path)?;
    let name = path
        .file_name()
        .expect("open_parent validates the filename");
    let flags = OFlag::O_WRONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let fd = match openat(
        &directory,
        name,
        flags | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::from_bits_retain(0o600),
    ) {
        Ok(fd) => {
            fchmod(&fd, Mode::from_bits_retain(0o600))
                .map_err(eyre::Report::from)
                .wrap_err_with(|| format!("set mode on {}", path.display()))?;
            fd
        }
        Err(nix::errno::Errno::EEXIST) => openat(&directory, name, flags, Mode::empty())
            .map_err(eyre::Report::from)
            .wrap_err_with(|| format!("open existing {}", path.display()))?,
        Err(error) => {
            return Err(eyre::Report::from(error))
                .wrap_err_with(|| format!("create {}", path.display()));
        }
    };
    validate_regular_file(&fd, path, nix::unistd::geteuid().as_raw())?;
    let mut file = File::from(fd);
    file.set_len(0)
        .wrap_err_with(|| format!("truncate {}", path.display()))?;
    file.write_all(contents)
        .wrap_err_with(|| format!("write {}", path.display()))?;
    file.sync_all()
        .wrap_err_with(|| format!("sync {}", path.display()))
}

fn open_parent(path: &Path) -> eyre::Result<OwnedFd> {
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("private path has no parent: {}", path.display()))?;
    path.file_name()
        .ok_or_else(|| eyre::eyre!("private path has no filename: {}", path.display()))?;
    let directory = open(
        parent,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(eyre::Report::from)
    .wrap_err_with(|| format!("open private directory {}", parent.display()))?;
    validate_private_directory(&directory, parent)?;
    Ok(directory)
}

fn validate_private_directory(fd: &OwnedFd, path: &Path) -> eyre::Result<()> {
    let stat = fstat(fd)
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("inspect log directory {}", path.display()))?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR {
        return Err(eyre::eyre!("{} is not a directory", path.display()));
    }
    if stat.st_uid != nix::unistd::geteuid().as_raw() {
        return Err(eyre::eyre!(
            "{} is owned by UID {}, expected UID {}",
            path.display(),
            stat.st_uid,
            nix::unistd::geteuid().as_raw()
        ));
    }
    if stat.st_mode & 0o7777 != 0o700 {
        return Err(eyre::eyre!(
            "{} has mode {:o}, expected 700",
            path.display(),
            stat.st_mode & 0o7777
        ));
    }
    Ok(())
}

pub(crate) fn validate_regular_file(
    fd: &OwnedFd,
    path: &Path,
    expected_uid: u32,
) -> eyre::Result<()> {
    let stat = fstat(fd)
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("inspect {}", path.display()))?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
        return Err(eyre::eyre!("{} is not a regular file", path.display()));
    }
    if stat.st_uid != expected_uid {
        return Err(eyre::eyre!(
            "{} is owned by UID {}, expected UID {}",
            path.display(),
            stat.st_uid,
            expected_uid
        ));
    }
    if stat.st_mode & 0o777 != 0o600 {
        return Err(eyre::eyre!(
            "{} has mode {:o}, expected 600",
            path.display(),
            stat.st_mode & 0o777
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    use crate::secure_file::{open_append, validate_regular_file, write_private};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("silo-vmmon-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).expect("create temporary directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure temporary directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn append_file_is_private_and_retains_prior_content_despite_umask() {
        let dir = TempDir::new();
        let path = dir.path().join("vm.trace.log");
        let original_umask = unsafe { libc::umask(0o077) };
        let mut first = open_append(&path).expect("create private append file");
        unsafe { libc::umask(original_umask) };
        first.write_all(b"first\n").expect("write first record");
        drop(first);

        let mut second = open_append(&path).expect("reopen append file");
        second.write_all(b"second\n").expect("write second record");
        drop(second);

        assert_eq!(
            fs::read(&path).expect("read append file"),
            b"first\nsecond\n"
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("append file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn unsafe_existing_paths_are_rejected_without_replacement() {
        let dir = TempDir::new();
        let target = dir.path().join("target");
        fs::write(&target, b"target").expect("write target");

        let link = dir.path().join("link.log");
        symlink(&target, &link).expect("create symlink");
        assert!(open_append(&link).is_err());
        assert_eq!(fs::read(&target).expect("read symlink target"), b"target");

        let directory = dir.path().join("directory.log");
        fs::create_dir(&directory).expect("create unexpected directory");
        assert!(open_append(&directory).is_err());

        let permissive = dir.path().join("permissive.log");
        fs::write(&permissive, b"existing").expect("write permissive file");
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o644))
            .expect("make file permissive");
        assert!(open_append(&permissive).is_err());
        assert_eq!(
            fs::metadata(&permissive)
                .expect("permissive file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn descriptor_owner_validation_uses_the_effective_uid() {
        let dir = TempDir::new();
        let path = dir.path().join("owned.log");
        let file = open_append(&path).expect("create owned file");
        let fd: OwnedFd = file.into();

        validate_regular_file(&fd, &path, nix::unistd::geteuid().as_raw())
            .expect("current effective UID owns the file");
        assert!(
            validate_regular_file(&fd, &path, nix::unistd::geteuid().as_raw().wrapping_add(1))
                .is_err()
        );
    }

    #[test]
    fn private_write_replaces_without_accepting_unsafe_existing_files() {
        let dir = TempDir::new();
        let path = dir.path().join("vm.pid");
        write_private(&path, b"123\n").expect("create private file");
        write_private(&path, b"9\n").expect("replace private file");
        assert_eq!(fs::read(&path).expect("read private file"), b"9\n");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("make private file unsafe");
        assert!(write_private(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path).expect("read rejected file"), b"9\n");
    }

    #[test]
    fn append_file_rejects_unsafe_or_linked_parent_directory() {
        let dir = TempDir::new();
        let unsafe_parent = dir.path().join("unsafe");
        fs::create_dir(&unsafe_parent).expect("create unsafe parent");
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o755))
            .expect("make parent unsafe");
        assert!(open_append(&unsafe_parent.join("vm.trace.log")).is_err());

        let target = dir.path().join("target");
        fs::create_dir(&target).expect("create parent target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("secure parent target");
        let link = dir.path().join("linked");
        symlink(&target, &link).expect("link parent");
        assert!(open_append(&link.join("vm.trace.log")).is_err());
    }
}
