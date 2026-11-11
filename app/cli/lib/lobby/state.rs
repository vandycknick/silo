use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use nix::{
    fcntl::{Flock, FlockArg, OFlag},
    unistd::Uid,
};

pub(crate) fn private_dir(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();
    DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state directory must be owned and private",
        ));
    }
    Ok(())
}

pub(crate) fn sync_dir(path: impl AsRef<Path>) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub(crate) fn atomic_write(path: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::Builder::new()
        .prefix(".lobby-")
        .tempfile_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    sync_dir(parent)
}

pub(crate) fn instance(home: impl AsRef<Path>) -> io::Result<String> {
    let home = home.as_ref();
    match read_instance(home) {
        Ok(value) => return Ok(value),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    private_dir(home.join("lobby"))?;
    let value = uuid::Uuid::new_v4().simple().to_string();
    atomic_write(home.join("lobby/instance"), format!("{value}\n").as_bytes())?;
    Ok(value)
}

pub(crate) fn read_instance(home: impl AsRef<Path>) -> io::Result<String> {
    let bytes = fs::read(home.as_ref().join("lobby/instance"))?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid lobby instance"))?
        .trim();
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid lobby instance",
        ));
    }
    Ok(value.to_owned())
}

pub(crate) fn lock_home(home: impl AsRef<Path>) -> io::Result<Flock<File>> {
    let dir = home.as_ref().join("lobby");
    private_dir(&dir)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW).bits())
        .open(dir.join("lock"))?;
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
        if error == nix::errno::Errno::EWOULDBLOCK {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "another lobby instance owns this home",
            )
        } else {
            io::Error::from(error)
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::lobby::state::{atomic_write, instance, lock_home, private_dir, read_instance};
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    #[test]
    fn private_atomic_files_and_stable_instance() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("lobby");
        private_dir(&dir).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let id = instance(home.path()).unwrap();
        assert_eq!(id, instance(home.path()).unwrap());
        let path = dir.join("document");
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::write(dir.join("instance"), "not-an-instance").unwrap();
        assert!(read_instance(home.path()).is_err());
        assert!(instance(home.path()).is_err());
    }

    #[test]
    fn private_directories_reject_public_permissions_and_symlinks() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("public");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_dir(&dir).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let link = home.path().join("link");
        symlink(&dir, &link).unwrap();
        assert!(private_dir(&link).is_err());
    }

    #[test]
    fn exclusive_home_lock() {
        let home = tempfile::tempdir().unwrap();
        let first = lock_home(home.path()).unwrap();
        assert_eq!(
            lock_home(home.path()).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(first);
        drop(lock_home(home.path()).unwrap());
    }

    #[test]
    fn lock_rejects_symlink() {
        let home = tempfile::tempdir().unwrap();
        private_dir(home.path().join("lobby")).unwrap();
        let target = home.path().join("target");
        fs::write(&target, "unchanged").unwrap();
        symlink(&target, home.path().join("lobby/lock")).unwrap();
        assert!(lock_home(home.path()).is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "unchanged");
    }
}
