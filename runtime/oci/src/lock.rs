use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;

use crate::OciResult;

use nix::fcntl::FlockArg;

pub(crate) struct FileLock {
    // Close only: duplicated/inherited OFDs must never be explicitly unlocked.
    _file: File,
}

impl std::fmt::Debug for FileLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("FileLock").finish_non_exhaustive()
    }
}

impl FileLock {
    pub(crate) fn exclusive(path: &Path) -> OciResult<Self> {
        Self::acquire(path, FlockArg::LockExclusive)
    }

    pub(crate) fn shared(path: &Path) -> OciResult<Self> {
        Self::acquire(path, FlockArg::LockShared)
    }

    fn acquire(path: &Path, operation: FlockArg) -> OciResult<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
        if let Some(parent) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits(),
            )
            .open(path)?;

        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "OCI lock is not a private owner-controlled mode0600 regular file",
            )
            .into());
        }
        loop {
            #[allow(deprecated)]
            match nix::fcntl::flock(file.as_raw_fd(), operation) {
                Ok(()) => return Ok(Self { _file: file }),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use crate::lock::FileLock;

    #[test]
    #[allow(deprecated)]
    fn duplicated_publication_lock_releases_only_after_the_last_close() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("locks/publication/stage.lock");
        let owner = FileLock::shared(&path).unwrap();
        let duplicate = owner._file.try_clone().unwrap();
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        drop(owner);
        assert_eq!(
            nix::fcntl::flock(
                contender.as_raw_fd(),
                nix::fcntl::FlockArg::LockExclusiveNonblock
            ),
            Err(nix::errno::Errno::EAGAIN),
        );
        drop(duplicate);
        nix::fcntl::flock(
            contender.as_raw_fd(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .unwrap();
        drop(contender);
        assert!(path.is_file());
    }
}
