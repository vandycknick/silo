use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use nix::errno::Errno;
use nix::fcntl::{openat, FlockArg, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode, SFlag};
use nix::unistd::geteuid;

use crate::paths::OwnedDirectory;
use crate::storage::StorageError;

/// An open-file-description lock. Drop closes only this descriptor, never issues
/// LOCK_UN: duplicates/inherited descriptors must preserve a lease's lifetime.
/// Stable lock files are never removed by normal cleanup.
#[must_use = "storage lock is released when its final descriptor closes"]
pub struct StorageLock {
    file: File,
}

impl StorageLock {
    pub fn duplicate(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
        })
    }
    pub(crate) fn durability_file(&self) -> io::Result<File> {
        self.file.try_clone()
    }
    pub(crate) fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Remains CLOEXEC in the parent; only an intended child may clear CLOEXEC.
    pub fn duplicate_inheritable(&self) -> io::Result<OwnedFd> {
        let fd = nix::fcntl::fcntl(&self.file, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(3))
            .map_err(io::Error::other)?;
        // F_DUPFD_CLOEXEC returned a new descriptor owned by this call.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    // Native stat field types differ between Linux and Darwin.
    #[allow(clippy::unnecessary_cast)]
    pub fn file_identity(&self) -> io::Result<(u64, u64)> {
        let stat = fstat(&self.file).map_err(io::Error::from)?;
        Ok((stat.st_dev as u64, stat.st_ino as u64))
    }
}

pub(crate) fn acquire(
    directory: &OwnedDirectory,
    name: &str,
    argument: FlockArg,
) -> Result<Option<StorageLock>, StorageError> {
    acquire_mode(directory, name, argument, true, false, true)
}

pub(crate) fn acquire_existing(
    directory: &OwnedDirectory,
    name: &str,
    argument: FlockArg,
) -> Result<Option<StorageLock>, StorageError> {
    acquire_mode(directory, name, argument, false, false, true)
}

pub(crate) fn acquire_new(
    directory: &OwnedDirectory,
    name: &str,
    argument: FlockArg,
) -> Result<Option<StorageLock>, StorageError> {
    acquire_mode(directory, name, argument, true, true, true)
}

pub(crate) fn acquire_new_deferred(
    directory: &OwnedDirectory,
    name: &str,
    argument: FlockArg,
) -> Result<Option<StorageLock>, StorageError> {
    acquire_mode(directory, name, argument, true, true, false)
}

fn acquire_mode(
    directory: &OwnedDirectory,
    name: &str,
    argument: FlockArg,
    create: bool,
    exclusive_create: bool,
    durable: bool,
) -> Result<Option<StorageLock>, StorageError> {
    let flags = OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
    let mode = Mode::S_IRUSR | Mode::S_IWUSR;
    let (fd, created) = if create {
        match openat(
            directory.fd(),
            name,
            flags | OFlag::O_CREAT | OFlag::O_EXCL,
            mode,
        ) {
            Ok(fd) => (fd, true),
            Err(Errno::EEXIST) if !exclusive_create => {
                (openat(directory.fd(), name, flags, Mode::empty())?, false)
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        (openat(directory.fd(), name, flags, Mode::empty())?, false)
    };
    if created {
        fchmod(&fd, mode)?;
    }
    let stat = fstat(&fd)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(StorageError::InvalidPath(format!(
            "invalid stable lock {}",
            directory.path().join(name).display()
        )));
    }
    let file = File::from(fd);
    if created && durable {
        file.sync_all()?;
        directory
            .sync()
            .map_err(|error| StorageError::InvalidPath(error.to_string()))?;
    }
    loop {
        #[allow(deprecated)]
        match nix::fcntl::flock(file.as_raw_fd(), argument) {
            Ok(()) => return Ok(Some(StorageLock { file })),
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn blocking(
    directory: &OwnedDirectory,
    name: &str,
    argument: FlockArg,
) -> Result<StorageLock, StorageError> {
    acquire(directory, name, argument)?.ok_or_else(|| {
        StorageError::Io(io::Error::new(
            io::ErrorKind::WouldBlock,
            "blocking storage lock was not acquired",
        ))
    })
}

#[cfg(test)]
mod tests {
    use nix::fcntl::FlockArg;

    use crate::paths::OwnedDirectory;
    use crate::storage::locks::{acquire, blocking};

    #[test]
    fn deferred_lease_keeps_private_exclusive_identity_and_barrier_ownership() {
        use crate::storage::locks::{acquire_existing, acquire_new_deferred};
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let directory = OwnedDirectory::open_root(&temporary.path().join("leases")).unwrap();
        let lease = acquire_new_deferred(&directory, "child.lease", FlockArg::LockSharedNonblock)
            .unwrap()
            .unwrap();
        assert_eq!(
            std::fs::metadata(directory.path().join("child.lease"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert!(
            acquire_new_deferred(&directory, "child.lease", FlockArg::LockSharedNonblock).is_err()
        );
        let barrier = lease.durability_file().unwrap();
        drop(lease);
        assert!(
            acquire_existing(&directory, "child.lease", FlockArg::LockExclusiveNonblock)
                .unwrap()
                .is_none()
        );
        barrier.sync_all().unwrap();
        directory.sync().unwrap();
        drop(barrier);
        assert!(
            acquire_existing(&directory, "child.lease", FlockArg::LockExclusiveNonblock)
                .unwrap()
                .is_some()
        );
    }

    fn isolated(name: &str) -> bool {
        if std::env::var("SILO_LEASE_TEST_CHILD").as_deref() == Ok(name) {
            return false;
        }
        // Other libtest threads fork subprocesses. CLOEXEC does not prevent
        // those children briefly retaining our OFD between fork and exec.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("SILO_LEASE_TEST_CHILD", name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    #[test]
    fn duplicate_extends_lease_and_stable_file_survives_drop() {
        if isolated("storage::locks::tests::duplicate_extends_lease_and_stable_file_survives_drop")
        {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let directory = OwnedDirectory::open_root(&temp.path().join("locks")).unwrap();
        let lease = blocking(&directory, "op.lease", FlockArg::LockShared).unwrap();
        let duplicate = lease.duplicate().unwrap();
        drop(lease);
        assert!(
            acquire(&directory, "op.lease", FlockArg::LockExclusiveNonblock)
                .unwrap()
                .is_none()
        );
        drop(duplicate);
        assert!(
            acquire(&directory, "op.lease", FlockArg::LockExclusiveNonblock)
                .unwrap()
                .is_some()
        );
        assert!(directory.path().join("op.lease").exists());
    }

    #[test]
    fn fresh_and_existing_lease_openers_never_replace_or_recreate_inodes() {
        if isolated("storage::locks::tests::fresh_and_existing_lease_openers_never_replace_or_recreate_inodes") {
            return;
        }
        use crate::storage::locks::{acquire_existing, acquire_new};
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let directory = OwnedDirectory::open_root(&temp.path().join("leases")).unwrap();
        assert!(
            acquire_existing(&directory, "missing.lease", FlockArg::LockExclusiveNonblock).is_err()
        );
        assert!(!directory.path().join("missing.lease").exists());
        let lease = acquire_new(&directory, "generation.lease", FlockArg::LockSharedNonblock)
            .unwrap()
            .unwrap();
        let identity = lease.file_identity().unwrap();
        let child = lease.duplicate_inheritable().unwrap();
        let flags = nix::fcntl::fcntl(&child, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert_ne!(flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
        drop(lease);
        assert!(acquire_existing(
            &directory,
            "generation.lease",
            FlockArg::LockExclusiveNonblock
        )
        .unwrap()
        .is_none());
        assert!(acquire_new(&directory, "generation.lease", FlockArg::LockSharedNonblock).is_err());
        drop(child);
        let exclusive = acquire_existing(
            &directory,
            "generation.lease",
            FlockArg::LockExclusiveNonblock,
        )
        .unwrap()
        .unwrap();
        assert_eq!(exclusive.file_identity().unwrap(), identity);
        drop(exclusive);
        std::fs::set_permissions(
            directory.path().join("generation.lease"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(acquire_existing(
            &directory,
            "generation.lease",
            FlockArg::LockExclusiveNonblock
        )
        .is_err());
        assert!(directory.path().join("generation.lease").exists());
    }
}
