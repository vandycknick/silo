use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use nix::fcntl::{fcntl, open, openat, AtFlags, FcntlArg, OFlag};
use nix::sys::stat::{fchmod, fstat, fstatat, mkdirat, Mode, SFlag};
use nix::unistd::{ftruncate, geteuid, mkdir, unlinkat, UnlinkatFlags};

use crate::LibVmError;

const PRIVATE_DIRECTORY_MODE: Mode = Mode::S_IRWXU;
const PRIVATE_FILE_MODE: Mode = Mode::S_IRUSR.union(Mode::S_IWUSR);

pub(crate) struct OwnedDirectory {
    fd: OwnedFd,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicWritePhase {
    Staged,
    Synced,
    Published,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sync {
    Durable,
    Deferred,
}

impl OwnedDirectory {
    pub(crate) fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn sync(&self) -> Result<(), LibVmError> {
        sync_directory(&self.fd, &self.path)
    }
    pub(crate) fn try_clone(&self) -> Result<Self, LibVmError> {
        Ok(Self {
            fd: self
                .fd
                .try_clone()
                .map_err(|error| invalid(&self.path, error))?,
            path: self.path.clone(),
        })
    }

    /// Duplicates this directory, keeping CLOEXEC until cleared in the child.
    pub(crate) fn duplicate_inheritable(&self) -> Result<OwnedFd, LibVmError> {
        let fd = fcntl(&self.fd, FcntlArg::F_DUPFD_CLOEXEC(3))
            .map_err(|error| invalid(&self.path, error))?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub(crate) fn open_root(path: &Path) -> Result<Self, LibVmError> {
        Self::open_root_with(path, Sync::Durable)
    }

    pub(crate) fn open_root_deferred(path: &Path) -> Result<Self, LibVmError> {
        Self::open_root_with(path, Sync::Deferred)
    }

    fn open_root_with(path: &Path, sync: Sync) -> Result<Self, LibVmError> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid(path, "has no parent directory"))?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        fs::create_dir_all(parent).map_err(|error| invalid(path, error))?;

        let created = match mkdir(path, PRIVATE_DIRECTORY_MODE) {
            Ok(()) => true,
            Err(nix::errno::Errno::EEXIST) => false,
            Err(error) => return Err(invalid(path, error)),
        };
        let fd = open_directory(path)?;
        if created {
            fchmod(&fd, PRIVATE_DIRECTORY_MODE).map_err(|error| invalid(path, error))?;
            if sync == Sync::Durable {
                sync_directory(&fd, path)?;
                sync_directory(&open_directory(parent)?, parent)?;
            }
        }
        validate_directory(&fd, path, created)?;
        Ok(Self {
            fd,
            path: path.to_path_buf(),
        })
    }

    /// Opens an existing root without creating it or any of its parents.
    pub(crate) fn open_existing_root(path: &Path) -> Result<Option<Self>, LibVmError> {
        let fd = match open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(invalid(path, error)),
        };
        validate_directory(&fd, path, false)?;
        Ok(Some(Self {
            fd,
            path: path.to_path_buf(),
        }))
    }

    pub(crate) fn ensure_dir(&self, name: &str) -> Result<Self, LibVmError> {
        self.ensure_dir_with(name, Sync::Durable)
    }

    pub(crate) fn ensure_dir_deferred(&self, name: &str) -> Result<Self, LibVmError> {
        self.ensure_dir_with(name, Sync::Deferred)
    }

    fn ensure_dir_with(&self, name: &str, sync: Sync) -> Result<Self, LibVmError> {
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "directory name is not one path component",
            ));
        }
        let path = self.path.join(name);
        let created = match mkdirat(&self.fd, name, PRIVATE_DIRECTORY_MODE) {
            Ok(()) => true,
            Err(nix::errno::Errno::EEXIST) => false,
            Err(error) => return Err(invalid(&path, error)),
        };
        let fd = openat(
            &self.fd,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| invalid(&path, error))?;
        if created {
            fchmod(&fd, PRIVATE_DIRECTORY_MODE).map_err(|error| invalid(&path, error))?;
            if sync == Sync::Durable {
                sync_directory(&self.fd, &self.path)?;
            }
        }
        validate_directory(&fd, &path, true)?;
        Ok(Self { fd, path })
    }

    /// Creates one private child directory, returning `None` when it already exists.
    pub(crate) fn create_dir(&self, name: &str) -> Result<Option<Self>, LibVmError> {
        self.create_dir_with(name, Sync::Durable)
    }

    pub(crate) fn create_dir_deferred(&self, name: &str) -> Result<Option<Self>, LibVmError> {
        self.create_dir_with(name, Sync::Deferred)
    }

    fn create_dir_with(&self, name: &str, sync: Sync) -> Result<Option<Self>, LibVmError> {
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "directory name is not one path component",
            ));
        }
        let path = self.path.join(name);
        match mkdirat(&self.fd, name, PRIVATE_DIRECTORY_MODE) {
            Ok(()) => {}
            Err(nix::errno::Errno::EEXIST) => {
                // Validate an existing entry instead of treating a symlink as a collision.
                let _ = self.open_dir(name)?;
                return Ok(None);
            }
            Err(error) => return Err(invalid(&path, error)),
        };
        let fd = openat(
            &self.fd,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| invalid(&path, error))?;
        fchmod(&fd, PRIVATE_DIRECTORY_MODE).map_err(|error| invalid(&path, error))?;
        validate_directory(&fd, &path, true)?;
        if sync == Sync::Durable {
            sync_directory(&self.fd, &self.path)?;
        }
        Ok(Some(Self { fd, path }))
    }

    pub(crate) fn open_dir(&self, name: &str) -> Result<Option<Self>, LibVmError> {
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "directory name is not one path component",
            ));
        }
        let path = self.path.join(name);
        let fd = match openat(
            &self.fd,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(invalid(&path, error)),
        };
        validate_directory(&fd, &path, true)?;
        Ok(Some(Self { fd, path }))
    }

    /// Opens one private regular file without creating it.
    pub(crate) fn open_file(&self, name: &str) -> Result<Option<File>, LibVmError> {
        self.open_file_modes(name, &[PRIVATE_FILE_MODE])
    }

    /// Immutable cut payload, never a mutable control/configuration record.
    pub(crate) fn open_immutable_file(&self, name: &str) -> Result<Option<File>, LibVmError> {
        self.open_file_modes(name, &[Mode::S_IRUSR])
    }

    /// A sealed capture may be journaled between relocation and chmod. Both
    /// private staging and final read-only modes remain explicit here.
    pub(crate) fn open_capture_payload(&self, name: &str) -> Result<Option<File>, LibVmError> {
        self.open_file_modes(name, &[PRIVATE_FILE_MODE, Mode::S_IRUSR])
    }

    fn open_file_modes(&self, name: &str, modes: &[Mode]) -> Result<Option<File>, LibVmError> {
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "file name is not one path component",
            ));
        }
        let path = self.path.join(name);
        let fd = match openat(
            &self.fd,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(invalid(&path, error)),
        };
        validate_file_modes(&fd, &path, modes)?;
        Ok(Some(File::from(fd)))
    }

    /// Removes one owned child without resolving any path below this directory.
    pub(crate) fn remove_tree(&self, name: &str) -> Result<(), LibVmError> {
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "removal target is not one path component",
            ));
        }
        remove_entry(self.fd.as_raw_fd(), &self.path, std::ffi::OsStr::new(name))
    }

    /// Remove only the admitted open directory, never a reopened mutable root
    /// name. Both admission and final unlink bind the parent entry to this FD.
    pub(crate) fn remove_open_tree(
        &self,
        name: &str,
        verified_child: &OwnedDirectory,
    ) -> Result<(), LibVmError> {
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "removal target is not one path component",
            ));
        }
        let path = self.path.join(name);
        validate_directory(&verified_child.fd, &path, true)?;
        verify_directory_entry(
            self.fd.as_raw_fd(),
            std::ffi::OsStr::new(name),
            &verified_child.fd,
            &path,
        )?;
        remove_directory_contents(&verified_child.fd, &path)?;
        unlink_verified_directory(
            self.fd.as_raw_fd(),
            std::ffi::OsStr::new(name),
            &verified_child.fd,
            &path,
        )
    }

    /// Publishes a complete private file. Interrupted writes remain only in
    /// `.atomic-write`, which callers must exclude from authoritative inventories.
    /// The caller serializes publishers and any abandoned-staging cleanup.
    pub(crate) fn write_file_atomic(&self, name: &str, contents: &[u8]) -> Result<(), LibVmError> {
        self.write_file_atomic_with(name, contents, |_| {})
    }

    pub(crate) fn write_file_atomic_deferred(
        &self,
        name: &str,
        contents: &[u8],
    ) -> Result<(), LibVmError> {
        self.write_file_atomic_sync(name, contents, Sync::Deferred, |_| {})
    }

    pub(crate) fn write_file_atomic_with(
        &self,
        name: &str,
        contents: &[u8],
        checkpoint: impl FnMut(AtomicWritePhase),
    ) -> Result<(), LibVmError> {
        self.write_file_atomic_sync(name, contents, Sync::Durable, checkpoint)
    }

    fn write_file_atomic_sync(
        &self,
        name: &str,
        contents: &[u8],
        sync: Sync,
        mut checkpoint: impl FnMut(AtomicWritePhase),
    ) -> Result<(), LibVmError> {
        if !is_single_component(name) || name == ".atomic-write" {
            return Err(invalid(&self.path.join(name), "invalid publication name"));
        }
        // Refuse non-private/non-regular existing entries before replacement.
        let _existing = self.open_file(name)?;
        let staging = self.ensure_dir_with(".atomic-write", sync)?;
        let temporary = uuid::Uuid::new_v4().to_string();
        let path = staging.path.join(&temporary);
        let fd = openat(
            staging.fd(),
            temporary.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            PRIVATE_FILE_MODE,
        )
        .map_err(|error| invalid(&path, error))?;
        let result = (|| {
            fchmod(&fd, PRIVATE_FILE_MODE).map_err(|error| invalid(&path, error))?;
            validate_file(&fd, &path)?;
            checkpoint(AtomicWritePhase::Staged);
            let mut file = File::from(fd);
            file.write_all(contents)
                .map_err(|error| invalid(&path, error))?;
            if sync == Sync::Durable {
                file.sync_all().map_err(|error| invalid(&path, error))?;
                checkpoint(AtomicWritePhase::Synced);
            }
            nix::fcntl::renameat(staging.fd(), temporary.as_str(), self.fd(), name)
                .map_err(|error| invalid(&self.path.join(name), error))?;
            checkpoint(AtomicWritePhase::Published);
            if sync == Sync::Durable {
                self.sync()?;
                staging.sync()?;
            }
            Ok(())
        })();
        if result.is_err() {
            // Never remove the authoritative name after a successful rename.
            staging.remove_tree(&temporary)?;
        }
        result
    }

    pub(crate) fn write_file(&self, name: &str, contents: &[u8]) -> Result<(), LibVmError> {
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "file name is not one path component",
            ));
        }
        let path = self.path.join(name);
        let flags = OFlag::O_WRONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let (fd, created) = match openat(
            &self.fd,
            name,
            flags | OFlag::O_CREAT | OFlag::O_EXCL,
            PRIVATE_FILE_MODE,
        ) {
            Ok(fd) => (fd, true),
            Err(nix::errno::Errno::EEXIST) => (
                openat(&self.fd, name, flags, Mode::empty())
                    .map_err(|error| invalid(&path, error))?,
                false,
            ),
            Err(error) => return Err(invalid(&path, error)),
        };
        if created {
            fchmod(&fd, PRIVATE_FILE_MODE).map_err(|error| invalid(&path, error))?;
        }
        validate_file(&fd, &path)?;
        ftruncate(&fd, 0).map_err(|error| invalid(&path, error))?;
        let mut file = File::from(fd);
        file.write_all(contents)
            .map_err(|error| invalid(&path, error))?;
        file.sync_all().map_err(|error| invalid(&path, error))?;
        sync_directory(&self.fd, &self.path)
    }
}

fn sync_directory(fd: &OwnedFd, path: &Path) -> Result<(), LibVmError> {
    File::from(fd.try_clone().map_err(|error| invalid(path, error))?)
        .sync_all()
        .map_err(|error| invalid(path, error))
}

fn remove_entry(
    parent_fd: std::os::fd::RawFd,
    parent_path: &Path,
    name: &std::ffi::OsStr,
) -> Result<(), LibVmError> {
    let path = parent_path.join(name);
    let parent_raw_fd = parent_fd;
    let parent_fd = unsafe { BorrowedFd::borrow_raw(parent_raw_fd) };
    let directory = match openat(
        parent_fd,
        Path::new(name),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Some(fd),
        Err(nix::errno::Errno::ENOENT) => return Ok(()),
        Err(nix::errno::Errno::ENOTDIR | nix::errno::Errno::ELOOP) => None,
        Err(error) => return Err(invalid(&path, error)),
    };

    if let Some(directory) = directory {
        remove_directory_contents(&directory, &path)?;
        unlink_verified_directory(parent_raw_fd, name, &directory, &path)
    } else {
        unlink_at(parent_raw_fd, name, 0, &path)
    }
}

fn remove_directory_contents(directory: &OwnedFd, path: &Path) -> Result<(), LibVmError> {
    for child in directory_entries(directory, path)? {
        remove_entry(directory.as_raw_fd(), path, &child)?;
    }
    Ok(())
}

fn verify_directory_entry(
    parent_fd: std::os::fd::RawFd,
    name: &std::ffi::OsStr,
    directory: &OwnedFd,
    path: &Path,
) -> Result<(), LibVmError> {
    let parent = unsafe { BorrowedFd::borrow_raw(parent_fd) };
    let held = fstat(directory).map_err(|error| invalid(path, error))?;
    let entry = fstatat(parent, Path::new(name), AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| invalid(path, error))?;
    if SFlag::from_bits_truncate(entry.st_mode) != SFlag::S_IFDIR
        || entry.st_dev != held.st_dev
        || entry.st_ino != held.st_ino
    {
        return Err(invalid(
            path,
            "directory entry no longer names the admitted open inode",
        ));
    }
    Ok(())
}

fn unlink_verified_directory(
    parent_fd: std::os::fd::RawFd,
    name: &std::ffi::OsStr,
    directory: &OwnedFd,
    path: &Path,
) -> Result<(), LibVmError> {
    verify_directory_entry(parent_fd, name, directory, path)?;
    let parent = unsafe { BorrowedFd::borrow_raw(parent_fd) };
    unlinkat(parent, Path::new(name), UnlinkatFlags::RemoveDir)
        .map_err(|error| invalid(path, error))
}

fn directory_entries(fd: &OwnedFd, path: &Path) -> Result<Vec<OsString>, LibVmError> {
    // A dup shares both the cursor and filesystem-specific enumeration state.
    // Btrfs bounds a stream at open time, so reopen "." through the held inode
    // to see current entries without resolving the replaceable pathname.
    let mut directory = nix::dir::Dir::openat(
        fd,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| invalid(path, error))?;
    let mut entries = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(|error| invalid(path, error))?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            entries.push(OsString::from_vec(name.to_vec()));
        }
    }
    Ok(entries)
}

fn unlink_at(
    parent_fd: std::os::fd::RawFd,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    path: &Path,
) -> Result<(), LibVmError> {
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| invalid(path, "path component contains a NUL byte"))?;
    let result = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), flags) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        return Ok(());
    }
    Err(invalid(path, error))
}

fn open_directory(path: &Path) -> Result<OwnedFd, LibVmError> {
    open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| invalid(path, error))
}

fn validate_directory(fd: &OwnedFd, path: &Path, require_private: bool) -> Result<(), LibVmError> {
    let stat = fstat(fd).map_err(|error| invalid(path, error))?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR {
        return Err(invalid(path, "is not a directory"));
    }
    let expected_uid = geteuid().as_raw();
    if stat.st_uid != expected_uid {
        return Err(invalid(
            path,
            format!(
                "is owned by uid {}, expected effective uid {expected_uid}",
                stat.st_uid
            ),
        ));
    }
    let mode = Mode::from_bits_retain(stat.st_mode & 0o7777);
    if require_private && mode != PRIVATE_DIRECTORY_MODE {
        return Err(invalid(
            path,
            format!("has mode {mode:o}, expected {PRIVATE_DIRECTORY_MODE:o}"),
        ));
    }
    if !require_private && mode.intersects(Mode::S_IWGRP | Mode::S_IWOTH) {
        return Err(invalid(
            path,
            format!("has group or other write permissions in mode {mode:o}"),
        ));
    }
    Ok(())
}

fn validate_file(fd: &OwnedFd, path: &Path) -> Result<(), LibVmError> {
    validate_file_modes(fd, path, &[PRIVATE_FILE_MODE])
}

fn validate_file_modes(fd: &OwnedFd, path: &Path, modes: &[Mode]) -> Result<(), LibVmError> {
    let stat = fstat(fd).map_err(|error| invalid(path, error))?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
        return Err(invalid(path, "is not a regular file"));
    }
    let expected_uid = geteuid().as_raw();
    if stat.st_uid != expected_uid {
        return Err(invalid(
            path,
            format!(
                "is owned by uid {}, expected effective uid {expected_uid}",
                stat.st_uid
            ),
        ));
    }
    let mode = Mode::from_bits_retain(stat.st_mode & 0o7777);
    if !modes.contains(&mode) {
        return Err(invalid(
            path,
            format!("has mode {mode:o}, not an admitted private file mode"),
        ));
    }
    Ok(())
}

fn is_single_component(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn invalid(path: &Path, message: impl std::fmt::Display) -> LibVmError {
    LibVmError::InvalidOwnedPath {
        path: path.to_path_buf(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use crate::paths::OwnedDirectory;

    #[test]
    fn deferred_root_preserves_private_directory_validation() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("parent").join("owned");
        let directory = OwnedDirectory::open_root_deferred(&path).unwrap();
        assert_eq!(directory.path(), path);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        drop(directory);
        OwnedDirectory::open_root_deferred(&path).unwrap();
        let target = temporary.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = temporary.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(OwnedDirectory::open_root_deferred(&link).is_err());
        let file = temporary.path().join("file");
        std::fs::write(&file, b"not a directory").unwrap();
        assert!(OwnedDirectory::open_root_deferred(&file).is_err());
    }

    #[test]
    fn deferred_publication_keeps_atomicity_and_validation_without_sync_phase() {
        use crate::paths::owned::{AtomicWritePhase, Sync};
        let temporary = tempfile::tempdir().unwrap();
        let root = OwnedDirectory::open_root(&temporary.path().join("owned")).unwrap();
        let directory = root.ensure_dir_deferred("cut").unwrap();
        let mut phases = Vec::new();
        directory
            .write_file_atomic_sync("receipt", b"closed", Sync::Deferred, |phase| {
                phases.push(phase)
            })
            .unwrap();
        assert_eq!(
            phases,
            [AtomicWritePhase::Staged, AtomicWritePhase::Published]
        );
        assert_eq!(
            std::fs::read(directory.path().join("receipt")).unwrap(),
            b"closed"
        );
        directory
            .write_file_atomic_deferred("receipt", b"replacement")
            .unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("receipt")).unwrap(),
            b"replacement"
        );
        assert!(root.ensure_dir_deferred("../escape").is_err());
        assert!(directory
            .write_file_atomic_deferred("../escape", b"bad")
            .is_err());
        let target = temporary.path().join("target");
        std::fs::write(&target, b"safe").unwrap();
        symlink(&target, directory.path().join("symlink")).unwrap();
        assert!(directory
            .write_file_atomic_deferred("symlink", b"bad")
            .is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"safe");
    }

    #[test]
    fn immutable_cut_payload_modes_do_not_weaken_private_control_file_checks() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = OwnedDirectory::open_root(&temporary.path().join("owned")).unwrap();
        directory.write_file("payload", b"sealed").unwrap();
        assert!(directory.open_file("payload").unwrap().is_some());
        assert!(directory.open_immutable_file("payload").is_err());
        let path = directory.path().join("payload");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(directory.open_immutable_file("payload").unwrap().is_some());
        assert!(
            directory.open_file("payload").is_err(),
            "mutable control APIs still require exactly 0600"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(directory.open_immutable_file("payload").is_err());
        assert!(directory.open_file("payload").is_err());
    }

    #[test]
    fn owned_directories_are_private_and_descriptor_relative() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let root_path = temp.path().join("state");
        let root = OwnedDirectory::open_root(&root_path).expect("create owned root");
        let duplicate = root.duplicate_inheritable().expect("duplicate directory");
        let flags = nix::fcntl::fcntl(&duplicate, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert!(
            nix::fcntl::FdFlag::from_bits_retain(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC)
        );
        let logs = root.ensure_dir("logs").expect("create logs directory");
        let machine = logs
            .ensure_dir("machine-id")
            .expect("create machine directory");

        assert_eq!(
            std::fs::metadata(root_path.join("logs/machine-id"))
                .expect("machine directory metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert!(machine.ensure_dir("../escape").is_err());
        machine
            .write_file("policy.json", b"first")
            .expect("create private file");
        machine
            .write_file("policy.json", b"second")
            .expect("replace private file");
        assert_eq!(
            std::fs::read(root_path.join("logs/machine-id/policy.json"))
                .expect("read private file"),
            b"second"
        );
    }

    #[test]
    fn owned_directories_reject_unsafe_existing_objects() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let root = OwnedDirectory::open_root(&temp.path().join("state")).expect("create root");

        let unsafe_dir = temp.path().join("state/unsafe");
        std::fs::create_dir(&unsafe_dir).expect("create unsafe directory");
        std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o755))
            .expect("set unsafe mode");
        assert!(root.ensure_dir("unsafe").is_err());

        let target = temp.path().join("target");
        std::fs::create_dir(&target).expect("create symlink target");
        symlink(&target, temp.path().join("state/link")).expect("create symlink");
        assert!(root.ensure_dir("link").is_err());

        std::fs::write(temp.path().join("state/file"), b"not a directory")
            .expect("create regular file");
        assert!(root.ensure_dir("file").is_err());

        let private = root
            .ensure_dir("private")
            .expect("create private directory");
        let unsafe_file = temp.path().join("state/private/unsafe.json");
        std::fs::write(&unsafe_file, b"unsafe").expect("create unsafe file");
        std::fs::set_permissions(&unsafe_file, std::fs::Permissions::from_mode(0o644))
            .expect("set unsafe file mode");
        assert!(private.write_file("unsafe.json", b"replacement").is_err());
        assert_eq!(
            std::fs::read(&unsafe_file).expect("read unsafe file"),
            b"unsafe"
        );
    }

    #[test]
    fn recursive_removal_unlinks_external_symlinks_without_following_them() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let external = temp.path().join("external-sentinel");
        std::fs::create_dir(&external).expect("create external sentinel");
        std::fs::write(external.join("keep"), b"safe").expect("write external sentinel");

        let root = OwnedDirectory::open_root(&temp.path().join("state")).expect("create root");
        let machine = root
            .ensure_dir("machines")
            .expect("create machines")
            .ensure_dir("machine-id")
            .expect("create machine");
        symlink(
            &external,
            temp.path().join("state/machines/machine-id/escape"),
        )
        .expect("create external symlink");

        root.open_dir("machines")
            .expect("open machines")
            .expect("machines exists")
            .remove_tree("machine-id")
            .expect("remove machine tree");
        assert!(!machine.path.exists());
        assert_eq!(
            std::fs::read(external.join("keep")).expect("read external sentinel"),
            b"safe"
        );
    }

    #[test]
    fn remove_open_tree_rejects_name_replacement_after_directory_admission() {
        let temp = tempfile::tempdir().unwrap();
        let parent = OwnedDirectory::open_root(&temp.path().join("owned")).unwrap();
        let admitted = parent.create_dir("candidate").unwrap().unwrap();
        admitted.write_file("original", b"owned original").unwrap();
        let moved = parent.path().join("moved");
        std::fs::rename(admitted.path(), &moved).unwrap();
        let replacement = parent.create_dir("candidate").unwrap().unwrap();
        replacement.write_file("keep", b"not admitted").unwrap();
        assert!(parent.remove_open_tree("candidate", &admitted).is_err());
        assert_eq!(
            std::fs::read(moved.join("original")).unwrap(),
            b"owned original"
        );
        assert_eq!(
            std::fs::read(replacement.path().join("keep")).unwrap(),
            b"not admitted"
        );
    }

    #[test]
    fn repeated_removal_refreshes_the_retained_directory_stream() {
        use crate::paths::owned::remove_directory_contents;

        let temp = tempfile::tempdir().unwrap();
        let root = OwnedDirectory::open_root(&temp.path().join("owned")).unwrap();
        root.write_file("first", b"first generation").unwrap();
        remove_directory_contents(root.fd(), root.path()).unwrap();
        assert!(!root.path().join("first").exists());

        root.write_file("second", b"second generation").unwrap();
        remove_directory_contents(root.fd(), root.path()).unwrap();
        assert!(!root.path().join("second").exists());
    }

    #[test]
    fn open_directory_traversal_cannot_switch_to_a_replacement_root() {
        use crate::paths::owned::{
            remove_directory_contents, unlink_verified_directory, verify_directory_entry,
        };
        use std::os::fd::AsRawFd;
        let temp = tempfile::tempdir().unwrap();
        let parent = OwnedDirectory::open_root(&temp.path().join("owned")).unwrap();
        let admitted = parent.create_dir("candidate").unwrap().unwrap();
        admitted.write_file("original", b"owned original").unwrap();
        let name = std::ffi::OsStr::new("candidate");
        verify_directory_entry(
            parent.fd().as_raw_fd(),
            name,
            admitted.fd(),
            admitted.path(),
        )
        .unwrap();
        // Rename precisely after entry validation, before recursive traversal.
        let moved = parent.path().join("moved");
        std::fs::rename(admitted.path(), &moved).unwrap();
        let replacement = parent.create_dir("candidate").unwrap().unwrap();
        replacement.write_file("keep", b"not admitted").unwrap();
        remove_directory_contents(admitted.fd(), admitted.path()).unwrap();
        assert!(!moved.join("original").exists());
        assert_eq!(
            std::fs::read(replacement.path().join("keep")).unwrap(),
            b"not admitted"
        );
        assert!(unlink_verified_directory(
            parent.fd().as_raw_fd(),
            name,
            admitted.fd(),
            admitted.path()
        )
        .is_err());
        assert!(replacement.path().is_dir());
    }

    #[test]
    fn verified_directory_unlink_rejects_empty_replacement_after_traversal() {
        use crate::paths::owned::{remove_directory_contents, unlink_verified_directory};
        use std::os::fd::AsRawFd;
        let temp = tempfile::tempdir().unwrap();
        let parent = OwnedDirectory::open_root(&temp.path().join("owned")).unwrap();
        let admitted = parent.create_dir("candidate").unwrap().unwrap();
        admitted.write_file("original", b"owned original").unwrap();
        remove_directory_contents(admitted.fd(), admitted.path()).unwrap();
        let moved = parent.path().join("moved");
        std::fs::rename(admitted.path(), &moved).unwrap();
        let replacement = parent.create_dir("candidate").unwrap().unwrap();
        // Empty is deliberate: an unchecked rmdir would remove this inode.
        assert!(unlink_verified_directory(
            parent.fd().as_raw_fd(),
            std::ffi::OsStr::new("candidate"),
            admitted.fd(),
            admitted.path()
        )
        .is_err());
        assert!(replacement.path().is_dir());
        assert!(moved.is_dir());
    }
    #[test]
    fn deferred_directory_creation_keeps_collision_and_symlink_checks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let root = OwnedDirectory::open_root(&temp.path().join("root")).unwrap();
        let child = root.create_dir_deferred("child").unwrap().unwrap();
        assert_eq!(
            std::fs::metadata(child.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert!(root.create_dir_deferred("child").unwrap().is_none());
        symlink(child.path(), root.path().join("alias")).unwrap();
        assert!(root.create_dir_deferred("alias").is_err());
    }
}
