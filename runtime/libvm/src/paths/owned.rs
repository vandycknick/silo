use std::ffi::{CStr, OsString};
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

use nix::fcntl::{fcntl, open, openat, FcntlArg, OFlag};
use nix::sys::stat::{fchmod, fstat, mkdirat, Mode, SFlag};
use nix::unistd::{ftruncate, geteuid};

use crate::LibVmError;

const PRIVATE_DIRECTORY_MODE: u16 = 0o700;
const PRIVATE_FILE_MODE: u16 = 0o600;

pub(crate) struct OwnedDirectory {
    fd: OwnedFd,
    path: PathBuf,
}

impl OwnedDirectory {
    /// Duplicates this validated directory for inheritance by one child process.
    pub(crate) fn duplicate_inheritable(&self) -> Result<OwnedFd, LibVmError> {
        let fd =
            fcntl(&self.fd, FcntlArg::F_DUPFD(3)).map_err(|error| invalid(&self.path, error))?;
        // F_DUPFD returns a newly owned descriptor without FD_CLOEXEC.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub(crate) fn open_root(path: &Path) -> Result<Self, LibVmError> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid(path, "has no parent directory"))?;
        fs::create_dir_all(parent).map_err(|error| invalid(path, error))?;

        let created = match fs::DirBuilder::new()
            .mode(u32::from(PRIVATE_DIRECTORY_MODE))
            .create(path)
        {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(invalid(path, error)),
        };
        let fd = open_directory(path)?;
        if created {
            fchmod(&fd, Mode::from_bits_retain(PRIVATE_DIRECTORY_MODE))
                .map_err(|error| invalid(path, error))?;
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
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "directory name is not one path component",
            ));
        }
        let path = self.path.join(name);
        let created = match mkdirat(
            &self.fd,
            name,
            Mode::from_bits_retain(PRIVATE_DIRECTORY_MODE),
        ) {
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
            fchmod(&fd, Mode::from_bits_retain(PRIVATE_DIRECTORY_MODE))
                .map_err(|error| invalid(&path, error))?;
        }
        validate_directory(&fd, &path, true)?;
        Ok(Self { fd, path })
    }

    /// Creates one private child directory, returning `None` when it already exists.
    pub(crate) fn create_dir(&self, name: &str) -> Result<Option<Self>, LibVmError> {
        if !is_single_component(name) {
            return Err(invalid(
                &self.path.join(name),
                "directory name is not one path component",
            ));
        }
        let path = self.path.join(name);
        match mkdirat(
            &self.fd,
            name,
            Mode::from_bits_retain(PRIVATE_DIRECTORY_MODE),
        ) {
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
        fchmod(&fd, Mode::from_bits_retain(PRIVATE_DIRECTORY_MODE))
            .map_err(|error| invalid(&path, error))?;
        validate_directory(&fd, &path, true)?;
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
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(invalid(&path, error)),
        };
        validate_file(&fd, &path)?;
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
            Mode::from_bits_retain(PRIVATE_FILE_MODE),
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
            fchmod(&fd, Mode::from_bits_retain(PRIVATE_FILE_MODE))
                .map_err(|error| invalid(&path, error))?;
        }
        validate_file(&fd, &path)?;
        ftruncate(&fd, 0).map_err(|error| invalid(&path, error))?;
        let mut file = File::from(fd);
        file.write_all(contents)
            .map_err(|error| invalid(&path, error))?;
        file.sync_all().map_err(|error| invalid(&path, error))
    }
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
        for child in directory_entries(&directory, &path)? {
            remove_entry(directory.as_raw_fd(), &path, &child)?;
        }
        unlink_at(parent_raw_fd, name, libc::AT_REMOVEDIR, &path)
    } else {
        unlink_at(parent_raw_fd, name, 0, &path)
    }
}

fn directory_entries(fd: &OwnedFd, path: &Path) -> Result<Vec<OsString>, LibVmError> {
    // nix does not expose a descriptor-relative directory iterator. fdopendir
    // lets us enumerate the already validated descriptor without reopening it.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(invalid(path, std::io::Error::last_os_error()));
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let error = std::io::Error::last_os_error();
        let _ = unsafe { libc::close(duplicate) };
        return Err(invalid(path, error));
    }

    let mut entries = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            let close_result = unsafe { libc::closedir(directory) };
            if error.raw_os_error() != Some(0) {
                return Err(invalid(path, error));
            }
            if close_result != 0 {
                return Err(invalid(path, std::io::Error::last_os_error()));
            }
            return Ok(entries);
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            entries.push(OsString::from_vec(name.to_vec()));
        }
    }
}

fn clear_errno() {
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = 0;
    }
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
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
    let mode = stat.st_mode & 0o7777;
    if require_private && mode != PRIVATE_DIRECTORY_MODE {
        return Err(invalid(
            path,
            format!("has mode {mode:o}, expected {PRIVATE_DIRECTORY_MODE:o}"),
        ));
    }
    if !require_private && mode & 0o022 != 0 {
        return Err(invalid(
            path,
            format!("has group or other write permissions in mode {mode:o}"),
        ));
    }
    Ok(())
}

fn validate_file(fd: &OwnedFd, path: &Path) -> Result<(), LibVmError> {
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
    let mode = stat.st_mode & 0o7777;
    if mode != PRIVATE_FILE_MODE {
        return Err(invalid(
            path,
            format!("has mode {mode:o}, expected {PRIVATE_FILE_MODE:o}"),
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
    fn owned_directories_are_private_and_descriptor_relative() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let root_path = temp.path().join("state");
        let root = OwnedDirectory::open_root(&root_path).expect("create owned root");
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
}
