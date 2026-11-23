//! Preflight required switch-root destinations before moving any mount.
//! Static no_std init uses libc because nix requires the std runtime.

pub fn prepare_mount_destinations(root: i32) -> Result<(), &'static str> {
    for name in [b"dev\0".as_slice(), b"proc\0", b"sys\0", b"run\0"] {
        if unsafe { libc::mkdirat(root, name.as_ptr().cast(), 0o755) } != 0 {
            // EEXIST is not sufficient: openat below rejects files and symlinks.
            if unsafe { *libc::__errno_location() } != libc::EEXIST {
                return Err("failed to create required mount destination");
            }
        }
        let fd = unsafe {
            libc::openat(
                root,
                name.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("required mount destination must be a real directory");
        }
        if unsafe { libc::close(fd) } != 0 {
            return Err("failed to close required mount destination");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use crate::handoff::prepare_mount_destinations;
    use std::{fs, os::fd::AsRawFd, os::unix::fs::symlink};

    #[test]
    fn required_mount_destinations_reject_image_symlinks_and_files() {
        let directory = std::env::temp_dir().join(std::format!(
            "silo-init-move-targets-{}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let root = fs::File::open(&directory).unwrap();
        symlink("/tmp", directory.join("run")).unwrap();
        assert!(prepare_mount_destinations(root.as_raw_fd()).is_err());
        assert!(fs::symlink_metadata(directory.join("run"))
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_file(directory.join("run")).unwrap();
        fs::write(directory.join("run"), b"not a directory").unwrap();
        assert!(prepare_mount_destinations(root.as_raw_fd()).is_err());
        fs::remove_file(directory.join("run")).unwrap();
        assert!(prepare_mount_destinations(root.as_raw_fd()).is_ok());
        for name in ["dev", "proc", "sys", "run"] {
            assert!(directory.join(name).is_dir());
        }
        drop(root);
        fs::remove_dir_all(directory).unwrap();
    }
}
