use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloneDiskMethod {
    #[cfg(target_os = "macos")]
    Clonefile,
    #[cfg(target_os = "linux")]
    Reflink,
    Copy,
}

#[derive(Debug, Error)]
pub(crate) enum RootDiskError {
    #[error("base rootfs {path} does not exist")]
    BaseRootfsNotFound { path: PathBuf },

    #[error("base rootfs {path} is not a regular file")]
    BaseRootfsNotFile { path: PathBuf },

    #[error(
        "refusing to shrink raw disk {path} from {current_size} bytes to {requested_size} bytes"
    )]
    RawDiskShrinkUnsupported {
        path: PathBuf,
        current_size: u64,
        requested_size: u64,
    },

    #[error("I/O failure")]
    Io(#[from] io::Error),
}

pub(crate) fn clone_or_copy_root_disk(
    source: &Path,
    destination: &Path,
) -> Result<CloneDiskMethod, RootDiskError> {
    validate_base_rootfs(source)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(target_os = "macos")]
    {
        if try_clonefile(source, destination).is_ok() {
            return Ok(CloneDiskMethod::Clonefile);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if try_reflink(source, destination).is_ok() {
            return Ok(CloneDiskMethod::Reflink);
        }
    }

    fs::copy(source, destination)?;
    Ok(CloneDiskMethod::Copy)
}

pub(crate) fn resize_raw_disk(path: &Path, size_bytes: u64) -> Result<(), RootDiskError> {
    let file = File::options().write(true).open(path)?;
    let current_size = file.metadata()?.len();
    if size_bytes < current_size {
        return Err(RootDiskError::RawDiskShrinkUnsupported {
            path: path.to_path_buf(),
            current_size,
            requested_size: size_bytes,
        });
    }

    file.set_len(size_bytes)?;
    Ok(())
}

fn validate_base_rootfs(path: &Path) -> Result<(), RootDiskError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(RootDiskError::BaseRootfsNotFile {
            path: path.to_path_buf(),
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Err(RootDiskError::BaseRootfsNotFound {
                path: path.to_path_buf(),
            })
        }
        Err(err) => Err(RootDiskError::Io(err)),
    }
}

#[cfg(target_os = "macos")]
fn try_clonefile(source: &Path, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid source path"))?;
    let dst = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid destination path"))?;

    // nix does not expose macOS clonefile(2), so call libc directly.
    // SAFETY: clonefile only reads these NUL-terminated paths during the call.
    let rc = unsafe { libc::clonefile(src.as_ptr(), dst.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn try_reflink(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    const FICLONE: libc::c_ulong = 0x4004_9409;

    let source = File::open(source)?;
    let destination_file = File::options()
        .write(true)
        .create_new(true)
        .open(destination)?;

    // nix does not expose a safe wrapper for the Linux FICLONE ioctl.
    // SAFETY: ioctl only reads the source file descriptor value and applies it
    // to the destination fd for the duration of this call.
    let rc = unsafe { libc::ioctl(destination_file.as_raw_fd(), FICLONE, source.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        drop(destination_file);
        let _ = fs::remove_file(destination);
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::root_disk::{clone_or_copy_root_disk, resize_raw_disk, RootDiskError};

    #[test]
    fn clone_or_copy_root_disk_copies_contents() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let source = temp.path().join("base.ext4");
        let destination = temp.path().join("instance/rootfs.img");
        fs::write(&source, b"disk").expect("write source");

        clone_or_copy_root_disk(&source, &destination).expect("clone or copy root disk");

        assert_eq!(fs::read(destination).expect("read destination"), b"disk");
    }

    #[test]
    fn clone_or_copy_root_disk_rejects_missing_source() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let err = clone_or_copy_root_disk(
            &temp.path().join("missing.ext4"),
            &temp.path().join("rootfs.img"),
        )
        .expect_err("missing source should fail");

        assert!(matches!(err, RootDiskError::BaseRootfsNotFound { .. }));
    }

    #[test]
    fn resize_raw_disk_grows_sparse_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        fs::write(&path, b"disk").expect("write disk");

        resize_raw_disk(&path, 1024).expect("resize disk");

        assert_eq!(fs::metadata(path).expect("metadata").len(), 1024);
    }

    #[test]
    fn resize_raw_disk_refuses_shrink() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        fs::write(&path, b"disk").expect("write disk");

        let err = resize_raw_disk(&path, 1).expect_err("shrink should fail");

        assert!(matches!(
            err,
            RootDiskError::RawDiskShrinkUnsupported { .. }
        ));
    }

    #[test]
    fn libvm_manifest_keeps_registry_and_ext4_out() {
        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let manifest = fs::read_to_string(manifest_path).expect("read manifest");

        for dependency in [
            "bento-ext4",
            "containerregistry-image",
            "containerregistry-registry",
        ] {
            assert!(
                !manifest.contains(dependency),
                "bento-libvm must not depend on {dependency}"
            );
        }
    }
}
