use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use thiserror::Error;
use utils::format_storage_size;

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
        "refusing to shrink raw disk {path} from {} to {}",
        format_storage_size(*current_size),
        format_storage_size(*requested_size)
    )]
    RawDiskShrinkUnsupported {
        path: PathBuf,
        current_size: u64,
        requested_size: u64,
    },

    #[error("failed to grow ext4 filesystem in {path}")]
    Ext4 {
        path: PathBuf,
        #[source]
        source: ext4::error::ResizeError,
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
    let mut file = File::options().read(true).write(true).open(path)?;
    let current_size = file.metadata()?.len();
    if size_bytes < current_size {
        return Err(RootDiskError::RawDiskShrinkUnsupported {
            path: path.to_path_buf(),
            current_size,
            requested_size: size_bytes,
        });
    }

    let is_ext4 = has_ext4_superblock(&mut file)?;
    drop(file);

    if is_ext4 {
        let filesystem_size = size_bytes - size_bytes % 4096;
        match ext4::grow_image(path, filesystem_size) {
            Ok(_) => {}
            Err(err) if err.can_fallback_online() => {}
            Err(source) => {
                return Err(RootDiskError::Ext4 {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }

    File::options()
        .write(true)
        .open(path)?
        .set_len(size_bytes)?;
    Ok(())
}

fn has_ext4_superblock(file: &mut File) -> io::Result<bool> {
    const MAGIC_OFFSET: u64 = ext4::constants::SUPERBLOCK_OFFSET + 0x38;

    file.seek(SeekFrom::Start(MAGIC_OFFSET))?;
    let mut magic = [0u8; 2];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(u16::from_le_bytes(magic) == ext4::constants::SUPERBLOCK_MAGIC),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
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
    use std::io::{Read, Seek, SeekFrom, Write};

    use crate::machine::root_disk::{clone_or_copy_root_disk, resize_raw_disk, RootDiskError};

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
        ext4::Formatter::new(&path, 4096, 256 * 1024)
            .expect("create ext4 image")
            .close()
            .expect("finish ext4 image");
        let old_size = fs::metadata(&path).expect("metadata").len();
        let new_size = old_size + 128 * 1024 * 1024;

        resize_raw_disk(&path, new_size).expect("resize disk");

        assert_eq!(fs::metadata(&path).expect("metadata").len(), new_size);
        let reader = ext4::Reader::new(&path).expect("open grown ext4 image");
        assert_eq!(reader.superblock().blocks_count_lo as u64 * 4096, new_size);
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
    fn resize_raw_disk_does_not_extend_ext4_after_fatal_validation_error() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        ext4::Formatter::new(&path, 4096, 256 * 1024)
            .expect("create ext4 image")
            .close()
            .expect("finish ext4 image");
        let old_size = fs::metadata(&path).expect("metadata").len();
        let too_large = (u32::MAX as u64 + 1) * 4096;

        let error = resize_raw_disk(&path, too_large).expect_err("reject oversized ext4");

        assert!(matches!(
            error,
            RootDiskError::Ext4 {
                source: ext4::error::ResizeError::TooLarge { .. },
                ..
            }
        ));
        assert_eq!(fs::metadata(&path).expect("metadata").len(), old_size);
    }

    #[test]
    fn resize_raw_disk_defers_non_ext4_filesystem_to_guest() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        fs::write(&path, b"not ext4").expect("write disk");

        resize_raw_disk(&path, 4096).expect("extend non-ext4 disk");

        assert_eq!(fs::metadata(&path).expect("metadata").len(), 4096);
        assert_eq!(&fs::read(&path).expect("read disk")[..8], b"not ext4");
    }

    #[test]
    fn resize_raw_disk_leaves_dirty_filesystem_for_online_recovery() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        ext4::Formatter::new(&path, 4096, 256 * 1024)
            .expect("create ext4 image")
            .close()
            .expect("finish ext4 image");
        let old_size = fs::metadata(&path).expect("metadata").len();
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open image");
        let mut superblock = [0u8; 1024];
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.read_exact(&mut superblock).expect("read superblock");
        let incompat = u32::from_le_bytes(superblock[0x60..0x64].try_into().unwrap());
        superblock[0x60..0x64].copy_from_slice(&(incompat | 0x4).to_le_bytes());
        file.seek(SeekFrom::Start(1024)).expect("seek superblock");
        file.write_all(&superblock).expect("write superblock");
        drop(file);
        let new_size = old_size + 128 * 1024 * 1024;

        resize_raw_disk(&path, new_size).expect("defer resize to guest");

        assert_eq!(fs::metadata(&path).expect("metadata").len(), new_size);
        let reader = ext4::Reader::new(&path).expect("open unchanged ext4 image");
        assert_eq!(reader.superblock().blocks_count_lo as u64 * 4096, old_size);
        assert_ne!(reader.superblock().feature_incompat & 0x4, 0);
    }
}
