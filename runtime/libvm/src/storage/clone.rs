//! Whole-file clone primitives shared by private disks and RAM publication.

use std::io;

pub(crate) fn clone_error_allows_fallback(error: &io::Error, valid_whole_file: bool) -> bool {
    let Some(errno) = error.raw_os_error() else {
        return false;
    };
    if errno == libc::EOPNOTSUPP || errno == libc::ENOTSUP || errno == libc::EXDEV {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        errno == libc::ENOTTY || (errno == libc::EINVAL && valid_whole_file)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = valid_whole_file;
        errno == libc::ENOSYS
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn try_reflink(source: &std::fs::File, destination: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    const FICLONE: libc::c_ulong = 0x4004_9409;

    // nix does not expose a safe wrapper for the Linux FICLONE ioctl.
    // SAFETY: ioctl only reads the source file descriptor value and applies it
    // to the destination fd for the duration of this call.
    let rc = unsafe { libc::ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
