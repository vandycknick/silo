use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::libc;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

/// First descriptor number of the worker contract; roles follow in order.
pub(crate) const FIRST_CHILD_FD: libc::c_int = 3;
const MAX_CHILD_FDS: usize = 5;

/// Map `descriptors` onto the child's fixed numbers 3, 4, ... in order and let
/// nothing else survive exec.
///
/// ```text
/// parent fds (any numbers)      child after exec
///   descriptors[0] ──────────►  3
///   descriptors[1] ──────────►  4
///   ...                         ...
///   everything else ─ CLOEXEC ► closed
/// ```
pub(crate) fn install(command: &mut Command, descriptors: &[&OwnedFd]) {
    let count = descriptors.len();
    let mut sources = [-1; MAX_CHILD_FDS];
    for (slot, fd) in sources.iter_mut().zip(descriptors) {
        *slot = fd.as_raw_fd();
    }
    // Raw libc, not nix: nix's descriptor wrappers need borrowed fds that cannot
    // be constructed soundly from this pre-fork number array.
    // SAFETY: child setup uses only raw OS descriptor operations on a fixed-size
    // stack array. OS errors are represented inline by from_raw_os_error, so this
    // path neither allocates nor takes locks.
    unsafe {
        command.pre_exec(move || {
            if count > MAX_CHILD_FDS {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            mark_child_fds_cloexec()?;
            // Park every source above the target range first: a source may
            // already occupy another role's target number.
            let floor = FIRST_CHILD_FD + count as libc::c_int;
            let mut parked = [-1; MAX_CHILD_FDS];
            for index in 0..count {
                let high = libc::fcntl(sources[index], libc::F_DUPFD_CLOEXEC, floor);
                if high < 0 {
                    return Err(child_last_os_error());
                }
                parked[index] = high;
            }
            // dup2 clears FD_CLOEXEC on the target; the parked copies close at exec.
            for (index, high) in parked.iter().copied().enumerate().take(count) {
                if libc::dup2(high, FIRST_CHILD_FD + index as libc::c_int) < 0 {
                    return Err(child_last_os_error());
                }
            }
            Ok(())
        });
    }
}

pub(crate) fn normalize(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        let mut flags = FdFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFD)?);
        flags.insert(FdFlag::FD_CLOEXEC);
        fcntl(&fd, FcntlArg::F_SETFD(flags))?;
        return Ok(fd);
    }
    let duplicated = fcntl(&fd, FcntlArg::F_DUPFD_CLOEXEC(3))?;
    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(target_os = "linux")]
fn mark_child_fds_cloexec() -> io::Result<()> {
    // nix has no close_range CLOEXEC operation for this post-fork allowlist.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result < 0 {
        return Err(child_last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn mark_child_fds_cloexec() -> io::Result<()> {
    const SYS_GETDIRENTRIES64: libc::c_int = 344;
    // nix has no allocation-free Darwin directory iterator suitable after fork.
    let directory = unsafe {
        libc::open(
            c"/dev/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if directory < 0 {
        return Err(child_last_os_error());
    }

    let mut storage = [0_usize; 512];
    let mut base = 0_i64;
    loop {
        // Darwin exposes getdirentries64 as syscall 344 in the public SDK.
        // syscall, open, close, and fcntl are allocation-free after fork.
        let count = unsafe {
            libc::syscall(
                SYS_GETDIRENTRIES64,
                directory,
                storage.as_mut_ptr(),
                std::mem::size_of_val(&storage),
                &mut base,
            )
        };
        if count < 0 {
            let error = child_last_os_error();
            unsafe { libc::close(directory) };
            return Err(error);
        }
        if count == 0 {
            break;
        }
        if count as usize > std::mem::size_of_val(&storage) {
            unsafe { libc::close(directory) };
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), count as usize) };
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let (record_len, fd) = match parse_darwin_fd_record(&bytes[offset..]) {
                Ok(record) => record,
                Err(()) => {
                    unsafe { libc::close(directory) };
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
            };
            if let Some(fd) = fd.filter(|fd| *fd >= 3) {
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if flags < 0 {
                    if child_errno() == libc::EBADF {
                        offset = match offset.checked_add(record_len) {
                            Some(offset) => offset,
                            None => {
                                unsafe { libc::close(directory) };
                                return Err(io::Error::from_raw_os_error(libc::EIO));
                            }
                        };
                        continue;
                    }
                    let error = child_last_os_error();
                    unsafe { libc::close(directory) };
                    return Err(error);
                }
                if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
                    let error = child_last_os_error();
                    unsafe { libc::close(directory) };
                    return Err(error);
                }
            }
            offset = match offset.checked_add(record_len) {
                Some(offset) => offset,
                None => {
                    unsafe { libc::close(directory) };
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
            };
        }
    }
    if unsafe { libc::close(directory) } < 0 {
        return Err(child_last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn parse_darwin_fd_record(bytes: &[u8]) -> std::result::Result<(usize, Option<i32>), ()> {
    const RECLEN_OFFSET: usize = std::mem::offset_of!(libc::dirent, d_reclen);
    const NAMLEN_OFFSET: usize = std::mem::offset_of!(libc::dirent, d_namlen);
    const NAME_OFFSET: usize = std::mem::offset_of!(libc::dirent, d_name);
    const NAME_CAPACITY: usize = std::mem::size_of::<[libc::c_char; 1024]>();

    if bytes.len() < NAME_OFFSET {
        return Err(());
    }
    let record_len = usize::from(unsafe {
        std::ptr::read_unaligned(bytes.as_ptr().add(RECLEN_OFFSET).cast::<u16>())
    });
    if record_len < NAME_OFFSET || record_len > bytes.len() {
        return Err(());
    }
    let name_len = usize::from(unsafe {
        std::ptr::read_unaligned(bytes.as_ptr().add(NAMLEN_OFFSET).cast::<u16>())
    });
    let name_end = NAME_OFFSET.checked_add(name_len).ok_or(())?;
    if name_len > NAME_CAPACITY || name_end > record_len {
        return Err(());
    }
    let name = bytes.get(NAME_OFFSET..name_end).ok_or(())?;
    if name.is_empty() || name.iter().any(|byte| !byte.is_ascii_digit()) {
        return Ok((record_len, None));
    }
    let mut fd = 0_i32;
    for byte in name {
        fd = match fd
            .checked_mul(10)
            .and_then(|value| value.checked_add(i32::from(*byte - b'0')))
        {
            Some(fd) => fd,
            None => return Ok((record_len, None)),
        };
    }
    Ok((record_len, Some(fd)))
}

#[cfg(target_os = "macos")]
fn child_errno() -> libc::c_int {
    unsafe { *libc::__error() }
}

#[cfg(target_os = "linux")]
fn child_errno() -> libc::c_int {
    unsafe { *libc::__errno_location() }
}

fn child_last_os_error() -> io::Error {
    io::Error::from_raw_os_error(child_errno())
}
