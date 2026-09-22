use std::io;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::sys::stat::{fstat, SFlag};

use crate::krun_worker::protocol::invalid;

pub(crate) struct Bootstrap {
    pub(crate) request: OwnedFd,
    pub(crate) events: OwnedFd,
    pub(crate) watchdog: OwnedFd,
    pub(crate) console: OwnedFd,
    pub(crate) mux: Option<OwnedFd>,
}

#[derive(Clone, Copy)]
enum Role {
    Request,
    Events,
    Watchdog,
    Console,
    Mux,
}

impl Bootstrap {
    /// Adopt descriptors only after validating all roles, access and aliases.
    pub(crate) fn adopt(
        request: RawFd,
        events: RawFd,
        watchdog: RawFd,
        console: RawFd,
        mux: Option<RawFd>,
    ) -> io::Result<Self> {
        let roles = [
            (request, Role::Request),
            (events, Role::Events),
            (watchdog, Role::Watchdog),
            (console, Role::Console),
        ];
        let mut identities = Vec::new();
        #[cfg(target_os = "macos")]
        let mut pipes = Vec::new();
        let mut numbers = Vec::new();
        for (raw, role) in roles.into_iter().chain(mux.map(|raw| (raw, Role::Mux))) {
            if raw < 3 || numbers.contains(&raw) {
                return Err(invalid("invalid or duplicated bootstrap descriptor"));
            }
            // nix's fcntl API requires an already-valid AsFd. Probe the untrusted
            // numeric argument with libc before constructing a Rust FD borrow.
            if unsafe { nix::libc::fcntl(raw, nix::libc::F_GETFD) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the worker has not started threads, all numbers were probed,
            // and this scope neither closes nor transfers any descriptor.
            let fd = unsafe { BorrowedFd::borrow_raw(raw) };
            let stat = fstat(fd)?;
            let identity = (stat.st_dev, stat.st_ino);
            if identities.contains(&identity) {
                return Err(invalid("bootstrap roles alias the same resource"));
            }
            let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
            #[cfg(target_os = "macos")]
            if kind == SFlag::S_IFIFO {
                let identity = pipe_identity(raw)?;
                if pipes.contains(&identity) {
                    return Err(invalid("bootstrap roles alias the same pipe"));
                }
                pipes.push(identity);
            }
            let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
            let access = flags & OFlag::O_ACCMODE;
            match role {
                Role::Request | Role::Watchdog
                    if kind == SFlag::S_IFIFO && access == OFlag::O_RDONLY => {}
                Role::Events if kind == SFlag::S_IFIFO && access == OFlag::O_WRONLY => {}
                Role::Console if nix::unistd::isatty(fd)? && access == OFlag::O_RDWR => {}
                Role::Mux if kind == SFlag::S_IFSOCK => {
                    use nix::sys::socket::{getpeername, getsockopt, sockopt, SockType, UnixAddr};
                    if getsockopt(&fd, sockopt::SockType)? != SockType::Stream {
                        return Err(invalid("mux must be a stream socket"));
                    }
                    getpeername::<UnixAddr>(raw)?;
                }
                _ => return Err(invalid("bootstrap descriptor has wrong type or access")),
            }
            numbers.push(raw);
            identities.push(identity);
        }
        // No descriptor has been adopted yet, so a validation error never closes
        // an unowned or duplicate resource. Every validated descriptor is unique.
        for raw in &numbers {
            let fd = unsafe { BorrowedFd::borrow_raw(*raw) };
            let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
            fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
        }
        // SAFETY: the private argv contract transfers each validated, unique FD once.
        Ok(unsafe {
            Self {
                request: OwnedFd::from_raw_fd(request),
                events: OwnedFd::from_raw_fd(events),
                watchdog: OwnedFd::from_raw_fd(watchdog),
                console: OwnedFd::from_raw_fd(console),
                mux: mux.map(|fd| OwnedFd::from_raw_fd(fd)),
            }
        })
    }
}

#[cfg(target_os = "macos")]
fn pipe_identity(fd: RawFd) -> io::Result<(u64, u64)> {
    // Darwin assigns distinct inodes to the ends of an anonymous pipe. Its
    // proc_info.h ABI exposes opaque handles linking those ends; nix does not
    // wrap PROC_PIDFDPIPEINFO, and libc only exposes the query and vinfo_stat.
    #[repr(C)]
    struct FileInfo {
        openflags: u32,
        status: u32,
        offset: nix::libc::off_t,
        kind: i32,
        guardflags: u32,
    }
    #[repr(C)]
    struct PipeInfo {
        stat: nix::libc::vinfo_stat,
        handle: u64,
        peerhandle: u64,
        status: i32,
        reserved: i32,
    }
    #[repr(C)]
    struct PipeFdInfo {
        file: FileInfo,
        pipe: PipeInfo,
    }
    const PROC_PIDFDPIPEINFO: i32 = 6;
    let mut info = std::mem::MaybeUninit::<PipeFdInfo>::uninit();
    let size = std::mem::size_of::<PipeFdInfo>() as i32;
    // SAFETY: the query writes at most size bytes into correctly aligned storage
    // matching the SDK's pipe_fdinfo layout. No fields are read on a short result.
    let count = unsafe {
        nix::libc::proc_pidfdinfo(
            nix::unistd::getpid().as_raw(),
            fd,
            PROC_PIDFDPIPEINFO,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if count <= 0 {
        return Err(io::Error::last_os_error());
    }
    if count != size {
        return Err(invalid("incomplete pipe descriptor information"));
    }
    // SAFETY: the kernel returned the entire initialized structure.
    let info = unsafe { info.assume_init() };
    let (handle, peer) = (info.pipe.handle, info.pipe.peerhandle);
    Ok((handle.min(peer), handle.max(peer)))
}

pub(crate) fn nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

pub(crate) fn start_watchdog(fd: OwnedFd) -> io::Result<()> {
    std::thread::Builder::new()
        .name("krun-watchdog".to_string())
        .spawn(move || {
            use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
            let mut ready = [PollFd::new(fd.as_fd(), PollFlags::POLLHUP)];
            loop {
                match poll(&mut ready, PollTimeout::NONE) {
                    Ok(_)
                        if ready[0].revents().is_some_and(|events| {
                            events.intersects(
                                PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL,
                            )
                        }) =>
                    {
                        break
                    }
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(_) => break,
                    _ => {}
                }
            }
            // nix exposes no immediate _exit. Do not run logging, destructors or
            // atexit handlers on parent loss, since native threads can hold locks.
            unsafe { nix::libc::_exit(125) }
        })
        .map(drop)
}

#[cfg(test)]
mod tests {
    use crate::krun_worker::fds::Bootstrap;
    use std::os::fd::AsRawFd;

    #[test]
    fn opposite_pipe_ends_cannot_fill_distinct_roles() {
        let (request, events) = nix::unistd::pipe().expect("request pipe");
        let (watchdog, _keepalive) = nix::unistd::pipe().expect("watchdog pipe");
        let pty = nix::pty::openpty(None, None).expect("pty");
        assert!(Bootstrap::adopt(
            request.as_raw_fd(),
            events.as_raw_fd(),
            watchdog.as_raw_fd(),
            pty.slave.as_raw_fd(),
            None,
        )
        .is_err());
        for fd in [&request, &events, &watchdog, &pty.slave] {
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).expect("still owned");
        }
    }

    #[test]
    fn invalid_roles_do_not_adopt_or_close_caller_descriptors() {
        let (read, write) = nix::unistd::pipe().expect("pipe");
        let pty = nix::pty::openpty(None, None).expect("pty");
        assert!(Bootstrap::adopt(
            read.as_raw_fd(),
            write.as_raw_fd(),
            read.as_raw_fd(),
            pty.slave.as_raw_fd(),
            None
        )
        .is_err());
        nix::fcntl::fcntl(&read, nix::fcntl::FcntlArg::F_GETFD).expect("still owned");
        let alias = read.try_clone().expect("dup");
        assert!(Bootstrap::adopt(
            read.as_raw_fd(),
            write.as_raw_fd(),
            alias.as_raw_fd(),
            pty.slave.as_raw_fd(),
            None
        )
        .is_err());
        assert!(Bootstrap::adopt(
            -1,
            write.as_raw_fd(),
            read.as_raw_fd(),
            pty.slave.as_raw_fd(),
            None
        )
        .is_err());
    }
}
