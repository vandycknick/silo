//! The worker's fixed descriptor table:
//!
//! | fd | role                                              |
//! |----|---------------------------------------------------|
//! | 0  | /dev/null                                         |
//! | 1  | diagnostics pipe (write end)                      |
//! | 2  | diagnostics pipe (write end)                      |
//! | 3  | config: FIFO read end, one `KrunConfig`, read to EOF |
//! | 4  | events: FIFO write end, length-prefixed events    |
//! | 5  | watchdog: FIFO read end, POLLHUP = supervisor gone |
//! | 6  | console: PTY slave                                |
//! | 7  | vsock mux: connected stream socket, iff configured |
//!
//! | 8  | generation lease: shared-flock regular file       |
//! | 9+ | Raw backing handles, in manifest order (max 16)   |
//!
//! The optional mux hole stays closed; no other descriptor may be open.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::sys::stat::{fstat, SFlag};

use crate::krun::worker::wire::invalid;

pub(crate) const CONFIG_FD: RawFd = 3;
pub(crate) const EVENTS_FD: RawFd = 4;
pub(crate) const WATCHDOG_FD: RawFd = 5;
pub(crate) const CONSOLE_FD: RawFd = 6;
pub(crate) const MUX_FD: RawFd = 7;
pub(crate) const STORAGE_LEASE_FD: RawFd = 8;
pub(crate) const FIRST_RAW_FD: RawFd = 9;
const MAX_RAW_HANDLES: usize = 16;
const MAX_INHERITED_FDS: usize = 6 + MAX_RAW_HANDLES;

pub(crate) struct Bootstrap {
    pub(crate) config: OwnedFd,
    pub(crate) events: OwnedFd,
    pub(crate) watchdog: OwnedFd,
    pub(crate) console: OwnedFd,
    pub(crate) mux: Option<OwnedFd>,
    pub(crate) storage_lease: OwnedFd,
    pub(crate) raw_handles: Vec<OwnedFd>,
}

#[derive(Clone, Copy)]
enum Role {
    Config,
    Events,
    Watchdog,
    Console,
    Mux,
    StorageLease,
    Raw,
}

impl Bootstrap {
    /// Adopt the fixed descriptor table. The mux is optional; whether it must be
    /// present is decided by the config, which is read afterwards.
    pub(crate) fn adopt_fixed() -> io::Result<Self> {
        let mux = descriptor_open(MUX_FD)?.then_some(MUX_FD);
        let mut raw_handles = [0; MAX_RAW_HANDLES];
        let mut raw_count = 0;
        let mut hole = false;
        for raw in FIRST_RAW_FD..FIRST_RAW_FD + MAX_RAW_HANDLES as RawFd {
            if descriptor_open(raw)? {
                if hole {
                    return Err(invalid("Raw descriptor table contains a hole"));
                }
                raw_handles[raw_count] = raw;
                raw_count += 1;
            } else {
                hole = true;
            }
        }
        let raw_handles = &raw_handles[..raw_count];
        let mut allowed = [0; MAX_INHERITED_FDS];
        let mut count = 0;
        for raw in [
            CONFIG_FD,
            EVENTS_FD,
            WATCHDOG_FD,
            CONSOLE_FD,
            STORAGE_LEASE_FD,
        ]
        .into_iter()
        .chain(mux)
        .chain(raw_handles.iter().copied())
        {
            allowed[count] = raw;
            count += 1;
        }
        ensure_exact_descriptors(&allowed[..count])?;
        Self::adopt(
            CONFIG_FD,
            EVENTS_FD,
            WATCHDOG_FD,
            CONSOLE_FD,
            mux,
            STORAGE_LEASE_FD,
            raw_handles,
        )
    }

    /// Adopt descriptors only after validating all roles, access and aliases.
    fn adopt(
        config: RawFd,
        events: RawFd,
        watchdog: RawFd,
        console: RawFd,
        mux: Option<RawFd>,
        storage_lease: RawFd,
        raw_handles: &[RawFd],
    ) -> io::Result<Self> {
        if raw_handles.len() > MAX_RAW_HANDLES {
            return Err(invalid("too many inherited Raw backing handles"));
        }
        let roles = [
            (config, Role::Config),
            (events, Role::Events),
            (watchdog, Role::Watchdog),
            (console, Role::Console),
        ];
        let mut identities = [((0_u64, 0_u64), false); MAX_INHERITED_FDS];
        #[cfg(target_os = "macos")]
        let mut pipes = [None; 3];
        let mut numbers = [-1; MAX_INHERITED_FDS];
        let mut count = 0;
        for (raw, role) in roles
            .into_iter()
            .chain(mux.map(|raw| (raw, Role::Mux)))
            .chain(std::iter::once((storage_lease, Role::StorageLease)))
            .chain(raw_handles.iter().map(|&raw| (raw, Role::Raw)))
        {
            if raw < 3 || numbers[..count].contains(&raw) {
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
            let identity = (stat.st_dev as u64, stat.st_ino as u64);
            if identities[..count].iter().any(|&(prior, prior_raw)| {
                prior == identity && !(prior_raw && matches!(role, Role::Raw))
            }) {
                return Err(invalid("bootstrap roles alias the same resource"));
            }
            let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
            #[cfg(target_os = "macos")]
            if kind == SFlag::S_IFIFO {
                let identity = pipe_identity(raw)?;
                if pipes.contains(&Some(identity)) {
                    return Err(invalid("bootstrap roles alias the same pipe"));
                }
                let Some(slot) = pipes.iter_mut().find(|slot| slot.is_none()) else {
                    return Err(invalid("too many inherited bootstrap pipes"));
                };
                *slot = Some(identity);
            }
            let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
            let access = flags & OFlag::O_ACCMODE;
            match role {
                Role::Config | Role::Watchdog
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
                Role::StorageLease => validate_lease_metadata(fd)?,
                Role::Raw
                    if matches!(kind, SFlag::S_IFREG | SFlag::S_IFBLK | SFlag::S_IFCHR)
                        && matches!(access, OFlag::O_RDONLY | OFlag::O_RDWR) => {}
                _ => return Err(invalid("bootstrap descriptor has wrong type or access")),
            }
            numbers[count] = raw;
            identities[count] = (identity, matches!(role, Role::Raw));
            count += 1;
        }
        // No descriptor has been adopted yet, so a validation error never closes
        // an unowned or duplicate resource. Every validated descriptor is unique.
        for raw in &numbers[..count] {
            let fd = unsafe { BorrowedFd::borrow_raw(*raw) };
            let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
            fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
        }
        // SAFETY: the fixed descriptor contract transfers each validated, unique FD once.
        Ok(unsafe {
            Self {
                config: OwnedFd::from_raw_fd(config),
                events: OwnedFd::from_raw_fd(events),
                watchdog: OwnedFd::from_raw_fd(watchdog),
                console: OwnedFd::from_raw_fd(console),
                mux: mux.map(|fd| OwnedFd::from_raw_fd(fd)),
                storage_lease: OwnedFd::from_raw_fd(storage_lease),
                raw_handles: raw_handles
                    .iter()
                    .map(|&raw| OwnedFd::from_raw_fd(raw))
                    .collect(),
            }
        })
    }
}

fn descriptor_open(raw: RawFd) -> io::Result<bool> {
    // An untrusted raw number must be probed before constructing BorrowedFd.
    if unsafe { nix::libc::fcntl(raw, nix::libc::F_GETFD) } >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(nix::libc::EBADF) {
        Ok(false)
    } else {
        Err(error)
    }
}

fn validate_lease_metadata(fd: BorrowedFd<'_>) -> io::Result<()> {
    let stat = fstat(fd)?;
    let access = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?) & OFlag::O_ACCMODE;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != nix::unistd::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || access != OFlag::O_RDWR
    {
        return Err(invalid("invalid inherited generation lease"));
    }
    Ok(())
}

/// Validate identity without acquiring, converting, or unlocking the shared OFD.
pub(crate) fn validate_lease(fd: BorrowedFd<'_>, device: u64, inode: u64) -> io::Result<()> {
    validate_lease_metadata(fd)?;
    let stat = fstat(fd)?;
    if stat.st_dev as u64 != device || stat.st_ino as u64 != inode {
        return Err(invalid(
            "generation lease inode does not match launch binding",
        ));
    }
    Ok(())
}

/// Fail closed for unexpected descriptors, including optional-role holes.
fn ensure_exact_descriptors(allowed: &[RawFd]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    const FD_DIR: &str = "/proc/self/fd";
    #[cfg(target_os = "macos")]
    const FD_DIR: &str = "/dev/fd";
    let mut directory = nix::dir::Dir::open(
        FD_DIR,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?;
    let own = std::os::fd::AsRawFd::as_raw_fd(&directory);
    for entry in directory.iter() {
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        let Ok(fd) = name.parse::<RawFd>() else {
            continue;
        };
        if fd >= 3 && !allowed.contains(&fd) && fd != own {
            return Err(invalid("worker inherited an unexpected descriptor"));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn pipe_identity(fd: RawFd) -> io::Result<(u64, u64)> {
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
    use crate::krun::worker::fds::Bootstrap;
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
            request.as_raw_fd(),
            &[],
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
            None,
            read.as_raw_fd(),
            &[],
        )
        .is_err());
        nix::fcntl::fcntl(&read, nix::fcntl::FcntlArg::F_GETFD).expect("still owned");
        let alias = read.try_clone().expect("dup");
        assert!(Bootstrap::adopt(
            read.as_raw_fd(),
            write.as_raw_fd(),
            alias.as_raw_fd(),
            pty.slave.as_raw_fd(),
            None,
            read.as_raw_fd(),
            &[],
        )
        .is_err());
        assert!(Bootstrap::adopt(
            -1,
            write.as_raw_fd(),
            read.as_raw_fd(),
            pty.slave.as_raw_fd(),
            None,
            read.as_raw_fd(),
            &[],
        )
        .is_err());
    }

    #[test]
    fn inherited_lease_metadata_rejects_unsafe_inodes_without_taking_ownership() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let root =
            std::env::temp_dir().join(format!("worker-lease-validation-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("operation.lease");
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let stat = nix::sys::stat::fstat(&lease).unwrap();
        let validate = |fd: std::os::fd::BorrowedFd<'_>| {
            crate::krun::worker::fds::validate_lease(fd, stat.st_dev as u64, stat.st_ino as u64)
        };
        validate(lease.as_fd()).unwrap();
        assert!(crate::krun::worker::fds::validate_lease(
            lease.as_fd(),
            stat.st_dev as u64,
            stat.st_ino as u64 + 1
        )
        .is_err());
        assert!(
            validate(std::fs::File::open(&path).unwrap().as_fd()).is_err(),
            "read-only lease"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            validate(lease.as_fd()).is_err(),
            "mode must be exactly 0600"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, root.join("alias")).unwrap();
        assert!(validate(lease.as_fd()).is_err(), "nlink must be one");
        std::fs::remove_file(root.join("alias")).unwrap();
        assert!(
            validate(std::fs::File::open(&root).unwrap().as_fd()).is_err(),
            "directory lease"
        );
        let (pipe, _) = nix::unistd::pipe().unwrap();
        assert!(validate(pipe.as_fd()).is_err(), "pipe lease");
        validate(lease.as_fd()).unwrap();
        nix::fcntl::fcntl(&lease, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        drop(lease);
        std::fs::remove_dir_all(root).unwrap();
    }
}
