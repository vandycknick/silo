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
//! | 25 | restore RAM, read-only regular file (standalone only) |
//! | 26 | restore layout, read-only regular file              |
//! | 27 | restore execution, read-only regular file           |
//! | 28 | restore devices, read-only regular file             |
//! | 29 | managed network: connected datagram socket (standalone only) |
//! | 30 | console input: connected stream socket (standalone only)     |
//! | 31 | console output: connected stream socket (standalone only)    |
//! | 32 | lifecycle: connected stream socket (normal worker only)      |
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
const MAX_INHERITED_FDS: usize = 14 + MAX_RAW_HANDLES;
pub(crate) const RESTORE_STATE_FDS: [RawFd; 4] = [25, 26, 27, 28];
pub(crate) const STANDALONE_ENDPOINT_FDS: [RawFd; 3] = [29, 30, 31];
/// The normal worker's monitor lifecycle endpoint; above every other role.
pub(crate) const LIFECYCLE_FD: RawFd = 32;

#[allow(dead_code)] // Consumed only by the explicit standalone API entry.
pub(crate) struct StandaloneEndpoints {
    pub(crate) network: OwnedFd,
    pub(crate) console_input: OwnedFd,
    pub(crate) console_output: OwnedFd,
}

/// State objects are not disk attachments and never enter `raw_handles`.
#[allow(dead_code)] // Normal worker launch never adopts state roles.
pub(crate) struct RestoreStateFiles {
    pub(crate) ram: std::fs::File,
    pub(crate) layout: std::fs::File,
    pub(crate) execution: std::fs::File,
    pub(crate) devices: std::fs::File,
}

pub(crate) struct Bootstrap {
    pub(crate) config: OwnedFd,
    pub(crate) events: OwnedFd,
    pub(crate) watchdog: OwnedFd,
    pub(crate) console: OwnedFd,
    pub(crate) mux: Option<OwnedFd>,
    pub(crate) storage_lease: OwnedFd,
    pub(crate) raw_handles: Vec<OwnedFd>,
    /// Required by the normal worker; never present for the standalone entry.
    pub(crate) lifecycle: Option<OwnedFd>,
    #[allow(dead_code)] // Only the explicit standalone entry consumes these roles.
    pub(crate) state_files: Option<RestoreStateFiles>,
    #[allow(dead_code)]
    pub(crate) standalone: Option<StandaloneEndpoints>,
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
    State { maximum: u64 },
    Network,
    Lifecycle,
}

impl Bootstrap {
    /// Adopt the fixed descriptor table. The mux is optional; whether it must be
    /// present is decided by the config, which is read afterwards.
    pub(crate) fn adopt_fixed() -> io::Result<Self> {
        Self::adopt_fixed_mode(false, false)
    }

    /// Explicit proof entry only; normal worker launch never admits these roles.
    #[allow(dead_code)] // Not an extension of the normal worker wire.
    pub(crate) fn adopt_standalone_fixed(restore: bool) -> io::Result<Self> {
        Self::adopt_fixed_mode(restore, true)
    }

    fn adopt_fixed_mode(restore: bool, standalone: bool) -> io::Result<Self> {
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
        let lifecycle = (!standalone).then_some(LIFECYCLE_FD);
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
        .chain(lifecycle)
        .chain(restore.then_some(RESTORE_STATE_FDS).into_iter().flatten())
        .chain(
            standalone
                .then_some(STANDALONE_ENDPOINT_FDS)
                .into_iter()
                .flatten(),
        ) {
            allowed[count] = raw;
            count += 1;
        }
        ensure_exact_descriptors(&allowed[..count])?;
        Self::adopt_with_state(
            CONFIG_FD,
            EVENTS_FD,
            WATCHDOG_FD,
            CONSOLE_FD,
            mux,
            STORAGE_LEASE_FD,
            raw_handles,
            lifecycle,
            restore.then_some(RESTORE_STATE_FDS),
            standalone.then_some(STANDALONE_ENDPOINT_FDS),
        )
    }

    /// Adopt descriptors only after validating all roles, access and aliases.
    #[cfg(test)]
    fn adopt(
        config: RawFd,
        events: RawFd,
        watchdog: RawFd,
        console: RawFd,
        mux: Option<RawFd>,
        storage_lease: RawFd,
        raw_handles: &[RawFd],
    ) -> io::Result<Self> {
        Self::adopt_with_state(
            config,
            events,
            watchdog,
            console,
            mux,
            storage_lease,
            raw_handles,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn adopt_with_state(
        config: RawFd,
        events: RawFd,
        watchdog: RawFd,
        console: RawFd,
        mux: Option<RawFd>,
        storage_lease: RawFd,
        raw_handles: &[RawFd],
        lifecycle: Option<RawFd>,
        state: Option<[RawFd; 4]>,
        standalone: Option<[RawFd; 3]>,
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
            .chain(lifecycle.map(|raw| (raw, Role::Lifecycle)))
            .chain(state.into_iter().flat_map(|fds| {
                fds.into_iter().zip([
                    Role::State { maximum: 1 << 40 },
                    Role::State { maximum: 64 * 1024 },
                    Role::State {
                        maximum: 16 * 1024 * 1024,
                    },
                    Role::State {
                        maximum: 32 * 1024 * 1024,
                    },
                ])
            }))
            .chain(standalone.into_iter().flat_map(|[network, input, output]| {
                [
                    (network, Role::Network),
                    (input, Role::Mux),
                    (output, Role::Mux),
                ]
            }))
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
            #[cfg(target_os = "linux")]
            if matches!(role, Role::State { .. })
                && flags.intersects(OFlag::O_PATH | OFlag::O_DIRECT)
            {
                return Err(invalid("state roles require readable buffered descriptors"));
            }
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
                Role::Lifecycle if kind == SFlag::S_IFSOCK && access == OFlag::O_RDWR => {
                    use nix::sys::socket::{getpeername, getsockopt, sockopt, SockType, UnixAddr};
                    if getsockopt(&fd, sockopt::SockType)? != SockType::Stream {
                        return Err(invalid("lifecycle endpoint must be a stream socket"));
                    }
                    getpeername::<UnixAddr>(raw)?;
                }
                Role::Network if kind == SFlag::S_IFSOCK => {
                    use nix::sys::socket::{getpeername, getsockopt, sockopt, SockType, UnixAddr};
                    if getsockopt(&fd, sockopt::SockType)? != SockType::Datagram {
                        return Err(invalid("managed network must be a datagram socket"));
                    }
                    getpeername::<UnixAddr>(raw)?;
                }
                Role::StorageLease => validate_lease_metadata(fd)?,
                Role::Raw
                    if matches!(kind, SFlag::S_IFREG | SFlag::S_IFBLK | SFlag::S_IFCHR)
                        && matches!(access, OFlag::O_RDONLY | OFlag::O_RDWR) => {}
                Role::State { maximum }
                    if kind == SFlag::S_IFREG
                        && access == OFlag::O_RDONLY
                        && !flags.contains(OFlag::O_APPEND)
                        && stat.st_size > 0
                        && (stat.st_size as u64) <= maximum => {}
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
                lifecycle: lifecycle.map(|raw| OwnedFd::from_raw_fd(raw)),
                state_files: state.map(|[ram, layout, execution, devices]| RestoreStateFiles {
                    ram: std::fs::File::from_raw_fd(ram),
                    layout: std::fs::File::from_raw_fd(layout),
                    execution: std::fs::File::from_raw_fd(execution),
                    devices: std::fs::File::from_raw_fd(devices),
                }),
                standalone: standalone.map(|[network, input, output]| StandaloneEndpoints {
                    network: OwnedFd::from_raw_fd(network),
                    console_input: OwnedFd::from_raw_fd(input),
                    console_output: OwnedFd::from_raw_fd(output),
                }),
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

    #[test]
    fn restore_roles_validate_before_any_descriptor_is_adopted() {
        use std::os::unix::fs::OpenOptionsExt;
        let root = std::env::temp_dir().join(format!("worker-state-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let (config, _config_writer) = nix::unistd::pipe().unwrap();
        let (_events_reader, events) = nix::unistd::pipe().unwrap();
        let (watchdog, _watchdog_writer) = nix::unistd::pipe().unwrap();
        let pty = nix::pty::openpty(None, None).unwrap();
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("lease"))
            .unwrap();
        let mut files = Vec::new();
        for index in 0..4 {
            let path = root.join(index.to_string());
            std::fs::write(&path, [1_u8; 8]).unwrap();
            files.push(std::fs::File::open(path).unwrap());
        }
        let raw = std::array::from_fn(|index| files[index].as_raw_fd());
        let refuse = |state, disks: &[std::os::fd::RawFd]| {
            assert!(Bootstrap::adopt_with_state(
                config.as_raw_fd(),
                events.as_raw_fd(),
                watchdog.as_raw_fd(),
                pty.slave.as_raw_fd(),
                None,
                lease.as_raw_fd(),
                disks,
                None,
                Some(state),
                None,
            )
            .is_err());
            for file in &files {
                nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_GETFD).unwrap();
            }
            nix::fcntl::fcntl(&config, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        };
        let writable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("0"))
            .unwrap();
        refuse([writable.as_raw_fd(), raw[1], raw[2], raw[3]], &[]);
        #[cfg(target_os = "linux")]
        {
            let path_only = nix::fcntl::open(
                &root.join("0"),
                nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC,
                nix::sys::stat::Mode::empty(),
            )
            .unwrap();
            refuse([path_only.as_raw_fd(), raw[1], raw[2], raw[3]], &[]);
        }
        let alias = files[0].try_clone().unwrap();
        refuse([raw[0], alias.as_raw_fd(), raw[2], raw[3]], &[]);
        refuse([raw[0], raw[0], raw[2], raw[3]], &[]);
        refuse([-1, raw[1], raw[2], raw[3]], &[]);
        refuse([config.as_raw_fd(), raw[1], raw[2], raw[3]], &[]);
        refuse(raw, &[alias.as_raw_fd()]);
        files[3]
            .set_len(0)
            .expect_err("read-only file cannot truncate");
        std::fs::write(root.join("3"), []).unwrap();
        refuse(raw, &[]);
        drop(files);
        drop(alias);
        drop(writable);
        drop(lease);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_state_adoption_restores_cloexec_and_keeps_state_out_of_disks() {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        use std::os::fd::{AsFd, IntoRawFd};
        use std::os::unix::fs::OpenOptionsExt;
        let root =
            std::env::temp_dir().join(format!("worker-state-adopt-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let (config, _config_writer) = nix::unistd::pipe().unwrap();
        let (_events_reader, events) = nix::unistd::pipe().unwrap();
        let (watchdog, _watchdog_writer) = nix::unistd::pipe().unwrap();
        let pty = nix::pty::openpty(None, None).unwrap();
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("lease"))
            .unwrap();
        let files: [std::fs::File; 4] = std::array::from_fn(|index| {
            let path = root.join(index.to_string());
            std::fs::write(&path, [1_u8; 8]).unwrap();
            let file = std::fs::File::open(path).unwrap();
            fcntl(&file, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
            file
        });
        let adopted = Bootstrap::adopt_with_state(
            config.into_raw_fd(),
            events.into_raw_fd(),
            watchdog.into_raw_fd(),
            pty.slave.into_raw_fd(),
            None,
            lease.into_raw_fd(),
            &[],
            None,
            Some(files.map(IntoRawFd::into_raw_fd)),
            None,
        )
        .unwrap();
        assert!(adopted.raw_handles.is_empty());
        let state = adopted.state_files.as_ref().unwrap();
        for fd in [
            adopted.config.as_fd(),
            adopted.events.as_fd(),
            adopted.watchdog.as_fd(),
            adopted.console.as_fd(),
            adopted.storage_lease.as_fd(),
            state.ram.as_fd(),
            state.layout.as_fd(),
            state.execution.as_fd(),
            state.devices.as_fd(),
        ] {
            assert!(
                FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD).unwrap())
                    .contains(FdFlag::FD_CLOEXEC)
            );
        }
        drop(adopted);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn lease(root: &std::path::Path) -> std::fs::File {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("lease"))
            .unwrap()
    }

    #[test]
    fn lifecycle_role_requires_a_distinct_connected_stream_socket() {
        use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
        let root = std::env::temp_dir().join(format!("worker-lifecycle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let (config, _config_writer) = nix::unistd::pipe().unwrap();
        let (_events_reader, events) = nix::unistd::pipe().unwrap();
        let (watchdog, _watchdog_writer) = nix::unistd::pipe().unwrap();
        let pty = nix::pty::openpty(None, None).unwrap();
        let lease = lease(&root);
        let (mux, _mux_peer) = UnixStream::pair().unwrap();
        let (datagram, _datagram_peer) = UnixDatagram::pair().unwrap();
        let unconnected = UnixListener::bind(root.join("unconnected.sock")).unwrap();
        let refuse = |lifecycle: std::os::fd::RawFd| {
            assert!(Bootstrap::adopt_with_state(
                config.as_raw_fd(),
                events.as_raw_fd(),
                watchdog.as_raw_fd(),
                pty.slave.as_raw_fd(),
                Some(mux.as_raw_fd()),
                lease.as_raw_fd(),
                &[],
                Some(lifecycle),
                None,
                None,
            )
            .is_err());
            // Validation failure never adopts or closes a caller descriptor.
            for fd in [config.as_raw_fd(), mux.as_raw_fd(), lifecycle] {
                assert!(unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } >= 0);
            }
        };
        refuse(datagram.as_raw_fd());
        refuse(unconnected.as_raw_fd());
        refuse(mux.as_raw_fd());
        let alias = mux.try_clone().unwrap();
        refuse(alias.as_raw_fd());
        refuse(config.as_raw_fd());
        drop(lease);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lifecycle_adoption_owns_the_endpoint_with_cloexec() {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        use std::io::{Read, Write};
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        let root =
            std::env::temp_dir().join(format!("worker-lifecycle-adopt-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let (config, _config_writer) = nix::unistd::pipe().unwrap();
        let (_events_reader, events) = nix::unistd::pipe().unwrap();
        let (watchdog, _watchdog_writer) = nix::unistd::pipe().unwrap();
        let pty = nix::pty::openpty(None, None).unwrap();
        let (child, mut parent) = UnixStream::pair().unwrap();
        fcntl(&child, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
        let adopted = Bootstrap::adopt_with_state(
            config.into_raw_fd(),
            events.into_raw_fd(),
            watchdog.into_raw_fd(),
            pty.slave.into_raw_fd(),
            None,
            lease(&root).into_raw_fd(),
            &[],
            Some(child.into_raw_fd()),
            None,
            None,
        )
        .unwrap();
        let endpoint = adopted.lifecycle.as_ref().expect("lifecycle endpoint");
        assert!(
            FdFlag::from_bits_retain(fcntl(endpoint, FcntlArg::F_GETFD).unwrap())
                .contains(FdFlag::FD_CLOEXEC)
        );
        let mut endpoint = UnixStream::from(endpoint.try_clone().unwrap());
        endpoint.write_all(b"ok").unwrap();
        let mut received = [0; 2];
        parent.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"ok");
        drop(endpoint);
        drop(adopted);
        let mut eof = [0; 1];
        assert_eq!(
            parent.read(&mut eof).unwrap(),
            0,
            "adopted endpoint closes on drop"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
