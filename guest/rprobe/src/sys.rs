use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use rprobe::frame::{Header, PAYLOAD_LEN, REQUEST};
use rprobe::probe::{
    ErrorKind, OwnedFailure, ProbeError, Stage, WriteAction, WriteEvent, WriteProgress,
};

const DEV_HVC0: *const c_char = c"/dev/hvc0".as_ptr();
const DEV_HVC1: *const c_char = c"/dev/hvc1".as_ptr();
const ROSETTA_FILE: *const c_char = c"/mnt/rosetta/rosetta".as_ptr();
const DEADLINE_SECONDS: i64 = 45;

struct OwnedFd(c_int);

impl OwnedFd {
    fn raw(&self) -> c_int {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // libc is used directly because this allocation-free PID1 intentionally has no nix dependency.
        unsafe { libc::close(self.0) };
    }
}

enum Diagnostic {
    Borrowed(c_int),
    Owned(OwnedFd),
}

impl Diagnostic {
    const fn stderr() -> Self {
        Self::Borrowed(libc::STDERR_FILENO)
    }

    fn raw(&self) -> c_int {
        match self {
            Self::Borrowed(fd) => *fd,
            Self::Owned(fd) => fd.raw(),
        }
    }
}

type RuntimeError = OwnedFailure<Diagnostic>;

#[derive(Clone, Copy)]
struct Deadline(libc::timespec);

impl Deadline {
    fn start() -> Result<Self, i32> {
        let now = monotonic()?;
        let tv_sec = now
            .tv_sec
            .checked_add(DEADLINE_SECONDS)
            .ok_or(libc::EOVERFLOW)?;
        Ok(Self(libc::timespec {
            tv_sec,
            tv_nsec: now.tv_nsec,
        }))
    }

    fn remaining_ms(self) -> Result<c_int, i32> {
        let now = monotonic()?;
        let mut seconds = self
            .0
            .tv_sec
            .checked_sub(now.tv_sec)
            .ok_or(libc::ETIMEDOUT)?;
        let mut nanos = self
            .0
            .tv_nsec
            .checked_sub(now.tv_nsec)
            .ok_or(libc::EOVERFLOW)?;
        if nanos < 0 {
            seconds = seconds.checked_sub(1).ok_or(libc::ETIMEDOUT)?;
            nanos = nanos.checked_add(1_000_000_000).ok_or(libc::EOVERFLOW)?;
        }
        if seconds < 0 || (seconds == 0 && nanos == 0) {
            return Err(libc::ETIMEDOUT);
        }
        let millis = seconds
            .saturating_mul(1000)
            .saturating_add(nanos.saturating_add(999_999) / 1_000_000);
        Ok(core::cmp::min(millis, i64::from(c_int::MAX)) as c_int)
    }
}

fn run() -> Result<Diagnostic, RuntimeError> {
    let deadline = match Deadline::start() {
        Ok(deadline) => deadline,
        Err(_) => return Err(failure(Stage::Filesystems, Diagnostic::stderr())),
    };
    if mount_filesystems().is_err() {
        return Err(failure(Stage::Filesystems, Diagnostic::stderr()));
    }

    let diagnostic = match open_retry(DEV_HVC0, deadline) {
        Ok(fd) => Diagnostic::Owned(OwnedFd(fd)),
        Err(_) => return Err(failure(Stage::DiagnosticPort, Diagnostic::stderr())),
    };
    let diagnostic_fd = diagnostic.raw();
    if set_nonblocking(diagnostic_fd).is_err() {
        return Err(failure(Stage::DiagnosticPort, diagnostic));
    }
    let data = match open_retry(DEV_HVC1, deadline) {
        Ok(fd) => OwnedFd(fd),
        Err(_) => return Err(failure(Stage::DataPort, diagnostic)),
    };
    if configure_data_port(data.raw()).is_err() {
        return Err(failure(Stage::DataPort, diagnostic));
    }

    if let Err(error) = mount_rosetta(deadline) {
        let _ = write_failure(data.raw(), error, deadline);
        return Err(failure(Stage::RosettaMount, diagnostic));
    }
    let translator = match open_readonly(ROSETTA_FILE) {
        Ok(fd) => OwnedFd(fd),
        Err(error) => {
            let _ = write_failure(data.raw(), error, deadline);
            return Err(failure(Stage::RosettaFile, diagnostic));
        }
    };

    let mut payload = [0xaa; PAYLOAD_LEN];
    // libc 0.2.189's musl binding uses Ioctl; the cast preserves the request's exact 32 bits.
    let result = unsafe {
        libc::ioctl(
            translator.raw(),
            REQUEST as libc::Ioctl,
            payload.as_mut_ptr().cast::<c_void>(),
        )
    };
    let saved_errno = errno();
    drop(translator);

    let header = match if result >= 0 {
        Header::success(result)
    } else {
        Header::failure(saved_errno)
    }
    .and_then(Header::encode)
    {
        Ok(header) => header,
        Err(_) => return Err(failure(Stage::Capture, diagnostic)),
    };

    if write_all(data.raw(), &header, deadline).is_err() {
        return Err(failure(Stage::FrameWrite, diagnostic));
    }
    if result >= 0 && write_all(data.raw(), &payload, deadline).is_err() {
        return Err(failure(Stage::FrameWrite, diagnostic));
    }
    drop(data);
    Ok(diagnostic)
}

fn mount_filesystems() -> Result<(), i32> {
    for path in [c"/dev", c"/proc", c"/sys", c"/mnt", c"/mnt/rosetta"] {
        mkdir(path.as_ptr())?;
    }
    mount(c"devtmpfs", c"/dev", c"devtmpfs", 0)?;
    mount(c"proc", c"/proc", c"proc", 0)?;
    mount(c"sysfs", c"/sys", c"sysfs", 0)
}

fn mount_rosetta(deadline: Deadline) -> Result<(), i32> {
    let flags =
        libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NOATIME;
    loop {
        match mount(c"rosetta", c"/mnt/rosetta", c"virtiofs", flags) {
            Ok(()) => return Ok(()),
            Err(error) if error == libc::ENOENT || error == libc::ENODEV => wait_retry(deadline)?,
            Err(error) => return Err(error),
        }
    }
}

fn mount(
    source: &core::ffi::CStr,
    target: &core::ffi::CStr,
    filesystem: &core::ffi::CStr,
    flags: libc::c_ulong,
) -> Result<(), i32> {
    // libc is required for mount(2); nix is deliberately absent from this fixed-buffer appliance.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags,
            ptr::null(),
        )
    };
    syscall_result(result)
}

fn mkdir(path: *const c_char) -> Result<(), i32> {
    let result = unsafe { libc::mkdir(path, 0o755) };
    let saved_errno = errno();
    if result == 0 || saved_errno == libc::EEXIST {
        Ok(())
    } else {
        Err(saved_errno)
    }
}

fn open_retry(path: *const c_char, deadline: Deadline) -> Result<c_int, i32> {
    loop {
        match open(
            path,
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK,
        ) {
            Ok(fd) => return Ok(fd),
            Err(error) if error == libc::ENOENT || error == libc::ENODEV => wait_retry(deadline)?,
            Err(error) => return Err(error),
        }
    }
}

fn open_readonly(path: *const c_char) -> Result<c_int, i32> {
    open(path, libc::O_RDONLY | libc::O_CLOEXEC)
}

fn open(path: *const c_char, flags: c_int) -> Result<c_int, i32> {
    let fd = unsafe { libc::open(path, flags) };
    if fd >= 0 {
        Ok(fd)
    } else {
        Err(errno())
    }
}

fn configure_data_port(fd: c_int) -> Result<(), i32> {
    let mut termios = unsafe { core::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
        return Err(errno());
    }
    unsafe { libc::cfmakeraw(&mut termios) };
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(errno());
    }
    set_nonblocking(fd)
}

fn set_nonblocking(fd: c_int) -> Result<(), i32> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(errno());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(errno());
    }
    Ok(())
}

fn write_all(fd: c_int, bytes: &[u8], deadline: Deadline) -> Result<(), ProbeError> {
    let mut progress = WriteProgress::new(bytes.len());
    while progress.remaining() > 0 {
        if deadline.remaining_ms().is_err() {
            progress.update(WriteEvent::Deadline)?;
        }
        let remaining = &bytes[progress.written()..];
        let written =
            unsafe { libc::write(fd, remaining.as_ptr().cast::<c_void>(), remaining.len()) };
        let event = if written > 0 {
            WriteEvent::Written(written as usize)
        } else if written == 0 {
            WriteEvent::Written(0)
        } else {
            match errno() {
                libc::EINTR => WriteEvent::Interrupted,
                libc::EAGAIN => WriteEvent::WouldBlock,
                error => WriteEvent::System(error),
            }
        };
        if progress.update(event)? == WriteAction::WaitWritable {
            poll_writable(fd, deadline).map_err(|error| ProbeError {
                stage: Stage::FrameWrite,
                kind: if error == libc::ETIMEDOUT {
                    ErrorKind::Deadline
                } else {
                    ErrorKind::System
                },
                errno: error,
            })?;
        }
    }
    Ok(())
}

fn write_failure(fd: c_int, errno: i32, deadline: Deadline) -> Result<(), ProbeError> {
    let header = Header::failure(errno)
        .and_then(Header::encode)
        .map_err(|_| ProbeError {
            stage: Stage::FrameWrite,
            kind: ErrorKind::InvalidFrame,
            errno,
        })?;
    write_all(fd, &header, deadline)
}

fn poll_writable(fd: c_int, deadline: Deadline) -> Result<(), i32> {
    loop {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, deadline.remaining_ms()?) };
        if result > 0 && pollfd.revents & libc::POLLOUT != 0 {
            return Ok(());
        }
        if result > 0 {
            return Err(libc::EIO);
        }
        if result == 0 {
            return Err(libc::ETIMEDOUT);
        }
        if result < 0 && errno() != libc::EINTR {
            return Err(errno());
        }
    }
}

fn wait_retry(deadline: Deadline) -> Result<(), i32> {
    let timeout = core::cmp::min(deadline.remaining_ms()?, 20);
    let result = unsafe { libc::poll(ptr::null_mut(), 0, timeout) };
    if result >= 0 || errno() == libc::EINTR {
        Ok(())
    } else {
        Err(errno())
    }
}

fn monotonic() -> Result<libc::timespec, i32> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0 {
        Ok(time)
    } else {
        Err(errno())
    }
}

fn syscall_result(result: c_int) -> Result<(), i32> {
    if result == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

const fn failure(stage: Stage, diagnostic: Diagnostic) -> RuntimeError {
    OwnedFailure::new(stage, diagnostic)
}

fn report(fd: c_int, stage: Stage) {
    let message: &[u8] = match stage {
        Stage::Filesystems => b"rprobe: filesystem setup failed\n",
        Stage::DiagnosticPort => b"rprobe: diagnostic port failed\n",
        Stage::DataPort => b"rprobe: data port failed\n",
        Stage::RosettaMount => b"rprobe: rosetta mount failed\n",
        Stage::RosettaFile => b"rprobe: rosetta file open failed\n",
        Stage::Capture => b"rprobe: capture failed\n",
        Stage::FrameWrite => b"rprobe: frame write failed\n",
        Stage::Poweroff => b"rprobe: panic or poweroff failed\n",
    };
    unsafe { libc::write(fd, message.as_ptr().cast::<c_void>(), message.len()) };
}

fn poweroff(diagnostic: Diagnostic) -> ! {
    unsafe { libc::reboot(libc::RB_POWER_OFF) };
    report(diagnostic.raw(), Stage::Poweroff);
    drop(diagnostic);
    loop {
        unsafe { libc::pause() };
    }
}

fn finish(result: Result<Diagnostic, RuntimeError>) -> ! {
    match result {
        Ok(diagnostic) => poweroff(diagnostic),
        Err(error) => {
            let (stage, diagnostic) = error.into_parts();
            report(diagnostic.raw(), stage);
            poweroff(diagnostic)
        }
    }
}

pub(crate) fn execute() -> ! {
    finish(run())
}

pub(crate) fn panic_poweroff() -> ! {
    let diagnostic = Diagnostic::stderr();
    report(diagnostic.raw(), Stage::Poweroff);
    poweroff(diagnostic)
}
