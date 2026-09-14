use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::libc;
use nix::pty::openpty;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};
use utils::format_mac;

use crate::config::{validate_config, Disk, KrunConfig, Network};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::error::KrunBackendError;
use crate::error::Result;
use crate::serial::SerialConnection;
use crate::vm::VirtualMachine;

#[derive(Debug)]
struct KrunSerialPty {
    child_stdin: Stdio,
    child_stdout: Stdio,
    child_stderr: Stdio,
    serial: SerialConnection,
}

#[derive(Debug)]
pub struct VirtualMachineBuilder {
    krun_binary: PathBuf,
    config: KrunConfig,
    vsock_mux_fd: Option<OwnedFd>,
}

impl VirtualMachineBuilder {
    pub fn new(krun_binary: impl Into<PathBuf>) -> Self {
        Self {
            krun_binary: krun_binary.into(),
            config: KrunConfig::default(),
            vsock_mux_fd: None,
        }
    }

    pub fn cpus(mut self, cpus: u8) -> Self {
        self.config.cpus = cpus;
        self
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.config.id = id.into();
        self
    }

    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.config.memory_mib = memory_mib;
        self
    }

    pub fn kernel(mut self, kernel: impl Into<PathBuf>) -> Self {
        self.config.kernel = Some(kernel.into());
        self
    }

    pub fn initramfs(mut self, initramfs: impl Into<PathBuf>) -> Self {
        self.config.initramfs = Some(initramfs.into());
        self
    }

    pub fn cmdline(mut self, args: Vec<String>) -> Self {
        self.config.cmdline = args;
        self
    }

    pub fn disk(mut self, disk: Disk) -> Self {
        self.config.disks.push(disk);
        self
    }

    pub fn mount(mut self, mount: crate::Mount) -> Self {
        self.config.mounts.push(mount);
        self
    }

    pub fn vsock_mux_fd(mut self, fd: OwnedFd) -> Self {
        self.config.vsock_mux = true;
        self.vsock_mux_fd = Some(fd);
        self
    }

    pub fn net_unixgram(mut self, net: crate::NetUnixgram) -> Self {
        self.config.network = Network::Unixgram(net);
        self
    }

    pub fn net_unixstream(mut self, net: crate::NetUnixstream) -> Self {
        self.config.network = Network::Unixstream(net);
        self
    }

    pub fn net_tap(mut self, net: crate::NetTap) -> Self {
        self.config.network = Network::Tap(net);
        self
    }

    pub fn network_none(mut self) -> Self {
        self.config.network = Network::None;
        self
    }

    pub fn stdio_console(mut self, enabled: bool) -> Self {
        self.config.stdio_console = enabled;
        self
    }

    pub fn host_memory_reclaim(mut self, enabled: bool) -> Self {
        self.config.host_memory_reclaim = enabled;
        self
    }

    pub fn build(self) -> Result<KrunConfig> {
        validate_config(&self.config)?;
        Ok(self.config)
    }

    pub fn start(mut self) -> Result<VirtualMachine> {
        validate_config(&self.config)?;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        check_krun_host(&self.krun_binary)?;

        self.vsock_mux_fd = self
            .vsock_mux_fd
            .take()
            .map(normalize_child_fd)
            .transpose()?;
        let (watchdog_fd, watchdog_keepalive) = crate::watchdog::create()?;
        let watchdog_fd = normalize_child_fd(watchdog_fd)?;
        let args = command_args(&self.config, self.vsock_mux_fd.as_ref());
        let mut command = Command::new(&self.krun_binary);
        for arg in &args {
            command.arg(arg);
        }
        command.env(
            crate::watchdog::ENV_WATCHDOG_FD,
            crate::watchdog::fd_env_value(&watchdog_fd),
        );
        let serial = if self.config.stdio_console {
            let serial_pty = open_krun_serial_pty()?;
            command
                .stdin(serial_pty.child_stdin)
                .stdout(serial_pty.child_stdout)
                .stderr(serial_pty.child_stderr);
            Some(serial_pty.serial)
        } else {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            None
        };
        install_child_fd_allowlist(&mut command, &watchdog_fd, self.vsock_mux_fd.as_ref())?;

        tracing::debug!(command = %format_command(self.krun_binary.as_os_str(), &args), "launching krun backend");

        let child = command.spawn()?;
        drop(watchdog_fd);
        Ok(VirtualMachine::new(
            child,
            self.krun_binary,
            self.config,
            serial,
            Some(watchdog_keepalive),
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn check_krun_host(binary: &std::path::Path) -> Result<()> {
    let output = Command::new(binary)
        .arg("--check-host-basic")
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let message = if stderr.is_empty() { stdout } else { stderr };
    Err(KrunBackendError::HostCheck {
        binary: binary.display().to_string(),
        status: output.status.to_string(),
        message: if message.is_empty() {
            "helper returned no diagnostic output".to_string()
        } else {
            message
        },
    })
}

impl Default for VirtualMachineBuilder {
    fn default() -> Self {
        Self::new("krun")
    }
}

pub(crate) fn command_args(config: &KrunConfig, vsock_mux_fd: Option<&OwnedFd>) -> Vec<OsString> {
    let mut args = Vec::new();
    push_arg(&mut args, "--id", &config.id);
    push_arg(&mut args, "--cpus", config.cpus.to_string());
    push_arg(&mut args, "--memory-mib", config.memory_mib.to_string());
    push_arg(
        &mut args,
        "--host-memory-reclaim",
        if config.host_memory_reclaim {
            "on"
        } else {
            "off"
        },
    );

    if let Some(kernel) = config.kernel.as_ref() {
        push_arg(&mut args, "--kernel", kernel.as_os_str());
    }
    if let Some(initramfs) = config.initramfs.as_ref() {
        push_arg(&mut args, "--initramfs", initramfs.as_os_str());
    }
    for arg in &config.cmdline {
        push_arg(&mut args, "--cmdline", arg);
    }
    for disk in &config.disks {
        push_arg(&mut args, "--disk", format_disk(disk));
    }
    for mount in &config.mounts {
        push_arg(&mut args, "--mount", format_mount(mount));
    }
    if let Some(fd) = vsock_mux_fd {
        push_arg(&mut args, "--vsock-mux-fd", fd.as_raw_fd().to_string());
    }
    match &config.network {
        Network::None => {
            push_arg(&mut args, "--network", "none");
        }
        Network::Unixgram(net) => {
            push_arg(&mut args, "--network", "unixgram");
            push_arg(&mut args, "--net-peer", net.peer_path.as_os_str());
            push_arg(&mut args, "--net-mac", format_mac(net.mac));
        }
        Network::Unixstream(net) => {
            push_arg(&mut args, "--network", "unixstream");
            push_arg(&mut args, "--net-peer", net.peer_path.as_os_str());
            push_arg(&mut args, "--net-mac", format_mac(net.mac));
        }
        Network::Tap(net) => {
            push_arg(&mut args, "--network", "tap");
            push_arg(&mut args, "--net-tap-name", &net.name);
            push_arg(&mut args, "--net-mac", format_mac(net.mac));
        }
    }
    if config.stdio_console {
        args.push("--stdio-console".into());
    }
    args
}

fn install_child_fd_allowlist(
    command: &mut Command,
    watchdog_fd: &OwnedFd,
    vsock_mux_fd: Option<&OwnedFd>,
) -> io::Result<()> {
    let watchdog_fd = watchdog_fd.as_raw_fd();
    let vsock_mux_fd = vsock_mux_fd.map(AsRawFd::as_raw_fd).unwrap_or(-1);
    // SAFETY: child setup uses only raw OS descriptor operations. OS errors are
    // represented inline by from_raw_os_error, so this path does not allocate.
    unsafe {
        command.pre_exec(move || {
            mark_child_fds_cloexec()?;
            for fd in [watchdog_fd, vsock_mux_fd] {
                if fd >= 3 {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(child_last_os_error());
                    }
                }
            }
            Ok(())
        });
    }
    Ok(())
}

fn normalize_child_fd(fd: OwnedFd) -> io::Result<OwnedFd> {
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

fn format_command(binary: &OsStr, args: &[OsString]) -> String {
    std::iter::once(binary)
        .chain(args.iter().map(OsString::as_os_str))
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value.is_empty() {
        return "''".to_string();
    }
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'_' | b'-' | b'.' | b'/' | b':' | b',' | b'=' | b'@' | b'+'
            )
    }) {
        return value.into_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn push_arg(value: &mut Vec<OsString>, name: impl Into<OsString>, arg: impl Into<OsString>) {
    value.push(name.into());
    value.push(arg.into());
}

fn format_disk(disk: &Disk) -> String {
    format!(
        "{}:{}:{}",
        disk.block_id,
        disk.path.display(),
        format_ro(disk.read_only)
    )
}

fn format_mount(mount: &crate::Mount) -> String {
    format!(
        "{}:{}:{}",
        mount.tag,
        mount.path.display(),
        format_ro(mount.read_only)
    )
}

fn format_ro(read_only: bool) -> &'static str {
    if read_only {
        "ro"
    } else {
        "rw"
    }
}

fn open_krun_serial_pty() -> io::Result<KrunSerialPty> {
    let pty = openpty(None, None).map_err(io::Error::other)?;
    let mut termios = tcgetattr(&pty.slave).map_err(io::Error::other)?;
    cfmakeraw(&mut termios);
    tcsetattr(&pty.slave, SetArg::TCSANOW, &termios).map_err(io::Error::other)?;

    let master = File::from(pty.master);
    let slave = File::from(pty.slave);

    // libkrun checks isatty(0/1/2). The helper must see a real TTY or hvc0
    // does not get wired to stdin/stdout/stderr.
    Ok(KrunSerialPty {
        child_stdin: Stdio::from(slave.try_clone()?),
        child_stdout: Stdio::from(slave.try_clone()?),
        child_stderr: Stdio::from(slave),
        serial: SerialConnection::new(master.try_clone()?, master),
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::path::PathBuf;

    use nix::libc;

    use crate::{Disk, KrunConfig, VirtualMachineBuilder};

    #[cfg(target_os = "macos")]
    use crate::builder::parse_darwin_fd_record;
    use crate::builder::{
        command_args, format_command, install_child_fd_allowlist, normalize_child_fd,
    };

    #[cfg(target_os = "macos")]
    fn darwin_dirent_bytes(name: &[u8]) -> Vec<u8> {
        let reclen_offset = std::mem::offset_of!(libc::dirent, d_reclen);
        let namlen_offset = std::mem::offset_of!(libc::dirent, d_namlen);
        let name_offset = std::mem::offset_of!(libc::dirent, d_name);
        let record_len = name_offset + name.len();
        let mut bytes = vec![0_u8; record_len];
        bytes[reclen_offset..reclen_offset + 2].copy_from_slice(&(record_len as u16).to_ne_bytes());
        bytes[namlen_offset..namlen_offset + 2].copy_from_slice(&(name.len() as u16).to_ne_bytes());
        bytes[name_offset..].copy_from_slice(name);
        bytes
    }

    #[test]
    fn builder_rejects_zero_cpus() {
        let err = VirtualMachineBuilder::new("krun")
            .cpus(0)
            .kernel("/kernel")
            .build()
            .expect_err("zero cpus should be invalid");
        assert!(err.to_string().contains("vCPU"));
    }

    #[test]
    fn builder_accepts_disks() {
        let config = VirtualMachineBuilder::new("krun")
            .kernel("/kernel")
            .disk(Disk {
                block_id: "root".to_string(),
                path: PathBuf::from("/root.img"),
                read_only: false,
            })
            .build()
            .expect("config should be valid");
        assert_eq!(config.disks.len(), 1);
    }

    #[test]
    fn start_arguments_are_flat_krun_arguments() {
        let config = VirtualMachineBuilder::new("krun")
            .cpus(2)
            .memory_mib(1024)
            .kernel("/kernel")
            .stdio_console(true)
            .build()
            .expect("config should be valid");

        let args = command_args(&config, None);

        assert!(!args.iter().any(|arg| arg == "run"));
        assert!(args.iter().any(|arg| arg == "--stdio-console"));
        assert!(args.windows(2).any(|pair| {
            pair == [
                std::ffi::OsString::from("--host-memory-reclaim"),
                std::ffi::OsString::from("off"),
            ]
        }));
    }

    #[test]
    fn start_arguments_request_host_memory_reclaim_explicitly() {
        let config = VirtualMachineBuilder::new("krun")
            .kernel("/kernel")
            .host_memory_reclaim(true)
            .build()
            .expect("config should be valid");

        let args = command_args(&config, None);
        assert!(args.windows(2).any(|pair| {
            pair == [
                std::ffi::OsString::from("--host-memory-reclaim"),
                std::ffi::OsString::from("on"),
            ]
        }));
    }

    #[test]
    fn start_arguments_include_unixgram_networks() {
        let config = VirtualMachineBuilder::new("krun")
            .cpus(2)
            .memory_mib(1024)
            .id("vm123")
            .kernel("/kernel")
            .net_unixgram(crate::NetUnixgram {
                peer_path: PathBuf::from("/tmp/gvproxy.sock"),
                mac: [0x02, 0x94, 0xef, 0xe4, 0x0c, 0xee],
            })
            .build()
            .expect("config should be valid");

        let args = command_args(&config, None);

        assert!(args.iter().any(|arg| arg == "--network"));
        assert!(args.iter().any(|arg| arg == "unixgram"));
        assert!(args.iter().any(|arg| arg == "--net-peer"));
        assert!(args.iter().any(|arg| arg == "--net-mac"));
        assert!(args.iter().any(|arg| arg == "--id"));
        assert!(args.iter().any(|arg| arg == "vm123"));
        assert!(args.iter().any(|arg| arg == "/tmp/gvproxy.sock"));
        assert!(args.iter().any(|arg| arg == "02:94:ef:e4:0c:ee"));
    }

    #[test]
    fn start_arguments_attach_vsock_mux_fd() {
        let (fd, _peer) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let fd = OwnedFd::from(fd);
        let config = KrunConfig {
            kernel: Some(PathBuf::from("/kernel")),
            vsock_mux: true,
            ..KrunConfig::default()
        };

        let args = command_args(&config, Some(&fd));
        assert!(args.windows(2).any(|pair| {
            pair == [
                OsString::from("--vsock-mux-fd"),
                OsString::from(fd.as_raw_fd().to_string()),
            ]
        }));
        assert!(!args.iter().any(|argument| argument == "--vsock-port"));
    }

    #[test]
    fn child_inherits_only_allowlisted_private_descriptors() {
        use std::process::Command;

        let (mux, _mux_peer) = std::os::unix::net::UnixStream::pair().expect("mux pair");
        let mux = OwnedFd::from(mux);
        let (watchdog, _keepalive) = crate::watchdog::create().expect("watchdog");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("test -e /dev/fd/$MUX && test -e /dev/fd/$WATCHDOG && test ! -e /dev/fd/$AMBIENT")
            .env("MUX", mux.as_raw_fd().to_string())
            .env("WATCHDOG", watchdog.as_raw_fd().to_string());
        install_child_fd_allowlist(&mut command, &watchdog, Some(&mux)).expect("child setup");
        let (ambient, _ambient_peer) =
            std::os::unix::net::UnixStream::pair().expect("late ambient pair");
        let flags =
            nix::fcntl::fcntl(&ambient, nix::fcntl::FcntlArg::F_GETFD).expect("read ambient flags");
        nix::fcntl::fcntl(
            &ambient,
            nix::fcntl::FcntlArg::F_SETFD(
                nix::fcntl::FdFlag::from_bits_retain(flags)
                    .difference(nix::fcntl::FdFlag::FD_CLOEXEC),
            ),
        )
        .expect("make late ambient descriptor inheritable");
        command.env("AMBIENT", ambient.as_raw_fd().to_string());

        assert!(command.status().expect("run descriptor probe").success());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_fd_record_parser_handles_minimum_and_maximum_records() {
        let minimum = darwin_dirent_bytes(b"3");
        assert_eq!(
            parse_darwin_fd_record(&minimum),
            Ok((minimum.len(), Some(3)))
        );
        let largest_fd = darwin_dirent_bytes(i32::MAX.to_string().as_bytes());
        assert_eq!(
            parse_darwin_fd_record(&largest_fd),
            Ok((largest_fd.len(), Some(i32::MAX)))
        );

        let maximum_name = darwin_dirent_bytes(&vec![b'x'; 1024]);
        assert_eq!(
            parse_darwin_fd_record(&maximum_name),
            Ok((maximum_name.len(), None))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_fd_record_parser_rejects_truncated_and_invalid_lengths() {
        let name_offset = std::mem::offset_of!(libc::dirent, d_name);
        assert_eq!(
            parse_darwin_fd_record(&vec![0_u8; name_offset - 1]),
            Err(())
        );

        let mut truncated = darwin_dirent_bytes(b"42");
        let reclen_offset = std::mem::offset_of!(libc::dirent, d_reclen);
        let declared = (truncated.len() + 1) as u16;
        truncated[reclen_offset..reclen_offset + 2].copy_from_slice(&declared.to_ne_bytes());
        assert_eq!(parse_darwin_fd_record(&truncated), Err(()));

        let mut name_overruns_record = darwin_dirent_bytes(b"42");
        let namlen_offset = std::mem::offset_of!(libc::dirent, d_namlen);
        name_overruns_record[namlen_offset..namlen_offset + 2]
            .copy_from_slice(&3_u16.to_ne_bytes());
        assert_eq!(parse_darwin_fd_record(&name_overruns_record), Err(()));

        let oversized_name = darwin_dirent_bytes(&vec![b'x'; 1025]);
        assert_eq!(parse_darwin_fd_record(&oversized_name), Err(()));
    }

    #[test]
    fn child_fd_allowlist_preserves_spawn_error_reporting() {
        let (watchdog, _keepalive) = crate::watchdog::create().expect("watchdog");
        let mut command = std::process::Command::new("/definitely/missing/silo-krun-helper");
        install_child_fd_allowlist(&mut command, &watchdog, None).expect("child setup");

        assert_eq!(
            command
                .spawn()
                .expect_err("missing executable must be reported")
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn child_fds_are_normalized_when_parent_stdio_is_closed() {
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("builder::tests::closed_stdio_normalization_fixture")
            .arg("--ignored")
            .env("SILO_CLOSED_STDIO_FIXTURE", "1")
            .status()
            .expect("run isolated closed-stdio fixture");
        assert!(status.success());
    }

    #[test]
    #[ignore]
    fn closed_stdio_normalization_fixture() {
        if std::env::var_os("SILO_CLOSED_STDIO_FIXTURE").is_none() {
            return;
        }
        for fd in 0..=2 {
            unsafe { libc::close(fd) };
        }
        let (mux, _peer) = std::os::unix::net::UnixStream::pair().expect("low mux pair");
        let mux = normalize_child_fd(OwnedFd::from(mux)).expect("normalize mux");
        let (watchdog, _keepalive) = crate::watchdog::create().expect("low watchdog");
        let watchdog = normalize_child_fd(watchdog).expect("normalize watchdog");
        let valid = mux.as_raw_fd() >= 3 && watchdog.as_raw_fd() >= 3;
        unsafe { libc::_exit(i32::from(!valid)) }
    }

    #[test]
    fn format_command_shell_quotes_copy_pasteable_arguments() {
        let args = vec![
            "--kernel".into(),
            "/tmp/kernel image".into(),
            "--cmdline".into(),
            "console='hvc0'".into(),
        ];

        assert_eq!(
            format_command(OsStr::new("/tmp/krun helper"), &args),
            "'/tmp/krun helper' --kernel '/tmp/kernel image' --cmdline 'console='\\''hvc0'\\'''"
        );
    }
}
