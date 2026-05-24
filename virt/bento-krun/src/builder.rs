use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use bento_utils::format_mac;
use nix::pty::openpty;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};

use crate::config::{validate_config, Disk, KrunConfig, Network};
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

#[derive(Debug, Clone)]
pub struct VirtualMachineBuilder {
    krun_binary: PathBuf,
    config: KrunConfig,
}

impl VirtualMachineBuilder {
    pub fn new(krun_binary: impl Into<PathBuf>) -> Self {
        Self {
            krun_binary: krun_binary.into(),
            config: KrunConfig::default(),
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

    pub fn vsock_port(mut self, port: crate::VsockPort) -> Self {
        self.config.vsock_ports.push(port);
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

    pub fn build(self) -> Result<KrunConfig> {
        validate_config(&self.config)?;
        Ok(self.config)
    }

    pub fn start(self) -> Result<VirtualMachine> {
        validate_config(&self.config)?;

        let args = command_args(&self.config);
        let (watchdog_fd, watchdog_keepalive) = crate::watchdog::create()?;
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

impl Default for VirtualMachineBuilder {
    fn default() -> Self {
        Self::new("krun")
    }
}

pub(crate) fn command_args(config: &KrunConfig) -> Vec<OsString> {
    let mut args = Vec::new();
    push_arg(&mut args, "--id", &config.id);
    push_arg(&mut args, "--cpus", config.cpus.to_string());
    push_arg(&mut args, "--memory-mib", config.memory_mib.to_string());

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
    for port in &config.vsock_ports {
        push_arg(&mut args, "--vsock-port", format_vsock_port(port));
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

fn format_vsock_port(port: &crate::VsockPort) -> String {
    format!(
        "{}:{}:{}",
        port.port,
        port.path.display(),
        if port.listen { "connect" } else { "listen" }
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
    use std::path::PathBuf;

    use crate::{Disk, VirtualMachineBuilder};

    use crate::builder::{command_args, format_command};

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

        let args = command_args(&config);

        assert!(!args.iter().any(|arg| arg == "run"));
        assert!(args.iter().any(|arg| arg == "--stdio-console"));
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

        let args = command_args(&config);

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
