use std::fs;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use krun::{validate_config, KrunConfig, NetTap, NetUnixgram, NetUnixstream, Network, DEFAULT_ID};
use nix::sys::socket::{setsockopt, sockopt};

#[path = "krun/admission.rs"]
mod admission;
#[path = "../internal/parse.rs"]
mod parse;
#[path = "krun/vmm.rs"]
mod vmm;
#[path = "../watchdog.rs"]
mod watchdog;

const LOCAL_SOCKET_ID_LEN: usize = 12;
const DEFAULT_SOCKET_BUF_SIZE: usize = 7 * 1024 * 1024;
const SOCKET_RCVBUF: usize = DEFAULT_SOCKET_BUF_SIZE;

#[cfg(target_os = "macos")]
const SOCKET_SNDBUF: usize = 65_562 - 12;

#[cfg(not(target_os = "macos"))]
const SOCKET_SNDBUF: usize = DEFAULT_SOCKET_BUF_SIZE;

#[derive(Debug, Parser)]
#[command(
    name = "krun",
    about = "Silo libkrun helper",
    after_help = "Examples:\n  krun --kernel ./vmlinux --initramfs ./initramfs.img --network none\n  krun --kernel ./vmlinux --net-peer \"$TMPDIR/gvproxy.sock\" --net-mac 02:94:ef:e4:0c:ee --network unixgram\n  krun --kernel ./vmlinux --net-peer \"$TMPDIR/passt.sock\" --net-mac 02:94:ef:e4:0c:ef --network unixstream\n  krun --kernel ./vmlinux --net-tap-name tap0 --net-mac 02:94:ef:e4:0c:f0 --network tap\n"
)]
struct Cli {
    /// Validate host virtualization access and empty VM creation.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(long, exclusive = true)]
    check_host: bool,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(long, exclusive = true, hide = true)]
    check_host_basic: bool,
    /// Stable VM identifier used for helper-owned socket names.
    #[arg(long, default_value = DEFAULT_ID)]
    id: String,
    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    cpus: u8,
    /// Guest memory size in MiB.
    #[arg(long, default_value_t = 512)]
    memory_mib: u32,
    /// Linux kernel image path.
    #[arg(long)]
    kernel: Option<PathBuf>,
    /// Optional initramfs image path.
    #[arg(long)]
    initramfs: Option<PathBuf>,
    /// Extra kernel command-line fragment. May be passed multiple times.
    #[arg(long = "cmdline")]
    cmdline: Vec<String>,
    /// Add a raw virtio-blk disk. Format: BLOCK_ID:PATH:ro|rw.
    #[arg(long = "disk", value_parser = parse::disk)]
    disks: Vec<krun::Disk>,
    /// Add a virtiofs mount. Format: TAG:PATH:ro|rw.
    #[arg(long = "mount", value_parser = parse::mount)]
    mounts: Vec<krun::Mount>,
    /// Attach a vhost-user virtio-vsock device at this Unix socket.
    #[arg(long = "vhost-user-vsock", conflicts_with = "vsock_cid")]
    vhost_user_vsock: Option<PathBuf>,
    /// Attach a standalone native virtio-vsock device with this guest CID.
    #[arg(
        long = "vsock-cid",
        hide = true,
        conflicts_with = "vhost_user_vsock",
        value_parser = clap::value_parser!(u64).range(3..=3)
    )]
    vsock_cid: Option<u64>,
    /// Explicit networking backend. Defaults to no guest networking.
    #[arg(long = "network", value_enum, default_value_t = NetworkArg::None)]
    network: NetworkArg,
    /// Userspace network socket path for unixgram or unixstream networking.
    #[arg(long = "net-peer")]
    net_peer: Option<PathBuf>,
    /// Guest virtio-net MAC address for unixgram, unixstream, or tap networking.
    #[arg(long = "net-mac", value_parser = parse::mac)]
    net_mac: Option<[u8; 6]>,
    /// Host TAP interface name for tap networking. Linux only.
    #[arg(long = "net-tap-name")]
    net_tap_name: Option<String>,
    /// Attach stdin/stdout/stderr to an explicit hvc0 virtio console.
    #[arg(long)]
    stdio_console: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum NetworkArg {
    None,
    Unixgram,
    Unixstream,
    Tap,
}

impl Cli {
    fn into_config(self) -> eyre::Result<KrunConfig> {
        let network = self.network()?;
        reject_unused_network_args(
            &network,
            self.net_peer.as_ref(),
            self.net_mac,
            self.net_tap_name.as_deref(),
        )?;

        Ok(KrunConfig {
            id: self.id,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            kernel: self.kernel,
            initramfs: self.initramfs,
            cmdline: self.cmdline,
            disks: self.disks,
            mounts: self.mounts,
            vhost_user_vsock: self.vhost_user_vsock,
            vsock_cid: self.vsock_cid,
            network,
            stdio_console: self.stdio_console,
        })
    }

    fn network(&self) -> eyre::Result<Network> {
        match self.network {
            NetworkArg::None => Ok(Network::None),
            NetworkArg::Unixgram => Ok(Network::Unixgram(NetUnixgram {
                peer_path: required_path(self.net_peer.as_ref(), "--net-peer", "unixgram")?,
                mac: required_mac(self.net_mac, "unixgram")?,
            })),
            NetworkArg::Unixstream => Ok(Network::Unixstream(NetUnixstream {
                peer_path: required_path(self.net_peer.as_ref(), "--net-peer", "unixstream")?,
                mac: required_mac(self.net_mac, "unixstream")?,
            })),
            NetworkArg::Tap => Ok(Network::Tap(NetTap {
                name: required_string(self.net_tap_name.as_deref(), "--net-tap-name", "tap")?,
                mac: required_mac(self.net_mac, "tap")?,
            })),
        }
    }
}

fn required_path(
    path: Option<&PathBuf>,
    flag: &'static str,
    mode: &'static str,
) -> eyre::Result<PathBuf> {
    path.cloned()
        .ok_or_else(|| eyre::eyre!("--network {mode} requires {flag}"))
}

fn required_string(
    value: Option<&str>,
    flag: &'static str,
    mode: &'static str,
) -> eyre::Result<String> {
    value
        .map(ToOwned::to_owned)
        .ok_or_else(|| eyre::eyre!("--network {mode} requires {flag}"))
}

fn required_mac(mac: Option<[u8; 6]>, mode: &'static str) -> eyre::Result<[u8; 6]> {
    mac.ok_or_else(|| eyre::eyre!("--network {mode} requires --net-mac"))
}

fn reject_unused_network_args(
    network: &Network,
    net_peer: Option<&PathBuf>,
    net_mac: Option<[u8; 6]>,
    net_tap_name: Option<&str>,
) -> eyre::Result<()> {
    match network {
        Network::None => {
            reject_arg(net_peer.is_some(), "--net-peer", "--network none")?;
            reject_arg(net_mac.is_some(), "--net-mac", "--network none")?;
            reject_arg(net_tap_name.is_some(), "--net-tap-name", "--network none")?;
        }
        Network::Unixgram(_) | Network::Unixstream(_) => {
            reject_arg(
                net_tap_name.is_some(),
                "--net-tap-name",
                "unix socket networking",
            )?;
        }
        Network::Tap(_) => {
            reject_arg(net_peer.is_some(), "--net-peer", "--network tap")?;
        }
    }
    Ok(())
}

fn reject_arg(present: bool, flag: &'static str, mode: &'static str) -> eyre::Result<()> {
    if present {
        eyre::bail!("{flag} cannot be used with {mode}");
    }
    Ok(())
}

fn main() -> eyre::Result<()> {
    watchdog::start_from_env();
    let cli = Cli::parse();
    #[cfg(target_os = "linux")]
    {
        if cli.check_host {
            let info = krun::check_host_with_vm_creation()
                .map_err(|error| eyre::eyre!("krun host check failed: {error}"))?;
            println!(
                "KVM host check passed: API version {}; required capabilities available; empty VM creation succeeded",
                info.api_version
            );
            return Ok(());
        }
        if cli.check_host_basic {
            krun::check_host().map_err(|error| eyre::eyre!("krun host check failed: {error}"))?;
            return Ok(());
        }
        krun::check_host().map_err(|error| eyre::eyre!("krun host check failed: {error}"))?;
    }
    #[cfg(target_os = "macos")]
    {
        if cli.check_host {
            admission::check_hvf()
                .map_err(|error| eyre::eyre!("krun host check failed: {error}"))?;
            println!(
                "Hypervisor.framework host check passed: kern.hv_support=1; empty VM creation and destruction succeeded"
            );
            return Ok(());
        }
        if cli.check_host_basic {
            admission::check_hvf()
                .map_err(|error| eyre::eyre!("krun host check failed: {error}"))?;
            return Ok(());
        }
        admission::check_hvf().map_err(|error| eyre::eyre!("krun host check failed: {error}"))?;
    }
    let config = cli.into_config()?;
    validate_config(&config)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    start_enter(
        &config,
        vmm::ConsoleFds {
            stdin: stdin.as_fd(),
            stdout: stdout.as_fd(),
            stderr: stderr.as_fd(),
        },
    )?;
    Ok(())
}

fn start_enter(config: &KrunConfig, console_fds: vmm::ConsoleFds<'_>) -> eyre::Result<()> {
    vmm::run(config, console_fds)?;
    Ok(())
}

fn open_local_unix_datagram_socket(
    peer_path: &Path,
    vm_id: &str,
    backend: &str,
) -> io::Result<UnixDatagram> {
    let local_path = local_unix_datagram_path(peer_path, vm_id, backend);
    remove_file_if_exists(&local_path)?;
    let socket = UnixDatagram::bind(&local_path)?;
    socket.connect(peer_path)?;
    configure_socket_buffers(&socket);
    Ok(socket)
}

fn configure_socket_buffers(socket: &UnixDatagram) {
    if let Err(err) = setsockopt(socket, sockopt::SndBuf, &SOCKET_SNDBUF) {
        tracing::warn!(error = %err, "failed to set krun unixgram SO_SNDBUF");
    }
    if let Err(err) = setsockopt(socket, sockopt::RcvBuf, &SOCKET_RCVBUF) {
        tracing::warn!(error = %err, "failed to set krun unixgram SO_RCVBUF");
    }
}

fn local_unix_datagram_path(peer_path: &Path, vm_id: &str, backend: &str) -> PathBuf {
    peer_path.with_file_name(format!("{}-{backend}.sock", local_socket_id(vm_id)))
}

fn local_socket_id(vm_id: &str) -> &str {
    vm_id.get(..LOCAL_SOCKET_ID_LEN).unwrap_or(vm_id)
}

fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use clap::Parser;

    use crate::local_unix_datagram_path;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::Cli;

    #[test]
    fn local_unix_datagram_path_uses_short_vm_id_and_backend() {
        assert_eq!(
            local_unix_datagram_path(
                Path::new("/tmp/silo-net/gvproxy.sock"),
                "1234567890abcdef",
                "krun"
            ),
            Path::new("/tmp/silo-net/1234567890ab-krun.sock")
        );
    }

    #[test]
    fn local_unix_datagram_path_keeps_short_vm_id() {
        assert_eq!(
            local_unix_datagram_path(Path::new("/tmp/silo-net/gvproxy.sock"), "vm123", "krun"),
            Path::new("/tmp/silo-net/vm123-krun.sock")
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn host_check_is_exclusive_with_vm_arguments() {
        assert!(Cli::try_parse_from(["krun", "--check-host"]).is_ok());
        assert!(Cli::try_parse_from(["krun", "--check-host", "--cpus", "2"]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_vhost_user_vsock() {
        let config = Cli::try_parse_from([
            "krun",
            "--kernel",
            "/kernel",
            "--vhost-user-vsock",
            "/tmp/vhost-vsock.sock",
        ])
        .expect("vhost-user argument should parse")
        .into_config()
        .expect("vhost-user argument should produce a config");

        assert_eq!(
            config.vhost_user_vsock.as_deref(),
            Some(Path::new("/tmp/vhost-vsock.sock"))
        );
    }

    #[test]
    fn parses_standalone_vsock_guest_cid() {
        let config = Cli::try_parse_from(["krun", "--kernel", "/kernel", "--vsock-cid", "3"])
            .expect("standalone vsock argument should parse")
            .into_config()
            .expect("standalone vsock argument should produce a config");

        assert_eq!(config.vsock_cid, Some(3));
    }

    #[test]
    fn rejects_standalone_and_vhost_user_vsock_together() {
        assert!(Cli::try_parse_from([
            "krun",
            "--kernel",
            "/kernel",
            "--vsock-cid",
            "3",
            "--vhost-user-vsock",
            "/tmp/vhost-vsock.sock",
        ])
        .is_err());
    }

    #[test]
    fn rejects_unsupported_standalone_vsock_guest_cid() {
        assert!(Cli::try_parse_from(["krun", "--kernel", "/kernel", "--vsock-cid", "4"]).is_err());
    }
}
