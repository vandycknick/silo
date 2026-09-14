use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
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
    /// Inherited Unix stream descriptor for the private vsock control mux.
    #[arg(long = "vsock-mux-fd", conflicts_with = "vsock_cid")]
    vsock_mux_fd: Option<RawFd>,
    /// Attach a standalone native virtio-vsock device with this guest CID.
    #[arg(
        long = "vsock-cid",
        hide = true,
        conflicts_with = "vsock_mux_fd",
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
    /// Request host memory reclaim after the startup qualification probe passes.
    #[arg(long, value_enum, default_value_t = HostMemoryReclaimArg::Off)]
    host_memory_reclaim: HostMemoryReclaimArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum NetworkArg {
    None,
    Unixgram,
    Unixstream,
    Tap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HostMemoryReclaimArg {
    On,
    Off,
}

impl Cli {
    fn into_launch(self) -> eyre::Result<(KrunConfig, Option<OwnedFd>)> {
        let network = self.network()?;
        reject_unused_network_args(
            &network,
            self.net_peer.as_ref(),
            self.net_mac,
            self.net_tap_name.as_deref(),
        )?;

        let vsock_mux_fd = self
            .vsock_mux_fd
            .map(validate_inherited_stream_fd)
            .transpose()?;
        Ok((
            KrunConfig {
                id: self.id,
                cpus: self.cpus,
                memory_mib: self.memory_mib,
                kernel: self.kernel,
                initramfs: self.initramfs,
                cmdline: self.cmdline,
                disks: self.disks,
                mounts: self.mounts,
                vsock_mux: vsock_mux_fd.is_some(),
                vsock_cid: self.vsock_cid,
                network,
                stdio_console: self.stdio_console,
                host_memory_reclaim: self.host_memory_reclaim == HostMemoryReclaimArg::On,
            },
            vsock_mux_fd,
        ))
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
    let watchdog_fd = watchdog::take_from_env()?;
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
    let (config, vsock_mux_fd) = cli.into_launch()?;
    validate_config(&config)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    start_enter(
        &config,
        vsock_mux_fd,
        watchdog_fd,
        vmm::ConsoleFds {
            stdin: stdin.as_fd(),
            stdout: stdout.as_fd(),
            stderr: stderr.as_fd(),
        },
    )?;
    Ok(())
}

fn start_enter(
    config: &KrunConfig,
    vsock_mux_fd: Option<OwnedFd>,
    watchdog_fd: Option<OwnedFd>,
    console_fds: vmm::ConsoleFds<'_>,
) -> eyre::Result<()> {
    vmm::run(config, vsock_mux_fd, watchdog_fd, console_fds)?;
    Ok(())
}

fn validate_inherited_stream_fd(fd: RawFd) -> eyre::Result<OwnedFd> {
    if fd < 0 {
        eyre::bail!("--vsock-mux-fd must name an open Unix stream socket");
    }
    // SAFETY: the numeric descriptor is transferred exactly once from argv ownership.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    nix::sys::stat::fstat(&fd)
        .map_err(|error| eyre::eyre!("--vsock-mux-fd is not open: {error}"))?;
    if nix::sys::socket::getsockopt(&fd, sockopt::SockType)? != nix::sys::socket::SockType::Stream
        || nix::sys::socket::getsockname::<nix::sys::socket::UnixAddr>(fd.as_fd().as_raw_fd())
            .is_err()
    {
        eyre::bail!("--vsock-mux-fd must name an open Unix stream socket");
    }
    let mut flags = nix::fcntl::FdFlag::from_bits_retain(nix::fcntl::fcntl(
        &fd,
        nix::fcntl::FcntlArg::F_GETFD,
    )?);
    flags.insert(nix::fcntl::FdFlag::FD_CLOEXEC);
    nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_SETFD(flags))?;
    Ok(fd)
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
    use std::os::fd::AsRawFd;
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

    #[test]
    fn parses_vsock_mux_fd() {
        use std::os::fd::IntoRawFd;

        let (fd, _peer) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let raw = fd.into_raw_fd();
        let (config, fd) = Cli::try_parse_from([
            "krun",
            "--kernel",
            "/kernel",
            "--vsock-mux-fd",
            &raw.to_string(),
        ])
        .expect("mux argument should parse")
        .into_launch()
        .expect("mux argument should produce a launch");

        assert!(config.vsock_mux);
        assert_eq!(fd.expect("owned mux fd").as_raw_fd(), raw);
    }

    #[test]
    fn parses_standalone_vsock_guest_cid() {
        let config = Cli::try_parse_from(["krun", "--kernel", "/kernel", "--vsock-cid", "3"])
            .expect("standalone vsock argument should parse")
            .into_launch()
            .map(|launch| launch.0)
            .expect("standalone vsock argument should produce a config");

        assert_eq!(config.vsock_cid, Some(3));
    }

    #[test]
    fn host_memory_reclaim_requires_an_explicit_on_value() {
        let default = Cli::try_parse_from(["krun", "--kernel", "/kernel"])
            .expect("default arguments should parse")
            .into_launch()
            .map(|launch| launch.0)
            .expect("default arguments should produce a config");
        let requested =
            Cli::try_parse_from(["krun", "--kernel", "/kernel", "--host-memory-reclaim=on"])
                .expect("host reclaim argument should parse")
                .into_launch()
                .map(|launch| launch.0)
                .expect("host reclaim argument should produce a config");

        assert!(!default.host_memory_reclaim);
        assert!(requested.host_memory_reclaim);
        assert!(
            Cli::try_parse_from(["krun", "--kernel", "/kernel", "--host-memory-reclaim",]).is_err()
        );
    }

    #[test]
    fn rejects_standalone_and_mux_vsock_together() {
        assert!(Cli::try_parse_from([
            "krun",
            "--kernel",
            "/kernel",
            "--vsock-cid",
            "3",
            "--vsock-mux-fd",
            "9",
        ])
        .is_err());
    }

    #[test]
    fn rejects_unsupported_standalone_vsock_guest_cid() {
        assert!(Cli::try_parse_from(["krun", "--kernel", "/kernel", "--vsock-cid", "4"]).is_err());
    }
}
