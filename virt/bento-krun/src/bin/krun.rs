use std::fs;
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use bento_krun::{
    validate_config, KrunConfig, NetTap, NetUnixgram, NetUnixstream, Network, DEFAULT_ID,
};
use bento_krun_sys::{ctx, DiskFormat, Feature, KernelFormat, SyncMode};
use clap::{Parser, ValueEnum};
use nix::sys::socket::{setsockopt, sockopt};

#[path = "../internal/parse.rs"]
mod parse;
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
    about = "BentoBox libkrun helper",
    after_help = "Examples:\n  krun --kernel ./vmlinux --initramfs ./initramfs.img --network none\n  krun --kernel ./vmlinux --net-peer /tmp/gvproxy.sock --net-mac 02:94:ef:e4:0c:ee --network unixgram\n  krun --kernel ./vmlinux --net-peer /tmp/passt.sock --net-mac 02:94:ef:e4:0c:ef --network unixstream\n  krun --kernel ./vmlinux --net-tap-name tap0 --net-mac 02:94:ef:e4:0c:f0 --network tap\n"
)]
struct Cli {
    /// Stable VM identifier used for helper-owned socket names.
    #[arg(long, default_value = DEFAULT_ID)]
    id: String,
    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    cpus: u8,
    /// Guest memory size in MiB.
    #[arg(long, default_value_t = 512)]
    memory_mib: u32,
    /// Raw Linux kernel image path.
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
    disks: Vec<bento_krun::Disk>,
    /// Add a virtiofs mount. Format: TAG:PATH:ro|rw.
    #[arg(long = "mount", value_parser = parse::mount)]
    mounts: Vec<bento_krun::Mount>,
    /// Add a vsock port mapping. Format: PORT:PATH:connect|listen.
    #[arg(long = "vsock-port", value_parser = parse::vsock_port)]
    vsock_ports: Vec<bento_krun::VsockPort>,
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
            vsock_ports: self.vsock_ports,
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
    let config = cli.into_config()?;
    validate_config(&config)?;
    start_enter(&config)?;
    Ok(())
}

fn start_enter(config: &KrunConfig) -> eyre::Result<()> {
    let ctx_id = ctx::create_ctx()?;
    let configured = configure_ctx(ctx_id, config);
    if let Err(err) = configured {
        let _ = ctx::free_ctx(ctx_id);
        return Err(err);
    }
    ctx::start_enter(ctx_id)?;
    Ok(())
}

fn configure_ctx(ctx_id: u32, config: &KrunConfig) -> eyre::Result<()> {
    ctx::set_vm_config(ctx_id, config.cpus, config.memory_mib)?;
    ctx::disable_implicit_console(ctx_id)?;
    ctx::disable_implicit_vsock(ctx_id)?;

    if let Some(kernel) = config.kernel.as_ref() {
        let cmdline = (!config.cmdline.is_empty()).then(|| config.cmdline.join(" "));
        ctx::set_kernel(
            ctx_id,
            &path_string(kernel),
            KernelFormat::Raw,
            config
                .initramfs
                .as_ref()
                .map(|path| path_string(path))
                .as_deref(),
            cmdline.as_deref(),
        )?;
    }

    for disk in &config.disks {
        require_feature(Feature::Blk, "block devices (--disk)")?;
        ctx::add_disk3(
            ctx_id,
            &disk.block_id,
            &path_string(&disk.path),
            DiskFormat::Raw,
            disk.read_only,
            false,
            SyncMode::Relaxed,
        )?;
    }

    for mount in &config.mounts {
        ctx::add_virtiofs3(
            ctx_id,
            &mount.tag,
            &path_string(&mount.path),
            0,
            mount.read_only,
        )?;
    }

    if !config.vsock_ports.is_empty() {
        ctx::add_vsock(ctx_id, 0)?;
    }
    for port in &config.vsock_ports {
        ctx::add_vsock_port2(ctx_id, port.port, &path_string(&port.path), port.listen)?;
    }

    match &config.network {
        Network::None => {}
        Network::Unixgram(net) => {
            require_feature(Feature::Net, "unixgram networking (--network unixgram)")?;
            let socket = open_local_unix_datagram_socket(&net.peer_path, &config.id, "krun")?;
            ctx::add_net_unixgram_fd(ctx_id, socket.into_raw_fd(), net.mac)?;
        }
        Network::Unixstream(net) => {
            require_feature(Feature::Net, "unixstream networking (--network unixstream)")?;
            ctx::add_net_unixstream(ctx_id, &path_string(&net.peer_path), net.mac)?;
        }
        Network::Tap(net) => {
            require_feature(Feature::Net, "tap networking (--network tap)")?;
            ctx::add_net_tap(ctx_id, &net.name, net.mac)?;
        }
    }

    if config.stdio_console {
        ctx::add_virtio_console_default(ctx_id, 0, 1, 2)?;
        ctx::set_kernel_console(ctx_id, "hvc0")?;
    }

    Ok(())
}

fn require_feature(feature: Feature, requested_by: &'static str) -> eyre::Result<()> {
    if ctx::has_feature(feature)? {
        return Ok(());
    }

    eyre::bail!(
        "unsupported libkrun feature: {requested_by} requires libkrun feature {}; rebuild or install a libkrun with {} support",
        feature_name(feature),
        feature_name(feature)
    )
}

fn feature_name(feature: Feature) -> &'static str {
    match feature {
        Feature::Net => "NET",
        Feature::Blk => "BLK",
        Feature::Gpu => "GPU",
        Feature::Snd => "SND",
        Feature::Input => "INPUT",
        Feature::Efi => "EFI",
        Feature::Tee => "TEE",
        Feature::AmdSev => "AMD_SEV",
        Feature::IntelTdx => "INTEL_TDX",
        Feature::AwsNitro => "AWS_NITRO",
        Feature::VirglResourceMap2 => "VIRGL_RESOURCE_MAP2",
    }
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

fn open_local_unix_datagram_socket(
    peer_path: &Path,
    vm_id: &str,
    backend: &str,
) -> eyre::Result<UnixDatagram> {
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
    use super::local_unix_datagram_path;
    use std::path::Path;

    #[test]
    fn local_unix_datagram_path_uses_short_vm_id_and_backend() {
        assert_eq!(
            local_unix_datagram_path(
                Path::new("/tmp/bento-net/gvproxy.sock"),
                "1234567890abcdef",
                "krun"
            ),
            Path::new("/tmp/bento-net/1234567890ab-krun.sock")
        );
    }

    #[test]
    fn local_unix_datagram_path_keeps_short_vm_id() {
        assert_eq!(
            local_unix_datagram_path(Path::new("/tmp/bento-net/gvproxy.sock"), "vm123", "krun"),
            Path::new("/tmp/bento-net/vm123-krun.sock")
        );
    }
}
