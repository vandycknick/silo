use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use krun::{Disk, KrunConfig, Mount, Network};
use libkrun::{
    init_log, BlockDevice, ConsoleDevice, DiskFormat, FsDevice, KernelFormat, LogLevel, LogOptions,
    LogStyle, MmioDeviceManager, NetDevice, NetFlags, Payload, RngDevice, SyncMode, TsiFlags,
    VmmBuilder, VmmError, VsockDevice,
};
use thiserror::Error;

#[cfg(target_os = "linux")]
use libkrun::VhostUserDevice;

const NET_FEATURE_CSUM: u32 = 1 << 0;
const NET_FEATURE_GUEST_CSUM: u32 = 1 << 1;
const NET_FEATURE_GUEST_TSO4: u32 = 1 << 7;
const NET_FEATURE_GUEST_UFO: u32 = 1 << 10;
const NET_FEATURE_HOST_TSO4: u32 = 1 << 11;
const NET_FEATURE_HOST_UFO: u32 = 1 << 14;
const COMPAT_NET_FEATURES: u32 = NET_FEATURE_CSUM
    | NET_FEATURE_GUEST_CSUM
    | NET_FEATURE_GUEST_TSO4
    | NET_FEATURE_GUEST_UFO
    | NET_FEATURE_HOST_TSO4
    | NET_FEATURE_HOST_UFO;

#[cfg(target_os = "linux")]
const VIRTIO_DEVICE_VSOCK: u32 = 19;
#[cfg(target_os = "linux")]
const VHOST_USER_VSOCK_QUEUE_SIZES: [u16; 3] = [128, 128, 128];

#[derive(Clone, Copy)]
pub(crate) struct ConsoleFds<'a> {
    pub(crate) stdin: BorrowedFd<'a>,
    pub(crate) stdout: BorrowedFd<'a>,
    pub(crate) stderr: BorrowedFd<'a>,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("krun requires a kernel")]
    MissingKernel,

    #[error("{kind} path is not valid UTF-8: {path:?}")]
    NonUtf8Path { kind: &'static str, path: PathBuf },

    #[error("libkrun {operation} failed: {source}")]
    Libkrun {
        operation: &'static str,
        #[source]
        source: VmmError,
    },

    #[error("failed to open unixgram network socket: {0}")]
    OpenUnixgramSocket(#[source] io::Error),

    #[error("libkrun event loop terminated")]
    EventLoopTerminated,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Console,
    Disk,
    Mount,
    #[cfg(target_os = "linux")]
    VhostUserVsock,
    Vsock,
    Network,
    Rng,
}

#[derive(Clone, Copy)]
enum DeviceConfig<'a> {
    Console,
    Disk(&'a Disk),
    Mount(&'a Mount),
    #[cfg(target_os = "linux")]
    VhostUserVsock(&'a Path),
    Vsock(u64),
    Network(&'a Network),
    Rng,
}

#[cfg(test)]
impl DeviceConfig<'_> {
    const fn kind(&self) -> DeviceKind {
        match self {
            Self::Console => DeviceKind::Console,
            Self::Disk(_) => DeviceKind::Disk,
            Self::Mount(_) => DeviceKind::Mount,
            #[cfg(target_os = "linux")]
            Self::VhostUserVsock(_) => DeviceKind::VhostUserVsock,
            Self::Vsock(_) => DeviceKind::Vsock,
            Self::Network(_) => DeviceKind::Network,
            Self::Rng => DeviceKind::Rng,
        }
    }
}

pub(crate) fn run(config: &KrunConfig, console_fds: ConsoleFds<'_>) -> Result<(), Error> {
    init_log(None, LogLevel::Error, LogStyle::Auto, LogOptions::empty())
        .map_err(|source| libkrun_error("initialize logging", source))?;

    let kernel = config.kernel.as_deref().ok_or(Error::MissingKernel)?;
    let cmdline = config.cmdline.join(" ");
    let payload = Payload::load_external(
        path_str(kernel, "kernel")?,
        external_kernel_format(),
        config
            .initramfs
            .as_deref()
            .map(|path| path_str(path, "initramfs"))
            .transpose()?,
        &cmdline,
    )
    .map_err(|source| libkrun_error("load payload", source))?;

    let mut devices = MmioDeviceManager::new();

    // MMIO attachment order is stable because guest disk naming follows it.
    for device in device_plan(config) {
        match device {
            DeviceConfig::Console => {
                let mut builder = ConsoleDevice::builder();
                builder
                    .add_default_console(
                        Some(console_fds.stdin),
                        Some(console_fds.stdout),
                        Some(console_fds.stderr),
                    )
                    .map_err(|source| libkrun_error("configure console", source))?;
                devices.add(
                    builder
                        .build()
                        .map_err(|source| libkrun_error("build console", source))?,
                );
            }
            DeviceConfig::Disk(disk) => {
                let mut device = BlockDevice::new(
                    &disk.block_id,
                    path_str(&disk.path, "disk")?,
                    DiskFormat::Raw,
                )
                .map_err(|source| libkrun_error("create block device", source))?;
                device.set_read_only(disk.read_only);
                device.set_sync_mode(disk_sync_mode());
                devices.add(device);
            }
            DeviceConfig::Mount(mount) => {
                let host_path = path_str(&mount.path, "virtiofs")?;
                let device = if mount.read_only {
                    FsDevice::new_read_only(&mount.tag, host_path)
                } else {
                    FsDevice::new(&mount.tag, host_path)
                }
                .map_err(|source| libkrun_error("create filesystem device", source))?;
                devices.add(device);
            }
            #[cfg(target_os = "linux")]
            DeviceConfig::VhostUserVsock(socket) => {
                devices.add(
                    VhostUserDevice::new(
                        VIRTIO_DEVICE_VSOCK,
                        path_str(socket, "vhost-user vsock")?,
                        "vhost-user-vsock",
                        VHOST_USER_VSOCK_QUEUE_SIZES.len() as u16,
                        &VHOST_USER_VSOCK_QUEUE_SIZES,
                    )
                    .map_err(|source| libkrun_error("create vhost-user vsock", source))?,
                );
            }
            DeviceConfig::Vsock(cid) => {
                devices.add(
                    VsockDevice::new(cid, TsiFlags::empty())
                        .map_err(|source| libkrun_error("create native vsock", source))?,
                );
            }
            DeviceConfig::Network(network) => {
                let device = match network {
                    Network::None => {
                        return Err(libkrun_error(
                            "plan network",
                            VmmError::Internal("invalid network device plan".to_string()),
                        ));
                    }
                    Network::Unixgram(net) => {
                        let socket = crate::open_local_unix_datagram_socket(
                            &net.peer_path,
                            &config.id,
                            "krun",
                        )
                        .map_err(Error::OpenUnixgramSocket)?;
                        NetDevice::new_unixgram_fd(
                            "net0",
                            OwnedFd::from(socket),
                            &net.mac,
                            COMPAT_NET_FEATURES,
                            NetFlags::empty(),
                        )
                    }
                    Network::Unixstream(net) => NetDevice::new_unixstream_path(
                        "net0",
                        path_str(&net.peer_path, "network peer")?,
                        &net.mac,
                        COMPAT_NET_FEATURES,
                        NetFlags::empty(),
                    ),
                    Network::Tap(net) => {
                        NetDevice::new_tap("net0", &net.name, &net.mac, COMPAT_NET_FEATURES)
                    }
                }
                .map_err(|source| libkrun_error("create network device", source))?;
                devices.add(device);
            }
            DeviceConfig::Rng => {
                devices.add(
                    RngDevice::new()
                        .map_err(|source| libkrun_error("create RNG device", source))?,
                );
            }
        }
    }

    let mut builder = VmmBuilder::new()
        .vcpus(config.cpus)
        .map_err(|source| libkrun_error("set vCPU count", source))?
        .ram_mib(config.memory_mib)
        .map_err(|source| libkrun_error("set memory size", source))?
        .payload(payload)
        .devices(devices);
    if config.stdio_console {
        builder = builder.set_kernel_console("hvc0");
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        builder = builder.shutdown_support(true);
    }

    let vmm = builder
        .build()
        .map_err(|source| libkrun_error("build VMM", source))?;
    vmm.run();
    Err(Error::EventLoopTerminated)
}

fn device_plan(config: &KrunConfig) -> Vec<DeviceConfig<'_>> {
    let mut devices = Vec::with_capacity(
        usize::from(config.stdio_console)
            + config.disks.len()
            + config.mounts.len()
            + usize::from(config.vhost_user_vsock.is_some())
            + usize::from(config.vsock_cid.is_some())
            + usize::from(!matches!(config.network, Network::None))
            + 1,
    );
    if config.stdio_console {
        devices.push(DeviceConfig::Console);
    }
    devices.extend(config.disks.iter().map(DeviceConfig::Disk));
    devices.extend(config.mounts.iter().map(DeviceConfig::Mount));
    #[cfg(target_os = "linux")]
    if let Some(socket) = config.vhost_user_vsock.as_deref() {
        devices.push(DeviceConfig::VhostUserVsock(socket));
    }
    if let Some(cid) = config.vsock_cid {
        devices.push(DeviceConfig::Vsock(cid));
    }
    if !matches!(config.network, Network::None) {
        devices.push(DeviceConfig::Network(&config.network));
    }
    devices.push(DeviceConfig::Rng);
    devices
}

fn external_kernel_format() -> KernelFormat {
    #[cfg(target_arch = "x86_64")]
    {
        KernelFormat::Elf
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        KernelFormat::Raw
    }
}

const fn disk_sync_mode() -> SyncMode {
    SyncMode::Relaxed
}

fn path_str<'a>(path: &'a Path, kind: &'static str) -> Result<&'a str, Error> {
    path.to_str().ok_or_else(|| Error::NonUtf8Path {
        kind,
        path: path.to_path_buf(),
    })
}

fn libkrun_error(operation: &'static str, source: VmmError) -> Error {
    Error::Libkrun { operation, source }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    use krun::{Disk, KrunConfig, Mount, NetUnixstream, Network};
    use libkrun::{KernelFormat, SyncMode};

    use crate::vmm::{
        device_plan, disk_sync_mode, external_kernel_format, path_str, DeviceConfig, DeviceKind,
        Error, COMPAT_NET_FEATURES,
    };

    #[test]
    fn external_kernel_format_matches_host_architecture() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(external_kernel_format(), KernelFormat::Elf);

        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        assert_eq!(external_kernel_format(), KernelFormat::Raw);
    }

    #[test]
    fn disks_use_relaxed_sync() {
        assert_eq!(disk_sync_mode(), SyncMode::Relaxed);
    }

    #[test]
    fn compatibility_network_features_remain_stable() {
        assert_eq!(COMPAT_NET_FEATURES, 19_587);
    }

    #[test]
    fn non_utf8_paths_are_rejected_without_lossy_conversion() {
        let path = PathBuf::from(OsString::from_vec(vec![0xff]));
        assert!(matches!(
            path_str(&path, "kernel"),
            Err(Error::NonUtf8Path { kind: "kernel", path: rejected }) if rejected == path
        ));
    }

    #[test]
    fn device_order_is_deterministic() {
        let config = KrunConfig {
            stdio_console: true,
            disks: vec![Disk {
                block_id: "root".to_string(),
                path: PathBuf::from("root.img"),
                read_only: false,
            }],
            mounts: vec![Mount {
                tag: "src".to_string(),
                path: PathBuf::from("src"),
                read_only: true,
            }],
            network: Network::Unixstream(NetUnixstream {
                peer_path: PathBuf::from("net.sock"),
                mac: [0x02, 0, 0, 0, 0, 1],
            }),
            ..KrunConfig::default()
        };
        #[cfg(target_os = "linux")]
        let config = KrunConfig {
            vhost_user_vsock: Some(PathBuf::from("vsock.sock")),
            ..config
        };

        let expected = vec![
            DeviceKind::Console,
            DeviceKind::Disk,
            DeviceKind::Mount,
            #[cfg(target_os = "linux")]
            DeviceKind::VhostUserVsock,
            DeviceKind::Network,
            DeviceKind::Rng,
        ];
        assert_eq!(
            device_plan(&config)
                .iter()
                .map(DeviceConfig::kind)
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn standalone_vsock_precedes_network_without_changing_the_default_plan() {
        let network = Network::Unixstream(NetUnixstream {
            peer_path: PathBuf::from("net.sock"),
            mac: [0x02, 0, 0, 0, 0, 1],
        });
        let default_config = KrunConfig {
            network: network.clone(),
            ..KrunConfig::default()
        };
        let standalone_config = KrunConfig {
            vsock_cid: Some(3),
            network,
            ..KrunConfig::default()
        };
        let standalone_plan = device_plan(&standalone_config);

        assert_eq!(
            device_plan(&default_config)
                .iter()
                .map(DeviceConfig::kind)
                .collect::<Vec<_>>(),
            vec![DeviceKind::Network, DeviceKind::Rng]
        );
        assert!(matches!(
            standalone_plan.first(),
            Some(DeviceConfig::Vsock(3))
        ));
        assert_eq!(
            standalone_plan
                .iter()
                .map(DeviceConfig::kind)
                .collect::<Vec<_>>(),
            vec![DeviceKind::Vsock, DeviceKind::Network, DeviceKind::Rng]
        );
    }
}
