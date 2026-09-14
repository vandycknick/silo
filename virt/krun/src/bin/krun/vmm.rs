use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use krun::{Disk, KrunConfig, Mount, Network};
use libkrun::{
    init_log, BalloonDevice, BlockDevice, ConsoleDevice, DiskFormat, FsDevice, KernelFormat,
    LogLevel, LogOptions, LogStyle, MmioDeviceManager, NetDevice, NetFlags, Payload, RngDevice,
    RosettaFsConfig, RosettaFsDevice, RosettaProfile, SyncMode, TsiFlags, VmmBuilder, VmmError,
    VsockDevice,
};
use thiserror::Error;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use nix::sys::signal::{self, SigSet, SigmaskHow, Signal};

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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[error("failed to {operation} shutdown signal handling: {source}")]
    ShutdownSignal {
        operation: &'static str,
        #[source]
        source: nix::errno::Errno,
    },

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[error("failed to spawn shutdown signal thread: {0}")]
    ShutdownThread(#[source] io::Error),
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Console,
    Disk,
    Mount,
    Rosetta,
    VsockMux,
    Vsock,
    Network,
    Rng,
    Balloon,
}

#[derive(Clone, Copy)]
enum DeviceConfig<'a> {
    Console,
    Disk(&'a Disk),
    Mount(&'a Mount),
    Rosetta(&'a krun::RosettaLaunchConfig),
    VsockMux,
    Vsock(u64),
    Network(&'a Network),
    Rng,
    Balloon(bool),
}

#[cfg(test)]
impl DeviceConfig<'_> {
    const fn kind(&self) -> DeviceKind {
        match self {
            Self::Console => DeviceKind::Console,
            Self::Disk(_) => DeviceKind::Disk,
            Self::Mount(_) => DeviceKind::Mount,
            Self::Rosetta(_) => DeviceKind::Rosetta,
            Self::VsockMux => DeviceKind::VsockMux,
            Self::Vsock(_) => DeviceKind::Vsock,
            Self::Network(_) => DeviceKind::Network,
            Self::Rng => DeviceKind::Rng,
            Self::Balloon(_) => DeviceKind::Balloon,
        }
    }
}

pub(crate) fn run(
    config: &KrunConfig,
    mut vsock_mux_fd: Option<OwnedFd>,
    watchdog_fd: Option<OwnedFd>,
    console_fds: ConsoleFds<'_>,
) -> Result<(), Error> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let shutdown_signals = block_shutdown_signal()?;

    init_log(None, LogLevel::Info, LogStyle::Auto, LogOptions::empty())
        .map_err(|source| libkrun_error("initialize logging", source))?;
    if config.host_memory_reclaim {
        eprintln!(
            "host memory reclaim requested=on effective=pending; startup probe result follows"
        );
    } else {
        eprintln!("host memory reclaim requested=off effective=off probe=not-run");
    }

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
            DeviceConfig::Rosetta(config) => {
                devices.add(rosetta_device(config)?);
            }
            DeviceConfig::VsockMux => {
                let fd = vsock_mux_fd.take().ok_or_else(|| {
                    libkrun_error(
                        "create vsock mux",
                        VmmError::Internal("vsock mux descriptor was not supplied".to_string()),
                    )
                })?;
                let mut device = VsockDevice::new(GUEST_CID, TsiFlags::empty())
                    .map_err(|source| libkrun_error("create native vsock", source))?;
                protect_stream_socket(&mut device, console_fds.stdin)?;
                protect_stream_socket(&mut device, console_fds.stdout)?;
                protect_stream_socket(&mut device, console_fds.stderr)?;
                if let Some(watchdog_fd) = watchdog_fd.as_ref() {
                    protect_stream_socket(&mut device, watchdog_fd.as_fd())?;
                }
                device.set_unix_mux_fd(fd);
                devices.add(device);
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
            DeviceConfig::Balloon(host_reclaim) => {
                devices.add(
                    BalloonDevice::new()
                        .map_err(|source| libkrun_error("create balloon device", source))?
                        .host_reclaim(host_reclaim),
                );
            }
        }
    }

    if let Some(watchdog_fd) = watchdog_fd {
        crate::watchdog::start(watchdog_fd);
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let handle = vmm
            .handle()
            .map_err(|source| libkrun_error("obtain VMM shutdown handle", source))?;
        std::thread::Builder::new()
            .name("silo-krun-shutdown".to_string())
            .spawn(move || match shutdown_signals.wait() {
                Ok(Signal::SIGTERM) => {
                    eprintln!("krun helper received SIGTERM");
                    match handle.shutdown() {
                        Ok(()) => eprintln!("krun helper sent guest shutdown request"),
                        Err(err) => {
                            eprintln!("krun helper failed to request guest shutdown: {err}");
                        }
                    }
                }
                Ok(signal) => {
                    eprintln!("krun helper shutdown waiter received unexpected signal: {signal:?}");
                }
                Err(err) => {
                    eprintln!("krun helper shutdown signal wait failed: {err}");
                }
            })
            .map_err(Error::ShutdownThread)?;
    }
    vmm.run();
    Err(Error::EventLoopTerminated)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn block_shutdown_signal() -> Result<SigSet, Error> {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGTERM);
    signal::pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None).map_err(|source| {
        Error::ShutdownSignal {
            operation: "block",
            source,
        }
    })?;
    Ok(signals)
}

fn device_plan(config: &KrunConfig) -> Vec<DeviceConfig<'_>> {
    let mut devices = Vec::with_capacity(
        usize::from(config.stdio_console)
            + config.disks.len()
            + config.mounts.len()
            + usize::from(config.rosetta.is_some())
            + usize::from(config.vsock_mux)
            + usize::from(config.vsock_cid.is_some())
            + usize::from(!matches!(config.network, Network::None))
            + 2,
    );
    if config.stdio_console {
        devices.push(DeviceConfig::Console);
    }
    devices.extend(config.disks.iter().map(DeviceConfig::Disk));
    devices.extend(config.mounts.iter().map(DeviceConfig::Mount));
    if let Some(rosetta) = config.rosetta.as_ref() {
        devices.push(DeviceConfig::Rosetta(rosetta));
    }
    if config.vsock_mux {
        devices.push(DeviceConfig::VsockMux);
    }
    if let Some(cid) = config.vsock_cid {
        devices.push(DeviceConfig::Vsock(cid));
    }
    if !matches!(config.network, Network::None) {
        devices.push(DeviceConfig::Network(&config.network));
    }
    devices.push(DeviceConfig::Rng);
    devices.push(DeviceConfig::Balloon(config.host_memory_reclaim));
    devices
}

fn rosetta_device(config: &krun::RosettaLaunchConfig) -> Result<RosettaFsDevice, Error> {
    let profile = match config.profile() {
        krun::RosettaProfileId::CapturedCompatibilityV1 => RosettaProfile::CapturedCompatibilityV1,
    };
    let config = RosettaFsConfig::new(
        profile,
        config.host_root().to_path_buf(),
        config.translator_sha256(),
        config.ioctl_result(),
        config.data().as_bytes(),
    )
    .map_err(|source| libkrun_error("configure Rosetta filesystem", source))?;
    RosettaFsDevice::new("rosetta", config)
        .map_err(|source| libkrun_error("create Rosetta filesystem", source))
}

const GUEST_CID: u64 = 3;

fn protect_stream_socket(device: &mut VsockDevice, fd: BorrowedFd<'_>) -> Result<(), Error> {
    if nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::SockType)
        .is_ok_and(|kind| kind == nix::sys::socket::SockType::Stream)
        && nix::sys::socket::getsockname::<nix::sys::socket::UnixAddr>(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
        )
        .is_ok()
    {
        device
            .add_unix_mux_protected_fd(fd)
            .map_err(|source| libkrun_error("protect vsock descriptor", source))?;
    }
    Ok(())
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use std::sync::atomic::{AtomicU64, Ordering};

    use krun::{Disk, KrunConfig, Mount, NetUnixstream, Network, RosettaLaunchConfig};
    use libkrun::{KernelFormat, SyncMode};

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use crate::vmm::rosetta_device;
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn native_rosetta_adapter_verifies_the_immutable_source_digest() {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "silo-rosetta-adapter-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create synthetic source root");
        let root = fs::canonicalize(root).expect("resolve synthetic source root");
        let translator = root.join("rosetta");
        fs::write(&translator, b"synthetic executable").expect("write synthetic translator");
        fs::set_permissions(&translator, fs::Permissions::from_mode(0o755))
            .expect("make synthetic translator executable");
        let digest = [
            0xeb, 0x4f, 0xfe, 0x43, 0xc9, 0xed, 0xcf, 0x31, 0x0d, 0xc3, 0x51, 0x39, 0x98, 0xdf,
            0x4f, 0xa1, 0x70, 0x0f, 0xc6, 0x57, 0x0c, 0x6c, 0x46, 0xe3, 0x2d, 0xd3, 0xaf, 0x9e,
            0x02, 0x8f, 0xe7, 0x20,
        ];
        let valid = RosettaLaunchConfig::new(root.clone(), digest, 1, [0x5a; 1024])
            .expect("valid launch config");
        rosetta_device(&valid).expect("construct verified immutable device");

        let mismatch = RosettaLaunchConfig::new(root.clone(), [0; 32], 1, [0x5a; 1024])
            .expect("structurally valid mismatched config");
        let error = match rosetta_device(&mismatch) {
            Ok(_) => panic!("digest mismatch must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("translator digest mismatch"));
        fs::remove_dir_all(root).expect("remove synthetic source root");
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
            rosetta: Some(
                RosettaLaunchConfig::new(PathBuf::from("/synthetic/root"), [0; 32], 0, [0; 1024])
                    .expect("valid synthetic Rosetta config"),
            ),
            ..KrunConfig::default()
        };
        let config = KrunConfig {
            vsock_mux: true,
            ..config
        };

        let expected = vec![
            DeviceKind::Console,
            DeviceKind::Disk,
            DeviceKind::Mount,
            DeviceKind::Rosetta,
            DeviceKind::VsockMux,
            DeviceKind::Network,
            DeviceKind::Rng,
            DeviceKind::Balloon,
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
            vec![DeviceKind::Network, DeviceKind::Rng, DeviceKind::Balloon]
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
            vec![
                DeviceKind::Vsock,
                DeviceKind::Network,
                DeviceKind::Rng,
                DeviceKind::Balloon,
            ]
        );
    }

    #[test]
    fn balloon_is_always_attached_with_the_requested_host_policy() {
        for requested in [false, true] {
            let config = KrunConfig {
                host_memory_reclaim: requested,
                ..KrunConfig::default()
            };
            assert!(matches!(
                device_plan(&config).last(),
                Some(DeviceConfig::Balloon(actual)) if *actual == requested
            ));
        }
    }
}
