use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Instant;

use libkrun::control::{ControlFailure, ControlState, OperationId, PauseOwner, PauseToken};
use libkrun::live::restore::{
    FailedRestore, RestoreBuildFailure, RestoreInputs, RestoreResources, RestoreToken,
};
use libkrun::live::{
    BaselineImage, BaselineToken, CaptureId, CaptureStatus, CaptureTicket, CompletedCapture,
    ExecutionCaptureReceipt, ExecutionOutputs, FlushReceipt, GenerationKind, GenerationObservation,
    GenerationSnapshot, GenerationTicket, LiveError, MemoryCaptureRequest, MemoryOutputs,
    StateBinding, StoppedOwner,
};

use crate::krun::{KrunConfig, Mount, Network};
use libkrun::{
    BalloonDevice, BlockDevice, ConsoleDevice, DiskFormat, FsDevice, GenerationDevice,
    KernelFormat, MmioDeviceManager, NetDevice, NetFlags, Payload, RngDevice, RosettaFsConfig,
    RosettaFsDevice, RosettaProfile, SyncMode, TsiFlags, VmmBuilder, VmmError, VsockDevice,
};
use thiserror::Error;
use vm_spec::Disk;

// Process entry points choose if and when global native logging is installed.
pub use libkrun::{init_log, LogLevel, LogOptions, LogStyle};

/// Resources borrowed by the native console must outlive process execution.
pub struct Resources<'a> {
    pub console: ConsoleFds<'a>,
    pub vsock_mux: Option<OwnedFd>,
    pub console_ports: Vec<ConsolePort<'a>>,
    pub managed_network: Option<OwnedFd>,
}

/// Extra finite console bindings, borrowed through native terminality.
pub struct ConsolePort<'a> {
    pub name: &'a str,
    pub input: Option<BorrowedFd<'a>>,
    pub output: Option<BorrowedFd<'a>>,
}

/// Process-local controls, not a reusable VM or a process lifecycle handle.
#[derive(Clone)]
pub struct Control {
    handle: std::sync::Arc<libkrun::VmmHandle>,
}

// The normal worker transport deliberately does not dispatch live commands yet.
#[allow(dead_code)]
impl Control {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn request_shutdown(&self) -> Result<(), Error> {
        self.handle
            .shutdown()
            .map_err(|source| libkrun_error("request shutdown", source))
    }

    pub fn host_memory_reclaim(&self) -> crate::krun::HostMemoryReclaimStatus {
        host_memory_reclaim_status(&self.handle)
    }

    /// These calls retain native tokens/errors unchanged. A caller deadline is
    /// never a cancellation or permission to reuse an accepted output.
    pub fn pause(
        &self,
        owner: PauseOwner,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<PauseToken, ControlFailure> {
        self.handle.pause(owner, operation, deadline)
    }

    pub fn resume(
        &self,
        pause: PauseToken,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), ControlFailure> {
        self.handle.resume(pause, operation, deadline)
    }

    pub fn cancel_pause(
        &self,
        pausing: OperationId,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), ControlFailure> {
        self.handle.cancel_pause(pausing, operation, deadline)
    }

    pub fn control_state(&self, deadline: Instant) -> Result<ControlState, ControlFailure> {
        self.handle.control_state(deadline)
    }

    pub fn stop(&self, operation: OperationId, deadline: Instant) -> Result<(), ControlFailure> {
        self.handle.stop(operation, deadline)
    }

    pub fn flush_writable_disks(
        &self,
        pause: &PauseToken,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<FlushReceipt, LiveError> {
        self.handle.flush_writable_disks(pause, operation, deadline)
    }

    pub fn capture_execution(
        &self,
        pause: &PauseToken,
        binding: StateBinding,
        outputs: ExecutionOutputs,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<ExecutionCaptureReceipt, LiveError> {
        self.handle
            .capture_execution(pause, binding, outputs, operation, deadline)
    }

    pub fn capture_memory(
        &self,
        ticket: &CaptureTicket,
        request: MemoryCaptureRequest,
        outputs: MemoryOutputs,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<CompletedCapture, LiveError> {
        self.handle
            .capture_memory(ticket, request, outputs, operation, deadline)
    }

    pub fn capture_status(
        &self,
        capture: CaptureId,
        deadline: Instant,
    ) -> Result<CaptureStatus, LiveError> {
        self.handle.capture_status(capture, deadline)
    }

    pub fn accept_baseline(
        &self,
        ticket: &CaptureTicket,
        sealed: BaselineImage,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<BaselineToken, LiveError> {
        self.handle
            .accept_baseline(ticket, sealed, operation, deadline)
    }

    pub fn abandon_capture(
        &self,
        ticket: &CaptureTicket,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.handle.abandon_capture(ticket, operation, deadline)
    }

    pub fn release_capture(
        &self,
        capture: CaptureId,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.handle.release_capture(capture, operation, deadline)
    }

    pub fn preserve_pause(
        &self,
        pause: PauseToken,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<PauseToken, LiveError> {
        self.handle.preserve_pause(pause, operation, deadline)
    }

    pub fn prepare_generation(
        &self,
        owner: StoppedOwner<'_>,
        kind: GenerationKind,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<GenerationTicket, LiveError> {
        self.handle
            .prepare_generation(owner, kind, operation, deadline)
    }

    pub fn poll_generation(
        &self,
        ticket: &GenerationTicket,
        deadline: Instant,
    ) -> Result<GenerationObservation, LiveError> {
        self.handle.poll_generation(ticket, deadline)
    }

    pub fn generation_snapshot(&self, deadline: Instant) -> Result<GenerationSnapshot, LiveError> {
        self.handle.generation_snapshot(deadline)
    }

    pub fn resume_generation(
        &self,
        pause: PauseToken,
        generation: &GenerationTicket,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.handle
            .resume_generation(pause, generation, operation, deadline)
    }

    pub fn resume_restored(
        &self,
        restore: &RestoreToken,
        generation: &GenerationTicket,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.handle
            .resume_restored(restore, generation, operation, deadline)
    }

    pub fn release_activation_fences(
        &self,
        restore: &RestoreToken,
        generation: &GenerationTicket,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.handle
            .release_activation_fences(restore, generation, operation, deadline)
    }

    pub fn ram_layout(
        &self,
        deadline: Instant,
    ) -> Result<std::sync::Arc<libkrun::live::ValidatedRamLayout>, LiveError> {
        self.handle.ram_layout(deadline)
    }

    pub fn live_snapshot(
        &self,
        deadline: Instant,
    ) -> Result<libkrun::live::LiveSnapshot, LiveError> {
        self.handle.live_snapshot(deadline)
    }

    pub fn baseline(&self, deadline: Instant) -> Result<Option<BaselineToken>, LiveError> {
        self.handle.baseline(deadline)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub fn set_capture_profile(
        &self,
        profile: libkrun::live::KvmCaptureProfile,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.handle
            .set_capture_profile(profile, operation, deadline)
    }
}

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
pub struct ConsoleFds<'a> {
    pub stdin: BorrowedFd<'a>,
    pub stdout: BorrowedFd<'a>,
    pub stderr: BorrowedFd<'a>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    InvalidConfig(#[from] crate::krun::KrunBackendError),

    #[error("post-build worker setup failed: {0}")]
    PostBuild(#[source] io::Error),
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
    Rosetta,
    VsockMux,
    Vsock,
    Network,
    Rng,
    Balloon,
    Generation,
}

#[derive(Clone, Copy)]
enum DeviceConfig<'a> {
    Console,
    Disk(&'a Disk),
    Mount(&'a Mount),
    Rosetta(&'a crate::krun::RosettaLaunchConfig),
    VsockMux,
    Vsock(u64),
    Network(&'a Network),
    Rng,
    Balloon,
    Generation,
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
            Self::Balloon => DeviceKind::Balloon,
            Self::Generation => DeviceKind::Generation,
        }
    }
}

/// Build and enter one VM in a dedicated process.
///
/// Normal VM shutdown terminates the calling process via libkrun's `_exit()`.
/// This function must never run inside the supervisor or on one of its threads.
/// Guest execution can begin during build, before `on_built` is called. Errors
/// after build also require the caller to terminate its process, not retry.
pub fn run_process(
    config: &KrunConfig,
    resources: Resources<'_>,
    on_built: impl FnOnce(Control) -> io::Result<()>,
) -> Result<(), Error> {
    crate::krun::validate_config(config)?;
    let Resources {
        console: console_fds,
        vsock_mux: mut vsock_mux_fd,
        console_ports,
        managed_network: mut managed_network_fd,
    } = resources;
    if config.vsock_mux != vsock_mux_fd.is_some() {
        return Err(crate::krun::KrunBackendError::InvalidConfig(
            "vsock mux configuration and resource must agree".to_string(),
        )
        .into());
    }
    if (!console_ports.is_empty() && !config.stdio_console)
        || (managed_network_fd.is_some() && !matches!(config.network, Network::Unixgram(_)))
    {
        return Err(crate::krun::KrunBackendError::InvalidConfig(
            "console/network resource roles disagree with the device plan".to_string(),
        )
        .into());
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
                for port in &console_ports {
                    builder
                        .add_inout_port(port.name, port.input, port.output)
                        .map_err(|source| libkrun_error("configure console port", source))?;
                }
                devices.add(
                    builder
                        .build()
                        .map_err(|source| libkrun_error("build console", source))?,
                );
            }
            DeviceConfig::Disk(disk) => {
                let mut device = BlockDevice::new(
                    disk.block_id.as_str(),
                    path_str(&disk.path, "disk")?,
                    disk_format(disk.format),
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
                        let fd = match managed_network_fd.take() {
                            Some(fd) => fd,
                            None => OwnedFd::from(
                                crate::krun::network::open_local_unix_datagram_socket(
                                    &net.peer_path,
                                    &config.id,
                                    "krun",
                                )
                                .map_err(Error::OpenUnixgramSocket)?,
                            ),
                        };
                        NetDevice::new_managed_unixgram_fd(
                            "net0",
                            fd,
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
            DeviceConfig::Balloon => {
                devices.add(
                    BalloonDevice::new()
                        .map_err(|source| libkrun_error("create balloon device", source))?,
                );
            }
            DeviceConfig::Generation => {
                devices.add(GenerationDevice::new());
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
    let handle = vmm
        .handle()
        .map_err(|source| libkrun_error("obtain VMM control handle", source))?;
    on_built(Control {
        handle: std::sync::Arc::new(handle),
    })
    .map_err(Error::PostBuild)?;
    vmm.run();
    Err(Error::EventLoopTerminated)
}

/// A restore construction failure retains the native failed owner, rather than
/// flattening it into the cold-build error's diagnostic.
#[allow(dead_code)]
pub enum RestoreProcessError<'a> {
    Build(RestoreBuildFailure<'a>),
    Handle {
        source: VmmError,
        failed: FailedRestore<'a>,
    },
    PreparedCallback {
        source: io::Error,
        failed: FailedRestore<'a>,
    },
    EventLoopTerminated,
}

/// Enter a descriptor-fed restore in a dedicated worker process.
///
/// There is intentionally no `KrunConfig`, payload, kernel or cold device plan.
/// Preparation is parked/fenced, not BackendStarted. `on_prepared` must return
/// before dispatch; move controls to another thread before making blocking calls.
/// The process owner retains leases and console bindings through actual reap,
/// including errors. A build failure must retain/settle its native failed owner.
#[allow(dead_code)]
pub fn run_restore_process<'a>(
    inputs: RestoreInputs,
    resources: RestoreResources,
    deadline: Instant,
    on_prepared: impl FnOnce(Control, RestoreToken) -> io::Result<()>,
) -> Result<(), RestoreProcessError<'a>> {
    let (vmm, restore) = VmmBuilder::new()
        .build_restored(inputs, resources, deadline)
        .map_err(RestoreProcessError::Build)?;
    let handle = match vmm.handle() {
        Ok(handle) => handle,
        Err(source) => {
            return Err(RestoreProcessError::Handle {
                source,
                failed: vmm.retain_failed_restore(),
            })
        }
    };
    if let Err(source) = on_prepared(
        Control {
            handle: std::sync::Arc::new(handle),
        },
        restore,
    ) {
        return Err(RestoreProcessError::PreparedCallback {
            source,
            failed: vmm.retain_failed_restore(),
        });
    }
    vmm.run();
    Err(RestoreProcessError::EventLoopTerminated)
}

fn host_memory_reclaim_status(handle: &libkrun::VmmHandle) -> crate::krun::HostMemoryReclaimStatus {
    use crate::krun::{
        HostMemoryReclaimBacking as B, HostMemoryReclaimQualification as Q,
        HostMemoryReclaimReason as R,
    };
    use libkrun::{HostReclaimBacking, HostReclaimQualification, HostReclaimReason};

    let status = handle.host_reclaim_status();
    crate::krun::HostMemoryReclaimStatus {
        backing: match status.backing {
            HostReclaimBacking::Boot => B::Boot,
            HostReclaimBacking::RestoredPrivate => B::RestoredPrivate,
        },
        reason: match status.reason {
            HostReclaimReason::None => R::None,
            HostReclaimReason::TrackedCapture => R::TrackedCapture,
            HostReclaimReason::RestoredPrivateMapping => R::RestoredPrivateMapping,
        },
        requested: status.requested,
        qualification: match status.qualification {
            HostReclaimQualification::NotRun => Q::NotRun,
            HostReclaimQualification::Passed => Q::Passed,
            HostReclaimQualification::Failed => Q::Failed,
            HostReclaimQualification::Inconclusive => Q::Inconclusive,
        },
        effective: status.effective,
        released_bytes: status.released_bytes,
        released_extents: status.released_extents,
        retried_faults: status.retried_faults,
        skipped_reports: status.skipped_reports,
        failed_operations: status.failed_operations,
    }
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
            + 3,
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
    if config.balloon {
        devices.push(DeviceConfig::Balloon);
    }
    devices.push(DeviceConfig::Generation);
    devices
}

fn rosetta_device(config: &crate::krun::RosettaLaunchConfig) -> Result<RosettaFsDevice, Error> {
    let profile = match config.profile() {
        crate::krun::RosettaProfileId::CapturedCompatibilityV1 => {
            RosettaProfile::CapturedCompatibilityV1
        }
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

fn disk_format(format: vm_spec::DiskFormat) -> DiskFormat {
    match format {
        vm_spec::DiskFormat::Raw => DiskFormat::Raw,
        vm_spec::DiskFormat::Vmdk => DiskFormat::Vmdk,
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

    use crate::krun::config::NetUnixstream;
    use crate::krun::{KrunConfig, Mount, Network, RosettaLaunchConfig};
    use libkrun::KernelFormat;
    use vm_spec::Disk;

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use crate::krun::engine::rosetta_device;
    use crate::krun::engine::{
        device_plan, external_kernel_format, path_str, DeviceConfig, DeviceKind, Error,
    };

    #[test]
    fn invalid_configuration_never_reaches_payload_or_post_build_setup() {
        use crate::krun::engine::{run_process, ConsoleFds, Resources};
        use std::os::fd::AsFd;
        let console = std::fs::File::open("/dev/null").expect("console fixture");
        let config = KrunConfig {
            cpus: 0,
            kernel: Some("/missing/kernel".into()),
            ..KrunConfig::default()
        };
        let result = run_process(
            &config,
            Resources {
                console: ConsoleFds {
                    stdin: console.as_fd(),
                    stdout: console.as_fd(),
                    stderr: console.as_fd(),
                },
                vsock_mux: None,
                console_ports: Vec::new(),
                managed_network: None,
            },
            |_| panic!("invalid config must not reach post-build hook"),
        );
        assert!(matches!(result, Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn mux_configuration_requires_exactly_one_matching_owned_resource() {
        use crate::krun::engine::{run_process, ConsoleFds, Resources};
        use std::os::fd::AsFd;
        let console = std::fs::File::open("/dev/null").expect("console fixture");
        for enabled in [false, true] {
            let config = KrunConfig {
                kernel: Some("/missing/kernel".into()),
                vsock_mux: enabled,
                ..KrunConfig::default()
            };
            let (mux, _peer) = std::os::unix::net::UnixStream::pair().expect("mux fixture");
            let result = run_process(
                &config,
                Resources {
                    console: ConsoleFds {
                        stdin: console.as_fd(),
                        stdout: console.as_fd(),
                        stderr: console.as_fd(),
                    },
                    vsock_mux: if enabled { None } else { Some(mux.into()) },
                    console_ports: Vec::new(),
                    managed_network: None,
                },
                |_| panic!("mismatched resources must not reach build"),
            );
            assert!(matches!(result, Err(Error::InvalidConfig(_))));
        }
    }

    #[test]
    fn external_kernel_format_matches_host_architecture() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(external_kernel_format(), KernelFormat::Elf);

        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        assert_eq!(external_kernel_format(), KernelFormat::Raw);
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
                block_id: vm_spec::BlockId::new("explicit-root").expect("valid ID"),
                path: PathBuf::from("root.raw"),
                role: vm_spec::DiskRole::Root,
                format: vm_spec::DiskFormat::Raw,
                geometry: vm_spec::DiskGeometry {
                    length: 4096,
                    logical_sector_size: 512,
                },
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
            balloon: true,
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
            DeviceKind::Generation,
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
            vec![DeviceKind::Network, DeviceKind::Rng, DeviceKind::Generation]
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
                DeviceKind::Generation
            ]
        );
    }

    #[test]
    fn balloon_attachment_is_explicit() {
        for enabled in [false, true] {
            let config = KrunConfig {
                balloon: enabled,
                ..KrunConfig::default()
            };
            assert_eq!(
                device_plan(&config)
                    .iter()
                    .any(|device| matches!(device, DeviceConfig::Balloon)),
                enabled
            );
        }
    }
}
