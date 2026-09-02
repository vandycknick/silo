//! Apple Virtualization.framework backend, built on the `vz` bindings crate.

use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use vz::device::{
    EntropyDeviceConfiguration, LinuxRosettaDirectoryShare, MemoryBalloonDeviceConfiguration,
    NetworkDeviceConfiguration, SerialPortConfiguration, SharedDirectory, SingleDirectoryShare,
    SocketDeviceConfiguration, StorageDeviceConfiguration, VirtioFileSystemDeviceConfiguration,
    VirtioSocketDevice,
};
use vz::{
    GenericMachineIdentifier, GenericPlatform, LinuxBootLoader, RosettaAvailability,
    VirtualMachine, VirtualMachineDelegate, VirtualMachineState, VzError,
};

use crate::virt::backend::VirtBackend;
use crate::virt::capacity::{VsockLease, VsockListenerAdmission};
use crate::virt::config::{validate_common, MachineIdentifier, NetworkMode, VmConfig};
use crate::virt::error::VirtError;
use crate::virt::stream::{SerialDevice, VsockListener, VsockStream};
use crate::virt::VmExit;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const SILO_ROSETTA_TAG: &str = "silo-rosetta";

#[derive(Debug)]
pub(crate) struct VzBackend {
    config: VmConfig,
    inner: AsyncMutex<VzMachineState>,
    exit: Arc<Mutex<Option<VmExit>>>,
    exit_notify: Arc<Notify>,
}

#[derive(Debug)]
struct VzMachineState {
    vm: Option<VirtualMachine>,
    serial_port: Option<SerialPortConfiguration>,
    started: bool,
}

impl VzBackend {
    pub(crate) fn new(config: VmConfig) -> Result<Self, VirtError> {
        validate(&config)?;
        Ok(Self {
            config,
            inner: AsyncMutex::new(VzMachineState {
                vm: None,
                serial_port: None,
                started: false,
            }),
            exit: Arc::new(Mutex::new(None)),
            exit_notify: Arc::new(Notify::new()),
        })
    }

    fn cached_exit(&self) -> Option<VmExit> {
        self.exit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn cache_exit(&self, exit: VmExit) {
        let mut slot = self.exit.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(exit);
            self.exit_notify.notify_waiters();
        }
    }

    fn try_cache_exit_from_vm(&self, vm: &VirtualMachine) {
        match vm.state() {
            VirtualMachineState::Stopped => self.cache_exit(VmExit::Stopped),
            VirtualMachineState::Error => self.cache_exit(VmExit::StoppedWithError(
                "virtual machine entered error state".to_string(),
            )),
            _ => {}
        }
    }
}

#[async_trait]
impl VirtBackend for VzBackend {
    async fn start(&self) -> Result<(), VirtError> {
        validate_support()?;
        let mut state = self.inner.lock().await;
        if state.started {
            return Err(VirtError::AlreadyRunning {
                name: self.config.name().to_string(),
            });
        }

        let (vm, serial_port) = match (state.vm.take(), state.serial_port.take()) {
            (Some(vm), Some(serial_port)) => (vm, serial_port),
            _ => build_vm(&self.config)?,
        };
        state.started = true;
        vm.set_delegate(ExitDelegate {
            exit: self.exit.clone(),
            notify: self.exit_notify.clone(),
        })
        .map_err(vz_error)?;
        let mut state_events = vm.subscribe_state();

        vm.start().await.map_err(vz_error)?;
        wait_for_state(
            &mut state_events,
            &vm,
            VirtualMachineState::Running,
            STARTUP_TIMEOUT,
        )
        .await?;

        state.vm = Some(vm);
        state.serial_port = Some(serial_port);
        Ok(())
    }

    async fn stop(&self) -> Result<(), VirtError> {
        let mut state = self.inner.lock().await;
        if let Some(vm) = state.vm.as_ref() {
            if vm.state() != VirtualMachineState::Stopped {
                let mut state_events = vm.subscribe_state();
                tracing::debug!(
                    machine_id = self.config.name(),
                    current_state = %vm.state(),
                    "starting VZ shutdown flow"
                );
                let graceful_stop_completed = if vm.can_request_stop() {
                    tracing::debug!(
                        machine_id = self.config.name(),
                        timeout = ?SHUTDOWN_TIMEOUT,
                        "requesting graceful VZ shutdown"
                    );
                    vm.request_stop().map_err(vz_error)?;
                    let graceful_result = wait_for_state(
                        &mut state_events,
                        vm,
                        VirtualMachineState::Stopped,
                        SHUTDOWN_TIMEOUT,
                    )
                    .await;
                    match &graceful_result {
                        Ok(()) => {
                            tracing::debug!(
                                machine_id = self.config.name(),
                                "graceful VZ shutdown completed"
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                machine_id = self.config.name(),
                                error = %err,
                                timeout = ?SHUTDOWN_TIMEOUT,
                                "graceful VZ shutdown did not complete before timeout, falling back to hard stop"
                            );
                        }
                    }
                    graceful_result.is_ok()
                } else {
                    tracing::debug!(
                        machine_id = self.config.name(),
                        "guest does not support graceful request_stop, using hard stop"
                    );
                    false
                };

                if !graceful_stop_completed {
                    tracing::warn!(
                        machine_id = self.config.name(),
                        timeout = ?SHUTDOWN_TIMEOUT,
                        "executing hard VZ stop"
                    );
                    vm.stop().await.map_err(vz_error)?;
                    wait_for_state(
                        &mut state_events,
                        vm,
                        VirtualMachineState::Stopped,
                        SHUTDOWN_TIMEOUT,
                    )
                    .await?;
                    tracing::debug!(machine_id = self.config.name(), "hard VZ stop completed");
                }
            }
        }

        state.vm = None;
        state.serial_port = None;
        self.cache_exit(VmExit::Stopped);
        Ok(())
    }

    async fn wait(&self) -> Result<VmExit, VirtError> {
        loop {
            if let Some(exit) = self.cached_exit() {
                return Ok(exit);
            }

            let maybe_vm = {
                let state = self.inner.lock().await;
                state.vm.clone()
            };

            let Some(vm) = maybe_vm else {
                return Err(VirtError::NotRunning {
                    name: self.config.name().to_string(),
                });
            };

            self.try_cache_exit_from_vm(&vm);
            if let Some(exit) = self.cached_exit() {
                return Ok(exit);
            }

            self.exit_notify.notified().await;
        }
    }

    async fn try_wait(&self) -> Result<Option<VmExit>, VirtError> {
        if let Some(exit) = self.cached_exit() {
            return Ok(Some(exit));
        }

        let maybe_vm = {
            let state = self.inner.lock().await;
            state.vm.clone()
        };

        let Some(vm) = maybe_vm else {
            return Ok(None);
        };

        self.try_cache_exit_from_vm(&vm);
        Ok(self.cached_exit())
    }

    async fn connect_vsock(&self, port: u32, lease: VsockLease) -> Result<VsockStream, VirtError> {
        let vm = self.running_vm().await?;
        let device = socket_device(&vm)?;
        let stream = device.connect(port).await.map_err(vz_error)?;
        Ok(VsockStream::from_vz(stream, Some(lease)))
    }

    async fn listen_vsock(
        &self,
        port: u32,
        admission: VsockListenerAdmission,
    ) -> Result<VsockListener, VirtError> {
        let vm = {
            let mut state = self.inner.lock().await;
            if state.vm.is_none() {
                let (vm, serial_port) = build_vm(&self.config)?;
                state.vm = Some(vm);
                state.serial_port = Some(serial_port);
            }
            state.vm.clone().ok_or_else(|| {
                VirtError::Backend(
                    "VZ machine preparation did not retain the virtual machine".to_string(),
                )
            })?
        };
        let device = socket_device(&vm)?;
        let listener_admission = admission.clone();
        let accepted_leases = Arc::new(Mutex::new(VecDeque::new()));
        let accepted_leases_out = accepted_leases.clone();
        let machine = self.config.name().to_string();
        let listener = device
            .listen(port, move |request| {
                match listener_admission.reserve() {
                    Ok(lease) => {
                        accepted_leases_out
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push_back(lease);
                        true
                    }
                    Err(error) => {
                        tracing::warn!(machine, port, source_port = request.source_port(), destination_port = request.destination_port(), %error, "rejected VZ guest vsock connection at active connection limit");
                        false
                    }
                }
            })
            .map_err(vz_error)?;
        Ok(VsockListener::from_vz(
            listener,
            port,
            admission,
            accepted_leases,
        ))
    }

    async fn open_serial(&self) -> Result<SerialDevice, VirtError> {
        let serial_port = {
            let state = self.inner.lock().await;
            state
                .serial_port
                .clone()
                .ok_or_else(|| VirtError::NotRunning {
                    name: self.config.name().to_string(),
                })?
        };

        let stream = serial_port.open_stream().map_err(vz_error)?;
        Ok(SerialDevice::from_vz(stream))
    }
}

impl VzBackend {
    async fn running_vm(&self) -> Result<VirtualMachine, VirtError> {
        let state = self.inner.lock().await;
        state.vm.clone().ok_or_else(|| VirtError::NotRunning {
            name: self.config.name().to_string(),
        })
    }
}

fn socket_device(vm: &VirtualMachine) -> Result<VirtioSocketDevice, VirtError> {
    vm.open_devices()
        .into_iter()
        .next()
        .ok_or_else(|| VirtError::Backend("no virtio socket device configured in VM".to_string()))
}

#[derive(Clone)]
struct ExitDelegate {
    exit: Arc<Mutex<Option<VmExit>>>,
    notify: Arc<Notify>,
}

impl VirtualMachineDelegate for ExitDelegate {
    fn guest_did_stop(&self) {
        let mut slot = self.exit.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(VmExit::Stopped);
        }
        drop(slot);
        self.notify.notify_waiters();
    }

    fn did_stop_with_error(&self, error: VzError) {
        let mut slot = self.exit.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(VmExit::StoppedWithError(error.to_string()));
        }
        drop(slot);
        self.notify.notify_waiters();
    }
}

fn validate(config: &VmConfig) -> Result<(), VirtError> {
    validate_support()?;
    validate_common(config)?;
    validate_machine_config(config)
}

fn validate_support() -> Result<(), VirtError> {
    let _ = VirtualMachine::builder().map_err(vz_error)?;
    Ok(())
}

fn build_vm(config: &VmConfig) -> Result<(VirtualMachine, SerialPortConfiguration), VirtError> {
    let serial_port = SerialPortConfiguration::virtio_console();

    let mut builder = VirtualMachine::builder()
        .map_err(vz_error)?
        .set_cpu_count(config.cpus().unwrap_or(2))
        .set_memory_size(config.memory_mib().unwrap_or(2048) * 1024 * 1024)
        .set_platform(build_platform(config)?)
        .set_boot_loader(build_boot_loader(config)?)
        .add_entropy_device(EntropyDeviceConfiguration::new())
        .add_memory_balloon_device(MemoryBalloonDeviceConfiguration::new())
        .add_serial_port(serial_port.clone())
        .add_socket_device(SocketDeviceConfiguration::new());

    match config.network() {
        NetworkMode::None => {}
        NetworkMode::UnixDatagram { peer_path, mac } => {
            builder = builder.add_network_device(
                NetworkDeviceConfiguration::unix_datagram(peer_path, config.vm_id(), *mac)
                    .map_err(vz_error)?,
            );
        }
        NetworkMode::UnixStream { .. } | NetworkMode::Tap { .. } => {}
    }

    for disk in config.disks() {
        builder = builder.add_storage_device(
            StorageDeviceConfiguration::new(disk.path.clone(), disk.read_only).map_err(vz_error)?,
        );
    }

    for mount in config.mounts() {
        let shared_dir = SharedDirectory::new(mount.host_path.clone(), mount.read_only);
        let single_share = SingleDirectoryShare::new(shared_dir);
        let mut fs_config = VirtioFileSystemDeviceConfiguration::new(mount.tag.clone());
        fs_config.set_share(single_share);
        builder = builder.add_directory_share(fs_config);
    }

    if config.vz().rosetta {
        let mut rosetta_config = VirtioFileSystemDeviceConfiguration::new(SILO_ROSETTA_TAG);
        rosetta_config.set_rosetta_share(LinuxRosettaDirectoryShare::new().map_err(vz_error)?);
        builder = builder.add_directory_share(rosetta_config);
    }

    let vm = builder.build().map_err(vz_error)?;
    Ok((vm, serial_port))
}

fn build_platform(config: &VmConfig) -> Result<GenericPlatform, VirtError> {
    let mut platform = GenericPlatform::new();
    let machine_identifier = resolve_machine_identifier(config)?;
    platform.set_machine_identifier(machine_identifier);
    platform.set_nested_virtualization_enabled(config.nested_virtualization());
    Ok(platform)
}

fn build_boot_loader(config: &VmConfig) -> Result<LinuxBootLoader, VirtError> {
    let kernel_path = required_path(config.name(), config.kernel_path(), "kernel_path")?;

    let mut boot_loader = LinuxBootLoader::new(kernel_path);
    if let Some(initramfs_path) = config.initramfs_path() {
        boot_loader.set_initial_ramdisk(initramfs_path);
    }

    let mut args = vec!["console=hvc0".to_string(), "rd.break=initqueue".to_string()];
    args.extend(config.kernel_cmdline().iter().cloned());
    let command_line = args.join(" ");
    boot_loader.set_command_line(&command_line);
    Ok(boot_loader)
}

/// Resolve the platform identity, generating one on first boot and writing
/// the generated bytes back into the config's [`MachineIdentifier`] so the
/// caller can persist them.
fn resolve_machine_identifier(config: &VmConfig) -> Result<GenericMachineIdentifier, VirtError> {
    let Some(machine_identifier) = config.vz().machine_identifier.as_ref() else {
        return Ok(GenericMachineIdentifier::new());
    };

    if machine_identifier.is_empty() {
        let generated = GenericMachineIdentifier::new();
        machine_identifier.set_generated_bytes(generated.data());
        return Ok(generated);
    }

    GenericMachineIdentifier::from_bytes(&machine_identifier.bytes()).map_err(vz_error)
}

fn validate_machine_config(config: &VmConfig) -> Result<(), VirtError> {
    let invalid = |reason: String| VirtError::InvalidConfig {
        name: config.name().to_string(),
        reason,
    };

    if let Some(machine_identifier) = config.vz().machine_identifier.as_ref() {
        validate_machine_identifier(config.name(), machine_identifier)?;
    }

    validate_nested_virtualization(config)?;
    validate_rosetta(config)?;

    match config.network() {
        NetworkMode::None => {}
        NetworkMode::UnixDatagram { peer_path, .. } => {
            if peer_path.as_os_str().is_empty() || config.vm_id().is_empty() {
                return Err(invalid(
                    "unixdatagram networking requires a non-empty VM id and peer socket path"
                        .to_string(),
                ));
            }
        }
        NetworkMode::UnixStream { .. } => {
            return Err(invalid(
                "unixstream networking is not supported by the VZ backend".to_string(),
            ));
        }
        NetworkMode::Tap { .. } => {
            return Err(invalid(
                "tap networking is not supported by the VZ backend".to_string(),
            ));
        }
    }

    for mount in config.mounts() {
        let metadata = fs::metadata(&mount.host_path).map_err(|err| {
            invalid(format!(
                "failed to access shared directory {}: {err}",
                mount.host_path.display()
            ))
        })?;
        if !metadata.is_dir() {
            return Err(invalid(format!(
                "shared directory path is not a directory: {}",
                mount.host_path.display()
            )));
        }
    }

    Ok(())
}

fn validate_nested_virtualization(config: &VmConfig) -> Result<(), VirtError> {
    if !config.nested_virtualization() {
        return Ok(());
    }

    if !GenericPlatform::is_nested_virtualization_supported() {
        return Err(VirtError::InvalidConfig {
            name: config.name().to_string(),
            reason: "nested virtualization is not supported on this host".to_string(),
        });
    }

    Ok(())
}

fn validate_rosetta(config: &VmConfig) -> Result<(), VirtError> {
    if !config.vz().rosetta {
        return Ok(());
    }

    match vz::rosetta_availability() {
        RosettaAvailability::Installed => Ok(()),
        RosettaAvailability::NotInstalled => Err(VirtError::InvalidConfig {
            name: config.name().to_string(),
            reason: "Rosetta for Linux VMs is not installed on this host. Install it with: softwareupdate --install-rosetta"
                .to_string(),
        }),
        RosettaAvailability::NotSupported => Err(VirtError::InvalidConfig {
            name: config.name().to_string(),
            reason: "Rosetta is not supported on this host".to_string(),
        }),
    }
}

fn validate_machine_identifier(
    name: &str,
    machine_identifier: &MachineIdentifier,
) -> Result<(), VirtError> {
    if machine_identifier.is_empty() {
        return Ok(());
    }

    GenericMachineIdentifier::from_bytes(&machine_identifier.bytes())
        .map(|_| ())
        .map_err(|err| VirtError::InvalidConfig {
            name: name.to_string(),
            reason: err.to_string(),
        })
}

fn required_path<'a>(
    name: &str,
    path: Option<&'a Path>,
    field: &'static str,
) -> Result<&'a Path, VirtError> {
    path.ok_or_else(|| VirtError::InvalidConfig {
        name: name.to_string(),
        reason: format!("{field} must be set"),
    })
}

async fn wait_for_state(
    events: &mut tokio::sync::watch::Receiver<VirtualMachineState>,
    vm: &VirtualMachine,
    target: VirtualMachineState,
    timeout: Duration,
) -> Result<(), VirtError> {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let state = vm.state();
        tracing::debug!(current_state = %state, target_state = %target, "waiting for virtual machine state");

        if state == target {
            return Ok(());
        }

        if state == VirtualMachineState::Error {
            return Err(VirtError::Backend(format!(
                "machine entered error state while waiting for {target}"
            )));
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(VirtError::Backend(format!(
                "timed out after {timeout:?} waiting for machine to enter {target} (current state: {state})"
            )));
        }

        let remaining = deadline.saturating_duration_since(now);
        match tokio::time::timeout(remaining, events.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(VirtError::Backend(
                    "machine state watcher closed before target state was reached".to_string(),
                ));
            }
            Err(_) => {
                return Err(VirtError::Backend(format!(
                    "timed out after {timeout:?} waiting for machine to enter {target} (current state: {})",
                    vm.state()
                )));
            }
        }
    }
}

fn vz_error(err: VzError) -> VirtError {
    VirtError::Backend(err.to_string())
}
