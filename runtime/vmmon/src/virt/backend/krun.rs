//! libkrun backend (Linux), driving the spawned `krun` helper binary through
//! the `krun` crate. Vsock ports are unix sockets in a per-machine directory:
//! `Connect` ports are listened on by the helper (we dial), `Listen` ports
//! are pre-bound here before boot (the guest dials).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use krun::{
    Disk as KrunDisk, KrunBackendError, Mount as KrunMount, NetUnixgram as KrunNetUnixgram,
    VirtualMachine, VirtualMachineBuilder, VsockPort as KrunVsockPort,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{sleep, timeout};

use super::VirtBackend;
use crate::virt::config::{
    validate_common, DiskImage, NetworkMode, SharedDirectory, VmConfig, VsockPortMode,
};
use crate::virt::error::VirtError;
use crate::virt::stream::{SerialDevice, VsockListener, VsockStream};
use crate::virt::VmExit;

const VSOCK_DIR_NAME: &str = "krun.vsock";
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) struct KrunBackend {
    config: VmConfig,
    krun_bin: PathBuf,
    runtime_dir: PathBuf,
    exit: Arc<Mutex<Option<VmExit>>>,
    runtime: AsyncMutex<Option<RunningKrun>>,
}

struct RunningKrun {
    vm: Arc<AsyncMutex<VirtualMachine>>,
    listeners: HashMap<u32, UnixListener>,
}

impl std::fmt::Debug for KrunBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KrunBackend")
            .field("name", &self.config.name())
            .field("runtime_dir", &self.runtime_dir)
            .finish_non_exhaustive()
    }
}

impl KrunBackend {
    pub(crate) fn new(config: VmConfig) -> Result<Self, VirtError> {
        validate(&config)?;
        let krun_bin = resolved_krun_binary(&config)?;
        let runtime_dir = runtime_dir_for(&config);
        Ok(Self {
            config,
            krun_bin,
            runtime_dir,
            exit: Arc::new(Mutex::new(None)),
            runtime: AsyncMutex::new(None),
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
        }
    }

    fn clear_exit_cache(&self) {
        *self.exit.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

#[async_trait]
impl VirtBackend for KrunBackend {
    async fn start(&self) -> Result<(), VirtError> {
        let mut runtime = self.runtime.lock().await;
        if runtime.is_some() {
            return Err(VirtError::AlreadyRunning {
                name: self.config.name().to_string(),
            });
        }

        prepare(&self.config)?;
        self.clear_exit_cache();

        let listeners = prepare_vsock_ports(&self.config)?;
        let vm = build_krun_vm(&self.krun_bin, &self.config)?
            .start()
            .map_err(|err| krun_error(&self.config, err))?;
        tracing::info!(machine = %self.config.name(), "krun process started");
        *runtime = Some(RunningKrun {
            vm: Arc::new(AsyncMutex::new(vm)),
            listeners,
        });
        Ok(())
    }

    async fn stop(&self) -> Result<(), VirtError> {
        let running = {
            let mut runtime = self.runtime.lock().await;
            runtime.take()
        };
        let Some(running) = running else {
            self.cache_exit(VmExit::Stopped);
            return Ok(());
        };
        {
            let mut vm = running.vm.lock().await;
            if vm
                .try_wait()
                .map_err(|err| krun_error(&self.config, err))?
                .is_none()
            {
                let _ = vm.kill();
            }
        }
        let _ = timeout(STOP_TIMEOUT, wait_for_vm_exit(running.vm.clone())).await;
        self.cache_exit(VmExit::Stopped);
        Ok(())
    }

    async fn wait(&self) -> Result<VmExit, VirtError> {
        if let Some(exit) = self.cached_exit() {
            return Ok(exit);
        }
        let vm = {
            let runtime = self.runtime.lock().await;
            let Some(running) = runtime.as_ref() else {
                return Err(VirtError::NotRunning {
                    name: self.config.name().to_string(),
                });
            };
            running.vm.clone()
        };

        let status = wait_for_vm_exit(vm).await?;
        let exit = vm_exit_from_status(status);
        let _ = self.runtime.lock().await.take();
        self.cache_exit(exit.clone());
        Ok(exit)
    }

    async fn try_wait(&self) -> Result<Option<VmExit>, VirtError> {
        if let Some(exit) = self.cached_exit() {
            return Ok(Some(exit));
        }
        let vm = {
            let runtime = self.runtime.lock().await;
            let Some(running) = runtime.as_ref() else {
                return Ok(None);
            };
            running.vm.clone()
        };

        let Some(status) = vm
            .lock()
            .await
            .try_wait()
            .map_err(|err| krun_error(&self.config, err))?
        else {
            return Ok(None);
        };
        let exit = vm_exit_from_status(status);
        let _ = self.runtime.lock().await.take();
        self.cache_exit(exit.clone());
        Ok(Some(exit))
    }

    async fn connect_vsock(&self, port: u32) -> Result<VsockStream, VirtError> {
        {
            let runtime = self.runtime.lock().await;
            if runtime.is_none() {
                return Err(VirtError::NotRunning {
                    name: self.config.name().to_string(),
                });
            }
        }

        let Some(mode) = declared_vsock_mode(&self.config, port) else {
            return Err(VirtError::Backend(format!(
                "krun vsock port {port} was not declared before boot"
            )));
        };
        if mode != VsockPortMode::Connect {
            return Err(VirtError::Backend(format!(
                "krun vsock port {port} is declared for listen, not connect"
            )));
        }

        let stream = UnixStream::connect(vsock_path(&self.config, port, mode)).await?;
        Ok(VsockStream::from_unix_stream(stream))
    }

    async fn listen_vsock(&self, port: u32) -> Result<VsockListener, VirtError> {
        let Some(mode) = declared_vsock_mode(&self.config, port) else {
            return Err(VirtError::Backend(format!(
                "krun vsock port {port} was not declared before boot"
            )));
        };
        if mode != VsockPortMode::Listen {
            return Err(VirtError::Backend(format!(
                "krun vsock port {port} is declared for connect, not listen"
            )));
        }

        let listener = {
            let mut runtime = self.runtime.lock().await;
            let Some(running) = runtime.as_mut() else {
                return Err(VirtError::NotRunning {
                    name: self.config.name().to_string(),
                });
            };
            running.listeners.remove(&port).ok_or_else(|| {
                VirtError::Backend(format!(
                    "krun vsock listener for port {port} was already claimed"
                ))
            })?
        };

        Ok(VsockListener::from_unix_listener(listener))
    }

    async fn open_serial(&self) -> Result<SerialDevice, VirtError> {
        let serial = {
            let runtime = self.runtime.lock().await;
            let running = runtime.as_ref().ok_or_else(|| VirtError::NotRunning {
                name: self.config.name().to_string(),
            })?;
            let mut vm = running.vm.lock().await;
            vm.serial().map_err(|err| krun_error(&self.config, err))?
        };

        let (read, write) = serial.into_files();
        Ok(SerialDevice::from_files(read, write)?)
    }
}

fn validate(config: &VmConfig) -> Result<(), VirtError> {
    validate_common(config)?;

    if config.cpus().is_none() {
        return invalid_config(config, "krun requires a CPU count");
    }
    if config.memory_mib().is_none() {
        return invalid_config(config, "krun requires a memory size");
    }
    if config.cpus().is_some_and(|cpus| cpus > u8::MAX as usize) {
        return invalid_config(config, "krun supports at most 255 vCPUs");
    }
    if config
        .memory_mib()
        .is_some_and(|memory_mib| memory_mib > u32::MAX as u64)
    {
        return invalid_config(config, "krun memory_mib exceeds u32::MAX");
    }
    if config.vz().machine_identifier.is_some() {
        return invalid_config(
            config,
            "machine identifiers are not used by the krun backend",
        );
    }
    if config.vz().rosetta {
        return invalid_config(config, "rosetta is not implemented for the krun backend");
    }
    if config.nested_virtualization() {
        return invalid_config(
            config,
            "nested virtualization is not implemented for the krun backend yet",
        );
    }

    match config.network() {
        NetworkMode::None => {}
        NetworkMode::UnixDatagram { peer_path, .. } => {
            if peer_path.as_os_str().is_empty() || config.vm_id().is_empty() {
                return invalid_config(
                    config,
                    "unixdatagram networking requires a non-empty VM id and peer socket path",
                );
            }
        }
        NetworkMode::UnixStream { .. } => {
            return invalid_config(config, "unixstream networking is not implemented yet")
        }
        NetworkMode::Tap { .. } => {
            return invalid_config(config, "tap networking is not implemented yet")
        }
    }

    validate_vsock_ports(config)?;

    Ok(())
}

fn prepare(config: &VmConfig) -> Result<(), VirtError> {
    let kernel = config.kernel_path().expect("validated kernel missing");
    ensure_path_exists(config, kernel, "kernel image")?;
    if let Some(initramfs) = config.initramfs_path() {
        ensure_path_exists(config, initramfs, "initramfs")?;
    }
    for (index, disk) in config.disks().iter().enumerate() {
        ensure_path_exists(config, &disk.path, &format!("disk #{index}"))?;
    }
    for mount in config.mounts() {
        ensure_path_exists(config, &mount.host_path, &format!("mount {}", mount.tag))?;
    }
    std::fs::create_dir_all(runtime_dir_for(config))?;
    Ok(())
}

fn build_boot_args(config: &VmConfig) -> Vec<String> {
    let mut args = vec!["console=hvc0".to_string(), "panic=1".to_string()];
    args.extend(config.kernel_cmdline().iter().cloned());
    args
}

fn build_krun_vm(krun_bin: &Path, config: &VmConfig) -> Result<VirtualMachineBuilder, VirtError> {
    let cpus = config.cpus().ok_or_else(|| VirtError::InvalidConfig {
        name: config.name().to_string(),
        reason: "krun requires a CPU count".to_string(),
    })?;
    let memory_mib = config
        .memory_mib()
        .ok_or_else(|| VirtError::InvalidConfig {
            name: config.name().to_string(),
            reason: "krun requires a memory size".to_string(),
        })?;
    let cpus = u8::try_from(cpus).map_err(|_| VirtError::InvalidConfig {
        name: config.name().to_string(),
        reason: "krun supports at most 255 vCPUs".to_string(),
    })?;
    let memory_mib = u32::try_from(memory_mib).map_err(|_| VirtError::InvalidConfig {
        name: config.name().to_string(),
        reason: "krun memory_mib exceeds u32::MAX".to_string(),
    })?;
    let kernel = config
        .kernel_path()
        .ok_or_else(|| VirtError::InvalidConfig {
            name: config.name().to_string(),
            reason: "krun requires a kernel image path".to_string(),
        })?;
    let mut builder = VirtualMachineBuilder::new(krun_bin)
        .id(config.vm_id().to_string())
        .cpus(cpus)
        .memory_mib(memory_mib)
        .kernel(kernel)
        .cmdline(build_boot_args(config))
        .stdio_console(true);

    if let Some(initramfs) = config.initramfs_path() {
        builder = builder.initramfs(initramfs);
    }
    for (index, disk) in config.disks().iter().enumerate() {
        builder = builder.disk(krun_disk(format!("disk{index}"), disk));
    }
    for mount in config.mounts() {
        builder = builder.mount(krun_mount(mount));
    }
    for (port, mode) in unique_vsock_ports(config)? {
        builder = builder.vsock_port(KrunVsockPort {
            port,
            path: vsock_path(config, port, mode),
            listen: mode == VsockPortMode::Connect,
        });
    }
    if let NetworkMode::UnixDatagram { peer_path, mac } = config.network() {
        builder = builder.net_unixgram(KrunNetUnixgram {
            peer_path: peer_path.clone(),
            mac: *mac,
        });
    }

    Ok(builder)
}

fn krun_disk(block_id: String, disk: &DiskImage) -> KrunDisk {
    KrunDisk {
        block_id,
        path: disk.path.clone(),
        read_only: disk.read_only,
    }
}

fn krun_mount(mount: &SharedDirectory) -> KrunMount {
    KrunMount {
        tag: mount.tag.clone(),
        path: mount.host_path.clone(),
        read_only: mount.read_only,
    }
}

async fn wait_for_vm_exit(vm: Arc<AsyncMutex<VirtualMachine>>) -> Result<ExitStatus, VirtError> {
    loop {
        if let Some(status) = vm
            .lock()
            .await
            .try_wait()
            .map_err(|err| VirtError::Backend(err.to_string()))?
        {
            return Ok(status);
        }
        sleep(WAIT_POLL_INTERVAL).await;
    }
}

fn krun_error(config: &VmConfig, err: KrunBackendError) -> VirtError {
    match err {
        KrunBackendError::InvalidConfig(reason) => VirtError::InvalidConfig {
            name: config.name().to_string(),
            reason,
        },
        err @ KrunBackendError::HostCheck { .. } => VirtError::UnsupportedBackend {
            kind: "krun",
            reason: err.to_string(),
        },
        KrunBackendError::Io(err) => VirtError::Io(err),
        err => VirtError::Backend(err.to_string()),
    }
}

fn prepare_vsock_ports(config: &VmConfig) -> Result<HashMap<u32, UnixListener>, VirtError> {
    validate_vsock_ports(config)?;
    let vsock_dir = vsock_dir_for(config);
    std::fs::create_dir_all(&vsock_dir)?;

    let mut listeners = HashMap::new();
    for (port, mode) in unique_vsock_ports(config)? {
        let path = vsock_path(config, port, mode);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        if mode == VsockPortMode::Listen {
            listeners.insert(port, UnixListener::bind(&path)?);
        }
    }
    Ok(listeners)
}

fn validate_vsock_ports(config: &VmConfig) -> Result<(), VirtError> {
    let _ = unique_vsock_ports(config)?;
    Ok(())
}

fn unique_vsock_ports(config: &VmConfig) -> Result<Vec<(u32, VsockPortMode)>, VirtError> {
    let mut ports = HashMap::new();
    for port in config.vsock_ports() {
        if port.port == 0 {
            return invalid_config(config, "vsock port must be greater than zero");
        }
        match ports.insert(port.port, port.mode) {
            Some(existing) if existing != port.mode => {
                return invalid_config(
                    config,
                    &format!(
                        "vsock port {} is declared for both {:?} and {:?}",
                        port.port, existing, port.mode
                    ),
                )
            }
            _ => {}
        }
    }

    let mut ports = ports.into_iter().collect::<Vec<_>>();
    ports.sort_by_key(|(port, _)| *port);
    Ok(ports)
}

fn declared_vsock_mode(config: &VmConfig, port: u32) -> Option<VsockPortMode> {
    config
        .vsock_ports()
        .iter()
        .find(|candidate| candidate.port == port)
        .map(|candidate| candidate.mode)
}

fn vsock_path(config: &VmConfig, port: u32, mode: VsockPortMode) -> PathBuf {
    let direction = match mode {
        VsockPortMode::Connect => "connect",
        VsockPortMode::Listen => "listen",
    };
    vsock_dir_for(config).join(format!("{direction}-{port}.sock"))
}

fn vsock_dir_for(config: &VmConfig) -> PathBuf {
    runtime_dir_for(config).join(VSOCK_DIR_NAME)
}

fn resolved_krun_binary(config: &VmConfig) -> Result<PathBuf, VirtError> {
    let path = config
        .krun()
        .helper_path
        .as_ref()
        .ok_or_else(|| VirtError::InvalidConfig {
            name: config.name().to_string(),
            reason: "krun helper path is required".to_string(),
        })?;
    if !path.is_absolute() || !path.is_file() {
        return invalid_config(
            config,
            &format!(
                "krun helper must be an absolute regular file: {}",
                path.display()
            ),
        );
    }
    Ok(path.clone())
}

fn runtime_dir_for(config: &VmConfig) -> PathBuf {
    config.base_directory().to_path_buf()
}

fn ensure_path_exists(config: &VmConfig, path: &Path, label: &str) -> Result<(), VirtError> {
    if path.exists() {
        return Ok(());
    }
    invalid_config(
        config,
        &format!("{label} does not exist: {}", path.display()),
    )
}

fn vm_exit_from_status(status: ExitStatus) -> VmExit {
    if status.success() {
        return VmExit::Stopped;
    }
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            return VmExit::StoppedWithError(format!("krun exited with status code {code}"));
        }
        if let Some(signal) = status.signal() {
            return VmExit::StoppedWithError(format!("krun exited after signal {signal}"));
        }
    }
    VmExit::StoppedWithError("krun exited with an unknown status".to_string())
}

fn invalid_config<T>(config: &VmConfig, reason: &str) -> Result<T, VirtError> {
    Err(VirtError::InvalidConfig {
        name: config.name().to_string(),
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::KrunBackend;
    use crate::virt::backend::VirtBackend;
    use crate::virt::{NetworkMode, VmConfig, VmExit};

    fn test_dir() -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vmmon-resolved-krun-{}-{timestamp}",
            std::process::id()
        ))
    }

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).expect("write executable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("make executable");
    }

    #[tokio::test]
    async fn resolved_krun_path_reaches_the_real_backend_child() {
        let root = test_dir();
        fs::create_dir_all(&root).expect("create test root");
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").expect("write kernel");
        let krun = root.join("krun");
        write_executable(
            &krun,
            "#!/bin/sh\nif [ \"$1\" = \"--check-host-basic\" ]; then exit 0; fi\nkernel=\nprevious=\nfor arg do\n  if [ \"$previous\" = \"--kernel\" ]; then kernel=$arg; fi\n  previous=$arg\ndone\nprintf '%s\\n' \"$0\" > \"${kernel%/*}/krun.program\"\nprintf '%s\\n' \"$@\" > \"${kernel%/*}/krun.args\"\n",
        );
        let krun = krun.canonicalize().expect("canonical krun");
        let kernel = kernel.canonicalize().expect("canonical kernel");
        let config = VmConfig::builder("resolved-krun")
            .vm_id("machine-1")
            .cpus(1)
            .memory(128)
            .base_directory(&root)
            .krun_path(&krun)
            .kernel(&kernel)
            .network(NetworkMode::None)
            .build();
        let backend = KrunBackend::new(config).expect("create krun backend");

        backend.start().await.expect("spawn resolved krun");
        assert_eq!(
            backend.wait().await.expect("wait for krun"),
            VmExit::Stopped
        );
        assert_eq!(
            fs::read_to_string(root.join("krun.program"))
                .expect("read executed krun path")
                .trim(),
            krun.display().to_string()
        );
        let args = fs::read_to_string(root.join("krun.args")).expect("read krun arguments");
        assert!(args.lines().any(|arg| arg == "--id"));
        assert!(args.lines().any(|arg| arg == "machine-1"));
        assert!(args.lines().any(|arg| arg == "--kernel"));
        assert!(args.lines().any(|arg| arg == kernel.display().to_string()));

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[tokio::test]
    async fn failed_host_check_prevents_krun_vm_launch() {
        let root = test_dir();
        fs::create_dir_all(&root).expect("create test root");
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").expect("write kernel");
        let krun = root.join("krun");
        write_executable(
            &krun,
            "#!/bin/sh\nif [ \"$1\" = \"--check-host-basic\" ]; then echo 'open /dev/kvm: Permission denied. Hint: check device-cgroup policy' >&2; exit 1; fi\ntouch \"$0.launched\"\n",
        );
        let krun = krun.canonicalize().expect("canonical krun");
        let kernel = kernel.canonicalize().expect("canonical kernel");
        let config = VmConfig::builder("unavailable-krun")
            .vm_id("machine-1")
            .cpus(1)
            .memory(128)
            .base_directory(&root)
            .krun_path(&krun)
            .kernel(&kernel)
            .network(NetworkMode::None)
            .build();
        let backend = KrunBackend::new(config).expect("create krun backend");

        let error = backend.start().await.expect_err("host check must fail");
        let message = error.to_string();
        assert!(message.contains("open /dev/kvm: Permission denied"));
        assert!(message.contains("device-cgroup policy"));
        assert!(!krun.with_extension("launched").exists());

        fs::remove_dir_all(root).expect("remove test root");
    }
}
