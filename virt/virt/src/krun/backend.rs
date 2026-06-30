use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use krun::{
    Disk as KrunDisk, KrunBackendError, Mount as KrunMount, NetUnixgram as KrunNetUnixgram,
    VirtualMachine, VirtualMachineBuilder, VsockPort as KrunVsockPort,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{sleep, timeout};

use crate::stream::{MachineSerialStream, VsockListener, VsockStream};
use crate::types::{
    DiskImage, NetworkMode, SharedDirectory, VirtError, VmConfig, VmExit, VsockPortMode,
};

const KRUN_BINARY_ENV: &str = "KRUN_BIN";
const KRUN_BINARY_NAME: &str = "krun";
const VSOCK_DIR_NAME: &str = "krun.vsock";
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) struct KrunMachineBackend {
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

impl std::fmt::Debug for KrunMachineBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KrunMachineBackend")
            .field("name", &self.config.name.as_str())
            .field("runtime_dir", &self.runtime_dir)
            .finish_non_exhaustive()
    }
}

fn validate(config: &VmConfig) -> Result<(), VirtError> {
    if config.cpus.is_none() {
        return invalid_config(config, "krun requires a CPU count");
    }
    if config.memory_mib.is_none() {
        return invalid_config(config, "krun requires a memory size");
    }
    if matches!(config.cpus, Some(0)) {
        return invalid_config(config, "krun requires at least one vCPU");
    }
    if config.cpus.is_some_and(|cpus| cpus > u8::MAX as usize) {
        return invalid_config(config, "krun supports at most 255 vCPUs");
    }
    if matches!(config.memory_mib, Some(0)) {
        return invalid_config(config, "krun requires memory_mib to be greater than zero");
    }
    if config
        .memory_mib
        .is_some_and(|memory_mib| memory_mib > u32::MAX as u64)
    {
        return invalid_config(config, "krun memory_mib exceeds u32::MAX");
    }
    if config.kernel_path.is_none() {
        return invalid_config(config, "krun requires a kernel image path");
    }
    if config.machine_identifier.is_some() {
        return invalid_config(
            config,
            "machine identifiers are not used by the krun backend",
        );
    }
    if config.rosetta {
        return invalid_config(config, "rosetta is not implemented for the krun backend");
    }
    if config.nested_virtualization {
        return invalid_config(
            config,
            "nested virtualization is not implemented for the krun backend yet",
        );
    }

    match &config.network {
        NetworkMode::None => {}
        NetworkMode::UnixDatagram { peer_path, .. } => {
            validate_unix_datagram_network(config, peer_path)?
        }
        NetworkMode::VzNat => {
            return invalid_config(
                config,
                "vznat networking is only supported by the VZ backend",
            )
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

fn validate_unix_datagram_network(config: &VmConfig, peer_path: &Path) -> Result<(), VirtError> {
    if !peer_path.as_os_str().is_empty() && !config.vm_id.is_empty() {
        return Ok(());
    }

    invalid_config(
        config,
        "unixdatagram networking requires a non-empty VM id and peer socket path",
    )
}

fn prepare(config: &VmConfig) -> Result<(), VirtError> {
    if config.base_directory.as_os_str().is_empty() {
        return invalid_config(config, "base_directory must be set");
    }
    ensure_path_exists(
        config,
        config
            .kernel_path
            .as_ref()
            .expect("validated kernel missing"),
        "kernel image",
    )?;
    if let Some(initramfs) = config.initramfs_path.as_ref() {
        ensure_path_exists(config, initramfs, "initramfs")?;
    }
    for (index, disk) in config.disks.iter().enumerate() {
        ensure_path_exists(config, &disk.path, &format!("disk #{index}"))?;
    }
    for mount in &config.mounts {
        ensure_path_exists(config, &mount.host_path, &format!("mount {}", mount.tag))?;
    }
    std::fs::create_dir_all(runtime_dir_for(config))?;
    Ok(())
}

impl KrunMachineBackend {
    pub(crate) fn new(config: VmConfig) -> Result<Self, VirtError> {
        validate(&config)?;
        let krun_bin = locate_krun_binary()?;
        let runtime_dir = runtime_dir_for(&config);
        Ok(Self {
            config,
            krun_bin,
            runtime_dir,
            exit: Arc::new(Mutex::new(None)),
            runtime: AsyncMutex::new(None),
        })
    }

    pub(crate) async fn start(&self) -> Result<(), VirtError> {
        let mut runtime = self.runtime.lock().await;
        if runtime.is_some() {
            return Err(VirtError::AlreadyRunning {
                name: self.config.name.clone(),
            });
        }

        prepare(&self.config)?;
        self.clear_exit_cache()?;

        let listeners = prepare_vsock_ports(&self.config)?;
        let vm = build_krun_vm(&self.krun_bin, &self.config)?
            .start()
            .map_err(|err| krun_error(&self.config, err))?;
        tracing::info!(machine = %self.config.name, "krun process started");
        *runtime = Some(RunningKrun {
            vm: Arc::new(AsyncMutex::new(vm)),
            listeners,
        });
        Ok(())
    }

    pub(crate) async fn stop(&self) -> Result<(), VirtError> {
        let running = {
            let mut runtime = self.runtime.lock().await;
            runtime.take()
        };
        let Some(running) = running else {
            self.cache_exit(VmExit::Stopped)?;
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
        self.cache_exit(VmExit::Stopped)?;
        Ok(())
    }

    pub(crate) async fn connect_vsock(&self, port: u32) -> Result<VsockStream, VirtError> {
        {
            let runtime = self.runtime.lock().await;
            if runtime.is_none() {
                return Err(VirtError::Backend(format!(
                    "cannot open vsock stream because machine {:?} is not running",
                    self.config.name.as_str()
                )));
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

    pub(crate) async fn listen_vsock(&self, port: u32) -> Result<VsockListener, VirtError> {
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
                return Err(VirtError::Backend(format!(
                    "cannot listen on vsock port because machine {:?} is not running",
                    self.config.name.as_str()
                )));
            };
            running.listeners.remove(&port).ok_or_else(|| {
                VirtError::Backend(format!(
                    "krun vsock listener for port {port} was already claimed"
                ))
            })?
        };

        Ok(VsockListener::from_unix_listener(listener))
    }

    pub(crate) async fn open_serial(&self) -> Result<MachineSerialStream, VirtError> {
        let serial = {
            let runtime = self.runtime.lock().await;
            let running = runtime.as_ref().ok_or_else(|| {
                VirtError::Backend(format!(
                    "cannot open serial stream because machine {:?} is not running",
                    self.config.name.as_str()
                ))
            })?;
            let mut vm = running.vm.lock().await;
            vm.serial().map_err(|err| krun_error(&self.config, err))?
        };

        let (read, write) = serial.into_files();
        Ok(MachineSerialStream::from_files(read, write)?)
    }

    pub(crate) async fn wait(&self) -> Result<VmExit, VirtError> {
        if let Some(exit) = self.cached_exit()? {
            return Ok(exit);
        }
        let vm = {
            let runtime = self.runtime.lock().await;
            let Some(running) = runtime.as_ref() else {
                return Err(VirtError::Backend(
                    "cannot wait for a virtual machine that has not been started".to_string(),
                ));
            };
            running.vm.clone()
        };

        let status = wait_for_vm_exit(vm).await?;
        let exit = vm_exit_from_status(status);
        let _ = self.runtime.lock().await.take();
        self.cache_exit(exit.clone())?;
        Ok(exit)
    }

    pub(crate) async fn try_wait(&self) -> Result<Option<VmExit>, VirtError> {
        if let Some(exit) = self.cached_exit()? {
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
        self.cache_exit(exit.clone())?;
        Ok(Some(exit))
    }

    fn cached_exit(&self) -> Result<Option<VmExit>, VirtError> {
        self.exit
            .lock()
            .map(|exit| exit.clone())
            .map_err(|_| VirtError::RegistryPoisoned)
    }

    fn cache_exit(&self, exit: VmExit) -> Result<(), VirtError> {
        let mut slot = self.exit.lock().map_err(|_| VirtError::RegistryPoisoned)?;
        if slot.is_none() {
            *slot = Some(exit);
        }
        Ok(())
    }

    fn clear_exit_cache(&self) -> Result<(), VirtError> {
        let mut slot = self.exit.lock().map_err(|_| VirtError::RegistryPoisoned)?;
        *slot = None;
        Ok(())
    }
}

fn build_boot_args(config: &VmConfig) -> Vec<String> {
    let mut args = vec!["console=hvc0".to_string(), "panic=1".to_string()];
    args.extend(config.kernel_cmdline.iter().cloned());
    args
}

fn build_krun_vm(krun_bin: &Path, config: &VmConfig) -> Result<VirtualMachineBuilder, VirtError> {
    let cpus = config.cpus.ok_or_else(|| VirtError::InvalidConfig {
        name: config.name.clone(),
        reason: "krun requires a CPU count".to_string(),
    })?;
    let memory_mib = config.memory_mib.ok_or_else(|| VirtError::InvalidConfig {
        name: config.name.clone(),
        reason: "krun requires a memory size".to_string(),
    })?;
    let cpus = u8::try_from(cpus).map_err(|_| VirtError::InvalidConfig {
        name: config.name.clone(),
        reason: "krun supports at most 255 vCPUs".to_string(),
    })?;
    let memory_mib = u32::try_from(memory_mib).map_err(|_| VirtError::InvalidConfig {
        name: config.name.clone(),
        reason: "krun memory_mib exceeds u32::MAX".to_string(),
    })?;
    let kernel = config
        .kernel_path
        .as_ref()
        .ok_or_else(|| VirtError::InvalidConfig {
            name: config.name.clone(),
            reason: "krun requires a kernel image path".to_string(),
        })?;
    let mut builder = VirtualMachineBuilder::new(krun_bin)
        .id(config.vm_id.clone())
        .cpus(cpus)
        .memory_mib(memory_mib)
        .kernel(kernel)
        .cmdline(build_boot_args(config))
        .stdio_console(true);

    if let Some(initramfs) = config.initramfs_path.as_ref() {
        builder = builder.initramfs(initramfs);
    }
    for (index, disk) in config.disks.iter().enumerate() {
        builder = builder.disk(krun_disk(format!("disk{index}"), disk));
    }
    for mount in &config.mounts {
        builder = builder.mount(krun_mount(mount));
    }
    for (port, mode) in unique_vsock_ports(config)? {
        builder = builder.vsock_port(KrunVsockPort {
            port,
            path: vsock_path(config, port, mode),
            listen: mode == VsockPortMode::Connect,
        });
    }
    if let NetworkMode::UnixDatagram { peer_path, mac } = &config.network {
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
            name: config.name.clone(),
            reason,
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
    for port in &config.vsock_ports {
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
        .vsock_ports
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

fn locate_krun_binary() -> Result<PathBuf, VirtError> {
    if let Some(path) = env::var_os(KRUN_BINARY_ENV) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(VirtError::UnsupportedBackend {
            kind: "krun",
            reason: format!(
                "{KRUN_BINARY_ENV} is set but does not point to a file: {}",
                path.display()
            ),
        });
    }

    if let Ok(current_exe) = env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            let candidate = dir.join(KRUN_BINARY_NAME);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    let path = env::var_os("PATH").ok_or_else(|| VirtError::UnsupportedBackend {
        kind: "krun",
        reason: "PATH is not set, so the krun binary cannot be located".to_string(),
    })?;
    for entry in env::split_paths(&path) {
        let candidate = entry.join(KRUN_BINARY_NAME);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(VirtError::UnsupportedBackend {
        kind: "krun",
        reason: "krun binary was not found in PATH".to_string(),
    })
}

fn runtime_dir_for(config: &VmConfig) -> PathBuf {
    config.base_directory.clone()
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
    #[cfg(unix)]
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
        name: config.name.clone(),
        reason: reason.to_string(),
    })
}
