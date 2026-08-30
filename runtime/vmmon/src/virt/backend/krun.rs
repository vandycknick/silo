//! libkrun backend (Linux), using an embedded vhost-user vsock device for the
//! same dynamic host surface exposed by the other virtualization backends.

use std::collections::HashMap;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use krun::{
    Disk as KrunDisk, KrunBackendError, Mount as KrunMount, NetUnixgram as KrunNetUnixgram,
    VirtualMachine, VirtualMachineBuilder,
};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{sleep, timeout};

use crate::virt::backend::VirtBackend;
use crate::virt::capacity::{VsockCapacity, VsockLease, MAX_ACTIVE_VSOCK_CONNECTIONS};
use crate::virt::config::{validate_common, DiskImage, NetworkMode, SharedDirectory, VmConfig};
use crate::virt::error::VirtError;
use crate::virt::stream::{PendingUnixVsock, SerialDevice, VsockListener, VsockStream};
use crate::virt::VmExit;

const VSOCK_DIR_NAME: &str = "krun.vsock";
const VHOST_SOCKET_NAME: &str = "vhost.sock";
const MAX_VSOCK_LISTENERS: usize = 1024;
const GUEST_CID: u64 = 3;
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) struct KrunBackend {
    config: VmConfig,
    krun_bin: PathBuf,
    runtime_dir: PathBuf,
    exit: Arc<Mutex<Option<VmExit>>>,
    runtime: AsyncMutex<Option<RunningKrun>>,
    vsock_registry: KrunVsockRegistry,
}

struct RunningKrun {
    vm: Arc<AsyncMutex<VirtualMachine>>,
    vsock: vhost_vsock::BackendServer,
    host_connector: vhost_vsock::HostConnector,
    vsock_session: Arc<AtomicBool>,
}

#[derive(Clone, Default)]
struct KrunVsockRegistry {
    listeners: Arc<Mutex<HashMap<u32, KrunVsockListener>>>,
}

#[derive(Clone)]
struct KrunVsockListener {
    sender: mpsc::Sender<PendingUnixVsock>,
    capacity: VsockCapacity,
    session_active: Arc<AtomicBool>,
}

impl KrunVsockRegistry {
    fn connect_guest(
        &self,
        request: vhost_vsock::ConnectionRequest,
        session_active: Arc<AtomicBool>,
    ) -> Option<StdUnixStream> {
        if !session_active.load(Ordering::Acquire) {
            return None;
        }
        let listener = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&request.destination_port)
            .cloned()?;
        if !Arc::ptr_eq(&listener.session_active, &session_active)
            || !listener.session_active.load(Ordering::Acquire)
        {
            return None;
        }
        let lease = listener.capacity.reserve().ok()?;
        let (backend_stream, vmmon_stream) = StdUnixStream::pair().ok()?;
        vmmon_stream.set_nonblocking(true).ok()?;
        listener
            .sender
            .try_send(PendingUnixVsock {
                stream: vmmon_stream,
                source_port: request.source_port,
                destination_port: request.destination_port,
                lease,
                session_active,
            })
            .ok()?;
        Some(backend_stream)
    }

    fn register(
        &self,
        port: u32,
        capacity: VsockCapacity,
        session_active: Arc<AtomicBool>,
    ) -> Result<VsockListener, VirtError> {
        if !session_active.load(Ordering::Acquire) {
            return Err(VirtError::Backend(
                "krun vsock frontend stopped while registering listener".to_string(),
            ));
        }
        let (sender, receiver) = mpsc::channel(MAX_ACTIVE_VSOCK_CONNECTIONS);
        {
            let mut listeners = self
                .listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if listeners
                .get(&port)
                .is_some_and(|listener| listener.session_active.load(Ordering::Acquire))
            {
                return Err(VirtError::Backend(format!(
                    "krun vsock port {port} already has a listener"
                )));
            }
            listeners.remove(&port);
            if listeners.len() >= MAX_VSOCK_LISTENERS {
                return Err(VirtError::Backend(format!(
                    "krun has reached its listener registration limit of {MAX_VSOCK_LISTENERS}"
                )));
            }
            listeners.insert(
                port,
                KrunVsockListener {
                    sender: sender.clone(),
                    capacity: capacity.clone(),
                    session_active: session_active.clone(),
                },
            );
        }

        let listeners = self.listeners.clone();
        Ok(VsockListener::from_krun_channel(
            receiver,
            port,
            capacity,
            move || {
                let mut listeners = listeners.lock().unwrap_or_else(PoisonError::into_inner);
                if listeners
                    .get(&port)
                    .is_some_and(|listener| listener.sender.same_channel(&sender))
                {
                    listeners.remove(&port);
                }
            },
        ))
    }
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
            vsock_registry: KrunVsockRegistry::default(),
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

        let registry = self.vsock_registry.clone();
        let vsock_session = Arc::new(AtomicBool::new(true));
        let session_for_connections = vsock_session.clone();
        let vsock = vhost_vsock::BackendServer::start(
            vhost_socket_for(&self.config),
            GUEST_CID,
            move |request| registry.connect_guest(request, session_for_connections.clone()),
        )
        .map_err(|error| VirtError::Backend(error.to_string()))?;
        let vm = match build_krun_vm(&self.krun_bin, &self.config, vsock.vhost_socket())?.start() {
            Ok(vm) => vm,
            Err(error) => {
                vsock_session.store(false, Ordering::Release);
                let _ = shutdown_vsock(vsock).await;
                return Err(krun_error(&self.config, error));
            }
        };
        tracing::info!(machine = %self.config.name(), "krun process started");
        let host_connector = vsock.host_connector();
        *runtime = Some(RunningKrun {
            vm: Arc::new(AsyncMutex::new(vm)),
            vsock,
            host_connector,
            vsock_session,
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
        let RunningKrun {
            vm,
            vsock,
            host_connector: _,
            vsock_session,
        } = running;
        vsock_session.store(false, Ordering::Release);
        {
            let mut vm = vm.lock().await;
            if vm
                .try_wait()
                .map_err(|err| krun_error(&self.config, err))?
                .is_none()
            {
                let _ = vm.kill();
            }
        }
        let _ = timeout(STOP_TIMEOUT, wait_for_vm_exit(vm)).await;
        shutdown_vsock(vsock).await?;
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
        if let Some(running) = self.runtime.lock().await.take() {
            running.vsock_session.store(false, Ordering::Release);
            shutdown_vsock(running.vsock).await?;
        }
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
        if let Some(running) = self.runtime.lock().await.take() {
            running.vsock_session.store(false, Ordering::Release);
            shutdown_vsock(running.vsock).await?;
        }
        self.cache_exit(exit.clone());
        Ok(Some(exit))
    }

    async fn connect_vsock(&self, port: u32, lease: VsockLease) -> Result<VsockStream, VirtError> {
        let host_connector = {
            let runtime = self.runtime.lock().await;
            let running = runtime.as_ref().ok_or_else(|| VirtError::NotRunning {
                name: self.config.name().to_string(),
            })?;
            running.host_connector.clone()
        };

        let mut stream = UnixStream::from_std(host_connector.connect(port)?)?;
        let source_port = read_vhost_connect_response(&mut stream).await?;
        Ok(VsockStream::from_unix_stream(
            stream,
            Some(source_port),
            port,
            Some(lease),
        ))
    }

    async fn listen_vsock(
        &self,
        port: u32,
        capacity: VsockCapacity,
    ) -> Result<VsockListener, VirtError> {
        let runtime = self.runtime.lock().await;
        let running = runtime.as_ref().ok_or_else(|| VirtError::NotRunning {
            name: self.config.name().to_string(),
        })?;

        self.vsock_registry
            .register(port, capacity, running.vsock_session.clone())
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
        Ok(SerialDevice::from_pty_files(read, write)?)
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
    std::fs::create_dir_all(vsock_dir_for(config))?;
    validate_private_vsock_paths(config)?;
    Ok(())
}

fn build_boot_args(config: &VmConfig) -> Vec<String> {
    let mut args = vec!["console=hvc0".to_string(), "panic=1".to_string()];
    args.extend(config.kernel_cmdline().iter().cloned());
    args
}

fn build_krun_vm(
    krun_bin: &Path,
    config: &VmConfig,
    vhost_socket: &Path,
) -> Result<VirtualMachineBuilder, VirtError> {
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
        .vhost_user_vsock(vhost_socket)
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

async fn read_vhost_connect_response(stream: &mut UnixStream) -> io::Result<u32> {
    const MAX_RESPONSE_BYTES: usize = 64;

    let mut response = Vec::with_capacity(MAX_RESPONSE_BYTES);
    while response.len() < MAX_RESPONSE_BYTES {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        response.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }

    let response = std::str::from_utf8(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if let Some(port) = response
        .strip_suffix('\n')
        .and_then(|response| response.strip_prefix("OK "))
        .and_then(|port| port.parse::<u32>().ok())
        .filter(|port| ((1_u32 << 30)..(1_u32 << 31)).contains(port))
    {
        return Ok(port);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid vhost-user vsock response: {response:?}"),
    ))
}

async fn shutdown_vsock(mut server: vhost_vsock::BackendServer) -> Result<(), VirtError> {
    tokio::task::spawn_blocking(move || loop {
        match server.shutdown() {
            Err(vhost_vsock::BackendError::ShutdownTimeout) => continue,
            result => break result,
        }
    })
    .await
    .map_err(|error| VirtError::Backend(format!("vhost-user shutdown task failed: {error}")))?
    .map_err(|error| VirtError::Backend(error.to_string()))
}

fn vhost_socket_for(config: &VmConfig) -> PathBuf {
    vsock_dir_for(config).join(VHOST_SOCKET_NAME)
}

fn validate_private_vsock_paths(config: &VmConfig) -> Result<(), VirtError> {
    let limit = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path)
        - 1;
    let path = vhost_socket_for(config);
    let length = path.as_os_str().as_bytes().len();
    if length > limit {
        return invalid_config(
            config,
            &format!(
                "private vsock path is {length} bytes, exceeding the Unix socket limit of {limit}: {}",
                path.display()
            ),
        );
    }
    Ok(())
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use super::{
        read_vhost_connect_response, validate_private_vsock_paths, KrunBackend, KrunVsockRegistry,
        MAX_VSOCK_LISTENERS,
    };
    use crate::virt::backend::VirtBackend;
    use crate::virt::capacity::VsockCapacity;
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
        assert!(args.lines().any(|arg| arg == "--vhost-user-vsock"));
        assert!(!args.lines().any(|arg| arg == "--vsock-port"));

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

    #[tokio::test]
    async fn registry_routes_dynamic_guest_connections_and_releases_capacity() {
        let registry = KrunVsockRegistry::default();
        let capacity = VsockCapacity::test_with_limit("krun-registry", 1);
        let session = Arc::new(AtomicBool::new(true));
        let mut listener = registry
            .register(7000, capacity.clone(), session.clone())
            .expect("register listener");

        let backend_stream = registry
            .connect_guest(
                vhost_vsock::ConnectionRequest {
                    source_port: 4000,
                    destination_port: 7000,
                },
                session.clone(),
            )
            .expect("route first guest connection");
        let accepted = listener.accept().await.expect("accept routed connection");
        assert_eq!(accepted.source_port(), Some(4000));
        assert_eq!(accepted.destination_port(), 7000);
        assert!(accepted.owns_capacity(&capacity));
        assert!(registry
            .connect_guest(
                vhost_vsock::ConnectionRequest {
                    source_port: 4001,
                    destination_port: 7000,
                },
                session.clone(),
            )
            .is_none());

        drop(backend_stream);
        drop(accepted);
        assert!(registry
            .connect_guest(
                vhost_vsock::ConnectionRequest {
                    source_port: 4001,
                    destination_port: 7000,
                },
                session.clone(),
            )
            .is_some());

        drop(listener);
        assert!(registry
            .connect_guest(
                vhost_vsock::ConnectionRequest {
                    source_port: 4002,
                    destination_port: 7000,
                },
                session,
            )
            .is_none());
    }

    #[tokio::test]
    async fn connect_response_is_consumed_without_buffering_guest_data() {
        let (mut client, mut backend) = UnixStream::pair().expect("create stream pair");
        backend
            .write_all(b"OK 1073741824\nguest payload")
            .await
            .expect("write response and payload");

        let source_port = read_vhost_connect_response(&mut client)
            .await
            .expect("read connect response");
        assert_eq!(source_port, 1_u32 << 30);
        let mut payload = vec![0_u8; "guest payload".len()];
        client
            .read_exact(&mut payload)
            .await
            .expect("read preserved guest payload");
        assert_eq!(payload, b"guest payload");
    }

    #[test]
    fn listener_discards_pending_connections_from_a_stopped_frontend() {
        let registry = KrunVsockRegistry::default();
        let capacity = VsockCapacity::test_with_limit("krun-session", 1);
        let session = Arc::new(AtomicBool::new(true));
        let mut listener = registry
            .register(7000, capacity.clone(), session.clone())
            .expect("register listener");
        let backend_stream = registry
            .connect_guest(
                vhost_vsock::ConnectionRequest {
                    source_port: 4000,
                    destination_port: 7000,
                },
                session.clone(),
            )
            .expect("queue guest connection");

        session.store(false, Ordering::Release);
        drop(backend_stream);
        assert!(listener
            .try_accept()
            .expect("discard stopped-session connection")
            .is_none());
        assert_eq!(capacity.available_permits(), 1);

        let next_session = Arc::new(AtomicBool::new(true));
        assert!(registry
            .connect_guest(
                vhost_vsock::ConnectionRequest {
                    source_port: 4001,
                    destination_port: 7000,
                },
                next_session.clone(),
            )
            .is_none());
        let replacement = registry
            .register(7000, capacity, next_session)
            .expect("replace stopped-session listener");
        drop(listener);
        assert!(registry.listeners.lock().unwrap().contains_key(&7000));
        drop(replacement);
    }

    #[tokio::test]
    async fn invalid_connect_response_is_rejected() {
        let (mut client, mut backend) = UnixStream::pair().expect("create stream pair");
        backend
            .write_all(b"NO 7000\n")
            .await
            .expect("write invalid response");

        let error = read_vhost_connect_response(&mut client)
            .await
            .expect_err("invalid response must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn registry_enforces_listener_limit_separately_from_connection_capacity() {
        let registry = KrunVsockRegistry::default();
        let capacity = VsockCapacity::new("krun-listeners");
        let session = Arc::new(AtomicBool::new(true));
        let listeners = (0..MAX_VSOCK_LISTENERS)
            .map(|port| {
                registry
                    .register(port as u32 + 1, capacity.clone(), session.clone())
                    .expect("register through exact listener limit")
            })
            .collect::<Vec<_>>();

        let error = registry
            .register(MAX_VSOCK_LISTENERS as u32 + 1, capacity, session)
            .expect_err("listener after exact limit must fail");
        assert!(error.to_string().contains("listener registration limit"));
        drop(listeners);
    }

    #[test]
    fn private_socket_paths_are_validated_before_launch() {
        let config = VmConfig::builder("long-runtime-path")
            .base_directory(PathBuf::from("/").join("x".repeat(200)))
            .build();

        let error = validate_private_vsock_paths(&config)
            .expect_err("overlong private socket path must fail");
        assert!(error.to_string().contains("Unix socket limit"));
    }
}
