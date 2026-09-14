//! Process-backed libkrun backend with a private descriptor-passing vsock mux.

mod mux;

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use krun::{
    Disk as KrunDisk, KrunBackendError, Mount as KrunMount, NetUnixgram as KrunNetUnixgram,
    VirtualMachine, VirtualMachineBuilder,
};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{sleep, timeout, timeout_at};

use crate::virt::backend::VirtBackend;
use crate::virt::capacity::{VsockLease, VsockListenerAdmission, MAX_ACTIVE_VSOCK_CONNECTIONS};
use crate::virt::config::{validate_common, DiskImage, NetworkMode, SharedDirectory, VmConfig};
use crate::virt::error::VirtError;
use crate::virt::stream::{
    KrunVsockSession, PendingUnixVsock, SerialDevice, VsockListener, VsockStream,
};
use crate::virt::VmExit;

const MAX_VSOCK_LISTENERS: usize = 1024;
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const VSOCK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
    mux: mux::KrunVsockMux,
    mux_task: mux::KrunVsockMuxTask,
    session: Arc<KrunVsockSession>,
}

#[derive(Clone, Copy)]
struct ConnectionRequest {
    id: u32,
    source_port: u32,
    destination_port: u32,
}

#[derive(Debug)]
struct Rejected;

#[derive(Clone, Default)]
struct KrunVsockRegistry {
    listeners: Arc<Mutex<HashMap<u32, KrunVsockListener>>>,
    next_registration: Arc<AtomicU64>,
}

#[derive(Clone)]
struct KrunVsockListener {
    sender: mpsc::Sender<PendingUnixVsock>,
    admission: VsockListenerAdmission,
    session: Arc<KrunVsockSession>,
    registration: u64,
}

impl KrunVsockRegistry {
    fn connect_guest_stream(
        &self,
        request: ConnectionRequest,
        stream: StdUnixStream,
        session: Arc<KrunVsockSession>,
    ) -> Result<(), Rejected> {
        if !session.is_active() {
            return Err(Rejected);
        }
        let listener = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&request.destination_port)
            .cloned()
            .ok_or(Rejected)?;
        if !Arc::ptr_eq(&listener.session, &session) || !listener.session.is_active() {
            return Err(Rejected);
        }
        let lease = listener.admission.reserve().map_err(|_| Rejected)?;
        let lease = session.hold_lease(lease).ok_or(Rejected)?;
        stream.set_nonblocking(true).map_err(|_| Rejected)?;
        let session_guard = session.track(stream.as_fd()).map_err(|_| Rejected)?;
        listener
            .sender
            .try_send(PendingUnixVsock {
                stream,
                source_port: request.source_port,
                destination_port: request.destination_port,
                lease,
                session,
                session_guard,
            })
            .map_err(|_| Rejected)
    }

    fn fence_session(&self, session: &Arc<KrunVsockSession>) {
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, listener| !Arc::ptr_eq(&listener.session, session));
    }

    #[cfg(test)]
    fn connect_guest(
        &self,
        request: ConnectionRequest,
        session: Arc<KrunVsockSession>,
    ) -> Option<StdUnixStream> {
        let (backend, vmmon) = StdUnixStream::pair().ok()?;
        self.connect_guest_stream(request, vmmon, session).ok()?;
        Some(backend)
    }

    fn register(
        &self,
        port: u32,
        admission: VsockListenerAdmission,
        session: Arc<KrunVsockSession>,
    ) -> Result<VsockListener, VirtError> {
        if !session.is_active() {
            return Err(VirtError::Backend(
                "krun vsock frontend stopped while registering listener".to_string(),
            ));
        }
        let (sender, receiver) = mpsc::channel(MAX_ACTIVE_VSOCK_CONNECTIONS);
        let registration;
        {
            let mut listeners = self
                .listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if listeners
                .get(&port)
                .is_some_and(|listener| listener.session.is_active())
            {
                return Err(VirtError::Backend(format!(
                    "krun vsock port {port} already has a listener"
                )));
            }
            let replacing_stopped = usize::from(listeners.contains_key(&port));
            if listeners.len() - replacing_stopped >= MAX_VSOCK_LISTENERS {
                return Err(VirtError::Backend(format!(
                    "krun has reached its listener registration limit of {MAX_VSOCK_LISTENERS}"
                )));
            }
            registration = self
                .next_registration
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| {
                    VirtError::Backend(
                        "krun vsock listener registration id space exhausted".to_string(),
                    )
                })?;
            listeners.remove(&port);
            listeners.insert(
                port,
                KrunVsockListener {
                    sender: sender.clone(),
                    admission: admission.clone(),
                    session: session.clone(),
                    registration,
                },
            );
        }

        let listeners = Arc::downgrade(&self.listeners);
        Ok(VsockListener::from_krun_channel(
            receiver,
            port,
            admission,
            move || {
                let Some(listeners) = listeners.upgrade() else {
                    return;
                };
                let mut listeners = listeners.lock().unwrap_or_else(PoisonError::into_inner);
                if listeners
                    .get(&port)
                    .is_some_and(|listener| listener.registration == registration)
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

        let session = KrunVsockSession::new();
        let (mux, mux_task, child_mux_fd) =
            mux::KrunVsockMux::pair(self.vsock_registry.clone(), session.clone(), &[])?;
        let vm = match build_krun_vm(&self.krun_bin, &self.config, child_mux_fd)?.start() {
            Ok(vm) => vm,
            Err(error) => {
                mux.shutdown().await;
                let _ = mux_task.join().await;
                return Err(krun_error(&self.config, error));
            }
        };
        tracing::info!(machine = %self.config.name(), "krun process started");
        *runtime = Some(RunningKrun {
            vm: Arc::new(AsyncMutex::new(vm)),
            mux,
            mux_task,
            session,
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
            mux,
            mux_task,
            session: _,
        } = running;
        mux.shutdown().await;
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
        mux_task.join().await?;
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
            running.mux.shutdown().await;
            running.mux_task.join().await?;
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
            running.mux.shutdown().await;
            running.mux_task.join().await?;
        }
        self.cache_exit(exit.clone());
        Ok(Some(exit))
    }

    async fn connect_vsock(&self, port: u32, lease: VsockLease) -> Result<VsockStream, VirtError> {
        let mux = {
            let runtime = self.runtime.lock().await;
            let running = runtime.as_ref().ok_or_else(|| VirtError::NotRunning {
                name: self.config.name().to_string(),
            })?;
            running.mux.clone()
        };

        let deadline = Instant::now() + VSOCK_CONNECT_TIMEOUT;
        let (stream, session_guard) = mux.connect(port, deadline).await?;
        let mut stream = UnixStream::from_std(stream)?;
        let source_port = read_connect_response(&mut stream, deadline).await?;
        Ok(VsockStream::from_krun_stream(
            stream,
            source_port,
            port,
            lease,
            session_guard,
        ))
    }

    async fn listen_vsock(
        &self,
        port: u32,
        admission: VsockListenerAdmission,
    ) -> Result<VsockListener, VirtError> {
        let session = {
            let runtime = self.runtime.lock().await;
            runtime
                .as_ref()
                .ok_or_else(|| VirtError::NotRunning {
                    name: self.config.name().to_string(),
                })?
                .session
                .clone()
        };
        self.vsock_registry.register(port, admission, session)
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
        return invalid_config(
            config,
            "rosetta is not supported on the krun backend yet\n\nhint: select the vz backend",
        );
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
    vsock_mux_fd: OwnedFd,
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
        .host_memory_reclaim(matches!(
            config.krun().host_memory_reclaim,
            crate::virt::HostMemoryReclaim::Auto
        ))
        .vsock_mux_fd(vsock_mux_fd)
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

async fn read_connect_response(stream: &mut UnixStream, deadline: Instant) -> io::Result<u32> {
    const MAX_RESPONSE_BYTES: usize = 64;

    let response = timeout_at(tokio::time::Instant::from_std(deadline), async {
        let mut response = Vec::with_capacity(MAX_RESPONSE_BYTES);
        while response.len() < MAX_RESPONSE_BYTES {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await?;
            response.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        Ok::<_, io::Error>(response)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for the krun vsock connection response",
        )
    })??;

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
        format!("invalid krun vsock response: {response:?}"),
    ))
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
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use super::{
        read_connect_response, validate, ConnectionRequest, KrunBackend, KrunVsockRegistry,
        MAX_VSOCK_LISTENERS, VSOCK_CONNECT_TIMEOUT,
    };
    use crate::virt::backend::VirtBackend;
    use crate::virt::capacity::VsockCapacity;
    use crate::virt::stream::KrunVsockSession;
    use crate::virt::{HostMemoryReclaim, NetworkMode, VmConfig, VmExit};

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

    #[test]
    fn rosetta_rejection_names_the_vz_escape_hatch() {
        let root = test_dir();
        fs::create_dir_all(&root).expect("create test root");
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").expect("write kernel");
        let config = VmConfig::builder("krun-rosetta")
            .base_directory(&root)
            .cpus(1)
            .memory(128)
            .kernel(kernel)
            .rosetta(true)
            .build();

        let error = validate(&config).expect_err("reject Rosetta");
        assert!(error
            .to_string()
            .contains("rosetta is not supported on the krun backend yet"));
        assert!(error.to_string().contains("select the vz backend"));
        let _ = fs::remove_dir_all(root);
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
            .host_memory_reclaim(HostMemoryReclaim::Auto)
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
        assert!(args.lines().any(|arg| arg == "--vsock-mux-fd"));
        assert!(args.lines().any(|arg| arg == "--host-memory-reclaim"));
        assert!(args.lines().any(|arg| arg == "on"));
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
    async fn control_only_eof_does_not_report_a_vm_exit() {
        let root = test_dir();
        fs::create_dir_all(&root).expect("create test root");
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").expect("write kernel");
        let krun = root.join("krun");
        write_executable(
            &krun,
            "#!/bin/sh\nif [ \"$1\" = \"--check-host-basic\" ]; then exit 0; fi\nmux=\nprevious=\nfor arg do\n  if [ \"$previous\" = \"--vsock-mux-fd\" ]; then mux=$arg; fi\n  previous=$arg\ndone\neval \"exec ${mux}>&-\"\nexec sleep 30\n",
        );
        let config = VmConfig::builder("control-eof")
            .vm_id("machine-1")
            .cpus(1)
            .memory(128)
            .base_directory(&root)
            .krun_path(krun.canonicalize().expect("canonical helper"))
            .kernel(kernel.canonicalize().expect("canonical kernel"))
            .network(NetworkMode::None)
            .build();
        let backend = KrunBackend::new(config).expect("create backend");
        backend.start().await.expect("start helper process");
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(backend.try_wait().await.expect("probe helper"), None);
        let capacity = VsockCapacity::test_with_limit("control-eof", 1);
        assert!(backend
            .listen_vsock(
                7000,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
            )
            .await
            .is_err());

        backend.stop().await.expect("stop helper process");
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[tokio::test]
    async fn registry_routes_dynamic_guest_connections_and_releases_capacity() {
        let registry = KrunVsockRegistry::default();
        let capacity = VsockCapacity::test_with_limit("krun-registry", 1);
        let session = KrunVsockSession::new();
        let mut listener = registry
            .register(
                7000,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                session.clone(),
            )
            .expect("register listener");

        let backend_stream = registry
            .connect_guest(
                ConnectionRequest {
                    id: 1,
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
                ConnectionRequest {
                    id: 2,
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
                ConnectionRequest {
                    id: 3,
                    source_port: 4001,
                    destination_port: 7000,
                },
                session.clone(),
            )
            .is_some());

        drop(listener);
        assert!(registry
            .connect_guest(
                ConnectionRequest {
                    id: 4,
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

        let source_port =
            read_connect_response(&mut client, Instant::now() + VSOCK_CONNECT_TIMEOUT)
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
        let session = KrunVsockSession::new();
        let mut listener = registry
            .register(
                7000,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                session.clone(),
            )
            .expect("register listener");
        let backend_stream = registry
            .connect_guest(
                ConnectionRequest {
                    id: 1,
                    source_port: 4000,
                    destination_port: 7000,
                },
                session.clone(),
            )
            .expect("queue guest connection");

        session.shutdown();
        drop(backend_stream);
        assert!(listener
            .try_accept()
            .expect("discard stopped-session connection")
            .is_none());
        assert_eq!(capacity.available_permits(), 1);

        let next_session = KrunVsockSession::new();
        assert!(registry
            .connect_guest(
                ConnectionRequest {
                    id: 2,
                    source_port: 4001,
                    destination_port: 7000,
                },
                next_session.clone(),
            )
            .is_none());
        let replacement = registry
            .register(
                7000,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                next_session,
            )
            .expect("replace stopped-session listener");
        drop(listener);
        assert!(registry.listeners.lock().unwrap().contains_key(&7000));
        drop(replacement);
    }

    #[tokio::test]
    async fn fencing_session_wakes_blocked_listener_without_removing_replacement() {
        let registry = KrunVsockRegistry::default();
        let capacity = VsockCapacity::test_with_limit("krun-listener-fence", 1);
        let session = KrunVsockSession::new();
        let mut listener = registry
            .register(
                7000,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                session.clone(),
            )
            .expect("register listener");
        let accept = tokio::spawn(async move {
            let result = listener.accept().await;
            (result, listener)
        });
        tokio::task::yield_now().await;

        session.shutdown();
        registry.fence_session(&session);
        let (result, old_listener) = tokio::time::timeout(Duration::from_secs(1), accept)
            .await
            .expect("blocked accept should wake")
            .expect("join blocked accept");
        assert!(result
            .expect_err("fenced listener must stop")
            .to_string()
            .contains("backend stopped"));

        let replacement_session = KrunVsockSession::new();
        let replacement = registry
            .register(
                7000,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                replacement_session,
            )
            .expect("register replacement listener");
        let replacement_registration = registry
            .listeners
            .lock()
            .unwrap()
            .get(&7000)
            .expect("replacement registry entry")
            .registration;
        drop(old_listener);
        assert_eq!(
            registry
                .listeners
                .lock()
                .unwrap()
                .get(&7000)
                .expect("old cleanup must preserve replacement")
                .registration,
            replacement_registration
        );
        drop(replacement);
    }

    #[tokio::test]
    async fn invalid_connect_response_is_rejected() {
        let (mut client, mut backend) = UnixStream::pair().expect("create stream pair");
        backend
            .write_all(b"NO 7000\n")
            .await
            .expect("write invalid response");

        let error = read_connect_response(&mut client, Instant::now() + VSOCK_CONNECT_TIMEOUT)
            .await
            .expect_err("invalid response must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn connect_response_wait_is_bounded() {
        let (mut client, _backend) = UnixStream::pair().expect("create stream pair");

        let error = read_connect_response(&mut client, Instant::now() + VSOCK_CONNECT_TIMEOUT)
            .await
            .expect_err("missing response must time out");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn registry_enforces_listener_limit_separately_from_connection_capacity() {
        let registry = KrunVsockRegistry::default();
        let capacity = VsockCapacity::new("krun-listeners");
        let session = KrunVsockSession::new();
        let listeners = (0..MAX_VSOCK_LISTENERS)
            .map(|port| {
                registry
                    .register(
                        port as u32 + 1,
                        capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                        session.clone(),
                    )
                    .expect("register through exact listener limit")
            })
            .collect::<Vec<_>>();

        let error = registry
            .register(
                MAX_VSOCK_LISTENERS as u32 + 1,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                session,
            )
            .expect_err("listener after exact limit must fail");
        assert!(error.to_string().contains("listener registration limit"));
        drop(listeners);
    }

    #[test]
    fn listener_registration_id_exhaustion_does_not_wrap_or_mutate_registry() {
        let registry = KrunVsockRegistry::default();
        registry
            .next_registration
            .store(u64::MAX - 1, Ordering::Relaxed);
        let capacity = VsockCapacity::new("krun-listener-generation");
        let session = KrunVsockSession::new();
        let listener = registry
            .register(
                7000,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                session.clone(),
            )
            .expect("allocate final listener generation");
        let final_registration = registry
            .listeners
            .lock()
            .unwrap()
            .get(&7000)
            .expect("final listener remains registered")
            .registration;
        assert_eq!(final_registration, u64::MAX - 1);

        let error = registry
            .register(
                7001,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
                session,
            )
            .expect_err("listener generation must not wrap");
        assert!(error.to_string().contains("id space exhausted"));
        let listeners = registry.listeners.lock().unwrap();
        assert_eq!(listeners.len(), 1);
        assert_eq!(
            listeners
                .get(&7000)
                .expect("failed allocation preserves registry")
                .registration,
            final_registration
        );
        assert!(!listeners.contains_key(&7001));
        drop(listeners);
        drop(listener);
    }
}
