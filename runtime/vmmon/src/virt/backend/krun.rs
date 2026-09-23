//! Same-executable libkrun worker with a private descriptor-passing vsock mux.
mod inherit;
mod mux;
mod owner;

use crate::krun::{Disk as KrunDisk, Mount as KrunMount};
use crate::virt::backend::{HostMemoryReclaimReport, StartAttempt, VirtBackend};
use crate::virt::capacity::{VsockLease, VsockListenerAdmission, MAX_ACTIVE_VSOCK_CONNECTIONS};
use crate::virt::config::{validate_common, DiskImage, NetworkMode, SharedDirectory, VmConfig};
use crate::virt::error::VirtError;
use crate::virt::exit::StartupStage;
use crate::virt::stream::{
    KrunVsockSession, PendingUnixVsock, SerialDevice, VsockListener, VsockStream,
};
use crate::virt::VmExit;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout_at;
use tokio_util::sync::CancellationToken;

const MAX_VSOCK_LISTENERS: usize = 1024;
const VSOCK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct KrunBackend {
    config: VmConfig,
    attempt: StartAttempt,
    state: watch::Sender<owner::Phase>,
    mux: Arc<AsyncMutex<Option<mux::KrunVsockMux>>>,
    vsock_registry: KrunVsockRegistry,
    session: Arc<KrunVsockSession>,
    host_memory_reclaim: watch::Sender<Option<HostMemoryReclaimReport>>,
    stop: CancellationToken,
    force: CancellationToken,
    console: Mutex<Option<OwnedFd>>,
    serial: Mutex<Option<(File, File)>>,
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
        let (sender, receiver) = mpsc::channel(MAX_ACTIVE_VSOCK_CONNECTIONS);
        let registration;
        {
            let mut listeners = self
                .listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !session.is_active() {
                return Err(VirtError::Backend(
                    "krun vsock frontend stopped while registering listener".to_string(),
                ));
            }
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
            .finish_non_exhaustive()
    }
}

impl KrunBackend {
    pub(crate) fn new(config: VmConfig) -> Result<Self, VirtError> {
        validate(&config)?;
        let pty = nix::pty::openpty(None, None).map_err(io::Error::from)?;
        let mut termios = nix::sys::termios::tcgetattr(&pty.slave).map_err(io::Error::from)?;
        nix::sys::termios::cfmakeraw(&mut termios);
        nix::sys::termios::tcsetattr(&pty.slave, nix::sys::termios::SetArg::TCSANOW, &termios)
            .map_err(io::Error::from)?;
        let master = File::from(pty.master);
        Ok(Self {
            config,
            attempt: StartAttempt::default(),
            state: watch::Sender::new(owner::Phase::default()),
            mux: Arc::new(AsyncMutex::new(None)),
            vsock_registry: KrunVsockRegistry::default(),
            session: KrunVsockSession::new(),
            host_memory_reclaim: watch::Sender::new(None),
            stop: CancellationToken::new(),
            force: CancellationToken::new(),
            console: Mutex::new(Some(pty.slave)),
            serial: Mutex::new(Some((master.try_clone()?, master))),
        })
    }

    async fn completion(&self) -> Result<VmExit, VirtError> {
        let mut state = self.state.subscribe();
        loop {
            if let Some(exit) = state.borrow().exit().cloned() {
                return Ok(exit);
            }
            state.changed().await.map_err(|_| {
                VirtError::Backend("krun owner closed without completion".to_string())
            })?;
        }
    }
}

impl Drop for KrunBackend {
    fn drop(&mut self) {
        self.stop.cancel();
        self.session.shutdown();
        self.vsock_registry.fence_session(&self.session);
    }
}

#[async_trait]
impl VirtBackend for KrunBackend {
    fn serial_available_before_start(&self) -> bool {
        true
    }

    async fn start(&self) -> Result<(), VirtError> {
        if !self.attempt.reserve() {
            return Err(VirtError::AlreadyRunning {
                name: self.config.name().to_string(),
            });
        }
        let guard = self.stop.clone().drop_guard();
        let config = self.config.clone();
        let running_mux = self.mux.clone();
        let registry = self.vsock_registry.clone();
        let session = self.session.clone();
        let console = self
            .console
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let owner = owner::Owner {
            state: self.state.clone(),
            stop: self.stop.clone(),
            force: self.force.clone(),
            reclaim: self.host_memory_reclaim.clone(),
        };
        // No await between attempt reservation and establishing cleanup ownership.
        tokio::spawn(async move {
            let result = async {
                prepare(&config)?;
                let launch = engine_config(&config)?;
                let console = console.ok_or_else(|| {
                    VirtError::Backend("krun console already consumed".to_string())
                })?;
                let (mux, task, child_mux) =
                    mux::KrunVsockMux::pair(registry.clone(), session.clone(), &[])?;
                *running_mux.lock().await = Some(mux.clone());
                let exit = owner.run(launch, console, child_mux).await;
                session.shutdown();
                registry.fence_session(&session);
                mux.shutdown().await;
                if let Err(error) = task.join().await {
                    tracing::warn!(%error, "krun mux cleanup failed");
                }
                *running_mux.lock().await = None;
                Ok::<_, VirtError>(exit)
            }
            .await;
            session.shutdown();
            registry.fence_session(&session);
            let exit = result
                .unwrap_or_else(|error| VmExit::failed(StartupStage::Spawned, error.to_string()));
            owner.state.send_replace(owner::Phase::Exited(exit));
        });
        let mut state = self.state.subscribe();
        loop {
            let phase = state.borrow().clone();
            match phase {
                owner::Phase::Exited(exit) => {
                    return Err(VirtError::Backend(exit.error().unwrap_or_else(|| {
                        "worker stopped before startup handoff".to_string()
                    })));
                }
                owner::Phase::Started => {
                    guard.disarm();
                    return Ok(());
                }
                owner::Phase::Starting | owner::Phase::Reaped => {}
            }
            state
                .changed()
                .await
                .map_err(|_| VirtError::Backend("krun startup owner closed".to_string()))?;
        }
    }

    async fn stop(&self) -> Result<(), VirtError> {
        self.stop.cancel();
        if self.attempt.reserve() {
            self.session.shutdown();
            self.vsock_registry.fence_session(&self.session);
            self.console
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            self.state
                .send_replace(owner::Phase::Exited(VmExit::stopped(StartupStage::Spawned)));
        }
        self.completion().await.map(|_| ())
    }

    async fn force_stop(&self) -> Result<(), VirtError> {
        self.force.cancel();
        self.stop().await
    }

    async fn wait(&self) -> Result<VmExit, VirtError> {
        self.completion().await
    }
    async fn try_wait(&self) -> Result<Option<VmExit>, VirtError> {
        Ok(self.state.borrow().exit().cloned())
    }

    async fn is_terminated(&self) -> Result<bool, VirtError> {
        Ok(matches!(
            *self.state.borrow(),
            owner::Phase::Reaped | owner::Phase::Exited(_)
        ))
    }

    async fn connect_vsock(&self, port: u32, lease: VsockLease) -> Result<VsockStream, VirtError> {
        let mux = {
            let mux = self.mux.lock().await;
            mux.as_ref()
                .ok_or_else(|| VirtError::NotRunning {
                    name: self.config.name().to_string(),
                })?
                .clone()
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
        if self.stop.is_cancelled() || self.is_terminated().await? {
            return Err(VirtError::NotRunning {
                name: self.config.name().to_string(),
            });
        }
        self.vsock_registry
            .register(port, admission, self.session.clone())
    }

    fn host_memory_reclaim_updates(
        &self,
    ) -> Option<watch::Receiver<Option<HostMemoryReclaimReport>>> {
        Some(self.host_memory_reclaim.subscribe())
    }

    async fn open_serial(&self) -> Result<SerialDevice, VirtError> {
        let (read, write) = self
            .serial
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| {
                VirtError::Backend("krun serial console already attached".to_string())
            })?;
        Ok(SerialDevice::from_pty_files(read, write)?)
    }
}

fn host_memory_reclaim_report(
    status: crate::krun::HostMemoryReclaimStatus,
) -> HostMemoryReclaimReport {
    HostMemoryReclaimReport {
        requested: status.requested,
        qualification: status.qualification.as_str(),
        effective: status.effective,
        released_bytes: status.released_bytes,
        released_extents: status.released_extents,
        retried_faults: status.retried_faults,
        skipped_reports: status.skipped_reports,
        failed_operations: status.failed_operations,
        observed_at: SystemTime::now(),
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
    match config.rosetta() {
        crate::virt::RosettaIntent::Disabled => {}
        crate::virt::RosettaIntent::KrunCaptured { profile } => match (
            profile,
            config
                .krun()
                .prepared_rosetta
                .as_ref()
                .map(|value| value.profile()),
        ) {
            (
                crate::virt::RosettaProfile::CapturedCompatibilityV1,
                Some(crate::krun::RosettaProfileId::CapturedCompatibilityV1),
            ) => {}
            _ => {
                return invalid_config(
                    config,
                    "captured Rosetta launch data is missing or mismatched",
                )
            }
        },
        crate::virt::RosettaIntent::VzNative => {
            return invalid_config(config, "VZ-native Rosetta intent cannot be used with krun")
        }
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
    }

    Ok(())
}

fn prepare(config: &VmConfig) -> Result<(), VirtError> {
    let kernel = config
        .kernel_path()
        .ok_or_else(|| VirtError::Backend("validated kernel missing".to_string()))?;
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

/// Declares libkrun's i8042 exit device as the guest's final poweroff path.
/// The Silo x86_64 kernel carries a patch that registers that handler only
/// when this argument is present; aarch64 powers off through PSCI.
#[cfg(target_arch = "x86_64")]
const X86_POWEROFF_ARG: &str = "krun.poweroff=i8042";

fn build_boot_args(config: &VmConfig) -> Vec<String> {
    let mut args = vec![
        "console=hvc0".to_string(),
        "panic=1".to_string(),
        "page_reporting.page_reporting_order=2".to_string(),
    ];
    #[cfg(target_arch = "x86_64")]
    args.push(X86_POWEROFF_ARG.to_string());
    args.extend(config.kernel_cmdline().iter().cloned());
    args
}

fn engine_config(config: &VmConfig) -> Result<crate::krun::KrunConfig, VirtError> {
    let cpus = config
        .cpus()
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| VirtError::Backend("invalid krun CPU count".to_string()))?;
    let memory_mib = config
        .memory_mib()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| VirtError::Backend("invalid krun memory size".to_string()))?;
    Ok(crate::krun::KrunConfig {
        id: config.vm_id().to_string(),
        cpus,
        memory_mib,
        kernel: config.kernel_path().map(Path::to_path_buf),
        initramfs: config.initramfs_path().map(Path::to_path_buf),
        cmdline: build_boot_args(config),
        disks: config
            .disks()
            .iter()
            .enumerate()
            .map(|(index, disk)| krun_disk(format!("disk{index}"), disk))
            .collect(),
        mounts: config.mounts().iter().map(krun_mount).collect(),
        vsock_mux: true,
        vsock_cid: None,
        network: match config.network() {
            NetworkMode::UnixDatagram { peer_path, mac } => {
                crate::krun::Network::Unixgram(crate::krun::NetUnixgram {
                    peer_path: peer_path.clone(),
                    mac: *mac,
                })
            }
            NetworkMode::None => crate::krun::Network::None,
        },
        stdio_console: true,
        balloon: true,
        rosetta: config.krun().prepared_rosetta.clone(),
    })
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

fn invalid_config<T>(config: &VmConfig, reason: &str) -> Result<T, VirtError> {
    Err(VirtError::InvalidConfig {
        name: config.name().to_string(),
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use crate::virt::backend::krun::{
        read_connect_response, validate, ConnectionRequest, KrunVsockRegistry, MAX_VSOCK_LISTENERS,
        VSOCK_CONNECT_TIMEOUT,
    };
    use crate::virt::capacity::VsockCapacity;
    use crate::virt::stream::KrunVsockSession;
    use crate::virt::VmConfig;

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

    #[tokio::test]
    async fn stopping_before_start_is_terminal_and_waiters_share_the_result() {
        use crate::virt::backend::{krun::KrunBackend, VirtBackend};
        let backend = KrunBackend::new(
            VmConfig::builder("cancelled")
                .base_directory(std::env::temp_dir())
                .cpus(1)
                .memory(128)
                .kernel("/not-opened/kernel")
                .build(),
        )
        .expect("backend");
        let capacity = VsockCapacity::new("pre-start-forward");
        let mut listener = backend
            .listen_vsock(
                1028,
                capacity.listener(crate::virt::capacity::ListenerAdmissionClass::Internal),
            )
            .await
            .expect("register before native startup");
        backend.stop().await.expect("stop before start");
        assert!(
            tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("fenced listener")
                .is_err()
        );
        assert!(backend.start().await.is_err());
        let (first, second) = tokio::join!(backend.wait(), backend.wait());
        assert_eq!(first.expect("first"), second.expect("second"));
        backend.stop().await.expect("idempotent stop");
        assert!(backend.console.lock().expect("console").is_none());
    }

    #[tokio::test]
    async fn cancelled_start_and_waiter_leave_one_terminal_preparation_attempt() {
        use crate::virt::backend::{krun::KrunBackend, VirtBackend};
        use futures::FutureExt;
        let backend = KrunBackend::new(
            VmConfig::builder("cancelled-preparation")
                .base_directory(std::env::temp_dir())
                .cpus(1)
                .memory(128)
                .kernel("/definitely-missing-silo/kernel")
                .build(),
        )
        .expect("backend");
        // Poll once, then drop both futures. No native worker can be launched with
        // this missing payload, and cancellation must not reset the attempt.
        assert!(backend.wait().now_or_never().is_none());
        assert!(backend.start().now_or_never().is_none());
        let (stopped, first, second) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(backend.stop(), backend.wait(), backend.wait())
        })
        .await
        .expect("owned preparation cleanup");
        stopped.expect("concurrent stop");
        let first = first.expect("first waiter");
        assert_eq!(first, second.expect("second waiter"));
        assert_eq!(Some(first), backend.try_wait().await.expect("cached exit"));
        backend.stop().await.expect("repeated stop");
        assert!(backend.start().await.is_err());
    }

    #[tokio::test]
    async fn preparation_failure_cannot_retry_or_erase_the_cached_error() {
        use crate::virt::backend::{krun::KrunBackend, VirtBackend};
        let backend = KrunBackend::new(
            VmConfig::builder("missing-payload")
                .base_directory(std::env::temp_dir())
                .cpus(1)
                .memory(128)
                .kernel("/definitely-missing-silo/kernel")
                .build(),
        )
        .expect("backend");
        let error = backend.start().await.expect_err("missing kernel");
        assert!(error.to_string().contains("does not exist"));
        let first = backend.wait().await.expect("terminal result");
        assert!(first.error().is_some());
        backend.stop().await.expect("cleanup remains idempotent");
        assert_eq!(backend.wait().await.expect("cached result"), first);
        assert!(backend.start().await.is_err());
    }

    #[test]
    fn boot_args_default_to_order_two_page_reporting() {
        let config = VmConfig::builder("page-reporting")
            .kernel_cmdline(vec!["root=/dev/vda".to_string()])
            .build();

        let args = crate::virt::backend::krun::build_boot_args(&config);
        assert_eq!(
            args.iter()
                .filter(|arg| arg.as_str() != "krun.poweroff=i8042")
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "console=hvc0",
                "panic=1",
                "page_reporting.page_reporting_order=2",
                "root=/dev/vda",
            ]
        );
    }

    #[test]
    fn x86_64_declares_the_i8042_poweroff_transport_and_aarch64_does_not() {
        let config = VmConfig::builder("poweroff").build();
        let args = crate::virt::backend::krun::build_boot_args(&config);
        let declared = args
            .iter()
            .filter(|arg| *arg == "krun.poweroff=i8042")
            .count();
        assert_eq!(declared, usize::from(cfg!(target_arch = "x86_64")));
    }

    #[test]
    fn captured_rosetta_requires_prepared_acquisition_data() {
        let root = test_dir();
        fs::create_dir_all(&root).expect("create test root");
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").expect("write kernel");
        let config = VmConfig::builder("krun-rosetta")
            .base_directory(&root)
            .cpus(1)
            .memory(128)
            .kernel(kernel)
            .rosetta(crate::virt::RosettaIntent::KrunCaptured {
                profile: crate::virt::RosettaProfile::CapturedCompatibilityV1,
            })
            .build();

        let error = validate(&config).expect_err("reject missing acquisition data");
        assert!(error
            .to_string()
            .contains("captured Rosetta launch data is missing or mismatched"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn captured_rosetta_accepts_matching_typed_acquisition_data() {
        let root = test_dir();
        fs::create_dir_all(&root).expect("create test root");
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").expect("write kernel");
        let prepared =
            crate::krun::RosettaLaunchConfig::new(root.clone(), [0x11; 32], 1, [0x22; 1024])
                .expect("prepared Rosetta config");
        let config = VmConfig::builder("krun-rosetta")
            .base_directory(&root)
            .cpus(1)
            .memory(128)
            .kernel(kernel)
            .rosetta(crate::virt::RosettaIntent::KrunCaptured {
                profile: crate::virt::RosettaProfile::CapturedCompatibilityV1,
            })
            .prepared_rosetta(prepared)
            .build();

        validate(&config).expect("accept matching captured Rosetta data");
        let _ = fs::remove_dir_all(root);
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
