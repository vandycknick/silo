//! In-process mock virtualization backend (testing only).
//!
//! Instead of booting a VM, this backend runs the *guest side* itself: an
//! in-process tonic server implementing `GuestAgentService`,
//! `GuestProcessService`, and `GuestFilesystemService`, reached through unix
//! socketpairs handed out by `connect_vsock`. Executions run real host
//! subprocesses sandboxed under `<base_directory>/mock-guest-root/`, so
//! stdio, exit codes, and signal plumbing stay honest. Behavior is scripted
//! by a [`test_utils::Scenario`] (path in `VmConfig::mock().scenario`).
//!
//! Scope: this fakes the vmmon<->guest contract, not the hypervisor. Real
//! krun/vz behavior, kernel vsock semantics, and actual guest boots still
//! require a virtualization-capable host.

mod fs;
mod guest;

use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use test_utils::Scenario;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex, Notify};
use tokio_stream::wrappers::ReceiverStream;

use crate::virt::backend::{BackendKind, VirtBackend};
use crate::virt::capacity::{VsockCapacity, VsockLease};
use crate::virt::config::{validate_common, VmConfig, VsockPortMode};
use crate::virt::error::VirtError;
use crate::virt::machine::VirtualMachine;
use crate::virt::stream::{SerialDevice, SyntheticPortAllocator, VsockListener, VsockStream};
use crate::virt::VmExit;

const GUEST_ROOT_DIR: &str = "mock-guest-root";
const SERIAL_BUFFER_BYTES: usize = 64 * 1024;
const BANNER_PACING: Duration = Duration::from_millis(5);

/// The vsock port serving plain byte echo instead of gRPC (mirrors SSH).
const SSH_PORT: u32 = agent_spec::SSH_VSOCK_PORT;

#[derive(Debug)]
pub(crate) struct MockBackend {
    config: VmConfig,
    scenario: Scenario,
    guest: Arc<guest::MockGuest>,
    running: AsyncMutex<Option<RunningGuest>>,
    exit: Arc<Mutex<Option<VmExit>>>,
    exit_notify: Arc<Notify>,
    /// Flips to true when the machine stops or crashes; every guest-side task
    /// watches it.
    shutdown: watch::Sender<bool>,
    started_once: Mutex<bool>,
    source_ports: SyntheticPortAllocator,
}

#[derive(Debug)]
struct RunningGuest {
    incoming_tx: mpsc::Sender<io::Result<UnixStream>>,
}

impl MockBackend {
    pub(crate) fn new(config: VmConfig) -> Result<Self, VirtError> {
        validate_common(&config)?;
        let scenario = match config.mock().scenario.as_deref() {
            Some(path) => {
                if !path.is_absolute() {
                    return Err(VirtError::InvalidConfig {
                        name: config.name().to_string(),
                        reason: format!("mock scenario path must be absolute: {}", path.display()),
                    });
                }
                Scenario::load(path).map_err(|err| VirtError::InvalidConfig {
                    name: config.name().to_string(),
                    reason: format!("failed to load mock scenario: {err}"),
                })?
            }
            None => Scenario::default(),
        };

        let guest_root = config.base_directory().join(GUEST_ROOT_DIR);
        let guest = Arc::new(guest::MockGuest::new(scenario.clone(), guest_root));
        let (shutdown, _) = watch::channel(false);

        tracing::warn!(
            machine = config.name(),
            "using the MOCK virtualization backend; no real VM will run"
        );

        Ok(Self {
            config,
            scenario,
            guest,
            running: AsyncMutex::new(None),
            exit: Arc::new(Mutex::new(None)),
            exit_notify: Arc::new(Notify::new()),
            shutdown,
            started_once: Mutex::new(false),
            source_ports: SyntheticPortAllocator::new(),
        })
    }

    fn cached_exit(&self) -> Option<VmExit> {
        self.exit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn cache_exit(&self, exit: VmExit) {
        cache_exit_in(&self.exit, &self.exit_notify, exit);
    }

    fn declared_mode(&self, port: u32) -> Option<VsockPortMode> {
        self.config
            .vsock_ports()
            .iter()
            .find(|candidate| candidate.port == port)
            .map(|candidate| candidate.mode)
    }
}

fn cache_exit_in(exit: &Mutex<Option<VmExit>>, notify: &Notify, value: VmExit) {
    let mut slot = exit.lock().unwrap_or_else(PoisonError::into_inner);
    if slot.is_none() {
        *slot = Some(value);
    }
    drop(slot);
    notify.notify_waiters();
}

#[async_trait]
impl VirtBackend for MockBackend {
    async fn start(&self) -> Result<(), VirtError> {
        let mut running = self.running.lock().await;
        if running.is_some() {
            return Err(VirtError::AlreadyRunning {
                name: self.config.name().to_string(),
            });
        }
        {
            let mut started = self
                .started_once
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *started {
                // One backend instance models one boot generation, matching
                // how vmmon uses the real backends.
                return Err(VirtError::AlreadyRunning {
                    name: self.config.name().to_string(),
                });
            }
            *started = true;
        }

        if let Some(delay_ms) = self.scenario.boot.delay_ms {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        if let Some(reason) = self.scenario.boot.fail.as_deref() {
            return Err(VirtError::Backend(format!(
                "mock boot failure (scripted): {reason}"
            )));
        }

        std::fs::create_dir_all(self.guest.guest_root())?;

        // Guest gRPC server over in-process connections.
        let (incoming_tx, incoming_rx) = mpsc::channel::<io::Result<UnixStream>>(64);
        let mut server_shutdown = self.shutdown.subscribe();
        let router = guest::guest_router(self.guest.clone());
        tokio::spawn(async move {
            let result = router
                .serve_with_incoming_shutdown(ReceiverStream::new(incoming_rx), async move {
                    while !*server_shutdown.borrow() {
                        if server_shutdown.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
            if let Err(error) = result {
                tracing::warn!(%error, "mock guest gRPC server stopped with error");
            }
        });

        self.guest.boot(self.shutdown.subscribe());

        // Scripted mid-run crash.
        if let Some(crash_after_ms) = self.scenario.run.crash_after_ms {
            let message = self
                .scenario
                .run
                .crash_message
                .clone()
                .unwrap_or_else(|| "mock VMM crashed (scripted)".to_string());
            let exit = self.exit.clone();
            let exit_notify = self.exit_notify.clone();
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(crash_after_ms)).await;
                cache_exit_in(&exit, &exit_notify, VmExit::StoppedWithError(message));
                shutdown.send_replace(true);
            });
        }

        *running = Some(RunningGuest { incoming_tx });
        tracing::info!(machine = self.config.name(), "mock machine started");
        Ok(())
    }

    async fn stop(&self) -> Result<(), VirtError> {
        let _ = self.running.lock().await.take();
        self.shutdown.send_replace(true);
        self.cache_exit(VmExit::Stopped);
        Ok(())
    }

    async fn wait(&self) -> Result<VmExit, VirtError> {
        loop {
            if let Some(exit) = self.cached_exit() {
                return Ok(exit);
            }
            if self.running.lock().await.is_none() {
                return Err(VirtError::NotRunning {
                    name: self.config.name().to_string(),
                });
            }
            self.exit_notify.notified().await;
        }
    }

    async fn try_wait(&self) -> Result<Option<VmExit>, VirtError> {
        Ok(self.cached_exit())
    }

    async fn connect_vsock(&self, port: u32, lease: VsockLease) -> Result<VsockStream, VirtError> {
        let incoming_tx = {
            let running = self.running.lock().await;
            let Some(running) = running.as_ref() else {
                return Err(VirtError::NotRunning {
                    name: self.config.name().to_string(),
                });
            };
            running.incoming_tx.clone()
        };
        if *self.shutdown.borrow() {
            return Err(VirtError::Backend(
                "mock guest is shut down; connection refused".to_string(),
            ));
        }

        match self.declared_mode(port) {
            Some(VsockPortMode::Connect) => {}
            Some(VsockPortMode::Listen) => {
                return Err(VirtError::Backend(format!(
                    "mock vsock port {port} is declared for listen, not connect"
                )));
            }
            None => {}
        }
        if self.scenario.vsock.refuse_ports.contains(&port) {
            return Err(VirtError::Backend(format!(
                "mock vsock port {port} refused connection (scripted)"
            )));
        }

        let (client, server) = UnixStream::pair()?;
        let server = match self.scenario.vsock.drop_after_bytes.get(&port) {
            Some(&limit) => limited_stream(server, limit, self.shutdown.subscribe())?,
            None => server,
        };

        if port == SSH_PORT {
            // vmmon relays raw bytes for SSH; a byte echo server is full
            // fidelity for relay and half-close behavior.
            let mut shutdown = self.shutdown.subscribe();
            tokio::spawn(async move {
                let mut server = server;
                let mut buffer = [0u8; 4096];
                loop {
                    tokio::select! {
                        read = server.read(&mut buffer) => match read {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if server.write_all(&buffer[..n]).await.is_err() {
                                    break;
                                }
                            }
                        },
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
        } else if incoming_tx.send(Ok(server)).await.is_err() {
            return Err(VirtError::Backend(
                "mock guest server is no longer accepting connections".to_string(),
            ));
        }

        let source = self.source_ports.allocate()?;
        Ok(VsockStream::from_synthetic_unix_stream(
            client, source, port, lease,
        ))
    }

    async fn listen_vsock(
        &self,
        port: u32,
        capacity: VsockCapacity,
    ) -> Result<VsockListener, VirtError> {
        match self.declared_mode(port) {
            Some(VsockPortMode::Listen) => {}
            Some(VsockPortMode::Connect) => {
                return Err(VirtError::Backend(format!(
                    "mock vsock port {port} is declared for connect, not listen"
                )));
            }
            None => {}
        }

        let path = self
            .config
            .base_directory()
            .join(format!("mock-vsock-listen-{port}.sock"));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(VsockListener::from_mock_unix_listener(
            UnixListener::bind(&path)?,
            port,
            capacity,
            self.source_ports.clone(),
        ))
    }

    async fn open_serial(&self) -> Result<SerialDevice, VirtError> {
        if self.running.lock().await.is_none() {
            return Err(VirtError::NotRunning {
                name: self.config.name().to_string(),
            });
        }

        let (host_side, guest_side) = tokio::io::duplex(SERIAL_BUFFER_BYTES);
        let banner = self.scenario.serial.banner.clone();
        let echo_input = self.scenario.serial.echo_input;
        let mut shutdown = self.shutdown.subscribe();
        tokio::spawn(async move {
            let (mut guest_read, mut guest_write) = tokio::io::split(guest_side);
            for line in banner {
                let payload = format!("{line}\n");
                if guest_write.write_all(payload.as_bytes()).await.is_err() {
                    return;
                }
                let _ = guest_write.flush().await;
                // Pace lines so consumers observe multiple chunks.
                tokio::time::sleep(BANNER_PACING).await;
            }

            let mut buffer = [0u8; 4096];
            loop {
                tokio::select! {
                    read = guest_read.read(&mut buffer) => match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if echo_input
                                && guest_write.write_all(&buffer[..n]).await.is_err()
                            {
                                break;
                            }
                            let _ = guest_write.flush().await;
                        }
                    },
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            // Dropping the guest side EOFs the console reader
                            // so drain() completes.
                            break;
                        }
                    }
                }
            }
        });

        Ok(SerialDevice::from_duplex(host_side))
    }
}

/// Wrap a stream so it hard-closes after relaying `limit` total bytes,
/// simulating a scripted mid-stream connection loss.
fn limited_stream(
    upstream: UnixStream,
    limit: u64,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<UnixStream> {
    let (near, far) = UnixStream::pair()?;
    tokio::spawn(async move {
        let (mut up_read, mut up_write) = tokio::io::split(upstream);
        let (mut far_read, mut far_write) = tokio::io::split(far);
        let mut relayed: u64 = 0;
        let mut up_buf = [0u8; 4096];
        let mut far_buf = [0u8; 4096];
        loop {
            let budget = limit.saturating_sub(relayed);
            if budget == 0 {
                break;
            }
            let budget = usize::try_from(budget.min(4096)).unwrap_or(4096);
            tokio::select! {
                read = up_read.read(&mut up_buf[..budget]) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        relayed += n as u64;
                        if far_write.write_all(&up_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                },
                read = far_read.read(&mut far_buf[..budget]) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        relayed += n as u64;
                        if up_write.write_all(&far_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                },
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        // Dropping both halves hard-closes the relay.
    });
    Ok(near)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tokio::net::UnixStream;

    use crate::virt::backend::mock::MockBackend;
    use crate::virt::backend::VirtBackend;
    use crate::virt::capacity::VsockCapacity;
    use crate::virt::{VmConfig, VsockPort, VsockPortMode};

    #[tokio::test]
    async fn mock_connect_reports_unique_reusable_synthetic_source_metadata() {
        let root = std::env::temp_dir().join(format!("vmmon-mock-metadata-{}", std::process::id()));
        let config = VmConfig::builder("mock-metadata")
            .base_directory(&root)
            .kernel(Path::new("/mock-kernel"))
            .vsock_port(VsockPort {
                port: agent_spec::SSH_VSOCK_PORT,
                mode: VsockPortMode::Connect,
            })
            .build();
        let backend = MockBackend::new(config).expect("mock backend");
        backend.start().await.expect("start mock");
        let capacity = VsockCapacity::test_with_limit("mock-metadata", 2);

        let first = backend
            .connect_vsock(
                agent_spec::SSH_VSOCK_PORT,
                capacity.reserve().expect("first capacity"),
            )
            .await
            .expect("first stream");
        let second = backend
            .connect_vsock(
                agent_spec::SSH_VSOCK_PORT,
                capacity.reserve().expect("second capacity"),
            )
            .await
            .expect("second stream");

        assert_eq!(first.source_port(), Some(1 << 30));
        assert_eq!(second.source_port(), Some((1 << 30) + 1));
        assert_eq!(first.destination_port(), agent_spec::SSH_VSOCK_PORT);
        drop(first);
        drop(second);

        let reused = backend
            .connect_vsock(
                agent_spec::SSH_VSOCK_PORT,
                capacity.reserve().expect("reused capacity"),
            )
            .await
            .expect("reused stream");
        assert_eq!(reused.source_port(), Some(1 << 30));

        backend.stop().await.expect("stop mock");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn mock_listener_reports_registered_destination_and_synthetic_source() {
        let root = std::env::temp_dir().join(format!(
            "vmmon-mock-listener-metadata-{}",
            std::process::id()
        ));
        let port = 7000;
        let config = VmConfig::builder("mock-listener-metadata")
            .base_directory(&root)
            .kernel(Path::new("/mock-kernel"))
            .vsock_port(VsockPort {
                port,
                mode: VsockPortMode::Listen,
            })
            .build();
        let backend = MockBackend::new(config).expect("mock backend");
        backend.start().await.expect("start mock");
        let capacity = VsockCapacity::test_with_limit("mock-listener-metadata", 1);
        let mut listener = backend
            .listen_vsock(port, capacity)
            .await
            .expect("mock listener");
        let path = root.join(format!("mock-vsock-listen-{port}.sock"));

        let _client = UnixStream::connect(path).await.expect("guest connection");
        let stream = listener.accept().await.expect("accepted stream");
        assert_eq!(stream.source_port(), Some(1 << 30));
        assert_eq!(stream.destination_port(), port);

        backend.stop().await.expect("stop mock");
        drop(listener);
        let _ = std::fs::remove_dir_all(root);
    }
}
