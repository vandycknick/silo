use std::sync::Arc;

use crate::virt::backend::{create_backend, BackendKind, VirtBackend};
use crate::virt::capacity::{VsockCapacity, VsockLease};
use crate::virt::config::VmConfig;
use crate::virt::error::VirtError;
use crate::virt::serial::SerialConsole;
use crate::virt::stream::{VsockListener, VsockStream};
use crate::virt::VmExit;

/// Clone-able handle to a single virtual machine.
///
/// All clones share the same backend instance and serial console; dropping
/// the last clone does not stop the machine — stopping is always explicit.
#[derive(Clone)]
pub struct VirtualMachine {
    inner: Arc<MachineInner>,
}

struct MachineInner {
    name: String,
    kind: BackendKind,
    backend: Arc<dyn VirtBackend>,
    serial_console: Arc<SerialConsole>,
    vsock_capacity: VsockCapacity,
}

impl std::fmt::Debug for VirtualMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualMachine")
            .field("name", &self.inner.name)
            .field("backend", &self.inner.kind.name())
            .finish()
    }
}

impl VirtualMachine {
    /// Create a machine on the platform-default backend
    /// (krun on Linux, Virtualization.framework on macOS).
    pub fn new(config: VmConfig) -> Result<Self, VirtError> {
        Self::with_backend(BackendKind::default_for_host()?, config)
    }

    /// Create a machine on an explicit backend.
    ///
    /// This is the entry point for runtime backend selection; today it is
    /// exercised by tests selecting the mock backend.
    pub fn with_backend(kind: BackendKind, config: VmConfig) -> Result<Self, VirtError> {
        let name = config.name().to_string();
        let backend = create_backend(kind, config)?;
        let serial_console = Arc::new(SerialConsole::new(backend.clone()));
        let vsock_capacity = VsockCapacity::new(name.clone());

        Ok(VirtualMachine {
            inner: Arc::new(MachineInner {
                name,
                kind,
                backend,
                serial_console,
                vsock_capacity,
            }),
        })
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.inner.kind
    }

    /// Boot the machine and attach the serial console. If the console cannot
    /// attach, the machine is stopped again and the error is returned.
    pub async fn start(&self) -> Result<(), VirtError> {
        self.inner.backend.start().await?;
        if let Err(error) = self.inner.serial_console.attach().await {
            let _ = self.inner.backend.stop().await;
            return Err(error);
        }
        Ok(())
    }

    /// Stop the machine, then drain remaining serial output to sinks.
    /// Idempotent.
    pub async fn stop(&self) -> Result<(), VirtError> {
        self.inner.backend.stop().await?;
        self.inner.serial_console.drain().await
    }

    /// Dynamically connect to a guest endpoint port.
    pub async fn connect_vsock(&self, port: u32) -> Result<VsockStream, VirtError> {
        let lease = self.reserve_vsock()?;
        self.connect_vsock_reserved(port, lease).await
    }

    /// Reserve one machine-wide slot before protocol negotiation begins.
    pub(crate) fn reserve_vsock(&self) -> Result<VsockLease, VirtError> {
        self.inner.vsock_capacity.reserve()
    }

    pub(crate) fn reserve_public_vsock(&self) -> Result<VsockLease, VirtError> {
        self.inner.vsock_capacity.reserve_public()
    }

    /// Connect using a reservation acquired by an earlier protocol stage.
    pub(crate) async fn connect_vsock_reserved(
        &self,
        port: u32,
        lease: VsockLease,
    ) -> Result<VsockStream, VirtError> {
        if !self.inner.vsock_capacity.owns(&lease) {
            return Err(VirtError::Backend(format!(
                "vsock lease does not belong to machine {}",
                self.name()
            )));
        }
        let stream = self.inner.backend.connect_vsock(port, lease).await?;
        if !stream.owns_capacity(&self.inner.vsock_capacity) {
            return Err(VirtError::Backend(format!(
                "backend returned a vsock stream without capacity from machine {}",
                self.name()
            )));
        }
        if stream.destination_port() != port {
            return Err(VirtError::Backend(format!(
                "backend connected to vsock destination {} instead of requested port {port}",
                stream.destination_port()
            )));
        }
        Ok(stream)
    }

    /// Start accepting guest-initiated vsock connections on the host.
    ///
    /// Dropping the returned listener stops accepting new connections for
    /// the port.
    pub async fn listen_vsock(&self, port: u32) -> Result<VsockListener, VirtError> {
        let listener = self
            .inner
            .backend
            .listen_vsock(port, self.inner.vsock_capacity.clone())
            .await?;
        if !listener.owns_capacity(&self.inner.vsock_capacity) {
            return Err(VirtError::Backend(format!(
                "backend returned a vsock listener without capacity from machine {}",
                self.name()
            )));
        }
        if listener.port() != port {
            return Err(VirtError::Backend(format!(
                "backend registered vsock listener {} instead of requested port {port}",
                listener.port()
            )));
        }
        Ok(listener)
    }

    /// Block until the machine exits; resolves immediately once exited.
    pub async fn wait(&self) -> Result<VmExit, VirtError> {
        self.inner.backend.wait().await
    }

    /// Non-blocking exit check.
    pub async fn try_wait(&self) -> Result<Option<VmExit>, VirtError> {
        self.inner.backend.try_wait().await
    }

    pub fn serial(&self) -> Arc<SerialConsole> {
        self.inner.serial_console.clone()
    }

    /// Drain remaining serial output to sinks without stopping the machine.
    pub async fn drain_serial(&self) -> Result<(), VirtError> {
        self.inner.serial_console.drain().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use tokio::net::UnixStream;

    use crate::virt::backend::{BackendKind, VirtBackend};
    use crate::virt::capacity::{VsockCapacity, VsockLease};
    use crate::virt::error::VirtError;
    use crate::virt::machine::{MachineInner, VirtualMachine};
    use crate::virt::serial::SerialConsole;
    use crate::virt::stream::{SerialDevice, VsockListener, VsockStream};
    use crate::virt::VmExit;

    #[derive(Debug, Clone, Copy)]
    enum ConnectBehavior {
        Success,
        Failure,
        Pending,
        WrongDestination,
        MissingLease,
    }

    #[derive(Debug, Clone, Copy)]
    enum ListenBehavior {
        WrongPort,
        ForeignCapacity,
    }

    #[derive(Debug)]
    struct TestBackend {
        behavior: ConnectBehavior,
        listen_behavior: Option<ListenBehavior>,
        attempts: AtomicUsize,
        peers: Mutex<Vec<UnixStream>>,
    }

    impl TestBackend {
        fn new(behavior: ConnectBehavior) -> Self {
            Self {
                behavior,
                listen_behavior: None,
                attempts: AtomicUsize::new(0),
                peers: Mutex::new(Vec::new()),
            }
        }

        fn with_listen_behavior(mut self, behavior: ListenBehavior) -> Self {
            self.listen_behavior = Some(behavior);
            self
        }
    }

    #[async_trait]
    impl VirtBackend for TestBackend {
        async fn start(&self) -> Result<(), VirtError> {
            Ok(())
        }

        async fn stop(&self) -> Result<(), VirtError> {
            Ok(())
        }

        async fn wait(&self) -> Result<VmExit, VirtError> {
            Ok(VmExit::Stopped)
        }

        async fn try_wait(&self) -> Result<Option<VmExit>, VirtError> {
            Ok(None)
        }

        async fn connect_vsock(
            &self,
            port: u32,
            lease: VsockLease,
        ) -> Result<VsockStream, VirtError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                ConnectBehavior::Failure => Err(VirtError::Backend("connect failed".to_string())),
                ConnectBehavior::Pending => {
                    let _lease = lease;
                    std::future::pending().await
                }
                ConnectBehavior::Success
                | ConnectBehavior::WrongDestination
                | ConnectBehavior::MissingLease => {
                    let (stream, peer) = UnixStream::pair()?;
                    self.peers.lock().expect("peer lock").push(peer);
                    let destination = match self.behavior {
                        ConnectBehavior::WrongDestination => port + 1,
                        _ => port,
                    };
                    let lease = match self.behavior {
                        ConnectBehavior::MissingLease => None,
                        _ => Some(lease),
                    };
                    Ok(VsockStream::from_unix_stream(
                        stream,
                        Some(1 << 30),
                        destination,
                        lease,
                    ))
                }
            }
        }

        async fn listen_vsock(
            &self,
            port: u32,
            capacity: VsockCapacity,
        ) -> Result<VsockListener, VirtError> {
            static NEXT_LISTENER: AtomicUsize = AtomicUsize::new(0);

            let Some(behavior) = self.listen_behavior else {
                return Err(VirtError::Backend("listener unused in test".to_string()));
            };
            let path = std::env::temp_dir().join(format!(
                "vl-{:x}-{:x}.sock",
                std::process::id(),
                NEXT_LISTENER.fetch_add(1, Ordering::Relaxed)
            ));
            let listener = tokio::net::UnixListener::bind(&path)?;
            std::fs::remove_file(path)?;
            let (registered_port, capacity) = match behavior {
                ListenBehavior::WrongPort => (port + 1, capacity),
                ListenBehavior::ForeignCapacity => {
                    (port, VsockCapacity::test_with_limit("foreign-listener", 1))
                }
            };
            Ok(VsockListener::from_unix_listener(
                listener,
                registered_port,
                capacity,
            ))
        }

        async fn open_serial(&self) -> Result<SerialDevice, VirtError> {
            let (device, _peer) = tokio::io::duplex(1);
            Ok(SerialDevice::from_duplex(device))
        }
    }

    fn machine(backend: Arc<TestBackend>, limit: usize) -> VirtualMachine {
        let backend_trait: Arc<dyn VirtBackend> = backend;
        VirtualMachine {
            inner: Arc::new(MachineInner {
                name: "capacity-test".to_string(),
                kind: BackendKind::default_for_host().expect("test host backend kind"),
                serial_console: Arc::new(SerialConsole::new(backend_trait.clone())),
                backend: backend_trait,
                vsock_capacity: VsockCapacity::test_with_limit("capacity-test", limit),
            }),
        }
    }

    #[tokio::test]
    async fn connect_and_clone_share_capacity_until_stream_drop() {
        let backend = Arc::new(TestBackend::new(ConnectBehavior::Success));
        let machine = machine(backend.clone(), 1);
        let clone = machine.clone();
        let stream = machine.connect_vsock(22).await.expect("first connect");

        assert!(matches!(
            clone.connect_vsock(22).await,
            Err(VirtError::VsockCapacityExhausted { limit: 1, .. })
        ));
        assert_eq!(backend.attempts.load(Ordering::SeqCst), 1);

        drop(stream);
        assert!(clone.connect_vsock(22).await.is_ok());
    }

    #[tokio::test]
    async fn failed_connect_releases_capacity() {
        let backend = Arc::new(TestBackend::new(ConnectBehavior::Failure));
        let machine = machine(backend, 1);

        assert!(machine.connect_vsock(22).await.is_err());
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelled_connect_releases_capacity() {
        let backend = Arc::new(TestBackend::new(ConnectBehavior::Pending));
        let machine = machine(backend.clone(), 1);
        let pending_machine = machine.clone();
        let task = tokio::spawn(async move { pending_machine.connect_vsock(22).await });

        while backend.attempts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 0);
        task.abort();
        let _ = task.await;
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn reserved_connect_transfers_one_lease_and_releases_on_drop() {
        let backend = Arc::new(TestBackend::new(ConnectBehavior::Success));
        let machine = machine(backend, 1);
        let lease = machine.reserve_vsock().expect("reserve handshake slot");
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 0);

        let stream = machine
            .connect_vsock_reserved(22, lease)
            .await
            .expect("connect with reservation");
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 0);
        drop(stream);
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn reserved_connect_failure_releases_lease() {
        let backend = Arc::new(TestBackend::new(ConnectBehavior::Failure));
        let machine = machine(backend, 1);
        let lease = machine.reserve_vsock().expect("reserve handshake slot");

        assert!(machine.connect_vsock_reserved(22, lease).await.is_err());
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn reserved_connect_rejects_a_lease_from_another_machine() {
        let first_backend = Arc::new(TestBackend::new(ConnectBehavior::Success));
        let second_backend = Arc::new(TestBackend::new(ConnectBehavior::Success));
        let first = machine(first_backend, 1);
        let second = machine(second_backend.clone(), 1);
        let lease = first.reserve_vsock().expect("reserve on first machine");

        let error = second
            .connect_vsock_reserved(22, lease)
            .await
            .expect_err("foreign lease must fail");
        assert!(error.to_string().contains("does not belong"));
        assert_eq!(second_backend.attempts.load(Ordering::SeqCst), 0);
        assert_eq!(first.inner.vsock_capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn host_connect_rejects_wrong_destination_metadata() {
        let backend = Arc::new(TestBackend::new(ConnectBehavior::WrongDestination));
        let machine = machine(backend, 1);

        let error = machine
            .connect_vsock(22)
            .await
            .expect_err("wrong destination must fail");
        assert!(error.to_string().contains("instead of requested port 22"));
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn host_connect_rejects_a_stream_without_its_lease() {
        let backend = Arc::new(TestBackend::new(ConnectBehavior::MissingLease));
        let machine = machine(backend, 1);

        let error = machine
            .connect_vsock(22)
            .await
            .expect_err("unaccounted stream must fail");
        assert!(error.to_string().contains("without capacity"));
        assert_eq!(machine.inner.vsock_capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn guest_listener_rejects_wrong_registered_port() {
        let backend = Arc::new(
            TestBackend::new(ConnectBehavior::Success)
                .with_listen_behavior(ListenBehavior::WrongPort),
        );
        let machine = machine(backend, 1);

        let error = machine
            .listen_vsock(7000)
            .await
            .expect_err("wrong listener port must fail");
        assert!(error
            .to_string()
            .contains("listener 7001 instead of requested port 7000"));
    }

    #[tokio::test]
    async fn guest_listener_rejects_foreign_capacity() {
        let backend = Arc::new(
            TestBackend::new(ConnectBehavior::Success)
                .with_listen_behavior(ListenBehavior::ForeignCapacity),
        );
        let machine = machine(backend, 1);

        let error = machine
            .listen_vsock(7000)
            .await
            .expect_err("foreign listener capacity must fail");
        assert!(error.to_string().contains("without capacity"));
    }
}
