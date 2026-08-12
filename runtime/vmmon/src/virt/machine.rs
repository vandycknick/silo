use std::sync::Arc;

use super::backend::{create_backend, BackendKind, VirtBackend};
use super::config::VmConfig;
use super::error::VirtError;
use super::serial::SerialConsole;
use super::stream::{VsockListener, VsockStream};
use super::VmExit;

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

        Ok(VirtualMachine {
            inner: Arc::new(MachineInner {
                name,
                kind,
                backend,
                serial_console,
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

    /// Host-initiated connection to a guest vsock port declared `Connect`.
    pub async fn connect_vsock(&self, port: u32) -> Result<VsockStream, VirtError> {
        self.inner.backend.connect_vsock(port).await
    }

    /// Start accepting guest-initiated vsock connections on the host.
    ///
    /// Dropping the returned listener stops accepting new connections for
    /// the port.
    pub async fn listen_vsock(&self, port: u32) -> Result<VsockListener, VirtError> {
        self.inner.backend.listen_vsock(port).await
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
