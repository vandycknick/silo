use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::virt::{SerialConsole, VirtualMachine};
use tokio_util::sync::CancellationToken;

use crate::state::InstanceStore;

#[derive(Debug, Clone)]
pub(crate) struct RuntimeContext {
    dir: PathBuf,
    runtime_dir: PathBuf,
    config: PathBuf,
    socket: PathBuf,
}

impl RuntimeContext {
    pub(crate) fn new(
        dir: PathBuf,
        runtime_dir: PathBuf,
        config: PathBuf,
        socket: PathBuf,
    ) -> Self {
        Self {
            dir,
            runtime_dir,
            config,
            socket,
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn config(&self) -> &Path {
        &self.config
    }

    pub(crate) fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }
}

#[derive(Clone)]
pub struct DaemonContext {
    pub(crate) machine_id: uuid::Uuid,
    pub(crate) machine_run_id: uuid::Uuid,
    pub(crate) guest_services_enabled: bool,
    pub(crate) machine: VirtualMachine,
    pub(crate) serial_console: Arc<SerialConsole>,
    pub(crate) store: Arc<InstanceStore>,
    pub(crate) forwards: Arc<crate::forward::ForwardTable>,
    pub(crate) stop_requested: CancellationToken,
    pub(crate) shutdown: CancellationToken,
}
