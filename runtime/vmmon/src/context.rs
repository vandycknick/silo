use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use virt::{SerialConsole, VirtualMachine};
use vm_spec::VmSpec;

use crate::state::InstanceStore;

#[derive(Debug, Clone)]
pub(crate) struct RuntimeContext {
    dir: PathBuf,
    config: PathBuf,
    socket: PathBuf,
}

impl RuntimeContext {
    pub(crate) fn new(dir: PathBuf, config: PathBuf, socket: PathBuf) -> Self {
        Self {
            dir,
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

    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }
}

#[derive(Clone)]
pub struct DaemonContext {
    pub(crate) spec: VmSpec,
    pub(crate) guest_services_enabled: bool,
    pub(crate) machine: VirtualMachine,
    pub(crate) serial_console: Arc<SerialConsole>,
    pub(crate) store: Arc<InstanceStore>,
    pub(crate) shutdown: CancellationToken,
}
