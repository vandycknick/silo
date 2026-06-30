use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use thiserror::Error;

#[derive(Debug, Default)]
struct MachineIdentifierState {
    bytes: Vec<u8>,
    generated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MachineIdentifier {
    inner: Arc<Mutex<MachineIdentifierState>>,
}

impl PartialEq for MachineIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.bytes() == other.bytes()
    }
}

impl Eq for MachineIdentifier {}

impl MachineIdentifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MachineIdentifierState {
                bytes,
                generated: false,
            })),
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.inner
            .lock()
            .map(|state| state.bytes.clone())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .map(|state| state.bytes.is_empty())
            .unwrap_or(true)
    }

    pub fn was_generated(&self) -> bool {
        self.inner
            .lock()
            .map(|state| state.generated)
            .unwrap_or(false)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn set_generated_bytes(&self, bytes: Vec<u8>) -> Result<(), VirtError> {
        let mut state = self.inner.lock().map_err(|_| VirtError::RegistryPoisoned)?;
        state.bytes = bytes;
        state.generated = true;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmConfig {
    pub(crate) name: String,
    pub vm_id: String,
    pub cpus: Option<usize>,
    pub memory_mib: Option<u64>,
    pub base_directory: PathBuf,
    pub kernel_path: Option<PathBuf>,
    pub initramfs_path: Option<PathBuf>,
    pub machine_identifier: Option<MachineIdentifier>,
    pub nested_virtualization: bool,
    pub rosetta: bool,
    pub network: NetworkMode,
    pub kernel_cmdline: Vec<String>,
    pub disks: Vec<DiskImage>,
    pub mounts: Vec<SharedDirectory>,
    pub vsock_ports: Vec<VsockPort>,
}

impl VmConfig {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            vm_id: String::new(),
            cpus: None,
            memory_mib: None,
            base_directory: PathBuf::new(),
            kernel_path: None,
            initramfs_path: None,
            machine_identifier: None,
            nested_virtualization: false,
            rosetta: false,
            network: NetworkMode::None,
            kernel_cmdline: Vec::new(),
            disks: Vec::new(),
            mounts: Vec::new(),
            vsock_ports: Vec::new(),
        }
    }

    pub fn builder(name: impl Into<String>) -> VmConfigBuilder {
        VmConfigBuilder {
            config: Self {
                name: name.into(),
                ..Self::new()
            },
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn base_directory(&self) -> &PathBuf {
        &self.base_directory
    }

    pub fn vm_id(&self) -> &str {
        &self.vm_id
    }

    pub fn unix_datagram_network(&self) -> Option<(&PathBuf, [u8; 6])> {
        match &self.network {
            NetworkMode::UnixDatagram { peer_path, mac } => Some((peer_path, *mac)),
            _ => None,
        }
    }
}

impl Default for VmConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct VmConfigBuilder {
    config: VmConfig,
}

impl VmConfigBuilder {
    pub fn cpus(mut self, cpus: usize) -> Self {
        self.config.cpus = Some(cpus);
        self
    }

    pub fn memory(mut self, memory: u64) -> Self {
        self.config.memory_mib = Some(memory);
        self
    }

    pub fn base_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.base_directory = path.into();
        self
    }

    pub fn vm_id(mut self, vm_id: impl Into<String>) -> Self {
        self.config.vm_id = vm_id.into();
        self
    }

    pub fn kernel(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.kernel_path = Some(path.into());
        self
    }

    pub fn initramfs(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.initramfs_path = Some(path.into());
        self
    }

    pub fn machine_identifier(mut self, machine_identifier: MachineIdentifier) -> Self {
        self.config.machine_identifier = Some(machine_identifier);
        self
    }

    pub fn nested_virtualization(mut self, enabled: bool) -> Self {
        self.config.nested_virtualization = enabled;
        self
    }

    pub fn rosetta(mut self, enabled: bool) -> Self {
        self.config.rosetta = enabled;
        self
    }

    pub fn network(mut self, network: NetworkMode) -> Self {
        self.config.network = network;
        self
    }

    pub fn no_network(mut self) -> Self {
        self.config.network = NetworkMode::None;
        self
    }

    pub fn vz_nat_network(mut self) -> Self {
        self.config.network = NetworkMode::VzNat;
        self
    }

    pub fn unix_datagram_network(mut self, peer_path: impl Into<PathBuf>, mac: [u8; 6]) -> Self {
        self.config.network = NetworkMode::UnixDatagram {
            peer_path: peer_path.into(),
            mac,
        };
        self
    }

    pub fn unix_stream_network(mut self, path: impl Into<PathBuf>, mac: [u8; 6]) -> Self {
        self.config.network = NetworkMode::UnixStream {
            path: path.into(),
            mac,
        };
        self
    }

    pub fn tap_network(mut self, name: impl Into<String>, mac: [u8; 6]) -> Self {
        self.config.network = NetworkMode::Tap {
            name: name.into(),
            mac,
        };
        self
    }

    pub fn kernel_cmdline(mut self, kernel_cmdline: Vec<String>) -> Self {
        self.config.kernel_cmdline = kernel_cmdline;
        self
    }

    pub fn disk(mut self, disk: DiskImage) -> Self {
        self.config.disks.push(disk);
        self
    }

    pub fn mount(mut self, mount: SharedDirectory) -> Self {
        self.config.mounts.push(mount);
        self
    }

    pub fn vsock_port(mut self, port: VsockPort) -> Self {
        self.config.vsock_ports.push(port);
        self
    }

    pub fn build(self) -> VmConfig {
        self.config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskImage {
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedDirectory {
    pub host_path: PathBuf,
    pub tag: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockPort {
    pub port: u32,
    pub mode: VsockPortMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VsockPortMode {
    Connect,
    Listen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMode {
    None,
    VzNat,
    UnixDatagram { peer_path: PathBuf, mac: [u8; 6] },
    UnixStream { path: PathBuf, mac: [u8; 6] },
    Tap { name: String, mac: [u8; 6] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExit {
    Stopped,
    StoppedWithError(String),
}

#[derive(Debug, Error)]
pub enum VirtError {
    #[error("machine {name} is already running")]
    AlreadyRunning { name: String },

    #[error("machine backend {kind} is unsupported on this host: {reason}")]
    UnsupportedBackend { kind: &'static str, reason: String },

    #[error("machine backend {kind} does not implement {operation} yet")]
    Unimplemented {
        kind: &'static str,
        operation: &'static str,
    },

    #[error("machine {name} is invalid: {reason}")]
    InvalidConfig { name: String, reason: String },

    #[error("backend error: {0}")]
    Backend(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("machine registry lock was poisoned")]
    RegistryPoisoned,
}
