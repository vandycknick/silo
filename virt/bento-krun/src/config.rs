use std::path::{Path, PathBuf};

use crate::error::{KrunBackendError, Result};

pub const DEFAULT_ID: &str = "anonymous-instance";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrunConfig {
    pub id: String,
    pub cpus: u8,
    pub memory_mib: u32,
    pub kernel: Option<PathBuf>,
    pub initramfs: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub disks: Vec<Disk>,
    pub mounts: Vec<Mount>,
    pub vsock_ports: Vec<VsockPort>,
    pub network: Network,
    pub stdio_console: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub block_id: String,
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub tag: String,
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockPort {
    pub port: u32,
    pub path: PathBuf,
    pub listen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetUnixgram {
    pub peer_path: PathBuf,
    pub mac: [u8; 6],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetUnixstream {
    pub peer_path: PathBuf,
    pub mac: [u8; 6],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetTap {
    pub name: String,
    pub mac: [u8; 6],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    None,
    Unixgram(NetUnixgram),
    Unixstream(NetUnixstream),
    Tap(NetTap),
}

impl Default for KrunConfig {
    fn default() -> Self {
        Self {
            id: DEFAULT_ID.to_string(),
            cpus: 1,
            memory_mib: 512,
            kernel: None,
            initramfs: None,
            cmdline: Vec::new(),
            disks: Vec::new(),
            mounts: Vec::new(),
            vsock_ports: Vec::new(),
            network: Network::None,
            stdio_console: false,
        }
    }
}

pub fn validate_config(config: &KrunConfig) -> Result<()> {
    if config.cpus == 0 {
        return Err(KrunBackendError::InvalidConfig(
            "krun requires at least one vCPU".to_string(),
        ));
    }
    if config.memory_mib == 0 {
        return Err(KrunBackendError::InvalidConfig(
            "krun requires memory_mib to be greater than zero".to_string(),
        ));
    }
    if config.kernel.is_none() {
        return Err(KrunBackendError::InvalidConfig(
            "krun requires a kernel".to_string(),
        ));
    }
    match &config.network {
        Network::None => {}
        Network::Unixgram(net) => {
            validate_vm_id(config, "net unixgram")?;
            validate_peer_path(&net.peer_path, "net unixgram")?;
            validate_mac(net.mac, "net unixgram")?;
        }
        Network::Unixstream(net) => {
            validate_peer_path(&net.peer_path, "net unixstream")?;
            validate_mac(net.mac, "net unixstream")?;
        }
        Network::Tap(net) => {
            validate_tap_name(&net.name)?;
            validate_mac(net.mac, "net tap")?;
            #[cfg(not(target_os = "linux"))]
            return Err(KrunBackendError::InvalidConfig(
                "net tap is only supported on Linux".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_vm_id(config: &KrunConfig, name: &str) -> Result<()> {
    if config.id.is_empty() {
        return Err(KrunBackendError::InvalidConfig(format!(
            "{name} requires a non-empty VM id"
        )));
    }
    Ok(())
}

fn validate_peer_path(path: &Path, name: &str) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(KrunBackendError::InvalidConfig(format!(
            "{name} peer path cannot be empty"
        )));
    }
    Ok(())
}

fn validate_tap_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(KrunBackendError::InvalidConfig(
            "net tap name cannot be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_mac(mac: [u8; 6], name: &str) -> Result<()> {
    if mac[0] & 0x01 != 0 {
        return Err(KrunBackendError::InvalidConfig(format!(
            "{name} mac cannot be multicast"
        )));
    }
    Ok(())
}
