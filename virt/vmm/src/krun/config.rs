use std::path::{Path, PathBuf};

use crate::krun::error::{KrunBackendError, Result};
use crate::krun::rosetta::{RosettaLaunchConfig, ROSETTA_MOUNT_TAG};

pub const DEFAULT_ID: &str = "anonymous-instance";
const STANDALONE_VSOCK_CID: u64 = 3;

/// The one typed worker config. Serialized to the worker's config descriptor;
/// the Rosetta field keeps its own redacted `Debug`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrunConfig {
    pub id: String,
    pub cpus: u8,
    pub memory_mib: u32,
    pub kernel: Option<PathBuf>,
    pub initramfs: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub disks: Vec<Disk>,
    pub mounts: Vec<Mount>,
    pub vsock_mux: bool,
    pub vsock_cid: Option<u64>,
    pub network: Network,
    pub stdio_console: bool,
    pub balloon: bool,
    pub rosetta: Option<RosettaLaunchConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disk {
    pub block_id: String,
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub tag: String,
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetUnixgram {
    pub peer_path: PathBuf,
    pub mac: [u8; 6],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetUnixstream {
    pub peer_path: PathBuf,
    pub mac: [u8; 6],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetTap {
    pub name: String,
    pub mac: [u8; 6],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
            vsock_mux: false,
            vsock_cid: None,
            network: Network::None,
            stdio_console: false,
            balloon: false,
            rosetta: None,
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
    if config.vsock_cid.is_some() && config.vsock_mux {
        return Err(KrunBackendError::InvalidConfig(
            "standalone vsock and the vsock mux cannot be used together".to_string(),
        ));
    }
    if config.rosetta.is_some()
        && config
            .mounts
            .iter()
            .any(|mount| mount.tag == ROSETTA_MOUNT_TAG)
    {
        return Err(KrunBackendError::InvalidConfig(format!(
            "mount tag {ROSETTA_MOUNT_TAG:?} is reserved for Rosetta"
        )));
    }
    if config
        .vsock_cid
        .is_some_and(|cid| cid != STANDALONE_VSOCK_CID)
    {
        return Err(KrunBackendError::InvalidConfig(format!(
            "native vsock currently requires guest CID {STANDALONE_VSOCK_CID}"
        )));
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::krun::config::{validate_config, KrunConfig};

    fn valid_config() -> KrunConfig {
        KrunConfig {
            kernel: Some(PathBuf::from("/kernel")),
            ..KrunConfig::default()
        }
    }

    #[test]
    fn standalone_vsock_accepts_guest_cid_three() {
        let config = KrunConfig {
            vsock_cid: Some(3),
            ..valid_config()
        };

        validate_config(&config).expect("guest CID 3 should be valid");
    }

    #[test]
    fn standalone_vsock_rejects_other_guest_cids() {
        let config = KrunConfig {
            vsock_cid: Some(4),
            ..valid_config()
        };

        let error = validate_config(&config).expect_err("guest CID 4 should be invalid");
        assert!(error.to_string().contains("guest CID 3"));
    }

    #[test]
    fn standalone_and_mux_vsock_are_mutually_exclusive() {
        let config = KrunConfig {
            vsock_mux: true,
            vsock_cid: Some(3),
            ..valid_config()
        };

        let error = validate_config(&config).expect_err("vsock devices should conflict");
        assert!(error.to_string().contains("cannot be used together"));
    }
}
