use std::path::{Path, PathBuf};

use eyre::Context;
use serde::Deserialize;

use crate::layout::resolve_config_dir;
use bento_core::NetworkDriver;

const CONFIG_FILE_NAME: &str = "config.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalConfig {
    pub guest_agent_binary: PathBuf,
    pub networking: NetworkingConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkingConfig {
    pub userspace: NetworkDriver,
    pub gvisor: GvisorConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GvisorConfig {
    pub subnet: String,
    pub pcap: bool,
    pub helper: GvisorHelper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GvisorHelper {
    Gvproxy,
    BentoNetd,
}

impl GlobalConfig {
    pub fn load() -> eyre::Result<Self> {
        let config_path = config_path()?;
        let raw = std::fs::read_to_string(&config_path)
            .with_context(|| format!("read global config {}", config_path.display()))?;

        parse_global_config(&raw).with_context(|| {
            format!(
                "parse global config {} (expected guest.agent_binary in yaml)",
                config_path.display()
            )
        })
    }
}

fn config_path() -> eyre::Result<PathBuf> {
    resolve_config_dir()
        .map(|base| base.join(CONFIG_FILE_NAME))
        .ok_or_else(|| eyre::eyre!("resolve ~/.config/bento path"))
}

fn parse_global_config(input: &str) -> eyre::Result<GlobalConfig> {
    let parsed: RawGlobalConfig =
        serde_yaml_ng::from_str(input).context("deserialize global config yaml")?;

    let guest_agent_binary = parsed.guest.agent_binary;

    if !guest_agent_binary.is_absolute() {
        return Err(eyre::eyre!(
            "[guest].agent_binary must be an absolute path: {}",
            guest_agent_binary.display()
        ));
    }

    Ok(GlobalConfig {
        guest_agent_binary,
        networking: NetworkingConfig {
            userspace: parsed
                .networking
                .as_ref()
                .map(|networking| networking.userspace)
                .unwrap_or(NetworkDriver::Gvisor),
            gvisor: parsed
                .networking
                .and_then(|networking| networking.drivers.and_then(|drivers| drivers.gvisor))
                .map(GvisorConfig::from)
                .unwrap_or_default(),
        },
    })
}

#[derive(Debug, Deserialize)]
struct RawGlobalConfig {
    guest: RawGuestConfig,
    networking: Option<RawNetworkingConfig>,
}

#[derive(Debug, Deserialize)]
struct RawGuestConfig {
    agent_binary: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RawNetworkingConfig {
    #[serde(default = "default_userspace_driver")]
    userspace: NetworkDriver,
    drivers: Option<RawNetworkDriversConfig>,
}

#[derive(Debug, Deserialize)]
struct RawNetworkDriversConfig {
    gvisor: Option<RawGvisorConfig>,
}

#[derive(Debug, Deserialize)]
struct RawGvisorConfig {
    subnet: Option<String>,
    pcap: Option<bool>,
    helper: Option<String>,
}

impl Default for GvisorConfig {
    fn default() -> Self {
        Self {
            subnet: "192.168.105.0/24".to_string(),
            pcap: false,
            helper: GvisorHelper::Gvproxy,
        }
    }
}

impl From<RawGvisorConfig> for GvisorConfig {
    fn from(raw: RawGvisorConfig) -> Self {
        let default = Self::default();
        Self {
            subnet: raw.subnet.unwrap_or(default.subnet),
            pcap: raw.pcap.unwrap_or(default.pcap),
            helper: raw
                .helper
                .as_deref()
                .map(parse_gvisor_helper)
                .unwrap_or(default.helper),
        }
    }
}

fn parse_gvisor_helper(value: &str) -> GvisorHelper {
    match value {
        "bento-netd" => GvisorHelper::BentoNetd,
        _ => GvisorHelper::Gvproxy,
    }
}

fn default_userspace_driver() -> NetworkDriver {
    NetworkDriver::Gvisor
}

pub fn ensure_guest_agent_binary(config: &GlobalConfig) -> eyre::Result<&Path> {
    let path = config.guest_agent_binary.as_path();
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("stat guest agent binary {}", path.display()))?;

    if !metadata.is_file() {
        return Err(eyre::eyre!(
            "guest agent path is not a file: {}",
            path.display()
        ));
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_global_config_reads_guest_agent_binary() {
        let cfg = parse_global_config(
            r#"
guest:
  agent_binary: "/tmp/bento-agent"
"#,
        )
        .expect("parse config");

        assert_eq!(cfg.guest_agent_binary, PathBuf::from("/tmp/bento-agent"));
        assert_eq!(cfg.networking.userspace, NetworkDriver::Gvisor);
        assert_eq!(cfg.networking.gvisor, GvisorConfig::default());
    }

    #[test]
    fn parse_global_config_reads_networking_defaults() {
        let cfg = parse_global_config(
            r#"
guest:
  agent_binary: "/tmp/bento-agent"
networking:
  userspace: gvisor
  drivers:
      gvisor:
        subnet: "192.168.105.0/24"
        pcap: true
        helper: bento-netd
"#,
        )
        .expect("parse config");

        assert_eq!(cfg.networking.userspace, NetworkDriver::Gvisor);
        assert_eq!(
            cfg.networking.gvisor,
            GvisorConfig {
                subnet: "192.168.105.0/24".to_string(),
                pcap: true,
                helper: GvisorHelper::BentoNetd,
            }
        );
    }

    #[test]
    fn parse_global_config_rejects_missing_guest_key() {
        let result = parse_global_config(
            r#"
guest:
  other: "value"
"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn parse_global_config_rejects_relative_paths() {
        let err = parse_global_config(
            r#"
guest:
  agent_binary: "./bento-agent"
"#,
        )
        .expect_err("relative path should fail");

        assert!(err.to_string().contains("absolute path"));
    }
}
