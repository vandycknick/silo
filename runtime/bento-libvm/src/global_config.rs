use std::path::{Path, PathBuf};

use eyre::Context;
use serde::Deserialize;

use crate::layout::resolve_config_dir;
use crate::network::config::NetworkDriverKind;

const CONFIG_FILE_NAME: &str = "config.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalConfig {
    pub guest_binary: PathBuf,
    pub networking: NetworkingConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkingConfig {
    pub private_driver: NetworkDriverKind,
    pub netd: NetdConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetdConfig {
    pub subnet: String,
    pub pcap: bool,
}

impl GlobalConfig {
    pub fn load() -> eyre::Result<Self> {
        let config_path = config_path()?;
        let raw = std::fs::read_to_string(&config_path)
            .with_context(|| format!("read global config {}", config_path.display()))?;

        parse_global_config(&raw).with_context(|| {
            format!(
                "parse global config {} (expected guest.binary in yaml)",
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

    let guest_binary = parsed.guest.binary;

    if !guest_binary.is_absolute() {
        return Err(eyre::eyre!(
            "[guest].binary must be an absolute path: {}",
            guest_binary.display()
        ));
    }

    Ok(GlobalConfig {
        guest_binary,
        networking: NetworkingConfig {
            private_driver: parsed
                .networking
                .as_ref()
                .map(RawNetworkingConfig::parse_private_driver)
                .transpose()?
                .flatten()
                .unwrap_or(NetworkDriverKind::Netd),
            netd: parsed
                .networking
                .and_then(|networking| networking.drivers.and_then(|drivers| drivers.netd))
                .map(NetdConfig::from)
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
    binary: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetworkingConfig {
    private: Option<RawPrivateNetworkingConfig>,
    drivers: Option<RawNetworkDriversConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrivateNetworkingConfig {
    driver: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetworkDriversConfig {
    netd: Option<RawNetdConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetdConfig {
    subnet: Option<String>,
    pcap: Option<bool>,
}

impl RawNetworkingConfig {
    fn parse_private_driver(&self) -> eyre::Result<Option<NetworkDriverKind>> {
        self.private
            .as_ref()
            .and_then(|private| private.driver.as_deref())
            .map(parse_network_driver)
            .transpose()
    }
}

impl Default for NetdConfig {
    fn default() -> Self {
        Self {
            subnet: "192.168.105.0/24".to_string(),
            pcap: false,
        }
    }
}

impl From<RawNetdConfig> for NetdConfig {
    fn from(raw: RawNetdConfig) -> Self {
        let default = Self::default();
        Self {
            subnet: raw.subnet.unwrap_or(default.subnet),
            pcap: raw.pcap.unwrap_or(default.pcap),
        }
    }
}

fn parse_network_driver(value: &str) -> eyre::Result<NetworkDriverKind> {
    match value {
        "netd" => Ok(NetworkDriverKind::Netd),
        "vznat" => Ok(NetworkDriverKind::VzNat),
        other => Err(eyre::eyre!(
            "invalid network driver {other:?}, expected netd or vznat"
        )),
    }
}

pub fn ensure_guest_binary(config: &GlobalConfig) -> eyre::Result<&Path> {
    let path = config.guest_binary.as_path();
    let metadata =
        std::fs::metadata(path).with_context(|| format!("stat guest binary {}", path.display()))?;

    if !metadata.is_file() {
        return Err(eyre::eyre!(
            "guest binary path is not a file: {}",
            path.display()
        ));
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_global_config_reads_guest_binary() {
        let cfg = parse_global_config(
            r#"
guest:
  binary: "/tmp/bento-agent"
"#,
        )
        .expect("parse config");

        assert_eq!(cfg.guest_binary, PathBuf::from("/tmp/bento-agent"));
        assert_eq!(cfg.networking.private_driver, NetworkDriverKind::Netd);
        assert_eq!(cfg.networking.netd, NetdConfig::default());
    }

    #[test]
    fn parse_global_config_reads_networking_defaults() {
        let cfg = parse_global_config(
            r#"
guest:
  binary: "/tmp/bento-agent"
networking:
  private:
    driver: netd
  drivers:
    netd:
      subnet: "192.168.105.0/24"
      pcap: true
"#,
        )
        .expect("parse config");

        assert_eq!(cfg.networking.private_driver, NetworkDriverKind::Netd);
        assert_eq!(
            cfg.networking.netd,
            NetdConfig {
                subnet: "192.168.105.0/24".to_string(),
                pcap: true,
            }
        );
    }

    #[test]
    fn parse_global_config_reads_vznat_private_driver() {
        let cfg = parse_global_config(
            r#"
guest:
  binary: "/tmp/bento-agent"
networking:
  private:
    driver: vznat
"#,
        )
        .expect("parse config");

        assert_eq!(cfg.networking.private_driver, NetworkDriverKind::VzNat);
    }

    #[test]
    fn parse_global_config_rejects_legacy_gvisor_config() {
        let result = parse_global_config(
            r#"
guest:
  binary: "/tmp/bento-agent"
networking:
  userspace: gvisor
  drivers:
    gvisor:
      helper: gvproxy
"#,
        );

        assert!(result.is_err());
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
  binary: "./bento-agent"
"#,
        )
        .expect_err("relative path should fail");

        assert!(err.to_string().contains("absolute path"));
    }
}
