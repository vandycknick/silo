use std::path::PathBuf;

use eyre::Context;
use serde::Deserialize;

use crate::layout::resolve_config_dir;
use crate::models::NetworkDriverKind;

const CONFIG_FILE_NAME: &str = "config.yaml";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalConfig {
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
    pub tls_ca_cert: Option<PathBuf>,
    pub tls_ca_key: Option<PathBuf>,
}

impl GlobalConfig {
    pub fn load() -> eyre::Result<Self> {
        let config_path = config_path()?;
        let raw = match std::fs::read_to_string(&config_path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("read global config {}", config_path.display()));
            }
        };

        parse_global_config(&raw)
            .with_context(|| format!("parse global config {}", config_path.display()))
    }
}

impl Default for NetworkingConfig {
    fn default() -> Self {
        Self {
            private_driver: NetworkDriverKind::Netd,
            netd: NetdConfig::default(),
        }
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

    let private_driver = parsed
        .networking
        .as_ref()
        .map(RawNetworkingConfig::parse_private_driver)
        .transpose()?
        .flatten()
        .unwrap_or(NetworkDriverKind::Netd);
    let netd = parsed
        .networking
        .and_then(|networking| networking.drivers.and_then(|drivers| drivers.netd))
        .map(NetdConfig::from)
        .unwrap_or_default();
    validate_netd_config(&netd)?;

    Ok(GlobalConfig {
        networking: NetworkingConfig {
            private_driver,
            netd,
        },
    })
}

#[derive(Debug, Deserialize)]
struct RawGlobalConfig {
    networking: Option<RawNetworkingConfig>,
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
    tls_ca_cert: Option<PathBuf>,
    tls_ca_key: Option<PathBuf>,
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
            tls_ca_cert: None,
            tls_ca_key: None,
        }
    }
}

impl From<RawNetdConfig> for NetdConfig {
    fn from(raw: RawNetdConfig) -> Self {
        let default = Self::default();
        Self {
            subnet: raw.subnet.unwrap_or(default.subnet),
            pcap: raw.pcap.unwrap_or(default.pcap),
            tls_ca_cert: raw.tls_ca_cert,
            tls_ca_key: raw.tls_ca_key,
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

fn validate_netd_config(config: &NetdConfig) -> eyre::Result<()> {
    if config.tls_ca_cert.is_some() != config.tls_ca_key.is_some() {
        return Err(eyre::eyre!(
            "[networking.drivers.netd].tls_ca_cert and tls_ca_key must be configured together"
        ));
    }
    for (field, path) in [
        ("tls_ca_cert", config.tls_ca_cert.as_ref()),
        ("tls_ca_key", config.tls_ca_key.as_ref()),
    ] {
        if let Some(path) = path {
            if !path.is_absolute() {
                return Err(eyre::eyre!(
                    "[networking.drivers.netd].{field} must be an absolute path: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_global_config_reads_defaults() {
        let cfg = parse_global_config("{}").expect("parse config");

        assert_eq!(cfg.networking.private_driver, NetworkDriverKind::Netd);
        assert_eq!(cfg.networking.netd, NetdConfig::default());
    }

    #[test]
    fn parse_global_config_ignores_legacy_guest_settings() {
        let cfg = parse_global_config(
            r#"
guest:
  binary: "/tmp/bento-agent"
"#,
        )
        .expect("parse config");

        assert_eq!(cfg, GlobalConfig::default());
    }

    #[test]
    fn parse_global_config_reads_networking_defaults() {
        let cfg = parse_global_config(
            r#"
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
                tls_ca_cert: None,
                tls_ca_key: None,
            }
        );
    }

    #[test]
    fn parse_global_config_reads_netd_tls_ca_paths() {
        let cfg = parse_global_config(
            r#"
networking:
  drivers:
    netd:
      tls_ca_cert: "/tmp/bento-ca.pem"
      tls_ca_key: "/tmp/bento-ca-key.pem"
"#,
        )
        .expect("parse config");

        assert_eq!(
            cfg.networking.netd.tls_ca_cert,
            Some(PathBuf::from("/tmp/bento-ca.pem"))
        );
        assert_eq!(
            cfg.networking.netd.tls_ca_key,
            Some(PathBuf::from("/tmp/bento-ca-key.pem"))
        );
    }

    #[test]
    fn parse_global_config_rejects_relative_netd_tls_ca_paths() {
        let result = parse_global_config(
            r#"
networking:
  drivers:
    netd:
      tls_ca_cert: "ca.pem"
      tls_ca_key: "/tmp/bento-ca-key.pem"
"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn parse_global_config_rejects_partial_netd_tls_ca_paths() {
        let result = parse_global_config(
            r#"
networking:
  drivers:
    netd:
      tls_ca_cert: "/tmp/bento-ca.pem"
"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn parse_global_config_reads_vznat_private_driver() {
        let cfg = parse_global_config(
            r#"
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
networking:
  userspace: gvisor
  drivers:
    gvisor:
      helper: gvproxy
"#,
        );

        assert!(result.is_err());
    }
}
