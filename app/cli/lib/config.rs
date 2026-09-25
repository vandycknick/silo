use std::path::PathBuf;

use eyre::Context as _;
use libvm::{NetdRuntimeConfig, RuntimeNetworkingConfig};
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};

use crate::daemon::config::DaemonConfig;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalConfig {
    pub(crate) default_machine: Option<String>,
    pub(crate) networking: RuntimeNetworkingConfig,
    pub(crate) daemon: Option<DaemonConfig>,
}

impl GlobalConfig {
    pub(crate) fn load() -> eyre::Result<Self> {
        Self::load_from(&libvm::HostPaths::from_env()?)
    }

    /// Reads the config file the host paths resolve (the config directory's
    /// `config.yaml`, else the home fallback). Policies stay in the config
    /// directory either way.
    pub(crate) fn load_from(host: &libvm::HostPaths) -> eyre::Result<Self> {
        let config_dir = host.config_dir().to_path_buf();
        let config_path = host.config_file();
        let raw = match std::fs::read_to_string(&config_path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default_for_config_dir(config_dir));
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("read global config {}", config_path.display()));
            }
        };

        let mut config = parse_global_config(&raw)
            .with_context(|| format!("parse global config {}", config_path.display()))?;
        config.networking.policy_config_dir = Some(config_dir);
        Ok(config)
    }

    pub(crate) fn default_machine(&self) -> Option<&str> {
        self.default_machine.as_deref()
    }

    /// The explicit system-appliance overrides to pass to silod.
    pub(crate) fn daemon_overrides(&self) -> eyre::Result<silod_spec::arguments::SystemOverrides> {
        self.daemon
            .as_ref()
            .map(DaemonConfig::overrides)
            .unwrap_or_else(|| Ok(Default::default()))
    }

    pub(crate) fn write_default_machine(default_machine: Option<&str>) -> eyre::Result<()> {
        let config_path = libvm::HostPaths::from_env()?.config_file();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create global config directory {}", parent.display()))?;
        }
        write_default_machine_to_path(&config_path, default_machine)
    }

    fn default_for_config_dir(config_dir: PathBuf) -> Self {
        Self {
            default_machine: None,
            networking: RuntimeNetworkingConfig::default().with_policy_config_dir(config_dir),
            daemon: None,
        }
    }
}

fn parse_global_config(input: &str) -> eyre::Result<GlobalConfig> {
    let parsed: RawGlobalConfig =
        serde_yaml_ng::from_str(input).context("deserialize global config yaml")?;
    let default_machine = parsed
        .default_machine
        .map(|name| validate_default_machine_name(&name).map(|()| name))
        .transpose()?;

    let netd = parsed
        .networking
        .and_then(|networking| networking.drivers.and_then(|drivers| drivers.netd))
        .map(NetdRuntimeConfig::from)
        .unwrap_or_default();
    validate_netd_config(&netd)?;

    Ok(GlobalConfig {
        default_machine,
        networking: RuntimeNetworkingConfig::default().with_netd(netd),
        daemon: parsed.daemon,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGlobalConfig {
    default_machine: Option<String>,
    networking: Option<RawNetworkingConfig>,
    daemon: Option<DaemonConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetworkingConfig {
    drivers: Option<RawNetworkDriversConfig>,
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

impl From<RawNetdConfig> for NetdRuntimeConfig {
    fn from(raw: RawNetdConfig) -> Self {
        let mut config = Self::default();
        if let Some(subnet) = raw.subnet {
            config.subnet = subnet;
        }
        if let Some(pcap) = raw.pcap {
            config.pcap = pcap;
        }
        config.tls_ca_cert = raw.tls_ca_cert;
        config.tls_ca_key = raw.tls_ca_key;
        config
    }
}

fn validate_default_machine_name(name: &str) -> eyre::Result<()> {
    if name.trim().is_empty() {
        return Err(eyre::eyre!("default_machine cannot be empty"));
    }
    Ok(())
}

fn validate_netd_config(config: &NetdRuntimeConfig) -> eyre::Result<()> {
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

fn write_default_machine_to_path(
    config_path: &std::path::Path,
    default_machine: Option<&str>,
) -> eyre::Result<()> {
    let mut document = match std::fs::read_to_string(config_path) {
        Ok(raw) => serde_yaml_ng::from_str::<Value>(&raw)
            .with_context(|| format!("parse global config {}", config_path.display()))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Value::Mapping(Mapping::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read global config {}", config_path.display()))
        }
    };

    if matches!(document, Value::Null) {
        document = Value::Mapping(Mapping::new());
    }
    let Some(mapping) = document.as_mapping_mut() else {
        return Err(eyre::eyre!(
            "global config {} must be a YAML mapping",
            config_path.display()
        ));
    };

    let key = Value::String("default_machine".to_string());
    match default_machine {
        Some(name) => {
            validate_default_machine_name(name)?;
            mapping.insert(key, Value::String(name.to_string()));
        }
        None => {
            mapping.remove(&key);
        }
    }

    let rendered = serde_yaml_ng::to_string(&document).context("serialize global config yaml")?;
    std::fs::write(config_path, rendered)
        .with_context(|| format!("write global config {}", config_path.display()))
}

#[cfg(test)]
mod tests {
    use crate::config::{parse_global_config, GlobalConfig};

    #[test]
    fn daemon_overrides_are_empty_without_a_config_file_or_section() {
        let temp = tempfile::tempdir().expect("temp home");
        let paths = libvm::HostPaths::new(temp.path().join(".silo"), temp.path().join("config"));
        let config = GlobalConfig::load_from(&paths).expect("load missing config");
        assert_eq!(
            config.daemon_overrides().expect("overrides"),
            Default::default()
        );
        for yaml in ["{}\n", "default_machine: example\n"] {
            assert_eq!(
                parse_global_config(yaml)
                    .expect("config")
                    .daemon_overrides()
                    .expect("overrides"),
                Default::default()
            );
        }
        assert!(!paths.config_file().exists());
        assert!(!paths.home().exists());
    }

    #[test]
    fn daemon_section_is_strict_and_versioned() {
        let config = parse_global_config(
            "daemon:\n  version: '1'\n  system:\n    resources:\n      cpus: 2\n",
        )
        .expect("explicit config");
        assert_eq!(config.daemon_overrides().expect("overrides").cpus, Some(2));
        assert!(parse_global_config("daemon:\n  version: '1'\n  unknown: true\n").is_err());
        assert!(parse_global_config("daemon:\n  version: '2'\n")
            .expect("parse version")
            .daemon_overrides()
            .is_err());
    }
}
