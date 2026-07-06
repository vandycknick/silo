use std::ffi::OsString;
use std::path::PathBuf;

use eyre::Context as _;
use libvm::{NetdRuntimeConfig, NetworkDriverKind, RuntimeNetworkingConfig};
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};

const APP_DIR_NAME: &str = "silo";
const CONFIG_FILE_NAME: &str = "config.yaml";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalConfig {
    pub(crate) default_machine: Option<String>,
    pub(crate) networking: RuntimeNetworkingConfig,
}

impl GlobalConfig {
    pub(crate) fn load() -> eyre::Result<Self> {
        let config_dir = resolve_default_config_dir()?;
        let config_path = config_dir.join(CONFIG_FILE_NAME);
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

    pub(crate) fn write_default_machine(default_machine: Option<&str>) -> eyre::Result<()> {
        let config_dir = resolve_default_config_dir()?;
        std::fs::create_dir_all(&config_dir)
            .with_context(|| format!("create global config directory {}", config_dir.display()))?;
        let config_path = config_dir.join(CONFIG_FILE_NAME);
        write_default_machine_to_path(&config_path, default_machine)
    }

    fn default_for_config_dir(config_dir: PathBuf) -> Self {
        Self {
            default_machine: None,
            networking: RuntimeNetworkingConfig::default().with_policy_config_dir(config_dir),
        }
    }
}

fn resolve_default_config_dir() -> eyre::Result<PathBuf> {
    let home = env_absolute_path("HOME")?;
    let config_home = env_absolute_path("XDG_CONFIG_HOME")?
        .or_else(|| home.as_ref().map(|path| path.join(".config")));

    config_home
        .map(|path| path.join(APP_DIR_NAME))
        .ok_or_else(|| {
            eyre::eyre!("could not resolve Silo config directory from XDG_CONFIG_HOME or HOME")
        })
}

fn env_absolute_path(name: &'static str) -> eyre::Result<Option<PathBuf>> {
    match std::env::var_os(name) {
        Some(value) => absolute_path(name, value).map(Some),
        None => Ok(None),
    }
}

fn absolute_path(name: &'static str, value: OsString) -> eyre::Result<PathBuf> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(eyre::eyre!(
            "environment variable {name} must be an absolute path: {}",
            path.display()
        ))
    }
}

fn parse_global_config(input: &str) -> eyre::Result<GlobalConfig> {
    let parsed: RawGlobalConfig =
        serde_yaml_ng::from_str(input).context("deserialize global config yaml")?;
    let default_machine = parsed
        .default_machine
        .map(|name| validate_default_machine_name(&name).map(|()| name))
        .transpose()?;

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
        .map(NetdRuntimeConfig::from)
        .unwrap_or_default();
    validate_netd_config(&netd)?;

    Ok(GlobalConfig {
        default_machine,
        networking: RuntimeNetworkingConfig::default()
            .with_private_driver(private_driver)
            .with_netd(netd),
    })
}

#[derive(Debug, Deserialize)]
struct RawGlobalConfig {
    default_machine: Option<String>,
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

fn parse_network_driver(value: &str) -> eyre::Result<NetworkDriverKind> {
    match value {
        "netd" => Ok(NetworkDriverKind::Netd),
        "vznat" => Ok(NetworkDriverKind::VzNat),
        other => Err(eyre::eyre!(
            "invalid network driver {other:?}, expected netd or vznat"
        )),
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
