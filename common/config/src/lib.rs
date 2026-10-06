use std::path::PathBuf;

use eyre::Context as _;
use libvm::{NetdRuntimeConfig, RuntimeNetworkingConfig};
use serde::Deserialize;
use serde_yaml_ng::Value;

mod daemon;
pub mod tailscale;
mod transaction;
use daemon::DaemonConfig;
use tailscale::TailscaleConfig;

/// Prepare and canonicalize manager-selected Home/config roots without opening a runtime.
/// Optional templates/policies directories are deliberately not created.
pub fn prepare_host_paths(host: &libvm::HostPaths) -> eyre::Result<libvm::HostPaths> {
    Ok(libvm::HostPaths::new(
        transaction::prepare_root(host.home())?,
        transaction::prepare_root(host.config_dir())?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalConfig {
    default_machine: Option<String>,
    networking: RuntimeNetworkingConfig,
    daemon: DaemonConfig,
}

impl GlobalConfig {
    pub fn load() -> eyre::Result<Self> {
        Self::load_from(&libvm::HostPaths::from_env()?)
    }

    /// Reads the config file the host paths resolve (the config directory's
    /// `config.yaml`, else the home fallback). Policies stay in the config
    /// directory either way.
    pub fn load_from(host: &libvm::HostPaths) -> eyre::Result<Self> {
        let config_dir = host.config_dir().to_path_buf();
        let config_path = transaction::config_path(host);
        let raw = match transaction::read_config(&config_path)? {
            Some(raw) => raw,
            None => return Ok(Self::default_for_config_dir(config_dir)),
        };

        let mut config = parse_global_config(&raw)
            .with_context(|| format!("parse global config {}", config_path.display()))?;
        config.networking.policy_config_dir = Some(config_dir);
        Ok(config)
    }

    pub fn default_machine(&self) -> Option<&str> {
        self.default_machine.as_deref()
    }

    /// The explicit system-appliance overrides to pass to silod.
    pub fn daemon_overrides(&self) -> eyre::Result<silod_spec::arguments::SystemOverrides> {
        self.daemon.overrides()
    }

    pub fn networking(&self) -> &RuntimeNetworkingConfig {
        &self.networking
    }

    pub fn tailscale(&self) -> &TailscaleConfig {
        &self.daemon.tailscale
    }

    /// Opaque, nonsecret identity for deciding whether the running daemon needs
    /// a configuration restart. CLI-only defaults and disabled integrations do
    /// not affect it. This is an equality token, not an authentication digest.
    pub fn daemon_identity(&self, features: FeatureSelection) -> eyre::Result<String> {
        let system = features
            .system
            .then(|| self.daemon_overrides())
            .transpose()?;
        let tailscale = features
            .tailscale
            .then(|| self.tailscale().effective_settings());
        Ok(format!(
            "{}:{features:?}:{:?}:{system:?}:{tailscale:?}",
            env!("CARGO_PKG_VERSION"),
            self.networking()
        ))
    }

    pub fn resolve_features(
        &self,
        overrides: FeatureOverrides,
        existing_system_installation: bool,
    ) -> FeatureSelection {
        let system = self.daemon.system_enabled();
        let tailscale = self.daemon.tailscale.enabled();
        FeatureSelection {
            system: overrides
                .system
                .or(system)
                .unwrap_or(cfg!(target_os = "macos") || existing_system_installation),
            tailscale: overrides.tailscale.or(tailscale).unwrap_or(false),
        }
    }

    /// Resolve and persist selections against the latest document under the transaction lock.
    pub fn persist_features(
        host: &libvm::HostPaths,
        overrides: FeatureOverrides,
        existing_system_installation: bool,
    ) -> eyre::Result<FeatureSelection> {
        transaction::update(host, |document, config| {
            let selected = config.resolve_features(overrides, existing_system_installation);
            let daemon = transaction::mapping_entry(document, "daemon")?;
            daemon.insert(Value::String("version".into()), Value::String("1".into()));
            for (name, enabled) in [
                ("system", selected.system),
                ("tailscale", selected.tailscale),
            ] {
                transaction::mapping_entry(daemon, name)?
                    .insert(Value::String("enabled".into()), Value::Bool(enabled));
            }
            Ok(selected)
        })
    }

    pub fn write_default_machine(default_machine: Option<&str>) -> eyre::Result<()> {
        Self::write_default_machine_from(&libvm::HostPaths::from_env()?, default_machine)
    }

    pub fn write_default_machine_from(
        host: &libvm::HostPaths,
        default_machine: Option<&str>,
    ) -> eyre::Result<()> {
        transaction::update(host, |document, _| {
            let key = Value::String("default_machine".into());
            match default_machine {
                Some(name) => {
                    validate_default_machine_name(name)?;
                    document.insert(key, Value::String(name.into()));
                }
                None => {
                    document.remove(&key);
                }
            }
            Ok(())
        })
    }

    fn default_for_config_dir(config_dir: PathBuf) -> Self {
        Self {
            default_machine: None,
            networking: RuntimeNetworkingConfig::default().with_policy_config_dir(config_dir),
            daemon: DaemonConfig::default(),
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

    if let Some(daemon) = &parsed.daemon {
        daemon.validate()?;
    }

    Ok(GlobalConfig {
        default_machine,
        networking: RuntimeNetworkingConfig::default().with_netd(netd),
        daemon: parsed.daemon.unwrap_or_default(),
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeatureOverrides {
    pub system: Option<bool>,
    pub tailscale: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureSelection {
    pub system: bool,
    pub tailscale: bool,
}

#[cfg(test)]
mod tests {
    use crate::{parse_global_config, GlobalConfig};

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
        assert!(parse_global_config("daemon:\n  version: '2'\n").is_err());
    }

    #[test]
    fn daemon_restart_identity_ignores_cli_defaults_and_disabled_components() {
        let baseline = parse_global_config("{}").unwrap();
        let changed = parse_global_config(concat!(
            "default_machine: different\n",
            "daemon:\n  version: '1'\n",
            "  system:\n    resources:\n      cpus: 4\n",
            "  tailscale:\n    hostname: another-lobby\n"
        ))
        .unwrap();
        let disabled = crate::FeatureSelection {
            system: false,
            tailscale: false,
        };
        assert_eq!(
            baseline.daemon_identity(disabled).unwrap(),
            changed.daemon_identity(disabled).unwrap()
        );
        for enabled in [
            crate::FeatureSelection {
                system: true,
                tailscale: false,
            },
            crate::FeatureSelection {
                system: false,
                tailscale: true,
            },
        ] {
            assert_ne!(
                baseline.daemon_identity(enabled).unwrap(),
                changed.daemon_identity(enabled).unwrap()
            );
        }
    }
    #[test]
    fn persisting_effective_feature_selection_does_not_require_restart() {
        let selected = crate::FeatureSelection {
            system: false,
            tailscale: true,
        };
        let baseline = parse_global_config("{}").unwrap();
        let persisted = parse_global_config(
            "daemon:\n  version: '1'\n  system:\n    enabled: false\n  tailscale:\n    enabled: true\n"
        ).unwrap();
        assert_eq!(
            baseline.daemon_identity(selected).unwrap(),
            persisted.daemon_identity(selected).unwrap()
        );
    }
}
