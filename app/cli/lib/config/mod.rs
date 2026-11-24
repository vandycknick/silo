use std::path::{Path, PathBuf};

use eyre::Context as _;
use libvm::{
    ImageRegistryConfig, NetdRuntimeConfig, RegistryAction, RegistryCa, RegistryHost,
    RegistryPolicy, RegistryRule, RegistryTrust, RuntimeNetworkingConfig,
};
use serde::Deserialize;
use serde_yaml_ng::Value;

mod daemon;
pub(crate) mod tailscale;
mod transaction;
use daemon::DaemonConfig;
use tailscale::TailscaleConfig;

/// Prepare and canonicalize manager-selected Home/config roots without opening a runtime.
/// Optional templates/policies directories are deliberately not created.
pub(crate) fn prepare_host_paths(host: &libvm::HostPaths) -> eyre::Result<libvm::HostPaths> {
    Ok(libvm::HostPaths::new(
        transaction::prepare_root(host.home())?,
        transaction::prepare_root(host.config_dir())?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct GlobalConfig {
    default_machine: Option<String>,
    networking: RuntimeNetworkingConfig,
    images: ImageRegistryConfig,
    daemon: DaemonConfig,
}

impl GlobalConfig {
    pub(crate) fn load() -> eyre::Result<Self> {
        Self::load_from(&libvm::HostPaths::from_env()?)
    }

    /// Reads the config file the host paths resolve (the config directory's
    /// `config.yaml`, else the home fallback). Policies stay in the config
    /// directory either way; relative paths inside the file resolve against
    /// the directory of the file that was actually read.
    pub(crate) fn load_from(host: &libvm::HostPaths) -> eyre::Result<Self> {
        let config_dir = host.config_dir().to_path_buf();
        let config_path = transaction::config_path(host);
        let raw = match transaction::read_config(&config_path)? {
            Some(raw) => raw,
            None => return Ok(Self::default_for_config_dir(config_dir)),
        };
        let config_file_dir = config_path
            .parent()
            .ok_or_else(|| eyre::eyre!("config has no parent"))?;

        let mut config = parse_global_config(&raw, config_file_dir)
            .with_context(|| format!("parse global config {}", config_path.display()))?;
        config.networking.policy_config_dir = Some(config_dir);
        Ok(config)
    }

    pub(crate) fn default_machine(&self) -> Option<&str> {
        self.default_machine.as_deref()
    }

    /// The explicit system-appliance overrides to pass to the daemon.
    pub(crate) fn daemon_overrides(&self) -> eyre::Result<silod_spec::arguments::SystemOverrides> {
        self.daemon.overrides()
    }

    pub(crate) fn networking(&self) -> &RuntimeNetworkingConfig {
        &self.networking
    }

    pub(crate) fn images(&self) -> &ImageRegistryConfig {
        &self.images
    }

    pub(crate) fn tailscale(&self) -> &TailscaleConfig {
        &self.daemon.tailscale
    }

    /// Opaque, nonsecret identity for deciding whether the running daemon needs
    /// a configuration restart. CLI-only defaults and disabled integrations do
    /// not affect it. This is an equality token, not an authentication digest.
    /// Registry CA bundles contribute their resolved path and SHA-256, so a
    /// bundle replaced in place changes the identity; certificate bytes never
    /// appear in it.
    pub(crate) fn daemon_identity(&self, features: FeatureSelection) -> eyre::Result<String> {
        let system = features
            .system
            .then(|| self.daemon_overrides())
            .transpose()?;
        let tailscale = features
            .tailscale
            .then(|| self.tailscale().effective_settings());
        Ok(format!(
            "{}:{features:?}:{:?}:{:?}:{system:?}:{tailscale:?}",
            env!("CARGO_PKG_VERSION"),
            self.networking(),
            self.images()
        ))
    }

    pub(crate) fn resolve_features(
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
    pub(crate) fn persist_features(
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

    pub(crate) fn write_default_machine(default_machine: Option<&str>) -> eyre::Result<()> {
        Self::write_default_machine_from(&libvm::HostPaths::from_env()?, default_machine)
    }

    pub(crate) fn write_default_machine_from(
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
            images: ImageRegistryConfig::default(),
            daemon: DaemonConfig::default(),
        }
    }
}

/// `config_file_dir` is the directory of the config file `input` came from.
/// It is mandatory so that no caller can resolve a relative path against the
/// working directory by accident.
fn parse_global_config(input: &str, config_file_dir: &Path) -> eyre::Result<GlobalConfig> {
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

    let images = parsed
        .images
        .map(|raw| image_registries(raw, config_file_dir))
        .transpose()?
        .unwrap_or_default();

    Ok(GlobalConfig {
        default_machine,
        networking: RuntimeNetworkingConfig::default().with_netd(netd),
        images,
        daemon: parsed.daemon.unwrap_or_default(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGlobalConfig {
    default_machine: Option<String>,
    networking: Option<RawNetworkingConfig>,
    images: Option<RawImagesConfig>,
    daemon: Option<DaemonConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImagesConfig {
    default: Option<RawRegistryAction>,
    search_registries: Option<Vec<String>>,
    rules: Option<Vec<RawRegistryRule>>,
    registries: Option<RawRegistries>,
}

/// `images.registries` entries in document order. A plain map would let a
/// repeated key silently replace the earlier entry.
#[derive(Debug)]
struct RawRegistries(Vec<(String, RawRegistryTls)>);

impl<'de> Deserialize<'de> for RawRegistries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;

        impl<'de> serde::de::Visitor<'de> for Entries {
            type Value = RawRegistries;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a mapping from registry host[:port] to its TLS settings")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, RawRegistryTls>()? {
                    entries.push(entry);
                }
                Ok(RawRegistries(entries))
            }
        }

        deserializer.deserialize_map(Entries)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistryTls {
    ca: PathBuf,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawRegistryAction {
    Allow,
    Deny,
}

impl From<RawRegistryAction> for RegistryAction {
    fn from(raw: RawRegistryAction) -> Self {
        match raw {
            RawRegistryAction::Allow => Self::Allow,
            RawRegistryAction::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistryRule {
    prefix: String,
    action: RawRegistryAction,
}

fn image_registries(
    raw: RawImagesConfig,
    config_file_dir: &Path,
) -> eyre::Result<ImageRegistryConfig> {
    let defaults = RegistryPolicy::default();
    let policy = RegistryPolicy::new(
        raw.default.map_or(defaults.default_action(), Into::into),
        raw.search_registries
            .unwrap_or_else(|| defaults.search_registries().to_vec()),
        raw.rules
            .unwrap_or_default()
            .into_iter()
            .map(|rule| RegistryRule::new(rule.prefix, rule.action.into()))
            .collect(),
    )
    .map_err(|err| eyre::eyre!("[images] {err}"))?;
    let trust = registry_trust(raw.registries, config_file_dir)?;
    Ok(ImageRegistryConfig::new(policy, trust))
}

/// Loads every configured CA bundle now, so a missing or malformed file fails
/// the configuration instead of a later pull, and never degrades to system
/// trust only.
fn registry_trust(
    raw: Option<RawRegistries>,
    config_file_dir: &Path,
) -> eyre::Result<RegistryTrust> {
    let mut entries = Vec::new();
    for (key, tls) in raw.map(|registries| registries.0).unwrap_or_default() {
        let registry =
            RegistryHost::parse(&key).map_err(|err| eyre::eyre!("[images] registries: {err}"))?;
        if tls.ca.as_os_str().is_empty() {
            eyre::bail!("images.registries[{key:?}].ca: the path is empty");
        }
        // `join` leaves an absolute `ca` untouched.
        let ca = RegistryCa::load(&registry, &config_file_dir.join(&tls.ca))?;
        entries.push((registry, ca));
    }
    Ok(RegistryTrust::new(entries)?)
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
pub(crate) struct FeatureOverrides {
    pub(crate) system: Option<bool>,
    pub(crate) tailscale: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FeatureSelection {
    pub(crate) system: bool,
    pub(crate) tailscale: bool,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;
    use std::sync::{Arc, Barrier};

    use libvm::{HostPaths, RegistryAction, RegistryHost, RegistryPolicy, RegistryRule};

    use crate::config::{FeatureOverrides, GlobalConfig};

    // The self-signed P-256 test CAs of `runtime/oci/src/registry_config.rs`
    // (CN silo-unit-test-ca-a and -b, `openssl req -x509`, keys discarded).
    const CA_A: &str = "-----BEGIN CERTIFICATE-----
MIIBWDCB/qADAgECAgkA51E7pzVjJPwwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwT
c2lsby11bml0LXRlc3QtY2EtYTAgFw0yNjExMjQxMjMzNTNaGA8yMTI2MTAzMTEy
MzM1M1owHjEcMBoGA1UEAwwTc2lsby11bml0LXRlc3QtY2EtYTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABPC6Om5ZX3HCVcoTwFG8O77DJZujH3Xk67WXEYqk6o6R
28xL8W4aS05dEn5wROmgu0rOlxoX46MQMhiqdJsvHyujIzAhMA8GA1UdEwEB/wQF
MAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQCRlPs//ffA
esRds0WmZ2yHq2izrpASQ1kKF2bePi2DnQIhAOcuoJWZ0+LdF2AWSoxgLkSoMkQB
ajyKdcq+ueHF6794
-----END CERTIFICATE-----
";
    const CA_B: &str = "-----BEGIN CERTIFICATE-----
MIIBVzCB/qADAgECAgkAng1IO/2Hj5EwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwT
c2lsby11bml0LXRlc3QtY2EtYjAgFw0yNjExMjQxMjMzNTNaGA8yMTI2MTAzMTEy
MzM1M1owHjEcMBoGA1UEAwwTc2lsby11bml0LXRlc3QtY2EtYjBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABP0ehW61AU0x+IBpFr+BoaZWCzmIBm/MRINEvd2sRVr2
92F7FqYpe6ZPbj45pLZ6ZhbVUwnpnV/eWUixFTVQBxOjIzAhMA8GA1UdEwEB/wQF
MAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIF/oPDHr6afX
CSrZcUjLrxgu0J6lURVzbdRp5a8tsFNIAiEAjE7XeApDr0I/x8zYnuQ2/YOxV3AN
5hSg/yL4plUrJ6Q=
-----END CERTIFICATE-----
";

    /// Parses a document that names no files, against a directory that does
    /// not exist.
    fn parse_global_config(input: &str) -> eyre::Result<GlobalConfig> {
        crate::config::parse_global_config(input, Path::new("/nonexistent-silo-config-dir"))
    }

    fn registry(value: &str) -> RegistryHost {
        RegistryHost::parse(value).unwrap()
    }

    #[test]
    fn lobby_can_be_selected_explicitly_or_from_persisted_features() {
        for (document, tailscale) in [
            ("{}", Some(true)),
            (
                "daemon:\n  version: '1'\n  tailscale:\n    enabled: true\n",
                None,
            ),
        ] {
            let config = parse_global_config(document).unwrap();
            let selected = config.resolve_features(
                FeatureOverrides {
                    system: Some(false),
                    tailscale,
                },
                false,
            );
            assert!(selected.tailscale);
            assert!(!selected.system);
            let disabled = config.resolve_features(
                FeatureOverrides {
                    system: Some(false),
                    tailscale: Some(false),
                },
                false,
            );
            assert!(!disabled.tailscale);
        }
        assert!(
            !GlobalConfig::default()
                .resolve_features(FeatureOverrides::default(), false)
                .tailscale
        );
    }

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
        let disabled = crate::config::FeatureSelection {
            system: false,
            tailscale: false,
        };
        assert_eq!(
            baseline.daemon_identity(disabled).unwrap(),
            changed.daemon_identity(disabled).unwrap()
        );
        for enabled in [
            crate::config::FeatureSelection {
                system: true,
                tailscale: false,
            },
            crate::config::FeatureSelection {
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
        let selected = crate::config::FeatureSelection {
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

    #[test]
    fn image_policy_changes_restart_the_daemon_even_with_features_disabled() {
        let disabled = crate::config::FeatureSelection {
            system: false,
            tailscale: false,
        };
        let baseline = parse_global_config("{}").unwrap();
        let denied = parse_global_config("images:\n  default: deny\n").unwrap();
        assert_ne!(
            baseline.daemon_identity(disabled).unwrap(),
            denied.daemon_identity(disabled).unwrap()
        );
    }

    #[test]
    fn images_section_maps_to_the_registry_policy() {
        let config = parse_global_config(concat!(
            "images:\n",
            "  default: deny\n",
            "  search_registries: [ghcr.io, docker.io]\n",
            "  rules:\n",
            "    - {prefix: docker.io, action: allow}\n",
            "    - {prefix: ghcr.io/vandycknick, action: allow}\n",
            "    - {prefix: localhost, action: deny}\n",
        ))
        .unwrap();
        assert_eq!(
            config.images().policy(),
            &RegistryPolicy::new(
                RegistryAction::Deny,
                vec!["ghcr.io".into(), "docker.io".into()],
                vec![
                    RegistryRule::new("docker.io", RegistryAction::Allow),
                    RegistryRule::new("ghcr.io/vandycknick", RegistryAction::Allow),
                    RegistryRule::new("localhost", RegistryAction::Deny),
                ],
            )
            .unwrap()
        );
        assert_eq!(
            parse_global_config("images: {}\n")
                .unwrap()
                .images()
                .policy(),
            &RegistryPolicy::default()
        );
        assert_eq!(
            parse_global_config("{}").unwrap().images().policy(),
            &RegistryPolicy::default()
        );
    }

    #[test]
    fn images_section_rejects_unknown_keys_and_invalid_rules() {
        for raw in [
            "images: {unknown: 1}\n",
            "images: {default: maybe}\n",
            "images: {rules: [{prefix: docker.io}]}\n",
            "images: {rules: [{prefix: docker.io, action: allow, extra: 1}]}\n",
            "daemon: {version: '1', tailscale: {vm: {allowed-registries: [x]}}}\n",
        ] {
            assert!(parse_global_config(raw).is_err(), "{raw}");
        }
        let err = parse_global_config("images: {rules: [{prefix: nixos/nix, action: allow}]}\n")
            .expect_err("prefix without registry host");
        assert_eq!(
            err.to_string(),
            "[images] invalid registry policy: rule prefix \"nixos/nix\" must start with a registry host, e.g. docker.io or ghcr.io/org"
        );
    }

    fn fixture() -> (tempfile::TempDir, HostPaths) {
        let temp = tempfile::tempdir().unwrap();
        let host = HostPaths::new(temp.path().join("home"), temp.path().join("config"));
        (temp, host)
    }
    fn load(yaml: &str) -> eyre::Result<GlobalConfig> {
        let (_temp, host) = fixture();
        fs::create_dir_all(host.config_dir())?;
        fs::write(host.config_file(), yaml)?;
        GlobalConfig::load_from(&host)
    }
    #[test]
    fn missing_config_has_resolved_defaults_without_side_effects() {
        let (_temp, host) = fixture();
        let config = GlobalConfig::load_from(&host).unwrap();
        assert!(!host.home().exists());
        assert!(!host.config_dir().exists());
        let features = config.resolve_features(FeatureOverrides::default(), false);
        assert_eq!(features.system, cfg!(target_os = "macos"));
        assert!(!features.tailscale);
        assert!(
            config
                .resolve_features(FeatureOverrides::default(), true)
                .system
        );
        assert_eq!(config.images(), &libvm::ImageRegistryConfig::default());
    }
    #[test]
    fn strict_validation_rejects_unknown_fields_units_and_limits() {
        for settings in [
            "capability: anything",
            "home: /tmp",
            "enrollment: {mode: unknown}",
            "hostname: Upper",
            "tag: user:1",
            "disk-reserve: 1.5GiB",
            "disk-reserve: 18446744073709551615TiB",
            "sessions: {per-peer: 65}",
            "sessions: {global: 0}",
            "vm: {ceilings: {cpus: 256}}",
            "vm: {defaults: {cpus: 9}}",
            "vm: {defaults: {memory: 33GiB}}",
            "vm: {defaults: {disk: 0}}",
            "vm: {ceilings: {vms-per-principal: 0}}",
            "vm: {guest-user: root}",
            "vm: {default-image: registry.example.test/image:latest}",
        ] {
            assert!(
                load(&format!(
                    "daemon:\n  version: '1'\n  tailscale:\n    {settings}\n"
                ))
                .is_err(),
                "accepted {settings}"
            );
        }
        for yaml in [
            "daemon: {version: '2'}",
            "daemon: {}",
            "daemon: {version: '1', system: {resources: {cpus: 0}}}",
            "daemon: {version: '1', system: {resources: {memory: nonsense}}}",
            "{}\n---\n{}",
        ] {
            assert!(load(yaml).is_err(), "accepted {yaml}");
        }
        for mode in ["oauth-app", "interactive", "none"] {
            assert!(load(&format!(
                "daemon: {{version: '1', tailscale: {{enrollment: {{mode: {mode}}}}}}}"
            ))
            .is_ok());
        }
    }
    #[test]
    fn feature_writes_preserve_settings_and_omission_preserves_selection() {
        let (_temp, host) = fixture();
        fs::create_dir_all(host.config_dir()).unwrap();
        fs::write(host.config_file(), "default_machine: old\nnetworking:\n  drivers:\n    netd:\n      pcap: true\ndaemon:\n  version: '1'\n  system:\n    resources: {cpus: 2}\n  tailscale:\n    hostname: chosen\n").unwrap();
        let selected = GlobalConfig::persist_features(
            &host,
            FeatureOverrides {
                system: Some(false),
                tailscale: Some(true),
            },
            true,
        )
        .unwrap();
        assert!(!selected.system);
        assert!(selected.tailscale);
        let config = GlobalConfig::load_from(&host).unwrap();
        assert_eq!(config.default_machine(), Some("old"));
        assert!(config.networking().netd.pcap);
        assert_eq!(config.daemon_overrides().unwrap().cpus, Some(2));
        assert_eq!(config.tailscale().hostname(), "chosen");
        assert_eq!(
            GlobalConfig::persist_features(&host, FeatureOverrides::default(), true).unwrap(),
            selected
        );
        GlobalConfig::write_default_machine_from(&host, None).unwrap();
        assert_eq!(
            GlobalConfig::load_from(&host).unwrap().default_machine(),
            None
        );
    }
    #[test]
    fn concurrent_default_and_feature_transactions_keep_both() {
        let (_temp, host) = fixture();
        let barrier = Arc::new(Barrier::new(3));
        std::thread::scope(|scope| {
            let b = barrier.clone();
            let h = host.clone();
            scope.spawn(move || {
                b.wait();
                GlobalConfig::write_default_machine_from(&h, Some("concurrent")).unwrap();
            });
            let b = barrier.clone();
            let h = host.clone();
            scope.spawn(move || {
                b.wait();
                GlobalConfig::persist_features(
                    &h,
                    FeatureOverrides {
                        system: Some(false),
                        tailscale: Some(true),
                    },
                    false,
                )
                .unwrap();
            });
            barrier.wait();
        });
        let config = GlobalConfig::load_from(&host).unwrap();
        assert_eq!(config.default_machine(), Some("concurrent"));
        let features = config.resolve_features(FeatureOverrides::default(), false);
        assert!(features.tailscale);
        assert!(!features.system);
    }
    #[test]
    fn malformed_existing_config_is_never_replaced() {
        for raw in [
            "daemon: {version: '2'}",
            "daemon: {version: '1', tailscale: {unknown: true}}",
            "networking: {drivers: {netd: {tls_ca_cert: /cert}}}",
            "[broken",
            "default_machine: ''",
        ] {
            let (_temp, host) = fixture();
            fs::create_dir_all(host.config_dir()).unwrap();
            fs::write(host.config_file(), raw).unwrap();
            assert!(GlobalConfig::persist_features(
                &host,
                FeatureOverrides {
                    system: None,
                    tailscale: Some(true)
                },
                false
            )
            .is_err());
            assert!(GlobalConfig::write_default_machine_from(&host, Some("new")).is_err());
            assert_eq!(fs::read_to_string(host.config_file()).unwrap(), raw);
        }
    }
    #[test]
    fn unsafe_config_and_lock_leaves_fail_without_following_or_blocking() {
        let (temp, host) = fixture();
        fs::create_dir_all(host.config_dir()).unwrap();
        let target = temp.path().join("target");
        fs::write(&target, "{}\n").unwrap();
        symlink(&target, host.config_file()).unwrap();
        assert!(GlobalConfig::load_from(&host).is_err());
        assert!(GlobalConfig::write_default_machine_from(&host, Some("new")).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "{}\n");
        fs::remove_file(host.config_file()).unwrap();
        symlink(
            temp.path().join("missing"),
            host.config_dir().join("config.yaml"),
        )
        .unwrap();
        assert!(GlobalConfig::load_from(&host).is_err());
        fs::remove_file(host.config_dir().join("config.yaml")).unwrap();
        nix::unistd::mkfifo(
            &host.config_file(),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(GlobalConfig::load_from(&host).is_err());
        assert!(GlobalConfig::write_default_machine_from(&host, Some("new")).is_err());
        fs::remove_file(host.config_file()).unwrap();
        fs::write(host.config_file(), "{}").unwrap();
        fs::set_permissions(host.config_file(), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(GlobalConfig::load_from(&host).is_err());
        fs::set_permissions(host.config_file(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(host.config_dir().join("config.yaml.lock")).unwrap();
        symlink(&target, host.config_dir().join("config.yaml.lock")).unwrap();
        assert!(GlobalConfig::write_default_machine_from(&host, Some("new")).is_err());
    }
    #[test]
    fn legacy_fallback_is_updated_in_place() {
        let (_temp, host) = fixture();
        fs::create_dir_all(host.home()).unwrap();
        fs::write(host.home().join("config.yaml"), "default_machine: legacy").unwrap();
        GlobalConfig::persist_features(&host, FeatureOverrides::default(), true).unwrap();
        assert!(!host.config_dir().join("config.yaml").exists());
        let config = GlobalConfig::load_from(&host).unwrap();
        assert_eq!(config.default_machine(), Some("legacy"));
        assert!(
            config
                .resolve_features(FeatureOverrides::default(), false)
                .system
        );
    }
    #[test]
    fn canonical_roots_leave_optional_documents_absent_and_refuse_unsafe_roots() {
        let (temp, host) = fixture();
        let canonical = crate::config::prepare_host_paths(&host).unwrap();
        assert_eq!(canonical.home(), fs::canonicalize(host.home()).unwrap());
        assert!(!canonical.config_dir().join("templates").exists());
        assert!(!canonical.config_dir().join("policies").exists());
        fs::set_permissions(host.home(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(crate::config::prepare_host_paths(&host).is_err());
        let alias = temp.path().join("alias");
        symlink(host.config_dir(), &alias).unwrap();
        assert!(
            crate::config::prepare_host_paths(&HostPaths::new(alias, host.config_dir())).is_err()
        );
    }

    #[test]
    fn registry_ca_paths_resolve_against_the_selected_config_file() {
        let (temp, host) = fixture();
        let absolute = temp.path().join("elsewhere.pem");
        fs::write(&absolute, CA_B).unwrap();
        fs::create_dir_all(host.config_dir().join("certs")).unwrap();
        fs::write(host.config_dir().join("certs/ca.pem"), CA_A).unwrap();
        fs::write(
            host.config_file(),
            format!(
                concat!(
                    "images:\n",
                    "  default: deny\n",
                    "  registries:\n",
                    "    \"localhost:5443\":\n",
                    "      ca: certs/ca.pem\n",
                    "    \"REGISTRY.example:443\":\n",
                    "      ca: {}\n",
                ),
                absolute.display()
            ),
        )
        .unwrap();
        let config = GlobalConfig::load_from(&host).unwrap();
        let trust = config.images().trust();
        assert_eq!(trust.iter().count(), 2);
        assert_eq!(
            trust.get(&registry("localhost:5443")).unwrap().path(),
            host.config_dir().join("certs/ca.pem")
        );
        assert_eq!(
            trust.get(&registry("registry.example")).unwrap().path(),
            absolute
        );
        assert_eq!(
            config.images().policy(),
            &RegistryPolicy::new(RegistryAction::Deny, vec!["docker.io".into()], Vec::new())
                .unwrap()
        );

        for (ca, resolved) in [
            ("missing.pem", host.config_dir().join("missing.pem")),
            ("certs", host.config_dir().join("certs")),
        ] {
            fs::write(
                host.config_file(),
                format!("images:\n  registries:\n    \"localhost:5443\": {{ca: {ca}}}\n"),
            )
            .unwrap();
            let error = format!("{:#}", GlobalConfig::load_from(&host).unwrap_err());
            assert!(
                error.contains(&format!(
                    "images.registries[\"localhost:5443\"].ca: cannot read {}: ",
                    resolved.display()
                )),
                "{error}"
            );
        }

        let (_temp, legacy) = fixture();
        fs::create_dir_all(legacy.home()).unwrap();
        fs::write(legacy.home().join("ca.pem"), CA_A).unwrap();
        fs::write(
            legacy.home().join("config.yaml"),
            "images: {registries: {localhost: {ca: ca.pem}}}\n",
        )
        .unwrap();
        let config = GlobalConfig::load_from(&legacy).unwrap();
        assert_eq!(
            config
                .images()
                .trust()
                .get(&registry("localhost"))
                .unwrap()
                .path(),
            legacy.home().join("ca.pem")
        );
    }

    #[test]
    fn registry_ca_bundles_without_certificates_fail_the_config_load() {
        let (_temp, host) = fixture();
        fs::create_dir_all(host.config_dir()).unwrap();
        fs::write(
            host.config_file(),
            "images:\n  registries:\n    \"localhost:5443\":\n      ca: ca.pem\n",
        )
        .unwrap();
        let ca = host.config_dir().join("ca.pem");
        let truncated = &CA_A[..CA_A.len() / 2];
        for (bundle, problem) in [
            ("", "contains no PEM certificates"),
            ("no certificate in here\n", "contains no PEM certificates"),
            (truncated, "invalid PEM certificate bundle"),
        ] {
            fs::write(&ca, bundle).unwrap();
            let error = format!("{:#}", GlobalConfig::load_from(&host).unwrap_err());
            assert!(
                error.contains("images.registries[\"localhost:5443\"].ca: "),
                "{error}"
            );
            assert!(error.contains(&ca.display().to_string()), "{error}");
            assert!(error.contains(problem), "{error}");
        }
        fs::write(&ca, format!("{CA_A}{CA_B}")).unwrap();
        assert!(GlobalConfig::load_from(&host).is_ok());
    }

    #[test]
    fn registries_section_is_strict_about_fields_keys_and_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("ca.pem"), CA_A).unwrap();
        let parse = |registries: &str| {
            crate::config::parse_global_config(
                &format!("images:\n  registries: {registries}\n"),
                temp.path(),
            )
        };
        for accepted in [
            "{}",
            "{\"localhost:5443\": {ca: ca.pem}}",
            "{\"localhost:5443\": {ca: ca.pem}, \"localhost:5444\": {ca: ca.pem}}",
            "{registry.example: {ca: ca.pem}, sub.registry.example: {ca: ca.pem}}",
        ] {
            assert!(parse(accepted).is_ok(), "rejected {accepted}");
        }
        for rejected in [
            "{\"localhost:5443\": {ca: ca.pem, insecure: true}}",
            "{\"localhost:5443\": {}}",
            "{\"localhost:5443\": {ca: [ca.pem]}}",
            "{\"localhost:5443\": {ca: ''}}",
            "{\"localhost:5443\": ca.pem}",
            "[\"localhost:5443\"]",
            "{\"https://localhost:5443\": {ca: ca.pem}}",
            "{\"localhost:5443/team\": {ca: ca.pem}}",
            "{\"user@localhost\": {ca: ca.pem}}",
            "{\"*.example\": {ca: ca.pem}}",
            "{\" localhost\": {ca: ca.pem}}",
            "{\"\": {ca: ca.pem}}",
            "{\"localhost:\": {ca: ca.pem}}",
            "{\"localhost:0\": {ca: ca.pem}}",
            "{\"localhost:5443\": {ca: ca.pem}, \"localhost:5443\": {ca: ca.pem}}",
            "{\"registry.example\": {ca: ca.pem}, \"registry.example:443\": {ca: ca.pem}}",
            "{\"registry.example\": {ca: ca.pem}, \"REGISTRY.example\": {ca: ca.pem}}",
            "{\"docker.io\": {ca: ca.pem}, \"index.docker.io\": {ca: ca.pem}}",
        ] {
            assert!(parse(rejected).is_err(), "accepted {rejected}");
        }
        let duplicate =
            parse("{\"registry.example\": {ca: ca.pem}, \"registry.example:443\": {ca: ca.pem}}")
                .unwrap_err();
        assert_eq!(
            duplicate.to_string(),
            "images.registries has more than one entry for registry \"registry.example\""
        );
        let scheme = parse("{\"https://localhost:5443\": {ca: ca.pem}}").unwrap_err();
        assert!(
            scheme.to_string().starts_with(
                "[images] registries: invalid registry host \"https://localhost:5443\""
            ),
            "{scheme}"
        );
    }

    #[test]
    fn unrelated_config_edits_keep_registry_entries_and_their_relative_paths() {
        for legacy in [false, true] {
            let (_temp, host) = fixture();
            let directory = if legacy {
                host.home().to_path_buf()
            } else {
                host.config_dir().to_path_buf()
            };
            fs::create_dir_all(&directory).unwrap();
            let ca = directory.join("ca.pem");
            let file = directory.join("config.yaml");
            fs::write(&ca, CA_A).unwrap();
            fs::write(
                &file,
                "images:\n  default: deny\n  registries:\n    \"localhost:5443\":\n      ca: ca.pem\n",
            )
            .unwrap();
            let before = GlobalConfig::load_from(&host).unwrap();
            assert_eq!(
                before
                    .images()
                    .trust()
                    .get(&registry("localhost:5443"))
                    .unwrap()
                    .path(),
                ca
            );

            GlobalConfig::write_default_machine_from(&host, Some("dev")).unwrap();
            GlobalConfig::persist_features(
                &host,
                FeatureOverrides {
                    system: Some(false),
                    tailscale: Some(true),
                },
                false,
            )
            .unwrap();
            let after = GlobalConfig::load_from(&host).unwrap();
            assert_eq!(after.default_machine(), Some("dev"));
            assert_eq!(after.images(), before.images());
            let raw = fs::read_to_string(&file).unwrap();
            assert!(raw.contains("ca: ca.pem"), "{raw}");

            // A broken bundle fails the edit and leaves the document alone.
            fs::write(&ca, "").unwrap();
            assert!(GlobalConfig::write_default_machine_from(&host, Some("other")).is_err());
            assert_eq!(fs::read_to_string(&file).unwrap(), raw);
        }
    }

    #[test]
    fn replacing_a_registry_ca_in_place_changes_the_daemon_identity_without_printing_it() {
        let (_temp, host) = fixture();
        fs::create_dir_all(host.config_dir()).unwrap();
        let ca = host.config_dir().join("ca.pem");
        fs::write(
            host.config_file(),
            "images:\n  registries:\n    \"localhost:5443\":\n      ca: ca.pem\n",
        )
        .unwrap();
        let disabled = crate::config::FeatureSelection {
            system: false,
            tailscale: false,
        };
        let load = |bundle: &str| {
            fs::write(&ca, bundle).unwrap();
            GlobalConfig::load_from(&host).unwrap()
        };
        let first = load(CA_A);
        let rotated = load(CA_B);
        let restored = load(CA_A);
        let first_identity = first.daemon_identity(disabled).unwrap();
        let rotated_identity = rotated.daemon_identity(disabled).unwrap();
        assert_ne!(first_identity, rotated_identity);
        assert_ne!(first, rotated);
        assert_eq!(first_identity, restored.daemon_identity(disabled).unwrap());
        assert_eq!(first, restored);

        fs::write(host.config_file(), "{}\n").unwrap();
        let without = GlobalConfig::load_from(&host).unwrap();
        assert_ne!(first_identity, without.daemon_identity(disabled).unwrap());

        assert!(
            first_identity.contains("localhost:5443"),
            "{first_identity}"
        );
        assert!(first_identity.contains("sha256:"), "{first_identity}");
        assert!(
            first_identity.contains(&ca.display().to_string()),
            "{first_identity}"
        );
        for text in [
            first_identity,
            rotated_identity,
            format!("{first:?}"),
            format!("{rotated:?}"),
        ] {
            for pem in ["BEGIN CERTIFICATE", "MIIBWDCB", "MIIBVzCB"] {
                assert!(!text.contains(pem), "{text}");
            }
        }
    }
}
