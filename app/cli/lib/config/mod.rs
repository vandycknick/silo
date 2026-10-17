use std::path::PathBuf;

use eyre::Context as _;
use libvm::{
    NetdRuntimeConfig, RegistryAction, RegistryPolicy, RegistryRule, RuntimeNetworkingConfig,
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
    images: RegistryPolicy,
    daemon: DaemonConfig,
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

    pub(crate) fn images(&self) -> &RegistryPolicy {
        &self.images
    }

    pub(crate) fn tailscale(&self) -> &TailscaleConfig {
        &self.daemon.tailscale
    }

    /// Opaque, nonsecret identity for deciding whether the running daemon needs
    /// a configuration restart. CLI-only defaults and disabled integrations do
    /// not affect it. This is an equality token, not an authentication digest.
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
            images: RegistryPolicy::default(),
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

    let images = parsed
        .images
        .map(registry_policy)
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

fn registry_policy(raw: RawImagesConfig) -> eyre::Result<RegistryPolicy> {
    let defaults = RegistryPolicy::default();
    RegistryPolicy::new(
        raw.default.map_or(defaults.default_action(), Into::into),
        raw.search_registries
            .unwrap_or_else(|| defaults.search_registries().to_vec()),
        raw.rules
            .unwrap_or_default()
            .into_iter()
            .map(|rule| RegistryRule::new(rule.prefix, rule.action.into()))
            .collect(),
    )
    .map_err(|err| eyre::eyre!("[images] {err}"))
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
    use std::sync::{Arc, Barrier};

    use libvm::{HostPaths, RegistryAction, RegistryPolicy, RegistryRule};

    use crate::config::tailscale::EnrollmentMode;
    use crate::config::{parse_global_config, FeatureOverrides, GlobalConfig};

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
            config.images(),
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
            parse_global_config("images: {}\n").unwrap().images(),
            &RegistryPolicy::default()
        );
        assert_eq!(
            parse_global_config("{}").unwrap().images(),
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
        let c = config.tailscale();
        assert_eq!(c.hostname(), "silo");
        assert_eq!(c.tag(), "tag:silo");
        assert_eq!(c.control_url(), "");
        assert_eq!(c.enrollment_mode(), EnrollmentMode::OauthApp);
        assert!(!c.disable_key_expiry());
        assert_eq!(config.images(), &libvm::RegistryPolicy::default());
        assert_eq!(c.vm().defaults().cpus(), 2);
        assert_eq!(c.vm().defaults().memory(), 4 << 30);
        assert_eq!(c.vm().defaults().disk(), 20 << 30);
        assert_eq!(c.vm().ceilings().cpus(), 8);
        assert_eq!(c.vm().ceilings().memory(), 32 << 30);
        assert_eq!(c.vm().ceilings().disk(), 200 << 30);
        assert_eq!(c.vm().ceilings().vms_per_principal(), 5);
        assert_eq!(c.sessions().global(), 64);
        assert_eq!(c.sessions().per_peer(), 8);
        assert_eq!(c.disk_reserve(), 1 << 30);
        assert_eq!(
            c.shutdown().stop_budget(),
            std::time::Duration::from_secs(4)
        );
        assert_eq!(c.shutdown().margin(), std::time::Duration::from_millis(250));
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
            "shutdown: {margin: 250}",
            "shutdown: {stop-budget: 61s}",
            "shutdown: {margin: 0s}",
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
            assert!(load(&format!("daemon: {{version: '1', tailscale: {{enrollment: {{mode: {mode}}}, shutdown: {{stop-budget: 1m, margin: 0.25s}}}}}}" )).is_ok());
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
}
