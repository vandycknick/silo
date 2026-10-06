use libvm::HostPaths;
use silo_config::tailscale::EnrollmentMode;
use silo_config::{FeatureOverrides, GlobalConfig};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::{Arc, Barrier};

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
    assert_eq!(c.capability(), "github.com/vandycknick/silo/cap/taild");
    assert_eq!(c.control_url(), "");
    assert_eq!(c.enrollment_mode(), EnrollmentMode::OauthApp);
    assert!(!c.disable_key_expiry());
    assert_eq!(
        c.vm().default_image(),
        "ghcr.io/vandycknick/silo/devbox:latest"
    );
    assert_eq!(c.vm().allowed_registries(), &["ghcr.io/vandycknick"]);
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
    let canonical = silo_config::prepare_host_paths(&host).unwrap();
    assert_eq!(canonical.home(), fs::canonicalize(host.home()).unwrap());
    assert!(!canonical.config_dir().join("templates").exists());
    assert!(!canonical.config_dir().join("policies").exists());
    fs::set_permissions(host.home(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(silo_config::prepare_host_paths(&host).is_err());
    let alias = temp.path().join("alias");
    symlink(host.config_dir(), &alias).unwrap();
    assert!(silo_config::prepare_host_paths(&HostPaths::new(alias, host.config_dir())).is_err());
}
