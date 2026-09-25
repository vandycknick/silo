use std::env::consts::OS;
use std::path::{Component, Path, PathBuf};

use crate::paths::{default_run_root, ensure_run_root, resolve_default_home, LocalRoots};
use crate::store::models::DbConfig;
use crate::LibVmError;

/// Local runtime configuration.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RuntimeConfig {
    /// Silo home holding all persistent state. `None` resolves `SILO_HOME`,
    /// else `~/.silo`. Generated sockets, pidfiles and locks always live under
    /// `/tmp/silo-<euid>`.
    pub home: Option<PathBuf>,
    /// Networking configuration for locally started machines.
    pub networking: RuntimeNetworkingConfig,
    /// Explicit silo-vmm executable path.
    pub supervisor_path: Option<PathBuf>,
    /// Explicit netd executable path.
    pub netd_path: Option<PathBuf>,
    /// Explicit default kernel path.
    pub kernel_path: Option<PathBuf>,
    /// Explicit default initramfs path.
    pub initramfs_path: Option<PathBuf>,
    /// Explicit default guest agent path.
    pub agent_path: Option<PathBuf>,
    /// Explicit portable runtime root.
    pub runtime_root: Option<PathBuf>,
    /// Portable runtime root bundled by an SDK frontend.
    pub bundled_runtime_root: Option<PathBuf>,
    /// Explicit override of silo-vmm's virtualization backend.
    pub virt_backend: Option<VirtBackendOverride>,
}

/// Explicit override of silo-vmm's virtualization backend.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VirtBackendOverride {
    /// libkrun in silo-vmm's private worker process.
    Krun,
    /// Apple Virtualization.framework.
    Vz,
    /// silo-vmm's in-process mock backend: no real VM runs, the guest side is
    /// faked in-process. `scenario` is an absolute path to a scenario file
    /// scripting the mock's behavior; absent means the happy path.
    Mock { scenario: Option<PathBuf> },
}

impl RuntimeConfig {
    /// Creates a local runtime configuration with an explicit Silo home.
    pub fn local(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
            ..Self::default()
        }
    }

    /// Creates the default local runtime configuration from the environment.
    pub fn from_env() -> Result<Self, LibVmError> {
        let _ = resolve_default_home()?;
        Ok(Self {
            virt_backend: VirtBackendOverride::from_env()?,
            ..Self::default()
        })
    }

    /// Sets local runtime networking configuration.
    pub fn with_networking(mut self, networking: RuntimeNetworkingConfig) -> Self {
        self.networking = networking;
        self
    }

    /// Sets the silo-vmm executable path used to launch machines.
    pub fn with_supervisor_path(mut self, supervisor_path: impl Into<PathBuf>) -> Self {
        self.supervisor_path = Some(supervisor_path.into());
        self
    }

    /// Sets the netd executable path used for userspace networking.
    pub fn with_netd_path(mut self, netd_path: impl Into<PathBuf>) -> Self {
        self.netd_path = Some(netd_path.into());
        self
    }

    /// Selects the virtualization backend used for machines started by this runtime.
    pub fn with_virt_backend(mut self, backend: VirtBackendOverride) -> Self {
        self.virt_backend = Some(backend);
        self
    }

    /// Sets the default kernel path.
    pub fn with_kernel_path(mut self, kernel_path: impl Into<PathBuf>) -> Self {
        self.kernel_path = Some(kernel_path.into());
        self
    }

    /// Sets the default initramfs path.
    pub fn with_initramfs_path(mut self, initramfs_path: impl Into<PathBuf>) -> Self {
        self.initramfs_path = Some(initramfs_path.into());
        self
    }

    /// Sets the default guest agent path.
    pub fn with_agent_path(mut self, agent_path: impl Into<PathBuf>) -> Self {
        self.agent_path = Some(agent_path.into());
        self
    }

    /// Sets an explicit portable runtime root.
    pub fn with_runtime_root(mut self, runtime_root: impl Into<PathBuf>) -> Self {
        self.runtime_root = Some(runtime_root.into());
        self
    }

    /// Sets a portable runtime root bundled by an SDK frontend.
    pub fn with_bundled_runtime_root(mut self, bundled_runtime_root: impl Into<PathBuf>) -> Self {
        self.bundled_runtime_root = Some(bundled_runtime_root.into());
        self
    }

    /// Testing only: run machines on silo-vmm's mock virtualization backend.
    ///
    /// `scenario` is an absolute path to a mock scenario file (see the
    /// `test-utils` crate, which also builds a mock-enabled silo-vmm binary to
    /// pass to [`RuntimeConfig::with_supervisor_path`]). No real VM will run.
    pub fn with_mock_vmm(mut self, scenario: impl Into<PathBuf>) -> Self {
        self.virt_backend = Some(VirtBackendOverride::Mock {
            scenario: Some(scenario.into()),
        });
        self
    }

    /// The Silo home, without creating anything.
    pub(crate) fn resolve_home(&self) -> Result<PathBuf, LibVmError> {
        let home = match &self.home {
            Some(home) => home.clone(),
            None => resolve_default_home()?,
        };
        validate_absolute_path("home", &home)?;
        Ok(home)
    }

    /// Both runtime roots; creates and validates the run root.
    pub(crate) fn resolve_roots(&self) -> Result<LocalRoots, LibVmError> {
        let run_root = default_run_root();
        ensure_run_root(&run_root)?;
        Ok(LocalRoots::with_roots(self.resolve_home()?, run_root))
    }
}

impl VirtBackendOverride {
    /// Reads the developer backend override from `SILO_VIRT_BACKEND`.
    pub fn from_env() -> Result<Option<Self>, LibVmError> {
        Self::from_env_value(std::env::var_os("SILO_VIRT_BACKEND"))
    }

    fn from_env_value(value: Option<std::ffi::OsString>) -> Result<Option<Self>, LibVmError> {
        let Some(value) = value else {
            return Ok(None);
        };
        let value = value
            .into_string()
            .map_err(|_| LibVmError::InvalidVirtBackendOverride {
                value: "<non-UTF-8>".to_string(),
            })?;
        Self::parse_selection(&value).map(Some)
    }

    fn parse_selection(value: &str) -> Result<Self, LibVmError> {
        match value {
            "krun" => Ok(Self::Krun),
            "vz" => Ok(Self::Vz),
            _ => Err(LibVmError::InvalidVirtBackendOverride {
                value: value.to_string(),
            }),
        }
    }
}

/// A state database only opens on the host OS that created it.
pub(crate) fn validate_db_config(config: &DbConfig) -> Result<(), LibVmError> {
    compare_str("os", OS, &config.os)
}

fn validate_absolute_path(field: &'static str, path: &Path) -> Result<(), LibVmError> {
    if path.is_absolute() {
        return Ok(());
    }

    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: "absolute path".to_string(),
        actual: path_to_db_string(path),
    })
}

fn compare_str(field: &'static str, expected: &str, actual: &str) -> Result<(), LibVmError> {
    if expected == actual {
        return Ok(());
    }
    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

pub(crate) fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn path_to_db_string(path: &Path) -> String {
    path.display().to_string()
}

/// Networking configuration for the local runtime.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct RuntimeNetworkingConfig {
    /// Directory containing network policy configuration files.
    pub policy_config_dir: Option<PathBuf>,
    /// netd-specific runtime configuration.
    pub netd: NetdRuntimeConfig,
}

impl RuntimeNetworkingConfig {
    /// Creates runtime networking config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the directory containing policy files.
    pub fn with_policy_config_dir(mut self, policy_config_dir: impl Into<PathBuf>) -> Self {
        self.policy_config_dir = Some(policy_config_dir.into());
        self
    }

    /// Sets netd-specific defaults.
    pub fn with_netd(mut self, netd: NetdRuntimeConfig) -> Self {
        self.netd = netd;
        self
    }
}

/// Configuration for the netd network driver.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetdRuntimeConfig {
    /// Subnet used for managed private networks.
    pub subnet: String,
    /// Whether packet capture should be enabled.
    pub pcap: bool,
    /// Optional TLS CA certificate path.
    pub tls_ca_cert: Option<PathBuf>,
    /// Optional TLS CA key path.
    pub tls_ca_key: Option<PathBuf>,
}

impl Default for NetdRuntimeConfig {
    fn default() -> Self {
        Self {
            subnet: "192.168.105.0/24".to_string(),
            pcap: false,
            tls_ca_cert: None,
            tls_ca_key: None,
        }
    }
}

impl NetdRuntimeConfig {
    /// Creates netd config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the subnet used for managed private networks.
    pub fn with_subnet(mut self, subnet: impl Into<String>) -> Self {
        self.subnet = subnet.into();
        self
    }

    /// Enables or disables packet capture.
    pub fn with_pcap(mut self, pcap: bool) -> Self {
        self.pcap = pcap;
        self
    }

    /// Sets both TLS CA paths.
    pub fn with_tls_ca(mut self, cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        self.tls_ca_cert = Some(cert.into());
        self.tls_ca_key = Some(key.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::store::models::MachineId;
    use crate::store::Store;
    use crate::{LibVmError, Runtime, RuntimeConfig, VirtBackendOverride};

    #[test]
    fn backend_override_is_typed() {
        let config = RuntimeConfig::default().with_virt_backend(VirtBackendOverride::Krun);
        assert_eq!(config.virt_backend, Some(VirtBackendOverride::Krun));
    }

    #[test]
    fn backend_override_parser_accepts_only_real_cli_backends() {
        assert_eq!(
            VirtBackendOverride::parse_selection("krun").expect("parse krun"),
            VirtBackendOverride::Krun
        );
        assert_eq!(
            VirtBackendOverride::parse_selection("vz").expect("parse VZ"),
            VirtBackendOverride::Vz
        );
        assert!(VirtBackendOverride::parse_selection("mock").is_err());
        assert!(VirtBackendOverride::parse_selection("").is_err());
    }

    #[test]
    fn backend_override_environment_input_is_strict_without_global_mutation() {
        assert_eq!(
            VirtBackendOverride::from_env_value(Some("krun".into())).expect("parse krun"),
            Some(VirtBackendOverride::Krun)
        );
        assert_eq!(
            VirtBackendOverride::from_env_value(Some("vz".into())).expect("parse vz"),
            Some(VirtBackendOverride::Vz)
        );
        assert!(VirtBackendOverride::from_env_value(Some("mock".into())).is_err());
        assert!(VirtBackendOverride::from_env_value(Some("KRUN".into())).is_err());
        assert_eq!(
            VirtBackendOverride::from_env_value(None).expect("absent override"),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn backend_override_rejects_non_utf8_environment_input() {
        use std::os::unix::ffi::OsStringExt as _;

        let error =
            VirtBackendOverride::from_env_value(Some(std::ffi::OsString::from_vec(vec![0xff])))
                .expect_err("reject non-UTF-8 override");
        assert!(matches!(
            error,
            LibVmError::InvalidVirtBackendOverride { ref value } if value == "<non-UTF-8>"
        ));
    }

    fn complete_runtime_root(base: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let root = base.join("runtime-components");
        for name in ["silo-vmm", "netd", "krun"] {
            let path = root.join("bin").join(name);
            std::fs::create_dir_all(path.parent().expect("helper parent"))
                .expect("create helper parent");
            std::fs::write(&path, b"helper").expect("write helper");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("set helper mode");
        }
        for (name, mode) in [
            ("kernel-default", 0o644),
            ("initramfs", 0o644),
            ("agent", 0o755),
        ] {
            let path = root.join("assets").join(name);
            std::fs::create_dir_all(path.parent().expect("asset parent"))
                .expect("create asset parent");
            std::fs::write(&path, b"asset").expect("write asset");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set asset mode");
        }
        root
    }

    #[test]
    fn explicit_home_must_be_absolute() {
        let err = RuntimeConfig::local("relative-silo")
            .resolve_home()
            .expect_err("relative home should fail");

        assert!(matches!(
            err,
            LibVmError::StateDatabaseConfigMismatch { field: "home", .. }
        ));
    }

    #[test]
    fn db_config_rejects_a_database_from_another_os() {
        let foreign = crate::store::models::DbConfig {
            os: "plan9".to_string(),
        };
        assert!(matches!(
            crate::runtime::config::validate_db_config(&foreign),
            Err(LibVmError::StateDatabaseConfigMismatch { field: "os", .. })
        ));
        crate::runtime::config::validate_db_config(&crate::store::models::DbConfig::current())
            .expect("current host database");
    }

    #[tokio::test]
    async fn runtime_keeps_state_in_home_and_generated_state_in_the_fixed_run_root() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let home = temp.path().join("home");
        let runtime_root = complete_runtime_root(temp.path());
        let config = RuntimeConfig::local(&home).with_runtime_root(&runtime_root);

        let runtime = Runtime::new(config.clone())
            .await
            .expect("open fresh runtime");
        let machine_id = MachineId::new();
        let machine = runtime.local_paths().machine(machine_id);
        let run_root = crate::paths::default_run_root();
        assert_eq!(runtime.local_home(), home);
        assert!(home.join("state.db").is_file());
        assert_eq!(runtime.local_paths().roots().run_root(), run_root);
        assert_eq!(
            machine.machine_data_dir(),
            home.join("machines").join(machine_id.to_string())
        );
        assert_eq!(
            machine.machine_logs_dir(),
            home.join("logs/machines").join(machine_id.to_string())
        );
        assert_eq!(
            machine.machine_run_dir(),
            run_root.join("machines").join(machine_id.to_string())
        );
        drop(runtime);

        let store = Store::open(&home.join("state.db"))
            .await
            .expect("open existing database");
        assert_eq!(
            store.db_config().await.expect("read db config"),
            Some(crate::store::models::DbConfig::current())
        );
        drop(store);
        Runtime::new(config).await.expect("reopen runtime");
    }
}
