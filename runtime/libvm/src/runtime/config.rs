use std::env::consts::OS;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use crate::paths::{
    ensure_run_root, resolve_default_data_dir, resolve_default_run_dir, resolve_default_state_dir,
    LocalPaths, LocalRoots,
};
use crate::store::models::DbConfig;
use crate::LibVmError;

/// Whether a runtime root came from defaults or a caller override.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathChoice {
    /// Resolve this root from the process environment and stored root config.
    Default,
    /// Use this explicit path and require it to match stored root config.
    Explicit(PathBuf),
}

/// Local runtime configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RuntimeConfig {
    /// Root containing persistent machine metadata and host-local assets.
    pub data_root: PathChoice,
    /// Root containing durable operational state.
    pub state_root: PathChoice,
    /// Root containing host-runtime state such as locks and network sockets.
    pub run_root: PathChoice,
    /// Root containing unpacked machine images.
    pub image_root: PathChoice,
    /// Networking configuration for locally started machines.
    pub networking: RuntimeNetworkingConfig,
    /// Explicit vmmon executable path.
    pub vmmon_path: Option<PathBuf>,
}

impl RuntimeConfig {
    /// Creates a local runtime configuration rooted at `data_dir`.
    pub fn local(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_root: PathChoice::Explicit(data_dir.into()),
            state_root: PathChoice::Default,
            run_root: PathChoice::Default,
            image_root: PathChoice::Default,
            networking: RuntimeNetworkingConfig::default(),
            vmmon_path: None,
        }
    }

    /// Creates the default local runtime configuration from the environment.
    pub fn from_env() -> Result<Self, LibVmError> {
        let _ = resolve_default_data_dir()?;
        Ok(Self::default())
    }

    /// Sets the local runtime root.
    pub fn with_run_root(mut self, run_root: impl Into<PathBuf>) -> Self {
        self.run_root = PathChoice::Explicit(run_root.into());
        self
    }

    /// Sets the durable operational state root.
    pub fn with_state_root(mut self, state_root: impl Into<PathBuf>) -> Self {
        self.state_root = PathChoice::Explicit(state_root.into());
        self
    }

    /// Sets the local image root.
    pub fn with_image_root(mut self, image_root: impl Into<PathBuf>) -> Self {
        self.image_root = PathChoice::Explicit(image_root.into());
        self
    }

    /// Sets local runtime networking configuration.
    pub fn with_networking(mut self, networking: RuntimeNetworkingConfig) -> Self {
        self.networking = networking;
        self
    }

    /// Sets the vmmon executable path used to launch machines.
    pub fn with_vmmon_path(mut self, vmmon_path: impl Into<PathBuf>) -> Self {
        self.vmmon_path = Some(vmmon_path.into());
        self
    }

    pub(crate) fn resolve_roots(&self) -> Result<LocalRoots, LibVmError> {
        let (data_root, state_root, image_root) = self.resolve_durable_roots()?;
        let run_root = self.resolve_run_root()?;
        let roots = LocalRoots::with_roots(data_root, state_root, run_root, image_root);
        validate_roots_absolute(&roots)?;
        ensure_run_root(roots.run_root())?;
        Ok(roots)
    }

    pub(crate) fn bootstrap_paths(&self) -> Result<LocalPaths, LibVmError> {
        let data_root = self.bootstrap_data_root()?;
        let roots = LocalRoots::with_roots(
            data_root.clone(),
            data_root.clone(),
            data_root.join("run"),
            data_root.join("images"),
        );
        validate_roots_absolute(&roots)?;
        Ok(LocalPaths::from_roots(roots))
    }

    pub(crate) fn seed_db_config(&self) -> Result<DbConfig, LibVmError> {
        let roots = self.resolve_roots()?;
        validate_roots_absolute(&roots)?;
        Ok(DbConfig::from_roots(&roots))
    }

    pub(crate) fn resolve_store_roots(
        &self,
        stored: &DbConfig,
        opened_db_path: &Path,
    ) -> Result<LocalRoots, LibVmError> {
        validate_db_config_header(stored)?;
        let (data_root, state_root, image_root) = merge_durable_roots(self, stored)?;
        let run_root = self.resolve_run_root()?;
        let roots = LocalRoots::with_roots(data_root, state_root, run_root, image_root);
        validate_roots_absolute(&roots)?;
        ensure_run_root(roots.run_root())?;
        validate_durable_roots_match_config(&roots, stored)?;
        compare_path("state_db_path", &roots.state_db_path(), opened_db_path)?;
        Ok(roots)
    }

    pub(crate) fn bootstrap_data_root(&self) -> Result<PathBuf, LibVmError> {
        match &self.data_root {
            PathChoice::Default => resolve_default_data_dir(),
            PathChoice::Explicit(path) => Ok(path.clone()),
        }
    }

    fn resolve_durable_roots(&self) -> Result<(PathBuf, PathBuf, PathBuf), LibVmError> {
        let data_root = self.bootstrap_data_root()?;
        let state_root = match &self.state_root {
            PathChoice::Default => resolve_default_state_dir()?,
            PathChoice::Explicit(path) => path.clone(),
        };
        let image_root = match &self.image_root {
            PathChoice::Default => data_root.join("images"),
            PathChoice::Explicit(path) => path.clone(),
        };
        Ok((data_root, state_root, image_root))
    }

    fn resolve_run_root(&self) -> Result<PathBuf, LibVmError> {
        match &self.run_root {
            PathChoice::Default => resolve_default_run_dir(),
            PathChoice::Explicit(path) => Ok(path.clone()),
        }
    }
}

fn validate_db_config_header(config: &DbConfig) -> Result<(), LibVmError> {
    compare_str("os", OS, &config.os)
}

fn merge_durable_roots(
    runtime_config: &RuntimeConfig,
    stored: &DbConfig,
) -> Result<(PathBuf, PathBuf, PathBuf), LibVmError> {
    let data_root = merge_root(
        "data_root",
        &runtime_config.data_root,
        Path::new(&stored.data_root),
    )?;
    let state_root = merge_root(
        "state_root",
        &runtime_config.state_root,
        Path::new(&stored.state_root),
    )?;
    let image_root = merge_root(
        "image_root",
        &runtime_config.image_root,
        Path::new(&stored.image_root),
    )?;

    Ok((data_root, state_root, image_root))
}

fn merge_root(
    field: &'static str,
    choice: &PathChoice,
    stored: &Path,
) -> Result<PathBuf, LibVmError> {
    match choice {
        PathChoice::Default => Ok(stored.to_path_buf()),
        PathChoice::Explicit(path) => {
            compare_path(field, path, stored)?;
            Ok(path.clone())
        }
    }
}

fn validate_durable_roots_match_config(
    roots: &LocalRoots,
    config: &DbConfig,
) -> Result<(), LibVmError> {
    compare_path("data_root", roots.data_root(), Path::new(&config.data_root))?;
    compare_path(
        "state_root",
        roots.state_root(),
        Path::new(&config.state_root),
    )?;
    compare_path(
        "image_root",
        roots.image_root(),
        Path::new(&config.image_root),
    )
}

fn validate_roots_absolute(roots: &LocalRoots) -> Result<(), LibVmError> {
    validate_absolute_path("data_root", roots.data_root())?;
    validate_absolute_path("state_root", roots.state_root())?;
    validate_absolute_path("run_root", roots.run_root())?;
    validate_absolute_path("image_root", roots.image_root())
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

fn compare_path(field: &'static str, expected: &Path, actual: &Path) -> Result<(), LibVmError> {
    let expected = path_for_compare(field, expected)?;
    let actual = path_for_compare(field, actual)?;
    if expected == actual {
        return Ok(());
    }

    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: path_to_db_string(&expected),
        actual: path_to_db_string(&actual),
    })
}

fn path_for_compare(field: &'static str, path: &Path) -> Result<PathBuf, LibVmError> {
    validate_absolute_path(field, path)?;
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(normalize_absolute_path(path)),
        Err(err) => Err(LibVmError::Io(err)),
    }
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

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            data_root: PathChoice::Default,
            state_root: PathChoice::Default,
            run_root: PathChoice::Default,
            image_root: PathChoice::Default,
            networking: RuntimeNetworkingConfig::default(),
            vmmon_path: None,
        }
    }
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
    use crate::paths::LocalRoots;
    use crate::store::{ConfigStore, Store};
    use crate::{LibVmError, Runtime, RuntimeConfig};

    fn stored_config(data_root: &std::path::Path) -> LocalRoots {
        let roots = LocalRoots::with_roots(
            data_root,
            data_root
                .parent()
                .expect("data root parent")
                .join("state-root"),
            data_root.parent().unwrap().join("runtime-root"),
            data_root.parent().unwrap().join("image-root"),
        );
        roots
    }

    #[test]
    fn db_config_merges_default_roots_from_existing_contract() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("silo");
        let stored_roots = stored_config(&data_root);
        let stored = crate::store::models::DbConfig::from_roots(&stored_roots);
        let expected_roots = LocalRoots::with_roots(
            &data_root,
            stored_roots.state_root(),
            crate::paths::resolve_default_run_dir().expect("resolve default run root"),
            stored_roots.image_root(),
        );

        let roots = RuntimeConfig::local(&data_root)
            .resolve_store_roots(&stored, &data_root.join("state.db"))
            .expect("resolve roots from stored contract");

        assert_eq!(roots, expected_roots);
    }

    #[test]
    fn db_config_exempts_run_root_from_stored_identity() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("silo");
        let stored_roots = stored_config(&data_root);
        let stored = crate::store::models::DbConfig::from_roots(&stored_roots);
        let run_root = temp.path().join("other-runtime-root");

        let roots = RuntimeConfig::local(&data_root)
            .with_run_root(temp.path().join("other-runtime-root"))
            .resolve_store_roots(&stored, &data_root.join("state.db"))
            .expect("explicit run root should not be compared with stored roots");

        assert_eq!(roots.run_root(), run_root);
    }

    #[test]
    fn db_config_rejects_relative_roots() {
        let err = RuntimeConfig::local("relative-silo")
            .bootstrap_paths()
            .expect_err("relative data root should fail");

        assert!(matches!(
            err,
            LibVmError::StateDatabaseConfigMismatch {
                field: "data_root",
                ..
            }
        ));
    }

    #[test]
    fn db_config_rejects_state_db_path_mismatch() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("silo");
        let stored_roots = stored_config(&data_root);
        let stored = crate::store::models::DbConfig::from_roots(&stored_roots);

        let err = RuntimeConfig::local(&data_root)
            .resolve_store_roots(&stored, &temp.path().join("other-state.db"))
            .expect_err("opened db path mismatch should fail");

        assert!(matches!(
            err,
            LibVmError::StateDatabaseConfigMismatch {
                field: "state_db_path",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn fresh_database_rejects_conflicting_durable_roots() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("data");
        let state_root = temp.path().join("state");
        let image_root = temp.path().join("images");
        let config = RuntimeConfig::local(&data_root)
            .with_state_root(&state_root)
            .with_image_root(&image_root)
            .with_run_root(temp.path().join("run-a"));
        let store = Store::open(&data_root.join("state.db"))
            .await
            .expect("open fresh database");
        let stored = store
            .read_or_seed_db_config(&config.seed_db_config().expect("seed config"))
            .await
            .expect("seed fresh database");

        for (field, conflicting) in [
            (
                "data_root",
                RuntimeConfig::local(temp.path().join("other-data"))
                    .with_state_root(&state_root)
                    .with_image_root(&image_root),
            ),
            (
                "state_root",
                RuntimeConfig::local(&data_root)
                    .with_state_root(temp.path().join("other-state"))
                    .with_image_root(&image_root),
            ),
            (
                "image_root",
                RuntimeConfig::local(&data_root)
                    .with_state_root(&state_root)
                    .with_image_root(temp.path().join("other-images")),
            ),
        ] {
            let err = conflicting
                .resolve_store_roots(&stored, &data_root.join("state.db"))
                .expect_err("conflicting durable root should fail");
            assert!(matches!(
                err,
                LibVmError::StateDatabaseConfigMismatch { field: actual, .. } if actual == field
            ));
        }
    }

    #[tokio::test]
    async fn runtime_reopens_fresh_database_with_a_new_run_root() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("data");
        let state_root = temp.path().join("state");
        let image_root = temp.path().join("images");
        let first_run_root = temp.path().join("run-a");
        let second_run_root = temp.path().join("run-b");
        let first = RuntimeConfig::local(&data_root)
            .with_state_root(&state_root)
            .with_image_root(&image_root)
            .with_run_root(&first_run_root);

        let runtime = Runtime::new(first).await.expect("open fresh runtime");
        assert_eq!(runtime.local_paths().roots().run_root(), first_run_root);
        drop(runtime);

        let runtime = Runtime::new(
            RuntimeConfig::local(&data_root)
                .with_state_root(&state_root)
                .with_image_root(&image_root)
                .with_run_root(&second_run_root),
        )
        .await
        .expect("reopen with a changed run root");
        assert_eq!(runtime.local_paths().roots().run_root(), second_run_root);
    }
}
