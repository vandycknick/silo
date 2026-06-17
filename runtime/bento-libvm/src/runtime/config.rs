use std::path::PathBuf;

use crate::network::NetworkDriverKind;
use crate::paths::{resolve_default_data_dir, resolve_default_run_dir, LocalRoots};
use crate::LibVmError;

/// Whether a runtime root came from defaults or a caller override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathChoice {
    /// Resolve this root from the process environment and stored root config.
    Default,
    /// Use this explicit path and require it to match stored root config.
    Explicit(PathBuf),
}

/// Local runtime configuration.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Root containing persistent machine metadata and host-local assets.
    pub data_root: PathChoice,
    /// Root containing host-runtime state such as locks and network sockets.
    pub run_root: PathChoice,
    /// Root containing unpacked machine images.
    pub image_root: PathChoice,
    /// Networking configuration for locally started machines.
    pub networking: RuntimeNetworkingConfig,
}

impl RuntimeConfig {
    /// Creates a local runtime configuration rooted at `data_dir`.
    pub fn local(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_root: PathChoice::Explicit(data_dir.into()),
            run_root: PathChoice::Default,
            image_root: PathChoice::Default,
            networking: RuntimeNetworkingConfig::default(),
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

    pub(crate) fn resolve_roots(&self) -> Result<LocalRoots, LibVmError> {
        let data_root = self.bootstrap_data_root()?;
        let run_root = match &self.run_root {
            PathChoice::Default => resolve_default_run_dir(&data_root)?,
            PathChoice::Explicit(path) => path.clone(),
        };
        let image_root = match &self.image_root {
            PathChoice::Default => data_root.join("images"),
            PathChoice::Explicit(path) => path.clone(),
        };
        Ok(LocalRoots::with_roots(data_root, run_root, image_root))
    }

    pub(crate) fn bootstrap_data_root(&self) -> Result<PathBuf, LibVmError> {
        match &self.data_root {
            PathChoice::Default => resolve_default_data_dir(),
            PathChoice::Explicit(path) => Ok(path.clone()),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            data_root: PathChoice::Default,
            run_root: PathChoice::Default,
            image_root: PathChoice::Default,
            networking: RuntimeNetworkingConfig::default(),
        }
    }
}

/// Networking configuration for the local runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeNetworkingConfig {
    /// Driver used for private machine networks.
    pub private_driver: NetworkDriverKind,
    /// Directory containing network policy configuration files.
    pub policy_config_dir: Option<PathBuf>,
    /// netd-specific runtime configuration.
    pub netd: NetdRuntimeConfig,
}

impl Default for RuntimeNetworkingConfig {
    fn default() -> Self {
        Self {
            private_driver: NetworkDriverKind::Netd,
            policy_config_dir: None,
            netd: NetdRuntimeConfig::default(),
        }
    }
}

/// Configuration for the netd network driver.
#[derive(Debug, Clone, PartialEq, Eq)]
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
