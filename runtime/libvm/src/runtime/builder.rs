use std::path::PathBuf;

use crate::runtime::{Runtime, RuntimeConfig, RuntimeNetworkingConfig};
use crate::LibVmError;

/// Builder for opening a local libvm runtime.
///
/// Use this when constructing a runtime from application configuration. The
/// lower-level `Runtime::new` API remains available when you already have a
/// complete `RuntimeConfig` value.
///
/// ```rust,no_run
/// use libvm::{NetdRuntimeConfig, Runtime, RuntimeNetworkingConfig};
///
/// # async fn example() -> Result<(), libvm::LibVmError> {
/// let runtime = Runtime::builder()
///     .data_root("/var/lib/silo")
///     .networking(
///         RuntimeNetworkingConfig::new()
///             .with_netd(NetdRuntimeConfig::new().with_pcap(true)),
///     )
///     .open()
///     .await?;
/// # let _ = runtime;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct RuntimeBuilder {
    config: RuntimeConfig,
}

impl RuntimeBuilder {
    /// Creates a runtime builder using environment/default roots.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the persistent data root.
    pub fn data_root(mut self, data_root: impl Into<PathBuf>) -> Self {
        self.config.data_root = crate::runtime::PathChoice::Explicit(data_root.into());
        self
    }

    /// Sets the host-runtime root.
    pub fn run_root(mut self, run_root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_run_root(run_root);
        self
    }

    /// Sets the image root.
    pub fn image_root(mut self, image_root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_image_root(image_root);
        self
    }

    /// Sets runtime networking defaults.
    pub fn networking(mut self, networking: RuntimeNetworkingConfig) -> Self {
        self.config = self.config.with_networking(networking);
        self
    }

    /// Sets the vmmon executable path used to launch machines.
    pub fn vmmon_path(mut self, vmmon_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_vmmon_path(vmmon_path);
        self
    }

    /// Opens the runtime.
    pub async fn open(self) -> Result<Runtime, LibVmError> {
        Runtime::new(self.config).await
    }

    /// Returns the underlying config without opening the runtime.
    pub fn into_config(self) -> RuntimeConfig {
        self.config
    }
}
