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

    /// Sets the durable logs and operational state root.
    pub fn state_root(mut self, state_root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_state_root(state_root);
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

    /// Sets the netd executable path used for private networking.
    pub fn netd_path(mut self, netd_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_netd_path(netd_path);
        self
    }

    /// Sets the krun executable path passed to vmmon.
    pub fn krun_path(mut self, krun_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_krun_path(krun_path);
        self
    }

    /// Sets the default guest kernel path.
    pub fn kernel_path(mut self, kernel_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_kernel_path(kernel_path);
        self
    }

    /// Sets the default guest initramfs path.
    pub fn initramfs_path(mut self, initramfs_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_initramfs_path(initramfs_path);
        self
    }

    /// Sets the default guest agent path.
    pub fn agent_path(mut self, agent_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_agent_path(agent_path);
        self
    }

    /// Sets a portable runtime root containing `bin/` and `assets/`.
    pub fn runtime_root(mut self, runtime_root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_runtime_root(runtime_root);
        self
    }

    /// Sets a lower-priority portable runtime bundled by the caller.
    pub fn bundled_runtime_root(mut self, runtime_root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_bundled_runtime_root(runtime_root);
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
