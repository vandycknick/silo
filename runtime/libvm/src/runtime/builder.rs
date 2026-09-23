use std::path::PathBuf;

use crate::runtime::{Runtime, RuntimeConfig, RuntimeNetworkingConfig, VirtBackendOverride};
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
///     .home("/var/lib/silo")
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
    /// Creates a runtime builder using the environment's Silo home.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Silo home holding all persistent state.
    pub fn home(mut self, home: impl Into<PathBuf>) -> Self {
        self.config.home = Some(home.into());
        self
    }

    /// Sets runtime networking defaults.
    pub fn networking(mut self, networking: RuntimeNetworkingConfig) -> Self {
        self.config = self.config.with_networking(networking);
        self
    }

    /// Sets the silo-vmmon executable path used to launch machines.
    pub fn supervisor_path(mut self, supervisor_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_supervisor_path(supervisor_path);
        self
    }

    /// Sets the netd executable path used for userspace networking.
    pub fn netd_path(mut self, netd_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_netd_path(netd_path);
        self
    }

    /// Selects the virtualization backend used for machines started by this runtime.
    pub fn virt_backend(mut self, backend: VirtBackendOverride) -> Self {
        self.config = self.config.with_virt_backend(backend);
        self
    }

    /// Sets the default kernel path.
    pub fn kernel_path(mut self, kernel_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_kernel_path(kernel_path);
        self
    }

    /// Sets the default initramfs path.
    pub fn initramfs_path(mut self, initramfs_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_initramfs_path(initramfs_path);
        self
    }

    /// Sets the default guest agent path.
    pub fn agent_path(mut self, agent_path: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_agent_path(agent_path);
        self
    }

    /// Sets an explicit portable runtime root.
    pub fn runtime_root(mut self, runtime_root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_runtime_root(runtime_root);
        self
    }

    /// Sets a portable runtime root bundled by an SDK frontend.
    pub fn bundled_runtime_root(mut self, bundled_runtime_root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_bundled_runtime_root(bundled_runtime_root);
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

#[cfg(test)]
mod tests {
    use crate::{RuntimeBuilder, VirtBackendOverride};

    #[test]
    fn component_and_runtime_root_methods_populate_runtime_config() {
        let config = RuntimeBuilder::new()
            .supervisor_path("/runtime/bin/silo-vmmon")
            .netd_path("/runtime/bin/netd")
            .virt_backend(VirtBackendOverride::Krun)
            .kernel_path("/runtime/assets/kernel-default")
            .initramfs_path("/runtime/assets/initramfs")
            .agent_path("/runtime/assets/agent")
            .runtime_root("/runtime")
            .bundled_runtime_root("/bundled-runtime")
            .into_config();

        assert_eq!(
            config.supervisor_path.as_deref(),
            Some(std::path::Path::new("/runtime/bin/silo-vmmon"))
        );
        assert_eq!(config.virt_backend, Some(VirtBackendOverride::Krun));
        assert_eq!(
            config.netd_path.as_deref(),
            Some(std::path::Path::new("/runtime/bin/netd"))
        );
        assert_eq!(
            config.kernel_path.as_deref(),
            Some(std::path::Path::new("/runtime/assets/kernel-default"))
        );
        assert_eq!(
            config.initramfs_path.as_deref(),
            Some(std::path::Path::new("/runtime/assets/initramfs"))
        );
        assert_eq!(
            config.agent_path.as_deref(),
            Some(std::path::Path::new("/runtime/assets/agent"))
        );
        assert_eq!(
            config.runtime_root.as_deref(),
            Some(std::path::Path::new("/runtime"))
        );
        assert_eq!(
            config.bundled_runtime_root.as_deref(),
            Some(std::path::Path::new("/bundled-runtime"))
        );
    }
}
