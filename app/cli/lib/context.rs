use eyre::Context as _;
use libvm::RuntimeConfig;

use crate::api::machine::AppMachine;
use crate::api::AppApi;
use crate::config::GlobalConfig;
use crate::system::config::ResolvedSystemConfig;
use crate::system::ownership::default_system_paths;
use crate::system::record::SystemPaths;

#[derive(Debug)]
pub struct Context {
    verbose: u8,
    config: Option<GlobalConfig>,
    api: Option<CachedAppApi>,
}

#[derive(Debug)]
struct CachedAppApi {
    api: AppApi,
    policy: CachedRuntimePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedRuntimePolicy {
    virt_backend: Option<libvm::VirtBackendOverride>,
}

impl CachedRuntimePolicy {
    fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            virt_backend: config.virt_backend.clone(),
        }
    }
}

impl Context {
    pub fn new(verbose: u8) -> Self {
        Self {
            verbose,
            config: None,
            api: None,
        }
    }

    pub fn verbose(&self) -> u8 {
        self.verbose
    }

    pub(crate) fn config(&mut self) -> eyre::Result<&GlobalConfig> {
        if self.config.is_none() {
            self.config = Some(GlobalConfig::load().context("load global config")?);
        }

        self.config
            .as_ref()
            .ok_or_else(|| eyre::eyre!("global config was not initialized"))
    }

    pub(crate) async fn app_api(&mut self) -> eyre::Result<&mut AppApi> {
        if self.api.is_none() {
            let networking = self.config()?.networking.clone();
            let runtime_config = RuntimeConfig::from_env()
                .context("resolve libvm runtime config")?
                .with_networking(networking);
            self.api = Some(CachedAppApi {
                policy: CachedRuntimePolicy::from_config(&runtime_config),
                api: AppApi::local(runtime_config),
            });
        }
        self.api
            .as_mut()
            .map(|cached| &mut cached.api)
            .ok_or_else(|| eyre::eyre!("application API was not initialized"))
    }

    pub(crate) async fn app_api_with_backend(
        &mut self,
        virt_backend: libvm::VirtBackendOverride,
    ) -> eyre::Result<&mut AppApi> {
        let requested_policy = CachedRuntimePolicy {
            virt_backend: Some(virt_backend.clone()),
        };
        if let Some(cached) = self.api.as_ref() {
            if cached.policy != requested_policy {
                eyre::bail!(
                    "the initialized runtime policy is incompatible with the daemon request: cached {:?}, requested {:?}",
                    cached.policy,
                    requested_policy
                );
            }
        }
        if self.api.is_some() {
            return self
                .api
                .as_mut()
                .map(|cached| &mut cached.api)
                .ok_or_else(|| eyre::eyre!("application API was not initialized"));
        }

        let networking = self.config()?.networking.clone();
        let runtime_config = explicit_runtime_config(networking, virt_backend);
        self.api = Some(CachedAppApi {
            policy: requested_policy,
            api: AppApi::local(runtime_config),
        });
        self.api
            .as_mut()
            .map(|cached| &mut cached.api)
            .ok_or_else(|| eyre::eyre!("application API was not initialized"))
    }

    pub(crate) fn resolve_machine_name(&mut self, name: Option<&str>) -> eyre::Result<String> {
        if let Some(name) = name {
            return Ok(name.to_string());
        }

        self.config()?.default_machine().map(str::to_string).ok_or_else(|| {
            eyre::eyre!(
                "no default machine configured\n\nhint: run `silo default <vm>` or pass a machine name"
            )
        })
    }

    pub(crate) async fn machine(
        &mut self,
        name: Option<&str>,
    ) -> eyre::Result<(String, AppMachine)> {
        let resolved = self.resolve_machine_name(name)?;
        let machine = self.app_api().await?.machine(&resolved).await?;
        Ok((resolved, machine))
    }

    pub(crate) fn resolved_system_config(
        &mut self,
    ) -> eyre::Result<(SystemPaths, ResolvedSystemConfig)> {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| {
                eyre::eyre!("HOME is required for the system VM share and Docker endpoint")
            })?;
        if !home.is_absolute() {
            return Err(eyre::eyre!("HOME must be absolute: {}", home.display()));
        }
        let config = self.config()?.daemon().cloned().ok_or_else(|| {
            eyre::eyre!("system daemon is not configured\n\nhint: add `daemon: {{ version: \"1\", system: {{}} }}` to the Silo config")
        })?;
        let paths = default_system_paths()?;
        let mut resolved = config.resolve(&home, &paths.home, None)?;
        if let Some(installation) = crate::system::record::DaemonRecord::load(&paths)? {
            if resolved.image == installation.configured_image
                && resolved.image != installation.config.image
            {
                resolved.image = installation.config.image;
            }
            // Disk sizes are fixed at creation. Unless the user pinned them, follow the
            // installation so a changed default never reads as a config change.
            let root_size = if config.system.storage.explicit_root_size() {
                resolved.root_size_bytes
            } else {
                installation.config.root_size_bytes
            };
            let data_size = if config.system.storage.explicit_data_size() {
                resolved.data_size_bytes
            } else {
                installation.data_size_bytes
            };
            resolved.root_size_bytes = root_size;
            resolved.data_size_bytes = data_size;
        }
        Ok((paths, resolved))
    }
}

fn explicit_runtime_config(
    networking: libvm::RuntimeNetworkingConfig,
    virt_backend: libvm::VirtBackendOverride,
) -> RuntimeConfig {
    RuntimeConfig::default()
        .with_networking(networking)
        .with_virt_backend(virt_backend)
}

#[cfg(test)]
mod tests {
    use crate::api::AppApi;
    use crate::context::{explicit_runtime_config, CachedAppApi, CachedRuntimePolicy, Context};

    #[tokio::test]
    async fn explicit_daemon_policy_rejects_incompatible_default_and_direct_env_caches() {
        for cached_backend in [None, Some(libvm::VirtBackendOverride::Vz)] {
            let mut runtime = libvm::RuntimeConfig::default();
            runtime.virt_backend = cached_backend.clone();
            let mut context = Context::new(0);
            context.api = Some(CachedAppApi {
                policy: CachedRuntimePolicy::from_config(&runtime),
                api: AppApi::local(runtime),
            });

            let error = context
                .app_api_with_backend(libvm::VirtBackendOverride::Krun)
                .await
                .expect_err("reject incompatible cached runtime");
            assert!(error.to_string().contains("incompatible"));
            assert_eq!(
                context.api.as_ref().map(|cached| &cached.policy),
                Some(&CachedRuntimePolicy {
                    virt_backend: cached_backend,
                })
            );
        }
    }

    #[tokio::test]
    async fn explicit_daemon_policy_reuses_a_compatible_cached_runtime() {
        let runtime = explicit_runtime_config(
            libvm::RuntimeNetworkingConfig::default(),
            libvm::VirtBackendOverride::Krun,
        );
        let mut context = Context::new(0);
        context.api = Some(CachedAppApi {
            policy: CachedRuntimePolicy::from_config(&runtime),
            api: AppApi::local(runtime),
        });

        context
            .app_api_with_backend(libvm::VirtBackendOverride::Krun)
            .await
            .expect("reuse compatible runtime");
        context
            .app_api()
            .await
            .expect("ordinary access reuses cache");
    }

    #[test]
    fn explicit_daemon_config_preserves_default_roots_components_and_networking() {
        let networking = libvm::RuntimeNetworkingConfig::default()
            .with_netd(libvm::NetdRuntimeConfig::new().with_subnet("192.168.247.0/24"));
        let runtime = explicit_runtime_config(networking.clone(), libvm::VirtBackendOverride::Krun);

        assert_eq!(runtime.home, None);
        assert_eq!(runtime.networking, networking);
        assert!(runtime.vmmon_path.is_none());
        assert!(runtime.netd_path.is_none());
        assert_eq!(runtime.virt_backend, Some(libvm::VirtBackendOverride::Krun));
    }
}
