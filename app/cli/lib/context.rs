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
    api: Option<AppApi>,
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
            self.api = Some(AppApi::local(runtime_config));
        }

        self.api
            .as_mut()
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
        image_override: Option<&str>,
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
        Ok((
            default_system_paths()?,
            config.resolve(&home, image_override)?,
        ))
    }
}
