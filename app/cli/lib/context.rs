use eyre::Context as _;
use libvm::{Machine, MachineRef, Runtime, RuntimeConfig};

use crate::config::GlobalConfig;

#[derive(Debug)]
pub struct Context {
    verbose: u8,
    config: Option<GlobalConfig>,
    runtime: Option<Runtime>,
}

impl Context {
    pub fn new(verbose: u8) -> Self {
        Self {
            verbose,
            config: None,
            runtime: None,
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

    pub(crate) async fn runtime(&mut self) -> eyre::Result<&Runtime> {
        if self.runtime.is_none() {
            let networking = self.config()?.networking.clone();
            let runtime_config = RuntimeConfig::from_env()
                .context("resolve libvm runtime config")?
                .with_networking(networking);
            let runtime = Runtime::new(runtime_config)
                .await
                .context("initialize libvm")?;
            self.runtime = Some(runtime);
        }

        self.runtime
            .as_ref()
            .ok_or_else(|| eyre::eyre!("libvm runtime was not initialized"))
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

    pub(crate) async fn machine(&mut self, name: Option<&str>) -> eyre::Result<(String, Machine)> {
        let resolved = self.resolve_machine_name(name)?;
        let machine_ref = MachineRef::parse(resolved.clone())?;
        let machine = self.runtime().await?.get_machine(&machine_ref).await?;
        Ok((resolved, machine))
    }
}
