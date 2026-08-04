use std::path::PathBuf;

use clap::Args;
use eyre::Context as _;
use libvm::{MachineRef, Runtime, RuntimeConfig};

use crate::config::GlobalConfig;
use crate::context::Context;

#[derive(Debug, Args)]
#[command(hide = true)]
pub struct Cmd {
    #[arg(long = "data-dir")]
    data_dir: PathBuf,

    #[arg(long = "machine-id")]
    machine_id: String,
}

impl Cmd {
    pub async fn run(self, _context: &mut Context) -> eyre::Result<()> {
        let global_config = GlobalConfig::load().context("load global config")?;
        let runtime_config =
            RuntimeConfig::local(self.data_dir).with_networking(global_config.networking.clone());
        let runtime = Runtime::new(runtime_config)
            .await
            .context("initialize libvm")?;
        let machine_ref = MachineRef::parse(self.machine_id)?;
        let machine = runtime.get_machine(&machine_ref).await?;
        machine.remove().await?;
        Ok(())
    }
}
