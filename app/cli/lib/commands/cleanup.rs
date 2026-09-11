use clap::Args;
use eyre::Context as _;
use libvm::{MachineRunId, RuntimeConfig};
use std::path::PathBuf;

use crate::config::GlobalConfig;
use crate::context::Context;

const MACHINE_RUN_ID_ENV: &str = "SILO_MACHINE_RUN_ID";

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
        let run_id = std::env::var(MACHINE_RUN_ID_ENV)
            .context("detached cleanup is missing its machine run ID")?
            .parse::<MachineRunId>()
            .context("detached cleanup received an invalid machine run ID")?;
        crate::api::AppApi::cleanup_local(runtime_config, self.machine_id, run_id).await
    }
}
