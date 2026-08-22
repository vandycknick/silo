use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use eyre::Context as _;
use libvm::{
    MachineExitOutcome, MachineRef, MachineRetention, MachineRunId, MachineStatus,
    MachineWaitOptions, Runtime, RuntimeConfig,
};

use crate::config::GlobalConfig;
use crate::context::Context;

const MACHINE_RUN_ID_ENV: &str = "SILO_MACHINE_RUN_ID";
const CLEANUP_WAIT_INTERVAL: Duration = Duration::from_secs(5 * 60);

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
        let reference = MachineRef::parse(self.machine_id)?;
        let machine = runtime.get_machine(&reference).await?;
        let run_id = std::env::var(MACHINE_RUN_ID_ENV)
            .context("detached cleanup is missing its machine run ID")?
            .parse::<MachineRunId>()
            .context("detached cleanup received an invalid machine run ID")?;
        if !wait_for_run_exit(&machine, run_id.clone()).await? {
            return Ok(());
        }
        if machine.inspect().await?.retention == MachineRetention::Ephemeral {
            match machine.remove_after_run(run_id).await {
                Ok(())
                | Err(libvm::LibVmError::MachineAlreadyRunning { .. })
                | Err(libvm::LibVmError::MachineStaleGeneration { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

async fn wait_for_run_exit(machine: &libvm::Machine, run_id: MachineRunId) -> eyre::Result<bool> {
    loop {
        match machine
            .wait_for_run_with(
                run_id.clone(),
                MachineWaitOptions::new().timeout(CLEANUP_WAIT_INTERVAL),
            )
            .await
        {
            Ok(exit)
                if exit.outcome == MachineExitOutcome::Unknown
                    && matches!(
                        exit.machine.status,
                        MachineStatus::Starting { .. }
                            | MachineStatus::Running { .. }
                            | MachineStatus::Stopping { .. }
                    ) => {}
            Ok(_) => return Ok(true),
            Err(libvm::LibVmError::MachineStaleGeneration { .. }) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
}
