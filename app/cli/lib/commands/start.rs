use clap::Args;
use libvm::{
    MachineAgent, MachineData, MachineReadinessOutcome, MachineRetention, MachineStatus,
    DEFAULT_GUEST_READINESS_TIMEOUT,
};

use crate::commands::start_options::machine_start_options;
use crate::context::Context;
use crate::ui::Spinner;

#[derive(Debug, Args)]
#[command(about = "Start a persistent VM in idle mode")]
pub struct Cmd {
    /// Name or ID of the VM to start. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    name: Option<String>,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mut spinner = Spinner::start("Finding", self.name.as_deref().unwrap_or("default VM"));
        let (name, machine) = context.machine(self.name.as_deref()).await?;
        let data = machine.inspect().await?;
        ensure_startable(&data)?;

        spinner.step("Starting", &name);
        let options = machine_start_options(context.runtime().await?, &machine).await?;
        let start = machine.start_with_options(options).await?;

        if requires_guest_readiness(&start.machine) {
            spinner.step("Waiting", &name);
            let readiness = machine.wait_ready(DEFAULT_GUEST_READINESS_TIMEOUT).await?;
            if readiness.outcome != MachineReadinessOutcome::Ready {
                eyre::bail!("guest readiness check ended with {:?}", readiness.outcome);
            }
        }

        spinner.step("Ready", &start.machine.name);
        spinner.finish_success("Started");
        Ok(())
    }
}

pub(crate) fn ensure_startable(data: &MachineData) -> eyre::Result<()> {
    if data.retention == MachineRetention::Ephemeral {
        eyre::bail!(
            "machine `{}` is ephemeral and cannot be started; use `silo run` instead",
            data.name
        );
    }
    if matches!(
        data.status,
        MachineStatus::Stopped | MachineStatus::Error { .. }
    ) {
        return Ok(());
    }

    eyre::bail!(
        "machine `{}` is {}; stop it before starting it",
        data.name,
        data.status.label()
    );
}

pub(crate) fn requires_guest_readiness(data: &MachineData) -> bool {
    !matches!(data.guest.agent, MachineAgent::Disabled)
}
