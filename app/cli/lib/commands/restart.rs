use clap::Args;
use libvm::{LibVmError, MachineReadinessOutcome, DEFAULT_GUEST_READINESS_TIMEOUT};

use crate::commands::start_options::machine_start_options;
use crate::context::Context;
use crate::ui::Spinner;

#[derive(Debug, Args)]
#[command(about = "Restart a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to restart. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    name: Option<String>,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mut spinner = Spinner::start("Finding", self.name.as_deref().unwrap_or("default VM"));
        let (name, machine) = context.machine(self.name.as_deref()).await?;

        spinner.step("Stopping", &name);
        match machine.stop().await {
            Ok(_) => {}
            Err(LibVmError::MachineNotRunning { .. }) => {
                spinner.step("Stopped", &name);
            }
            Err(err) => return Err(err.into()),
        }

        spinner.step("Starting", &name);
        let options = machine_start_options(context.runtime().await?, &machine).await?;
        let data = machine.start_with_options(options).await?;

        spinner.step("Waiting", &name);
        let readiness = machine.wait_ready(DEFAULT_GUEST_READINESS_TIMEOUT).await?;
        if readiness.outcome != MachineReadinessOutcome::Ready {
            eyre::bail!("guest readiness check ended with {:?}", readiness.outcome);
        }

        spinner.step("Ready", &data.name);
        spinner.finish_success("Restarted");
        Ok(())
    }
}
