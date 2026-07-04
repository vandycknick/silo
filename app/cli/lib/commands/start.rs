use clap::Args;
use libvm::DEFAULT_GUEST_READINESS_TIMEOUT;

use crate::commands::start_options::machine_start_options;
use crate::context::Context;
use crate::ui::Spinner;

#[derive(Debug, Args)]
#[command(about = "Start a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to start. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    name: Option<String>,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mut spinner = Spinner::start("Finding", self.name.as_deref().unwrap_or("default VM"));
        let (name, machine) = context.machine(self.name.as_deref()).await?;

        spinner.step("Starting", &name);
        let options = machine_start_options(context.runtime().await?, &machine)?;
        let data = machine.start_with_options(options).await?;

        spinner.step("Waiting", &name);
        machine
            .wait_for_guest_running(DEFAULT_GUEST_READINESS_TIMEOUT)
            .await
            .map_err(|err| eyre::eyre!("guest readiness check failed: {err}"))?;

        spinner.step("Ready", &data.name);
        spinner.finish_success("Started");
        Ok(())
    }
}
