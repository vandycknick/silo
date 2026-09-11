use clap::Args;
use libvm::{
    MachineAgent, MachineData, MachineRetention, MachineStatus, DEFAULT_GUEST_READINESS_TIMEOUT,
};

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
        let name = context.resolve_machine_name(self.name.as_deref())?;

        spinner.step("Starting", &name);
        let data = context
            .app_api()
            .await?
            .start_machine(&name, DEFAULT_GUEST_READINESS_TIMEOUT)
            .await?;

        spinner.step("Ready", &data.name);
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
