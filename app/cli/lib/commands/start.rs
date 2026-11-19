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

    /// Return once the VM is running, without waiting for guest agent readiness.
    #[arg(long)]
    no_wait: bool,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mut spinner = Spinner::start("Finding", self.name.as_deref().unwrap_or("default VM"));
        let name = context.resolve_machine_name(self.name.as_deref())?;

        spinner.step("Starting", &name);
        let data = context
            .app_api()
            .await?
            .start_machine(&name, DEFAULT_GUEST_READINESS_TIMEOUT, !self.no_wait)
            .await?;

        spinner.step(if self.no_wait { "Running" } else { "Ready" }, &data.name);
        spinner.finish_success("Started");
        Ok(())
    }
}

pub(crate) fn ensure_startable(data: &MachineData) -> eyre::Result<()> {
    if data.retention == MachineRetention::Ephemeral {
        eyre::bail!(
            "machine `{}` is an ephemeral `silo run` machine and cannot be started; remove it with `silo rm {}`",
            data.name, data.name
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

#[cfg(test)]
mod tests {
    use clap::Parser;
    use libvm::{MachineData, MachineRetention};

    #[test]
    fn rejects_ephemeral_start_with_removal_hint() {
        let mut data = MachineData::new(
            "00000000-0000-4000-8000-000000000001".into(),
            "temporary".into(),
            vm_spec::VmSpec::current(),
        );
        data.retention = MachineRetention::Ephemeral;
        let error = crate::commands::start::ensure_startable(&data).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("ephemeral `silo run` machine"));
        assert!(message.contains("cannot be started"));
        assert!(message.contains("silo rm temporary"));
        assert!(!message.contains("use `silo run` instead"));
        data.retention = MachineRetention::Persistent;
        assert!(crate::commands::start::ensure_startable(&data).is_ok());
    }

    #[test]
    fn parses_no_wait_for_named_and_default_vms() {
        for args in [
            vec!["silo", "start", "--no-wait", "dev"],
            vec!["silo", "start", "--no-wait"],
        ] {
            let app = crate::app::Cli::try_parse_from(args).unwrap();
            let crate::commands::Command::Start(command) = app.command else {
                panic!("expected start command");
            };
            assert!(command.no_wait);
        }
    }
}
