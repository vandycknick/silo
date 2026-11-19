use clap::Args;

use crate::config::GlobalConfig;
use crate::context::Context;
use crate::ui::{self, Spinner};

#[derive(Debug, Args)]
#[command(about = "Remove a VM")]
pub struct Cmd {
    /// Name or ID of the VM to remove.
    #[arg(value_name = "VM")]
    name: String,

    /// Stop the VM first if it is running.
    #[arg(long)]
    force: bool,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mut spinner = Spinner::start("Finding", &self.name);
        let data = context.app_api().await?.inspect_machine(&self.name).await?;
        let machine_name = data.name;
        let removed_default = context.config()?.default_machine() == Some(machine_name.as_str());

        if self.force {
            spinner.step("Stopping", &machine_name);
        }

        spinner.step("Removing", &machine_name);
        context
            .app_api()
            .await?
            .remove_machine(&self.name, self.force)
            .await
            .map_err(removal_error)?;
        if removed_default {
            GlobalConfig::write_default_machine(None)?;
        }
        spinner.step("Removed", &machine_name);
        spinner.finish_success("Removed");

        if removed_default {
            ui::warn("removed default machine. Set a new one with `silo default <vm>`.");
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RunningMachineRemoval(String);

impl std::error::Error for RunningMachineRemoval {}

impl std::fmt::Display for RunningMachineRemoval {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "machine {} is running; stop it first or use --force",
            self.0
        )
    }
}

fn removal_error(error: eyre::Report) -> eyre::Report {
    match error.downcast_ref::<libvm::LibVmError>() {
        Some(libvm::LibVmError::MachineAlreadyRunning { reference }) => {
            RunningMachineRemoval(reference.clone()).into()
        }
        _ => error,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn removal_explains_running_refusal_without_changing_other_errors() {
        let error = crate::commands::rm::removal_error(
            libvm::LibVmError::MachineAlreadyRunning {
                reference: "base".into(),
            }
            .into(),
        );
        assert!(error
            .downcast_ref::<crate::commands::rm::RunningMachineRemoval>()
            .is_some());
        assert_eq!(
            error.to_string(),
            "machine base is running; stop it first or use --force"
        );
        let error = crate::commands::rm::removal_error(
            libvm::LibVmError::MachineNotFound {
                reference: "base".into(),
            }
            .into(),
        );
        assert!(matches!(
            error.downcast_ref::<libvm::LibVmError>(),
            Some(libvm::LibVmError::MachineNotFound { .. })
        ));
    }
}
