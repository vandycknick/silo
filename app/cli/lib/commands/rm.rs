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
            .await?;
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
