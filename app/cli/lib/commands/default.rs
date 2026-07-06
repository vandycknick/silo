use clap::Args;

use crate::config::GlobalConfig;
use crate::context::Context;

#[derive(Debug, Args)]
#[command(about = "Show or set the default VM")]
pub struct Cmd {
    /// Name or ID of the VM to use by default.
    #[arg(value_name = "VM")]
    name: Option<String>,

    /// Clear the configured default VM.
    #[arg(long, conflicts_with = "name")]
    unset: bool,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        if self.unset {
            GlobalConfig::write_default_machine(None)?;
            println!("default machine unset");
            return Ok(());
        }

        let Some(name) = self.name.as_deref() else {
            match context.config()?.default_machine() {
                Some(name) => println!("default machine is {name}"),
                None => println!(
                    "no default machine configured\n\nhint: run `silo default <vm>` to choose one"
                ),
            }
            return Ok(());
        };

        let (_name, machine) = context.machine(Some(name)).await?;
        let inspect_data = machine.inspect().await?;
        GlobalConfig::write_default_machine(Some(inspect_data.name.as_str()))?;
        println!("default machine is {}", inspect_data.name);
        Ok(())
    }
}
