use std::fmt::{Display, Formatter};

use clap::Args;
use libvm::{MachineRef, Runtime};

use crate::config::GlobalConfig;

#[derive(Args, Debug)]
#[command(about = "Show or set the default VM")]
pub struct Cmd {
    /// Name or ID of the VM to use by default.
    #[arg(value_name = "VM")]
    pub name: Option<String>,

    /// Clear the configured default VM.
    #[arg(long, conflicts_with = "name")]
    pub unset: bool,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match (self.name.as_deref(), self.unset) {
            (Some(name), _) => f.write_str(name),
            (None, true) => f.write_str("--unset"),
            (None, false) => Ok(()),
        }
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime, config: &GlobalConfig) -> eyre::Result<()> {
        if self.unset {
            GlobalConfig::write_default_machine(None)?;
            println!("default machine unset");
            return Ok(());
        }

        let Some(name) = self.name.as_deref() else {
            match config.default_machine() {
                Some(name) => println!("default machine is {name}"),
                None => println!(
                    "no default machine configured\n\nhint: run `bento default <vm>` to choose one"
                ),
            }
            return Ok(());
        };

        let machine = libvm
            .get_machine(&MachineRef::parse(name.to_string())?)
            .await?;
        let inspect_data = machine.inspect().await?;
        GlobalConfig::write_default_machine(Some(inspect_data.name.as_str()))?;
        println!("default machine is {}", inspect_data.name);
        Ok(())
    }
}
