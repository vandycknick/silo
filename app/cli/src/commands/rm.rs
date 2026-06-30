use std::fmt::{Display, Formatter};

use clap::Args;
use libvm::{MachineRef, Runtime};

use crate::config::GlobalConfig;
use crate::progress::Progress;

#[derive(Args, Debug)]
#[command(about = "Remove a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to remove.
    #[arg(value_name = "VM")]
    pub name: String,
    /// Stop the VM first if it is running.
    #[arg(long)]
    pub force: bool,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime, config: &GlobalConfig) -> eyre::Result<()> {
        let progress = Progress::start(format!("finding {}", self.name));
        let machine = libvm
            .get_machine(&MachineRef::parse(self.name.clone())?)
            .await?;
        let inspect_data = machine.inspect().await?;
        let machine_name = inspect_data.name;
        let removed_default = config.default_machine() == Some(machine_name.as_str());
        if self.force {
            progress.step(format!("stopping {} before removal", self.name));
            match machine.stop().await {
                Ok(_) => {}
                Err(err) if err.to_string().contains("is not running") => {
                    progress.step(format!("{} was already stopped", self.name));
                }
                Err(err) => return Err(err.into()),
            }
        }
        progress.step(format!("removing {}", self.name));
        machine.remove().await?;
        progress.clear();
        println!("removed {machine_name}");
        if removed_default {
            GlobalConfig::write_default_machine(None)?;
            println!("removed default machine. Set a new one with `bento default <vm>`.");
        }
        Ok(())
    }
}
