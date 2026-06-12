use std::fmt::{Display, Formatter};

use bento_libvm::{MachineRef, Runtime};
use clap::Args;

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
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let machine = libvm
            .get_machine(&MachineRef::parse(self.name.clone())?)
            .await?;
        if self.force {
            match machine.stop().await {
                Ok(_) => {}
                Err(err) if err.to_string().contains("is not running") => {}
                Err(err) => return Err(err.into()),
            }
        }
        machine.remove().await?;
        println!("removed {}", self.name);
        Ok(())
    }
}
