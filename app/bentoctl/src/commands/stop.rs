use bento_libvm::{MachineRef, Runtime};
use clap::Args;
use std::fmt::{Display, Formatter};

#[derive(Args, Debug)]
#[command(about = "Stop a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to stop.
    #[arg(value_name = "VM")]
    pub name: String,
    /// Force stop if graceful shutdown support is unavailable.
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
        machine.stop().await?;
        Ok(())
    }
}
