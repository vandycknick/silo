use clap::Args;
use libvm::Runtime;
use std::fmt::{Display, Formatter};

use crate::commands::get_machine;
use crate::config::GlobalConfig;
use crate::progress::Progress;

#[derive(Args, Debug)]
#[command(about = "Stop a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to stop. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    pub name: Option<String>,
    /// Force stop if graceful shutdown support is unavailable.
    #[arg(long)]
    pub force: bool,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.name.as_deref() {
            Some(name) => f.write_str(name),
            None => Ok(()),
        }
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime, config: &GlobalConfig) -> eyre::Result<()> {
        let name = self.name.as_deref();
        let progress = Progress::start(match name {
            Some(name) => format!("finding {name}"),
            None => "finding default VM".to_string(),
        });
        let (name, machine) = get_machine(libvm, config, name).await?;
        progress.step(format!("asking {name} to power down"));
        machine.stop().await?;
        progress.success(format!("{name} stopped"));
        Ok(())
    }
}
