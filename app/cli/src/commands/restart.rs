use std::fmt::{Display, Formatter};

use clap::Args;
use libvm::{Runtime, DEFAULT_GUEST_READINESS_TIMEOUT};

use crate::commands::{get_machine, start_options::machine_start_options};
use crate::config::GlobalConfig;
use crate::progress::Progress;

#[derive(Args, Debug)]
#[command(about = "Restart a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to restart. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    pub name: Option<String>,
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
        progress.step(format!("stopping {name}"));
        match machine.stop().await {
            Ok(_) => {}
            Err(err) if err.to_string().contains("is not running") => {
                progress.step(format!("{name} was already stopped"));
            }
            Err(err) => return Err(err.into()),
        }
        progress.step(format!("starting {name}"));
        let inspect_data = machine
            .start_with(machine_start_options(libvm, &machine)?)
            .await?;
        progress.step(format!("waiting for guest agent in {name}"));
        machine
            .wait_for_guest_running(DEFAULT_GUEST_READINESS_TIMEOUT)
            .await
            .map_err(|err| eyre::eyre!("guest readiness check failed: {err}"))?;
        progress.success(format!("{} is back", inspect_data.name));
        Ok(())
    }
}
