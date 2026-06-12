use bento_libvm::{MachineRef, Runtime, DEFAULT_GUEST_READINESS_TIMEOUT};
use clap::Args;
use std::fmt::{Display, Formatter};

#[derive(Args, Debug)]
#[command(about = "Start a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to start.
    #[arg(value_name = "VM")]
    pub name: String,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let machine_ref = MachineRef::parse(self.name.clone())?;
        let machine = libvm.get_machine(&machine_ref).await?;
        machine.start().await?;

        machine
            .wait_for_guest_running(DEFAULT_GUEST_READINESS_TIMEOUT)
            .await
            .map_err(|err| eyre::eyre!("guest readiness check failed: {err}"))?;

        Ok(())
    }
}
