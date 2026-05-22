use bento_libvm::{LibVm, MachineRecord, MachineRef};
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
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        let machine_ref = MachineRef::parse(self.name.clone())?;
        let machine = libvm.start(&machine_ref).await?;

        if requires_guest_readiness(&machine) {
            libvm
                .wait_for_guest_running(
                    &MachineRef::Id(machine.id),
                    bento_libvm::DEFAULT_GUEST_READINESS_TIMEOUT,
                )
                .await
                .map_err(|err| eyre::eyre!("guest readiness check failed: {err}"))?;
        }

        Ok(())
    }
}

fn requires_guest_readiness(machine: &MachineRecord) -> bool {
    machine.spec.guest_agent().is_some()
}
