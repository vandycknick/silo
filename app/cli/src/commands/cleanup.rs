use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use clap::Args;
use libvm::{MachineRef, Runtime};

#[derive(Args, Debug)]
#[command(hide = true)]
pub struct Cmd {
    #[arg(long = "data-dir")]
    pub data_dir: PathBuf,

    #[arg(long = "machine-id")]
    pub machine_id: String,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "--data-dir {} --machine-id {}",
            self.data_dir.display(),
            self.machine_id
        )
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let machine_ref = MachineRef::parse(self.machine_id.clone())?;
        let machine = libvm.get_machine(&machine_ref).await?;
        machine.cleanup().await?;
        Ok(())
    }
}
