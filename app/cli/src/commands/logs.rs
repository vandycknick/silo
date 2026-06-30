use std::fmt::{Display, Formatter};
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

use clap::Args;
use libvm::Runtime;

use crate::commands::get_machine;
use crate::config::GlobalConfig;

#[derive(Args, Debug)]
#[command(about = "Show VM logs")]
pub struct Cmd {
    /// Name or ID of the VM whose logs should be shown. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    pub name: Option<String>,
    /// Continue streaming logs as they are written.
    #[arg(long)]
    pub follow: bool,
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
        let (_name, machine) = get_machine(libvm, config, self.name.as_deref()).await?;
        let inspect_data = machine.inspect().await?;
        let path = inspect_data.trace_log_path();
        if !path.exists() {
            return Ok(());
        }
        if !self.follow {
            print!("{}", std::fs::read_to_string(path)?);
            return Ok(());
        }

        let mut file = std::fs::File::open(&path)?;
        let mut pos = file.seek(SeekFrom::Start(0))?;
        loop {
            file.seek(SeekFrom::Start(pos))?;
            let mut buf = String::new();
            file.read_to_string(&mut buf)?;
            if !buf.is_empty() {
                print!("{buf}");
                pos += buf.len() as u64;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
