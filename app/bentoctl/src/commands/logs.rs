use std::fmt::{Display, Formatter};
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

use bento_core::InstanceFile;
use bento_libvm::{LibVm, MachineRef};
use clap::Args;

#[derive(Args, Debug)]
#[command(about = "Show VM logs")]
pub struct Cmd {
    /// Name or ID of the VM whose logs should be shown.
    #[arg(value_name = "VM")]
    pub name: String,
    /// Continue streaming logs as they are written.
    #[arg(long)]
    pub follow: bool,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        let machine = libvm.inspect(&MachineRef::parse(self.name.clone())?)?;
        let path = machine.dir.join(InstanceFile::VmmonTraceLog.as_str());
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
