use bento_libvm::{MachineData, Runtime};
use clap::{Args, ValueEnum};
use eyre::bail;
use std::fmt::{Display, Formatter};

use crate::commands::{get_machine, not_running_error};
use crate::config::GlobalConfig;
use crate::ssh;
use crate::terminal;

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum AttachMode {
    Shell,
    Serial,
}

#[derive(Args, Debug)]
#[command(about = "Open a shell in a running VM")]
pub struct Cmd {
    /// Name or ID of the running VM. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    pub name: Option<String>,

    /// Guest user for the shell session.
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Attach through the guest shell or serial console.
    #[arg(long, value_enum)]
    pub attach: Option<AttachMode>,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = self.name.as_deref().unwrap_or("<default>");
        match (self.user.as_deref(), self.attach) {
            (Some(user), Some(attach)) => {
                write!(f, "{} --user {} --attach {}", name, user, attach)
            }
            (Some(user), None) => write!(f, "{} --user {}", name, user),
            (None, Some(attach)) => write!(f, "{} --attach {}", name, attach),
            (None, None) => write!(f, "{}", name),
        }
    }
}

impl Display for AttachMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachMode::Shell => write!(f, "shell"),
            AttachMode::Serial => write!(f, "serial"),
        }
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime, config: &GlobalConfig) -> eyre::Result<()> {
        let (_reference, machine) = get_machine(libvm, config, self.name.as_deref()).await?;
        let inspect_data = machine.inspect().await?;
        let machine_name = inspect_data.name.clone();

        if !inspect_data.is_running() {
            return Err(not_running_error(&machine_name));
        }

        if self.attach == Some(AttachMode::Serial) {
            if self.user.is_some() {
                eprintln!("[bento] --user is ignored for serial attach");
            }
            let stream = machine.open_serial_stream().await?;
            return terminal::attach_serial_stream(stream).await;
        }

        ensure_guest_ready(&inspect_data)?;
        ssh::exec_remote_shell(&machine_name, self.user.as_deref())
    }
}

fn ensure_guest_ready(data: &MachineData) -> eyre::Result<()> {
    if !data.status.guest_ready() {
        let summary = data
            .status
            .message()
            .map(str::to_string)
            .unwrap_or_else(|| format!("machine state is {}", data.status.label()));
        bail!("guest service is not ready: {summary}");
    }

    Ok(())
}
