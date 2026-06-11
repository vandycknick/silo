use bento_libvm::{LibVm, MachineRef};
use clap::{Args, ValueEnum};
use eyre::bail;
use std::fmt::{Display, Formatter};

use bento_protocol::v1::LifecycleState;

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
    /// Name or ID of the running VM.
    #[arg(value_name = "VM")]
    pub name: String,

    /// Guest user for the shell session.
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Attach through the guest shell or serial console.
    #[arg(long, value_enum)]
    pub attach: Option<AttachMode>,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match (self.user.as_deref(), self.attach) {
            (Some(user), Some(attach)) => {
                write!(f, "{} --user {} --attach {}", self.name, user, attach)
            }
            (Some(user), None) => write!(f, "{} --user {}", self.name, user),
            (None, Some(attach)) => write!(f, "{} --attach {}", self.name, attach),
            (None, None) => write!(f, "{}", self.name),
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
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        let machine_ref = MachineRef::parse(self.name.clone())?;
        let machine = libvm.inspect(&machine_ref).await?;

        if !machine.is_running() {
            return Err(bento_libvm::LibVmError::MachineNotRunning {
                reference: self.name.clone(),
            }
            .into());
        }

        match self.attach {
            Some(AttachMode::Serial) => {
                if self.user.is_some() {
                    eprintln!("[bento] --user is ignored for serial attach");
                }
                let stream = libvm
                    .open_serial_stream(&MachineRef::Id(machine.id))
                    .await?;
                return terminal::attach_serial_stream(stream).await;
            }
            Some(AttachMode::Shell) => {
                ensure_guest_ready(libvm, &machine).await?;
                return ssh::exec_remote_shell(&self.name, self.user.as_deref());
            }
            None => {}
        }

        ensure_guest_ready(libvm, &machine).await?;

        ssh::exec_remote_shell(&self.name, self.user.as_deref())
    }
}

async fn ensure_guest_ready(
    libvm: &LibVm,
    machine: &bento_libvm::MachineRecord,
) -> eyre::Result<()> {
    let status = libvm.get_status(&MachineRef::Id(machine.id)).await?;
    let guest_state =
        LifecycleState::try_from(status.guest_state).unwrap_or(LifecycleState::Unspecified);

    if guest_state != LifecycleState::Running || !status.ready {
        let summary = if status.summary.is_empty() {
            format!("guest state is {guest_state:?}")
        } else {
            status.summary
        };
        bail!("guest service is not ready: {summary}");
    }

    Ok(())
}
