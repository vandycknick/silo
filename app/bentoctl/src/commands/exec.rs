use std::fmt::{Display, Formatter};

use bento_libvm::{Machine, MachineRef, Runtime};
use clap::Args;
use eyre::bail;

use bento_protocol::v1::LifecycleState;

use crate::ssh;

#[derive(Args, Debug)]
#[command(about = "Execute a command in a running VM")]
pub struct Cmd {
    /// Name or ID of the running VM.
    #[arg(value_name = "VM")]
    pub name: String,

    /// Guest user for the command.
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Guest command and arguments to execute after `--`.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.user.as_deref() {
            Some(user) => write!(
                f,
                "{} --user {} -- {}",
                self.name,
                user,
                self.command.join(" ")
            ),
            None => write!(f, "{} -- {}", self.name, self.command.join(" ")),
        }
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let machine = libvm
            .get_machine(&MachineRef::parse(self.name.clone())?)
            .await?;
        let inspection = machine.inspect().await?;

        if !inspection.state.status.is_running() {
            return Err(bento_libvm::LibVmError::MachineNotRunning {
                reference: self.name.clone(),
            }
            .into());
        }

        ensure_guest_ready(&machine).await?;

        let status = ssh::run_remote_command(&self.name, self.user.as_deref(), &self.command)?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

async fn ensure_guest_ready(machine: &Machine) -> eyre::Result<()> {
    let status = machine.get_status().await?;
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::commands::{BentoCtlCmd, Command};

    #[test]
    fn exec_command_parses_trailing_args() {
        let cmd = BentoCtlCmd::try_parse_from([
            "bentoctl",
            "exec",
            "arch",
            "--",
            "make",
            "kernel",
            "TRACK=stable",
            "ARCH=arm64",
        ])
        .expect("exec command should parse");

        let exec = match cmd.cmd {
            Command::Exec(cmd) => cmd,
            other => panic!("expected exec command, got {other:?}"),
        };

        assert_eq!(exec.name, "arch");
        assert_eq!(
            exec.command,
            vec!["make", "kernel", "TRACK=stable", "ARCH=arm64"]
        );
    }
}
