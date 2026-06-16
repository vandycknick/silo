use std::fmt::{Display, Formatter};

use bento_libvm::{MachineData, Runtime};
use clap::Args;
use eyre::bail;

use crate::commands::{get_machine, not_running_error};
use crate::config::GlobalConfig;
use crate::ssh;

#[derive(Args, Debug)]
#[command(about = "Execute a command in a running VM")]
pub struct Cmd {
    /// Name or ID of the running VM. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    pub name: Option<String>,

    /// Guest user for the command.
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Guest command and arguments to execute after `--`.
    #[arg(required = true, last = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = self.name.as_deref().unwrap_or("<default>");
        match self.user.as_deref() {
            Some(user) => write!(f, "{} --user {} -- {}", name, user, self.command.join(" ")),
            None => write!(f, "{} -- {}", name, self.command.join(" ")),
        }
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime, config: &GlobalConfig) -> eyre::Result<()> {
        if self.command.is_empty() {
            bail!("command is required; pass it after `--`");
        }

        let (_reference, machine) = get_machine(libvm, config, self.name.as_deref()).await?;
        let inspect_data = machine.inspect().await?;
        let machine_name = inspect_data.name.clone();

        if !inspect_data.is_running() {
            return Err(not_running_error(&machine_name));
        }

        ensure_guest_ready(&inspect_data)?;

        let status = ssh::run_remote_command(&machine_name, self.user.as_deref(), &self.command)?;
        std::process::exit(status.code().unwrap_or(1));
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::commands::{BentoCmd, Command};

    #[test]
    fn exec_command_parses_trailing_args() {
        let cmd = BentoCmd::try_parse_from([
            "bento",
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

        assert_eq!(exec.name.as_deref(), Some("arch"));
        assert_eq!(
            exec.command,
            vec![
                "make".to_string(),
                "kernel".to_string(),
                "TRACK=stable".to_string(),
                "ARCH=arm64".to_string(),
            ]
        );
    }

    #[test]
    fn exec_command_parses_default_machine_form() {
        let cmd = BentoCmd::try_parse_from(["bento", "exec", "--", "make", "kernel"])
            .expect("exec command should parse");

        let exec = match cmd.cmd {
            Command::Exec(cmd) => cmd,
            other => panic!("expected exec command, got {other:?}"),
        };

        assert_eq!(exec.name, None);
        assert_eq!(exec.command, vec!["make".to_string(), "kernel".to_string()]);
    }
}
