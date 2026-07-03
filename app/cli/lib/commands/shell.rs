use clap::{Args, ValueEnum};
use eyre::bail;
use libvm::MachineData;

use crate::context::Context;
use crate::guest;
use crate::terminal;
use crate::ui;

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum AttachMode {
    Shell,
    Serial,
}

#[derive(Debug, Args)]
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

    /// Forward the host SSH agent into the guest shell.
    #[arg(long, short = 'A')]
    pub forward_agent: bool,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let (_reference, machine) = context.machine(self.name.as_deref()).await?;
        let inspect_data = machine.inspect().await?;

        ensure_running(&inspect_data)?;

        if self.attach == Some(AttachMode::Serial) {
            reject_serial_forward_agent(self.forward_agent)?;
            if self.user.is_some() {
                ui::warn("--user is ignored for serial attach");
            }
            let stream = machine.open_serial_stream().await?;
            return terminal::attach_serial_stream(stream).await;
        }

        ensure_guest_ready(&inspect_data)?;
        let status =
            guest::attach_shell(&machine, self.user.as_deref(), self.forward_agent).await?;
        std::process::exit(status.code);
    }
}

fn reject_serial_forward_agent(forward_agent: bool) -> eyre::Result<()> {
    if forward_agent {
        bail!("--forward-agent cannot be used with serial attach");
    }

    Ok(())
}

fn ensure_running(data: &MachineData) -> eyre::Result<()> {
    if data.is_running() {
        return Ok(());
    }

    Err(eyre::eyre!(
        "machine `{}` is not running; start it with `bento start {}`",
        data.name,
        data.name
    ))
}

fn ensure_guest_ready(data: &MachineData) -> eyre::Result<()> {
    if data.status.guest_ready() {
        return Ok(());
    }

    let summary = data
        .status
        .message()
        .map(str::to_string)
        .unwrap_or_else(|| format!("machine state is {}", data.status.label()));
    bail!("guest service is not ready: {summary}");
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::app::Cli;
    use crate::commands::shell::{reject_serial_forward_agent, AttachMode};
    use crate::commands::Command;

    #[test]
    fn shell_command_parses_forward_agent() {
        let cli = Cli::try_parse_from(["bento", "shell", "-A", "dev"])
            .expect("shell command should parse");

        let Command::Shell(shell) = cli.command else {
            panic!("expected shell command");
        };

        assert_eq!(shell.name.as_deref(), Some("dev"));
        assert!(shell.forward_agent);
        assert_eq!(shell.attach, None);
    }

    #[test]
    fn shell_command_parses_serial_attach() {
        let cli = Cli::try_parse_from(["bento", "shell", "--attach", "serial"])
            .expect("shell command should parse");

        let Command::Shell(shell) = cli.command else {
            panic!("expected shell command");
        };

        assert_eq!(shell.attach, Some(AttachMode::Serial));
    }

    #[test]
    fn serial_attach_rejects_forward_agent() {
        let error = reject_serial_forward_agent(true).expect_err("forwarding should be rejected");

        assert_eq!(
            error.to_string(),
            "--forward-agent cannot be used with serial attach"
        );
    }
}
