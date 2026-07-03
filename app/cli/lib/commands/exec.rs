use clap::Args;
use eyre::bail;
use libvm::MachineData;

use crate::context::Context;
use crate::guest;

#[derive(Debug, Args)]
#[command(about = "Execute a command in a running VM")]
pub struct Cmd {
    /// Name or ID of the running VM. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    pub name: Option<String>,

    /// Guest user for the command.
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Forward the host SSH agent into the guest command.
    #[arg(long, short = 'A')]
    pub forward_agent: bool,

    /// Attach a TTY to the guest command.
    #[arg(long, short = 't')]
    pub tty: bool,

    /// Guest command and arguments to execute after `--`.
    #[arg(required = true, last = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        if self.command.is_empty() {
            bail!("command is required; pass it after `--`");
        }

        let (_reference, machine) = context.machine(self.name.as_deref()).await?;
        let inspect_data = machine.inspect().await?;

        ensure_running(&inspect_data)?;
        ensure_guest_ready(&inspect_data)?;

        let status = if self.tty {
            guest::attach_command(
                &machine,
                self.user.as_deref(),
                &self.command,
                self.forward_agent,
            )
            .await?
        } else {
            guest::run_command_streaming(
                &machine,
                self.user.as_deref(),
                &self.command,
                self.forward_agent,
            )
            .await?
        };
        std::process::exit(status.code);
    }
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
    use crate::commands::Command;

    #[test]
    fn exec_command_parses_trailing_args() {
        let cli = Cli::try_parse_from([
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

        let Command::Exec(exec) = cli.command else {
            panic!("expected exec command");
        };

        assert_eq!(exec.name.as_deref(), Some("arch"));
        assert!(!exec.forward_agent);
        assert!(!exec.tty);
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
        let cli = Cli::try_parse_from(["bento", "exec", "--", "make", "kernel"])
            .expect("exec command should parse");

        let Command::Exec(exec) = cli.command else {
            panic!("expected exec command");
        };

        assert_eq!(exec.name, None);
        assert!(!exec.forward_agent);
        assert!(!exec.tty);
        assert_eq!(exec.command, vec!["make".to_string(), "kernel".to_string()]);
    }

    #[test]
    fn exec_command_parses_forward_agent() {
        let cli = Cli::try_parse_from(["bento", "exec", "-A", "arch", "--", "git", "fetch"])
            .expect("exec command should parse");

        let Command::Exec(exec) = cli.command else {
            panic!("expected exec command");
        };

        assert_eq!(exec.name.as_deref(), Some("arch"));
        assert!(exec.forward_agent);
        assert!(!exec.tty);
        assert_eq!(exec.command, vec!["git".to_string(), "fetch".to_string()]);
    }

    #[test]
    fn exec_command_parses_tty_and_forward_agent() {
        let cli = Cli::try_parse_from(["bento", "exec", "-A", "-t", "dev", "--", "opencode"])
            .expect("exec command should parse");

        let Command::Exec(exec) = cli.command else {
            panic!("expected exec command");
        };

        assert_eq!(exec.name.as_deref(), Some("dev"));
        assert!(exec.forward_agent);
        assert!(exec.tty);
        assert_eq!(exec.command, vec!["opencode".to_string()]);
    }
}
