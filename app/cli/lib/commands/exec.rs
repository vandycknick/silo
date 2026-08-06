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
            guest::attach_command(&machine, self.user.as_deref(), &self.command).await?
        } else {
            guest::run_command_streaming(&machine, self.user.as_deref(), &self.command).await?
        };
        if let Some(message) = execution_failure_message(&status) {
            eprintln!("{} {message}", crate::ui::error_label());
        }
        std::process::exit(execution_exit_code(status));
    }
}

fn execution_failure_message(result: &libvm::ExecutionResult) -> Option<String> {
    match result {
        libvm::ExecutionResult::LaunchFailed(failure) => {
            let reason = match failure.reason {
                libvm::ExecutionLaunchFailureReason::Unspecified => "unspecified launch failure",
                libvm::ExecutionLaunchFailureReason::CommandNotFound => "command not found",
                libvm::ExecutionLaunchFailureReason::InvalidProcessSpec => {
                    "invalid process specification"
                }
                libvm::ExecutionLaunchFailureReason::WorkingDirectoryNotFound => {
                    "working directory not found"
                }
                libvm::ExecutionLaunchFailureReason::WorkingDirectoryNotDirectory => {
                    "working directory is not a directory"
                }
                libvm::ExecutionLaunchFailureReason::InvalidIdentity => "invalid user or group",
                libvm::ExecutionLaunchFailureReason::IdentityNotFound => "user or group not found",
                libvm::ExecutionLaunchFailureReason::PermissionDenied => "permission denied",
                libvm::ExecutionLaunchFailureReason::SpawnFailed => "process spawn failed",
                libvm::ExecutionLaunchFailureReason::CancelledBeforeStart => {
                    "cancelled before start"
                }
            };
            Some(match failure.message.as_deref() {
                Some(message) => format!("guest command launch failed ({reason}): {message}"),
                None => format!("guest command launch failed ({reason})"),
            })
        }
        libvm::ExecutionResult::Lost(lost) => Some(match lost.message.as_deref() {
            Some(message) => format!("guest command was lost: {message}"),
            None => format!("guest command was lost ({:?})", lost.reason),
        }),
        libvm::ExecutionResult::Exited { .. } | libvm::ExecutionResult::Signaled { .. } => None,
    }
}

fn execution_exit_code(result: libvm::ExecutionResult) -> i32 {
    match result {
        libvm::ExecutionResult::Exited { code: Some(code) } => {
            i32::try_from(code).map_or(125, |code| code)
        }
        libvm::ExecutionResult::Exited { code: None }
        | libvm::ExecutionResult::Signaled { signal: None }
        | libvm::ExecutionResult::Lost(_) => 125,
        libvm::ExecutionResult::Signaled {
            signal: Some(signal),
        } => i32::try_from(128_u32.saturating_add(signal)).map_or(125, |code| code),
        libvm::ExecutionResult::LaunchFailed(failure)
            if failure.reason == libvm::ExecutionLaunchFailureReason::CommandNotFound =>
        {
            127
        }
        libvm::ExecutionResult::LaunchFailed(_) => 126,
    }
}

fn ensure_running(data: &MachineData) -> eyre::Result<()> {
    if data.is_running() {
        return Ok(());
    }

    Err(eyre::eyre!(
        "machine `{}` is not running; start it with `silo start {}`",
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
    use crate::commands::exec::{execution_exit_code, execution_failure_message};
    use crate::commands::Command;

    #[test]
    fn exec_command_parses_trailing_args() {
        let cli = Cli::try_parse_from([
            "silo",
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
        let cli = Cli::try_parse_from(["silo", "exec", "--", "make", "kernel"])
            .expect("exec command should parse");

        let Command::Exec(exec) = cli.command else {
            panic!("expected exec command");
        };

        assert_eq!(exec.name, None);
        assert!(!exec.tty);
        assert_eq!(exec.command, vec!["make".to_string(), "kernel".to_string()]);
    }

    #[test]
    fn exec_command_rejects_ssh_agent_forwarding() {
        assert!(Cli::try_parse_from(["silo", "exec", "-A", "arch", "--", "git", "fetch"]).is_err());
    }

    #[test]
    fn execution_results_use_the_documented_cli_exit_codes() {
        assert_eq!(
            execution_exit_code(libvm::ExecutionResult::Exited { code: Some(42) }),
            42
        );
        assert_eq!(
            execution_exit_code(libvm::ExecutionResult::Signaled { signal: Some(15) }),
            143
        );
        assert_eq!(
            execution_exit_code(libvm::ExecutionResult::LaunchFailed(
                libvm::ExecutionLaunchFailure {
                    reason: libvm::ExecutionLaunchFailureReason::CommandNotFound,
                    message: None,
                }
            )),
            127
        );
        assert_eq!(
            execution_exit_code(libvm::ExecutionResult::LaunchFailed(
                libvm::ExecutionLaunchFailure {
                    reason: libvm::ExecutionLaunchFailureReason::SpawnFailed,
                    message: None,
                }
            )),
            126
        );
        assert_eq!(
            execution_exit_code(libvm::ExecutionResult::Lost(libvm::ExecutionLost {
                reason: libvm::ExecutionLostReason::GuestStreamLost,
                message: None,
            })),
            125
        );
    }

    #[test]
    fn launch_failures_and_lost_executions_have_stderr_messages() {
        let launch_failure = libvm::ExecutionResult::LaunchFailed(libvm::ExecutionLaunchFailure {
            reason: libvm::ExecutionLaunchFailureReason::IdentityNotFound,
            message: Some("user `nickvd` was not found".to_string()),
        });
        assert_eq!(
            execution_failure_message(&launch_failure).as_deref(),
            Some(
                "guest command launch failed (user or group not found): user `nickvd` was not found"
            )
        );

        let lost = libvm::ExecutionResult::Lost(libvm::ExecutionLost {
            reason: libvm::ExecutionLostReason::AgentUnavailable,
            message: Some("guest agent is no longer ready".to_string()),
        });
        assert_eq!(
            execution_failure_message(&lost).as_deref(),
            Some("guest command was lost: guest agent is no longer ready")
        );

        assert_eq!(
            execution_failure_message(&libvm::ExecutionResult::Exited { code: Some(1) }),
            None
        );
    }
}
