use std::io::Write;

use clap::{Args, ValueEnum};
use libvm::{MachineLogOptions, MachineLogOutput, MachineLogSource};
use tokio_stream::StreamExt;

use crate::context::Context;

#[derive(Debug, Args)]
#[command(about = "Show VM logs")]
pub struct Cmd {
    /// Name or ID of the VM whose logs should be shown. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    name: Option<String>,

    /// Continue streaming logs as they are written.
    #[arg(long)]
    follow: bool,

    /// Log stream to show.
    #[arg(long, value_enum, default_value_t = LogStream::Monitor)]
    stream: LogStream,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum LogStream {
    Monitor,
    Exec,
    Serial,
    Network,
    #[value(name = "network-audit")]
    NetworkAudit,
}

impl From<LogStream> for MachineLogSource {
    fn from(value: LogStream) -> Self {
        match value {
            LogStream::Monitor => Self::Monitor,
            LogStream::Exec => Self::Exec,
            LogStream::Serial => Self::Serial,
            LogStream::Network => Self::Network,
            LogStream::NetworkAudit => Self::NetworkAudit,
        }
    }
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let (_name, machine) = context.machine(self.name.as_deref()).await?;
        let mut logs = machine
            .logs(
                self.stream.into(),
                MachineLogOptions {
                    follow: self.follow,
                },
            )
            .await?;
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let mut stdout = stdout.lock();
        let mut stderr = stderr.lock();

        while let Some(chunk) = logs.next().await {
            let chunk = chunk?;
            match chunk.output {
                MachineLogOutput::Stdout => {
                    stdout.write_all(chunk.data.as_ref())?;
                    stdout.flush()?;
                }
                MachineLogOutput::Stderr => {
                    stderr.write_all(chunk.data.as_ref())?;
                    stderr.flush()?;
                }
                _ => return Err(eyre::eyre!("unsupported machine log output")),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::app::Cli;
    use crate::commands::Command;

    #[test]
    fn logs_accepts_a_vm_stream_and_follow() {
        let cli = Cli::try_parse_from(["silo", "logs", "vm", "--stream", "serial", "--follow"])
            .expect("logs with follow should parse");
        let Command::Logs(logs) = cli.command else {
            panic!("logs command should parse");
        };

        assert_eq!(logs.name.as_deref(), Some("vm"));
        assert!(logs.follow);
        assert_eq!(logs.stream, super::LogStream::Serial);
    }

    #[test]
    fn logs_defaults_to_monitor_stream() {
        let cli = Cli::try_parse_from(["silo", "logs", "vm"]).expect("logs should parse");

        let Command::Logs(logs) = cli.command else {
            panic!("logs command should parse");
        };
        assert_eq!(logs.stream, super::LogStream::Monitor);
    }

    #[test]
    fn logs_rejects_unknown_stream() {
        assert!(Cli::try_parse_from(["silo", "logs", "vm", "--stream", "host"]).is_err());
    }
}
