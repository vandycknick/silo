use std::io::Write;

use clap::Args;
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
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let (_name, machine) = context.machine(self.name.as_deref()).await?;
        let mut logs = machine
            .logs(
                MachineLogSource::Monitor,
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
    fn logs_accepts_a_vm_and_follow() {
        let cli = Cli::try_parse_from(["silo", "logs", "vm", "--follow"])
            .expect("logs with follow should parse");
        let Command::Logs(logs) = cli.command else {
            panic!("logs command should parse");
        };

        assert_eq!(logs.name.as_deref(), Some("vm"));
        assert!(logs.follow);
    }

    #[test]
    fn logs_rejects_source_selection() {
        assert!(Cli::try_parse_from(["silo", "logs", "vm", "--source", "serial"]).is_err());
    }
}
