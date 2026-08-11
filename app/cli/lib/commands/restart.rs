use std::time::{Duration, Instant};

use clap::Args;
use libvm::{
    MachineKillOptions, MachineReadinessOutcome, MachineStatus, MachineStopOptions,
    DEFAULT_GUEST_READINESS_TIMEOUT,
};

use crate::commands::start::{ensure_startable, requires_guest_readiness};
use crate::commands::start_options::machine_start_options;
use crate::commands::stop::parse_timeout;
use crate::context::Context;
use crate::ui::Spinner;

#[derive(Debug, Args)]
#[command(about = "Restart a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to restart. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    name: Option<String>,

    /// Force stop instead of asking the VM to shut down.
    #[arg(long)]
    force: bool,

    /// Total time allowed for stopping and readiness, for example 30s or 2m.
    #[arg(long, default_value = "45s", value_parser = parse_timeout)]
    timeout: Duration,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mut spinner = Spinner::start("Finding", self.name.as_deref().unwrap_or("default VM"));
        let (name, machine) = context.machine(self.name.as_deref()).await?;
        let data = machine.inspect().await?;
        if data.retention == libvm::MachineRetention::Ephemeral {
            eyre::bail!(
                "machine `{}` is ephemeral and cannot be restarted; use `silo run` instead",
                data.name
            );
        }
        if matches!(data.status, MachineStatus::Starting { .. }) {
            eyre::bail!(
                "machine `{}` is starting; wait for it to become ready",
                data.name
            );
        }
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| eyre::eyre!("restart timeout is too large"))?;

        if matches!(
            data.status,
            MachineStatus::Running { .. } | MachineStatus::Stopping { .. }
        ) {
            if self.force {
                spinner.step("Killing", &name);
                machine
                    .kill_with(MachineKillOptions::new().timeout(remaining(deadline)?))
                    .await?;
            } else {
                spinner.step("Stopping", &name);
                machine
                    .stop_with(MachineStopOptions::new().timeout(remaining(deadline)?))
                    .await?;
            }
        }

        let data = machine.inspect().await?;
        ensure_startable(&data)?;
        spinner.step("Starting", &name);
        let options = machine_start_options(context.runtime().await?, &machine).await?;
        let start = machine.start_with_options(options).await?;

        if requires_guest_readiness(&start.machine) {
            spinner.step("Waiting", &name);
            let timeout = remaining(deadline)?.min(DEFAULT_GUEST_READINESS_TIMEOUT);
            let readiness = machine.wait_ready(timeout).await?;
            if readiness.outcome != MachineReadinessOutcome::Ready {
                eyre::bail!("guest readiness check ended with {:?}", readiness.outcome);
            }
        }

        spinner.step("Ready", &start.machine.name);
        spinner.finish_success("Restarted");
        Ok(())
    }
}

fn remaining(deadline: Instant) -> eyre::Result<Duration> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        eyre::bail!("restart timed out before the VM became ready");
    }
    Ok(timeout)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use libvm::DEFAULT_MACHINE_WAIT_TIMEOUT;

    use crate::app::Cli;
    use crate::commands::Command;

    #[test]
    fn restart_parses_force_and_total_timeout() {
        let cli = Cli::try_parse_from(["silo", "restart", "vm", "--force", "--timeout", "90s"])
            .expect("restart command should parse");

        let Command::Restart(restart) = cli.command else {
            panic!("expected restart command");
        };
        assert!(restart.force);
        assert_eq!(restart.timeout, Duration::from_secs(90));
    }

    #[test]
    fn restart_default_timeout_matches_lifecycle_timeout() {
        let cli =
            Cli::try_parse_from(["silo", "restart", "vm"]).expect("restart command should parse");

        let Command::Restart(restart) = cli.command else {
            panic!("expected restart command");
        };
        assert_eq!(restart.timeout, DEFAULT_MACHINE_WAIT_TIMEOUT);
    }
}
