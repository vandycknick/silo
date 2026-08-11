use std::time::Duration;

use clap::Args;
use libvm::{MachineKillOptions, MachineStatus, MachineStopOptions};

use crate::context::Context;
use crate::ui::Spinner;

#[derive(Debug, Args)]
#[command(about = "Stop a persistent VM")]
pub struct Cmd {
    /// Name or ID of the VM to stop. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    name: Option<String>,

    /// Force stop instead of asking the VM to shut down.
    #[arg(long)]
    force: bool,

    /// Maximum time to wait for the VM to stop, for example 30s or 2m.
    #[arg(long, default_value = "45s", value_parser = parse_timeout)]
    timeout: Duration,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mut spinner = Spinner::start("Finding", self.name.as_deref().unwrap_or("default VM"));
        let (name, machine) = context.machine(self.name.as_deref()).await?;
        let data = machine.inspect().await?;

        if matches!(
            data.status,
            MachineStatus::Stopped | MachineStatus::Error { .. }
        ) {
            spinner.step("Stopped", &name);
            spinner.finish_success("Stopped");
            return Ok(());
        }

        if self.force {
            spinner.step("Killing", &name);
            machine
                .kill_with(MachineKillOptions::new().timeout(self.timeout))
                .await?;
        } else {
            spinner.step("Stopping", &name);
            machine
                .stop_with(MachineStopOptions::new().timeout(self.timeout))
                .await?;
        }

        spinner.step("Stopped", &name);
        spinner.finish_success("Stopped");
        Ok(())
    }
}

pub(crate) fn parse_timeout(value: &str) -> Result<Duration, String> {
    let (amount, unit) = value
        .strip_suffix("ms")
        .map(|amount| (amount, "ms"))
        .or_else(|| value.strip_suffix('s').map(|amount| (amount, "s")))
        .or_else(|| value.strip_suffix('m').map(|amount| (amount, "m")))
        .or_else(|| value.strip_suffix('h').map(|amount| (amount, "h")))
        .unwrap_or((value, "s"));
    let amount = amount
        .parse::<u64>()
        .map_err(|_| "timeout must be a positive duration such as 30s or 2m".to_string())?;
    if amount == 0 {
        return Err("timeout must be greater than zero".to_string());
    }

    let timeout = match unit {
        "ms" => Duration::from_millis(amount),
        "s" => Duration::from_secs(amount),
        "m" => amount
            .checked_mul(60)
            .map(Duration::from_secs)
            .ok_or_else(|| "timeout is too large".to_string())?,
        "h" => amount
            .checked_mul(60 * 60)
            .map(Duration::from_secs)
            .ok_or_else(|| "timeout is too large".to_string())?,
        _ => return Err("timeout must use ms, s, m, or h".to_string()),
    };
    Ok(timeout)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use libvm::DEFAULT_MACHINE_WAIT_TIMEOUT;

    use crate::app::Cli;
    use crate::commands::stop::parse_timeout;
    use crate::commands::Command;

    #[test]
    fn stop_parses_force_and_timeout() {
        let cli = Cli::try_parse_from(["silo", "stop", "vm", "--force", "--timeout", "2m"])
            .expect("stop command should parse");

        let Command::Stop(stop) = cli.command else {
            panic!("expected stop command");
        };
        assert!(stop.force);
        assert_eq!(stop.timeout, Duration::from_secs(120));
    }

    #[test]
    fn timeout_parser_accepts_cli_duration_units() {
        assert_eq!(
            parse_timeout("250ms").expect("milliseconds"),
            Duration::from_millis(250)
        );
        assert_eq!(
            parse_timeout("30").expect("seconds"),
            Duration::from_secs(30)
        );
        assert!(parse_timeout("0s").is_err());
        assert!(parse_timeout("soon").is_err());
    }

    #[test]
    fn stop_default_timeout_matches_libvm() {
        let cli = Cli::try_parse_from(["silo", "stop", "vm"]).expect("stop command should parse");

        let Command::Stop(stop) = cli.command else {
            panic!("expected stop command");
        };
        assert_eq!(stop.timeout, DEFAULT_MACHINE_WAIT_TIMEOUT);
    }
}
