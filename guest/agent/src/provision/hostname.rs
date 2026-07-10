use eyre::Context;

use crate::provision::{
    command_exists, run_command, write_file, ProvisionContext, ProvisionOutcome, Provisioner,
    ProvisionerId,
};

pub(crate) struct Hostname<'a> {
    hostname: Option<&'a str>,
}

impl<'a> Provisioner<'a> for Hostname<'a> {
    type Config = Option<String>;

    fn init(config: &'a Self::Config) -> Self {
        Self {
            hostname: config
                .as_deref()
                .map(str::trim)
                .filter(|hostname| !hostname.is_empty()),
        }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::HOSTNAME
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        let Some(hostname) = self.hostname else {
            return Ok(ProvisionOutcome::skipped("no hostname configured"));
        };

        let hostname_path = context.guest_path("/etc/hostname");
        write_file(&hostname_path, format!("{hostname}\n"), 0o644)?;
        nix::unistd::sethostname(hostname).context("set kernel hostname")?;

        if command_exists("hostnamectl") {
            let readiness = context
                .service_manager()
                .wait_for_systemd(context.process_supervisor());
            if readiness.is_ready() {
                run_command(
                    context.process_supervisor(),
                    "hostnamectl",
                    ["set-hostname", hostname],
                )?;
            } else {
                tracing::info!(
                    reason = readiness.message(),
                    "skipping hostnamectl because systemd manager is not ready"
                );
                tracing::info!(hostname, path = %hostname_path.display(), "reconciled hostname");
                return Ok(ProvisionOutcome::Succeeded {
                    changed: false,
                    message: format!(
                        "reconciled hostname; skipped hostnamectl: {}",
                        readiness.message()
                    ),
                });
            }
        }

        tracing::info!(hostname, path = %hostname_path.display(), "reconciled hostname");
        Ok(ProvisionOutcome::succeeded(false))
    }
}
