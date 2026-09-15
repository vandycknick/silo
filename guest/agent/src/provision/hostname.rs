use eyre::Context;

use crate::provision::{
    write_file, ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
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

        tracing::info!(hostname, path = %hostname_path.display(), "reconciled hostname");
        Ok(ProvisionOutcome::succeeded(false))
    }
}
