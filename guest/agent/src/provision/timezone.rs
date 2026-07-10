use std::fs;
use std::os::unix::fs::symlink;

use eyre::Context;

use crate::provision::{
    write_file, ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
};

pub(crate) struct Timezone<'a> {
    timezone: Option<&'a str>,
}

impl<'a> Provisioner<'a> for Timezone<'a> {
    type Config = Option<String>;

    fn init(config: &'a Self::Config) -> Self {
        Self {
            timezone: config
                .as_deref()
                .map(str::trim)
                .filter(|timezone| !timezone.is_empty()),
        }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::TIMEZONE
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        let Some(timezone) = self.timezone else {
            return Ok(ProvisionOutcome::skipped("no timezone configured"));
        };

        write_file(
            &context.guest_path("/etc/timezone"),
            format!("{timezone}\n"),
            0o644,
        )?;

        let zoneinfo = format!("/usr/share/zoneinfo/{timezone}");
        let localtime = context.guest_path("/etc/localtime");
        if context.guest_path(&zoneinfo).exists() {
            match fs::remove_file(&localtime) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| format!("remove {}", localtime.display()))
                }
            }
            symlink(&zoneinfo, &localtime)
                .with_context(|| format!("link {} to {zoneinfo}", localtime.display()))?;
        }

        tracing::info!(timezone, "reconciled timezone");
        Ok(ProvisionOutcome::succeeded(false))
    }
}
