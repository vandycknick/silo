use std::fs;
use std::os::unix::fs::symlink;

use eyre::Context;

use crate::provision::{write_file, ProvisionContext};

pub(crate) fn apply(context: &ProvisionContext, timezone: Option<&str>) -> eyre::Result<()> {
    let Some(timezone) = timezone
        .map(str::trim)
        .filter(|timezone| !timezone.is_empty())
    else {
        return Ok(());
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
            Err(err) => return Err(err).with_context(|| format!("remove {}", localtime.display())),
        }
        symlink(&zoneinfo, &localtime)
            .with_context(|| format!("link {} to {zoneinfo}", localtime.display()))?;
    }

    tracing::info!(timezone, "reconciled timezone");
    Ok(())
}
