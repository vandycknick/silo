use eyre::Context;

use crate::provision::{command_exists, run_command, write_file, ProvisionContext};

pub(crate) fn apply(context: &ProvisionContext, hostname: Option<&str>) -> eyre::Result<()> {
    let Some(hostname) = hostname
        .map(str::trim)
        .filter(|hostname| !hostname.is_empty())
    else {
        return Ok(());
    };

    let hostname_path = context.guest_path("/etc/hostname");
    write_file(&hostname_path, format!("{hostname}\n"), 0o644)?;
    nix::unistd::sethostname(hostname).context("set kernel hostname")?;

    if command_exists("hostnamectl") {
        run_command("hostnamectl", ["set-hostname", hostname])?;
    }

    tracing::info!(hostname, "provisioned hostname");
    Ok(())
}
