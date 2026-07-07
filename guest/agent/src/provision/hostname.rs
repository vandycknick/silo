use eyre::Context;

use crate::provision::{
    command_exists, run_command, write_file, ProvisionContext, ProvisionOutcome,
};

pub(crate) fn apply(
    context: &ProvisionContext,
    hostname: Option<&str>,
) -> eyre::Result<ProvisionOutcome> {
    let Some(hostname) = hostname
        .map(str::trim)
        .filter(|hostname| !hostname.is_empty())
    else {
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
