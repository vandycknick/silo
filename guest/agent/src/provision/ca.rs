use agent_spec::CertificateAuthorityConfig;

use crate::provision::{run_command, write_file, ProvisionContext, ProvisionOutcome};

pub(crate) fn apply(
    context: &ProvisionContext,
    config: Option<&CertificateAuthorityConfig>,
) -> eyre::Result<ProvisionOutcome> {
    let Some(config) = config else {
        return Ok(ProvisionOutcome::skipped(
            "no certificate authority configured",
        ));
    };

    write_file(&context.guest_path(&config.path), &config.pem, 0o644)?;
    if config.update_trust {
        let command = format!(
            "if command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates; elif command -v trust >/dev/null 2>&1; then trust anchor --store {} && trust extract-compat; fi",
            shell_quote(&config.path)
        );
        run_command(
            context.process_supervisor(),
            "/bin/sh",
            ["-c", command.as_str()],
        )?;
    }

    tracing::info!(
        path = %config.path,
        update_trust = config.update_trust,
        "reconciled certificate authority"
    );
    Ok(ProvisionOutcome::succeeded(false))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
