use agent_spec::CertificateAuthorityConfig;

use crate::provision::{
    run_command, write_file, ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
};

pub(crate) struct CertificateAuthority<'a> {
    config: Option<&'a CertificateAuthorityConfig>,
}

impl<'a> Provisioner<'a> for CertificateAuthority<'a> {
    type Config = Option<CertificateAuthorityConfig>;

    fn init(config: &'a Self::Config) -> Self {
        Self {
            config: config.as_ref(),
        }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::CERTIFICATE_AUTHORITY
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        let Some(config) = self.config else {
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
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
