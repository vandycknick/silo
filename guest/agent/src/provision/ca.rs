use agent_spec::CertificateAuthorityConfig;

use crate::provision::{
    command_exists, run_command, write_file, FailurePolicy, ProvisionContext, ProvisionOutcome,
    Provisioner, ProvisionerId,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TrustBackend {
    UpdateCaCertificates,
    P11Kit,
}

impl TrustBackend {
    fn detect() -> Option<Self> {
        if command_exists("update-ca-certificates") {
            Some(Self::UpdateCaCertificates)
        } else if command_exists("trust") {
            Some(Self::P11Kit)
        } else {
            None
        }
    }

    fn install(self, context: &ProvisionContext, certificate_path: &str) -> eyre::Result<()> {
        match self {
            Self::UpdateCaCertificates => run_command(
                context.process_supervisor(),
                "update-ca-certificates",
                std::iter::empty::<&str>(),
            ),
            Self::P11Kit => {
                run_command(
                    context.process_supervisor(),
                    "trust",
                    ["anchor", "--store", certificate_path],
                )?;
                run_command(context.process_supervisor(), "trust", ["extract-compat"])
            }
        }
    }
}

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

    fn failure_policy(&self) -> FailurePolicy {
        if self.config.is_some() {
            FailurePolicy::FailBoot
        } else {
            FailurePolicy::BestEffort
        }
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        let Some(config) = self.config else {
            return Ok(ProvisionOutcome::skipped(
                "no certificate authority configured",
            ));
        };

        let trust_backend = if config.update_trust {
            let Some(backend) = TrustBackend::detect() else {
                return Ok(ProvisionOutcome::unsupported(
                    "no supported certificate trust backend found",
                ));
            };
            Some(backend)
        } else {
            None
        };

        write_file(&context.guest_path(&config.path), &config.pem, 0o644)?;
        if let Some(backend) = trust_backend {
            backend.install(context, &config.path)?;
        }

        tracing::info!(
            path = %config.path,
            update_trust = config.update_trust,
            "reconciled certificate authority"
        );
        Ok(ProvisionOutcome::succeeded(false))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use agent_spec::CertificateAuthorityConfig;

    use crate::provision::ca::CertificateAuthority;
    use crate::provision::{FailurePolicy, ProvisionContext, ProvisionOutcome, Provisioner};

    #[test]
    fn skips_without_configuration() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let context = ProvisionContext::for_test(temp.path());
        let provisioner = CertificateAuthority::init(&None);

        let outcome = provisioner.apply(&context).expect("apply provisioner");

        assert!(matches!(outcome, ProvisionOutcome::Skipped { .. }));
        assert_eq!(provisioner.failure_policy(), FailurePolicy::BestEffort);
    }

    #[test]
    fn writes_certificate_without_updating_trust() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let context = ProvisionContext::for_test(temp.path());
        let config = Some(CertificateAuthorityConfig {
            path: "/usr/local/share/ca-certificates/silo.crt".to_string(),
            pem: "certificate-pem\n".to_string(),
            update_trust: false,
        });
        let provisioner = CertificateAuthority::init(&config);

        let outcome = provisioner.apply(&context).expect("apply provisioner");

        assert!(matches!(outcome, ProvisionOutcome::Succeeded { .. }));
        assert_eq!(provisioner.failure_policy(), FailurePolicy::FailBoot);
        assert_eq!(
            fs::read_to_string(temp.path().join("usr/local/share/ca-certificates/silo.crt"))
                .expect("read certificate"),
            "certificate-pem\n"
        );
    }
}
