//! Redacted diagnostics from the same resolver used by start.
use crate::{LibVmError, NetworkSecretRequirement, NetworkSecretSlot};

#[derive(Debug)]
pub enum PolicySecretsCheck {
    Ready,
    Missing {
        requirements: Vec<NetworkSecretRequirement>,
        slots: Vec<NetworkSecretSlot>,
    },
    Unavailable {
        slot: String,
        key: String,
        code: String,
    },
}

pub(crate) fn diagnostic(
    result: Result<crate::secrets::ResolvedSecrets, LibVmError>,
) -> Result<PolicySecretsCheck, LibVmError> {
    match result {
        Ok(_) => Ok(PolicySecretsCheck::Ready),
        Err(LibVmError::MissingNetworkSecrets {
            requirements,
            policy,
            ..
        }) => {
            let slots = policy
                .secret_slots()
                .into_iter()
                .filter(|slot| {
                    requirements
                        .iter()
                        .any(|r| r.alternatives.iter().any(|a| a.slots.contains(&slot.name)))
                })
                .collect();
            Ok(PolicySecretsCheck::Missing {
                requirements,
                slots,
            })
        }
        Err(LibVmError::SecretResolution { slot, key, code }) => {
            Ok(PolicySecretsCheck::Unavailable { slot, key, code })
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn public_check_distinguishes_missing_corrupt_and_explicit_without_values() {
        use crate::policy_secrets::PolicySecretsCheck;
        let home = tempfile::tempdir().unwrap();
        let runtime = crate::Runtime::open(
            crate::paths::LocalPaths::new(home.path().to_path_buf()),
            crate::RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let policy = crate::NetworkPolicy::from_hcl_str("endpoint \"https\" \"api\" { hosts = [\"example.com\"] }\ncredential \"bearer_token\" \"key\" { endpoint = https.api }\ntailscale \"vm\" {}").unwrap();
        let empty = crate::EgressCredentials::default();
        match runtime
            .check_policy_secrets(&policy, None, &empty)
            .await
            .unwrap()
        {
            PolicySecretsCheck::Missing {
                requirements,
                slots,
            } => {
                assert_eq!(requirements.len(), 1);
                assert_eq!(slots.len(), 1);
                assert_eq!(slots[0].name, "key.token");
                assert_eq!(slots[0].source.key.as_str(), "bearer_token.key.token");
            }
            other => panic!("{other:?}"),
        }
        std::fs::write(home.path().join("secrets.json"), "corrupt-secret-content").unwrap();
        let result = runtime
            .check_policy_secrets(&policy, None, &empty)
            .await
            .unwrap();
        assert!(
            matches!(&result, PolicySecretsCheck::Unavailable { code, .. } if code == "invalid_request")
        );
        let diagnostic = format!("{result:?}");
        assert!(!diagnostic.contains("corrupt-secret-content"));
        assert!(!diagnostic.contains(&home.path().display().to_string()));
        assert!(matches!(
            runtime
                .check_policy_secrets(
                    &policy,
                    None,
                    &empty.secret("key.token", "synthetic-override")
                )
                .await
                .unwrap(),
            PolicySecretsCheck::Ready
        ));
        assert!(!runtime.policy_secrets_ready(&policy, None).await.unwrap());
    }
}
