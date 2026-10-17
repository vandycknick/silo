use crate::values::{policy_from_wire, policy_to_wire};
use crate::{invalid, required, ConversionError};
use silod_spec::daemon::v1 as w;
pub fn slot_to_wire(v: &libvm::NetworkSecretSlot) -> w::SecretSlot {
    w::SecretSlot {
        name: v.name.clone(),
        required: v.required,
        kind: match v.kind {
            libvm::NetworkSecretKind::Plain => 1,
            libvm::NetworkSecretKind::OAuth => 2,
        },
        key: v.source.key.as_str().into(),
        field: match v.source.field {
            silo_secrets::SecretField::Value => 1,
            silo_secrets::SecretField::OAuthAccessToken => 2,
            silo_secrets::SecretField::OAuthExpiresAt => 3,
            silo_secrets::SecretField::OAuthAccountId => 4,
        },
    }
}
pub fn slot_from_wire(v: w::SecretSlot) -> Result<libvm::NetworkSecretSlot, ConversionError> {
    Ok(libvm::NetworkSecretSlot {
        name: v.name,
        required: v.required,
        kind: match v.kind {
            1 => libvm::NetworkSecretKind::Plain,
            2 => libvm::NetworkSecretKind::OAuth,
            _ => return Err(invalid("secret_slot.kind", "invalid enum")),
        },
        source: silo_policy::NetworkSecretSource {
            key: silo_secrets::SecretName::new(v.key)
                .map_err(|_| invalid("secret_slot.key", "invalid secret name"))?,
            field: match v.field {
                1 => silo_secrets::SecretField::Value,
                2 => silo_secrets::SecretField::OAuthAccessToken,
                3 => silo_secrets::SecretField::OAuthExpiresAt,
                4 => silo_secrets::SecretField::OAuthAccountId,
                _ => return Err(invalid("secret_slot.field", "invalid enum")),
            },
        },
    })
}
pub fn requirement_to_wire(v: &libvm::NetworkSecretRequirement) -> w::SecretRequirement {
    w::SecretRequirement {
        owner: v.owner.clone(),
        alternatives: v
            .alternatives
            .iter()
            .map(|v| w::SecretAlternative {
                slots: v.slots.clone(),
            })
            .collect(),
    }
}
pub fn requirement_from_wire(v: w::SecretRequirement) -> libvm::NetworkSecretRequirement {
    libvm::NetworkSecretRequirement {
        owner: v.owner,
        alternatives: v
            .alternatives
            .into_iter()
            .map(|v| libvm::NetworkSecretAlternative { slots: v.slots })
            .collect(),
    }
}
pub fn normalize_policy(
    v: w::NormalizePolicyRequest,
) -> Result<w::PolicyDocument, ConversionError> {
    let policy = match required(v.input, "policy.input")? {
        w::normalize_policy_request::Input::Hcl(v) => libvm::NetworkPolicy::from_hcl_str(&v)
            .map_err(|_| invalid("policy.hcl", "invalid HCL policy"))?,
        w::normalize_policy_request::Input::CanonicalJson(v) => policy_from_wire(&v)?,
        w::normalize_policy_request::Input::Empty(()) => libvm::NetworkPolicy::from_hcl_str("")
            .map_err(|_| invalid("policy.empty", "cannot normalize empty policy"))?,
    };
    Ok(w::PolicyDocument {
        canonical_json: policy_to_wire(&policy)?,
        hcl: policy
            .to_hcl_string()
            .map_err(|_| invalid("policy", "cannot render HCL"))?,
        secret_slots: policy.secret_slots().iter().map(slot_to_wire).collect(),
        secret_requirements: policy
            .secret_requirements()
            .iter()
            .map(requirement_to_wire)
            .collect(),
    })
}
pub fn secrets_to_wire(v: &libvm::policy_secrets::PolicySecretsCheck) -> w::PolicySecretsResult {
    match v {
        libvm::policy_secrets::PolicySecretsCheck::Ready => w::PolicySecretsResult {
            state: 1,
            ..Default::default()
        },
        libvm::policy_secrets::PolicySecretsCheck::Missing {
            requirements,
            slots,
        } => w::PolicySecretsResult {
            state: 2,
            requirements: requirements.iter().map(requirement_to_wire).collect(),
            slots: slots.iter().map(slot_to_wire).collect(),
            diagnostics: slots
                .iter()
                .map(|v| w::SecretDiagnostic {
                    slot: v.name.clone(),
                    key: Some(v.source.key.as_str().into()),
                    code: "missing".into(),
                })
                .collect(),
        },
        libvm::policy_secrets::PolicySecretsCheck::Unavailable { slot, key, code } => {
            w::PolicySecretsResult {
                state: 3,
                diagnostics: vec![w::SecretDiagnostic {
                    slot: slot.clone(),
                    key: Some(key.clone()),
                    code: code.clone(),
                }],
                ..Default::default()
            }
        }
    }
}
pub fn secrets_from_wire(
    v: w::PolicySecretsResult,
) -> Result<libvm::policy_secrets::PolicySecretsCheck, ConversionError> {
    Ok(match v.state {
        1 => libvm::policy_secrets::PolicySecretsCheck::Ready,
        2 => libvm::policy_secrets::PolicySecretsCheck::Missing {
            requirements: v
                .requirements
                .into_iter()
                .map(requirement_from_wire)
                .collect(),
            slots: v
                .slots
                .into_iter()
                .map(slot_from_wire)
                .collect::<Result<_, _>>()?,
        },
        3 => {
            let mut diagnostics = v.diagnostics.into_iter();
            let d = diagnostics
                .next()
                .ok_or_else(|| invalid("secret.diagnostic", "missing unavailable diagnostic"))?;
            if diagnostics.next().is_some() {
                return Err(invalid(
                    "secret.diagnostic",
                    "too many unavailable diagnostics",
                ));
            }
            libvm::policy_secrets::PolicySecretsCheck::Unavailable {
                slot: d.slot,
                key: required(d.key, "secret.key")?,
                code: d.code,
            }
        }
        _ => return Err(invalid("secret.state", "invalid enum")),
    })
}
