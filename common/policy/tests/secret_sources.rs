use silo_policy::{NetworkPolicy, NetworkPolicyBuilder};
use silo_secrets::SecretField;

#[test]
fn every_credential_kind_and_tailscale_has_typed_source() {
    let cases = [
        (
            "basic_auth",
            vec![("password", "password", SecretField::Value, true)],
        ),
        (
            "bearer_token",
            vec![("token", "token", SecretField::Value, true)],
        ),
        (
            "header_token",
            vec![("token", "token", SecretField::Value, true)],
        ),
        (
            "github_oauth",
            vec![
                (
                    "oauth.access_token",
                    "oauth",
                    SecretField::OAuthAccessToken,
                    true,
                ),
                (
                    "oauth.expires_at",
                    "oauth",
                    SecretField::OAuthExpiresAt,
                    true,
                ),
                (
                    "oauth.account_id",
                    "oauth",
                    SecretField::OAuthAccountId,
                    false,
                ),
            ],
        ),
        (
            "openai_codex_oauth",
            vec![
                (
                    "oauth.access_token",
                    "oauth",
                    SecretField::OAuthAccessToken,
                    true,
                ),
                (
                    "oauth.expires_at",
                    "oauth",
                    SecretField::OAuthExpiresAt,
                    true,
                ),
                (
                    "oauth.account_id",
                    "oauth",
                    SecretField::OAuthAccountId,
                    false,
                ),
            ],
        ),
        (
            "aws_credential",
            vec![
                ("access_key_id", "access_key_id", SecretField::Value, true),
                (
                    "secret_access_key",
                    "secret_access_key",
                    SecretField::Value,
                    true,
                ),
                ("session_token", "session_token", SecretField::Value, false),
                ("profile", "profile", SecretField::Value, false),
            ],
        ),
    ];
    for (kind, fields) in cases {
        let config = match kind {
            "basic_auth" => "username = \"user\"",
            "header_token" => "header = \"X-Token\"",
            _ => "",
        };
        let source = format!(
            r#"
endpoint "https" "api" {{ hosts = ["api.example.com"] }}
credential "{kind}" "personal" {{
endpoint = https.api
{config}
}}
tailscale "worktail" {{ tags = ["tag:dev"] }}
"#
        );
        let policy = NetworkPolicy::from_hcl_str(&source).unwrap();
        for policy in [
            policy.clone(),
            NetworkPolicy::from_json_str(&serde_json::to_string(&policy).unwrap()).unwrap(),
        ] {
            let slots = policy.secret_slots();
            assert_eq!(slots.len(), fields.len() + 1, "{kind}");
            for (suffix, key_suffix, field, required) in &fields {
                let slot = slots
                    .iter()
                    .find(|s| s.name == format!("personal.{suffix}"))
                    .unwrap();
                assert_eq!(
                    slot.source.key.as_str(),
                    format!("{kind}.personal.{key_suffix}")
                );
                assert_eq!(slot.source.field, *field);
                assert_eq!(slot.required, *required);
                let encoded = serde_json::to_string(slot).unwrap();
                let decoded: silo_policy::NetworkSecretSlot =
                    serde_json::from_str(&encoded).unwrap();
                assert_eq!(decoded.source.key, slot.source.key);
                assert_eq!(decoded.source.field, slot.source.field);
            }
            let slot = slots.last().unwrap();
            assert_eq!(slot.name, "worktail.tailscale.auth_key");
            assert_eq!(slot.source.key.as_str(), "tailscale.worktail.auth_key");
            assert_eq!(slot.source.field, SecretField::Value);
            assert!(!slot.required);
            assert!(policy.secret_requirements().iter().all(|r| r
                .alternatives
                .iter()
                .all(|a| a.slots.iter().all(|s| !s.contains("tailscale")))));
        }
    }
    let policy = NetworkPolicy::from_hcl_str("tailscale \"work\" {}\n").unwrap();
    assert!(policy.secret_requirements().is_empty());
}

#[test]
fn reserved_names_rejected_by_hcl_json_and_builders() {
    let source = r#"endpoint "https" "api" { hosts = ["example.com"] }
credential "bearer_token" "silo" { endpoint = https.api }
"#;
    assert!(silo_policy::Policy::parse_str("reserved.hcl", source)
        .unwrap_err()
        .to_string()
        .contains("silo"));
    assert!(NetworkPolicy::from_hcl_str(source).is_err());
    assert!(silo_policy::Policy::parse_str("reserved.hcl", "tailscale \"silo\" {}\n").is_err());
    assert!(
        NetworkPolicy::from_json_str(r#"{"version":1,"tailscale":[{"name":"silo"}]}"#).is_err()
    );
    assert!(NetworkPolicy::from_json_str(
        r#"{"version":1,"credentials":[{"name":"silo","kind":"bearer_token","endpoint":"api"}]}"#
    )
    .is_err());
    assert!(NetworkPolicyBuilder::new()
        .tailscale("silo", |t| t)
        .build()
        .is_err());
    let error = NetworkPolicyBuilder::new()
        .credential("silo", |c| c.bearer_token().endpoint("api"))
        .build()
        .unwrap_err();
    assert!(error.to_string().contains("reserved"));
    // Endpoint names don't occupy the generated-secret namespace.
    assert!(NetworkPolicy::from_hcl_str(
        "endpoint \"https\" \"silo\" { hosts = [\"example.com\"] }\n"
    )
    .is_ok());
}
