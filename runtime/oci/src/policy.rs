use oci_client::Reference;

use crate::error::{OciError, OciResult};
use crate::registry::RegistryClient;

const DOCKER_HUB: &str = "docker.io";
const DOCKER_HUB_LEGACY: &str = "index.docker.io";

/// What the policy does with an image reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryAction {
    Allow,
    Deny,
}

/// A prefix rule matched against canonical image references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRule {
    prefix: String,
    action: RegistryAction,
}

impl RegistryRule {
    pub fn new(prefix: impl Into<String>, action: RegistryAction) -> Self {
        Self {
            prefix: prefix.into(),
            action,
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn action(&self) -> RegistryAction {
        self.action
    }
}

/// Short-name expansion and registry access policy for OCI pulls.
///
/// Short names (`nixos/nix`, `alpine`) expand against `search_registries` in
/// order. Every expanded or fully qualified reference is checked against the
/// rules before any registry is contacted: the longest matching prefix wins,
/// and `default` applies when no rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPolicy {
    default: RegistryAction,
    search_registries: Vec<String>,
    rules: Vec<RegistryRule>,
}

impl Default for RegistryPolicy {
    fn default() -> Self {
        Self {
            default: RegistryAction::Allow,
            search_registries: vec![DOCKER_HUB.to_string()],
            rules: Vec::new(),
        }
    }
}

impl RegistryPolicy {
    pub fn new(
        default: RegistryAction,
        search_registries: Vec<String>,
        rules: Vec<RegistryRule>,
    ) -> OciResult<Self> {
        let mut registries: Vec<String> = Vec::with_capacity(search_registries.len());
        for registry in search_registries {
            if !is_registry_host(&registry) {
                return Err(invalid_policy(format!(
                    "search registry {registry:?} must be a registry host such as docker.io or localhost:5000"
                )));
            }
            let registry = normalize_host(registry);
            if registries.contains(&registry) {
                return Err(invalid_policy(format!(
                    "duplicate search registry {registry:?}"
                )));
            }
            registries.push(registry);
        }

        let mut normalized: Vec<RegistryRule> = Vec::with_capacity(rules.len());
        for rule in rules {
            let prefix = normalize_prefix(&rule.prefix)?;
            if normalized.iter().any(|existing| existing.prefix == prefix) {
                return Err(invalid_policy(format!("duplicate rule prefix {prefix:?}")));
            }
            normalized.push(RegistryRule {
                prefix,
                action: rule.action,
            });
        }

        Ok(Self {
            default,
            search_registries: registries,
            rules: normalized,
        })
    }

    pub fn default_action(&self) -> RegistryAction {
        self.default
    }

    pub fn search_registries(&self) -> &[String] {
        &self.search_registries
    }

    pub fn rules(&self) -> &[RegistryRule] {
        &self.rules
    }

    /// Expands `image_ref` into the fully qualified references to try, in order.
    pub(crate) fn candidates(&self, image_ref: &str) -> OciResult<Vec<Reference>> {
        if !is_short_name(image_ref) {
            return Ok(vec![RegistryClient::parse_reference(image_ref)?]);
        }
        if self.search_registries.is_empty() {
            return Err(OciError::InvalidReference {
                reference: image_ref.to_string(),
                message: "short image names need a search registry; none are configured"
                    .to_string(),
            });
        }
        self.search_registries
            .iter()
            .map(|registry| {
                RegistryClient::parse_reference(&format!("{registry}/{image_ref}")).map_err(|err| {
                    match err {
                        OciError::InvalidReference { message, .. } => OciError::InvalidReference {
                            reference: image_ref.to_string(),
                            message,
                        },
                        other => other,
                    }
                })
            })
            .collect()
    }

    /// Fails with `RegistryPolicyDenied` when the policy forbids contacting a registry for `reference`.
    pub(crate) fn check(&self, reference: &Reference) -> OciResult<()> {
        let canonical = reference.to_string();
        let matched = self
            .rules
            .iter()
            .filter(|rule| prefix_matches(&canonical, &rule.prefix))
            .max_by_key(|rule| rule.prefix.len());
        let (action, rule) = match matched {
            Some(rule) => (rule.action, Some(rule.prefix.clone())),
            None => (self.default, None),
        };
        match action {
            RegistryAction::Allow => Ok(()),
            RegistryAction::Deny => Err(OciError::RegistryPolicyDenied {
                reference: canonical,
                rule,
            }),
        }
    }
}

/// Docker's rule: the first path component names a registry only when it looks like a host.
fn is_short_name(image_ref: &str) -> bool {
    match image_ref.split_once('/') {
        None => true,
        Some((first, _)) => !(first.contains('.') || first.contains(':') || first == "localhost"),
    }
}

fn is_registry_host(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        && (value.contains('.') || value.contains(':') || value == "localhost")
}

fn normalize_host(host: String) -> String {
    if host == DOCKER_HUB_LEGACY {
        DOCKER_HUB.to_string()
    } else {
        host
    }
}

fn normalize_prefix(prefix: &str) -> OciResult<String> {
    let invalid = || {
        invalid_policy(format!(
            "rule prefix {prefix:?} must start with a registry host, e.g. docker.io or ghcr.io/org"
        ))
    };
    if prefix.is_empty()
        || prefix
            .chars()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        || prefix.contains("://")
        || prefix.contains('*')
        || prefix.ends_with('/')
    {
        return Err(invalid());
    }
    let (host, rest) = match prefix.split_once('/') {
        Some((host, rest)) => (host, Some(rest)),
        None => (prefix, None),
    };
    if !is_registry_host(host) {
        return Err(invalid());
    }
    let host = normalize_host(host.to_string());
    Ok(match rest {
        Some(rest) => format!("{host}/{rest}"),
        None => host,
    })
}

fn prefix_matches(reference: &str, prefix: &str) -> bool {
    match reference.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => rest.starts_with(['/', ':', '@']),
        None => false,
    }
}

fn invalid_policy(message: String) -> OciError {
    OciError::InvalidRegistryPolicy { message }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use oci_client::Reference;

    use crate::policy::{RegistryAction, RegistryPolicy, RegistryRule};
    use crate::OciError;

    fn policy(
        default: RegistryAction,
        search: &[&str],
        rules: &[(&str, RegistryAction)],
    ) -> RegistryPolicy {
        RegistryPolicy::new(
            default,
            search.iter().map(|s| s.to_string()).collect(),
            rules
                .iter()
                .map(|(prefix, action)| RegistryRule::new(*prefix, *action))
                .collect(),
        )
        .expect("valid policy")
    }

    fn expand(policy: &RegistryPolicy, image_ref: &str) -> Vec<String> {
        policy
            .candidates(image_ref)
            .expect("candidates")
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn reference(value: &str) -> Reference {
        Reference::from_str(value).expect("reference")
    }

    fn policy_error(search: &[&str], rules: &[(&str, RegistryAction)]) -> String {
        let err = RegistryPolicy::new(
            RegistryAction::Allow,
            search.iter().map(|s| s.to_string()).collect(),
            rules
                .iter()
                .map(|(prefix, action)| RegistryRule::new(*prefix, *action))
                .collect(),
        )
        .expect_err("policy must be rejected");
        match err {
            OciError::InvalidRegistryPolicy { message } => message,
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn default_policy_expands_short_names_against_docker_hub() {
        let policy = RegistryPolicy::default();
        assert_eq!(policy.default_action(), RegistryAction::Allow);
        assert_eq!(expand(&policy, "nixos/nix"), ["docker.io/nixos/nix:latest"]);
        assert_eq!(
            expand(&policy, "alpine:3.21"),
            ["docker.io/library/alpine:3.21"]
        );
        assert_eq!(
            expand(&policy, "ghcr.io/vandycknick/silo/devbox:latest"),
            ["ghcr.io/vandycknick/silo/devbox:latest"]
        );
        assert_eq!(
            expand(&policy, "localhost:5000/x"),
            ["localhost:5000/x:latest"]
        );
        assert_eq!(expand(&policy, "localhost/x"), ["localhost/x:latest"]);
        assert_eq!(
            expand(&policy, "index.docker.io/library/alpine"),
            ["docker.io/library/alpine:latest"]
        );
    }

    #[test]
    fn short_names_try_search_registries_in_order() {
        let policy = policy(RegistryAction::Allow, &["ghcr.io", "docker.io"], &[]);
        assert_eq!(
            expand(&policy, "nixos/nix"),
            ["ghcr.io/nixos/nix:latest", "docker.io/nixos/nix:latest"]
        );
        assert_eq!(
            expand(&policy, "quay.io/x/y"),
            ["quay.io/x/y:latest"],
            "qualified names never expand"
        );
    }

    #[test]
    fn short_names_without_search_registries_are_rejected() {
        let policy = policy(RegistryAction::Allow, &[], &[]);
        let err = policy.candidates("nixos/nix").expect_err("no registries");
        assert_eq!(
            err.to_string(),
            "invalid OCI image reference \"nixos/nix\": short image names need a search registry; none are configured"
        );
        assert_eq!(expand(&policy, "ghcr.io/x/y"), ["ghcr.io/x/y:latest"]);
    }

    #[test]
    fn malformed_references_are_invalid_and_keep_the_user_input() {
        let policy = RegistryPolicy::default();
        for input in [
            "/etc/passwd",
            "ghcr.io/vandycknick/../x",
            "ghcr.io/vandycknick/devbox?path=/etc",
            "https://ghcr.io/vandycknick/devbox",
            "Nixos/Nix",
            "",
        ] {
            match policy.candidates(input) {
                Err(OciError::InvalidReference { reference, .. }) => {
                    assert_eq!(reference, input)
                }
                other => panic!("{input:?} must be invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn rules_match_on_path_tag_and_digest_boundaries() {
        let policy = policy(
            RegistryAction::Deny,
            &["docker.io"],
            &[("ghcr.io/vandycknick", RegistryAction::Allow)],
        );
        assert!(policy
            .check(&reference("ghcr.io/vandycknick/silo/devbox:latest"))
            .is_ok());
        assert!(policy.check(&reference("ghcr.io/vandycknick:1")).is_ok());
        for denied in [
            "ghcr.io/vandycknick-evil/x:latest",
            "ghcr.io.evil/vandycknick/x:latest",
            "ghcr.io/other/x:latest",
        ] {
            match policy.check(&reference(denied)) {
                Err(OciError::RegistryPolicyDenied { reference, rule }) => {
                    assert_eq!(reference, denied);
                    assert_eq!(rule, None);
                }
                other => panic!("{denied:?} must be denied, got {other:?}"),
            }
        }
    }

    #[test]
    fn host_rule_covers_every_port_and_repository() {
        let policy = policy(
            RegistryAction::Allow,
            &["docker.io"],
            &[("localhost", RegistryAction::Deny)],
        );
        for denied in ["localhost:5000/x:latest", "localhost/x:latest"] {
            assert!(matches!(
                &policy.check(&reference(denied)),
                Err(OciError::RegistryPolicyDenied { rule: Some(r), .. }) if r == "localhost"
            ));
        }
        assert!(policy.check(&reference("localhostx.io/x:latest")).is_ok());
    }

    #[test]
    fn longest_prefix_wins() {
        let policy = policy(
            RegistryAction::Allow,
            &["docker.io"],
            &[
                ("docker.io/library", RegistryAction::Allow),
                ("docker.io", RegistryAction::Deny),
            ],
        );
        let alpine = &policy.candidates("alpine").expect("candidates")[0];
        assert!(policy.check(alpine).is_ok());
        let nix = &policy.candidates("nixos/nix").expect("candidates")[0];
        assert!(matches!(
            &policy.check(nix),
            Err(OciError::RegistryPolicyDenied { rule: Some(r), .. }) if r == "docker.io"
        ));
        let pinned = reference(&format!(
            "docker.io/library/alpine@sha256:{}",
            "a".repeat(64)
        ));
        assert!(policy.check(&pinned).is_ok());
    }

    #[test]
    fn denial_messages_name_the_reference_and_the_deciding_rule() {
        let by_rule = OciError::RegistryPolicyDenied {
            reference: "docker.io/nixos/nix:latest".to_string(),
            rule: Some("docker.io".to_string()),
        };
        assert_eq!(
            by_rule.to_string(),
            "image \"docker.io/nixos/nix:latest\" is denied by registry policy rule \"docker.io\""
        );
        let by_default = OciError::RegistryPolicyDenied {
            reference: "docker.io/nixos/nix:latest".to_string(),
            rule: None,
        };
        assert_eq!(
            by_default.to_string(),
            "image \"docker.io/nixos/nix:latest\" is denied by the registry policy default"
        );
    }

    #[test]
    fn legacy_docker_hub_host_is_normalized_in_policy() {
        let policy = policy(
            RegistryAction::Deny,
            &["index.docker.io"],
            &[("index.docker.io/nixos", RegistryAction::Allow)],
        );
        assert_eq!(policy.search_registries(), ["docker.io"]);
        assert_eq!(policy.rules()[0].prefix(), "docker.io/nixos");
        let nix = &policy.candidates("nixos/nix").expect("candidates")[0];
        assert!(policy.check(nix).is_ok());
    }

    #[test]
    fn invalid_rule_prefixes_are_rejected() {
        for prefix in [
            "",
            "https://x",
            "nixos/nix",
            "ghcr.io/org/",
            "*.example.com",
            "ghcr.io/a b",
        ] {
            assert_eq!(
                policy_error(&["docker.io"], &[(prefix, RegistryAction::Allow)]),
                format!(
                    "rule prefix {prefix:?} must start with a registry host, e.g. docker.io or ghcr.io/org"
                ),
            );
        }
        assert_eq!(
            policy_error(
                &["docker.io"],
                &[
                    ("docker.io/nixos", RegistryAction::Allow),
                    ("index.docker.io/nixos", RegistryAction::Deny),
                ],
            ),
            "duplicate rule prefix \"docker.io/nixos\""
        );
    }

    #[test]
    fn invalid_search_registries_are_rejected() {
        for registry in ["ghcr.io/org", "", "docker", "https://ghcr.io"] {
            assert_eq!(
                policy_error(&[registry], &[]),
                format!(
                    "search registry {registry:?} must be a registry host such as docker.io or localhost:5000"
                ),
            );
        }
        assert_eq!(
            policy_error(&["docker.io", "index.docker.io"], &[]),
            "duplicate search registry \"docker.io\""
        );
        let err = RegistryPolicy::new(
            RegistryAction::Allow,
            vec!["ghcr.io/org".to_string()],
            Vec::new(),
        )
        .expect_err("invalid");
        assert!(err.to_string().starts_with("invalid registry policy: "));
    }
}
