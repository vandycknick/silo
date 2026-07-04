use crate::condition::HttpCondition;
use crate::{Action, Diagnostic, DiagnosticSeverity, PortRange};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const POLICY_VERSION: u32 = 1;
const DEFAULT_BODY_BUFFER_BYTES: u64 = 1_048_576;
const DEFAULT_BODY_STORAGE_BYTES: u64 = 4_096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub version: u32,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    #[serde(default)]
    pub settings: NetworkPolicySettings,
    #[serde(default)]
    pub endpoints: Vec<NetworkEndpoint>,
    #[serde(default)]
    pub credentials: Vec<NetworkCredential>,
    #[serde(default)]
    pub rules: Vec<NetworkRule>,
    #[serde(default)]
    pub tailscale: Vec<TailscaleTunnel>,
    #[serde(default)]
    pub forwards: Vec<NetworkForward>,
}

impl NetworkPolicy {
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, PolicyLoadError> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path).map_err(|err| PolicyLoadError {
            filename: path.display().to_string(),
            diagnostics: vec![Diagnostic::error(
                path.display().to_string(),
                0,
                0,
                "failed to read policy JSON",
                err.to_string(),
            )],
        })?;
        Self::from_json_source(path.display().to_string(), &source)
    }

    pub fn from_json_str(source: &str) -> Result<Self, PolicyLoadError> {
        Self::from_json_source("<json>", source)
    }

    pub fn from_json_slice(source: &[u8]) -> Result<Self, PolicyLoadError> {
        let source = std::str::from_utf8(source).map_err(|err| PolicyLoadError {
            filename: "<json>".to_owned(),
            diagnostics: vec![Diagnostic::error(
                "<json>",
                0,
                0,
                "policy JSON is not UTF-8",
                err.to_string(),
            )],
        })?;
        Self::from_json_source("<json>", source)
    }

    pub fn normalize(&mut self) {
        self.settings.normalize();
        for endpoint in &mut self.endpoints {
            endpoint.normalize();
        }
        for rule in &mut self.rules {
            rule.normalize();
        }
        for forward in &mut self.forwards {
            forward.normalize();
        }
    }

    pub fn normalized(mut self) -> Self {
        self.normalize();
        self
    }

    pub fn validate(&self) -> Vec<Diagnostic> {
        let mut validator = PolicyValidator::default();
        validator.validate(self);
        validator.diagnostics
    }

    pub fn secret_slots(&self) -> Vec<NetworkSecretSlot> {
        let mut slots = Vec::new();
        for credential in &self.credentials {
            slots.extend(credential_secret_slots(credential));
        }
        for tunnel in &self.tailscale {
            slots.push(NetworkSecretSlot::required(
                format!("{}.tailscale.auth_key", tunnel.name),
                NetworkSecretKind::Plain,
            ));
        }
        slots
    }

    fn from_json_source(
        filename: impl Into<String>,
        source: &str,
    ) -> Result<Self, PolicyLoadError> {
        let filename = filename.into();
        let mut policy: Self = serde_json::from_str(source).map_err(|err| PolicyLoadError {
            filename: filename.clone(),
            diagnostics: vec![Diagnostic::error(
                filename.clone(),
                err.line(),
                err.column(),
                "failed to parse policy JSON",
                err.to_string(),
            )],
        })?;
        policy.normalize();
        let diagnostics = policy.validate();
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        {
            return Err(PolicyLoadError {
                filename,
                diagnostics,
            });
        }
        Ok(policy)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicySettings {
    #[serde(default)]
    pub default_action: Action,
    #[serde(default)]
    pub audit: NetworkAuditSettings,
}

impl NetworkPolicySettings {
    fn normalize(&mut self) {}
}

impl Default for NetworkPolicySettings {
    fn default() -> Self {
        Self {
            default_action: Action::Allow,
            audit: NetworkAuditSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAuditSettings {
    #[serde(default = "default_body_buffer_bytes")]
    pub body_buffer_bytes: u64,
    #[serde(default = "default_body_storage_bytes")]
    pub body_storage_bytes: u64,
}

impl Default for NetworkAuditSettings {
    fn default() -> Self {
        Self {
            body_buffer_bytes: DEFAULT_BODY_BUFFER_BYTES,
            body_storage_bytes: DEFAULT_BODY_STORAGE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpoint {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub source_cidrs: Vec<String>,
    #[serde(default)]
    pub destination_cidrs: Vec<String>,
    #[serde(default)]
    pub protocol: IpProtocol,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl NetworkEndpoint {
    fn normalize(&mut self) {
        if self.kind == "http" || self.kind == "https" {
            self.hosts = self.hosts.iter().map(|host| normalize_host(host)).collect();
        }
    }

    fn family(&self) -> Option<EndpointFamilyKind> {
        match self.kind.as_str() {
            "ip" => Some(EndpointFamilyKind::Ip),
            "http" | "https" => Some(EndpointFamilyKind::Http),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpProtocol {
    #[default]
    Any,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCredential {
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default)]
    pub idempotency_key: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>,
    #[serde(default)]
    pub verdict: Action,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub reason: String,
}

impl NetworkRule {
    fn normalize(&mut self) {}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleTunnel {
    pub name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkForward {
    pub name: String,
    pub kind: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>,
}

impl NetworkForward {
    fn normalize(&mut self) {
        if self.kind == "host" && self.listen_host.is_none() {
            self.listen_host = Some("127.0.0.1".to_owned());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecretSlot {
    pub name: String,
    pub required: bool,
    pub kind: NetworkSecretKind,
}

impl NetworkSecretSlot {
    pub fn env_name(&self) -> String {
        let mut name = String::from("BENTO_NET_SECRET_");
        let mut previous_was_separator = false;
        for character in self.name.chars() {
            if character.is_ascii_alphanumeric() {
                name.push(character.to_ascii_uppercase());
                previous_was_separator = false;
            } else if !previous_was_separator {
                name.push('_');
                previous_was_separator = true;
            }
        }
        while name.ends_with('_') {
            name.pop();
        }
        name
    }

    fn required(name: String, kind: NetworkSecretKind) -> Self {
        Self {
            name,
            required: true,
            kind,
        }
    }

    fn optional(name: String, kind: NetworkSecretKind) -> Self {
        Self {
            name,
            required: false,
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkSecretKind {
    Plain,
    OAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyLoadError {
    pub filename: String,
    pub diagnostics: Vec<Diagnostic>,
}

impl std::fmt::Display for PolicyLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_count = self
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .count();
        write!(
            formatter,
            "load network policy {} failed with {error_count} error(s)",
            self.filename
        )?;
        for diagnostic in self
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        {
            write!(
                formatter,
                "\n{}:{}:{}: {}",
                diagnostic.file, diagnostic.line, diagnostic.column, diagnostic.summary
            )?;
            if !diagnostic.detail.is_empty() {
                for line in diagnostic.detail.lines() {
                    write!(formatter, "\n  {line}")?;
                }
            }
        }
        Ok(())
    }
}

impl std::error::Error for PolicyLoadError {}

#[derive(Default)]
struct PolicyValidator {
    diagnostics: Vec<Diagnostic>,
}

impl PolicyValidator {
    fn validate(&mut self, policy: &NetworkPolicy) {
        self.validate_version(policy.version);
        self.validate_audit_settings(&policy.settings.audit);

        let endpoints = self.validate_endpoints(&policy.endpoints);
        let credentials = self.validate_credentials(&policy.credentials, &endpoints);
        let tunnels = self.validate_tunnels(&policy.tailscale);
        self.validate_rules(&policy.rules, &endpoints, &credentials, &tunnels);
        self.validate_forwards(&policy.forwards, &tunnels);
        self.validate_secret_slots(policy);
    }

    fn validate_version(&mut self, version: u32) {
        if version != POLICY_VERSION {
            self.error(
                "unsupported policy version",
                format!("expected version {POLICY_VERSION}, got {version}"),
            );
        }
    }

    fn validate_audit_settings(&mut self, settings: &NetworkAuditSettings) {
        if settings.body_buffer_bytes < settings.body_storage_bytes {
            self.warning(
                "audit body buffer is smaller than body storage",
                "body_buffer_bytes < body_storage_bytes makes the effective storage limit unreachable",
            );
        }
    }

    fn validate_endpoints(
        &mut self,
        endpoints: &[NetworkEndpoint],
    ) -> BTreeMap<String, NetworkEndpointInfo> {
        let mut by_name = BTreeMap::new();
        let mut exact_hosts = BTreeSet::new();
        for endpoint in endpoints {
            self.validate_name("endpoint", &endpoint.name);
            let Some(family) = endpoint.family() else {
                self.error(
                    "unsupported endpoint kind",
                    format!(
                        "endpoint {} uses unsupported kind {}",
                        endpoint.name, endpoint.kind
                    ),
                );
                continue;
            };
            if by_name
                .insert(
                    endpoint.name.clone(),
                    NetworkEndpointInfo {
                        kind: endpoint.kind.clone(),
                        family,
                    },
                )
                .is_some()
            {
                self.error(
                    "duplicate endpoint name",
                    format!("endpoint name {} is declared more than once", endpoint.name),
                );
            }
            match endpoint.kind.as_str() {
                "ip" => self.validate_ip_endpoint(endpoint),
                "http" | "https" => self.validate_http_endpoint(endpoint, &mut exact_hosts),
                _ => {}
            }
        }
        by_name
    }

    fn validate_ip_endpoint(&mut self, endpoint: &NetworkEndpoint) {
        if !endpoint.hosts.is_empty() {
            self.error(
                "ip endpoint cannot declare hosts",
                format!("endpoint {} has hosts", endpoint.name),
            );
        }
        for port in &endpoint.ports {
            if port.start > port.end {
                self.error(
                    "invalid port range",
                    format!(
                        "endpoint {} has port range {}-{}",
                        endpoint.name, port.start, port.end
                    ),
                );
            }
        }
    }

    fn validate_http_endpoint(
        &mut self,
        endpoint: &NetworkEndpoint,
        exact_hosts: &mut BTreeSet<String>,
    ) {
        if !endpoint.source_cidrs.is_empty()
            || !endpoint.destination_cidrs.is_empty()
            || endpoint.protocol != IpProtocol::Any
            || !endpoint.ports.is_empty()
        {
            self.error(
                "http endpoint has ip-only fields",
                format!(
                    "endpoint {} has fields only valid for ip endpoints",
                    endpoint.name
                ),
            );
        }
        if endpoint.hosts.is_empty() {
            self.error(
                "http endpoint requires hosts",
                format!("endpoint {} has no hosts", endpoint.name),
            );
        }
        for host in &endpoint.hosts {
            if host.trim().is_empty() {
                self.error(
                    "empty host binding",
                    format!("endpoint {} has an empty host binding", endpoint.name),
                );
            }
            if !host.starts_with("*.") && !exact_hosts.insert(host.clone()) {
                self.error(
                    "duplicate exact host binding",
                    format!("host {host} is declared more than once"),
                );
            }
        }
    }

    fn validate_credentials(
        &mut self,
        credentials: &[NetworkCredential],
        endpoints: &BTreeMap<String, NetworkEndpointInfo>,
    ) -> BTreeMap<String, NetworkCredentialInfo> {
        let mut by_name = BTreeMap::new();
        for credential in credentials {
            self.validate_name("credential", &credential.name);
            if by_name
                .insert(
                    credential.name.clone(),
                    NetworkCredentialInfo {
                        endpoint: credential.endpoint.clone(),
                    },
                )
                .is_some()
            {
                self.error(
                    "duplicate credential name",
                    format!(
                        "credential name {} is declared more than once",
                        credential.name
                    ),
                );
            }
            if !is_supported_credential_kind(&credential.kind) {
                self.error(
                    "unsupported credential kind",
                    format!(
                        "credential {} uses unsupported kind {}",
                        credential.name, credential.kind
                    ),
                );
            }
            let Some(endpoint) = endpoints.get(&credential.endpoint) else {
                self.error(
                    "credential references unknown endpoint",
                    format!(
                        "credential {} references endpoint {}",
                        credential.name, credential.endpoint
                    ),
                );
                continue;
            };
            if endpoint.kind != "https" {
                self.error(
                    "credential endpoint must be https",
                    format!(
                        "credential {} references {} endpoint {}",
                        credential.name, endpoint.kind, credential.endpoint
                    ),
                );
            }
            if let Some(condition) = &credential.condition {
                self.validate_http_condition(condition, "credential condition");
            }
        }
        by_name
    }

    fn validate_tunnels(&mut self, tunnels: &[TailscaleTunnel]) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for tunnel in tunnels {
            self.validate_name("tailscale tunnel", &tunnel.name);
            if !names.insert(tunnel.name.clone()) {
                self.error(
                    "duplicate tailscale tunnel name",
                    format!(
                        "tailscale tunnel name {} is declared more than once",
                        tunnel.name
                    ),
                );
            }
        }
        names
    }

    fn validate_rules(
        &mut self,
        rules: &[NetworkRule],
        endpoints: &BTreeMap<String, NetworkEndpointInfo>,
        credentials: &BTreeMap<String, NetworkCredentialInfo>,
        tunnels: &BTreeSet<String>,
    ) {
        for rule in rules {
            if let Some(name) = &rule.name {
                self.validate_name("rule", name);
            }
            if rule.endpoints.is_empty() {
                self.error(
                    "rule requires endpoints",
                    "rule endpoints must not be empty",
                );
                continue;
            }
            let mut family = None;
            let mut endpoint_names = BTreeSet::new();
            for endpoint_name in &rule.endpoints {
                let Some(endpoint) = endpoints.get(endpoint_name) else {
                    self.error(
                        "rule references unknown endpoint",
                        format!("rule references endpoint {endpoint_name}"),
                    );
                    continue;
                };
                endpoint_names.insert(endpoint_name.as_str());
                match family {
                    Some(existing) if existing != endpoint.family => self.error(
                        "rule endpoints must share a family",
                        "all endpoints on one rule must resolve to the same family",
                    ),
                    None => family = Some(endpoint.family),
                    _ => {}
                }
            }
            if rule.condition.is_some() && family != Some(EndpointFamilyKind::Http) {
                self.error(
                    "condition requires http-family endpoints",
                    "conditions are only valid on http-family rules",
                );
            }
            if let Some(condition) = &rule.condition {
                self.validate_http_condition(condition, "rule condition");
            }
            if let Some(credential_name) = &rule.credential {
                let Some(credential) = credentials.get(credential_name) else {
                    self.error(
                        "rule references unknown credential",
                        format!("rule references credential {credential_name}"),
                    );
                    continue;
                };
                if family != Some(EndpointFamilyKind::Http) {
                    self.error(
                        "credential predicate requires http-family endpoints",
                        "rule.credential is only valid on http-family rules",
                    );
                }
                if !endpoint_names.contains(credential.endpoint.as_str()) {
                    self.error(
                        "credential predicate is not compatible with rule endpoints",
                        format!(
                            "credential {credential_name} is bound to endpoint {}",
                            credential.endpoint
                        ),
                    );
                }
            }
            if let Some(tunnel_name) = &rule.tunnel {
                if !tunnels.contains(tunnel_name) {
                    self.error(
                        "rule references unknown tunnel",
                        format!("rule references tunnel {tunnel_name}"),
                    );
                }
                if rule.verdict != Action::Allow {
                    self.error(
                        "tunnel requires allow verdict",
                        "rules with tunnel references must be explicit allow rules",
                    );
                }
            }
        }
    }

    fn validate_forwards(&mut self, forwards: &[NetworkForward], tunnels: &BTreeSet<String>) {
        let mut names = BTreeSet::new();
        for forward in forwards {
            self.validate_name("forward", &forward.name);
            if !names.insert(forward.name.clone()) {
                self.error(
                    "duplicate forward name",
                    format!("forward name {} is declared more than once", forward.name),
                );
            }
            match forward.kind.as_str() {
                "host" => {
                    if forward.tunnel.is_some() {
                        self.error(
                            "host forward cannot reference a tunnel",
                            format!("forward {} is a host forward", forward.name),
                        );
                    }
                }
                "tailscale" => {
                    if let Some(tunnel_name) = &forward.tunnel {
                        if !tunnels.contains(tunnel_name) {
                            self.error(
                                "forward references unknown tunnel",
                                format!("forward {} references tunnel {tunnel_name}", forward.name),
                            );
                        }
                    }
                }
                _ => self.error(
                    "unsupported forward kind",
                    format!(
                        "forward {} uses unsupported kind {}",
                        forward.name, forward.kind
                    ),
                ),
            }
            if !valid_target_selector(&forward.target) {
                self.error(
                    "invalid forward target selector",
                    format!(
                        "forward {} target must start with name:, id:, or label:",
                        forward.name
                    ),
                );
            }
        }
    }

    fn validate_secret_slots(&mut self, policy: &NetworkPolicy) {
        for slot in policy.secret_slots() {
            if !valid_secret_slot(&slot.name) {
                self.error(
                    "invalid network secret slot",
                    format!(
                        "derived slot {} is not a valid lowercase slot path",
                        slot.name
                    ),
                );
            }
        }
    }

    fn validate_name(&mut self, kind: &str, name: &str) {
        if !valid_identifier(name) {
            self.error(
                "invalid policy object name",
                format!("{kind} name {name:?} must use the policy identifier grammar"),
            );
        }
    }

    fn validate_http_condition(&mut self, source: &str, summary: &str) {
        if let Err(err) = HttpCondition::compile(source) {
            self.error(summary, err.to_string());
        }
    }

    fn error(&mut self, summary: impl Into<String>, detail: impl Into<String>) {
        self.diagnostics
            .push(Diagnostic::error("<policy>", 0, 0, summary, detail));
    }

    fn warning(&mut self, summary: impl Into<String>, detail: impl Into<String>) {
        self.diagnostics
            .push(Diagnostic::warning("<policy>", 0, 0, summary, detail));
    }
}

#[derive(Debug, Clone)]
struct NetworkEndpointInfo {
    kind: String,
    family: EndpointFamilyKind,
}

#[derive(Debug, Clone)]
struct NetworkCredentialInfo {
    endpoint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointFamilyKind {
    Ip,
    Http,
}

fn credential_secret_slots(credential: &NetworkCredential) -> Vec<NetworkSecretSlot> {
    let slot = |name: &str| format!("{}.{}", credential.name, name);
    match credential.kind.as_str() {
        "basic_auth" => vec![NetworkSecretSlot::required(
            slot("password"),
            NetworkSecretKind::Plain,
        )],
        "bearer_token" | "header_token" => vec![NetworkSecretSlot::required(
            slot("token"),
            NetworkSecretKind::Plain,
        )],
        "github_oauth" | "openai_codex_oauth" => vec![
            NetworkSecretSlot::required(slot("oauth.access_token"), NetworkSecretKind::OAuth),
            NetworkSecretSlot::required(slot("oauth.expires_at"), NetworkSecretKind::OAuth),
            NetworkSecretSlot::optional(slot("oauth.account_id"), NetworkSecretKind::OAuth),
        ],
        "aws_credential" => vec![
            NetworkSecretSlot::required(slot("access_key_id"), NetworkSecretKind::Plain),
            NetworkSecretSlot::required(slot("secret_access_key"), NetworkSecretKind::Plain),
            NetworkSecretSlot::optional(slot("session_token"), NetworkSecretKind::Plain),
            NetworkSecretSlot::optional(slot("profile"), NetworkSecretKind::Plain),
        ],
        _ => Vec::new(),
    }
}

fn is_supported_credential_kind(kind: &str) -> bool {
    matches!(
        kind,
        "basic_auth"
            | "bearer_token"
            | "header_token"
            | "github_oauth"
            | "openai_codex_oauth"
            | "aws_credential"
    )
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

fn valid_secret_slot(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|segment| {
            let mut chars = segment.chars();
            let Some(first) = chars.next() else {
                return false;
            };
            (first.is_ascii_lowercase() || first.is_ascii_digit() || first == '_')
                && chars.all(|character| {
                    character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || character == '_'
                        || character == '-'
                })
        })
}

fn valid_target_selector(value: &str) -> bool {
    ["name:", "id:", "label:"]
        .iter()
        .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len())
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn default_body_buffer_bytes() -> u64 {
    DEFAULT_BODY_BUFFER_BYTES
}

fn default_body_storage_bytes() -> u64 {
    DEFAULT_BODY_STORAGE_BYTES
}

#[cfg(test)]
mod tests {
    use crate::{Action, NetworkPolicy, NetworkSecretKind};

    #[test]
    fn json_load_normalizes_defaults() {
        let policy = NetworkPolicy::from_json_str(r#"{ "version": 1 }"#).unwrap();

        assert_eq!(policy.version, 1);
        assert_eq!(policy.settings.default_action, Action::Allow);
        assert_eq!(policy.settings.audit.body_buffer_bytes, 1_048_576);
        assert_eq!(policy.settings.audit.body_storage_bytes, 4_096);
        assert!(policy.metadata.is_empty());
        assert!(policy.endpoints.is_empty());
        assert!(policy.credentials.is_empty());
        assert!(policy.rules.is_empty());
        assert!(policy.tailscale.is_empty());
        assert!(policy.forwards.is_empty());
    }

    #[test]
    fn json_loader_rejects_unknown_fields() {
        let error = NetworkPolicy::from_json_str(r#"{ "version": 1, "documents": [] }"#)
            .expect_err("documents is not canonical policy JSON");

        assert!(error.diagnostics[0].detail.contains("unknown field"));
    }

    #[test]
    fn derives_credential_and_tailscale_secret_slots() {
        let policy = NetworkPolicy::from_json_str(
            r#"
            {
              "version": 1,
              "endpoints": [
                { "name": "chatgpt", "kind": "https", "hosts": ["chatgpt.com"] }
              ],
              "credentials": [
                { "name": "codex", "kind": "openai_codex_oauth", "endpoint": "chatgpt" }
              ],
              "tailscale": [
                { "name": "worktail", "tags": ["tag:dev"] }
              ]
            }
            "#,
        )
        .unwrap();

        let slots = policy.secret_slots();
        assert!(slots.iter().any(|slot| {
            slot.name == "codex.oauth.access_token"
                && slot.required
                && slot.kind == NetworkSecretKind::OAuth
                && slot.env_name() == "BENTO_NET_SECRET_CODEX_OAUTH_ACCESS_TOKEN"
        }));
        assert!(slots
            .iter()
            .any(|slot| slot.name == "codex.oauth.account_id" && !slot.required));
        assert!(slots
            .iter()
            .any(|slot| slot.name == "worktail.tailscale.auth_key" && slot.required));
    }

    #[test]
    fn rejects_credential_bound_to_non_https_endpoint() {
        let error = NetworkPolicy::from_json_str(
            r#"
            {
              "version": 1,
              "endpoints": [
                { "name": "metadata", "kind": "http", "hosts": ["metadata.example"] }
              ],
              "credentials": [
                { "name": "token", "kind": "bearer_token", "endpoint": "metadata" }
              ]
            }
            "#,
        )
        .expect_err("credentials require https endpoints");

        assert!(error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.summary == "credential endpoint must be https"));
    }

    #[test]
    fn rejects_ip_rule_condition() {
        let error = NetworkPolicy::from_json_str(
            r#"
            {
              "version": 1,
              "endpoints": [
                {
                  "name": "dns",
                  "kind": "ip",
                  "destination_cidrs": ["1.1.1.1/32"],
                  "protocol": "udp",
                  "ports": [{ "start": 53, "end": 53 }]
                }
              ],
              "rules": [
                {
                  "endpoints": ["dns"],
                  "condition": "http.method == 'GET'",
                  "verdict": "allow"
                }
              ]
            }
            "#,
        )
        .expect_err("conditions require http-family rules");

        assert!(error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.summary == "condition requires http-family endpoints"));
    }
}
