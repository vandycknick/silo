use crate::{
    Action, Diagnostic, DiagnosticSeverity, IpProtocol, NetworkAuditSettings, NetworkCredential,
    NetworkEndpoint, NetworkForward, NetworkPolicy, NetworkRule, PortRange, TailscaleTunnel,
};
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct NetworkPolicyBuilder {
    policy: NetworkPolicy,
}

impl NetworkPolicyBuilder {
    pub fn new() -> Self {
        Self {
            policy: NetworkPolicy::empty(),
        }
    }

    pub fn from_policy(policy: NetworkPolicy) -> Self {
        Self {
            policy: policy.normalized(),
        }
    }

    pub fn default_allow(mut self) -> Self {
        self.policy.settings.default_action = Action::Allow;
        self
    }

    pub fn default_deny(mut self) -> Self {
        self.policy.settings.default_action = Action::Deny;
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.policy.metadata.insert(key.into(), value.into());
        self
    }

    pub fn metadata_map(mut self, metadata: Map<String, Value>) -> Self {
        self.policy.metadata = metadata;
        self
    }

    pub fn audit(
        mut self,
        configure: impl FnOnce(NetworkAuditBuilder) -> NetworkAuditBuilder,
    ) -> Self {
        self.policy.settings.audit = configure(NetworkAuditBuilder::from_settings(
            self.policy.settings.audit.clone(),
        ))
        .build();
        self
    }

    pub fn endpoint(
        mut self,
        name: impl Into<String>,
        configure: impl FnOnce(NetworkEndpointBuilder) -> NetworkEndpointBuilder,
    ) -> Self {
        self.policy
            .endpoints
            .push(configure(NetworkEndpointBuilder::new(name)).build());
        self
    }

    pub fn credential(
        mut self,
        name: impl Into<String>,
        configure: impl FnOnce(NetworkCredentialBuilder) -> NetworkCredentialBuilder,
    ) -> Self {
        self.policy
            .credentials
            .push(configure(NetworkCredentialBuilder::new(name)).build());
        self
    }

    pub fn rule(
        mut self,
        name: impl Into<String>,
        configure: impl FnOnce(NetworkRuleBuilder) -> NetworkRuleBuilder,
    ) -> Self {
        self.policy
            .rules
            .push(configure(NetworkRuleBuilder::named(name)).build());
        self
    }

    pub fn unnamed_rule(
        mut self,
        configure: impl FnOnce(NetworkRuleBuilder) -> NetworkRuleBuilder,
    ) -> Self {
        self.policy
            .rules
            .push(configure(NetworkRuleBuilder::unnamed()).build());
        self
    }

    pub fn tailscale(
        mut self,
        name: impl Into<String>,
        configure: impl FnOnce(TailscaleTunnelBuilder) -> TailscaleTunnelBuilder,
    ) -> Self {
        self.policy
            .tailscale
            .push(configure(TailscaleTunnelBuilder::new(name)).build());
        self
    }

    pub fn forward(
        mut self,
        name: impl Into<String>,
        configure: impl FnOnce(NetworkForwardBuilder) -> NetworkForwardBuilder,
    ) -> Self {
        self.policy
            .forwards
            .push(configure(NetworkForwardBuilder::new(name)).build());
        self
    }

    pub fn build(mut self) -> Result<NetworkPolicy, NetworkPolicyBuildError> {
        self.policy.normalize();
        let diagnostics = self.policy.validate();
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        {
            return Err(NetworkPolicyBuildError { diagnostics });
        }
        Ok(self.policy)
    }
}

impl Default for NetworkPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct NetworkAuditBuilder {
    settings: NetworkAuditSettings,
}

impl NetworkAuditBuilder {
    fn from_settings(settings: NetworkAuditSettings) -> Self {
        Self { settings }
    }

    pub fn body_buffer_bytes(mut self, bytes: u64) -> Self {
        self.settings.body_buffer_bytes = bytes;
        self
    }

    pub fn body_storage_bytes(mut self, bytes: u64) -> Self {
        self.settings.body_storage_bytes = bytes;
        self
    }

    fn build(self) -> NetworkAuditSettings {
        self.settings
    }
}

#[derive(Debug, Clone)]
pub struct NetworkEndpointBuilder {
    endpoint: NetworkEndpoint,
}

impl NetworkEndpointBuilder {
    fn new(name: impl Into<String>) -> Self {
        Self {
            endpoint: NetworkEndpoint {
                name: name.into(),
                kind: "ip".to_string(),
                source_cidrs: Vec::new(),
                destination_cidrs: Vec::new(),
                protocol: IpProtocol::Any,
                ports: Vec::new(),
                hosts: Vec::new(),
            },
        }
    }

    pub fn ip(mut self) -> Self {
        self.endpoint.kind = "ip".to_string();
        self
    }

    pub fn http(mut self) -> Self {
        self.endpoint.kind = "http".to_string();
        self
    }

    pub fn https(mut self) -> Self {
        self.endpoint.kind = "https".to_string();
        self
    }

    pub fn source_cidr(mut self, cidr: impl Into<String>) -> Self {
        self.endpoint.source_cidrs.push(cidr.into());
        self
    }

    pub fn destination_cidr(mut self, cidr: impl Into<String>) -> Self {
        self.endpoint.destination_cidrs.push(cidr.into());
        self
    }

    pub fn any_protocol(mut self) -> Self {
        self.endpoint.protocol = IpProtocol::Any;
        self
    }

    pub fn tcp(mut self) -> Self {
        self.endpoint.protocol = IpProtocol::Tcp;
        self
    }

    pub fn udp(mut self) -> Self {
        self.endpoint.protocol = IpProtocol::Udp;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.endpoint.ports.push(PortRange {
            start: port,
            end: port,
        });
        self
    }

    pub fn port_range(mut self, start: u16, end: u16) -> Self {
        self.endpoint.ports.push(PortRange { start, end });
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.endpoint.hosts.push(host.into());
        self
    }

    fn build(self) -> NetworkEndpoint {
        self.endpoint
    }
}

#[derive(Debug, Clone)]
pub struct NetworkCredentialBuilder {
    credential: NetworkCredential,
}

impl NetworkCredentialBuilder {
    fn new(name: impl Into<String>) -> Self {
        Self {
            credential: NetworkCredential {
                name: name.into(),
                kind: "bearer_token".to_string(),
                endpoint: String::new(),
                username: None,
                header: None,
                prefix: None,
                idempotency_key: false,
                condition: None,
            },
        }
    }

    pub fn basic_auth(mut self) -> Self {
        self.credential.kind = "basic_auth".to_string();
        self
    }

    pub fn bearer_token(mut self) -> Self {
        self.credential.kind = "bearer_token".to_string();
        self
    }

    pub fn header_token(mut self) -> Self {
        self.credential.kind = "header_token".to_string();
        self
    }

    pub fn github_oauth(mut self) -> Self {
        self.credential.kind = "github_oauth".to_string();
        self
    }

    pub fn openai_codex_oauth(mut self) -> Self {
        self.credential.kind = "openai_codex_oauth".to_string();
        self
    }

    pub fn aws_credential(mut self) -> Self {
        self.credential.kind = "aws_credential".to_string();
        self
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.credential.endpoint = endpoint.into();
        self
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.credential.username = Some(username.into());
        self
    }

    pub fn header(mut self, header: impl Into<String>) -> Self {
        self.credential.header = Some(header.into());
        self
    }

    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.credential.prefix = Some(prefix.into());
        self
    }

    pub fn idempotency_key(mut self) -> Self {
        self.credential.idempotency_key = true;
        self
    }

    pub fn idempotency_key_enabled(mut self, enabled: bool) -> Self {
        self.credential.idempotency_key = enabled;
        self
    }

    pub fn condition(mut self, condition: impl Into<String>) -> Self {
        self.credential.condition = Some(condition.into());
        self
    }

    fn build(self) -> NetworkCredential {
        self.credential
    }
}

#[derive(Debug, Clone)]
pub struct NetworkRuleBuilder {
    rule: NetworkRule,
}

impl NetworkRuleBuilder {
    fn named(name: impl Into<String>) -> Self {
        Self::new(Some(name.into()))
    }

    fn unnamed() -> Self {
        Self::new(None)
    }

    fn new(name: Option<String>) -> Self {
        Self {
            rule: NetworkRule {
                name,
                endpoints: Vec::new(),
                credential: None,
                condition: None,
                tunnel: None,
                verdict: Action::Allow,
                priority: 0,
                disabled: false,
                reason: String::new(),
            },
        }
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.rule.endpoints.push(endpoint.into());
        self
    }

    pub fn credential(mut self, credential: impl Into<String>) -> Self {
        self.rule.credential = Some(credential.into());
        self
    }

    pub fn condition(mut self, condition: impl Into<String>) -> Self {
        self.rule.condition = Some(condition.into());
        self
    }

    pub fn tunnel(mut self, tunnel: impl Into<String>) -> Self {
        self.rule.tunnel = Some(tunnel.into());
        self
    }

    pub fn priority(mut self, priority: i32) -> Self {
        self.rule.priority = priority;
        self
    }

    pub fn disabled(mut self, disabled: bool) -> Self {
        self.rule.disabled = disabled;
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.rule.reason = reason.into();
        self
    }

    pub fn allow(mut self) -> Self {
        self.rule.verdict = Action::Allow;
        self
    }

    pub fn deny(mut self) -> Self {
        self.rule.verdict = Action::Deny;
        self
    }

    fn build(self) -> NetworkRule {
        self.rule
    }
}

#[derive(Debug, Clone)]
pub struct TailscaleTunnelBuilder {
    tunnel: TailscaleTunnel,
}

impl TailscaleTunnelBuilder {
    fn new(name: impl Into<String>) -> Self {
        Self {
            tunnel: TailscaleTunnel {
                name: name.into(),
                tags: Vec::new(),
                hostname: None,
                control_url: None,
            },
        }
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tunnel.tags.push(tag.into());
        self
    }

    pub fn tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tunnel.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.tunnel.hostname = Some(hostname.into());
        self
    }

    pub fn control_url(mut self, control_url: impl Into<String>) -> Self {
        self.tunnel.control_url = Some(control_url.into());
        self
    }

    fn build(self) -> TailscaleTunnel {
        self.tunnel
    }
}

#[derive(Debug, Clone)]
pub struct NetworkForwardBuilder {
    forward: NetworkForward,
}

impl NetworkForwardBuilder {
    fn new(name: impl Into<String>) -> Self {
        Self {
            forward: NetworkForward {
                name: name.into(),
                kind: "host".to_string(),
                target: String::new(),
                target_port: 0,
                listen: String::new(),
                tunnel: None,
            },
        }
    }

    pub fn host(mut self) -> Self {
        self.forward.kind = "host".to_string();
        self.forward.tunnel = None;
        self
    }

    pub fn tailscale(mut self, tunnel: impl Into<String>) -> Self {
        self.forward.kind = "tailscale".to_string();
        self.forward.tunnel = Some(tunnel.into());
        self
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.forward.target = target.into();
        self
    }

    pub fn target_port(mut self, port: u16) -> Self {
        self.forward.target_port = port;
        self
    }

    pub fn listen(mut self, listen: impl Into<String>) -> Self {
        self.forward.listen = listen.into();
        self
    }

    fn build(self) -> NetworkForward {
        self.forward
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPolicyBuildError {
    pub diagnostics: Vec<Diagnostic>,
}

impl std::fmt::Display for NetworkPolicyBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_count = self
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .count();
        write!(
            formatter,
            "build network policy failed with {error_count} error(s)"
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

impl std::error::Error for NetworkPolicyBuildError {}

#[cfg(test)]
mod tests {
    use crate::{Action, NetworkPolicy, NetworkPolicyBuildError};

    #[test]
    fn builder_creates_valid_canonical_policy() {
        let policy = NetworkPolicy::builder()
            .default_deny()
            .metadata("source", "test")
            .audit(|audit| audit.body_buffer_bytes(8192).body_storage_bytes(4096))
            .endpoint("openai", |endpoint| {
                endpoint.https().host("API.OpenAI.com.").host("chatgpt.com")
            })
            .credential("codex", |credential| {
                credential.openai_codex_oauth().endpoint("openai")
            })
            .rule("allow-openai", |rule| {
                rule.endpoint("openai")
                    .credential("codex")
                    .priority(100)
                    .reason("Codex auth flow")
                    .allow()
            })
            .build()
            .unwrap();

        assert_eq!(policy.settings().default_action, Action::Deny);
        assert_eq!(policy.metadata()["source"], "test");
        assert_eq!(policy.endpoints()[0].hosts[0], "api.openai.com");
        assert_eq!(policy.credentials()[0].endpoint, "openai");
        assert_eq!(policy.rules()[0].priority, 100);
    }

    #[test]
    fn builder_uses_existing_validation() {
        let error = NetworkPolicy::builder()
            .default_deny()
            .endpoint("openai", |endpoint| endpoint.https())
            .build()
            .expect_err("https endpoints require hosts");

        assert!(error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.summary == "http endpoint requires hosts"));
    }

    #[test]
    fn builder_rejects_zero_endpoint_ports() {
        let single_port_error = NetworkPolicy::builder()
            .default_deny()
            .endpoint("dns", |endpoint| endpoint.udp().port(0))
            .build()
            .expect_err("port 0 is invalid");

        assert_invalid_port_range(single_port_error);

        let range_error = NetworkPolicy::builder()
            .default_deny()
            .endpoint("dns", |endpoint| endpoint.udp().port_range(0, 53))
            .build()
            .expect_err("port range starting at 0 is invalid");

        assert_invalid_port_range(range_error);
    }

    fn assert_invalid_port_range(error: NetworkPolicyBuildError) {
        assert!(error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.summary == "invalid port range"));
    }
}
