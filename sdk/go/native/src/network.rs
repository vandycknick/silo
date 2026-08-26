use libvm::{
    NetworkAuditBuilder, NetworkCredentialBuilder, NetworkEndpointBuilder, NetworkForwardBuilder,
    NetworkPolicy, NetworkRuleBuilder, TailscaleTunnelBuilder,
};
use serde::Deserialize;

use crate::buffer::SiloBuffer;
use crate::error::{catch_ffi, invalid_argument, SiloError};
use crate::runtime::request_bytes;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRequest {
    json: Option<String>,
    config: Option<PolicyConfig>,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PolicyConfig {
    default_action: Option<String>,
    #[serde(default)]
    metadata: std::collections::BTreeMap<String, String>,
    audit: Option<Audit>,
    #[serde(default)]
    endpoints: Vec<Endpoint>,
    #[serde(default)]
    credentials: Vec<Credential>,
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    tunnels: Vec<Tunnel>,
    #[serde(default)]
    forwards: Vec<Forward>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Audit {
    body_buffer_bytes: Option<u64>,
    body_storage_bytes: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Port {
    start: u16,
    end: Option<u16>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    name: String,
    kind: String,
    #[serde(default)]
    source_cidrs: Vec<String>,
    #[serde(default)]
    destination_cidrs: Vec<String>,
    protocol: Option<String>,
    #[serde(default)]
    ports: Vec<Port>,
    #[serde(default)]
    hosts: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    name: String,
    kind: String,
    endpoint: Option<String>,
    username: Option<String>,
    header: Option<String>,
    prefix: Option<String>,
    idempotency_key: Option<bool>,
    condition: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    name: Option<String>,
    #[serde(default)]
    endpoints: Vec<String>,
    credential: Option<String>,
    condition: Option<String>,
    tunnel: Option<String>,
    priority: Option<i32>,
    #[serde(default)]
    disabled: bool,
    reason: Option<String>,
    verdict: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tunnel {
    name: String,
    #[serde(default)]
    tags: Vec<String>,
    hostname: Option<String>,
    control_url: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Forward {
    name: String,
    kind: String,
    tunnel: Option<String>,
    target: Option<String>,
    target_port: Option<u16>,
    listen: Option<String>,
}

#[no_mangle]
pub unsafe extern "C" fn silo_network_policy_build(
    request_ptr: *const u8,
    request_len: usize,
    out_policy: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        if out_policy.is_null() {
            return Err(invalid_argument("out_policy must not be null"));
        }
        *out_policy = SiloBuffer::empty();
        let request: PolicyRequest =
            serde_json::from_slice(request_bytes(request_ptr, request_len)?).map_err(|error| {
                invalid_argument(format!("decode network policy request: {error}"))
            })?;
        let policy = match (request.json, request.config) {
            (Some(value), None) => NetworkPolicy::from_json_str(&value).map_err(|error| {
                invalid_argument(format!("invalid network policy JSON: {error}"))
            })?,
            (None, Some(config)) => build(config)?,
            _ => {
                return Err(invalid_argument(
                    "provide exactly one policy JSON or configuration",
                ))
            }
        };
        let value = serde_json::to_vec(&policy.normalized())
            .map_err(|error| SiloError::new("Serialization", error.to_string()))?;
        *out_policy = SiloBuffer::from_vec(value);
        Ok(())
    })
}
fn build(input: PolicyConfig) -> Result<NetworkPolicy, *mut SiloError> {
    let mut builder = NetworkPolicy::builder();
    if let Some(action) = input.default_action {
        builder = match action.as_str() {
            "allow" => builder.default_allow(),
            "deny" => builder.default_deny(),
            _ => return Err(invalid_argument("unsupported default network action")),
        }
    }
    for (key, value) in input.metadata {
        builder = builder.metadata(key, value)
    }
    if let Some(audit) = input.audit {
        builder = builder.audit(|value| apply_audit(value, audit))
    }
    for endpoint in input.endpoints {
        let name = endpoint.name.clone();
        builder = builder.endpoint(name, |value| apply_endpoint(value, endpoint))
    }
    for credential in input.credentials {
        let name = credential.name.clone();
        builder = builder.credential(name, |value| apply_credential(value, credential))
    }
    for rule in input.rules {
        builder = if let Some(name) = rule.name.clone() {
            builder.rule(name, |value| apply_rule(value, rule))
        } else {
            builder.unnamed_rule(|value| apply_rule(value, rule))
        }
    }
    for tunnel in input.tunnels {
        let name = tunnel.name.clone();
        builder = builder.tailscale(name, |value| apply_tunnel(value, tunnel))
    }
    for forward in input.forwards {
        let name = forward.name.clone();
        builder = builder.forward(name, |value| apply_forward(value, forward))
    }
    builder
        .build()
        .map_err(|error| invalid_argument(format!("invalid network policy: {error}")))
}
fn apply_audit(mut b: NetworkAuditBuilder, v: Audit) -> NetworkAuditBuilder {
    if let Some(x) = v.body_buffer_bytes {
        b = b.body_buffer_bytes(x)
    }
    if let Some(x) = v.body_storage_bytes {
        b = b.body_storage_bytes(x)
    }
    b
}
fn apply_endpoint(mut b: NetworkEndpointBuilder, v: Endpoint) -> NetworkEndpointBuilder {
    b = match v.kind.as_str() {
        "ip" => b.ip(),
        "http" => b.http(),
        "https" => b.https(),
        _ => b,
    };
    for x in v.source_cidrs {
        b = b.source_cidr(x)
    }
    for x in v.destination_cidrs {
        b = b.destination_cidr(x)
    }
    if let Some(x) = v.protocol {
        b = match x.as_str() {
            "any" => b.any_protocol(),
            "tcp" => b.tcp(),
            "udp" => b.udp(),
            _ => b,
        }
    }
    for x in v.ports {
        b = if let Some(end) = x.end {
            b.port_range(x.start, end)
        } else {
            b.port(x.start)
        }
    }
    for x in v.hosts {
        b = b.host(x)
    }
    b
}
fn apply_credential(mut b: NetworkCredentialBuilder, v: Credential) -> NetworkCredentialBuilder {
    b = match v.kind.as_str() {
        "basic_auth" => b.basic_auth(),
        "bearer_token" => b.bearer_token(),
        "header_token" => b.header_token(),
        "github_oauth" => b.github_oauth(),
        "openai_codex_oauth" => b.openai_codex_oauth(),
        "aws_credential" => b.aws_credential(),
        _ => b,
    };
    if let Some(x) = v.endpoint {
        b = b.endpoint(x)
    }
    if let Some(x) = v.username {
        b = b.username(x)
    }
    if let Some(x) = v.header {
        b = b.header(x)
    }
    if let Some(x) = v.prefix {
        b = b.prefix(x)
    }
    if let Some(x) = v.idempotency_key {
        b = b.idempotency_key_enabled(x)
    }
    if let Some(x) = v.condition {
        b = b.condition(x)
    }
    b
}
fn apply_rule(mut b: NetworkRuleBuilder, v: Rule) -> NetworkRuleBuilder {
    for x in v.endpoints {
        b = b.endpoint(x)
    }
    if let Some(x) = v.credential {
        b = b.credential(x)
    }
    if let Some(x) = v.condition {
        b = b.condition(x)
    }
    if let Some(x) = v.tunnel {
        b = b.tunnel(x)
    }
    if let Some(x) = v.priority {
        b = b.priority(x)
    }
    b = b.disabled(v.disabled);
    if let Some(x) = v.reason {
        b = b.reason(x)
    }
    if let Some(x) = v.verdict {
        b = match x.as_str() {
            "allow" => b.allow(),
            "deny" => b.deny(),
            _ => b,
        }
    }
    b
}
fn apply_tunnel(mut b: TailscaleTunnelBuilder, v: Tunnel) -> TailscaleTunnelBuilder {
    b = b.tags(v.tags);
    if let Some(x) = v.hostname {
        b = b.hostname(x)
    }
    if let Some(x) = v.control_url {
        b = b.control_url(x)
    }
    b
}
fn apply_forward(mut b: NetworkForwardBuilder, v: Forward) -> NetworkForwardBuilder {
    b = match v.kind.as_str() {
        "host" => b.host(),
        "tailscale" => v.tunnel.map_or(b.clone(), |x| b.tailscale(x)),
        _ => b,
    };
    if let Some(x) = v.target {
        b = b.target(x)
    }
    if let Some(x) = v.target_port {
        b = b.target_port(x)
    }
    if let Some(x) = v.listen {
        b = b.listen(x)
    }
    b
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use crate::network::silo_network_policy_build;
    use crate::{silo_buffer_free, silo_error_free, SiloBuffer};

    #[test]
    fn builds_canonical_policy_through_the_abi() {
        let request = br#"{"config":{"default_action":"deny","metadata":{"source":"go"}}}"#;
        let mut output = SiloBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        };
        let error =
            unsafe { silo_network_policy_build(request.as_ptr(), request.len(), &mut output) };
        assert!(error.is_null());
        assert!(output.len > 0);
        unsafe { silo_buffer_free(output) };
    }

    #[test]
    fn rejects_malformed_policy_requests() {
        let request = b"{";
        let mut output = SiloBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        };
        let error =
            unsafe { silo_network_policy_build(request.as_ptr(), request.len(), &mut output) };
        assert!(!error.is_null());
        unsafe { silo_error_free(error) };
    }
}
