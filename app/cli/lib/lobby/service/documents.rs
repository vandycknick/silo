use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_yaml_ng::Value as Yaml;
use silod_spec::daemon::v1 as w;

use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::identity::{Peer, Principal};

pub(crate) const DOCUMENT_LIMIT: usize = 64 << 10;
pub(crate) const TEMPLATE_LABEL: &str = "io.silo.lobby.template";
pub(crate) const POLICY_LABEL: &str = "io.silo.lobby.policy";
pub(crate) const GUEST_PORTS_LABEL: &str = "io.silo.lobby.guest-tcp-ports";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DocumentKind {
    Template,
    Policy,
}

impl DocumentKind {
    pub(crate) fn directory(self) -> &'static str {
        match self {
            Self::Template => "templates",
            Self::Policy => "policies",
        }
    }
    pub(crate) fn extension(self) -> &'static str {
        match self {
            Self::Template => ".yaml",
            Self::Policy => ".hcl",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DocumentTier {
    Yours,
    Operator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Template {
    pub(crate) version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resources: Option<TemplateResources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) disk_size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vsock: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) userdata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<TemplateNetwork>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TemplateResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cpus: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) memory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TemplateNetwork {
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) policy_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) publish: Vec<u16>,
}

pub(crate) fn valid_document_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Clone, Copy)]
enum Shape {
    Template,
    Resources,
    Network,
    Labels,
    Ports,
    String,
    Integer,
    Bool,
}

fn yaml_shape(value: &Yaml, shape: Shape, depth: usize) -> Outcome<()> {
    if depth > 16 || matches!(value, Yaml::Null | Yaml::Tagged(_)) {
        return Err(usage_document());
    }
    match shape {
        Shape::String if matches!(value, Yaml::String(_)) => Ok(()),
        Shape::Integer if value.as_u64().is_some() => Ok(()),
        Shape::Bool if matches!(value, Yaml::Bool(_)) => Ok(()),
        Shape::Ports => {
            let values = value.as_sequence().ok_or_else(usage_document)?;
            if values.len() > 256 {
                return Err(usage_document());
            }
            for value in values {
                yaml_shape(value, Shape::Integer, depth + 1)?;
            }
            Ok(())
        }
        Shape::Template | Shape::Resources | Shape::Network | Shape::Labels => {
            let fields = value.as_mapping().ok_or_else(usage_document)?;
            for (key, value) in fields {
                let key = key.as_str().ok_or_else(usage_document)?;
                let child = match (shape, key) {
                    (
                        Shape::Template,
                        "version" | "description" | "image" | "disk_size" | "userdata",
                    ) => Shape::String,
                    (Shape::Template, "resources") => Shape::Resources,
                    (Shape::Template, "network") => Shape::Network,
                    (Shape::Template, "labels") => Shape::Labels,
                    (Shape::Template, "vsock") => Shape::Bool,
                    (Shape::Resources, "cpus") => Shape::Integer,
                    (Shape::Resources, "memory") => Shape::String,
                    (Shape::Network, "kind" | "policy_ref") => Shape::String,
                    (Shape::Network, "publish") => Shape::Ports,
                    (Shape::Labels, _) => Shape::String,
                    _ => {
                        return Err(Failure::new(
                            Code::Usage,
                            format!("unknown template field: {key}"),
                        ))
                    }
                };
                yaml_shape(value, child, depth + 1)?;
            }
            Ok(())
        }
        _ => Err(usage_document()),
    }
}

/// serde_yaml resolves aliases and merge-key tags before exposing Values. Guard
/// those tokens while respecting quoted/plain scalars and block-scalar content.
fn reject_yaml_aliases(raw: &str) -> Outcome<()> {
    let mut quote = None;
    let mut flow = 0usize;
    let mut block = None;
    let mut plain_indent = None;
    let mut plain = false;
    for line in raw.lines() {
        let bytes = line.as_bytes();
        let indent = bytes.iter().take_while(|byte| **byte == b' ').count();
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if let Some(parent) = block {
            if indent > parent {
                continue;
            }
            block = None;
        }
        if quote.is_none() && flow == 0 && plain_indent.is_some_and(|parent| indent > parent) {
            continue;
        }
        plain_indent = None;
        let mut start = !plain || flow == 0;
        let mut quoted_key = false;
        let mut explicit_string = false;
        plain = false;
        let mut index = indent;
        while let Some(&byte) = bytes.get(index) {
            if let Some(delimiter) = quote {
                if delimiter == b'"' && byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == delimiter {
                    if delimiter == b'\'' && bytes.get(index + 1) == Some(&b'\'') {
                        index += 2;
                        continue;
                    }
                    quote = None;
                    quoted_key = true;
                }
                index += 1;
                continue;
            }
            if start && byte.is_ascii_whitespace() {
                index += 1;
                continue;
            }
            if start && byte == b'#' {
                break;
            }
            if start && byte == b'*' {
                return Err(Failure::new(Code::Usage, "aliases are not allowed"));
            }
            if start && !explicit_string && bytes.get(index..index + 2) == Some(b"<<") {
                let mut after = index + 2;
                while bytes.get(after).is_some_and(u8::is_ascii_whitespace) {
                    after += 1;
                }
                if bytes.get(after) == Some(&b':') {
                    return Err(Failure::new(Code::Usage, "merges are not allowed"));
                }
            }
            if start && (byte == b'&' || byte == b'!') {
                let property_start = index;
                if byte == b'!' && bytes.get(index + 1) == Some(&b'<') {
                    index += 2;
                    while bytes.get(index).is_some_and(|byte| *byte != b'>') {
                        index += 1;
                    }
                    index = (index + 1).min(bytes.len());
                } else {
                    index += 1;
                    while bytes
                        .get(index)
                        .is_some_and(|byte| !byte.is_ascii_whitespace() && !b",[]{}".contains(byte))
                    {
                        index += 1;
                    }
                }
                explicit_string |= matches!(
                    &line[property_start..index],
                    "!!str" | "!<tag:yaml.org,2002:str>"
                );
                continue;
            }
            if start && (byte == b'\'' || byte == b'"') {
                quote = Some(byte);
                start = false;
                plain = false;
            } else if start && (byte == b'|' || byte == b'>') && flow == 0 {
                block = Some(indent);
                break;
            } else if (start || flow > 0) && (byte == b'{' || byte == b'[') {
                flow += 1;
                start = true;
                plain = false;
            } else if flow > 0 && (byte == b'}' || byte == b']') {
                flow -= 1;
                start = false;
                plain = false;
            } else if (flow > 0 && byte == b',')
                || (byte == b':'
                    && (quoted_key
                        || bytes.get(index + 1).is_none_or(|next| {
                            next.is_ascii_whitespace() || (flow > 0 && b",[]{}".contains(next))
                        })))
            {
                start = true;
                plain = false;
            } else if start
                && (byte == b'-' || byte == b'?')
                && bytes.get(index + 1).is_none_or(u8::is_ascii_whitespace)
            {
                start = true;
            } else if byte == b'#' && index > 0 && bytes[index - 1].is_ascii_whitespace() {
                break;
            } else {
                if start {
                    plain = true;
                }
                start = false;
            }
            if !byte.is_ascii_whitespace() {
                quoted_key = false;
            }
            if !byte.is_ascii_whitespace() {
                explicit_string = false;
            }
            index += 1;
        }
        if plain && flow == 0 {
            plain_indent = Some(indent);
        }
    }
    Ok(())
}

pub(crate) fn parse_template(raw: &str) -> Outcome<Template> {
    check_document_size(raw)?;
    reject_yaml_aliases(raw)?;
    let node: Yaml = serde_yaml_ng::from_str(raw).map_err(|_| usage_document())?;
    yaml_shape(&node, Shape::Template, 0)?;
    let template: Template = serde_yaml_ng::from_value(node).map_err(|_| usage_document())?;
    if template.version != "1" {
        return Err(Failure::new(
            Code::Usage,
            "template version must be the string '1'",
        ));
    }
    if template
        .description
        .as_ref()
        .is_some_and(|value| value.len() > 4096 || !text(value))
    {
        return Err(usage_document());
    }
    if let Some(resources) = &template.resources {
        if resources.cpus.is_some_and(|cpus| cpus == 0 || cpus > 255) {
            return Err(usage_document());
        }
        if let Some(memory) = &resources.memory {
            crate::lobby::units::memory(memory)?;
        }
    }
    if let Some(disk) = &template.disk_size {
        crate::lobby::units::disk(disk)?;
    }
    if template.vsock == Some(false) {
        return Err(Failure::new(
            Code::Usage,
            "remote guest management requires vsock: true",
        ));
    }
    if template
        .userdata
        .as_ref()
        .is_some_and(|value| value.is_empty() || !valid_userdata(value))
    {
        return Err(Failure::new(
            Code::Usage,
            "userdata must be an inline shebang script of at most 16KiB",
        ));
    }
    validate_labels(&template.labels)?;
    if let Some(network) = &template.network {
        if network.kind != "private" {
            return Err(Failure::new(
                Code::Usage,
                "only private networking is allowed",
            ));
        }
        if network
            .policy_ref
            .as_ref()
            .is_some_and(|name| !valid_document_name(name))
        {
            return Err(Failure::new(Code::Usage, "invalid policy_ref"));
        }
        let mut seen = BTreeSet::new();
        if network
            .publish
            .iter()
            .any(|port| *port == 0 || !seen.insert(*port))
        {
            return Err(Failure::new(
                Code::Usage,
                "publish requires unique fixed guest TCP ports 1..65535",
            ));
        }
    }
    Ok(template)
}

pub(crate) fn valid_userdata(value: &str) -> bool {
    value.len() <= 16384 && !value.contains('\0') && (value.is_empty() || value.starts_with("#!"))
}

pub(crate) fn validate_labels(labels: &BTreeMap<String, String>) -> Outcome<()> {
    if labels.len() > 32 {
        return Err(Failure::new(Code::Usage, "too many labels"));
    }
    if labels.iter().any(|(key, value)| {
        key.is_empty()
            || key.len() > 128
            || value.len() > 1024
            || !text(key)
            || !text(value)
            || key.starts_with("io.silo.")
    }) {
        return Err(Failure::new(Code::Usage, "invalid or reserved label"));
    }
    Ok(())
}

fn text(value: &str) -> bool {
    !value.chars().any(char::is_control)
}
fn usage_document() -> Failure {
    Failure::new(Code::Usage, "invalid remote document field type")
}
fn check_document_size(raw: &str) -> Outcome<()> {
    if raw.is_empty() || raw.len() > DOCUMENT_LIMIT {
        Err(Failure::new(Code::Usage, "document must be 1..65536 bytes"))
    } else {
        Ok(())
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PolicyAuthority {
    metadata: BTreeMap<String, Value>,
    tailscale: Vec<Value>,
    forwards: Vec<ForwardAuthority>,
    rules: Vec<RuleAuthority>,
}
#[derive(Deserialize)]
struct ForwardAuthority {
    kind: String,
    target: String,
    tunnel: Option<String>,
}
#[derive(Deserialize)]
struct RuleAuthority {
    tunnel: Option<String>,
}

pub(crate) fn validate_remote_policy(policy: &w::PolicyDocument) -> Outcome<()> {
    if policy.canonical_json.len() > DOCUMENT_LIMIT || policy.hcl.len() > DOCUMENT_LIMIT {
        return Err(Failure::new(
            Code::Usage,
            "canonical document exceeds 64KiB",
        ));
    }
    let authority: PolicyAuthority =
        serde_json::from_str(&policy.canonical_json).map_err(|_| usage_document())?;
    if authority
        .metadata
        .keys()
        .any(|key| key.starts_with("io.silo.lobby."))
    {
        return Err(Failure::new(
            Code::Usage,
            "remote policies cannot declare reserved lobby metadata",
        ));
    }
    if !authority.tailscale.is_empty() {
        return Err(Failure::new(
            Code::Usage,
            "remote policies cannot declare tailscale nodes",
        ));
    }
    if authority.forwards.iter().any(|forward| {
        forward.kind != "tailscale" || forward.target != "self" || forward.tunnel.is_some()
    }) {
        return Err(Failure::new(
            Code::Usage,
            "remote policy forwards require tailscale, target self, and no explicit tunnel",
        ));
    }
    if authority.rules.iter().any(|rule| rule.tunnel.is_some()) {
        return Err(Failure::new(
            Code::Usage,
            "remote policies cannot reference tunnels",
        ));
    }
    Ok(())
}

pub(crate) async fn parse_remote_policy<N, F>(
    raw: &str,
    normalize: &mut N,
) -> Outcome<w::PolicyDocument>
where
    N: FnMut(w::NormalizePolicyRequest) -> F,
    F: Future<Output = Outcome<w::PolicyDocument>>,
{
    check_document_size(raw)?;
    let policy = normalize(policy_request(w::normalize_policy_request::Input::Hcl(
        raw.to_owned(),
    )))
    .await?;
    validate_remote_policy(&policy)?;
    Ok(policy)
}

fn policy_request(input: w::normalize_policy_request::Input) -> w::NormalizePolicyRequest {
    w::NormalizePolicyRequest { input: Some(input) }
}

/// Preserve canonical plugin fields and explicit denies, and bind authored
/// same-VM forwards without changing their protocol or TLS configuration.
pub(crate) async fn inject_tailnet<N, F>(
    policy: Option<&w::PolicyDocument>,
    hostname: &str,
    owner: &Principal,
    control_url: &str,
    requested_tags: &[String],
    normalize: &mut N,
) -> Outcome<w::PolicyDocument>
where
    N: FnMut(w::NormalizePolicyRequest) -> F,
    F: Future<Output = Outcome<w::PolicyDocument>>,
{
    Principal::parse(owner.as_str()).map_err(|_| usage_document())?;
    let empty;
    let policy = match policy {
        Some(policy) => policy,
        None => {
            empty = normalize(policy_request(
                w::normalize_policy_request::Input::Empty(()),
            ))
            .await?;
            &empty
        }
    };
    validate_remote_policy(policy)?;
    let tags = if !requested_tags.is_empty() {
        serde_json::to_string(requested_tags)
    } else if owner.is_tag() {
        serde_json::to_string(&[owner.as_str()])
    } else {
        serde_json::to_string(&[] as &[&str])
    }
    .map_err(|_| usage_document())?;
    let control_url = if control_url.is_empty() {
        "https://controlplane.tailscale.com"
    } else {
        control_url
    };
    let hostname = serde_json::to_string(hostname).map_err(|_| usage_document())?;
    let control_url = serde_json::to_string(control_url).map_err(|_| usage_document())?;
    let addition = format!(
        r#"tailscale "vm" {{
  hostname = {hostname}
  tags = {tags}
  control_url = {control_url}
}}
endpoint "ip" "silo-tailnet-v4" {{
  protocol = "tcp"
  destination_cidrs = ["100.64.0.0/10"]
}}
endpoint "ip" "silo-tailnet-v6" {{
  protocol = "tcp"
  destination_cidrs = ["fd7a:115c:a1e0::/48"]
}}
rule "silo-tailnet-v4" {{
  endpoints = [ip.silo-tailnet-v4]
  tunnel = tailscale.vm
  priority = -2147483648
  verdict = "allow"
}}
rule "silo-tailnet-v6" {{
  endpoints = [ip.silo-tailnet-v6]
  tunnel = tailscale.vm
  priority = -2147483648
  verdict = "allow"
}}
"#
    );
    let addition = normalize(policy_request(w::normalize_policy_request::Input::Hcl(
        addition,
    )))
    .await?;
    let merged = merge_tailnet(&policy.canonical_json, &addition.canonical_json)?;
    normalize(policy_request(
        w::normalize_policy_request::Input::CanonicalJson(merged),
    ))
    .await
}

fn object_array(root: &mut Map<String, Value>, key: &str) -> Outcome<Vec<Map<String, Value>>> {
    let Some(Value::Array(values)) = root.remove(key) else {
        return Err(usage_document());
    };
    values
        .into_iter()
        .map(|value| match value {
            Value::Object(value) => Ok(value),
            _ => Err(usage_document()),
        })
        .collect()
}

fn merge_tailnet(original: &str, addition: &str) -> Outcome<String> {
    let mut root: Map<String, Value> =
        serde_json::from_str(original).map_err(|_| usage_document())?;
    let mut additions: Map<String, Value> =
        serde_json::from_str(addition).map_err(|_| usage_document())?;
    let mut endpoints = object_array(&mut root, "endpoints")?;
    let mut rules = object_array(&mut root, "rules")?;
    let mut names = BTreeSet::new();
    let mut ip = BTreeSet::new();
    for endpoint in &endpoints {
        if let Some(name) = endpoint.get("name").and_then(Value::as_str) {
            names.insert(name.to_owned());
            if endpoint.get("family").and_then(Value::as_str) == Some("ip") {
                ip.insert(name.to_owned());
            }
        }
    }
    for rule in &mut rules {
        if let Some(name) = rule.get("name").and_then(Value::as_str) {
            names.insert(name.to_owned());
        }
        let first = rule
            .get("endpoints")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str);
        if rule.get("verdict").and_then(Value::as_str) == Some("allow")
            && first.is_some_and(|name| ip.contains(name))
        {
            rule.insert("tunnel".to_owned(), Value::String("vm".to_owned()));
        }
    }
    for name in ["silo-tailnet-v4", "silo-tailnet-v6"] {
        if names.contains(name) {
            return Err(Failure::new(
                Code::Usage,
                format!("policy uses reserved injection name {name}"),
            ));
        }
    }
    if root.contains_key("forwards") {
        let mut forwards = object_array(&mut root, "forwards")?;
        for forward in &mut forwards {
            forward.insert("tunnel".to_owned(), Value::String("vm".to_owned()));
        }
        root.insert(
            "forwards".to_owned(),
            Value::Array(forwards.into_iter().map(Value::Object).collect()),
        );
    }
    endpoints.extend(object_array(&mut additions, "endpoints")?);
    rules.extend(object_array(&mut additions, "rules")?);
    root.insert(
        "endpoints".to_owned(),
        Value::Array(endpoints.into_iter().map(Value::Object).collect()),
    );
    root.insert(
        "rules".to_owned(),
        Value::Array(rules.into_iter().map(Value::Object).collect()),
    );
    root.insert(
        "tailscale".to_owned(),
        additions.remove("tailscale").ok_or_else(usage_document)?,
    );
    serde_json::to_string(&root).map_err(|_| usage_document())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecretKind {
    Plain,
    Oauth,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecretField {
    Value,
    OauthAccessToken,
    OauthExpiresAt,
    OauthAccountId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SecretSource {
    pub(crate) key: String,
    pub(crate) field: SecretField,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SecretSlot {
    pub(crate) name: String,
    pub(crate) required: bool,
    pub(crate) kind: SecretKind,
    pub(crate) source: SecretSource,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SecretRequirement {
    pub(crate) owner: String,
    pub(crate) alternatives: Vec<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SecretMetadata {
    pub(crate) slots: Vec<SecretSlot>,
    pub(crate) requirements: Vec<SecretRequirement>,
}

impl SecretMetadata {
    pub(crate) fn from_policy(policy: &w::PolicyDocument) -> Outcome<Self> {
        let slots = policy
            .secret_slots
            .iter()
            .map(|slot| {
                Ok(SecretSlot {
                    name: slot.name.clone(),
                    required: slot.required,
                    kind: match slot.kind {
                        1 => SecretKind::Plain,
                        2 => SecretKind::Oauth,
                        _ => {
                            return Err(Failure::new(
                                Code::Unavailable,
                                "invalid policy secret kind",
                            ))
                        }
                    },
                    source: SecretSource {
                        key: slot.key.clone(),
                        field: match slot.field {
                            1 => SecretField::Value,
                            2 => SecretField::OauthAccessToken,
                            3 => SecretField::OauthExpiresAt,
                            4 => SecretField::OauthAccountId,
                            _ => {
                                return Err(Failure::new(
                                    Code::Unavailable,
                                    "invalid policy secret field",
                                ))
                            }
                        },
                    },
                })
            })
            .collect::<Outcome<Vec<_>>>()?;
        let requirements = policy
            .secret_requirements
            .iter()
            .map(|requirement| SecretRequirement {
                owner: requirement.owner.clone(),
                alternatives: requirement
                    .alternatives
                    .iter()
                    .map(|alternative| alternative.slots.clone())
                    .collect(),
            })
            .collect();
        Ok(Self {
            slots,
            requirements,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Document {
    pub(crate) name: String,
    #[serde(serialize_with = "serialize_tier")]
    pub(crate) tier: Option<DocumentTier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) owner: Option<Principal>,
    pub(crate) kind: DocumentKind,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) template: Option<Template>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) secrets: Option<SecretMetadata>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) bound_vms: Vec<BoundVM>,
}
impl Document {
    pub(crate) fn new(kind: DocumentKind) -> Self {
        Self {
            name: String::new(),
            tier: None,
            owner: None,
            kind,
            content: String::new(),
            template: None,
            secrets: None,
            bound_vms: Vec::new(),
        }
    }
}
fn serialize_tier<S: serde::Serializer>(
    tier: &Option<DocumentTier>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match tier {
        Some(tier) => tier.serialize(serializer),
        None => serializer.serialize_str(""),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BoundVmState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct BoundVM {
    pub(crate) name: String,
    pub(crate) state: BoundVmState,
}

pub(crate) async fn validate_document<N, F>(
    kind: DocumentKind,
    raw: &str,
    normalize: &mut N,
) -> Outcome<Document>
where
    N: FnMut(w::NormalizePolicyRequest) -> F,
    F: Future<Output = Outcome<w::PolicyDocument>>,
{
    let mut document = Document::new(kind);
    match kind {
        DocumentKind::Template => {
            let template = parse_template(raw)?;
            document.content = serde_yaml_ng::to_string(&template).map_err(|_| usage_document())?;
            document.template = Some(template);
        }
        DocumentKind::Policy => {
            let policy = parse_remote_policy(raw, normalize).await?;
            document.secrets = Some(SecretMetadata::from_policy(&policy)?);
            document.content = policy.hcl;
        }
    }
    if document.content.len() > DOCUMENT_LIMIT {
        return Err(Failure::new(
            Code::Usage,
            "canonical document exceeds 64KiB",
        ));
    }
    Ok(document)
}

pub(crate) fn selected_owner(peer: &Peer, owner: Option<&Principal>) -> Outcome<Principal> {
    match owner {
        None => match peer.principals.as_slice() {
            [principal] => Ok(principal.clone()),
            _ => Err(Failure::new(
                Code::Usage,
                "multi-tag peers require --owner tag:<name>",
            )),
        },
        Some(owner) if owner.is_tag() && peer.owns(owner) => Ok(owner.clone()),
        Some(_) => Err(Failure::new(
            Code::Forbidden,
            "owner must be a verified peer tag",
        )),
    }
}

pub(crate) async fn check_secrets<C, F>(policy: &w::PolicyDocument, check: C) -> Outcome<()>
where
    C: FnOnce(w::CheckPolicySecretsRequest) -> F,
    F: Future<Output = Outcome<w::PolicySecretsResult>>,
{
    let result = check(w::CheckPolicySecretsRequest {
        policy_json: policy.canonical_json.clone(),
        machine_id: None,
        secret_scope: w::SecretScopePolicy::MachineOnly as i32,
    })
    .await?;
    validate_secret_result(&result)
}

pub(crate) fn validate_secret_result(result: &w::PolicySecretsResult) -> Outcome<()> {
    match result.state {
        1 => Ok(()),
        2 => {
            let mut message = result
                .requirements
                .iter()
                .map(|requirement| {
                    format!(
                        "{}: {}",
                        requirement.owner,
                        requirement
                            .alternatives
                            .iter()
                            .map(|alternative| alternative.slots.join(" + "))
                            .collect::<Vec<_>>()
                            .join(" or ")
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            if !result.requirements.is_empty() && !result.slots.is_empty() {
                message.push_str("; slots: ");
            }
            message.push_str(
                &result
                    .slots
                    .iter()
                    .map(|slot| format!("{} (key {})", slot.name, slot.key))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            Err(Failure::new(
                Code::Usage,
                format!("missing policy secrets; satisfy an alternative: {message}"),
            ))
        }
        3 => {
            let message = result
                .diagnostics
                .iter()
                .map(|diagnostic| {
                    format!(
                        "slot {}, key {} ({})",
                        diagnostic.slot,
                        diagnostic.key.as_deref().unwrap_or_default(),
                        diagnostic.code
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            Err(Failure::new(
                Code::Unavailable,
                format!("policy secret unavailable: {message}"),
            ))
        }
        _ => Err(Failure::new(
            Code::Unavailable,
            "secret resolver returned an unknown status",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::future::{ready, Ready};

    use serde_json::{json, Value};
    use silod_spec::daemon::v1 as w;

    use crate::lobby::failure::{Code, Failure, Outcome};
    use crate::lobby::identity::{Peer, Principal};
    use crate::lobby::service::documents::{
        inject_tailnet, parse_remote_policy, parse_template, selected_owner, valid_document_name,
        valid_userdata, validate_document, validate_labels, validate_remote_policy,
        validate_secret_result, Document, DocumentKind, SecretMetadata, DOCUMENT_LIMIT,
    };

    fn normalize(request: w::NormalizePolicyRequest) -> Ready<Outcome<w::PolicyDocument>> {
        ready(
            silo_vm_control::policy::normalize_policy(request)
                .map_err(|_| Failure::new(Code::Usage, "invalid policy")),
        )
    }

    fn canonical(hcl: &str) -> w::PolicyDocument {
        silo_vm_control::policy::normalize_policy(w::NormalizePolicyRequest {
            input: Some(w::normalize_policy_request::Input::Hcl(hcl.to_owned())),
        })
        .unwrap()
    }

    #[test]
    fn remote_template_strict_allowlist() {
        let good = "version: '1'\ndescription: Daily driver\nimage: ghcr.io/vandycknick/silo/devbox:latest\nresources: {cpus: 4}\nvsock: true\nuserdata: |\n  #!/bin/sh\n  id\nnetwork: {kind: private, policy_ref: dev-egress, publish: [1, 22, 65535]}\nlabels: {team: runtime}\n";
        let template = parse_template(good).unwrap();
        assert_eq!(template.resources.unwrap().cpus, Some(4));
        assert_eq!(template.network.unwrap().publish, [1, 22, 65535]);
        for field in [
            "mounts",
            "disks",
            "kernel",
            "initramfs",
            "guest_agent",
            "forwards",
            "mount",
            "disk",
            "user",
            "unknown",
        ] {
            assert!(
                parse_template(&format!("version: '1'\n{field}: []\n")).is_err(),
                "{field}"
            );
        }
        for raw in [
            "version: '1'\nuserdata: ''",
            "version: 1",
            "version: '2'",
            "version: null",
            "version: ['1']",
            "[]",
            "version: '1'\n---\n",
            "version: '1'\nversion: '1'",
            "version: '1'\nresources: {cpus: null}",
            "version: '1'\nresources: {cpus: '4'}",
            "version: '1'\nresources: {cpus: 0}",
            "version: '1'\nresources: {cpus: 256}",
            "version: '1'\nnetwork: {kind: none}",
            "version: '1'\nnetwork: {kind: named, target: private}",
            "version: '1'\nnetwork: {kind: private, target: /etc/passwd}",
            "version: '1'\nnetwork: {kind: private, policy_ref: ../x}",
            "version: '1'\nnetwork: {kind: private, publish: [0]}",
            "version: '1'\nnetwork: {kind: private, publish: [65536]}",
            "version: '1'\nnetwork: {kind: private, publish: [22,22]}",
            "version: '1'\nnetwork: {kind: private, publish: {bind: any}}",
            "version: '1'\nnetwork: {kind: private, publish: ['127.0.0.1:8080:80']}",
            "version: '1'\nvsock: false",
            "version: '1'\nuserdata: /etc/passwd",
            "version: '1'\nuserdata: {file: /etc/passwd}",
            "version: '1'\nlabels: {io.silo.lobby.owner: forged}",
            "version: '1'\nlabels: {n: 7}",
            "version: '1'\nlabels: {n: one, n: two}",
            "version: &v '1'\ndescription: *v",
            "version: '1'\n<<: {image: bad}",
            "",
            "version: '1'\nresources: null",
            "version: '1'\nnetwork: null",
            "version: '1'\nlabels: null",
            "version: '1'\nlabels: {x: null}",
            "version: '1'\nresources: {cpus: -1}",
            "version: '1'\nvsock: 'true'",
            "version: '1'\nnetwork: {kind: private, publish: [1.0]}",
            "version: '1'\nnetwork: {kind: private, publish: [true]}",
            "version: &v '1'\nnetwork: {kind: private, policy_ref: *v}",
            "version: &v '1'\nlabels: {'quoted':*v}",
            "version: '1'\nlabels: &l {x: value}\nresources: *l",
            "version: '1'\nlabels: {<<: {x: value}}",
            "version: '1'\nlabels: {<<: literal}",
            "version: !<unterminated",
        ] {
            assert!(parse_template(raw).is_err(), "accepted {raw:?}");
        }
        assert!(parse_template(&"x".repeat(DOCUMENT_LIMIT + 1)).is_err());
        let ports = (1..=257)
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_template(&format!(
            "version: '1'\nnetwork: {{kind: private, publish: [{ports}]}}"
        ))
        .is_err());
    }

    #[test]
    fn template_resources_use_native_cli_units() {
        for raw in [
            "version: '1'\nresources: {memory: 8GiB}\ndisk_size: 20GiB",
            "version: '1'\nresources: {memory: 8gb}\ndisk_size: 20g",
            "version: '1'\nresources: {memory: 8GB}\ndisk_size: 20GiB",
        ] {
            assert!(parse_template(raw).is_ok(), "{raw}");
        }
        for raw in [
            "version: '1'\nresources: {memory: 1.5GiB}",
            "version: '1'\ndisk_size: 18446744073709551615GiB",
            "version: '1'\ndisk_size: 0GiB",
        ] {
            assert!(parse_template(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn alias_like_scalar_content_is_not_an_alias() {
        for raw in [
            "version: &v '1'\ndescription: '*v'",
            "version: '1'\ndescription: \"*v\"",
            "version: '1'\ndescription: hello *v",
            "version: '1'\ndescription: hello\n  *v",
            "version: '1'\nuserdata: |\n  #!/bin/sh\n  *v\n",
            "version: '1'\nuserdata: >\n  #!/bin/sh\n  *v\n",
            "version: '1'\nlabels: {text: '*v'} # *ignored",
            "version: '1'\nlabels: {'<<': literal}",
            "version: '1'\nlabels: {!!str <<: literal}",
            "version: '1'\nlabels: {text: x:*v}",
        ] {
            assert!(parse_template(raw).is_ok(), "{raw:?}");
        }
    }

    #[test]
    fn userdata_labels_names_and_bounds() {
        for name in ["a", "0", "a-b", "a-"] {
            assert!(valid_document_name(name));
        }
        assert!(valid_document_name(&"a".repeat(63)));
        for name in ["", "-a", "A", "../x", "a/b", "a.b", "é"] {
            assert!(!valid_document_name(name), "{name}");
        }
        assert!(!valid_document_name(&"a".repeat(64)));
        assert!(valid_userdata(""));
        assert!(valid_userdata("#!/bin/sh\nid"));
        assert!(valid_userdata(&format!("#!{}", "x".repeat(16382))));
        for script in ["/etc/passwd", "#!\0"] {
            assert!(!valid_userdata(script));
        }
        assert!(!valid_userdata(&format!("#!{}", "x".repeat(16383))));
        for (key, value) in [
            ("", "v"),
            ("io.silo.owner", "v"),
            ("io.silo.lobby.owner", "v"),
            ("control\n", "v"),
            ("key", "control\u{85}"),
        ] {
            assert!(
                validate_labels(&BTreeMap::from([(key.to_owned(), value.to_owned())])).is_err()
            );
        }
        let mut labels = BTreeMap::from([("k".repeat(128), "v".repeat(1024))]);
        assert!(validate_labels(&labels).is_ok());
        labels.insert("x".repeat(129), "v".to_owned());
        assert!(validate_labels(&labels).is_err());
        let labels = (0..33)
            .map(|number| (format!("key{number}"), "v".to_owned()))
            .collect();
        assert!(validate_labels(&labels).is_err());
        assert!(parse_template(&format!(
            "version: '1'\ndescription: '{}'",
            "x".repeat(4096)
        ))
        .is_ok());
        assert!(parse_template(&format!(
            "version: '1'\ndescription: '{}'",
            "x".repeat(4097)
        ))
        .is_err());
    }

    #[test]
    fn remote_policy_rejects_normalized_authority() {
        for raw in [
            r#"tailscale "vm" {}"#,
            r#"tailscale "other" { tags = ["tag:a"] }"#,
            "forward \"host\" \"host\" {\n target = \"name:other-vm\"\n target_port = 80\n}",
            "tailscale \"vm\" {}\nforward \"tailscale\" \"tail\" {\n tunnel = tailscale.vm\n target = \"name:peer\"\n target_port = 80\n}",
            "tailscale \"vm\" {}\nforward \"tailscale\" \"tail\" {\n tunnel = tailscale.vm\n listen = \":8080\"\n target = \"self\"\n target_port = 80\n}",
            "tailscale \"vm\" {}\nendpoint \"ip\" \"all\" {\n protocol = \"tcp\"\n destination_cidrs = [\"0.0.0.0/0\"]\n}\nrule \"via\" {\n endpoints = [ip.all]\n tunnel = tailscale.vm\n verdict = \"allow\"\n}",
        ] {
            let policy = canonical(raw);
            assert_eq!(validate_remote_policy(&policy).unwrap_err().code, Code::Usage, "{raw}");
        }
        let mut root: Value = serde_json::from_str(&canonical("").canonical_json).unwrap();
        root["metadata"] = json!({"io.silo.lobby.node": "{\"owner\":\"user:1\"}"});
        let policy = silo_vm_control::policy::normalize_policy(w::NormalizePolicyRequest {
            input: Some(w::normalize_policy_request::Input::CanonicalJson(
                root.to_string(),
            )),
        })
        .unwrap();
        assert!(validate_remote_policy(&policy).is_err());
        assert!(validate_remote_policy(&w::PolicyDocument {
            canonical_json: "{".into(),
            ..Default::default()
        })
        .is_err());
    }

    #[tokio::test]
    async fn canonical_injection_preserves_plugin_fields_and_denies() {
        let raw = r#"settings { default_action = "deny" }
endpoint "ip" "all" {
 protocol = "tcp"
 destination_cidrs = ["0.0.0.0/0", "::/0"]
}
endpoint "https" "plugin" {
 hosts = ["api.example.test"]
}
credential "openai_codex_oauth" "plugin-auth" {
 endpoint = https.plugin
}
rule "deny" {
 endpoints = [ip.all]
 priority = -2147483648
 verdict = "deny"
}
rule "allow" {
 endpoints = [ip.all]
 priority = 10
 verdict = "allow"
 reason = "keep me"
 disabled = true
}
rule "plugin-rule" {
 endpoints = [https.plugin]
 credential = openai_codex_oauth.plugin-auth
 condition = "http.method == 'POST'"
 verdict = "allow"
}
"#;
        let policy = parse_remote_policy(raw, &mut normalize).await.unwrap();
        let mut before: Value = serde_json::from_str(&policy.canonical_json).unwrap();
        before["metadata"] = json!({"nested":{"numbers":[1,2],"flag":true}});
        let policy = normalize(w::NormalizePolicyRequest {
            input: Some(w::normalize_policy_request::Input::CanonicalJson(
                before.to_string(),
            )),
        })
        .await
        .unwrap();
        let injected = inject_tailnet(
            Some(&policy),
            "exact-name",
            &Principal::parse("user:1").unwrap(),
            "",
            &[],
            &mut normalize,
        )
        .await
        .unwrap();
        let after: Value = serde_json::from_str(&injected.canonical_json).unwrap();
        for key in ["metadata", "settings", "credentials", "forwards"] {
            assert_eq!(before[key], after[key], "{key}");
        }
        let old_endpoints = before["endpoints"].as_array().unwrap();
        let endpoints = after["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), old_endpoints.len() + 2);
        assert_eq!(&endpoints[..old_endpoints.len()], old_endpoints);
        let old_rules = before["rules"].as_array().unwrap();
        let rules = after["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[0], old_rules[0]);
        assert_eq!(rules[2], old_rules[2]);
        let mut expected_allow = old_rules[1].clone();
        expected_allow["tunnel"] = json!("vm");
        assert_eq!(rules[1], expected_allow);
        for rule in &rules[3..] {
            assert_eq!(rule["priority"], i32::MIN);
        }
        assert!(injected.hcl.contains("100.64.0.0/10"));
        assert!(injected.hcl.contains("fd7a:115c:a1e0::/48"));
        assert!(injected.hcl.contains("hostname = \"exact-name\""));
        assert_eq!(canonical(&injected.hcl).hcl, injected.hcl);
        assert!(validate_remote_policy(&injected).is_err());
        for name in ["silo-tailnet-v4", "silo-tailnet-v6"] {
            let collision = canonical(&format!("endpoint \"ip\" \"{name}\" {{\n protocol = \"tcp\"\n destination_cidrs = [\"0.0.0.0/0\"]\n}}"));
            assert!(inject_tailnet(
                Some(&collision),
                "vm",
                &Principal::parse("user:1").unwrap(),
                "",
                &[],
                &mut normalize
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn injection_carries_verified_owner_pinned_control_and_requested_tags() {
        for (owner, requested, expected) in [
            ("tag:owner", Vec::new(), vec!["tag:owner"]),
            ("user:7", Vec::new(), Vec::new()),
            (
                "tag:owner",
                vec!["tag:requested".to_owned()],
                vec!["tag:requested"],
            ),
        ] {
            let policy = inject_tailnet(
                None,
                "exact",
                &Principal::parse(owner).unwrap(),
                "https://pinned-control.example.test",
                &requested,
                &mut normalize,
            )
            .await
            .unwrap();
            let root: Value = serde_json::from_str(&policy.canonical_json).unwrap();
            let nodes = root["tailscale"].as_array().unwrap();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0]["hostname"], "exact");
            assert_eq!(nodes[0]["tags"], json!(expected));
            assert_eq!(
                nodes[0]["control_url"],
                "https://pinned-control.example.test"
            );
            assert!(validate_remote_policy(&policy).is_err());
        }
    }

    #[tokio::test]
    async fn injection_preserves_same_vm_forward_protocol_tls_and_target() {
        let policy = canonical(
            r#"forward "tailscale" "web" {
  listen = ":443"
  target = "self"
  target_port = 8080
  protocol = "https"
  tls { provider = "tailscale" }
}
forward "tailscale" "raw" {
  listen = ":18080"
  target = "self"
  target_port = 8080
}
"#,
        );
        validate_remote_policy(&policy).unwrap();
        let before: Value = serde_json::from_str(&policy.canonical_json).unwrap();
        let injected = inject_tailnet(
            Some(&policy),
            "web",
            &Principal::parse("user:1").unwrap(),
            "",
            &[],
            &mut normalize,
        )
        .await
        .unwrap();
        let after: Value = serde_json::from_str(&injected.canonical_json).unwrap();
        let mut expected = before["forwards"].clone();
        for forward in expected.as_array_mut().unwrap() {
            forward["tunnel"] = json!("vm");
        }
        assert_eq!(expected, after["forwards"]);
    }

    #[tokio::test]
    async fn policy_secret_alternatives_and_public_projection() {
        let policy = canonical("endpoint \"https\" \"aws\" {\n hosts = [\"sts.amazonaws.com\"]\n}\ncredential \"aws_credential\" \"prod\" {\n endpoint = https.aws\n}");
        let metadata = SecretMetadata::from_policy(&policy).unwrap();
        assert_eq!(metadata.requirements.len(), 1);
        let alternatives = &metadata.requirements[0].alternatives;
        assert!(alternatives.contains(&vec!["prod.profile".to_owned()]));
        assert!(alternatives.contains(&vec![
            "prod.access_key_id".to_owned(),
            "prod.secret_access_key".to_owned()
        ]));
        let missing = w::PolicySecretsResult {
            state: 2,
            requirements: policy.secret_requirements.clone(),
            slots: policy.secret_slots.clone(),
            diagnostics: Vec::new(),
        };
        let error = validate_secret_result(&missing).unwrap_err();
        assert_eq!(error.code, Code::Usage);
        for part in [
            "prod.profile",
            "prod.access_key_id + prod.secret_access_key",
            " or ",
        ] {
            assert!(error.message.contains(part));
        }
        let document = validate_document(DocumentKind::Policy, &policy.hcl, &mut normalize)
            .await
            .unwrap();
        assert_eq!(
            document.secrets.unwrap().requirements,
            metadata.requirements
        );
        let unavailable = w::PolicySecretsResult {
            state: 3,
            diagnostics: vec![w::SecretDiagnostic {
                slot: "prod.profile".into(),
                key: Some("aws.profile".into()),
                code: "corrupt".into(),
            }],
            ..Default::default()
        };
        let error = validate_secret_result(&unavailable).unwrap_err();
        assert_eq!(error.code, Code::Unavailable);
        assert_eq!(
            error.message,
            "policy secret unavailable: slot prod.profile, key aws.profile (corrupt)"
        );
        assert!(validate_secret_result(&w::PolicySecretsResult {
            state: 1,
            ..Default::default()
        })
        .is_ok());
        assert!(validate_secret_result(&w::PolicySecretsResult::default()).is_err());
    }

    #[test]
    fn selected_owner_requires_verified_tag_or_single_principal() {
        let user = Principal::parse("user:7").unwrap();
        let tag = Principal::parse("tag:one").unwrap();
        let other = Principal::parse("tag:two").unwrap();
        let mut peer = Peer {
            principals: vec![user.clone()],
            ..Default::default()
        };
        assert_eq!(selected_owner(&peer, None).unwrap(), user);
        assert_eq!(
            selected_owner(&peer, Some(&user)).unwrap_err().code,
            Code::Forbidden
        );
        peer.principals = vec![tag.clone(), other.clone()];
        assert_eq!(selected_owner(&peer, None).unwrap_err().code, Code::Usage);
        assert_eq!(selected_owner(&peer, Some(&tag)).unwrap(), tag);
        assert_eq!(selected_owner(&peer, Some(&other)).unwrap(), other);
        assert_eq!(
            selected_owner(&peer, Some(&Principal::parse("tag:foreign").unwrap()))
                .unwrap_err()
                .code,
            Code::Forbidden
        );
        peer.principals.clear();
        assert!(selected_owner(&peer, None).is_err());
        let identity = serde_json::to_value(Document::new(DocumentKind::Template)).unwrap();
        assert_eq!(identity["tier"], "");
        assert!(identity.get("owner").is_none());
    }
}
