use crate::model::{
    Action, AuditSettingsDecl, CredentialDecl, Diagnostic, DiagnosticSeverity, EndpointDecl,
    EndpointFamily, ForwardDecl, LoadError, Policy, PolicyDocument, PortRange, Ref, RuleDecl,
    SettingsDecl, SourceFile, TailscaleDecl, Transport,
};
use hcl::{Block, Body, Expression, Structure};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

pub fn parse_policy(filename: String, source: &str) -> Result<Policy, LoadError> {
    let mut policy = Policy {
        policy_hash: policy_hash(source.as_bytes()),
        documents: Vec::new(),
        diagnostics: Vec::new(),
        conditions: Vec::new(),
    };
    let mut document = parse_document(&filename, source, &mut policy)?;
    policy
        .diagnostics
        .extend(document.diagnostics.iter().cloned());
    if has_errors(&policy.diagnostics) {
        return Err(LoadError {
            filename,
            diagnostics: policy.diagnostics,
        });
    }
    document.id = 1;
    policy.documents.push(document);
    Ok(policy)
}

fn policy_hash(source: &[u8]) -> String {
    let digest = Sha256::digest(source);
    let mut hash = String::with_capacity("sha256:".len() + digest.len() * 2);
    hash.push_str("sha256:");
    for byte in digest {
        let _ = write!(&mut hash, "{byte:02x}");
    }
    hash
}

fn parse_document(
    filename: &str,
    source: &str,
    policy: &mut Policy,
) -> Result<PolicyDocument, LoadError> {
    let body = match hcl::parse(source) {
        Ok(body) => body,
        Err(err) => {
            let diagnostic = Diagnostic::error(filename, 1, 1, "Parse error", err.to_string());
            return Err(LoadError {
                filename: filename.to_owned(),
                diagnostics: vec![diagnostic],
            });
        }
    };

    let mut builder = DocumentBuilder::new(filename, source, policy);
    builder.read_body(&body);
    builder.validate_references();
    Ok(builder.finish())
}

fn has_errors(diagnostics: &[Diagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
}

struct DocumentBuilder<'a> {
    filename: &'a str,
    locator: SourceLocator<'a>,
    policy: &'a mut Policy,
    diagnostics: Vec<Diagnostic>,
    settings: SettingsDecl,
    settings_seen: bool,
    endpoints: Vec<EndpointDecl>,
    credentials: Vec<CredentialDecl>,
    rules: Vec<RuleDecl>,
    tailscale: Vec<TailscaleDecl>,
    forwards: Vec<ForwardDecl>,
    endpoint_keys: HashSet<String>,
    credential_keys: HashSet<String>,
    rule_names: HashSet<String>,
    tailscale_names: HashSet<String>,
    forward_keys: HashSet<String>,
}

impl<'a> DocumentBuilder<'a> {
    fn new(filename: &'a str, source: &'a str, policy: &'a mut Policy) -> Self {
        Self {
            filename,
            locator: SourceLocator::new(source),
            policy,
            diagnostics: Vec::new(),
            settings: SettingsDecl::default(),
            settings_seen: false,
            endpoints: Vec::new(),
            credentials: Vec::new(),
            rules: Vec::new(),
            tailscale: Vec::new(),
            forwards: Vec::new(),
            endpoint_keys: HashSet::new(),
            credential_keys: HashSet::new(),
            rule_names: HashSet::new(),
            tailscale_names: HashSet::new(),
            forward_keys: HashSet::new(),
        }
    }

    fn read_body(&mut self, body: &Body) {
        for structure in body.iter() {
            match structure {
                Structure::Attribute(attribute) => {
                    let position = self.locator.find_attr_after(attribute.key(), 1);
                    self.error_at(
                        position,
                        "Unsupported argument",
                        format!(
                            "An argument named \"{}\" is not expected here.",
                            attribute.key()
                        ),
                    );
                }
                Structure::Block(block) => self.read_top_level_block(block),
            }
        }
    }

    fn read_top_level_block(&mut self, block: &Block) {
        let labels = block_labels(block);
        let block_position = self.locator.find_block(block.identifier(), &labels);
        match block.identifier() {
            "settings" => {
                if !labels.is_empty() {
                    self.error_at(
                        block_position,
                        "Invalid settings block",
                        "settings does not accept labels",
                    );
                    return;
                }
                if self.settings_seen {
                    self.error_at(
                        block_position,
                        "Duplicate settings block",
                        "Only one settings block is allowed.",
                    );
                    return;
                }
                self.settings_seen = true;
                self.read_settings(block, block_position.line);
            }
            "endpoint" => self.read_endpoint(block, labels, block_position),
            "credential" => self.read_credential(block, labels, block_position),
            "rule" => self.read_rule(block, labels, block_position),
            "tailscale" => self.read_tailscale(block, labels, block_position),
            "forward" => self.read_forward(block, labels, block_position),
            other => self.error_at(
                block_position,
                "Unsupported block",
                format!("Blocks of type \"{other}\" are not expected here."),
            ),
        }
    }

    fn read_settings(&mut self, block: &Block, block_line: usize) {
        let mut audit_seen = false;
        for structure in block.body().iter() {
            match structure {
                Structure::Attribute(attribute) => match attribute.key() {
                    "default_action" => match decode_string(attribute.expr()) {
                        Ok(value) => match parse_terminal_action(&value) {
                            Ok(action) => self.settings.default_action = action,
                            Err(detail) => self.attr_error(
                                attribute,
                                block_line,
                                "Invalid settings.default_action",
                                detail,
                            ),
                        },
                        Err(detail) => self.attr_error(
                            attribute,
                            block_line,
                            "Invalid settings.default_action",
                            detail,
                        ),
                    },
                    key => self.attr_error(
                        attribute,
                        block_line,
                        "Unsupported argument",
                        format!("An argument named \"{key}\" is not expected here."),
                    ),
                },
                Structure::Block(child) => match child.identifier() {
                    "audit" => {
                        let position = self.locator.find_block_after("audit", &[], block_line);
                        if audit_seen {
                            self.error_at(
                                position,
                                "Duplicate settings.audit block",
                                "Only one settings.audit block is allowed.",
                            );
                            continue;
                        }
                        audit_seen = true;
                        self.read_audit_settings(child, position.line);
                    }
                    other => {
                        let position =
                            self.locator
                                .find_block_after(other, &block_labels(child), block_line);
                        self.error_at(
                            position,
                            "Unsupported block",
                            format!("Blocks of type \"{other}\" are not expected here."),
                        );
                    }
                },
            }
        }
    }

    fn read_audit_settings(&mut self, block: &Block, block_line: usize) {
        let mut body_buffer = 1024 * 1024;
        let mut body_storage = 4 * 1024;
        for structure in block.body().iter() {
            match structure {
                Structure::Attribute(attribute) => match attribute.key() {
                    "body_buffer" | "body_buffer_bytes" => match decode_size(attribute.expr()) {
                        Ok(value) => body_buffer = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_line,
                            format!("Invalid settings.audit.{}", attribute.key()),
                            detail,
                        ),
                    },
                    "body_storage" | "body_storage_bytes" => match decode_size(attribute.expr()) {
                        Ok(value) => body_storage = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_line,
                            format!("Invalid settings.audit.{}", attribute.key()),
                            detail,
                        ),
                    },
                    key => self.attr_error(
                        attribute,
                        block_line,
                        "Unsupported argument",
                        format!("An argument named \"{key}\" is not expected here."),
                    ),
                },
                Structure::Block(child) => {
                    let position = self.locator.find_block_after(
                        child.identifier(),
                        &block_labels(child),
                        block_line,
                    );
                    self.error_at(
                        position,
                        "Unsupported block",
                        format!(
                            "Blocks of type \"{}\" are not expected here.",
                            child.identifier()
                        ),
                    );
                }
            }
        }
        if body_buffer < body_storage {
            self.warning_at(
                Position {
                    line: block_line,
                    column: 1,
                },
                "Policy warning",
                "settings.audit.body_buffer is smaller than settings.audit.body_storage",
            );
        }
        self.settings.audit = Some(AuditSettingsDecl {
            body_buffer,
            body_storage,
        });
    }

    fn read_endpoint(&mut self, block: &Block, labels: Vec<String>, block_position: Position) {
        if labels.len() != 2 {
            self.error_at(
                block_position,
                "Invalid endpoint block",
                "endpoint requires kind and name labels",
            );
            return;
        }
        let kind = labels[0].clone();
        let name = labels[1].clone();
        let key = format!("{kind}.{name}");
        if !valid_identifier(&name) {
            let position = self
                .locator
                .find_label(block_position.line, &name)
                .unwrap_or(block_position);
            self.error_at(
                position,
                "Invalid endpoint name",
                format!("endpoint \"{kind}\".\"{name}\" name must use a traversal identifier"),
            );
            return;
        }
        let family;
        let transport;
        let default_port;
        match kind.as_str() {
            "ip" => {
                family = EndpointFamily::Ip;
                transport = Transport::PacketFilter;
                default_port = 0;
            }
            "http" => {
                family = EndpointFamily::Http;
                transport = Transport::HttpProxy;
                default_port = 80;
            }
            "https" => {
                family = EndpointFamily::Http;
                transport = Transport::HttpsMitm;
                default_port = 443;
            }
            _ => {
                let position = self
                    .locator
                    .find_label(block_position.line, &kind)
                    .unwrap_or(block_position);
                self.error_at(
                    position,
                    "Unsupported endpoint kind",
                    format!("unsupported endpoint kind \"{kind}\""),
                );
                return;
            }
        }
        if !self.endpoint_keys.insert(key.clone()) {
            self.error_at(
                block_position,
                "Duplicate endpoint",
                format!("Endpoint \"{key}\" is already defined."),
            );
            return;
        }

        let mut source = Vec::new();
        let mut destination = Vec::new();
        let mut protocol = if kind == "ip" {
            "any".to_owned()
        } else {
            String::new()
        };
        let mut ports = Vec::new();
        let mut hosts = Vec::new();
        let mut hosts_seen = false;
        for structure in block.body().iter() {
            match structure {
                Structure::Attribute(attribute) => match (kind.as_str(), attribute.key()) {
                    ("ip", "source" | "source_cidrs") => match decode_string_list(attribute.expr())
                    {
                        Ok(value) => source = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid endpoint source",
                            detail,
                        ),
                    },
                    ("ip", "destination" | "destination_cidrs") => {
                        match decode_string_list(attribute.expr()) {
                            Ok(value) => destination = value,
                            Err(detail) => self.attr_error(
                                attribute,
                                block_position.line,
                                "Invalid endpoint destination",
                                detail,
                            ),
                        }
                    }
                    ("ip", "protocol") => match decode_string(attribute.expr()) {
                        Ok(value) => protocol = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid endpoint protocol",
                            detail,
                        ),
                    },
                    ("ip", "ports") => match decode_port_ranges(attribute.expr()) {
                        Ok(value) => ports = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid endpoint ports",
                            detail,
                        ),
                    },
                    ("http" | "https", "hosts") => {
                        hosts_seen = true;
                        match decode_string_list(attribute.expr()) {
                            Ok(value) if value.is_empty() => self.attr_error(
                                attribute,
                                block_position.line,
                                "Invalid hosts",
                                "hosts must not be empty",
                            ),
                            Ok(value) => hosts = value,
                            Err(detail) => self.attr_error(
                                attribute,
                                block_position.line,
                                "Invalid hosts",
                                detail,
                            ),
                        }
                    }
                    (_, key) => self.attr_error(
                        attribute,
                        block_position.line,
                        "Unsupported argument",
                        format!("An argument named \"{key}\" is not expected here."),
                    ),
                },
                Structure::Block(child) => {
                    let position = self.locator.find_block_after(
                        child.identifier(),
                        &block_labels(child),
                        block_position.line,
                    );
                    self.error_at(
                        position,
                        "Unsupported block",
                        format!(
                            "Blocks of type \"{}\" are not expected here.",
                            child.identifier()
                        ),
                    );
                }
            }
        }
        if kind == "ip" && !["any", "tcp", "udp"].contains(&protocol.as_str()) {
            self.error_at(
                block_position,
                "Invalid endpoint protocol",
                format!("protocol must be any, tcp, or udp, got {protocol}"),
            );
        }
        if (kind == "http" || kind == "https") && !hosts_seen {
            self.error_at(block_position, "Missing hosts", "hosts is required");
        }
        self.endpoints.push(EndpointDecl {
            kind,
            name,
            family,
            transport,
            default_port,
            source,
            destination,
            protocol,
            ports,
            hosts,
            order: self.endpoints.len(),
        });
    }

    fn read_credential(&mut self, block: &Block, labels: Vec<String>, block_position: Position) {
        if labels.len() != 2 {
            self.error_at(
                block_position,
                "Invalid credential block",
                "credential requires kind and name labels",
            );
            return;
        }
        let kind = labels[0].clone();
        let name = labels[1].clone();
        if !valid_identifier(&name) {
            let position = self
                .locator
                .find_label(block_position.line, &name)
                .unwrap_or(block_position);
            self.error_at(
                position,
                "Invalid credential name",
                format!("credential \"{kind}\".\"{name}\" name must use a traversal identifier"),
            );
        }
        let key = format!("{kind}.{name}");
        if !self.credential_keys.insert(key.clone()) {
            self.error_at(
                block_position,
                "Invalid credential",
                format!("duplicate credential \"{key}\""),
            );
            return;
        }
        let mut endpoint = None;
        let mut condition_source = None;
        let mut username = String::new();
        let mut header = String::new();
        let mut prefix = String::new();
        let mut idempotency_key = false;
        for structure in block.body().iter() {
            match structure {
                Structure::Attribute(attribute) => match (kind.as_str(), attribute.key()) {
                    (_, "endpoint") => match decode_ref(attribute.expr()) {
                        Ok(value) => endpoint = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential endpoint",
                            detail,
                        ),
                    },
                    (_, "condition") => match decode_string(attribute.expr()) {
                        Ok(value) => condition_source = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential condition",
                            detail,
                        ),
                    },
                    ("basic_auth", "username") => match decode_string(attribute.expr()) {
                        Ok(value) if value.is_empty() => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential username",
                            "username must not be empty",
                        ),
                        Ok(value) => username = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential username",
                            detail,
                        ),
                    },
                    ("bearer_token", "idempotency_key") => match decode_bool(attribute.expr()) {
                        Ok(value) => idempotency_key = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential idempotency_key",
                            detail,
                        ),
                    },
                    ("header_token", "header") => match decode_string(attribute.expr()) {
                        Ok(value) if valid_http_header_name(&value) => header = value,
                        Ok(_) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential header",
                            "header must be a valid HTTP header name",
                        ),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential header",
                            detail,
                        ),
                    },
                    ("header_token", "prefix") => match decode_string(attribute.expr()) {
                        Ok(value) => prefix = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential prefix",
                            detail,
                        ),
                    },
                    (_, key) => self.attr_error(
                        attribute,
                        block_position.line,
                        "Unsupported argument",
                        format!("An argument named \"{key}\" is not expected here."),
                    ),
                },
                Structure::Block(child) => {
                    let position = self.locator.find_block_after(
                        child.identifier(),
                        &block_labels(child),
                        block_position.line,
                    );
                    self.error_at(
                        position,
                        "Unsupported block",
                        format!(
                            "Blocks of type \"{}\" are not expected here.",
                            child.identifier()
                        ),
                    );
                }
            }
        }
        let Some(endpoint) = endpoint else {
            self.error_at(
                block_position,
                "Missing credential endpoint",
                format!("credential \"{kind}\".\"{name}\" requires endpoint"),
            );
            return;
        };
        match kind.as_str() {
            "basic_auth" if username.is_empty() => self.error_at(
                block_position,
                "Invalid credential",
                format!("credential \"{kind}\".\"{name}\" requires username"),
            ),
            "header_token" if header.is_empty() => self.error_at(
                block_position,
                "Invalid credential",
                format!("credential \"{kind}\".\"{name}\" requires header"),
            ),
            _ => {}
        }
        let condition = match condition_source {
            Some(source) if !source.is_empty() => {
                if credential_condition_references_secret(&source) {
                    self.error_at(
                        block_position,
                        "Invalid credential",
                        format!(
                            "credential \"{kind}\".\"{name}\" condition cannot reference credential.* or secret material"
                        ),
                    );
                    None
                } else {
                    match self.policy.register_http_condition(&source) {
                        Ok(condition) => Some(condition),
                        Err(err) => {
                            self.error_at(
                                block_position,
                                "Invalid credential",
                                format!("credential \"{kind}\".\"{name}\" condition: {err}"),
                            );
                            None
                        }
                    }
                }
            }
            _ => None,
        };
        self.credentials.push(CredentialDecl {
            kind,
            name,
            endpoint,
            username,
            header,
            prefix,
            idempotency_key,
            condition,
            order: self.credentials.len(),
        });
    }

    fn read_rule(&mut self, block: &Block, labels: Vec<String>, block_position: Position) {
        if labels.len() != 1 {
            self.error_at(
                block_position,
                "Invalid rule block",
                "rule requires a name label",
            );
            return;
        }
        let name = labels[0].clone();
        if !self.rule_names.insert(name.clone()) {
            self.error_at(
                block_position,
                "Duplicate rule",
                format!("Rule \"{name}\" is already defined."),
            );
            return;
        }
        let mut endpoints = Vec::new();
        let mut saw_endpoint = false;
        let mut saw_endpoints = false;
        let mut credential = None;
        let mut tunnel = None;
        let mut verdict = None;
        let mut priority = 0;
        let mut disabled = false;
        let mut condition_source = None;
        let mut reason = String::new();
        for structure in block.body().iter() {
            match structure {
                Structure::Attribute(attribute) => match attribute.key() {
                    "endpoint" => {
                        saw_endpoint = true;
                        match decode_ref(attribute.expr()) {
                            Ok(value) => endpoints.push(value),
                            Err(detail) => self.attr_error(
                                attribute,
                                block_position.line,
                                "Invalid rule endpoint",
                                detail,
                            ),
                        }
                    }
                    "endpoints" => {
                        saw_endpoints = true;
                        if saw_endpoint {
                            self.attr_error(
                                attribute,
                                block_position.line,
                                "Invalid rule endpoints",
                                format!("rule \"{name}\" uses endpoint and endpoints"),
                            );
                        } else {
                            match decode_ref_list(attribute.expr()) {
                                Ok(value) => endpoints = value,
                                Err(detail) => self.attr_error(
                                    attribute,
                                    block_position.line,
                                    "Invalid rule endpoints",
                                    detail,
                                ),
                            }
                        }
                    }
                    "credential" => match decode_ref(attribute.expr()) {
                        Ok(value) => credential = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid rule credential",
                            detail,
                        ),
                    },
                    "tunnel" => match decode_ref(attribute.expr()) {
                        Ok(value) => tunnel = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid rule tunnel",
                            detail,
                        ),
                    },
                    "condition" => match decode_string(attribute.expr()) {
                        Ok(value) => condition_source = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid rule condition",
                            detail,
                        ),
                    },
                    "verdict" => match decode_string(attribute.expr())
                        .and_then(|value| parse_rule_action(&value))
                    {
                        Ok(value) => verdict = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid rule verdict",
                            detail,
                        ),
                    },
                    "priority" => match decode_int(attribute.expr()) {
                        Ok(value) => priority = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid rule priority",
                            detail,
                        ),
                    },
                    "disabled" => match decode_bool(attribute.expr()) {
                        Ok(value) => disabled = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid rule disabled",
                            detail,
                        ),
                    },
                    "reason" => match decode_string(attribute.expr()) {
                        Ok(value) => reason = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid rule reason",
                            detail,
                        ),
                    },
                    key => self.attr_error(
                        attribute,
                        block_position.line,
                        "Unsupported argument",
                        format!("An argument named \"{key}\" is not expected here."),
                    ),
                },
                Structure::Block(child) => {
                    let position = self.locator.find_block_after(
                        child.identifier(),
                        &block_labels(child),
                        block_position.line,
                    );
                    self.error_at(
                        position,
                        "Unsupported block",
                        format!(
                            "Blocks of type \"{}\" are not expected here.",
                            child.identifier()
                        ),
                    );
                }
            }
        }
        if saw_endpoint && saw_endpoints {
            endpoints.truncate(1);
        }
        if endpoints.is_empty() {
            self.error_at(
                block_position,
                "Missing rule endpoint",
                format!("rule \"{name}\" requires endpoint or endpoints"),
            );
        }
        let Some(verdict) = verdict else {
            self.error_at(
                block_position,
                "Missing rule verdict",
                format!("rule \"{name}\" requires verdict"),
            );
            return;
        };
        let condition = match condition_source {
            Some(source) if !source.is_empty() => {
                match self.policy.register_http_condition(&source) {
                    Ok(condition) => Some(condition),
                    Err(err) => {
                        self.error_at(
                            block_position,
                            "Invalid rule",
                            format!("rule \"{name}\" condition: {err}"),
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        self.rules.push(RuleDecl {
            name,
            endpoints,
            credential,
            tunnel,
            verdict,
            priority,
            disabled,
            condition,
            reason,
            order: self.rules.len(),
        });
    }

    fn read_tailscale(&mut self, block: &Block, labels: Vec<String>, block_position: Position) {
        if labels.len() != 1 {
            self.error_at(
                block_position,
                "Invalid tailscale block",
                "tailscale requires a name label",
            );
            return;
        }
        let name = labels[0].clone();
        if !valid_identifier(&name) {
            let position = self
                .locator
                .find_label(block_position.line, &name)
                .unwrap_or(block_position);
            self.error_at(
                position,
                "Invalid tailscale name",
                format!("tailscale \"{name}\" name must use a traversal identifier"),
            );
            return;
        }
        if !self.tailscale_names.insert(name.clone()) {
            self.error_at(
                block_position,
                "Duplicate tailscale block",
                format!("tailscale \"{name}\" is already defined."),
            );
            return;
        }

        let mut tags = Vec::new();
        let mut hostname = String::new();
        let mut control_url = String::new();
        for structure in block.body().iter() {
            match structure {
                Structure::Attribute(attribute) => match attribute.key() {
                    "tags" => match decode_string_list(attribute.expr()) {
                        Ok(value) => tags = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid tailscale tags",
                            detail,
                        ),
                    },
                    "hostname" => match decode_string(attribute.expr()) {
                        Ok(value) => hostname = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid tailscale hostname",
                            detail,
                        ),
                    },
                    "control_url" => match decode_string(attribute.expr()) {
                        Ok(value) => control_url = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid tailscale control_url",
                            detail,
                        ),
                    },
                    key => self.attr_error(
                        attribute,
                        block_position.line,
                        "Unsupported argument",
                        format!("An argument named \"{key}\" is not expected here."),
                    ),
                },
                Structure::Block(child) => {
                    let position = self.locator.find_block_after(
                        child.identifier(),
                        &block_labels(child),
                        block_position.line,
                    );
                    self.error_at(
                        position,
                        "Unsupported block",
                        format!(
                            "Blocks of type \"{}\" are not expected here.",
                            child.identifier()
                        ),
                    );
                }
            }
        }

        self.tailscale.push(TailscaleDecl {
            name,
            tags,
            hostname,
            control_url,
            order: self.tailscale.len(),
        });
    }

    fn read_forward(&mut self, block: &Block, labels: Vec<String>, block_position: Position) {
        if labels.len() != 2 {
            self.error_at(
                block_position,
                "Invalid forward block",
                "forward requires kind and name labels",
            );
            return;
        }
        let kind = labels[0].clone();
        let name = labels[1].clone();
        let key = format!("{kind}.{name}");
        if !valid_identifier(&name) {
            let position = self
                .locator
                .find_label(block_position.line, &name)
                .unwrap_or(block_position);
            self.error_at(
                position,
                "Invalid forward name",
                format!("forward \"{kind}\".\"{name}\" name must use a traversal identifier"),
            );
            return;
        }
        if !matches!(kind.as_str(), "host" | "tailscale") {
            self.error_at(
                block_position,
                "Unsupported forward kind",
                format!("unsupported forward kind \"{kind}\""),
            );
            return;
        }
        if !self.forward_keys.insert(key.clone()) {
            self.error_at(
                block_position,
                "Duplicate forward",
                format!("forward \"{key}\" is already defined."),
            );
            return;
        }

        let mut listen = String::new();
        let mut target = None;
        let mut target_port = None;
        let mut tunnel = None;
        for structure in block.body().iter() {
            match structure {
                Structure::Attribute(attribute) => match attribute.key() {
                    "listen" => match decode_string(attribute.expr()) {
                        Ok(value) => listen = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid forward listen",
                            detail,
                        ),
                    },
                    "target" => match decode_string(attribute.expr()) {
                        Ok(value) => target = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid forward target",
                            detail,
                        ),
                    },
                    "target_port" => match decode_u16(attribute.expr()) {
                        Ok(value) => target_port = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid forward target_port",
                            detail,
                        ),
                    },
                    "tunnel" => match decode_ref(attribute.expr()) {
                        Ok(value) => tunnel = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid forward tunnel",
                            detail,
                        ),
                    },
                    key => self.attr_error(
                        attribute,
                        block_position.line,
                        "Unsupported argument",
                        format!("An argument named \"{key}\" is not expected here."),
                    ),
                },
                Structure::Block(child) => {
                    let position = self.locator.find_block_after(
                        child.identifier(),
                        &block_labels(child),
                        block_position.line,
                    );
                    self.error_at(
                        position,
                        "Unsupported block",
                        format!(
                            "Blocks of type \"{}\" are not expected here.",
                            child.identifier()
                        ),
                    );
                }
            }
        }

        let Some(target) = target else {
            self.error_at(
                block_position,
                "Missing forward target",
                format!("forward \"{kind}\".\"{name}\" requires target"),
            );
            return;
        };
        let Some(target_port) = target_port else {
            self.error_at(
                block_position,
                "Missing forward target_port",
                format!("forward \"{kind}\".\"{name}\" requires target_port"),
            );
            return;
        };
        if kind == "tailscale" && tunnel.is_none() {
            self.error_at(
                block_position,
                "Missing forward tunnel",
                format!("forward \"{kind}\".\"{name}\" requires tunnel"),
            );
        }

        self.forwards.push(ForwardDecl {
            kind,
            name,
            listen,
            target,
            target_port,
            tunnel,
            order: self.forwards.len(),
        });
    }

    fn validate_references(&mut self) {
        let endpoint_kinds: HashMap<String, String> = self
            .endpoints
            .iter()
            .map(|endpoint| {
                (
                    format!("{}.{}", endpoint.kind, endpoint.name),
                    endpoint.kind.clone(),
                )
            })
            .collect();
        let credential_endpoints: HashMap<String, Ref> = self
            .credentials
            .iter()
            .map(|credential| {
                (
                    format!("{}.{}", credential.kind, credential.name),
                    credential.endpoint.clone(),
                )
            })
            .collect();
        let tunnel_names: HashSet<String> = self
            .tailscale
            .iter()
            .map(|tunnel| format!("tailscale.{}", tunnel.name))
            .collect();

        let credentials_snapshot = self.credentials.clone();
        for credential in &credentials_snapshot {
            if !known_credential_kind(&credential.kind) {
                self.error_at(
                    Position { line: 1, column: 1 },
                    "Invalid credential",
                    format!("unsupported credential kind \"{}\"", credential.kind),
                );
                continue;
            }
            if credential.endpoint.kind != "https" {
                self.error_at(
                    Position { line: 1, column: 1 },
                    "Invalid credential",
                    format!(
                        "credential \"{}\".\"{}\" must reference an https endpoint",
                        credential.kind, credential.name
                    ),
                );
                continue;
            }
            if !endpoint_kinds.contains_key(&credential.endpoint.key()) {
                self.error_at(
                    Position { line: 1, column: 1 },
                    "Invalid credential",
                    format!(
                        "credential \"{}\".\"{}\" references unknown endpoint \"{}\"",
                        credential.kind,
                        credential.name,
                        credential.endpoint.key()
                    ),
                );
            }
        }
        self.warn_credential_overlap();

        let rules_snapshot = self.rules.clone();
        for rule in &rules_snapshot {
            let mut family = None;
            for endpoint in &rule.endpoints {
                let Some(kind) = endpoint_kinds.get(&endpoint.key()) else {
                    self.error_at(
                        Position { line: 1, column: 1 },
                        "Invalid rule",
                        format!(
                            "rule \"{}\": references unknown endpoint \"{}\"",
                            rule.name,
                            endpoint.key()
                        ),
                    );
                    continue;
                };
                let endpoint_family = if kind == "ip" {
                    EndpointFamily::Ip
                } else {
                    EndpointFamily::Http
                };
                if let Some(existing) = family {
                    if existing != endpoint_family {
                        self.error_at(
                            Position { line: 1, column: 1 },
                            "Invalid rule",
                            format!(
                                "rule \"{}\": all endpoints in one rule must have the same family",
                                rule.name
                            ),
                        );
                    }
                } else {
                    family = Some(endpoint_family);
                }
            }
            if family == Some(EndpointFamily::Ip) && rule.condition.is_some() {
                self.error_at(
                    Position { line: 1, column: 1 },
                    "Invalid rule",
                    format!(
                        "rule \"{}\" condition is only supported for HTTP-family endpoint rules",
                        rule.name
                    ),
                );
            }
            if let Some(credential) = &rule.credential {
                let Some(endpoint) = credential_endpoints.get(&credential.key()) else {
                    self.error_at(
                        Position { line: 1, column: 1 },
                        "Invalid rule",
                        format!(
                            "rule \"{}\" references unknown credential \"{}\"",
                            rule.name,
                            credential.key()
                        ),
                    );
                    continue;
                };
                if family != Some(EndpointFamily::Http) {
                    self.error_at(
                        Position { line: 1, column: 1 },
                        "Invalid rule",
                        format!(
                            "rule \"{}\" credential predicates are invalid on ip endpoints",
                            rule.name
                        ),
                    );
                    continue;
                }
                if !rule.endpoints.iter().any(|candidate| candidate == endpoint) {
                    self.error_at(
                        Position { line: 1, column: 1 },
                        "Invalid rule",
                        format!(
                            "rule \"{}\" credential \"{}\" must bind to a directly referenced endpoint",
                            rule.name,
                            credential.key()
                        ),
                    );
                }
            }
            if let Some(tunnel) = &rule.tunnel {
                if tunnel.kind != "tailscale" || !tunnel_names.contains(&tunnel.key()) {
                    self.error_at(
                        Position { line: 1, column: 1 },
                        "Invalid rule",
                        format!(
                            "rule \"{}\" references unknown tunnel \"{}\"",
                            rule.name,
                            tunnel.key()
                        ),
                    );
                }
                if rule.verdict != Action::Allow {
                    self.error_at(
                        Position { line: 1, column: 1 },
                        "Invalid rule",
                        format!("rule \"{}\" tunnel requires verdict allow", rule.name),
                    );
                }
            }
        }

        let forwards_snapshot = self.forwards.clone();
        for forward in &forwards_snapshot {
            if !valid_target_selector(&forward.target) {
                self.error_at(
                    Position { line: 1, column: 1 },
                    "Invalid forward",
                    format!(
                        "forward \"{}\".\"{}\" target must start with name:, id:, or label:",
                        forward.kind, forward.name
                    ),
                );
            }
            if let Some(tunnel) = &forward.tunnel {
                if tunnel.kind != "tailscale" || !tunnel_names.contains(&tunnel.key()) {
                    self.error_at(
                        Position { line: 1, column: 1 },
                        "Invalid forward",
                        format!(
                            "forward \"{}\".\"{}\" references unknown tunnel \"{}\"",
                            forward.kind,
                            forward.name,
                            tunnel.key()
                        ),
                    );
                }
            }
        }
    }

    fn warn_credential_overlap(&mut self) {
        let mut by_endpoint: HashMap<String, Vec<CredentialDecl>> = HashMap::new();
        for credential in &self.credentials {
            by_endpoint
                .entry(credential.endpoint.key())
                .or_default()
                .push(credential.clone());
        }
        for (endpoint, credentials) in by_endpoint {
            let unconditional_count = credentials
                .iter()
                .filter(|credential| credential.condition.is_none())
                .count();
            if unconditional_count > 1 {
                self.warning_at(
                    Position { line: 1, column: 1 },
                    "Policy warning",
                    format!(
                        "multiple unconditional credentials bind to endpoint \"{endpoint}\"; runtime requests will fail closed if more than one matches"
                    ),
                );
            }

            let mut seen_conditions = HashSet::new();
            let mut warned_conditions = HashSet::new();
            for condition in credentials
                .iter()
                .filter_map(|credential| credential.condition.as_ref())
            {
                if !seen_conditions.insert(condition.source.clone())
                    && warned_conditions.insert(condition.source.clone())
                {
                    self.warning_at(
                        Position { line: 1, column: 1 },
                        "Policy warning",
                        format!(
                            "multiple credentials on endpoint \"{endpoint}\" use the same condition string"
                        ),
                    );
                }
            }
        }
    }

    fn finish(self) -> PolicyDocument {
        PolicyDocument {
            id: 1,
            source: SourceFile {
                filename: self.filename.to_owned(),
            },
            diagnostics: self.diagnostics,
            settings: self.settings,
            endpoints: self.endpoints,
            credentials: self.credentials,
            rules: self.rules,
            tailscale: self.tailscale,
            forwards: self.forwards,
        }
    }

    fn attr_error(
        &mut self,
        attribute: &hcl::Attribute,
        block_line: usize,
        summary: impl Into<String>,
        detail: impl Into<String>,
    ) {
        let position = self.locator.find_attr_after(attribute.key(), block_line);
        self.error_at(position, summary, detail);
    }

    fn error_at(
        &mut self,
        position: Position,
        summary: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.diagnostics.push(Diagnostic::error(
            self.filename,
            position.line,
            position.column,
            summary,
            detail,
        ));
    }

    fn warning_at(
        &mut self,
        position: Position,
        summary: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.diagnostics.push(Diagnostic::warning(
            self.filename,
            position.line,
            position.column,
            summary,
            detail,
        ));
    }
}

#[derive(Debug, Clone, Copy)]
struct Position {
    line: usize,
    column: usize,
}

struct SourceLocator<'a> {
    lines: Vec<&'a str>,
    cursor: usize,
}

impl<'a> SourceLocator<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            lines: source.lines().collect(),
            cursor: 0,
        }
    }

    fn find_block(&mut self, identifier: &str, labels: &[String]) -> Position {
        let position = self.find_block_from(identifier, labels, self.cursor + 1);
        self.cursor = position.line.saturating_sub(1);
        position
    }

    fn find_block_after(&self, identifier: &str, labels: &[String], after_line: usize) -> Position {
        self.find_block_from(identifier, labels, after_line)
    }

    fn find_block_from(&self, identifier: &str, labels: &[String], start_line: usize) -> Position {
        let start = start_line.saturating_sub(1);
        for (index, line) in self.lines.iter().enumerate().skip(start) {
            let trimmed = line.trim_start();
            if !trimmed.starts_with(identifier) {
                continue;
            }
            if labels.iter().all(|label| line.contains(label)) {
                return Position {
                    line: index + 1,
                    column: line.find(identifier).unwrap_or(0) + 1,
                };
            }
        }
        Position {
            line: start_line.max(1),
            column: 1,
        }
    }

    fn find_attr_after(&self, key: &str, after_line: usize) -> Position {
        let start = after_line.saturating_sub(1);
        for (index, line) in self.lines.iter().enumerate().skip(start) {
            if let Some(column) = find_attr_column(line, key) {
                return Position {
                    line: index + 1,
                    column,
                };
            }
        }
        Position {
            line: after_line.max(1),
            column: 1,
        }
    }

    fn find_label(&self, line: usize, label: &str) -> Option<Position> {
        let text = self.lines.get(line.saturating_sub(1))?;
        let quoted = format!("\"{label}\"");
        text.find(&quoted).map(|column| Position {
            line,
            column: column + 1,
        })
    }
}

fn find_attr_column(line: &str, key: &str) -> Option<usize> {
    let column = line.find(key)?;
    let before = &line[..column];
    if before.chars().any(|character| !character.is_whitespace()) {
        return None;
    }
    let after = &line[column + key.len()..];
    if after.trim_start().starts_with('=') {
        Some(column + 1)
    } else {
        None
    }
}

fn block_labels(block: &Block) -> Vec<String> {
    block
        .labels()
        .iter()
        .map(|label| label.as_str().to_owned())
        .collect()
}

fn decode_string(expression: &Expression) -> Result<String, String> {
    match expression {
        Expression::String(value) => Ok(value.clone()),
        _ => Err("string value required".to_owned()),
    }
}

fn decode_bool(expression: &Expression) -> Result<bool, String> {
    match expression {
        Expression::Bool(value) => Ok(*value),
        _ => Err("bool value required".to_owned()),
    }
}

fn decode_int(expression: &Expression) -> Result<i32, String> {
    match expression {
        Expression::Number(value) => {
            let text = value.to_string();
            if text.contains('.') {
                return Err(format!("number {text} must be an integer"));
            }
            text.parse::<i32>()
                .map_err(|_| format!("invalid integer {text}"))
        }
        _ => Err("integer value required".to_owned()),
    }
}

fn decode_u16(expression: &Expression) -> Result<u16, String> {
    let value = decode_int(expression)?;
    if !(1..=u16::MAX as i32).contains(&value) {
        return Err(format!("integer {value} is out of range"));
    }
    Ok(value as u16)
}

fn decode_size(expression: &Expression) -> Result<i64, String> {
    match expression {
        Expression::String(value) => parse_size(value),
        Expression::Number(value) => {
            let text = value.to_string();
            if text.contains('.') {
                return Err(format!("size {text} must be an integer"));
            }
            let parsed = text
                .parse::<i64>()
                .map_err(|_| format!("invalid size {text}"))?;
            if parsed < 0 {
                return Err(format!("invalid size {text}"));
            }
            Ok(parsed)
        }
        _ => Err("size string or integer required".to_owned()),
    }
}

fn decode_string_list(expression: &Expression) -> Result<Vec<String>, String> {
    match expression {
        Expression::Array(values) => values.iter().map(decode_string).collect(),
        _ => Err("expected list of strings".to_owned()),
    }
}

fn decode_port_ranges(expression: &Expression) -> Result<Vec<PortRange>, String> {
    let Expression::Array(values) = expression else {
        return Err("expected list of ports or port ranges".to_owned());
    };
    let mut ports = Vec::new();
    for value in values {
        match value {
            Expression::Number(number) => {
                let text = number.to_string();
                if text.contains('.') {
                    return Err(format!("port {text} must be an integer"));
                }
                let port = text
                    .parse::<u16>()
                    .map_err(|_| format!("port {text} is out of range"))?;
                if port == 0 {
                    return Err("port 0 is out of range".to_owned());
                }
                ports.push(PortRange {
                    start: port,
                    end: port,
                });
            }
            Expression::String(value) => ports.push(parse_port_range(value)?),
            _ => return Err("ports entries must be numbers or string ranges".to_owned()),
        }
    }
    Ok(ports)
}

fn parse_port_range(value: &str) -> Result<PortRange, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("port range must not be empty".to_owned());
    }
    let Some((start, end)) = value.split_once('-') else {
        return Err(format!("invalid port range \"{value}\""));
    };
    if end.contains('-') {
        return Err(format!("invalid port range \"{value}\""));
    }
    let start = parse_port(start.trim())?;
    let end = parse_port(end.trim())?;
    if end < start {
        return Err(format!("port range \"{value}\" ends before it starts"));
    }
    Ok(PortRange { start, end })
}

fn parse_port(value: &str) -> Result<u16, String> {
    if value.is_empty() || !value.chars().all(|character| character.is_ascii_digit()) {
        return Err(format!("port \"{value}\" is out of range"));
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("port \"{value}\" is out of range"))?;
    if port == 0 {
        return Err(format!("port \"{value}\" is out of range"));
    }
    Ok(port)
}

fn decode_ref(expression: &Expression) -> Result<Ref, String> {
    ref_from_text(&expression.to_string())
}

fn decode_ref_list(expression: &Expression) -> Result<Vec<Ref>, String> {
    let Expression::Array(values) = expression else {
        return Err("expected at least one reference".to_owned());
    };
    if values.is_empty() {
        return Err("expected at least one reference".to_owned());
    }
    values.iter().map(decode_ref).collect()
}

fn ref_from_text(value: &str) -> Result<Ref, String> {
    let text = value.trim();
    let Some((kind, name)) = text.split_once('.') else {
        return Err("expected two-part reference like https.github".to_owned());
    };
    if name.contains('.') || !valid_identifier(kind) || !valid_identifier(name) {
        return Err(format!(
            "reference \"{text}\" must use traversal identifiers"
        ));
    }
    Ok(Ref {
        kind: kind.to_owned(),
        name: name.to_owned(),
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

fn valid_http_header_name(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(http_header_token_byte)
}

fn valid_target_selector(value: &str) -> bool {
    ["name:", "id:", "label:"]
        .iter()
        .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len())
}

fn http_header_token_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn credential_condition_references_secret(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => index = skip_quoted_condition_literal(bytes, index),
            value if identifier_start_byte(value) => {
                let start = index;
                index += 1;
                while index < bytes.len() && identifier_byte(bytes[index]) {
                    index += 1;
                }
                let identifier = &source[start..index];
                if identifier == "secret" || identifier == "secrets" || identifier == "credential" {
                    return true;
                }
            }
            _ => index += 1,
        }
    }
    false
}

fn skip_quoted_condition_literal(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
            continue;
        }
        if bytes[index] == quote {
            return index + 1;
        }
        index += 1;
    }
    index
}

fn identifier_start_byte(value: u8) -> bool {
    value.is_ascii_alphabetic() || value == b'_'
}

fn identifier_byte(value: u8) -> bool {
    identifier_start_byte(value) || value.is_ascii_digit()
}

fn parse_terminal_action(value: &str) -> Result<Action, String> {
    match value {
        "" | "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        _ => Err(format!(
            "invalid action \"{value}\", expected allow or deny"
        )),
    }
}

fn parse_rule_action(value: &str) -> Result<Action, String> {
    match value {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        _ => Err(format!(
            "invalid verdict \"{value}\", expected allow or deny"
        )),
    }
}

fn parse_size(value: &str) -> Result<i64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("size must not be empty".to_owned());
    }
    let lower = value.to_lowercase();
    for (suffix, multiplier) in [
        ("gib", 1024 * 1024 * 1024),
        ("mib", 1024 * 1024),
        ("kib", 1024),
        ("b", 1),
    ] {
        if lower.ends_with(suffix) {
            let number = value[..value.len() - suffix.len()].trim();
            let parsed = number
                .parse::<i64>()
                .map_err(|_| format!("invalid size \"{value}\""))?;
            if parsed < 0 {
                return Err(format!("invalid size \"{value}\""));
            }
            return Ok(parsed * multiplier);
        }
    }
    let parsed = value
        .parse::<i64>()
        .map_err(|_| format!("invalid size \"{value}\""))?;
    if parsed < 0 {
        return Err(format!("invalid size \"{value}\""));
    }
    Ok(parsed)
}

fn known_credential_kind(kind: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use crate::model::{DiagnosticSeverity, ExpectedSecret, Policy};
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    fn expected_hash(source: &str) -> String {
        let digest = Sha256::digest(source.as_bytes());
        let mut hash = String::with_capacity("sha256:".len() + digest.len() * 2);
        hash.push_str("sha256:");
        for byte in digest {
            let _ = write!(&mut hash, "{byte:02x}");
        }
        hash
    }

    #[test]
    fn policy_hash_covers_exact_source_bytes() {
        let source = "settings {\n  default_action = \"allow\"\n}";
        let with_comment = "# comment\nsettings {\n  default_action = \"allow\"\n}";
        let reformatted = "settings { default_action = \"allow\" }";

        let policy = Policy::parse_str("policy.hcl", source).expect("policy parses");
        let comment_policy = Policy::parse_str("policy.hcl", with_comment).expect("policy parses");
        let reformatted_policy =
            Policy::parse_str("policy.hcl", reformatted).expect("policy parses");

        assert_eq!(policy.policy_hash, expected_hash(source));
        assert_ne!(policy.policy_hash, comment_policy.policy_hash);
        assert_ne!(policy.policy_hash, reformatted_policy.policy_hash);
    }

    #[test]
    fn parses_provider_specific_credential_metadata() {
        let policy = Policy::parse_str(
            "policy.hcl",
            r#"
endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "basic_auth" "git-basic" {
  endpoint = https.api
  username = "git"
}

credential "bearer_token" "api-token" {
  endpoint = https.api
  idempotency_key = true
  condition = "http.path.startsWith('/v1')"
}

credential "header_token" "internal" {
  endpoint = https.api
  header = "X-Internal-Token"
  prefix = "Token "
}
"#,
        )
        .expect("policy parses");

        let credentials = &policy.documents[0].credentials;
        assert_eq!(credentials[0].username, "git");
        assert!(credentials[1].idempotency_key);
        assert!(credentials[1].condition.is_some());
        assert_eq!(credentials[2].header, "X-Internal-Token");
        assert_eq!(credentials[2].prefix, "Token ");
    }

    #[test]
    fn rejects_missing_required_provider_metadata_and_secret_argument() {
        let err = Policy::parse_str(
            "policy.hcl",
            r#"
endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "basic_auth" "git-basic" {
  endpoint = https.api
  secret = "old-syntax"
}

credential "header_token" "internal" {
  endpoint = https.api
}
"#,
        )
        .expect_err("policy should fail");
        let text = err.to_string();
        assert!(text.contains("Unsupported argument"), "{text}");
        assert!(text.contains("requires username"), "{text}");
        assert!(text.contains("requires header"), "{text}");
    }

    #[test]
    fn rejects_credential_condition_secret_references() {
        let err = Policy::parse_str(
            "policy.hcl",
            r#"
endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "api" {
  endpoint = https.api
  condition = "credential.name == 'api' || secret.token != ''"
}
"#,
        )
        .expect_err("policy should fail");

        assert!(
            err.to_string()
                .contains("condition cannot reference credential.* or secret material"),
            "{err}"
        );
    }

    #[test]
    fn reports_provider_secret_slots() {
        let policy = Policy::parse_str(
            "policy.hcl",
            r#"
endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "basic_auth" "git-basic" {
  endpoint = https.api
  username = "git"
}

credential "openai_codex_oauth" "personal" {
  endpoint = https.api
}

credential "aws_credential" "prod" {
  endpoint = https.api
}
"#,
        )
        .expect("policy parses");

        let requirements = policy.secret_requirements();
        assert!(requirements.iter().any(|requirement| {
            requirement.credential.kind == "basic_auth"
                && requirement.credential.name == "git-basic"
                && requirement.slot == "password"
                && requirement.required
                && requirement.expected_secret == ExpectedSecret::Plain
        }));
        assert!(requirements.iter().any(|requirement| {
            requirement.credential.kind == "openai_codex_oauth"
                && requirement.slot == "oauth"
                && requirement.required
                && requirement.expected_secret == ExpectedSecret::OAuth
        }));
        assert!(requirements.iter().any(|requirement| {
            requirement.credential.kind == "aws_credential"
                && requirement.slot == "profile"
                && !requirement.required
                && requirement.expected_secret == ExpectedSecret::Plain
        }));
    }

    #[test]
    fn warns_on_suspicious_overlapping_credentials() {
        let policy = Policy::parse_str(
            "policy.hcl",
            r#"
endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "one" {
  endpoint = https.api
}

credential "bearer_token" "two" {
  endpoint = https.api
}

credential "bearer_token" "three" {
  endpoint = https.api
  condition = "http.path == '/private'"
}

credential "bearer_token" "four" {
  endpoint = https.api
  condition = "http.path == '/private'"
}
"#,
        )
        .expect("warnings do not fail load");

        let warnings = policy
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
            .map(|diagnostic| diagnostic.detail.as_str())
            .collect::<Vec<_>>();
        assert!(
            warnings
                .iter()
                .any(|detail| detail.contains("multiple unconditional credentials")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|detail| detail.contains("same condition string")),
            "{warnings:?}"
        );
    }
}
