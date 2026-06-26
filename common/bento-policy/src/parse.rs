use crate::model::{
    Action, AuditSettingsDecl, CredentialDecl, Diagnostic, DiagnosticSeverity, EndpointDecl,
    EndpointFamily, LoadError, Policy, PolicyDocument, PortRange, Ref, RuleDecl, SettingsDecl,
    SourceFile, Transport,
};
use hcl::{Block, Body, Expression, Structure};
use std::collections::{HashMap, HashSet};

pub fn parse_policy(filename: String, source: &str) -> Result<Policy, LoadError> {
    let mut policy = Policy {
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
    endpoint_keys: HashSet<String>,
    credential_keys: HashSet<String>,
    rule_names: HashSet<String>,
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
            endpoint_keys: HashSet::new(),
            credential_keys: HashSet::new(),
            rule_names: HashSet::new(),
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
                    self.error_at(block_position, "Invalid settings block", "settings does not accept labels");
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
            "tailscale" | "forward" => self.error_at(
                block_position,
                "Reserved policy block",
                format!(
                    "{} blocks are reserved by the policy schema but not implemented by bento-netd yet",
                    block.identifier()
                ),
            ),
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
                    "body_buffer" => {
                        match decode_string(attribute.expr()).and_then(|value| parse_size(&value)) {
                            Ok(value) => body_buffer = value,
                            Err(detail) => self.attr_error(
                                attribute,
                                block_line,
                                "Invalid settings.audit.body_buffer",
                                detail,
                            ),
                        }
                    }
                    "body_storage" => {
                        match decode_string(attribute.expr()).and_then(|value| parse_size(&value)) {
                            Ok(value) => body_storage = value,
                            Err(detail) => self.attr_error(
                                attribute,
                                block_line,
                                "Invalid settings.audit.body_storage",
                                detail,
                            ),
                        }
                    }
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
                    ("ip", "source") => match decode_string_list(attribute.expr()) {
                        Ok(value) => source = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid endpoint source",
                            detail,
                        ),
                    },
                    ("ip", "destination") => match decode_string_list(attribute.expr()) {
                        Ok(value) => destination = value,
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid endpoint destination",
                            detail,
                        ),
                    },
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
        for structure in block.body().iter() {
            match structure {
                Structure::Attribute(attribute) => match attribute.key() {
                    "endpoint" => match decode_ref(attribute.expr()) {
                        Ok(value) => endpoint = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential endpoint",
                            detail,
                        ),
                    },
                    "condition" => match decode_string(attribute.expr()) {
                        Ok(value) => condition_source = Some(value),
                        Err(detail) => self.attr_error(
                            attribute,
                            block_position.line,
                            "Invalid credential condition",
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
        let Some(endpoint) = endpoint else {
            self.error_at(
                block_position,
                "Missing credential endpoint",
                format!("credential \"{kind}\".\"{name}\" requires endpoint"),
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
                            "Invalid credential",
                            format!("credential \"{kind}\".\"{name}\" condition: {err}"),
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        self.credentials.push(CredentialDecl {
            kind,
            name,
            endpoint,
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
            verdict,
            priority,
            disabled,
            condition,
            reason,
            order: self.rules.len(),
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
