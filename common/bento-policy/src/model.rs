use crate::condition::{
    ConditionCompileError, ConditionEvalError, HttpCondition, HttpConditionContext,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct Policy {
    pub documents: Vec<PolicyDocument>,
    pub diagnostics: Vec<Diagnostic>,
    #[serde(skip)]
    pub(crate) conditions: Vec<HttpCondition>,
}

impl Policy {
    pub fn parse_str(filename: impl Into<String>, source: &str) -> Result<Self, LoadError> {
        crate::parse::parse_policy(filename.into(), source)
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn secret_requirements(&self) -> Vec<SecretRequirement> {
        self.documents
            .iter()
            .flat_map(|document| document.credentials.iter())
            .map(|credential| SecretRequirement {
                credential: Ref {
                    kind: credential.kind.clone(),
                    name: credential.name.clone(),
                },
                endpoint: credential.endpoint.clone(),
                expected_secret: ExpectedSecret::Plain,
            })
            .collect()
    }

    pub fn evaluate_http_condition(
        &self,
        condition_id: u32,
        context: &HttpConditionContext,
    ) -> Result<bool, ConditionEvalError> {
        if condition_id == 0 {
            return Ok(true);
        }
        let index = condition_id
            .checked_sub(1)
            .ok_or(ConditionEvalError::UnknownCondition(condition_id))?
            as usize;
        let condition = self
            .conditions
            .get(index)
            .ok_or(ConditionEvalError::UnknownCondition(condition_id))?;
        condition.evaluate(context)
    }

    pub(crate) fn register_http_condition(
        &mut self,
        source: &str,
    ) -> Result<ConditionDecl, ConditionCompileError> {
        let condition = HttpCondition::compile(source)?;
        let id = (self.conditions.len() + 1) as u32;
        self.conditions.push(condition);
        Ok(ConditionDecl {
            id,
            source: source.to_owned(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub id: u32,
    pub source: SourceFile,
    pub diagnostics: Vec<Diagnostic>,
    pub settings: SettingsDecl,
    pub endpoints: Vec<EndpointDecl>,
    pub credentials: Vec<CredentialDecl>,
    pub rules: Vec<RuleDecl>,
}

impl PolicyDocument {
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub filename: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadError {
    pub filename: String,
    pub diagnostics: Vec<Diagnostic>,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_count = self
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .count();
        if error_count == 1 {
            write!(
                formatter,
                "load policy file {} failed with 1 error:",
                self.filename
            )?;
        } else {
            write!(
                formatter,
                "load policy file {} failed with {error_count} errors:",
                self.filename
            )?;
        }
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

impl std::error::Error for LoadError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub summary: String,
    pub detail: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
}

impl Diagnostic {
    pub fn error(
        file: impl Into<String>,
        line: usize,
        column: usize,
        summary: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            severity: DiagnosticSeverity::Error,
            code: None,
            summary: summary.into(),
            detail: detail.into(),
            file: file.into(),
            line,
            column,
        }
    }

    pub fn warning(
        file: impl Into<String>,
        line: usize,
        column: usize,
        summary: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            severity: DiagnosticSeverity::Warning,
            code: None,
            summary: summary.into(),
            detail: detail.into(),
            file: file.into(),
            line,
            column,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsDecl {
    pub default_action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditSettingsDecl>,
}

impl Default for SettingsDecl {
    fn default() -> Self {
        Self {
            default_action: Action::Allow,
            audit: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSettingsDecl {
    pub body_buffer: i64,
    pub body_storage: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointFamily {
    Ip,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    PacketFilter,
    HttpProxy,
    HttpsMitm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointDecl {
    pub kind: String,
    pub name: String,
    pub family: EndpointFamily,
    pub transport: Transport,
    pub default_port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    pub order: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ref {
    pub kind: String,
    pub name: String,
}

impl Ref {
    pub fn key(&self) -> String {
        format!("{}.{}", self.kind, self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionDecl {
    pub id: u32,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDecl {
    pub kind: String,
    pub name: String,
    pub endpoint: Ref,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionDecl>,
    pub order: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDecl {
    pub name: String,
    pub endpoints: Vec<Ref>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<Ref>,
    pub verdict: Action,
    pub priority: i32,
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionDecl>,
    pub reason: String,
    pub order: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRequirement {
    pub credential: Ref,
    pub endpoint: Ref,
    pub expected_secret: ExpectedSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedSecret {
    Plain,
    OAuth,
}
