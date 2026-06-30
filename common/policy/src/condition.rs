use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct HttpCondition {
    program: cel::Program,
    query_keys: BTreeSet<String>,
    header_keys: BTreeSet<String>,
}

impl HttpCondition {
    pub fn compile(source: &str) -> Result<Self, ConditionCompileError> {
        let prepared = prepare_http_condition_source(source)?;
        let program = cel::Program::compile(&prepared.source)
            .map_err(|err| ConditionCompileError::new(format!("parse condition: {err}")))?;

        let dummy =
            HttpConditionContext::default_with_keys(&prepared.query_keys, &prepared.header_keys);
        match execute(&program, &dummy)? {
            cel::Value::Bool(_) => Ok(Self {
                program,
                query_keys: prepared.query_keys,
                header_keys: prepared.header_keys,
            }),
            value => Err(ConditionCompileError::new(format!(
                "must return bool, got {}",
                value_type_name(&value)
            ))),
        }
    }

    pub fn evaluate(&self, context: &HttpConditionContext) -> Result<bool, ConditionEvalError> {
        let mut context = context.clone();
        context.fill_missing_keys(&self.query_keys, &self.header_keys);
        match execute(&self.program, &context).map_err(ConditionEvalError::from)? {
            cel::Value::Bool(value) => Ok(value),
            value => Err(ConditionEvalError::Message(format!(
                "condition returned {}",
                value_type_name(&value)
            ))),
        }
    }
}

fn execute(
    program: &cel::Program,
    context: &HttpConditionContext,
) -> Result<cel::Value, ConditionCompileError> {
    let mut cel_context = cel::Context::default();
    cel_context
        .add_variable("http_method", context.method.clone())
        .map_err(|err| ConditionCompileError::new(err.to_string()))?;
    cel_context
        .add_variable("http_host", context.host.clone())
        .map_err(|err| ConditionCompileError::new(err.to_string()))?;
    cel_context
        .add_variable("http_path", context.path.clone())
        .map_err(|err| ConditionCompileError::new(err.to_string()))?;
    cel_context
        .add_variable("http_query", context.query.clone())
        .map_err(|err| ConditionCompileError::new(err.to_string()))?;
    cel_context
        .add_variable("http_headers", context.headers.clone())
        .map_err(|err| ConditionCompileError::new(err.to_string()))?;
    program
        .execute(&cel_context)
        .map_err(|err| ConditionCompileError::new(err.to_string()))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpConditionContext {
    pub method: String,
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub headers: BTreeMap<String, Vec<String>>,
}

impl HttpConditionContext {
    fn default_with_keys(query_keys: &BTreeSet<String>, header_keys: &BTreeSet<String>) -> Self {
        let mut context = Self::default();
        for key in query_keys {
            context
                .query
                .insert(key.clone(), vec![String::new(), String::new()]);
        }
        for key in header_keys {
            context
                .headers
                .insert(key.clone(), vec![String::new(), String::new()]);
        }
        context
    }

    fn fill_missing_keys(&mut self, query_keys: &BTreeSet<String>, header_keys: &BTreeSet<String>) {
        for key in query_keys {
            self.query.entry(key.clone()).or_default();
        }
        for key in header_keys {
            self.headers.entry(key.clone()).or_default();
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ConditionCompileError {
    message: String,
}

impl ConditionCompileError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConditionEvalError {
    #[error("unknown condition id {0}")]
    UnknownCondition(u32),
    #[error("{0}")]
    Message(String),
}

impl From<ConditionCompileError> for ConditionEvalError {
    fn from(value: ConditionCompileError) -> Self {
        Self::Message(value.to_string())
    }
}

#[derive(Debug)]
struct PreparedSource {
    source: String,
    query_keys: BTreeSet<String>,
    header_keys: BTreeSet<String>,
}

fn prepare_http_condition_source(source: &str) -> Result<PreparedSource, ConditionCompileError> {
    reject_known_unavailable_facets(source)?;
    let mut query_keys = BTreeSet::new();
    let mut header_keys = BTreeSet::new();
    let mut prepared =
        rewrite_field_selects(source, "http.query", "http_query", false, &mut query_keys);
    prepared = rewrite_field_selects(
        &prepared,
        "http.headers",
        "http_headers",
        true,
        &mut header_keys,
    );
    prepared = rewrite_bracket_keys(&prepared, "http.query", false, &mut query_keys);
    prepared = rewrite_bracket_keys(&prepared, "http.headers", true, &mut header_keys);
    prepared = prepared.replace("http.method", "http_method");
    prepared = prepared.replace("http.host", "http_host");
    prepared = prepared.replace("http.path", "http_path");
    prepared = prepared.replace("http.query", "http_query");
    prepared = prepared.replace("http.headers", "http_headers");
    if prepared.contains("http.") {
        return Err(ConditionCompileError::new("unknown http condition facet"));
    }
    if prepared.contains("http_method") {
        prepared = lowercase_string_literals(&prepared);
    }
    reject_static_type_mismatches(&prepared)?;
    Ok(PreparedSource {
        source: prepared,
        query_keys,
        header_keys,
    })
}

fn reject_known_unavailable_facets(source: &str) -> Result<(), ConditionCompileError> {
    for facet in [
        "http.body",
        "http.body_json",
        "http.header",
        "http.raw_path",
        "http.escaped_path",
        "http.unknown",
    ] {
        if contains_http_facet(source, facet) {
            return Err(ConditionCompileError::new(format!(
                "unsupported http condition facet {facet}"
            )));
        }
    }
    Ok(())
}

fn contains_http_facet(source: &str, facet: &str) -> bool {
    let mut rest = source;
    while let Some(relative) = rest.find(facet) {
        let after = relative + facet.len();
        let next = rest[after..].chars().next();
        if next.is_none_or(|character| !is_identifier_char(character)) {
            return true;
        }
        rest = &rest[after..];
    }
    false
}

fn reject_static_type_mismatches(source: &str) -> Result<(), ConditionCompileError> {
    if source.contains("http_query ==") || source.contains("== http_query") {
        return Err(ConditionCompileError::new(
            "http.query comparisons must index a string list",
        ));
    }
    if source.contains("http_headers ==") || source.contains("== http_headers") {
        return Err(ConditionCompileError::new(
            "http.headers comparisons must index a string list",
        ));
    }
    if indexed_list_compared_to_string(source, "http_headers")
        || indexed_list_compared_to_string(source, "http_query")
    {
        return Err(ConditionCompileError::new(
            "http query and header entries are string lists",
        ));
    }
    Ok(())
}

fn indexed_list_compared_to_string(source: &str, variable: &str) -> bool {
    let mut rest = source;
    while let Some(index) = rest.find(variable) {
        rest = &rest[index + variable.len()..];
        let trimmed = rest.trim_start();
        if !trimmed.starts_with('[') {
            continue;
        }
        if let Some(close) = trimmed.find(']') {
            let after = trimmed[close + 1..].trim_start();
            if after.starts_with("== '") || after.starts_with("== \"") {
                return true;
            }
        }
    }
    false
}

fn rewrite_field_selects(
    source: &str,
    original: &str,
    replacement: &str,
    lowercase_key: bool,
    keys: &mut BTreeSet<String>,
) -> String {
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while let Some(relative) = source[index..].find(original) {
        let start = index + relative;
        output.push_str(&source[index..start]);
        let after_original = start + original.len();
        if source[after_original..].starts_with('.') {
            let key_start = after_original + 1;
            let key_end = source[key_start..]
                .find(|character: char| !is_identifier_char(character))
                .map(|offset| key_start + offset)
                .unwrap_or(source.len());
            if key_end > key_start {
                let mut key = source[key_start..key_end].to_owned();
                if lowercase_key {
                    key = key.to_lowercase();
                }
                keys.insert(key.clone());
                output.push_str(replacement);
                output.push('[');
                output.push('\'');
                output.push_str(&key);
                output.push('\'');
                output.push(']');
                index = key_end;
                continue;
            }
        }
        output.push_str(original);
        index = after_original;
    }
    output.push_str(&source[index..]);
    output
}

fn rewrite_bracket_keys(
    source: &str,
    variable: &str,
    lowercase_key: bool,
    keys: &mut BTreeSet<String>,
) -> String {
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while let Some(relative) = source[index..].find(variable) {
        let start = index + relative;
        output.push_str(&source[index..start]);
        output.push_str(variable);
        let mut cursor = start + variable.len();
        let after = &source[cursor..];
        if let Some(stripped) = after.strip_prefix('[') {
            if let Some(quote) = stripped.chars().next().filter(|c| *c == '\'' || *c == '"') {
                let key_start = cursor + 2;
                if let Some(end_relative) = source[key_start..].find(quote) {
                    let key_end = key_start + end_relative;
                    let after_quote = key_end + quote.len_utf8();
                    if source[after_quote..].starts_with(']') {
                        let mut key = source[key_start..key_end].to_owned();
                        if lowercase_key {
                            key = key.to_lowercase();
                        }
                        keys.insert(key.clone());
                        output.push('[');
                        output.push('\'');
                        output.push_str(&key);
                        output.push('\'');
                        output.push(']');
                        cursor = after_quote + 1;
                    }
                }
            }
        }
        index = cursor;
    }
    output.push_str(&source[index..]);
    output
}

fn lowercase_string_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\'' && character != '"' {
            output.push(character);
            continue;
        }
        output.push(character);
        let quote = character;
        while let Some(value) = chars.next() {
            output.push(value.to_ascii_lowercase());
            if value == quote {
                break;
            }
            if value == '\\' {
                if let Some(escaped) = chars.next() {
                    output.push(escaped.to_ascii_lowercase());
                }
            }
        }
    }
    output
}

fn is_identifier_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_' || character == '-'
}

fn value_type_name(value: &cel::Value) -> &'static str {
    match value {
        cel::Value::List(_) => "list",
        cel::Value::Map(_) => "map",
        cel::Value::Function(..) => "function",
        cel::Value::Int(_) => "int",
        cel::Value::UInt(_) => "uint",
        cel::Value::Float(_) => "float",
        cel::Value::String(_) => "string",
        cel::Value::Bytes(_) => "bytes",
        cel::Value::Bool(_) => "bool",
        cel::Value::Duration(_) => "duration",
        cel::Value::Timestamp(_) => "timestamp",
        cel::Value::Opaque(_) => "opaque",
        cel::Value::Null => "null",
    }
}
