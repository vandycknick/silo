use crate::model::EndpointFamily;
use crate::plugin::{FacetKind, PluginRegistry};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct HttpCondition {
    program: cel::Program,
    query_keys: BTreeSet<String>,
    header_keys: BTreeSet<String>,
}

#[derive(Debug)]
pub(crate) struct FacetCondition;

impl FacetCondition {
    pub fn compile(
        source: &str,
        family: EndpointFamily,
        plugins: &PluginRegistry,
    ) -> Result<Self, ConditionCompileError> {
        let family_definition = plugins.family(&family).ok_or_else(|| {
            ConditionCompileError::new(format!("unknown endpoint family {family:?}"))
        })?;
        let mut prepared = if family_definition.facets.iter().any(|facet| facet == "http") {
            prepare_http_condition_source(source)?
        } else {
            PreparedSource {
                source: source.to_owned(),
                query_keys: BTreeSet::new(),
                header_keys: BTreeSet::new(),
            }
        };
        for facet_name in family_definition
            .facets
            .iter()
            .filter(|name| name.as_str() != "http")
        {
            let facet = plugins.facet(facet_name).ok_or_else(|| {
                ConditionCompileError::new(format!(
                    "endpoint family {family:?} references unknown facet {facet_name}"
                ))
            })?;
            for field in facet.fields {
                prepared.source = rewrite_cel_identifier(
                    &prepared.source,
                    &format!("{}.{}", facet.name, field.name),
                    &format!("{}_{}", facet.name, field.name),
                );
            }
            if contains_cel_path_prefix(&prepared.source, &format!("{}.", facet.name)) {
                return Err(ConditionCompileError::new(format!(
                    "unknown {} condition facet",
                    facet.name
                )));
            }
        }
        let program = cel::Program::compile(&prepared.source)
            .map_err(|err| ConditionCompileError::new(format!("parse condition: {err}")))?;
        let value = execute_facet_condition(&program, family, plugins, &prepared)?;
        if !matches!(value, cel::Value::Bool(_)) {
            return Err(ConditionCompileError::new(format!(
                "must return bool, got {}",
                value_type_name(&value)
            )));
        }
        Ok(Self)
    }
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
    add_http_context(&mut cel_context, context)?;
    program
        .execute(&cel_context)
        .map_err(|err| ConditionCompileError::new(err.to_string()))
}

fn add_http_context(
    cel_context: &mut cel::Context,
    context: &HttpConditionContext,
) -> Result<(), ConditionCompileError> {
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
    Ok(())
}

fn execute_facet_condition(
    program: &cel::Program,
    family: EndpointFamily,
    plugins: &PluginRegistry,
    prepared: &PreparedSource,
) -> Result<cel::Value, ConditionCompileError> {
    let family_definition = plugins
        .family(&family)
        .ok_or_else(|| ConditionCompileError::new(format!("unknown endpoint family {family:?}")))?;
    let mut context = cel::Context::default();
    if family_definition.facets.iter().any(|facet| facet == "http") {
        add_http_context(
            &mut context,
            &HttpConditionContext::default_with_keys(&prepared.query_keys, &prepared.header_keys),
        )?;
    }
    for facet_name in family_definition
        .facets
        .iter()
        .filter(|name| name.as_str() != "http")
    {
        let facet = plugins.facet(facet_name).ok_or_else(|| {
            ConditionCompileError::new(format!(
                "endpoint family {family:?} references unknown facet {facet_name}"
            ))
        })?;
        for field in facet.fields {
            let variable = format!("{}_{}", facet.name, field.name);
            match field.kind {
                FacetKind::String => context.add_variable(variable, String::new()),
                FacetKind::StringListMap => {
                    context.add_variable(variable, BTreeMap::<String, Vec<String>>::new())
                }
                FacetKind::Int => context.add_variable(variable, 0_i64),
                FacetKind::Bool => context.add_variable(variable, false),
            }
            .map_err(|err| ConditionCompileError::new(err.to_string()))?;
        }
    }
    program
        .execute(&context)
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
    pub(crate) fn new(message: impl Into<String>) -> Self {
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
    prepared = rewrite_cel_identifier(&prepared, "http.method", "http_method");
    prepared = rewrite_cel_identifier(&prepared, "http.host", "http_host");
    prepared = rewrite_cel_identifier(&prepared, "http.path", "http_path");
    prepared = rewrite_cel_identifier(&prepared, "http.query", "http_query");
    prepared = rewrite_cel_identifier(&prepared, "http.headers", "http_headers");
    if contains_cel_path_prefix(&prepared, "http.") {
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
    let mut index = 0;
    while index < source.len() {
        if quoted_literal_at(source, index) {
            index = quoted_literal_end(source, index);
            continue;
        }
        if cel_path_at(source, index, facet) {
            return true;
        }
        index = next_char_index(source, index);
    }
    false
}

fn contains_cel_path_prefix(source: &str, prefix: &str) -> bool {
    let mut index = 0;
    while index < source.len() {
        if quoted_literal_at(source, index) {
            index = quoted_literal_end(source, index);
            continue;
        }
        if source[index..].starts_with(prefix) && cel_path_start_boundary(source, index) {
            return true;
        }
        index = next_char_index(source, index);
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
    while index < source.len() {
        if quoted_literal_at(source, index) {
            let end = quoted_literal_end(source, index);
            output.push_str(&source[index..end]);
            index = end;
            continue;
        }
        if cel_path_at(source, index, original) {
            let after_original = index + original.len();
            if !source[after_original..].starts_with('.') {
                output.push_str(original);
                index = after_original;
                continue;
            }
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
        let next = next_char_index(source, index);
        output.push_str(&source[index..next]);
        index = next;
    }
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
    while index < source.len() {
        if quoted_literal_at(source, index) {
            let end = quoted_literal_end(source, index);
            output.push_str(&source[index..end]);
            index = end;
            continue;
        }
        if !cel_path_at(source, index, variable) {
            let next = next_char_index(source, index);
            output.push_str(&source[index..next]);
            index = next;
            continue;
        }
        output.push_str(variable);
        let mut cursor = index + variable.len();
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
    output
}

fn rewrite_cel_identifier(source: &str, original: &str, replacement: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        if quoted_literal_at(source, index) {
            let end = quoted_literal_end(source, index);
            output.push_str(&source[index..end]);
            index = end;
            continue;
        }
        if cel_path_at(source, index, original) {
            output.push_str(replacement);
            index += original.len();
            continue;
        }
        let next = next_char_index(source, index);
        output.push_str(&source[index..next]);
        index = next;
    }
    output
}

fn cel_path_at(source: &str, index: usize, path: &str) -> bool {
    if !source[index..].starts_with(path) {
        return false;
    }
    if !cel_path_start_boundary(source, index) {
        return false;
    }
    source[index + path.len()..]
        .chars()
        .next()
        .is_none_or(|character| !is_cel_identifier_char(character))
}

fn cel_path_start_boundary(source: &str, index: usize) -> bool {
    source[..index]
        .chars()
        .next_back()
        .is_none_or(|character| !is_cel_identifier_char(character) && character != '.')
}

fn quoted_literal_at(source: &str, index: usize) -> bool {
    matches!(source.as_bytes().get(index), Some(b'\'' | b'"'))
}

fn quoted_literal_end(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == quote {
            return index + 1;
        } else {
            index += 1;
        }
    }
    index
}

fn next_char_index(source: &str, index: usize) -> usize {
    index + source[index..].chars().next().map_or(0, char::len_utf8)
}

fn is_cel_identifier_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
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

#[cfg(test)]
mod tests {
    use crate::condition::{rewrite_cel_identifier, FacetCondition};
    use crate::model::EndpointFamily;
    use crate::plugin::PluginRegistry;

    #[test]
    fn compiles_composed_package_condition() {
        FacetCondition::compile(
            "http.method == 'GET' && package.identity_known && package.age_hours < 24 && !package.malware",
            EndpointFamily::Package,
            &PluginRegistry::builtins(),
        )
        .expect("package condition");
    }

    #[test]
    fn rejects_unknown_package_field() {
        let error = FacetCondition::compile(
            "package.unknown",
            EndpointFamily::Package,
            &PluginRegistry::builtins(),
        )
        .expect_err("unknown field must fail");

        assert!(error
            .to_string()
            .contains("unknown package condition facet"));
    }

    #[test]
    fn rejects_non_boolean_package_condition() {
        let error = FacetCondition::compile(
            "package.age_hours",
            EndpointFamily::Package,
            &PluginRegistry::builtins(),
        )
        .expect_err("integer result must fail");

        assert!(error.to_string().contains("must return bool"));
    }

    #[test]
    fn facet_rewrite_preserves_string_literals() {
        assert_eq!(
            rewrite_cel_identifier(
                r#"package.name == "package.age_hours""#,
                "package.age_hours",
                "package_age_hours",
            ),
            r#"package.name == "package.age_hours""#
        );
        FacetCondition::compile(
            r#"package.name == "package.age_hours""#,
            EndpointFamily::Package,
            &PluginRegistry::builtins(),
        )
        .expect("facet path in string literal");
    }
}
