use std::collections::BTreeMap;
use std::path::Path;

use eyre::{bail, Context as _};
use serde::{Deserialize, Serialize};

pub(crate) const MINIMAL_LINUX_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// A concrete environment layer, captured before planning so plan resolution is pure.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct EnvironmentLayer(pub(crate) BTreeMap<String, String>);

impl EnvironmentLayer {
    pub(crate) fn new(values: BTreeMap<String, String>) -> eyre::Result<Self> {
        for (key, value) in &values {
            validate_environment_key(key)?;
            validate_no_nul(value, "environment value")?;
        }
        Ok(Self(values))
    }
}

/// A CLI environment request. Bare keys import a value from the supplied host snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnvironmentOverride {
    Set { key: String, value: String },
    Import { key: String },
}

impl EnvironmentOverride {
    pub(crate) fn parse(value: &str) -> eyre::Result<Self> {
        let (key, value) = match value.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (value, None),
        };
        validate_environment_key(key)?;
        match value {
            Some(value) => {
                validate_no_nul(value, "environment value")?;
                Ok(Self::Set {
                    key: key.to_string(),
                    value: value.to_string(),
                })
            }
            None => Ok(Self::Import {
                key: key.to_string(),
            }),
        }
    }
}

/// Parses one env-file after resolving bare imports against a captured host environment.
///
/// This adapter performs no I/O. Its result is a concrete layer suitable for the pure merger.
pub(crate) fn parse_environment_file(
    contents: &str,
    host_environment: &BTreeMap<String, String>,
) -> eyre::Result<EnvironmentLayer> {
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        apply_override(
            &mut values,
            EnvironmentOverride::parse(line)?,
            host_environment,
        )?;
    }
    EnvironmentLayer::new(values)
}

/// Reads and concretizes one env-file. All later planning accepts the returned layer, not paths.
pub(crate) fn read_environment_file(
    path: &Path,
    host_environment: &BTreeMap<String, String>,
) -> eyre::Result<EnvironmentLayer> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read environment file {}", path.display()))?;
    parse_environment_file(&contents, host_environment)
}

/// Deterministically merges OCI defaults, concrete env-file layers, and CLI overrides.
pub(crate) fn resolve_environment(
    oci_environment: Option<&[String]>,
    file_layers: &[EnvironmentLayer],
    overrides: &[EnvironmentOverride],
    host_environment: &BTreeMap<String, String>,
) -> eyre::Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    if let Some(oci_environment) = oci_environment {
        for entry in oci_environment {
            let Some((key, value)) = entry.split_once('=') else {
                bail!("OCI environment entry must be KEY=VALUE: {entry:?}");
            };
            validate_environment_key(key)?;
            validate_no_nul(value, "OCI environment value")?;
            environment.insert(key.to_string(), value.to_string());
        }
    }
    for layer in file_layers {
        for (key, value) in &layer.0 {
            validate_environment_key(key)?;
            validate_no_nul(value, "environment file value")?;
            environment.insert(key.clone(), value.clone());
        }
    }
    for override_value in overrides {
        apply_override(&mut environment, override_value.clone(), host_environment)?;
    }
    environment
        .entry("PATH".to_string())
        .or_insert_with(|| MINIMAL_LINUX_PATH.to_string());
    Ok(environment)
}

fn apply_override(
    environment: &mut BTreeMap<String, String>,
    override_value: EnvironmentOverride,
    host_environment: &BTreeMap<String, String>,
) -> eyre::Result<()> {
    match override_value {
        EnvironmentOverride::Set { key, value } => {
            environment.insert(key, value);
        }
        EnvironmentOverride::Import { key } => {
            let value = host_environment.get(&key).ok_or_else(|| {
                eyre::eyre!("environment variable {key:?} is not set in host snapshot")
            })?;
            validate_no_nul(value, "host environment value")?;
            environment.insert(key, value.clone());
        }
    }
    Ok(())
}

pub(crate) fn validate_no_nul(value: &str, field: &str) -> eyre::Result<()> {
    if value.contains('\0') {
        bail!("{field} cannot contain NUL")
    }
    Ok(())
}

pub(crate) fn validate_environment_key(key: &str) -> eyre::Result<()> {
    let mut characters = key.bytes();
    let Some(first) = characters.next() else {
        bail!("environment variable name cannot be empty");
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !characters.all(|character| character.is_ascii_alphanumeric() || character == b'_')
    {
        bail!("invalid environment variable name {key:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::environment::{
        parse_environment_file, resolve_environment, EnvironmentLayer, EnvironmentOverride,
        MINIMAL_LINUX_PATH,
    };

    #[test]
    fn merges_environment_layers_in_documented_order() {
        let files = vec![
            EnvironmentLayer::new(BTreeMap::from([
                ("FROM_FILE".to_string(), "first".to_string()),
                ("SHARED".to_string(), "file-one".to_string()),
            ]))
            .expect("valid layer"),
            EnvironmentLayer::new(BTreeMap::from([(
                "SHARED".to_string(),
                "file-two".to_string(),
            )]))
            .expect("valid layer"),
        ];
        let environment = resolve_environment(
            Some(&["FROM_OCI=oci".to_string(), "SHARED=oci".to_string()]),
            &files,
            &[
                EnvironmentOverride::parse("SHARED=cli").expect("parse cli value"),
                EnvironmentOverride::parse("HOST").expect("parse host import"),
            ],
            &BTreeMap::from([("HOST".to_string(), "captured".to_string())]),
        )
        .expect("merge environment");

        assert_eq!(environment["FROM_OCI"], "oci");
        assert_eq!(environment["FROM_FILE"], "first");
        assert_eq!(environment["SHARED"], "cli");
        assert_eq!(environment["HOST"], "captured");
        assert_eq!(environment["PATH"], MINIMAL_LINUX_PATH);
    }

    #[test]
    fn rejects_invalid_environment_grammar_and_missing_host_imports() {
        for value in ["", "1BAD=value", "HAS-DASH=value", "KEY\0=value"] {
            assert!(
                EnvironmentOverride::parse(value).is_err(),
                "accepted {value:?}"
            );
        }
        assert!(
            resolve_environment(Some(&["BARE".to_string()]), &[], &[], &BTreeMap::new(),).is_err()
        );
        assert!(resolve_environment(
            None,
            &[],
            &[EnvironmentOverride::parse("MISSING").expect("parse import")],
            &BTreeMap::new(),
        )
        .is_err());
    }

    #[test]
    fn env_file_parser_captures_bare_imports_before_planning() {
        let layer = parse_environment_file(
            "# comment\nFROM_FILE=file\nHOST\n",
            &BTreeMap::from([("HOST".to_string(), "captured".to_string())]),
        )
        .expect("parse environment file");

        assert_eq!(layer.0["FROM_FILE"], "file");
        assert_eq!(layer.0["HOST"], "captured");
    }
}
