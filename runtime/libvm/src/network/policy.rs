use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkPolicyRef {
    value: String,
}

impl NetworkPolicyRef {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_policy_ref(&value)?;
        Ok(Self { value })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn resolve(&self, config_dir: Option<PathBuf>) -> Result<PathBuf, String> {
        let path = Path::new(&self.value);
        if path.is_absolute() {
            validate_absolute_policy_path(path)?;
            return Ok(path.to_path_buf());
        }

        validate_policy_name(&self.value)?;
        let config_dir = config_dir.ok_or_else(|| {
            format!(
                "could not resolve named network policy {:?} because HOME is unavailable",
                self.value
            )
        })?;
        Ok(config_dir
            .join("policies")
            .join(format!("{}.hcl", self.value)))
    }
}

impl Serialize for NetworkPolicyRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.value)
    }
}

impl<'de> Deserialize<'de> for NetworkPolicyRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

fn validate_policy_ref(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if path.is_absolute() {
        validate_absolute_policy_path(path)
    } else {
        validate_policy_name(value)
    }
}

fn validate_absolute_policy_path(path: &Path) -> Result<(), String> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("hcl") {
        return Err(format!(
            "network policy path must point to a .hcl file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_policy_name(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err("network policy_ref cannot be empty".to_string());
    }
    if value.contains('/') || value.contains('\\') {
        return Err(format!(
            "relative network policy paths are not supported: {value:?}; use an absolute .hcl path or a named policy"
        ));
    }
    if matches!(value, "." | "..") {
        return Err(format!("invalid network policy name {value:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::NetworkPolicyRef;
    use std::path::PathBuf;

    #[test]
    fn resolves_named_policy_from_config_dir() {
        let policy_ref = NetworkPolicyRef::new("github").expect("policy ref");

        assert_eq!(
            policy_ref
                .resolve(Some(PathBuf::from("/home/me/.config/bento")))
                .expect("resolve policy ref"),
            PathBuf::from("/home/me/.config/bento/policies/github.hcl")
        );
    }

    #[test]
    fn resolves_absolute_hcl_path() {
        let policy_ref = NetworkPolicyRef::new("/etc/bento/policy.hcl").expect("policy ref");

        assert_eq!(
            policy_ref.resolve(None).expect("resolve policy ref"),
            PathBuf::from("/etc/bento/policy.hcl")
        );
    }

    #[test]
    fn rejects_relative_policy_paths() {
        let err = NetworkPolicyRef::new("policies/github.hcl").expect_err("relative path");

        assert!(err.contains("relative network policy paths are not supported"));
    }

    #[test]
    fn rejects_non_hcl_absolute_path() {
        let err = NetworkPolicyRef::new("/etc/bento/policy.json").expect_err("non-hcl path");

        assert!(err.contains(".hcl"));
    }
}
