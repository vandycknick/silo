use std::path::{Component, Path};

use bento_policy::NetworkPolicy;
use eyre::Context as _;

pub(crate) fn resolve_network_policy_source(
    source: &str,
    policy_config_dir: Option<&Path>,
) -> eyre::Result<NetworkPolicy> {
    let source = source.trim();
    if source.is_empty() {
        eyre::bail!("network policy source cannot be empty");
    }

    let path = Path::new(source);
    if path.is_absolute() {
        return load_policy_path(path);
    }

    if looks_like_relative_path(path) {
        eyre::bail!(
            "relative network policy paths are not supported; use an absolute path or named policy"
        );
    }

    let policy_dir = policy_config_dir
        .ok_or_else(|| eyre::eyre!("named network policies require a config directory"))?
        .join("policies");
    let hcl = policy_dir.join(format!("{source}.hcl"));
    if hcl.exists() {
        return load_policy_path(&hcl);
    }
    let json = policy_dir.join(format!("{source}.json"));
    if json.exists() {
        return load_policy_path(&json);
    }

    eyre::bail!(
        "network policy `{source}` not found; looked for {} and {}",
        hcl.display(),
        json.display()
    );
}

fn load_policy_path(path: &Path) -> eyre::Result<NetworkPolicy> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("hcl") => NetworkPolicy::from_hcl_file(path)
            .with_context(|| format!("load HCL network policy {}", path.display())),
        Some("json") => NetworkPolicy::from_json_file(path)
            .with_context(|| format!("load JSON network policy {}", path.display())),
        Some(extension) => eyre::bail!(
            "unsupported network policy file extension .{extension}; expected .hcl or .json"
        ),
        None => eyre::bail!(
            "network policy path {} has no extension; expected .hcl or .json",
            path.display()
        ),
    }
}

fn looks_like_relative_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Normal(_)
        )
    }) && (path.components().count() > 1 || path.extension().is_some())
}

pub(crate) fn policy_source_display(source: &str) -> &str {
    source
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::resolve_network_policy_source;

    const MINIMAL_JSON: &str = r#"{ "version": 1, "metadata": { "source": "test" } }"#;

    #[test]
    fn resolves_absolute_json_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.json");
        fs::write(&path, MINIMAL_JSON).expect("write policy");

        let policy = resolve_network_policy_source(path.to_str().expect("utf8"), None)
            .expect("resolve policy");

        assert_eq!(policy.metadata["source"], "test");
    }

    #[test]
    fn resolves_named_json_policy_from_config_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policies = dir.path().join("policies");
        fs::create_dir(&policies).expect("create policies dir");
        fs::write(policies.join("github.json"), MINIMAL_JSON).expect("write policy");

        let policy = resolve_network_policy_source("github", Some(dir.path())).expect("resolve");

        assert_eq!(policy.metadata["source"], "test");
    }

    #[test]
    fn rejects_relative_policy_paths() {
        let err = resolve_network_policy_source("policies/github.hcl", None)
            .expect_err("relative path should fail");

        assert!(err.to_string().contains("relative network policy paths"));
    }

    #[test]
    fn rejects_unknown_policy_extensions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.txt");
        fs::write(&path, "{}").expect("write policy");

        let err = resolve_network_policy_source(path.to_str().expect("utf8"), None)
            .expect_err("extension should fail");

        assert!(err
            .to_string()
            .contains("unsupported network policy file extension"));
    }
}
