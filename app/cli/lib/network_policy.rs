use std::path::{Component, Path};

use eyre::Context as _;
use libvm::NetworkPolicy;

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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::resolve_network_policy_source;

    const MINIMAL_JSON: &str = r#"{ "version": 1, "metadata": { "source": "test" } }"#;

    #[test]
    fn resolves_json_policy_sources() {
        for (label, named) in [("absolute", false), ("named", true)] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = if named {
                let policies = dir.path().join("policies");
                fs::create_dir(&policies).expect("create policies dir");
                policies.join("github.json")
            } else {
                dir.path().join("policy.json")
            };
            fs::write(&path, MINIMAL_JSON).expect("write policy");
            let source = if named {
                "github"
            } else {
                path.to_str().expect("utf8")
            };
            let config_dir = if named { Some(dir.path()) } else { None };
            let policy = resolve_network_policy_source(source, config_dir)
                .unwrap_or_else(|err| panic!("{label}: {err}"));
            assert_eq!(policy.metadata()["source"], "test", "{label}");
        }
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
