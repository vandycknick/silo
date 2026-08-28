use std::fs;
use std::path::Path;

use serde_json::Value;
use thiserror::Error;

const RUST_PRODUCT_MANIFESTS: &[&str] = &[
    "app/cli/Cargo.toml",
    "runtime/libvm/Cargo.toml",
    "runtime/vmmon/Cargo.toml",
    "virt/krun/Cargo.toml",
    "guest/agent/Cargo.toml",
    "guest/init/Cargo.toml",
    "sdk/node/Cargo.toml",
    "sdk/go/native/Cargo.toml",
];
const NODE_PRODUCT_MANIFEST: &str = "sdk/node/package.json";
const GO_PRODUCT_VERSION: &str = "sdk/go/version.go";
const GO_NATIVE_ABI: &str = "sdk/go/native/src/abi.rs";
const NODE_PRODUCT_LOCKFILE: &str = "sdk/node/package-lock.json";

#[derive(Debug, Error)]
pub enum VersionError {
    #[error("failed to read version authority {path}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse JSON in {path}")]
    ParseJson {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("VERSION must contain a semantic version, found {version:?}")]
    InvalidAuthority { version: String },
    #[error("no version declaration found in {path}")]
    MissingDeclaration { path: String },
    #[error("version mismatch in {path}: expected {expected}, found {actual}")]
    Mismatch {
        path: String,
        expected: String,
        actual: String,
    },
}

pub fn check(workspace_root: &Path) -> Result<(), VersionError> {
    let authority_path = workspace_root.join("VERSION");
    let authority = read(&authority_path)?;
    let authority = authority.trim().to_string();
    if !is_semver(&authority) {
        return Err(VersionError::InvalidAuthority { version: authority });
    }

    for manifest in RUST_PRODUCT_MANIFESTS {
        check_declaration(workspace_root, manifest, "version =", &authority)?;
    }
    check_json_version(
        workspace_root,
        NODE_PRODUCT_MANIFEST,
        &["version"],
        &authority,
    )?;
    check_json_version(
        workspace_root,
        NODE_PRODUCT_LOCKFILE,
        &["version"],
        &authority,
    )?;
    check_json_version(
        workspace_root,
        NODE_PRODUCT_LOCKFILE,
        &["packages", "", "version"],
        &authority,
    )?;
    check_declaration(
        workspace_root,
        GO_PRODUCT_VERSION,
        "const Version =",
        &authority,
    )?;
    let go_abi = unquoted_declaration(
        workspace_root,
        GO_PRODUCT_VERSION,
        "const ffiABIVersion uint32 =",
    )?;
    let native_abi =
        unquoted_declaration(workspace_root, GO_NATIVE_ABI, "const ABI_VERSION: u32 =")?;
    if go_abi != native_abi {
        return Err(VersionError::Mismatch {
            path: GO_NATIVE_ABI.to_string(),
            expected: go_abi,
            actual: native_abi,
        });
    }

    println!("version-check: {authority}");
    Ok(())
}

fn check_declaration(
    workspace_root: &Path,
    relative_path: &str,
    prefix: &str,
    expected: &str,
) -> Result<(), VersionError> {
    let path = workspace_root.join(relative_path);
    let contents = read(&path)?;
    let actual =
        declaration(&contents, prefix).ok_or_else(|| VersionError::MissingDeclaration {
            path: relative_path.to_string(),
        })?;
    if actual != expected {
        return Err(VersionError::Mismatch {
            path: relative_path.to_string(),
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

fn unquoted_declaration(
    workspace_root: &Path,
    relative_path: &str,
    prefix: &str,
) -> Result<String, VersionError> {
    let contents = read(&workspace_root.join(relative_path))?;
    contents
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix).map(str::trim))
        .map(|value| value.trim_end_matches(';').trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| VersionError::MissingDeclaration {
            path: relative_path.to_string(),
        })
}

fn check_json_version(
    workspace_root: &Path,
    relative_path: &str,
    fields: &[&str],
    expected: &str,
) -> Result<(), VersionError> {
    let path = workspace_root.join(relative_path);
    let contents = read(&path)?;
    let json: Value =
        serde_json::from_str(&contents).map_err(|source| VersionError::ParseJson {
            path: relative_path.to_string(),
            source,
        })?;
    let actual = fields
        .iter()
        .try_fold(&json, |value, field| value.get(*field))
        .and_then(Value::as_str)
        .ok_or_else(|| VersionError::MissingDeclaration {
            path: format!("{relative_path} ({})", fields.join(".")),
        })?;
    if actual != expected {
        return Err(VersionError::Mismatch {
            path: format!("{relative_path} ({})", fields.join(".")),
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, VersionError> {
    fs::read_to_string(path).map_err(|source| VersionError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn declaration(contents: &str, prefix: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let value = line.trim().strip_prefix(prefix)?.trim();
        let value = value.strip_prefix('"')?.split('"').next()?;
        Some(value.to_string())
    })
}

fn is_semver(version: &str) -> bool {
    version.split('.').count() == 3
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}
