use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::profiles::Profile;
use crate::targets::HostTarget;

const COMPLETE_RECORD: &str = ".silo-release-complete.json";
const QUALIFICATION_RECORD: &str = "release-qualification.json";
const COMPLETE_RECORD_VERSION: u64 = 1;
const QUALIFICATION_POLICY: &str = "runtime-audit-v1";

#[derive(Debug, Error)]
pub enum RecordError {
    #[error("failed to read release record {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write release record {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid release record {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

pub fn complete_source_matches(target: &Path, source: &str) -> Result<bool, RecordError> {
    let Some(record) = read_json(&target.join(COMPLETE_RECORD))? else {
        return Ok(false);
    };
    Ok(record.get("source_fingerprint").and_then(Value::as_str) == Some(source))
}

pub fn complete_matches(
    target: &Path,
    source: &str,
    toolchain: &str,
    profile: Profile,
    host: HostTarget,
    kernel: &Value,
) -> Result<bool, RecordError> {
    let path = target.join(COMPLETE_RECORD);
    let Some(record) = read_json(&path)? else {
        return Ok(false);
    };
    if record.get("version").and_then(Value::as_u64) != Some(COMPLETE_RECORD_VERSION)
        || record.get("source_fingerprint").and_then(Value::as_str) != Some(source)
        || record.get("toolchain_fingerprint").and_then(Value::as_str) != Some(toolchain)
        || record.get("profile").and_then(Value::as_str) != Some(profile.directory())
        || record.get("target").and_then(Value::as_str) != Some(host.runtime_target())
        || record.get("kernel") != Some(kernel)
        || fingerprint(&record)?
            != record
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or_default()
    {
        return Ok(false);
    }
    artifacts_match(target, &record, complete_artifact_paths(profile, host))
}

pub fn write_complete(
    target: &Path,
    source: &str,
    toolchain: &str,
    profile: Profile,
    host: HostTarget,
    kernel: &Value,
) -> Result<(), RecordError> {
    let artifacts = snapshots(target, complete_artifact_paths(profile, host))?;
    let mut record = json!({
        "version": COMPLETE_RECORD_VERSION,
        "source_fingerprint": source,
        "toolchain_fingerprint": toolchain,
        "profile": profile.directory(),
        "target": host.runtime_target(),
        "kernel": kernel,
        "artifacts": artifacts,
    });
    let digest = fingerprint(&record)?;
    record["fingerprint"] = Value::String(digest);
    write_json_atomic(&target.join(COMPLETE_RECORD), &record)
}

pub fn invalidate_qualification(target_dir: &Path, host: HostTarget) -> Result<(), RecordError> {
    let path = qualification_path(target_dir, host);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RecordError::Write { path, source }),
    }
}

pub fn write_qualification(target_dir: &Path, host: HostTarget) -> Result<(), RecordError> {
    let complete_target = target_dir.join("release-build").join(host.runtime_target());
    let complete_path = complete_target.join(COMPLETE_RECORD);
    let complete = read_json(&complete_path)?.ok_or_else(|| RecordError::Invalid {
        path: complete_path.clone(),
        reason: "missing complete release record".to_string(),
    })?;
    let complete_fingerprint = fingerprint(&complete)?;
    if complete.get("fingerprint").and_then(Value::as_str) != Some(complete_fingerprint.as_str())
        || !artifacts_match(
            &complete_target,
            &complete,
            complete_artifact_paths(Profile::Release, host),
        )?
    {
        return Err(RecordError::Invalid {
            path: complete_path,
            reason: "complete release record does not bind current isolated outputs".to_string(),
        });
    }
    let artifacts = snapshots(target_dir, qualification_artifact_paths(host))?;
    let mut record = json!({
        "version": 1,
        "audit_policy": QUALIFICATION_POLICY,
        "complete_fingerprint": complete_fingerprint,
        "target": host.runtime_target(),
        "artifacts": artifacts,
    });
    let digest = fingerprint(&record)?;
    record["fingerprint"] = Value::String(digest);
    write_json_atomic(&qualification_path(target_dir, host), &record)
}

pub fn qualification_matches(target_dir: &Path, host: HostTarget) -> Result<bool, RecordError> {
    let path = qualification_path(target_dir, host);
    let Some(record) = read_json(&path)? else {
        return Ok(false);
    };
    if record.get("version").and_then(Value::as_u64) != Some(1)
        || record.get("audit_policy").and_then(Value::as_str) != Some(QUALIFICATION_POLICY)
        || record.get("target").and_then(Value::as_str) != Some(host.runtime_target())
        || fingerprint(&record)?
            != record
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or_default()
        || !artifacts_match(target_dir, &record, qualification_artifact_paths(host))?
    {
        return Ok(false);
    }
    let complete_target = target_dir.join("release-build").join(host.runtime_target());
    let complete_path = complete_target.join(COMPLETE_RECORD);
    let Some(complete) = read_json(&complete_path)? else {
        return Ok(false);
    };
    let complete_fingerprint = fingerprint(&complete)?;
    Ok(record.get("complete_fingerprint").and_then(Value::as_str)
        == Some(complete_fingerprint.as_str())
        && complete.get("fingerprint").and_then(Value::as_str)
            == Some(complete_fingerprint.as_str())
        && artifacts_match(
            &complete_target,
            &complete,
            complete_artifact_paths(Profile::Release, host),
        )?)
}

fn complete_artifact_paths(
    profile: Profile,
    host: HostTarget,
) -> Vec<(&'static str, PathBuf, u32)> {
    let profile = PathBuf::from(profile.directory());
    let guest = PathBuf::from(host.guest_target().triple()).join("release");
    vec![
        ("cli", profile.join("silo"), 0o755),
        ("vmmon", profile.join("vmmon"), 0o755),
        ("netd", profile.join("netd"), 0o755),
        ("krun", profile.join("krun"), 0o755),
        ("init", guest.join("init"), 0o755),
        ("agent", guest.join("silo-agent"), 0o755),
        ("kernel", profile.join("assets/kernel-default"), 0o644),
        ("initramfs", profile.join("assets/initramfs"), 0o644),
        ("runtime-agent", profile.join("assets/agent"), 0o755),
    ]
}

fn qualification_artifact_paths(host: HostTarget) -> Vec<(&'static str, PathBuf, u32)> {
    let stage = PathBuf::from("silo-runtime")
        .join(host.runtime_target())
        .join("release");
    vec![
        ("cli", PathBuf::from("release/silo"), 0o755),
        ("vmmon", stage.join("bin/vmmon"), 0o755),
        ("netd", stage.join("bin/netd"), 0o755),
        ("krun", stage.join("bin/krun"), 0o755),
        ("kernel", stage.join("assets/kernel-default"), 0o644),
        ("initramfs", stage.join("assets/initramfs"), 0o644),
        ("agent", stage.join("assets/agent"), 0o755),
    ]
}

fn snapshots(
    root: &Path,
    expected: Vec<(&'static str, PathBuf, u32)>,
) -> Result<Value, RecordError> {
    let mut artifacts = BTreeMap::new();
    for (name, relative, mode) in expected {
        artifacts.insert(name, snapshot(root, &relative, mode)?);
    }
    serde_json::to_value(artifacts).map_err(|error| RecordError::Invalid {
        path: root.to_path_buf(),
        reason: error.to_string(),
    })
}

fn artifacts_match(
    root: &Path,
    record: &Value,
    expected: Vec<(&'static str, PathBuf, u32)>,
) -> Result<bool, RecordError> {
    let Some(artifacts) = record.get("artifacts").and_then(Value::as_object) else {
        return Ok(false);
    };
    if artifacts.len() != expected.len() {
        return Ok(false);
    }
    for (name, relative, mode) in expected {
        let Some(recorded_snapshot) = artifacts.get(name) else {
            return Ok(false);
        };
        let actual = match snapshot(root, &relative, mode) {
            Ok(actual) => actual,
            Err(RecordError::Invalid { .. } | RecordError::Read { .. }) => return Ok(false),
            Err(error) => return Err(error),
        };
        if actual != *recorded_snapshot {
            return Ok(false);
        }
    }
    Ok(true)
}

fn snapshot(root: &Path, relative: &Path, mode: u32) -> Result<Value, RecordError> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|source| RecordError::Read {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(RecordError::Invalid {
            path,
            reason: format!("expected a regular file with mode {mode:o}"),
        });
    }
    let bytes = fs::read(&path).map_err(|source| RecordError::Read {
        path: path.clone(),
        source,
    })?;
    Ok(json!({
        "path": relative,
        "mode": mode,
        "size": bytes.len(),
        "sha256": sha256(&bytes),
    }))
}

fn read_json(path: &Path) -> Result<Option<Value>, RecordError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RecordError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| RecordError::Invalid {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })
}

fn fingerprint(record: &Value) -> Result<String, RecordError> {
    let mut value = record.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("fingerprint");
    }
    let bytes = serde_json::to_vec(&value).map_err(|error| RecordError::Invalid {
        path: PathBuf::from("release record"),
        reason: error.to_string(),
    })?;
    Ok(sha256(&bytes))
}

fn write_json_atomic(path: &Path, value: &Value) -> Result<(), RecordError> {
    let parent = path.parent().ok_or_else(|| RecordError::Invalid {
        path: path.to_path_buf(),
        reason: "path has no parent".to_string(),
    })?;
    fs::create_dir_all(parent).map_err(|source| RecordError::Write {
        path: parent.to_path_buf(),
        source,
    })?;
    let temporary = parent.join(format!(
        ".{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("record"),
        std::process::id()
    ));
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| RecordError::Invalid {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| RecordError::Write {
            path: temporary.clone(),
            source,
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| RecordError::Write {
            path: temporary.clone(),
            source,
        })?;
    drop(file);
    fs::rename(&temporary, path).map_err(|source| RecordError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn qualification_path(target_dir: &Path, host: HostTarget) -> PathBuf {
    target_dir
        .join("release-qualification")
        .join(host.runtime_target())
        .join(QUALIFICATION_RECORD)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
