use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Args;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command;
use crate::components::BuildContext;

pub const DEFAULT_KERNEL_REFERENCE: &str = "ghcr.io/vandycknick/silo/kernel:stable";
pub const DEFAULT_RPROBE_REFERENCE: &str = "ghcr.io/vandycknick/silo/rprobe:stable";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum KernelProfile {
    #[default]
    Workload,
    Rprobe,
}

impl KernelProfile {
    fn image_type(self) -> &'static str {
        match self {
            Self::Workload => KERNEL_MEDIA_TYPE,
            Self::Rprobe => "application/vnd.silo.rprobe-kernel.image.v1",
        }
    }
}

#[derive(Debug, Args)]
pub struct RprobeOptions {
    #[arg(long, default_value = DEFAULT_RPROBE_REFERENCE)]
    rprobe_reference: String,
    #[arg(long, value_name = "PATH", conflicts_with = "rprobe_assets")]
    rprobe_path: Option<PathBuf>,
    #[arg(long)]
    rprobe_offline: bool,
}

pub fn resolve_rprobe(
    context: &BuildContext<'_>,
    options: &RprobeOptions,
    assets: Option<&Path>,
) -> Result<KernelArtifact, KernelError> {
    if context.host.oci_architecture() != "arm64" {
        return Err(KernelError::Invalid("rprobe requires ARM64".to_string()));
    }
    let path = match assets {
        Some(directory) => {
            let path = directory.join("rprobe");
            Some(std::path::absolute(&path).map_err(|source| KernelError::Read { path, source })?)
        }
        None => options.rprobe_path.clone(),
    };
    resolve(
        context,
        &KernelOptions {
            reference: options.rprobe_reference.clone(),
            path,
            offline: options.rprobe_offline,
            profile: KernelProfile::Rprobe,
        },
    )
}

const KERNEL_MEDIA_TYPE: &str = "application/vnd.silo.kernel.image.v1";

#[derive(Debug, Args)]
pub struct KernelOptions {
    #[arg(long, default_value = DEFAULT_KERNEL_REFERENCE)]
    reference: String,
    #[arg(long, value_name = "PATH")]
    path: Option<PathBuf>,
    #[arg(long)]
    offline: bool,
    #[arg(skip)]
    profile: KernelProfile,
}

pub struct KernelArtifact {
    pub path: PathBuf,
}

#[derive(Clone)]
struct Descriptor {
    digest: String,
    size: u64,
    value: Value,
}

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("failed to fetch OCI reference {reference} with ORAS")]
    Oras {
        reference: String,
        #[source]
        source: command::CommandError,
    },
    #[error("failed to read {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to create directory {path}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to rename {from} to {to}")]
    Rename {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid OCI JSON from {context}: {message}")]
    Json { context: String, message: String },
    #[error("invalid kernel artifact: {0}")]
    Invalid(String),
    #[error("offline kernel cache has no verified resolution for {reference}")]
    OfflineCacheMiss { reference: String },
    #[error("kernel path must be absolute: {path}")]
    LocalPathNotAbsolute { path: PathBuf },
    #[error("kernel path is not a regular non-symlink file: {path}")]
    UnsafeLocalPath { path: PathBuf },
}

pub fn resolve(
    context: &BuildContext<'_>,
    options: &KernelOptions,
) -> Result<KernelArtifact, KernelError> {
    let cache_root = context.target_dir.join(match options.profile {
        KernelProfile::Workload => "kernel-cache",
        KernelProfile::Rprobe => "rprobe-cache",
    });
    create_directory(&cache_root)?;

    let (path, identity) = match options.path.as_deref() {
        Some(path) => resolve_local_kernel(context, &cache_root, path)?,
        None => resolve_oci_kernel(context, &cache_root, options)?,
    };
    write_provenance(context, &identity, options.profile)?;
    Ok(KernelArtifact { path })
}

fn resolve_local_kernel(
    context: &BuildContext<'_>,
    cache_root: &Path,
    path: &Path,
) -> Result<(PathBuf, Value), KernelError> {
    if !path.is_absolute() {
        return Err(KernelError::LocalPathNotAbsolute {
            path: path.to_path_buf(),
        });
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| KernelError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KernelError::UnsafeLocalPath {
            path: path.to_path_buf(),
        });
    }
    let bytes = fs::read(path).map_err(|source| KernelError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let digest = sha256_digest(&bytes);
    let cached = cache_bytes(cache_root, &digest, &bytes)?;
    Ok((
        cached,
        json!({
            "source": "local",
            "architecture": context.host.kernel_architecture(),
            "descriptor": {"digest": digest, "size": bytes.len()},
        }),
    ))
}

fn resolve_oci_kernel(
    context: &BuildContext<'_>,
    cache_root: &Path,
    options: &KernelOptions,
) -> Result<(PathBuf, Value), KernelError> {
    let reference = &options.reference;
    let repository = repository(reference)?;
    let reference_key = sha256_digest(reference.as_bytes());
    let references = cache_root.join("references");
    create_directory(&references)?;
    let reference_record = references.join(
        reference_key
            .strip_prefix("sha256:")
            .unwrap_or(&reference_key),
    );

    // Always follow the tag to whatever is published right now. Content is
    // cached by digest, so an unchanged tag costs one lookup and zero downloads.
    let index_descriptor = if options.offline {
        read_reference_record(&reference_record, reference, context)?
    } else {
        fetch_manifest_descriptor(reference)?
    };
    let index = fetch_or_cached_manifest(
        cache_root,
        &index_descriptor,
        &format!("{repository}@{}", index_descriptor.digest),
        options.offline,
    )?;
    if !options.offline {
        write_reference_record(&reference_record, reference, context, &index_descriptor)?;
    }
    let index = parse_json(&index, "OCI index")?;
    let manifest_descriptor = select_manifest(&index, context)?;
    let manifest = fetch_or_cached_manifest(
        cache_root,
        &manifest_descriptor,
        &format!("{repository}@{}", manifest_descriptor.digest),
        options.offline,
    )?;
    let manifest = parse_json(&manifest, "platform OCI manifest")?;
    let config_descriptor = descriptor(
        manifest.get("config").ok_or_else(|| {
            KernelError::Invalid("OCI manifest has no config descriptor".to_string())
        })?,
        "OCI config descriptor",
    )?;
    let config = fetch_or_cached_blob(cache_root, &config_descriptor, repository, options.offline)?;
    let config = parse_json(&config, "kernel artifact config")?;
    let image_type = options.profile.image_type();
    let kernel = manifest
        .get("layers")
        .and_then(Value::as_array)
        .and_then(|layers| {
            layers
                .iter()
                .find(|layer| layer.get("mediaType").and_then(Value::as_str) == Some(image_type))
        })
        .ok_or_else(|| KernelError::Invalid(format!("OCI manifest has no {image_type} layer")))?;
    let kernel = descriptor(kernel, "OCI kernel layer")?;
    fetch_or_cached_blob(cache_root, &kernel, repository, options.offline)?;
    let kernel_path = cache_path(cache_root, &kernel.digest)?;

    Ok((
        kernel_path,
        json!({
            "source": "oci",
            "reference": reference,
            "platform": {
                "os": "linux",
                "architecture": context.host.oci_architecture(),
            },
            "index": index_descriptor.value,
            "manifest": manifest_descriptor.value,
            "config": config_descriptor.value,
            "kernel": kernel.value,
            "artifactConfig": config,
        }),
    ))
}

fn select_manifest(index: &Value, context: &BuildContext<'_>) -> Result<Descriptor, KernelError> {
    let manifests = index
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or_else(|| KernelError::Invalid("OCI index manifests must be an array".to_string()))?;
    let expected_architecture = context.host.oci_architecture();
    let manifest = manifests
        .iter()
        .find(|manifest| {
            manifest
                .get("platform")
                .and_then(Value::as_object)
                .is_some_and(|platform| {
                    platform.get("os").and_then(Value::as_str) == Some("linux")
                        && platform.get("architecture").and_then(Value::as_str)
                            == Some(expected_architecture)
                })
        })
        .ok_or_else(|| {
            KernelError::Invalid(format!(
                "OCI index has no linux/{expected_architecture} manifest"
            ))
        })?;
    descriptor(manifest, "selected OCI platform manifest")
}

fn fetch_or_cached_manifest(
    cache_root: &Path,
    descriptor: &Descriptor,
    reference: &str,
    offline: bool,
) -> Result<Vec<u8>, KernelError> {
    if offline {
        return read_cached(cache_root, descriptor);
    }
    let cache = cache_path(cache_root, &descriptor.digest)?;
    if cache.exists() {
        return read_cached(cache_root, descriptor);
    }
    let bytes = fetch_manifest(reference)?;
    cache_bytes(cache_root, &descriptor.digest, &bytes)
        .and_then(|_| verify_bytes(&bytes, descriptor).map(|_| bytes))
}

fn fetch_or_cached_blob(
    cache_root: &Path,
    descriptor: &Descriptor,
    repository: &str,
    offline: bool,
) -> Result<Vec<u8>, KernelError> {
    if offline {
        return read_cached(cache_root, descriptor);
    }
    let cache = cache_path(cache_root, &descriptor.digest)?;
    if cache.exists() {
        return read_cached(cache_root, descriptor);
    }
    let temporary = temporary_path(cache_root, "blob")?;
    let reference = format!("{repository}@{}", descriptor.digest);
    let mut command = Command::new("oras");
    command.args(["blob", "fetch", "--no-tty", "--output"]);
    command.arg(&temporary).arg(&reference);
    let result = command::run(command);
    if let Err(source) = result {
        let _ = fs::remove_file(&temporary);
        return Err(KernelError::Oras { reference, source });
    }
    let bytes = fs::read(&temporary).map_err(|source| KernelError::Read {
        path: temporary.clone(),
        source,
    })?;
    let _ = fs::remove_file(&temporary);
    verify_bytes(&bytes, descriptor)?;
    cache_bytes(cache_root, &descriptor.digest, &bytes)?;
    Ok(bytes)
}

fn fetch_manifest_descriptor(reference: &str) -> Result<Descriptor, KernelError> {
    let mut command = Command::new("oras");
    command.args(["manifest", "fetch", "--descriptor", reference]);
    let output = command::output(command).map_err(|source| KernelError::Oras {
        reference: reference.to_string(),
        source,
    })?;
    let value = parse_json(&output.stdout, "OCI index descriptor")?;
    descriptor(&value, "OCI index descriptor")
}

fn fetch_manifest(reference: &str) -> Result<Vec<u8>, KernelError> {
    let mut command = Command::new("oras");
    command.args(["manifest", "fetch", reference]);
    let output = command::output(command).map_err(|source| KernelError::Oras {
        reference: reference.to_string(),
        source,
    })?;
    Ok(output.stdout)
}

fn read_cached(cache_root: &Path, descriptor: &Descriptor) -> Result<Vec<u8>, KernelError> {
    let path = cache_path(cache_root, &descriptor.digest)?;
    let metadata = fs::symlink_metadata(&path).map_err(|source| KernelError::Read {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KernelError::Invalid(format!(
            "cached digest {} is not a regular non-symlink file",
            descriptor.digest
        )));
    }
    let bytes = fs::read(&path).map_err(|source| KernelError::Read {
        path: path.clone(),
        source,
    })?;
    verify_bytes(&bytes, descriptor)?;
    Ok(bytes)
}

fn cache_bytes(cache_root: &Path, digest: &str, bytes: &[u8]) -> Result<PathBuf, KernelError> {
    let descriptor = Descriptor {
        digest: digest.to_string(),
        size: bytes.len() as u64,
        value: Value::Null,
    };
    verify_bytes(bytes, &descriptor)?;
    let path = cache_path(cache_root, digest)?;
    if path.exists() {
        read_cached(cache_root, &descriptor)?;
        return Ok(path);
    }
    let temporary = temporary_path(cache_root, "content")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| KernelError::Write {
            path: temporary.clone(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| KernelError::Write {
        path: temporary.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| KernelError::Write {
        path: temporary.clone(),
        source,
    })?;
    set_mode(&temporary, 0o644)?;
    fs::rename(&temporary, &path).map_err(|source| KernelError::Rename {
        from: temporary,
        to: path.clone(),
        source,
    })?;
    Ok(path)
}

fn write_provenance(
    context: &BuildContext<'_>,
    provenance: &Value,
    profile: KernelProfile,
) -> Result<(), KernelError> {
    let directory = context
        .target_dir
        .join(match profile {
            KernelProfile::Workload => "kernel-provenance",
            KernelProfile::Rprobe => "rprobe-provenance",
        })
        .join(context.host.runtime_target());
    create_directory(&directory)?;
    write_json_atomic(
        &directory.join(format!("{}.json", context.profile.directory())),
        provenance,
        0o644,
    )
}

fn write_reference_record(
    path: &Path,
    reference: &str,
    context: &BuildContext<'_>,
    index: &Descriptor,
) -> Result<(), KernelError> {
    write_json_atomic(
        path,
        &json!({
            "reference": reference,
            "platform": {
                "os": "linux",
                "architecture": context.host.oci_architecture(),
            },
            "index": index.value.clone(),
        }),
        0o644,
    )
}

fn read_reference_record(
    path: &Path,
    reference: &str,
    context: &BuildContext<'_>,
) -> Result<Descriptor, KernelError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(KernelError::OfflineCacheMiss {
                reference: reference.to_string(),
            });
        }
        Err(source) => {
            return Err(KernelError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let record = parse_json(&bytes, "offline reference record")?;
    if required_string(&record, "reference", "offline reference record")? != reference {
        return Err(KernelError::OfflineCacheMiss {
            reference: reference.to_string(),
        });
    }
    let platform = record
        .get("platform")
        .and_then(Value::as_object)
        .ok_or_else(|| KernelError::OfflineCacheMiss {
            reference: reference.to_string(),
        })?;
    if platform.get("os").and_then(Value::as_str) != Some("linux")
        || platform.get("architecture").and_then(Value::as_str)
            != Some(context.host.oci_architecture())
    {
        return Err(KernelError::OfflineCacheMiss {
            reference: reference.to_string(),
        });
    }
    descriptor(
        record
            .get("index")
            .ok_or_else(|| KernelError::OfflineCacheMiss {
                reference: reference.to_string(),
            })?,
        "offline index descriptor",
    )
}

fn write_json_atomic(path: &Path, value: &Value, mode: u32) -> Result<(), KernelError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| KernelError::Json {
        context: path.display().to_string(),
        message: error.to_string(),
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| KernelError::Invalid(format!("path has no parent: {}", path.display())))?;
    let (temporary, mut file) = create_temporary_file(parent, "json")?;
    file.write_all(&bytes)
        .map_err(|source| KernelError::Write {
            path: temporary.clone(),
            source,
        })?;
    file.sync_all().map_err(|source| KernelError::Write {
        path: temporary.clone(),
        source,
    })?;
    set_mode(&temporary, mode)?;
    drop(file);
    fs::rename(&temporary, path).map_err(|source| KernelError::Rename {
        from: temporary,
        to: path.to_path_buf(),
        source,
    })
}

fn parse_json(bytes: &[u8], source: &str) -> Result<Value, KernelError> {
    serde_json::from_slice(bytes).map_err(|error| KernelError::Json {
        context: source.to_string(),
        message: error.to_string(),
    })
}

fn descriptor(value: &Value, source: &str) -> Result<Descriptor, KernelError> {
    let digest = required_string(value, "digest", source)?.to_string();
    validate_digest(&digest)?;
    let size = value
        .get("size")
        .and_then(Value::as_u64)
        .filter(|size| *size > 0)
        .ok_or_else(|| KernelError::Invalid(format!("{source} size must be a positive integer")))?;
    Ok(Descriptor {
        digest,
        size,
        value: value.clone(),
    })
}

fn required_string<'a>(value: &'a Value, key: &str, source: &str) -> Result<&'a str, KernelError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|string| !string.is_empty())
        .ok_or_else(|| KernelError::Invalid(format!("{source} {key} must be a non-empty string")))
}

fn validate_digest(digest: &str) -> Result<(), KernelError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(KernelError::Invalid(format!(
            "digest must use sha256: {digest}"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(KernelError::Invalid(format!(
            "invalid sha256 digest: {digest}"
        )));
    }
    Ok(())
}

fn verify_bytes(bytes: &[u8], descriptor: &Descriptor) -> Result<(), KernelError> {
    if bytes.len() as u64 != descriptor.size {
        return Err(KernelError::Invalid(format!(
            "content for {} has size {}, expected {}",
            descriptor.digest,
            bytes.len(),
            descriptor.size
        )));
    }
    let actual = sha256_digest(bytes);
    if actual != descriptor.digest {
        return Err(KernelError::Invalid(format!(
            "content digest is {actual}, expected {}",
            descriptor.digest
        )));
    }
    Ok(())
}

fn cache_path(cache_root: &Path, digest: &str) -> Result<PathBuf, KernelError> {
    validate_digest(digest)?;
    let directory = cache_root.join("sha256");
    create_directory(&directory)?;
    Ok(directory.join(
        digest
            .strip_prefix("sha256:")
            .ok_or_else(|| KernelError::Invalid(format!("invalid digest: {digest}")))?,
    ))
}

fn repository(reference: &str) -> Result<&str, KernelError> {
    let without_digest = reference
        .split_once('@')
        .map_or(reference, |(repository, _)| repository);
    let slash = without_digest.rfind('/').unwrap_or(0);
    let repository = match without_digest[slash..].rfind(':') {
        Some(tag) => &without_digest[..slash + tag],
        None => without_digest,
    };
    if repository.is_empty() || repository.contains(char::is_whitespace) {
        return Err(KernelError::Invalid(format!(
            "invalid OCI reference: {reference}"
        )));
    }
    Ok(repository)
}

fn sha256_digest(bytes: &[u8]) -> String {
    let hex = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

fn create_directory(path: &Path) -> Result<(), KernelError> {
    fs::create_dir_all(path).map_err(|source| KernelError::CreateDirectory {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| KernelError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(KernelError::Invalid(format!(
            "cache directory is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn temporary_path(parent: &Path, purpose: &str) -> Result<PathBuf, KernelError> {
    for attempt in 0..128 {
        let path = parent.join(format!(
            ".kernel-{purpose}-{}-{attempt}",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(KernelError::Invalid(format!(
        "could not reserve a temporary {purpose} path in {}",
        parent.display()
    )))
}

fn create_temporary_file(parent: &Path, purpose: &str) -> Result<(PathBuf, File), KernelError> {
    for attempt in 0..128 {
        let path = parent.join(format!(
            ".kernel-{purpose}-{}-{attempt}",
            std::process::id()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(KernelError::Write { path, source }),
        }
    }
    Err(KernelError::Invalid(format!(
        "could not create a temporary {purpose} file in {}",
        parent.display()
    )))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), KernelError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
        KernelError::Write {
            path: path.to_path_buf(),
            source,
        }
    })
}
