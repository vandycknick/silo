use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Args;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command;
use crate::components::BuildContext;

pub const DEFAULT_KERNEL_REFERENCE: &str = "ghcr.io/vandycknick/silo/kernel:stable";

const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const ARTIFACT_TYPE: &str = "application/vnd.silo.kernel.v1";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.silo.kernel.config.v1+json";
const KERNEL_MEDIA_TYPE: &str = "application/vnd.silo.kernel.image.v1";
const KCONFIG_MEDIA_TYPE: &str = "application/vnd.silo.kernel.kconfig.v1";
const SYSTEM_MAP_MEDIA_TYPE: &str = "application/vnd.silo.kernel.system-map.v1";
const DEBUG_MEDIA_TYPE: &str = "application/vnd.silo.kernel.debug.v1+xz";

#[derive(Debug, Args)]
pub struct KernelOptions {
    #[arg(long, default_value = DEFAULT_KERNEL_REFERENCE)]
    reference: String,
    #[arg(long, value_name = "PATH")]
    path: Option<PathBuf>,
    #[arg(long)]
    offline: bool,
}

pub struct KernelArtifact {
    pub path: PathBuf,
}

impl KernelOptions {
    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn local_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn offline(&self) -> bool {
        self.offline
    }
}

#[derive(Clone)]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    value: Value,
}

struct ManifestArtifacts {
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Debug, Error)]
pub enum KernelError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
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
    #[error("offline kernel reference record is unsafe: {path}")]
    UnsafeReferenceRecord { path: PathBuf },
}

pub fn resolve(
    context: &BuildContext<'_>,
    options: &KernelOptions,
) -> Result<KernelArtifact, KernelError> {
    let cache_root = context.target_dir.join("kernel-cache");
    create_directory(&cache_root)?;

    let (path, provenance) = match options.path.as_deref() {
        Some(path) => resolve_local_kernel(context, &cache_root, path)?,
        None => resolve_oci_kernel(context, &cache_root, options)?,
    };
    write_provenance(context, &provenance)?;
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
    validate_kernel(&bytes, context)?;
    let digest = sha256_digest(&bytes);
    let cached = cache_bytes(cache_root, &digest, &bytes)?;
    Ok((
        cached,
        json!({
            "source": "local",
            "path": path,
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
    let reference_key = sha256_digest(reference.as_bytes());
    let references = cache_root.join("references");
    create_directory(&references)?;
    let reference_record = references.join(
        reference_key
            .strip_prefix("sha256:")
            .unwrap_or(&reference_key),
    );

    let index_descriptor = if options.offline {
        read_reference_record(&reference_record, reference, context)?
    } else {
        let descriptor = fetch_manifest_descriptor(reference)?;
        if descriptor.media_type != OCI_INDEX_MEDIA_TYPE {
            return Err(KernelError::Invalid(format!(
                "OCI reference {reference} resolved to {}, expected {OCI_INDEX_MEDIA_TYPE}",
                descriptor.media_type
            )));
        }
        let index = fetch_manifest(reference)?;
        cache_bytes(cache_root, &descriptor.digest, &index)?;
        descriptor
    };

    if index_descriptor.media_type != OCI_INDEX_MEDIA_TYPE {
        return Err(KernelError::Invalid(format!(
            "cached index descriptor has media type {}, expected {OCI_INDEX_MEDIA_TYPE}",
            index_descriptor.media_type
        )));
    }
    let index = read_cached(cache_root, &index_descriptor)?;
    let index = parse_json(&index, "OCI index")?;
    validate_index(&index)?;
    let manifest_descriptor = select_manifest(&index, context)?;
    let repository = repository(reference)?;
    let manifest_reference = format!("{repository}@{}", manifest_descriptor.digest);
    let manifest = fetch_or_cached_manifest(
        cache_root,
        &manifest_descriptor,
        &manifest_reference,
        options.offline,
    )?;
    let manifest = parse_json(&manifest, "platform OCI manifest")?;
    let artifacts = validate_manifest(&manifest, context)?;
    let config = fetch_or_cached_blob(cache_root, &artifacts.config, repository, options.offline)?;
    let config = parse_json(&config, "kernel artifact config")?;
    validate_config(&config, context)?;
    let mut kernel_path = None;
    for layer in &artifacts.layers {
        let bytes = fetch_or_cached_blob(cache_root, layer, repository, options.offline)?;
        if layer.media_type == KERNEL_MEDIA_TYPE {
            validate_kernel(&bytes, context)?;
            kernel_path = Some(cache_path(cache_root, &layer.digest)?);
        }
    }
    let kernel_path = kernel_path.ok_or_else(|| {
        KernelError::Invalid("OCI manifest has no validated kernel layer".to_string())
    })?;

    if !options.offline {
        write_reference_record(&reference_record, reference, context, &index_descriptor)?;
    }

    Ok((
        kernel_path,
        json!({
            "source": "oci",
            "reference": reference,
            "index": index_descriptor.value,
            "manifest": manifest_descriptor.value,
            "config": artifacts.config.value,
            "layers": artifacts.layers.iter().map(|layer| layer.value.clone()).collect::<Vec<_>>(),
        }),
    ))
}

fn validate_index(index: &Value) -> Result<(), KernelError> {
    require_u64(index, "schemaVersion", "OCI index", 2)?;
    require_string_value(index, "mediaType", "OCI index", OCI_INDEX_MEDIA_TYPE)?;
    require_string_value(index, "artifactType", "OCI index", ARTIFACT_TYPE)?;
    let manifests = index
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or_else(|| KernelError::Invalid("OCI index manifests must be an array".to_string()))?;
    if manifests.is_empty() {
        return Err(KernelError::Invalid(
            "OCI index has no manifests".to_string(),
        ));
    }
    for manifest in manifests {
        let descriptor = descriptor(manifest, "OCI index manifest")?;
        if descriptor.media_type != OCI_MANIFEST_MEDIA_TYPE {
            return Err(KernelError::Invalid(format!(
                "OCI index manifest {} has media type {}, expected {OCI_MANIFEST_MEDIA_TYPE}",
                descriptor.digest, descriptor.media_type
            )));
        }
    }
    Ok(())
}

fn select_manifest(index: &Value, context: &BuildContext<'_>) -> Result<Descriptor, KernelError> {
    let manifests = index
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or_else(|| KernelError::Invalid("OCI index manifests must be an array".to_string()))?;
    let expected_architecture = context.host.oci_architecture();
    let matches = manifests
        .iter()
        .filter(|manifest| {
            manifest
                .get("platform")
                .and_then(Value::as_object)
                .is_some_and(|platform| {
                    platform.get("os").and_then(Value::as_str) == Some("linux")
                        && platform.get("architecture").and_then(Value::as_str)
                            == Some(expected_architecture)
                        && platform.get("variant").is_none()
                })
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(KernelError::Invalid(format!(
            "OCI index must contain exactly one linux/{expected_architecture} manifest, found {}",
            matches.len()
        )));
    }
    descriptor(matches[0], "selected OCI platform manifest")
}

fn validate_manifest(
    manifest: &Value,
    context: &BuildContext<'_>,
) -> Result<ManifestArtifacts, KernelError> {
    require_u64(manifest, "schemaVersion", "OCI manifest", 2)?;
    require_string_value(
        manifest,
        "mediaType",
        "OCI manifest",
        OCI_MANIFEST_MEDIA_TYPE,
    )?;
    require_string_value(manifest, "artifactType", "OCI manifest", ARTIFACT_TYPE)?;
    let config = descriptor(
        manifest.get("config").ok_or_else(|| {
            KernelError::Invalid("OCI manifest has no config descriptor".to_string())
        })?,
        "OCI config descriptor",
    )?;
    if config.media_type != CONFIG_MEDIA_TYPE {
        return Err(KernelError::Invalid(format!(
            "OCI config has media type {}, expected {CONFIG_MEDIA_TYPE}",
            config.media_type
        )));
    }
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| KernelError::Invalid("OCI manifest layers must be an array".to_string()))?;
    let mut kernel = None;
    let mut kconfig = 0;
    let mut system_map = 0;
    let mut debug = 0;
    let mut descriptors = Vec::with_capacity(layers.len());
    for layer in layers {
        let descriptor = descriptor(layer, "OCI layer descriptor")?;
        match descriptor.media_type.as_str() {
            KERNEL_MEDIA_TYPE => {
                if kernel.replace(descriptor.clone()).is_some() {
                    return Err(KernelError::Invalid(
                        "OCI manifest contains more than one kernel layer".to_string(),
                    ));
                }
            }
            KCONFIG_MEDIA_TYPE => kconfig += 1,
            SYSTEM_MAP_MEDIA_TYPE => system_map += 1,
            DEBUG_MEDIA_TYPE => debug += 1,
            other => {
                return Err(KernelError::Invalid(format!(
                    "OCI manifest contains unsupported layer media type {other}"
                )));
            }
        }
        descriptors.push(descriptor);
    }
    let expected_debug = usize::from(context.host.oci_architecture() == "arm64");
    if kernel.is_none() || kconfig != 1 || system_map != 1 || debug != expected_debug {
        return Err(KernelError::Invalid(format!(
            "OCI manifest layer contract is invalid (kernel={}, kconfig={kconfig}, system-map={system_map}, debug={debug})",
            kernel.is_some()
        )));
    }
    match kernel {
        Some(_) => Ok(ManifestArtifacts {
            config,
            layers: descriptors,
        }),
        None => Err(KernelError::Invalid(
            "OCI manifest has no kernel layer".to_string(),
        )),
    }
}

fn validate_config(config: &Value, context: &BuildContext<'_>) -> Result<(), KernelError> {
    require_u64(config, "schemaVersion", "kernel artifact config", 1)?;
    require_string_value(config, "track", "kernel artifact config", "stable")?;
    require_string_value(
        config,
        "architecture",
        "kernel artifact config",
        context.host.kernel_architecture(),
    )?;
    let platform = config
        .get("platform")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            KernelError::Invalid("kernel artifact config platform must be an object".to_string())
        })?;
    if platform.get("os").and_then(Value::as_str) != Some("linux")
        || platform.get("architecture").and_then(Value::as_str)
            != Some(context.host.oci_architecture())
    {
        return Err(KernelError::Invalid(format!(
            "kernel artifact config platform must be linux/{}",
            context.host.oci_architecture()
        )));
    }
    let kernel = config
        .get("kernel")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            KernelError::Invalid("kernel artifact config kernel must be an object".to_string())
        })?;
    if kernel.get("mediaType").and_then(Value::as_str) != Some(KERNEL_MEDIA_TYPE) {
        return Err(KernelError::Invalid(
            "kernel artifact config has an invalid kernel media type".to_string(),
        ));
    }
    let expected_format = if context.host.oci_architecture() == "arm64" {
        "arm64-image"
    } else {
        "elf"
    };
    if kernel.get("format").and_then(Value::as_str) != Some(expected_format) {
        return Err(KernelError::Invalid(format!(
            "kernel artifact config format must be {expected_format}"
        )));
    }
    let source = config
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            KernelError::Invalid("kernel artifact config source must be an object".to_string())
        })?;
    let source_digest = source
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            KernelError::Invalid("kernel artifact config source digest is missing".to_string())
        })?;
    validate_digest(source_digest)?;
    Ok(())
}

fn validate_kernel(bytes: &[u8], context: &BuildContext<'_>) -> Result<(), KernelError> {
    match context.host.oci_architecture() {
        "arm64" => validate_arm64_image(bytes),
        "amd64" => validate_x86_64_elf(bytes),
        architecture => Err(KernelError::Invalid(format!(
            "unsupported kernel architecture {architecture}"
        ))),
    }
}

fn validate_arm64_image(bytes: &[u8]) -> Result<(), KernelError> {
    const ARM64_IMAGE_HEADER_SIZE: usize = 64;
    const ARM64_IMAGE_MAGIC_OFFSET: usize = 0x38;
    const ARM64_IMAGE_MAGIC: &[u8; 4] = b"ARM\x64";

    if bytes.len() < ARM64_IMAGE_HEADER_SIZE {
        return Err(KernelError::Invalid(
            "arm64 kernel is shorter than the Linux Image header".to_string(),
        ));
    }
    if bytes.get(ARM64_IMAGE_MAGIC_OFFSET..ARM64_IMAGE_MAGIC_OFFSET + ARM64_IMAGE_MAGIC.len())
        != Some(ARM64_IMAGE_MAGIC)
    {
        return Err(KernelError::Invalid(
            "arm64 kernel is not an uncompressed Linux Image".to_string(),
        ));
    }
    Ok(())
}

fn validate_x86_64_elf(bytes: &[u8]) -> Result<(), KernelError> {
    const ELF_HEADER_SIZE: usize = 64;
    const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const EV_CURRENT: u8 = 1;
    const EM_X86_64: u16 = 62;

    let machine = bytes
        .get(18..20)
        .and_then(|value| <&[u8; 2]>::try_from(value).ok())
        .map(|value| u16::from_le_bytes(*value));
    if bytes.len() < ELF_HEADER_SIZE
        || bytes.get(0..4) != Some(ELF_MAGIC)
        || bytes.get(4) != Some(&ELFCLASS64)
        || bytes.get(5) != Some(&ELFDATA2LSB)
        || bytes.get(6) != Some(&EV_CURRENT)
        || machine != Some(EM_X86_64)
    {
        return Err(KernelError::Invalid(
            "amd64 kernel is not a 64-bit little-endian x86-64 ELF file".to_string(),
        ));
    }
    Ok(())
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
    command.arg(&temporary).arg(reference);
    let result = command::run(command);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(KernelError::Command(error));
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
    let output = command::output(command)?;
    let value = parse_json(&output.stdout, "OCI index descriptor")?;
    descriptor(&value, "OCI index descriptor")
}

fn fetch_manifest(reference: &str) -> Result<Vec<u8>, KernelError> {
    let mut command = Command::new("oras");
    command.args(["manifest", "fetch", reference]);
    let output = command::output(command)?;
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
        media_type: "cached content".to_string(),
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

fn write_provenance(context: &BuildContext<'_>, provenance: &Value) -> Result<(), KernelError> {
    let directory = context
        .target_dir
        .join("kernel-provenance")
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
        0o600,
    )
}

fn read_reference_record(
    path: &Path,
    reference: &str,
    context: &BuildContext<'_>,
) -> Result<Descriptor, KernelError> {
    let fd = match open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => {
            return Err(KernelError::OfflineCacheMiss {
                reference: reference.to_string(),
            });
        }
        Err(source) => {
            return Err(KernelError::Read {
                path: path.to_path_buf(),
                source: std::io::Error::from_raw_os_error(source as i32),
            });
        }
    };
    let mut file = File::from(fd);
    let metadata = file.metadata().map_err(|source| KernelError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(KernelError::UnsafeReferenceRecord {
            path: path.to_path_buf(),
        });
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| KernelError::Read {
            path: path.to_path_buf(),
            source,
        })?;
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
    let media_type = required_string(value, "mediaType", source)?.to_string();
    let digest = required_string(value, "digest", source)?.to_string();
    validate_digest(&digest)?;
    let size = value
        .get("size")
        .and_then(Value::as_u64)
        .filter(|size| *size > 0)
        .ok_or_else(|| KernelError::Invalid(format!("{source} size must be a positive integer")))?;
    Ok(Descriptor {
        media_type,
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

fn require_string_value(
    value: &Value,
    key: &str,
    source: &str,
    expected: &str,
) -> Result<(), KernelError> {
    let actual = required_string(value, key, source)?;
    if actual == expected {
        Ok(())
    } else {
        Err(KernelError::Invalid(format!(
            "{source} {key} must be {expected}, got {actual}"
        )))
    }
}

fn require_u64(value: &Value, key: &str, source: &str, expected: u64) -> Result<(), KernelError> {
    if value.get(key).and_then(Value::as_u64) == Some(expected) {
        Ok(())
    } else {
        Err(KernelError::Invalid(format!(
            "{source} {key} must be {expected}"
        )))
    }
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
