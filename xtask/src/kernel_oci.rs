use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use thiserror::Error;

use crate::release_target::{ReleaseTarget, ReleaseTargetDescriptor};
use crate::stage_runtime::{validate_kernel, StageRuntimeError};

const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const KERNEL_ARTIFACT_TYPE: &str = "application/vnd.silo.kernel.v1";
const KERNEL_CONFIG_MEDIA_TYPE: &str = "application/vnd.silo.kernel.config.v1+json";
const KERNEL_IMAGE_MEDIA_TYPE: &str = "application/vnd.silo.kernel.image.v1";
const KERNEL_KCONFIG_MEDIA_TYPE: &str = "application/vnd.silo.kernel.kconfig.v1";
const KERNEL_SYSTEM_MAP_MEDIA_TYPE: &str = "application/vnd.silo.kernel.system-map.v1";
const KERNEL_DEBUG_MEDIA_TYPE: &str = "application/vnd.silo.kernel.debug.v1+xz";

#[derive(Debug)]
pub(crate) struct ResolveKernelOptions {
    pub(crate) target: ReleaseTarget,
    pub(crate) reference: String,
    pub(crate) oci_layout: Option<PathBuf>,
    pub(crate) output_dir: PathBuf,
}

#[derive(Debug)]
pub(crate) struct ResolvedKernel {
    pub(crate) kernel: PathBuf,
    pub(crate) provenance: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum ResolveKernelError {
    #[error("kernel OCI reference must not be empty")]
    EmptyReference,
    #[error("kernel output directory must be absolute: {path}")]
    RelativeOutput { path: PathBuf },
    #[error("kernel output directory already exists; use a fresh release output: {path}")]
    OutputExists { path: PathBuf },
    #[error("kernel OCI layout must be an absolute real directory: {path}")]
    InvalidLayout { path: PathBuf },
    #[error("invalid kernel OCI {context}: {reason}")]
    InvalidContract {
        context: &'static str,
        reason: String,
    },
    #[error("failed to run ORAS command: {command}")]
    RunOras { command: String, source: io::Error },
    #[error("ORAS command failed ({command}): {stderr}")]
    OrasFailed { command: String, stderr: String },
    #[error("failed to {operation} {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error(transparent)]
    KernelValidation(#[from] StageRuntimeError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    artifact_type: Option<String>,
}

#[derive(Debug)]
struct ResolvedContract {
    index: Descriptor,
    manifest: Descriptor,
    config: Descriptor,
    kernel: Descriptor,
    layers: Vec<Descriptor>,
    config_value: Value,
}

#[derive(Debug)]
enum OciSource {
    Registry {
        reference: String,
        repository: String,
    },
    Layout {
        path: PathBuf,
        reference: String,
    },
}

impl OciSource {
    fn new(options: &ResolveKernelOptions) -> Result<Self, ResolveKernelError> {
        let reference = options.reference.trim();
        if reference.is_empty() {
            return Err(ResolveKernelError::EmptyReference);
        }
        if let Some(path) = &options.oci_layout {
            if !path.is_absolute() || !path.is_dir() || path.is_symlink() {
                return Err(ResolveKernelError::InvalidLayout { path: path.clone() });
            }
            let path = fs::canonicalize(path).map_err(|source| ResolveKernelError::Io {
                operation: "canonicalize OCI layout",
                path: path.clone(),
                source,
            })?;
            return Ok(Self::Layout {
                path,
                reference: reference.to_string(),
            });
        }
        Ok(Self::Registry {
            reference: reference.to_string(),
            repository: repository_from_reference(reference)?,
        })
    }

    fn tagged_target(&self) -> String {
        match self {
            Self::Registry { reference, .. } => reference.clone(),
            Self::Layout { path, reference } => format!("{}:{reference}", path.display()),
        }
    }

    fn digest_target(&self, digest: &str) -> String {
        match self {
            Self::Registry { repository, .. } => format!("{repository}@{digest}"),
            Self::Layout { path, .. } => format!("{}@{digest}", path.display()),
        }
    }

    fn add_layout_flag(&self, command: &mut Command) {
        if matches!(self, Self::Layout { .. }) {
            command.arg("--oci-layout");
        }
    }

    fn display_reference(&self) -> &str {
        match self {
            Self::Registry { reference, .. } | Self::Layout { reference, .. } => reference,
        }
    }
}

pub(crate) fn resolve_kernel(
    options: &ResolveKernelOptions,
) -> Result<ResolvedKernel, ResolveKernelError> {
    if !options.output_dir.is_absolute() {
        return Err(ResolveKernelError::RelativeOutput {
            path: options.output_dir.clone(),
        });
    }
    if fs::symlink_metadata(&options.output_dir).is_ok() {
        return Err(ResolveKernelError::OutputExists {
            path: options.output_dir.clone(),
        });
    }
    let source = OciSource::new(options)?;
    let descriptor = options.target.descriptor();
    let temporary = temporary_directory(&options.output_dir)?;
    fs::create_dir(&temporary).map_err(|source| ResolveKernelError::Io {
        operation: "create temporary kernel directory",
        path: temporary.clone(),
        source,
    })?;
    let result = (|| {
        let contract = resolve_contract(&source, descriptor, &temporary)?;
        verify_layers(&source, &contract.layers, &temporary)?;
        let kernel = temporary.join("kernel-default");
        fetch_blob(&source, &contract.kernel, &kernel)?;
        validate_kernel(&kernel, options.target)?;
        let provenance = temporary.join("kernel-provenance.json");
        write_provenance(&provenance, &source, descriptor, &contract)?;
        install_directory_noreplace(&temporary, &options.output_dir)?;
        Ok(ResolvedKernel {
            kernel: options.output_dir.join("kernel-default"),
            provenance: options.output_dir.join("kernel-provenance.json"),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn resolve_contract(
    source: &OciSource,
    target: ReleaseTargetDescriptor,
    temporary: &Path,
) -> Result<ResolvedContract, ResolveKernelError> {
    let index_descriptor = fetch_manifest_descriptor(source, &source.tagged_target())?;
    require_descriptor(
        &index_descriptor,
        OCI_INDEX_MEDIA_TYPE,
        None,
        "index descriptor",
    )?;
    let index_target = source.digest_target(&index_descriptor.digest);
    let index = fetch_manifest(source, &index_target)?;
    let manifest_descriptor = validate_index(&index, target)?;
    let manifest_target = source.digest_target(&manifest_descriptor.digest);
    let manifest = fetch_manifest(source, &manifest_target)?;
    let (config_descriptor, kernel_descriptor, layers) = validate_manifest(&manifest, target)?;

    let config_path = temporary.join("artifact-config.json");
    fetch_blob(source, &config_descriptor, &config_path)?;
    let config_bytes = fs::read(&config_path).map_err(|source| ResolveKernelError::Io {
        operation: "read kernel artifact config",
        path: config_path.clone(),
        source,
    })?;
    let config_value = serde_json::from_slice(&config_bytes).map_err(|error| {
        ResolveKernelError::InvalidContract {
            context: "artifact config",
            reason: error.to_string(),
        }
    })?;
    validate_config(&config_value, target)?;
    fs::remove_file(&config_path).map_err(|source| ResolveKernelError::Io {
        operation: "remove temporary kernel artifact config",
        path: config_path,
        source,
    })?;

    Ok(ResolvedContract {
        index: index_descriptor,
        manifest: manifest_descriptor,
        config: config_descriptor,
        kernel: kernel_descriptor,
        layers,
        config_value,
    })
}

fn fetch_manifest_descriptor(
    source: &OciSource,
    target: &str,
) -> Result<Descriptor, ResolveKernelError> {
    let mut command = Command::new("oras");
    command.args(["manifest", "fetch", "--descriptor"]);
    source.add_layout_flag(&mut command);
    command.arg(target);
    let output = run_oras(command)?;
    let value: Value =
        serde_json::from_slice(&output).map_err(|error| ResolveKernelError::InvalidContract {
            context: "index descriptor",
            reason: error.to_string(),
        })?;
    descriptor_from_value(&value, "index descriptor")
}

fn fetch_manifest(source: &OciSource, target: &str) -> Result<Value, ResolveKernelError> {
    let mut command = Command::new("oras");
    command.args(["manifest", "fetch"]);
    source.add_layout_flag(&mut command);
    command.arg(target);
    let output = run_oras(command)?;
    serde_json::from_slice(&output).map_err(|error| ResolveKernelError::InvalidContract {
        context: "manifest",
        reason: error.to_string(),
    })
}

fn fetch_blob(
    source: &OciSource,
    descriptor: &Descriptor,
    output: &Path,
) -> Result<(), ResolveKernelError> {
    let mut command = Command::new("oras");
    command.args(["blob", "fetch", "--output"]);
    command.arg(output);
    source.add_layout_flag(&mut command);
    command.arg(source.digest_target(&descriptor.digest));
    run_oras(command)?;
    let actual_size = fs::metadata(output)
        .map_err(|source| ResolveKernelError::Io {
            operation: "inspect fetched OCI blob",
            path: output.to_path_buf(),
            source,
        })?
        .len();
    if actual_size != descriptor.size {
        return invalid(
            "blob descriptor",
            format!(
                "{} declared {} bytes but ORAS wrote {actual_size}",
                descriptor.digest, descriptor.size
            ),
        );
    }
    Ok(())
}

fn verify_layers(
    source: &OciSource,
    layers: &[Descriptor],
    temporary: &Path,
) -> Result<(), ResolveKernelError> {
    for (index, layer) in layers.iter().enumerate() {
        if layer.media_type == KERNEL_IMAGE_MEDIA_TYPE {
            continue;
        }
        let path = temporary.join(format!(".verified-layer-{index}"));
        fetch_blob(source, layer, &path)?;
        fs::remove_file(&path).map_err(|source| ResolveKernelError::Io {
            operation: "remove verified OCI layer",
            path,
            source,
        })?;
    }
    Ok(())
}

fn run_oras(mut command: Command) -> Result<Vec<u8>, ResolveKernelError> {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .map_err(|source| ResolveKernelError::RunOras {
            command: rendered.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(ResolveKernelError::OrasFailed {
            command: rendered,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(output.stdout)
}

fn validate_index(
    value: &Value,
    target: ReleaseTargetDescriptor,
) -> Result<Descriptor, ResolveKernelError> {
    require_u64(value, "schemaVersion", "index")?
        .eq(&2)
        .then_some(())
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "index",
            reason: "schemaVersion must be 2".to_string(),
        })?;
    require_string(value, "mediaType", "index")
        .and_then(|actual| require_equal(actual, OCI_INDEX_MEDIA_TYPE, "index mediaType"))?;
    require_string(value, "artifactType", "index")
        .and_then(|actual| require_equal(actual, KERNEL_ARTIFACT_TYPE, "index artifactType"))?;
    let manifests = value
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "index",
            reason: "manifests must be an array".to_string(),
        })?;
    if manifests.len() != 2 {
        return invalid(
            "index",
            format!(
                "expected amd64 and arm64 manifests, found {}",
                manifests.len()
            ),
        );
    }
    let mut platforms = Vec::new();
    let mut matches = Vec::new();
    for manifest in manifests {
        let platform = manifest.get("platform").and_then(Value::as_object);
        let os = platform
            .and_then(|value| value.get("os"))
            .and_then(Value::as_str);
        let arch = platform
            .and_then(|value| value.get("architecture"))
            .and_then(Value::as_str);
        let (Some(os), Some(arch)) = (os, arch) else {
            return invalid("index", "every manifest must declare a platform");
        };
        if os != "linux" || !matches!(arch, "amd64" | "arm64") {
            return invalid("index", format!("unsupported platform {os}/{arch}"));
        }
        if platforms.contains(&arch) {
            return invalid("index", format!("duplicate linux/{arch} manifest"));
        }
        platforms.push(arch);
        let descriptor = descriptor_from_value(manifest, "platform manifest descriptor")?;
        require_descriptor(
            &descriptor,
            OCI_MANIFEST_MEDIA_TYPE,
            Some(KERNEL_ARTIFACT_TYPE),
            "platform manifest descriptor",
        )?;
        if arch == target.goarch {
            matches.push(descriptor);
        }
    }
    if matches.len() != 1 {
        return invalid(
            "index",
            format!(
                "expected exactly one {} platform manifest, found {}",
                target.oci_platform,
                matches.len()
            ),
        );
    }
    let descriptor = matches.remove(0);
    require_descriptor(
        &descriptor,
        OCI_MANIFEST_MEDIA_TYPE,
        Some(KERNEL_ARTIFACT_TYPE),
        "platform manifest descriptor",
    )?;
    Ok(descriptor)
}

fn validate_manifest(
    value: &Value,
    target: ReleaseTargetDescriptor,
) -> Result<(Descriptor, Descriptor, Vec<Descriptor>), ResolveKernelError> {
    if require_u64(value, "schemaVersion", "platform manifest")? != 2 {
        return invalid("platform manifest", "schemaVersion must be 2");
    }
    require_string(value, "mediaType", "platform manifest").and_then(|actual| {
        require_equal(
            actual,
            OCI_MANIFEST_MEDIA_TYPE,
            "platform manifest mediaType",
        )
    })?;
    require_string(value, "artifactType", "platform manifest").and_then(|actual| {
        require_equal(
            actual,
            KERNEL_ARTIFACT_TYPE,
            "platform manifest artifactType",
        )
    })?;
    let config_value = value
        .get("config")
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "platform manifest",
            reason: "missing config descriptor".to_string(),
        })?;
    let config = descriptor_from_value(config_value, "config descriptor")?;
    require_descriptor(&config, KERNEL_CONFIG_MEDIA_TYPE, None, "config descriptor")?;
    let layers = value
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "platform manifest",
            reason: "layers must be an array".to_string(),
        })?;
    let descriptors = layers
        .iter()
        .map(|value| descriptor_from_value(value, "layer descriptor"))
        .collect::<Result<Vec<_>, _>>()?;
    let allowed = [
        KERNEL_IMAGE_MEDIA_TYPE,
        KERNEL_KCONFIG_MEDIA_TYPE,
        KERNEL_SYSTEM_MAP_MEDIA_TYPE,
        KERNEL_DEBUG_MEDIA_TYPE,
    ];
    if let Some(unexpected) = descriptors
        .iter()
        .find(|descriptor| !allowed.contains(&descriptor.media_type.as_str()))
    {
        return invalid(
            "platform manifest",
            format!("unexpected layer media type {:?}", unexpected.media_type),
        );
    }
    let kernel = exactly_one_layer(&descriptors, KERNEL_IMAGE_MEDIA_TYPE)?;
    exactly_one_layer(&descriptors, KERNEL_KCONFIG_MEDIA_TYPE)?;
    exactly_one_layer(&descriptors, KERNEL_SYSTEM_MAP_MEDIA_TYPE)?;
    let debug_count = descriptors
        .iter()
        .filter(|descriptor| descriptor.media_type == KERNEL_DEBUG_MEDIA_TYPE)
        .count();
    let expected_debug_count = usize::from(target.goarch == "arm64");
    if debug_count != expected_debug_count {
        return invalid(
            "platform manifest",
            format!(
                "expected {expected_debug_count} debug layer(s) for {}, found {debug_count}",
                target.oci_platform
            ),
        );
    }
    Ok((config, kernel, descriptors))
}

fn validate_config(
    value: &Value,
    target: ReleaseTargetDescriptor,
) -> Result<(), ResolveKernelError> {
    if require_u64(value, "schemaVersion", "artifact config")? != 1 {
        return invalid("artifact config", "schemaVersion must be 1");
    }
    require_string(value, "track", "artifact config")
        .and_then(|actual| require_equal(actual, "stable", "kernel track"))?;
    let repository_arch = if target.goarch == "arm64" {
        "arm64"
    } else {
        "x86_64"
    };
    require_string(value, "architecture", "artifact config").and_then(|actual| {
        require_equal(actual, repository_arch, "kernel repository architecture")
    })?;
    let platform = value
        .get("platform")
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "artifact config",
            reason: "missing platform".to_string(),
        })?;
    require_string(platform, "os", "artifact config platform")
        .and_then(|actual| require_equal(actual, "linux", "kernel platform OS"))?;
    require_string(platform, "architecture", "artifact config platform")
        .and_then(|actual| require_equal(actual, target.goarch, "kernel platform architecture"))?;
    let kernel = value
        .get("kernel")
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "artifact config",
            reason: "missing kernel metadata".to_string(),
        })?;
    require_string(kernel, "mediaType", "artifact config kernel")
        .and_then(|actual| require_equal(actual, KERNEL_IMAGE_MEDIA_TYPE, "kernel mediaType"))?;
    let expected_format = if target.goarch == "arm64" {
        "arm64-image"
    } else {
        "elf"
    };
    require_string(kernel, "format", "artifact config kernel")
        .and_then(|actual| require_equal(actual, expected_format, "kernel format"))?;
    let source = value
        .get("source")
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "artifact config",
            reason: "missing source provenance".to_string(),
        })?;
    if require_string(source, "url", "artifact config source")?.is_empty() {
        return invalid("artifact config", "source URL must not be empty");
    }
    require_digest(require_string(source, "digest", "artifact config source")?)?;
    let build = value
        .get("build")
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "artifact config",
            reason: "missing build provenance".to_string(),
        })?;
    for field in ["revision", "created"] {
        if require_string(build, field, "artifact config build")?.is_empty() {
            return invalid(
                "artifact config",
                format!("build {field} must not be empty"),
            );
        }
    }
    Ok(())
}

fn descriptor_from_value(
    value: &Value,
    context: &'static str,
) -> Result<Descriptor, ResolveKernelError> {
    let media_type = require_string(value, "mediaType", context)?.to_string();
    let digest = require_string(value, "digest", context)?.to_string();
    require_digest(&digest)?;
    let size = require_u64(value, "size", context)?;
    if size == 0 {
        return invalid(context, "descriptor size must be positive");
    }
    let artifact_type = value
        .get("artifactType")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(Descriptor {
        media_type,
        digest,
        size,
        artifact_type,
    })
}

fn require_descriptor(
    descriptor: &Descriptor,
    media_type: &str,
    artifact_type: Option<&str>,
    context: &'static str,
) -> Result<(), ResolveKernelError> {
    require_equal(&descriptor.media_type, media_type, context)?;
    if let Some(expected) = artifact_type {
        require_equal(
            descriptor.artifact_type.as_deref().unwrap_or_default(),
            expected,
            context,
        )?;
    }
    Ok(())
}

fn exactly_one_layer(
    descriptors: &[Descriptor],
    media_type: &str,
) -> Result<Descriptor, ResolveKernelError> {
    let matches = descriptors
        .iter()
        .filter(|descriptor| descriptor.media_type == media_type)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return invalid(
            "platform manifest",
            format!(
                "expected exactly one {media_type} layer, found {}",
                matches.len()
            ),
        );
    }
    Ok(matches[0].clone())
}

fn require_string<'a>(
    value: &'a Value,
    field: &str,
    context: &'static str,
) -> Result<&'a str, ResolveKernelError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context,
            reason: format!("{field} must be a string"),
        })
}

fn require_u64(
    value: &Value,
    field: &str,
    context: &'static str,
) -> Result<u64, ResolveKernelError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context,
            reason: format!("{field} must be an unsigned integer"),
        })
}

fn require_equal(
    actual: &str,
    expected: &str,
    context: &'static str,
) -> Result<(), ResolveKernelError> {
    if actual == expected {
        return Ok(());
    }
    invalid(context, format!("expected {expected:?}, found {actual:?}"))
}

fn require_digest(value: &str) -> Result<(), ResolveKernelError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return invalid("descriptor digest", format!("unsupported digest {value:?}"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(
            "descriptor digest",
            format!("invalid SHA-256 digest {value:?}"),
        );
    }
    Ok(())
}

fn write_provenance(
    path: &Path,
    source: &OciSource,
    target: ReleaseTargetDescriptor,
    contract: &ResolvedContract,
) -> Result<(), ResolveKernelError> {
    let value = serde_json::json!({
        "schemaVersion": 1,
        "reference": source.display_reference(),
        "target": target.name,
        "platform": target.oci_platform,
        "index": descriptor_json(&contract.index),
        "manifest": descriptor_json(&contract.manifest),
        "config": descriptor_json(&contract.config),
        "kernelLayer": descriptor_json(&contract.kernel),
        "layers": contract.layers.iter().map(descriptor_json).collect::<Vec<_>>(),
        "kernelMetadata": contract.config_value,
    });
    let mut bytes =
        serde_json::to_vec_pretty(&value).map_err(|error| ResolveKernelError::InvalidContract {
            context: "release provenance",
            reason: error.to_string(),
        })?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|source| ResolveKernelError::Io {
        operation: "write kernel provenance",
        path: path.to_path_buf(),
        source,
    })
}

fn descriptor_json(descriptor: &Descriptor) -> Value {
    serde_json::json!({
        "mediaType": descriptor.media_type,
        "digest": descriptor.digest,
        "size": descriptor.size,
        "artifactType": descriptor.artifact_type,
    })
}

fn repository_from_reference(reference: &str) -> Result<String, ResolveKernelError> {
    let without_digest = reference
        .split_once('@')
        .map_or(reference, |(value, _)| value);
    let last_slash = without_digest.rfind('/');
    let repository = match without_digest.rfind(':') {
        Some(colon) if last_slash.is_none_or(|slash| colon > slash) => &without_digest[..colon],
        _ => without_digest,
    };
    if repository.is_empty() || !repository.contains('/') {
        return invalid(
            "registry reference",
            format!("expected a repository and tag or digest, found {reference:?}"),
        );
    }
    Ok(repository.to_string())
}

fn temporary_directory(destination: &Path) -> Result<PathBuf, ResolveKernelError> {
    let parent = destination
        .parent()
        .ok_or_else(|| ResolveKernelError::InvalidContract {
            context: "output directory",
            reason: format!("{} has no parent", destination.display()),
        })?;
    create_directory(parent)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ResolveKernelError::InvalidContract {
            context: "system clock",
            reason: error.to_string(),
        })?
        .as_nanos();
    Ok(parent.join(format!(".kernel-resolve-{}-{nonce}", std::process::id())))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn install_directory_noreplace(
    temporary: &Path,
    destination: &Path,
) -> Result<(), ResolveKernelError> {
    nix::fcntl::renameat2(
        nix::fcntl::AT_FDCWD,
        temporary,
        nix::fcntl::AT_FDCWD,
        destination,
        nix::fcntl::RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|error| ResolveKernelError::Io {
        operation: "install resolved kernel without replacing an existing output",
        path: destination.to_path_buf(),
        source: io::Error::from_raw_os_error(error as i32),
    })
}

#[cfg(target_os = "macos")]
fn install_directory_noreplace(
    temporary: &Path,
    destination: &Path,
) -> Result<(), ResolveKernelError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    const RENAME_EXCL: u32 = 0x0000_0004;

    // nix has no wrapper for Apple's renamex_np, which is the only native
    // no-replace directory rename available on supported macOS hosts.
    unsafe extern "C" {
        fn renamex_np(
            from: *const std::ffi::c_char,
            to: *const std::ffi::c_char,
            flags: u32,
        ) -> std::ffi::c_int;
    }

    let from = CString::new(temporary.as_os_str().as_bytes()).map_err(|error| {
        ResolveKernelError::InvalidContract {
            context: "temporary output path",
            reason: error.to_string(),
        }
    })?;
    let to = CString::new(destination.as_os_str().as_bytes()).map_err(|error| {
        ResolveKernelError::InvalidContract {
            context: "kernel output path",
            reason: error.to_string(),
        }
    })?;
    let result = unsafe { renamex_np(from.as_ptr(), to.as_ptr(), RENAME_EXCL) };
    if result == 0 {
        return Ok(());
    }
    Err(ResolveKernelError::Io {
        operation: "install resolved kernel without replacing an existing output",
        path: destination.to_path_buf(),
        source: io::Error::last_os_error(),
    })
}

fn create_directory(path: &Path) -> Result<(), ResolveKernelError> {
    fs::create_dir_all(path).map_err(|source| ResolveKernelError::Io {
        operation: "create directory",
        path: path.to_path_buf(),
        source,
    })
}

fn invalid<T>(context: &'static str, reason: impl Into<String>) -> Result<T, ResolveKernelError> {
    Err(ResolveKernelError::InvalidContract {
        context,
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use serde_json::{json, Value};

    use crate::kernel_oci::{
        repository_from_reference, resolve_kernel, validate_config, validate_index,
        validate_manifest, ResolveKernelOptions, KERNEL_ARTIFACT_TYPE, KERNEL_CONFIG_MEDIA_TYPE,
        KERNEL_DEBUG_MEDIA_TYPE, KERNEL_IMAGE_MEDIA_TYPE, KERNEL_KCONFIG_MEDIA_TYPE,
        KERNEL_SYSTEM_MAP_MEDIA_TYPE, OCI_INDEX_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE,
    };
    use crate::release_target::ReleaseTarget;

    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const DIGEST_D: &str =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn descriptor(media_type: &str, digest: &str) -> Value {
        json!({"mediaType": media_type, "digest": digest, "size": 123})
    }

    fn index() -> Value {
        json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "artifactType": KERNEL_ARTIFACT_TYPE,
            "manifests": [
                {
                    "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                    "digest": DIGEST_A,
                    "size": 123,
                    "artifactType": KERNEL_ARTIFACT_TYPE,
                    "platform": {"os": "linux", "architecture": "amd64"}
                },
                {
                    "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                    "digest": DIGEST_B,
                    "size": 123,
                    "artifactType": KERNEL_ARTIFACT_TYPE,
                    "platform": {"os": "linux", "architecture": "arm64"}
                }
            ]
        })
    }

    fn manifest(arm64: bool) -> Value {
        let mut layers = vec![
            descriptor(KERNEL_IMAGE_MEDIA_TYPE, DIGEST_B),
            descriptor(KERNEL_KCONFIG_MEDIA_TYPE, DIGEST_C),
            descriptor(KERNEL_SYSTEM_MAP_MEDIA_TYPE, DIGEST_D),
        ];
        if arm64 {
            layers.push(descriptor(KERNEL_DEBUG_MEDIA_TYPE, DIGEST_A));
        }
        json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "artifactType": KERNEL_ARTIFACT_TYPE,
            "config": descriptor(KERNEL_CONFIG_MEDIA_TYPE, DIGEST_A),
            "layers": layers
        })
    }

    fn config(arm64: bool) -> Value {
        json!({
            "schemaVersion": 1,
            "track": "stable",
            "kernelVersion": "7.1.3",
            "architecture": if arm64 { "arm64" } else { "x86_64" },
            "platform": {
                "os": "linux",
                "architecture": if arm64 { "arm64" } else { "amd64" }
            },
            "kernel": {
                "mediaType": KERNEL_IMAGE_MEDIA_TYPE,
                "format": if arm64 { "arm64-image" } else { "elf" }
            },
            "source": {"url": "https://kernel.example/source.tar.xz", "digest": DIGEST_D},
            "build": {"revision": "abc123", "created": "2026-07-24T00:00:00Z"}
        })
    }

    #[test]
    fn validates_each_release_platform_contract() {
        for (target, digest, arm64) in [
            (ReleaseTarget::DarwinArm64, DIGEST_B, true),
            (ReleaseTarget::LinuxArm64Gnu, DIGEST_B, true),
            (ReleaseTarget::LinuxAmd64Gnu, DIGEST_A, false),
        ] {
            let descriptor = validate_index(&index(), target.descriptor()).expect("index");
            assert_eq!(descriptor.digest, digest);
            validate_manifest(&manifest(arm64), target.descriptor()).expect("manifest");
            validate_config(&config(arm64), target.descriptor()).expect("config");
        }
    }

    #[test]
    fn rejects_duplicate_platform_and_kernel_layers() {
        let mut duplicate_platform = index();
        let platform_manifest = duplicate_platform["manifests"][0].clone();
        duplicate_platform["manifests"]
            .as_array_mut()
            .expect("manifests")
            .push(platform_manifest);
        assert!(validate_index(
            &duplicate_platform,
            ReleaseTarget::LinuxAmd64Gnu.descriptor()
        )
        .is_err());

        let mut duplicate_kernel = manifest(false);
        duplicate_kernel["layers"]
            .as_array_mut()
            .expect("layers")
            .push(descriptor(KERNEL_IMAGE_MEDIA_TYPE, DIGEST_D));
        assert!(
            validate_manifest(&duplicate_kernel, ReleaseTarget::LinuxAmd64Gnu.descriptor())
                .is_err()
        );
    }

    #[test]
    fn rejects_wrong_config_platform_media_type_and_source_digest() {
        let mut wrong = config(false);
        wrong["platform"]["architecture"] = json!("arm64");
        assert!(validate_config(&wrong, ReleaseTarget::LinuxAmd64Gnu.descriptor()).is_err());

        let mut wrong = config(false);
        wrong["kernel"]["mediaType"] = json!("application/octet-stream");
        assert!(validate_config(&wrong, ReleaseTarget::LinuxAmd64Gnu.descriptor()).is_err());

        let mut wrong = config(false);
        wrong["source"]["digest"] = json!("sha256:not-a-digest");
        assert!(validate_config(&wrong, ReleaseTarget::LinuxAmd64Gnu.descriptor()).is_err());
    }

    #[test]
    fn registry_repository_parsing_handles_ports_tags_and_digests() {
        assert_eq!(
            repository_from_reference("ghcr.io/example/silo/kernel:stable").expect("tag"),
            "ghcr.io/example/silo/kernel"
        );
        assert_eq!(
            repository_from_reference(&format!("localhost:5000/silo/kernel@{DIGEST_A}"))
                .expect("digest"),
            "localhost:5000/silo/kernel"
        );
        assert!(repository_from_reference("kernel:stable").is_err());
    }

    #[test]
    fn resolves_and_verifies_a_local_oci_layout() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let layout = temp.path().join("layout");
        push_platform(temp.path(), &layout, "amd64", false);
        push_platform(temp.path(), &layout, "arm64", true);
        push_index(&layout, temp.path());
        let output = temp.path().join("resolved");

        let resolved = resolve_kernel(&ResolveKernelOptions {
            target: ReleaseTarget::DarwinArm64,
            reference: "stable".to_string(),
            oci_layout: Some(layout),
            output_dir: output.clone(),
        })
        .expect("resolve local OCI kernel");

        assert_eq!(resolved.kernel, output.join("kernel-default"));
        assert_eq!(resolved.provenance, output.join("kernel-provenance.json"));
        let mut entries = fs::read_dir(&output)
            .expect("read output")
            .map(|entry| entry.expect("output entry").file_name())
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(
            entries,
            ["kernel-default", "kernel-provenance.json"].map(std::ffi::OsString::from)
        );
        let provenance: Value =
            serde_json::from_slice(&fs::read(resolved.provenance).expect("read kernel provenance"))
                .expect("parse kernel provenance");
        assert_eq!(provenance["platform"], "linux/arm64");
        assert_eq!(
            provenance["layers"]
                .as_array()
                .expect("layer descriptors")
                .len(),
            4
        );

        let error = resolve_kernel(&ResolveKernelOptions {
            target: ReleaseTarget::DarwinArm64,
            reference: "stable".to_string(),
            oci_layout: None,
            output_dir: output.clone(),
        })
        .expect_err("existing output must not be replaced");
        assert!(error.to_string().contains("already exists"));
    }

    fn push_platform(root: &Path, layout: &Path, tag: &str, arm64: bool) {
        let package = root.join(format!("package-{tag}"));
        fs::create_dir(&package).expect("create package directory");
        let kernel = if arm64 {
            let mut bytes = vec![0_u8; 64];
            bytes[16..24].copy_from_slice(&64_u64.to_le_bytes());
            bytes[56..60].copy_from_slice(b"ARM\x64");
            bytes
        } else {
            executable_elf(62)
        };
        fs::write(package.join("kernel"), kernel).expect("write kernel");
        fs::write(package.join(".config"), b"CONFIG_SILO=y\n").expect("write kconfig");
        fs::write(package.join("System.map"), b"00000000 T start\n").expect("write map");
        if arm64 {
            fs::write(package.join("vmlinux.xz"), b"debug").expect("write debug layer");
        }
        fs::write(
            package.join("artifact-config.json"),
            serde_json::to_vec(&config(arm64)).expect("encode artifact config"),
        )
        .expect("write artifact config");

        let mut command = Command::new("oras");
        command
            .current_dir(&package)
            .args(["push", "--oci-layout"])
            .arg(format!("{}:{tag}", layout.display()))
            .args(["--artifact-type", KERNEL_ARTIFACT_TYPE, "--config"])
            .arg(format!("artifact-config.json:{KERNEL_CONFIG_MEDIA_TYPE}"))
            .arg(format!("kernel:{KERNEL_IMAGE_MEDIA_TYPE}"))
            .arg(format!(".config:{KERNEL_KCONFIG_MEDIA_TYPE}"))
            .arg(format!("System.map:{KERNEL_SYSTEM_MAP_MEDIA_TYPE}"));
        if arm64 {
            command.arg(format!("vmlinux.xz:{KERNEL_DEBUG_MEDIA_TYPE}"));
        }
        run_fixture_command(command, "push platform manifest");
    }

    fn push_index(layout: &Path, root: &Path) {
        let manifests = [("amd64", "amd64"), ("arm64", "arm64")].map(|(tag, architecture)| {
            let mut command = Command::new("oras");
            command
                .args(["manifest", "fetch", "--descriptor", "--oci-layout"])
                .arg(format!("{}:{tag}", layout.display()));
            let output = command.output().expect("fetch platform descriptor");
            assert!(
                output.status.success(),
                "fetch platform descriptor: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut descriptor: Value =
                serde_json::from_slice(&output.stdout).expect("parse platform descriptor");
            descriptor["artifactType"] = json!(KERNEL_ARTIFACT_TYPE);
            descriptor["platform"] = json!({"os": "linux", "architecture": architecture});
            descriptor
        });
        let index = json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "artifactType": KERNEL_ARTIFACT_TYPE,
            "manifests": manifests
        });
        let index_path = root.join("kernel-index.json");
        fs::write(
            &index_path,
            serde_json::to_vec(&index).expect("encode index"),
        )
        .expect("write index");
        let mut command = Command::new("oras");
        command
            .args(["manifest", "push", "--oci-layout"])
            .arg(format!("{}:stable", layout.display()))
            .arg(index_path);
        run_fixture_command(command, "push index");
    }

    fn run_fixture_command(mut command: Command, context: &str) {
        let output = command.output().unwrap_or_else(|error| {
            panic!("{context}: failed to run ORAS: {error}");
        });
        assert!(
            output.status.success(),
            "{context}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn executable_elf(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 120];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[96..104].copy_from_slice(&120_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&120_u64.to_le_bytes());
        bytes
    }
}
