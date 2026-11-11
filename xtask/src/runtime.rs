use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::components::BuildContext;
use crate::initramfs::{write_initramfs, InitramfsOptions};
use crate::kernel::KernelArtifact;
use crate::rprobe::ASSETS as RPROBE_ASSETS;

const HELPERS: [(&str, u32); 2] = [("silo-vmm", 0o755), ("netd", 0o755)];
const ASSETS: [(&str, u32); 3] = [
    ("kernel-default", 0o644),
    ("initramfs", 0o644),
    ("agent", 0o755),
];
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Initramfs(#[from] crate::initramfs::InitramfsError),
    #[error("failed to create directory {path}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read metadata for {path}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to copy {from} to {to}")]
    Copy {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set mode on {path}")]
    SetMode {
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
    #[error("failed to atomically exchange {temporary} and {final_path}")]
    Exchange {
        temporary: PathBuf,
        final_path: PathBuf,
        #[source]
        source: rustix::io::Errno,
    },
    #[error("failed to remove temporary directory {path}")]
    RemoveTemporaryDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("installed {final_path}, but failed to remove the prior runtime at {previous}")]
    InstalledButCleanupFailed {
        final_path: PathBuf,
        previous: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid runtime layout: {0}")]
    Invalid(String),
    #[error(transparent)]
    Archive(#[from] crate::archive::ArchiveError),
    #[error(transparent)]
    Command(#[from] crate::command::CommandError),
    #[error(transparent)]
    Release(#[from] crate::release::ReleaseError),
}

pub fn assemble_development(
    context: &BuildContext<'_>,
    kernel: &KernelArtifact,
    rprobe: Option<&Path>,
) -> Result<(), RuntimeError> {
    let profile_dir = context.target_dir.join(context.profile.directory());
    validate_directory(&profile_dir)?;
    let assets = profile_dir.join("assets");
    let temporary = create_sibling_directory(&assets, "assets")?;
    let result = (|| {
        copy_regular_file(&kernel.path, &temporary.join("kernel-default"), 0o644)?;
        let init = guest_binary(context, "init");
        write_initramfs(&InitramfsOptions::new(init, temporary.join("initramfs")))?;
        set_mode(&temporary.join("initramfs"), 0o644)?;
        package_guest_agent(&guest_binary(context, "agent"), &temporary.join("agent"))?;
        if let Some(rprobe) = rprobe {
            copy_regular_file(rprobe, &temporary.join("rprobe"), 0o644)?;
        } else {
            copy_optional_rprobe_assets(&assets, &temporary)?;
        }
        validate_assets(&temporary)?;
        if assets_match(&temporary, &assets)? {
            fs::remove_dir_all(&temporary).map_err(|source| {
                RuntimeError::RemoveTemporaryDirectory {
                    path: temporary.clone(),
                    source,
                }
            })?;
            println!("runtime assets unchanged: {}", assets.display());
        } else {
            replace_directory(&temporary, &assets)?;
        }
        validate_adjacent(context)
    })();
    if result.is_err()
        && !matches!(&result, Err(RuntimeError::InstalledButCleanupFailed { .. }))
        && temporary.exists()
    {
        fs::remove_dir_all(&temporary).map_err(|source| {
            RuntimeError::RemoveTemporaryDirectory {
                path: temporary,
                source,
            }
        })?;
    }
    result
}

pub fn stage(context: &BuildContext<'_>) -> Result<(), RuntimeError> {
    validate_adjacent(context)?;
    let profile_dir = context.target_dir.join(context.profile.directory());
    let stage = context
        .target_dir
        .join("silo-runtime")
        .join(context.host.runtime_target())
        .join(context.profile.directory());
    let parent = stage.parent().ok_or_else(|| {
        RuntimeError::Invalid(format!("stage path has no parent: {}", stage.display()))
    })?;
    create_directory(parent)?;
    match validate_stage_against_adjacent(context, &stage) {
        Ok(()) => {
            println!("runtime stage unchanged: {}", stage.display());
            return Ok(());
        }
        Err(RuntimeError::Invalid(_)) => {}
        Err(RuntimeError::Metadata { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = create_sibling_directory(&stage, "stage")?;
    let result = (|| {
        let bin = temporary.join("bin");
        let assets = temporary.join("assets");
        create_directory(&bin)?;
        create_directory(&assets)?;
        for (name, mode) in HELPERS {
            copy_regular_file(&profile_dir.join(name), &bin.join(name), mode)?;
        }
        for (name, mode) in ASSETS {
            copy_regular_file(
                &profile_dir.join("assets").join(name),
                &assets.join(name),
                mode,
            )?;
        }
        if has_rprobe_assets(&profile_dir.join("assets"))? {
            for (name, mode) in RPROBE_ASSETS {
                copy_regular_file(
                    &profile_dir.join("assets").join(name),
                    &assets.join(name),
                    mode,
                )?;
            }
        }
        create_directory(&temporary.join("LICENSES"))?;
        let notices = temporary.join("THIRD_PARTY_NOTICES");
        fs::write(&notices, release_notices(context.workspace_root)?).map_err(|source| {
            RuntimeError::Metadata {
                path: notices.clone(),
                source,
            }
        })?;
        set_mode(&notices, 0o644)?;
        copy_regular_file(
            &context
                .workspace_root
                .join("common/disk-image/LICENSE-APACHE"),
            &temporary.join("LICENSES/APACHE-2.0.txt"),
            0o644,
        )?;
        write_manifest(context, &temporary)?;
        validate_stage_against_adjacent(context, &temporary)?;
        replace_directory(&temporary, &stage)?;
        validate_stage_against_adjacent(context, &stage)
    })();
    if result.is_err()
        && !matches!(&result, Err(RuntimeError::InstalledButCleanupFailed { .. }))
        && temporary.exists()
    {
        fs::remove_dir_all(&temporary).map_err(|source| {
            RuntimeError::RemoveTemporaryDirectory {
                path: temporary,
                source,
            }
        })?;
    }
    result
}

fn guest_binary(context: &BuildContext<'_>, name: &str) -> PathBuf {
    let binary = match name {
        "agent" => "silo-agent",
        name => name,
    };
    context
        .target_dir
        .join(context.host.guest_target().triple())
        .join(context.profile.directory())
        .join(binary)
}

fn validate_adjacent(context: &BuildContext<'_>) -> Result<(), RuntimeError> {
    let profile_dir = context.target_dir.join(context.profile.directory());
    validate_regular_file(&profile_dir.join("silo"), true, None)?;
    for (name, _) in HELPERS {
        validate_regular_file(&profile_dir.join(name), true, None)?;
    }
    validate_assets(&profile_dir.join("assets"))
}

fn validate_assets(assets: &Path) -> Result<(), RuntimeError> {
    validate_directory(assets)?;
    for (name, mode) in ASSETS {
        validate_regular_file(&assets.join(name), name == "agent", Some(mode))?;
    }
    if has_rprobe_assets(assets)? {
        for (name, mode) in RPROBE_ASSETS {
            validate_regular_file(&assets.join(name), false, Some(mode))?;
        }
    }
    Ok(())
}

fn validate_stage(stage: &Path) -> Result<(), RuntimeError> {
    validate_directory(stage)?;
    let expected_root = BTreeSet::from([
        "assets",
        "bin",
        "runtime-manifest.json",
        "THIRD_PARTY_NOTICES",
        "LICENSES",
    ]);
    validate_directory_entries(stage, &expected_root)?;
    validate_regular_file(&stage.join("runtime-manifest.json"), false, Some(0o644))?;
    validate_regular_file(&stage.join("THIRD_PARTY_NOTICES"), false, Some(0o644))?;
    validate_directory_entries(&stage.join("LICENSES"), &BTreeSet::from(["APACHE-2.0.txt"]))?;
    validate_regular_file(&stage.join("LICENSES/APACHE-2.0.txt"), false, Some(0o644))?;
    let bin = stage.join("bin");
    let assets = stage.join("assets");
    validate_directory_entries(&bin, &BTreeSet::from(["netd", "silo-vmm"]))?;
    let mut expected_assets = BTreeSet::from(["agent", "initramfs", "kernel-default"]);
    if has_rprobe_assets(&assets)? {
        expected_assets.extend(RPROBE_ASSETS.map(|(name, _)| name));
    }
    validate_directory_entries(&assets, &expected_assets)?;
    for (name, mode) in HELPERS {
        validate_regular_file(&bin.join(name), true, Some(mode))?;
    }
    validate_assets(&assets)
}

fn assets_match(source: &Path, destination: &Path) -> Result<bool, RuntimeError> {
    let source_has_rprobe = has_rprobe_assets(source)?;
    let mut expected = vec!["agent", "initramfs", "kernel-default"];
    if source_has_rprobe {
        expected.extend(RPROBE_ASSETS.map(|(name, _)| name));
    }
    if !directory_entries_match(destination, &expected)? {
        return Ok(false);
    }
    for (name, mode) in ASSETS {
        if !regular_files_match(
            &source.join(name),
            &destination.join(name),
            name == "agent",
            mode,
        )? {
            return Ok(false);
        }
    }
    if source_has_rprobe {
        for (name, mode) in RPROBE_ASSETS {
            if !regular_files_match(&source.join(name), &destination.join(name), false, mode)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub fn validate_stage_against_adjacent(
    context: &BuildContext<'_>,
    stage: &Path,
) -> Result<(), RuntimeError> {
    validate_stage(stage)?;
    let notices_path = stage.join("THIRD_PARTY_NOTICES");
    let notices = fs::read(&notices_path).map_err(|source| RuntimeError::Metadata {
        path: notices_path,
        source,
    })?;
    if notices != release_notices(context.workspace_root)? {
        return Err(RuntimeError::Invalid(
            "runtime notices do not match the packaged license notices".into(),
        ));
    }
    compare_regular_files(
        &context
            .workspace_root
            .join("common/disk-image/LICENSE-APACHE"),
        &stage.join("LICENSES/APACHE-2.0.txt"),
        0o644,
    )?;
    let manifest =
        fs::read(stage.join("runtime-manifest.json")).map_err(|source| RuntimeError::Metadata {
            path: stage.join("runtime-manifest.json"),
            source,
        })?;
    if manifest != manifest_bytes(context, stage)? {
        return Err(RuntimeError::Invalid(
            "runtime manifest differs from current version, target or component digests".into(),
        ));
    }
    let profile = context.target_dir.join(context.profile.directory());
    for (name, mode) in HELPERS {
        compare_regular_files(&profile.join(name), &stage.join("bin").join(name), mode)?;
    }
    for (name, mode) in ASSETS {
        compare_regular_files(
            &profile.join("assets").join(name),
            &stage.join("assets").join(name),
            mode,
        )?;
    }
    if has_rprobe_assets(&profile.join("assets"))? {
        for (name, mode) in RPROBE_ASSETS {
            compare_regular_files(
                &profile.join("assets").join(name),
                &stage.join("assets").join(name),
                mode,
            )?;
        }
    }
    Ok(())
}

fn release_notices(workspace: &Path) -> Result<Vec<u8>, RuntimeError> {
    let path = workspace.join("packaging/release/THIRD_PARTY_NOTICES");
    fs::read(&path).map_err(|source| RuntimeError::Metadata { path, source })
}

fn manifest_bytes(context: &BuildContext<'_>, stage: &Path) -> Result<Vec<u8>, RuntimeError> {
    let version = fs::read_to_string(context.workspace_root.join("VERSION")).map_err(|source| {
        RuntimeError::Metadata {
            path: context.workspace_root.join("VERSION"),
            source,
        }
    })?;
    if !crate::version::is_semver(version.trim()) {
        return Err(RuntimeError::Invalid(
            "VERSION must contain exactly three numeric components".into(),
        ));
    }
    let mut files = std::collections::BTreeMap::new();
    for directory in ["bin", "assets"] {
        let path = stage.join(directory);
        for entry in fs::read_dir(&path).map_err(|source| RuntimeError::Metadata {
            path: path.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| RuntimeError::Metadata {
                path: path.clone(),
                source,
            })?;
            validate_regular_file(&entry.path(), false, None)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| RuntimeError::Invalid("non UTF-8 component name".into()))?;
            files.insert(
                format!("{directory}/{name}"),
                crate::archive::sha256(&entry.path())?,
            );
        }
    }
    for name in ["THIRD_PARTY_NOTICES", "LICENSES/APACHE-2.0.txt"] {
        validate_regular_file(&stage.join(name), false, None)?;
        files.insert(name.into(), crate::archive::sha256(&stage.join(name))?);
    }
    let candidate = candidate_boot_metadata(context, &files)?;
    serde_json::to_vec_pretty(&serde_json::json!({
        "version": version.trim(),
        "target": context.host.runtime_target(),
        "files": files,
        "managedOverlayCandidate": candidate,
    }))
    .map_err(|error| RuntimeError::Invalid(error.to_string()))
}

fn candidate_boot_metadata(
    context: &BuildContext<'_>,
    files: &std::collections::BTreeMap<String, String>,
) -> Result<serde_json::Value, RuntimeError> {
    let provenance_path = context
        .target_dir
        .join("kernel-provenance")
        .join(context.host.runtime_target())
        .join(format!("{}.json", context.profile.directory()));
    let provenance: serde_json::Value = match fs::read(&provenance_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
            RuntimeError::Invalid(format!(
                "invalid kernel provenance {}: {error}",
                provenance_path.display()
            ))
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::Value::Null,
        Err(source) => {
            return Err(RuntimeError::Metadata {
                path: provenance_path,
                source,
            })
        }
    };
    let kernel_digest = files
        .get("assets/kernel-default")
        .map(|hex| format!("sha256:{hex}"));
    let initramfs_digest = files
        .get("assets/initramfs")
        .map(|hex| format!("sha256:{hex}"));
    let native_digest = files.get("bin/silo-vmm").map(|hex| format!("sha256:{hex}"));
    let artifact = provenance.get("artifactConfig").filter(|config| {
        kernel_digest
            .as_deref()
            .is_some_and(|digest| config["kernel"]["digest"].as_str() == Some(digest))
    });
    // Missing local-build config provenance remains unavailable; a source
    // fragment hash or host uname cannot stand in for the build-time gate.
    Ok(serde_json::json!({
        "qualification": "kernel-config-build-gate",
        "guestArchitecture": context.host.oci_architecture(),
        "rootProfile": "linux-erofs-overlay-v1",
        "upperProfile": "silo-upper-ext4-v1",
        "overlayProfile": "silo-overlay-v1",
        "renderingAbi": "linux-overlayfs-mountinfo-v1",
        "attachmentFamily": "krun-virtio-blk-v1",
        "kernelDigest": kernel_digest,
        "baseInitramfsDigest": initramfs_digest,
        "nativeExecutableDigest": native_digest,
        "kernelArtifact": artifact,
        "configEvidence": if artifact.is_some() {
            "authenticated-oci-resolved-config"
        } else {
            "unavailable-requires-actual-build-evidence"
        },
    }))
}

fn write_manifest(context: &BuildContext<'_>, stage: &Path) -> Result<(), RuntimeError> {
    let path = stage.join("runtime-manifest.json");
    fs::write(&path, manifest_bytes(context, stage)?).map_err(|source| RuntimeError::Metadata {
        path: path.clone(),
        source,
    })?;
    set_mode(&path, 0o644)
}

fn copy_optional_rprobe_assets(source: &Path, destination: &Path) -> Result<(), RuntimeError> {
    if has_rprobe_assets(source)? {
        for (name, mode) in RPROBE_ASSETS {
            copy_regular_file(&source.join(name), &destination.join(name), mode)?;
        }
    }
    Ok(())
}

fn has_rprobe_assets(assets: &Path) -> Result<bool, RuntimeError> {
    crate::rprobe::installed_asset_set_present(assets).map_err(|source| RuntimeError::Metadata {
        path: assets.to_path_buf(),
        source,
    })
}

fn compare_regular_files(source: &Path, destination: &Path, mode: u32) -> Result<(), RuntimeError> {
    if regular_files_match(source, destination, mode & 0o111 != 0, mode)? {
        return Ok(());
    }
    Err(RuntimeError::Invalid(format!(
        "{} does not match {} byte-for-byte",
        destination.display(),
        source.display()
    )))
}

fn regular_files_match(
    source: &Path,
    destination: &Path,
    executable: bool,
    mode: u32,
) -> Result<bool, RuntimeError> {
    validate_regular_file(source, executable, Some(mode))?;
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(RuntimeError::Metadata {
                path: destination.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o777 != mode {
            return Ok(false);
        }
    }
    let source_bytes = fs::read(source).map_err(|source_error| RuntimeError::Metadata {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    let destination_bytes =
        fs::read(destination).map_err(|source_error| RuntimeError::Metadata {
            path: destination.to_path_buf(),
            source: source_error,
        })?;
    Ok(source_bytes == destination_bytes)
}

fn directory_entries_match(directory: &Path, expected: &[&str]) -> Result<bool, RuntimeError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(RuntimeError::Metadata {
                path: directory.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(false);
    }
    let entries = fs::read_dir(directory).map_err(|source| RuntimeError::Metadata {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut actual = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| RuntimeError::Metadata {
            path: directory.to_path_buf(),
            source,
        })?;
        actual.insert(entry.file_name());
    }
    Ok(actual == expected.iter().map(std::ffi::OsString::from).collect())
}

fn validate_directory_entries(
    directory: &Path,
    expected: &BTreeSet<&str>,
) -> Result<(), RuntimeError> {
    validate_directory(directory)?;
    let entries = fs::read_dir(directory).map_err(|source| RuntimeError::Metadata {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut actual = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| RuntimeError::Metadata {
            path: directory.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        actual.insert(name.into_owned());
    }
    let expected = expected.iter().map(|name| (*name).to_string()).collect();
    if actual != expected {
        return Err(RuntimeError::Invalid(format!(
            "{} contains {:?}, expected {:?}",
            directory.display(),
            actual,
            expected
        )));
    }
    Ok(())
}

/// Package only the guest payload, retaining the original Cargo artifact and
/// its DWARF outside the VM. Large debug sections are not runtime agent data:
/// carrying them in initramfs can exhaust the kernel's initial tmpfs budget.
fn package_guest_agent(source: &Path, destination: &Path) -> Result<(), RuntimeError> {
    validate_regular_file(source, true, None)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(RuntimeError::Invalid(format!(
                "guest agent destination already exists: {}",
                destination.display()
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RuntimeError::Metadata {
                path: destination.to_path_buf(),
                source,
            })
        }
    }
    // llvm-tools is already a declared Rust toolchain component. Its ELF tools
    // are host executables supporting both guest architectures, but rustup/Nix
    // do not place them on PATH. Resolve the active compiler's toolchain rather
    // than a native-only system objcopy or an incomplete Zig subcommand.
    let rustc = crate::release::tool("rustc")?;
    let library_directory = crate::release::tool_output(&rustc, &["--print", "target-libdir"])?;
    let tool = Path::new(&library_directory)
        .parent()
        .filter(|directory| directory.is_absolute())
        .ok_or_else(|| {
            RuntimeError::Invalid("rustc returned an invalid host target-libdir".into())
        })?
        .join("bin/llvm-objcopy");
    let tool =
        fs::canonicalize(&tool).map_err(|source| RuntimeError::Metadata { path: tool, source })?;
    validate_regular_file(&tool, true, None)?;
    let mut strip = std::process::Command::new(tool);
    strip.arg("--strip-debug").arg(source).arg(destination);
    crate::command::run(strip)?;
    set_mode(destination, 0o755)?;
    validate_regular_file(destination, true, Some(0o755))
}

fn copy_regular_file(source: &Path, destination: &Path, mode: u32) -> Result<(), RuntimeError> {
    validate_regular_file(source, mode & 0o111 != 0, None)?;
    fs::copy(source, destination).map_err(|error| RuntimeError::Copy {
        from: source.to_path_buf(),
        to: destination.to_path_buf(),
        source: error,
    })?;
    set_mode(destination, mode)?;
    validate_regular_file(destination, mode & 0o111 != 0, Some(mode))
}

fn create_sibling_directory(path: &Path, purpose: &str) -> Result<PathBuf, RuntimeError> {
    let parent = path
        .parent()
        .ok_or_else(|| RuntimeError::Invalid(format!("path has no parent: {}", path.display())))?;
    create_directory(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RuntimeError::Invalid(format!("invalid path name: {}", path.display())))?;
    for attempt in 0..128 {
        let temporary = parent.join(format!(
            ".{name}.{purpose}-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&temporary) {
            Ok(()) => return Ok(temporary),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(RuntimeError::CreateDirectory {
                    path: temporary,
                    source,
                });
            }
        }
    }
    Err(RuntimeError::Invalid(format!(
        "could not create a temporary sibling for {}",
        path.display()
    )))
}

fn replace_directory(temporary: &Path, final_path: &Path) -> Result<(), RuntimeError> {
    validate_directory(temporary)?;
    let parent = final_path.parent().ok_or_else(|| {
        RuntimeError::Invalid(format!("path has no parent: {}", final_path.display()))
    })?;
    validate_directory(parent)?;
    let final_exists = match fs::symlink_metadata(final_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RuntimeError::Invalid(format!(
                    "{} is not a real directory",
                    final_path.display()
                )));
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(RuntimeError::Metadata {
                path: final_path.to_path_buf(),
                source,
            });
        }
    };
    if !final_exists {
        return fs::rename(temporary, final_path).map_err(|source| RuntimeError::Rename {
            from: temporary.to_path_buf(),
            to: final_path.to_path_buf(),
            source,
        });
    }
    let temporary_name = temporary.file_name().ok_or_else(|| {
        RuntimeError::Invalid(format!("invalid path name: {}", temporary.display()))
    })?;
    let final_name = final_path.file_name().ok_or_else(|| {
        RuntimeError::Invalid(format!("invalid path name: {}", final_path.display()))
    })?;
    let parent_file = File::open(parent).map_err(|source| RuntimeError::Metadata {
        path: parent.to_path_buf(),
        source,
    })?;
    rustix::fs::renameat_with(
        &parent_file,
        temporary_name,
        &parent_file,
        final_name,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|source| RuntimeError::Exchange {
        temporary: temporary.to_path_buf(),
        final_path: final_path.to_path_buf(),
        source,
    })?;
    fs::remove_dir_all(temporary).map_err(|source| RuntimeError::InstalledButCleanupFailed {
        final_path: final_path.to_path_buf(),
        previous: temporary.to_path_buf(),
        source,
    })
}

fn create_directory(path: &Path) -> Result<(), RuntimeError> {
    fs::create_dir_all(path).map_err(|source| RuntimeError::CreateDirectory {
        path: path.to_path_buf(),
        source,
    })?;
    validate_directory(path)
}

fn validate_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::Invalid(format!(
            "{} is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    executable: bool,
    expected_mode: Option<u32>,
) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RuntimeError::Invalid(format!(
            "{} is not a regular non-symlink file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode() & 0o777;
        if executable && mode & 0o111 == 0 {
            return Err(RuntimeError::Invalid(format!(
                "{} is not executable",
                path.display()
            )));
        }
        if let Some(expected_mode) = expected_mode {
            if mode != expected_mode {
                return Err(RuntimeError::Invalid(format!(
                    "{} has mode {mode:o}, expected {expected_mode:o}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
        RuntimeError::SetMode {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn overlay_candidate_metadata_requires_matching_actual_kernel_provenance() {
        use crate::components::BuildContext;
        use crate::profiles::Profile;
        use crate::targets::HostTarget;
        use std::collections::BTreeMap;

        let root =
            std::env::temp_dir().join(format!("silo-overlay-provenance-{}", std::process::id()));
        let provenance = root.join("kernel-provenance/linux-amd64-gnu");
        std::fs::create_dir_all(&provenance).unwrap();
        let context = BuildContext {
            workspace_root: &root,
            target_dir: &root,
            profile: Profile::Debug,
            host: HostTarget::LinuxX86_64,
        };
        let files = BTreeMap::from([
            ("assets/kernel-default".to_string(), "a".repeat(64)),
            ("assets/initramfs".to_string(), "b".repeat(64)),
            ("bin/silo-vmm".to_string(), "e".repeat(64)),
        ]);
        let artifact = serde_json::json!({
            "kernel": {"digest": format!("sha256:{}", "a".repeat(64))},
            "resolvedConfig": {"digest": format!("sha256:{}", "c".repeat(64))},
        });
        std::fs::write(
            provenance.join("debug.json"),
            serde_json::to_vec(&serde_json::json!({"artifactConfig": artifact})).unwrap(),
        )
        .unwrap();
        let candidate = crate::runtime::candidate_boot_metadata(&context, &files).unwrap();
        assert_eq!(candidate["kernelArtifact"], artifact);
        assert_eq!(
            candidate["configEvidence"],
            "authenticated-oci-resolved-config"
        );
        assert_eq!(candidate["qualification"], "kernel-config-build-gate");
        assert_eq!(
            candidate["nativeExecutableDigest"],
            format!("sha256:{}", "e".repeat(64))
        );
        let mut changed = files;
        changed.insert("assets/kernel-default".to_string(), "d".repeat(64));
        let candidate = crate::runtime::candidate_boot_metadata(&context, &changed).unwrap();
        assert!(candidate["kernelArtifact"].is_null());
        assert_eq!(
            candidate["configEvidence"],
            "unavailable-requires-actual-build-evidence"
        );
        std::fs::write(provenance.join("debug.json"), b"{").unwrap();
        assert!(crate::runtime::candidate_boot_metadata(&context, &changed).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn notices_do_not_observe_native_sources_or_execute_monitor() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir_all(root.join("packaging/release")).unwrap();
        let template = "libkrun\nApache license remains unchanged.\n";
        std::fs::write(root.join("packaging/release/THIRD_PARTY_NOTICES"), template).unwrap();
        assert_eq!(
            crate::runtime::release_notices(root).unwrap(),
            template.as_bytes()
        );
        // Neither Cargo metadata nor a monitor executable is required for notices.
        std::fs::write(root.join("Cargo.toml"), "not Cargo metadata").unwrap();
        assert_eq!(
            crate::runtime::release_notices(root).unwrap(),
            template.as_bytes()
        );
    }
    #[test]
    fn manifest_hashes_current_components_and_rejects_symlinks() {
        use crate::components::BuildContext;
        use crate::profiles::Profile;
        use crate::targets::HostTarget;
        let root = std::env::temp_dir().join(format!("silo-manifest-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("VERSION"), "0.1.0\n").unwrap();
        std::fs::create_dir(root.join("bin")).unwrap();
        std::fs::create_dir(root.join("assets")).unwrap();
        std::fs::create_dir(root.join("LICENSES")).unwrap();
        std::fs::write(root.join("THIRD_PARTY_NOTICES"), b"notices").unwrap();
        std::fs::write(root.join("LICENSES/APACHE-2.0.txt"), b"license").unwrap();
        std::fs::write(root.join("bin/netd"), b"actual netd").unwrap();
        std::fs::write(root.join("bin/silo-vmm"), b"actual monitor and worker").unwrap();
        std::fs::write(root.join("assets/agent"), b"actual agent").unwrap();
        std::fs::write(root.join("assets/kernel-default"), b"actual kernel").unwrap();
        std::fs::write(root.join("assets/initramfs"), b"actual base archive").unwrap();
        let context = BuildContext {
            workspace_root: &root,
            target_dir: &root,
            profile: Profile::Debug,
            host: HostTarget::LinuxX86_64,
        };
        let first = crate::runtime::manifest_bytes(&context, &root).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(manifest["target"], "linux-amd64-gnu");
        assert_eq!(manifest["version"], "0.1.0");
        assert_eq!(
            manifest["managedOverlayCandidate"]["qualification"],
            "kernel-config-build-gate"
        );
        assert_eq!(
            manifest["managedOverlayCandidate"]["configEvidence"],
            "unavailable-requires-actual-build-evidence"
        );
        assert!(manifest["managedOverlayCandidate"]["kernelArtifact"].is_null());
        assert_eq!(
            manifest["managedOverlayCandidate"]["kernelDigest"],
            format!(
                "sha256:{}",
                crate::archive::sha256(&root.join("assets/kernel-default")).unwrap()
            )
        );
        assert_eq!(
            manifest["managedOverlayCandidate"]["nativeExecutableDigest"],
            format!(
                "sha256:{}",
                crate::archive::sha256(&root.join("bin/silo-vmm")).unwrap()
            )
        );
        assert_eq!(
            manifest["files"]["assets/agent"],
            crate::archive::sha256(&root.join("assets/agent")).unwrap()
        );
        std::fs::write(root.join("assets/agent"), b"new agent").unwrap();
        assert_ne!(
            first,
            crate::runtime::manifest_bytes(&context, &root).unwrap()
        );
        std::os::unix::fs::symlink("../VERSION", root.join("assets/escape")).unwrap();
        assert!(crate::runtime::manifest_bytes(&context, &root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn runtime_layout_requires_vmm_and_netd_only() {
        assert_eq!(
            crate::runtime::HELPERS,
            [("silo-vmm", 0o755), ("netd", 0o755)]
        );
    }

    fn elf_section<'a>(elf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
        assert_eq!(&elf[..6], b"\x7fELF\x02\x01");
        let section_offset = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
        let entry_size = u16::from_le_bytes(elf[58..60].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(elf[60..62].try_into().unwrap()) as usize;
        let names_index = u16::from_le_bytes(elf[62..64].try_into().unwrap()) as usize;
        let data = |header: &[u8]| {
            let offset = u64::from_le_bytes(header[24..32].try_into().unwrap()) as usize;
            let size = u64::from_le_bytes(header[32..40].try_into().unwrap()) as usize;
            &elf[offset..offset + size]
        };
        let names_header = section_offset + names_index * entry_size;
        let names = data(&elf[names_header..names_header + entry_size]);
        for index in 0..count {
            let offset = section_offset + index * entry_size;
            let header = &elf[offset..offset + entry_size];
            let name_offset = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
            let section_name = names[name_offset..]
                .split(|byte| *byte == 0)
                .next()
                .unwrap();
            if section_name == name {
                return Some(data(header));
            }
        }
        None
    }

    #[test]
    fn staged_guest_agent_removes_dwarf_without_mutating_debug_artifact_or_loadable_code() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let c_source = temp.path().join("agent.c");
        std::fs::write(
            &c_source,
            b"int main(void) { volatile int value = 23; return value; }\n",
        )
        .unwrap();
        let zig = crate::release::tool("zig").unwrap();
        for target in ["x86_64-linux-musl", "aarch64-linux-musl"] {
            let source = temp.path().join(format!("agent-debug-{target}"));
            let destination = temp.path().join(format!("agent-packaged-{target}"));
            let repeated = temp.path().join(format!("agent-repeated-{target}"));
            let mut build = std::process::Command::new(&zig);
            build
                .args(["cc", "-target", target, "-g", "-O0"])
                .arg(&c_source)
                .arg("-o")
                .arg(&source);
            crate::command::run(build).unwrap();
            let original = std::fs::read(&source).unwrap();
            assert!(elf_section(&original, b".debug_info").is_some());

            crate::runtime::package_guest_agent(&source, &destination).unwrap();
            crate::runtime::package_guest_agent(&source, &repeated).unwrap();
            let packaged = std::fs::read(&destination).unwrap();
            assert_eq!(std::fs::read(&source).unwrap(), original);
            assert!(packaged.len() < original.len());
            assert_eq!(
                &packaged[18..20],
                &original[18..20],
                "guest ELF architecture must remain unchanged"
            );
            assert!(elf_section(&packaged, b".debug_info").is_none());
            assert!(elf_section(&packaged, b".symtab").is_some());
            assert_eq!(
                elf_section(&packaged, b".text"),
                elf_section(&original, b".text")
            );
            assert_eq!(
                elf_section(&packaged, b".eh_frame"),
                elf_section(&original, b".eh_frame")
            );
            assert_eq!(std::fs::read(&repeated).unwrap(), packaged);
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            if cfg!(target_os = "linux") && target.starts_with(std::env::consts::ARCH) {
                let output = std::process::Command::new(&destination).output().unwrap();
                assert_eq!(output.status.code(), Some(23));
            }
        }
    }

    #[test]
    fn staged_guest_agent_refuses_an_existing_output_before_running_packaging() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("unmodified-debug-source");
        let destination = temp.path().join("existing-output");
        std::fs::write(&source, b"source bytes").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&destination, b"retain existing output").unwrap();
        assert!(matches!(
            crate::runtime::package_guest_agent(&source, &destination),
            Err(crate::runtime::RuntimeError::Invalid(_))
        ));
        assert_eq!(std::fs::read(source).unwrap(), b"source bytes");
        assert_eq!(
            std::fs::read(destination).unwrap(),
            b"retain existing output"
        );
    }
}
