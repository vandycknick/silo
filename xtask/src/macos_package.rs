use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::release_target::{BuildProfile, ReleaseTarget};

const APP_IDENTIFIER: &str = "sh.silo.app";
const APP_NAME: &str = "Silo.app";
const FILE_MODE: u32 = 0o644;
const EXECUTABLE_MODE: u32 = 0o755;
const NOTARY_TIMEOUT: &str = "30m";

#[derive(Debug)]
pub(crate) struct PackageMacosOptions {
    pub(crate) build_number: String,
    pub(crate) signing_identity: Option<String>,
    pub(crate) notary_keychain_profile: Option<String>,
    pub(crate) target_dir: PathBuf,
    pub(crate) workspace_root: PathBuf,
}

#[derive(Debug)]
pub(crate) struct PackageMacosResult {
    pub(crate) app: PathBuf,
    pub(crate) dmg: PathBuf,
    pub(crate) metadata: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum MacosPackageError {
    #[error("macOS packages must be built on an arm64 macOS host")]
    UnsupportedHost,
    #[error("invalid CFBundleVersion {value:?}: expected one to three dot-separated integers")]
    InvalidBuildNumber { value: String },
    #[error("{field} must not be empty")]
    EmptyOption { field: &'static str },
    #[error("--notary-keychain-profile requires --signing-identity")]
    NotarizationRequiresIdentity,
    #[error("macOS package output already exists; use a clean target directory: {path}")]
    OutputExists { path: PathBuf },
    #[error("required release input is missing or is not a regular file: {path}")]
    MissingInput { path: PathBuf },
    #[error("invalid release metadata at {path}: {reason}")]
    InvalidReleaseMetadata { path: PathBuf, reason: String },
    #[error("macOS packaging requires a clean source worktree; found {status}")]
    DirtyWorktree { status: String },
    #[error("release staging used source revision {expected}, but the workspace is at {actual}")]
    SourceRevisionMismatch { expected: String, actual: String },
    #[error("invalid app bundle at {path}: {reason}")]
    InvalidBundle { path: PathBuf, reason: String },
    #[error("failed to {operation} {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("failed to run {command}")]
    RunCommand { command: String, source: io::Error },
    #[error("command failed ({command}): {stderr}")]
    CommandFailed { command: String, stderr: String },
    #[error("notarization of {path} was not accepted: {reason}")]
    NotarizationRejected { path: PathBuf, reason: String },
    #[error("failed to encode macOS package metadata: {0}")]
    Metadata(#[from] serde_json::Error),
}

struct TemporaryDirectory {
    path: PathBuf,
}

#[derive(Clone, Copy)]
struct ComponentContract {
    name: &'static str,
    logical_path: &'static str,
    bundle_path: &'static str,
    mode: u32,
}

struct ValidatedComponent {
    contract: ComponentContract,
    source: PathBuf,
    digest: String,
    size: u64,
}

const COMPONENTS: [ComponentContract; 7] = [
    ComponentContract {
        name: "silo",
        logical_path: "bin/silo",
        bundle_path: "Contents/MacOS/silo",
        mode: EXECUTABLE_MODE,
    },
    ComponentContract {
        name: "vmmon",
        logical_path: "runtime/bin/vmmon",
        bundle_path: "Contents/Helpers/vmmon",
        mode: EXECUTABLE_MODE,
    },
    ComponentContract {
        name: "netd",
        logical_path: "runtime/bin/netd",
        bundle_path: "Contents/Helpers/netd",
        mode: EXECUTABLE_MODE,
    },
    ComponentContract {
        name: "krun",
        logical_path: "runtime/bin/krun",
        bundle_path: "Contents/Helpers/krun",
        mode: EXECUTABLE_MODE,
    },
    ComponentContract {
        name: "kernel-default",
        logical_path: "runtime/assets/kernel-default",
        bundle_path: "Contents/Resources/assets/kernel-default",
        mode: FILE_MODE,
    },
    ComponentContract {
        name: "initramfs",
        logical_path: "runtime/assets/initramfs",
        bundle_path: "Contents/Resources/assets/initramfs",
        mode: FILE_MODE,
    },
    ComponentContract {
        name: "agent",
        logical_path: "runtime/assets/agent",
        bundle_path: "Contents/Resources/assets/agent",
        mode: EXECUTABLE_MODE,
    },
];

struct MountedDmg {
    mount_point: PathBuf,
    attached: bool,
}

impl MountedDmg {
    fn attach(dmg: &Path, mount_point: PathBuf) -> Result<Self, MacosPackageError> {
        create_directory(&mount_point)?;
        let mut command = Command::new("/usr/bin/hdiutil");
        command
            .args(["attach", "-quiet", "-readonly", "-nobrowse", "-mountpoint"])
            .arg(&mount_point)
            .arg(dmg);
        run(command)?;
        Ok(Self {
            mount_point,
            attached: true,
        })
    }

    fn detach(mut self) -> Result<(), MacosPackageError> {
        let mut command = Command::new("/usr/bin/hdiutil");
        command.args(["detach", "-quiet"]).arg(&self.mount_point);
        run(command)?;
        self.attached = false;
        Ok(())
    }
}

impl Drop for MountedDmg {
    fn drop(&mut self) {
        if self.attached {
            let _ = Command::new("/usr/bin/hdiutil")
                .args(["detach", "-quiet", "-force"])
                .arg(&self.mount_point)
                .status();
        }
    }
}

impl TemporaryDirectory {
    fn new(path: PathBuf) -> Result<Self, MacosPackageError> {
        fs::create_dir(&path).map_err(|source| MacosPackageError::Io {
            operation: "create temporary macOS package directory",
            path: path.clone(),
            source,
        })?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn package_macos(
    options: &PackageMacosOptions,
) -> Result<PackageMacosResult, MacosPackageError> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(MacosPackageError::UnsupportedHost);
    }
    validate_options(options)?;
    validate_source_identity(options)?;

    let target = ReleaseTarget::DarwinArm64;
    let descriptor = target.descriptor();
    let output = options
        .target_dir
        .join("silo-artifacts")
        .join(descriptor.name)
        .join("macos");
    if fs::symlink_metadata(&output).is_ok() {
        return Err(MacosPackageError::OutputExists { path: output });
    }
    let parent = output
        .parent()
        .ok_or_else(|| MacosPackageError::InvalidBundle {
            path: output.clone(),
            reason: "output has no parent".to_string(),
        })?;
    create_directory(parent)?;
    let temporary = TemporaryDirectory::new(parent.join(nonce("macos")))?;
    let package = temporary.path.join("output");
    create_directory(&package)?;
    let app = package.join(APP_NAME);
    assemble_app(options, &app)?;
    sign_app(options, &app)?;

    if let Some(profile) = &options.notary_keychain_profile {
        let archive = temporary.path.join("Silo.app.zip");
        create_notary_archive(&app, &archive)?;
        notarize(&archive, profile)?;
        staple_and_validate(&app)?;
        verify_app_signature(&app)?;
    }

    let dmg_name = format!("Silo-{}-{}.dmg", env!("CARGO_PKG_VERSION"), descriptor.name);
    let dmg = package.join(&dmg_name);
    create_dmg(&temporary.path, &app, &dmg)?;
    if let Some(identity) = &options.signing_identity {
        run(codesign_dmg_command(identity, &dmg))?;
        verify_dmg_signature(&dmg)?;
    }
    if let Some(profile) = &options.notary_keychain_profile {
        notarize(&dmg, profile)?;
        staple_and_validate(&dmg)?;
        assess_distribution(&app, &dmg)?;
    }

    let metadata = package.join("macos.json");
    write_metadata(options, &metadata, &dmg_name, &dmg)?;
    publish_noreplace(&package, &output)?;

    Ok(PackageMacosResult {
        app: output.join(APP_NAME),
        dmg: output.join(dmg_name),
        metadata: output.join("macos.json"),
    })
}

fn validate_options(options: &PackageMacosOptions) -> Result<(), MacosPackageError> {
    let components = options.build_number.split('.').collect::<Vec<_>>();
    let parsed = components
        .iter()
        .map(|component| component.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>();
    if components.is_empty()
        || components.len() > 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
        || parsed
            .as_ref()
            .and_then(|values| values.first())
            .is_none_or(|value| *value == 0)
    {
        return Err(MacosPackageError::InvalidBuildNumber {
            value: options.build_number.clone(),
        });
    }
    if options
        .signing_identity
        .as_ref()
        .is_some_and(|identity| identity.trim().is_empty())
    {
        return Err(MacosPackageError::EmptyOption {
            field: "--signing-identity",
        });
    }
    if options
        .notary_keychain_profile
        .as_ref()
        .is_some_and(|profile| profile.trim().is_empty())
    {
        return Err(MacosPackageError::EmptyOption {
            field: "--notary-keychain-profile",
        });
    }
    if options.notary_keychain_profile.is_some() && options.signing_identity.is_none() {
        return Err(MacosPackageError::NotarizationRequiresIdentity);
    }
    Ok(())
}

fn validate_source_identity(options: &PackageMacosOptions) -> Result<(), MacosPackageError> {
    let descriptor = ReleaseTarget::DarwinArm64.descriptor();
    let metadata_path = options
        .target_dir
        .join("silo-release")
        .join(descriptor.name)
        .join("release/metadata/release.json");
    require_regular_file(&metadata_path)?;
    let bytes = fs::read(&metadata_path).map_err(|source| MacosPackageError::Io {
        operation: "read release metadata source identity",
        path: metadata_path.clone(),
        source,
    })?;
    let metadata: Value = serde_json::from_slice(&bytes).map_err(|error| {
        MacosPackageError::InvalidReleaseMetadata {
            path: metadata_path.clone(),
            reason: error.to_string(),
        }
    })?;
    let expected = metadata
        .pointer("/source/revision")
        .and_then(Value::as_str)
        .filter(|revision| !revision.is_empty())
        .ok_or_else(|| MacosPackageError::InvalidReleaseMetadata {
            path: metadata_path.clone(),
            reason: "source.revision must be a non-empty string".to_string(),
        })?;
    if metadata
        .pointer("/source/sourceDateEpoch")
        .and_then(Value::as_u64)
        .is_none()
    {
        return invalid_release_metadata(
            &metadata_path,
            "source.sourceDateEpoch must be an integer".to_string(),
        );
    }

    let status = git_output(&options.workspace_root, ["status", "--porcelain=v1"])?;
    if !status.is_empty() {
        return Err(MacosPackageError::DirtyWorktree { status });
    }
    let actual = git_output(&options.workspace_root, ["rev-parse", "HEAD"])?;
    if actual != expected {
        return Err(MacosPackageError::SourceRevisionMismatch {
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

fn git_output<const N: usize>(
    workspace: &Path,
    arguments: [&str; N],
) -> Result<String, MacosPackageError> {
    let mut command = Command::new("git");
    command.current_dir(workspace).args(arguments);
    let output = run_capture(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn assemble_app(options: &PackageMacosOptions, app: &Path) -> Result<(), MacosPackageError> {
    let descriptor = ReleaseTarget::DarwinArm64.descriptor();
    let components = validate_release_inputs(options)?;
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    let helpers = contents.join("Helpers");
    let resources = contents.join("Resources");
    let assets = resources.join("assets");
    for directory in [&macos, &helpers, &assets] {
        create_directory(directory)?;
    }

    for component in &components {
        copy_file(
            &component.source,
            &app.join(component.contract.bundle_path),
            component.contract.mode,
        )?;
    }
    copy_file(
        &options
            .workspace_root
            .join("packaging/THIRD_PARTY_NOTICES.txt"),
        &resources.join("THIRD_PARTY_NOTICES.txt"),
        FILE_MODE,
    )?;
    let info = contents.join("Info.plist");
    fs::write(
        &info,
        info_plist(
            &options.build_number,
            descriptor.macos_minimum_version.unwrap_or("26.0"),
        ),
    )
    .map_err(|source| MacosPackageError::Io {
        operation: "write Info.plist",
        path: info.clone(),
        source,
    })?;
    set_mode(&info, FILE_MODE)?;
    validate_unsigned_app(app)?;
    validate_bundle_components(app, &components)
}

fn validate_release_inputs(
    options: &PackageMacosOptions,
) -> Result<Vec<ValidatedComponent>, MacosPackageError> {
    let descriptor = ReleaseTarget::DarwinArm64.descriptor();
    let runtime = descriptor.stage_dir_in(&options.target_dir, BuildProfile::Release);
    let release = options
        .target_dir
        .join("silo-release")
        .join(descriptor.name)
        .join("release");
    let metadata_path = release.join("metadata/release.json");
    require_regular_file(&metadata_path)?;
    let bytes = fs::read(&metadata_path).map_err(|source| MacosPackageError::Io {
        operation: "read release metadata",
        path: metadata_path.clone(),
        source,
    })?;
    let metadata: Value = serde_json::from_slice(&bytes).map_err(|error| {
        MacosPackageError::InvalidReleaseMetadata {
            path: metadata_path.clone(),
            reason: error.to_string(),
        }
    })?;
    for (field, expected) in [
        ("version", env!("CARGO_PKG_VERSION")),
        ("target", descriptor.name),
        ("runtimeLayout", "portable-v1"),
    ] {
        if metadata.get(field).and_then(Value::as_str) != Some(expected) {
            return invalid_release_metadata(
                &metadata_path,
                format!("expected {field} to be {expected:?}"),
            );
        }
    }
    if metadata.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        return invalid_release_metadata(&metadata_path, "expected schemaVersion 1".to_string());
    }
    let entries = metadata
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| MacosPackageError::InvalidReleaseMetadata {
            path: metadata_path.clone(),
            reason: "components must be an array".to_string(),
        })?;
    if entries.len() != COMPONENTS.len() {
        return invalid_release_metadata(
            &metadata_path,
            format!(
                "expected {} components, found {}",
                COMPONENTS.len(),
                entries.len()
            ),
        );
    }

    COMPONENTS
        .iter()
        .map(|contract| {
            let matches = entries
                .iter()
                .filter(|entry| {
                    entry.get("path").and_then(Value::as_str) == Some(contract.logical_path)
                })
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return invalid_release_metadata(
                    &metadata_path,
                    format!(
                        "expected exactly one component at {:?}",
                        contract.logical_path
                    ),
                );
            }
            let entry = matches[0];
            if entry.get("name").and_then(Value::as_str) != Some(contract.name) {
                return invalid_release_metadata(
                    &metadata_path,
                    format!(
                        "component {:?} must be named {:?}",
                        contract.logical_path, contract.name
                    ),
                );
            }
            let digest = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| MacosPackageError::InvalidReleaseMetadata {
                    path: metadata_path.clone(),
                    reason: format!("component {:?} has no sha256", contract.logical_path),
                })?
                .to_string();
            let size = entry.get("size").and_then(Value::as_u64).ok_or_else(|| {
                MacosPackageError::InvalidReleaseMetadata {
                    path: metadata_path.clone(),
                    reason: format!("component {:?} has no size", contract.logical_path),
                }
            })?;
            let mode = entry.get("mode").and_then(Value::as_u64);
            if mode != Some(u64::from(contract.mode)) {
                return invalid_release_metadata(
                    &metadata_path,
                    format!(
                        "component {:?} must have mode {:o}",
                        contract.logical_path, contract.mode
                    ),
                );
            }
            let source = contract.logical_path.strip_prefix("runtime/").map_or_else(
                || release.join(contract.logical_path),
                |path| runtime.join(path),
            );
            let source_metadata = require_regular_file(&source)?;
            let source_mode = source_metadata.permissions().mode() & 0o777;
            let actual_digest = sha256(&source)?;
            if source_metadata.len() != size
                || source_mode != contract.mode
                || actual_digest != digest
            {
                return invalid_release_metadata(
                    &metadata_path,
                    format!(
                        "component {:?} does not match its recorded size, mode, and digest",
                        contract.logical_path
                    ),
                );
            }
            Ok(ValidatedComponent {
                contract: *contract,
                source,
                digest,
                size,
            })
        })
        .collect()
}

fn validate_bundle_components(
    app: &Path,
    components: &[ValidatedComponent],
) -> Result<(), MacosPackageError> {
    for component in components {
        let path = app.join(component.contract.bundle_path);
        let metadata = require_regular_file(&path)?;
        if metadata.len() != component.size || sha256(&path)? != component.digest {
            return Err(MacosPackageError::InvalidBundle {
                path,
                reason: format!(
                    "copied component {:?} does not match release metadata",
                    component.contract.name
                ),
            });
        }
    }
    Ok(())
}

fn invalid_release_metadata<T>(path: &Path, reason: String) -> Result<T, MacosPackageError> {
    Err(MacosPackageError::InvalidReleaseMetadata {
        path: path.to_path_buf(),
        reason,
    })
}

fn info_plist(build_number: &str, minimum_version: &str) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "    <key>CFBundleDevelopmentRegion</key>\n",
            "    <string>en</string>\n",
            "    <key>CFBundleDisplayName</key>\n",
            "    <string>Silo</string>\n",
            "    <key>CFBundleExecutable</key>\n",
            "    <string>silo</string>\n",
            "    <key>CFBundleIdentifier</key>\n",
            "    <string>{app_identifier}</string>\n",
            "    <key>CFBundleInfoDictionaryVersion</key>\n",
            "    <string>6.0</string>\n",
            "    <key>CFBundleName</key>\n",
            "    <string>Silo</string>\n",
            "    <key>CFBundlePackageType</key>\n",
            "    <string>APPL</string>\n",
            "    <key>CFBundleShortVersionString</key>\n",
            "    <string>{version}</string>\n",
            "    <key>CFBundleVersion</key>\n",
            "    <string>{build_number}</string>\n",
            "    <key>LSMinimumSystemVersion</key>\n",
            "    <string>{minimum_version}</string>\n",
            "</dict>\n",
            "</plist>\n"
        ),
        app_identifier = APP_IDENTIFIER,
        version = env!("CARGO_PKG_VERSION"),
        build_number = build_number,
        minimum_version = minimum_version,
    )
}

fn validate_unsigned_app(app: &Path) -> Result<(), MacosPackageError> {
    let expected = [
        ("Contents/Info.plist", FILE_MODE),
        ("Contents/MacOS/silo", EXECUTABLE_MODE),
        ("Contents/Helpers/vmmon", EXECUTABLE_MODE),
        ("Contents/Helpers/netd", EXECUTABLE_MODE),
        ("Contents/Helpers/krun", EXECUTABLE_MODE),
        ("Contents/Resources/assets/kernel-default", FILE_MODE),
        ("Contents/Resources/assets/initramfs", FILE_MODE),
        ("Contents/Resources/assets/agent", EXECUTABLE_MODE),
        ("Contents/Resources/THIRD_PARTY_NOTICES.txt", FILE_MODE),
    ];
    let mut actual = collect_files(app)?;
    actual.sort();
    let mut expected_paths = expected
        .iter()
        .map(|(path, _)| (*path).to_string())
        .collect::<Vec<_>>();
    expected_paths.sort();
    if actual != expected_paths {
        return Err(MacosPackageError::InvalidBundle {
            path: app.to_path_buf(),
            reason: format!("expected files {expected_paths:?}, found {actual:?}"),
        });
    }
    for (relative, expected_mode) in expected {
        let path = app.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|source| MacosPackageError::Io {
            operation: "inspect app bundle file",
            path: path.clone(),
            source,
        })?;
        let actual_mode = metadata.permissions().mode() & 0o777;
        if actual_mode != expected_mode {
            return Err(MacosPackageError::InvalidBundle {
                path,
                reason: format!("expected mode {expected_mode:o}, found {actual_mode:o}"),
            });
        }
    }
    Ok(())
}

fn collect_files(root: &Path) -> Result<Vec<String>, MacosPackageError> {
    let mut files = Vec::new();
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| MacosPackageError::Io {
            operation: "read app bundle directory",
            path: directory.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| MacosPackageError::Io {
                operation: "read app bundle entry",
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| MacosPackageError::Io {
                operation: "inspect app bundle entry",
                path: path.clone(),
                source,
            })?;
            if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
                return Err(MacosPackageError::InvalidBundle {
                    path,
                    reason: "symlinks and special files are not allowed".to_string(),
                });
            }
            if metadata.is_dir() {
                directories.push(path);
            } else {
                let relative =
                    path.strip_prefix(root)
                        .map_err(|error| MacosPackageError::InvalidBundle {
                            path: path.clone(),
                            reason: error.to_string(),
                        })?;
                files.push(relative.to_string_lossy().to_string());
            }
        }
    }
    Ok(files)
}

fn sign_app(options: &PackageMacosOptions, app: &Path) -> Result<(), MacosPackageError> {
    let identity = options.signing_identity.as_deref().unwrap_or("-");
    let timestamp = options.signing_identity.is_some();
    let contents = app.join("Contents");
    for (path, identifier, entitlements) in [
        (
            contents.join("Helpers/vmmon"),
            "sh.silo.app.vmmon",
            Some(
                options
                    .workspace_root
                    .join("runtime/vmmon/vmmon.entitlements"),
            ),
        ),
        (contents.join("Helpers/netd"), "sh.silo.app.netd", None),
        (
            contents.join("Helpers/krun"),
            "sh.silo.app.krun",
            Some(options.workspace_root.join("virt/krun/krun.entitlements")),
        ),
    ] {
        run(codesign_command(
            identity,
            identifier,
            entitlements.as_deref(),
            timestamp,
            &path,
        ))?;
    }
    run(codesign_command(
        identity,
        APP_IDENTIFIER,
        None,
        timestamp,
        app,
    ))?;
    verify_app_signature(app)
}

fn codesign_command(
    identity: &str,
    identifier: &str,
    entitlements: Option<&Path>,
    timestamp: bool,
    path: &Path,
) -> Command {
    let mut command = Command::new("/usr/bin/codesign");
    command.args(["--force", "--sign"]).arg(identity).args([
        "--identifier",
        identifier,
        "--options",
        "runtime",
    ]);
    if timestamp {
        command.arg("--timestamp");
    }
    if let Some(entitlements) = entitlements {
        command.arg("--entitlements").arg(entitlements);
    }
    command.arg(path);
    command
}

fn codesign_dmg_command(identity: &str, dmg: &Path) -> Command {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .args(["--force", "--sign"])
        .arg(identity)
        .arg("--timestamp")
        .arg(dmg);
    command
}

fn verify_app_signature(app: &Path) -> Result<(), MacosPackageError> {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .args(["--verify", "--deep", "--strict", "--verbose=4"])
        .arg(app);
    run(command)
}

fn verify_dmg_signature(dmg: &Path) -> Result<(), MacosPackageError> {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .args(["--verify", "--strict", "--verbose=4"])
        .arg(dmg);
    run(command)
}

fn create_notary_archive(app: &Path, archive: &Path) -> Result<(), MacosPackageError> {
    let mut command = Command::new("/usr/bin/ditto");
    command
        .args(["-c", "-k", "--keepParent"])
        .arg(app)
        .arg(archive);
    run(command)
}

fn notarize(path: &Path, profile: &str) -> Result<(), MacosPackageError> {
    let mut command = Command::new("xcrun");
    command
        .args([
            "notarytool",
            "submit",
            "--keychain-profile",
            profile,
            "--wait",
            "--timeout",
            NOTARY_TIMEOUT,
            "--output-format",
            "json",
        ])
        .arg(path);
    let output = run_capture(command)?;
    let response: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        MacosPackageError::NotarizationRejected {
            path: path.to_path_buf(),
            reason: format!("invalid notarytool response: {error}"),
        }
    })?;
    let status = response.get("status").and_then(Value::as_str);
    if status == Some("Accepted") {
        return Ok(());
    }
    Err(MacosPackageError::NotarizationRejected {
        path: path.to_path_buf(),
        reason: response.to_string(),
    })
}

fn staple_and_validate(path: &Path) -> Result<(), MacosPackageError> {
    for action in ["staple", "validate"] {
        let mut command = Command::new("xcrun");
        command.args(["stapler", action, "-v"]).arg(path);
        run(command)?;
    }
    Ok(())
}

fn create_dmg(root: &Path, app: &Path, dmg: &Path) -> Result<(), MacosPackageError> {
    let payload = root.join("dmg-root");
    create_directory(&payload)?;
    copy_tree(app, &payload.join(APP_NAME))?;
    let volume_name = format!("Silo {}", env!("CARGO_PKG_VERSION"));
    let mut command = Command::new("/usr/bin/hdiutil");
    command
        .args([
            "create",
            "-quiet",
            "-nospotlight",
            "-fs",
            "HFS+",
            "-format",
            "UDZO",
            "-volname",
        ])
        .arg(volume_name)
        .arg("-srcfolder")
        .arg(&payload)
        .arg(dmg);
    run(command)?;
    let mut verify = Command::new("/usr/bin/hdiutil");
    verify.args(["verify", "-quiet"]).arg(dmg);
    run(verify)?;

    let mounted = MountedDmg::attach(dmg, root.join("dmg-mount"))?;
    verify_app_signature(&mounted.mount_point.join(APP_NAME))?;
    mounted.detach()
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), MacosPackageError> {
    create_directory(destination)?;
    let entries = fs::read_dir(source).map_err(|source_error| MacosPackageError::Io {
        operation: "read app for DMG assembly",
        path: source.to_path_buf(),
        source: source_error,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source_error| MacosPackageError::Io {
            operation: "read app entry for DMG assembly",
            path: source.to_path_buf(),
            source: source_error,
        })?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata =
            fs::symlink_metadata(&from).map_err(|source_error| MacosPackageError::Io {
                operation: "inspect app entry for DMG assembly",
                path: from.clone(),
                source: source_error,
            })?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(MacosPackageError::InvalidBundle {
                path: from,
                reason: "symlinks and special files are not allowed".to_string(),
            });
        }
        if metadata.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            fs::copy(&from, &to).map_err(|source_error| MacosPackageError::Io {
                operation: "copy app entry into DMG payload",
                path: to.clone(),
                source: source_error,
            })?;
            fs::set_permissions(&to, metadata.permissions()).map_err(|source_error| {
                MacosPackageError::Io {
                    operation: "preserve app entry mode in DMG payload",
                    path: to,
                    source: source_error,
                }
            })?;
        }
    }
    Ok(())
}

fn assess_distribution(app: &Path, dmg: &Path) -> Result<(), MacosPackageError> {
    let mut app_assessment = Command::new("/usr/sbin/spctl");
    app_assessment
        .args(["--assess", "--type", "execute", "--verbose=4"])
        .arg(app);
    run(app_assessment)?;
    let mut dmg_assessment = Command::new("/usr/sbin/spctl");
    dmg_assessment
        .args([
            "--assess",
            "--type",
            "open",
            "--context",
            "context:primary-signature",
            "--verbose=4",
        ])
        .arg(dmg);
    run(dmg_assessment)
}

fn write_metadata(
    options: &PackageMacosOptions,
    path: &Path,
    dmg_name: &str,
    dmg: &Path,
) -> Result<(), MacosPackageError> {
    let dmg_metadata = fs::metadata(dmg).map_err(|source| MacosPackageError::Io {
        operation: "inspect packaged DMG",
        path: dmg.to_path_buf(),
        source,
    })?;
    let signing = options.signing_identity.as_deref().unwrap_or("ad-hoc");
    let value = serde_json::json!({
        "schemaVersion": 1,
        "version": env!("CARGO_PKG_VERSION"),
        "target": ReleaseTarget::DarwinArm64.descriptor().name,
        "buildNumber": options.build_number,
        "bundleIdentifier": APP_IDENTIFIER,
        "minimumSystemVersion": ReleaseTarget::DarwinArm64
            .descriptor()
            .macos_minimum_version,
        "app": APP_NAME,
        "dmg": {
            "path": dmg_name,
            "sha256": sha256(dmg)?,
            "size": dmg_metadata.len(),
        },
        "signing": signing,
        "notarized": options.notary_keychain_profile.is_some(),
    });
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|source| MacosPackageError::Io {
        operation: "write macOS package metadata",
        path: path.to_path_buf(),
        source,
    })
}

fn sha256(path: &Path) -> Result<String, MacosPackageError> {
    let mut file = File::open(path).map_err(|source| MacosPackageError::Io {
        operation: "open file for hashing",
        path: path.to_path_buf(),
        source,
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| MacosPackageError::Io {
                operation: "hash file",
                path: path.to_path_buf(),
                source,
            })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn copy_file(source: &Path, destination: &Path, mode: u32) -> Result<(), MacosPackageError> {
    require_regular_file(source)?;
    fs::copy(source, destination).map_err(|source_error| MacosPackageError::Io {
        operation: "copy macOS package input",
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    set_mode(destination, mode)
}

fn require_regular_file(path: &Path) -> Result<fs::Metadata, MacosPackageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| MacosPackageError::MissingInput {
        path: path.to_path_buf(),
    })?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(metadata)
    } else {
        Err(MacosPackageError::MissingInput {
            path: path.to_path_buf(),
        })
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<(), MacosPackageError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
        MacosPackageError::Io {
            operation: "set macOS package file mode",
            path: path.to_path_buf(),
            source,
        }
    })
}

fn create_directory(path: &Path) -> Result<(), MacosPackageError> {
    fs::create_dir_all(path).map_err(|source| MacosPackageError::Io {
        operation: "create macOS package directory",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(target_os = "macos")]
fn publish_noreplace(temporary: &Path, destination: &Path) -> Result<(), MacosPackageError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    const RENAME_EXCL: u32 = 0x0000_0004;

    // nix has no wrapper for renamex_np, Apple's atomic no-replace rename.
    unsafe extern "C" {
        fn renamex_np(
            from: *const std::ffi::c_char,
            to: *const std::ffi::c_char,
            flags: u32,
        ) -> std::ffi::c_int;
    }

    let from = CString::new(temporary.as_os_str().as_bytes()).map_err(|error| {
        MacosPackageError::InvalidBundle {
            path: temporary.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    let to = CString::new(destination.as_os_str().as_bytes()).map_err(|error| {
        MacosPackageError::InvalidBundle {
            path: destination.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    let result = unsafe { renamex_np(from.as_ptr(), to.as_ptr(), RENAME_EXCL) };
    if result == 0 {
        return Ok(());
    }
    Err(MacosPackageError::Io {
        operation: "publish macOS package without replacing existing output",
        path: destination.to_path_buf(),
        source: io::Error::last_os_error(),
    })
}

#[cfg(not(target_os = "macos"))]
fn publish_noreplace(_temporary: &Path, _destination: &Path) -> Result<(), MacosPackageError> {
    Err(MacosPackageError::UnsupportedHost)
}

fn run(command: Command) -> Result<(), MacosPackageError> {
    run_capture(command).map(|_| ())
}

fn run_capture(mut command: Command) -> Result<Output, MacosPackageError> {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .map_err(|source| MacosPackageError::RunCommand {
            command: rendered.clone(),
            source,
        })?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(MacosPackageError::CommandFailed {
            command: rendered,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn nonce(kind: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(".{kind}-{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use crate::macos_package::{
        assemble_app, codesign_command, info_plist, package_macos, validate_options,
        validate_source_identity, validate_unsigned_app, PackageMacosOptions, COMPONENTS,
    };

    fn options(root: &Path, build_number: &str) -> PackageMacosOptions {
        PackageMacosOptions {
            build_number: build_number.to_string(),
            signing_identity: None,
            notary_keychain_profile: None,
            target_dir: root.join("target"),
            workspace_root: root.join("workspace"),
        }
    }

    #[test]
    fn assembles_the_canonical_app_bundle() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = options(temp.path(), "42.7");
        populate_release(&options);
        let app = temp.path().join("Silo.app");

        assemble_app(&options, &app).expect("assemble app");

        validate_unsigned_app(&app).expect("validate app");
        assert_eq!(
            std::fs::read(app.join("Contents/Helpers/vmmon")).expect("read vmmon"),
            b"vmmon"
        );
        let plist =
            std::fs::read_to_string(app.join("Contents/Info.plist")).expect("read Info.plist");
        assert!(plist.contains("<string>sh.silo.app</string>"));
        assert!(plist.contains("<string>0.1.0</string>"));
        assert!(plist.contains("<string>42.7</string>"));
        assert!(plist.contains("<string>26.0</string>"));
    }

    #[test]
    fn validates_build_and_notary_options() {
        let root = Path::new("/workspace");
        assert!(validate_options(&options(root, "123")).is_ok());
        assert!(validate_options(&options(root, "1.2.3")).is_ok());
        for invalid in ["", "0", "0.1", "1.2.3.4", "release", "1..2", "-1"] {
            assert!(validate_options(&options(root, invalid)).is_err());
        }
        let mut notary_without_identity = options(root, "1");
        notary_without_identity.notary_keychain_profile = Some("release".to_string());
        assert!(validate_options(&notary_without_identity).is_err());
    }

    #[test]
    fn signing_commands_apply_hardened_runtime_without_deep_signing() {
        let entitlement = Path::new("vmmon.entitlements");
        let command = codesign_command(
            "Developer ID Application: Silo",
            "sh.silo.app.vmmon",
            Some(entitlement),
            true,
            Path::new("Silo.app/Contents/Helpers/vmmon"),
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|args| args == ["--options", "runtime"]));
        assert!(args.contains(&"--timestamp".to_string()));
        assert!(args.contains(&"--entitlements".to_string()));
        assert!(!args.contains(&"--deep".to_string()));
    }

    #[test]
    fn plist_uses_only_validated_interpolated_values() {
        let plist = info_plist("100.2", "26.0");
        assert!(plist.contains("<key>CFBundlePackageType</key>"));
        assert!(plist.contains("<string>APPL</string>"));
        assert!(plist.ends_with("</plist>\n"));
    }

    #[test]
    fn bundle_validation_rejects_extra_files_and_symlinks() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = options(temp.path(), "1");
        populate_release(&options);
        let app = temp.path().join("Silo.app");
        assemble_app(&options, &app).expect("assemble app");
        std::fs::write(app.join("Contents/Resources/unexpected"), b"bad")
            .expect("write unexpected file");
        assert!(validate_unsigned_app(&app).is_err());
        std::fs::remove_file(app.join("Contents/Resources/unexpected"))
            .expect("remove unexpected file");
        std::os::unix::fs::symlink(
            "kernel-default",
            app.join("Contents/Resources/assets/kernel-link"),
        )
        .expect("create symlink");
        assert!(validate_unsigned_app(&app).is_err());
    }

    #[test]
    fn assembly_rejects_components_that_do_not_match_release_metadata() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = options(temp.path(), "1");
        populate_release(&options);
        std::fs::write(
            options
                .target_dir
                .join("silo-runtime/darwin-arm64/release/bin/vmmon"),
            b"modified",
        )
        .expect("modify staged vmmon");

        assert!(assemble_app(&options, &temp.path().join("Silo.app")).is_err());
    }

    #[test]
    fn source_identity_requires_the_staged_clean_revision() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = options(temp.path(), "1");
        populate_release(&options);
        let revision = initialize_git_workspace(&options.workspace_root);
        write_release_metadata(&options, &revision);
        validate_source_identity(&options).expect("matching clean source identity");

        std::fs::write(options.workspace_root.join("dirty"), b"dirty")
            .expect("dirty fixture workspace");
        assert!(validate_source_identity(&options).is_err());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn native_tools_accept_the_ad_hoc_signed_app_and_dmg() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = options(temp.path(), "1");
        populate_release(&options);
        for path in [
            options
                .target_dir
                .join("silo-release/darwin-arm64/release/bin/silo"),
            options
                .target_dir
                .join("silo-runtime/darwin-arm64/release/bin/vmmon"),
            options
                .target_dir
                .join("silo-runtime/darwin-arm64/release/bin/netd"),
            options
                .target_dir
                .join("silo-runtime/darwin-arm64/release/bin/krun"),
        ] {
            std::fs::copy("/usr/bin/true", &path).expect("copy signable Mach-O fixture");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("set Mach-O fixture mode");
        }
        let revision = initialize_git_workspace(&options.workspace_root);
        write_release_metadata(&options, &revision);
        let packaged = package_macos(&options).expect("package macOS distribution");
        assert!(packaged.app.is_dir());
        assert!(packaged.dmg.is_file());
        assert!(packaged.metadata.is_file());

        assert_entitlement(
            &packaged.app.join("Contents/Helpers/vmmon"),
            "com.apple.security.virtualization",
        );
        assert_entitlement(
            &packaged.app.join("Contents/Helpers/krun"),
            "com.apple.security.hypervisor",
        );
    }

    fn populate_release(options: &PackageMacosOptions) {
        let runtime = options.target_dir.join("silo-runtime/darwin-arm64/release");
        let release = options.target_dir.join("silo-release/darwin-arm64/release");
        for (relative, contents) in [
            ("bin/vmmon", "vmmon"),
            ("bin/netd", "netd"),
            ("bin/krun", "krun"),
            ("assets/kernel-default", "kernel"),
            ("assets/initramfs", "initramfs"),
            ("assets/agent", "agent"),
        ] {
            let mode = if relative == "assets/kernel-default" || relative == "assets/initramfs" {
                0o644
            } else {
                0o755
            };
            write_fixture(&runtime.join(relative), contents.as_bytes(), mode);
        }
        write_fixture(&release.join("bin/silo"), b"silo", 0o755);
        write_fixture(
            &options
                .workspace_root
                .join("packaging/THIRD_PARTY_NOTICES.txt"),
            b"notices\n",
            0o644,
        );
        write_fixture(
            &options
                .workspace_root
                .join("runtime/vmmon/vmmon.entitlements"),
            include_bytes!("../../runtime/vmmon/vmmon.entitlements"),
            0o644,
        );
        write_fixture(
            &options.workspace_root.join("virt/krun/krun.entitlements"),
            include_bytes!("../../virt/krun/krun.entitlements"),
            0o644,
        );
        write_release_metadata(options, "abc123");
    }

    fn write_fixture(path: &Path, contents: &[u8], mode: u32) {
        std::fs::create_dir_all(path.parent().expect("fixture parent"))
            .expect("create fixture parent");
        std::fs::write(path, contents).expect("write fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set fixture mode");
    }

    fn write_release_metadata(options: &PackageMacosOptions, revision: &str) {
        let runtime = options.target_dir.join("silo-runtime/darwin-arm64/release");
        let release = options.target_dir.join("silo-release/darwin-arm64/release");
        let components = COMPONENTS.map(|contract| {
            let source = contract.logical_path.strip_prefix("runtime/").map_or_else(
                || release.join(contract.logical_path),
                |path| runtime.join(path),
            );
            let metadata = std::fs::metadata(&source).expect("component metadata");
            serde_json::json!({
                "name": contract.name,
                "path": contract.logical_path,
                "sha256": crate::macos_package::sha256(&source).expect("component digest"),
                "size": metadata.len(),
                "mode": metadata.permissions().mode() & 0o777,
            })
        });
        let metadata = serde_json::json!({
            "schemaVersion": 1,
            "version": env!("CARGO_PKG_VERSION"),
            "target": "darwin-arm64",
            "runtimeLayout": "portable-v1",
            "components": components,
            "source": {
                "revision": revision,
                "sourceDateEpoch": 1_700_000_000_u64,
            },
        });
        let path = release.join("metadata/release.json");
        std::fs::create_dir_all(path.parent().expect("metadata parent"))
            .expect("create metadata parent");
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&metadata).expect("encode release metadata"),
        )
        .expect("write release metadata");
    }

    fn initialize_git_workspace(workspace: &Path) -> String {
        let run = |arguments: &[&str]| {
            let mut command = std::process::Command::new("git");
            command
                .current_dir(workspace)
                .args(arguments)
                .env("GIT_AUTHOR_NAME", "Silo Test")
                .env("GIT_AUTHOR_EMAIL", "test@silo.invalid")
                .env("GIT_COMMITTER_NAME", "Silo Test")
                .env("GIT_COMMITTER_EMAIL", "test@silo.invalid");
            let output = command.output().expect("run fixture git command");
            assert!(
                output.status.success(),
                "git {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        };
        run(&["init", "--quiet"]);
        run(&["add", "."]);
        run(&["commit", "--quiet", "-m", "fixture"]);
        run(&["rev-parse", "HEAD"])
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn assert_entitlement(path: &Path, entitlement: &str) {
        let output = std::process::Command::new("/usr/bin/codesign")
            .args(["--display", "--entitlements", ":-"])
            .arg(path)
            .output()
            .expect("display signed entitlements");
        assert!(output.status.success());
        let mut text = String::from_utf8_lossy(&output.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        assert!(text.contains(entitlement), "missing {entitlement}: {text}");
    }
}
