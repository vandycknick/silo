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
use crate::remove_path::remove_if_exists;

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
    pub(crate) notary_keychain: Option<PathBuf>,
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
    #[error("--notary-keychain requires --notary-keychain-profile")]
    NotaryKeychainRequiresProfile,
    #[error("required release input is missing or is not a regular file: {path}")]
    MissingInput { path: PathBuf },
    #[error("invalid release metadata at {path}: {reason}")]
    InvalidReleaseMetadata { path: PathBuf, reason: String },
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
    #[error("command failed ({command}): {output}")]
    CommandFailed { command: String, output: String },
    #[error(transparent)]
    Dmg(#[from] crate::dmg::DmgError),
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

#[derive(Debug, Eq, PartialEq)]
struct NotarizationSubmission {
    id: String,
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
    remove_if_exists(&output).map_err(|source| MacosPackageError::Io {
        operation: "remove previous macOS package output",
        path: output.clone(),
        source,
    })?;
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

    let app_notarization = if let Some(profile) = &options.notary_keychain_profile {
        let archive = temporary.path.join("Silo.app.zip");
        create_notary_archive(&app, &archive)?;
        let submission = notarize(
            &archive,
            profile,
            options.notary_keychain.as_deref(),
            &temporary.path.join("app-notarization.json"),
        )?;
        staple_and_validate(&app)?;
        verify_app_signature(&app)?;
        Some(submission)
    } else {
        None
    };

    let dmg_name = format!("Silo-{}-{}.dmg", env!("CARGO_PKG_VERSION"), descriptor.name);
    let dmg = package.join(&dmg_name);
    create_dmg(options, &temporary.path, &app, &dmg)?;
    if let Some(identity) = &options.signing_identity {
        run(codesign_dmg_command(identity, &dmg))?;
        verify_dmg_signature(&dmg)?;
        verify_dmg_image(&dmg)?;
    }
    let dmg_notarization = if let Some(profile) = &options.notary_keychain_profile {
        let submission = notarize(
            &dmg,
            profile,
            options.notary_keychain.as_deref(),
            &temporary.path.join("dmg-notarization.json"),
        )?;
        staple_and_validate(&dmg)?;
        verify_dmg_signature(&dmg)?;
        verify_dmg_image(&dmg)?;
        validate_dmg_contents(&temporary.path, &dmg, true)?;
        assess_distribution(&app, &dmg)?;
        Some(submission)
    } else {
        None
    };

    let metadata = package.join("macos.json");
    write_metadata(
        options,
        &metadata,
        &dmg_name,
        &dmg,
        app_notarization.as_ref(),
        dmg_notarization.as_ref(),
    )?;
    fs::rename(&package, &output).map_err(|source| MacosPackageError::Io {
        operation: "publish macOS package",
        path: output.clone(),
        source,
    })?;

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
    if options
        .notary_keychain
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        return Err(MacosPackageError::EmptyOption {
            field: "--notary-keychain",
        });
    }
    if options.notary_keychain_profile.is_some() && options.signing_identity.is_none() {
        return Err(MacosPackageError::NotarizationRequiresIdentity);
    }
    if options.notary_keychain.is_some() && options.notary_keychain_profile.is_none() {
        return Err(MacosPackageError::NotaryKeychainRequiresProfile);
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
    let icon = options.workspace_root.join("packaging/macos/Silo.icns");
    validate_icns(&icon)?;
    copy_file(&icon, &resources.join("Silo.icns"), FILE_MODE)?;
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
            "    <key>CFBundleIconFile</key>\n",
            "    <string>Silo.icns</string>\n",
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
        ("Contents/Resources/Silo.icns", FILE_MODE),
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
        if let Some(entitlements) = entitlements.as_deref() {
            validate_entitlements(entitlements)?;
        }
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
        .args(["--options", "runtime", "--timestamp"])
        .arg(dmg);
    command
}

fn validate_entitlements(path: &Path) -> Result<(), MacosPackageError> {
    require_regular_file(path)?;
    let contents = fs::read(path).map_err(|source| MacosPackageError::Io {
        operation: "read entitlement file",
        path: path.to_path_buf(),
        source,
    })?;
    if contents.starts_with(&[0xef, 0xbb, 0xbf]) || !contents.is_ascii() {
        return Err(MacosPackageError::InvalidBundle {
            path: path.to_path_buf(),
            reason: "entitlements must be ASCII XML without a byte-order mark".to_string(),
        });
    }
    let mut command = Command::new("/usr/bin/plutil");
    command.args(["-lint", "--"]).arg(path);
    run(command)
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

fn notarize(
    path: &Path,
    profile: &str,
    keychain: Option<&Path>,
    log_path: &Path,
) -> Result<NotarizationSubmission, MacosPackageError> {
    let output = run_capture(notary_submit_command(path, profile, keychain))?;
    let submission = parse_notary_submission(path, &output.stdout)?;
    eprintln!(
        "notarytool submission for {}: {}",
        path.display(),
        submission.id
    );

    let (wait_command, wait_output) =
        capture_command(notary_wait_command(&submission.id, profile, keychain))?;
    run(notary_log_command(
        &submission.id,
        profile,
        keychain,
        log_path,
    ))?;
    let log = read_notary_log(path, log_path)?;
    report_notary_log(path, &log);

    if !wait_output.status.success() {
        return Err(MacosPackageError::NotarizationRejected {
            path: path.to_path_buf(),
            reason: format!(
                "{wait_command} failed: {}; log: {log}",
                String::from_utf8_lossy(&wait_output.stderr).trim()
            ),
        });
    }
    parse_notary_wait(path, &wait_output.stdout, &log)?;
    Ok(submission)
}

fn notary_submit_command(path: &Path, profile: &str, keychain: Option<&Path>) -> Command {
    let mut command = Command::new("xcrun");
    command.args(["notarytool", "submit"]).arg(path);
    append_notary_authentication(&mut command, profile, keychain);
    command.args(["--output-format", "json"]);
    command
}

fn notary_wait_command(submission_id: &str, profile: &str, keychain: Option<&Path>) -> Command {
    let mut command = Command::new("xcrun");
    command.args(["notarytool", "wait", submission_id]);
    append_notary_authentication(&mut command, profile, keychain);
    command.args(["--timeout", NOTARY_TIMEOUT, "--output-format", "json"]);
    command
}

fn notary_log_command(
    submission_id: &str,
    profile: &str,
    keychain: Option<&Path>,
    output: &Path,
) -> Command {
    let mut command = Command::new("xcrun");
    command.args(["notarytool", "log", submission_id]);
    append_notary_authentication(&mut command, profile, keychain);
    command.arg(output);
    command
}

fn append_notary_authentication(command: &mut Command, profile: &str, keychain: Option<&Path>) {
    command.args(["--keychain-profile", profile]);
    if let Some(keychain) = keychain {
        command.arg("--keychain").arg(keychain);
    }
}

fn parse_notary_submission(
    path: &Path,
    response: &[u8],
) -> Result<NotarizationSubmission, MacosPackageError> {
    let response: Value = serde_json::from_slice(response).map_err(|error| {
        MacosPackageError::NotarizationRejected {
            path: path.to_path_buf(),
            reason: format!("invalid notarytool submit response: {error}"),
        }
    })?;
    let id = response
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_uuid(id))
        .ok_or_else(|| MacosPackageError::NotarizationRejected {
            path: path.to_path_buf(),
            reason: format!("notarytool submit returned no valid submission UUID: {response}"),
        })?;
    Ok(NotarizationSubmission { id: id.to_string() })
}

fn parse_notary_wait(path: &Path, response: &[u8], log: &Value) -> Result<(), MacosPackageError> {
    let response: Value = serde_json::from_slice(response).map_err(|error| {
        MacosPackageError::NotarizationRejected {
            path: path.to_path_buf(),
            reason: format!("invalid notarytool wait response: {error}; log: {log}"),
        }
    })?;
    if response.get("status").and_then(Value::as_str) == Some("Accepted") {
        return Ok(());
    }
    Err(MacosPackageError::NotarizationRejected {
        path: path.to_path_buf(),
        reason: format!("notarytool wait returned {response}; log: {log}"),
    })
}

fn read_notary_log(path: &Path, log_path: &Path) -> Result<Value, MacosPackageError> {
    let bytes = fs::read(log_path).map_err(|source| MacosPackageError::Io {
        operation: "read notarytool log",
        path: log_path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|error| MacosPackageError::NotarizationRejected {
        path: path.to_path_buf(),
        reason: format!("invalid notarytool log: {error}"),
    })
}

fn report_notary_log(path: &Path, log: &Value) {
    for field in ["issues", "warnings"] {
        let Some(entries) = log.get(field).and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            eprintln!("notarytool {field} for {}: {entry}", path.display());
        }
    }
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn staple_and_validate(path: &Path) -> Result<(), MacosPackageError> {
    let mut command = Command::new("xcrun");
    command.args(["stapler", "staple", "-v"]).arg(path);
    run(command)?;
    validate_staple(path)
}

fn validate_staple(path: &Path) -> Result<(), MacosPackageError> {
    let mut command = Command::new("xcrun");
    command.args(["stapler", "validate", "-v"]).arg(path);
    run(command)
}

fn create_dmg(
    options: &PackageMacosOptions,
    root: &Path,
    app: &Path,
    dmg: &Path,
) -> Result<(), MacosPackageError> {
    let volume_icon = options.workspace_root.join("packaging/macos/Silo.icns");
    let finder_layout = options.workspace_root.join("packaging/macos/Silo.DS_Store");
    require_regular_file(&volume_icon)?;
    require_regular_file(&finder_layout)?;
    let volume_name = format!("Silo {}", env!("CARGO_PKG_VERSION"));
    crate::dmg::create(crate::dmg::DmgSpec {
        root,
        app,
        volume_icon: &volume_icon,
        finder_layout: &finder_layout,
        volume_name: &volume_name,
        output: dmg,
    })?;
    verify_dmg_image(dmg)?;
    validate_dmg_contents(root, dmg, false)
}

fn validate_dmg_contents(
    root: &Path,
    dmg: &Path,
    require_stapled_app: bool,
) -> Result<(), MacosPackageError> {
    let mounted = MountedDmg::attach(dmg, root.join(nonce("dmg-mount")))?;
    validate_mounted_dmg_root(&mounted.mount_point)?;
    let app = mounted.mount_point.join(APP_NAME);
    verify_app_signature(&app)?;
    if require_stapled_app {
        validate_staple(&app)?;
    }
    mounted.detach()
}

fn verify_dmg_image(dmg: &Path) -> Result<(), MacosPackageError> {
    let mut command = Command::new("/usr/bin/hdiutil");
    command.args(["verify", "-quiet"]).arg(dmg);
    run(command)
}

fn validate_mounted_dmg_root(root: &Path) -> Result<(), MacosPackageError> {
    let entries = fs::read_dir(root).map_err(|source| MacosPackageError::Io {
        operation: "read mounted disk image root",
        path: root.to_path_buf(),
        source,
    })?;
    let mut found_app = false;
    let mut found_applications = false;
    for entry in entries {
        let entry = entry.map_err(|source| MacosPackageError::Io {
            operation: "read mounted disk image entry",
            path: root.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| MacosPackageError::Io {
            operation: "inspect mounted disk image entry",
            path: path.clone(),
            source,
        })?;
        match name.to_str() {
            Some(APP_NAME) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                found_app = true;
            }
            Some("Applications") if metadata.file_type().is_symlink() => {
                let target = fs::read_link(&path).map_err(|source| MacosPackageError::Io {
                    operation: "read Applications link from disk image",
                    path: path.clone(),
                    source,
                })?;
                if target != Path::new("/Applications") {
                    return Err(MacosPackageError::InvalidBundle {
                        path,
                        reason: format!(
                            "Applications link must target /Applications, found {}",
                            target.display()
                        ),
                    });
                }
                found_applications = true;
            }
            _ => {
                return Err(MacosPackageError::InvalidBundle {
                    path,
                    reason: "unexpected visible disk image root item".to_string(),
                });
            }
        }
    }
    if !found_app || !found_applications {
        return Err(MacosPackageError::InvalidBundle {
            path: root.to_path_buf(),
            reason: "disk image must contain Silo.app and Applications -> /Applications"
                .to_string(),
        });
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
    app_notarization: Option<&NotarizationSubmission>,
    dmg_notarization: Option<&NotarizationSubmission>,
) -> Result<(), MacosPackageError> {
    let dmg_metadata = fs::metadata(dmg).map_err(|source| MacosPackageError::Io {
        operation: "inspect packaged DMG",
        path: dmg.to_path_buf(),
        source,
    })?;
    let signing = options.signing_identity.as_deref().unwrap_or("ad-hoc");
    let mut value = serde_json::json!({
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
    match (app_notarization, dmg_notarization) {
        (Some(app), Some(dmg)) => {
            let object = value
                .as_object_mut()
                .ok_or_else(|| MacosPackageError::InvalidBundle {
                    path: path.to_path_buf(),
                    reason: "macOS metadata root must be an object".to_string(),
                })?;
            object.insert(
                "notarization".to_string(),
                serde_json::json!({
                    "appSubmissionId": app.id,
                    "dmgSubmissionId": dmg.id,
                }),
            );
        }
        (None, None) => {}
        _ => {
            return Err(MacosPackageError::InvalidBundle {
                path: dmg.to_path_buf(),
                reason: "app and disk image notarization receipts must be recorded together"
                    .to_string(),
            });
        }
    }
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

fn validate_icns(path: &Path) -> Result<(), MacosPackageError> {
    let metadata = require_regular_file(path)?;
    let mut file = File::open(path).map_err(|source| MacosPackageError::Io {
        operation: "open macOS icon",
        path: path.to_path_buf(),
        source,
    })?;
    let mut header = [0_u8; 8];
    file.read_exact(&mut header)
        .map_err(|source| MacosPackageError::Io {
            operation: "read macOS icon header",
            path: path.to_path_buf(),
            source,
        })?;
    let recorded_size = u64::from(u32::from_be_bytes([
        header[4], header[5], header[6], header[7],
    ]));
    if &header[..4] != b"icns" || recorded_size != metadata.len() {
        return Err(MacosPackageError::InvalidBundle {
            path: path.to_path_buf(),
            reason: "icon must be an ICNS file with a valid length header".to_string(),
        });
    }
    Ok(())
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

fn run(command: Command) -> Result<(), MacosPackageError> {
    run_capture(command).map(|_| ())
}

fn run_capture(command: Command) -> Result<Output, MacosPackageError> {
    let (rendered, output) = capture_command(command)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(MacosPackageError::CommandFailed {
            command: rendered,
            output: command_output(&output.stdout, &output.stderr),
        })
    }
}

fn command_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    match (stdout.trim(), stderr.trim()) {
        ("", "") => "no command output".to_string(),
        (stdout, "") => stdout.to_string(),
        ("", stderr) => stderr.to_string(),
        (stdout, stderr) => format!("stdout: {stdout}; stderr: {stderr}"),
    }
}

fn capture_command(mut command: Command) -> Result<(String, Output), MacosPackageError> {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .map_err(|source| MacosPackageError::RunCommand {
            command: rendered.clone(),
            source,
        })?;
    Ok((rendered, output))
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
        assemble_app, codesign_command, codesign_dmg_command, command_output, info_plist,
        notary_log_command, notary_submit_command, notary_wait_command, parse_notary_submission,
        parse_notary_wait, validate_icns, validate_mounted_dmg_root, validate_options,
        validate_unsigned_app, write_metadata, NotarizationSubmission, PackageMacosOptions,
        COMPONENTS,
    };

    fn options(root: &Path, build_number: &str) -> PackageMacosOptions {
        PackageMacosOptions {
            build_number: build_number.to_string(),
            signing_identity: None,
            notary_keychain_profile: None,
            notary_keychain: None,
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
        assert!(plist.contains("<key>CFBundleIconFile</key>"));
        assert!(app.join("Contents/Resources/Silo.icns").is_file());
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

        let mut keychain_without_profile = options(root, "1");
        keychain_without_profile.notary_keychain = Some("release.keychain-db".into());
        assert!(validate_options(&keychain_without_profile).is_err());

        let mut production = options(root, "1");
        production.signing_identity = Some("Developer ID Application: Silo".to_string());
        production.notary_keychain_profile = Some("release".to_string());
        production.notary_keychain = Some("release.keychain-db".into());
        assert!(validate_options(&production).is_ok());
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

        let dmg_command =
            codesign_dmg_command("Developer ID Application: Silo", Path::new("Silo.dmg"));
        let dmg_args = command_args(&dmg_command);
        assert!(dmg_args
            .windows(2)
            .any(|args| args == ["--options", "runtime"]));
        assert!(dmg_args.contains(&"--timestamp".to_string()));
        assert!(!dmg_args.contains(&"--deep".to_string()));
    }

    #[test]
    fn command_failures_include_stdout_and_stderr() {
        assert_eq!(
            command_output(b"create-dmg log", b"hdiutil error"),
            "stdout: create-dmg log; stderr: hdiutil error"
        );
        assert_eq!(command_output(b"", b""), "no command output");
    }

    #[test]
    fn notary_commands_reuse_the_explicit_profile_and_keychain() {
        let keychain = Path::new("/tmp/release.keychain-db");
        let submit = notary_submit_command(Path::new("Silo.app.zip"), "silo-ci", Some(keychain));
        let submit_args = command_args(&submit);
        assert_eq!(
            submit_args,
            [
                "notarytool",
                "submit",
                "Silo.app.zip",
                "--keychain-profile",
                "silo-ci",
                "--keychain",
                "/tmp/release.keychain-db",
                "--output-format",
                "json",
            ]
        );

        let id = "12345678-1234-1234-1234-123456789abc";
        let wait = notary_wait_command(id, "silo-ci", Some(keychain));
        let wait_args = command_args(&wait);
        assert_eq!(
            wait_args,
            [
                "notarytool",
                "wait",
                id,
                "--keychain-profile",
                "silo-ci",
                "--keychain",
                "/tmp/release.keychain-db",
                "--timeout",
                "30m",
                "--output-format",
                "json",
            ]
        );

        let log = notary_log_command(id, "silo-ci", Some(keychain), Path::new("log.json"));
        let log_args = command_args(&log);
        assert_eq!(
            log_args,
            [
                "notarytool",
                "log",
                id,
                "--keychain-profile",
                "silo-ci",
                "--keychain",
                "/tmp/release.keychain-db",
                "log.json",
            ]
        );
    }

    #[test]
    fn notary_responses_require_a_uuid_and_accepted_status() {
        let path = Path::new("Silo.dmg");
        let id = "12345678-1234-1234-1234-123456789abc";
        let submission = parse_notary_submission(
            path,
            format!(r#"{{"id":"{id}","status":"In Progress"}}"#).as_bytes(),
        )
        .expect("parse submission");
        assert_eq!(submission.id, id);
        assert!(parse_notary_submission(path, br#"{"status":"In Progress"}"#).is_err());
        assert!(parse_notary_submission(path, b"not JSON").is_err());

        let log = serde_json::json!({"issues": []});
        parse_notary_wait(path, br#"{"status":"Accepted"}"#, &log).expect("accepted notarization");
        assert!(parse_notary_wait(path, br#"{"status":"Invalid"}"#, &log).is_err());
        assert!(parse_notary_wait(path, b"not JSON", &log).is_err());
    }

    #[test]
    fn mounted_image_requires_the_app_and_applications_link() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let root = temp.path();
        std::fs::create_dir(root.join("Silo.app")).expect("create app directory");
        std::os::unix::fs::symlink("/Applications", root.join("Applications"))
            .expect("create Applications link");
        std::fs::write(root.join(".DS_Store"), b"hidden").expect("write hidden metadata");
        validate_mounted_dmg_root(root).expect("validate image root");

        std::fs::remove_file(root.join("Applications")).expect("remove Applications link");
        std::os::unix::fs::symlink("/tmp", root.join("Applications"))
            .expect("create invalid Applications link");
        assert!(validate_mounted_dmg_root(root).is_err());

        std::fs::remove_file(root.join("Applications")).expect("remove invalid link");
        std::os::unix::fs::symlink("/Applications", root.join("Applications"))
            .expect("restore Applications link");
        std::fs::write(root.join("README"), b"unexpected").expect("write unexpected item");
        assert!(validate_mounted_dmg_root(root).is_err());
    }

    #[test]
    fn metadata_records_both_notarization_submission_ids() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let mut production_options = options(temp.path(), "7");
        production_options.signing_identity = Some("Developer ID Application: Silo".to_string());
        production_options.notary_keychain_profile = Some("release".to_string());
        let dmg_name = "Silo-0.1.0-darwin-arm64.dmg";
        let dmg = temp.path().join(dmg_name);
        std::fs::write(&dmg, b"dmg").expect("write DMG");
        let metadata = temp.path().join("macos.json");
        let app = NotarizationSubmission {
            id: "12345678-1234-1234-1234-123456789abc".to_string(),
        };
        let image = NotarizationSubmission {
            id: "abcdefab-1234-1234-1234-123456789abc".to_string(),
        };

        write_metadata(
            &production_options,
            &metadata,
            dmg_name,
            &dmg,
            Some(&app),
            Some(&image),
        )
        .expect("write metadata");
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(metadata).expect("read metadata"))
                .expect("parse metadata");
        assert_eq!(
            value
                .pointer("/notarization/appSubmissionId")
                .and_then(serde_json::Value::as_str),
            Some(app.id.as_str())
        );
        assert_eq!(
            value
                .pointer("/notarization/dmgSubmissionId")
                .and_then(serde_json::Value::as_str),
            Some(image.id.as_str())
        );

        let ad_hoc_options = options(temp.path(), "8");
        let ad_hoc_metadata = temp.path().join("macos-ad-hoc.json");
        write_metadata(
            &ad_hoc_options,
            &ad_hoc_metadata,
            dmg_name,
            &dmg,
            None,
            None,
        )
        .expect("write ad-hoc metadata");
        let ad_hoc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ad_hoc_metadata).expect("read ad-hoc metadata"))
                .expect("parse ad-hoc metadata");
        assert_eq!(
            ad_hoc.get("notarized"),
            Some(&serde_json::Value::Bool(false))
        );
        assert!(ad_hoc.get("notarization").is_none());
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
    fn committed_icon_has_a_valid_icns_header() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        validate_icns(&repository.join("packaging/macos/Silo.icns"))
            .expect("validate committed icon");
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
            &options.workspace_root.join("packaging/macos/Silo.icns"),
            b"icns\0\0\0\x08",
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

    fn command_args(command: &std::process::Command) -> Vec<String> {
        command
            .get_args()
            .map(|argument| argument.to_string_lossy().to_string())
            .collect()
    }
}
