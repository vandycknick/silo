use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use thiserror::Error;

use crate::command;
use crate::release;
use crate::rprobe::ASSETS as RPROBE_ASSETS;
use crate::targets::HostTarget;

const APP_NAME: &str = "Silo.app";
const BUNDLE_IDENTIFIER: &str = "sh.silo.app";
const MINIMUM_SYSTEM_VERSION: &str = "26.0";
const BRIDGE: &str = "libsilo_go_ffi.dylib";
const HELPERS: [(&str, u32, Option<&str>); 5] = [
    (BRIDGE, 0o644, None),
    ("silo-vmm", 0o755, Some("virt/vmm/silo-vmm.entitlements")),
    ("netd", 0o755, None),
    ("silod", 0o755, None),
    ("taild", 0o755, None),
];
const ASSETS: [(&str, u32); 3] = [
    ("kernel-default", 0o644),
    ("initramfs", 0o644),
    ("agent", 0o755),
];
pub(crate) fn package_directory(target_dir: &Path, version: &str) -> PathBuf {
    target_dir
        .join("packages")
        .join(version)
        .join(HostTarget::MacosArm64.runtime_target())
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Release(#[from] release::ReleaseError),
    #[error(transparent)]
    Archive(#[from] crate::archive::ArchiveError),
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error("make app requires macOS arm64")]
    UnsupportedHost,
    #[error("failed to {action} {path}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid macOS app input {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

#[derive(Clone, Copy)]
enum SigningMode<'a> {
    AdHoc,
    DeveloperId(&'a str),
}

impl SigningMode<'_> {
    fn name(self) -> &'static str {
        match self {
            Self::AdHoc => "ad-hoc",
            Self::DeveloperId(_) => "Developer ID",
        }
    }

    fn identity(&self) -> &str {
        match self {
            Self::AdHoc => "-",
            Self::DeveloperId(identity) => identity,
        }
    }

    fn is_release(self) -> bool {
        matches!(self, Self::DeveloperId(_))
    }
}

pub fn assemble(
    workspace_root: &Path,
    target_dir: &Path,
    supplied_build_number: Option<&str>,
    supplied_identity: Option<&str>,
) -> Result<(), AppError> {
    let version = product_version(workspace_root)?;
    let build_number = build_number(workspace_root, supplied_build_number)?;
    let signing = signing_mode(supplied_identity)?;
    let stage = target_dir.join("silo-runtime/darwin-arm64/release");
    let release = target_dir.join("release");
    let output = package_directory(target_dir, &version);
    create_directory(&output)?;
    let temporary = temporary_directory(&output, "Silo.app")?;
    let result = (|| {
        let contents = temporary.join("Contents");
        let macos = contents.join("MacOS");
        let helpers = contents.join("Helpers");
        let resources = contents.join("Resources");
        let assets = resources.join("assets");
        for directory in [&contents, &macos, &helpers, &resources, &assets] {
            create_directory(directory)?;
        }

        write_info_plist(
            workspace_root,
            &contents.join("Info.plist"),
            &version,
            &build_number,
        )?;
        copy_regular_file(&release.join("silo"), &macos.join("silo"), 0o755)?;
        for (name, mode, _) in HELPERS {
            let source = helper_source(&release, &stage, name);
            if name == BRIDGE {
                copy_bridge(&source, &helpers.join(name))?;
            } else {
                copy_regular_file(&source, &helpers.join(name), mode)?;
            }
        }
        copy_notices(&stage, &target_dir.join("taild-licenses"), &resources)?;
        for (name, mode) in ASSETS {
            copy_regular_file(&stage.join("assets").join(name), &assets.join(name), mode)?;
        }
        if has_rprobe_assets(&stage.join("assets"))? {
            for (name, mode) in RPROBE_ASSETS {
                copy_regular_file(&stage.join("assets").join(name), &assets.join(name), mode)?;
            }
        }
        generate_icon(workspace_root, &temporary, &resources.join("Silo.icns"))?;
        verify_unsigned_copies(&release, &stage, &temporary)?;
        validate_unsigned_layout(&temporary, &version, &build_number)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755)).map_err(|source| {
            AppError::Io {
                action: "set published app directory permissions",
                path: temporary.clone(),
                source,
            }
        })?;

        // The library must be sealed before any executable that loads it.
        sign(&helpers.join(BRIDGE), None, signing)?;
        sign(&macos.join("silo"), None, signing)?;
        for (name, _, entitlement) in HELPERS {
            if name == BRIDGE {
                continue;
            }
            let entitlement = entitlement.map(|path| workspace_root.join(path));
            sign(&helpers.join(name), entitlement.as_deref(), signing)?;
        }
        sign(&temporary, None, signing)?;
        verify_signed_bundle(&temporary)?;
        verify_selected_identity(&temporary, signing)?;

        let app = output.join(APP_NAME);
        replace_directory(&temporary, &app)?;
        verify_signed_bundle(&app)?;
        write_signed_provenance(
            &app,
            &output.join("Silo.app.provenance.json"),
            &version,
            &build_number,
            signing,
        )?;
        println!(
            "app: {} version={} build={} signing={}",
            app.display(),
            version,
            build_number,
            signing.name()
        );
        Ok(())
    })();
    if temporary.exists() {
        fs::remove_dir_all(&temporary).map_err(|source| AppError::Io {
            action: "remove temporary app bundle",
            path: temporary,
            source,
        })?;
    }
    result
}

pub fn product_version(workspace_root: &Path) -> Result<String, AppError> {
    let path = workspace_root.join("VERSION");
    let version = fs::read_to_string(&path).map_err(|source| AppError::Io {
        action: "read product version",
        path: path.clone(),
        source,
    })?;
    let version = version.trim();
    if version.is_empty() || !version.split('.').all(is_decimal_component) {
        return invalid(
            &path,
            format!("VERSION {version:?} is not a numeric dotted version"),
        );
    }
    Ok(version.to_string())
}

fn build_number(
    workspace_root: &Path,
    supplied_build_number: Option<&str>,
) -> Result<String, AppError> {
    let build_number = match supplied_build_number {
        Some(value) => value.to_string(),
        None => git_output(workspace_root, ["rev-list", "--count", "HEAD"])?,
    };
    if !build_number.split('.').all(is_decimal_component) {
        return invalid(
            workspace_root,
            format!("build number {build_number:?} is not numeric or dotted-numeric"),
        );
    }
    Ok(build_number)
}

fn is_decimal_component(component: &str) -> bool {
    !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
}

fn signing_mode(identity: Option<&str>) -> Result<SigningMode<'_>, AppError> {
    match identity {
        None => Ok(SigningMode::AdHoc),
        Some(identity) if identity.starts_with("Developer ID Application:") => {
            Ok(SigningMode::DeveloperId(identity))
        }
        Some(identity) => invalid(
            Path::new("DEVELOPER_ID_APPLICATION"),
            format!("must name a Developer ID Application identity, got {identity:?}"),
        ),
    }
}

fn write_info_plist(
    workspace_root: &Path,
    destination: &Path,
    version: &str,
    build_number: &str,
) -> Result<(), AppError> {
    let template_path = workspace_root.join("packaging/macos/Info.plist.in");
    let template = fs::read_to_string(&template_path).map_err(|source| AppError::Io {
        action: "read Info.plist template",
        path: template_path.clone(),
        source,
    })?;
    let plist = template
        .replace("@VERSION@", version)
        .replace("@BUILD_NUMBER@", build_number);
    if plist.contains('@') {
        return invalid(
            &template_path,
            "contains an unresolved template marker".to_string(),
        );
    }
    fs::write(destination, plist).map_err(|source| AppError::Io {
        action: "write Info.plist",
        path: destination.to_path_buf(),
        source,
    })?;
    let mut lint = Command::new("/usr/bin/plutil");
    lint.args(["-lint"]).arg(destination);
    command::run(lint)?;
    for (key, expected) in [
        ("CFBundleIdentifier", BUNDLE_IDENTIFIER),
        ("CFBundleExecutable", "silo"),
        ("CFBundleShortVersionString", version),
        ("CFBundleVersion", build_number),
        ("LSArchitecturePriority:0", "arm64"),
        ("LSMinimumSystemVersion", MINIMUM_SYSTEM_VERSION),
    ] {
        let value = plist_value(destination, key)?;
        if value != expected {
            return invalid(
                destination,
                format!("{key} is {value:?}, expected {expected:?}"),
            );
        }
    }
    Ok(())
}

fn plist_value(path: &Path, key: &str) -> Result<String, AppError> {
    let mut command = Command::new("/usr/libexec/PlistBuddy");
    command.args(["-c", &format!("Print :{key}")]).arg(path);
    let output = command::output(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn generate_icon(workspace_root: &Path, bundle: &Path, destination: &Path) -> Result<(), AppError> {
    let source = workspace_root.join("docs/brand/silo-mark-transparent@4x.png");
    validate_regular_file(&source, None)?;
    let iconset = bundle.join(".Silo.iconset");
    create_directory(&iconset)?;
    let result = (|| {
        for (name, size) in [
            ("icon_16x16.png", 16),
            ("icon_16x16@2x.png", 32),
            ("icon_32x32.png", 32),
            ("icon_32x32@2x.png", 64),
            ("icon_128x128.png", 128),
            ("icon_128x128@2x.png", 256),
            ("icon_256x256.png", 256),
            ("icon_256x256@2x.png", 512),
            ("icon_512x512.png", 512),
            ("icon_512x512@2x.png", 1024),
        ] {
            let image = iconset.join(name);
            let mut resize = Command::new("/usr/bin/sips");
            resize
                .args(["--resampleHeightWidthMax", &size.to_string()])
                .arg(&source)
                .args(["--out"])
                .arg(&image);
            command::run(resize)?;
            let mut pad = Command::new("/usr/bin/sips");
            pad.args([
                "--padToHeightWidth",
                &size.to_string(),
                &size.to_string(),
                "--padColor",
                "000000",
            ])
            .arg(&image);
            command::run(pad)?;
        }
        let mut iconutil = Command::new("/usr/bin/iconutil");
        iconutil.args(["-c", "icns"]).arg(&iconset).args(["-o"]);
        iconutil.arg(destination);
        command::run(iconutil)?;
        validate_regular_file(destination, None)
    })();
    fs::remove_dir_all(&iconset).map_err(|source| AppError::Io {
        action: "remove temporary iconset",
        path: iconset,
        source,
    })?;
    result
}

fn helper_source(release: &Path, stage: &Path, name: &str) -> PathBuf {
    match name {
        "silo-vmm" | "netd" => stage.join("bin").join(name),
        _ => release.join(name),
    }
}

fn verify_unsigned_copies(release: &Path, stage: &Path, bundle: &Path) -> Result<(), AppError> {
    compare_files(&release.join("silo"), &bundle.join("Contents/MacOS/silo"))?;
    for (name, _, _) in HELPERS {
        compare_files(
            &helper_source(release, stage, name),
            &bundle.join("Contents/Helpers").join(name),
        )?;
    }
    for (name, _) in ASSETS {
        compare_files(
            &stage.join("assets").join(name),
            &bundle.join("Contents/Resources/assets").join(name),
        )?;
    }
    if has_rprobe_assets(&stage.join("assets"))? {
        for (name, _) in RPROBE_ASSETS {
            compare_files(
                &stage.join("assets").join(name),
                &bundle.join("Contents/Resources/assets").join(name),
            )?;
        }
    }
    compare_notices(
        stage,
        &release
            .parent()
            .ok_or_else(|| AppError::Invalid {
                path: release.to_path_buf(),
                reason: "release directory has no parent".to_string(),
            })?
            .join("taild-licenses"),
        &bundle.join("Contents/Resources"),
    )?;
    Ok(())
}

fn validate_unsigned_layout(
    bundle: &Path,
    version: &str,
    build_number: &str,
) -> Result<(), AppError> {
    validate_bundle_filesystem(bundle, false)?;
    let contents = bundle.join("Contents");
    for (key, expected) in [
        ("CFBundleIdentifier", BUNDLE_IDENTIFIER),
        ("CFBundleExecutable", "silo"),
        ("CFBundleShortVersionString", version),
        ("CFBundleVersion", build_number),
        ("LSArchitecturePriority:0", "arm64"),
        ("LSMinimumSystemVersion", MINIMUM_SYSTEM_VERSION),
    ] {
        let actual = plist_value(&contents.join("Info.plist"), key)?;
        if actual != expected {
            return invalid(
                &contents.join("Info.plist"),
                format!("{key} is {actual:?}, expected {expected:?}"),
            );
        }
    }
    Ok(())
}

fn sign(path: &Path, entitlement: Option<&Path>, mode: SigningMode<'_>) -> Result<(), AppError> {
    let mut command = Command::new("/usr/bin/codesign");
    command.args(["--force", "--sign", mode.identity()]);
    if mode.is_release() {
        command.args(["--options", "runtime", "--timestamp"]);
    }
    if let Some(entitlement) = entitlement {
        command.args(["--entitlements"]).arg(entitlement);
    }
    command.arg(path);
    command::run(command)?;
    Ok(())
}

fn verify_signature(path: &Path) -> Result<(), AppError> {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .args(["--verify", "--strict", "--verbose=4"])
        .arg(path);
    command::run(command)?;
    Ok(())
}

fn verify_entitlements(path: &Path, expected_keys: &[&str]) -> Result<(), AppError> {
    let mut command = Command::new("/usr/bin/codesign");
    command.args(["-d", "--entitlements", ":-"]).arg(path);
    let output = command.output().map_err(|source| AppError::Io {
        action: "inspect signed entitlements",
        path: path.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        return invalid(
            path,
            format!(
                "codesign entitlement inspection exited with {}",
                output.status
            ),
        );
    }
    let actual = entitlement_map(path, &output.stdout)?;
    let expected = expected_keys
        .iter()
        .map(|key| ((*key).to_string(), true))
        .collect::<BTreeMap<_, _>>();
    if actual != expected {
        return invalid(
            path,
            format!("entitlements are {actual:?}, expected {expected:?}"),
        );
    }
    Ok(())
}

fn entitlement_map(path: &Path, plist: &[u8]) -> Result<BTreeMap<String, bool>, AppError> {
    if plist.iter().all(u8::is_ascii_whitespace) {
        return Ok(BTreeMap::new());
    }
    let mut command = Command::new("/usr/bin/plutil");
    command
        .args(["-convert", "json", "-o", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = command.spawn().map_err(|source| AppError::Io {
        action: "convert signed entitlements to JSON",
        path: path.to_path_buf(),
        source,
    })?;
    let mut input = child.stdin.take().ok_or_else(|| AppError::Invalid {
        path: path.to_path_buf(),
        reason: "plutil has no entitlement input pipe".to_string(),
    })?;
    input.write_all(plist).map_err(|source| AppError::Io {
        action: "write signed entitlements to plutil",
        path: path.to_path_buf(),
        source,
    })?;
    drop(input);
    let output = child.wait_with_output().map_err(|source| AppError::Io {
        action: "read converted signed entitlements",
        path: path.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        return invalid(
            path,
            format!(
                "plutil entitlement conversion exited with {}",
                output.status
            ),
        );
    }
    let values = serde_json::from_slice::<BTreeMap<String, serde_json::Value>>(&output.stdout)
        .map_err(|error| AppError::Invalid {
            path: path.to_path_buf(),
            reason: format!("parse signed entitlements as JSON: {error}"),
        })?;
    values
        .into_iter()
        .map(|(key, value)| match value {
            serde_json::Value::Bool(value) => Ok((key, value)),
            value => Err(AppError::Invalid {
                path: path.to_path_buf(),
                reason: format!("entitlement {key:?} is not a boolean: {value}"),
            }),
        })
        .collect()
}

pub fn verify_signed_bundle(bundle: &Path) -> Result<(), AppError> {
    validate_distribution_layout(bundle)?;
    verify_signature(bundle)?;
    let identity = signature_identity(bundle)?;
    for path in signed_code_paths(bundle) {
        verify_signature(&path)?;
        ensure_same_identity(&path, &identity, &signature_identity(&path)?)?;
    }
    verify_entitlements(
        &bundle.join("Contents/Helpers/silo-vmm"),
        &[
            "com.apple.security.hypervisor",
            "com.apple.security.virtualization",
        ],
    )?;
    verify_entitlements(bundle, &[])?;
    verify_entitlements(&bundle.join("Contents/MacOS/silo"), &[])?;
    for (name, _, entitlement) in HELPERS {
        if entitlement.is_none() {
            verify_entitlements(&bundle.join("Contents/Helpers").join(name), &[])?;
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct SignatureIdentity {
    certificate_sha256: Option<String>,
    team_identifier: Option<String>,
    authorities: Vec<String>,
    ad_hoc: bool,
}

fn signed_code_paths(bundle: &Path) -> Vec<PathBuf> {
    let mut paths = vec![bundle.join("Contents/MacOS/silo")];
    paths.extend(
        HELPERS
            .iter()
            .map(|(name, _, _)| bundle.join("Contents/Helpers").join(name)),
    );
    paths
}

fn signature_identity(path: &Path) -> Result<SignatureIdentity, AppError> {
    let mut inspect = Command::new("/usr/bin/codesign");
    inspect.args(["--display", "--verbose=4"]).arg(path);
    let output = command::output(inspect)?;
    let details = String::from_utf8_lossy(&output.stderr);
    let ad_hoc = details.lines().any(|line| line == "Signature=adhoc");
    let authorities = details
        .lines()
        .filter_map(|line| line.strip_prefix("Authority=").map(str::to_string))
        .collect::<Vec<_>>();
    let team_identifier = details
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))
        .filter(|value| *value != "not set")
        .map(str::to_string);
    let certificate_sha256 = if ad_hoc {
        if !authorities.is_empty() || team_identifier.is_some() {
            return invalid(
                path,
                "ad-hoc signature unexpectedly has a signing authority".to_string(),
            );
        }
        None
    } else {
        if authorities.is_empty() || team_identifier.is_none() {
            return invalid(
                path,
                "signature has no certificate authority or team identity".to_string(),
            );
        }
        let certificates = tempfile::tempdir().map_err(|source| AppError::Io {
            action: "create signature certificate directory",
            path: path.to_path_buf(),
            source,
        })?;
        let prefix = certificates.path().join("certificate");
        let mut certificate_option = std::ffi::OsString::from("--extract-certificates=");
        certificate_option.push(&prefix);
        let mut extract = Command::new("/usr/bin/codesign");
        extract.arg("--display").arg(certificate_option).arg(path);
        command::run(extract)?;
        let leaf = certificates.path().join("certificate0");
        validate_regular_file(&leaf, None)?;
        Some(crate::archive::sha256(&leaf)?)
    };
    Ok(SignatureIdentity {
        certificate_sha256,
        team_identifier,
        authorities,
        ad_hoc,
    })
}

fn ensure_same_identity(
    path: &Path,
    expected: &SignatureIdentity,
    actual: &SignatureIdentity,
) -> Result<(), AppError> {
    if expected != actual {
        return invalid(
            path,
            format!("nested signing identity {actual:?} differs from app {expected:?}"),
        );
    }
    Ok(())
}

fn verify_selected_identity(bundle: &Path, selected: SigningMode<'_>) -> Result<(), AppError> {
    let actual = signature_identity(bundle)?;
    match selected {
        SigningMode::AdHoc if actual.ad_hoc => Ok(()),
        SigningMode::DeveloperId(identity)
            if !actual.ad_hoc
                && actual.authorities.first().map(String::as_str) == Some(identity) =>
        {
            Ok(())
        }
        _ => invalid(
            bundle,
            format!(
                "signature {actual:?} does not use selected identity {:?}",
                selected.identity()
            ),
        ),
    }
}

fn signed_file_hashes(bundle: &Path) -> Result<BTreeMap<String, String>, AppError> {
    regular_tree(bundle)?
        .into_iter()
        .map(|relative| {
            let name = relative.to_str().ok_or_else(|| AppError::Invalid {
                path: bundle.join(&relative),
                reason: "non-UTF-8 signed artifact path".to_string(),
            })?;
            Ok((
                name.to_string(),
                crate::archive::sha256(&bundle.join(&relative))?,
            ))
        })
        .collect()
}

fn write_signed_provenance(
    bundle: &Path,
    output: &Path,
    version: &str,
    build_number: &str,
    signing: SigningMode<'_>,
) -> Result<(), AppError> {
    let identity = signature_identity(bundle)?;
    let provenance = serde_json::json!({
        "schema": "https://silo.dev/app-provenance/v1",
        "version": version,
        "build": build_number,
        "target": HostTarget::MacosArm64.runtime_target(),
        "signing": {
            "selected_identity": signing.identity(),
            "certificate_sha256": identity.certificate_sha256,
            "team_identifier": identity.team_identifier,
            "authorities": identity.authorities,
            "ad_hoc": identity.ad_hoc,
        },
        "files": signed_file_hashes(bundle)?,
    });
    let bytes = serde_json::to_vec_pretty(&provenance).map_err(|error| AppError::Invalid {
        path: output.to_path_buf(),
        reason: format!("serialize signed app provenance: {error}"),
    })?;
    let parent = output.parent().ok_or_else(|| AppError::Invalid {
        path: output.to_path_buf(),
        reason: "provenance path has no parent".to_string(),
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|source| AppError::Io {
        action: "create signed app provenance",
        path: output.to_path_buf(),
        source,
    })?;
    temporary.write_all(&bytes).map_err(|source| AppError::Io {
        action: "write signed app provenance",
        path: output.to_path_buf(),
        source,
    })?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|source| AppError::Io {
            action: "set signed app provenance mode",
            path: output.to_path_buf(),
            source,
        })?;
    temporary.persist(output).map_err(|error| AppError::Io {
        action: "publish signed app provenance",
        path: output.to_path_buf(),
        source: error.error,
    })?;
    Ok(())
}

pub fn has_bundle_identifier(bundle: &Path) -> Result<bool, AppError> {
    Ok(
        plist_value(&bundle.join("Contents/Info.plist"), "CFBundleIdentifier")?
            == BUNDLE_IDENTIFIER,
    )
}

pub fn is_owned_cli_symlink(path: &Path) -> Result<bool, AppError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(AppError::Io {
                action: "read installed CLI metadata",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.file_type().is_symlink() {
        return Ok(false);
    }
    let executable = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => return Ok(false),
    };
    let Some(macos) = executable.parent() else {
        return Ok(false);
    };
    let Some(contents) = macos.parent() else {
        return Ok(false);
    };
    let Some(bundle) = contents.parent() else {
        return Ok(false);
    };
    if executable.file_name().and_then(|name| name.to_str()) != Some("silo")
        || macos.file_name().and_then(|name| name.to_str()) != Some("MacOS")
        || contents.file_name().and_then(|name| name.to_str()) != Some("Contents")
        || bundle.file_name().and_then(|name| name.to_str()) != Some(APP_NAME)
    {
        return Ok(false);
    }
    has_bundle_identifier(bundle)
}

pub fn replace_bundle(temporary: &Path, final_path: &Path) -> Result<(), AppError> {
    replace_directory(temporary, final_path)
}

fn validate_distribution_layout(bundle: &Path) -> Result<(), AppError> {
    validate_bundle_filesystem(bundle, true)?;
    let contents = bundle.join("Contents");
    for (key, expected) in [
        ("CFBundleIdentifier", BUNDLE_IDENTIFIER),
        ("CFBundleExecutable", "silo"),
        ("LSArchitecturePriority:0", "arm64"),
        ("LSMinimumSystemVersion", MINIMUM_SYSTEM_VERSION),
    ] {
        let actual = plist_value(&contents.join("Info.plist"), key)?;
        if actual != expected {
            return invalid(
                &contents.join("Info.plist"),
                format!("{key} is {actual:?}, expected {expected:?}"),
            );
        }
    }
    for key in ["CFBundleShortVersionString", "CFBundleVersion"] {
        let value = plist_value(&contents.join("Info.plist"), key)?;
        if !value.split('.').all(is_decimal_component) {
            return invalid(
                &contents.join("Info.plist"),
                format!("{key} {value:?} is not numeric or dotted-numeric"),
            );
        }
    }
    Ok(())
}

fn validate_bundle_filesystem(bundle: &Path, signed: bool) -> Result<(), AppError> {
    if signed {
        let metadata = fs::symlink_metadata(bundle).map_err(|source| AppError::Io {
            action: "read published app directory permissions",
            path: bundle.to_path_buf(),
            source,
        })?;
        if metadata.permissions().mode() & 0o7777 != 0o755 {
            return invalid(
                bundle,
                "published app directory must have mode 0755".to_string(),
            );
        }
    }
    validate_directory_entries(bundle, ["Contents"])?;
    let contents = bundle.join("Contents");
    if signed {
        validate_directory_entries(
            &contents,
            [
                "_CodeSignature",
                "Helpers",
                "Info.plist",
                "MacOS",
                "Resources",
            ],
        )?;
        validate_directory_entries(&contents.join("_CodeSignature"), ["CodeResources"])?;
        validate_regular_file(&contents.join("_CodeSignature/CodeResources"), None)?;
    } else {
        validate_directory_entries(&contents, ["Helpers", "Info.plist", "MacOS", "Resources"])?;
    }
    validate_payload_layout(&contents)
}

fn validate_payload_layout(contents: &Path) -> Result<(), AppError> {
    validate_directory_entries(&contents.join("MacOS"), ["silo"])?;
    validate_directory_entries(
        &contents.join("Helpers"),
        [BRIDGE, "netd", "silo-vmm", "silod", "taild"],
    )?;
    validate_directory_entries(
        &contents.join("Resources"),
        ["Silo.icns", "assets", "THIRD_PARTY_NOTICES", "LICENSES"],
    )?;
    validate_asset_entries(&contents.join("Resources/assets"))?;
    validate_regular_file(&contents.join("Info.plist"), None)?;
    validate_regular_file(&contents.join("MacOS/silo"), Some(0o755))?;
    for (name, mode, _) in HELPERS {
        validate_regular_file(&contents.join("Helpers").join(name), Some(mode))?;
    }
    for (name, mode) in ASSETS {
        validate_regular_file(&contents.join("Resources/assets").join(name), Some(mode))?;
    }
    if has_rprobe_assets(&contents.join("Resources/assets"))? {
        for (name, mode) in RPROBE_ASSETS {
            validate_regular_file(&contents.join("Resources/assets").join(name), Some(mode))?;
        }
    }
    validate_regular_file(&contents.join("Resources/Silo.icns"), None)?;
    let resources = contents.join("Resources");
    validate_regular_file(&resources.join("THIRD_PARTY_NOTICES"), Some(0o644))?;
    validate_directory_entries(&resources.join("LICENSES"), ["APACHE-2.0.txt", "taild"])?;
    validate_regular_file(&resources.join("LICENSES/APACHE-2.0.txt"), Some(0o644))?;
    taild_notice_inventory(&resources.join("LICENSES/taild"))?;
    Ok(())
}

fn validate_real_directory(path: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| AppError::Io {
        action: "read app directory metadata",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return invalid(path, "is not a real non-symlink directory".to_string());
    }
    Ok(())
}

// No symlink may redirect notices or signed provenance outside the artifact.
fn regular_tree(root: &Path) -> Result<BTreeSet<PathBuf>, AppError> {
    validate_real_directory(root)?;
    let mut files = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|source| AppError::Io {
        action: "read app file inventory",
        path: root.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| AppError::Io {
            action: "read app inventory entry",
            path: root.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|source| AppError::Io {
            action: "read app inventory entry type",
            path: path.clone(),
            source,
        })?;
        if entry.file_name().to_str().is_none() {
            return invalid(&path, "contains a non-UTF-8 name".to_string());
        }
        if kind.is_dir() {
            let nested = regular_tree(&path)?;
            if nested.is_empty() {
                return invalid(&path, "contains an empty unlisted directory".to_string());
            }
            for relative in nested {
                files.insert(PathBuf::from(entry.file_name()).join(relative));
            }
        } else {
            validate_regular_file(&path, None)?;
            files.insert(PathBuf::from(entry.file_name()));
        }
    }
    Ok(files)
}

fn safe_notice_path(root: &Path, value: &str) -> Result<PathBuf, AppError> {
    if value.is_empty()
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || value.contains('\\')
        || Path::new(value).is_absolute()
    {
        return invalid(root, format!("unsafe notice path {value:?}"));
    }
    Ok(PathBuf::from(value))
}

fn taild_notice_inventory(root: &Path) -> Result<BTreeSet<PathBuf>, AppError> {
    let actual = regular_tree(root)?;
    let manifest = root.join("modules.json");
    validate_regular_file(&manifest, Some(0o644))?;
    let bytes = fs::read(&manifest).map_err(|source| AppError::Io {
        action: "read taild notice manifest",
        path: manifest.clone(),
        source,
    })?;
    let modules: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| AppError::Invalid {
            path: manifest.clone(),
            reason: format!("parse taild notices: {error}"),
        })?;
    let modules = modules.as_array().ok_or_else(|| AppError::Invalid {
        path: manifest.clone(),
        reason: "taild notice manifest is not an array".to_string(),
    })?;
    if modules.is_empty() {
        return invalid(
            &manifest,
            "taild notice manifest has no dependencies".to_string(),
        );
    }
    let mut expected = BTreeSet::from([PathBuf::from("modules.json")]);
    let mut seen = BTreeSet::new();
    for module in modules {
        let name = module["module"].as_str().ok_or_else(|| AppError::Invalid {
            path: manifest.clone(),
            reason: "notice entry has no module name".to_string(),
        })?;
        let module_path = safe_notice_path(&manifest, name)?;
        if !seen.insert(name) {
            return invalid(&manifest, format!("duplicate module {name:?}"));
        }
        let version = match &module["version"] {
            serde_json::Value::Null => "local",
            serde_json::Value::String(value) => value,
            _ => return invalid(&manifest, format!("invalid version for {name:?}")),
        };
        let version_path = safe_notice_path(&manifest, version)?;
        if version_path.components().count() != 1 {
            return invalid(&manifest, format!("invalid version for {name:?}"));
        }
        let prefix = module_path.join(version_path);
        let notices = module["notices"]
            .as_array()
            .ok_or_else(|| AppError::Invalid {
                path: manifest.clone(),
                reason: format!("module {name:?} has no notice array"),
            })?;
        if notices.is_empty() {
            return invalid(&manifest, format!("module {name:?} has no notices"));
        }
        for notice in notices {
            let notice = notice.as_str().ok_or_else(|| AppError::Invalid {
                path: manifest.clone(),
                reason: "notice path is not a string".to_string(),
            })?;
            let relative = safe_notice_path(&manifest, notice)?;
            if relative.parent() != Some(prefix.as_path()) || !expected.insert(relative.clone()) {
                return invalid(
                    &manifest,
                    format!("unexpected or duplicate notice {notice:?}"),
                );
            }
            validate_regular_file(&root.join(relative), Some(0o644))?;
        }
    }
    if actual != expected {
        return invalid(
            root,
            format!("notice files are {actual:?}, expected {expected:?}"),
        );
    }
    Ok(actual)
}

fn copy_notices(stage: &Path, taild: &Path, resources: &Path) -> Result<(), AppError> {
    copy_regular_file(
        &stage.join("THIRD_PARTY_NOTICES"),
        &resources.join("THIRD_PARTY_NOTICES"),
        0o644,
    )?;
    create_directory(&resources.join("LICENSES"))?;
    validate_real_directory(&stage.join("LICENSES"))?;
    copy_regular_file(
        &stage.join("LICENSES/APACHE-2.0.txt"),
        &resources.join("LICENSES/APACHE-2.0.txt"),
        0o644,
    )?;
    let destination = resources.join("LICENSES/taild");
    create_directory(&destination)?;
    for relative in taild_notice_inventory(taild)? {
        let output = destination.join(&relative);
        if let Some(parent) = output.parent() {
            create_directory(parent)?;
        }
        copy_regular_file(&taild.join(relative), &output, 0o644)?;
    }
    Ok(())
}

fn compare_notices(stage: &Path, taild: &Path, resources: &Path) -> Result<(), AppError> {
    for relative in ["THIRD_PARTY_NOTICES", "LICENSES/APACHE-2.0.txt"] {
        compare_files(&stage.join(relative), &resources.join(relative))?;
    }
    let destination = resources.join("LICENSES/taild");
    let source_files = taild_notice_inventory(taild)?;
    if source_files != taild_notice_inventory(&destination)? {
        return invalid(
            &destination,
            "notice inventory differs from source".to_string(),
        );
    }
    for relative in source_files {
        compare_files(&taild.join(&relative), &destination.join(relative))?;
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path, mode: u32) -> Result<(), AppError> {
    validate_regular_file(source, Some(mode))?;
    copy_validated_file(source, destination, mode)
}

fn copy_bridge(source: &Path, destination: &Path) -> Result<(), AppError> {
    // Cargo's shared-library output can be executable; the bundled dylib is data.
    validate_regular_file(source, None)?;
    copy_validated_file(source, destination, 0o644)
}

fn copy_validated_file(source: &Path, destination: &Path, mode: u32) -> Result<(), AppError> {
    fs::copy(source, destination).map_err(|source_error| AppError::Io {
        action: "copy app input",
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode)).map_err(|source| {
        AppError::Io {
            action: "set app file mode",
            path: destination.to_path_buf(),
            source,
        }
    })?;
    validate_regular_file(destination, Some(mode))
}

fn compare_files(source: &Path, destination: &Path) -> Result<(), AppError> {
    let source_bytes = fs::read(source).map_err(|error| AppError::Io {
        action: "read app source copy",
        path: source.to_path_buf(),
        source: error,
    })?;
    let destination_bytes = fs::read(destination).map_err(|error| AppError::Io {
        action: "read app bundle copy",
        path: destination.to_path_buf(),
        source: error,
    })?;
    if source_bytes == destination_bytes {
        Ok(())
    } else {
        invalid(
            destination,
            format!(
                "does not match {} byte-for-byte before signing",
                source.display()
            ),
        )
    }
}

fn validate_directory_entries<const N: usize>(
    directory: &Path,
    expected: [&str; N],
) -> Result<(), AppError> {
    validate_real_directory(directory)?;
    let entries = fs::read_dir(directory).map_err(|source| AppError::Io {
        action: "read app bundle directory",
        path: directory.to_path_buf(),
        source,
    })?;
    let mut actual = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| AppError::Io {
            action: "read app bundle directory entry",
            path: directory.to_path_buf(),
            source,
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| AppError::Invalid {
                path: directory.to_path_buf(),
                reason: "contains a non-UTF-8 name".to_string(),
            })?;
        actual.insert(name);
    }
    let expected = expected.into_iter().map(str::to_string).collect();
    if actual == expected {
        Ok(())
    } else {
        invalid(
            directory,
            format!("contains {actual:?}, expected {expected:?}"),
        )
    }
}

fn validate_asset_entries(assets: &Path) -> Result<(), AppError> {
    if has_rprobe_assets(assets)? {
        validate_directory_entries(assets, ["agent", "initramfs", "kernel-default", "rprobe"])
    } else {
        validate_directory_entries(assets, ["agent", "initramfs", "kernel-default"])
    }
}

fn has_rprobe_assets(assets: &Path) -> Result<bool, AppError> {
    crate::rprobe::installed_asset_set_present(assets).map_err(|source| AppError::Io {
        action: "read rprobe asset metadata",
        path: assets.to_path_buf(),
        source,
    })
}

fn validate_regular_file(path: &Path, expected_mode: Option<u32>) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| AppError::Io {
        action: "read app input metadata",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return invalid(path, "is not a regular non-symlink file".to_string());
    }
    if let Some(expected_mode) = expected_mode {
        let mode = metadata.permissions().mode() & 0o7777;
        if mode != expected_mode {
            return invalid(
                path,
                format!("has mode {mode:o}, expected {expected_mode:o}"),
            );
        }
    }
    Ok(())
}

fn create_directory(path: &Path) -> Result<(), AppError> {
    fs::create_dir_all(path).map_err(|source| AppError::Io {
        action: "create app bundle directory",
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| AppError::Io {
        action: "read app bundle directory metadata",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return invalid(path, "is not a real directory".to_string());
    }
    Ok(())
}

fn temporary_directory(parent: &Path, name: &str) -> Result<PathBuf, AppError> {
    create_directory(parent)?;
    for attempt in 0..128 {
        let path = parent.join(format!(".{name}-{}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                    |source| AppError::Io {
                        action: "secure temporary app bundle directory",
                        path: path.clone(),
                        source,
                    },
                )?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(AppError::Io {
                    action: "create temporary app bundle directory",
                    path,
                    source,
                });
            }
        }
    }
    invalid(
        parent,
        "could not create a temporary app bundle directory".to_string(),
    )
}

fn replace_directory(temporary: &Path, final_path: &Path) -> Result<(), AppError> {
    let parent = final_path.parent().ok_or_else(|| AppError::Invalid {
        path: final_path.to_path_buf(),
        reason: "has no parent directory".to_string(),
    })?;
    create_directory(parent)?;
    match fs::symlink_metadata(final_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return invalid(final_path, "is not a real directory".to_string());
            }
            let temporary_name = temporary.file_name().ok_or_else(|| AppError::Invalid {
                path: temporary.to_path_buf(),
                reason: "has no file name".to_string(),
            })?;
            let final_name = final_path.file_name().ok_or_else(|| AppError::Invalid {
                path: final_path.to_path_buf(),
                reason: "has no file name".to_string(),
            })?;
            let parent_file = File::open(parent).map_err(|source| AppError::Io {
                action: "open app bundle output directory",
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
            .map_err(|source| AppError::Invalid {
                path: final_path.to_path_buf(),
                reason: format!("atomically exchange app bundle: {source}"),
            })?;
            fs::remove_dir_all(temporary).map_err(|source| AppError::Io {
                action: "remove prior app bundle",
                path: temporary.to_path_buf(),
                source,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::rename(temporary, final_path).map_err(|source| AppError::Io {
                action: "install app bundle",
                path: final_path.to_path_buf(),
                source,
            })
        }
        Err(source) => Err(AppError::Io {
            action: "read app bundle output metadata",
            path: final_path.to_path_buf(),
            source,
        }),
    }
}

fn git_output(
    workspace_root: &Path,
    args: impl IntoIterator<Item = &'static str>,
) -> Result<String, AppError> {
    let mut command = Command::new(release::tool("git")?);
    command.current_dir(workspace_root).args(args);
    let output = command::output(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn invalid<T>(path: &Path, reason: String) -> Result<T, AppError> {
    Err(AppError::Invalid {
        path: path.to_path_buf(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    use crate::app::{
        compare_notices, copy_bridge, copy_notices, copy_regular_file, ensure_same_identity,
        helper_source, signed_code_paths, signed_file_hashes, taild_notice_inventory,
        validate_bundle_filesystem, verify_unsigned_copies, SignatureIdentity, ASSETS, BRIDGE,
        HELPERS,
    };

    fn file(path: &Path, bytes: &[u8], mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn notices(root: &Path) {
        file(
            &root.join("example.org/dependency/v1.2.3/LICENSE"),
            b"dependency license",
            0o644,
        );
        file(&root.join("modules.json"), br#"[{"module":"example.org/dependency","version":"v1.2.3","notices":["example.org/dependency/v1.2.3/LICENSE"]}]"#, 0o644);
    }

    fn fixture(root: &Path) -> std::path::PathBuf {
        let release = root.join("release");
        let stage = root.join("stage");
        let bundle = root.join("Silo.app");
        let contents = bundle.join("Contents");
        file(&release.join("silo"), b"cli", 0o755);
        file(
            &contents.join("Info.plist"),
            b"filesystem fixture, not a signed app",
            0o644,
        );
        file(&contents.join("Resources/Silo.icns"), b"icon", 0o644);
        fs::create_dir_all(contents.join("MacOS")).unwrap();
        copy_regular_file(&release.join("silo"), &contents.join("MacOS/silo"), 0o755).unwrap();
        for (name, mode, _) in HELPERS {
            let source = helper_source(&release, &stage, name);
            file(&source, format!("actual input {name}").as_bytes(), mode);
            let output = contents.join("Helpers").join(name);
            fs::create_dir_all(output.parent().unwrap()).unwrap();
            copy_regular_file(&source, &output, mode).unwrap();
        }
        for (name, mode) in ASSETS {
            let source = stage.join("assets").join(name);
            file(&source, name.as_bytes(), mode);
            let output = contents.join("Resources/assets").join(name);
            fs::create_dir_all(output.parent().unwrap()).unwrap();
            copy_regular_file(&source, &output, mode).unwrap();
        }
        file(
            &stage.join("THIRD_PARTY_NOTICES"),
            b"runtime notices",
            0o644,
        );
        file(
            &stage.join("LICENSES/APACHE-2.0.txt"),
            b"Apache license",
            0o644,
        );
        notices(&root.join("taild-licenses"));
        copy_notices(
            &stage,
            &root.join("taild-licenses"),
            &contents.join("Resources"),
        )
        .unwrap();
        bundle
    }

    #[test]
    fn integrated_app_copies_release_frontends_bridge_and_complete_notices() {
        let root = tempfile::tempdir().unwrap();
        let bundle = fixture(root.path());
        validate_bundle_filesystem(&bundle, false).unwrap();
        verify_unsigned_copies(
            &root.path().join("release"),
            &root.path().join("stage"),
            &bundle,
        )
        .unwrap();
        assert!(root.path().join("release/taild").is_file());
        assert!(root.path().join("release").join(BRIDGE).is_file());
        assert!(!root.path().join("stage/bin/taild").exists());
        assert!(!root.path().join("stage/bin").join(BRIDGE).exists());
        file(
            &bundle.join("Contents/Helpers/taild"),
            b"changed helper",
            0o755,
        );
        assert!(verify_unsigned_copies(
            &root.path().join("release"),
            &root.path().join("stage"),
            &bundle
        )
        .is_err());
    }

    #[test]
    fn unsigned_and_distribution_layouts_reject_missing_extra_and_wrong_mode_helpers() {
        let root = tempfile::tempdir().unwrap();
        let bundle = fixture(root.path());
        file(
            &bundle.join("Contents/_CodeSignature/CodeResources"),
            b"resource inventory only",
            0o644,
        );
        validate_bundle_filesystem(&bundle, true).unwrap();
        assert!(validate_bundle_filesystem(&bundle, false).is_err());
        for mode in [0o700, 0o775, 0o4755] {
            fs::set_permissions(&bundle, fs::Permissions::from_mode(mode)).unwrap();
            assert!(validate_bundle_filesystem(&bundle, true).is_err());
        }
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o755)).unwrap();
        let bridge = bundle.join("Contents/Helpers").join(BRIDGE);
        for mode in [0o755, 0o600, 0o4644] {
            fs::set_permissions(&bridge, fs::Permissions::from_mode(mode)).unwrap();
            assert!(validate_bundle_filesystem(&bundle, true).is_err());
        }
        fs::set_permissions(&bridge, fs::Permissions::from_mode(0o644)).unwrap();
        file(&bundle.join("Contents/Helpers/unexpected"), b"extra", 0o755);
        assert!(validate_bundle_filesystem(&bundle, true).is_err());
        fs::remove_file(bundle.join("Contents/Helpers/unexpected")).unwrap();
        for (name, mode, _) in HELPERS {
            let path = bundle.join("Contents/Helpers").join(name);
            fs::remove_file(&path).unwrap();
            assert!(validate_bundle_filesystem(&bundle, true).is_err());
            file(&path, b"restored", mode);
        }
        validate_bundle_filesystem(&bundle, true).unwrap();
    }

    #[test]
    fn notices_reject_unlisted_missing_unsafe_and_symlink_material() {
        let root = tempfile::tempdir().unwrap();
        notices(root.path());
        taild_notice_inventory(root.path()).unwrap();
        file(&root.path().join("unlisted"), b"unlisted", 0o644);
        assert!(taild_notice_inventory(root.path()).is_err());
        fs::remove_file(root.path().join("unlisted")).unwrap();
        let notice = root.path().join("example.org/dependency/v1.2.3/LICENSE");
        fs::remove_file(&notice).unwrap();
        assert!(taild_notice_inventory(root.path()).is_err());
        symlink("/etc/passwd", &notice).unwrap();
        assert!(taild_notice_inventory(root.path()).is_err());
        fs::remove_file(&notice).unwrap();
        file(&notice, b"license", 0o644);
        fs::set_permissions(&notice, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(taild_notice_inventory(root.path()).is_err());
        fs::set_permissions(&notice, fs::Permissions::from_mode(0o644)).unwrap();
        for path in [
            "../LICENSE",
            "/etc/passwd",
            "example.org/dependency/v1.2.3/../LICENSE",
            "example.org//dependency/v1.2.3/LICENSE",
        ] {
            file(
                &root.path().join("modules.json"),
                serde_json::to_vec(&serde_json::json!([{
                    "module": "example.org/dependency", "version": "v1.2.3", "notices": [path],
                }]))
                .unwrap()
                .as_slice(),
                0o644,
            );
            assert!(taild_notice_inventory(root.path()).is_err(), "{path}");
        }
    }

    #[test]
    fn notice_copy_comparison_and_directory_validation_detect_tampering() {
        let root = tempfile::tempdir().unwrap();
        let bundle = fixture(root.path());
        let resources = bundle.join("Contents/Resources");
        file(
            &resources.join("LICENSES/taild/example.org/dependency/v1.2.3/LICENSE"),
            b"changed license",
            0o644,
        );
        assert!(compare_notices(
            &root.path().join("stage"),
            &root.path().join("taild-licenses"),
            &resources
        )
        .is_err());
        let original = resources.join("LICENSES/taild/example.org");
        let outside = root.path().join("outside");
        fs::rename(&original, &outside).unwrap();
        symlink(&outside, &original).unwrap();
        assert!(validate_bundle_filesystem(&bundle, false).is_err());
    }

    #[test]
    fn signature_inventory_and_hashes_cover_actual_nested_bytes() {
        let root = tempfile::tempdir().unwrap();
        let bundle = fixture(root.path());
        let paths = signed_code_paths(&bundle);
        for name in ["taild", BRIDGE, "silod", "netd", "silo-vmm"] {
            assert!(paths.contains(&bundle.join("Contents/Helpers").join(name)));
        }
        assert!(paths.contains(&bundle.join("Contents/MacOS/silo")));
        let before = signed_file_hashes(&bundle).unwrap();
        let relative = format!("Contents/Helpers/{BRIDGE}");
        file(&bundle.join(&relative), b"post-signing bytes", 0o644);
        let after = signed_file_hashes(&bundle).unwrap();
        assert_ne!(before[&relative], after[&relative]);
        assert_eq!(
            after[&relative],
            crate::archive::sha256(&bundle.join(relative)).unwrap()
        );
        assert!(after.contains_key("Contents/Resources/LICENSES/taild/modules.json"));
    }

    #[test]
    fn nested_identity_requires_same_certificate_not_just_same_team() {
        let identity = SignatureIdentity {
            certificate_sha256: Some("selected certificate".to_string()),
            team_identifier: Some("same team".to_string()),
            authorities: vec!["Developer ID Application: selected".to_string()],
            ad_hoc: false,
        };
        ensure_same_identity(Path::new("library"), &identity, &identity).unwrap();
        let other = SignatureIdentity {
            certificate_sha256: Some("other certificate".to_string()),
            team_identifier: identity.team_identifier.clone(),
            authorities: identity.authorities.clone(),
            ad_hoc: false,
        };
        assert!(ensure_same_identity(Path::new("library"), &identity, &other).is_err());
        let ad_hoc = SignatureIdentity {
            certificate_sha256: None,
            team_identifier: None,
            authorities: vec![],
            ad_hoc: true,
        };
        assert!(ensure_same_identity(Path::new("taild"), &identity, &ad_hoc).is_err());
    }

    #[test]
    fn library_copy_normalizes_cargo_mode_and_rejects_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join(BRIDGE);
        let destination = root.path().join("bundled.dylib");
        file(&source, b"cargo shared library", 0o755);
        copy_bridge(&source, &destination).unwrap();
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert_eq!(fs::read(&source).unwrap(), fs::read(&destination).unwrap());
        fs::remove_file(&source).unwrap();
        symlink(&destination, &source).unwrap();
        assert!(copy_bridge(&source, &root.path().join("other.dylib")).is_err());
    }

    #[test]
    fn bundle_filesystem_rejects_symlink_helpers_assets_and_signature_inventory() {
        let root = tempfile::tempdir().unwrap();
        let bundle = fixture(root.path());
        for relative in [
            "Contents/Helpers/taild",
            "Contents/Helpers/libsilo_go_ffi.dylib",
            "Contents/Resources/assets/kernel-default",
        ] {
            let path = bundle.join(relative);
            let backup = root.path().join("saved-input");
            fs::rename(&path, &backup).unwrap();
            symlink(&backup, &path).unwrap();
            assert!(validate_bundle_filesystem(&bundle, false).is_err());
            fs::remove_file(&path).unwrap();
            fs::rename(&backup, &path).unwrap();
        }
        file(
            &bundle.join("Contents/_CodeSignature/CodeResources"),
            b"inventory only",
            0o644,
        );
        file(
            &bundle.join("Contents/_CodeSignature/extra"),
            b"unexpected",
            0o644,
        );
        assert!(validate_bundle_filesystem(&bundle, true).is_err());
        fs::remove_file(bundle.join("Contents/_CodeSignature/extra")).unwrap();
        validate_bundle_filesystem(&bundle, true).unwrap();
    }
}
