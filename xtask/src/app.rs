use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use thiserror::Error;

use crate::command;
use crate::release_audit;

const APP_NAME: &str = "Silo.app";
const BUNDLE_IDENTIFIER: &str = "sh.silo.app";
const MINIMUM_SYSTEM_VERSION: &str = "26.0";
const HELPERS: [(&str, Option<&str>); 3] = [
    ("vmmon", Some("runtime/vmmon/vmmon.entitlements")),
    ("netd", None),
    ("krun", Some("packaging/macos/krun.entitlements")),
];
const ASSETS: [(&str, u32); 3] = [
    ("kernel-default", 0o644),
    ("initramfs", 0o644),
    ("agent", 0o755),
];

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Audit(#[from] release_audit::AuditError),
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
    let output = target_dir.join("package/macos");
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
        for (name, _) in HELPERS {
            copy_regular_file(&stage.join("bin").join(name), &helpers.join(name), 0o755)?;
        }
        for (name, mode) in ASSETS {
            copy_regular_file(&stage.join("assets").join(name), &assets.join(name), mode)?;
        }
        generate_icon(workspace_root, &temporary, &resources.join("Silo.icns"))?;
        verify_unsigned_copies(&release, &stage, &temporary)?;
        validate_unsigned_layout(&temporary, &version, &build_number)?;

        for name in ["silo", "vmmon", "netd", "krun"] {
            let path = match name {
                "silo" => macos.join(name),
                _ => helpers.join(name),
            };
            release_audit::audit_macho(name, &path)?;
        }

        sign(&macos.join("silo"), None, signing)?;
        for (name, entitlement) in HELPERS {
            let entitlement = entitlement.map(|path| workspace_root.join(path));
            sign(&helpers.join(name), entitlement.as_deref(), signing)?;
        }
        sign(&temporary, None, signing)?;

        let app = output.join(APP_NAME);
        replace_directory(&temporary, &app)?;
        verify_signed_bundle(&app)?;
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

fn verify_unsigned_copies(release: &Path, stage: &Path, bundle: &Path) -> Result<(), AppError> {
    compare_files(&release.join("silo"), &bundle.join("Contents/MacOS/silo"))?;
    for (name, _) in HELPERS {
        compare_files(
            &stage.join("bin").join(name),
            &bundle.join("Contents/Helpers").join(name),
        )?;
    }
    for (name, _) in ASSETS {
        compare_files(
            &stage.join("assets").join(name),
            &bundle.join("Contents/Resources/assets").join(name),
        )?;
    }
    Ok(())
}

fn validate_unsigned_layout(
    bundle: &Path,
    version: &str,
    build_number: &str,
) -> Result<(), AppError> {
    validate_directory_entries(bundle, ["Contents"])?;
    let contents = bundle.join("Contents");
    validate_directory_entries(&contents, ["Helpers", "Info.plist", "MacOS", "Resources"])?;
    validate_directory_entries(&contents.join("MacOS"), ["silo"])?;
    validate_directory_entries(&contents.join("Helpers"), ["krun", "netd", "vmmon"])?;
    validate_directory_entries(&contents.join("Resources"), ["Silo.icns", "assets"])?;
    validate_directory_entries(
        &contents.join("Resources/assets"),
        ["agent", "initramfs", "kernel-default"],
    )?;
    validate_regular_file(&contents.join("Info.plist"), None)?;
    validate_regular_file(&contents.join("MacOS/silo"), Some(0o755))?;
    for (name, _) in HELPERS {
        validate_regular_file(&contents.join("Helpers").join(name), Some(0o755))?;
    }
    for (name, mode) in ASSETS {
        validate_regular_file(&contents.join("Resources/assets").join(name), Some(mode))?;
    }
    validate_regular_file(&contents.join("Resources/Silo.icns"), None)?;
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
    for name in ["silo", "vmmon", "netd", "krun"] {
        let path = match name {
            "silo" => bundle.join("Contents/MacOS/silo"),
            _ => bundle.join("Contents/Helpers").join(name),
        };
        verify_signature(&path)?;
    }
    verify_signature(bundle)?;
    verify_entitlements(
        &bundle.join("Contents/Helpers/vmmon"),
        &["com.apple.security.virtualization"],
    )?;
    verify_entitlements(
        &bundle.join("Contents/Helpers/krun"),
        &["com.apple.security.hypervisor"],
    )?;
    verify_entitlements(&bundle.join("Contents/MacOS/silo"), &[])?;
    verify_entitlements(&bundle.join("Contents/Helpers/netd"), &[])?;
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
    validate_directory_entries(bundle, ["Contents"])?;
    let contents = bundle.join("Contents");
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
    validate_directory_entries(&contents.join("MacOS"), ["silo"])?;
    validate_directory_entries(&contents.join("Helpers"), ["krun", "netd", "vmmon"])?;
    validate_directory_entries(&contents.join("Resources"), ["Silo.icns", "assets"])?;
    validate_directory_entries(
        &contents.join("Resources/assets"),
        ["agent", "initramfs", "kernel-default"],
    )?;
    validate_regular_file(&contents.join("Info.plist"), None)?;
    validate_regular_file(&contents.join("MacOS/silo"), Some(0o755))?;
    for (name, _) in HELPERS {
        validate_regular_file(&contents.join("Helpers").join(name), Some(0o755))?;
    }
    for (name, mode) in ASSETS {
        validate_regular_file(&contents.join("Resources/assets").join(name), Some(mode))?;
    }
    validate_regular_file(&contents.join("Resources/Silo.icns"), None)?;
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

fn copy_regular_file(source: &Path, destination: &Path, mode: u32) -> Result<(), AppError> {
    validate_regular_file(source, Some(mode))?;
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
        let mode = metadata.permissions().mode() & 0o777;
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
    let mut command = Command::new("/usr/bin/git");
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
