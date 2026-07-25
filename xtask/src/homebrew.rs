use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::release_target::ReleaseTarget;
use crate::remove_path::remove_if_exists;

const CASK_NAME: &str = "vandycknick-silo.rb";
const CASK_TOKEN: &str = "vandycknick-silo";

#[derive(Debug)]
pub(crate) struct PackageHomebrewOptions {
    pub(crate) target_dir: PathBuf,
    pub(crate) published_macos_dmg: PathBuf,
}

#[derive(Debug)]
pub(crate) struct PackageHomebrewResult {
    pub(crate) cask: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum HomebrewError {
    #[error("Homebrew Casks must be generated on macOS")]
    UnsupportedHost,
    #[error("required macOS package input is missing or is not a regular file: {path}")]
    MissingInput { path: PathBuf },
    #[error("published macOS DMG path must be absolute: {path}")]
    PublishedInputMustBeAbsolute { path: PathBuf },
    #[error("invalid macOS package metadata at {path}: {reason}")]
    InvalidMetadata { path: PathBuf, reason: String },
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
}

pub(crate) fn package_homebrew_cask(
    options: &PackageHomebrewOptions,
) -> Result<PackageHomebrewResult, HomebrewError> {
    if !cfg!(target_os = "macos") {
        return Err(HomebrewError::UnsupportedHost);
    }
    let input = validated_input(options)?;
    validate_dmg_trust(&input.dmg, &input.signing_identity)?;
    let published_digest = validate_published_dmg(&input, &options.published_macos_dmg)?;
    publish_cask(&input.artifact_root, &published_digest)
}

struct ValidatedInput {
    artifact_root: PathBuf,
    dmg: PathBuf,
    digest: String,
    signing_identity: String,
    size: u64,
}

fn validated_input(options: &PackageHomebrewOptions) -> Result<ValidatedInput, HomebrewError> {
    let target = ReleaseTarget::DarwinArm64.descriptor();
    let artifact_root = options.target_dir.join("silo-artifacts").join(target.name);
    let macos = artifact_root.join("macos");
    let metadata_path = macos.join("macos.json");
    let metadata = read_metadata(&metadata_path)?;
    let dmg_name = format!("Silo-{}-{}.dmg", env!("CARGO_PKG_VERSION"), target.name);
    let signing_identity = validate_metadata(&metadata_path, &metadata, &dmg_name)?;

    let dmg = macos.join(&dmg_name);
    let dmg_metadata = require_file(&dmg)?;
    let recorded_size = metadata
        .pointer("/dmg/size")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_metadata(&metadata_path, "dmg.size must be an integer"))?;
    let recorded_digest = metadata
        .pointer("/dmg/sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_metadata(&metadata_path, "dmg.sha256 must be a string"))?;
    let digest = recorded_digest
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            invalid_metadata(
                &metadata_path,
                "dmg.sha256 must be an OCI-style SHA-256 digest",
            )
        })?;
    if dmg_metadata.len() != recorded_size || sha256(&dmg)? != recorded_digest {
        return Err(invalid_metadata(
            &metadata_path,
            "DMG does not match its recorded size and digest",
        ));
    }

    Ok(ValidatedInput {
        artifact_root,
        dmg,
        digest: digest.to_string(),
        signing_identity,
        size: recorded_size,
    })
}

fn publish_cask(
    artifact_root: &Path,
    digest: &str,
) -> Result<PackageHomebrewResult, HomebrewError> {
    let cask_dir = artifact_root.join("homebrew/Casks");
    create_directory(&cask_dir)?;
    let cask = cask_dir.join(CASK_NAME);
    remove_if_exists(&cask).map_err(|source| HomebrewError::Io {
        operation: "remove previous Homebrew Cask",
        path: cask.clone(),
        source,
    })?;
    write_new(&cask, cask_contents(digest).as_bytes())?;

    Ok(PackageHomebrewResult { cask })
}

fn validate_dmg_trust(dmg: &Path, signing_identity: &str) -> Result<(), HomebrewError> {
    let mut image = Command::new("/usr/bin/hdiutil");
    image.args(["verify", "-quiet"]).arg(dmg);
    run(image)?;

    let mut signature = Command::new("/usr/bin/codesign");
    signature
        .args(["--verify", "--strict", "--verbose=4"])
        .arg(dmg);
    run(signature)?;

    let mut display = Command::new("/usr/bin/codesign");
    display.args(["--display", "--verbose=4"]).arg(dmg);
    let rendered = format!("{display:?}");
    let output = display
        .output()
        .map_err(|source| HomebrewError::RunCommand {
            command: rendered.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(HomebrewError::CommandFailed {
            command: rendered,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    let details = String::from_utf8_lossy(&output.stderr);
    if !has_signing_authority(&details, signing_identity) {
        return Err(invalid_metadata(
            dmg,
            "DMG signing authority does not match macOS package metadata",
        ));
    }

    let mut ticket = Command::new("xcrun");
    ticket.args(["stapler", "validate", "-v"]).arg(dmg);
    run(ticket)?;

    let mut gatekeeper = Command::new("/usr/sbin/spctl");
    gatekeeper
        .args([
            "--assess",
            "--type",
            "open",
            "--context",
            "context:primary-signature",
            "--verbose=4",
        ])
        .arg(dmg);
    run(gatekeeper)
}

fn validate_published_dmg(
    input: &ValidatedInput,
    published_dmg: &Path,
) -> Result<String, HomebrewError> {
    if !published_dmg.is_absolute() {
        return Err(HomebrewError::PublishedInputMustBeAbsolute {
            path: published_dmg.to_path_buf(),
        });
    }
    let metadata = require_file(published_dmg)?;
    let digest = sha256(published_dmg)?;
    if metadata.len() != input.size || digest != format!("sha256:{}", input.digest) {
        return Err(invalid_metadata(
            published_dmg,
            "published GitHub release DMG differs from the local notarized artifact",
        ));
    }
    digest
        .strip_prefix("sha256:")
        .map(str::to_string)
        .ok_or_else(|| invalid_metadata(published_dmg, "downloaded DMG has an invalid digest"))
}

fn read_metadata(path: &Path) -> Result<Value, HomebrewError> {
    require_file(path)?;
    let bytes = fs::read(path).map_err(|source| HomebrewError::Io {
        operation: "read macOS package metadata",
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_metadata(path, &format!("invalid JSON: {error}")))
}

fn validate_metadata(
    path: &Path,
    metadata: &Value,
    dmg_name: &str,
) -> Result<String, HomebrewError> {
    let target = ReleaseTarget::DarwinArm64.descriptor();
    for (pointer, expected) in [
        ("/version", env!("CARGO_PKG_VERSION")),
        ("/target", target.name),
        ("/bundleIdentifier", "sh.silo.app"),
        ("/minimumSystemVersion", "26.0"),
        ("/app", "Silo.app"),
        ("/dmg/path", dmg_name),
    ] {
        if metadata.pointer(pointer).and_then(Value::as_str) != Some(expected) {
            return Err(invalid_metadata(
                path,
                &format!("expected {pointer} to be {expected:?}"),
            ));
        }
    }
    if metadata.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_metadata(path, "expected schemaVersion 1"));
    }
    if metadata.get("notarized").and_then(Value::as_bool) != Some(true) {
        return Err(invalid_metadata(
            path,
            "Homebrew publication requires a notarized DMG",
        ));
    }
    let signing = metadata
        .get("signing")
        .and_then(Value::as_str)
        .filter(|identity| is_developer_id_application(identity))
        .ok_or_else(|| {
            invalid_metadata(
                path,
                "Homebrew publication requires a Developer ID signing identity",
            )
        })?;
    Ok(signing.to_string())
}

fn is_developer_id_application(identity: &str) -> bool {
    let Some(value) = identity.strip_prefix("Developer ID Application: ") else {
        return false;
    };
    let Some((name, team)) = value.rsplit_once(" (") else {
        return false;
    };
    let Some(team) = team.strip_suffix(')') else {
        return false;
    };
    !name.is_empty()
        && team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn has_signing_authority(details: &str, identity: &str) -> bool {
    let expected = format!("Authority={identity}");
    details.lines().any(|line| line == expected)
}

fn cask_contents(digest: &str) -> String {
    format!(
        concat!(
            "cask \"{token}\" do\n",
            "  version \"{version}\"\n",
            "  sha256 \"{digest}\"\n",
            "\n",
            "  url \"https://github.com/vandycknick/silo/releases/download/",
            "v#{{version}}/Silo-#{{version}}-darwin-arm64.dmg\"\n",
            "  name \"Silo\"\n",
            "  desc \"Local microVM sandbox runtime for OCI images\"\n",
            "  homepage \"https://github.com/vandycknick/silo\"\n",
            "\n",
            "  depends_on arch: :arm64\n",
            "  depends_on macos: :tahoe\n",
            "\n",
            "  app \"Silo.app\"\n",
            "  binary \"#{{appdir}}/Silo.app/Contents/MacOS/silo\", target: \"silo\"\n",
            "end\n"
        ),
        token = CASK_TOKEN,
        version = env!("CARGO_PKG_VERSION"),
        digest = digest,
    )
}

fn require_file(path: &Path) -> Result<fs::Metadata, HomebrewError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HomebrewError::MissingInput {
        path: path.to_path_buf(),
    })?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(metadata)
    } else {
        Err(HomebrewError::MissingInput {
            path: path.to_path_buf(),
        })
    }
}

fn sha256(path: &Path) -> Result<String, HomebrewError> {
    let mut file = File::open(path).map_err(|source| HomebrewError::Io {
        operation: "open DMG for hashing",
        path: path.to_path_buf(),
        source,
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| HomebrewError::Io {
            operation: "hash DMG",
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

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), HomebrewError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| HomebrewError::Io {
            operation: "create Homebrew Cask",
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| HomebrewError::Io {
        operation: "write Homebrew Cask",
        path: path.to_path_buf(),
        source,
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(|source| {
        HomebrewError::Io {
            operation: "set Homebrew Cask mode",
            path: path.to_path_buf(),
            source,
        }
    })?;
    file.sync_all().map_err(|source| HomebrewError::Io {
        operation: "sync Homebrew Cask",
        path: path.to_path_buf(),
        source,
    })
}

fn create_directory(path: &Path) -> Result<(), HomebrewError> {
    fs::create_dir_all(path).map_err(|source| HomebrewError::Io {
        operation: "create Homebrew artifact directory",
        path: path.to_path_buf(),
        source,
    })
}

fn run(mut command: Command) -> Result<(), HomebrewError> {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .map_err(|source| HomebrewError::RunCommand {
            command: rendered.clone(),
            source,
        })?;
    ensure_success(rendered, output)
}

fn ensure_success(command: String, output: Output) -> Result<(), HomebrewError> {
    if output.status.success() {
        Ok(())
    } else {
        Err(HomebrewError::CommandFailed {
            command,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn invalid_metadata(path: &Path, reason: &str) -> HomebrewError {
    HomebrewError::InvalidMetadata {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use crate::homebrew::{
        cask_contents, has_signing_authority, package_homebrew_cask, publish_cask, sha256,
        validate_published_dmg, validated_input, PackageHomebrewOptions,
    };

    #[test]
    fn generates_cask_for_the_notarized_release_dmg() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = fixture(temp.path(), true);

        let input = validated_input(&options).expect("validate Homebrew input");
        let digest = validate_published_dmg(&input, &options.published_macos_dmg)
            .expect("validate published DMG");
        let result = publish_cask(&input.artifact_root, &digest).expect("publish Cask");
        let cask = std::fs::read_to_string(&result.cask).expect("read generated Cask");
        assert_eq!(
            std::fs::metadata(&result.cask)
                .expect("Cask metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            cask,
            cask_contents("00cbbd0ddbda2762798f7009838ed34ca1f12b93965813c7df22943bc62166d1")
        );
        assert!(cask.contains("cask \"vandycknick-silo\" do"));
        assert!(cask.contains("depends_on arch: :arm64"));
        assert!(cask.contains("depends_on macos: :tahoe"));
        assert!(cask.contains("binary \"#{appdir}/Silo.app/Contents/MacOS/silo\""));
    }

    #[test]
    fn rejects_ad_hoc_and_modified_dmg_inputs() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let ad_hoc = fixture(temp.path(), false);
        assert!(validated_input(&ad_hoc).is_err());

        let temp = tempfile::tempdir().expect("create temp directory");
        let modified = fixture(temp.path(), true);
        let dmg = modified
            .target_dir
            .join("silo-artifacts/darwin-arm64/macos/Silo-0.1.0-darwin-arm64.dmg");
        std::fs::write(dmg, b"modified").expect("modify DMG");
        assert!(validated_input(&modified).is_err());

        let temp = tempfile::tempdir().expect("create temp directory");
        let published_modified = fixture(temp.path(), true);
        std::fs::write(&published_modified.published_macos_dmg, b"modified")
            .expect("modify published DMG");
        let input = validated_input(&published_modified).expect("validate local input");
        assert!(validate_published_dmg(&input, &published_modified.published_macos_dmg).is_err());

        let temp = tempfile::tempdir().expect("create temp directory");
        let development = fixture(temp.path(), true);
        let metadata_path = development
            .target_dir
            .join("silo-artifacts/darwin-arm64/macos/macos.json");
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).expect("read metadata fixture"))
                .expect("parse metadata fixture");
        metadata["signing"] = serde_json::json!("Apple Development: Silo (TEAMID1234)");
        std::fs::write(
            metadata_path,
            serde_json::to_vec_pretty(&metadata).expect("encode metadata fixture"),
        )
        .expect("write metadata fixture");
        assert!(validated_input(&development).is_err());
    }

    #[test]
    fn replaces_an_existing_cask() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = fixture(temp.path(), true);
        let input = validated_input(&options).expect("validate Homebrew input");
        let first = publish_cask(&input.artifact_root, &input.digest).expect("publish first Cask");
        std::fs::write(&first.cask, b"stale").expect("replace Cask with stale output");

        let second = publish_cask(&input.artifact_root, &input.digest).expect("replace Cask");
        assert_eq!(
            std::fs::read_to_string(second.cask).expect("read replaced Cask"),
            cask_contents(&input.digest)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn forged_notarization_metadata_does_not_pass_native_validation() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = fixture(temp.path(), true);
        assert!(package_homebrew_cask(&options).is_err());
    }

    #[test]
    fn published_asset_must_be_an_absolute_regular_file() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let options = fixture(temp.path(), true);
        let input = validated_input(&options).expect("validate local input");
        assert!(validate_published_dmg(&input, Path::new("download.dmg")).is_err());

        let symlink = temp.path().join("published-link.dmg");
        std::os::unix::fs::symlink(&options.published_macos_dmg, &symlink)
            .expect("create published DMG symlink");
        assert!(validate_published_dmg(&input, &symlink).is_err());
    }

    #[test]
    fn signing_authority_must_exactly_match_metadata() {
        let details = concat!(
            "Executable=/tmp/Silo.dmg\n",
            "Authority=Developer ID Application: Silo (TEAMID1234)\n",
            "Authority=Developer ID Certification Authority\n",
        );
        assert!(has_signing_authority(
            details,
            "Developer ID Application: Silo (TEAMID1234)"
        ));
        assert!(!has_signing_authority(
            details,
            "Developer ID Application: Other (TEAMID1234)"
        ));
    }

    fn fixture(root: &Path, notarized: bool) -> PackageHomebrewOptions {
        let target_dir = root.join("target");
        let macos = target_dir.join("silo-artifacts/darwin-arm64/macos");
        std::fs::create_dir_all(&macos).expect("create macOS artifact directory");
        let dmg_name = "Silo-0.1.0-darwin-arm64.dmg";
        let dmg = macos.join(dmg_name);
        std::fs::write(&dmg, b"dmg").expect("write DMG");
        let metadata = serde_json::json!({
            "schemaVersion": 1,
            "version": "0.1.0",
            "target": "darwin-arm64",
            "buildNumber": "1",
            "bundleIdentifier": "sh.silo.app",
            "minimumSystemVersion": "26.0",
            "app": "Silo.app",
            "dmg": {
                "path": dmg_name,
                "sha256": sha256(&dmg).expect("hash DMG"),
                "size": 3,
            },
            "signing": if notarized {
                "Developer ID Application: Silo (TEAMID1234)"
            } else {
                "ad-hoc"
            },
            "notarized": notarized,
        });
        std::fs::write(
            macos.join("macos.json"),
            serde_json::to_vec_pretty(&metadata).expect("encode metadata"),
        )
        .expect("write metadata");
        let published_macos_dmg = root.join("published-Silo.dmg");
        std::fs::copy(&dmg, &published_macos_dmg).expect("copy published DMG fixture");
        PackageHomebrewOptions {
            target_dir,
            published_macos_dmg,
        }
    }
}
