use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command;
use crate::profiles::Profile;
use crate::release;
use crate::rprobe::ASSETS as RPROBE_ASSETS;
use crate::targets::HostTarget;

const RUNTIME_FILES: [(&str, u32); 5] = [
    ("bin/silo-vmm", 0o755),
    ("bin/netd", 0o755),
    ("assets/kernel-default", 0o644),
    ("assets/initramfs", 0o644),
    ("assets/agent", 0o755),
];
#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Release(#[from] release::ReleaseError),
    #[error("failed to {action} {path}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid release archive {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

#[derive(Clone, Copy)]
enum ArchiveKind {
    Runtime,
    Portable,
}

impl ArchiveKind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Runtime => "silo-runtime",
            Self::Portable => "silo",
        }
    }

    fn has_cli(self) -> bool {
        matches!(self, Self::Portable)
    }
}

fn product_files(host: HostTarget) -> [&'static str; 4] {
    ["silo", "silod", "taild", host.go_ffi_library()]
}

pub fn produce_runtime(
    workspace_root: &Path,
    target_dir: &Path,
    profile: Profile,
) -> Result<(), ArchiveError> {
    produce_kinds(workspace_root, target_dir, profile, &[ArchiveKind::Runtime])
}

pub fn produce_portable(workspace_root: &Path, target_dir: &Path) -> Result<(), ArchiveError> {
    produce_kinds(
        workspace_root,
        target_dir,
        Profile::Release,
        &[ArchiveKind::Portable],
    )
}

fn produce_kinds(
    workspace_root: &Path,
    target_dir: &Path,
    profile: Profile,
    kinds: &[ArchiveKind],
) -> Result<(), ArchiveError> {
    let host = HostTarget::current().map_err(|error| ArchiveError::Invalid {
        path: target_dir.to_path_buf(),
        reason: error.to_string(),
    })?;
    let version = version(workspace_root)?;
    let epoch = source_date_epoch(workspace_root)?;
    let stage = stage_path(target_dir, host, profile);
    validate_stage(&stage)?;
    crate::runtime::validate_stage_against_adjacent(
        &crate::components::BuildContext {
            workspace_root,
            target_dir,
            profile,
            host,
        },
        &stage,
    )
    .map_err(|error| ArchiveError::Invalid {
        path: stage.clone(),
        reason: error.to_string(),
    })?;
    let output = artifact_directory(target_dir, host, &version, profile);
    create_directory(&output)?;
    let syft = release::tool("syft")?;

    for &kind in kinds {
        if kind.has_cli() {
            validate_product(workspace_root, target_dir, host)?;
        }
        if profile == Profile::Release && host != HostTarget::MacosArm64 {
            let mut audit = Command::new("python3");
            audit
                .arg(workspace_root.join("packaging/silo-taild/elf_audit.py"))
                .arg("--target")
                .arg(host.runtime_target());
            for name in ["bin/silo-vmm", "bin/netd", "assets/agent"] {
                audit.arg(stage.join(name));
            }
            if kind.has_cli() {
                for name in product_files(host) {
                    audit.arg(target_dir.join("release").join(name));
                }
            }
            command::run(audit)?;
        }
        let root = archive_root(kind, &version, host);
        let archive = output.join(format!("{root}.tar.zst"));
        let raw = output.join(format!(".{root}.tar"));
        create_tar(
            workspace_root,
            target_dir,
            &stage,
            host,
            kind,
            &root,
            epoch,
            &raw,
        )?;
        compress_tar(&raw, &archive)?;
        let raw_size = file_size(&raw)?;
        let compressed_size = file_size(&archive)?;
        write_checksum(&archive)?;
        write_sbom(
            &syft,
            &archive,
            &output.join(format!("{root}.sbom.spdx.json")),
        )?;
        write_provenance(
            workspace_root,
            target_dir,
            host,
            profile,
            &version,
            epoch,
            kind,
            &archive,
            raw_size,
            compressed_size,
            &output.join(format!("{root}.provenance.json")),
            &syft,
        )?;
        fs::remove_file(&raw).map_err(|source| ArchiveError::Io {
            action: "remove uncompressed archive",
            path: raw,
            source,
        })?;
        println!(
            "archive: {} raw={} compressed={}",
            archive.display(),
            raw_size,
            compressed_size
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_tar(
    workspace_root: &Path,
    target_dir: &Path,
    stage: &Path,
    host: HostTarget,
    kind: ArchiveKind,
    root: &str,
    epoch: u64,
    raw: &Path,
) -> Result<(), ArchiveError> {
    let tar = release::tool("tar")?;
    let stage_name = stage
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ArchiveError::Invalid {
            path: stage.into(),
            reason: "stage lacks a profile name".into(),
        })?;
    let mut command = Command::new(tar);
    command
        .current_dir(stage)
        .args(["--create", "--file"])
        .arg(raw)
        .args([
            "--format=ustar",
            "--sort=name",
            "--exclude=__pycache__",
            &format!("--mtime=@{epoch}"),
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mode=u+rwX,go+rX,go-w",
            "--transform",
            &format!("s,^silo$,{root}/bin/silo,"),
            "--transform",
            &format!("s,^silod$,{root}/bin/silod,"),
            "--transform",
            &format!("s,^taild$,{root}/bin/taild,"),
            "--transform",
            &format!(
                "s,^{}$,{root}/bin/{},",
                host.go_ffi_library(),
                host.go_ffi_library()
            ),
            "--transform",
            &format!("s,^packaging/silo-taild,{root}/share/silo-taild,"),
            "--transform",
            &format!("s,^taild-licenses,{root}/LICENSES/taild,"),
            "--transform",
            &format!("s,^{stage_name}$,{root},"),
            "--transform",
            &format!("s,^{stage_name}/,{root}/,"),
        ])
        .arg("--directory")
        .arg(stage.parent().ok_or_else(|| ArchiveError::Invalid {
            path: stage.into(),
            reason: "stage has no parent".into(),
        })?)
        .arg(stage_name);
    if kind.has_cli() {
        command
            .args(["--directory"])
            .arg(target_dir.join("release"))
            .args(product_files(host))
            .arg("--directory")
            .arg(workspace_root)
            .arg("packaging/silo-taild/examples")
            .arg("--directory")
            .arg(target_dir)
            .arg("taild-licenses");
    }
    command::run(command)?;
    Ok(())
}

fn compress_tar(raw: &Path, archive: &Path) -> Result<(), ArchiveError> {
    let zstd = release::tool("zstd")?;
    let mut command = Command::new(zstd);
    command.args([
        "--quiet",
        "--force",
        "--threads=0",
        "--no-progress",
        "-19",
        "-o",
    ]);
    command.arg(archive).arg(raw);
    command::run(command)?;
    Ok(())
}

fn write_sbom(syft: &Path, archive: &Path, output: &Path) -> Result<(), ArchiveError> {
    let mut command = Command::new(syft);
    command.arg(archive).args(["-o"]);
    command.arg(format!("spdx-json={}", output.display()));
    command::run(command)?;
    if output.is_file() {
        Ok(())
    } else {
        invalid(output, "Syft did not produce an SPDX JSON SBOM".to_string())
    }
}

#[allow(clippy::too_many_arguments)]
fn write_provenance(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
    profile: Profile,
    version: &str,
    epoch: u64,
    kind: ArchiveKind,
    archive: &Path,
    raw_size: u64,
    compressed_size: u64,
    output: &Path,
    syft: &Path,
) -> Result<(), ArchiveError> {
    let files = archive_file_hashes(target_dir, host, profile, kind)?;
    let kernel = target_dir
        .join("kernel-provenance")
        .join(host.runtime_target())
        .join(format!("{}.json", profile.directory()));
    let kernel: Value =
        serde_json::from_slice(&read(&kernel)?).map_err(|error| ArchiveError::Invalid {
            path: kernel.clone(),
            reason: format!("cannot parse kernel provenance: {error}"),
        })?;
    let provenance = json!({
        "schema": "https://silo.dev/release-provenance/v1",
        "archive": {
            "name": archive.file_name().and_then(|value| value.to_str()).unwrap_or_default(),
            "sha256": sha256(archive)?,
            "raw_bytes": raw_size,
            "compressed_bytes": compressed_size,
            "format": "tar.zst",
            "zstd": "zstd -19 --threads=0 --no-progress",
        },
        "build_environment": {
            "host_os": env::consts::OS,
            "host_architecture": env::consts::ARCH,
            "source_date_epoch": epoch,
            "profile": profile.directory(),
        },
        "file_hashes": files,
        "kernel": kernel,
        "source_revision": git_output(workspace_root, ["rev-parse", "HEAD"] )?,
        "source_modified": !git_output(workspace_root, ["status", "--porcelain"] )?.is_empty(),
        "target": host.runtime_target(),
        "toolchains": actual_toolchains(syft, workspace_root)?,
        "version": version,
    });
    let bytes = serde_json::to_vec_pretty(&provenance).map_err(|error| ArchiveError::Invalid {
        path: output.to_path_buf(),
        reason: format!("cannot serialize provenance: {error}"),
    })?;
    fs::write(output, bytes).map_err(|source| ArchiveError::Io {
        action: "write archive provenance",
        path: output.to_path_buf(),
        source,
    })
}

fn archive_file_hashes(
    target_dir: &Path,
    host: HostTarget,
    profile: Profile,
    kind: ArchiveKind,
) -> Result<BTreeMap<String, String>, ArchiveError> {
    let stage = stage_path(target_dir, host, profile);
    let mut files = BTreeMap::new();
    for (path, _) in RUNTIME_FILES {
        files.insert(path.to_string(), sha256(&stage.join(path))?);
    }
    for path in ["THIRD_PARTY_NOTICES", "LICENSES/APACHE-2.0.txt"] {
        files.insert(path.to_string(), sha256(&stage.join(path))?);
    }
    if has_rprobe_assets(&stage)? {
        for (name, _) in RPROBE_ASSETS {
            let path = format!("assets/{name}");
            files.insert(path.clone(), sha256(&stage.join(path))?);
        }
    }
    if kind.has_cli() {
        for name in product_files(host) {
            files.insert(
                format!("bin/{name}"),
                sha256(&target_dir.join("release").join(name))?,
            );
        }
    }
    Ok(files)
}

fn actual_toolchains(
    syft: &Path,
    workspace_root: &Path,
) -> Result<BTreeMap<String, String>, ArchiveError> {
    let mut tools = BTreeMap::new();
    for (name, path, args) in [
        ("cargo", release::tool("cargo")?, vec!["--version"]),
        ("rustc", release::tool("rustc")?, vec!["--version"]),
        ("zig", release::tool("zig")?, vec!["version"]),
        (
            "cargo-zigbuild",
            release::tool("cargo-zigbuild")?,
            vec!["--version"],
        ),
        ("tar", release::tool("tar")?, vec!["--version"]),
        ("zstd", release::tool("zstd")?, vec!["--version"]),
        ("syft", syft.to_path_buf(), vec!["version"]),
    ] {
        tools.insert(name.to_string(), release::tool_output(&path, &args)?);
    }
    for (name, module) in [("go-netd", "net/netd"), ("go-taild", "app/taild")] {
        let mut go = Command::new(release::tool("go")?);
        go.current_dir(workspace_root.join(module)).arg("version");
        tools.insert(
            name.into(),
            String::from_utf8_lossy(&command::output(go)?.stdout)
                .trim()
                .into(),
        );
    }
    if env::consts::OS == "linux" {
        tools.insert(
            "native-cc".into(),
            release::tool_output(Path::new("/usr/bin/cc"), &["--version"])?,
        );
    }
    Ok(tools)
}

fn write_checksum(archive: &Path) -> Result<(), ArchiveError> {
    let checksum = checksum_path(archive)?;
    let name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ArchiveError::Invalid {
            path: archive.to_path_buf(),
            reason: "archive has no UTF-8 file name".to_string(),
        })?;
    fs::write(&checksum, format!("{}  {name}\n", sha256(archive)?)).map_err(|source| {
        ArchiveError::Io {
            action: "write detached archive checksum",
            path: checksum,
            source,
        }
    })
}

fn checksum_path(archive: &Path) -> Result<PathBuf, ArchiveError> {
    let name = archive.file_name().ok_or_else(|| ArchiveError::Invalid {
        path: archive.to_path_buf(),
        reason: "archive has no file name".to_string(),
    })?;
    let mut checksum = name.to_os_string();
    checksum.push(".sha256");
    Ok(archive.with_file_name(checksum))
}

fn source_date_epoch(workspace_root: &Path) -> Result<u64, ArchiveError> {
    let value = match env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => {
            git_output(workspace_root, ["show", "-s", "--format=%ct", "HEAD"])?
        }
        Err(error) => {
            return invalid(
                workspace_root,
                format!("cannot read SOURCE_DATE_EPOCH: {error}"),
            )
        }
    };
    value.parse::<u64>().map_err(|error| ArchiveError::Invalid {
        path: workspace_root.to_path_buf(),
        reason: format!("SOURCE_DATE_EPOCH {value:?} is not an epoch: {error}"),
    })
}

fn version(workspace_root: &Path) -> Result<String, ArchiveError> {
    let path = workspace_root.join("VERSION");
    let version = String::from_utf8(read(&path)?).map_err(|error| ArchiveError::Invalid {
        path: path.clone(),
        reason: format!("version is not UTF-8: {error}"),
    })?;
    let version = version.trim();
    if !crate::version::is_semver(version) {
        return invalid(
            &path,
            "VERSION must contain exactly three numeric components".into(),
        );
    }
    Ok(version.to_string())
}

fn stage_path(target_dir: &Path, host: HostTarget, profile: Profile) -> PathBuf {
    target_dir
        .join("silo-runtime")
        .join(host.runtime_target())
        .join(profile.directory())
}

pub fn packages_root(target_dir: &Path, profile: Profile) -> PathBuf {
    target_dir.join(if profile == Profile::Release {
        "packages"
    } else {
        "packages-debug"
    })
}

fn artifact_directory(
    target_dir: &Path,
    host: HostTarget,
    version: &str,
    profile: Profile,
) -> PathBuf {
    packages_root(target_dir, profile)
        .join(version)
        .join(host.runtime_target())
}

fn archive_root(kind: ArchiveKind, version: &str, host: HostTarget) -> String {
    format!("{}-{version}-{}", kind.prefix(), host.runtime_target())
}

fn validate_stage(stage: &Path) -> Result<(), ArchiveError> {
    for (path, mode) in RUNTIME_FILES {
        validate_regular_file(&stage.join(path), mode)?;
    }
    if has_rprobe_assets(stage)? {
        for (name, mode) in RPROBE_ASSETS {
            validate_regular_file(&stage.join("assets").join(name), mode)?;
        }
    }
    Ok(())
}

fn validate_product(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
) -> Result<(), ArchiveError> {
    for name in product_files(host) {
        let path = target_dir.join("release").join(name);
        if !fs::symlink_metadata(&path)
            .map_err(|source| ArchiveError::Io {
                action: "read archive file metadata",
                path: path.clone(),
                source,
            })?
            .is_file()
        {
            return invalid(&path, "is not a regular file".into());
        }
    }
    for path in [
        target_dir.join("taild-licenses"),
        workspace_root.join("packaging/silo-taild/examples"),
    ] {
        validate_archive_tree(&path, true)?;
    }
    validate_regular_file(&target_dir.join("taild-licenses/modules.json"), 0o644)?;
    Ok(())
}

fn validate_archive_tree(path: &Path, require_directory: bool) -> Result<(), ArchiveError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ArchiveError::Io {
        action: "read archive file metadata",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(|source| ArchiveError::Io {
            action: "read archive directory",
            path: path.to_path_buf(),
            source,
        })? {
            let entry = entry.map_err(|source| ArchiveError::Io {
                action: "read archive directory entry",
                path: path.to_path_buf(),
                source,
            })?;
            validate_archive_tree(&entry.path(), false)?;
        }
        Ok(())
    } else if metadata.is_file() && !require_directory {
        Ok(())
    } else {
        invalid(path, "is not a regular file or directory".into())
    }
}

fn has_rprobe_assets(stage: &Path) -> Result<bool, ArchiveError> {
    let assets = stage.join("assets");
    crate::rprobe::installed_asset_set_present(&assets).map_err(|source| ArchiveError::Io {
        action: "read rprobe asset metadata",
        path: assets,
        source,
    })
}

fn validate_regular_file(path: &Path, expected_mode: u32) -> Result<(), ArchiveError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ArchiveError::Io {
        action: "read archive file metadata",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return invalid(path, "is not a regular non-symlink file".to_string());
    }
    let actual_mode = metadata.permissions().mode() & 0o777;
    if actual_mode != expected_mode {
        return invalid(
            path,
            format!("has mode {actual_mode:o}, expected {expected_mode:o}"),
        );
    }
    Ok(())
}

pub(crate) fn sha256(path: &Path) -> Result<String, ArchiveError> {
    let mut file = fs::File::open(path).map_err(|source| ArchiveError::Io {
        action: "open file for SHA-256",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| ArchiveError::Io {
            action: "read file for SHA-256",
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn git_output(
    workspace_root: &Path,
    args: impl IntoIterator<Item = &'static str>,
) -> Result<String, ArchiveError> {
    let mut command = Command::new(release::tool("git")?);
    command.current_dir(workspace_root).args(args);
    let output = command::output(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn file_size(path: &Path) -> Result<u64, ArchiveError> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|source| ArchiveError::Io {
            action: "read archive size",
            path: path.to_path_buf(),
            source,
        })
}

fn create_directory(path: &Path) -> Result<(), ArchiveError> {
    fs::create_dir_all(path).map_err(|source| ArchiveError::Io {
        action: "create archive directory",
        path: path.to_path_buf(),
        source,
    })
}

fn read(path: &Path) -> Result<Vec<u8>, ArchiveError> {
    fs::read(path).map_err(|source| ArchiveError::Io {
        action: "read archive input",
        path: path.to_path_buf(),
        source,
    })
}

fn invalid<T>(path: &Path, reason: String) -> Result<T, ArchiveError> {
    Err(ArchiveError::Invalid {
        path: path.to_path_buf(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    struct Fixture {
        root: PathBuf,
        stage: PathBuf,
    }

    impl Fixture {
        fn new(name: &str, host: HostTarget) -> Self {
            let root = env::temp_dir().join(format!("silo-archive-{name}-{}", std::process::id()));
            fs::create_dir(&root).unwrap();
            let stage = stage_path(&root, host, Profile::Release);
            for directory in [
                stage.join("bin"),
                stage.join("assets"),
                stage.join("LICENSES"),
                root.join("release"),
                root.join("taild-licenses/dependency"),
                root.join("packaging/silo-taild/examples"),
            ] {
                fs::create_dir_all(directory).unwrap();
            }
            for (path, mode) in RUNTIME_FILES {
                fs::write(stage.join(path), path).unwrap();
                fs::set_permissions(stage.join(path), fs::Permissions::from_mode(mode)).unwrap();
            }
            for path in [
                "runtime-manifest.json",
                "THIRD_PARTY_NOTICES",
                "LICENSES/APACHE-2.0.txt",
            ] {
                fs::write(stage.join(path), path).unwrap();
            }
            for name in product_files(host) {
                fs::write(root.join("release").join(name), name).unwrap();
            }
            for path in [
                "taild-licenses/modules.json",
                "taild-licenses/dependency/LICENSE",
                "packaging/silo-taild/examples/devbox.yaml",
                "packaging/silo-taild/config.yaml",
                "packaging/silo-taild/silo-taild.service",
                "packaging/silo-taild/silo-taild.sysusers",
                "packaging/silo-taild/licenses.py",
                "packaging/silo-taild/verify-artifact.py",
            ] {
                fs::write(root.join(path), path).unwrap();
            }
            Self { root, stage }
        }

        fn inventory(&self, host: HostTarget, kind: ArchiveKind) -> BTreeSet<String> {
            let archive = self.root.join("test.tar");
            create_tar(
                &self.root,
                &self.root,
                &self.stage,
                host,
                kind,
                "product",
                0,
                &archive,
            )
            .unwrap();
            let output = Command::new("tar")
                .arg("-tf")
                .arg(archive)
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter(|entry| !entry.ends_with('/'))
                .map(str::to_string)
                .collect()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn runtime_inventory() -> BTreeSet<String> {
        RUNTIME_FILES
            .iter()
            .map(|(path, _)| *path)
            .chain([
                "runtime-manifest.json",
                "THIRD_PARTY_NOTICES",
                "LICENSES/APACHE-2.0.txt",
            ])
            .map(|path| format!("product/{path}"))
            .collect()
    }

    #[test]
    fn portable_and_runtime_archives_have_exact_component_inventories_on_every_target() {
        for host in [
            HostTarget::LinuxX86_64,
            HostTarget::LinuxArm64,
            HostTarget::MacosArm64,
        ] {
            let fixture = Fixture::new("inventory", host);
            validate_product(&fixture.root, &fixture.root, host).unwrap();
            assert_eq!(
                fixture.inventory(host, ArchiveKind::Runtime),
                runtime_inventory()
            );
            let mut expected = runtime_inventory();
            expected.extend(product_files(host).map(|name| format!("product/bin/{name}")));
            expected.extend([
                "product/LICENSES/taild/modules.json".to_string(),
                "product/LICENSES/taild/dependency/LICENSE".to_string(),
                "product/share/silo-taild/examples/devbox.yaml".to_string(),
            ]);
            assert_eq!(fixture.inventory(host, ArchiveKind::Portable), expected);
        }
    }

    #[test]
    fn provenance_hashes_actual_helper_and_sidecar_and_keeps_runtime_frontend_free() {
        for host in [
            HostTarget::LinuxX86_64,
            HostTarget::LinuxArm64,
            HostTarget::MacosArm64,
        ] {
            let fixture = Fixture::new("hashes", host);
            let hashes =
                archive_file_hashes(&fixture.root, host, Profile::Release, ArchiveKind::Portable)
                    .unwrap();
            for name in product_files(host) {
                assert_eq!(
                    hashes[&format!("bin/{name}")],
                    sha256(&fixture.root.join("release").join(name)).unwrap()
                );
            }
            for name in ["taild", host.go_ffi_library()] {
                fs::write(
                    fixture.root.join("release").join(name),
                    "changed actual bytes",
                )
                .unwrap();
                let changed = archive_file_hashes(
                    &fixture.root,
                    host,
                    Profile::Release,
                    ArchiveKind::Portable,
                )
                .unwrap();
                assert_ne!(
                    hashes[&format!("bin/{name}")],
                    changed[&format!("bin/{name}")]
                );
            }
            let runtime =
                archive_file_hashes(&fixture.root, host, Profile::Release, ArchiveKind::Runtime)
                    .unwrap();
            assert_eq!(
                runtime
                    .keys()
                    .map(|path| format!("product/{path}"))
                    .collect::<BTreeSet<_>>(),
                runtime_inventory()
                    .into_iter()
                    .filter(|path| !path.ends_with("runtime-manifest.json"))
                    .collect()
            );
        }
    }

    #[test]
    fn product_admission_rejects_missing_sidecars_and_unsafe_notice_or_example_entries() {
        let host = HostTarget::LinuxX86_64;
        let fixture = Fixture::new("admission", host);
        let bridge = fixture.root.join("release").join(host.go_ffi_library());
        fs::remove_file(&bridge).unwrap();
        assert!(validate_product(&fixture.root, &fixture.root, host).is_err());
        symlink(fixture.root.join("release/taild"), &bridge).unwrap();
        assert!(validate_product(&fixture.root, &fixture.root, host).is_err());
        fs::remove_file(&bridge).unwrap();
        fs::write(&bridge, "bridge").unwrap();
        for directory in ["taild-licenses/dependency", "packaging/silo-taild/examples"] {
            let unsafe_path = fixture.root.join(directory).join("unsafe");
            symlink(&bridge, &unsafe_path).unwrap();
            assert!(validate_product(&fixture.root, &fixture.root, host).is_err());
            fs::remove_file(unsafe_path).unwrap();
        }
        validate_product(&fixture.root, &fixture.root, host).unwrap();
    }
}
