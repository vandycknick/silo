use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command;
use crate::release;
use crate::release_audit;
use crate::targets::HostTarget;

const RELEASE_MATERIAL: [&str; 2] = [
    "packaging/release/THIRD_PARTY_NOTICES",
    "common/ext4/LICENSE-APACHE",
];
const RUNTIME_FILES: [(&str, u32); 6] = [
    ("bin/vmmon", 0o755),
    ("bin/netd", 0o755),
    ("bin/krun", 0o755),
    ("assets/kernel-default", 0o644),
    ("assets/initramfs", 0o644),
    ("assets/agent", 0o755),
];
const RUNTIME_OVERRIDES: [&str; 5] = [
    "SILO_VMMON_PATH",
    "NETD_BIN",
    "KRUN_BIN",
    "SILO_ASSET_DIR",
    "SILO_RUNTIME_DIR",
];

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Release(#[from] release::ReleaseError),
    #[error(transparent)]
    Audit(#[from] release_audit::AuditError),
    #[error("failed to {action} {path}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid release archive {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
    #[error("release command timed out after {seconds} seconds: {program}")]
    TimedOut { program: String, seconds: u64 },
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

pub fn produce(workspace_root: &Path, target_dir: &Path) -> Result<(), ArchiveError> {
    let host = HostTarget::current().map_err(|error| ArchiveError::Invalid {
        path: target_dir.to_path_buf(),
        reason: error.to_string(),
    })?;
    let version = version(workspace_root)?;
    let epoch = source_date_epoch(workspace_root)?;
    let stage = stage_path(target_dir, host);
    validate_stage(&stage)?;
    let output = artifact_directory(target_dir, host, &version);
    create_directory(&output)?;
    let syft = syft_program(workspace_root, target_dir, host)?;

    for kind in [ArchiveKind::Runtime, ArchiveKind::Portable] {
        let root = archive_root(kind, &version, host);
        let archive = output.join(format!("{root}.tar.zst"));
        let raw = output.join(format!(".{root}.tar"));
        create_tar(workspace_root, target_dir, &stage, kind, &root, epoch, &raw)?;
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

pub fn verify(workspace_root: &Path, target_dir: &Path) -> Result<(), ArchiveError> {
    let host = HostTarget::current().map_err(|error| ArchiveError::Invalid {
        path: target_dir.to_path_buf(),
        reason: error.to_string(),
    })?;
    let version = version(workspace_root)?;
    let stage = stage_path(target_dir, host);
    validate_stage(&stage)?;
    let output = artifact_directory(target_dir, host, &version);
    let temporary = temporary_directory(target_dir, "archive-verify")?;
    let result = (|| {
        for kind in [ArchiveKind::Runtime, ArchiveKind::Portable] {
            let root_name = archive_root(kind, &version, host);
            let archive = output.join(format!("{root_name}.tar.zst"));
            verify_checksum(&archive)?;
            let entries = archive_entries(&archive)?;
            validate_entries(workspace_root, &entries, kind, &root_name)?;
            extract_archive(&archive, &temporary)?;
            let root = temporary.join(&root_name);
            validate_extracted(workspace_root, target_dir, &stage, &root, kind)?;
            release_audit::verify_archive_runtime(&root, kind.has_cli(), host)?;
            verify_sbom(
                &archive,
                &output.join(format!("{root_name}.sbom.spdx.json")),
            )?;
            verify_provenance(
                &archive,
                &output.join(format!("{root_name}.provenance.json")),
                &version,
                host,
            )?;
            if kind.has_cli() && matches!(host, HostTarget::MacosArm64) {
                boot_portable_vm(&root)?;
                println!("verify-archive: VZ boot completed and the acceptance VM was removed");
            }
        }
        Ok(())
    })();
    fs::remove_dir_all(&temporary).map_err(|source| ArchiveError::Io {
        action: "remove extracted archive directory",
        path: temporary,
        source,
    })?;
    result
}

fn create_tar(
    workspace_root: &Path,
    target_dir: &Path,
    stage: &Path,
    kind: ArchiveKind,
    root: &str,
    epoch: u64,
    raw: &Path,
) -> Result<(), ArchiveError> {
    let tar = release::tool("tar")?;
    let mut command = Command::new(tar);
    command
        .current_dir(stage)
        .args(["--create", "--file"])
        .arg(raw)
        .args([
            "--format=ustar",
            "--sort=name",
            &format!("--mtime=@{epoch}"),
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mode=u+rwX,go+rX,go-w",
            "--transform",
            &format!("s,^bin,{root}/bin,"),
            "--transform",
            &format!("s,^assets,{root}/assets,"),
            "--transform",
            &format!("s,^packaging/release/,{root}/,"),
            "--transform",
            &format!("s,^common/ext4/LICENSE-APACHE$,{root}/LICENSES/libkrun-APACHE-2.0.txt,"),
            "--transform",
            &format!("s,^silo$,{root}/bin/silo,"),
        ])
        .args(["bin", "assets", "--directory"])
        .arg(workspace_root)
        .args(RELEASE_MATERIAL);
    if kind.has_cli() {
        command
            .args(["--directory"])
            .arg(target_dir.join("release"))
            .arg("silo");
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
    version: &str,
    epoch: u64,
    kind: ArchiveKind,
    archive: &Path,
    raw_size: u64,
    compressed_size: u64,
    output: &Path,
    syft: &Path,
) -> Result<(), ArchiveError> {
    let stage = stage_path(target_dir, host);
    let mut files = BTreeMap::new();
    for (path, _) in RUNTIME_FILES {
        files.insert(path, sha256(&stage.join(path))?);
    }
    if kind.has_cli() {
        files.insert("bin/silo", sha256(&target_dir.join("release/silo"))?);
    }
    let kernel = target_dir
        .join("kernel-provenance")
        .join(host.runtime_target())
        .join("release.json");
    let kernel: serde_json::Value =
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
        },
        "file_hashes": files,
        "kernel": kernel,
        "source_revision": git_output(workspace_root, ["rev-parse", "HEAD"] )?,
        "target": host.runtime_target(),
        "toolchains": actual_toolchains(workspace_root, target_dir, syft)?,
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

fn actual_toolchains(
    workspace_root: &Path,
    target_dir: &Path,
    syft: &Path,
) -> Result<BTreeMap<String, String>, ArchiveError> {
    let go = release::go_program(target_dir, workspace_root, true)?;
    let mut tools = BTreeMap::new();
    for (name, path, args) in [
        ("cargo", release::tool("cargo")?, vec!["--version"]),
        ("rustc", release::tool("rustc")?, vec!["--version"]),
        ("go", go, vec!["version"]),
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
        tools.insert(name.to_string(), tool_output(&path, &args)?);
    }
    Ok(tools)
}

fn syft_program(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
) -> Result<PathBuf, ArchiveError> {
    let tools = release::toolchains(workspace_root)?;
    let version = tools.value("tools.syft")?;
    let platform = match host {
        HostTarget::MacosArm64 => "darwin_arm64",
        HostTarget::LinuxX86_64 => "linux_amd64",
        HostTarget::LinuxArm64 => "linux_arm64",
    };
    let digest = tools.value(&format!("tools.syft_{platform}_sha256"))?;
    let root = target_dir.join("release-tools");
    create_directory(&root)?;
    let archive = root.join(format!("syft_{version}_{platform}.tar.gz"));
    let program = root.join(format!("syft-{version}-{platform}"));
    if archive.is_file() {
        match verify_digest(&archive, digest) {
            Ok(()) => {}
            Err(ArchiveError::Invalid { .. }) => {
                fs::remove_file(&archive).map_err(|source| ArchiveError::Io {
                    action: "remove invalid cached Syft archive",
                    path: archive.clone(),
                    source,
                })?;
            }
            Err(error) => return Err(error),
        }
    }
    if !archive.is_file() {
        let temporary = temporary_file(&root, "syft-download")?;
        let mut curl = Command::new("/usr/bin/curl");
        curl.args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--output",
        ])
        .arg(&temporary)
        .arg(format!(
            "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_{platform}.tar.gz"
        ));
        let result = (|| {
            command::run(curl)?;
            verify_digest(&temporary, digest)?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)).map_err(
                |source| ArchiveError::Io {
                    action: "set cached Syft archive mode",
                    path: temporary.clone(),
                    source,
                },
            )?;
            fs::rename(&temporary, &archive).map_err(|source| ArchiveError::Io {
                action: "install pinned Syft archive",
                path: archive.clone(),
                source,
            })
        })();
        if temporary.exists() {
            fs::remove_file(&temporary).map_err(|source| ArchiveError::Io {
                action: "remove temporary Syft download",
                path: temporary,
                source,
            })?;
        }
        result?;
    }
    if !program.is_file() {
        let temporary = temporary_directory(&root, "syft")?;
        let result = (|| {
            let tar = release::tool("tar")?;
            let mut extract = Command::new(tar);
            extract.args(["-xzf"]);
            extract.arg(&archive).args(["-C"]).arg(&temporary);
            command::run(extract)?;
            let extracted = temporary.join("syft");
            if !extracted.is_file() {
                return invalid(
                    &extracted,
                    "pinned Syft archive contains no syft executable".to_string(),
                );
            }
            fs::set_permissions(&extracted, fs::Permissions::from_mode(0o755)).map_err(
                |source| ArchiveError::Io {
                    action: "set pinned Syft executable mode",
                    path: extracted.clone(),
                    source,
                },
            )?;
            fs::rename(&extracted, &program).map_err(|source| ArchiveError::Io {
                action: "install pinned Syft executable",
                path: program.clone(),
                source,
            })
        })();
        fs::remove_dir_all(&temporary).map_err(|source| ArchiveError::Io {
            action: "remove Syft extraction directory",
            path: temporary,
            source,
        })?;
        result?;
    }
    let reported = tool_output(&program, &["version"])?;
    if reported.contains(version) {
        Ok(program)
    } else {
        invalid(
            &program,
            format!("reported {reported:?}, expected Syft {version}"),
        )
    }
}

fn archive_entries(archive: &Path) -> Result<Vec<(char, String)>, ArchiveError> {
    let tar = release::tool("tar")?;
    let mut command = Command::new(tar);
    command.args(["--list", "--verbose", "--zstd", "--file"]);
    command.arg(archive);
    let output = command::output(command)?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            let kind = line.chars().next().ok_or_else(|| ArchiveError::Invalid {
                path: archive.to_path_buf(),
                reason: "empty verbose tar listing line".to_string(),
            })?;
            let path = line
                .split_whitespace()
                .last()
                .ok_or_else(|| ArchiveError::Invalid {
                    path: archive.to_path_buf(),
                    reason: format!("cannot parse verbose tar listing line {line:?}"),
                })?;
            Ok((kind, path.trim_end_matches('/').to_string()))
        })
        .collect()
}

fn validate_entries(
    workspace_root: &Path,
    entries: &[(char, String)],
    kind: ArchiveKind,
    root: &str,
) -> Result<(), ArchiveError> {
    let mut expected = BTreeMap::new();
    expected.insert(format!("{root}/bin"), 'd');
    expected.insert(format!("{root}/assets"), 'd');
    expected.insert(format!("{root}/THIRD_PARTY_NOTICES"), '-');
    expected.insert(format!("{root}/LICENSES/libkrun-APACHE-2.0.txt"), '-');
    for (path, _) in RUNTIME_FILES {
        expected.insert(format!("{root}/{path}"), '-');
    }
    if kind.has_cli() {
        expected.insert(format!("{root}/bin/silo"), '-');
    }
    let actual = entries
        .iter()
        .map(|(entry_kind, entry)| (entry.clone(), *entry_kind))
        .collect::<BTreeMap<_, _>>();
    if actual.len() != entries.len() {
        return invalid(
            workspace_root,
            "archive contains duplicate paths".to_string(),
        );
    }
    for (entry_kind, entry) in entries {
        if !safe_archive_path(entry) {
            return invalid(workspace_root, format!("archive entry {entry:?} is unsafe"));
        }
        if !matches!(entry_kind, '-' | 'd') {
            return invalid(
                workspace_root,
                format!("archive entry {entry:?} is not a regular file or directory"),
            );
        }
    }
    if actual != expected {
        return invalid(
            workspace_root,
            format!("archive entries are {actual:?}, expected {expected:?}"),
        );
    }
    Ok(())
}

fn extract_archive(archive: &Path, destination: &Path) -> Result<(), ArchiveError> {
    let tar = release::tool("tar")?;
    let mut command = Command::new(tar);
    command
        .args(["--extract", "--zstd", "--no-same-owner", "--file"])
        .arg(archive)
        .args(["--directory"])
        .arg(destination);
    command::run(command)?;
    Ok(())
}

fn validate_extracted(
    workspace_root: &Path,
    target_dir: &Path,
    stage: &Path,
    root: &Path,
    kind: ArchiveKind,
) -> Result<(), ArchiveError> {
    for (path, mode) in RUNTIME_FILES {
        validate_regular_file(&root.join(path), mode)?;
        compare_files(&stage.join(path), &root.join(path))?;
    }
    if kind.has_cli() {
        let source = target_dir.join("release/silo");
        validate_regular_file(&root.join("bin/silo"), 0o755)?;
        compare_files(&source, &root.join("bin/silo"))?;
    }
    for material in RELEASE_MATERIAL {
        validate_material(
            &workspace_root.join(material),
            &root.join(release_material_path(material)?),
        )?;
    }
    Ok(())
}

fn release_material_path(material: &str) -> Result<&'static str, ArchiveError> {
    match material {
        "packaging/release/THIRD_PARTY_NOTICES" => Ok("THIRD_PARTY_NOTICES"),
        "common/ext4/LICENSE-APACHE" => Ok("LICENSES/libkrun-APACHE-2.0.txt"),
        _ => invalid(Path::new(material), "unknown release material".to_string()),
    }
}

fn boot_portable_vm(root: &Path) -> Result<(), ArchiveError> {
    let temporary = temporary_directory(Path::new("/tmp"), "s")?;
    prepare_acceptance_state(&temporary)?;
    let name = format!("archive-acceptance-{}", std::process::id());
    let result = run_portable_command(
        root,
        &temporary,
        &["create", &name, "--image=ubuntu:24.04", "--start"],
    );
    let stop = run_portable_command(root, &temporary, &["stop", &name]);
    let remove = run_portable_command(root, &temporary, &["rm", &name, "--force"]);
    fs::remove_dir_all(&temporary).map_err(|source| ArchiveError::Io {
        action: "remove portable VM acceptance state",
        path: temporary,
        source,
    })?;
    result?;
    stop?;
    remove
}

fn prepare_acceptance_state(temporary: &Path) -> Result<(), ArchiveError> {
    for directory in ["data", "state", "run", "config"] {
        create_directory(&temporary.join(directory))?;
    }
    Ok(())
}

fn run_portable_command(root: &Path, temporary: &Path, args: &[&str]) -> Result<(), ArchiveError> {
    let mut command = Command::new(root.join("bin/silo"));
    command.args(args);
    for variable in RUNTIME_OVERRIDES {
        command.env_remove(variable);
    }
    command
        .env("XDG_DATA_HOME", temporary.join("data"))
        .env("XDG_STATE_HOME", temporary.join("state"))
        .env("XDG_RUNTIME_DIR", temporary.join("run"))
        .env("XDG_CONFIG_HOME", temporary.join("config"));
    run_with_timeout(command, Duration::from_secs(300)).map(|_| ())
}

fn run_with_timeout(mut command: Command, timeout: Duration) -> Result<Output, ArchiveError> {
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command.spawn().map_err(|source| ArchiveError::Io {
        action: "start archive acceptance command",
        path: PathBuf::from(&program),
        source,
    })?;
    let start = Instant::now();
    loop {
        match child.try_wait().map_err(|source| ArchiveError::Io {
            action: "wait for archive acceptance command",
            path: PathBuf::from(&program),
            source,
        })? {
            Some(status) if status.success() => {
                return Ok(Output {
                    status,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            Some(status) => {
                return Err(ArchiveError::Invalid {
                    path: PathBuf::from(program),
                    reason: format!("archive acceptance command exited with {status}"),
                });
            }
            None if start.elapsed() >= timeout => {
                child.kill().map_err(|source| ArchiveError::Io {
                    action: "stop timed out archive acceptance command",
                    path: PathBuf::from(&program),
                    source,
                })?;
                let _ = child.wait();
                return Err(ArchiveError::TimedOut {
                    program,
                    seconds: timeout.as_secs(),
                });
            }
            None => thread::sleep(Duration::from_millis(100)),
        }
    }
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

fn verify_checksum(archive: &Path) -> Result<(), ArchiveError> {
    let checksum = checksum_path(archive)?;
    let contents = String::from_utf8(read(&checksum)?).map_err(|error| ArchiveError::Invalid {
        path: checksum.clone(),
        reason: format!("checksum is not UTF-8: {error}"),
    })?;
    let expected = contents
        .split_whitespace()
        .next()
        .ok_or_else(|| ArchiveError::Invalid {
            path: checksum.clone(),
            reason: "checksum is empty".to_string(),
        })?;
    let actual = sha256(archive)?;
    if actual == expected {
        Ok(())
    } else {
        invalid(&checksum, format!("expected {expected}, got {actual}"))
    }
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

fn verify_sbom(archive: &Path, sbom: &Path) -> Result<(), ArchiveError> {
    let value: Value =
        serde_json::from_slice(&read(sbom)?).map_err(|error| ArchiveError::Invalid {
            path: sbom.to_path_buf(),
            reason: format!("cannot parse SPDX JSON SBOM: {error}"),
        })?;
    let expected = archive_name(archive)?;
    let actual = required_string(&value, "/name", sbom, "SBOM name")?;
    if actual == expected {
        Ok(())
    } else {
        invalid(
            sbom,
            format!("names archive {actual:?}, expected {expected:?}"),
        )
    }
}

fn verify_provenance(
    archive: &Path,
    provenance: &Path,
    version: &str,
    host: HostTarget,
) -> Result<(), ArchiveError> {
    let value: Value =
        serde_json::from_slice(&read(provenance)?).map_err(|error| ArchiveError::Invalid {
            path: provenance.to_path_buf(),
            reason: format!("cannot parse archive provenance: {error}"),
        })?;
    let name = archive_name(archive)?;
    let expected_sha256 = sha256(archive)?;
    for (pointer, expected, field) in [
        ("/archive/name", name, "archive name"),
        (
            "/archive/sha256",
            expected_sha256.as_str(),
            "archive SHA-256",
        ),
        ("/version", version, "version"),
        ("/target", host.runtime_target(), "target"),
    ] {
        let actual = required_string(&value, pointer, provenance, field)?;
        if actual != expected {
            return invalid(
                provenance,
                format!("{field} is {actual:?}, expected {expected:?}"),
            );
        }
    }
    verify_kernel_descriptors(
        value
            .pointer("/kernel")
            .ok_or_else(|| ArchiveError::Invalid {
                path: provenance.to_path_buf(),
                reason: "provenance contains no kernel record".to_string(),
            })?,
        provenance,
    )?;
    let raw = required_u64(&value, "/archive/raw_bytes", provenance, "raw archive size")?;
    let compressed = required_u64(
        &value,
        "/archive/compressed_bytes",
        provenance,
        "compressed archive size",
    )?;
    println!("verify-archive: {name} raw={raw} compressed={compressed}");
    Ok(())
}

fn verify_kernel_descriptors(kernel: &Value, provenance: &Path) -> Result<(), ArchiveError> {
    match required_string(kernel, "/source", provenance, "kernel source")? {
        "local" => verify_descriptor(
            kernel
                .pointer("/descriptor")
                .ok_or_else(|| ArchiveError::Invalid {
                    path: provenance.to_path_buf(),
                    reason: "local kernel provenance contains no descriptor".to_string(),
                })?,
            provenance,
            "local kernel",
        ),
        "oci" => {
            for name in ["index", "manifest", "config"] {
                verify_descriptor(
                    kernel
                        .pointer(&format!("/{name}"))
                        .ok_or_else(|| ArchiveError::Invalid {
                            path: provenance.to_path_buf(),
                            reason: format!("OCI kernel provenance contains no {name} descriptor"),
                        })?,
                    provenance,
                    name,
                )?;
            }
            let layers = kernel
                .pointer("/layers")
                .and_then(Value::as_array)
                .filter(|layers| !layers.is_empty())
                .ok_or_else(|| ArchiveError::Invalid {
                    path: provenance.to_path_buf(),
                    reason: "OCI kernel provenance contains no layer descriptors".to_string(),
                })?;
            for layer in layers {
                verify_descriptor(layer, provenance, "kernel layer")?;
            }
            Ok(())
        }
        source => invalid(
            provenance,
            format!("kernel source {source:?} has no descriptor contract"),
        ),
    }
}

fn verify_descriptor(
    descriptor: &Value,
    provenance: &Path,
    name: &str,
) -> Result<(), ArchiveError> {
    required_string(descriptor, "/digest", provenance, &format!("{name} digest"))?;
    required_u64(descriptor, "/size", provenance, &format!("{name} size"))?;
    Ok(())
}

fn required_string<'a>(
    value: &'a Value,
    pointer: &str,
    path: &Path,
    field: &str,
) -> Result<&'a str, ArchiveError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ArchiveError::Invalid {
            path: path.to_path_buf(),
            reason: format!("contains no {field}"),
        })
}

fn required_u64(
    value: &Value,
    pointer: &str,
    path: &Path,
    field: &str,
) -> Result<u64, ArchiveError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| ArchiveError::Invalid {
            path: path.to_path_buf(),
            reason: format!("contains no {field}"),
        })
}

fn archive_name(archive: &Path) -> Result<&str, ArchiveError> {
    archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ArchiveError::Invalid {
            path: archive.to_path_buf(),
            reason: "archive has no UTF-8 file name".to_string(),
        })
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
    Ok(version.trim().to_string())
}

fn stage_path(target_dir: &Path, host: HostTarget) -> PathBuf {
    target_dir
        .join("silo-runtime")
        .join(host.runtime_target())
        .join("release")
}

fn artifact_directory(target_dir: &Path, host: HostTarget, version: &str) -> PathBuf {
    target_dir
        .join("release-artifacts")
        .join(host.runtime_target())
        .join(version)
}

fn archive_root(kind: ArchiveKind, version: &str, host: HostTarget) -> String {
    format!("{}-{version}-{}", kind.prefix(), host.runtime_target())
}

fn validate_stage(stage: &Path) -> Result<(), ArchiveError> {
    for (path, mode) in RUNTIME_FILES {
        validate_regular_file(&stage.join(path), mode)?;
    }
    Ok(())
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

fn validate_material(source: &Path, destination: &Path) -> Result<(), ArchiveError> {
    let metadata = fs::symlink_metadata(source).map_err(|error| ArchiveError::Io {
        action: "read release material metadata",
        path: source.to_path_buf(),
        source: error,
    })?;
    if metadata.is_file() {
        compare_files(source, destination)
    } else if metadata.is_dir() {
        let source_entries = fs::read_dir(source).map_err(|error| ArchiveError::Io {
            action: "read release material directory",
            path: source.to_path_buf(),
            source: error,
        })?;
        for entry in source_entries {
            let entry = entry.map_err(|error| ArchiveError::Io {
                action: "read release material directory entry",
                path: source.to_path_buf(),
                source: error,
            })?;
            validate_material(&entry.path(), &destination.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        invalid(source, "is not regular release material".to_string())
    }
}

fn compare_files(left: &Path, right: &Path) -> Result<(), ArchiveError> {
    if read(left)? == read(right)? {
        Ok(())
    } else {
        invalid(
            right,
            format!("does not match {} byte-for-byte", left.display()),
        )
    }
}

fn safe_archive_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn sha256(path: &Path) -> Result<String, ArchiveError> {
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

fn verify_digest(path: &Path, expected: &str) -> Result<(), ArchiveError> {
    let actual = sha256(path)?;
    if actual == expected {
        Ok(())
    } else {
        invalid(path, format!("expected SHA-256 {expected}, got {actual}"))
    }
}

fn git_output(
    workspace_root: &Path,
    args: impl IntoIterator<Item = &'static str>,
) -> Result<String, ArchiveError> {
    let mut command = Command::new("/usr/bin/git");
    command.current_dir(workspace_root).args(args);
    let output = command::output(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn tool_output(path: &Path, args: &[&str]) -> Result<String, ArchiveError> {
    let mut command = Command::new(path);
    command.args(args);
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

fn temporary_directory(parent: &Path, name: &str) -> Result<PathBuf, ArchiveError> {
    create_directory(parent)?;
    for attempt in 0..128 {
        let path = parent.join(format!(".{name}-{}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                    |source| ArchiveError::Io {
                        action: "secure temporary archive directory",
                        path: path.clone(),
                        source,
                    },
                )?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ArchiveError::Io {
                    action: "create temporary archive directory",
                    path,
                    source,
                });
            }
        }
    }
    invalid(
        parent,
        "could not create a temporary archive directory".to_string(),
    )
}

fn temporary_file(parent: &Path, name: &str) -> Result<PathBuf, ArchiveError> {
    create_directory(parent)?;
    for attempt in 0..128 {
        let path = parent.join(format!(".{name}-{}-{attempt}", std::process::id()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(
                    |source| ArchiveError::Io {
                        action: "secure temporary archive file",
                        path: path.clone(),
                        source,
                    },
                )?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ArchiveError::Io {
                    action: "create temporary archive file",
                    path,
                    source,
                });
            }
        }
    }
    invalid(
        parent,
        "could not create a temporary archive file".to_string(),
    )
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
