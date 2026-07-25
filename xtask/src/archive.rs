use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::release_target::{BuildProfile, ReleaseTarget};
use crate::remove_path::remove_if_exists;

#[derive(Debug)]
pub(crate) struct PackageArchivesOptions {
    pub(crate) target: ReleaseTarget,
    pub(crate) target_dir: PathBuf,
    pub(crate) workspace_root: PathBuf,
}

#[derive(Debug)]
pub(crate) struct ArchiveResult {
    pub(crate) runtime: PathBuf,
    pub(crate) cli: PathBuf,
    pub(crate) metadata: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum ArchiveError {
    #[error("invalid archive input: {reason}")]
    Invalid { reason: String },
    #[error("failed to {operation} {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("failed to run {command}")]
    Run { command: String, source: io::Error },
    #[error("{command} failed with status {status}")]
    CommandFailed { command: String, status: String },
}

struct Temporary(PathBuf);

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn package_archives(
    options: &PackageArchivesOptions,
) -> Result<ArchiveResult, ArchiveError> {
    let descriptor = options.target.descriptor();
    let runtime = descriptor.stage_dir_in(&options.target_dir, BuildProfile::Release);
    validate_tree(&runtime, false, false)?;
    let release = options
        .target_dir
        .join("silo-release")
        .join(descriptor.name)
        .join("release");
    let cli = release.join("bin/silo");
    require_file(&cli)?;
    let release_metadata = read_json(&release.join("metadata/release.json"))?;
    let epoch = release_metadata
        .pointer("/source/sourceDateEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| ArchiveError::Invalid {
            reason: "release metadata has no source.sourceDateEpoch".to_string(),
        })?;
    let version = env!("CARGO_PKG_VERSION");
    let output = options
        .target_dir
        .join("silo-artifacts")
        .join(descriptor.name)
        .join(version);
    remove_if_exists(&output)
        .map_err(|source| io_error("remove previous archive output", &output, source))?;
    let parent = output.parent().ok_or_else(|| ArchiveError::Invalid {
        reason: format!("{} has no parent", output.display()),
    })?;
    fs::create_dir_all(parent)
        .map_err(|source| io_error("create artifact parent", parent, source))?;
    let temporary = Temporary(parent.join(nonce()));
    fs::create_dir(&temporary.0)
        .map_err(|source| io_error("create temporary artifact directory", &temporary.0, source))?;
    let assembly = temporary.0.join("assembly");
    fs::create_dir(&assembly)
        .map_err(|source| io_error("create archive assembly", &assembly, source))?;

    let runtime_name = format!("silo-runtime-{version}-{}", descriptor.name);
    let runtime_root = assembly.join(&runtime_name);
    copy_tree(&runtime, &runtime_root)?;
    copy_notice(options, &runtime_root)?;
    let runtime_archive = temporary.0.join(format!("{runtime_name}.tar.zst"));
    create_archive(&assembly, &runtime_name, epoch, &runtime_archive)?;

    let cli_name = format!("silo-{version}-{}", descriptor.name);
    let cli_root = assembly.join(&cli_name);
    copy_tree(&runtime, &cli_root)?;
    copy_file(&cli, &cli_root.join("bin/silo"), 0o755)?;
    copy_notice(options, &cli_root)?;
    let cli_archive = temporary.0.join(format!("{cli_name}.tar.zst"));
    create_archive(&assembly, &cli_name, epoch, &cli_archive)?;

    verify_archive(&runtime_archive, &runtime_name, false, &temporary.0)?;
    verify_archive(&cli_archive, &cli_name, true, &temporary.0)?;
    fs::remove_dir_all(&assembly)
        .map_err(|source| io_error("remove archive assembly", &assembly, source))?;
    let archives = [
        archive_metadata(&runtime_archive)?,
        archive_metadata(&cli_archive)?,
    ];
    write_checksum(&runtime_archive)?;
    write_checksum(&cli_archive)?;
    let metadata_path = temporary.0.join("archives.json");
    write_json(
        &metadata_path,
        &serde_json::json!({
            "schemaVersion": 1,
            "version": version,
            "target": descriptor.name,
            "sourceDateEpoch": epoch,
            "archives": archives,
        }),
    )?;
    fs::rename(&temporary.0, &output)
        .map_err(|source| io_error("publish archive output", &output, source))?;
    Ok(ArchiveResult {
        runtime: output.join(format!("{runtime_name}.tar.zst")),
        cli: output.join(format!("{cli_name}.tar.zst")),
        metadata: output.join("archives.json"),
    })
}

fn create_archive(
    assembly: &Path,
    root: &str,
    epoch: u64,
    output: &Path,
) -> Result<(), ArchiveError> {
    let mut tar = Command::new("tar");
    tar.current_dir(assembly)
        .args([
            "--sort=name",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--format=posix",
            "--pax-option=delete=atime,delete=ctime",
        ])
        .arg(format!("--mtime=@{epoch}"))
        .args(["-cf", "-", root])
        .stdout(Stdio::piped());
    let rendered = format!("{tar:?}");
    let mut tar = tar.spawn().map_err(|source| ArchiveError::Run {
        command: rendered,
        source,
    })?;
    let stdout = tar.stdout.take().ok_or_else(|| ArchiveError::Invalid {
        reason: "tar stdout is unavailable".to_string(),
    })?;
    let status = Command::new("zstd")
        .args(["-q", "-19", "--threads=0", "--no-progress", "-o"])
        .arg(output)
        .stdin(Stdio::from(stdout))
        .status()
        .map_err(|source| ArchiveError::Run {
            command: "zstd".to_string(),
            source,
        })?;
    let tar_status = tar.wait().map_err(|source| ArchiveError::Run {
        command: "tar".to_string(),
        source,
    })?;
    require_success("tar", tar_status)?;
    require_success("zstd", status)
}

fn verify_archive(
    archive: &Path,
    root: &str,
    include_cli: bool,
    temporary: &Path,
) -> Result<(), ArchiveError> {
    let extraction = temporary.join(format!("extract-{root}"));
    fs::create_dir(&extraction)
        .map_err(|source| io_error("create extraction directory", &extraction, source))?;
    let mut zstd = Command::new("zstd");
    zstd.args(["-dc"]).arg(archive).stdout(Stdio::piped());
    let mut zstd = zstd.spawn().map_err(|source| ArchiveError::Run {
        command: "zstd -dc".to_string(),
        source,
    })?;
    let stdout = zstd.stdout.take().ok_or_else(|| ArchiveError::Invalid {
        reason: "zstd stdout is unavailable".to_string(),
    })?;
    let tar_status = Command::new("tar")
        .args(["--same-permissions", "-xf", "-", "-C"])
        .arg(&extraction)
        .stdin(Stdio::from(stdout))
        .status()
        .map_err(|source| ArchiveError::Run {
            command: "tar extract".to_string(),
            source,
        })?;
    let zstd_status = zstd.wait().map_err(|source| ArchiveError::Run {
        command: "zstd decompress".to_string(),
        source,
    })?;
    require_success("tar extract", tar_status)?;
    require_success("zstd decompress", zstd_status)?;
    let validation = validate_tree(&extraction.join(root), include_cli, true);
    fs::remove_dir_all(&extraction)
        .map_err(|source| io_error("remove archive verification directory", &extraction, source))?;
    validation
}

fn validate_tree(root: &Path, include_cli: bool, include_notice: bool) -> Result<(), ArchiveError> {
    let mut expected = vec![
        "assets/agent",
        "assets/initramfs",
        "assets/kernel-default",
        "bin/krun",
        "bin/netd",
        "bin/vmmon",
    ];
    if include_cli {
        expected.push("bin/silo");
    }
    if include_notice {
        expected.push("THIRD_PARTY_NOTICES.txt");
    }
    expected.sort_unstable();
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    if files != expected {
        return Err(ArchiveError::Invalid {
            reason: format!("expected archive files {expected:?}, found {files:?}"),
        });
    }
    for relative in ["bin/vmmon", "bin/netd", "bin/krun", "assets/agent"] {
        require_mode(&root.join(relative), 0o755)?;
    }
    if include_cli {
        require_mode(&root.join("bin/silo"), 0o755)?;
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<String>,
) -> Result<(), ArchiveError> {
    for entry in fs::read_dir(directory)
        .map_err(|source| io_error("read archive tree", directory, source))?
    {
        let entry = entry.map_err(|source| io_error("read archive entry", directory, source))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| io_error("inspect archive entry", &entry.path(), source))?;
        if metadata.file_type().is_symlink() {
            return Err(ArchiveError::Invalid {
                reason: format!("archive contains symlink {}", entry.path().display()),
            });
        }
        if metadata.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else if metadata.is_file() {
            files.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|error| ArchiveError::Invalid {
                        reason: error.to_string(),
                    })?
                    .to_string_lossy()
                    .to_string(),
            );
        } else {
            return Err(ArchiveError::Invalid {
                reason: format!("archive contains special file {}", entry.path().display()),
            });
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), ArchiveError> {
    fs::create_dir_all(destination)
        .map_err(|error| io_error("create archive tree", destination, error))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))
        .map_err(|error| io_error("set archive directory mode", destination, error))?;
    for entry in
        fs::read_dir(source).map_err(|error| io_error("read runtime tree", source, error))?
    {
        let entry = entry.map_err(|error| io_error("read runtime entry", source, error))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| io_error("inspect runtime entry", &entry.path(), error))?;
        let target = destination.join(entry.file_name());
        if metadata.file_type().is_symlink() {
            return Err(ArchiveError::Invalid {
                reason: format!("runtime contains symlink {}", entry.path().display()),
            });
        }
        if metadata.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if metadata.is_file() {
            copy_file(
                &entry.path(),
                &target,
                metadata.permissions().mode() & 0o777,
            )?;
        } else {
            return Err(ArchiveError::Invalid {
                reason: format!("runtime contains special file {}", entry.path().display()),
            });
        }
    }
    Ok(())
}

fn copy_notice(options: &PackageArchivesOptions, root: &Path) -> Result<(), ArchiveError> {
    copy_file(
        &options
            .workspace_root
            .join("packaging/THIRD_PARTY_NOTICES.txt"),
        &root.join("THIRD_PARTY_NOTICES.txt"),
        0o644,
    )
}

fn copy_file(source: &Path, destination: &Path, mode: u32) -> Result<(), ArchiveError> {
    require_file(source)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| io_error("create archive parent", parent, error))?;
    }
    fs::copy(source, destination)
        .map_err(|error| io_error("copy archive file", destination, error))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode))
        .map_err(|error| io_error("set archive file mode", destination, error))
}

fn require_file(path: &Path) -> Result<(), ArchiveError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect archive input", path, error))?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(ArchiveError::Invalid {
            reason: format!("{} is not a regular file", path.display()),
        })
    }
}

fn require_mode(path: &Path, expected: u32) -> Result<(), ArchiveError> {
    let actual = fs::metadata(path)
        .map_err(|error| io_error("inspect archive mode", path, error))?
        .permissions()
        .mode()
        & 0o777;
    if actual == expected {
        Ok(())
    } else {
        Err(ArchiveError::Invalid {
            reason: format!(
                "{} has mode {actual:o}, expected {expected:o}",
                path.display()
            ),
        })
    }
}

fn archive_metadata(path: &Path) -> Result<Value, ArchiveError> {
    Ok(serde_json::json!({
        "file": path.file_name().and_then(|name| name.to_str()),
        "sha256": sha256(path)?,
        "compressedSize": fs::metadata(path)
            .map_err(|error| io_error("inspect archive", path, error))?
            .len(),
    }))
}

fn write_checksum(path: &Path) -> Result<(), ArchiveError> {
    let digest = sha256(path)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ArchiveError::Invalid {
            reason: format!("archive has no UTF-8 name: {}", path.display()),
        })?;
    let checksum = PathBuf::from(format!("{}.sha256", path.display()));
    fs::write(
        &checksum,
        format!("{}  {name}\n", digest.trim_start_matches("sha256:")),
    )
    .map_err(|error| io_error("write archive checksum", &checksum, error))
}

fn sha256(path: &Path) -> Result<String, ArchiveError> {
    let mut file = File::open(path).map_err(|error| io_error("open archive", path, error))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| io_error("hash archive", path, error))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn read_json(path: &Path) -> Result<Value, ArchiveError> {
    serde_json::from_slice(
        &fs::read(path).map_err(|error| io_error("read release metadata", path, error))?,
    )
    .map_err(|error| ArchiveError::Invalid {
        reason: error.to_string(),
    })
}

fn write_json(path: &Path, value: &Value) -> Result<(), ArchiveError> {
    let mut file = File::create(path).map_err(|error| io_error("create metadata", path, error))?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|error| ArchiveError::Invalid {
        reason: error.to_string(),
    })?;
    file.write_all(b"\n")
        .map_err(|error| io_error("write metadata", path, error))
}

fn require_success(command: &str, status: std::process::ExitStatus) -> Result<(), ArchiveError> {
    if status.success() {
        Ok(())
    } else {
        Err(ArchiveError::CommandFailed {
            command: command.to_string(),
            status: status.to_string(),
        })
    }
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> ArchiveError {
    ArchiveError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(".archives-{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::archive::{package_archives, validate_tree, PackageArchivesOptions};
    use crate::release_target::{BuildProfile, ReleaseTarget};

    const UMASK_CHILD_TARGET: &str = "SILO_ARCHIVE_UMASK_CHILD_TARGET";
    const UMASK_CHILD_WORKSPACE: &str = "SILO_ARCHIVE_UMASK_CHILD_WORKSPACE";

    #[test]
    fn archive_tree_rejects_unexpected_files() {
        let temp = tempfile::tempdir().expect("create temp directory");
        std::fs::write(temp.path().join("unexpected"), b"bad").expect("write unexpected file");
        assert!(validate_tree(temp.path(), false, false).is_err());
    }

    #[test]
    fn portable_archives_are_reproducible_and_self_validating() {
        if let Some(target) = std::env::var_os(UMASK_CHILD_TARGET) {
            let workspace = std::env::var_os(UMASK_CHILD_WORKSPACE)
                .map(PathBuf::from)
                .expect("child workspace");
            let target = PathBuf::from(target);
            populate_release(&target);
            let output = archive_paths(&target).2;
            let output = output.parent().expect("archive output directory");
            std::fs::create_dir_all(output).expect("create stale archive output");
            std::fs::write(output.join("stale"), b"stale").expect("write stale archive output");
            let result = package_archives(&PackageArchivesOptions {
                target: ReleaseTarget::DarwinArm64,
                target_dir: target,
                workspace_root: workspace,
            })
            .expect("package child archives");
            assert!(result.metadata.is_file());
            assert!(!output.join("stale").exists());
            let published = std::fs::read_dir(output)
                .expect("read archive output")
                .collect::<Result<Vec<_>, _>>()
                .expect("read archive entries");
            assert_eq!(published.len(), 5);
            assert!(published.iter().all(|entry| entry.path().is_file()));
            return;
        }

        let temp = tempfile::tempdir().expect("create temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(workspace.join("packaging")).expect("create packaging directory");
        std::fs::write(
            workspace.join("packaging/THIRD_PARTY_NOTICES.txt"),
            b"notices\n",
        )
        .expect("write notices");
        let first_target = temp.path().join("first-target");
        let second_target = temp.path().join("second-target");
        package_with_umask(&first_target, &workspace, "022");
        package_with_umask(&second_target, &workspace, "077");
        let (first_runtime, first_cli, first_metadata) = archive_paths(&first_target);
        let (second_runtime, second_cli, second_metadata) = archive_paths(&second_target);

        assert_eq!(
            std::fs::read(first_runtime).expect("read first runtime archive"),
            std::fs::read(second_runtime).expect("read second runtime archive")
        );
        assert_eq!(
            std::fs::read(first_cli).expect("read first cli archive"),
            std::fs::read(second_cli).expect("read second cli archive")
        );
        assert!(first_metadata.is_file());
        assert!(second_metadata.is_file());
    }

    fn package_with_umask(target: &Path, workspace: &Path, umask: &str) {
        let test_binary = std::env::current_exe().expect("test binary");
        let status = Command::new("sh")
            .args(["-c", "umask \"$1\"; shift; exec \"$@\"", "sh", umask])
            .arg(test_binary)
            .args([
                "--exact",
                "archive::tests::portable_archives_are_reproducible_and_self_validating",
                "--nocapture",
            ])
            .env(UMASK_CHILD_TARGET, target)
            .env(UMASK_CHILD_WORKSPACE, workspace)
            .status()
            .expect("run archive packaging child");
        assert!(status.success(), "archive packaging child failed: {status}");
    }

    fn archive_paths(target_dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let descriptor = ReleaseTarget::DarwinArm64.descriptor();
        let version = env!("CARGO_PKG_VERSION");
        let output = target_dir
            .join("silo-artifacts")
            .join(descriptor.name)
            .join(version);
        (
            output.join(format!(
                "silo-runtime-{version}-{}.tar.zst",
                descriptor.name
            )),
            output.join(format!("silo-{version}-{}.tar.zst", descriptor.name)),
            output.join("archives.json"),
        )
    }

    fn populate_release(target_dir: &Path) {
        let target = ReleaseTarget::DarwinArm64;
        let runtime = target
            .descriptor()
            .stage_dir_in(target_dir, BuildProfile::Release);
        for relative in [
            "bin/vmmon",
            "bin/netd",
            "bin/krun",
            "assets/kernel-default",
            "assets/initramfs",
            "assets/agent",
        ] {
            let path = runtime.join(relative);
            std::fs::create_dir_all(path.parent().expect("component parent"))
                .expect("create component parent");
            std::fs::write(&path, relative).expect("write component");
            let mode = if relative.starts_with("bin/") || relative.ends_with("agent") {
                0o755
            } else {
                0o644
            };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .expect("set component mode");
        }
        let release = target_dir
            .join("silo-release")
            .join(target.descriptor().name)
            .join("release");
        std::fs::create_dir_all(release.join("bin")).expect("create release bin");
        std::fs::create_dir_all(release.join("metadata")).expect("create release metadata");
        std::fs::write(release.join("bin/silo"), b"silo").expect("write silo");
        std::fs::set_permissions(
            release.join("bin/silo"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("set silo mode");
        std::fs::write(
            release.join("metadata/release.json"),
            br#"{"source":{"sourceDateEpoch":1700000000}}"#,
        )
        .expect("write release metadata");
    }
}
