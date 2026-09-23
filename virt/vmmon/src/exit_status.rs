use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use eyre::Context;
use nix::fcntl::{open, openat, renameat, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode, SFlag};
use nix::unistd::{unlinkat, UnlinkatFlags};
use serde::Serialize;

use crate::virt::exit::{Diagnostic, ForceReason, ProcessExit, StartupStage};
use crate::virt::{BackendKind, VmExit};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExitStatus {
    machine_id: String,
    run_id: String,
    pid: i32,
    exited_at: i64,
    outcome: ExitOutcome,
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<BackendExit>,
}

/// Backend detail of the terminal outcome. libvm stores it without
/// interpreting it; fields are added, never repurposed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendExit {
    kind: &'static str,
    stage: StartupStage,
    force_reason: Option<ForceReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<ProcessExit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<Diagnostic>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExitOutcome {
    Clean,
    Error,
    Forced,
}

impl ExitStatus {
    pub(crate) fn new(
        machine_id: String,
        run_id: String,
        outcome: ExitOutcome,
        error: Option<String>,
    ) -> eyre::Result<Self> {
        let pid = i32::try_from(std::process::id()).context("convert silo-vmmon pid")?;
        Ok(Self {
            machine_id,
            run_id,
            pid,
            exited_at: current_unix(),
            outcome,
            error,
            backend: None,
        })
    }

    pub(crate) fn with_vm_exit(mut self, kind: BackendKind, exit: VmExit) -> Self {
        self.error = self.error.or_else(|| exit.error());
        self.outcome = if self.error.is_some() {
            ExitOutcome::Error
        } else if exit.forced() {
            ExitOutcome::Forced
        } else {
            ExitOutcome::Clean
        };
        self.backend = Some(BackendExit {
            kind: kind.name(),
            stage: exit.stage,
            force_reason: exit.force_reason,
            process: exit.process,
            diagnostic: exit.diagnostic,
        });
        self
    }
}

pub(crate) fn write(path: &Path, status: &ExitStatus) -> eyre::Result<()> {
    let payload = serde_json::to_vec_pretty(status).context("serialize exit status")?;
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("exit status path has no parent: {}", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| eyre::eyre!("exit status path has no filename: {}", path.display()))?;
    let directory = open(
        parent,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(eyre::Report::from)
    .wrap_err_with(|| format!("open exit status directory {}", parent.display()))?;
    validate_directory(&directory, parent)?;
    validate_existing_target(&directory, name, path)?;

    let temp_name = temporary_name(name);
    let result = write_and_replace(&directory, &temp_name, name, path, &payload);
    if result.is_err() {
        let _ = unlinkat(directory, temp_name.as_os_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

fn write_and_replace(
    directory: &OwnedFd,
    temp_name: &OsString,
    name: &OsStr,
    path: &Path,
    payload: &[u8],
) -> eyre::Result<()> {
    let fd = openat(
        directory,
        temp_name.as_os_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_retain(0o600),
    )
    .map_err(eyre::Report::from)
    .wrap_err_with(|| format!("create exit status temporary file for {}", path.display()))?;
    fchmod(&fd, Mode::from_bits_retain(0o600))
        .map_err(eyre::Report::from)
        .wrap_err_with(|| {
            format!(
                "set mode on exit status temporary file for {}",
                path.display()
            )
        })?;
    validate_regular_file(&fd, path)?;

    let mut file = File::from(fd);
    file.write_all(payload)
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("write exit status {}", path.display()))?;
    file.sync_all()
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("sync exit status temporary file for {}", path.display()))?;
    drop(file);

    renameat(directory, temp_name.as_os_str(), directory, name)
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("replace exit status {}", path.display()))?;
    File::from(directory.try_clone().map_err(eyre::Report::from)?)
        .sync_all()
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("sync exit status directory {}", path.display()))
}

fn validate_directory(fd: &OwnedFd, path: &Path) -> eyre::Result<()> {
    let stat = fstat(fd)
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("inspect exit status directory {}", path.display()))?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR {
        return Err(eyre::eyre!("{} is not a directory", path.display()));
    }
    if stat.st_uid != nix::unistd::geteuid().as_raw() {
        return Err(eyre::eyre!(
            "{} is owned by UID {}, expected UID {}",
            path.display(),
            stat.st_uid,
            nix::unistd::geteuid().as_raw()
        ));
    }
    if stat.st_mode & 0o7777 != 0o700 {
        return Err(eyre::eyre!(
            "{} has mode {:o}, expected 700",
            path.display(),
            stat.st_mode & 0o7777
        ));
    }
    Ok(())
}

fn validate_existing_target(directory: &OwnedFd, name: &OsStr, path: &Path) -> eyre::Result<()> {
    let fd = match openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(()),
        Err(error) => {
            return Err(eyre::Report::from(error))
                .wrap_err_with(|| format!("open existing exit status {}", path.display()));
        }
    };
    validate_regular_file(&fd, path)
}

fn validate_regular_file(fd: &OwnedFd, path: &Path) -> eyre::Result<()> {
    let stat = fstat(fd)
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("inspect exit status {}", path.display()))?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
        return Err(eyre::eyre!("{} is not a regular file", path.display()));
    }
    if stat.st_uid != nix::unistd::geteuid().as_raw() {
        return Err(eyre::eyre!(
            "{} is owned by UID {}, expected UID {}",
            path.display(),
            stat.st_uid,
            nix::unistd::geteuid().as_raw()
        ));
    }
    if stat.st_mode & 0o777 != 0o600 {
        return Err(eyre::eyre!(
            "{} has mode {:o}, expected 600",
            path.display(),
            stat.st_mode & 0o777
        ));
    }
    Ok(())
}

fn temporary_name(name: &OsStr) -> OsString {
    let mut temporary = OsString::from(".");
    temporary.push(name);
    temporary.push(".");
    temporary.push(uuid::Uuid::new_v4().to_string());
    temporary.push(".tmp");
    temporary
}

fn current_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use serde_json::Value;

    use crate::exit_status::{temporary_name, write, ExitOutcome, ExitStatus};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("silo-vmmon-exit-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).expect("create temporary directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure temporary directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn status(run_id: &str) -> ExitStatus {
        ExitStatus::new(
            "machine-1".to_string(),
            run_id.to_string(),
            ExitOutcome::Clean,
            None,
        )
        .expect("build exit status")
    }

    #[test]
    fn backend_force_is_not_a_crash_and_does_not_replace_startup_failure() {
        use crate::virt::exit::{
            Diagnostic, ForceReason, ProcessExit, StartupStage, VmExit, VmOutcome,
        };
        use crate::virt::BackendKind;
        let exit = VmExit {
            outcome: VmOutcome::Forced,
            stage: StartupStage::Build,
            force_reason: Some(ForceReason::StartupFailure),
            process: Some(ProcessExit {
                pid: 123,
                raw_status: 9,
                code: None,
                signal: Some(9),
                core_dumped: false,
            }),
            diagnostic: Some(Diagnostic {
                tail: "diagnostic".to_string(),
                truncated: false,
            }),
        };
        for error in [None, Some("admission failed".to_string())] {
            let record = ExitStatus::new(
                "machine".to_string(),
                "run".to_string(),
                ExitOutcome::Clean,
                error.clone(),
            )
            .expect("record")
            .with_vm_exit(BackendKind::Krun, exit.clone());
            let value = serde_json::to_value(record).expect("encode record");
            assert_eq!(value["pid"], std::process::id());
            assert_eq!(value["backend"]["kind"], "krun");
            assert_eq!(value["backend"]["stage"], "build");
            assert_eq!(value["backend"]["forceReason"], "startup_failure");
            assert_eq!(value["backend"]["process"]["pid"], 123);
            assert_eq!(value["backend"]["process"]["rawStatus"], 9);
            assert_eq!(value["backend"]["diagnostic"]["tail"], "diagnostic");
            if error.is_none() {
                assert_eq!(value["outcome"], "forced");
            } else {
                assert_eq!(value["error"], "admission failed");
                assert_eq!(value["outcome"], "error");
            }
        }
    }

    #[test]
    fn backend_without_process_omits_process_and_diagnostic() {
        use crate::virt::exit::{StartupStage, VmExit};
        use crate::virt::BackendKind;
        let record =
            status("run").with_vm_exit(BackendKind::Vz, VmExit::stopped(StartupStage::Started));
        let value = serde_json::to_value(record).expect("encode record");
        assert_eq!(value["outcome"], "clean");
        assert_eq!(value["backend"]["kind"], "vz");
        assert_eq!(value["backend"]["stage"], "started");
        assert!(value["backend"]["forceReason"].is_null());
        assert!(value["backend"].get("process").is_none());
        assert!(value["backend"].get("diagnostic").is_none());
    }

    #[test]
    fn record_without_machine_has_no_backend_block() {
        let value = serde_json::to_value(status("run")).expect("encode record");
        assert!(value.get("backend").is_none());
    }

    #[test]
    fn atomic_exit_record_is_private_complete_and_replaces_prior_record() {
        let dir = TempDir::new();
        let path = dir.path().join("vm.exit.json");
        write(&path, &status("run-1")).expect("write initial exit record");
        write(&path, &status("run-2")).expect("replace exit record");

        let value: Value = serde_json::from_slice(&fs::read(&path).expect("read exit record"))
            .expect("parse exit record");
        assert_eq!(value["machineId"], "machine-1");
        assert_eq!(value["runId"], "run-2");
        assert!(value.get("error").is_some());
        assert_eq!(
            fs::metadata(&path)
                .expect("exit record metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(dir.path())
                .expect("read temporary directory")
                .count(),
            1
        );
    }

    #[test]
    fn exit_record_temp_names_are_unique_and_failed_replacement_preserves_prior_object() {
        let dir = TempDir::new();
        let path = dir.path().join("vm.exit.json");
        let first = temporary_name(path.file_name().expect("exit filename"));
        let second = temporary_name(path.file_name().expect("exit filename"));
        assert_ne!(first, second);

        fs::create_dir(&path).expect("create invalid prior exit record");
        assert!(write(&path, &status("run-2")).is_err());
        assert!(path.is_dir());
        assert_eq!(
            fs::read_dir(dir.path())
                .expect("read temporary directory")
                .count(),
            1
        );
    }
}
