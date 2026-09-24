use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use nix::unistd::geteuid;
use serde::Deserialize;

/// Exit status written by silo-vmm when a machine run ends.
///
/// This is silo-vmm telemetry, not the machine lifecycle state stored in SQLite.
/// The runtime uses it as one input while reconciling `MachineState` after a
/// monitor exits or disappears.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmExitStatus {
    pub(crate) machine_id: String,
    pub(crate) run_id: String,
    pub(crate) pid: i32,
    pub(crate) exited_at: i64,
    pub(crate) outcome: VmmExitOutcome,
    pub(crate) error: Option<String>,
    pub(crate) backend: Option<VmmBackendExit>,
}

/// Backend detail of the terminal outcome. Stored for diagnosis, never
/// interpreted by reconciliation and never a replacement for the monitor pid.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmBackendExit {
    pub(crate) kind: String,
    pub(crate) stage: String,
    pub(crate) force_reason: Option<String>,
    pub(crate) process: Option<VmmProcessExit>,
    pub(crate) diagnostic: Option<VmmDiagnostic>,
}

/// Wait status of the process that ran the VMM, when the backend owns one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmProcessExit {
    pub(crate) pid: u32,
    pub(crate) raw_status: i32,
    pub(crate) code: Option<i32>,
    pub(crate) signal: Option<i32>,
    pub(crate) core_dumped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmDiagnostic {
    pub(crate) tail: String,
    pub(crate) truncated: bool,
}

/// High-level outcome reported in a silo-vmm exit status file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VmmExitOutcome {
    Clean,
    Error,
    Forced,
}

pub(crate) fn read(path: &Path) -> io::Result<Option<VmmExitStatus>> {
    let fd = match open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(path_error(path, error)),
    };
    let stat = fstat(&fd).map_err(|error| path_error(path, error))?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
        return Err(invalid(path, "is not a regular file"));
    }
    if stat.st_uid != geteuid().as_raw() {
        return Err(invalid(
            path,
            format!(
                "is owned by uid {}, expected effective uid {}",
                stat.st_uid,
                geteuid().as_raw()
            ),
        ));
    }
    if stat.st_mode & 0o7777 != 0o600 {
        return Err(invalid(
            path,
            format!("has mode {:o}, expected 600", stat.st_mode & 0o7777),
        ));
    }
    let mut raw = String::new();
    File::from(fd).read_to_string(&mut raw)?;
    let status = serde_json::from_str(&raw).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse silo-vmm exit status from {}: {err}", path.display()),
        )
    })?;
    Ok(Some(status))
}

fn path_error(path: &Path, error: nix::errno::Errno) -> io::Error {
    io::Error::other(format!(
        "open silo-vmm exit status {}: {error}",
        path.display()
    ))
}

fn invalid(path: &Path, message: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid silo-vmm exit status {}: {message}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use crate::supervisor::exit_status::read;

    #[test]
    fn exit_status_requires_current_private_schema() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("vm.exit.json");
        std::fs::write(
            &path,
            r#"{"machineId":"machine-1","runId":"run-1","pid":42,"exitedAt":99,"outcome":"clean","error":null}"#,
        )
        .expect("write exit status");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure exit status");

        let status = read(&path)
            .expect("read exit status")
            .expect("exit status exists");
        assert_eq!(status.machine_id, "machine-1");
        assert_eq!(status.run_id, "run-1");
        assert_eq!(status.pid, 42);

        std::fs::write(
            &path,
            r#"{"runId":"run-1","pid":42,"exitedAt":99,"outcome":"clean"}"#,
        )
        .expect("write legacy exit status");
        assert!(read(&path).is_err());
    }

    #[test]
    fn backend_detail_is_additive_and_keeps_supervisor_identity() {
        let status: crate::supervisor::exit_status::VmmExitStatus =
            serde_json::from_value(serde_json::json!({
                "machineId": "machine-1", "runId": "run-1", "pid": 42,
                "exitedAt": 99, "outcome": "forced", "error": null,
                "backend": { "kind": "krun", "stage": "started", "forceReason": "stop",
                    "process": { "pid": 43, "rawStatus": 9, "code": null, "signal": 9,
                        "coreDumped": false },
                    "diagnostic": { "tail": "tail", "truncated": false },
                    "futureField": true }
            }))
            .expect("read additive backend detail");
        assert_eq!(status.pid, 42);
        let backend = status.backend.expect("backend");
        assert_eq!(backend.kind, "krun");
        assert_eq!(backend.force_reason.as_deref(), Some("stop"));
        assert_eq!(backend.process.expect("process").pid, 43);
        assert_eq!(backend.diagnostic.expect("diagnostic").tail, "tail");
        assert_eq!(
            status.outcome,
            crate::supervisor::exit_status::VmmExitOutcome::Forced
        );
    }

    #[test]
    fn backend_detail_is_optional_at_every_level() {
        let status: crate::supervisor::exit_status::VmmExitStatus =
            serde_json::from_value(serde_json::json!({
                "machineId": "machine-1", "runId": "run-1", "pid": 42,
                "exitedAt": 99, "outcome": "clean", "error": null,
                "backend": { "kind": "vz", "stage": "started", "forceReason": null }
            }))
            .expect("read backend without process");
        let backend = status.backend.expect("backend");
        assert!(backend.process.is_none());
        assert!(backend.diagnostic.is_none());

        let status: crate::supervisor::exit_status::VmmExitStatus =
            serde_json::from_value(serde_json::json!({
                "machineId": "machine-1", "runId": "run-1", "pid": 42,
                "exitedAt": 99, "outcome": "error", "error": "startup cancelled"
            }))
            .expect("read record without backend");
        assert!(status.backend.is_none());
    }

    #[test]
    fn exit_status_rejects_unsafe_objects() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let permissive = temp.path().join("permissive.json");
        std::fs::write(
            &permissive,
            r#"{"machineId":"machine-1","runId":"run-1","pid":42,"exitedAt":99,"outcome":"clean"}"#,
        )
        .expect("write permissive exit status");
        std::fs::set_permissions(&permissive, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive mode");
        assert!(read(&permissive).is_err());

        let target = temp.path().join("target.json");
        std::fs::write(&target, b"target").expect("write symlink target");
        let link = temp.path().join("link.json");
        symlink(&target, &link).expect("create symlink");
        assert!(read(&link).is_err());
        assert_eq!(
            std::fs::read(&target).expect("read symlink target"),
            b"target"
        );
    }
}
