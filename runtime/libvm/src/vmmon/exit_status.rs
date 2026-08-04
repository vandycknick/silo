use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use nix::unistd::geteuid;
use serde::Deserialize;

/// Exit status written by vmmon when a machine run ends.
///
/// This is vmmon telemetry, not the machine lifecycle state stored in SQLite.
/// The runtime uses it as one input while reconciling `MachineState` after a
/// monitor exits or disappears.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmonExitStatus {
    pub(crate) machine_id: String,
    pub(crate) run_id: String,
    pub(crate) pid: i32,
    pub(crate) exited_at: i64,
    pub(crate) outcome: VmmonExitOutcome,
    pub(crate) error: Option<String>,
}

/// High-level outcome reported in a vmmon exit status file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VmmonExitOutcome {
    Clean,
    Error,
}

pub(crate) fn read(path: &Path) -> io::Result<Option<VmmonExitStatus>> {
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
            format!("parse vmmon exit status from {}: {err}", path.display()),
        )
    })?;
    Ok(Some(status))
}

fn path_error(path: &Path, error: nix::errno::Errno) -> io::Error {
    io::Error::other(format!(
        "open vmmon exit status {}: {error}",
        path.display()
    ))
}

fn invalid(path: &Path, message: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid vmmon exit status {}: {message}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use crate::vmmon::exit_status::read;

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
