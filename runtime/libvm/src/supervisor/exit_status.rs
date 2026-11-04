use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use nix::fcntl::{open, openat, renameat, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode, SFlag};
use nix::unistd::{geteuid, unlinkat, UnlinkatFlags};
use serde::Serialize;

use protocol::shutdown::CurrentExitRecord;

pub(crate) fn storage_outcome(
    status: &CurrentExitRecord,
    machine_id: &str,
    run_id: &str,
) -> crate::StorageStopOutcome {
    match status.classify(machine_id, run_id) {
        protocol::shutdown::StorageStopOutcome::Clean => crate::StorageStopOutcome::Clean,
        protocol::shutdown::StorageStopOutcome::Forced => crate::StorageStopOutcome::Forced,
        protocol::shutdown::StorageStopOutcome::Unknown => crate::StorageStopOutcome::Unknown,
    }
}

pub(crate) fn read(path: &Path) -> io::Result<Option<CurrentExitRecord>> {
    let fd = match open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
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
    if stat.st_nlink != 1 {
        return Err(invalid(path, "does not have exactly one link"));
    }
    if stat.st_mode & 0o7777 != 0o600 {
        return Err(invalid(
            path,
            format!("has mode {:o}, expected 600", stat.st_mode & 0o7777),
        ));
    }
    let mut raw = Vec::new();
    File::from(fd)
        .take((protocol::STRUCTURED_16_MIB + 1) as u64)
        .read_to_end(&mut raw)?;
    CurrentExitRecord::decode(&raw)
        .map(Some)
        .map_err(|message| invalid(path, message))
}

/// Records a confirmed forced exit while the caller still owns the machine's
/// lifecycle lock. The lock must span killing, observing exit, and publication
/// so this record cannot overwrite evidence from a replacement generation.
pub(crate) fn write_forced(
    path: &Path,
    machine_id: &str,
    run_id: &str,
    pid: i32,
) -> io::Result<i64> {
    protocol::shutdown::validate_uuid(machine_id)
        .and_then(|()| protocol::shutdown::validate_uuid(run_id))
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid monitor pid",
        ));
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ForcedExit<'a> {
        machine_id: &'a str,
        run_id: &'a str,
        pid: i32,
        exited_at: i64,
        outcome: &'static str,
    }
    let exited_at = crate::utils::now_unix();
    let payload = serde_json::to_vec(&ForcedExit {
        machine_id,
        run_id,
        pid,
        exited_at,
        outcome: "forced",
    })
    .map_err(io::Error::other)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid(path, "has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid(path, "has no filename"))?;
    let directory = File::from(open(
        parent,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    let stat = fstat(&directory)?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(invalid(parent, "is not a private owned directory"));
    }
    let temporary = format!(".exit-{}.tmp", uuid::Uuid::new_v4());
    let fd = openat(
        &directory,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_retain(0o600),
    )?;
    let result = (|| {
        fchmod(&fd, Mode::from_bits_retain(0o600))?;
        let mut file = File::from(fd);
        file.write_all(&payload)?;
        file.sync_all()?;
        renameat(&directory, temporary.as_str(), &directory, name)?;
        directory.sync_all()
    })();
    if result.is_err() {
        let _ = unlinkat(&directory, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result.map(|()| exited_at)
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
    use crate::supervisor::exit_status::{read, storage_outcome};
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn private_exit_reader_preserves_forced_despite_malformed_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vm.exit.json");
        let machine = uuid::Uuid::new_v4().to_string();
        let run = uuid::Uuid::new_v4().to_string();
        let raw = format!(
            r#"{{"machineId":"{machine}","runId":"{run}","pid":42,"exitedAt":99,"outcome":"forced","storageShutdown":{{"version":1,"guestProtocolCompleted":true,"guestProtocolCompleted":false}}}}"#
        );
        std::fs::write(&path, raw).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let status = read(&path).unwrap().unwrap();
        assert_eq!(
            storage_outcome(&status, &machine, &run),
            crate::StorageStopOutcome::Forced
        );
        assert_eq!(
            storage_outcome(&status, &machine, &uuid::Uuid::new_v4().to_string()),
            crate::StorageStopOutcome::Unknown
        );
    }

    #[test]
    fn private_exit_reader_rejects_malformed_outer_and_unsafe_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vm.exit.json");
        std::fs::write(&path, b"{").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read(&path).is_err());
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path).is_err());
    }
}
