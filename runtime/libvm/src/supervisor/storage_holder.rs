use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use nix::unistd::geteuid;
use protocol::shutdown::{StorageHolderRecord, MAX_HOLDER_BYTES};

use crate::supervisor::process::ProcessIdentity;

pub(crate) fn read(path: &Path) -> io::Result<Option<StorageHolderRecord>> {
    let fd = match open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let stat = fstat(&fd)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "storage holder is not a private owned regular file",
        ));
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take((MAX_HOLDER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    StorageHolderRecord::decode(&bytes)
        .map(Some)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))
}

/// PID reuse is terminal for the recorded identity, not a live replacement owner.
/// Opening a pidfd (where available) and comparing birth identity are independent
/// of the operation's exclusive lease probe.
pub(crate) fn all_terminal(record: &StorageHolderRecord) -> io::Result<bool> {
    for holder in &record.holders {
        let pid = i32::try_from(holder.pid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid storage holder pid")
        })?;
        let started_at = i64::try_from(holder.started_at).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid storage holder start identity",
            )
        })?;
        if let Some(identity) = ProcessIdentity::for_pid(pid)? {
            if identity.matches_started_at(Some(started_at)) && identity.is_alive()? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// The caller holds lifecycle exclusion and an independent exclusive lease,
/// and has already reconciled the operation and observed every holder terminal.
pub(crate) fn remove_reconciled(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "holder has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "holder has no filename"))?;
    let directory = open(
        parent,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let stat = fstat(&directory)?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "holder parent is not private and owned",
        ));
    }
    nix::unistd::unlinkat(&directory, name, nix::unistd::UnlinkatFlags::NoRemoveDir)?;
    File::from(directory).sync_all()
}

#[cfg(test)]
mod tests {
    use crate::supervisor::process::ProcessIdentity;
    use crate::supervisor::storage_holder::all_terminal;
    use protocol::shutdown::{StorageHolder, StorageHolderRecord, StorageHolderRole};

    #[test]
    fn live_holder_blocks_terminality_even_without_monitor() {
        let identity = ProcessIdentity::for_pid(std::process::id() as i32)
            .unwrap()
            .unwrap();
        let mut record = StorageHolderRecord {
            schema_version: 1,
            machine_id: uuid::Uuid::new_v4().to_string(),
            run_id: uuid::Uuid::new_v4().to_string(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            holders: vec![StorageHolder {
                role: StorageHolderRole::Monitor,
                pid: std::process::id(),
                started_at: u64::try_from(identity.started_at().unwrap()).unwrap(),
            }],
        };
        assert!(!all_terminal(&record).unwrap());
        record.holders[0].started_at += 1;
        assert!(all_terminal(&record).unwrap());
    }
}
