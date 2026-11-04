//! Secure atomic publication for current monitor records.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;

use eyre::Context;
use nix::fcntl::{open, openat, renameat, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode, SFlag};
use nix::unistd::{unlinkat, UnlinkatFlags};

pub(crate) fn write(path: &Path, payload: &[u8]) -> eyre::Result<()> {
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
    let result = write_and_replace(&directory, &temp_name, name, path, payload);
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

pub(crate) fn temporary_name(name: &OsStr) -> OsString {
    let mut temporary = OsString::from(".");
    temporary.push(name);
    temporary.push(".");
    temporary.push(uuid::Uuid::new_v4().to_string());
    temporary.push(".tmp");
    temporary
}
