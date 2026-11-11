//! Inherited restore descriptors: early validation at process entry and
//! adoption against the exact start request. Numbers never authorize a path
//! open; every adopted descriptor is compared with fstat facts first.

use std::fs::File;
use std::io;
use std::os::fd::{BorrowedFd, FromRawFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::stat::{fstat, SFlag};
use vm_spec::restore::RestoreRequest;

/// Five state objects plus every lower descriptor and extent.
pub(crate) const MAX_RESTORE_FDS: usize = 5 + 16 + vm_spec::restore::MAX_RESTORE_LOWER_EXTENTS;
const MAX_ENV_BYTES: usize = 16 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Parse `_VM_RESTORE_OBJECTS`: a bounded JSON array of distinct numbers.
pub(crate) fn parse_env(value: Option<&std::ffi::OsStr>) -> eyre::Result<Vec<RawFd>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let value = value
        .to_str()
        .ok_or_else(|| eyre::eyre!("restore descriptor list is not UTF-8"))?;
    eyre::ensure!(
        value.len() <= MAX_ENV_BYTES,
        "restore descriptor list exceeds {}",
        utils::format_storage_size(MAX_ENV_BYTES as u64)
    );
    let fds: Vec<RawFd> = serde_json::from_str(value)
        .map_err(|error| eyre::eyre!("invalid restore descriptor list: {error}"))?;
    eyre::ensure!(
        (5..=MAX_RESTORE_FDS).contains(&fds.len()),
        "restore descriptor list must name 5..={MAX_RESTORE_FDS} descriptors"
    );
    Ok(fds)
}

/// Read-only buffered regular file, never append, path-only or direct I/O.
fn readonly_regular(fd: BorrowedFd<'_>) -> io::Result<(u64, u64, u64)> {
    let stat = fstat(fd)?;
    let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    #[cfg(target_os = "linux")]
    let forbidden = OFlag::O_APPEND | OFlag::O_PATH | OFlag::O_DIRECT;
    #[cfg(not(target_os = "linux"))]
    let forbidden = OFlag::O_APPEND;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || flags & OFlag::O_ACCMODE != OFlag::O_RDONLY
        || flags.intersects(forbidden)
        || stat.st_size <= 0
    {
        return Err(invalid(
            "restore descriptor is not a read-only buffered regular file",
        ));
    }
    Ok((stat.st_dev as u64, stat.st_ino as u64, stat.st_size as u64))
}

/// Validate every inherited restore number before any role takes ownership:
/// open, read-only regular, and never aliasing another inherited role.
pub(crate) fn validate_inherited(restore: &[RawFd], others: &[RawFd]) -> eyre::Result<()> {
    let mut other_identities = Vec::with_capacity(others.len());
    for &raw in others {
        // SAFETY: the caller validated these numbers as open inherited roles.
        let stat = fstat(unsafe { BorrowedFd::borrow_raw(raw) })?;
        other_identities.push((stat.st_dev as u64, stat.st_ino as u64));
    }
    for &raw in restore {
        // nix requires a valid FD before constructing a borrow.
        eyre::ensure!(
            unsafe { nix::libc::fcntl(raw, nix::libc::F_GETFD) } >= 0,
            "invalid inherited restore descriptor {raw}"
        );
        // SAFETY: probed open above; no ownership is taken here.
        let (device, inode, _) = readonly_regular(unsafe { BorrowedFd::borrow_raw(raw) })?;
        eyre::ensure!(
            !other_identities.contains(&(device, inode)),
            "inherited restore descriptor aliases another inherited role"
        );
    }
    Ok(())
}

/// One adopted lower closure.
#[derive(Debug)]
pub(crate) struct LowerFiles {
    pub(crate) descriptor: File,
    pub(crate) extents: Vec<File>,
}

/// The monitor's owned restore objects, in request order.
#[derive(Debug)]
pub(crate) struct RestoreFiles {
    pub(crate) objects: [File; 5],
    pub(crate) lowers: Vec<LowerFiles>,
}

impl RestoreFiles {
    /// Every descriptor in the fixed worker role order: objects, then each
    /// lower's descriptor followed by its extents.
    pub(crate) fn duplicates(&self) -> io::Result<(Vec<File>, Vec<File>)> {
        let objects = self
            .objects
            .iter()
            .map(File::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        let mut lowers = Vec::new();
        for lower in &self.lowers {
            lowers.push(lower.descriptor.try_clone()?);
            for extent in &lower.extents {
                lowers.push(extent.try_clone()?);
            }
        }
        Ok((objects, lowers))
    }

    /// The retained descriptor identity of the lower for `block_id`.
    pub(crate) fn lower_descriptor(
        &self,
        request: &RestoreRequest,
        block_id: &str,
    ) -> Option<&File> {
        request
            .lowers
            .iter()
            .zip(&self.lowers)
            .find(|(lower, _)| lower.block_id.as_str() == block_id)
            .map(|(_, files)| &files.descriptor)
    }
}

fn check(raw: RawFd, expected_fd: i32, device: u64, inode: u64, length: u64) -> io::Result<()> {
    if raw != expected_fd {
        return Err(invalid(
            "inherited restore descriptor order differs from the start request",
        ));
    }
    // SAFETY: validated as an open inherited role at process entry.
    let actual = readonly_regular(unsafe { BorrowedFd::borrow_raw(raw) })?;
    if actual != (device, inode, length) {
        return Err(invalid(
            "inherited restore descriptor differs from its sealed identity",
        ));
    }
    Ok(())
}

/// Adopt the complete inherited set only after every descriptor matched the
/// request. On refusal nothing is adopted; the CLOEXEC numbers die with exit.
pub(crate) fn adopt(raw: Vec<RawFd>, request: &RestoreRequest) -> io::Result<RestoreFiles> {
    let expected = 5 + request
        .lowers
        .iter()
        .map(|lower| 1 + lower.extents.len())
        .sum::<usize>();
    if raw.len() != expected {
        return Err(invalid(
            "inherited restore descriptors do not cover the start request",
        ));
    }
    let mut numbers = raw.iter().copied();
    let mut next = || {
        numbers
            .next()
            .ok_or_else(|| invalid("inherited restore descriptor is missing"))
    };
    let mut order = Vec::with_capacity(raw.len());
    for object in &request.objects {
        let fd = next()?;
        check(
            fd,
            object.fd,
            object.file_device,
            object.file_inode,
            object.length,
        )?;
        order.push(fd);
    }
    for lower in &request.lowers {
        let fd = next()?;
        let descriptor = &lower.descriptor;
        check(
            fd,
            descriptor.fd,
            descriptor.file_device,
            descriptor.file_inode,
            descriptor.length,
        )?;
        order.push(fd);
        for extent in &lower.extents {
            let fd = next()?;
            check(
                fd,
                extent.fd,
                extent.file_device,
                extent.file_inode,
                extent.length,
            )?;
            order.push(fd);
        }
    }
    // SAFETY: every number was validated, is unique, and is adopted once.
    let mut files = order.into_iter().map(|fd| unsafe { File::from_raw_fd(fd) });
    let mut take = || {
        files
            .next()
            .ok_or_else(|| invalid("inherited restore descriptor is missing"))
    };
    let objects = [take()?, take()?, take()?, take()?, take()?];
    let mut lowers = Vec::with_capacity(request.lowers.len());
    for lower in &request.lowers {
        let descriptor = take()?;
        let extents = (0..lower.extents.len())
            .map(|_| take())
            .collect::<io::Result<Vec<_>>>()?;
        lowers.push(LowerFiles {
            descriptor,
            extents,
        });
    }
    Ok(RestoreFiles { objects, lowers })
}

/// Identity of an adopted file, for cross-role checks.
pub(crate) fn identity(file: &File) -> io::Result<(u64, u64)> {
    let stat = fstat(file)?;
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

/// Decode the already immutable inherited map and authenticate its whole file
/// and complete stream identity against the seal, never against live child RAM.
pub(crate) fn verified_ram_map(
    request: &RestoreRequest,
    file: &File,
) -> io::Result<vm_spec::capture::StreamMap> {
    use std::os::unix::fs::FileExt as _;
    let object = request
        .objects
        .iter()
        .find(|object| object.role == vm_spec::restore::RestoreObjectRole::RamMap)
        .ok_or_else(|| invalid("restore lacks its complete RAM map"))?;
    if object.length > vm_spec::capture::MAX_RAM_MAP_BYTES as u64
        || file.metadata()?.len() != object.length
    {
        return Err(invalid(
            "restore RAM map exceeds its bound or changed length",
        ));
    }
    let mut bytes = vec![0; object.length as usize];
    file.read_exact_at(&mut bytes, 0)?;
    if vm_spec::capture::Sha256Digest::of_bytes(&bytes) != object.identity {
        return Err(invalid("restore RAM map differs from its sealed SHA"));
    }
    let map = vm_spec::capture::StreamMap::decode(&bytes).map_err(invalid)?;
    let memory = request
        .evidence
        .memory
        .as_ref()
        .ok_or_else(|| invalid("restore lacks RAM evidence"))?;
    if map.length() != memory.packed_length
        || map.id() != memory.ram_stream
        || map.canonical_bytes().map_err(invalid)? != bytes
    {
        return Err(invalid(
            "restore RAM map differs from the complete canonical stream",
        ));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    use crate::restore::inputs::{parse_env, validate_inherited, MAX_RESTORE_FDS};

    #[test]
    fn restore_descriptor_list_is_bounded_json() {
        assert!(parse_env(None).unwrap().is_empty());
        assert_eq!(
            parse_env(Some("[10,11,12,13,14]".as_ref())).unwrap(),
            vec![10, 11, 12, 13, 14]
        );
        for refused in ["[10,11,12,13]", "not json", "{\"fd\":1}"] {
            assert!(parse_env(Some(refused.as_ref())).is_err(), "{refused}");
        }
        let oversized =
            serde_json::to_string(&(0..=MAX_RESTORE_FDS as i32).collect::<Vec<_>>()).unwrap();
        assert!(parse_env(Some(oversized.as_ref())).is_err());
    }

    #[test]
    fn inherited_restore_descriptors_must_be_readonly_regular_and_unaliased() {
        let directory =
            std::env::temp_dir().join(format!("silo-restore-inputs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("object");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"state")
            .unwrap();
        let readonly = std::fs::File::open(&path).unwrap();
        validate_inherited(&[readonly.as_raw_fd()], &[]).unwrap();
        let writable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(validate_inherited(&[writable.as_raw_fd()], &[]).is_err());
        let alias = std::fs::File::open(&path).unwrap();
        assert!(validate_inherited(&[readonly.as_raw_fd()], &[alias.as_raw_fd()]).is_err());
        let empty = directory.join("empty");
        std::fs::File::create(&empty).unwrap();
        let empty = std::fs::File::open(&empty).unwrap();
        assert!(validate_inherited(&[empty.as_raw_fd()], &[]).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn inherited_map_is_bound_to_sealed_sha_length_and_complete_stream_without_live_ram() {
        use crate::restore::inputs::verified_ram_map;
        let directory =
            std::env::temp_dir().join(format!("silo-restore-map-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let launch = crate::krun::worker::restore::tests::launch(&directory);
        let map = verified_ram_map(&launch.request, &launch.files.objects[4]).unwrap();
        assert_eq!(
            map.id(),
            launch.request.evidence.memory.as_ref().unwrap().ram_stream
        );
        let mut wrong = launch.request.clone();
        wrong.evidence.memory.as_mut().unwrap().ram_stream =
            vm_spec::capture::Sha256Digest::of_bytes(b"different stream");
        assert!(verified_ram_map(&wrong, &launch.files.objects[4]).is_err());
        let mut wrong = launch.request.clone();
        wrong.objects[4].identity =
            vm_spec::capture::Sha256Digest::of_bytes(b"different full file");
        assert!(verified_ram_map(&wrong, &launch.files.objects[4]).is_err());
        let mut wrong = launch.request.clone();
        wrong.objects[4].length += 1;
        assert!(verified_ram_map(&wrong, &launch.files.objects[4]).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
