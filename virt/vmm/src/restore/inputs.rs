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
        (4..=MAX_RESTORE_FDS).contains(&fds.len()),
        "restore descriptor list must name 4..={MAX_RESTORE_FDS} descriptors"
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
    pub(crate) objects: Vec<File>,
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
    request.validate().map_err(invalid)?;
    let expected = request.objects.len()
        + request
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
    let objects = (0..request.objects.len())
        .map(|_| take())
        .collect::<io::Result<Vec<_>>>()?;
    for (file, object) in objects.iter().zip(&request.objects) {
        validate_object(file, object)?;
    }
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

pub(crate) fn fingerprint(file: &File) -> io::Result<vm_spec::capture::SourceFingerprint> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("owned cut member is not a regular file"));
    }
    Ok(vm_spec::capture::SourceFingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

pub(crate) fn validate_object(
    file: &File,
    object: &vm_spec::restore::RestoreObject,
) -> io::Result<()> {
    use std::os::fd::AsFd;
    let facts = readonly_regular(file.as_fd())?;
    if facts != (object.file_device, object.file_inode, object.length) {
        return Err(invalid("restore object differs from its held descriptor"));
    }
    if let vm_spec::restore::RestoreObjectAuthority::Owned {
        fingerprint: expected,
    } = &object.authority
    {
        expected.validate().map_err(invalid)?;
        #[cfg(target_os = "linux")]
        reject_surviving_writer(file)?;
        if fingerprint(file)? != *expected {
            return Err(invalid("owned restore object fingerprint changed"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn reject_surviving_writer(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // nix exposes no F_SETLEASE command. A read lease refuses existing writers;
    // release immediately, before handing the held descriptor to native code.
    if unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_SETLEASE, nix::libc::F_RDLCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_SETLEASE, nix::libc::F_UNLCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Decode the immutable inherited binary root and authenticate its exact bytes
/// and role/profile against the seal, without scanning RAM or node descendants.
pub(crate) fn verified_ram_map(
    request: &RestoreRequest,
    file: &File,
) -> io::Result<vm_spec::stream_map::StreamRoot> {
    use std::os::unix::fs::FileExt as _;
    let vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { evidence, .. } =
        &request.authority
    else {
        return Err(invalid("owned cut cannot authorize an identified RAM map"));
    };
    let object = request
        .objects
        .iter()
        .find(|object| object.role == vm_spec::restore::RestoreObjectRole::RamMap)
        .ok_or_else(|| invalid("restore lacks its complete RAM map"))?;
    if object.length > vm_spec::stream_map::MAX_ROOT_BYTES as u64
        || file.metadata()?.len() != object.length
    {
        return Err(invalid(
            "restore RAM map exceeds its bound or changed length",
        ));
    }
    let mut bytes = vec![0; object.length as usize];
    file.read_exact_at(&mut bytes, 0)?;
    let vm_spec::restore::RestoreObjectAuthority::Identified { identity } = &object.authority
    else {
        return Err(invalid("RAM map lacks identified authority"));
    };
    if vm_spec::capture::Sha256Digest::of_bytes(&bytes) != *identity {
        return Err(invalid("restore RAM map differs from its sealed SHA"));
    }
    let map = vm_spec::stream_map::StreamRoot::decode(&bytes).map_err(io::Error::other)?;
    map.validate_role(vm_spec::stream_map::StreamRole::Ram)
        .map_err(io::Error::other)?;
    let memory = evidence
        .memory
        .as_ref()
        .ok_or_else(|| invalid("restore lacks RAM evidence"))?;
    if map.length() != memory.packed_length
        || map.id() != memory.ram_stream
        || map.chunk_size().bytes() != u64::from(memory.identity_chunk_bytes)
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
        assert_eq!(
            parse_env(Some("[10,11,12,13]".as_ref())).unwrap(),
            vec![10, 11, 12, 13]
        );
        for refused in ["[10,11,12]", "not json", "{\"fd\":1}"] {
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
            crate::krun::worker::restore::tests::evidence(&launch.request.authority)
                .memory
                .as_ref()
                .unwrap()
                .ram_stream
        );
        let mut wrong = launch.request.clone();
        crate::krun::worker::restore::tests::evidence_mut(&mut wrong.authority)
            .memory
            .as_mut()
            .unwrap()
            .ram_stream = vm_spec::capture::Sha256Digest::of_bytes(b"different stream");
        assert!(verified_ram_map(&wrong, &launch.files.objects[4]).is_err());
        let mut wrong = launch.request.clone();
        wrong.objects[4].authority = vm_spec::restore::RestoreObjectAuthority::Identified {
            identity: vm_spec::capture::Sha256Digest::of_bytes(b"different full file"),
        };
        assert!(verified_ram_map(&wrong, &launch.files.objects[4]).is_err());
        let mut wrong = launch.request.clone();
        wrong.objects[4].length += 1;
        assert!(verified_ram_map(&wrong, &launch.files.objects[4]).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn owned_restore_rechecks_real_files_and_never_downgrades_authority() {
        use crate::restore::inputs::validate_object;
        let directory =
            std::env::temp_dir().join(format!("silo-owned-restore-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let launch = crate::krun::worker::restore::tests::owned_launch(&directory);
        assert_eq!(launch.request.objects.len(), 4);
        assert!(launch.request.map_node_store.is_none());
        for (file, object) in launch.files.objects.iter().zip(&launch.request.objects) {
            validate_object(file, object).unwrap();
        }
        assert!(crate::restore::inputs::verified_ram_map(
            &launch.request,
            &launch.files.objects[0]
        )
        .is_err());
        let mut mixed = launch.request.clone();
        mixed.objects[0].authority = vm_spec::restore::RestoreObjectAuthority::Identified {
            identity: vm_spec::capture::Sha256Digest::of_bytes(b"not owned authority"),
        };
        assert!(mixed.validate().is_err());
        let mut identified = crate::krun::worker::restore::tests::request();
        identified.objects[0].authority = launch.request.objects[0].authority.clone();
        assert!(identified.validate().is_err());
        use std::os::unix::fs::PermissionsExt;
        let mut object = launch.request.objects[2].clone();
        let path = directory.join("restore-object-2");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        object.authority = vm_spec::restore::RestoreObjectAuthority::Owned {
            fingerprint: crate::restore::inputs::fingerprint(&launch.files.objects[2]).unwrap(),
        };
        #[cfg(target_os = "linux")]
        assert!(
            validate_object(&launch.files.objects[2], &object).is_err(),
            "a surviving writer must refuse local admission"
        );
        use std::os::unix::fs::FileExt;
        writer.write_all_at(b"same!", 0).unwrap();
        drop(writer);
        assert!(
            validate_object(&launch.files.objects[2], &object).is_err(),
            "same-length edits invalidate exact fingerprints"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"x").unwrap();
        assert!(
            validate_object(&launch.files.objects[2], &object).is_err(),
            "truncation invalidates the expected length"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"state").unwrap();
        let replacement = std::fs::File::open(&path).unwrap();
        assert!(
            validate_object(&replacement, &object).is_err(),
            "replacement inode is not admitted"
        );
        drop((replacement, launch));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
