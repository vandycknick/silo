//! Lifecycle-owned root context and checked, internal-only storage shutdown.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use eyre::Context;
use nix::fcntl::{openat, OFlag};
use nix::mount::{mount, umount, MsFlags};
use nix::sys::stat::{major, minor, Mode};
use nix::sys::statvfs::{fstatvfs, FsFlags};
use nix::unistd::syncfs;
use rootfs_spec::{Observation, LOWER_MOUNT, MAX_JSON_BYTES, OBSERVATION_PATH, UPPER_MOUNT};

pub(crate) fn retained_root() -> eyre::Result<Option<Observation>> {
    let file = match open_observation() {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if root_is_overlay(&fs::read_to_string("/proc/self/mountinfo")?)? {
                eyre::bail!("overlay root is missing retained root observation");
            }
            return Ok(None);
        }
        Err(error) => return Err(error).context("open retained root observation"),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o777 != 0o600
    {
        eyre::bail!("retained root observation must be a root-owned mode 0600 regular file");
    }
    let mut bytes = Vec::new();
    file.take((MAX_JSON_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let observation = rootfs_spec::decode_observation(&bytes)
        .map_err(|error| eyre::eyre!("invalid retained root observation: {error}"))?;
    if !root_is_overlay(&fs::read_to_string("/proc/self/mountinfo")?)? {
        eyre::bail!("retained overlay observation does not describe current root");
    }
    for (path, expected) in [
        (LOWER_MOUNT, observation.lower_device),
        (UPPER_MOUNT, observation.upper_device),
    ] {
        let mounted = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY).bits())
            .open(path)?;
        let device = mounted.metadata()?.dev();
        if major(device) != u64::from(expected.major) || minor(device) != u64::from(expected.minor)
        {
            eyre::bail!("retained root device disagrees with maintenance mount {path}");
        }
    }
    Ok(Some(observation))
}

fn open_observation() -> io::Result<File> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW).bits())
        .open("/run")?;
    for component in ["silo", "rootfs"] {
        let fd = openat(
            &directory,
            component,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        directory = File::from(fd);
        let metadata = directory.metadata()?;
        if metadata.uid() != 0 || metadata.gid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "root observation parents must be root-only directories",
            ));
        }
    }
    let name = Path::new(OBSERVATION_PATH)
        .file_name()
        .ok_or_else(|| io::Error::other("invalid observation path"))?;
    Ok(File::from(openat(
        &directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?))
}

fn root_is_overlay(contents: &str) -> eyre::Result<bool> {
    for line in contents.lines() {
        let (mount, filesystem) = line
            .split_once(" - ")
            .ok_or_else(|| eyre::eyre!("malformed mountinfo"))?;
        if mount.split_whitespace().nth(4) == Some("/") {
            return Ok(filesystem.split_whitespace().next() == Some("overlay"));
        }
    }
    eyre::bail!("root mount is missing from mountinfo")
}

/// The first error is sticky even if every subsequent cleanup operation succeeds.
#[derive(Default)]
pub(crate) struct ShutdownResult {
    first_error: Option<eyre::Report>,
}

impl ShutdownResult {
    pub(crate) fn record(&mut self, result: eyre::Result<()>) {
        if let Err(error) = result {
            tracing::error!(error = ?error, "guest storage shutdown step failed");
            if self.first_error.is_none() {
                self.first_error = Some(error);
            }
        }
    }

    pub(crate) fn finish(self) -> eyre::Result<()> {
        match self.first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[derive(Debug)]
struct RetainedMount {
    mount_id: u64,
    path: PathBuf,
    file: File,
    root: bool,
}

#[derive(Debug)]
pub(crate) struct StorageShutdown {
    mounts: Vec<RetainedMount>,
    overlay: bool,
}

impl StorageShutdown {
    /// Retain writeback-error cursors before any agent mutation.
    pub(crate) fn capture() -> eyre::Result<Self> {
        let mut storage = Self {
            mounts: Vec::new(),
            overlay: retained_root()?.is_some(),
        };
        storage.register_current(false)?;
        Ok(storage)
    }

    /// Register newly mounted filesystems before admitting writes to them.
    /// Shutdown-only discovery cannot establish coverage of earlier writeback.
    /// Initially read-only mounts are retained too: remounting them later must
    /// not create an uncovered error interval or hide a late filesystem.
    pub(crate) fn register_current(&mut self, late: bool) -> eyre::Result<()> {
        let contents = fs::read_to_string("/proc/self/mountinfo")?;
        self.register_mountinfo(&contents, late)
    }

    fn register_mountinfo(&mut self, contents: &str, late: bool) -> eyre::Result<()> {
        let mut root_found = false;
        let mut upper_found = false;
        let mut added = 0;
        for line in contents.lines() {
            let (mount, filesystem) = line
                .split_once(" - ")
                .ok_or_else(|| eyre::eyre!("malformed mountinfo"))?;
            let mut fields = mount.split_whitespace();
            let mount_id = fields
                .next()
                .ok_or_else(|| eyre::eyre!("missing mountinfo identity"))?
                .parse::<u64>()?;
            let target = fields
                .nth(3)
                .ok_or_else(|| eyre::eyre!("missing mountinfo target"))?;
            let _flags = fields
                .next()
                .ok_or_else(|| eyre::eyre!("missing mountinfo flags"))?;
            let fstype = filesystem
                .split_whitespace()
                .next()
                .ok_or_else(|| eyre::eyre!("missing mountinfo filesystem"))?;
            if matches!(
                fstype,
                "proc"
                    | "sysfs"
                    | "devtmpfs"
                    | "devpts"
                    | "cgroup2"
                    | "mqueue"
                    | "securityfs"
                    | "debugfs"
                    | "tracefs"
                    | "configfs"
                    | "pstore"
                    | "binfmt_misc"
            ) {
                continue;
            }
            root_found |= target == "/";
            upper_found |= target == UPPER_MOUNT;
            if self.mounts.iter().any(|known| known.mount_id == mount_id) {
                continue;
            }
            let path = decode_mount_path(target)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
                .open(&path)
                .with_context(|| format!("retain filesystem mount {}", path.display()))?;
            require_mount_identity(&file, mount_id)?;
            self.mounts.push(RetainedMount {
                mount_id,
                root: target == "/",
                path,
                file,
            });
            added += 1;
        }
        if !root_found {
            eyre::bail!("root missing from shutdown mount plan");
        }
        if self.overlay && !upper_found {
            eyre::bail!("retained upper missing from shutdown mount plan");
        }
        self.mounts
            .sort_by_key(|mount| std::cmp::Reverse(mount.path.components().count()));
        if late && added != 0 {
            eyre::bail!("{added} filesystem mount(s) discovered only at shutdown; prior writeback-error coverage is incomplete");
        }
        Ok(())
    }

    /// Coverage is checked after workload termination and before unmounting.
    /// An absent writable device is not evidence it was never written.
    pub(crate) fn coverage(
        &self,
        manifest: &protocol::shutdown::StorageManifest,
    ) -> eyre::Result<()> {
        verify_mount_namespaces()?;
        let devices = discover_blocks(Path::new("/sys/block"))?;
        let mounts = fs::read_to_string("/proc/self/mountinfo")?;
        self.coverage_inventory(manifest, &devices, &mounts)
    }

    fn coverage_inventory(
        &self,
        manifest: &protocol::shutdown::StorageManifest,
        devices: &[DiscoveredBlock],
        mounts: &str,
    ) -> eyre::Result<()> {
        manifest.validate().map_err(eyre::Report::msg)?;
        if let Some(reason) = manifest.unsupported_reason() {
            eyre::bail!("{reason}");
        }
        let protocol::shutdown::StorageManifest::Complete { attachments } = manifest else {
            eyre::bail!("complete storage inventory unavailable");
        };
        let mut covered = std::collections::HashSet::new();
        for attachment in attachments {
            match attachment {
                protocol::shutdown::StorageAttachment::Block {
                    block_id,
                    geometry,
                    read_only,
                    ..
                } => {
                    let mut matching = devices
                        .iter()
                        .filter(|device| device.serial == block_id.as_str());
                    let device = matching.next().ok_or_else(|| {
                        eyre::eyre!(
                            "block {} is absent from the discovered inventory",
                            block_id.as_str()
                        )
                    })?;
                    if matching.next().is_some() {
                        eyre::bail!("block {} has duplicate serials", block_id.as_str());
                    }
                    if device.length != geometry.length
                        || device.sector_size != geometry.logical_sector_size
                        || device.read_only != *read_only
                    {
                        eyre::bail!(
                            "block {} differs from trusted launch geometry/access",
                            block_id.as_str()
                        );
                    }
                    covered.insert(device.number.as_str());
                    if !read_only
                        && !self.mounts.iter().any(|mount| {
                            mount.file.metadata().is_ok_and(|metadata| {
                                format!("{}:{}", major(metadata.dev()), minor(metadata.dev()))
                                    == device.number
                                    && mount_target(mounts, mount.mount_id)
                                        .is_ok_and(|target| target.is_some())
                            })
                        })
                    {
                        eyre::bail!(
                            "writable block {} is not covered by a retained filesystem",
                            block_id.as_str()
                        );
                    }
                }
                protocol::shutdown::StorageAttachment::Share { tag, read_only } => {
                    if !read_only {
                        eyre::bail!("writable virtiofs share {tag} has uncontrolled file/nested-mount writers");
                    }
                    if !mounts.lines().any(|line| {
                        line.split_once(" - ").is_some_and(|(_, filesystem)| {
                            let mut fields = filesystem.split_whitespace();
                            fields.next() == Some("virtiofs")
                                && fields.next() == Some(tag.as_str())
                                && fields
                                    .next()
                                    .is_some_and(|flags| flags.split(',').any(|flag| flag == "ro"))
                        })
                    }) {
                        eyre::bail!(
                            "read-only share {tag} is not represented by the mount inventory"
                        );
                    }
                }
            }
        }
        if devices
            .iter()
            .any(|device| !covered.contains(device.number.as_str()))
        {
            eyre::bail!("discovered block attachment is absent from trusted manifest");
        }
        for line in mounts.lines() {
            let (mount, filesystem) = line
                .split_once(" - ")
                .ok_or_else(|| eyre::eyre!("malformed mountinfo"))?;
            let mut fields = mount.split_whitespace();
            let number = fields
                .nth(2)
                .ok_or_else(|| eyre::eyre!("mount device missing"))?;
            let target = fields
                .nth(1)
                .ok_or_else(|| eyre::eyre!("mount target missing"))?;
            let flags = fields
                .next()
                .ok_or_else(|| eyre::eyre!("mount flags missing"))?;
            let fstype = filesystem
                .split_whitespace()
                .next()
                .ok_or_else(|| eyre::eyre!("mount filesystem missing"))?;
            if fstype == "virtiofs" {
                let source = filesystem
                    .split_whitespace()
                    .nth(1)
                    .ok_or_else(|| eyre::eyre!("virtiofs source missing"))?;
                if !attachments.iter().any(|attachment| {
                    matches!(attachment,
                    protocol::shutdown::StorageAttachment::Share { tag, .. } if tag == source)
                }) {
                    eyre::bail!("virtiofs mount {source} is absent from trusted manifest");
                }
            }
            if flags.split(',').any(|flag| flag == "rw") {
                match fstype {
                    "ext4" if covered.contains(number) => {}
                    "overlay" if self.overlay && target == "/" => {}
                    "tmpfs" | "ramfs" | "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup2"
                    | "mqueue" | "securityfs" | "debugfs" | "tracefs" | "configfs" | "pstore"
                    | "binfmt_misc" => {}
                    _ => eyre::bail!("unqualified writable filesystem/device {fstype} {number}"),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn shutdown(mut self, result: &mut ShutdownResult) {
        result.record(self.register_current(true));
        for mount in &self.mounts {
            tracing::info!(path = %mount.path.display(), "guest storage shutdown syncfs");
            result.record(
                syncfs(&mount.file).with_context(|| format!("syncfs {}", mount.path.display())),
            );
        }
        // Freeze the active overlay before touching the ext4 upper it references.
        if self.overlay {
            if let Some(root) = self.mounts.iter().find(|mount| mount.root) {
                remount_read_only(root, result);
            }
        }
        for mount in &self.mounts {
            if mount.root && self.overlay {
                continue;
            }
            let target = match checked_mount_target(mount) {
                Ok(Some(target)) => target,
                Ok(None) => continue,
                Err(error) => {
                    result.record(Err(error));
                    continue;
                }
            };
            match fstatvfs(&mount.file) {
                Ok(stat) if stat.flags().contains(FsFlags::ST_RDONLY) => {
                    tracing::info!(path = %target.display(), "guest storage shutdown verified read-only");
                    continue;
                }
                Ok(_) => {}
                Err(error) => {
                    result.record(Err(error).context("inspect retained mount access"));
                    continue;
                }
            }
            // An active root or retained FD can make unmount impossible. A checked
            // read-only remount is the alternative, never lazy detach.
            if mount.root {
                remount_read_only(mount, result);
                continue;
            }
            match umount(&target) {
                Ok(()) => {
                    tracing::info!(path = %mount.path.display(), "guest storage shutdown unmounted");
                    result.record((|| {
                        let contents = fs::read_to_string("/proc/self/mountinfo")?;
                        if mount_target(&contents, mount.mount_id)?.is_some() {
                            eyre::bail!(
                                "mount {} remains attached after unmount",
                                mount.path.display()
                            );
                        }
                        Ok(())
                    })());
                }
                Err(nix::errno::Errno::EBUSY) => remount_read_only(mount, result),
                Err(error) => {
                    result.record(
                        Err(error).with_context(|| format!("unmount {}", mount.path.display())),
                    );
                    remount_read_only(mount, result);
                }
            }
        }
        for mount in &self.mounts {
            tracing::info!(path = %mount.path.display(), "guest storage shutdown final syncfs");
            result.record(
                syncfs(&mount.file)
                    .with_context(|| format!("final syncfs {}", mount.path.display())),
            );
        }
    }
}

#[derive(Debug)]
struct DiscoveredBlock {
    serial: String,
    number: String,
    length: u64,
    sector_size: u32,
    read_only: bool,
}

fn discover_blocks(root: &Path) -> eyre::Result<Vec<DiscoveredBlock>> {
    let mut devices = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let serial = match fs::read_to_string(path.join("serial")) {
            Ok(serial) => serial.strip_suffix('\n').unwrap_or(&serial).to_owned(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("read block serial"),
        };
        if devices.len() == 16 {
            eyre::bail!("discovered block inventory exceeds the sixteen-attachment contract");
        }
        let number = fs::read_to_string(path.join("dev"))?.trim().to_owned();
        let sectors = fs::read_to_string(path.join("size"))?
            .trim()
            .parse::<u64>()?;
        let length = sectors
            .checked_mul(512)
            .ok_or_else(|| eyre::eyre!("block size overflow"))?;
        let sector_size = fs::read_to_string(path.join("queue/logical_block_size"))?
            .trim()
            .parse::<u32>()?;
        let read_only = match fs::read_to_string(path.join("ro"))?.trim() {
            "0" => false,
            "1" => true,
            _ => eyre::bail!("invalid block access mode"),
        };
        devices.push(DiscoveredBlock {
            serial,
            number,
            length,
            sector_size,
            read_only,
        });
    }
    Ok(devices)
}

/// Namespace and raw-device writers cannot be hidden behind the root syncfs.
pub(crate) fn verify_mount_namespaces() -> eyre::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let own = fs::metadata("/proc/self/ns/mnt")?;
    for process in fs::read_dir("/proc")? {
        let process = process?;
        if !process
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let tasks = match fs::read_dir(process.path().join("task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inventory workload namespaces"),
        };
        for task in tasks {
            let task = task?;
            verify_task_mount_namespace(&task.path(), &own)?;
        }
        let descriptors = match fs::read_dir(process.path().join("fd")) {
            Ok(descriptors) => descriptors,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inventory raw-device writers"),
        };
        for descriptor in descriptors {
            match fs::metadata(descriptor?.path()) {
                Ok(metadata) if metadata.file_type().is_block_device() => eyre::bail!(
                    "raw block-device workload access is not a qualified filesystem writer"
                ),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect raw-device writer"),
            }
        }
    }
    Ok(())
}

fn verify_task_mount_namespace(task: &Path, own: &fs::Metadata) -> eyre::Result<()> {
    let stat = match fs::read_to_string(task.join("stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect namespace owner task flags"),
    };
    // PF_KTHREAD is kernel-supplied provenance, unlike a PID or process name.
    // Kernel workers may retain the boot namespace; their filesystem writeback
    // is drained by syncfs, not by treating them as userspace workload owners.
    if crate::pid1::is_kernel_task(&stat)? {
        return Ok(());
    }
    let namespace = match fs::metadata(task.join("ns/mnt")) {
        Ok(namespace) => namespace,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect workload mount namespace"),
    };
    if namespace.dev() != own.dev() || namespace.ino() != own.ino() {
        eyre::bail!(
            "unknown workload mount namespace: task {} has {}:{}, expected {}:{}",
            task.display(),
            namespace.dev(),
            namespace.ino(),
            own.dev(),
            own.ino()
        );
    }
    Ok(())
}

fn remount_read_only(mountpoint: &RetainedMount, result: &mut ShutdownResult) {
    let target = match checked_mount_target(mountpoint) {
        Ok(Some(target)) => target,
        Ok(None) => return,
        Err(error) => {
            result.record(Err(error));
            return;
        }
    };
    tracing::info!(path = %target.display(), "guest storage shutdown remount read-only");
    result.record(
        mount::<str, Path, str, str>(
            None,
            &target,
            None,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None,
        )
        .with_context(|| format!("remount read-only {}", target.display())),
    );
    result.record((|| {
        if !fstatvfs(&mountpoint.file)?.flags().contains(FsFlags::ST_RDONLY) {
            eyre::bail!("mount remains writable: {}", mountpoint.path.display());
        }
        tracing::info!(path = %mountpoint.path.display(), "guest storage shutdown verified read-only");
        Ok(())
    })());
}

fn mount_target(contents: &str, mount_id: u64) -> eyre::Result<Option<PathBuf>> {
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let id = fields
            .next()
            .ok_or_else(|| eyre::eyre!("malformed mountinfo"))?
            .parse::<u64>()?;
        if id == mount_id {
            return Ok(Some(decode_mount_path(
                fields
                    .nth(3)
                    .ok_or_else(|| eyre::eyre!("mount target missing"))?,
            )?));
        }
    }
    Ok(None)
}

fn checked_mount_target(mountpoint: &RetainedMount) -> eyre::Result<Option<PathBuf>> {
    require_mount_identity(&mountpoint.file, mountpoint.mount_id)?;
    let Some(target) = mount_target(
        &fs::read_to_string("/proc/self/mountinfo")?,
        mountpoint.mount_id,
    )?
    else {
        return Ok(None);
    };
    let current = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(&target)?;
    require_mount_identity(&current, mountpoint.mount_id)?;
    Ok(Some(target))
}

fn require_mount_identity(file: &File, expected: u64) -> eyre::Result<()> {
    let contents = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    let actual = parse_fd_mount_id(&contents)?;
    if actual != expected {
        eyre::bail!("mount target identity changed: expected {expected}, observed {actual}");
    }
    Ok(())
}

fn parse_fd_mount_id(contents: &str) -> eyre::Result<u64> {
    let mut result = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("mnt_id:") {
            if result.is_some() {
                eyre::bail!("duplicate fdinfo mount identity");
            }
            result = Some(value.trim().parse::<u64>()?);
        }
    }
    result.ok_or_else(|| eyre::eyre!("fdinfo mount identity missing"))
}

pub(crate) fn decode_mount_path(value: &str) -> eyre::Result<PathBuf> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        if byte == b'\\' {
            let digits = [input.next(), input.next(), input.next()];
            let decoded = match digits {
                [Some(b'0'), Some(b'4'), Some(b'0')] => b' ',
                [Some(b'0'), Some(b'1'), Some(b'1')] => b'\t',
                [Some(b'0'), Some(b'1'), Some(b'2')] => b'\n',
                [Some(b'1'), Some(b'3'), Some(b'4')] => b'\\',
                _ => eyre::bail!("invalid mountinfo path escape"),
            };
            bytes.push(decoded);
        } else {
            bytes.push(byte);
        }
    }
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(test)]
mod tests {
    use crate::root_storage::{decode_mount_path, root_is_overlay, ShutdownResult};

    #[test]
    fn namespace_inventory_uses_kernel_task_flags_not_pid_or_name() {
        let root = tempfile::tempdir().unwrap();
        let task = root.path().join("2");
        std::fs::create_dir_all(task.join("ns")).unwrap();
        let own = std::fs::metadata("/proc/self/ns/mnt").unwrap();
        // An actual distinct inode stands in for the proc inventory entry;
        // these unit tests exercise provenance and identity selection only.
        std::fs::write(task.join("ns/mnt"), []).unwrap();
        std::fs::write(task.join("stat"), "2 (ordinary sh) S 0 0 0 0 -1 2130240").unwrap();
        crate::root_storage::verify_task_mount_namespace(&task, &own).unwrap();
        // A userspace owner cannot obtain the exemption by using PID 2 or a
        // kernel-looking comm; a different mount namespace stays noncertifying.
        std::fs::write(task.join("stat"), "2 (kthreadd) S 0 0 0 0 -1 4194304").unwrap();
        assert!(crate::root_storage::verify_task_mount_namespace(&task, &own).is_err());
        std::fs::remove_file(task.join("ns/mnt")).unwrap();
        std::os::unix::fs::symlink("/proc/self/ns/mnt", task.join("ns/mnt")).unwrap();
        crate::root_storage::verify_task_mount_namespace(&task, &own).unwrap();
    }

    #[test]
    fn namespace_inventory_fails_closed_on_malformed_owner_and_handles_task_exit() {
        let root = tempfile::tempdir().unwrap();
        let own = std::fs::metadata("/proc/self/ns/mnt").unwrap();
        std::fs::write(root.path().join("stat"), "invalid task flags").unwrap();
        assert!(crate::root_storage::verify_task_mount_namespace(root.path(), &own).is_err());
        std::fs::remove_file(root.path().join("stat")).unwrap();
        crate::root_storage::verify_task_mount_namespace(root.path(), &own).unwrap();
    }

    fn coverage_fixture() -> (
        crate::root_storage::StorageShutdown,
        protocol::shutdown::StorageManifest,
        Vec<crate::root_storage::DiscoveredBlock>,
        String,
    ) {
        use std::os::unix::fs::MetadataExt;
        let file = std::fs::File::open("/").unwrap();
        let metadata = file.metadata().unwrap();
        let number = format!(
            "{}:{}",
            nix::sys::stat::major(metadata.dev()),
            nix::sys::stat::minor(metadata.dev())
        );
        let storage = crate::root_storage::StorageShutdown {
            mounts: vec![crate::root_storage::RetainedMount {
                mount_id: 42,
                path: "/".into(),
                file,
                root: true,
            }],
            overlay: false,
        };
        let manifest = protocol::shutdown::manifest_from_json(br#"{"kind":"complete","attachments":[{"kind":"block","blockId":"root","role":"root","format":"raw","geometry":{"length":67108864,"logicalSectorSize":512},"readOnly":false,"exclusiveWriter":true}]}"#).unwrap();
        let mounts = format!("42 1 {number} / / rw - ext4 /dev/root rw\n");
        let blocks = vec![crate::root_storage::DiscoveredBlock {
            serial: "root".into(),
            number,
            length: 67108864,
            sector_size: 512,
            read_only: false,
        }];
        (storage, manifest, blocks, mounts)
    }

    #[test]
    fn coverage_requires_every_manifest_block_and_rejects_unmounted_writable_data() {
        let (storage, mut manifest, mut blocks, mounts) = coverage_fixture();
        storage
            .coverage_inventory(&manifest, &blocks, &mounts)
            .unwrap();
        let protocol::shutdown::StorageManifest::Complete { attachments } = &mut manifest else {
            panic!("complete");
        };
        attachments.push(serde_json::from_str(r#"{"kind":"block","blockId":"data","role":"data","format":"raw","geometry":{"length":67108864,"logicalSectorSize":512},"readOnly":false,"exclusiveWriter":true}"#).unwrap());
        assert!(storage
            .coverage_inventory(&manifest, &blocks, &mounts)
            .unwrap_err()
            .to_string()
            .contains("absent"));
        blocks.push(crate::root_storage::DiscoveredBlock {
            serial: "data".into(),
            number: "252:99".into(),
            length: 67108864,
            sector_size: 512,
            read_only: false,
        });
        assert!(storage
            .coverage_inventory(&manifest, &blocks, &mounts)
            .unwrap_err()
            .to_string()
            .contains("retained filesystem"));
        // A retained error cursor alone does not cover a now-unmounted device.
        assert!(storage.coverage_inventory(&manifest, &blocks, "").is_err());
    }

    #[test]
    fn coverage_rejects_duplicate_serial_geometry_change_and_unlisted_devices() {
        let (storage, manifest, mut blocks, mounts) = coverage_fixture();
        blocks[0].length += 512;
        assert!(storage
            .coverage_inventory(&manifest, &blocks, &mounts)
            .is_err());
        blocks[0].length -= 512;
        blocks.push(crate::root_storage::DiscoveredBlock {
            serial: "root".into(),
            number: "252:99".into(),
            length: 67108864,
            sector_size: 512,
            read_only: false,
        });
        assert!(storage
            .coverage_inventory(&manifest, &blocks, &mounts)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
        blocks[1].serial = "unlisted".into();
        assert!(storage
            .coverage_inventory(&manifest, &blocks, &mounts)
            .unwrap_err()
            .to_string()
            .contains("absent from trusted manifest"));
    }

    #[test]
    fn share_and_external_writer_exclusions_cover_the_whole_generation() {
        let (storage, mut manifest, blocks, mounts) = coverage_fixture();
        let protocol::shutdown::StorageManifest::Complete { attachments } = &mut manifest else {
            panic!("complete");
        };
        attachments.push(protocol::shutdown::StorageAttachment::Share {
            tag: "share".into(),
            read_only: true,
        });
        assert!(storage
            .coverage_inventory(&manifest, &blocks, &mounts)
            .is_err());
        let mounted = format!("{mounts}43 1 0:55 / /share ro - virtiofs share ro\n");
        storage
            .coverage_inventory(&manifest, &blocks, &mounted)
            .unwrap();
        let protocol::shutdown::StorageManifest::Complete { attachments } = &mut manifest else {
            panic!("complete");
        };
        attachments[1] = protocol::shutdown::StorageAttachment::Share {
            tag: "share".into(),
            read_only: false,
        };
        assert!(storage
            .coverage_inventory(&manifest, &blocks, &mounted)
            .unwrap_err()
            .to_string()
            .contains("directory shares"));
        let protocol::shutdown::StorageManifest::Complete { attachments } = &mut manifest else {
            panic!("complete");
        };
        attachments.pop();
        let protocol::shutdown::StorageAttachment::Block {
            exclusive_writer, ..
        } = &mut attachments[0]
        else {
            panic!("block");
        };
        *exclusive_writer = false;
        assert!(storage
            .coverage_inventory(&manifest, &blocks, &mounts)
            .unwrap_err()
            .to_string()
            .contains("external/concurrent"));
    }

    #[test]
    fn block_inventory_reads_serial_and_geometry_not_positional_device_names() {
        let root = tempfile::tempdir().unwrap();
        let device = root.path().join("not-vda");
        std::fs::create_dir_all(device.join("queue")).unwrap();
        for (name, value) in [
            ("serial", "disk-identity\n"),
            ("dev", "252:17\n"),
            ("size", "131072\n"),
            ("queue/logical_block_size", "512\n"),
            ("ro", "0\n"),
        ] {
            std::fs::write(device.join(name), value).unwrap();
        }
        let blocks = crate::root_storage::discover_blocks(root.path()).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].serial, "disk-identity");
        assert_eq!(blocks[0].length, 67108864);
        assert_eq!(blocks[0].number, "252:17");
        std::fs::write(device.join("size"), "18446744073709551615\n").unwrap();
        assert!(crate::root_storage::discover_blocks(root.path()).is_err());
        std::fs::write(device.join("size"), "131072\n").unwrap();
        for index in 0..16 {
            let extra = root.path().join(format!("extra-{index}"));
            std::fs::create_dir_all(extra.join("queue")).unwrap();
            for name in ["serial", "dev", "size", "queue/logical_block_size", "ro"] {
                std::fs::copy(device.join(name), extra.join(name)).unwrap();
            }
        }
        assert!(crate::root_storage::discover_blocks(root.path())
            .unwrap_err()
            .to_string()
            .contains("sixteen-attachment"));
    }

    #[test]
    fn mount_target_tracks_identity_after_move_and_replacement() {
        let contents = "40 1 8:1 / /moved\\040upper rw - ext4 /dev/vdb rw\n41 1 0:22 / /old-upper rw - tmpfs tmpfs rw\n";
        assert_eq!(
            crate::root_storage::mount_target(contents, 40).unwrap(),
            Some(std::path::PathBuf::from("/moved upper"))
        );
        assert_eq!(
            crate::root_storage::mount_target(contents, 41).unwrap(),
            Some(std::path::PathBuf::from("/old-upper"))
        );
        assert!(crate::root_storage::mount_target(contents, 42)
            .unwrap()
            .is_none());
    }

    #[test]
    fn cleanup_resolves_retained_fd_identity_instead_of_saved_path() {
        use std::os::fd::AsRawFd;
        let fixture = tempfile::tempdir().unwrap();
        let file = std::fs::File::open(fixture.path()).unwrap();
        let contents =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).unwrap();
        let mount_id = crate::root_storage::parse_fd_mount_id(&contents).unwrap();
        crate::root_storage::require_mount_identity(&file, mount_id).unwrap();
        assert!(
            crate::root_storage::require_mount_identity(&file, mount_id.wrapping_add(1)).is_err()
        );
        let mount = crate::root_storage::RetainedMount {
            mount_id,
            path: std::path::PathBuf::from("/not-the-current-mount-target"),
            file,
            root: false,
        };
        let actual = crate::root_storage::checked_mount_target(&mount)
            .unwrap()
            .unwrap();
        assert_ne!(actual, mount.path);
    }

    #[test]
    fn late_mount_discovery_refuses_prior_writeback_coverage() {
        let mut storage = crate::root_storage::StorageShutdown {
            mounts: Vec::new(),
            overlay: false,
        };
        use std::os::fd::AsRawFd;
        let root = std::fs::File::open("/").unwrap();
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", root.as_raw_fd())).unwrap();
        let root_id = crate::root_storage::parse_fd_mount_id(&info).unwrap();
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        // Use the actual root record and actual open operation, without depending
        // on access to unrelated host mounts in the unit-test runner's namespace.
        let root_record = mounts
            .lines()
            .find(|line| {
                line.split_whitespace()
                    .next()
                    .and_then(|id| id.parse::<u64>().ok())
                    == Some(root_id)
            })
            .unwrap();
        let error = storage.register_mountinfo(root_record, true).unwrap_err();
        assert!(error
            .to_string()
            .contains("prior writeback-error coverage is incomplete"));
        assert!(storage.mounts.iter().any(|mount| mount.root));
    }

    #[test]
    fn fdinfo_requires_one_valid_mount_identity() {
        assert_eq!(
            crate::root_storage::parse_fd_mount_id("pos:\t0\nmnt_id:\t42\n").unwrap(),
            42
        );
        for input in ["pos: 0\n", "mnt_id: invalid\n", "mnt_id: 1\nmnt_id: 2\n"] {
            assert!(crate::root_storage::parse_fd_mount_id(input).is_err());
        }
    }

    #[test]
    fn shutdown_first_failure_survives_success_and_later_failure() {
        let mut result = ShutdownResult::default();
        result.record(Err(eyre::eyre!("first syncfs EIO")));
        result.record(Ok(()));
        result.record(Err(eyre::eyre!("later remount EBUSY")));
        assert_eq!(result.finish().unwrap_err().to_string(), "first syncfs EIO");
    }

    #[test]
    fn shutdown_success_requires_no_recorded_failure() {
        let mut result = ShutdownResult::default();
        result.record(Ok(()));
        assert!(result.finish().is_ok());
    }

    #[test]
    fn mountinfo_path_decoding_is_byte_preserving_and_strict() {
        assert_eq!(
            decode_mount_path("/with\\040space\\134name").unwrap(),
            std::path::PathBuf::from("/with space\\name")
        );
        assert!(decode_mount_path("/bad\\000").is_err());
        assert!(decode_mount_path("/bad\\04").is_err());
    }

    #[test]
    fn root_mount_kind_is_not_inferred_from_device_position() {
        assert!(root_is_overlay("42 1 0:12 / / rw - overlay overlay rw\n").unwrap());
        assert!(!root_is_overlay("42 1 252:0 / / rw - ext4 /dev/vda rw\n").unwrap());
        assert!(root_is_overlay("malformed").is_err());
    }
}
