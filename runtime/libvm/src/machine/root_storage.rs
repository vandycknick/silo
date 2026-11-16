use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

use vm_spec::{BlockId, Disk, DiskFormat, DiskGeometry, DiskRole};

use crate::storage::pool::StoragePool;
use crate::store::composition_store::LaunchLower;
use crate::{LibVmError, MachineRoot, MachineStorageRecord, TemporaryDirectoryPolicy};

/// Value of the single builder-emitted `silo.rootfs=` kernel argument.
pub(crate) const ROOT_MARKER_VALUE: &str = "linux-erofs-overlay-v1";
/// The exact whole kernel argument selecting the layered overlay root.
pub(crate) const ROOT_MARKER: &str = "silo.rootfs=linux-erofs-overlay-v1";

pub(crate) struct PreparedRoot {
    pub(crate) disks: Vec<Disk>,
    pub(crate) bootstrap: Vec<u8>,
    pub(crate) descriptor: Option<String>,
    pub(crate) qualification: Option<crate::OwnedOverlayBoot>,
    pub(crate) storage: MachineStorageRecord,
    pub(crate) rosetta: rootfs_spec::RosettaMode,
    /// Resolved lower protected by the caller's launch-generation lease until
    /// the monitor has opened its verified backings.
    pub(crate) _lower: Option<LaunchLower>,
}

pub(crate) fn invalid(message: impl Into<String>) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "machine-storage",
        message: message.into(),
    }
}

pub(crate) fn disk(
    path: impl Into<std::path::PathBuf>,
    role: DiskRole,
    length: u64,
    serial: String,
) -> Result<Disk, LibVmError> {
    Ok(Disk {
        path: path.into(),
        role,
        format: if role == DiskRole::RootLower {
            DiskFormat::Vmdk
        } else {
            DiskFormat::Raw
        },
        geometry: DiskGeometry {
            length,
            logical_sector_size: 512,
        },
        block_id: BlockId::new(serial).map_err(invalid)?,
        read_only: role == DiskRole::RootLower,
    })
}

pub(crate) fn validate_spec(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
) -> Result<(), LibVmError> {
    let args = spec
        .boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
        .map(|kernel| kernel.cmdline.as_slice())
        .unwrap_or_default();
    let overlay = matches!(&storage.root, MachineRoot::LinuxOverlay { .. });
    validate_root_arguments(args, overlay)?;
    let MachineRoot::LinuxOverlay {
        lower,
        upper,
        capacity,
        ..
    } = &storage.root
    else {
        return Ok(());
    };
    let geometry = lower.geometry();
    spec.validate()
        .map_err(|error| invalid(error.to_string()))?;
    let disks = spec
        .storage
        .as_ref()
        .ok_or_else(|| invalid("overlay specification has no roots"))?;
    let expected = [
        disk(
            "lower.vmdk",
            DiskRole::RootLower,
            geometry.length,
            "silo-root-lower".into(),
        )?,
        disk(
            upper.as_path(),
            DiskRole::RootUpper,
            *capacity,
            "silo-root-upper".into(),
        )?,
    ];
    if disks.disks.get(..2) != Some(expected.as_slice()) {
        return Err(invalid(
            "overlay launch roots differ from retained semantic identities",
        ));
    }
    let args = spec
        .boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
        .map(|kernel| &kernel.cmdline)
        .ok_or_else(|| invalid("overlay requires direct kernel boot"))?;
    // The token checks above already refused selectors and conflicting
    // markers; the builder-emitted marker must also be a whole argument.
    if !args.iter().any(|arg| arg.as_str() == ROOT_MARKER) {
        return Err(invalid(
            "overlay requires its exact root marker as a whole kernel argument",
        ));
    }
    Ok(())
}

/// Root discovery is exclusively owned by the mandatory bootstrap and the first
/// executable by the trusted `/init`. Both backends join the arguments with a
/// space, so the joined line is read with the kernel's own tokenizer: quoting
/// or kernel-only whitespace (VT, NBSP) cannot carry `root=`, `rootfstype=`,
/// `rootflags=` or `rdinit=` past admission. `init=` stays the image handoff
/// input. Only the overlay consistency marker is permitted.
pub(crate) fn validate_root_arguments(args: &[String], overlay: bool) -> Result<(), LibVmError> {
    let invalid_arguments = |reason: &str| LibVmError::InvalidKernelArguments {
        reason: reason.to_owned(),
    };
    // The kernel command line is a C string; a NUL would silently cut it.
    if args.iter().any(|arg| arg.contains('\0')) {
        return Err(invalid_arguments(
            "kernel arguments cannot contain NUL bytes",
        ));
    }
    let cmdline = args.join(" ");
    let mut markers = 0;
    for param in rootfs_spec::kernel_cmdline::params(cmdline.as_bytes()) {
        match param.reserved() {
            Some(rootfs_spec::kernel_cmdline::Reserved::RootSelection) => {
                return Err(invalid_arguments(
                    "root-selection kernel arguments are reserved for the trusted bootstrap",
                ));
            }
            Some(rootfs_spec::kernel_cmdline::Reserved::InitialExecutable) => {
                return Err(invalid_arguments(
                    "rdinit= is reserved; the trusted /init is the initial executable",
                ));
            }
            None => {}
        }
        let Some(value) = param.value else {
            continue;
        };
        if param.is(b"silo.rootfs") {
            if !overlay || value != ROOT_MARKER_VALUE.as_bytes() {
                return Err(invalid_arguments(
                    "root profile marker conflicts with the persisted root",
                ));
            }
            markers += 1;
        }
    }
    if overlay && markers != 1 {
        return Err(invalid_arguments(
            "overlay requires exactly one root profile marker",
        ));
    }
    Ok(())
}

pub(crate) fn allows_rootfs_resize(storage: &MachineStorageRecord) -> bool {
    matches!(
        &storage.boot,
        crate::BootProfile::LinuxDirect {
            root_selector: crate::RootSelector::WholeDisk | crate::RootSelector::ManagedOverlay,
            ..
        }
    )
}

/// A layered lower is admissible only for the userspace its boot profile
/// names: the composition recipe platform is the image's exact OCI platform.
pub(crate) fn check_lower_platform(
    recipe: &oci::Platform,
    boot: &crate::BootProfile,
) -> Result<(), LibVmError> {
    let crate::BootProfile::LinuxDirect {
        userspace_platform, ..
    } = boot
    else {
        return Err(invalid(
            "layered lower requires a Linux direct boot profile",
        ));
    };
    if crate::LinuxPlatform::from_oci(recipe)? != *userspace_platform {
        return Err(invalid(
            "layered lower recipe platform differs from the boot userspace platform",
        ));
    }
    Ok(())
}

/// Geometry, UUID and profile admission of a private upper. The dirty
/// journal (`EXT4_FEATURE_INCOMPAT_RECOVER`) is deliberately permitted: exact
/// captures and forks never replay, repair or clear it. Consumers requiring a
/// clean filesystem (flattening export) must check that separately.
pub(crate) fn validate_upper_file(
    file: &File,
    upper_uuid: uuid::Uuid,
    capacity: u64,
) -> Result<(), LibVmError> {
    let mut bytes = [0u8; 1024];
    file.read_exact_at(&mut bytes, 1024)?;
    let word = |offset: usize| {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    let profile = rootfs_spec::upper_geometry::FEATURE_INCOMPAT;
    if bytes[56..58] != [0x53, 0xef]
        || &bytes[104..120] != upper_uuid.as_bytes()
        || word(24) != 2
        || word(96) & !4 != profile
        || word(92) & !rootfs_spec::upper_geometry::FEATURE_COMPAT != 0
        || word(100) & !rootfs_spec::upper_geometry::FEATURE_RO_COMPAT != 0
        || u64::from(word(4)) * 4096 > capacity
        || word(4) == 0
        || word(336) != 0
    {
        return Err(invalid(
            "upper metadata does not match its admitted profile and UUID",
        ));
    }
    Ok(())
}

pub(crate) fn validate_private(path: &Path, length: u64) -> Result<(), LibVmError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != length
    {
        return Err(invalid(format!(
            "private root {} has incorrect type, owner, mode, links or length",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn prepare(
    storage: &MachineStorageRecord,
    machine_dir: &Path,
    images_dir: &Path,
    lower: Option<LaunchLower>,
    data_disks: u64,
    qualification: Option<crate::OwnedOverlayBoot>,
    rosetta: rootfs_spec::RosettaMode,
) -> Result<PreparedRoot, LibVmError> {
    storage.validate()?;
    let mut descriptor = None;
    let (disks, root) = match &storage.root {
        MachineRoot::OpaqueRaw { path, geometry, .. } => {
            let actual = std::fs::symlink_metadata(machine_dir.join(path.as_path()))?;
            if !actual.is_file() {
                return Err(invalid("private raw root is not a regular file"));
            }
            crate::storage::limits::validate_disk_length(actual.len())
                .map_err(crate::storage::StorageError::from)?;
            (
                vec![disk(
                    path.as_path(),
                    DiskRole::Root,
                    actual.len().max(geometry.length),
                    "silo-root".into(),
                )?],
                {
                    let crate::BootProfile::LinuxDirect {
                        root_selector,
                        root_filesystem,
                        ..
                    } = &storage.boot
                    else {
                        return Err(invalid("opaque raw requires Linux direct boot"));
                    };
                    let selector = match root_selector {
                        crate::RootSelector::WholeDisk => rootfs_spec::RawSelector::WholeDisk,
                        crate::RootSelector::GptPartition { guid } => {
                            rootfs_spec::RawSelector::GptPartition {
                                guid: rootfs_spec::PartitionGuid::new(*guid.as_bytes())
                                    .map_err(|error| invalid(error.to_string()))?,
                            }
                        }
                        crate::RootSelector::MbrPartition { number } => {
                            rootfs_spec::RawSelector::MbrPartition {
                                number: rootfs_spec::MbrPartitionNumber::new(*number)
                                    .map_err(|error| invalid(error.to_string()))?,
                            }
                        }
                        crate::RootSelector::ManagedOverlay => {
                            return Err(invalid("raw root has an overlay selector"))
                        }
                    };
                    let filesystem = match root_filesystem {
                        crate::store::models::storage::RootFilesystem::Ext4 => {
                            rootfs_spec::RootFilesystem::Ext4
                        }
                    };
                    rootfs_spec::Root::Raw(rootfs_spec::RawRoot {
                        device: rootfs_spec::RawDeviceExpectation {
                            serial: rootfs_spec::RawSerial::Root,
                            length_bytes: actual.len().max(geometry.length),
                            logical_sector_size: geometry.logical_sector_size,
                            read_only: false,
                        },
                        selector,
                        filesystem,
                    })
                },
            )
        }
        MachineRoot::LinuxOverlay {
            lower: persisted,
            upper,
            upper_uuid,
            capacity,
            temporary_directory,
            ..
        } => {
            qualification
                .as_ref()
                .ok_or_else(|| invalid("layered overlay boot has no owned boot assets"))?;
            let launch = lower
                .as_ref()
                .ok_or_else(|| invalid("overlay launch has no leased retained composition"))?;
            // Geometry and UUID are derived claims of the authenticated result.
            launch.retained.check_lower(persisted)?;
            check_lower_platform(&launch.retained.recipe.platform, &storage.boot)?;
            let geometry = persisted.geometry();
            let lower_uuid = persisted.filesystem_uuid();
            let pool = StoragePool::open_existing(images_dir)?
                .ok_or_else(|| invalid("immutable lower pool is missing"))?;
            let plan = crate::storage::vmdk::FlatLowerPlan::new(&launch.occurrences)?;
            if plan.logical_length() != geometry.length {
                return Err(invalid(
                    "retained lower occurrences differ from semantic geometry",
                ));
            }
            let admitted = plan.preflight(data_disks)?;
            admitted.verify_composition(&pool, &launch.validation)?;
            validate_private(&machine_dir.join(upper.as_path()), *capacity)?;
            descriptor = Some(admitted.descriptor()?);
            let temporary_directory = match temporary_directory {
                TemporaryDirectoryPolicy::DiskBacked => rootfs_spec::TemporaryDirectory::DiskBacked,
                TemporaryDirectoryPolicy::Tmpfs { capacity_bytes } => {
                    rootfs_spec::TemporaryDirectory::Tmpfs {
                        capacity_bytes: *capacity_bytes,
                    }
                }
            };
            let expectation =
                |serial, length_bytes, read_only, uuid: uuid::Uuid| -> Result<_, LibVmError> {
                    Ok(rootfs_spec::DeviceExpectation {
                        serial,
                        length_bytes,
                        logical_sector_size: 512,
                        read_only,
                        filesystem_uuid: rootfs_spec::FilesystemUuid::new(*uuid.as_bytes())
                            .map_err(|e| invalid(e.to_string()))?,
                    })
                };
            let root = rootfs_spec::OverlayRoot {
                lower: expectation(
                    rootfs_spec::RootSerial::Lower,
                    geometry.length,
                    true,
                    lower_uuid,
                )?,
                upper: expectation(
                    rootfs_spec::RootSerial::Upper,
                    *capacity,
                    false,
                    *upper_uuid,
                )?,
                upper_profile: rootfs_spec::UpperProfile::SiloUpperExt4V1,
                overlay_profile: rootfs_spec::OverlayProfile::SiloOverlayV1,
                rendering_abi: rootfs_spec::OverlayRenderingAbi::LinuxOverlayfsMountinfoV1,
                temporary_directory,
            };
            (
                vec![
                    disk(
                        "lower.vmdk",
                        DiskRole::RootLower,
                        geometry.length,
                        "silo-root-lower".into(),
                    )?,
                    disk(
                        upper.as_path(),
                        DiskRole::RootUpper,
                        *capacity,
                        "silo-root-upper".into(),
                    )?,
                ],
                rootfs_spec::Root::ErofsOverlay(root),
            )
        }
    };
    let mut bootstrap = vec![0; rootfs_spec::MAX_JSON_BYTES];
    let count =
        rootfs_spec::encode_bootstrap(&rootfs_spec::Bootstrap { root, rosetta }, &mut bootstrap)
            .map_err(|e| invalid(e.to_string()))?;
    bootstrap.truncate(count);
    Ok(PreparedRoot {
        disks,
        bootstrap,
        descriptor,
        qualification,
        storage: storage.clone(),
        rosetta,
        _lower: lower,
    })
}

/// Retained publication descriptors, flushed together immediately before spawn.
pub(crate) struct LaunchArtifacts {
    pub(crate) files: Vec<File>,
    directory: crate::paths::OwnedDirectory,
}

impl std::fmt::Debug for LaunchArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchArtifacts")
            .field("directory", &self.directory.path())
            .field("files", &self.files.len())
            .finish()
    }
}

impl LaunchArtifacts {
    pub(crate) fn new(machine_dir: &Path) -> Result<Self, LibVmError> {
        Ok(Self {
            files: Vec::with_capacity(4),
            directory: crate::paths::OwnedDirectory::open_existing_root(machine_dir)?
                .ok_or_else(|| invalid("machine launch directory disappeared"))?,
        })
    }

    pub(crate) fn sync(
        &self,
        lease: &crate::store::operation_store::LaunchStorageLease,
    ) -> Result<(), LibVmError> {
        // All final metadata and bytes precede all namespace barriers. The
        // stable lease lives in the pool, not in the machine directory.
        for file in &self.files {
            file.sync_all()?;
        }
        lease.lock().sync()?;
        self.directory.sync()?;
        lease.durability_directory().sync()
    }
}

pub(crate) fn publish_descriptor(machine_dir: &Path, descriptor: &str) -> Result<File, LibVmError> {
    let directory = crate::paths::OwnedDirectory::open_existing_root(machine_dir)?
        .ok_or_else(|| invalid("machine directory disappeared before descriptor publication"))?;
    directory.publish_file_deferred(
        "lower.vmdk",
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        |file| {
            file.write_all(descriptor.as_bytes())?;
            Ok(())
        },
    )
}

pub(crate) fn publish_kernel(
    machine_dir: &Path,
    kernel: &crate::owned_boot_assets::OwnedBootAsset,
) -> Result<(std::path::PathBuf, File), LibVmError> {
    let directory = crate::paths::OwnedDirectory::open_existing_root(machine_dir)?
        .ok_or_else(|| invalid("machine directory disappeared before kernel publication"))?;
    let file = directory.publish_file_deferred(
        "kernel-qualified",
        nix::sys::stat::Mode::S_IRUSR,
        |file| {
            kernel.copy_into(file)?;
            Ok(())
        },
    )?;
    Ok((machine_dir.join("kernel-qualified"), file))
}

pub(crate) fn baseline_map_path(
    identity: &vm_spec::capture::Sha256Digest,
) -> Result<crate::PrivatePath, LibVmError> {
    let stream = crate::storage::identity::StreamId::from_sha256(*identity.as_bytes());
    crate::PrivatePath::new(format!("disk-baseline-{}.map", stream.hex()))
}

/// Optional map cache, not a durability boundary. Launch authenticates it before
/// issuing a seed and falls back to unknown coverage if a crash loses its bytes.
pub(crate) fn retain_disk_map(
    machine_dir: &Path,
    map: &crate::storage::stream::StreamMap,
) -> Result<crate::PrivatePath, LibVmError> {
    let path = baseline_map_path(&vm_spec::capture::Sha256Digest::from_bytes(
        *map.id().as_bytes(),
    ))?;
    let name = path
        .as_path()
        .to_str()
        .ok_or_else(|| invalid("disk baseline path is not UTF-8"))?;
    let directory = crate::paths::OwnedDirectory::open_existing_root(machine_dir)?
        .ok_or_else(|| invalid("machine directory disappeared before disk baseline"))?;
    let bytes = map.canonical_bytes()?;
    if let Some(existing) = directory.open_immutable_file(name)? {
        use std::io::Read;
        let mut retained = Vec::new();
        existing
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut retained)?;
        if retained == bytes {
            return Ok(path);
        }
        tracing::warn!("replacing incomplete disk baseline map cache");
    }
    directory.publish_file_deferred(name, nix::sys::stat::Mode::S_IRUSR, |file| {
        file.write_all(&bytes)?;
        Ok(())
    })?;
    Ok(path)
}

pub(crate) fn seed_disk(
    storage: &mut MachineStorageRecord,
    machine_dir: &Path,
    index: usize,
    disk: &Disk,
    file: &File,
    map: &crate::storage::stream::StreamMap,
) -> Result<(), LibVmError> {
    use crate::store::models::storage::{DiskBaseline, DiskBaselineState};
    let metadata = file.metadata()?;
    if disk.read_only
        || disk.format != DiskFormat::Raw
        || metadata.len() != map.length()
        || disk.geometry.length != map.length()
    {
        return Err(invalid("disk baseline differs from private raw attachment"));
    }
    let map_path = retain_disk_map(machine_dir, map)?;
    let seed = vm_spec::capture::DiskTrackingSeed {
        version: vm_spec::capture::DISK_TRACKING_VERSION,
        role: disk.role,
        attachment_index: u32::try_from(index).map_err(|error| invalid(error.to_string()))?,
        block_id: disk.block_id.clone(),
        file_device: metadata.dev(),
        file_inode: metadata.ino(),
        length: metadata.len(),
        chunk_size: vm_spec::capture::STREAM_CHUNK_BYTES,
        epoch: vm_spec::lifecycle::LiveId::parse(&uuid::Uuid::new_v4().to_string())
            .map_err(invalid)?,
        baseline: Some(vm_spec::capture::Sha256Digest::from_bytes(
            *map.id().as_bytes(),
        )),
    };
    seed.validate().map_err(invalid)?;
    storage
        .disk_baselines
        .retain(|baseline| baseline.seed.attachment_index != seed.attachment_index);
    storage.disk_baselines.push(DiskBaseline {
        seed,
        map: map_path,
        storage_generation: storage.storage_generation,
        generation: 0,
        state: DiskBaselineState::Ready,
        fingerprint: crate::storage::identity_file::SourceFingerprint::new(&metadata),
    });
    storage
        .disk_baselines
        .sort_by_key(|baseline| baseline.seed.attachment_index);
    Ok(())
}

pub(crate) fn launch_disk_seeds(
    storage: &MachineStorageRecord,
    machine_dir: &Path,
) -> Result<Vec<vm_spec::capture::DiskTrackingSeed>, LibVmError> {
    use crate::store::models::storage::DiskBaselineState;
    let mut ready = storage
        .disk_baselines
        .iter()
        .filter(|baseline| {
            matches!(baseline.state, DiskBaselineState::Ready)
                && baseline.storage_generation == storage.storage_generation
        })
        .peekable();
    if ready.peek().is_none() {
        return Ok(Vec::new());
    }
    let directory = crate::paths::OwnedDirectory::open_existing_root(machine_dir)?
        .ok_or_else(|| invalid("ready disk baseline machine directory disappeared"))?;
    let mut seeds = Vec::with_capacity(storage.disk_baselines.len());
    for baseline in ready {
        let path = match baseline.seed.role {
            DiskRole::Root | DiskRole::RootUpper => {
                crate::machine::stopped::root_private(storage).0
            }
            DiskRole::Data => match storage
                .disks
                .iter()
                .find(|disk| disk.order == baseline.seed.attachment_index)
                .map(|disk| &disk.storage)
            {
                Some(crate::DiskStorage::ManagedWritable { path, .. }) => path,
                _ => continue,
            },
            DiskRole::RootLower => continue,
        };
        let held = crate::machine::stopped::open_private(&directory, path, baseline.seed.length)?;
        if crate::storage::identity_file::SourceFingerprint::new(&held.file.metadata()?)
            != baseline.fingerprint
        {
            tracing::warn!(
                attachment = baseline.seed.attachment_index,
                "disk baseline invalidated by stopped backing fingerprint change"
            );
            continue;
        }
        let authenticated = (|| -> Result<(), LibVmError> {
            use std::io::Read;
            let name = baseline
                .map
                .as_path()
                .to_str()
                .ok_or_else(|| invalid("disk baseline map path is not UTF-8"))?;
            let file = directory
                .open_immutable_file(name)?
                .ok_or_else(|| invalid("disk baseline map cache is missing"))?;
            let limit = baseline
                .seed
                .length
                .div_ceil(vm_spec::capture::STREAM_CHUNK_BYTES)
                * 74
                + 256;
            let length = file.metadata()?.len();
            if length > limit {
                return Err(invalid("disk baseline map cache exceeds its encoded bound"));
            }
            let mut bytes = Vec::with_capacity(length as usize);
            file.take(limit + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > limit {
                return Err(invalid(
                    "disk baseline map cache grew beyond its encoded bound",
                ));
            }
            let map = vm_spec::capture::StreamMap::decode(&bytes).map_err(invalid)?;
            if map.length() != baseline.seed.length || Some(map.id()) != baseline.seed.baseline {
                return Err(invalid("disk baseline map cache differs from its seed"));
            }
            Ok(())
        })();
        if let Err(error) = authenticated {
            tracing::warn!(
                attachment = baseline.seed.attachment_index,
                %error,
                "disk baseline invalidated by unavailable map cache"
            );
            continue;
        }
        seeds.push(baseline.seed.clone());
    }
    Ok(seeds)
}

#[cfg(test)]
mod tests {
    use crate::machine::root_storage::{disk, prepare, validate_spec};
    use crate::{
        MachineRoot, MachineStorageRecord, OverlayLower, PrivatePath, TemporaryDirectoryPolicy,
    };
    use vm_spec::DiskRole;

    fn storage() -> MachineStorageRecord {
        let mut storage = MachineStorageRecord::opaque_raw(
            PrivatePath::new("upper.raw").unwrap(),
            64 * 1024 * 1024,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        storage.root = MachineRoot::LinuxOverlay {
            lower: OverlayLower::ErofsComposition {
                record: format!("sha256:{}", "ab".repeat(32)).parse().unwrap(),
                geometry: vm_spec::DiskGeometry {
                    length: 4096,
                    logical_sector_size: 512,
                },
                filesystem_uuid: uuid::Uuid::new_v4(),
            },
            upper: PrivatePath::new("upper.raw").unwrap(),
            upper_uuid: uuid::Uuid::new_v4(),
            capacity: 64 * 1024 * 1024,
            ext4_profile: crate::Ext4Profile::SiloUpperExt4V1,
            overlay_profile: crate::OverlayProfile::SiloOverlayV1,
            temporary_directory: TemporaryDirectoryPolicy::DiskBacked,
        };
        storage.profile = crate::StorageProfile::LinuxOverlayV1;
        storage.backend = crate::BackendRequirement::KrunOverlay;
        if let crate::BootProfile::LinuxDirect { root_selector, .. } = &mut storage.boot {
            *root_selector = crate::RootSelector::ManagedOverlay;
        }
        storage
    }

    fn spec() -> vm_spec::VmSpec {
        let mut spec = vm_spec::VmSpec::current();
        spec.storage = Some(vm_spec::Storage {
            disks: vec![
                disk(
                    "lower.vmdk",
                    DiskRole::RootLower,
                    4096,
                    "silo-root-lower".into(),
                )
                .unwrap(),
                disk(
                    "upper.raw",
                    DiskRole::RootUpper,
                    64 * 1024 * 1024,
                    "silo-root-upper".into(),
                )
                .unwrap(),
            ],
        });
        spec.boot = Some(vm_spec::Boot {
            kernel: Some(vm_spec::Kernel {
                path: None,
                initramfs: None,
                cmdline: vec![crate::machine::root_storage::ROOT_MARKER.into()],
            }),
            userdata: None,
        });
        spec
    }

    #[test]
    fn vmdk_root_spec_requires_semantic_pair_and_fail_closed_marker() {
        let storage = storage();
        let valid = spec();
        validate_spec(&storage, &valid).unwrap();
        for argument in [
            "root=/dev/vda",
            "rootfstype=ext4",
            "rootflags=rw",
            "\"root=/dev/vda\"",
            "rdinit=/agent/silo-agent",
            "\"rdinit=/agent/silo-agent\"",
            "rdinit=\"/agent/silo-agent\"",
            "silo.rootfs=other",
            "silo.rootfs=linux-flat-overlay-v1",
            "silo.rootfs=linux-erofs-overlay-v1",
            "\"silo.rootfs=linux-erofs-overlay-v1\"",
        ] {
            let mut invalid = valid.clone();
            invalid
                .boot
                .as_mut()
                .unwrap()
                .kernel
                .as_mut()
                .unwrap()
                .cmdline
                .push(argument.into());
            assert!(validate_spec(&storage, &invalid).is_err(), "{argument}");
        }
        let mut missing_marker = valid.clone();
        missing_marker
            .boot
            .as_mut()
            .unwrap()
            .kernel
            .as_mut()
            .unwrap()
            .cmdline
            .clear();
        assert!(validate_spec(&storage, &missing_marker).is_err());
        // One marker token, but not the builder-emitted whole argument.
        let mut embedded_marker = valid.clone();
        embedded_marker
            .boot
            .as_mut()
            .unwrap()
            .kernel
            .as_mut()
            .unwrap()
            .cmdline = vec!["silo.rootfs=linux-erofs-overlay-v1 quiet".into()];
        assert!(validate_spec(&storage, &embedded_marker).is_err());
        let mut imported = valid.clone();
        imported.storage.as_mut().unwrap().disks[0].path = "/external/arbitrary.vmdk".into();
        assert!(validate_spec(&storage, &imported).is_err());
        let mut changed_upper = valid.clone();
        changed_upper.storage.as_mut().unwrap().disks[1]
            .geometry
            .length += 4096;
        assert!(validate_spec(&storage, &changed_upper).is_err());
        let mut changed_lower = valid.clone();
        changed_lower.storage.as_mut().unwrap().disks[0]
            .geometry
            .length += 4096;
        assert!(validate_spec(&storage, &changed_lower).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vmdk_kernel_version_floor_precedes_pool_or_private_file_access() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let kernel = temp.path().join("kernel");
        let initramfs = temp.path().join("initramfs");
        let native = temp.path().join("native");
        std::fs::write(&kernel, test_utils::direct_kernel::bzimage("5.15.219")).unwrap();
        let open = || {
            crate::owned_boot_assets::open_overlay_boot(
                &kernel,
                &initramfs,
                vm_spec::live::LiveBackend::Krun,
                &native,
            )
        };
        let error = open().unwrap_err();
        assert!(matches!(error, crate::BootAssetError::KernelTooOld { .. }));
        assert!(error.to_string().contains("5.15.219"));
        assert!(error.to_string().contains("6.6"));
        assert!(!initramfs.exists());
        assert!(!native.exists());
        assert!(!temp.path().join("missing-pool").exists());

        std::fs::write(&initramfs, b"base archive").unwrap();
        std::fs::write(&native, b"held executable").unwrap();
        std::fs::set_permissions(&native, std::fs::Permissions::from_mode(0o500)).unwrap();
        for version in ["6.6.0", "6.18.48", "7.2.2"] {
            std::fs::write(&kernel, test_utils::direct_kernel::bzimage(version)).unwrap();
            let assets = open().expect("6.6+ kernel passes the overlay floor");
            let error = match prepare(
                &storage(),
                temp.path(),
                &temp.path().join("missing-pool"),
                None,
                0,
                Some(assets),
                rootfs_spec::RosettaMode::Disabled,
            ) {
                Ok(_) => panic!("root without retained lower unexpectedly prepared"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("no leased retained composition"));
            assert!(!temp.path().join("missing-pool").exists());
            assert!(!temp.path().join("upper.raw").exists());
        }
    }

    #[test]
    fn lower_recipe_platform_must_equal_boot_userspace_platform() {
        let storage = storage();
        crate::machine::root_storage::check_lower_platform(
            &oci::Platform::host().unwrap(),
            &storage.boot,
        )
        .unwrap();
        let foreign = if oci::Platform::host().unwrap().architecture == "amd64" {
            oci::Platform {
                os: "linux".into(),
                architecture: "arm64".into(),
                variant: None,
            }
        } else {
            oci::Platform::linux_amd64()
        };
        assert!(
            crate::machine::root_storage::check_lower_platform(&foreign, &storage.boot).is_err()
        );
        let windows = oci::Platform {
            os: "windows".into(),
            ..oci::Platform::host().unwrap()
        };
        assert!(
            crate::machine::root_storage::check_lower_platform(&windows, &storage.boot).is_err()
        );
    }

    #[test]
    fn upper_admission_checks_profile_uuid_and_capacity_but_never_journal_state() {
        use std::os::unix::fs::FileExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("upper.raw");
        let capacity = 64 * 1024 * 1024;
        let formatted = disk_image::ext4::upper::format_upper(
            &path,
            rootfs_spec::upper_geometry::UpperCapacity::new(capacity).unwrap(),
        )
        .unwrap();
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap()
        };
        let validate = |uuid, capacity| {
            crate::machine::root_storage::validate_upper_file(&open(), uuid, capacity)
        };
        validate(formatted.uuid, capacity).unwrap();
        assert!(validate(uuid::Uuid::new_v4(), capacity).is_err());
        assert!(validate(formatted.uuid, 4096).is_err());
        // A dirty journal (RECOVER) is an exact captured state, never repaired.
        let file = open();
        let mut incompat = [0u8; 4];
        file.read_exact_at(&mut incompat, 1024 + 96).unwrap();
        let dirty = u32::from_le_bytes(incompat) | 4;
        file.write_all_at(&dirty.to_le_bytes(), 1024 + 96).unwrap();
        validate(formatted.uuid, capacity).unwrap();
        // An unknown incompatible feature is refused.
        file.write_all_at(&(dirty | 0x8000_0000).to_le_bytes(), 1024 + 96)
            .unwrap();
        assert!(validate(formatted.uuid, capacity).is_err());
    }

    #[test]
    fn raw_root_keeps_separate_bootstrap_and_explicit_geometry() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("root.raw"), [0; 512]).unwrap();
        let storage = MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let root = prepare(
            &storage,
            temp.path(),
            &temp.path().join("missing-pool"),
            None,
            0,
            None,
            rootfs_spec::RosettaMode::Disabled,
        )
        .unwrap();
        assert!(root.descriptor.is_none());
        assert_eq!(root.disks[0].role, DiskRole::Root);
        assert_eq!(root.disks[0].geometry.length, 512);
        let bootstrap = rootfs_spec::decode_bootstrap(&root.bootstrap).unwrap();
        assert_eq!(bootstrap.rosetta, rootfs_spec::RosettaMode::Disabled);
        let rootfs_spec::Root::Raw(raw) = bootstrap.root else {
            panic!("raw bootstrap expected")
        };
        assert_eq!(raw.device.serial, rootfs_spec::RawSerial::Root);
        assert_eq!(raw.device.length_bytes, 512);
        assert_eq!(raw.selector, rootfs_spec::RawSelector::WholeDisk);
        assert_eq!(raw.filesystem, rootfs_spec::RootFilesystem::Ext4);
    }

    #[test]
    fn partition_bootstrap_uses_persisted_disk_local_identity_and_disables_resize() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("root.raw"), [0; 4096]).unwrap();
        let guid = uuid::Uuid::new_v4();
        let mut storage = MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        if let MachineRoot::OpaqueRaw { layout, .. } = &mut storage.root {
            *layout = crate::RawLayout::Partitioned {
                table: crate::PartitionTable::Gpt,
            };
        }
        if let crate::BootProfile::LinuxDirect { root_selector, .. } = &mut storage.boot {
            *root_selector = crate::RootSelector::GptPartition { guid };
        }
        let prepared = prepare(
            &storage,
            temp.path(),
            &temp.path().join("images"),
            None,
            0,
            None,
            rootfs_spec::RosettaMode::Required,
        )
        .unwrap();
        let bootstrap = rootfs_spec::decode_bootstrap(&prepared.bootstrap).unwrap();
        assert_eq!(bootstrap.rosetta, rootfs_spec::RosettaMode::Required);
        let rootfs_spec::Root::Raw(raw) = bootstrap.root else {
            panic!("raw bootstrap expected")
        };
        assert_eq!(raw.device.length_bytes, prepared.disks[0].geometry.length);
        assert_eq!(raw.device.length_bytes, 4096);
        assert_eq!(
            raw.selector,
            rootfs_spec::RawSelector::GptPartition {
                guid: rootfs_spec::PartitionGuid::new(*guid.as_bytes()).unwrap(),
            }
        );
        assert!(!crate::machine::root_storage::allows_rootfs_resize(
            &storage
        ));
    }

    #[test]
    fn raw_boot_rejects_hidden_and_duplicate_root_arguments() {
        for argument in [
            "root=/dev/vda",
            "quiet rootflags=rw",
            "rootfstype=ext4",
            "\"root=/dev/vda\"",
            "rootflags=\"rw\"",
            "quiet\u{b}root=/dev/vda",
            "silo.rootfs=linux-flat-overlay-v1",
            "\"silo.rootfs=linux-flat-overlay-v1\"",
        ] {
            assert!(crate::machine::root_storage::validate_root_arguments(
                &[argument.into()],
                false
            )
            .is_err());
        }
        crate::machine::root_storage::validate_root_arguments(&["quiet".into()], false).unwrap();
    }

    #[test]
    fn initial_executable_override_is_rejected_in_every_kernel_spelling() {
        let rejected = |args: &[&str]| {
            let args = args
                .iter()
                .map(|arg| (*arg).to_string())
                .collect::<Vec<_>>();
            let error =
                crate::machine::root_storage::validate_root_arguments(&args, false).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("rdinit= is reserved; the trusted /init is the initial executable"),
                "{args:?}: {error}"
            );
        };
        rejected(&["rdinit=/agent/silo-agent"]);
        rejected(&["rdinit=/init"]);
        // An empty value discards /init and falls through to kernel root mounting.
        rejected(&["rdinit="]);
        rejected(&["\"rdinit=/agent/silo-agent\""]);
        rejected(&["rdinit=\"/agent/silo-agent\""]);
        rejected(&["\"rdinit=\"/agent/silo-agent\"\""]);
        rejected(&["init=/sbin/init", "rdinit=/agent/silo-agent"]);
        // Kernel-only separators: VT, Latin-1 NBSP inside U+00A0 and U+00E0.
        rejected(&["quiet\u{b}rdinit=/agent/silo-agent"]);
        rejected(&["quiet\u{a0}rdinit=/agent/silo-agent"]);
        rejected(&["x\u{e0}rdinit=/agent/silo-agent"]);
        // Quoting spans arguments because backends join them with a space.
        rejected(&["console=hvc0", "\"rdinit=/agent/silo-agent", "quiet\""]);
        rejected(&["x=\"", "\"", "rdinit=/agent/silo-agent"]);

        // The kernel reads these as other parameters; `init=` stays the
        // image handoff input.
        for args in [
            vec!["init=/sbin/init"],
            vec!["rdinit"],
            vec!["xrdinit=/x", "rdinit_extra=/x"],
            vec!["\"a rdinit=/agent/silo-agent\""],
            vec!["a=\"b", "rdinit=/agent/silo-agent\""],
            vec!["rd\"init\"=/agent/silo-agent"],
        ] {
            let args = args.into_iter().map(String::from).collect::<Vec<_>>();
            crate::machine::root_storage::validate_root_arguments(&args, false)
                .unwrap_or_else(|error| panic!("{args:?}: {error}"));
        }
        assert!(crate::machine::root_storage::validate_root_arguments(
            &["quiet\0".into(), "rdinit=/agent/silo-agent".into()],
            false
        )
        .is_err());
    }

    #[test]
    fn vmdk_launch_descriptor_is_regenerated_after_home_move_with_spaces() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let old_home = temp.path().join("old home");
        let new_home = temp.path().join("moved home");
        let machine = old_home.join("machines/test");
        std::fs::create_dir_all(&machine).unwrap();
        std::fs::set_permissions(&old_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&machine, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pool = crate::storage::pool::StoragePool::open(&old_home.join("images")).unwrap();
        let source = temp.path().join("source");
        std::fs::write(&source, [0x61; 512]).unwrap();
        let lower = pool.publish_stream(&source).unwrap();
        let occurrences = [pool.lower_occurrence(&lower.id).unwrap()];
        let admitted = crate::storage::vmdk::FlatLowerPlan::new(&occurrences)
            .unwrap()
            .preflight(0)
            .unwrap();
        admitted.verify(&pool).unwrap();
        let first = admitted.descriptor().unwrap();
        crate::machine::root_storage::publish_descriptor(&machine, &first).unwrap();
        drop(pool);
        std::fs::rename(&old_home, &new_home).unwrap();
        let pool = crate::storage::pool::StoragePool::open_existing(&new_home.join("images"))
            .unwrap()
            .unwrap();
        let occurrences = [pool.lower_occurrence(&lower.id).unwrap()];
        let admitted = crate::storage::vmdk::FlatLowerPlan::new(&occurrences)
            .unwrap()
            .preflight(0)
            .unwrap();
        admitted.verify(&pool).unwrap();
        let second = admitted.descriptor().unwrap();
        crate::machine::root_storage::publish_descriptor(&new_home.join("machines/test"), &second)
            .unwrap();
        assert!(!second.contains(old_home.to_str().unwrap()));
        assert!(second.contains(new_home.to_str().unwrap()));
        assert_ne!(first, second);
        assert_eq!(pool.verify_stream(&lower.id).unwrap().id(), lower.id);
        assert_eq!(
            std::fs::read_to_string(new_home.join("machines/test/lower.vmdk")).unwrap(),
            second
        );
    }

    #[tokio::test]
    async fn layered_launch_lower_holds_exact_occurrences_and_refuses_forged_claims_or_bytes() {
        use std::os::unix::fs::{FileExt, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::paths::LocalPaths::new(temp.path());
        let store = crate::store::Store::new(&paths).await.unwrap();
        let held = crate::store::storage::tests::retained_lower(&store, paths.home(), b'R').await;
        let retained = held.retained().clone();
        let lower = retained.overlay_lower();
        let (_config, lease) =
            crate::store::storage::tests::leased_layered_machine(&store, &paths, &held).await;
        let layers = crate::store::layer_store::LayerStore::from_store(store.clone());
        let launch = layers
            .launch_lower(&lease, lease.storage_record())
            .await
            .unwrap();
        let foreign_home = tempfile::tempdir().unwrap();
        let foreign_store =
            crate::store::Store::new(&crate::paths::LocalPaths::new(foreign_home.path()))
                .await
                .unwrap();
        assert!(
            crate::store::layer_store::LayerStore::from_store(foreign_store)
                .launch_lower(&lease, lease.storage_record())
                .await
                .is_err()
        );
        // fsmeta object first, then every pack occurrence; the repeated layer
        // keeps its exact position and shares one retained backing.
        assert_eq!(launch.occurrences.len(), 3);
        assert_eq!(
            launch.occurrences[0].backing(),
            crate::storage::vmdk::LowerBacking::Object(retained.fsmeta())
        );
        assert_eq!(
            launch.occurrences[1].backing(),
            launch.occurrences[2].backing()
        );
        let pool = crate::storage::pool::StoragePool::open_existing(paths.images_dir())
            .unwrap()
            .unwrap();
        let admitted = crate::storage::vmdk::FlatLowerPlan::new(&launch.occurrences)
            .unwrap()
            .preflight(0)
            .unwrap();
        assert_eq!(admitted.logical_length(), lower.geometry().length);
        admitted
            .verify_composition(&pool, &launch.validation)
            .unwrap();
        // Neither another generation nor forged lower claims can reuse this authority.
        let mut forged = lease.storage_record().clone();
        forged.storage_generation += 1;
        assert!(layers.launch_lower(&lease, &forged).await.is_err());
        let mut forged = lease.storage_record().clone();
        let crate::MachineRoot::LinuxOverlay {
            lower: forged_lower,
            ..
        } = &mut forged.root
        else {
            unreachable!("layered fixture");
        };
        let crate::OverlayLower::ErofsComposition {
            filesystem_uuid, ..
        } = forged_lower;
        *filesystem_uuid = uuid::Uuid::new_v4();
        assert!(layers.launch_lower(&lease, &forged).await.is_err());
        // A ctime change revokes the held proof before descriptor handoff.
        let fsmeta = pool.object_path(&retained.fsmeta());
        let mode = std::fs::metadata(&fsmeta).unwrap().permissions().mode();
        std::fs::set_permissions(&fsmeta, std::fs::Permissions::from_mode(0o600)).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fsmeta)
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact_at(&mut byte, 0).unwrap();
        file.write_all_at(&[byte[0] ^ 0xff], 0).unwrap();
        drop(file);
        std::fs::set_permissions(&fsmeta, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(admitted
            .verify_composition(&pool, &launch.validation)
            .is_err());
    }
    #[test]
    fn fresh_upper_has_no_disk_baseline_or_launch_seed() {
        use crate::machine::root_storage::launch_disk_seeds;
        let temp = tempfile::tempdir().unwrap();
        let directory =
            crate::paths::OwnedDirectory::open_root(&temp.path().join("machine")).unwrap();
        let length = 64 << 20;
        let formatted = disk_image::ext4::upper::format_upper(
            &directory.path().join("upper.raw"),
            rootfs_spec::upper_geometry::UpperCapacity::new(length).unwrap(),
        )
        .unwrap();
        let mut record = storage();
        if let MachineRoot::LinuxOverlay { upper_uuid, .. } = &mut record.root {
            *upper_uuid = formatted.uuid;
        }
        #[cfg(target_os = "linux")]
        let reads = crate::store::snapshot_store::tests::watch_stream_reads(
            &directory.path().join("upper.raw"),
        );
        assert!(record.disk_baselines.is_empty());
        assert!(launch_disk_seeds(&record, directory.path())
            .unwrap()
            .is_empty());
        #[cfg(target_os = "linux")]
        assert!(!crate::store::snapshot_store::tests::observed_stream_read(
            &reads
        ));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn authenticated_private_children_inherit_maps_with_distinct_bindings() {
        use crate::machine::root_disk::{copy_private, CopyQualification, CopySource};
        use crate::machine::root_storage::{launch_disk_seeds, seed_disk};
        use crate::storage::stream::{AuthenticatedStream, CopyWriteback, StreamHasher};
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let source = crate::paths::OwnedDirectory::open_root(&temp.path().join("source")).unwrap();
        source.write_file("root.raw", &[0x56; 512]).unwrap();
        let file = std::fs::File::open(source.path().join("root.raw")).unwrap();
        let parent_inode = file.metadata().unwrap().ino();
        let map = StreamHasher::new().hash_open_file(&file, 512).unwrap().map;
        let authenticated = AuthenticatedStream::from_receipt(file, map.clone()).unwrap();
        let disk = disk("root.raw", DiskRole::Root, 512, "root".into()).unwrap();
        let mut epochs = std::collections::BTreeSet::new();
        let mut inodes = std::collections::BTreeSet::new();
        for name in ["restore", "fork-a", "fork-b"] {
            let directory =
                crate::paths::OwnedDirectory::open_root(&temp.path().join(name)).unwrap();
            let mut copy = copy_private(
                CopySource::Authenticated(&authenticated),
                directory.try_clone().unwrap(),
                "staged",
                &mut CopyQualification::new(32),
                CopyWriteback::Buffered,
            )
            .unwrap();
            assert_eq!(copy.map(), Some(&map));
            copy.publish_constructed(directory.try_clone().unwrap(), "root.raw")
                .unwrap();
            let mut record = MachineStorageRecord::opaque_raw(
                PrivatePath::new("root.raw").unwrap(),
                512,
                &oci::Platform::host().unwrap(),
            )
            .unwrap();
            #[cfg(target_os = "linux")]
            let reads = crate::store::snapshot_store::tests::watch_stream_reads(
                &directory.path().join("root.raw"),
            );
            seed_disk(
                &mut record,
                directory.path(),
                0,
                &disk,
                copy.file(),
                copy.map().unwrap(),
            )
            .unwrap();
            let seed = launch_disk_seeds(&record, directory.path())
                .unwrap()
                .remove(0);
            #[cfg(target_os = "linux")]
            assert!(!crate::store::snapshot_store::tests::observed_stream_read(
                &reads
            ));
            assert_eq!(seed.baseline.unwrap().as_bytes(), map.id().as_bytes());
            assert_ne!(seed.file_inode, parent_inode);
            assert!(epochs.insert(seed.epoch));
            assert!(inodes.insert(seed.file_inode));
            assert_eq!(
                StreamHasher::new()
                    .hash_open_file(copy.file(), 512)
                    .unwrap()
                    .map,
                map
            );
            copy.retain();
        }
    }

    #[test]
    fn stopped_mutations_and_unavailable_maps_never_reuse_a_ready_disk_baseline() {
        use crate::machine::root_storage::{launch_disk_seeds, retain_disk_map, seed_disk};
        use std::os::unix::fs::{FileExt, PermissionsExt};
        for mutation in [
            "write",
            "replace",
            "resize",
            "chmod",
            "link",
            "generation",
            "map-missing",
            "map-truncated",
            "map-identity",
            "map-writable",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let directory =
                crate::paths::OwnedDirectory::open_root(&temp.path().join("machine")).unwrap();
            directory.write_file("root.raw", &[0x41; 512]).unwrap();
            let path = directory.path().join("root.raw");
            let file = std::fs::File::options()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let map = crate::storage::stream::StreamHasher::new()
                .hash_open_file(&file, 512)
                .unwrap()
                .map;
            let mut record = MachineStorageRecord::opaque_raw(
                PrivatePath::new("root.raw").unwrap(),
                512,
                &oci::Platform::host().unwrap(),
            )
            .unwrap();
            let disk = disk("root.raw", DiskRole::Root, 512, "root".into()).unwrap();
            seed_disk(&mut record, directory.path(), 0, &disk, &file, &map).unwrap();
            assert_eq!(
                launch_disk_seeds(&record, directory.path()).unwrap().len(),
                1
            );
            let map_path = directory
                .path()
                .join(record.disk_baselines[0].map.as_path());
            #[cfg(target_os = "linux")]
            let reads = crate::store::snapshot_store::tests::watch_stream_reads(&path);
            match mutation {
                "write" => file.write_all_at(b"changed", 0).unwrap(),
                "replace" => {
                    directory
                        .write_file("replacement.raw", &[0x42; 512])
                        .unwrap();
                    std::fs::rename(directory.path().join("replacement.raw"), &path).unwrap();
                }
                "resize" => file.set_len(1024).unwrap(),
                "chmod" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap()
                }
                "link" => std::fs::hard_link(&path, directory.path().join("alias.raw")).unwrap(),
                "generation" => record.storage_generation += 1,
                "map-missing" => std::fs::remove_file(&map_path).unwrap(),
                "map-truncated" | "map-identity" => {
                    std::fs::set_permissions(&map_path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    let bytes = if mutation == "map-truncated" {
                        b"{".to_vec()
                    } else {
                        crate::storage::stream::StreamMap::new(
                            512,
                            vec![crate::storage::stream::Chunk::Zero],
                        )
                        .unwrap()
                        .canonical_bytes()
                        .unwrap()
                    };
                    std::fs::write(&map_path, bytes).unwrap();
                    std::fs::set_permissions(&map_path, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                }
                "map-writable" => {
                    std::fs::set_permissions(&map_path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            if let Ok(seeds) = launch_disk_seeds(&record, directory.path()) {
                assert!(seeds.is_empty(), "{mutation}");
            }
            if matches!(mutation, "map-missing" | "map-truncated" | "map-identity") {
                assert!(launch_disk_seeds(&record, directory.path())
                    .unwrap()
                    .is_empty());
                retain_disk_map(directory.path(), &map).unwrap();
                assert_eq!(
                    launch_disk_seeds(&record, directory.path()).unwrap().len(),
                    1
                );
            }
            #[cfg(target_os = "linux")]
            assert!(!crate::store::snapshot_store::tests::observed_stream_read(
                &reads
            ));
        }
    }
    #[test]
    fn disk_baselines_cover_root_and_each_managed_writable_data_attachment() {
        use crate::machine::root_storage::{launch_disk_seeds, seed_disk};
        use std::os::unix::fs::FileExt;
        let temporary = tempfile::tempdir().unwrap();
        let directory =
            crate::paths::OwnedDirectory::open_root(&temporary.path().join("machine")).unwrap();
        let mut record = MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        for (index, name) in ["root.raw", "data-a.raw", "data-b.raw"]
            .into_iter()
            .enumerate()
        {
            directory.write_file(name, &[index as u8 + 1; 512]).unwrap();
            let role = if index == 0 {
                DiskRole::Root
            } else {
                DiskRole::Data
            };
            let disk = disk(name, role, 512, format!("disk-{index}")).unwrap();
            if index != 0 {
                record.disks.push(crate::IncludedDisk {
                    id: uuid::Uuid::new_v4(),
                    role,
                    order: index as u32,
                    storage: crate::DiskStorage::ManagedWritable {
                        path: PrivatePath::new(name).unwrap(),
                        geometry: disk.geometry,
                    },
                });
            }
            let file = std::fs::File::open(directory.path().join(name)).unwrap();
            let map = crate::storage::stream::StreamHasher::new()
                .hash_open_file(&file, 512)
                .unwrap()
                .map;
            seed_disk(&mut record, directory.path(), index, &disk, &file, &map).unwrap();
        }
        record.validate().unwrap();
        let seeds = launch_disk_seeds(&record, directory.path()).unwrap();
        assert_eq!(
            seeds
                .iter()
                .map(|seed| seed.attachment_index)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(
            seeds
                .iter()
                .map(|seed| &seed.epoch)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        std::fs::File::options()
            .write(true)
            .open(directory.path().join("data-a.raw"))
            .unwrap()
            .write_all_at(b"host edit", 0)
            .unwrap();
        let seeds = launch_disk_seeds(&record, directory.path()).unwrap();
        assert_eq!(
            seeds
                .iter()
                .map(|seed| seed.attachment_index)
                .collect::<Vec<_>>(),
            [0, 2]
        );
    }
    #[test]
    fn retained_disk_baseline_reuses_only_an_immutable_owned_map() {
        use crate::machine::root_storage::retain_disk_map;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let temporary = tempfile::tempdir().unwrap();
        let directory =
            crate::paths::OwnedDirectory::open_root(&temporary.path().join("machine")).unwrap();
        directory.write_file("root.raw", &[0x41; 512]).unwrap();
        let map = crate::storage::stream::StreamHasher::new()
            .hash_file(&directory.path().join("root.raw"))
            .unwrap();
        let retained = retain_disk_map(directory.path(), &map).unwrap();
        let path = directory.path().join(retained.as_path());
        let before = std::fs::metadata(&path).unwrap();
        assert_eq!(before.mode() & 0o7777, 0o400);
        assert_eq!(retain_disk_map(directory.path(), &map).unwrap(), retained);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), before.ino());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(retain_disk_map(directory.path(), &map).is_err());
    }
}
