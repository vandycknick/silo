use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use vm_spec::{BlockId, Disk, DiskFormat, DiskGeometry, DiskRole};

use crate::storage::pool::StoragePool;
use crate::{
    LibVmError, MachineRoot, MachineStorageRecord, OverlayLower, TemporaryDirectoryPolicy,
};

pub(crate) struct PreparedRoot {
    pub(crate) disks: Vec<Disk>,
    pub(crate) bootstrap: Vec<u8>,
    pub(crate) descriptor: Option<String>,
    pub(crate) qualification: Option<crate::QualifiedOverlayBoot>,
    pub(crate) storage: MachineStorageRecord,
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
    let MachineRoot::LinuxOverlay {
        lower: OverlayLower::FlatExt4 { geometry, .. },
        upper,
        capacity,
        ..
    } = &storage.root
    else {
        return Ok(());
    };
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
        .ok_or_else(|| invalid("overlay requires qualified direct kernel boot"))?;
    let marker = "silo.rootfs=linux-flat-overlay-v1";
    if args.iter().filter(|arg| arg.as_str() == marker).count() != 1
        || args.iter().any(|arg| {
            ["root=", "rootfstype=", "rootflags="]
                .iter()
                .any(|prefix| arg.starts_with(prefix))
                || (arg.starts_with("silo.rootfs=") && arg != marker)
        })
    {
        return Err(invalid(
            "overlay requires its exact root marker without conflicting root-selection arguments",
        ));
    }
    Ok(())
}

pub(crate) fn filesystem_uuid(path: &Path) -> Result<uuid::Uuid, LibVmError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)?;
    let mut superblock = [0u8; 120];
    file.read_exact_at(&mut superblock, 1024)?;
    if superblock[56..58] != [0x53, 0xef] {
        return Err(invalid("flat lower is not ext4"));
    }
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&superblock[104..120]);
    let uuid = uuid::Uuid::from_bytes(bytes);
    if uuid.is_nil() {
        return Err(invalid("flat lower has zero filesystem UUID"));
    }
    Ok(uuid)
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
    data_disks: u64,
    qualification: Option<crate::QualifiedOverlayBoot>,
) -> Result<PreparedRoot, LibVmError> {
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
                rootfs_spec::Root::Raw,
            )
        }
        MachineRoot::LinuxOverlay {
            lower:
                OverlayLower::FlatExt4 {
                    stream,
                    geometry,
                    filesystem_uuid: lower_uuid,
                },
            upper,
            upper_uuid,
            capacity,
            temporary_directory,
            ..
        } => {
            let qualification = qualification
                .as_ref()
                .ok_or_else(|| invalid("flat overlay boot was not qualified"))?;
            let pool = StoragePool::open_existing(images_dir)?
                .ok_or_else(|| invalid("immutable lower pool is missing"))?;
            let occurrence = pool.lower_occurrence(stream)?;
            if occurrence.length() != geometry.length {
                return Err(invalid(
                    "retained lower length differs from semantic geometry",
                ));
            }
            let occurrences = [occurrence];
            let plan = crate::storage::vmdk::FlatLowerPlan::new(&occurrences)?;
            let admitted = plan.preflight(data_disks)?;
            admitted.verify(&pool)?;
            if filesystem_uuid(occurrences[0].path())? != *lower_uuid {
                return Err(invalid(
                    "retained lower filesystem UUID differs from semantic identity",
                ));
            }
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
                    *lower_uuid,
                )?,
                upper: expectation(
                    rootfs_spec::RootSerial::Upper,
                    *capacity,
                    false,
                    *upper_uuid,
                )?,
                upper_profile: rootfs_spec::UpperProfile::SiloUpperExt4V1,
                overlay_profile: rootfs_spec::OverlayProfile::SiloOverlayV1,
                rendering_abi: qualification.rendering_abi(),
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
                rootfs_spec::Root::FlatOverlay(root),
            )
        }
        _ => return Err(invalid("root family has not passed the launch gate")),
    };
    let mut bootstrap = vec![0; rootfs_spec::MAX_JSON_BYTES];
    let count = rootfs_spec::encode_bootstrap(&rootfs_spec::Bootstrap { root }, &mut bootstrap)
        .map_err(|e| invalid(e.to_string()))?;
    bootstrap.truncate(count);
    Ok(PreparedRoot {
        disks,
        bootstrap,
        descriptor,
        qualification,
        storage: storage.clone(),
    })
}

pub(crate) fn publish_descriptor(machine_dir: &Path, descriptor: &str) -> Result<(), LibVmError> {
    let directory = crate::paths::OwnedDirectory::open_existing_root(machine_dir)?
        .ok_or_else(|| invalid("machine directory disappeared before descriptor publication"))?;
    let name = format!(".lower-{}.tmp", uuid::Uuid::new_v4().simple());
    let path = machine_dir.join(&name);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(descriptor.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&path, machine_dir.join("lower.vmdk"))?;
        directory.sync()?;
        Ok::<_, LibVmError>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

pub(crate) fn publish_kernel(
    machine_dir: &Path,
    kernel: &crate::boot_qualification::QualifiedAsset,
) -> Result<std::path::PathBuf, LibVmError> {
    let directory = crate::paths::OwnedDirectory::open_existing_root(machine_dir)?
        .ok_or_else(|| invalid("machine directory disappeared before kernel publication"))?;
    let temporary = machine_dir.join(format!(".kernel-{}.tmp", uuid::Uuid::new_v4().simple()));
    let destination = machine_dir.join("kernel-qualified");
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        kernel.copy_into(&mut file)?;
        file.sync_all()?;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        std::fs::rename(&temporary, &destination)?;
        directory.sync()?;
        Ok::<_, LibVmError>(destination)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
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
        let stream = crate::storage::stream::StreamHasher::new()
            .hash_reader([0u8; 512].as_slice())
            .unwrap()
            .id();
        storage.root = MachineRoot::LinuxOverlay {
            lower: OverlayLower::FlatExt4 {
                stream,
                geometry: vm_spec::DiskGeometry {
                    length: 512,
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
                    512,
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
                cmdline: vec!["silo.rootfs=linux-flat-overlay-v1".into()],
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
            "silo.rootfs=other",
            "silo.rootfs=linux-flat-overlay-v1",
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
        let mut imported = valid.clone();
        imported.storage.as_mut().unwrap().disks[0].path = "/external/arbitrary.vmdk".into();
        assert!(validate_spec(&storage, &imported).is_err());
        let mut changed_upper = valid.clone();
        changed_upper.storage.as_mut().unwrap().disks[1]
            .geometry
            .length += 4096;
        assert!(validate_spec(&storage, &changed_upper).is_err());
    }

    #[test]
    fn vmdk_unqualified_root_fails_before_pool_or_private_file_access() {
        let temp = tempfile::tempdir().unwrap();
        let error = match prepare(
            &storage(),
            temp.path(),
            &temp.path().join("missing-pool"),
            0,
            None,
        ) {
            Ok(_) => panic!("unqualified root unexpectedly prepared"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            crate::LibVmError::InvalidStorageRecord { .. }
        ));
        assert!(std::fs::read_dir(temp.path()).unwrap().next().is_none());
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
            0,
            None,
        )
        .unwrap();
        assert!(root.descriptor.is_none());
        assert_eq!(root.disks[0].role, DiskRole::Root);
        assert_eq!(root.disks[0].geometry.length, 512);
        assert_eq!(
            rootfs_spec::decode_bootstrap(&root.bootstrap).unwrap().root,
            rootfs_spec::Root::Raw
        );
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
}
