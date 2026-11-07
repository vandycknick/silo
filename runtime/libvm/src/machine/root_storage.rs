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
    pub(crate) rosetta: rootfs_spec::RosettaMode,
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
    // The token checks above already refused selectors and conflicting
    // markers; the builder-emitted marker must also be a whole argument.
    if !args
        .iter()
        .any(|arg| arg.as_str() == "silo.rootfs=linux-flat-overlay-v1")
    {
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
    // The kernel command line is a C string; a NUL would silently cut it.
    if args.iter().any(|arg| arg.contains('\0')) {
        return Err(invalid("kernel arguments cannot contain NUL bytes"));
    }
    let cmdline = args.join(" ");
    let mut markers = 0;
    for param in rootfs_spec::kernel_cmdline::params(cmdline.as_bytes()) {
        match param.reserved() {
            Some(rootfs_spec::kernel_cmdline::Reserved::RootSelection) => {
                return Err(invalid(
                    "root-selection kernel arguments are reserved for the trusted bootstrap",
                ));
            }
            Some(rootfs_spec::kernel_cmdline::Reserved::InitialExecutable) => {
                return Err(invalid(
                    "rdinit= is reserved; the trusted /init is the initial executable",
                ));
            }
            None => {}
        }
        let Some(value) = param.value else {
            continue;
        };
        if param.is(b"silo.rootfs") {
            if !overlay || value != b"linux-flat-overlay-v1" {
                return Err(invalid(
                    "root profile marker conflicts with the persisted root",
                ));
            }
            markers += 1;
        }
    }
    if overlay && markers != 1 {
        return Err(invalid("overlay requires exactly one root profile marker"));
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
            "\"root=/dev/vda\"",
            "rdinit=/agent/silo-agent",
            "\"rdinit=/agent/silo-agent\"",
            "rdinit=\"/agent/silo-agent\"",
            "silo.rootfs=other",
            "silo.rootfs=linux-flat-overlay-v1",
            "\"silo.rootfs=linux-flat-overlay-v1\"",
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
            .cmdline = vec!["silo.rootfs=linux-flat-overlay-v1 quiet".into()];
        assert!(validate_spec(&storage, &embedded_marker).is_err());
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
            rootfs_spec::RosettaMode::Disabled,
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
}
