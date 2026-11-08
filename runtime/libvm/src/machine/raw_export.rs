//! Explicit, read-only stopped root export. Staging and both publication links
//! stay owned by this operation until the disk, report and directory are durable.
use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{fstatat, Mode};
use nix::unistd::{linkat, unlinkat, UnlinkatFlags};
use serde::{Serialize, Serializer};

use crate::machine::stopped::{admit_stopped, ExternalResourcePolicy, StoppedAdmission};
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::pool::StoragePool;
use crate::storage::stream::StreamHasher;
use crate::store::layer_store::LayerStore;
use crate::{BootProfile, LibVmError, Machine, MachineRoot};

#[derive(Debug, Clone)]
pub struct RawDiskExportOptions {
    pub destination: PathBuf,
    pub flatten_filesystem: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawDiskExport {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    #[serde(serialize_with = "serialize_path")]
    pub metadata_path: PathBuf,
    pub geometry: vm_spec::DiskGeometry,
    pub boot: BootProfile,
    pub kind: RawDiskExportKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum RawDiskExportKind {
    OpaqueExact,
    FlattenedFilesystem { filesystem_uuid: uuid::Uuid },
}

fn serialize_path<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    path.as_os_str().as_bytes().serialize(serializer)
}

fn unsupported(reason: impl ToString) -> LibVmError {
    LibVmError::RawExportUnsupported {
        reason: reason.to_string(),
    }
}

fn flatten_error(error: oci::overlay_flatten::FlattenError) -> LibVmError {
    use oci::overlay_flatten::FlattenError;
    match error {
        FlattenError::RecoveryRequired(error) => LibVmError::RawExportRecoveryRequired {
            reason: error.to_string(),
        },
        FlattenError::Io(error) => error.into(),
        other => unsupported(format!("{other}: {other:?}")),
    }
}

struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), LibVmError> {
    if cancel.load(Ordering::Acquire) {
        return Err(
            std::io::Error::new(std::io::ErrorKind::Interrupted, "raw export cancelled").into(),
        );
    }
    Ok(())
}

impl Machine {
    /// Export only the root disk. No source is started, stopped, repaired or
    /// snapshotted. Additional disks and shares are not part of this report.
    pub async fn export_raw_disk(
        &self,
        options: RawDiskExportOptions,
    ) -> Result<RawDiskExport, LibVmError> {
        let runtime = self.runtime().clone();
        let id = self.machine_id();
        let handle = tokio::runtime::Handle::current();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancellation = CancelOnDrop(cancel.clone());
        let result = tokio::task::spawn_blocking(move || {
            handle.block_on(async {
                let source = admit_stopped(
                    &runtime,
                    id,
                    &ExternalResourcePolicy::RequireMappings,
                    StoppedAdmission::RawExport,
                )
                .await?;
                if matches!(source.storage.root, MachineRoot::LinuxOverlay { .. })
                    && !options.flatten_filesystem
                {
                    return Err(unsupported("overlay roots require flatten_filesystem"));
                }
                if !matches!(source.storage.boot, BootProfile::LinuxDirect { .. }) {
                    return Err(unsupported(
                        "raw export requires Linux direct boot, never EFI",
                    ));
                }
                let output = ExportOutput::prepare(&options.destination, runtime.local_home())?;
                let root = source
                    .files
                    .first()
                    .ok_or_else(|| unsupported("source root descriptor is missing"))?;
                let before = SourceFingerprint::new(&root.file.metadata()?);
                // Recovery is authoritative even when the retained lower is missing.
                if matches!(source.storage.root, MachineRoot::LinuxOverlay { .. }) {
                    disk_image::ext4::Reader::from_file(root.file.try_clone()?)
                        .map_err(|error| flatten_error(error.into()))?;
                }
                let layers = LayerStore::from_store(runtime.native_store()?);
                let held = match &source.storage.root {
                    MachineRoot::LinuxOverlay { lower, .. } => {
                        let held = layers.hold_composition(lower.record()).await?;
                        held.retained().check_lower(lower)?;
                        crate::machine::root_storage::check_lower_platform(
                            &held.retained().recipe.platform,
                            &source.storage.boot,
                        )?;
                        Some(held)
                    }
                    MachineRoot::OpaqueRaw { .. } => None,
                };
                let store = runtime.native_store()?;
                let pool = StoragePool::open(runtime.local_images_dir())?;
                let dependencies =
                    crate::store::cache_paths::storage_pool_dependencies(&source.storage)?;
                let streams = dependencies.streams.into_iter().collect::<Vec<_>>();
                let objects = dependencies.objects.into_iter().collect::<Vec<_>>();
                let (operation, lease) = store
                    .begin_stopped_operation("raw-export", &streams, &objects)
                    .await?;
                let result = async {
                    store
                        .pin_operation_lowers(
                            operation,
                            &dependencies.lowers.into_iter().collect::<Vec<_>>(),
                        )
                        .await?;
                    let mut boot = crate::runtime::boot_assets::capture_export_boot(
                        &source.storage,
                        &source.config.spec,
                        &source.config.guest.agent,
                        runtime.captured_boot_context(&pool, &store, operation),
                    )
                    .await?;
                    check_cancel(&cancel)?;
                    let (geometry, kind) = match &source.storage.root {
                        MachineRoot::OpaqueRaw { geometry, .. } => {
                            let file = output.create_disk()?;
                            StreamHasher::new().copy_file_and_hash(
                                &root.file,
                                root.length,
                                &file,
                            )?;
                            file.sync_all()?;
                            (*geometry, RawDiskExportKind::OpaqueExact)
                        }
                        MachineRoot::LinuxOverlay { capacity, .. } => {
                            let held = held
                                .as_ref()
                                .ok_or_else(|| unsupported("held lower is missing"))?;
                            let occurrences = held.layers();
                            let flattened = oci::overlay_flatten::flatten_overlay(
                                oci::overlay_flatten::FlattenLower {
                                    recipe: &held.retained().recipe,
                                    result: &held.retained().result,
                                    layers: &occurrences,
                                    fsmeta: held.fsmeta(),
                                },
                                root.file.try_clone()?,
                                &output.disk_path(),
                                *capacity,
                                &cancel,
                            )
                            .map_err(flatten_error)?;
                            let BootProfile::LinuxDirect {
                                root_selector,
                                root_filesystem,
                                ..
                            } = &mut boot
                            else {
                                return Err(unsupported(
                                    "flattened output requires Linux direct boot",
                                ));
                            };
                            *root_selector = crate::RootSelector::WholeDisk;
                            *root_filesystem = crate::RootFilesystem::Ext4;
                            (
                                vm_spec::DiskGeometry {
                                    length: flattened.length,
                                    logical_sector_size: 512,
                                },
                                RawDiskExportKind::FlattenedFilesystem {
                                    filesystem_uuid: uuid::Uuid::from_bytes(flattened.uuid),
                                },
                            )
                        }
                    };
                    if before != SourceFingerprint::new(&root.file.metadata()?) {
                        return Err(unsupported("source changed during raw export"));
                    }
                    check_cancel(&cancel)?;
                    let report = RawDiskExport {
                        path: options.destination.clone(),
                        metadata_path: sidecar_path(&options.destination),
                        geometry,
                        boot,
                        kind,
                    };
                    let bytes =
                        serde_json::to_vec_pretty(&report).map_err(std::io::Error::other)?;
                    Ok((report, bytes))
                }
                .await;
                let finished = store.finish_stopped_operation(operation).await;
                let result = match result {
                    Err(error) => Err(error),
                    Ok((report, bytes)) => {
                        finished?;
                        output.publish(&bytes, &cancel)?;
                        Ok(report)
                    }
                };
                drop(lease);
                result
            })
        })
        .await?;
        drop(cancellation);
        result
    }
}

fn sidecar_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".json");
    name.into()
}

/// The directory FD makes publication/rollback independent of pathname aliases.
/// Both final entries use linkat without replacement; an existing dangling
/// symlink is a collision too. Only links to our staged inodes are rolled back.
struct ExportOutput {
    parent: File,
    parent_path: PathBuf,
    requested_parent: PathBuf,
    name: OsString,
    metadata_name: OsString,
    stage_name: String,
    stage: File,
}

impl ExportOutput {
    fn prepare(destination: &Path, home: &Path) -> Result<Self, LibVmError> {
        let name = destination
            .file_name()
            .ok_or_else(|| unsupported("destination must name a fresh file"))?
            .to_os_string();
        if destination
            .as_os_str()
            .as_bytes()
            .rsplit(|byte| *byte == b'/')
            .next()
            != Some(name.as_os_str().as_bytes())
        {
            return Err(unsupported(
                "destination must end in a file name, not a directory selector",
            ));
        }
        let requested_parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let parent_path = std::fs::canonicalize(&requested_parent)?;
        let home = std::fs::canonicalize(home)?;
        if parent_path.starts_with(home) {
            return Err(unsupported(
                "export destination must be outside the runtime state root",
            ));
        }
        let parent = File::from(
            nix::fcntl::open(
                &parent_path,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
        let mut metadata_name = name.clone();
        metadata_name.push(".json");
        for entry in [&name, &metadata_name] {
            match fstatat(&parent, entry.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
                Err(nix::errno::Errno::ENOENT) => {}
                Err(error) => return Err(std::io::Error::from(error).into()),
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "raw export disk or sidecar already exists",
                    )
                    .into())
                }
            }
        }
        let stage_name = format!(".silo-raw-export-{}", uuid::Uuid::new_v4());
        // Private staging is on the output filesystem for atomic, no-replace links.
        nix::sys::stat::mkdirat(&parent, stage_name.as_str(), Mode::S_IRWXU)
            .map_err(std::io::Error::from)?;
        let stage = match nix::fcntl::openat(
            &parent,
            stage_name.as_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(error) => {
                let _ = unlinkat(&parent, stage_name.as_str(), UnlinkatFlags::RemoveDir);
                return Err(std::io::Error::from(error).into());
            }
        };
        Ok(Self {
            parent,
            parent_path,
            requested_parent,
            name,
            metadata_name,
            stage_name,
            stage,
        })
    }

    fn disk_path(&self) -> PathBuf {
        self.parent_path.join(&self.stage_name).join("disk")
    }

    fn create_disk(&self) -> Result<File, LibVmError> {
        Ok(File::from(
            nix::fcntl::openat(
                &self.stage,
                "disk",
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map_err(std::io::Error::from)?,
        ))
    }

    fn publish(&self, bytes: &[u8], cancel: &AtomicBool) -> Result<(), LibVmError> {
        let disk = File::from(
            nix::fcntl::openat(
                &self.stage,
                "disk",
                OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
        disk.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        disk.sync_all()?;
        let mut metadata = File::from(
            nix::fcntl::openat(
                &self.stage,
                "report",
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map_err(std::io::Error::from)?,
        );
        metadata.write_all(bytes)?;
        metadata.sync_all()?;
        self.stage.sync_all()?;
        check_cancel(cancel)?;
        let current_parent = File::open(&self.parent_path)?.metadata()?;
        let parent = self.parent.metadata()?;
        if (current_parent.dev(), current_parent.ino()) != (parent.dev(), parent.ino()) {
            return Err(unsupported("destination parent changed during export"));
        }
        let requested_parent = File::open(&self.requested_parent)?.metadata()?;
        if (requested_parent.dev(), requested_parent.ino()) != (parent.dev(), parent.ino()) {
            return Err(unsupported(
                "destination parent alias changed during export",
            ));
        }
        linkat(
            &self.stage,
            "disk",
            &self.parent,
            self.name.as_os_str(),
            AtFlags::empty(),
        )
        .map_err(std::io::Error::from)?;
        let result = (|| {
            linkat(
                &self.stage,
                "report",
                &self.parent,
                self.metadata_name.as_os_str(),
                AtFlags::empty(),
            )
            .map_err(std::io::Error::from)?;
            check_cancel(cancel)?;
            self.parent.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            self.remove_owned(&self.name, &disk);
            self.remove_owned(&self.metadata_name, &metadata);
            let _ = self.parent.sync_all();
        }
        result
    }

    fn remove_owned(&self, name: &OsString, file: &File) {
        if let (Ok(entry), Ok(held)) = (
            fstatat(&self.parent, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW),
            nix::sys::stat::fstat(file),
        ) {
            if (entry.st_dev, entry.st_ino) == (held.st_dev, held.st_ino) {
                let _ = unlinkat(&self.parent, name.as_os_str(), UnlinkatFlags::NoRemoveDir);
            }
        }
    }
}

impl Drop for ExportOutput {
    fn drop(&mut self) {
        for name in ["disk", "report"] {
            let _ = unlinkat(&self.stage, name, UnlinkatFlags::NoRemoveDir);
        }
        let _ = unlinkat(
            &self.parent,
            self.stage_name.as_str(),
            UnlinkatFlags::RemoveDir,
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::ffi::OsString;
    use std::fs::{File, OpenOptions};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{FileExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;

    use crate::machine::raw_export::{ExportOutput, RawDiskExportKind, RawDiskExportOptions};
    use crate::store::layer_store::LayerStore;
    use crate::{BootProfile, LibVmError, Machine, Runtime};
    use disk_image::ext4::constants::file_mode;
    use disk_image::ext4::{FileData, Formatter, Reader};

    struct Fixture {
        files: tempfile::TempDir,
        _run: tempfile::TempDir,
        runtime: Runtime,
        machine: Machine,
        root: PathBuf,
    }

    impl Fixture {
        async fn new() -> Self {
            let files = tempfile::tempdir().unwrap();
            let run = tempfile::Builder::new()
                .prefix("rawex-")
                .tempdir_in("/tmp")
                .unwrap();
            std::fs::set_permissions(run.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let kernel = files.path().join("kernel");
            let initramfs = files.path().join("initramfs");
            let agent = files.path().join("agent");
            std::fs::write(
                &kernel,
                test_utils::direct_kernel::host_kernel("raw-export kernel bytes"),
            )
            .unwrap();
            std::fs::write(&initramfs, b"raw-export initramfs bytes").unwrap();
            std::fs::write(&agent, b"raw-export agent bytes").unwrap();
            for path in [&kernel, &initramfs] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o700)).unwrap();
            let executable = test_utils::mock_vmm_binary().to_path_buf();
            let components = crate::ResolvedRuntimeComponents::from_paths(
                executable.clone(),
                executable,
                kernel,
                initramfs,
                agent,
                files.path().to_owned(),
            )
            .unwrap();
            let config =
                crate::RuntimeConfig::local(files.path().join("home")).with_run_root(run.path());
            let paths = crate::paths::LocalPaths::from_roots(config.resolve_roots().unwrap());
            let store = crate::store::Store::new(&paths).await.unwrap();
            let runtime = Runtime::from_store(
                paths,
                std::sync::Arc::new(store),
                crate::RuntimeNetworkingConfig::default(),
                crate::RegistryPolicy::default(),
                components,
                None,
            )
            .await
            .unwrap();
            let input = files.path().join("input.raw");
            Formatter::new(&input, 4096, 16 << 20)
                .unwrap()
                .close()
                .unwrap();
            let machine = runtime
                .machine()
                .name("export-source")
                .image_source(crate::ImageSource::disk(input))
                .network(|network| network.none())
                .create()
                .await
                .unwrap();
            let root = runtime
                .local_home()
                .join("machines")
                .join(machine.id())
                .join("root.raw");
            Self {
                files,
                _run: run,
                runtime,
                machine,
                root,
            }
        }

        fn destination(&self, name: &str) -> PathBuf {
            self.files.path().join(name)
        }

        async fn overlay(&mut self, unknown_control: bool) {
            let store = self.runtime.native_store().unwrap();
            let layers = LayerStore::from_store(store.clone());
            // Real tar -> admitted changeset -> catalog pack/index -> exact EROFS.
            let mut header = [0u8; 512];
            header[..5].copy_from_slice(b"lower");
            header[100..108].copy_from_slice(b"0000644\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            header[124..136].copy_from_slice(b"00000000001\0");
            header[136..148].copy_from_slice(b"00000000000\0");
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
            header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            let mut tar = header.to_vec();
            tar.push(b'L');
            tar.resize(2048, 0);
            let tar_path = self.destination("lower.tar");
            std::fs::write(&tar_path, &tar).unwrap();
            let digest = oci::changeset::ContentDigest::of_bytes(&tar);
            let limits = oci::changeset::ChangesetLimits::default();
            let staged = oci::changeset::ingest_layer(
                &tar_path,
                &oci::changeset::LayerInput {
                    blob_digest: digest,
                    media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                    size_bytes: tar.len() as u64,
                    diff_id: digest,
                },
                self.runtime.local_images_dir(),
                &oci::StagingOperation::try_from(uuid::Uuid::new_v4().to_string()).unwrap(),
                &limits,
            )
            .unwrap();
            let layer = layers.publish(staged, &limits).await.unwrap();
            let mut storage = self
                .runtime
                .machine_storage_record(self.machine.machine_id())
                .await
                .unwrap();
            let BootProfile::LinuxDirect {
                userspace_platform, ..
            } = &storage.boot
            else {
                panic!("direct fixture")
            };
            let platform = oci::Platform {
                os: "linux".into(),
                architecture: match userspace_platform.architecture {
                    crate::GuestArchitecture::Amd64 => "amd64",
                    crate::GuestArchitecture::Arm64 => "arm64",
                }
                .into(),
                variant: userspace_platform.variant.clone(),
            };
            let lower = layers
                .compose_retained(platform, &[layer.id], &limits)
                .await
                .unwrap();
            let upper = self.root.with_file_name("upper.raw");
            let capacity = 64 << 20;
            let mut formatter = Formatter::new_upper(
                &upper,
                rootfs_spec::upper_geometry::UpperCapacity::new(capacity).unwrap(),
            )
            .unwrap();
            formatter
                .create(
                    "/upper",
                    file_mode::S_IFDIR | 0o755,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();
            formatter
                .create(
                    "/work",
                    file_mode::S_IFDIR | 0o700,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();
            let attributes: &[(&[u8], &[u8])] = if unknown_control {
                &[(b"trusted.overlay.unknown", b"x")]
            } else {
                &[(b"user.export", b"preserved")]
            };
            let mut body = &b"upper exact bytes\0\xff"[..];
            formatter
                .create(
                    "/upper/upper-file",
                    file_mode::S_IFREG | 0o640,
                    None,
                    None,
                    Some(FileData::Dense(&mut body)),
                    Some(123),
                    Some(456),
                    Some(attributes),
                    None,
                )
                .unwrap();
            formatter.link("/upper/alias", "/upper/upper-file").unwrap();
            formatter.close().unwrap();
            std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(0o600)).unwrap();
            let upper_uuid = uuid::Uuid::from_bytes(
                disk_image::ext4::read_superblock(&File::open(&upper).unwrap())
                    .unwrap()
                    .uuid,
            );
            let mut root_nid_bytes = [0; 2];
            lower
                .fsmeta()
                .read_exact_at(&mut root_nid_bytes, 1024 + 14)
                .unwrap();
            let root_nid = u64::from(u16::from_le_bytes(root_nid_bytes));
            // Kernel-shaped indexed mount provenance, written independently
            // through libext2fs rather than bypassing the flattener's checks.
            let mut origin = vec![0, 0xfb, 33, 0, 0x81];
            origin.extend_from_slice(&lower.retained().result.fsmeta.uuid);
            origin.extend_from_slice(&((root_nid >> 32) as u32).to_le_bytes());
            origin.extend_from_slice(&(root_nid as u32).to_le_bytes());
            origin.extend_from_slice(&0_u32.to_le_bytes());
            let reader = Reader::new(&upper).unwrap();
            let upper_inode = reader
                .lookup(disk_image::ext4::constants::ROOT_INODE, b"upper")
                .unwrap()
                .unwrap();
            let mut bound = vec![0, 0xfb, 29, 1 << 2, 1];
            bound.extend_from_slice(upper_uuid.as_bytes());
            bound.extend_from_slice(&upper_inode.to_le_bytes());
            bound.extend_from_slice(
                &reader
                    .metadata(upper_inode)
                    .unwrap()
                    .generation
                    .to_le_bytes(),
            );
            drop(reader);
            let origin_path = self.destination("origin.bin");
            let bound_path = self.destination("bound.bin");
            std::fs::write(&origin_path, origin).unwrap();
            std::fs::write(&bound_path, bound).unwrap();
            let commands = self.destination("index.debugfs");
            std::fs::write(
                &commands,
                format!(
                    "mkdir /work/work\nmkdir /work/index\nea_set -f {} /upper trusted.overlay.origin\nea_set -f {} /work/index trusted.overlay.upper\n",
                    origin_path.display(),
                    bound_path.display(),
                ),
            )
            .unwrap();
            let output = std::process::Command::new("debugfs")
                .args(["-w", "-f"])
                .arg(commands)
                .arg(&upper)
                .output()
                .expect("raw export fixtures require e2fsprogs debugfs");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            storage.root = crate::MachineRoot::LinuxOverlay {
                lower: lower.retained().overlay_lower(),
                upper: crate::PrivatePath::new("upper.raw").unwrap(),
                upper_uuid,
                capacity,
                ext4_profile: crate::Ext4Profile::SiloUpperExt4V1,
                overlay_profile: crate::OverlayProfile::SiloOverlayV1,
                temporary_directory: crate::TemporaryDirectoryPolicy::DiskBacked,
            };
            storage.profile = crate::StorageProfile::LinuxOverlayV1;
            storage.backend = crate::BackendRequirement::KrunOverlay;
            if let BootProfile::LinuxDirect { root_selector, .. } = &mut storage.boot {
                *root_selector = crate::RootSelector::ManagedOverlay;
            }
            let (_lock, mut config) = self
                .runtime
                .lock_machine_config(self.machine.machine_id())
                .await
                .unwrap();
            let spec_disks = &mut config.spec.storage.as_mut().unwrap().disks;
            *spec_disks = vec![
                crate::machine::root_storage::disk(
                    "lower.vmdk",
                    vm_spec::DiskRole::RootLower,
                    lower.retained().geometry().length,
                    "silo-root-lower".into(),
                )
                .unwrap(),
                crate::machine::root_storage::disk(
                    "upper.raw",
                    vm_spec::DiskRole::RootUpper,
                    capacity,
                    "silo-root-upper".into(),
                )
                .unwrap(),
            ];
            config
                .spec
                .boot
                .as_mut()
                .unwrap()
                .kernel
                .as_mut()
                .unwrap()
                .cmdline
                .push("silo.rootfs=linux-erofs-overlay-v1".into());
            let mut tx = store.test_pool().begin().await.unwrap();
            crate::store::Store::write_machine_storage(
                &mut tx,
                self.machine.machine_id(),
                &storage,
            )
            .await
            .unwrap();
            sqlx::query("UPDATE machine_config SET config_json=jsonb(json_set(config_json,'$.spec',json(?2))) WHERE id=?1")
                .bind(self.machine.id()).bind(serde_json::to_string(&config.spec).unwrap()).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
            self.root = upper;
        }
    }

    fn source_identity(
        path: &Path,
    ) -> (
        crate::storage::identity_file::SourceFingerprint,
        crate::storage::identity::StreamId,
    ) {
        let file = File::open(path).unwrap();
        (
            crate::storage::identity_file::SourceFingerprint::new(&file.metadata().unwrap()),
            crate::storage::stream::StreamHasher::new()
                .hash_file(path)
                .unwrap()
                .id(),
        )
    }

    fn make_dirty(path: &Path) {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut features = [0u8; 4];
        file.read_exact_at(&mut features, 1024 + 96).unwrap();
        file.write_all_at(&(u32::from_le_bytes(features) | 4).to_le_bytes(), 1024 + 96)
            .unwrap();
        file.sync_all().unwrap();
    }

    #[tokio::test]
    async fn opaque_dirty_exact_non_utf8_report_and_no_overwrite() {
        let fixture = Fixture::new().await;
        make_dirty(&fixture.root);
        let before = source_identity(&fixture.root);
        let path = fixture
            .files
            .path()
            .join(OsString::from_vec(b"export-\xff.raw".to_vec()));
        let options = RawDiskExportOptions {
            destination: path.clone(),
            flatten_filesystem: false,
        };
        let report = fixture
            .machine
            .export_raw_disk(options.clone())
            .await
            .unwrap();
        assert_eq!(report.kind, RawDiskExportKind::OpaqueExact);
        assert_eq!(source_identity(&fixture.root), before);
        assert_eq!(source_identity(&path).1, before.1);
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report.metadata_path).unwrap()).unwrap();
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(json["path"], serde_json::json!(path.as_os_str().as_bytes()));
        assert_eq!(
            json["metadataPath"],
            serde_json::json!(report.metadata_path.as_os_str().as_bytes())
        );
        assert_eq!(json["kind"]["kind"], "opaque-exact");
        assert!(fixture.machine.export_raw_disk(options).await.is_err());
        assert_eq!(source_identity(&path).1, before.1);
        let sidecar_collision = fixture.destination("sidecar-collision.raw");
        std::fs::write(
            crate::machine::raw_export::sidecar_path(&sidecar_collision),
            b"keep",
        )
        .unwrap();
        assert!(fixture
            .machine
            .export_raw_disk(RawDiskExportOptions {
                destination: sidecar_collision.clone(),
                flatten_filesystem: false,
            })
            .await
            .is_err());
        assert!(!sidecar_collision.exists());
        assert_eq!(source_identity(&fixture.root), before);
    }

    #[tokio::test]
    async fn overlay_flatten_preserves_data_aliases_and_pinned_boot_with_new_identity() {
        let mut fixture = Fixture::new().await;
        fixture.overlay(false).await;
        let before = source_identity(&fixture.root);
        let storage = fixture
            .runtime
            .machine_storage_record(fixture.machine.machine_id())
            .await
            .unwrap();
        let report = fixture
            .machine
            .export_raw_disk(RawDiskExportOptions {
                destination: fixture.destination("flattened.raw"),
                flatten_filesystem: true,
            })
            .await
            .unwrap();
        let RawDiskExportKind::FlattenedFilesystem { filesystem_uuid } = report.kind else {
            panic!("flattened report")
        };
        let reader = Reader::new(&report.path).unwrap();
        reader.audit().unwrap();
        assert_eq!(reader.uuid(), *filesystem_uuid.as_bytes());
        let crate::MachineRoot::LinuxOverlay { upper_uuid, .. } = storage.root else {
            panic!("overlay fixture")
        };
        assert_ne!(filesystem_uuid, upper_uuid);
        assert_eq!(reader.read_file(b"/lower", 0, Some(1)).unwrap(), b"L");
        assert_eq!(
            reader.read_file(b"/upper-file", 0, Some(19)).unwrap(),
            b"upper exact bytes\0\xff"
        );
        let root = reader
            .read_dir(disk_image::ext4::constants::ROOT_INODE)
            .unwrap();
        assert_eq!(root.lookup(b"upper-file"), root.lookup(b"alias"));
        assert!(root.lookup(b"upper").is_none());
        assert!(root.lookup(b"work").is_none());
        let inode = reader
            .metadata(root.lookup(b"upper-file").unwrap())
            .unwrap();
        assert_eq!((inode.uid, inode.gid, inode.permissions), (123, 456, 0o640));
        assert_eq!(
            reader
                .xattrs(b"/upper-file")
                .unwrap()
                .get(b"user.export".as_slice())
                .unwrap(),
            b"preserved"
        );
        assert_eq!(source_identity(&fixture.root), before);
        let BootProfile::LinuxDirect {
            binding,
            root_selector,
            root_filesystem,
            userspace_platform,
            translation,
            ..
        } = &report.boot
        else {
            panic!("never EFI")
        };
        assert_eq!(root_selector, &crate::RootSelector::WholeDisk);
        assert_eq!(root_filesystem, &crate::RootFilesystem::Ext4);
        let BootProfile::LinuxDirect {
            binding: old_binding,
            userspace_platform: old_platform,
            translation: old_translation,
            ..
        } = &storage.boot
        else {
            panic!("source boot")
        };
        assert_eq!(
            (binding, userspace_platform, translation),
            (old_binding, old_platform, old_translation)
        );
        assert_eq!(
            report.geometry.length,
            std::fs::metadata(&report.path).unwrap().len()
        );
    }

    #[tokio::test]
    async fn overlay_refusals_publish_nothing_and_leave_source_untouched() {
        for unknown in [false, true] {
            let mut fixture = Fixture::new().await;
            fixture.overlay(unknown).await;
            let destination = fixture.destination("refused.raw");
            assert!(matches!(
                fixture
                    .machine
                    .export_raw_disk(RawDiskExportOptions {
                        destination: destination.clone(),
                        flatten_filesystem: false,
                    })
                    .await,
                Err(LibVmError::RawExportUnsupported { .. })
            ));
            if !unknown {
                make_dirty(&fixture.root);
            }
            let before = source_identity(&fixture.root);
            let result = fixture
                .machine
                .export_raw_disk(RawDiskExportOptions {
                    destination: destination.clone(),
                    flatten_filesystem: true,
                })
                .await;
            if unknown {
                assert!(
                    matches!(result, Err(LibVmError::RawExportUnsupported { .. })),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(LibVmError::RawExportRecoveryRequired { .. })),
                    "{result:?}"
                );
            }
            assert!(!destination.exists());
            assert!(!crate::machine::raw_export::sidecar_path(&destination).exists());
            assert_eq!(source_identity(&fixture.root), before);
            let active: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_operation WHERE kind='raw-export' AND state='staging'")
                .fetch_one(fixture.runtime.native_store().unwrap().test_pool()).await.unwrap();
            assert_eq!(active, 0);
        }
    }

    #[tokio::test]
    async fn unsupported_upper_layout_is_typed_and_never_repaired() {
        let mut fixture = Fixture::new().await;
        fixture.overlay(false).await;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fixture.root)
            .unwrap();
        let mut features = [0u8; 4];
        file.read_exact_at(&mut features, 1024 + 96).unwrap();
        file.write_all_at(
            &(u32::from_le_bytes(features) | 0x8000_0000).to_le_bytes(),
            1024 + 96,
        )
        .unwrap();
        file.sync_all().unwrap();
        let before = source_identity(&fixture.root);
        let destination = fixture.destination("unsupported-layout.raw");
        let result = fixture
            .machine
            .export_raw_disk(RawDiskExportOptions {
                destination: destination.clone(),
                flatten_filesystem: true,
            })
            .await;
        assert!(
            matches!(result, Err(LibVmError::RawExportUnsupported { .. })),
            "{result:?}"
        );
        assert!(!destination.exists());
        assert!(!crate::machine::raw_export::sidecar_path(&destination).exists());
        assert_eq!(source_identity(&fixture.root), before);
    }

    #[tokio::test]
    async fn lifetime_fence_and_reserved_ownership_refuse_before_output() {
        let fixture = Fixture::new().await;
        let before = source_identity(&fixture.root);
        let path = fixture
            .runtime
            .machine_paths(fixture.machine.machine_id())
            .vmm_lock_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let lifetime = crate::lock_manager::MachineLifetimeLock::try_acquire(&path)
            .unwrap()
            .unwrap();
        let destination = fixture.destination("busy.raw");
        assert!(fixture
            .machine
            .export_raw_disk(RawDiskExportOptions {
                destination: destination.clone(),
                flatten_filesystem: false,
            })
            .await
            .is_err());
        assert!(!destination.exists());
        drop(lifetime);
        let store = fixture.runtime.native_store().unwrap();
        let mut storage = fixture
            .runtime
            .machine_storage_record(fixture.machine.machine_id())
            .await
            .unwrap();
        storage.ownership = crate::MachineOwnership::Reserved {
            operation: crate::handoff::types::OperationId::new(uuid::Uuid::new_v4()).unwrap(),
        };
        let mut tx = store.test_pool().begin().await.unwrap();
        crate::store::Store::write_machine_storage(&mut tx, fixture.machine.machine_id(), &storage)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(fixture
            .machine
            .export_raw_disk(RawDiskExportOptions {
                destination: destination.clone(),
                flatten_filesystem: false,
            })
            .await
            .is_err());
        assert!(!destination.exists());
        assert!(!crate::machine::raw_export::sidecar_path(&destination).exists());
        assert_eq!(source_identity(&fixture.root), before);
    }

    #[test]
    fn destination_boundaries_and_kind_report_are_lossless() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("home");
        std::fs::create_dir(&home).unwrap();
        assert!(ExportOutput::prepare(Path::new(""), &home).is_err());
        assert!(ExportOutput::prepare(&directory.path().join("trailing/"), &home).is_err());
        let dangling = directory.path().join("dangling.raw");
        std::os::unix::fs::symlink(directory.path().join("absent"), &dangling).unwrap();
        assert!(ExportOutput::prepare(&dangling, &home).is_err());
        assert!(std::fs::symlink_metadata(&dangling)
            .unwrap()
            .file_type()
            .is_symlink());
        let uuid = uuid::Uuid::new_v4();
        let kind = serde_json::to_value(RawDiskExportKind::FlattenedFilesystem {
            filesystem_uuid: uuid,
        })
        .unwrap();
        assert_eq!(
            kind,
            serde_json::json!({ "kind": "flattened-filesystem", "filesystemUuid": uuid })
        );
    }

    #[test]
    fn changed_parent_alias_refuses_without_publishing_to_either_directory() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("home");
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        for path in [&home, &first, &second] {
            std::fs::create_dir(path).unwrap();
        }
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&first, &alias).unwrap();
        let output = ExportOutput::prepare(&alias.join("disk.raw"), &home).unwrap();
        output.create_disk().unwrap().set_len(4096).unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&second, &alias).unwrap();
        assert!(output.publish(b"{}", &AtomicBool::new(false)).is_err());
        assert!(!first.join("disk.raw").exists());
        assert!(!second.join("disk.raw").exists());
    }

    #[test]
    fn cancelled_publication_and_sidecar_race_remove_only_owned_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let destination = directory.path().join("output.raw");
        let output = ExportOutput::prepare(&destination, &home).unwrap();
        output.create_disk().unwrap().set_len(4096).unwrap();
        assert!(output.publish(b"{}", &AtomicBool::new(true)).is_err());
        assert!(!destination.exists());
        drop(output);
        let output = ExportOutput::prepare(&destination, &home).unwrap();
        output.create_disk().unwrap().set_len(4096).unwrap();
        std::fs::write(
            crate::machine::raw_export::sidecar_path(&destination),
            b"racing owner",
        )
        .unwrap();
        assert!(output.publish(b"{}", &AtomicBool::new(false)).is_err());
        assert!(!destination.exists());
        assert_eq!(
            std::fs::read(crate::machine::raw_export::sidecar_path(&destination)).unwrap(),
            b"racing owner"
        );
        assert!(ExportOutput::prepare(&home.join("alias.raw"), &home).is_err());
    }
}
