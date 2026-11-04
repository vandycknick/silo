use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use vm_spec::live::LiveBackend;

use crate::boot_qualification::QualifiedAsset;

use crate::storage::identity::ObjectDigest;
use crate::storage::pool::StoragePool;
use crate::storage::stream::open_regular_source;
use crate::store::Store;
use crate::{BootBinding, BootProfile, GuestArchitecture, MachineStorageRecord};

use crate::machine::{MachineAgent, MachineGuestConfig};
use crate::LibVmError;

#[derive(Debug, Clone)]
pub(crate) struct BootAssetOverrides<'a> {
    pub(crate) kernel: Option<&'a Path>,
    pub(crate) initramfs: Option<&'a Path>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedBootAssets {
    pub(crate) kernel: PathBuf,
    pub(crate) initramfs: PathBuf,
}

const CAPTURED_BOOT_ABI: &str = "silo-direct-v1";

pub(crate) struct BootSelectionContext<'a> {
    pub(crate) pool: &'a StoragePool,
    pub(crate) default_kernel: &'a Path,
    pub(crate) default_initramfs: &'a Path,
    pub(crate) default_agent: &'a Path,
    pub(crate) native_executable: &'a Path,
    pub(crate) backend: LiveBackend,
}

pub(crate) struct CapturedBootContext<'a> {
    pub(crate) pool: &'a StoragePool,
    pub(crate) store: &'a Store,
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) default_kernel: &'a Path,
    pub(crate) default_initramfs: &'a Path,
    pub(crate) default_agent: &'a Path,
    pub(crate) native_executable: &'a Path,
    pub(crate) backend: LiveBackend,
}

impl CapturedBootContext<'_> {
    fn selection(&self) -> BootSelectionContext<'_> {
        BootSelectionContext {
            pool: self.pool,
            default_kernel: self.default_kernel,
            default_initramfs: self.default_initramfs,
            default_agent: self.default_agent,
            native_executable: self.native_executable,
            backend: self.backend,
        }
    }
}

// One short-lived selection owns its retained descriptors; boxing adds an
// allocation without reducing a collection or long-lived per-machine footprint.
#[allow(clippy::large_enum_variant)]
pub(crate) enum CapturedBootAssets {
    Direct {
        kernel: QualifiedAsset,
        initramfs: QualifiedAsset,
    },
    Overlay(crate::QualifiedOverlayBoot),
}

impl CapturedBootAssets {
    pub(crate) fn kernel(&self) -> &QualifiedAsset {
        match self {
            Self::Direct { kernel, .. } => kernel,
            Self::Overlay(qualification) => qualification.kernel_asset(),
        }
    }

    pub(crate) fn initramfs(&self) -> &QualifiedAsset {
        match self {
            Self::Direct { initramfs, .. } => initramfs,
            Self::Overlay(qualification) => qualification.initramfs_asset(),
        }
    }

    pub(crate) fn into_overlay_qualification(self) -> Option<crate::QualifiedOverlayBoot> {
        match self {
            Self::Overlay(qualification) => Some(qualification),
            Self::Direct { .. } => None,
        }
    }

    fn into_sources(self) -> (QualifiedAsset, QualifiedAsset) {
        match self {
            Self::Direct { kernel, initramfs } => (kernel, initramfs),
            Self::Overlay(qualification) => qualification.into_boot_assets(),
        }
    }
}

pub(crate) struct ResolvedCapturedBoot {
    pub(crate) assets: CapturedBootAssets,
    pub(crate) agent: Option<QualifiedAsset>,
}

fn invalid_capture(message: impl Into<String>) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "captured-boot",
        message: message.into(),
    }
}

/// Semantic variants do not qualify a destination lane. This check is also
/// usable by read-only admission before creating a pool or operation staging.
pub(crate) fn validate_captured_boot_lane(
    storage: &MachineStorageRecord,
    backend: LiveBackend,
) -> Result<(), LibVmError> {
    use crate::store::models::storage::{
        BackendRequirement, MachineRoot, OverlayLower, RawLayout, RootSelector, StorageProfile,
        Translation,
    };

    storage.validate()?;
    if !cfg!(target_os = "linux") || backend != LiveBackend::Krun {
        return Err(invalid_capture(
            "stopped boot capture requires the admitted Linux krun direct-boot lane",
        ));
    }
    let host_architecture = match std::env::consts::ARCH {
        "x86_64" => GuestArchitecture::Amd64,
        "aarch64" => GuestArchitecture::Arm64,
        arch => {
            return Err(LibVmError::UnsupportedHostArchitecture {
                arch: arch.to_owned(),
            });
        }
    };
    let BootProfile::LinuxDirect {
        userspace_platform,
        kernel_architecture,
        binding,
        root_selector,
        translation,
        ..
    } = &storage.boot
    else {
        return Err(invalid_capture(
            "EFI and macOS stopped boot capture are not admitted",
        ));
    };
    if *kernel_architecture != host_architecture
        || userspace_platform.architecture != host_architecture
        || *translation != Translation::None
    {
        return Err(invalid_capture(
            "captured boot requires the same admitted host and guest architecture without translation",
        ));
    }
    let admitted_root = matches!(
        (
            &storage.root,
            root_selector,
            storage.profile,
            storage.backend
        ),
        (
            MachineRoot::OpaqueRaw {
                layout: RawLayout::WholeDisk,
                ..
            },
            RootSelector::WholeDisk,
            StorageProfile::OpaqueRawV1,
            BackendRequirement::RawBlock
        ) | (
            MachineRoot::LinuxOverlay {
                lower: OverlayLower::FlatExt4 { .. },
                ..
            },
            RootSelector::ManagedOverlay,
            StorageProfile::LinuxOverlayV1,
            BackendRequirement::KrunOverlay
        )
    );
    if !admitted_root {
        return Err(invalid_capture(
            "root and boot profile have no admitted stopped capture lane",
        ));
    }
    if let BootBinding::Pinned {
        abi, architecture, ..
    } = binding
    {
        if abi != CAPTURED_BOOT_ABI || architecture != kernel_architecture {
            return Err(invalid_capture(
                "captured boot bundle architecture or bootstrap ABI is incompatible",
            ));
        }
    }
    Ok(())
}

fn qualify_captured_assets(
    storage: &MachineStorageRecord,
    kernel: QualifiedAsset,
    initramfs: QualifiedAsset,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<CapturedBootAssets, LibVmError> {
    if matches!(storage.root, crate::MachineRoot::LinuxOverlay { .. }) {
        let BootProfile::LinuxDirect {
            kernel_architecture,
            ..
        } = &storage.boot
        else {
            return Err(invalid_capture("overlay requires direct boot"));
        };
        Ok(CapturedBootAssets::Overlay(
            crate::boot_qualification::admit_flat_overlay_assets(
                kernel,
                initramfs,
                *kernel_architecture,
                backend,
                native_executable,
            )?,
        ))
    } else {
        Ok(CapturedBootAssets::Direct { kernel, initramfs })
    }
}

/// Authenticate immutable objects without allocating a kernel-sized byte vector.
/// The caller retains their semantic closure through launch or publication.
fn resolve_boot_object(
    pool: &StoragePool,
    digest: &ObjectDigest,
) -> Result<QualifiedAsset, LibVmError> {
    let asset =
        QualifiedAsset::from_open_file(pool.open_object(digest)?, &pool.object_path(digest))?;
    if ObjectDigest::from_sha256(asset.digest()) != *digest {
        return Err(crate::storage::StorageError::ContentMismatch(pool.object_path(digest)).into());
    }
    Ok(asset)
}

/// Pinned launches never consult mutable installed paths, even when an exact
/// object is missing or incompatible. The composite is still generated anew.
pub(crate) fn resolve_pinned_boot(
    storage: &MachineStorageRecord,
    pool: &StoragePool,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<Option<ResolvedCapturedBoot>, LibVmError> {
    let BootProfile::LinuxDirect {
        binding:
            BootBinding::Pinned {
                kernel,
                base_initramfs,
                agent,
                ..
            },
        ..
    } = &storage.boot
    else {
        return Ok(None);
    };
    validate_captured_boot_lane(storage, backend)?;
    let kernel = resolve_boot_object(pool, kernel)?;
    let initramfs = resolve_boot_object(pool, base_initramfs)?;
    let assets = qualify_captured_assets(storage, kernel, initramfs, backend, native_executable)?;
    Ok(Some(ResolvedCapturedBoot {
        assets,
        agent: agent
            .as_ref()
            .map(|digest| resolve_boot_object(pool, digest))
            .transpose()?,
    }))
}

fn resolve_capture_selection(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
    context: &BootSelectionContext<'_>,
) -> Result<ResolvedCapturedBoot, LibVmError> {
    validate_captured_boot_lane(storage, context.backend)?;
    if let Some(resolved) = resolve_pinned_boot(
        storage,
        context.pool,
        context.backend,
        context.native_executable,
    )? {
        if resolved.agent.is_some() != agent.enabled() {
            return Err(invalid_capture(
                "pinned boot agent and configured agent mode disagree",
            ));
        }
        return Ok(resolved);
    }
    let configured = spec.boot.as_ref().and_then(|boot| boot.kernel.as_ref());
    let assets = resolve_boot_assets(
        BootAssetOverrides {
            kernel: configured.and_then(|kernel| kernel.path.as_deref()),
            initramfs: configured.and_then(|kernel| kernel.initramfs.as_deref()),
        },
        context.default_kernel,
        context.default_initramfs,
    )?;
    let kernel = qualify_capture_source(&assets.kernel)?;
    let initramfs = qualify_capture_source(&assets.initramfs)?;
    let agent = resolve_agent(agent, context.default_agent)?
        .as_deref()
        .map(qualify_capture_source)
        .transpose()?;
    Ok(ResolvedCapturedBoot {
        assets: qualify_captured_assets(
            storage,
            kernel,
            initramfs,
            context.backend,
            context.native_executable,
        )?,
        agent,
    })
}

pub(crate) fn preflight_captured_boot(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
    context: &CapturedBootContext<'_>,
) -> Result<(), LibVmError> {
    preflight_boot_selection(storage, spec, agent, context.selection())
}

pub(crate) fn preflight_boot_selection(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
    context: BootSelectionContext<'_>,
) -> Result<(), LibVmError> {
    resolve_capture_selection(storage, spec, agent, &context)?;
    Ok(())
}

fn open_capture_source(path: &Path) -> Result<File, LibVmError> {
    let file = open_regular_source(path)?;
    let metadata = file.metadata()?;
    if metadata.len() == 0
        || (metadata.uid() != nix::unistd::geteuid().as_raw() && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid_capture(
            "boot input must be a nonempty regular file not writable by other users",
        ));
    }
    Ok(file)
}

fn qualify_capture_source(path: &Path) -> Result<QualifiedAsset, LibVmError> {
    Ok(QualifiedAsset::from_open_file(
        open_capture_source(path)?,
        path,
    )?)
}

async fn ingest_boot_object(
    file: File,
    source: &Path,
    context: &CapturedBootContext<'_>,
) -> Result<ObjectDigest, LibVmError> {
    let (object, publication) = context.pool.publish_object_file_for_catalog(file, source)?;
    context
        .store
        .pin_published_storage_dependencies(context.operation_id, &[], &[object.digest])
        .await?;
    drop(publication);
    Ok(object.digest)
}

async fn ingest_selected_object(
    asset: QualifiedAsset,
    context: &CapturedBootContext<'_>,
) -> Result<ObjectDigest, LibVmError> {
    let expected = ObjectDigest::from_sha256(asset.digest());
    let (file, path) = asset.into_source();
    let digest = ingest_boot_object(file, &path, context).await?;
    if digest != expected {
        return Err(crate::storage::StorageError::ContentMismatch(path).into());
    }
    Ok(digest)
}

/// Capture the configured *next* boot, not an unverifiable prior-run selection.
/// No source selection is changed, and no generated source composite is copied.
pub(crate) async fn capture_boot(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
    context: CapturedBootContext<'_>,
) -> Result<BootProfile, LibVmError> {
    let selection = resolve_capture_selection(storage, spec, agent, &context.selection())?;
    let mut boot = storage.boot.clone();
    let BootProfile::LinuxDirect {
        binding,
        kernel_architecture,
        ..
    } = &mut boot
    else {
        return Err(invalid_capture("capture requires direct boot"));
    };
    if let BootBinding::Pinned {
        kernel,
        base_initramfs,
        agent,
        ..
    } = binding
    {
        let _roots = context.pool.lock_roots_shared()?;
        let objects = [*kernel, *base_initramfs, agent.unwrap_or(*kernel)];
        let count = if agent.is_some() { 3 } else { 2 };
        context
            .store
            .pin_published_storage_dependencies(context.operation_id, &[], &objects[..count])
            .await?;
        return Ok(boot);
    }
    // These are the already authenticated sources selected above. Publication
    // consumes the same descriptors, never their mutable diagnostic paths.
    let (kernel, initramfs) = selection.assets.into_sources();
    let kernel = ingest_selected_object(kernel, &context).await?;
    let base_initramfs = ingest_selected_object(initramfs, &context).await?;
    let agent = match selection.agent {
        Some(asset) => Some(ingest_selected_object(asset, &context).await?),
        None => None,
    };
    *binding = BootBinding::Pinned {
        kernel,
        base_initramfs,
        agent,
        architecture: *kernel_architecture,
        abi: CAPTURED_BOOT_ABI.to_owned(),
    };
    // Qualification must bind the ingested bytes too, not merely paths checked
    // before publication when an installer could have replaced the inputs.
    let mut captured = storage.clone();
    captured.boot = boot.clone();
    resolve_pinned_boot(
        &captured,
        context.pool,
        context.backend,
        context.native_executable,
    )?;
    Ok(boot)
}

pub(crate) fn resolve_boot_assets(
    overrides: BootAssetOverrides<'_>,
    default_kernel: &Path,
    default_initramfs: &Path,
) -> Result<ResolvedBootAssets, LibVmError> {
    Ok(ResolvedBootAssets {
        kernel: resolve_asset("kernel", overrides.kernel, default_kernel)?,
        initramfs: resolve_asset("initramfs", overrides.initramfs, default_initramfs)?,
    })
}

pub(crate) fn canonicalize_boot_overrides(
    overrides: BootAssetOverrides<'_>,
) -> Result<(Option<PathBuf>, Option<PathBuf>), LibVmError> {
    Ok((
        overrides
            .kernel
            .map(|path| require_asset("kernel", path))
            .transpose()?,
        overrides
            .initramfs
            .map(|path| require_asset("initramfs", path))
            .transpose()?,
    ))
}

pub(crate) fn canonicalize_guest_config(
    mut guest: MachineGuestConfig,
) -> Result<MachineGuestConfig, LibVmError> {
    if let MachineAgent::Custom { path } = &mut guest.agent {
        *path = require_asset("agent", path)?;
    }
    Ok(guest)
}

pub(crate) fn resolve_agent(
    agent: &MachineAgent,
    default_agent: &Path,
) -> Result<Option<PathBuf>, LibVmError> {
    match agent {
        MachineAgent::Default => require_asset("agent", default_agent).map(Some),
        MachineAgent::Custom { path } => require_asset("agent", path).map(Some),
        MachineAgent::Disabled => Ok(None),
    }
}

fn resolve_asset(
    asset: &'static str,
    explicit: Option<&Path>,
    default: &Path,
) -> Result<PathBuf, LibVmError> {
    if let Some(path) = explicit {
        return require_asset(asset, path);
    }
    require_asset(asset, default)
}

fn require_asset(asset: &'static str, path: &Path) -> Result<PathBuf, LibVmError> {
    let absolute = absolute_path(path)?;
    if !absolute.is_file() {
        return Err(LibVmError::BootAssetInvalid {
            asset,
            path: absolute,
        });
    }
    canonicalize_asset(asset, &absolute)
}

fn canonicalize_asset(asset: &'static str, path: &Path) -> Result<PathBuf, LibVmError> {
    std::fs::canonicalize(path).map_err(|_| LibVmError::BootAssetInvalid {
        asset,
        path: path.to_path_buf(),
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf, LibVmError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use crate::machine::{MachineAgent, MachineGuestConfig};
    use crate::runtime::boot_assets::{
        canonicalize_boot_overrides, canonicalize_guest_config, resolve_asset, BootAssetOverrides,
    };

    #[cfg(target_os = "linux")]
    use crate::runtime::boot_assets::{
        capture_boot, ingest_boot_object, preflight_captured_boot, resolve_pinned_boot,
        validate_captured_boot_lane, CapturedBootContext,
    };
    #[cfg(target_os = "linux")]
    use crate::store::ImageStore;

    #[cfg(target_os = "linux")]
    struct CaptureFixture {
        _temp: TempDir,
        paths: crate::paths::LocalPaths,
        store: crate::store::Store,
        pool: crate::storage::pool::StoragePool,
        kernel: PathBuf,
        initramfs: PathBuf,
        agent: PathBuf,
        storage: crate::MachineStorageRecord,
        spec: vm_spec::VmSpec,
    }

    #[cfg(target_os = "linux")]
    impl CaptureFixture {
        async fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let temp = TempDir::new().unwrap();
            let paths = crate::paths::LocalPaths::new(temp.path());
            let store = crate::store::Store::new(&paths).await.unwrap();
            let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
            let private = temp.path().join("source-private");
            std::fs::create_dir(&private).unwrap();
            let kernel = private.join("kernel");
            let initramfs = private.join("base-initramfs");
            let agent = private.join("agent");
            std::fs::write(&kernel, b"exact custom kernel").unwrap();
            std::fs::write(&initramfs, b"exact base initramfs").unwrap();
            std::fs::write(&agent, b"exact custom agent").unwrap();
            for path in [&kernel, &initramfs, &agent] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let storage = crate::MachineStorageRecord::opaque_raw(
                crate::PrivatePath::new("root.raw").unwrap(),
                512,
                &oci::Platform::host().unwrap(),
            )
            .unwrap();
            let spec = vm_spec::VmSpec {
                boot: Some(vm_spec::Boot {
                    kernel: Some(vm_spec::Kernel {
                        path: Some(kernel.clone()),
                        cmdline: vec!["custom.argument=1".into()],
                        initramfs: Some(initramfs.clone()),
                    }),
                    userdata: Some("exact configured userdata".into()),
                }),
                ..vm_spec::VmSpec::current()
            };
            Self {
                _temp: temp,
                paths,
                store,
                pool,
                kernel,
                initramfs,
                agent,
                storage,
                spec,
            }
        }

        fn context(&self, operation_id: uuid::Uuid) -> CapturedBootContext<'_> {
            CapturedBootContext {
                pool: &self.pool,
                store: &self.store,
                operation_id,
                default_kernel: &self.kernel,
                default_initramfs: &self.initramfs,
                default_agent: &self.agent,
                native_executable: &self.kernel,
                backend: vm_spec::live::LiveBackend::Krun,
            }
        }
    }

    fn write_asset(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).expect("create asset dir");
        let path = dir.join(name);
        std::fs::write(&path, b"asset").expect("write asset");
        path
    }

    #[test]
    fn explicit_overrides_are_canonicalized_without_default_lookup() {
        let temp = TempDir::new().expect("tempdir");
        let kernel = write_asset(temp.path(), "custom-kernel");

        let (resolved_kernel, resolved_initramfs) =
            canonicalize_boot_overrides(BootAssetOverrides {
                kernel: Some(&kernel),
                initramfs: None,
            })
            .expect("canonicalize overrides");

        assert_eq!(
            resolved_kernel,
            Some(kernel.canonicalize().expect("canonical"))
        );
        assert!(resolved_initramfs.is_none());
    }

    #[test]
    fn defaults_use_the_resolved_installation_asset() {
        let temp = TempDir::new().expect("tempdir");
        let default = write_asset(temp.path(), "agent");
        let explicit = write_asset(temp.path(), "custom-agent");

        let resolved = resolve_asset("agent", None, &default).expect("resolve default asset");
        let overridden =
            resolve_asset("agent", Some(&explicit), &default).expect("resolve explicit asset");

        assert_eq!(resolved, default.canonicalize().expect("canonical default"));
        assert_eq!(
            overridden,
            explicit.canonicalize().expect("canonical override")
        );
    }

    #[test]
    fn custom_agent_is_canonicalized_for_persistence() {
        let temp = TempDir::new().expect("tempdir");
        let agent = write_asset(temp.path(), "custom-agent");
        let guest = MachineGuestConfig {
            agent: MachineAgent::Custom {
                path: agent.clone(),
            },
            user: None,
        };

        let guest = canonicalize_guest_config(guest).expect("canonicalize guest");

        assert_eq!(
            guest.agent,
            MachineAgent::Custom {
                path: agent.canonicalize().expect("canonical")
            }
        );
    }

    #[cfg(target_os = "linux")]
    fn retained_bytes(asset: &crate::boot_qualification::QualifiedAsset) -> Vec<u8> {
        let mut bytes = Vec::new();
        asset.copy_into(&mut bytes).unwrap();
        bytes
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn captured_boot_survives_path_replacement_source_deletion_and_gc() {
        let fixture = CaptureFixture::new().await;
        let operation = uuid::Uuid::new_v4();
        let lease = fixture
            .store
            .begin_storage_operation(operation)
            .await
            .unwrap();
        let source_storage = fixture.storage.clone();
        let source_spec = fixture.spec.clone();
        let custom = MachineAgent::Custom {
            path: fixture.agent.clone(),
        };
        let boot = capture_boot(
            &fixture.storage,
            &fixture.spec,
            &custom,
            fixture.context(operation),
        )
        .await
        .unwrap();
        assert_eq!(fixture.storage, source_storage);
        assert_eq!(fixture.spec, source_spec);
        let crate::BootProfile::LinuxDirect {
            binding:
                crate::BootBinding::Pinned {
                    kernel,
                    base_initramfs,
                    agent: Some(agent),
                    ..
                },
            ..
        } = &boot
        else {
            panic!("capture must pin all selected assets");
        };
        assert_eq!(
            *kernel,
            crate::storage::identity::ObjectDigest::of_bytes(b"exact custom kernel")
        );
        assert_eq!(
            *base_initramfs,
            crate::storage::identity::ObjectDigest::of_bytes(b"exact base initramfs")
        );
        assert_eq!(
            *agent,
            crate::storage::identity::ObjectDigest::of_bytes(b"exact custom agent")
        );
        for path in [&fixture.kernel, &fixture.initramfs, &fixture.agent] {
            let replacement = path.with_extension("replacement");
            std::fs::write(&replacement, b"not the captured asset").unwrap();
            std::fs::rename(&replacement, path).unwrap();
        }
        std::fs::remove_dir_all(fixture.kernel.parent().unwrap()).unwrap();
        fixture.store.prune_images().await.unwrap();
        let mut captured = fixture.storage.clone();
        captured.boot = boot.clone();
        let resolved = resolve_pinned_boot(
            &captured,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            retained_bytes(resolved.assets.kernel()),
            b"exact custom kernel"
        );
        assert_eq!(
            retained_bytes(resolved.assets.initramfs()),
            b"exact base initramfs"
        );
        assert_eq!(
            retained_bytes(resolved.agent.as_ref().unwrap()),
            b"exact custom agent"
        );
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 3);

        // A second capture retains the already pinned closure without consulting
        // now-missing custom/default installation paths or substituting assets.
        let second = uuid::Uuid::new_v4();
        let second_lease = fixture.store.begin_storage_operation(second).await.unwrap();
        assert_eq!(
            capture_boot(&captured, &fixture.spec, &custom, fixture.context(second))
                .await
                .unwrap(),
            boot,
        );
        drop(lease);
        fixture.store.prune_images().await.unwrap();
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 3);
        drop(second_lease);
        fixture.store.prune_images().await.unwrap();
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn held_boot_input_ignores_replaced_path_and_rewinds_before_ingestion() {
        use std::io::{Seek, SeekFrom};
        let fixture = CaptureFixture::new().await;
        let operation = uuid::Uuid::new_v4();
        let _lease = fixture
            .store
            .begin_storage_operation(operation)
            .await
            .unwrap();
        let mut source = std::fs::File::open(&fixture.kernel).unwrap();
        source.seek(SeekFrom::End(0)).unwrap();
        let replacement = fixture.kernel.with_extension("replacement");
        std::fs::write(&replacement, b"replacement kernel").unwrap();
        std::fs::rename(&replacement, &fixture.kernel).unwrap();
        let digest = ingest_boot_object(source, &fixture.kernel, &fixture.context(operation))
            .await
            .unwrap();
        assert_eq!(
            digest,
            crate::storage::identity::ObjectDigest::of_bytes(b"exact custom kernel")
        );
        assert_eq!(
            std::fs::read(&fixture.kernel).unwrap(),
            b"replacement kernel"
        );
        fixture.store.prune_images().await.unwrap();
        assert_eq!(
            std::fs::read(fixture.pool.object_path(&digest)).unwrap(),
            b"exact custom kernel"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disabled_agent_requires_only_kernel_and_base_and_never_falls_back() {
        let fixture = CaptureFixture::new().await;
        let operation = uuid::Uuid::new_v4();
        let _lease = fixture
            .store
            .begin_storage_operation(operation)
            .await
            .unwrap();
        std::fs::remove_file(&fixture.agent).unwrap();
        let mut storage = fixture.storage.clone();
        storage.boot = capture_boot(
            &storage,
            &fixture.spec,
            &MachineAgent::Disabled,
            fixture.context(operation),
        )
        .await
        .unwrap();
        let crate::BootProfile::LinuxDirect {
            binding:
                crate::BootBinding::Pinned {
                    agent,
                    base_initramfs,
                    ..
                },
            ..
        } = &storage.boot
        else {
            panic!("must pin direct boot");
        };
        assert!(agent.is_none());
        let base_path = fixture.pool.object_path(base_initramfs);
        fixture.store.prune_images().await.unwrap();
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 2);
        assert!(resolve_pinned_boot(
            &storage,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .unwrap()
        .unwrap()
        .agent
        .is_none());
        std::fs::remove_file(&base_path).unwrap();
        assert!(resolve_pinned_boot(
            &storage,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .is_err());
        assert!(
            fixture.initramfs.is_file(),
            "current default must not rescue a missing pin"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn captured_boot_preflight_rejects_lane_abi_and_empty_input_before_publication() {
        let fixture = CaptureFixture::new().await;
        let operation = uuid::Uuid::new_v4();
        assert!(
            validate_captured_boot_lane(&fixture.storage, vm_spec::live::LiveBackend::Mock,)
                .is_err()
        );
        let architecture = match &fixture.storage.boot {
            crate::BootProfile::LinuxDirect {
                kernel_architecture,
                ..
            } => *kernel_architecture,
            _ => panic!("direct boot fixture"),
        };
        for unsupported in [
            crate::BootProfile::LinuxEfi {
                architecture,
                firmware: crate::store::models::storage::EfiFirmware::VzEfi,
                variable_store: crate::PrivatePath::new("variables").unwrap(),
            },
            crate::BootProfile::MacOs {
                hardware_model: crate::PrivatePath::new("hardware-model").unwrap(),
                machine_identifier: crate::PrivatePath::new("machine-identifier").unwrap(),
                auxiliary_storage: crate::PrivatePath::new("auxiliary-storage").unwrap(),
                compatibility: "unqualified-release".into(),
            },
        ] {
            let mut candidate = fixture.storage.clone();
            candidate.boot = unsupported;
            assert!(preflight_captured_boot(
                &candidate,
                &fixture.spec,
                &MachineAgent::Disabled,
                &fixture.context(operation),
            )
            .is_err());
        }
        let mut incompatible = fixture.storage.clone();
        if let crate::BootProfile::LinuxDirect {
            binding,
            kernel_architecture,
            ..
        } = &mut incompatible.boot
        {
            *binding = crate::BootBinding::Pinned {
                kernel: crate::storage::identity::ObjectDigest::of_bytes(b"kernel"),
                base_initramfs: crate::storage::identity::ObjectDigest::of_bytes(b"initramfs"),
                agent: None,
                architecture: *kernel_architecture,
                abi: "unqualified-bootstrap-v99".into(),
            };
        }
        assert!(preflight_captured_boot(
            &incompatible,
            &fixture.spec,
            &MachineAgent::Disabled,
            &fixture.context(operation),
        )
        .is_err());
        let mut wrong_architecture = fixture.storage.clone();
        if let crate::BootProfile::LinuxDirect {
            userspace_platform,
            kernel_architecture,
            ..
        } = &mut wrong_architecture.boot
        {
            let opposite = match kernel_architecture {
                crate::GuestArchitecture::Amd64 => crate::GuestArchitecture::Arm64,
                crate::GuestArchitecture::Arm64 => crate::GuestArchitecture::Amd64,
            };
            *kernel_architecture = opposite;
            userspace_platform.architecture = opposite;
        }
        assert!(
            validate_captured_boot_lane(&wrong_architecture, vm_spec::live::LiveBackend::Krun,)
                .is_err()
        );
        std::fs::write(&fixture.kernel, b"").unwrap();
        assert!(preflight_captured_boot(
            &fixture.storage,
            &fixture.spec,
            &MachineAgent::Disabled,
            &fixture.context(operation),
        )
        .is_err());
        assert!(capture_boot(
            &fixture.storage,
            &fixture.spec,
            &MachineAgent::Disabled,
            fixture.context(operation),
        )
        .await
        .is_err());
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 0);
        assert_eq!(
            std::fs::read_dir(fixture.paths.images_dir().join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pinned_boot_rejects_corruption_and_regenerates_child_composite_identity() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = CaptureFixture::new().await;
        let operation = uuid::Uuid::new_v4();
        let _lease = fixture
            .store
            .begin_storage_operation(operation)
            .await
            .unwrap();
        let mut storage = fixture.storage.clone();
        storage.boot = capture_boot(
            &storage,
            &fixture.spec,
            &MachineAgent::Default,
            fixture.context(operation),
        )
        .await
        .unwrap();
        let resolved = resolve_pinned_boot(
            &storage,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .unwrap()
        .unwrap();
        let first = fixture.paths.home().join("child-first.initramfs");
        let second = fixture.paths.home().join("child-second.initramfs");
        for (destination, identity) in [
            (
                &first,
                b"{\"machine\":\"child-first\",\"run\":\"fresh-first\"}".as_slice(),
            ),
            (
                &second,
                b"{\"machine\":\"child-second\",\"run\":\"fresh-second\"}".as_slice(),
            ),
        ] {
            crate::initramfs_overlay::write_composite(
                crate::initramfs_overlay::CompositeBase::Retained(resolved.assets.initramfs()),
                Some((
                    crate::initramfs_overlay::CompositeAgent::Retained(
                        resolved.agent.as_ref().unwrap(),
                    ),
                    identity,
                )),
                None,
                destination,
            )
            .unwrap();
        }
        let first_bytes = std::fs::read(&first).unwrap();
        let second_bytes = std::fs::read(&second).unwrap();
        assert_ne!(first_bytes, second_bytes);
        assert!(first_bytes.starts_with(b"exact base initramfs"));
        assert!(second_bytes.starts_with(b"exact base initramfs"));
        assert!(first_bytes
            .windows(b"fresh-first".len())
            .any(|part| part == b"fresh-first"));
        assert!(!second_bytes
            .windows(b"fresh-first".len())
            .any(|part| part == b"fresh-first"));
        assert_eq!(
            retained_bytes(resolved.assets.initramfs()),
            b"exact base initramfs"
        );
        let crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { kernel, .. },
            ..
        } = &storage.boot
        else {
            panic!("pinned direct boot");
        };
        let kernel_path = fixture.pool.object_path(kernel);
        std::fs::set_permissions(&kernel_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&kernel_path, b"corrupt retained kernel").unwrap();
        std::fs::set_permissions(&kernel_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(resolved.assets.kernel().copy_into(&mut Vec::new()).is_err());
        assert!(resolve_pinned_boot(
            &storage,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pinned_boot_consumes_authenticated_descriptors_after_pool_path_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = CaptureFixture::new().await;
        let operation = uuid::Uuid::new_v4();
        let _lease = fixture
            .store
            .begin_storage_operation(operation)
            .await
            .unwrap();
        let mut storage = fixture.storage.clone();
        storage.boot = capture_boot(
            &storage,
            &fixture.spec,
            &MachineAgent::Default,
            fixture.context(operation),
        )
        .await
        .unwrap();
        let resolved = resolve_pinned_boot(
            &storage,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .unwrap()
        .unwrap();
        let crate::BootProfile::LinuxDirect {
            binding:
                crate::BootBinding::Pinned {
                    kernel,
                    base_initramfs,
                    agent: Some(agent),
                    ..
                },
            ..
        } = &storage.boot
        else {
            panic!("complete pinned boot fixture");
        };
        for digest in [kernel, base_initramfs, agent] {
            let path = fixture.pool.object_path(digest);
            let replacement = path.with_extension("replacement");
            std::fs::write(&replacement, b"replacement must never be consumed").unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
            std::fs::rename(&replacement, &path).unwrap();
        }
        let launch_kernel = crate::machine::root_storage::publish_kernel(
            fixture.paths.home(),
            resolved.assets.kernel(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(launch_kernel).unwrap(),
            b"exact custom kernel"
        );
        let composite = fixture.paths.home().join("retained-composite");
        crate::initramfs_overlay::write_composite(
            crate::initramfs_overlay::CompositeBase::Retained(resolved.assets.initramfs()),
            Some((
                crate::initramfs_overlay::CompositeAgent::Retained(
                    resolved.agent.as_ref().unwrap(),
                ),
                b"{\"machine\":\"new-child\",\"run\":\"new-run\"}",
            )),
            None,
            &composite,
        )
        .unwrap();
        let bytes = std::fs::read(composite).unwrap();
        assert!(bytes.starts_with(b"exact base initramfs"));
        assert!(bytes
            .windows(b"exact custom agent".len())
            .any(|part| part == b"exact custom agent"));
        assert!(!bytes
            .windows(b"replacement must never be consumed".len())
            .any(|part| part == b"replacement must never be consumed"));
        assert!(
            resolve_pinned_boot(
                &storage,
                &fixture.pool,
                vm_spec::live::LiveBackend::Krun,
                &fixture.kernel,
            )
            .is_err(),
            "a new resolution must reject the substituted objects"
        );
    }
}
