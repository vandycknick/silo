use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use vm_spec::live::LiveBackend;

use crate::boot_qualification::{InspectedKernel, QualifiedAsset};

use crate::storage::identity::ObjectDigest;
use crate::storage::pool::StoragePool;
use crate::storage::stream::open_regular_source;
use crate::store::Store;
use crate::{BootBinding, BootProfile, GuestArchitecture, MachineStorageRecord};

use crate::machine::{MachineAgent, MachineGuestConfig};
use crate::LibVmError;

/// The bootstrap schema is part of the complete, immutable direct-boot tuple.
pub(crate) const DIRECT_BOOT_ABI: &str = "silo-direct-v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceFamily {
    Oci,
    LocalDisk,
    ManagedImage,
    Snapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionRemedy {
    ExplicitOciToRawConversion,
    UseKrun,
    UnsupportedBootProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectiveBoot {
    pub(crate) rosetta: rootfs_spec::RosettaMode,
}

pub(crate) fn admit_create_source(
    source_family: SourceFamily,
    profile: crate::StorageProfile,
    requirement: crate::BackendRequirement,
    backend: LiveBackend,
) -> Result<(), LibVmError> {
    let remedy = if backend == LiveBackend::Vz && source_family == SourceFamily::Oci {
        Some(AdmissionRemedy::ExplicitOciToRawConversion)
    } else if backend == LiveBackend::Vz && requirement == crate::BackendRequirement::KrunOverlay {
        Some(AdmissionRemedy::UseKrun)
    } else {
        None
    };
    if let Some(remedy) = remedy {
        return Err(LibVmError::BackendAdmissionRejected {
            source_family,
            root_profile: profile,
            requirement,
            effective_backend: backend,
            remedy,
        });
    }
    Ok(())
}

fn host_architecture() -> Result<GuestArchitecture, LibVmError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(GuestArchitecture::Amd64),
        "aarch64" => Ok(GuestArchitecture::Arm64),
        arch => Err(LibVmError::UnsupportedHostArchitecture {
            arch: arch.to_owned(),
        }),
    }
}

pub(crate) fn direct_boot_profile(
    userspace: &crate::LinuxPlatform,
    selector: crate::RootSelector,
) -> Result<BootProfile, LibVmError> {
    userspace.validate()?;
    let kernel = host_architecture()?;
    let translation = if userspace.architecture == kernel {
        crate::Translation::None
    } else if userspace.architecture == GuestArchitecture::Amd64
        && kernel == GuestArchitecture::Arm64
    {
        crate::Translation::Rosetta
    } else {
        return Err(LibVmError::TranslationUnavailable {
            reason: "no translation is available for the requested userspace on this host".into(),
        });
    };
    let boot = BootProfile::LinuxDirect {
        userspace_platform: userspace.clone(),
        kernel_architecture: kernel,
        command_line_policy: crate::store::models::storage::DirectCommandLinePolicy::SiloDirectV1,
        binding: BootBinding::RuntimeSelected,
        root_selector: selector,
        root_filesystem: crate::store::models::storage::RootFilesystem::Ext4,
        translation,
    };
    boot.validate()?;
    Ok(boot)
}

/// Ordinary boot admission deliberately does not claim stopped/live capture
/// qualification. Partitioned roots and translation have independent gates.
pub(crate) fn effective_boot(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    backend: LiveBackend,
) -> Result<EffectiveBoot, LibVmError> {
    storage.validate()?;
    admit_create_source(
        SourceFamily::ManagedImage,
        storage.profile,
        storage.backend,
        backend,
    )?;
    effective_boot_profile(&storage.boot, spec, backend)
}

pub(crate) fn effective_boot_profile(
    boot: &BootProfile,
    spec: &vm_spec::VmSpec,
    backend: LiveBackend,
) -> Result<EffectiveBoot, LibVmError> {
    validate_direct_boot_profile(boot)?;
    let BootProfile::LinuxDirect { translation, .. } = boot else {
        return Err(invalid_capture("only Linux direct boot is admitted"));
    };
    let hardware = spec.hardware.as_ref();
    let intent = hardware.and_then(|hardware| hardware.rosetta);
    let required = *translation == crate::Translation::Rosetta;
    if required && intent == Some(false) {
        return Err(LibVmError::TranslationUnavailable {
            reason: "amd64 userspace requires Rosetta, but it was explicitly disabled".into(),
        });
    }
    let rosetta = if required {
        rootfs_spec::RosettaMode::Required
    } else if intent == Some(true) {
        rootfs_spec::RosettaMode::Optional
    } else {
        rootfs_spec::RosettaMode::Disabled
    };
    if rosetta != rootfs_spec::RosettaMode::Disabled {
        if hardware
            .and_then(|hardware| hardware.nested_virtualization)
            .unwrap_or(false)
        {
            return Err(LibVmError::TranslationUnavailable {
                reason: "Rosetta does not support nested virtualization".into(),
            });
        }
        require_rosetta_available(backend)?;
        let mounts = vm_spec::project_mounts(&spec.mounts).map_err(|reason| {
            LibVmError::TranslationUnavailable {
                reason: reason.to_string(),
            }
        })?;
        if mounts
            .iter()
            .any(|mount| mount.backend_tag == rootfs_spec::rosetta::SHARE_TAG)
        {
            return Err(LibVmError::TranslationUnavailable {
                reason: "mount tag rosetta is reserved for the trusted init".into(),
            });
        }
    }
    Ok(EffectiveBoot { rosetta })
}

fn require_rosetta_available(backend: LiveBackend) -> Result<(), LibVmError> {
    if backend == LiveBackend::Mock {
        return Err(LibVmError::TranslationUnavailable {
            reason: "Rosetta is not supported by the mock backend".into(),
        });
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        match vz::rosetta_availability() {
            vz::RosettaAvailability::Installed => Ok(()),
            vz::RosettaAvailability::NotInstalled => Err(LibVmError::TranslationUnavailable {
                reason: "Rosetta for Linux VMs is not installed; install with softwareupdate --install-rosetta".into(),
            }),
            vz::RosettaAvailability::NotSupported => Err(LibVmError::TranslationUnavailable {
                reason: "Rosetta for Linux VMs is not supported on this host".into(),
            }),
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    Err(LibVmError::TranslationUnavailable {
        reason: "Rosetta requires an Apple silicon macOS host".into(),
    })
}

pub(crate) fn validate_direct_boot(
    storage: &MachineStorageRecord,
    backend: LiveBackend,
) -> Result<(), LibVmError> {
    storage.validate()?;
    admit_create_source(
        SourceFamily::ManagedImage,
        storage.profile,
        storage.backend,
        backend,
    )?;
    validate_direct_boot_profile(&storage.boot)?;
    if matches!(
        &storage.boot,
        BootProfile::LinuxDirect {
            translation: crate::Translation::Rosetta,
            ..
        }
    ) {
        require_rosetta_available(backend)?;
    }
    Ok(())
}

fn validate_direct_boot_profile(boot: &BootProfile) -> Result<(), LibVmError> {
    boot.validate()?;
    let BootProfile::LinuxDirect {
        userspace_platform,
        kernel_architecture,
        binding,
        translation,
        ..
    } = boot
    else {
        return Err(invalid_capture(
            "EFI and macOS boot profiles are not admitted",
        ));
    };
    userspace_platform.validate()?;
    if *kernel_architecture != host_architecture()? {
        return Err(invalid_capture(
            "pinned kernel architecture differs from the host; CPU emulation is not supported",
        ));
    }
    let expected = if userspace_platform.architecture == *kernel_architecture {
        crate::Translation::None
    } else if userspace_platform.architecture == GuestArchitecture::Amd64
        && *kernel_architecture == GuestArchitecture::Arm64
    {
        crate::Translation::Rosetta
    } else {
        return Err(LibVmError::TranslationUnavailable {
            reason: "no translation is available for the userspace/kernel architecture combination"
                .into(),
        });
    };
    if *translation != expected {
        return Err(invalid_capture(
            "translation does not match userspace and pinned kernel architecture",
        ));
    }
    if let BootBinding::Pinned {
        architecture, abi, ..
    } = binding
    {
        if architecture != kernel_architecture || abi != DIRECT_BOOT_ABI {
            return Err(invalid_capture(
                "boot bundle architecture or schema-2 bootstrap ABI is incompatible",
            ));
        }
    }
    Ok(())
}
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
    pub(crate) fn selection(&self) -> BootSelectionContext<'_> {
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

pub(crate) fn configured_boot_selection(
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
    context: &CapturedBootContext<'_>,
) -> crate::image::import_types::BootAssetSelection {
    let configured = spec.boot.as_ref().and_then(|boot| boot.kernel.as_ref());
    crate::image::import_types::BootAssetSelection::Files {
        kernel: configured
            .and_then(|kernel| kernel.path.clone())
            .unwrap_or_else(|| context.default_kernel.to_path_buf()),
        base_initramfs: configured
            .and_then(|kernel| kernel.initramfs.clone())
            .unwrap_or_else(|| context.default_initramfs.to_path_buf()),
        agent: match agent {
            MachineAgent::Disabled => None,
            MachineAgent::Default => Some(context.default_agent.to_path_buf()),
            MachineAgent::Custom { path } => Some(path.clone()),
        },
    }
}

/// Report a different locally admitted packaged tuple without publishing,
/// downloading, repairing or changing any durable boot state.
pub(crate) fn locally_admitted_replacement(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    context: BootSelectionContext<'_>,
) -> Result<Option<ObjectDigest>, LibVmError> {
    let BootProfile::LinuxDirect {
        binding: current,
        kernel_architecture,
        ..
    } = &storage.boot
    else {
        return Ok(None);
    };
    let BootBinding::Pinned { agent, .. } = current else {
        return Ok(None);
    };
    let kernel = qualify_kernel_source(context.default_kernel)?;
    let initramfs = qualify_capture_source(context.default_initramfs)?;
    let agent = agent
        .as_ref()
        .map(|_| qualify_capture_source(context.default_agent))
        .transpose()?;
    let assets = qualify_captured_assets(
        &storage.boot,
        kernel,
        initramfs,
        context.backend,
        context.native_executable,
    )?;
    let replacement = BootBinding::Pinned {
        kernel: ObjectDigest::from_sha256(assets.kernel().digest()),
        base_initramfs: ObjectDigest::from_sha256(assets.initramfs().digest()),
        agent: agent
            .as_ref()
            .map(|asset| ObjectDigest::from_sha256(asset.digest())),
        architecture: *kernel_architecture,
        abi: DIRECT_BOOT_ABI.to_owned(),
    };
    let mut candidate = storage.clone();
    if let BootProfile::LinuxDirect { binding, .. } = &mut candidate.boot {
        *binding = replacement.clone();
    }
    effective_boot(&candidate, spec, context.backend)?;
    let digest = replacement.digest()?;
    Ok((digest != current.digest()?).then_some(digest))
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
        record: "boot",
        message: message.into(),
    }
}

/// The capture boundary a boot tuple is admitted for. Stopped capture copies
/// quiescent disks; live capture also carries execution state and keeps its
/// separately qualified narrower root set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureLane {
    Stopped,
    Live,
}

impl CaptureLane {
    fn label(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Live => "live",
        }
    }
}

/// Semantic variants do not qualify a destination lane. This check is also
/// usable by read-only admission before creating a pool or operation staging.
pub(crate) fn validate_captured_boot_lane(
    storage: &MachineStorageRecord,
    backend: LiveBackend,
    lane: CaptureLane,
) -> Result<(), LibVmError> {
    use crate::store::models::storage::{
        BackendRequirement, MachineRoot, OverlayLower, RawLayout, RootSelector, StorageProfile,
        Translation,
    };

    storage.validate()?;
    if !cfg!(target_os = "linux") || backend != LiveBackend::Krun {
        return Err(invalid_capture(format!(
            "{} boot capture requires the admitted Linux krun direct-boot lane",
            lane.label()
        )));
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
        return Err(invalid_capture(format!(
            "EFI and macOS {} boot capture are not admitted",
            lane.label()
        )));
    };
    if *kernel_architecture != host_architecture
        || userspace_platform.architecture != host_architecture
        || *translation != Translation::None
    {
        return Err(invalid_capture(
            "captured boot requires the same admitted host and guest architecture without translation",
        ));
    }
    let admitted_root = match (
        &storage.root,
        root_selector,
        storage.profile,
        storage.backend,
    ) {
        (
            MachineRoot::OpaqueRaw {
                layout: RawLayout::WholeDisk,
                ..
            },
            RootSelector::WholeDisk,
            StorageProfile::OpaqueRawV1,
            BackendRequirement::RawBlock,
        ) => true,
        // A validated record's disk-local partition selector is ordinary block
        // content for a quiescent copy; the selector and table travel with it.
        (
            MachineRoot::OpaqueRaw {
                layout: RawLayout::Partitioned { .. },
                ..
            },
            RootSelector::GptPartition { .. } | RootSelector::MbrPartition { .. },
            StorageProfile::OpaqueRawV1,
            BackendRequirement::RawBlock,
        ) => lane == CaptureLane::Stopped,
        (
            MachineRoot::LinuxOverlay {
                lower: OverlayLower::FlatExt4 { .. },
                ..
            },
            RootSelector::ManagedOverlay,
            StorageProfile::LinuxOverlayV1,
            BackendRequirement::KrunOverlay,
        ) => true,
        _ => false,
    };
    if !admitted_root {
        return Err(invalid_capture(format!(
            "root and boot profile have no admitted {} capture lane",
            lane.label()
        )));
    }
    if let BootBinding::Pinned {
        abi, architecture, ..
    } = binding
    {
        if abi != DIRECT_BOOT_ABI || architecture != kernel_architecture {
            return Err(invalid_capture(
                "captured boot bundle architecture or bootstrap ABI is incompatible",
            ));
        }
    }
    Ok(())
}

/// Overlay roots are admitted only by their exact reviewed tuple. Raw roots
/// need no overlay lane or backend tuple, but their kernel bytes must be the
/// host's native direct-boot format for the pinned kernel architecture.
/// Capabilities are not inspected; a kernel lacking them fails at boot.
fn qualify_captured_assets(
    boot: &BootProfile,
    kernel: InspectedKernel,
    initramfs: QualifiedAsset,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<CapturedBootAssets, LibVmError> {
    let BootProfile::LinuxDirect {
        kernel_architecture,
        root_selector,
        ..
    } = boot
    else {
        return Err(invalid_capture("boot assets require Linux direct boot"));
    };
    if *root_selector == crate::RootSelector::ManagedOverlay {
        return Ok(CapturedBootAssets::Overlay(
            crate::boot_qualification::admit_flat_overlay_assets(
                kernel.into_asset(),
                initramfs,
                *kernel_architecture,
                backend,
                native_executable,
            )?,
        ));
    }
    let kernel = kernel.admit_direct(*kernel_architecture)?;
    Ok(CapturedBootAssets::Direct { kernel, initramfs })
}

fn open_boot_object(pool: &StoragePool, digest: &ObjectDigest) -> Result<File, LibVmError> {
    pool.open_object(digest).map_err(|error| {
        if matches!(&error, crate::storage::StorageError::Io(io) if io.kind() == std::io::ErrorKind::NotFound) {
            LibVmError::BootAssetsAcquisitionRequired { missing: *digest }
        } else {
            error.into()
        }
    })
}

fn require_object_digest(
    pool: &StoragePool,
    digest: &ObjectDigest,
    observed: [u8; 32],
) -> Result<(), LibVmError> {
    if ObjectDigest::from_sha256(observed) != *digest {
        return Err(crate::storage::StorageError::ContentMismatch(pool.object_path(digest)).into());
    }
    Ok(())
}

/// Authenticate immutable objects without allocating a kernel-sized byte vector.
/// The caller retains their semantic closure through launch or publication.
fn resolve_boot_object(
    pool: &StoragePool,
    digest: &ObjectDigest,
) -> Result<QualifiedAsset, LibVmError> {
    let asset =
        QualifiedAsset::from_open_file(open_boot_object(pool, digest)?, &pool.object_path(digest))?;
    require_object_digest(pool, digest, asset.digest())?;
    Ok(asset)
}

fn resolve_kernel_object(
    pool: &StoragePool,
    digest: &ObjectDigest,
) -> Result<InspectedKernel, LibVmError> {
    let kernel = InspectedKernel::from_open_file(
        open_boot_object(pool, digest)?,
        &pool.object_path(digest),
    )?;
    require_object_digest(pool, digest, kernel.digest())?;
    Ok(kernel)
}

/// Pinned launches never consult mutable installed paths, even when an exact
/// object is missing or incompatible. The composite is still generated anew.
pub(crate) fn resolve_pinned_boot(
    storage: &MachineStorageRecord,
    pool: &StoragePool,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<Option<ResolvedCapturedBoot>, LibVmError> {
    if !matches!(
        &storage.boot,
        BootProfile::LinuxDirect {
            binding: BootBinding::Pinned { .. },
            ..
        }
    ) {
        return Ok(None);
    }
    validate_direct_boot(storage, backend)?;
    resolve_pinned_profile(&storage.boot, pool, backend, native_executable).map(Some)
}

/// Authenticate and admit one complete pinned tuple from owned objects only.
fn resolve_pinned_profile(
    boot: &BootProfile,
    pool: &StoragePool,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<ResolvedCapturedBoot, LibVmError> {
    let BootProfile::LinuxDirect { binding, .. } = boot else {
        return Err(invalid_capture("pinned launch requires direct boot"));
    };
    let BootBinding::Pinned {
        kernel,
        base_initramfs,
        agent,
        ..
    } = binding
    else {
        return Err(invalid_capture("persistent boot assets must be pinned"));
    };
    resolve_boot_object(pool, &binding.digest()?)?;
    let kernel = resolve_kernel_object(pool, kernel)?;
    let initramfs = resolve_boot_object(pool, base_initramfs)?;
    let assets = qualify_captured_assets(boot, kernel, initramfs, backend, native_executable)?;
    Ok(ResolvedCapturedBoot {
        assets,
        agent: agent
            .as_ref()
            .map(|digest| resolve_boot_object(pool, digest))
            .transpose()?,
    })
}

fn resolve_capture_selection(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
    context: &BootSelectionContext<'_>,
    lane: CaptureLane,
) -> Result<ResolvedCapturedBoot, LibVmError> {
    validate_captured_boot_lane(storage, context.backend, lane)?;
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
    let kernel = qualify_kernel_source(&assets.kernel)?;
    let initramfs = qualify_capture_source(&assets.initramfs)?;
    let agent = resolve_agent(agent, context.default_agent)?
        .as_deref()
        .map(qualify_capture_source)
        .transpose()?;
    Ok(ResolvedCapturedBoot {
        assets: qualify_captured_assets(
            &storage.boot,
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
    lane: CaptureLane,
) -> Result<(), LibVmError> {
    preflight_boot_selection(storage, spec, agent, context.selection(), lane)
}

pub(crate) fn preflight_boot_selection(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
    context: BootSelectionContext<'_>,
    lane: CaptureLane,
) -> Result<(), LibVmError> {
    resolve_capture_selection(storage, spec, agent, &context, lane)?;
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

fn qualify_kernel_source(path: &Path) -> Result<InspectedKernel, LibVmError> {
    Ok(InspectedKernel::from_open_file(
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
/// Resolve a complete creation/update selection and transfer every immutable
/// member into the caller's existing operation before publishing its tuple.
pub(crate) async fn pin_boot_selection(
    storage: &MachineStorageRecord,
    selection: &crate::image::import_types::BootAssetSelection,
    context: CapturedBootContext<'_>,
) -> Result<BootProfile, LibVmError> {
    storage.validate()?;
    admit_create_source(
        SourceFamily::ManagedImage,
        storage.profile,
        storage.backend,
        context.backend,
    )?;
    pin_boot_profile(&storage.boot, Some(storage), selection, context).await
}

pub(crate) async fn pin_image_boot(
    boot: &BootProfile,
    selection: &crate::image::import_types::BootAssetSelection,
    context: CapturedBootContext<'_>,
) -> Result<BootProfile, LibVmError> {
    if matches!(
        boot,
        BootProfile::LinuxDirect {
            root_selector: crate::RootSelector::ManagedOverlay,
            ..
        }
    ) {
        return Err(invalid_capture(
            "an opaque image cannot select a managed overlay",
        ));
    }
    pin_boot_profile(boot, None, selection, context).await
}

async fn pin_boot_profile(
    boot: &BootProfile,
    storage: Option<&MachineStorageRecord>,
    selection: &crate::image::import_types::BootAssetSelection,
    context: CapturedBootContext<'_>,
) -> Result<BootProfile, LibVmError> {
    use crate::image::import_types::BootAssetSelection;
    let mut boot = boot.clone();
    let BootProfile::LinuxDirect {
        binding,
        kernel_architecture,
        ..
    } = &mut boot
    else {
        return Err(invalid_capture("boot assets require Linux direct boot"));
    };
    // Replacement is explicit. The old binding is not an asset-selection input.
    *binding = BootBinding::RuntimeSelected;
    let kernel_architecture = *kernel_architecture;
    validate_direct_boot_profile(&boot)?;
    if matches!(
        &boot,
        BootProfile::LinuxDirect {
            translation: crate::Translation::Rosetta,
            ..
        }
    ) {
        require_rosetta_available(context.backend)?;
    }
    let binding = match selection {
        BootAssetSelection::Exact { bundle } => {
            let _roots = context.pool.lock_roots_shared()?;
            let asset = resolve_boot_object(context.pool, bundle)?;
            let (mut source, _) = asset.into_source();
            use std::io::Read;
            let mut bytes = Vec::new();
            source.by_ref().take(65537).read_to_end(&mut bytes)?;
            if bytes.len() > 65536 {
                return Err(invalid_capture("boot bundle exceeds metadata bound"));
            }
            let binding = BootBinding::decode(&bytes)?;
            if binding.digest()? != *bundle {
                return Err(invalid_capture(
                    "boot bundle digest differs from canonical tuple",
                ));
            }
            pin_binding_dependencies(&binding, &context).await?;
            binding
        }
        BootAssetSelection::Packaged | BootAssetSelection::Files { .. } => {
            let (kernel, initramfs, agent) = match selection {
                BootAssetSelection::Packaged => (
                    context.default_kernel,
                    context.default_initramfs,
                    Some(context.default_agent),
                ),
                BootAssetSelection::Files {
                    kernel,
                    base_initramfs,
                    agent,
                } => (kernel.as_path(), base_initramfs.as_path(), agent.as_deref()),
                BootAssetSelection::Exact { .. } => {
                    return Err(invalid_capture(
                        "exact boot selection cannot be resolved as files",
                    ));
                }
            };
            // Open every input before publication, retaining descriptor authority.
            let kernel = qualify_kernel_source(kernel)?;
            let initramfs = qualify_capture_source(initramfs)?;
            if matches!(selection, BootAssetSelection::Files { .. }) {
                let packaged = qualify_capture_source(context.default_initramfs)?;
                if initramfs.digest() != packaged.digest() {
                    return Err(LibVmError::BootBundleAbiUnsupported {
                        expected: ObjectDigest::from_sha256(packaged.digest()),
                        actual: ObjectDigest::from_sha256(initramfs.digest()),
                    });
                }
            }
            let agent = agent.map(qualify_capture_source).transpose()?;
            // Admission precedes ingestion: a rejected tuple publishes nothing.
            let (kernel, initramfs) = qualify_captured_assets(
                &boot,
                kernel,
                initramfs,
                context.backend,
                context.native_executable,
            )?
            .into_sources();
            BootBinding::Pinned {
                kernel: ingest_selected_object(kernel, &context).await?,
                base_initramfs: ingest_selected_object(initramfs, &context).await?,
                agent: match agent {
                    Some(agent) => Some(ingest_selected_object(agent, &context).await?),
                    None => None,
                },
                architecture: kernel_architecture,
                abi: DIRECT_BOOT_ABI.to_owned(),
            }
        }
    };
    if let BootProfile::LinuxDirect {
        binding: target, ..
    } = &mut boot
    {
        *target = binding;
    }
    validate_direct_boot_profile(&boot)?;
    let BootProfile::LinuxDirect { binding, .. } = &boot else {
        return Err(invalid_capture("boot assets require Linux direct boot"));
    };
    publish_binding(binding, &context).await?;
    // Qualification must bind the ingested bytes too, including an exact bundle
    // whose objects were admitted by another operation or host.
    match storage {
        Some(storage) => {
            let mut candidate = storage.clone();
            candidate.boot = boot.clone();
            resolve_pinned_boot(
                &candidate,
                context.pool,
                context.backend,
                context.native_executable,
            )?;
        }
        None => {
            resolve_pinned_profile(
                &boot,
                context.pool,
                context.backend,
                context.native_executable,
            )?;
        }
    }
    Ok(boot)
}

async fn pin_binding_dependencies(
    binding: &BootBinding,
    context: &CapturedBootContext<'_>,
) -> Result<(), LibVmError> {
    let BootBinding::Pinned {
        kernel,
        base_initramfs,
        agent,
        ..
    } = binding
    else {
        return Err(invalid_capture("persistent boot assets must be pinned"));
    };
    let objects = [
        binding.digest()?,
        *kernel,
        *base_initramfs,
        agent.unwrap_or(*kernel),
    ];
    let objects = &objects[..if agent.is_some() { 4 } else { 3 }];
    for object in objects {
        resolve_boot_object(context.pool, object)?;
    }
    context
        .store
        .pin_published_storage_dependencies(context.operation_id, &[], objects)
        .await
}

async fn publish_binding(
    binding: &BootBinding,
    context: &CapturedBootContext<'_>,
) -> Result<(), LibVmError> {
    let bytes = binding.canonical_bytes()?;
    let input = crate::store::snapshot_store::RecordInput::new(
        context.store.images_path(),
        context.operation_id,
        &bytes,
    )?;
    let (object, roots) = context.pool.publish_object_for_catalog(&input.path())?;
    if object.digest != binding.digest()? {
        return Err(invalid_capture(
            "published boot bundle differs from canonical tuple",
        ));
    }
    context
        .store
        .pin_published_storage_dependencies(context.operation_id, &[], &[object.digest])
        .await?;
    drop(roots);
    Ok(())
}

/// Capture the configured *next* boot, not an unverifiable prior-run selection.
/// No source selection is changed, and no generated source composite is copied.
pub(crate) async fn capture_boot(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
    context: CapturedBootContext<'_>,
    lane: CaptureLane,
) -> Result<BootProfile, LibVmError> {
    let selection = resolve_capture_selection(storage, spec, agent, &context.selection(), lane)?;
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
    } = &*binding
    {
        let _roots = context.pool.lock_roots_shared()?;
        let objects = [
            binding.digest()?,
            *kernel,
            *base_initramfs,
            agent.unwrap_or(*kernel),
        ];
        let count = if agent.is_some() { 4 } else { 3 };
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
        abi: DIRECT_BOOT_ABI.to_owned(),
    };
    publish_binding(binding, &context).await?;
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
        validate_captured_boot_lane, CaptureLane, CapturedBootContext,
    };
    #[cfg(target_os = "linux")]
    use crate::store::ImageStore;

    /// A valid native-format kernel image; never executed.
    #[cfg(target_os = "linux")]
    fn custom_kernel() -> Vec<u8> {
        test_utils::direct_kernel::host_kernel("exact custom kernel")
    }

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
            std::fs::write(&kernel, custom_kernel()).unwrap();
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

        async fn begin_capture(
            &self,
            operation_id: uuid::Uuid,
        ) -> crate::storage::locks::StorageLock {
            let lease = self
                .store
                .begin_storage_operation(operation_id)
                .await
                .unwrap();
            self.pool
                .create_operation_with_lease(operation_id, lease.duplicate().unwrap())
                .unwrap();
            lease
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
        let lease = fixture.begin_capture(operation).await;
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
            CaptureLane::Stopped,
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
            crate::storage::identity::ObjectDigest::of_bytes(&custom_kernel())
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
        assert_eq!(retained_bytes(resolved.assets.kernel()), custom_kernel());
        assert_eq!(
            retained_bytes(resolved.assets.initramfs()),
            b"exact base initramfs"
        );
        assert_eq!(
            retained_bytes(resolved.agent.as_ref().unwrap()),
            b"exact custom agent"
        );
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 4);

        // A second capture retains the already pinned closure without consulting
        // now-missing custom/default installation paths or substituting assets.
        let second = uuid::Uuid::new_v4();
        let second_lease = fixture.begin_capture(second).await;
        assert_eq!(
            capture_boot(
                &captured,
                &fixture.spec,
                &custom,
                fixture.context(second),
                CaptureLane::Stopped
            )
            .await
            .unwrap(),
            boot,
        );
        drop(lease);
        fixture.store.prune_images().await.unwrap();
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 4);
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
        let _lease = fixture.begin_capture(operation).await;
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
            crate::storage::identity::ObjectDigest::of_bytes(&custom_kernel())
        );
        assert_eq!(
            std::fs::read(&fixture.kernel).unwrap(),
            b"replacement kernel"
        );
        fixture.store.prune_images().await.unwrap();
        assert_eq!(
            std::fs::read(fixture.pool.object_path(&digest)).unwrap(),
            custom_kernel()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disabled_agent_requires_only_kernel_and_base_and_never_falls_back() {
        let fixture = CaptureFixture::new().await;
        let operation = uuid::Uuid::new_v4();
        let _lease = fixture.begin_capture(operation).await;
        std::fs::remove_file(&fixture.agent).unwrap();
        let mut storage = fixture.storage.clone();
        storage.boot = capture_boot(
            &storage,
            &fixture.spec,
            &MachineAgent::Disabled,
            fixture.context(operation),
            CaptureLane::Stopped,
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
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 3);
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
        for lane in [CaptureLane::Stopped, CaptureLane::Live] {
            assert!(validate_captured_boot_lane(
                &fixture.storage,
                vm_spec::live::LiveBackend::Mock,
                lane
            )
            .is_err());
            assert!(validate_captured_boot_lane(
                &fixture.storage,
                vm_spec::live::LiveBackend::Krun,
                lane
            )
            .is_ok());
        }
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
                CaptureLane::Stopped,
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
            CaptureLane::Stopped,
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
        assert!(validate_captured_boot_lane(
            &wrong_architecture,
            vm_spec::live::LiveBackend::Krun,
            CaptureLane::Stopped,
        )
        .is_err());
        // A nonempty non-kernel selection fails kernel admission before publication.
        std::fs::write(&fixture.kernel, b"exact custom kernel").unwrap();
        assert!(matches!(
            preflight_captured_boot(
                &fixture.storage,
                &fixture.spec,
                &MachineAgent::Disabled,
                &fixture.context(operation),
                CaptureLane::Stopped,
            ),
            Err(crate::LibVmError::DirectKernelRejected(rejected))
                if rejected.reason == crate::DirectKernelRejection::UnrecognizedFormat
        ));
        std::fs::write(&fixture.kernel, b"").unwrap();
        assert!(preflight_captured_boot(
            &fixture.storage,
            &fixture.spec,
            &MachineAgent::Disabled,
            &fixture.context(operation),
            CaptureLane::Stopped,
        )
        .is_err());
        assert!(capture_boot(
            &fixture.storage,
            &fixture.spec,
            &MachineAgent::Disabled,
            fixture.context(operation),
            CaptureLane::Stopped,
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
        let _lease = fixture.begin_capture(operation).await;
        let mut storage = fixture.storage.clone();
        storage.boot = capture_boot(
            &storage,
            &fixture.spec,
            &MachineAgent::Default,
            fixture.context(operation),
            CaptureLane::Stopped,
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
        let _lease = fixture.begin_capture(operation).await;
        let mut storage = fixture.storage.clone();
        storage.boot = capture_boot(
            &storage,
            &fixture.spec,
            &MachineAgent::Default,
            fixture.context(operation),
            CaptureLane::Stopped,
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
        assert_eq!(std::fs::read(launch_kernel).unwrap(), custom_kernel());
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

    #[test]
    fn vz_creation_admission_names_explicit_conversion_without_capture_qualification() {
        use crate::runtime::boot_assets::{admit_create_source, AdmissionRemedy, SourceFamily};
        let error = admit_create_source(
            SourceFamily::Oci,
            crate::StorageProfile::OpaqueRawV1,
            crate::BackendRequirement::RawBlock,
            vm_spec::live::LiveBackend::Vz,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::BackendAdmissionRejected {
                remedy: AdmissionRemedy::ExplicitOciToRawConversion,
                ..
            }
        ));
        assert!(admit_create_source(
            SourceFamily::ManagedImage,
            crate::StorageProfile::OpaqueRawV1,
            crate::BackendRequirement::RawBlock,
            vm_spec::live::LiveBackend::Vz
        )
        .is_ok());
        assert!(matches!(
            admit_create_source(
                SourceFamily::ManagedImage,
                crate::StorageProfile::LinuxOverlayV1,
                crate::BackendRequirement::KrunOverlay,
                vm_spec::live::LiveBackend::Vz
            ),
            Err(crate::LibVmError::BackendAdmissionRejected {
                remedy: AdmissionRemedy::UseKrun,
                ..
            })
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn partition_boot_admits_stopped_but_not_live_capture() {
        for (table, selector) in [
            (
                crate::PartitionTable::Gpt,
                crate::RootSelector::GptPartition {
                    guid: uuid::Uuid::new_v4(),
                },
            ),
            (
                crate::PartitionTable::Mbr,
                crate::RootSelector::MbrPartition { number: 2 },
            ),
        ] {
            let fixture = CaptureFixture::new().await;
            let (operation, lease) = fixture
                .store
                .begin_stopped_operation("import", &[], &[])
                .await
                .unwrap();
            fixture
                .pool
                .create_operation_with_lease(operation, lease.duplicate().unwrap())
                .unwrap();
            let mut storage = fixture.storage.clone();
            if let crate::MachineRoot::OpaqueRaw { layout, .. } = &mut storage.root {
                *layout = crate::RawLayout::Partitioned { table };
            }
            if let crate::BootProfile::LinuxDirect { root_selector, .. } = &mut storage.boot {
                *root_selector = selector;
            }
            storage.boot = crate::runtime::boot_assets::pin_boot_selection(
                &storage,
                &crate::BootAssetSelection::Packaged,
                fixture.context(operation),
            )
            .await
            .unwrap();
            for backend in [
                vm_spec::live::LiveBackend::Krun,
                vm_spec::live::LiveBackend::Vz,
            ] {
                assert!(
                    resolve_pinned_boot(&storage, &fixture.pool, backend, &fixture.kernel)
                        .unwrap()
                        .is_some()
                );
            }
            assert!(validate_captured_boot_lane(
                &storage,
                vm_spec::live::LiveBackend::Krun,
                CaptureLane::Stopped
            )
            .is_ok());
            assert!(matches!(
                validate_captured_boot_lane(
                    &storage,
                    vm_spec::live::LiveBackend::Krun,
                    CaptureLane::Live
                ),
                Err(crate::LibVmError::InvalidStorageRecord { message, .. })
                    if message.contains("no admitted live capture lane")
            ));
            // Partitioned stopped capture still requires the Linux krun lane.
            assert!(validate_captured_boot_lane(
                &storage,
                vm_spec::live::LiveBackend::Vz,
                CaptureLane::Stopped
            )
            .is_err());
            preflight_captured_boot(
                &storage,
                &fixture.spec,
                &MachineAgent::Default,
                &fixture.context(operation),
                CaptureLane::Stopped,
            )
            .unwrap();
            assert!(preflight_captured_boot(
                &storage,
                &fixture.spec,
                &MachineAgent::Default,
                &fixture.context(operation),
                CaptureLane::Live,
            )
            .is_err());
            let capture = uuid::Uuid::new_v4();
            let _capture_lease = fixture.begin_capture(capture).await;
            assert_eq!(
                capture_boot(
                    &storage,
                    &fixture.spec,
                    &MachineAgent::Default,
                    fixture.context(capture),
                    CaptureLane::Stopped,
                )
                .await
                .unwrap(),
                storage.boot
            );
            assert!(capture_boot(
                &storage,
                &fixture.spec,
                &MachineAgent::Default,
                fixture.context(capture),
                CaptureLane::Live,
            )
            .await
            .is_err());
            let crate::BootProfile::LinuxDirect { binding, .. } = &storage.boot else {
                panic!("direct")
            };
            assert!(fixture
                .pool
                .object_path(&binding.digest().unwrap())
                .is_file());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn translated_and_foreign_roots_have_no_capture_lane() {
        let storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let mut translated = storage.clone();
        if let crate::BootProfile::LinuxDirect {
            userspace_platform,
            kernel_architecture,
            translation,
            ..
        } = &mut translated.boot
        {
            userspace_platform.architecture = crate::GuestArchitecture::Amd64;
            *kernel_architecture = crate::GuestArchitecture::Arm64;
            *translation = crate::Translation::Rosetta;
        }
        for lane in [CaptureLane::Stopped, CaptureLane::Live] {
            assert!(validate_captured_boot_lane(
                &translated,
                vm_spec::live::LiveBackend::Krun,
                lane
            )
            .is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exact_boot_selection_ignores_package_upgrade_and_rejects_missing_bundle() {
        let fixture = CaptureFixture::new().await;
        let (operation, lease) = fixture
            .store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        fixture
            .pool
            .create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let boot = crate::runtime::boot_assets::pin_image_boot(
            &fixture.storage.boot,
            &crate::BootAssetSelection::Packaged,
            fixture.context(operation),
        )
        .await
        .unwrap();
        let crate::BootProfile::LinuxDirect { binding, .. } = &boot else {
            panic!("direct")
        };
        let bundle = binding.digest().unwrap();
        std::fs::write(&fixture.initramfs, b"new package initramfs").unwrap();
        std::fs::remove_file(&fixture.kernel).unwrap();
        let (second, second_lease) = fixture
            .store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        fixture
            .pool
            .create_operation_with_lease(second, second_lease.duplicate().unwrap())
            .unwrap();
        let selected = crate::runtime::boot_assets::pin_image_boot(
            &fixture.storage.boot,
            &crate::BootAssetSelection::Exact { bundle },
            fixture.context(second),
        )
        .await
        .unwrap();
        assert_eq!(selected, boot);
        std::fs::remove_file(fixture.pool.object_path(&bundle)).unwrap();
        assert!(matches!(
            crate::runtime::boot_assets::pin_image_boot(
                &fixture.storage.boot, &crate::BootAssetSelection::Exact { bundle }, fixture.context(second),
            ).await,
            Err(crate::LibVmError::BootAssetsAcquisitionRequired { missing }) if missing == bundle
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unknown_custom_base_abi_is_rejected_before_any_bundle_publication() {
        let fixture = CaptureFixture::new().await;
        let custom = fixture.kernel.with_file_name("unknown-initramfs");
        std::fs::write(&custom, b"unknown bootstrap contract").unwrap();
        let (operation, lease) = fixture
            .store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        fixture
            .pool
            .create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let error = crate::runtime::boot_assets::pin_image_boot(
            &fixture.storage.boot,
            &crate::BootAssetSelection::Files {
                kernel: fixture.kernel.clone(),
                base_initramfs: custom,
                agent: None,
            },
            fixture.context(operation),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::BootBundleAbiUnsupported { .. }
        ));
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_replacement_inspection_does_not_publish_or_change_the_tuple() {
        let fixture = CaptureFixture::new().await;
        let (operation, lease) = fixture
            .store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        fixture
            .pool
            .create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let mut storage = fixture.storage.clone();
        storage.boot = crate::runtime::boot_assets::pin_boot_selection(
            &storage,
            &crate::BootAssetSelection::Packaged,
            fixture.context(operation),
        )
        .await
        .unwrap();
        let original = storage.clone();
        let context = fixture.context(operation);
        assert!(crate::runtime::boot_assets::locally_admitted_replacement(
            &storage,
            &fixture.spec,
            context.selection(),
        )
        .unwrap()
        .is_none());
        let before = fixture.pool.scan_objects().unwrap().count();
        std::fs::write(
            &fixture.kernel,
            test_utils::direct_kernel::host_kernel("new packaged kernel"),
        )
        .unwrap();
        assert!(crate::runtime::boot_assets::locally_admitted_replacement(
            &storage,
            &fixture.spec,
            context.selection(),
        )
        .unwrap()
        .is_some());
        assert_eq!(storage, original);
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), before);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unadmitted_packaged_kernel_is_never_reported_as_a_replacement() {
        let fixture = CaptureFixture::new().await;
        let (operation, _lease) = import_operation(&fixture).await;
        let mut storage = fixture.storage.clone();
        storage.boot = crate::runtime::boot_assets::pin_boot_selection(
            &storage,
            &crate::BootAssetSelection::Packaged,
            fixture.context(operation),
        )
        .await
        .unwrap();
        let before = fixture.pool.scan_objects().unwrap().count();
        std::fs::write(&fixture.kernel, b"new packaged text").unwrap();
        let context = fixture.context(operation);
        assert!(matches!(
            crate::runtime::boot_assets::locally_admitted_replacement(
                &storage,
                &fixture.spec,
                context.selection(),
            ),
            Err(crate::LibVmError::DirectKernelRejected(_))
        ));
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), before);
    }

    #[cfg(target_os = "linux")]
    fn write_private(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(target_os = "linux")]
    async fn import_operation(
        fixture: &CaptureFixture,
    ) -> (uuid::Uuid, crate::storage::locks::StorageLock) {
        let (operation, lease) = fixture
            .store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        fixture
            .pool
            .create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        (operation, lease)
    }

    #[cfg(target_os = "linux")]
    fn rejection(error: crate::LibVmError) -> crate::DirectKernelRejection {
        match error {
            crate::LibVmError::DirectKernelRejected(rejected) => rejected.reason,
            other => panic!("expected direct kernel rejection, got {other}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn raw_import_and_update_reject_unadmitted_kernels_before_publication() {
        use test_utils::direct_kernel::{kernel, KernelArchitecture};
        let fixture = CaptureFixture::new().await;
        let text = fixture.kernel.with_file_name("text-kernel");
        write_private(&text, b"exact custom kernel");
        let foreign = fixture.kernel.with_file_name("foreign-kernel");
        write_private(
            &foreign,
            &kernel(KernelArchitecture::host().opposite(), "foreign"),
        );
        let (operation, _lease) = import_operation(&fixture).await;
        let files = |kernel: &Path| crate::BootAssetSelection::Files {
            kernel: kernel.to_path_buf(),
            base_initramfs: fixture.initramfs.clone(),
            agent: None,
        };
        let expected_foreign = match KernelArchitecture::host() {
            KernelArchitecture::Amd64 => "an arm64 Image",
            KernelArchitecture::Arm64 => "an x86-64 ELF vmlinux",
        };
        for (path, expected) in [
            (&text, crate::DirectKernelRejection::UnrecognizedFormat),
            (
                &foreign,
                crate::DirectKernelRejection::ForeignImage {
                    actual: expected_foreign.into(),
                },
            ),
        ] {
            let error = crate::runtime::boot_assets::pin_image_boot(
                &fixture.storage.boot,
                &files(path),
                fixture.context(operation),
            )
            .await
            .unwrap_err();
            assert_eq!(rejection(error), expected);
            assert_eq!(fixture.pool.scan_objects().unwrap().count(), 0);
        }

        // An explicit stopped update validates the replacement before it can
        // publish anything; the current pinned tuple keeps resolving.
        let mut storage = fixture.storage.clone();
        storage.boot = crate::runtime::boot_assets::pin_boot_selection(
            &storage,
            &crate::BootAssetSelection::Packaged,
            fixture.context(operation),
        )
        .await
        .unwrap();
        let pinned = storage.clone();
        let before = fixture.pool.scan_objects().unwrap().count();
        let (update, _update_lease) = import_operation(&fixture).await;
        for path in [&text, &foreign] {
            let error = crate::runtime::boot_assets::pin_boot_selection(
                &storage,
                &files(path),
                fixture.context(update),
            )
            .await
            .unwrap_err();
            assert!(matches!(error, crate::LibVmError::DirectKernelRejected(_)));
        }
        assert_eq!(storage, pinned);
        assert_eq!(fixture.pool.scan_objects().unwrap().count(), before);
        assert!(resolve_pinned_boot(
            &storage,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .unwrap()
        .is_some());

        // A valid native complete file tuple is admitted.
        let valid = fixture.kernel.with_file_name("valid-kernel");
        write_private(&valid, &test_utils::direct_kernel::host_kernel("valid"));
        let replaced = crate::runtime::boot_assets::pin_boot_selection(
            &storage,
            &files(&valid),
            fixture.context(update),
        )
        .await
        .unwrap();
        let crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { kernel, agent, .. },
            ..
        } = &replaced
        else {
            panic!("replacement must pin a complete tuple");
        };
        assert_eq!(
            *kernel,
            crate::storage::identity::ObjectDigest::of_bytes(
                &test_utils::direct_kernel::host_kernel("valid")
            )
        );
        assert!(agent.is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exact_bundle_with_unadmitted_kernel_fails_import_and_start() {
        let fixture = CaptureFixture::new().await;
        let (operation, _lease) = import_operation(&fixture).await;
        let text = fixture.kernel.with_file_name("text-kernel");
        write_private(&text, b"bundle text kernel");
        let context = fixture.context(operation);
        let kernel = crate::runtime::boot_assets::ingest_boot_object(
            std::fs::File::open(&text).unwrap(),
            &text,
            &context,
        )
        .await
        .unwrap();
        let base_initramfs = crate::runtime::boot_assets::ingest_boot_object(
            std::fs::File::open(&fixture.initramfs).unwrap(),
            &fixture.initramfs,
            &context,
        )
        .await
        .unwrap();
        let crate::BootProfile::LinuxDirect {
            kernel_architecture,
            ..
        } = &fixture.storage.boot
        else {
            panic!("direct boot fixture");
        };
        let binding = crate::BootBinding::Pinned {
            kernel,
            base_initramfs,
            agent: None,
            architecture: *kernel_architecture,
            abi: crate::runtime::boot_assets::DIRECT_BOOT_ABI.into(),
        };
        crate::runtime::boot_assets::publish_binding(&binding, &context)
            .await
            .unwrap();
        let bundle = binding.digest().unwrap();
        let error = crate::runtime::boot_assets::pin_image_boot(
            &fixture.storage.boot,
            &crate::BootAssetSelection::Exact { bundle },
            fixture.context(operation),
        )
        .await
        .unwrap_err();
        assert_eq!(
            rejection(error),
            crate::DirectKernelRejection::UnrecognizedFormat
        );
        let mut storage = fixture.storage.clone();
        if let crate::BootProfile::LinuxDirect {
            binding: target, ..
        } = &mut storage.boot
        {
            *target = binding;
        }
        storage.validate_persistent().unwrap();
        let error = resolve_pinned_boot(
            &storage,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .err()
        .unwrap();
        assert_eq!(
            rejection(error),
            crate::DirectKernelRejection::UnrecognizedFormat
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pinned_start_survives_packaged_asset_removal() {
        let fixture = CaptureFixture::new().await;
        let (operation, _lease) = import_operation(&fixture).await;
        let mut storage = fixture.storage.clone();
        storage.boot = crate::runtime::boot_assets::pin_boot_selection(
            &storage,
            &crate::BootAssetSelection::Packaged,
            fixture.context(operation),
        )
        .await
        .unwrap();
        std::fs::remove_dir_all(fixture.kernel.parent().unwrap()).unwrap();
        let resolved = resolve_pinned_boot(
            &storage,
            &fixture.pool,
            vm_spec::live::LiveBackend::Krun,
            &fixture.kernel,
        )
        .unwrap()
        .unwrap();
        assert_eq!(retained_bytes(resolved.assets.kernel()), custom_kernel());
        assert!(resolved.agent.is_some());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    #[test]
    fn optional_rosetta_needs_actual_capability_and_kernel_must_be_native() {
        let mut storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let mut spec = vm_spec::VmSpec::current();
        spec.hardware = Some(vm_spec::Hardware {
            cpus: None,
            memory: None,
            nested_virtualization: None,
            rosetta: None,
        });
        assert_eq!(
            crate::runtime::boot_assets::effective_boot(
                &storage,
                &spec,
                vm_spec::live::LiveBackend::Krun
            )
            .unwrap()
            .rosetta,
            rootfs_spec::RosettaMode::Disabled
        );
        spec.hardware.as_mut().unwrap().rosetta = Some(false);
        assert_eq!(
            crate::runtime::boot_assets::effective_boot(
                &storage,
                &spec,
                vm_spec::live::LiveBackend::Krun
            )
            .unwrap()
            .rosetta,
            rootfs_spec::RosettaMode::Disabled
        );
        spec.hardware.as_mut().unwrap().rosetta = Some(true);
        assert!(matches!(
            crate::runtime::boot_assets::effective_boot(
                &storage,
                &spec,
                vm_spec::live::LiveBackend::Krun
            ),
            Err(crate::LibVmError::TranslationUnavailable { .. })
        ));
        if let crate::BootProfile::LinuxDirect {
            kernel_architecture,
            ..
        } = &mut storage.boot
        {
            *kernel_architecture = match kernel_architecture {
                crate::GuestArchitecture::Amd64 => crate::GuestArchitecture::Arm64,
                crate::GuestArchitecture::Arm64 => crate::GuestArchitecture::Amd64,
            };
        }
        assert!(crate::runtime::boot_assets::validate_direct_boot(
            &storage,
            vm_spec::live::LiveBackend::Krun
        )
        .is_err());
    }
}
