//! Strict platform, root-selection and pinned boot-bundle DTOs.
//!
//! Wire values are validated here before any native mutation: missing or
//! unknown arms, nil or noncanonical GUIDs, MBR slots outside 1..=4 (checked
//! before narrowing), malformed digests and relative or NUL-containing asset
//! paths never reach libvm. libvm still revalidates semantic combinations.
use crate::{invalid, path_from_wire, path_to_wire, required, ConversionError};
use libvm::storage::identity::ObjectDigest;
use libvm::{
    BootAssetSelection, BootBinding, BootProfile, DirectCommandLinePolicy, DiskImportBoot,
    DiskImportRequest, GuestArchitecture, ImportRootSelection, LinuxPlatform, RootFilesystem,
    RootSelector, Translation,
};
use silod_spec::daemon::v1 as w;

pub fn architecture_to_wire(value: GuestArchitecture) -> i32 {
    match value {
        GuestArchitecture::Amd64 => w::GuestArchitecture::Amd64 as i32,
        GuestArchitecture::Arm64 => w::GuestArchitecture::Arm64 as i32,
    }
}

pub fn architecture_from_wire(
    value: i32,
    field: &'static str,
) -> Result<GuestArchitecture, ConversionError> {
    match w::GuestArchitecture::try_from(value) {
        Ok(w::GuestArchitecture::Amd64) => Ok(GuestArchitecture::Amd64),
        Ok(w::GuestArchitecture::Arm64) => Ok(GuestArchitecture::Arm64),
        _ => Err(invalid(field, "unknown guest architecture")),
    }
}

pub fn platform_to_wire(value: &LinuxPlatform) -> w::LinuxPlatform {
    w::LinuxPlatform {
        architecture: architecture_to_wire(value.architecture),
        variant: value.variant.clone(),
    }
}

pub fn platform_from_wire(value: w::LinuxPlatform) -> Result<LinuxPlatform, ConversionError> {
    let platform = LinuxPlatform {
        architecture: architecture_from_wire(value.architecture, "platform.architecture")?,
        variant: value.variant,
    };
    platform
        .validate()
        .map_err(|_| invalid("platform.variant", "unsupported Linux platform variant"))?;
    Ok(platform)
}

/// Parses the user spelling `[linux/]ARCH[/VARIANT]`. Only the admitted Linux
/// platforms are accepted; nothing is silently dropped.
pub fn parse_platform(value: &str) -> Result<LinuxPlatform, ConversionError> {
    let value = value.strip_prefix("linux/").unwrap_or(value);
    let (architecture, variant) = match value.split_once('/') {
        Some((architecture, variant)) => (architecture, Some(variant)),
        None => (value, None),
    };
    let architecture = match architecture {
        "amd64" | "x86_64" => GuestArchitecture::Amd64,
        "arm64" | "aarch64" => GuestArchitecture::Arm64,
        _ => {
            return Err(invalid(
                "platform",
                "expected linux/amd64 or linux/arm64[/v8]",
            ))
        }
    };
    let platform = LinuxPlatform {
        architecture,
        variant: variant.map(str::to_owned),
    };
    platform
        .validate()
        .map_err(|_| invalid("platform", "unsupported Linux platform variant"))?;
    Ok(platform)
}

/// Selects the platform of an already resolved OCI identity. The manifest and
/// configuration identities stay bound to exactly this platform.
pub fn platform_from_oci(value: &libvm::Platform) -> Result<LinuxPlatform, ConversionError> {
    if value.os != "linux" {
        return Err(invalid("platform.os", "only Linux userspace is admitted"));
    }
    let mut spelling = value.architecture.clone();
    if let Some(variant) = &value.variant {
        spelling.push('/');
        spelling.push_str(variant);
    }
    parse_platform(&spelling)
}

pub fn host_platform() -> Result<LinuxPlatform, ConversionError> {
    parse_platform(std::env::consts::ARCH)
        .map_err(|_| invalid("platform", "host architecture has no native Linux platform"))
}

pub(crate) fn guid_from_wire(
    value: &str,
    field: &'static str,
) -> Result<uuid::Uuid, ConversionError> {
    let guid = uuid::Uuid::parse_str(value).map_err(|_| invalid(field, "invalid GUID"))?;
    if guid.is_nil() {
        return Err(invalid(field, "nil GUID"));
    }
    if guid.hyphenated().to_string() != value {
        return Err(invalid(
            field,
            "GUID is not canonical lowercase hyphenated text",
        ));
    }
    Ok(guid)
}

pub(crate) fn guid_to_wire(
    value: &uuid::Uuid,
    field: &'static str,
) -> Result<String, ConversionError> {
    if value.is_nil() {
        return Err(invalid(field, "nil GUID"));
    }
    Ok(value.hyphenated().to_string())
}

pub(crate) fn mbr_from_wire(value: u32, field: &'static str) -> Result<u8, ConversionError> {
    if !(1..=4).contains(&value) {
        return Err(invalid(field, "MBR primary slot must be 1..4"));
    }
    u8::try_from(value).map_err(|_| invalid(field, "MBR primary slot must be 1..4"))
}

pub(crate) fn mbr_to_wire(value: u8, field: &'static str) -> Result<u32, ConversionError> {
    if !(1..=4).contains(&value) {
        return Err(invalid(field, "MBR primary slot must be 1..4"));
    }
    Ok(u32::from(value))
}

pub fn import_root_to_wire(
    value: &ImportRootSelection,
) -> Result<w::ImportRootSelection, ConversionError> {
    use w::import_root_selection::Selection;
    Ok(w::ImportRootSelection {
        selection: Some(match value {
            ImportRootSelection::WholeDisk => Selection::WholeDisk(()),
            ImportRootSelection::AutoGpt => Selection::AutoGpt(()),
            ImportRootSelection::GptPartition { guid } => {
                Selection::GptPartition(guid_to_wire(guid, "root.gpt_partition")?)
            }
            ImportRootSelection::MbrPartition { number } => {
                Selection::MbrPartition(mbr_to_wire(*number, "root.mbr_partition")?)
            }
        }),
    })
}

pub fn import_root_from_wire(
    value: w::ImportRootSelection,
) -> Result<ImportRootSelection, ConversionError> {
    use w::import_root_selection::Selection;
    Ok(match required(value.selection, "root.selection")? {
        Selection::WholeDisk(()) => ImportRootSelection::WholeDisk,
        Selection::AutoGpt(()) => ImportRootSelection::AutoGpt,
        Selection::GptPartition(guid) => ImportRootSelection::GptPartition {
            guid: guid_from_wire(&guid, "root.gpt_partition")?,
        },
        Selection::MbrPartition(number) => ImportRootSelection::MbrPartition {
            number: mbr_from_wire(number, "root.mbr_partition")?,
        },
    })
}

/// Parses `whole-disk`, `auto`, `gpt:GUID` or `mbr:N` with the wire rules.
pub fn parse_import_root(value: &str) -> Result<ImportRootSelection, ConversionError> {
    match value {
        "whole-disk" => Ok(ImportRootSelection::WholeDisk),
        "auto" => Ok(ImportRootSelection::AutoGpt),
        _ => {
            if let Some(guid) = value.strip_prefix("gpt:") {
                let guid = guid.to_ascii_lowercase();
                return Ok(ImportRootSelection::GptPartition {
                    guid: guid_from_wire(&guid, "root")?,
                });
            }
            if let Some(number) = value.strip_prefix("mbr:") {
                let number = number
                    .parse::<u32>()
                    .map_err(|_| invalid("root", "MBR primary slot must be 1..4"))?;
                return Ok(ImportRootSelection::MbrPartition {
                    number: mbr_from_wire(number, "root")?,
                });
            }
            Err(invalid(
                "root",
                "expected whole-disk, auto, gpt:GUID or mbr:N",
            ))
        }
    }
}

pub fn root_selector_to_wire(value: &RootSelector) -> Result<w::RootSelector, ConversionError> {
    use w::root_selector::Selector;
    Ok(w::RootSelector {
        selector: Some(match value {
            RootSelector::ManagedOverlay => Selector::ManagedOverlay(()),
            RootSelector::WholeDisk => Selector::WholeDisk(()),
            RootSelector::GptPartition { guid } => {
                Selector::GptPartition(guid_to_wire(guid, "root_selector.gpt_partition")?)
            }
            RootSelector::MbrPartition { number } => {
                Selector::MbrPartition(mbr_to_wire(*number, "root_selector.mbr_partition")?)
            }
        }),
    })
}

pub fn root_selector_from_wire(value: w::RootSelector) -> Result<RootSelector, ConversionError> {
    use w::root_selector::Selector;
    Ok(match required(value.selector, "root_selector.selector")? {
        Selector::ManagedOverlay(()) => RootSelector::ManagedOverlay,
        Selector::WholeDisk(()) => RootSelector::WholeDisk,
        Selector::GptPartition(guid) => RootSelector::GptPartition {
            guid: guid_from_wire(&guid, "root_selector.gpt_partition")?,
        },
        Selector::MbrPartition(number) => RootSelector::MbrPartition {
            number: mbr_from_wire(number, "root_selector.mbr_partition")?,
        },
    })
}

/// A candidate is an import-time observation of one GPT or MBR partition,
/// carrying exactly the type identity of its own table.
fn validate_candidate(value: &libvm::RootCandidate) -> Result<(), ConversionError> {
    let consistent = match value.selector {
        RootSelector::GptPartition { .. } => value.gpt_type.is_some() && value.mbr_type.is_none(),
        RootSelector::MbrPartition { .. } => value.gpt_type.is_none() && value.mbr_type.is_some(),
        RootSelector::WholeDisk | RootSelector::ManagedOverlay => false,
    };
    if !consistent || value.length_lbas == 0 {
        return Err(invalid(
            "root_candidate",
            "candidate must be a nonempty GPT or MBR partition with its own type",
        ));
    }
    Ok(())
}

pub fn root_candidate_to_wire(
    value: &libvm::RootCandidate,
) -> Result<w::RootCandidate, ConversionError> {
    validate_candidate(value)?;
    Ok(w::RootCandidate {
        selector: Some(root_selector_to_wire(&value.selector)?),
        first_lba: value.first_lba,
        length_lbas: value.length_lbas,
        gpt_type: value
            .gpt_type
            .as_ref()
            .map(|guid| guid_to_wire(guid, "root_candidate.gpt_type"))
            .transpose()?,
        mbr_type: value.mbr_type.map(u32::from),
        attributes: value.attributes,
    })
}

pub fn root_candidate_from_wire(
    value: w::RootCandidate,
) -> Result<libvm::RootCandidate, ConversionError> {
    let candidate = libvm::RootCandidate {
        selector: root_selector_from_wire(required(value.selector, "root_candidate.selector")?)?,
        first_lba: value.first_lba,
        length_lbas: value.length_lbas,
        gpt_type: value
            .gpt_type
            .map(|guid| guid_from_wire(&guid, "root_candidate.gpt_type"))
            .transpose()?,
        mbr_type: value
            .mbr_type
            .map(|kind| {
                u8::try_from(kind)
                    .map_err(|_| invalid("root_candidate.mbr_type", "exceeds one byte"))
            })
            .transpose()?,
        attributes: value.attributes,
    };
    validate_candidate(&candidate)?;
    Ok(candidate)
}

pub fn root_filesystem_to_wire(value: RootFilesystem) -> i32 {
    match value {
        RootFilesystem::Ext4 => w::RootFilesystem::Ext4 as i32,
    }
}

pub fn root_filesystem_from_wire(value: i32) -> Result<RootFilesystem, ConversionError> {
    match w::RootFilesystem::try_from(value) {
        Ok(w::RootFilesystem::Ext4) => Ok(RootFilesystem::Ext4),
        _ => Err(invalid("root_filesystem", "unsupported root filesystem")),
    }
}

pub fn translation_to_wire(value: Translation) -> i32 {
    match value {
        Translation::None => w::Translation::None as i32,
        Translation::Rosetta => w::Translation::Rosetta as i32,
    }
}

pub fn translation_from_wire(value: i32) -> Result<Translation, ConversionError> {
    match w::Translation::try_from(value) {
        Ok(w::Translation::None) => Ok(Translation::None),
        Ok(w::Translation::Rosetta) => Ok(Translation::Rosetta),
        _ => Err(invalid("translation", "unknown translation")),
    }
}

pub fn digest_from_wire(value: &str, field: &'static str) -> Result<ObjectDigest, ConversionError> {
    value
        .parse()
        .map_err(|_| invalid(field, "invalid lowercase sha256 digest"))
}

fn asset_path_from_wire(
    value: Vec<u8>,
    field: &'static str,
) -> Result<std::path::PathBuf, ConversionError> {
    let path = path_from_wire(value)?;
    if !path.is_absolute() {
        return Err(invalid(field, "must be absolute"));
    }
    Ok(path)
}

pub fn assets_to_wire(
    value: &BootAssetSelection,
) -> Result<w::BootAssetSelection, ConversionError> {
    use w::boot_asset_selection::Selection;
    Ok(w::BootAssetSelection {
        selection: Some(match value {
            BootAssetSelection::Packaged => Selection::Packaged(()),
            BootAssetSelection::Files {
                kernel,
                base_initramfs,
                agent,
            } => {
                for path in [Some(kernel), Some(base_initramfs), agent.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    if !path.is_absolute() {
                        return Err(invalid("boot_assets.files", "must be absolute"));
                    }
                }
                Selection::Files(w::BootAssetFiles {
                    kernel: path_to_wire(kernel),
                    base_initramfs: path_to_wire(base_initramfs),
                    agent: agent.as_deref().map(path_to_wire),
                })
            }
            BootAssetSelection::Exact { bundle } => Selection::ExactBundle(bundle.to_string()),
        }),
    })
}

pub fn assets_from_wire(
    value: w::BootAssetSelection,
) -> Result<BootAssetSelection, ConversionError> {
    use w::boot_asset_selection::Selection;
    Ok(match required(value.selection, "boot_assets.selection")? {
        Selection::Packaged(()) => BootAssetSelection::Packaged,
        Selection::Files(files) => BootAssetSelection::Files {
            kernel: asset_path_from_wire(files.kernel, "boot_assets.kernel")?,
            base_initramfs: asset_path_from_wire(
                files.base_initramfs,
                "boot_assets.base_initramfs",
            )?,
            agent: files
                .agent
                .map(|agent| asset_path_from_wire(agent, "boot_assets.agent"))
                .transpose()?,
        },
        Selection::ExactBundle(bundle) => BootAssetSelection::Exact {
            bundle: digest_from_wire(&bundle, "boot_assets.exact_bundle")?,
        },
    })
}

pub fn import_boot_to_wire(
    value: &DiskImportBoot,
) -> Result<w::disk_import_request::Boot, ConversionError> {
    Ok(match value {
        DiskImportBoot::LinuxDirect {
            platform,
            root,
            assets,
        } => w::disk_import_request::Boot::LinuxDirect(w::LinuxDirectImport {
            platform: Some(platform_to_wire(platform)),
            root: Some(import_root_to_wire(root)?),
            assets: Some(assets_to_wire(assets)?),
        }),
    })
}

pub fn import_boot_from_wire(
    value: w::disk_import_request::Boot,
) -> Result<DiskImportBoot, ConversionError> {
    Ok(match value {
        w::disk_import_request::Boot::LinuxDirect(boot) => DiskImportBoot::LinuxDirect {
            platform: platform_from_wire(required(boot.platform, "import.boot.platform")?)?,
            root: import_root_from_wire(required(boot.root, "import.boot.root")?)?,
            assets: assets_from_wire(required(boot.assets, "import.boot.assets")?)?,
        },
    })
}

pub fn import_request_to_wire(
    value: &DiskImportRequest,
) -> Result<w::DiskImportRequest, ConversionError> {
    if !value.path.is_absolute() {
        return Err(invalid("import.path", "must be absolute"));
    }
    if let Some(alias) = &value.alias {
        crate::stopped::alias(alias)?;
    }
    Ok(w::DiskImportRequest {
        path: path_to_wire(&value.path),
        boot: Some(import_boot_to_wire(&value.boot)?),
        alias: value.alias.clone(),
    })
}

pub fn import_request_from_wire(
    value: w::DiskImportRequest,
) -> Result<DiskImportRequest, ConversionError> {
    let path = path_from_wire(value.path)?;
    if !path.is_absolute() {
        return Err(invalid("import.path", "must be absolute"));
    }
    Ok(DiskImportRequest {
        path,
        boot: import_boot_from_wire(required(value.boot, "import.boot")?)?,
        alias: value
            .alias
            .map(|alias| crate::stopped::alias(&alias))
            .transpose()?,
    })
}

/// Projects the persisted pinned Linux direct boot meaning. Runtime-selected
/// bindings and non-direct profiles are never presented as pinned boot state.
pub fn boot_profile_to_wire(value: &BootProfile) -> Result<w::LinuxDirectBoot, ConversionError> {
    let BootProfile::LinuxDirect {
        userspace_platform,
        kernel_architecture,
        command_line_policy: DirectCommandLinePolicy::SiloDirectV1,
        binding,
        root_selector,
        root_filesystem,
        translation,
    } = value
    else {
        return Err(invalid("boot", "only Linux direct boot is admitted"));
    };
    value
        .validate()
        .map_err(|_| invalid("boot", "inconsistent boot profile"))?;
    let BootBinding::Pinned {
        kernel,
        base_initramfs,
        agent,
        architecture,
        abi,
    } = binding
    else {
        return Err(invalid("boot.bundle", "boot bundle is not pinned"));
    };
    Ok(w::LinuxDirectBoot {
        userspace_platform: Some(platform_to_wire(userspace_platform)),
        kernel_architecture: architecture_to_wire(*kernel_architecture),
        bundle: Some(w::PinnedBootBundle {
            digest: binding
                .digest()
                .map_err(|_| invalid("boot.bundle", "boot bundle is not canonical"))?
                .to_string(),
            kernel: kernel.to_string(),
            base_initramfs: base_initramfs.to_string(),
            agent: agent.map(|agent| agent.to_string()),
            architecture: architecture_to_wire(*architecture),
            abi: abi.clone(),
        }),
        root_selector: Some(root_selector_to_wire(root_selector)?),
        root_filesystem: root_filesystem_to_wire(*root_filesystem),
        translation: translation_to_wire(*translation),
    })
}

pub fn boot_profile_from_wire(value: w::LinuxDirectBoot) -> Result<BootProfile, ConversionError> {
    let bundle = required(value.bundle, "boot.bundle")?;
    let binding = BootBinding::Pinned {
        kernel: digest_from_wire(&bundle.kernel, "boot.bundle.kernel")?,
        base_initramfs: digest_from_wire(&bundle.base_initramfs, "boot.bundle.base_initramfs")?,
        agent: bundle
            .agent
            .map(|agent| digest_from_wire(&agent, "boot.bundle.agent"))
            .transpose()?,
        architecture: architecture_from_wire(bundle.architecture, "boot.bundle.architecture")?,
        abi: bundle.abi,
    };
    let digest = binding
        .digest()
        .map_err(|_| invalid("boot.bundle", "boot bundle is not canonical"))?;
    if digest != digest_from_wire(&bundle.digest, "boot.bundle.digest")? {
        return Err(invalid(
            "boot.bundle.digest",
            "does not match the pinned tuple",
        ));
    }
    let profile = BootProfile::LinuxDirect {
        userspace_platform: platform_from_wire(required(
            value.userspace_platform,
            "boot.userspace_platform",
        )?)?,
        kernel_architecture: architecture_from_wire(
            value.kernel_architecture,
            "boot.kernel_architecture",
        )?,
        command_line_policy: DirectCommandLinePolicy::SiloDirectV1,
        binding,
        root_selector: root_selector_from_wire(required(
            value.root_selector,
            "boot.root_selector",
        )?)?,
        root_filesystem: root_filesystem_from_wire(value.root_filesystem)?,
        translation: translation_from_wire(value.translation)?,
    };
    profile
        .validate()
        .map_err(|_| invalid("boot", "inconsistent boot profile"))?;
    Ok(profile)
}

pub fn machine_boot_to_wire(
    profile: Option<&BootProfile>,
    replacement: Option<&ObjectDigest>,
) -> Result<Option<w::MachineBoot>, ConversionError> {
    match profile {
        Some(profile) => Ok(Some(w::MachineBoot {
            linux_direct: Some(boot_profile_to_wire(profile)?),
            packaged_replacement: replacement.map(ToString::to_string),
        })),
        None if replacement.is_some() => Err(invalid(
            "boot.packaged_replacement",
            "replacement without a pinned boot profile",
        )),
        None => Ok(None),
    }
}

pub fn machine_boot_from_wire(
    value: Option<w::MachineBoot>,
) -> Result<(Option<BootProfile>, Option<ObjectDigest>), ConversionError> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    let profile = boot_profile_from_wire(required(value.linux_direct, "boot.linux_direct")?)?;
    let replacement = value
        .packaged_replacement
        .map(|digest| digest_from_wire(&digest, "boot.packaged_replacement"))
        .transpose()?;
    Ok((Some(profile), replacement))
}

pub fn update_boot_assets_to_wire(
    machine: &libvm::MachineRef,
    value: &libvm::BootAssetsUpdate,
) -> Result<w::UpdateBootAssetsRequest, ConversionError> {
    Ok(w::UpdateBootAssetsRequest {
        machine: Some(crate::lifecycle::reference_to_wire(machine)?),
        selection: Some(assets_to_wire(&value.selection)?),
    })
}

pub fn update_boot_assets_from_wire(
    value: w::UpdateBootAssetsRequest,
) -> Result<(libvm::MachineRef, libvm::BootAssetsUpdate), ConversionError> {
    Ok((
        crate::lifecycle::reference_from_wire(required(value.machine, "boot_update.machine")?)?,
        libvm::BootAssetsUpdate {
            selection: assets_from_wire(required(value.selection, "boot_update.selection")?)?,
        },
    ))
}

#[cfg(test)]
mod tests {
    use crate::boot::*;

    const GUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    fn digest(byte: &str) -> ObjectDigest {
        format!("sha256:{}", byte.repeat(32)).parse().unwrap()
    }

    fn pinned_profile() -> BootProfile {
        BootProfile::LinuxDirect {
            userspace_platform: LinuxPlatform {
                architecture: GuestArchitecture::Arm64,
                variant: Some("v8".into()),
            },
            kernel_architecture: GuestArchitecture::Arm64,
            command_line_policy: DirectCommandLinePolicy::SiloDirectV1,
            binding: BootBinding::Pinned {
                kernel: digest("01"),
                base_initramfs: digest("02"),
                agent: None,
                architecture: GuestArchitecture::Arm64,
                abi: "silo-direct-v1".into(),
            },
            root_selector: RootSelector::GptPartition {
                guid: GUID.parse().unwrap(),
            },
            root_filesystem: RootFilesystem::Ext4,
            translation: Translation::None,
        }
    }

    #[test]
    fn root_selection_rejects_nil_noncanonical_and_out_of_range_before_narrowing() {
        use w::import_root_selection::Selection;
        let wire = |selection| w::ImportRootSelection {
            selection: Some(selection),
        };
        assert_eq!(
            import_root_from_wire(wire(Selection::GptPartition(GUID.into()))).unwrap(),
            ImportRootSelection::GptPartition {
                guid: GUID.parse().unwrap()
            }
        );
        for invalid in [
            Selection::GptPartition("00000000-0000-0000-0000-000000000000".into()),
            Selection::GptPartition(GUID.to_ascii_uppercase()),
            Selection::GptPartition(GUID.replace('-', "")),
            Selection::GptPartition(format!("{{{GUID}}}")),
            Selection::MbrPartition(0),
            Selection::MbrPartition(5),
            Selection::MbrPartition(256 + 1),
            Selection::MbrPartition(u32::MAX),
        ] {
            assert!(
                import_root_from_wire(wire(invalid.clone())).is_err(),
                "{invalid:?}"
            );
        }
        assert!(import_root_from_wire(w::ImportRootSelection { selection: None }).is_err());
        for number in 1..=4u8 {
            let value = ImportRootSelection::MbrPartition { number };
            assert_eq!(
                import_root_from_wire(import_root_to_wire(&value).unwrap()).unwrap(),
                value
            );
        }
        assert!(import_root_to_wire(&ImportRootSelection::MbrPartition { number: 0 }).is_err());
        assert!(root_selector_to_wire(&RootSelector::GptPartition {
            guid: uuid::Uuid::nil()
        })
        .is_err());
        assert_eq!(
            parse_import_root(&format!("gpt:{}", GUID.to_ascii_uppercase())).unwrap(),
            ImportRootSelection::GptPartition {
                guid: GUID.parse().unwrap()
            }
        );
        assert!(parse_import_root("mbr:01x").is_err());
    }

    #[test]
    fn platforms_are_closed_and_never_drop_a_variant() {
        assert_eq!(
            parse_platform("linux/arm64/v8").unwrap(),
            LinuxPlatform {
                architecture: GuestArchitecture::Arm64,
                variant: Some("v8".into())
            }
        );
        assert_eq!(
            parse_platform("x86_64").unwrap().architecture,
            GuestArchitecture::Amd64
        );
        for invalid in [
            "linux/amd64/v2",
            "linux/arm64/v7",
            "linux/s390x",
            "darwin/arm64",
            "",
        ] {
            assert!(parse_platform(invalid).is_err(), "{invalid}");
        }
        assert!(platform_from_wire(w::LinuxPlatform {
            architecture: 0,
            variant: None
        })
        .is_err());
        assert!(platform_from_wire(w::LinuxPlatform {
            architecture: w::GuestArchitecture::Amd64 as i32,
            variant: Some("v8".into())
        })
        .is_err());
        let oci = libvm::Platform {
            os: "linux".into(),
            architecture: "arm64".into(),
            variant: Some("v8".into()),
        };
        assert_eq!(
            platform_from_oci(&oci).unwrap(),
            parse_platform("arm64/v8").unwrap()
        );
        let windows = libvm::Platform {
            os: "windows".into(),
            ..oci
        };
        assert!(platform_from_oci(&windows).is_err());
    }

    #[test]
    fn import_requests_require_complete_typed_boot_metadata() {
        let request = DiskImportRequest {
            path: "/images/cloud.qcow2".into(),
            boot: DiskImportBoot::LinuxDirect {
                platform: parse_platform("amd64").unwrap(),
                root: ImportRootSelection::AutoGpt,
                assets: BootAssetSelection::Files {
                    kernel: "/boot/vmlinux".into(),
                    base_initramfs: "/boot/initramfs".into(),
                    agent: None,
                },
            },
            alias: Some("cloud".into()),
        };
        let wire = import_request_to_wire(&request).unwrap();
        assert_eq!(import_request_from_wire(wire.clone()).unwrap(), request);
        let mut missing = wire.clone();
        missing.boot = None;
        assert!(import_request_from_wire(missing).is_err());
        let w::disk_import_request::Boot::LinuxDirect(direct) = wire.boot.clone().unwrap();
        for field in ["platform", "root", "assets"] {
            let mut direct = direct.clone();
            match field {
                "platform" => direct.platform = None,
                "root" => direct.root = None,
                _ => direct.assets = None,
            }
            let mut incomplete = wire.clone();
            incomplete.boot = Some(w::disk_import_request::Boot::LinuxDirect(direct));
            assert!(import_request_from_wire(incomplete).is_err(), "{field}");
        }
        let mut relative = wire.clone();
        relative.path = b"cloud.qcow2".to_vec();
        assert!(import_request_from_wire(relative).is_err());
        let mut bad_alias = wire.clone();
        bad_alias.alias = Some("sha256:abc".into());
        assert!(import_request_from_wire(bad_alias).is_err());
        let relative_asset = w::BootAssetSelection {
            selection: Some(w::boot_asset_selection::Selection::Files(
                w::BootAssetFiles {
                    kernel: b"vmlinux".to_vec(),
                    base_initramfs: b"/boot/initramfs".to_vec(),
                    agent: None,
                },
            )),
        };
        assert!(assets_from_wire(relative_asset).is_err());
        let bad_digest = w::BootAssetSelection {
            selection: Some(w::boot_asset_selection::Selection::ExactBundle(
                "sha256:XYZ".into(),
            )),
        };
        assert!(assets_from_wire(bad_digest).is_err());
        assert!(assets_from_wire(w::BootAssetSelection { selection: None }).is_err());
    }

    #[test]
    fn pinned_boot_inspection_round_trips_and_authenticates_the_bundle() {
        let profile = pinned_profile();
        let replacement = digest("03");
        let wire = machine_boot_to_wire(Some(&profile), Some(&replacement))
            .unwrap()
            .unwrap();
        assert_eq!(
            machine_boot_from_wire(Some(wire.clone())).unwrap(),
            (Some(profile.clone()), Some(replacement))
        );
        assert_eq!(machine_boot_from_wire(None).unwrap(), (None, None));
        assert!(machine_boot_to_wire(None, Some(&replacement)).is_err());
        let mut tampered = wire.clone();
        tampered
            .linux_direct
            .as_mut()
            .unwrap()
            .bundle
            .as_mut()
            .unwrap()
            .kernel = digest("09").to_string();
        assert!(machine_boot_from_wire(Some(tampered)).is_err());
        let mut filesystem = wire.clone();
        filesystem.linux_direct.as_mut().unwrap().root_filesystem = 99;
        assert!(machine_boot_from_wire(Some(filesystem)).is_err());
        let mut translation = wire.clone();
        translation.linux_direct.as_mut().unwrap().translation = w::Translation::Rosetta as i32;
        assert!(machine_boot_from_wire(Some(translation)).is_err());
        let mut missing = wire;
        missing.linux_direct.as_mut().unwrap().root_selector = None;
        assert!(machine_boot_from_wire(Some(missing)).is_err());
        let BootProfile::LinuxDirect {
            userspace_platform,
            kernel_architecture,
            command_line_policy,
            root_selector,
            root_filesystem,
            translation,
            ..
        } = profile
        else {
            unreachable!()
        };
        let runtime_selected = BootProfile::LinuxDirect {
            userspace_platform,
            kernel_architecture,
            command_line_policy,
            binding: BootBinding::RuntimeSelected,
            root_selector,
            root_filesystem,
            translation,
        };
        assert!(boot_profile_to_wire(&runtime_selected).is_err());
    }

    #[test]
    fn root_candidates_carry_exactly_their_own_table_type() {
        let gpt = libvm::RootCandidate {
            selector: RootSelector::GptPartition {
                guid: GUID.parse().unwrap(),
            },
            first_lba: 2048,
            length_lbas: 4096,
            gpt_type: Some(GUID.parse().unwrap()),
            mbr_type: None,
            attributes: 1 << 60,
        };
        assert_eq!(
            root_candidate_from_wire(root_candidate_to_wire(&gpt).unwrap()).unwrap(),
            gpt
        );
        let mut mixed = gpt.clone();
        mixed.mbr_type = Some(0x83);
        assert!(root_candidate_to_wire(&mixed).is_err());
        let mut empty = gpt.clone();
        empty.length_lbas = 0;
        assert!(root_candidate_to_wire(&empty).is_err());
        let mut wire = root_candidate_to_wire(&gpt).unwrap();
        wire.selector =
            Some(root_selector_to_wire(&RootSelector::MbrPartition { number: 1 }).unwrap());
        wire.gpt_type = None;
        wire.mbr_type = Some(256);
        assert!(root_candidate_from_wire(wire).is_err());
    }
}
