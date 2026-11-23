//! Strict storage-artifact management DTOs, separate from machine observations.
use crate::{invalid, path_from_wire, path_to_wire, required, ConversionError};
use libvm::{
    ExternalResourceKey, ExternalResourceMapping, ExternalResourcePolicy, SnapshotInfo,
    SnapshotMemory, SnapshotRef, SnapshotRemoval,
};
use silod_spec::daemon::v1 as w;

fn export_path(path: &std::path::Path, field: &'static str) -> Result<(), ConversionError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(invalid(field, "must name an absolute output file"));
    }
    Ok(())
}

pub fn raw_export_request_to_wire(
    machine: &libvm::MachineRef,
    options: &libvm::RawDiskExportOptions,
) -> Result<w::ExportRawDiskRequest, ConversionError> {
    export_path(&options.destination, "export.destination")?;
    let value = w::ExportRawDiskRequest {
        machine: Some(crate::lifecycle::reference_to_wire(machine)?),
        destination: path_to_wire(&options.destination),
        format: w::DiskFormat::Raw as i32,
        flatten_filesystem: options.flatten_filesystem,
    };
    Ok(value)
}

pub fn raw_export_request_from_wire(
    value: w::ExportRawDiskRequest,
) -> Result<(libvm::MachineRef, libvm::RawDiskExportOptions), ConversionError> {
    if value.format != w::DiskFormat::Raw as i32 {
        return Err(invalid("export.format", "raw format must be explicit"));
    }
    let destination = path_from_wire(value.destination)?;
    export_path(&destination, "export.destination")?;
    Ok((
        crate::lifecycle::reference_from_wire(required(value.machine, "export.machine")?)?,
        libvm::RawDiskExportOptions {
            destination,
            flatten_filesystem: value.flatten_filesystem,
        },
    ))
}

pub fn raw_export_to_wire(
    value: &libvm::RawDiskExport,
) -> Result<w::RawDiskExport, ConversionError> {
    use w::raw_disk_export::Kind;
    value
        .geometry
        .validate()
        .map_err(|_| invalid("export.geometry", "invalid geometry"))?;
    Ok(w::RawDiskExport {
        path: path_to_wire(&value.path),
        metadata_path: path_to_wire(&value.metadata_path),
        geometry: Some(w::DiskGeometry {
            length: value.geometry.length,
            logical_sector_size: value.geometry.logical_sector_size,
        }),
        boot: Some(crate::boot::boot_profile_to_wire(&value.boot)?),
        kind: Some(match &value.kind {
            libvm::RawDiskExportKind::OpaqueExact => Kind::OpaqueExact(()),
            libvm::RawDiskExportKind::FlattenedFilesystem { filesystem_uuid } => {
                Kind::FlattenedFilesystemUuid(filesystem_uuid.to_string())
            }
        }),
    })
}

pub fn raw_export_from_wire(
    value: w::RawDiskExport,
) -> Result<libvm::RawDiskExport, ConversionError> {
    use w::raw_disk_export::Kind;
    let geometry = required(value.geometry, "export.geometry")?;
    let geometry = vm_spec::DiskGeometry {
        length: geometry.length,
        logical_sector_size: geometry.logical_sector_size,
    };
    geometry
        .validate()
        .map_err(|_| invalid("export.geometry", "invalid geometry"))?;
    let kind = match required(value.kind, "export.kind")? {
        Kind::OpaqueExact(()) => libvm::RawDiskExportKind::OpaqueExact,
        Kind::FlattenedFilesystemUuid(value) => {
            let filesystem_uuid = uuid::Uuid::parse_str(&value)
                .map_err(|_| invalid("export.filesystem_uuid", "invalid UUID"))?;
            if filesystem_uuid.is_nil() {
                return Err(invalid("export.filesystem_uuid", "nil UUID"));
            }
            libvm::RawDiskExportKind::FlattenedFilesystem { filesystem_uuid }
        }
    };
    let path = path_from_wire(value.path)?;
    let metadata_path = path_from_wire(value.metadata_path)?;
    export_path(&path, "export.path")?;
    export_path(&metadata_path, "export.metadata_path")?;
    if path == metadata_path {
        return Err(invalid(
            "export.metadata_path",
            "must differ from the disk path",
        ));
    }
    Ok(libvm::RawDiskExport {
        path,
        metadata_path,
        geometry,
        boot: crate::boot::boot_profile_from_wire(required(value.boot, "export.boot")?)?,
        kind,
    })
}

pub fn name(value: Option<String>) -> Result<Option<String>, ConversionError> {
    if let Some(value) = &value {
        libvm::validate_new_machine_name(value)
            .map_err(|_| invalid("name", "invalid machine name"))?;
    }
    Ok(value)
}

pub fn reference_to_wire(value: &SnapshotRef) -> w::StorageSnapshotRef {
    use w::storage_snapshot_ref::Reference;
    w::StorageSnapshotRef {
        reference: Some(match value {
            SnapshotRef::Id(id) => Reference::Id(id.to_string()),
            SnapshotRef::Name(name) => Reference::Name(name.clone()),
        }),
    }
}

/// A name is a local name, pulled registry reference or unique id prefix; a
/// full id travels only as `id`.
pub fn reference_from_wire(value: w::StorageSnapshotRef) -> Result<SnapshotRef, ConversionError> {
    use w::storage_snapshot_ref::Reference;
    match required(value.reference, "snapshot.reference")? {
        Reference::Id(id) => {
            Ok(SnapshotRef::Id(id.parse().map_err(|_| {
                invalid("snapshot.id", "invalid snapshot identity")
            })?))
        }
        Reference::Name(name) => {
            registry_reference(&name)?;
            match name.parse::<SnapshotRef>() {
                Ok(reference @ SnapshotRef::Name(_)) => Ok(reference),
                _ => Err(invalid("snapshot.name", "invalid snapshot name")),
            }
        }
    }
}

fn registry_reference(value: &str) -> Result<(), ConversionError> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(invalid("snapshot.reference", "empty, oversized or NUL"));
    }
    Ok(())
}

pub fn snapshot_request_to_wire(
    machine: &libvm::MachineRef,
    options: &libvm::SnapshotOptions,
) -> Result<w::CreateSnapshotRequest, ConversionError> {
    let wire = w::CreateSnapshotRequest {
        machine: Some(crate::lifecycle::reference_to_wire(machine)?),
        name: options.name.clone(),
        memory: options.memory,
        preserve: options.preserve,
        capture_policy: options.capture_policy.map(crate::capture::policy_to_wire),
        dirty_crossover_percent: options.dirty_crossover_percent.map(u32::from),
        external_requirements: options.external_requirements,
    };
    snapshot_request_from_wire(wire.clone())?;
    Ok(wire)
}

/// Option combinations (memory-only options, external requirements with
/// memory) are libvm's to refuse; this checks each value's grammar.
pub fn snapshot_request_from_wire(
    value: w::CreateSnapshotRequest,
) -> Result<(libvm::MachineRef, libvm::SnapshotOptions), ConversionError> {
    Ok((
        crate::lifecycle::reference_from_wire(required(value.machine, "snapshot.machine")?)?,
        libvm::SnapshotOptions {
            name: value.name.as_deref().map(crate::local_name).transpose()?,
            memory: value.memory,
            preserve: value.preserve,
            capture_policy: value
                .capture_policy
                .map(crate::capture::policy_from_wire)
                .transpose()?,
            dirty_crossover_percent: value
                .dirty_crossover_percent
                .map(crate::capture::crossover_from_wire)
                .transpose()?,
            external_requirements: value.external_requirements,
        },
    ))
}

pub fn restore_request_to_wire(
    source: &libvm::RestoreSource,
    options: &libvm::RestoreOptions,
) -> Result<w::RestoreSnapshotRequest, ConversionError> {
    use w::restore_snapshot_request::Source;
    let wire = w::RestoreSnapshotRequest {
        source: Some(match source {
            libvm::RestoreSource::Local(reference) => {
                Source::Snapshot(reference_to_wire(reference))
            }
            libvm::RestoreSource::Registry(reference) => {
                Source::RegistryReference(reference.clone())
            }
        }),
        name: options.name.clone(),
        external_resources: Some(policy_to_wire(&options.external_resources)),
        activation_hook: options
            .activation_hook
            .as_ref()
            .map(hook_to_wire)
            .transpose()?,
        pull_policy: crate::images::pull_policy_to_wire(options.pull),
        without_memory: options.without_memory,
    };
    restore_request_from_wire(wire.clone())?;
    Ok(wire)
}

pub fn restore_request_from_wire(
    value: w::RestoreSnapshotRequest,
) -> Result<(libvm::RestoreSource, libvm::RestoreOptions), ConversionError> {
    use w::restore_snapshot_request::Source;
    let source = match required(value.source, "restore.source")? {
        Source::Snapshot(reference) => libvm::RestoreSource::Local(reference_from_wire(reference)?),
        Source::RegistryReference(reference) => {
            registry_reference(&reference)?;
            libvm::RestoreSource::Registry(reference)
        }
    };
    Ok((
        source,
        libvm::RestoreOptions {
            name: name(value.name)?,
            pull: crate::images::pull_policy_from_wire(value.pull_policy)?,
            without_memory: value.without_memory,
            activation_hook: value.activation_hook.map(hook_from_wire).transpose()?,
            external_resources: policy_from_wire(required(
                value.external_resources,
                "restore.external_resources",
            )?)?,
        },
    ))
}

fn key_to_wire(value: &ExternalResourceKey) -> w::ExternalResourceKey {
    use w::external_resource_key::Resource;
    w::ExternalResourceKey {
        resource: Some(match value {
            ExternalResourceKey::Disk { order } => Resource::DiskOrder(*order),
            ExternalResourceKey::Share { tag } => Resource::ShareTag(tag.clone()),
        }),
    }
}
pub fn resource_key(resource: ExternalResourceKey) -> Result<ExternalResourceKey, ConversionError> {
    let requirement = libvm::ExternalResourceRequirement {
        resource,
        read_only: false,
    };
    requirement
        .validate()
        .map_err(|_| invalid("resource.key", "invalid external resource key"))?;
    Ok(requirement.resource)
}
fn key_from_wire(value: w::ExternalResourceKey) -> Result<ExternalResourceKey, ConversionError> {
    use w::external_resource_key::Resource;
    resource_key(match required(value.resource, "resource.key")? {
        Resource::DiskOrder(order) => ExternalResourceKey::Disk { order },
        Resource::ShareTag(tag) => ExternalResourceKey::Share { tag },
    })
}

pub fn policy_to_wire(value: &ExternalResourcePolicy) -> w::ExternalResourcePolicy {
    use w::external_resource_policy::Policy;
    w::ExternalResourcePolicy {
        policy: Some(match value {
            ExternalResourcePolicy::Reject => Policy::Reject(()),
            ExternalResourcePolicy::RequireMappings => Policy::RequireMappings(()),
            ExternalResourcePolicy::Map { mappings } => {
                Policy::Mappings(w::ExternalResourceMappings {
                    values: mappings
                        .iter()
                        .map(|mapping| w::ExternalResourceMapping {
                            resource: Some(key_to_wire(&mapping.resource)),
                            path: path_to_wire(&mapping.path),
                        })
                        .collect(),
                })
            }
        }),
    }
}

pub fn policy_from_wire(
    value: w::ExternalResourcePolicy,
) -> Result<ExternalResourcePolicy, ConversionError> {
    use w::external_resource_policy::Policy;
    match required(value.policy, "external_resources.policy")? {
        Policy::Reject(()) => Ok(ExternalResourcePolicy::Reject),
        Policy::RequireMappings(()) => Ok(ExternalResourcePolicy::RequireMappings),
        Policy::Mappings(value) => {
            if value.values.is_empty() || value.values.len() > 256 {
                return Err(invalid(
                    "external_resources.mappings",
                    "expected 1..=256 mappings",
                ));
            }
            let mut mappings = Vec::with_capacity(value.values.len());
            for value in value.values {
                let resource = key_from_wire(required(value.resource, "mapping.resource")?)?;
                if mappings
                    .iter()
                    .any(|v: &ExternalResourceMapping| v.resource == resource)
                {
                    return Err(invalid(
                        "external_resources.mappings",
                        "duplicate resource mapping",
                    ));
                }
                let path = path_from_wire(value.path)?;
                if !path.is_absolute() {
                    return Err(invalid(
                        "mapping.path",
                        "expected absolute destination path",
                    ));
                }
                mappings.push(ExternalResourceMapping { resource, path });
            }
            Ok(ExternalResourcePolicy::Map { mappings })
        }
    }
}
pub fn hook_to_wire(
    value: &libvm::RestoreHook,
) -> Result<w::RestoreActivationHook, ConversionError> {
    value.validate().map_err(|_| {
        invalid(
            "activation_hook",
            "invalid command, environment, directory or timeout",
        )
    })?;
    Ok(w::RestoreActivationHook {
        argv: value.argv.clone(),
        environment: value
            .environment
            .iter()
            .map(|variable| w::EnvironmentPair {
                name: variable.name.clone(),
                value: variable.value.clone(),
            })
            .collect(),
        working_directory: value.working_directory.clone(),
        timeout_ms: Some(value.timeout_ms),
    })
}

pub fn hook_from_wire(
    value: w::RestoreActivationHook,
) -> Result<libvm::RestoreHook, ConversionError> {
    let hook = libvm::RestoreHook {
        argv: value.argv,
        environment: value
            .environment
            .into_iter()
            .map(|variable| libvm::RestoreEnvironmentVariable {
                name: variable.name,
                value: variable.value,
            })
            .collect(),
        working_directory: value.working_directory,
        timeout_ms: required(value.timeout_ms, "activation_hook.timeout_ms")?,
    };
    hook.validate().map_err(|_| {
        invalid(
            "activation_hook",
            "invalid command, environment, directory or timeout",
        )
    })?;
    Ok(hook)
}

pub fn info_to_wire(value: &SnapshotInfo) -> Result<w::StorageSnapshotInfo, ConversionError> {
    let result = w::StorageSnapshotInfo {
        id: value.id.to_string(),
        record_digest: value.record_digest.to_string(),
        names: value.names.clone(),
        created_at: Some(value.created_at),
        streams: value
            .streams
            .iter()
            .map(crate::snapshots::stream_summary_to_wire)
            .collect(),
        memory: memory_to_wire(value.memory),
        provenance: value
            .provenance
            .iter()
            .map(|provenance| w::SnapshotCaptureProvenance {
                capture_id: provenance.capture_id.to_string(),
                machine_id: provenance.machine_id.to_string(),
                run_id: provenance.run_id.to_string(),
                evidence_digest: provenance.evidence_digest.to_string(),
            })
            .collect(),
    };
    info_from_wire(result.clone())?;
    Ok(result)
}

fn memory_to_wire(value: SnapshotMemory) -> i32 {
    (match value {
        SnapshotMemory::None => w::SnapshotMemory::None,
        SnapshotMemory::Included => w::SnapshotMemory::Included,
    }) as i32
}

pub fn info_from_wire(value: w::StorageSnapshotInfo) -> Result<SnapshotInfo, ConversionError> {
    let memory = match w::SnapshotMemory::try_from(value.memory) {
        Ok(w::SnapshotMemory::None) => SnapshotMemory::None,
        Ok(w::SnapshotMemory::Included) => SnapshotMemory::Included,
        _ => return Err(invalid("snapshot.memory", "expected none or included")),
    };
    if value.streams.len() > 4096 {
        return Err(invalid("snapshot.streams", "too many stream summaries"));
    }
    let created_at = required(value.created_at, "snapshot.created_at")?;
    if !(0..=9_007_199_254_740_991).contains(&created_at) {
        return Err(invalid("snapshot.created_at", "invalid timestamp"));
    }
    // Provenance is evidence of memory captures only.
    if value.provenance.len() > 4096
        || (memory == SnapshotMemory::None && !value.provenance.is_empty())
    {
        return Err(invalid(
            "snapshot.provenance",
            "unexpected capture provenance",
        ));
    }
    let provenance = value
        .provenance
        .into_iter()
        .map(|provenance| {
            let uuid = |field: &'static str, value: &str| {
                crate::validate_uuid(value, field)?;
                uuid::Uuid::parse_str(value).map_err(|_| invalid(field, "invalid UUID"))
            };
            Ok(libvm::SnapshotCaptureProvenance {
                capture_id: uuid("snapshot.provenance.capture_id", &provenance.capture_id)?,
                machine_id: uuid("snapshot.provenance.machine_id", &provenance.machine_id)?,
                run_id: uuid("snapshot.provenance.run_id", &provenance.run_id)?,
                evidence_digest: provenance.evidence_digest.parse().map_err(|_| {
                    invalid(
                        "snapshot.provenance.evidence_digest",
                        "invalid object digest",
                    )
                })?,
            })
        })
        .collect::<Result<Vec<_>, ConversionError>>()?;
    Ok(SnapshotInfo {
        id: value
            .id
            .parse()
            .map_err(|_| invalid("snapshot.id", "invalid snapshot identity"))?,
        record_digest: value
            .record_digest
            .parse()
            .map_err(|_| invalid("snapshot.record_digest", "invalid object digest"))?,
        memory,
        provenance,
        names: crate::names_from_wire(value.names, "snapshot.names")?,
        created_at,
        streams: value
            .streams
            .into_iter()
            .map(crate::snapshots::stream_summary_from_wire)
            .collect::<Result<_, _>>()?,
    })
}

pub fn removal_to_wire(value: &SnapshotRemoval) -> Result<w::SnapshotRemoval, ConversionError> {
    let wire = w::SnapshotRemoval {
        id: value.id.to_string(),
        names: value.names.clone(),
        record_removed: value.record_removed,
    };
    removal_from_wire(wire.clone())?;
    Ok(wire)
}

pub fn removal_from_wire(value: w::SnapshotRemoval) -> Result<SnapshotRemoval, ConversionError> {
    Ok(SnapshotRemoval {
        id: value
            .id
            .parse()
            .map_err(|_| invalid("snapshot.id", "invalid snapshot identity"))?,
        names: crate::names_from_wire(value.names, "snapshot.names")?,
        record_removed: value.record_removed,
    })
}

#[cfg(test)]
mod tests {
    use crate::stopped::{
        info_from_wire, policy_from_wire, policy_to_wire, reference_from_wire, reference_to_wire,
    };
    use libvm::{
        ExternalResourceKey, ExternalResourceMapping, ExternalResourcePolicy, SnapshotRef,
    };
    use silod_spec::daemon::v1 as w;

    #[test]
    fn storage_references_round_trip_names_registry_references_and_ids() {
        assert!(reference_from_wire(w::StorageSnapshotRef::default()).is_err());
        for value in [
            "hello",
            "abc",
            "ghcr.io/team/snap:v2",
            &format!("sha256:{}", "a".repeat(64)),
        ] {
            let reference: SnapshotRef = value.parse().unwrap();
            assert_eq!(
                reference_from_wire(reference_to_wire(&reference)).unwrap(),
                reference
            );
        }
    }

    #[test]
    fn storage_references_reject_cuts_invalid_names_and_disguised_ids() {
        use w::storage_snapshot_ref::Reference;
        for name in [
            "fork:00000000-0000-4000-8000-000000000001".to_owned(),
            "Bad Name".into(),
            String::new(),
            format!("sha256:{}", "a".repeat(64)),
        ] {
            let wire = w::StorageSnapshotRef {
                reference: Some(Reference::Name(name.clone())),
            };
            assert!(reference_from_wire(wire).is_err(), "{name:?}");
        }
        let wire = w::StorageSnapshotRef {
            reference: Some(Reference::Id("hello".into())),
        };
        assert!(reference_from_wire(wire).is_err());
    }

    #[test]
    fn storage_policy_requires_discriminant_and_unique_absolute_mappings() {
        assert!(policy_from_wire(w::ExternalResourcePolicy::default()).is_err());
        let policy = ExternalResourcePolicy::Map {
            mappings: vec![ExternalResourceMapping {
                resource: ExternalResourceKey::Disk { order: 1 },
                path: "/tmp/external.raw".into(),
            }],
        };
        assert!(matches!(
            policy_from_wire(policy_to_wire(&policy)).unwrap(),
            ExternalResourcePolicy::Map { .. }
        ));
        let mut wire = policy_to_wire(&policy);
        if let Some(w::external_resource_policy::Policy::Mappings(mappings)) = &mut wire.policy {
            mappings.values.push(mappings.values[0].clone());
        }
        assert!(policy_from_wire(wire).is_err());
        let relative = ExternalResourcePolicy::Map {
            mappings: vec![ExternalResourceMapping {
                resource: ExternalResourceKey::Disk { order: 1 },
                path: "relative.raw".into(),
            }],
        };
        assert!(policy_from_wire(policy_to_wire(&relative)).is_err());
        for resource in [
            ExternalResourceKey::Disk { order: 0 },
            ExternalResourceKey::Disk { order: 16 },
            ExternalResourceKey::Share { tag: " ".into() },
            ExternalResourceKey::Share {
                tag: "configured\0share".into(),
            },
        ] {
            let policy = ExternalResourcePolicy::Map {
                mappings: vec![ExternalResourceMapping {
                    resource,
                    path: "/tmp/external".into(),
                }],
            };
            assert!(policy_from_wire(policy_to_wire(&policy)).is_err());
        }
        let tag = "長い構成済み共有名".repeat(20);
        let policy = ExternalResourcePolicy::Map {
            mappings: vec![ExternalResourceMapping {
                resource: ExternalResourceKey::Share { tag: tag.clone() },
                path: "/tmp/shared".into(),
            }],
        };
        let ExternalResourcePolicy::Map { mappings } =
            policy_from_wire(policy_to_wire(&policy)).unwrap()
        else {
            panic!("mapping policy was not preserved");
        };
        assert_eq!(mappings[0].resource, ExternalResourceKey::Share { tag });
    }

    #[test]
    fn storage_info_round_trips_memory_and_rejects_foreign_provenance() {
        let mut wire = w::StorageSnapshotInfo {
            id: format!("sha256:{}", "a".repeat(64)),
            record_digest: format!("sha256:{}", "b".repeat(64)),
            names: vec!["snap".into(), "ghcr.io/team/snap:v1".into()],
            created_at: Some(1),
            memory: w::SnapshotMemory::None as i32,
            provenance: vec![],
            streams: Vec::new(),
        };
        let stopped = info_from_wire(wire.clone()).unwrap();
        assert_eq!(stopped.memory, libvm::SnapshotMemory::None);
        assert_eq!(crate::stopped::info_to_wire(&stopped).unwrap(), wire);
        let mut unspecified = wire.clone();
        unspecified.memory = w::SnapshotMemory::Unspecified as i32;
        assert!(info_from_wire(unspecified).is_err());
        let provenance = w::SnapshotCaptureProvenance {
            capture_id: "00000000-0000-4000-8000-000000000001".into(),
            machine_id: "00000000-0000-4000-8000-000000000002".into(),
            run_id: "00000000-0000-4000-8000-000000000003".into(),
            evidence_digest: format!("sha256:{}", "c".repeat(64)),
        };
        wire.memory = w::SnapshotMemory::Included as i32;
        wire.provenance = vec![provenance];
        let included = info_from_wire(wire.clone()).unwrap();
        assert_eq!(included.memory, libvm::SnapshotMemory::Included);
        assert_eq!(
            crate::stopped::info_to_wire(&included).unwrap(),
            wire,
            "a snapshot with memory round-trips exactly"
        );
        let mut malformed = wire.clone();
        malformed.provenance[0].run_id = "not-a-uuid".into();
        assert!(info_from_wire(malformed).is_err());
        wire.memory = w::SnapshotMemory::None as i32;
        assert!(
            info_from_wire(wire.clone()).is_err(),
            "a snapshot without memory carries no capture provenance"
        );
        wire.provenance.clear();
        wire.names.push("snap".into());
        assert!(info_from_wire(wire.clone()).is_err(), "duplicate name");
        wire.names = vec!["Not A Name".into()];
        assert!(info_from_wire(wire).is_err(), "invalid name");
    }

    #[test]
    fn removal_round_trips_and_rejects_invalid_identity() {
        let removal = libvm::SnapshotRemoval {
            id: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            names: vec!["snap".into()],
            record_removed: false,
        };
        let wire = crate::stopped::removal_to_wire(&removal).unwrap();
        assert_eq!(
            crate::stopped::removal_from_wire(wire.clone()).unwrap(),
            removal
        );
        let mut invalid = wire;
        invalid.id = "snap".into();
        assert!(crate::stopped::removal_from_wire(invalid).is_err());
    }

    #[test]
    fn snapshot_request_round_trips_options_and_rejects_invalid_values() {
        let machine = libvm::MachineRef::parse("vm-1").unwrap();
        let options = libvm::SnapshotOptions {
            name: Some("snap".into()),
            memory: true,
            preserve: true,
            capture_policy: Some(vm_spec::lifecycle::CapturePolicy::Full),
            dirty_crossover_percent: Some(30),
            external_requirements: false,
        };
        let wire = crate::stopped::snapshot_request_to_wire(&machine, &options).unwrap();
        let (decoded_machine, decoded) =
            crate::stopped::snapshot_request_from_wire(wire.clone()).unwrap();
        assert_eq!(decoded_machine, machine);
        assert_eq!(decoded, options);
        let defaults =
            crate::stopped::snapshot_request_to_wire(&machine, &libvm::SnapshotOptions::default())
                .unwrap();
        assert_eq!(
            crate::stopped::snapshot_request_from_wire(defaults)
                .unwrap()
                .1,
            libvm::SnapshotOptions::default()
        );
        for case in 0..4 {
            let mut invalid = wire.clone();
            match case {
                0 => invalid.name = Some("registry/name:tag".into()),
                1 => invalid.capture_policy = Some(w::CapturePolicy::Unspecified as i32),
                2 => invalid.dirty_crossover_percent = Some(61),
                3 => invalid.machine = None,
                _ => unreachable!(),
            }
            assert!(
                crate::stopped::snapshot_request_from_wire(invalid).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn restore_request_round_trips_local_and_registry_sources() {
        let hook = libvm::RestoreHook {
            argv: vec!["/bin/true".into()],
            environment: Vec::new(),
            working_directory: "/".into(),
            timeout_ms: 1_000,
        };
        for (source, options) in [
            (
                libvm::RestoreSource::Local("snap".parse().unwrap()),
                libvm::RestoreOptions {
                    name: Some("child".into()),
                    pull: libvm::PullPolicy::Never,
                    without_memory: false,
                    activation_hook: Some(hook),
                    external_resources: ExternalResourcePolicy::Reject,
                },
            ),
            (
                libvm::RestoreSource::Registry("ghcr.io/team/snap:v1".into()),
                libvm::RestoreOptions {
                    name: None,
                    pull: libvm::PullPolicy::Always,
                    without_memory: true,
                    activation_hook: None,
                    external_resources: ExternalResourcePolicy::RequireMappings,
                },
            ),
        ] {
            let wire = crate::stopped::restore_request_to_wire(&source, &options).unwrap();
            let (decoded_source, decoded) =
                crate::stopped::restore_request_from_wire(wire).unwrap();
            assert_eq!(decoded_source, source);
            assert_eq!(decoded.name, options.name);
            assert_eq!(decoded.pull, options.pull);
            assert_eq!(decoded.without_memory, options.without_memory);
            assert_eq!(decoded.activation_hook, options.activation_hook);
            assert!(matches!(
                (&decoded.external_resources, &options.external_resources),
                (
                    ExternalResourcePolicy::Reject,
                    ExternalResourcePolicy::Reject
                ) | (
                    ExternalResourcePolicy::RequireMappings,
                    ExternalResourcePolicy::RequireMappings
                )
            ));
        }
    }

    #[test]
    fn restore_request_requires_source_policy_and_valid_machine_name() {
        let wire = crate::stopped::restore_request_to_wire(
            &libvm::RestoreSource::Registry("snap".into()),
            &libvm::RestoreOptions::default(),
        )
        .unwrap();
        for case in 0..5 {
            let mut invalid = wire.clone();
            match case {
                0 => invalid.source = None,
                1 => invalid.pull_policy = w::PullPolicy::Unspecified as i32,
                2 => invalid.external_resources = None,
                3 => invalid.name = Some("../escape".into()),
                4 => {
                    invalid.source = Some(w::restore_snapshot_request::Source::RegistryReference(
                        String::new(),
                    ))
                }
                _ => unreachable!(),
            }
            assert!(
                crate::stopped::restore_request_from_wire(invalid).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn creation_names_use_exact_native_grammar() {
        for value in ["child", "child-1", "0"] {
            assert!(crate::stopped::name(Some(value.into())).is_ok());
        }
        for value in [
            "INVALID",
            "trailing-",
            "contains space",
            "",
            &"a".repeat(64),
        ] {
            assert!(crate::stopped::name(Some(value.into())).is_err());
        }
    }

    #[test]
    fn restore_hook_wire_roundtrip_preserves_exact_guest_argv_and_requires_bounded_timeout() {
        let hook = libvm::RestoreHook {
            argv: vec!["/bin/sh".into(), "-c".into(), "exit 7".into()],
            environment: vec![libvm::RestoreEnvironmentVariable {
                name: "RESTORED".into(),
                value: "yes".into(),
            }],
            working_directory: "/".into(),
            timeout_ms: 30_000,
        };
        let wire = crate::stopped::hook_to_wire(&hook).unwrap();
        assert_eq!(crate::stopped::hook_from_wire(wire.clone()).unwrap(), hook);
        let mut missing = wire.clone();
        missing.timeout_ms = None;
        assert!(crate::stopped::hook_from_wire(missing).is_err());
        let mut oversized = wire;
        oversized.timeout_ms = Some(30_001);
        assert!(crate::stopped::hook_from_wire(oversized).is_err());
    }
}
