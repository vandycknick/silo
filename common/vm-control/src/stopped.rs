//! Strict storage-artifact management DTOs, separate from machine observations.
use crate::{invalid, path_from_wire, path_to_wire, required, ConversionError};
use libvm::{
    ExternalResourceKey, ExternalResourceMapping, ExternalResourcePolicy, SnapshotInfo, SnapshotRef,
};
use silod_spec::daemon::v1 as w;

pub fn name(value: Option<String>) -> Result<Option<String>, ConversionError> {
    if let Some(value) = &value {
        libvm::validate_new_machine_name(value)
            .map_err(|_| invalid("name", "invalid machine name"))?;
    }
    Ok(value)
}

pub fn alias(value: &str) -> Result<String, ConversionError> {
    match format!("image:{value}").parse::<SnapshotRef>() {
        Ok(SnapshotRef::Image(alias)) if alias == value => Ok(alias),
        _ => Err(invalid("alias", "invalid image alias")),
    }
}

pub fn snapshot_policy(value: &ExternalResourcePolicy) -> Result<(), ConversionError> {
    if matches!(value, ExternalResourcePolicy::Map { .. }) {
        return Err(invalid("external_resources", "snapshot creation accepts only reject or required external declarations; destination mappings belong to fork or restore"));
    }
    Ok(())
}

pub fn reference_to_wire(value: &SnapshotRef) -> w::StorageSnapshotRef {
    use w::storage_snapshot_ref::Reference;
    w::StorageSnapshotRef {
        reference: Some(match value {
            SnapshotRef::Id(id) => Reference::Id(id.to_string()),
            SnapshotRef::Image(name) => Reference::ImageAlias(name.clone()),
        }),
    }
}

pub fn reference_from_wire(value: w::StorageSnapshotRef) -> Result<SnapshotRef, ConversionError> {
    use w::storage_snapshot_ref::Reference;
    match required(value.reference, "snapshot.reference")? {
        Reference::Id(id) => {
            Ok(SnapshotRef::Id(id.parse().map_err(|_| {
                invalid("snapshot.id", "invalid snapshot identity")
            })?))
        }
        Reference::ImageAlias(value) => Ok(SnapshotRef::Image(alias(&value)?)),
    }
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

pub fn restore_resources_to_wire(value: libvm::RestoreResourcePolicy) -> w::RestoreResourcePolicy {
    w::RestoreResourcePolicy {
        private_write_percent: value.private_write_allowance.into(),
        memory: match value.memory {
            libvm::RestoreMemoryPolicy::Reserved => w::RestoreMemoryPolicy::Reserved,
            libvm::RestoreMemoryPolicy::AllowOvercommit => w::RestoreMemoryPolicy::AllowOvercommit,
        } as i32,
    }
}

pub fn restore_resources_from_wire(
    value: Option<w::RestoreResourcePolicy>,
) -> Result<libvm::RestoreResourcePolicy, ConversionError> {
    let Some(value) = value else {
        return Ok(libvm::RestoreResourcePolicy::default());
    };
    Ok(libvm::RestoreResourcePolicy {
        private_write_allowance: libvm::PrivateWriteAllowance::try_from(
            value.private_write_percent,
        )
        .map_err(|_| invalid("resources.private_write_percent", "expected 0..=100"))?,
        memory: match w::RestoreMemoryPolicy::try_from(value.memory) {
            Ok(w::RestoreMemoryPolicy::Reserved) => libvm::RestoreMemoryPolicy::Reserved,
            Ok(w::RestoreMemoryPolicy::AllowOvercommit) => {
                libvm::RestoreMemoryPolicy::AllowOvercommit
            }
            _ => {
                return Err(invalid(
                    "resources.memory",
                    "expected an explicit restore memory policy",
                ))
            }
        },
    })
}

pub fn info_to_wire(value: &SnapshotInfo) -> Result<w::StorageSnapshotInfo, ConversionError> {
    let result = w::StorageSnapshotInfo {
        id: value.id.to_string(),
        record_digest: value.record_digest.to_string(),
        retained: Some(value.retained),
        aliases: value.aliases.clone(),
        created_at: Some(value.created_at),
        capture_kind: match value.capture_kind {
            libvm::SnapshotCaptureKindName::StoppedStorage => w::StorageCaptureKind::StoppedStorage,
            libvm::SnapshotCaptureKindName::LiveExecution => w::StorageCaptureKind::LiveExecution,
        } as i32,
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
pub fn info_from_wire(value: w::StorageSnapshotInfo) -> Result<SnapshotInfo, ConversionError> {
    let capture_kind = match w::StorageCaptureKind::try_from(value.capture_kind) {
        Ok(w::StorageCaptureKind::StoppedStorage) => libvm::SnapshotCaptureKindName::StoppedStorage,
        Ok(w::StorageCaptureKind::LiveExecution) => libvm::SnapshotCaptureKindName::LiveExecution,
        _ => {
            return Err(invalid(
                "snapshot.capture_kind",
                "expected stopped-storage or live-execution",
            ))
        }
    };
    if value.aliases.len() > 4096 {
        return Err(invalid("snapshot.aliases", "too many aliases"));
    }
    let mut aliases = std::collections::BTreeSet::new();
    for value in &value.aliases {
        if !aliases.insert(alias(value)?) {
            return Err(invalid("snapshot.aliases", "duplicate alias"));
        }
    }
    let created_at = required(value.created_at, "snapshot.created_at")?;
    if !(0..=9_007_199_254_740_991).contains(&created_at) {
        return Err(invalid("snapshot.created_at", "invalid timestamp"));
    }
    // Provenance is evidence of live captures only; a stopped snapshot has none.
    if value.provenance.len() > 4096
        || (capture_kind == libvm::SnapshotCaptureKindName::StoppedStorage
            && !value.provenance.is_empty())
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
        capture_kind,
        provenance,
        retained: required(value.retained, "snapshot.retained")?,
        aliases: value.aliases,
        created_at,
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
    fn storage_references_are_explicit_and_strict() {
        assert!(reference_from_wire(w::StorageSnapshotRef::default()).is_err());
        for value in [
            "image:checkpoint",
            "image:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let reference: SnapshotRef = value.parse().unwrap();
            assert_eq!(
                reference_from_wire(reference_to_wire(&reference))
                    .unwrap()
                    .to_string(),
                value
            );
        }
        for value in ["snapshot:checkpoint", "checkpoint", "image:"] {
            assert!(value.parse::<SnapshotRef>().is_err());
        }
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
    fn storage_info_rejects_observation_shaped_success_and_foreign_provenance() {
        let mut wire = w::StorageSnapshotInfo {
            id: format!("sha256:{}", "a".repeat(64)),
            record_digest: format!("sha256:{}", "b".repeat(64)),
            retained: Some(false),
            aliases: vec!["checkpoint".into()],
            created_at: Some(1),
            capture_kind: w::StorageCaptureKind::StoppedStorage as i32,
            provenance: vec![],
        };
        assert!(info_from_wire(wire.clone()).is_ok());
        wire.capture_kind = 0;
        assert!(info_from_wire(wire.clone()).is_err());
        let provenance = w::SnapshotCaptureProvenance {
            capture_id: "00000000-0000-4000-8000-000000000001".into(),
            machine_id: "00000000-0000-4000-8000-000000000002".into(),
            run_id: "00000000-0000-4000-8000-000000000003".into(),
            evidence_digest: format!("sha256:{}", "c".repeat(64)),
        };
        wire.capture_kind = w::StorageCaptureKind::LiveExecution as i32;
        wire.provenance = vec![provenance.clone()];
        let live = info_from_wire(wire.clone()).unwrap();
        assert_eq!(
            live.capture_kind,
            libvm::SnapshotCaptureKindName::LiveExecution
        );
        assert_eq!(
            crate::stopped::info_to_wire(&live).unwrap(),
            wire,
            "live execution info round-trips exactly"
        );
        let mut malformed = wire.clone();
        malformed.provenance[0].run_id = "not-a-uuid".into();
        assert!(info_from_wire(malformed).is_err());
        wire.capture_kind = w::StorageCaptureKind::StoppedStorage as i32;
        assert!(
            info_from_wire(wire.clone()).is_err(),
            "stopped snapshots carry no capture provenance"
        );
        wire.provenance.clear();
        wire.retained = None;
        assert!(info_from_wire(wire.clone()).is_err());
        wire.retained = Some(true);
        wire.aliases.push("checkpoint".into());
        assert!(info_from_wire(wire).is_err());
    }

    #[test]
    fn creation_names_and_snapshot_external_policy_use_exact_native_grammar() {
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
        assert!(crate::stopped::snapshot_policy(&ExternalResourcePolicy::Reject).is_ok());
        assert!(crate::stopped::snapshot_policy(&ExternalResourcePolicy::RequireMappings).is_ok());
        assert!(
            crate::stopped::snapshot_policy(&ExternalResourcePolicy::Map {
                mappings: vec![ExternalResourceMapping {
                    resource: ExternalResourceKey::Disk { order: 1 },
                    path: "/tmp/external.raw".into()
                }],
            })
            .is_err()
        );
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

    #[test]
    fn restore_resource_wire_defaults_require_explicit_valid_policy_when_present() {
        use crate::stopped::{restore_resources_from_wire, restore_resources_to_wire};
        assert_eq!(
            restore_resources_from_wire(None).unwrap(),
            libvm::RestoreResourcePolicy::default()
        );
        for percent in [0, 25, 33, 100] {
            for memory in [
                libvm::RestoreMemoryPolicy::Reserved,
                libvm::RestoreMemoryPolicy::AllowOvercommit,
            ] {
                let policy = libvm::RestoreResourcePolicy {
                    private_write_allowance: libvm::PrivateWriteAllowance::try_from(percent)
                        .unwrap(),
                    memory,
                };
                assert_eq!(
                    restore_resources_from_wire(Some(restore_resources_to_wire(policy))).unwrap(),
                    policy
                );
            }
        }
        for (percent, memory) in [(101, 1), (u32::MAX, 2), (25, 0), (25, 3), (25, -1)] {
            assert!(restore_resources_from_wire(Some(w::RestoreResourcePolicy {
                private_write_percent: percent,
                memory,
            }))
            .is_err());
        }
    }
}
