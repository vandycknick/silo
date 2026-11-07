//! ADR 0014 v1 compatibility limits. Bounds are inclusive, not resource promises.

pub const CHUNK_SIZE: usize = oci::vm_artifact::wire::CHUNK_SIZE as usize;
const GIB: u64 = 1024 * 1024 * 1024;
pub const JSON_SAFE_INTEGER_MAX: u64 = oci::changeset::limits::JSON_SAFE_INTEGER_MAX;
pub const LOGICAL_SECTOR_SIZE: u64 = 512;
pub const MTIME_FRACTIONAL_DIGITS: usize = 9;
pub const NANOSECONDS_PER_SECOND: u64 = 10_u64.pow(MTIME_FRACTIONAL_DIGITS as u32);
pub const FD_RESERVED_OVERHEAD: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    LayerOccurrences,
    LayerEntries,
    NamespaceEntries,
    GuestPathBytes,
    ComponentBytes,
    PathDepth,
    UidGid,
    MtimeSeconds,
    /// Normalized fractional seconds; text decoders truncate excess digits.
    MtimeNanoseconds,
    XattrsPerInode,
    EncodedXattrBytes,
    RegularFileBytes,
    ExpandedLayerBytes,
    LogicalLowerBytes,
    FsmetaBytes,
    HardlinkNames,
    VirtualDiskBytes,
    CapturedRamBytes,
    GptEntries,
    MbrPrimaryEntries,
    IncludedDisks,
    ArtifactStreamBytes,
    MetadataPageBytes,
    MetadataPageEntries,
    RootBootstrapBytes,
    OciManifestBytes,
    OciChildDescriptors,
    OciPayloadChildren,
    OciGraphLevels,
    TransferChunkBytes,
    ZstdWindowBytes,
    VmdkDescriptorBytes,
    VmdkFlatRecords,
    JsonInteger,
}

impl Resource {
    pub const fn maximum(self) -> u64 {
        match self {
            Self::LayerOccurrences => oci::changeset::limits::FORMAT_LIMITS.max_layers,
            Self::LayerEntries => oci::changeset::limits::FORMAT_LIMITS.max_entries,
            Self::NamespaceEntries => oci::changeset::limits::FORMAT_LIMITS.max_namespace_entries,
            Self::GuestPathBytes => oci::changeset::limits::FORMAT_LIMITS.max_path_bytes,
            Self::ComponentBytes => oci::changeset::limits::FORMAT_LIMITS.max_component_bytes,
            Self::PathDepth => oci::changeset::limits::FORMAT_LIMITS.max_depth,
            Self::UidGid => oci::changeset::limits::MAX_UID,
            Self::MtimeSeconds => oci::changeset::limits::MAX_MTIME_SECONDS,
            Self::MtimeNanoseconds => NANOSECONDS_PER_SECOND - 1,
            Self::XattrsPerInode => oci::changeset::limits::FORMAT_LIMITS.max_xattrs,
            Self::EncodedXattrBytes => oci::changeset::limits::FORMAT_LIMITS.max_xattr_bytes,
            Self::RegularFileBytes => oci::changeset::limits::FORMAT_LIMITS.max_file_bytes,
            Self::ExpandedLayerBytes => oci::changeset::limits::FORMAT_LIMITS.max_expanded_bytes,
            Self::LogicalLowerBytes | Self::VirtualDiskBytes => {
                oci::vm_artifact::wire::MAX_STREAM_BYTES
            }
            Self::CapturedRamBytes => vm_spec::capture::MAX_CAPTURE_RAM_BYTES,
            Self::FsmetaBytes => 4 * GIB,
            Self::HardlinkNames => oci::changeset::limits::FORMAT_LIMITS.max_hardlinks,
            Self::GptEntries => 128,
            Self::MbrPrimaryEntries => 4,
            Self::IncludedDisks => 16,
            Self::ArtifactStreamBytes => oci::vm_artifact::wire::MAX_ARTIFACT_BYTES,
            Self::MetadataPageBytes | Self::OciManifestBytes => {
                oci::vm_artifact::wire::MAX_METADATA_BYTES as u64
            }
            Self::MetadataPageEntries | Self::OciChildDescriptors | Self::OciPayloadChildren => {
                oci::vm_artifact::wire::MAX_PAGE_ENTRIES as u64
            }
            Self::RootBootstrapBytes => oci::changeset::limits::MAX_ROOT_BYTES,
            Self::OciGraphLevels => 2,
            Self::TransferChunkBytes | Self::ZstdWindowBytes => CHUNK_SIZE as u64,
            Self::VmdkDescriptorBytes => 2_097_152,
            Self::VmdkFlatRecords => 1536,
            Self::JsonInteger => JSON_SAFE_INTEGER_MAX,
        }
    }

    pub fn check(self, actual: u64) -> Result<(), BoundViolation> {
        if actual > self.maximum() {
            return Err(BoundViolation::Exceeded {
                resource: self,
                actual,
                maximum: self.maximum(),
            });
        }
        Ok(())
    }

    /// Reject overflow as a bound violation rather than wrapping a closure sum.
    pub fn sum(self, values: impl IntoIterator<Item = u64>) -> Result<u64, BoundViolation> {
        values.into_iter().try_fold(0_u64, |total, value| {
            let sum = total
                .checked_add(value)
                .ok_or(BoundViolation::Overflow { resource: self })?;
            self.check(sum)?;
            Ok(sum)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BoundViolation {
    #[error("{resource:?} is {actual}, exceeding v1 maximum {maximum}")]
    Exceeded {
        resource: Resource,
        actual: u64,
        maximum: u64,
    },
    #[error("{resource:?} arithmetic overflow")]
    Overflow { resource: Resource },
    #[error(
        "virtual disk length {length} must be positive and aligned to 512-byte logical sectors"
    )]
    DiskGeometry { length: u64 },
    #[error("upper length {length} must be at least 64 MiB and aligned to 4096 bytes")]
    UpperGeometry { length: u64 },
}

/// Host capacity preflight, separate from the storage format's admission bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FileDescriptorBudgetError {
    #[error("file descriptor budget requires {required}, but soft limit is {soft} and hard limit is {hard}")]
    Insufficient { required: u64, soft: u64, hard: u64 },
    #[error("file descriptor budget {flat_records} FLAT records + 256 reserved descriptors overflows; soft limit is {soft}, hard limit is {hard}")]
    Overflow {
        flat_records: u64,
        soft: u64,
        hard: u64,
    },
    #[error("cannot query RLIMIT_NOFILE: {source}")]
    Query {
        #[source]
        source: nix::errno::Errno,
    },
    #[error(
        "cannot raise RLIMIT_NOFILE soft {soft} to hard {hard}, preserving hard {hard}: {source}"
    )]
    Raise {
        soft: u64,
        hard: u64,
        #[source]
        source: nix::errno::Errno,
    },
    #[error(
        "cannot query effective RLIMIT_NOFILE after raising soft {soft} to hard {hard}: {source}"
    )]
    QueryAfterRaise {
        soft: u64,
        hard: u64,
        #[source]
        source: nix::errno::Errno,
    },
}

/// Check observed limits without querying or mutating process-wide rlimits.
/// A caller that raises its soft limit first must pass the resulting limits.
/// Fitting the format limits alone does not imply that this host can start it.
pub fn check_fd_budget(
    flat_records: u64,
    soft: u64,
    hard: u64,
) -> Result<u64, FileDescriptorBudgetError> {
    let required = flat_records.checked_add(FD_RESERVED_OVERHEAD).ok_or(
        FileDescriptorBudgetError::Overflow {
            flat_records,
            soft,
            hard,
        },
    )?;
    if required > soft || required > hard {
        return Err(FileDescriptorBudgetError::Insufficient {
            required,
            soft,
            hard,
        });
    }
    Ok(required)
}

/// Actual process limits after start admission. `RLIM_INFINITY` remains the
/// operating system's unlimited sentinel; it is never added to a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDescriptorLimits {
    pub soft: u64,
    pub hard: u64,
    pub required: u64,
}

/// Raise only the process-wide soft limit, never lower or restore either limit.
/// Call before opening any lower backing, including content-verification opens.
pub fn preflight_fd_budget(
    flat_records: u64,
) -> Result<FileDescriptorLimits, FileDescriptorBudgetError> {
    use nix::sys::resource::{getrlimit, setrlimit, Resource as HostResource};

    let (soft, hard) = getrlimit(HostResource::RLIMIT_NOFILE)
        .map_err(|source| FileDescriptorBudgetError::Query { source })?;
    let (effective_soft, effective_hard) = if soft < hard {
        setrlimit(HostResource::RLIMIT_NOFILE, hard, hard)
            .map_err(|source| FileDescriptorBudgetError::Raise { soft, hard, source })?;
        getrlimit(HostResource::RLIMIT_NOFILE)
            .map_err(|source| FileDescriptorBudgetError::QueryAfterRaise { soft, hard, source })?
    } else {
        (soft, hard)
    };
    let required = check_fd_budget(flat_records, effective_soft, effective_hard)?;
    Ok(FileDescriptorLimits {
        soft: effective_soft,
        hard: effective_hard,
        required,
    })
}

pub fn validate_mtime(seconds: u64, nanoseconds: u32) -> Result<(), BoundViolation> {
    Resource::MtimeSeconds.check(seconds)?;
    Resource::MtimeNanoseconds.check(u64::from(nanoseconds))
}

pub fn validate_disk_length(length: u64) -> Result<(), BoundViolation> {
    Resource::VirtualDiskBytes.check(length)?;
    if length == 0 || !length.is_multiple_of(LOGICAL_SECTOR_SIZE) {
        return Err(BoundViolation::DiskGeometry { length });
    }
    Ok(())
}

pub fn validate_upper_length(length: u64) -> Result<(), BoundViolation> {
    validate_disk_length(length)?;
    if length < 64 * 1024 * 1024 || !length.is_multiple_of(4096) {
        return Err(BoundViolation::UpperGeometry { length });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::storage::limits::{
        check_fd_budget, validate_disk_length, validate_mtime, validate_upper_length,
        BoundViolation, FileDescriptorBudgetError, Resource,
    };

    #[test]
    fn every_admission_boundary_matches_explicit_adr_values() {
        for (resource, maximum) in [
            (Resource::LayerOccurrences, 1024),
            (Resource::LayerEntries, 1_000_000),
            (Resource::NamespaceEntries, 4_000_000),
            (Resource::GuestPathBytes, 4096),
            (Resource::ComponentBytes, 255),
            (Resource::PathDepth, 256),
            (Resource::UidGid, 4_294_967_294),
            (Resource::MtimeSeconds, 15_032_385_535),
            (Resource::MtimeNanoseconds, 999_999_999),
            (Resource::XattrsPerInode, 64),
            (Resource::EncodedXattrBytes, 3072),
            (Resource::RegularFileBytes, 137_438_953_472),
            (Resource::ExpandedLayerBytes, 1_099_511_627_776),
            (Resource::LogicalLowerBytes, 1_099_511_627_776),
            (Resource::FsmetaBytes, 4_294_967_296),
            (Resource::HardlinkNames, 64_999),
            (Resource::VirtualDiskBytes, 1_099_511_627_776),
            (Resource::GptEntries, 128),
            (Resource::MbrPrimaryEntries, 4),
            (Resource::IncludedDisks, 16),
            (Resource::ArtifactStreamBytes, 4_398_046_511_104),
            (Resource::MetadataPageBytes, 4_194_304),
            (Resource::MetadataPageEntries, 4096),
            (Resource::RootBootstrapBytes, 65_536),
            (Resource::OciManifestBytes, 4_194_304),
            (Resource::OciChildDescriptors, 4096),
            (Resource::OciPayloadChildren, 4096),
            (Resource::OciGraphLevels, 2),
            (Resource::TransferChunkBytes, 8_388_608),
            (Resource::ZstdWindowBytes, 8_388_608),
            (Resource::VmdkDescriptorBytes, 2_097_152),
            (Resource::VmdkFlatRecords, 1536),
            (Resource::JsonInteger, 9_007_199_254_740_991),
        ] {
            assert!(resource.check(maximum - 1).is_ok(), "{resource:?}");
            assert!(resource.check(maximum).is_ok(), "{resource:?}");
            assert_eq!(
                resource.check(maximum + 1),
                Err(BoundViolation::Exceeded {
                    resource,
                    actual: maximum + 1,
                    maximum
                })
            );
        }
    }

    #[test]
    fn aggregate_admission_checks_capacity_and_arithmetic_overflow() {
        assert_eq!(
            Resource::ArtifactStreamBytes
                .sum([1_099_511_627_776; 4])
                .unwrap(),
            4_398_046_511_104
        );
        assert!(Resource::ArtifactStreamBytes
            .sum([1_099_511_627_776; 5])
            .is_err());
        assert!(matches!(
            Resource::JsonInteger.sum([1, u64::MAX]),
            Err(BoundViolation::Overflow { .. })
        ));
    }

    #[test]
    fn nanosecond_mtime_is_normalized_without_changing_the_seconds_bound() {
        assert!(validate_mtime(0, 0).is_ok());
        assert!(validate_mtime(15_032_385_535, 999_999_999).is_ok());
        assert!(matches!(
            validate_mtime(15_032_385_536, 0),
            Err(BoundViolation::Exceeded {
                resource: Resource::MtimeSeconds,
                ..
            })
        ));
        assert!(matches!(
            validate_mtime(0, 1_000_000_000),
            Err(BoundViolation::Exceeded {
                resource: Resource::MtimeNanoseconds,
                ..
            })
        ));
    }

    #[test]
    fn fd_preflight_reserves_runtime_descriptors_and_reports_both_limits() {
        assert_eq!(check_fd_budget(0, 256, 256).unwrap(), 256);
        assert_eq!(check_fd_budget(1536, 1792, 4096).unwrap(), 1792);
        assert_eq!(
            check_fd_budget(0, 255, 256),
            Err(FileDescriptorBudgetError::Insufficient {
                required: 256,
                soft: 255,
                hard: 256
            })
        );
        let error = check_fd_budget(1536, 1791, 4096).unwrap_err();
        assert_eq!(
            error,
            FileDescriptorBudgetError::Insufficient {
                required: 1792,
                soft: 1791,
                hard: 4096
            }
        );
        let message = error.to_string();
        assert!(message.contains("requires 1792"));
        assert!(message.contains("soft limit is 1791"));
        assert!(message.contains("hard limit is 4096"));
        assert_eq!(
            check_fd_budget(1536, 4096, 1791),
            Err(FileDescriptorBudgetError::Insufficient {
                required: 1792,
                soft: 4096,
                hard: 1791
            })
        );
        assert_eq!(
            check_fd_budget(u64::MAX, 1024, 4096),
            Err(FileDescriptorBudgetError::Overflow {
                flat_records: u64::MAX,
                soft: 1024,
                hard: 4096
            })
        );
    }

    #[test]
    fn disk_and_upper_geometry_admission_is_not_just_a_maximum() {
        assert!(validate_disk_length(0).is_err());
        assert!(validate_disk_length(511).is_err());
        assert!(validate_disk_length(512).is_ok());
        assert!(validate_disk_length(1024_u64.pow(4)).is_ok());
        assert!(validate_disk_length(1024_u64.pow(4) + 512).is_err());
        assert!(validate_upper_length(64 * 1024 * 1024 - 4096).is_err());
        assert!(validate_upper_length(64 * 1024 * 1024).is_ok());
        assert!(validate_upper_length(64 * 1024 * 1024 + 512).is_err());
    }

    #[test]
    fn vmdk_rlimit_syscall_errors_retain_sources_and_actual_bounds() {
        use nix::errno::Errno;
        use std::error::Error;
        for error in [
            FileDescriptorBudgetError::Query {
                source: Errno::EPERM,
            },
            FileDescriptorBudgetError::Raise {
                soft: 32,
                hard: 512,
                source: Errno::EPERM,
            },
            FileDescriptorBudgetError::QueryAfterRaise {
                soft: 32,
                hard: 512,
                source: Errno::EPERM,
            },
        ] {
            assert_eq!(
                error.source().unwrap().to_string(),
                Errno::EPERM.to_string()
            );
            assert!(error.to_string().contains("RLIMIT_NOFILE"));
            if !matches!(error, FileDescriptorBudgetError::Query { .. }) {
                assert!(error.to_string().contains("soft 32"));
                assert!(error.to_string().contains("hard 512"));
            }
        }
        assert_eq!(
            check_fd_budget(
                1536,
                nix::sys::resource::RLIM_INFINITY,
                nix::sys::resource::RLIM_INFINITY
            )
            .unwrap(),
            1792
        );
    }
}
