//! Strict daemon transport of live execution captures. Capture identity is
//! the request/operation UUID; staging is a relative diagnostic path only.
use std::path::{Component, Path, PathBuf};

use silod_spec::daemon::v1 as w;
use vm_spec::capture::{
    CaptureFullReason, CaptureIdentityReadFallback, CaptureMemoryEvidence, CaptureMemoryStats,
    CapturePauseDisposition, CaptureSeedMethod, CaptureStateBinding, Sha256Digest,
};
use vm_spec::lifecycle::{CapturePolicy, CaptureResumePolicy, Diagnostic, LiveId};

use crate::{invalid, required, ConversionError};

pub fn policy_to_wire(value: CapturePolicy) -> i32 {
    (match value {
        CapturePolicy::Full => w::CapturePolicy::Full,
        CapturePolicy::Incremental => w::CapturePolicy::Incremental,
    }) as i32
}

pub fn policy_from_wire(value: i32) -> Result<CapturePolicy, ConversionError> {
    match w::CapturePolicy::try_from(value) {
        Ok(w::CapturePolicy::Full) => Ok(CapturePolicy::Full),
        Ok(w::CapturePolicy::Incremental) => Ok(CapturePolicy::Incremental),
        _ => Err(invalid("capture.policy", "unknown or unspecified enum")),
    }
}

pub fn crossover_from_wire(value: u32) -> Result<u8, ConversionError> {
    if !(1..=60).contains(&value) {
        return Err(invalid(
            "capture.dirty_crossover_percent",
            "expected 1..=60",
        ));
    }
    u8::try_from(value).map_err(|_| invalid("capture.dirty_crossover_percent", "expected 1..=60"))
}

fn full_reason_to_wire(value: CaptureFullReason) -> i32 {
    (match value {
        CaptureFullReason::Requested => w::CaptureFullReason::Requested,
        CaptureFullReason::NoBaseline => w::CaptureFullReason::NoBaseline,
        CaptureFullReason::BaselineToken => w::CaptureFullReason::BaselineToken,
        CaptureFullReason::CoverageLost => w::CaptureFullReason::CoverageLost,
        CaptureFullReason::DirtyCrossover => w::CaptureFullReason::DirtyCrossover,
    }) as i32
}

fn full_reason_from_wire(value: i32) -> Result<CaptureFullReason, ConversionError> {
    match w::CaptureFullReason::try_from(value) {
        Ok(w::CaptureFullReason::Requested) => Ok(CaptureFullReason::Requested),
        Ok(w::CaptureFullReason::NoBaseline) => Ok(CaptureFullReason::NoBaseline),
        Ok(w::CaptureFullReason::BaselineToken) => Ok(CaptureFullReason::BaselineToken),
        Ok(w::CaptureFullReason::CoverageLost) => Ok(CaptureFullReason::CoverageLost),
        Ok(w::CaptureFullReason::DirtyCrossover) => Ok(CaptureFullReason::DirtyCrossover),
        _ => Err(invalid(
            "capture.memory.full_reason",
            "unknown or unspecified enum",
        )),
    }
}

fn identity_policy_to_wire(value: vm_spec::capture::CaptureIdentityPolicy) -> i32 {
    use vm_spec::capture::CaptureIdentityPolicy as Policy;
    (match value {
        Policy::None => w::CaptureIdentityPolicy::None,
        Policy::Full => w::CaptureIdentityPolicy::Full,
        Policy::SinceAnchor => w::CaptureIdentityPolicy::SinceAnchor,
    }) as i32
}

fn identity_policy_from_wire(
    value: i32,
) -> Result<vm_spec::capture::CaptureIdentityPolicy, ConversionError> {
    use vm_spec::capture::CaptureIdentityPolicy as Policy;
    match w::CaptureIdentityPolicy::try_from(value) {
        Ok(w::CaptureIdentityPolicy::None) => Ok(Policy::None),
        Ok(w::CaptureIdentityPolicy::Full) => Ok(Policy::Full),
        Ok(w::CaptureIdentityPolicy::SinceAnchor) => Ok(Policy::SinceAnchor),
        _ => Err(invalid(
            "capture.memory.identity_policy",
            "unknown or unspecified policy",
        )),
    }
}

fn identity_reason_to_wire(value: vm_spec::capture::CaptureIdentityFullReason) -> i32 {
    use vm_spec::capture::CaptureIdentityFullReason as Reason;
    (match value {
        Reason::Requested => w::CaptureIdentityFullReason::Requested,
        Reason::UnknownAnchorAfterFork => w::CaptureIdentityFullReason::UnknownAnchorAfterFork,
        Reason::CoverageLost => w::CaptureIdentityFullReason::CoverageLost,
        Reason::NoIdentifiedAnchor => w::CaptureIdentityFullReason::NoIdentifiedAnchor,
    }) as i32
}

fn identity_reason_from_wire(
    value: i32,
) -> Result<vm_spec::capture::CaptureIdentityFullReason, ConversionError> {
    use vm_spec::capture::CaptureIdentityFullReason as Reason;
    match w::CaptureIdentityFullReason::try_from(value) {
        Ok(w::CaptureIdentityFullReason::Requested) => Ok(Reason::Requested),
        Ok(w::CaptureIdentityFullReason::UnknownAnchorAfterFork) => {
            Ok(Reason::UnknownAnchorAfterFork)
        }
        Ok(w::CaptureIdentityFullReason::CoverageLost) => Ok(Reason::CoverageLost),
        Ok(w::CaptureIdentityFullReason::NoIdentifiedAnchor) => Ok(Reason::NoIdentifiedAnchor),
        _ => Err(invalid(
            "capture.memory.identity_full_reason",
            "unknown or unspecified reason",
        )),
    }
}

fn seed_method_to_wire(value: CaptureSeedMethod) -> i32 {
    (match value {
        CaptureSeedMethod::Clone => w::CaptureSeedMethod::Clone,
        CaptureSeedMethod::Rebuild => w::CaptureSeedMethod::Rebuild,
    }) as i32
}

fn seed_method_from_wire(value: i32) -> Result<CaptureSeedMethod, ConversionError> {
    match w::CaptureSeedMethod::try_from(value) {
        Ok(w::CaptureSeedMethod::Clone) => Ok(CaptureSeedMethod::Clone),
        Ok(w::CaptureSeedMethod::Rebuild) => Ok(CaptureSeedMethod::Rebuild),
        _ => Err(invalid(
            "capture.memory.stats.seed_method",
            "unknown or unspecified enum",
        )),
    }
}

fn identity_read_fallback_to_wire(value: CaptureIdentityReadFallback) -> i32 {
    (match value {
        CaptureIdentityReadFallback::None => w::CaptureIdentityReadFallback::None,
        CaptureIdentityReadFallback::CoverageLost => w::CaptureIdentityReadFallback::CoverageLost,
        CaptureIdentityReadFallback::BaselineMismatch => {
            w::CaptureIdentityReadFallback::BaselineMismatch
        }
        CaptureIdentityReadFallback::ExtentsUnavailable => {
            w::CaptureIdentityReadFallback::ExtentsUnavailable
        }
        CaptureIdentityReadFallback::ExtentLimit => w::CaptureIdentityReadFallback::ExtentLimit,
    }) as i32
}

fn identity_read_fallback_from_wire(
    value: i32,
) -> Result<CaptureIdentityReadFallback, ConversionError> {
    match w::CaptureIdentityReadFallback::try_from(value) {
        Ok(w::CaptureIdentityReadFallback::None) => Ok(CaptureIdentityReadFallback::None),
        Ok(w::CaptureIdentityReadFallback::CoverageLost) => {
            Ok(CaptureIdentityReadFallback::CoverageLost)
        }
        Ok(w::CaptureIdentityReadFallback::BaselineMismatch) => {
            Ok(CaptureIdentityReadFallback::BaselineMismatch)
        }
        Ok(w::CaptureIdentityReadFallback::ExtentsUnavailable) => {
            Ok(CaptureIdentityReadFallback::ExtentsUnavailable)
        }
        Ok(w::CaptureIdentityReadFallback::ExtentLimit) => {
            Ok(CaptureIdentityReadFallback::ExtentLimit)
        }
        _ => Err(invalid(
            "capture.memory.stats.full_identity_read_fallback",
            "unknown or unspecified enum",
        )),
    }
}

pub fn hibernate_memory_to_wire(
    value: &vm_spec::capture::HibernateMemoryReceipt,
) -> w::HibernateMemoryReceipt {
    w::HibernateMemoryReceipt {
        mode: policy_to_wire(value.mode),
        full_reason: value.full_reason.map(full_reason_to_wire),
        stats: Some(stats_to_wire(&value.stats)),
    }
}

pub fn hibernate_memory_from_wire(
    value: w::HibernateMemoryReceipt,
) -> Result<vm_spec::capture::HibernateMemoryReceipt, ConversionError> {
    let receipt = vm_spec::capture::HibernateMemoryReceipt {
        mode: policy_from_wire(value.mode)?,
        full_reason: value.full_reason.map(full_reason_from_wire).transpose()?,
        stats: stats_from_wire(required(value.stats, "hibernation.memory_capture.stats")?)?,
    };
    receipt
        .validate()
        .map_err(|_| invalid("hibernation.memory_capture", "invalid memory receipt"))?;
    Ok(receipt)
}

fn stats_to_wire(stats: &CaptureMemoryStats) -> w::CaptureMemoryStats {
    w::CaptureMemoryStats {
        seed_method: seed_method_to_wire(stats.seed_method),
        logical_bytes: stats.logical_bytes,
        live_bytes_read: stats.live_bytes_read,
        baseline_bytes_read: stats.baseline_bytes_read,
        baseline_bytes_written: stats.baseline_bytes_written,
        overlay_bytes_written: stats.overlay_bytes_written,
        full_bytes_written: stats.full_bytes_written,
        layout_bytes_written: stats.layout_bytes_written,
        baseline_hole_bytes: stats.baseline_hole_bytes,
        zero_bytes_omitted: stats.zero_bytes_omitted,
        explicit_zero_bytes_written: stats.explicit_zero_bytes_written,
        zero_run_bytes_covered: stats.zero_run_bytes_covered,
        zero_bytes_punched: stats.zero_bytes_punched,
        known_zero_bytes_skipped: stats.known_zero_bytes_skipped,
        extent_queries: stats.extent_queries,
        identity_bytes_hashed: stats.identity_bytes_hashed,
        whole_file_bytes_hashed: stats.whole_file_bytes_hashed,
        map_nodes_written: stats.map_nodes_written,
        identity_dirty_pages: stats.identity_dirty_pages,
        materialization_dirty_pages: stats.materialization_dirty_pages,
        live_pages_classified: stats.live_pages_classified,
        identity_zero_bytes_filled: stats.identity_zero_bytes_filled,
        full_identity_read_fallback: identity_read_fallback_to_wire(
            stats.full_identity_read_fallback,
        ),
    }
}

fn stats_from_wire(stats: w::CaptureMemoryStats) -> Result<CaptureMemoryStats, ConversionError> {
    Ok(CaptureMemoryStats {
        seed_method: seed_method_from_wire(stats.seed_method)?,
        logical_bytes: stats.logical_bytes,
        live_bytes_read: stats.live_bytes_read,
        baseline_bytes_read: stats.baseline_bytes_read,
        baseline_bytes_written: stats.baseline_bytes_written,
        overlay_bytes_written: stats.overlay_bytes_written,
        full_bytes_written: stats.full_bytes_written,
        layout_bytes_written: stats.layout_bytes_written,
        baseline_hole_bytes: stats.baseline_hole_bytes,
        zero_bytes_omitted: stats.zero_bytes_omitted,
        explicit_zero_bytes_written: stats.explicit_zero_bytes_written,
        zero_run_bytes_covered: stats.zero_run_bytes_covered,
        zero_bytes_punched: stats.zero_bytes_punched,
        known_zero_bytes_skipped: stats.known_zero_bytes_skipped,
        extent_queries: stats.extent_queries,
        identity_bytes_hashed: stats.identity_bytes_hashed,
        whole_file_bytes_hashed: stats.whole_file_bytes_hashed,
        map_nodes_written: stats.map_nodes_written,
        identity_dirty_pages: stats.identity_dirty_pages,
        materialization_dirty_pages: stats.materialization_dirty_pages,
        live_pages_classified: stats.live_pages_classified,
        identity_zero_bytes_filled: stats.identity_zero_bytes_filled,
        full_identity_read_fallback: identity_read_fallback_from_wire(
            stats.full_identity_read_fallback,
        )?,
    })
}

fn memory_to_wire(value: &CaptureMemoryEvidence) -> w::CaptureMemoryEvidence {
    let binding = &value.binding;
    w::CaptureMemoryEvidence {
        packed_length: value.packed_length,
        page_granule: value.page_granule,
        regions: value.regions,
        ram_stream: value.ram_stream.to_string(),
        binding: Some(w::CaptureStateBinding {
            live_state_schema: binding.live_state_schema.clone(),
            architecture: binding.architecture.clone(),
            profile: binding.profile.to_string(),
            topology: binding.topology.to_string(),
            ram_layout: binding.ram_layout.to_string(),
            source_run: binding.source_run.to_string(),
            pause_generation: binding.pause_generation.get(),
            capture: binding.capture.to_string(),
        }),
        mode: policy_to_wire(value.mode),
        baseline: value.baseline.as_ref().map(ToString::to_string),
        full_reason: value.full_reason.map(full_reason_to_wire),
        identity_policy: identity_policy_to_wire(value.identity_policy),
        identity_full_reason: value.identity_full_reason.map(identity_reason_to_wire),
        identity_chunk_bytes: value.identity_chunk_bytes,
        changes: Some(w::CaptureRamChanges {
            byte_len: value.changes.byte_len,
            sha256: value.changes.sha256.to_string(),
            record_count: value.changes.record_count,
            coverage: match value.changes.coverage {
                vm_spec::capture::CaptureRamCoverage::Full => w::CaptureRamCoverage::Full,
                vm_spec::capture::CaptureRamCoverage::Incremental => {
                    w::CaptureRamCoverage::Incremental
                }
            } as i32,
            baseline_stream: value.changes.baseline_stream.map(|value| value.to_string()),
        }),
        stats: Some(stats_to_wire(&value.stats)),
    }
}

fn digest(value: String, field: &'static str) -> Result<Sha256Digest, ConversionError> {
    value
        .parse()
        .map_err(|_| invalid(field, "invalid SHA-256 digest"))
}

fn memory_from_wire(
    value: w::CaptureMemoryEvidence,
) -> Result<CaptureMemoryEvidence, ConversionError> {
    let binding = required(value.binding, "capture.memory.binding")?;
    let stats = required(value.stats, "capture.memory.stats")?;
    let changes = required(value.changes, "capture.memory.changes")?;
    let memory = CaptureMemoryEvidence {
        packed_length: value.packed_length,
        page_granule: value.page_granule,
        regions: value.regions,
        ram_stream: digest(value.ram_stream, "capture.memory.ram_stream")?,
        binding: CaptureStateBinding {
            live_state_schema: binding.live_state_schema,
            architecture: binding.architecture,
            profile: digest(binding.profile, "capture.memory.binding.profile")?,
            topology: digest(binding.topology, "capture.memory.binding.topology")?,
            ram_layout: digest(binding.ram_layout, "capture.memory.binding.ram_layout")?,
            source_run: id(binding.source_run, "capture.memory.binding.source_run")?,
            pause_generation: std::num::NonZeroU64::new(binding.pause_generation).ok_or_else(
                || {
                    invalid(
                        "capture.memory.binding.pause_generation",
                        "expected nonzero generation",
                    )
                },
            )?,
            capture: id(binding.capture, "capture.memory.binding.capture")?,
        },
        mode: policy_from_wire(value.mode)?,
        baseline: value
            .baseline
            .map(|value| digest(value, "capture.memory.baseline"))
            .transpose()?,
        full_reason: value.full_reason.map(full_reason_from_wire).transpose()?,
        identity_policy: identity_policy_from_wire(value.identity_policy)?,
        identity_full_reason: value
            .identity_full_reason
            .map(identity_reason_from_wire)
            .transpose()?,
        identity_chunk_bytes: value.identity_chunk_bytes,
        changes: vm_spec::capture::CaptureRamChanges {
            byte_len: changes.byte_len,
            sha256: digest(changes.sha256, "capture.memory.changes.sha256")?,
            record_count: changes.record_count,
            coverage: match w::CaptureRamCoverage::try_from(changes.coverage) {
                Ok(w::CaptureRamCoverage::Full) => vm_spec::capture::CaptureRamCoverage::Full,
                Ok(w::CaptureRamCoverage::Incremental) => {
                    vm_spec::capture::CaptureRamCoverage::Incremental
                }
                _ => {
                    return Err(invalid(
                        "capture.memory.changes.coverage",
                        "unknown or unspecified coverage",
                    ))
                }
            },
            baseline_stream: changes
                .baseline_stream
                .map(|value| digest(value, "capture.memory.changes.baseline_stream"))
                .transpose()?,
        },
        stats: stats_from_wire(stats)?,
    };
    memory
        .validate_capture()
        .map_err(|_| invalid("capture.memory", "invalid memory receipt"))?;
    Ok(memory)
}

pub fn resume_policy_to_wire(value: CaptureResumePolicy) -> i32 {
    (match value {
        CaptureResumePolicy::ResumeIfAcquired => w::CaptureResumePolicy::ResumeIfAcquired,
        CaptureResumePolicy::Preserve => w::CaptureResumePolicy::Preserve,
    }) as i32
}

pub fn resume_policy_from_wire(value: i32) -> Result<CaptureResumePolicy, ConversionError> {
    match w::CaptureResumePolicy::try_from(value) {
        Ok(w::CaptureResumePolicy::ResumeIfAcquired) => Ok(CaptureResumePolicy::ResumeIfAcquired),
        Ok(w::CaptureResumePolicy::Preserve) => Ok(CaptureResumePolicy::Preserve),
        _ => Err(invalid(
            "capture.resume_policy",
            "unknown or unspecified enum",
        )),
    }
}

fn pause_to_wire(value: CapturePauseDisposition) -> i32 {
    (match value {
        CapturePauseDisposition::Acquired => w::CapturePauseDisposition::Acquired,
        CapturePauseDisposition::Borrowed => w::CapturePauseDisposition::Borrowed,
    }) as i32
}

fn pause_from_wire(value: i32) -> Result<CapturePauseDisposition, ConversionError> {
    match w::CapturePauseDisposition::try_from(value) {
        Ok(w::CapturePauseDisposition::Acquired) => Ok(CapturePauseDisposition::Acquired),
        Ok(w::CapturePauseDisposition::Borrowed) => Ok(CapturePauseDisposition::Borrowed),
        _ => Err(invalid("capture.pause", "unknown or unspecified enum")),
    }
}

fn source_to_wire(value: libvm::LiveCaptureSource) -> i32 {
    (match value {
        libvm::LiveCaptureSource::Resumed => w::CaptureSourceOutcome::Resumed,
        libvm::LiveCaptureSource::Preserved => w::CaptureSourceOutcome::Preserved,
        libvm::LiveCaptureSource::ResumeFailed => w::CaptureSourceOutcome::ResumeFailed,
        libvm::LiveCaptureSource::Unknown => w::CaptureSourceOutcome::Unknown,
    }) as i32
}

fn source_from_wire(value: i32) -> Result<Option<libvm::LiveCaptureSource>, ConversionError> {
    match w::CaptureSourceOutcome::try_from(value) {
        Ok(w::CaptureSourceOutcome::Unspecified) => Ok(None),
        Ok(w::CaptureSourceOutcome::Resumed) => Ok(Some(libvm::LiveCaptureSource::Resumed)),
        Ok(w::CaptureSourceOutcome::Preserved) => Ok(Some(libvm::LiveCaptureSource::Preserved)),
        Ok(w::CaptureSourceOutcome::ResumeFailed) => {
            Ok(Some(libvm::LiveCaptureSource::ResumeFailed))
        }
        Ok(w::CaptureSourceOutcome::Unknown) => Ok(Some(libvm::LiveCaptureSource::Unknown)),
        Err(_) => Err(invalid("capture.source_outcome", "unknown enum")),
    }
}

fn id(value: String, field: &'static str) -> Result<LiveId, ConversionError> {
    LiveId::parse(&value).map_err(|_| invalid(field, "noncanonical or nil UUID"))
}

/// Relative `machines/<id>/captures/<id>` diagnostic path: no absolute or
/// parent components, UTF-8 only.
fn staging_to_wire(value: &Path) -> Result<String, ConversionError> {
    let value = value
        .to_str()
        .ok_or_else(|| invalid("capture.staging", "non-UTF-8 path"))?
        .to_owned();
    staging_from_wire(value.clone())?;
    Ok(value)
}

fn staging_from_wire(value: String) -> Result<PathBuf, ConversionError> {
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty()
        || path.as_os_str().len() > 4096
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(invalid(
            "capture.staging",
            "expected a relative path of normal components",
        ));
    }
    Ok(path)
}

fn summary_to_wire(
    value: &libvm::LiveCaptureSummary,
) -> Result<w::LiveCaptureSummary, ConversionError> {
    Ok(w::LiveCaptureSummary {
        capture_id: value.capture_id.to_string(),
        machine_id: value.machine_id.to_string(),
        run_id: value.run_id.to_string(),
        resume_policy: resume_policy_to_wire(value.resume_policy),
        pause: pause_to_wire(value.pause),
        source_outcome: source_to_wire(value.source_outcome),
        source_error: value.source_error.as_ref().map(ToString::to_string),
        released: value.released,
        staging: staging_to_wire(&value.staging)?,
        memory: Some(memory_to_wire(&value.memory)),
        first_snapshot_full_identity_reason: value
            .first_snapshot_full_identity_reason
            .as_ref()
            .map(|reason| match reason {
                libvm::SnapshotIdentityReason::UnknownAfterFork => {
                    w::SnapshotIdentityReason::UnknownAfterFork as i32
                }
            }),
    })
}

fn summary_from_wire(
    value: w::LiveCaptureSummary,
) -> Result<libvm::LiveCaptureSummary, ConversionError> {
    let source_outcome = source_from_wire(value.source_outcome)?
        .ok_or_else(|| invalid("capture.source_outcome", "required value is absent"))?;
    let source_error = value
        .source_error
        .map(|error| {
            Diagnostic::try_from(error)
                .map_err(|_| invalid("capture.source_error", "oversized diagnostic"))
        })
        .transpose()?;
    if source_error.is_some() != (source_outcome == libvm::LiveCaptureSource::ResumeFailed) {
        return Err(invalid(
            "capture.source_error",
            "failed continuation requires an error and other outcomes forbid one",
        ));
    }
    let resume_policy = resume_policy_from_wire(value.resume_policy)?;
    let pause = pause_from_wire(value.pause)?;
    if (pause == CapturePauseDisposition::Borrowed
        && resume_policy != CaptureResumePolicy::Preserve)
        || (source_outcome == libvm::LiveCaptureSource::Resumed
            && (pause == CapturePauseDisposition::Borrowed
                || resume_policy == CaptureResumePolicy::Preserve))
    {
        return Err(invalid(
            "capture.source_outcome",
            "continuation contradicts pause ownership",
        ));
    }
    let summary = libvm::LiveCaptureSummary {
        capture_id: id(value.capture_id, "capture.capture_id")?,
        machine_id: id(value.machine_id, "capture.machine_id")?,
        run_id: id(value.run_id, "capture.run_id")?,
        resume_policy,
        pause,
        source_outcome,
        source_error,
        released: value.released,
        staging: staging_from_wire(value.staging)?,
        memory: memory_from_wire(required(value.memory, "capture.memory")?)?,
        first_snapshot_full_identity_reason: value
            .first_snapshot_full_identity_reason
            .map(|reason| match w::SnapshotIdentityReason::try_from(reason) {
                Ok(w::SnapshotIdentityReason::UnknownAfterFork) => {
                    Ok(libvm::SnapshotIdentityReason::UnknownAfterFork)
                }
                _ => Err(invalid(
                    "capture.first_snapshot_full_identity_reason",
                    "unknown or unspecified reason",
                )),
            })
            .transpose()?,
    };
    if summary.memory.binding.source_run != summary.run_id
        || summary.memory.binding.capture != summary.capture_id
    {
        return Err(invalid(
            "capture.memory.binding",
            "receipt belongs to another capture or run",
        ));
    }
    Ok(summary)
}

pub fn created_snapshot_to_wire(
    value: &libvm::CreatedSnapshot,
) -> Result<w::CreatedSnapshot, ConversionError> {
    let result = w::CreatedSnapshot {
        snapshot: Some(crate::stopped::info_to_wire(&value.snapshot)?),
        capture: value.capture.as_ref().map(summary_to_wire).transpose()?,
        name_conflict: value.naming_outcome.as_ref().map(|outcome| match outcome {
            libvm::CaptureNamingOutcome::NameConflict { name } => name.clone(),
        }),
    };
    created_snapshot_from_wire(result.clone())?;
    Ok(result)
}

/// A capture is present exactly for a snapshot with memory, and the snapshot
/// carries that capture's provenance.
pub fn created_snapshot_from_wire(
    value: w::CreatedSnapshot,
) -> Result<libvm::CreatedSnapshot, ConversionError> {
    let snapshot = crate::stopped::info_from_wire(required(value.snapshot, "created.snapshot")?)?;
    let capture = value.capture.map(summary_from_wire).transpose()?;
    match (&capture, snapshot.memory) {
        (Some(capture), libvm::SnapshotMemory::Included) => {
            if !snapshot.provenance.iter().any(|provenance| {
                provenance.capture_id.to_string() == capture.capture_id.as_str()
                    && provenance.machine_id.to_string() == capture.machine_id.as_str()
                    && provenance.run_id.to_string() == capture.run_id.as_str()
            }) {
                return Err(invalid(
                    "created.snapshot.provenance",
                    "snapshot lacks this capture's provenance",
                ));
            }
        }
        (None, libvm::SnapshotMemory::None) => {}
        _ => {
            return Err(invalid(
                "created.capture",
                "a capture is present exactly for a snapshot with memory",
            ))
        }
    }
    let naming_outcome = value
        .name_conflict
        .map(|name| {
            let name = crate::local_name(&name)?;
            if snapshot.names.contains(&name) {
                return Err(invalid(
                    "created.name_conflict",
                    "the snapshot was kept without the conflicting name",
                ));
            }
            Ok(libvm::CaptureNamingOutcome::NameConflict { name })
        })
        .transpose()?;
    Ok(libvm::CreatedSnapshot {
        snapshot,
        capture,
        naming_outcome,
    })
}

fn stage_to_wire(value: libvm::MachineCaptureStage) -> i32 {
    (match value {
        libvm::MachineCaptureStage::Reserved => w::MachineCaptureStage::Reserved,
        libvm::MachineCaptureStage::Sealed => w::MachineCaptureStage::Sealed,
        libvm::MachineCaptureStage::Published => w::MachineCaptureStage::Published,
    }) as i32
}

fn stage_from_wire(value: i32) -> Result<libvm::MachineCaptureStage, ConversionError> {
    match w::MachineCaptureStage::try_from(value) {
        Ok(w::MachineCaptureStage::Reserved) => Ok(libvm::MachineCaptureStage::Reserved),
        Ok(w::MachineCaptureStage::Sealed) => Ok(libvm::MachineCaptureStage::Sealed),
        Ok(w::MachineCaptureStage::Published) => Ok(libvm::MachineCaptureStage::Published),
        _ => Err(invalid("capture.stage", "unknown or unspecified enum")),
    }
}

pub fn machine_capture_to_wire(
    value: &libvm::MachineCapture,
) -> Result<w::MachineCapture, ConversionError> {
    Ok(w::MachineCapture {
        capture_id: value.capture_id.to_string(),
        run_id: value.run_id.to_string(),
        resume_policy: resume_policy_to_wire(value.resume_policy),
        pause: pause_to_wire(value.pause),
        stage: stage_to_wire(value.stage),
        snapshot_id: value.snapshot_id.as_ref().map(ToString::to_string),
        source_outcome: value
            .source_outcome
            .map(source_to_wire)
            .unwrap_or(w::CaptureSourceOutcome::Unspecified as i32),
        staging: staging_to_wire(&value.staging)?,
    })
}

pub fn machine_capture_from_wire(
    value: w::MachineCapture,
) -> Result<libvm::MachineCapture, ConversionError> {
    let stage = stage_from_wire(value.stage)?;
    let snapshot_id = value
        .snapshot_id
        .map(|snapshot| {
            snapshot
                .parse()
                .map_err(|_| invalid("capture.snapshot_id", "invalid snapshot identity"))
        })
        .transpose()?;
    if snapshot_id.is_some() != (stage == libvm::MachineCaptureStage::Published) {
        return Err(invalid(
            "capture.snapshot_id",
            "a snapshot identity is present exactly once published",
        ));
    }
    Ok(libvm::MachineCapture {
        capture_id: id(value.capture_id, "capture.capture_id")?,
        run_id: id(value.run_id, "capture.run_id")?,
        resume_policy: resume_policy_from_wire(value.resume_policy)?,
        pause: pause_from_wire(value.pause)?,
        stage,
        snapshot_id,
        source_outcome: source_from_wire(value.source_outcome)?,
        staging: staging_from_wire(value.staging)?,
    })
}

#[cfg(test)]
mod tests {
    use silod_spec::daemon::v1 as w;
    use vm_spec::capture::CapturePauseDisposition;
    use vm_spec::lifecycle::{CaptureResumePolicy, Diagnostic, LiveId};

    use crate::capture::{
        created_snapshot_from_wire, created_snapshot_to_wire, machine_capture_from_wire,
        machine_capture_to_wire, resume_policy_from_wire,
    };

    const CAPTURE: &str = "00000000-0000-4000-8000-000000000001";
    const MACHINE: &str = "00000000-0000-4000-8000-000000000002";
    const RUN: &str = "00000000-0000-4000-8000-000000000003";

    fn snapshot() -> libvm::SnapshotInfo {
        libvm::SnapshotInfo {
            id: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            record_digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
            memory: libvm::SnapshotMemory::Included,
            provenance: vec![libvm::SnapshotCaptureProvenance {
                capture_id: CAPTURE.parse().unwrap(),
                machine_id: MACHINE.parse().unwrap(),
                run_id: RUN.parse().unwrap(),
                evidence_digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
            }],
            names: vec!["snapshot".into()],
            created_at: 1,
            streams: Vec::new(),
        }
    }

    fn memory() -> vm_spec::capture::CaptureMemoryEvidence {
        let digest: vm_spec::capture::Sha256Digest =
            format!("sha256:{}", "d".repeat(64)).parse().unwrap();
        let length = 3 * 65_536;
        vm_spec::capture::CaptureMemoryEvidence {
            packed_length: length,
            page_granule: 4096,
            regions: 1,
            ram_stream: vm_spec::stream_map::StreamRoot::empty(
                length,
                vm_spec::stream_map::ChunkSize::RAM,
            )
            .unwrap()
            .id(),
            binding: vm_spec::capture::CaptureStateBinding {
                live_state_schema: "silo.live-state/1".into(),
                architecture: "x86_64".into(),
                profile: digest,
                topology: digest,
                ram_layout: digest,
                source_run: LiveId::parse(RUN).unwrap(),
                pause_generation: std::num::NonZeroU64::new(1).unwrap(),
                capture: LiveId::parse(CAPTURE).unwrap(),
            },
            mode: vm_spec::lifecycle::CapturePolicy::Full,
            baseline: None,
            full_reason: Some(vm_spec::capture::CaptureFullReason::Requested),
            identity_policy: vm_spec::capture::CaptureIdentityPolicy::Full,
            identity_full_reason: Some(vm_spec::capture::CaptureIdentityFullReason::Requested),
            identity_chunk_bytes: 65_536,
            changes: vm_spec::capture::CaptureRamChanges {
                byte_len: 16,
                sha256: vm_spec::capture::Sha256Digest::of_bytes(b"KRUNRAM\0\x01\0\x10\0\0\0\0\0"),
                record_count: 0,
                coverage: vm_spec::capture::CaptureRamCoverage::Full,
                baseline_stream: None,
            },
            stats: vm_spec::capture::CaptureMemoryStats {
                logical_bytes: length,
                live_bytes_read: length,
                full_bytes_written: 0,
                zero_bytes_omitted: length,
                identity_bytes_hashed: 0,
                whole_file_bytes_hashed: 0,
                ..Default::default()
            },
        }
    }

    fn live() -> libvm::CreatedSnapshot {
        libvm::CreatedSnapshot {
            snapshot: snapshot(),
            naming_outcome: None,
            capture: Some(libvm::LiveCaptureSummary {
                capture_id: LiveId::parse(CAPTURE).unwrap(),
                machine_id: LiveId::parse(MACHINE).unwrap(),
                run_id: LiveId::parse(RUN).unwrap(),
                resume_policy: CaptureResumePolicy::Preserve,
                pause: CapturePauseDisposition::Borrowed,
                source_outcome: libvm::LiveCaptureSource::Preserved,
                source_error: None,
                released: true,
                staging: format!("machines/{MACHINE}/captures/{CAPTURE}").into(),
                memory: memory(),
                first_snapshot_full_identity_reason: None,
            }),
        }
    }

    #[test]
    fn fork_child_full_identity_reason_round_trips_and_rejects_unknown_reason() {
        let mut snapshot = live();
        snapshot
            .capture
            .as_mut()
            .unwrap()
            .first_snapshot_full_identity_reason =
            Some(libvm::SnapshotIdentityReason::UnknownAfterFork);
        snapshot.capture.as_mut().unwrap().memory.mode =
            vm_spec::lifecycle::CapturePolicy::Incremental;
        snapshot.capture.as_mut().unwrap().memory.full_reason = None;
        snapshot
            .capture
            .as_mut()
            .unwrap()
            .memory
            .identity_full_reason =
            Some(vm_spec::capture::CaptureIdentityFullReason::UnknownAnchorAfterFork);
        let mut wire = created_snapshot_to_wire(&snapshot).unwrap();
        assert_eq!(created_snapshot_from_wire(wire.clone()).unwrap(), snapshot);
        wire.capture
            .as_mut()
            .unwrap()
            .first_snapshot_full_identity_reason = Some(0);
        assert!(created_snapshot_from_wire(wire).is_err());
    }

    #[test]
    fn identity_full_reasons_round_trip_without_conflating_cold_boot_and_fork() {
        use vm_spec::capture::CaptureIdentityFullReason as Reason;
        for reason in [
            Reason::Requested,
            Reason::NoIdentifiedAnchor,
            Reason::UnknownAnchorAfterFork,
            Reason::CoverageLost,
        ] {
            let wire = crate::capture::identity_reason_to_wire(reason);
            assert_eq!(
                crate::capture::identity_reason_from_wire(wire).unwrap(),
                reason
            );
        }
        assert!(crate::capture::identity_reason_from_wire(0).is_err());
    }

    #[test]
    fn identity_read_work_and_fallback_reasons_round_trip_strictly() {
        use vm_spec::capture::CaptureIdentityReadFallback as Reason;
        for reason in [
            Reason::None,
            Reason::CoverageLost,
            Reason::BaselineMismatch,
            Reason::ExtentsUnavailable,
            Reason::ExtentLimit,
        ] {
            let mut value = live();
            value
                .capture
                .as_mut()
                .unwrap()
                .memory
                .stats
                .full_identity_read_fallback = reason;
            value
                .capture
                .as_mut()
                .unwrap()
                .memory
                .stats
                .live_pages_classified = 7;
            value
                .capture
                .as_mut()
                .unwrap()
                .memory
                .stats
                .identity_zero_bytes_filled = 4096;
            let wire = created_snapshot_to_wire(&value).unwrap();
            assert_eq!(created_snapshot_from_wire(wire).unwrap(), value);
        }
        for value in [0, -1, 6, i32::MAX] {
            assert!(crate::capture::identity_read_fallback_from_wire(value).is_err());
        }
    }

    #[test]
    fn capture_policy_round_trips_default_preference_and_full_override() {
        let default = libvm::LiveSnapshotOptions::default().policy;
        assert_eq!(default, vm_spec::lifecycle::CapturePolicy::Incremental);
        for policy in [default, vm_spec::lifecycle::CapturePolicy::Full] {
            let wire = crate::capture::policy_to_wire(policy);
            assert_eq!(crate::capture::policy_from_wire(wire).unwrap(), policy);
        }
    }

    #[test]
    fn capture_policy_and_crossover_reject_unspecified_or_out_of_range_requests() {
        for policy in [0, -1, 3, i32::MAX] {
            assert!(crate::capture::policy_from_wire(policy).is_err());
        }
        for crossover in [0, 61, 256, u32::MAX] {
            assert!(crate::capture::crossover_from_wire(crossover).is_err());
        }
        for crossover in [1, 60] {
            assert_eq!(
                u32::from(crate::capture::crossover_from_wire(crossover).unwrap()),
                crossover
            );
        }
    }

    #[test]
    fn capture_name_conflict_round_trips_and_reports_kept_snapshot() {
        let mut value = live();
        value.naming_outcome = Some(libvm::CaptureNamingOutcome::NameConflict {
            name: "taken".into(),
        });
        let wire = created_snapshot_to_wire(&value).unwrap();
        assert_eq!(wire.name_conflict.as_deref(), Some("taken"));
        let decoded = created_snapshot_from_wire(wire.clone()).unwrap();
        assert_eq!(decoded, value);
        assert!(matches!(
            decoded.require_requested_name(),
            Err(libvm::LibVmError::CaptureNameConflict { name, snapshot })
                if name == "taken" && snapshot == value.snapshot.id
        ));
        let mut invalid = wire.clone();
        invalid.name_conflict = Some("bad name".into());
        assert!(created_snapshot_from_wire(invalid).is_err());
        let mut invalid = wire;
        invalid
            .snapshot
            .as_mut()
            .unwrap()
            .names
            .push("taken".into());
        assert!(created_snapshot_from_wire(invalid).is_err());
        assert!(live().require_requested_name().is_ok());
    }

    #[test]
    fn created_snapshot_carries_a_capture_exactly_with_memory() {
        let wire = created_snapshot_to_wire(&live()).unwrap();
        let mut without_capture = wire.clone();
        without_capture.capture = None;
        assert!(created_snapshot_from_wire(without_capture).is_err());

        let mut stopped = live();
        stopped.capture = None;
        stopped.snapshot.memory = libvm::SnapshotMemory::None;
        stopped.snapshot.provenance.clear();
        let stopped_wire = created_snapshot_to_wire(&stopped).unwrap();
        assert_eq!(
            created_snapshot_from_wire(stopped_wire.clone()).unwrap(),
            stopped
        );
        let mut with_capture = stopped_wire;
        with_capture.capture = wire.capture;
        assert!(created_snapshot_from_wire(with_capture).is_err());
    }

    #[test]
    fn capture_receipt_rejects_foreign_binding_and_incoherent_memory_evidence() {
        let wire = created_snapshot_to_wire(&live()).unwrap();
        for case in 0..12 {
            let mut changed = wire.clone();
            let capture = changed.capture.as_mut().unwrap();
            let memory = capture.memory.as_mut().unwrap();
            match case {
                0 => memory.mode = w::CapturePolicy::Unspecified as i32,
                1 => memory.full_reason = Some(w::CaptureFullReason::Unspecified as i32),
                2 => memory.full_reason = None,
                3 => memory.baseline = Some(memory.ram_stream.clone()),
                4 => memory.identity_chunk_bytes = 8 * 1024 * 1024,
                5 => memory.changes = None,
                6 => memory.stats.as_mut().unwrap().logical_bytes -= 1,
                7 => memory.stats.as_mut().unwrap().identity_bytes_hashed += 1,
                8 => memory.binding.as_mut().unwrap().source_run = MACHINE.into(),
                9 => memory.binding.as_mut().unwrap().capture = MACHINE.into(),
                10 => memory.binding.as_mut().unwrap().pause_generation = 0,
                11 => capture.memory = None,
                _ => unreachable!(),
            }
            assert!(created_snapshot_from_wire(changed).is_err(), "case {case}");
        }
        let mut incremental = wire;
        let memory = incremental
            .capture
            .as_mut()
            .unwrap()
            .memory
            .as_mut()
            .unwrap();
        memory.mode = w::CapturePolicy::Incremental as i32;
        memory.full_reason = None;
        memory.identity_policy = w::CaptureIdentityPolicy::SinceAnchor as i32;
        memory.identity_full_reason = None;
        memory.changes.as_mut().unwrap().coverage = w::CaptureRamCoverage::Incremental as i32;
        assert!(created_snapshot_from_wire(incremental).is_err());
    }

    #[test]
    fn memory_change_reference_round_trips_without_per_chunk_entries() {
        use prost::Message;
        let mut value = live();
        let wire = created_snapshot_to_wire(&value).unwrap();
        let encoded = wire.encode_to_vec();
        assert!(encoded.len() < 4096);
        let decoded = w::CreatedSnapshot::decode(encoded.as_slice()).unwrap();
        assert_eq!(created_snapshot_from_wire(decoded).unwrap(), value);
        for case in 0..5 {
            let mut invalid = wire.clone();
            let changes = invalid
                .capture
                .as_mut()
                .unwrap()
                .memory
                .as_mut()
                .unwrap()
                .changes
                .as_mut()
                .unwrap();
            match case {
                0 => changes.coverage = 0,
                1 => changes.sha256 = "invalid".into(),
                2 => changes.byte_len = 15,
                3 => changes.record_count = 1,
                4 => changes.baseline_stream = Some("invalid".into()),
                _ => unreachable!(),
            }
            assert!(created_snapshot_from_wire(invalid).is_err(), "case {case}");
        }
        let memory = &mut value.capture.as_mut().unwrap().memory;
        memory.mode = vm_spec::lifecycle::CapturePolicy::Incremental;
        memory.baseline = Some(vm_spec::capture::Sha256Digest::of_bytes(b"baseline"));
        memory.full_reason = None;
        memory.identity_policy = vm_spec::capture::CaptureIdentityPolicy::SinceAnchor;
        memory.identity_full_reason = None;
        memory.changes.coverage = vm_spec::capture::CaptureRamCoverage::Incremental;
        memory.changes.baseline_stream = memory.baseline;
        memory.stats.full_bytes_written = 0;
        memory.stats.live_bytes_read = 0;
        memory.stats.identity_bytes_hashed = 0;
        memory.stats.zero_bytes_omitted = 0;
        let wire = created_snapshot_to_wire(&value).unwrap();
        assert_eq!(created_snapshot_from_wire(wire).unwrap(), value);
    }

    #[test]
    fn created_snapshot_round_trips_exact_capture_identity() {
        let value = live();
        let wire = created_snapshot_to_wire(&value).unwrap();
        assert_eq!(created_snapshot_from_wire(wire).unwrap(), value);
    }

    #[test]
    fn memory_zero_stats_round_trip_through_protobuf() {
        use prost::Message;

        let mut value = memory();
        value.stats.explicit_zero_bytes_written = 4096;
        value.stats.zero_run_bytes_covered = 7 * 4096;
        value.stats.zero_bytes_punched = 2 * 4096;
        value.stats.known_zero_bytes_skipped = 3 * 4096;
        let wire = crate::capture::memory_to_wire(&value);
        let stats = wire.stats.as_ref().unwrap();
        assert_eq!(stats.explicit_zero_bytes_written, 4096);
        assert_eq!(stats.zero_run_bytes_covered, 7 * 4096);
        assert_eq!(stats.zero_bytes_punched, 2 * 4096);
        assert_eq!(stats.known_zero_bytes_skipped, 3 * 4096);
        let decoded = w::CaptureMemoryEvidence::decode(wire.encode_to_vec().as_slice()).unwrap();
        assert_eq!(crate::capture::memory_from_wire(decoded).unwrap(), value);
    }

    #[test]
    fn created_snapshot_rejects_memoryless_kind_foreign_provenance_and_path_authority() {
        let wire = created_snapshot_to_wire(&live()).unwrap();
        let mut stopped = wire.clone();
        let info = stopped.snapshot.as_mut().unwrap();
        info.memory = w::SnapshotMemory::None as i32;
        info.provenance.clear();
        assert!(created_snapshot_from_wire(stopped).is_err());

        let mut foreign = wire.clone();
        foreign.snapshot.as_mut().unwrap().provenance[0].capture_id =
            "00000000-0000-4000-8000-000000000009".into();
        assert!(created_snapshot_from_wire(foreign).is_err());

        for staging in ["/home/user/.silo/machines/x", "machines/../etc", ""] {
            let mut path = wire.clone();
            path.capture.as_mut().unwrap().staging = staging.into();
            assert!(created_snapshot_from_wire(path).is_err(), "{staging}");
        }

        let mut unspecified = wire.clone();
        unspecified.capture.as_mut().unwrap().source_outcome =
            w::CaptureSourceOutcome::Unspecified as i32;
        assert!(created_snapshot_from_wire(unspecified).is_err());

        let mut error_without_failure = wire;
        error_without_failure.capture.as_mut().unwrap().source_error = Some("boom".into());
        assert!(created_snapshot_from_wire(error_without_failure).is_err());
    }

    #[test]
    fn created_snapshot_rejects_foreign_source_and_impossible_continuation() {
        let wire = created_snapshot_to_wire(&live()).unwrap();
        for field in ["machine", "run"] {
            let mut changed = wire.clone();
            let summary = changed.capture.as_mut().unwrap();
            if field == "machine" {
                summary.machine_id = CAPTURE.into();
            } else {
                summary.run_id = CAPTURE.into();
            }
            assert!(created_snapshot_from_wire(changed).is_err(), "{field}");
            let mut changed = live();
            if field == "machine" {
                changed.capture.as_mut().unwrap().machine_id = LiveId::parse(CAPTURE).unwrap();
            } else {
                changed.capture.as_mut().unwrap().run_id = LiveId::parse(CAPTURE).unwrap();
            }
            assert!(created_snapshot_to_wire(&changed).is_err(), "{field}");
        }
        for (policy, pause, outcome) in [
            (
                CaptureResumePolicy::ResumeIfAcquired,
                CapturePauseDisposition::Borrowed,
                libvm::LiveCaptureSource::Preserved,
            ),
            (
                CaptureResumePolicy::Preserve,
                CapturePauseDisposition::Acquired,
                libvm::LiveCaptureSource::Resumed,
            ),
            (
                CaptureResumePolicy::Preserve,
                CapturePauseDisposition::Borrowed,
                libvm::LiveCaptureSource::Resumed,
            ),
            (
                CaptureResumePolicy::ResumeIfAcquired,
                CapturePauseDisposition::Acquired,
                libvm::LiveCaptureSource::ResumeFailed,
            ),
        ] {
            let mut changed = live();
            changed.capture.as_mut().unwrap().resume_policy = policy;
            changed.capture.as_mut().unwrap().pause = pause;
            changed.capture.as_mut().unwrap().source_outcome = outcome;
            assert!(created_snapshot_to_wire(&changed).is_err());
            let mut changed = wire.clone();
            let summary = changed.capture.as_mut().unwrap();
            summary.resume_policy = crate::capture::resume_policy_to_wire(policy);
            summary.pause = crate::capture::pause_to_wire(pause);
            summary.source_outcome = crate::capture::source_to_wire(outcome);
            assert!(created_snapshot_from_wire(changed).is_err());
        }
    }

    #[test]
    fn failed_continuation_keeps_its_diagnostic_and_unknown_is_distinct() {
        let mut value = live();
        value.capture.as_mut().unwrap().source_outcome = libvm::LiveCaptureSource::ResumeFailed;
        value.capture.as_mut().unwrap().source_error = Some(Diagnostic::new("thaw unacknowledged"));
        let wire = created_snapshot_to_wire(&value).unwrap();
        assert_eq!(created_snapshot_from_wire(wire).unwrap(), value);
        value.capture.as_mut().unwrap().source_outcome = libvm::LiveCaptureSource::Unknown;
        value.capture.as_mut().unwrap().source_error = None;
        let wire = created_snapshot_to_wire(&value).unwrap();
        assert_eq!(
            wire.capture.as_ref().unwrap().source_outcome,
            w::CaptureSourceOutcome::Unknown as i32
        );
        assert_eq!(created_snapshot_from_wire(wire).unwrap(), value);
    }

    #[test]
    fn resume_policy_requires_an_explicit_value() {
        assert!(resume_policy_from_wire(w::CaptureResumePolicy::Unspecified as i32).is_err());
        assert_eq!(
            resume_policy_from_wire(w::CaptureResumePolicy::Preserve as i32).unwrap(),
            CaptureResumePolicy::Preserve
        );
    }

    #[test]
    fn machine_capture_binds_snapshot_identity_to_publication() {
        let mut value = libvm::MachineCapture {
            capture_id: LiveId::parse(CAPTURE).unwrap(),
            run_id: LiveId::parse(RUN).unwrap(),
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            pause: CapturePauseDisposition::Acquired,
            stage: libvm::MachineCaptureStage::Reserved,
            snapshot_id: None,
            source_outcome: None,
            staging: format!("machines/{MACHINE}/captures/{CAPTURE}").into(),
        };
        let wire = machine_capture_to_wire(&value).unwrap();
        assert_eq!(machine_capture_from_wire(wire.clone()).unwrap(), value);
        let mut published_without_id = wire;
        published_without_id.stage = w::MachineCaptureStage::Published as i32;
        assert!(machine_capture_from_wire(published_without_id).is_err());
        value.stage = libvm::MachineCaptureStage::Published;
        value.snapshot_id = Some(snapshot().id);
        value.source_outcome = Some(libvm::LiveCaptureSource::Resumed);
        let wire = machine_capture_to_wire(&value).unwrap();
        assert_eq!(machine_capture_from_wire(wire).unwrap(), value);
    }

    #[test]
    fn memory_seed_method_round_trips_clone_and_rebuild_receipts() {
        use vm_spec::capture::CaptureSeedMethod;

        for (method, expected) in [
            (CaptureSeedMethod::Clone, w::CaptureSeedMethod::Clone),
            (CaptureSeedMethod::Rebuild, w::CaptureSeedMethod::Rebuild),
        ] {
            let mut value = live();
            let memory = &mut value.capture.as_mut().unwrap().memory;
            memory.mode = vm_spec::lifecycle::CapturePolicy::Incremental;
            memory.baseline = Some(vm_spec::capture::Sha256Digest::of_bytes(b"baseline"));
            memory.full_reason = None;
            memory.identity_policy = vm_spec::capture::CaptureIdentityPolicy::SinceAnchor;
            memory.identity_full_reason = None;
            memory.changes.coverage = vm_spec::capture::CaptureRamCoverage::Incremental;
            memory.changes.baseline_stream = memory.baseline;
            memory.stats.seed_method = method;
            memory.stats.full_bytes_written = 0;
            memory.stats.overlay_bytes_written = 0;
            memory.stats.live_bytes_read = 0;
            memory.stats.zero_bytes_omitted = 0;
            let wire = created_snapshot_to_wire(&value).unwrap();
            assert_eq!(
                wire.capture
                    .as_ref()
                    .unwrap()
                    .memory
                    .as_ref()
                    .unwrap()
                    .stats
                    .as_ref()
                    .unwrap()
                    .seed_method,
                expected as i32
            );
            assert_eq!(created_snapshot_from_wire(wire).unwrap(), value);
        }
    }

    #[test]
    fn memory_seed_method_rejects_unspecified_and_unknown_wire_values() {
        let wire = created_snapshot_to_wire(&live()).unwrap();
        for method in [w::CaptureSeedMethod::Unspecified as i32, -1, 3, i32::MAX] {
            let mut changed = wire.clone();
            changed
                .capture
                .as_mut()
                .unwrap()
                .memory
                .as_mut()
                .unwrap()
                .stats
                .as_mut()
                .unwrap()
                .seed_method = method;
            assert!(
                created_snapshot_from_wire(changed).is_err(),
                "method {method}"
            );
        }
    }
}
