//! Strict daemon transport of live execution captures. Capture identity is
//! the request/operation UUID; staging is a relative diagnostic path only.
use std::path::{Component, Path, PathBuf};

use silod_spec::daemon::v1 as w;
use vm_spec::capture::{
    CaptureFullReason, CaptureMemoryEvidence, CaptureMemoryStats, CapturePauseDisposition,
    CaptureSeedMethod, CaptureStateBinding, Sha256Digest,
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

fn memory_to_wire(value: &CaptureMemoryEvidence) -> w::CaptureMemoryEvidence {
    let binding = &value.binding;
    let stats = &value.stats;
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
        dirty_chunks: value.dirty_chunks.clone(),
        chunk_digests: value
            .chunk_digests
            .iter()
            .map(|digest| match digest {
                Some(digest) => digest.as_bytes().to_vec(),
                None => Vec::new(),
            })
            .collect(),
        stats: Some(w::CaptureMemoryStats {
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
            extent_queries: stats.extent_queries,
            identity_bytes_hashed: stats.identity_bytes_hashed,
            whole_file_bytes_hashed: stats.whole_file_bytes_hashed,
        }),
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
        dirty_chunks: value.dirty_chunks,
        chunk_digests: value
            .chunk_digests
            .into_iter()
            .map(|bytes| {
                if bytes.is_empty() {
                    return Ok(None);
                }
                let digest: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    invalid(
                        "capture.memory.chunk_digests",
                        "expected an empty entry or exactly 32 digest bytes",
                    )
                })?;
                Ok(Some(Sha256Digest::from_bytes(digest)))
            })
            .collect::<Result<Vec<_>, ConversionError>>()?,
        stats: CaptureMemoryStats {
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
            extent_queries: stats.extent_queries,
            identity_bytes_hashed: stats.identity_bytes_hashed,
            whole_file_bytes_hashed: stats.whole_file_bytes_hashed,
        },
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

pub fn live_snapshot_to_wire(
    value: &libvm::LiveSnapshot,
) -> Result<w::LiveSnapshotInfo, ConversionError> {
    let result = w::LiveSnapshotInfo {
        snapshot: Some(crate::stopped::info_to_wire(&value.snapshot)?),
        capture: Some(summary_to_wire(&value.capture)?),
        alias_conflict: value.naming_outcome.as_ref().map(|outcome| match outcome {
            libvm::CaptureNamingOutcome::AliasConflict { alias } => alias.clone(),
        }),
    };
    live_snapshot_from_wire(result.clone())?;
    Ok(result)
}

pub fn live_snapshot_from_wire(
    value: w::LiveSnapshotInfo,
) -> Result<libvm::LiveSnapshot, ConversionError> {
    let snapshot = crate::stopped::info_from_wire(required(value.snapshot, "live.snapshot")?)?;
    let capture = summary_from_wire(required(value.capture, "live.capture")?)?;
    if snapshot.capture_kind != libvm::SnapshotCaptureKindName::LiveExecution {
        return Err(invalid(
            "live.snapshot",
            "expected a live execution checkpoint",
        ));
    }
    if !snapshot.provenance.iter().any(|provenance| {
        provenance.capture_id.to_string() == capture.capture_id.as_str()
            && provenance.machine_id.to_string() == capture.machine_id.as_str()
            && provenance.run_id.to_string() == capture.run_id.as_str()
    }) {
        return Err(invalid(
            "live.snapshot.provenance",
            "checkpoint lacks this capture's provenance",
        ));
    }
    let naming_outcome = value
        .alias_conflict
        .map(|alias| {
            let alias = crate::stopped::alias(&alias)?;
            if !snapshot.retained || snapshot.aliases.contains(&alias) {
                return Err(invalid(
                    "live.alias_conflict",
                    "conflicting checkpoint must be retained without the requested alias",
                ));
            }
            Ok(libvm::CaptureNamingOutcome::AliasConflict { alias })
        })
        .transpose()?;
    Ok(libvm::LiveSnapshot {
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
            "a checkpoint identity is present exactly once published",
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
        live_snapshot_from_wire, live_snapshot_to_wire, machine_capture_from_wire,
        machine_capture_to_wire, resume_policy_from_wire,
    };

    const CAPTURE: &str = "00000000-0000-4000-8000-000000000001";
    const MACHINE: &str = "00000000-0000-4000-8000-000000000002";
    const RUN: &str = "00000000-0000-4000-8000-000000000003";

    fn snapshot() -> libvm::SnapshotInfo {
        libvm::SnapshotInfo {
            id: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            record_digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
            capture_kind: libvm::SnapshotCaptureKindName::LiveExecution,
            provenance: vec![libvm::SnapshotCaptureProvenance {
                capture_id: CAPTURE.parse().unwrap(),
                machine_id: MACHINE.parse().unwrap(),
                run_id: RUN.parse().unwrap(),
                evidence_digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
            }],
            retained: true,
            aliases: vec!["checkpoint".into()],
            created_at: 1,
        }
    }

    fn memory() -> vm_spec::capture::CaptureMemoryEvidence {
        let digest: vm_spec::capture::Sha256Digest =
            format!("sha256:{}", "d".repeat(64)).parse().unwrap();
        let length = 3 * vm_spec::capture::STREAM_CHUNK_BYTES;
        let chunk_digests = vec![
            Some(digest),
            None,
            Some(vm_spec::capture::Sha256Digest::of_bytes(b"last chunk")),
        ];
        let mut identity = vm_spec::capture::StreamIdentity::new();
        for chunk in &chunk_digests {
            identity
                .push_digest(vm_spec::capture::STREAM_CHUNK_BYTES, *chunk)
                .unwrap();
        }
        vm_spec::capture::CaptureMemoryEvidence {
            packed_length: length,
            page_granule: 4096,
            regions: 1,
            ram_stream: identity.finish(),
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
            dirty_chunks: vec![7],
            chunk_digests,
            stats: vm_spec::capture::CaptureMemoryStats {
                logical_bytes: length,
                live_bytes_read: length,
                full_bytes_written: length,
                identity_bytes_hashed: length,
                whole_file_bytes_hashed: 0,
                ..Default::default()
            },
        }
    }

    fn live() -> libvm::LiveSnapshot {
        libvm::LiveSnapshot {
            snapshot: snapshot(),
            naming_outcome: None,
            capture: libvm::LiveCaptureSummary {
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
            },
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
    fn capture_alias_conflict_round_trips_and_reports_retained_checkpoint() {
        let mut value = live();
        value.snapshot.retained = true;
        value.naming_outcome = Some(libvm::CaptureNamingOutcome::AliasConflict {
            alias: "taken".into(),
        });
        let wire = live_snapshot_to_wire(&value).unwrap();
        assert_eq!(wire.alias_conflict.as_deref(), Some("taken"));
        let decoded = live_snapshot_from_wire(wire.clone()).unwrap();
        assert_eq!(decoded, value);
        assert!(matches!(
            decoded.require_requested_name(),
            Err(libvm::LibVmError::CaptureAliasConflict { alias, checkpoint })
                if alias == "taken" && checkpoint == value.snapshot.id
        ));
        let mut invalid = wire.clone();
        invalid.alias_conflict = Some("bad alias".into());
        assert!(live_snapshot_from_wire(invalid).is_err());
        let mut invalid = wire.clone();
        invalid.snapshot.as_mut().unwrap().retained = Some(false);
        assert!(live_snapshot_from_wire(invalid).is_err());
        let mut invalid = wire;
        invalid
            .snapshot
            .as_mut()
            .unwrap()
            .aliases
            .push("taken".into());
        assert!(live_snapshot_from_wire(invalid).is_err());
        assert!(live().require_requested_name().is_ok());
    }

    #[test]
    fn capture_receipt_rejects_foreign_binding_and_incoherent_memory_evidence() {
        let wire = live_snapshot_to_wire(&live()).unwrap();
        for case in 0..12 {
            let mut changed = wire.clone();
            let capture = changed.capture.as_mut().unwrap();
            let memory = capture.memory.as_mut().unwrap();
            match case {
                0 => memory.mode = w::CapturePolicy::Unspecified as i32,
                1 => memory.full_reason = Some(w::CaptureFullReason::Unspecified as i32),
                2 => memory.full_reason = None,
                3 => memory.baseline = Some(memory.ram_stream.clone()),
                4 => memory.dirty_chunks = vec![0],
                5 => memory.dirty_chunks = vec![3],
                6 => memory.stats.as_mut().unwrap().logical_bytes -= 1,
                7 => memory.stats.as_mut().unwrap().identity_bytes_hashed += 1,
                8 => memory.binding.as_mut().unwrap().source_run = MACHINE.into(),
                9 => memory.binding.as_mut().unwrap().capture = MACHINE.into(),
                10 => memory.binding.as_mut().unwrap().pause_generation = 0,
                11 => capture.memory = None,
                _ => unreachable!(),
            }
            assert!(live_snapshot_from_wire(changed).is_err(), "case {case}");
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
        assert!(live_snapshot_from_wire(incremental).is_err());
    }

    #[test]
    fn memory_chunk_digests_round_trip_mixed_entries_and_reject_wrong_widths() {
        let value = live();
        let wire = live_snapshot_to_wire(&value).unwrap();
        let chunks = &wire
            .capture
            .as_ref()
            .unwrap()
            .memory
            .as_ref()
            .unwrap()
            .chunk_digests;
        assert_eq!(chunks.len(), 3);
        assert_eq!(
            chunks[0].as_slice(),
            value.capture.memory.chunk_digests[0].unwrap().as_bytes()
        );
        assert!(chunks[1].is_empty());
        assert_eq!(
            chunks[2].as_slice(),
            value.capture.memory.chunk_digests[2].unwrap().as_bytes()
        );
        assert_eq!(live_snapshot_from_wire(wire.clone()).unwrap(), value);
        for length in [1, 31, 33, 64] {
            let mut invalid = wire.clone();
            invalid
                .capture
                .as_mut()
                .unwrap()
                .memory
                .as_mut()
                .unwrap()
                .chunk_digests[1] = vec![0x51; length];
            assert!(
                live_snapshot_from_wire(invalid).is_err(),
                "digest width {length}"
            );
        }
        let mut missing = wire;
        missing
            .capture
            .as_mut()
            .unwrap()
            .memory
            .as_mut()
            .unwrap()
            .chunk_digests
            .pop();
        assert!(
            live_snapshot_from_wire(missing).is_err(),
            "chunk count is part of the receipt"
        );
    }

    #[test]
    fn incremental_receipt_preserves_unaffected_chunk_digest_entries() {
        let mut value = live();
        let memory = &mut value.capture.memory;
        memory.mode = vm_spec::lifecycle::CapturePolicy::Incremental;
        memory.baseline = Some(vm_spec::capture::Sha256Digest::of_bytes(
            b"retained baseline",
        ));
        memory.full_reason = None;
        memory.dirty_chunks = vec![0b101];
        memory.stats.full_bytes_written = 0;
        memory.stats.overlay_bytes_written = 2 * vm_spec::capture::STREAM_CHUNK_BYTES;
        memory.stats.identity_bytes_hashed = 2 * vm_spec::capture::STREAM_CHUNK_BYTES;
        memory.validate_capture().unwrap();
        let wire = live_snapshot_to_wire(&value).unwrap();
        assert!(wire
            .capture
            .as_ref()
            .unwrap()
            .memory
            .as_ref()
            .unwrap()
            .chunk_digests[1]
            .is_empty());
        assert_eq!(live_snapshot_from_wire(wire).unwrap(), value);
    }

    #[test]
    fn live_snapshot_round_trips_exact_capture_identity() {
        let value = live();
        let wire = live_snapshot_to_wire(&value).unwrap();
        assert_eq!(live_snapshot_from_wire(wire).unwrap(), value);
    }

    #[test]
    fn live_snapshot_rejects_stopped_kind_foreign_provenance_and_path_authority() {
        let wire = live_snapshot_to_wire(&live()).unwrap();
        let mut stopped = wire.clone();
        let info = stopped.snapshot.as_mut().unwrap();
        info.capture_kind = w::StorageCaptureKind::StoppedStorage as i32;
        info.provenance.clear();
        assert!(live_snapshot_from_wire(stopped).is_err());

        let mut foreign = wire.clone();
        foreign.snapshot.as_mut().unwrap().provenance[0].capture_id =
            "00000000-0000-4000-8000-000000000009".into();
        assert!(live_snapshot_from_wire(foreign).is_err());

        for staging in ["/home/user/.silo/machines/x", "machines/../etc", ""] {
            let mut path = wire.clone();
            path.capture.as_mut().unwrap().staging = staging.into();
            assert!(live_snapshot_from_wire(path).is_err(), "{staging}");
        }

        let mut unspecified = wire.clone();
        unspecified.capture.as_mut().unwrap().source_outcome =
            w::CaptureSourceOutcome::Unspecified as i32;
        assert!(live_snapshot_from_wire(unspecified).is_err());

        let mut error_without_failure = wire;
        error_without_failure.capture.as_mut().unwrap().source_error = Some("boom".into());
        assert!(live_snapshot_from_wire(error_without_failure).is_err());
    }

    #[test]
    fn live_snapshot_rejects_foreign_source_and_impossible_continuation() {
        let wire = live_snapshot_to_wire(&live()).unwrap();
        for field in ["machine", "run"] {
            let mut changed = wire.clone();
            let summary = changed.capture.as_mut().unwrap();
            if field == "machine" {
                summary.machine_id = CAPTURE.into();
            } else {
                summary.run_id = CAPTURE.into();
            }
            assert!(live_snapshot_from_wire(changed).is_err(), "{field}");
            let mut changed = live();
            if field == "machine" {
                changed.capture.machine_id = LiveId::parse(CAPTURE).unwrap();
            } else {
                changed.capture.run_id = LiveId::parse(CAPTURE).unwrap();
            }
            assert!(live_snapshot_to_wire(&changed).is_err(), "{field}");
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
            changed.capture.resume_policy = policy;
            changed.capture.pause = pause;
            changed.capture.source_outcome = outcome;
            assert!(live_snapshot_to_wire(&changed).is_err());
            let mut changed = wire.clone();
            let summary = changed.capture.as_mut().unwrap();
            summary.resume_policy = crate::capture::resume_policy_to_wire(policy);
            summary.pause = crate::capture::pause_to_wire(pause);
            summary.source_outcome = crate::capture::source_to_wire(outcome);
            assert!(live_snapshot_from_wire(changed).is_err());
        }
    }

    #[test]
    fn failed_continuation_keeps_its_diagnostic_and_unknown_is_distinct() {
        let mut value = live();
        value.capture.source_outcome = libvm::LiveCaptureSource::ResumeFailed;
        value.capture.source_error = Some(Diagnostic::new("thaw unacknowledged"));
        let wire = live_snapshot_to_wire(&value).unwrap();
        assert_eq!(live_snapshot_from_wire(wire).unwrap(), value);
        value.capture.source_outcome = libvm::LiveCaptureSource::Unknown;
        value.capture.source_error = None;
        let wire = live_snapshot_to_wire(&value).unwrap();
        assert_eq!(
            wire.capture.as_ref().unwrap().source_outcome,
            w::CaptureSourceOutcome::Unknown as i32
        );
        assert_eq!(live_snapshot_from_wire(wire).unwrap(), value);
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
    fn machine_capture_binds_checkpoint_identity_to_publication() {
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
            let memory = &mut value.capture.memory;
            memory.mode = vm_spec::lifecycle::CapturePolicy::Incremental;
            memory.baseline = Some(vm_spec::capture::Sha256Digest::of_bytes(b"baseline"));
            memory.full_reason = None;
            memory.stats.seed_method = method;
            memory.stats.full_bytes_written = 0;
            memory.stats.overlay_bytes_written = 4096;
            let wire = live_snapshot_to_wire(&value).unwrap();
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
            assert_eq!(live_snapshot_from_wire(wire).unwrap(), value);
        }
    }

    #[test]
    fn memory_seed_method_rejects_unspecified_and_unknown_wire_values() {
        let wire = live_snapshot_to_wire(&live()).unwrap();
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
            assert!(live_snapshot_from_wire(changed).is_err(), "method {method}");
        }
    }
}
