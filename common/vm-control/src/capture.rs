//! Strict daemon transport of live execution captures. Capture identity is
//! the request/operation UUID; staging is a relative diagnostic path only.
use std::path::{Component, Path, PathBuf};

use silod_spec::daemon::v1 as w;
use vm_spec::capture::CapturePauseDisposition;
use vm_spec::lifecycle::{CaptureResumePolicy, Diagnostic, LiveId};

use crate::{invalid, required, ConversionError};

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
    Ok(libvm::LiveCaptureSummary {
        capture_id: id(value.capture_id, "capture.capture_id")?,
        machine_id: id(value.machine_id, "capture.machine_id")?,
        run_id: id(value.run_id, "capture.run_id")?,
        resume_policy,
        pause,
        source_outcome,
        source_error,
        released: value.released,
        staging: staging_from_wire(value.staging)?,
    })
}

pub fn live_snapshot_to_wire(
    value: &libvm::LiveSnapshot,
) -> Result<w::LiveSnapshotInfo, ConversionError> {
    let result = w::LiveSnapshotInfo {
        snapshot: Some(crate::stopped::info_to_wire(&value.snapshot)?),
        capture: Some(summary_to_wire(&value.capture)?),
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
    Ok(libvm::LiveSnapshot { snapshot, capture })
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

    fn live() -> libvm::LiveSnapshot {
        libvm::LiveSnapshot {
            snapshot: snapshot(),
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
            },
        }
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
}
