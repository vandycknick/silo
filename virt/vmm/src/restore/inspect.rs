//! `silo-vmm inspect-restore`: descriptor-only native compatibility admission
//! before the manager allocates any child resource. stdin carries exactly one
//! newline-terminated `RestoreInspectionRequest`; its four owned-cut or five
//! identified state objects are inherited at their request numbers. stdout carries one report line
//! or a typed bounded portability refusal on nonzero exit. No child VM is
//! created: native may probe an empty host-profile VM only.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{BorrowedFd, FromRawFd};
use std::time::{Duration, Instant};

use vm_spec::capture::Sha256Digest;
use vm_spec::restore::{
    RestoreInspectionReport, RestoreInspectionRequest, MAX_RESTORE_INSPECTION_BYTES,
    RESTORE_INSPECTION_VERSION,
};

const SUBCOMMAND: &str = "inspect-restore";
const INSPECTION_BUDGET: Duration = Duration::from_secs(10);

fn validate_request(
    request: &RestoreInspectionRequest,
) -> Result<(), vm_spec::restore::RestorePortabilityRefusal> {
    request.validate().map_err(|reason| {
        let (pin, expected, actual) = if request.version != RESTORE_INSPECTION_VERSION {
            (
                "inspection-schema",
                RESTORE_INSPECTION_VERSION.to_string(),
                request.version.to_string(),
            )
        } else if !request.restore.configuration.shares.is_empty()
            || request.restore.configuration.rosetta
        {
            (
                "topology.devices",
                "restore-supported devices without shares or Rosetta".into(),
                reason,
            )
        } else {
            (
                "restore-authority",
                "complete matching identified snapshot or owned-cut authority".into(),
                reason,
            )
        };
        vm_spec::restore::RestorePortabilityRefusal::new(pin, expected, actual)
    })
}

fn inspection_failure(error: &eyre::Report) -> vm_spec::restore::RestoreInspectionFailure {
    let refusal = error
        .chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<vm_spec::restore::RestorePortabilityRefusal>()
                .cloned()
                .or_else(|| {
                    cause.downcast_ref::<std::io::Error>().and_then(|error| {
                        error
                            .get_ref()
                            .and_then(|inner| {
                                inner.downcast_ref::<vm_spec::restore::RestorePortabilityRefusal>()
                            })
                            .cloned()
                    })
                })
        })
        .unwrap_or_else(|| {
            vm_spec::restore::RestorePortabilityRefusal::new(
                "restore-inputs",
                "exact supported restore inputs",
                format!("{error:#}"),
            )
        });
    vm_spec::restore::RestoreInspectionFailure {
        version: RESTORE_INSPECTION_VERSION,
        refusal,
    }
}

/// Called after private worker dispatch, before any launch initialization.
pub(crate) fn dispatch() -> Option<eyre::Result<()>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new(SUBCOMMAND)) {
        return None;
    }
    Some((|| {
        eyre::ensure!(args.next().is_none(), "{SUBCOMMAND} takes no arguments");
        let mut encoded = Vec::new();
        std::io::stdin()
            .lock()
            .take(MAX_RESTORE_INSPECTION_BYTES as u64 + 2)
            .read_to_end(&mut encoded)?;
        let report = match inspect(&encoded) {
            Ok(report) => report,
            Err(error) => {
                let failure = inspection_failure(&error);
                let mut line = serde_json::to_vec(&failure)?;
                line.push(b'\n');
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&line)?;
                stdout.flush()?;
                return Err(error);
            }
        };
        let mut line = serde_json::to_vec(&report)?;
        eyre::ensure!(
            line.len() <= vm_spec::restore::MAX_RESTORE_INSPECTION_REPORT_BYTES,
            "restore inspection report exceeds its bound"
        );
        line.push(b'\n');
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&line)?;
        stdout.flush()?;
        Ok(())
    })())
}

/// Strict single-record decoding, then exact admission of these inputs.
pub(crate) fn inspect(encoded: &[u8]) -> eyre::Result<RestoreInspectionReport> {
    let record = encoded
        .strip_suffix(b"\n")
        .ok_or_else(|| eyre::eyre!("inspection request is not newline terminated"))?;
    eyre::ensure!(
        !record.is_empty()
            && record.len() <= MAX_RESTORE_INSPECTION_BYTES
            && !record.iter().any(|byte| matches!(byte, b'\n' | b'\r')),
        "inspection request must be one bounded record"
    );
    let request: RestoreInspectionRequest = serde_json::from_slice(record)
        .map_err(|error| eyre::eyre!("parse inspection request: {error}"))?;
    validate_request(&request)?;
    let restore = &request.restore;
    // The objects are borrowed for fstat/pread only; ownership stays with the
    // inherited table, which ends with this process.
    let mut files = Vec::with_capacity(restore.objects.len());
    for object in &restore.objects {
        crate::restore::inputs::validate_inherited(&[object.fd], &[])?;
        // SAFETY: probed open; wrapped in ManuallyDrop so it is never closed here.
        let file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(object.fd) });
        let stat = nix::sys::stat::fstat(unsafe { BorrowedFd::borrow_raw(object.fd) })?;
        eyre::ensure!(
            stat.st_dev as u64 == object.file_device
                && stat.st_ino as u64 == object.file_inode
                && stat.st_size as u64 == object.length,
            "inspection object {:?} differs from its sealed identity",
            object.role
        );
        crate::startup::set_cloexec(object.fd, true)?;
        crate::restore::inputs::validate_object(&file, object)?;
        files.push(file);
    }
    let (layout, execution, devices) = match (&restore.authority, files.as_slice()) {
        (
            vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { .. },
            [_, layout, execution, devices, ram_map],
        ) => {
            crate::restore::inputs::verified_ram_map(restore, ram_map)?;
            (layout, execution, devices)
        }
        (
            vm_spec::restore::RestoreAuthority::OwnedLocalCut { .. }
            | vm_spec::restore::RestoreAuthority::Hibernation { .. },
            [_, layout, execution, devices],
        ) => (layout, execution, devices),
        _ => {
            return Err(eyre::eyre!(
                "inspection object set differs from its authority"
            ))
        }
    };
    let shape = crate::krun::restore::inspect(
        restore,
        request.network,
        crate::krun::restore::StateObjects {
            layout,
            execution,
            devices,
        },
        Instant::now() + INSPECTION_BUDGET,
    )?;
    for (file, object) in files.iter().zip(&restore.objects) {
        crate::restore::inputs::validate_object(file, object)?;
    }
    let selection = crate::capabilities::ResolvedSelection::from_start(None)?;
    eyre::ensure!(
        selection.backend_kind()? == crate::virt::BackendKind::Krun,
        "restore requires the krun backend"
    );
    let host = selection.host_report()?;
    let report = RestoreInspectionReport {
        version: RESTORE_INSPECTION_VERSION,
        request: match &restore.authority {
            vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { .. } => {
                vm_spec::restore::RestoreInspectionRequestBinding::Identified {
                    sha256: Sha256Digest::of_bytes(record),
                }
            }
            vm_spec::restore::RestoreAuthority::OwnedLocalCut { .. }
            | vm_spec::restore::RestoreAuthority::Hibernation { .. } => {
                vm_spec::restore::RestoreInspectionRequestBinding::OwnedLocalCut {
                    request: std::str::from_utf8(record)?.to_owned(),
                }
            }
        },
        authority: restore.authority.reference(),
        live_state_schema: libkrun::capabilities::LIVE_STATE_SCHEMA.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        lane: host.lane,
        cpu_count: u32::try_from(shape.cpu_count())?,
        ram_bytes: restore.configuration.ram_bytes(),
        devices: crate::krun::restore::admitted_devices(&shape),
    };
    if let Some(refusal) = report.portability_refusal(&request) {
        return Err(eyre::Report::new(refusal));
    }
    // Self-check with the shared rules: never emit a report Main would refuse.
    report
        .validate_against(record, &request)
        .map_err(|error| eyre::eyre!(error))?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use crate::restore::inspect::inspect;

    #[test]
    fn inspection_refuses_unframed_or_malformed_records_before_any_descriptor() {
        for encoded in [
            &b""[..],
            b"{}",
            b"{}\n{}\n",
            b"not json\n",
            b"{\"version\":1}\n",
        ] {
            assert!(inspect(encoded).is_err());
        }
    }

    #[test]
    fn inspection_schema_and_authority_validation_uses_the_real_shared_contract() {
        use crate::restore::inspect::{inspection_failure, validate_request};
        use vm_spec::restore::{RestoreInspectionRequest, RESTORE_INSPECTION_VERSION};
        let directory =
            std::env::temp_dir().join(format!("inspection-authorities-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let owned = crate::krun::worker::restore::tests::owned_launch(&directory);
        for restore in [
            crate::krun::worker::restore::tests::request(),
            owned.request.clone(),
        ] {
            let mut request = RestoreInspectionRequest {
                version: RESTORE_INSPECTION_VERSION,
                restore,
                network: false,
            };
            validate_request(&request).unwrap();
            request.version = RESTORE_INSPECTION_VERSION - 1;
            let mut bytes = serde_json::to_vec(&request).unwrap();
            bytes.push(b'\n');
            let error = inspect(&bytes).unwrap_err();
            let failure = inspection_failure(&error);
            failure.validate().unwrap();
            assert_eq!(failure.refusal.pin, "inspection-schema");
            assert_eq!(
                failure.refusal.expected,
                RESTORE_INSPECTION_VERSION.to_string()
            );
            assert_eq!(failure.refusal.actual, request.version.to_string());
            request.version = RESTORE_INSPECTION_VERSION;
            request.restore.configuration.rosetta = true;
            assert_eq!(
                validate_request(&request).unwrap_err().pin,
                "topology.devices"
            );
            request.restore.configuration.rosetta = false;
            request.restore.objects.pop();
            assert_eq!(
                validate_request(&request).unwrap_err().pin,
                "restore-authority"
            );
        }
        drop(owned);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn inspection_failure_keeps_native_reason_and_types_other_input_errors() {
        use crate::restore::inspect::inspection_failure;
        use vm_spec::restore::RestorePortabilityRefusal;
        let expected = RestorePortabilityRefusal::new(
            "cpu.profile",
            "captured CPU",
            "native profile mismatch",
        );
        let error = eyre::Report::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            expected.clone(),
        ));
        assert_eq!(inspection_failure(&error).refusal, expected);
        let error = eyre::eyre!("owned restore member fingerprint changed");
        let failure = inspection_failure(&error);
        failure.validate().unwrap();
        assert_eq!(failure.refusal.pin, "restore-inputs");
        assert!(failure.refusal.actual.contains("fingerprint changed"));
    }
}
