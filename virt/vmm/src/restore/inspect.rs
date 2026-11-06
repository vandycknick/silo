//! `silo-vmm inspect-restore`: descriptor-only native compatibility admission
//! before the manager allocates any child resource. stdin carries exactly one
//! newline-terminated `RestoreInspectionRequest`; the four state objects are
//! inherited at their request numbers. stdout carries exactly one report line;
//! any refusal exits nonzero with a bounded diagnostic and empty stdout. No
//! child VM is created: native may probe an empty host-profile VM only.

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
        let report = inspect(&encoded)?;
        let mut line = serde_json::to_vec(&report)?;
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
    request.validate().map_err(|error| eyre::eyre!(error))?;
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
        files.push(file);
    }
    let [_, layout, execution, devices] = files.as_slice() else {
        return Err(eyre::eyre!("inspection requires exactly four objects"));
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
    let selection = crate::capabilities::ResolvedSelection::from_start(None)?;
    eyre::ensure!(
        selection.backend_kind()? == crate::virt::BackendKind::Krun,
        "restore requires the krun backend"
    );
    let host = selection.host_report()?;
    let native_producer = libkrun::capabilities::compiled_live_build()
        .execution_producer()
        .map_err(|error| eyre::eyre!("native producer unavailable: {error}"))?;
    let report = RestoreInspectionReport {
        version: RESTORE_INSPECTION_VERSION,
        request: Sha256Digest::of_bytes(record),
        checkpoint: restore.checkpoint,
        native_producer,
        silo_producer: Sha256Digest::from_bytes(crate::capabilities::capture_producer()?),
        lane: host.lane,
        cpu_count: u32::try_from(shape.cpu_count())?,
        ram_bytes: restore.configuration.ram_bytes(),
        devices: crate::krun::restore::admitted_devices(&shape),
    };
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
}
