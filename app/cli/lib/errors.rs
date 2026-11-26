use eyre::Report;

#[derive(Debug)]
pub(crate) struct ExecutionExit {
    code: i32,
}

impl ExecutionExit {
    pub(crate) fn new(code: i32) -> Self {
        Self { code }
    }
}

impl std::fmt::Display for ExecutionExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "execution exited with status {}", self.code)
    }
}

impl std::error::Error for ExecutionExit {}

pub(crate) fn execution_exit_code(error: &Report) -> Option<i32> {
    error.downcast_ref::<ExecutionExit>().map(|exit| exit.code)
}

pub(crate) fn exit_code(error: &Report) -> std::process::ExitCode {
    execution_exit_code(error)
        .and_then(|code| u8::try_from(code).ok())
        .map(std::process::ExitCode::from)
        .unwrap_or(std::process::ExitCode::FAILURE)
}

pub fn print(error: &Report, verbose: u8) {
    if let Some(libvm::LibVmError::LiveOperationUnsupported {
        operation,
        backend,
        lane,
        reason,
    }) = error.downcast_ref::<libvm::LibVmError>()
    {
        let refusal = vm_spec::live::LiveOperationUnsupported {
            operation: *operation,
            backend: *backend,
            lane: *lane,
            reason: reason.clone(),
        };
        eprintln!("{} {}", crate::ui::error_label(), live_refusal(&refusal));
        return;
    }
    // The exit-code wrapper is always outermost; eyre reports its context
    // wrapper in the chain, so `is::<ExecutionExit>` on the cause never matches.
    let causes = error
        .chain()
        .skip(usize::from(execution_exit_code(error).is_some()))
        .collect::<Vec<_>>();
    let Some(head) = causes.first() else {
        eprintln!("error: {error}");
        return;
    };

    match head.downcast_ref::<libvm::LibVmError>() {
        Some(error) => eprintln!("{} {}", crate::ui::error_label(), native_message(error)),
        None => eprintln!("{} {head}", crate::ui::error_label()),
    }

    if verbose == 0 {
        if causes.len() > 1 {
            eprintln!("\nhint: rerun with -v for more detail");
        }
        return;
    }

    for (index, cause) in causes.into_iter().skip(1).enumerate() {
        eprintln!("  {}: {cause}", index + 1);
    }
}

pub(crate) fn native_message(error: &libvm::LibVmError) -> String {
    match error {
        libvm::LibVmError::HibernateOutOfSpace {
            reference,
            needed_bytes,
            free_bytes,
        } => format!(
            "not enough disk space to hibernate `{reference}`: {} needed, {} free",
            crate::ui::human_bytes(Some(*needed_bytes)),
            crate::ui::human_bytes(Some(*free_bytes)),
        ),
        libvm::LibVmError::MachineNotRunning { reference } => {
            format!("machine `{reference}` is not running; start it with `silo start {reference}`")
        }
        libvm::LibVmError::MachineNotPaused { reference } => {
            format!("machine `{reference}` is not paused")
        }
        _ => error.to_string(),
    }
}

fn live_refusal(value: &vm_spec::live::LiveOperationUnsupported) -> String {
    let alternative = if value.backend == vm_spec::live::LiveBackend::Vz {
        "snapshots, forks and live operations need the krun backend"
    } else {
        "use silo stop, then a snapshot without memory"
    };
    format!("{value}; {alternative}")
}

#[cfg(test)]
mod tests {
    use crate::errors::{execution_exit_code, ExecutionExit};

    #[test]
    fn execution_exit_code_survives_context() {
        let error = eyre::eyre!("guest stream failed").wrap_err(ExecutionExit::new(125));

        assert_eq!(execution_exit_code(&error), Some(125));
    }

    #[test]
    fn vz_refusal_names_the_required_backend() {
        let value = vm_spec::live::LiveOperationUnsupported {
            operation: vm_spec::live::LiveOperation::Pause,
            backend: vm_spec::live::LiveBackend::Vz,
            lane: vm_spec::live::LiveLane::NotApplicable,
            reason: vm_spec::live::LiveUnsupportedReason::new(
                vm_spec::live::LiveReasonCode::BackendExcluded,
            ),
        };
        let line = crate::errors::live_refusal(&value);
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains("backend-excluded (backend=vz, lane=not-applicable)"));
        assert!(line.ends_with("; snapshots, forks and live operations need the krun backend"));
        assert!(!line.contains("silo stop"));
        assert!(!line.contains("checkpoint"));
    }

    #[test]
    fn non_vz_refusal_suggests_a_stopped_snapshot() {
        use vm_spec::live::{LiveBackend, LiveLane, LiveOperation, LiveOperationUnsupported};
        use vm_spec::live::{LiveReasonCode, LiveUnsupportedReason};

        for (backend, lane) in [
            (LiveBackend::Krun, LiveLane::HvfArm64),
            (LiveBackend::Mock, LiveLane::NotApplicable),
        ] {
            let line = crate::errors::live_refusal(&LiveOperationUnsupported {
                operation: LiveOperation::Pause,
                backend,
                lane,
                reason: LiveUnsupportedReason::new(LiveReasonCode::BuildExcluded),
            });
            assert!(line.ends_with("; use silo stop, then a snapshot without memory"));
        }
    }

    #[test]
    fn resume_on_running_machine_names_the_missing_pause() {
        let error = libvm::LibVmError::MachineNotPaused {
            reference: "dev".into(),
        };
        assert_eq!(
            crate::errors::native_message(&error),
            "machine `dev` is not paused"
        );
    }

    #[test]
    fn capture_name_conflict_names_kept_snapshot_and_uses_failure_exit() {
        let snapshot: libvm::SnapshotId = format!("sha256:{}", "c".repeat(64)).parse().unwrap();
        let error: eyre::Report = libvm::LibVmError::CaptureNameConflict {
            name: "web-cp".into(),
            snapshot,
        }
        .into();
        let rendered = error.to_string();
        assert!(rendered.contains("web-cp"));
        assert!(rendered.contains(&snapshot.to_string()));
        assert!(rendered.contains("kept without the requested name"));
        assert_eq!(rendered.lines().count(), 1);
        // The CLI's normal error path defaults to failure, not a guest exit.
        assert_eq!(execution_exit_code(&error), None);
        assert_eq!(
            crate::errors::exit_code(&error),
            std::process::ExitCode::FAILURE
        );
    }
    #[test]
    fn hibernation_diagnostics_match_the_user_contract() {
        use libvm::LibVmError as E;
        let reference = || "dev".to_string();
        for (error, expected) in [
            (E::HibernatedStartFirst { reference: reference() }, "machine `dev` is hibernated; start it with `silo start dev` first"),
            (E::HibernatedStopFirst { reference: reference() }, "machine `dev` is hibernated; run `silo stop dev` first"),
            (E::AlreadyHibernated { reference: reference() }, "machine `dev` is already hibernated; wake it with `silo start dev`"),
            (E::HibernateTemporary { reference: reference() }, "machine `dev` is a temporary `silo run` machine and cannot be hibernated"),
            (E::HibernateBusy { reference: reference() }, "machine `dev` is busy with another lifecycle operation; try again when it finishes"),
            (E::HibernateFailed { reference: reference(), message: "disk write failed".into() }, "could not hibernate `dev`: disk write failed"),
            (E::WakeFailedBeforeConsume { reference: reference(), source: Box::new(E::InvalidRequest { message: "construction failed".into() }) }, "could not wake `dev`; its saved state was kept; retry `silo start dev`"),
            (E::WakeConsumed { reference: reference(), source: None }, "could not wake `dev`; its saved state is gone and the machine is stopped; run `silo start dev` to boot it"),
            (E::MachineNotRunning { reference: reference() }, "machine `dev` is not running; start it with `silo start dev`"),
        ] {
            assert_eq!(crate::errors::native_message(&error), expected);
        }
        let space = E::HibernateOutOfSpace {
            reference: reference(),
            needed_bytes: 2 << 30,
            free_bytes: 1 << 30,
        };
        assert_eq!(
            crate::errors::native_message(&space),
            format!(
                "not enough disk space to hibernate `dev`: {} needed, {} free",
                crate::ui::human_bytes(Some(2 << 30)),
                crate::ui::human_bytes(Some(1 << 30)),
            )
        );
        use libvm::storage::hibernate_file::HibernateUnusableReason as R;
        for (reason, text) in [
            (R::FilesMissing, "files are missing"),
            (R::FilesChanged, "files were changed"),
            (R::DisksChanged, "disks were changed"),
            (R::NotCompatible, "not compatible with this system"),
        ] {
            assert_eq!(crate::errors::native_message(&E::HibernateUnusable { reference: reference(), reason }),
                format!("cannot wake `dev`: its saved state cannot be used ({text}); run `silo stop dev` to discard it, then `silo start dev`"));
            assert_eq!(libvm::MachineStopWarning::SavedStateUnusable { reason }.to_string(),
                format!("the guest could not be shut down cleanly because its saved state cannot be used ({text}); the saved state was discarded"));
        }
        assert_eq!(
            libvm::MachineStopWarning::WakeFailed.to_string(),
            "the guest could not be shut down cleanly because wake failed; the machine is stopped"
        );
    }
}
