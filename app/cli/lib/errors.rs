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

    eprintln!("{} {head}", crate::ui::error_label());

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

fn live_refusal(value: &vm_spec::live::LiveOperationUnsupported) -> String {
    let alternative = if value.backend == vm_spec::live::LiveBackend::Vz {
        "use silo stop, then an ordinary stopped-storage snapshot (not an execution checkpoint)"
    } else {
        "use ordinary boot or a stopped-storage workflow; no live fallback is performed"
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
    fn vz_refusal_is_one_line_and_names_only_existing_command() {
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
        assert!(line.contains("silo stop"));
        assert!(line.contains("stopped-storage snapshot"));
        assert!(!line.contains("silo snapshot"));
    }

    #[test]
    fn capture_alias_conflict_names_retained_checkpoint_and_uses_failure_exit() {
        let checkpoint: libvm::SnapshotId = format!("sha256:{}", "c".repeat(64)).parse().unwrap();
        let error: eyre::Report = libvm::LibVmError::CaptureAliasConflict {
            alias: "web-cp".into(),
            checkpoint,
        }
        .into();
        let rendered = error.to_string();
        assert!(rendered.contains("web-cp"));
        assert!(rendered.contains(&checkpoint.to_string()));
        assert!(rendered.contains("retained without the requested alias"));
        assert_eq!(rendered.lines().count(), 1);
        // The CLI's normal error path defaults to failure, not a guest exit.
        assert_eq!(execution_exit_code(&error), None);
        assert_eq!(
            crate::errors::exit_code(&error),
            std::process::ExitCode::FAILURE
        );
    }
}
