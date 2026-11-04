//! The single terminal path of a monitor generation.
//!
//! Every controlled exit, whether startup failed, a signal arrived, the guest
//! exited or the stop was forced, ends here exactly once:
//!
//! ```text
//! stop the primary VM if the generation failed while it was live
//!   -> await checked host attachment finalization
//!   -> freeze independently observed storage facts
//!   -> write vm.exit.json (primary error first, cleanup errors appended)
//!   -> release the generation lease after publication
//!   -> report failure on the syncpipe
//!   -> remove the pidfile
//!   -> trigger the exit runner
//! ```

use std::path::Path;

use crate::exec_log::ExecLogWriter;
use crate::exit_command::ExitRunner;
use crate::exit_status::{ExitOutcome, ExitStatus};
use crate::lock::pid::PidGuard;
use crate::startup::{PrimaryMachine, SyncReporter};

pub(crate) struct Finalization<'a> {
    pub(crate) machine_id: &'a str,
    pub(crate) run_id: &'a str,
    pub(crate) data_dir: &'a Path,
    pub(crate) exit_status: &'a Path,
    pub(crate) primary_machine: &'a PrimaryMachine,
    pub(crate) exec_log: Option<&'a ExecLogWriter>,
    pub(crate) sync_reporter: &'a mut SyncReporter,
    pub(crate) pid_guard: PidGuard,
    pub(crate) exit_runner: Option<ExitRunner>,
}

impl Finalization<'_> {
    pub(crate) async fn run(self, result: eyre::Result<()>) -> eyre::Result<()> {
        let machine = self.primary_machine.get();
        let mut result = match (result, &machine) {
            (Err(error), Some(machine)) => match machine.stop().await {
                Ok(()) => Err(error),
                Err(stop) => Err(eyre::eyre!(
                    "{}; primary VM finalization failed: {stop}",
                    format_error_chain(&error)
                )),
            },
            (result, _) => result,
        };

        let guest_completed = match self.primary_machine.shutdown_state() {
            Ok(Some(state)) => match state.guest_protocol_completed() {
                Ok(completed) => {
                    match state.guest_failure() {
                        Ok(Some(error)) => {
                            result = append_error(
                                result,
                                format!("guest storage shutdown failed: {error}"),
                            )
                        }
                        Ok(None) => {}
                        Err(error) => result = append_error(result, error),
                    }
                    completed
                }
                Err(error) => {
                    result = append_error(result, error);
                    false
                }
            },
            Ok(None) => false,
            Err(error) => {
                result = append_error(result, format_error_chain(&error));
                false
            }
        };
        // The backend's finalizer owns actual retained handles and its lease
        // through blocking syscall completion, even if an async waiter dies.
        // Only an explicit report can supply either independent host fact.
        let (storage_shutdown, publishable) = match &machine {
            Some(machine) => match machine.finalize_storage(guest_completed).await {
                Ok(report) => {
                    if let Some(error) = report.error {
                        result = append_error(result, error);
                    }
                    (
                        Some(protocol::shutdown::StorageShutdown {
                            version: protocol::shutdown::VERSION,
                            guest_protocol_completed: guest_completed,
                            host_flush_completed: report.host_writes_flushed,
                            attachments_closed: report.attachments_closed,
                        }),
                        true,
                    )
                }
                Err(error) => {
                    result = append_error(
                        result,
                        format!("host storage finalization did not complete: {error}"),
                    );
                    (None, false)
                }
            },
            None => (None, true),
        };

        let backend_exit = match &machine {
            Some(machine) => match machine.try_wait().await {
                Ok(exit) => exit.map(|exit| (machine.backend_kind(), exit)),
                Err(error) => {
                    result = append_error(result, format!("inspect final backend status: {error}"));
                    None
                }
            },
            None => None,
        };
        let last_error = result.as_ref().err().map(format_error_chain);
        if let Some(exec_log) = self.exec_log {
            exec_log.generation(self.machine_id, self.run_id, "stopped");
        }
        if let Some(full_error) = &last_error {
            tracing::error!(error = %full_error, data_dir = %self.data_dir.display(), "silo-vmm exiting with error");
        }

        let outcome = if last_error.is_some() {
            ExitOutcome::Error
        } else {
            ExitOutcome::Clean
        };
        match ExitStatus::new(
            self.machine_id.to_string(),
            self.run_id.to_string(),
            outcome,
            last_error.clone(),
        )
        .and_then(|status| match storage_shutdown {
            Some(evidence) => status.with_storage_shutdown(evidence),
            None => Ok(status),
        }) {
            Ok(status) => {
                let status = match backend_exit {
                    Some((kind, exit)) => status.with_vm_exit(kind, exit),
                    None => status,
                };
                if publishable {
                    if let Err(error) = crate::exit_status::write(self.exit_status, &status) {
                        tracing::error!(%error, path = %self.exit_status.display(), "write runtime exit status");
                        result =
                            append_error(result, format!("publish runtime exit status: {error}"));
                    }
                }
            }
            Err(error) => {
                tracing::error!(%error, "build runtime exit status");
                result = append_error(result, format!("build runtime exit status: {error}"));
            }
        }
        if let Some(full_error) = result.as_ref().err().map(format_error_chain) {
            let _ = self.sync_reporter.report_failed(&full_error);
        }

        drop(self.pid_guard);
        if let Some(exit_runner) = self.exit_runner {
            exit_runner.trigger();
        }

        result
    }
}

fn append_error(result: eyre::Result<()>, error: impl std::fmt::Display) -> eyre::Result<()> {
    match result {
        Ok(()) => Err(eyre::eyre!("{error}")),
        Err(primary) => Err(eyre::eyre!("{}; {error}", format_error_chain(&primary))),
    }
}

pub(crate) fn format_error_chain(err: &eyre::Report) -> String {
    let mut parts = Vec::new();
    for cause in err.chain() {
        parts.push(cause.to_string());
    }
    parts.join(": ")
}
