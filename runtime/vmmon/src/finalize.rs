//! The single terminal path of a monitor generation.
//!
//! Every controlled exit, whether startup failed, a signal arrived, the guest
//! exited or the stop was forced, ends here exactly once:
//!
//! ```text
//! stop the primary VM if the generation failed while it was live
//!   -> read the cached backend exit
//!   -> write vm.exit.json (primary error first, cleanup errors appended)
//!   -> report failure on the syncpipe
//!   -> remove the pidfile
//!   -> trigger the exit command
//! ```

use std::path::Path;

use crate::exec_log::ExecLogWriter;
use crate::exit_command::ExitCommand;
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
    pub(crate) exit_command: Option<&'a ExitCommand>,
}

impl Finalization<'_> {
    pub(crate) async fn run(self, result: eyre::Result<()>) -> eyre::Result<()> {
        let machine = self.primary_machine.get();
        let result = match (result, &machine) {
            (Err(error), Some(machine)) => match machine.stop().await {
                Ok(()) => Err(error),
                Err(stop) => Err(eyre::eyre!(
                    "{}; primary VM finalization failed: {stop}",
                    format_error_chain(&error)
                )),
            },
            (result, _) => result,
        };

        let last_error = result.as_ref().err().map(format_error_chain);
        if let Some(exec_log) = self.exec_log {
            exec_log.generation(self.machine_id, self.run_id, "stopped");
        }
        if let Some(full_error) = &last_error {
            tracing::error!(error = %full_error, data_dir = %self.data_dir.display(), "vmmon exiting with error");
        }

        let outcome = if last_error.is_some() {
            ExitOutcome::Error
        } else {
            ExitOutcome::Clean
        };
        let backend_exit = match &machine {
            Some(machine) => match machine.try_wait().await {
                Ok(exit) => exit.map(|exit| (machine.backend_kind(), exit)),
                Err(error) => {
                    tracing::warn!(%error, "could not inspect final backend status");
                    None
                }
            },
            None => None,
        };
        match ExitStatus::new(
            self.machine_id.to_string(),
            self.run_id.to_string(),
            outcome,
            last_error.clone(),
        ) {
            Ok(status) => {
                let status = match backend_exit {
                    Some((kind, exit)) => status.with_vm_exit(kind, exit),
                    None => status,
                };
                if let Err(err) = crate::exit_status::write(self.exit_status, &status) {
                    tracing::warn!(error = %err, path = %self.exit_status.display(), "write runtime exit status");
                }
            }
            Err(err) => tracing::warn!(error = %err, "build runtime exit status"),
        }
        if let Some(full_error) = &last_error {
            let _ = self.sync_reporter.report_failed(full_error);
        }

        drop(self.pid_guard);
        if let Some(exit_command) = self.exit_command {
            exit_command.spawn(self.machine_id, self.run_id);
        }

        result
    }
}

pub(crate) fn format_error_chain(err: &eyre::Report) -> String {
    let mut parts = Vec::new();
    for cause in err.chain() {
        parts.push(cause.to_string());
    }
    parts.join(": ")
}
