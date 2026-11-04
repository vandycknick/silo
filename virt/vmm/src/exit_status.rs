use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use eyre::Context;
use serde::Serialize;

use crate::virt::exit::{Diagnostic, ForceReason, ProcessExit, StartupStage};
use crate::virt::{BackendKind, VmExit};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExitStatus {
    machine_id: String,
    run_id: String,
    pid: i32,
    exited_at: i64,
    outcome: ExitOutcome,
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<BackendExit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_shutdown: Option<protocol::shutdown::StorageShutdown>,
}

/// Backend detail of the terminal outcome. libvm stores it without
/// interpreting it; fields are added, never repurposed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendExit {
    kind: &'static str,
    stage: StartupStage,
    force_reason: Option<ForceReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<ProcessExit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<Diagnostic>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExitOutcome {
    Clean,
    Error,
    Forced,
}

impl ExitStatus {
    pub(crate) fn new(
        machine_id: String,
        run_id: String,
        outcome: ExitOutcome,
        error: Option<String>,
    ) -> eyre::Result<Self> {
        let pid = i32::try_from(std::process::id()).context("convert silo-vmm pid")?;
        Ok(Self {
            machine_id,
            run_id,
            pid,
            exited_at: current_unix(),
            outcome,
            error,
            backend: None,
            storage_shutdown: None,
        })
    }

    pub(crate) fn with_vm_exit(mut self, kind: BackendKind, exit: VmExit) -> Self {
        self.error = self.error.or_else(|| exit.error());
        self.outcome = if self.error.is_some() {
            ExitOutcome::Error
        } else if exit.forced() {
            ExitOutcome::Forced
        } else {
            ExitOutcome::Clean
        };
        self.backend = Some(BackendExit {
            kind: kind.name(),
            stage: exit.stage,
            force_reason: exit.force_reason,
            process: exit.process,
            diagnostic: exit.diagnostic,
        });
        self
    }

    pub(crate) fn with_storage_shutdown(
        mut self,
        evidence: protocol::shutdown::StorageShutdown,
    ) -> eyre::Result<Self> {
        evidence.validate().map_err(eyre::Report::msg)?;
        self.storage_shutdown = Some(evidence);
        Ok(self)
    }
}

pub(crate) fn write(path: &Path, status: &ExitStatus) -> eyre::Result<()> {
    let payload = serde_json::to_vec_pretty(status).context("serialize exit status")?;
    crate::durable_file::write(path, &payload)
}

fn current_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use serde_json::Value;

    use crate::durable_file::temporary_name;
    use crate::exit_status::{write, ExitOutcome, ExitStatus};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("silo-vmm-exit-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).expect("create temporary directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure temporary directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn status(run_id: &str) -> ExitStatus {
        ExitStatus::new(
            "machine-1".to_string(),
            run_id.to_string(),
            ExitOutcome::Clean,
            None,
        )
        .expect("build exit status")
    }

    #[test]
    fn backend_force_is_not_a_crash_and_does_not_replace_startup_failure() {
        use crate::virt::exit::{
            Diagnostic, ForceReason, ProcessExit, StartupStage, VmExit, VmOutcome,
        };
        use crate::virt::BackendKind;
        let exit = VmExit {
            outcome: VmOutcome::Forced,
            stage: StartupStage::Build,
            force_reason: Some(ForceReason::StartupFailure),
            process: Some(ProcessExit {
                pid: 123,
                raw_status: 9,
                code: None,
                signal: Some(9),
                core_dumped: false,
            }),
            diagnostic: Some(Diagnostic {
                tail: "diagnostic".to_string(),
                truncated: false,
            }),
        };
        for error in [None, Some("admission failed".to_string())] {
            let record = ExitStatus::new(
                "machine".to_string(),
                "run".to_string(),
                ExitOutcome::Clean,
                error.clone(),
            )
            .expect("record")
            .with_vm_exit(BackendKind::Krun, exit.clone());
            let value = serde_json::to_value(record).expect("encode record");
            assert_eq!(value["pid"], std::process::id());
            assert_eq!(value["backend"]["kind"], "krun");
            assert_eq!(value["backend"]["stage"], "build");
            assert_eq!(value["backend"]["forceReason"], "startup_failure");
            assert_eq!(value["backend"]["process"]["pid"], 123);
            assert_eq!(value["backend"]["process"]["rawStatus"], 9);
            assert_eq!(value["backend"]["diagnostic"]["tail"], "diagnostic");
            if error.is_none() {
                assert_eq!(value["outcome"], "forced");
            } else {
                assert_eq!(value["error"], "admission failed");
                assert_eq!(value["outcome"], "error");
            }
        }
    }

    #[test]
    fn backend_without_process_omits_process_and_diagnostic() {
        use crate::virt::exit::{StartupStage, VmExit};
        use crate::virt::BackendKind;
        let record =
            status("run").with_vm_exit(BackendKind::Vz, VmExit::stopped(StartupStage::Started));
        let value = serde_json::to_value(record).expect("encode record");
        assert_eq!(value["outcome"], "clean");
        assert_eq!(value["backend"]["kind"], "vz");
        assert_eq!(value["backend"]["stage"], "started");
        assert!(value["backend"]["forceReason"].is_null());
        assert!(value["backend"].get("process").is_none());
        assert!(value["backend"].get("diagnostic").is_none());
    }

    #[test]
    fn record_without_machine_has_no_backend_block() {
        let value = serde_json::to_value(status("run")).expect("encode record");
        assert!(value.get("backend").is_none());
    }

    #[test]
    fn atomic_exit_record_is_private_complete_and_replaces_prior_record() {
        let dir = TempDir::new();
        let path = dir.path().join("vm.exit.json");
        write(&path, &status("run-1")).expect("write initial exit record");
        write(&path, &status("run-2")).expect("replace exit record");

        let value: Value = serde_json::from_slice(&fs::read(&path).expect("read exit record"))
            .expect("parse exit record");
        assert_eq!(value["machineId"], "machine-1");
        assert_eq!(value["runId"], "run-2");
        assert!(value.get("error").is_some());
        assert_eq!(
            fs::metadata(&path)
                .expect("exit record metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(dir.path())
                .expect("read temporary directory")
                .count(),
            1
        );
    }

    #[test]
    fn exit_record_temp_names_are_unique_and_failed_replacement_preserves_prior_object() {
        let dir = TempDir::new();
        let path = dir.path().join("vm.exit.json");
        let first = temporary_name(path.file_name().expect("exit filename"));
        let second = temporary_name(path.file_name().expect("exit filename"));
        assert_ne!(first, second);

        fs::create_dir(&path).expect("create invalid prior exit record");
        assert!(write(&path, &status("run-2")).is_err());
        assert!(path.is_dir());
        assert_eq!(
            fs::read_dir(dir.path())
                .expect("read temporary directory")
                .count(),
            1
        );
    }

    #[test]
    fn independent_storage_facts_survive_forced_and_error_outcomes() {
        use crate::virt::exit::{ForceReason, StartupStage, VmExit, VmOutcome};
        use crate::virt::BackendKind;
        use protocol::shutdown::{StorageShutdown, VERSION};

        for bits in 0..8 {
            let evidence = StorageShutdown {
                version: VERSION,
                guest_protocol_completed: bits & 1 != 0,
                host_flush_completed: bits & 2 != 0,
                attachments_closed: bits & 4 != 0,
            };
            for error in [None, Some("first host failure".to_string())] {
                let record = ExitStatus::new(
                    "machine".into(),
                    "run".into(),
                    ExitOutcome::Clean,
                    error.clone(),
                )
                .unwrap()
                .with_storage_shutdown(evidence)
                .unwrap()
                .with_vm_exit(
                    BackendKind::Krun,
                    VmExit {
                        outcome: VmOutcome::Forced,
                        force_reason: Some(ForceReason::Stop),
                        ..VmExit::stopped(StartupStage::Started)
                    },
                );
                let value = serde_json::to_value(record).unwrap();
                assert_eq!(
                    value["storageShutdown"]["guestProtocolCompleted"],
                    bits & 1 != 0
                );
                assert_eq!(
                    value["storageShutdown"]["hostFlushCompleted"],
                    bits & 2 != 0
                );
                assert_eq!(value["storageShutdown"]["attachmentsClosed"], bits & 4 != 0);
                assert_eq!(
                    value["outcome"],
                    if error.is_some() { "error" } else { "forced" }
                );
            }
        }
    }

    #[test]
    fn unsupported_storage_evidence_version_is_not_published() {
        let evidence = protocol::shutdown::StorageShutdown {
            version: protocol::shutdown::VERSION + 1,
            guest_protocol_completed: true,
            host_flush_completed: true,
            attachments_closed: true,
        };
        assert!(status("run").with_storage_shutdown(evidence).is_err());
    }
}
