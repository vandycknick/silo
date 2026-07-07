use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::handoff::BootMode;
use crate::pid1::ProcessSupervisor;
use crate::provision::{command_exists, command_output};

const SYSTEMD_MARKER_DIR: &str = "/run/systemd/system";
const PID1_COMM: &str = "/proc/1/comm";
const PID1_EXE: &str = "/proc/1/exe";
const SYSTEMD_READY_TIMEOUT: Duration = Duration::from_secs(30);
const SYSTEMD_READY_POLL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug)]
pub(crate) struct ServiceManagerState {
    detection: ServiceManagerDetection,
    systemd_readiness: Arc<Mutex<Option<SystemdReadiness>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ServiceManagerDetection {
    SystemdCandidate { reason: String },
    Unknown { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SystemdReadiness {
    ready: bool,
    message: String,
}

impl ServiceManagerState {
    pub(crate) fn detect(boot_mode: &BootMode) -> Self {
        let marker_exists = Path::new(SYSTEMD_MARKER_DIR).is_dir();
        let pid1_comm = read_trimmed(PID1_COMM).ok();
        let pid1_exe = fs::read_link(PID1_EXE).ok();
        let handoff_init_path = match boot_mode {
            BootMode::InitChild { init_path, .. } => Some(init_path.as_path()),
            BootMode::Standard | BootMode::AgentPid1 { .. } => None,
        };
        let detection = classify_systemd_candidate(
            marker_exists,
            pid1_comm.as_deref(),
            pid1_exe.as_deref(),
            handoff_init_path,
        );

        tracing::debug!(detection = ?detection, "detected guest service manager");
        Self {
            detection,
            systemd_readiness: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn wait_for_systemd(
        &self,
        process_supervisor: &ProcessSupervisor,
    ) -> SystemdReadiness {
        if let Some(readiness) = self.cached_systemd_readiness() {
            return readiness;
        }

        let readiness = match &self.detection {
            ServiceManagerDetection::SystemdCandidate { reason } => {
                wait_for_systemd_ready(process_supervisor, reason)
            }
            ServiceManagerDetection::Unknown { reason } => SystemdReadiness::not_ready(format!(
                "systemd was not detected as PID 1 service manager: {reason}"
            )),
        };

        if readiness.is_ready() {
            match self.systemd_readiness.lock() {
                Ok(mut cached) => *cached = Some(readiness.clone()),
                Err(err) => *err.into_inner() = Some(readiness.clone()),
            }
        }
        readiness
    }

    fn cached_systemd_readiness(&self) -> Option<SystemdReadiness> {
        match self.systemd_readiness.lock() {
            Ok(cached) => cached.clone(),
            Err(err) => err.into_inner().clone(),
        }
    }
}

impl SystemdReadiness {
    pub(crate) fn is_ready(&self) -> bool {
        self.ready
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    fn ready(message: impl Into<String>) -> Self {
        Self {
            ready: true,
            message: message.into(),
        }
    }

    fn not_ready(message: impl Into<String>) -> Self {
        Self {
            ready: false,
            message: message.into(),
        }
    }
}

fn wait_for_systemd_ready(
    process_supervisor: &ProcessSupervisor,
    detection_reason: &str,
) -> SystemdReadiness {
    if !command_exists("systemctl") {
        return SystemdReadiness::not_ready(
            "systemd candidate detected, but systemctl is not available",
        );
    }

    let started = Instant::now();
    let mut last_message = format!("systemd candidate detected: {detection_reason}");

    loop {
        if !Path::new(SYSTEMD_MARKER_DIR).is_dir() {
            last_message = format!("waiting for {SYSTEMD_MARKER_DIR} to exist");
        } else {
            match command_output(
                process_supervisor,
                "systemctl",
                ["show", "--property=SystemState", "--value"],
            ) {
                Ok(output) => {
                    let state = output.trim();
                    if systemd_state_ready(state) {
                        return SystemdReadiness::ready(format!(
                            "systemd manager ready with state {state}"
                        ));
                    }
                    last_message = if state.is_empty() {
                        String::from("systemctl returned an empty SystemState")
                    } else {
                        format!("systemd manager state is {state}")
                    };
                }
                Err(err) => {
                    last_message = format!("systemctl show SystemState failed: {err}");
                }
            }
        }

        if started.elapsed() >= SYSTEMD_READY_TIMEOUT {
            return SystemdReadiness::not_ready(format!(
                "systemd manager did not become ready within {:?}; last check: {last_message}",
                SYSTEMD_READY_TIMEOUT
            ));
        }

        thread::sleep(SYSTEMD_READY_POLL);
    }
}

fn classify_systemd_candidate(
    marker_exists: bool,
    pid1_comm: Option<&str>,
    pid1_exe: Option<&Path>,
    handoff_init_path: Option<&Path>,
) -> ServiceManagerDetection {
    if marker_exists && pid1_contradicts_systemd(pid1_comm, pid1_exe) {
        return ServiceManagerDetection::Unknown {
            reason: format!(
                "{SYSTEMD_MARKER_DIR} exists, but PID 1 identity is not systemd ({})",
                pid1_identity(pid1_comm, pid1_exe)
            ),
        };
    }

    if marker_exists {
        return ServiceManagerDetection::SystemdCandidate {
            reason: format!("{SYSTEMD_MARKER_DIR} exists"),
        };
    }
    if pid1_looks_like_systemd(pid1_comm, pid1_exe) {
        return ServiceManagerDetection::SystemdCandidate {
            reason: format!(
                "PID 1 identity is systemd ({})",
                pid1_identity(pid1_comm, pid1_exe)
            ),
        };
    }
    if handoff_init_path.is_some_and(handoff_path_looks_like_systemd) {
        return ServiceManagerDetection::SystemdCandidate {
            reason: String::from("handoff init path is systemd"),
        };
    }

    ServiceManagerDetection::Unknown {
        reason: format!(
            "PID 1 identity is {}; handoff init path is {}",
            pid1_identity(pid1_comm, pid1_exe),
            handoff_init_path
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| String::from("<none>"))
        ),
    }
}

fn pid1_contradicts_systemd(pid1_comm: Option<&str>, pid1_exe: Option<&Path>) -> bool {
    if pid1_comm.is_none() && pid1_exe.is_none() {
        return false;
    }
    !pid1_looks_like_systemd(pid1_comm, pid1_exe)
}

fn pid1_looks_like_systemd(pid1_comm: Option<&str>, pid1_exe: Option<&Path>) -> bool {
    pid1_comm == Some("systemd") || pid1_exe.is_some_and(path_looks_like_systemd)
}

fn path_looks_like_systemd(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "systemd")
        || path
            .to_str()
            .is_some_and(|value| value.ends_with("/systemd/systemd"))
}

fn handoff_path_looks_like_systemd(path: &Path) -> bool {
    path_looks_like_systemd(path)
        || fs::canonicalize(path)
            .ok()
            .as_deref()
            .is_some_and(path_looks_like_systemd)
}

fn systemd_state_ready(state: &str) -> bool {
    matches!(state.trim(), "running" | "degraded")
}

fn pid1_identity(pid1_comm: Option<&str>, pid1_exe: Option<&Path>) -> String {
    format!(
        "comm={}, exe={}",
        pid1_comm.unwrap_or("<unknown>"),
        pid1_exe
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| String::from("<unknown>"))
    )
}

fn read_trimmed(path: &str) -> std::io::Result<String> {
    fs::read_to_string(path).map(|value| value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::provision::service_manager::{
        classify_systemd_candidate, systemd_state_ready, ServiceManagerDetection,
    };

    #[test]
    fn systemd_state_running_and_degraded_are_ready() {
        assert!(systemd_state_ready("running"));
        assert!(systemd_state_ready("degraded"));
        assert!(systemd_state_ready(" degraded\n"));
        assert!(!systemd_state_ready("starting"));
        assert!(!systemd_state_ready("initializing"));
        assert!(!systemd_state_ready(""));
    }

    #[test]
    fn marker_with_systemd_identity_detects_systemd() {
        let detection = classify_systemd_candidate(
            true,
            Some("systemd"),
            Some(Path::new("/usr/lib/systemd/systemd")),
            None,
        );

        assert!(matches!(
            detection,
            ServiceManagerDetection::SystemdCandidate { .. }
        ));
    }

    #[test]
    fn marker_with_contradictory_pid1_is_unknown() {
        let detection = classify_systemd_candidate(
            true,
            Some("busybox"),
            Some(Path::new("/bin/busybox")),
            None,
        );

        assert!(matches!(detection, ServiceManagerDetection::Unknown { .. }));
    }

    #[test]
    fn handoff_systemd_path_detects_systemd_candidate_before_marker_exists() {
        let detection = classify_systemd_candidate(
            false,
            Some("init"),
            Some(Path::new("/sbin/init")),
            Some(Path::new("/usr/lib/systemd/systemd")),
        );

        assert!(matches!(
            detection,
            ServiceManagerDetection::SystemdCandidate { .. }
        ));
    }
}
