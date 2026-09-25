//! `status.json`: live silod state, republished atomically on every change.
//!
//! Unlike silod's installation record this is not strict: a newer or older silod
//! may have written it, and a field a reader does not know must not stop `status`,
//! `up`, or `down` from working. New fields must default.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonPhase {
    PreparingStorage,
    Creating,
    StartingVm,
    WaitingGuest,
    ActivatingEngine,
    Retrying,
    Ready,
    Degraded,
    /// Replacing the system VM with a newer image; Docker is briefly unavailable.
    Upgrading,
    Failed,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub schema: u32,
    pub generation: Uuid,
    pub pid: u32,
    /// [`crate::process::start_time`] of `pid` on Linux; opaque elsewhere.
    #[serde(default)]
    pub process_start: String,
    pub phase: DaemonPhase,
    pub machine_id: Option<String>,
    pub run_id: Option<String>,
    pub image_digest: Option<String>,
    /// The image reference silod follows.
    #[serde(default)]
    pub configured_image: Option<String>,
    /// Configured guest memory ceiling.
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    /// Backend reported by the running silo-vmm instance.
    #[serde(default)]
    pub actual_backend: Option<String>,
    pub docker_socket: String,
    pub updated_at: String,
    pub last_error: Option<String>,
    pub restart_count: u32,
    /// When silod last asked the registry for a newer system image (RFC 3339).
    #[serde(default)]
    pub update_checked_at: Option<String>,
    /// Why the last image update check or upgrade failed, if it did.
    #[serde(default)]
    pub update_error: Option<String>,
    /// How the agent's last guest cache-reclaim run ended.
    #[serde(default)]
    pub memory_reclaim_outcome: Option<MemoryReclaimOutcome>,
    /// Reclaim mode the agent used for that run: `gradual` or `dropcache`.
    #[serde(default)]
    pub memory_reclaim_mode: Option<String>,
    /// How far the guest's own `Cached` figure fell across that run, not host memory returned.
    #[serde(default)]
    pub memory_reclaim_observed_cache_delta_bytes: Option<u64>,
    /// When that run finished (RFC 3339).
    #[serde(default)]
    pub memory_reclaim_at: Option<String>,
    /// Reclaim runs the agent has completed since it started.
    #[serde(default)]
    pub memory_reclaim_runs: Option<u64>,
    /// Whether the runtime requested per-VM host memory reclaim qualification.
    #[serde(default)]
    pub host_memory_reclaim_requested: bool,
    /// Effective state as last reported by the VM backend. `None` until it reports.
    #[serde(default)]
    pub host_memory_reclaim_effective: Option<bool>,
    /// Outcome of the backend's qualification probe, when reported.
    #[serde(default)]
    pub host_memory_reclaim_qualification: Option<String>,
    /// Bytes the backend released to the host during this VM run, when reported.
    #[serde(default)]
    pub host_memory_reclaim_released_bytes: Option<u64>,
    /// Release cycles that failed during this VM run, when reported.
    #[serde(default)]
    pub host_memory_reclaim_failed_operations: Option<u64>,
}

/// Outcome of one agent reclaim run, as the agent reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryReclaimOutcome {
    /// The kernel accepted the whole request.
    Reclaimed,
    /// The kernel stopped early and freed less than half of the request.
    Partial,
    /// No reclaimable cache above the agent's floor.
    Nothing,
    /// The control file could not be written.
    Failed,
}

#[cfg(test)]
mod tests {
    use crate::status::{DaemonPhase, DaemonStatus};

    #[test]
    fn minimal_status_from_an_older_writer_defaults_newer_fields() {
        let status: DaemonStatus = serde_json::from_value(serde_json::json!({
            "schema": 1, "generation": "d823458f-090b-48c3-87d4-33daf76c0000",
            "pid": 1, "phase": "ready", "machine_id": null, "run_id": null,
            "image_digest": null, "docker_socket": "/tmp/test.sock",
            "updated_at": "2026-01-01T00:00:00Z", "last_error": null, "restart_count": 0,
            "field_from_a_newer_silod": true,
        }))
        .expect("lenient status");
        assert_eq!(status.phase, DaemonPhase::Ready);
        assert_eq!(status.process_start, "");
        assert!(status.memory_reclaim_outcome.is_none());
        assert!(status.update_checked_at.is_none());
        assert!(!status.host_memory_reclaim_requested);
        assert!(status.host_memory_reclaim_effective.is_none());
    }

    #[test]
    fn phases_use_snake_case() {
        assert_eq!(
            serde_json::to_value(DaemonPhase::PreparingStorage).expect("serialize"),
            "preparing_storage"
        );
        assert_eq!(
            serde_json::from_value::<DaemonPhase>("upgrading".into()).expect("parse"),
            DaemonPhase::Upgrading
        );
    }
}
