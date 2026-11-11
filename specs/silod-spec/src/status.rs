//! `status.json`: live silod state, republished atomically on every change.
//! Live reports retain their explicit prospective-host or exact-machine scope.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemPhase {
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
    /// [`crate::process::start_time`] of `pid`: its birth time in Unix seconds.
    #[serde(default)]
    pub process_start: String,
    pub core: CorePhase,
    pub home: PathBuf,
    pub control_endpoint: PathBuf,
    pub updated_at: String,
    pub last_error: Option<String>,
    pub system: Option<SystemStatus>,
    pub configuration_identity: String,
    #[serde(deserialize_with = "required_option")]
    pub manager_live: Option<vm_spec::live::LiveHostReport>,
    #[serde(deserialize_with = "required_option")]
    pub appliance_live: Option<vm_spec::live::LiveHostReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorePhase {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSystemStatus")]
pub struct SystemStatus {
    pub phase: SystemPhase,
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
    #[serde(deserialize_with = "required_option")]
    pub live: Option<vm_spec::live::LiveMachineReport>,
    #[serde(deserialize_with = "required_option")]
    pub prospective_live: Option<vm_spec::live::LiveHostReport>,
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
    /// Finalized runtime policy once observed; backend intent before the first report.
    #[serde(default)]
    pub host_memory_reclaim_requested: bool,
    /// Effective state as last reported by the VM backend. `None` until it reports.
    #[serde(default)]
    pub host_memory_reclaim_effective: Option<bool>,
    /// Outcome of the backend's qualification probe, when reported.
    #[serde(default)]
    pub host_memory_reclaim_qualification: Option<String>,
    /// Actual RAM backing, absent until the backend reports.
    pub host_memory_reclaim_backing: Option<String>,
    /// Structural inhibition reason, absent until the backend reports.
    pub host_memory_reclaim_reason: Option<String>,
    /// Successfully advised bytes including repeats, not physical memory saved.
    #[serde(default)]
    pub host_memory_reclaim_released_bytes: Option<u64>,
    /// Release cycles that failed during this VM run, when reported.
    #[serde(default)]
    pub host_memory_reclaim_failed_operations: Option<u64>,
    /// Discards skipped at the host mapping-count bound.
    pub host_memory_reclaim_mapping_limit_skips: Option<u64>,
    /// Current anonymous replacement islands in restored RAM.
    pub host_memory_reclaim_replaced_islands: Option<u64>,
}

#[derive(Deserialize)]
struct RawSystemStatus {
    phase: SystemPhase,
    machine_id: Option<String>,
    run_id: Option<String>,
    image_digest: Option<String>,
    configured_image: Option<String>,
    memory_bytes: Option<u64>,
    actual_backend: Option<String>,
    #[serde(deserialize_with = "required_option")]
    live: Option<vm_spec::live::LiveMachineReport>,
    #[serde(deserialize_with = "required_option")]
    prospective_live: Option<vm_spec::live::LiveHostReport>,
    docker_socket: String,
    updated_at: String,
    last_error: Option<String>,
    restart_count: u32,
    update_checked_at: Option<String>,
    update_error: Option<String>,
    memory_reclaim_outcome: Option<MemoryReclaimOutcome>,
    memory_reclaim_mode: Option<String>,
    memory_reclaim_observed_cache_delta_bytes: Option<u64>,
    memory_reclaim_at: Option<String>,
    memory_reclaim_runs: Option<u64>,
    #[serde(default)]
    host_memory_reclaim_requested: bool,
    host_memory_reclaim_effective: Option<bool>,
    host_memory_reclaim_qualification: Option<String>,
    host_memory_reclaim_released_bytes: Option<u64>,
    host_memory_reclaim_failed_operations: Option<u64>,
    host_memory_reclaim_backing: Option<String>,
    host_memory_reclaim_reason: Option<String>,
    host_memory_reclaim_mapping_limit_skips: Option<u64>,
    host_memory_reclaim_replaced_islands: Option<u64>,
}

impl TryFrom<RawSystemStatus> for SystemStatus {
    type Error = String;

    fn try_from(raw: RawSystemStatus) -> Result<Self, Self::Error> {
        let status = Self {
            phase: raw.phase,
            machine_id: raw.machine_id,
            run_id: raw.run_id,
            image_digest: raw.image_digest,
            configured_image: raw.configured_image,
            memory_bytes: raw.memory_bytes,
            actual_backend: raw.actual_backend,
            live: raw.live,
            prospective_live: raw.prospective_live,
            docker_socket: raw.docker_socket,
            updated_at: raw.updated_at,
            last_error: raw.last_error,
            restart_count: raw.restart_count,
            update_checked_at: raw.update_checked_at,
            update_error: raw.update_error,
            memory_reclaim_outcome: raw.memory_reclaim_outcome,
            memory_reclaim_mode: raw.memory_reclaim_mode,
            memory_reclaim_observed_cache_delta_bytes: raw
                .memory_reclaim_observed_cache_delta_bytes,
            memory_reclaim_at: raw.memory_reclaim_at,
            memory_reclaim_runs: raw.memory_reclaim_runs,
            host_memory_reclaim_requested: raw.host_memory_reclaim_requested,
            host_memory_reclaim_effective: raw.host_memory_reclaim_effective,
            host_memory_reclaim_qualification: raw.host_memory_reclaim_qualification,
            host_memory_reclaim_released_bytes: raw.host_memory_reclaim_released_bytes,
            host_memory_reclaim_failed_operations: raw.host_memory_reclaim_failed_operations,
            host_memory_reclaim_backing: raw.host_memory_reclaim_backing,
            host_memory_reclaim_reason: raw.host_memory_reclaim_reason,
            host_memory_reclaim_mapping_limit_skips: raw.host_memory_reclaim_mapping_limit_skips,
            host_memory_reclaim_replaced_islands: raw.host_memory_reclaim_replaced_islands,
        };
        status.validate()?;
        Ok(status)
    }
}

impl SystemStatus {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(live) = &self.live {
            live.validate()?;
            let machine_id = self
                .machine_id
                .as_deref()
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| "system machine_id is not a UUID")?;
            let observed_machine_id =
                Uuid::parse_str(&live.machine_id).map_err(|_| "live machine_id is not a UUID")?;
            if machine_id != Some(observed_machine_id)
                || self.run_id.as_deref() != Some(live.run_id.as_str())
            {
                return Err("system status and live evidence machine/run identities differ".into());
            }
        }
        if let Some(prospective) = &self.prospective_live {
            prospective.validate()?;
        }
        Ok(())
    }
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
    use crate::status::{SystemPhase, SystemStatus};
    use vm_spec::live::{
        LiveBackend, LiveCapabilityVector, LiveLane, LiveMachineReport, LiveReasonCode, LiveScope,
    };

    fn system_json() -> serde_json::Value {
        let live = LiveMachineReport {
            schema_version: 1,
            scope: LiveScope::Machine,
            machine_id: "00000000-0000-4000-8000-000000000001".into(),
            run_id: "00000000-0000-4000-8000-000000000002".into(),
            monitor_id: "00000000-0000-4000-8000-000000000003".into(),
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            topology_revision: 1,
            live: LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered),
        };
        serde_json::json!({
            "phase": "ready", "machine_id": live.machine_id, "run_id": live.run_id,
            "image_digest": null, "docker_socket": "/tmp/test.sock",
            "updated_at": "2026-01-01T00:00:00Z", "last_error": null, "restart_count": 0,
            "live": live, "prospective_live": null,
        })
    }

    fn daemon_json(system: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "schema": 1, "generation": "00000000-0000-4000-8000-000000000004",
            "pid": 1, "process_start": "1", "core": "ready", "home": "/tmp/home",
            "control_endpoint": "/tmp/control", "updated_at": "2026-01-01T00:00:00Z",
            "last_error": null, "system": system, "configuration_identity": "unit",
            "manager_live": null, "appliance_live": null,
        })
    }

    #[test]
    fn live_capabilities_system_json_requires_exact_outer_run_identity() {
        let matching = system_json();
        assert!(serde_json::from_value::<SystemStatus>(matching.clone()).is_ok());
        assert!(
            serde_json::from_value::<crate::status::DaemonStatus>(daemon_json(matching.clone()))
                .is_ok()
        );
        for field in ["machine_id", "run_id"] {
            for mismatch in [
                serde_json::Value::Null,
                "00000000-0000-4000-8000-000000000099".into(),
            ] {
                let mut invalid = matching.clone();
                invalid[field] = mismatch;
                assert!(
                    serde_json::from_value::<SystemStatus>(invalid.clone()).is_err(),
                    "{field}"
                );
                assert!(
                    serde_json::from_value::<crate::status::DaemonStatus>(daemon_json(invalid))
                        .is_err(),
                    "nested {field}"
                );
            }
        }
    }

    #[test]
    fn live_capabilities_system_json_preserves_compact_durable_machine_id() {
        let mut payload = system_json();
        let canonical = payload["machine_id"].as_str().unwrap().to_owned();
        let compact = uuid::Uuid::parse_str(&canonical)
            .unwrap()
            .simple()
            .to_string();
        payload["machine_id"] = compact.clone().into();
        let parsed: SystemStatus = serde_json::from_value(payload.clone()).unwrap();
        assert_eq!(parsed.machine_id.as_deref(), Some(compact.as_str()));
        assert_eq!(parsed.live.as_ref().unwrap().machine_id, canonical);
        assert!(
            serde_json::from_value::<crate::status::DaemonStatus>(daemon_json(payload.clone()))
                .is_ok()
        );
        let mut invalid = payload.clone();
        invalid["machine_id"] = "00000000000040008000000000000099".into();
        assert!(serde_json::from_value::<SystemStatus>(invalid).is_err());
        let mut invalid = payload.clone();
        invalid["live"]["machineId"] = compact.into();
        assert!(serde_json::from_value::<SystemStatus>(invalid).is_err());
        payload["run_id"] = "00000000000040008000000000000002".into();
        assert!(serde_json::from_value::<SystemStatus>(payload).is_err());
    }

    #[test]
    fn live_capabilities_status_json_distinguishes_missing_and_null_reports() {
        let mut unavailable = system_json();
        unavailable["live"] = serde_json::Value::Null;
        unavailable["machine_id"] = serde_json::Value::Null;
        unavailable["run_id"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<SystemStatus>(unavailable.clone()).is_ok());
        for field in ["live", "prospective_live"] {
            let mut missing = unavailable.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<SystemStatus>(missing).is_err(),
                "{field}"
            );
        }
        let daemon = daemon_json(unavailable);
        assert!(serde_json::from_value::<crate::status::DaemonStatus>(daemon.clone()).is_ok());
        for field in ["manager_live", "appliance_live"] {
            let mut missing = daemon.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<crate::status::DaemonStatus>(missing).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn legacy_appliance_status_cannot_be_read_as_core_ready() {
        let legacy = serde_json::json!({
            "schema": 1, "generation": "d823458f-090b-48c3-87d4-33daf76c0000",
            "pid": 1, "phase": "ready", "machine_id": null, "run_id": null,
            "image_digest": null, "docker_socket": "/tmp/test.sock",
            "updated_at": "2026-01-01T00:00:00Z", "last_error": null, "restart_count": 0,
        });
        assert!(serde_json::from_value::<crate::status::DaemonStatus>(legacy).is_err());
    }

    #[test]
    fn system_status_explicitly_marks_unavailable_live_evidence() {
        let status: SystemStatus = serde_json::from_value(serde_json::json!({
            "phase": "ready", "machine_id": null, "run_id": null,
            "image_digest": null, "docker_socket": "/tmp/test.sock",
            "updated_at": "2026-01-01T00:00:00Z", "last_error": null, "restart_count": 0,
            "live": null, "prospective_live": null,
            "field_from_a_newer_silod": true,
        }))
        .expect("lenient status");
        assert_eq!(status.phase, SystemPhase::Ready);
        assert!(status.memory_reclaim_outcome.is_none());
        assert!(status.update_checked_at.is_none());
        assert!(!status.host_memory_reclaim_requested);
        assert!(status.host_memory_reclaim_effective.is_none());
    }

    #[test]
    fn phases_use_snake_case() {
        assert_eq!(
            serde_json::to_value(SystemPhase::PreparingStorage).expect("serialize"),
            "preparing_storage"
        );
        assert_eq!(
            serde_json::from_value::<SystemPhase>("upgrading".into()).expect("parse"),
            SystemPhase::Upgrading
        );
    }
}
