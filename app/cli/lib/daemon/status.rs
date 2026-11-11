//! One process-owned snapshot for both the status file and management API.
use crate::daemon::{
    record::write_record,
    supervisor::{now, process_start_identity},
};
use silod_spec::{daemon::v1 as w, status::*};
use std::{path::PathBuf, sync::Mutex};

pub(crate) struct StatusPublisher {
    path: PathBuf,
    config_dir: PathBuf,
    status: Mutex<DaemonStatus>,
}
impl StatusPublisher {
    pub(crate) fn new(
        host: &libvm::HostPaths,
        generation: uuid::Uuid,
        configuration_identity: String,
        system: Option<SystemStatus>,
    ) -> eyre::Result<Self> {
        let publisher = Self {
            path: silod_spec::paths::DaemonPaths::new(host.home()).status(),
            config_dir: host.config_dir().into(),
            status: Mutex::new(DaemonStatus {
                schema: 2,
                generation,
                pid: std::process::id(),
                process_start: process_start_identity()?,
                core: CorePhase::Starting,
                home: host.home().into(),
                control_endpoint: silod_spec::paths::control_socket(&libvm::HostPaths::run_root()?),
                updated_at: now(),
                last_error: None,
                system,
                configuration_identity,
                manager_live: None,
                appliance_live: None,
            }),
        };
        publisher.update(|_| {})?;
        Ok(publisher)
    }
    fn update(&self, change: impl FnOnce(&mut DaemonStatus)) -> eyre::Result<()> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| eyre::eyre!("status publisher poisoned"))?;
        // Publish before replacing the API snapshot: a failed write must not claim success.
        let mut next = status.clone();
        change(&mut next);
        next.updated_at = now();
        write_record(&self.path, &next)?;
        *status = next;
        Ok(())
    }
    pub(crate) fn set_core(&self, core: CorePhase, error: Option<String>) -> eyre::Result<()> {
        self.update(|s| {
            s.core = core;
            s.last_error = error;
        })
    }
    pub(crate) fn set_manager_live(
        &self,
        report: vm_spec::live::LiveHostReport,
    ) -> eyre::Result<()> {
        self.update(|s| s.manager_live = Some(report))
    }
    pub(crate) fn set_system(&self, system: SystemStatus) -> eyre::Result<()> {
        self.update(|s| {
            s.appliance_live = system.prospective_live.clone();
            s.system = Some(system);
        })
    }
    pub(crate) fn fail_system(&self, error: String) -> eyre::Result<()> {
        self.update(|s| {
            if let Some(system) = &mut s.system {
                system.phase = SystemPhase::Failed;
                system.last_error = Some(error);
                system.updated_at = now();
            }
        })
    }
    pub(crate) fn wire(&self) -> eyre::Result<w::DaemonStatus> {
        let s = self
            .status
            .lock()
            .map_err(|_| eyre::eyre!("status publisher poisoned"))?;
        Ok(w::DaemonStatus {
            live_schema_version: Some(1),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol_major: 1,
            generation: s.generation.to_string(),
            home: silo_vm_control::path_to_wire(&s.home),
            config_dir: silo_vm_control::path_to_wire(&self.config_dir),
            core: match s.core {
                CorePhase::Starting => w::CorePhase::Starting,
                CorePhase::Ready => w::CorePhase::Ready,
                CorePhase::Stopping => w::CorePhase::Stopping,
                CorePhase::Stopped => w::CorePhase::Stopped,
                CorePhase::Failed => w::CorePhase::Failed,
            } as i32,
            schema: s.schema,
            pid: s.pid,
            process_start: s.process_start.clone(),
            control_endpoint: silo_vm_control::path_to_wire(&s.control_endpoint),
            updated_at: timestamp(&s.updated_at),
            last_error: s.last_error.clone(),
            manager_live: s
                .manager_live
                .as_ref()
                .map(silo_vm_control::live::host_to_wire)
                .transpose()?,
            appliance_live: s
                .appliance_live
                .as_ref()
                .map(silo_vm_control::live::host_to_wire)
                .transpose()?,
            system: s.system.as_ref().map(system_wire).transpose()?,
        })
    }
}
fn timestamp(s: &str) -> Option<prost_types::Timestamp> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| prost_types::Timestamp {
            seconds: t.timestamp(),
            nanos: t.timestamp_subsec_nanos() as i32,
        })
}
fn system_wire(s: &SystemStatus) -> eyre::Result<w::SystemStatus> {
    Ok(w::SystemStatus {
        live_schema_version: Some(1),
        phase: match s.phase {
            SystemPhase::PreparingStorage => w::SystemPhase::PreparingStorage,
            SystemPhase::Creating => w::SystemPhase::Creating,
            SystemPhase::StartingVm => w::SystemPhase::StartingVm,
            SystemPhase::WaitingGuest => w::SystemPhase::WaitingGuest,
            SystemPhase::ActivatingEngine => w::SystemPhase::ActivatingEngine,
            SystemPhase::Retrying => w::SystemPhase::Retrying,
            SystemPhase::Ready => w::SystemPhase::Ready,
            SystemPhase::Degraded => w::SystemPhase::Degraded,
            SystemPhase::Upgrading => w::SystemPhase::Upgrading,
            SystemPhase::Failed => w::SystemPhase::Failed,
            SystemPhase::Stopping => w::SystemPhase::Stopping,
            SystemPhase::Stopped => w::SystemPhase::Stopped,
        } as i32,
        machine_id: s.machine_id.clone(),
        run_id: s.run_id.clone(),
        image_digest: s.image_digest.clone(),
        configured_image: s.configured_image.clone(),
        memory_bytes: s.memory_bytes,
        actual_backend: s.actual_backend.clone(),
        live: s
            .live
            .as_ref()
            .map(silo_vm_control::live::machine_to_wire)
            .transpose()?,
        prospective_live: s
            .prospective_live
            .as_ref()
            .map(silo_vm_control::live::host_to_wire)
            .transpose()?,
        docker_socket: silo_vm_control::path_to_wire(std::path::Path::new(&s.docker_socket)),
        last_error: s.last_error.clone(),
        restart_count: s.restart_count.into(),
        update_checked_at: s.update_checked_at.as_deref().and_then(timestamp),
        update_error: s.update_error.clone(),
        memory_reclaim_outcome: s.memory_reclaim_outcome.map(|o| match o {
            MemoryReclaimOutcome::Reclaimed => w::MemoryReclaimOutcome::Reclaimed,
            MemoryReclaimOutcome::Partial => w::MemoryReclaimOutcome::Partial,
            MemoryReclaimOutcome::Nothing => w::MemoryReclaimOutcome::Nothing,
            MemoryReclaimOutcome::Failed => w::MemoryReclaimOutcome::Failed,
        } as i32),
        memory_reclaim_mode: s.memory_reclaim_mode.clone(),
        memory_reclaim_observed_cache_delta_bytes: s.memory_reclaim_observed_cache_delta_bytes,
        memory_reclaim_at: s.memory_reclaim_at.as_deref().and_then(timestamp),
        memory_reclaim_runs: s.memory_reclaim_runs,
        host_memory_reclaim_requested: s.host_memory_reclaim_requested,
        host_memory_reclaim_effective: s.host_memory_reclaim_effective,
        host_memory_reclaim_qualification: s.host_memory_reclaim_qualification.clone(),
        host_memory_reclaim_released_bytes: s.host_memory_reclaim_released_bytes,
        host_memory_reclaim_failed_operations: s.host_memory_reclaim_failed_operations,
        host_memory_reclaim_backing: s.host_memory_reclaim_backing.clone(),
        host_memory_reclaim_reason: s.host_memory_reclaim_reason.clone(),
        host_memory_reclaim_mapping_limit_skips: s.host_memory_reclaim_mapping_limit_skips,
        host_memory_reclaim_replaced_islands: s.host_memory_reclaim_replaced_islands,
    })
}

#[cfg(test)]
mod tests {
    use crate::daemon::status::*;
    use std::sync::Arc;

    #[test]
    fn system_wire_preserves_reclaim_mapping_counters() {
        let mut status = crate::daemon::supervisor::initial_status(std::path::Path::new(
            "/tmp/silo-test-docker.sock",
        ))
        .expect("initial status");
        status.host_memory_reclaim_mapping_limit_skips = Some(3);
        status.host_memory_reclaim_replaced_islands = Some(7);
        let wire = system_wire(&status).expect("status wire");
        assert_eq!(wire.host_memory_reclaim_mapping_limit_skips, Some(3));
        assert_eq!(wire.host_memory_reclaim_replaced_islands, Some(7));
    }

    #[test]
    fn system_updates_share_one_root_identity_and_api_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let host = libvm::HostPaths::new(root.path().join("home"), root.path().join("config"));
        let generation = uuid::Uuid::new_v4();
        let system =
            crate::daemon::supervisor::initial_status(&root.path().join("docker.sock")).unwrap();
        let publisher = Arc::new(
            StatusPublisher::new(
                &host,
                generation,
                "effective-config".into(),
                Some(system.clone()),
            )
            .unwrap(),
        );
        publisher.set_core(CorePhase::Ready, None).unwrap();
        let system_writer = publisher.clone();
        let thread = std::thread::spawn(move || {
            let mut system = system;
            system.phase = SystemPhase::Retrying;
            system.machine_id = Some("retained-machine".into());
            system.last_error = Some("runtime unavailable".into());
            for _ in 0..10 {
                system_writer.set_system(system.clone()).unwrap();
            }
        });
        for _ in 0..10 {
            publisher.set_core(CorePhase::Ready, None).unwrap();
        }
        thread.join().unwrap();
        let disk: DaemonStatus = serde_json::from_slice(
            &std::fs::read(silod_spec::paths::DaemonPaths::new(host.home()).status()).unwrap(),
        )
        .unwrap();
        let api = publisher.wire().unwrap();
        assert_eq!(disk.schema, 2);
        assert_eq!(disk.generation, generation);
        assert_eq!(api.generation, generation.to_string());
        assert_eq!(api.pid, disk.pid);
        assert_eq!(api.process_start, disk.process_start);
        assert_eq!(api.updated_at, timestamp(&disk.updated_at));
        assert_eq!(disk.core, CorePhase::Ready);
        assert_eq!(api.core, w::CorePhase::Ready as i32);
        assert_eq!(disk.configuration_identity, "effective-config");
        assert_eq!(disk.system.as_ref().unwrap().phase, SystemPhase::Retrying);
        assert_eq!(api.system.unwrap().phase, w::SystemPhase::Retrying as i32);
        publisher.fail_system("supervisor exited".into()).unwrap();
        assert_eq!(
            publisher
                .wire()
                .unwrap()
                .system
                .unwrap()
                .machine_id
                .as_deref(),
            Some("retained-machine")
        );
        assert!(!host.home().join("state.db").exists());
    }

    #[test]
    fn failed_publication_does_not_advance_api_state() {
        let root = tempfile::tempdir().unwrap();
        let host = libvm::HostPaths::new(root.path().join("home"), root.path().join("config"));
        let publisher =
            StatusPublisher::new(&host, uuid::Uuid::new_v4(), "test".into(), None).unwrap();
        std::fs::remove_file(&publisher.path).unwrap();
        std::fs::create_dir(&publisher.path).unwrap();
        assert!(publisher.set_core(CorePhase::Ready, None).is_err());
        assert_eq!(
            publisher.wire().unwrap().core,
            w::CorePhase::Starting as i32
        );
    }
}
