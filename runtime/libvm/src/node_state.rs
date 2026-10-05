//! Exclusive stopped-machine node-state leases shared by every native consumer.
use crate::lock_manager::MachineLifetimeLock;
use crate::machine::Machine;
use crate::store::models::MachineConfig;
use crate::LibVmError;

#[must_use = "the node-state lease releases when dropped"]
pub struct NodeStateLease {
    _lock: MachineLifetimeLock,
}

pub(crate) fn acquire(config: &MachineConfig) -> Result<NodeStateLease, LibVmError> {
    let lease = acquire_lock(config)?;
    // Directory artifacts are fences too, including transactions from older writers.
    // A process crash releases flock, but must not authorize starting/updating
    // an identity mid-transaction. Explicit removal may discard abandoned state.
    for name in [
        "tailscale.transaction",
        "tailscale.pending",
        "tailscale.backup",
        "tailscale.unreadable",
    ] {
        match std::fs::symlink_metadata(config.machine_dir.join(name)) {
            Ok(_) => {
                return Err(LibVmError::InvalidMachineUpdate {
                    reference: config.name.clone(),
                    reason: "node state recovery required".into(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(lease)
}

pub(crate) fn acquire_lock(config: &MachineConfig) -> Result<NodeStateLease, LibVmError> {
    let lock = MachineLifetimeLock::try_acquire(&config.machine_dir.join("node-state.lock"))?
        .ok_or_else(|| LibVmError::InvalidMachineUpdate {
            reference: config.name.clone(),
            reason: "node state busy".into(),
        })?;
    Ok(NodeStateLease { _lock: lock })
}

impl Machine {
    /// Excludes Start, Remove and Update across processes while replacing node state.
    /// Inspect remains available. Release the lease before starting the machine.
    pub async fn lease_node_state(&self) -> Result<NodeStateLease, LibVmError> {
        let runtime = self.runtime();
        let (_config_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        runtime.validate_machine_data_dir(&config)?;
        // Recovery must be able to lease a fenced machine without mutating it.
        let lease = acquire_lock(&config)?;
        runtime.ensure_no_live_vmm_generation(&config).await?;
        if runtime
            .reconcile_machine_runtime_locked(&config)
            .await?
            .is_active()
        {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name,
            });
        }
        runtime.reconcile_machine_network(&config, false).await?;
        Ok(lease)
    }
}

#[cfg(test)]
mod tests {
    use crate::{ImageSource, MachineUpdate, Runtime, RuntimeNetworkingConfig};
    #[tokio::test]
    async fn lease_excludes_native_mutations_without_blocking_inspect() {
        let home = tempfile::tempdir().unwrap();
        let disk = home.path().join("root.raw");
        std::fs::write(&disk, b"stopped fixture").unwrap();
        let runtime = Runtime::open(
            crate::paths::LocalPaths::new(home.path().join("home")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let machine = runtime
            .machine()
            .name("leased")
            .image_source(ImageSource::disk(&disk))
            .create()
            .await
            .unwrap();
        let before = machine.inspect().await.unwrap();
        let lease = machine.lease_node_state().await.unwrap();
        assert!(machine.lease_node_state().await.is_err());
        assert!(machine
            .start()
            .await
            .unwrap_err()
            .to_string()
            .contains("node state busy"));
        assert!(machine
            .update(MachineUpdate::new().cpus(2))
            .await
            .unwrap_err()
            .to_string()
            .contains("node state busy"));
        assert!(machine
            .clone()
            .remove()
            .await
            .unwrap_err()
            .to_string()
            .contains("node state busy"));
        let after = machine.inspect().await.unwrap();
        assert_eq!(before.name, after.name);
        assert_eq!(before.spec.hardware, after.spec.hardware);
        drop(lease);
        machine.update(MachineUpdate::new().cpus(2)).await.unwrap();
        machine.remove().await.unwrap();
    }

    #[tokio::test]
    async fn recovery_artifacts_fence_mutations_but_not_inspection_or_recovery_leases() {
        let home = tempfile::tempdir().unwrap();
        let disk = home.path().join("root.raw");
        std::fs::write(&disk, b"stopped fixture").unwrap();
        let runtime = Runtime::open(
            crate::paths::LocalPaths::new(home.path().join("home")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let machine = runtime
            .machine()
            .name("fenced")
            .image_source(ImageSource::disk(&disk))
            .create()
            .await
            .unwrap();
        let dir = runtime
            .machine_paths(machine.machine_id())
            .dir()
            .to_path_buf();
        for name in [
            "tailscale.transaction",
            "tailscale.pending",
            "tailscale.backup",
            "tailscale.unreadable",
        ] {
            let path = dir.join(name);
            std::fs::write(&path, b"retained transaction").unwrap();
            let lease = machine.lease_node_state().await.unwrap();
            drop(lease);
            machine.inspect().await.unwrap();
            assert!(machine
                .start()
                .await
                .unwrap_err()
                .to_string()
                .contains("node state recovery required"));
            assert!(machine
                .update(MachineUpdate::new().cpus(2))
                .await
                .unwrap_err()
                .to_string()
                .contains("node state recovery required"));
            assert!(path.exists());
        }
        let lease = machine.lease_node_state().await.unwrap();
        assert!(machine
            .clone()
            .remove()
            .await
            .unwrap_err()
            .to_string()
            .contains("node state busy"));
        drop(lease);
        machine.remove().await.unwrap();
        assert!(!dir.exists());
    }
}
