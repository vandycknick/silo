//! Internal adapter for the `silo-vmm` supervisor process.
//!
//! This module is deliberately thin: it launches silo-vmm, speaks the silo-vmm
//! control protocol, reads silo-vmm-owned files, and probes silo-vmm process
//! identity. It does not read or write the machine store, take machine locks, or
//! decide whether a lifecycle operation is valid. Those policies live in
//! `Machine` and `Runtime`.

use std::path::PathBuf;

use crate::paths::LocalPaths;
use crate::store::models::MachineId;

mod client;
pub(crate) mod exit_status;
pub(crate) mod launch;
mod launch_spec;
pub(crate) mod process;
pub(crate) mod start_request;
pub(crate) mod storage_holder;

pub use client::DEFAULT_GUEST_READINESS_TIMEOUT;
pub(crate) use client::{forward_rpc_error, ForwardClientError, VmmClient, VmmClientError};
pub(crate) use launch::VmmLaunch;
pub(crate) use launch_spec::{prepare_launch_spec, write_launch_spec, LaunchSpecInput};

/// Crate-private adapter for the `silo-vmm` supervisor process.
#[derive(Debug, Clone)]
pub(crate) struct VmSupervisor {
    paths: LocalPaths,
    executable: PathBuf,
    selection: std::sync::Arc<crate::runtime::capabilities::ResolvedBackendSelection>,
}

#[derive(Debug)]
pub(crate) struct VmmLaunchInputs {
    pub(crate) agent_enabled: bool,
    pub(crate) rosetta_intent: start_request::VmmRosettaIntent,
    pub(crate) asset_directory: PathBuf,
    pub(crate) storage_shutdown: protocol::shutdown::StorageShutdownContext,
    pub(crate) artifacts: crate::machine::root_storage::LaunchArtifacts,
}

impl VmSupervisor {
    /// Creates a silo-vmm adapter bound to the runtime's local paths.
    pub(crate) fn new(
        paths: LocalPaths,
        executable: PathBuf,
        selection: std::sync::Arc<crate::runtime::capabilities::ResolvedBackendSelection>,
    ) -> Self {
        Self {
            paths,
            executable,
            selection,
        }
    }

    pub(crate) fn executable(&self) -> &std::path::Path {
        &self.executable
    }

    /// Explicit backend selection forwarded in every start request.
    pub(crate) fn virt_backend_request(&self) -> Option<start_request::VmmVirtBackend> {
        Some(self.selection.request())
    }

    pub(crate) fn rosetta_intent_request(
        &self,
        config: &crate::store::models::MachineConfig,
        effective_rosetta: rootfs_spec::RosettaMode,
    ) -> Result<start_request::VmmRosettaIntent, String> {
        let hardware = config.spec.hardware.as_ref();
        if effective_rosetta == rootfs_spec::RosettaMode::Disabled {
            return Ok(start_request::VmmRosettaIntent::Disabled {});
        }
        if hardware
            .and_then(|hardware| hardware.nested_virtualization)
            .unwrap_or(false)
        {
            return Err("Rosetta does not support nested virtualization".to_string());
        }
        let mounts = vm_spec::project_mounts(&config.spec.mounts)
            .map_err(|error| format!("validate Rosetta mount contract: {error}"))?;
        if mounts
            .iter()
            .any(|mount| mount.backend_tag == rootfs_spec::rosetta::SHARE_TAG)
        {
            return Err(format!(
                "mount tag {:?} is reserved for Rosetta",
                rootfs_spec::rosetta::SHARE_TAG
            ));
        }

        Ok(start_request::VmmRosettaIntent::Enabled {})
    }

    pub(crate) fn client(&self, machine_id: MachineId) -> VmmClient {
        VmmClient::new(self.paths.machine(machine_id).vmm_socket_path())
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::VirtBackendOverride;
    use crate::store::models::{MachineConfig, MachineId, MachineNetworkConfig};
    use crate::supervisor::VmSupervisor;

    fn rosetta_machine_config() -> MachineConfig {
        MachineConfig {
            id: MachineId::new(),
            lock_id: crate::lock_manager::LockId::from(0),
            name: "rosetta-test".to_string(),
            spec: vm_spec::VmSpec {
                boot: Some(vm_spec::Boot {
                    kernel: Some(vm_spec::Kernel {
                        path: None,
                        cmdline: Vec::new(),
                        initramfs: None,
                    }),
                    userdata: None,
                }),
                hardware: Some(vm_spec::Hardware {
                    cpus: None,
                    memory: None,
                    nested_virtualization: Some(false),
                    rosetta: Some(true),
                }),
                ..vm_spec::VmSpec::current()
            },
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: Some(crate::machine::MachineAgent::Disabled),
            guest: crate::machine::MachineGuestConfig::default(),
            machine_dir: "/tmp/rosetta-test".into(),
            created_at: 1,
            modified_at: 1,
            image_ref: "test:latest".to_string(),
            root_disk_size: None,
            labels: std::collections::BTreeMap::new(),
            metadata: std::collections::BTreeMap::new(),
            network: MachineNetworkConfig::default(),
        }
    }

    #[test]
    fn real_backend_requests_are_strictly_paired_without_mock_scenarios() {
        for (selection, expected) in [
            (VirtBackendOverride::Krun, "krun"),
            (VirtBackendOverride::Vz, "vz"),
        ] {
            let supervisor = VmSupervisor::new(
                crate::paths::LocalPaths::new("/tmp/silo-test"),
                "/tmp/silo-vmm".into(),
                crate::runtime::capabilities::ResolvedBackendSelection::resolve(Some(&selection))
                    .expect("selection"),
            );
            let request = supervisor.virt_backend_request().expect("backend request");
            assert_eq!(request.kind, expected);
            assert!(request.scenario.is_none());
        }
    }

    #[test]
    fn durable_rosetta_eligibility_uses_guest_contract_not_completed_assets_or_legacy_label() {
        use crate::supervisor::start_request::VmmRosettaIntent;

        let supervisor = VmSupervisor::new(
            crate::paths::LocalPaths::new("/tmp/silo-test"),
            "/operator/silo-vmm".into(),
            crate::runtime::capabilities::ResolvedBackendSelection::resolve(Some(
                &VirtBackendOverride::Krun,
            ))
            .expect("selection"),
        );
        let config = rosetta_machine_config();
        assert_eq!(
            supervisor
                .rosetta_intent_request(&config, rootfs_spec::RosettaMode::Required)
                .expect("default durable contract"),
            VmmRosettaIntent::Enabled {}
        );
    }

    #[test]
    fn rosetta_intent_is_backend_independent() {
        use crate::supervisor::start_request::VmmRosettaIntent;

        for backend in [
            None,
            Some(VirtBackendOverride::Krun),
            Some(VirtBackendOverride::Vz),
        ] {
            let supervisor = VmSupervisor::new(
                crate::paths::LocalPaths::new("/tmp/silo-test"),
                "/operator/silo-vmm".into(),
                crate::runtime::capabilities::ResolvedBackendSelection::resolve(backend.as_ref())
                    .expect("selection"),
            );
            assert_eq!(
                supervisor
                    .rosetta_intent_request(
                        &rosetta_machine_config(),
                        rootfs_spec::RosettaMode::Optional
                    )
                    .expect("generic Rosetta intent"),
                VmmRosettaIntent::Enabled {}
            );
        }
    }

    #[test]
    fn init_owned_rosetta_allows_custom_assets_but_rejects_nested_and_reserved_tag() {
        let supervisor = VmSupervisor::new(
            crate::paths::LocalPaths::new("/tmp/silo-test"),
            "/operator/silo-vmm".into(),
            crate::runtime::capabilities::ResolvedBackendSelection::resolve(Some(
                &VirtBackendOverride::Vz,
            ))
            .expect("selection"),
        );

        let mut custom_agent = rosetta_machine_config();
        custom_agent.guest.agent = crate::machine::MachineAgent::Custom {
            path: "/custom/agent".into(),
        };
        assert!(supervisor
            .rosetta_intent_request(&custom_agent, rootfs_spec::RosettaMode::Required)
            .is_ok());
        custom_agent.guest.agent = crate::machine::MachineAgent::Disabled;
        custom_agent.spec.hardware.as_mut().unwrap().rosetta = None;
        assert!(supervisor
            .rosetta_intent_request(&custom_agent, rootfs_spec::RosettaMode::Required)
            .is_ok());

        let mut custom_kernel = rosetta_machine_config();
        custom_kernel
            .spec
            .boot
            .as_mut()
            .and_then(|boot| boot.kernel.as_mut())
            .expect("kernel")
            .path = Some("/custom/kernel".into());
        assert!(supervisor
            .rosetta_intent_request(&custom_kernel, rootfs_spec::RosettaMode::Optional)
            .is_ok());

        let mut nested = rosetta_machine_config();
        nested
            .spec
            .hardware
            .as_mut()
            .expect("hardware")
            .nested_virtualization = Some(true);
        assert!(supervisor
            .rosetta_intent_request(&nested, rootfs_spec::RosettaMode::Required)
            .is_err());

        let mut collision = rosetta_machine_config();
        collision.spec.mounts.push(vm_spec::Mount {
            source: "/host/share".into(),
            tag: rootfs_spec::rosetta::SHARE_TAG.to_string(),
            read_only: true,
        });
        let error = supervisor
            .rosetta_intent_request(&collision, rootfs_spec::RosettaMode::Required)
            .expect_err("reject reserved mount tag");
        assert!(error.contains("reserved for Rosetta"));
    }
}
