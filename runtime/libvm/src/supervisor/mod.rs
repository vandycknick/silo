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
mod launch;
mod launch_spec;
pub(crate) mod process;
pub(crate) mod start_request;

pub use client::DEFAULT_GUEST_READINESS_TIMEOUT;
pub(crate) use client::{forward_rpc_error, ForwardClientError, VmmClient, VmmClientError};
pub(crate) use launch::VmmLaunch;
pub(crate) use launch_spec::{prepare_launch_spec, write_launch_spec, LaunchSpecInput};

/// Crate-private adapter for the `silo-vmm` supervisor process.
#[derive(Debug, Clone)]
pub(crate) struct VmSupervisor {
    paths: LocalPaths,
    executable: PathBuf,
    virt_backend: Option<crate::runtime::VirtBackendOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmmLaunchInputs {
    pub(crate) agent_enabled: bool,
    pub(crate) rosetta_intent: start_request::VmmRosettaIntent,
    pub(crate) asset_directory: PathBuf,
}

impl VmSupervisor {
    /// Creates a silo-vmm adapter bound to the runtime's local paths.
    pub(crate) fn new(
        paths: LocalPaths,
        executable: PathBuf,
        virt_backend: Option<crate::runtime::VirtBackendOverride>,
    ) -> Self {
        Self {
            paths,
            executable,
            virt_backend,
        }
    }

    pub(crate) fn executable(&self) -> &std::path::Path {
        &self.executable
    }

    /// Explicit backend selection forwarded in every start request.
    pub(crate) fn virt_backend_request(&self) -> Option<start_request::VmmVirtBackend> {
        self.virt_backend.as_ref().map(|selection| match selection {
            crate::runtime::VirtBackendOverride::Krun => start_request::VmmVirtBackend {
                kind: "krun".to_string(),
                scenario: None,
            },
            crate::runtime::VirtBackendOverride::Vz => start_request::VmmVirtBackend {
                kind: "vz".to_string(),
                scenario: None,
            },
            crate::runtime::VirtBackendOverride::Mock { scenario } => {
                start_request::VmmVirtBackend {
                    kind: "mock".to_string(),
                    scenario: scenario.clone(),
                }
            }
        })
    }

    pub(crate) fn rosetta_intent_request(
        &self,
        config: &crate::store::models::MachineConfig,
    ) -> Result<start_request::VmmRosettaIntent, String> {
        let hardware = config.spec.hardware.as_ref();
        if !hardware
            .and_then(|hardware| hardware.rosetta)
            .unwrap_or(false)
        {
            return Ok(start_request::VmmRosettaIntent::Disabled {});
        }

        if config.guest.agent != crate::machine::MachineAgent::Default {
            return Err("Rosetta requires the installed default guest agent".to_string());
        }
        if config
            .spec
            .boot
            .as_ref()
            .and_then(|boot| boot.kernel.as_ref())
            .and_then(|kernel| kernel.path.as_ref())
            .is_some()
        {
            return Err("Rosetta requires the runtime's default workload kernel".to_string());
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
            .any(|mount| mount.backend_tag == agent_spec::ROSETTA_MOUNT_TAG)
        {
            return Err(format!(
                "mount tag {:?} is reserved for Rosetta",
                agent_spec::ROSETTA_MOUNT_TAG
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use crate::store::models::{MachineConfig, MachineId, MachineNetworkConfig};
    use crate::supervisor::VmSupervisor;

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
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
                Some(selection),
            );
            let request = supervisor.virt_backend_request().expect("backend request");
            assert_eq!(request.kind, expected);
            assert!(request.scenario.is_none());
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn durable_rosetta_eligibility_uses_guest_contract_not_completed_assets_or_legacy_label() {
        use crate::supervisor::start_request::VmmRosettaIntent;

        let supervisor = VmSupervisor::new(
            crate::paths::LocalPaths::new("/tmp/silo-test"),
            "/operator/silo-vmm".into(),
            Some(VirtBackendOverride::Krun),
        );
        let config = rosetta_machine_config();
        assert_eq!(
            supervisor
                .rosetta_intent_request(&config)
                .expect("default durable contract"),
            VmmRosettaIntent::Enabled {}
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
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
                backend,
            );
            assert_eq!(
                supervisor
                    .rosetta_intent_request(&rosetta_machine_config())
                    .expect("generic Rosetta intent"),
                VmmRosettaIntent::Enabled {}
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn durable_rosetta_eligibility_rejects_custom_agent_kernel_nested_and_reserved_tag() {
        let supervisor = VmSupervisor::new(
            crate::paths::LocalPaths::new("/tmp/silo-test"),
            "/operator/silo-vmm".into(),
            Some(VirtBackendOverride::Vz),
        );

        let mut custom_agent = rosetta_machine_config();
        custom_agent.guest.agent = crate::machine::MachineAgent::Custom {
            path: "/custom/agent".into(),
        };
        assert!(supervisor.rosetta_intent_request(&custom_agent).is_err());

        let mut custom_kernel = rosetta_machine_config();
        custom_kernel
            .spec
            .boot
            .as_mut()
            .and_then(|boot| boot.kernel.as_mut())
            .expect("kernel")
            .path = Some("/custom/kernel".into());
        assert!(supervisor.rosetta_intent_request(&custom_kernel).is_err());

        let mut nested = rosetta_machine_config();
        nested
            .spec
            .hardware
            .as_mut()
            .expect("hardware")
            .nested_virtualization = Some(true);
        assert!(supervisor.rosetta_intent_request(&nested).is_err());

        let mut collision = rosetta_machine_config();
        collision.spec.mounts.push(vm_spec::Mount {
            source: "/host/share".into(),
            tag: agent_spec::ROSETTA_MOUNT_TAG.to_string(),
            read_only: true,
        });
        let error = supervisor
            .rosetta_intent_request(&collision)
            .expect_err("reject reserved mount tag");
        assert!(error.contains("reserved for Rosetta"));
    }
}
