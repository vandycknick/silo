//! Internal adapter for the `vmmon` supervisor process.
//!
//! This module is deliberately thin: it launches vmmon, speaks the vmmon
//! control protocol, reads vmmon-owned files, and probes vmmon process
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

pub(crate) use client::VmmonClient;
pub use client::DEFAULT_GUEST_READINESS_TIMEOUT;
pub(crate) use launch::VmmonLaunch;
pub(crate) use launch_spec::{prepare_launch_spec, write_launch_spec, LaunchSpecInput};

/// Crate-private adapter for the `vmmon` supervisor process.
#[derive(Debug, Clone)]
pub(crate) struct Vmmon {
    paths: LocalPaths,
    executable: PathBuf,
    krun_path: PathBuf,
    virt_backend: Option<crate::runtime::VirtBackendOverride>,
}

impl Vmmon {
    /// Creates a vmmon adapter bound to the runtime's local paths.
    pub(crate) fn new(
        paths: LocalPaths,
        executable: PathBuf,
        krun_path: PathBuf,
        virt_backend: Option<crate::runtime::VirtBackendOverride>,
    ) -> Self {
        Self {
            paths,
            executable,
            krun_path,
            virt_backend,
        }
    }

    pub(crate) fn executable(&self) -> &std::path::Path {
        &self.executable
    }

    pub(crate) fn krun_path(&self) -> &std::path::Path {
        &self.krun_path
    }

    /// Testing-only backend selection forwarded in every start request.
    pub(crate) fn virt_backend_request(&self) -> Option<start_request::VmmonVirtBackend> {
        self.virt_backend.as_ref().map(|selection| match selection {
            crate::runtime::VirtBackendOverride::Mock { scenario } => {
                start_request::VmmonVirtBackend {
                    kind: "mock".to_string(),
                    scenario: scenario.clone(),
                }
            }
        })
    }

    pub(crate) fn client(&self, machine_id: MachineId) -> VmmonClient {
        VmmonClient::new(self.paths.machine(machine_id).vmmon_socket_path())
    }
}
