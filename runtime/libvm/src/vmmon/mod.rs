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

pub(crate) use client::VmmonClient;
pub use client::DEFAULT_GUEST_READINESS_TIMEOUT;
pub(crate) use launch::VmmonLaunch;
pub(crate) use launch_spec::{prepare_launch_spec, write_launch_spec, LaunchSpecInput};

/// Crate-private adapter for the `vmmon` supervisor process.
#[derive(Debug, Clone)]
pub(crate) struct Vmmon {
    paths: LocalPaths,
    executable: Option<PathBuf>,
}

impl Vmmon {
    /// Creates a vmmon adapter bound to the runtime's local paths.
    pub(crate) fn new(paths: LocalPaths, executable: Option<PathBuf>) -> Self {
        Self { paths, executable }
    }

    pub(crate) fn executable(&self) -> Option<&std::path::Path> {
        self.executable.as_deref()
    }

    pub(crate) fn client(&self, machine_id: MachineId) -> VmmonClient {
        VmmonClient::new(self.paths.machine(machine_id).vmmon_socket_path())
    }
}
