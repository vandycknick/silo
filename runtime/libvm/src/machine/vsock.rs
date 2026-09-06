use std::path::PathBuf;

use crate::machine::{Machine, MachineRef};
use crate::LibVmError;

impl Machine {
    /// Return the public vsock mux path when the surface is enabled.
    pub async fn vsock_socket(&self) -> Result<Option<PathBuf>, LibVmError> {
        let runtime = self.runtime();
        let config = runtime
            .resolve_machine_config(&MachineRef::id(self.machine_id()))
            .await?;
        let Some(filename) = vm_spec::effective_vsock_filename(config.spec.vsock.as_ref()) else {
            return Ok(None);
        };
        runtime.local_paths().ensure_machine_run_dir(config.id)?;
        Ok(Some(
            runtime.machine_paths(config.id).vsock_mux_path(filename),
        ))
    }

    /// Return the guest-initiated listener path when the public surface permits it.
    pub async fn vsock_listener_socket(&self, port: u32) -> Result<Option<PathBuf>, LibVmError> {
        let runtime = self.runtime();
        let config = runtime
            .resolve_machine_config(&MachineRef::id(self.machine_id()))
            .await?;
        let Some(filename) = vm_spec::effective_vsock_filename(config.spec.vsock.as_ref()) else {
            return Ok(None);
        };
        if matches!(
            port,
            protocol::DEFAULT_GUEST_CONTROL_PORT | protocol::FORWARD_VSOCK_PORT
        ) {
            return Ok(None);
        }
        runtime.local_paths().ensure_machine_run_dir(config.id)?;
        Ok(Some(
            runtime
                .machine_paths(config.id)
                .vsock_listener_path(filename, port),
        ))
    }
}
