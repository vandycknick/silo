use std::time::Duration;

use crate::machine::{Machine, MachineData, MachineRef};
use crate::store::models::MachineConfig;
use crate::LibVmError;

impl Machine {
    /// Inspects the machine and returns an owned point-in-time snapshot.
    ///
    /// This always loads the persisted machine config and reconciles the stored
    /// runtime state with the local vmmon process before returning. If vmmon is
    /// running, libvm also attempts a best-effort vmmon inspect RPC to enrich the
    /// public status with guest readiness and a summary message. A vmmon
    /// telemetry failure does not fail inspect by itself; it is reported as a
    /// running status with a message. Store/config errors still fail the call.
    pub async fn inspect(&self) -> Result<MachineData, LibVmError> {
        let config = self
            .runtime()
            .resolve_machine_config(&MachineRef::id(self.machine_id()))
            .await?;
        self.runtime().machine_inspect_data(config).await
    }

    /// Waits until the guest agent reports the machine as running.
    pub async fn wait_for_guest_running(&self, timeout: Duration) -> Result<(), LibVmError> {
        let config = self.running_config().await?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .wait_for_guest_running(timeout)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name,
                message,
            })
    }

    /// Opens the machine serial stream.
    pub async fn open_serial_stream(&self) -> Result<tokio::net::UnixStream, LibVmError> {
        let config = self.running_config().await?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .open_serial_stream()
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name,
                message,
            })
    }

    /// Opens the guest shell stream.
    ///
    /// When `wait_for_guest_readiness` is true, this waits for the guest agent
    /// before opening the stream.
    pub async fn open_shell_stream(
        &self,
        wait_for_guest_readiness: bool,
    ) -> Result<tokio::net::UnixStream, LibVmError> {
        let config = self.running_config().await?;
        let client = self.runtime().vmmon().client(self.machine_id());

        if wait_for_guest_readiness {
            client
                .wait_for_shell_with_timeout(
                    crate::vmmon::DEFAULT_GUEST_READINESS_TIMEOUT,
                    Duration::from_secs(1),
                )
                .await
                .map_err(|message| LibVmError::MonitorProtocol {
                    reference: config.name.clone(),
                    message,
                })?;
        }

        client
            .open_shell_stream()
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name,
                message,
            })
    }

    async fn running_config(&self) -> Result<MachineConfig, LibVmError> {
        let runtime = self.runtime();
        let machine_id = self.machine_id();
        let config = runtime
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        if !runtime
            .reconcile_machine_runtime_best_effort(&config)
            .await?
            .is_running()
        {
            return Err(LibVmError::MachineNotRunning {
                reference: config.name,
            });
        }

        Ok(config)
    }
}
