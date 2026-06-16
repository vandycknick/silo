use std::fs;

use uuid::Uuid;

use crate::machine::{Machine, MachineData, MachineStartOptions};
use crate::runtime::core::{
    interrupt_monitor, monitor_started_at, pid_file_mtime, read_monitor_pid,
    reconcile_root_disk_size, wait_for_monitor_stop, VmmonRunIdentity,
};
use crate::store::models::MachineRuntimeState;
use crate::vmmon::{VmmonHandshake, VmmonLaunch};
use crate::LibVmError;

impl Machine {
    /// Starts the machine and returns its updated inspect data.
    pub async fn start(&self) -> Result<MachineData, LibVmError> {
        self.start_with(MachineStartOptions::default()).await
    }

    /// Starts the machine with explicit start options.
    pub async fn start_with(
        &self,
        options: MachineStartOptions,
    ) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let vmmon = runtime.vmmon();
        let config = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let machine_paths = runtime.machine_paths(config.id);
            let pid_path = machine_paths.vmmon_pid_path();
            let exit_status_path = machine_paths.vmmon_exit_status_path();
            let config_path = machine_paths.vm_spec_path();
            let socket_path = machine_paths.vmmon_socket_path();
            let trace_path = machine_paths.vmmon_trace_log_path();
            let serial_log_path = machine_paths.serial_log_path();
            let metadata_config_path = machine_paths.metadata_config_path();

            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            runtime
                .reconcile_machine_network(&config, status.is_active())
                .await?;

            if status.is_active() {
                return Err(LibVmError::MachineAlreadyRunning {
                    reference: config.name.clone(),
                });
            }

            reconcile_root_disk_size(&config)?;
            runtime.remove_vmmon_exit_status(&config)?;
            let run_id = Uuid::new_v4().to_string();

            let resolved_network = runtime.prepare_machine_network(&config).await?;
            let mut spec = config.spec.clone();
            runtime.prepare_machine_instance_runtime(&config, &mut spec, &resolved_network)?;

            runtime.request_machine_start(config.id, &run_id).await?;

            let launch = VmmonLaunch {
                machine_id: config.id,
                name: &config.name,
                instance_dir: &config.instance_dir,
                pidfile: &pid_path,
                exit_status: &exit_status_path,
                config: &config_path,
                socket: &socket_path,
                serial_log: &serial_log_path,
                trace_log: &trace_path,
                network: &resolved_network,
                metadata_config: &metadata_config_path,
                run_id: &run_id,
                exit_command: options.exit_command.as_ref(),
                wait_for_registration: crate::vmmon::DEFAULT_GUEST_READINESS_TIMEOUT,
            };
            let VmmonHandshake {
                start_write,
                sync_read,
            } = match vmmon.spawn(&launch).await {
                Ok(handshake) => handshake,
                Err(err) => {
                    runtime
                        .mark_machine_start_stopped(config.id, &run_id, Some(err.to_string()))
                        .await?;
                    return Err(err);
                }
            };
            if let Err(err) = vmmon.release_startpipe(start_write) {
                runtime
                    .mark_machine_start_stopped(config.id, &run_id, Some(err.to_string()))
                    .await?;
                return Err(err.into());
            }

            if let Err(err) = vmmon.wait_for_start(sync_read, &trace_path).await {
                runtime
                    .mark_machine_start_stopped(config.id, &run_id, Some(err.to_string()))
                    .await?;
                return Err(err);
            }

            let pid = match read_monitor_pid(&pid_path) {
                Ok(pid) => pid,
                Err(err) => {
                    runtime
                        .mark_machine_start_error(config.id, &run_id, Some(err.to_string()))
                        .await?;
                    return Err(err.into());
                }
            };
            let started_at = match monitor_started_at(pid, &pid_path, &config.name) {
                Ok(started_at) => started_at,
                Err(err) => {
                    runtime
                        .mark_machine_start_error(config.id, &run_id, Some(err.to_string()))
                        .await?;
                    return Err(err);
                }
            };
            runtime
                .mark_machine_monitor_ready(config.id, run_id, pid, started_at)
                .await?;

            config
        };
        runtime.machine_inspect_data(config).await
    }

    /// Stops the machine and returns its updated inspect data.
    pub async fn stop(&self) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let (config, vmmon_run_identity) = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let pid_path = runtime.machine_paths(config.id).vmmon_pid_path();
            let previous_state = runtime.machine_state(config.id).await?;
            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            if matches!(
                status.state,
                MachineRuntimeState::Stopped | MachineRuntimeState::Error
            ) {
                if previous_state.status == MachineRuntimeState::Stopping {
                    runtime.cleanup_machine_resources_locked(&config).await?;
                    return runtime.machine_inspect_data(config).await;
                }

                return Err(LibVmError::MachineNotRunning {
                    reference: config.name.clone(),
                });
            }

            match status.pid {
                Some(pid) if status.state == MachineRuntimeState::Stopping => {
                    let generation = VmmonRunIdentity {
                        pid,
                        started_at: Some(
                            status
                                .started_at
                                .unwrap_or_else(|| pid_file_mtime(&pid_path)),
                        ),
                        run_id: status.run_id.clone(),
                    };
                    runtime.request_machine_stop(config.id, &generation).await?;
                    (config, Some(generation))
                }
                Some(pid) => {
                    if interrupt_monitor(pid)? {
                        let generation = VmmonRunIdentity {
                            pid,
                            started_at: Some(
                                status
                                    .started_at
                                    .unwrap_or_else(|| pid_file_mtime(&pid_path)),
                            ),
                            run_id: status.run_id.clone(),
                        };
                        runtime.request_machine_stop(config.id, &generation).await?;

                        (config, Some(generation))
                    } else {
                        runtime.mark_machine_stopped(config.id, None).await?;
                        runtime.cleanup_machine_resources_locked(&config).await?;
                        (config, None)
                    }
                }
                None => {
                    runtime.mark_machine_stopped(config.id, None).await?;
                    runtime.cleanup_machine_resources_locked(&config).await?;
                    (config, None)
                }
            }
        };

        if let Some(generation) = vmmon_run_identity {
            wait_for_monitor_stop(&generation, &config.name).await?;
            {
                let (_lock, _) = runtime.lock_machine_config(config.id).await?;
                runtime
                    .complete_stop_locked(&config, generation, None)
                    .await?;
            }
        }
        runtime.machine_inspect_data(config).await
    }

    /// Cleans host resources associated with a stopped machine.
    ///
    /// This is safe to call repeatedly. If the machine is still active, cleanup
    /// leaves it alone and returns the current inspect data.
    pub async fn cleanup(&self) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return runtime.machine_inspect_data(config).await;
        }

        if status.state == MachineRuntimeState::Stopping {
            runtime.mark_machine_stopped(config.id, None).await?;
        }

        runtime.cleanup_machine_resources_locked(&config).await?;
        runtime.machine_inspect_data(config).await
    }

    /// Removes the persistent machine record and files.
    pub async fn remove(self) -> Result<(), LibVmError> {
        let runtime = self.runtime();
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        runtime
            .reconcile_machine_network(&config, status.is_active())
            .await?;

        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }

        match fs::remove_dir_all(&config.instance_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }

        runtime.remove_machine_records(&config).await
    }
}
