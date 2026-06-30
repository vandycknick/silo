use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::{sleep, Instant};
use uuid::Uuid;

use crate::machine::{
    Machine, MachineData, MachineExit, MachineExitOutcome, MachineKillOptions, MachineStartOptions,
    MachineStopOptions, MachineWaitOptions,
};
use crate::runtime::core::{
    interrupt_monitor, kill_monitor_process_group, monitor_started_at, pid_file_mtime,
    read_monitor_pid, reconcile_root_disk_size, wait_for_monitor_stop, VmmonRunIdentity,
};
use crate::store::models::{MachineConfig, MachineRuntimeState};
use crate::vmmon::exit_status::{self, VmmonExitOutcome, VmmonExitStatus};
use crate::vmmon::VmmonLaunch;
use crate::LibVmError;

const WAIT_TARGET_POLL_INTERVAL: Duration = Duration::from_millis(200);

struct WaitTarget {
    config: MachineConfig,
    generation: VmmonRunIdentity,
    stop_requested: bool,
    forced: bool,
}

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
            runtime.prepare_vmmon_launch_inputs(&config, &resolved_network)?;

            runtime.request_machine_start(config.id, &run_id).await?;

            let launch = VmmonLaunch {
                machine_id: config.id,
                name: &config.name,
                machine_dir: &config.machine_dir,
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
            if let Err(err) = vmmon.spawn(&launch).await {
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
        self.stop_with(MachineStopOptions::default()).await
    }

    /// Stops the machine with explicit stop options.
    pub async fn stop_with(&self, options: MachineStopOptions) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let wait_target = {
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
                    WaitTarget {
                        config,
                        generation,
                        stop_requested: true,
                        forced: false,
                    }
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

                        WaitTarget {
                            config,
                            generation,
                            stop_requested: true,
                            forced: false,
                        }
                    } else {
                        runtime.mark_machine_stopped(config.id, None).await?;
                        runtime.cleanup_machine_resources_locked(&config).await?;
                        return runtime.machine_inspect_data(config).await;
                    }
                }
                None => {
                    runtime.mark_machine_stopped(config.id, None).await?;
                    runtime.cleanup_machine_resources_locked(&config).await?;
                    return runtime.machine_inspect_data(config).await;
                }
            }
        };

        self.wait_for_target_exit(wait_target, options.wait_options())
            .await
            .map(|exit| exit.machine)
    }

    /// Waits for the current machine run to exit without sending a stop signal.
    pub async fn wait(&self) -> Result<MachineExit, LibVmError> {
        self.wait_with(MachineWaitOptions::default()).await
    }

    /// Waits for the current machine run with explicit wait options.
    pub async fn wait_with(&self, options: MachineWaitOptions) -> Result<MachineExit, LibVmError> {
        let deadline = Instant::now()
            .checked_add(options.timeout_value())
            .unwrap_or_else(Instant::now);

        loop {
            if let Some(wait_target) = self.active_wait_target().await? {
                let remaining = deadline.saturating_duration_since(Instant::now());
                return self
                    .wait_for_target_exit(wait_target, MachineWaitOptions::new().timeout(remaining))
                    .await;
            }

            let runtime = self.runtime();
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            let machine = runtime.machine_inspect_data(config).await?;
            if !status.is_active() {
                return Ok(MachineExit::already_stopped(machine));
            }

            let now = Instant::now();
            if now >= deadline {
                return Ok(MachineExit {
                    machine,
                    run_id: status.run_id,
                    exited_at: None,
                    outcome: MachineExitOutcome::Unknown,
                });
            }

            sleep(std::cmp::min(
                WAIT_TARGET_POLL_INTERVAL,
                deadline.saturating_duration_since(now),
            ))
            .await;
        }
    }

    /// Forcefully stops the machine and waits for the monitor to exit.
    pub async fn kill(&self) -> Result<MachineExit, LibVmError> {
        self.kill_with(MachineKillOptions::default()).await
    }

    /// Forcefully stops the machine with explicit kill options.
    pub async fn kill_with(&self, options: MachineKillOptions) -> Result<MachineExit, LibVmError> {
        let runtime = self.runtime();
        let wait_target = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let pid_path = runtime.machine_paths(config.id).vmmon_pid_path();
            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            if matches!(
                status.state,
                MachineRuntimeState::Stopped | MachineRuntimeState::Error
            ) {
                return Err(LibVmError::MachineNotRunning {
                    reference: config.name.clone(),
                });
            }

            let Some(pid) = status.pid else {
                runtime.mark_machine_stopped(config.id, None).await?;
                runtime.cleanup_machine_resources_locked(&config).await?;
                let machine = runtime.machine_inspect_data(config).await?;
                return Ok(MachineExit {
                    machine,
                    run_id: status.run_id,
                    exited_at: None,
                    outcome: MachineExitOutcome::Unknown,
                });
            };

            let generation = VmmonRunIdentity {
                pid,
                started_at: Some(
                    status
                        .started_at
                        .unwrap_or_else(|| pid_file_mtime(&pid_path)),
                ),
                run_id: status.run_id.clone(),
            };
            if !kill_monitor_process_group(pid)? {
                runtime.mark_machine_stopped(config.id, None).await?;
                runtime.cleanup_machine_resources_locked(&config).await?;
                let exit_status =
                    exit_status::read(&runtime.machine_paths(config.id).vmmon_exit_status_path())?;
                let machine = runtime.machine_inspect_data(config).await?;
                return Ok(machine_exit(machine, generation, false, exit_status));
            }
            runtime.request_machine_stop(config.id, &generation).await?;

            WaitTarget {
                config,
                generation,
                stop_requested: true,
                forced: true,
            }
        };

        self.wait_for_target_exit(wait_target, options.wait_options())
            .await
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

        match fs::remove_dir_all(&config.machine_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }

        runtime.remove_machine_records(&config).await
    }
}

impl Machine {
    async fn active_wait_target(&self) -> Result<Option<WaitTarget>, LibVmError> {
        let runtime = self.runtime();
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        let state = runtime.machine_state(config.id).await?;
        let stored_target = if matches!(
            state.status,
            MachineRuntimeState::Starting
                | MachineRuntimeState::Running
                | MachineRuntimeState::Stopping
        ) {
            state.vmmon_pid.map(|pid| {
                let pid_path = runtime.machine_paths(config.id).vmmon_pid_path();
                WaitTarget {
                    config: config.clone(),
                    generation: VmmonRunIdentity {
                        pid,
                        started_at: Some(
                            state
                                .started_at
                                .unwrap_or_else(|| pid_file_mtime(&pid_path)),
                        ),
                        run_id: state.run_id.clone(),
                    },
                    stop_requested: false,
                    forced: false,
                }
            })
        } else {
            None
        };

        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if !status.is_active() {
            return Ok(stored_target);
        }

        let Some(pid) = status.pid else {
            return Ok(None);
        };

        let pid_path = runtime.machine_paths(config.id).vmmon_pid_path();
        let generation = VmmonRunIdentity {
            pid,
            started_at: Some(
                status
                    .started_at
                    .unwrap_or_else(|| pid_file_mtime(&pid_path)),
            ),
            run_id: status.run_id.clone(),
        };
        Ok(Some(WaitTarget {
            config,
            generation,
            stop_requested: false,
            forced: false,
        }))
    }

    async fn wait_for_target_exit(
        &self,
        target: WaitTarget,
        options: MachineWaitOptions,
    ) -> Result<MachineExit, LibVmError> {
        let runtime = self.runtime();
        wait_for_monitor_stop(
            &target.generation,
            &target.config.name,
            options.timeout_value(),
        )
        .await?;
        {
            let (_lock, _) = runtime.lock_machine_config(target.config.id).await?;
            if target.stop_requested {
                runtime
                    .complete_stop_locked(&target.config, target.generation.clone(), None)
                    .await?;
            } else {
                let status = runtime
                    .reconcile_machine_runtime_locked(&target.config)
                    .await?;
                if !status.is_active() {
                    runtime
                        .cleanup_machine_resources_locked(&target.config)
                        .await?;
                }
            }
        }

        let exit_status = exit_status::read(
            &runtime
                .machine_paths(target.config.id)
                .vmmon_exit_status_path(),
        )?;
        let machine = runtime.machine_inspect_data(target.config).await?;
        Ok(machine_exit(
            machine,
            target.generation,
            target.forced,
            exit_status,
        ))
    }
}

fn machine_exit(
    machine: MachineData,
    generation: VmmonRunIdentity,
    forced: bool,
    exit_status: Option<VmmonExitStatus>,
) -> MachineExit {
    let matching_exit =
        exit_status.filter(|status| exit_status_matches_generation(status, &generation));
    let (exited_at, outcome) = match matching_exit {
        Some(status) => (
            unix_time(status.exited_at),
            match status.outcome {
                VmmonExitOutcome::Clean => MachineExitOutcome::Clean,
                VmmonExitOutcome::Error => MachineExitOutcome::Error {
                    message: status.error,
                },
            },
        ),
        None if forced => (None, MachineExitOutcome::Forced),
        None => (None, MachineExitOutcome::Unknown),
    };

    MachineExit {
        machine,
        run_id: generation.run_id,
        exited_at,
        outcome,
    }
}

fn exit_status_matches_generation(status: &VmmonExitStatus, generation: &VmmonRunIdentity) -> bool {
    if let Some(run_id) = status.run_id.as_deref() {
        return generation.run_id.as_deref() == Some(run_id);
    }

    match status.pid {
        Some(pid) => generation.pid == pid,
        None => true,
    }
}

fn unix_time(timestamp: i64) -> Option<SystemTime> {
    let timestamp = u64::try_from(timestamp).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(timestamp))
}
