use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::{
    errno::Errno,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use tokio::time::{sleep, Instant};
use uuid::Uuid;

use crate::lock_manager::MachineLifetimeLock;
use crate::machine::root_disk::RootDiskResizeOutcome;
use crate::machine::{
    Machine, MachineData, MachineExit, MachineExitOutcome, MachineKillOptions, MachineRunId,
    MachineStart, MachineStartOptions, MachineStopOptions, MachineWaitOptions,
};
use crate::runtime::core::{
    interrupt_monitor, kill_monitor_process_group, monitor_identity as monitor_identity_for_pid,
    read_monitor_pid, reconcile_root_disk_size, wait_for_monitor_stop, VmmonRunIdentity,
};
use crate::runtime::Runtime;
use crate::store::models::{MachineConfig, MachineRuntimeState};
use crate::vmmon::exit_status::{self, VmmonExitOutcome, VmmonExitStatus};
use crate::vmmon::process::ProcessIdentity;
use crate::vmmon::VmmonLaunch;
use crate::LibVmError;

const WAIT_TARGET_POLL_INTERVAL: Duration = Duration::from_millis(200);

struct WaitTarget {
    config: MachineConfig,
    generation: VmmonRunIdentity,
    identity: ProcessIdentity,
    stop_requested: bool,
    forced: bool,
}

#[derive(Clone, Copy)]
enum FailedStartState {
    Stopped,
    Error,
}

impl Machine {
    /// Starts the machine and returns its acknowledged generation and snapshot.
    pub async fn start(&self) -> Result<MachineStart, LibVmError> {
        self.start_with_options(MachineStartOptions::default())
            .await
    }

    /// Starts the machine with explicit start options.
    pub async fn start_with<F>(&self, configure: F) -> Result<MachineStart, LibVmError>
    where
        F: FnOnce(MachineStartOptions) -> MachineStartOptions,
    {
        self.start_with_options(configure(MachineStartOptions::default()))
            .await
    }

    /// Starts the machine with prebuilt start options.
    pub async fn start_with_options(
        &self,
        options: MachineStartOptions,
    ) -> Result<MachineStart, LibVmError> {
        let runtime = self.runtime();
        let vmmon = runtime.vmmon();
        let (config, run_id) = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            runtime.validate_machine_data_dir(&config)?;
            let machine_paths = runtime.machine_paths(config.id);
            let pid_path = machine_paths.vmmon_pid_path();
            let exit_status_path = machine_paths.vmmon_exit_status_path();
            let config_path = machine_paths.vm_spec_path();
            let socket_path = machine_paths.vmmon_socket_path();
            let trace_path = machine_paths.vm_trace_log_path();
            let serial_log_path = machine_paths.serial_log_path();

            runtime.ensure_machine_runtime_directories(config.id)?;
            let lifetime_lock = MachineLifetimeLock::try_acquire(&machine_paths.vmmon_lock_path())?
                .ok_or_else(|| LibVmError::MachineAlreadyRunning {
                    reference: config.name.clone(),
                })?;

            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            runtime
                .reconcile_machine_network(&config, status.is_active())
                .await?;

            if status.is_active() {
                return Err(LibVmError::MachineAlreadyRunning {
                    reference: config.name.clone(),
                });
            }

            let run_uuid = Uuid::new_v4();
            let run_id = run_uuid.to_string();

            runtime.request_machine_start(&config, &run_id).await?;
            let root_disk_resize = match (|| {
                options.validate_egress_credentials(&config.network, &config.name)?;
                reconcile_root_disk_size(&config)
            })() {
                Ok(outcome) => outcome,
                Err(error) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Stopped),
                        None,
                        error,
                    )
                    .await);
                }
            };

            let resolved_network = match runtime
                .prepare_machine_network(&config, &run_id, &options.egress_credentials)
                .await
            {
                Ok(network) => network,
                Err(error) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Stopped),
                        None,
                        error,
                    )
                    .await);
                }
            };
            let agent_enabled = match runtime.prepare_vmmon_launch_inputs(
                &config,
                &resolved_network,
                root_disk_resize == RootDiskResizeOutcome::GuestRequired,
            ) {
                Ok(agent_enabled) => agent_enabled,
                Err(err) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Stopped),
                        None,
                        err,
                    )
                    .await);
                }
            };
            if options.entrypoint.is_some() && !agent_enabled {
                let error = LibVmError::MachinePreparationFailed {
                    reference: config.name.clone(),
                    message: "an entrypoint requires the managed guest agent".to_string(),
                };
                return Err(finish_failed_start(
                    runtime,
                    &config,
                    &run_id,
                    Some(FailedStartState::Stopped),
                    None,
                    error,
                )
                .await);
            }
            let machine_log_dir = match runtime.local_paths().machine_logs_directory(config.id) {
                Ok(directory) => directory,
                Err(error) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Stopped),
                        None,
                        error,
                    )
                    .await)
                }
            };
            let startup_command = options.vmmon_startup_command();

            let launch = VmmonLaunch {
                machine_id: config.id,
                name: &config.name,
                machine_dir: &config.machine_dir,
                machine_runtime_dir: machine_paths.machine_run_dir(),
                pidfile: &pid_path,
                exit_status: &exit_status_path,
                config: &config_path,
                socket: &socket_path,
                serial_log: &serial_log_path,
                trace_log: &trace_path,
                network: &resolved_network,
                run_id: &run_id,
                exit_command: options.on_exit.as_ref(),
                agent_enabled,
                startup_command: startup_command.as_ref(),
                machine_log_dir: &machine_log_dir,
                machine_lock: &lifetime_lock,
            };
            if let Err(err) = vmmon.spawn(&launch).await {
                return Err(finish_failed_start(
                    runtime,
                    &config,
                    &run_id,
                    Some(FailedStartState::Stopped),
                    None,
                    err,
                )
                .await);
            }

            let pid = match read_monitor_pid(&pid_path) {
                Ok(pid) => pid,
                Err(err) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Error),
                        None,
                        err.into(),
                    )
                    .await);
                }
            };
            let monitor = match monitor_identity_for_pid(pid, &pid_path, &config.name) {
                Ok(monitor) => monitor,
                Err(err) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Error),
                        None,
                        err,
                    )
                    .await);
                }
            };
            let Some(started_at) = monitor.started_at() else {
                return Err(finish_failed_start(
                    runtime,
                    &config,
                    &run_id,
                    Some(FailedStartState::Error),
                    Some(&monitor),
                    LibVmError::MonitorConnection {
                        reference: config.name.clone(),
                        message: format!(
                            "vmmon pid {pid} from {} has no stable process generation",
                            pid_path.display()
                        ),
                    },
                )
                .await);
            };
            if let Err(err) = runtime
                .mark_machine_monitor_ready(config.id, run_id.clone(), pid, started_at)
                .await
            {
                return Err(finish_failed_start(
                    runtime,
                    &config,
                    &run_id,
                    Some(FailedStartState::Error),
                    Some(&monitor),
                    err,
                )
                .await);
            }

            (config, MachineRunId::from_raw(run_id))
        };
        Ok(MachineStart {
            machine: runtime.machine_inspect_data(config).await?,
            run_id,
        })
    }

    /// Stops the machine and returns its updated inspect data.
    pub async fn stop(&self) -> Result<MachineData, LibVmError> {
        self.stop_impl(None, MachineStopOptions::default()).await
    }

    /// Stops the machine with explicit stop options.
    pub async fn stop_with(&self, options: MachineStopOptions) -> Result<MachineData, LibVmError> {
        self.stop_impl(None, options).await
    }

    /// Stops this exact machine run without affecting a replacement run.
    pub async fn stop_run(&self, run_id: MachineRunId) -> Result<MachineData, LibVmError> {
        self.stop_impl(Some(&run_id), MachineStopOptions::default())
            .await
    }

    /// Stops this exact machine run with explicit stop options.
    pub async fn stop_run_with(
        &self,
        run_id: MachineRunId,
        options: MachineStopOptions,
    ) -> Result<MachineData, LibVmError> {
        self.stop_impl(Some(&run_id), options).await
    }

    async fn stop_impl(
        &self,
        expected_run_id: Option<&MachineRunId>,
        options: MachineStopOptions,
    ) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let wait_target = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            require_current_run(&config, &status, expected_run_id)?;
            if matches!(
                status.state,
                MachineRuntimeState::Stopped | MachineRuntimeState::Error
            ) {
                runtime.cleanup_machine_resources_locked(&config).await?;
                return runtime.machine_inspect_data(config).await;
            }

            match status.pid {
                Some(pid) if status.state == MachineRuntimeState::Stopping => {
                    let generation = VmmonRunIdentity {
                        pid,
                        started_at: status.started_at,
                        run_id: status.run_id.clone(),
                    };
                    let Some(identity) = monitor_identity(&generation)? else {
                        runtime.mark_machine_stopped(config.id, None).await?;
                        runtime.cleanup_machine_resources_locked(&config).await?;
                        return runtime.machine_inspect_data(config).await;
                    };
                    runtime.request_machine_stop(config.id, &generation).await?;
                    WaitTarget {
                        config,
                        generation,
                        identity,
                        stop_requested: true,
                        forced: false,
                    }
                }
                Some(pid) => {
                    let generation = VmmonRunIdentity {
                        pid,
                        started_at: status.started_at,
                        run_id: status.run_id.clone(),
                    };
                    let Some(identity) = monitor_identity(&generation)? else {
                        runtime.mark_machine_stopped(config.id, None).await?;
                        runtime.cleanup_machine_resources_locked(&config).await?;
                        return runtime.machine_inspect_data(config).await;
                    };
                    if !interrupt_monitor(&identity)? {
                        runtime.mark_machine_stopped(config.id, None).await?;
                        runtime.cleanup_machine_resources_locked(&config).await?;
                        return runtime.machine_inspect_data(config).await;
                    }
                    runtime.request_machine_stop(config.id, &generation).await?;

                    WaitTarget {
                        config,
                        generation,
                        identity,
                        stop_requested: true,
                        forced: false,
                    }
                }
                None => {
                    runtime.mark_machine_stopped(config.id, None).await?;
                    runtime.cleanup_machine_resources_locked(&config).await?;
                    return runtime.machine_inspect_data(config).await;
                }
            }
        };

        self.wait_for_target_exit(wait_target, options.wait_options(), expected_run_id)
            .await
            .map(|exit| exit.machine)
    }

    /// Waits for the current machine run to exit without sending a stop signal.
    pub async fn wait(&self) -> Result<MachineExit, LibVmError> {
        self.wait_impl(None, MachineWaitOptions::default()).await
    }

    /// Waits for the current machine run with explicit wait options.
    pub async fn wait_with(&self, options: MachineWaitOptions) -> Result<MachineExit, LibVmError> {
        self.wait_impl(None, options).await
    }

    /// Waits for this exact machine run without observing a replacement run.
    pub async fn wait_for_run(&self, run_id: MachineRunId) -> Result<MachineExit, LibVmError> {
        self.wait_impl(Some(&run_id), MachineWaitOptions::default())
            .await
    }

    /// Waits for this exact machine run with explicit wait options.
    pub async fn wait_for_run_with(
        &self,
        run_id: MachineRunId,
        options: MachineWaitOptions,
    ) -> Result<MachineExit, LibVmError> {
        self.wait_impl(Some(&run_id), options).await
    }

    async fn wait_impl(
        &self,
        expected_run_id: Option<&MachineRunId>,
        options: MachineWaitOptions,
    ) -> Result<MachineExit, LibVmError> {
        let deadline = Instant::now()
            .checked_add(options.timeout_value())
            .unwrap_or_else(Instant::now);

        loop {
            if let Some(wait_target) = self.active_wait_target(expected_run_id).await? {
                let remaining = deadline.saturating_duration_since(Instant::now());
                return self
                    .wait_for_target_exit(
                        wait_target,
                        MachineWaitOptions::new().timeout(remaining),
                        expected_run_id,
                    )
                    .await;
            }

            let runtime = self.runtime();
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            if !status.is_active() {
                return Ok(MachineExit::already_stopped(
                    runtime.machine_inspect_data(config).await?,
                ));
            }
            require_current_run(&config, &status, expected_run_id)?;
            let machine = runtime.machine_inspect_data(config).await?;

            let now = Instant::now();
            if now >= deadline {
                return Ok(MachineExit {
                    machine,
                    run_id: status.run_id.map(MachineRunId::from_raw),
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
        self.kill_impl(None, MachineKillOptions::default()).await
    }

    /// Forcefully stops the machine with explicit kill options.
    pub async fn kill_with(&self, options: MachineKillOptions) -> Result<MachineExit, LibVmError> {
        self.kill_impl(None, options).await
    }

    /// Forcefully stops this exact machine run without affecting a replacement run.
    pub async fn kill_run(&self, run_id: MachineRunId) -> Result<MachineExit, LibVmError> {
        self.kill_impl(Some(&run_id), MachineKillOptions::default())
            .await
    }

    /// Forcefully stops this exact machine run with explicit kill options.
    pub async fn kill_run_with(
        &self,
        run_id: MachineRunId,
        options: MachineKillOptions,
    ) -> Result<MachineExit, LibVmError> {
        self.kill_impl(Some(&run_id), options).await
    }

    async fn kill_impl(
        &self,
        expected_run_id: Option<&MachineRunId>,
        options: MachineKillOptions,
    ) -> Result<MachineExit, LibVmError> {
        let runtime = self.runtime();
        let wait_target = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            require_current_run(&config, &status, expected_run_id)?;
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
                    run_id: status.run_id.map(MachineRunId::from_raw),
                    exited_at: None,
                    outcome: MachineExitOutcome::Unknown,
                });
            };

            let generation = VmmonRunIdentity {
                pid,
                started_at: status.started_at,
                run_id: status.run_id.clone(),
            };
            let Some(identity) = monitor_identity(&generation)? else {
                runtime.mark_machine_stopped(config.id, None).await?;
                runtime.cleanup_machine_resources_locked(&config).await?;
                let exit_status =
                    exit_status::read(&runtime.machine_paths(config.id).vmmon_exit_status_path())?;
                let machine = runtime.machine_inspect_data(config).await?;
                return Ok(machine_exit(machine, generation, false, exit_status));
            };
            if !kill_monitor_process_group(&identity)? {
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
                identity,
                stop_requested: true,
                forced: true,
            }
        };

        self.wait_for_target_exit(wait_target, options.wait_options(), expected_run_id)
            .await
    }

    /// Removes a stopped machine's durable records and files.
    pub async fn remove(self) -> Result<(), LibVmError> {
        self.remove_impl(None).await
    }

    /// Removes a stopped machine only when its latest exit belongs to the
    /// supplied run generation.
    pub async fn remove_after_run(self, run_id: MachineRunId) -> Result<(), LibVmError> {
        self.remove_impl(Some(run_id)).await
    }

    async fn remove_impl(self, expected_run_id: Option<MachineRunId>) -> Result<(), LibVmError> {
        let runtime = self.runtime();
        if runtime.machine_config(self.machine_id()).await?.is_none() {
            return Ok(());
        }
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        runtime.validate_machine_data_dir(&config)?;
        runtime.ensure_no_live_vmmon_generation(&config).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;

        if status.is_active() {
            if let Some(expected_run_id) = expected_run_id.as_ref() {
                require_current_run(&config, &status, Some(expected_run_id))?;
            }
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }

        if let Some(expected_run_id) = expected_run_id {
            let exit_status =
                exit_status::read(&runtime.machine_paths(config.id).vmmon_exit_status_path())?;
            let machine_id = config.id.to_string();
            let current = exit_status
                .as_ref()
                .filter(|exit| exit.machine_id == machine_id)
                .map(|exit| MachineRunId::from_raw(exit.run_id.clone()));
            if current.as_ref() != Some(&expected_run_id) {
                return Err(LibVmError::MachineStaleGeneration {
                    reference: config.name.clone(),
                    requested: expected_run_id,
                    current,
                });
            }
        }

        runtime.cleanup_machine_resources_locked(&config).await?;
        runtime.local_paths().remove_machine_logs_tree(config.id)?;
        runtime.local_paths().remove_machine_data_tree(config.id)?;
        runtime.remove_machine_records(&config).await
    }
}

async fn finish_failed_start(
    runtime: &Runtime,
    config: &MachineConfig,
    run_id: &str,
    start_failure: Option<FailedStartState>,
    monitor: Option<&ProcessIdentity>,
    primary: LibVmError,
) -> LibVmError {
    let primary_message = primary.to_string();
    let mut cleanup_errors = Vec::new();

    let discovered_monitor = if monitor.is_none() {
        match read_monitor_pid(&runtime.machine_paths(config.id).vmmon_pid_path()) {
            Ok(pid) => match ProcessIdentity::for_pid(pid) {
                Ok(identity) => identity,
                Err(err) => {
                    cleanup_errors.push(format!("inspect vmmon for cleanup: {err}"));
                    None
                }
            },
            Err(_) => None,
        }
    } else {
        None
    };
    let monitor_stopped = match monitor.or(discovered_monitor.as_ref()) {
        Some(monitor) => match stop_failed_start_monitor(monitor, &config.name).await {
            Ok(()) => true,
            Err(err) => {
                cleanup_errors.push(format!("terminate vmmon: {err}"));
                false
            }
        },
        None => true,
    };
    if monitor_stopped {
        if let Err(err) = runtime.reconcile_machine_network(config, false).await {
            cleanup_errors.push(format!("reconcile prepared network: {err}"));
        }
    }
    let mut terminal_transitioned = false;
    if monitor_stopped {
        if let Some(start_failure) = start_failure {
            let result = match start_failure {
                FailedStartState::Stopped => {
                    runtime
                        .mark_machine_start_stopped(
                            config.id,
                            run_id,
                            Some(primary_message.clone()),
                        )
                        .await
                }
                FailedStartState::Error => {
                    runtime
                        .mark_machine_start_error(config.id, run_id, Some(primary_message.clone()))
                        .await
                }
            };
            match result {
                Ok(()) => terminal_transitioned = true,
                Err(err) => cleanup_errors.push(format!("record failed start: {err}")),
            }
        }
    }
    if terminal_transitioned && config.retention == crate::MachineRetention::Ephemeral {
        let _: Result<(), LibVmError> = async {
            runtime.cleanup_machine_resources_locked(config).await?;
            runtime.local_paths().remove_machine_logs_tree(config.id)?;
            runtime.local_paths().remove_machine_data_tree(config.id)?;
            runtime.remove_machine_records(config).await
        }
        .await;
    }

    if cleanup_errors.is_empty() {
        primary
    } else {
        LibVmError::MachineStartCleanupFailed {
            primary: primary_message,
            cleanup: cleanup_errors.join("; "),
        }
    }
}

async fn stop_failed_start_monitor(
    monitor: &ProcessIdentity,
    machine_name: &str,
) -> Result<(), LibVmError> {
    if kill_monitor_process_group(monitor)? {
        return wait_for_monitor_stop(monitor, machine_name, Duration::from_secs(5)).await;
    }
    if !monitor.is_alive()? {
        return Ok(());
    }
    match kill(Pid::from_raw(monitor.pid()), Some(Signal::SIGKILL)) {
        Ok(()) | Err(Errno::ESRCH) => {
            wait_for_monitor_stop(monitor, machine_name, Duration::from_secs(5)).await
        }
        Err(err) => Err(std::io::Error::other(err.to_string()).into()),
    }
}

impl Machine {
    async fn active_wait_target(
        &self,
        expected_run_id: Option<&MachineRunId>,
    ) -> Result<Option<WaitTarget>, LibVmError> {
        let runtime = self.runtime();
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;

        // vmmon removes its pidfile during shutdown before releasing its lifetime lock and
        // exiting. Preserve the persisted process identity long enough to wait for that final
        // shutdown work instead of reconciling the missing pidfile as an already-stopped run.
        let persisted = runtime.machine_state(config.id).await?;
        if matches!(
            persisted.status,
            MachineRuntimeState::Starting
                | MachineRuntimeState::Running
                | MachineRuntimeState::Stopping
        ) {
            if let Some(pid) = persisted.vmmon_pid {
                let generation = VmmonRunIdentity {
                    pid,
                    started_at: persisted.started_at,
                    run_id: persisted.run_id.clone(),
                };
                if let Some(identity) = monitor_identity(&generation)? {
                    if let Some(expected_run_id) = expected_run_id {
                        if generation.run_id.as_deref() != Some(expected_run_id.as_str()) {
                            return Err(stale_generation(
                                &config,
                                expected_run_id,
                                generation.run_id,
                            ));
                        }
                    }
                    return Ok(Some(WaitTarget {
                        config,
                        generation,
                        identity,
                        stop_requested: false,
                        forced: false,
                    }));
                }
            }
        }

        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if !status.is_active() {
            return Ok(None);
        }
        require_current_run(&config, &status, expected_run_id)?;
        Ok(None)
    }

    async fn wait_for_target_exit(
        &self,
        target: WaitTarget,
        options: MachineWaitOptions,
        expected_run_id: Option<&MachineRunId>,
    ) -> Result<MachineExit, LibVmError> {
        let runtime = self.runtime();
        wait_for_monitor_stop(
            &target.identity,
            &target.config.name,
            options.timeout_value(),
        )
        .await?;
        {
            let (_lock, _) = runtime.lock_machine_config(target.config.id).await?;
            if target.stop_requested {
                let completed = runtime
                    .complete_stop_locked(&target.config, target.generation.clone(), None)
                    .await?;
                if !completed {
                    if let Some(expected_run_id) = expected_run_id {
                        return Err(stale_generation(
                            &target.config,
                            expected_run_id,
                            runtime.machine_state(target.config.id).await?.run_id,
                        ));
                    }
                }
            } else {
                let status = runtime
                    .reconcile_machine_runtime_locked(&target.config)
                    .await?;
                if let Some(expected_run_id) = expected_run_id {
                    if status.is_active()
                        && status.run_id.as_deref() != Some(expected_run_id.as_str())
                    {
                        return Err(stale_generation(
                            &target.config,
                            expected_run_id,
                            status.run_id,
                        ));
                    }
                } else if !status.is_active() {
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
    let matching_exit = exit_status.filter(|status| {
        status.machine_id == machine.id && exit_status_matches_generation(status, &generation)
    });
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
        run_id: generation.run_id.map(MachineRunId::from_raw),
        exited_at,
        outcome,
    }
}

fn require_current_run(
    config: &MachineConfig,
    status: &crate::runtime::core::RuntimeStatus,
    expected_run_id: Option<&MachineRunId>,
) -> Result<(), LibVmError> {
    let Some(expected_run_id) = expected_run_id else {
        return Ok(());
    };
    if status.run_id.as_deref() == Some(expected_run_id.as_str()) {
        return Ok(());
    }
    Err(stale_generation(
        config,
        expected_run_id,
        status.run_id.clone(),
    ))
}

fn stale_generation(
    config: &MachineConfig,
    requested: &MachineRunId,
    current: Option<String>,
) -> LibVmError {
    LibVmError::MachineStaleGeneration {
        reference: config.name.clone(),
        requested: requested.clone(),
        current: current.map(MachineRunId::from_raw),
    }
}

fn exit_status_matches_generation(status: &VmmonExitStatus, generation: &VmmonRunIdentity) -> bool {
    generation.run_id.as_deref() == Some(status.run_id.as_str()) && generation.pid == status.pid
}

fn monitor_identity(generation: &VmmonRunIdentity) -> Result<Option<ProcessIdentity>, LibVmError> {
    let Some(identity) = ProcessIdentity::for_pid(generation.pid)? else {
        return Ok(None);
    };
    if (generation.started_at.is_some() && !identity.matches_started_at(generation.started_at))
        || !identity.is_alive()?
    {
        return Ok(None);
    }
    Ok(Some(identity))
}

fn unix_time(timestamp: i64) -> Option<SystemTime> {
    let timestamp = u64::try_from(timestamp).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(timestamp))
}
