use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::sys::signal::Signal;
use tokio::time::{sleep, Instant};
use uuid::Uuid;

use crate::lock_manager::MachineLifetimeLock;
use crate::machine::root_disk::RootDiskResizeOutcome;
use crate::machine::{
    Machine, MachineData, MachineExit, MachineExitOutcome, MachineKillOptions, MachineRunId,
    MachineStart, MachineStartOptions, MachineStopOptions, MachineWaitOptions,
};
use crate::runtime::core::{
    read_exit_for_reconciliation, reconcile_root_disk_size, wait_for_monitor_stop, VmmRunIdentity,
};
use crate::runtime::Runtime;
use crate::store::models::{MachineConfig, MachineRuntimeState};
use crate::supervisor::exit_status;
use crate::supervisor::process::ProcessIdentity;
use crate::supervisor::VmmLaunch;
use crate::LibVmError;
use protocol::shutdown::{CurrentExitRecord, ExitOutcome, StorageHolderRole};

const WAIT_TARGET_POLL_INTERVAL: Duration = Duration::from_millis(200);

struct WaitTarget {
    config: MachineConfig,
    generation: VmmRunIdentity,
    identity: ProcessIdentity,
    stop_requested: bool,
    forced: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum FailedStartState {
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
        let supervisor = runtime.supervisor();
        let (config, run_id) = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            runtime.validate_machine_data_dir(&config)?;
            if config.image_ref == "execution-restore" {
                return Err(crate::machine::root_storage::invalid(
                    "an execution-restore child cannot cold boot; retry the retained checkpoint under a new restore run",
                ));
            }
            let storage = runtime.validate_machine_storage_for_launch(&config).await?;
            let qualification = runtime.open_machine_boot(&config, &storage)?;
            let _node_state = crate::node_state::acquire(&config).await?;
            let machine_paths = runtime.machine_paths(config.id);
            let pid_path = machine_paths.vmm_pid_path();
            let exit_status_path = machine_paths.vmm_exit_status_path();
            let config_path = machine_paths.vm_spec_path();
            let socket_path = machine_paths.vmm_socket_path();
            let trace_path = machine_paths.vm_trace_log_path();
            let serial_log_path = machine_paths.serial_log_path();

            runtime.ensure_machine_runtime_directories(config.id)?;
            let lifetime_lock = MachineLifetimeLock::try_acquire(&machine_paths.vmm_lock_path())?
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

            let storage_lease = runtime
                .register_launch_storage(&config, run_uuid, &storage)
                .await?;
            runtime.request_machine_start(&config, &run_id).await?;
            let prepared_root = match runtime
                .prepare_machine_root(&config, &storage_lease, qualification)
                .await
            {
                Ok(root) => root,
                Err(error) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Stopped),
                        None,
                        storage_lease,
                        error,
                    )
                    .await);
                }
            };
            let (root_disk_resize, mut secrets) = match (|| {
                let secrets = runtime.resolve_machine_secrets(
                    &config,
                    &run_id,
                    &options.egress_credentials,
                )?;
                let resize = match &storage_lease.storage_record().root {
                    crate::MachineRoot::OpaqueRaw { path, .. } => {
                        reconcile_root_disk_size(&config, path.as_path())?
                    }
                    crate::MachineRoot::LinuxOverlay { .. } => {
                        RootDiskResizeOutcome::OfflineComplete
                    }
                };
                Ok((resize, secrets))
            })() {
                Ok(outcome) => outcome,
                Err(error) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Stopped),
                        None,
                        storage_lease,
                        error,
                    )
                    .await);
                }
            };

            let resolved_network = match runtime
                .prepare_machine_network(
                    &config,
                    &run_id,
                    &secrets,
                    crate::MachineDurability::Durable,
                )
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
                        storage_lease,
                        error,
                    )
                    .await);
                }
            };
            secrets.infrastructure.clear();
            let launch_inputs = match runtime.prepare_vmm_launch_inputs(
                &config,
                &run_id,
                &resolved_network,
                root_disk_resize == RootDiskResizeOutcome::GuestRequired,
                &secrets,
                &prepared_root,
            ) {
                Ok(inputs) => inputs,
                Err(err) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Stopped),
                        None,
                        storage_lease,
                        err,
                    )
                    .await);
                }
            };
            if options.entrypoint.is_some() && !launch_inputs.agent_enabled {
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
                    storage_lease,
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
                        storage_lease,
                        error,
                    )
                    .await)
                }
            };
            let startup_command = options.vmm_startup_command();
            let (file_device, file_inode) = match storage_lease.file_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Stopped),
                        None,
                        storage_lease,
                        error.into(),
                    )
                    .await)
                }
            };

            let launch = VmmLaunch {
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
                agent_enabled: launch_inputs.agent_enabled,
                rosetta_intent: launch_inputs.rosetta_intent,
                asset_directory: launch_inputs.asset_directory,
                startup_command: startup_command.as_ref(),
                machine_log_dir: &machine_log_dir,
                machine_lock: &lifetime_lock,
                qualification: prepared_root.qualification.as_ref(),
                storage_lease: storage_lease.lock(),
                storage_lease_binding: protocol::shutdown::StorageLeaseBinding {
                    operation_id: storage_lease.operation_id().to_string(),
                    file_device,
                    file_inode,
                },
                storage_shutdown: &launch_inputs.storage_shutdown,
                restore: None,
            };
            if let Err(error) = runtime
                .mark_launch_storage_admitted(storage_lease.operation_id())
                .await
            {
                return Err(finish_failed_start(
                    runtime,
                    &config,
                    &run_id,
                    Some(FailedStartState::Stopped),
                    None,
                    storage_lease,
                    error,
                )
                .await);
            }
            let startup = async {
                launch_inputs.artifacts.sync(&storage_lease)?;
                supervisor.spawn(&launch).await?.wait().await
            };
            if let Err(err) = startup.await {
                return Err(finish_failed_start(
                    runtime,
                    &config,
                    &run_id,
                    Some(FailedStartState::Stopped),
                    None,
                    storage_lease,
                    err,
                )
                .await);
            }

            let monitor = match started_run_monitor(
                runtime,
                &config,
                &run_id,
                storage_lease.operation_id(),
            ) {
                Ok(monitor) => monitor,
                Err(err) => {
                    return Err(finish_failed_start(
                        runtime,
                        &config,
                        &run_id,
                        Some(FailedStartState::Error),
                        None,
                        storage_lease,
                        err,
                    )
                    .await);
                }
            };
            let pid = monitor.pid();
            let Some(started_at) = monitor.started_at() else {
                return Err(finish_failed_start(
                    runtime,
                    &config,
                    &run_id,
                    Some(FailedStartState::Error),
                    Some(&monitor),
                    storage_lease,
                    LibVmError::MonitorConnection {
                        reference: config.name.clone(),
                        message: format!("silo-vmm pid {pid} has no stable process generation"),
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
                    storage_lease,
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
            if status.state == MachineRuntimeState::Stopped
                || (status.state == MachineRuntimeState::Error && status.pid.is_none())
            {
                runtime.cleanup_machine_resources_locked(&config).await?;
                return runtime.machine_inspect_data(config).await;
            }

            match status.pid {
                Some(pid) if status.state == MachineRuntimeState::Stopping => {
                    let generation = VmmRunIdentity {
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
                    let generation = VmmRunIdentity {
                        pid,
                        started_at: status.started_at,
                        run_id: status.run_id.clone(),
                    };
                    let Some(identity) = monitor_identity(&generation)? else {
                        runtime.mark_machine_stopped(config.id, None).await?;
                        runtime.cleanup_machine_resources_locked(&config).await?;
                        return runtime.machine_inspect_data(config).await;
                    };
                    if !identity.signal(Signal::SIGINT)? {
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

        // Capture the generation before releasing control to the wait. Never
        // escalate against whichever run happens to be current after a timeout.
        let run_id = wait_target
            .generation
            .run_id
            .clone()
            .map(MachineRunId::from_raw);
        let result = self
            .wait_for_target_exit(wait_target, options.wait_options(), expected_run_id)
            .await;
        match (result, options.force_timeout(), run_id) {
            (Err(LibVmError::Io(error)), Some(timeout), Some(run_id))
                if error.kind() == std::io::ErrorKind::TimedOut =>
            {
                match self
                    .kill_run_with(run_id.clone(), MachineKillOptions::new().timeout(timeout))
                    .await
                {
                    Ok(exit) => Ok(exit.machine),
                    // The original monitor may have exited between the timed
                    // wait and the generation-checked kill. Reconcile its exit.
                    Err(LibVmError::MachineNotRunning { .. }) => self
                        .wait_for_run_with(run_id, MachineWaitOptions::new().timeout(timeout))
                        .await
                        .map(|exit| exit.machine),
                    Err(error) => Err(error),
                }
            }
            (result, _, _) => result.map(|exit| exit.machine),
        }
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
        let exit = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let status = runtime.reconcile_machine_runtime_locked(&config).await?;
            require_current_run(&config, &status, expected_run_id)?;
            if !status.is_active() {
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

            let generation = VmmRunIdentity {
                pid,
                started_at: status.started_at,
                run_id: status.run_id.clone(),
            };
            let Some(identity) = monitor_identity(&generation)? else {
                runtime.mark_machine_stopped(config.id, None).await?;
                runtime.cleanup_machine_resources_locked(&config).await?;
                let exit_status = read_exit_for_reconciliation(
                    &runtime.machine_paths(config.id).vmm_exit_status_path(),
                );
                let machine = runtime.machine_inspect_data(config).await?;
                return Ok(machine_exit(machine, generation, false, exit_status));
            };
            let stop_deadline = Instant::now() + options.wait_options().timeout_value();
            if !identity.signal_process_group(Signal::SIGKILL)? {
                runtime.mark_machine_stopped(config.id, None).await?;
                runtime.cleanup_machine_resources_locked(&config).await?;
                let exit_status = read_exit_for_reconciliation(
                    &runtime.machine_paths(config.id).vmm_exit_status_path(),
                );
                let machine = runtime.machine_inspect_data(config).await?;
                return Ok(machine_exit(machine, generation, false, exit_status));
            }
            runtime.request_machine_stop(config.id, &generation).await?;

            // SIGKILL prevents the monitor from publishing its own exit record.
            // Keep lifecycle ownership until death is confirmed and its run
            // fence is durable, before another start can replace this generation.
            wait_for_monitor_stop(
                &identity,
                &config.name,
                stop_deadline.saturating_duration_since(Instant::now()),
            )
            .await?;
            let path = runtime.machine_paths(config.id).vmm_exit_status_path();
            let machine_id = uuid::Uuid::from(config.id).to_string();
            let recorded = read_exit_for_reconciliation(&path);
            let mut forced_at = None;
            if !recorded.as_ref().is_some_and(|status| {
                status.machine_id == machine_id
                    && exit_status_matches_generation(status, &generation)
            }) {
                if let Some(run_id) = generation.run_id.as_deref() {
                    forced_at = Some(exit_status::write_forced(
                        &path,
                        &machine_id,
                        run_id,
                        generation.pid,
                    )?);
                }
            }
            loop {
                if runtime
                    .complete_stop_locked(&config, generation.clone(), None)
                    .await?
                {
                    break;
                }
                let now = Instant::now();
                if now >= stop_deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("timed out waiting for machine {:?} storage holders and lease reconciliation after monitor termination", config.name),
                    ).into());
                }
                sleep(std::cmp::min(
                    WAIT_TARGET_POLL_INTERVAL,
                    stop_deadline.saturating_duration_since(now),
                ))
                .await;
            }
            let machine = runtime.machine_inspect_data(config).await?;
            let mut exit = machine_exit(machine, generation, true, recorded);
            if let Some(exited_at) = forced_at {
                exit.exited_at = unix_time(exited_at);
            }
            exit
        };

        Ok(exit)
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
        // Publish every valid seal and settle ended captures before any data
        // deletion; staging lives below the machine data directory.
        crate::machine::live_capture::reconcile_captures(runtime, Some(self.machine_id())).await?;
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        runtime.validate_machine_data_dir(&config)?;
        let storage = runtime.machine_storage_record(config.id).await?;
        storage.ownership.ensure_owned(config.id)?;
        runtime
            .preflight_stopped_generation_locked(&config, &storage)
            .await?;
        let _node_state = crate::node_state::acquire_lock(&config).await?;
        runtime.ensure_no_live_vmm_generation(&config).await?;
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
            let exit_status = read_exit_for_reconciliation(
                &runtime.machine_paths(config.id).vmm_exit_status_path(),
            );
            let machine_id = uuid::Uuid::from(config.id).to_string();
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
        let retained = match runtime.optional_native_store() {
            Some(store) => {
                crate::SnapshotStore::from_store(std::sync::Arc::new(store))
                    .machine_capture_retained(config.id)
                    .await?
            }
            None => false,
        };
        if retained {
            return Err(LibVmError::MachinePreparationFailed {
                reference: config.name.clone(),
                message: "a live capture of this machine is unreconciled or its staging is still leased; reconcile captures before removal".into(),
            });
        }

        runtime.cleanup_machine_resources_locked(&config).await?;
        let scope_error = crate::ssh_ca::delete_scope(runtime.secret_store(), config.id).err();
        if let Some(error) = &scope_error {
            tracing::error!(machine = %config.id, %error, "remove machine secret scope");
        }
        runtime.local_paths().remove_machine_logs_tree(config.id)?;
        runtime.local_paths().remove_machine_data_tree(config.id)?;
        runtime.remove_machine_records(&config).await?;
        if let Some(error) = scope_error {
            return Err(LibVmError::MachinePreparationFailed {
                reference: config.name,
                message: format!("machine removed but secret scope cleanup failed: {error}"),
            });
        }
        Ok(())
    }
}

pub(crate) async fn finish_failed_start(
    runtime: &Runtime,
    config: &MachineConfig,
    run_id: &str,
    start_failure: Option<FailedStartState>,
    monitor: Option<&ProcessIdentity>,
    storage_lease: crate::store::operation_store::LaunchStorageLease,
    primary: LibVmError,
) -> LibVmError {
    let primary_message = primary.to_string();
    let mut cleanup_errors = Vec::new();

    // Only the run-bound holder authorizes a signal. Without it, closed startup
    // pipes cancel a pre-holder monitor and lease reconciliation below waits.
    let discovered_monitor = match monitor {
        Some(_) => Ok(None),
        None => run_monitor_identity(runtime, config, run_id, storage_lease.operation_id()),
    };
    let monitor_stopped = match discovered_monitor {
        Ok(discovered) => match monitor.or(discovered.as_ref()) {
            Some(monitor) => match stop_failed_start_monitor(monitor, &config.name).await {
                Ok(()) => true,
                Err(err) => {
                    cleanup_errors.push(format!("terminate silo-vmm: {err}"));
                    false
                }
            },
            None => true,
        },
        Err(err) => {
            cleanup_errors.push(format!("authenticate silo-vmm for cleanup: {err}"));
            false
        }
    };
    if monitor_stopped && config.image_ref != "execution-restore" {
        if let Err(err) = runtime.reconcile_machine_network(config, false).await {
            cleanup_errors.push(format!("reconcile prepared network: {err}"));
        }
    }
    // Only release the manager's copy after actual startup owner cleanup. A
    // cancelled waiter leaves the durable operation for later reconciliation.
    drop(storage_lease);
    let mut terminal_transitioned = false;
    if monitor_stopped {
        if let Some(start_failure) = start_failure {
            let deadline = Instant::now() + Duration::from_secs(5);
            let result = loop {
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
                            .mark_machine_start_error(
                                config.id,
                                run_id,
                                Some(primary_message.clone()),
                            )
                            .await
                    }
                };
                if !matches!(&result, Err(LibVmError::MachineAlreadyRunning { .. })) {
                    break result;
                }
                let now = Instant::now();
                if now >= deadline {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("timed out waiting for failed-start storage holders and lease reconciliation for {:?}", config.name),
                    ).into());
                }
                sleep(std::cmp::min(
                    WAIT_TARGET_POLL_INTERVAL,
                    deadline.saturating_duration_since(now),
                ))
                .await;
            };
            match result {
                Ok(()) => terminal_transitioned = true,
                Err(err) => cleanup_errors.push(format!("record failed start: {err}")),
            }
        }
    }
    if terminal_transitioned && config.image_ref == "execution-restore" {
        // Monitor death does not certify terminal worker/mapping ownership.
        // Keep the destination reservation until holder/lease reconciliation
        // above has positively retired this exact restore generation.
        if let Err(err) = runtime.reconcile_machine_network(config, false).await {
            cleanup_errors.push(format!("reconcile restored network: {err}"));
        }
    }
    if terminal_transitioned
        && (config.retention == crate::MachineRetention::Ephemeral
            || config.image_ref == "execution-restore")
    {
        if let Err(error) = crate::ssh_ca::delete_scope(runtime.secret_store(), config.id) {
            tracing::error!(machine = %config.id, %error, "delete ephemeral machine secret scope");
            cleanup_errors.push(format!("delete ephemeral machine secret scope: {error}"));
        }
        let cleanup: Result<(), LibVmError> = async {
            runtime.cleanup_machine_resources_locked(config).await?;
            runtime.local_paths().remove_machine_logs_tree(config.id)?;
            runtime.local_paths().remove_machine_data_tree(config.id)?;
            runtime.remove_machine_records(config).await
        }
        .await;
        if let Err(error) = cleanup {
            cleanup_errors.push(format!("remove ephemeral machine: {error}"));
        }
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
    // Let silo-vmm stop/reap its worker and finalize the generation first. The
    // process-group kill below is only the emergency fallback for a stuck owner.
    if monitor.signal(Signal::SIGINT)?
        && wait_for_monitor_stop(monitor, machine_name, Duration::from_secs(75))
            .await
            .is_ok()
    {
        return Ok(());
    }
    if monitor.signal_process_group(Signal::SIGKILL)? || monitor.signal(Signal::SIGKILL)? {
        return wait_for_monitor_stop(monitor, machine_name, Duration::from_secs(5)).await;
    }
    Ok(())
}

/// Resolves the exact monitor of `run_id` from its durable storage holder.
///
/// The pidfile is an unauthenticated number: an earlier generation may have
/// left it, or its process may have exited and the number been reused. The
/// monitor publishes this run-, operation- and birth-bound holder before any
/// worker exists. `None` means no live process carries that identity; a holder
/// of another run names another generation and never authorizes a signal.
fn run_monitor_identity(
    runtime: &Runtime,
    config: &MachineConfig,
    run_id: &str,
    operation_id: Uuid,
) -> Result<Option<ProcessIdentity>, LibVmError> {
    let path = runtime.machine_paths(config.id).vmm_storage_holder_path();
    let Some(record) = crate::supervisor::storage_holder::read(&path)? else {
        return Ok(None);
    };
    if record.machine_id != Uuid::from(config.id).to_string()
        || record.run_id != run_id
        || record.operation_id != operation_id.to_string()
    {
        return Ok(None);
    }
    let invalid = |message: &str| LibVmError::InvalidStorageRecord {
        record: "storage-holder",
        message: message.to_string(),
    };
    let holder = record
        .holders
        .iter()
        .find(|holder| holder.role == StorageHolderRole::Monitor)
        .ok_or_else(|| invalid("holder record has no monitor"))?;
    let pid = i32::try_from(holder.pid).map_err(|_| invalid("invalid monitor holder pid"))?;
    let started_at = i64::try_from(holder.started_at)
        .map_err(|_| invalid("invalid monitor holder start identity"))?;
    let Some(identity) = ProcessIdentity::for_pid(pid)? else {
        return Ok(None);
    };
    // Another birth identity at the recorded number is a reused PID.
    if !identity.matches_started_at(Some(started_at)) {
        return Ok(None);
    }
    Ok(Some(identity))
}

/// The monitor that reported startup must still be this run's holder process.
pub(crate) fn started_run_monitor(
    runtime: &Runtime,
    config: &MachineConfig,
    run_id: &str,
    operation_id: Uuid,
) -> Result<ProcessIdentity, LibVmError> {
    run_monitor_identity(runtime, config, run_id, operation_id)?.ok_or_else(|| {
        LibVmError::MonitorConnection {
            reference: config.name.clone(),
            message: format!(
                "silo-vmm reported startup but no live process matches run {run_id}'s storage holder"
            ),
        }
    })
}

impl Machine {
    async fn active_wait_target(
        &self,
        expected_run_id: Option<&MachineRunId>,
    ) -> Result<Option<WaitTarget>, LibVmError> {
        let runtime = self.runtime();
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;

        // silo-vmm removes its pidfile during shutdown before releasing its lifetime lock and
        // exiting. Preserve the persisted process identity long enough to wait for that final
        // shutdown work instead of reconciling the missing pidfile as an already-stopped run.
        let persisted = runtime.machine_state(config.id).await?;
        if persisted.status.is_live() || persisted.vmm_pid.is_some() {
            if let Some(pid) = persisted.vmm_pid {
                let generation = VmmRunIdentity {
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
                        let current = runtime.machine_state(target.config.id).await?.run_id;
                        if current.as_deref() != Some(expected_run_id.as_str()) {
                            return Err(stale_generation(&target.config, expected_run_id, current));
                        }
                    }
                    return Err(LibVmError::MachineAlreadyRunning {
                        reference: target.config.name.clone(),
                    });
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
                if status.is_active() {
                    return Err(LibVmError::MachineAlreadyRunning {
                        reference: target.config.name.clone(),
                    });
                }
            }
        }

        let exit_status = read_exit_for_reconciliation(
            &runtime
                .machine_paths(target.config.id)
                .vmm_exit_status_path(),
        );
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
    generation: VmmRunIdentity,
    forced: bool,
    exit_status: Option<CurrentExitRecord>,
) -> MachineExit {
    let matching_exit = exit_status.filter(|status| {
        status
            .machine_id
            .parse::<uuid::Uuid>()
            .ok()
            .is_some_and(|id| machine.id.parse::<uuid::Uuid>().ok() == Some(id))
            && exit_status_matches_generation(status, &generation)
    });
    let (exited_at, outcome) = match matching_exit {
        Some(status) => (
            unix_time(status.exited_at),
            match status.outcome {
                ExitOutcome::Clean => MachineExitOutcome::Clean,
                ExitOutcome::Forced => MachineExitOutcome::Forced,
                ExitOutcome::Error => MachineExitOutcome::Error {
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

fn exit_status_matches_generation(status: &CurrentExitRecord, generation: &VmmRunIdentity) -> bool {
    generation.run_id.as_deref() == Some(status.run_id.as_str()) && generation.pid == status.pid
}

fn monitor_identity(generation: &VmmRunIdentity) -> Result<Option<ProcessIdentity>, LibVmError> {
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

#[cfg(test)]
mod tests {
    use crate::machine::lifecycle::{
        finish_failed_start, stop_failed_start_monitor, FailedStartState,
    };
    use crate::runtime::Runtime;
    use crate::store::models::{MachineConfig, MachineRuntimeState};
    use crate::store::operation_store::LaunchStorageLease;
    use crate::store::{MachineStore, Store};
    use crate::supervisor::process::ProcessIdentity;
    use crate::LibVmError;
    use protocol::shutdown::{StorageHolder, StorageHolderRecord, StorageHolderRole};
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const MONITOR_HOLDER_ENV: &str = "SILO_LIBVM_FAILED_START_MONITOR_HOLDER";
    const MONITOR_MACHINE_ENV: &str = "SILO_LIBVM_FAILED_START_MONITOR_MACHINE";
    const MONITOR_RUN_ENV: &str = "SILO_LIBVM_FAILED_START_MONITOR_RUN";
    const MONITOR_OPERATION_ENV: &str = "SILO_LIBVM_FAILED_START_MONITOR_OPERATION";
    const MONITOR_WORKER_ENV: &str = "SILO_LIBVM_FAILED_START_MONITOR_WORKER";

    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    async fn admitted_start(
        temp: &tempfile::TempDir,
    ) -> (Runtime, MachineConfig, String, LaunchStorageLease) {
        let (runtime, config, storage) =
            crate::runtime::core::tests::shutdown_storage_fixture(temp).await;
        let run = uuid::Uuid::new_v4();
        let run_id = run.to_string();
        let lease = runtime
            .register_launch_storage(&config, run, &storage)
            .await
            .unwrap();
        runtime
            .request_machine_start(&config, &run_id)
            .await
            .unwrap();
        runtime
            .mark_launch_storage_admitted(lease.operation_id())
            .await
            .unwrap();
        (runtime, config, run_id, lease)
    }

    /// Keeps the shared lease OFD open across exec in the spawned process.
    fn inherit_lease(command: &mut Command, lease: &LaunchStorageLease) -> OwnedFd {
        let descriptor = lease.lock().duplicate_inheritable().unwrap();
        let raw = descriptor.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                nix::fcntl::fcntl(
                    BorrowedFd::borrow_raw(raw),
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
                )
                .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
                Ok(())
            });
        }
        descriptor
    }

    fn write_holder(
        runtime: &Runtime,
        config: &MachineConfig,
        run_id: &str,
        lease: &LaunchStorageLease,
        holders: Vec<StorageHolder>,
    ) {
        let record = StorageHolderRecord {
            schema_version: 1,
            machine_id: uuid::Uuid::from(config.id).to_string(),
            run_id: run_id.to_string(),
            operation_id: lease.operation_id().to_string(),
            holders,
        };
        let path = runtime.machine_paths(config.id).vmm_storage_holder_path();
        std::fs::write(&path, record.encode().unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A real process outside the launch, standing where a reused PID points.
    fn unrelated_process() -> Child {
        Child(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
                .expect("unrelated process"),
        )
    }

    fn write_stale_pidfile(runtime: &Runtime, config: &MachineConfig, pid: u32) {
        std::fs::write(
            runtime.machine_paths(config.id).vmm_pid_path(),
            format!("{pid}\n"),
        )
        .unwrap();
    }

    /// Cleanup waits for every signaled target to exit, so a process that is
    /// still unreaped afterwards was never signaled by it.
    fn assert_untouched(mut unrelated: Child) {
        assert!(
            unrelated.0.try_wait().unwrap().is_none(),
            "failed-start cleanup signaled a process named only by stale pid evidence"
        );
        unrelated.0.kill().unwrap();
        assert_eq!(
            unrelated.0.wait().unwrap().signal(),
            Some(nix::libc::SIGKILL)
        );
    }

    fn rejected_start(config: &MachineConfig) -> LibVmError {
        LibVmError::MachinePreparationFailed {
            reference: config.name.clone(),
            message: "rejected ELF".into(),
        }
    }

    fn assert_rejected_start(error: &LibVmError) {
        assert!(
            matches!(error, LibVmError::MachinePreparationFailed { message, .. } if message == "rejected ELF"),
            "cleanup must return the unchanged primary failure, got {error}"
        );
    }

    async fn assert_retired(runtime: &Runtime, config: &MachineConfig, state: MachineRuntimeState) {
        assert_eq!(
            runtime.machine_state(config.id).await.unwrap().status,
            state
        );
        let store = Store::open(&runtime.local_paths().state_db_path())
            .await
            .unwrap();
        assert!(store
            .launch_storage_operations(config.id)
            .await
            .unwrap()
            .is_empty());
    }

    fn wait_ready(stdout: std::process::ChildStdout) -> std::process::ChildStdout {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line).expect("read monitor stdout");
            assert!(bytes > 0, "monitor exited before reporting readiness");
            if line.trim() == "SILO_READY" {
                return reader.into_inner();
            }
        }
    }

    /// Re-executes this test binary as a monitor of the admitted run. It holds
    /// the inherited lease, optionally starts a lease-holding worker that exits
    /// when the monitor's pipe closes, and publishes its own run-bound holder
    /// before reporting readiness, in the order silo-vmm uses.
    fn spawn_holder_monitor(
        runtime: &Runtime,
        config: &MachineConfig,
        run_id: &str,
        lease: &LaunchStorageLease,
        with_worker: bool,
    ) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "machine::lifecycle::tests::failed_start_monitor_child_process",
                "--nocapture",
            ])
            .env(
                MONITOR_HOLDER_ENV,
                runtime.machine_paths(config.id).vmm_storage_holder_path(),
            )
            .env(MONITOR_MACHINE_ENV, uuid::Uuid::from(config.id).to_string())
            .env(MONITOR_RUN_ENV, run_id)
            .env(MONITOR_OPERATION_ENV, lease.operation_id().to_string())
            .process_group(0)
            .stdout(Stdio::piped());
        if with_worker {
            command.env(MONITOR_WORKER_ENV, "1");
        }
        let descriptor = inherit_lease(&mut command, lease);
        let mut monitor = Child(command.spawn().unwrap());
        drop(descriptor);
        monitor.0.stdout = Some(wait_ready(monitor.0.stdout.take().unwrap()));
        monitor
    }

    #[test]
    fn failed_start_monitor_child_process() {
        let Some(holder_path) = std::env::var_os(MONITOR_HOLDER_ENV) else {
            return;
        };
        let binding = |name: &str| std::env::var(name).expect("monitor run binding");
        let holder = |role, pid: u32| StorageHolder {
            role,
            pid,
            started_at: utils::process::start_time(pid as i32)
                .unwrap()
                .and_then(|started| u64::try_from(started).ok())
                .unwrap(),
        };
        let mut holders = vec![holder(StorageHolderRole::Monitor, std::process::id())];
        // Like a krun worker's watchdog, EOF on the monitor-held pipe ends it.
        let worker = std::env::var_os(MONITOR_WORKER_ENV).map(|_| {
            Command::new("/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .expect("worker")
        });
        if let Some(worker) = &worker {
            holders.push(holder(StorageHolderRole::KrunWorker, worker.id()));
        }
        let record = StorageHolderRecord {
            schema_version: 1,
            machine_id: binding(MONITOR_MACHINE_ENV),
            run_id: binding(MONITOR_RUN_ENV),
            operation_id: binding(MONITOR_OPERATION_ENV),
            holders,
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(holder_path)
            .unwrap();
        file.write_all(&record.encode().unwrap()).unwrap();
        file.sync_all().unwrap();
        println!("SILO_READY");
        std::io::stdout().flush().unwrap();
        let _worker = worker;
        loop {
            std::thread::park();
        }
    }

    /// Exercises the restore wait/lock boundary with a re-executed monitor
    /// holding the launch lease, without needing a hypervisor.
    #[tokio::test]
    async fn restore_startup_wait_releases_mutation_lock_and_rejects_superseded_run() {
        for disposition in [
            MachineRuntimeState::Stopping,
            MachineRuntimeState::Running,
            MachineRuntimeState::ActivationFailed,
        ] {
            let replacement = disposition == MachineRuntimeState::Running;
            let temp = tempfile::tempdir().unwrap();
            let (runtime, config, run_id, lease) = admitted_start(&temp).await;
            let mut monitor = spawn_holder_monitor(&runtime, &config, &run_id, &lease, true);
            let identity = ProcessIdentity::for_pid(monitor.0.id() as i32)
                .unwrap()
                .unwrap();
            let started = identity.started_at().unwrap();
            runtime
                .mark_machine_monitor_ready(config.id, run_id.clone(), identity.pid(), started)
                .await
                .unwrap();
            let pending = crate::supervisor::launch::PendingStartup::new(
                monitor.0.stdout.take().unwrap().into(),
                std::time::Instant::now() + Duration::from_secs(10),
                runtime.machine_paths(config.id).vm_trace_log_path(),
            );
            let (lock, _) = runtime.lock_machine_config(config.id).await.unwrap();
            let wait = crate::machine::restore::await_restored_start(
                &runtime,
                config.id,
                uuid::Uuid::parse_str(&run_id).unwrap(),
                lock,
                pending,
            );
            let interrupt = async {
                let (_lock, _) = tokio::time::timeout(
                    Duration::from_secs(2),
                    runtime.lock_machine_config(config.id),
                )
                .await
                .expect("stop must acquire mutation lock before startup completes")
                .unwrap();
                if disposition != MachineRuntimeState::Stopping {
                    let mut state = runtime.machine_state(config.id).await.unwrap();
                    state.status = disposition;
                    if replacement {
                        state.run_id = Some(uuid::Uuid::new_v4().to_string());
                    }
                    runtime
                        .native_store()
                        .unwrap()
                        .save_machine_state(&state)
                        .await
                        .unwrap();
                } else {
                    runtime
                        .request_machine_stop(
                            config.id,
                            &crate::runtime::core::VmmRunIdentity {
                                pid: identity.pid(),
                                started_at: Some(started),
                                run_id: Some(run_id.clone()),
                            },
                        )
                        .await
                        .unwrap();
                }
                assert!(identity.signal(nix::sys::signal::Signal::SIGINT).unwrap());
            };
            let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(wait, interrupt)
            })
            .await
            .expect("monitor death must unblock startup without its original deadline");
            if replacement {
                assert!(matches!(
                    result,
                    Err(LibVmError::MachineStaleGeneration { .. })
                ));
            } else if disposition == MachineRuntimeState::ActivationFailed {
                let Ok((_lock, _, startup)) = result else {
                    panic!("exact failed activation must retain cleanup authority");
                };
                assert!(startup.is_err());
            } else {
                assert!(result.is_err());
                assert_eq!(
                    runtime.machine_state(config.id).await.unwrap().status,
                    MachineRuntimeState::Stopping,
                );
            }
            assert_eq!(monitor.0.wait().unwrap().signal(), Some(nix::libc::SIGINT));
            // Stop admission must not retire the manager's construction roots.
            let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir()).unwrap();
            assert!(pool
                .try_exclusive_lease(lease.operation_id())
                .unwrap()
                .is_none());
        }
    }

    /// Generic OS signal mechanics, not a substitute for a silo-vmm/VM test.
    #[tokio::test]
    async fn failed_start_cleanup_interrupts_before_emergency_group_kill() {
        let mut child = Child(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
                .expect("real OS child"),
        );
        let pid = child.0.id() as i32;
        let identity = ProcessIdentity::for_pid(pid)
            .expect("identity lookup")
            .expect("live child");
        let (cleanup, status) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                stop_failed_start_monitor(&identity, "signal-mechanics"),
                async {
                    loop {
                        if let Some(status) = child.0.try_wait().expect("probe child") {
                            break status;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            )
        })
        .await
        .expect("cooperative cleanup budget");
        cleanup.expect("cooperative cleanup");
        assert_eq!(status.signal(), Some(nix::libc::SIGINT));
    }

    #[tokio::test]
    async fn failed_start_cleanup_never_signals_unrelated_process_from_stale_pid_evidence() {
        // Monitor died before publishing its holder, or published one whose
        // number now belongs to a process with another birth identity.
        for reused_holder in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (runtime, config, run_id, lease) = admitted_start(&temp).await;
            let unrelated = unrelated_process();
            write_stale_pidfile(&runtime, &config, unrelated.0.id());
            if reused_holder {
                let reused = ProcessIdentity::for_pid(unrelated.0.id() as i32)
                    .unwrap()
                    .unwrap();
                let original_birth = u64::try_from(reused.started_at().unwrap())
                    .unwrap()
                    .checked_sub(1)
                    .unwrap();
                write_holder(
                    &runtime,
                    &config,
                    &run_id,
                    &lease,
                    vec![StorageHolder {
                        role: StorageHolderRole::Monitor,
                        pid: unrelated.0.id(),
                        started_at: original_birth,
                    }],
                );
            }
            let error = tokio::time::timeout(
                Duration::from_secs(10),
                finish_failed_start(
                    &runtime,
                    &config,
                    &run_id,
                    Some(FailedStartState::Stopped),
                    None,
                    lease,
                    rejected_start(&config),
                ),
            )
            .await
            .expect("bounded cleanup");
            assert_rejected_start(&error);
            assert_untouched(unrelated);
            assert_retired(&runtime, &config, MachineRuntimeState::Stopped).await;
        }
    }

    #[tokio::test]
    async fn failed_start_cleanup_interrupts_exact_holder_monitor_not_stale_pidfile_process() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, run_id, lease) = admitted_start(&temp).await;
        let unrelated = unrelated_process();
        write_stale_pidfile(&runtime, &config, unrelated.0.id());
        let mut monitor = spawn_holder_monitor(&runtime, &config, &run_id, &lease, false);
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            finish_failed_start(
                &runtime,
                &config,
                &run_id,
                Some(FailedStartState::Error),
                None,
                lease,
                rejected_start(&config),
            ),
        )
        .await
        .expect("bounded cleanup");
        assert_rejected_start(&error);
        assert_eq!(
            monitor.0.wait().unwrap().signal(),
            Some(nix::libc::SIGINT),
            "the authenticated monitor receives the cooperative interrupt"
        );
        assert_untouched(unrelated);
        assert_retired(&runtime, &config, MachineRuntimeState::Error).await;
    }

    #[tokio::test]
    async fn failed_start_after_monitor_death_retires_only_after_genuine_worker_exit() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, run_id, lease) = admitted_start(&temp).await;
        let unrelated = unrelated_process();
        write_stale_pidfile(&runtime, &config, unrelated.0.id());
        let mut monitor = spawn_holder_monitor(&runtime, &config, &run_id, &lease, true);
        let record = crate::supervisor::storage_holder::read(
            &runtime.machine_paths(config.id).vmm_storage_holder_path(),
        )
        .unwrap()
        .unwrap();
        let worker = record
            .holders
            .iter()
            .find(|holder| holder.role == StorageHolderRole::KrunWorker)
            .unwrap();
        let worker = ProcessIdentity::for_pid(worker.pid as i32)
            .unwrap()
            .expect("published worker is live");
        // Abrupt monitor death before readiness; its worker still holds the lease.
        monitor.0.kill().unwrap();
        monitor.0.wait().unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            finish_failed_start(
                &runtime,
                &config,
                &run_id,
                Some(FailedStartState::Error),
                None,
                lease,
                rejected_start(&config),
            ),
        )
        .await
        .expect("bounded cleanup");
        assert_rejected_start(&error);
        assert!(
            !worker.is_alive().unwrap(),
            "retirement requires the genuine worker to have exited"
        );
        assert_untouched(unrelated);
        assert_retired(&runtime, &config, MachineRuntimeState::Error).await;
    }

    #[tokio::test]
    async fn failed_start_waits_for_registered_holder_and_lease_before_recording_terminal_state() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, run_id, lease) = admitted_start(&temp).await;
        let mut command = Command::new("/bin/sleep");
        command.arg("30").process_group(0);
        let descriptor = inherit_lease(&mut command, &lease);
        let mut worker = Child(command.spawn().unwrap());
        drop(descriptor);
        let identity = ProcessIdentity::for_pid(worker.0.id() as i32)
            .unwrap()
            .unwrap();
        write_holder(
            &runtime,
            &config,
            &run_id,
            &lease,
            vec![
                StorageHolder {
                    role: StorageHolderRole::Monitor,
                    pid: i32::MAX as u32,
                    started_at: 1,
                },
                StorageHolder {
                    role: StorageHolderRole::KrunWorker,
                    pid: worker.0.id(),
                    started_at: u64::try_from(identity.started_at().unwrap()).unwrap(),
                },
            ],
        );
        let cleanup = finish_failed_start(
            &runtime,
            &config,
            &run_id,
            Some(FailedStartState::Stopped),
            None,
            lease,
            rejected_start(&config),
        );
        tokio::pin!(cleanup);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut cleanup)
                .await
                .is_err(),
            "failed start must not finish while the actual registered child retains its lease"
        );
        assert_eq!(
            runtime.machine_state(config.id).await.unwrap().status,
            MachineRuntimeState::Starting
        );
        worker.0.kill().unwrap();
        worker.0.wait().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), cleanup)
            .await
            .unwrap();
        assert_rejected_start(&error);
        assert_retired(&runtime, &config, MachineRuntimeState::Stopped).await;
        assert_eq!(
            runtime
                .machine_storage_record(config.id)
                .await
                .unwrap()
                .stop_outcome,
            crate::StorageStopOutcome::Unknown
        );
    }
}
