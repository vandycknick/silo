//! Same-machine saved execution and storage exclusion (ADR 0023).
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use nix::sys::signal::Signal;
use uuid::Uuid;
use vm_spec::capture::CaptureReleaseDisposition;
use vm_spec::capture::{
    CaptureConfiguration, CaptureDiskCopy, CaptureDiskName, CaptureDiskPlan, CaptureIdentityPolicy,
    CaptureLaunchLease, CaptureMode, CapturePlan, CaptureReadOnlyInput, CaptureReservation,
    DiskIdentityState, HibernateCapturePhase, CAPTURE_RECORD_VERSION, CAPTURE_STATE_RESERVE_BYTES,
};
use vm_spec::hibernate::{HibernateCut, HibernateFileBinding};
use vm_spec::lifecycle::{
    CancelOperationCommand, CaptureCommand, CaptureOutcome, CapturePolicy, CaptureResumePolicy,
    LiveCommand, LiveCommandEnvelope, LiveCommandResult, LiveId, ReleaseCaptureCommand,
};

use crate::machine::live_operations::{envelope, result_error};
use crate::machine::{Machine, MachineData, MachineRef};
use crate::paths::OwnedDirectory;
use crate::storage::hibernate_file::{HibernateFileCheck, HibernateFileKind};
use crate::storage::pool::StoragePool;
use crate::store::hibernate::{
    HibernateBegin, HibernatePhase, HibernatePriorState, HibernateRecord,
};
use crate::store::models::{MachineConfig, MachineRuntimeState};
use crate::store::MachineStore;
use crate::supervisor::process::ProcessIdentity;
use crate::{LibVmError, Runtime};

const POLL: Duration = Duration::from_millis(50);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(240);
const RETIRE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachineHibernationInfo {
    pub hibernated_at: i64,
    pub saved_state_bytes: u64,
    pub memory_capture: vm_spec::capture::HibernateMemoryReceipt,
}

/// Stop completes even when a hibernated guest cannot be shut down cleanly.
#[derive(Debug, Clone)]
pub struct MachineStopOutcome {
    pub machine: MachineData,
    pub warning: Option<MachineStopWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MachineStopWarning {
    #[error("the guest could not be shut down cleanly because its saved state cannot be used ({reason}); the saved state was discarded")]
    SavedStateUnusable {
        reason: crate::storage::hibernate_file::HibernateUnusableReason,
    },
    #[error(
        "the guest could not be shut down cleanly because wake failed; the machine is stopped"
    )]
    WakeFailed,
}

#[derive(Clone, Copy)]
pub(crate) enum HibernateRemedy {
    Start,
    Stop,
}

pub(crate) async fn fence(
    runtime: &Runtime,
    config: &MachineConfig,
    remedy: HibernateRemedy,
) -> Result<(), LibVmError> {
    if runtime.native_store()?.has_hibernation(config.id).await? {
        return Err(match remedy {
            HibernateRemedy::Start => LibVmError::HibernatedStartFirst {
                reference: config.name.clone(),
            },
            HibernateRemedy::Stop => LibVmError::HibernatedStopFirst {
                reference: config.name.clone(),
            },
        });
    }
    Ok(())
}

fn failure(config: &MachineConfig, message: impl ToString) -> LibVmError {
    LibVmError::HibernateFailed {
        reference: config.name.clone(),
        message: message.to_string(),
    }
}
fn id(value: Uuid) -> Result<LiveId, LibVmError> {
    LiveId::parse(&value.to_string()).map_err(|message| LibVmError::LiveProtocol { message })
}
fn record_envelope(record: &HibernateRecord) -> Result<LiveCommandEnvelope, LibVmError> {
    Ok(LiveCommandEnvelope {
        machine_id: id(record.begin.machine_id.into())?,
        run_id: id(record.begin.ended_run_id)?,
        request_id: id(Uuid::new_v4())?,
    })
}

impl Machine {
    /// Save this persistent run and release its processes without guest shutdown.
    /// Cancellation of the caller does not cancel the durable lifecycle owner.
    pub async fn hibernate(&self) -> Result<MachineData, LibVmError> {
        let machine = self.clone();
        tokio::spawn(async move { machine.hibernate_inner().await }).await?
    }

    async fn hibernate_inner(&self) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        runtime.validate_machine_data_dir(&config)?;
        let store = runtime.native_store()?;
        if store.has_hibernation(config.id).await? {
            return Err(LibVmError::AlreadyHibernated {
                reference: config.name.clone(),
            });
        }
        if config.retention != crate::MachineRetention::Persistent {
            return Err(LibVmError::HibernateTemporary {
                reference: config.name.clone(),
            });
        }
        let state = runtime.reconcile_machine_runtime_locked(&config).await?;
        if !state.is_active() {
            return Err(LibVmError::MachineNotRunning {
                reference: config.name.clone(),
            });
        }
        let observation = runtime.observe_live(&MachineRef::id(config.id)).await?;
        if !matches!(
            observation.state()?,
            vm_spec::lifecycle::VmLifecycleState::Running
                | vm_spec::lifecycle::VmLifecycleState::Paused
        ) || observation.lifecycle()?.activity.is_some()
        {
            return Err(LibVmError::HibernateBusy {
                reference: config.name.clone(),
            });
        }
        let (pause, _) =
            crate::machine::live_capture::admission(&observation, CaptureResumePolicy::Preserve)?;
        if !observation.report().supports_same_machine_activation() {
            return Err(failure(&config, "the guest agent cannot wake this machine; stop it and update its boot assets first"));
        }
        let projection = crate::machine::live_operations::projection(&observation)?;
        let prior = crate::machine::live_operations::project_machine_state(
            runtime.machine_state(config.id).await?,
            &projection,
        );
        if !store
            .save_live_projection(config.id, &projection, &prior)
            .await?
        {
            return Err(failure(
                &config,
                "the running generation changed; inspect the machine before retrying",
            ));
        }
        let run = Uuid::parse_str(&observation.report().run_id)
            .map_err(|error| failure(&config, error))?;
        let launches = store.launch_storage_operations(config.id).await?;
        let launch = launches
            .first()
            .filter(|launch| launches.len() == 1 && launch.run_id == run)
            .ok_or_else(|| {
                failure(
                    &config,
                    "the current run cannot be identified; inspect the machine before retrying",
                )
            })?;
        let paths = runtime.machine_paths(config.id);
        let machine = OwnedDirectory::open_existing_root(paths.machine_data_dir())?
            .ok_or_else(|| failure(&config, "machine data is missing"))?;
        let mut bytes = Vec::new();
        machine
            .open_file("config.json")?
            .ok_or_else(|| failure(&config, "launch configuration is missing"))?
            .take((4 << 20) + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 4 << 20 {
            return Err(failure(&config, "launch configuration is too large"));
        }
        let spec: vm_spec::VmSpec =
            serde_json::from_slice(&bytes).map_err(|error| failure(&config, error))?;
        let configuration =
            CaptureConfiguration::from_spec(&spec).map_err(|error| failure(&config, error))?;
        let save = Uuid::new_v4();
        let (device, inode) = StoragePool::open(runtime.local_images_dir())?
            .operation_lease_identity(launch.operation_id)?;
        let mut disks = Vec::new();
        let mut read_only_inputs = Vec::new();
        for (index, disk) in launch.disks.iter().enumerate() {
            let index = u32::try_from(index).map_err(|error| failure(&config, error))?;
            if disk.read_only {
                read_only_inputs.push(CaptureReadOnlyInput {
                    attachment_index: index,
                    block_id: disk.block_id.clone(),
                    identity: crate::store::capture::read_only_identity(
                        &launch.storage,
                        index,
                        disk.role,
                    )?,
                });
            } else {
                disks.push(CaptureDiskPlan {
                    name: CaptureDiskName::new(format!("disk-{index}"))
                        .map_err(|error| failure(&config, error))?,
                    attachment_index: index,
                    block_id: disk.block_id.clone(),
                    length: disk.geometry.length,
                    tracking_eligible: false,
                    identity: DiskIdentityState::Unknown,
                    baseline_map: None,
                    copy: CaptureDiskCopy::Copy,
                });
            }
        }
        let plan = CapturePlan {
            version: CAPTURE_RECORD_VERSION,
            mode: CaptureMode::Hibernate {
                directory: store.hibernation_directory(config.id, save),
            },
            machine_id: id(config.id.into())?,
            run_id: id(run)?,
            capture_id: id(save)?,
            configuration_digest: configuration
                .digest()
                .map_err(|error| failure(&config, error))?,
            ram_bytes: configuration.ram_bytes(),
            configuration,
            policy: crate::machine::live_capture::resolve_policy(
                CapturePolicy::Incremental,
                &observation,
            ),
            identity_policy: CaptureIdentityPolicy::None,
            dirty_crossover_percent: 30,
            resume_policy: CaptureResumePolicy::Preserve,
            pause,
            disks,
            read_only_inputs,
            reservation: CaptureReservation {
                storage_operation_id: id(save)?,
                launch_lease: CaptureLaunchLease {
                    operation_id: id(launch.operation_id)?,
                    device,
                    inode,
                },
                staging_bytes: 0,
            },
            map_node_store: None,
        };
        plan.validate().map_err(|error| failure(&config, error))?;
        let effective_network = saved_network(runtime, &config).await?;
        let ssh_trusted_ca = crate::ssh_ca::resolve(runtime.secret_store(), config.id, false)
            .map_err(|_| failure(&config, "the retained SSH trust is missing or damaged; stop the machine before replacing its boot assets"))?.public;
        let record = store
            .begin_hibernation(&HibernateBegin {
                save_id: save,
                machine_id: config.id,
                ended_run_id: run,
                launch_operation_id: launch.operation_id,
                storage_generation: launch.storage_generation,
                launch_spec: spec,
                effective_network,
                ssh_trusted_ca,
            })
            .await?;
        let result = async {
            let response = runtime
                .supervisor()
                .client(config.id)
                .lifecycle(LiveCommand::Capture(Box::new(CaptureCommand {
                    envelope: envelope(&observation, save)?,
                    plan,
                })))
                .await
                .map_err(|error| failure(&config, error))?;
            if !matches!(
                response,
                LiveCommandResult::Capture(CaptureOutcome::Accepted { .. })
            ) {
                return Err(result_error(&response));
            }
            let (cut, memory) = self.capture_hibernation(&config, &record).await?;
            let allocated = validate_cut(runtime, &config, &record, &cut)?;
            Ok((cut, memory, allocated))
        }
        .await;
        let (cut, memory, allocated) = match result {
            Ok(cut) => cut,
            Err(primary) => {
                rollback(runtime, &config, &record)
                    .await
                    .map_err(|cleanup| LibVmError::MachineStartCleanupFailed {
                        primary: primary.to_string(),
                        cleanup: cleanup.to_string(),
                    })?;
                return Err(primary);
            }
        };
        if let Err(primary) = store
            .commit_hibernation_available(config.id, save, &cut, &memory, allocated)
            .await
        {
            if matches!(primary, LibVmError::DurabilityPending) {
                let mut durable = false;
                for _ in 0..2 {
                    if store.checkpoint_catalog().await.is_ok() {
                        durable = true;
                        break;
                    }
                }
                if !durable {
                    store.abort_hibernation_available(config.id, save).await?;
                    rollback(runtime, &config, &record).await?;
                    return Err(failure(&config, "saved state could not be made durable; the guest was returned to its original state"));
                }
            } else {
                rollback(runtime, &config, &record)
                    .await
                    .map_err(|cleanup| LibVmError::MachineStartCleanupFailed {
                        primary: primary.to_string(),
                        cleanup: cleanup.to_string(),
                    })?;
                return Err(primary);
            }
        }
        let released = runtime
            .supervisor()
            .client(config.id)
            .lifecycle(LiveCommand::ReleaseCapture(ReleaseCaptureCommand {
                envelope: record_envelope(&record)?,
                operation_id: id(save)?,
                disposition: CaptureReleaseDisposition::Published,
            }))
            .await;
        match released {
            Ok(LiveCommandResult::ReleaseCapture(
                vm_spec::lifecycle::ReleaseCaptureOutcome::Released { .. },
            )) => retire_available(runtime, &config, &record).await?,
            Ok(result) => {
                if recover_unaccepted_available(runtime, &config, &record).await? {
                    return Err(failure(&config, result_error(&result)));
                }
                retire_available(runtime, &config, &record).await?;
            }
            Err(_) => {
                if recover_unaccepted_available(runtime, &config, &record).await? {
                    return Err(failure(&config, "the monitor returned the guest to its original state before release; retry hibernate"));
                }
                retire_available(runtime, &config, &record).await?;
            }
        }
        runtime.machine_inspect_data(config).await
    }

    async fn capture_hibernation(
        &self,
        config: &MachineConfig,
        record: &HibernateRecord,
    ) -> Result<(HibernateCut, vm_spec::capture::HibernateMemoryReceipt), LibVmError> {
        let client = self.runtime().supervisor().client(config.id);
        let deadline = tokio::time::Instant::now() + CAPTURE_TIMEOUT;
        let mut authorized = false;
        loop {
            let status = client
                .control_hibernate(record_envelope(record)?, id(record.begin.save_id)?, false)
                .await
                .map_err(|error| failure(config, error))?;
            match status.phase {
                HibernateCapturePhase::AwaitingWrite if !authorized => {
                    let estimate = status
                        .populated_memory_estimate_bytes
                        .ok_or_else(|| failure(config, "memory estimate is missing"))?;
                    let fs = nix::sys::statvfs::statvfs(config.machine_dir.as_path())
                        .map_err(std::io::Error::from)?;
                    check_space(
                        config,
                        estimate,
                        u64::from(fs.blocks_available()).saturating_mul(fs.fragment_size()),
                    )?;
                    client
                        .control_hibernate(
                            record_envelope(record)?,
                            id(record.begin.save_id)?,
                            true,
                        )
                        .await
                        .map_err(|error| failure(config, error))?;
                    authorized = true;
                }
                HibernateCapturePhase::Prepared => {
                    return Ok((
                        *status
                            .cut
                            .ok_or_else(|| failure(config, "saved execution files are missing"))?,
                        status
                            .memory
                            .ok_or_else(|| failure(config, "memory write receipt is missing"))?,
                    ))
                }
                HibernateCapturePhase::Failed => {
                    return Err(failure(
                        config,
                        status
                            .failure
                            .map_or_else(|| "capture failed".into(), |error| error.to_string()),
                    ))
                }
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failure(
                    config,
                    "saving timed out; the guest will be returned to its original state",
                ));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Never cold boots stopped machines or resumes a user-paused machine.
    /// Lifecycle exclusion makes concurrent access callers join one wake.
    pub async fn ensure_running_for_access(
        &self,
        progress: Option<&crate::machine::live_operations::LiveOperationProgressSender>,
    ) -> Result<crate::MachineRunId, LibVmError> {
        let machine = self.clone();
        let progress = progress.cloned();
        tokio::spawn(async move { machine.ensure_access_inner(progress.as_ref()).await }).await?
    }

    async fn ensure_access_inner(
        &self,
        progress: Option<&crate::machine::live_operations::LiveOperationProgressSender>,
    ) -> Result<crate::MachineRunId, LibVmError> {
        let runtime = self.runtime();
        let waiting_for_wake = runtime
            .native_store()?
            .has_hibernation(self.machine_id())
            .await?;
        if waiting_for_wake {
            crate::machine::live_operations::report_progress(
                progress,
                crate::machine::live_operations::LiveOperationProgress::Waking,
            );
        }
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        recover_locked(runtime, &config).await?;
        // A wake only proves the VM runs again. Access needs the agent of the
        // new run, so the waker waits for readiness exactly as a joiner does.
        if let Some(record) = runtime
            .native_store()?
            .machine_hibernation(config.id)
            .await?
        {
            self.wake_locked(&config, record).await?;
        }
        // Judge "running" from the reconciled observation, as access did
        // before wake existed. The stored state alone can lag the monitor,
        // for example right after a refused pause.
        let observed = runtime.machine_inspect_data(config.clone()).await?;
        if !observed.is_running() {
            return Err(LibVmError::MachineNotRunning {
                reference: config.name.clone(),
            });
        }
        let run = observed
            .run_id
            .as_ref()
            .map(|run| run.as_str().to_owned())
            .ok_or_else(|| failure(&config, "running generation is missing"))?;
        if waiting_for_wake {
            crate::machine::live_operations::report_progress(
                progress,
                crate::machine::live_operations::LiveOperationProgress::WaitingForAgent,
            );
        }
        let ready = self.wait_ready(Duration::from_secs(60)).await?;
        if !ready.status.readiness.ready {
            return Err(failure(
                &config,
                "the guest agent is not ready; inspect the machine before retrying",
            ));
        }
        let current = runtime.machine_state(config.id).await?;
        if current.run_id.as_deref() != Some(run.as_str()) {
            return Err(LibVmError::MachineNotRunning {
                reference: config.name.clone(),
            });
        }
        Ok(crate::MachineRunId::from_raw(run))
    }

    pub(crate) async fn wake_locked(
        &self,
        config: &MachineConfig,
        record: HibernateRecord,
    ) -> Result<crate::MachineStart, LibVmError> {
        let runtime = self.runtime();
        let store = runtime.native_store()?;
        if record.phase == HibernatePhase::Waking {
            let deadline = tokio::time::Instant::now() + RETIRE_TIMEOUT;
            loop {
                recover_locked(runtime, config).await?;
                match store.machine_hibernation(config.id).await? {
                    Some(current) if current.phase == HibernatePhase::Waking => {}
                    None if runtime.machine_state(config.id).await?.status
                        == MachineRuntimeState::Running =>
                    {
                        let state = runtime.machine_state(config.id).await?;
                        let run_id = state
                            .run_id
                            .ok_or_else(|| failure(config, "wake generation is missing"))?;
                        return Ok(crate::MachineStart {
                            machine: runtime.machine_inspect_data(config.clone()).await?,
                            run_id: crate::MachineRunId::from_raw(run_id),
                        });
                    }
                    _ => {
                        return Err(LibVmError::WakeFailedBeforeConsume {
                            reference: config.name.clone(),
                            source: Box::new(failure(
                                config,
                                "the joined wake ended before execution",
                            )),
                        })
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(LibVmError::WakeFailedBeforeConsume {
                        reference: config.name.clone(),
                        source: Box::new(failure(config, "the joined wake is still parked")),
                    });
                }
                tokio::time::sleep(POLL).await;
            }
        }
        if record.phase != HibernatePhase::Available {
            return Err(failure(
                config,
                "a wake is already in progress; wait for it to finish",
            ));
        }
        let run = Uuid::new_v4();
        store
            .claim_hibernation_wake(config.id, record.begin.save_id, run)
            .await?;
        let mut consumed = false;
        let mut lease = None;
        let result = async {
            let cut = record.cut.as_ref().ok_or_else(|| failure(config, "saved execution files are missing"))?;
            validate_cut(runtime, config, &record, cut)?;
            let mut objects = Vec::with_capacity(4);
            let mut descriptors = Vec::with_capacity(4);
            for (saved, role) in cut.saved_files.iter().zip([
                vm_spec::restore::RestoreObjectRole::Ram, vm_spec::restore::RestoreObjectRole::Layout,
                vm_spec::restore::RestoreObjectRole::Execution, vm_spec::restore::RestoreObjectRole::Devices,
            ]) {
                let file = checked_file(config, &saved.file, HibernateFileKind::Saved)?;
                let stat = file.metadata()?;
                descriptors.push(vm_spec::restore::RestoreObject { role, fd: file.as_raw_fd(), file_device: stat.dev(), file_inode: stat.ino(), length: stat.len(), authority: vm_spec::restore::RestoreObjectAuthority::Hibernation { file: saved.file.clone() } });
                objects.push(file);
            }
            let mut launch_config = config.clone();
            launch_config.spec = record.begin.launch_spec.clone();
            let storage = runtime.machine_storage_record(config.id).await?;
            if storage.storage_generation != record.begin.storage_generation { return Err(LibVmError::HibernateUnusable { reference: config.name.clone(), reason: crate::storage::hibernate_file::HibernateUnusableReason::DisksChanged }); }
            let trust = crate::ssh_ca::resolve(runtime.secret_store(), config.id, false).map_err(|_| LibVmError::HibernateUnusable {
                reference: config.name.clone(), reason: crate::storage::hibernate_file::HibernateUnusableReason::NotCompatible,
            })?;
            if trust.public != record.begin.ssh_trusted_ca {
                return Err(LibVmError::HibernateUnusable { reference: config.name.clone(), reason: crate::storage::hibernate_file::HibernateUnusableReason::NotCompatible });
            }
            lease = Some(runtime.register_launch_storage(config, run, &storage).await?);
            let lease_ref = lease.as_ref().ok_or_else(|| failure(config, "wake storage ownership is missing"))?;
            let (lowers, lower_files) = crate::machine::restore::hibernation_lower(runtime, &launch_config, lease_ref).await?;
            let seeds = crate::machine::root_storage::launch_disk_seeds(&storage, &config.machine_dir, runtime.local_images_dir())?;
            let request = vm_spec::restore::RestoreRequest {
                version: vm_spec::restore::RESTORE_REQUEST_VERSION, purpose: vm_spec::restore::ActivationPurpose::SameMachine,
                authority: vm_spec::restore::RestoreAuthority::Hibernation { cut: Box::new(cut.clone()) },
                activation_id: id(Uuid::new_v4())?, freeze_operation_id: cut.freeze_operation_id.clone(), start_paused: true,
                configuration: cut.configuration.clone(), disk_tracking_seeds: seeds, map_node_store: None,
                objects: descriptors, lowers, network: record.begin.effective_network.clone(), ssh_trusted_ca: Some(record.begin.ssh_trusted_ca.clone()), hook: None,
            };
            request.validate().map_err(|error| failure(config, error))?;
            let executable = crate::storage::stream::open_regular_source(runtime.supervisor().executable())?;
            let executable_identity = crate::storage::identity_file::SourceFingerprint::new(&executable.metadata()?);
            crate::machine::restore::inspect(&executable, &request, request.network.is_some()).await.map_err(|_| LibVmError::HibernateUnusable { reference: config.name.clone(), reason: crate::storage::hibernate_file::HibernateUnusableReason::NotCompatible })?;
            let restore = crate::supervisor::launch::RestoreLaunch { request, objects, executable, executable_identity, lowers: lower_files };
            runtime.ensure_machine_runtime_directories(config.id)?;
            let paths = runtime.machine_paths(config.id);
            let lifetime = crate::lock_manager::MachineLifetimeLock::try_acquire(&paths.vmm_lock_path())?.ok_or_else(|| failure(config, "the previous run still owns the machine; retry after it exits"))?;
            let secrets = runtime.resolve_machine_secrets(config, &run.to_string(), &crate::EgressCredentials::default())?;
            let network = runtime.prepare_wake_network(config, &run.to_string(), &secrets, record.begin.effective_network.as_ref()).await?;
            // Wake retains the already-published launch assets. It never generates
            // a new initramfs, rotates SSH trust, resizes or provisions a disk.
            let shutdown = crate::guest_agent::storage_shutdown_context(&Uuid::from(config.id).to_string(), &run.to_string(), &launch_config.spec, rootfs_spec::RosettaMode::Disabled).map_err(|error| failure(config, error))?;
            let logs = runtime.local_paths().machine_logs_directory(config.id)?;
            let (file_device, file_inode) = lease_ref.file_identity()?;
            let pidfile = paths.vmm_pid_path(); let exit_status = paths.vmm_exit_status_path();
            let spec_path = paths.vm_spec_path(); let socket = paths.vmm_socket_path();
            let serial = paths.serial_log_path(); let trace = paths.vm_trace_log_path();
            let run_id = run.to_string();
            let launch = crate::supervisor::VmmLaunch {
                machine_id: config.id, name: &config.name, machine_dir: &config.machine_dir, machine_runtime_dir: paths.machine_run_dir(),
                pidfile: &pidfile, exit_status: &exit_status, config: &spec_path, socket: &socket, serial_log: &serial, trace_log: &trace,
                network: &network, run_id: &run_id, exit_command: None, agent_enabled: true,
                rosetta_intent: crate::supervisor::start_request::VmmRosettaIntent::Disabled {}, asset_directory: runtime.asset_directory().to_path_buf(), startup_command: None,
                machine_log_dir: &logs, machine_lock: &lifetime, storage_lease: lease_ref.lock(),
                storage_lease_binding: protocol::shutdown::StorageLeaseBinding { operation_id: lease_ref.operation_id().to_string(), file_device, file_inode },
                storage_shutdown: &shutdown, disk_tracking_seeds: restore.request.disk_tracking_seeds.clone(), restore: Some(&restore),
            };
            runtime.mark_launch_storage_admitted(lease_ref.operation_id()).await?;
            let pending = runtime.supervisor().spawn(&launch, None).await?;
            let startup = pending.wait();
            tokio::pin!(startup);
            let client = runtime.supervisor().client(config.id);
            let authorization = vm_spec::hibernate::ConsumeAuthorization { machine_id: id(config.id.into())?, save_id: id(record.begin.save_id)?, new_run_id: id(run)? };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            loop {
                tokio::select! {
                    result = &mut startup => { result?; return Err(failure(config, "wake completed without its execution barrier")); }
                    _ = tokio::time::sleep(POLL) => {}
                }
                if let Ok(Some(prepared)) = client.restore_prepared().await {
                    prepared.validate_authorization(&authorization).map_err(|error| failure(config, error))?;
                    break;
                }
                if tokio::time::Instant::now() >= deadline { return Err(failure(config, "wake construction timed out; retry start")); }
            }
            validate_cut(runtime, config, &record, cut)?;
            let consume = store.consume_hibernation(config.id, record.begin.save_id, run, lease_ref.operation_id()).await;
            // A durability-pending consume committed. Never restore the old save.
            consumed = consume.is_ok() || matches!(consume, Err(LibVmError::DurabilityPending));
            match consume {
                Err(LibVmError::DurabilityPending) => store.checkpoint_catalog().await?,
                other => other?,
            }
            let authorize_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            let startup_completed = loop {
                tokio::select! {
                    result = &mut startup => { result?; break true; }
                    result = client.authorize_consume(authorization.clone()) => {
                        if result.is_ok() { break false; }
                        if tokio::time::Instant::now() >= authorize_deadline {
                            return Err(failure(config, "wake authorization could not be delivered"));
                        }
                    }
                }
                tokio::time::sleep(POLL).await;
            };
            if !startup_completed { startup.await?; }
            let monitor = crate::machine::lifecycle::started_run_monitor(runtime, config, &run_id, lease_ref.operation_id())?;
            let birth = monitor.started_at().ok_or_else(|| failure(config, "wake monitor generation is missing"))?;
            runtime.mark_machine_monitor_ready(config.id, run_id, monitor.pid(), birth).await?;
            Ok(())
        }.await;
        if let Err(primary) = result {
            if !consumed {
                let _ = runtime
                    .supervisor()
                    .client(config.id)
                    .abandon_restore()
                    .await;
            }
            reap_wake(runtime, config, run).await.map_err(|cleanup| {
                LibVmError::MachineStartCleanupFailed {
                    primary: primary.to_string(),
                    cleanup: cleanup.to_string(),
                }
            })?;
            drop(lease);
            runtime.reconcile_machine_network(config, false).await?;
            if consumed {
                runtime.mark_machine_stopped(config.id, None).await?;
                return Err(LibVmError::WakeConsumed {
                    reference: config.name.clone(),
                    source: Some(Box::new(primary)),
                });
            }
            store
                .release_hibernation_wake(config.id, record.begin.save_id, run)
                .await?;
            return Err(match primary {
                unusable @ LibVmError::HibernateUnusable { .. } => unusable,
                other => LibVmError::WakeFailedBeforeConsume {
                    reference: config.name.clone(),
                    source: Box::new(other),
                },
            });
        }
        drop(lease);
        Ok(crate::MachineStart {
            machine: runtime.machine_inspect_data(config.clone()).await?,
            run_id: crate::MachineRunId::from_raw(run.to_string()),
        })
    }
}

async fn reap_wake(runtime: &Runtime, config: &MachineConfig, run: Uuid) -> Result<(), LibVmError> {
    let store = runtime.native_store()?;
    let deadline = tokio::time::Instant::now() + RETIRE_TIMEOUT;
    loop {
        let state = runtime.machine_state(config.id).await?;
        let mut terminal = true;
        for operation in store.launch_storage_operations(config.id).await? {
            if operation.run_id != run {
                continue;
            }
            if let Some(holder) = crate::supervisor::storage_holder::read(
                &runtime.machine_paths(config.id).vmm_storage_holder_path(),
            )? {
                holder
                    .validate_binding(
                        &Uuid::from(config.id).to_string(),
                        &run.to_string(),
                        &operation.operation_id.to_string(),
                    )
                    .map_err(|error| failure(config, error))?;
                for process in &holder.holders {
                    let pid = i32::try_from(process.pid).map_err(|error| failure(config, error))?;
                    let birth = i64::try_from(process.started_at)
                        .map_err(|error| failure(config, error))?;
                    if let Some(identity) = ProcessIdentity::for_pid(pid)? {
                        if identity.matches_started_at(Some(birth)) {
                            identity.signal(Signal::SIGKILL)?;
                        }
                    }
                }
            }
            terminal &= runtime.launch_holders_terminal(config, &operation, Some(&state))?;
        }
        if terminal {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(failure(
                config,
                "wake processes have not ended; retry after they exit",
            ));
        }
        tokio::time::sleep(POLL).await;
    }
}

fn check_space(config: &MachineConfig, estimate: u64, free_bytes: u64) -> Result<(), LibVmError> {
    let needed_bytes = estimate
        .checked_add(CAPTURE_STATE_RESERVE_BYTES)
        .ok_or_else(|| failure(config, "memory estimate exceeds supported size"))?;
    if needed_bytes > free_bytes {
        return Err(LibVmError::HibernateOutOfSpace {
            reference: config.name.clone(),
            needed_bytes,
            free_bytes,
        });
    }
    Ok(())
}

async fn saved_network(
    runtime: &Runtime,
    config: &MachineConfig,
) -> Result<Option<vm_spec::restore::RestoreNetwork>, LibVmError> {
    use crate::store::NetworkStore;
    if matches!(
        config.network,
        crate::store::models::MachineNetworkConfig::None
    ) {
        return Ok(None);
    }
    let store = runtime.native_store()?;
    let attachment = store
        .network_attachment(config.id)
        .await?
        .ok_or_else(|| failure(config, "the running network attachment is missing"))?;
    let instance = store
        .network_instance(&attachment.network_instance_id)
        .await?
        .ok_or_else(|| failure(config, "the running network configuration is missing"))?;
    crate::network::persisted_restore_network(&instance)
        .map(Some)
        .map_err(|error| failure(config, error))
}

fn checked_file(
    config: &MachineConfig,
    binding: &HibernateFileBinding,
    kind: HibernateFileKind,
) -> Result<File, LibVmError> {
    HibernateFileCheck::open(binding).map_err(|error| match error.reason(kind) {
        Some(reason) => LibVmError::HibernateUnusable {
            reference: config.name.clone(),
            reason,
        },
        None => failure(config, error),
    })
}

fn validate_cut(
    runtime: &Runtime,
    config: &MachineConfig,
    record: &HibernateRecord,
    cut: &HibernateCut,
) -> Result<u64, LibVmError> {
    cut.validate().map_err(|error| failure(config, error))?;
    let directory = runtime
        .native_store()?
        .hibernation_directory(config.id, record.begin.save_id);
    let spec = &record.begin.launch_spec;
    if cut.machine_id != id(config.id.into())?
        || cut.save_id != id(record.begin.save_id)?
        || cut.ended_run_id != id(record.begin.ended_run_id)?
        || cut.configuration
            != CaptureConfiguration::from_spec(spec).map_err(|error| failure(config, error))?
    {
        return Err(failure(
            config,
            "saved state does not match this machine's run",
        ));
    }
    let mut allocated = 0u64;
    for saved in &cut.saved_files {
        if saved.file.path.parent() != Some(directory.as_path()) {
            return Err(failure(
                config,
                "saved files are outside the machine's private save directory",
            ));
        }
        let file = checked_file(config, &saved.file, HibernateFileKind::Saved)?;
        allocated = allocated
            .checked_add(file.metadata()?.blocks().saturating_mul(512))
            .ok_or_else(|| failure(config, "saved size overflow"))?;
        file.sync_all()?;
    }
    for disk in &cut.writable_disks {
        let expected = spec
            .storage
            .as_ref()
            .and_then(|storage| storage.disks.get(disk.attachment_index as usize))
            .ok_or_else(|| failure(config, "saved writable disk is not configured"))?;
        let expected_path = if expected.path.is_absolute() {
            expected.path.clone()
        } else {
            config.machine_dir.join(&expected.path)
        };
        if expected.read_only || expected_path != disk.file.path {
            return Err(failure(
                config,
                "saved writable disk path differs from the machine",
            ));
        }
        checked_file(config, &disk.file, HibernateFileKind::Disk)?.sync_all()?;
    }
    Ok(allocated)
}

async fn rollback(
    runtime: &Runtime,
    config: &MachineConfig,
    record: &HibernateRecord,
) -> Result<(), LibVmError> {
    let client = runtime.supervisor().client(config.id);
    let operations = runtime
        .native_store()?
        .launch_storage_operations(config.id)
        .await?;
    let mut terminal = true;
    for operation in &operations {
        if operation.run_id == record.begin.ended_run_id {
            terminal &=
                runtime.launch_holders_terminal(config, operation, Some(&record.prior_state))?;
        }
    }
    if terminal {
        abort_record(runtime, record).await?;
        return delete_save(runtime, config, record).await;
    }
    let canceled = client
        .lifecycle(LiveCommand::CancelOperation(CancelOperationCommand {
            envelope: record_envelope(record)?,
            operation_id: id(record.begin.save_id)?,
        }))
        .await
        .map_err(|error| failure(config, error))?;
    if matches!(canceled, LiveCommandResult::CancelOperation(vm_spec::lifecycle::CancelOperationOutcome::Rejected { ref rejection }) if rejection.reason == vm_spec::lifecycle::LiveRejectionReason::OperationNotFound)
    {
        abort_record(runtime, record).await?;
        return delete_save(runtime, config, record).await;
    }
    let deadline = tokio::time::Instant::now() + RETIRE_TIMEOUT;
    loop {
        let result = client
            .lifecycle(LiveCommand::ReleaseCapture(ReleaseCaptureCommand {
                envelope: record_envelope(record)?,
                operation_id: id(record.begin.save_id)?,
                disposition: CaptureReleaseDisposition::Abandoned,
            }))
            .await
            .map_err(|error| failure(config, error))?;
        if matches!(
            result,
            LiveCommandResult::ReleaseCapture(
                vm_spec::lifecycle::ReleaseCaptureOutcome::Released { .. }
            )
        ) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(failure(
                config,
                "rollback is still in progress; inspect the machine before retrying",
            ));
        }
        tokio::time::sleep(POLL).await;
    }
    abort_record(runtime, record).await?;
    delete_save(runtime, config, record).await
}

async fn abort_record(runtime: &Runtime, record: &HibernateRecord) -> Result<(), LibVmError> {
    if runtime
        .native_store()?
        .machine_hibernation(record.begin.machine_id)
        .await?
        .is_none()
    {
        return Ok(());
    }
    let prior = match record.prior_state.status {
        MachineRuntimeState::Paused => HibernatePriorState::Paused,
        _ => HibernatePriorState::Running,
    };
    runtime
        .native_store()?
        .abort_hibernation_saving(record.begin.machine_id, record.begin.save_id, prior)
        .await
}

fn cleanup_journal(config: &MachineConfig, save: Uuid) -> Result<(), LibVmError> {
    let Some(machine) = OwnedDirectory::open_existing_root(&config.machine_dir)? else {
        return Ok(());
    };
    let Some(captures) = machine.open_dir(vm_spec::capture::CAPTURES_DIRECTORY)? else {
        return Ok(());
    };
    captures.remove_tree(&save.to_string())?;
    captures.sync()
}

async fn delete_save(
    runtime: &Runtime,
    config: &MachineConfig,
    record: &HibernateRecord,
) -> Result<(), LibVmError> {
    cleanup_journal(config, record.begin.save_id)?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let _roots = pool.lock_roots()?;
    let Some(machine) = OwnedDirectory::open_existing_root(&config.machine_dir)? else {
        return Ok(());
    };
    let Some(parent) = machine.open_dir("hibernation")? else {
        return Ok(());
    };
    let name = record.begin.save_id.to_string();
    if let Some(directory) = parent.open_dir(&name)? {
        parent.remove_open_tree(&name, &directory)?;
    }
    parent.sync()
}

pub(crate) async fn discard_locked(
    runtime: &Runtime,
    config: &MachineConfig,
) -> Result<bool, LibVmError> {
    let store = runtime.native_store()?;
    let existed = store.has_hibernation(config.id).await?;
    recover_locked(runtime, config).await?;
    let Some(record) = store.machine_hibernation(config.id).await? else {
        return Ok(existed
            && runtime.machine_state(config.id).await?.status == MachineRuntimeState::Stopped);
    };
    if record.phase != HibernatePhase::Discarding {
        store
            .begin_hibernation_discard(config.id, record.begin.save_id)
            .await?;
    } else {
        store.checkpoint_catalog().await?;
    }
    delete_save(runtime, config, &record).await?;
    store
        .finish_hibernation_discard(config.id, record.begin.save_id)
        .await?;
    Ok(true)
}

async fn retire_available(
    runtime: &Runtime,
    config: &MachineConfig,
    record: &HibernateRecord,
) -> Result<(), LibVmError> {
    let store = runtime.native_store()?;
    store.checkpoint_catalog().await?;
    let deadline = tokio::time::Instant::now() + RETIRE_TIMEOUT;
    loop {
        let operations = store.launch_storage_operations(config.id).await?;
        let Some(operation) = operations.iter().find(|operation| {
            operation.operation_id == record.begin.launch_operation_id
                && operation.run_id == record.begin.ended_run_id
        }) else {
            cleanup_journal(config, record.begin.save_id)?;
            return runtime.reconcile_machine_network(config, false).await;
        };
        let holder = crate::supervisor::storage_holder::read(
            &runtime.machine_paths(config.id).vmm_storage_holder_path(),
        )?;
        if let Some(holder) = holder {
            holder
                .validate_binding(
                    &Uuid::from(config.id).to_string(),
                    &record.begin.ended_run_id.to_string(),
                    &record.begin.launch_operation_id.to_string(),
                )
                .map_err(|error| failure(config, error))?;
            for process in &holder.holders {
                let pid = i32::try_from(process.pid).map_err(|error| failure(config, error))?;
                let birth =
                    i64::try_from(process.started_at).map_err(|error| failure(config, error))?;
                if let Some(identity) = ProcessIdentity::for_pid(pid)? {
                    if identity.matches_started_at(Some(birth)) {
                        identity.signal(Signal::SIGKILL)?;
                    }
                }
            }
        }
        let mut next = runtime.machine_state(config.id).await?;
        if runtime.launch_holders_terminal(config, operation, Some(&next))? {
            next.status = MachineRuntimeState::Hibernated;
            next.run_id = None;
            next.vmm_pid = None;
            next.started_at = None;
            if store
                .try_retire_launch_storage(
                    operation.operation_id,
                    operation.run_id,
                    operation.storage_generation,
                    &next,
                    crate::StorageStopOutcome::Unknown,
                )
                .await?
            {
                cleanup_journal(config, record.begin.save_id)?;
                return runtime.reconcile_machine_network(config, false).await;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(failure(config, "saved state is durable but its old processes have not ended; retry the lifecycle operation"));
        }
        tokio::time::sleep(POLL).await;
    }
}

/// A reachable monitor is authoritative about whether the source is still a
/// cancellable capture. An unreachable source is ended under exact-holder proof.
async fn recover_unaccepted_available(
    runtime: &Runtime,
    config: &MachineConfig,
    record: &HibernateRecord,
) -> Result<bool, LibVmError> {
    for operation in runtime
        .native_store()?
        .launch_storage_operations(config.id)
        .await?
    {
        if operation.operation_id != record.begin.launch_operation_id
            || operation.run_id != record.begin.ended_run_id
        {
            continue;
        }
        if runtime.launch_holders_terminal(config, &operation, Some(&record.prior_state))? {
            return Ok(false);
        }
        let client = runtime.supervisor().client(config.id);
        let status = tokio::time::timeout(
            Duration::from_secs(2),
            client.control_hibernate(record_envelope(record)?, id(record.begin.save_id)?, false),
        )
        .await;
        if let Ok(Ok(status)) = status {
            if matches!(
                status.phase,
                HibernateCapturePhase::Prepared | HibernateCapturePhase::Failed
            ) {
                runtime
                    .native_store()?
                    .abort_hibernation_available(config.id, record.begin.save_id)
                    .await?;
                rollback(runtime, config, record).await?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Called before ordinary ended-run reduction, with lifecycle exclusion held.
pub(crate) async fn recover_locked(
    runtime: &Runtime,
    config: &MachineConfig,
) -> Result<bool, LibVmError> {
    let store = runtime.native_store()?;
    let Some(record) = store.machine_hibernation(config.id).await? else {
        return Ok(false);
    };
    match record.phase {
        HibernatePhase::Available => {
            if recover_unaccepted_available(runtime, config, &record).await? {
                return Ok(false);
            }
            retire_available(runtime, config, &record).await?;
        }
        HibernatePhase::Discarding => {
            store.checkpoint_catalog().await?;
            delete_save(runtime, config, &record).await?;
            store
                .finish_hibernation_discard(config.id, record.begin.save_id)
                .await?;
            return Ok(false);
        }
        HibernatePhase::Saving => {
            let operations = store.launch_storage_operations(config.id).await?;
            let mut alive = false;
            for operation in &operations {
                if operation.run_id == record.begin.ended_run_id
                    && !runtime.launch_holders_terminal(
                        config,
                        operation,
                        Some(&record.prior_state),
                    )?
                {
                    alive = true;
                }
            }
            if alive {
                rollback(runtime, config, &record).await?;
            } else {
                abort_record(runtime, &record).await?;
                delete_save(runtime, config, &record).await?;
            }
            return Ok(false);
        }
        HibernatePhase::Waking => {
            let run = record
                .new_run_id
                .ok_or_else(|| failure(config, "wake generation is missing"))?;
            let state = runtime.machine_state(config.id).await?;
            for operation in store.launch_storage_operations(config.id).await? {
                if operation.run_id == run
                    && !runtime.launch_holders_terminal(config, &operation, Some(&state))?
                {
                    return Ok(true);
                }
            }
            store
                .release_hibernation_wake(config.id, record.begin.save_id, run)
                .await?;
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use crate::machine::hibernate::check_space;
    use crate::{LibVmError, Machine, MachineRetention, Memory, Runtime, RuntimeConfig};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use test_utils::{
        CaptureScenario, LifecycleScenario, LiveScenario, NativeCaptureResult, NativeCaptureStep,
        Scenario,
    };
    use vm_spec::live::{LiveAvailability, LiveCapability, LiveCapabilityVector, LiveLane};

    struct CaptureFixture {
        _temporary: tempfile::TempDir,
        runtime: Runtime,
        machine: Machine,
        monitor: crate::supervisor::process::ProcessIdentity,
    }

    impl Drop for CaptureFixture {
        fn drop(&mut self) {
            let _ = self.monitor.signal(nix::sys::signal::Signal::SIGKILL);
        }
    }

    impl CaptureFixture {
        async fn new(mut lifecycle: LifecycleScenario, retention: MachineRetention) -> Self {
            let temporary = tempfile::Builder::new()
                .prefix("hib-")
                .tempdir_in("/tmp")
                .unwrap();
            let root = temporary.path();
            for provider in &mut lifecycle.providers {
                if provider.device_id == 2 {
                    provider.configured_id = "silo-root".into();
                }
            }
            lifecycle.capture.ram_bytes = 1 << 20;
            let supported = LiveCapability {
                native: true,
                availability: LiveAvailability::Supported,
            };
            let scenario = Scenario {
                lifecycle: Some(lifecycle),
                live: Some(LiveScenario {
                    lane: LiveLane::KvmX86_64,
                    host: LiveCapabilityVector {
                        pause: supported.clone(),
                        capture: supported.clone(),
                        restore: supported.clone(),
                        fork: supported.clone(),
                        incremental: supported,
                    },
                    machine: None,
                }),
                ..Default::default()
            };
            let scenario_path = root.join("scenario.json");
            scenario.write_to(&scenario_path).unwrap();
            let binary = test_utils::mock_vmm_binary();
            let kernel = root.join("kernel");
            let initramfs = root.join("initramfs");
            let agent = root.join("agent");
            std::fs::write(
                &kernel,
                test_utils::direct_kernel::host_kernel("hibernate-fixture"),
            )
            .unwrap();
            std::fs::write(&initramfs, b"scenario-initramfs").unwrap();
            std::fs::write(&agent, b"scenario-agent").unwrap();
            std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
            let disk = root.join("disk.raw");
            disk_image::ext4::Formatter::new(&disk, 4096, 64 << 20)
                .unwrap()
                .close()
                .unwrap();
            let components = crate::ResolvedRuntimeComponents::from_paths(
                binary.to_path_buf(),
                binary.to_path_buf(),
                kernel,
                initramfs,
                agent,
                root.to_path_buf(),
            )
            .unwrap();
            let runtime = Runtime::new(
                RuntimeConfig::local(root.join("home"))
                    .with_run_root(root.join("run"))
                    .with_runtime_components(components)
                    .with_mock_vmm(&scenario_path),
            )
            .await
            .unwrap();
            let machine = runtime
                .machine()
                .name("source")
                .memory(Memory::mebibytes(1))
                .retention(retention)
                .image_source(crate::ImageSource::disk(disk))
                .network(|network| network.none())
                .create()
                .await
                .unwrap();
            machine.start().await.unwrap();
            assert!(
                machine
                    .wait_ready(Duration::from_secs(30))
                    .await
                    .unwrap()
                    .status
                    .readiness
                    .ready
            );
            let state = runtime.machine_state(machine.machine_id()).await.unwrap();
            let monitor =
                crate::supervisor::process::ProcessIdentity::for_pid(state.vmm_pid.unwrap())
                    .unwrap()
                    .unwrap();
            Self {
                _temporary: temporary,
                runtime,
                machine,
                monitor,
            }
        }

        async fn config(&self) -> crate::store::models::MachineConfig {
            self.runtime
                .resolve_machine_config(&crate::MachineRef::id(self.machine.machine_id()))
                .await
                .unwrap()
        }
    }

    fn lifecycle() -> LifecycleScenario {
        LifecycleScenario {
            same_machine_activation: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn hibernation_capture_happy_path_releases_run_and_preserves_four_saved_files() {
        use crate::store::MachineStore;
        for paused in [false, true] {
            let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
            if paused {
                f.machine
                    .pause_and_wait(&f.machine.observe_live().await.unwrap())
                    .await
                    .unwrap();
            }
            let data = f.machine.hibernate().await.unwrap();
            assert_eq!(data.status.label(), "hibernated");
            let info = data.hibernation.unwrap();
            assert!(info.saved_state_bytes > 0);
            assert_eq!(
                info.memory_capture.mode,
                vm_spec::lifecycle::CapturePolicy::Full
            );
            let store = f.runtime.native_store().unwrap();
            let record = store
                .machine_hibernation(f.machine.machine_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                record.phase,
                crate::store::hibernate::HibernatePhase::Available
            );
            assert_eq!(
                record.prior_state.status,
                if paused {
                    crate::store::models::MachineRuntimeState::Paused
                } else {
                    crate::store::models::MachineRuntimeState::Running
                }
            );
            assert!(store
                .launch_storage_operations(f.machine.machine_id())
                .await
                .unwrap()
                .is_empty());
            assert!(!f.monitor.is_alive().unwrap());
            let directory =
                store.hibernation_directory(f.machine.machine_id(), record.begin.save_id);
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 4);
            assert!(!f
                .config()
                .await
                .machine_dir
                .join("captures")
                .join(record.begin.save_id.to_string())
                .exists());
            assert!(matches!(
                f.machine.hibernate().await,
                Err(LibVmError::AlreadyHibernated { .. })
            ));
            assert_eq!(
                f.machine.kill().await.unwrap().machine.status.label(),
                "stopped"
            );
            assert!(!directory.exists());
        }
    }

    #[tokio::test]
    async fn hibernation_capture_precommit_failures_restore_original_state_and_cleanup() {
        for memory in [false, true] {
            for paused in [false, true] {
                let mut scenario = lifecycle();
                let step = NativeCaptureStep {
                    delay_ms: 0,
                    result: NativeCaptureResult::Fail,
                };
                scenario.capture = CaptureScenario {
                    execution: if memory {
                        Vec::new()
                    } else {
                        vec![step.clone()]
                    },
                    memory: if memory { vec![step] } else { Vec::new() },
                    ..Default::default()
                };
                let f = CaptureFixture::new(scenario, MachineRetention::Persistent).await;
                if paused {
                    f.machine
                        .pause_and_wait(&f.machine.observe_live().await.unwrap())
                        .await
                        .unwrap();
                }
                let config = f.config().await;
                let disk = config.spec.storage.as_ref().unwrap().disks[0].path.clone();
                let path = if disk.is_absolute() {
                    disk
                } else {
                    config.machine_dir.join(disk)
                };
                let before = std::fs::read(&path).unwrap();
                let error = f.machine.hibernate().await.unwrap_err();
                let stage = if memory {
                    "capture-memory"
                } else {
                    "capture-execution"
                };
                assert!(
                    matches!(&error, LibVmError::HibernateFailed { message, .. } if message.contains(stage)),
                    "{error}"
                );
                assert!(!f
                    .runtime
                    .native_store()
                    .unwrap()
                    .has_hibernation(config.id)
                    .await
                    .unwrap());
                let observed = f.machine.observe_live().await.unwrap();
                assert_eq!(
                    f.runtime.machine_state(config.id).await.unwrap().status,
                    if paused {
                        crate::store::models::MachineRuntimeState::Paused
                    } else {
                        crate::store::models::MachineRuntimeState::Running
                    }
                );
                assert_eq!(
                    observed.state().unwrap(),
                    if paused {
                        vm_spec::lifecycle::VmLifecycleState::Paused
                    } else {
                        vm_spec::lifecycle::VmLifecycleState::Running
                    }
                );
                assert_eq!(std::fs::read(path).unwrap(), before);
                let hibernation = config.machine_dir.join("hibernation");
                if hibernation.exists() {
                    assert_eq!(std::fs::read_dir(hibernation).unwrap().count(), 0);
                }
                f.machine.kill().await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn hibernation_capture_admission_refuses_temporary_and_unsupported_agent() {
        for (retention, supports) in [
            (MachineRetention::Ephemeral, true),
            (MachineRetention::Persistent, false),
        ] {
            let scenario = LifecycleScenario {
                same_machine_activation: supports,
                ..Default::default()
            };
            let f = CaptureFixture::new(scenario, retention).await;
            let error = f.machine.hibernate().await.unwrap_err();
            if supports {
                assert!(
                    matches!(error, LibVmError::HibernateTemporary { .. }),
                    "{error}"
                );
            } else {
                assert!(
                    matches!(error, LibVmError::HibernateFailed { .. }),
                    "{error}"
                );
            }
            assert!(!f
                .runtime
                .native_store()
                .unwrap()
                .has_hibernation(f.machine.machine_id())
                .await
                .unwrap());
            f.machine.kill().await.unwrap();
        }
    }

    #[tokio::test]
    async fn hibernation_capture_stopped_refusal_and_space_boundary_are_typed() {
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        let config = f.config().await;
        let allowance = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
        assert!(check_space(&config, 1234, allowance + 1234).is_ok());
        assert!(
            matches!(check_space(&config, 1234, 12), Err(LibVmError::HibernateOutOfSpace { needed_bytes, free_bytes: 12, .. }) if needed_bytes == allowance + 1234)
        );
        assert!(check_space(&config, u64::MAX, u64::MAX).is_err());
        f.machine.kill().await.unwrap();
        assert!(matches!(
            f.machine.hibernate().await,
            Err(LibVmError::MachineNotRunning { .. })
        ));
        assert!(matches!(
            f.machine.ensure_running_for_access(None).await,
            Err(LibVmError::MachineNotRunning { .. })
        ));
    }

    async fn blocked_checkpoint(f: &CaptureFixture) -> sqlx::Transaction<'static, sqlx::Sqlite> {
        let store = f.runtime.native_store().unwrap();
        store.checkpoint_catalog().await.unwrap();
        let mut reader = store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM machine_hibernation")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        reader
    }

    async fn interrupted_available(f: &CaptureFixture) -> crate::store::hibernate::HibernateRecord {
        let reader = blocked_checkpoint(f).await;
        let machine = f.machine.clone();
        // Directly cancel the inner owner to model manager death. The public
        // method deliberately does not cancel this owner with its requester.
        let mut owner = tokio::spawn(async move { machine.hibernate_inner().await });
        let store = f.runtime.native_store().unwrap();
        let record = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(record) = store
                    .machine_hibernation(f.machine.machine_id())
                    .await
                    .unwrap()
                {
                    if record.phase == crate::store::hibernate::HibernatePhase::Available {
                        break record;
                    }
                }
                if owner.is_finished() {
                    panic!(
                        "capture ended before the available commit: {:?}",
                        (&mut owner).await
                    );
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        reader.rollback().await.unwrap();
        store.checkpoint_catalog().await.unwrap();
        let observed = f.machine.inspect().await.unwrap();
        assert_eq!(observed.status.label(), "hibernated");
        assert!(observed.run_id.is_none());
        assert_eq!(
            store
                .machine_hibernation(f.machine.machine_id())
                .await
                .unwrap()
                .unwrap(),
            record
        );
        record
    }

    #[tokio::test]
    async fn hibernation_capture_checkpoint_failure_compensates_before_rollback() {
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        let reader = blocked_checkpoint(&f).await;
        let error = tokio::time::timeout(Duration::from_secs(40), f.machine.hibernate())
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(error, LibVmError::HibernateFailed { .. }),
            "{error}"
        );
        assert!(!f
            .runtime
            .native_store()
            .unwrap()
            .has_hibernation(f.machine.machine_id())
            .await
            .unwrap());
        assert_eq!(
            f.machine.observe_live().await.unwrap().state().unwrap(),
            vm_spec::lifecycle::VmLifecycleState::Running
        );
        reader.rollback().await.unwrap();
        f.machine.kill().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_capture_available_prepared_recovery_compensates_live_source() {
        for paused in [false, true] {
            let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
            if paused {
                f.machine
                    .pause_and_wait(&f.machine.observe_live().await.unwrap())
                    .await
                    .unwrap();
            }
            let record = interrupted_available(&f).await;
            let (_lock, config) = f
                .runtime
                .lock_machine_config(f.machine.machine_id())
                .await
                .unwrap();
            let status = f
                .runtime
                .reconcile_machine_runtime_locked(&config)
                .await
                .unwrap();
            assert_eq!(
                status.state,
                if paused {
                    crate::store::models::MachineRuntimeState::Paused
                } else {
                    crate::store::models::MachineRuntimeState::Running
                }
            );
            assert!(!f
                .runtime
                .native_store()
                .unwrap()
                .has_hibernation(config.id)
                .await
                .unwrap());
            assert!(!f
                .runtime
                .native_store()
                .unwrap()
                .hibernation_directory(config.id, record.begin.save_id)
                .exists());
            assert!(!config
                .machine_dir
                .join(vm_spec::capture::CAPTURES_DIRECTORY)
                .join(record.begin.save_id.to_string())
                .exists());
            drop(_lock);
            f.machine.kill().await.unwrap();
        }
    }

    #[tokio::test]
    async fn hibernation_capture_available_unreachable_source_is_reaped_not_resumed() {
        use crate::store::MachineStore;
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        let record = interrupted_available(&f).await;
        assert!(f.monitor.signal(nix::sys::signal::Signal::SIGSTOP).unwrap());
        let (_lock, config) = f
            .runtime
            .lock_machine_config(f.machine.machine_id())
            .await
            .unwrap();
        let status = f
            .runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap();
        assert_eq!(
            status.state,
            crate::store::models::MachineRuntimeState::Hibernated
        );
        let store = f.runtime.native_store().unwrap();
        assert!(store.has_hibernation(config.id).await.unwrap());
        assert!(store
            .launch_storage_operations(config.id)
            .await
            .unwrap()
            .is_empty());
        assert!(!f.monitor.is_alive().unwrap());
        assert_eq!(
            std::fs::read_dir(store.hibernation_directory(config.id, record.begin.save_id))
                .unwrap()
                .count(),
            4
        );
        assert!(!config
            .machine_dir
            .join(vm_spec::capture::CAPTURES_DIRECTORY)
            .join(record.begin.save_id.to_string())
            .exists());
        drop(_lock);
        f.machine.kill().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_capture_native_wake_refusal_keeps_same_save_retryable() {
        use crate::store::MachineStore;
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        f.machine.hibernate().await.unwrap();
        let store = f.runtime.native_store().unwrap();
        let saved = store
            .machine_hibernation(f.machine.machine_id())
            .await
            .unwrap()
            .unwrap();
        let error = f.machine.start().await.unwrap_err();
        assert!(
            matches!(
                error,
                LibVmError::HibernateUnusable {
                    reason: crate::storage::hibernate_file::HibernateUnusableReason::NotCompatible,
                    ..
                }
            ),
            "{error}"
        );
        let after = store
            .machine_hibernation(f.machine.machine_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.begin.save_id, saved.begin.save_id);
        assert_eq!(
            after.phase,
            crate::store::hibernate::HibernatePhase::Available
        );
        assert!(store
            .launch_storage_operations(f.machine.machine_id())
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            f.machine.inspect().await.unwrap().status.label(),
            "hibernated"
        );
        f.machine.kill().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_capture_missing_or_replaced_trust_refuses_before_consume() {
        for replaced in [false, true] {
            let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
            f.machine.hibernate().await.unwrap();
            let id = f.machine.machine_id();
            crate::ssh_ca::delete_scope(f.runtime.secret_store(), id).unwrap();
            if replaced {
                crate::ssh_ca::resolve(f.runtime.secret_store(), id, true).unwrap();
            }
            let error = f.machine.start().await.unwrap_err();
            assert!(
                matches!(
                    error,
                    LibVmError::HibernateUnusable {
                        reason:
                            crate::storage::hibernate_file::HibernateUnusableReason::NotCompatible,
                        ..
                    }
                ),
                "{error}"
            );
            assert_eq!(
                f.machine.inspect().await.unwrap().status.label(),
                "hibernated"
            );
            assert_eq!(
                f.runtime
                    .native_store()
                    .unwrap()
                    .machine_hibernation(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .phase,
                crate::store::hibernate::HibernatePhase::Available
            );
            f.machine.kill().await.unwrap();
        }
    }

    #[tokio::test]
    async fn hibernation_capture_publish_after_authorization_timeout_is_compensated() {
        use crate::machine::hibernate::{id, record_envelope};
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        let record = interrupted_available(&f).await;
        let client = f.runtime.supervisor().client(f.machine.machine_id());
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                let status = client
                    .control_hibernate(
                        record_envelope(&record).unwrap(),
                        id(record.begin.save_id).unwrap(),
                        false,
                    )
                    .await
                    .unwrap();
                if status.phase == vm_spec::capture::HibernateCapturePhase::Failed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        let result = client
            .lifecycle(vm_spec::lifecycle::LiveCommand::ReleaseCapture(
                vm_spec::lifecycle::ReleaseCaptureCommand {
                    envelope: record_envelope(&record).unwrap(),
                    operation_id: id(record.begin.save_id).unwrap(),
                    disposition: vm_spec::capture::CaptureReleaseDisposition::Published,
                },
            ))
            .await
            .unwrap();
        assert!(!matches!(
            result,
            vm_spec::lifecycle::LiveCommandResult::ReleaseCapture(
                vm_spec::lifecycle::ReleaseCaptureOutcome::Released { .. }
            )
        ));
        let (_lock, config) = f
            .runtime
            .lock_machine_config(f.machine.machine_id())
            .await
            .unwrap();
        let status = f
            .runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap();
        assert_eq!(
            status.state,
            crate::store::models::MachineRuntimeState::Running
        );
        assert!(!f
            .runtime
            .native_store()
            .unwrap()
            .has_hibernation(config.id)
            .await
            .unwrap());
        drop(_lock);
        f.machine.kill().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_capture_busy_pause_is_refused_without_a_save() {
        let mut scenario = lifecycle();
        scenario.native_pause.push(test_utils::NativePauseStep {
            delay_ms: 1000,
            result: test_utils::NativePauseResult::Complete,
        });
        let f = CaptureFixture::new(scenario, MachineRetention::Persistent).await;
        let machine = f.machine.clone();
        let pause = tokio::spawn(async move {
            let observation = machine.observe_live().await?;
            machine.pause_and_wait(&observation).await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if f.machine.observe_live().await.unwrap().state().unwrap()
                    == vm_spec::lifecycle::VmLifecycleState::Pausing
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let error = f.machine.hibernate().await.unwrap_err();
        assert!(matches!(error, LibVmError::HibernateBusy { .. }), "{error}");
        assert!(!f
            .runtime
            .native_store()
            .unwrap()
            .has_hibernation(f.machine.machine_id())
            .await
            .unwrap());
        pause.await.unwrap().unwrap();
        f.machine.kill().await.unwrap();
    }
    #[tokio::test]
    async fn hibernation_access_binding_never_replays_between_file_steps() {
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        let admitted = f.machine.for_access(None).await.unwrap();
        admitted.running_config().await.unwrap();
        f.machine.hibernate().await.unwrap();
        for machine in [&admitted, &f.machine] {
            assert!(matches!(
                machine.get_file_entry("/").await,
                Err(LibVmError::MachineNotRunning { .. })
            ));
            assert_eq!(
                f.machine.inspect().await.unwrap().status.label(),
                "hibernated"
            );
        }
        assert!(matches!(
            admitted.for_access(None).await,
            Err(LibVmError::MachineNotRunning { .. })
        ));
        assert!(matches!(
            admitted.download_file("/file").await,
            Err(LibVmError::MachineNotRunning { .. })
        ));
        f.machine.kill().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_access_refuses_paused_and_stopped_without_resuming_or_booting() {
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        f.machine
            .pause(&f.machine.observe_live().await.unwrap())
            .await
            .unwrap();
        assert!(matches!(
            f.machine.for_access(None).await,
            Err(LibVmError::MachineNotRunning { .. })
        ));
        assert_eq!(f.machine.inspect().await.unwrap().status.label(), "paused");
        f.machine.kill().await.unwrap();
        assert!(matches!(
            f.machine.for_access(None).await,
            Err(LibVmError::MachineNotRunning { .. })
        ));
        assert_eq!(f.machine.inspect().await.unwrap().status.label(), "stopped");
    }

    #[tokio::test]
    async fn hibernation_pause_refusal_precedes_stale_observation() {
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        let observation = f.machine.observe_live().await.unwrap();
        f.machine.hibernate().await.unwrap();
        assert!(matches!(
            f.machine.pause(&observation).await,
            Err(LibVmError::HibernatedStartFirst { .. })
        ));
        assert!(matches!(
            f.runtime
                .observe_live_for_mutation(&crate::MachineRef::id(f.machine.machine_id()))
                .await,
            Err(LibVmError::HibernatedStartFirst { .. })
        ));
        assert_eq!(
            f.machine.inspect().await.unwrap().status.label(),
            "hibernated"
        );
        f.machine.kill().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_resume_refusal_precedes_stale_observation() {
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        let observation = f.machine.observe_live().await.unwrap();
        f.machine.hibernate().await.unwrap();
        assert!(matches!(
            f.machine.resume(&observation).await,
            Err(LibVmError::HibernatedStartFirst { .. })
        ));
        f.machine.kill().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_snapshot_refusal_precedes_live_observation() {
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        f.machine.hibernate().await.unwrap();
        assert!(matches!(
            f.runtime
                .snapshot(
                    &crate::MachineRef::id(f.machine.machine_id()),
                    crate::SnapshotOptions {
                        memory: true,
                        ..Default::default()
                    },
                    None,
                )
                .await,
            Err(LibVmError::HibernatedStartFirst { .. })
        ));
        f.machine.kill().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_fork_refusal_precedes_stale_observation() {
        let f = CaptureFixture::new(lifecycle(), MachineRetention::Persistent).await;
        let observation = f.machine.observe_live().await.unwrap();
        f.machine.hibernate().await.unwrap();
        let options = crate::LiveForkOptions {
            operation_id: uuid::Uuid::new_v4(),
            children: vec![crate::LiveForkChild {
                name: "child".into(),
                activation_hook: None,
                destination: Default::default(),
            }],
            max_children: std::num::NonZeroU32::MIN,
            resume_policy: vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired,
            policy: vm_spec::lifecycle::CapturePolicy::Incremental,
            dirty_crossover_percent: 60,
        };
        assert!(matches!(
            f.machine.fork_live(&observation, options, None).await,
            Err(LibVmError::HibernatedStartFirst { .. })
        ));
        f.machine.kill().await.unwrap();
    }
}
