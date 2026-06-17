use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::instance::prepare_instance_runtime;
use crate::lock_manager::{LockGuard, LockId, LockManager, ManagedLock};
use crate::paths::{root_disk_relative_path, vm_spec_path_in, LocalPaths, MachinePaths};
use crate::root_disk::{clone_or_copy_root_disk, resize_raw_disk};
use crate::runtime::{RuntimeConfig, RuntimeNetworkingConfig};
use bento_utils::format_storage_size;
use bento_vm_spec::{Boot, Disk, Guest, GuestOs, Hardware, Kernel, Mount, Storage, VmSpec};
use nix::{
    errno::Errno,
    sys::signal::{kill, Signal},
    unistd::Pid,
};

use crate::machine::{
    generate_machine_name, validate_machine_name, Machine, MachineCreate, MachineData, MachineRef,
    MachineRefKind, MachineStatus,
};
use crate::network::{
    prepare_network_runtime, reconcile_network_runtime, NetworkDefinition, VmmonNetworkAttachment,
};
use crate::runtime::transitions::{self, StartFailure, TransitionError};
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, MachineNetworkConfig as ModelMachineNetworkConfig, MachineRuntimeState,
    MachineState,
};
use crate::store::{ConfigStore, DataStore, Store};
use crate::utils::now_unix;
use crate::vmmon::exit_status::{self, VmmonExitOutcome, VmmonExitStatus};
use crate::vmmon::process::{self, ProcessIdentity};
use crate::vmmon::Vmmon;
use crate::LibVmError;

const DEFAULT_IMAGE_CPUS: u8 = 1;
const DEFAULT_IMAGE_MEMORY_MIB: u32 = 512;
const ROOT_DISK_KERNEL_ARG: &str = "root=/dev/vda";
const STALE_STARTING_TIMEOUT: Duration = Duration::from_secs(60);
const GENERATED_NAME_ATTEMPTS: u32 = 3;

/// Live runtime observation for a machine: its reconciled state plus the
/// start timestamp when running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeStatus {
    pub(crate) state: MachineRuntimeState,
    pub(crate) pid: Option<i32>,
    pub(crate) started_at: Option<i64>,
    pub(crate) run_id: Option<String>,
    pub(crate) last_error: Option<String>,
}

impl RuntimeStatus {
    fn from_machine_state(state: &MachineState) -> Self {
        Self {
            state: state.status,
            pid: state.vmmon_pid,
            started_at: state.started_at,
            run_id: state.run_id.clone(),
            last_error: state.last_error.clone(),
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        self.state.is_running()
    }

    pub(crate) fn is_active(&self) -> bool {
        matches!(
            self.state,
            MachineRuntimeState::Starting
                | MachineRuntimeState::Running
                | MachineRuntimeState::Stopping
        )
    }
}

#[derive(Debug, Clone)]
pub struct Runtime {
    paths: LocalPaths,
    store: Arc<dyn DataStore>,
    lock_manager: LockManager,
    networking: RuntimeNetworkingConfig,
    vmmon: Vmmon,
}

struct PendingMachine {
    id: MachineId,
    name: String,
    spec: VmSpec,
    staged_dir: PathBuf,
    final_dir: PathBuf,
    image_ref: String,
    root_disk_size: Option<u64>,
    labels: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    network: ModelMachineNetworkConfig,
    committed: bool,
}

struct PendingMachineRequest {
    name: String,
    spec: VmSpec,
    image_ref: String,
    root_disk_size: Option<u64>,
    labels: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    network: ModelMachineNetworkConfig,
}

/// Identity for one concrete vmmon run.
///
/// PID alone is not enough because host PIDs can be reused. When the platform
/// can expose process birth time we include it, and we also carry the runtime
/// run ID written into persisted state and vmmon exit files. Stop and cleanup
/// paths use this to avoid applying stale transitions to a newer machine run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmmonRunIdentity {
    pub(crate) pid: i32,
    pub(crate) started_at: Option<i64>,
    pub(crate) run_id: Option<String>,
}

impl Runtime {
    /// Opens a local runtime from explicit configuration.
    pub async fn new(config: RuntimeConfig) -> Result<Self, LibVmError> {
        let bootstrap_paths = config.bootstrap_paths()?;
        let store = Store::open(bootstrap_paths.state_db_path()).await?;
        let stored = match store.db_config().await? {
            Some(stored) => stored,
            None => {
                let seed = config.seed_db_config()?;
                store.read_or_seed_db_config(&seed).await?
            }
        };
        let roots = config.resolve_store_roots(&stored, bootstrap_paths.state_db_path())?;
        let paths = LocalPaths::from_roots(roots);
        Self::from_store(paths, Arc::new(store), config.networking).await
    }

    /// Opens the default local runtime from the process environment.
    pub async fn from_env() -> Result<Self, LibVmError> {
        Self::new(RuntimeConfig::from_env()?).await
    }

    #[cfg(test)]
    pub(crate) async fn open(
        paths: LocalPaths,
        networking: RuntimeNetworkingConfig,
    ) -> Result<Self, LibVmError> {
        let store = Store::new(&paths).await?;
        Self::from_store(paths, Arc::new(store), networking).await
    }

    async fn from_store(
        paths: LocalPaths,
        store: Arc<dyn DataStore>,
        networking: RuntimeNetworkingConfig,
    ) -> Result<Self, LibVmError> {
        let lock_manager = LockManager::open(paths.locks_dir().to_path_buf())?;
        let runtime = Self {
            paths,
            store,
            lock_manager,
            networking,
            vmmon: Vmmon::new(),
        };
        runtime.refresh_active_machine_states().await?;
        Ok(runtime)
    }

    /// Returns the local data directory.
    pub fn local_data_dir(&self) -> &Path {
        self.paths.data_dir()
    }

    /// Returns the local image directory.
    pub fn local_images_dir(&self) -> &Path {
        self.paths.images_dir()
    }

    pub(crate) fn machine_paths(&self, machine_id: MachineId) -> MachinePaths {
        self.paths.machine(machine_id)
    }

    pub(crate) fn vmmon(&self) -> Vmmon {
        self.vmmon
    }

    /// Creates a machine and returns an operable handle for it.
    ///
    /// When `request.name` is `None`, the runtime generates a valid random name
    /// and retries name-reservation conflicts up to three times. Explicit names
    /// are attempted once and preserve normal duplicate-name errors.
    pub async fn create_machine(&self, request: MachineCreate) -> Result<Machine, LibVmError> {
        let config = self.create_machine_config(request).await?;
        Ok(Machine::new(self.clone(), config.id))
    }

    pub(crate) async fn create_machine_config(
        &self,
        request: MachineCreate,
    ) -> Result<MachineConfig, LibVmError> {
        let Some(name) = request.name.clone() else {
            return self
                .create_machine_config_with_generated_name(request)
                .await;
        };

        self.create_machine_config_with_name(request, name).await
    }

    async fn create_machine_config_with_generated_name(
        &self,
        request: MachineCreate,
    ) -> Result<MachineConfig, LibVmError> {
        for _ in 0..GENERATED_NAME_ATTEMPTS {
            let name = generate_machine_name()?;
            match self
                .create_machine_config_with_name(request.clone(), name)
                .await
            {
                Err(LibVmError::MachineAlreadyExists { .. }) => {}
                result => return result,
            }
        }

        Err(LibVmError::MachineNameGenerationFailed {
            attempts: GENERATED_NAME_ATTEMPTS,
        })
    }

    async fn create_machine_config_with_name(
        &self,
        request: MachineCreate,
        name: String,
    ) -> Result<MachineConfig, LibVmError> {
        if matches!(request.disk_size_bytes, Some(0)) {
            return Err(LibVmError::InvalidCreateRequest {
                name,
                reason: "root disk size must be greater than 0".to_string(),
            });
        }

        let base_rootfs_path =
            canonicalize_existing_path(&request.base_rootfs_path, "base rootfs")?;
        let root_disk_size = request.disk_size_bytes.or_else(|| {
            fs::metadata(&base_rootfs_path)
                .ok()
                .map(|metadata| metadata.len())
        });
        if matches!(root_disk_size, Some(0)) {
            return Err(LibVmError::InvalidCreateRequest {
                name,
                reason: "root disk size must be greater than 0".to_string(),
            });
        }
        let kernel_path = canonicalize_optional_existing_path(request.kernel.as_deref(), "kernel")?;
        let initramfs_path =
            canonicalize_optional_existing_path(request.initramfs.as_deref(), "initramfs")?;
        if let Some(userdata) = request.userdata.as_deref() {
            if userdata.trim().is_empty() {
                return Err(LibVmError::InvalidCreateRequest {
                    name,
                    reason: "userdata cannot be empty".to_string(),
                });
            }
        }
        let userdata = request.userdata;
        let disk_paths = canonicalize_existing_paths(&request.disks, "disk")?;

        let resolved_cpus = request.cpus.unwrap_or(DEFAULT_IMAGE_CPUS);
        let resolved_memory = request.memory_mib.unwrap_or(DEFAULT_IMAGE_MEMORY_MIB);

        let mounts = assign_mount_tags(request.mounts);
        let disks = std::iter::once(Disk {
            path: root_disk_relative_path(),
            read_only: false,
        })
        .chain(disk_paths.into_iter().map(|path| Disk {
            path,
            read_only: false,
        }))
        .collect();

        let spec = VmSpec {
            guest: Some(Guest {
                os: Some(GuestOs::Linux),
            }),
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: kernel_path,
                    cmdline: vec![ROOT_DISK_KERNEL_ARG.to_string()],
                    initramfs: initramfs_path,
                }),
                userdata,
            }),
            hardware: Some(Hardware {
                cpus: Some(resolved_cpus),
                memory: Some(resolved_memory),
                nested_virtualization: Some(request.nested_virtualization),
                rosetta: Some(request.rosetta),
            }),
            storage: Some(Storage { disks }),
            mounts,
            ..VmSpec::current()
        };

        let network = request.network.unwrap_or_default().into();
        self.validate_machine_network_config(&network).await?;
        let pending = self
            .create_pending(PendingMachineRequest {
                name,
                spec,
                image_ref: request.image_ref.clone(),
                root_disk_size,
                labels: request.labels,
                metadata: request.metadata,
                network,
            })
            .await?;
        let rootfs_path = MachinePaths::new(pending.dir()).root_disk_path();
        clone_or_copy_root_disk(&base_rootfs_path, &rootfs_path)?;

        if let Some(size_bytes) = request.disk_size_bytes {
            resize_raw_disk(&rootfs_path, size_bytes)?;
        }

        pending.commit(self).await
    }

    async fn create_pending(
        &self,
        request: PendingMachineRequest,
    ) -> Result<PendingMachine, LibVmError> {
        let PendingMachineRequest {
            name,
            spec,
            image_ref,
            root_disk_size,
            labels,
            metadata,
            network,
        } = request;
        validate_machine_name(&name)?;

        if self
            .store
            .machine_config_by_name(name.as_str())
            .await?
            .is_some()
        {
            return Err(LibVmError::MachineAlreadyExists { name });
        }

        let id = MachineId::new();
        let final_dir = self.paths.machine(id).dir().to_path_buf();
        if final_dir.exists() {
            return Err(LibVmError::MachineIdAlreadyExists { id: id.to_string() });
        }

        let staged_dir = create_staging_dir(&self.paths)?;
        write_machine_config(&staged_dir, &name, &spec)?;

        Ok(PendingMachine {
            id,
            name,
            spec,
            staged_dir,
            final_dir,
            image_ref,
            root_disk_size,
            labels,
            metadata,
            network,
            committed: false,
        })
    }

    /// Resolves a machine by name, full ID, or ID prefix.
    pub async fn get_machine(&self, machine: &MachineRef) -> Result<Machine, LibVmError> {
        let config = self.resolve_machine_config(machine).await?;
        Ok(Machine::new(self.clone(), config.id))
    }

    /// Lists known machines as operable handles.
    pub async fn list_machines(&self) -> Result<Vec<Machine>, LibVmError> {
        let configs = self.list_machine_configs().await?;
        Ok(configs
            .into_iter()
            .map(|config| Machine::new(self.clone(), config.id))
            .collect())
    }

    pub(crate) async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError> {
        let machines = self.store.list_machine_configs().await?;
        for config in &machines {
            self.reconcile_machine_runtime_best_effort(config).await?;
        }
        Ok(machines)
    }

    /// Creates a named network definition.
    pub async fn create_network_definition(
        &self,
        definition: NetworkDefinition,
    ) -> Result<(), LibVmError> {
        definition
            .validate()
            .map_err(|reason| LibVmError::InvalidCreateRequest {
                name: definition.name.clone(),
                reason,
            })?;
        self.store.define_network(&definition.into()).await
    }

    /// Lists all named network definitions.
    pub async fn list_network_definitions(&self) -> Result<Vec<NetworkDefinition>, LibVmError> {
        Ok(self
            .store
            .list_network_definitions()
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Returns a named network definition when it exists.
    pub async fn get_network_definition(
        &self,
        name: &str,
    ) -> Result<Option<NetworkDefinition>, LibVmError> {
        Ok(self.store.network_definition(name).await?.map(Into::into))
    }

    /// Removes a named network definition.
    pub async fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError> {
        self.store.remove_network_definition(name).await
    }

    pub(crate) async fn resolve_machine_config(
        &self,
        machine: &MachineRef,
    ) -> Result<MachineConfig, LibVmError> {
        match machine.kind() {
            MachineRefKind::Id(id) => {
                self.store
                    .machine_config(*id)
                    .await?
                    .ok_or_else(|| LibVmError::MachineNotFound {
                        reference: id.to_string(),
                    })
            }
            MachineRefKind::Name(name) => self
                .store
                .machine_config_by_name(name)
                .await?
                .ok_or_else(|| LibVmError::MachineNotFound {
                    reference: name.clone(),
                }),
            MachineRefKind::IdPrefix(prefix) => {
                let matches = self.store.machine_configs_by_id_prefix(prefix).await?;
                match matches.len() {
                    0 => Err(LibVmError::MachineNotFound {
                        reference: prefix.clone(),
                    }),
                    1 => Ok(matches.into_iter().next().expect("just checked len == 1")),
                    count => Err(LibVmError::AmbiguousIdPrefix {
                        prefix: prefix.clone(),
                        count,
                    }),
                }
            }
        }
    }

    pub(crate) async fn lock_machine_config(
        &self,
        machine_id: MachineId,
    ) -> Result<(LockGuard, MachineConfig), LibVmError> {
        let initial = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let lock = self.acquire_machine_lock(initial.lock_id).await?;
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        if config.lock_id != initial.lock_id {
            return Err(io::Error::other(format!(
                "machine {machine_id} lock id changed from {} to {} while acquiring lock",
                initial.lock_id, config.lock_id
            ))
            .into());
        }
        Ok((lock, config))
    }

    async fn acquire_machine_lock(&self, lock_id: LockId) -> Result<LockGuard, LibVmError> {
        self.acquire_lock(self.lock_manager.retrieve(lock_id)).await
    }

    async fn acquire_lock(&self, lock: ManagedLock) -> Result<LockGuard, LibVmError> {
        let lock = tokio::task::spawn_blocking(move || lock.lock())
            .await
            .map_err(|err| io::Error::other(format!("join lock task: {err}")))??;
        Ok(lock)
    }

    fn try_acquire_machine_lock(&self, lock_id: LockId) -> Result<Option<LockGuard>, LibVmError> {
        Ok(self.lock_manager.retrieve(lock_id).try_lock()?)
    }

    pub(crate) async fn reconcile_machine_runtime_best_effort(
        &self,
        metadata: &MachineConfig,
    ) -> Result<RuntimeStatus, LibVmError> {
        let persisted = self.store.machine_state(metadata.id).await?;
        let observed = self
            .observe_machine_state(metadata, persisted.as_ref())
            .await?;
        if machine_state_needs_writeback(persisted.as_ref(), &observed) {
            let Some(_lock) = self.try_acquire_machine_lock(metadata.lock_id)? else {
                let state = self.machine_state(metadata.id).await?;
                return Ok(RuntimeStatus::from_machine_state(&state));
            };
            return self.reconcile_machine_runtime_locked(metadata).await;
        }
        Ok(RuntimeStatus::from_machine_state(&observed))
    }

    pub(crate) async fn reconcile_machine_runtime_locked(
        &self,
        metadata: &MachineConfig,
    ) -> Result<RuntimeStatus, LibVmError> {
        let persisted = self.store.machine_state(metadata.id).await?;
        let observed = self
            .observe_machine_state(metadata, persisted.as_ref())
            .await?;
        if machine_state_needs_writeback(persisted.as_ref(), &observed) {
            self.store.save_machine_state(&observed).await?;
        }
        Ok(RuntimeStatus::from_machine_state(&observed))
    }

    async fn refresh_active_machine_states(&self) -> Result<(), LibVmError> {
        for config in self.store.list_machine_configs().await? {
            let state = self.machine_state(config.id).await?;
            if !RuntimeStatus::from_machine_state(&state).is_active() {
                continue;
            }

            let Some(_lock) = self.try_acquire_machine_lock(config.lock_id)? else {
                continue;
            };
            let status = self.reconcile_machine_runtime_locked(&config).await?;
            reconcile_network_runtime(
                &self.paths,
                self.store.as_ref(),
                &config,
                status.is_active(),
            )
            .await?;
        }
        Ok(())
    }

    async fn observe_machine_state(
        &self,
        metadata: &MachineConfig,
        runtime: Option<&MachineState>,
    ) -> Result<MachineState, LibVmError> {
        let pid_path = self.paths.machine(metadata.id).vmmon_pid_path();
        let exit_status_path = self.paths.machine(metadata.id).vmmon_exit_status_path();
        let pid_from_file = match read_monitor_pid(&pid_path) {
            Ok(pid) => Some(pid),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err.into()),
        };
        let stored_pid = runtime.and_then(|runtime| runtime.vmmon_pid);
        let expected_started_at = runtime.and_then(|runtime| runtime.started_at);
        let live_identity = live_monitor_identity(pid_from_file, stored_pid, expected_started_at)?;
        let live_pid = live_identity.as_ref().map(ProcessIdentity::pid);

        let current_state = runtime
            .map(|runtime| runtime.status)
            .unwrap_or(MachineRuntimeState::Stopped);
        let exit_status = exit_status::read(&exit_status_path)?;
        let matching_exit = exit_status
            .as_ref()
            .filter(|status| runtime_exit_matches(status, runtime))
            .filter(|_| live_pid.is_none());
        let stale_starting = current_state == MachineRuntimeState::Starting
            && live_pid.is_none()
            && runtime.is_some_and(|runtime| state_is_older_than(runtime, STALE_STARTING_TIMEOUT));
        let stored_state = runtime
            .cloned()
            .unwrap_or_else(|| stopped_machine_state(metadata.id, None));
        let observed_state = match matching_exit {
            Some(status) => {
                let (clean, error) = exit_observed_event(status);
                transitions::reduce(
                    stored_state,
                    transitions::Event::ExitObserved { clean, error },
                    now_unix(),
                )
                .map_err(transition_error)?
            }
            None => match live_pid {
                Some(pid) => {
                    let started_at = live_identity
                        .as_ref()
                        .and_then(ProcessIdentity::started_at)
                        .or_else(|| runtime.and_then(|runtime| runtime.started_at))
                        .unwrap_or_else(|| pid_file_mtime(&pid_path));
                    let run_id = runtime.and_then(|runtime| runtime.run_id.clone());
                    transitions::reduce(
                        stored_state,
                        transitions::Event::MonitorObserved {
                            pid,
                            started_at,
                            run_id,
                        },
                        now_unix(),
                    )
                    .map_err(transition_error)?
                }
                None if stale_starting => {
                    transitions::reduce(stored_state, transitions::Event::StartTimedOut, now_unix())
                        .map_err(transition_error)?
                }
                None if current_state == MachineRuntimeState::Starting => MachineState {
                    vmmon_pid: None,
                    started_at: None,
                    last_error: None,
                    updated_at: now_unix(),
                    ..stored_state
                },
                None => {
                    let last_error = runtime.and_then(|runtime| runtime.last_error.clone());
                    transitions::reduce(
                        stored_state,
                        transitions::Event::MonitorGone { last_error },
                        now_unix(),
                    )
                    .map_err(transition_error)?
                }
            },
        };
        Ok(observed_state)
    }

    pub(crate) async fn set_machine_state(
        &self,
        machine_id: MachineId,
        status: MachineRuntimeState,
        vmmon_pid: Option<i32>,
        started_at: Option<i64>,
        run_id: Option<String>,
        last_error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.store
            .save_machine_state(&MachineState {
                machine_id,
                status,
                vmmon_pid,
                started_at,
                run_id,
                last_error,
                updated_at: now_unix(),
            })
            .await
    }

    async fn transition_current_machine_state(
        &self,
        machine_id: MachineId,
        event: transitions::Event,
    ) -> Result<MachineState, LibVmError> {
        let state = self.machine_state(machine_id).await?;
        self.transition_machine_state(state, event).await
    }

    async fn transition_machine_state(
        &self,
        state: MachineState,
        event: transitions::Event,
    ) -> Result<MachineState, LibVmError> {
        let next = transitions::reduce(state, event, now_unix()).map_err(transition_error)?;
        self.store.save_machine_state(&next).await?;
        Ok(next)
    }

    pub(crate) async fn request_machine_start(
        &self,
        machine_id: MachineId,
        run_id: &str,
    ) -> Result<(), LibVmError> {
        self.transition_current_machine_state(
            machine_id,
            transitions::Event::StartRequested {
                run_id: run_id.to_string(),
            },
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn mark_machine_monitor_ready(
        &self,
        machine_id: MachineId,
        run_id: String,
        pid: i32,
        started_at: i64,
    ) -> Result<(), LibVmError> {
        self.transition_current_machine_state(
            machine_id,
            transitions::Event::MonitorReady {
                run_id,
                pid,
                started_at,
            },
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn mark_machine_start_stopped(
        &self,
        machine_id: MachineId,
        run_id: &str,
        error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.mark_machine_start_failed(machine_id, run_id, StartFailure::Stopped, error)
            .await
    }

    pub(crate) async fn mark_machine_start_error(
        &self,
        machine_id: MachineId,
        run_id: &str,
        error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.mark_machine_start_failed(machine_id, run_id, StartFailure::Error, error)
            .await
    }

    async fn mark_machine_start_failed(
        &self,
        machine_id: MachineId,
        run_id: &str,
        failure: StartFailure,
        error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.transition_current_machine_state(
            machine_id,
            transitions::Event::StartFailed {
                run_id: run_id.to_string(),
                failure,
                error,
            },
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn mark_machine_stopped(
        &self,
        machine_id: MachineId,
        last_error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.set_machine_state(
            machine_id,
            MachineRuntimeState::Stopped,
            None,
            None,
            None,
            last_error,
        )
        .await
    }

    pub(crate) async fn request_machine_stop(
        &self,
        machine_id: MachineId,
        generation: &VmmonRunIdentity,
    ) -> Result<(), LibVmError> {
        self.transition_current_machine_state(
            machine_id,
            transitions::Event::StopRequested {
                pid: generation.pid,
                started_at: generation.started_at,
                run_id: generation.run_id.clone(),
            },
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn complete_stop_locked(
        &self,
        config: &MachineConfig,
        generation: VmmonRunIdentity,
        last_error: Option<String>,
    ) -> Result<(), LibVmError> {
        let state = self.machine_state(config.id).await?;
        if !vmmon_run_identity_matches(&state, &generation) {
            return Ok(());
        }

        if vmmon_run_is_alive(&generation)? {
            return Ok(());
        }

        let next = match transitions::reduce(
            state,
            transitions::Event::StopCompleted {
                pid: generation.pid,
                started_at: generation.started_at,
                run_id: generation.run_id,
                last_error,
            },
            now_unix(),
        ) {
            Ok(next) => next,
            Err(TransitionError::StaleGeneration) => return Ok(()),
            Err(err) => return Err(transition_error(err)),
        };
        self.store.save_machine_state(&next).await?;
        self.cleanup_machine_resources_locked(config).await
    }

    pub(crate) async fn cleanup_machine_resources_locked(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        reconcile_network_runtime(&self.paths, self.store.as_ref(), config, false).await
    }

    pub(crate) async fn validate_machine_network_config(
        &self,
        network: &ModelMachineNetworkConfig,
    ) -> Result<(), LibVmError> {
        if let ModelMachineNetworkConfig::Named { name } = network {
            self.store.network_definition(name).await?.ok_or_else(|| {
                LibVmError::NetworkRuntime {
                    reference: name.clone(),
                    message: format!("named network {:?} is not defined", name),
                }
            })?;
        }
        Ok(())
    }

    pub(crate) async fn prepare_machine_network(
        &self,
        config: &MachineConfig,
    ) -> Result<VmmonNetworkAttachment, LibVmError> {
        prepare_network_runtime(&self.paths, self.store.as_ref(), config, &self.networking).await
    }

    pub(crate) async fn reconcile_machine_network(
        &self,
        config: &MachineConfig,
        monitor_running: bool,
    ) -> Result<(), LibVmError> {
        reconcile_network_runtime(&self.paths, self.store.as_ref(), config, monitor_running).await
    }

    pub(crate) fn prepare_machine_instance_runtime(
        &self,
        config: &MachineConfig,
        spec: &mut VmSpec,
        network: &VmmonNetworkAttachment,
    ) -> Result<(), LibVmError> {
        prepare_instance_runtime(
            &self.paths,
            &config.instance_dir,
            &config.name,
            spec,
            network,
            &self.networking,
        )
        .map_err(|err| LibVmError::InstancePreparationFailed {
            reference: config.name.clone(),
            message: err.to_string(),
        })
    }

    pub(crate) fn remove_vmmon_exit_status(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        let exit_status_path = self.machine_paths(config.id).vmmon_exit_status_path();
        exit_status::remove(&exit_status_path)?;
        Ok(())
    }

    pub(crate) async fn save_machine_config(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        self.store.save_machine_config(config).await
    }

    pub(crate) async fn machine_config_by_name(
        &self,
        name: &str,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        self.store.machine_config_by_name(name).await
    }

    pub(crate) async fn remove_machine_records(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        self.store.remove_machine(config).await?;
        self.lock_manager.free(config.lock_id)?;
        Ok(())
    }

    pub(crate) async fn machine_state(
        &self,
        machine_id: MachineId,
    ) -> Result<MachineState, LibVmError> {
        if let Some(state) = self.store.machine_state(machine_id).await? {
            return Ok(state);
        }

        Ok(stopped_machine_state(machine_id, None))
    }

    pub(crate) async fn machine_inspect_data(
        &self,
        config: MachineConfig,
    ) -> Result<MachineData, LibVmError> {
        let runtime_status = self.reconcile_machine_runtime_best_effort(&config).await?;
        let state = self.machine_state(config.id).await?;
        let status = if runtime_status.is_running() {
            let socket_path = self.machine_paths(config.id).vmmon_socket_path();
            match self.vmmon.inspect(&socket_path).await {
                Ok(response) => MachineStatus::from_protocol(response),
                Err(message) => {
                    MachineStatus::running_with_message(format!("vmmon inspect failed: {message}"))
                }
            }
        } else {
            MachineStatus::from_machine_state(state.status, state.last_error.clone())
        };

        Ok(MachineData::from_models_with_status(
            config,
            status,
            state.started_at,
            state.last_error,
            state.updated_at,
        ))
    }
}

pub(crate) fn write_machine_config(
    instance_dir: &Path,
    name: &str,
    spec: &VmSpec,
) -> Result<(), LibVmError> {
    let config =
        serde_json::to_string_pretty(spec).map_err(|source| LibVmError::VmSpecSerializeFailed {
            name: name.to_string(),
            source,
        })?;
    fs::write(vm_spec_path_in(instance_dir), config)?;
    Ok(())
}

pub(crate) fn empty_hardware() -> Hardware {
    Hardware {
        cpus: None,
        memory: None,
        nested_virtualization: None,
        rosetta: None,
    }
}

pub(crate) fn validate_root_disk_growth(
    config: &MachineConfig,
    desired_size: u64,
) -> Result<(), LibVmError> {
    let root_disk_path = MachinePaths::new(&config.instance_dir).root_disk_path();
    let current_size = fs::metadata(&root_disk_path)?.len();
    if desired_size < current_size {
        return Err(LibVmError::InvalidMachineUpdate {
            reference: config.name.clone(),
            reason: format!(
                "root disk cannot be shrunk from {} to {}",
                format_storage_size(current_size),
                format_storage_size(desired_size)
            ),
        });
    }
    Ok(())
}

pub(crate) fn reconcile_root_disk_size(config: &MachineConfig) -> Result<(), LibVmError> {
    let Some(desired_size) = config.root_disk_size else {
        return Ok(());
    };

    let root_disk_path = MachinePaths::new(&config.instance_dir).root_disk_path();
    resize_raw_disk(&root_disk_path, desired_size)?;
    Ok(())
}

fn assign_mount_tags(mounts: Vec<Mount>) -> Vec<Mount> {
    mounts
        .into_iter()
        .enumerate()
        .map(|(index, mut mount)| {
            if mount.tag.trim().is_empty() {
                mount.tag = format!("mount{index}");
            }
            mount
        })
        .collect()
}

fn canonicalize_optional_existing_path(
    path: Option<&Path>,
    kind: &str,
) -> Result<Option<PathBuf>, LibVmError> {
    let Some(path) = path else {
        return Ok(None);
    };

    Ok(Some(canonicalize_existing_path(path, kind)?))
}

fn canonicalize_existing_paths(paths: &[PathBuf], kind: &str) -> Result<Vec<PathBuf>, LibVmError> {
    paths
        .iter()
        .map(|path| canonicalize_existing_path(path, kind))
        .collect()
}

fn canonicalize_existing_path(path: &Path, kind: &str) -> Result<PathBuf, LibVmError> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    std::fs::canonicalize(&abs).map_err(|err| LibVmError::InvalidCreateRequest {
        name: kind.to_string(),
        reason: format!("{kind} path does not exist: {} ({err})", abs.display()),
    })
}

pub(crate) async fn wait_for_monitor_stop(
    generation: &VmmonRunIdentity,
    machine_name: &str,
) -> Result<(), LibVmError> {
    let timeout = std::time::Duration::from_secs(45);
    let poll_interval = std::time::Duration::from_millis(200);
    let Some(identity) = ProcessIdentity::for_pid(generation.pid)? else {
        return Ok(());
    };
    if !identity.matches_started_at(generation.started_at) {
        return Ok(());
    }

    process::wait_for_exit(&identity, machine_name, timeout, poll_interval)
        .await
        .map_err(Into::into)
}

pub(crate) fn read_monitor_pid(pid_path: &Path) -> io::Result<i32> {
    let raw = fs::read_to_string(pid_path)?;
    let trimmed = raw.trim();
    let pid = trimmed.parse::<i32>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse monitor pid from {}: {err}", pid_path.display()),
        )
    })?;
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("monitor pid in {} must be positive", pid_path.display()),
        ));
    }
    Ok(pid)
}

fn live_monitor_identity(
    pid_from_file: Option<i32>,
    stored_pid: Option<i32>,
    expected_started_at: Option<i64>,
) -> Result<Option<ProcessIdentity>, LibVmError> {
    let mut last_pid = None;
    for pid in [pid_from_file, stored_pid].into_iter().flatten() {
        if last_pid == Some(pid) {
            continue;
        }
        last_pid = Some(pid);

        let Some(identity) = ProcessIdentity::for_pid(pid)? else {
            continue;
        };
        if identity.matches_started_at(expected_started_at) {
            return Ok(Some(identity));
        }
    }

    Ok(None)
}

pub(crate) fn monitor_started_at(
    pid: i32,
    pid_path: &Path,
    machine_name: &str,
) -> Result<i64, LibVmError> {
    let Some(identity) = ProcessIdentity::for_pid(pid)? else {
        return Err(LibVmError::MonitorConnection {
            reference: machine_name.to_string(),
            message: format!("vmmon pid {pid} from {} is not running", pid_path.display()),
        });
    };

    Ok(identity
        .started_at()
        .unwrap_or_else(|| pid_file_mtime(pid_path)))
}

fn runtime_exit_matches(status: &VmmonExitStatus, state: Option<&MachineState>) -> bool {
    let Some(state) = state else {
        return true;
    };

    if let Some(run_id) = status.run_id.as_deref() {
        return state.run_id.as_deref() == Some(run_id);
    }

    match status.pid {
        Some(pid) => state.vmmon_pid == Some(pid),
        None => true,
    }
}

fn exit_observed_event(status: &VmmonExitStatus) -> (bool, Option<String>) {
    let _ = status.exited_at;
    match status.outcome {
        VmmonExitOutcome::Clean => (true, None),
        VmmonExitOutcome::Error => (false, status.error.clone()),
    }
}

fn state_is_older_than(state: &MachineState, age: Duration) -> bool {
    let age = i64::try_from(age.as_secs()).unwrap_or(i64::MAX);
    now_unix().saturating_sub(state.updated_at) >= age
}

fn machine_state_needs_writeback(
    persisted: Option<&MachineState>,
    observed: &MachineState,
) -> bool {
    let Some(persisted) = persisted else {
        return true;
    };

    persisted.status != observed.status
        || persisted.vmmon_pid != observed.vmmon_pid
        || persisted.started_at != observed.started_at
        || persisted.run_id.as_deref() != observed.run_id.as_deref()
        || persisted.last_error.as_deref() != observed.last_error.as_deref()
}

fn vmmon_run_identity_matches(state: &MachineState, generation: &VmmonRunIdentity) -> bool {
    if let Some(run_id) = generation.run_id.as_deref() {
        if state.run_id.as_deref() != Some(run_id) {
            return false;
        }
    }

    if state.vmmon_pid != Some(generation.pid) {
        return false;
    }

    match generation.started_at {
        Some(started_at) => state.started_at == Some(started_at),
        None => true,
    }
}

fn vmmon_run_is_alive(generation: &VmmonRunIdentity) -> Result<bool, LibVmError> {
    let Some(identity) = ProcessIdentity::for_pid(generation.pid)? else {
        return Ok(false);
    };
    Ok(identity.matches_started_at(generation.started_at))
}

fn transition_error(err: TransitionError) -> LibVmError {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string()).into()
}

pub(crate) fn interrupt_monitor(pid: i32) -> io::Result<bool> {
    match kill(Pid::from_raw(pid), Some(Signal::SIGINT)) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}

pub(crate) fn pid_file_mtime(pid_path: &Path) -> i64 {
    std::fs::metadata(pid_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn stopped_machine_state(machine_id: MachineId, last_error: Option<String>) -> MachineState {
    MachineState {
        machine_id,
        status: MachineRuntimeState::Stopped,
        vmmon_pid: None,
        started_at: None,
        run_id: None,
        last_error,
        updated_at: now_unix(),
    }
}

impl PendingMachine {
    fn dir(&self) -> &Path {
        &self.staged_dir
    }

    async fn commit(mut self, runtime: &Runtime) -> Result<MachineConfig, LibVmError> {
        if self.final_dir.exists() {
            return Err(LibVmError::MachineIdAlreadyExists {
                id: self.id.to_string(),
            });
        }

        if let Some(parent) = self.final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&self.staged_dir, &self.final_dir)?;

        let lock = match runtime.lock_manager.allocate() {
            Ok(lock) => lock,
            Err(err) => {
                let _ = fs::remove_dir_all(&self.final_dir);
                return Err(err.into());
            }
        };

        let now = now_unix();
        let config = MachineConfig {
            id: self.id,
            lock_id: lock.id(),
            name: self.name.clone(),
            spec: self.spec.clone(),
            instance_dir: self.final_dir.clone(),
            created_at: now,
            modified_at: now,
            image_ref: self.image_ref.clone(),
            root_disk_size: self.root_disk_size,
            labels: self.labels.clone(),
            metadata: self.metadata.clone(),
            network: self.network.clone(),
        };
        let initial_state = stopped_machine_state(self.id, None);
        if let Err(err) = runtime.store.add_machine(&config, &initial_state).await {
            let _ = lock.free();
            let _ = fs::remove_dir_all(&self.final_dir);
            return Err(err);
        }

        self.committed = true;
        Ok(config)
    }
}

impl Drop for PendingMachine {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        match fs::remove_dir_all(&self.staged_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
}

fn create_staging_dir(paths: &LocalPaths) -> Result<PathBuf, LibVmError> {
    let staging_root = paths.staging_dir();
    fs::create_dir_all(&staging_root)?;

    for attempt in 0..256u32 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| LibVmError::InvalidMachineName {
                name: "staging".to_string(),
                reason: format!("system clock error while creating staging dir: {err}"),
            })?
            .as_nanos();
        let candidate = staging_root.join(format!("{}-{timestamp}-{attempt}", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(LibVmError::InvalidMachineName {
        name: "staging".to_string(),
        reason: "failed to allocate unique staging directory".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use crate::lock_manager::LockId;
    use crate::machine::{validate_machine_name, MachineRefKind};
    use crate::paths::{root_disk_relative_path, LocalPaths};
    use crate::runtime::core::{
        assign_mount_tags, read_monitor_pid, write_machine_config, PendingMachine,
        PendingMachineRequest, Runtime, ROOT_DISK_KERNEL_ARG, STALE_STARTING_TIMEOUT,
    };
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRuntimeState, MachineState,
    };
    use crate::store::MockDataStore;
    use crate::utils::now_unix;
    use crate::vmmon::process::ProcessIdentity;
    use crate::{
        LibVmError, MachineCreate, MachineRef, MachineStatus, MachineUpdate,
        RuntimeNetworkingConfig,
    };
    use bento_vm_spec::{Boot, Guest, GuestOs, Hardware, Kernel, Mount, Storage, VmSpec};
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn sample_vm_spec() -> VmSpec {
        VmSpec {
            guest: Some(Guest {
                os: Some(GuestOs::Linux),
            }),
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: None,
                    cmdline: Vec::new(),
                    initramfs: None,
                }),
                userdata: None,
            }),
            hardware: Some(Hardware {
                cpus: Some(4),
                memory: Some(4096),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            }),
            ..VmSpec::current()
        }
    }

    fn spec_kernel(spec: &VmSpec) -> &Kernel {
        spec.boot
            .as_ref()
            .and_then(|boot| boot.kernel.as_ref())
            .expect("spec should have kernel section")
    }

    fn spec_hardware(spec: &VmSpec) -> &Hardware {
        spec.hardware
            .as_ref()
            .expect("spec should have hardware section")
    }

    fn spec_hardware_mut(spec: &mut VmSpec) -> &mut Hardware {
        spec.hardware
            .as_mut()
            .expect("spec should have hardware section")
    }

    fn spec_storage(spec: &VmSpec) -> &Storage {
        spec.storage
            .as_ref()
            .expect("spec should have storage section")
    }

    fn spec_userdata(spec: &VmSpec) -> Option<&str> {
        spec.boot.as_ref().and_then(|boot| boot.userdata.as_deref())
    }

    fn sample_machine_config(paths: &LocalPaths, id: MachineId, name: &str) -> MachineConfig {
        MachineConfig {
            id,
            lock_id: LockId::from(0),
            name: name.to_string(),
            spec: sample_vm_spec(),
            instance_dir: paths.machine(id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: "test-image:latest".to_string(),
            root_disk_size: None,
            labels: std::collections::BTreeMap::new(),
            metadata: std::collections::BTreeMap::new(),
            network: MachineNetworkConfig::default(),
        }
    }

    fn stopped_state(machine_id: MachineId) -> MachineState {
        MachineState {
            machine_id,
            status: MachineRuntimeState::Stopped,
            vmmon_pid: None,
            started_at: None,
            run_id: None,
            last_error: None,
            updated_at: 1,
        }
    }

    fn expect_empty_refresh(store: &mut MockDataStore) {
        store
            .expect_list_machine_configs()
            .once()
            .returning(|| Ok(Vec::new()));
    }

    async fn runtime_with_mock_store(paths: LocalPaths, store: MockDataStore) -> Runtime {
        Runtime::from_store(paths, Arc::new(store), RuntimeNetworkingConfig::default())
            .await
            .expect("create runtime with mock store")
    }

    async fn create_pending_sample(
        runtime: &Runtime,
        name: &str,
    ) -> Result<PendingMachine, LibVmError> {
        runtime
            .create_pending(PendingMachineRequest {
                name: name.to_string(),
                spec: sample_vm_spec(),
                image_ref: "test-image:latest".to_string(),
                root_disk_size: None,
                labels: std::collections::BTreeMap::new(),
                metadata: std::collections::BTreeMap::new(),
                network: crate::store::models::MachineNetworkConfig::default(),
            })
            .await
    }

    fn create_request(base_rootfs_path: PathBuf, name: &str) -> MachineCreate {
        MachineCreate {
            image_ref: "ghcr.io/vandycknick/archlinuxarm:latest".to_string(),
            base_rootfs_path,
            name: Some(name.to_string()),
            labels: std::collections::BTreeMap::new(),
            metadata: std::collections::BTreeMap::new(),
            cpus: None,
            memory_mib: None,
            kernel: None,
            initramfs: None,
            disk_size_bytes: None,
            nested_virtualization: false,
            rosetta: false,
            userdata: None,
            disks: Vec::new(),
            mounts: Vec::new(),
            network: None,
        }
    }

    fn write_base_rootfs(data_dir: &std::path::Path) -> PathBuf {
        let image_dir = data_dir.join("images/sha256-test/linux-arm64");
        std::fs::create_dir_all(&image_dir).expect("image dir should be created");
        let base_rootfs_path = image_dir.join("rootfs.img");
        std::fs::write(&base_rootfs_path, b"disk").expect("rootfs should be written");
        base_rootfs_path
    }

    fn write_base_rootfs_with_size(data_dir: &Path, size: u64) -> PathBuf {
        let image_dir = data_dir.join("images/sha256-test/linux-arm64");
        std::fs::create_dir_all(&image_dir).expect("image dir should be created");
        let base_rootfs_path = image_dir.join("rootfs.img");
        let file = std::fs::File::create(&base_rootfs_path).expect("rootfs should be created");
        file.set_len(size).expect("rootfs size should be set");
        base_rootfs_path
    }

    struct ChildGuard {
        child: std::process::Child,
    }

    impl ChildGuard {
        fn sleep() -> Self {
            let child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn sleep process");
            Self { child }
        }

        fn sleep_ignoring_sigint() -> Self {
            let mut child = std::process::Command::new("python3")
                .arg("-c")
                .arg(
                    "import signal, sys, time; \
                     signal.signal(signal.SIGINT, signal.SIG_IGN); \
                     sys.stdout.write('r'); sys.stdout.flush(); \
                     time.sleep(30)",
                )
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("spawn signal-resistant sleep process");
            let mut stdout = child.stdout.take().expect("child stdout should be piped");
            let mut ready = [0_u8; 1];
            stdout
                .read_exact(&mut ready)
                .expect("child should report readiness");
            Self { child }
        }

        fn id(&self) -> u32 {
            self.child.id()
        }

        fn started_at(&self) -> Option<i64> {
            ProcessIdentity::for_pid(self.id() as i32)
                .expect("read child process identity")
                .expect("child process should exist")
                .started_at()
        }

        fn kill(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            self.kill();
        }
    }

    async fn wait_for_machine_state(
        runtime: &Runtime,
        machine_id: MachineId,
        expected: MachineRuntimeState,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = runtime
                    .machine_state(machine_id)
                    .await
                    .expect("read machine state");
                if state.status == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("machine state should change before timeout");
    }

    fn machine_handle(runtime: &Runtime, machine_id: MachineId) -> crate::Machine {
        crate::Machine::new(runtime.clone(), machine_id)
    }

    async fn inspect_machine(
        runtime: &Runtime,
        machine_ref: MachineRef,
    ) -> Result<crate::MachineData, LibVmError> {
        runtime.get_machine(&machine_ref).await?.inspect().await
    }

    #[tokio::test]
    async fn validate_named_network_config_uses_store_boundary() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        store
            .expect_network_definition()
            .withf(|name| name == "devnet")
            .once()
            .returning(|_| Ok(None));
        let runtime = runtime_with_mock_store(paths, store).await;

        let err = runtime
            .validate_machine_network_config(&MachineNetworkConfig::Named {
                name: "devnet".to_string(),
            })
            .await
            .expect_err("missing named network should fail validation");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref reference, ref message }
                if reference == "devnet" && message.contains("not defined")
        ));
    }

    #[tokio::test]
    async fn resolve_machine_config_reports_missing_name_from_store_boundary() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        store
            .expect_machine_config_by_name()
            .withf(|name| name == "ghost")
            .once()
            .returning(|_| Ok(None));
        let runtime = runtime_with_mock_store(paths, store).await;

        let err = runtime
            .resolve_machine_config(&MachineRef::parse("ghost").expect("valid machine ref"))
            .await
            .expect_err("missing name should fail");

        assert!(matches!(
            err,
            LibVmError::MachineNotFound { ref reference } if reference == "ghost"
        ));
    }

    #[tokio::test]
    async fn resolve_machine_config_handles_id_prefix_store_results() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let id = MachineId::new();
        let config = sample_machine_config(&paths, id, "devbox");
        let prefix = id.to_string()[..8].to_string();
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        let expected_prefix = prefix.clone();
        store
            .expect_machine_configs_by_id_prefix()
            .withf(move |prefix| prefix == expected_prefix)
            .once()
            .return_once(move |_| Ok(vec![config.clone()]));
        let runtime = runtime_with_mock_store(paths, store).await;

        let found = runtime
            .resolve_machine_config(&MachineRef::parse(prefix).expect("valid id prefix"))
            .await
            .expect("prefix should resolve");

        assert_eq!(found.id, id);
    }

    #[tokio::test]
    async fn resolve_machine_config_rejects_ambiguous_id_prefix_from_store_boundary() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let first_id = MachineId::new();
        let second_id = MachineId::new();
        let first = sample_machine_config(&paths, first_id, "first");
        let second = sample_machine_config(&paths, second_id, "second");
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        store
            .expect_machine_configs_by_id_prefix()
            .withf(|prefix| prefix == "deadbeef")
            .once()
            .return_once(move |_| Ok(vec![first, second]));
        let runtime = runtime_with_mock_store(paths, store).await;

        let err = runtime
            .resolve_machine_config(&MachineRef::parse("deadbeef").expect("valid id prefix"))
            .await
            .expect_err("ambiguous prefix should fail");

        assert!(matches!(
            err,
            LibVmError::AmbiguousIdPrefix { ref prefix, count: 2 } if prefix == "deadbeef"
        ));
    }

    #[tokio::test]
    async fn pending_commit_cleans_files_and_lock_when_store_add_fails() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        store
            .expect_machine_config_by_name()
            .withf(|name| name == "devbox")
            .once()
            .returning(|_| Ok(None));
        store.expect_add_machine().once().returning(|_, _| {
            Err(LibVmError::InvalidCreateRequest {
                name: "store".to_string(),
                reason: "forced add failure".to_string(),
            })
        });
        let runtime = runtime_with_mock_store(paths, store).await;
        let pending = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine");
        let final_dir = pending.final_dir.clone();

        let result = pending.commit(&runtime).await;

        assert!(matches!(
            result,
            Err(LibVmError::InvalidCreateRequest { ref reason, .. })
                if reason == "forced add failure"
        ));
        assert!(!final_dir.exists(), "failed commit should remove final dir");
        let lock = runtime
            .lock_manager
            .allocate()
            .expect("failed commit should free allocated lock");
        assert_eq!(lock.id(), LockId::from(0));
    }

    #[tokio::test]
    async fn replace_config_rolls_back_vm_spec_when_store_save_fails() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let id = MachineId::new();
        let config = sample_machine_config(&paths, id, "devbox");
        std::fs::create_dir_all(&config.instance_dir).expect("create instance dir");
        write_machine_config(&config.instance_dir, &config.name, &config.spec)
            .expect("write original spec");
        let state = stopped_state(id);
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        let config_for_lookup = config.clone();
        store
            .expect_machine_config()
            .withf(move |machine_id| *machine_id == id)
            .times(2)
            .returning(move |_| Ok(Some(config_for_lookup.clone())));
        store
            .expect_machine_state()
            .withf(move |machine_id| *machine_id == id)
            .once()
            .return_once(move |_| Ok(Some(state)));
        store.expect_save_machine_config().once().returning(|_| {
            Err(LibVmError::InvalidMachineUpdate {
                reference: "devbox".to_string(),
                reason: "forced save failure".to_string(),
            })
        });
        let runtime = runtime_with_mock_store(paths, store).await;
        let mut replacement = sample_vm_spec();
        spec_hardware_mut(&mut replacement).cpus = Some(8);

        let err = machine_handle(&runtime, id)
            .replace_config(replacement)
            .await
            .expect_err("store failure should fail replace_config");

        assert!(matches!(
            err,
            LibVmError::InvalidMachineUpdate { ref reason, .. }
                if reason == "forced save failure"
        ));
        let restored: VmSpec = serde_json::from_slice(
            &std::fs::read(config.instance_dir.join("config.json")).expect("read rolled back spec"),
        )
        .expect("parse rolled back spec");
        assert_eq!(spec_hardware(&restored).cpus, Some(4));
    }

    #[tokio::test]
    async fn create_machine_clones_rootfs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);

        let runtime = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let mut request = create_request(base_rootfs_path, "devbox");
        request.userdata = Some("#!/bin/sh\necho profile\n".to_string());
        let machine = runtime
            .create_machine_config(request)
            .await
            .expect("create from image");

        let root_disk = machine.instance_dir.join(root_disk_relative_path());
        assert_eq!(
            std::fs::read(root_disk).expect("root disk should exist"),
            b"disk"
        );
        assert_eq!(spec_hardware(&machine.spec).cpus, Some(1));
        assert_eq!(spec_hardware(&machine.spec).memory, Some(512));
        assert_eq!(
            spec_kernel(&machine.spec).cmdline,
            vec![ROOT_DISK_KERNEL_ARG.to_string()]
        );
        assert_eq!(spec_storage(&machine.spec).disks.len(), 1);
        assert_eq!(
            spec_storage(&machine.spec).disks[0].path,
            root_disk_relative_path()
        );
        assert!(!spec_storage(&machine.spec).disks[0].read_only);
        assert_eq!(
            spec_userdata(&machine.spec),
            Some("#!/bin/sh\necho profile\n")
        );
        assert_eq!(machine.root_disk_size, Some(4));
    }

    #[tokio::test]
    async fn create_machine_generates_valid_name_when_missing() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);

        let runtime = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let mut request = create_request(base_rootfs_path, "ignored");
        request.name = None;

        let machine = runtime
            .create_machine_config(request)
            .await
            .expect("create with generated name");

        validate_machine_name(&machine.name).expect("generated name is valid");
        assert_eq!(machine.name, machine.name.to_ascii_lowercase());
        assert_eq!(machine.name.split('-').count(), 3);
        let machine_ref = MachineRef::parse(machine.name.clone()).expect("parse generated name");
        assert_eq!(machine_ref.kind(), &MachineRefKind::Name(machine.name));
    }

    #[tokio::test]
    async fn create_machine_retries_generated_name_conflicts() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);
        let paths = LocalPaths::new(data_dir);
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed_attempts = attempts.clone();
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        store
            .expect_machine_config_by_name()
            .times(2)
            .returning(|_| Ok(None));
        store
            .expect_add_machine()
            .times(2)
            .returning(move |config, state| {
                assert_eq!(state.machine_id, config.id);
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    Err(LibVmError::MachineAlreadyExists {
                        name: config.name.clone(),
                    })
                } else {
                    Ok(())
                }
            });
        let runtime = runtime_with_mock_store(paths, store).await;
        let mut request = create_request(base_rootfs_path, "ignored");
        request.name = None;

        let config = runtime
            .create_machine_config(request)
            .await
            .expect("generated-name conflict should retry");

        assert_eq!(observed_attempts.load(Ordering::SeqCst), 2);
        validate_machine_name(&config.name).expect("generated name is valid");
    }

    #[tokio::test]
    async fn create_machine_generated_name_conflicts_stop_after_three_attempts() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);
        let paths = LocalPaths::new(data_dir);
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        store
            .expect_machine_config_by_name()
            .times(3)
            .returning(|_| Ok(None));
        store.expect_add_machine().times(3).returning(|config, _| {
            Err(LibVmError::MachineAlreadyExists {
                name: config.name.clone(),
            })
        });
        let runtime = runtime_with_mock_store(paths, store).await;
        let mut request = create_request(base_rootfs_path, "ignored");
        request.name = None;

        let err = runtime
            .create_machine_config(request)
            .await
            .expect_err("generated-name conflicts should eventually fail");

        assert!(matches!(
            err,
            LibVmError::MachineNameGenerationFailed { attempts: 3 }
        ));
    }

    #[tokio::test]
    async fn create_machine_generated_name_does_not_retry_other_errors() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);
        let paths = LocalPaths::new(data_dir);
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed_attempts = attempts.clone();
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        store
            .expect_machine_config_by_name()
            .once()
            .returning(|_| Ok(None));
        store.expect_add_machine().once().returning(move |_, _| {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err(LibVmError::InvalidCreateRequest {
                name: "store".to_string(),
                reason: "forced add failure".to_string(),
            })
        });
        let runtime = runtime_with_mock_store(paths, store).await;
        let mut request = create_request(base_rootfs_path, "ignored");
        request.name = None;

        let err = runtime
            .create_machine_config(request)
            .await
            .expect_err("non-conflict errors should not retry");

        assert_eq!(observed_attempts.load(Ordering::SeqCst), 1);
        assert!(matches!(
            err,
            LibVmError::InvalidCreateRequest { ref reason, .. } if reason == "forced add failure"
        ));
    }

    #[tokio::test]
    async fn inspect_returns_local_status_for_stopped_machine() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);

        let runtime = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let machine = runtime
            .create_machine_config(create_request(base_rootfs_path, "devbox"))
            .await
            .expect("create from image");

        let data = machine_handle(&runtime, machine.id)
            .inspect()
            .await
            .expect("stopped machine status should not require vmmon socket");

        assert_eq!(data.status, MachineStatus::Stopped);
        assert!(!data.status.ready());
        assert_eq!(data.status.label(), "stopped");
        assert_eq!(data.status.message(), None);
    }

    #[tokio::test]
    async fn create_machine_defers_initramfs_generation_until_start() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);

        let runtime = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let machine = runtime
            .create_machine_config(create_request(base_rootfs_path, "devbox"))
            .await
            .expect("create from image");

        assert_eq!(spec_kernel(&machine.spec).initramfs, None);
        assert!(!machine.instance_dir.join("initramfs").exists());
    }

    #[tokio::test]
    async fn create_machine_respects_explicit_initramfs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);
        let explicit = temp.path().join("custom-initramfs");
        std::fs::write(&explicit, b"custom initramfs").expect("write explicit initramfs");

        let runtime = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let mut request = create_request(base_rootfs_path, "devbox");
        request.initramfs = Some(explicit.clone());
        let machine = runtime
            .create_machine_config(request)
            .await
            .expect("create from image");

        assert_eq!(
            spec_kernel(&machine.spec).initramfs,
            Some(std::fs::canonicalize(explicit).expect("canonicalize explicit"))
        );
        assert!(!machine.instance_dir.join("initramfs").exists());
    }

    #[tokio::test]
    async fn create_machine_does_not_require_initramfs_assets() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);

        let runtime = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let machine = runtime
            .create_machine_config(create_request(base_rootfs_path, "devbox"))
            .await
            .expect("create without boot assets");

        assert_eq!(spec_kernel(&machine.spec).initramfs, None);
        assert!(!machine.instance_dir.join("initramfs").exists());
    }

    #[test]
    fn assign_mount_tags_fills_missing_tags_without_rewriting_sources() {
        let mounts = assign_mount_tags(vec![Mount {
            source: PathBuf::from("~"),
            tag: String::new(),
            read_only: false,
        }]);

        assert_eq!(mounts[0].tag, "mount0");
        assert_eq!(mounts[0].source, PathBuf::from("~"));
    }

    #[tokio::test]
    async fn create_pending_and_commit_write_vm_spec_and_state() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let pending = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine");

        assert!(pending.dir().starts_with(runtime.paths.staging_dir()));

        let machine = pending.commit(&runtime).await.expect("commit machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(machine.name, "devbox");
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        assert_eq!(
            machine.instance_dir,
            runtime.paths.machine(machine.id).dir()
        );
        assert!(runtime.paths.machine(machine.id).vm_spec_path().exists());
        assert!(runtime.lock_manager.lock_path(machine.lock_id).exists());
    }

    #[tokio::test]
    async fn inspect_and_list_use_name_and_id_lookup() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");

        let by_name = inspect_machine(
            &runtime,
            MachineRef::parse("devbox").expect("parse machine ref"),
        )
        .await
        .expect("inspect by name");
        let by_id = inspect_machine(
            &runtime,
            MachineRef::parse(machine.id.to_string()).expect("parse machine ref"),
        )
        .await
        .expect("inspect by id");
        let listed = runtime.list_machine_configs().await.expect("list machines");

        assert_eq!(by_name.id, machine.id.to_string());
        assert_eq!(by_id.id, machine.id.to_string());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "devbox");
    }

    #[tokio::test]
    async fn inspect_and_list_use_stale_state_when_machine_lock_is_busy() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(std::process::id() as i32),
                Some(42),
                None,
                None,
            )
            .await
            .expect("set stale running state");
        let _lock = runtime
            .acquire_machine_lock(machine.lock_id)
            .await
            .expect("hold machine lock");

        let inspect_data = tokio::time::timeout(
            Duration::from_secs(1),
            inspect_machine(&runtime, MachineRef::id(machine.id)),
        )
        .await
        .expect("inspect should not wait for lock")
        .expect("inspect machine");
        let listed = tokio::time::timeout(Duration::from_secs(1), runtime.list_machine_configs())
            .await
            .expect("list should not wait for lock")
            .expect("list machines");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert!(inspect_data.status.is_running());
        assert_eq!(listed.len(), 1);
        assert_eq!(state.status, MachineRuntimeState::Running);
    }

    #[tokio::test]
    async fn stop_releases_machine_lock_while_waiting_for_monitor_shutdown() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let mut child = ChildGuard::sleep_ignoring_sigint();
        let pid = child.id() as i32;
        let started_at = child.started_at();
        let pid_path = runtime.paths.machine(machine.id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{pid}\n")).expect("write pid file");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(pid),
                started_at,
                Some("run-1".to_string()),
                None,
            )
            .await
            .expect("set running state");

        let machine_id = machine.id;
        let stop_machine = machine_handle(&runtime, machine_id);
        let stop_task = tokio::spawn(async move { stop_machine.stop().await });

        wait_for_machine_state(&runtime, machine_id, MachineRuntimeState::Stopping).await;
        let lock = runtime
            .try_acquire_machine_lock(machine.lock_id)
            .expect("try acquire lock while stop waits")
            .expect("machine lock should be available while stop waits");
        drop(lock);

        std::fs::remove_file(&pid_path).expect("remove pid file");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let state = runtime
            .machine_state(machine_id)
            .await
            .expect("read machine state while process is still alive");
        assert_eq!(state.status, MachineRuntimeState::Stopping);

        child.kill();
        let inspect_data = stop_task
            .await
            .expect("join stop task")
            .expect("stop machine");
        let state = runtime
            .machine_state(machine_id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
    }

    #[tokio::test]
    async fn stop_starting_without_live_monitor_marks_machine_stopped() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Starting,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("set starting state");

        let inspect_data = machine_handle(&runtime, machine.id)
            .stop()
            .await
            .expect("stop machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
    }

    #[tokio::test]
    async fn stop_stopping_without_live_monitor_marks_machine_stopped() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Stopping,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("set stopping state");

        let inspect_data = machine_handle(&runtime, machine.id)
            .stop()
            .await
            .expect("stop machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
    }

    #[tokio::test]
    async fn stop_rejects_malformed_pidfile_without_clearing_state() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let pid_path = runtime.paths.machine(machine.id).vmmon_pid_path();
        std::fs::write(&pid_path, "not-a-pid\n").expect("write malformed pid file");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Starting,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("set starting state");

        let err = machine_handle(&runtime, machine.id)
            .stop()
            .await
            .expect_err("malformed pidfile should fail stop");
        match err {
            LibVmError::Io(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidData),
            other => panic!("expected invalid pidfile io error, got {other:?}"),
        }
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(state.status, MachineRuntimeState::Starting);
    }

    #[test]
    fn read_monitor_pid_rejects_non_positive_pid() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let pid_path = temp.path().join("vmmon.pid");
        std::fs::write(&pid_path, "0\n").expect("write pid file");

        let err = read_monitor_pid(&pid_path).expect_err("pid 0 should be invalid");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn cleanup_reconciles_stopped_runtime_and_cleans_resources() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(12_345),
                Some(42),
                Some("run-1".to_string()),
                None,
            )
            .await
            .expect("set running state");

        let inspect_data = machine_handle(&runtime, machine.id)
            .cleanup()
            .await
            .expect("cleanup machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        assert_eq!(state.vmmon_pid, None);
    }

    #[tokio::test]
    async fn cleanup_keeps_starting_machine_active_without_live_runtime() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Starting,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("set starting state");

        let inspect_data = machine_handle(&runtime, machine.id)
            .cleanup()
            .await
            .expect("cleanup machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status.label(), "starting");
        assert_eq!(state.status, MachineRuntimeState::Starting);
    }

    #[tokio::test]
    async fn cleanup_finishes_stopping_machine_without_live_runtime() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Stopping,
                None,
                Some(42),
                Some("run-1".to_string()),
                None,
            )
            .await
            .expect("set stopping state");

        let inspect_data = machine_handle(&runtime, machine.id)
            .cleanup()
            .await
            .expect("cleanup machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        assert_eq!(state.vmmon_pid, None);
    }

    #[tokio::test]
    async fn cleanup_ignores_live_runtime() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let child = ChildGuard::sleep();
        let pid = child.id() as i32;
        let started_at = child.started_at();
        let pid_path = runtime.paths.machine(machine.id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{pid}\n")).expect("write pid file");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(pid),
                started_at,
                Some("run-1".to_string()),
                None,
            )
            .await
            .expect("set running state");

        let inspect_data = machine_handle(&runtime, machine.id)
            .cleanup()
            .await
            .expect("cleanup machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert!(inspect_data.status.is_running());
        assert_eq!(state.status, MachineRuntimeState::Running);
        assert_eq!(state.vmmon_pid, Some(pid));
        drop(child);
    }

    #[tokio::test]
    async fn list_reconciles_stopping_without_live_runtime_to_stopped() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Stopping,
                None,
                Some(42),
                Some("run-1".to_string()),
                None,
            )
            .await
            .expect("set stopping state");

        let machines = runtime.list_machine_configs().await.expect("list machines");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(machines.len(), 1);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        assert_eq!(state.vmmon_pid, None);
        assert_eq!(state.run_id, None);
    }

    #[tokio::test]
    async fn matching_exit_status_marks_runtime_error() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(12_345),
                Some(42),
                Some("run-1".to_string()),
                None,
            )
            .await
            .expect("set running state");
        std::fs::write(
            runtime.paths.machine(machine.id).vmmon_exit_status_path(),
            r#"{"runId":"run-1","pid":12345,"exitedAt":99,"outcome":"error","error":"runtime exploded"}"#,
        )
        .expect("write exit status");

        let inspect_data = inspect_machine(&runtime, MachineRef::id(machine.id))
            .await
            .expect("inspect machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status.label(), "error");
        assert_eq!(state.status, MachineRuntimeState::Error);
        assert_eq!(state.vmmon_pid, None);
        assert_eq!(state.run_id, None);
        assert_eq!(state.last_error.as_deref(), Some("runtime exploded"));
    }

    #[tokio::test]
    async fn stale_exit_status_does_not_apply_to_new_runtime_generation() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(12_345),
                Some(42),
                Some("run-2".to_string()),
                None,
            )
            .await
            .expect("set running state");
        std::fs::write(
            runtime.paths.machine(machine.id).vmmon_exit_status_path(),
            r#"{"runId":"run-1","pid":12345,"exitedAt":99,"outcome":"error","error":"old runtime exploded"}"#,
        )
        .expect("write stale exit status");

        let inspect_data = inspect_machine(&runtime, MachineRef::id(machine.id))
            .await
            .expect("inspect machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        assert_eq!(state.last_error, None);
    }

    #[tokio::test]
    async fn stale_starting_without_live_runtime_becomes_error() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let stale_age = i64::try_from(STALE_STARTING_TIMEOUT.as_secs()).expect("timeout fits i64");
        runtime
            .store
            .save_machine_state(&MachineState {
                machine_id: machine.id,
                status: MachineRuntimeState::Starting,
                vmmon_pid: None,
                started_at: None,
                run_id: Some("run-1".to_string()),
                last_error: None,
                updated_at: now_unix() - stale_age - 1,
            })
            .await
            .expect("set stale starting state");

        let inspect_data = inspect_machine(&runtime, MachineRef::id(machine.id))
            .await
            .expect("inspect machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status.label(), "error");
        assert_eq!(state.status, MachineRuntimeState::Error);
        assert_eq!(state.run_id, None);
        assert_eq!(
            state.last_error.as_deref(),
            Some("machine start did not leave a live runtime")
        );
    }

    #[tokio::test]
    async fn runtime_open_refreshes_stale_active_state() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let runtime = Runtime::open(
            LocalPaths::new(data_dir.clone()),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let stale_age = i64::try_from(STALE_STARTING_TIMEOUT.as_secs()).expect("timeout fits i64");
        runtime
            .store
            .save_machine_state(&MachineState {
                machine_id: machine.id,
                status: MachineRuntimeState::Starting,
                vmmon_pid: None,
                started_at: None,
                run_id: Some("run-1".to_string()),
                last_error: None,
                updated_at: now_unix() - stale_age - 1,
            })
            .await
            .expect("set stale starting state");
        drop(runtime);

        let reopened = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("reopen runtime");
        let state = reopened
            .machine_state(machine.id)
            .await
            .expect("read refreshed machine state");

        assert_eq!(state.status, MachineRuntimeState::Error);
        assert_eq!(state.run_id, None);
        assert_eq!(
            state.last_error.as_deref(),
            Some("machine start did not leave a live runtime")
        );
    }

    #[tokio::test]
    async fn inspect_uses_sqlite_config_when_config_file_is_missing() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        std::fs::remove_file(runtime.paths.machine(machine.id).vm_spec_path())
            .expect("remove generated config");

        let inspect_data = inspect_machine(
            &runtime,
            MachineRef::parse(machine.id.to_string()).expect("parse machine ref"),
        )
        .await
        .expect("inspect machine");

        assert_eq!(inspect_data.name, "devbox");
    }

    #[tokio::test]
    async fn replace_config_updates_stopped_machine_config() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let mut updated = machine.spec.clone();
        spec_hardware_mut(&mut updated).cpus = Some(6);

        let edited = machine_handle(&runtime, machine.id)
            .replace_config(updated)
            .await
            .expect("replace config");

        assert_eq!(spec_hardware(&edited.spec).cpus, Some(6));
        let persisted = inspect_machine(
            &runtime,
            MachineRef::parse(machine.id.to_string()).expect("parse machine ref"),
        )
        .await
        .expect("inspect");
        assert_eq!(spec_hardware(&persisted.spec).cpus, Some(6));
    }

    #[tokio::test]
    async fn update_renames_stopped_machine() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");

        let updated = machine_handle(&runtime, machine.id)
            .update(MachineUpdate {
                name: Some("ubuntu".to_string()),
                ..MachineUpdate::default()
            })
            .await
            .expect("rename machine");

        assert_eq!(updated.name, "ubuntu");
        assert!(matches!(
            runtime
                .get_machine(&MachineRef::parse("devbox").expect("parse old name"))
                .await
                .expect_err("old name should not resolve"),
            LibVmError::MachineNotFound { ref reference } if reference == "devbox"
        ));
        assert_eq!(
            inspect_machine(
                &runtime,
                MachineRef::parse("ubuntu").expect("parse new name"),
            )
            .await
            .expect("new name should resolve")
            .id,
            machine.id.to_string()
        );
    }

    #[tokio::test]
    async fn update_rejects_duplicate_machine_name() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        create_pending_sample(&runtime, "devbox")
            .await
            .expect("create first machine")
            .commit(&runtime)
            .await
            .expect("commit first machine");
        let second = create_pending_sample(&runtime, "ubuntu")
            .await
            .expect("create second machine")
            .commit(&runtime)
            .await
            .expect("commit second machine");

        let err = machine_handle(&runtime, second.id)
            .update(MachineUpdate {
                name: Some("devbox".to_string()),
                ..MachineUpdate::default()
            })
            .await
            .expect_err("duplicate rename should fail");

        assert!(matches!(
            err,
            LibVmError::InvalidMachineUpdate { ref reference, ref reason }
                if reference == "ubuntu" && reason.contains("already exists")
        ));
    }

    #[tokio::test]
    async fn update_changes_hardware_and_desired_root_disk_size() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);
        let runtime = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let machine = runtime
            .create_machine_config(create_request(base_rootfs_path, "devbox"))
            .await
            .expect("create machine");

        let updated = machine_handle(&runtime, machine.id)
            .update(MachineUpdate {
                cpus: Some(6),
                memory_mib: Some(2048),
                root_disk_size: Some(8),
                ..MachineUpdate::default()
            })
            .await
            .expect("update machine");

        assert_eq!(spec_hardware(&updated.spec).cpus, Some(6));
        assert_eq!(spec_hardware(&updated.spec).memory, Some(2048));
        assert_eq!(updated.root_disk_size, Some(8));
        let persisted = inspect_machine(
            &runtime,
            MachineRef::parse("devbox").expect("parse machine ref"),
        )
        .await
        .expect("inspect persisted update");
        assert_eq!(spec_hardware(&persisted.spec).cpus, Some(6));
        assert_eq!(persisted.root_disk_size, Some(8));
    }

    #[tokio::test]
    async fn update_root_disk_shrink_error_uses_human_sizes() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs_with_size(&data_dir, 2 * 1024 * 1024);
        let runtime = Runtime::open(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let machine = runtime
            .create_machine_config(create_request(base_rootfs_path, "devbox"))
            .await
            .expect("create machine");

        let err = machine_handle(&runtime, machine.id)
            .update(MachineUpdate {
                root_disk_size: Some(1024 * 1024),
                ..MachineUpdate::default()
            })
            .await
            .expect_err("root disk shrink should fail");

        assert!(matches!(
            err,
            LibVmError::InvalidMachineUpdate { ref reason, .. }
                if reason.contains("2MiB") && reason.contains("1MiB")
        ));
    }

    #[tokio::test]
    async fn remove_deletes_machine_from_state_and_disk() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let lock_path = runtime.lock_manager.lock_path(machine.lock_id);

        machine_handle(&runtime, machine.id)
            .remove()
            .await
            .expect("remove machine");

        assert!(!machine.instance_dir.exists());
        assert!(!lock_path.exists());
        assert!(runtime
            .list_machine_configs()
            .await
            .expect("list machines")
            .is_empty());
    }

    #[tokio::test]
    async fn remove_refuses_running_machine_when_pid_file_exists() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");

        let pid_path = runtime.paths.machine(machine.id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{}\n", std::process::id())).expect("write pid file");

        let err = machine_handle(&runtime, machine.id)
            .remove()
            .await
            .expect_err("removing running machine should fail");

        assert!(matches!(
            err,
            LibVmError::MachineAlreadyRunning { ref reference } if reference == "devbox"
        ));
        assert!(machine.instance_dir.exists());
        assert_eq!(
            runtime
                .list_machine_configs()
                .await
                .expect("list machines")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn removed_machine_lock_id_is_reused() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let lock_id = machine.lock_id;
        let lock_path = runtime.lock_manager.lock_path(lock_id);

        machine_handle(&runtime, machine.id)
            .remove()
            .await
            .expect("remove machine");
        let next_machine = create_pending_sample(&runtime, "nextbox")
            .await
            .expect("create next pending machine")
            .commit(&runtime)
            .await
            .expect("commit next machine");

        assert_eq!(next_machine.lock_id, lock_id);
        assert!(lock_path.exists());
    }
}
