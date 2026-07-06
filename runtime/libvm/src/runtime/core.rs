use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use eyre::Context;
use ocidisk::{
    ImageStore as RootfsImageStore, OciDiskResult, RootfsImage, RootfsImageMetadata,
    RootfsImageSource, RootfsOptions,
};

use crate::guest_agent::{self, GuestAgentConfigInput};
use crate::lock_manager::{LockGuard, LockId, LockManager, ManagedLock};
use crate::machine::root_disk::resize_raw_disk;
use crate::paths::{vm_spec_path_in, LocalPaths, MachinePaths};
use crate::runtime::boot_assets::{
    self, BootAssetOverrides, ResolvedBootAssets, RuntimeBootDefaults,
};
use crate::runtime::{RuntimeConfig, RuntimeNetworkingConfig};
use nix::{
    errno::Errno,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use utils::format_storage_size;
use vm_spec::{Boot, Hardware, Kernel, VmSpec};

use crate::image::{
    ImageDetail, ImageHandle, ImageProgress, ImageProgressSender, ImagePruneReport,
    ImagePullPolicy, ImageRemoveOptions, ImageSource, ImageSourceKind, Images, MaterializedImage,
};
use crate::machine::{
    Machine, MachineBuilder, MachineData, MachineRef, MachineRefKind, MachineStatus, NetworkLaunch,
};
use crate::network::{
    prepare_network_runtime, reconcile_network_runtime, validate_network_name, NetworkBuilder,
    NetworkDefinition, VmmonNetworkAttachment,
};
use crate::runtime::transitions::{self, StartFailure, TransitionError};
use crate::runtime::RuntimeBuilder;
use crate::store::models::MachineId;
use crate::store::models::{
    ImageConfigRecord, ImageLayerRecord, ImageManifestLayerRecord, ImageManifestRecord,
    ImageRefRecord, ImageRootfsArtifactRecord, MachineConfig,
    MachineNetworkConfig as ModelMachineNetworkConfig, MachineRootfsRecord, MachineRuntimeState,
    MachineState, OciImageRecord,
};
use crate::store::{ConfigStore, DataStore, Store};
use crate::utils::now_unix;
use crate::vmmon::exit_status::{self, VmmonExitOutcome, VmmonExitStatus};
use crate::vmmon::process::{self, ProcessIdentity};
use crate::vmmon::{self, LaunchSpecInput, Vmmon};
use crate::LibVmError;

const STALE_STARTING_TIMEOUT: Duration = Duration::from_secs(60);

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
    boot_defaults: RuntimeBootDefaults,
    image_pull_policy: ImagePullPolicy,
    image_progress: Option<ImageProgressSender>,
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
    /// Creates a builder for opening a runtime.
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder::new()
    }

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
        let boot_defaults = RuntimeBootDefaults {
            kernel: config.default_kernel,
            initramfs: config.default_initramfs,
        };
        Self::from_store(
            paths,
            Arc::new(store),
            config.networking,
            boot_defaults,
            config.vmmon_path,
        )
        .await
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
        Self::from_store(
            paths,
            Arc::new(store),
            networking,
            RuntimeBootDefaults::default(),
            None,
        )
        .await
    }

    pub(crate) async fn from_store(
        paths: LocalPaths,
        store: Arc<dyn DataStore>,
        networking: RuntimeNetworkingConfig,
        boot_defaults: RuntimeBootDefaults,
        vmmon_path: Option<PathBuf>,
    ) -> Result<Self, LibVmError> {
        let lock_manager = LockManager::open(paths.locks_dir().to_path_buf())?;
        let vmmon = Vmmon::new(paths.clone(), vmmon_path);
        let runtime = Self {
            paths,
            store,
            lock_manager,
            networking,
            vmmon,
            boot_defaults,
            image_pull_policy: ImagePullPolicy::default(),
            image_progress: None,
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

    /// Returns the runtime-scoped image management namespace.
    pub fn images(&self) -> Images {
        Images::new(self.clone())
    }

    /// Returns a runtime handle that uses `policy` for future image materialization.
    ///
    /// The policy applies to `Runtime::images().pull` and machine creation through
    /// `Runtime::machine().image(...).create()`. Starting an existing machine
    /// never pulls or re-resolves images.
    pub fn with_image_pull_policy(mut self, policy: ImagePullPolicy) -> Self {
        self.image_pull_policy = policy;
        self
    }

    /// Returns a runtime handle that reports future image materialization progress.
    ///
    /// Progress is runtime-scoped on purpose: machine start options stay focused
    /// on starting an already-created machine.
    pub fn with_image_progress(mut self, sender: ImageProgressSender) -> Self {
        self.image_progress = Some(sender);
        self
    }

    pub(crate) fn without_image_progress(mut self) -> Self {
        self.image_progress = None;
        self
    }

    pub(crate) fn load_guest_ssh_keypair(&self) -> eyre::Result<crate::host::SshKeyPair> {
        guest_agent::load_or_generate_guest_ssh_keypair(&self.paths)
    }

    #[cfg(test)]
    pub(crate) fn local_paths(&self) -> &LocalPaths {
        &self.paths
    }

    pub(crate) fn machine_paths(&self, machine_id: MachineId) -> MachinePaths {
        self.paths.machine(machine_id)
    }

    pub(crate) fn vmmon(&self) -> &Vmmon {
        &self.vmmon
    }

    pub(crate) fn resolve_boot_assets(
        &self,
        kernel: Option<&Path>,
        initramfs: Option<&Path>,
    ) -> Result<ResolvedBootAssets, LibVmError> {
        boot_assets::resolve_boot_assets(
            BootAssetOverrides { kernel, initramfs },
            &self.boot_defaults,
        )
    }

    fn complete_launch_boot_assets(&self, spec: &mut VmSpec) -> Result<(), LibVmError> {
        let (kernel, initramfs) = boot_asset_overrides_from_spec(spec);
        let boot_assets = self.resolve_boot_assets(kernel, initramfs)?;
        apply_resolved_boot_assets(spec, boot_assets);
        Ok(())
    }

    /// Creates a builder for a new machine.
    pub fn machine(&self) -> MachineBuilder {
        MachineBuilder::new(self.clone())
    }

    /// Creates a builder for a named network definition.
    pub fn network(&self, name: impl Into<String>) -> NetworkBuilder {
        NetworkBuilder::new(self.clone(), name)
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

    pub(crate) async fn materialize_image(
        &self,
        source: &ImageSource,
    ) -> Result<MaterializedImage, LibVmError> {
        let cache_reference = source.cache_reference();
        let store = RootfsImageStore::open(self.local_images_dir())
            .map_err(|err| image_error(&cache_reference, err))?;
        let options =
            RootfsOptions::for_host().map_err(|err| image_error(&cache_reference, err))?;
        let progress = self.image_progress.clone();

        let rootfs = match self.image_pull_policy {
            ImagePullPolicy::IfMissing => {
                match get_cached_rootfs(&store, source, &cache_reference, options.clone())
                    .map_err(|err| image_error(&cache_reference, err))?
                {
                    Some(image) => {
                        emit_cached_image_progress(progress.as_ref(), &image.image_ref);
                        image
                    }
                    None => {
                        get_or_create_rootfs(&store, source, &cache_reference, options, progress)
                            .await
                            .map_err(|err| image_error(&cache_reference, err))?
                    }
                }
            }
            ImagePullPolicy::Always => {
                get_or_create_rootfs(&store, source, &cache_reference, options, progress)
                    .await
                    .map_err(|err| image_error(&cache_reference, err))?
            }
            ImagePullPolicy::Never => get_cached_rootfs(&store, source, &cache_reference, options)
                .map_err(|err| image_error(&cache_reference, err))?
                .ok_or_else(|| LibVmError::ImageNotFound {
                    reference: source.source_reference(),
                })?,
        };

        let metadata = store
            .rootfs_metadata(&rootfs)
            .map_err(|err| image_error(&rootfs.image_ref, err))?;
        let size_bytes = fs::metadata(&rootfs.path)?.len();
        let manifest_digest = materialized_manifest_digest(source, &rootfs, metadata.as_ref())?;
        self.persist_materialized_image(source, &rootfs, metadata.as_ref(), size_bytes)
            .await?;

        Ok(MaterializedImage {
            rootfs_path: rootfs.path,
            image_ref: rootfs.image_ref,
            source_kind: source.kind(),
            source_reference: source.source_reference(),
            image_id: Some(rootfs.image_id),
            manifest_digest,
            size_bytes,
        })
    }

    async fn persist_materialized_image(
        &self,
        source: &ImageSource,
        rootfs: &RootfsImage,
        metadata: Option<&RootfsImageMetadata>,
        size_bytes: u64,
    ) -> Result<(), LibVmError> {
        match source.kind() {
            ImageSourceKind::Oci => {
                let metadata = metadata.ok_or_else(|| LibVmError::StateDecode {
                    field: "image.metadata",
                    message: format!("OCI image {} is missing rootfs metadata", rootfs.image_ref),
                })?;
                let record = oci_image_record(source, rootfs, metadata, size_bytes)?;
                self.store.save_oci_image(&record).await
            }
            ImageSourceKind::Tar => {
                let metadata = metadata.ok_or_else(|| LibVmError::StateDecode {
                    field: "image.metadata",
                    message: format!("tar image {} is missing rootfs metadata", rootfs.image_ref),
                })?;
                let artifact = image_artifact_record(
                    source.kind(),
                    source.source_reference(),
                    rootfs,
                    metadata,
                    None,
                    size_bytes,
                );
                self.store.save_rootfs_artifact(&artifact).await
            }
            ImageSourceKind::Disk => Ok(()),
        }
    }

    /// Creates a named network definition.
    pub(crate) async fn create_network_definition(
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

    pub(crate) fn allocate_machine_lock(&self) -> io::Result<ManagedLock> {
        self.lock_manager.allocate()
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
        match network {
            ModelMachineNetworkConfig::Private { policy, .. } => {
                if let Some(policy) = policy {
                    if let Some(diagnostic) = policy.validate().into_iter().find(|diagnostic| {
                        diagnostic.severity == bento_policy::DiagnosticSeverity::Error
                    }) {
                        return Err(LibVmError::NetworkRuntime {
                            reference: "private".to_string(),
                            message: format!(
                                "invalid network policy: {}: {}",
                                diagnostic.summary, diagnostic.detail
                            ),
                        });
                    }
                }
            }
            ModelMachineNetworkConfig::Named { name } => {
                validate_network_name(name).map_err(|message| LibVmError::NetworkRuntime {
                    reference: name.clone(),
                    message,
                })?;
                self.store.network_definition(name).await?.ok_or_else(|| {
                    LibVmError::NetworkRuntime {
                        reference: name.clone(),
                        message: format!("named network {:?} is not defined", name),
                    }
                })?;
            }
            ModelMachineNetworkConfig::None => {}
        }
        Ok(())
    }

    pub(crate) async fn prepare_machine_network(
        &self,
        config: &MachineConfig,
        network_launch: &NetworkLaunch,
    ) -> Result<VmmonNetworkAttachment, LibVmError> {
        prepare_network_runtime(
            &self.paths,
            self.store.as_ref(),
            config,
            &self.networking,
            network_launch,
        )
        .await
    }

    pub(crate) async fn reconcile_machine_network(
        &self,
        config: &MachineConfig,
        monitor_running: bool,
    ) -> Result<(), LibVmError> {
        reconcile_network_runtime(&self.paths, self.store.as_ref(), config, monitor_running).await
    }

    pub(crate) fn prepare_vmmon_launch_inputs(
        &self,
        config: &MachineConfig,
        network: &VmmonNetworkAttachment,
    ) -> Result<(), LibVmError> {
        let prepare = || -> eyre::Result<()> {
            let relative_mount_base = std::env::current_dir()
                .context("resolve current directory for relative mount sources")?;
            let machine_paths = self.machine_paths(config.id);
            let mut launch_spec = config.spec.clone();
            self.complete_launch_boot_assets(&mut launch_spec)?;
            let launch_spec = vmmon::prepare_launch_spec(LaunchSpecInput {
                relative_mount_base: &relative_mount_base,
                spec: launch_spec,
            })?;
            let agent_config = guest_agent::build_config(GuestAgentConfigInput {
                paths: &self.paths,
                machine_name: &config.name,
                spec: &launch_spec,
                network,
                networking: &self.networking,
            })?;

            vmmon::write_launch_spec(&machine_paths.vm_spec_path(), &launch_spec)?;
            guest_agent::write_config(&machine_paths.metadata_config_path(), &agent_config)?;
            Ok(())
        };

        prepare().map_err(|err| LibVmError::MachinePreparationFailed {
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

    #[cfg(test)]
    pub(crate) async fn add_machine_record(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
    ) -> Result<(), LibVmError> {
        self.store.add_machine(config, initial_state).await
    }

    pub(crate) async fn add_machine_record_with_rootfs(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
        rootfs: &MachineRootfsRecord,
    ) -> Result<(), LibVmError> {
        self.store
            .add_machine_with_rootfs(config, initial_state, rootfs)
            .await
    }

    pub(crate) async fn image_handle(
        &self,
        reference: &str,
    ) -> Result<Option<ImageHandle>, LibVmError> {
        self.store.image_handle(reference).await
    }

    pub(crate) async fn list_image_handles(&self) -> Result<Vec<ImageHandle>, LibVmError> {
        self.store.list_image_handles().await
    }

    pub(crate) async fn image_detail(
        &self,
        reference: &str,
    ) -> Result<Option<ImageDetail>, LibVmError> {
        self.store.image_detail(reference).await
    }

    pub(crate) async fn remove_image(
        &self,
        reference: &str,
        options: ImageRemoveOptions,
    ) -> Result<(), LibVmError> {
        self.store.remove_image(reference, options).await
    }

    pub(crate) async fn prune_images(&self) -> Result<ImagePruneReport, LibVmError> {
        self.store.prune_images().await
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
            match self.vmmon.client(config.id).inspect().await {
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

const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

fn image_error(reference: &str, source: ocidisk::OciDiskError) -> LibVmError {
    LibVmError::Image {
        reference: reference.to_string(),
        source,
    }
}

fn get_cached_rootfs(
    store: &RootfsImageStore,
    source: &ImageSource,
    cache_reference: &str,
    options: RootfsOptions,
) -> OciDiskResult<Option<RootfsImage>> {
    match source {
        ImageSource::Oci(reference) => store.get_cached_oci(reference, options),
        ImageSource::Disk(_) | ImageSource::Tar(_) => store.get_cached(cache_reference, options),
    }
}

async fn get_or_create_rootfs(
    store: &RootfsImageStore,
    source: &ImageSource,
    cache_reference: &str,
    options: RootfsOptions,
    progress: Option<ImageProgressSender>,
) -> OciDiskResult<RootfsImage> {
    match source {
        ImageSource::Oci(reference) => store.get_or_create_oci(reference, options, progress).await,
        ImageSource::Disk(_) | ImageSource::Tar(_) => {
            store
                .get_or_create(cache_reference, options, progress)
                .await
        }
    }
}

fn emit_cached_image_progress(progress: Option<&ImageProgressSender>, image_ref: &str) {
    let Some(progress) = progress else {
        return;
    };
    progress.send(ImageProgress::CheckingCache {
        image_ref: image_ref.to_string(),
    });
    progress.send(ImageProgress::CacheHit {
        image_ref: image_ref.to_string(),
    });
}

fn oci_image_record(
    source: &ImageSource,
    rootfs: &RootfsImage,
    metadata: &RootfsImageMetadata,
    size_bytes: u64,
) -> Result<OciImageRecord, LibVmError> {
    if rootfs.source != RootfsImageSource::OciRegistry {
        return Err(LibVmError::StateDecode {
            field: "image.source",
            message: format!("expected OCI rootfs source, found {}", rootfs.source),
        });
    }

    let now = now_unix();
    let manifest_digest = effective_oci_manifest_digest(rootfs, metadata);
    let created_at = metadata.created_at_unix;
    let total_size_bytes = i64_from_u64("image_manifest.total_size_bytes", size_bytes)?;
    let layer_count =
        i64::try_from(metadata.layers.len()).map_err(|_| LibVmError::StateDecode {
            field: "image_manifest.layer_count",
            message: format!("layer count {} does not fit in i64", metadata.layers.len()),
        })?;

    let layers = metadata
        .layers
        .iter()
        .map(|layer| ImageLayerRecord {
            diff_id: layer.diff_id.clone(),
            blob_digest: layer.blob_digest.clone(),
            media_type: layer.media_type.clone(),
            compressed_size_bytes: Some(layer.size_bytes),
            uncompressed_size_bytes: None,
            created_at,
            last_used_at: Some(now),
        })
        .collect::<Vec<_>>();
    let manifest_layers = metadata
        .layers
        .iter()
        .enumerate()
        .map(|(position, layer)| {
            let position = i64::try_from(position).map_err(|_| LibVmError::StateDecode {
                field: "image_manifest_layer.position",
                message: format!("layer position {position} does not fit in i64"),
            })?;
            Ok(ImageManifestLayerRecord {
                manifest_digest: manifest_digest.clone(),
                layer_diff_id: layer.diff_id.clone(),
                position,
            })
        })
        .collect::<Result<Vec<_>, LibVmError>>()?;

    Ok(OciImageRecord {
        manifest: ImageManifestRecord {
            digest: manifest_digest.clone(),
            media_type: OCI_MANIFEST_MEDIA_TYPE.to_string(),
            image_id: rootfs.image_id.clone(),
            platform_os: rootfs.platform.os.clone(),
            platform_architecture: rootfs.platform.architecture.clone(),
            platform_variant: rootfs.platform.variant.clone(),
            config_digest: metadata.config_digest.clone(),
            layer_count,
            total_size_bytes,
            created_at,
            last_used_at: Some(now),
        },
        reference: ImageRefRecord {
            reference: rootfs.image_ref.clone(),
            manifest_digest: manifest_digest.clone(),
            image_id: rootfs.image_id.clone(),
            platform_os: rootfs.platform.os.clone(),
            platform_architecture: rootfs.platform.architecture.clone(),
            platform_variant: rootfs.platform.variant.clone(),
            size_bytes: Some(size_bytes),
            created_at,
            updated_at: now,
            last_used_at: Some(now),
        },
        config: ImageConfigRecord {
            manifest_digest: manifest_digest.clone(),
            digest: metadata.config_digest.clone(),
            env_json: "[]".to_string(),
            cmd_json: "[]".to_string(),
            entrypoint_json: "[]".to_string(),
            working_dir: None,
            user: None,
            labels_json: "{}".to_string(),
            created_at,
        },
        layers,
        manifest_layers,
        artifact: image_artifact_record(
            ImageSourceKind::Oci,
            source.source_reference(),
            rootfs,
            metadata,
            Some(manifest_digest),
            size_bytes,
        ),
    })
}

fn materialized_manifest_digest(
    source: &ImageSource,
    rootfs: &RootfsImage,
    metadata: Option<&RootfsImageMetadata>,
) -> Result<Option<String>, LibVmError> {
    match source.kind() {
        ImageSourceKind::Oci => {
            let metadata = metadata.ok_or_else(|| LibVmError::StateDecode {
                field: "image.metadata",
                message: format!("OCI image {} is missing rootfs metadata", rootfs.image_ref),
            })?;
            Ok(Some(effective_oci_manifest_digest(rootfs, metadata)))
        }
        ImageSourceKind::Disk | ImageSourceKind::Tar => {
            Ok(metadata.and_then(|metadata| metadata.manifest_digest.clone()))
        }
    }
}

fn effective_oci_manifest_digest(rootfs: &RootfsImage, metadata: &RootfsImageMetadata) -> String {
    metadata
        .manifest_digest
        .clone()
        .unwrap_or_else(|| rootfs.image_id.clone())
}

fn image_artifact_record(
    source_kind: ImageSourceKind,
    source_reference: String,
    rootfs: &RootfsImage,
    metadata: &RootfsImageMetadata,
    manifest_digest: Option<String>,
    size_bytes: u64,
) -> ImageRootfsArtifactRecord {
    let now = now_unix();
    ImageRootfsArtifactRecord {
        image_id: rootfs.image_id.clone(),
        source_kind,
        manifest_digest,
        source_reference,
        platform_os: rootfs.platform.os.clone(),
        platform_architecture: rootfs.platform.architecture.clone(),
        platform_variant: rootfs.platform.variant.clone(),
        filesystem: metadata.filesystem.clone(),
        rootfs_path: rootfs.path.clone(),
        size_bytes,
        created_at: metadata.created_at_unix,
        last_used_at: Some(now),
    }
}

fn i64_from_u64(field: &'static str, value: u64) -> Result<i64, LibVmError> {
    i64::try_from(value).map_err(|_| LibVmError::StateDecode {
        field,
        message: format!("value {value} does not fit in i64"),
    })
}

pub(crate) fn write_machine_config(
    machine_dir: &Path,
    name: &str,
    spec: &VmSpec,
) -> Result<(), LibVmError> {
    let config =
        serde_json::to_string_pretty(spec).map_err(|source| LibVmError::VmSpecSerializeFailed {
            name: name.to_string(),
            source,
        })?;
    fs::write(vm_spec_path_in(machine_dir), config)?;
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
    let root_disk_path = MachinePaths::new(&config.machine_dir).root_disk_path();
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

    let root_disk_path = MachinePaths::new(&config.machine_dir).root_disk_path();
    resize_raw_disk(&root_disk_path, desired_size)?;
    Ok(())
}

pub(crate) async fn wait_for_monitor_stop(
    generation: &VmmonRunIdentity,
    machine_name: &str,
    timeout: std::time::Duration,
) -> Result<(), LibVmError> {
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

pub(crate) fn kill_monitor_process_group(pid: i32) -> io::Result<bool> {
    if pid <= 0 {
        return Ok(false);
    }

    match kill(Pid::from_raw(-pid), Some(Signal::SIGKILL)) {
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

pub(crate) fn stopped_machine_state(
    machine_id: MachineId,
    last_error: Option<String>,
) -> MachineState {
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

fn boot_asset_overrides_from_spec(spec: &VmSpec) -> (Option<&Path>, Option<&Path>) {
    let kernel = spec.boot.as_ref().and_then(|boot| boot.kernel.as_ref());
    (
        kernel.and_then(|kernel| kernel.path.as_deref()),
        kernel.and_then(|kernel| kernel.initramfs.as_deref()),
    )
}

fn apply_resolved_boot_assets(spec: &mut VmSpec, boot_assets: ResolvedBootAssets) {
    let boot = spec.boot.get_or_insert(Boot {
        kernel: None,
        userdata: None,
    });
    let kernel = boot.kernel.get_or_insert_with(|| Kernel {
        path: None,
        cmdline: Vec::new(),
        initramfs: None,
    });
    kernel.path = Some(boot_assets.kernel);
    kernel.initramfs = Some(boot_assets.initramfs);
}

#[cfg(test)]
mod tests {
    use crate::lock_manager::LockId;
    use crate::paths::{LocalPaths, MachinePaths};
    use crate::runtime::boot_assets::RuntimeBootDefaults;
    use crate::runtime::core::{
        effective_oci_manifest_digest, materialized_manifest_digest, oci_image_record,
        read_monitor_pid, stopped_machine_state, write_machine_config, Runtime,
        STALE_STARTING_TIMEOUT,
    };
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRuntimeState, MachineState,
    };
    use crate::store::MockDataStore;
    use crate::utils::now_unix;
    use crate::vmmon::process::ProcessIdentity;
    use crate::{
        ImageSource, LibVmError, MachineExitOutcome, MachineKillOptions, MachineRef, MachineStatus,
        MachineUpdate, Memory, RuntimeNetworkingConfig,
    };
    use bento_policy::NetworkPolicy;
    use ocidisk::{Platform, RootfsImage, RootfsImageMetadata, RootfsImageSource};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::process::CommandExt;
    use std::sync::Arc;
    use std::time::Duration;
    use vm_spec::{Boot, Guest, GuestOs, Hardware, Kernel, VmSpec};

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

    fn sample_network_policy() -> NetworkPolicy {
        NetworkPolicy::from_json_str(
            r#"{
                "version": 1,
                "metadata": { "source": "test" }
            }"#,
        )
        .expect("sample network policy")
    }

    fn sample_machine_config(paths: &LocalPaths, id: MachineId, name: &str) -> MachineConfig {
        MachineConfig {
            id,
            lock_id: LockId::from(0),
            name: name.to_string(),
            spec: sample_vm_spec(),
            machine_dir: paths.machine(id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: "test-image:latest".to_string(),
            root_disk_size: None,
            labels: std::collections::BTreeMap::new(),
            metadata: std::collections::BTreeMap::new(),
            network: MachineNetworkConfig::default(),
        }
    }

    fn sample_oci_rootfs_image() -> RootfsImage {
        RootfsImage {
            path: std::path::PathBuf::from("/tmp/rootfs.img"),
            image_ref: "ubuntu:latest".to_string(),
            image_id: "sha256:imageid".to_string(),
            platform: Platform::linux_arm64(),
            source: RootfsImageSource::OciRegistry,
        }
    }

    fn sample_oci_rootfs_metadata(manifest_digest: Option<&str>) -> RootfsImageMetadata {
        RootfsImageMetadata {
            version: 1,
            image_ref: "ubuntu:latest".to_string(),
            image_id: "sha256:imageid".to_string(),
            source: RootfsImageSource::OciRegistry,
            manifest_digest: manifest_digest.map(str::to_string),
            config_digest: Some("sha256:config".to_string()),
            layers: Vec::new(),
            platform: Platform::linux_arm64(),
            filesystem: "ext4".to_string(),
            rootfs_file: "rootfs.img".to_string(),
            created_at_unix: 1,
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
        Runtime::from_store(
            paths,
            Arc::new(store),
            RuntimeNetworkingConfig::default(),
            RuntimeBootDefaults::default(),
            None,
        )
        .await
        .expect("create runtime with mock store")
    }

    async fn runtime_with_boot_defaults(
        paths: LocalPaths,
        mut store: MockDataStore,
        boot_defaults: RuntimeBootDefaults,
    ) -> Runtime {
        expect_empty_refresh(&mut store);
        Runtime::from_store(
            paths,
            Arc::new(store),
            RuntimeNetworkingConfig::default(),
            boot_defaults,
            None,
        )
        .await
        .expect("create runtime with boot defaults")
    }

    fn write_test_asset(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).expect("create asset dir");
        let path = dir.join(name);
        std::fs::write(&path, b"asset").expect("write asset");
        path
    }

    #[tokio::test]
    async fn launch_boot_assets_fill_missing_initramfs_for_legacy_specs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let asset_dir = temp.path().join("assets");
        let kernel = write_test_asset(&asset_dir, "kernel-default");
        let initramfs = write_test_asset(&asset_dir, "initramfs");
        let runtime = runtime_with_boot_defaults(
            LocalPaths::new(temp.path().join("data")),
            MockDataStore::new(),
            RuntimeBootDefaults {
                kernel: Some(kernel.clone()),
                initramfs: Some(initramfs.clone()),
            },
        )
        .await;
        let mut spec = sample_vm_spec();
        let kernel_spec = spec
            .boot
            .as_mut()
            .and_then(|boot| boot.kernel.as_mut())
            .expect("sample spec kernel");
        kernel_spec.path = Some(kernel.clone());
        kernel_spec.initramfs = None;
        kernel_spec.cmdline = vec!["root=/dev/vda".to_string()];

        runtime
            .complete_launch_boot_assets(&mut spec)
            .expect("complete launch boot assets");
        let kernel_spec = spec
            .boot
            .as_ref()
            .and_then(|boot| boot.kernel.as_ref())
            .expect("launch spec kernel");

        assert_eq!(
            kernel_spec.path,
            Some(kernel.canonicalize().expect("kernel"))
        );
        assert_eq!(
            kernel_spec.initramfs,
            Some(initramfs.canonicalize().expect("initramfs"))
        );
        assert_eq!(kernel_spec.cmdline, vec!["root=/dev/vda".to_string()]);
    }

    #[tokio::test]
    async fn launch_boot_assets_preserve_explicit_initramfs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let asset_dir = temp.path().join("assets");
        let kernel = write_test_asset(&asset_dir, "kernel-default");
        let runtime_initramfs = write_test_asset(&asset_dir, "runtime-initramfs");
        let explicit_initramfs = write_test_asset(&asset_dir, "explicit-initramfs");
        let runtime = runtime_with_boot_defaults(
            LocalPaths::new(temp.path().join("data")),
            MockDataStore::new(),
            RuntimeBootDefaults {
                kernel: Some(kernel.clone()),
                initramfs: Some(runtime_initramfs),
            },
        )
        .await;
        let mut spec = sample_vm_spec();
        let kernel_spec = spec
            .boot
            .as_mut()
            .and_then(|boot| boot.kernel.as_mut())
            .expect("sample spec kernel");
        kernel_spec.path = Some(kernel.clone());
        kernel_spec.initramfs = Some(explicit_initramfs.clone());

        runtime
            .complete_launch_boot_assets(&mut spec)
            .expect("complete launch boot assets");
        let kernel_spec = spec
            .boot
            .as_ref()
            .and_then(|boot| boot.kernel.as_ref())
            .expect("launch spec kernel");

        assert_eq!(
            kernel_spec.path,
            Some(kernel.canonicalize().expect("kernel"))
        );
        assert_eq!(
            kernel_spec.initramfs,
            Some(
                explicit_initramfs
                    .canonicalize()
                    .expect("explicit initramfs")
            )
        );
    }

    #[test]
    fn effective_oci_manifest_digest_prefers_metadata_digest() {
        let rootfs = sample_oci_rootfs_image();
        let metadata = sample_oci_rootfs_metadata(Some("sha256:manifest"));

        let digest = effective_oci_manifest_digest(&rootfs, &metadata);

        assert_eq!(digest, "sha256:manifest");
    }

    #[test]
    fn materialized_oci_manifest_digest_matches_record_fallback() {
        let source = ImageSource::oci("ubuntu:latest");
        let rootfs = sample_oci_rootfs_image();
        let metadata = sample_oci_rootfs_metadata(None);

        let digest = materialized_manifest_digest(&source, &rootfs, Some(&metadata))
            .expect("materialized digest should resolve");
        let record = oci_image_record(&source, &rootfs, &metadata, 4)
            .expect("OCI image record should resolve");

        assert_eq!(digest.as_deref(), Some("sha256:imageid"));
        assert_eq!(record.manifest.digest, "sha256:imageid");
        assert_eq!(record.reference.manifest_digest, "sha256:imageid");
        assert_eq!(
            record.artifact.manifest_digest.as_deref(),
            Some("sha256:imageid")
        );
    }

    struct TestMachineCreate {
        name: String,
        root_disk_size: Option<u64>,
    }

    impl TestMachineCreate {
        async fn commit(self, runtime: &Runtime) -> Result<MachineConfig, LibVmError> {
            crate::machine::validate_machine_name(&self.name)?;
            if runtime.machine_config_by_name(&self.name).await?.is_some() {
                return Err(LibVmError::MachineAlreadyExists { name: self.name });
            }

            let id = MachineId::new();
            let machine_dir = runtime.paths.machine(id).dir().to_path_buf();
            if machine_dir.exists() {
                return Err(LibVmError::MachineIdAlreadyExists { id: id.to_string() });
            }
            std::fs::create_dir_all(&machine_dir)?;

            let spec = sample_vm_spec();
            write_machine_config(&machine_dir, &self.name, &spec)?;
            std::fs::write(MachinePaths::new(&machine_dir).root_disk_path(), b"disk")?;

            let lock = match runtime.allocate_machine_lock() {
                Ok(lock) => lock,
                Err(err) => {
                    let _ = std::fs::remove_dir_all(&machine_dir);
                    return Err(err.into());
                }
            };

            let now = now_unix();
            let config = MachineConfig {
                id,
                lock_id: lock.id(),
                name: self.name,
                spec,
                machine_dir: machine_dir.clone(),
                created_at: now,
                modified_at: now,
                image_ref: "test-image:latest".to_string(),
                root_disk_size: self.root_disk_size,
                labels: std::collections::BTreeMap::new(),
                metadata: std::collections::BTreeMap::new(),
                network: MachineNetworkConfig::default(),
            };
            let initial_state = stopped_machine_state(id, None);
            if let Err(err) = runtime.add_machine_record(&config, &initial_state).await {
                let _ = lock.free();
                let _ = std::fs::remove_dir_all(&machine_dir);
                return Err(err);
            }

            Ok(config)
        }
    }

    async fn create_pending_sample(
        _runtime: &Runtime,
        name: &str,
    ) -> Result<TestMachineCreate, LibVmError> {
        Ok(TestMachineCreate {
            name: name.to_string(),
            root_disk_size: None,
        })
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
            let mut child = std::process::Command::new(
                std::env::current_exe().expect("current test binary path"),
            )
            .env("BENTO_LIBVM_SIGINT_IGNORING_CHILD", "1")
            .arg("sigint_ignoring_child_process")
            .arg("--nocapture")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn signal-resistant sleep process");
            let stdout = child.stdout.take().expect("child stdout should be piped");
            wait_for_child_ready(stdout);
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

    fn wait_for_child_ready(stdout: std::process::ChildStdout) {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line).expect("read child stdout");
            assert!(bytes > 0, "child exited before reporting readiness");
            if line.trim() == "BENTO_READY" {
                return;
            }
        }
    }

    #[test]
    fn sigint_ignoring_child_process() {
        if std::env::var_os("BENTO_LIBVM_SIGINT_IGNORING_CHILD").is_none() {
            return;
        }

        let action = nix::sys::signal::SigAction::new(
            nix::sys::signal::SigHandler::SigIgn,
            nix::sys::signal::SaFlags::empty(),
            nix::sys::signal::SigSet::empty(),
        );
        unsafe {
            nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGINT, &action)
                .expect("ignore SIGINT");
        }
        println!("BENTO_READY");
        std::io::stdout().flush().expect("flush readiness");
        std::thread::sleep(Duration::from_secs(30));
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
    async fn replace_config_rolls_back_vm_spec_when_store_save_fails() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let id = MachineId::new();
        let config = sample_machine_config(&paths, id, "devbox");
        std::fs::create_dir_all(&config.machine_dir).expect("create machine dir");
        write_machine_config(&config.machine_dir, &config.name, &config.spec)
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
            &std::fs::read(config.machine_dir.join("config.json")).expect("read rolled back spec"),
        )
        .expect("parse rolled back spec");
        assert_eq!(spec_hardware(&restored).cpus, Some(4));
    }

    #[tokio::test]
    async fn inspect_returns_local_status_for_stopped_machine() {
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
    async fn wait_reports_matching_exit_status_when_monitor_already_exited() {
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

        let exit = machine_handle(&runtime, machine.id)
            .wait()
            .await
            .expect("wait should report vmmon exit status");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(exit.run_id.as_deref(), Some("run-1"));
        assert!(exit.exited_at.is_some());
        assert_eq!(
            exit.outcome,
            MachineExitOutcome::Error {
                message: Some("runtime exploded".to_string())
            }
        );
        assert_eq!(exit.machine.status.label(), "error");
        assert_eq!(state.status, MachineRuntimeState::Error);
        assert_eq!(state.last_error.as_deref(), Some("runtime exploded"));
    }

    #[tokio::test]
    async fn kill_with_returns_forced_machine_exit() {
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
        let mut command = std::process::Command::new("sleep");
        command.arg("5").process_group(0);
        let mut child = command.spawn().expect("spawn sleep process group");
        let pid = child.id() as i32;
        let started_at = ProcessIdentity::for_pid(pid)
            .expect("read child process identity")
            .expect("child process should exist")
            .started_at();
        let reaper = std::thread::spawn(move || child.wait());
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

        let exit = machine_handle(&runtime, machine.id)
            .kill_with(MachineKillOptions::new().timeout(Duration::from_secs(2)))
            .await
            .expect("kill should return machine exit");
        let wait_status = reaper
            .join()
            .expect("join child reaper")
            .expect("wait for child");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert!(!wait_status.success());
        assert_eq!(exit.run_id.as_deref(), Some("run-1"));
        assert_eq!(exit.outcome, MachineExitOutcome::Forced);
        assert_eq!(exit.machine.status, MachineStatus::Stopped);
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
                cpus: Some(6),
                memory: Some(Memory::mebibytes(2048)),
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
    async fn update_sets_and_clears_private_network_policy() {
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
        let policy = sample_network_policy();

        let updated = machine_handle(&runtime, machine.id)
            .update(MachineUpdate::new().set_network_policy(policy.clone()))
            .await
            .expect("set network policy");

        assert_eq!(updated.network.policy(), Some(&policy));

        let cleared = machine_handle(&runtime, machine.id)
            .update(MachineUpdate::new().clear_network_policy())
            .await
            .expect("clear network policy");

        assert!(cleared.network.policy().is_none());
    }

    #[tokio::test]
    async fn update_rejects_policy_update_when_network_is_disabled() {
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
        machine_handle(&runtime, machine.id)
            .set_network(|network| network.none())
            .await
            .expect("disable network");

        let err = machine_handle(&runtime, machine.id)
            .update(MachineUpdate::new().set_network_policy(sample_network_policy()))
            .await
            .expect_err("policy update should require private network");

        assert!(matches!(
            err,
            LibVmError::InvalidMachineUpdate { ref reason, .. }
                if reason.contains("machine networking is disabled")
        ));
    }

    #[tokio::test]
    async fn update_root_disk_shrink_error_uses_human_sizes() {
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
        let root_disk = MachinePaths::new(&machine.machine_dir).root_disk_path();
        let root_disk_file = std::fs::OpenOptions::new()
            .write(true)
            .open(root_disk)
            .expect("open root disk");
        root_disk_file
            .set_len(2 * 1024 * 1024)
            .expect("set root disk size");

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

        assert!(!machine.machine_dir.exists());
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
        assert!(machine.machine_dir.exists());
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
