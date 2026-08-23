use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use eyre::Context;
use oci::{
    ImageStore as RootfsImageStore, MaterializeOptions, OciError, PublishedRootfs, RootfsMetadata,
};

use crate::guest_agent::{self, GuestAgentConfigInput};
use crate::lock_manager::{LockGuard, LockId, LockManager, ManagedLock};
use crate::machine::root_disk::resize_raw_disk;
use crate::paths::{vm_spec_path_in, LocalPaths, MachinePaths};
use crate::runtime::boot_assets::{self, BootAssetOverrides, ResolvedBootAssets};
use crate::runtime::components::{resolve_components, ResolvedRuntimeComponents};
use crate::runtime::{RuntimeConfig, RuntimeNetworkingConfig};
use nix::{
    errno::Errno,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use utils::format_storage_size;
use vm_spec::{Boot, Hardware, Kernel, VmSpec};

use crate::image::{
    local_disk::resolve_local_disk,
    oci::{
        cached_resolved_oci_image, ensure_resolved_oci_identity, image_error,
        resolve_oci_image_from_registry,
    },
    progress::oci_progress_reporter,
    ImageDetail, ImageHandle, ImageProgress, ImageProgressSender, ImagePruneReport,
    ImagePullPolicy, ImageRemoveOptions, ImageSource, ImageSourceKind, Images, MaterializedImage,
    ResolvedOciImage, ResolvedOciImageMaterialization,
};
use crate::machine::{
    EgressCredentials, Machine, MachineBuilder, MachineData, MachineRef, MachineRefKind,
    MachineStatus,
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
    components: ResolvedRuntimeComponents,
    vmmon: Vmmon,
    image_pull_policy: ImagePullPolicy,
    image_progress: Option<ImageProgressSender>,
}

/// Identity for one concrete vmmon run.
///
/// PID alone is not enough because host PIDs can be reused. When the platform
/// can expose process birth time we include it, and we also carry the runtime
/// run ID written into persisted state and vmmon exit files. Lifecycle paths use
/// this to avoid applying stale transitions to a newer machine run.
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
        let components = resolve_components(&config)?;
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
        Self::from_store(
            paths,
            Arc::new(store),
            config.networking,
            components,
            config.virt_backend,
        )
        .await
    }

    /// Opens the default local runtime from the process environment.
    pub async fn from_env() -> Result<Self, LibVmError> {
        Self::new(RuntimeConfig::from_env()?).await
    }

    pub(crate) fn execution_client(&self, machine_id: MachineId) -> crate::vmmon::VmmonClient {
        self.vmmon.client(machine_id)
    }

    #[cfg(test)]
    pub(crate) async fn open(
        paths: LocalPaths,
        networking: RuntimeNetworkingConfig,
    ) -> Result<Self, LibVmError> {
        let store = Store::new(&paths).await?;
        let components = crate::runtime::components::test_components(paths.data_dir());
        Self::from_store(paths, Arc::new(store), networking, components, None).await
    }

    pub(crate) async fn from_store(
        paths: LocalPaths,
        store: Arc<dyn DataStore>,
        networking: RuntimeNetworkingConfig,
        components: ResolvedRuntimeComponents,
        virt_backend: Option<crate::runtime::VirtBackendOverride>,
    ) -> Result<Self, LibVmError> {
        let lock_manager = LockManager::open(paths.locks_dir().to_path_buf())?;
        let vmmon = Vmmon::new(
            paths.clone(),
            components.vmmon.clone(),
            components.krun.clone(),
            virt_backend,
        );
        let runtime = Self {
            paths,
            store,
            lock_manager,
            networking,
            components,
            vmmon,
            image_pull_policy: ImagePullPolicy::default(),
            image_progress: None,
        };
        runtime.refresh_machine_states().await?;
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

    pub(crate) fn image_pull_policy(&self) -> ImagePullPolicy {
        self.image_pull_policy
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

    pub(crate) fn local_paths(&self) -> &LocalPaths {
        &self.paths
    }

    pub(crate) fn machine_paths(&self, machine_id: MachineId) -> MachinePaths {
        self.paths.machine(machine_id)
    }

    pub(crate) fn ensure_machine_runtime_directories(
        &self,
        machine_id: MachineId,
    ) -> Result<(), LibVmError> {
        self.paths.ensure_machine_run_dir(machine_id)?;
        self.paths.ensure_machine_logs_dir(machine_id)
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
            &self.components.kernel,
            &self.components.initramfs,
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
        validate_image_pull_policy(source, self.image_pull_policy)?;
        match source {
            ImageSource::Oci(reference) => self.materialize_oci_image(reference).await,
            ImageSource::Disk(path) => self.materialize_local_disk(path),
        }
    }

    async fn materialize_oci_image(
        &self,
        reference: &str,
    ) -> Result<MaterializedImage, LibVmError> {
        let store = RootfsImageStore::open(self.local_images_dir())
            .map_err(|err| image_error(reference, err))?;
        let options = MaterializeOptions::for_host().map_err(|err| image_error(reference, err))?;
        let progress = self.image_progress.clone();

        let rootfs = match self.image_pull_policy {
            ImagePullPolicy::IfMissing => {
                match store
                    .get_cached(reference, &options)
                    .map_err(|err| image_error(reference, err))?
                {
                    Some(image) => {
                        emit_cached_image_progress(
                            progress.as_ref(),
                            &image.flat_ext4().requested_reference,
                        );
                        image
                    }
                    None => store
                        .get_or_create(reference, &options, oci_progress_reporter(progress))
                        .await
                        .map_err(|err| image_error(reference, err))?,
                }
            }
            ImagePullPolicy::Always => store
                .get_or_create(reference, &options, oci_progress_reporter(progress))
                .await
                .map_err(|err| image_error(reference, err))?,
            ImagePullPolicy::Never => store
                .get_cached(reference, &options)
                .map_err(|err| image_error(reference, err))?
                .ok_or_else(|| LibVmError::ImageNotFound {
                    reference: reference.to_string(),
                })?,
        };

        let metadata = store
            .metadata(&rootfs)
            .map_err(|err| image_error(&rootfs.flat_ext4().requested_reference, err))?;
        let size_bytes = fs::metadata(&rootfs.flat_ext4().path)?.len();
        let source = ImageSource::oci(reference);
        let identity = materialized_image_identity(&source, &rootfs, Some(&metadata))?;
        self.persist_materialized_image(
            &source,
            &rootfs,
            Some(&metadata),
            size_bytes,
            &identity.requested_reference,
        )
        .await?;

        let image = MaterializedImage {
            rootfs_path: rootfs.flat_ext4().path.clone(),
            requested_reference: identity.requested_reference,
            selected_reference: identity.selected_reference,
            source_kind: ImageSourceKind::Oci,
            image_id: Some(rootfs.flat_ext4().image_id.clone()),
            manifest_digest: identity.manifest_digest,
            config_digest: identity.config_digest,
            size_bytes,
        };
        emit_image_progress_complete(self.image_progress.as_ref());
        Ok(image)
    }

    fn materialize_local_disk(&self, path: &Path) -> Result<MaterializedImage, LibVmError> {
        let image_ref = format!("disk:{}", path.display());
        if let Some(progress) = &self.image_progress {
            progress.send(ImageProgress::UsingLocalDisk { image_ref });
        }
        let source = resolve_local_disk(path)?;
        let size_bytes = fs::metadata(&source.canonical_path)?.len();
        let image = MaterializedImage {
            rootfs_path: source.canonical_path,
            requested_reference: path.display().to_string(),
            selected_reference: None,
            source_kind: ImageSourceKind::Disk,
            image_id: Some(source.image_id),
            manifest_digest: None,
            config_digest: None,
            size_bytes,
        };
        emit_image_progress_complete(self.image_progress.as_ref());
        Ok(image)
    }

    pub(crate) async fn resolve_oci_image(
        &self,
        reference: String,
        policy: ImagePullPolicy,
    ) -> Result<ResolvedOciImage, LibVmError> {
        let store = RootfsImageStore::open(self.local_images_dir())
            .map_err(|err| image_error(&reference, err))?;
        let options = MaterializeOptions::for_host().map_err(|err| image_error(&reference, err))?;

        match policy {
            ImagePullPolicy::IfMissing => {
                if let Some(image) = cached_resolved_oci_image(&store, &reference, options.clone())?
                {
                    return Ok(image);
                }
                resolve_oci_image_from_registry(
                    &store,
                    reference,
                    options,
                    self.image_progress.clone(),
                )
                .await
            }
            ImagePullPolicy::Always => {
                resolve_oci_image_from_registry(
                    &store,
                    reference,
                    options,
                    self.image_progress.clone(),
                )
                .await
            }
            ImagePullPolicy::Never => cached_resolved_oci_image(&store, &reference, options)?
                .ok_or(LibVmError::ImageNotFound { reference }),
        }
    }

    pub(crate) async fn materialize_resolved_oci_image(
        &self,
        resolved: &ResolvedOciImage,
    ) -> Result<MaterializedImage, LibVmError> {
        let source = ImageSource::oci(resolved.requested_reference.clone());
        let store = RootfsImageStore::open(self.local_images_dir())
            .map_err(|err| image_error(&resolved.requested_reference, err))?;
        let options = MaterializeOptions::for_host()
            .map_err(|err| image_error(&resolved.requested_reference, err))?;
        if options.platform != resolved.platform {
            return Err(image_error(
                &resolved.requested_reference,
                OciError::PlatformMismatch {
                    reference: resolved.requested_reference.clone(),
                    requested: options.platform.to_string(),
                    actual: resolved.platform.to_string(),
                },
            ));
        }

        let rootfs = match &resolved.materialization {
            ResolvedOciImageMaterialization::Cached => {
                emit_cached_image_progress(
                    self.image_progress.as_ref(),
                    &resolved.requested_reference,
                );
                store
                    .get_cached(&resolved.selected_reference, &options)
                    .map_err(|err| image_error(&resolved.selected_reference, err))?
                    .ok_or_else(|| LibVmError::ImageNotFound {
                        reference: resolved.selected_reference.clone(),
                    })?
            }
            ResolvedOciImageMaterialization::Registry(image) => store
                .materialize(
                    image,
                    &options,
                    oci_progress_reporter(self.image_progress.clone()),
                )
                .await
                .map_err(|err| image_error(&resolved.requested_reference, err))?,
        };
        let metadata = store
            .metadata(&rootfs)
            .map_err(|err| image_error(&rootfs.flat_ext4().requested_reference, err))?;
        ensure_resolved_oci_identity(resolved, &rootfs, &metadata)?;
        let size_bytes = fs::metadata(&rootfs.flat_ext4().path)?.len();
        self.persist_materialized_image(
            &source,
            &rootfs,
            Some(&metadata),
            size_bytes,
            &resolved.requested_reference,
        )
        .await?;

        let image = MaterializedImage {
            rootfs_path: rootfs.flat_ext4().path.clone(),
            requested_reference: resolved.requested_reference.clone(),
            selected_reference: Some(resolved.selected_reference.clone()),
            source_kind: ImageSourceKind::Oci,
            image_id: Some(rootfs.flat_ext4().image_id.clone()),
            manifest_digest: Some(resolved.manifest_digest.clone()),
            config_digest: Some(resolved.config_digest.clone()),
            size_bytes,
        };
        emit_image_progress_complete(self.image_progress.as_ref());
        Ok(image)
    }

    async fn persist_materialized_image(
        &self,
        source: &ImageSource,
        rootfs: &PublishedRootfs,
        metadata: Option<&RootfsMetadata>,
        size_bytes: u64,
        requested_reference: &str,
    ) -> Result<(), LibVmError> {
        match source {
            ImageSource::Oci(_) => {
                let metadata = metadata.ok_or_else(|| LibVmError::StateDecode {
                    field: "image.metadata",
                    message: format!(
                        "OCI image {} is missing rootfs metadata",
                        rootfs.flat_ext4().requested_reference
                    ),
                })?;
                let record = oci_image_record(rootfs, metadata, size_bytes, requested_reference)?;
                self.store.save_oci_image(&record).await
            }
            ImageSource::Disk(_) => Ok(()),
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

    async fn refresh_machine_states(&self) -> Result<(), LibVmError> {
        for config in self.store.list_machine_configs().await? {
            let Some(_lock) = self.try_acquire_machine_lock(config.lock_id)? else {
                continue;
            };
            let status = self.reconcile_machine_runtime_locked(&config).await?;
            if status.is_active() {
                reconcile_network_runtime(&self.paths, self.store.as_ref(), &config, true).await?;
            }
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
        let live_identity = live_monitor_identity(pid_from_file, runtime)?;
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
                    let started_at = live_identity.as_ref().and_then(ProcessIdentity::started_at);
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
        config: &MachineConfig,
        run_id: &str,
    ) -> Result<(), LibVmError> {
        let state = self.machine_state(config.id).await?;
        let next = transitions::reduce(
            state,
            transitions::Event::StartRequested {
                run_id: run_id.to_string(),
            },
            now_unix(),
        )
        .map_err(transition_error)?;
        self.store.save_machine_state(&next).await
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
    ) -> Result<bool, LibVmError> {
        let state = self.machine_state(config.id).await?;
        if !matches!(
            state.status,
            MachineRuntimeState::Starting
                | MachineRuntimeState::Running
                | MachineRuntimeState::Stopping
        ) {
            return Ok(true);
        }
        if !vmmon_run_identity_matches(&state, &generation) {
            return Ok(false);
        }

        if vmmon_run_is_alive(&generation)? {
            return Ok(false);
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
            Err(TransitionError::StaleGeneration) => return Ok(false),
            Err(err) => return Err(transition_error(err)),
        };
        self.store.save_machine_state(&next).await?;
        self.cleanup_machine_resources_locked(config).await?;
        Ok(true)
    }

    pub(crate) async fn cleanup_machine_resources_locked(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        self.validate_machine_data_dir(config)?;
        reconcile_network_runtime(&self.paths, self.store.as_ref(), config, false).await?;
        self.paths.remove_machine_run_tree(config.id)
    }

    pub(crate) fn validate_machine_data_dir(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        let machine_paths = self.paths.machine(config.id);
        let canonical = machine_paths.machine_data_dir();
        if config.machine_dir != canonical {
            return Err(LibVmError::InvalidOwnedPath {
                path: config.machine_dir.clone(),
                message: format!(
                    "persisted machine directory does not equal canonical machine path {}",
                    canonical.display()
                ),
            });
        }
        Ok(())
    }

    pub(crate) async fn ensure_no_live_vmmon_generation(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        let state = self.machine_state(config.id).await?;
        let Some(pid) = state.vmmon_pid else {
            return Ok(());
        };
        let Some(identity) = ProcessIdentity::for_pid(pid)? else {
            return Ok(());
        };
        if !identity_matches_generation(&identity, state.started_at) {
            return Err(LibVmError::InvalidOwnedPath {
                path: self
                    .machine_paths(config.id)
                    .machine_run_dir()
                    .to_path_buf(),
                message: format!(
                    "vmmon pid {pid} is a different process generation than persisted machine state"
                ),
            });
        }
        if identity.is_alive()? {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        Ok(())
    }

    pub(crate) async fn validate_machine_network_config(
        &self,
        network: &ModelMachineNetworkConfig,
    ) -> Result<(), LibVmError> {
        match network {
            ModelMachineNetworkConfig::Private { policy, .. } => {
                if let Some(policy) = policy {
                    if let Some(diagnostic) = policy.validate().into_iter().find(|diagnostic| {
                        diagnostic.severity == silo_policy::DiagnosticSeverity::Error
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
        run_id: &str,
        egress_credentials: &EgressCredentials,
    ) -> Result<VmmonNetworkAttachment, LibVmError> {
        prepare_network_runtime(
            &self.paths,
            self.store.as_ref(),
            config,
            run_id,
            &self.networking,
            &self.components.netd,
            egress_credentials,
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
        resize_rootfs: bool,
    ) -> Result<bool, LibVmError> {
        let prepare = || -> eyre::Result<bool> {
            let relative_mount_base = std::env::current_dir()
                .context("resolve current directory for relative mount sources")?;
            let machine_paths = self.machine_paths(config.id);
            let mut launch_spec = config.spec.clone();
            self.complete_launch_boot_assets(&mut launch_spec)?;
            let mut launch_spec = vmmon::prepare_launch_spec(LaunchSpecInput {
                relative_mount_base: &relative_mount_base,
                spec: launch_spec,
            })?;

            let agent_enabled = config.guest.agent.enabled();
            if let Some(agent_path) =
                boot_assets::resolve_agent(&config.guest.agent, &self.components.agent)?
            {
                let agent_config = guest_agent::build_config(GuestAgentConfigInput {
                    paths: &self.paths,
                    machine_name: &config.name,
                    spec: &launch_spec,
                    network,
                    networking: &self.networking,
                    resize_rootfs,
                    user: config.guest.user.as_ref(),
                })?;
                agent_config.validate().context("validate agent config")?;
                let serialized =
                    serde_json::to_vec(&agent_config).context("serialize agent config")?;
                let base_path = boot_asset_overrides_from_spec(&launch_spec)
                    .1
                    .ok_or_else(|| eyre::eyre!("resolved launch spec has no initramfs"))?
                    .to_path_buf();
                let composite_path = machine_paths.composite_initramfs_path();
                crate::initramfs_overlay::write_composite(
                    &base_path,
                    &agent_path,
                    &serialized,
                    &composite_path,
                )?;
                set_launch_initramfs(&mut launch_spec, composite_path);
            } else {
                remove_file_if_exists(&machine_paths.composite_initramfs_path())?;
            }

            remove_file_if_exists(&machine_paths.metadata_config_path())?;

            vmmon::write_launch_spec(&machine_paths.vm_spec_path(), &launch_spec)?;
            Ok(agent_enabled)
        };

        prepare().map_err(|err| LibVmError::MachinePreparationFailed {
            reference: config.name.clone(),
            message: err.to_string(),
        })
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
        let image = self
            .store
            .ensure_image_removable(reference, options.clone())
            .await?;
        let rootfs_store = RootfsImageStore::open(self.local_images_dir())
            .map_err(|err| image_error(&image.requested_reference, err))?;
        let rootfs_options = MaterializeOptions::for_host()
            .map_err(|err| image_error(&image.requested_reference, err))?;
        rootfs_store
            .remove_reference(&image.requested_reference, &rootfs_options.platform)
            .map_err(|err| image_error(&image.requested_reference, err))?;
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

    pub(crate) async fn machine_config(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        self.store.machine_config(machine_id).await
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
        let (status, boot_report, provision_report) = if runtime_status.is_running() {
            match self.vmmon.client(config.id).status().await {
                Ok(response) => {
                    let (boot_report, provision_report) = response
                        .agent
                        .as_ref()
                        .and_then(|agent| match agent.mode.as_ref() {
                            Some(protocol::v1::host_agent::Mode::Enabled(enabled)) => enabled
                                .status
                                .as_ref()
                                .and_then(|status| status.report.as_ref()),
                            _ => None,
                        })
                        .map(|report| {
                            (
                                report
                                    .boot
                                    .clone()
                                    .map(crate::machine::MachineBootReport::from_protocol),
                                report
                                    .provisioning
                                    .clone()
                                    .map(crate::machine::MachineProvisionReport::from_protocol),
                            )
                        })
                        .unwrap_or((None, None));
                    (
                        MachineStatus::from_protocol(response),
                        boot_report,
                        provision_report,
                    )
                }
                Err(message) => (
                    MachineStatus::running_with_message(format!(
                        "vmmon get_status failed: {message}"
                    )),
                    None,
                    None,
                ),
            }
        } else {
            (
                MachineStatus::from_machine_state(state.status, state.last_error.clone()),
                None,
                None,
            )
        };

        let rootfs = self.store.machine_rootfs(config.id).await?;
        Ok(MachineData::from_models_with_status(
            config,
            rootfs,
            status,
            boot_report,
            provision_report,
            state,
        ))
    }
}

fn set_launch_initramfs(spec: &mut VmSpec, path: PathBuf) {
    let boot = spec.boot.get_or_insert(Boot {
        kernel: None,
        userdata: None,
    });
    let kernel = boot.kernel.get_or_insert_with(|| Kernel {
        path: None,
        cmdline: Vec::new(),
        initramfs: None,
    });
    kernel.initramfs = Some(path);
}

fn remove_file_if_exists(path: &Path) -> eyre::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove stale artifact {}", path.display())),
    }
}

const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

fn validate_image_pull_policy(
    source: &ImageSource,
    policy: ImagePullPolicy,
) -> Result<(), LibVmError> {
    if matches!(source, ImageSource::Disk(_)) && policy != ImagePullPolicy::IfMissing {
        return Err(LibVmError::ImagePullPolicyUnsupported {
            policy,
            source_kind: ImageSourceKind::Disk,
        });
    }
    Ok(())
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

fn emit_image_progress_complete(progress: Option<&ImageProgressSender>) {
    if let Some(progress) = progress {
        progress.send(ImageProgress::Complete);
    }
}

fn oci_image_record(
    rootfs: &PublishedRootfs,
    metadata: &RootfsMetadata,
    size_bytes: u64,
    requested_reference: &str,
) -> Result<OciImageRecord, LibVmError> {
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
            image_id: rootfs.flat_ext4().image_id.clone(),
            platform_os: rootfs.flat_ext4().platform.os.clone(),
            platform_architecture: rootfs.flat_ext4().platform.architecture.clone(),
            platform_variant: rootfs.flat_ext4().platform.variant.clone(),
            config_digest: Some(metadata.config_digest.clone()),
            layer_count,
            total_size_bytes,
            created_at,
            last_used_at: Some(now),
        },
        reference: ImageRefRecord {
            requested_reference: requested_reference.to_string(),
            selected_reference: metadata.selected_reference.clone(),
            manifest_digest: manifest_digest.clone(),
            image_id: rootfs.flat_ext4().image_id.clone(),
            platform_os: rootfs.flat_ext4().platform.os.clone(),
            platform_architecture: rootfs.flat_ext4().platform.architecture.clone(),
            platform_variant: rootfs.flat_ext4().platform.variant.clone(),
            size_bytes: Some(size_bytes),
            created_at,
            updated_at: now,
            last_used_at: Some(now),
        },
        config: ImageConfigRecord {
            manifest_digest: manifest_digest.clone(),
            digest: metadata.config_digest.clone(),
            metadata: metadata.config.clone(),
            created_at,
        },
        layers,
        manifest_layers,
        artifact: image_artifact_record(rootfs, metadata, manifest_digest, size_bytes),
    })
}

struct MaterializedImageIdentity {
    requested_reference: String,
    selected_reference: Option<String>,
    manifest_digest: Option<String>,
    config_digest: Option<String>,
}

fn materialized_image_identity(
    source: &ImageSource,
    rootfs: &PublishedRootfs,
    metadata: Option<&RootfsMetadata>,
) -> Result<MaterializedImageIdentity, LibVmError> {
    match source.kind() {
        ImageSourceKind::Oci => {
            let metadata = metadata.ok_or_else(|| LibVmError::StateDecode {
                field: "image.metadata",
                message: format!(
                    "OCI image {} is missing rootfs metadata",
                    rootfs.flat_ext4().requested_reference
                ),
            })?;
            Ok(MaterializedImageIdentity {
                requested_reference: rootfs.flat_ext4().requested_reference.clone(),
                selected_reference: Some(metadata.selected_reference.clone()),
                manifest_digest: Some(effective_oci_manifest_digest(rootfs, metadata)),
                config_digest: Some(metadata.config_digest.clone()),
            })
        }
        ImageSourceKind::Disk => Ok(MaterializedImageIdentity {
            requested_reference: source.source_reference(),
            selected_reference: None,
            manifest_digest: None,
            config_digest: None,
        }),
    }
}

fn effective_oci_manifest_digest(_rootfs: &PublishedRootfs, metadata: &RootfsMetadata) -> String {
    metadata.manifest_digest.clone()
}

fn image_artifact_record(
    rootfs: &PublishedRootfs,
    metadata: &RootfsMetadata,
    manifest_digest: String,
    size_bytes: u64,
) -> ImageRootfsArtifactRecord {
    let now = now_unix();
    ImageRootfsArtifactRecord {
        image_id: rootfs.flat_ext4().image_id.clone(),
        manifest_digest,
        config_digest: metadata.config_digest.clone(),
        platform_os: rootfs.flat_ext4().platform.os.clone(),
        platform_architecture: rootfs.flat_ext4().platform.architecture.clone(),
        platform_variant: rootfs.flat_ext4().platform.variant.clone(),
        filesystem: metadata.filesystem.clone(),
        rootfs_path: rootfs.flat_ext4().path.clone(),
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
    let root_disk_path = config
        .machine_dir
        .join(crate::paths::root_disk_relative_path());
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

pub(crate) fn reconcile_root_disk_size(
    config: &MachineConfig,
) -> Result<crate::machine::root_disk::RootDiskResizeOutcome, LibVmError> {
    let Some(desired_size) = config.root_disk_size else {
        return Ok(crate::machine::root_disk::RootDiskResizeOutcome::GuestRequired);
    };

    let root_disk_path = config
        .machine_dir
        .join(crate::paths::root_disk_relative_path());
    resize_raw_disk(&root_disk_path, desired_size).map_err(Into::into)
}

pub(crate) async fn wait_for_monitor_stop(
    identity: &ProcessIdentity,
    machine_name: &str,
    timeout: std::time::Duration,
) -> Result<(), LibVmError> {
    let poll_interval = std::time::Duration::from_millis(200);
    process::wait_for_exit(identity, machine_name, timeout, poll_interval)
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
    runtime: Option<&MachineState>,
) -> Result<Option<ProcessIdentity>, LibVmError> {
    let stored_pid = runtime.and_then(|state| state.vmmon_pid);
    let expected_started_at = runtime.and_then(|state| state.started_at);
    let recovering_prearmed_start = runtime.is_some_and(|state| {
        state.status == MachineRuntimeState::Starting
            && (state.vmmon_pid.is_none() || state.started_at.is_none())
    });
    let mut last_pid = None;
    for pid in [pid_from_file, stored_pid].into_iter().flatten() {
        if last_pid == Some(pid) {
            continue;
        }
        last_pid = Some(pid);

        let Some(identity) = ProcessIdentity::for_pid(pid)? else {
            continue;
        };
        if identity.is_alive()?
            && (identity_matches_generation(&identity, expected_started_at)
                || recovering_prearmed_start)
        {
            return Ok(Some(identity));
        }
    }

    Ok(None)
}

pub(crate) fn monitor_identity(
    pid: i32,
    pid_path: &Path,
    machine_name: &str,
) -> Result<ProcessIdentity, LibVmError> {
    let Some(identity) = ProcessIdentity::for_pid(pid)? else {
        return Err(LibVmError::MonitorConnection {
            reference: machine_name.to_string(),
            message: format!("vmmon pid {pid} from {} is not running", pid_path.display()),
        });
    };
    if !identity.is_alive()? {
        return Err(LibVmError::MonitorConnection {
            reference: machine_name.to_string(),
            message: format!("vmmon pid {pid} from {} is not running", pid_path.display()),
        });
    }
    Ok(identity)
}

fn runtime_exit_matches(status: &VmmonExitStatus, state: Option<&MachineState>) -> bool {
    let Some(state) = state else {
        return true;
    };

    status.machine_id == state.machine_id.to_string()
        && state.run_id.as_deref() == Some(status.run_id.as_str())
        && state.vmmon_pid == Some(status.pid)
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
    Ok(identity_matches_generation(&identity, generation.started_at) && identity.is_alive()?)
}

fn identity_matches_generation(
    identity: &ProcessIdentity,
    expected_started_at: Option<i64>,
) -> bool {
    expected_started_at.is_none() || identity.matches_started_at(expected_started_at)
}

fn transition_error(err: TransitionError) -> LibVmError {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string()).into()
}

pub(crate) fn interrupt_monitor(identity: &ProcessIdentity) -> io::Result<bool> {
    if !identity.is_alive()? {
        return Ok(false);
    }
    match kill(Pid::from_raw(identity.pid()), Some(Signal::SIGINT)) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}

pub(crate) fn kill_monitor_process_group(identity: &ProcessIdentity) -> io::Result<bool> {
    if !identity.is_alive()? {
        return Ok(false);
    }

    match kill(Pid::from_raw(-identity.pid()), Some(Signal::SIGKILL)) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
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
    use crate::paths::LocalPaths;
    use crate::runtime::core::{
        effective_oci_manifest_digest, materialized_image_identity, oci_image_record,
        read_monitor_pid, stopped_machine_state, validate_image_pull_policy, write_machine_config,
        Runtime, STALE_STARTING_TIMEOUT,
    };
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRootfsRecord, MachineRuntimeState,
        MachineState,
    };
    use crate::store::{MachineStore, MockDataStore, Store};
    use crate::utils::now_unix;
    use crate::vmmon::process::ProcessIdentity;
    use crate::OciImageConfigMetadata;
    use crate::Platform;
    use crate::{
        ImageCacheState, ImageProgress, ImageProgressSender, ImagePullOptions, ImagePullPolicy,
        ImageResolveOptions, ImageSource, LibVmError, MachineExitOutcome, MachineKillOptions,
        MachineRef, MachineRetention, MachineRunId, MachineStatus, MachineUpdate, Memory,
        RuntimeNetworkingConfig,
    };
    use oci::{FlatExt4Artifact, PublishedRootfs, RootfsMetadata};
    use silo_policy::NetworkPolicy;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
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

    fn create_machine_runtime_dirs(runtime: &Runtime, machine_id: MachineId) {
        runtime
            .ensure_machine_runtime_directories(machine_id)
            .expect("create machine runtime directories");
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
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            machine_dir: paths.machine(id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: "test-image:latest".to_string(),
            root_disk_size: None,
            labels: std::collections::BTreeMap::new(),
            metadata: std::collections::BTreeMap::new(),
            network: MachineNetworkConfig::default(),
            guest: crate::machine::MachineGuestConfig::default(),
        }
    }

    fn sample_oci_rootfs_image() -> PublishedRootfs {
        PublishedRootfs::FlatExt4(FlatExt4Artifact {
            path: std::path::PathBuf::from("/tmp/rootfs.img"),
            requested_reference: "ubuntu:latest".to_string(),
            image_id: "sha256:imageid".to_string(),
            manifest_digest: "sha256:imageid".to_string(),
            platform: Platform::linux_arm64(),
        })
    }

    fn sample_oci_rootfs_metadata(manifest_digest: &str) -> RootfsMetadata {
        RootfsMetadata {
            version: 2,
            image_ref: "ubuntu:latest".to_string(),
            image_id: "sha256:imageid".to_string(),
            requested_reference: "ubuntu:latest".to_string(),
            selected_reference: format!("ubuntu@{manifest_digest}"),
            manifest_digest: manifest_digest.to_string(),
            config_digest: "sha256:config".to_string(),
            config: OciImageConfigMetadata::default(),
            layers: Vec::new(),
            platform: Platform::linux_arm64(),
            filesystem: "ext4".to_string(),
            rootfs_file: "rootfs.img".to_string(),
            created_at_unix: 1,
        }
    }

    fn write_cached_oci_rootfs(
        paths: &LocalPaths,
        requested_reference: &str,
        manifest_digest: &str,
        config_digest: &str,
    ) -> RootfsMetadata {
        let platform = Platform::host().expect("host platform");
        let mut cache_key = format!("{}-{}", platform.os, platform.architecture);
        if let Some(variant) = &platform.variant {
            cache_key.push('-');
            cache_key.push_str(variant);
        }
        let image_dir = paths
            .images_dir()
            .join(manifest_digest.replace(':', "-"))
            .join(&cache_key);
        std::fs::create_dir_all(&image_dir).expect("create cached image directory");
        std::fs::write(image_dir.join("rootfs.img"), b"cached rootfs").expect("write rootfs");
        let metadata = RootfsMetadata {
            version: 2,
            image_ref: requested_reference.to_string(),
            image_id: manifest_digest.to_string(),
            requested_reference: requested_reference.to_string(),
            selected_reference: format!("example.invalid/demo@{manifest_digest}"),
            manifest_digest: manifest_digest.to_string(),
            config_digest: config_digest.to_string(),
            config: OciImageConfigMetadata {
                cmd: Some(vec!["serve".to_string()]),
                ..OciImageConfigMetadata::default()
            },
            layers: Vec::new(),
            platform: platform.clone(),
            filesystem: "ext4".to_string(),
            rootfs_file: "rootfs.img".to_string(),
            created_at_unix: 7,
        };
        let mut stored_metadata =
            serde_json::to_value(&metadata).expect("serialize cache metadata");
        stored_metadata
            .as_object_mut()
            .expect("metadata object")
            .insert(
                "source".to_string(),
                serde_json::Value::String("oci-registry".to_string()),
            );
        std::fs::write(
            image_dir.join("metadata.json"),
            serde_json::to_vec(&stored_metadata).expect("serialize stored metadata"),
        )
        .expect("write cache metadata");
        let tag_key = format!("{requested_reference}|{cache_key}");
        std::fs::write(
            paths.images_dir().join("index.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "tags": {
                    tag_key: {
                        "image_ref": requested_reference,
                        "platform": platform,
                        "manifest_digest": manifest_digest,
                        "updated_at_unix": 7
                    }
                }
            }))
            .expect("serialize cache index"),
        )
        .expect("write cache index");
        metadata
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
        let components = crate::runtime::components::test_components(paths.data_dir());
        Runtime::from_store(
            paths,
            Arc::new(store),
            RuntimeNetworkingConfig::default(),
            components,
            None,
        )
        .await
        .expect("create runtime with mock store")
    }

    fn write_test_asset(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).expect("create asset dir");
        let path = dir.join(name);
        std::fs::write(&path, b"asset").expect("write asset");
        path
    }

    fn write_complete_portable_runtime(root: &std::path::Path) -> std::path::PathBuf {
        let bin = root.join("bin");
        let assets = root.join("assets");
        std::fs::create_dir_all(&bin).expect("create runtime bin");
        std::fs::create_dir_all(&assets).expect("create runtime assets");
        for helper in ["netd", "krun"] {
            let path = bin.join(helper);
            std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write helper");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("make helper executable");
        }
        let vmmon = bin.join("vmmon");
        std::fs::write(
            &vmmon,
            "#!/bin/sh\ntrace=\nprevious=\nfor arg do\n  if [ \"$previous\" = \"--trace-log\" ]; then trace=\"$arg\"; fi\n  previous=\"$arg\"\ndone\nprintf '%s\\n' \"$0\" > \"$trace.program\"\nprintf '%s\\n' \"$@\" > \"$trace.args\"\n( sleep 1; eval \"printf 'started\\n' >&$_VM_SYNCPIPE\" ) &\nexit 0\n",
        )
        .expect("write vmmon helper");
        std::fs::set_permissions(&vmmon, std::fs::Permissions::from_mode(0o755))
            .expect("make vmmon executable");
        for (asset, mode) in [
            ("kernel-default", 0o644),
            ("initramfs", 0o644),
            ("agent", 0o755),
        ] {
            let path = assets.join(asset);
            std::fs::write(&path, asset).expect("write runtime asset");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set runtime asset mode");
        }
        root.to_path_buf()
    }

    #[test]
    fn resolved_default_assets_stay_together_while_machine_overrides_remain_independent() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime_root = write_complete_portable_runtime(&temp.path().join("runtime"));
        let components = crate::runtime::components::test_components(&runtime_root);
        let override_kernel = write_test_asset(temp.path(), "custom-kernel");
        let assets = crate::runtime::boot_assets::resolve_boot_assets(
            crate::runtime::boot_assets::BootAssetOverrides {
                kernel: Some(&override_kernel),
                initramfs: None,
            },
            &components.kernel,
            &components.initramfs,
        )
        .expect("resolve assets");

        assert_eq!(
            assets.kernel,
            override_kernel.canonicalize().expect("canonical kernel")
        );
        assert_eq!(
            assets.initramfs,
            runtime_root
                .join("assets/initramfs")
                .canonicalize()
                .expect("canonical initramfs")
        );
        assert_eq!(
            crate::runtime::boot_assets::resolve_agent(
                &crate::machine::MachineAgent::Default,
                &components.agent,
            )
            .expect("resolve default agent"),
            Some(
                runtime_root
                    .join("assets/agent")
                    .canonicalize()
                    .expect("canonical agent")
            )
        );
    }

    #[tokio::test]
    async fn launch_boot_assets_preserve_explicit_initramfs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let asset_dir = temp.path().join("assets");
        let kernel = write_test_asset(&asset_dir, "kernel-default");
        let explicit_initramfs = write_test_asset(&asset_dir, "explicit-initramfs");
        let mut store = MockDataStore::new();
        expect_empty_refresh(&mut store);
        let runtime =
            runtime_with_mock_store(LocalPaths::new(temp.path().join("data")), store).await;
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
        let metadata = sample_oci_rootfs_metadata("sha256:manifest");

        let digest = effective_oci_manifest_digest(&rootfs, &metadata);

        assert_eq!(digest, "sha256:manifest");
    }

    #[test]
    fn materialized_oci_manifest_digest_matches_record_metadata() {
        let source = ImageSource::oci("ubuntu:latest");
        let rootfs = sample_oci_rootfs_image();
        let metadata = sample_oci_rootfs_metadata("sha256:manifest");

        let identity = materialized_image_identity(&source, &rootfs, Some(&metadata))
            .expect("materialized identity should resolve");
        let record = oci_image_record(&rootfs, &metadata, 4, "ubuntu:latest")
            .expect("OCI image record should resolve");

        assert_eq!(identity.manifest_digest.as_deref(), Some("sha256:manifest"));
        assert_eq!(identity.config_digest.as_deref(), Some("sha256:config"));
        assert_eq!(
            identity.selected_reference.as_deref(),
            Some("ubuntu@sha256:manifest")
        );
        assert_eq!(record.manifest.digest, "sha256:manifest");
        assert_eq!(record.reference.manifest_digest, "sha256:manifest");
        assert_eq!(record.artifact.manifest_digest, "sha256:manifest");
    }

    #[test]
    fn disk_sources_reject_oci_pull_policies() {
        let disk = ImageSource::disk("rootfs.img");

        for policy in [
            crate::ImagePullPolicy::Always,
            crate::ImagePullPolicy::Never,
        ] {
            let error = validate_image_pull_policy(&disk, policy)
                .expect_err("disk source must reject OCI pull policy");
            assert!(matches!(
                error,
                LibVmError::ImagePullPolicyUnsupported {
                    policy: actual,
                    source_kind: crate::ImageSourceKind::Disk,
                } if actual == policy
            ));
        }
        validate_image_pull_policy(&disk, crate::ImagePullPolicy::IfMissing)
            .expect("default disk materialization remains supported");
    }

    #[tokio::test]
    async fn materializing_a_local_disk_skips_the_oci_cache() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("open runtime");
        let disk = temp.path().join("rootfs.img");
        std::fs::write(&disk, b"caller-owned disk").expect("write local disk");

        let image = runtime
            .materialize_image(&ImageSource::disk(&disk))
            .await
            .expect("materialize local disk");

        assert_eq!(
            image.rootfs_path,
            disk.canonicalize().expect("canonical local disk")
        );
        assert_eq!(image.source_kind, crate::ImageSourceKind::Disk);
        assert!(image.image_id.is_some());
        assert!(!paths.images_dir().exists());
    }

    #[tokio::test]
    async fn resolve_uses_complete_cache_without_writing_or_contacting_registry() {
        const REFERENCE: &str = "example.invalid/demo:mutable";
        const MANIFEST: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const CONFIG: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("open runtime");
        let metadata = write_cached_oci_rootfs(&paths, REFERENCE, MANIFEST, CONFIG);
        let index_before =
            std::fs::read(paths.images_dir().join("index.json")).expect("read index");
        let metadata_before = std::fs::read(
            paths
                .images_dir()
                .join(MANIFEST.replace(':', "-"))
                .join(format!(
                    "{}-{}",
                    metadata.platform.os, metadata.platform.architecture
                ))
                .join("metadata.json"),
        )
        .expect("read metadata");

        for policy in [ImagePullPolicy::IfMissing, ImagePullPolicy::Never] {
            let resolved = runtime
                .images()
                .resolve_with(
                    REFERENCE,
                    ImageResolveOptions {
                        policy: Some(policy),
                    },
                )
                .await
                .expect("complete cache must avoid example.invalid");
            assert_eq!(resolved.requested_reference, REFERENCE);
            assert_eq!(resolved.selected_reference, metadata.selected_reference);
            assert_eq!(resolved.manifest_digest, MANIFEST);
            assert_eq!(resolved.config, metadata.config);
            assert_eq!(resolved.cache_state, ImageCacheState::Complete);
        }

        assert!(runtime
            .images()
            .list()
            .await
            .expect("list images")
            .is_empty());
        assert_eq!(
            std::fs::read(paths.images_dir().join("index.json")).expect("read index"),
            index_before
        );
        assert_eq!(
            std::fs::read(
                paths
                    .images_dir()
                    .join(MANIFEST.replace(':', "-"))
                    .join(format!(
                        "{}-{}",
                        metadata.platform.os, metadata.platform.architecture
                    ))
                    .join("metadata.json"),
            )
            .expect("read metadata"),
            metadata_before
        );

        let error = runtime
            .images()
            .resolve_with(
                "example.invalid/missing:mutable",
                ImageResolveOptions {
                    policy: Some(ImagePullPolicy::Never),
                },
            )
            .await
            .expect_err("Never must not contact a missing registry reference");
        assert!(matches!(error, LibVmError::ImageNotFound { .. }));
    }

    #[tokio::test]
    async fn pulling_a_second_tag_for_a_cached_manifest_preserves_the_requested_tag() {
        const FIRST_REFERENCE: &str = "example.invalid/demo:first";
        const SECOND_REFERENCE: &str = "example.invalid/demo:second";
        const MANIFEST: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const CONFIG: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("open runtime");
        let metadata = write_cached_oci_rootfs(&paths, FIRST_REFERENCE, MANIFEST, CONFIG);
        let cache_key = format!(
            "{}-{}",
            metadata.platform.os, metadata.platform.architecture
        );
        let index_path = paths.images_dir().join("index.json");
        let mut index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index_path).expect("read cache index"))
                .expect("decode cache index");
        let first_key = format!("{FIRST_REFERENCE}|{cache_key}");
        let mut second_tag = index["tags"][&first_key].clone();
        second_tag["image_ref"] = serde_json::Value::String(SECOND_REFERENCE.to_string());
        index["tags"]
            .as_object_mut()
            .expect("cache tags")
            .insert(format!("{SECOND_REFERENCE}|{cache_key}"), second_tag);
        std::fs::write(
            &index_path,
            serde_json::to_vec_pretty(&index).expect("encode cache index"),
        )
        .expect("write cache index");

        let handle = runtime
            .images()
            .pull_with(
                SECOND_REFERENCE,
                ImagePullOptions {
                    policy: Some(ImagePullPolicy::Never),
                },
            )
            .await
            .expect("pull second cached tag");

        assert_eq!(handle.requested_reference, SECOND_REFERENCE);
        assert_eq!(handle.selected_manifest_digest, MANIFEST);
        assert!(runtime
            .images()
            .get(FIRST_REFERENCE)
            .await
            .expect("get first tag")
            .is_none());
        assert!(runtime
            .images()
            .get(SECOND_REFERENCE)
            .await
            .expect("get second tag")
            .is_some());
    }

    #[tokio::test]
    async fn removing_an_image_clears_the_cache_reference_until_prune() {
        const REFERENCE: &str = "example.invalid/demo:mutable";
        const MANIFEST: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const CONFIG: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("open runtime");
        let metadata = write_cached_oci_rootfs(&paths, REFERENCE, MANIFEST, CONFIG);
        let artifact_dir = paths
            .images_dir()
            .join(MANIFEST.replace(':', "-"))
            .join(format!(
                "{}-{}",
                metadata.platform.os, metadata.platform.architecture
            ));

        runtime
            .images()
            .pull_with(
                REFERENCE,
                ImagePullOptions {
                    policy: Some(ImagePullPolicy::Never),
                },
            )
            .await
            .expect("persist cached image reference");
        runtime
            .images()
            .remove(REFERENCE)
            .await
            .expect("remove image reference");

        let index: serde_json::Value = serde_json::from_slice(
            &std::fs::read(paths.images_dir().join("index.json")).expect("read cache index"),
        )
        .expect("decode cache index");
        assert!(
            index["tags"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty),
            "removal must clear the OCI tag mapping: {index}"
        );

        assert!(runtime
            .images()
            .get(REFERENCE)
            .await
            .expect("look up removed image")
            .is_none());
        let error = runtime
            .images()
            .pull_with(
                REFERENCE,
                ImagePullOptions {
                    policy: Some(ImagePullPolicy::Never),
                },
            )
            .await
            .expect_err("removed reference must miss the Never cache");
        assert!(matches!(error, LibVmError::ImageNotFound { .. }));
        assert!(
            artifact_dir.exists(),
            "removal must retain artifact until prune"
        );

        let report = runtime
            .images()
            .prune()
            .await
            .expect("prune image artifacts");
        assert_eq!(report.artifacts_removed, 1);
        assert!(!artifact_dir.exists());
    }

    #[tokio::test]
    async fn resolved_image_builder_persists_the_selected_identity() {
        const REFERENCE: &str = "example.invalid/demo:mutable";
        const MANIFEST: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const CONFIG: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("open runtime");
        let metadata = write_cached_oci_rootfs(&paths, REFERENCE, MANIFEST, CONFIG);
        let (progress, mut progress_events) = ImageProgressSender::default_channel();
        let progress_runtime = runtime.clone().with_image_progress(progress);
        let resolved = progress_runtime
            .images()
            .resolve_with(
                REFERENCE,
                ImageResolveOptions {
                    policy: Some(ImagePullPolicy::Never),
                },
            )
            .await
            .expect("resolve cached image");
        let selected_reference = resolved.selected_reference.clone();

        let machine = progress_runtime
            .machine()
            .name("resolved-image")
            .resolved_image(resolved)
            .create()
            .await
            .expect("create machine from resolved image");
        drop(progress_runtime);
        let mut events = Vec::new();
        while let Some(event) = progress_events.recv().await {
            events.push(event);
        }
        assert_eq!(
            events,
            [
                ImageProgress::CheckingCache {
                    image_ref: REFERENCE.to_string(),
                },
                ImageProgress::CacheHit {
                    image_ref: REFERENCE.to_string(),
                },
                ImageProgress::Complete,
            ]
        );
        let rootfs = runtime
            .store
            .machine_rootfs(machine.machine_id())
            .await
            .expect("read rootfs pin")
            .expect("machine rootfs pin");

        assert_eq!(rootfs.requested_reference, REFERENCE);
        assert_eq!(
            rootfs.selected_reference.as_deref(),
            Some(selected_reference.as_str())
        );
        assert_eq!(rootfs.manifest_digest.as_deref(), Some(MANIFEST));
        assert_eq!(rootfs.config_digest.as_deref(), Some(CONFIG));
        assert_eq!(
            runtime
                .images()
                .get(REFERENCE)
                .await
                .expect("read persisted image")
                .expect("persisted image")
                .selected_reference,
            metadata.selected_reference
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
            std::fs::set_permissions(
                machine_dir
                    .parent()
                    .ok_or_else(|| LibVmError::InvalidOwnedPath {
                        path: machine_dir.clone(),
                        message: "machine path has no owner directory".to_string(),
                    })?,
                std::fs::Permissions::from_mode(0o700),
            )?;

            let spec = sample_vm_spec();
            write_machine_config(&machine_dir, &self.name, &spec)?;
            std::fs::write(
                machine_dir.join(crate::paths::root_disk_relative_path()),
                b"disk",
            )?;

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
                retention: crate::MachineRetention::Persistent,
                process: crate::ProcessConfig::default(),
                template_name: None,
                agent_mode: None,
                machine_dir: machine_dir.clone(),
                created_at: now,
                modified_at: now,
                image_ref: "test-image:latest".to_string(),
                root_disk_size: self.root_disk_size,
                labels: std::collections::BTreeMap::new(),
                metadata: std::collections::BTreeMap::new(),
                network: MachineNetworkConfig::default(),
                guest: crate::machine::MachineGuestConfig::default(),
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

    fn write_start_failure_components(paths: &LocalPaths, vmmon: &str) {
        let root = paths.data_dir();
        let bin = root.join("bin");
        let assets = root.join("assets");
        std::fs::create_dir_all(&bin).expect("create test runtime binaries");
        std::fs::create_dir_all(&assets).expect("create test runtime assets");
        let netd = bin.join("netd");
        std::fs::write(
            &netd,
            "#!/bin/sh\nsocket=\nprevious=\nfor arg do\n  if [ \"$previous\" = \"--listen-vfkit\" ]; then socket=\"${arg#unixgram://}\"; fi\n  previous=\"$arg\"\ndone\n: > \"$socket\"\nwhile :; do sleep 1; done\n",
        )
        .expect("write test netd");
        std::fs::set_permissions(&netd, std::fs::Permissions::from_mode(0o755))
            .expect("make test netd executable");
        let vmmon_path = bin.join("vmmon");
        std::fs::write(&vmmon_path, vmmon).expect("write test vmmon");
        std::fs::set_permissions(&vmmon_path, std::fs::Permissions::from_mode(0o755))
            .expect("make test vmmon executable");
        for asset in ["kernel-default", "initramfs"] {
            std::fs::write(assets.join(asset), b"asset").expect("write test boot asset");
        }
    }

    async fn start_failure_runtime(
        temp: &tempfile::TempDir,
        vmmon: &str,
    ) -> (Runtime, MachineConfig, Arc<Store>) {
        let paths = LocalPaths::new(temp.path().join("silo"));
        write_start_failure_components(&paths, vmmon);
        let store = Arc::new(Store::new(&paths).await.expect("open test store"));
        let components = crate::runtime::components::test_components(paths.data_dir());
        let runtime = Runtime::from_store(
            paths,
            store.clone(),
            RuntimeNetworkingConfig::default(),
            components,
            None,
        )
        .await
        .expect("create runtime");
        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let mut config = runtime
            .machine_config(machine.id)
            .await
            .expect("read machine config")
            .expect("machine config exists");
        config.guest.agent = crate::machine::MachineAgent::Disabled;
        runtime
            .save_machine_config(&config)
            .await
            .expect("disable test guest agent");
        (runtime, config, store)
    }

    async fn assert_failed_start_network_is_clean(runtime: &Runtime, machine_id: MachineId) {
        assert!(runtime
            .store
            .network_attachment(machine_id)
            .await
            .expect("read network attachment")
            .is_none());
        let network_root = runtime.paths.roots().net_dir();
        if network_root.exists() {
            assert!(std::fs::read_dir(network_root)
                .expect("read network runtime root")
                .next()
                .is_none());
        }
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
            .env("SILO_LIBVM_SIGINT_IGNORING_CHILD", "1")
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
            if line.trim() == "SILO_READY" {
                return;
            }
        }
    }

    #[test]
    fn sigint_ignoring_child_process() {
        if std::env::var_os("SILO_LIBVM_SIGINT_IGNORING_CHILD").is_none() {
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
        println!("SILO_READY");
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

    #[tokio::test]
    async fn start_failures_after_network_preparation_remove_network_runtime() {
        let launch_failure = "#!/bin/sh\nexit 23\n";
        let missing_pid = "#!/bin/sh\neval \"printf 'started\\n' >&$_VM_SYNCPIPE\"\nexit 0\n";
        let missing_process = "#!/bin/sh\npidfile=\nprevious=\nfor arg do\n  if [ \"$previous\" = \"--pidfile\" ]; then pidfile=\"$arg\"; fi\n  previous=\"$arg\"\ndone\nprintf '999999\\n' > \"$pidfile\"\neval \"printf 'started\\n' >&$_VM_SYNCPIPE\"\nexit 0\n";

        let temp = tempfile::tempdir().expect("create temp dir");
        let (runtime, mut config, _store) = start_failure_runtime(&temp, launch_failure).await;
        config.spec.mounts.push(vm_spec::Mount {
            source: std::path::PathBuf::from("~unsupported"),
            tag: "invalid".to_string(),
            read_only: true,
        });
        runtime
            .save_machine_config(&config)
            .await
            .expect("persist invalid launch spec");

        machine_handle(&runtime, config.id)
            .start()
            .await
            .expect_err("launch input preparation must fail");

        assert_failed_start_network_is_clean(&runtime, config.id).await;

        for vmmon in [launch_failure, missing_pid, missing_process] {
            let temp = tempfile::tempdir().expect("create temp dir");
            let (runtime, config, _store) = start_failure_runtime(&temp, vmmon).await;

            machine_handle(&runtime, config.id)
                .start()
                .await
                .expect_err("test vmmon must fail to start");

            assert_failed_start_network_is_clean(&runtime, config.id).await;
            assert!(!runtime
                .machine_state(config.id)
                .await
                .expect("read failed start state")
                .status
                .is_running());
            machine_handle(&runtime, config.id)
                .start()
                .await
                .expect_err("failed start must remain retryable");
            assert_failed_start_network_is_clean(&runtime, config.id).await;
        }
    }

    #[tokio::test]
    async fn request_start_failure_after_network_preparation_removes_network_runtime() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let (runtime, config, store) = start_failure_runtime(&temp, "#!/bin/sh\nexit 23\n").await;
        store
            .execute_test_sql(
                "CREATE TRIGGER reject_start_request
             BEFORE UPDATE ON machine_state WHEN NEW.status = 'starting'
             BEGIN SELECT RAISE(FAIL, 'forced start request failure'); END",
            )
            .await
            .expect("reject start request state write");

        let error = machine_handle(&runtime, config.id)
            .start()
            .await
            .expect_err("start request state write must fail");

        assert!(error.to_string().contains("forced start request failure"));
        assert_failed_start_network_is_clean(&runtime, config.id).await;
    }

    #[tokio::test]
    async fn start_rejects_noncanonical_machine_directory_before_creating_runtime_files() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths, RuntimeNetworkingConfig::default())
            .await
            .expect("create runtime");
        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let mut config = runtime
            .machine_config(machine.id)
            .await
            .expect("read machine config")
            .expect("machine config exists");
        config.machine_dir = temp.path().join("outside-machine-data");
        runtime
            .save_machine_config(&config)
            .await
            .expect("persist invalid machine directory");

        let error = machine_handle(&runtime, config.id)
            .start()
            .await
            .expect_err("noncanonical machine directory must fail start");

        assert!(matches!(error, LibVmError::InvalidOwnedPath { .. }));
        assert!(!runtime.paths.machine(config.id).machine_run_dir().exists());
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
        let paths = LocalPaths::new(temp.path().join("silo"));
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
        let paths = LocalPaths::new(temp.path().join("silo"));
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
        let paths = LocalPaths::new(temp.path().join("silo"));
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
        let paths = LocalPaths::new(temp.path().join("silo"));
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
        let paths = LocalPaths::new(temp.path().join("silo"));
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
            LocalPaths::new(temp.path().join("silo")),
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
    async fn inspect_exposes_the_durable_oci_rootfs_pin() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("create runtime");
        let id = MachineId::new();
        let config = sample_machine_config(&paths, id, "rootfs-inspect");
        std::fs::create_dir_all(&config.machine_dir).expect("create machine directory");
        runtime
            .store
            .save_oci_image(
                &oci_image_record(
                    &sample_oci_rootfs_image(),
                    &sample_oci_rootfs_metadata("sha256:manifest"),
                    4,
                    "ubuntu:latest",
                )
                .expect("build OCI image record"),
            )
            .await
            .expect("persist OCI image");
        runtime
            .add_machine_record_with_rootfs(
                &config,
                &stopped_state(id),
                &MachineRootfsRecord {
                    machine_id: id,
                    source_kind: crate::ImageSourceKind::Oci,
                    requested_reference: "example.test/demo:latest".to_string(),
                    selected_reference: Some("example.test/demo@sha256:manifest".to_string()),
                    manifest_digest: Some("sha256:manifest".to_string()),
                    config_digest: Some("sha256:config".to_string()),
                    image_id: Some("sha256:image-id".to_string()),
                    root_disk_path: config.machine_dir.join("rootfs.img"),
                    root_disk_size_bytes: 64 * 1024 * 1024,
                    created_at: 7,
                },
            )
            .await
            .expect("persist machine rootfs pin");

        let data = runtime
            .machine_inspect_data(config)
            .await
            .expect("inspect machine");
        let rootfs = data.rootfs.expect("rootfs pin is present");
        assert_eq!(rootfs.requested_reference, "example.test/demo:latest");
        assert_eq!(
            rootfs.selected_reference.as_deref(),
            Some("example.test/demo@sha256:manifest")
        );
        assert_eq!(
            rootfs.selected_manifest_digest.as_deref(),
            Some("sha256:manifest")
        );
        assert_eq!(rootfs.config_digest.as_deref(), Some("sha256:config"));
        assert_eq!(rootfs.image_id.as_deref(), Some("sha256:image-id"));
    }

    #[tokio::test]
    async fn inspect_and_list_use_name_and_id_lookup() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
        let machine_id = machine.id;
        let mut child = ChildGuard::sleep_ignoring_sigint();
        let pid = child.id() as i32;
        let started_at = child.started_at();
        create_machine_runtime_dirs(&runtime, machine_id);
        let pid_path = runtime.paths.machine(machine_id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{pid}\n")).expect("write pid file");
        runtime
            .set_machine_state(
                machine_id,
                MachineRuntimeState::Running,
                Some(pid),
                started_at,
                Some("run-1".to_string()),
                None,
            )
            .await
            .expect("set running state");
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
    async fn generation_checked_stop_does_not_clean_up_a_replacement_run() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
        let mut old_monitor = ChildGuard::sleep_ignoring_sigint();
        let old_pid = old_monitor.id() as i32;
        let old_started_at = old_monitor.started_at();
        create_machine_runtime_dirs(&runtime, machine.id);
        let machine_paths = runtime.machine_paths(machine.id);
        std::fs::write(machine_paths.vmmon_pid_path(), format!("{old_pid}\n"))
            .expect("write old pid file");
        std::fs::write(machine_paths.vmmon_socket_path(), b"replacement sentinel")
            .expect("write runtime sentinel");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(old_pid),
                old_started_at,
                Some("run-old".to_string()),
                None,
            )
            .await
            .expect("set old generation");

        let old_machine = machine_handle(&runtime, machine.id);
        let old_run = MachineRunId::from_raw("run-old".to_string());
        let stop_task = tokio::spawn(async move { old_machine.stop_run(old_run).await });
        wait_for_machine_state(&runtime, machine.id, MachineRuntimeState::Stopping).await;

        let replacement_monitor = ChildGuard::sleep_ignoring_sigint();
        let replacement_pid = replacement_monitor.id() as i32;
        let replacement_started_at = replacement_monitor.started_at();
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(replacement_pid),
                replacement_started_at,
                Some("run-new".to_string()),
                None,
            )
            .await
            .expect("install replacement generation");

        old_monitor.kill();
        let error = stop_task
            .await
            .expect("join old stop")
            .expect_err("old stop must not clean up the replacement run");
        assert!(matches!(
            error,
            LibVmError::MachineStaleGeneration {
                requested,
                current: Some(current),
                ..
            } if requested.as_str() == "run-old" && current.as_str() == "run-new"
        ));
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read replacement state");

        let wait_error = machine_handle(&runtime, machine.id)
            .wait_for_run(MachineRunId::from_raw("run-old".to_string()))
            .await
            .expect_err("old wait must not observe the replacement run");
        assert!(matches!(
            wait_error,
            LibVmError::MachineStaleGeneration { .. }
        ));
        let kill_error = machine_handle(&runtime, machine.id)
            .kill_run(MachineRunId::from_raw("run-old".to_string()))
            .await
            .expect_err("old kill must not signal the replacement run");
        assert!(matches!(
            kill_error,
            LibVmError::MachineStaleGeneration { .. }
        ));

        assert_eq!(state.status, MachineRuntimeState::Running);
        assert_eq!(state.run_id.as_deref(), Some("run-new"));
        assert!(ProcessIdentity::for_pid(replacement_pid)
            .expect("read replacement monitor")
            .expect("replacement monitor should exist")
            .is_alive()
            .expect("check replacement monitor"));
        assert!(machine_paths.vmmon_socket_path().exists());
    }

    #[tokio::test]
    async fn generation_checked_stop_accepts_a_concurrent_terminal_completion() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("create runtime");
        let concurrent_store = Store::new(&paths)
            .await
            .expect("open concurrent SQLite connection");
        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let machine_id = machine.id;
        let mut monitor = ChildGuard::sleep_ignoring_sigint();
        let pid = monitor.id() as i32;
        let started_at = monitor.started_at();
        create_machine_runtime_dirs(&runtime, machine_id);
        let pid_path = runtime.paths.machine(machine_id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{pid}\n")).expect("write pid file");
        runtime
            .set_machine_state(
                machine_id,
                MachineRuntimeState::Running,
                Some(pid),
                started_at,
                Some("run-old".to_string()),
                None,
            )
            .await
            .expect("set running state");

        let stopping_machine = machine_handle(&runtime, machine_id);
        let stop_task = tokio::spawn(async move {
            stopping_machine
                .stop_run(MachineRunId::from_raw("run-old".to_string()))
                .await
        });
        wait_for_machine_state(&runtime, machine_id, MachineRuntimeState::Stopping).await;

        concurrent_store
            .save_machine_state(&stopped_machine_state(machine_id, None))
            .await
            .expect("record concurrent terminal completion");
        monitor.kill();

        let machine = stop_task
            .await
            .expect("join stop task")
            .expect("captured terminal completion should be idempotent");
        assert_eq!(machine.status, MachineStatus::Stopped);
        assert_eq!(
            runtime
                .machine_state(machine_id)
                .await
                .expect("read terminal state")
                .status,
            MachineRuntimeState::Stopped
        );
    }

    #[tokio::test]
    async fn wait_reports_matching_exit_status_when_monitor_already_exited() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
        create_machine_runtime_dirs(&runtime, machine.id);
        let exit_status_path = runtime.paths.machine(machine.id).vmmon_exit_status_path();
        std::fs::write(
            &exit_status_path,
            format!(
                r#"{{"machineId":"{}","runId":"run-1","pid":12345,"exitedAt":99,"outcome":"error","error":"runtime exploded"}}"#,
                machine.id
            ),
        )
        .expect("write exit status");
        std::fs::set_permissions(&exit_status_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure exit status");

        let exit = machine_handle(&runtime, machine.id)
            .wait()
            .await
            .expect("wait should report vmmon exit status");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(exit.run_id, None);
        assert_eq!(exit.outcome, MachineExitOutcome::AlreadyStopped);
        assert_eq!(exit.machine.status.label(), "error");
        assert_eq!(state.status, MachineRuntimeState::Error);
        assert_eq!(state.last_error.as_deref(), Some("runtime exploded"));
    }

    #[tokio::test]
    async fn kill_with_returns_forced_machine_exit() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
        let run_id = uuid::Uuid::new_v4();
        create_machine_runtime_dirs(&runtime, machine.id);
        let pid_path = runtime.paths.machine(machine.id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{pid}\n")).expect("write pid file");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(pid),
                started_at,
                Some(run_id.to_string()),
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
        let expected_run_id = run_id.to_string();
        assert_eq!(
            exit.run_id.as_ref().map(|run_id| run_id.as_str()),
            Some(expected_run_id.as_str())
        );
        assert_eq!(exit.outcome, MachineExitOutcome::Forced);
        assert_eq!(exit.machine.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
    }

    #[tokio::test]
    async fn stop_starting_without_live_monitor_marks_machine_stopped() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
        create_machine_runtime_dirs(&runtime, machine.id);
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
    async fn stop_reconciles_stopped_runtime_and_cleans_resources() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
        runtime
            .ensure_machine_runtime_directories(machine.id)
            .expect("create runtime trees");
        let machine_paths = runtime.machine_paths(machine.id);
        std::fs::write(machine_paths.vmmon_socket_path(), b"runtime")
            .expect("write runtime sentinel");
        std::fs::write(machine_paths.serial_log_path(), b"durable log").expect("write durable log");
        std::fs::set_permissions(
            machine_paths.serial_log_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("secure durable log");

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
        assert_eq!(state.vmmon_pid, None);
        assert!(!machine_paths.machine_run_dir().exists());
        assert_eq!(
            std::fs::read(machine_paths.serial_log_path()).expect("read durable log"),
            b"durable log"
        );
    }

    #[tokio::test]
    async fn stop_finishes_starting_machine_without_live_runtime() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
    async fn stop_finishes_stopping_machine_without_live_runtime() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
            .stop()
            .await
            .expect("stop machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        assert_eq!(state.vmmon_pid, None);
    }

    #[tokio::test]
    async fn stop_interrupts_live_runtime() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
        create_machine_runtime_dirs(&runtime, machine.id);
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
            .stop()
            .await
            .expect("stop machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status, MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        assert_eq!(state.vmmon_pid, None);
        drop(child);
    }

    #[tokio::test]
    async fn list_reconciles_stopping_without_live_runtime_to_stopped() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
        create_machine_runtime_dirs(&runtime, machine.id);
        let exit_status_path = runtime.paths.machine(machine.id).vmmon_exit_status_path();
        std::fs::write(
            &exit_status_path,
            format!(
                r#"{{"machineId":"{}","runId":"run-1","pid":12345,"exitedAt":99,"outcome":"error","error":"runtime exploded"}}"#,
                machine.id
            ),
        )
        .expect("write exit status");
        std::fs::set_permissions(&exit_status_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure exit status");

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
            LocalPaths::new(temp.path().join("silo")),
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
        create_machine_runtime_dirs(&runtime, machine.id);
        let exit_status_path = runtime.paths.machine(machine.id).vmmon_exit_status_path();
        std::fs::write(
            &exit_status_path,
            format!(
                r#"{{"machineId":"{}","runId":"run-1","pid":12345,"exitedAt":99,"outcome":"error","error":"old runtime exploded"}}"#,
                machine.id
            ),
        )
        .expect("write stale exit status");
        std::fs::set_permissions(&exit_status_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure stale exit status");

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
            LocalPaths::new(temp.path().join("silo")),
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
        let data_dir = temp.path().join("silo");
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
    async fn reopened_prearmed_ephemeral_start_recovers_a_live_pidfile() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("create runtime");
        let config = add_ephemeral_machine(&runtime, "prearmed-live-pidfile").await;
        runtime
            .request_machine_start(&config, "run-one")
            .await
            .expect("pre-arm ephemeral start");
        let stale_age = i64::try_from(STALE_STARTING_TIMEOUT.as_secs()).expect("timeout fits i64");
        runtime
            .store
            .save_machine_state(&MachineState {
                machine_id: config.id,
                status: MachineRuntimeState::Starting,
                vmmon_pid: None,
                started_at: None,
                run_id: Some("run-one".to_string()),
                last_error: None,
                updated_at: now_unix() - stale_age - 1,
            })
            .await
            .expect("simulate crash after pre-arm");
        create_machine_runtime_dirs(&runtime, config.id);
        let mut monitor = ChildGuard::sleep();
        std::fs::write(
            runtime.machine_paths(config.id).vmmon_pid_path(),
            format!("{}\n", monitor.id()),
        )
        .expect("write live vmmon pidfile");
        drop(runtime);

        let reopened = Runtime::open(paths, RuntimeNetworkingConfig::default())
            .await
            .expect("reopen after pre-arm crash");
        let recovered = reopened
            .machine_state(config.id)
            .await
            .expect("recover runtime state");
        assert_eq!(recovered.status, MachineRuntimeState::Starting);
        assert_eq!(recovered.vmmon_pid, Some(monitor.id() as i32));
        assert_eq!(recovered.run_id.as_deref(), Some("run-one"));
        assert!(reopened
            .machine_config(config.id)
            .await
            .expect("read machine config")
            .is_some());
        assert!(config.machine_dir.exists());

        let recovered_at = recovered.updated_at;
        tokio::time::sleep(Duration::from_secs(1)).await;
        reopened
            .reconcile_machine_runtime_best_effort(&config)
            .await
            .expect("reconcile recovered monitor");
        assert_eq!(
            reopened
                .machine_state(config.id)
                .await
                .expect("read recovered state")
                .updated_at,
            recovered_at,
            "reconciliation must not keep refreshing a recovered starting state"
        );
        monitor.kill();
    }

    #[tokio::test]
    async fn ephemeral_pre_vmmon_start_failure_cleans_up_immediately() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let (runtime, mut config, _store) =
            start_failure_runtime(&temp, "#!/bin/sh\nexit 23\n").await;
        config.retention = MachineRetention::Ephemeral;
        config.spec.mounts.push(vm_spec::Mount {
            source: std::path::PathBuf::from("~unsupported"),
            tag: "invalid".to_string(),
            read_only: true,
        });
        runtime
            .save_machine_config(&config)
            .await
            .expect("persist ephemeral invalid launch spec");

        let error = machine_handle(&runtime, config.id)
            .start()
            .await
            .expect_err("pre-vmmon preparation must fail");
        assert!(matches!(error, LibVmError::MachinePreparationFailed { .. }));
        assert!(runtime
            .machine_config(config.id)
            .await
            .expect("read cleaned machine")
            .is_none());
        assert!(!config.machine_dir.exists());
    }

    #[tokio::test]
    async fn inspect_uses_sqlite_config_when_config_file_is_missing() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
            LocalPaths::new(temp.path().join("silo")),
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
        let root_disk = machine
            .machine_dir
            .join(crate::paths::root_disk_relative_path());
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
            LocalPaths::new(temp.path().join("silo")),
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
        runtime
            .ensure_machine_runtime_directories(machine.id)
            .expect("create runtime trees");
        let machine_paths = runtime.machine_paths(machine.id);
        std::fs::write(machine_paths.serial_log_path(), b"remove me").expect("write machine log");
        std::fs::set_permissions(
            machine_paths.serial_log_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("secure machine log");

        let retry = machine_handle(&runtime, machine.id);
        machine_handle(&runtime, machine.id)
            .remove()
            .await
            .expect("remove machine");
        retry.remove().await.expect("repeat removal");

        assert!(!machine.machine_dir.exists());
        assert!(!machine_paths.machine_run_dir().exists());
        assert!(!machine_paths.machine_logs_dir().exists());
        assert!(!lock_path.exists());
        assert!(runtime
            .list_machine_configs()
            .await
            .expect("list machines")
            .is_empty());
    }

    #[tokio::test]
    async fn failed_removal_retains_machine_identity_for_manual_retry() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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
        let machine_paths = runtime.machine_paths(machine.id);
        create_machine_runtime_dirs(&runtime, machine.id);
        std::fs::write(
            machine_paths.serial_log_path(),
            b"retain until removal succeeds",
        )
        .expect("write machine log");
        std::fs::set_permissions(
            machine_paths.serial_log_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("secure machine log");

        let logs_root = machine_paths
            .machine_logs_dir()
            .parent()
            .and_then(std::path::Path::parent)
            .expect("machine logs have a logs root");
        std::fs::set_permissions(logs_root, std::fs::Permissions::from_mode(0o755))
            .expect("make logs root unsafe");

        let retry = machine_handle(&runtime, machine.id);
        let error = machine_handle(&runtime, machine.id)
            .remove()
            .await
            .expect_err("unsafe logs root must stop removal");
        assert!(matches!(
            error,
            LibVmError::InvalidOwnedPath { ref path, .. } if path.as_path() == logs_root
        ));
        assert!(!machine_paths.machine_run_dir().exists());
        assert!(machine.machine_dir.exists());
        assert!(machine_paths.machine_logs_dir().exists());
        assert!(runtime
            .machine_config(machine.id)
            .await
            .expect("read retained machine")
            .is_some());

        std::fs::set_permissions(logs_root, std::fs::Permissions::from_mode(0o700))
            .expect("restore logs root");
        retry.remove().await.expect("retry removal");

        assert!(!machine.machine_dir.exists());
        assert!(!machine_paths.machine_logs_dir().exists());
        assert!(runtime
            .machine_config(machine.id)
            .await
            .expect("read removed machine")
            .is_none());
    }

    #[tokio::test]
    async fn remove_refuses_running_machine_when_pid_file_exists() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = Runtime::open(
            LocalPaths::new(temp.path().join("silo")),
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

        create_machine_runtime_dirs(&runtime, machine.id);
        let pid_path = runtime.paths.machine(machine.id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{}\n", std::process::id())).expect("write pid file");
        let started_at = ProcessIdentity::for_pid(std::process::id() as i32)
            .expect("read current process")
            .and_then(|identity| identity.started_at())
            .expect("current process generation");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(std::process::id() as i32),
                Some(started_at),
                Some("test-run".to_string()),
                None,
            )
            .await
            .expect("set running state");

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
            LocalPaths::new(temp.path().join("silo")),
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

    async fn add_ephemeral_machine(runtime: &Runtime, name: &str) -> MachineConfig {
        let id = MachineId::new();
        let lock = runtime
            .allocate_machine_lock()
            .expect("allocate machine lock");
        let mut config = sample_machine_config(runtime.local_paths(), id, name);
        config.lock_id = lock.id();
        config.retention = MachineRetention::Ephemeral;
        drop(lock);
        runtime
            .local_paths()
            .create_machine_data_dir(id)
            .expect("create owned machine data root");
        std::fs::write(config.machine_dir.join("data.txt"), b"machine data")
            .expect("write machine data");
        runtime
            .add_machine_record(&config, &stopped_machine_state(id, None))
            .await
            .expect("persist ephemeral machine");
        config
    }
}
