use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eyre::Context;
use oci::{MaterializeOptions, OciError, OciMaterializer};

use crate::guest_agent::{self, GuestAgentConfigInput};
use crate::lock_manager::{LockGuard, LockId, LockManager, MachineLifetimeLock, ManagedLock};
use crate::machine::root_disk::resize_raw_disk;
use crate::paths::{vm_spec_path_in, LocalPaths, MachinePaths};
use crate::runtime::boot_assets::{self, BootAssetOverrides, ResolvedBootAssets};
use crate::runtime::components::{resolve_components, ResolvedRuntimeComponents};
use crate::runtime::{RuntimeConfig, RuntimeNetworkingConfig};
use crate::RegistryPolicy;
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
        cached_resolved_oci_image, ensure_resolved_oci_identity, image_error, materialized_image,
        oci_image_record, resolve_oci_image_from_registry, storage_error, verify_cached_image,
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
    NetworkDefinition, VmmNetworkAttachment,
};
use crate::runtime::transitions::{self, StartFailure, TransitionError};
use crate::runtime::RuntimeBuilder;
use crate::store::models::DbConfig;
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, MachineNetworkConfig as ModelMachineNetworkConfig, MachineRootfsRecord,
    MachineRuntimeState, MachineState, OciImageRecord,
};
use crate::store::{ConfigStore, DataStore, Store};
use crate::supervisor::exit_status;
use crate::supervisor::process::{self, ProcessIdentity};
use crate::supervisor::{self, LaunchSpecInput, VmSupervisor};
use crate::utils::now_unix;
use crate::LibVmError;
use protocol::shutdown::{CurrentExitRecord, ExitOutcome};

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
            pid: state.vmm_pid,
            started_at: state.started_at,
            run_id: state.run_id.clone(),
            last_error: state.last_error.clone(),
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        self.state.is_running()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.state.is_live() || self.pid.is_some()
    }
}

struct ObservedMachineRuntime {
    state: MachineState,
    storage_stop_outcome: Option<crate::StorageStopOutcome>,
}

#[derive(Debug, Clone, Copy)]
enum MachineScopeRecovery {
    CatalogFile,
    External,
}

#[derive(Debug, Clone)]
pub struct Runtime {
    paths: LocalPaths,
    store: Arc<dyn DataStore>,
    lock_manager: LockManager,
    networking: RuntimeNetworkingConfig,
    registry_policy: RegistryPolicy,
    components: ResolvedRuntimeComponents,
    supervisor: VmSupervisor,
    live_query: crate::runtime::capabilities::LiveCapabilityQuery,
    observation_store: Option<Arc<crate::store::observation::ObservationStore>>,
    image_pull_policy: ImagePullPolicy,
    image_progress: Option<ImageProgressSender>,
    secret_store: Arc<dyn silo_secrets::SecretStore>,
    secret_provider: Option<crate::HostCommand>,
    machine_scope_recovery: MachineScopeRecovery,
}

/// Identity for one concrete silo-vmm run.
///
/// PID alone is not enough because host PIDs can be reused. When the platform
/// can expose process birth time we include it, and we also carry the runtime
/// run ID written into persisted state and silo-vmm exit files. Lifecycle paths use
/// this to avoid applying stale transitions to a newer machine run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmmRunIdentity {
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
        let selection = crate::runtime::capabilities::ResolvedBackendSelection::resolve(
            config.virt_backend.as_ref(),
        )?;
        let live_query = crate::runtime::capabilities::LiveCapabilityQuery::resolved(
            components.supervisor().to_path_buf(),
            selection,
        )?;
        live_query.host_report().await?;
        let roots = config.resolve_roots()?;
        let store = Store::open(&roots.state_db_path()).await?;
        let stored = store.read_or_seed_db_config(&DbConfig::current()).await?;
        crate::runtime::config::validate_db_config(&stored)?;
        let observation_store = crate::store::observation::ObservationStore::existing(&store);
        let paths = LocalPaths::from_roots(roots);
        Self::from_store_resolved(
            paths,
            Arc::new(store),
            config.networking,
            config.registry_policy,
            components,
            live_query,
            Some(Arc::new(observation_store)),
        )
        .await
    }

    /// Opens the default local runtime from the process environment.
    pub async fn from_env() -> Result<Self, LibVmError> {
        Self::new(RuntimeConfig::from_env()?).await
    }

    pub(crate) fn execution_client(&self, machine_id: MachineId) -> crate::supervisor::VmmClient {
        self.supervisor.client(machine_id)
    }

    #[cfg(test)]
    pub(crate) async fn open(
        paths: LocalPaths,
        networking: RuntimeNetworkingConfig,
    ) -> Result<Self, LibVmError> {
        let store = Store::new(&paths).await?;
        let components = crate::runtime::components::test_components(paths.home());
        Self::from_store(
            paths,
            Arc::new(store),
            networking,
            RegistryPolicy::default(),
            components,
            None,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn from_store(
        paths: LocalPaths,
        store: Arc<dyn DataStore>,
        networking: RuntimeNetworkingConfig,
        registry_policy: RegistryPolicy,
        components: ResolvedRuntimeComponents,
        virt_backend: Option<crate::runtime::VirtBackendOverride>,
    ) -> Result<Self, LibVmError> {
        let selection =
            crate::runtime::capabilities::ResolvedBackendSelection::resolve(virt_backend.as_ref())?;
        let query = crate::runtime::capabilities::LiveCapabilityQuery::resolved(
            components.supervisor().to_path_buf(),
            selection,
        )?;
        Self::from_store_resolved(
            paths,
            store,
            networking,
            registry_policy,
            components,
            query,
            None,
        )
        .await
    }

    async fn from_store_resolved(
        paths: LocalPaths,
        store: Arc<dyn DataStore>,
        networking: RuntimeNetworkingConfig,
        registry_policy: RegistryPolicy,
        components: ResolvedRuntimeComponents,
        live_query: crate::runtime::capabilities::LiveCapabilityQuery,
        observation_store: Option<Arc<crate::store::observation::ObservationStore>>,
    ) -> Result<Self, LibVmError> {
        let lock_manager = LockManager::open(paths.locks_dir().to_path_buf())?;
        let supervisor = VmSupervisor::new(
            paths.clone(),
            components.supervisor().to_path_buf(),
            live_query.selection().clone(),
        );
        let runtime = Self {
            secret_store: Arc::new(silo_secrets::FileStore::new(paths.home())),
            secret_provider: None,
            machine_scope_recovery: MachineScopeRecovery::CatalogFile,
            paths,
            store,
            lock_manager,
            networking,
            registry_policy,
            components,
            supervisor,
            live_query,
            observation_store,
            image_pull_policy: ImagePullPolicy::default(),
            image_progress: None,
        };
        // Opening an installation must not depend on any individual VM's
        // runtime artifacts. Observation belongs to inspect; repair belongs to
        // the selected machine's lifecycle operations.
        Ok(runtime)
    }

    /// Returns the Silo home holding this runtime's persistent state.
    pub fn local_home(&self) -> &Path {
        self.paths.home()
    }

    pub(crate) fn native_store(&self) -> Result<Store, LibVmError> {
        self.store.native_store().ok_or_else(|| {
            crate::machine::root_storage::invalid("stopped storage requires a native catalog")
        })
    }

    pub(crate) fn captured_boot_context<'a>(
        &'a self,
        pool: &'a crate::storage::pool::StoragePool,
        store: &'a Store,
        operation_id: uuid::Uuid,
    ) -> boot_assets::CapturedBootContext<'a> {
        boot_assets::CapturedBootContext {
            pool,
            store,
            operation_id,
            default_kernel: self.components.kernel(),
            default_initramfs: self.components.initramfs(),
            default_agent: self.components.agent(),
            native_executable: self.components.supervisor(),
            backend: self.live_query.selection().backend,
        }
    }

    pub(crate) fn preflight_captured_lane(
        &self,
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        boot_assets::validate_captured_boot_lane(storage, self.live_query.selection().backend)
    }

    /// Host-scoped capabilities for this runtime's frozen next-start selection.
    pub async fn live_capabilities(&self) -> Result<vm_spec::live::LiveHostReport, LibVmError> {
        self.live_query.host_report().await
    }

    /// Observe through the initialized pool without reopening/recovering storage.
    pub async fn observe_live(
        &self,
        reference: &MachineRef,
    ) -> Result<crate::MachineLiveObservation, LibVmError> {
        let store = self
            .observation_store
            .as_ref()
            .ok_or_else(|| LibVmError::LiveObservation {
                reference: format!("{reference:?}"),
                message: "runtime has no native catalog observation adapter".to_string(),
            })?;
        let (config, state) = store.lookup(reference).await?;
        let pending = store
            .pending_pause(config.id, state.run_id.as_deref())
            .await?;
        Ok(
            crate::machine::live::observe_run(&self.paths, config, state)
                .await?
                .with_pending_pause(pending),
        )
    }

    /// Execution restore is not delivered. Refuse before opening the artifact
    /// or allocating any destination state, even for positive test scenarios.
    pub async fn restore_execution(
        &self,
        report: &vm_spec::live::LiveHostReport,
        _checkpoint: &Path,
        _name: Option<&str>,
    ) -> Result<(), LibVmError> {
        crate::runtime::capabilities::require_host_live_operation(
            report,
            vm_spec::live::LiveOperation::Restore,
        )
    }

    pub(crate) fn image_store(&self) -> oci::OciResult<OciMaterializer> {
        OciMaterializer::open(self.local_images_dir(), self.registry_policy.clone())
    }

    /// Read-only readiness using the start resolver. No values or signing material are returned.
    /// Without a machine reference only Home secrets participate.
    pub async fn policy_secrets_ready(
        &self,
        policy: &silo_policy::NetworkPolicy,
        machine: Option<&MachineRef>,
    ) -> Result<bool, LibVmError> {
        Ok(matches!(
            self.check_policy_secrets(policy, machine, &EgressCredentials::default())
                .await?,
            crate::policy_secrets::PolicySecretsCheck::Ready
        ))
    }

    /// Resolves prospective Home or existing Machine/Home secrets without mutation.
    /// Missing alternatives and unavailable/corrupt projections are distinct, redacted results.
    pub async fn check_policy_secrets(
        &self,
        policy: &silo_policy::NetworkPolicy,
        machine: Option<&MachineRef>,
        explicit: &EgressCredentials,
    ) -> Result<crate::policy_secrets::PolicySecretsCheck, LibVmError> {
        let id = match machine {
            Some(reference) => Some(self.get_machine(reference).await?.machine_id()),
            None => None,
        };
        let network = ModelMachineNetworkConfig::Private {
            policy: Some(policy.clone()),
            publish: None,
        };
        crate::policy_secrets::diagnostic(crate::secrets::resolve_for_scope(
            self.secret_store(),
            &network,
            id,
            "readiness",
            explicit,
            None,
            "readiness",
        ))
    }

    pub(crate) async fn lock_machine_names(&self) -> Result<std::fs::File, LibVmError> {
        use std::os::unix::fs::OpenOptionsExt;
        let _home = crate::paths::OwnedDirectory::open_root(self.local_home())?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(self.local_home().join("machine-names.lock"))?;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }
    }

    pub(crate) fn validate_tailscale_vsock(
        &self,
        network: &ModelMachineNetworkConfig,
        spec: &VmSpec,
    ) -> Result<bool, LibVmError> {
        let present = matches!(network, ModelMachineNetworkConfig::Private { policy: Some(policy), .. } if !policy.tailscale().is_empty());
        if present && !spec.vsock.as_ref().is_some_and(|vsock| vsock.enabled) {
            return Err(LibVmError::NetworkRuntime {
                reference: "tailscale".into(),
                message: "Tailscale requires vsock.enabled (CLI: --vsock)".into(),
            });
        }
        Ok(present)
    }

    pub(crate) fn ensure_tailscale_directory(&self, id: MachineId) -> Result<(), LibVmError> {
        let missing =
            || std::io::Error::other("Tailscale state requires an existing machine directory");
        let root = crate::paths::OwnedDirectory::open_existing_root(self.local_home())?
            .ok_or_else(missing)?;
        let machines = root.open_dir("machines")?.ok_or_else(missing)?;
        let machine = machines.open_dir(&id.to_string())?.ok_or_else(missing)?;
        machine.ensure_dir("tailscale")?;
        Ok(())
    }

    /// Uses this store to resolve policy secrets for future starts.
    pub fn with_secret_store(mut self, store: Arc<dyn silo_secrets::SecretStore>) -> Self {
        self.secret_store = store;
        self.machine_scope_recovery = MachineScopeRecovery::External;
        self
    }

    /// Configures the host command used to refresh resolved OAuth records.
    pub fn with_secret_provider(mut self, command: crate::HostCommand) -> Self {
        self.secret_provider = Some(command);
        self
    }

    pub(crate) fn secret_store(&self) -> &dyn silo_secrets::SecretStore {
        self.secret_store.as_ref()
    }

    pub(crate) fn secret_store_arc(&self) -> Arc<dyn silo_secrets::SecretStore> {
        Arc::clone(&self.secret_store)
    }

    pub(crate) fn require_recoverable_child_scopes(&self) -> Result<(), LibVmError> {
        match self.machine_scope_recovery {
            MachineScopeRecovery::CatalogFile => Ok(()),
            MachineScopeRecovery::External => Err(crate::machine::root_storage::invalid(
                "stopped child publication requires catalog-owned secret scopes; custom SecretStore has no durable recovery contract",
            )),
        }
    }

    pub(crate) fn resolve_secrets(
        &self,
        config: &MachineConfig,
        run_id: &str,
        explicit: &EgressCredentials,
    ) -> Result<crate::secrets::ResolvedSecrets, LibVmError> {
        crate::secrets::resolve_for_start(
            self.secret_store(),
            &config.network,
            config.id,
            run_id,
            explicit,
            self.secret_provider.as_ref(),
            &config.name,
        )
    }

    pub(crate) fn resolve_machine_secrets(
        &self,
        config: &MachineConfig,
        run_id: &str,
        explicit: &EgressCredentials,
    ) -> Result<crate::secrets::ResolvedSecrets, LibVmError> {
        let mut resolved = self.resolve_secrets(config, run_id, explicit)?;
        let pair =
            crate::ssh_ca::resolve(self.secret_store(), config.id, false).map_err(|error| {
                LibVmError::MachinePreparationFailed {
                    reference: config.name.clone(),
                    message: format!("resolve machine SSH CA: {error}"),
                }
            })?;
        resolved.ssh_trusted_ca = Some(pair.public);
        resolved
            .infrastructure
            .push((crate::ssh_ca::PRIVATE.into(), pair.private));
        if matches!(&config.network, crate::store::models::MachineNetworkConfig::Private { policy: Some(policy), .. } if policy.has_https_interception())
        {
            let pair = crate::host::certificates::resolve(
                self.secret_store(),
                &self.paths,
                &self.networking.netd,
            )
            .map_err(|error| LibVmError::MachinePreparationFailed {
                reference: config.name.clone(),
                message: format!("resolve home TLS CA: {error}"),
            })?;
            resolved.tls_certificate = Some(pair.certificate.clone());
            resolved.infrastructure.push((
                crate::host::certificates::CERTIFICATE.into(),
                silo_secrets::SecretBytes::new(pair.certificate.into_bytes()),
            ));
            resolved
                .infrastructure
                .push((crate::host::certificates::PRIVATE.into(), pair.private));
        }
        Ok(resolved)
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

    pub(crate) fn supervisor(&self) -> &VmSupervisor {
        &self.supervisor
    }

    pub(crate) fn resolve_boot_assets(
        &self,
        kernel: Option<&Path>,
        initramfs: Option<&Path>,
    ) -> Result<ResolvedBootAssets, LibVmError> {
        boot_assets::resolve_boot_assets(
            BootAssetOverrides { kernel, initramfs },
            self.components.kernel(),
            self.components.initramfs(),
        )
    }

    pub(crate) fn qualify_flat_overlay(
        &self,
        kernel: Option<&Path>,
        initramfs: Option<&Path>,
    ) -> Result<crate::QualifiedOverlayBoot, LibVmError> {
        let backend = self.live_query.selection().backend;
        if backend != vm_spec::live::LiveBackend::Krun {
            return Err(LibVmError::OverlayBackendUnsupported { backend });
        }
        let assets = self.resolve_boot_assets(kernel, initramfs)?;
        let architecture = match std::env::consts::ARCH {
            "x86_64" => crate::GuestArchitecture::Amd64,
            "aarch64" => crate::GuestArchitecture::Arm64,
            arch => {
                return Err(LibVmError::UnsupportedHostArchitecture {
                    arch: arch.to_string(),
                })
            }
        };
        crate::boot_qualification::admit_flat_overlay(
            &assets.kernel,
            &assets.initramfs,
            architecture,
            backend,
            self.components.supervisor(),
        )
        .map_err(Into::into)
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
        match self.resolve_machine_config(machine).await {
            Ok(config) => Ok(Machine::new(self.clone(), config.id)),
            Err(error) if error.is_machine_observation_error() => {
                let record = self.inventory_record(machine).await?;
                let id = record.id.parse().map_err(|_| LibVmError::CorruptState {
                    id: record.id,
                    field: "machine_config.id",
                })?;
                Ok(Machine::new(self.clone(), id))
            }
            Err(error) => Err(error),
        }
    }

    async fn inventory_record(
        &self,
        reference: &MachineRef,
    ) -> Result<crate::store::machine_store::InventoryRecord, LibVmError> {
        let mut records = self
            .store
            .machine_inventory()
            .await?
            .into_iter()
            .filter(|record| match reference.kind() {
                MachineRefKind::Id(id) => record.id == id.to_string(),
                MachineRefKind::IdPrefix(prefix) => record.id.starts_with(prefix),
                MachineRefKind::Name(name) => &record.name == name,
            });
        let record = records.next().ok_or_else(|| LibVmError::MachineNotFound {
            reference: format!("{reference:?}"),
        })?;
        if records.next().is_some() {
            return Err(LibVmError::AmbiguousIdPrefix {
                prefix: format!("{reference:?}"),
                count: 2 + records.count(),
            });
        }
        Ok(record)
    }

    /// Inspect one indexed machine even when its configuration cannot decode.
    pub async fn inspect_inventory(
        &self,
        reference: &MachineRef,
    ) -> Result<crate::MachineInventoryEntry, LibVmError> {
        let record = self.inventory_record(reference).await?;
        self.observe_inventory_record(record).await
    }

    async fn observe_inventory_record(
        &self,
        record: crate::store::machine_store::InventoryRecord,
    ) -> Result<crate::MachineInventoryEntry, LibVmError> {
        let result = match record.config {
            Ok(config) => self.machine_inspect_data(config).await,
            Err(error) => Err(error),
        };
        let (data, issues) = match result {
            Ok(data) => (Some(data), Vec::new()),
            Err(error) if error.is_machine_observation_error() => (
                None,
                vec![crate::MachineIssue::new(
                    crate::MachineIssueComponent::Configuration,
                    error,
                )],
            ),
            Err(error) => return Err(error),
        };
        Ok(crate::MachineInventoryEntry {
            id: record.id,
            name: record.name,
            data,
            issues,
        })
    }

    /// Read-only, best-effort inventory. Global database errors remain fatal;
    /// individual invalid configurations retain their indexed identity.
    pub async fn inventory(&self) -> Result<Vec<crate::MachineInventoryEntry>, LibVmError> {
        let mut entries = Vec::new();
        for record in self.store.machine_inventory().await? {
            entries.push(self.observe_inventory_record(record).await?);
        }
        Ok(entries)
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
        self.store.list_machine_configs().await
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
        let resolved = self
            .resolve_oci_image(reference.to_string(), self.image_pull_policy)
            .await?;
        self.materialize_resolved_oci_image(&resolved).await
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
            stream: None,
            requested_reference: path.display().to_string(),
            selected_reference: None,
            source_kind: ImageSourceKind::Disk,
            image_id: Some(source.image_id),
            manifest_digest: None,
            config_digest: None,
            size_bytes,
            platform: oci::Platform::host()
                .map_err(|error| image_error(&path.display().to_string(), error))?,
            _lease: None,
        };
        emit_image_progress_complete(self.image_progress.as_ref());
        Ok(image)
    }

    pub(crate) async fn resolve_oci_image(
        &self,
        reference: String,
        policy: ImagePullPolicy,
    ) -> Result<ResolvedOciImage, LibVmError> {
        let options = MaterializeOptions::for_host().map_err(|err| image_error(&reference, err))?;
        if policy != ImagePullPolicy::Always {
            if let Some(image) = self
                .cached_oci_record(&reference, &options.platform)
                .await?
            {
                return Ok(cached_resolved_oci_image(
                    &image,
                    image.reference.requested_reference.clone(),
                ));
            }
            if policy == ImagePullPolicy::Never {
                return Err(LibVmError::ImageNotFound { reference });
            }
        }
        let producer = self
            .image_store()
            .map_err(|err| image_error(&reference, err))?;
        let mut resolved = resolve_oci_image_from_registry(
            &producer,
            reference,
            options,
            self.image_progress.clone(),
        )
        .await?;
        if self
            .cached_oci_record(&resolved.selected_reference, &resolved.platform)
            .await?
            .is_some()
        {
            resolved.cache_state = crate::ImageCacheState::Complete;
        }
        Ok(resolved)
    }

    pub(crate) async fn materialize_resolved_oci_image(
        &self,
        resolved: &ResolvedOciImage,
    ) -> Result<MaterializedImage, LibVmError> {
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
        let pool = crate::storage::pool::StoragePool::open(self.local_images_dir())
            .map_err(storage_error)?;
        let key_bytes = serde_json::to_vec(&(
            crate::image::oci::CONVERSION_ABI,
            &resolved.manifest_digest,
            &resolved.config_digest,
            &resolved.platform,
        ))
        .map_err(|error| LibVmError::StateDecode {
            field: "image.conversion-key",
            message: error.to_string(),
        })?;
        let key = crate::storage::identity::ObjectDigest::of_bytes(&key_bytes);
        let (pool, _conversion) = tokio::task::spawn_blocking(move || {
            let lock = pool.lock_publication(&key)?;
            Ok::<_, crate::storage::StorageError>((pool, lock))
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
        .map_err(storage_error)?;
        let operation_id = uuid::Uuid::new_v4();
        let lease = self.store.begin_storage_operation(operation_id).await?;
        if let Some(image) = self
            .store
            .cached_oci_image(&resolved.selected_reference, &resolved.platform)
            .await?
        {
            self.store
                .retain_storage_stream(&image.artifact.stream_id, operation_id)
                .await?;
            let images_dir = self.local_images_dir().to_path_buf();
            let (mut image, lease) = tokio::task::spawn_blocking(move || {
                let fingerprint = verify_cached_image(&image, &images_dir)?;
                if fingerprint
                    != crate::storage::identity_file::SourceFingerprint::new(&fs::symlink_metadata(
                        &image.artifact.rootfs_path,
                    )?)
                {
                    return Err(LibVmError::StateDecode {
                        field: "image.cache",
                        message: "retained stream changed before use".into(),
                    });
                }
                Ok((image, lease))
            })
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
            ensure_resolved_oci_identity(resolved, &image)?;
            emit_cached_image_progress(self.image_progress.as_ref(), &resolved.requested_reference);
            image.reference.requested_reference = resolved.requested_reference.clone();
            image.reference.last_used_at = Some(now_unix());
            self.store.save_oci_image(&image).await?;
            emit_image_progress_complete(self.image_progress.as_ref());
            return Ok(materialized_image(
                image,
                &resolved.requested_reference,
                lease,
            ));
        }
        if let Some(progress) = &self.image_progress {
            progress.send(ImageProgress::CheckingCache {
                image_ref: resolved.requested_reference.clone(),
            });
            progress.send(ImageProgress::CacheMiss {
                image_ref: resolved.requested_reference.clone(),
            });
        }
        let ResolvedOciImageMaterialization::Registry(image) = &resolved.materialization else {
            return Err(LibVmError::ImageNotFound {
                reference: resolved.selected_reference.clone(),
            });
        };
        let producer = self
            .image_store()
            .map_err(|err| image_error(&resolved.requested_reference, err))?;
        let staging_operation = oci::StagingOperation::try_from(operation_id.to_string())
            .map_err(|error| image_error(&resolved.requested_reference, error))?;
        let staged = producer
            .materialize(
                image,
                &options,
                &staging_operation,
                oci_progress_reporter(self.image_progress.clone()),
            )
            .await
            .map_err(|err| image_error(&resolved.requested_reference, err))?;
        if let Some(progress) = &self.image_progress {
            progress.send(ImageProgress::PublishingRootfs);
        }
        let published = tokio::task::spawn_blocking(move || {
            let (published, guard) = pool.publish_stream_for_catalog(&staged.path)?;
            Ok::<_, crate::storage::StorageError>((published, guard, lease, staged))
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
        .map_err(storage_error)?;
        let record = oci_image_record(
            &published.0,
            &published.3.metadata,
            &resolved.requested_reference,
        )?;
        ensure_resolved_oci_identity(resolved, &record)?;
        self.store
            .retain_storage_stream(&record.artifact.stream_id, operation_id)
            .await?;
        self.store.save_oci_image(&record).await?;
        emit_image_progress_complete(self.image_progress.as_ref());
        Ok(materialized_image(
            record,
            &resolved.requested_reference,
            published.2,
        ))
    }

    async fn cached_oci_record(
        &self,
        reference: &str,
        platform: &oci::Platform,
    ) -> Result<Option<OciImageRecord>, LibVmError> {
        for candidate in self
            .registry_policy
            .candidates(reference)
            .map_err(|error| image_error(reference, error))?
        {
            if let Some(image) = self
                .store
                .cached_oci_image(&candidate.to_string(), platform)
                .await?
            {
                let images = self.local_images_dir().to_path_buf();
                return tokio::task::spawn_blocking(move || {
                    verify_cached_image(&image, &images)?;
                    Ok(Some(image))
                })
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            }
        }
        Ok(None)
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
        let config = match machine.kind() {
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
                    1 => matches
                        .into_iter()
                        .next()
                        .ok_or_else(|| LibVmError::MachineNotFound {
                            reference: prefix.clone(),
                        }),
                    count => Err(LibVmError::AmbiguousIdPrefix {
                        prefix: prefix.clone(),
                        count,
                    }),
                }
            }
        }?;
        Ok(config)
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
        if machine_state_needs_writeback(persisted.as_ref(), &observed.state)
            || observed.state.vmm_pid.is_some()
            || !self
                .store
                .launch_storage_operations(metadata.id)
                .await?
                .is_empty()
        {
            let Some(_lock) = self.try_acquire_machine_lock(metadata.lock_id)? else {
                let state = self.machine_state(metadata.id).await?;
                return Ok(RuntimeStatus::from_machine_state(&state));
            };
            self.reconcile_machine_runtime_locked(metadata).await?;
            if observed.state.vmm_pid.is_some() {
                if let Err(error) = crate::machine::live_operations::reconcile(self, metadata).await
                {
                    tracing::warn!(machine = %metadata.id, %error, "live reconciliation retained uncertainty");
                }
            }
            return Ok(RuntimeStatus::from_machine_state(
                &self.machine_state(metadata.id).await?,
            ));
        }
        Ok(RuntimeStatus::from_machine_state(&observed.state))
    }

    pub(crate) async fn reconcile_machine_runtime_locked(
        &self,
        metadata: &MachineConfig,
    ) -> Result<RuntimeStatus, LibVmError> {
        let persisted = self.store.machine_state(metadata.id).await?;
        let observed = self
            .observe_machine_state(metadata, persisted.as_ref())
            .await?;
        if !self
            .persist_reconciled_state(metadata, persisted.as_ref(), &observed.state)
            .await?
        {
            return Ok(RuntimeStatus::from_machine_state(&storage_busy_state(
                metadata.id,
                persisted.as_ref(),
            )));
        }
        Ok(RuntimeStatus::from_machine_state(&observed.state))
    }

    /// Refused live/orphaned generations do not allocate locks or rewrite SQL.
    pub(crate) async fn preflight_stopped_generation_locked(
        &self,
        config: &MachineConfig,
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        let state = self.store.machine_state(config.id).await?.ok_or_else(|| {
            crate::machine::root_storage::invalid(
                "source has no durable lifecycle admission record",
            )
        })?;
        let operations = self.store.launch_storage_operations(config.id).await?;
        if operations.len() > 1
            || operations.first().is_some_and(|operation| {
                operation.storage_generation != storage.storage_generation
                    || state.run_id.as_deref().is_some_and(|run| {
                        uuid::Uuid::parse_str(run).ok() != Some(operation.run_id)
                    })
            })
        {
            return Err(crate::machine::root_storage::invalid(
                "source launch operation does not uniquely match its exact run and storage generation",
            ));
        }
        let busy = || LibVmError::MachineAlreadyRunning {
            reference: config.name.clone(),
        };
        if let Some(pid) = state.vmm_pid {
            if let Some(identity) = ProcessIdentity::for_pid(pid)? {
                if identity.is_alive()? {
                    return Err(busy());
                }
            }
        }
        if operations.is_empty() {
            if state.status.is_live() || state.run_id.is_some() || state.vmm_pid.is_some() {
                return Err(crate::machine::root_storage::invalid(
                    "admitted lifecycle generation has no retained launch operation",
                ));
            }
            if let Some(holder) = crate::supervisor::storage_holder::read(
                &self.machine_paths(config.id).vmm_storage_holder_path(),
            )? {
                if holder.machine_id != uuid::Uuid::from(config.id).to_string() {
                    return Err(crate::machine::root_storage::invalid(
                        "source holder belongs to another machine",
                    ));
                }
                if !crate::supervisor::storage_holder::all_terminal(&holder)? {
                    return Err(busy());
                }
                let operation = uuid::Uuid::parse_str(&holder.operation_id)
                    .map_err(|error| crate::machine::root_storage::invalid(error.to_string()))?;
                let pool =
                    crate::storage::pool::StoragePool::open_existing(self.local_images_dir())?
                        .ok_or_else(|| {
                            crate::machine::root_storage::invalid(
                                "reconciled holder lease pool is missing",
                            )
                        })?;
                let Some(_old_operation) = pool.try_exclusive_lease(operation)? else {
                    return Err(busy());
                };
            }
            return Ok(());
        }
        let pool = crate::storage::pool::StoragePool::open_existing(self.local_images_dir())?
            .ok_or_else(|| crate::machine::root_storage::invalid("launch lease pool is missing"))?;
        for operation in operations {
            if !self.launch_holders_terminal(config, &operation, Some(&state))? {
                return Err(busy());
            }
            // Probe the old stable inode independently. Never take a shared
            // old-operation lease before trying to prove it exclusive.
            let Some(_old_operation) = pool.try_exclusive_lease(operation.operation_id)? else {
                return Err(busy());
            };
        }
        Ok(())
    }

    async fn persist_reconciled_state(
        &self,
        config: &MachineConfig,
        expected: Option<&MachineState>,
        next: &MachineState,
    ) -> Result<bool, LibVmError> {
        let operations = self.store.launch_storage_operations(config.id).await?;
        if operations.len() > 1
            || operations.first().is_some_and(|operation| {
                expected
                    .and_then(|state| state.run_id.as_deref())
                    .is_some_and(|run| uuid::Uuid::parse_str(run).ok() != Some(operation.run_id))
            })
        {
            return Err(LibVmError::InvalidStorageRecord {
                record: "storage-operation",
                message: "launch operation does not uniquely match the expected runtime generation"
                    .into(),
            });
        }
        if next.status.is_live() || next.vmm_pid.is_some() || operations.is_empty() {
            if machine_state_needs_writeback(expected, next) {
                self.store.save_machine_state(next).await?;
            }
            return Ok(true);
        }
        for operation in operations {
            if !self.launch_holders_terminal(config, &operation, expected)? {
                return Ok(false);
            }
            let status =
                read_exit_for_reconciliation(&self.machine_paths(config.id).vmm_exit_status_path());
            let outcome = status
                .as_ref()
                .filter(|status| runtime_exit_matches(status, expected))
                .map_or(crate::StorageStopOutcome::Unknown, |status| {
                    exit_status::storage_outcome(
                        status,
                        &uuid::Uuid::from(config.id).to_string(),
                        &operation.run_id.to_string(),
                    )
                });
            if !self
                .store
                .try_retire_launch_storage(
                    operation.operation_id,
                    operation.run_id,
                    operation.storage_generation,
                    next,
                    outcome,
                )
                .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn launch_holders_terminal(
        &self,
        config: &MachineConfig,
        operation: &crate::store::operation_store::RetainedStorageOperation,
        expected: Option<&MachineState>,
    ) -> Result<bool, LibVmError> {
        let path = self.machine_paths(config.id).vmm_storage_holder_path();
        let Some(record) = crate::supervisor::storage_holder::read(&path)? else {
            // The monitor publishes its holder before attachment construction,
            // and worker config is withheld until the complete holder is durable.
            // Only an unstarted generation can use the absence as a proof.
            if !operation.admitted {
                return Ok(true);
            }
            let preattachment = expected.is_some_and(|state| {
                state.status == MachineRuntimeState::Starting
                    && state.vmm_pid.is_none()
                    && state
                        .run_id
                        .as_deref()
                        .and_then(|run| uuid::Uuid::parse_str(run).ok())
                        == Some(operation.run_id)
            });
            let exit = exit_status::read(&self.machine_paths(config.id).vmm_exit_status_path())?;
            let contradictory = exit.as_ref().is_some_and(|status| {
                uuid::Uuid::parse_str(&status.run_id).ok() == Some(operation.run_id)
                    && status
                        .backend
                        .as_ref()
                        .is_some_and(|backend| backend["stage"] == "started")
            });
            if preattachment && !contradictory {
                return Ok(true);
            }
            return Err(LibVmError::InvalidStorageRecord {
                record: "storage-holder",
                message: format!(
                    "missing admitted holder evidence for operation {}",
                    operation.operation_id
                ),
            });
        };
        record
            .validate_binding(
                &uuid::Uuid::from(config.id).to_string(),
                &operation.run_id.to_string(),
                &operation.operation_id.to_string(),
            )
            .map_err(|message| LibVmError::InvalidStorageRecord {
                record: "storage-holder",
                message,
            })?;
        Ok(crate::supervisor::storage_holder::all_terminal(&record)?)
    }
    async fn observe_machine_state(
        &self,
        metadata: &MachineConfig,
        runtime: Option<&MachineState>,
    ) -> Result<ObservedMachineRuntime, LibVmError> {
        let pid_path = self.paths.machine(metadata.id).vmm_pid_path();
        let exit_status_path = self.paths.machine(metadata.id).vmm_exit_status_path();
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
        let abandoned_start =
            if current_state == MachineRuntimeState::Starting && live_pid.is_none() {
                MachineLifetimeLock::available_existing(
                    &self.paths.machine(metadata.id).vmm_lock_path(),
                )?
            } else {
                false
            };
        let exit_status = read_exit_for_reconciliation(&exit_status_path);
        let matching_exit = exit_status
            .as_ref()
            .filter(|status| runtime_exit_matches(status, runtime))
            .filter(|_| live_pid.is_none());
        let stored_state = runtime
            .cloned()
            .unwrap_or_else(|| stopped_machine_state(metadata.id, None));
        let mut terminal_storage_observed = runtime.is_some_and(|state| {
            state.run_id.is_some() && (state.status.is_live() || state.vmm_pid.is_some())
        });
        if live_pid.is_none() {
            for operation in self.store.launch_storage_operations(metadata.id).await? {
                terminal_storage_observed = true;
                if !self.launch_holders_terminal(metadata, &operation, runtime)? {
                    return Ok(ObservedMachineRuntime {
                        state: storage_busy_state(metadata.id, runtime),
                        storage_stop_outcome: None,
                    });
                }
            }
        }
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
                None if abandoned_start => {
                    transitions::reduce(stored_state, transitions::Event::StartTimedOut, now_unix())
                        .map_err(transition_error)?
                }
                None if current_state == MachineRuntimeState::Starting => MachineState {
                    vmm_pid: None,
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
        let storage_stop_outcome = if live_pid.is_none() && terminal_storage_observed {
            Some(
                matching_exit.map_or(crate::StorageStopOutcome::Unknown, |status| {
                    exit_status::storage_outcome(
                        status,
                        &uuid::Uuid::from(metadata.id).to_string(),
                        status.run_id.as_str(),
                    )
                }),
            )
        } else {
            None
        };
        Ok(ObservedMachineRuntime {
            state: observed_state,
            storage_stop_outcome,
        })
    }

    #[cfg(test)]
    pub(crate) async fn set_machine_state(
        &self,
        machine_id: MachineId,
        status: MachineRuntimeState,
        vmm_pid: Option<i32>,
        started_at: Option<i64>,
        run_id: Option<String>,
        last_error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.store
            .save_machine_state(&MachineState {
                machine_id,
                status,
                vmm_pid,
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

    pub(crate) async fn validate_machine_storage_for_launch(
        &self,
        config: &MachineConfig,
    ) -> Result<crate::MachineStorageRecord, LibVmError> {
        let storage = self
            .store
            .machine_storage(config.id)
            .await?
            .ok_or_else(|| LibVmError::InvalidStorageRecord {
                record: "machine-storage",
                message: format!("machine {} has no durable storage record", config.id),
            })?;
        storage.validate()?;
        if !storage.external_requirements.is_empty() {
            return Err(crate::machine::root_storage::invalid(
                "required external resources are unresolved; supply explicit destination mappings",
            ));
        }
        validate_launch_storage(&storage)?;
        crate::machine::root_storage::validate_spec(&storage, &config.spec)?;
        crate::store::operation_store::preflight_launch_storage(
            &storage,
            &config.spec,
            self.local_images_dir(),
        )?;
        Ok(storage)
    }

    pub(crate) async fn register_launch_storage(
        &self,
        config: &MachineConfig,
        run_id: uuid::Uuid,
        storage: &crate::MachineStorageRecord,
    ) -> Result<crate::store::operation_store::LaunchStorageLease, LibVmError> {
        self.clear_reconciled_storage_holder(config).await?;
        self.store
            .register_launch_storage(config.id, run_id, storage, &config.spec)
            .await
    }

    pub(crate) async fn mark_launch_storage_admitted(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<(), LibVmError> {
        self.store.mark_launch_storage_admitted(operation_id).await
    }

    async fn clear_reconciled_storage_holder(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        if !self
            .store
            .launch_storage_operations(config.id)
            .await?
            .is_empty()
        {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        let path = self.machine_paths(config.id).vmm_storage_holder_path();
        let Some(record) = crate::supervisor::storage_holder::read(&path)? else {
            return Ok(());
        };
        if record.machine_id != uuid::Uuid::from(config.id).to_string() {
            return Err(LibVmError::InvalidStorageRecord {
                record: "storage-holder",
                message: "holder belongs to another machine".into(),
            });
        }
        if !crate::supervisor::storage_holder::all_terminal(&record)? {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        let operation_id = uuid::Uuid::parse_str(&record.operation_id)
            .map_err(|error| crate::machine::root_storage::invalid(error.to_string()))?;
        let images_dir = self.local_images_dir().to_path_buf();
        let store = self.store.clone();
        let machine_id = config.id;
        let reference = config.name.clone();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            // This owner retains catalog/roots/lease authority through unlink
            // and directory durability even if the async waiter is cancelled.
            let pool = crate::storage::pool::StoragePool::open_existing(&images_dir)?.ok_or_else(
                || crate::machine::root_storage::invalid("holder lease pool is missing"),
            )?;
            let _roots = pool.lock_roots()?;
            if !handle
                .block_on(store.launch_storage_operations(machine_id))?
                .is_empty()
            {
                return Err(LibVmError::MachineAlreadyRunning { reference });
            }
            if crate::supervisor::storage_holder::read(&path)?.as_ref() != Some(&record) {
                return Err(LibVmError::InvalidStorageRecord {
                    record: "storage-holder",
                    message: "reconciled holder changed before telemetry cleanup".into(),
                });
            }
            let Some(_lease) = pool.try_exclusive_lease(operation_id)? else {
                return Err(LibVmError::MachineAlreadyRunning { reference });
            };
            crate::supervisor::storage_holder::remove_reconciled(&path)?;
            Ok(())
        })
        .await
        .map_err(|error| io::Error::other(format!("join holder cleanup owner: {error}")))?
    }

    pub(crate) fn qualify_machine_root(
        &self,
        config: &MachineConfig,
        storage: &crate::MachineStorageRecord,
    ) -> Result<Option<crate::QualifiedOverlayBoot>, LibVmError> {
        let pool = crate::storage::pool::StoragePool::open_existing(self.local_images_dir())?;
        let pinned = match &storage.boot {
            crate::BootProfile::LinuxDirect {
                binding: crate::BootBinding::Pinned { .. },
                ..
            } => Some(
                boot_assets::resolve_pinned_boot(
                    storage,
                    pool.as_ref().ok_or_else(|| {
                        crate::machine::root_storage::invalid("pinned boot pool is missing")
                    })?,
                    self.live_query.selection().backend,
                    self.components.supervisor(),
                )?
                .ok_or_else(|| {
                    crate::machine::root_storage::invalid("pinned boot selection disappeared")
                })?,
            ),
            _ => None,
        };
        if matches!(&storage.root, crate::MachineRoot::LinuxOverlay { .. }) {
            if let Some(pinned) = pinned {
                return pinned
                    .assets
                    .into_overlay_qualification()
                    .map(Some)
                    .ok_or_else(|| {
                        crate::machine::root_storage::invalid(
                            "pinned overlay boot has no retained qualification",
                        )
                    });
            }
            let (kernel, initramfs) = boot_asset_overrides_from_spec(&config.spec);
            Ok(Some(self.qualify_flat_overlay(kernel, initramfs)?))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn prepare_machine_root(
        &self,
        config: &MachineConfig,
        storage: &crate::MachineStorageRecord,
        qualification: Option<crate::QualifiedOverlayBoot>,
    ) -> Result<crate::machine::root_storage::PreparedRoot, LibVmError> {
        let data_disks = config.spec.storage.as_ref().map_or(0, |storage| {
            storage
                .disks
                .iter()
                .filter(|disk| disk.role == vm_spec::DiskRole::Data)
                .count() as u64
        });
        crate::machine::root_storage::prepare(
            storage,
            &config.machine_dir,
            self.local_images_dir(),
            data_disks,
            qualification,
        )
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
        let expected = self.store.machine_state(machine_id).await?;
        let state = expected
            .clone()
            .unwrap_or_else(|| stopped_machine_state(machine_id, None));
        let next = transitions::reduce(
            state,
            transitions::Event::StartFailed {
                run_id: run_id.to_string(),
                failure,
                error,
            },
            now_unix(),
        )
        .map_err(transition_error)?;
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        if !self
            .persist_reconciled_state(&config, expected.as_ref(), &next)
            .await?
        {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name,
            });
        }
        Ok(())
    }

    pub(crate) async fn mark_machine_stopped(
        &self,
        machine_id: MachineId,
        last_error: Option<String>,
    ) -> Result<(), LibVmError> {
        let expected = self.store.machine_state(machine_id).await?;
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let next = stopped_machine_state(machine_id, last_error);
        if !self
            .persist_reconciled_state(&config, expected.as_ref(), &next)
            .await?
        {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name,
            });
        }
        Ok(())
    }

    pub(crate) async fn request_machine_stop(
        &self,
        machine_id: MachineId,
        generation: &VmmRunIdentity,
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
        generation: VmmRunIdentity,
        last_error: Option<String>,
    ) -> Result<bool, LibVmError> {
        let state = self.machine_state(config.id).await?;
        if !state.status.is_live() && state.vmm_pid.is_none() {
            return Ok(true);
        }
        if !vmm_run_identity_matches(&state, &generation) {
            return Ok(false);
        }

        if vmm_run_is_alive(&generation)? {
            return Ok(false);
        }

        let next = match transitions::reduce(
            state.clone(),
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
        if !self
            .persist_reconciled_state(config, Some(&state), &next)
            .await?
        {
            return Ok(false);
        }
        self.cleanup_machine_resources_locked(config).await?;
        Ok(true)
    }

    pub(crate) async fn cleanup_machine_resources_locked(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        self.ensure_no_live_vmm_generation(config).await?;
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

    pub(crate) async fn ensure_no_live_vmm_generation(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        if !self
            .store
            .launch_storage_operations(config.id)
            .await?
            .is_empty()
        {
            let status = self.reconcile_machine_runtime_locked(config).await?;
            if status.is_active()
                || !self
                    .store
                    .launch_storage_operations(config.id)
                    .await?
                    .is_empty()
            {
                return Err(LibVmError::MachineAlreadyRunning {
                    reference: config.name.clone(),
                });
            }
        }
        let state = self.machine_state(config.id).await?;
        let Some(pid) = state.vmm_pid else {
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
                    "silo-vmm pid {pid} is a different process generation than persisted machine state"
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
        egress_credentials: &crate::secrets::ResolvedSecrets,
    ) -> Result<VmmNetworkAttachment, LibVmError> {
        prepare_network_runtime(
            &self.paths,
            self.store.as_ref(),
            config,
            run_id,
            &self.networking,
            self.components.netd(),
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

    pub(crate) fn prepare_vmm_launch_inputs(
        &self,
        config: &MachineConfig,
        run_id: &str,
        network: &VmmNetworkAttachment,
        resize_rootfs: bool,
        secrets: &crate::secrets::ResolvedSecrets,
        root: &crate::machine::root_storage::PreparedRoot,
    ) -> Result<crate::supervisor::VmmLaunchInputs, LibVmError> {
        let prepare = || -> eyre::Result<crate::supervisor::VmmLaunchInputs> {
            let rosetta_intent = self
                .supervisor
                .rosetta_intent_request(config)
                .map_err(eyre::Report::msg)?;
            let relative_mount_base = std::env::current_dir()
                .context("resolve current directory for relative mount sources")?;
            let machine_paths = self.machine_paths(config.id);
            let mut launch_spec = config.spec.clone();
            crate::machine::stopped::project_child_disks(
                &mut launch_spec,
                &root.storage,
                self.local_images_dir(),
            )?;
            let data = launch_spec
                .storage
                .take()
                .map(|storage| {
                    storage
                        .disks
                        .into_iter()
                        .filter(|disk| disk.role == vm_spec::DiskRole::Data)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let mut data = data;
            for (offset, disk) in data.iter_mut().enumerate() {
                let order = root.disks.len() + offset;
                if root
                    .storage
                    .disks
                    .iter()
                    .any(|managed| managed.order as usize == order)
                {
                    disk.path = config.machine_dir.join(&disk.path);
                }
            }
            launch_spec.storage = Some(vm_spec::Storage {
                disks: root
                    .disks
                    .iter()
                    .cloned()
                    .map(|mut disk| {
                        disk.path = config.machine_dir.join(&disk.path);
                        disk
                    })
                    .chain(data)
                    .collect(),
            });
            let pool = crate::storage::pool::StoragePool::open_existing(self.local_images_dir())?;
            let pinned = match &root.storage.boot {
                crate::BootProfile::LinuxDirect {
                    binding: crate::BootBinding::Pinned { .. },
                    ..
                } => boot_assets::resolve_pinned_boot(
                    &root.storage,
                    pool.as_ref()
                        .ok_or_else(|| eyre::eyre!("pinned boot pool is missing"))?,
                    self.live_query.selection().backend,
                    self.components.supervisor(),
                )?,
                _ => None,
            };
            if let Some(pinned) = &pinned {
                let kernel = launch_spec
                    .boot
                    .as_mut()
                    .and_then(|boot| boot.kernel.as_mut())
                    .ok_or_else(|| eyre::eyre!("pinned direct boot has no kernel configuration"))?;
                kernel.path = Some(crate::machine::root_storage::publish_kernel(
                    &config.machine_dir,
                    pinned.assets.kernel(),
                )?);
                kernel.initramfs = None;
            }
            if let Some(descriptor) = &root.descriptor {
                crate::machine::root_storage::publish_descriptor(&config.machine_dir, descriptor)?;
            }
            if let Some(qualification) = root.qualification.as_ref().filter(|_| pinned.is_none()) {
                let kernel_path = crate::machine::root_storage::publish_kernel(
                    &config.machine_dir,
                    qualification.kernel_asset(),
                )?;
                let kernel = launch_spec
                    .boot
                    .as_mut()
                    .and_then(|boot| boot.kernel.as_mut())
                    .ok_or_else(|| eyre::eyre!("qualified overlay has no direct kernel boot"))?;
                kernel.path = Some(kernel_path);
            } else if pinned.is_none() {
                self.complete_launch_boot_assets(&mut launch_spec)?;
            }
            let mut launch_spec = supervisor::prepare_launch_spec(LaunchSpecInput {
                relative_mount_base: &relative_mount_base,
                spec: launch_spec,
            })?;
            let storage_shutdown = guest_agent::storage_shutdown_context(
                &uuid::Uuid::from(config.id).to_string(),
                run_id,
                &launch_spec,
            )?;

            let agent_enabled = config.guest.agent.enabled();
            let agent_path = if pinned.is_none() {
                boot_assets::resolve_agent(&config.guest.agent, self.components.agent())?
            } else {
                None
            };
            let agent = match &pinned {
                Some(pinned) => pinned
                    .agent
                    .as_ref()
                    .map(crate::initramfs_overlay::CompositeAgent::Retained),
                None => agent_path
                    .as_deref()
                    .map(crate::initramfs_overlay::CompositeAgent::Path),
            };
            let serialized = if agent.is_some() {
                let agent_config = guest_agent::build_config(GuestAgentConfigInput {
                    machine_name: &config.name,
                    spec: &launch_spec,
                    network,
                    resize_rootfs,
                    user: config.guest.user.as_ref(),
                    ssh_trusted_ca: secrets
                        .ssh_trusted_ca
                        .as_deref()
                        .ok_or_else(|| eyre::eyre!("missing resolved SSH CA"))?,
                    tls_certificate: secrets.tls_certificate.as_deref(),
                    storage_shutdown: &storage_shutdown,
                })?;
                agent_config.validate().context("validate agent config")?;
                Some(serde_json::to_vec(&agent_config).context("serialize agent config")?)
            } else {
                None
            };
            let base_path = boot_asset_overrides_from_spec(&launch_spec)
                .1
                .map(Path::to_path_buf);
            let base = if let Some(pinned) = &pinned {
                crate::initramfs_overlay::CompositeBase::Retained(pinned.assets.initramfs())
            } else {
                match root.qualification.as_ref() {
                    Some(qualification) => {
                        crate::initramfs_overlay::CompositeBase::Qualified(qualification)
                    }
                    None => crate::initramfs_overlay::CompositeBase::Path(
                        base_path
                            .as_deref()
                            .ok_or_else(|| eyre::eyre!("resolved launch spec has no initramfs"))?,
                    ),
                }
            };
            let composite_path = machine_paths.composite_initramfs_path();
            crate::initramfs_overlay::write_composite(
                base,
                agent.zip(serialized.as_deref()),
                Some(&root.bootstrap),
                &composite_path,
            )?;
            set_launch_initramfs(&mut launch_spec, composite_path);

            supervisor::write_launch_spec(&machine_paths.vm_spec_path(), &launch_spec)?;
            Ok(crate::supervisor::VmmLaunchInputs {
                agent_enabled,
                rosetta_intent,
                asset_directory: self.components.asset_dir().to_path_buf(),
                storage_shutdown,
            })
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

    pub(crate) async fn machine_storage_record(
        &self,
        id: MachineId,
    ) -> Result<crate::MachineStorageRecord, LibVmError> {
        self.store.machine_storage(id).await?.ok_or_else(|| {
            crate::machine::root_storage::invalid("machine has no semantic storage record")
        })
    }

    pub(crate) async fn save_machine_config_with_storage(
        &self,
        config: &MachineConfig,
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        self.store
            .save_machine_config_with_storage(config, storage)
            .await
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
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        self.store
            .add_machine_with_rootfs(config, initial_state, rootfs, storage)
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
        use crate::machine::{MachineIssue, MachineIssueComponent, MachineObservation};

        let mut issues = Vec::new();
        let persisted = match self.store.machine_state(config.id).await {
            Ok(state) => state,
            Err(error) if error.is_machine_observation_error() => {
                issues.push(MachineIssue::new(MachineIssueComponent::Lifecycle, error));
                None
            }
            Err(error) => return Err(error),
        };
        let observed = match self
            .observe_machine_state(&config, persisted.as_ref())
            .await
        {
            Ok(observed) if machine_state_needs_writeback(persisted.as_ref(), &observed.state) => {
                match self.try_acquire_machine_lock(config.lock_id) {
                    Ok(Some(_lock)) => Ok(observed),
                    Ok(None) => Err(LibVmError::MonitorConnection {
                        reference: config.name.clone(),
                        message: "machine is being modified; showing last-known state".into(),
                    }),
                    Err(error) => Err(error),
                }
            }
            result => result,
        };
        let (state, storage_stop_outcome, observation) = match observed {
            Ok(observed) if issues.is_empty() => (
                observed.state,
                observed.storage_stop_outcome,
                MachineObservation::Observed,
            ),
            result => {
                if let Err(error) = result {
                    if !error.is_machine_observation_error() {
                        return Err(error);
                    }
                    issues.push(MachineIssue::new(MachineIssueComponent::Lifecycle, error));
                }
                let observation = if persisted.is_some() {
                    MachineObservation::LastKnown
                } else {
                    MachineObservation::Unavailable
                };
                (
                    persisted.unwrap_or_else(|| stopped_machine_state(config.id, None)),
                    None,
                    observation,
                )
            }
        };
        let runtime_status = RuntimeStatus::from_machine_state(&state);
        if let Err(error) =
            crate::network::observe_network_runtime(self.store.as_ref(), config.id).await
        {
            if !error.is_machine_observation_error() {
                return Err(error);
            }
            issues.push(MachineIssue::new(MachineIssueComponent::Network, error));
        }
        let mut live = None;
        let mut lifecycle = None;
        let (status, boot_report, provision_report) = if runtime_status.is_active()
            && observation == MachineObservation::Observed
        {
            let response =
                self.supervisor
                    .client(config.id)
                    .status()
                    .await
                    .and_then(|response| {
                        validate_host_status_identity(
                            &response,
                            config.id,
                            runtime_status.run_id.as_deref(),
                        )
                        .map_err(crate::supervisor::VmmClientError::from)?;
                        let report = crate::machine::live::report_from_status(&response).map_err(
                            |error| crate::supervisor::VmmClientError::Protocol(error.to_string()),
                        )?;
                        Ok((response, report))
                    });
            match response {
                Ok((mut response, report)) => {
                    lifecycle = match crate::machine::live::projection_from_status(&response) {
                        Ok(projection) => Some(projection),
                        Err(error) => {
                            issues.push(MachineIssue::new(MachineIssueComponent::Telemetry, error));
                            if let Some(readiness) = response.readiness.as_mut() {
                                readiness.ready = Some(false);
                            }
                            None
                        }
                    };
                    if let (Some(current), Ok(store)) = (&mut lifecycle, self.native_store()) {
                        let target = current
                            .lifecycle
                            .current_pause
                            .as_ref()
                            .map(|pause| &pause.operation_id)
                            .or_else(|| {
                                current
                                    .lifecycle
                                    .activity
                                    .as_ref()
                                    .map(|activity| &activity.operation_id)
                            });
                        if let Some(target) = target {
                            current.operation = store
                                .live_operation(
                                    config.id,
                                    &current.report.run_id,
                                    &current.report.monitor_id,
                                    target,
                                )
                                .await?;
                        }
                    }
                    live = Some(report);
                    let listener =
                        response
                            .agent
                            .as_ref()
                            .and_then(|agent| match agent.mode.as_ref() {
                                Some(protocol::v1::host_agent::Mode::Enabled(enabled)) => enabled
                                    .status
                                    .as_ref()
                                    .and_then(|status| status.report.as_ref())
                                    .and_then(|report| report.ssh.as_ref()),
                                _ => None,
                            });
                    if let Some(listener) = listener {
                        if listener.config_verified && listener.kex_verified {
                            let pin = ssh_key::PublicKey::from_openssh(&listener.host_public_key)
                                .map_err(eyre::Report::from)
                                .and_then(|key| {
                                    utils::ssh::verify_host_key_pin(&config.machine_dir, &key)
                                        .map_err(eyre::Report::from)
                                });
                            if let Err(error) = pin {
                                issues.push(MachineIssue::new(
                                    MachineIssueComponent::Telemetry,
                                    format!("SSH host key verification: {error}"),
                                ));
                                if let Some(readiness) = response.readiness.as_mut() {
                                    readiness.ready = Some(false);
                                }
                            }
                        }
                    }
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
                Err(message) => {
                    issues.push(MachineIssue::new(
                        MachineIssueComponent::Telemetry,
                        &message,
                    ));
                    (
                        MachineStatus::from_machine_state(
                            state.status,
                            Some(format!("silo-vmm get_status failed: {message}")),
                        ),
                        None,
                        None,
                    )
                }
            }
        } else {
            (
                MachineStatus::from_machine_state(state.status, state.last_error.clone()),
                None,
                None,
            )
        };

        let rootfs = match self.store.machine_rootfs(config.id).await {
            Ok(rootfs) => rootfs,
            Err(error) if error.is_machine_observation_error() => {
                issues.push(MachineIssue::new(MachineIssueComponent::Rootfs, error));
                None
            }
            Err(error) => return Err(error),
        };
        let mut storage = match self.store.machine_storage(config.id).await {
            Ok(storage) => storage,
            Err(error) if error.is_machine_observation_error() => {
                issues.push(MachineIssue::new(MachineIssueComponent::Rootfs, error));
                None
            }
            Err(error) => return Err(error),
        };
        if let (Some(storage), Some(outcome)) = (&mut storage, storage_stop_outcome) {
            storage.stop_outcome = outcome;
        }
        let run_id = runtime_status
            .is_active()
            .then(|| {
                runtime_status
                    .run_id
                    .clone()
                    .map(crate::machine::MachineRunId::from_raw)
            })
            .flatten();
        let mut data = MachineData::from_models_with_status(
            config,
            rootfs,
            status,
            run_id,
            boot_report,
            provision_report,
            state,
        );
        data.storage = storage;
        data.live = live;
        data.lifecycle = lifecycle;
        if !runtime_status.is_active() && observation == MachineObservation::Observed {
            match self.live_capabilities().await {
                Ok(report) => data.prospective_live = Some(report),
                Err(error) => {
                    issues.push(MachineIssue::new(MachineIssueComponent::Telemetry, error))
                }
            }
        }
        data.observation = observation;
        data.issues = issues;
        Ok(data)
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

fn validate_launch_storage(storage: &crate::MachineStorageRecord) -> Result<(), LibVmError> {
    use crate::store::models::storage::{
        BackendRequirement, BootBinding, BootProfile, MachineRoot, RawLayout, RootSelector,
        StorageProfile, Translation,
    };
    let admitted = matches!(
        (&storage.root, &storage.boot, storage.profile, storage.backend),
        (MachineRoot::OpaqueRaw { path, layout: RawLayout::WholeDisk, .. },
         BootProfile::LinuxDirect { binding: BootBinding::RuntimeSelected | BootBinding::Pinned { .. }, root_selector: RootSelector::WholeDisk, translation: Translation::None, .. },
         StorageProfile::OpaqueRawV1, BackendRequirement::RawBlock)
        if path.as_path() == crate::paths::root_disk_relative_path().as_path()
    ) || matches!(
        (
            &storage.root,
            &storage.boot,
            storage.profile,
            storage.backend
        ),
        (
            MachineRoot::LinuxOverlay {
                lower: crate::OverlayLower::FlatExt4 { .. },
                ..
            },
            BootProfile::LinuxDirect {
                binding: BootBinding::RuntimeSelected | BootBinding::Pinned { .. },
                root_selector: RootSelector::ManagedOverlay,
                translation: Translation::None,
                ..
            },
            StorageProfile::LinuxOverlayV1,
            BackendRequirement::KrunOverlay
        )
    );
    if !admitted || storage.fence.is_some() || storage.relocation_operation.is_some() {
        return Err(LibVmError::InvalidStorageRecord {
            record: "machine-storage",
            message: "storage/boot combination has not passed the launch gate".into(),
        });
    }
    Ok(())
}

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
    crate::storage::limits::validate_disk_length(desired_size)
        .map_err(crate::storage::StorageError::from)?;
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
    crate::storage::limits::validate_disk_length(desired_size)
        .map_err(crate::storage::StorageError::from)?;

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
    let stored_pid = runtime.and_then(|state| state.vmm_pid);
    let expected_started_at = runtime.and_then(|state| state.started_at);
    let recovering_prearmed_start = runtime.is_some_and(|state| {
        state.status == MachineRuntimeState::Starting
            && (state.vmm_pid.is_none() || state.started_at.is_none())
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
            message: format!(
                "silo-vmm pid {pid} from {} is not running",
                pid_path.display()
            ),
        });
    };
    if !identity.is_alive()? {
        return Err(LibVmError::MonitorConnection {
            reference: machine_name.to_string(),
            message: format!(
                "silo-vmm pid {pid} from {} is not running",
                pid_path.display()
            ),
        });
    }
    Ok(identity)
}

fn runtime_exit_matches(status: &CurrentExitRecord, state: Option<&MachineState>) -> bool {
    let Some(state) = state else {
        return false;
    };

    uuid::Uuid::parse_str(&status.machine_id).ok() == Some(uuid::Uuid::from(state.machine_id))
        && state.run_id.as_deref() == Some(status.run_id.as_str())
        && state.vmm_pid.is_none_or(|pid| pid == status.pid)
}

pub(crate) fn read_exit_for_reconciliation(path: &Path) -> Option<CurrentExitRecord> {
    match exit_status::read(path) {
        Ok(status) => status,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "exit record cannot certify current storage");
            None
        }
    }
}

fn storage_busy_state(machine_id: MachineId, state: Option<&MachineState>) -> MachineState {
    let mut state = state
        .cloned()
        .unwrap_or_else(|| stopped_machine_state(machine_id, None));
    state.status = MachineRuntimeState::Stopping;
    state.last_error =
        Some("storage generation is retained by a live or unreconciled attachment owner".into());
    state
}

fn validate_host_status_identity(
    status: &protocol::v1::HostStatus,
    machine: MachineId,
    run: Option<&str>,
) -> Result<(), String> {
    let observed_machine = status
        .machine_id
        .as_deref()
        .ok_or("monitor status omitted machine_id")?
        .parse::<MachineId>()
        .map_err(|_| "monitor status has invalid machine_id")?;
    if observed_machine != machine {
        return Err("monitor status belongs to another machine".into());
    }
    let observed_run = status
        .run_id
        .as_deref()
        .ok_or("monitor status omitted run_id")?
        .parse::<crate::MachineRunId>()
        .map_err(|_| "monitor status has invalid run_id")?;
    let expected_run = run
        .ok_or("running machine has no expected run_id")?
        .parse::<crate::MachineRunId>()
        .map_err(|_| "running machine has invalid expected run_id")?;
    if observed_run != expected_run {
        return Err("monitor status belongs to another run".into());
    }
    Ok(())
}

fn exit_observed_event(status: &CurrentExitRecord) -> (bool, Option<String>) {
    let _ = status.exited_at;
    match status.outcome {
        ExitOutcome::Clean | ExitOutcome::Forced => (true, None),
        ExitOutcome::Error => (false, status.error.clone()),
    }
}

fn machine_state_needs_writeback(
    persisted: Option<&MachineState>,
    observed: &MachineState,
) -> bool {
    let Some(persisted) = persisted else {
        return true;
    };

    persisted.status != observed.status
        || persisted.vmm_pid != observed.vmm_pid
        || persisted.started_at != observed.started_at
        || persisted.run_id.as_deref() != observed.run_id.as_deref()
        || persisted.last_error.as_deref() != observed.last_error.as_deref()
}

fn vmm_run_identity_matches(state: &MachineState, generation: &VmmRunIdentity) -> bool {
    if let Some(run_id) = generation.run_id.as_deref() {
        if state.run_id.as_deref() != Some(run_id) {
            return false;
        }
    }

    if state.vmm_pid != Some(generation.pid) {
        return false;
    }

    match generation.started_at {
        Some(started_at) => state.started_at == Some(started_at),
        None => true,
    }
}

fn vmm_run_is_alive(generation: &VmmRunIdentity) -> Result<bool, LibVmError> {
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
        vmm_pid: None,
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
pub(crate) mod tests {
    #[test]
    fn generic_monitor_status_requires_expected_machine_and_launch_run() {
        let machine = crate::store::models::MachineId::new();
        let run = uuid::Uuid::new_v4().to_string();
        let mut status = protocol::v1::HostStatus {
            machine_id: Some(machine.to_string()),
            run_id: Some(run.clone()),
            monitor: Some(protocol::v1::MonitorSnapshot {
                instance_id: Some(uuid::Uuid::new_v4().to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        crate::runtime::core::validate_host_status_identity(&status, machine, Some(&run)).unwrap();
        assert!(crate::runtime::core::validate_host_status_identity(
            &status,
            crate::store::models::MachineId::new(),
            Some(&run)
        )
        .is_err());
        assert!(crate::runtime::core::validate_host_status_identity(
            &status,
            machine,
            Some(&uuid::Uuid::new_v4().to_string())
        )
        .is_err());
        status.run_id = None;
        assert!(
            crate::runtime::core::validate_host_status_identity(&status, machine, Some(&run))
                .unwrap_err()
                .contains("run_id")
        );
    }
    use crate::lock_manager::LockId;
    use crate::paths::LocalPaths;
    use crate::runtime::core::{
        oci_image_record, read_monitor_pid, stopped_machine_state, validate_image_pull_policy,
        write_machine_config, Runtime,
    };
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRootfsRecord, MachineRuntimeState,
        MachineState,
    };
    use crate::store::{MachineStore, MockDataStore, Store};
    use crate::supervisor::process::ProcessIdentity;
    use crate::utils::now_unix;
    use crate::OciImageConfigMetadata;
    use crate::Platform;
    use crate::{
        GuestPublish, ImageCacheState, ImageProgress, ImageProgressSender, ImagePullOptions,
        ImagePullPolicy, ImageResolveOptions, ImageSource, LibVmError, MachineExitOutcome,
        MachineKillOptions, MachineRef, MachineRetention, MachineRunId, MachineStatus,
        MachineUpdate, Memory, PublishBind, RuntimeNetworkingConfig,
    };
    use oci::RootfsMetadata;
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[tokio::test]
    async fn rosetta_eligibility_fails_before_launch_asset_completion() {
        let temp = tempfile::tempdir().expect("temp runtime");
        let paths = LocalPaths::new(temp.path());
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("open runtime");
        let mut config = sample_machine_config(&paths, MachineId::new(), "rosetta-test");
        spec_hardware_mut(&mut config.spec).rosetta = Some(true);
        config.guest.agent = crate::machine::MachineAgent::Custom {
            path: "/custom/agent".into(),
        };

        let error = runtime
            .prepare_vmm_launch_inputs(
                &config,
                &uuid::Uuid::new_v4().to_string(),
                &crate::network::VmmNetworkAttachment::None,
                false,
                &crate::secrets::ResolvedSecrets::default(),
                &crate::machine::root_storage::PreparedRoot {
                    disks: vec![],
                    bootstrap: vec![],
                    descriptor: None,
                    qualification: None,
                    storage: crate::MachineStorageRecord::opaque_raw(
                        crate::PrivatePath::new("root.raw").unwrap(),
                        512,
                        &oci::Platform::host().unwrap(),
                    )
                    .unwrap(),
                },
            )
            .expect_err("reject ineligible durable contract");
        assert!(error.to_string().contains("installed default guest agent"));
        assert!(!error.to_string().contains("kernel"));
        assert!(!runtime.machine_paths(config.id).vm_spec_path().exists());
    }

    pub(crate) async fn write_cached_oci_rootfs(
        runtime: &Runtime,
        paths: &LocalPaths,
        requested_reference: &str,
        manifest_digest: &str,
        config_digest: &str,
    ) -> RootfsMetadata {
        let source = paths.home().join("cache-fixture.raw");
        std::fs::write(&source, [0x5a_u8; 512]).unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let published = pool.publish_stream(&source).unwrap();
        std::fs::remove_file(source).unwrap();
        let repository = requested_reference.split('@').next().unwrap();
        let repository = repository
            .rsplit_once(':')
            .map_or(repository, |(repository, _)| repository);
        let metadata = RootfsMetadata {
            requested_reference: requested_reference.into(),
            selected_reference: format!("{repository}@{manifest_digest}"),
            manifest_digest: manifest_digest.into(),
            config_digest: config_digest.into(),
            config: OciImageConfigMetadata {
                cmd: Some(vec!["serve".into()]),
                ..OciImageConfigMetadata::default()
            },
            layers: Vec::new(),
            platform: Platform::host().unwrap(),
            created_at_unix: 7,
        };
        let record = oci_image_record(&published, &metadata, requested_reference).unwrap();
        runtime.store.save_oci_image(&record).await.unwrap();
        metadata
    }

    fn stopped_state(machine_id: MachineId) -> MachineState {
        MachineState {
            machine_id,
            status: MachineRuntimeState::Stopped,
            vmm_pid: None,
            started_at: None,
            run_id: None,
            last_error: None,
            updated_at: 1,
        }
    }

    fn expect_empty_refresh(store: &mut MockDataStore) {
        store.expect_list_machine_configs().never();
    }

    async fn runtime_with_mock_store(paths: LocalPaths, mut store: MockDataStore) -> Runtime {
        store.expect_machine_storage().returning(|_| Ok(None));
        let components = crate::runtime::components::test_components(paths.home());
        Runtime::from_store(
            paths,
            Arc::new(store),
            RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::default(),
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
        let netd = bin.join("netd");
        std::fs::write(&netd, "#!/bin/sh\nexit 0\n").expect("write helper");
        std::fs::set_permissions(&netd, std::fs::Permissions::from_mode(0o755))
            .expect("make helper executable");
        let supervisor = bin.join("silo-vmm");
        std::fs::write(
            &supervisor,
            "#!/bin/sh\ntrace=\nprevious=\nfor arg do\n  if [ \"$previous\" = \"--trace-log\" ]; then trace=\"$arg\"; fi\n  previous=\"$arg\"\ndone\nprintf '%s\\n' \"$0\" > \"$trace.program\"\nprintf '%s\\n' \"$@\" > \"$trace.args\"\n( sleep 1; eval \"printf 'started\\n' >&$_VM_SYNCPIPE\" ) &\nexit 0\n",
        )
        .expect("write silo-vmm helper");
        std::fs::set_permissions(&supervisor, std::fs::Permissions::from_mode(0o755))
            .expect("make silo-vmm executable");
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
            components.kernel(),
            components.initramfs(),
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
                components.agent(),
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

    #[tokio::test]
    async fn retained_stream_corruption_is_rejected_for_offline_pull_policies() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .unwrap();
        let reference = "example.invalid/demo:latest";
        write_cached_oci_rootfs(
            &runtime,
            &paths,
            reference,
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "b".repeat(64)),
        )
        .await;
        let platform = Platform::host().unwrap();
        let record = runtime
            .store
            .cached_oci_image(reference, &platform)
            .await
            .unwrap()
            .unwrap();
        std::fs::set_permissions(
            &record.artifact.rootfs_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(&record.artifact.rootfs_path, b"corrupted").unwrap();
        std::fs::set_permissions(
            &record.artifact.rootfs_path,
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        for policy in [ImagePullPolicy::IfMissing, ImagePullPolicy::Never] {
            let error = runtime
                .resolve_oci_image(reference.into(), policy)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                LibVmError::Storage(crate::storage::StorageError::ContentMismatch(_))
            ));
        }
    }

    #[tokio::test]
    async fn warm_cache_requires_readonly_single_link_owned_streams() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .unwrap();
        let reference = "example.invalid/demo:latest";
        write_cached_oci_rootfs(
            &runtime,
            &paths,
            reference,
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "b".repeat(64)),
        )
        .await;
        let record = runtime
            .store
            .cached_oci_image(reference, &Platform::host().unwrap())
            .await
            .unwrap()
            .unwrap();
        let path = &record.artifact.rootfs_path;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            runtime
                .resolve_oci_image(reference.into(), ImagePullPolicy::Never)
                .await,
            Err(LibVmError::Storage(
                crate::storage::StorageError::InvalidPath(_)
            ))
        ));
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let alias = paths.home().join("unexpected-hardlink");
        std::fs::hard_link(path, &alias).unwrap();
        assert!(matches!(
            runtime
                .resolve_oci_image(reference.into(), ImagePullPolicy::Never)
                .await,
            Err(LibVmError::Storage(
                crate::storage::StorageError::InvalidPath(_)
            ))
        ));
        std::fs::remove_file(alias).unwrap();
        assert_eq!(
            runtime
                .resolve_oci_image(reference.into(), ImagePullPolicy::Never)
                .await
                .unwrap()
                .cache_state,
            ImageCacheState::Complete
        );
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
        let metadata = write_cached_oci_rootfs(&runtime, &paths, REFERENCE, MANIFEST, CONFIG).await;
        let before = runtime.images().list().await.unwrap();

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

        assert_eq!(runtime.images().list().await.unwrap(), before);
        assert!(!paths.images_dir().join("index.json").exists());

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
        write_cached_oci_rootfs(&runtime, &paths, FIRST_REFERENCE, MANIFEST, CONFIG).await;
        write_cached_oci_rootfs(&runtime, &paths, SECOND_REFERENCE, MANIFEST, CONFIG).await;

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
            .is_some());
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
        let metadata = write_cached_oci_rootfs(&runtime, &paths, REFERENCE, MANIFEST, CONFIG).await;
        let artifact_dir = runtime
            .store
            .cached_oci_image(REFERENCE, &Platform::host().unwrap())
            .await
            .unwrap()
            .unwrap()
            .artifact
            .rootfs_path;

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
        let pinned = runtime
            .resolve_oci_image(metadata.selected_reference, ImagePullPolicy::Never)
            .await
            .unwrap();
        assert_eq!(pinned.manifest_digest, MANIFEST);

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
        let metadata = write_cached_oci_rootfs(&runtime, &paths, REFERENCE, MANIFEST, CONFIG).await;
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
                [0_u8; 512],
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

    fn write_start_failure_components(paths: &LocalPaths, supervisor: &str) {
        let root = paths.home();
        let bin = root.join("bin");
        let assets = root.join("assets");
        std::fs::create_dir_all(&bin).expect("create test runtime binaries");
        std::fs::create_dir_all(&assets).expect("create test runtime assets");
        let netd = bin.join("netd");
        let build = std::process::Command::new("go")
            .args(["build", "-o"])
            .arg(&netd)
            .arg("./cmd/netd")
            .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../net/netd"))
            .output()
            .expect("build real netd");
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let supervisor_path = bin.join("silo-vmm");
        std::fs::write(&supervisor_path, supervisor).expect("write test silo-vmm");
        std::fs::set_permissions(&supervisor_path, std::fs::Permissions::from_mode(0o755))
            .expect("make test silo-vmm executable");
        for asset in ["kernel-default", "initramfs"] {
            std::fs::write(assets.join(asset), b"asset").expect("write test boot asset");
        }
    }

    async fn start_failure_runtime(
        temp: &tempfile::TempDir,
        supervisor: &str,
    ) -> (Runtime, MachineConfig, Arc<Store>) {
        let paths = LocalPaths::new(temp.path().join("silo"));
        write_start_failure_components(&paths, supervisor);
        let store = Arc::new(Store::new(&paths).await.expect("open test store"));
        let components = crate::runtime::components::test_components(paths.home());
        let runtime = Runtime::from_store(
            paths,
            store.clone(),
            RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::default(),
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
        let storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        config.spec.storage = Some(vm_spec::Storage {
            disks: vec![crate::machine::root_storage::disk(
                "root.raw",
                vm_spec::DiskRole::Root,
                512,
                "silo-root".into(),
            )
            .unwrap()],
        });
        std::fs::set_permissions(
            config.machine_dir.join("root.raw"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        runtime
            .save_machine_config_with_storage(&config, &storage)
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

        fn sleep_ready() -> Self {
            let child = std::process::Command::new(
                std::env::current_exe().expect("current test binary path"),
            )
            .env("SILO_LIBVM_STORAGE_HOLDER_CHILD", "1")
            .args([
                "--exact",
                "runtime::core::tests::storage_holder_child_process",
                "--nocapture",
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn storage holder process");
            let mut guard = Self { child };
            let stdout = guard
                .child
                .stdout
                .take()
                .expect("child stdout should be piped");
            // Userspace readiness, unlike an exec-status notification, proves
            // inherited CLOEXEC descriptors have completed exec-time teardown.
            wait_for_child_ready(stdout);
            guard
        }

        fn sleep_ignoring_sigint() -> Self {
            let mut child = std::process::Command::new(
                std::env::current_exe().expect("current test binary path"),
            )
            .env("SILO_LIBVM_SIGINT_IGNORING_CHILD", "1")
            .process_group(0)
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

    #[test]
    fn storage_holder_child_process() {
        if std::env::var_os("SILO_LIBVM_STORAGE_HOLDER_CHILD").is_none() {
            return;
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

        let temp = tempfile::tempdir_in("/tmp").expect("create temp dir");
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

        for supervisor in [launch_failure, missing_pid, missing_process] {
            let temp = tempfile::tempdir_in("/tmp").expect("create temp dir");
            let (runtime, config, _store) = start_failure_runtime(&temp, supervisor).await;

            machine_handle(&runtime, config.id)
                .start()
                .await
                .expect_err("test silo-vmm must fail to start");

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
        let temp = tempfile::tempdir_in("/tmp").expect("create temp dir");
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

    async fn inspect_machine(
        runtime: &Runtime,
        machine_ref: MachineRef,
    ) -> Result<crate::MachineData, LibVmError> {
        runtime.get_machine(&machine_ref).await?.inspect().await
    }

    #[tokio::test]
    async fn inventory_retains_broken_machine_and_does_not_repair_it() {
        let temp = tempfile::tempdir().expect("temp");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("runtime");
        let broken = create_pending_sample(&runtime, "broken")
            .await
            .expect("prepare")
            .commit(&runtime)
            .await
            .expect("commit");
        create_pending_sample(&runtime, "healthy")
            .await
            .expect("prepare")
            .commit(&runtime)
            .await
            .expect("commit");
        runtime
            .paths
            .ensure_machine_run_dir(broken.id)
            .expect("run dir");
        let pid_path = runtime.paths.machine(broken.id).vmm_pid_path();
        std::fs::write(&pid_path, "not a pid").expect("bad pid");
        let reopened = Runtime::open(paths, RuntimeNetworkingConfig::default())
            .await
            .expect("opening is independent of VM state");
        let entries = reopened.inventory().await.expect("inventory");
        assert_eq!(entries.len(), 2);
        let data = entries[0].data.as_ref().expect("partial details");
        assert!(!data.issues.is_empty());
        assert_ne!(data.observation, crate::MachineObservation::Observed);
        let healthy = entries[1].data.as_ref().expect("healthy");
        assert_eq!(healthy.observation, crate::MachineObservation::Observed);
        // This storage-only fixture has no monitor executable. Prospective
        // capability discovery is unavailable, independently of lifecycle.
        assert!(healthy
            .issues
            .iter()
            .all(|issue| issue.component == crate::MachineIssueComponent::Telemetry));
        assert!(healthy.prospective_live.is_none());
        assert_eq!(
            std::fs::read_to_string(pid_path).expect("still present"),
            "not a pid"
        );
    }

    #[tokio::test]
    async fn inventory_retains_corrupt_configuration_identity() {
        let temp = tempfile::tempdir().expect("temp");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("runtime");
        create_pending_sample(&runtime, "broken")
            .await
            .expect("prepare")
            .commit(&runtime)
            .await
            .expect("commit");
        let store = Store::open(&paths.state_db_path()).await.expect("store");
        store
            .execute_test_sql("UPDATE machine_config SET config_json = x'00' WHERE name = 'broken'")
            .await
            .expect("corrupt record");
        let entries = runtime.inventory().await.expect("inventory");
        assert_eq!(entries[0].name, "broken");
        assert!(entries[0].data.is_none());
        assert_eq!(
            entries[0].issues[0].component,
            crate::MachineIssueComponent::Configuration
        );
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
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("open real runtime");
        let source = temp.path().join("base.raw");
        std::fs::write(&source, [0x64; 512]).expect("write source disk");
        let machine = runtime
            .machine()
            .name("devbox")
            .image_source(ImageSource::disk(&source))
            .create()
            .await
            .expect("create current-format machine");
        let config = runtime
            .machine_config(machine.machine_id())
            .await
            .expect("read config")
            .expect("published machine");
        let original_storage = runtime
            .machine_storage_record(config.id)
            .await
            .expect("read semantic storage");
        original_storage.validate().expect("valid current storage");
        let path = config.machine_dir.join("config.json");
        let original_file = std::fs::read(&path).expect("read original spec");
        let store = Store::open(&paths.state_db_path())
            .await
            .expect("open real catalog");
        store
            .execute_test_sql(
                "CREATE TRIGGER reject_spec_publication BEFORE UPDATE ON machine_config
             BEGIN SELECT RAISE(ABORT, 'reject specification publication'); END",
            )
            .await
            .expect("install real SQLite write failure");
        let mut replacement = config.spec.clone();
        spec_hardware_mut(&mut replacement).cpus = Some(8);
        replacement
            .validate()
            .expect("valid replacement specification");

        let error = machine
            .replace_config(replacement.clone())
            .await
            .expect_err("SQLite trigger must reject publication");
        assert!(
            matches!(&error,
                LibVmError::Database(sqlx::Error::Database(source))
                    if source.code().as_deref() == Some("1811")
            ),
            "expected SQLite SQLITE_CONSTRAINT_TRIGGER: {error:?}"
        );
        assert_eq!(
            std::fs::read(&path).expect("read rolled back spec"),
            original_file
        );
        assert_eq!(
            store.machine_config(config.id).await.expect("read catalog"),
            Some(config.clone())
        );
        assert_eq!(
            store
                .machine_storage(config.id)
                .await
                .expect("read storage"),
            Some(original_storage)
        );
        assert_eq!(
            std::fs::read(
                config
                    .machine_dir
                    .join(crate::paths::root_disk_relative_path())
            )
            .expect("read preserved private root"),
            [0x64; 512]
        );

        store
            .execute_test_sql("DROP TRIGGER reject_spec_publication")
            .await
            .expect("remove write failure");
        machine
            .replace_config(replacement.clone())
            .await
            .expect("same valid replacement succeeds after rollback");
        let published = store
            .machine_config(config.id)
            .await
            .expect("read published config")
            .expect("machine remains published");
        let published_file: VmSpec =
            serde_json::from_slice(&std::fs::read(path).expect("read published spec"))
                .expect("decode published spec");
        assert_eq!(spec_hardware(&published.spec).cpus, Some(8));
        assert_eq!(
            serde_json::to_value(&published_file).expect("serialize file spec"),
            serde_json::to_value(&published.spec).expect("serialize catalog spec")
        );
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
            .expect("stopped machine status should not require silo-vmm socket");

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
                    root_disk_path: config.machine_dir.join("root.raw"),
                    root_disk_size_bytes: 64 * 1024 * 1024,
                    created_at: 7,
                },
                &crate::MachineStorageRecord::opaque_raw(
                    crate::store::models::storage::PrivatePath::new("root.raw").unwrap(),
                    64 * 1024 * 1024,
                    &Platform::host().unwrap(),
                )
                .unwrap(),
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
    async fn stop_timeout_escalates_only_when_requested() {
        for force in [false, true] {
            let temp = tempfile::tempdir().expect("tempdir");
            let runtime = Runtime::open(
                LocalPaths::new(temp.path().join("silo")),
                RuntimeNetworkingConfig::default(),
            )
            .await
            .expect("runtime");
            let machine = create_pending_sample(&runtime, "stop-timeout")
                .await
                .expect("pending")
                .commit(&runtime)
                .await
                .expect("commit");
            let mut child = ChildGuard::sleep_ignoring_sigint();
            let pid = child.id() as i32;
            create_machine_runtime_dirs(&runtime, machine.id);
            std::fs::write(
                runtime.machine_paths(machine.id).vmm_pid_path(),
                format!("{pid}\n"),
            )
            .expect("pidfile");
            let run_id = uuid::Uuid::new_v4().to_string();
            runtime
                .set_machine_state(
                    machine.id,
                    MachineRuntimeState::Running,
                    Some(pid),
                    child.started_at(),
                    Some(run_id.clone()),
                    None,
                )
                .await
                .expect("running");
            let mut options = crate::MachineStopOptions::new().timeout(Duration::from_millis(100));
            if force {
                options = options.force_after_timeout(Duration::from_secs(2));
            }
            // A real parent must reap the child, as init does for detached silo-vmm.
            let reaper = tokio::spawn(async move {
                loop {
                    if let Some(status) = child.child.try_wait().expect("wait child") {
                        return status;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
            let result = tokio::time::timeout(
                Duration::from_secs(4),
                machine_handle(&runtime, machine.id)
                    .stop_run_with(MachineRunId::from_raw(run_id), options),
            )
            .await
            .expect("bounded stop");
            if force {
                assert_eq!(result.expect("forced stop").status, MachineStatus::Stopped);
                assert!(!reaper.await.expect("reap").success());
                assert!(!runtime.machine_paths(machine.id).vmm_pid_path().exists());
            } else {
                assert!(
                    matches!(result, Err(LibVmError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut)
                );
                assert!(ProcessIdentity::for_pid(pid).expect("identity").is_some());
                reaper.abort();
                let _ = reaper.await;
            }
        }
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
        let pid_path = runtime.paths.machine(machine_id).vmm_pid_path();
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
        for force in [false, true] {
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
            std::fs::write(machine_paths.vmm_pid_path(), format!("{old_pid}\n"))
                .expect("write old pid file");
            std::fs::write(machine_paths.vmm_socket_path(), b"replacement sentinel")
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
            let stop_task = tokio::spawn(async move {
                let options = if force {
                    crate::MachineStopOptions::new()
                        .timeout(Duration::from_millis(500))
                        .force_after_timeout(Duration::from_secs(2))
                } else {
                    crate::MachineStopOptions::new()
                };
                old_machine.stop_run_with(old_run, options).await
            });
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

            if !force {
                old_monitor.kill();
            }
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
            assert!(machine_paths.vmm_socket_path().exists());
        }
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
        let pid_path = runtime.paths.machine(machine_id).vmm_pid_path();
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
                Some("11111111-1111-4111-8111-111111111111".to_string()),
                None,
            )
            .await
            .expect("set running state");
        create_machine_runtime_dirs(&runtime, machine.id);
        let exit_status_path = runtime.paths.machine(machine.id).vmm_exit_status_path();
        std::fs::write(
            &exit_status_path,
            format!(
                r#"{{"machineId":"{}","runId":"11111111-1111-4111-8111-111111111111","pid":12345,"exitedAt":99,"outcome":"error","error":"runtime exploded"}}"#,
                uuid::Uuid::from(machine.id)
            ),
        )
        .expect("write exit status");
        std::fs::set_permissions(&exit_status_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure exit status");

        let exit = machine_handle(&runtime, machine.id)
            .wait()
            .await
            .expect("wait should report silo-vmm exit status");
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
    async fn kill_with_persists_generation_for_fenced_removal() {
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
        let pid_path = runtime.paths.machine(machine.id).vmm_pid_path();
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
        let stale = machine_handle(&runtime, machine.id)
            .remove_after_run(
                uuid::Uuid::new_v4()
                    .to_string()
                    .parse()
                    .expect("parse stale run"),
            )
            .await
            .expect_err("different run must not remove the machine");
        assert!(matches!(stale, LibVmError::MachineStaleGeneration { .. }));
        machine_handle(&runtime, machine.id)
            .remove_after_run(expected_run_id.parse().expect("parse killed run"))
            .await
            .expect("confirmed killed run remains removable");
        assert!(runtime
            .machine_config(machine.id)
            .await
            .expect("inspect removed machine")
            .is_none());
    }

    #[tokio::test]
    async fn stop_starting_without_live_monitor_preserves_start_failure() {
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

        let message = "machine start did not leave a live runtime";
        assert_eq!(
            inspect_data.status,
            MachineStatus::Error {
                message: Some(message.to_string())
            }
        );
        assert_eq!(state.status, MachineRuntimeState::Error);
        assert_eq!(state.last_error.as_deref(), Some(message));
        assert!(!runtime.machine_paths(machine.id).machine_run_dir().exists());
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
        let pid_path = runtime.paths.machine(machine.id).vmm_pid_path();
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
        let pid_path = temp.path().join("silo-vmm.pid");
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
        std::fs::write(machine_paths.vmm_socket_path(), b"runtime")
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
        assert_eq!(state.vmm_pid, None);
        assert!(!machine_paths.machine_run_dir().exists());
        assert_eq!(
            std::fs::read(machine_paths.serial_log_path()).expect("read durable log"),
            b"durable log"
        );
    }

    #[tokio::test]
    async fn stop_cleans_abandoned_start_without_live_runtime() {
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

        let message = "machine start did not leave a live runtime";
        assert_eq!(
            inspect_data.status,
            MachineStatus::Error {
                message: Some(message.to_string())
            }
        );
        assert_eq!(state.status, MachineRuntimeState::Error);
        assert_eq!(state.last_error.as_deref(), Some(message));
        assert!(!runtime.machine_paths(machine.id).machine_run_dir().exists());
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
        assert_eq!(state.vmm_pid, None);
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
        let pid_path = runtime.paths.machine(machine.id).vmm_pid_path();
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
        assert_eq!(state.vmm_pid, None);
        drop(child);
    }

    #[tokio::test]
    async fn inventory_observes_stopped_without_writing_back_stopping_state() {
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
        assert_eq!(state.status, MachineRuntimeState::Stopping);
        assert_eq!(state.vmm_pid, None);
        assert_eq!(state.run_id.as_deref(), Some("run-1"));
        let inventory = runtime.inventory().await.expect("inventory");
        assert_eq!(
            inventory[0].data.as_ref().expect("snapshot").status,
            MachineStatus::Stopped
        );
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
                Some("11111111-1111-4111-8111-111111111111".to_string()),
                None,
            )
            .await
            .expect("set running state");
        create_machine_runtime_dirs(&runtime, machine.id);
        let exit_status_path = runtime.paths.machine(machine.id).vmm_exit_status_path();
        std::fs::write(
            &exit_status_path,
            format!(
                r#"{{"machineId":"{}","runId":"11111111-1111-4111-8111-111111111111","pid":12345,"exitedAt":99,"outcome":"error","error":"runtime exploded"}}"#,
                uuid::Uuid::from(machine.id)
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
        assert_eq!(inspect_data.last_error.as_deref(), Some("runtime exploded"));
        assert_eq!(
            state.status,
            MachineRuntimeState::Running,
            "inspection does not write back"
        );
        runtime
            .reconcile_machine_runtime_best_effort(&machine)
            .await
            .expect("explicit reconciliation");
        let repaired = runtime.machine_state(machine.id).await.expect("state");
        assert_eq!(repaired.status, MachineRuntimeState::Error);
        assert_eq!(repaired.vmm_pid, None);
        assert_eq!(repaired.run_id, None);
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
        let exit_status_path = runtime.paths.machine(machine.id).vmm_exit_status_path();
        std::fs::write(
            &exit_status_path,
            format!(
                r#"{{"machineId":"{}","runId":"11111111-1111-4111-8111-111111111111","pid":12345,"exitedAt":99,"outcome":"error","error":"old runtime exploded"}}"#,
                uuid::Uuid::from(machine.id)
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
        assert_eq!(
            state.status,
            MachineRuntimeState::Running,
            "inspection does not write back"
        );
        assert_eq!(state.last_error, None);
    }

    #[tokio::test]
    async fn unlocked_starting_without_live_runtime_becomes_error_immediately() {
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
            .store
            .save_machine_state(&MachineState {
                machine_id: machine.id,
                status: MachineRuntimeState::Starting,
                vmm_pid: None,
                started_at: None,
                run_id: Some("run-1".to_string()),
                last_error: None,
                updated_at: now_unix(),
            })
            .await
            .expect("set unlocked starting state");

        let inspect_data = inspect_machine(&runtime, MachineRef::id(machine.id))
            .await
            .expect("inspect machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspect_data.status.label(), "error");
        assert_eq!(
            state.status,
            MachineRuntimeState::Starting,
            "inspection does not write back"
        );
        assert_eq!(inspect_data.run_id, None);
        assert_eq!(
            inspect_data.last_error.as_deref(),
            Some("machine start did not leave a live runtime")
        );
    }

    #[tokio::test]
    async fn monitorless_starting_is_preserved_only_while_lifetime_lock_is_held() {
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
            .ensure_machine_runtime_directories(machine.id)
            .expect("create machine runtime directories");
        let lifetime_lock = crate::lock_manager::MachineLifetimeLock::try_acquire(
            &runtime.machine_paths(machine.id).vmm_lock_path(),
        )
        .expect("acquire lifetime lock")
        .expect("lifetime lock available");
        runtime
            .request_machine_start(&machine, "run-1")
            .await
            .expect("request machine start");
        let mut starting = runtime
            .machine_state(machine.id)
            .await
            .expect("read starting state");
        starting.updated_at = now_unix() - 5 * 60;
        runtime
            .store
            .save_machine_state(&starting)
            .await
            .expect("age lock-owned start");

        let locked = inspect_machine(&runtime, MachineRef::id(machine.id))
            .await
            .expect("inspect lock-owned start");
        assert!(matches!(locked.status, MachineStatus::Starting { .. }));
        assert_eq!(
            runtime
                .machine_state(machine.id)
                .await
                .expect("read lock-owned state")
                .run_id
                .as_deref(),
            Some("run-1")
        );

        drop(lifetime_lock);

        // Parallel std::process forks can briefly retain the original CLOEXEC
        // descriptor until exec. Require release, without assuming zero fork time.
        let released = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let released = inspect_machine(&runtime, MachineRef::id(machine.id))
                    .await
                    .expect("inspect abandoned start");
                if released.status.label() == "error" {
                    break released;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("lifetime lock must release after concurrent exec");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read abandoned state");
        assert_eq!(released.status.label(), "error");
        assert_eq!(
            state.status,
            MachineRuntimeState::Starting,
            "inspection does not write back"
        );
        assert_eq!(released.run_id, None);
        assert_eq!(
            released.last_error.as_deref(),
            Some("machine start did not leave a live runtime")
        );
    }

    #[tokio::test]
    async fn runtime_open_leaves_unlocked_active_state_for_explicit_reconciliation() {
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
        runtime
            .store
            .save_machine_state(&MachineState {
                machine_id: machine.id,
                status: MachineRuntimeState::Starting,
                vmm_pid: None,
                started_at: None,
                run_id: Some("run-1".to_string()),
                last_error: None,
                updated_at: now_unix(),
            })
            .await
            .expect("set unlocked starting state");
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

        assert_eq!(state.status, MachineRuntimeState::Starting);
        assert_eq!(state.run_id.as_deref(), Some("run-1"));
        assert_eq!(state.last_error, None);
        let data = reopened.inventory().await.expect("inventory");
        assert_eq!(
            data[0].data.as_ref().expect("snapshot").status.label(),
            "error"
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
        runtime
            .store
            .save_machine_state(&MachineState {
                machine_id: config.id,
                status: MachineRuntimeState::Starting,
                vmm_pid: None,
                started_at: None,
                run_id: Some("run-one".to_string()),
                last_error: None,
                updated_at: now_unix(),
            })
            .await
            .expect("simulate crash after pre-arm");
        create_machine_runtime_dirs(&runtime, config.id);
        let mut monitor = ChildGuard::sleep();
        std::fs::write(
            runtime.machine_paths(config.id).vmm_pid_path(),
            format!("{}\n", monitor.id()),
        )
        .expect("write live silo-vmm pidfile");
        drop(runtime);

        let reopened = Runtime::open(paths, RuntimeNetworkingConfig::default())
            .await
            .expect("reopen after pre-arm crash");
        reopened
            .reconcile_machine_runtime_best_effort(&config)
            .await
            .expect("explicitly recover runtime");
        let recovered = reopened
            .machine_state(config.id)
            .await
            .expect("recover runtime state");
        assert_eq!(recovered.status, MachineRuntimeState::Starting);
        assert_eq!(recovered.vmm_pid, Some(monitor.id() as i32));
        assert_eq!(recovered.run_id.as_deref(), Some("run-one"));
        assert!(reopened
            .machine_config(config.id)
            .await
            .expect("read machine config")
            .is_some());
        assert!(config.machine_dir.exists());

        let recovered_at = recovered.updated_at - 10;
        reopened
            .store
            .save_machine_state(&MachineState {
                updated_at: recovered_at,
                ..recovered
            })
            .await
            .expect("persist distinct recovered timestamp");
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
    async fn ephemeral_pre_vmm_start_failure_cleans_up_immediately() {
        let temp = tempfile::tempdir_in("/tmp").expect("create temp dir");
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
            .expect_err("pre-supervisor preparation must fail");
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
                root_disk_size: Some(1024),
                ..MachineUpdate::default()
            })
            .await
            .expect("update machine");

        assert_eq!(spec_hardware(&updated.spec).cpus, Some(6));
        assert_eq!(spec_hardware(&updated.spec).memory, Some(2048));
        assert_eq!(updated.root_disk_size, Some(1024));
        let persisted = inspect_machine(
            &runtime,
            MachineRef::parse("devbox").expect("parse machine ref"),
        )
        .await
        .expect("inspect persisted update");
        assert_eq!(spec_hardware(&persisted.spec).cpus, Some(6));
        assert_eq!(persisted.root_disk_size, Some(1024));
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
    async fn update_sets_and_clears_guest_publication() {
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
            .update(MachineUpdate::new().publish(Some(PublishBind::Any)))
            .await
            .expect("set guest publication");

        assert_eq!(
            updated.network.publish(),
            Some(GuestPublish {
                bind: PublishBind::Any
            })
        );
        let persisted = inspect_machine(
            &runtime,
            MachineRef::parse("devbox").expect("parse machine ref"),
        )
        .await
        .expect("inspect persisted publication");
        assert_eq!(persisted.network.publish(), updated.network.publish());

        let cleared = machine_handle(&runtime, machine.id)
            .update(MachineUpdate::new().publish(None))
            .await
            .expect("clear guest publication");

        assert!(cleared.network.publish().is_none());
    }

    #[tokio::test]
    async fn update_rejects_guest_publication_when_network_is_disabled() {
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

        let error = machine_handle(&runtime, machine.id)
            .update(MachineUpdate::new().publish(Some(PublishBind::Loopback)))
            .await
            .expect_err("guest publication should require private network");

        assert!(matches!(
            error,
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
        let pid_path = runtime.paths.machine(machine.id).vmm_pid_path();
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
        crate::ssh_ca::resolve(runtime.secret_store(), id, true).expect("create test machine CA");
        std::fs::write(config.machine_dir.join("data.txt"), b"machine data")
            .expect("write machine data");
        runtime
            .add_machine_record(&config, &stopped_machine_state(id, None))
            .await
            .expect("persist ephemeral machine");
        config
    }
    #[tokio::test]
    async fn always_policy_rechecks_registry_while_offline_policies_reuse_verified_cache() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let mut runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .unwrap();
        let reference = "example.invalid/demo:latest";
        write_cached_oci_rootfs(
            &runtime,
            &paths,
            reference,
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "b".repeat(64)),
        )
        .await;
        runtime.registry_policy = crate::RegistryPolicy::new(
            crate::RegistryAction::Deny,
            vec!["docker.io".into()],
            vec![],
        )
        .unwrap();
        for policy in [ImagePullPolicy::IfMissing, ImagePullPolicy::Never] {
            assert_eq!(
                runtime
                    .resolve_oci_image(reference.into(), policy)
                    .await
                    .unwrap()
                    .cache_state,
                ImageCacheState::Complete
            );
        }
        assert!(matches!(
            runtime
                .resolve_oci_image(reference.into(), ImagePullPolicy::Always)
                .await,
            Err(LibVmError::ImageReferenceRejected { .. })
        ));
    }

    #[test]
    fn launch_admission_rejects_unimplemented_and_noncanonical_root_paths() {
        let mut storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &Platform::host().unwrap(),
        )
        .unwrap();
        crate::runtime::core::validate_launch_storage(&storage).unwrap();
        if let crate::MachineRoot::OpaqueRaw { path, .. } = &mut storage.root {
            *path = crate::PrivatePath::new("different.raw").unwrap();
        }
        assert!(matches!(
            crate::runtime::core::validate_launch_storage(&storage),
            Err(LibVmError::InvalidStorageRecord { .. })
        ));
        if let crate::MachineRoot::OpaqueRaw { path, .. } = &mut storage.root {
            *path = crate::PrivatePath::new("root.raw").unwrap();
        }
        if let crate::BootProfile::LinuxDirect { root_selector, .. } = &mut storage.boot {
            *root_selector = crate::RootSelector::ManagedOverlay;
        }
        assert!(matches!(
            crate::runtime::core::validate_launch_storage(&storage),
            Err(LibVmError::InvalidStorageRecord { .. })
        ));
    }

    #[tokio::test]
    async fn launch_requires_a_real_durable_storage_record() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .unwrap();
        let config = sample_machine_config(&paths, MachineId::new(), "missing-storage");
        assert!(matches!(
            runtime.validate_machine_storage_for_launch(&config).await,
            Err(LibVmError::InvalidStorageRecord { .. })
        ));
    }

    pub(crate) async fn shutdown_storage_fixture(
        temp: &tempfile::TempDir,
    ) -> (Runtime, MachineConfig, crate::MachineStorageRecord) {
        let paths = LocalPaths::new(temp.path().join("silo"));
        let runtime = Runtime::open(paths, RuntimeNetworkingConfig::default())
            .await
            .unwrap();
        let mut config = create_pending_sample(&runtime, "shutdown")
            .await
            .unwrap()
            .commit(&runtime)
            .await
            .unwrap();
        let storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        config.spec.storage = Some(vm_spec::Storage {
            disks: vec![crate::machine::root_storage::disk(
                "root.raw",
                vm_spec::DiskRole::Root,
                512,
                "silo-root".into(),
            )
            .unwrap()],
        });
        std::fs::set_permissions(
            config.machine_dir.join("root.raw"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        runtime
            .save_machine_config_with_storage(&config, &storage)
            .await
            .unwrap();
        create_machine_runtime_dirs(&runtime, config.id);
        (runtime, config, storage)
    }

    fn write_shutdown_holder(
        runtime: &Runtime,
        config: &MachineConfig,
        run: uuid::Uuid,
        operation: uuid::Uuid,
        worker: Option<&ChildGuard>,
    ) {
        use protocol::shutdown::{StorageHolder, StorageHolderRecord, StorageHolderRole};
        let mut holders = vec![StorageHolder {
            role: StorageHolderRole::Monitor,
            pid: i32::MAX as u32,
            started_at: 1,
        }];
        if let Some(worker) = worker {
            holders.push(StorageHolder {
                role: StorageHolderRole::KrunWorker,
                pid: worker.id(),
                started_at: u64::try_from(worker.started_at().unwrap()).unwrap(),
            });
        }
        let record = StorageHolderRecord {
            schema_version: 1,
            machine_id: uuid::Uuid::from(config.id).to_string(),
            run_id: run.to_string(),
            operation_id: operation.to_string(),
            holders,
        };
        let path = runtime.machine_paths(config.id).vmm_storage_holder_path();
        std::fs::write(&path, record.encode().unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn write_shutdown_exit(
        runtime: &Runtime,
        config: &MachineConfig,
        run: uuid::Uuid,
        outcome: &str,
        evidence: Option<serde_json::Value>,
    ) {
        let mut value = serde_json::json!({
            "machineId": uuid::Uuid::from(config.id).to_string(), "runId": run.to_string(),
            "pid": i32::MAX, "exitedAt": 99, "outcome": outcome,
        });
        if let Some(evidence) = evidence {
            value["storageShutdown"] = evidence;
        }
        let path = runtime.machine_paths(config.id).vmm_exit_status_path();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[tokio::test]
    async fn shutdown_reconciliation_requires_exact_run_outer_and_all_three_facts() {
        use crate::StorageStopOutcome::{Clean, Forced, Unknown};
        for (outer, evidence, wrong_run, expected) in [
            (
                "clean",
                Some(
                    serde_json::json!({"version":1,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true}),
                ),
                false,
                Clean,
            ),
            ("clean", None, false, Unknown),
            (
                "clean",
                Some(
                    serde_json::json!({"version":1,"guestProtocolCompleted":true,"hostFlushCompleted":false,"attachmentsClosed":true}),
                ),
                false,
                Unknown,
            ),
            (
                "clean",
                Some(
                    serde_json::json!({"version":2,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true}),
                ),
                false,
                Unknown,
            ),
            (
                "clean",
                Some(
                    serde_json::json!({"version":1,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true}),
                ),
                true,
                Unknown,
            ),
            (
                "forced",
                Some(serde_json::json!({"version":"malformed"})),
                false,
                Forced,
            ),
            (
                "error",
                Some(serde_json::json!({"version":"malformed"})),
                false,
                Forced,
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
            let run = uuid::Uuid::new_v4();
            let lease = runtime
                .register_launch_storage(&config, run, &storage)
                .await
                .unwrap();
            runtime
                .mark_launch_storage_admitted(lease.operation_id())
                .await
                .unwrap();
            runtime
                .set_machine_state(
                    config.id,
                    MachineRuntimeState::Running,
                    Some(i32::MAX),
                    Some(1),
                    Some(run.to_string()),
                    None,
                )
                .await
                .unwrap();
            write_shutdown_holder(&runtime, &config, run, lease.operation_id(), None);
            write_shutdown_exit(
                &runtime,
                &config,
                if wrong_run { uuid::Uuid::new_v4() } else { run },
                outer,
                evidence,
            );
            drop(lease);
            let result = runtime
                .reconcile_machine_runtime_locked(&config)
                .await
                .unwrap();
            assert!(!result.is_active());
            assert_eq!(
                runtime
                    .machine_storage_record(config.id)
                    .await
                    .unwrap()
                    .stop_outcome,
                expected
            );
            assert!(runtime
                .store
                .launch_storage_operations(config.id)
                .await
                .unwrap()
                .is_empty());
            assert_eq!(runtime.machine_state(config.id).await.unwrap().run_id, None);
        }
    }

    #[tokio::test]
    async fn live_holders_fence_clean_missing_and_malformed_exits_until_actual_completion() {
        // A concurrent test's fork can briefly inherit the lease even with
        // CLOEXEC. Keep the immediate final-close assertion process-isolated.
        if std::env::var_os("SILO_LIVE_HOLDER_TEST_CHILD").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::core::tests::live_holders_fence_clean_missing_and_malformed_exits_until_actual_completion",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("SILO_LIVE_HOLDER_TEST_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        for record in ["clean", "missing", "malformed"] {
            let temp = tempfile::tempdir().unwrap();
            let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
            let run = uuid::Uuid::new_v4();
            let lease = runtime
                .register_launch_storage(&config, run, &storage)
                .await
                .unwrap();
            runtime
                .mark_launch_storage_admitted(lease.operation_id())
                .await
                .unwrap();
            runtime
                .set_machine_state(
                    config.id,
                    MachineRuntimeState::Running,
                    Some(i32::MAX),
                    Some(1),
                    Some(run.to_string()),
                    None,
                )
                .await
                .unwrap();
            let mut worker = ChildGuard::sleep_ready();
            write_shutdown_holder(&runtime, &config, run, lease.operation_id(), Some(&worker));
            if record == "malformed" {
                let path = runtime.machine_paths(config.id).vmm_exit_status_path();
                std::fs::write(&path, b"{").unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            if record == "clean" {
                write_shutdown_exit(
                    &runtime,
                    &config,
                    run,
                    "clean",
                    Some(serde_json::json!({
                        "version":1,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true,
                    })),
                );
            }
            let operation = lease.operation_id();
            drop(lease);
            let pool = crate::storage::pool::StoragePool::open_existing(runtime.local_images_dir())
                .unwrap()
                .unwrap();
            assert!(
                pool.try_exclusive_lease(operation).unwrap().is_some(),
                "{record}: holder liveness is independent of a free flock"
            );
            assert!(runtime
                .reconcile_machine_runtime_locked(&config)
                .await
                .unwrap()
                .is_active());
            assert!(runtime
                .ensure_no_live_vmm_generation(&config)
                .await
                .is_err());
            assert_eq!(
                runtime
                    .store
                    .launch_storage_operations(config.id)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                runtime
                    .machine_storage_record(config.id)
                    .await
                    .unwrap()
                    .stop_outcome,
                crate::StorageStopOutcome::Unknown
            );
            assert!(config.machine_dir.join("root.raw").exists());
            worker.kill();
            assert!(!runtime
                .reconcile_machine_runtime_locked(&config)
                .await
                .unwrap()
                .is_active());
            assert_eq!(
                runtime
                    .machine_storage_record(config.id)
                    .await
                    .unwrap()
                    .stop_outcome,
                if record == "clean" {
                    crate::StorageStopOutcome::Clean
                } else {
                    crate::StorageStopOutcome::Unknown
                }
            );
            assert!(runtime
                .store
                .launch_storage_operations(config.id)
                .await
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn admitted_wrong_run_malformed_or_missing_holders_preserve_operation_and_lifecycle() {
        for holder in ["missing", "malformed", "wrong-run"] {
            let temp = tempfile::tempdir().unwrap();
            let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
            let run = uuid::Uuid::new_v4();
            let lease = runtime
                .register_launch_storage(&config, run, &storage)
                .await
                .unwrap();
            runtime
                .mark_launch_storage_admitted(lease.operation_id())
                .await
                .unwrap();
            runtime
                .set_machine_state(
                    config.id,
                    MachineRuntimeState::Running,
                    Some(i32::MAX),
                    Some(1),
                    Some(run.to_string()),
                    None,
                )
                .await
                .unwrap();
            if holder == "malformed" {
                let path = runtime.machine_paths(config.id).vmm_storage_holder_path();
                std::fs::write(&path, b"{").unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            } else if holder == "wrong-run" {
                write_shutdown_holder(
                    &runtime,
                    &config,
                    uuid::Uuid::new_v4(),
                    lease.operation_id(),
                    None,
                );
            }
            drop(lease);
            assert!(runtime
                .reconcile_machine_runtime_locked(&config)
                .await
                .is_err());
            assert_eq!(
                runtime.machine_state(config.id).await.unwrap().status,
                MachineRuntimeState::Running
            );
            assert_eq!(
                runtime
                    .store
                    .launch_storage_operations(config.id)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[tokio::test]
    async fn preattachment_startup_failure_reconciles_atomically_without_inventing_clean() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
        let run = uuid::Uuid::new_v4();
        let lease = runtime
            .register_launch_storage(&config, run, &storage)
            .await
            .unwrap();
        runtime
            .request_machine_start(&config, &run.to_string())
            .await
            .unwrap();
        drop(lease);
        runtime
            .mark_machine_start_error(
                config.id,
                &run.to_string(),
                Some("pre-attachment failure".into()),
            )
            .await
            .unwrap();
        assert_eq!(
            runtime.machine_state(config.id).await.unwrap().status,
            MachineRuntimeState::Error
        );
        assert_eq!(
            runtime
                .machine_storage_record(config.id)
                .await
                .unwrap()
                .stop_outcome,
            crate::StorageStopOutcome::Unknown
        );
        assert!(runtime
            .store
            .launch_storage_operations(config.id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn cancelled_waiter_keeps_closure_pins_until_actual_blocking_owner_finishes() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
        let run = uuid::Uuid::new_v4();
        let lease = runtime
            .register_launch_storage(&config, run, &storage)
            .await
            .unwrap();
        runtime
            .request_machine_start(&config, &run.to_string())
            .await
            .unwrap();
        let retained = lease.lock().duplicate_inheritable().unwrap();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let (finished, finishing) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _retained = retained;
                let _ = entered.send(());
                let _ = wait.recv();
                drop(_retained);
                let _ = finished.send(());
            })
            .await
        });
        entering.await.unwrap();
        drop(lease);
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap()
            .is_active());
        assert_eq!(
            runtime
                .store
                .launch_storage_operations(config.id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(machine_handle(&runtime, config.id).remove().await.is_err());
        assert!(config.machine_dir.join("root.raw").exists());
        release.send(()).unwrap();
        finishing.await.unwrap();
        assert!(!runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap()
            .is_active());
        assert!(runtime
            .store
            .launch_storage_operations(config.id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn exit_record_without_an_expected_run_never_certifies_storage() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
        let run = uuid::Uuid::new_v4();
        let lease = runtime
            .register_launch_storage(&config, run, &storage)
            .await
            .unwrap();
        runtime
            .mark_launch_storage_admitted(lease.operation_id())
            .await
            .unwrap();
        write_shutdown_holder(&runtime, &config, run, lease.operation_id(), None);
        write_shutdown_exit(
            &runtime,
            &config,
            run,
            "clean",
            Some(serde_json::json!({
                "version":1,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true,
            })),
        );
        drop(lease);
        assert!(!runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap()
            .is_active());
        assert_eq!(
            runtime
                .machine_storage_record(config.id)
                .await
                .unwrap()
                .stop_outcome,
            crate::StorageStopOutcome::Unknown
        );
    }

    #[tokio::test]
    async fn admitted_preconfig_failure_can_retire_only_without_contradictory_started_evidence() {
        for started in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
            let run = uuid::Uuid::new_v4();
            let lease = runtime
                .register_launch_storage(&config, run, &storage)
                .await
                .unwrap();
            runtime
                .request_machine_start(&config, &run.to_string())
                .await
                .unwrap();
            runtime
                .mark_launch_storage_admitted(lease.operation_id())
                .await
                .unwrap();
            let path = runtime.machine_paths(config.id).vmm_exit_status_path();
            let value = serde_json::json!({
                "machineId": uuid::Uuid::from(config.id).to_string(), "runId": run.to_string(),
                "pid": i32::MAX, "exitedAt":99, "outcome":"error",
                "backend":{"kind":"krun","stage":if started { "started" } else { "prepared" }},
            });
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            drop(lease);
            let result = runtime
                .mark_machine_start_error(
                    config.id,
                    &run.to_string(),
                    Some("startup failed".into()),
                )
                .await;
            if started {
                assert!(result.is_err());
                assert_eq!(
                    runtime.machine_state(config.id).await.unwrap().status,
                    MachineRuntimeState::Starting
                );
                assert_eq!(
                    runtime
                        .store
                        .launch_storage_operations(config.id)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
            } else {
                result.unwrap();
                assert_eq!(
                    runtime.machine_state(config.id).await.unwrap().status,
                    MachineRuntimeState::Error
                );
                assert_eq!(
                    runtime
                        .machine_storage_record(config.id)
                        .await
                        .unwrap()
                        .stop_outcome,
                    crate::StorageStopOutcome::Forced
                );
                assert!(runtime
                    .store
                    .launch_storage_operations(config.id)
                    .await
                    .unwrap()
                    .is_empty());
            }
        }
    }

    #[tokio::test]
    async fn failed_terminal_sql_write_rolls_back_storage_outcome_and_operation_retirement() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
        let run = uuid::Uuid::new_v4();
        let lease = runtime
            .register_launch_storage(&config, run, &storage)
            .await
            .unwrap();
        runtime
            .mark_launch_storage_admitted(lease.operation_id())
            .await
            .unwrap();
        runtime
            .set_machine_state(
                config.id,
                MachineRuntimeState::Running,
                Some(i32::MAX),
                Some(1),
                Some(run.to_string()),
                None,
            )
            .await
            .unwrap();
        write_shutdown_holder(&runtime, &config, run, lease.operation_id(), None);
        write_shutdown_exit(
            &runtime,
            &config,
            run,
            "clean",
            Some(serde_json::json!({
                "version":1,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true,
            })),
        );
        drop(lease);
        let sql = sqlx::SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new().filename(runtime.paths.state_db_path()),
        )
        .await
        .unwrap();
        sqlx::query("CREATE TRIGGER fail_terminal_state BEFORE UPDATE ON machine_state BEGIN SELECT RAISE(ABORT, 'injected terminal SQL failure'); END")
            .execute(&sql).await.unwrap();
        assert!(runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .is_err());
        assert_eq!(
            runtime.machine_state(config.id).await.unwrap().status,
            MachineRuntimeState::Running
        );
        assert_eq!(
            runtime
                .machine_storage_record(config.id)
                .await
                .unwrap()
                .stop_outcome,
            crate::StorageStopOutcome::Unknown
        );
        assert_eq!(
            runtime
                .store
                .launch_storage_operations(config.id)
                .await
                .unwrap()
                .len(),
            1
        );
        sqlx::query("DROP TRIGGER fail_terminal_state")
            .execute(&sql)
            .await
            .unwrap();
        assert!(!runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap()
            .is_active());
        assert_eq!(
            runtime
                .machine_storage_record(config.id)
                .await
                .unwrap()
                .stop_outcome,
            crate::StorageStopOutcome::Clean
        );
    }

    #[tokio::test]
    async fn next_launch_clears_only_terminal_reconciled_holder_telemetry() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
        let run = uuid::Uuid::new_v4();
        let lease = runtime
            .register_launch_storage(&config, run, &storage)
            .await
            .unwrap();
        runtime
            .mark_launch_storage_admitted(lease.operation_id())
            .await
            .unwrap();
        runtime
            .set_machine_state(
                config.id,
                MachineRuntimeState::Running,
                Some(i32::MAX),
                Some(1),
                Some(run.to_string()),
                None,
            )
            .await
            .unwrap();
        write_shutdown_holder(&runtime, &config, run, lease.operation_id(), None);
        drop(lease);
        assert!(!runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap()
            .is_active());
        assert!(runtime
            .machine_paths(config.id)
            .vmm_storage_holder_path()
            .exists());
        let current = runtime.machine_storage_record(config.id).await.unwrap();
        let next = runtime
            .register_launch_storage(&config, uuid::Uuid::new_v4(), &current)
            .await
            .unwrap();
        assert!(!runtime
            .machine_paths(config.id)
            .vmm_storage_holder_path()
            .exists());
        drop(next);
        runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn readonly_crash_observation_projects_forced_storage_without_retiring_pins_or_writing_state(
    ) {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
        let run = uuid::Uuid::new_v4();
        let lease = runtime
            .register_launch_storage(&config, run, &storage)
            .await
            .unwrap();
        runtime
            .mark_launch_storage_admitted(lease.operation_id())
            .await
            .unwrap();
        runtime
            .set_machine_state(
                config.id,
                MachineRuntimeState::Running,
                Some(i32::MAX),
                Some(1),
                Some(run.to_string()),
                None,
            )
            .await
            .unwrap();
        let mut worker = ChildGuard::sleep();
        write_shutdown_holder(&runtime, &config, run, lease.operation_id(), Some(&worker));
        write_shutdown_exit(
            &runtime,
            &config,
            run,
            "error",
            Some(serde_json::json!({
                "version":1, "guestProtocolCompleted":false, "hostFlushCompleted":false, "attachmentsClosed":true,
            })),
        );
        drop(lease);
        let before = runtime.machine_state(config.id).await.unwrap();
        let live = runtime.machine_inspect_data(config.clone()).await.unwrap();
        assert!(matches!(live.status, MachineStatus::Stopping { .. }));
        assert_eq!(
            live.storage.unwrap().stop_outcome,
            crate::StorageStopOutcome::Unknown
        );
        worker.kill();
        let terminal = runtime.machine_inspect_data(config.clone()).await.unwrap();
        assert!(matches!(terminal.status, MachineStatus::Error { .. }));
        assert_eq!(
            terminal.storage.unwrap().stop_outcome,
            crate::StorageStopOutcome::Forced
        );
        assert_eq!(runtime.machine_state(config.id).await.unwrap(), before);
        assert_eq!(
            runtime.machine_storage_record(config.id).await.unwrap(),
            storage
        );
        assert_eq!(
            runtime
                .store
                .launch_storage_operations(config.id)
                .await
                .unwrap()
                .len(),
            1
        );
        runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap();
        assert_eq!(
            runtime.machine_state(config.id).await.unwrap().status,
            MachineRuntimeState::Error
        );
        assert_eq!(
            runtime
                .machine_storage_record(config.id)
                .await
                .unwrap()
                .stop_outcome,
            crate::StorageStopOutcome::Forced
        );
        assert!(runtime
            .store
            .launch_storage_operations(config.id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn force_stop_waits_for_the_actual_attachment_holder_after_monitor_death() {
        use protocol::shutdown::{StorageHolder, StorageHolderRecord, StorageHolderRole};
        use std::os::fd::{AsRawFd, BorrowedFd};
        let temp = tempfile::tempdir().unwrap();
        let (runtime, config, storage) = shutdown_storage_fixture(&temp).await;
        let run = uuid::Uuid::new_v4();
        let lease = runtime
            .register_launch_storage(&config, run, &storage)
            .await
            .unwrap();
        runtime
            .mark_launch_storage_admitted(lease.operation_id())
            .await
            .unwrap();
        let monitor = ChildGuard::sleep_ignoring_sigint();
        let identity = ProcessIdentity::for_pid(monitor.id() as i32)
            .unwrap()
            .unwrap();
        let lease_descriptor = lease.lock().duplicate_inheritable().unwrap();
        let backing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(config.machine_dir.join("root.raw"))
            .unwrap();
        let inherited = [lease_descriptor.as_raw_fd(), backing.as_raw_fd()];
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("30").process_group(0);
        // Actual process/FD lifetime mechanics, not a native-backend simulation.
        // Parent descriptors remain CLOEXEC; only this child's table changes.
        unsafe {
            command.pre_exec(move || {
                for raw in inherited {
                    let fd = BorrowedFd::borrow_raw(raw);
                    nix::fcntl::fcntl(
                        fd,
                        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
                    )
                    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
                }
                Ok(())
            });
        }
        let mut worker = ChildGuard {
            child: command.spawn().unwrap(),
        };
        drop(lease_descriptor);
        drop(backing);
        let holder = StorageHolderRecord {
            schema_version: 1,
            machine_id: uuid::Uuid::from(config.id).to_string(),
            run_id: run.to_string(),
            operation_id: lease.operation_id().to_string(),
            holders: vec![
                StorageHolder {
                    role: StorageHolderRole::Monitor,
                    pid: monitor.id(),
                    started_at: u64::try_from(monitor.started_at().unwrap()).unwrap(),
                },
                StorageHolder {
                    role: StorageHolderRole::KrunWorker,
                    pid: worker.id(),
                    started_at: u64::try_from(worker.started_at().unwrap()).unwrap(),
                },
            ],
        };
        let path = runtime.machine_paths(config.id).vmm_storage_holder_path();
        std::fs::write(&path, holder.encode().unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        runtime
            .set_machine_state(
                config.id,
                MachineRuntimeState::Running,
                Some(monitor.id() as i32),
                monitor.started_at(),
                Some(run.to_string()),
                None,
            )
            .await
            .unwrap();
        std::fs::write(
            runtime.machine_paths(config.id).vmm_pid_path(),
            format!("{}\n", monitor.id()),
        )
        .unwrap();
        let operation_id = lease.operation_id();
        drop(lease);
        let pool = crate::storage::pool::StoragePool::open_existing(runtime.local_images_dir())
            .unwrap()
            .unwrap();
        assert!(
            pool.try_exclusive_lease(operation_id).unwrap().is_none(),
            "the actual child retains the lease"
        );
        let machine = machine_handle(&runtime, config.id);
        let stop = tokio::spawn(async move {
            machine
                .kill_with(crate::MachineKillOptions::new().timeout(Duration::from_secs(3)))
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while identity.is_alive().unwrap() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            worker.child.try_wait().unwrap().is_none(),
            "monitor-only group kill leaves the independent holder alive"
        );
        assert!(
            !stop.is_finished(),
            "monitor death alone must not finish force stop"
        );
        assert_eq!(
            runtime
                .store
                .launch_storage_operations(config.id)
                .await
                .unwrap()
                .len(),
            1
        );
        worker.kill();
        let exit = tokio::time::timeout(Duration::from_secs(2), stop)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(exit.outcome, MachineExitOutcome::Forced);
        assert_eq!(exit.machine.status, MachineStatus::Stopped);
        assert_eq!(
            exit.machine.storage.unwrap().stop_outcome,
            crate::StorageStopOutcome::Forced
        );
        assert!(runtime
            .store
            .launch_storage_operations(config.id)
            .await
            .unwrap()
            .is_empty());
        assert!(pool.try_exclusive_lease(operation_id).unwrap().is_some());
    }
}
