use eyre::Context as _;
use std::time::Duration;

use libvm::{
    ImageProgressSender, ImageResolveOptions, ImageSource, MachineData, MachineExitOutcome,
    MachineKillOptions, MachineRef, MachineRetention, MachineRunId, MachineStopOptions,
    MachineUpdate, MachineWaitOptions, Memory, NetworkDefinition, NetworkDriver, NetworkTopology,
    ReadOnlyRuntime, Runtime, RuntimeConfig,
};
use silo_vm_control::create::{NormalizedMachineCreate, ResolvedNetwork};

use crate::api::machine::AppMachine;
use crate::api::types::{
    ReadOnlyCreationResolution, ReadOnlySourceResolution, ResolvedSource, SourceOptions,
    SourceResolution,
};
use crate::commands::create::{parse_source, validate_source_options, SourceSpelling};
use crate::machine_defaults::{
    disk_size_bytes, memory_mib, resolve_machine_mounts, ResolvedMachineNetwork,
};
use crate::planning::{self, CreatePlan, ImageCacheState, PullPolicy, ResolvedImage};
use crate::template::Template;

#[derive(Debug)]
pub(crate) enum LocalVmService {
    Uninitialized {
        config: Option<RuntimeConfig>,
        query: tokio::sync::OnceCell<libvm::LiveCapabilityQuery>,
    },
    Ready {
        runtime: Runtime,
        mode: libvm::RuntimeOpenMode,
    },
}

impl LocalVmService {
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        Self::Uninitialized {
            config: Some(config),
            query: tokio::sync::OnceCell::new(),
        }
    }

    pub(crate) async fn runtime(&mut self) -> eyre::Result<&Runtime> {
        self.runtime_with_mode(libvm::RuntimeOpenMode::Maintenance)
            .await
    }

    async fn observation_runtime(&mut self) -> eyre::Result<&Runtime> {
        self.runtime_with_mode(libvm::RuntimeOpenMode::Observation)
            .await
    }

    async fn runtime_with_mode(
        &mut self,
        requested: libvm::RuntimeOpenMode,
    ) -> eyre::Result<&Runtime> {
        if let Self::Uninitialized { config, query } = self {
            let config = config
                .take()
                .ok_or_else(|| eyre::eyre!("local runtime configuration was not initialized"))?;
            let runtime = match query.get() {
                Some(query) => {
                    Box::pin(Runtime::new_with_capability_query_and_mode(
                        config,
                        query.clone(),
                        requested,
                    ))
                    .await
                }
                None => Box::pin(Runtime::new_with_mode(config, requested)).await,
            }?;
            let provider = libvm::HostCommand::new(
                std::env::current_exe().context("resolve CLI binary path")?,
            )
            .arg("secret")
            .arg("provide")
            .arg("--store-file")
            .arg(runtime.local_home().join("secrets.json"));
            *self = Self::Ready {
                runtime: runtime.with_secret_provider(provider),
                mode: requested,
            };
        }

        match self {
            Self::Ready { runtime, mode } => {
                if requested == libvm::RuntimeOpenMode::Maintenance
                    && *mode == libvm::RuntimeOpenMode::Observation
                {
                    Box::pin(runtime.recover_maintenance()).await?;
                    *mode = libvm::RuntimeOpenMode::Maintenance;
                }
                Ok(runtime)
            }
            Self::Uninitialized { .. } => Err(eyre::eyre!("local runtime was not initialized")),
        }
    }

    pub(crate) async fn live_capabilities(&self) -> eyre::Result<vm_spec::live::LiveHostReport> {
        match self {
            Self::Ready { runtime, .. } => Ok(runtime.live_capabilities().await?),
            Self::Uninitialized {
                config: Some(config),
                query,
            } => {
                let query = query
                    .get_or_try_init(|| async { libvm::LiveCapabilityQuery::open(config) })
                    .await?;
                Ok(query.host_report().await?)
            }
            Self::Uninitialized { config: None, .. } => {
                eyre::bail!("local runtime configuration unavailable")
            }
        }
    }

    async fn observe_machine_live(
        &self,
        reference: &MachineRef,
    ) -> eyre::Result<libvm::MachineLiveObservation> {
        Ok(match self {
            Self::Ready { runtime, .. } => runtime.observe_live(reference).await?,
            Self::Uninitialized {
                config: Some(config),
                ..
            } => {
                libvm::LiveObservationReader::open(config)?
                    .observe(reference)
                    .await?
            }
            Self::Uninitialized { config: None, .. } => {
                eyre::bail!("local runtime configuration unavailable")
            }
        })
    }

    async fn require_capture_available(
        &mut self,
        reference: &MachineRef,
        observation: &libvm::MachineLiveObservation,
        fork_operation: Option<uuid::Uuid>,
    ) -> eyre::Result<()> {
        match self {
            Self::Uninitialized {
                config: Some(config),
                ..
            } => {
                libvm::LiveObservationReader::open(config)?
                    .require_capture_available(observation, fork_operation)
                    .await?;
            }
            Self::Ready { runtime, .. } => {
                runtime
                    .get_machine(reference)
                    .await?
                    .require_capture_available(observation, fork_operation)
                    .await?;
            }
            Self::Uninitialized { config: None, .. } => {
                eyre::bail!("local runtime configuration unavailable");
            }
        }
        Ok(())
    }

    pub(crate) async fn export_raw_disk(
        &mut self,
        reference: &str,
        options: libvm::RawDiskExportOptions,
    ) -> eyre::Result<libvm::RawDiskExport> {
        let reference = MachineRef::parse(reference)?;
        let machine = self.runtime().await?.get_machine(&reference).await?;
        Ok(machine.export_raw_disk(options).await?)
    }

    pub(crate) async fn pause_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        let reference = MachineRef::parse(reference)?;
        if let Self::Uninitialized {
            config: Some(config),
            ..
        } = self
        {
            if !libvm::LiveObservationReader::open(config)?.catalog_exists()? {
                libvm::require_host_live_operation(
                    &self.live_capabilities().await?,
                    vm_spec::live::LiveOperation::Pause,
                )?;
            }
        }
        let observation = self.observe_machine_live(&reference).await?;
        observation.require_pause_submission()?;
        let machine = self
            .observation_runtime()
            .await?
            .get_machine(&reference)
            .await?;
        machine.pause(&observation).await?;
        Ok(machine.inspect().await?)
    }

    pub(crate) async fn resume_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        let reference = MachineRef::parse(reference)?;
        let observation = self.observe_machine_live(&reference).await?;
        let machine = self
            .observation_runtime()
            .await?
            .get_machine(&reference)
            .await?;
        machine.resume(&observation).await?;
        Ok(machine.inspect().await?)
    }

    /// A memory snapshot requires exact Capture capability admission, and a
    /// snapshot without memory a stopped source, both from read-only evidence
    /// before writable initialization; libvm repeats them under locks.
    pub(crate) async fn snapshot(
        &mut self,
        reference: &str,
        mut options: libvm::SnapshotOptions,
        progress: Option<libvm::LiveOperationProgressSender>,
    ) -> eyre::Result<libvm::CreatedSnapshot> {
        options.name = options
            .name
            .as_deref()
            .map(silo_vm_control::local_name)
            .transpose()?;
        let machine = MachineRef::parse(reference)?;
        if options.memory {
            self.require_machine_live(reference, vm_spec::live::LiveOperation::Capture)
                .await
                .map_err(|error| match error.downcast::<libvm::LibVmError>() {
                    Ok(libvm::LibVmError::MachineNotRunning { reference }) => {
                        libvm::LibVmError::MemorySnapshotRequiresRunningMachine { reference }.into()
                    }
                    Ok(error) => error.into(),
                    Err(error) => error,
                })?;
            let observation = self.observe_machine_live(&machine).await?;
            self.require_capture_available(&machine, &observation, None)
                .await?;
        } else {
            let policy = if options.external_requirements {
                libvm::ExternalResourcePolicy::RequireMappings
            } else {
                libvm::ExternalResourcePolicy::Reject
            };
            self.preflight_stopped(&machine, true, &policy)
                .await
                .map_err(|error| match error.downcast::<libvm::LibVmError>() {
                    Ok(libvm::LibVmError::MachineAlreadyRunning { reference }) => {
                        libvm::LibVmError::SnapshotRequiresStoppedMachine { reference }.into()
                    }
                    Ok(error) => error.into(),
                    Err(error) => error,
                })?;
        }
        Ok(self
            .runtime()
            .await?
            .snapshot(&machine, options, progress)
            .await?)
    }

    /// Live fork applies the daemon's strict request rules and requires exact
    /// Fork capability admission from read-only evidence before writable
    /// initialization; libvm repeats admission under its locks.
    pub(crate) async fn fork_live(
        &mut self,
        reference: &str,
        options: libvm::LiveForkOptions,
        progress: Option<libvm::LiveOperationProgressSender>,
    ) -> eyre::Result<libvm::LiveForkResult> {
        let machine_ref = MachineRef::parse(reference)?;
        silo_vm_control::fork::request_to_wire(&machine_ref, &options)?;
        options.validate()?;
        self.require_machine_live(reference, vm_spec::live::LiveOperation::Fork)
            .await?;
        let observation = self.observe_machine_live(&machine_ref).await?;
        self.require_capture_available(&machine_ref, &observation, Some(options.operation_id))
            .await?;
        let machine = self.runtime().await?.get_machine(&machine_ref).await?;
        Ok(machine.fork_live(&observation, options, progress).await?)
    }

    /// Fork operations are addressed by ID alone, never through their source.
    pub(crate) async fn inspect_fork(
        &mut self,
        operation_id: uuid::Uuid,
    ) -> eyre::Result<libvm::LiveForkResult> {
        self.require_fork_catalog(operation_id)?;
        Ok(self.runtime().await?.inspect_fork(operation_id).await?)
    }

    pub(crate) async fn cancel_fork(
        &mut self,
        operation_id: uuid::Uuid,
    ) -> eyre::Result<libvm::LiveForkResult> {
        self.require_fork_catalog(operation_id)?;
        Ok(self.runtime().await?.cancel_fork(operation_id).await?)
    }

    /// A home without a catalog holds no fork operation; answer that without
    /// writable initialization.
    fn require_fork_catalog(&self, operation_id: uuid::Uuid) -> eyre::Result<()> {
        match self {
            Self::Uninitialized {
                config: Some(config),
                ..
            } if !libvm::LiveObservationReader::open(config)?.catalog_exists()? => {
                Err(libvm::LibVmError::LiveForkNotFound {
                    operation_id: operation_id.hyphenated().to_string(),
                }
                .into())
            }
            Self::Uninitialized { config: None, .. } => {
                eyre::bail!("local runtime configuration unavailable")
            }
            _ => Ok(()),
        }
    }

    async fn require_machine_live(
        &self,
        reference: &str,
        operation: vm_spec::live::LiveOperation,
    ) -> eyre::Result<()> {
        let reference = MachineRef::parse(reference)?;
        let observation = match self {
            Self::Ready { runtime, .. } => runtime.observe_live(&reference).await?,
            Self::Uninitialized {
                config: Some(config),
                ..
            } => {
                let reader = libvm::LiveObservationReader::open(config)?;
                if !reader.catalog_exists()? {
                    // No machine evidence exists. Refuse using explicitly host-scoped evidence.
                    libvm::require_host_live_operation(
                        &self.live_capabilities().await?,
                        operation,
                    )?;
                }
                reader.observe(&reference).await?
            }
            Self::Uninitialized { config: None, .. } => {
                eyre::bail!("local runtime configuration unavailable")
            }
        };
        libvm::require_live_operation(&observation, operation)?;
        Ok(())
    }

    async fn preflight_stopped(
        &self,
        reference: &MachineRef,
        snapshot: bool,
        policy: &libvm::ExternalResourcePolicy,
    ) -> eyre::Result<()> {
        match self {
            Self::Uninitialized {
                config: Some(config),
                ..
            } => {
                libvm::preflight_stopped(config, reference, snapshot, policy).await?;
            }
            Self::Uninitialized { config: None, .. } => {
                eyre::bail!("local runtime configuration unavailable")
            }
            // Already initialized ownership is not new admission; the native API
            // repeats authoritative checks under the source lifecycle locks.
            Self::Ready { .. } => {}
        }
        Ok(())
    }

    pub(crate) async fn fork_stopped(
        &mut self,
        reference: &str,
        mut options: libvm::ForkOptions,
    ) -> eyre::Result<MachineData> {
        options.name = silo_vm_control::stopped::name(options.name)?;
        let reference = MachineRef::parse(reference)?;
        self.preflight_stopped(&reference, false, &options.external_resources)
            .await?;
        let machine = self.runtime().await?.get_machine(&reference).await?;
        Ok(machine.fork_stopped(options).await?.inspect().await?)
    }

    pub(crate) async fn restore(
        &mut self,
        source: libvm::RestoreSource,
        options: libvm::RestoreOptions,
        progress: Option<libvm::LiveOperationProgressSender>,
    ) -> eyre::Result<MachineData> {
        if let Some(name) = &options.name {
            libvm::validate_new_machine_name(name)?;
        }
        silo_vm_control::stopped::restore_request_to_wire(&source, &options)?;
        if let libvm::RestoreSource::Local(reference) = &source {
            if let Self::Uninitialized {
                config: Some(config),
                query,
            } = self
            {
                let query = query
                    .get_or_try_init(|| async { libvm::LiveCapabilityQuery::open(config) })
                    .await?;
                libvm::preflight_restore_snapshot(config, query, reference, &options).await?;
            }
        }
        Ok(self
            .runtime()
            .await?
            .restore(source, options, progress)
            .await?
            .inspect()
            .await?)
    }

    pub(crate) async fn inspect_snapshot(
        &mut self,
        reference: libvm::SnapshotRef,
    ) -> eyre::Result<libvm::SnapshotInfo> {
        Ok(self
            .observation_runtime()
            .await?
            .snapshots()
            .inspect(&reference)
            .await?)
    }

    pub(crate) async fn verify_snapshot(
        &mut self,
        reference: libvm::SnapshotRef,
    ) -> eyre::Result<libvm::SnapshotVerificationReport> {
        Ok(self
            .observation_runtime()
            .await?
            .snapshots()
            .verify(&reference)
            .await?)
    }

    pub(crate) async fn list_snapshots(&mut self) -> eyre::Result<Vec<libvm::SnapshotInfo>> {
        Ok(self.observation_runtime().await?.snapshots().list().await?)
    }

    pub(crate) async fn remove_snapshot(
        &mut self,
        reference: libvm::SnapshotRef,
    ) -> eyre::Result<libvm::SnapshotRemoval> {
        Ok(self.runtime().await?.snapshots().remove(&reference).await?)
    }

    pub(crate) async fn list_machines(
        &mut self,
    ) -> eyre::Result<Vec<libvm::MachineInventoryEntry>> {
        Ok(self.observation_runtime().await?.inventory().await?)
    }

    pub(crate) async fn inspect_inventory(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::MachineInventoryEntry> {
        Ok(self
            .observation_runtime()
            .await?
            .inspect_inventory(&MachineRef::parse(reference)?)
            .await?)
    }

    pub(crate) async fn inspect_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        if let Self::Uninitialized {
            config: Some(config),
            ..
        } = self
        {
            libvm::LiveObservationReader::open(config)?
                .require_machine_exists(&MachineRef::parse(reference)?)
                .await?;
        }
        let machine = self
            .observation_runtime()
            .await?
            .get_machine(&MachineRef::parse(reference)?)
            .await?;
        Ok(Box::pin(machine.inspect()).await?)
    }

    pub(crate) async fn stop_machine(
        &mut self,
        reference: &str,
        force: bool,
        timeout: Duration,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let data = machine.inspect().await?;
        if !data.is_running() {
            // Observation is read-only. The lifecycle API must still reconcile
            // terminal owners, storage outcome and durable operation pins.
            return Ok(machine
                .stop_with(MachineStopOptions::new().timeout(timeout))
                .await?
                .machine);
        }
        if force {
            machine
                .kill_with(MachineKillOptions::new().timeout(timeout))
                .await?;
        } else {
            machine
                .stop_with(MachineStopOptions::new().timeout(timeout))
                .await?;
        }
        Ok(machine.inspect().await?)
    }

    pub(crate) async fn update_machine(
        &mut self,
        reference: &str,
        update: MachineUpdate,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        machine.update(update).await.map_err(Into::into)
    }

    pub(crate) async fn update_kernel_args(
        &mut self,
        reference: &str,
        clear: bool,
        append: Vec<String>,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        Ok(Box::pin(machine.update_kernel_args(clear, append)).await?)
    }

    pub(crate) async fn list_networks(&mut self) -> eyre::Result<Vec<NetworkDefinition>> {
        Ok(self
            .observation_runtime()
            .await?
            .list_network_definitions()
            .await?)
    }

    pub(crate) async fn inspect_network(
        &mut self,
        name: &str,
    ) -> eyre::Result<Option<NetworkDefinition>> {
        Ok(self
            .observation_runtime()
            .await?
            .get_network_definition(name)
            .await?)
    }

    pub(crate) async fn create_network(
        &mut self,
        name: String,
        topology: NetworkTopology,
        driver: NetworkDriver,
    ) -> eyre::Result<()> {
        self.runtime()
            .await?
            .network(name)
            .topology(topology)
            .driver(driver)
            .create()
            .await?;
        Ok(())
    }

    pub(crate) async fn remove_network(&mut self, name: &str) -> eyre::Result<()> {
        self.runtime()
            .await?
            .remove_network_definition(name)
            .await?;
        Ok(())
    }

    pub(crate) async fn set_machine_network(
        &mut self,
        reference: &str,
        network: ResolvedMachineNetwork,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        Ok(machine
            .set_network(|builder| network.apply(builder))
            .await?)
    }

    async fn machine(&mut self, reference: &str) -> eyre::Result<libvm::Machine> {
        let reference = MachineRef::parse(reference)?;
        Ok(self.runtime().await?.get_machine(&reference).await?)
    }

    pub(crate) async fn machine_handle(&mut self, reference: &str) -> eyre::Result<AppMachine> {
        let machine = self.machine(reference).await?;
        Ok(AppMachine::new(
            machine,
            self.runtime().await?.local_home().to_path_buf(),
        ))
    }

    pub(crate) async fn observation_machine_handle(
        &mut self,
        reference: &str,
    ) -> eyre::Result<AppMachine> {
        let runtime = self.observation_runtime().await?;
        let machine = runtime.get_machine(&MachineRef::parse(reference)?).await?;
        Ok(AppMachine::new(machine, runtime.local_home().to_path_buf()))
    }

    pub(crate) async fn cleanup_local(
        config: RuntimeConfig,
        machine_id: String,
        run_id: MachineRunId,
    ) -> eyre::Result<()> {
        const WAIT_INTERVAL: Duration = Duration::from_secs(5 * 60);
        let runtime = Runtime::new(config).await.context("initialize libvm")?;
        let machine = runtime.get_machine(&MachineRef::parse(machine_id)?).await?;
        loop {
            match machine
                .wait_for_run_with(
                    run_id.clone(),
                    MachineWaitOptions::new().timeout(WAIT_INTERVAL),
                )
                .await
            {
                Ok(exit)
                    if exit.outcome == MachineExitOutcome::Unknown
                        && (exit.machine.status.is_active() || exit.machine.run_id.is_some()) => {}
                Ok(_) => break,
                Err(libvm::LibVmError::MachineStaleGeneration { .. }) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        if machine.inspect().await?.retention == MachineRetention::Ephemeral {
            match machine.remove_after_run(run_id).await {
                Ok(())
                | Err(libvm::LibVmError::MachineAlreadyRunning { .. })
                | Err(libvm::LibVmError::MachineStaleGeneration { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub(crate) async fn resolve_oci_source(
        &mut self,
        reference: String,
        (runtime_pull, plan_pull): (libvm::PullPolicy, PullPolicy),
        options: &SourceOptions,
        progress: ImageProgressSender,
        is_positional: bool,
    ) -> eyre::Result<SourceResolution> {
        let runtime = self.runtime().await?.clone().with_image_progress(progress);
        let resolved = runtime
            .images()
            .resolve_with(
                reference,
                ImageResolveOptions {
                    policy: Some(runtime_pull),
                    platform: options.platform.clone(),
                },
            )
            .await?;
        Ok(SourceResolution {
            plan_image: oci_plan_image(&resolved, plan_pull),
            is_positional,
            source: ResolvedSource::LocalResolvedOci(resolved),
        })
    }

    pub(crate) async fn resolve_read_only_creation(
        config: RuntimeConfig,
        requested_name: Option<String>,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(libvm::PullPolicy, PullPolicy)>,
        options: &SourceOptions,
    ) -> eyre::Result<ReadOnlyCreationResolution> {
        let requested = crate::commands::create::selected_image_reference(positional, template)?;
        let spelling = parse_source(&requested)?;
        validate_source_options(&spelling, options, pull.is_some())?;
        let runtime = ReadOnlyRuntime::open(config).await?;
        let name = match requested_name {
            Some(name) => {
                let _ = MachineRef::parse(name.clone())?;
                if !runtime.machine_name_available(&name).await? {
                    eyre::bail!("machine {name:?} already exists");
                }
                name
            }
            None => runtime.propose_machine_name()?,
        };
        let is_positional = positional.is_some();
        let plan_image = match spelling {
            SourceSpelling::Disk(path) => {
                runtime.validate_disk_source(&path)?;
                disk_resolution(path, options, is_positional)?.plan_image
            }
            SourceSpelling::Reference(reference) => {
                let (runtime_pull, plan_pull) =
                    pull.unwrap_or((libvm::PullPolicy::IfMissing, PullPolicy::IfMissing));
                let local = match runtime.inspect_image(&reference.parse()?).await {
                    Ok(image) => CreationImage::local(reference, image)?,
                    Err(libvm::LibVmError::ImageNotFound { .. }) => CreationImage::Oci(reference),
                    Err(error) => return Err(error.into()),
                };
                match local {
                    CreationImage::Stored(image) => {
                        stored_resolution(requested, &image, options, is_positional)?.plan_image
                    }
                    CreationImage::Oci(reference) => {
                        let resolved = runtime
                            .resolve_oci_image(reference, runtime_pull, options.platform.as_ref())
                            .await?;
                        oci_plan_image(&resolved, plan_pull)
                    }
                }
            }
        };
        Ok(ReadOnlyCreationResolution {
            name,
            source: ReadOnlySourceResolution {
                plan_image,
                is_positional,
            },
        })
    }

    pub(crate) async fn ensure_name_available(&mut self, name: &str) -> eyre::Result<()> {
        self.runtime().await?.ensure_name_available(name).await?;
        Ok(())
    }

    pub(crate) async fn create_machine(
        &mut self,
        plan: &CreatePlan,
        source: SourceResolution,
        policy_config_dir: Option<&std::path::Path>,
        progress: ImageProgressSender,
    ) -> eyre::Result<MachineData> {
        ensure_source_matches_plan(plan, &source)?;
        let runtime = self.runtime().await?.clone().with_image_progress(progress);
        let mut builder = runtime.machine();
        // Source materialization remains native; normalization never selects an image.
        builder = match source.source {
            ResolvedSource::LocalResolvedOci(image) => builder.resolved_image(image),
            ResolvedSource::Disk(request) => builder.image_source(ImageSource::Disk(request)),
            ResolvedSource::Stored(id) => {
                builder.image_source(ImageSource::Stored(libvm::ImageRef::Id(id)))
            }
            ResolvedSource::DaemonOciIdentity(_) => {
                eyre::bail!("daemon-resolved source cannot be materialized by the local backend")
            }
        };
        let machine = normalize_plan(plan, policy_config_dir)?
            .apply_to_builder(builder)?
            .create()
            .await?;
        Ok(machine.inspect().await?)
    }

    pub(crate) async fn inspect_artifact(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::ArtifactInspection> {
        silo_vm_control::artifacts::validate_reference(reference)?;
        Ok(self
            .runtime()
            .await?
            .images()
            .inspect_artifact(reference)
            .await?)
    }

    pub(crate) async fn publish_artifact(
        &mut self,
        request: libvm::ArtifactPublishRequest,
    ) -> eyre::Result<libvm::ArtifactPublishReport> {
        silo_vm_control::artifacts::publish_to_wire(&request)?;
        Ok(self
            .runtime()
            .await?
            .images()
            .publish_artifact(request)
            .await?)
    }

    pub(crate) async fn import_image(
        &mut self,
        request: libvm::DiskImportRequest,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::StoredImageInfo> {
        silo_vm_control::boot::import_request_to_wire(&request)?;
        let admitted = request.admit().await?;
        Ok(self
            .runtime()
            .await?
            .clone()
            .with_image_progress(progress)
            .images()
            .import_admitted_disk(admitted)
            .await?)
    }

    /// Resolves a mutable OCI spelling once, then converts exactly the
    /// selected immutable manifest/platform identity.
    pub(crate) async fn convert_image(
        &mut self,
        reference: String,
        pull: libvm::PullPolicy,
        platform: Option<libvm::LinuxPlatform>,
        options: libvm::RawConversionOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::StoredImageInfo> {
        if let Some(name) = &options.name {
            silo_vm_control::local_name(name)?;
        }
        let images = self
            .runtime()
            .await?
            .clone()
            .with_image_progress(progress)
            .images();
        let resolved = images
            .resolve_with(
                reference,
                ImageResolveOptions {
                    policy: Some(pull),
                    platform,
                },
            )
            .await?;
        silo_vm_control::boot::platform_from_oci(&resolved.platform)?;
        Ok(images.convert(&resolved, options).await?)
    }

    pub(crate) async fn list_images(&mut self) -> eyre::Result<Vec<libvm::ImageInfo>> {
        Ok(self.observation_runtime().await?.images().list().await?)
    }

    pub(crate) async fn inspect_image(
        &mut self,
        reference: &libvm::ImageRef,
    ) -> eyre::Result<libvm::ImageInfo> {
        Ok(self
            .observation_runtime()
            .await?
            .images()
            .inspect(reference)
            .await?)
    }

    pub(crate) async fn remove_image(
        &mut self,
        reference: &libvm::ImageRef,
    ) -> eyre::Result<libvm::ImageRemoval> {
        Ok(self.runtime().await?.images().remove(reference).await?)
    }

    pub(crate) async fn prune_images(&mut self) -> eyre::Result<libvm::ImagePruneReport> {
        Ok(self.runtime().await?.images().prune().await?)
    }

    pub(crate) async fn pull_image(
        &mut self,
        reference: &str,
        options: libvm::ImagePullOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::ImageInfo> {
        silo_vm_control::images::pull_request_to_wire(reference, &options)?;
        Ok(self
            .runtime()
            .await?
            .clone()
            .with_image_progress(progress)
            .images()
            .pull_with(reference, options)
            .await?)
    }

    pub(crate) async fn update_boot_assets(
        &mut self,
        reference: &str,
        update: libvm::BootAssetsUpdate,
    ) -> eyre::Result<MachineData> {
        let reference = MachineRef::parse(reference)?;
        silo_vm_control::boot::update_boot_assets_to_wire(&reference, &update)?;
        Ok(self
            .runtime()
            .await?
            .get_machine(&reference)
            .await?
            .update_boot_assets(update)
            .await?)
    }
}

/// What a create/run reference names once local images are consulted.
pub(crate) enum CreationImage {
    /// A local stored image, used by id.
    Stored(Box<libvm::StoredImageInfo>),
    /// An OCI reference for the OCI resolver: as spelled, or the first name of
    /// a cached OCI image the spelling matched by id or id prefix.
    Oci(String),
}

impl CreationImage {
    pub(crate) fn local(reference: String, image: libvm::ImageInfo) -> eyre::Result<Self> {
        Ok(match image {
            libvm::ImageInfo::Stored(image) => Self::Stored(image),
            libvm::ImageInfo::Oci(image) => {
                let id = image.id.to_string();
                let hex = id.strip_prefix("sha256:").unwrap_or(&id);
                if reference != id && !hex.starts_with(reference.as_str()) {
                    return Ok(Self::Oci(reference));
                }
                Self::Oci(image.names.first().cloned().ok_or_else(|| {
                    eyre::eyre!(
                        "cached OCI image {id} has no name; pull it by its registry reference"
                    )
                })?)
            }
        })
    }
}

/// `:` or `/` (other than a full `sha256:` id) marks a registry reference.
pub(crate) fn is_registry_reference(reference: &str) -> bool {
    !reference.starts_with("sha256:") && reference.contains([':', '/'])
}

/// Binds a stored image to the id observed now, so a later name move cannot
/// change what the planned creation materializes.
pub(crate) fn stored_resolution(
    requested_reference: String,
    image: &libvm::StoredImageInfo,
    options: &SourceOptions,
    is_positional: bool,
) -> eyre::Result<SourceResolution> {
    if options.platform.is_some() {
        eyre::bail!("--platform cannot change a stored image; its boot metadata is immutable");
    }
    Ok(SourceResolution {
        plan_image: ResolvedImage::Stored {
            requested_reference,
            id: image.id,
            metadata: Box::new(planning::stored_image_metadata(&image.record.process)),
        },
        is_positional,
        source: ResolvedSource::Stored(image.id),
    })
}

pub(crate) fn disk_resolution(
    path: std::path::PathBuf,
    options: &SourceOptions,
    is_positional: bool,
) -> eyre::Result<SourceResolution> {
    let request = crate::commands::create::disk_create_request(path, options)?;
    Ok(SourceResolution {
        plan_image: ResolvedImage::Disk {
            path: request.path.clone(),
            boot: request.boot.clone(),
        },
        is_positional,
        source: ResolvedSource::Disk(request),
    })
}

/// The plan records libvm's canonical requested reference (`docker.io/library/alpine:3.20`),
/// never the user's spelling (`alpine:3.20`): the source check compares the plan
/// against the canonical reference carried by the resolved image.
fn oci_plan_image(resolved: &libvm::ResolvedOciImage, pull_policy: PullPolicy) -> ResolvedImage {
    ResolvedImage::Oci {
        identity: planning::OciImageIdentity {
            requested_reference: resolved.requested_reference.clone(),
            selected_reference: resolved.selected_reference.clone(),
            platform: resolved.platform.clone(),
            manifest_digest: resolved.manifest_digest.clone(),
            config_digest: resolved.config_digest.clone(),
            cache_state: image_cache_state(resolved.cache_state),
            pull_policy,
        },
        metadata: Box::new(resolved.config.clone()),
    }
}

pub(crate) fn normalize_plan(
    plan: &CreatePlan,
    policy_config_dir: Option<&std::path::Path>,
) -> eyre::Result<NormalizedMachineCreate> {
    let mut mounts = resolve_machine_mounts(&plan.machine.mounts)?;
    for mount in &mut mounts {
        mount.source = canonical_host_path(&mount.source)?;
    }
    let mut forwards = plan.machine.forwards.clone();
    normalize_forwards(&mut forwards)?;
    let agent = match &plan.machine_settings.agent {
        libvm::MachineAgent::Custom { path } => libvm::MachineAgent::Custom {
            path: canonical_host_path(path)?,
        },
        agent => agent.clone(),
    };
    let memory_bytes = memory_mib(plan.machine.resources.as_ref())?
        .map(|memory| Memory::mebibytes(u64::from(memory)).as_bytes());
    let root_disk_size_bytes = disk_size_bytes(plan.machine.disk_size.as_deref())?;
    let network = plan
        .machine
        .network
        .clone()
        .map(|network| network.resolve_machine_network(policy_config_dir))
        .transpose()?
        .map(|network| match network {
            ResolvedMachineNetwork::Private { policy, publish } => {
                ResolvedNetwork::Private { policy, publish }
            }
            ResolvedMachineNetwork::None => ResolvedNetwork::None,
            ResolvedMachineNetwork::Named { name } => ResolvedNetwork::Named { name },
        });
    let normalized = NormalizedMachineCreate {
        name: plan.proposed_name.clone(),
        template_name: plan.template.name.clone(),
        labels: plan.machine.labels.clone(),
        process: plan.process.clone(),
        retention: plan.retention,
        kernel: plan
            .machine_settings
            .kernel
            .as_deref()
            .map(canonical_host_path)
            .transpose()?,
        initramfs: plan
            .machine_settings
            .initramfs
            .as_deref()
            .map(canonical_host_path)
            .transpose()?,
        kernel_args: plan.machine_settings.kernel_args.clone(),
        nested_virtualization: plan.machine_settings.nested_virtualization,
        rosetta: plan.machine_settings.rosetta,
        platform: plan.machine_settings.platform.clone(),
        disks: plan
            .machine_settings
            .disks
            .iter()
            .map(|path| canonical_host_path(path))
            .collect::<eyre::Result<_>>()?,
        mounts,
        forwards,
        vsock: plan.machine.vsock,
        cpus: plan
            .machine
            .resources
            .as_ref()
            .and_then(|resources| resources.cpus),
        memory_bytes,
        root_disk_size_bytes,
        temporary_directory: match crate::machine_defaults::disk_size_bytes(
            plan.machine.tmpfs_size.as_deref(),
        )? {
            Some(capacity_bytes) => libvm::TemporaryDirectoryPolicy::Tmpfs { capacity_bytes },
            None => libvm::TemporaryDirectoryPolicy::DiskBacked,
        },
        userdata: plan.machine.userdata.clone(),
        network,
        agent,
        provision_user: plan.machine_settings.provision_user.clone(),
    };
    Ok(normalized)
}

pub(crate) fn ensure_source_matches_plan(
    plan: &CreatePlan,
    source: &SourceResolution,
) -> eyre::Result<()> {
    let matches = match (&plan.image, &source.plan_image, &source.source) {
        (planning::ImageIdentity::Oci(plan), ResolvedImage::Oci { identity, .. }, resolved) => {
            // Cache presence is an observation, not part of the immutable artifact identity.
            let metadata_matches = plan.requested_reference == identity.requested_reference
                && plan.selected_reference == identity.selected_reference
                && plan.platform == identity.platform
                && plan.manifest_digest == identity.manifest_digest
                && plan.config_digest == identity.config_digest
                && plan.pull_policy == identity.pull_policy;
            metadata_matches
                && match resolved {
                    ResolvedSource::LocalResolvedOci(image) => {
                        image.requested_reference == plan.requested_reference
                            && image.selected_reference == plan.selected_reference
                            && image.platform == plan.platform
                            && image.manifest_digest == plan.manifest_digest
                            && image.config_digest == plan.config_digest
                    }
                    ResolvedSource::DaemonOciIdentity(image) => {
                        image.requested_reference == plan.requested_reference
                            && image.selected_reference == plan.selected_reference
                            && image.platform == plan.platform
                            && image.manifest_digest == plan.manifest_digest
                            && image.config_digest == plan.config_digest
                            && image.pull_policy
                                == match plan.pull_policy {
                                    PullPolicy::IfMissing => libvm::PullPolicy::IfMissing,
                                    PullPolicy::Always => libvm::PullPolicy::Always,
                                    PullPolicy::Never => libvm::PullPolicy::Never,
                                }
                    }
                    ResolvedSource::Disk(_) | ResolvedSource::Stored(_) => false,
                }
        }
        (
            planning::ImageIdentity::Disk { path: plan, boot },
            ResolvedImage::Disk {
                path,
                boot: resolved_boot,
            },
            ResolvedSource::Disk(request),
        ) => {
            plan == path
                && boot == resolved_boot
                && &request.path == path
                && &request.boot == boot
                && request.name.is_none()
                && path.is_absolute()
        }
        (
            planning::ImageIdentity::Stored {
                requested_reference,
                id: plan,
            },
            ResolvedImage::Stored {
                requested_reference: resolved_reference,
                id: resolved,
                ..
            },
            ResolvedSource::Stored(source),
        ) => requested_reference == resolved_reference && plan == resolved && source == plan,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        eyre::bail!("resolved image no longer matches the planned immutable identity")
    }
}

pub(crate) fn normalize_update(update: &mut MachineUpdate) -> eyre::Result<()> {
    if let Some(guest) = &mut update.guest {
        if let libvm::MachineAgent::Custom { path } = &mut guest.agent {
            *path = canonical_host_path(path)?;
        }
    }
    if let Some(forwards) = &mut update.forwards {
        normalize_forwards(forwards)?;
    }
    if let Some(path) = update.vsock.as_mut().and_then(|vsock| vsock.uds.as_mut()) {
        *path = canonical_socket_path(path)?;
    }
    Ok(())
}

fn normalize_forwards(forwards: &mut [libvm::Forward]) -> eyre::Result<()> {
    for forward in forwards {
        for endpoint in [&mut forward.listen, &mut forward.connect] {
            if let libvm::ForwardEndpoint::Host(libvm::ForwardAddress::Unix(path)) = endpoint {
                *path = canonical_socket_path(path)?;
            }
        }
    }
    Ok(())
}

fn canonical_host_path(path: &std::path::Path) -> eyre::Result<std::path::PathBuf> {
    let path = crate::machine_defaults::resolve_host_path(path)?;
    std::fs::canonicalize(&path)
        .with_context(|| format!("canonicalize host path {}", path.display()))
}

fn canonical_socket_path(path: &std::path::Path) -> eyre::Result<std::path::PathBuf> {
    // Bare socket names belong to the machine runtime, not the client's CWD.
    if path
        .file_name()
        .is_some_and(|name| name == path.as_os_str())
    {
        return Ok(path.to_path_buf());
    }
    let path = crate::machine_defaults::resolve_host_path(path)?;
    // Listening sockets need not exist yet. Resolve the existing ancestor without
    // losing the intended leaf, while keeping daemon CWD out of path interpretation.
    let mut ancestor = path.as_path();
    let mut suffix = Vec::new();
    loop {
        match std::fs::canonicalize(ancestor) {
            Ok(mut resolved) => {
                for component in suffix.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let leaf = ancestor
                    .file_name()
                    .ok_or_else(|| eyre::eyre!("invalid host socket path {}", path.display()))?;
                suffix.push(leaf);
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| eyre::eyre!("invalid host socket path {}", path.display()))?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("canonicalize host socket path {}", path.display()))
            }
        }
    }
}

fn image_cache_state(state: libvm::ImageCacheState) -> ImageCacheState {
    match state {
        libvm::ImageCacheState::Complete => ImageCacheState::Complete,
        libvm::ImageCacheState::Missing => ImageCacheState::Missing,
    }
}

#[cfg(test)]
mod tests {
    use crate::api::local::{ensure_source_matches_plan, normalize_plan};
    use crate::api::types::{ResolvedSource, SourceResolution};
    use crate::planning::{
        CleanupPlan, CreatePlan, ImageCacheState, ImageIdentity, MachineCreationSettings,
        MachinePlan, OciImageIdentity, PullPolicy, ResolvedImage, TemplateMetadata,
    };

    fn plan(image: ImageIdentity) -> CreatePlan {
        CreatePlan {
            schema_version: 1,
            proposed_name: Some("test".into()),
            template: TemplateMetadata {
                name: None,
                version: "1".into(),
                description: None,
            },
            image,
            machine: MachinePlan {
                resources: None,
                disk_size: None,
                tmpfs_size: None,
                userdata: None,
                mounts: Vec::new(),
                forwards: Vec::new(),
                vsock: None,
                network: None,
                labels: Default::default(),
            },
            machine_settings: MachineCreationSettings {
                kernel: None,
                initramfs: None,
                kernel_args: Vec::new(),
                nested_virtualization: false,
                rosetta: None,
                platform: None,
                disks: Vec::new(),
                agent: libvm::MachineAgent::Default,
                provision_user: None,
            },
            process: libvm::ProcessConfig::default(),
            retention: libvm::MachineRetention::Persistent,
            cleanup: CleanupPlan::RetainMachine,
        }
    }

    #[tokio::test]
    async fn incompatible_home_keeps_fresh_state_guidance_in_default_error_message() {
        use std::os::unix::fs::OpenOptionsExt;

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(home.join("catalog.lock"))
            .unwrap();
        let database = home.join("state.db");
        std::fs::File::create(&database).unwrap();
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", database.display()))
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE _sqlx_migrations (
                version BIGINT PRIMARY KEY,
                description TEXT NOT NULL,
                installed_on TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN NOT NULL,
                checksum BLOB NOT NULL,
                execution_time BIGINT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO _sqlx_migrations
                (version, description, success, checksum, execution_time)
             VALUES (1, 'initial', TRUE, x'00', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let config = crate::api::tests::isolated_runtime_config(temp.path(), &home);
        let mut service = crate::api::local::LocalVmService::new(config);
        let error = service.list_machines().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<libvm::LibVmError>(),
            Some(libvm::LibVmError::StateDatabaseIncompatible { .. })
        ));
        let message = error.to_string();
        assert!(message.contains("incompatible state database"));
        assert!(message.contains("cannot be read or converted"));
        assert!(message.contains("fresh home"));
    }

    #[test]
    fn source_check_accepts_cache_warming_but_rejects_identity_and_policy_changes() {
        let identity = OciImageIdentity {
            requested_reference: "registry/image:latest".into(),
            selected_reference: "registry/image@sha256:manifest".into(),
            platform: libvm::Platform::linux_amd64(),
            manifest_digest: "sha256:manifest".into(),
            config_digest: "sha256:config".into(),
            cache_state: ImageCacheState::Missing,
            pull_policy: PullPolicy::Never,
        };
        let plan = plan(ImageIdentity::Oci(identity.clone()));
        let mut observed = identity.clone();
        observed.cache_state = ImageCacheState::Complete;
        let mut source = SourceResolution {
            plan_image: ResolvedImage::Oci {
                identity: observed,
                metadata: Box::default(),
            },
            is_positional: true,
            source: ResolvedSource::DaemonOciIdentity(silo_vm_control::images::OciIdentity {
                requested_reference: identity.requested_reference,
                selected_reference: identity.selected_reference,
                platform: identity.platform,
                manifest_digest: identity.manifest_digest,
                config_digest: identity.config_digest,
                pull_policy: libvm::PullPolicy::Never,
            }),
        };
        ensure_source_matches_plan(&plan, &source).expect("cache warming is not a conflict");
        let ResolvedSource::DaemonOciIdentity(image) = &mut source.source else {
            unreachable!()
        };
        image.pull_policy = libvm::PullPolicy::Always;
        assert!(ensure_source_matches_plan(&plan, &source).is_err());
        let ResolvedSource::DaemonOciIdentity(image) = &mut source.source else {
            unreachable!()
        };
        image.pull_policy = libvm::PullPolicy::Never;
        image.config_digest = "sha256:other".into();
        assert!(ensure_source_matches_plan(&plan, &source).is_err());
    }

    fn disk_boot() -> libvm::DiskImportBoot {
        libvm::DiskImportBoot::LinuxDirect {
            platform: libvm::LinuxPlatform {
                architecture: libvm::GuestArchitecture::Amd64,
                variant: None,
            },
            root: libvm::ImportRootSelection::WholeDisk,
            assets: libvm::BootAssetSelection::Packaged,
        }
    }

    #[test]
    fn disk_and_stored_sources_must_match_the_planned_identity() {
        let path = std::path::PathBuf::from("/images/root.raw");
        let request = libvm::DiskImportRequest {
            path: path.clone(),
            boot: disk_boot(),
            name: None,
        };
        let plan_disk = plan(ImageIdentity::Disk {
            path: path.clone(),
            boot: disk_boot(),
        });
        let disk = |request: libvm::DiskImportRequest| SourceResolution {
            plan_image: ResolvedImage::Disk {
                path: path.clone(),
                boot: disk_boot(),
            },
            is_positional: true,
            source: ResolvedSource::Disk(request),
        };
        ensure_source_matches_plan(&plan_disk, &disk(request.clone())).expect("same disk");
        let mut other_root = request.clone();
        other_root.boot = libvm::DiskImportBoot::LinuxDirect {
            platform: libvm::LinuxPlatform {
                architecture: libvm::GuestArchitecture::Amd64,
                variant: None,
            },
            root: libvm::ImportRootSelection::AutoGpt,
            assets: libvm::BootAssetSelection::Packaged,
        };
        assert!(ensure_source_matches_plan(&plan_disk, &disk(other_root)).is_err());
        let mut named = request;
        named.name = Some("published".into());
        assert!(ensure_source_matches_plan(&plan_disk, &disk(named)).is_err());

        let image: libvm::ImageId = format!("sha256:{}", "cd".repeat(32)).parse().unwrap();
        let other: libvm::ImageId = format!("sha256:{}", "ef".repeat(32)).parse().unwrap();
        let plan_stored = plan(ImageIdentity::Stored {
            requested_reference: "base".into(),
            id: image,
        });
        let stored = |resolved: libvm::ImageId, source: libvm::ImageId| SourceResolution {
            plan_image: ResolvedImage::Stored {
                requested_reference: "base".into(),
                id: resolved,
                metadata: Box::default(),
            },
            is_positional: true,
            source: ResolvedSource::Stored(source),
        };
        ensure_source_matches_plan(&plan_stored, &stored(image, image)).expect("same stored image");
        // A name that moved to another image between planning and creation.
        assert!(ensure_source_matches_plan(&plan_stored, &stored(other, other)).is_err());
        assert!(ensure_source_matches_plan(&plan_stored, &stored(image, other)).is_err());
        assert!(ensure_source_matches_plan(&plan_disk, &stored(image, image)).is_err());
    }

    #[test]
    fn normalization_preserves_tri_state_rosetta_intent() {
        for intent in [None, Some(false), Some(true)] {
            let mut plan = plan(ImageIdentity::Disk {
                path: "/images/root.raw".into(),
                boot: disk_boot(),
            });
            plan.machine_settings.rosetta = intent;
            assert_eq!(normalize_plan(&plan, None).unwrap().rosetta, intent);
        }
    }

    #[test]
    fn normalization_canonicalizes_host_files_and_uncreated_socket_paths() {
        let temp = tempfile::tempdir_in(".").expect("relative temp directory");
        let file = temp.path().join("asset");
        std::fs::write(&file, b"asset").expect("host asset");
        let canonical = std::fs::canonicalize(&file).expect("canonical asset");
        let mut plan = plan(ImageIdentity::Disk {
            path: canonical.clone(),
            boot: disk_boot(),
        });
        plan.machine_settings.kernel = Some(file.clone());
        plan.machine_settings.initramfs = Some(file.clone());
        plan.machine_settings.disks = vec![file.clone()];
        plan.machine_settings.agent = libvm::MachineAgent::Custom { path: file.clone() };
        plan.machine
            .mounts
            .push(crate::machine_defaults::MachineMount {
                source: file,
                target: "/asset".into(),
                mode: crate::machine_defaults::MountMode::Ro,
            });
        plan.machine.forwards.push(libvm::Forward::new(
            libvm::ForwardEndpoint::host(libvm::ForwardAddress::unix(temp.path().join("new.sock"))),
            libvm::ForwardEndpoint::guest(libvm::ForwardAddress::unix("/run/guest.sock")),
        ));
        let normalized = normalize_plan(&plan, None).expect("normalize plan");
        assert_eq!(normalized.kernel, Some(canonical.clone()));
        assert_eq!(normalized.initramfs, Some(canonical.clone()));
        assert_eq!(normalized.disks, vec![canonical.clone()]);
        assert_eq!(normalized.mounts[0].source, canonical.clone());
        assert_eq!(
            normalized.agent,
            libvm::MachineAgent::Custom { path: canonical }
        );
        assert_eq!(
            normalized.forwards[0].listen,
            libvm::ForwardEndpoint::host(libvm::ForwardAddress::unix(
                std::fs::canonicalize(temp.path())
                    .expect("canonical directory")
                    .join("new.sock")
            )),
        );
        assert_eq!(
            normalized.forwards[0].connect,
            plan.machine.forwards[0].connect
        );
    }

    #[test]
    fn normalization_preserves_machine_relative_socket_names() {
        let mut update = libvm::MachineUpdate::new();
        update.forwards = Some(vec![libvm::Forward::new(
            libvm::ForwardEndpoint::host(libvm::ForwardAddress::unix("svc.sock")),
            libvm::ForwardEndpoint::guest(libvm::ForwardAddress::tcp(
                "127.0.0.1:7301".parse().unwrap(),
            )),
        )]);
        crate::api::local::normalize_update(&mut update).unwrap();
        assert_eq!(
            update.forwards.unwrap()[0].listen,
            libvm::ForwardEndpoint::host(libvm::ForwardAddress::unix("svc.sock"))
        );
    }

    #[test]
    fn updates_resolve_relative_host_paths_before_backend_selection() {
        let temp = tempfile::tempdir_in(".").unwrap();
        let agent = temp.path().join("agent");
        std::fs::write(&agent, b"guest executable").unwrap();
        let mut update = libvm::MachineUpdate::new();
        update.guest = Some(libvm::MachineGuestConfig {
            agent: libvm::MachineAgent::Custom {
                path: agent.clone(),
            },
            user: None,
        });
        update.vsock = Some(vm_spec::Vsock {
            enabled: true,
            uds: Some(temp.path().join("uncreated.sock")),
        });
        crate::api::local::normalize_update(&mut update).unwrap();
        assert_eq!(
            update.guest.unwrap().agent,
            libvm::MachineAgent::Custom {
                path: agent.canonicalize().unwrap()
            }
        );
        assert_eq!(
            update.vsock.unwrap().uds,
            Some(temp.path().canonicalize().unwrap().join("uncreated.sock"))
        );
        let mut missing = libvm::MachineUpdate::new();
        missing.guest = Some(libvm::MachineGuestConfig {
            agent: libvm::MachineAgent::Custom {
                path: temp.path().join("missing"),
            },
            user: None,
        });
        assert!(crate::api::local::normalize_update(&mut missing).is_err());
    }

    #[tokio::test]
    async fn stopped_option_validation_precedes_cold_runtime_initialization() {
        use crate::api::local::LocalVmService;
        use libvm::{
            ExternalResourcePolicy, ForkOptions, RestoreOptions, RestoreSource, RuntimeConfig,
            SnapshotOptions,
        };
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("absent-home");
        let run = temp.path().join("absent-run");
        let mut service = LocalVmService::new(RuntimeConfig::local(&home).with_run_root(&run));
        for name in [
            "INVALID",
            "trailing-",
            "contains space",
            "",
            &"a".repeat(64),
        ] {
            let error = service
                .fork_stopped(
                    "absent",
                    ForkOptions {
                        name: Some(name.into()),
                        external_resources: ExternalResourcePolicy::Reject,
                    },
                )
                .await
                .unwrap_err();
            assert!(
                error
                    .downcast_ref::<silo_vm_control::ConversionError>()
                    .is_some(),
                "{error}"
            );
            let error = service
                .restore(
                    RestoreSource::Registry("absent".into()),
                    RestoreOptions {
                        name: Some(name.into()),
                        ..RestoreOptions::default()
                    },
                    None,
                )
                .await
                .unwrap_err();
            assert!(
                error
                    .downcast_ref::<libvm::LibVmError>()
                    .is_some_and(|error| matches!(
                        error,
                        libvm::LibVmError::InvalidMachineName { .. }
                    )),
                "{error}"
            );
            assert!(!home.exists());
            assert!(!run.exists());
        }
        for name in [
            "invalid name",
            "sha256:invalid",
            "registry/name",
            "tag:v1",
            "",
            &"a".repeat(129),
        ] {
            for memory in [false, true] {
                let error = service
                    .snapshot(
                        "absent",
                        SnapshotOptions {
                            name: Some(name.into()),
                            memory,
                            ..SnapshotOptions::default()
                        },
                        None,
                    )
                    .await
                    .unwrap_err();
                assert!(
                    error
                        .downcast_ref::<silo_vm_control::ConversionError>()
                        .is_some(),
                    "{error}"
                );
                assert!(!home.exists());
                assert!(!run.exists());
            }
        }
        assert!(matches!(
            service,
            LocalVmService::Uninitialized {
                config: Some(_),
                ..
            }
        ));
        assert!(!home.exists());
        assert!(!run.exists());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[test]
    fn cached_oci_images_matched_by_id_resolve_through_their_registry_name() {
        use crate::api::local::{is_registry_reference, CreationImage};
        let id = format!("sha256:{}", "ab".repeat(32));
        let cached = |names: &[&str]| {
            libvm::ImageInfo::Oci(Box::new(libvm::OciImageInfo {
                id: id.parse().unwrap(),
                names: names.iter().map(|name| (*name).to_owned()).collect(),
                config_digest: format!("sha256:{}", "cd".repeat(32)),
                platform: libvm::Platform::linux_amd64(),
                config: libvm::OciImageConfigMetadata::default(),
                layers: Vec::new(),
                lower_length: 0,
                compressed_size_bytes: 0,
                created_at: 0,
                last_used_at: None,
            }))
        };
        let name = "docker.io/library/alpine:3.21";
        for (reference, expected) in [
            ("alpine:3.21", "alpine:3.21"),
            (name, name),
            ("abab", name),
            (id.as_str(), name),
        ] {
            let CreationImage::Oci(resolved) =
                CreationImage::local(reference.into(), cached(&[name])).unwrap()
            else {
                panic!("a cached OCI image stays an OCI source");
            };
            assert_eq!(resolved, expected, "{reference}");
        }
        let error = CreationImage::local("abab".into(), cached(&[]))
            .err()
            .unwrap();
        assert!(error.to_string().contains("has no name"), "{error}");

        for reference in ["alpine:3.21", "nixos/nix", "ghcr.io/acme/app:1"] {
            assert!(is_registry_reference(reference), "{reference}");
        }
        for reference in ["base", "abab", id.as_str()] {
            assert!(!is_registry_reference(reference), "{reference}");
        }
    }
}
