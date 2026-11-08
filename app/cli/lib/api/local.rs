use eyre::Context as _;
use std::time::Duration;

use libvm::{
    ImageProgressSender, ImagePullPolicy, ImageResolveOptions, ImageSource, MachineData,
    MachineExitOutcome, MachineKillOptions, MachineRef, MachineRetention, MachineRunId,
    MachineStopOptions, MachineUpdate, MachineWaitOptions, Memory, NetworkDefinition,
    NetworkDriver, NetworkTopology, ReadOnlyRuntime, Runtime, RuntimeConfig,
};
use silo_vm_control::create::{NormalizedMachineCreate, ResolvedNetwork};
use silo_vm_control::images::ManagedSpelling;

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
    Ready(Runtime),
}

impl LocalVmService {
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        Self::Uninitialized {
            config: Some(config),
            query: tokio::sync::OnceCell::new(),
        }
    }

    pub(crate) async fn runtime(&mut self) -> eyre::Result<&Runtime> {
        if let Self::Uninitialized { config, .. } = self {
            let config = config
                .take()
                .ok_or_else(|| eyre::eyre!("local runtime configuration was not initialized"))?;
            let runtime = Runtime::new(config)
                .await
                .context("initialize local libvm adapter")?;
            let provider = libvm::HostCommand::new(
                std::env::current_exe().context("resolve CLI binary path")?,
            )
            .arg("secret")
            .arg("provide")
            .arg("--store-file")
            .arg(runtime.local_home().join("secrets.json"));
            *self = Self::Ready(runtime.with_secret_provider(provider));
        }

        match self {
            Self::Ready(runtime) => Ok(runtime),
            Self::Uninitialized { .. } => Err(eyre::eyre!("local runtime was not initialized")),
        }
    }

    pub(crate) async fn live_capabilities(&self) -> eyre::Result<vm_spec::live::LiveHostReport> {
        match self {
            Self::Ready(runtime) => Ok(runtime.live_capabilities().await?),
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
            Self::Ready(runtime) => runtime.observe_live(reference).await?,
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
        let machine = self.runtime().await?.get_machine(&reference).await?;
        machine.pause(&observation).await?;
        Ok(machine.inspect().await?)
    }

    pub(crate) async fn resume_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        let reference = MachineRef::parse(reference)?;
        let observation = self.observe_machine_live(&reference).await?;
        let machine = self.runtime().await?.get_machine(&reference).await?;
        machine.resume(&observation).await?;
        Ok(machine.inspect().await?)
    }

    /// New capture requires exact Capture capability admission from read-only
    /// evidence before writable initialization; libvm repeats it under locks.
    pub(crate) async fn snapshot_live(
        &mut self,
        reference: &str,
        mut options: libvm::LiveSnapshotOptions,
    ) -> eyre::Result<libvm::LiveSnapshot> {
        options.validate()?;
        options.name = options
            .name
            .map(|name| silo_vm_control::stopped::alias(&name))
            .transpose()?;
        self.require_machine_live(reference, vm_spec::live::LiveOperation::Capture)
            .await?;
        if options.policy == vm_spec::lifecycle::CapturePolicy::Incremental {
            self.require_machine_live(reference, vm_spec::live::LiveOperation::Incremental)
                .await?;
        }
        let reference = MachineRef::parse(reference)?;
        let observation = self.observe_machine_live(&reference).await?;
        let machine = self.runtime().await?.get_machine(&reference).await?;
        Ok(machine.snapshot_live(&observation, options).await?)
    }

    /// Live fork applies the daemon's strict request rules and requires exact
    /// Fork capability admission from read-only evidence before writable
    /// initialization; libvm repeats admission under its locks.
    pub(crate) async fn fork_live(
        &mut self,
        reference: &str,
        options: libvm::LiveForkOptions,
    ) -> eyre::Result<libvm::LiveForkResult> {
        let machine_ref = MachineRef::parse(reference)?;
        silo_vm_control::fork::request_to_wire(&machine_ref, &options)?;
        options.validate()?;
        self.require_machine_live(reference, vm_spec::live::LiveOperation::Fork)
            .await?;
        if options.policy == vm_spec::lifecycle::CapturePolicy::Incremental {
            self.require_machine_live(reference, vm_spec::live::LiveOperation::Incremental)
                .await?;
        }
        let observation = self.observe_machine_live(&machine_ref).await?;
        let machine = self.runtime().await?.get_machine(&machine_ref).await?;
        Ok(machine.fork_live(&observation, options).await?)
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
            Self::Ready(runtime) => runtime.observe_live(&reference).await?,
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
            Self::Ready(_) => {}
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

    pub(crate) async fn snapshot_stopped(
        &mut self,
        reference: &str,
        mut options: libvm::SnapshotOptions,
    ) -> eyre::Result<libvm::SnapshotInfo> {
        options.name = options
            .name
            .map(|name| silo_vm_control::stopped::alias(&name))
            .transpose()?;
        silo_vm_control::stopped::snapshot_policy(&options.external_resources)?;
        let reference = MachineRef::parse(reference)?;
        self.preflight_stopped(&reference, true, &options.external_resources)
            .await?;
        Ok(self
            .runtime()
            .await?
            .get_machine(&reference)
            .await?
            .snapshot_stopped(options)
            .await?)
    }

    pub(crate) async fn restore_snapshot(
        &mut self,
        reference: libvm::SnapshotRef,
        mut options: libvm::RestoreOptions,
    ) -> eyre::Result<MachineData> {
        options.name = silo_vm_control::stopped::name(options.name)?;
        if let Self::Uninitialized {
            config: Some(config),
            ..
        } = self
        {
            libvm::preflight_restore_snapshot(config, &reference, &options.external_resources)
                .await?;
        }
        Ok(self
            .runtime()
            .await?
            .restore_snapshot(reference, options)
            .await?
            .inspect()
            .await?)
    }

    pub(crate) async fn recover_checkpoint_disks(
        &mut self,
        reference: libvm::SnapshotRef,
        mut options: libvm::RecoverDisksOptions,
    ) -> eyre::Result<MachineData> {
        options.name = silo_vm_control::stopped::name(options.name)?;
        if let Self::Uninitialized {
            config: Some(config),
            ..
        } = self
        {
            libvm::preflight_recover_checkpoint_disks(
                config,
                &reference,
                &options.external_resources,
            )
            .await?;
        }
        Ok(self
            .runtime()
            .await?
            .recover_checkpoint_disks(reference, options)
            .await?
            .inspect()
            .await?)
    }

    pub(crate) async fn inspect_snapshot(
        &mut self,
        reference: libvm::SnapshotRef,
    ) -> eyre::Result<libvm::SnapshotInfo> {
        Ok(
            libvm::SnapshotStore::open(self.runtime().await?.local_home())
                .await?
                .inspect(&reference)
                .await?,
        )
    }

    pub(crate) async fn list_snapshots(&mut self) -> eyre::Result<Vec<libvm::SnapshotInfo>> {
        Ok(
            libvm::SnapshotStore::open(self.runtime().await?.local_home())
                .await?
                .list()
                .await?,
        )
    }

    pub(crate) async fn release_snapshot(
        &mut self,
        reference: libvm::SnapshotRef,
    ) -> eyre::Result<()> {
        libvm::SnapshotStore::open(self.runtime().await?.local_home())
            .await?
            .release_retention(&reference)
            .await?;
        Ok(())
    }

    /// Removes one name from the single image/snapshot namespace. Explicit
    /// retention of the target is never released here.
    pub(crate) async fn remove_image_alias(&mut self, alias: String) -> eyre::Result<()> {
        self.runtime().await?.images().remove_alias(&alias).await?;
        Ok(())
    }

    pub(crate) async fn list_machines(
        &mut self,
    ) -> eyre::Result<Vec<libvm::MachineInventoryEntry>> {
        Ok(self.runtime().await?.inventory().await?)
    }

    pub(crate) async fn inspect_inventory(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::MachineInventoryEntry> {
        Ok(self
            .runtime()
            .await?
            .inspect_inventory(&MachineRef::parse(reference)?)
            .await?)
    }

    pub(crate) async fn inspect_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        Ok(self.machine(reference).await?.inspect().await?)
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
                .await?);
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

    pub(crate) async fn list_networks(&mut self) -> eyre::Result<Vec<NetworkDefinition>> {
        Ok(self.runtime().await?.list_network_definitions().await?)
    }

    pub(crate) async fn inspect_network(
        &mut self,
        name: &str,
    ) -> eyre::Result<Option<NetworkDefinition>> {
        Ok(self.runtime().await?.get_network_definition(name).await?)
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

    /// Resolves an `image:` spelling to a typed reference. A bare digest is
    /// resolved by kind; an impossible cross-kind collision is refused by libvm.
    pub(crate) async fn managed_reference(
        &mut self,
        spelling: ManagedSpelling,
    ) -> eyre::Result<libvm::ManagedSourceRef> {
        Ok(match spelling {
            ManagedSpelling::Reference(reference) => reference,
            ManagedSpelling::Digest(digest) => silo_vm_control::images::managed_id_to_ref(
                self.runtime()
                    .await?
                    .images()
                    .resolve_managed_digest(&digest)
                    .await?,
            ),
        })
    }

    pub(crate) async fn resolve_source(
        &mut self,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(ImagePullPolicy, PullPolicy)>,
        options: &SourceOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<SourceResolution> {
        let requested = crate::commands::create::selected_image_reference(positional, template)?;
        let spelling = parse_source(&requested)?;
        validate_source_options(&spelling, options, pull.is_some())?;
        let is_positional = positional.is_some();
        match spelling {
            SourceSpelling::Managed(spelling) => {
                let reference = self.managed_reference(spelling).await?;
                let info = self.inspect_managed(&reference).await?;
                Ok(managed_resolution(requested, &info, is_positional))
            }
            SourceSpelling::Disk(path) => Ok(disk_resolution(path, options, is_positional)?),
            SourceSpelling::Oci(reference) => {
                let runtime = self.runtime().await?.clone().with_image_progress(progress);
                let (runtime_pull, plan_pull) =
                    pull.unwrap_or((ImagePullPolicy::IfMissing, PullPolicy::IfMissing));
                let resolved = runtime
                    .images()
                    .resolve_with(
                        reference.clone(),
                        ImageResolveOptions {
                            policy: Some(runtime_pull),
                            platform: options.platform.clone(),
                        },
                    )
                    .await?;
                let plan_image = oci_plan_image(reference, &resolved, plan_pull);
                Ok(SourceResolution {
                    plan_image,
                    is_positional,
                    source: ResolvedSource::LocalResolvedOci(resolved),
                })
            }
        }
    }

    pub(crate) async fn resolve_read_only_creation(
        config: RuntimeConfig,
        requested_name: Option<String>,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(ImagePullPolicy, PullPolicy)>,
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
            SourceSpelling::Managed(spelling) => {
                let reference = match spelling {
                    ManagedSpelling::Reference(reference) => reference,
                    ManagedSpelling::Digest(digest) => silo_vm_control::images::managed_id_to_ref(
                        runtime.resolve_managed_digest(&digest).await?,
                    ),
                };
                let info = runtime.inspect_managed(&reference).await?;
                managed_resolution(requested, &info, is_positional).plan_image
            }
            SourceSpelling::Disk(path) => {
                runtime.validate_disk_source(&path)?;
                disk_resolution(path, options, is_positional)?.plan_image
            }
            SourceSpelling::Oci(reference) => {
                let (runtime_pull, plan_pull) =
                    pull.unwrap_or((ImagePullPolicy::IfMissing, PullPolicy::IfMissing));
                let resolved = runtime
                    .resolve_oci_image(reference.clone(), runtime_pull, options.platform.as_ref())
                    .await?;
                oci_plan_image(reference, &resolved, plan_pull)
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
        let reference = MachineRef::parse(name)?;
        match self.runtime().await?.get_machine(&reference).await {
            Ok(_) => eyre::bail!("machine {name:?} already exists"),
            Err(libvm::LibVmError::MachineNotFound { .. }) => Ok(()),
            Err(error) => Err(error.into()),
        }
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
            ResolvedSource::Managed(reference) => {
                builder.image_source(ImageSource::Managed(reference))
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

    pub(crate) async fn acquire_artifact(
        &mut self,
        request: libvm::ArtifactAcquireRequest,
    ) -> eyre::Result<libvm::ArtifactAcquireReport> {
        silo_vm_control::artifacts::acquire_to_wire(&request)?;
        Ok(self
            .runtime()
            .await?
            .images()
            .acquire_artifact(request)
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
    ) -> eyre::Result<libvm::ManagedImageInfo> {
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
        pull: ImagePullPolicy,
        platform: Option<libvm::LinuxPlatform>,
        options: libvm::RawConversionOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::ManagedImageInfo> {
        if let Some(alias) = &options.alias {
            silo_vm_control::stopped::alias(alias)?;
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

    pub(crate) async fn inspect_managed(
        &mut self,
        reference: &libvm::ManagedSourceRef,
    ) -> eyre::Result<libvm::ManagedSourceInfo> {
        Ok(self
            .runtime()
            .await?
            .images()
            .inspect_managed(reference)
            .await?)
    }

    pub(crate) async fn list_managed(&mut self) -> eyre::Result<Vec<libvm::ManagedSourceInfo>> {
        Ok(self.runtime().await?.images().list_managed().await?)
    }

    pub(crate) async fn release_image(
        &mut self,
        reference: &libvm::ManagedSourceRef,
    ) -> eyre::Result<()> {
        self.runtime()
            .await?
            .images()
            .release_retention(reference)
            .await?;
        Ok(())
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

/// Binds a managed spelling to the typed identity observed now, so a later
/// alias move cannot change what the planned creation materializes.
pub(crate) fn managed_resolution(
    requested_reference: String,
    info: &libvm::ManagedSourceInfo,
    is_positional: bool,
) -> SourceResolution {
    let (source, metadata) = match info {
        libvm::ManagedSourceInfo::Image(image) => (
            libvm::ManagedSourceId::Image(image.id),
            Some(Box::new(planning::managed_image_metadata(
                &image.record.process,
            ))),
        ),
        libvm::ManagedSourceInfo::Snapshot(snapshot) => {
            (libvm::ManagedSourceId::Snapshot(snapshot.id), None)
        }
    };
    SourceResolution {
        plan_image: ResolvedImage::Managed {
            requested_reference,
            source,
            metadata,
        },
        is_positional,
        source: ResolvedSource::Managed(silo_vm_control::images::managed_id_to_ref(source)),
    }
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

fn oci_plan_image(
    requested_reference: String,
    resolved: &libvm::ResolvedOciImage,
    pull_policy: PullPolicy,
) -> ResolvedImage {
    ResolvedImage::Oci {
        identity: planning::OciImageIdentity {
            requested_reference,
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
                            && matches!(
                                (image.pull_policy, plan.pull_policy),
                                (ImagePullPolicy::IfMissing, PullPolicy::IfMissing)
                                    | (ImagePullPolicy::Always, PullPolicy::Always)
                                    | (ImagePullPolicy::Never, PullPolicy::Never)
                            )
                    }
                    ResolvedSource::Disk(_) | ResolvedSource::Managed(_) => false,
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
                && request.alias.is_none()
                && path.is_absolute()
        }
        (
            planning::ImageIdentity::Managed {
                requested_reference,
                source: plan,
            },
            ResolvedImage::Managed {
                requested_reference: resolved_reference,
                source: resolved,
                ..
            },
            ResolvedSource::Managed(reference),
        ) => {
            requested_reference == resolved_reference
                && plan == resolved
                && *reference == silo_vm_control::images::managed_id_to_ref(*plan)
        }
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
                pull_policy: libvm::ImagePullPolicy::Never,
            }),
        };
        ensure_source_matches_plan(&plan, &source).expect("cache warming is not a conflict");
        let ResolvedSource::DaemonOciIdentity(image) = &mut source.source else {
            unreachable!()
        };
        image.pull_policy = libvm::ImagePullPolicy::Always;
        assert!(ensure_source_matches_plan(&plan, &source).is_err());
        let ResolvedSource::DaemonOciIdentity(image) = &mut source.source else {
            unreachable!()
        };
        image.pull_policy = libvm::ImagePullPolicy::Never;
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
    fn disk_and_managed_sources_must_match_the_planned_typed_identity() {
        let path = std::path::PathBuf::from("/images/root.raw");
        let request = libvm::DiskImportRequest {
            path: path.clone(),
            boot: disk_boot(),
            alias: None,
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
        let mut aliased = request;
        aliased.alias = Some("published".into());
        assert!(ensure_source_matches_plan(&plan_disk, &disk(aliased)).is_err());

        let image: libvm::storage::identity::ImageId =
            format!("sha256:{}", "cd".repeat(32)).parse().unwrap();
        let snapshot: libvm::storage::identity::SnapshotId =
            format!("sha256:{}", "cd".repeat(32)).parse().unwrap();
        let plan_managed = plan(ImageIdentity::Managed {
            requested_reference: "image:base".into(),
            source: libvm::ManagedSourceId::Image(image),
        });
        let managed =
            |source: libvm::ManagedSourceId, reference: libvm::ManagedSourceRef| SourceResolution {
                plan_image: ResolvedImage::Managed {
                    requested_reference: "image:base".into(),
                    source,
                    metadata: None,
                },
                is_positional: true,
                source: ResolvedSource::Managed(reference),
            };
        ensure_source_matches_plan(
            &plan_managed,
            &managed(
                libvm::ManagedSourceId::Image(image),
                libvm::ManagedSourceRef::Image(image),
            ),
        )
        .expect("same managed image");
        // Same digest, other kind: never interchangeable.
        assert!(ensure_source_matches_plan(
            &plan_managed,
            &managed(
                libvm::ManagedSourceId::Snapshot(snapshot),
                libvm::ManagedSourceRef::Snapshot(snapshot),
            ),
        )
        .is_err());
        // A movable alias is never the creation source.
        assert!(ensure_source_matches_plan(
            &plan_managed,
            &managed(
                libvm::ManagedSourceId::Image(image),
                libvm::ManagedSourceRef::Alias("base".into()),
            ),
        )
        .is_err());
        assert!(ensure_source_matches_plan(
            &plan_disk,
            &managed(
                libvm::ManagedSourceId::Image(image),
                libvm::ManagedSourceRef::Image(image),
            )
        )
        .is_err());
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
            ExternalResourceKey, ExternalResourceMapping, ExternalResourcePolicy, ForkOptions,
            RestoreOptions, RuntimeConfig, SnapshotOptions,
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
                .restore_snapshot(
                    "image:absent".parse().unwrap(),
                    RestoreOptions {
                        name: Some(name.into()),
                        external_resources: ExternalResourcePolicy::Reject,
                        activation_hook: None,
                        resources: Default::default(),
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
            assert!(!home.exists());
            assert!(!run.exists());
        }
        for name in ["invalid alias", "sha256:invalid", "", &"a".repeat(129)] {
            let error = service
                .snapshot_stopped(
                    "absent",
                    SnapshotOptions {
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
            assert!(!home.exists());
            assert!(!run.exists());
        }
        let error = service
            .snapshot_stopped(
                "absent",
                SnapshotOptions {
                    name: None,
                    external_resources: ExternalResourcePolicy::Map {
                        mappings: vec![ExternalResourceMapping {
                            resource: ExternalResourceKey::Disk { order: 1 },
                            path: "/must/not/open.raw".into(),
                        }],
                    },
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
}
