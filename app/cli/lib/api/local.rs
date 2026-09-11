use eyre::Context as _;
use std::time::Duration;

use libvm::{
    ImageProgressSender, ImagePullPolicy, ImageResolveOptions, ImageSource, MachineAgent,
    MachineBuilder, MachineData, MachineKillOptions, MachineReadinessOutcome, MachineRef,
    MachineRetention, MachineStartOptions, MachineStopOptions, MachineUpdate, Memory,
    NetworkDefinition, NetworkDriver, NetworkTopology, ReadOnlyRuntime, Runtime, RuntimeConfig,
};

use crate::api::types::{ReadOnlyCreationResolution, SourceResolution};
use crate::machine_defaults::{
    disk_size_bytes, memory_mib, resolve_machine_mounts, ResolvedMachineNetwork,
};
use crate::planning::{self, CreatePlan, ImageCacheState, PullPolicy, ResolvedImage};
use crate::template::Template;

#[derive(Debug)]
pub(crate) struct LocalVmService {
    config: Option<RuntimeConfig>,
    runtime: Option<Runtime>,
}

impl LocalVmService {
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        Self {
            config: Some(config),
            runtime: None,
        }
    }

    pub(crate) async fn runtime(&mut self) -> eyre::Result<&Runtime> {
        if self.runtime.is_none() {
            let config = self
                .config
                .take()
                .ok_or_else(|| eyre::eyre!("local runtime configuration was not initialized"))?;
            self.runtime = Some(
                Runtime::new(config)
                    .await
                    .context("initialize local libvm adapter")?,
            );
        }

        self.runtime
            .as_ref()
            .ok_or_else(|| eyre::eyre!("local runtime was not initialized"))
    }

    pub(crate) async fn list_machines(&mut self) -> eyre::Result<Vec<MachineData>> {
        let machines = self.runtime().await?.list_machines().await?;
        let mut data = Vec::with_capacity(machines.len());
        for machine in machines {
            data.push(machine.inspect().await?);
        }
        Ok(data)
    }

    pub(crate) async fn inspect_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        Ok(self.machine(reference).await?.inspect().await?)
    }

    pub(crate) async fn start_machine(
        &mut self,
        reference: &str,
        readiness_timeout: Duration,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let before = machine.inspect().await?;
        crate::commands::start::ensure_startable(&before)?;
        let options = self.start_options(&machine, true).await?;
        let start = machine.start_with_options(options).await?;
        if crate::commands::start::requires_guest_readiness(&start.machine) {
            let readiness = machine.wait_ready(readiness_timeout).await?;
            if readiness.outcome != MachineReadinessOutcome::Ready {
                eyre::bail!("guest readiness check ended with {:?}", readiness.outcome);
            }
        }
        Ok(start.machine)
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
            return Ok(data);
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

    pub(crate) async fn remove_machine(
        &mut self,
        reference: &str,
        force: bool,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let data = machine.inspect().await?;
        if force && data.is_running() {
            match machine.stop().await {
                Ok(_) | Err(libvm::LibVmError::MachineNotRunning { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        machine.remove().await?;
        Ok(data)
    }

    pub(crate) async fn update_machine(
        &mut self,
        reference: &str,
        update: MachineUpdate,
    ) -> eyre::Result<MachineData> {
        self.machine(reference)
            .await?
            .update(update)
            .await
            .map_err(Into::into)
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
        Ok(self
            .machine(reference)
            .await?
            .set_network(|builder| network.apply(builder))
            .await?)
    }

    async fn machine(&mut self, reference: &str) -> eyre::Result<libvm::Machine> {
        let reference = MachineRef::parse(reference)?;
        Ok(self.runtime().await?.get_machine(&reference).await?)
    }

    async fn start_options(
        &mut self,
        machine: &libvm::Machine,
        detached_cleanup: bool,
    ) -> eyre::Result<MachineStartOptions> {
        let data = machine
            .inspect()
            .await
            .context("inspect machine network policy")?;
        let mut options = MachineStartOptions::new();
        if detached_cleanup && data.retention == MachineRetention::Ephemeral {
            let executable = std::env::current_exe().context("resolve CLI binary path")?;
            options = crate::commands::start_options::cleanup_on_exit_options(
                executable,
                self.runtime().await?.local_data_dir(),
                &machine.id(),
            );
        }
        if let Some(policy) = data.network.policy() {
            options = options.credentials(
                crate::commands::secret::egress_credentials_from_secret_store(policy)?,
            );
        }
        Ok(options)
    }

    pub(crate) async fn resolve_source(
        &mut self,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(ImagePullPolicy, PullPolicy)>,
        progress: ImageProgressSender,
    ) -> eyre::Result<SourceResolution> {
        let runtime = self.runtime().await?.clone().with_image_progress(progress);
        let reference = crate::commands::create::selected_image_reference(positional, template)?;
        if let Some(path) = reference.strip_prefix("disk:") {
            if pull.is_some() {
                eyre::bail!("--pull is only supported for OCI image sources");
            }
            let path = crate::commands::create::canonical_disk_source(&reference, path)?;
            return Ok(SourceResolution {
                plan_image: ResolvedImage::Disk { path: path.clone() },
                is_positional: positional.is_some(),
                resolved_oci: None,
                disk: Some(path),
            });
        }
        let (runtime_pull, plan_pull) =
            pull.unwrap_or((ImagePullPolicy::IfMissing, PullPolicy::IfMissing));
        let resolved = runtime
            .images()
            .resolve_with(
                reference.clone(),
                ImageResolveOptions {
                    policy: Some(runtime_pull),
                },
            )
            .await?;
        let plan_image = ResolvedImage::Oci {
            identity: planning::OciImageIdentity {
                requested_reference: reference,
                selected_reference: resolved.selected_reference.clone(),
                platform: resolved.platform.clone(),
                manifest_digest: resolved.manifest_digest.clone(),
                config_digest: resolved.config_digest.clone(),
                cache_state: image_cache_state(resolved.cache_state),
                pull_policy: plan_pull,
            },
            metadata: Box::new(resolved.config.clone()),
        };
        Ok(SourceResolution {
            plan_image,
            is_positional: positional.is_some(),
            resolved_oci: Some(resolved),
            disk: None,
        })
    }

    pub(crate) async fn resolve_read_only_creation(
        config: RuntimeConfig,
        requested_name: Option<String>,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(ImagePullPolicy, PullPolicy)>,
    ) -> eyre::Result<ReadOnlyCreationResolution> {
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
        let reference = crate::commands::create::selected_image_reference(positional, template)?;
        let source = if let Some(path) = reference.strip_prefix("disk:") {
            if pull.is_some() {
                eyre::bail!("--pull is only supported for OCI image sources");
            }
            let path = crate::commands::create::canonical_disk_source(&reference, path)?;
            let path = runtime.validate_disk_source(&path)?;
            SourceResolution {
                plan_image: ResolvedImage::Disk { path: path.clone() },
                is_positional: positional.is_some(),
                resolved_oci: None,
                disk: Some(path),
            }
        } else {
            let (runtime_pull, plan_pull) =
                pull.unwrap_or((ImagePullPolicy::IfMissing, PullPolicy::IfMissing));
            let resolved = runtime
                .resolve_oci_image(reference.clone(), runtime_pull)
                .await?;
            SourceResolution {
                plan_image: ResolvedImage::Oci {
                    identity: planning::OciImageIdentity {
                        requested_reference: reference,
                        selected_reference: resolved.selected_reference.clone(),
                        platform: resolved.platform,
                        manifest_digest: resolved.manifest_digest,
                        config_digest: resolved.config_digest,
                        cache_state: image_cache_state(resolved.cache_state),
                        pull_policy: plan_pull,
                    },
                    metadata: Box::new(resolved.config),
                },
                is_positional: positional.is_some(),
                resolved_oci: None,
                disk: None,
            }
        };
        Ok(ReadOnlyCreationResolution { name, source })
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
    ) -> eyre::Result<MachineData> {
        ensure_source_matches_plan(plan, &source)?;
        let mut builder = self.runtime().await?.machine();
        if let Some(name) = &plan.proposed_name {
            builder = builder.name(name);
        }
        builder = match source.resolved_oci {
            Some(image) => builder.resolved_image(image),
            None => builder.image_source(ImageSource::disk(
                source
                    .disk
                    .ok_or_else(|| eyre::eyre!("machine source was not resolved"))?,
            )),
        };
        let machine = apply_plan(builder, plan, policy_config_dir)?
            .create()
            .await?;
        Ok(machine.inspect().await?)
    }
}

fn apply_plan(
    mut builder: MachineBuilder,
    plan: &CreatePlan,
    policy_config_dir: Option<&std::path::Path>,
) -> eyre::Result<MachineBuilder> {
    builder = builder
        .labels(plan.machine.labels.clone())
        .process(plan.process.clone())
        .retention(plan.retention)
        .template_name(plan.template.name.clone())
        .kernel_args(plan.machine_settings.kernel_args.clone())
        .nested_virtualization(plan.machine_settings.nested_virtualization)
        .rosetta(plan.machine_settings.rosetta)
        .disks(plan.machine_settings.disks.clone())
        .mounts(resolve_machine_mounts(&plan.machine.mounts)?)
        .forwards(plan.machine.forwards.clone());
    if let Some(vsock) = plan.machine.vsock {
        builder = builder.vsock(vsock);
    }
    if let Some(resources) = &plan.machine.resources {
        if let Some(cpus) = resources.cpus {
            builder = builder.cpus(cpus);
        }
        if let Some(memory) = memory_mib(Some(resources))? {
            builder = builder.memory(Memory::mebibytes(u64::from(memory)));
        }
    }
    if let Some(bytes) = disk_size_bytes(plan.machine.disk_size.as_deref())? {
        builder = builder.root_disk_size(bytes);
    }
    if let Some(userdata) = &plan.machine.userdata {
        builder = builder.userdata(userdata);
    }
    if let Some(network) = plan.machine.network.clone() {
        let network = network.resolve_machine_network(policy_config_dir)?;
        builder = builder.network(|network_builder| network.apply(network_builder));
    }
    if let Some(kernel) = &plan.machine_settings.kernel {
        builder = builder.kernel(kernel);
    }
    if let Some(initramfs) = &plan.machine_settings.initramfs {
        builder = builder.initramfs(initramfs);
    }
    let agent = plan.machine_settings.agent.clone();
    let user = plan.machine_settings.provision_user.clone();
    builder = builder.guest(|guest| {
        let guest = match agent.clone() {
            MachineAgent::Default => guest,
            MachineAgent::Custom { path } => guest.agent(Some(path)),
            MachineAgent::Disabled => guest.agent(None),
            _ => guest,
        };
        match user {
            Some(user) => guest.user(user),
            None => guest,
        }
    });
    Ok(builder.agent_mode(Some(agent)))
}

fn ensure_source_matches_plan(plan: &CreatePlan, source: &SourceResolution) -> eyre::Result<()> {
    let matches = match (&plan.image, &source.plan_image) {
        (planning::ImageIdentity::Oci(plan), ResolvedImage::Oci { identity, .. }) => {
            plan == identity
                && source.resolved_oci.as_ref().is_some_and(|image| {
                    image.selected_reference == plan.selected_reference
                        && image.platform == plan.platform
                        && image.manifest_digest == plan.manifest_digest
                        && image.config_digest == plan.config_digest
                        && image_cache_state(image.cache_state) == plan.cache_state
                })
        }
        (planning::ImageIdentity::Disk { path: plan }, ResolvedImage::Disk { path }) => {
            plan == path && source.resolved_oci.is_none() && source.disk.as_ref() == Some(path)
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        eyre::bail!("resolved image no longer matches the planned immutable identity")
    }
}

fn image_cache_state(state: libvm::ImageCacheState) -> ImageCacheState {
    match state {
        libvm::ImageCacheState::Complete => ImageCacheState::Complete,
        libvm::ImageCacheState::Missing => ImageCacheState::Missing,
    }
}
