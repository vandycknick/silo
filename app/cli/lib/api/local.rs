use eyre::Context as _;
use std::time::Duration;

use libvm::{
    ImageProgressSender, ImagePullPolicy, ImageResolveOptions, ImageSource, MachineData,
    MachineExitOutcome, MachineKillOptions, MachineRef, MachineRetention, MachineRunId,
    MachineStatus, MachineStopOptions, MachineUpdate, MachineWaitOptions, Memory,
    NetworkDefinition, NetworkDriver, NetworkTopology, ReadOnlyRuntime, Runtime, RuntimeConfig,
};
use silo_vm_control::create::{NormalizedMachineCreate, ResolvedNetwork};

use crate::api::machine::AppMachine;
use crate::api::types::{
    ReadOnlyCreationResolution, ReadOnlySourceResolution, ResolvedSource, SourceResolution,
};
use crate::machine_defaults::{
    disk_size_bytes, memory_mib, resolve_machine_mounts, ResolvedMachineNetwork,
};
use crate::planning::{self, CreatePlan, ImageCacheState, PullPolicy, ResolvedImage};
use crate::template::Template;

#[derive(Debug)]
pub(crate) enum LocalVmService {
    Uninitialized(Option<RuntimeConfig>),
    Ready(Runtime),
}

impl LocalVmService {
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        Self::Uninitialized(Some(config))
    }

    pub(crate) async fn runtime(&mut self) -> eyre::Result<&Runtime> {
        if let Self::Uninitialized(config) = self {
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
            Self::Uninitialized(_) => Err(eyre::eyre!("local runtime was not initialized")),
        }
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
                        && matches!(
                            exit.machine.status,
                            MachineStatus::Starting { .. }
                                | MachineStatus::Running { .. }
                                | MachineStatus::Stopping { .. }
                        ) => {}
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
                source: ResolvedSource::Disk(path),
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
            source: ResolvedSource::LocalResolvedOci(resolved),
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
            ReadOnlySourceResolution {
                plan_image: ResolvedImage::Disk { path: path.clone() },
                is_positional: positional.is_some(),
            }
        } else {
            let (runtime_pull, plan_pull) =
                pull.unwrap_or((ImagePullPolicy::IfMissing, PullPolicy::IfMissing));
            let resolved = runtime
                .resolve_oci_image(reference.clone(), runtime_pull)
                .await?;
            ReadOnlySourceResolution {
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
        progress: ImageProgressSender,
    ) -> eyre::Result<MachineData> {
        ensure_source_matches_plan(plan, &source)?;
        let runtime = self.runtime().await?.clone().with_image_progress(progress);
        let mut builder = runtime.machine();
        // Source materialization remains native; normalization never selects an image.
        builder = match source.source {
            ResolvedSource::LocalResolvedOci(image) => builder.resolved_image(image),
            ResolvedSource::Disk(path) => builder.image_source(ImageSource::disk(path)),
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
                    ResolvedSource::Disk(_) => false,
                }
        }
        (
            planning::ImageIdentity::Disk { path: plan },
            ResolvedImage::Disk { path },
            ResolvedSource::Disk(resolved),
        ) => plan == path && resolved == path && path.is_absolute(),
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
                rosetta: false,
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

    #[test]
    fn normalization_canonicalizes_host_files_and_uncreated_socket_paths() {
        let temp = tempfile::tempdir_in(".").expect("relative temp directory");
        let file = temp.path().join("asset");
        std::fs::write(&file, b"asset").expect("host asset");
        let canonical = std::fs::canonicalize(&file).expect("canonical asset");
        let mut plan = plan(ImageIdentity::Disk {
            path: canonical.clone(),
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
}
