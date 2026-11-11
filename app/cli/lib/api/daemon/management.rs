use std::path::Path;
use std::time::Duration;

use libvm::{
    ImageProgressSender, ImagePullPolicy, LibVmError, MachineData, MachineExit,
    MachineInventoryEntry, MachineKillOptions, MachineReadiness, MachineRunId, MachineStart,
    MachineStopOptions, MachineUpdate, MachineWaitOptions, NetworkDefinition, NetworkDriver,
    NetworkTopology,
};
use silo_vm_control::requests::{self, CreateSource};
use silo_vm_control::{
    duration_to_wire, images, lifecycle, network, readiness, snapshots, updates,
};
use silod_spec::daemon::v1 as w;

use crate::api::daemon::{invalid_response, native_status, DaemonVmService};
use crate::api::machine::AppMachine;
use crate::api::start_options::AppStartOptions;
use crate::api::types::{ResolvedSource, SourceOptions, SourceResolution};
use crate::commands::create::{parse_source, validate_source_options, SourceSpelling};
use crate::machine_defaults::ResolvedMachineNetwork;
use crate::planning::{self, CreatePlan, PullPolicy, ResolvedImage};
use crate::template::Template;

fn reference(value: &str) -> Result<w::MachineRef, LibVmError> {
    lifecycle::reference_to_wire(&libvm::MachineRef::parse(value)?).map_err(invalid_response)
}
fn run_ref(id: &str, run: MachineRunId) -> Result<w::MachineRunRef, LibVmError> {
    silo_vm_control::validate_uuid(id, "machine.id").map_err(invalid_response)?;
    Ok(w::MachineRunRef {
        id: id.into(),
        run_id: run.to_string(),
    })
}

impl DaemonVmService {
    pub(crate) async fn live_capabilities(&self) -> eyre::Result<vm_spec::live::LiveHostReport> {
        Ok(silo_vm_control::live::host_from_wire(
            self.daemon
                .clone()
                .get_live_capabilities(())
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn appliance_live_capabilities(
        &self,
    ) -> eyre::Result<Option<vm_spec::live::LiveHostReport>> {
        let status = self
            .daemon
            .clone()
            .get_status(())
            .await
            .map_err(native_status)?
            .into_inner();
        silo_vm_control::live::validate_daemon_status(&status)?;
        Ok(status
            .appliance_live
            .map(silo_vm_control::live::host_from_wire)
            .transpose()?)
    }

    pub(crate) async fn export_raw_disk(
        &self,
        value: &str,
        options: libvm::RawDiskExportOptions,
    ) -> eyre::Result<libvm::RawDiskExport> {
        let request = silo_vm_control::stopped::raw_export_request_to_wire(
            &libvm::MachineRef::parse(value)?,
            &options,
        )?;
        let result = silo_vm_control::stopped::raw_export_from_wire(
            self.machines
                .clone()
                .export_raw_disk(request)
                .await
                .map_err(native_status)?
                .into_inner(),
        )?;
        eyre::ensure!(
            result.path == options.destination,
            "daemon export destination mismatch"
        );
        eyre::ensure!(
            !matches!(
                result.kind,
                libvm::RawDiskExportKind::FlattenedFilesystem { .. }
            ) || options.flatten_filesystem,
            "daemon flattened storage without explicit permission"
        );
        Ok(result)
    }

    pub(crate) async fn pause_machine(&self, value: &str) -> eyre::Result<MachineData> {
        Ok(snapshots::snapshot_from_wire(
            self.machines
                .clone()
                .pause_machine(w::LiveMachineRequest {
                    machine: Some(reference(value)?),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn resume_machine(&self, value: &str) -> eyre::Result<MachineData> {
        Ok(snapshots::snapshot_from_wire(
            self.machines
                .clone()
                .resume_machine(w::LiveMachineRequest {
                    machine: Some(reference(value)?),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn snapshot_live(
        &self,
        value: &str,
        options: libvm::LiveSnapshotOptions,
    ) -> eyre::Result<libvm::LiveSnapshot> {
        options.validate()?;
        Ok(silo_vm_control::capture::live_snapshot_from_wire(
            self.machines
                .clone()
                .capture_execution(w::LiveCaptureRequest {
                    machine: Some(reference(value)?),
                    name: options.name,
                    resume_policy: silo_vm_control::capture::resume_policy_to_wire(
                        options.resume_policy,
                    ),
                    policy: silo_vm_control::capture::policy_to_wire(options.policy),
                    dirty_crossover_percent: u32::from(options.dirty_crossover_percent),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    /// The daemon owns the operation once submitted: a lost reply or client
    /// disconnect is not cancellation.
    pub(crate) async fn fork_live(
        &self,
        value: &str,
        options: libvm::LiveForkOptions,
    ) -> eyre::Result<libvm::LiveForkResult> {
        let request =
            silo_vm_control::fork::request_to_wire(&libvm::MachineRef::parse(value)?, &options)?;
        Ok(silo_vm_control::fork::result_from_wire(
            self.machines
                .clone()
                .fork_execution(request)
                .await
                .map_err(
                    |status| match silo_vm_control::errors::status_to_native_error(&status) {
                        Ok(error) => eyre::Report::new(error),
                        Err(_) => eyre::Report::new(status),
                    },
                )?
                .into_inner(),
        )?)
    }

    pub(crate) async fn inspect_fork(
        &self,
        operation_id: uuid::Uuid,
    ) -> eyre::Result<libvm::LiveForkResult> {
        Ok(silo_vm_control::fork::result_from_wire(
            self.runtime
                .clone()
                .get_fork(silo_vm_control::fork::operation_to_wire(operation_id)?)
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn cancel_fork(
        &self,
        operation_id: uuid::Uuid,
    ) -> eyre::Result<libvm::LiveForkResult> {
        Ok(silo_vm_control::fork::result_from_wire(
            self.runtime
                .clone()
                .cancel_fork(silo_vm_control::fork::operation_to_wire(operation_id)?)
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn fork_stopped(
        &self,
        value: &str,
        options: libvm::ForkOptions,
    ) -> eyre::Result<MachineData> {
        Ok(snapshots::snapshot_from_wire(
            self.machines
                .clone()
                .fork_stopped(w::StoppedForkRequest {
                    machine: Some(reference(value)?),
                    name: options.name,
                    external_resources: Some(silo_vm_control::stopped::policy_to_wire(
                        &options.external_resources,
                    )),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn snapshot_stopped(
        &self,
        value: &str,
        options: libvm::SnapshotOptions,
    ) -> eyre::Result<libvm::SnapshotInfo> {
        Ok(silo_vm_control::stopped::info_from_wire(
            self.machines
                .clone()
                .snapshot_stopped(w::CreateStorageSnapshotRequest {
                    machine: Some(reference(value)?),
                    name: options.name,
                    external_resources: Some(silo_vm_control::stopped::policy_to_wire(
                        &options.external_resources,
                    )),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn restore_snapshot(
        &self,
        reference: libvm::SnapshotRef,
        options: libvm::RestoreOptions,
    ) -> eyre::Result<MachineData> {
        Ok(snapshots::snapshot_from_wire(
            self.runtime
                .clone()
                .restore_snapshot(w::RestoreStorageSnapshotRequest {
                    snapshot: Some(silo_vm_control::stopped::reference_to_wire(&reference)),
                    name: options.name,
                    external_resources: Some(silo_vm_control::stopped::policy_to_wire(
                        &options.external_resources,
                    )),
                    activation_hook: options
                        .activation_hook
                        .as_ref()
                        .map(silo_vm_control::stopped::hook_to_wire)
                        .transpose()?,
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn recover_checkpoint_disks(
        &self,
        reference: libvm::SnapshotRef,
        options: libvm::RecoverDisksOptions,
    ) -> eyre::Result<MachineData> {
        Ok(snapshots::snapshot_from_wire(
            self.runtime
                .clone()
                .recover_checkpoint_disks(w::RecoverCheckpointDisksRequest {
                    snapshot: Some(silo_vm_control::stopped::reference_to_wire(&reference)),
                    name: options.name,
                    external_resources: Some(silo_vm_control::stopped::policy_to_wire(
                        &options.external_resources,
                    )),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn inspect_snapshot(
        &self,
        reference: libvm::SnapshotRef,
    ) -> eyre::Result<libvm::SnapshotInfo> {
        Ok(silo_vm_control::stopped::info_from_wire(
            self.runtime
                .clone()
                .inspect_storage_snapshot(silo_vm_control::stopped::reference_to_wire(&reference))
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn list_snapshots(&self) -> eyre::Result<Vec<libvm::SnapshotInfo>> {
        self.runtime
            .clone()
            .list_storage_snapshots(())
            .await
            .map_err(native_status)?
            .into_inner()
            .snapshots
            .into_iter()
            .map(|value| silo_vm_control::stopped::info_from_wire(value).map_err(Into::into))
            .collect()
    }

    pub(crate) async fn release_snapshot(&self, reference: libvm::SnapshotRef) -> eyre::Result<()> {
        self.runtime
            .clone()
            .release_snapshot_retention(silo_vm_control::stopped::reference_to_wire(&reference))
            .await
            .map_err(native_status)?;
        Ok(())
    }

    pub(crate) async fn remove_image_alias(&self, alias: String) -> eyre::Result<()> {
        self.runtime
            .clone()
            .remove_image_alias(w::Name { name: alias })
            .await
            .map_err(native_status)?;
        Ok(())
    }
    pub(crate) async fn list_machines(&self) -> eyre::Result<Vec<MachineInventoryEntry>> {
        let mut stream = self
            .machines
            .clone()
            .list_machines(())
            .await
            .map_err(native_status)?
            .into_inner();
        let mut entries = Vec::new();
        while let Some(entry) = stream.message().await.map_err(native_status)? {
            entries.push(snapshots::inventory_from_wire(entry)?);
        }
        Ok(entries)
    }
    pub(crate) async fn inspect_inventory(
        &self,
        value: &str,
    ) -> eyre::Result<MachineInventoryEntry> {
        Ok(snapshots::inventory_from_wire(
            self.machines
                .clone()
                .inspect_inventory(reference(value)?)
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }
    pub(crate) async fn inspect_machine(&self, value: &str) -> eyre::Result<MachineData> {
        Ok(self.inspect(value).await?)
    }
    pub(crate) async fn inspect(&self, value: &str) -> Result<MachineData, LibVmError> {
        snapshots::snapshot_from_wire(
            self.machines
                .clone()
                .inspect_machine(reference(value)?)
                .await
                .map_err(native_status)?
                .into_inner(),
        )
        .map_err(invalid_response)
    }
    pub(crate) async fn machine_handle(&self, value: &str) -> eyre::Result<AppMachine> {
        let data = self.inspect(value).await?;
        Ok(AppMachine::daemon(data.id, self.clone()))
    }
    pub(crate) async fn start_with_options(
        &self,
        id: &str,
        options: AppStartOptions,
    ) -> Result<MachineStart, LibVmError> {
        let options = lifecycle::StartOptions {
            cleanup_on_exit: options.cleanup_on_exit,
            credentials: options.egress_credentials,
            entrypoint: options.entrypoint,
        };
        let value = self
            .machines
            .clone()
            .start_machine(w::StartMachineRequest {
                machine: Some(reference(id)?),
                options: Some(lifecycle::start_options_to_wire(&options)),
            })
            .await
            .map_err(native_status)?
            .into_inner();
        lifecycle::start_from_wire(value).map_err(invalid_response)
    }
    pub(crate) async fn wait_ready(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<MachineReadiness, LibVmError> {
        silo_vm_control::validate_uuid(id, "machine.id").map_err(invalid_response)?;
        readiness::readiness_from_wire(
            self.machines
                .clone()
                .wait_ready(w::WaitReadyRequest {
                    id: id.into(),
                    expected_run: None,
                    timeout: Some(duration_to_wire(timeout).map_err(invalid_response)?),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )
        .map_err(invalid_response)
    }
    pub(crate) async fn stop_machine(
        &self,
        value: &str,
        force: bool,
        timeout: Duration,
    ) -> eyre::Result<MachineData> {
        Ok(snapshots::snapshot_from_wire(
            self.machines
                .clone()
                .stop_machine(w::StopMachineRequest {
                    machine: Some(reference(value)?),
                    force,
                    timeout: Some(duration_to_wire(timeout)?),
                    expected_run: None,
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }
    pub(crate) async fn stop_run(
        &self,
        id: &str,
        run: MachineRunId,
        options: MachineStopOptions,
    ) -> Result<MachineData, LibVmError> {
        snapshots::snapshot_from_wire(
            self.machines
                .clone()
                .stop_run(w::StopRunRequest {
                    machine: Some(run_ref(id, run)?),
                    timeout: Some(
                        duration_to_wire(options.wait_options().timeout_value())
                            .map_err(invalid_response)?,
                    ),
                    force_after: options
                        .force_timeout()
                        .map(duration_to_wire)
                        .transpose()
                        .map_err(invalid_response)?,
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )
        .map_err(invalid_response)
    }
    pub(crate) async fn kill_run(
        &self,
        id: &str,
        run: MachineRunId,
        options: MachineKillOptions,
    ) -> Result<MachineExit, LibVmError> {
        lifecycle::exit_from_wire(
            self.machines
                .clone()
                .kill_run(w::KillRunRequest {
                    machine: Some(run_ref(id, run)?),
                    timeout: Some(
                        duration_to_wire(options.wait_options().timeout_value())
                            .map_err(invalid_response)?,
                    ),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )
        .map_err(invalid_response)
    }
    pub(crate) async fn wait_for_run_with(
        &self,
        id: &str,
        run: MachineRunId,
        options: MachineWaitOptions,
    ) -> Result<MachineExit, LibVmError> {
        lifecycle::exit_from_wire(
            self.machines
                .clone()
                .wait_for_run(w::WaitForRunRequest {
                    machine: Some(run_ref(id, run)?),
                    timeout: Some(
                        duration_to_wire(options.timeout_value()).map_err(invalid_response)?,
                    ),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )
        .map_err(invalid_response)
    }
    pub(crate) async fn remove(&self, id: &str) -> Result<(), LibVmError> {
        self.machines
            .clone()
            .remove_machine(w::RemoveMachineRequest {
                machine: Some(reference(id)?),
            })
            .await
            .map_err(native_status)?;
        Ok(())
    }
    pub(crate) async fn remove_after_run(
        &self,
        id: &str,
        run: MachineRunId,
    ) -> Result<(), LibVmError> {
        self.machines
            .clone()
            .remove_after_run(run_ref(id, run)?)
            .await
            .map_err(native_status)?;
        Ok(())
    }
    pub(crate) async fn update_machine(
        &self,
        value: &str,
        update: MachineUpdate,
    ) -> eyre::Result<MachineData> {
        Ok(snapshots::snapshot_from_wire(
            self.machines
                .clone()
                .update_machine(w::UpdateMachineRequest {
                    machine: Some(reference(value)?),
                    update: Some(updates::update_to_wire(&update)?),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }
    pub(crate) async fn ensure_name_available(&self, name: &str) -> eyre::Result<()> {
        self.machines
            .clone()
            .ensure_name_available(w::Name { name: name.into() })
            .await
            .map_err(native_status)?;
        Ok(())
    }
    pub(crate) async fn list_networks(&self) -> eyre::Result<Vec<NetworkDefinition>> {
        let mut stream = self
            .networks
            .clone()
            .list_network_definitions(())
            .await
            .map_err(native_status)?
            .into_inner();
        let mut definitions = Vec::new();
        while let Some(value) = stream.message().await.map_err(native_status)? {
            definitions.push(network::definition_from_wire(value)?);
        }
        Ok(definitions)
    }
    pub(crate) async fn inspect_network(
        &self,
        name: &str,
    ) -> eyre::Result<Option<NetworkDefinition>> {
        self.networks
            .clone()
            .get_network_definition(w::Name { name: name.into() })
            .await
            .map_err(native_status)?
            .into_inner()
            .definition
            .map(network::definition_from_wire)
            .transpose()
            .map_err(Into::into)
    }
    pub(crate) async fn create_network(
        &self,
        name: String,
        topology: NetworkTopology,
        driver: NetworkDriver,
    ) -> eyre::Result<()> {
        let definition = NetworkDefinition::new(name, topology).driver(driver);
        self.networks
            .clone()
            .create_network_definition(w::CreateNetworkDefinitionRequest {
                definition: Some(network::definition_to_wire(&definition)?),
            })
            .await
            .map_err(native_status)?;
        Ok(())
    }
    pub(crate) async fn remove_network(&self, name: &str) -> eyre::Result<()> {
        self.networks
            .clone()
            .remove_network_definition(w::Name { name: name.into() })
            .await
            .map_err(native_status)?;
        Ok(())
    }
    pub(crate) async fn set_machine_network(
        &self,
        value: &str,
        selected: ResolvedMachineNetwork,
    ) -> eyre::Result<MachineData> {
        let attachment = match selected {
            ResolvedMachineNetwork::None => w::resolved_network::Attachment::None(()),
            ResolvedMachineNetwork::Named { name } => {
                w::resolved_network::Attachment::Named(w::Name { name })
            }
            ResolvedMachineNetwork::Private { policy, publish } => {
                w::resolved_network::Attachment::Private(w::PrivateNetwork {
                    policy_json: policy
                        .as_ref()
                        .map(silo_vm_control::values::policy_to_wire)
                        .transpose()?,
                    publish: publish.map(silo_vm_control::values::publish_to_wire),
                })
            }
        };
        Ok(snapshots::snapshot_from_wire(
            self.networks
                .clone()
                .set_machine_network(w::SetMachineNetworkRequest {
                    machine: Some(reference(value)?),
                    network: Some(w::ResolvedNetwork {
                        attachment: Some(attachment),
                    }),
                })
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }
    pub(crate) async fn resolve_source(
        &self,
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
        let reference = match spelling {
            SourceSpelling::Managed(spelling) => {
                let reference = self.managed_reference(spelling).await?;
                let info = self.inspect_managed(&reference).await?;
                return Ok(crate::api::local::managed_resolution(
                    requested,
                    &info,
                    is_positional,
                ));
            }
            SourceSpelling::Disk(path) => {
                return crate::api::local::disk_resolution(path, options, is_positional)
            }
            SourceSpelling::Oci(reference) => reference,
        };
        let (policy, plan_policy) =
            pull.unwrap_or((ImagePullPolicy::IfMissing, PullPolicy::IfMissing));
        let image = self
            .resolve_oci(reference, policy, options.platform.as_ref(), &progress)
            .await?;
        let identity = &image.identity;
        let plan_image = ResolvedImage::Oci {
            identity: planning::OciImageIdentity {
                requested_reference: identity.requested_reference.clone(),
                selected_reference: identity.selected_reference.clone(),
                platform: identity.platform.clone(),
                manifest_digest: identity.manifest_digest.clone(),
                config_digest: identity.config_digest.clone(),
                cache_state: match image.cache_state {
                    libvm::ImageCacheState::Complete => planning::ImageCacheState::Complete,
                    libvm::ImageCacheState::Missing => planning::ImageCacheState::Missing,
                },
                pull_policy: plan_policy,
            },
            metadata: Box::new(image.config),
        };
        Ok(SourceResolution {
            plan_image,
            is_positional,
            source: ResolvedSource::DaemonOciIdentity(image.identity),
        })
    }

    async fn resolve_oci(
        &self,
        reference: String,
        policy: ImagePullPolicy,
        platform: Option<&libvm::LinuxPlatform>,
        progress: &ImageProgressSender,
    ) -> eyre::Result<images::ResolvedImage> {
        let mut stream = self
            .runtime
            .clone()
            .resolve_image(images::resolve_request_to_wire(reference, policy, platform))
            .await
            .map_err(native_status)?
            .into_inner();
        let mut terminal = None;
        while let Some(event) = stream.message().await.map_err(native_status)? {
            eyre::ensure!(
                terminal.is_none(),
                "daemon image stream continued after terminal image"
            );
            match event
                .event
                .ok_or_else(|| eyre::eyre!("daemon image stream omitted event"))?
            {
                w::resolve_image_event::Event::Progress(value) => {
                    progress.send(images::progress_from_wire(value)?)
                }
                w::resolve_image_event::Event::Image(value) => {
                    terminal = Some(images::resolved_image_from_wire(value)?)
                }
            }
        }
        let image = terminal
            .ok_or_else(|| eyre::eyre!("daemon image stream ended without resolved image"))?;
        if let Some(platform) = platform {
            eyre::ensure!(
                &silo_vm_control::boot::platform_from_oci(&image.identity.platform)? == platform,
                "daemon selected a platform other than the requested one"
            );
        }
        Ok(image)
    }

    pub(crate) async fn create_machine(
        &self,
        plan: &CreatePlan,
        source: SourceResolution,
        policy_config_dir: Option<&Path>,
        progress: ImageProgressSender,
    ) -> eyre::Result<MachineData> {
        crate::api::local::ensure_source_matches_plan(plan, &source)?;
        let configuration = crate::api::local::normalize_plan(plan, policy_config_dir)?;
        let source = match source.source {
            ResolvedSource::DaemonOciIdentity(identity) => CreateSource::Oci(identity),
            ResolvedSource::Disk(request) => CreateSource::Disk(request),
            ResolvedSource::Managed(reference) => CreateSource::Managed(reference),
            ResolvedSource::LocalResolvedOci(_) => {
                eyre::bail!("local OCI source cannot be created through daemon management")
            }
        };
        let mut stream = self
            .machines
            .clone()
            .create_machine(requests::create_request_to_wire(&configuration, &source)?)
            .await
            .map_err(native_status)?
            .into_inner();
        let mut terminal = None;
        while let Some(event) = stream.message().await.map_err(native_status)? {
            eyre::ensure!(
                terminal.is_none(),
                "daemon create stream continued after terminal machine"
            );
            match event
                .event
                .ok_or_else(|| eyre::eyre!("daemon create stream omitted event"))?
            {
                w::create_machine_event::Event::Progress(value) => {
                    progress.send(images::progress_from_wire(value)?)
                }
                w::create_machine_event::Event::Machine(value) => {
                    terminal = Some(snapshots::snapshot_from_wire(*value)?)
                }
            }
        }
        terminal.ok_or_else(|| {
            eyre::eyre!(
                "daemon create stream ended without terminal machine; inspect state before retrying"
            )
        })
    }

    pub(crate) async fn managed_reference(
        &self,
        spelling: images::ManagedSpelling,
    ) -> eyre::Result<libvm::ManagedSourceRef> {
        Ok(match spelling {
            images::ManagedSpelling::Reference(reference) => reference,
            images::ManagedSpelling::Digest(digest) => {
                images::managed_id_to_ref(images::managed_id_from_wire(
                    self.runtime
                        .clone()
                        .resolve_managed_digest(images::managed_digest_to_wire(&digest))
                        .await
                        .map_err(native_status)?
                        .into_inner(),
                )?)
            }
        })
    }

    pub(crate) async fn inspect_managed(
        &self,
        reference: &libvm::ManagedSourceRef,
    ) -> eyre::Result<libvm::ManagedSourceInfo> {
        let info = images::managed_info_from_wire(
            self.runtime
                .clone()
                .inspect_managed_image(images::managed_ref_to_wire(reference)?)
                .await
                .map_err(native_status)?
                .into_inner(),
        )?;
        let answers = match (reference, &info) {
            (libvm::ManagedSourceRef::Image(id), libvm::ManagedSourceInfo::Image(image)) => {
                image.id == *id
            }
            (
                libvm::ManagedSourceRef::Snapshot(id),
                libvm::ManagedSourceInfo::Snapshot(snapshot),
            ) => snapshot.id == *id,
            (libvm::ManagedSourceRef::Alias(alias), libvm::ManagedSourceInfo::Image(image)) => {
                image.aliases.contains(alias)
            }
            (
                libvm::ManagedSourceRef::Alias(alias),
                libvm::ManagedSourceInfo::Snapshot(snapshot),
            ) => snapshot.aliases.contains(alias),
            _ => false,
        };
        eyre::ensure!(
            answers,
            "daemon inspection does not answer the requested reference"
        );
        Ok(info)
    }

    pub(crate) async fn list_managed(&self) -> eyre::Result<Vec<libvm::ManagedSourceInfo>> {
        Ok(images::managed_list_from_wire(
            self.runtime
                .clone()
                .list_managed_images(())
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }

    pub(crate) async fn release_image(
        &self,
        reference: &libvm::ManagedSourceRef,
    ) -> eyre::Result<()> {
        self.runtime
            .clone()
            .release_image_retention(images::managed_ref_to_wire(reference)?)
            .await
            .map_err(native_status)?;
        Ok(())
    }

    pub(crate) async fn inspect_artifact(
        &self,
        reference: &str,
    ) -> eyre::Result<libvm::ArtifactInspection> {
        silo_vm_control::artifacts::validate_reference(reference)?;
        let result = self
            .runtime
            .clone()
            .inspect_artifact(w::InspectArtifactRequest {
                reference: reference.into(),
            })
            .await
            .map_err(native_status)?
            .into_inner();
        Ok(silo_vm_control::artifacts::inspection_from_wire(result)?)
    }

    pub(crate) async fn acquire_artifact(
        &self,
        request: libvm::ArtifactAcquireRequest,
    ) -> eyre::Result<libvm::ArtifactAcquireReport> {
        let result = self
            .runtime
            .clone()
            .acquire_artifact(silo_vm_control::artifacts::acquire_to_wire(&request)?)
            .await
            .map_err(native_status)?
            .into_inner();
        Ok(silo_vm_control::artifacts::acquired_from_wire(result)?)
    }

    pub(crate) async fn publish_artifact(
        &self,
        request: libvm::ArtifactPublishRequest,
    ) -> eyre::Result<libvm::ArtifactPublishReport> {
        let result = self
            .runtime
            .clone()
            .publish_artifact(silo_vm_control::artifacts::publish_to_wire(&request)?)
            .await
            .map_err(native_status)?
            .into_inner();
        Ok(silo_vm_control::artifacts::published_from_wire(result)?)
    }

    /// The daemon owns the import once submitted; a lost reply is not cancellation.
    pub(crate) async fn import_image(
        &self,
        request: libvm::DiskImportRequest,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::ManagedImageInfo> {
        let stream = self
            .runtime
            .clone()
            .import_image(silo_vm_control::boot::import_request_to_wire(&request)?)
            .await
            .map_err(native_status)?
            .into_inner();
        managed_image_stream(stream, &progress).await
    }

    /// Resolves the mutable spelling once, then converts exactly that selected
    /// immutable manifest/platform identity.
    pub(crate) async fn convert_image(
        &self,
        reference: String,
        pull: ImagePullPolicy,
        platform: Option<libvm::LinuxPlatform>,
        options: libvm::RawConversionOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::ManagedImageInfo> {
        let image = self
            .resolve_oci(reference, pull, platform.as_ref(), &progress)
            .await?;
        let stream = self
            .runtime
            .clone()
            .convert_image(images::convert_request_to_wire(&image.identity, &options)?)
            .await
            .map_err(native_status)?
            .into_inner();
        managed_image_stream(stream, &progress).await
    }

    pub(crate) async fn update_boot_assets(
        &self,
        value: &str,
        update: libvm::BootAssetsUpdate,
    ) -> eyre::Result<MachineData> {
        Ok(snapshots::snapshot_from_wire(
            self.machines
                .clone()
                .update_boot_assets(silo_vm_control::boot::update_boot_assets_to_wire(
                    &libvm::MachineRef::parse(value)?,
                    &update,
                )?)
                .await
                .map_err(native_status)?
                .into_inner(),
        )?)
    }
}

/// Exactly one terminal managed image ends the stream; progress precedes it.
async fn managed_image_stream(
    mut stream: tonic::Streaming<w::ManagedImageEvent>,
    progress: &ImageProgressSender,
) -> eyre::Result<libvm::ManagedImageInfo> {
    let mut terminal = None;
    while let Some(event) = stream.message().await.map_err(native_status)? {
        eyre::ensure!(
            terminal.is_none(),
            "daemon image stream continued after terminal image"
        );
        match event
            .event
            .ok_or_else(|| eyre::eyre!("daemon image stream omitted event"))?
        {
            w::managed_image_event::Event::Progress(value) => {
                progress.send(images::progress_from_wire(value)?)
            }
            w::managed_image_event::Event::Image(value) => {
                terminal = Some(images::managed_image_from_wire(value)?)
            }
        }
    }
    terminal.ok_or_else(|| {
        eyre::eyre!("daemon image stream ended without a managed image; inspect before retrying")
    })
}
