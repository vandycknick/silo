use std::path::Path;
use std::time::Duration;

use libvm::{
    ImageProgressSender, ImagePullPolicy, LibVmError, MachineData, MachineExit,
    MachineInventoryEntry, MachineKillOptions, MachineReadiness, MachineRunId, MachineStart,
    MachineStopOptions, MachineUpdate, MachineWaitOptions, NetworkDefinition, NetworkDriver,
    NetworkTopology,
};
use silo_vm_control::{
    duration_to_wire, images, lifecycle, network, readiness, snapshots, updates,
};
use silod_spec::daemon::v1 as w;

use crate::api::daemon::{invalid_response, native_status, DaemonVmService};
use crate::api::machine::AppMachine;
use crate::api::start_options::AppStartOptions;
use crate::api::types::{ResolvedSource, SourceResolution};
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
        progress: ImageProgressSender,
    ) -> eyre::Result<SourceResolution> {
        let requested = crate::commands::create::selected_image_reference(positional, template)?;
        if let Some(path) = requested.strip_prefix("disk:") {
            eyre::ensure!(
                pull.is_none(),
                "--pull is only supported for OCI image sources"
            );
            let path = crate::commands::create::canonical_disk_source(&requested, path)?;
            return Ok(SourceResolution {
                plan_image: ResolvedImage::Disk { path: path.clone() },
                is_positional: positional.is_some(),
                source: ResolvedSource::Disk(path),
            });
        }
        let (policy, plan_policy) =
            pull.unwrap_or((ImagePullPolicy::IfMissing, PullPolicy::IfMissing));
        let mut stream = self
            .runtime
            .clone()
            .resolve_image(w::ResolveImageRequest {
                reference: requested,
                pull_policy: images::pull_policy_to_wire(policy),
            })
            .await
            .map_err(native_status)?
            .into_inner();
        let mut terminal = None;
        while let Some(event) = stream.message().await.map_err(native_status)? {
            eyre::ensure!(
                terminal.is_none(),
                "silod image stream continued after terminal image"
            );
            match event
                .event
                .ok_or_else(|| eyre::eyre!("silod image stream omitted event"))?
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
            .ok_or_else(|| eyre::eyre!("silod image stream ended without resolved image"))?;
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
            is_positional: positional.is_some(),
            source: ResolvedSource::DaemonOciIdentity(image.identity),
        })
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
            ResolvedSource::DaemonOciIdentity(identity) => {
                w::create_machine_request::Source::Oci(w::OciIdentity {
                    requested_reference: identity.requested_reference,
                    selected_reference: identity.selected_reference,
                    platform: identity.platform.to_string(),
                    manifest_digest: identity.manifest_digest,
                    config_digest: identity.config_digest,
                    pull_policy: images::pull_policy_to_wire(identity.pull_policy),
                })
            }
            ResolvedSource::Disk(path) => {
                w::create_machine_request::Source::DiskPath(silo_vm_control::path_to_wire(&path))
            }
            ResolvedSource::LocalResolvedOci(_) => {
                eyre::bail!("local OCI source cannot be created through daemon management")
            }
        };
        let mut stream = self
            .machines
            .clone()
            .create_machine(w::CreateMachineRequest {
                configuration: Some(updates::create_to_wire(&configuration)?),
                source: Some(source),
            })
            .await
            .map_err(native_status)?
            .into_inner();
        let mut terminal = None;
        while let Some(event) = stream.message().await.map_err(native_status)? {
            eyre::ensure!(
                terminal.is_none(),
                "silod create stream continued after terminal machine"
            );
            match event
                .event
                .ok_or_else(|| eyre::eyre!("silod create stream omitted event"))?
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
                "silod create stream ended without terminal machine; inspect state before retrying"
            )
        })
    }
}
