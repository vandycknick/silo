//! CLI application API boundary.
//!
//! `local` is the in-process ABI adapter around libvm. ABI here means ordinary
//! Rust calls within the CLI process, not a C ABI, FFI surface, or wire protocol.

mod daemon;
pub(crate) mod files;
mod local;
pub(crate) mod machine;
pub(crate) mod start_options;
pub(crate) mod streams;
pub(crate) mod types;

use std::time::Duration;

use libvm::{
    ImageProgressSender, MachineData, MachineUpdate, NetworkDefinition, NetworkDriver,
    NetworkTopology, RuntimeConfig,
};

use crate::machine_defaults::ResolvedMachineNetwork;
use crate::planning::{CreatePlan, PullPolicy};
use crate::template::Template;

use crate::api::machine::AppMachine;
use crate::api::start_options::AppStartOptions;
use crate::api::types::{ReadOnlyCreationResolution, SourceOptions, SourceResolution};
use crate::commands::create::{parse_source, validate_source_options, SourceSpelling};

#[derive(Debug)]
pub(crate) enum AppApi {
    Local(local::LocalVmService),
    Daemon(daemon::DaemonVmService),
}

/// A guest boot diagnostic lives on the serial console; point at the command
/// that shows it rather than at the file.
pub(crate) fn readiness_failure(
    outcome: libvm::MachineReadinessOutcome,
    message: Option<&str>,
    machine: &str,
) -> eyre::Report {
    let reason = if outcome == libvm::MachineReadinessOutcome::Terminal {
        message.map(str::to_owned)
    } else {
        None
    }
    .unwrap_or_else(|| format!("guest readiness check ended with {outcome:?}"));
    eyre::eyre!("{reason}; check `silo logs {machine} --stream serial`")
}

impl AppApi {
    pub(crate) fn local(config: RuntimeConfig) -> Self {
        Self::Local(local::LocalVmService::new(config))
    }

    pub(crate) async fn select(
        config: RuntimeConfig,
        host: &libvm::HostPaths,
        admission: silo_vm_control::transport::Admission,
    ) -> eyre::Result<Self> {
        match daemon::DaemonVmService::probe(&config, host, admission).await? {
            Some(service) => Ok(Self::Daemon(service)),
            None => Ok(Self::local(config)),
        }
    }

    pub(crate) async fn live_capabilities(
        &mut self,
    ) -> eyre::Result<vm_spec::live::LiveHostReport> {
        match self {
            Self::Local(service) => service.live_capabilities().await,
            Self::Daemon(service) => service.live_capabilities().await,
        }
    }

    pub(crate) async fn appliance_live_capabilities(
        &mut self,
    ) -> eyre::Result<Option<vm_spec::live::LiveHostReport>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Daemon(service) => service.appliance_live_capabilities().await,
        }
    }

    pub(crate) async fn export_raw_disk(
        &mut self,
        reference: &str,
        options: libvm::RawDiskExportOptions,
    ) -> eyre::Result<libvm::RawDiskExport> {
        match self {
            Self::Local(service) => service.export_raw_disk(reference, options).await,
            Self::Daemon(service) => service.export_raw_disk(reference, options).await,
        }
    }

    pub(crate) async fn hibernate_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => service.hibernate_machine(reference).await,
            Self::Daemon(service) => service.hibernate_machine(reference).await,
        }
    }

    pub(crate) async fn pause_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => service.pause_machine(reference).await,
            Self::Daemon(service) => service.pause_machine(reference).await,
        }
    }

    pub(crate) async fn resume_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => service.resume_machine(reference).await,
            Self::Daemon(service) => service.resume_machine(reference).await,
        }
    }

    pub(crate) async fn snapshot(
        &mut self,
        reference: &str,
        options: libvm::SnapshotOptions,
        progress: Option<libvm::LiveOperationProgressSender>,
    ) -> eyre::Result<libvm::CreatedSnapshot> {
        match self {
            Self::Local(service) => service.snapshot(reference, options, progress).await,
            Self::Daemon(service) => service.snapshot(reference, options).await,
        }
    }

    /// Both transports run the same libvm operation and every accepted result
    /// must answer exactly this request.
    pub(crate) async fn fork_live(
        &mut self,
        reference: &str,
        options: libvm::LiveForkOptions,
        progress: Option<libvm::LiveOperationProgressSender>,
    ) -> eyre::Result<libvm::LiveForkResult> {
        let result = match self {
            Self::Local(service) => {
                service
                    .fork_live(reference, options.clone(), progress)
                    .await?
            }
            Self::Daemon(service) => service.fork_live(reference, options.clone()).await?,
        };
        silo_vm_control::fork::validate_creation(&result, &options)?;
        Ok(result)
    }

    pub(crate) async fn inspect_fork(
        &mut self,
        operation_id: uuid::Uuid,
    ) -> eyre::Result<libvm::LiveForkResult> {
        let result = match self {
            Self::Local(service) => service.inspect_fork(operation_id).await?,
            Self::Daemon(service) => service.inspect_fork(operation_id).await?,
        };
        silo_vm_control::fork::validate_observation(&result, operation_id)?;
        Ok(result)
    }

    pub(crate) async fn cancel_fork(
        &mut self,
        operation_id: uuid::Uuid,
    ) -> eyre::Result<libvm::LiveForkResult> {
        let result = match self {
            Self::Local(service) => service.cancel_fork(operation_id).await?,
            Self::Daemon(service) => service.cancel_fork(operation_id).await?,
        };
        silo_vm_control::fork::validate_observation(&result, operation_id)?;
        Ok(result)
    }

    pub(crate) async fn fork_stopped(
        &mut self,
        reference: &str,
        options: libvm::ForkOptions,
    ) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => service.fork_stopped(reference, options).await,
            Self::Daemon(service) => service.fork_stopped(reference, options).await,
        }
    }

    /// Local references (including bare names) are admitted without writable
    /// initialization. Only qualified registry paths may pull.
    pub(crate) async fn restore(
        &mut self,
        reference: &str,
        options: libvm::RestoreOptions,
        progress: Option<libvm::LiveOperationProgressSender>,
    ) -> eyre::Result<MachineData> {
        silo_vm_control::images::reject_local_cut(reference)?;
        let source = if options.pull == libvm::PullPolicy::Never || !reference.contains('/') {
            libvm::RestoreSource::Local(reference.parse()?)
        } else {
            libvm::RestoreSource::Registry(reference.to_owned())
        };
        match self {
            Self::Local(service) => service.restore(source, options, progress).await,
            Self::Daemon(service) => service.restore(source, options).await,
        }
    }

    pub(crate) async fn inspect_snapshot(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::SnapshotInfo> {
        let reference: libvm::SnapshotRef = reference.parse()?;
        match self {
            Self::Local(service) => service.inspect_snapshot(reference).await,
            Self::Daemon(service) => service.inspect_snapshot(reference).await,
        }
    }

    pub(crate) async fn verify_snapshot(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::SnapshotVerificationReport> {
        let reference: libvm::SnapshotRef = reference.parse()?;
        match self {
            Self::Local(service) => service.verify_snapshot(reference).await,
            Self::Daemon(service) => service.verify_snapshot(reference).await,
        }
    }

    pub(crate) async fn list_snapshots(&mut self) -> eyre::Result<Vec<libvm::SnapshotInfo>> {
        match self {
            Self::Local(service) => service.list_snapshots().await,
            Self::Daemon(service) => service.list_snapshots().await,
        }
    }

    /// A name removes that name, and the snapshot with its last name; an id
    /// removes the snapshot and all its names.
    pub(crate) async fn remove_snapshot(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::SnapshotRemoval> {
        let reference: libvm::SnapshotRef = reference.parse()?;
        match self {
            Self::Local(service) => service.remove_snapshot(reference).await,
            Self::Daemon(service) => service.remove_snapshot(reference).await,
        }
    }

    pub(crate) async fn list_images(&mut self) -> eyre::Result<Vec<libvm::ImageInfo>> {
        match self {
            Self::Local(service) => service.list_images().await,
            Self::Daemon(service) => service.list_images().await,
        }
    }

    /// Local only: a name, `search_registries` expansion, id or unique id prefix.
    pub(crate) async fn inspect_image(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::ImageInfo> {
        let reference: libvm::ImageRef = reference.parse()?;
        match self {
            Self::Local(service) => service.inspect_image(&reference).await,
            Self::Daemon(service) => service.inspect_image(&reference).await,
        }
    }

    /// A name removes that name, and the image with its last name; an id
    /// removes the image and all its names.
    pub(crate) async fn remove_image(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::ImageRemoval> {
        let reference: libvm::ImageRef = reference.parse()?;
        match self {
            Self::Local(service) => service.remove_image(&reference).await,
            Self::Daemon(service) => service.remove_image(&reference).await,
        }
    }

    pub(crate) async fn prune_images(&mut self) -> eyre::Result<libvm::ImagePruneReport> {
        match self {
            Self::Local(service) => service.prune_images().await,
            Self::Daemon(service) => service.prune_images().await,
        }
    }

    pub(crate) async fn pull_image(
        &mut self,
        reference: &str,
        options: libvm::ImagePullOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::ImageInfo> {
        match self {
            Self::Local(service) => service.pull_image(reference, options, progress).await,
            Self::Daemon(service) => service.pull_image(reference, options, progress).await,
        }
    }

    pub(crate) async fn inspect_artifact(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::ArtifactInspection> {
        match self {
            Self::Local(service) => service.inspect_artifact(reference).await,
            Self::Daemon(service) => service.inspect_artifact(reference).await,
        }
    }

    pub(crate) async fn publish_artifact(
        &mut self,
        request: libvm::ArtifactPublishRequest,
    ) -> eyre::Result<libvm::ArtifactPublishReport> {
        match self {
            Self::Local(service) => service.publish_artifact(request).await,
            Self::Daemon(service) => service.publish_artifact(request).await,
        }
    }

    pub(crate) async fn import_image(
        &mut self,
        request: libvm::DiskImportRequest,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::StoredImageInfo> {
        match self {
            Self::Local(service) => service.import_image(request, progress).await,
            Self::Daemon(service) => service.import_image(request, progress).await,
        }
    }

    pub(crate) async fn convert_image(
        &mut self,
        reference: String,
        pull: libvm::PullPolicy,
        platform: Option<libvm::LinuxPlatform>,
        options: libvm::RawConversionOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::StoredImageInfo> {
        match self {
            Self::Local(service) => {
                service
                    .convert_image(reference, pull, platform, options, progress)
                    .await
            }
            Self::Daemon(service) => {
                service
                    .convert_image(reference, pull, platform, options, progress)
                    .await
            }
        }
    }

    /// Explicit stopped boot-bundle replacement; never combined with other settings.
    pub(crate) async fn update_boot_assets(
        &mut self,
        reference: &str,
        update: libvm::BootAssetsUpdate,
    ) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => service.update_boot_assets(reference, update).await,
            Self::Daemon(service) => service.update_boot_assets(reference, update).await,
        }
    }

    pub(crate) async fn update_kernel_args(
        &mut self,
        reference: &str,
        clear: bool,
        append: Vec<String>,
    ) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => service.update_kernel_args(reference, clear, append).await,
            Self::Daemon(service) => service.update_kernel_args(reference, clear, append).await,
        }
    }

    pub(crate) async fn list_machines(
        &mut self,
    ) -> eyre::Result<Vec<libvm::MachineInventoryEntry>> {
        match self {
            Self::Local(service) => service.list_machines().await,
            Self::Daemon(service) => service.list_machines().await,
        }
    }

    pub(crate) async fn inspect_inventory(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::MachineInventoryEntry> {
        match self {
            Self::Local(service) => service.inspect_inventory(reference).await,
            Self::Daemon(service) => service.inspect_inventory(reference).await,
        }
    }

    pub(crate) async fn inspect_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => service.inspect_machine(reference).await,
            Self::Daemon(service) => service.inspect_machine(reference).await,
        }
    }

    /// Preflight failures have not entered a capture and must not initialize
    /// a runtime merely to enrich their diagnostics.
    pub(crate) async fn inspect_capture_source(&mut self, reference: &str) -> Option<MachineData> {
        match self {
            Self::Local(local::LocalVmService::Uninitialized { .. }) => None,
            _ => self.inspect_machine(reference).await.ok(),
        }
    }

    pub(crate) async fn start_machine(
        &mut self,
        reference: &str,
        readiness_timeout: Duration,
        wait_ready: bool,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let before = machine.inspect().await?;
        crate::commands::start::ensure_startable(&before)?;
        if matches!(before.status, libvm::MachineStatus::Hibernated { .. }) {
            crate::ui::waking(&before.name);
        }
        let options = AppStartOptions::new();
        let start = machine.start_with_options(options).await?;
        if wait_ready && crate::commands::start::requires_guest_readiness(&start.machine) {
            let readiness = machine.wait_ready(readiness_timeout).await?;
            if readiness.outcome != libvm::MachineReadinessOutcome::Ready {
                return Err(machine.readiness_failure(&readiness));
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
        let outcome = match self {
            Self::Local(service) => service.stop_machine(reference, force, timeout).await?,
            Self::Daemon(service) => service.stop_machine(reference, force, timeout).await?,
        };
        crate::ui::stop_warning(outcome.warning);
        Ok(outcome.machine)
    }

    pub(crate) async fn remove_machine(
        &mut self,
        reference: &str,
        force: bool,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let data = machine.inspect().await?;
        if force {
            machine.remove_force().await?;
        } else {
            machine.remove().await?;
        }
        Ok(data)
    }

    pub(crate) async fn update_machine(
        &mut self,
        reference: &str,
        mut update: MachineUpdate,
    ) -> eyre::Result<MachineData> {
        local::normalize_update(&mut update)?;
        match self {
            Self::Local(service) => service.update_machine(reference, update).await,
            Self::Daemon(service) => service.update_machine(reference, update).await,
        }
    }

    pub(crate) async fn list_networks(&mut self) -> eyre::Result<Vec<NetworkDefinition>> {
        match self {
            Self::Local(service) => service.list_networks().await,
            Self::Daemon(service) => service.list_networks().await,
        }
    }

    pub(crate) async fn inspect_network(
        &mut self,
        name: &str,
    ) -> eyre::Result<Option<NetworkDefinition>> {
        match self {
            Self::Local(service) => service.inspect_network(name).await,
            Self::Daemon(service) => service.inspect_network(name).await,
        }
    }

    pub(crate) async fn create_network(
        &mut self,
        name: String,
        topology: NetworkTopology,
        driver: NetworkDriver,
    ) -> eyre::Result<()> {
        match self {
            Self::Local(service) => service.create_network(name, topology, driver).await,
            Self::Daemon(service) => service.create_network(name, topology, driver).await,
        }
    }

    pub(crate) async fn remove_network(&mut self, name: &str) -> eyre::Result<()> {
        match self {
            Self::Local(service) => service.remove_network(name).await,
            Self::Daemon(service) => service.remove_network(name).await,
        }
    }

    pub(crate) async fn set_machine_network(
        &mut self,
        reference: &str,
        network: ResolvedMachineNetwork,
    ) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => service.set_machine_network(reference, network).await,
            Self::Daemon(service) => service.set_machine_network(reference, network).await,
        }
    }

    /// `disk:PATH` is a disk; anything else is resolved like DESIGN §4: a
    /// local stored image by name, expansion or id prefix is used directly
    /// (re-pulled first under `--pull always` when spelled as a registry
    /// reference); otherwise the reference selects an OCI image.
    pub(crate) async fn resolve_source(
        &mut self,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(libvm::PullPolicy, PullPolicy)>,
        options: &SourceOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<SourceResolution> {
        let requested = crate::commands::create::selected_image_reference(positional, template)?;
        let spelling = parse_source(&requested)?;
        validate_source_options(&spelling, options, pull.is_some())?;
        let is_positional = positional.is_some();
        let reference = match spelling {
            SourceSpelling::Disk(path) => {
                return local::disk_resolution(path, options, is_positional)
            }
            SourceSpelling::Reference(reference) => reference,
        };
        let pull = pull.unwrap_or((libvm::PullPolicy::IfMissing, PullPolicy::IfMissing));
        let oci_reference = match self.creation_image(reference, pull.0, &progress).await? {
            local::CreationImage::Stored(image) => {
                return local::stored_resolution(requested, &image, options, is_positional)
            }
            local::CreationImage::Oci(reference) => reference,
        };
        let resolved = match self {
            Self::Local(service) => {
                service
                    .resolve_oci_source(
                        oci_reference,
                        pull,
                        options,
                        progress.clone(),
                        is_positional,
                    )
                    .await
            }
            Self::Daemon(service) => {
                service
                    .resolve_oci_source(
                        oci_reference,
                        pull,
                        options,
                        progress.clone(),
                        is_positional,
                    )
                    .await
            }
        };
        // A Silo image artifact is not an OCI container image: pulling it
        // stores the image, which creation then uses by id.
        let artifact = match resolved {
            Err(error) if pull.0 != libvm::PullPolicy::Never => {
                match error.downcast::<libvm::LibVmError>() {
                    Ok(libvm::LibVmError::ImageIsVmArtifact { reference }) => reference,
                    Ok(error) => return Err(error.into()),
                    Err(error) => return Err(error),
                }
            }
            resolved => return resolved,
        };
        let options_for_pull = libvm::ImagePullOptions {
            policy: Some(pull.0),
        };
        match self.pull_image(&artifact, options_for_pull, progress).await? {
            libvm::ImageInfo::Stored(image) => {
                local::stored_resolution(requested, &image, options, is_positional)
            }
            libvm::ImageInfo::Oci(_) => eyre::bail!(
                "{artifact} changed from a Silo image artifact to a container image while pulling; retry"
            ),
        }
    }

    async fn creation_image(
        &mut self,
        reference: String,
        pull: libvm::PullPolicy,
        progress: &ImageProgressSender,
    ) -> eyre::Result<local::CreationImage> {
        let image = match self.inspect_image(&reference).await {
            Ok(image) => image,
            Err(error)
                if matches!(
                    error.downcast_ref::<libvm::LibVmError>(),
                    Some(libvm::LibVmError::ImageNotFound { .. })
                ) =>
            {
                return Ok(local::CreationImage::Oci(reference))
            }
            Err(error) => return Err(error),
        };
        match image {
            libvm::ImageInfo::Stored(_)
                if pull == libvm::PullPolicy::Always
                    && local::is_registry_reference(&reference) =>
            {
                let options = libvm::ImagePullOptions {
                    policy: Some(libvm::PullPolicy::Always),
                };
                Ok(
                    match self
                        .pull_image(&reference, options, progress.clone())
                        .await?
                    {
                        libvm::ImageInfo::Stored(image) => local::CreationImage::Stored(image),
                        libvm::ImageInfo::Oci(_) => local::CreationImage::Oci(reference),
                    },
                )
            }
            image => local::CreationImage::local(reference, image),
        }
    }

    pub(crate) async fn resolve_read_only_creation(
        config: RuntimeConfig,
        requested_name: Option<String>,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(libvm::PullPolicy, PullPolicy)>,
        options: &SourceOptions,
    ) -> eyre::Result<ReadOnlyCreationResolution> {
        local::LocalVmService::resolve_read_only_creation(
            config,
            requested_name,
            positional,
            template,
            pull,
            options,
        )
        .await
    }

    pub(crate) async fn ensure_name_available(&mut self, name: &str) -> eyre::Result<()> {
        match self {
            Self::Local(service) => service.ensure_name_available(name).await,
            Self::Daemon(service) => service.ensure_name_available(name).await,
        }
    }

    pub(crate) async fn create_machine(
        &mut self,
        plan: &CreatePlan,
        source: SourceResolution,
        policy_config_dir: Option<&std::path::Path>,
        progress: ImageProgressSender,
    ) -> eyre::Result<MachineData> {
        match self {
            Self::Local(service) => {
                service
                    .create_machine(plan, source, policy_config_dir, progress)
                    .await
            }
            Self::Daemon(service) => {
                service
                    .create_machine(plan, source, policy_config_dir, progress)
                    .await
            }
        }
    }

    pub(crate) async fn machine(&mut self, reference: &str) -> eyre::Result<AppMachine> {
        match self {
            Self::Local(service) => service.machine_handle(reference).await,
            Self::Daemon(service) => service.machine_handle(reference).await,
        }
    }

    pub(crate) async fn observation_machine(
        &mut self,
        reference: &str,
    ) -> eyre::Result<AppMachine> {
        match self {
            Self::Local(service) => service.observation_machine_handle(reference).await,
            Self::Daemon(service) => service.machine_handle(reference).await,
        }
    }

    pub(crate) async fn machine_start_options(
        &mut self,
        machine: &AppMachine,
        detached_cleanup: bool,
    ) -> eyre::Result<AppStartOptions> {
        let data = machine.inspect().await?;
        Ok(AppStartOptions {
            cleanup_on_exit: detached_cleanup
                && data.retention == libvm::MachineRetention::Ephemeral,
            ..AppStartOptions::new()
        })
    }

    pub(crate) async fn cleanup_local(
        config: RuntimeConfig,
        machine_id: String,
        run_id: libvm::MachineRunId,
    ) -> eyre::Result<()> {
        local::LocalVmService::cleanup_local(config, machine_id, run_id).await
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use libvm::RuntimeConfig;

    use crate::api::AppApi;

    #[test]
    fn terminal_readiness_error_keeps_reason_and_points_at_serial_logs() {
        let message = crate::api::readiness_failure(
            libvm::MachineReadinessOutcome::Terminal,
            Some("guest powered off during boot"),
            "archy",
        )
        .to_string();
        assert_eq!(
            message,
            "guest powered off during boot; check `silo logs archy --stream serial`"
        );
    }

    fn minimal_template() -> crate::template::Template {
        serde_json::from_str(r#"{"version":"1"}"#).expect("parse minimal template")
    }

    // Stopped boot capture is admitted only on the Linux krun lane
    // (libvm boot_assets::validate_captured_boot_lane).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_names_restore_machines_and_are_refused_as_creation_images() {
        let temp = tempfile::tempdir().unwrap();
        // Stopped capture admits only the krun direct-boot lane; nothing boots here.
        let mut api = AppApi::local(
            isolated_runtime_config(temp.path(), &temp.path().join("home"))
                .with_virt_backend(libvm::VirtBackendOverride::Krun),
        );
        let source = create_idle_fixture(&mut api, temp.path(), "source").await;
        let created = api
            .snapshot(
                "source",
                libvm::SnapshotOptions {
                    name: Some("web".into()),
                    ..libvm::SnapshotOptions::default()
                },
                None,
            )
            .await
            .expect("snapshot a stopped machine");
        created.require_requested_name().unwrap();
        assert_eq!(created.snapshot.names, ["web"]);
        assert_eq!(created.snapshot.memory, libvm::SnapshotMemory::None);
        assert!(created.capture.is_none());

        let (progress, _events) = libvm::ImageProgressSender::default_channel();
        let error = api
            .resolve_source(
                Some("web"),
                &minimal_template(),
                None,
                &crate::api::types::SourceOptions::default(),
                progress,
            )
            .await
            .expect_err("create takes images only");
        assert!(
            matches!(
                error.downcast_ref::<libvm::LibVmError>(),
                Some(libvm::LibVmError::SnapshotIsNotAnImage { .. })
            ),
            "{error}"
        );
        assert!(error.to_string().contains("silo restore web"), "{error}");

        let restored = api
            .restore(
                "web",
                libvm::RestoreOptions {
                    name: Some("restored".into()),
                    ..libvm::RestoreOptions::default()
                },
                None,
            )
            .await
            .expect("restore by local snapshot name");
        assert_eq!(restored.name, "restored");
        assert_eq!(restored.status, libvm::MachineStatus::Stopped);

        let listed = api.list_snapshots().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.snapshot.id);
        let removal = api.remove_snapshot("web").await.unwrap();
        assert_eq!(removal.id, created.snapshot.id);
        assert_eq!(removal.names, ["web"]);
        assert!(removal.record_removed);
        assert!(api.list_snapshots().await.unwrap().is_empty());
        assert_eq!(
            api.inspect_machine("restored").await.unwrap().status,
            libvm::MachineStatus::Stopped,
            "removing a snapshot leaves machines restored from it intact"
        );
        api.machine("restored")
            .await
            .unwrap()
            .remove()
            .await
            .unwrap();
        source.remove().await.unwrap();
    }

    #[tokio::test]
    async fn stored_image_names_resolve_for_creation_and_follow_tag_removal() {
        use crate::api::types::{ResolvedSource, SourceOptions};
        use crate::planning::ResolvedImage;

        let temp = tempfile::tempdir().unwrap();
        let mut api = AppApi::local(isolated_runtime_config(
            temp.path(),
            &temp.path().join("home"),
        ));
        let disk = temp.path().join("base.img");
        disk_image::ext4::Formatter::new(&disk, 4096, 256 * 1024)
            .and_then(|formatter| formatter.close())
            .unwrap();
        let platform = silo_vm_control::boot::host_platform().unwrap();
        let (progress, _events) = libvm::ImageProgressSender::default_channel();
        let image = api
            .import_image(
                libvm::DiskImportRequest {
                    path: disk,
                    boot: libvm::DiskImportBoot::LinuxDirect {
                        platform: platform.clone(),
                        root: libvm::ImportRootSelection::WholeDisk,
                        assets: libvm::BootAssetSelection::Packaged,
                    },
                    name: Some("base".into()),
                },
                progress.clone(),
            )
            .await
            .expect("import a named stored image");
        assert_eq!(image.names, ["base"]);

        let id = image.id.to_string();
        let prefix = &id["sha256:".len().."sha256:".len() + 12];
        for reference in ["base", prefix, id.as_str()] {
            let source = api
                .resolve_source(
                    Some(reference),
                    &minimal_template(),
                    None,
                    &SourceOptions::default(),
                    progress.clone(),
                )
                .await
                .expect("a stored image by name, id prefix or id");
            assert!(
                matches!(source.source, ResolvedSource::Stored(id) if id == image.id),
                "{reference}"
            );
            assert!(matches!(
                &source.plan_image,
                ResolvedImage::Stored { requested_reference, id, .. }
                    if requested_reference == reference && *id == image.id
            ));
        }
        let error = api
            .resolve_source(
                Some("base"),
                &minimal_template(),
                None,
                &SourceOptions {
                    platform: Some(platform),
                    root: None,
                },
                progress,
            )
            .await
            .expect_err("--platform cannot rewrite stored boot metadata");
        assert!(
            error
                .to_string()
                .contains("--platform cannot change a stored image"),
            "{error}"
        );

        let error = api
            .restore("base", libvm::RestoreOptions::default(), None)
            .await
            .expect_err("restore takes snapshots only");
        assert!(
            matches!(
                error.downcast_ref::<libvm::LibVmError>(),
                Some(libvm::LibVmError::ImageIsNotASnapshot { .. })
            ),
            "{error}"
        );
        assert!(error.to_string().contains("silo create base"), "{error}");

        assert!(api.list_images().await.unwrap().iter().any(|listed| {
            matches!(listed, libvm::ImageInfo::Stored(stored) if stored.id == image.id && stored.names == ["base"])
        }));
        let removal = api.remove_image("base").await.unwrap();
        assert_eq!(removal.id, image.id);
        assert_eq!(removal.names, ["base"]);
        assert!(removal.record_removed, "the last name removes the image");
        assert!(matches!(
            api.inspect_image("base")
                .await
                .unwrap_err()
                .downcast_ref::<libvm::LibVmError>(),
            Some(libvm::LibVmError::ImageNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn local_api_uses_only_its_explicit_disposable_roots() {
        let temp = tempfile::tempdir().expect("create disposable application roots");
        let home = temp.path().join("home");
        let config = isolated_runtime_config(temp.path(), &home);
        let mut api = AppApi::local(config);

        let machines = api
            .list_machines()
            .await
            .expect("open and list isolated local API");

        assert!(machines.is_empty());
        assert!(home.join("state.db").is_file());
        assert!(libvm::HostPaths::run_root().unwrap().is_dir());
        assert!(!temp.path().join(".docker").exists());
        assert!(!temp.path().join("native-service").exists());
    }

    #[tokio::test]
    async fn image_progress_survives_resolution_and_covers_creation() {
        use crate::commands::create::{machine_settings, VmOverrideArgs};
        use crate::planning::{self, Plan, PlanKind, ProcessOverrides, ResolveRequest};
        use crate::template::Template;
        use libvm::{ImageProgress, ImageProgressSender, MachineRetention};

        let temp = tempfile::tempdir().expect("create disposable roots");
        let mut api = AppApi::local(isolated_runtime_config(
            temp.path(),
            &temp.path().join("home"),
        ));
        let disk = temp.path().join("rootfs.img");
        disk_image::ext4::Formatter::new(&disk, 4096, 256 * 1024)
            .and_then(|formatter| formatter.close())
            .expect("format admissible whole-disk ext4");
        let reference = format!("disk:{}", disk.display());
        let template: Template =
            serde_json::from_str(r#"{"version":"1"}"#).expect("parse minimal template");
        let (progress, mut events) = ImageProgressSender::default_channel();
        let source = api
            .resolve_source(
                Some(&reference),
                &template,
                None,
                &crate::api::types::SourceOptions::default(),
                progress.clone(),
            )
            .await
            .expect("resolve local disk");
        assert!(
            matches!(
                events.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "resolution must not close the progress channel"
        );
        let options = VmOverrideArgs::default()
            .resolve()
            .expect("resolve defaults");
        let plan = planning::resolve(ResolveRequest {
            kind: PlanKind::Create,
            template,
            template_name: None,
            template_image: None,
            positional_image: Some(source.plan_image.clone()),
            machine_settings: machine_settings(&options),
            machine_overrides: options.overrides,
            environment_files: Vec::new(),
            host_environment: Default::default(),
            environment_overrides: Vec::new(),
            command_tail: Vec::new(),
            process_overrides: ProcessOverrides::default(),
            retention: MachineRetention::Persistent,
            name: Some("progress-test".to_string()),
        })
        .expect("resolve creation plan");
        let Plan::Create(plan) = plan else {
            panic!("expected create plan");
        };
        let machine = api
            .create_machine(&plan, source, None, progress)
            .await
            .expect("create machine");
        assert_eq!(machine.name, "progress-test");
        assert!(matches!(
            events.try_recv(),
            Ok(ImageProgress::UsingLocalDisk { .. })
        ));
        assert!(matches!(events.try_recv(), Ok(ImageProgress::Complete)));
        assert!(
            matches!(
                events.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ),
            "creation must release its reporter even while the API stays alive"
        );
    }

    pub(crate) fn isolated_runtime_config(root: &Path, home: &Path) -> RuntimeConfig {
        let components = root.join("components");
        let bin = components.join("bin");
        let assets = components.join("assets");
        std::fs::create_dir_all(&bin).expect("create binary component fixtures");
        std::fs::create_dir(&assets).expect("create asset component fixtures");
        let supervisor = bin.join("silo-vmm");
        test_utils::install_mock_vmm(&supervisor);
        for name in ["netd", "krun"] {
            executable_fixture(&bin, name);
        }
        std::fs::write(
            assets.join("kernel-default"),
            test_utils::direct_kernel::host_kernel("fixture"),
        )
        .expect("write asset fixture");
        std::fs::write(assets.join("initramfs"), b"fixture").expect("write asset fixture");
        executable_fixture(&assets, "agent");
        RuntimeConfig::local(home)
            .with_runtime_root(&components)
            .with_virt_backend(libvm::VirtBackendOverride::Mock { scenario: None })
    }

    #[tokio::test]
    async fn both_cli_start_paths_map_real_store_missing_secret_to_the_same_hint() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let mut api = AppApi::local(isolated_runtime_config(temp.path(), &home));
        let disk = temp.path().join("disk.img");
        disk_image::ext4::Formatter::new(&disk, 4096, 256 * 1024)
            .and_then(|formatter| formatter.close())
            .unwrap();
        let policy = libvm::NetworkPolicy::from_json_str(r#"{"version":1,"endpoints":[{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["example.com"]}],"credentials":[{"name":"personal","kind":"openai_codex_oauth","endpoint":"api"}]}"#).unwrap();
        let AppApi::Local(service) = &mut api else {
            unreachable!("explicit local fixture")
        };
        let created = service
            .runtime()
            .await
            .unwrap()
            .machine()
            .name("secret-hint")
            .image_source(libvm::ImageSource::Disk(
                crate::commands::create::disk_create_request(disk, &Default::default()).unwrap(),
            ))
            .agent_mode(Some(libvm::MachineAgent::Disabled))
            .network(|network| network.private().policy(policy))
            .create()
            .await
            .unwrap();
        let message = api
            .start_machine("secret-hint", std::time::Duration::from_secs(1), true)
            .await
            .unwrap_err()
            .to_string();
        assert!(message.contains(&home.join("secrets.json").display().to_string()));
        assert!(message.contains("silo secret login openai-codex --name personal"));
        let machine = api.machine("secret-hint").await.unwrap();
        for detached in [true, false] {
            let options = api.machine_start_options(&machine, detached).await.unwrap();
            assert!(options.egress_credentials.secrets.is_empty());
            assert_eq!(
                machine
                    .start_with_options(options)
                    .await
                    .unwrap_err()
                    .to_string(),
                message
            );
        }
        assert_eq!(
            created.inspect().await.unwrap().status,
            libvm::MachineStatus::Stopped
        );
        created.remove().await.unwrap();
    }

    #[tokio::test]
    async fn start_no_wait_returns_for_an_agent_that_never_becomes_ready() {
        use std::time::Duration;

        let temp = tempfile::tempdir().unwrap();
        let scenario = temp.path().join("scenario.json");
        test_utils::Scenario {
            agent: test_utils::AgentScenario {
                never_ready: true,
                ..Default::default()
            },
            ..Default::default()
        }
        .write_to(&scenario)
        .unwrap();
        let config = isolated_runtime_config(temp.path(), &temp.path().join("home"))
            .with_mock_vmm(&scenario);
        let mut api = AppApi::local(config);
        let machine = create_idle_fixture(&mut api, temp.path(), "no-wait").await;
        let result = api.start_machine("no-wait", Duration::ZERO, false).await;
        let observed = Box::pin(machine.inspect()).await.unwrap();
        Box::pin(
            machine.kill_with(libvm::MachineKillOptions::new().timeout(Duration::from_secs(10))),
        )
        .await
        .unwrap();
        let data = result.expect("no-wait must not wait for guest readiness");
        assert!(data.is_running());
        assert!(!observed.status.ready());

        let result = api.start_machine("no-wait", Duration::ZERO, true).await;
        Box::pin(
            machine.kill_with(libvm::MachineKillOptions::new().timeout(Duration::from_secs(10))),
        )
        .await
        .unwrap();
        assert!(
            result.is_err(),
            "ordinary start must still wait for readiness"
        );
        machine.remove().await.unwrap();
    }

    #[tokio::test]
    async fn kernel_arguments_use_stopped_config_admission() {
        use std::time::Duration;

        let temp = tempfile::tempdir().unwrap();
        let mut api = AppApi::local(isolated_runtime_config(
            temp.path(),
            &temp.path().join("home"),
        ));
        let machine = create_idle_fixture(&mut api, temp.path(), "kernel-args").await;
        let original = Box::pin(machine.inspect()).await.unwrap().spec;
        let data = api
            .update_kernel_args("kernel-args", false, vec!["quiet".into()])
            .await
            .unwrap();
        assert_eq!(cmdline(&data), ["quiet"]);
        let data = api
            .update_kernel_args(
                "kernel-args",
                false,
                vec!["silo.rescue=on-failure".into(), "debug".into()],
            )
            .await
            .unwrap();
        assert_eq!(cmdline(&data), ["quiet", "silo.rescue=on-failure", "debug"]);
        let accepted = data.spec;
        for reserved in [
            "rdinit=/bin/sh",
            "root=/dev/vdb",
            "rootfstype=ext4",
            "rootflags=ro",
            "\"rdinit=/bin/sh\"",
            "quiet root=/dev/vdb",
        ] {
            assert!(
                api.update_kernel_args("kernel-args", false, vec![reserved.into()])
                    .await
                    .is_err(),
                "{reserved}"
            );
            assert_eq!(Box::pin(machine.inspect()).await.unwrap().spec, accepted);
        }
        let cleared = api
            .update_kernel_args("kernel-args", true, Vec::new())
            .await
            .unwrap();
        assert!(cmdline(&cleared).is_empty());
        assert_eq!(cleared.spec, original);
        api.start_machine("kernel-args", Duration::from_secs(10), true)
            .await
            .unwrap();
        let result = api
            .update_kernel_args("kernel-args", false, vec!["debug".into()])
            .await;
        let current = Box::pin(machine.inspect()).await.unwrap().spec;
        Box::pin(
            machine.kill_with(libvm::MachineKillOptions::new().timeout(Duration::from_secs(10))),
        )
        .await
        .unwrap();
        assert!(matches!(
            result.unwrap_err().downcast_ref::<libvm::LibVmError>(),
            Some(libvm::LibVmError::MachineAlreadyRunning { .. })
        ));
        assert_eq!(current, original);
        machine.remove().await.unwrap();
    }

    fn cmdline(data: &libvm::MachineData) -> &[String] {
        &data
            .spec
            .boot
            .as_ref()
            .unwrap()
            .kernel
            .as_ref()
            .unwrap()
            .cmdline
    }

    async fn create_idle_fixture(api: &mut AppApi, root: &Path, name: &str) -> libvm::Machine {
        let disk = root.join(format!("{name}.img"));
        disk_image::ext4::Formatter::new(&disk, 4096, 256 * 1024)
            .and_then(|formatter| formatter.close())
            .unwrap();
        let AppApi::Local(service) = api else {
            panic!("explicit local fixture");
        };
        let builder = service
            .runtime()
            .await
            .unwrap()
            .machine()
            .name(name)
            .image_source(libvm::ImageSource::Disk(
                crate::commands::create::disk_create_request(disk, &Default::default()).unwrap(),
            ))
            .network(|network| network.none());
        Box::pin(builder.create()).await.unwrap()
    }

    fn executable_fixture(parent: &Path, name: &str) -> std::path::PathBuf {
        let path = parent.join(name);
        std::fs::write(&path, b"fixture").expect("write component fixture");
        let mut permissions = std::fs::metadata(&path)
            .expect("inspect component fixture")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("make component fixture executable");
        path
    }
}
