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
    ImageProgressSender, ImagePullPolicy, MachineData, MachineUpdate, NetworkDefinition,
    NetworkDriver, NetworkTopology, RuntimeConfig,
};

use crate::machine_defaults::ResolvedMachineNetwork;
use crate::planning::{CreatePlan, PullPolicy};
use crate::template::Template;

use crate::api::machine::AppMachine;
use crate::api::start_options::AppStartOptions;
use crate::api::types::{ReadOnlyCreationResolution, SourceOptions, SourceResolution};

#[derive(Debug)]
pub(crate) enum AppApi {
    Local(local::LocalVmService),
    Daemon(daemon::DaemonVmService),
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

    pub(crate) async fn snapshot_live(
        &mut self,
        reference: &str,
        options: libvm::LiveSnapshotOptions,
    ) -> eyre::Result<libvm::LiveSnapshot> {
        match self {
            Self::Local(service) => service.snapshot_live(reference, options).await,
            Self::Daemon(service) => service.snapshot_live(reference, options).await,
        }
    }

    /// Both transports run the same libvm operation and every accepted result
    /// must answer exactly this request.
    pub(crate) async fn fork_live(
        &mut self,
        reference: &str,
        options: libvm::LiveForkOptions,
    ) -> eyre::Result<libvm::LiveForkResult> {
        let result = match self {
            Self::Local(service) => service.fork_live(reference, options.clone()).await?,
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

    pub(crate) async fn snapshot_stopped(
        &mut self,
        reference: &str,
        options: libvm::SnapshotOptions,
    ) -> eyre::Result<libvm::SnapshotInfo> {
        match self {
            Self::Local(service) => service.snapshot_stopped(reference, options).await,
            Self::Daemon(service) => service.snapshot_stopped(reference, options).await,
        }
    }

    pub(crate) async fn restore_snapshot(
        &mut self,
        reference: &str,
        options: libvm::RestoreOptions,
    ) -> eyre::Result<MachineData> {
        let reference: libvm::SnapshotRef = if reference.starts_with("image:") {
            reference.parse()?
        } else {
            format!("image:{reference}").parse()?
        };
        match self {
            Self::Local(service) => service.restore_snapshot(reference, options).await,
            Self::Daemon(service) => service.restore_snapshot(reference, options).await,
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

    pub(crate) async fn list_snapshots(&mut self) -> eyre::Result<Vec<libvm::SnapshotInfo>> {
        match self {
            Self::Local(service) => service.list_snapshots().await,
            Self::Daemon(service) => service.list_snapshots().await,
        }
    }

    pub(crate) async fn release_snapshot(&mut self, reference: &str) -> eyre::Result<()> {
        let reference: libvm::SnapshotRef = reference.parse()?;
        match self {
            Self::Local(service) => service.release_snapshot(reference).await,
            Self::Daemon(service) => service.release_snapshot(reference).await,
        }
    }

    /// Removes only an `image:NAME` alias in the single image/snapshot namespace,
    /// never an explicit retention.
    pub(crate) async fn remove_image_alias(&mut self, reference: &str) -> eyre::Result<()> {
        let alias = match silo_vm_control::images::parse_managed(reference)? {
            silo_vm_control::images::ManagedSpelling::Reference(
                libvm::ManagedSourceRef::Alias(alias),
            ) => alias,
            _ => {
                eyre::bail!("image remove requires an image:NAME alias, not an immutable identity")
            }
        };
        match self {
            Self::Local(service) => service.remove_image_alias(alias).await,
            Self::Daemon(service) => service.remove_image_alias(alias).await,
        }
    }

    /// Resolves any `image:` spelling to a typed reference in either transport.
    pub(crate) async fn managed_reference(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::ManagedSourceRef> {
        let spelling = silo_vm_control::images::parse_managed(reference)?;
        match self {
            Self::Local(service) => service.managed_reference(spelling).await,
            Self::Daemon(service) => service.managed_reference(spelling).await,
        }
    }

    pub(crate) async fn inspect_managed(
        &mut self,
        reference: &str,
    ) -> eyre::Result<libvm::ManagedSourceInfo> {
        let reference = self.managed_reference(reference).await?;
        match self {
            Self::Local(service) => service.inspect_managed(&reference).await,
            Self::Daemon(service) => service.inspect_managed(&reference).await,
        }
    }

    pub(crate) async fn list_managed(&mut self) -> eyre::Result<Vec<libvm::ManagedSourceInfo>> {
        match self {
            Self::Local(service) => service.list_managed().await,
            Self::Daemon(service) => service.list_managed().await,
        }
    }

    /// Releases explicit retention of an image or snapshot; aliases and other
    /// consumers still retain its bytes.
    pub(crate) async fn release_image(&mut self, reference: &str) -> eyre::Result<()> {
        let reference = self.managed_reference(reference).await?;
        match self {
            Self::Local(service) => service.release_image(&reference).await,
            Self::Daemon(service) => service.release_image(&reference).await,
        }
    }

    pub(crate) async fn import_image(
        &mut self,
        request: libvm::DiskImportRequest,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::ManagedImageInfo> {
        match self {
            Self::Local(service) => service.import_image(request, progress).await,
            Self::Daemon(service) => service.import_image(request, progress).await,
        }
    }

    pub(crate) async fn convert_image(
        &mut self,
        reference: String,
        pull: ImagePullPolicy,
        platform: Option<libvm::LinuxPlatform>,
        options: libvm::RawConversionOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<libvm::ManagedImageInfo> {
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

    pub(crate) async fn start_machine(
        &mut self,
        reference: &str,
        readiness_timeout: Duration,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let before = machine.inspect().await?;
        crate::commands::start::ensure_startable(&before)?;
        let options = self.machine_start_options(&machine, true).await?;
        let start = machine.start_with_options(options).await?;
        if crate::commands::start::requires_guest_readiness(&start.machine) {
            let readiness = machine.wait_ready(readiness_timeout).await?;
            if readiness.outcome != libvm::MachineReadinessOutcome::Ready {
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
        match self {
            Self::Local(service) => service.stop_machine(reference, force, timeout).await,
            Self::Daemon(service) => service.stop_machine(reference, force, timeout).await,
        }
    }

    pub(crate) async fn remove_machine(
        &mut self,
        reference: &str,
        force: bool,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let data = machine.inspect().await?;
        if force && data.is_running() {
            if let Err(error) = self
                .stop_machine(&machine.id(), false, Duration::from_secs(60))
                .await
            {
                if !matches!(
                    error.downcast_ref::<libvm::LibVmError>(),
                    Some(libvm::LibVmError::MachineNotRunning { .. })
                ) {
                    return Err(error);
                }
            }
        }
        machine.remove().await?;
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

    pub(crate) async fn resolve_source(
        &mut self,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(ImagePullPolicy, PullPolicy)>,
        options: &SourceOptions,
        progress: ImageProgressSender,
    ) -> eyre::Result<SourceResolution> {
        match self {
            Self::Local(service) => {
                service
                    .resolve_source(positional, template, pull, options, progress)
                    .await
            }
            Self::Daemon(service) => {
                service
                    .resolve_source(positional, template, pull, options, progress)
                    .await
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

    fn isolated_runtime_config(root: &Path, home: &Path) -> RuntimeConfig {
        let components = root.join("components");
        let bin = components.join("bin");
        let assets = components.join("assets");
        std::fs::create_dir_all(&bin).expect("create binary component fixtures");
        std::fs::create_dir(&assets).expect("create asset component fixtures");
        let supervisor = bin.join("silo-vmm");
        std::fs::copy(test_utils::mock_vmm_binary(), &supervisor)
            .expect("install real scenario-capable monitor");
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
            .start_machine("secret-hint", std::time::Duration::from_secs(1))
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
