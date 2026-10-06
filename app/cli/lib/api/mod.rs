//! CLI application API boundary.
//!
//! `local` is the in-process ABI adapter around libvm. ABI here means ordinary
//! Rust calls within the CLI process, not a C ABI, FFI surface, or wire protocol.

mod daemon;
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
use crate::api::types::{ReadOnlyCreationResolution, SourceResolution};

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
    ) -> eyre::Result<Self> {
        match daemon::DaemonVmService::probe(&config, host).await? {
            Some(service) => Ok(Self::Daemon(service)),
            None => Ok(Self::local(config)),
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
        progress: ImageProgressSender,
    ) -> eyre::Result<SourceResolution> {
        match self {
            Self::Local(service) => {
                service
                    .resolve_source(positional, template, pull, progress)
                    .await
            }
            Self::Daemon(service) => {
                service
                    .resolve_source(positional, template, pull, progress)
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
    ) -> eyre::Result<ReadOnlyCreationResolution> {
        local::LocalVmService::resolve_read_only_creation(
            config,
            requested_name,
            positional,
            template,
            pull,
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
        assert!(libvm::HostPaths::run_root().is_dir());
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
        std::fs::write(&disk, b"caller-owned disk").expect("write local disk");
        let reference = format!("disk:{}", disk.display());
        let template: Template =
            serde_json::from_str(r#"{"version":"1"}"#).expect("parse minimal template");
        let (progress, mut events) = ImageProgressSender::default_channel();
        let source = api
            .resolve_source(Some(&reference), &template, None, progress.clone())
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
        for name in ["silo-vmm", "netd", "krun"] {
            executable_fixture(&bin, name);
        }
        for name in ["kernel-default", "initramfs"] {
            std::fs::write(assets.join(name), b"fixture").expect("write asset fixture");
        }
        executable_fixture(&assets, "agent");
        RuntimeConfig::local(home).with_runtime_root(&components)
    }

    #[tokio::test]
    async fn both_cli_start_paths_map_real_store_missing_secret_to_the_same_hint() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let mut api = AppApi::local(isolated_runtime_config(temp.path(), &home));
        let disk = temp.path().join("disk.img");
        std::fs::write(&disk, b"never-booted disk fixture").unwrap();
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
            .image_source(libvm::ImageSource::disk(disk))
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
