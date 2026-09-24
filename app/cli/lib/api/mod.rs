//! CLI application API boundary.
//!
//! `local` is the in-process ABI adapter around libvm. ABI here means ordinary
//! Rust calls within the CLI process, not a C ABI, FFI surface, or wire protocol.

mod local;
pub(crate) mod machine;
pub(crate) mod start_options;
pub(crate) mod streams;
pub(crate) mod types;

use std::time::Duration;

use libvm::{
    ImageProgressSender, ImagePullPolicy, MachineData, MachineStartOptions, MachineUpdate,
    NetworkDefinition, NetworkDriver, NetworkTopology, RuntimeConfig,
};

use crate::machine_defaults::ResolvedMachineNetwork;
use crate::planning::{CreatePlan, PullPolicy};
use crate::template::Template;

use self::machine::AppMachine;
use self::types::{ReadOnlyCreationResolution, SourceResolution};

#[derive(Debug)]
pub(crate) struct AppApi {
    local: local::LocalVmService,
}

impl AppApi {
    pub(crate) fn local(config: RuntimeConfig) -> Self {
        Self {
            local: local::LocalVmService::new(config),
        }
    }

    pub(crate) async fn list_machines(&mut self) -> eyre::Result<Vec<MachineData>> {
        self.local.list_machines().await
    }

    pub(crate) async fn inspect_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        self.local.inspect_machine(reference).await
    }

    pub(crate) async fn start_machine(
        &mut self,
        reference: &str,
        readiness_timeout: Duration,
    ) -> eyre::Result<MachineData> {
        self.local.start_machine(reference, readiness_timeout).await
    }

    pub(crate) async fn stop_machine(
        &mut self,
        reference: &str,
        force: bool,
        timeout: Duration,
    ) -> eyre::Result<MachineData> {
        self.local.stop_machine(reference, force, timeout).await
    }

    pub(crate) async fn remove_machine(
        &mut self,
        reference: &str,
        force: bool,
    ) -> eyre::Result<MachineData> {
        self.local.remove_machine(reference, force).await
    }

    pub(crate) async fn update_machine(
        &mut self,
        reference: &str,
        update: MachineUpdate,
    ) -> eyre::Result<MachineData> {
        self.local.update_machine(reference, update).await
    }

    pub(crate) async fn list_networks(&mut self) -> eyre::Result<Vec<NetworkDefinition>> {
        self.local.list_networks().await
    }

    pub(crate) async fn inspect_network(
        &mut self,
        name: &str,
    ) -> eyre::Result<Option<NetworkDefinition>> {
        self.local.inspect_network(name).await
    }

    pub(crate) async fn create_network(
        &mut self,
        name: String,
        topology: NetworkTopology,
        driver: NetworkDriver,
    ) -> eyre::Result<()> {
        self.local.create_network(name, topology, driver).await
    }

    pub(crate) async fn remove_network(&mut self, name: &str) -> eyre::Result<()> {
        self.local.remove_network(name).await
    }

    pub(crate) async fn set_machine_network(
        &mut self,
        reference: &str,
        network: ResolvedMachineNetwork,
    ) -> eyre::Result<MachineData> {
        self.local.set_machine_network(reference, network).await
    }

    pub(crate) async fn resolve_source(
        &mut self,
        positional: Option<&str>,
        template: &Template,
        pull: Option<(ImagePullPolicy, PullPolicy)>,
        progress: ImageProgressSender,
    ) -> eyre::Result<SourceResolution> {
        self.local
            .resolve_source(positional, template, pull, progress)
            .await
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
        self.local.ensure_name_available(name).await
    }

    pub(crate) async fn create_machine(
        &mut self,
        plan: &CreatePlan,
        source: SourceResolution,
        policy_config_dir: Option<&std::path::Path>,
        progress: ImageProgressSender,
    ) -> eyre::Result<MachineData> {
        self.local
            .create_machine(plan, source, policy_config_dir, progress)
            .await
    }

    pub(crate) async fn machine(&mut self, reference: &str) -> eyre::Result<AppMachine> {
        self.local.machine_handle(reference).await
    }

    pub(crate) async fn machine_start_options(
        &mut self,
        machine: &AppMachine,
        detached_cleanup: bool,
    ) -> eyre::Result<MachineStartOptions> {
        self.local
            .machine_start_options(machine, detached_cleanup)
            .await
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
