use crate::daemon::control::lobby::{categorize, Management};
use crate::lobby::{
    audit::Audit,
    caller::Caller,
    failure::{Code, Failure, Outcome},
    identity::{Action, Limits, Peer, Permissions, Principal},
    jobs::Registry,
    service::{create::CreateRequest, vm, Service, ServiceConfig},
};
use silod_spec::daemon::v1 as w;
use std::{sync::Arc, time::Duration};

pub(crate) struct Fixture {
    pub(crate) service: Service,
    pub(crate) management: Management,
    pub(crate) root: tempfile::TempDir,
}
pub(crate) async fn fixture() -> Fixture {
    let root = tempfile::Builder::new().prefix("lobby-").tempdir().unwrap();
    let (components, native) = if let Some(stage) = std::env::var_os("SILO_LOBBY_E2E_RUNTIME") {
        let stage = std::path::PathBuf::from(stage).canonicalize().unwrap();
        (
            libvm::ResolvedRuntimeComponents::from_paths(
                stage.join("bin/silo-vmm"),
                stage.join("bin/netd"),
                stage.join("assets/kernel-default"),
                stage.join("assets/initramfs"),
                stage.join("assets/agent"),
                stage.join("assets"),
            )
            .unwrap(),
            true,
        )
    } else {
        let binary = test_utils::mock_vmm_binary().to_path_buf();
        let kernel = root.path().join("kernel");
        let initramfs = root.path().join("initramfs");
        std::fs::write(&kernel, test_utils::direct_kernel::host_kernel("lobby")).unwrap();
        std::fs::write(&initramfs, b"inventory initramfs").unwrap();
        (
            libvm::ResolvedRuntimeComponents::from_paths(
                binary.clone(),
                binary.clone(),
                kernel,
                initramfs,
                binary,
                root.path().to_path_buf(),
            )
            .unwrap(),
            false,
        )
    };
    let mut config = libvm::RuntimeConfig::local(root.path().join("home"))
        .with_run_root(root.path().join("run"))
        .with_runtime_components(components.clone());
    if !native {
        config = config.with_virt_backend(libvm::VirtBackendOverride::Mock { scenario: None });
    }
    let runtime = libvm::Runtime::new(config.clone()).await.unwrap();
    let management = Management::for_test_runtime(root.path(), config, runtime, components);
    let service = Service::new(ServiceConfig {
        home: root.path().join("home"),
        config_dir: root.path().join("config"),
        management: management.clone(),
        settings: Default::default(),
        capability: "github.com/vandycknick/silo".into(),
        instance: "test-instance".into(),
        audit: Audit::open(root.path().join("home"), 1 << 20, 2).unwrap(),
        jobs: Arc::new(Registry::new(
            tokio_util::sync::CancellationToken::new(),
            64,
            Arc::new(crate::lobby::metrics::Metrics::new()),
        )),
        visible_names: Arc::new(|| Box::pin(async { Ok(Vec::new()) })),
        node_pin: None,
        lobby_hostname: "silo".into(),
        vm_nodes_enabled: false,
        consent: None,
    })
    .unwrap();
    Fixture {
        root,
        management,
        service,
    }
}
pub(crate) fn caller(principal: &str, actions: &[Action]) -> Caller {
    let peer = Peer {
        principals: vec![Principal::parse(principal).unwrap()],
        node_id: format!("node-{principal}"),
        node_name: "caller.tail.test".into(),
        login: if principal.starts_with("user:") {
            "owner@example.test".into()
        } else {
            String::new()
        },
        observed_at: chrono::Utc::now(),
        permissions: Permissions {
            actions: actions.to_vec(),
            limits: Limits {
                vms: 5,
                cpus: 8,
                memory: 32 << 30,
                disk: 200 << 30,
            },
            reason: String::new(),
        },
    };
    let fresh = peer.clone();
    Caller::new(
        peer,
        Arc::new(move || {
            let mut peer = fresh.clone();
            peer.observed_at = chrono::Utc::now();
            Box::pin(async move { Ok(peer) })
        }),
    )
}
pub(crate) async fn stopped_vm(fixture: &Fixture, name: &str, owner: &str) -> w::MachineSnapshot {
    stopped_vm_with_scope(fixture, name, owner, libvm::SecretScopePolicy::MachineOnly).await
}

pub(crate) async fn stopped_vm_with_scope(
    fixture: &Fixture,
    name: &str,
    owner: &str,
    scope: libvm::SecretScopePolicy,
) -> w::MachineSnapshot {
    let runtime = fixture.management.runtime().await.unwrap();
    let disk = fixture.root.path().join(format!("{name}.raw"));
    disk_image::ext4::Formatter::new(&disk, 4096, 256 * 1024)
        .and_then(|formatter| formatter.close())
        .unwrap();
    let machine = runtime
        .machine()
        .secret_scope(scope)
        .name(name)
        .cpus(2)
        .memory(libvm::Memory::gibibytes(4))
        .root_disk_size(1 << 30)
        .labels(
            [
                (vm::OWNER_LABEL.into(), owner.into()),
                (vm::NAME_LABEL.into(), name.into()),
                (
                    vm::INSTANCE_LABEL.into(),
                    fixture.service.config().instance.clone(),
                ),
                (vm::MODE_LABEL.into(), "none".into()),
            ]
            .into(),
        )
        .image_source(libvm::ImageSource::Disk(
            crate::commands::create::disk_create_request(disk, &Default::default()).unwrap(),
        ))
        .network(|network| network.none())
        .create()
        .await
        .unwrap();
    fixture.management.inspect(&machine.id()).await.unwrap()
}
impl Fixture {
    pub(crate) async fn running_vm(&self, owner: &str) -> Outcome<String> {
        if std::env::var_os("SILO_LOBBY_E2E_RUNTIME").is_none() {
            return Err(Failure::new(
                Code::Unavailable,
                "SILO_LOBBY_E2E_RUNTIME is required",
            ));
        }
        #[cfg(target_os = "linux")]
        if !std::path::Path::new("/dev/kvm").exists() {
            return Err(Failure::new(Code::Unavailable, "/dev/kvm is required"));
        }
        let caller = caller(owner, &[Action::Create, Action::Read, Action::Start]);
        let image = std::env::var("SILO_LOBBY_E2E_IMAGE")
            .unwrap_or_else(|_| "docker.io/library/alpine:latest".into());
        let operation = self
            .service
            .create(
                &caller,
                CreateRequest {
                    image,
                    name: format!("guest-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
                    ..Default::default()
                },
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(240), async {
            loop {
                let (operation, mut changed) =
                    self.service.jobs().observe(&caller.peer, &operation.id)?;
                if let Some(error) = operation.error {
                    return Err(error);
                }
                if let Some(completion) = operation.completion {
                    return Ok(completion.vm_id);
                }
                changed.changed().await.map_err(|_| {
                    Failure::new(Code::Unavailable, "operation ended without completion")
                })?;
            }
        })
        .await
        .map_err(|_| Failure::new(Code::Unavailable, "guest startup timed out"))?
    }
    pub(crate) async fn cleanup_vm(&self, id: &str) -> Outcome<()> {
        let snapshot = self
            .management
            .inspect(id)
            .await
            .map_err(|status| categorize(&status))?;
        if let Some(run) = snapshot.run_id {
            self.management
                .stop(
                    id,
                    Some(run.clone()),
                    true,
                    Some(prost_types::Duration {
                        seconds: 10,
                        nanos: 0,
                    }),
                )
                .await
                .map_err(|status| categorize(&status))?;
            self.management
                .remove_after_run(id, &run)
                .await
                .map_err(|status| categorize(&status))
        } else {
            self.management
                .remove(id)
                .await
                .map_err(|status| categorize(&status))
        }
    }
}
