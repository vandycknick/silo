use crate::control::{socket, ControlState, Service};
use libvm::{HostPaths, Runtime, RuntimeConfig};
use silo_config::GlobalConfig;
use silod_spec::daemon::v1 as w;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;
use tonic::{Request, Status};
fn state(root: &std::path::Path) -> Arc<ControlState> {
    let host = HostPaths::new(root.join("home"), root.join("config"));
    let global = GlobalConfig::default();
    let generation = uuid::Uuid::new_v4();
    let features = silo_config::FeatureSelection {
        system: false,
        tailscale: false,
    };
    let publisher = Arc::new(
        crate::status::StatusPublisher::new(
            &host,
            generation,
            features,
            global.daemon_identity(features).unwrap(),
            None,
        )
        .unwrap(),
    );
    Arc::new(ControlState::new(host, global, generation, publisher))
}
#[tokio::test]
async fn status_does_not_initialize_runtime() {
    let root = tempfile::tempdir().unwrap();
    let state = state(root.path());
    state
        .publisher
        .set_core(silod_spec::status::CorePhase::Ready, None)
        .unwrap();
    assert_eq!(
        state.get_status().await.unwrap().core,
        w::CorePhase::Ready as i32
    );
    assert!(!root.path().join("home/state.db").exists());
    assert!(state.components.get().is_none());
    assert!(state.runtime.get().is_none());
}
#[tokio::test]
async fn private_socket_singleton_and_inode_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("control");
    let bound = socket::BoundServer::bind_at(state(root.path()), dir.clone()).unwrap();
    assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        std::fs::metadata(dir.join("control.sock")).unwrap().mode() & 0o777,
        0o600
    );
    let _client = tokio::net::UnixStream::connect(dir.join("control.sock"))
        .await
        .unwrap();
    assert!(socket::BoundServer::bind_at(state(root.path()), dir.clone()).is_err());
    std::fs::remove_file(dir.join("control.sock")).unwrap();
    std::fs::write(dir.join("control.sock"), b"replacement").unwrap();
    drop(bound);
    assert_eq!(
        std::fs::read(dir.join("control.sock")).unwrap(),
        b"replacement"
    );
    assert!(socket::BoundServer::bind_at(state(root.path()), dir).is_err());
}
#[tokio::test]
async fn unsafe_socket_and_directory_rejected() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("control");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(root.path().join("victim"), dir.join("control.sock")).unwrap();
    assert!(socket::BoundServer::bind_at(state(root.path()), dir.clone()).is_err());
    std::fs::remove_file(dir.join("control.sock")).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(socket::BoundServer::bind_at(state(root.path()), dir).is_err());
}
#[tokio::test]
async fn canceled_waiter_does_not_drain_accepted_work() {
    let root = tempfile::tempdir().unwrap();
    let state = state(root.path());
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let owner = state.clone();
    let waiter = tokio::spawn(async move {
        owner
            .mutate(&Request::new(()), false, async move {
                let _ = entered_tx.send(());
                release_rx.await.unwrap();
                Ok::<_, Status>(())
            })
            .await
    });
    entered_rx.await.unwrap();
    waiter.abort();
    state.seal_mutations().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), state.drain_mutations())
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    state.drain_mutations().await.unwrap();
    assert!(state.admit(&Request::new(()), false).await.is_err());
}
#[tokio::test]
async fn stale_helper_and_public_stopping_requests_rejected() {
    let root = tempfile::tempdir().unwrap();
    let state = state(root.path());
    let generation = uuid::Uuid::new_v4();
    state.set_helper_generation(Some(generation)).await;
    state.begin_stopping().await.unwrap();
    assert!(state.admit(&Request::new(()), false).await.is_err());
    let mut request = Request::new(());
    request.metadata_mut().insert(
        "x-silo-helper-generation",
        generation.to_string().parse().unwrap(),
    );
    drop(state.admit(&request, false).await.unwrap());
    request.metadata_mut().insert(
        "x-silo-helper-generation",
        uuid::Uuid::new_v4().to_string().parse().unwrap(),
    );
    assert!(state.admit(&request, false).await.is_err());
}
/// Real stopped disk lifecycle. Explicit assets and a real Linux root disk are required;
/// this test never synthesizes a VMM or a disk image.
#[tokio::test]
#[ignore = "requires SILO_TEST_RUNTIME_ROOT and SILO_TEST_DISK_IMAGE"]
async fn native_disk_create_inspect_update_remove() {
    use w::machine_service_server::MachineService;
    let root = tempfile::tempdir().unwrap();
    let state = state(root.path());
    let runtime_root = std::env::var_os("SILO_TEST_RUNTIME_ROOT").expect("SILO_TEST_RUNTIME_ROOT");
    let config = RuntimeConfig::local(state.host.home()).with_runtime_root(runtime_root);
    state
        .components
        .set(config.resolve_components().unwrap())
        .unwrap();
    let runtime = Runtime::new(config).await.unwrap();
    state.runtime.set(runtime).unwrap();
    let state = Service(state);
    let disk = std::path::PathBuf::from(
        std::env::var_os("SILO_TEST_DISK_IMAGE").expect("SILO_TEST_DISK_IMAGE"),
    )
    .canonicalize()
    .unwrap();
    let config = w::NormalizedMachineCreate {
        name: Some("control-disk".into()),
        process: Some(w::ProcessConfig::default()),
        retention: w::Retention::Persistent as i32,
        network: Some(w::ResolvedNetwork {
            attachment: Some(w::resolved_network::Attachment::None(())),
        }),
        agent: Some(w::Agent {
            mode: Some(w::agent::Mode::None(())),
        }),
        cpus: Some(2),
        memory_bytes: Some(512 * 1024 * 1024),
        ..Default::default()
    };
    let response = state
        .create_machine(Request::new(w::CreateMachineRequest {
            configuration: Some(config),
            source: Some(w::create_machine_request::Source::DiskPath(
                silo_vm_control::path_to_wire(&disk),
            )),
        }))
        .await
        .unwrap();
    use futures::StreamExt;
    let mut stream = response.into_inner();
    let mut created = None;
    while let Some(event) = stream.next().await {
        if let Some(w::create_machine_event::Event::Machine(machine)) = event.unwrap().event {
            created = Some(machine);
        }
    }
    let created = created.unwrap();
    let reference = w::MachineRef {
        reference: Some(w::machine_ref::Reference::Id(created.id.clone())),
    };
    let inspected = state
        .inspect_machine(Request::new(reference.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(inspected.name, "control-disk");
    assert_eq!(inspected.spec.unwrap().hardware.unwrap().cpus, Some(2));
    state
        .update_machine(Request::new(w::UpdateMachineRequest {
            machine: Some(reference.clone()),
            update: Some(w::MachineUpdate {
                name: Some("control-renamed".into()),
                labels: Some(w::StringMap::default()),
                ..Default::default()
            }),
        }))
        .await
        .unwrap();
    state
        .remove_machine(Request::new(w::RemoveMachineRequest {
            machine: Some(reference),
        }))
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_mutations_fail_before_runtime_or_admission() {
    use w::{
        machine_service_server::MachineService, network_service_server::NetworkService,
        runtime_service_server::RuntimeService,
    };
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    owner.seal_mutations().await;
    let service = Service(owner.clone());
    assert_eq!(
        service
            .start_machine(Request::new(w::StartMachineRequest::default()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        service
            .stop_machine(Request::new(w::StopMachineRequest::default()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        service
            .update_machine(Request::new(w::UpdateMachineRequest::default()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        service
            .set_machine_secret(Request::new(w::SetMachineSecretRequest::default()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        service
            .create_network_definition(Request::new(w::CreateNetworkDefinitionRequest::default()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    let result = service
        .create_machine(Request::new(w::CreateMachineRequest::default()))
        .await;
    assert!(matches!(&result, Err(e) if e.code() == tonic::Code::InvalidArgument));
    let result = service
        .resolve_image(Request::new(w::ResolveImageRequest {
            reference: "valid".into(),
            pull_policy: 0,
        }))
        .await;
    assert!(matches!(&result, Err(e) if e.code() == tonic::Code::InvalidArgument));
    let result = service
        .pull_image(Request::new(w::PullImageRequest {
            reference: String::new(),
        }))
        .await;
    assert!(matches!(&result, Err(e) if e.code() == tonic::Code::InvalidArgument));
    assert!(owner.runtime.get().is_none());
    assert!(owner.components.get().is_none());
    assert_eq!(owner.capacity.available_permits(), 64);
}

#[tokio::test]
async fn mutation_capacity_and_shutdown_marker_are_enforced() {
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let mut permits = Vec::new();
    for _ in 0..64 {
        permits.push(owner.admit(&Request::new(()), false).await.unwrap());
    }
    assert_eq!(
        owner
            .admit(&Request::new(()), false)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    drop(permits);
    std::fs::create_dir_all(owner.host.home().join("taild")).unwrap();
    // Even an unreadable/symlink marker seals protected operations. No repair occurs.
    std::os::unix::fs::symlink(
        root.path().join("missing"),
        owner.host.home().join("taild/shutdown"),
    )
    .unwrap();
    assert_eq!(
        owner
            .admit(&Request::new(()), true)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    drop(owner.admit(&Request::new(()), false).await.unwrap());
    assert!(
        std::fs::symlink_metadata(owner.host.home().join("taild/shutdown"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[tokio::test]
async fn drain_rpc_requires_generation_and_sealed_admission() {
    use w::daemon_service_server::DaemonService;
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let service = Service(owner.clone());
    let request = || {
        Request::new(w::DrainMutationsRequest {
            expected_generation: owner.generation.to_string(),
        })
    };
    assert_eq!(
        service.drain_mutations(request()).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    owner.seal_mutations().await;
    assert_eq!(
        service
            .drain_mutations(Request::new(w::DrainMutationsRequest {
                expected_generation: uuid::Uuid::new_v4().to_string()
            }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    service.drain_mutations(request()).await.unwrap();
}

#[tokio::test]
async fn unsafe_owner_lock_is_rejected_without_following_or_blocking() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("control");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lock = dir.join("owner.lock");
    nix::unistd::mkfifo(
        &lock,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(socket::BoundServer::bind_at(state(root.path()), dir.clone()).is_err());
    std::fs::remove_file(&lock).unwrap();
    let victim = root.path().join("victim");
    std::fs::write(&victim, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&victim, &lock).unwrap();
    assert!(socket::BoundServer::bind_at(state(root.path()), dir.clone()).is_err());
    assert_eq!(std::fs::read(victim).unwrap(), b"unchanged");
    assert!(!dir.join("control.sock").exists());
}

#[tokio::test]
async fn closing_response_streams_does_not_cancel_native_mutations() {
    use futures::StreamExt;
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<w::LogChunk, Status>>(1);
    let mut response = owner.response_stream(rx);
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let worker = owner.clone();
    let waiter = tokio::spawn(async move {
        worker
            .mutate(&Request::new(()), false, async move {
                entered_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok::<_, Status>(())
            })
            .await
    });
    entered_rx.await.unwrap();
    owner.stream_shutdown.cancel();
    assert!(response.next().await.is_none());
    drop(response);
    tx.closed().await;
    owner.seal_mutations().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), owner.drain_mutations())
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    waiter.await.unwrap().unwrap();
    owner.drain_mutations().await.unwrap();
}

#[tokio::test]
async fn helper_reports_preserve_instance_and_reject_stale_generations() {
    use w::daemon_service_server::DaemonService;
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let generation = uuid::Uuid::new_v4();
    owner.set_helper_generation(Some(generation)).await;
    let service = Service(owner.clone());
    let report = |generation: uuid::Uuid, instance: &str| {
        let mut request = Request::new(w::TailscaleStatusReport {
            helper_generation: generation.to_string(),
            status: Some(w::ComponentStatus {
                enabled: true,
                state: w::ComponentState::NeedsAuth as i32,
                shutdown_protection: w::ShutdownProtection::Unavailable as i32,
                ..Default::default()
            }),
            instance: Some(instance.into()),
        });
        request.metadata_mut().insert(
            "x-silo-helper-generation",
            generation.to_string().parse().unwrap(),
        );
        request
    };
    let instance = "0123456789abcdef0123456789abcdef";
    service
        .report_tailscale_status(report(generation, instance))
        .await
        .unwrap();
    let replacement = uuid::Uuid::new_v4();
    owner.set_helper_generation(Some(replacement)).await;
    assert_eq!(
        service
            .report_tailscale_status(report(generation, instance))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    service
        .report_tailscale_status(report(replacement, instance))
        .await
        .unwrap();
    assert_eq!(
        service
            .report_tailscale_status(report(replacement, "bad"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        service
            .report_tailscale_status(report(replacement, "ffffffffffffffffffffffffffffffff"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        owner.get_status().await.unwrap().tailscale.unwrap().state,
        w::ComponentState::NeedsAuth as i32
    );
    assert!(owner.runtime.get().is_none());
}

#[tokio::test]
async fn real_uds_server_stops_without_runtime_initialization() {
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let dir = root.path().join("control");
    let server = socket::BoundServer::bind_at(owner.clone(), dir.clone()).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    let client = tokio::net::UnixStream::connect(dir.join("control.sock"))
        .await
        .unwrap();
    drop(client);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!dir.join("control.sock").exists());
    assert!(owner.runtime.get().is_none());
    assert!(owner.components.get().is_none());
}
