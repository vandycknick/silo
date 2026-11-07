use crate::config::GlobalConfig;
use crate::daemon::control::{socket, ControlState, Service};
use libvm::HostPaths;
use silod_spec::daemon::v1 as w;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;
use tonic::{Request, Status};
fn state(root: &std::path::Path) -> Arc<ControlState> {
    let host = HostPaths::new(root.join("home"), root.join("config"));
    let global = GlobalConfig::default();
    let generation = uuid::Uuid::new_v4();
    let features = crate::config::FeatureSelection {
        system: false,
        tailscale: false,
    };
    let publisher = Arc::new(
        crate::daemon::status::StatusPublisher::new(
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
            platform: None,
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
    owner
        .publisher
        .set_tailscale(silod_spec::status::ComponentStatus {
            enabled: true,
            state: silod_spec::status::ComponentState::Starting,
            diagnostic: None,
            approval_url: None,
            dns_name: None,
            restart_count: 3,
            shutdown_protection: silod_spec::status::ShutdownProtection::Unavailable,
        })
        .unwrap();
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
    assert_eq!(
        owner
            .get_status()
            .await
            .unwrap()
            .tailscale
            .unwrap()
            .restart_count,
        3
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

#[tokio::test]
async fn stale_helper_reads_rejected_at_every_rpc_service_boundary() {
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let generation = uuid::Uuid::new_v4();
    owner.set_helper_generation(Some(generation)).await;
    let dir = root.path().join("control");
    let server = socket::BoundServer::bind_at(owner.clone(), dir.clone()).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    let path = dir.join("control.sock");
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .unwrap();
    let stale = || {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "x-silo-helper-generation",
            uuid::Uuid::new_v4().to_string().parse().unwrap(),
        );
        request
    };
    let mut daemon = w::daemon_service_client::DaemonServiceClient::new(channel.clone());
    assert_eq!(
        daemon.get_status(stale()).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        daemon.get_runtime_info(stale()).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    let mut machine = w::machine_service_client::MachineServiceClient::new(channel.clone());
    assert_eq!(
        machine.list_machines(stale()).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    let mut network = w::network_service_client::NetworkServiceClient::new(channel.clone());
    assert_eq!(
        network
            .list_network_definitions(stale())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let mut runtime = w::runtime_service_client::RuntimeServiceClient::new(channel);
    assert_eq!(
        runtime
            .propose_machine_name(stale())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let mut current = Request::new(());
    current.metadata_mut().insert(
        "x-silo-helper-generation",
        generation.to_string().parse().unwrap(),
    );
    owner.begin_stopping().await.unwrap();
    assert!(daemon.get_status(current).await.is_ok());
    assert!(daemon.get_status(Request::new(())).await.is_ok());
    assert!(owner.runtime.get().is_none());
    assert!(owner.components.get().is_none());
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn draining_helper_can_finish_mutations_before_final_seal() {
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let generation = uuid::Uuid::new_v4();
    owner.set_helper_generation(Some(generation)).await;
    owner.begin_stopping().await.unwrap();
    assert!(owner.admit(&Request::new(()), false).await.is_err());
    let mut request = Request::new(());
    request.metadata_mut().insert(
        "x-silo-helper-generation",
        generation.to_string().parse().unwrap(),
    );
    let permit = owner.admit(&request, false).await.unwrap();
    // This represents helper exit: invalidate identity before final admission
    // seal, but do not count cancellation of its waiter as native completion.
    owner.set_helper_generation(None).await;
    owner.seal_mutations().await;
    assert!(owner.admit(&request, false).await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), owner.drain_mutations())
            .await
            .is_err()
    );
    drop(permit);
    tokio::time::timeout(Duration::from_secs(1), owner.drain_mutations())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ownership_acquisition_does_not_replace_socket_and_retains_both_locks() {
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let dir = root.path().join("control");
    let lifetime_path = owner.host.home().join("daemon/daemon.lock");
    let lifetime = crate::daemon::supervisor::LifetimeLock::acquire(&lifetime_path).unwrap();
    let ownership = socket::SocketOwnership::acquire_at(dir.clone()).unwrap();
    let stale = tokio::net::UnixListener::bind(dir.join("control.sock")).unwrap();
    let before = std::fs::metadata(dir.join("control.sock")).unwrap().ino();
    assert!(crate::daemon::supervisor::LifetimeLock::acquire(&lifetime_path).is_err());
    assert!(socket::SocketOwnership::acquire_at(dir.clone()).is_err());
    assert_eq!(
        std::fs::metadata(dir.join("control.sock")).unwrap().ino(),
        before
    );
    drop(stale);
    let server = ownership.bind(owner).unwrap();
    assert!(crate::daemon::supervisor::LifetimeLock::acquire(&lifetime_path).is_err());
    assert!(socket::SocketOwnership::acquire_at(dir.clone()).is_err());
    drop(server);
    assert!(!dir.join("control.sock").exists());
    drop(lifetime);
    assert!(crate::daemon::supervisor::LifetimeLock::acquire(&lifetime_path).is_ok());
    assert!(socket::SocketOwnership::acquire_at(dir).is_ok());
}

#[tokio::test]
async fn marker_drain_tracks_real_work_without_queueing_ahead_of_stops() {
    use w::daemon_service_server::DaemonService;
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let initial = owner.admit(&Request::new(()), true).await.unwrap();
    std::fs::create_dir_all(owner.host.home().join("taild")).unwrap();
    std::fs::write(owner.host.home().join("taild/shutdown"), b"sealed").unwrap();
    let service = Service(owner.clone());
    let drain_request = || {
        Request::new(w::DrainMutationsRequest {
            expected_generation: owner.generation.to_string(),
        })
    };
    let mut drain = Box::pin(service.drain_mutations(drain_request()));
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut drain)
        .await
        .is_err());
    // Drain does not consume/queue all semaphore permits: safe stop admission
    // remains available while protected mutations are sealed by the marker.
    let stop = owner.admit(&Request::new(()), false).await.unwrap();
    assert!(owner.admit(&Request::new(()), true).await.is_err());
    drop(initial);
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut drain)
        .await
        .is_err());
    drop(stop);
    tokio::time::timeout(Duration::from_secs(1), &mut drain)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        service
            .drain_mutations(Request::new(w::DrainMutationsRequest {
                expected_generation: uuid::Uuid::new_v4().to_string(),
            }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    owner.seal_mutations().await;
    assert!(owner.admit(&Request::new(()), false).await.is_err());
}

#[tokio::test]
async fn unsafe_marker_parent_seals_admission_and_allows_drain() {
    use w::daemon_service_server::DaemonService;
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    std::os::unix::fs::symlink(root.path().join("missing"), owner.host.home().join("taild"))
        .unwrap();
    assert!(owner.admit(&Request::new(()), true).await.is_err());
    drop(owner.admit(&Request::new(()), false).await.unwrap());
    Service(owner.clone())
        .drain_mutations(Request::new(w::DrainMutationsRequest {
            expected_generation: owner.generation.to_string(),
        }))
        .await
        .unwrap();
}

#[tokio::test]
async fn shutdown_only_real_transport_enforces_every_protocol_method() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = state(root.path());
    Arc::get_mut(&mut owner).unwrap().shutdown_only = true;
    let dir = root.path().join("control");
    let server = socket::BoundServer::bind_at(owner.clone(), dir.clone()).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    let path = dir.join("control.sock");
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .unwrap();
    let mut daemon = w::daemon_service_client::DaemonServiceClient::new(channel.clone());
    assert_eq!(
        daemon.get_status(()).await.unwrap().into_inner().generation,
        owner.generation.to_string()
    );
    std::fs::create_dir_all(owner.host.home().join("taild")).unwrap();
    std::fs::write(owner.host.home().join("taild/shutdown"), b"sealed").unwrap();
    daemon
        .drain_mutations(w::DrainMutationsRequest {
            expected_generation: owner.generation.to_string(),
        })
        .await
        .unwrap();
    // Parse the authoritative protocol, so additions must explicitly be admitted.
    let mut service = "";
    let mut denied = 0;
    for line in include_str!("../../../../../specs/silod-spec/proto/daemon.proto").lines() {
        if let Some(declaration) = line.strip_prefix("service ") {
            service = declaration.split_whitespace().next().unwrap();
        } else if let Some(declaration) = line.trim().strip_prefix("rpc ") {
            let method = declaration.split('(').next().unwrap();
            if matches!(
                (service, method),
                (
                    "DaemonService",
                    "GetStatus" | "GetLiveCapabilities" | "DrainMutations"
                ) | (
                    "MachineService",
                    "ListMachines" | "InspectInventory" | "InspectMachine" | "StopMachine"
                )
            ) {
                continue;
            }
            let uri = format!("/silo.daemon.v1.{service}/{method}");
            let mut grpc = tonic::client::Grpc::new(channel.clone());
            grpc.ready().await.unwrap();
            let result: Result<tonic::Response<()>, tonic::Status> = grpc
                .unary(
                    Request::new(()),
                    tonic::codegen::http::uri::PathAndQuery::try_from(uri.clone()).unwrap(),
                    tonic_prost::ProstCodec::default(),
                )
                .await;
            assert_eq!(
                result.unwrap_err().code(),
                tonic::Code::PermissionDenied,
                "{uri}"
            );
            denied += 1;
        }
    }
    assert!(denied > 20);
    let mut machines = w::machine_service_client::MachineServiceClient::new(channel);
    // Allowed methods reach validation rather than the URI denial.
    assert_eq!(
        machines
            .inspect_machine(w::MachineRef::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        machines
            .inspect_inventory(w::MachineRef::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        machines
            .stop_machine(w::StopMachineRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert!(owner.components.get().is_none());
    assert!(owner.runtime.get().is_none());
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn early_rejection_precedes_sealed_and_exhausted_daemon_admission() {
    use vm_spec::live::{LiveBackend, LiveLane, LiveOperation, LiveReasonCode};
    use w::{
        daemon_service_client::DaemonServiceClient, machine_service_client::MachineServiceClient,
        runtime_service_client::RuntimeServiceClient,
    };
    let root = tempfile::tempdir().unwrap();
    let mut owner = state(root.path());
    let config = libvm::RuntimeConfig::local(root.path().join("home"))
        .with_supervisor_path(test_utils::mock_vmm_binary())
        .with_virt_backend(libvm::VirtBackendOverride::Vz)
        .with_run_root(root.path().join("run"));
    Arc::get_mut(&mut owner).unwrap().config = config;
    owner.begin_stopping().await.unwrap();
    owner.seal_mutations().await;
    let permits = owner.capacity.clone().acquire_many_owned(64).await.unwrap();
    let status_before = std::fs::read(owner.host.home().join("daemon/status.json")).unwrap();
    let control = root.path().join("control");
    let server = socket::BoundServer::bind_at(owner.clone(), control.clone()).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    let socket = control.join("control.sock");
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            async move {
                tokio::net::UnixStream::connect(socket)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .unwrap();
    let mut daemon = DaemonServiceClient::new(channel.clone());
    assert_eq!(
        daemon.get_status(()).await.unwrap().into_inner().core,
        w::CorePhase::Stopping as i32
    );
    let mut machines = MachineServiceClient::new(channel.clone());
    let mut runtime = RuntimeServiceClient::new(channel);
    let host = daemon.get_live_capabilities(()).await.unwrap().into_inner();
    let host = silo_vm_control::live::host_from_wire(host).unwrap();
    assert_eq!(host.backend, LiveBackend::Vz);
    assert_eq!(host.scope, vm_spec::live::LiveScope::Host);
    let request = || w::LiveMachineRequest {
        machine: Some(w::MachineRef {
            reference: Some(w::machine_ref::Reference::Name("not-created".into())),
        }),
    };
    let fork_request = || w::LiveForkRequest {
        machine: request().machine,
        operation_id: "00000000-0000-4000-8000-0000000000aa".into(),
        children: vec![w::LiveForkChild {
            name: "child".into(),
            activation_hook: None,
            destination: Some(w::ForkDestination::default()),
        }],
        max_children: 16,
        resume_policy: w::CaptureResumePolicy::ResumeIfAcquired as i32,
        resources: Some(silo_vm_control::stopped::restore_resources_to_wire(
            libvm::RestoreResourcePolicy::default(),
        )),
    };
    let results = [
        (
            LiveOperation::Pause,
            machines.pause_machine(request()).await.unwrap_err(),
        ),
        (
            LiveOperation::Capture,
            machines
                .capture_execution(w::LiveCaptureRequest {
                    machine: request().machine,
                    name: None,
                    resume_policy: w::CaptureResumePolicy::ResumeIfAcquired as i32,
                })
                .await
                .unwrap_err(),
        ),
        (
            LiveOperation::Fork,
            machines.fork_execution(fork_request()).await.unwrap_err(),
        ),
        (
            LiveOperation::Restore,
            runtime
                .restore_snapshot(w::RestoreStorageSnapshotRequest {
                    snapshot: Some(silo_vm_control::stopped::reference_to_wire(
                        &libvm::SnapshotRef::Image("checkpoint".into()),
                    )),
                    name: Some("child".into()),
                    external_resources: Some(silo_vm_control::stopped::policy_to_wire(
                        &libvm::ExternalResourcePolicy::Reject,
                    )),
                    activation_hook: None,
                    resources: None,
                })
                .await
                .unwrap_err(),
        ),
    ];
    for (expected, status) in results {
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        match silo_vm_control::errors::status_to_native_error(&status).unwrap() {
            libvm::LibVmError::LiveOperationUnsupported {
                operation,
                backend,
                lane,
                reason,
            } => {
                assert_eq!(operation, expected);
                assert_eq!(backend, LiveBackend::Vz);
                assert_eq!(lane, LiveLane::NotApplicable);
                assert_eq!(reason.code, LiveReasonCode::BackendExcluded);
            }
            error => panic!("not a typed live refusal: {error:?}"),
        }
    }
    // Malformed fork requests and operation references are refused before
    // capability evidence, admission or runtime initialization.
    let mut duplicate = fork_request();
    duplicate.children.push(duplicate.children[0].clone());
    let mut nil = fork_request();
    nil.operation_id = "00000000-0000-0000-0000-000000000000".into();
    for request in [duplicate, nil] {
        assert_eq!(
            machines.fork_execution(request).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
    let invalid = || w::ForkOperationRef {
        operation_id: "00000000-0000-0000-0000-000000000000".into(),
    };
    assert_eq!(
        runtime.get_fork(invalid()).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        runtime.cancel_fork(invalid()).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    assert!(owner.runtime.get().is_none());
    assert!(owner.components.get().is_none());
    assert_eq!(owner.capacity.available_permits(), 0);
    assert!(!root.path().join("run").exists());
    assert!(!owner.host.home().join("state.db").exists());
    assert_eq!(
        std::fs::read(owner.host.home().join("daemon/status.json")).unwrap(),
        status_before
    );
    drop(permits);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stopped_retention_mutations_obey_sealed_admission_without_runtime_initialization() {
    use w::runtime_service_server::RuntimeService;
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    owner.begin_stopping().await.unwrap();
    owner.seal_mutations().await;
    let service = Service(owner.clone());
    let reference =
        silo_vm_control::stopped::reference_to_wire(&"image:checkpoint".parse().unwrap());
    assert_eq!(
        service
            .release_snapshot_retention(Request::new(reference))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable,
    );
    assert_eq!(
        service
            .remove_image_alias(Request::new(w::Name {
                name: "checkpoint".into()
            }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable,
    );
    assert!(owner.runtime.get().is_none());
    assert!(owner.components.get().is_none());
    assert_eq!(owner.capacity.available_permits(), 64);
    assert!(!owner.host.home().join("state.db").exists());
}

#[tokio::test]
async fn malformed_stopped_contracts_fail_before_native_initialization() {
    use w::{machine_service_server::MachineService, runtime_service_server::RuntimeService};
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let service = Service(owner.clone());
    let machine = Some(w::MachineRef {
        reference: Some(w::machine_ref::Reference::Name("source".into())),
    });
    assert_eq!(
        service
            .fork_stopped(Request::new(w::StoppedForkRequest {
                machine: machine.clone(),
                name: Some("child".into()),
                external_resources: None,
            }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument,
    );
    assert_eq!(
        service
            .snapshot_stopped(Request::new(w::CreateStorageSnapshotRequest {
                machine: machine.clone(),
                name: None,
                external_resources: Some(w::ExternalResourcePolicy::default()),
            }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument,
    );
    assert_eq!(
        service
            .restore_snapshot(Request::new(w::RestoreStorageSnapshotRequest::default()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument,
    );
    assert_eq!(
        service
            .remove_image_alias(Request::new(w::Name {
                name: "sha256:invalid".into()
            }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument,
    );
    let reject = || {
        Some(silo_vm_control::stopped::policy_to_wire(
            &libvm::ExternalResourcePolicy::Reject,
        ))
    };
    for name in ["INVALID", "trailing-", "contains space"] {
        assert_eq!(
            service
                .fork_stopped(Request::new(w::StoppedForkRequest {
                    machine: machine.clone(),
                    name: Some(name.into()),
                    external_resources: reject(),
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument,
        );
        assert_eq!(
            service
                .restore_snapshot(Request::new(w::RestoreStorageSnapshotRequest {
                    snapshot: Some(silo_vm_control::stopped::reference_to_wire(
                        &"image:checkpoint".parse().unwrap()
                    )),
                    name: Some(name.into()),
                    external_resources: reject(),
                    activation_hook: None,
                    resources: None,
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument,
        );
    }
    assert_eq!(
        service
            .snapshot_stopped(Request::new(w::CreateStorageSnapshotRequest {
                machine: machine.clone(),
                name: Some("invalid alias".into()),
                external_resources: reject(),
            }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument,
    );
    let mappings = libvm::ExternalResourcePolicy::Map {
        mappings: vec![libvm::ExternalResourceMapping {
            resource: libvm::ExternalResourceKey::Disk { order: 1 },
            path: "/must/not/open.raw".into(),
        }],
    };
    assert_eq!(
        service
            .snapshot_stopped(Request::new(w::CreateStorageSnapshotRequest {
                machine,
                name: None,
                external_resources: Some(silo_vm_control::stopped::policy_to_wire(&mappings)),
            }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument,
    );
    assert!(owner.runtime.get().is_none());
    assert!(owner.components.get().is_none());
    assert!(!owner.host.home().join("state.db").exists());
}

#[tokio::test]
async fn pause_local_and_daemon_routes_share_durable_authority_across_adapters() {
    use vm_spec::live::{LiveAvailability, LiveCapability, LiveCapabilityVector, LiveLane};
    use w::machine_service_client::MachineServiceClient;
    let root = tempfile::Builder::new()
        .prefix("silo-pause-api-")
        .tempdir()
        .unwrap();
    let binary = test_utils::mock_vmm_binary();
    for name in ["kernel", "initramfs", "agent"] {
        let path = root.path().join(name);
        let bytes = if name == "kernel" {
            test_utils::direct_kernel::host_kernel("pause-api")
        } else {
            b"scenario-asset".to_vec()
        };
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let supported = LiveCapability {
        native: true,
        availability: LiveAvailability::Supported,
    };
    let scenario = test_utils::Scenario {
        lifecycle: Some(Default::default()),
        live: Some(test_utils::LiveScenario {
            lane: LiveLane::KvmX86_64,
            host: LiveCapabilityVector {
                pause: supported.clone(),
                capture: supported.clone(),
                restore: supported.clone(),
                fork: supported.clone(),
                incremental: supported,
            },
            machine: None,
        }),
        ..Default::default()
    };
    let scenario_path = root.path().join("scenario.json");
    scenario.write_to(&scenario_path).unwrap();
    let components = libvm::ResolvedRuntimeComponents::from_paths(
        binary.to_path_buf(),
        binary.to_path_buf(),
        root.path().join("kernel"),
        root.path().join("initramfs"),
        root.path().join("agent"),
        root.path().to_path_buf(),
    )
    .unwrap();
    let config = libvm::RuntimeConfig::local(root.path().join("home"))
        .with_run_root(root.path().join("run"))
        .with_runtime_components(components.clone())
        .with_mock_vmm(&scenario_path);
    let runtime = libvm::Runtime::new(config.clone()).await.unwrap();
    let disk = root.path().join("root.raw");
    disk_image::ext4::Formatter::new(&disk, 4096, 256 * 1024)
        .and_then(|formatter| formatter.close())
        .unwrap();
    let machine = runtime
        .machine()
        .name("pause-api")
        .image_source(libvm::ImageSource::Disk(
            crate::commands::create::disk_create_request(disk, &Default::default()).unwrap(),
        ))
        .network(|network| network.none())
        .create()
        .await
        .unwrap();
    let started = machine.start().await.unwrap();
    assert_eq!(
        machine
            .wait_ready(Duration::from_secs(10))
            .await
            .unwrap()
            .outcome,
        libvm::MachineReadinessOutcome::Ready
    );
    struct Cleanup(Option<nix::unistd::Pid>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(pid) = self.0 {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
            }
        }
    }
    let pid: i32 = std::fs::read_to_string(
        root.path()
            .join("run/machines")
            .join(machine.id())
            .join("vm.pid"),
    )
    .unwrap()
    .trim()
    .parse()
    .unwrap();
    let mut cleanup = Cleanup(Some(nix::unistd::Pid::from_raw(pid)));
    let mut owner = state(root.path());
    Arc::get_mut(&mut owner).unwrap().config = config.clone();
    assert!(owner.runtime.set(runtime).is_ok());
    assert!(owner.components.set(components).is_ok());
    let control = root.path().join("control");
    let server = socket::BoundServer::bind_at(owner, control.clone()).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    let socket = control.join("control.sock");
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            async move {
                tokio::net::UnixStream::connect(socket)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .unwrap();
    let mut daemon = MachineServiceClient::new(channel);
    let request = || w::LiveMachineRequest {
        machine: Some(w::MachineRef {
            reference: Some(w::machine_ref::Reference::Name("pause-api".into())),
        }),
    };
    let parked = silo_vm_control::snapshots::snapshot_from_wire(
        daemon.pause_machine(request()).await.unwrap().into_inner(),
    )
    .unwrap();
    assert_eq!(parked.status.label(), "paused");
    assert!(!parked.status.ready());
    let authority = parked.lifecycle.unwrap().lifecycle.current_pause.unwrap();
    assert_eq!(authority.token.owner, vm_spec::lifecycle::PauseOwner::User);
    assert_eq!(parked.run_id.as_ref(), Some(&started.run_id));
    let mut local = crate::api::AppApi::local(config);
    let resumed = local.resume_machine("pause-api").await.unwrap();
    assert_eq!(resumed.status.label(), "running");
    assert_eq!(resumed.run_id.as_ref(), Some(&started.run_id));
    let parked_again = local.pause_machine("pause-api").await.unwrap();
    assert!(
        parked_again
            .lifecycle
            .unwrap()
            .lifecycle
            .current_pause
            .unwrap()
            .token
            .generation
            > authority.token.generation
    );
    let resumed = silo_vm_control::snapshots::snapshot_from_wire(
        daemon.resume_machine(request()).await.unwrap().into_inner(),
    )
    .unwrap();
    assert_eq!(resumed.status.label(), "running");
    assert_eq!(resumed.run_id.as_ref(), Some(&started.run_id));
    machine.stop().await.unwrap();
    cleanup.0 = None;
    shutdown.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn restore_resource_policy_is_validated_before_daemon_native_initialization() {
    use w::runtime_service_server::RuntimeService;
    let root = tempfile::tempdir().unwrap();
    let owner = state(root.path());
    let service = Service(owner.clone());
    for (percent, memory) in [(101, 1), (u32::MAX, 2), (25, 0), (25, 999), (25, -1)] {
        let error = service
            .restore_snapshot(Request::new(w::RestoreStorageSnapshotRequest {
                snapshot: Some(silo_vm_control::stopped::reference_to_wire(
                    &"image:checkpoint".parse().unwrap(),
                )),
                name: Some("child".into()),
                external_resources: Some(silo_vm_control::stopped::policy_to_wire(
                    &libvm::ExternalResourcePolicy::Reject,
                )),
                activation_hook: None,
                resources: Some(w::RestoreResourcePolicy {
                    private_write_percent: percent,
                    memory,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
    assert!(owner.runtime.get().is_none());
    assert!(owner.components.get().is_none());
    assert_eq!(owner.capacity.available_permits(), 64);
    assert!(!owner.host.home().join("state.db").exists());
}
