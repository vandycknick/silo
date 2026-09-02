//! libvm <-> vmmon integration tests for hosts without virtualization support.
//!
//! Each test spawns a real vmmon process built with its `mock-backend`
//! feature, so the full launch handshake (pipes, daemonization, gRPC socket),
//! machine lifecycle, guest execution, and exit reconciliation are exercised
//! against the in-process fake guest instead of a VM.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use libvm::{
    ExecutionLaunchFailureReason, ExecutionLostReason, ExecutionResult, FileWriteDisposition,
    ImageSource, LibVmError, Machine, MachineAgent, MachineAgentStatus,
    MachineDirectoryCreateDisposition, MachineExitOutcome, MachineFileUploadOptions,
    MachineForwardErrorDetail, MachineForwardScope, MachineForwardState, MachineReadinessOutcome,
    MachineStatus, MachineUpdate, Runtime, RuntimeConfig,
};
use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
use test_utils::Scenario;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;
use tower::service_fn;

const READY_TIMEOUT: Duration = Duration::from_secs(30);

fn write_file(path: &Path, contents: &[u8], mode: u32) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    std::fs::write(path, contents).expect("write file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

/// A minimal portable runtime tree. The real mock-enabled vmmon is installed
/// into it so each test also exercises portable component resolution.
fn write_runtime_root(root: &Path) -> PathBuf {
    for helper in ["netd", "krun"] {
        write_file(
            &root.join("bin").join(helper),
            b"#!/bin/sh\nexit 0\n",
            0o755,
        );
    }
    let vmmon = root.join("bin/vmmon");
    std::fs::copy(test_utils::mock_vmmon_binary(), &vmmon).expect("install mock-enabled vmmon");
    std::fs::set_permissions(&vmmon, std::fs::Permissions::from_mode(0o755))
        .expect("make vmmon executable");
    write_file(&root.join("assets/kernel-default"), b"kernel", 0o644);
    write_file(&root.join("assets/initramfs"), b"initramfs", 0o644);
    write_file(&root.join("assets/agent"), b"agent", 0o755);
    root.to_path_buf()
}

struct TestEnv {
    _temp: tempfile::TempDir,
    _run_root: tempfile::TempDir,
    runtime: Runtime,
    disk: PathBuf,
    machines: Mutex<Vec<Machine>>,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let machines = std::mem::take(
            self.machines
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner),
        );
        if machines.is_empty() {
            return;
        }
        let cleanup = std::thread::Builder::new()
            .name("vmmon-test-cleanup".to_string())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    for machine in machines {
                        let stopped = tokio::time::timeout(Duration::from_secs(5), machine.stop())
                            .await
                            .is_ok_and(|result| result.is_ok());
                        if !stopped {
                            let _ =
                                tokio::time::timeout(Duration::from_secs(5), machine.kill()).await;
                        }
                        let _ =
                            tokio::time::timeout(Duration::from_secs(5), machine.clone().remove())
                                .await;
                    }
                });
            });
        if let Ok(cleanup) = cleanup {
            let _ = cleanup.join();
        }
    }
}

async fn test_env(name: &str, scenario: &Scenario) -> TestEnv {
    // The mock backend and runtime both create Unix sockets below these roots.
    // Keep them short enough for macOS's 104-byte sockaddr_un limit.
    let temp = tempfile::Builder::new()
        .prefix("silo-test")
        .tempdir_in("/tmp")
        .expect("create short temp dir");
    let run_root = tempfile::Builder::new()
        .prefix("silo-mock")
        .tempdir_in("/tmp")
        .expect("create short run root");
    std::fs::set_permissions(run_root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restrict run root");
    let runtime_root = write_runtime_root(&temp.path().join("runtime"));
    let scenario_path = temp.path().join(format!("{name}-scenario.json"));
    scenario.write_to(&scenario_path).expect("write scenario");

    let disk = temp.path().join("rootfs.img");
    std::fs::write(&disk, vec![0u8; 4096]).expect("write disk image");

    let runtime = Runtime::new(
        RuntimeConfig::local(temp.path().join("data"))
            .with_state_root(temp.path().join("state"))
            .with_run_root(run_root.path())
            .with_image_root(temp.path().join("images"))
            .with_runtime_root(&runtime_root)
            .with_mock_vmm(&scenario_path),
    )
    .await
    .expect("open runtime");

    TestEnv {
        _temp: temp,
        _run_root: run_root,
        runtime,
        disk,
        machines: Mutex::new(Vec::new()),
    }
}

async fn create_machine(env: &TestEnv, name: &str) -> Machine {
    let machine = env
        .runtime
        .machine()
        .name(name)
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");
    env.machines
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(machine.clone());
    machine
}

async fn set_forwards(machine: &Machine, forwards: Vec<forward_spec::Forward>) {
    let mut spec = machine.inspect().await.expect("inspect machine").spec;
    spec.forwards = forwards;
    machine
        .replace_config(spec)
        .await
        .expect("set machine-scoped forwards");
}

fn inbound_unix(listen: impl Into<PathBuf>, connect: impl Into<PathBuf>) -> forward_spec::Forward {
    forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Unix(listen.into())),
        forward_spec::Endpoint::Guest(forward_spec::Address::Unix(connect.into())),
    )
}

async fn spawn_unix_echo(path: &Path) -> tokio::task::JoinHandle<()> {
    let listener = UnixListener::bind(path).expect("bind Unix echo target");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    })
}

async fn spawn_tcp_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP echo target");
    let address = listener.local_addr().expect("TCP echo address");
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    (address, task)
}

fn available_tcp_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve test port");
    listener.local_addr().expect("reserved test address")
}

async fn connect_tcp_eventually(address: std::net::SocketAddr) -> TcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(error) if tokio::time::Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("TCP forward at {address} did not become active: {error}"),
        }
    }
}

async fn machine_tcp_bound(machine: &Machine) -> std::net::SocketAddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let forwards = machine.list_forwards().await.expect("list forwards");
        if let Some(address) = forwards.into_iter().find_map(|status| match status.bound {
            Some(forward_spec::Endpoint::Host(forward_spec::Address::Tcp(address)))
            | Some(forward_spec::Endpoint::Guest(forward_spec::Address::Tcp(address)))
                if status.state == MachineForwardState::Active =>
            {
                Some(address)
            }
            _ => None,
        }) {
            return address;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "forward did not report an active TCP bound address"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn assert_echo<S>(stream: &mut S, payload: &[u8])
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(payload)
        .await
        .expect("write forwarded bytes");
    let mut echoed = vec![0_u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("forward echo deadline")
        .expect("read forwarded bytes");
    assert_eq!(echoed, payload);
}

async fn assert_closed_without_bytes<S>(stream: &mut S)
where
    S: tokio::io::AsyncRead + Unpin,
{
    assert_closed_without_bytes_within(stream, Duration::from_secs(2)).await;
}

async fn assert_closed_without_bytes_within<S>(stream: &mut S, timeout: Duration)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(timeout, stream.read(&mut byte)).await {
        Ok(Ok(0)) => {}
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(Ok(count)) => panic!("forward wrote {count} bytes before closing"),
        Ok(Err(error)) => panic!("unexpected forward close error: {error}"),
        Err(_) => panic!("forward did not close within deadline"),
    }
}

#[tokio::test]
async fn dropping_test_environment_stops_a_running_monitor() {
    let env = test_env("drop-cleanup", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-drop-cleanup").await;
    start_ready(&machine).await;
    let pid_path = env
        ._run_root
        .path()
        .join("machines")
        .join(machine.id())
        .join("vm.pid");
    let pid = std::fs::read_to_string(pid_path)
        .expect("read vmmon pid")
        .trim()
        .parse::<i32>()
        .expect("parse vmmon pid");
    assert!(kill(Pid::from_raw(pid), None).is_ok());

    drop(machine);
    drop(env);

    assert_eq!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH));
}

#[tokio::test]
async fn machine_inbound_unix_forward_reaches_guest_unix_target_and_cleans_up() {
    let env = test_env("forward-unix", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-forward-unix").await;
    let target = env._temp.path().join("guest-target.sock");
    let echo = spawn_unix_echo(&target).await;
    set_forwards(&machine, vec![inbound_unix("svc.sock", &target)]).await;
    let listen = env
        ._run_root
        .path()
        .join("machines")
        .join(machine.id())
        .join("svc.sock");

    start_ready(&machine).await;
    let mut client = UnixStream::connect(&listen)
        .await
        .expect("connect Unix forward");
    assert_echo(&mut client, b"unix-forward").await;
    assert_eq!(
        std::fs::metadata(&listen)
            .expect("forward metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let status = machine.monitor_status().await.expect("monitor status");
    let services = match status.agent {
        MachineAgentStatus::Enabled(enabled) => enabled.services,
        MachineAgentStatus::Disabled => panic!("agent unexpectedly disabled"),
    };
    assert!(services.contains(&"silo.v1.GuestAgentService".to_string()));
    assert!(services.contains(&"silo.v1.GuestFilesystemService".to_string()));
    assert!(services.contains(&"silo.v1.GuestProcessService".to_string()));
    assert!(services.contains(&"silo.v1.GuestForwardService".to_string()));

    machine.stop().await.expect("stop machine");
    assert!(!listen.exists(), "owned Unix listener must be removed");
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn builder_and_update_persist_machine_forwards_and_vsock_while_stopped() {
    let env = test_env("builder-forwards", &Scenario::default()).await;
    let initial = forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
            "127.0.0.1:0".parse().expect("initial listen"),
        )),
        forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
    )
    .with_name("initial");
    let machine = env
        .runtime
        .machine()
        .name("integration-builder-forwards")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .forwards(vec![initial.clone()])
        .vsock(true)
        .create()
        .await
        .expect("create machine with forwards");

    let created = machine.inspect().await.expect("inspect created machine");
    assert_eq!(created.spec.forwards, vec![initial.clone()]);
    assert!(created.spec.vsock.expect("created vsock config").enabled);
    start_ready(&machine).await;
    let listed = machine.list_forwards().await.expect("list initial forward");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].forward.name.as_deref(), Some("initial"));
    assert_eq!(listed[0].state, MachineForwardState::Active);

    let replacement = forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
            "127.0.0.1:0".parse().expect("replacement listen"),
        )),
        forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
    )
    .with_name("replacement");
    let error = machine
        .update(MachineUpdate::new().forwards(vec![replacement.clone()]))
        .await
        .expect_err("running machine update must fail");
    assert!(matches!(error, LibVmError::MachineAlreadyRunning { .. }));

    machine.stop().await.expect("stop before update");
    let duplicate = replacement.clone().with_name("initial");
    let error = machine
        .update(MachineUpdate::new().forwards(vec![initial, duplicate]))
        .await
        .expect_err("invalid stopped update must fail validation");
    assert!(matches!(error, LibVmError::InvalidMachineConfig { .. }));
    assert_eq!(
        machine
            .inspect()
            .await
            .expect("inspect after rejected update")
            .spec
            .forwards[0]
            .name
            .as_deref(),
        Some("initial")
    );
    let updated = machine
        .update(
            MachineUpdate::new()
                .forwards(vec![replacement.clone()])
                .vsock(false),
        )
        .await
        .expect("replace stopped forward config");
    assert_eq!(updated.spec.forwards, vec![replacement]);
    assert!(!updated.spec.vsock.expect("updated vsock config").enabled);
    assert_eq!(
        machine.vsock_socket().await.expect("disabled vsock path"),
        None
    );

    start_ready(&machine).await;
    let listed = machine
        .list_forwards()
        .await
        .expect("list replacement forward");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].forward.name.as_deref(), Some("replacement"));
    assert_eq!(listed[0].state, MachineForwardState::Active);

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_inbound_tcp_forward_reaches_guest_tcp_target() {
    let env = test_env("forward-tcp", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-forward-tcp").await;
    let (target, echo) = spawn_tcp_echo().await;
    let listen = "127.0.0.1:0".parse().expect("ephemeral listen address");
    set_forwards(
        &machine,
        vec![forward_spec::Forward::new(
            forward_spec::Endpoint::Host(forward_spec::Address::Tcp(listen)),
            forward_spec::Endpoint::Guest(forward_spec::Address::Tcp(target)),
        )],
    )
    .await;

    start_ready(&machine).await;
    let listen = machine_tcp_bound(&machine).await;
    let mut client = TcpStream::connect(listen)
        .await
        .expect("connect TCP forward");
    assert_echo(&mut client, b"tcp-forward").await;

    machine.stop().await.expect("stop machine");
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn agent_disabled_rejects_agent_forward_immediately_while_raw_vsock_works() {
    let env = test_env("forward-raw", &Scenario::default()).await;
    let machine = env
        .runtime
        .machine()
        .name("integration-forward-raw")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .agent_mode(Some(MachineAgent::Disabled))
        .create()
        .await
        .expect("create agent-disabled machine");
    let raw_listen = env._temp.path().join("raw.sock");
    let agent_listen = env._temp.path().join("agent.sock");
    set_forwards(
        &machine,
        vec![
            forward_spec::Forward::new(
                forward_spec::Endpoint::Host(forward_spec::Address::Unix(agent_listen.clone())),
                forward_spec::Endpoint::Guest(forward_spec::Address::Unix(
                    env._temp.path().join("unavailable-guest.sock"),
                )),
            ),
            forward_spec::Forward::new(
                forward_spec::Endpoint::Host(forward_spec::Address::Unix(raw_listen.clone())),
                forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
            ),
        ],
    )
    .await;

    machine.start().await.expect("start agent-disabled machine");
    let mut agent_client = UnixStream::connect(&agent_listen)
        .await
        .expect("connect disabled agent forward");
    let refusal_started = std::time::Instant::now();
    assert_closed_without_bytes(&mut agent_client).await;
    assert!(refusal_started.elapsed() < Duration::from_secs(1));

    let mut raw_client = UnixStream::connect(&raw_listen)
        .await
        .expect("connect raw forward");
    assert_echo(&mut raw_client, b"raw-vsock").await;
    machine.stop().await.expect("stop machine");
    assert!(!agent_listen.exists());
    assert!(!raw_listen.exists());
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn inbound_connection_before_agent_ready_is_parked_then_served() {
    let mut scenario = Scenario::default();
    scenario.agent.ready_delay_ms = Some(750);
    let env = test_env("forward-park", &scenario).await;
    let machine = create_machine(&env, "integration-forward-park").await;
    let target = env._temp.path().join("park-target.sock");
    let echo = spawn_unix_echo(&target).await;
    let listen = env._temp.path().join("park-listen.sock");
    set_forwards(&machine, vec![inbound_unix(&listen, &target)]).await;

    machine
        .start()
        .await
        .expect("start machine before agent ready");
    let mut client = UnixStream::connect(&listen)
        .await
        .expect("connect pending forward");
    let started = std::time::Instant::now();
    assert_echo(&mut client, b"parked").await;
    assert!(started.elapsed() >= Duration::from_millis(500));

    machine.stop().await.expect("stop machine");
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn inbound_refusal_closes_host_connection_without_bytes() {
    let target = PathBuf::from("/tmp/refused-forward-target.sock");
    let mut scenario = Scenario::default();
    scenario
        .forward
        .refuse_targets
        .push(format!("unix:{}", target.display()));
    let env = test_env("forward-refused", &scenario).await;
    let machine = create_machine(&env, "integration-forward-refused").await;
    let listen = env._temp.path().join("refused-listen.sock");
    set_forwards(&machine, vec![inbound_unix(&listen, &target)]).await;

    start_ready(&machine).await;
    let mut client = UnixStream::connect(&listen)
        .await
        .expect("connect refused forward");
    if let Err(error) = client.write_all(b"must-not-return").await {
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ));
    }
    assert_closed_without_bytes(&mut client).await;

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn forward_bind_failure_fails_machine_start_and_rolls_back() {
    let env = test_env("forward-bind-failure", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-forward-bind-failure").await;
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy TCP port");
    let address = occupied.local_addr().expect("occupied address");
    let rollback = env._temp.path().join("rollback.sock");
    set_forwards(
        &machine,
        vec![
            forward_spec::Forward::new(
                forward_spec::Endpoint::Host(forward_spec::Address::Unix(rollback.clone())),
                forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
            ),
            forward_spec::Forward::new(
                forward_spec::Endpoint::Host(forward_spec::Address::Tcp(address)),
                forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
            )
            .with_name("occupied"),
        ],
    )
    .await;

    let error = machine.start().await.expect_err("occupied bind must fail");
    let message = error.to_string();
    assert!(message.contains("occupied"), "{message}");
    assert!(message.contains(&address.to_string()), "{message}");
    assert!(
        !rollback.exists(),
        "earlier prepared listener must roll back"
    );
    drop(occupied);
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn explicit_mode_widens_unix_forward_socket() {
    let env = test_env("forward-mode", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-forward-mode").await;
    let listen = env._temp.path().join("shared.sock");
    let forward = forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Unix(listen.clone())),
        forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
    )
    .with_mode(forward_spec::UnixMode::new(0o666).expect("valid mode"));
    set_forwards(&machine, vec![forward]).await;

    machine.start().await.expect("start machine");
    assert_eq!(
        std::fs::metadata(&listen)
            .expect("shared listener metadata")
            .permissions()
            .mode()
            & 0o777,
        0o666
    );
    machine.stop().await.expect("stop machine");
    assert!(!listen.exists());
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn unsupported_agent_closes_forward_without_changing_readiness() {
    let mut scenario = Scenario::default();
    scenario.forward.unsupported = true;
    let env = test_env("forward-unsupported", &scenario).await;
    let machine = create_machine(&env, "integration-forward-unsupported").await;
    let listen = env._temp.path().join("unsupported.sock");
    let target = env._temp.path().join("unused-target.sock");
    set_forwards(&machine, vec![inbound_unix(&listen, &target)]).await;

    start_ready(&machine).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let status = machine.monitor_status().await.expect("monitor status");
    assert!(status.readiness.ready);
    let services = match status.agent {
        MachineAgentStatus::Enabled(enabled) => enabled.services,
        MachineAgentStatus::Disabled => panic!("agent unexpectedly disabled"),
    };
    assert!(!services.contains(&"silo.v1.GuestForwardService".to_string()));
    let mut client = UnixStream::connect(&listen)
        .await
        .expect("connect unsupported forward");
    assert_closed_without_bytes(&mut client).await;

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn pending_forward_parking_is_bounded_and_expires_after_thirty_seconds() {
    let mut scenario = Scenario::default();
    scenario.agent.ready_delay_ms = Some(40_000);
    let env = test_env("forward-parking-limit", &scenario).await;
    let machine = create_machine(&env, "integration-forward-parking-limit").await;
    let listen = env._temp.path().join("parking-limit.sock");
    let target = env._temp.path().join("parking-target.sock");
    set_forwards(&machine, vec![inbound_unix(&listen, &target)]).await;
    machine.start().await.expect("start pending machine");

    let mut parked = Vec::new();
    for _ in 0..64 {
        parked.push(
            UnixStream::connect(&listen)
                .await
                .expect("connect parked client"),
        );
    }
    let mut overflow = UnixStream::connect(&listen)
        .await
        .expect("connect overflow client");
    assert_closed_without_bytes(&mut overflow).await;

    let started = std::time::Instant::now();
    assert_closed_without_bytes_within(&mut parked[0], Duration::from_secs(35)).await;
    assert!(started.elapsed() >= Duration::from_secs(27));
    assert!(started.elapsed() <= Duration::from_secs(35));

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn mux_and_forward_streams_share_public_capacity_and_leave_headroom() {
    let env = test_env("forward-capacity", &Scenario::default()).await;
    let machine = env
        .runtime
        .machine()
        .name("integration-forward-capacity")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .agent_mode(Some(MachineAgent::Disabled))
        .create()
        .await
        .expect("create capacity machine");
    let listen = env._temp.path().join("capacity.sock");
    let mut spec = machine
        .inspect()
        .await
        .expect("inspect capacity machine")
        .spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: None,
    });
    spec.forwards = vec![forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Unix(listen.clone())),
        forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
    )];
    machine
        .replace_config(spec)
        .await
        .expect("configure capacity machine");
    let mux = machine
        .vsock_socket()
        .await
        .expect("resolve mux")
        .expect("enabled mux");
    machine.start().await.expect("start capacity machine");

    let mut mux_client = UnixStream::connect(mux)
        .await
        .expect("connect mux capacity slot");
    mux_client
        .write_all(b"CONNECT 22\n")
        .await
        .expect("open mux capacity slot");
    read_mux_acknowledgement(&mut mux_client).await;

    let mut clients = Vec::with_capacity(1006);
    for _ in 0..1006 {
        let mut client = UnixStream::connect(&listen)
            .await
            .expect("connect forward capacity slot");
        assert_echo(&mut client, b"x").await;
        clients.push(client);
    }
    let mut exhausted = UnixStream::connect(&listen)
        .await
        .expect("connect exhausted forward");
    assert_closed_without_bytes(&mut exhausted).await;

    drop(clients);
    drop(mux_client);
    machine.stop().await.expect("stop capacity machine");
    machine.remove().await.expect("remove capacity machine");
}

#[tokio::test]
async fn machine_outbound_tcp_forward_reaches_host_service() {
    let env = test_env("outbound-tcp", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-outbound-tcp").await;
    let (target, echo) = spawn_tcp_echo().await;
    let listen = "127.0.0.1:0".parse().expect("ephemeral listen address");
    set_forwards(
        &machine,
        vec![forward_spec::Forward::new(
            forward_spec::Endpoint::Guest(forward_spec::Address::Tcp(listen)),
            forward_spec::Endpoint::Host(forward_spec::Address::Tcp(target)),
        )],
    )
    .await;

    start_ready(&machine).await;
    let listen = machine_tcp_bound(&machine).await;
    let mut client = connect_tcp_eventually(listen).await;
    assert_echo(&mut client, b"outbound-tcp").await;

    machine.stop().await.expect("stop machine");
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_outbound_unix_forward_applies_mode_and_reaches_host_service() {
    let env = test_env("outbound-unix", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-outbound-unix").await;
    let listen = env._temp.path().join("guest-listen.sock");
    let target = env._temp.path().join("host-target.sock");
    let echo = spawn_unix_echo(&target).await;
    let forward = forward_spec::Forward::new(
        forward_spec::Endpoint::Guest(forward_spec::Address::Unix(listen.clone())),
        forward_spec::Endpoint::Host(forward_spec::Address::Unix(target)),
    )
    .with_mode(forward_spec::UnixMode::new(0o666).expect("valid mode"));
    set_forwards(&machine, vec![forward]).await;

    start_ready(&machine).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let active = machine
            .list_forwards()
            .await
            .expect("list outbound Unix forward")
            .into_iter()
            .any(|status| {
                status.state == MachineForwardState::Active
                    && status.bound
                        == Some(forward_spec::Endpoint::Guest(forward_spec::Address::Unix(
                            listen.clone(),
                        )))
            });
        if active {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "outbound Unix forward did not become active"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut client = UnixStream::connect(&listen)
        .await
        .expect("connect guest Unix listener");
    assert_echo(&mut client, b"outbound-unix").await;
    assert_eq!(
        std::fs::metadata(&listen)
            .expect("guest listener metadata")
            .permissions()
            .mode()
            & 0o777,
        0o666
    );

    machine.stop().await.expect("stop machine");
    assert!(!listen.exists());
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_outbound_raw_vsock_reaches_relative_host_unix_target() {
    let env = test_env("outbound-raw", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-outbound-raw").await;
    const PORT: u32 = 5000;
    let mut spec = machine.inspect().await.expect("inspect raw machine").spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: None,
    });
    spec.forwards = vec![forward_spec::Forward::new(
        forward_spec::Endpoint::Vsock(PORT),
        forward_spec::Endpoint::Host(forward_spec::Address::Unix(PathBuf::from(
            "raw-target.sock",
        ))),
    )];
    machine
        .replace_config(spec)
        .await
        .expect("configure raw outbound forward");

    machine.start().await.expect("start raw outbound machine");
    let machine_run_dir = env._run_root.path().join("machines").join(machine.id());
    let echo = spawn_unix_echo(&machine_run_dir.join("raw-target.sock")).await;
    let _extension = UnixListener::bind(machine_run_dir.join(format!("vsock.sock_{PORT}")))
        .expect("bind extension path that discovery must ignore");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut guest = UnixStream::connect(
        env._temp
            .path()
            .join("data/machines")
            .join(machine.id())
            .join(format!(".v_{PORT}")),
    )
    .await
    .expect("mock raw guest dial");
    assert_echo(&mut guest, b"raw-outbound").await;

    machine.stop().await.expect("stop machine");
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn outbound_agent_restart_reopens_listener_and_unknown_token_is_rejected() {
    let mut scenario = Scenario::default();
    scenario.agent.restart_after_ms = Some(750);
    let env = test_env("outbound-restart", &scenario).await;
    let machine = create_machine(&env, "integration-outbound-restart").await;
    let (target, echo) = spawn_tcp_echo().await;
    let listen = "127.0.0.1:0".parse().expect("ephemeral listen address");
    set_forwards(
        &machine,
        vec![forward_spec::Forward::new(
            forward_spec::Endpoint::Guest(forward_spec::Address::Tcp(listen)),
            forward_spec::Endpoint::Host(forward_spec::Address::Tcp(target)),
        )],
    )
    .await;
    start_ready(&machine).await;

    let listen = machine_tcp_bound(&machine).await;
    let mut first = connect_tcp_eventually(listen).await;
    assert_echo(&mut first, b"before-restart").await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let listen = machine_tcp_bound(&machine).await;
    let mut second = connect_tcp_eventually(listen).await;
    assert_echo(&mut second, b"after-restart").await;

    let return_path = env
        ._temp
        .path()
        .join("data/machines")
        .join(machine.id())
        .join(format!(".v_{}", forward_spec::FORWARD_VSOCK_PORT));
    let mut unknown = UnixStream::connect(return_path)
        .await
        .expect("connect return port directly");
    unknown
        .write_all(b"CONNECT 00000000000000000000000000000000\n")
        .await
        .expect("write unknown token");
    let mut reply = [0_u8; 12];
    unknown
        .read_exact(&mut reply)
        .await
        .expect("read invalid reply");
    assert_eq!(&reply, b"ERR invalid\n");
    assert_closed_without_bytes(&mut unknown).await;

    let mut malformed = UnixStream::connect(
        env._temp
            .path()
            .join("data/machines")
            .join(machine.id())
            .join(format!(".v_{}", forward_spec::FORWARD_VSOCK_PORT)),
    )
    .await
    .expect("connect return port for malformed token");
    malformed
        .write_all(b"CONNECT not-a-token\n")
        .await
        .expect("write malformed token");
    let mut malformed_reply = [0_u8; 12];
    malformed
        .read_exact(&mut malformed_reply)
        .await
        .expect("read malformed-token reply");
    assert_eq!(&malformed_reply, b"ERR invalid\n");

    machine.stop().await.expect("stop machine");
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn unsupported_agent_never_binds_machine_outbound_listener() {
    let mut scenario = Scenario::default();
    scenario.forward.unsupported = true;
    let env = test_env("outbound-unsupported", &scenario).await;
    let machine = create_machine(&env, "integration-outbound-unsupported").await;
    let listen = available_tcp_address();
    let target = available_tcp_address();
    set_forwards(
        &machine,
        vec![forward_spec::Forward::new(
            forward_spec::Endpoint::Guest(forward_spec::Address::Tcp(listen)),
            forward_spec::Endpoint::Host(forward_spec::Address::Tcp(target)),
        )],
    )
    .await;

    start_ready(&machine).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(TcpStream::connect(listen).await.is_err());
    let status = machine.monitor_status().await.expect("monitor status");
    let services = match status.agent {
        MachineAgentStatus::Enabled(enabled) => enabled.services,
        MachineAgentStatus::Disabled => panic!("agent unexpectedly disabled"),
    };
    assert!(!services.contains(&"silo.v1.GuestForwardService".to_string()));
    assert!(status.readiness.ready);

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn session_forward_lifecycle_is_the_response_stream_and_port_zero_sessions_coexist() {
    let env = test_env("session-lifecycle", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-session-lifecycle").await;
    start_ready(&machine).await;
    let forward = forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
            "127.0.0.1:0".parse().expect("ephemeral listen"),
        )),
        forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
    );

    let mut first = machine
        .open_forward(forward.clone())
        .await
        .expect("open first forward session");
    let first_status = first
        .next_status()
        .await
        .expect("first status")
        .expect("first snapshot");
    assert_eq!(first_status.scope, MachineForwardScope::Session);
    assert_eq!(first_status.state, MachineForwardState::Active);
    assert_eq!(first_status.active_connections, 0);
    assert_eq!(first_status.refused_connections, 0);
    let Some(forward_spec::Endpoint::Host(forward_spec::Address::Tcp(first_bound))) =
        first_status.bound
    else {
        panic!("session-scoped forward must report its actual host TCP address");
    };
    assert_ne!(first_bound.port(), 0);

    let mut second = machine
        .open_forward(forward)
        .await
        .expect("a second port-zero session must coexist");
    let second_status = second
        .next_status()
        .await
        .expect("second status")
        .expect("second snapshot");
    let Some(forward_spec::Endpoint::Host(forward_spec::Address::Tcp(second_bound))) =
        second_status.bound
    else {
        panic!("second session must report its actual address");
    };
    assert_ne!(first_bound, second_bound);
    drop(second);

    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut client = TcpStream::connect(first_bound)
        .await
        .expect("silent session remains alive");
    assert_echo(&mut client, b"session-forward").await;
    drop(client);
    drop(first);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let listed = machine.list_forwards().await.expect("list after drop");
        if listed.is_empty() && TcpStream::connect(first_bound).await.is_err() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "dropped session remained visible or bound"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn open_rejections_are_typed_and_session_capacity_recovers() {
    let env = test_env("session-errors", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-session-errors").await;
    start_ready(&machine).await;

    let invalid = forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
            "127.0.0.1:0".parse().expect("listen"),
        )),
        forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
            "127.0.0.1:1".parse().expect("connect"),
        )),
    );
    let error = machine
        .open_forward(invalid)
        .await
        .expect_err("invalid shape must fail");
    assert!(matches!(
        error,
        LibVmError::ForwardRejected {
            detail: Some(MachineForwardErrorDetail::Invalid),
            ..
        }
    ));

    let named = forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
            "127.0.0.1:0".parse().expect("named listen"),
        )),
        forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
    )
    .with_name("duplicate");
    let named_session = machine
        .open_forward(named.clone())
        .await
        .expect("open named session");
    let error = machine
        .open_forward(named)
        .await
        .expect_err("duplicate name must fail validation");
    assert!(matches!(
        error,
        LibVmError::ForwardRejected {
            detail: Some(MachineForwardErrorDetail::Invalid),
            ..
        }
    ));
    drop(named_session);

    let occupied = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind occupied address");
    let occupied_address = occupied.local_addr().expect("occupied address");
    let error = machine
        .open_forward(forward_spec::Forward::new(
            forward_spec::Endpoint::Host(forward_spec::Address::Tcp(occupied_address)),
            forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
        ))
        .await
        .expect_err("occupied host address must fail");
    assert!(matches!(
        error,
        LibVmError::ForwardRejected {
            detail: Some(MachineForwardErrorDetail::AddressInUse),
            ..
        }
    ));
    drop(occupied);

    let conflict_path = env._temp.path().join("session-conflict.sock");
    let conflict = forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Unix(conflict_path)),
        forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
    );
    let first = machine
        .open_forward(conflict.clone())
        .await
        .expect("open conflicting session");
    let error = machine
        .open_forward(conflict)
        .await
        .expect_err("duplicate listen must fail");
    assert!(matches!(
        error,
        LibVmError::ForwardRejected {
            detail: Some(MachineForwardErrorDetail::AddressInUse),
            ..
        }
    ));
    drop(first);
    let removal_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !machine
        .list_forwards()
        .await
        .expect("list conflict cleanup")
        .is_empty()
    {
        assert!(
            tokio::time::Instant::now() < removal_deadline,
            "conflicting session was not removed"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let forward = forward_spec::Forward::new(
        forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
            "127.0.0.1:0".parse().expect("ephemeral listen"),
        )),
        forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
    );
    let mut sessions = Vec::new();
    for _ in 0..64 {
        sessions.push(
            machine
                .open_forward(forward.clone())
                .await
                .expect("open within limit"),
        );
    }
    let error = machine
        .open_forward(forward.clone())
        .await
        .expect_err("65th session must fail");
    assert!(matches!(
        error,
        LibVmError::ForwardRejected {
            detail: Some(MachineForwardErrorDetail::Limit),
            ..
        }
    ));
    drop(sessions.pop());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let recovered = loop {
        match machine.open_forward(forward.clone()).await {
            Ok(session) => break session,
            Err(LibVmError::ForwardRejected {
                detail: Some(MachineForwardErrorDetail::Limit),
                ..
            }) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("session capacity did not recover: {error}"),
        }
    };
    drop(recovered);
    drop(sessions);
    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");

    let stopped = create_machine(&env, "integration-session-stopped").await;
    let error = stopped
        .open_forward(forward)
        .await
        .expect_err("stopped machine must reject open");
    assert!(matches!(error, LibVmError::MachineNotRunning { .. }));
    stopped.remove().await.expect("remove stopped machine");
}

#[tokio::test]
async fn session_outbound_return_port_is_lazy_reusable_and_shutdown_closes_stream() {
    let env = test_env("session-outbound", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-session-outbound").await;
    let (target, echo) = spawn_tcp_echo().await;
    start_ready(&machine).await;
    let forward = forward_spec::Forward::new(
        forward_spec::Endpoint::Guest(forward_spec::Address::Tcp(
            "127.0.0.1:0".parse().expect("ephemeral guest listen"),
        )),
        forward_spec::Endpoint::Host(forward_spec::Address::Tcp(target)),
    );

    for iteration in 0..2 {
        let mut session = machine
            .open_forward(forward.clone())
            .await
            .expect("open outbound forward session");
        let bound = loop {
            let status = session
                .next_status()
                .await
                .expect("outbound status")
                .expect("outbound snapshot");
            if status.state == MachineForwardState::Active {
                let Some(forward_spec::Endpoint::Guest(forward_spec::Address::Tcp(bound))) =
                    status.bound
                else {
                    panic!("active outbound session must report guest TCP bound address");
                };
                break bound;
            }
        };
        let mut client = TcpStream::connect(bound)
            .await
            .expect("connect session-scoped outbound listener");
        assert_echo(&mut client, format!("outbound-{iteration}").as_bytes()).await;
        drop(client);
        if iteration == 0 {
            drop(session);
        } else {
            machine.stop().await.expect("stop with session stream");
            let closed = tokio::time::timeout(Duration::from_secs(2), async {
                while let Ok(Some(_)) = session.next_status().await {}
            })
            .await;
            assert!(
                closed.is_ok(),
                "session stream remained open after vmmon shutdown"
            );
        }
    }
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn list_reports_machine_and_session_scopes_and_port_1028_has_no_public_socket() {
    let env = test_env("forward-list", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-forward-list").await;
    let machine_path = env._temp.path().join("machine-list.sock");
    set_forwards(
        &machine,
        vec![forward_spec::Forward::new(
            forward_spec::Endpoint::Host(forward_spec::Address::Unix(machine_path)),
            forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
        )
        .with_name("machine")],
    )
    .await;
    start_ready(&machine).await;
    let mut session = machine
        .open_forward(
            forward_spec::Forward::new(
                forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
                    "127.0.0.1:0".parse().expect("ephemeral listen"),
                )),
                forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
            )
            .with_name("session"),
        )
        .await
        .expect("open listed forward session");
    let _ = session.next_status().await.expect("session status");

    let listed = machine
        .list_forwards()
        .await
        .expect("list machine- and session-scoped forwards");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].forward.name.as_deref(), Some("machine"));
    assert_eq!(listed[0].scope, MachineForwardScope::Machine);
    assert_eq!(listed[1].forward.name.as_deref(), Some("session"));
    assert_eq!(listed[1].scope, MachineForwardScope::Session);
    assert!(listed.iter().all(|status| {
        status.state == MachineForwardState::Active
            && status.bound.is_some()
            && status.active_connections == 0
            && status.refused_connections == 0
            && status.error.is_none()
    }));
    assert_eq!(
        machine
            .vsock_listener_socket(forward_spec::FORWARD_VSOCK_PORT)
            .await
            .expect("reserved listener accessor"),
        None
    );

    drop(session);
    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn session_raw_vsock_port_detaches_and_reattaches_without_reregistering() {
    const PORT: u32 = 5017;
    let env = test_env("session-raw-reattach", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-session-raw-reattach").await;
    let target = env._temp.path().join("session-raw-target.sock");
    let echo = spawn_unix_echo(&target).await;
    start_ready(&machine).await;
    let forward = forward_spec::Forward::new(
        forward_spec::Endpoint::Vsock(PORT),
        forward_spec::Endpoint::Host(forward_spec::Address::Unix(target)),
    );
    let guest_path = env
        ._temp
        .path()
        .join("data/machines")
        .join(machine.id())
        .join(format!(".v_{PORT}"));

    let mut first = machine
        .open_forward(forward.clone())
        .await
        .expect("open raw forward session");
    assert_eq!(
        first
            .next_status()
            .await
            .expect("raw status")
            .expect("raw snapshot")
            .state,
        MachineForwardState::Active
    );
    let mut guest = UnixStream::connect(&guest_path)
        .await
        .expect("dial first raw session");
    assert_echo(&mut guest, b"first-session").await;
    drop(guest);
    drop(first);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !machine
        .list_forwards()
        .await
        .expect("list raw cleanup")
        .is_empty()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "raw session was not detached"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let mut ownerless = UnixStream::connect(&guest_path)
        .await
        .expect("retained raw registration remains present");
    assert_closed_without_bytes(&mut ownerless).await;
    let mut second = machine
        .open_forward(forward)
        .await
        .expect("reattach raw forward");
    let _ = second.next_status().await.expect("reattached status");
    let mut guest = UnixStream::connect(&guest_path)
        .await
        .expect("dial reattached raw session");
    assert_echo(&mut guest, b"second-session").await;

    drop(guest);
    drop(second);
    machine.stop().await.expect("stop machine");
    echo.abort();
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn vsock_path_accessors_are_store_backed_and_follow_enablement() {
    let env = test_env("vsock-paths", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-vsock-paths").await;

    assert_eq!(
        machine.vsock_socket().await.expect("disabled mux path"),
        None
    );
    assert_eq!(
        machine
            .vsock_listener_socket(5000)
            .await
            .expect("disabled listener path"),
        None
    );
    let machine_run_dir = env._run_root.path().join("machines").join(machine.id());
    assert!(
        !machine_run_dir.exists(),
        "omitted path accessors must not create runtime state"
    );

    let mut spec = machine.inspect().await.expect("inspect machine").spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: false,
        uds: None,
    });
    machine
        .replace_config(spec)
        .await
        .expect("explicitly disable vsock");
    assert_eq!(
        machine.vsock_socket().await.expect("disabled mux path"),
        None
    );
    assert_eq!(
        machine
            .vsock_listener_socket(5000)
            .await
            .expect("disabled listener path"),
        None
    );
    assert!(
        !machine_run_dir.exists(),
        "disabled path accessors must not create runtime state"
    );

    let mut spec = machine.inspect().await.expect("inspect machine").spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: None,
    });
    machine.replace_config(spec).await.expect("enable vsock");
    let expected_mux = machine_run_dir.join(vm_spec::DEFAULT_VSOCK_MUX_FILENAME);
    assert_eq!(
        machine.vsock_socket().await.expect("default mux path"),
        Some(expected_mux.clone())
    );
    assert_eq!(
        machine
            .vsock_listener_socket(5000)
            .await
            .expect("default listener path"),
        Some(PathBuf::from(format!("{}_5000", expected_mux.display())))
    );
    assert_eq!(
        machine
            .vsock_listener_socket(protocol::DEFAULT_GUEST_CONTROL_PORT)
            .await
            .expect("reserved listener path"),
        None
    );

    let mut spec = machine
        .inspect()
        .await
        .expect("inspect enabled machine")
        .spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: Some(PathBuf::from("custom.sock")),
    });
    machine
        .replace_config(spec)
        .await
        .expect("customize vsock path");
    let custom_mux = env
        ._run_root
        .path()
        .join("machines")
        .join(machine.id())
        .join("custom.sock");
    assert_eq!(
        machine.vsock_socket().await.expect("custom mux path"),
        Some(custom_mux.clone())
    );
    assert_eq!(
        machine
            .vsock_listener_socket(5000)
            .await
            .expect("custom listener path"),
        Some(PathBuf::from(format!("{}_5000", custom_mux.display())))
    );

    for reserved in ["vm.sock", "vm.pid", "vm.lock", "krun.vsock"] {
        let mut spec = machine
            .inspect()
            .await
            .expect("inspect custom machine")
            .spec;
        spec.vsock = Some(vm_spec::Vsock {
            enabled: true,
            uds: Some(PathBuf::from(reserved)),
        });
        let error = machine
            .replace_config(spec)
            .await
            .expect_err("reserved mux filename must be rejected");
        assert!(matches!(error, LibVmError::InvalidMachineConfig { .. }));
    }

    machine.clone().remove().await.expect("remove machine");
    assert!(matches!(
        machine.vsock_socket().await,
        Err(LibVmError::MachineNotFound { .. })
    ));
}

async fn start_ready(machine: &Machine) {
    machine.start().await.expect("start machine");
    let readiness = machine
        .wait_ready(READY_TIMEOUT)
        .await
        .expect("wait for readiness");
    assert_eq!(readiness.outcome, MachineReadinessOutcome::Ready);
}

async fn read_mux_acknowledgement(stream: &mut UnixStream) -> u32 {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut acknowledgement = Vec::new();
        loop {
            let byte = stream.read_u8().await.expect("read mux acknowledgement");
            acknowledgement.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        std::str::from_utf8(&acknowledgement)
            .expect("UTF-8 acknowledgement")
            .strip_prefix("OK ")
            .and_then(|value| value.strip_suffix('\n'))
            .and_then(|value| value.parse::<u32>().ok())
            .expect("canonical OK source port")
    })
    .await
    .expect("mux acknowledgement deadline")
}

async fn open_raw_ssh(
    vmmon_socket: PathBuf,
) -> (
    mpsc::Sender<protocol::v1::ByteChunk>,
    tonic::Streaming<protocol::v1::ByteChunk>,
) {
    let channel = tokio::time::timeout(
        Duration::from_secs(2),
        Endpoint::try_from("http://[::]:50051")
            .expect("vmmon endpoint")
            .connect_with_connector(service_fn(move |_| {
                let vmmon_socket = vmmon_socket.clone();
                async move { UnixStream::connect(vmmon_socket).await.map(TokioIo::new) }
            })),
    )
    .await
    .expect("vmmon connection deadline")
    .expect("connect vmmon");
    let mut client = protocol::v1::vm_access_service_client::VmAccessServiceClient::new(channel);
    let (sender, receiver) = mpsc::channel(1);
    let stream = tokio::time::timeout(
        Duration::from_secs(2),
        client.open_ssh(ReceiverStream::new(receiver)),
    )
    .await
    .expect("SSH setup deadline")
    .expect("open SSH stream")
    .into_inner();
    (sender, stream)
}

#[tokio::test]
async fn machine_lifecycle_uses_vmmon_from_portable_runtime() {
    let env = test_env("lifecycle", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-lifecycle").await;

    start_ready(&machine).await;
    assert!(
        machine
            .inspect()
            .await
            .expect("inspect running machine")
            .is_running(),
        "machine must be running after readiness"
    );
    assert!(
        !env._run_root
            .path()
            .join("machines")
            .join(machine.id())
            .join(vm_spec::DEFAULT_VSOCK_MUX_FILENAME)
            .exists(),
        "disabled public vsock must create no mux"
    );

    machine.stop().await.expect("stop machine");
    let inspected = machine.inspect().await.expect("inspect after stop");
    assert!(!inspected.is_running(), "machine must be stopped");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn agent_disabled_machine_runs_without_public_vsock() {
    let env = test_env("agent-disabled", &Scenario::default()).await;
    let machine = env
        .runtime
        .machine()
        .name("integration-agent-disabled")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .agent_mode(Some(MachineAgent::Disabled))
        .create()
        .await
        .expect("create agent-disabled machine");

    machine.start().await.expect("start agent-disabled machine");
    assert!(machine
        .inspect()
        .await
        .expect("inspect agent-disabled machine")
        .is_running());
    assert_eq!(machine.vsock_socket().await.expect("disabled mux"), None);

    machine.stop().await.expect("stop agent-disabled machine");
    machine
        .remove()
        .await
        .expect("remove agent-disabled machine");
}

#[tokio::test]
async fn explicitly_disabled_public_vsock_preserves_internal_ssh_and_agent_services() {
    let env = test_env("disabled-vsock-services", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-disabled-vsock-services").await;
    let mut spec = machine.inspect().await.expect("inspect machine").spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: false,
        uds: None,
    });
    machine
        .replace_config(spec)
        .await
        .expect("disable public vsock");

    start_ready(&machine).await;
    assert_eq!(machine.vsock_socket().await.expect("disabled mux"), None);

    let output = machine
        .exec("/bin/echo", ["agent-over-internal-vsock"])
        .await
        .expect("guest agent request");
    assert_eq!(output.stdout_bytes(), b"agent-over-internal-vsock\n");

    let vmmon_socket = env
        ._run_root
        .path()
        .join("machines")
        .join(machine.id())
        .join("vm.sock");
    let (ssh_input, mut ssh_output) = open_raw_ssh(vmmon_socket).await;
    ssh_input
        .send(protocol::v1::ByteChunk {
            data: Some(b"ssh-over-internal-vsock".to_vec().into()),
        })
        .await
        .expect("write SSH bytes");
    let echoed = tokio::time::timeout(Duration::from_secs(2), ssh_output.message())
        .await
        .expect("SSH echo deadline")
        .expect("read SSH stream")
        .expect("SSH echo");
    assert_eq!(
        echoed.data.as_deref(),
        Some(&b"ssh-over-internal-vsock"[..])
    );

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn custom_mux_connects_to_core_and_arbitrary_guest_ports() {
    let mut scenario = Scenario::default();
    scenario.vsock.refuse_ports.push(7001);
    let env = test_env("custom-vsock-mux", &scenario).await;
    let machine = create_machine(&env, "integration-custom-vsock-mux").await;
    let mut spec = machine.inspect().await.expect("inspect machine").spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: Some(PathBuf::from("custom-vsock.sock")),
    });
    machine.replace_config(spec).await.expect("set custom mux");
    let mux_path = machine
        .vsock_socket()
        .await
        .expect("resolve custom mux")
        .expect("enabled custom mux");

    start_ready(&machine).await;
    let mut ssh = UnixStream::connect(&mux_path)
        .await
        .expect("connect custom mux");
    ssh.write_all(b"CONNECT 22\ncustom")
        .await
        .expect("dial SSH through custom mux");
    assert!(read_mux_acknowledgement(&mut ssh).await >= 1_u32 << 30);
    let mut echo = [0_u8; 6];
    tokio::time::timeout(Duration::from_secs(2), ssh.read_exact(&mut echo))
        .await
        .expect("custom mux echo deadline")
        .expect("read custom mux echo");
    assert_eq!(&echo, b"custom");

    let mut arbitrary = UnixStream::connect(&mux_path)
        .await
        .expect("connect arbitrary-port mux");
    arbitrary
        .write_all(b"CONNECT 7000\n")
        .await
        .expect("dial arbitrary guest port");
    assert!(read_mux_acknowledgement(&mut arbitrary).await >= 1_u32 << 30);

    let mut refused = UnixStream::connect(&mux_path)
        .await
        .expect("connect refused-port mux");
    refused
        .write_all(b"CONNECT 7001\n")
        .await
        .expect("dial refused guest port");
    refused.shutdown().await.expect("close refused mux input");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), refused.read_to_end(&mut response))
        .await
        .expect("refused mux close deadline")
        .expect("read refused mux closure");
    assert!(
        response.is_empty(),
        "refused guest port receives no OK reply"
    );

    machine.stop().await.expect("stop machine");
    assert!(!mux_path.exists(), "vmmon must clean the custom mux");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn reserved_host_listener_is_ignored_and_remains_extension_owned() {
    let env = test_env("reserved-vsock-listener", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-reserved-vsock-listener").await;
    let inspected = machine.inspect().await.expect("inspect machine");
    let machine_dir = inspected.machine_dir;
    let mut spec = inspected.spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: None,
    });
    machine.replace_config(spec).await.expect("enable vsock");
    let mux_path = machine
        .vsock_socket()
        .await
        .expect("resolve mux")
        .expect("enabled mux");
    let reserved_path = PathBuf::from(format!(
        "{}_{}",
        mux_path.display(),
        protocol::DEFAULT_GUEST_CONTROL_PORT
    ));
    let reserved_listener =
        UnixListener::bind(&reserved_path).expect("publish reserved listener-shaped socket");

    start_ready(&machine).await;
    assert!(
        !machine_dir
            .join(format!(".v_{}", protocol::DEFAULT_GUEST_CONTROL_PORT))
            .exists(),
        "reserved host port must not be registered"
    );

    machine.stop().await.expect("stop machine");
    assert!(
        !reserved_path.exists(),
        "libvm must remove the machine runtime tree after vmmon stops"
    );
    drop(reserved_listener);
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn mux_closes_malformed_and_oversized_commands_without_reply() {
    let env = test_env("invalid-vsock-mux", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-invalid-vsock-mux").await;
    let mut spec = machine.inspect().await.expect("inspect machine").spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: None,
    });
    machine.replace_config(spec).await.expect("enable vsock");
    let mux_path = machine
        .vsock_socket()
        .await
        .expect("resolve mux")
        .expect("enabled mux");
    start_ready(&machine).await;

    for command in [&b"CONNECT 22 \n"[..], &[b'x'; 32][..]] {
        let mut client = UnixStream::connect(&mux_path)
            .await
            .expect("connect invalid mux client");
        client
            .write_all(command)
            .await
            .expect("write invalid command");
        client
            .shutdown()
            .await
            .expect("close invalid command input");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("invalid mux close deadline")
            .expect("read invalid mux closure");
        assert!(response.is_empty(), "invalid commands receive no reply");
    }

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn hybrid_vsock_surface_serves_mux_and_preboot_listener_end_to_end() {
    let env = test_env("hybrid-vsock", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-hybrid-vsock").await;
    let inspected = machine.inspect().await.expect("inspect machine");
    let machine_dir = inspected.machine_dir.clone();
    let mut spec = inspected.spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: None,
    });
    machine.replace_config(spec).await.expect("enable vsock");

    let mux_path = machine
        .vsock_socket()
        .await
        .expect("resolve mux path")
        .expect("enabled mux path");
    let listener_path = machine
        .vsock_listener_socket(5000)
        .await
        .expect("resolve listener path")
        .expect("enabled listener path");
    let user_listener = UnixListener::bind(&listener_path).expect("bind preboot host listener");

    start_ready(&machine).await;

    let mut mux = UnixStream::connect(&mux_path).await.expect("connect mux");
    mux.write_all(b"CONNECT 22\nhello")
        .await
        .expect("write mux request");
    assert!(read_mux_acknowledgement(&mut mux).await >= 1_u32 << 30);
    let mut echoed = [0_u8; 5];
    tokio::time::timeout(Duration::from_secs(2), mux.read_exact(&mut echoed))
        .await
        .expect("mux echo deadline")
        .expect("read mux echo");
    assert_eq!(&echoed, b"hello");

    let mut arbitrary = UnixStream::connect(&mux_path)
        .await
        .expect("connect arbitrary default mux");
    arbitrary
        .write_all(b"CONNECT 7000\n")
        .await
        .expect("dial arbitrary guest port through default mux");
    assert!(read_mux_acknowledgement(&mut arbitrary).await >= 1_u32 << 30);

    let guest_path = machine_dir.join(".v_5000");
    let mut guest = UnixStream::connect(&guest_path)
        .await
        .expect("connect mock guest to host port");
    let (mut host, _) = user_listener.accept().await.expect("accept relayed guest");
    guest.write_all(b"guest").await.expect("write guest bytes");
    let mut guest_bytes = [0_u8; 5];
    host.read_exact(&mut guest_bytes)
        .await
        .expect("read guest bytes");
    assert_eq!(&guest_bytes, b"guest");
    host.write_all(b"host").await.expect("write host bytes");
    let mut host_bytes = [0_u8; 4];
    guest
        .read_exact(&mut host_bytes)
        .await
        .expect("read host bytes");
    assert_eq!(&host_bytes, b"host");

    let dynamic_listener_path = machine
        .vsock_listener_socket(5001)
        .await
        .expect("resolve dynamic listener path")
        .expect("dynamic listener path");
    let dynamic_listener =
        UnixListener::bind(&dynamic_listener_path).expect("publish dynamic host listener");
    let dynamic_guest_path = machine_dir.join(".v_5001");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !dynamic_guest_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dynamic listener registration deadline");
    let mut dynamic_guest = UnixStream::connect(&dynamic_guest_path)
        .await
        .expect("connect guest to dynamic listener");
    let (mut dynamic_host, _) = dynamic_listener
        .accept()
        .await
        .expect("accept dynamic guest");
    dynamic_guest
        .write_all(b"dynamic")
        .await
        .expect("write dynamic guest bytes");
    let mut dynamic_bytes = [0_u8; 7];
    dynamic_host
        .read_exact(&mut dynamic_bytes)
        .await
        .expect("read dynamic guest bytes");
    assert_eq!(&dynamic_bytes, b"dynamic");

    drop(dynamic_host);
    drop(dynamic_guest);
    drop(dynamic_listener);
    let mut stale_guest = UnixStream::connect(&dynamic_guest_path)
        .await
        .expect("registered guest port remains available");
    let mut closed = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), stale_guest.read(&mut closed))
            .await
            .expect("stale listener reset deadline")
            .expect("read stale listener reset"),
        0
    );

    std::fs::remove_file(&dynamic_listener_path).expect("remove stale listener socket");
    let replacement_listener =
        UnixListener::bind(&dynamic_listener_path).expect("bind replacement listener");
    let replacement_guest = UnixStream::connect(&dynamic_guest_path)
        .await
        .expect("connect guest after listener replacement");
    let (_replacement_host, _) = replacement_listener
        .accept()
        .await
        .expect("accept guest through retained registration");
    drop(replacement_guest);

    machine.stop().await.expect("stop machine");
    assert!(!mux_path.exists(), "vmmon must clean its mux socket");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn host_port_22_listener_is_independent_of_host_to_guest_ssh() {
    let env = test_env("hybrid-vsock-port-22", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-hybrid-vsock-port-22").await;
    let inspected = machine.inspect().await.expect("inspect machine");
    let machine_dir = inspected.machine_dir;
    let mut spec = inspected.spec;
    spec.vsock = Some(vm_spec::Vsock {
        enabled: true,
        uds: None,
    });
    machine.replace_config(spec).await.expect("enable vsock");
    let listener_path = machine
        .vsock_listener_socket(agent_spec::SSH_VSOCK_PORT)
        .await
        .expect("resolve SSH host listener")
        .expect("SSH host listener path");
    let listener = UnixListener::bind(&listener_path).expect("publish host port 22 listener");

    start_ready(&machine).await;
    let guest_path = machine_dir.join(format!(".v_{}", agent_spec::SSH_VSOCK_PORT));
    let guest = UnixStream::connect(guest_path)
        .await
        .expect("guest connection to host port 22");
    let (_host, _) = listener.accept().await.expect("accept host port 22 stream");
    drop(guest);

    let mux_path = machine
        .vsock_socket()
        .await
        .expect("resolve mux path")
        .expect("enabled mux path");
    let mut ssh = UnixStream::connect(mux_path)
        .await
        .expect("connect host mux");
    ssh.write_all(b"CONNECT 22\nssh")
        .await
        .expect("dial guest SSH");
    assert!(read_mux_acknowledgement(&mut ssh).await >= 1_u32 << 30);
    let mut echo = [0_u8; 3];
    tokio::time::timeout(Duration::from_secs(2), ssh.read_exact(&mut echo))
        .await
        .expect("SSH echo deadline")
        .expect("read SSH echo");
    assert_eq!(&echo, b"ssh");

    let mut guest_control = UnixStream::connect(
        machine
            .vsock_socket()
            .await
            .expect("resolve control mux path")
            .expect("enabled control mux path"),
    )
    .await
    .expect("connect control mux");
    guest_control
        .write_all(b"CONNECT 1027\n")
        .await
        .expect("dial guest control service");
    assert!(read_mux_acknowledgement(&mut guest_control).await >= 1_u32 << 30);

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_exec_round_trips_stdout() {
    let env = test_env("exec-stdout", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-exec-stdout").await;
    start_ready(&machine).await;

    let output = machine
        .exec("/bin/echo", ["hello-from-mock-guest"])
        .await
        .expect("exec in guest");
    assert!(
        matches!(output.result(), ExecutionResult::Exited { code: Some(0) }),
        "unexpected result: {:?}",
        output.result()
    );
    assert_eq!(
        String::from_utf8_lossy(output.stdout_bytes()),
        "hello-from-mock-guest\n"
    );

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_exec_round_trips_stdin() {
    let env = test_env("exec-stdin", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-exec-stdin").await;
    start_ready(&machine).await;

    let output = machine
        .exec_with("/bin/cat", |options| {
            options.stdin_bytes(b"hello-through-stdin".to_vec())
        })
        .await
        .expect("exec with stdin in guest");
    assert_eq!(output.result(), &ExecutionResult::Exited { code: Some(0) });
    assert_eq!(output.stdout_bytes(), b"hello-through-stdin");

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn guest_filesystem_round_trips_directory_and_file_operations() {
    let env = test_env("filesystem-roundtrip", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-filesystem-roundtrip").await;
    start_ready(&machine).await;

    let created = machine
        .create_directory("/nested", true, Some(0o755), None, None)
        .await
        .expect("create guest directory");
    assert_eq!(created, MachineDirectoryCreateDisposition::Created);
    let uploaded = machine
        .upload_file(
            MachineFileUploadOptions {
                path: "/nested/greeting.txt".to_string(),
                mode: Some(0o644),
                uid: None,
                gid: None,
            },
            std::io::Cursor::new(b"hello mock filesystem".to_vec()),
        )
        .await
        .expect("upload guest file");
    assert_eq!(uploaded, FileWriteDisposition::Created);

    let entry = machine
        .get_file_entry("/nested/greeting.txt")
        .await
        .expect("inspect guest file");
    assert_eq!(entry.size_bytes, 21);
    let mut download = machine
        .download_file("/nested/greeting.txt")
        .await
        .expect("download guest file");
    let mut contents = Vec::new();
    download
        .read_to_end(&mut contents)
        .await
        .expect("read guest file");
    assert_eq!(contents, b"hello mock filesystem");

    let page = machine
        .list_directory("/nested", None, None)
        .await
        .expect("list guest directory");
    assert!(
        page.entries
            .iter()
            .any(|entry| entry.name == "greeting.txt"),
        "uploaded file must appear in the directory listing: {:?}",
        page.entries
    );

    machine
        .remove_file_entry("/nested", true)
        .await
        .expect("remove guest directory");

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn serial_stream_round_trips_input() {
    let env = test_env("serial", &Scenario::default()).await;
    let machine = create_machine(&env, "integration-serial").await;
    start_ready(&machine).await;

    let mut serial = machine
        .open_serial_stream()
        .await
        .expect("open serial stream");
    serial
        .write_all(b"serial-integration-echo\n")
        .await
        .expect("write serial input");
    let mut serial_output = Vec::new();
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    while !String::from_utf8_lossy(&serial_output).contains("serial-integration-echo") {
        let mut buffer = [0u8; 1024];
        let read = tokio::time::timeout_at(deadline, serial.read(&mut buffer))
            .await
            .expect("serial echo before timeout")
            .expect("read serial output");
        assert!(read > 0, "serial stream closed before echoing input");
        serial_output.extend_from_slice(&buffer[..read]);
    }

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_start_propagates_backend_boot_failure_and_leaves_machine_stopped() {
    let scenario = Scenario {
        boot: test_utils::BootScenario {
            delay_ms: None,
            fail: Some("scripted kvm outage".to_string()),
        },
        ..Scenario::default()
    };
    let env = test_env("boot-failure", &scenario).await;

    let machine = env
        .runtime
        .machine()
        .name("mock-boot-failure")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");

    let error = machine.start().await.expect_err("start must fail");
    let message = error.to_string();
    assert!(
        message.contains("scripted kvm outage") || message.contains("mock boot failure"),
        "boot failure must carry the scripted reason: {message}"
    );

    let inspected = machine.inspect().await.expect("inspect after failed start");
    assert!(
        !inspected.is_running(),
        "machine must not stay active after a failed boot: {:?}",
        inspected.status
    );

    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_wait_reconciles_vmmon_crash_and_marks_machine_stopped() {
    let scenario = Scenario {
        run: test_utils::RunScenario {
            crash_after_ms: Some(500),
            crash_message: Some("scripted vmm crash".to_string()),
        },
        ..Scenario::default()
    };
    let env = test_env("crash", &scenario).await;

    let machine = env
        .runtime
        .machine()
        .name("mock-crash")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");

    machine.start().await.expect("start machine");

    // The scripted crash stops the machine; wait() reconciles the dead
    // monitor through the exit-status file.
    let exit = tokio::time::timeout(READY_TIMEOUT, machine.wait())
        .await
        .expect("wait resolves before timeout")
        .expect("wait reconciles the crash");
    assert!(
        !exit.machine.is_running(),
        "machine must be inactive after the crash: {:?}",
        exit.machine.status
    );
    match exit.outcome {
        MachineExitOutcome::Error { message } => assert!(
            message
                .as_deref()
                .is_some_and(|message| message.contains("scripted vmm crash")),
            "backend crash must survive vmmon exit reconciliation: {message:?}"
        ),
        other => panic!("backend crash must produce an error exit, got {other:?}"),
    }

    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_start_reports_entrypoint_command_not_found() {
    let env = test_env("startup-command", &Scenario::default()).await;

    let machine = env
        .runtime
        .machine()
        .name("mock-startup-command")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");

    let failure = machine
        .start_with(|options| {
            options.entrypoint("/silo-definitely-missing-entrypoint", |entrypoint| {
                entrypoint
            })
        })
        .await;

    match failure {
        Err(libvm::LibVmError::EntrypointLaunchFailed { failure }) => {
            assert_eq!(
                failure.reason,
                libvm::ExecutionLaunchFailureReason::CommandNotFound
            );
        }
        Err(other) => panic!("expected a typed entrypoint launch failure, got: {other}"),
        Ok(_) => panic!("missing entrypoint unexpectedly started"),
    }

    let _ = machine.stop().await;
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_entrypoint_completion_stops_with_a_clean_exit() {
    let env = test_env("startup-command-completion", &Scenario::default()).await;
    let machine = create_machine(&env, "mock-startup-command-completion").await;

    let start = machine
        .start_with(|options| options.entrypoint("/usr/bin/true", |entrypoint| entrypoint))
        .await
        .expect("start machine with entrypoint");
    let exit = tokio::time::timeout(READY_TIMEOUT, machine.wait_for_run(start.run_id.clone()))
        .await
        .expect("entrypoint completion stops vmmon before timeout")
        .expect("reconcile entrypoint completion");

    assert_eq!(exit.outcome, MachineExitOutcome::Clean);
    assert_eq!(exit.machine.status, MachineStatus::Stopped);

    machine
        .remove_after_run(start.run_id)
        .await
        .expect("remove completed run");
}

#[tokio::test]
async fn cleanup_for_an_old_entrypoint_run_cannot_remove_a_replacement() {
    let env = test_env("startup-command-replacement", &Scenario::default()).await;
    let machine = create_machine(&env, "mock-startup-command-replacement").await;

    let first = machine
        .start_with(|options| options.entrypoint("/usr/bin/true", |entrypoint| entrypoint))
        .await
        .expect("start first entrypoint run");
    machine
        .wait_for_run(first.run_id.clone())
        .await
        .expect("wait for first entrypoint run");

    let second = machine
        .start_with(|options| options.entrypoint("/usr/bin/true", |entrypoint| entrypoint))
        .await
        .expect("start replacement entrypoint run");
    machine
        .wait_for_run(second.run_id.clone())
        .await
        .expect("wait for replacement entrypoint run");

    let stale = machine
        .clone()
        .remove_after_run(first.run_id)
        .await
        .expect_err("old cleanup generation must be rejected");
    assert!(matches!(stale, LibVmError::MachineStaleGeneration { .. }));
    machine
        .remove_after_run(second.run_id)
        .await
        .expect("current cleanup generation removes machine");
}

#[tokio::test]
async fn machine_exec_reports_permission_denied_launch_failure() {
    let scenario = Scenario {
        exec: test_utils::ExecScenario {
            launch_failure: Some("PERMISSION_DENIED".to_string()),
            drop_after_events: None,
        },
        ..Scenario::default()
    };
    let env = test_env("execution-failure", &scenario).await;
    let machine = env
        .runtime
        .machine()
        .name("mock-execution-failure")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");

    machine.start().await.expect("start machine");
    let output = machine
        .exec("/bin/echo", ["never-runs"])
        .await
        .expect("execution returns a terminal result");
    match output.result() {
        ExecutionResult::LaunchFailed(failure) => {
            assert_eq!(
                failure.reason,
                ExecutionLaunchFailureReason::PermissionDenied
            );
        }
        other => panic!("expected a typed launch failure, got: {other:?}"),
    }

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn machine_exec_reports_guest_stream_lost_when_event_stream_disconnects() {
    let scenario = Scenario {
        exec: test_utils::ExecScenario {
            launch_failure: None,
            drop_after_events: Some(1),
        },
        ..Scenario::default()
    };
    let env = test_env("execution-stream-loss", &scenario).await;
    let machine = env
        .runtime
        .machine()
        .name("mock-execution-stream-loss")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");

    machine.start().await.expect("start machine");
    let output = machine
        .exec("/bin/echo", ["stream-will-drop"])
        .await
        .expect("execution returns a terminal result");
    match output.result() {
        ExecutionResult::Lost(lost) => {
            assert_eq!(lost.reason, ExecutionLostReason::GuestStreamLost);
        }
        other => panic!("expected a typed stream loss, got: {other:?}"),
    }

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn get_file_entry_preserves_guest_permission_denied_code() {
    let scenario = Scenario {
        filesystem: test_utils::FilesystemScenario {
            errors: [("/locked".to_string(), "PERMISSION_DENIED".to_string())]
                .into_iter()
                .collect(),
        },
        ..Scenario::default()
    };
    let env = test_env("filesystem-error", &scenario).await;
    let machine = env
        .runtime
        .machine()
        .name("mock-filesystem-error")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");

    machine.start().await.expect("start machine");
    let error = machine
        .get_file_entry("/locked")
        .await
        .expect_err("scripted filesystem access must fail");
    match error {
        LibVmError::MonitorProtocol { message, .. } => assert!(
            message.contains("permission_denied"),
            "filesystem error must preserve its structured code: {message}"
        ),
        other => panic!("expected a monitor protocol error, got: {other}"),
    }

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn wait_ready_times_out_without_stopping_a_running_machine() {
    let scenario = Scenario {
        agent: test_utils::AgentScenario {
            never_ready: true,
            ..test_utils::AgentScenario::default()
        },
        ..Scenario::default()
    };
    let env = test_env("never-ready", &scenario).await;
    let machine = env
        .runtime
        .machine()
        .name("mock-never-ready")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");

    machine.start().await.expect("start machine");
    let readiness = machine
        .wait_ready(Duration::from_millis(250))
        .await
        .expect("wait for readiness");
    assert_eq!(readiness.outcome, MachineReadinessOutcome::TimedOut);
    assert!(
        machine
            .inspect()
            .await
            .expect("inspect machine")
            .is_running(),
        "a readiness timeout must not stop the machine"
    );

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}

#[tokio::test]
async fn vmmon_reconnects_after_agent_restart_and_preserves_boot_identity() {
    const INITIAL_INSTANCE_ID: &str = "00000000-0000-4000-8000-000000000001";
    const BOOT_ID: &str = "00000000-0000-4000-8000-000000000002";

    let scenario = Scenario {
        agent: test_utils::AgentScenario {
            restart_after_ms: Some(250),
            instance_id: Some(INITIAL_INSTANCE_ID.to_string()),
            boot_id: Some(BOOT_ID.to_string()),
            ..test_utils::AgentScenario::default()
        },
        ..Scenario::default()
    };
    let env = test_env("agent-restart", &scenario).await;
    let machine = env
        .runtime
        .machine()
        .name("mock-agent-restart")
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine");

    machine.start().await.expect("start machine");
    let initial = machine
        .wait_ready(READY_TIMEOUT)
        .await
        .expect("initial readiness");
    assert_eq!(initial.outcome, MachineReadinessOutcome::Ready);

    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        let status = machine.monitor_status().await.expect("monitor status");
        let identity = match status.agent {
            MachineAgentStatus::Enabled(agent) => agent.identity,
            MachineAgentStatus::Disabled => panic!("mock guest agent must be enabled"),
        };
        if let Some(identity) = identity {
            if identity.instance_id != INITIAL_INSTANCE_ID {
                assert_eq!(identity.boot_id, BOOT_ID);
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "vmmon did not reconnect after the scripted agent restart"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    machine.stop().await.expect("stop machine");
    machine.remove().await.expect("remove machine");
}
