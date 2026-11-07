//! Hypervisor-free acceptance tests against the existing scenario monitor.
//! Observation and strict operation intervals deliberately have separate baselines.

use std::collections::BTreeMap;
use std::fs::File;
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use libvm::{
    ImageSource, LibVmError, LiveCapabilityQuery, LiveObservationReader, Machine,
    MachineMonitorStatus, MachineRef, ResolvedRuntimeComponents, Runtime, RuntimeConfig,
    VirtBackendOverride,
};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use protocol::v1::vm_monitor_service_client::VmMonitorServiceClient;
use protocol::v1::{GetStatusRequest, WaitReadyRequest};
use sqlx::{Connection, SqliteConnection};
use test_utils::{LiveScenario, Scenario};
use tokio::net::UnixStream;
use tonic::transport::Endpoint;
use tower::service_fn;
use vm_spec::live::{
    LiveAvailability, LiveBackend, LiveCapability, LiveCapabilityVector, LiveDeviceSubject,
    LiveLane, LiveMachineReport, LiveOperation, LiveReasonCode, LiveScope, LiveUnsupportedReason,
};

#[path = "support/live_catalog.rs"]
mod live_catalog;

const DEADLINE: Duration = Duration::from_secs(3);

fn bounded_refusal(
    operation: impl Future<Output = Result<(), LibVmError>> + Send + 'static,
    deadline: Duration,
) -> LibVmError {
    // A timer around the same async task cannot detect a synchronous flock
    // regression: that task never yields. An independent thread deadline can,
    // and unwinding releases the externally held lock if the assertion fails.
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("operation thread runtime");
        let _ = sender.send(runtime.block_on(operation));
    });
    let result = receiver
        .recv_timeout(deadline)
        .expect("operation waited for a held lock or suspended monitor");
    worker.join().expect("operation thread panicked");
    result.expect_err("expected refusal or observation failure")
}

fn suspend_monitor(pid: Pid) {
    kill(pid, Signal::SIGSTOP).expect("suspend actual monitor");
    let deadline = std::time::Instant::now() + DEADLINE;
    loop {
        let stopped = if cfg!(target_os = "linux") {
            std::fs::read_to_string(format!("/proc/{pid}/status"))
                .expect("actual monitor process status")
                .lines()
                .find_map(|line| line.strip_prefix("State:"))
                .is_some_and(|state| state.trim_start().starts_with('T'))
        } else {
            let output = std::process::Command::new("ps")
                .args(["-o", "state=", "-p", &pid.to_string()])
                .output()
                .expect("read actual monitor process state");
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .trim_start()
                    .starts_with('T')
        };
        if stopped {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "monitor did not enter stopped state"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    mode: u32,
    owner: (u32, u32),
    modified: (i64, i64),
    contents: Vec<u8>,
    symlink: Option<PathBuf>,
}

fn file_bytes(path: &Path) -> Vec<u8> {
    // Used only for malformed main-file specimens, never live catalog
    // snapshots. An independent process cannot release a writer's POSIX locks.
    let output = std::process::Command::new("cat")
        .arg(path)
        .output()
        .expect("read malformed main-file bytes in independent process");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        if matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("state.db" | "state.db-wal" | "state.db-shm")
        ) {
            return;
        }
        let metadata = std::fs::symlink_metadata(path).expect("stat without following symlink");
        let symlink = metadata
            .file_type()
            .is_symlink()
            .then(|| std::fs::read_link(path).expect("read symlink"));
        entries.insert(
            path.strip_prefix(root)
                .expect("relative path")
                .to_path_buf(),
            Entry {
                mode: metadata.mode(),
                // SQLite coordination may add/remove sidecars in this one
                // directory. All machine/runtime directory metadata stays exact.
                modified: if metadata.is_dir() && path.join("catalog.lock").exists() {
                    (0, 0)
                } else {
                    (metadata.mtime(), metadata.mtime_nsec())
                },
                owner: (metadata.uid(), metadata.gid()),
                contents: if metadata.is_file() {
                    std::fs::read(path).expect("read noncatalog fixture file")
                } else {
                    Vec::new()
                },
                symlink,
            },
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).expect("list directory") {
                visit(root, &entry.expect("directory entry").path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut entries);
    }
    entries
}

fn scenario(reason: Option<LiveReasonCode>, machine_device: bool) -> Scenario {
    let host = match reason {
        Some(reason) => LiveCapabilityVector::all_unsupported(reason),
        None => {
            let supported = LiveCapability {
                native: true,
                availability: LiveAvailability::Supported,
            };
            LiveCapabilityVector {
                pause: supported.clone(),
                capture: supported.clone(),
                restore: supported.clone(),
                fork: supported.clone(),
                incremental: supported,
            }
        }
    };
    let machine = machine_device.then(|| {
        let rejected = LiveCapability {
            native: true,
            availability: LiveAvailability::Unsupported {
                reason: LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs),
            },
        };
        LiveCapabilityVector {
            pause: rejected.clone(),
            capture: rejected.clone(),
            restore: rejected.clone(),
            fork: rejected.clone(),
            incremental: rejected,
        }
    });
    Scenario {
        live: Some(LiveScenario {
            lane: LiveLane::KvmX86_64,
            host,
            machine,
        }),
        ..Scenario::default()
    }
}

struct Fixture {
    temp: tempfile::TempDir,
    config: RuntimeConfig,
    runtime: Runtime,
    machine: Machine,
    pid: Pid,
    run_root: PathBuf,
    home: PathBuf,
    detached: bool,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        // Always reap through the monitor's normal parent when possible, even
        // if an assertion panics while the monitor is suspended.
        let _ = kill(self.pid, Signal::SIGCONT);
        let _ = kill(self.pid, Signal::SIGTERM);
    }
}

impl Fixture {
    async fn new(scenario: &Scenario) -> Self {
        let temp = tempfile::Builder::new()
            .prefix("silo-live-")
            .tempdir_in(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .expect("short private root");
        let home = temp.path().join("home");
        let run_root = temp.path().join("run");
        let scenario_path = temp.path().join("scenario.json");
        scenario
            .write_to(&scenario_path)
            .expect("write typed scenario");
        let binary = test_utils::mock_vmm_binary();
        let kernel = temp.path().join("kernel");
        let initramfs = temp.path().join("initramfs");
        std::fs::write(
            &kernel,
            test_utils::direct_kernel::host_kernel("scenario-kernel"),
        )
        .expect("write kernel fixture");
        std::fs::write(&initramfs, b"scenario-initramfs").expect("write initramfs fixture");
        let agent = temp.path().join("agent");
        std::fs::write(&agent, b"scenario-agent-fixture").expect("write inert guest agent fixture");
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755))
            .expect("agent fixture mode");
        let disk = temp.path().join("disk.raw");
        disk_image::ext4::Formatter::new(&disk, 4096, 64 * 1024 * 1024)
            .expect("create ext4 disk")
            .close()
            .expect("finish ext4 disk");
        let components = ResolvedRuntimeComponents::from_paths(
            binary.to_path_buf(),
            binary.to_path_buf(),
            kernel,
            initramfs,
            agent,
            temp.path().to_path_buf(),
        )
        .expect("validate explicit scenario components");
        let config = RuntimeConfig::local(&home)
            .with_run_root(&run_root)
            .with_runtime_components(components)
            .with_mock_vmm(&scenario_path);
        let runtime = Runtime::new(config.clone())
            .await
            .expect("open real runtime");
        let machine = runtime
            .machine()
            .name("source")
            .image_source(ImageSource::disk(disk))
            .network(|network| network.none())
            .create()
            .await
            .expect("create scenario machine");
        machine
            .start()
            .await
            .expect("start actual scenario monitor");
        let pid =
            std::fs::read_to_string(run_root.join("machines").join(machine.id()).join("vm.pid"))
                .expect("read monitor PID")
                .trim()
                .parse::<i32>()
                .expect("valid PID");
        let fixture = Self {
            temp,
            config,
            runtime,
            machine,
            pid: Pid::from_raw(pid),
            run_root,
            home,
            detached: false,
        };
        assert_eq!(
            fixture
                .machine
                .wait_ready(Duration::from_secs(30))
                .await
                .expect("wait for scenario readiness")
                .outcome,
            libvm::MachineReadinessOutcome::Ready
        );
        fixture
    }

    fn reference(&self) -> MachineRef {
        MachineRef::parse("source").expect("valid machine reference")
    }

    async fn stop(&self) {
        let _ = kill(self.pid, Signal::SIGCONT);
        self.machine.stop().await.expect("stop scenario monitor");
    }
}

fn unsupported(
    error: LibVmError,
    operation: LiveOperation,
    backend: LiveBackend,
    reason: LiveReasonCode,
    subject: Option<LiveDeviceSubject>,
) {
    match error {
        LibVmError::LiveOperationUnsupported {
            operation: actual,
            backend: actual_backend,
            lane,
            reason: actual_reason,
        } => {
            assert_eq!(actual, operation);
            assert_eq!(actual_backend, backend);
            assert_eq!(lane, LiveLane::KvmX86_64);
            assert_eq!(
                actual_reason,
                LiveUnsupportedReason {
                    code: reason,
                    subject
                }
            );
        }
        other => panic!("expected exact typed unsupported error, got {other:?}"),
    }
}

#[tokio::test]
async fn live_capabilities_query_freezes_selection_and_rewritten_scenario_changes_new_identity() {
    let temp = tempfile::tempdir().expect("private root");
    let path = temp.path().join("scenario.json");
    scenario(Some(LiveReasonCode::NotDelivered), false)
        .write_to(&path)
        .expect("write first scenario");
    let config = RuntimeConfig::local(temp.path().join("absent-home"))
        .with_run_root(temp.path().join("absent-run"))
        .with_supervisor_path(test_utils::mock_vmm_binary())
        .with_mock_vmm(&path);
    let first_query = LiveCapabilityQuery::open(&config).expect("resolve first selection");
    let first = first_query
        .host_report()
        .await
        .expect("query first scenario");
    scenario(Some(LiveReasonCode::BackendExcluded), false)
        .write_to(&path)
        .expect("replace same scenario path");
    let second = LiveCapabilityQuery::open(&config)
        .expect("resolve changed selection")
        .host_report()
        .await
        .expect("query changed scenario");
    assert_ne!(first.scenario_digest, second.scenario_digest);
    assert_ne!(first.live, second.live);
    assert!(
        matches!(
            first_query.host_report().await,
            Err(LibVmError::LiveDiscovery { .. })
        ),
        "stale frozen selection must fail before returning a cached report"
    );
    let equal_path = temp.path().join("equal.json");
    std::fs::copy(&path, &equal_path).expect("copy identical scenario bytes");
    let equal = LiveCapabilityQuery::open(&config.clone().with_mock_vmm(&equal_path))
        .expect("resolve equal bytes")
        .host_report()
        .await
        .expect("query equal bytes");
    assert_eq!(equal.scenario_digest, second.scenario_digest);
    assert!(!temp.path().join("absent-home").exists());
    assert!(!temp.path().join("absent-run").exists());
    std::fs::remove_file(&path).expect("remove explicitly selected scenario");
    assert!(matches!(
        LiveCapabilityQuery::open(&config),
        Err(LibVmError::LiveDiscovery { .. })
    ));
}

#[tokio::test]
async fn live_capabilities_cold_query_and_absent_catalog_never_initialize_runtime() {
    let temp = tempfile::tempdir().expect("private root");
    let home = temp.path().join("absent-home");
    let config = RuntimeConfig::local(&home)
        .with_run_root(temp.path().join("absent-run"))
        .with_supervisor_path(test_utils::mock_vmm_binary())
        .with_virt_backend(VirtBackendOverride::Vz);
    let before = snapshot(temp.path());
    let host = LiveCapabilityQuery::open(&config)
        .expect("open cold query")
        .host_report()
        .await
        .expect("query excluded VZ without constructing it");
    assert_eq!(host.backend, LiveBackend::Vz);
    assert_eq!(host.scope, LiveScope::Host);
    let reader = LiveObservationReader::open(&config).expect("open path-only reader");
    assert!(reader
        .observe(&MachineRef::parse("missing").expect("valid name"))
        .await
        .is_err());
    assert_eq!(snapshot(temp.path()), before);
}

#[tokio::test]
async fn live_capabilities_get_status_wait_ready_and_actual_run_override_agree() {
    let fixture = Fixture::new(&scenario(None, true)).await;
    let socket = fixture
        .run_root
        .join("machines")
        .join(fixture.machine.id())
        .join("vm.sock");
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_| {
            let socket = socket.clone();
            async move { UnixStream::connect(socket).await.map(TokioIo::new) }
        }))
        .await
        .expect("connect real monitor");
    let mut client = VmMonitorServiceClient::new(channel);
    let status = client
        .get_status(GetStatusRequest {})
        .await
        .expect("GetStatus")
        .into_inner();
    let ready = client
        .wait_ready(WaitReadyRequest {
            max_wait: Some(prost_types::Duration {
                seconds: 1,
                nanos: 0,
            }),
        })
        .await
        .expect("WaitReady")
        .into_inner()
        .status
        .expect("mandatory status");
    assert_eq!(status.live, ready.live);
    let report: LiveMachineReport = status
        .live
        .expect("mandatory live")
        .try_into()
        .expect("strict live conversion");
    assert_eq!(report.backend, LiveBackend::Mock);
    assert_eq!(
        uuid::Uuid::parse_str(&report.machine_id).expect("canonical reported machine UUID"),
        uuid::Uuid::parse_str(&fixture.machine.id()).expect("durable machine UUID"),
    );
    assert_eq!(report.scope, LiveScope::Machine);
    for operation in LiveOperation::ALL {
        assert!(
            matches!(&report.live.get(operation).availability, LiveAvailability::Unsupported { reason } if reason == &LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs))
        );
    }
    let prospective = fixture
        .config
        .clone()
        .with_virt_backend(VirtBackendOverride::Vz);
    let host = LiveCapabilityQuery::open(&prospective)
        .expect("resolve different prospective backend")
        .host_report()
        .await
        .expect("query excluded VZ without hypervisor access");
    assert_eq!(host.backend, LiveBackend::Vz);
    let observation = LiveObservationReader::open(&prospective)
        .expect("readonly reader")
        .observe(&fixture.reference())
        .await
        .expect("observe actual run");
    assert_eq!(
        observation.report(),
        &report,
        "current prospective selection must not relabel actual Mock run"
    );
    fixture.stop().await;
}

#[tokio::test]
async fn live_capabilities_unsupported_operations_refuse_under_real_lock_and_suspended_monitor() {
    for reason in [
        LiveReasonCode::BackendExcluded,
        LiveReasonCode::HostOsBelowFloor,
        LiveReasonCode::LaneNotQualified,
        LiveReasonCode::HypervisorUnavailable,
        LiveReasonCode::BuildExcluded,
        LiveReasonCode::NotDelivered,
        LiveReasonCode::DeviceProfileRejected,
    ] {
        let fixture = Fixture::new(&scenario(
            (reason != LiveReasonCode::DeviceProfileRejected).then_some(reason),
            reason == LiveReasonCode::DeviceProfileRejected,
        ))
        .await;
        let observation = LiveObservationReader::open(&fixture.config)
            .expect("reader")
            .observe(&fixture.reference())
            .await
            .expect("explicit observation before strict interval");
        let host = LiveCapabilityQuery::open(&fixture.config)
            .expect("host query")
            .host_report()
            .await
            .expect("host report");
        // The lock is the runtime's actual numeric operation lock, not vm.lock
        // (which belongs to the monitor's separate machine lifetime).
        let lock_entries: Vec<_> = std::fs::read_dir(fixture.run_root.join("locks"))
            .expect("operation locks")
            .map(|entry| entry.expect("lock entry").path())
            .collect();
        assert_eq!(lock_entries.len(), 1);
        let _operation_lock = Flock::lock(
            File::options()
                .read(true)
                .write(true)
                .open(&lock_entries[0])
                .expect("open existing operation lock"),
            FlockArg::LockExclusiveNonblock,
        )
        .expect("hold real operation lock");
        let marker = fixture.home.join("boundary-marker");
        std::fs::write(&marker, b"untouched").expect("write marker");
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o400))
            .expect("marker mode");
        symlink("boundary-marker", fixture.home.join("boundary-link")).expect("symlink marker");
        suspend_monitor(fixture.pid);
        let before_home = snapshot(&fixture.home);
        let before_catalog = live_catalog::snapshot(&fixture.home).await;
        let before_run = snapshot(&fixture.run_root);
        let subject = (reason == LiveReasonCode::DeviceProfileRejected)
            .then_some(LiveDeviceSubject::Virtiofs);
        for operation in [
            LiveOperation::Pause,
            LiveOperation::Capture,
            LiveOperation::Fork,
        ] {
            let machine = fixture.machine.clone();
            let observed = observation.clone();
            let error = bounded_refusal(
                async move {
                    match operation {
                        LiveOperation::Pause => machine.pause(&observed).await.map(|_| ()),
                        LiveOperation::Capture => machine
                            .snapshot_live(&observed, capture_options())
                            .await
                            .map(|_| ()),
                        LiveOperation::Fork => machine
                            .fork_live(&observed, fork_options())
                            .await
                            .map(|_| ()),
                        _ => unreachable!("machine-only operation table"),
                    }
                },
                DEADLINE,
            );
            unsupported(error, operation, LiveBackend::Mock, reason, subject.clone());
        }
        if reason == LiveReasonCode::DeviceProfileRejected {
            // Artifact restore has no dependency on this running machine's
            // rejected topology. Host support is a separate admission scope.
            libvm::require_host_live_operation(&host, LiveOperation::Restore).unwrap();
        } else {
            let error = bounded_refusal(
                async move { libvm::require_host_live_operation(&host, LiveOperation::Restore) },
                DEADLINE,
            );
            unsupported(
                error,
                LiveOperation::Restore,
                LiveBackend::Mock,
                reason,
                None,
            );
        }
        assert_eq!(
            snapshot(&fixture.home),
            before_home,
            "strict operation changed machine files for {reason:?}"
        );
        assert_eq!(
            snapshot(&fixture.run_root),
            before_run,
            "strict operation changed run files for {reason:?}"
        );
        assert_eq!(
            live_catalog::snapshot(&fixture.home).await,
            before_catalog,
            "strict operation changed logical catalog/schema"
        );
        drop(_operation_lock);
        fixture.stop().await;
    }
}

#[tokio::test]
async fn live_capabilities_positive_mock_reports_delivered_fork_without_mutation() {
    let fixture = Fixture::new(&pause_scenario(Default::default())).await;
    let observation = LiveObservationReader::open(&fixture.config)
        .expect("reader")
        .observe(&fixture.reference())
        .await
        .expect("observe positive scenario");
    let before = snapshot(&fixture.home);
    let before_catalog = live_catalog::snapshot(&fixture.home).await;
    libvm::require_live_operation(&observation, LiveOperation::Fork)
        .expect("the delivered fork gate honors a positive capability observation");
    assert_eq!(snapshot(&fixture.home), before);
    assert_eq!(live_catalog::snapshot(&fixture.home).await, before_catalog);
    fixture.stop().await;
}

fn pause_scenario(lifecycle: test_utils::LifecycleScenario) -> Scenario {
    Scenario {
        lifecycle: Some(lifecycle),
        ..scenario(None, false)
    }
}

fn capture_options() -> libvm::LiveSnapshotOptions {
    libvm::LiveSnapshotOptions {
        name: None,
        resume_policy: vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired,
    }
}

fn fork_options() -> libvm::LiveForkOptions {
    libvm::LiveForkOptions {
        operation_id: uuid::Uuid::new_v4(),
        children: vec![libvm::LiveForkChild {
            name: "unallocated-child".into(),
            activation_hook: None,
            destination: libvm::ForkDestination::default(),
        }],
        max_children: libvm::DEFAULT_LIVE_FORK_MAX_CHILDREN,
        resume_policy: vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired,
        resources: libvm::RestoreResourcePolicy::default(),
    }
}

async fn wait_pause_state(
    machine: &Machine,
    expected: vm_spec::lifecycle::VmLifecycleState,
) -> libvm::MachineLiveObservation {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let observation = machine.observe_live().await.unwrap();
        if observation.state().unwrap() == expected {
            return observation;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "lifecycle did not reach {expected}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn pause_independent_manager_recovers_lost_receipt_replay_conflict_and_stops_parked() {
    use vm_spec::lifecycle::*;
    let fixture = Fixture::new(&pause_scenario(Default::default())).await;
    let before = fixture.machine.monitor_status().await.unwrap();
    let observed = fixture.machine.observe_live().await.unwrap();
    let request_id = uuid::Uuid::new_v4();
    let receipt = fixture
        .machine
        .pause_with_request(&observed, request_id)
        .await
        .unwrap();
    assert!(matches!(
        receipt,
        LiveCommandResult::Pause(PauseOutcome::Accepted { .. })
    ));
    // Deliberately discard the establishing response. Another Runtime must use
    // the monitor and durable intent, not memory in the original handle.
    let paused = wait_pause_state(&fixture.machine, VmLifecycleState::Paused).await;
    let current = paused.lifecycle().unwrap().current_pause.unwrap();
    let captures = fixture
        .home
        .join("machines")
        .join(fixture.machine.id())
        .join("captures");
    assert_eq!(std::fs::metadata(&captures).unwrap().mode() & 0o777, 0o700);
    assert!(std::fs::read_dir(&captures).unwrap().next().is_none());
    let child = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .kill_on_drop(true)
            .args(["--exact", "pause_manager_restart_child", "--nocapture"])
            .env("SILO_PAUSE_MANAGER_HOME", &fixture.home)
            .env("SILO_PAUSE_MANAGER_RUN_ROOT", &fixture.run_root)
            .env("SILO_PAUSE_MANAGER_ASSETS", fixture.temp.path())
            .env(
                "SILO_PAUSE_MANAGER_TOKEN",
                serde_json::to_string(&current).unwrap(),
            )
            .output(),
    )
    .await
    .expect("independent manager deadline")
    .unwrap();
    assert!(
        child.status.success(),
        "independent manager: stdout={} stderr={}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let independent = Runtime::new(fixture.config.clone()).await.unwrap();
    let machine = independent.get_machine(&fixture.reference()).await.unwrap();
    let fresh = machine.observe_live().await.unwrap();
    assert_eq!(
        fresh.lifecycle().unwrap().current_pause.as_ref(),
        Some(&current)
    );
    let operation = machine
        .get_operation(&fresh, uuid::Uuid::new_v4(), current.operation_id.clone())
        .await
        .unwrap();
    let LiveCommandResult::GetOperation(GetOperationOutcome::Observation { observation }) =
        operation
    else {
        panic!("operation not observed");
    };
    assert_eq!(observation.operation.status(), OperationStatus::Succeeded);
    let OperationOutcome::Succeeded { pause } = observation.operation.outcome else {
        panic!("no establishing token");
    };
    assert_eq!(pause.token, current.token);
    assert_eq!(
        machine
            .pause_with_request(&fresh, request_id)
            .await
            .unwrap(),
        receipt
    );
    let conflict = machine
        .live_command(
            &fresh,
            LiveCommand::Resume(ResumeCommand {
                envelope: LiveCommandEnvelope {
                    machine_id: current.token.machine_id.clone(),
                    run_id: current.token.run_id.clone(),
                    request_id: LiveId::parse(&request_id.to_string()).unwrap(),
                },
                operation_id: current.operation_id.clone(),
                token: current.token.clone(),
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        conflict.rejection().unwrap().reason.code(),
        LiveRejectionCode::RequestConflict
    );
    let inspected = machine.inspect().await.unwrap();
    assert_eq!(inspected.status.label(), "paused");
    assert!(!inspected.status.ready());
    assert_eq!(inspected.run_id, before.run_id);
    let snapshot = machine.monitor_status().await.unwrap();
    match (&snapshot.agent, &before.agent) {
        (libvm::MachineAgentStatus::Enabled(after), libvm::MachineAgentStatus::Enabled(before)) => {
            assert_eq!(after.identity, before.identity)
        }
        _ => panic!("scenario must retain its enabled resident agent"),
    }
    machine.stop().await.unwrap();
    assert_eq!(machine.inspect().await.unwrap().status.label(), "stopped");
}

#[tokio::test]
async fn pause_lost_thaw_recovery_keeps_original_success_and_resume_replay_cannot_consume_new_token(
) {
    use vm_spec::lifecycle::*;
    let lifecycle = test_utils::LifecycleScenario {
        thaw: vec![test_utils::GuestThawStep {
            delay_ms: 0,
            result: test_utils::GuestThawResult::DropResponse,
        }],
        ..Default::default()
    };
    let fixture = Fixture::new(&pause_scenario(lifecycle)).await;
    let established = fixture
        .machine
        .pause(&fixture.machine.observe_live().await.unwrap())
        .await
        .unwrap();
    let original = established.lifecycle.current_pause.unwrap();
    let observed = fixture.machine.observe_live().await.unwrap();
    let resume_id = uuid::Uuid::new_v4();
    let result = fixture
        .machine
        .resume_with_request(&observed, resume_id)
        .await
        .unwrap();
    let LiveCommandResult::Resume(ResumeOutcome::Failed { failed }) = &result else {
        panic!("lost thaw must fail resume explicitly: {result:?}");
    };
    assert_eq!(failed.state, VmLifecycleState::Paused);
    let recovered = failed.current_pause.as_ref().unwrap();
    assert!(recovered.token.generation > original.token.generation);
    assert!(recovered.freeze_epoch > original.freeze_epoch);
    let current = fixture.machine.observe_live().await.unwrap();
    assert_eq!(
        current.lifecycle().unwrap().current_pause.as_ref(),
        Some(recovered)
    );
    let original_request = LiveCommand::Resume(ResumeCommand {
        envelope: LiveCommandEnvelope {
            machine_id: original.token.machine_id.clone(),
            run_id: original.token.run_id.clone(),
            request_id: LiveId::parse(&resume_id.to_string()).unwrap(),
        },
        operation_id: original.operation_id.clone(),
        token: original.token.clone(),
    });
    assert_eq!(
        fixture
            .machine
            .live_command(&current, original_request)
            .await
            .unwrap(),
        result
    );
    assert_eq!(
        fixture
            .machine
            .observe_live()
            .await
            .unwrap()
            .lifecycle()
            .unwrap()
            .current_pause
            .as_ref(),
        Some(recovered)
    );
    let queried = fixture
        .machine
        .get_operation(
            &current,
            uuid::Uuid::new_v4(),
            original.operation_id.clone(),
        )
        .await
        .unwrap();
    let LiveCommandResult::GetOperation(GetOperationOutcome::Observation { observation }) = queried
    else {
        panic!("missing operation");
    };
    let OperationOutcome::Succeeded { pause } = observation.operation.outcome else {
        panic!("original Pause changed");
    };
    assert_eq!(pause.token, original.token);
    assert_eq!(observation.current_pause.as_ref(), Some(recovered));
    let resumed = fixture.machine.resume(&current).await.unwrap();
    assert_eq!(resumed.state, VmLifecycleState::Running);
    assert!(resumed.lifecycle.current_pause.is_none());
    fixture.stop().await;
}

#[tokio::test]
async fn pause_partial_failure_cancel_and_failed_rollback_preserve_recovery_exit() {
    use vm_spec::lifecycle::*;
    for rollback_fails in [false, true] {
        let lifecycle = test_utils::LifecycleScenario {
            native_pause: vec![test_utils::NativePauseStep {
                delay_ms: 0,
                result: test_utils::NativePauseResult::Fail,
            }],
            native_cancel: if rollback_fails {
                vec![test_utils::NativeCancelStep {
                    delay_ms: 0,
                    result: test_utils::NativeCancelResult::Fail,
                }]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        let fixture = Fixture::new(&pause_scenario(lifecycle)).await;
        assert!(fixture
            .machine
            .pause(&fixture.machine.observe_live().await.unwrap())
            .await
            .is_err());
        let failed = wait_pause_state(&fixture.machine, VmLifecycleState::Pausing).await;
        let lifecycle = failed.lifecycle().unwrap();
        assert!(lifecycle.current_pause.is_none());
        assert_eq!(
            lifecycle.activity.as_ref().unwrap().stage,
            LiveStage::PauseFailed
        );
        let target = lifecycle.activity.unwrap().operation_id;
        let result = fixture
            .machine
            .cancel_operation(&failed, uuid::Uuid::new_v4(), target)
            .await
            .unwrap();
        if rollback_fails {
            assert!(matches!(
                result,
                LiveCommandResult::CancelOperation(CancelOperationOutcome::Failed { .. })
            ));
            let current = fixture.machine.observe_live().await.unwrap();
            assert_eq!(current.state().unwrap(), VmLifecycleState::Error);
            assert!(current.lifecycle().unwrap().error.is_some());
        } else {
            assert!(matches!(
                result,
                LiveCommandResult::CancelOperation(CancelOperationOutcome::Completed { .. })
            ));
            assert_eq!(
                fixture
                    .machine
                    .observe_live()
                    .await
                    .unwrap()
                    .state()
                    .unwrap(),
                VmLifecycleState::Running
            );
        }
        fixture.stop().await;
    }
}

#[tokio::test]
async fn pause_dropped_resume_waiter_reconciles_original_request_without_consuming_authority_twice()
{
    use vm_spec::lifecycle::*;
    let lifecycle = test_utils::LifecycleScenario {
        native_resume: vec![test_utils::NativeResumeStep {
            delay_ms: 400,
            result: test_utils::NativeResumeResult::Complete,
            clock_delay_ms: 0,
        }],
        ..Default::default()
    };
    let fixture = Fixture::new(&pause_scenario(lifecycle)).await;
    let established = fixture
        .machine
        .pause(&fixture.machine.observe_live().await.unwrap())
        .await
        .unwrap();
    let original = established.lifecycle.current_pause.unwrap();
    let request_id = uuid::Uuid::new_v4();
    let command = LiveCommand::Resume(ResumeCommand {
        envelope: LiveCommandEnvelope {
            machine_id: original.token.machine_id.clone(),
            run_id: original.token.run_id.clone(),
            request_id: LiveId::parse(&request_id.to_string()).unwrap(),
        },
        operation_id: original.operation_id.clone(),
        token: original.token.clone(),
    });
    let machine = fixture.machine.clone();
    let request = command.clone();
    let observed = machine.observe_live().await.unwrap();
    let waiter = tokio::spawn(async move { machine.live_command(&observed, request).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let observed = fixture.machine.observe_live().await.unwrap();
        if observed
            .lifecycle()
            .unwrap()
            .activity
            .is_some_and(|activity| activity.request_id.as_str() == request_id.to_string())
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "resume was not admitted"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    waiter.abort();
    let _ = waiter.await;
    let independent = Runtime::new(fixture.config.clone()).await.unwrap();
    let machine = independent.get_machine(&fixture.reference()).await.unwrap();
    let current = machine.reconcile_live().await.unwrap();
    assert_eq!(current.state, VmLifecycleState::Running);
    assert!(current.lifecycle.current_pause.is_none());
    let replay = machine
        .live_command(&machine.observe_live().await.unwrap(), command)
        .await
        .unwrap();
    let LiveCommandResult::Resume(ResumeOutcome::Resumed { resumed }) = replay else {
        panic!("original Resume did not settle");
    };
    assert_eq!(resumed.consumed_token, original.token);
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(fixture.home.join("state.db"))
        .read_only(true)
        .create_if_missing(false);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM live_command WHERE json_extract(input_json,'$.command.command')='resume'")
        .fetch_one(&mut connection).await.unwrap();
    connection.close().await.unwrap();
    assert_eq!(count, 1, "recovery invented a replacement Resume identity");
    fixture.stop().await;
}

#[tokio::test]
async fn pause_manager_restart_child() {
    let Some(home) = std::env::var_os("SILO_PAUSE_MANAGER_HOME") else {
        return;
    };
    let run = std::env::var_os("SILO_PAUSE_MANAGER_RUN_ROOT").unwrap();
    let assets = PathBuf::from(std::env::var_os("SILO_PAUSE_MANAGER_ASSETS").unwrap());
    let expected: vm_spec::lifecycle::CurrentPause =
        serde_json::from_str(&std::env::var("SILO_PAUSE_MANAGER_TOKEN").unwrap()).unwrap();
    let binary = test_utils::mock_vmm_binary();
    let components = ResolvedRuntimeComponents::from_paths(
        binary.to_path_buf(),
        binary.to_path_buf(),
        assets.join("kernel"),
        assets.join("initramfs"),
        assets.join("agent"),
        assets.clone(),
    )
    .unwrap();
    let config = RuntimeConfig::local(home)
        .with_run_root(run)
        .with_runtime_components(components)
        .with_mock_vmm(assets.join("scenario.json"));
    let observed = LiveObservationReader::open(&config)
        .unwrap()
        .observe(&MachineRef::parse("source").unwrap())
        .await
        .unwrap();
    assert_eq!(
        observed.lifecycle().unwrap().current_pause.as_ref(),
        Some(&expected)
    );
    let runtime = Runtime::new(config).await.unwrap();
    let machine = runtime
        .get_machine(&MachineRef::parse("source").unwrap())
        .await
        .unwrap();
    let current = machine.reconcile_live().await.unwrap();
    assert_eq!(current.state, vm_spec::lifecycle::VmLifecycleState::Paused);
    assert_eq!(current.lifecycle.current_pause.as_ref(), Some(&expected));
    // The independent manager exits without any continuation policy.
}

#[tokio::test]
async fn pause_freeze_and_recovery_failure_rows_are_fenced_without_fabricated_authority() {
    use vm_spec::lifecycle::*;
    for fault in [false, true] {
        let lifecycle = test_utils::LifecycleScenario {
            freeze: vec![test_utils::GuestFreezeStep {
                delay_ms: 0,
                result: if fault {
                    test_utils::GuestFreezeResult::Faulted
                } else {
                    test_utils::GuestFreezeResult::FreezeFailed
                },
            }],
            ..Default::default()
        };
        let fixture = Fixture::new(&pause_scenario(lifecycle)).await;
        assert!(fixture
            .machine
            .pause(&fixture.machine.observe_live().await.unwrap())
            .await
            .is_err());
        let current = fixture.machine.observe_live().await.unwrap();
        assert_eq!(
            current.state().unwrap(),
            if fault {
                VmLifecycleState::Error
            } else {
                VmLifecycleState::Running
            }
        );
        assert!(current.lifecycle().unwrap().current_pause.is_none());
        fixture.stop().await;
    }
    for native_failure in [false, true] {
        let lifecycle = test_utils::LifecycleScenario {
            thaw: vec![test_utils::GuestThawStep {
                delay_ms: 0,
                result: test_utils::GuestThawResult::DropResponse,
            }],
            freeze: if native_failure {
                Vec::new()
            } else {
                vec![
                    test_utils::GuestFreezeStep {
                        delay_ms: 0,
                        result: test_utils::GuestFreezeResult::Frozen,
                    },
                    test_utils::GuestFreezeStep {
                        delay_ms: 0,
                        result: test_utils::GuestFreezeResult::Faulted,
                    },
                ]
            },
            native_pause: if native_failure {
                vec![
                    test_utils::NativePauseStep {
                        delay_ms: 0,
                        result: test_utils::NativePauseResult::Complete,
                    },
                    test_utils::NativePauseStep {
                        delay_ms: 0,
                        result: test_utils::NativePauseResult::Fail,
                    },
                ]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        let fixture = Fixture::new(&pause_scenario(lifecycle)).await;
        let established = fixture
            .machine
            .pause(&fixture.machine.observe_live().await.unwrap())
            .await
            .unwrap();
        let result = fixture
            .machine
            .resume_with_request(
                &fixture.machine.observe_live().await.unwrap(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
        let LiveCommandResult::Resume(ResumeOutcome::Failed { failed }) = result else {
            panic!("recovery failure must be explicit");
        };
        assert_eq!(failed.state, VmLifecycleState::Error);
        assert!(failed.current_pause.is_none());
        assert!(failed.recovery_failure.is_some());
        let current = fixture.machine.observe_live().await.unwrap();
        assert_eq!(current.state().unwrap(), VmLifecycleState::Error);
        assert!(current.lifecycle().unwrap().current_pause.is_none());
        let target = established.lifecycle.current_pause.unwrap().operation_id;
        let query = fixture
            .machine
            .get_operation(&current, uuid::Uuid::new_v4(), target)
            .await
            .unwrap();
        let LiveCommandResult::GetOperation(GetOperationOutcome::Observation { observation }) =
            query
        else {
            panic!("Error must retain GetOperation");
        };
        assert_eq!(observation.operation.status(), OperationStatus::Succeeded);
        fixture.stop().await;
    }
}

// A real separate process proves cold observation without an initialized
// writable Runtime. SQLite may coordinate its normal WAL/SHM files.
#[tokio::test]
async fn live_capabilities_cold_observer_process() {
    let Some(home) = std::env::var_os("SILO_ACCEPTANCE_OBSERVER_HOME") else {
        return;
    };
    let run = std::env::var_os("SILO_ACCEPTANCE_OBSERVER_RUN").expect("child run root");
    let name = std::env::var("SILO_ACCEPTANCE_OBSERVER_NAME").expect("child reference");
    let config = RuntimeConfig::local(PathBuf::from(home)).with_run_root(PathBuf::from(run));
    let result = match LiveObservationReader::open(&config) {
        Ok(reader) => {
            reader
                .observe(&MachineRef::parse(name).expect("child reference"))
                .await
        }
        Err(error) => Err(error),
    };
    let value = match result {
        Ok(observation) => serde_json::json!({"report": observation.report()}),
        Err(LibVmError::MachineNotFound { .. }) => serde_json::json!({"error": "not-found"}),
        Err(error) => serde_json::json!({"error": "observation", "detail": error.to_string()}),
    };
    println!("SILO_ACCEPTANCE_RESULT={value}");
}

async fn cold_observe(home: &Path, run: &Path, name: &str) -> serde_json::Value {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(std::env::current_exe().expect("integration binary"))
            .args([
                "--exact",
                "live_capabilities_cold_observer_process",
                "--nocapture",
            ])
            .env("SILO_ACCEPTANCE_OBSERVER_HOME", home)
            .env("SILO_ACCEPTANCE_OBSERVER_RUN", run)
            .env("SILO_ACCEPTANCE_OBSERVER_NAME", name)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("cold observer terminates")
    .expect("launch cold observer");
    assert!(
        output.status.success(),
        "observer child: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("observer UTF-8 output");
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("SILO_ACCEPTANCE_RESULT="))
        .expect("child result record");
    serde_json::from_str(line).expect("child JSON result")
}

#[tokio::test]
async fn live_capabilities_cold_active_wal_observes_commits_not_uncommitted_without_writes() {
    let fixture = Fixture::new(&scenario(Some(LiveReasonCode::NotDelivered), false)).await;
    let database = fixture.home.join("state.db");
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&database)
        .create_if_missing(false);
    let mut writer = SqliteConnection::connect_with(&options)
        .await
        .expect("independent real SQLite writer");
    sqlx::query("PRAGMA wal_autocheckpoint = 0")
        .execute(&mut writer)
        .await
        .expect("disable fixture writer automatic checkpoint");
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut writer)
        .await
        .expect("actual fixture journal mode");
    assert_eq!(
        journal, "wal",
        "visibility test must use real WAL-mode SQLite"
    );
    sqlx::query("UPDATE machine_config SET name = 'committed-in-wal', config_json = jsonb_set(config_json, '$.name', 'committed-in-wal') WHERE id = ?")
        .bind(fixture.machine.id()).execute(&mut writer).await.expect("commit WAL-only machine name");
    let before = snapshot(&fixture.home);
    let before_catalog = live_catalog::snapshot(&fixture.home).await;
    let visible = cold_observe(&fixture.home, &fixture.run_root, "committed-in-wal").await;
    let report: LiveMachineReport = serde_json::from_value(visible["report"].clone())
        .expect("committed WAL-only row is observable");
    assert_eq!(
        uuid::Uuid::parse_str(&report.machine_id).expect("canonical reported machine UUID"),
        uuid::Uuid::parse_str(&fixture.machine.id()).expect("durable machine UUID"),
    );
    assert_eq!(report.backend, LiveBackend::Mock);
    assert_eq!(
        snapshot(&fixture.home),
        before,
        "cold read changed machine files, modes, links or inventory"
    );
    assert_eq!(
        live_catalog::snapshot(&fixture.home).await,
        before_catalog,
        "cold reader changed logical committed catalog/schema"
    );

    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut writer)
        .await
        .expect("begin real writer transaction");
    sqlx::query("UPDATE machine_config SET name = 'uncommitted-name', config_json = jsonb_set(config_json, '$.name', 'uncommitted-name') WHERE id = ?")
        .bind(fixture.machine.id()).execute(&mut writer).await.expect("write uncommitted name");
    let before = snapshot(&fixture.home);
    let before_catalog = live_catalog::snapshot(&fixture.home).await;
    let committed = cold_observe(&fixture.home, &fixture.run_root, "committed-in-wal").await;
    assert_eq!(committed["report"]["runId"], report.run_id);
    assert_eq!(
        cold_observe(&fixture.home, &fixture.run_root, "uncommitted-name").await["error"],
        "not-found"
    );
    assert_eq!(
        snapshot(&fixture.home),
        before,
        "cold reader repaired or modified state while a writer held a transaction"
    );
    assert_eq!(
        live_catalog::snapshot(&fixture.home).await,
        before_catalog,
        "reader changed committed logical state while writer transaction remained uncommitted"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut writer)
        .await
        .expect("rollback fixture write");
    writer.close().await.expect("close independent writer");
    fixture.stop().await;
}

#[tokio::test]
async fn live_capabilities_cold_missing_empty_truncated_and_corrupt_catalogs_never_initialize_or_repair(
) {
    let temp = tempfile::tempdir().expect("private root");
    let valid = temp.path().join("valid-sqlite");
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&valid)
        .create_if_missing(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("create native SQLite corruption fixture");
    sqlx::query("CREATE TABLE acceptance_fixture (value TEXT)")
        .execute(&mut connection)
        .await
        .expect("initialize real SQLite pages");
    connection
        .close()
        .await
        .expect("close before constructing corrupt specimen");
    let mut corrupt = std::fs::read(&valid).expect("read closed SQLite fixture");
    assert!(corrupt.len() >= 4096);
    corrupt[100..].fill(0xff);
    for contents in [
        None,
        Some(Vec::new()),
        Some(b"SQLite format 3\0".to_vec()),
        Some(vec![0; 100]),
        Some(corrupt.clone()),
    ] {
        let home = temp.path().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&home).expect("create fixture home");
        std::fs::write(home.join("catalog.lock"), b"").expect("existing catalog coordination file");
        std::fs::set_permissions(
            home.join("catalog.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("valid catalog exclusion mode");
        if let Some(contents) = contents {
            std::fs::write(home.join("state.db"), contents).expect("write malformed database");
        }
        symlink("missing", home.join("unrelated-link")).expect("sentinel symlink");
        let before = snapshot(&home);
        let before_main = home
            .join("state.db")
            .exists()
            .then(|| file_bytes(&home.join("state.db")));
        let result = cold_observe(&home, &temp.path().join("absent-run"), "source").await;
        assert!(result.get("error").is_some(), "{result}");
        assert_eq!(
            snapshot(&home),
            before,
            "malformed catalog observation initialized or changed machine files"
        );
        assert_eq!(
            home.join("state.db")
                .exists()
                .then(|| file_bytes(&home.join("state.db"))),
            before_main,
            "observer created or repaired malformed main catalog"
        );
        assert!(!temp.path().join("absent-run").exists());
    }
}

#[tokio::test]
async fn live_capabilities_actual_status_mandatory_fields_and_generation_are_strict() {
    let fixture = Fixture::new(&scenario(Some(LiveReasonCode::NotDelivered), false)).await;
    let socket = fixture
        .run_root
        .join("machines")
        .join(fixture.machine.id())
        .join("vm.sock");
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_| {
            let socket = socket.clone();
            async move { UnixStream::connect(socket).await.map(TokioIo::new) }
        }))
        .await
        .expect("connect scenario monitor");
    let status = VmMonitorServiceClient::new(channel)
        .get_status(GetStatusRequest {})
        .await
        .expect("actual GetStatus")
        .into_inner();
    assert!(MachineMonitorStatus::try_from(status.clone()).is_ok());
    for field in [
        "live",
        "schema",
        "scope",
        "backend",
        "lane",
        "machine",
        "run",
        "monitor",
        "topology",
        "vector",
        "pause",
        "capture",
        "restore",
        "fork",
        "incremental",
        "native",
        "availability",
        "unknown-backend",
        "unknown-lane",
        "unknown-scope",
        "unknown-reason",
        "device-without-subject",
        "mismatched-run",
        "mismatched-machine",
        "mismatched-monitor",
    ] {
        let mut invalid = status.clone();
        if field == "live" {
            invalid.live = None;
        } else {
            let live = invalid.live.as_mut().expect("actual live report");
            match field {
                "schema" => live.schema_version = None,
                "scope" => live.scope = None,
                "backend" => live.backend = None,
                "lane" => live.lane = None,
                "machine" => live.machine_id = None,
                "run" => live.run_id = None,
                "monitor" => live.monitor_id = None,
                "topology" => live.topology_revision = None,
                "vector" => live.live = None,
                "pause" => live.live.as_mut().unwrap().pause = None,
                "capture" => live.live.as_mut().unwrap().capture = None,
                "restore" => live.live.as_mut().unwrap().restore = None,
                "fork" => live.live.as_mut().unwrap().fork = None,
                "incremental" => live.live.as_mut().unwrap().incremental = None,
                "native" => live.live.as_mut().unwrap().pause.as_mut().unwrap().native = None,
                "availability" => {
                    live.live
                        .as_mut()
                        .unwrap()
                        .pause
                        .as_mut()
                        .unwrap()
                        .availability = None
                }
                "unknown-backend" => live.backend = Some(999),
                "unknown-lane" => live.lane = Some(999),
                "unknown-scope" => live.scope = Some(999),
                "unknown-reason" | "device-without-subject" => {
                    let capability = live.live.as_mut().unwrap().pause.as_mut().unwrap();
                    capability.availability =
                        Some(protocol::v1::live_capability::Availability::Unsupported(
                            protocol::v1::LiveUnsupportedReason {
                                code: Some(if field == "unknown-reason" { 999 } else { 7 }),
                                subject: None,
                            },
                        ));
                }
                "mismatched-run" => live.run_id = Some(uuid::Uuid::new_v4().to_string()),
                "mismatched-machine" => live.machine_id = Some(uuid::Uuid::new_v4().to_string()),
                "mismatched-monitor" => live.monitor_id = Some(uuid::Uuid::new_v4().to_string()),
                _ => unreachable!("closed mutation table"),
            }
        }
        assert!(
            MachineMonitorStatus::try_from(invalid).is_err(),
            "consumer accepted malformed mandatory field {field}"
        );
    }
    fixture.stop().await;
}

#[tokio::test]
async fn live_capabilities_start_consumes_original_resolved_scenario_bytes() {
    for change in ["replaced", "removed"] {
        let mut original_scenario = scenario(Some(LiveReasonCode::NotDelivered), false);
        original_scenario.exec.launch_failure = Some("PERMISSION_DENIED".to_string());
        let mut fixture = Fixture::new(&original_scenario).await;
        fixture.stop().await;
        let original = fixture
            .runtime
            .live_capabilities()
            .await
            .expect("frozen report before source change");
        let source = fixture.temp.path().join("scenario.json");
        if change == "removed" {
            std::fs::remove_file(&source).expect("remove source before next start");
        } else {
            scenario(Some(LiveReasonCode::BackendExcluded), false)
                .write_to(&source)
                .expect("replace scenario before next start");
        }
        fixture
            .machine
            .start()
            .await
            .expect("start consumes resolved bytes, not mutable path");
        fixture.pid = Pid::from_raw(
            std::fs::read_to_string(
                fixture
                    .run_root
                    .join("machines")
                    .join(fixture.machine.id())
                    .join("vm.pid"),
            )
            .expect("new monitor PID")
            .trim()
            .parse()
            .expect("valid PID"),
        );
        assert_eq!(
            fixture
                .machine
                .wait_ready(Duration::from_secs(30))
                .await
                .expect("scenario ready")
                .outcome,
            libvm::MachineReadinessOutcome::Ready
        );
        let observed = LiveObservationReader::open(&fixture.config)
            .expect("reader")
            .observe(&fixture.reference())
            .await
            .expect("observe frozen-start run");
        assert_eq!(observed.report().backend, LiveBackend::Mock);
        assert_eq!(observed.report().live, original.live);
        let execution = fixture
            .machine
            .exec("/bin/echo", ["must-never-run"])
            .await
            .expect("real scenario execution service terminal result");
        match execution.result() {
            libvm::ExecutionResult::LaunchFailed(failure) => assert_eq!(
                failure.reason,
                libvm::ExecutionLaunchFailureReason::PermissionDenied
            ),
            result => panic!("{change} source changed frozen non-live behavior: {result:?}"),
        }
        assert!(execution.stdout_bytes().is_empty());
        assert!(
            matches!(
                fixture.runtime.live_capabilities().await,
                Err(LibVmError::LiveDiscovery { .. })
            ),
            "changed source cannot silently reselect an existing Runtime"
        );
        fixture.stop().await;
    }
}

#[tokio::test]
async fn live_capabilities_cached_report_cannot_survive_executable_replacement_or_retarget() {
    for change in [
        "atomic-replacement",
        "symlink-retarget",
        "in-place-metadata",
        "in-place-rewrite",
    ] {
        let temp = tempfile::tempdir().expect("private root");
        let first = temp.path().join("monitor-one");
        std::fs::copy(test_utils::mock_vmm_binary(), &first)
            .expect("private copy of actual monitor");
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o700))
            .expect("executable private copy");
        let selected = temp.path().join("selected-monitor");
        symlink(&first, &selected).expect("selected executable symlink");
        let config = RuntimeConfig::local(temp.path().join("absent-home"))
            .with_run_root(temp.path().join("absent-run"))
            .with_supervisor_path(&selected)
            .with_virt_backend(VirtBackendOverride::Vz);
        let query = LiveCapabilityQuery::open(&config).expect("resolve actual executable");
        assert_eq!(
            query
                .host_report()
                .await
                .expect("populate immutable refusal cache")
                .backend,
            LiveBackend::Vz
        );
        match change {
            "atomic-replacement" => {
                let replacement = temp.path().join("replacement");
                std::fs::copy(test_utils::mock_vmm_binary(), &replacement)
                    .expect("copy actual replacement");
                std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
                    .expect("replacement deliberately not executable");
                std::fs::rename(replacement, &first).expect("atomic executable replacement");
            }
            "symlink-retarget" => {
                let replacement = temp.path().join("replacement");
                std::fs::copy(test_utils::mock_vmm_binary(), &replacement)
                    .expect("copy actual replacement");
                std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
                    .expect("retarget deliberately not executable");
                std::fs::remove_file(&selected).expect("unlink selected symlink");
                symlink(replacement, &selected).expect("retarget selected executable");
            }
            "in-place-metadata" => {
                std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o600))
                    .expect("change original executable identity metadata");
            }
            "in-place-rewrite" => {
                let metadata = std::fs::metadata(&first).expect("original executable metadata");
                let mut file = File::options()
                    .write(true)
                    .open(&first)
                    .expect("rewrite private actual monitor");
                file.write_all(b"BAD!")
                    .expect("invalidate executable header without changing length");
                file.set_times(
                    std::fs::FileTimes::new()
                        .set_modified(metadata.modified().expect("original modification time")),
                )
                .expect("restore mtime, not ctime");
            }
            _ => unreachable!("closed executable change table"),
        }
        assert!(
            matches!(
                query.host_report().await,
                Err(LibVmError::LiveDiscovery { .. })
            ),
            "stale cached report hid {change}"
        );
        assert!(!temp.path().join("absent-home").exists());
        assert!(!temp.path().join("absent-run").exists());
    }
}

#[tokio::test]
async fn live_capabilities_scenario_bounds_and_absent_marker_are_not_compatibility_defaults() {
    let temp = tempfile::tempdir().expect("private root");
    let path = temp.path().join("scenario.json");
    std::fs::write(&path, b"{}").expect("explicit empty scenario");
    let config = RuntimeConfig::local(temp.path().join("absent-home"))
        .with_run_root(temp.path().join("absent-run"))
        .with_supervisor_path(test_utils::mock_vmm_binary());
    let absent = LiveCapabilityQuery::open(
        &config
            .clone()
            .with_virt_backend(VirtBackendOverride::Mock { scenario: None }),
    )
    .expect("absent selection")
    .host_report()
    .await
    .expect("default scenario report");
    let explicit = LiveCapabilityQuery::open(&config.clone().with_mock_vmm(&path))
        .expect("explicit selection")
        .host_report()
        .await
        .expect("explicit empty scenario report");
    assert!(absent.scenario_digest.is_none());
    assert!(explicit.scenario_digest.is_some());
    assert_eq!(absent.live, explicit.live);
    std::fs::write(&path, vec![b' '; 1024 * 1024 + 1]).expect("oversized scenario");
    let before = snapshot(temp.path());
    assert!(matches!(
        LiveCapabilityQuery::open(&config.clone().with_mock_vmm(&path)),
        Err(LibVmError::LiveDiscovery { .. })
    ));
    assert_eq!(snapshot(temp.path()), before);
    std::fs::write(&path, b"{").expect("malformed scenario bytes");
    let before = snapshot(temp.path());
    let query = LiveCapabilityQuery::open(&config.with_mock_vmm(&path))
        .expect("freeze bounded bytes, not invented default");
    assert!(matches!(
        query.host_report().await,
        Err(LibVmError::LiveDiscovery { .. })
    ));
    assert_eq!(snapshot(temp.path()), before);
}

#[tokio::test]
async fn live_capabilities_wrong_machine_evidence_fails_before_unsupported_reason() {
    let fixture = Fixture::new(&scenario(Some(LiveReasonCode::NotDelivered), false)).await;
    let observation = LiveObservationReader::open(&fixture.config)
        .expect("reader")
        .observe(&fixture.reference())
        .await
        .expect("source observation");
    let other_disk = fixture.temp.path().join("other.raw");
    disk_image::ext4::Formatter::new(&other_disk, 4096, 64 * 1024 * 1024)
        .expect("create other ext4 disk")
        .close()
        .expect("finish other ext4 disk");
    let other = fixture
        .runtime
        .machine()
        .name("other")
        .image_source(ImageSource::disk(other_disk))
        .network(|network| network.none())
        .create()
        .await
        .expect("other machine handle");
    let before_home = snapshot(&fixture.home);
    let before_catalog = live_catalog::snapshot(&fixture.home).await;
    let before_run = snapshot(&fixture.run_root);
    for result in [
        other.pause(&observation).await.map(|_| ()),
        other
            .snapshot_live(&observation, capture_options())
            .await
            .map(|_| ()),
        other
            .fork_live(&observation, fork_options())
            .await
            .map(|_| ()),
    ] {
        assert!(
            matches!(result, Err(LibVmError::LiveObservation { .. })),
            "wrong machine evidence must fail before semantic capability refusal: {result:?}"
        );
    }
    assert_eq!(snapshot(&fixture.home), before_home);
    assert_eq!(snapshot(&fixture.run_root), before_run);
    assert_eq!(live_catalog::snapshot(&fixture.home).await, before_catalog);
    fixture.stop().await;
}

#[tokio::test]
async fn live_capabilities_effective_readonly_mount_narrows_positive_but_preserves_host_refusal() {
    for host_reason in [None, Some(LiveReasonCode::LaneNotQualified)] {
        // There is deliberately no scenario machine vector. Only the actual
        // effective configured read-only virtiofs mount may narrow this run.
        let mut fixture = Fixture::new(&scenario(host_reason, false)).await;
        fixture.stop().await;
        let shared = fixture.temp.path().join("readonly-share");
        std::fs::create_dir(&shared).expect("real host directory mount");
        std::fs::write(shared.join("sentinel"), b"read-only host share").expect("mount contents");
        let mut spec = fixture
            .machine
            .inspect()
            .await
            .expect("stopped machine config")
            .spec;
        spec.mounts = vec![vm_spec::Mount {
            source: shared.clone(),
            tag: "readonly-share".to_string(),
            read_only: true,
        }];
        fixture
            .machine
            .replace_config(spec)
            .await
            .expect("persist actual readonly mount");
        let before_share = snapshot(&shared);
        let host = fixture
            .runtime
            .live_capabilities()
            .await
            .expect("prospective host report without machine narrowing");
        fixture
            .machine
            .start()
            .await
            .expect("start with actual readonly mount");
        fixture.pid = Pid::from_raw(
            std::fs::read_to_string(
                fixture
                    .run_root
                    .join("machines")
                    .join(fixture.machine.id())
                    .join("vm.pid"),
            )
            .expect("new monitor PID")
            .trim()
            .parse()
            .expect("valid PID"),
        );
        assert_eq!(
            fixture
                .machine
                .wait_ready(Duration::from_secs(30))
                .await
                .expect("mounted scenario ready")
                .outcome,
            libvm::MachineReadinessOutcome::Ready
        );
        let socket = fixture
            .run_root
            .join("machines")
            .join(fixture.machine.id())
            .join("vm.sock");
        let channel = Endpoint::from_static("http://[::]:50051")
            .connect_with_connector(service_fn(move |_| {
                let socket = socket.clone();
                async move { UnixStream::connect(socket).await.map(TokioIo::new) }
            }))
            .await
            .expect("connect real monitor");
        let mut client = VmMonitorServiceClient::new(channel);
        let status = client
            .get_status(GetStatusRequest {})
            .await
            .expect("GetStatus with configured mount")
            .into_inner();
        let ready = client
            .wait_ready(WaitReadyRequest {
                max_wait: Some(prost_types::Duration {
                    seconds: 1,
                    nanos: 0,
                }),
            })
            .await
            .expect("WaitReady with configured mount")
            .into_inner()
            .status
            .expect("mandatory WaitReady status");
        assert_eq!(status.live, ready.live);
        let actual: LiveMachineReport = status
            .live
            .expect("mandatory run live")
            .try_into()
            .expect("strict machine report");
        for operation in LiveOperation::ALL {
            let expected = match host_reason {
                None => {
                    assert_eq!(
                        host.live.get(operation).availability,
                        LiveAvailability::Supported
                    );
                    LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs)
                }
                Some(reason) => LiveUnsupportedReason::new(reason),
            };
            assert_eq!(
                actual.live.get(operation).availability,
                LiveAvailability::Unsupported { reason: expected }
            );
            assert_eq!(
                actual.live.get(operation).native,
                host.live.get(operation).native
            );
        }
        assert_eq!(
            snapshot(&shared),
            before_share,
            "read-only mount fixture was mutated"
        );
        fixture.stop().await;
    }
}

#[tokio::test]
async fn live_capabilities_malformed_indexed_rows_fail_before_status_without_mutation() {
    let fixture = Fixture::new(&scenario(Some(LiveReasonCode::NotDelivered), false)).await;
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(fixture.home.join("state.db"))
        .create_if_missing(false);
    let mut writer = SqliteConnection::connect_with(&options)
        .await
        .expect("real fixture catalog writer");
    suspend_monitor(fixture.pid);
    for (select, malformed_blob, malformed_text, restore) in [
        (
            "SELECT CAST(config_json AS BLOB) FROM machine_config WHERE id = ?",
            "UPDATE machine_config SET config_json = x'00' WHERE id = ?",
            "UPDATE machine_config SET config_json = '{}' WHERE id = ?",
            "UPDATE machine_config SET config_json = ? WHERE id = ?",
        ),
        (
            "SELECT CAST(state_json AS BLOB) FROM machine_state WHERE machine_id = ?",
            "UPDATE machine_state SET state_json = x'00' WHERE machine_id = ?",
            "UPDATE machine_state SET state_json = '{}' WHERE machine_id = ?",
            "UPDATE machine_state SET state_json = ? WHERE machine_id = ?",
        ),
    ] {
        let saved: Vec<u8> = sqlx::query_scalar(select)
            .bind(fixture.machine.id())
            .fetch_one(&mut writer)
            .await
            .expect("retain valid original current-format row");
        for mutation in [malformed_blob, malformed_text] {
            sqlx::query(mutation)
                .bind(fixture.machine.id())
                .execute(&mut writer)
                .await
                .expect("commit malformed payload with valid indexed identity");
            let before_home = snapshot(&fixture.home);
            let before_catalog = live_catalog::snapshot(&fixture.home).await;
            let before_run = snapshot(&fixture.run_root);
            let reader =
                LiveObservationReader::open(&fixture.config).expect("readonly observation reader");
            let reference = fixture.reference();
            // This independent deadline is shorter than the monitor status
            // RPC deadline. The actual suspended monitor cannot mask a row
            // decoding regression by returning a later observation timeout.
            let error = bounded_refusal(
                async move { reader.observe(&reference).await.map(|_| ()) },
                Duration::from_secs(1),
            );
            assert!(
                matches!(error, LibVmError::LiveObservation { .. }),
                "malformed persisted row must fail typed observation: {error:?}"
            );
            assert_eq!(
                snapshot(&fixture.home),
                before_home,
                "corrupt row observation changed machine files"
            );
            assert_eq!(
                snapshot(&fixture.run_root),
                before_run,
                "corrupt row observation changed run files"
            );
            assert_eq!(
                live_catalog::snapshot(&fixture.home).await,
                before_catalog,
                "corrupt row observation mutated logical catalog/schema"
            );
            sqlx::query(restore)
                .bind(&saved)
                .bind(fixture.machine.id())
                .execute(&mut writer)
                .await
                .expect("restore valid fixture after no-write assertion");
        }
    }
    writer.close().await.expect("close fixture writer");
    fixture.stop().await;
}

struct DetachedMonitor {
    root: PathBuf,
    pid: Pid,
}

impl Drop for DetachedMonitor {
    fn drop(&mut self) {
        let _ = kill(self.pid, Signal::SIGCONT);
        let _ = kill(self.pid, Signal::SIGTERM);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn live_capabilities_cold_catalog_observes_detached_actual_run_without_initialization() {
    let mut fixture = Fixture::new(&scenario(Some(LiveReasonCode::NotDelivered), false)).await;
    let expected = fixture
        .machine
        .observe_live()
        .await
        .expect("observe actual run before detaching")
        .report()
        .clone();
    let home = fixture.home.clone();
    let run = fixture.run_root.clone();
    let detached = DetachedMonitor {
        root: fixture.temp.path().to_path_buf(),
        pid: fixture.pid,
    };
    // Retain the same monitor/filesystem identity but release every writable
    // Runtime/Machine handle. SQLite owns any auxiliary-file coordination.
    fixture.detached = true;
    fixture.temp.disable_cleanup(true);
    drop(fixture);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let file = File::open(home.join("catalog.lock")).expect("existing catalog guard");
        if let Ok(exclusive) = Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            drop(exclusive);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "last SQLx writer did not release its catalog guard"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let before_home = snapshot(&home);
    let before_catalog = live_catalog::snapshot(&home).await;
    let before_run = snapshot(&run);
    let result = cold_observe(&home, &run, "source").await;
    let actual: LiveMachineReport = serde_json::from_value(result["report"].clone())
        .expect("cold catalog resolves detached actual monitor run");
    assert_eq!(actual, expected);
    assert_eq!(
        snapshot(&home),
        before_home,
        "cold observer initialized or changed machine files"
    );
    assert_eq!(
        snapshot(&run),
        before_run,
        "quiescent observer changed actual run files"
    );
    assert_eq!(
        live_catalog::snapshot(&home).await,
        before_catalog,
        "detached-run observation changed logical catalog/schema"
    );
    drop(detached);
}
