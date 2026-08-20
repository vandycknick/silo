//! libvm <-> vmmon integration tests for hosts without virtualization support.
//!
//! Each test spawns a real vmmon process built with its `mock-backend`
//! feature, so the full launch handshake (pipes, daemonization, gRPC socket),
//! machine lifecycle, guest execution, and exit reconciliation are exercised
//! against the in-process fake guest instead of a VM.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libvm::{
    ExecutionLaunchFailureReason, ExecutionLostReason, ExecutionResult, FileWriteDisposition,
    ImageSource, LibVmError, Machine, MachineAgentStatus, MachineDirectoryCreateDisposition,
    MachineExitOutcome, MachineFileUploadOptions, MachineReadinessOutcome, Runtime, RuntimeConfig,
};
use test_utils::Scenario;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
}

async fn test_env(name: &str, scenario: &Scenario) -> TestEnv {
    let temp = tempfile::tempdir().expect("create temp dir");
    // Unix socket paths live under the run root and must stay below SUN_LEN
    // (104 bytes on macOS); the default TMPDIR can be too deep for that.
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
    }
}

async fn create_machine(env: &TestEnv, name: &str) -> Machine {
    env.runtime
        .machine()
        .name(name)
        .image_source(ImageSource::Disk(env.disk.clone()))
        .network(|network| network.none())
        .create()
        .await
        .expect("create machine")
}

async fn start_ready(machine: &Machine) {
    machine.start().await.expect("start machine");
    let readiness = machine
        .wait_ready(READY_TIMEOUT)
        .await
        .expect("wait for readiness");
    assert_eq!(readiness.outcome, MachineReadinessOutcome::Ready);
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

    machine.stop().await.expect("stop machine");
    let inspected = machine.inspect().await.expect("inspect after stop");
    assert!(!inspected.is_running(), "machine must be stopped");
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
