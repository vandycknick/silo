//! Black-box tests of the silod executable through its published interface.
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use silod_spec::paths::DaemonPaths;
use silod_spec::status::{CorePhase, DaemonStatus, SystemPhase};

fn command(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_silod"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SILO_HOME", home.join("runtime-home"))
        .env("SILO_VIRT_BACKEND", "not-a-daemon-setting")
        .env("SILO_RUNTIME_DIR", home.join("missing-runtime"));
    command
}

fn unreadable_cli_config(home: &std::path::Path) {
    std::fs::create_dir_all(home.join(".config/silo")).expect("config dir");
    std::fs::write(
        home.join(".config/silo/config.yaml"),
        b"daemon: [invalid yaml",
    )
    .expect("unreadable CLI config");
}

fn read_status(paths: &DaemonPaths) -> Option<DaemonStatus> {
    let bytes = std::fs::read(paths.status()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn malformed_shared_configuration_is_rejected_without_creating_state() {
    let root = tempfile::tempdir().expect("temporary home");
    unreadable_cli_config(root.path());
    let original = std::fs::read(root.path().join(".config/silo/config.yaml")).expect("config");
    let check = command(root.path()).arg("--check").output().expect("check");
    assert_eq!(check.status.code(), Some(2));
    assert_eq!(
        std::fs::read(root.path().join(".config/silo/config.yaml")).expect("config"),
        original
    );
    assert!(!root.path().join("runtime-home").exists());
    assert!(!root.path().join(".silo").exists());
}

#[test]
fn invalid_system_configuration_exits_two_before_startup() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let root = tempfile::tempdir().expect("temporary home");
    let output = command(root.path())
        .arg("--system-enabled=true")
        .args(["--system-memory", "1MiB"])
        .output()
        .expect("serve");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least 128MiB"));
    assert!(!root.path().join("runtime-home").exists());
}

#[test]
fn daemon_keeps_core_ready_through_system_retry_and_log_failure() {
    // The daemon intentionally refuses root. This test exercises the same entrypoint
    // under an ordinary user, as in the host CI lanes.
    if nix::unistd::geteuid().is_root() {
        return;
    }
    use std::os::unix::fs::OpenOptionsExt;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(std::env::temp_dir().join(format!(
            "silo-control-fixture-{}.lock",
            nix::unistd::geteuid()
        )))
        .expect("fixture lock");
    let _fixture = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .expect("use an idle dedicated test UID");
    let existing = Command::new("pgrep")
        .args(["-x", "silod"])
        .output()
        .expect("check live silod");
    assert_eq!(
        existing.status.code(),
        Some(1),
        "live silod found; use an idle dedicated test UID"
    );
    let root = tempfile::tempdir().expect("temporary home");
    // A genuinely missing runtime prevents any VM launch or registry access, while
    // exercising real startup, status publication, retry, and signal handling.
    let mut child = Process(
        command(root.path())
            .arg("--system-enabled=true")
            .args([
                "--system-image",
                "registry.invalid/unused:test",
                "--system-cpus",
                "2",
                "--system-memory",
                "1GiB",
                "--system-root-size",
                "512MiB",
                "--system-data-size",
                "512MiB",
                "--system-home-share",
                "false",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon"),
    );
    let paths = DaemonPaths::new(root.path().join("runtime-home"));
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = read_status(&paths) {
            if status
                .system
                .as_ref()
                .is_some_and(|system| system.phase == SystemPhase::Retrying)
            {
                break status;
            }
        }
        assert!(
            child.0.try_wait().expect("poll daemon").is_none(),
            "daemon exited before retrying"
        );
        assert!(Instant::now() < deadline, "daemon did not reach retrying");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.core, CorePhase::Ready);
    let system = status.system.as_ref().expect("enabled system");
    assert!(system
        .last_error
        .as_deref()
        .unwrap_or_default()
        .contains("missing-runtime"));
    assert_eq!(status.pid, child.0.id());
    assert_eq!(
        system.configured_image.as_deref(),
        Some("registry.invalid/unused:test")
    );
    assert_eq!(system.memory_bytes, Some(1024 * 1024 * 1024));
    assert_eq!(
        system.docker_socket,
        paths.docker_socket().display().to_string()
    );
    assert!(!root.path().join(".silo").exists());

    // A second daemon for the same installation refuses to start.
    let second = command(root.path()).output().expect("second daemon");
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("another Silo system daemon"));
    // `--stop` never races a live daemon for its VM.
    let stop = command(root.path()).arg("--stop").output().expect("stop");
    assert!(!stop.status.success());
    assert!(String::from_utf8_lossy(&stop.stderr).contains("another Silo system daemon"));

    // Losing the optional system's log must not tear down the core API.
    std::fs::remove_file(paths.log()).expect("remove fixture log");
    std::fs::create_dir(paths.log()).expect("block optional log writes");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.0.try_wait().expect("poll daemon").is_none(),
            "optional logging failure killed core"
        );
        if read_status(&paths).is_some_and(|status| {
            status.core == CorePhase::Ready
                && status
                    .system
                    .is_some_and(|system| system.phase == SystemPhase::Failed)
        }) {
            break;
        }
        assert!(Instant::now() < deadline, "system did not report failure");
        std::thread::sleep(Duration::from_millis(20));
    }
    let endpoint = status.control_endpoint;
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async move {
            let channel = tonic::transport::Endpoint::from_static("http://localhost")
                .connect_with_connector(tower::service_fn(move |_| {
                    let endpoint = endpoint.clone();
                    async move {
                        tokio::net::UnixStream::connect(endpoint)
                            .await
                            .map(hyper_util::rt::TokioIo::new)
                    }
                }))
                .await
                .expect("core connection");
            let response =
                silod_spec::daemon::v1::daemon_service_client::DaemonServiceClient::new(channel)
                    .get_status(())
                    .await
                    .expect("working core after system failure")
                    .into_inner();
            assert_eq!(
                response.core,
                silod_spec::daemon::v1::CorePhase::Ready as i32
            );
        });

    // SIGTERM after optional failure is still a clean, reported stop.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).expect("pid")),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("terminate");
    let exit = child.0.wait().expect("wait");
    assert!(exit.success(), "{exit:?}");
    assert_eq!(
        read_status(&paths).expect("status").core,
        CorePhase::Stopped
    );
}

#[test]
fn stop_without_an_installation_reports_stopped() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let root = tempfile::tempdir().expect("temporary home");
    let output = command(root.path()).arg("--stop").output().expect("stop");
    assert!(output.status.success(), "{output:?}");
    let status = read_status(&DaemonPaths::new(root.path().join("runtime-home"))).expect("status");
    assert_eq!(status.core, CorePhase::Stopped);
    assert_eq!(status.system.unwrap().phase, SystemPhase::Stopped);
    assert!(!root.path().join("runtime-home/daemon/daemon.json").exists());
}
