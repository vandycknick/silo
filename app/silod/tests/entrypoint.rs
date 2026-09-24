//! Black-box tests of the silod executable through its published interface.
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use silod_spec::paths::DaemonPaths;
use silod_spec::status::{DaemonPhase, DaemonStatus};

fn command(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_silod"));
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SILO_HOME", home.join("ignored-home"))
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
fn help_and_check_do_not_read_cli_config_or_create_state() {
    let root = tempfile::tempdir().expect("temporary home");
    unreadable_cli_config(root.path());
    let help = command(root.path()).arg("--help").output().expect("help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("silod [OPTIONS]"));
    assert!(help.contains("--system-cpus"));
    assert!(help.contains("--check"));
    assert!(!help.contains("Commands:"));

    let valid = command(root.path())
        .args(["--check", "--system-cpus", "2"])
        .output()
        .expect("check");
    assert!(valid.status.success(), "{valid:?}");
    let invalid = command(root.path())
        .args(["--check", "--system-cpus", "0"])
        .output()
        .expect("check");
    assert!(!invalid.status.success());
    let error = String::from_utf8_lossy(&invalid.stderr);
    assert!(error.contains("cpus must be greater than zero"), "{error}");
    assert!(!root.path().join(".silo").exists());
    assert!(!root.path().join("ignored-home").exists());

    for argument in ["--home", "--state", "service", "start", "stop", "upgrade"] {
        assert!(!command(root.path())
            .arg(argument)
            .output()
            .expect("reject management interface")
            .status
            .success());
    }
}

#[test]
fn invalid_configuration_is_published_as_a_failure() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let root = tempfile::tempdir().expect("temporary home");
    let output = command(root.path())
        .args(["--system-memory", "1MiB"])
        .output()
        .expect("serve");
    assert!(!output.status.success());
    let status = read_status(&DaemonPaths::for_user_home(root.path())).expect("status");
    assert_eq!(status.phase, DaemonPhase::Failed);
    assert!(status
        .last_error
        .as_deref()
        .unwrap_or_default()
        .contains("at least 128MiB"));
    assert!(!root.path().join(".silo/daemon/daemon.json").exists());
}

#[test]
fn daemon_retries_startup_and_stops_cleanly_in_the_fixed_home() {
    // The daemon intentionally refuses root. This test exercises the same entrypoint
    // under an ordinary user, as in the host CI lanes.
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let root = tempfile::tempdir().expect("temporary home");
    unreadable_cli_config(root.path());
    // A genuinely missing runtime prevents any VM launch or registry access, while
    // exercising real startup, status publication, retry, and signal handling.
    let mut child = Process(
        command(root.path())
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
    let paths = DaemonPaths::for_user_home(root.path());
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = read_status(&paths) {
            if status.phase == DaemonPhase::Retrying {
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
    assert!(status
        .last_error
        .as_deref()
        .unwrap_or_default()
        .contains("missing-runtime"));
    assert_eq!(status.pid, child.0.id());
    assert_eq!(
        status.configured_image.as_deref(),
        Some("registry.invalid/unused:test")
    );
    assert_eq!(status.memory_bytes, Some(1024 * 1024 * 1024));
    assert_eq!(
        status.docker_socket,
        paths.docker_socket().display().to_string()
    );
    assert!(!root.path().join("ignored-home").exists());

    // A second daemon for the same installation refuses to start.
    let second = command(root.path()).output().expect("second daemon");
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("another Silo system daemon"));
    // `--stop` never races a live daemon for its VM.
    let stop = command(root.path()).arg("--stop").output().expect("stop");
    assert!(!stop.status.success());
    assert!(String::from_utf8_lossy(&stop.stderr).contains("another Silo system daemon"));

    // SIGTERM during startup retries is a clean, reported stop.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).expect("pid")),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("terminate");
    let exit = child.0.wait().expect("wait");
    assert!(exit.success(), "{exit:?}");
    assert_eq!(
        read_status(&paths).expect("status").phase,
        DaemonPhase::Stopped
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
    let status = read_status(&DaemonPaths::for_user_home(root.path())).expect("status");
    assert_eq!(status.phase, DaemonPhase::Stopped);
    assert!(!root.path().join(".silo/daemon/daemon.json").exists());
}
