//! Capability discovery invokes the real monitor without constructing a VM.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use vm_spec::live::{
    LiveAvailability, LiveBackend, LiveHostReport, LiveOperation, LiveReasonCode, LiveScope,
};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("silo-cap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).expect("create private test directory");
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    mode: u32,
    owner: (u32, u32),
    modified: (i64, i64),
    contents: Vec<u8>,
    target: Option<PathBuf>,
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        let metadata = std::fs::symlink_metadata(path).expect("stat entry without following links");
        let target = metadata
            .file_type()
            .is_symlink()
            .then(|| std::fs::read_link(path).expect("read link"));
        entries.insert(
            path.strip_prefix(root)
                .expect("relative path")
                .to_path_buf(),
            Entry {
                mode: metadata.mode(),
                owner: (metadata.uid(), metadata.gid()),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                contents: if metadata.is_file() {
                    std::fs::read(path).expect("read file")
                } else {
                    Vec::new()
                },
                target,
            },
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).expect("list directory") {
                visit(root, &entry.expect("directory entry").path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

fn bounded_output(command: &mut Command) -> Output {
    const LIMIT: u64 = 2 * 1024 * 1024;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn real monitor");
    let stdout = child.stdout.take().expect("child stdout");
    let stderr = child.stderr.take().expect("child stderr");
    fn read(reader: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            reader
                .take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .expect("read bounded child output");
            bytes
        })
    }
    let stdout = read(stdout);
    let stderr = read(stderr);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll real monitor child") {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break child.wait().expect("reap timed-out real monitor");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().expect("stdout reader joined");
    let stderr = stderr.join().expect("stderr reader joined");
    assert!(
        !timed_out,
        "capability subprocess exceeded external deadline"
    );
    assert!(
        stdout.len() as u64 <= LIMIT && stderr.len() as u64 <= LIMIT,
        "capability subprocess exceeded output bound"
    );
    Output {
        status,
        stdout,
        stderr,
    }
}

fn command(temp: &Temp, backend: &str, scenario: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_silo-vmm"));
    command
        .current_dir(&temp.0)
        .env("SILO_HOME", temp.0.join("absent-home"))
        .env("SILO_RUN_ROOT", temp.0.join("absent-run"))
        .args(["capabilities", "--backend", backend, "--json"]);
    if let Some(scenario) = scenario {
        command.arg("--scenario").arg(scenario);
    }
    bounded_output(&mut command)
}

fn report(output: Output) -> LiveHostReport {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("strict complete host report")
}

fn assert_reason(report: &LiveHostReport, reason: LiveReasonCode) {
    assert_eq!(report.scope, LiveScope::Host);
    assert_eq!(report.schema_version, 1);
    for operation in LiveOperation::ALL {
        let capability = report.live.get(operation);
        assert!(!capability.native, "{operation:?}");
        assert!(
            matches!(&capability.availability, LiveAvailability::Unsupported { reason: actual } if actual.code == reason && actual.subject.is_none()),
            "{operation:?}: {capability:?}"
        );
    }
}

#[test]
fn capabilities_excluded_query_does_not_initialize_paths_and_binds_native_build_facts() {
    let temp = Temp::new();
    std::fs::write(temp.0.join("sentinel"), b"preserve").expect("write sentinel");
    symlink("missing-target", temp.0.join("sentinel-link")).expect("create symlink");
    let before = snapshot(&temp.0);
    let report = report(command(&temp, "vz", None));
    assert_eq!(report.backend, LiveBackend::Vz);
    assert_reason(&report, LiveReasonCode::BackendExcluded);
    assert!(report.build_identity.starts_with(&format!(
        "v2:{}:{}:{}:content={}:inputs=",
        env!("SILO_LIBKRUN_SOURCE_KIND"),
        env!("SILO_LIBKRUN_SOURCE_STATE"),
        env!("SILO_LIBKRUN_REVISION"),
        env!("SILO_LIBKRUN_SOURCE_CONTENT"),
    )));
    assert!(report.qualification_identity.starts_with("v2:native="));
    assert!(!report.qualification_identity.contains("native=unobserved"));
    assert!(report.scenario_digest.is_none());
    assert_eq!(snapshot(&temp.0), before, "query created or modified state");
}

#[test]
fn capabilities_vz_is_excluded_even_when_backend_cannot_be_constructed() {
    let temp = Temp::new();
    let before = snapshot(&temp.0);
    let report = report(command(&temp, "vz", None));
    assert_eq!(report.backend, LiveBackend::Vz);
    assert_reason(&report, LiveReasonCode::BackendExcluded);
    assert_eq!(snapshot(&temp.0), before);
}

#[test]
fn capabilities_unknown_backend_never_falls_back_or_initializes() {
    let temp = Temp::new();
    let before = snapshot(&temp.0);
    let output = command(&temp, "unknown", None);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(snapshot(&temp.0), before);
}

#[cfg(feature = "mock-backend")]
mod scenarios {
    use crate::{assert_reason, command, report, snapshot, Temp};
    use test_utils::{LiveScenario, Scenario};
    use vm_spec::live::{
        LiveAvailability, LiveBackend, LiveCapability, LiveCapabilityVector, LiveLane,
        LiveOperation, LiveReasonCode,
    };

    fn write(temp: &Temp, scenario: &Scenario) -> std::path::PathBuf {
        let path = temp.0.join("scenario.json");
        scenario.write_to(&path).expect("write typed scenario");
        path
    }

    #[test]
    fn capabilities_scenario_reports_every_host_reason_and_default_exclusion() {
        let temp = Temp::new();
        let path = write(&temp, &Scenario::default());
        assert_reason(
            &report(command(&temp, "mock", Some(&path))),
            LiveReasonCode::BackendExcluded,
        );
        for reason in [
            LiveReasonCode::BackendExcluded,
            LiveReasonCode::HostOsBelowFloor,
            LiveReasonCode::LaneNotQualified,
            LiveReasonCode::HypervisorUnavailable,
            LiveReasonCode::BuildExcluded,
            LiveReasonCode::NotDelivered,
        ] {
            let scenario = Scenario {
                live: Some(LiveScenario {
                    lane: LiveLane::KvmX86_64,
                    host: LiveCapabilityVector::all_unsupported(reason),
                    machine: None,
                }),
                ..Scenario::default()
            };
            write(&temp, &scenario);
            let before = snapshot(&temp.0);
            let report = report(command(&temp, "mock", Some(&path)));
            assert_eq!(report.backend, LiveBackend::Mock);
            assert!(report.scenario_digest.is_some());
            assert_reason(&report, reason);
            assert_eq!(snapshot(&temp.0), before);
        }
    }

    #[test]
    fn capabilities_positive_scenario_stays_mock_and_content_digest_changes() {
        let temp = Temp::new();
        let supported = LiveCapability {
            native: true,
            availability: LiveAvailability::Supported,
        };
        let scenario = Scenario {
            live: Some(LiveScenario {
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
            ..Scenario::default()
        };
        let path = write(&temp, &scenario);
        let first = report(command(&temp, "mock", Some(&path)));
        assert_eq!(first.backend, LiveBackend::Mock);
        for operation in LiveOperation::ALL {
            assert_eq!(
                first.live.get(operation).availability,
                LiveAvailability::Supported
            );
        }
        write(&temp, &Scenario::default());
        let second = report(command(&temp, "mock", Some(&path)));
        assert_ne!(first.scenario_digest, second.scenario_digest);
        assert_reason(&second, LiveReasonCode::BackendExcluded);
    }

    #[test]
    fn capabilities_explicit_missing_malformed_and_host_device_scenarios_fail_without_repair() {
        let temp = Temp::new();
        let path = temp.0.join("scenario.json");
        let before = snapshot(&temp.0);
        assert!(!command(&temp, "mock", Some(&path)).status.success());
        assert_eq!(snapshot(&temp.0), before);
        for bytes in [
            b"{".as_slice(),
            b"{\"unknown\":true}".as_slice(),
            b"{\"live\":{}}".as_slice(),
        ] {
            std::fs::write(&path, bytes).expect("write malformed scenario");
            let before = snapshot(&temp.0);
            assert!(!command(&temp, "mock", Some(&path)).status.success());
            assert_eq!(snapshot(&temp.0), before);
        }
        let mut value = serde_json::to_value(Scenario {
            live: Some(LiveScenario {
                lane: LiveLane::KvmX86_64,
                host: LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered),
                machine: None,
            }),
            ..Scenario::default()
        })
        .expect("encode scenario");
        value["live"]["host"]["pause"]["availability"] = serde_json::json!({"status":"unsupported","reason":{"code":"device-profile-rejected","subject":{"kind":"virtiofs"}}});
        std::fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode invalid scope"),
        )
        .expect("write invalid scope");
        let before = snapshot(&temp.0);
        assert!(!command(&temp, "mock", Some(&path)).status.success());
        assert_eq!(snapshot(&temp.0), before);

        let mut host = LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered);
        host.pause = LiveCapability {
            native: true,
            availability: LiveAvailability::Supported,
        };
        let scenario = Scenario {
            live: Some(LiveScenario {
                lane: LiveLane::KvmX86_64,
                host: host.clone(),
                machine: Some(host),
            }),
            ..Scenario::default()
        };
        let valid = serde_json::to_value(scenario).expect("encode valid narrowing input");
        for kind in ["virtiofs", "rosetta", "tap", "gpu", "nested", "tee"] {
            for extra in ["profile", "unexpected"] {
                let mut subject = serde_json::json!({"kind": kind});
                subject[extra] = "unexpected".into();
                let mut invalid = valid.clone();
                invalid["live"]["machine"]["pause"]["availability"] = serde_json::json!({
                    "status": "unsupported",
                    "reason": {"code": "device-profile-rejected", "subject": subject},
                });
                std::fs::write(
                    &path,
                    serde_json::to_vec(&invalid).expect("encode invalid subject"),
                )
                .expect("write invalid subject");
                let before = snapshot(&temp.0);
                let output = command(&temp, "mock", Some(&path));
                assert!(!output.status.success(), "accepted {kind}/{extra}");
                assert!(output.stdout.is_empty());
                assert_eq!(snapshot(&temp.0), before);
            }
        }
        let mut invalid = valid;
        invalid["live"]["host"]["pause"]["availability"] = serde_json::json!({
            "status": "supported", "reason": {"code": "not-delivered"},
        });
        std::fs::write(
            &path,
            serde_json::to_vec(&invalid).expect("encode invalid supported fields"),
        )
        .expect("write invalid supported fields");
        let before = snapshot(&temp.0);
        let output = command(&temp, "mock", Some(&path));
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(snapshot(&temp.0), before);
    }
}

#[test]
fn capabilities_dispatch_ignores_invalid_launch_descriptor_environment() {
    let temp = Temp::new();
    let before = snapshot(&temp.0);
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_silo-vmm"))
            .current_dir(&temp.0)
            .env("SILO_HOME", temp.0.join("absent-home"))
            .env("SILO_RUN_ROOT", temp.0.join("absent-run"))
            .env("_VM_STARTPIPE", "not-a-descriptor")
            .env("_VM_SYNCPIPE", "-1")
            .env("_VM_MACHINE_LOG_DIR", "2147483648")
            .env("_VM_MACHINE_LOCK", "closed-descriptor")
            .env("_VM_NETD_EXIT", "invalid")
            .args(["capabilities", "--backend", "vz", "--json"]),
    );
    assert_reason(&report(output), LiveReasonCode::BackendExcluded);
    assert_eq!(
        snapshot(&temp.0),
        before,
        "query parsed launch descriptors or initialized launch paths"
    );
}

#[cfg(feature = "mock-backend")]
#[test]
fn capabilities_scenario_filesystem_and_exact_size_boundaries_have_bounded_lifecycles() {
    let temp = Temp::new();
    let fifo = temp.0.join("scenario-fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("create actual FIFO without a writer");
    let directory = temp.0.join("scenario-directory");
    std::fs::create_dir(&directory).expect("directory scenario input");
    let invalid_utf8 = temp.0.join("non-utf8.json");
    std::fs::write(&invalid_utf8, [0xff, 0xfe]).expect("write non-UTF8 scenario bytes");
    for path in [&fifo, &directory, &invalid_utf8] {
        let before = snapshot(&temp.0);
        let output = command(&temp, "mock", Some(path));
        assert!(
            !output.status.success(),
            "invalid scenario accepted: {}",
            path.display()
        );
        assert!(output.stdout.is_empty(), "failure emitted a success report");
        assert!(
            !output.stderr.is_empty(),
            "missing typed parse/input diagnostic"
        );
        assert_eq!(
            snapshot(&temp.0),
            before,
            "invalid scenario query repaired or initialized files"
        );
    }
    let path = temp.0.join("boundary.json");
    let mut bytes = b"{}".to_vec();
    bytes.resize(1024 * 1024, b' ');
    std::fs::write(&path, &bytes).expect("write valid exactly-limit scenario");
    let before = snapshot(&temp.0);
    assert_eq!(
        report(command(&temp, "mock", Some(&path))).backend,
        LiveBackend::Mock
    );
    assert_eq!(snapshot(&temp.0), before);
    bytes.push(b' ');
    std::fs::write(&path, bytes).expect("write valid JSON one byte beyond limit");
    let before = snapshot(&temp.0);
    let output = command(&temp, "mock", Some(&path));
    assert!(!output.status.success(), "oversized valid JSON accepted");
    assert!(output.stdout.is_empty());
    assert_eq!(snapshot(&temp.0), before);
}
