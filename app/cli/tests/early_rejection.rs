//! Actual CLI capability/refusal paths, with no hypervisor or fake service.

use std::collections::BTreeMap;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use libvm::{ImageSource, Runtime, RuntimeConfig};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use test_utils::{LiveScenario, Scenario};
use vm_spec::live::{
    LiveBackend, LiveCapabilityVector, LiveHostReport, LiveLane, LiveOperation, LiveReasonCode,
    LiveScope,
};

#[path = "../../../runtime/libvm/tests/support/live_catalog.rs"]
mod live_catalog;

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    mode: u32,
    owner: (u32, u32),
    modified: (i64, i64),
    contents: Vec<u8>,
    symlink: Option<PathBuf>,
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        if matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("state.db" | "state.db-wal" | "state.db-shm")
        ) {
            return;
        }
        let metadata = std::fs::symlink_metadata(path).expect("stat without following links");
        entries.insert(
            path.strip_prefix(root)
                .expect("relative path")
                .to_path_buf(),
            Entry {
                mode: metadata.mode(),
                // Parent catalog-directory mtime may change when SQLite
                // coordinates sidecars; machine/runtime directories stay exact.
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
                symlink: metadata
                    .file_type()
                    .is_symlink()
                    .then(|| std::fs::read_link(path).expect("read link")),
            },
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).expect("list directory") {
                visit(root, &entry.expect("entry").path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut entries);
    }
    entries
}

fn install_runtime(root: &Path) {
    std::fs::create_dir_all(root.join("bin")).expect("create portable bin");
    std::fs::create_dir(root.join("assets")).expect("create portable assets");
    let monitor = test_utils::mock_vmm_binary();
    // Networking is disabled; netd is validated but never launched.
    // The actual monitor serves both query and scenario-run requests.
    for path in ["bin/silo-vmm", "bin/netd"] {
        std::fs::copy(monitor, root.join(path))
            .expect("install actual monitor inside portable runtime");
    }
    std::fs::write(
        root.join("assets/kernel-default"),
        test_utils::direct_kernel::host_kernel("scenario kernel"),
    )
    .expect("kernel fixture");
    std::fs::write(root.join("assets/initramfs"), b"scenario initramfs")
        .expect("initramfs fixture");
    let agent = root.join("assets/agent");
    std::fs::write(&agent, b"inert scenario guest-agent fixture").expect("agent fixture");
    std::fs::set_permissions(agent, std::fs::Permissions::from_mode(0o755))
        .expect("agent fixture mode");
    symlink("agent", root.join("assets/agent-link")).expect("sentinel relative symlink");
}

fn run(root: &Path, backend: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_silo"))
        .current_dir(root)
        .env("SILO_HOME", root.join("home"))
        .env("SILO_RUN_ROOT", root.join("run"))
        .env("SILO_RUNTIME_DIR", root.join("runtime"))
        .env("SILO_VMM_PATH", test_utils::mock_vmm_binary())
        .env("SILO_VIRT_BACKEND", backend)
        .env("NO_COLOR", "1")
        .env_remove("SILO_ASSET_DIR")
        .env_remove("NETD_BIN")
        .args(args)
        .output()
        .expect("execute real CLI")
}

#[test]
fn early_rejection_system_info_json_is_scoped_and_cold_without_initialization() {
    let temp = tempfile::tempdir().expect("private root");
    install_runtime(&temp.path().join("runtime"));
    let before = snapshot(temp.path());
    for backend in ["krun", "vz"] {
        let output = run(
            temp.path(),
            backend,
            &["system", "info", "--format", "json"],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("system JSON");
        let report: LiveHostReport = serde_json::from_value(value["manager"].clone())
            .expect("strict separately labelled manager report");
        assert_eq!(report.scope, LiveScope::Host);
        assert_eq!(
            report.backend,
            if backend == "vz" {
                LiveBackend::Vz
            } else {
                LiveBackend::Krun
            }
        );
        let live = value["manager"]["live"].as_object().expect("fixed vector");
        assert_eq!(live.len(), 5);
        for operation in LiveOperation::ALL {
            assert_eq!(
                live[operation.as_str()]["availability"]["status"],
                "unsupported"
            );
            assert_eq!(
                live[operation.as_str()]["availability"]["reason"]["code"],
                if backend == "vz" {
                    "backend-excluded"
                } else if matches!(
                    operation,
                    LiveOperation::Pause
                        | LiveOperation::Capture
                        | LiveOperation::Restore
                        | LiveOperation::Fork
                ) {
                    "lane-not-qualified"
                } else {
                    "not-delivered"
                }
            );
        }
        assert!(
            value.get("appliance").is_some(),
            "appliance scope key must remain distinct"
        );
        assert_eq!(
            snapshot(temp.path()),
            before,
            "system info initialized or changed state"
        );
    }
}

#[test]
fn early_rejection_cold_live_commands_preserve_absent_home_and_checkpoint() {
    let temp = tempfile::tempdir().expect("private root");
    install_runtime(&temp.path().join("runtime"));
    let checkpoint = temp.path().join("checkpoint");
    std::fs::write(
        &checkpoint,
        b"not a valid execution checkpoint; must not be parsed",
    )
    .expect("artifact fixture");
    std::fs::set_permissions(&checkpoint, std::fs::Permissions::from_mode(0o400))
        .expect("read-only artifact mode");
    let before = snapshot(temp.path());
    for backend in ["krun", "vz"] {
        for (args, operation) in [
            (vec!["pause", "absent"], "pause"),
            (vec!["snapshot", "create", "absent", "--live"], "capture"),
            (
                vec!["fork", "absent", "--name", "unallocated-child", "--live"],
                "fork",
            ),
            (
                vec![
                    "restore",
                    "image:checkpoint",
                    "--name",
                    "unallocated-restore",
                ],
                "restore",
            ),
        ] {
            let output = run(temp.path(), backend, &args);
            assert!(!output.status.success(), "unsupported {args:?} succeeded");
            assert!(output.stdout.is_empty());
            let error = String::from_utf8(output.stderr).expect("UTF-8 error");
            assert!(
                error.contains(&format!("{operation} unsupported")),
                "{error}"
            );
            assert!(error.contains(&format!("backend={backend}")), "{error}");
            assert!(
                error.contains(if backend == "vz" {
                    "backend-excluded"
                } else if matches!(operation, "pause" | "capture" | "restore" | "fork") {
                    "lane-not-qualified"
                } else {
                    "not-delivered"
                }),
                "{error}"
            );
            assert_eq!(
                snapshot(temp.path()),
                before,
                "refusal changed bytes, metadata, links or paths: {args:?}"
            );
            assert!(!temp.path().join("home").exists());
            assert!(!temp.path().join("run").exists());
        }
    }
}

#[test]
fn early_rejection_explicit_live_execution_grammar_has_no_legacy_aliases_or_fallback() {
    let temp = tempfile::tempdir().expect("private root");
    install_runtime(&temp.path().join("runtime"));
    let before = snapshot(temp.path());
    for args in [
        vec!["snapshot", "source"],
        vec!["restore", "checkpoint"],
        vec!["fork", "source"],
        vec!["show", "source"],
        vec!["status"],
    ] {
        let output = run(temp.path(), "krun", &args);
        assert!(
            !output.status.success(),
            "ambiguous or obsolete grammar accepted: {args:?}"
        );
        assert_eq!(snapshot(temp.path()), before);
    }
}

#[test]
fn early_rejection_fork_operation_lookup_in_absent_home_creates_nothing() {
    let temp = tempfile::tempdir().expect("private root");
    install_runtime(&temp.path().join("runtime"));
    let before = snapshot(temp.path());
    let operation = "00000000-0000-4000-8000-0000000000aa";
    for args in [
        vec!["fork", "--operation", operation],
        vec!["fork", "--operation", operation, "--cancel"],
    ] {
        let output = run(temp.path(), "krun", &args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).expect("UTF-8 error");
        assert!(
            error.contains(&format!("live fork {operation} was not found")),
            "{error}"
        );
        assert_eq!(snapshot(temp.path()), before, "{args:?}");
        assert!(!temp.path().join("home").exists());
        assert!(!temp.path().join("run").exists());
    }
}

struct MonitorGuard(Pid);
impl Drop for MonitorGuard {
    fn drop(&mut self) {
        let _ = kill(self.0, Signal::SIGTERM);
    }
}

#[tokio::test]
async fn early_rejection_actual_mock_run_wins_over_prospective_krun_and_info_reports_all_operations(
) {
    for positive in [false, true] {
        let temp = tempfile::Builder::new()
            .prefix("silo-cli-live-")
            .tempdir_in(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .expect("short private root");
        let root = temp.path();
        let runtime_root = root.join("runtime");
        install_runtime(&runtime_root);
        let scenario_path = root.join("scenario.json");
        Scenario {
            live: Some(LiveScenario {
                lane: LiveLane::KvmX86_64,
                host: if positive {
                    let supported = vm_spec::live::LiveCapability {
                        native: true,
                        availability: vm_spec::live::LiveAvailability::Supported,
                    };
                    LiveCapabilityVector {
                        pause: supported.clone(),
                        capture: supported.clone(),
                        restore: supported.clone(),
                        fork: supported.clone(),
                        incremental: supported,
                    }
                } else {
                    LiveCapabilityVector::all_unsupported(LiveReasonCode::LaneNotQualified)
                },
                machine: None,
            }),
            ..Scenario::default()
        }
        .write_to(&scenario_path)
        .expect("write typed scenario");
        let disk = root.join("disk.raw");
        disk_image::ext4::Formatter::new(&disk, 4096, 256 * 1024)
            .and_then(|formatter| formatter.close())
            .expect("admissible whole-disk ext4 fixture");
        let runtime = Runtime::new(
            RuntimeConfig::local(root.join("home"))
                .with_run_root(root.join("run"))
                .with_runtime_root(&runtime_root)
                .with_mock_vmm(&scenario_path),
        )
        .await
        .expect("open fixture runtime");
        let machine = runtime
            .machine()
            .name("source")
            .image_source(ImageSource::Disk(libvm::DiskImportRequest {
                path: disk,
                boot: libvm::DiskImportBoot::LinuxDirect {
                    platform: silo_vm_control::boot::host_platform().expect("host platform"),
                    root: libvm::ImportRootSelection::WholeDisk,
                    assets: libvm::BootAssetSelection::Packaged,
                },
                alias: None,
            }))
            .network(|network| network.none())
            .create()
            .await
            .expect("create scenario machine");
        machine
            .start()
            .await
            .expect("start actual scenario monitor");
        let pid =
            std::fs::read_to_string(root.join("run/machines").join(machine.id()).join("vm.pid"))
                .expect("monitor PID")
                .trim()
                .parse::<i32>()
                .expect("valid PID");
        let _monitor = MonitorGuard(Pid::from_raw(pid));
        assert_eq!(
            machine
                .wait_ready(Duration::from_secs(30))
                .await
                .expect("scenario readiness")
                .outcome,
            libvm::MachineReadinessOutcome::Ready
        );
        for args in [
            vec!["pause", "source"],
            vec!["snapshot", "create", "source", "--live"],
            vec!["fork", "source", "--name", "unallocated", "--live"],
        ] {
            let before_home = snapshot(&root.join("home"));
            let before_catalog = live_catalog::snapshot(&root.join("home")).await;
            let before_run = snapshot(&root.join("run"));
            let output = run(root, "krun", &args);
            assert!(!output.status.success());
            let error = String::from_utf8(output.stderr).expect("error UTF-8");
            assert!(
                error.contains("backend=mock"),
                "prospective backend replaced actual run: {error}"
            );
            assert_eq!(
                snapshot(&root.join("home")),
                before_home,
                "cold CLI observation/admission mutated persisted state"
            );
            assert_eq!(
                snapshot(&root.join("run")),
                before_run,
                "cold CLI observation/admission mutated run files"
            );
            assert_eq!(
                live_catalog::snapshot(&root.join("home")).await,
                before_catalog,
                "CLI observation/admission changed logical catalog/schema"
            );
        }
        let output = run(root, "krun", &["info", "source", "--format", "json"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("info JSON");
        assert_eq!(value["live"]["scope"], "machine");
        assert_eq!(value["live"]["backend"], "mock");
        for operation in LiveOperation::ALL {
            assert_eq!(
                value["live"]["live"][operation.as_str()]["availability"]["reason"]["code"],
                if positive { "device-profile-rejected" } else { "lane-not-qualified" },
                "missing guest lifecycle evidence must narrow support, not replace an existing refusal"
            );
        }
        machine.stop().await.expect("stop scenario monitor");
    }
}

#[test]
fn disk_import_structural_refusals_precede_writable_runtime_initialization() {
    let temporary = tempfile::tempdir().expect("private fixture root");
    let root = temporary.path();
    let odd = root.join("odd.raw");
    let empty = root.join("empty.raw");
    let foreign = root.join("foreign.vmdk");
    let qcow = root.join("malformed.qcow2");
    let directory = root.join("directory");
    let fifo = root.join("fifo");
    let link = root.join("link.raw");
    std::fs::write(&odd, [0; 513]).expect("odd geometry");
    std::fs::write(&empty, []).expect("empty geometry");
    let mut foreign_bytes = [0; 512];
    foreign_bytes[..4].copy_from_slice(b"KDMV");
    std::fs::write(&foreign, foreign_bytes).expect("foreign container");
    std::fs::write(&qcow, b"QFI\xfb").expect("malformed qcow2");
    std::fs::create_dir(&directory).expect("directory source");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("FIFO source");
    symlink(&odd, &link).expect("source symlink");
    let platform = if cfg!(target_arch = "aarch64") {
        "linux/arm64"
    } else {
        "linux/amd64"
    };
    for path in [&odd, &empty, &foreign, &qcow, &directory, &fifo, &link] {
        let before = snapshot(root);
        let output = run(
            root,
            "krun",
            &[
                "image",
                "import",
                path.to_str().expect("fixture path"),
                "--platform",
                platform,
                "--root",
                "whole-disk",
                "--boot",
                "linux-direct",
            ],
        );
        assert!(!output.status.success(), "{path:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("raw disk image")
                || error.contains("qcow2")
                || error.contains("convert")
                || error.contains("not a regular file")
                || error.contains("symbolic link"),
            "{path:?}: {error}"
        );
        assert_eq!(snapshot(root), before, "{path:?}: {error}");
        assert!(!root.join("home").exists());
        assert!(!root.join("run").exists());
    }
}

#[test]
fn stopped_preflight_rejects_missing_sources_and_wrong_reference_kinds_without_initialization() {
    let temp = tempfile::tempdir().expect("private root");
    install_runtime(&temp.path().join("runtime"));
    let execution = temp.path().join("execution-checkpoint");
    std::fs::write(
        &execution,
        b"execution bytes must not be cold booted or decoded",
    )
    .unwrap();
    let before = snapshot(temp.path());
    for args in [
        vec!["fork", "absent", "--name", "child"],
        vec!["snapshot", "create", "absent", "--name", "checkpoint"],
        vec!["restore", "image:absent", "--name", "child"],
        vec!["restore", execution.to_str().unwrap(), "--name", "child"],
        vec!["restore", "snapshot:checkpoint", "--name", "child"],
        vec![
            "image",
            "remove",
            "image:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
    ] {
        let output = run(temp.path(), "krun", &args);
        assert!(
            !output.status.success(),
            "invalid stopped request succeeded: {args:?}"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(
            snapshot(temp.path()),
            before,
            "stopped preflight initialized or changed state: {args:?}"
        );
        assert!(!temp.path().join("home").exists());
        assert!(!temp.path().join("run").exists());
    }
}
