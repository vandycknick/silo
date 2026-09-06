//! Shared utilities for Silo's Rust tests.
//!
//! This crate is the single source of truth for the mock scenario schema:
//! vmmon (behind its `mock-backend` feature) reads scenarios, tests write
//! them. It also provides [`mock_vmmon_binary`], which builds and locates a
//! vmmon binary compiled with the mock backend so libvm integration tests can
//! spawn a real monitor process on hosts without virtualization support.
//!
//! Every scenario field is optional; an absent field (or an absent scenario
//! file altogether) means the happy-path default: the machine boots
//! immediately, the fake guest agent becomes ready, executions run real host
//! subprocesses in a sandbox, and the filesystem service operates on a
//! per-machine temp directory.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Scripted behavior for one mock-backed machine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct Scenario {
    pub boot: BootScenario,
    pub run: RunScenario,
    pub serial: SerialScenario,
    pub agent: AgentScenario,
    pub exec: ExecScenario,
    pub vsock: VsockScenario,
    pub filesystem: FilesystemScenario,
    pub forward: ForwardScenario,
}

/// Behavior of `machine.start()`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct BootScenario {
    /// Delay before start() returns, in milliseconds.
    pub delay_ms: Option<u64>,
    /// When set, start() fails with this message (machine never boots).
    pub fail: Option<String>,
}

/// Behavior of the running machine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct RunScenario {
    /// Simulate a VMM crash this many milliseconds after boot:
    /// `wait()` resolves with a stopped-with-error exit.
    pub crash_after_ms: Option<u64>,
    /// Error message reported when the scripted crash fires.
    pub crash_message: Option<String>,
}

/// Behavior of the serial device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct SerialScenario {
    /// Lines written to the serial device after boot (newline-terminated),
    /// paced so consumers observe multiple chunks.
    pub banner: Vec<String>,
    /// Echo interactive input back onto the serial output.
    pub echo_input: bool,
}

impl Default for SerialScenario {
    fn default() -> Self {
        Self {
            banner: vec![
                "[mock] booting linux".to_string(),
                "[mock] silo-agent started".to_string(),
            ],
            echo_input: true,
        }
    }
}

/// Behavior of the fake guest agent (status/metrics services).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct AgentScenario {
    /// Delay before the agent reports Ready, in milliseconds.
    pub ready_delay_ms: Option<u64>,
    /// The agent never becomes ready (stays in Starting forever).
    pub never_ready: bool,
    /// End the status watch stream this many milliseconds after it opens,
    /// forcing the supervisor to reconnect.
    pub drop_status_stream_after_ms: Option<u64>,
    /// Simulate an in-place agent restart after this many milliseconds:
    /// a fresh `agent_instance_id` is minted (identity-reset fencing).
    pub restart_after_ms: Option<u64>,
    /// Pin the agent instance id instead of generating one at boot.
    pub instance_id: Option<String>,
    /// Pin the boot id instead of generating one at boot.
    pub boot_id: Option<String>,
}

/// Behavior of the fake guest process service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct ExecScenario {
    /// Force every launch to fail with this reason instead of spawning.
    /// Matches `LaunchFailureReason` names, e.g. "COMMAND_NOT_FOUND".
    pub launch_failure: Option<String>,
    /// Abort the execution event stream after this many events, simulating
    /// a mid-flight guest stream loss.
    pub drop_after_events: Option<u32>,
}

/// Behavior of vsock ports beyond the built-in control (1027) and SSH (22).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct VsockScenario {
    /// Ports that refuse host connections even when configured.
    pub refuse_ports: Vec<u32>,
    /// Hard-close a port's streams after relaying this many bytes.
    pub drop_after_bytes: HashMap<u32, u64>,
}

/// Behavior of the fake guest filesystem service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct FilesystemScenario {
    /// Guest paths that fail with a structured error code.
    /// Matches `ErrorCode` names, e.g. "PERMISSION_DENIED".
    pub errors: HashMap<String, String>,
}

/// Behavior of the mock guest forward dialer and capability check.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct ForwardScenario {
    /// Canonical guest target addresses answered with `ERR refused`.
    pub refuse_targets: Vec<String>,
    /// Omit GuestForwardService from health discovery.
    pub unsupported: bool,
}

impl Scenario {
    /// Parse a scenario from JSON.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("scenario serializes")
    }

    /// Load a scenario file; a missing file is the happy-path default.
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Self::from_json(&contents).map_err(io::Error::other),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err),
        }
    }

    /// Write the scenario to a file, creating parent directories.
    pub fn write_to(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_json())
    }
}

/// Build (once) and return the path to a vmmon binary compiled with the
/// `mock-backend` feature.
///
/// Runs `cargo build -p vmmon --features mock-backend` in the workspace root
/// the first time it is called in a process. Under `make test` / CI this is a
/// cache hit because the workspace is already built with `--all-features`.
/// Nested `cargo build` inside `cargo test` is safe: cargo releases its build
/// lock before executing tests.
pub fn mock_vmmon_binary() -> &'static Path {
    use std::sync::OnceLock;

    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let workspace_root = workspace_root();
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = std::process::Command::new(cargo)
            .current_dir(&workspace_root)
            .args(["build", "-p", "vmmon", "--features", "mock-backend"])
            .status()
            .expect("failed to invoke cargo to build the mock-enabled vmmon");
        assert!(
            status.success(),
            "cargo build -p vmmon --features mock-backend failed"
        );

        let binary = target_dir(&workspace_root).join("debug").join("vmmon");
        assert!(
            binary.is_file(),
            "expected mock-enabled vmmon binary at {}",
            binary.display()
        );
        binary
    })
}

fn workspace_root() -> PathBuf {
    // runtime/test-utils -> runtime -> workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("test-utils crate lives two levels below the workspace root")
        .to_path_buf()
}

fn target_dir(workspace_root: &Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if dir.is_absolute() {
                dir
            } else {
                workspace_root.join(dir)
            }
        }
        None => workspace_root.join("target"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scenario_round_trips() {
        let scenario = Scenario::default();
        let parsed = Scenario::from_json(&scenario.to_json()).expect("parse scenario");
        assert_eq!(parsed, scenario);
    }

    #[test]
    fn empty_object_is_the_default_scenario() {
        assert_eq!(
            Scenario::from_json("{}").expect("parse"),
            Scenario::default()
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(Scenario::from_json(r#"{"bogus": true}"#).is_err());
    }

    #[test]
    fn fault_fields_parse() {
        let scenario = Scenario::from_json(
            r#"{
                "boot": {"delayMs": 25, "fail": "kvm unavailable"},
                "run": {"crashAfterMs": 1500, "crashMessage": "mock crash"},
                "agent": {"neverReady": true},
                "exec": {"launchFailure": "COMMAND_NOT_FOUND", "dropAfterEvents": 2},
                "vsock": {"refusePorts": [22], "dropAfterBytes": {"1027": 4096}},
                "filesystem": {"errors": {"/locked": "PERMISSION_DENIED"}}
            }"#,
        )
        .expect("parse scenario");

        assert_eq!(scenario.boot.delay_ms, Some(25));
        assert_eq!(scenario.run.crash_after_ms, Some(1500));
        assert!(scenario.agent.never_ready);
        assert_eq!(scenario.vsock.drop_after_bytes.get(&1027), Some(&4096));
        assert_eq!(
            scenario.filesystem.errors.get("/locked"),
            Some(&"PERMISSION_DENIED".to_string())
        );
    }

    #[test]
    fn missing_scenario_file_is_default() {
        let path =
            std::env::temp_dir().join(format!("test-utils-missing-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(Scenario::load(&path).expect("load"), Scenario::default());
    }
}
