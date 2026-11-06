//! Shared utilities for Silo's Rust tests.
//!
//! This crate is the single source of truth for the mock scenario schema:
//! silo-vmm (behind its `mock-backend` feature) reads scenarios, tests write
//! them. It also provides [`mock_vmm_binary`], which builds and locates a
//! silo-vmm binary compiled with the mock backend so libvm integration tests can
//! spawn a real monitor process on hosts without virtualization support.
//!
//! An absent optional scenario field means the happy-path default. An
//! explicitly selected scenario file must exist and contain valid JSON. The machine boots
//! immediately, the fake guest agent becomes ready, executions run real host
//! subprocesses in a sandbox, and the filesystem service operates on a
//! per-machine temp directory.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use vm_spec::live::{LiveAvailability, LiveCapabilityVector, LiveLane, LiveOperation, LiveScope};

/// Scripted behavior for one mock-backed machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Test-only transport grants. Never qualifies a production backend.
    pub live: Option<LiveScenario>,
    /// Modeled native pause control and guest workload freezer. Absent means the
    /// mock carries no lifecycle evidence: guest freeze/thaw stay unimplemented,
    /// the guest reports no lifecycle status and native pause is unsupported.
    pub lifecycle: Option<LifecycleScenario>,
}

/// Explicitly modeled lifecycle evidence and scripted failures. Every script
/// list is consumed in order, one entry per attempt; an exhausted list means
/// the happy path with no delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct LifecycleScenario {
    /// Boot-observed bound generation driver, reported by the guest status.
    pub generation_driver_ready: bool,
    /// Guest freezer refusal (unsupported containment). `None` models the
    /// admitted AgentPid1 workload layout.
    pub freezer_unsupported: Option<String>,
    /// Canonical workload roots reported by the guest freezer.
    pub workload_roots: Vec<String>,
    /// Native live provider inventory reported by native control.
    pub providers: Vec<ProviderScenario>,
    /// Native runtime memory tracking mode.
    pub memory_tracking: MemoryTrackingScenario,
    pub native_pause: Vec<NativePauseStep>,
    pub native_cancel: Vec<NativeCancelStep>,
    pub native_resume: Vec<NativeResumeStep>,
    pub freeze: Vec<GuestFreezeStep>,
    pub thaw: Vec<GuestThawStep>,
    /// Modeled native capture (execution, RAM, preserve).
    pub capture: CaptureScenario,
}

impl Default for LifecycleScenario {
    fn default() -> Self {
        Self {
            generation_driver_ready: true,
            freezer_unsupported: None,
            workload_roots: vec!["/sys/fs/cgroup/silo-workloads".to_string()],
            providers: ProviderScenario::standard(),
            memory_tracking: MemoryTrackingScenario::Capture,
            native_pause: Vec::new(),
            native_cancel: Vec::new(),
            native_resume: Vec::new(),
            freeze: Vec::new(),
            thaw: Vec::new(),
            capture: CaptureScenario::default(),
        }
    }
}

/// Modeled native capture. Scripts are consumed one entry per attempt; an
/// exhausted list is the happy path with no delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct CaptureScenario {
    /// Guest RAM written by a full capture; a positive multiple of 4096.
    pub ram_bytes: u64,
    pub execution: Vec<NativeCaptureStep>,
    pub memory: Vec<NativeCaptureStep>,
    pub preserve: Vec<NativePreserveStep>,
}

impl Default for CaptureScenario {
    fn default() -> Self {
        Self {
            ram_bytes: 64 * 1024,
            execution: Vec::new(),
            memory: Vec::new(),
            preserve: Vec::new(),
        }
    }
}

/// One native execution or RAM capture attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCaptureStep {
    #[serde(default)]
    pub delay_ms: u64,
    pub result: NativeCaptureResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeCaptureResult {
    Complete,
    /// Execution: both outputs closed, capture failed. RAM: a partial write
    /// whose files stay owned by the native failure until abandonment.
    Fail,
    /// Completes natively but the caller sees CallerTimeout.
    LoseReply,
}

/// One native preserve (Capture → User ownership transfer) attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativePreserveStep {
    pub result: NativePreserveResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativePreserveResult {
    Complete,
    /// Refused: the Capture-owned pause stays exactly as it was.
    Fail,
}

/// One live device as the native provider inventory reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderScenario {
    /// Virtio device ID (block 2, console 3, rng 4, balloon 5, vsock 19,
    /// fs 26, generation 0x5347).
    pub device_id: u32,
    pub configured_id: String,
    #[serde(default)]
    pub activation_fenced: Option<bool>,
    /// Backing format of a block provider.
    #[serde(default)]
    pub block_backing: Option<BlockBackingScenario>,
    /// Read-only block attachment. Native quiesces read-only VMDK lowers;
    /// writable VMDK is refused.
    #[serde(default)]
    pub read_only: bool,
    /// A live device without a state provider: native inventory fails closed.
    #[serde(default)]
    pub missing_state_provider: bool,
}

impl ProviderScenario {
    fn device(device_id: u32, configured_id: &str) -> Self {
        Self {
            device_id,
            configured_id: configured_id.to_string(),
            activation_fenced: Some(false),
            block_backing: None,
            read_only: false,
            missing_state_provider: false,
        }
    }

    /// The ordinary Raw-rooted krun device set.
    pub fn standard() -> Vec<Self> {
        vec![
            Self::device(3, "console"),
            Self {
                block_backing: Some(BlockBackingScenario::Raw),
                ..Self::device(2, "root")
            },
            Self::device(19, "vsock"),
            Self::device(4, "rng"),
            Self::device(5, "balloon"),
            Self::device(0x5347, "generation"),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BlockBackingScenario {
    Raw,
    Vmdk,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MemoryTrackingScenario {
    Disabled,
    #[default]
    Capture,
}

/// One native pause attempt. `delayMs` is the barrier duration before the
/// scripted result is observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativePauseStep {
    #[serde(default)]
    pub delay_ms: u64,
    pub result: NativePauseResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativePauseResult {
    /// Complete barrier: native Paused with a token.
    Complete,
    /// Barrier failure after admission: native failed Pausing, no token.
    Fail,
    /// Admission rejection: native stays Running.
    Reject,
    /// Native completes the barrier but the caller's reply is lost.
    LoseReply,
    /// The barrier never completes; native fails it at the deadline.
    Hang,
}

/// One native pause cancellation (rollback) attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCancelStep {
    #[serde(default)]
    pub delay_ms: u64,
    pub result: NativeCancelResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeCancelResult {
    /// Rollback reaches Running.
    Complete,
    /// Rollback fails: native FailedFenced.
    Fail,
}

/// One native ClockOnly resume attempt (prepare, release, acknowledgement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeResumeStep {
    /// Release duration.
    #[serde(default)]
    pub delay_ms: u64,
    pub result: NativeResumeResult,
    /// Guest generation driver acknowledgement latency after release.
    #[serde(default)]
    pub clock_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeResumeResult {
    /// Released and the ClockOnly request is acknowledged.
    Complete,
    /// ClockOnly preparation fails; native stays Paused with the same token.
    PrepareFail,
    /// Release fails: native FailedFenced.
    ReleaseFail,
    /// Released, but the caller's release reply is lost.
    LoseReply,
    /// Released, the guest driver reports a generation failure.
    ClockFail,
    /// Released, the guest driver never acknowledges before the deadline.
    ClockTimeout,
}

/// One guest FreezeWorkloads attempt (a new epoch, not a same-input retry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestFreezeStep {
    #[serde(default)]
    pub delay_ms: u64,
    pub result: GuestFreezeResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GuestFreezeResult {
    Frozen,
    /// Freeze fails and the guest's own rollback succeeds (FREEZE_FAILED).
    FreezeFailed,
    /// Freeze fails and its rollback fails (FAULTED).
    Faulted,
    /// The freeze takes effect but the RPC response is lost.
    DropResponse,
    /// The freeze never completes before its deadline; then FREEZE_FAILED.
    Hang,
}

/// One guest Thaw attempt (rollback or normal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestThawStep {
    #[serde(default)]
    pub delay_ms: u64,
    pub result: GuestThawResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GuestThawResult {
    Thawed,
    /// Thaw fails: guest FAULTED.
    Faulted,
    /// The thaw takes effect (workloads run) but the RPC response is lost.
    DropResponse,
}

/// Behavior of `machine.start()`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct BootScenario {
    /// Delay before start() returns, in milliseconds.
    pub delay_ms: Option<u64>,
    /// When set, start() fails with this message (machine never boots).
    pub fail: Option<String>,
}

/// Behavior of the running machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct RunScenario {
    /// Simulate a VMM crash this many milliseconds after boot:
    /// `wait()` resolves with a stopped-with-error exit.
    pub crash_after_ms: Option<u64>,
    /// Error message reported when the scripted crash fires.
    pub crash_message: Option<String>,
}

/// Behavior of the serial device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct VsockScenario {
    /// Ports that refuse host connections even when configured.
    pub refuse_ports: Vec<u32>,
    /// Hard-close a port's streams after relaying this many bytes.
    pub drop_after_bytes: HashMap<u32, u64>,
}

/// Behavior of the fake guest filesystem service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct FilesystemScenario {
    /// Guest paths that fail with a structured error code.
    /// Matches `ErrorCode` names, e.g. "PERMISSION_DENIED".
    pub errors: HashMap<String, String>,
}

/// Behavior of the mock guest forward dialer and capability check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct ForwardScenario {
    /// Canonical guest target addresses answered with `ERR refused`.
    pub refuse_targets: Vec<String>,
    /// Omit GuestForwardService from health discovery.
    pub unsupported: bool,
    /// Override the pending inbound connection parking timeout in milliseconds.
    pub park_timeout_ms: Option<u64>,
}

/// Complete host vector and optional strictly narrowing machine vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "LiveScenarioFields"
)]
pub struct LiveScenario {
    pub lane: LiveLane,
    pub host: LiveCapabilityVector,
    pub machine: Option<LiveCapabilityVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveScenarioFields {
    lane: LiveLane,
    host: LiveCapabilityVector,
    machine: Option<LiveCapabilityVector>,
}

impl TryFrom<LiveScenarioFields> for LiveScenario {
    type Error = String;

    fn try_from(fields: LiveScenarioFields) -> Result<Self, Self::Error> {
        let scenario = Self {
            lane: fields.lane,
            host: fields.host,
            machine: fields.machine,
        };
        scenario.validate()?;
        Ok(scenario)
    }
}

impl LiveScenario {
    pub fn validate(&self) -> Result<(), String> {
        self.host.validate(LiveScope::Host)?;
        if let Some(machine) = &self.machine {
            machine.validate(LiveScope::Machine)?;
            for operation in LiveOperation::ALL {
                let host = self.host.get(operation);
                let narrowed = machine.get(operation);
                if narrowed.native && !host.native {
                    return Err(format!(
                        "machine scenario promotes native {}",
                        operation.as_str()
                    ));
                }
                if matches!(host.availability, LiveAvailability::Unsupported { .. })
                    && narrowed != host
                {
                    return Err(format!(
                        "machine scenario changes host refusal for {}",
                        operation.as_str()
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Scenario {
    /// Parse a scenario from JSON.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("scenario serializes")
    }

    /// Load an explicitly selected scenario. Missing files are errors.
    pub fn load(path: &Path) -> io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents).map_err(io::Error::other)
    }

    /// Write the scenario to a file, creating parent directories.
    pub fn write_to(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_json())
    }
}

/// Build (once) and return the path to a silo-vmm binary compiled with the
/// `mock-backend` feature.
///
/// `SILO_TEST_MOCK_VMM_BINARY` names a prebuilt binary and skips the nested
/// build; `xtask test`/`xtask coverage` set it so every test process reuses one
/// artifact (and, under coverage, an instrumented one). Otherwise this runs
/// `cargo build -p silo-vmm --features mock-backend` in the workspace root the
/// first time it is called in a process. Under `make test` / CI this is a cache
/// hit because the workspace is already built with `--all-features`. Nested
/// `cargo build` inside `cargo test` is safe: cargo releases its build lock
/// before executing tests.
pub fn mock_vmm_binary() -> &'static Path {
    static BINARY: LazyLock<PathBuf> = LazyLock::new(|| {
        if let Some(binary) = std::env::var_os("SILO_TEST_MOCK_VMM_BINARY") {
            let binary = PathBuf::from(binary);
            assert!(
                binary.is_file(),
                "SILO_TEST_MOCK_VMM_BINARY does not name a file: {}",
                binary.display()
            );
            warm(&binary);
            return binary;
        }
        let workspace_root = workspace_root();
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = std::process::Command::new(cargo)
            .current_dir(&workspace_root)
            .args(["build", "-p", "silo-vmm", "--features", "mock-backend"])
            .status()
            .expect("failed to invoke cargo to build the mock-enabled silo-vmm");
        assert!(
            status.success(),
            "cargo build -p silo-vmm --features mock-backend failed"
        );

        let binary = target_dir(&workspace_root).join("debug").join("silo-vmm");
        assert!(
            binary.is_file(),
            "expected mock-enabled silo-vmm binary at {}",
            binary.display()
        );
        warm(&binary);
        binary
    });
    &BINARY
}

/// Cargo uplifts binaries by copying, so every build leaves a fresh inode.
/// macOS policy-scans the first exec of a new executable inode for about a
/// second; pay it here, not inside a timed launch.
fn warm(binary: &Path) {
    let warm = std::process::Command::new(binary)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .status()
        .expect("failed to execute the mock-enabled silo-vmm");
    assert!(warm.success(), "mock-enabled silo-vmm --help failed");
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
    use crate::*;

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
    fn lifecycle_scenario_is_explicit_and_scripts_parse_in_order() {
        assert_eq!(Scenario::default().lifecycle, None, "no implicit evidence");
        let modeled = Scenario::from_json(r#"{"lifecycle": {}}"#).expect("parse");
        let lifecycle = modeled.lifecycle.expect("modeled lifecycle");
        assert_eq!(lifecycle, LifecycleScenario::default());
        assert!(lifecycle.generation_driver_ready);
        assert!(lifecycle
            .providers
            .iter()
            .any(|provider| provider.device_id == 2
                && provider.block_backing == Some(BlockBackingScenario::Raw)));
        let scripted = Scenario::from_json(
            r#"{"lifecycle": {
                "generationDriverReady": false,
                "memoryTracking": "disabled",
                "nativePause": [{"result": "loseReply"}, {"delayMs": 5, "result": "fail"}],
                "nativeCancel": [{"result": "fail"}],
                "nativeResume": [{"result": "clockTimeout", "clockDelayMs": 3}],
                "freeze": [{"result": "dropResponse"}],
                "thaw": [{"delayMs": 1, "result": "faulted"}],
                "providers": [{"deviceId": 26, "configuredId": "share", "missingStateProvider": true}]
            }}"#,
        )
        .expect("parse")
        .lifecycle
        .expect("lifecycle");
        assert!(!scripted.generation_driver_ready);
        assert_eq!(scripted.memory_tracking, MemoryTrackingScenario::Disabled);
        assert_eq!(
            scripted
                .native_pause
                .iter()
                .map(|step| step.result)
                .collect::<Vec<_>>(),
            [NativePauseResult::LoseReply, NativePauseResult::Fail]
        );
        assert_eq!(scripted.native_resume[0].clock_delay_ms, 3);
        assert_eq!(scripted.freeze[0].result, GuestFreezeResult::DropResponse);
        assert_eq!(scripted.thaw[0].result, GuestThawResult::Faulted);
        assert!(scripted.providers[0].missing_state_provider);
        assert_eq!(lifecycle.capture, CaptureScenario::default());
        assert_eq!(lifecycle.capture.ram_bytes, 64 * 1024);
        let capture = Scenario::from_json(
            r#"{"lifecycle": {
                "providers": [{"deviceId": 2, "configuredId": "lower", "blockBacking": "vmdk", "readOnly": true}],
                "capture": {
                    "ramBytes": 8192,
                    "execution": [{"result": "loseReply"}],
                    "memory": [{"delayMs": 2, "result": "fail"}],
                    "preserve": [{"result": "fail"}]
                }
            }}"#,
        )
        .expect("parse")
        .lifecycle
        .expect("lifecycle");
        assert!(capture.providers[0].read_only);
        assert_eq!(capture.capture.ram_bytes, 8192);
        assert_eq!(
            capture.capture.execution[0].result,
            NativeCaptureResult::LoseReply
        );
        assert_eq!(capture.capture.memory[0].delay_ms, 2);
        assert_eq!(
            capture.capture.preserve[0].result,
            NativePreserveResult::Fail
        );
        for invalid in [
            r#"{"lifecycle": {"nativePause": [{"result": "maybe"}]}}"#,
            r#"{"lifecycle": {"freeze": [{"delayMs": 1}]}}"#,
            r#"{"lifecycle": {"bogus": true}}"#,
            r#"{"lifecycle": {"capture": {"memory": [{"result": "partial"}]}}}"#,
            r#"{"lifecycle": {"capture": {"bogus": 1}}}"#,
        ] {
            assert!(Scenario::from_json(invalid).is_err(), "{invalid}");
        }
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
    fn missing_scenario_file_is_an_error() {
        let path =
            std::env::temp_dir().join(format!("test-utils-missing-{}.json", std::process::id()));
        assert_eq!(
            Scenario::load(&path).expect_err("missing").kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn capabilities_scenario_rejects_host_device_reasons_and_machine_promotions() {
        use vm_spec::live::{
            LiveCapability, LiveDeviceSubject, LiveReasonCode, LiveUnsupportedReason,
        };
        let excluded = LiveCapabilityVector::all_unsupported(LiveReasonCode::BackendExcluded);
        let supported = LiveCapability {
            native: true,
            availability: LiveAvailability::Supported,
        };
        let mut host = excluded.clone();
        host.pause = supported.clone();
        let mut machine = host.clone();
        machine.pause.availability = LiveAvailability::Unsupported {
            reason: LiveUnsupportedReason::device(LiveDeviceSubject::Rosetta),
        };
        let valid = LiveScenario {
            lane: LiveLane::KvmX86_64,
            host: host.clone(),
            machine: Some(machine.clone()),
        };
        assert!(valid.validate().is_ok());
        let scenario = Scenario {
            live: Some(valid),
            ..Default::default()
        };
        assert_eq!(
            Scenario::from_json(&scenario.to_json()).expect("roundtrip"),
            scenario
        );

        let host_device = LiveScenario {
            lane: LiveLane::NotApplicable,
            host: machine,
            machine: None,
        };
        assert!(host_device.validate().is_err());
        assert!(serde_json::from_value::<LiveScenario>(
            serde_json::to_value(host_device).expect("serialize")
        )
        .is_err());
        let promoted = LiveScenario {
            lane: LiveLane::NotApplicable,
            host: excluded.clone(),
            machine: Some(host),
        };
        assert!(promoted.validate().is_err());
        let mut different_reason = excluded.clone();
        different_reason.pause = LiveCapability::unsupported(LiveReasonCode::NotDelivered);
        assert!(LiveScenario {
            lane: LiveLane::NotApplicable,
            host: excluded,
            machine: Some(different_reason)
        }
        .validate()
        .is_err());
    }
}
