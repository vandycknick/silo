use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::{ExecutionResult, MachineReadinessOutcome, MachineStatus};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::AppApi;
use crate::system::config::ResolvedSystemConfig;
use crate::system::provision::ensure_system_machine;
use crate::system::record::{load_record, write_record, SystemPaths};

pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(60);
const ENGINE_REACHABLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DaemonPhase {
    PreparingStorage,
    Creating,
    StartingVm,
    WaitingGuest,
    ActivatingEngine,
    Ready,
    Degraded,
    Failed,
    Stopping,
    Stopped,
}

/// Live supervisor state, republished on every change. Unlike the installation
/// records this is not strict: a newer or older daemon may have written it, and a
/// field it does not know must not stop `status`, `up`, or `down` from working.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DaemonStatus {
    pub(crate) schema: u32,
    pub(crate) generation: Uuid,
    pub(crate) pid: u32,
    pub(crate) phase: DaemonPhase,
    pub(crate) machine_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) image_digest: Option<String>,
    /// Backend reported by the running vmmon instance.
    #[serde(default)]
    pub(crate) actual_backend: Option<String>,
    pub(crate) docker_socket: String,
    pub(crate) updated_at: String,
    pub(crate) last_error: Option<String>,
    pub(crate) restart_count: u32,
    /// How the last guest cache-reclaim attempt ended.
    #[serde(default)]
    pub(crate) memory_reclaim_outcome: Option<MemoryReclaimOutcome>,
    /// Exit status from a bounded reclaim that required the global fallback.
    #[serde(default)]
    pub(crate) memory_reclaim_bounded_exit_code: Option<u32>,
    /// Guest cached-byte decrease observed after the attempt, not host memory returned.
    #[serde(default)]
    pub(crate) memory_reclaim_observed_cache_delta_bytes: Option<u64>,
    /// When the last guest cache-reclaim attempt ran (RFC 3339).
    #[serde(default)]
    pub(crate) memory_reclaim_at: Option<String>,
    /// Whether the runtime requested per-VM host memory reclaim qualification.
    #[serde(default)]
    pub(crate) host_memory_reclaim_requested: bool,
    /// Observed effective state. `None` means no acknowledgement channel exists.
    #[serde(default)]
    pub(crate) host_memory_reclaim_effective: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemoryReclaimOutcome {
    Bounded,
    Fallback,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRecord {
    schema: u32,
    generation: Uuid,
    pid: u32,
    process_start: String,
    run_root: String,
}

pub(crate) struct LifetimeLock {
    _file: Flock<File>,
}

impl LifetimeLock {
    pub(crate) fn acquire(path: &Path) -> eyre::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| eyre::eyre!("daemon lock path has no parent"))?;
        std::fs::create_dir_all(parent)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(file) => Ok(Self { _file: file }),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => {
                bail!("another Silo system daemon owns this installation")
            }
            Err((_, error)) => Err(error).context("lock system daemon installation"),
        }
    }
}

pub(crate) async fn serve(
    api: &mut AppApi,
    paths: SystemPaths,
    config: ResolvedSystemConfig,
) -> eyre::Result<()> {
    if paths.upgrade().exists() {
        bail!("a system image upgrade is pending; run `silo daemon upgrade --recover`");
    }
    let _lock = LifetimeLock::acquire(&paths.lifetime_lock())?;
    let generation = Uuid::new_v4();
    write_record(
        &paths.owner(),
        &OwnerRecord {
            schema: 1,
            generation,
            pid: std::process::id(),
            process_start: process_start_identity()?,
            run_root: paths.run_root.display().to_string(),
        },
    )?;
    let mut status = DaemonStatus {
        schema: 1,
        generation,
        pid: std::process::id(),
        phase: DaemonPhase::PreparingStorage,
        machine_id: None,
        run_id: None,
        image_digest: None,
        actual_backend: None,
        docker_socket: config.docker_socket.display().to_string(),
        updated_at: now(),
        last_error: None,
        restart_count: 0,
        memory_reclaim_outcome: None,
        memory_reclaim_bounded_exit_code: None,
        memory_reclaim_observed_cache_delta_bytes: None,
        memory_reclaim_at: None,
        host_memory_reclaim_requested: config.host_memory_reclaim,
        host_memory_reclaim_effective: initial_host_memory_reclaim_effective(
            config.host_memory_reclaim,
        ),
    };
    publish(&paths, &mut status)?;
    append_log(&paths, "preparing installation storage")?;

    let mut failed_attempts = 0_u32;
    let startup = loop {
        let outcome = {
            let startup = reconcile_ready(api, &paths, &config, &mut status);
            tokio::pin!(startup);
            tokio::select! {
                result = &mut startup => Some(result),
                signal = shutdown_signal() => {
                    signal?;
                    None
                }
            }
        };
        match outcome {
            None => break None,
            Some(Ok(value)) => break Some(value),
            Some(Err(error)) => {
                // Startup problems such as an unavailable system image are often
                // transient. Stay alive, publish the failure for `daemon status`, and
                // retry with backoff instead of exiting and leaving the service manager
                // to relaunch the process in a loop.
                failed_attempts = failed_attempts.saturating_add(1);
                let delay = startup_retry_delay(failed_attempts);
                let causes = error_causes(&error);
                status.phase = DaemonPhase::Failed;
                status.last_error = Some(error_summary(&causes));
                status.restart_count = failed_attempts;
                publish(&paths, &mut status)?;
                append_log(
                    &paths,
                    &format!(
                        "startup attempt {failed_attempts} failed: {}; retrying in {}s",
                        causes.join(": "),
                        delay.as_secs()
                    ),
                )?;
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    signal = shutdown_signal() => {
                        signal?;
                        break None;
                    }
                }
            }
        }
    };
    let Some((machine, run_id)) = startup else {
        status.phase = DaemonPhase::Stopping;
        publish(&paths, &mut status)?;
        // Stop the VM even when startup never got as far as writing the system record;
        // otherwise an interrupted first start leaves it running unattended.
        if let Some(installation) =
            load_record::<crate::system::record::InstallationRecord>(&paths.installation())?
        {
            match crate::system::provision::stop_system_machine(
                api,
                &paths,
                installation.installation_id,
                Duration::from_secs(60),
            )
            .await
            {
                Ok(machine_id) => status.machine_id = machine_id,
                Err(error) => {
                    status.phase = DaemonPhase::Failed;
                    status.last_error = Some(format!(
                        "startup cancellation could not stop the system VM: {error:#}"
                    ));
                    publish(&paths, &mut status)?;
                    return Err(error);
                }
            }
        }
        status.phase = DaemonPhase::Stopped;
        status.run_id = None;
        publish(&paths, &mut status)?;
        append_log(&paths, "system daemon cancelled during startup")?;
        return Ok(());
    };

    let mut consecutive_failures = 0_u8;
    let mut reclaimer = IdleReclaimer::new(&config);
    let mut ticks = 0_u64;
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                break;
            }
            () = tokio::time::sleep(RECLAIM_INTERVAL) => {
                ticks += 1;
                reclaimer.tick(&machine, &paths, &mut status).await?;
                if !ticks.is_multiple_of(HEALTH_INTERVAL.as_secs() / RECLAIM_INTERVAL.as_secs()) {
                    continue;
                }
                match probe_docker_socket(&config.docker_socket) {
                    Ok(()) => {
                        consecutive_failures = 0;
                        if status.phase != DaemonPhase::Ready {
                            status.phase = DaemonPhase::Ready;
                            status.last_error = None;
                            publish(&paths, &mut status)?;
                        }
                    }
                    Err(error) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        status.phase = DaemonPhase::Degraded;
                        status.last_error = Some(error.to_string());
                        publish(&paths, &mut status)?;
                        if consecutive_failures >= 3 {
                            append_log(&paths, "Docker health failed three consecutive probes")?;
                        }
                    }
                }
            }
        }
    }
    status.phase = DaemonPhase::Stopping;
    publish(&paths, &mut status)?;
    let _ = machine
        .exec_with_input(
            "/usr/bin/systemctl",
            &["stop", "silo-system-docker.target"],
            "root",
            Vec::new(),
            Duration::from_secs(30),
        )
        .await;
    machine.stop_run(run_id).await?;
    status.phase = DaemonPhase::Stopped;
    status.run_id = None;
    publish(&paths, &mut status)?;
    append_log(&paths, "system daemon stopped")?;
    Ok(())
}

const fn initial_host_memory_reclaim_effective(requested: bool) -> Option<bool> {
    if requested {
        None
    } else {
        Some(false)
    }
}

async fn reconcile_ready(
    api: &mut AppApi,
    paths: &SystemPaths,
    config: &ResolvedSystemConfig,
    status: &mut DaemonStatus,
) -> eyre::Result<(crate::api::machine::AppMachine, libvm::MachineRunId)> {
    status.phase = DaemonPhase::Creating;
    publish(paths, status)?;
    let (record, machine_data) = ensure_system_machine(api, paths, config.clone()).await?;
    status.machine_id = Some(record.active_machine_id.clone());
    status.image_digest = Some(record.image_digest.clone());
    let machine = api.machine(&record.active_machine_id).await?;
    let run_id = match machine_data.status {
        MachineStatus::Running { .. } | MachineStatus::Starting { .. } => {
            machine.current_run_id().await?
        }
        MachineStatus::Stopping { .. } => bail!("recorded system VM is stopping; wait and retry"),
        _ => {
            status.phase = DaemonPhase::StartingVm;
            publish(paths, status)?;
            let options = api.machine_start_options(&machine, false).await?;
            machine.start_with_options(options).await?.run_id
        }
    };
    status.run_id = Some(run_id.to_string());
    status.actual_backend = machine.metrics().await?.actual_backend;
    status.phase = DaemonPhase::WaitingGuest;
    publish(paths, status)?;
    let readiness = machine.wait_ready(READY_TIMEOUT).await?;
    if readiness.outcome != MachineReadinessOutcome::Ready {
        bail!("system guest readiness ended with {:?}", readiness.outcome);
    }
    status.phase = DaemonPhase::ActivatingEngine;
    publish(paths, status)?;
    activate(&machine, config, &machine_data.spec, record.data_uuid).await?;
    // Activation returns once the guest units are up; the host-side socket forward
    // becomes live shortly after the guest half exists, so poll rather than probe once.
    wait_docker_socket(&config.docker_socket, ENGINE_REACHABLE_TIMEOUT).await?;
    status.phase = DaemonPhase::Ready;
    status.last_error = None;
    publish(paths, status)?;
    append_log(paths, "system Docker engine ready")?;
    Ok((machine, run_id))
}

/// Engine health probe cadence.
const HEALTH_INTERVAL: Duration = Duration::from_secs(10);
/// Idle-detector cadence; the guest agent reports metrics every 5 seconds.
const RECLAIM_INTERVAL: Duration = Duration::from_secs(5);
const MIB: u64 = 1024 * 1024;
/// Guest CPU busy fraction (of all vCPUs) at or below which the guest counts as idle.
const IDLE_CPU_FRACTION: f64 = 0.05;
/// Guest block I/O rate at or below which the guest counts as idle.
const IDLE_IO_BYTES_PER_SEC: u64 = MIB;
/// Page cache worth a reclaim attempt.
const RECLAIM_MIN_CACHE: u64 = 512 * MIB;
/// Guest-side reclaim: cgroup v2 proactive reclaim first, the global cache drop as a
/// fallback on older kernels. `%BYTES%` is replaced with the amount to reclaim.
const GUEST_RECLAIM_SCRIPT: &str = "echo %BYTES% > %CGROUP_RECLAIM% 2>/dev/null || { bounded_status=$?; printf 'fallback:%s\\n' \"$bounded_status\"; sync; echo 1 > %DROP_CACHES%; exit $?; }; printf 'bounded\\n'";
const CGROUP_RECLAIM_PATH: &str = "/sys/fs/cgroup/memory.reclaim";
const DROP_CACHES_PATH: &str = "/proc/sys/vm/drop_caches";

/// Reclaims idle guest page cache, the way WSL2's `autoMemoryReclaim` does.
///
/// Every tick reads the guest's metrics. Once CPU and block I/O have stayed idle for
/// the configured window and the guest holds enough page cache, the controller asks
/// the guest kernel to reclaim that cache. This does not claim that the host released
/// the same number of bytes.
pub(crate) struct IdleReclaimer {
    enabled: bool,
    idle_after: Duration,
    last_sample: Option<ActivitySample>,
    idle_since: Option<tokio::time::Instant>,
}

/// Cumulative guest activity counters at one instant.
#[derive(Debug, Clone, Copy)]
struct ActivitySample {
    at: tokio::time::Instant,
    busy_seconds: f64,
    io_bytes: u64,
}

impl ActivitySample {
    fn from_snapshot(at: tokio::time::Instant, snapshot: &libvm::MachineMetricSnapshot) -> Self {
        let busy_seconds = snapshot
            .cpu
            .as_ref()
            .map(|cpu| {
                cpu.user_seconds
                    + cpu.nice_seconds
                    + cpu.system_seconds
                    + cpu.irq_seconds
                    + cpu.softirq_seconds
                    + cpu.steal_seconds
            })
            .unwrap_or_default();
        let io_bytes = snapshot
            .block_devices
            .iter()
            .map(|device| device.read_bytes.saturating_add(device.write_bytes))
            .fold(0_u64, u64::saturating_add);
        Self {
            at,
            busy_seconds,
            io_bytes,
        }
    }
}

impl IdleReclaimer {
    pub(crate) fn new(config: &ResolvedSystemConfig) -> Self {
        Self {
            enabled: config.memory_reclaim,
            idle_after: Duration::from_secs(config.memory_reclaim_after_secs),
            last_sample: None,
            idle_since: None,
        }
    }

    /// Records one metrics sample and returns how long the guest has been idle, if
    /// it is idle now. Activity between two samples is judged against the CPU and
    /// I/O thresholds; any busy interval resets the idle clock.
    fn observe(&mut self, sample: ActivitySample, cpus: u32) -> Option<Duration> {
        let previous = self.last_sample.replace(sample)?;
        let elapsed = sample
            .at
            .saturating_duration_since(previous.at)
            .as_secs_f64();
        if elapsed <= 0.0 {
            return self
                .idle_since
                .map(|since| sample.at.saturating_duration_since(since));
        }
        let busy = (sample.busy_seconds - previous.busy_seconds).max(0.0)
            / (elapsed * f64::from(cpus.max(1)));
        let io_rate = sample.io_bytes.saturating_sub(previous.io_bytes) as f64 / elapsed;
        if busy <= IDLE_CPU_FRACTION && io_rate <= IDLE_IO_BYTES_PER_SEC as f64 {
            let since = *self.idle_since.get_or_insert(previous.at);
            Some(sample.at.saturating_duration_since(since))
        } else {
            self.idle_since = None;
            None
        }
    }

    async fn tick(
        &mut self,
        machine: &crate::api::machine::AppMachine,
        paths: &SystemPaths,
        status: &mut DaemonStatus,
    ) -> eyre::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let Some(snapshot) = fetch_snapshot(machine).await else {
            return Ok(());
        };
        let now = tokio::time::Instant::now();
        let cpus = snapshot
            .cpu
            .as_ref()
            .map(|cpu| cpu.logical_cpu_count)
            .unwrap_or(1);
        let idle_for = self.observe(ActivitySample::from_snapshot(now, &snapshot), cpus);
        if idle_for.is_none_or(|idle_for| idle_for < self.idle_after) {
            return Ok(());
        }
        let Some(memory) = snapshot.memory.as_ref() else {
            return Ok(());
        };
        let cached = cached_bytes(memory);
        if cached < RECLAIM_MIN_CACHE {
            return Ok(());
        }
        // Require a fresh idle window before the next attempt whatever happens now.
        self.idle_since = None;
        self.reclaim(machine, paths, status, cached).await
    }

    async fn reclaim(
        &mut self,
        machine: &crate::api::machine::AppMachine,
        paths: &SystemPaths,
        status: &mut DaemonStatus,
        cached: u64,
    ) -> eyre::Result<()> {
        let script = guest_reclaim_script(cached, CGROUP_RECLAIM_PATH, DROP_CACHES_PATH);
        let output = match machine
            .exec_with_input(
                "/bin/sh",
                &["-c", &script],
                "root",
                Vec::new(),
                Duration::from_secs(60),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                record_reclaim(status, MemoryReclaimOutcome::Failed, None, None);
                publish(paths, status)?;
                append_log(
                    paths,
                    &format!("memory reclaim: guest execution failed: {error}"),
                )?;
                return Ok(());
            }
        };
        let branch = parse_reclaim_branch(output.stdout_bytes());
        if !matches!(output.result(), ExecutionResult::Exited { code: Some(0) }) {
            let bounded_exit_code = branch.and_then(ReclaimBranch::bounded_exit_code);
            record_reclaim(
                status,
                MemoryReclaimOutcome::Failed,
                bounded_exit_code,
                None,
            );
            publish(paths, status)?;
            append_log(
                paths,
                &format!(
                    "memory reclaim: guest cache reclaim failed ({:?}): {}",
                    output.result(),
                    String::from_utf8_lossy(output.stderr_bytes()).trim()
                ),
            )?;
            return Ok(());
        }
        let Some(branch) = branch else {
            record_reclaim(status, MemoryReclaimOutcome::Failed, None, None);
            publish(paths, status)?;
            append_log(
                paths,
                "memory reclaim: guest returned an invalid branch result",
            )?;
            return Ok(());
        };
        let observed_delta = fetch_snapshot(machine)
            .await
            .and_then(|snapshot| snapshot.memory)
            .map(|memory| cached.saturating_sub(cached_bytes(&memory)));
        let (outcome, bounded_exit_code, description) = match branch {
            ReclaimBranch::Bounded => (
                MemoryReclaimOutcome::Bounded,
                None,
                "bounded guest cgroup reclaim completed".to_string(),
            ),
            ReclaimBranch::Fallback { bounded_exit_code } => (
                MemoryReclaimOutcome::Fallback,
                Some(bounded_exit_code),
                format!(
                    "bounded guest cgroup reclaim was incomplete or failed with exit {bounded_exit_code}; global cache-drop fallback completed"
                ),
            ),
        };
        record_reclaim(status, outcome, bounded_exit_code, observed_delta);
        publish(paths, status)?;
        let observation = observed_delta
            .map(|bytes| format!("; observed guest cache delta {} MiB", bytes / MIB))
            .unwrap_or_default();
        append_log(
            paths,
            &format!("memory reclaim: {description}{observation}"),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReclaimBranch {
    Bounded,
    Fallback { bounded_exit_code: u32 },
}

impl ReclaimBranch {
    fn bounded_exit_code(self) -> Option<u32> {
        match self {
            Self::Bounded => None,
            Self::Fallback { bounded_exit_code } => Some(bounded_exit_code),
        }
    }
}

fn guest_reclaim_script(bytes: u64, cgroup_reclaim: &str, drop_caches: &str) -> String {
    GUEST_RECLAIM_SCRIPT
        .replace("%BYTES%", &bytes.to_string())
        .replace("%CGROUP_RECLAIM%", cgroup_reclaim)
        .replace("%DROP_CACHES%", drop_caches)
}

fn parse_reclaim_branch(stdout: &[u8]) -> Option<ReclaimBranch> {
    let output = std::str::from_utf8(stdout).ok()?.trim();
    if output == "bounded" {
        return Some(ReclaimBranch::Bounded);
    }
    output
        .strip_prefix("fallback:")?
        .parse()
        .ok()
        .map(|bounded_exit_code| ReclaimBranch::Fallback { bounded_exit_code })
}

fn cached_bytes(memory: &libvm::MachineMemoryMetrics) -> u64 {
    memory.cached_bytes.unwrap_or_else(|| {
        memory
            .available_bytes
            .saturating_sub(memory.free_bytes.unwrap_or(memory.available_bytes))
    })
}

fn record_reclaim(
    status: &mut DaemonStatus,
    outcome: MemoryReclaimOutcome,
    bounded_exit_code: Option<u32>,
    observed_delta: Option<u64>,
) {
    status.memory_reclaim_outcome = Some(outcome);
    status.memory_reclaim_bounded_exit_code = bounded_exit_code;
    status.memory_reclaim_observed_cache_delta_bytes = observed_delta;
    status.memory_reclaim_at = Some(now());
}

async fn fetch_snapshot(
    machine: &crate::api::machine::AppMachine,
) -> Option<libvm::MachineMetricSnapshot> {
    machine
        .metrics()
        .await
        .ok()?
        .metrics
        .map(|observation| observation.report.snapshot)
}

/// Renders an error as its distinct causes, outermost first, skipping causes whose text
/// the previous cause already repeats.
pub(crate) fn error_causes(error: &eyre::Report) -> Vec<String> {
    let mut causes: Vec<String> = Vec::new();
    for cause in error.chain() {
        let text = cause.to_string();
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        if causes
            .last()
            .is_some_and(|previous| previous.contains(text))
        {
            continue;
        }
        causes.push(text.to_string());
    }
    if causes.is_empty() {
        causes.push("unknown failure".to_string());
    }
    causes
}

/// One-line operator summary of a cause chain: what failed, and the root cause.
pub(crate) fn error_summary(causes: &[String]) -> String {
    match (causes.first(), causes.last()) {
        (Some(first), Some(last)) if causes.len() > 1 => format!("{first}: {last}"),
        (Some(first), _) => first.clone(),
        (None, _) => "unknown failure".to_string(),
    }
}

/// Exponential backoff between failed startup attempts: 5s, 10s, 20s, 40s, then 60s.
fn startup_retry_delay(failed_attempts: u32) -> Duration {
    const BASE: Duration = Duration::from_secs(5);
    const MAX: Duration = Duration::from_secs(60);
    let exponent = failed_attempts.saturating_sub(1).min(8);
    BASE.saturating_mul(1 << exponent).min(MAX)
}

pub(crate) async fn activate(
    machine: &crate::api::machine::AppMachine,
    config: &ResolvedSystemConfig,
    machine_spec: &vm_spec::VmSpec,
    data_uuid: Uuid,
) -> eyre::Result<()> {
    let request = activation_request(config, machine_spec, data_uuid)?;
    let output = machine
        .exec_with_input(
            "/usr/sbin/silo-system-activate",
            &["activate"],
            "root",
            serde_json::to_vec(&request)?,
            Duration::from_secs(60),
        )
        .await?;
    if !matches!(output.result(), ExecutionResult::Exited { code: Some(0) }) {
        bail!(
            "guest Docker activation failed: {}",
            String::from_utf8_lossy(output.stderr_bytes())
        );
    }
    Ok(())
}

fn activation_request(
    config: &ResolvedSystemConfig,
    machine_spec: &vm_spec::VmSpec,
    data_uuid: Uuid,
) -> eyre::Result<serde_json::Value> {
    let projected = vm_spec::project_mounts(&machine_spec.mounts)
        .map_err(eyre::Report::msg)
        .context("project actual system machine shares for activation")?;
    if projected.len() != config.shares.len() {
        bail!(
            "system activation configuration/spec mismatch: actual machine has {} shares, configuration requires {}",
            projected.len(),
            config.shares.len()
        );
    }

    let required_shares = config
        .shares
        .iter()
        .map(|share| {
            let mut matching = projected
                .iter()
                .filter(|mount| mount.host_source == share.path);
            let mount = matching.next().ok_or_else(|| {
                eyre::eyre!(
                    "system activation configuration/spec mismatch: required host share {} is missing from the actual machine",
                    share.path.display()
                )
            })?;
            if matching.next().is_some() {
                bail!(
                    "system activation configuration/spec mismatch: required host share {} is ambiguous in the actual machine",
                    share.path.display()
                );
            }
            if mount.guest_path != share.path {
                bail!(
                    "system activation configuration/spec mismatch: host share {} has guest path {}, expected {}",
                    share.path.display(),
                    mount.guest_path.display(),
                    share.path.display()
                );
            }
            if mount.read_only != share.read_only {
                bail!(
                    "system activation configuration/spec mismatch: share {} is {} in the actual machine, expected {}",
                    share.path.display(),
                    if mount.read_only { "read-only" } else { "read-write" },
                    if share.read_only { "read-only" } else { "read-write" }
                );
            }
            Ok(serde_json::json!({
                "path": mount.guest_path,
                "tag": mount.backend_tag,
                "writable": !mount.read_only,
            }))
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    Ok(serde_json::json!({
        "schema": 1,
        "data_uuid": data_uuid,
        "data_layout": 1,
        "required_shares": required_shares,
    }))
}

async fn wait_docker_socket(path: &Path, timeout: Duration) -> eyre::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = None;
    while tokio::time::Instant::now() < deadline {
        match probe_docker_socket(path) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(last_error
        .unwrap_or_else(|| eyre::eyre!("no probe attempted"))
        .wrap_err(format!(
            "Docker engine did not become reachable at {} within {}s",
            path.display(),
            timeout.as_secs()
        )))
}

pub(crate) fn probe_docker_socket(path: &Path) -> eyre::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(path)
            .with_context(|| format!("connect Docker socket {}", path.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(b"GET /_ping HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n")?;
        let mut response = Vec::new();
        stream.take(8192).read_to_end(&mut response)?;
        if !response.starts_with(b"HTTP/1.1 200")
            || !response.windows(2).any(|window| window == b"OK")
        {
            bail!("Docker /_ping returned an unhealthy response");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("Docker Unix sockets are unsupported on this host")
    }
}

fn publish(paths: &SystemPaths, status: &mut DaemonStatus) -> eyre::Result<()> {
    status.updated_at = now();
    write_record(&paths.status(), status)
}

fn append_log(paths: &SystemPaths, message: &str) -> eyre::Result<()> {
    let path = paths.log();
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("daemon log has no parent"))?;
    std::fs::create_dir_all(parent)?;
    if std::fs::metadata(&path)
        .map(|metadata| metadata.len() > 1024 * 1024)
        .unwrap_or(false)
    {
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{} {}", now(), message)?;
    Ok(())
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn process_start_identity() -> eyre::Result<String> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let end = stat
            .rfind(')')
            .ok_or_else(|| eyre::eyre!("invalid /proc/self/stat"))?;
        let start = stat[end + 2..]
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| eyre::eyre!("missing process start time"))?;
        Ok(start.to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(format!("pid-{}-{}", std::process::id(), now()))
    }
}

async fn shutdown_signal() -> eyre::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => {} }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

/// Reads the published status. A file this binary cannot parse is treated as
/// absent rather than fatal: it is transient runtime state, and the PID and owner
/// checks that follow decide whether anything is actually running.
pub(crate) fn read_status(paths: &SystemPaths) -> eyre::Result<Option<DaemonStatus>> {
    Ok(load_record(&paths.status()).unwrap_or_default())
}

pub(crate) fn last_run_root(paths: &SystemPaths) -> eyre::Result<Option<std::path::PathBuf>> {
    let Some(owner) = load_record::<OwnerRecord>(&paths.owner())? else {
        return Ok(None);
    };
    let run_root = std::path::PathBuf::from(owner.run_root);
    if !run_root.is_absolute() {
        bail!("recorded daemon run root is not absolute");
    }
    Ok(Some(run_root))
}

pub(crate) fn status_owner_is_live(
    paths: &SystemPaths,
    status: &DaemonStatus,
) -> eyre::Result<bool> {
    let Some(owner) = load_record::<OwnerRecord>(&paths.owner())? else {
        return Ok(false);
    };
    if owner.generation != status.generation || owner.pid != status.pid {
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    {
        let stat = match std::fs::read_to_string(format!("/proc/{}/stat", owner.pid)) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let end = stat
            .rfind(')')
            .ok_or_else(|| eyre::eyre!("invalid process stat for daemon PID {}", owner.pid))?;
        let start = stat[end + 2..]
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| eyre::eyre!("missing daemon process start time"))?;
        Ok(start == owner.process_start)
    }
    #[cfg(not(target_os = "linux"))]
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;
    use std::time::Duration;

    use crate::system::config::{ResolvedShare, SystemConfig};
    use crate::system::supervisor::{
        activation_request, error_causes, error_summary, guest_reclaim_script,
        initial_host_memory_reclaim_effective, parse_reclaim_branch, startup_retry_delay,
        ActivitySample, IdleReclaimer, LifetimeLock, ReclaimBranch, MIB,
    };
    use vm_spec::Mount;

    fn activation_config(
        shares: Vec<ResolvedShare>,
    ) -> crate::system::config::ResolvedSystemConfig {
        let home = tempfile::tempdir().expect("home");
        let config: SystemConfig =
            serde_yaml_ng::from_str("version: '1'\nsystem: {}\n").expect("config");
        let mut config = config
            .resolve(home.path(), None)
            .expect("resolve system config");
        config.shares = shares;
        config
    }

    #[test]
    fn activation_uses_full_machine_mount_projection() {
        let long_one = "/guest/a/very/long/workspace/destination/that/exceeds/the/tag/field";
        let long_two = "/guest/another/long/read-only/destination/that/exceeds/the/tag/field";
        let shares = vec![
            ResolvedShare {
                path: long_one.into(),
                read_only: false,
            },
            ResolvedShare {
                path: "/literal".into(),
                read_only: false,
            },
            ResolvedShare {
                path: long_two.into(),
                read_only: true,
            },
            ResolvedShare {
                path: "/cache".into(),
                read_only: true,
            },
        ];
        let config = activation_config(shares.clone());
        let mut spec = vm_spec::VmSpec::current();
        spec.mounts = vec![
            Mount {
                source: long_one.into(),
                tag: long_one.to_string(),
                read_only: false,
            },
            Mount {
                source: "/literal".into(),
                tag: "silo-mount-0".to_string(),
                read_only: false,
            },
            Mount {
                source: long_two.into(),
                tag: long_two.to_string(),
                read_only: true,
            },
            Mount {
                source: "/cache".into(),
                tag: "/cache".to_string(),
                read_only: true,
            },
        ];

        let request = activation_request(&config, &spec, uuid::Uuid::nil())
            .expect("build activation request");

        assert_eq!(
            request["required_shares"],
            serde_json::json!([
                { "path": long_one, "tag": "silo-mount-1", "writable": true },
                { "path": "/literal", "tag": "silo-mount-0", "writable": true },
                { "path": long_two, "tag": "silo-mount-2", "writable": false },
                { "path": "/cache", "tag": "/cache", "writable": false }
            ])
        );
        assert_eq!(spec.mounts[0].source, shares[0].path);
        assert_eq!(spec.mounts[0].tag, long_one);
    }

    #[test]
    fn activation_rejects_required_share_configuration_spec_mismatches() {
        let config = activation_config(vec![ResolvedShare {
            path: "/required".into(),
            read_only: true,
        }]);
        let spec_with = |source: &str, tag: &str, read_only| {
            let mut spec = vm_spec::VmSpec::current();
            spec.mounts.push(Mount {
                source: source.into(),
                tag: tag.to_string(),
                read_only,
            });
            spec
        };

        for (spec, expected) in [
            (
                spec_with("/other", "/required", true),
                "required host share /required is missing",
            ),
            (
                spec_with("/required", "/other", true),
                "has guest path /other, expected /required",
            ),
            (
                spec_with("/required", "/required", false),
                "is read-write in the actual machine, expected read-only",
            ),
        ] {
            let error = activation_request(&config, &spec, uuid::Uuid::nil())
                .expect_err("mismatched activation share must fail");
            assert!(error.to_string().contains(expected), "{error:#}");
        }

        let empty = vm_spec::VmSpec::current();
        let error = activation_request(&config, &empty, uuid::Uuid::nil())
            .expect_err("missing machine share must fail");
        assert!(error
            .to_string()
            .contains("actual machine has 0 shares, configuration requires 1"));
    }

    #[test]
    fn error_causes_list_each_distinct_cause_once() {
        use eyre::WrapErr as _;
        let inner = std::io::Error::other("Not authorized: url https://example/manifests/dev");
        let wrapped: eyre::Result<()> = Err(inner)
            .wrap_err("registry request failed")
            .wrap_err("image operation for example:dev failed");
        assert_eq!(
            error_causes(&wrapped.unwrap_err()),
            vec![
                "image operation for example:dev failed",
                "registry request failed",
                "Not authorized: url https://example/manifests/dev",
            ]
        );
        let duplicated = eyre::eyre!("outer: inner detail").wrap_err("outer: inner detail");
        assert_eq!(error_causes(&duplicated), vec!["outer: inner detail"]);
    }

    #[test]
    fn error_summary_keeps_only_what_failed_and_why() {
        let causes = [
            "could not fetch the system image",
            "image operation failed",
            "denied",
        ]
        .map(str::to_string);
        assert_eq!(
            error_summary(&causes),
            "could not fetch the system image: denied"
        );
        assert_eq!(
            error_summary(&causes[..1]),
            "could not fetch the system image"
        );
        assert_eq!(error_summary(&[]), "unknown failure");
    }

    #[test]
    fn idle_reclaimer_tracks_idle_windows() {
        let mut reclaimer = IdleReclaimer {
            enabled: true,
            idle_after: Duration::from_secs(120),
            last_sample: None,
            idle_since: None,
        };
        let start = tokio::time::Instant::now();
        let sample = |offset: u64, busy: f64, io: u64| ActivitySample {
            at: start + Duration::from_secs(offset),
            busy_seconds: busy,
            io_bytes: io,
        };
        // The first sample only establishes a baseline.
        assert_eq!(reclaimer.observe(sample(0, 100.0, 0), 4), None);
        // 4 vCPUs, 5 seconds: 0.5 busy seconds is 2.5%, idle.
        assert_eq!(
            reclaimer.observe(sample(5, 100.5, 100 * 1024), 4),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            reclaimer.observe(sample(10, 101.0, 200 * 1024), 4),
            Some(Duration::from_secs(10))
        );
        // A busy interval (3 of 20 CPU-seconds) resets the idle clock.
        assert_eq!(reclaimer.observe(sample(15, 104.0, 200 * 1024), 4), None);
        // Heavy I/O alone also counts as activity.
        assert_eq!(reclaimer.observe(sample(20, 104.1, 200 * MIB), 4), None);
        assert_eq!(
            reclaimer.observe(sample(25, 104.2, 200 * MIB), 4),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn guest_reclaim_success_never_drops_global_caches() {
        let temp = tempfile::tempdir().expect("temp");
        let bounded = temp.path().join("memory.reclaim");
        let global = temp.path().join("drop_caches");
        fs::write(&bounded, "before").expect("bounded fixture");
        fs::write(&global, "untouched").expect("global fixture");
        let script = guest_reclaim_script(4096, "memory.reclaim", "drop_caches");

        let output = Command::new("/bin/sh")
            .args(["-c", &script])
            .current_dir(temp.path())
            .output()
            .expect("run shell");

        assert!(output.status.success(), "stderr: {:?}", output.stderr);
        assert_eq!(
            parse_reclaim_branch(&output.stdout),
            Some(ReclaimBranch::Bounded)
        );
        assert_eq!(
            fs::read_to_string(bounded).expect("bounded result"),
            "4096\n"
        );
        assert_eq!(
            fs::read_to_string(global).expect("global result"),
            "untouched"
        );
    }

    #[test]
    fn guest_reclaim_falls_back_only_after_bounded_failure() {
        let temp = tempfile::tempdir().expect("temp");
        let bounded = temp.path().join("memory.reclaim");
        let global = temp.path().join("drop_caches");
        fs::create_dir(&bounded).expect("unwritable bounded fixture");
        fs::write(&global, "before").expect("global fixture");
        let script = guest_reclaim_script(4096, "memory.reclaim", "drop_caches");

        let output = Command::new("/bin/sh")
            .args(["-c", &script])
            .current_dir(temp.path())
            .output()
            .expect("run shell");

        assert!(output.status.success(), "stderr: {:?}", output.stderr);
        assert!(matches!(
            parse_reclaim_branch(&output.stdout),
            Some(ReclaimBranch::Fallback {
                bounded_exit_code
            }) if bounded_exit_code != 0
        ));
        assert_eq!(fs::read_to_string(global).expect("global result"), "1\n");
    }

    #[test]
    fn reclaim_branch_preserves_incomplete_bounded_exit_status() {
        assert_eq!(
            parse_reclaim_branch(b"fallback:11\n"),
            Some(ReclaimBranch::Fallback {
                bounded_exit_code: 11
            })
        );
    }

    #[test]
    fn daemon_status_defaults_absent_reclaim_fields() {
        let status: crate::system::supervisor::DaemonStatus =
            serde_json::from_value(serde_json::json!({
                "schema": 1,
                "generation": "12345678-1234-1234-1234-123456789abc",
                "pid": 42,
                "phase": "ready",
                "machine_id": null,
                "run_id": null,
                "image_digest": null,
                "docker_socket": "/tmp/silo.sock",
                "updated_at": "2026-09-14T00:00:00Z",
                "last_error": null,
                "restart_count": 0
            }))
            .expect("status");

        assert_eq!(status.memory_reclaim_outcome, None);
        assert_eq!(status.memory_reclaim_bounded_exit_code, None);
        assert_eq!(status.memory_reclaim_observed_cache_delta_bytes, None);
        assert_eq!(status.memory_reclaim_at, None);
        assert!(!status.host_memory_reclaim_requested);
        assert_eq!(status.host_memory_reclaim_effective, None);
    }

    #[test]
    fn host_memory_reclaim_auto_does_not_invent_an_effective_backend_state() {
        assert_eq!(initial_host_memory_reclaim_effective(true), None);
        assert_eq!(initial_host_memory_reclaim_effective(false), Some(false));
    }

    #[test]
    fn startup_retries_back_off_and_cap() {
        assert_eq!(startup_retry_delay(1), Duration::from_secs(5));
        assert_eq!(startup_retry_delay(2), Duration::from_secs(10));
        assert_eq!(startup_retry_delay(4), Duration::from_secs(40));
        assert_eq!(startup_retry_delay(5), Duration::from_secs(60));
        assert_eq!(startup_retry_delay(u32::MAX), Duration::from_secs(60));
    }

    #[test]
    fn lifetime_lock_is_exclusive_and_file_is_stable() {
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("daemon.lock");
        let first = LifetimeLock::acquire(&path).expect("first");
        assert!(LifetimeLock::acquire(&path).is_err());
        drop(first);
        assert!(path.exists());
        LifetimeLock::acquire(&path).expect("released");
    }
}
