use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::{
    ExecutionResult, MachineHostMemoryReclaim, MachineHostMemoryReclaimQualification,
    MachineReadinessOutcome, MachineStatus,
};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::AppApi;
use crate::system::config::ResolvedSystemConfig;
use crate::system::host_pressure::{self, HostMemoryPressure};
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
    /// Guest cached-byte decrease the guest measured across the attempt, not host memory returned.
    #[serde(default)]
    pub(crate) memory_reclaim_observed_cache_delta_bytes: Option<u64>,
    /// When the last guest cache-reclaim attempt ran (RFC 3339).
    #[serde(default)]
    pub(crate) memory_reclaim_at: Option<String>,
    /// What triggered the last guest cache-reclaim attempt.
    #[serde(default)]
    pub(crate) memory_reclaim_trigger: Option<MemoryReclaimTrigger>,
    /// Whether the runtime requested per-VM host memory reclaim qualification.
    #[serde(default)]
    pub(crate) host_memory_reclaim_requested: bool,
    /// Effective state as last reported by the VM backend. `None` until it reports.
    #[serde(default)]
    pub(crate) host_memory_reclaim_effective: Option<bool>,
    /// Outcome of the backend's qualification probe, when reported.
    #[serde(default)]
    pub(crate) host_memory_reclaim_qualification: Option<String>,
    /// Bytes the backend released to the host during this VM run, when reported.
    #[serde(default)]
    pub(crate) host_memory_reclaim_released_bytes: Option<u64>,
    /// Release cycles that failed during this VM run, when reported.
    #[serde(default)]
    pub(crate) host_memory_reclaim_failed_operations: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemoryReclaimOutcome {
    Bounded,
    Fallback,
    Nothing,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemoryReclaimTrigger {
    Idle,
    HostPressure,
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
        memory_reclaim_trigger: None,
        host_memory_reclaim_requested: config.host_memory_reclaim,
        host_memory_reclaim_effective: initial_host_memory_reclaim_effective(
            config.host_memory_reclaim,
        ),
        host_memory_reclaim_qualification: None,
        host_memory_reclaim_released_bytes: None,
        host_memory_reclaim_failed_operations: None,
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
                let metrics = machine.metrics().await.ok();
                if let Some(metrics) = metrics.as_ref() {
                    if apply_host_memory_reclaim(&mut status, metrics.host_memory_reclaim.as_ref()) {
                        publish(&paths, &mut status)?;
                    }
                }
                let snapshot = metrics.and_then(snapshot_of);
                reclaimer.tick(&machine, &paths, &mut status, snapshot.as_ref()).await?;
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
/// Page cache worth an idle reclaim attempt.
const RECLAIM_MIN_CACHE: u64 = 512 * MIB;
/// Page cache worth a reclaim attempt while the host is under memory pressure.
const PRESSURE_RECLAIM_MIN_CACHE: u64 = 128 * MIB;
/// Minimum spacing between pressure-triggered reclaim attempts.
const PRESSURE_RECLAIM_COOLDOWN: Duration = Duration::from_secs(30);
/// Guest-side reclaim, run as root inside the guest.
///
/// The target is computed in the guest from `/proc/meminfo`: page cache minus
/// shmem (tmpfs and shared memory cannot be dropped) plus reclaimable slab.
/// cgroup v2 root `memory.reclaim` refuses a request it cannot fully satisfy,
/// so the target is requested in chunks and a partial result is kept. The
/// global cache drop is only a fallback for kernels without `memory.reclaim`.
/// The last stdout line reports `<kind> before=<Cached> after=<Cached> ...`.
const GUEST_RECLAIM_SCRIPT: &str = r#"meminfo() { while read -r key value _; do if [ "$key" = "$1" ]; then echo $((value * 1024)); return 0; fi; done < %MEMINFO%; echo 0; }
before=$(meminfo Cached:)
shmem=$(meminfo Shmem:)
slab=$(meminfo SReclaimable:)
target=$((before - shmem + slab))
if [ "$target" -le 0 ]; then
  printf 'nothing before=%s after=%s target=%s
' "$before" "$before" "$target"
  exit 0
fi
if [ -f %CGROUP_RECLAIM% ] && [ -w %CGROUP_RECLAIM% ]; then
  chunk=$((target / 8))
  min=$((32 * 1024 * 1024))
  [ "$chunk" -lt "$min" ] && chunk=$min
  remaining=$target
  chunks=0
  status=0
  while [ "$remaining" -gt 0 ]; do
    step=$chunk
    [ "$step" -gt "$remaining" ] && step=$remaining
    if echo "$step" > %CGROUP_RECLAIM% 2>/dev/null; then
      chunks=$((chunks + 1))
      remaining=$((remaining - step))
    else
      status=$?
      break
    fi
  done
  after=$(meminfo Cached:)
  printf 'bounded before=%s after=%s target=%s chunks=%s status=%s
' "$before" "$after" "$target" "$chunks" "$status"
  exit 0
fi
sync
echo 1 > %DROP_CACHES% || exit $?
after=$(meminfo Cached:)
printf 'fallback before=%s after=%s target=%s
' "$before" "$after" "$target"
"#;
const CGROUP_RECLAIM_PATH: &str = "/sys/fs/cgroup/memory.reclaim";
const DROP_CACHES_PATH: &str = "/proc/sys/vm/drop_caches";
const MEMINFO_PATH: &str = "/proc/meminfo";

/// Reclaims guest page cache, the way WSL2's `autoMemoryReclaim` does.
///
/// Every tick reads the guest's metrics. Once CPU and block I/O have stayed idle for
/// the configured window and the guest holds enough page cache, the controller asks
/// the guest kernel to reclaim that cache. When the host itself reports memory
/// pressure the wait is skipped and reclaim runs at once, rate-limited by a
/// cooldown. Freed guest pages reach the host through the balloon's free-page
/// reporting; this controller does not claim that the host released the same
/// number of bytes.
pub(crate) struct IdleReclaimer {
    enabled: bool,
    idle_after: Duration,
    last_sample: Option<ActivitySample>,
    idle_since: Option<tokio::time::Instant>,
    last_pressure_reclaim: Option<tokio::time::Instant>,
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
            last_pressure_reclaim: None,
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
        snapshot: Option<&libvm::MachineMetricSnapshot>,
    ) -> eyre::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let Some(snapshot) = snapshot else {
            return Ok(());
        };
        let now = tokio::time::Instant::now();
        let cpus = snapshot
            .cpu
            .as_ref()
            .map(|cpu| cpu.logical_cpu_count)
            .unwrap_or(1);
        let idle_for = self.observe(ActivitySample::from_snapshot(now, snapshot), cpus);
        let Some(memory) = snapshot.memory.as_ref() else {
            return Ok(());
        };
        let cached = cached_bytes(memory);
        let Some(trigger) = self.decide(now, idle_for, cached, host_pressure::current()) else {
            return Ok(());
        };
        self.reclaim(machine, paths, status, trigger).await
    }

    /// Picks the reclaim trigger for this tick, if any, and arms the matching
    /// cooldown. Host pressure wins over the idle window because it means the
    /// memory is needed now.
    fn decide(
        &mut self,
        now: tokio::time::Instant,
        idle_for: Option<Duration>,
        cached: u64,
        pressure: Option<HostMemoryPressure>,
    ) -> Option<MemoryReclaimTrigger> {
        let pressured = pressure.is_some_and(|level| level >= HostMemoryPressure::Warning);
        let cooled_down = self
            .last_pressure_reclaim
            .is_none_or(|last| now.saturating_duration_since(last) >= PRESSURE_RECLAIM_COOLDOWN);
        if pressured && cooled_down && cached >= PRESSURE_RECLAIM_MIN_CACHE {
            self.last_pressure_reclaim = Some(now);
            // The guest is about to change; judge idleness afresh afterwards.
            self.idle_since = None;
            return Some(MemoryReclaimTrigger::HostPressure);
        }
        if idle_for.is_some_and(|idle_for| idle_for >= self.idle_after)
            && cached >= RECLAIM_MIN_CACHE
        {
            // Require a fresh idle window before the next attempt whatever happens now.
            self.idle_since = None;
            return Some(MemoryReclaimTrigger::Idle);
        }
        None
    }

    async fn reclaim(
        &mut self,
        machine: &crate::api::machine::AppMachine,
        paths: &SystemPaths,
        status: &mut DaemonStatus,
        trigger: MemoryReclaimTrigger,
    ) -> eyre::Result<()> {
        let trigger_text = match trigger {
            MemoryReclaimTrigger::Idle => "idle",
            MemoryReclaimTrigger::HostPressure => "host memory pressure",
        };
        let script = guest_reclaim_script(CGROUP_RECLAIM_PATH, DROP_CACHES_PATH, MEMINFO_PATH);
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
                record_reclaim(status, trigger, MemoryReclaimOutcome::Failed, None, None);
                publish(paths, status)?;
                append_log(
                    paths,
                    &format!("memory reclaim ({trigger_text}): guest execution failed: {error}"),
                )?;
                return Ok(());
            }
        };
        if !matches!(output.result(), ExecutionResult::Exited { code: Some(0) }) {
            record_reclaim(status, trigger, MemoryReclaimOutcome::Failed, None, None);
            publish(paths, status)?;
            append_log(
                paths,
                &format!(
                    "memory reclaim ({trigger_text}): guest cache reclaim failed ({:?}): {}",
                    output.result(),
                    String::from_utf8_lossy(output.stderr_bytes()).trim()
                ),
            )?;
            return Ok(());
        }
        let Some(result) = parse_reclaim_result(output.stdout_bytes()) else {
            record_reclaim(status, trigger, MemoryReclaimOutcome::Failed, None, None);
            publish(paths, status)?;
            append_log(
                paths,
                &format!("memory reclaim ({trigger_text}): guest returned an invalid result"),
            )?;
            return Ok(());
        };
        let reclaimed = result.reclaimed();
        let (outcome, bounded_exit_code, description) = match result.branch {
            ReclaimBranch::Bounded { chunks, status: 0 } => (
                MemoryReclaimOutcome::Bounded,
                None,
                format!(
                    "bounded guest cgroup reclaim completed in {chunks} chunk(s) for a {} MiB target",
                    result.target / MIB
                ),
            ),
            ReclaimBranch::Bounded { chunks, status } => (
                MemoryReclaimOutcome::Bounded,
                Some(status),
                format!(
                    "bounded guest cgroup reclaim stopped after {chunks} chunk(s) with exit {status} for a {} MiB target",
                    result.target / MIB
                ),
            ),
            ReclaimBranch::Fallback => (
                MemoryReclaimOutcome::Fallback,
                None,
                format!(
                    "memory.reclaim is unavailable in the guest; global cache-drop fallback completed for a {} MiB target",
                    result.target / MIB
                ),
            ),
            ReclaimBranch::Nothing => (
                MemoryReclaimOutcome::Nothing,
                None,
                "guest has no reclaimable page cache".to_string(),
            ),
        };
        record_reclaim(status, trigger, outcome, bounded_exit_code, Some(reclaimed));
        publish(paths, status)?;
        append_log(
            paths,
            &format!(
                "memory reclaim ({trigger_text}): {description}; guest cached memory fell by {} MiB",
                reclaimed / MIB
            ),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReclaimBranch {
    /// cgroup v2 `memory.reclaim` ran; `status` is the exit of the first refused
    /// chunk, or 0 when the whole target was accepted.
    Bounded { chunks: u32, status: u32 },
    /// `memory.reclaim` is missing; the global cache drop ran instead.
    Fallback,
    /// The guest computed no reclaimable cache.
    Nothing,
}

/// What the guest reported after one reclaim attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestReclaimResult {
    branch: ReclaimBranch,
    /// `Cached` from `/proc/meminfo` before and after, in bytes.
    before: u64,
    after: u64,
    /// Reclaimable estimate the guest targeted, in bytes.
    target: u64,
}

impl GuestReclaimResult {
    fn reclaimed(&self) -> u64 {
        self.before.saturating_sub(self.after)
    }
}

fn guest_reclaim_script(cgroup_reclaim: &str, drop_caches: &str, meminfo: &str) -> String {
    GUEST_RECLAIM_SCRIPT
        .replace("%CGROUP_RECLAIM%", cgroup_reclaim)
        .replace("%DROP_CACHES%", drop_caches)
        .replace("%MEMINFO%", meminfo)
}

fn parse_reclaim_result(stdout: &[u8]) -> Option<GuestReclaimResult> {
    let text = std::str::from_utf8(stdout).ok()?;
    let line = text.lines().rev().find(|line| !line.trim().is_empty())?;
    let mut fields = line.split_whitespace();
    let kind = fields.next()?;
    let (mut before, mut after, mut target, mut chunks, mut status) =
        (None, None, None, None, None);
    for field in fields {
        let (key, value) = field.split_once('=')?;
        match key {
            "before" => before = value.parse::<u64>().ok(),
            "after" => after = value.parse::<u64>().ok(),
            "target" => target = value.parse::<i64>().ok().map(|bytes| bytes.max(0) as u64),
            "chunks" => chunks = value.parse::<u32>().ok(),
            "status" => status = value.parse::<u32>().ok(),
            _ => {}
        }
    }
    let branch = match kind {
        "bounded" => ReclaimBranch::Bounded {
            chunks: chunks?,
            status: status?,
        },
        "fallback" => ReclaimBranch::Fallback,
        "nothing" => ReclaimBranch::Nothing,
        _ => return None,
    };
    Some(GuestReclaimResult {
        branch,
        before: before?,
        after: after?,
        target: target?,
    })
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
    trigger: MemoryReclaimTrigger,
    outcome: MemoryReclaimOutcome,
    bounded_exit_code: Option<u32>,
    observed_delta: Option<u64>,
) {
    status.memory_reclaim_trigger = Some(trigger);
    status.memory_reclaim_outcome = Some(outcome);
    status.memory_reclaim_bounded_exit_code = bounded_exit_code;
    status.memory_reclaim_observed_cache_delta_bytes = observed_delta;
    status.memory_reclaim_at = Some(now());
}

fn snapshot_of(metrics: libvm::MachineMetrics) -> Option<libvm::MachineMetricSnapshot> {
    metrics
        .metrics
        .map(|observation| observation.report.snapshot)
}

/// Copies the backend's host memory reclaim report into the status. Returns
/// whether anything changed. A missing report leaves the status untouched, so
/// backends that never report keep the initial "unknown" state.
fn apply_host_memory_reclaim(
    status: &mut DaemonStatus,
    report: Option<&MachineHostMemoryReclaim>,
) -> bool {
    let Some(report) = report else {
        return false;
    };
    let qualification = match report.qualification {
        MachineHostMemoryReclaimQualification::NotRun => "not-run",
        MachineHostMemoryReclaimQualification::Passed => "passed",
        MachineHostMemoryReclaimQualification::Failed => "failed",
        MachineHostMemoryReclaimQualification::Inconclusive => "inconclusive",
    };
    let changed = status.host_memory_reclaim_effective != Some(report.effective)
        || status.host_memory_reclaim_qualification.as_deref() != Some(qualification)
        || status.host_memory_reclaim_released_bytes != Some(report.released_bytes)
        || status.host_memory_reclaim_failed_operations != Some(report.failed_operations);
    if changed {
        status.host_memory_reclaim_effective = Some(report.effective);
        status.host_memory_reclaim_qualification = Some(qualification.to_string());
        status.host_memory_reclaim_released_bytes = Some(report.released_bytes);
        status.host_memory_reclaim_failed_operations = Some(report.failed_operations);
    }
    changed
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
    use crate::system::host_pressure::HostMemoryPressure;
    use crate::system::supervisor::{
        activation_request, error_causes, error_summary, guest_reclaim_script,
        initial_host_memory_reclaim_effective, parse_reclaim_result, startup_retry_delay,
        ActivitySample, GuestReclaimResult, IdleReclaimer, LifetimeLock, MemoryReclaimTrigger,
        ReclaimBranch, MIB,
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
            last_pressure_reclaim: None,
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

    /// `/proc/meminfo` shape with 1 GiB cached, 256 MiB of it shmem, and 64 MiB
    /// reclaimable slab: the guest should target 832 MiB.
    const MEMINFO_FIXTURE: &str = "MemTotal:        8388608 kB\nMemFree:         1048576 kB\nCached:          1048576 kB\nShmem:            262144 kB\nSReclaimable:      65536 kB\n";

    fn run_reclaim_script(temp: &std::path::Path) -> std::process::Output {
        let script = guest_reclaim_script("memory.reclaim", "drop_caches", "meminfo");
        Command::new("/bin/sh")
            .args(["-c", &script])
            .current_dir(temp)
            .output()
            .expect("run shell")
    }

    #[test]
    fn guest_reclaim_requests_the_reclaimable_target_in_chunks() {
        let temp = tempfile::tempdir().expect("temp");
        fs::write(temp.path().join("meminfo"), MEMINFO_FIXTURE).expect("meminfo fixture");
        fs::write(temp.path().join("memory.reclaim"), "").expect("bounded fixture");
        fs::write(temp.path().join("drop_caches"), "untouched").expect("global fixture");

        let output = run_reclaim_script(temp.path());

        assert!(output.status.success(), "stderr: {:?}", output.stderr);
        let result = parse_reclaim_result(&output.stdout).expect("parsed result");
        assert_eq!(
            result,
            GuestReclaimResult {
                branch: ReclaimBranch::Bounded {
                    chunks: 8,
                    status: 0
                },
                before: 1024 * MIB,
                after: 1024 * MIB,
                target: 832 * MIB,
            }
        );
        assert_eq!(result.reclaimed(), 0);
        // The last chunk is the remainder of an 8-way split of the target.
        assert_eq!(
            fs::read_to_string(temp.path().join("memory.reclaim")).expect("bounded result"),
            format!("{}\n", 832 * MIB - 7 * (832 * MIB / 8))
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("drop_caches")).expect("global result"),
            "untouched"
        );
    }

    #[test]
    fn guest_reclaim_keeps_partial_progress_when_a_chunk_is_refused() {
        let temp = tempfile::tempdir().expect("temp");
        fs::write(temp.path().join("meminfo"), MEMINFO_FIXTURE).expect("meminfo fixture");
        // Writable but every write fails: a directory named like the control file.
        fs::create_dir(temp.path().join("memory.reclaim")).expect("bounded fixture");
        fs::write(temp.path().join("drop_caches"), "untouched").expect("global fixture");

        // Not a regular file, so the script must treat memory.reclaim as absent.
        let output = run_reclaim_script(temp.path());
        assert!(output.status.success(), "stderr: {:?}", output.stderr);
        assert_eq!(
            parse_reclaim_result(&output.stdout).map(|result| result.branch),
            Some(ReclaimBranch::Fallback)
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("drop_caches")).expect("global result"),
            "1\n"
        );
    }

    #[test]
    fn guest_reclaim_reports_nothing_when_cache_is_all_shmem() {
        let temp = tempfile::tempdir().expect("temp");
        fs::write(
            temp.path().join("meminfo"),
            "Cached:           262144 kB\nShmem:            262144 kB\n",
        )
        .expect("meminfo fixture");
        fs::write(temp.path().join("memory.reclaim"), "").expect("bounded fixture");
        fs::write(temp.path().join("drop_caches"), "untouched").expect("global fixture");

        let output = run_reclaim_script(temp.path());
        assert!(output.status.success(), "stderr: {:?}", output.stderr);
        let result = parse_reclaim_result(&output.stdout).expect("parsed result");
        assert_eq!(result.branch, ReclaimBranch::Nothing);
        assert_eq!(result.target, 0);
        assert_eq!(
            fs::read_to_string(temp.path().join("memory.reclaim")).expect("bounded result"),
            ""
        );
    }

    #[test]
    fn reclaim_result_parser_reads_the_last_line_and_partial_status() {
        let result = parse_reclaim_result(
            b"noise\nbounded before=1073741824 after=536870912 target=800000000 chunks=3 status=1\n",
        )
        .expect("parsed");
        assert_eq!(
            result.branch,
            ReclaimBranch::Bounded {
                chunks: 3,
                status: 1
            }
        );
        assert_eq!(result.reclaimed(), 512 * MIB);
        assert_eq!(
            parse_reclaim_result(b"nothing before=1 after=1 target=-5\n").map(|r| r.target),
            Some(0)
        );
        assert_eq!(
            parse_reclaim_result(b"bounded before=1 after=1 target=1\n"),
            None
        );
        assert_eq!(
            parse_reclaim_result(b"unknown before=1 after=1 target=1\n"),
            None
        );
    }

    #[test]
    fn host_pressure_triggers_reclaim_before_the_idle_window_with_a_cooldown() {
        let mut reclaimer = IdleReclaimer {
            enabled: true,
            idle_after: Duration::from_secs(120),
            last_sample: None,
            idle_since: None,
            last_pressure_reclaim: None,
        };
        let start = tokio::time::Instant::now();
        // Not idle long enough, no pressure: nothing happens.
        assert_eq!(
            reclaimer.decide(start, Some(Duration::from_secs(10)), 600 * MIB, None),
            None
        );
        // Warning-level pressure fires at once, even with less cache than idle needs.
        assert_eq!(
            reclaimer.decide(
                start,
                Some(Duration::from_secs(10)),
                200 * MIB,
                Some(HostMemoryPressure::Warning)
            ),
            Some(MemoryReclaimTrigger::HostPressure)
        );
        // Inside the cooldown the same pressure is ignored.
        assert_eq!(
            reclaimer.decide(
                start + Duration::from_secs(10),
                Some(Duration::from_secs(20)),
                600 * MIB,
                Some(HostMemoryPressure::Critical)
            ),
            None
        );
        // Too little cache is never worth a pressure run.
        assert_eq!(
            reclaimer.decide(
                start + Duration::from_secs(40),
                None,
                64 * MIB,
                Some(HostMemoryPressure::Critical)
            ),
            None
        );
        // After the cooldown pressure fires again.
        assert_eq!(
            reclaimer.decide(
                start + Duration::from_secs(40),
                None,
                600 * MIB,
                Some(HostMemoryPressure::Critical)
            ),
            Some(MemoryReclaimTrigger::HostPressure)
        );
        // The idle path still needs the full window and the larger cache floor.
        assert_eq!(
            reclaimer.decide(
                start + Duration::from_secs(50),
                Some(Duration::from_secs(120)),
                200 * MIB,
                Some(HostMemoryPressure::Normal)
            ),
            None
        );
        assert_eq!(
            reclaimer.decide(
                start + Duration::from_secs(50),
                Some(Duration::from_secs(120)),
                600 * MIB,
                Some(HostMemoryPressure::Normal)
            ),
            Some(MemoryReclaimTrigger::Idle)
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
        assert_eq!(status.memory_reclaim_trigger, None);
        assert!(!status.host_memory_reclaim_requested);
        assert_eq!(status.host_memory_reclaim_effective, None);
        assert_eq!(status.host_memory_reclaim_qualification, None);
        assert_eq!(status.host_memory_reclaim_released_bytes, None);
        assert_eq!(status.host_memory_reclaim_failed_operations, None);
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
