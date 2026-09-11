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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonStatus {
    pub(crate) schema: u32,
    pub(crate) generation: Uuid,
    pub(crate) pid: u32,
    pub(crate) phase: DaemonPhase,
    pub(crate) machine_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) image_digest: Option<String>,
    pub(crate) docker_socket: String,
    pub(crate) updated_at: String,
    pub(crate) last_error: Option<String>,
    pub(crate) restart_count: u32,
    /// Guest memory target the balloon controller last applied, in bytes.
    #[serde(default)]
    pub(crate) memory_target_bytes: Option<u64>,
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
        docker_socket: config.docker_socket.display().to_string(),
        updated_at: now(),
        last_error: None,
        restart_count: 0,
        memory_target_bytes: None,
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
    let mut reclaimer = MemoryReclaimer::new(&config);
    let mut ticks = 0_u64;
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                break;
            }
            () = tokio::time::sleep(RECLAIM_INTERVAL) => {
                ticks += 1;
                // Memory pressure is exactly when the Docker probe tends to stall, so the
                // balloon controller runs on every tick regardless of engine health.
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
    status.phase = DaemonPhase::WaitingGuest;
    publish(paths, status)?;
    let readiness = machine.wait_ready(READY_TIMEOUT).await?;
    if readiness.outcome != MachineReadinessOutcome::Ready {
        bail!("system guest readiness ended with {:?}", readiness.outcome);
    }
    status.phase = DaemonPhase::ActivatingEngine;
    publish(paths, status)?;
    activate(&machine, config, record.data_uuid).await?;
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
/// Balloon controller cadence; the guest agent reports metrics every 5 seconds.
const RECLAIM_INTERVAL: Duration = Duration::from_secs(5);
const MIB: u64 = 1024 * 1024;
/// Memory kept free in the guest above what it currently uses.
const RECLAIM_HEADROOM: u64 = 1024 * MIB;
/// Largest shrink per tick, so the guest sheds page cache gradually.
const RECLAIM_STEP: u64 = 512 * MIB;
/// Smallest shrink worth a balloon request.
const RECLAIM_MIN_CHANGE: u64 = 64 * MIB;
/// After the target had to grow, leave it alone this long before shrinking again so a
/// bursty workload is not squeezed between its bursts.
const RECLAIM_HOLDOFF: Duration = Duration::from_secs(60);

/// Drives the guest's memory balloon so a mostly idle engine does not pin its whole
/// configured memory on the host. Every healthy tick reads the guest's memory metrics
/// and moves the balloon target toward "in use plus headroom", shrinking in steps and
/// growing at once when the guest runs short. Only Virtualization.framework has a
/// balloon; on other backends the first request reports unsupported and the
/// controller switches itself off.
pub(crate) struct MemoryReclaimer {
    max_bytes: u64,
    floor_bytes: u64,
    target_bytes: u64,
    enabled: bool,
    hold_until: Option<tokio::time::Instant>,
}

impl MemoryReclaimer {
    pub(crate) fn new(config: &ResolvedSystemConfig) -> Self {
        Self {
            max_bytes: config.memory_bytes,
            floor_bytes: config.memory_floor_bytes.min(config.memory_bytes),
            target_bytes: config.memory_bytes,
            enabled: config.memory_reclaim,
            hold_until: None,
        }
    }

    /// Returns the next target, or `None` when the current one should stay.
    ///
    /// `total_bytes` and `available_bytes` are the guest's own view. Inflated balloon
    /// pages count as used inside the guest, so they are subtracted to recover what
    /// the guest really needs.
    pub(crate) fn plan(&self, total_bytes: u64, available_bytes: u64) -> Option<u64> {
        let withheld = self.max_bytes.saturating_sub(self.target_bytes);
        let used = total_bytes
            .saturating_sub(available_bytes)
            .saturating_sub(withheld);
        let desired = used
            .saturating_add(RECLAIM_HEADROOM)
            .clamp(self.floor_bytes, self.max_bytes)
            / MIB
            * MIB;
        if desired > self.target_bytes {
            // The guest is running short: give memory back immediately. Under real
            // pressure release everything rather than chasing the estimate.
            let next = if available_bytes < RECLAIM_HEADROOM / 2 {
                self.max_bytes
            } else {
                desired
            };
            return (next != self.target_bytes).then_some(next);
        }
        let next = desired.max(self.target_bytes.saturating_sub(RECLAIM_STEP));
        (self.target_bytes.saturating_sub(next) >= RECLAIM_MIN_CHANGE).then_some(next)
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
        let metrics = match machine.metrics().await {
            Ok(metrics) => metrics,
            Err(error) => {
                append_log(paths, &format!("memory reclaim skipped: {error}"))?;
                return Ok(());
            }
        };
        let Some(memory) = metrics
            .metrics
            .and_then(|observation| observation.report.snapshot.memory)
        else {
            return Ok(());
        };
        let Some(next) = self.plan(memory.total_bytes, memory.available_bytes) else {
            return Ok(());
        };
        let now = tokio::time::Instant::now();
        if next < self.target_bytes && self.hold_until.is_some_and(|until| now < until) {
            return Ok(());
        }
        if next > self.target_bytes {
            self.hold_until = Some(now + RECLAIM_HOLDOFF);
        }
        // Balloon pages show up as used inside the guest; report what the guest itself uses.
        let withheld = self.max_bytes.saturating_sub(self.target_bytes);
        let guest_used = memory
            .total_bytes
            .saturating_sub(memory.available_bytes)
            .saturating_sub(withheld);
        match machine.set_memory_target(next).await {
            Ok(applied) => {
                let direction = if applied < self.target_bytes {
                    "shrunk"
                } else {
                    "grew"
                };
                self.target_bytes = applied;
                status.memory_target_bytes = Some(applied);
                publish(paths, status)?;
                append_log(
                    paths,
                    &format!(
                        "memory target {direction} to {} MiB (guest uses {} MiB)",
                        applied / MIB,
                        guest_used / MIB
                    ),
                )?;
            }
            Err(libvm::LibVmError::MonitorUnsupported { .. }) => {
                self.enabled = false;
                append_log(
                    paths,
                    "memory reclaim disabled: this virtualization backend has no memory balloon",
                )?;
            }
            Err(error) => {
                append_log(paths, &format!("memory target change failed: {error}"))?;
            }
        }
        Ok(())
    }
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
    data_uuid: Uuid,
) -> eyre::Result<()> {
    let request = serde_json::json!({
        "schema": 1,
        "data_uuid": data_uuid,
        "data_layout": 1,
        "required_shares": config.shares.iter().map(|share| serde_json::json!({
            "path": share.path,
            "tag": share.path.to_string_lossy(),
            "writable": !share.read_only,
        })).collect::<Vec<_>>(),
    });
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

pub(crate) fn read_status(paths: &SystemPaths) -> eyre::Result<Option<DaemonStatus>> {
    load_record(&paths.status())
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
    use std::time::Duration;

    use crate::system::supervisor::{
        error_causes, error_summary, startup_retry_delay, LifetimeLock,
    };

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
    fn memory_reclaimer_shrinks_in_steps_and_grows_at_once() {
        use crate::system::supervisor::{MemoryReclaimer, MIB};
        let mut reclaimer = MemoryReclaimer {
            max_bytes: 8192 * MIB,
            floor_bytes: 2048 * MIB,
            target_bytes: 8192 * MIB,
            enabled: true,
            hold_until: None,
        };
        // Idle guest: 700 MiB used, wants 1700 MiB; shrinks by at most 512 MiB per tick.
        let total = 7900 * MIB;
        assert_eq!(reclaimer.plan(total, total - 700 * MIB), Some(7680 * MIB));
        reclaimer.target_bytes = 2560 * MIB;
        // Balloon holds 5632 MiB, which the guest reports as used; real use is 700 MiB.
        let available = total - 700 * MIB - 5632 * MIB;
        assert_eq!(reclaimer.plan(total, available), Some(2048 * MIB));
        reclaimer.target_bytes = 2048 * MIB;
        // At the floor nothing more happens.
        assert_eq!(reclaimer.plan(total, total - 700 * MIB - 6144 * MIB), None);
        // A build starts: 1200 MiB in use with the balloon holding 6 GiB; use plus the
        // 1 GiB headroom is demanded right away.
        let available = total - 1200 * MIB - 6144 * MIB;
        assert_eq!(reclaimer.plan(total, available), Some(2224 * MIB));
        // Under real pressure (almost nothing available) release everything.
        assert_eq!(reclaimer.plan(total, 100 * MIB), Some(8192 * MIB));
        // Tiny differences are ignored.
        reclaimer.target_bytes = 3500 * MIB;
        let available = total - 2470 * MIB - 4692 * MIB;
        assert_eq!(reclaimer.plan(total, available), None);
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
