use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::{
    ExecutionResult, MachineHostMemoryReclaim, MachineHostMemoryReclaimQualification,
    MachineMemoryReclaimReport, MachineReadinessOutcome, MachineStatus,
};
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
    /// How the agent's last guest cache-reclaim run ended.
    #[serde(default)]
    pub(crate) memory_reclaim_outcome: Option<MemoryReclaimOutcome>,
    /// Reclaim mode the agent used for that run: `gradual` or `dropcache`.
    #[serde(default)]
    pub(crate) memory_reclaim_mode: Option<String>,
    /// How far the guest's own `Cached` figure fell across that run, not host memory returned.
    #[serde(default)]
    pub(crate) memory_reclaim_observed_cache_delta_bytes: Option<u64>,
    /// When that run finished (RFC 3339).
    #[serde(default)]
    pub(crate) memory_reclaim_at: Option<String>,
    /// Reclaim runs the agent has completed since it started.
    #[serde(default)]
    pub(crate) memory_reclaim_runs: Option<u64>,
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

/// Outcome of one agent reclaim run, as the agent reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemoryReclaimOutcome {
    /// The kernel accepted the whole request.
    Reclaimed,
    /// The kernel stopped early and freed less than half of the request.
    Partial,
    /// No reclaimable cache above the agent's floor.
    Nothing,
    /// The control file could not be written.
    Failed,
}

impl MemoryReclaimOutcome {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "reclaimed" => Self::Reclaimed,
            "partial" => Self::Partial,
            "nothing" => Self::Nothing,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
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
        memory_reclaim_mode: None,
        memory_reclaim_observed_cache_delta_bytes: None,
        memory_reclaim_at: None,
        memory_reclaim_runs: None,
        host_memory_reclaim_requested: config.backend == crate::system::config::SystemBackend::Krun,
        host_memory_reclaim_effective: initial_host_memory_reclaim_effective(
            config.backend == crate::system::config::SystemBackend::Krun,
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
    let mut ticks = 0_u64;
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                break;
            }
            () = tokio::time::sleep(TICK_INTERVAL) => {
                ticks += 1;
                if let Ok(metrics) = machine.metrics().await {
                    let mut changed =
                        apply_host_memory_reclaim(&mut status, metrics.host_memory_reclaim.as_ref());
                    let guest_reclaim = metrics
                        .metrics
                        .as_ref()
                        .and_then(|observation| observation.report.snapshot.memory_reclaim.as_ref());
                    if let Some(report) = guest_reclaim {
                        if apply_guest_memory_reclaim(&mut status, report) {
                            changed = true;
                            append_log(&paths, &describe_guest_memory_reclaim(report))?;
                        }
                    }
                    if changed {
                        publish(&paths, &mut status)?;
                    }
                }
                if !ticks.is_multiple_of(HEALTH_INTERVAL.as_secs() / TICK_INTERVAL.as_secs()) {
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
/// Supervisor tick: refreshes status from vmmon metrics and, every `HEALTH_INTERVAL`,
/// probes the Docker socket.
const TICK_INTERVAL: Duration = Duration::from_secs(5);

/// Copies the agent's latest guest memory reclaim report into the status. Returns
/// whether it describes a run the status did not have yet. Guest memory reclaim
/// itself runs inside the guest agent; the daemon only observes it.
fn apply_guest_memory_reclaim(
    status: &mut DaemonStatus,
    report: &MachineMemoryReclaimReport,
) -> bool {
    let finished_at = chrono::DateTime::<chrono::Utc>::from(report.finished_at).to_rfc3339();
    if status.memory_reclaim_runs == Some(report.runs)
        && status.memory_reclaim_at.as_deref() == Some(finished_at.as_str())
    {
        return false;
    }
    status.memory_reclaim_outcome = MemoryReclaimOutcome::parse(&report.outcome);
    status.memory_reclaim_mode = Some(report.mode.clone());
    status.memory_reclaim_observed_cache_delta_bytes = Some(report.cached_delta_bytes());
    status.memory_reclaim_at = Some(finished_at);
    status.memory_reclaim_runs = Some(report.runs);
    true
}

fn describe_guest_memory_reclaim(report: &MachineMemoryReclaimReport) -> String {
    format!(
        "guest memory reclaim run {}: mode {} outcome {} requested {} MiB, guest cached memory fell by {} MiB{}",
        report.runs,
        report.mode,
        report.outcome,
        report.requested_bytes / (1024 * 1024),
        report.cached_delta_bytes() / (1024 * 1024),
        if report.compacted { ", compacted" } else { "" }
    )
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
    use std::time::Duration;

    use crate::system::config::{ResolvedShare, SystemConfig};
    use crate::system::supervisor::{
        activation_request, apply_guest_memory_reclaim, describe_guest_memory_reclaim,
        error_causes, error_summary, initial_host_memory_reclaim_effective, startup_retry_delay,
        LifetimeLock, MemoryReclaimOutcome,
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
    fn guest_reclaim_report_is_applied_once_per_run() {
        let mut status: crate::system::supervisor::DaemonStatus =
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
        let report = libvm::MachineMemoryReclaimReport {
            finished_at: std::time::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            mode: "gradual".to_string(),
            outcome: "partial".to_string(),
            requested_bytes: 256 * 1024 * 1024,
            cached_before_bytes: 1024 * 1024 * 1024,
            cached_after_bytes: 960 * 1024 * 1024,
            compacted: true,
            runs: 4,
        };
        assert!(apply_guest_memory_reclaim(&mut status, &report));
        assert_eq!(
            status.memory_reclaim_outcome,
            Some(MemoryReclaimOutcome::Partial)
        );
        assert_eq!(status.memory_reclaim_mode.as_deref(), Some("gradual"));
        assert_eq!(
            status.memory_reclaim_observed_cache_delta_bytes,
            Some(64 * 1024 * 1024)
        );
        assert_eq!(status.memory_reclaim_runs, Some(4));
        assert_eq!(
            status.memory_reclaim_at.as_deref(),
            Some("2027-01-15T08:00:00+00:00")
        );
        // The same run seen again is not a change.
        assert!(!apply_guest_memory_reclaim(&mut status, &report));
        assert_eq!(
            describe_guest_memory_reclaim(&report),
            "guest memory reclaim run 4: mode gradual outcome partial requested 256 MiB, guest cached memory fell by 64 MiB, compacted"
        );
        let unknown = libvm::MachineMemoryReclaimReport {
            outcome: "surprising".to_string(),
            runs: 5,
            ..report
        };
        assert!(apply_guest_memory_reclaim(&mut status, &unknown));
        assert_eq!(status.memory_reclaim_outcome, None);
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
        assert_eq!(status.memory_reclaim_mode, None);
        assert_eq!(status.memory_reclaim_observed_cache_delta_bytes, None);
        assert_eq!(status.memory_reclaim_at, None);
        assert_eq!(status.memory_reclaim_runs, None);
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
