//! Brings the system VM up, keeps it healthy, and upgrades it in place.
//!
//! ```text
//!        ┌────────────── restart (upgraded or rolled back) ──────────────┐
//!        ▼                                                               │
//!  start: recover ─► ensure VM ─► boot ─► activate ─► Ready ─► supervise ┤
//!        ▲    │ error                                   health, metrics, │
//!        └────┘ back off                                 update checks   │
//!                                                                        ▼
//!                                                     SIGINT/SIGTERM: stop VM
//! ```
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::{
    MachineHostMemoryReclaim, MachineHostMemoryReclaimQualification, MachineMemoryReclaimReport,
    MachineReadinessOutcome, MachineStatus,
};
use nix::fcntl::{Flock, FlockArg};
use silod_spec::status::{DaemonPhase, DaemonStatus, MemoryReclaimOutcome};
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio::time::Instant;
use uuid::Uuid;

use crate::config::{DesiredSystem, SystemBackend};
use crate::engine::{
    activate, probe_docker_socket, stop_engine, wait_docker_socket, ENGINE_REACHABLE_TIMEOUT,
    READY_TIMEOUT,
};
use crate::paths::SystemPaths;
use crate::provision::ensure_system_machine;
use crate::record::{write_record, DaemonRecord};
use crate::runtime::{SystemMachine, SystemRuntime};

/// Engine health probe cadence.
const HEALTH_INTERVAL: Duration = Duration::from_secs(10);
/// Supervisor tick: refreshes status from silo-vmm metrics (the guest agent reports
/// every 5 seconds) and, every `HEALTH_INTERVAL`, probes the Docker socket.
const TICK_INTERVAL: Duration = Duration::from_secs(5);
/// How often silod asks the registry whether the configured image moved. The first
/// check follows the first Ready so a changed image applies promptly.
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

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
            Err((_, error @ nix::errno::Errno::EWOULDBLOCK)) => {
                Err(error).context("another Silo system daemon owns this installation")
            }
            Err((_, error)) => Err(error).context("lock system daemon installation"),
        }
    }
}

/// SIGINT and SIGTERM, registered once for the process lifetime. A signal that
/// arrives while the supervisor is busy (mid-upgrade, say) is kept and observed at
/// the next `recv`, rather than lost between short-lived listeners.
struct Shutdown {
    interrupt: Signal,
    terminate: Signal,
}

impl Shutdown {
    fn listen() -> eyre::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

/// The running system VM the supervisor started or adopted.
struct Active {
    machine: SystemMachine,
    machine_id: String,
}

enum Next {
    Shutdown,
    /// The VM was replaced by an upgrade or restored by a rollback; boot it again.
    Restart,
}

enum UpdateOutcome {
    Unchanged,
    Restart,
    Shutdown,
}

/// A fresh status for this process, before any configuration is known.
pub(crate) fn initial_status(docker_socket: &Path) -> eyre::Result<DaemonStatus> {
    Ok(DaemonStatus {
        schema: 1,
        generation: Uuid::new_v4(),
        pid: std::process::id(),
        process_start: process_start_identity()?,
        phase: DaemonPhase::PreparingStorage,
        machine_id: None,
        run_id: None,
        image_digest: None,
        configured_image: None,
        memory_bytes: None,
        actual_backend: None,
        docker_socket: docker_socket.display().to_string(),
        updated_at: now(),
        last_error: None,
        restart_count: 0,
        update_checked_at: None,
        update_error: None,
        memory_reclaim_outcome: None,
        memory_reclaim_mode: None,
        memory_reclaim_observed_cache_delta_bytes: None,
        memory_reclaim_at: None,
        memory_reclaim_runs: None,
        host_memory_reclaim_requested: false,
        host_memory_reclaim_effective: None,
        host_memory_reclaim_qualification: None,
        host_memory_reclaim_released_bytes: None,
        host_memory_reclaim_failed_operations: None,
    })
}

/// Reports a failure that ends this silod process.
pub(crate) fn publish_failure(
    paths: &SystemPaths,
    status: &mut DaemonStatus,
    error: &eyre::Report,
) -> eyre::Result<()> {
    status.phase = DaemonPhase::Failed;
    status.last_error = Some(error_summary(&error_causes(error)));
    publish(paths, status)?;
    append_log(paths, &format!("system daemon failed: {error:#}"))
}

struct Supervisor {
    paths: SystemPaths,
    desired: DesiredSystem,
    runtime_config: libvm::RuntimeConfig,
    /// Connected on the first startup attempt that gets that far; kept thereafter.
    runtime: Option<SystemRuntime>,
    status: DaemonStatus,
    /// Manifests that failed qualification, validation, or their first boot in this
    /// process. Not retried until silod restarts.
    rejected: BTreeSet<String>,
    next_update_check: Instant,
}

/// Runs until SIGINT/SIGTERM. The caller holds the lifetime lock.
pub(crate) async fn serve(
    paths: SystemPaths,
    desired: DesiredSystem,
    mut status: DaemonStatus,
) -> eyre::Result<()> {
    let mut shutdown = Shutdown::listen()?;
    let host_reclaim = desired.config.backend == SystemBackend::Krun;
    status.configured_image = Some(desired.image.clone());
    status.memory_bytes = Some(desired.config.memory_bytes);
    status.docker_socket = desired.config.docker_socket.display().to_string();
    status.host_memory_reclaim_requested = host_reclaim;
    status.host_memory_reclaim_effective = initial_host_memory_reclaim_effective(host_reclaim);
    publish(&paths, &mut status)?;
    append_log(&paths, "preparing installation storage")?;
    let mut supervisor = Supervisor {
        runtime_config: libvm::RuntimeConfig::local(paths.home())
            .with_virt_backend(desired.config.backend.runtime_override()),
        paths,
        desired,
        runtime: None,
        status,
        rejected: BTreeSet::new(),
        next_update_check: Instant::now(),
    };
    let result = supervisor.run(&mut shutdown).await;
    if let Err(error) = &result {
        publish_failure(&supervisor.paths, &mut supervisor.status, error)?;
    }
    result
}

impl Supervisor {
    async fn run(&mut self, shutdown: &mut Shutdown) -> eyre::Result<()> {
        loop {
            let Some(active) = self.start(shutdown).await? else {
                return self.cancelled().await;
            };
            match self.supervise(&active, shutdown).await? {
                Next::Shutdown => return self.stop(active).await,
                Next::Restart => {}
            }
        }
    }

    /// Retries startup with backoff until the engine is Ready or shutdown is requested.
    async fn start(&mut self, shutdown: &mut Shutdown) -> eyre::Result<Option<Active>> {
        let mut failed_attempts = 0_u32;
        loop {
            let outcome = {
                let attempt = attempt(
                    &mut self.runtime,
                    &self.runtime_config,
                    &self.paths,
                    &self.desired,
                    &mut self.status,
                );
                tokio::pin!(attempt);
                tokio::select! {
                    result = &mut attempt => Some(result),
                    () = shutdown.recv() => None,
                }
            };
            let error = match outcome {
                None => return Ok(None),
                Some(Ok(active)) => {
                    self.after_ready().await?;
                    return Ok(Some(active));
                }
                Some(Err(error)) => error,
            };
            self.roll_back_unproven_upgrade().await?;
            // Startup problems such as an unavailable system image are often
            // transient. Stay alive, publish the failure for `daemon status`, and
            // retry with backoff instead of exiting and leaving the service manager
            // to relaunch the process in a loop.
            failed_attempts = failed_attempts.saturating_add(1);
            let delay = startup_retry_delay(failed_attempts);
            let causes = error_causes(&error);
            self.status.phase = DaemonPhase::Retrying;
            self.status.last_error = Some(error_summary(&causes));
            self.status.restart_count = failed_attempts;
            publish(&self.paths, &mut self.status)?;
            append_log(
                &self.paths,
                &format!(
                    "startup attempt {failed_attempts} failed: {}; retrying in {}s",
                    causes.join(": "),
                    delay.as_secs()
                ),
            )?;
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = shutdown.recv() => return Ok(None),
            }
        }
    }

    /// A committed upgrade becomes permanent once its VM reached Ready.
    async fn after_ready(&mut self) -> eyre::Result<()> {
        let runtime = connected(&mut self.runtime)?;
        if let Err(error) = crate::upgrade::finalize(runtime, &self.paths).await {
            append_log(
                &self.paths,
                &format!("could not finalize the system image upgrade: {error:#}"),
            )?;
        }
        Ok(())
    }

    /// A committed upgrade whose VM cannot reach Ready is rolled back to the
    /// previous VM rather than retried forever.
    async fn roll_back_unproven_upgrade(&mut self) -> eyre::Result<()> {
        let Some(runtime) = self.runtime.as_mut() else {
            return Ok(());
        };
        let Some(record) = DaemonRecord::load(&self.paths)? else {
            return Ok(());
        };
        let Some(upgrade) = record.upgrade.filter(|upgrade| upgrade.complete) else {
            return Ok(());
        };
        if let Some(candidate) = &upgrade.candidate_machine_id {
            if let Some(digest) = runtime
                .inspect_machine(candidate)
                .await
                .ok()
                .and_then(|machine| machine.rootfs)
                .and_then(|rootfs| rootfs.selected_manifest_digest)
            {
                self.rejected.insert(digest);
            }
        }
        append_log(
            &self.paths,
            "the upgraded system VM did not become ready; rolling back",
        )?;
        crate::upgrade::recover(runtime, &self.paths).await
    }

    async fn supervise(&mut self, active: &Active, shutdown: &mut Shutdown) -> eyre::Result<Next> {
        let mut consecutive_failures = 0_u8;
        let mut ticks = 0_u64;
        loop {
            tokio::select! {
                () = shutdown.recv() => return Ok(Next::Shutdown),
                () = tokio::time::sleep(TICK_INTERVAL) => {}
            }
            ticks += 1;
            self.observe_metrics(&active.machine).await?;
            if Instant::now() >= self.next_update_check {
                self.next_update_check = Instant::now() + UPDATE_CHECK_INTERVAL;
                match self.update(active, shutdown).await? {
                    UpdateOutcome::Unchanged => {}
                    UpdateOutcome::Restart => return Ok(Next::Restart),
                    UpdateOutcome::Shutdown => return Ok(Next::Shutdown),
                }
            }
            if !ticks.is_multiple_of(HEALTH_INTERVAL.as_secs() / TICK_INTERVAL.as_secs()) {
                continue;
            }
            match probe_docker_socket(&self.desired.config.docker_socket) {
                Ok(()) => {
                    consecutive_failures = 0;
                    if self.status.phase != DaemonPhase::Ready {
                        self.status.phase = DaemonPhase::Ready;
                        self.status.last_error = None;
                        publish(&self.paths, &mut self.status)?;
                    }
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    self.status.phase = DaemonPhase::Degraded;
                    self.status.last_error = Some(error.to_string());
                    publish(&self.paths, &mut self.status)?;
                    if consecutive_failures >= 3 {
                        append_log(&self.paths, "Docker health failed three consecutive probes")?;
                    }
                }
            }
        }
    }

    async fn observe_metrics(&mut self, machine: &SystemMachine) -> eyre::Result<()> {
        let Ok(metrics) = machine.metrics().await else {
            return Ok(());
        };
        let mut changed =
            apply_host_memory_reclaim(&mut self.status, metrics.host_memory_reclaim.as_ref());
        let guest_reclaim = metrics
            .metrics
            .as_ref()
            .and_then(|observation| observation.report.snapshot.memory_reclaim.as_ref());
        if let Some(report) = guest_reclaim {
            if apply_guest_memory_reclaim(&mut self.status, report) {
                changed = true;
                append_log(&self.paths, &describe_guest_memory_reclaim(report))?;
            }
        }
        if changed {
            publish(&self.paths, &mut self.status)?;
        }
        Ok(())
    }

    /// Checks the registry and, when the configured image moved, replaces the VM.
    /// Only a failed rollback is fatal; every other failure leaves a working VM.
    async fn update(
        &mut self,
        active: &Active,
        shutdown: &mut Shutdown,
    ) -> eyre::Result<UpdateOutcome> {
        let runtime = connected(&mut self.runtime)?;
        let checked = async {
            let current = runtime.inspect_machine(&active.machine_id).await?;
            crate::upgrade::check(runtime, &self.desired.image, &current).await
        }
        .await;
        self.status.update_checked_at = Some(now());
        let image = match checked {
            Ok(image) => image.filter(|image| !self.rejected.contains(&image.manifest_digest)),
            Err(error) => {
                return self
                    .update_failed(None, "system image update check failed", &error)
                    .map(|()| UpdateOutcome::Unchanged);
            }
        };
        self.status.update_error = None;
        publish(&self.paths, &mut self.status)?;
        let Some(image) = image else {
            return Ok(UpdateOutcome::Unchanged);
        };

        let digest = image.manifest_digest.clone();
        // An upgrade record still present here belongs to an earlier upgrade whose
        // cleanup failed. Finish it first, so a failure below can only ever roll
        // back the upgrade this call starts.
        if let Err(error) = crate::upgrade::finalize(runtime, &self.paths).await {
            return self
                .update_failed(None, "could not finalize the previous upgrade", &error)
                .map(|()| UpdateOutcome::Unchanged);
        }
        append_log(
            &self.paths,
            &format!("qualifying system image {}", image.selected_reference),
        )?;
        let qualified = {
            let qualify =
                crate::upgrade::qualify(runtime, &self.paths, &self.desired, image.clone());
            tokio::pin!(qualify);
            tokio::select! {
                result = &mut qualify => Some(result),
                () = shutdown.recv() => None,
            }
        };
        match qualified {
            None => {
                // Best effort: shutdown must still stop the active VM, and the next
                // start removes whatever is left.
                if let Err(error) =
                    crate::upgrade::remove_abandoned_qualifications(runtime, &self.paths).await
                {
                    append_log(
                        &self.paths,
                        &format!("could not remove the cancelled qualification VM: {error:#}"),
                    )?;
                }
                return Ok(UpdateOutcome::Shutdown);
            }
            Some(Err(error)) => {
                return self
                    .update_failed(Some(digest), "system image qualification failed", &error)
                    .map(|()| UpdateOutcome::Unchanged);
            }
            Some(Ok(())) => {}
        }

        // From here the engine is down until the new or the restored VM is Ready.
        self.status.phase = DaemonPhase::Upgrading;
        publish(&self.paths, &mut self.status)?;
        append_log(
            &self.paths,
            &format!("upgrading the system VM to {}", image.selected_reference),
        )?;
        stop_engine(&active.machine).await;
        if let Err(error) = active.machine.stop().await {
            self.update_failed(
                Some(digest),
                "could not stop the system VM for its upgrade",
                &error.into(),
            )?;
            return Ok(UpdateOutcome::Restart);
        }
        let runtime = connected(&mut self.runtime)?;
        match crate::upgrade::replace(runtime, &self.paths, &self.desired, image).await {
            Ok(()) => {
                append_log(&self.paths, "system VM upgraded; starting it")?;
                Ok(UpdateOutcome::Restart)
            }
            Err(error) => {
                self.update_failed(Some(digest), "system image upgrade failed", &error)?;
                // Nothing to restore when it failed before recording the transaction.
                if DaemonRecord::load(&self.paths)?.is_some_and(|record| record.upgrade.is_some()) {
                    let runtime = connected(&mut self.runtime)?;
                    crate::upgrade::recover(runtime, &self.paths)
                        .await
                        .context("restore the system VM after a failed upgrade")?;
                    append_log(&self.paths, "restored the previous system VM")?;
                }
                Ok(UpdateOutcome::Restart)
            }
        }
    }

    fn update_failed(
        &mut self,
        digest: Option<String>,
        what: &str,
        error: &eyre::Report,
    ) -> eyre::Result<()> {
        if let Some(digest) = digest {
            self.rejected.insert(digest);
        }
        self.status.update_error = Some(format!("{what}: {}", error_summary(&error_causes(error))));
        publish(&self.paths, &mut self.status)?;
        append_log(&self.paths, &format!("{what}: {error:#}"))
    }

    async fn stop(&mut self, active: Active) -> eyre::Result<()> {
        self.status.phase = DaemonPhase::Stopping;
        publish(&self.paths, &mut self.status)?;
        stop_engine(&active.machine).await;
        active.machine.stop().await?;
        self.status.phase = DaemonPhase::Stopped;
        self.status.run_id = None;
        publish(&self.paths, &mut self.status)?;
        append_log(&self.paths, "system daemon stopped")
    }

    /// Stops the VM even when startup never got as far as recording it; otherwise an
    /// interrupted first start leaves it running unattended.
    async fn cancelled(&mut self) -> eyre::Result<()> {
        self.status.phase = DaemonPhase::Stopping;
        publish(&self.paths, &mut self.status)?;
        if let (Some(runtime), Some(record)) =
            (self.runtime.as_mut(), DaemonRecord::load(&self.paths)?)
        {
            let stopped =
                crate::provision::stop_system_machine(runtime, &record, Duration::from_secs(60))
                    .await
                    .context("startup cancellation could not stop the system VM")?;
            self.status.machine_id = stopped;
        }
        self.status.phase = DaemonPhase::Stopped;
        self.status.run_id = None;
        publish(&self.paths, &mut self.status)?;
        append_log(&self.paths, "system daemon cancelled during startup")
    }
}

/// Stops every live VM this installation owns, for a controller that found no
/// daemon left to do it: silod exited without stopping its VM, or was killed.
/// The caller holds the lifetime lock.
pub(crate) async fn stop_installation(
    paths: &SystemPaths,
    mut status: DaemonStatus,
) -> eyre::Result<()> {
    if let Some(record) = DaemonRecord::load(paths)? {
        let config = libvm::RuntimeConfig::local(paths.home())
            .with_virt_backend(record.config.backend.runtime_override());
        let mut runtime = SystemRuntime::connect(config).await?;
        crate::upgrade::remove_abandoned_qualifications(&mut runtime, paths).await?;
        for machine in runtime.list_machines().await? {
            if !crate::provision::is_installation_machine(&machine, record.installation_id)
                || !crate::provision::is_live(&machine)
            {
                continue;
            }
            append_log(paths, &format!("stopping system VM {}", machine.name))?;
            runtime.machine(&machine.id).await?.stop().await?;
        }
    }
    status.phase = DaemonPhase::Stopped;
    publish(paths, &mut status)?;
    append_log(paths, "system VM stopped")
}

fn connected(runtime: &mut Option<SystemRuntime>) -> eyre::Result<&mut SystemRuntime> {
    runtime
        .as_mut()
        .ok_or_else(|| eyre::eyre!("the libvm runtime is not connected"))
}

/// One startup attempt: recover an interrupted upgrade, ensure the VM exists, boot or
/// adopt it, and activate the engine.
async fn attempt(
    runtime: &mut Option<SystemRuntime>,
    runtime_config: &libvm::RuntimeConfig,
    paths: &SystemPaths,
    desired: &DesiredSystem,
    status: &mut DaemonStatus,
) -> eyre::Result<Active> {
    if runtime.is_none() {
        *runtime = Some(SystemRuntime::connect(runtime_config.clone()).await?);
    }
    let runtime = connected(runtime)?;
    crate::upgrade::remove_abandoned_qualifications(runtime, paths).await?;
    if DaemonRecord::load(paths)?
        .and_then(|record| record.upgrade)
        .is_some_and(|upgrade| !upgrade.complete)
    {
        append_log(paths, "recovering an interrupted system image upgrade")?;
        crate::upgrade::recover(runtime, paths).await?;
    }
    status.phase = DaemonPhase::Creating;
    publish(paths, status)?;
    let (record, machine_data) = ensure_system_machine(runtime, paths, desired).await?;
    status.machine_id = Some(machine_data.id.clone());
    status.image_digest = machine_data
        .rootfs
        .as_ref()
        .and_then(|rootfs| rootfs.selected_manifest_digest.clone());
    let machine = runtime.machine(&machine_data.id).await?;
    let run_id = match machine_data.status {
        MachineStatus::Running { .. } | MachineStatus::Starting { .. } => machine_data
            .run_id
            .clone()
            .ok_or_else(|| eyre::eyre!("the running system VM reports no run ID"))?,
        MachineStatus::Stopping { .. } => bail!("recorded system VM is stopping; wait and retry"),
        _ => {
            status.phase = DaemonPhase::StartingVm;
            publish(paths, status)?;
            let options = libvm::MachineStartOptions::new();
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
    activate(
        &machine,
        &desired.config,
        &machine_data.spec,
        record.data_uuid,
    )
    .await?;
    // Activation returns once the guest units are up; the host-side socket forward
    // becomes live shortly after the guest half exists, so poll rather than probe once.
    wait_docker_socket(&desired.config.docker_socket, ENGINE_REACHABLE_TIMEOUT).await?;
    status.phase = DaemonPhase::Ready;
    status.last_error = None;
    publish(paths, status)?;
    append_log(paths, "system Docker engine ready")?;
    Ok(Active {
        machine,
        machine_id: machine_data.id,
    })
}

const fn initial_host_memory_reclaim_effective(requested: bool) -> Option<bool> {
    if requested {
        None
    } else {
        Some(false)
    }
}

fn parse_reclaim_outcome(value: &str) -> Option<MemoryReclaimOutcome> {
    Some(match value {
        "reclaimed" => MemoryReclaimOutcome::Reclaimed,
        "partial" => MemoryReclaimOutcome::Partial,
        "nothing" => MemoryReclaimOutcome::Nothing,
        "failed" => MemoryReclaimOutcome::Failed,
        _ => return None,
    })
}

fn publish(paths: &SystemPaths, status: &mut DaemonStatus) -> eyre::Result<()> {
    status.updated_at = now();
    write_record(&paths.status(), status)
}

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
    status.memory_reclaim_outcome = parse_reclaim_outcome(&report.outcome);
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
fn error_causes(error: &eyre::Report) -> Vec<String> {
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
fn error_summary(causes: &[String]) -> String {
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

pub(crate) fn append_log(paths: &SystemPaths, message: &str) -> eyre::Result<()> {
    let path = paths.log();
    libvm::HostPaths::ensure_log_dir(paths.home(), "daemon")?;
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

pub(crate) fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn process_start_identity() -> eyre::Result<String> {
    #[cfg(target_os = "linux")]
    {
        silod_spec::process::start_time(std::process::id())?
            .ok_or_else(|| eyre::eyre!("missing own process start time"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(format!("pid-{}-{}", std::process::id(), now()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use silod_spec::status::{DaemonStatus, MemoryReclaimOutcome};

    use crate::supervisor::{
        apply_guest_memory_reclaim, describe_guest_memory_reclaim, error_causes, error_summary,
        initial_host_memory_reclaim_effective, startup_retry_delay, LifetimeLock,
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
    fn guest_reclaim_report_is_applied_once_per_run() {
        let mut status: DaemonStatus = serde_json::from_value(serde_json::json!({
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
