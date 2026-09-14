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
    };
    publish(&paths, &mut status)?;
    append_log(&paths, "preparing installation storage")?;

    let startup = {
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
    let Some(startup) = startup else {
        status.phase = DaemonPhase::Stopping;
        publish(&paths, &mut status)?;
        if let Some(record) =
            load_record::<crate::system::record::SystemRecord>(&paths.system_record())?
        {
            status.machine_id = Some(record.active_machine_id.clone());
            let machine = api.inspect_machine(&record.active_machine_id).await?;
            if matches!(
                machine.status,
                MachineStatus::Running { .. }
                    | MachineStatus::Starting { .. }
                    | MachineStatus::Stopping { .. }
            ) {
                if let Err(error) = api
                    .stop_machine(&record.active_machine_id, false, Duration::from_secs(60))
                    .await
                {
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
    let (machine, run_id) = match startup {
        Ok(value) => value,
        Err(error) => {
            status.phase = DaemonPhase::Failed;
            status.last_error = Some(format!("{error:#}"));
            publish(&paths, &mut status)?;
            return Err(error);
        }
    };

    let mut consecutive_failures = 0_u8;
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                break;
            }
            () = tokio::time::sleep(Duration::from_secs(10)) => {
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
    probe_docker_socket(&config.docker_socket)?;
    status.phase = DaemonPhase::Ready;
    publish(paths, status)?;
    append_log(paths, "system Docker engine ready")?;
    Ok((machine, run_id))
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
    use crate::system::supervisor::LifetimeLock;

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
