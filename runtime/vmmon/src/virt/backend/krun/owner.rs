//! The only owner allowed to signal, wait for, or reap a krun worker.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe::{Receiver, Sender};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::krun::worker::protocol::{self, Event, Launch, MAX_EVENT, MAX_REQUEST};
use crate::virt::backend::krun::{host_memory_reclaim_report, inherit};
use crate::virt::backend::HostMemoryReclaimReport;
use crate::virt::exit::{Diagnostic, ForceReason, ProcessExit, StartupStage, VmExit, VmOutcome};

const DIAGNOSTIC_LIMIT: usize = 64 * 1024;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(target_os = "macos")]
const GRACEFUL_TIMEOUT: Duration = Duration::from_secs(30);
const FORCE_OBSERVATION: Duration = Duration::from_secs(5);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Published lifecycle of one worker generation. `Reaped` means the child is
/// gone but the owner is still draining channels; `Exited` is terminal.
#[derive(Clone, Default)]
pub(crate) enum Phase {
    #[default]
    Starting,
    Started,
    Reaped,
    Exited(VmExit),
}

impl Phase {
    pub(crate) fn exit(&self) -> Option<&VmExit> {
        match self {
            Self::Exited(exit) => Some(exit),
            Self::Starting | Self::Started | Self::Reaped => None,
        }
    }
}

pub(crate) struct Owner {
    pub(crate) state: watch::Sender<Phase>,
    pub(crate) stop: CancellationToken,
    pub(crate) force: CancellationToken,
    pub(crate) reclaim: watch::Sender<Option<HostMemoryReclaimReport>>,
}

struct Spawned {
    child: Child,
    request: Sender,
    events: Receiver,
    diagnostics: Receiver,
    _keepalive: OwnedFd,
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = nix::unistd::pipe()?;
    Ok((inherit::normalize(read)?, inherit::normalize(write)?))
}

fn spawn(console: OwnedFd, mux: OwnedFd) -> io::Result<Spawned> {
    let console = inherit::normalize(console)?;
    let mux = inherit::normalize(mux)?;
    let (request, send) = pipe()?;
    let (receive, events) = pipe()?;
    let (diagnostics, output) = pipe()?;
    let (watchdog, keepalive) = pipe()?;
    // Every fallible channel registration precedes spawn. Once spawn succeeds,
    // returning this bundle cannot lose a child through an error path.
    let request_sender = Sender::from_owned_fd(send)?;
    let event_receiver = Receiver::from_owned_fd(receive)?;
    let diagnostic_receiver = Receiver::from_owned_fd(diagnostics)?;
    let mut command = Command::new(std::env::current_exe()?);
    command.arg("worker");
    for (name, fd) in [
        ("--request-fd", &request),
        ("--events-fd", &events),
        ("--watchdog-fd", &watchdog),
        ("--console-fd", &console),
        ("--vsock-mux-fd", &mux),
    ] {
        command.arg(name).arg(fd.as_raw_fd().to_string());
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output));
    command.kill_on_drop(true);
    inherit::install(
        command.as_std_mut(),
        &[&request, &events, &watchdog, &console, &mux],
    );
    let child = command.spawn()?;
    Ok(Spawned {
        child,
        request: request_sender,
        events: event_receiver,
        diagnostics: diagnostic_receiver,
        _keepalive: keepalive,
    })
}

#[derive(Default)]
struct Tail {
    bytes: VecDeque<u8>,
    truncated: bool,
}

impl Tail {
    fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.bytes.len() == DIAGNOSTIC_LIMIT {
                self.bytes.pop_front();
                self.truncated = true;
            }
            self.bytes.push_back(byte);
        }
    }

    fn text(&self) -> String {
        let bytes: Vec<_> = self.bytes.iter().copied().collect();
        let text = String::from_utf8_lossy(&bytes);
        let mut start = text.len().saturating_sub(DIAGNOSTIC_LIMIT);
        while !text.is_char_boundary(start) {
            start += 1;
        }
        text[start..].to_string()
    }
}

async fn collect_diagnostics(mut diagnostics: Receiver, pid: u32, tail: Arc<Mutex<Tail>>) {
    let mut chunk = [0; 4096];
    loop {
        match diagnostics.read(&mut chunk).await {
            Ok(0) => break,
            Ok(count) => {
                tail.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(&chunk[..count]);
                tracing::debug!(worker_pid = pid, diagnostic = %String::from_utf8_lossy(&chunk[..count]), "krun diagnostic");
            }
            Err(error) => {
                tracing::warn!(%error, "krun diagnostics closed");
                break;
            }
        }
    }
}

async fn read_event(events: &mut Receiver) -> io::Result<Event> {
    let mut header = [0; 4];
    events.read_exact(&mut header).await?;
    let mut payload = vec![0; protocol::frame_length(header, MAX_EVENT)?];
    events.read_exact(&mut payload).await?;
    protocol::decode(&payload)
}

fn force(
    child: &mut Child,
    reason: ForceReason,
    issued: &mut Option<ForceReason>,
) -> io::Result<()> {
    // Child remains owned and unreaped, so its PID cannot be reused here.
    if child.try_wait()?.is_none() {
        child.start_kill()?;
        *issued = Some(reason);
    }
    Ok(())
}

impl Owner {
    pub(crate) async fn run(
        &self,
        config: crate::krun::KrunConfig,
        console: OwnedFd,
        mux: OwnedFd,
    ) -> VmExit {
        if self.stop.is_cancelled() || self.force.is_cancelled() {
            return VmExit::stopped(StartupStage::Spawned);
        }
        let frame = match Launch::from_config(config)
            .and_then(|launch| protocol::encode(&launch, MAX_REQUEST))
        {
            Ok(frame) => frame,
            Err(error) => return VmExit::failed(StartupStage::Spawned, error.to_string()),
        };
        let Spawned {
            mut child,
            mut request,
            mut events,
            diagnostics,
            _keepalive,
        } = match spawn(console, mux) {
            Ok(spawned) => spawned,
            Err(error) => {
                return VmExit::failed(StartupStage::Spawned, format!("spawn krun worker: {error}"))
            }
        };
        let pid = child.id().unwrap_or_default();
        tracing::info!(worker_pid = pid, "krun worker spawned");
        let tail = Arc::new(Mutex::new(Tail::default()));
        let mut diagnostic_task = tokio::spawn(collect_diagnostics(diagnostics, pid, tail.clone()));
        let mut transmission = tokio::spawn(async move { request.write_all(&frame).await });
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let event_task = tokio::spawn(async move {
            loop {
                let event = read_event(&mut events).await;
                let failed = event.is_err();
                if event_tx.send(event).await.is_err() || failed {
                    return;
                }
            }
        });
        let mut stage = StartupStage::Spawned;
        let mut started = false;
        let mut stopping = false;
        let mut transmitted = false;
        let mut events_open = true;
        let mut failure = None;
        let mut forced = None;
        let mut force_observed = false;
        let mut escalated = false;
        let mut shutdown_requested = false;
        let startup_deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        let mut stop_deadline = startup_deadline;
        let status = loop {
            tokio::select! {
                biased;
                status = child.wait() => match status {
                    Ok(status) => break status,
                    Err(error) => {
                        // No synthesized exit: retain child ownership until wait succeeds.
                        tracing::error!(%error, worker_pid = pid, "krun wait failed; retaining owner");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                },
                _ = self.force.cancelled(), if !escalated => {
                    escalated = true;
                    shutdown_requested = true;
                    stopping = true;
                    if let Err(error) = force(&mut child, ForceReason::Escalated, &mut forced) {
                        failure.get_or_insert_with(|| format!("force worker: {error}"));
                    }
                    stop_deadline = tokio::time::Instant::now() + FORCE_OBSERVATION;
                }
                _ = self.stop.cancelled(), if !stopping => {
                    shutdown_requested = true;
                    stopping = true;
                    #[cfg(target_os = "macos")]
                    if started {
                        let result = i32::try_from(pid).map_err(io::Error::other).and_then(|pid| {
                            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGTERM).map_err(io::Error::from)
                        });
                        if let Err(error) = result { failure.get_or_insert_with(|| format!("request worker shutdown: {error}")); }
                        stop_deadline = tokio::time::Instant::now() + GRACEFUL_TIMEOUT;
                    }
                    if !started || cfg!(target_os = "linux") {
                        let reason = if started { ForceReason::Stop } else { ForceReason::Cancelled };
                        if let Err(error) = force(&mut child, reason, &mut forced) { failure.get_or_insert_with(|| format!("stop worker: {error}")); }
                        stop_deadline = tokio::time::Instant::now() + FORCE_OBSERVATION;
                    }
                }
                event = event_rx.recv(), if events_open && !stopping => {
                    let error = match event {
                        Some(Ok(Event::StartupStage { stage: next })) if valid_stage(stage, next) && !started => { stage = next; None }
                        Some(Ok(Event::BackendStarted {})) if stage == StartupStage::Build && !started => {
                            started = true; stage = StartupStage::Started;
                            self.state.send_replace(Phase::Started); None
                        }
                        Some(Ok(Event::StartupFailed { stage: observed, diagnostic })) if observed == stage => Some(diagnostic),
                        Some(Ok(Event::HostMemoryReclaim { status })) if stage == StartupStage::Build || started => {
                            self.reclaim.send_replace(Some(host_memory_reclaim_report(status))); None
                        }
                        Some(Ok(_)) => Some("invalid worker event ordering".to_string()),
                        Some(Err(error)) => {
                            events_open = false;
                            if started && error.kind() == io::ErrorKind::UnexpectedEof {
                                None
                            } else { Some(format!("worker event channel: {error}")) }
                        }
                        None => { events_open = false; if started { None } else { Some("worker event reader closed".to_string()) } }
                    };
                    if let Some(error) = error {
                        failure.get_or_insert(error);
                        stopping = true;
                        let reason = if started { ForceReason::ProtocolFailure } else { ForceReason::StartupFailure };
                        if let Err(error) = force(&mut child, reason, &mut forced) { tracing::warn!(%error, "failed to terminate failed worker"); }
                        stop_deadline = tokio::time::Instant::now() + FORCE_OBSERVATION;
                    }
                }
                result = &mut transmission, if !transmitted => {
                    transmitted = true;
                    if !matches!(result, Ok(Ok(()))) {
                        failure.get_or_insert_with(|| "worker launch transmission failed".to_string());
                        stopping = true;
                        let _ = force(&mut child, ForceReason::StartupFailure, &mut forced);
                        stop_deadline = tokio::time::Instant::now() + FORCE_OBSERVATION;
                    }
                }
                _ = tokio::time::sleep_until(startup_deadline), if !started && !stopping => {
                    failure.get_or_insert_with(|| "worker startup timed out".to_string());
                    stopping = true;
                    let _ = force(&mut child, ForceReason::StartupFailure, &mut forced);
                    stop_deadline = tokio::time::Instant::now() + FORCE_OBSERVATION;
                }
                _ = tokio::time::sleep_until(stop_deadline), if stopping && !force_observed => {
                    if forced.is_none() {
                        let _ = force(&mut child, ForceReason::GracefulTimeout, &mut forced);
                        stop_deadline = tokio::time::Instant::now() + FORCE_OBSERVATION;
                    } else {
                        force_observed = true;
                        tracing::error!(worker_pid = pid, "worker has not exited after SIGKILL; retaining reap owner");
                    }
                }
            }
        };
        self.state.send_replace(Phase::Reaped);
        if !transmitted {
            transmission.abort();
            let _ = transmission.await;
        }
        // Exit can win the select before buffered failure/stage frames. Preserve
        // these reports without publishing a late readiness acknowledgement.
        let drain_deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        let _ = tokio::time::timeout_at(drain_deadline, async {
            while let Some(event) = event_rx.recv().await {
                match event {
                    Ok(Event::StartupStage { stage: next }) if valid_stage(stage, next) => {
                        stage = next
                    }
                    Ok(Event::BackendStarted {}) if stage == StartupStage::Build => {
                        stage = StartupStage::Started;
                        started = true;
                    }
                    Ok(Event::StartupFailed { diagnostic, .. }) => {
                        failure.get_or_insert(diagnostic);
                    }
                    Err(_) => break,
                    _ => {}
                }
            }
        })
        .await;
        event_task.abort();
        let _ = event_task.await;
        if tokio::time::timeout_at(drain_deadline, &mut diagnostic_task)
            .await
            .is_err()
        {
            diagnostic_task.abort();
            let _ = diagnostic_task.await;
        }
        if !started && !shutdown_requested {
            failure
                .get_or_insert_with(|| "worker exited before startup acknowledgement".to_string());
        }
        let tail = tail.lock().unwrap_or_else(PoisonError::into_inner);
        let process = ProcessExit {
            pid,
            raw_status: status.into_raw(),
            code: status.code(),
            signal: status.signal(),
            core_dumped: status.core_dumped(),
        };
        let diagnostic = (!tail.bytes.is_empty()).then(|| Diagnostic {
            tail: tail.text(),
            truncated: tail.truncated,
        });
        VmExit {
            outcome: worker_outcome(failure, forced, &process),
            stage,
            force_reason: forced,
            process: Some(process),
            diagnostic,
        }
    }
}

/// A requested force only counts when SIGKILL is what the reaper observed;
/// any other signal or a non-zero code is a crash even during shutdown.
fn worker_outcome(
    failure: Option<String>,
    forced: Option<ForceReason>,
    process: &ProcessExit,
) -> VmOutcome {
    if let Some(failure) = failure {
        return VmOutcome::Failed(failure);
    }
    if forced.is_some() && process.signal == Some(nix::libc::SIGKILL) {
        return VmOutcome::Forced;
    }
    match (process.code, process.signal) {
        (Some(0), _) => VmOutcome::Clean,
        (Some(code), _) => VmOutcome::Failed(format!("krun exited with status code {code}")),
        (_, Some(signal)) => VmOutcome::Failed(format!("krun exited after signal {signal}")),
        _ => VmOutcome::Failed(format!(
            "krun exited with unknown status {}",
            process.raw_status
        )),
    }
}

fn valid_stage(current: StartupStage, next: StartupStage) -> bool {
    matches!(
        (current, next),
        (StartupStage::Spawned, StartupStage::Request)
            | (StartupStage::Request, StartupStage::Admission)
            | (StartupStage::Admission, StartupStage::Build)
    )
}

#[cfg(test)]
mod tests {
    use crate::virt::backend::krun::owner::{valid_stage, worker_outcome, Tail, DIAGNOSTIC_LIMIT};
    use crate::virt::exit::{ForceReason, ProcessExit, StartupStage, VmOutcome};

    fn process(code: Option<i32>, signal: Option<i32>) -> ProcessExit {
        ProcessExit {
            pid: 123,
            raw_status: 0,
            code,
            signal,
            core_dumped: false,
        }
    }

    #[test]
    fn shutdown_intent_does_not_hide_crashes_or_nonzero_exits() {
        for signal in [nix::libc::SIGSEGV, nix::libc::SIGTERM, nix::libc::SIGKILL] {
            assert!(matches!(
                worker_outcome(None, None, &process(None, Some(signal))),
                VmOutcome::Failed(_)
            ));
        }
        assert!(matches!(
            worker_outcome(None, Some(ForceReason::Stop), &process(Some(127), None)),
            VmOutcome::Failed(_)
        ));
        assert!(matches!(
            worker_outcome(
                None,
                Some(ForceReason::Stop),
                &process(None, Some(nix::libc::SIGSEGV))
            ),
            VmOutcome::Failed(_)
        ));
        assert_eq!(
            worker_outcome(None, None, &process(Some(0), None)),
            VmOutcome::Clean
        );
    }

    #[test]
    fn force_requires_observed_sigkill_and_preserves_primary_startup_error() {
        let killed = process(None, Some(nix::libc::SIGKILL));
        assert_eq!(
            worker_outcome(None, Some(ForceReason::StartupFailure), &killed),
            VmOutcome::Forced
        );
        assert_eq!(
            worker_outcome(
                Some("host admission failed".to_string()),
                Some(ForceReason::StartupFailure),
                &killed
            ),
            VmOutcome::Failed("host admission failed".to_string())
        );
    }

    #[test]
    fn diagnostic_tail_is_bounded_for_binary_unterminated_output() {
        let mut tail = Tail::default();
        tail.push(&vec![0xff; DIAGNOSTIC_LIMIT * 2]);
        assert!(tail.truncated);
        assert_eq!(tail.bytes.len(), DIAGNOSTIC_LIMIT);
        assert!(tail.text().len() <= DIAGNOSTIC_LIMIT);
    }
    /// Generic child output collection through the production pipe reader.
    #[tokio::test]
    async fn real_child_can_fill_many_pipe_capacities_without_a_newline() {
        use crate::virt::backend::krun::owner::{collect_diagnostics, pipe};
        use std::process::Stdio;
        use std::sync::{Arc, Mutex};
        let (read, write) = pipe().expect("diagnostic pipe");
        let reader = tokio::net::unix::pipe::Receiver::from_owned_fd(read).expect("async reader");
        let tail = Arc::new(Mutex::new(Tail::default()));
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "i=0; while [ $i -lt 4096 ]; do printf '%0256d' 0; i=$((i+1)); done; printf diagnostic-tail"])
            .stdout(Stdio::from(write)).stderr(Stdio::null()).kill_on_drop(true).spawn().expect("real child");
        let pid = child.id().expect("child PID");
        let (status, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(child.wait(), collect_diagnostics(reader, pid, tail.clone()))
        })
        .await
        .expect("diagnostics do not block child exit");
        assert!(status.expect("reap child").success());
        let tail = tail.lock().expect("tail");
        assert!(tail.truncated);
        assert_eq!(tail.bytes.len(), DIAGNOSTIC_LIMIT);
        assert!(tail.text().ends_with("diagnostic-tail"));
    }

    #[test]
    fn startup_stages_cannot_repeat_skip_or_regress() {
        assert!(valid_stage(StartupStage::Request, StartupStage::Admission));
        assert!(!valid_stage(StartupStage::Spawned, StartupStage::Build));
        assert!(!valid_stage(StartupStage::Build, StartupStage::Build));
        assert!(!valid_stage(StartupStage::Started, StartupStage::Request));
    }
}
