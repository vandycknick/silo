//! Monitor-side client of one worker generation's lifecycle socket.
//!
//! The client allocates checked transport sequences, joins identical retries
//! of a [`CommandKey`] and retains every command result for the backend's
//! lifetime. A dropped caller never cancels accepted worker work: results keep
//! arriving into the journal and a retry or `GetControl` observes them.
//!
//! Rights-bearing commands carry owned descriptor duplicates. The queued frame
//! owns them until its first byte is sent with them, then closes them; a
//! joined replay checks and closes its duplicates before it waits.
//!
//! Stop linearizes with mutator submission through [`LifecycleSlot`]: the
//! fence and every enqueue take the client's state lock, so a mutator is
//! either admitted before the fence or refused `Stopping` without effect.

use std::collections::HashMap;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, watch};

use crate::krun::worker::lifecycle::Binding;
use crate::krun::worker::lifecycle_wire::{
    self, FrameBuffer, ParentFrame, WorkerFrame, PROTOCOL_VERSION,
};
use crate::virt::lifecycle::{
    CommandKey, CommandReport, CommandSequence, CommandState, ControlObservation, InvalidRequest,
    LifecycleCommand, LifecycleError, LifecycleRejection, LifecycleRequest, LifecycleResponse,
    LifecycleRights, LifecycleUncertainty, RightsKind,
};

/// Waiting for the worker's Hello before the first command.
const HELLO_WAIT: Duration = Duration::from_secs(10);
/// A mutator report is awaited until its deadline plus this grace.
const REPORT_GRACE: Duration = Duration::from_secs(5);
const CONTROL_WAIT: Duration = Duration::from_secs(10);
/// An accepted replay observes retained progress without renewing native work.
const REPLAY_OBSERVATION_WAIT: Duration = Duration::from_secs(1);
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Loss of the lifecycle endpoint, delivered once to the worker's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleFault {
    /// The endpoint violated the protocol: the worker must be terminated.
    Protocol(String),
    /// The endpoint closed; normal only while the worker is exiting.
    Closed,
}

#[derive(Clone)]
pub(crate) struct LifecycleClient {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for LifecycleClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleClient").finish_non_exhaustive()
    }
}

type ReportSlot = Option<Result<(CommandReport, ControlObservation), LifecycleError>>;

struct Shared {
    binding: Binding,
    state: Mutex<State>,
    hello: watch::Sender<Hello>,
    frames: mpsc::UnboundedSender<Outbound>,
    faults: mpsc::Sender<LifecycleFault>,
}

/// One encoded frame and the descriptors riding its first byte.
struct Outbound {
    bytes: Vec<u8>,
    rights: Vec<OwnedFd>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hello {
    Waiting,
    Ready,
    Lost,
}

#[derive(Default)]
struct State {
    last_sequence: u64,
    keys: HashMap<CommandKey, Entry>,
    pending: HashMap<CommandSequence, Pending>,
    lost: Option<LifecycleUncertainty>,
    admission_closed: bool,
}

struct Entry {
    command: LifecycleCommand,
    wait_until: Instant,
    report: watch::Sender<ReportSlot>,
}

enum Pending {
    Mutator(CommandKey),
    Control(oneshot::Sender<Result<LifecycleResponse, LifecycleError>>),
}

/// A backend's lifecycle client and its permanent submission fence. Closing
/// and installation share one lock, so a client installed after stop began
/// never admits a mutator either.
#[derive(Debug, Default)]
pub(crate) struct LifecycleSlot {
    state: Mutex<Slot>,
}

#[derive(Debug, Default)]
struct Slot {
    client: Option<LifecycleClient>,
    closed: bool,
}

impl LifecycleSlot {
    fn slot(&self) -> MutexGuard<'_, Slot> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn install(&self, client: LifecycleClient) {
        let mut slot = self.slot();
        if slot.closed {
            client.close_admission();
        }
        slot.client = Some(client);
    }

    pub(crate) fn client(&self) -> Option<LifecycleClient> {
        self.slot().client.clone()
    }

    /// Close mutator submission for good; observation and joins of commands
    /// admitted earlier stay available. Synchronous: it returns only after
    /// any concurrent enqueue has either finished or been refused.
    pub(crate) fn close_admission(&self) {
        let mut slot = self.slot();
        slot.closed = true;
        if let Some(client) = &slot.client {
            client.close_admission();
        }
    }

    pub(crate) fn closed(&self) -> bool {
        self.slot().closed
    }
}

fn lock(mutex: &Mutex<State>) -> MutexGuard<'_, State> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl LifecycleClient {
    /// Own the parent endpoint. Must run inside a Tokio runtime.
    pub(crate) fn start(
        endpoint: OwnedFd,
        binding: Binding,
    ) -> std::io::Result<(Self, mpsc::Receiver<LifecycleFault>)> {
        let stream = std::os::unix::net::UnixStream::from(endpoint);
        stream.set_nonblocking(true)?;
        let (read, mut write) = UnixStream::from_std(stream)?.into_split();
        let (frames, mut outbound) = mpsc::unbounded_channel::<Outbound>();
        let (faults, fault_receiver) = mpsc::channel(2);
        let shared = Arc::new(Shared {
            binding,
            state: Mutex::new(State::default()),
            hello: watch::Sender::new(Hello::Waiting),
            frames,
            faults,
        });
        let writer = shared.clone();
        tokio::spawn(async move {
            while let Some(frame) = outbound.recv().await {
                let result = send_frame(&mut write, frame).await;
                if let Err(error) = result {
                    writer.lose(
                        LifecycleUncertainty::Transport(error.to_string()),
                        LifecycleFault::Protocol(format!("lifecycle write failed: {error}")),
                    );
                    return;
                }
            }
        });
        let reader = shared.clone();
        tokio::spawn(async move {
            let (uncertainty, fault) = match reader.read_loop(read).await {
                Ok(()) => (LifecycleUncertainty::WorkerLost, LifecycleFault::Closed),
                Err(error) => (
                    LifecycleUncertainty::Protocol(error.to_string()),
                    LifecycleFault::Protocol(error.to_string()),
                ),
            };
            reader.lose(uncertainty, fault);
        });
        Ok((Self { shared }, fault_receiver))
    }

    /// Stop admitting new mutators; observation and joins stay available.
    /// Only [`LifecycleSlot`] closes, so its fence also covers late installs.
    fn close_admission(&self) {
        lock(&self.shared.state).admission_closed = true;
    }

    pub(crate) async fn lifecycle(
        &self,
        request: LifecycleRequest,
        rights: LifecycleRights,
    ) -> Result<LifecycleResponse, LifecycleError> {
        request.validate().map_err(LifecycleError::Rejected)?;
        if request.machine_id != self.shared.binding.machine_id
            || request.run_id != self.shared.binding.run_id
        {
            return Err(LifecycleError::Rejected(LifecycleRejection::WrongRun));
        }
        // Supplied rights must be exactly the command's set with the declared
        // identities. Absent rights are legal only for a joining replay.
        if rights.kind() != RightsKind::None {
            rights
                .check(&request.command)
                .map_err(LifecycleError::Rejected)?;
        }
        match request.command.kind() {
            Some(kind) => {
                let key = CommandKey {
                    request_id: request.request_id,
                    kind,
                };
                self.mutate(key, request.request_id, request.command, rights)
                    .await
            }
            None => self.observe(request.request_id, request.command).await,
        }
    }

    async fn mutate(
        &self,
        key: CommandKey,
        request_id: uuid::Uuid,
        command: LifecycleCommand,
        rights: LifecycleRights,
    ) -> Result<LifecycleResponse, LifecycleError> {
        let (mut report, wait_until) = match self.join(key, &command)? {
            Some(joined) => {
                // A joined replay never resends: its identity-checked
                // duplicates close now, not when this wait ends.
                drop(rights);
                joined
            }
            None => {
                self.ready().await?;
                match self.join(key, &command)? {
                    Some(joined) => {
                        drop(rights);
                        joined
                    }
                    None => self.submit(key, request_id, command, rights)?,
                }
            }
        };
        let deadline = tokio::time::Instant::from_std(wait_until);
        loop {
            let current = report.borrow_and_update().clone();
            match current {
                Some(Ok((report, control)))
                    if matches!(report.state, CommandState::Completed { .. }) =>
                {
                    return Ok(LifecycleResponse {
                        control,
                        command: Some(report),
                        inventory: None,
                        capture: None,
                    })
                }
                Some(Err(error)) => return Err(error),
                _ => {}
            }
            tokio::select! {
                changed = report.changed() => {
                    if changed.is_err() {
                        return Err(LifecycleError::Unknown(LifecycleUncertainty::WorkerLost));
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return match report.borrow().clone() {
                        Some(Ok((report, control))) => Ok(LifecycleResponse {
                            control,
                            command: Some(report),
                            inventory: None,
                            capture: None,
                        }),
                        Some(Err(error)) => Err(error),
                        None => Err(LifecycleError::Unknown(LifecycleUncertainty::Transport(
                            "worker did not acknowledge the command".to_string(),
                        ))),
                    };
                }
            }
        }
    }

    /// Replay precedes every current-state check: identical inputs join.
    fn join(
        &self,
        key: CommandKey,
        command: &LifecycleCommand,
    ) -> Result<Option<(watch::Receiver<ReportSlot>, Instant)>, LifecycleError> {
        let state = lock(&self.shared.state);
        match state.keys.get(&key) {
            Some(entry) if &entry.command == command => {
                let now = Instant::now();
                let wait_until = if entry.wait_until <= now
                    && matches!(&*entry.report.borrow(), Some(Ok((report, _))) if matches!(report.state, CommandState::Accepted))
                {
                    now + REPLAY_OBSERVATION_WAIT
                } else {
                    entry.wait_until
                };
                Ok(Some((entry.report.subscribe(), wait_until)))
            }
            Some(_) => Err(LifecycleError::Rejected(
                LifecycleRejection::RequestConflict,
            )),
            None => Ok(None),
        }
    }

    fn submit(
        &self,
        key: CommandKey,
        request_id: uuid::Uuid,
        command: LifecycleCommand,
        rights: LifecycleRights,
    ) -> Result<(watch::Receiver<ReportSlot>, Instant), LifecycleError> {
        if rights.kind() != command.rights() {
            return Err(LifecycleError::Rejected(
                LifecycleRejection::InvalidRequest(InvalidRequest::CaptureRights),
            ));
        }
        let mut state = lock(&self.shared.state);
        if state.lost.is_some() || state.admission_closed {
            return Err(LifecycleError::Rejected(LifecycleRejection::Stopping));
        }
        let sequence = next_sequence(&mut state)?;
        let frame = ParentFrame::Command {
            sequence,
            request_id,
            command,
        };
        let bytes = lifecycle_wire::encode(&frame).map_err(|error| {
            LifecycleError::Unknown(LifecycleUncertainty::Protocol(error.to_string()))
        })?;
        let ParentFrame::Command { command, .. } = frame;
        // Sequence allocation and enqueue share one critical section, so frames
        // reach the worker in strictly increasing order.
        let outbound = Outbound {
            bytes,
            rights: rights.into_descriptors(),
        };
        if self.shared.frames.send(outbound).is_err() {
            return Err(LifecycleError::Rejected(LifecycleRejection::Stopping));
        }
        let timeout = command.timeout().unwrap_or_default();
        let wait_until = Instant::now() + timeout + REPORT_GRACE;
        let (report, receiver) = watch::channel(None);
        state.keys.insert(
            key,
            Entry {
                command,
                wait_until,
                report,
            },
        );
        state.pending.insert(sequence, Pending::Mutator(key));
        Ok((receiver, wait_until))
    }

    async fn observe(
        &self,
        request_id: uuid::Uuid,
        command: LifecycleCommand,
    ) -> Result<LifecycleResponse, LifecycleError> {
        self.ready().await?;
        let (sequence, receiver) = {
            let mut state = lock(&self.shared.state);
            if let Some(lost) = &state.lost {
                return Err(LifecycleError::Unknown(lost.clone()));
            }
            let sequence = next_sequence(&mut state)?;
            let bytes = lifecycle_wire::encode(&ParentFrame::Command {
                sequence,
                request_id,
                command,
            })
            .map_err(|error| {
                LifecycleError::Unknown(LifecycleUncertainty::Protocol(error.to_string()))
            })?;
            let outbound = Outbound {
                bytes,
                rights: Vec::new(),
            };
            if self.shared.frames.send(outbound).is_err() {
                return Err(LifecycleError::Unknown(LifecycleUncertainty::WorkerLost));
            }
            let (sender, receiver) = oneshot::channel();
            state.pending.insert(sequence, Pending::Control(sender));
            (sequence, receiver)
        };
        match tokio::time::timeout(CONTROL_WAIT, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(LifecycleError::Unknown(LifecycleUncertainty::WorkerLost)),
            Err(_) => {
                lock(&self.shared.state).pending.remove(&sequence);
                Err(LifecycleError::Unknown(LifecycleUncertainty::Transport(
                    "worker control observation timed out".to_string(),
                )))
            }
        }
    }

    async fn ready(&self) -> Result<(), LifecycleError> {
        let mut hello = self.shared.hello.subscribe();
        let waited =
            tokio::time::timeout(HELLO_WAIT, hello.wait_for(|state| *state != Hello::Waiting))
                .await;
        match waited {
            Ok(Ok(state)) if *state == Hello::Ready => Ok(()),
            Ok(_) => Err(LifecycleError::Rejected(LifecycleRejection::Stopping)),
            Err(_) => Err(LifecycleError::Rejected(LifecycleRejection::NotReady)),
        }
    }
}

/// Connected lifecycle pair: the parent end is nonblocking for the async
/// client; the child end stays blocking for the worker's reader thread. Both
/// are CLOEXEC, so only an explicit child mapping inherits the child end.
pub(crate) fn lifecycle_pair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    #[cfg(target_os = "linux")]
    let flags = SockFlag::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = SockFlag::empty();
    let (parent, child) = socketpair(AddressFamily::Unix, SockType::Stream, None, flags)?;
    for fd in [&parent, &child] {
        let descriptor = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
        fcntl(fd, FcntlArg::F_SETFD(descriptor | FdFlag::FD_CLOEXEC))?;
    }
    let status = OFlag::from_bits_retain(fcntl(&parent, FcntlArg::F_GETFL)?);
    fcntl(&parent, FcntlArg::F_SETFL(status | OFlag::O_NONBLOCK))?;
    Ok((parent, child))
}

/// The exact canonical launch identity the worker's Hello must repeat.
pub(crate) fn launch_binding(
    config: &crate::virt::config::VmConfig,
) -> Option<std::io::Result<Binding>> {
    let launch = config.storage_launch()?;
    let parse = |value: &str| {
        uuid::Uuid::parse_str(value)
            .ok()
            .filter(|id| !id.is_nil() && id.hyphenated().to_string() == value)
            .ok_or_else(|| protocol("launch identity is not a canonical UUID"))
    };
    Some(
        parse(&launch.machine_id).and_then(|machine_id| {
            parse(&launch.run_id).map(|run_id| Binding { machine_id, run_id })
        }),
    )
}

fn next_sequence(state: &mut State) -> Result<CommandSequence, LifecycleError> {
    let sequence = state
        .last_sequence
        .checked_add(1)
        .and_then(CommandSequence::new)
        .ok_or(LifecycleError::Rejected(LifecycleRejection::Busy))?;
    state.last_sequence = sequence.get();
    Ok(sequence)
}

fn protocol(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Write one frame. Rights ride only its first byte; once that byte is sent
/// the worker owns its received copies and ours close.
async fn send_frame(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    outbound: Outbound,
) -> std::io::Result<()> {
    let Outbound { bytes, rights } = outbound;
    let mut sent = 0;
    if !rights.is_empty() {
        let first = *bytes
            .first()
            .ok_or_else(|| protocol("empty lifecycle frame"))?;
        let stream: &UnixStream = write.as_ref();
        while sent == 0 {
            stream.writable().await?;
            match stream.try_io(Interest::WRITABLE, || {
                lifecycle_wire::send_first_with_rights(stream.as_fd(), first, &rights)
            }) {
                Ok(count) => sent = count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
    }
    drop(rights);
    write.write_all(&bytes[sent..]).await
}

impl Shared {
    async fn read_loop(&self, read: tokio::net::unix::OwnedReadHalf) -> std::io::Result<()> {
        let stream: &UnixStream = read.as_ref();
        let mut buffer = FrameBuffer::default();
        let mut chunk = [0_u8; 4096];
        let mut partial_deadline: Option<tokio::time::Instant> = None;
        loop {
            let readable = match partial_deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, stream.readable())
                    .await
                    .map_err(|_| protocol("unfinished lifecycle frame timed out"))?,
                None => stream.readable().await,
            };
            readable?;
            let count = match stream.try_io(Interest::READABLE, || {
                lifecycle_wire::recv_without_rights(stream.as_fd(), &mut chunk)
            }) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            };
            if count == 0 {
                return if buffer.partial() {
                    Err(protocol("lifecycle endpoint closed inside a frame"))
                } else {
                    Ok(())
                };
            }
            buffer.extend(&chunk[..count])?;
            while let Some(frame) = buffer.next::<WorkerFrame>()? {
                self.handle(frame)?;
            }
            partial_deadline = match (buffer.partial(), partial_deadline) {
                (true, Some(deadline)) => Some(deadline),
                (true, None) => Some(tokio::time::Instant::now() + FRAME_TIMEOUT),
                (false, _) => None,
            };
        }
    }

    fn handle(&self, frame: WorkerFrame) -> std::io::Result<()> {
        if let WorkerFrame::Hello {
            version,
            machine_id,
            run_id,
        } = frame
        {
            if *self.hello.borrow() != Hello::Waiting {
                return Err(protocol("duplicate lifecycle hello"));
            }
            if version != PROTOCOL_VERSION
                || machine_id != self.binding.machine_id
                || run_id != self.binding.run_id
            {
                return Err(protocol("lifecycle hello does not match this run"));
            }
            self.hello.send_replace(Hello::Ready);
            return Ok(());
        }
        if *self.hello.borrow() != Hello::Ready {
            return Err(protocol("lifecycle frame before hello"));
        }
        let mut state = lock(&self.state);
        match frame {
            WorkerFrame::Hello { .. } => Err(protocol("duplicate lifecycle hello")),
            WorkerFrame::Report { report, control } => {
                if !matches!(state.pending.get(&report.sequence), Some(Pending::Mutator(key)) if *key == report.key)
                {
                    return Err(protocol("lifecycle report for an unknown command"));
                }
                record(&state, report, control)
            }
            WorkerFrame::Rejected {
                sequence,
                rejection,
                control: _,
            } => match state.pending.remove(&sequence) {
                Some(Pending::Mutator(key)) => {
                    state.pending.insert(sequence, Pending::Mutator(key));
                    let entry = state
                        .keys
                        .get(&key)
                        .ok_or_else(|| protocol("lifecycle rejection without a command"))?;
                    if entry.report.borrow().is_some() {
                        return Err(protocol("lifecycle rejection after admission"));
                    }
                    entry
                        .report
                        .send_replace(Some(Err(LifecycleError::Rejected(rejection))));
                    Ok(())
                }
                Some(Pending::Control(sender)) => {
                    let _ = sender.send(Err(LifecycleError::Rejected(rejection)));
                    Ok(())
                }
                // A timed-out observation was abandoned; its late answer is dropped.
                None if sequence.get() <= state.last_sequence => Ok(()),
                None => Err(protocol("lifecycle rejection for an unknown sequence")),
            },
            WorkerFrame::Control {
                sequence,
                target,
                control,
                inventory,
            } => {
                if let Some(report) = &target {
                    if !matches!(state.pending.get(&report.sequence), Some(Pending::Mutator(key)) if *key == report.key)
                    {
                        return Err(protocol("lifecycle observation of an unknown command"));
                    }
                    record(&state, report.clone(), control.clone())?;
                }
                match state.pending.remove(&sequence) {
                    Some(Pending::Control(sender)) => {
                        let _ = sender.send(Ok(LifecycleResponse {
                            control,
                            command: target,
                            inventory: Some(inventory),
                            capture: None,
                        }));
                        Ok(())
                    }
                    Some(pending @ Pending::Mutator(_)) => {
                        state.pending.insert(sequence, pending);
                        Err(protocol("lifecycle observation answered a mutator"))
                    }
                    None if sequence.get() <= state.last_sequence => Ok(()),
                    None => Err(protocol("lifecycle observation for an unknown sequence")),
                }
            }
            WorkerFrame::Capture {
                sequence,
                capture,
                control,
            } => match state.pending.remove(&sequence) {
                Some(Pending::Control(sender)) => {
                    let _ = sender.send(Ok(LifecycleResponse {
                        control,
                        command: None,
                        inventory: None,
                        capture: Some(capture),
                    }));
                    Ok(())
                }
                Some(pending @ Pending::Mutator(_)) => {
                    state.pending.insert(sequence, pending);
                    Err(protocol("lifecycle capture observation answered a mutator"))
                }
                None if sequence.get() <= state.last_sequence => Ok(()),
                None => Err(protocol(
                    "lifecycle capture observation for an unknown sequence",
                )),
            },
        }
    }

    /// Terminal loss: every unfinished wait resolves with the uncertainty.
    fn lose(&self, uncertainty: LifecycleUncertainty, fault: LifecycleFault) {
        let mut state = lock(&self.state);
        if state.lost.is_some() {
            return;
        }
        state.lost = Some(uncertainty.clone());
        for entry in state.keys.values() {
            let terminal = matches!(
                &*entry.report.borrow(),
                Some(Err(_))
                    | Some(Ok((
                        CommandReport {
                            state: CommandState::Completed { .. },
                            ..
                        },
                        _
                    )))
            );
            if !terminal {
                entry
                    .report
                    .send_replace(Some(Err(LifecycleError::Unknown(uncertainty.clone()))));
            }
        }
        let pending = std::mem::take(&mut state.pending);
        for (sequence, pending) in pending {
            match pending {
                Pending::Control(sender) => {
                    let _ = sender.send(Err(LifecycleError::Unknown(uncertainty.clone())));
                }
                mutator @ Pending::Mutator(_) => {
                    state.pending.insert(sequence, mutator);
                }
            }
        }
        drop(state);
        self.hello.send_replace(Hello::Lost);
        let _ = self.faults.try_send(fault);
    }
}

/// A completed outcome is immutable; a late `Accepted` never regresses it.
fn record(
    state: &State,
    report: CommandReport,
    control: ControlObservation,
) -> std::io::Result<()> {
    let entry = state
        .keys
        .get(&report.key)
        .ok_or_else(|| protocol("lifecycle report without a command"))?;
    let previous = entry.report.borrow().clone();
    match (&previous, &report.state) {
        (Some(Err(_)), _) => Err(protocol("lifecycle report after a rejection")),
        (
            Some(Ok((
                CommandReport {
                    state: CommandState::Completed { outcome: before },
                    ..
                },
                _,
            ))),
            CommandState::Completed { outcome },
        ) => {
            if before == outcome {
                Ok(())
            } else {
                Err(protocol("lifecycle outcome changed after completion"))
            }
        }
        (
            Some(Ok((
                CommandReport {
                    state: CommandState::Completed { .. },
                    ..
                },
                _,
            ))),
            CommandState::Accepted,
        ) => Ok(()),
        _ => {
            entry.report.send_replace(Some(Ok((report, control))));
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "mock-backend"))]
mod tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use test_utils::Scenario;
    use uuid::Uuid;

    use crate::krun::worker::lifecycle::Binding;
    use crate::krun::worker::lifecycle_wire::{self, ParentFrame, WorkerFrame};
    use crate::virt::backend::lifecycle::{
        lifecycle_pair, LifecycleClient, LifecycleFault, LifecycleSlot,
    };
    use crate::virt::lifecycle::*;
    use crate::virt::{BackendKind, VirtualMachine, VmConfig};

    struct Machine {
        vm: VirtualMachine,
        machine_id: Uuid,
        run_id: Uuid,
        root: PathBuf,
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Machine {
        async fn start(scenario: &str) -> Self {
            let root = Path::new("/tmp").join(format!("lc-{:x}", rand::random::<u64>()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .expect("root");
            let (machine_id, run_id) = (Uuid::new_v4(), Uuid::new_v4());
            let mut config = VmConfig::builder("lifecycle")
                .base_directory(&root)
                .kernel(Path::new("/mock-kernel"))
                .build()
                .with_storage_launch(
                    crate::virt::test_storage_launch(&root, machine_id, run_id).expect("launch"),
                );
            config.set_resolved_mock_scenario(Arc::new(
                Scenario::from_json(scenario).expect("scenario"),
            ));
            let vm = VirtualMachine::with_backend(BackendKind::Mock, config).expect("machine");
            vm.start().await.expect("start");
            Self {
                vm,
                machine_id,
                run_id,
                root,
            }
        }

        fn request(&self, request_id: Uuid, command: LifecycleCommand) -> LifecycleRequest {
            LifecycleRequest {
                machine_id: self.machine_id,
                run_id: self.run_id,
                request_id,
                command,
            }
        }

        async fn send(
            &self,
            request_id: Uuid,
            command: LifecycleCommand,
        ) -> Result<LifecycleResponse, LifecycleError> {
            self.vm.lifecycle(self.request(request_id, command)).await
        }

        async fn pause(&self, operation: Uuid) -> Result<LifecycleResponse, LifecycleError> {
            self.send(operation, pause(operation, PausePurpose::Initial))
                .await
        }

        async fn control(&self) -> LifecycleResponse {
            self.send(
                Uuid::new_v4(),
                LifecycleCommand::GetControl { target: None },
            )
            .await
            .expect("observe")
        }

        async fn native(&self) -> NativeControl {
            match self.control().await.control {
                ControlObservation::Observed { control } => control,
                ControlObservation::Unavailable { failure } => panic!("unobserved: {failure}"),
            }
        }

        /// Poll until native control satisfies `ready`.
        async fn until(&self, ready: impl Fn(&NativeControl) -> bool) -> NativeControl {
            for _ in 0..500 {
                let control = self.native().await;
                if ready(&control) {
                    return control;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("native control never reached the expected state");
        }
    }

    const BUDGET: Duration = Duration::from_secs(5);

    fn pause(operation: Uuid, purpose: PausePurpose) -> LifecycleCommand {
        LifecycleCommand::Pause {
            operation,
            purpose,
            timeout: BUDGET,
            clock_profile: None,
        }
    }

    fn resume(operation: Uuid, generation: NativePauseGeneration) -> LifecycleCommand {
        LifecycleCommand::Resume {
            operation,
            generation,
            timeout: BUDGET,
        }
    }

    fn cancel(operation: Uuid) -> LifecycleCommand {
        LifecycleCommand::CancelPause {
            operation,
            timeout: BUDGET,
        }
    }

    fn outcome(response: &LifecycleResponse) -> CommandOutcome {
        match &response.command {
            Some(CommandReport {
                state: CommandState::Completed { outcome },
                ..
            }) => outcome.clone(),
            other => panic!("not completed: {other:?}"),
        }
    }

    fn paused(response: &LifecycleResponse) -> NativePauseGeneration {
        match outcome(response) {
            CommandOutcome::Paused { pause } => {
                assert_eq!(pause.owner, NativePauseOwner::User);
                pause.generation
            }
            other => panic!("not paused: {other:?}"),
        }
    }

    fn rejected(result: Result<LifecycleResponse, LifecycleError>) -> LifecycleRejection {
        match result {
            Err(LifecycleError::Rejected(rejection)) => rejection,
            other => panic!("not rejected: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pause_and_clock_only_resume_publish_exact_native_facts() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        assert_eq!(machine.native().await, NativeControl::Running);
        let first = Uuid::new_v4();
        let response = machine.pause(first).await.expect("pause");
        let generation = paused(&response);
        assert_eq!(
            response.control,
            ControlObservation::Observed {
                control: NativeControl::Paused {
                    generation,
                    owner: NativePauseOwner::User
                }
            }
        );
        let observed = machine.control().await;
        let Some(InventoryObservation::Observed {
            providers,
            memory_tracking,
        }) = observed.inventory.clone()
        else {
            panic!("inventory must be observed: {observed:?}");
        };
        assert_eq!(memory_tracking, Some(MemoryTracking::Capture));
        assert!(providers
            .iter()
            .any(|provider| provider.configured_id == "root"
                && provider.block_backing == Some(BlockBacking::Raw)
                && matches!(
                    provider.device,
                    ProviderDevice::Virtio {
                        kind: VirtioKind::Block,
                        ..
                    }
                )));
        let resumed = machine
            .send(Uuid::new_v4(), resume(first, generation))
            .await
            .expect("resume");
        match outcome(&resumed) {
            CommandOutcome::Resumed { clock } => {
                assert_eq!(clock.flags, 3, "SYNC_CLOCK | CLOCK_ONLY");
                assert_eq!(clock.sequence, 1);
            }
            other => panic!("not resumed: {other:?}"),
        }
        assert_eq!(machine.native().await, NativeControl::Running);
        let second = paused(&machine.pause(Uuid::new_v4()).await.expect("second pause"));
        assert!(second > generation, "pause generations strictly increase");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identical_retries_join_one_native_effect_and_changed_inputs_conflict() {
        let machine = Machine::start(
            r#"{"lifecycle": {"nativePause": [{"delayMs": 200, "result": "complete"}]}}"#,
        )
        .await;
        let operation = Uuid::new_v4();
        let (first, second) = tokio::join!(machine.pause(operation), machine.pause(operation));
        let (first, second) = (first.expect("first"), second.expect("second"));
        assert_eq!(
            first.command, second.command,
            "one retained command answers both"
        );
        let generation = paused(&first);
        let changed = machine
            .send(
                operation,
                LifecycleCommand::Pause {
                    operation,
                    purpose: PausePurpose::Initial,
                    timeout: Duration::from_secs(6),
                    clock_profile: None,
                },
            )
            .await;
        assert_eq!(rejected(changed), LifecycleRejection::RequestConflict);
        // Replay after completion returns the original result, not a new pause.
        let replay = machine.pause(operation).await.expect("replay");
        assert_eq!(replay.command, first.command);
        assert_eq!(
            machine.native().await,
            NativeControl::Paused {
                generation,
                owner: NativePauseOwner::User
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_wait_never_cancels_accepted_work() {
        let machine = Machine::start(
            r#"{"lifecycle": {"nativePause": [{"delayMs": 300, "result": "complete"}]}}"#,
        )
        .await;
        assert_eq!(
            machine.native().await,
            NativeControl::Running,
            "worker ready"
        );
        let operation = Uuid::new_v4();
        let abandoned =
            tokio::time::timeout(Duration::from_millis(50), machine.pause(operation)).await;
        assert!(abandoned.is_err(), "the caller gave up first");
        machine
            .until(|control| matches!(control, NativeControl::Paused { .. }))
            .await;
        let generation = paused(&machine.pause(operation).await.expect("join"));
        let target = machine
            .send(
                Uuid::new_v4(),
                LifecycleCommand::GetControl {
                    target: Some(CommandKey {
                        request_id: operation,
                        kind: CommandKind::Pause,
                    }),
                },
            )
            .await
            .expect("observe target");
        assert_eq!(paused(&target), generation);
        assert_eq!(
            rejected(
                machine
                    .send(
                        Uuid::new_v4(),
                        LifecycleCommand::GetControl {
                            target: Some(CommandKey {
                                request_id: Uuid::new_v4(),
                                kind: CommandKind::Resume,
                            }),
                        },
                    )
                    .await
            ),
            LifecycleRejection::UnknownTarget
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_admitted_before_completion_rolls_back_and_withdraws_the_pause() {
        let machine =
            Machine::start(r#"{"lifecycle": {"nativePause": [{"result": "hang"}]}}"#).await;
        let operation = Uuid::new_v4();
        let pending = {
            let vm = machine.vm.clone();
            let request = machine.request(operation, pause(operation, PausePurpose::Initial));
            tokio::spawn(async move { vm.lifecycle(request).await })
        };
        machine
            .until(|control| matches!(control, NativeControl::Pausing { failed: false, .. }))
            .await;
        assert_eq!(
            rejected(
                machine
                    .send(
                        Uuid::new_v4(),
                        resume(operation, NativePauseGeneration::new(1).expect("nonzero"))
                    )
                    .await
            ),
            LifecycleRejection::Busy,
            "Resume never overlaps a pending pause"
        );
        let cancelled = machine
            .send(Uuid::new_v4(), cancel(operation))
            .await
            .expect("cancel");
        assert_eq!(
            outcome(&cancelled),
            CommandOutcome::CancelSettled {
                settlement: CancelSettlement::RolledBack
            }
        );
        let withdrawn = pending.await.expect("join").expect("pause report");
        assert_eq!(outcome(&withdrawn), CommandOutcome::PauseWithdrawn);
        assert_eq!(machine.native().await, NativeControl::Running);
        paused(
            &machine
                .pause(Uuid::new_v4())
                .await
                .expect("a retry is a new pause"),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_of_a_completed_unpublished_pause_consumes_it_through_clock_only_resume() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let operation = Uuid::new_v4();
        let generation = paused(&machine.pause(operation).await.expect("pause"));
        let cancelled = machine
            .send(Uuid::new_v4(), cancel(operation))
            .await
            .expect("cancel");
        match outcome(&cancelled) {
            CommandOutcome::CancelSettled {
                settlement: CancelSettlement::ConsumedCompletedPause { clock },
            } => assert_eq!(clock.flags, 3),
            other => panic!("token must be consumed, not stranded: {other:?}"),
        }
        assert_eq!(machine.native().await, NativeControl::Running);
        assert_eq!(
            rejected(
                machine
                    .send(Uuid::new_v4(), resume(operation, generation))
                    .await
            ),
            LifecycleRejection::StaleGeneration,
            "a consumed generation never authorizes resume"
        );
        assert_eq!(
            rejected(machine.send(Uuid::new_v4(), cancel(operation)).await),
            LifecycleRejection::NotCancellable
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_barrier_has_no_token_until_explicit_cancel_rolls_back() {
        let machine =
            Machine::start(r#"{"lifecycle": {"nativePause": [{"result": "fail"}]}}"#).await;
        let operation = Uuid::new_v4();
        let failed = machine.pause(operation).await.expect("pause report");
        assert!(matches!(
            outcome(&failed),
            CommandOutcome::PauseFailed { failure } if failure.kind == NativeFailureKind::Participant
        ));
        assert!(matches!(
            machine.native().await,
            NativeControl::Pausing { failed: true, .. }
        ));
        assert_eq!(
            rejected(
                machine
                    .send(
                        Uuid::new_v4(),
                        resume(operation, NativePauseGeneration::new(1).expect("nonzero"))
                    )
                    .await
            ),
            LifecycleRejection::NoCurrentPause
        );
        assert_eq!(
            rejected(machine.pause(Uuid::new_v4()).await),
            LifecycleRejection::PauseActive,
            "a failed pause is never silently replaced"
        );
        let cancelled = machine
            .send(Uuid::new_v4(), cancel(operation))
            .await
            .expect("cancel");
        assert_eq!(
            outcome(&cancelled),
            CommandOutcome::CancelSettled {
                settlement: CancelSettlement::RolledBack
            }
        );
        assert_eq!(machine.native().await, NativeControl::Running);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejected_admission_leaves_native_running_and_cancel_has_no_effect() {
        let machine =
            Machine::start(r#"{"lifecycle": {"nativePause": [{"result": "reject"}]}}"#).await;
        let operation = Uuid::new_v4();
        assert!(matches!(
            outcome(&machine.pause(operation).await.expect("report")),
            CommandOutcome::PauseFailed { failure } if failure.kind == NativeFailureKind::Unsupported
        ));
        assert_eq!(machine.native().await, NativeControl::Running);
        assert_eq!(
            outcome(
                &machine
                    .send(Uuid::new_v4(), cancel(operation))
                    .await
                    .expect("cancel")
            ),
            CommandOutcome::CancelSettled {
                settlement: CancelSettlement::NoNativeEffect
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rollback_failure_fences_native_control() {
        let machine = Machine::start(
            r#"{"lifecycle": {"nativePause": [{"result": "fail"}], "nativeCancel": [{"result": "fail"}]}}"#,
        )
        .await;
        let operation = Uuid::new_v4();
        machine.pause(operation).await.expect("failed pause report");
        let cancelled = machine
            .send(Uuid::new_v4(), cancel(operation))
            .await
            .expect("cancel report");
        assert!(matches!(
            outcome(&cancelled),
            CommandOutcome::CancelFailed {
                stage: CancelStage::Rollback,
                ..
            }
        ));
        assert_eq!(machine.native().await, NativeControl::FailedFenced);
        assert_eq!(
            rejected(machine.send(Uuid::new_v4(), cancel(operation)).await),
            LifecycleRejection::NotCancellable
        );
        assert_eq!(
            rejected(machine.pause(Uuid::new_v4()).await),
            LifecycleRejection::PauseActive,
            "fenced worker refuses a new pause before any native effect",
        );
        assert_eq!(machine.native().await, NativeControl::FailedFenced);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lost_native_replies_are_reconciled_never_guessed() {
        let machine = Machine::start(
            r#"{"lifecycle": {"nativePause": [{"result": "loseReply"}], "nativeResume": [{"result": "loseReply", "clockDelayMs": 20}]}}"#,
        )
        .await;
        let operation = Uuid::new_v4();
        let generation = paused(&machine.pause(operation).await.expect("pause"));
        assert!(matches!(
            outcome(
                &machine
                    .send(Uuid::new_v4(), resume(operation, generation))
                    .await
                    .expect("resume")
            ),
            CommandOutcome::Resumed { .. }
        ));
        assert_eq!(machine.native().await, NativeControl::Running);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_failures_report_retention_and_never_claim_completion() {
        let machine = Machine::start(
            r#"{"lifecycle": {"nativeResume": [{"result": "prepareFail"}, {"result": "clockFail"}]}}"#,
        )
        .await;
        let operation = Uuid::new_v4();
        let generation = paused(&machine.pause(operation).await.expect("pause"));
        let prepared = machine
            .send(Uuid::new_v4(), resume(operation, generation))
            .await
            .expect("report");
        assert!(matches!(
            outcome(&prepared),
            CommandOutcome::ResumeFailed {
                stage: ResumeStage::PrepareClock,
                pause_retained: true,
                ..
            }
        ));
        assert_eq!(
            machine.native().await,
            NativeControl::Paused {
                generation,
                owner: NativePauseOwner::User
            }
        );
        let clock = machine
            .send(Uuid::new_v4(), resume(operation, generation))
            .await
            .expect("report");
        assert!(matches!(
            outcome(&clock),
            CommandOutcome::ResumeFailed {
                stage: ResumeStage::ClockAcknowledgement,
                pause_retained: false,
                failure: NativeFailure {
                    kind: NativeFailureKind::Generation(GenerationFailureKind::DriverError),
                    ..
                },
            }
        ));
        assert_eq!(machine.native().await, NativeControl::Running);

        let fenced =
            Machine::start(r#"{"lifecycle": {"nativeResume": [{"result": "releaseFail"}]}}"#).await;
        let operation = Uuid::new_v4();
        let generation = paused(&fenced.pause(operation).await.expect("pause"));
        assert!(matches!(
            outcome(
                &fenced
                    .send(Uuid::new_v4(), resume(operation, generation))
                    .await
                    .expect("report")
            ),
            CommandOutcome::ResumeFailed {
                stage: ResumeStage::Release,
                pause_retained: false,
                ..
            }
        ));
        assert_eq!(fenced.native().await, NativeControl::FailedFenced);

        let late =
            Machine::start(r#"{"lifecycle": {"nativeResume": [{"result": "clockTimeout"}]}}"#)
                .await;
        let operation = Uuid::new_v4();
        let generation = paused(&late.pause(operation).await.expect("pause"));
        let timed_out = late
            .send(
                Uuid::new_v4(),
                LifecycleCommand::Resume {
                    operation,
                    generation,
                    timeout: Duration::from_millis(200),
                },
            )
            .await
            .expect("report");
        assert!(matches!(
            outcome(&timed_out),
            CommandOutcome::ResumeFailed {
                stage: ResumeStage::ClockAcknowledgement,
                pause_retained: false,
                failure: NativeFailure {
                    kind: NativeFailureKind::Generation(GenerationFailureKind::Deadline),
                    ..
                },
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_foreign_and_wrong_run_requests_are_refused_without_effect() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let operation = Uuid::new_v4();
        let generation = paused(&machine.pause(operation).await.expect("pause"));
        let next = NativePauseGeneration::new(generation.get() + 1).expect("nonzero");
        assert_eq!(
            rejected(machine.send(Uuid::new_v4(), resume(operation, next)).await),
            LifecycleRejection::StaleGeneration
        );
        assert_eq!(
            rejected(
                machine
                    .send(Uuid::new_v4(), resume(Uuid::new_v4(), generation))
                    .await
            ),
            LifecycleRejection::NoCurrentPause
        );
        let mut foreign = machine.request(Uuid::new_v4(), resume(operation, generation));
        foreign.run_id = Uuid::new_v4();
        assert_eq!(
            rejected(machine.vm.lifecycle(foreign).await),
            LifecycleRejection::WrongRun
        );
        assert_eq!(
            machine.native().await,
            NativeControl::Paused {
                generation,
                owner: NativePauseOwner::User
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lost_thaw_recovery_establishes_a_new_generation_for_the_same_operation() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let operation = Uuid::new_v4();
        let first = paused(&machine.pause(operation).await.expect("pause"));
        let resume_request = Uuid::new_v4();
        assert!(matches!(
            outcome(
                &machine
                    .send(resume_request, resume(operation, first))
                    .await
                    .expect("resume")
            ),
            CommandOutcome::Resumed { .. }
        ));
        let wrong = NativePauseGeneration::new(first.get() + 7).expect("nonzero");
        assert_eq!(
            rejected(
                machine
                    .send(
                        resume_request,
                        pause(operation, PausePurpose::Recovery { consumed: wrong })
                    )
                    .await
            ),
            LifecycleRejection::StaleGeneration
        );
        let recovered = machine
            .send(
                Uuid::new_v4(),
                pause(operation, PausePurpose::Recovery { consumed: first }),
            )
            .await
            .expect("recovery pause");
        let second = paused(&recovered);
        assert!(second > first, "recovery mints new authority");
        assert_eq!(
            rejected(machine.send(Uuid::new_v4(), resume(operation, first)).await),
            LifecycleRejection::StaleGeneration,
            "the old generation never authorizes anything new"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_closes_admission_and_ends_the_worker_without_resuming() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let operation = Uuid::new_v4();
        let original = machine.pause(operation).await.expect("pause");
        paused(&original);
        machine.vm.stop().await.expect("stop");
        assert_eq!(
            rejected(machine.pause(Uuid::new_v4()).await),
            LifecycleRejection::Stopping
        );
        let replay = machine.pause(operation).await.expect("historical replay");
        assert_eq!(
            replay.command, original.command,
            "terminal results are retained"
        );
        let observed = machine
            .send(
                Uuid::new_v4(),
                LifecycleCommand::GetControl { target: None },
            )
            .await;
        assert!(matches!(
            observed,
            Err(LifecycleError::Unknown(_))
                | Err(LifecycleError::Rejected(LifecycleRejection::Stopping))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_profile_evidence_is_explicit_and_fails_closed() {
        let absent = Machine::start("{}").await;
        assert!(matches!(
            outcome(&absent.pause(Uuid::new_v4()).await.expect("report")),
            CommandOutcome::PauseFailed { failure } if failure.kind == NativeFailureKind::Unsupported
        ));
        assert!(matches!(
            absent.control().await.inventory,
            Some(InventoryObservation::Unavailable { .. })
        ));

        // A read-only VMDK lower quiesces natively; a writable VMDK cannot.
        let lower = Machine::start(
            r#"{"lifecycle": {"providers": [{"deviceId": 2, "configuredId": "lower", "blockBacking": "vmdk", "readOnly": true}, {"deviceId": 2, "configuredId": "upper", "blockBacking": "raw"}]}}"#,
        )
        .await;
        let Some(InventoryObservation::Observed { providers, .. }) =
            lower.control().await.inventory
        else {
            panic!("inventory must be observed");
        };
        assert_eq!(providers[0].block_backing, Some(BlockBacking::Vmdk));
        assert_eq!(providers[0].block_read_only, Some(true));
        assert_eq!(providers[1].block_read_only, Some(false));
        paused(
            &lower
                .pause(Uuid::new_v4())
                .await
                .expect("read-only lower pauses"),
        );

        let vmdk = Machine::start(
            r#"{"lifecycle": {"providers": [{"deviceId": 2, "configuredId": "lower", "blockBacking": "vmdk"}]}}"#,
        )
        .await;
        assert!(matches!(
            outcome(&vmdk.pause(Uuid::new_v4()).await.expect("report")),
            CommandOutcome::PauseFailed { failure } if failure.kind == NativeFailureKind::Unsupported
        ));
        assert_eq!(vmdk.native().await, NativeControl::Running);

        let uncovered = Machine::start(
            r#"{"lifecycle": {"providers": [{"deviceId": 26, "configuredId": "share", "missingStateProvider": true}]}}"#,
        )
        .await;
        assert!(matches!(
            uncovered.control().await.inventory,
            Some(InventoryObservation::Unavailable { failure }) if failure.kind == NativeFailureKind::FailedFenced
        ));
    }

    fn binding() -> Binding {
        Binding {
            machine_id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
        }
    }

    fn hello(binding: Binding) -> Vec<u8> {
        lifecycle_wire::encode(&WorkerFrame::Hello {
            version: lifecycle_wire::PROTOCOL_VERSION,
            machine_id: binding.machine_id,
            run_id: binding.run_id,
        })
        .expect("hello")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepted_replay_after_report_deadline_waits_for_delayed_terminal() {
        use crate::virt::backend::mock::native::ScenarioNative;
        let (parent, child) = lifecycle_pair().expect("pair");
        let bound = binding();
        let scenario = Scenario::from_json(
            r#"{"lifecycle":{"nativePause":[{"delayMs":300,"result":"complete"}]}}"#,
        )
        .expect("scenario");
        crate::krun::worker::lifecycle::serve(
            child,
            bound,
            ScenarioNative::new(scenario.lifecycle.clone(), 1),
            None,
            Box::new(|_| {}),
        )
        .expect("serve");
        let (client, _faults) = LifecycleClient::start(parent, bound).expect("client");
        let operation = Uuid::new_v4();
        let request = LifecycleRequest {
            machine_id: bound.machine_id,
            run_id: bound.run_id,
            request_id: operation,
            command: pause(operation, PausePurpose::Initial),
        };
        let key = CommandKey {
            request_id: operation,
            kind: CommandKind::Pause,
        };
        let waiting = {
            let client = client.clone();
            let request = request.clone();
            tokio::spawn(async move { client.lifecycle(request, LifecycleRights::None).await })
        };
        // Wait for actual worker acceptance, then simulate an expired client
        // observation window without altering the native command's deadline.
        tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let accepted = {
                let mut state = crate::virt::backend::lifecycle::lock(&client.shared.state);
                state.keys.get_mut(&key).is_some_and(|entry| {
                    if matches!(&*entry.report.borrow(), Some(Ok((report, _))) if matches!(report.state, CommandState::Accepted)) {
                        entry.wait_until = std::time::Instant::now() - Duration::from_secs(1);
                        true
                    } else { false }
                })
            };
            if accepted { break; }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        }).await.expect("worker acceptance");
        waiting.abort();
        let original_wait = {
            let state = crate::virt::backend::lifecycle::lock(&client.shared.state);
            state.keys.get(&key).expect("retained").wait_until
        };
        let replay = client
            .lifecycle(request, LifecycleRights::None)
            .await
            .expect("replay");
        assert!(matches!(outcome(&replay), CommandOutcome::Paused { .. }));
        let state = crate::virt::backend::lifecycle::lock(&client.shared.state);
        assert_eq!(
            state.keys.get(&key).expect("retained").wait_until,
            original_wait
        );
        assert_eq!(state.last_sequence, 1, "replay never resubmits native work");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_faults_on_foreign_hello_rights_and_early_frames() {
        // Hello for another run.
        let (parent, child) = lifecycle_pair().expect("pair");
        let mut child = std::os::unix::net::UnixStream::from(child);
        let (_client, mut faults) = LifecycleClient::start(parent, binding()).expect("client");
        child.write_all(&hello(binding())).expect("hello");
        assert!(matches!(
            faults.recv().await,
            Some(LifecycleFault::Protocol(_))
        ));

        // A report before Hello.
        let (parent, child) = lifecycle_pair().expect("pair");
        let mut child = std::os::unix::net::UnixStream::from(child);
        let (_client, mut faults) = LifecycleClient::start(parent, binding()).expect("client");
        let early = lifecycle_wire::encode(&WorkerFrame::Rejected {
            sequence: CommandSequence::new(1).expect("nonzero"),
            rejection: LifecycleRejection::Busy,
            control: ControlObservation::Observed {
                control: NativeControl::Running,
            },
        })
        .expect("frame");
        child.write_all(&early).expect("early");
        assert!(matches!(
            faults.recv().await,
            Some(LifecycleFault::Protocol(_))
        ));

        // Rights attached to a valid Hello are refused and closed.
        let (parent, child) = lifecycle_pair().expect("pair");
        let bound = binding();
        let (_client, mut faults) = LifecycleClient::start(parent, bound).expect("client");
        let (passenger, witness) = nix::unistd::pipe().expect("pipe");
        nix::sys::socket::sendmsg::<()>(
            child.as_raw_fd(),
            &[std::io::IoSlice::new(&hello(bound))],
            &[nix::sys::socket::ControlMessage::ScmRights(&[
                passenger.as_raw_fd()
            ])],
            nix::sys::socket::MsgFlags::empty(),
            None,
        )
        .expect("send rights");
        drop(passenger);
        assert!(matches!(
            faults.recv().await,
            Some(LifecycleFault::Protocol(_))
        ));
        assert_eq!(
            nix::unistd::write(&witness, b"x"),
            Err(nix::errno::Errno::EPIPE),
            "received descriptor is closed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_loss_resolves_pending_waits_as_unknown_never_success() {
        let (parent, child) = lifecycle_pair().expect("pair");
        let bound = binding();
        let mut child = std::os::unix::net::UnixStream::from(child);
        let (client, mut faults) = LifecycleClient::start(parent, bound).expect("client");
        child.write_all(&hello(bound)).expect("hello");
        let operation = Uuid::new_v4();
        let request = LifecycleRequest {
            machine_id: bound.machine_id,
            run_id: bound.run_id,
            request_id: operation,
            command: pause(operation, PausePurpose::Initial),
        };
        let waiting = {
            let client = client.clone();
            let request = request.clone();
            tokio::spawn(async move { client.lifecycle(request, LifecycleRights::None).await })
        };
        // Read the command the worker would receive, then die without answering.
        let mut frames = lifecycle_wire::FrameBuffer::default();
        let mut chunk = [0_u8; 512];
        let command = loop {
            let count = std::io::Read::read(&mut child, &mut chunk).expect("read");
            frames.extend(&chunk[..count]).expect("extend");
            if let Some(frame) = frames.next::<ParentFrame>().expect("decode") {
                break frame;
            }
        };
        let ParentFrame::Command { sequence, .. } = command;
        assert_eq!(sequence.get(), 1);
        drop(child);
        assert_eq!(faults.recv().await, Some(LifecycleFault::Closed));
        assert!(matches!(
            waiting.await.expect("join"),
            Err(LifecycleError::Unknown(LifecycleUncertainty::WorkerLost))
        ));
        assert!(matches!(
            client.lifecycle(request, LifecycleRights::None).await,
            Err(LifecycleError::Unknown(LifecycleUncertainty::WorkerLost))
        ));
    }

    #[test]
    fn worker_treats_reordered_sequences_rights_and_eof_as_fatal() {
        use crate::virt::backend::mock::native::ScenarioNative;
        let run = |input: &dyn Fn(&std::os::unix::net::UnixStream)| {
            let (parent, child) = lifecycle_pair().expect("pair");
            let parent = std::os::unix::net::UnixStream::from(parent);
            parent.set_nonblocking(false).expect("blocking");
            let (sender, receiver) = std::sync::mpsc::channel();
            crate::krun::worker::lifecycle::serve(
                child,
                binding(),
                ScenarioNative::new(None, 1),
                None,
                Box::new(move |reason: &str| {
                    let _ = sender.send(reason.to_string());
                }),
            )
            .expect("serve");
            input(&parent);
            receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("worker loses control")
        };
        let observe = |sequence: u64| {
            lifecycle_wire::encode(&ParentFrame::Command {
                sequence: CommandSequence::new(sequence).expect("nonzero"),
                request_id: Uuid::new_v4(),
                command: LifecycleCommand::GetControl { target: None },
            })
            .expect("frame")
        };
        run(&|parent| {
            (&*parent).write_all(&observe(2)).expect("first");
            (&*parent).write_all(&observe(2)).expect("reused");
        });
        run(&|parent| {
            let (passenger, _keep) = nix::unistd::pipe().expect("pipe");
            nix::sys::socket::sendmsg::<()>(
                parent.as_raw_fd(),
                &[std::io::IoSlice::new(&observe(1))],
                &[nix::sys::socket::ControlMessage::ScmRights(&[
                    passenger.as_raw_fd()
                ])],
                nix::sys::socket::MsgFlags::empty(),
                None,
            )
            .expect("rights");
        });
        run(&|parent| {
            parent
                .shutdown(std::net::Shutdown::Write)
                .expect("monitor closes");
        });
    }

    // -------------------------------------------------------------- capture

    /// Private staging with exclusively created, empty 0600 outputs and a pin.
    /// The writers are the monitor's originals; it closes them after
    /// PrepareCapture is admitted.
    struct Staging {
        /// execution, devices, ram, layout.
        writers: Option<[std::fs::File; 4]>,
        pin: std::fs::File,
        outputs: CaptureOutputIdentities,
        pin_identity: OutputIdentity,
        directory: PathBuf,
    }

    fn create(path: &Path) -> std::fs::File {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("exclusive private output")
    }

    impl Staging {
        fn new(machine: &Machine) -> Self {
            Self::under(&machine.root)
        }

        fn under(root: &Path) -> Self {
            let directory = root.join(format!("captures-{:x}", rand::random::<u64>()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .expect("staging");
            let writers = [
                "execution.state",
                "devices.state",
                "memory.ram",
                "memory-layout.json",
            ]
            .map(|name| create(&directory.join(name)));
            let pin = create(&directory.join("pin.lease"));
            let id = |file: &std::fs::File| OutputIdentity::of(file).expect("identity");
            Self {
                outputs: CaptureOutputIdentities {
                    execution: id(&writers[0]),
                    devices: id(&writers[1]),
                    ram: id(&writers[2]),
                    layout: id(&writers[3]),
                },
                pin_identity: id(&pin),
                writers: Some(writers),
                pin,
                directory,
            }
        }

        fn identities(&self) -> (CaptureOutputIdentities, OutputIdentity) {
            (self.outputs, self.pin_identity)
        }

        fn writer(&self, index: usize) -> &std::fs::File {
            &self.writers.as_ref().expect("writers open")[index]
        }

        fn close_writers(&mut self) {
            self.writers = None;
        }

        fn rights(&self) -> LifecycleRights {
            let dup = |file: &std::fs::File| file.try_clone().expect("dup");
            LifecycleRights::CaptureOutputs(CaptureOutputFiles {
                execution: dup(self.writer(0)),
                devices: dup(self.writer(1)),
                ram: dup(self.writer(2)),
                layout: dup(self.writer(3)),
                pin: dup(&self.pin),
            })
        }

        fn sealed(&self) -> LifecycleRights {
            LifecycleRights::SealedMemory(SealedMemoryFiles {
                ram: std::fs::File::open(self.directory.join("memory.ram")).expect("ram"),
                layout: std::fs::File::open(self.directory.join("memory-layout.json"))
                    .expect("layout"),
            })
        }
    }

    fn digests() -> CaptureDigests {
        CaptureDigests {
            silo_producer: Digest32([1; 32]),
            profile: Digest32([2; 32]),
            topology: Digest32([3; 32]),
        }
    }

    fn prepare(
        staging: &Staging,
        operation: Uuid,
        pause: CapturePauseSource,
        resume_policy: CaptureResumePolicy,
    ) -> LifecycleCommand {
        let (outputs, pin) = staging.identities();
        LifecycleCommand::PrepareCapture {
            operation,
            preparation: CapturePreparation {
                outputs,
                pin,
                pause,
                resume_policy,
                binding: digests(),
                policy: vm_spec::lifecycle::CapturePolicy::Full,
                dirty_crossover_percent: 60,
                baseline: None,
            },
            timeout: BUDGET,
        }
    }

    /// Open descriptors of this process that reference `identity`.
    #[cfg(target_os = "linux")]
    fn open_copies(identity: OutputIdentity) -> usize {
        use std::os::unix::fs::MetadataExt;
        std::fs::read_dir("/proc/self/fd")
            .expect("fd table")
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::metadata(entry.path()).ok())
            .filter(|metadata| {
                metadata.dev() == identity.device && metadata.ino() == identity.inode
            })
            .count()
    }

    impl Machine {
        async fn rights(
            &self,
            request_id: Uuid,
            command: LifecycleCommand,
            rights: LifecycleRights,
        ) -> Result<LifecycleResponse, LifecycleError> {
            self.vm
                .lifecycle_with_rights(self.request(request_id, command), rights)
                .await
        }

        async fn stage(&self, operation: Uuid, command: LifecycleCommand) -> CommandOutcome {
            outcome(&self.send(operation, command).await.expect("stage report"))
        }

        async fn capture(&self, operation: Uuid) -> CaptureObservation {
            self.send(Uuid::new_v4(), LifecycleCommand::GetCapture { operation })
                .await
                .expect("capture observation")
                .capture
                .expect("capture facts")
        }

        /// Prepare, pause (acquired) and capture execution and full RAM.
        async fn candidate(
            &self,
            staging: &Staging,
            operation: Uuid,
            policy: CaptureResumePolicy,
        ) -> (NativePause, CommandOutcome) {
            let prepared = self
                .rights(
                    operation,
                    prepare(staging, operation, CapturePauseSource::Acquire, policy),
                    staging.rights(),
                )
                .await
                .expect("prepare");
            assert!(matches!(
                outcome(&prepared),
                CommandOutcome::CapturePrepared { .. }
            ));
            let cut = match self
                .stage(operation, pause(operation, PausePurpose::Capture))
                .await
            {
                CommandOutcome::Paused { pause } => pause,
                other => panic!("capture pause: {other:?}"),
            };
            assert_eq!(cut.owner, NativePauseOwner::Capture);
            assert!(matches!(
                self.stage(
                    operation,
                    LifecycleCommand::FlushCapture {
                        operation,
                        timeout: BUDGET
                    }
                )
                .await,
                CommandOutcome::CaptureFlushed { pause, ref attachments }
                    if pause == cut && attachments.iter().any(|item| item.configured_id == "root")
            ));
            assert!(matches!(
                self.stage(
                    operation,
                    LifecycleCommand::CaptureExecution {
                        operation,
                        timeout: BUDGET
                    }
                )
                .await,
                CommandOutcome::ExecutionCaptured { .. }
            ));
            let memory = self
                .stage(
                    operation,
                    LifecycleCommand::CaptureMemory {
                        operation,
                        timeout: BUDGET,
                    },
                )
                .await;
            (cut, memory)
        }
    }

    fn accept(staging: &Staging, operation: Uuid) -> LifecycleCommand {
        let (outputs, _) = staging.identities();
        LifecycleCommand::AcceptCapture {
            operation,
            ram: outputs.ram,
            layout: outputs.layout,
            stream: Digest32([9; 32]),
            timeout: BUDGET,
        }
    }

    fn continuation(operation: Uuid, continuation: CaptureContinuation) -> LifecycleCommand {
        LifecycleCommand::ContinueCapture {
            operation,
            continuation,
            timeout: BUDGET,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_capture_closes_every_writer_and_preserve_transfers_the_cut_to_user() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let mut staging = Staging::new(&machine);
        let (outputs, pin) = staging.identities();
        let operation = Uuid::new_v4();
        let prepared = machine
            .rights(
                operation,
                prepare(
                    &staging,
                    operation,
                    CapturePauseSource::Acquire,
                    CaptureResumePolicy::Preserve,
                ),
                staging.rights(),
            )
            .await
            .expect("prepare");
        assert_eq!(
            outcome(&prepared),
            CommandOutcome::CapturePrepared { outputs, pin }
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_copies(outputs.ram),
            2,
            "the monitor's original and the worker's prepared copy"
        );
        // The monitor closes its writable transfer copies after admission.
        staging.close_writers();
        #[cfg(target_os = "linux")]
        assert_eq!(open_copies(outputs.ram), 1, "only the worker holds RAM");

        let cut = match machine
            .stage(operation, pause(operation, PausePurpose::Capture))
            .await
        {
            CommandOutcome::Paused { pause } => pause,
            other => panic!("capture pause: {other:?}"),
        };
        assert_eq!(cut.owner, NativePauseOwner::Capture);
        assert_eq!(
            rejected(
                machine
                    .send(Uuid::new_v4(), resume(operation, cut.generation))
                    .await
            ),
            LifecycleRejection::CaptureOwned,
            "public Resume never consumes a capture-owned pause"
        );
        assert_eq!(
            rejected(machine.send(Uuid::new_v4(), cancel(operation)).await),
            LifecycleRejection::NotCancellable
        );
        assert!(matches!(
            machine
                .stage(
                    operation,
                    LifecycleCommand::FlushCapture {
                        operation,
                        timeout: BUDGET
                    }
                )
                .await,
            CommandOutcome::CaptureFlushed { pause, .. } if pause == cut
        ));
        let CommandOutcome::ExecutionCaptured {
            binding,
            execution,
            devices,
        } = machine
            .stage(
                operation,
                LifecycleCommand::CaptureExecution {
                    operation,
                    timeout: BUDGET,
                },
            )
            .await
        else {
            panic!("execution not captured");
        };
        assert_eq!(binding.capture, operation);
        assert_eq!(binding.source_run, machine.run_id);
        assert_eq!(binding.pause_generation, cut.generation);
        assert_eq!(
            binding.native_producer,
            crate::virt::backend::mock::native::SCENARIO_PRODUCER
        );
        assert_eq!(execution.identity(), outputs.execution);
        assert_eq!(devices.identity(), outputs.devices);
        for (name, receipt) in [("execution.state", execution), ("devices.state", devices)] {
            let length = std::fs::metadata(staging.directory.join(name))
                .expect("output")
                .len();
            assert!(length > 0 && length == receipt.length, "{name}");
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(open_copies(outputs.execution), 0, "native closed execution");
            assert_eq!(open_copies(outputs.ram), 1, "RAM still prepared");
        }
        let CommandOutcome::MemoryCaptured {
            binding: ram_binding,
            ram,
            layout,
            writers_closed,
            ..
        } = machine
            .stage(
                operation,
                LifecycleCommand::CaptureMemory {
                    operation,
                    timeout: BUDGET,
                },
            )
            .await
        else {
            panic!("memory not captured");
        };
        assert!(writers_closed);
        assert_eq!(ram_binding, binding);
        assert_eq!((ram.identity(), ram.length), (outputs.ram, 64 * 1024));
        assert_eq!(layout.identity(), outputs.layout);
        let layout_bytes =
            std::fs::read(staging.directory.join("memory-layout.json")).expect("layout");
        assert_eq!(layout_bytes.len() as u64, layout.length);
        assert!(layout_bytes.starts_with(br#"{"architecture":"x86_64","kind":"ram-layout""#));
        #[cfg(target_os = "linux")]
        for identity in [
            outputs.execution,
            outputs.devices,
            outputs.ram,
            outputs.layout,
        ] {
            assert_eq!(open_copies(identity), 0, "no writer survives the candidate");
        }
        let observed = machine.capture(operation).await;
        assert_eq!(observed.progress, CaptureProgress::CandidateComplete);
        assert!(observed.outputs.all_closed());
        assert_eq!(observed.pin, PinHolder::Capture);
        assert_eq!(
            observed.evidence,
            CaptureNativeEvidence {
                pause_completed: true,
                flush_completed: true,
                execution_sealed: true,
                memory_sealed: true,
            }
        );
        assert_eq!(observed.pause.cut, Some(cut));
        assert_eq!(observed.pause.current, Some(cut));

        // After the (monitor's) durable seal: accept the exact read-only pair.
        let accepted = machine
            .rights(operation, accept(&staging, operation), staging.sealed())
            .await
            .expect("accept");
        assert!(matches!(
            outcome(&accepted),
            CommandOutcome::CaptureAccepted { .. }
        ));
        let preserved = machine
            .stage(
                operation,
                continuation(operation, CaptureContinuation::Preserve),
            )
            .await;
        let current = match preserved {
            CommandOutcome::CapturePreserved { pause } => pause,
            other => panic!("not preserved: {other:?}"),
        };
        assert_eq!(current.owner, NativePauseOwner::User);
        assert_eq!(current.generation, cut.generation, "no extra generation");
        assert_eq!(
            machine.native().await,
            NativeControl::Paused {
                generation: cut.generation,
                owner: NativePauseOwner::User
            }
        );
        let observed = machine.capture(operation).await;
        assert_eq!(observed.pause.cut, Some(cut), "historical cut is immutable");
        assert_eq!(observed.pause.current, Some(current));
        let released = machine
            .stage(
                Uuid::new_v4(),
                LifecycleCommand::ReleaseCapture {
                    operation,
                    timeout: BUDGET,
                },
            )
            .await;
        assert_eq!(
            released,
            CommandOutcome::CaptureReleased {
                baseline_retained: true
            }
        );
        assert_eq!(machine.capture(operation).await.pin, PinHolder::Baseline);
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_copies(pin),
            2,
            "the source-baseline pin survives release"
        );
        // The preserved pause is ordinary user authority of the capture operation.
        assert!(matches!(
            outcome(
                &machine
                    .send(Uuid::new_v4(), resume(operation, current.generation))
                    .await
                    .expect("resume")
            ),
            CommandOutcome::Resumed { .. }
        ));
        assert_eq!(machine.native().await, NativeControl::Running);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_policy_releases_the_cut_only_after_the_candidate_resolves() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let staging = Staging::new(&machine);
        let operation = Uuid::new_v4();
        let (_, memory) = machine
            .candidate(&staging, operation, CaptureResumePolicy::ResumeIfAcquired)
            .await;
        assert!(matches!(memory, CommandOutcome::MemoryCaptured { .. }));
        assert_eq!(
            rejected(
                machine
                    .send(
                        operation,
                        continuation(operation, CaptureContinuation::Resume)
                    )
                    .await
            ),
            LifecycleRejection::CaptureUnresolved
        );
        // Cancel before seal: abandon under the cancel request's own identity.
        assert_eq!(
            machine
                .stage(
                    Uuid::new_v4(),
                    LifecycleCommand::AbandonCapture {
                        operation,
                        timeout: BUDGET
                    }
                )
                .await,
            CommandOutcome::CaptureAbandoned
        );
        assert_eq!(
            rejected(
                machine
                    .rights(operation, accept(&staging, operation), staging.sealed())
                    .await
            ),
            LifecycleRejection::CaptureStage,
            "an abandoned candidate is never accepted"
        );
        assert!(matches!(
            machine
                .stage(
                    Uuid::new_v4(),
                    continuation(operation, CaptureContinuation::Resume)
                )
                .await,
            CommandOutcome::Resumed { clock } if clock.flags == 3
        ));
        assert_eq!(machine.native().await, NativeControl::Running);
        assert_eq!(
            machine
                .stage(
                    Uuid::new_v4(),
                    LifecycleCommand::ReleaseCapture {
                        operation,
                        timeout: BUDGET
                    }
                )
                .await,
            CommandOutcome::CaptureReleased {
                baseline_retained: false
            }
        );
        let observed = machine.capture(operation).await;
        assert_eq!(observed.progress, CaptureProgress::Released);
        assert_eq!(observed.pin, PinHolder::Released);
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_copies(staging.identities().1),
            1,
            "worker dropped the pin"
        );
        // A new user pause is admissible again once the capture resolved.
        paused(&machine.pause(Uuid::new_v4()).await.expect("pause"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_ram_write_keeps_writers_native_until_abandonment() {
        let machine =
            Machine::start(r#"{"lifecycle": {"capture": {"memory": [{"result": "fail"}]}}}"#).await;
        let staging = Staging::new(&machine);
        let (outputs, _) = staging.identities();
        let operation = Uuid::new_v4();
        let (_, memory) = machine
            .candidate(&staging, operation, CaptureResumePolicy::ResumeIfAcquired)
            .await;
        assert!(matches!(
            memory,
            CommandOutcome::CaptureFailed {
                stage: CaptureStage::Memory,
                ..
            }
        ));
        let observed = machine.capture(operation).await;
        assert_eq!(observed.outputs.ram, OutputHolder::Native);
        assert_eq!(observed.outputs.layout, OutputHolder::Native);
        assert!(!observed.evidence.memory_sealed);
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_copies(outputs.ram),
            2,
            "the native failure still owns the RAM writer (plus the test's original)"
        );
        assert_eq!(
            machine
                .stage(
                    Uuid::new_v4(),
                    LifecycleCommand::AbandonCapture {
                        operation,
                        timeout: BUDGET
                    }
                )
                .await,
            CommandOutcome::CaptureAbandoned
        );
        assert!(machine.capture(operation).await.outputs.all_closed());
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_copies(outputs.ram),
            1,
            "only the test's original remains"
        );
        let _ = outputs;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn borrowed_user_pause_is_never_resumed_or_replaced_by_its_capture() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let user = Uuid::new_v4();
        let generation = paused(&machine.pause(user).await.expect("pause"));
        let staging = Staging::new(&machine);
        let operation = Uuid::new_v4();
        let borrow = CapturePauseSource::Borrow {
            operation: user,
            generation,
        };
        assert_eq!(
            rejected(
                machine
                    .rights(
                        operation,
                        prepare(
                            &staging,
                            operation,
                            borrow,
                            CaptureResumePolicy::ResumeIfAcquired
                        ),
                        staging.rights()
                    )
                    .await
            ),
            LifecycleRejection::InvalidRequest(InvalidRequest::CapturePolicy)
        );
        let operation = Uuid::new_v4();
        machine
            .rights(
                operation,
                prepare(&staging, operation, borrow, CaptureResumePolicy::Preserve),
                staging.rights(),
            )
            .await
            .expect("prepare");
        assert_eq!(
            rejected(machine.send(Uuid::new_v4(), resume(user, generation)).await),
            LifecycleRejection::CaptureActive,
            "the borrowed pause is not resumable while its capture runs"
        );
        for command in [
            LifecycleCommand::FlushCapture {
                operation,
                timeout: BUDGET,
            },
            LifecycleCommand::CaptureExecution {
                operation,
                timeout: BUDGET,
            },
            LifecycleCommand::CaptureMemory {
                operation,
                timeout: BUDGET,
            },
        ] {
            assert!(!matches!(
                machine.stage(operation, command).await,
                CommandOutcome::CaptureFailed { .. }
            ));
        }
        machine
            .rights(operation, accept(&staging, operation), staging.sealed())
            .await
            .expect("accept");
        assert_eq!(
            rejected(
                machine
                    .send(
                        Uuid::new_v4(),
                        continuation(operation, CaptureContinuation::Resume)
                    )
                    .await
            ),
            LifecycleRejection::BorrowedPause
        );
        assert_eq!(
            machine
                .stage(
                    Uuid::new_v4(),
                    continuation(operation, CaptureContinuation::Preserve)
                )
                .await,
            CommandOutcome::CapturePreserved {
                pause: NativePause {
                    generation,
                    owner: NativePauseOwner::User
                }
            }
        );
        assert_eq!(
            machine.native().await,
            NativeControl::Paused {
                generation,
                owner: NativePauseOwner::User
            },
            "the original user token is untouched"
        );
        assert!(matches!(
            outcome(
                &machine
                    .send(Uuid::new_v4(), resume(user, generation))
                    .await
                    .expect("resume")
            ),
            CommandOutcome::Resumed { .. }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prepare_refuses_unsafe_or_mismatched_descriptors_without_effect() {
        use std::os::unix::fs::PermissionsExt;
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let refuse = |problem: OutputProblem| LifecycleRejection::CaptureOutputs(problem);

        let staging = Staging::new(&machine);
        std::io::Write::write_all(&mut staging.writer(0), b"stale").expect("dirty");
        let operation = Uuid::new_v4();
        let command = prepare(
            &staging,
            operation,
            CapturePauseSource::Acquire,
            CaptureResumePolicy::Preserve,
        );
        assert_eq!(
            rejected(machine.rights(operation, command, staging.rights()).await),
            refuse(OutputProblem {
                role: OutputRole::Execution,
                problem: OutputDefect::NotEmpty
            })
        );

        let staging = Staging::new(&machine);
        std::fs::set_permissions(
            staging.directory.join("memory.ram"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod");
        let operation = Uuid::new_v4();
        let command = prepare(
            &staging,
            operation,
            CapturePauseSource::Acquire,
            CaptureResumePolicy::Preserve,
        );
        assert_eq!(
            rejected(machine.rights(operation, command, staging.rights()).await),
            refuse(OutputProblem {
                role: OutputRole::Ram,
                problem: OutputDefect::Mode
            })
        );

        let staging = Staging::new(&machine);
        std::fs::hard_link(
            staging.directory.join("memory-layout.json"),
            staging.directory.join("alias"),
        )
        .expect("link");
        let operation = Uuid::new_v4();
        let command = prepare(
            &staging,
            operation,
            CapturePauseSource::Acquire,
            CaptureResumePolicy::Preserve,
        );
        assert_eq!(
            rejected(machine.rights(operation, command, staging.rights()).await),
            refuse(OutputProblem {
                role: OutputRole::Layout,
                problem: OutputDefect::Links
            })
        );

        // The same inode in two roles.
        let staging = Staging::new(&machine);
        let operation = Uuid::new_v4();
        let (mut outputs, pin) = staging.identities();
        outputs.layout = outputs.ram;
        let rights = LifecycleRights::CaptureOutputs(CaptureOutputFiles {
            execution: staging.writer(0).try_clone().expect("dup"),
            devices: staging.writer(1).try_clone().expect("dup"),
            ram: staging.writer(2).try_clone().expect("dup"),
            layout: staging.writer(2).try_clone().expect("dup"),
            pin: staging.pin.try_clone().expect("dup"),
        });
        let command = LifecycleCommand::PrepareCapture {
            operation,
            preparation: CapturePreparation {
                outputs,
                pin,
                pause: CapturePauseSource::Acquire,
                resume_policy: CaptureResumePolicy::Preserve,
                binding: digests(),
                policy: vm_spec::lifecycle::CapturePolicy::Full,
                dirty_crossover_percent: 60,
                baseline: None,
            },
            timeout: BUDGET,
        };
        assert_eq!(
            rejected(machine.rights(operation, command, rights).await),
            refuse(OutputProblem {
                role: OutputRole::Layout,
                problem: OutputDefect::Alias
            })
        );

        // Declared identities differing from the actual descriptors, and a
        // rights-bearing command without rights, never leave the client.
        let staging = Staging::new(&machine);
        let other = Staging::new(&machine);
        let operation = Uuid::new_v4();
        assert_eq!(
            rejected(
                machine
                    .rights(
                        operation,
                        prepare(
                            &staging,
                            operation,
                            CapturePauseSource::Acquire,
                            CaptureResumePolicy::Preserve
                        ),
                        other.rights()
                    )
                    .await
            ),
            LifecycleRejection::InvalidRequest(InvalidRequest::CaptureRights)
        );
        assert_eq!(
            rejected(
                machine
                    .send(
                        operation,
                        prepare(
                            &staging,
                            operation,
                            CapturePauseSource::Acquire,
                            CaptureResumePolicy::Preserve
                        )
                    )
                    .await
            ),
            LifecycleRejection::InvalidRequest(InvalidRequest::CaptureRights)
        );
        assert_eq!(
            rejected(
                machine
                    .send(
                        Uuid::new_v4(),
                        LifecycleCommand::FlushCapture {
                            operation,
                            timeout: BUDGET
                        }
                    )
                    .await
            ),
            LifecycleRejection::InvalidRequest(InvalidRequest::CaptureRequestIdentity)
        );
        assert_eq!(machine.native().await, NativeControl::Running);
        // Nothing was admitted: the same staging still prepares cleanly.
        let prepared = machine
            .rights(
                operation,
                prepare(
                    &staging,
                    operation,
                    CapturePauseSource::Acquire,
                    CaptureResumePolicy::Preserve,
                ),
                staging.rights(),
            )
            .await
            .expect("prepare");
        assert!(matches!(
            outcome(&prepared),
            CommandOutcome::CapturePrepared { .. }
        ));
        assert_eq!(
            rejected(
                machine
                    .rights(
                        Uuid::new_v4(),
                        {
                            let next = Uuid::new_v4();
                            prepare(
                                &other,
                                next,
                                CapturePauseSource::Acquire,
                                CaptureResumePolicy::Preserve,
                            )
                        },
                        other.rights()
                    )
                    .await
            ),
            LifecycleRejection::InvalidRequest(InvalidRequest::CaptureRequestIdentity)
        );
        let next = Uuid::new_v4();
        assert_eq!(
            rejected(
                machine
                    .rights(
                        next,
                        prepare(
                            &other,
                            next,
                            CapturePauseSource::Acquire,
                            CaptureResumePolicy::Preserve
                        ),
                        other.rights()
                    )
                    .await
            ),
            LifecycleRejection::CaptureActive,
            "one unresolved capture per run"
        );
        assert_eq!(
            rejected(machine.pause(Uuid::new_v4()).await),
            LifecycleRejection::CaptureActive,
            "no user pause while a capture is unresolved"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replayed_rights_join_the_retained_command_and_conflicts_are_refused() {
        let machine = Machine::start(r#"{"lifecycle": {}}"#).await;
        let staging = Staging::new(&machine);
        let operation = Uuid::new_v4();
        let command = prepare(
            &staging,
            operation,
            CapturePauseSource::Acquire,
            CaptureResumePolicy::ResumeIfAcquired,
        );
        let first = machine
            .rights(operation, command.clone(), staging.rights())
            .await
            .expect("prepare");
        // A replay with fresh duplicates joins; one without rights joins too.
        let replay = machine
            .rights(operation, command.clone(), staging.rights())
            .await
            .expect("replay");
        assert_eq!(replay.command, first.command);
        let bare = machine.send(operation, command).await.expect("bare replay");
        assert_eq!(bare.command, first.command);
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_copies(staging.identities().0.ram),
            2,
            "replayed duplicates were closed, not retained"
        );
        let other = Staging::new(&machine);
        assert_eq!(
            rejected(
                machine
                    .rights(
                        operation,
                        prepare(
                            &other,
                            operation,
                            CapturePauseSource::Acquire,
                            CaptureResumePolicy::ResumeIfAcquired
                        ),
                        other.rights()
                    )
                    .await
            ),
            LifecycleRejection::RequestConflict
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_capture_pause_rolls_back_and_leaves_a_prepared_only_capture() {
        let machine =
            Machine::start(r#"{"lifecycle": {"nativePause": [{"result": "hang"}]}}"#).await;
        let staging = Staging::new(&machine);
        let operation = Uuid::new_v4();
        machine
            .rights(
                operation,
                prepare(
                    &staging,
                    operation,
                    CapturePauseSource::Acquire,
                    CaptureResumePolicy::Preserve,
                ),
                staging.rights(),
            )
            .await
            .expect("prepare");
        let pending = {
            let vm = machine.vm.clone();
            let request = machine.request(operation, pause(operation, PausePurpose::Capture));
            tokio::spawn(async move { vm.lifecycle(request).await })
        };
        machine
            .until(|control| matches!(control, NativeControl::Pausing { failed: false, .. }))
            .await;
        assert_eq!(
            outcome(
                &machine
                    .send(Uuid::new_v4(), cancel(operation))
                    .await
                    .expect("cancel")
            ),
            CommandOutcome::CancelSettled {
                settlement: CancelSettlement::RolledBack
            }
        );
        assert_eq!(
            outcome(&pending.await.expect("join").expect("pause report")),
            CommandOutcome::PauseWithdrawn
        );
        let observed = machine.capture(operation).await;
        assert_eq!(observed.progress, CaptureProgress::Prepared);
        assert!(!observed.evidence.pause_completed);
        assert_eq!(
            machine
                .stage(
                    Uuid::new_v4(),
                    LifecycleCommand::AbandonCapture {
                        operation,
                        timeout: BUDGET
                    }
                )
                .await,
            CommandOutcome::CaptureAbandoned
        );
        assert!(machine.capture(operation).await.outputs.all_closed());
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_copies(staging.identities().0.ram),
            1,
            "prepared copy closed"
        );
        assert_eq!(
            rejected(
                machine
                    .send(
                        Uuid::new_v4(),
                        continuation(operation, CaptureContinuation::Preserve)
                    )
                    .await
            ),
            LifecycleRejection::NoCurrentPause,
            "no token exists to preserve"
        );
        assert_eq!(machine.native().await, NativeControl::Running);
    }

    // ------------------------------------------------------ stop and replays

    /// A private scratch root for tests without a machine.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch() -> Scratch {
        let root = Path::new("/tmp").join(format!("lc-{:x}", rand::random::<u64>()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("root");
        Scratch(root)
    }

    /// Read one parent frame as the worker end. A plain read never installs
    /// descriptors riding the frame: the kernel discards them.
    fn read_command(child: &mut std::os::unix::net::UnixStream) -> ParentFrame {
        let mut frames = lifecycle_wire::FrameBuffer::default();
        let mut chunk = [0_u8; 512];
        loop {
            let count = std::io::Read::read(child, &mut chunk).expect("read");
            assert_ne!(count, 0, "the client closed the endpoint");
            frames.extend(&chunk[..count]).expect("extend");
            if let Some(frame) = frames.next::<ParentFrame>().expect("decode") {
                return frame;
            }
        }
    }

    /// Poll a synchronous fact for a bounded time.
    async fn eventually(what: &str, ready: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !ready() {
            assert!(tokio::time::Instant::now() < deadline, "never: {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_fence_refuses_new_mutators_but_keeps_admitted_work_joins_and_observation() {
        let machine = Machine::start(
            r#"{"lifecycle": {"nativePause": [{"delayMs": 300, "result": "complete"}]}}"#,
        )
        .await;
        let operation = Uuid::new_v4();
        // Admitted before the fence: its native work and report continue.
        let pending = {
            let vm = machine.vm.clone();
            let request = machine.request(operation, pause(operation, PausePurpose::Initial));
            tokio::spawn(async move { vm.lifecycle(request).await })
        };
        machine
            .until(|control| matches!(control, NativeControl::Pausing { .. }))
            .await;
        // The shutdown path holds here: the fence is closed, the worker lives.
        machine.vm.close_lifecycle_admission();
        let original = pending
            .await
            .expect("join")
            .expect("pause admitted before the fence");
        let generation = paused(&original);
        let replay = machine.pause(operation).await.expect("replay joins");
        assert_eq!(replay.command, original.command);

        // No new mutator reaches the worker: neither a resume of the paused
        // source nor a rights-bearing capture preparation.
        assert_eq!(
            rejected(
                machine
                    .send(Uuid::new_v4(), resume(operation, generation))
                    .await
            ),
            LifecycleRejection::Stopping
        );
        let staging = Staging::new(&machine);
        let capture = Uuid::new_v4();
        assert_eq!(
            rejected(
                machine
                    .rights(
                        capture,
                        prepare(
                            &staging,
                            capture,
                            CapturePauseSource::Acquire,
                            CaptureResumePolicy::ResumeIfAcquired
                        ),
                        staging.rights()
                    )
                    .await
            ),
            LifecycleRejection::Stopping
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_copies(staging.identities().0.ram),
            1,
            "refused duplicates are closed"
        );
        assert_eq!(
            rejected(
                machine
                    .send(
                        Uuid::new_v4(),
                        LifecycleCommand::GetCapture { operation: capture }
                    )
                    .await
            ),
            LifecycleRejection::UnknownCapture,
            "the refused preparation never reached the worker"
        );
        // Observation stays available and the source was never resumed.
        assert_eq!(
            machine.native().await,
            NativeControl::Paused {
                generation,
                owner: NativePauseOwner::User
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_installed_after_the_stop_fence_admits_no_mutator() {
        let slot = LifecycleSlot::default();
        slot.close_admission();
        let (parent, child) = lifecycle_pair().expect("pair");
        let bound = binding();
        let mut child = std::os::unix::net::UnixStream::from(child);
        let (client, _faults) = LifecycleClient::start(parent, bound).expect("client");
        slot.install(client);
        assert!(slot.closed());
        child.write_all(&hello(bound)).expect("hello");
        let client = slot.client().expect("installed");
        let request = |command| LifecycleRequest {
            machine_id: bound.machine_id,
            run_id: bound.run_id,
            request_id: Uuid::new_v4(),
            command,
        };
        let operation = Uuid::new_v4();
        let mut initial = request(pause(operation, PausePurpose::Initial));
        initial.request_id = operation;
        assert_eq!(
            rejected(client.lifecycle(initial, LifecycleRights::None).await),
            LifecycleRejection::Stopping
        );
        // Observation is still sent, and it is the first frame the worker
        // sees: the refused mutator never took a sequence or a frame.
        let observing = {
            let client = client.clone();
            let observe = request(LifecycleCommand::GetControl { target: None });
            tokio::spawn(async move { client.lifecycle(observe, LifecycleRights::None).await })
        };
        let frame = tokio::task::spawn_blocking(move || read_command(&mut child))
            .await
            .expect("reader");
        let ParentFrame::Command {
            sequence, command, ..
        } = frame;
        assert_eq!(sequence.get(), 1);
        assert_eq!(command, LifecycleCommand::GetControl { target: None });
        observing.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_observation_after_an_unreported_preparation_sees_its_effect() {
        use crate::virt::backend::mock::native::ScenarioNative;
        let scratch = scratch();
        let staging = Staging::under(&scratch.0);
        let (parent, child) = lifecycle_pair().expect("pair");
        let bound = binding();
        let scenario = Scenario::from_json(r#"{"lifecycle":{}}"#).expect("scenario");
        crate::krun::worker::lifecycle::serve(
            child,
            bound,
            ScenarioNative::new(scenario.lifecycle.clone(), 1),
            None,
            Box::new(|_| {}),
        )
        .expect("serve");
        let (client, _faults) = LifecycleClient::start(parent, bound).expect("client");
        let request = |request_id, command| LifecycleRequest {
            machine_id: bound.machine_id,
            run_id: bound.run_id,
            request_id,
            command,
        };
        let observe =
            |operation| request(Uuid::new_v4(), LifecycleCommand::GetCapture { operation });
        // Absence is definitive only for a capture the worker never admitted.
        assert_eq!(
            rejected(
                client
                    .lifecycle(observe(Uuid::new_v4()), LifecycleRights::None)
                    .await
            ),
            LifecycleRejection::UnknownCapture
        );
        let operation = Uuid::new_v4();
        let preparing = {
            let client = client.clone();
            let command = request(
                operation,
                prepare(
                    &staging,
                    operation,
                    CapturePauseSource::Acquire,
                    CaptureResumePolicy::ResumeIfAcquired,
                ),
            );
            let rights = staging.rights();
            tokio::spawn(async move { client.lifecycle(command, rights).await })
        };
        // Observe as soon as the preparation is enqueued, before its report:
        // the ordered stream makes the worker admit it first, so a monitor
        // reconciling an unanswered preparation can never see it as absent.
        eventually("the preparation is enqueued", || {
            crate::virt::backend::lifecycle::lock(&client.shared.state).last_sequence == 2
        })
        .await;
        let observed = client
            .lifecycle(observe(operation), LifecycleRights::None)
            .await
            .expect("observation")
            .capture
            .expect("capture facts");
        assert_eq!(observed.progress, CaptureProgress::Prepared);
        assert!(matches!(
            outcome(&preparing.await.expect("join").expect("prepared")),
            CommandOutcome::CapturePrepared { .. }
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn joined_rights_replay_closes_its_duplicates_before_awaiting_the_report() {
        let scratch = scratch();
        let staging = Staging::under(&scratch.0);
        let ram = staging.identities().0.ram;
        let (parent, child) = lifecycle_pair().expect("pair");
        let bound = binding();
        let mut child = std::os::unix::net::UnixStream::from(child);
        let (client, _faults) = LifecycleClient::start(parent, bound).expect("client");
        child.write_all(&hello(bound)).expect("hello");
        let operation = Uuid::new_v4();
        let request = LifecycleRequest {
            machine_id: bound.machine_id,
            run_id: bound.run_id,
            request_id: operation,
            command: prepare(
                &staging,
                operation,
                CapturePauseSource::Acquire,
                CaptureResumePolicy::ResumeIfAcquired,
            ),
        };
        let send = |rights: LifecycleRights| {
            let client = client.clone();
            let request = request.clone();
            tokio::spawn(async move { client.lifecycle(request, rights).await })
        };
        let original = send(staging.rights());
        // The worker end receives the frame; the sent duplicates close.
        let (mut child, frame) = tokio::task::spawn_blocking(move || {
            let frame = read_command(&mut child);
            (child, frame)
        })
        .await
        .expect("reader");
        let ParentFrame::Command { sequence, .. } = frame;
        eventually("the sent duplicates are closed", || open_copies(ram) == 1).await;

        // The worker has not reported: an identity-checked replay joins the
        // retained command and must not hold its duplicates while it waits.
        let replay = send(staging.rights());
        eventually("the joined replay closed its duplicates", || {
            open_copies(ram) == 1
        })
        .await;
        assert!(
            !original.is_finished() && !replay.is_finished(),
            "both callers still await the report"
        );

        let (outputs, pin) = staging.identities();
        let report = lifecycle_wire::encode(&WorkerFrame::Report {
            report: CommandReport {
                key: CommandKey {
                    request_id: operation,
                    kind: CommandKind::PrepareCapture,
                },
                sequence,
                operation,
                state: CommandState::Completed {
                    outcome: CommandOutcome::CapturePrepared { outputs, pin },
                },
            },
            control: ControlObservation::Observed {
                control: NativeControl::Running,
            },
        })
        .expect("report");
        child.write_all(&report).expect("report");
        let original = original.await.expect("join").expect("prepared");
        let replay = replay.await.expect("join").expect("replayed");
        assert!(matches!(
            outcome(&original),
            CommandOutcome::CapturePrepared { .. }
        ));
        assert_eq!(replay.command, original.command);
        assert_eq!(open_copies(ram), 1);
        assert_eq!(
            crate::virt::backend::lifecycle::lock(&client.shared.state).last_sequence,
            1,
            "the replay never resent"
        );
    }
}
