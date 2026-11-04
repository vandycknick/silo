//! Process, filesystem-cursor, forward-listener and held-session operations.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use protocol::v1;
use protocol::v1::guest_forward_service_client::GuestForwardServiceClient;
use protocol::v1::guest_process_service_client::GuestProcessServiceClient;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::attach::dto::{
    enum_name, hex, monotonic_ns, unhex, Checks, Content, EnvironmentVariable, ExpectRpc,
    ListenRegistration, RpcError, RpcOutcome,
};
use crate::attach::observe::Guest;

const MAX_OUTPUT_BYTES: u32 = 1024 * 1024;
const MAX_EXEC_TIMEOUT_MS: u32 = 600_000;
const KILL_DRAIN: Duration = Duration::from_secs(5);
const SIGKILL: u32 = 9;

/// Exactly the generated `StartGuestProcess` with pipe stdio.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessStart {
    pub(crate) execution_id: String,
    pub(crate) expected_agent_instance_id: String,
    pub(crate) expected_agent_boot_id: String,
    pub(crate) argv: Vec<String>,
    #[serde(default)]
    pub(crate) working_directory: Option<String>,
    #[serde(default)]
    pub(crate) user: Option<String>,
    #[serde(default)]
    pub(crate) environment: Vec<EnvironmentVariable>,
}

impl ProcessStart {
    fn to_wire(&self, stdin: bool) -> v1::GuestProcessInput {
        v1::GuestProcessInput {
            message: Some(v1::guest_process_input::Message::Start(
                v1::StartGuestProcess {
                    execution_id: self.execution_id.clone(),
                    expected_agent_instance_id: self.expected_agent_instance_id.clone(),
                    expected_agent_boot_id: self.expected_agent_boot_id.clone(),
                    process: Some(v1::ProcessSpec {
                        argv: self.argv.clone(),
                        working_directory: self.working_directory.clone(),
                        user: self.user.clone(),
                        environment: self.environment.iter().map(Into::into).collect(),
                        stdio: Some(v1::process_spec::Stdio::Pipes(v1::PipeStdio { stdin })),
                    }),
                },
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecOperation {
    pub(crate) start: ProcessStart,
    #[serde(default)]
    pub(crate) stdin_hex: Option<String>,
    pub(crate) timeout_ms: u32,
    pub(crate) max_output_bytes: u32,
    #[serde(default)]
    pub(crate) expect_rpc: ExpectRpc,
    #[serde(default)]
    pub(crate) expect_exit_code: Option<u32>,
}

impl ExecOperation {
    pub(crate) fn validate(&self) -> eyre::Result<()> {
        eyre::ensure!(
            (1..=MAX_EXEC_TIMEOUT_MS).contains(&self.timeout_ms),
            "exec timeout_ms must be 1..={MAX_EXEC_TIMEOUT_MS}"
        );
        eyre::ensure!(
            (1..=MAX_OUTPUT_BYTES).contains(&self.max_output_bytes),
            "exec max_output_bytes must be 1..={MAX_OUTPUT_BYTES}"
        );
        if let Some(stdin) = &self.stdin_hex {
            eyre::ensure!(
                stdin.len() / 2 <= MAX_OUTPUT_BYTES as usize,
                "oversized stdin"
            );
            unhex(stdin)?;
        }
        Ok(())
    }
}

/// Unary-style record for one streaming RPC: its terminal transport outcome.
#[derive(Debug, Serialize)]
pub(crate) struct StreamRecord {
    pub(crate) outcome: RpcOutcome,
    pub(crate) started_monotonic_ns: u64,
    pub(crate) finished_monotonic_ns: u64,
    pub(crate) request_debug: String,
    pub(crate) error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
pub(crate) struct LaunchFailed {
    pub(crate) reason: Option<String>,
    pub(crate) message: Option<String>,
}

/// Bounded output capture: keeps the first `limit` bytes, counts all of them.
#[derive(Debug)]
struct Capture {
    bytes: Vec<u8>,
    total: u64,
    limit: usize,
}

impl Capture {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            total: 0,
            limit,
        }
    }
    fn push(&mut self, data: &[u8]) {
        self.total = self.total.saturating_add(data.len() as u64);
        let room = self.limit.saturating_sub(self.bytes.len());
        self.bytes.extend_from_slice(&data[..data.len().min(room)]);
    }
    fn truncated(&self) -> bool {
        self.total > self.bytes.len() as u64
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ProcessOutcome {
    pub(crate) started: bool,
    pub(crate) launch_failed: Option<LaunchFailed>,
    pub(crate) exit_code: Option<u32>,
    pub(crate) signal: Option<u32>,
    pub(crate) stdout: Content,
    pub(crate) stderr: Content,
    pub(crate) stdout_bytes: u64,
    pub(crate) stderr_bytes: u64,
    pub(crate) output_truncated: bool,
    pub(crate) timed_out: bool,
}

/// Folds process events; returns true for a terminal event.
fn apply_event(
    event: v1::GuestProcessEvent,
    started: &mut bool,
    stdout: &mut Capture,
    stderr: &mut Capture,
    terminal: &mut Option<Terminal>,
) -> bool {
    use v1::guest_process_event::Event;
    match event.event {
        Some(Event::Started(_)) => {
            *started = true;
            false
        }
        Some(Event::Stdout(output)) => {
            stdout.push(&output.data);
            false
        }
        Some(Event::TerminalOutput(output)) => {
            stdout.push(&output.data);
            false
        }
        Some(Event::Stderr(output)) => {
            stderr.push(&output.data);
            false
        }
        Some(Event::Exited(exited)) => {
            *terminal = Some(Terminal::Exited(exited.code));
            true
        }
        Some(Event::Signaled(signaled)) => {
            *terminal = Some(Terminal::Signaled(signaled.signal));
            true
        }
        Some(Event::LaunchFailed(failed)) => {
            *terminal = Some(Terminal::LaunchFailed(LaunchFailed {
                reason: failed.reason.map(|reason| {
                    enum_name(
                        v1::LaunchFailureReason::try_from(reason)
                            .ok()
                            .map(|value| value.as_str_name()),
                        "LAUNCH_FAILURE_REASON_",
                        reason,
                    )
                }),
                message: failed.message,
            }));
            true
        }
        None => false,
    }
}

#[derive(Debug)]
enum Terminal {
    Exited(Option<u32>),
    Signaled(Option<u32>),
    LaunchFailed(LaunchFailed),
}

#[derive(Debug, Serialize)]
pub(crate) struct ExecOutput {
    pub(crate) rpc: StreamRecord,
    pub(crate) process: ProcessOutcome,
}

pub(crate) async fn exec(
    guest: &Guest,
    operation: &ExecOperation,
    checks: &mut Checks,
) -> eyre::Result<ExecOutput> {
    let stdin = operation.stdin_hex.as_deref().map(unhex).transpose()?;
    let start = operation.start.to_wire(stdin.is_some());
    let request_debug = format!("{start:?}");
    let (sender, receiver) = mpsc::channel(8);
    sender.send(start).await?;
    if let Some(stdin) = stdin {
        sender
            .send(v1::GuestProcessInput {
                message: Some(v1::guest_process_input::Message::StdinData(v1::StdinData {
                    data: stdin.into(),
                })),
            })
            .await?;
        sender
            .send(v1::GuestProcessInput {
                message: Some(v1::guest_process_input::Message::CloseStdin(
                    v1::CloseStdin {},
                )),
            })
            .await?;
    }
    let limit = operation.max_output_bytes as usize;
    let (mut stdout, mut stderr) = (Capture::new(limit), Capture::new(limit));
    let (mut started, mut terminal, mut timed_out, mut error) = (false, None, false, None);
    let started_ns = monotonic_ns()?;
    let mut processes = GuestProcessServiceClient::new(guest.channel())
        .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
        .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
    match processes
        .execute(tokio_stream::wrappers::ReceiverStream::new(receiver))
        .await
    {
        Err(status) => error = Some(RpcError::from(&status)),
        Ok(response) => {
            let mut events = response.into_inner();
            let deadline = tokio::time::Instant::now()
                + Duration::from_millis(u64::from(operation.timeout_ms));
            let mut killed_at = None;
            loop {
                let bound = killed_at.unwrap_or(deadline);
                match tokio::time::timeout_at(bound, events.message()).await {
                    Ok(Ok(Some(event))) => {
                        if apply_event(event, &mut started, &mut stdout, &mut stderr, &mut terminal)
                        {
                            break;
                        }
                    }
                    Ok(Ok(None)) => break,
                    Ok(Err(status)) => {
                        error = Some(RpcError::from(&status));
                        break;
                    }
                    Err(_) if killed_at.is_none() => {
                        timed_out = true;
                        sender
                            .send(v1::GuestProcessInput {
                                message: Some(v1::guest_process_input::Message::SignalProcess(
                                    v1::SignalProcess {
                                        signal: Some(SIGKILL),
                                    },
                                )),
                            })
                            .await?;
                        killed_at = Some(tokio::time::Instant::now() + KILL_DRAIN);
                    }
                    Err(_) => eyre::bail!("guest process ignored SIGKILL for {KILL_DRAIN:?}"),
                }
            }
        }
    }
    let finished_ns = monotonic_ns()?;
    let rpc = StreamRecord {
        outcome: if error.is_some() {
            RpcOutcome::Error
        } else {
            RpcOutcome::Ok
        },
        started_monotonic_ns: started_ns,
        finished_monotonic_ns: finished_ns,
        request_debug,
        error,
    };
    operation
        .expect_rpc
        .evaluate(rpc.error.as_ref().map_or(Ok(()), Err), checks);
    let (exit_code, signal, launch_failed) = match terminal {
        Some(Terminal::Exited(code)) => (code, None, None),
        Some(Terminal::Signaled(signal)) => (None, signal, None),
        Some(Terminal::LaunchFailed(failed)) => (None, None, Some(failed)),
        None => (None, None, None),
    };
    if let Some(expected) = operation.expect_exit_code {
        checks.check(
            "exit_code",
            exit_code == Some(expected) && !timed_out,
            format!(
                "expected {expected}, got {exit_code:?} signal {signal:?} timed_out {timed_out}"
            ),
        );
    }
    Ok(ExecOutput {
        rpc,
        process: ProcessOutcome {
            started,
            launch_failed,
            exit_code,
            signal,
            output_truncated: stdout.truncated() || stderr.truncated(),
            stdout: Content::new(&stdout.bytes),
            stderr: Content::new(&stderr.bytes),
            stdout_bytes: stdout.total,
            stderr_bytes: stderr.total,
            timed_out,
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListDirectoryOperation {
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) limit: Option<u32>,
    #[serde(default)]
    pub(crate) cursor_hex: Option<String>,
    #[serde(default)]
    pub(crate) expect_rpc: ExpectRpc,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListedEntry {
    pub(crate) path: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) kind: Option<String>,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) mode: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Page {
    pub(crate) entries: Vec<ListedEntry>,
    pub(crate) next_cursor_hex: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListDirectoryOutput {
    pub(crate) rpc: StreamRecord,
    pub(crate) page: Option<Page>,
}

pub(crate) async fn list_directory(
    guest: &Guest,
    operation: &ListDirectoryOperation,
    checks: &mut Checks,
) -> eyre::Result<ListDirectoryOutput> {
    let request = v1::ListDirectoryRequest {
        path: Some(operation.path.clone()),
        limit: operation.limit,
        cursor: operation.cursor_hex.as_deref().map(unhex).transpose()?,
    };
    let started = monotonic_ns()?;
    let result = guest.files().list_directory(request.clone()).await;
    let finished = monotonic_ns()?;
    let (page, error) = match result {
        Ok(response) => {
            let page = response.into_inner();
            (
                Some(Page {
                    entries: page
                        .entries
                        .into_iter()
                        .map(|entry| ListedEntry {
                            kind: entry.kind.map(|kind| {
                                enum_name(
                                    v1::FilesystemEntryKind::try_from(kind)
                                        .ok()
                                        .map(|value| value.as_str_name()),
                                    "FILESYSTEM_ENTRY_KIND_",
                                    kind,
                                )
                            }),
                            path: entry.path,
                            name: entry.name,
                            size_bytes: entry.size_bytes,
                            mode: entry.mode,
                        })
                        .collect(),
                    next_cursor_hex: page.next_cursor.as_deref().map(hex),
                }),
                None,
            )
        }
        Err(status) => (None, Some(RpcError::from(&status))),
    };
    operation
        .expect_rpc
        .evaluate(error.as_ref().map_or(Ok(()), Err), checks);
    Ok(ListDirectoryOutput {
        rpc: StreamRecord {
            outcome: if error.is_some() {
                RpcOutcome::Error
            } else {
                RpcOutcome::Ok
            },
            started_monotonic_ns: started,
            finished_monotonic_ns: finished,
            request_debug: format!("{request:?}"),
            error,
        },
        page,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenOperation {
    pub(crate) registration: ListenRegistration,
    #[serde(default)]
    pub(crate) expect_rpc: ExpectRpc,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListenFailure {
    pub(crate) error_code: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct ListenEvent {
    pub(crate) bound: Option<String>,
    pub(crate) failed: Option<ListenFailure>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListenOutput {
    pub(crate) rpc: StreamRecord,
    pub(crate) event: Option<ListenEvent>,
}

fn listen_event(event: v1::ListenEvent) -> ListenEvent {
    match event.event {
        Some(v1::listen_event::Event::Bound(bound)) => ListenEvent {
            bound: Some(bound.address),
            failed: None,
        },
        Some(v1::listen_event::Event::Failed(failed)) => ListenEvent {
            bound: None,
            failed: Some(ListenFailure {
                error_code: failed.error.and_then(|error| error.code).map(|code| {
                    v1::ErrorCode::try_from(code)
                        .map(|code| code.as_str_name().to_string())
                        .unwrap_or_else(|_| format!("unknown({code})"))
                }),
            }),
        },
        None => ListenEvent::default(),
    }
}

/// Opens one ordinary Listen stream and returns its first event; the listener
/// exists only while the returned stream is held.
async fn open_listener(
    guest: &Guest,
    registration: &ListenRegistration,
) -> eyre::Result<(
    StreamRecord,
    Option<ListenEvent>,
    Option<tonic::Streaming<v1::ListenEvent>>,
)> {
    let request = registration.to_wire()?;
    let request_debug = format!("{request:?}");
    let started = monotonic_ns()?;
    let mut client = GuestForwardServiceClient::new(guest.channel());
    let result = match client.listen(request).await {
        Ok(response) => {
            let mut stream = response.into_inner();
            match stream.message().await {
                Ok(Some(event)) => Ok((Some(listen_event(event)), Some(stream))),
                Ok(None) => Ok((None, None)),
                Err(status) => Err(status),
            }
        }
        Err(status) => Err(status),
    };
    let finished = monotonic_ns()?;
    Ok(match result {
        Ok((event, stream)) => (
            StreamRecord {
                outcome: RpcOutcome::Ok,
                started_monotonic_ns: started,
                finished_monotonic_ns: finished,
                request_debug,
                error: None,
            },
            event,
            stream,
        ),
        Err(status) => (
            StreamRecord {
                outcome: RpcOutcome::Error,
                started_monotonic_ns: started,
                finished_monotonic_ns: finished,
                request_debug,
                error: Some(RpcError::from(&status)),
            },
            None,
            None,
        ),
    })
}

pub(crate) async fn listen(
    guest: &Guest,
    operation: &ListenOperation,
    checks: &mut Checks,
) -> eyre::Result<ListenOutput> {
    let (rpc, event, stream) = open_listener(guest, &operation.registration).await?;
    drop(stream);
    operation
        .expect_rpc
        .evaluate(rpc.error.as_ref().map_or(Ok(()), Err), checks);
    if matches!(operation.expect_rpc, ExpectRpc::Ok) {
        checks.check(
            "listener_bound",
            event.as_ref().is_some_and(|event| event.bound.is_some()),
            format!("{event:?}"),
        );
    }
    Ok(ListenOutput { rpc, event })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshHold {
    pub(crate) fd: i32,
    pub(crate) host_public_key: String,
    pub(crate) private_key: PathBuf,
    pub(crate) certificate: PathBuf,
    pub(crate) user: String,
    pub(crate) command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HoldOperation {
    #[serde(default)]
    pub(crate) process: Option<ProcessStart>,
    #[serde(default)]
    pub(crate) ssh: Option<SshHold>,
    #[serde(default)]
    pub(crate) listen: Option<ListenRegistration>,
}

impl HoldOperation {
    pub(crate) fn validate(&self, attach_fd: i32) -> eyre::Result<()> {
        eyre::ensure!(
            self.process.is_some() || self.ssh.is_some() || self.listen.is_some(),
            "hold requires at least one session"
        );
        if let Some(ssh) = &self.ssh {
            eyre::ensure!(ssh.fd != attach_fd, "hold.ssh.fd must differ from fd");
        }
        Ok(())
    }
}

/// What a held session did before its owner released it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeldEnd {
    pub(crate) ended_before_release: bool,
    pub(crate) end: Option<String>,
    pub(crate) end_monotonic_ns: Option<u64>,
    pub(crate) output_bytes: u64,
}

#[derive(Debug, Default)]
struct HeldState {
    end: Option<(String, u64)>,
    output_bytes: u64,
}

type Held = Arc<std::sync::Mutex<HeldState>>;

fn mark_end(state: &Held, end: String) {
    let at = monotonic_ns().unwrap_or(0);
    if let Ok(mut state) = state.lock() {
        if state.end.is_none() {
            state.end = Some((end, at));
        }
    }
}

fn add_output(state: &Held, bytes: usize) {
    if let Ok(mut state) = state.lock() {
        state.output_bytes = state.output_bytes.saturating_add(bytes as u64);
    }
}

fn held_end(state: &Held) -> HeldEnd {
    match state.lock() {
        Ok(state) => HeldEnd {
            ended_before_release: state.end.is_some(),
            end: state.end.as_ref().map(|(end, _)| end.clone()),
            end_monotonic_ns: state.end.as_ref().map(|(_, at)| *at),
            output_bytes: state.output_bytes,
        },
        Err(_) => HeldEnd {
            ended_before_release: false,
            end: Some("held-state lock poisoned".to_string()),
            end_monotonic_ns: None,
            output_bytes: 0,
        },
    }
}

/// Records what a held process stream did until its owner releases it.
async fn watch_process(mut events: tonic::Streaming<v1::GuestProcessEvent>, state: Held) {
    use v1::guest_process_event::Event;
    loop {
        match events.message().await {
            Ok(Some(event)) => match &event.event {
                Some(Event::Stdout(output)) => add_output(&state, output.data.len()),
                Some(Event::Stderr(output)) => add_output(&state, output.data.len()),
                Some(Event::Exited(_) | Event::Signaled(_) | Event::LaunchFailed(_)) => {
                    mark_end(&state, format!("{event:?}"));
                    return;
                }
                _ => {}
            },
            Ok(None) => {
                mark_end(&state, "stream ended".to_string());
                return;
            }
            Err(status) => {
                mark_end(&state, format!("{:?}", RpcError::from(&status)));
                return;
            }
        }
    }
}

/// Records what a held SSH exec channel did until its owner releases it.
async fn watch_ssh(mut channel: russh::Channel<russh::client::Msg>, state: Held) {
    while let Some(message) = channel.wait().await {
        match &message {
            russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                add_output(&state, data.len())
            }
            russh::ChannelMsg::ExitStatus { .. }
            | russh::ChannelMsg::ExitSignal { .. }
            | russh::ChannelMsg::Close => {
                mark_end(&state, format!("{message:?}"));
                return;
            }
            _ => {}
        }
    }
    mark_end(&state, "channel ended".to_string());
}

#[derive(Debug, Serialize)]
pub(crate) struct HeldProcess {
    pub(crate) rpc: StreamRecord,
    pub(crate) started: bool,
    pub(crate) first_event: Option<String>,
    pub(crate) end: Option<HeldEnd>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HeldSsh {
    pub(crate) source_port: Option<u32>,
    pub(crate) exec_started: bool,
    pub(crate) failure: Option<String>,
    pub(crate) end: Option<HeldEnd>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HeldListener {
    pub(crate) rpc: StreamRecord,
    pub(crate) event: Option<ListenEvent>,
    pub(crate) end: Option<HeldEnd>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Release {
    StdinLine,
    StdinEof,
    Deadline,
    NotReady,
}

#[derive(Debug, Serialize)]
pub(crate) struct HoldOutput {
    pub(crate) process: Option<HeldProcess>,
    pub(crate) ssh: Option<HeldSsh>,
    pub(crate) listen: Option<HeldListener>,
    pub(crate) ready_monotonic_ns: Option<u64>,
    pub(crate) release: Release,
    pub(crate) release_monotonic_ns: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Ready<'a> {
    pub(crate) record: &'static str,
    pub(crate) monotonic_ns: u64,
    pub(crate) process_started: bool,
    pub(crate) ssh_exec_started: bool,
    pub(crate) listen_bound: Option<&'a str>,
}

/// Starts every requested session, announces readiness, then holds them
/// until the owner writes a line, closes stdin, or the deadline arrives.
/// Sessions are only dropped on release; nothing is signalled.
pub(crate) async fn hold(
    guest: &Guest,
    operation: &HoldOperation,
    deadline: tokio::time::Instant,
    ready: impl FnOnce(&Ready<'_>) -> eyre::Result<()>,
    checks: &mut Checks,
) -> eyre::Result<HoldOutput> {
    let mut tasks = Vec::new();
    let mut all_started = true;

    let mut process = None;
    let mut process_sender = None;
    if let Some(start) = &operation.process {
        let wire = start.to_wire(false);
        let request_debug = format!("{wire:?}");
        let (sender, receiver) = mpsc::channel(4);
        sender.send(wire).await?;
        let started_ns = monotonic_ns()?;
        let mut client = GuestProcessServiceClient::new(guest.channel());
        let call = client
            .execute(tokio_stream::wrappers::ReceiverStream::new(receiver))
            .await;
        let (mut started, mut first_event, mut error, mut end) = (false, None, None, None);
        match call {
            Err(status) => error = Some(RpcError::from(&status)),
            Ok(response) => {
                let mut events = response.into_inner();
                match events.message().await {
                    Ok(Some(event)) => {
                        first_event = Some(format!("{event:?}"));
                        started = matches!(
                            event.event,
                            Some(v1::guest_process_event::Event::Started(_))
                        );
                        if started {
                            let state = Held::default();
                            end = Some(state.clone());
                            tasks.push(tokio::spawn(watch_process(events, state)));
                        }
                    }
                    Ok(None) => first_event = Some("stream ended before start".to_string()),
                    Err(status) => error = Some(RpcError::from(&status)),
                }
            }
        }
        all_started &= started;
        process_sender = Some(sender);
        process = Some((
            HeldProcess {
                rpc: StreamRecord {
                    outcome: if error.is_some() {
                        RpcOutcome::Error
                    } else {
                        RpcOutcome::Ok
                    },
                    started_monotonic_ns: started_ns,
                    finished_monotonic_ns: monotonic_ns()?,
                    request_debug,
                    error,
                },
                started,
                first_event,
                end: None,
            },
            end,
        ));
    }

    let mut ssh = None;
    let mut ssh_owner = None;
    if let Some(request) = &operation.ssh {
        match start_ssh(request).await {
            Ok((source_port, handle, channel)) => {
                let state = Held::default();
                tasks.push(tokio::spawn(watch_ssh(channel, state.clone())));
                ssh_owner = Some(handle);
                ssh = Some((
                    HeldSsh {
                        source_port: Some(source_port),
                        exec_started: true,
                        failure: None,
                        end: None,
                    },
                    Some(state),
                ));
            }
            Err(error) => {
                all_started = false;
                ssh = Some((
                    HeldSsh {
                        source_port: None,
                        exec_started: false,
                        failure: Some(format!("{error:#}")),
                        end: None,
                    },
                    None,
                ));
            }
        }
    }

    let mut listen = None;
    if let Some(registration) = &operation.listen {
        let (rpc, event, stream) = open_listener(guest, registration).await?;
        let bound = event.as_ref().is_some_and(|event| event.bound.is_some());
        all_started &= bound;
        let mut end = None;
        if let (true, Some(mut stream)) = (bound, stream) {
            let state = Held::default();
            end = Some(state.clone());
            tasks.push(tokio::spawn(async move {
                match stream.message().await {
                    Ok(Some(event)) => mark_end(&state, format!("{event:?}")),
                    Ok(None) => mark_end(&state, "stream ended".to_string()),
                    Err(status) => mark_end(&state, format!("{:?}", RpcError::from(&status))),
                }
            }));
        }
        listen = Some((
            HeldListener {
                rpc,
                event,
                end: None,
            },
            end,
        ));
    }

    checks.check(
        "sessions_started",
        all_started,
        "every requested held session started before readiness",
    );
    let (ready_monotonic_ns, release) = if all_started {
        let at = monotonic_ns()?;
        ready(&Ready {
            record: "ready",
            monotonic_ns: at,
            process_started: process.as_ref().is_some_and(|(held, _)| held.started),
            ssh_exec_started: ssh.as_ref().is_some_and(|(held, _)| held.exec_started),
            listen_bound: listen
                .as_ref()
                .and_then(|(held, _)| held.event.as_ref())
                .and_then(|event| event.bound.as_deref()),
        })?;
        // tokio's `io-std` feature is not enabled for silo-vmm; read on the
        // blocking pool. The attach runtime shuts down in the background, so a
        // still-blocked reader never delays exit after a deadline release.
        let reader = tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
        });
        let release = match tokio::time::timeout_at(deadline, reader).await {
            Ok(Ok(Ok(0))) => Release::StdinEof,
            Ok(Ok(Ok(_))) => Release::StdinLine,
            Ok(Ok(Err(error))) => return Err(error.into()),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => Release::Deadline,
        };
        checks.check(
            "released_by_owner",
            release != Release::Deadline,
            format!("{release:?}"),
        );
        (Some(at), release)
    } else {
        (None, Release::NotReady)
    };
    let release_monotonic_ns = monotonic_ns()?;
    // Snapshot what happened while held, then drop every session.
    let finish = |held: Option<Held>| held.as_ref().map(held_end);
    let process = process.map(|(mut held, state)| {
        held.end = finish(state);
        held
    });
    let ssh = ssh.map(|(mut held, state)| {
        held.end = finish(state);
        held
    });
    let listen = listen.map(|(mut held, state)| {
        held.end = finish(state);
        held
    });
    for task in tasks {
        task.abort();
    }
    drop(process_sender);
    drop(ssh_owner);
    Ok(HoldOutput {
        process,
        ssh,
        listen,
        ready_monotonic_ns,
        release,
        release_monotonic_ns,
    })
}

/// SSH over a second inherited native mux stream (guest port 22), using the
/// cold fixture's pinned host key and CA-certificate authentication.
async fn start_ssh(
    request: &SshHold,
) -> eyre::Result<(
    u32,
    russh::client::Handle<crate::SshKey>,
    russh::Channel<russh::client::Msg>,
)> {
    let key = russh::keys::PublicKey::from_openssh(&request.host_public_key)?;
    let private = Arc::new(russh::keys::PrivateKey::read_openssh_file(
        &request.private_key,
    )?);
    let certificate = russh::keys::ssh_key::Certificate::from_openssh(&std::fs::read_to_string(
        &request.certificate,
    )?)?;
    let (stream, source_port) = crate::attach::connection::open(request.fd).await?;
    let mut client = russh::client::connect_stream(
        Arc::new(Default::default()),
        stream,
        crate::SshKey { expected: key },
    )
    .await?;
    eyre::ensure!(
        client
            .authenticate_openssh_cert(request.user.clone(), private, certificate)
            .await?
            .success(),
        "SSH CA authentication failed"
    );
    let mut channel = client.channel_open_session().await?;
    channel.exec(true, request.command.clone()).await?;
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Success) => return Ok((source_port, client, channel)),
            Some(russh::ChannelMsg::Failure) => eyre::bail!("SSH exec request refused"),
            Some(
                russh::ChannelMsg::WindowAdjusted { .. }
                | russh::ChannelMsg::XonXoff { .. }
                | russh::ChannelMsg::Data { .. }
                | russh::ChannelMsg::ExtendedData { .. },
            ) => {}
            Some(other) => eyre::bail!("unexpected SSH message before exec reply: {other:?}"),
            None => eyre::bail!("SSH channel closed before exec reply"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::attach::session::{
        apply_event, Capture, ExecOperation, HoldOperation, ProcessStart, Terminal,
    };
    use protocol::v1;

    fn start() -> ProcessStart {
        ProcessStart {
            execution_id: "x".into(),
            expected_agent_instance_id: "i".into(),
            expected_agent_boot_id: "b".into(),
            argv: vec!["/bin/true".into()],
            working_directory: Some("/".into()),
            user: Some("root".into()),
            environment: Vec::new(),
        }
    }

    #[test]
    fn capture_keeps_prefix_and_counts_everything() {
        let mut capture = Capture::new(4);
        capture.push(b"abc");
        capture.push(b"def");
        assert_eq!(capture.bytes, b"abcd");
        assert_eq!(capture.total, 6);
        assert!(capture.truncated());
        let mut exact = Capture::new(3);
        exact.push(b"abc");
        assert!(!exact.truncated());
    }

    #[test]
    fn process_events_fold_to_one_terminal_outcome() {
        use v1::guest_process_event::Event;
        let (mut started, mut terminal) = (false, None);
        let (mut stdout, mut stderr) = (Capture::new(16), Capture::new(16));
        let mut fold = |event| {
            apply_event(
                v1::GuestProcessEvent { event: Some(event) },
                &mut started,
                &mut stdout,
                &mut stderr,
                &mut terminal,
            )
        };
        assert!(!fold(Event::Started(v1::GuestProcessStarted {})));
        assert!(!fold(Event::Stdout(v1::GuestProcessStdout {
            data: bytes::Bytes::from_static(b"out")
        })));
        assert!(!fold(Event::Stderr(v1::GuestProcessStderr {
            data: bytes::Bytes::from_static(b"err")
        })));
        assert!(fold(Event::Exited(v1::GuestProcessExited {
            code: Some(3)
        })));
        assert!(started);
        assert_eq!(stdout.bytes, b"out");
        assert_eq!(stderr.bytes, b"err");
        assert!(matches!(terminal, Some(Terminal::Exited(Some(3)))));
    }

    #[test]
    fn exec_and_hold_requests_are_bounded() {
        let mut operation = ExecOperation {
            start: start(),
            stdin_hex: None,
            timeout_ms: 1000,
            max_output_bytes: 1024,
            expect_rpc: Default::default(),
            expect_exit_code: Some(0),
        };
        operation.validate().unwrap();
        operation.timeout_ms = 0;
        assert!(operation.validate().is_err());
        operation.timeout_ms = 1000;
        operation.stdin_hex = Some("0".into());
        assert!(operation.validate().is_err());
        let empty: HoldOperation = serde_json::from_str("{}").unwrap();
        assert!(empty.validate(3).is_err());
    }
}
