//! Guest streams retain VM lifecycle ownership in the daemon. Each stream refreshes
//! identity, ownership and its action every 30 seconds; session loss cancels only
//! that attachment or execution. Management owns bounded log-tail line alignment.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::StreamExt;
use libvm::{
    ExecutionEvent, ExecutionLaunchFailureReason, ExecutionResult, Machine, MachineRef,
    SshShellAttachment, SshShellControl, SshShellSignal,
};
use silod_spec::daemon::v1 as w;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::daemon::control::lobby::categorize;
use crate::lobby::caller::Caller;
use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::identity::Action;
use crate::lobby::metrics::Handle;
use crate::lobby::service::guest_identity::guest_identity;
use crate::lobby::service::Service;
use crate::lobby::session::{SessionExtras, SessionIo, Signal, Terminal, Window};

const STREAM_RECHECK: Duration = Duration::from_secs(30);
const LOG_LIMIT: u64 = 4 << 20;
const CHUNK: usize = 64 << 10;

#[derive(Default)]
pub(crate) struct ExecRequest {
    pub(crate) user: String,
    pub(crate) directory: String,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) tty: bool,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

#[derive(Default)]
pub(crate) struct LogsRequest {
    pub(crate) follow: bool,
    pub(crate) source: String,
    pub(crate) output: String,
}

impl Service {
    pub(crate) async fn shell(
        &self,
        caller: &Caller,
        reference: &str,
        user: &str,
        io: &mut SessionIo,
        _extras: &SessionExtras,
    ) -> Outcome<i32> {
        let (window, term) = terminal(io.terminal.as_ref(), "shell requires a PTY; use ssh -t")?;
        if !text(user) {
            return Err(usage("invalid execution request"));
        }
        let peer = caller.fresh().await?;
        let snapshot = self.inspect_for(&peer, reference, Action::Shell).await?;
        ensure_running(&snapshot)?;
        let user = selected_user(user, &snapshot);
        let cancel = io.cancel.clone();
        self.run_stream(
            caller,
            &snapshot.id.clone(),
            Action::Shell,
            &cancel,
            |token| async move {
                let machine = tokio::select! {
                    biased;
                    _ = token.cancelled() => return Err(cancelled()),
                    machine = self.guest_machine(&snapshot.id) => machine?,
                };
                let _execution = self.jobs().metrics().track("exec", ());
                attached_shell(&machine, user, term, window, io, token).await
            },
        )
        .await
    }

    pub(crate) async fn exec(
        &self,
        caller: &Caller,
        reference: &str,
        mut request: ExecRequest,
        io: &mut SessionIo,
    ) -> Outcome<i32> {
        validate_exec(&request)?;
        let pty = if request.tty {
            Some(terminal(
                io.terminal.as_ref(),
                "-t requires a PTY; use ssh -t",
            )?)
        } else {
            None
        };
        let peer = caller.fresh().await?;
        let snapshot = self.inspect_for(&peer, reference, Action::Exec).await?;
        ensure_running(&snapshot)?;
        request.user = selected_user(&request.user, &snapshot);
        let cancel = io.cancel.clone();
        self.run_stream(caller, &snapshot.id.clone(), Action::Exec, &cancel, |token| async move {
            let execution = async {
                let machine = self.guest_machine(&snapshot.id).await?;
                let account = guest_identity(&machine, &request.user, snapshot.guest.as_ref().and_then(|guest| guest.user.as_ref())).await?;
                let mut env = BTreeMap::new();
                if !account.name.is_empty() {
                    env.insert("HOME".to_owned(), account.home.clone());
                    env.insert("USER".to_owned(), account.name.clone());
                    env.insert("LOGNAME".to_owned(), account.name);
                    env.insert("SHELL".to_owned(), account.shell);
                }
                env.extend(request.env);
                if request.directory.is_empty() { request.directory = account.home; }
                let process = machine.spawn_with(request.program, |options| {
                    let mut options = options.args(request.args).user(request.user).cwd(request.directory).envs(env).stdin_pipe().tty(request.tty);
                    if let Some((size, term)) = pty { options = options.initial_pty_size(size.rows, size.columns).term(term); }
                    options
                }).await.map_err(native_failure)?;
                let mut process = self.jobs().metrics().track("exec", process);
                let done = token.child_token();
                let control = process.control();
                let (started, ready) = watch::channel(false);
                let input = async {
                    let mut ready = ready;
                    if ready.wait_for(|ready| *ready).await.is_err() { return; }
                    let mut buffer = vec![0; CHUNK];
                    loop {
                        match io.stdin.read(&mut buffer).await {
                            Ok(0) => {
                                if request.tty { let _ = control.write_stdin(vec![4, 4]).await; }
                                else { let _ = control.close_stdin().await; }
                                return;
                            }
                            Ok(count) => if control.write_stdin(buffer[..count].to_vec()).await.is_err() { return; },
                            Err(_) => { control.close_requests(); return; }
                        }
                    }
                };
                let controls = async {
                    let mut ready = started.subscribe();
                    if ready.wait_for(|ready| *ready).await.is_err() { return; }
                    let mut windows = io.terminal.as_ref().map(|terminal| terminal.window.clone());
                    let mut signals_open = true;
                    loop {
                        tokio::select! {
                            size = next_window(&mut windows), if request.tty && windows.is_some() => {
                                if let Some(size) = size { let _ = control.resize_pty(size.rows, size.columns).await; }
                            }
                            signal = io.signals.recv(), if signals_open => match signal {
                                Some(signal) => { let _ = control.signal(linux_signal(signal)).await; }
                                None => signals_open = false,
                            },
                            else => return,
                        }
                    }
                };
                let receive = async {
                    let result = loop {
                        match process.recv().await {
                            Ok(Some(ExecutionEvent::Started)) => { started.send_replace(true); }
                            Ok(Some(ExecutionEvent::Stdout(data) | ExecutionEvent::TerminalOutput(data))) => io.stdout.write_all(&data).await.map_err(|_| lost("guest output transport failed"))?,
                            Ok(Some(ExecutionEvent::Stderr(data))) => io.stderr.write_all(&data).await.map_err(|_| lost("guest output transport failed"))?,
                            Ok(Some(ExecutionEvent::Terminal(result))) => break execution_status(result),
                            Ok(Some(ExecutionEvent::Accepted)) => {},
                            Ok(None) | Err(_) => break Err(lost("guest execution stream lost")),
                        }
                    };
                    io.stdout.flush().await.map_err(|_| lost("guest output transport failed"))?;
                    io.stderr.flush().await.map_err(|_| lost("guest output transport failed"))?;
                    result
                };
                let receive = async { let result = receive.await; done.cancel(); result };
                let input = async { tokio::select! { biased; _ = done.cancelled() => {}, _ = input => {} } };
                let controls = async { tokio::select! { biased; _ = done.cancelled() => {}, _ = controls => {} } };
                let (result, (), ()) = tokio::join!(receive, input, controls);
                result
            };
            tokio::select! { biased; _ = token.cancelled() => Err(cancelled()), result = execution => result }
        }).await
    }

    pub(crate) async fn logs(
        &self,
        caller: &Caller,
        reference: &str,
        request: LogsRequest,
        io: &mut SessionIo,
    ) -> Outcome<()> {
        let source = log_source(&request.source)?;
        let output = match request.output.as_str() {
            "" => w::LogOutput::All,
            "stdout" => w::LogOutput::Stdout,
            "stderr" => w::LogOutput::Stderr,
            _ => return Err(usage("invalid log output filter")),
        };
        let peer = caller.fresh().await?;
        let snapshot = self.inspect_for(&peer, reference, Action::Logs).await?;
        let cancel = io.cancel.clone();
        self.run_stream(caller, &snapshot.id.clone(), Action::Logs, &cancel, |token| async move {
            let read = async {
                // Management preserves tail/follow descriptors and drops a partial first line.
                let stream = self.management().read_logs(w::ReadLogsRequest { id: snapshot.id, source: source as i32, output: output as i32, follow: request.follow, tail_bytes: Some(LOG_LIMIT) }).await.map_err(|error| categorize(&error))?;
                let mut lines = LogLines::default();
                let mut stream = self.jobs().metrics().track("logs", stream);
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|error| categorize(&error))?;
                    for byte in chunk.data {
                        if let Some(line) = lines.push(byte) { io.stdout.write_all(line.as_bytes()).await.map_err(|_| lost("log output transport failed"))?; }
                    }
                }
                if let Some(line) = lines.finish(false) { io.stdout.write_all(line.as_bytes()).await.map_err(|_| lost("log output transport failed"))?; }
                io.stdout.flush().await.map_err(|_| lost("log output transport failed"))
            };
            tokio::select! { biased; _ = token.cancelled() => Err(cancelled()), result = read => result }
        }).await
    }

    pub(crate) async fn guest_machine(&self, id: &str) -> Outcome<Handle<Machine>> {
        let reference = MachineRef::parse(id).map_err(native_failure)?;
        let runtime = self
            .management()
            .runtime()
            .await
            .map_err(|error| categorize(&error))?;
        let runtime = self.jobs().metrics().track("runtime", runtime);
        let machine = runtime
            .get_machine(&reference)
            .await
            .map_err(native_failure)?;
        Ok(self.jobs().metrics().track("machine", machine))
    }

    pub(crate) async fn run_stream<T, F, Fut>(
        &self,
        caller: &Caller,
        id: &str,
        action: Action,
        parent: &CancellationToken,
        operation: F,
    ) -> Outcome<T>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Outcome<T>>,
    {
        if parent.is_cancelled() {
            return Err(cancelled());
        }
        let token = parent.child_token();
        let _guard = token.clone().drop_guard();
        let reauthorize = async {
            loop {
                tokio::time::sleep(STREAM_RECHECK).await;
                let checked = async {
                    let peer = caller.fresh().await?;
                    self.inspect_for(&peer, id, action).await?;
                    Ok::<(), Failure>(())
                }
                .await;
                if let Err(error) = checked {
                    break Err::<(), _>(error);
                }
            }
        };
        let operation = operation(token.clone());
        tokio::pin!(operation);
        tokio::select! {
            biased;
            result = reauthorize => {
                token.cancel();
                let _ = operation.await;
                result?;
                Err(cancelled())
            }
            _ = parent.cancelled() => {
                token.cancel();
                let _ = operation.await;
                Err(cancelled())
            }
            result = &mut operation => result,
        }
    }
}

async fn attached_shell(
    machine: &Machine,
    user: String,
    term: String,
    size: Window,
    io: &mut SessionIo,
    token: CancellationToken,
) -> Outcome<i32> {
    let (mut input, stdin) = tokio::io::duplex(CHUNK);
    let (stdout, mut output) = tokio::io::duplex(CHUNK);
    let (stderr, mut errors) = tokio::io::duplex(CHUNK);
    let (controls, receiver) = mpsc::channel(8);
    let attachment = SshShellAttachment::new(
        EofAdapter::new(stdin, token.clone()),
        stdout,
        stderr,
        size.rows,
        size.columns,
    )
    .controls(receiver);
    let done = token.child_token();
    let shell = async {
        let result = machine
            .shell_with(|options| {
                options
                    .user(user)
                    .term(term)
                    .attachment(attachment)
                    .cancellation(token.clone())
            })
            .await;
        done.cancel();
        result.map(|status| status.code).map_err(native_failure)
    };
    let input = async {
        let result = tokio::select! { biased; _ = done.cancelled() => None, result = tokio::io::copy(&mut io.stdin, &mut input) => Some(result) };
        if result.is_some_and(|result| result.is_err()) {
            token.cancel();
        }
        drop(input);
    };
    let controls = async {
        let mut windows = io.terminal.as_ref().map(|terminal| terminal.window.clone());
        let mut signals_open = true;
        loop {
            let control = tokio::select! {
                biased;
                _ = done.cancelled() => return,
                size = next_window(&mut windows), if windows.is_some() => match size {
                    Some(size) => SshShellControl::Resize { rows: size.rows, columns: size.columns },
                    None => continue,
                },
                signal = io.signals.recv(), if signals_open => match signal {
                    Some(signal) => {
                        let Some(signal) = SshShellSignal::from_linux(linux_signal(signal)) else { continue };
                        SshShellControl::Signal(signal)
                    }
                    None => { signals_open = false; continue; }
                },
                else => return,
            };
            tokio::select! { biased; _ = done.cancelled() => return, sent = controls.send(control) => if sent.is_err() { return; } }
        }
    };
    let out = relay_output(&mut output, &mut io.stdout, &token);
    let err = relay_output(&mut errors, &mut io.stderr, &token);
    let (status, (), (), out, err) = tokio::join!(shell, input, controls, out, err);
    out?;
    err?;
    status
}

async fn relay_output<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    input: &mut R,
    output: &mut W,
    token: &CancellationToken,
) -> Outcome<()> {
    let result = tokio::select! {
        biased;
        _ = token.cancelled() => return Err(cancelled()),
        result = async { tokio::io::copy(input, output).await?; output.flush().await } => result,
    };
    result.map_err(|_| {
        token.cancel();
        lost("guest output transport failed")
    })
}

async fn next_window(windows: &mut Option<watch::Receiver<Window>>) -> Option<Window> {
    let Some(receiver) = windows else { return None };
    if receiver.changed().await.is_err() {
        *windows = None;
        return None;
    }
    let window = *receiver.borrow_and_update();
    (window.rows > 0 && window.columns > 0).then_some(window)
}

fn terminal(terminal: Option<&Terminal>, missing: &str) -> Outcome<(Window, String)> {
    let terminal = terminal.ok_or_else(|| usage(missing))?;
    let window = *terminal.window.borrow();
    if window.rows == 0 || window.columns == 0 {
        return Err(usage("invalid initial PTY size"));
    }
    let term = if terminal.term.is_empty() {
        "xterm-256color"
    } else {
        &terminal.term
    };
    if term.len() > 128 || !text(term) {
        return Err(usage("invalid TERM"));
    }
    Ok((window, term.to_owned()))
}

pub(crate) fn ensure_running(snapshot: &w::MachineSnapshot) -> Outcome<()> {
    if matches!(
        snapshot
            .status
            .as_ref()
            .and_then(|status| status.status.as_ref()),
        Some(w::machine_status::Status::Running(_))
    ) {
        Ok(())
    } else {
        Err(Failure::new(Code::Conflict, "VM must be running"))
    }
}

fn selected_user(user: &str, snapshot: &w::MachineSnapshot) -> String {
    if user.is_empty() {
        snapshot
            .guest
            .as_ref()
            .and_then(|guest| guest.user.as_ref())
            .map_or("root", |user| user.name.as_str())
            .to_owned()
    } else {
        user.to_owned()
    }
}

fn validate_exec(request: &ExecRequest) -> Outcome<()> {
    if request.program.is_empty()
        || request.program.len() > 4096
        || request.program.contains('\0')
        || request.args.len() > 256
        || request.env.len() > 64
        || !text(&request.user)
        || !text(&request.directory)
    {
        return Err(usage("invalid execution request"));
    }
    if request
        .args
        .iter()
        .any(|arg| arg.len() > 16384 || arg.contains('\0'))
    {
        return Err(usage("invalid guest argument"));
    }
    if request
        .env
        .iter()
        .any(|(key, value)| !env_key(key) || value.len() > 16384 || value.contains('\0'))
    {
        return Err(usage("invalid guest environment"));
    }
    Ok(())
}

fn text(value: &str) -> bool {
    value.len() <= 4096 && !value.chars().any(char::is_control)
}
fn env_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}
fn linux_signal(signal: Signal) -> u32 {
    match signal {
        Signal::Hup => 1,
        Signal::Int => 2,
        Signal::Quit => 3,
        Signal::Kill => 9,
        Signal::Usr1 => 10,
        Signal::Usr2 => 12,
        Signal::Term => 15,
    }
}
pub(crate) fn native_failure(error: libvm::LibVmError) -> Failure {
    categorize(&silo_vm_control::errors::native_error_to_status(&error))
}
pub(crate) fn cancelled() -> Failure {
    Failure::new(Code::Cancelled, "operation cancelled")
}
fn usage(message: &str) -> Failure {
    Failure::new(Code::Usage, message)
}
fn lost(message: &str) -> Failure {
    Failure {
        code: Code::Unavailable,
        message: message.into(),
        exit: 255,
    }
}
fn execution_status(result: ExecutionResult) -> Outcome<i32> {
    match result {
        ExecutionResult::Exited { code: Some(code) } => {
            i32::try_from(code).map_err(|_| lost("guest exit status out of range"))
        }
        ExecutionResult::Signaled {
            signal: Some(signal),
        } => Ok(signal.saturating_add(128).min(255) as i32),
        ExecutionResult::LaunchFailed(failure) => {
            let (exit, message) = if failure.reason == ExecutionLaunchFailureReason::CommandNotFound
            {
                (127, "guest command not found")
            } else {
                (126, "guest process could not launch")
            };
            Err(Failure {
                code: Code::OperationFailed,
                message: message.into(),
                exit,
            })
        }
        _ => Err(lost("guest execution lost")),
    }
}

fn log_source(source: &str) -> Outcome<w::LogSource> {
    match source {
        "" | "serial" => Ok(w::LogSource::Serial),
        "monitor" => Ok(w::LogSource::Monitor),
        "exec" => Ok(w::LogSource::Exec),
        "network" => Ok(w::LogSource::Network),
        "network-audit" | "network_audit" => Ok(w::LogSource::NetworkAudit),
        _ => Err(usage("invalid log stream")),
    }
}

#[derive(Default)]
struct LogLines {
    line: Vec<u8>,
    oversized: bool,
}
impl LogLines {
    fn push(&mut self, byte: u8) -> Option<String> {
        if byte == b'\n' {
            return Some(self.finish(true).unwrap_or_else(|| "\n".into()));
        }
        if self.line.len() < CHUNK && !self.oversized {
            self.line.push(byte);
        } else {
            self.line.clear();
            self.oversized = true;
        }
        None
    }
    fn finish(&mut self, newline: bool) -> Option<String> {
        if self.line.is_empty() && !self.oversized && !newline {
            return None;
        }
        let mut line = if self.oversized {
            "[oversized log line omitted]".to_owned()
        } else {
            redact_log_line(&String::from_utf8_lossy(&self.line))
        };
        if newline {
            line.push('\n');
        }
        self.line.clear();
        self.oversized = false;
        Some(line)
    }
}
fn redact_log_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let private_key = lower.match_indices("private").any(|(offset, _)| {
        let rest = &lower[offset + "private".len()..];
        rest.starts_with("key")
            || rest
                .chars()
                .next()
                .is_some_and(|separator| rest[separator.len_utf8()..].starts_with("key"))
    });
    if [
        "tskey-",
        "token",
        "secret",
        "password",
        "authorization",
        "authkey",
        "credential",
    ]
    .iter()
    .any(|word| lower.contains(word))
        || private_key
    {
        "[credential diagnostic redacted]".into()
    } else {
        let redacted = crate::lobby::redact::log_text(line, &[]);
        let mut output = String::with_capacity(redacted.len());
        let mut characters = redacted.chars().peekable();
        let path_character = |c: &char| !c.is_whitespace() && !matches!(c, '"' | '\'' | '<' | '>');
        while let Some(character) = characters.next() {
            if character == '/' && characters.peek().is_some_and(path_character) {
                output.push_str("[path]");
                while characters.peek().is_some_and(path_character) {
                    characters.next();
                }
            } else {
                output.push(character);
            }
        }
        output
    }
}

struct EofAdapter<R> {
    input: R,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    eof: bool,
    eot: usize,
}
impl<R> EofAdapter<R> {
    fn new(input: R, token: CancellationToken) -> Self {
        Self {
            input,
            cancelled: Box::pin(token.cancelled_owned()),
            eof: false,
            eot: 0,
        }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for EofAdapter<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "session cancelled",
            )));
        }
        if !self.eof {
            let previous = buffer.filled().len();
            match Pin::new(&mut self.input).poll_read(cx, buffer) {
                Poll::Ready(Ok(())) if buffer.filled().len() == previous => self.eof = true,
                result => return result,
            }
        }
        let count = buffer.remaining().min(2 - self.eot);
        for _ in 0..count {
            buffer.put_slice(&[4]);
        }
        self.eot += count;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::lobby::service::streams::{
        env_key, execution_status, log_source, redact_log_line, validate_exec, EofAdapter,
        ExecRequest, LogLines,
    };
    use crate::lobby::session::{SessionIo, Terminal, Window};
    use parking_lot::Mutex;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWrite;
    use tokio::sync::{mpsc, watch};
    use tokio_util::sync::CancellationToken;

    pub(crate) struct CapturedIo {
        pub(crate) io: SessionIo,
        pub(crate) stdout: Arc<Mutex<Vec<u8>>>,
        pub(crate) stderr: Arc<Mutex<Vec<u8>>>,
        pub(crate) windows: watch::Sender<Window>,
    }

    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl AsyncWrite for Buffer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.lock().extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    pub(crate) fn captured_io(input: Vec<u8>, pty: bool) -> CapturedIo {
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let (windows, receiver) = watch::channel(Window::default());
        let (_, signals) = mpsc::channel(8);
        let io = SessionIo {
            stdin: Box::new(std::io::Cursor::new(input)),
            stdout: Box::new(Buffer(stdout.clone())),
            stderr: Box::new(Buffer(stderr.clone())),
            terminal: pty.then_some(Terminal {
                term: "xterm-256color".into(),
                window: receiver,
            }),
            signals,
            cancel: CancellationToken::new(),
        };
        CapturedIo {
            io,
            stdout,
            stderr,
            windows,
        }
    }

    pub(crate) fn native_enabled() -> bool {
        if std::env::var_os("SILO_LOBBY_E2E_RUNTIME").is_none() {
            eprintln!("set SILO_LOBBY_E2E_RUNTIME to run lobby guest tests");
            return false;
        }
        if cfg!(target_os = "linux") && !std::path::Path::new("/dev/kvm").exists() {
            eprintln!("SILO_LOBBY_E2E_RUNTIME guest tests require /dev/kvm");
            return false;
        }
        true
    }

    #[test]
    fn environment_key_tables() {
        for key in ["A", "_", "HOME", "a0_B"] {
            assert!(env_key(key), "{key}");
        }
        for key in ["", "0A", "A-B", "A=B", "A B", "é", "A\0"] {
            assert!(!env_key(key), "{key}");
        }
        assert!(env_key(&"x".repeat(128)));
        assert!(!env_key(&"x".repeat(129)));
    }

    #[test]
    fn execution_validation_bounds() {
        let mut request = ExecRequest {
            program: "/bin/true".into(),
            ..Default::default()
        };
        assert!(validate_exec(&request).is_ok());
        request.env.insert("0BAD".into(), "value".into());
        assert!(validate_exec(&request).is_err());
        request.env.clear();
        request.directory = "/tmp\nunsafe".into();
        assert!(validate_exec(&request).is_err());
        request.directory.clear();
        request.args = vec!["a".repeat(16385)];
        assert!(validate_exec(&request).is_err());
    }

    #[tokio::test]
    async fn eof_adapter_orders_data_then_two_eots_once() {
        let mut reader = EofAdapter::new(std::io::Cursor::new(b"last"), CancellationToken::new());
        let mut output = Vec::new();
        let mut byte = [0];
        while reader.read(&mut byte).await.unwrap() != 0 {
            output.extend(byte);
        }
        assert_eq!(output, b"last\x04\x04");
        assert_eq!(reader.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn eof_adapter_never_synthesizes_eot_on_cancel_or_failure() {
        let token = CancellationToken::new();
        token.cancel();
        let mut reader = EofAdapter::new(tokio::io::empty(), token);
        let mut byte = [0];
        assert!(reader.read(&mut byte).await.is_err());
        let directory = tokio::fs::File::open("/").await.unwrap();
        let mut reader = EofAdapter::new(directory, CancellationToken::new());
        assert!(reader.read(&mut byte).await.is_err());
    }

    #[test]
    fn logs_are_redacted_after_reassembling_lines() {
        assert_eq!(redact_log_line("read /home/private/state"), "read [path]");
        assert_eq!(redact_log_line("at:/home/private/state"), "at:[path]");
        for line in [
            "TOKEN abc",
            "client secret",
            "private_key",
            "private:key",
            "private.key",
            "Authorization: xyz",
            "tskey-auth-abc",
        ] {
            assert_eq!(redact_log_line(line), "[credential diagnostic redacted]");
        }
        let mut lines = LogLines::default();
        let output: Vec<_> = b"tok"
            .iter()
            .chain(b"en=value\nokay\nlast")
            .filter_map(|byte| lines.push(*byte))
            .collect();
        assert_eq!(output, ["[credential diagnostic redacted]\n", "okay\n"]);
        assert_eq!(lines.finish(false).as_deref(), Some("last"));
        for _ in 0..65537 {
            assert!(lines.push(b'a').is_none());
        }
        assert_eq!(
            lines.push(b'\n').as_deref(),
            Some("[oversized log line omitted]\n")
        );
    }

    #[test]
    fn log_sources_and_execution_status() {
        assert_eq!(
            log_source("network_audit").unwrap(),
            log_source("network-audit").unwrap()
        );
        assert!(log_source("all").is_err());
        assert_eq!(
            execution_status(libvm::ExecutionResult::Exited { code: Some(37) }).unwrap(),
            37
        );
        assert_eq!(
            execution_status(libvm::ExecutionResult::Signaled { signal: Some(15) }).unwrap(),
            143
        );
        assert_eq!(
            execution_status(libvm::ExecutionResult::Exited { code: None })
                .unwrap_err()
                .exit,
            255
        );
    }
    async fn wait_for_output(output: &Arc<Mutex<Vec<u8>>>, marker: &[u8]) {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if output
                    .lock()
                    .windows(marker.len())
                    .any(|bytes| bytes == marker)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn native_exec_shell_and_stream_cancellation_preserve_run() {
        if !native_enabled() {
            return;
        }
        use crate::lobby::identity::Action;
        use crate::lobby::service::testing::{caller, fixture};
        use crate::lobby::session::SessionExtras;
        use std::time::Duration;

        let fixture = fixture().await;
        let caller = caller("user:1", &[Action::Exec, Action::Shell, Action::Logs]);
        let id = fixture.running_vm("user:1").await.unwrap();
        let initial_run = fixture.management.inspect(&id).await.unwrap().run_id;
        let mut io = captured_io(Vec::new(), false);
        let status = fixture
            .service
            .exec(
                &caller,
                &id,
                ExecRequest {
                    program: "/bin/sh".into(),
                    args: vec![
                        "-c".into(),
                        "head -c 131073 /dev/zero; head -c 131075 /dev/zero >&2; exit 37".into(),
                    ],
                    ..Default::default()
                },
                &mut io.io,
            )
            .await
            .unwrap();
        assert_eq!(status, 37);
        assert_eq!(io.stdout.lock().len(), 131073);
        assert_eq!(io.stderr.lock().len(), 131075);

        let payload = vec![b'x'; 196613];
        let mut io = captured_io(payload.clone(), false);
        assert_eq!(
            fixture
                .service
                .exec(
                    &caller,
                    &id,
                    ExecRequest {
                        program: "/bin/cat".into(),
                        ..Default::default()
                    },
                    &mut io.io
                )
                .await
                .unwrap(),
            0
        );
        assert_eq!(*io.stdout.lock(), payload);

        let mut io = captured_io(
            b"printf '\\nSHELL-READY\\n'; sleep 2; stty size; exit 19\n".to_vec(),
            true,
        );
        let stdout = io.stdout.clone();
        let resize = async {
            wait_for_output(&stdout, b"\r\nSHELL-READY\r\n").await;
            let metrics = fixture.service.jobs().metrics().render();
            assert!(metrics
                .contains("lobby_native_handles{kind=\"machine\",scope=\"daemon_owned\"} 1\n"));
            assert!(
                metrics.contains("lobby_native_handles{kind=\"exec\",scope=\"daemon_owned\"} 1\n")
            );
            io.windows
                .send(Window {
                    rows: 37,
                    columns: 119,
                })
                .unwrap();
        };
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        let shell = fixture.service.shell(&caller, &id, "", &mut io.io, &extras);
        let (status, ()) = tokio::join!(shell, resize);
        assert_eq!(status.unwrap(), 19);
        assert!(String::from_utf8_lossy(&io.stdout.lock()).contains("37 119"));
        let metrics = fixture.service.jobs().metrics().render();
        assert!(
            metrics.contains("lobby_native_handles{kind=\"machine\",scope=\"daemon_owned\"} 0\n")
        );
        assert!(metrics.contains("lobby_native_handles{kind=\"exec\",scope=\"daemon_owned\"} 0\n"));

        for shell in [false, true] {
            let mut io = captured_io(Vec::new(), shell);
            let (mut input, reader) = tokio::io::duplex(4096);
            use tokio::io::AsyncWriteExt;
            input
                .write_all(b"printf '\\nCANCEL-READY\\n'; sleep 120\n")
                .await
                .unwrap();
            io.io.stdin = Box::new(reader);
            let stdout = io.stdout.clone();
            let token = io.io.cancel.clone();
            let cancel = async {
                wait_for_output(
                    &stdout,
                    if shell {
                        b"\r\nCANCEL-READY\r\n"
                    } else {
                        b"CANCEL-READY"
                    },
                )
                .await;
                let metrics = fixture.service.jobs().metrics().render();
                assert!(metrics
                    .contains("lobby_native_handles{kind=\"machine\",scope=\"daemon_owned\"} 1\n"));
                assert!(metrics
                    .contains("lobby_native_handles{kind=\"exec\",scope=\"daemon_owned\"} 1\n"));
                token.cancel();
            };
            let run = async {
                if shell {
                    fixture
                        .service
                        .shell(&caller, &id, "", &mut io.io, &extras)
                        .await
                } else {
                    fixture
                        .service
                        .exec(
                            &caller,
                            &id,
                            ExecRequest {
                                program: "/bin/sh".into(),
                                args: vec!["-c".into(), "printf CANCEL-READY; sleep 120".into()],
                                ..Default::default()
                            },
                            &mut io.io,
                        )
                        .await
                }
            };
            let (result, ()) =
                tokio::time::timeout(Duration::from_secs(40), async { tokio::join!(run, cancel) })
                    .await
                    .unwrap();
            assert_eq!(
                result.unwrap_err().code,
                crate::lobby::failure::Code::Cancelled
            );
            drop(input);
        }

        let after = fixture.management.inspect(&id).await.unwrap();
        assert_eq!(after.run_id, initial_run);
        assert!(matches!(
            after.status.unwrap().status,
            Some(silod_spec::daemon::v1::machine_status::Status::Running(_))
        ));
        fixture
            .management
            .stop(&id, initial_run, true, None)
            .await
            .unwrap();
        fixture.management.remove(&id).await.unwrap();
    }

    #[tokio::test]
    async fn bounded_log_tail_discards_partial_line_even_during_follow() {
        use crate::lobby::failure::Code;
        use crate::lobby::identity::Action;
        use crate::lobby::service::streams::LogsRequest;
        use crate::lobby::service::testing::{caller, fixture, stopped_vm};
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use std::time::Duration;

        let fixture = fixture().await;
        let caller = caller("user:1", &[Action::Logs]);
        let snapshot = stopped_vm(&fixture, "log-tail", "user:1").await;
        let path = fixture
            .service
            .config()
            .home
            .join("logs/machines")
            .join(&snapshot.id)
            .join("serial.log");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path.parent().unwrap())
            .unwrap();
        let partial = vec![b'x'; (4 << 20) + 100];
        let mut content = partial.clone();
        content.extend_from_slice(b"\nwhole\n");
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut io = captured_io(Vec::new(), false);
        fixture
            .service
            .logs(
                &caller,
                &snapshot.id,
                LogsRequest {
                    source: "serial".into(),
                    ..Default::default()
                },
                &mut io.io,
            )
            .await
            .unwrap();
        assert_eq!(*io.stdout.lock(), b"whole\n");

        std::fs::write(&path, partial).unwrap();
        let mut io = captured_io(Vec::new(), false);
        let output = io.stdout.clone();
        let token = io.io.cancel.clone();
        let append = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            file.write_all(b"still-partial\nnext-line\n").unwrap();
            wait_for_output(&output, b"next-line\n").await;
            assert!(fixture
                .service
                .jobs()
                .metrics()
                .render()
                .contains("lobby_native_handles{kind=\"logs\",scope=\"daemon_owned\"} 1\n"));
            token.cancel();
        };
        let follow = fixture.service.logs(
            &caller,
            &snapshot.id,
            LogsRequest {
                source: "serial".into(),
                follow: true,
                ..Default::default()
            },
            &mut io.io,
        );
        let (result, ()) = tokio::join!(follow, append);
        assert_eq!(result.unwrap_err().code, Code::Cancelled);
        assert_eq!(*io.stdout.lock(), b"next-line\n");
        assert!(fixture
            .service
            .jobs()
            .metrics()
            .render()
            .contains("lobby_native_handles{kind=\"logs\",scope=\"daemon_owned\"} 0\n"));
        fixture.management.remove(&snapshot.id).await.unwrap();
    }

    #[tokio::test]
    async fn native_logs_trim_partial_tail_redact_follow_and_cancel() {
        if !native_enabled() {
            return;
        }
        use crate::lobby::identity::Action;
        use crate::lobby::service::streams::LogsRequest;
        use crate::lobby::service::testing::{caller, fixture};
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let fixture = fixture().await;
        let caller = caller("user:1", &[Action::Logs]);
        let id = fixture.running_vm("user:1").await.unwrap();
        let path = fixture
            .service
            .config()
            .home
            .join("logs/machines")
            .join(&id)
            .join("network/audit.jsonl");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path.parent().unwrap())
            .unwrap();
        let mut content = vec![b'x'; (4 << 20) + 100];
        content.extend_from_slice(b"\nread /home/private/state\nTOKEN=value\nretained\n");
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut io = captured_io(Vec::new(), false);
        fixture
            .service
            .logs(
                &caller,
                &id,
                LogsRequest {
                    source: "network_audit".into(),
                    ..Default::default()
                },
                &mut io.io,
            )
            .await
            .unwrap();
        assert_eq!(
            *io.stdout.lock(),
            b"read [path]\n[credential diagnostic redacted]\nretained\n"
        );
        let mut io = captured_io(Vec::new(), false);
        let output = io.stdout.clone();
        let cancel = io.io.cancel.clone();
        let append = async {
            wait_for_output(&output, b"retained\n").await;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            file.write_all(b"followed\n").unwrap();
            wait_for_output(&output, b"followed\n").await;
            cancel.cancel();
        };
        let follow = fixture.service.logs(
            &caller,
            &id,
            LogsRequest {
                source: "network-audit".into(),
                follow: true,
                ..Default::default()
            },
            &mut io.io,
        );
        let (result, ()) = tokio::join!(follow, append);
        assert_eq!(
            result.unwrap_err().code,
            crate::lobby::failure::Code::Cancelled
        );
        fixture
            .management
            .stop(&id, None, true, None)
            .await
            .unwrap();
        fixture.management.remove(&id).await.unwrap();
    }

    #[tokio::test]
    async fn native_revocation_stops_execution_within_one_recheck() {
        if !native_enabled() {
            return;
        }
        use crate::lobby::caller::Caller;
        use crate::lobby::identity::Action;
        use crate::lobby::service::testing::{caller, fixture};
        use std::time::Duration;
        let fixture = fixture().await;
        let original = caller("user:1", &[Action::Exec]).peer;
        let current = Arc::new(Mutex::new(original.clone()));
        let identity = current.clone();
        let caller = Caller::new(
            original,
            Arc::new(move || {
                let peer = identity.lock().clone();
                Box::pin(async move { Ok(peer) })
            }),
        );
        let id = fixture.running_vm("user:1").await.unwrap();
        let mut io = captured_io(Vec::new(), false);
        let output = io.stdout.clone();
        let revoke = async {
            wait_for_output(&output, b"REVOKE-READY").await;
            current.lock().permissions.actions.clear();
        };
        let execution = fixture.service.exec(
            &caller,
            &id,
            ExecRequest {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "printf REVOKE-READY; sleep 120".into()],
                ..Default::default()
            },
            &mut io.io,
        );
        let started = tokio::time::Instant::now();
        let (result, ()) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(execution, revoke)
        })
        .await
        .unwrap();
        assert_eq!(
            result.unwrap_err().code,
            crate::lobby::failure::Code::Forbidden
        );
        assert!(started.elapsed() < Duration::from_secs(60));
        fixture
            .management
            .stop(&id, None, true, None)
            .await
            .unwrap();
        fixture.management.remove(&id).await.unwrap();
    }
}
