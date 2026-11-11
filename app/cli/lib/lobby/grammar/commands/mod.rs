use futures::future::BoxFuture;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::lobby::caller::Caller;
use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::grammar::cmdline::{Args, FlagSet, PositionalError};
use crate::lobby::grammar::render::{self, ProgressDisplay};
use crate::lobby::identity::Action;
use crate::lobby::jobs::Operation;
use crate::lobby::service::lifecycle::RemovalTarget;
use crate::lobby::service::Service;
use crate::lobby::session::{SessionExtras, SessionIo};

pub(crate) mod cp;
pub(crate) mod create;
pub(crate) mod exec;
pub(crate) mod help;
pub(crate) mod logs;
pub(crate) mod ls;
pub(crate) mod ops;
pub(crate) mod policy;
pub(crate) mod restart;
pub(crate) mod rm;
pub(crate) mod set;
pub(crate) mod shell;
pub(crate) mod show;
pub(crate) mod start;
pub(crate) mod stop;
pub(crate) mod template;
pub(crate) mod version;
pub(crate) mod whoami;

/// One authenticated command and its transport-owned streams.
pub(crate) struct Context<'a> {
    pub(crate) service: &'a Service,
    pub(crate) caller: Caller,
    pub(crate) streams: &'a mut SessionIo,
    pub(crate) extras: &'a SessionExtras,
    pub(crate) json: bool,
    /// Admitted operations retain their record even when Outcome is an error.
    pub(crate) failure_data: Option<Value>,
}

#[derive(Debug, Default)]
pub(crate) struct Result {
    pub(crate) data: Option<Value>,
    pub(crate) human: String,
    pub(crate) exit: i32,
}

pub(crate) trait Handler: Send {
    fn flags<'a>(&'a mut self, _flags: &mut FlagSet<'a>) {}
    fn run<'a>(
        self: Box<Self>,
        context: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>>;
}

pub(crate) fn usage(message: impl Into<String>) -> Failure {
    Failure::new(Code::Usage, message)
}

pub(crate) fn positional<T>(
    command: &str,
    result: std::result::Result<T, PositionalError>,
) -> Outcome<T> {
    result.map_err(|error| usage(format!("{command}: {error}. See '{command} --help'.")))
}

pub(crate) fn result(data: impl Serialize, human: String) -> Outcome<Result> {
    Ok(Result {
        data: Some(value(data)?),
        human,
        exit: 0,
    })
}

fn value(data: impl Serialize) -> Outcome<Value> {
    serde_json::to_value(data)
        .map_err(|_| Failure::new(Code::Unavailable, "response serialization failed"))
}

fn transport() -> Failure {
    Failure::new(Code::Disconnected, "session transport closed")
}

impl Context<'_> {
    pub(crate) async fn await_operation(&mut self, operation: Operation) -> Outcome<Result> {
        let animated = !self.json
            && self
                .streams
                .terminal
                .as_ref()
                .is_some_and(|terminal| terminal.term != "dumb");
        let mut windows = self
            .streams
            .terminal
            .as_ref()
            .map(|terminal| terminal.window.clone());
        let width = windows
            .as_ref()
            .map_or(80, |window| usize::from(window.borrow().columns));
        let mut display = ProgressDisplay::new(animated, width);
        display.message = render::phase(
            &format!("{} {}", operation.kind, operation.vm),
            &operation.vm,
        );
        let mut animation = tokio::time::interval(std::time::Duration::from_millis(80));
        let mut refresh = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(30),
        );
        let mut reported = 0;
        let outcome = loop {
            let (current, mut changed) = match self
                .service
                .jobs()
                .observe(&self.caller.peer, &operation.id)
            {
                Ok(observed) => observed,
                Err(error) => break Err(error),
            };
            if reported > current.progress.len() {
                reported = 0;
            }
            for line in current.progress.iter().skip(reported) {
                display.message = render::phase(line, &current.vm);
                if line.starts_with("approve: ") {
                    self.streams
                        .stderr
                        .write_all(display.clear().as_bytes())
                        .await
                        .map_err(|_| transport())?;
                    self.streams
                        .stderr
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .map_err(|_| transport())?;
                }
            }
            reported = current.progress.len();
            if current.finished.is_some() {
                if let Some(error) = current.error.clone() {
                    self.failure_data = Some(value(&current)?);
                    break Err(error);
                }
                if let (Some(completion), Some(shown)) =
                    (&current.completion, &self.extras.approval_shown)
                {
                    if !completion.approval_url.is_empty() {
                        shown(&completion.vm_id, &completion.approval_url);
                    }
                }
                let human =
                    render::completion_text(&current, &self.service.config().lobby_hostname);
                break result(current, human);
            }
            tokio::select! {
                _ = self.streams.cancel.cancelled() => {
                    self.failure_data = Some(value(&operation)?);
                    let mut error = transport();
                    error.message = "observer closed; operation continues".into();
                    break Err(error);
                }
                _ = changed.changed() => {}
                _ = animation.tick() => {
                    self.streams.stderr.write_all(display.tick().as_bytes()).await.map_err(|_| transport())?;
                }
                window = async {
                    match &mut windows {
                        Some(window) => window.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if window.is_err() { windows = None; }
                    else if let Some(window) = &windows { display.width = usize::from(window.borrow().columns); }
                }
                _ = refresh.tick() => {
                    match self.caller.fresh().await {
                        Ok(peer) if peer.owns(&current.principal) => self.caller.peer = peer,
                        _ => break Err(Failure::new(Code::Forbidden, "operation observer authorization lost")),
                    }
                }
            }
        };
        self.streams
            .stderr
            .write_all(display.clear().as_bytes())
            .await
            .map_err(|_| transport())?;
        outcome
    }

    /// Authorization precedes consuming any bytes; the deadline also bounds silent peers.
    pub(crate) async fn document(&mut self, action: Action, limit: usize) -> Outcome<Vec<u8>> {
        self.service.authorize(&self.caller.peer, action, None)?;
        let mut data = Vec::new();
        let mut input = self
            .streams
            .stdin
            .as_mut()
            .take((limit as u64).saturating_add(1));
        let read = input.read_to_end(&mut data);
        tokio::select! {
            _ = self.streams.cancel.cancelled() => return Err(usage("document input interrupted or timed out")),
            outcome = tokio::time::timeout(std::time::Duration::from_secs(30), read) => {
                if !matches!(outcome, Ok(Ok(_))) { return Err(usage("document input interrupted or timed out")); }
            }
        }
        if data.len() > limit {
            return Err(usage("document input exceeds size limit"));
        }
        Ok(data)
    }

    pub(crate) async fn confirm(&mut self, target: &RemovalTarget) -> bool {
        let Some(prompt) = &self.extras.prompt else {
            return false;
        };
        let verb = if target.running {
            "Stop and remove"
        } else {
            "Remove"
        };
        let message = format!("{verb} VM '{}'? [y/N] ", target.name);
        loop {
            let line = tokio::select! {
                biased;
                _ = self.streams.cancel.cancelled() => return false,
                line = prompt(message.clone(), 1024) => match line { Ok(line) => line, Err(_) => return false },
            };
            if self.streams.cancel.is_cancelled() {
                return false;
            }
            match line.trim().to_lowercase().as_str() {
                "y" | "yes" => return true,
                "" | "n" | "no" => return false,
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio_util::sync::CancellationToken;

    use crate::lobby::failure::{Code, Failure};
    use crate::lobby::grammar::commands::Context;
    use crate::lobby::identity::Action;
    use crate::lobby::service::lifecycle::RemovalTarget;
    use crate::lobby::service::testing::{caller, fixture};
    use crate::lobby::session::{SessionExtras, SessionIo};

    fn streams() -> (SessionIo, tokio::io::DuplexStream, tokio::io::DuplexStream) {
        let (stdout, stdout_read) = tokio::io::duplex(8192);
        let (stderr, stderr_read) = tokio::io::duplex(8192);
        let (_, signals) = tokio::sync::mpsc::channel(1);
        (
            SessionIo {
                stdin: Box::new(tokio::io::empty()),
                stdout: Box::new(stdout),
                stderr: Box::new(stderr),
                terminal: None,
                signals,
                cancel: CancellationToken::new(),
            },
            stdout_read,
            stderr_read,
        )
    }

    #[tokio::test]
    async fn documents_are_bounded_authorized_and_cancellable() {
        let fixture = fixture().await;
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        let (mut streams, _, _) = streams();
        streams.stdin = Box::new(std::io::Cursor::new(b"not consumed".to_vec()));
        let mut context = Context {
            service: &fixture.service,
            caller: caller("user:7", &[]),
            streams: &mut streams,
            extras: &extras,
            json: false,
            failure_data: None,
        };
        assert_eq!(
            context
                .document(Action::TemplateManage, 65536)
                .await
                .unwrap_err()
                .code,
            Code::Forbidden
        );
        let mut unread = Vec::new();
        context
            .streams
            .stdin
            .read_to_end(&mut unread)
            .await
            .unwrap();
        assert_eq!(unread, b"not consumed");
        context.caller = caller("user:7", &[Action::TemplateManage]);
        for length in [0, 65536, 65537] {
            context.streams.stdin = Box::new(std::io::Cursor::new(vec![b'x'; length]));
            let result = context.document(Action::TemplateManage, 65536).await;
            if length > 65536 {
                assert_eq!(
                    result.unwrap_err().message,
                    "document input exceeds size limit"
                );
            } else {
                assert_eq!(result.unwrap().len(), length);
            }
        }
        let (silent, _peer) = tokio::net::UnixStream::pair().unwrap();
        context.streams.stdin = Box::new(silent);
        context.streams.cancel.cancel();
        let failure = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            context.document(Action::TemplateManage, 65536),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(failure.message, "document input interrupted or timed out");
    }

    #[tokio::test]
    async fn document_deadline_bounds_a_silent_socket() {
        let fixture = fixture().await;
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        let (mut streams, _, _) = streams();
        let (silent, _peer) = tokio::net::UnixStream::pair().unwrap();
        streams.stdin = Box::new(silent);
        let mut context = Context {
            service: &fixture.service,
            caller: caller("user:7", &[Action::Read]),
            streams: &mut streams,
            extras: &extras,
            json: false,
            failure_data: None,
        };
        let started = tokio::time::Instant::now();
        let failure = tokio::time::timeout(
            std::time::Duration::from_secs(31),
            context.document(Action::Read, 65536),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(failure.message, "document input interrupted or timed out");
        assert!(started.elapsed() >= std::time::Duration::from_secs(30));
    }

    #[tokio::test]
    async fn confirmation_uses_explicit_prompter_and_requires_yes() {
        let fixture = fixture().await;
        for (input, expected, prompts) in [
            ("y\n", true, 1),
            ("yes\n", true, 1),
            (" \tYeS \t\n", true, 1),
            ("Y\n", true, 1),
            ("n\n", false, 1),
            (" NO \n", false, 1),
            ("\n", false, 1),
            ("", false, 1),
            ("yes", false, 1),
            ("maybe\nyep\n Y \n", true, 3),
            ("sure\nno\n", false, 2),
            ("maybe\n", false, 2),
        ] {
            let (socket, mut peer) = tokio::net::UnixStream::pair().unwrap();
            peer.write_all(input.as_bytes()).await.unwrap();
            peer.shutdown().await.unwrap();
            let socket = Arc::new(tokio::sync::Mutex::new(BufReader::new(socket)));
            let extras = SessionExtras {
                prompt: Some(Arc::new(move |message, _| {
                    let socket = socket.clone();
                    Box::pin(async move {
                        let mut socket = socket.lock().await;
                        socket
                            .get_mut()
                            .write_all(message.as_bytes())
                            .await
                            .map_err(|_| Failure::new(Code::Disconnected, "prompt closed"))?;
                        let mut line = String::new();
                        socket
                            .read_line(&mut line)
                            .await
                            .map_err(|_| Failure::new(Code::Disconnected, "prompt closed"))?;
                        if !line.ends_with('\n') {
                            return Err(Failure::new(Code::Cancelled, "prompt closed"));
                        }
                        Ok(line)
                    })
                })),
                approval_shown: None,
            };
            let (mut streams, _, _) = streams();
            let mut context = Context {
                service: &fixture.service,
                caller: caller("user:7", &[]),
                streams: &mut streams,
                extras: &extras,
                json: false,
                failure_data: None,
            };
            assert_eq!(
                context
                    .confirm(&RemovalTarget {
                        id: "vm".into(),
                        name: "devbox".into(),
                        running: false
                    })
                    .await,
                expected,
                "{input:?}"
            );
            drop(context);
            drop(extras);
            let mut output = String::new();
            peer.read_to_string(&mut output).await.unwrap();
            assert_eq!(
                output,
                "Remove VM 'devbox'? [y/N] ".repeat(prompts),
                "{input:?}"
            );
        }
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        let (mut streams, _, _) = streams();
        streams.stdin = Box::new(std::io::Cursor::new(b"yes\n".to_vec()));
        let mut context = Context {
            service: &fixture.service,
            caller: caller("user:7", &[]),
            streams: &mut streams,
            extras: &extras,
            json: false,
            failure_data: None,
        };
        assert!(
            !context
                .confirm(&RemovalTarget {
                    id: "vm".into(),
                    name: "devbox".into(),
                    running: true
                })
                .await
        );
        let mut unread = Vec::new();
        context
            .streams
            .stdin
            .read_to_end(&mut unread)
            .await
            .unwrap();
        assert_eq!(unread, b"yes\n");
    }

    #[tokio::test]
    async fn await_retains_failed_operation_and_publishes_consent_on_stderr() {
        let fixture = fixture().await;
        let caller = caller("user:7", &[]);
        for failing in [false, true] {
            let operation = fixture
                .service
                .jobs()
                .submit_result(
                    "create",
                    "vm",
                    caller.peer.principals[0].clone(),
                    move |_, progress| async move {
                        progress("approve: https://login.tailscale.com/a/example".into());
                        if failing {
                            Err(Failure::new(Code::Conflict, "operation refused"))
                        } else {
                            Ok(None)
                        }
                    },
                    || {},
                )
                .unwrap();
            let extras = SessionExtras {
                prompt: None,
                approval_shown: None,
            };
            let (mut streams, mut stdout, mut stderr) = streams();
            let mut context = Context {
                service: &fixture.service,
                caller: caller.clone(),
                streams: &mut streams,
                extras: &extras,
                json: true,
                failure_data: None,
            };
            let outcome = context.await_operation(operation.clone()).await;
            let data = if failing {
                assert_eq!(outcome.unwrap_err().code, Code::Conflict);
                context.failure_data.take().unwrap()
            } else {
                outcome.unwrap().data.unwrap()
            };
            assert_eq!(data["id"], operation.id);
            assert_eq!(data["state"], if failing { "failed" } else { "succeeded" });
            drop(context);
            drop(streams);
            let mut output = String::new();
            stdout.read_to_string(&mut output).await.unwrap();
            assert!(output.is_empty());
            stderr.read_to_string(&mut output).await.unwrap();
            assert_eq!(output, "approve: https://login.tailscale.com/a/example\n");
        }
    }

    #[tokio::test]
    async fn observer_disconnect_does_not_cancel_operation() {
        let fixture = fixture().await;
        let caller = caller("user:7", &[]);
        let (release, wait) = tokio::sync::oneshot::channel();
        let operation = fixture
            .service
            .jobs()
            .submit_result(
                "create",
                "vm",
                caller.peer.principals[0].clone(),
                move |_, _| async move {
                    wait.await.unwrap();
                    Ok(None)
                },
                || {},
            )
            .unwrap();
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        let (mut streams, _, _) = streams();
        streams.cancel.cancel();
        let mut context = Context {
            service: &fixture.service,
            caller: caller.clone(),
            streams: &mut streams,
            extras: &extras,
            json: true,
            failure_data: None,
        };
        let failure = context
            .await_operation(operation.clone())
            .await
            .unwrap_err();
        assert_eq!(failure.code, Code::Disconnected);
        assert_eq!(failure.exit, 255);
        assert_eq!(context.failure_data.as_ref().unwrap()["id"], operation.id);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let (current, mut changed) = fixture
                    .service
                    .jobs()
                    .observe(&caller.peer, &operation.id)
                    .unwrap();
                if current.finished.is_some() {
                    assert!(current.error.is_none());
                    break;
                }
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn confirmation_cancellation_interrupts_socket_prompt() {
        let fixture = fixture().await;
        let (socket, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let socket = Arc::new(tokio::sync::Mutex::new(BufReader::new(socket)));
        let extras = SessionExtras {
            prompt: Some(Arc::new(move |message, _| {
                let socket = socket.clone();
                Box::pin(async move {
                    let mut socket = socket.lock().await;
                    socket
                        .get_mut()
                        .write_all(message.as_bytes())
                        .await
                        .map_err(|_| Failure::new(Code::Disconnected, "prompt closed"))?;
                    let mut line = String::new();
                    socket
                        .read_line(&mut line)
                        .await
                        .map_err(|_| Failure::new(Code::Disconnected, "prompt closed"))?;
                    Ok(line)
                })
            })),
            approval_shown: None,
        };
        let (mut streams, _, _) = streams();
        let cancel = streams.cancel.clone();
        let mut context = Context {
            service: &fixture.service,
            caller: caller("user:7", &[]),
            streams: &mut streams,
            extras: &extras,
            json: false,
            failure_data: None,
        };
        let target = RemovalTarget {
            id: "vm".into(),
            name: "devbox".into(),
            running: true,
        };
        let prompt = b"Stop and remove VM 'devbox'? [y/N] ";
        let peer = async {
            let mut bytes = vec![0; prompt.len()];
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, prompt);
            cancel.cancel();
        };
        let confirmation = context.confirm(&target);
        let (confirmed, ()) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(confirmation, peer)
        })
        .await
        .unwrap();
        assert!(!confirmed);
    }

    #[tokio::test]
    async fn terminal_await_clears_spinner_and_reports_completion_approval() {
        let fixture = fixture().await;
        let caller = caller("user:7", &[]);
        let (release, wait) = tokio::sync::oneshot::channel();
        let operation = fixture
            .service
            .jobs()
            .submit_result(
                "create",
                "vm",
                caller.peer.principals[0].clone(),
                move |_, progress| async move {
                    progress("starting VM".into());
                    wait.await.unwrap();
                    Ok(Some(crate::lobby::jobs::Completion {
                        vm_id: "vm-id".into(),
                        name: "devbox".into(),
                        running: true,
                        user: "root".into(),
                        node_state: "pending approval".into(),
                        approval_url: "https://login.tailscale.com/a/example".into(),
                        ..Default::default()
                    }))
                },
                || {},
            )
            .unwrap();
        let approvals = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let shown = approvals.clone();
        let extras = SessionExtras {
            prompt: None,
            approval_shown: Some(Arc::new(move |id, url| {
                shown.lock().push((id.to_owned(), url.to_owned()))
            })),
        };
        let (mut streams, stdout, mut stderr) = streams();
        let (_, window) = tokio::sync::watch::channel(crate::lobby::session::Window::default());
        streams.terminal = Some(crate::lobby::session::Terminal {
            term: "xterm".into(),
            window,
        });
        let mut context = Context {
            service: &fixture.service,
            caller,
            streams: &mut streams,
            extras: &extras,
            json: false,
            failure_data: None,
        };
        let release = async {
            let mut bytes = vec![0; "\r\x1b[2K".len()];
            stderr.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"\r\x1b[2K");
            release.send(()).unwrap();
            stderr
        };
        let (result, mut stderr) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(context.await_operation(operation), release)
        })
        .await
        .unwrap();
        let result = result.unwrap();
        assert!(result.human.contains("✓ Ready"));
        assert!(result.human.contains("ssh -t silo shell devbox"));
        assert_eq!(
            approvals.lock().as_slice(),
            [(
                "vm-id".into(),
                "https://login.tailscale.com/a/example".into()
            )]
        );
        drop(context);
        drop(streams);
        drop(stdout);
        let mut remainder = String::new();
        stderr.read_to_string(&mut remainder).await.unwrap();
        assert!(remainder.ends_with("\r\x1b[2K"));
    }
}
