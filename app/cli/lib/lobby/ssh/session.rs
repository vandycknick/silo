use russh::{
    server::{Auth, ChannelOpenHandle, Msg, Session},
    Channel, ChannelId, Pty, Sig,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, watch, Mutex},
};
use tokio_util::sync::CancellationToken;

use crate::lobby::{
    caller::Caller,
    failure::{Code, Failure},
    grammar::help,
    session::{SessionExtras, SessionIo, Signal, Terminal, Window},
    ssh::{
        input::{Editor, Line, SharedInput, Writer},
        notices::Notices,
        output::HumanWriter,
        server::{Dispatcher, Permit, Shared},
    },
};

struct ChannelState {
    channel: Option<Channel<Msg>>,
    term: Option<String>,
    window: watch::Sender<Window>,
    signals: mpsc::Sender<Signal>,
    signal_rx: Option<mpsc::Receiver<Signal>>,
    cancel: CancellationToken,
    permit: Option<Permit>,
    denied: Option<(u32, &'static str)>,
}

impl Drop for ChannelState {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub(crate) struct Handler {
    caller: Option<Caller>,
    dispatcher: Arc<dyn Dispatcher>,
    shared: Arc<Shared>,
    cancel: CancellationToken,
    channels: HashMap<ChannelId, ChannelState>,
}

impl Handler {
    pub(crate) fn new(
        caller: Option<Caller>,
        dispatcher: Arc<dyn Dispatcher>,
        shared: Arc<Shared>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            caller,
            dispatcher,
            shared,
            cancel,
            channels: HashMap::new(),
        }
    }

    fn start(
        &mut self,
        id: ChannelId,
        line: Option<String>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Some(state) = self.channels.get_mut(&id) else {
            return session.channel_failure(id);
        };
        let Some(channel) = state.channel.take() else {
            return session.channel_failure(id);
        };
        session.channel_success(id)?;
        let handle = session.handle();
        let denied = state.denied;
        let caller = self.caller.clone();
        let dispatcher = self.dispatcher.clone();
        let term = state.term.take();
        let window = state.window.subscribe();
        let signals = state.signal_rx.take();
        let cancel = state.cancel.clone();
        let permit = state.permit.take();
        tokio::spawn(async move {
            let code = if let Some((code, message)) = denied {
                let _ = handle
                    .extended_data(id, 1, format!("Error: {message}\n"))
                    .await;
                code
            } else if let (Some(caller), Some(signals)) = (caller, signals) {
                let run = run(
                    channel,
                    caller,
                    dispatcher,
                    term,
                    window,
                    signals,
                    cancel.clone(),
                    line,
                );
                tokio::select! { biased; code = run => code, _ = cancel.cancelled() => 255 }
            } else {
                4
            };
            drop(permit);
            let finish = async {
                let _ = handle.exit_status_request(id, code).await;
                let _ = handle.eof(id).await;
                let _ = handle.close(id).await;
                if denied.is_some_and(|(code, _)| code == 4) {
                    let _ = handle
                        .disconnect(
                            russh::Disconnect::ByApplication,
                            "exit 4: identity unavailable or node not tagged".into(),
                            "en".into(),
                        )
                        .await;
                }
            };
            let _ = tokio::time::timeout(Duration::from_secs(2), finish).await;
        });
        Ok(())
    }
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let permit = self
            .caller
            .as_ref()
            .and_then(|caller| self.shared.admit(&caller.peer.node_id));
        let denied = if self.caller.is_none() {
            Some((4, "identity unavailable or node not tagged"))
        } else if permit.is_none() {
            Some((6, "session limit reached"))
        } else {
            None
        };
        let (window, _) = watch::channel(Window::default());
        let (signals, signal_rx) = mpsc::channel(16);
        let id = channel.id();
        self.channels.insert(
            id,
            ChannelState {
                channel: Some(channel),
                term: None,
                window,
                signals,
                signal_rx: Some(signal_rx),
                cancel: self.cancel.child_token(),
                permit,
                denied,
            },
        );
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        columns: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match (
            self.channels.get_mut(&channel),
            window(
                if columns == 0 { 80 } else { columns },
                if rows == 0 { 24 } else { rows },
            ),
        ) {
            (Some(state), Some(size))
                if state.channel.is_some() && state.term.is_none() && term.len() <= 256 =>
            {
                state.term = Some(term.to_owned());
                state.window.send_replace(size);
                session.channel_success(channel)?;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        columns: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let (Some(state), Some(size)) = (self.channels.get_mut(&channel), window(columns, rows))
        {
            state.window.send_replace(size);
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let signal = match signal {
            Sig::INT => Signal::Int,
            Sig::TERM => Signal::Term,
            Sig::HUP => Signal::Hup,
            Sig::QUIT => Signal::Quit,
            Sig::KILL => Signal::Kill,
            Sig::USR1 => Signal::Usr1,
            Sig::Custom(name) if name == "USR2" => Signal::Usr2,
            _ => return Ok(()),
        };
        if let Some(state) = self.channels.get(&channel) {
            if state.signals.try_send(signal).is_err() {
                state.cancel.cancel();
            }
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data.len() > 16384 {
            return session.channel_failure(channel);
        }
        match std::str::from_utf8(data) {
            Ok(line) => self.start(channel, Some(line.to_owned()), session),
            Err(_) => session.channel_failure(channel),
        }
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, None, session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        session.channel_failure(channel)?;
        Ok(false)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single: bool,
        _protocol: &str,
        _cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
    }
}

fn window(columns: u32, rows: u32) -> Option<Window> {
    let columns = u16::try_from(columns).ok().filter(|value| *value > 0)?;
    let rows = u16::try_from(rows).ok().filter(|value| *value > 0)?;
    Some(Window { rows, columns })
}

#[allow(clippy::too_many_arguments)]
async fn run(
    channel: Channel<Msg>,
    caller: Caller,
    dispatcher: Arc<dyn Dispatcher>,
    term: Option<String>,
    window: watch::Receiver<Window>,
    signals: mpsc::Receiver<Signal>,
    cancel: CancellationToken,
    line: Option<String>,
) -> u32 {
    let pty = term.is_some();
    let stdout = channel.make_writer();
    let stderr = channel.make_writer_ext(Some(1));
    let prompt_output = channel.make_writer_ext(Some(1));
    let human: Writer = Arc::new(Mutex::new(if pty {
        Box::new(HumanWriter::new(prompt_output))
    } else {
        Box::new(prompt_output)
    }));
    let input = SharedInput::new(channel.into_stream());
    let editor = Arc::new(Mutex::new(Editor::new(input.clone(), human, pty)));
    let notices = Arc::new(Notices::default());
    let prompt_editor = editor.clone();
    let shown = notices.clone();
    let extras = SessionExtras {
        prompt: Some(Arc::new(move |prompt, limit| {
            let editor = prompt_editor.clone();
            Box::pin(async move {
                match editor.lock().await.read_line(&prompt, limit, false).await {
                    Ok(Line::Text(line)) => Ok(line),
                    Ok(Line::Cancelled | Line::Eof) => {
                        Err(Failure::new(Code::Cancelled, "confirmation cancelled"))
                    }
                    Err(error) => Err(Failure::new(Code::Usage, error.to_string())),
                }
            })
        })),
        approval_shown: Some(Arc::new(move |id, url| shown.shown(id, url))),
    };
    let mut io = SessionIo {
        stdin: Box::new(input),
        stdout: Box::new(stdout),
        stderr: if pty {
            Box::new(HumanWriter::new(stderr))
        } else {
            Box::new(stderr)
        },
        terminal: term.map(|term| Terminal { term, window }),
        signals,
        cancel: cancel.clone(),
    };
    let execute = async {
        let code = if let Some(line) = line {
            match caller.fresh().await {
                Ok(peer) => {
                    dispatcher
                        .dispatch(
                            &Caller::new(peer, fresh_resolver(&caller)),
                            &line,
                            &mut io,
                            &extras,
                        )
                        .await as u32
                }
                Err(_) => {
                    let _ = io
                        .stderr
                        .write_all(b"Error: identity unavailable or changed\n")
                        .await;
                    4
                }
            }
        } else if !pty {
            let _ = io.stderr.write_all(help::help().as_bytes()).await;
            2
        } else {
            repl(&caller, dispatcher, &mut io, &extras, editor, notices).await
        };
        let _ = io.stdout.flush().await;
        let _ = io.stderr.flush().await;
        code
    };
    if pty {
        tokio::select! {
            code = execute => code,
            _ = identity_expired(&caller) => { cancel.cancel(); 4 }
        }
    } else {
        execute.await
    }
}

fn fresh_resolver(caller: &Caller) -> crate::lobby::caller::Resolve {
    let caller = caller.clone();
    Arc::new(move || {
        let caller = caller.clone();
        Box::pin(async move { caller.fresh().await })
    })
}

async fn identity_expired(caller: &Caller) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.tick().await;
    loop {
        interval.tick().await;
        if caller.fresh().await.is_err() {
            return;
        }
    }
}

async fn repl(
    caller: &Caller,
    dispatcher: Arc<dyn Dispatcher>,
    io: &mut SessionIo,
    extras: &SessionExtras,
    editor: Arc<Mutex<Editor>>,
    notices: Arc<Notices>,
) -> u32 {
    loop {
        let (send, receive) = mpsc::channel(8);
        let stop = CancellationToken::new();
        let _stop_on_drop = stop.clone().drop_guard();
        let task = tokio::spawn(notices.clone().poll(
            dispatcher.clone(),
            caller.clone(),
            send,
            stop.clone(),
        ));
        let line = {
            let mut editor = editor.lock().await;
            editor.notices(receive, notices.clone());
            let line = editor.read_line("silo> ", 16384, true).await;
            editor.clear_notices();
            line
        };
        stop.cancel();
        let _ = task.await;
        let line = match line {
            Ok(Line::Text(line)) => line,
            Ok(Line::Cancelled) => continue,
            Ok(Line::Eof) => return 0,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                let _ = io.stderr.write_all(b"Error: input line too long\n").await;
                continue;
            }
            Err(_) => return 255,
        };
        let line = line.trim();
        if line == "exit" {
            return 0;
        }
        if line.is_empty() {
            continue;
        }
        let peer = match caller.fresh().await {
            Ok(peer) => peer,
            Err(_) => return 4,
        };
        let caller = Caller::new(peer, fresh_resolver(caller));
        if dispatcher.dispatch(&caller, line, io, extras).await == 255 {
            return 255;
        }
    }
}
