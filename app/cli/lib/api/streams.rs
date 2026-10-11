use std::collections::BTreeMap;
use std::os::fd::AsRawFd;

use eyre::Context as _;
use libvm::{
    ExecutionControl, ExecutionEvent, ExecutionOptionsBuilder, ExecutionResult, ExecutionSession,
    MachineData, ProcessConfig, SshExitStatus,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use utils::terminal::RawTerminalGuard;

use crate::api::machine::AppMachine;

pub(crate) async fn shell(
    machine: &AppMachine,
    user: Option<&str>,
    forward_agent: bool,
) -> eyre::Result<SshExitStatus> {
    let cwd = std::env::current_dir().context("resolve current working directory")?;
    machine
        .session_machine()
        .await?
        .shell_with(|options| {
            let options = options.cwd(cwd.to_string_lossy()).best_effort_cwd();
            let options = match user {
                Some(user) => options.user(user),
                None => options,
            };
            options.forward_agent(forward_agent)
        })
        .await
        .map_err(Into::into)
}

pub(crate) fn ensure_running(data: &MachineData) -> eyre::Result<()> {
    if data.is_running() {
        return Ok(());
    }
    Err(eyre::eyre!(
        "machine `{}` is not running; start it with `silo start {}`",
        data.name,
        data.name
    ))
}

pub(crate) fn ensure_guest_ready(data: &MachineData) -> eyre::Result<()> {
    if data.status.guest_ready() {
        return Ok(());
    }
    let summary = data
        .status
        .message()
        .map(str::to_string)
        .unwrap_or_else(|| format!("machine state is {}", data.status.label()));
    eyre::bail!("guest service is not ready: {summary}")
}

pub(crate) async fn run_command_streaming(
    machine: &AppMachine,
    user: Option<&str>,
    argv: &[String],
    working_directory: &str,
    environment: &BTreeMap<String, String>,
) -> eyre::Result<ExecutionResult> {
    let (program, args) = command_argv(argv)?;
    let mut session = machine
        .session_machine()
        .await?
        .spawn_with(program, |options| {
            with_exec_options(options.args(args), user, working_directory, environment).stdin_pipe()
        })
        .await?;
    stream_events(&mut session, StreamMode::Piped).await
}

pub(crate) async fn attach_command(
    machine: &AppMachine,
    user: Option<&str>,
    argv: &[String],
    working_directory: &str,
    environment: &BTreeMap<String, String>,
) -> eyre::Result<ExecutionResult> {
    let (program, args) = command_argv(argv)?;
    let mut session = machine
        .session_machine()
        .await?
        .spawn_with(program, |options| {
            with_exec_options(options.args(args), user, working_directory, environment)
                .stdin_pipe()
                .tty(true)
        })
        .await?;
    stream_events(&mut session, StreamMode::Interactive).await
}

/// Runs one exact process configuration through the structured guest protocol.
/// The caller owns machine lifecycle; this function owns only process I/O.
pub(crate) async fn run_process(
    machine: &AppMachine,
    process: &ProcessConfig,
    argv: &[String],
    tty: bool,
) -> eyre::Result<ExecutionResult> {
    if tty {
        return attach_command(
            machine,
            process.user.as_deref(),
            argv,
            &process.working_directory,
            &process.environment,
        )
        .await;
    }
    run_command_streaming(
        machine,
        process.user.as_deref(),
        argv,
        &process.working_directory,
        &process.environment,
    )
    .await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    Piped,
    Interactive,
}

async fn stream_events(
    session: &mut ExecutionSession,
    mode: StreamMode,
) -> eyre::Result<ExecutionResult> {
    // Input's Drop joins its worker before the terminal guard restores termios.
    let mut _raw_terminal = None;
    let mut host_stdin = match mode {
        StreamMode::Piped => {
            Some(libvm::host_input::HostInput::stdin().context("open host stdin")?)
        }
        StreamMode::Interactive => None,
    };
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let control = session.control();
    let mut stdin: Option<libvm::ExecutionStdin> = None;
    let mut stdin_closed = false;
    let mut started = false;
    let mut launch_cancelled = false;
    let mut signals = match mode {
        StreamMode::Piped => HostSignals::forwardable()?,
        StreamMode::Interactive => HostSignals::new(interactive_signals())?,
    };
    let mut signals_open = true;
    loop {
        let event = tokio::select! {
            event = session.recv() => event?,
            read = read_host_input(&mut host_stdin), if started && !launch_cancelled && !stdin_closed => {
                let input = read.context("read host stdin")?;
                if input.is_empty() {
                    stdin_closed = true;
                    if mode == StreamMode::Piped {
                        if let Some(stdin) = stdin.as_ref() {
                            stdin.close().await.context("close guest stdin")?;
                        }
                    }
                } else if let Some(stdin) = stdin.as_ref() {
                    stdin.write(input).await.context("write guest stdin")?;
                }
                continue;
            }
            signal = signals.recv(), if signals_open => {
                if let Some(signal) = signal {
                    if mode == StreamMode::Interactive && signal == libc::SIGWINCH as u32 {
                        if started && !launch_cancelled {
                            let (rows, columns) = current_terminal_size();
                            control.resize_pty(rows, columns).await.context("resize guest terminal")?;
                        }
                    } else {
                        let signal = if mode == StreamMode::Interactive {
                            guest_signal(signal).ok_or_else(|| eyre::eyre!("unsupported host signal {signal}"))?
                        } else {
                            signal
                        };
                        forward_signal(&control, started, &mut launch_cancelled, signal).await?;
                    }
                } else {
                    signals_open = false;
                }
                continue;
            }
        };
        let Some(event) = event else {
            break;
        };
        match event {
            ExecutionEvent::Accepted => {}
            ExecutionEvent::Started if !launch_cancelled => {
                if mode == StreamMode::Interactive {
                    _raw_terminal = Some(
                        RawTerminalGuard::new(std::io::stdin()).context("enable raw terminal")?,
                    );
                    host_stdin =
                        Some(libvm::host_input::HostInput::stdin().context("open host stdin")?);
                }
                stdin = control.stdin();
                started = true;
            }
            ExecutionEvent::Started => started = true,
            ExecutionEvent::Stdout(data) => {
                stdout
                    .write_all(&data)
                    .await
                    .context("write guest stdout")?;
                stdout.flush().await.context("flush guest stdout")?;
            }
            ExecutionEvent::Stderr(data) if mode == StreamMode::Interactive => {
                stdout
                    .write_all(&data)
                    .await
                    .context("write guest terminal output")?;
                stdout
                    .flush()
                    .await
                    .context("flush guest terminal output")?;
            }
            ExecutionEvent::Stderr(data) => {
                stderr
                    .write_all(&data)
                    .await
                    .context("write guest stderr")?;
                stderr.flush().await.context("flush guest stderr")?;
            }
            ExecutionEvent::TerminalOutput(data) => {
                stdout
                    .write_all(&data)
                    .await
                    .context("write guest terminal output")?;
                stdout
                    .flush()
                    .await
                    .context("flush guest terminal output")?;
            }
            ExecutionEvent::Terminal(result) => return Ok(result),
        }
    }
    eyre::bail!("guest command ended without a terminal result")
}

async fn read_host_input(
    input: &mut Option<libvm::host_input::HostInput>,
) -> std::io::Result<Vec<u8>> {
    match input {
        Some(input) => input.read().await,
        None => std::future::pending().await,
    }
}

fn interactive_signals() -> impl Iterator<Item = u32> {
    [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
    ]
    .into_iter()
    .map(|signal| signal as u32)
}

// Host signal numbers are not Linux guest signal numbers on macOS.
fn guest_signal(signal: u32) -> Option<u32> {
    match signal as i32 {
        libc::SIGHUP => Some(1),
        libc::SIGINT => Some(2),
        libc::SIGQUIT => Some(3),
        libc::SIGTERM => Some(15),
        libc::SIGUSR1 => Some(10),
        libc::SIGUSR2 => Some(12),
        _ => None,
    }
}

fn current_terminal_size() -> (u16, u16) {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // nix has no safe terminal-size query.
    if unsafe { libc::ioctl(std::io::stdout().as_raw_fd(), libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_row > 0
        && size.ws_col > 0
    {
        (size.ws_row, size.ws_col)
    } else {
        (24, 80)
    }
}

pub(crate) struct HostSignals {
    receiver: mpsc::Receiver<u32>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl HostSignals {
    fn new(signals: impl IntoIterator<Item = u32>) -> eyre::Result<Self> {
        let (sender, receiver) = mpsc::channel(64);
        let mut tasks = Vec::new();
        for signal in signals {
            let Ok(mut listener) = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::from_raw(signal as i32),
            ) else {
                continue;
            };
            let sender = sender.clone();
            tasks.push(tokio::spawn(async move {
                while listener.recv().await.is_some() {
                    if sender.send(signal).await.is_err() {
                        break;
                    }
                }
            }));
        }
        drop(sender);
        if tasks.is_empty() {
            eyre::bail!("listen for host signals");
        }
        Ok(Self { receiver, tasks })
    }

    fn forwardable() -> eyre::Result<Self> {
        Self::new(forwardable_signals())
    }

    pub(crate) fn termination() -> eyre::Result<Self> {
        Self::new([libc::SIGINT as u32, libc::SIGTERM as u32])
    }

    pub(crate) async fn recv(&mut self) -> Option<u32> {
        self.receiver.recv().await
    }
}

impl Drop for HostSignals {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn forwardable_signals() -> impl Iterator<Item = u32> {
    (1..=64).filter(|signal| {
        !matches!(
            *signal as i32,
            libc::SIGKILL | libc::SIGSTOP | libc::SIGCHLD | libc::SIGWINCH
        )
    })
}

async fn forward_signal(
    control: &ExecutionControl,
    started: bool,
    launch_cancelled: &mut bool,
    signal: u32,
) -> eyre::Result<()> {
    if !started {
        if !*launch_cancelled {
            control.close_requests();
            *launch_cancelled = true;
        }
        return Ok(());
    }
    if *launch_cancelled {
        return Ok(());
    }
    control
        .signal(signal)
        .await
        .wrap_err_with(|| format!("forward host signal {signal} to guest"))
}

fn command_argv(argv: &[String]) -> eyre::Result<(String, Vec<String>)> {
    let Some((program, args)) = argv.split_first() else {
        eyre::bail!("guest command is required");
    };
    Ok((program.clone(), args.to_vec()))
}

fn with_exec_options(
    builder: ExecutionOptionsBuilder,
    user: Option<&str>,
    working_directory: &str,
    environment: &BTreeMap<String, String>,
) -> ExecutionOptionsBuilder {
    let builder = builder.cwd(working_directory).envs(
        environment
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    match user {
        Some(user) => builder.user(user),
        None => builder,
    }
}

#[cfg(test)]
mod tests {
    use crate::api::streams::{
        command_argv, forwardable_signals, guest_signal, interactive_signals,
    };

    #[test]
    fn command_argv_preserves_the_exact_argv_vector() {
        let argv = vec!["cargo test".to_string(), "name with spaces".to_string()];
        let (program, args) = command_argv(&argv).expect("command argv");
        assert_eq!(program, "cargo test");
        assert_eq!(args, ["name with spaces"]);
    }

    #[test]
    fn command_argv_rejects_empty_command() {
        assert!(command_argv(&[]).is_err());
    }

    #[test]
    fn pipe_signal_forwarding_excludes_unforwardable_signals() {
        let signals = forwardable_signals().collect::<Vec<_>>();

        for signal in [libc::SIGKILL, libc::SIGSTOP, libc::SIGCHLD, libc::SIGWINCH] {
            assert!(!signals.contains(&(signal as u32)));
        }
        assert!(signals.contains(&(libc::SIGINT as u32)));
        assert!(signals.contains(&(libc::SIGTERM as u32)));
    }

    #[test]
    fn interactive_signals_use_linux_guest_numbers_and_keep_resize_separate() {
        for (host, guest) in [
            (libc::SIGHUP, 1),
            (libc::SIGINT, 2),
            (libc::SIGQUIT, 3),
            (libc::SIGTERM, 15),
            (libc::SIGUSR1, 10),
            (libc::SIGUSR2, 12),
        ] {
            assert_eq!(guest_signal(host as u32), Some(guest));
            assert!(interactive_signals().any(|signal| signal == host as u32));
        }
        assert_eq!(guest_signal(libc::SIGWINCH as u32), None);
        assert!(interactive_signals().any(|signal| signal == libc::SIGWINCH as u32));
        assert_eq!(guest_signal(libc::SIGCHLD as u32), None);
    }
}
