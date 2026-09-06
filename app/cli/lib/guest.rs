use std::collections::BTreeMap;

use eyre::Context as _;
use libvm::{
    ExecutionControl, ExecutionEvent, ExecutionOptionsBuilder, ExecutionResult, ExecutionSession,
    Machine, MachineData, ProcessConfig, SshExitStatus,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

pub(crate) async fn attach_shell(
    machine: &Machine,
    user: Option<&str>,
    forward_agent: bool,
) -> eyre::Result<SshExitStatus> {
    let cwd = std::env::current_dir().context("resolve current working directory")?;
    machine
        .attach_shell_with(|options| {
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
    machine: &Machine,
    user: Option<&str>,
    argv: &[String],
    working_directory: &str,
    environment: &BTreeMap<String, String>,
) -> eyre::Result<ExecutionResult> {
    let (program, args) = command_argv(argv)?;
    let mut session = machine
        .spawn_with(program, |options| {
            with_exec_options(options.args(args), user, working_directory, environment).stdin_pipe()
        })
        .await?;
    stream_events(&mut session).await
}

pub(crate) async fn attach_command(
    machine: &Machine,
    user: Option<&str>,
    argv: &[String],
    working_directory: &str,
    environment: &BTreeMap<String, String>,
) -> eyre::Result<ExecutionResult> {
    let (program, args) = command_argv(argv)?;
    machine
        .attach_with(program, |options| {
            with_exec_options(options.args(args), user, working_directory, environment)
        })
        .await
        .map_err(Into::into)
}

/// Runs one exact process configuration through the structured guest protocol.
/// The caller owns machine lifecycle; this function owns only process I/O.
pub(crate) async fn run_process(
    machine: &Machine,
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

async fn stream_events(session: &mut ExecutionSession) -> eyre::Result<ExecutionResult> {
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut host_stdin = tokio::io::stdin();
    let mut input = [0_u8; 8192];
    let control = session.control();
    let mut stdin: Option<libvm::ExecutionStdin> = None;
    let mut stdin_closed = false;
    let mut started = false;
    let mut launch_cancelled = false;
    let mut signals = HostSignals::forwardable()?;
    loop {
        let event = tokio::select! {
            event = session.recv() => event?,
            read = host_stdin.read(&mut input), if started && !launch_cancelled && !stdin_closed => {
                let read = read.context("read host stdin")?;
                if read == 0 {
                    stdin_closed = true;
                    if let Some(stdin) = stdin.as_ref() {
                        stdin.close().await.context("close guest stdin")?;
                    }
                } else if let Some(stdin) = stdin.as_ref() {
                    stdin.write(input[..read].to_vec()).await.context("write guest stdin")?;
                }
                continue;
            }
            signal = signals.recv() => {
                if let Some(signal) = signal {
                    forward_signal(&control, started, &mut launch_cancelled, signal).await?;
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
    use crate::guest::{command_argv, forwardable_signals};

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
}
