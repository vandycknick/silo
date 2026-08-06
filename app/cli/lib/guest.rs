use std::io::Write;

use eyre::Context as _;
use libvm::{
    ExecutionControl, ExecutionEvent, ExecutionOptionsBuilder, ExecutionResult, ExecutionSession,
    ExecutionStdin, Machine, SshExitStatus,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

pub(crate) async fn run_legacy_command(
    machine: &Machine,
    argv: &[String],
    tty: bool,
) -> eyre::Result<SshExitStatus> {
    machine
        .run_legacy_ssh_command(argv, tty)
        .await
        .map_err(Into::into)
}

pub(crate) async fn run_command_streaming(
    machine: &Machine,
    user: Option<&str>,
    argv: &[String],
) -> eyre::Result<ExecutionResult> {
    let (program, args) = command_argv(argv)?;
    let mut session = machine
        .spawn_with(program, |options| {
            with_exec_user(options.args(args), user).stdin_pipe()
        })
        .await?;
    let stdin = session.stdin();
    if let Some(stdin) = stdin {
        tokio::spawn(forward_stdin(stdin));
    }
    stream_events(&mut session).await
}

pub(crate) async fn attach_command(
    machine: &Machine,
    user: Option<&str>,
    argv: &[String],
) -> eyre::Result<ExecutionResult> {
    let (program, args) = command_argv(argv)?;
    machine
        .attach_with(program, |options| with_exec_user(options.args(args), user))
        .await
        .map_err(Into::into)
}

async fn forward_stdin(stdin: ExecutionStdin) {
    let mut host_stdin = tokio::io::stdin();
    let mut buffer = [0_u8; 8192];
    loop {
        match host_stdin.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if let Err(error) = stdin.write(buffer[..read].to_vec()).await {
                    let _ = writeln!(std::io::stderr(), "guest stdin warning: {error}");
                    return;
                }
            }
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "guest stdin warning: {error}");
                return;
            }
        }
    }
    if let Err(error) = stdin.close().await {
        let _ = writeln!(std::io::stderr(), "guest stdin warning: {error}");
    }
}

async fn stream_events(session: &mut ExecutionSession) -> eyre::Result<ExecutionResult> {
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let control = session.control();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("listen for host interrupt")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("listen for host termination")?;
    loop {
        let event = tokio::select! {
            event = session.recv() => event?,
            signal = interrupt.recv() => {
                if signal.is_some() {
                    forward_signal(&control, libc::SIGINT as u32).await?;
                }
                continue;
            }
            signal = terminate.recv() => {
                if signal.is_some() {
                    forward_signal(&control, libc::SIGTERM as u32).await?;
                }
                continue;
            }
        };
        let Some(event) = event else {
            break;
        };
        match event {
            ExecutionEvent::Accepted | ExecutionEvent::Started => {}
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

async fn forward_signal(control: &ExecutionControl, signal: u32) -> eyre::Result<()> {
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

fn with_exec_user(builder: ExecutionOptionsBuilder, user: Option<&str>) -> ExecutionOptionsBuilder {
    match user {
        Some(user) => builder.user(user),
        None => builder,
    }
}

#[cfg(test)]
mod tests {
    use crate::guest::command_argv;

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
}
