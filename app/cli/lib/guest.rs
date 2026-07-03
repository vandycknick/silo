use std::io::Write;

use eyre::Context as _;
use libvm::{
    AttachOptionsBuilder, ExecEvent, ExecHandle, ExecOptionsBuilder, ExecSink, ExitStatus, Machine,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) async fn attach_shell(
    machine: &Machine,
    user: Option<&str>,
    forward_agent: bool,
) -> eyre::Result<ExitStatus> {
    let script = format!(
        "{}; exec \"${{SHELL:-/bin/bash}}\" -l || exec /bin/sh",
        current_dir_prologue()?
    );
    machine
        .attach_with("/bin/sh", |attach| {
            with_attach_user(attach.arg("-lc").arg(script), user).forward_agent(forward_agent)
        })
        .await
        .map_err(Into::into)
}

pub(crate) async fn run_command_streaming(
    machine: &Machine,
    user: Option<&str>,
    argv: &[String],
    forward_agent: bool,
) -> eyre::Result<ExitStatus> {
    if argv.is_empty() {
        eyre::bail!("guest command is required");
    }

    let script = command_script(argv)?;
    let mut handle = machine
        .spawn_with("/bin/sh", |command| {
            with_exec_user(command.arg("-lc").arg(script).stdin_pipe(), user)
                .forward_agent(forward_agent)
        })
        .await?;
    if let Some(stdin) = handle.take_stdin() {
        let _stdin_forward = tokio::spawn(forward_stdin(stdin));
    }
    stream_events(&mut handle).await
}

pub(crate) async fn attach_command(
    machine: &Machine,
    user: Option<&str>,
    argv: &[String],
    forward_agent: bool,
) -> eyre::Result<ExitStatus> {
    if argv.is_empty() {
        eyre::bail!("guest command is required");
    }

    let script = command_script(argv)?;
    machine
        .attach_with("/bin/sh", |attach| {
            with_attach_user(attach.arg("-lc").arg(script), user).forward_agent(forward_agent)
        })
        .await
        .map_err(Into::into)
}

async fn forward_stdin(sink: ExecSink) {
    let mut stdin = tokio::io::stdin();
    let mut buffer = [0_u8; 8192];

    loop {
        match stdin.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if let Err(error) = sink.write(buffer[..read].to_vec()).await {
                    let _ = writeln!(std::io::stderr(), "guest stdin warning: {error}");
                    break;
                }
            }
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "guest stdin warning: {error}");
                break;
            }
        }
    }

    sink.close();
}

async fn stream_events(handle: &mut ExecHandle) -> eyre::Result<ExitStatus> {
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    while let Some(event) = handle.recv().await {
        match event {
            ExecEvent::Started => {}
            ExecEvent::Stdout(data) => {
                stdout
                    .write_all(&data)
                    .await
                    .context("write guest stdout")?;
                stdout.flush().await.context("flush guest stdout")?;
            }
            ExecEvent::Stderr(data) => {
                stderr
                    .write_all(&data)
                    .await
                    .context("write guest stderr")?;
                stderr.flush().await.context("flush guest stderr")?;
            }
            ExecEvent::Exited { code } => {
                return Ok(ExitStatus {
                    code,
                    success: code == 0,
                });
            }
            ExecEvent::Failed { message } => {
                eyre::bail!("guest command failed: {message}");
            }
            ExecEvent::StdinError { message } => {
                writeln!(std::io::stderr(), "guest stdin warning: {message}")
                    .context("write guest stdin warning")?;
            }
        }
    }

    eyre::bail!("guest command ended without an exit status")
}

fn with_exec_user(builder: ExecOptionsBuilder, user: Option<&str>) -> ExecOptionsBuilder {
    match user {
        Some(user) => builder.user(user),
        None => builder,
    }
}

fn with_attach_user(builder: AttachOptionsBuilder, user: Option<&str>) -> AttachOptionsBuilder {
    match user {
        Some(user) => builder.user(user),
        None => builder,
    }
}

fn current_dir_prologue() -> eyre::Result<String> {
    let cwd = std::env::current_dir().context("resolve current working directory")?;
    Ok(format!(
        "cd {} 2>/dev/null || true",
        shell_quote(&cwd.to_string_lossy())
    ))
}

fn command_script(argv: &[String]) -> eyre::Result<String> {
    Ok(format!(
        "{}; exec {}",
        current_dir_prologue()?,
        shell_join(argv)
    ))
}

fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use crate::guest::{command_script, shell_join, shell_quote};

    #[test]
    fn shell_quote_handles_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
    }

    #[test]
    fn shell_join_quotes_each_argument() {
        assert_eq!(
            shell_join(&["cargo".to_string(), "test name".to_string()]),
            "'cargo' 'test name'"
        );
    }

    #[test]
    fn command_script_execs_quoted_argv_after_cwd_prologue() {
        let script = command_script(&["opencode".to_string(), "it's alive".to_string()])
            .expect("command script");

        assert!(script.starts_with("cd '"));
        assert!(script.contains("' 2>/dev/null || true; exec "));
        assert!(script.ends_with("'opencode' 'it'\"'\"'s alive'"));
    }
}
