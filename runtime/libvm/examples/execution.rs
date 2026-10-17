use std::error::Error;
use std::process::ExitCode;

use libvm::{
    ExecutionEvent, ExecutionOutput, ExecutionResult, Machine, MachineRef, Runtime,
    SshShellAttachment, SshShellControl,
};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<ExitCode, Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let reference = args
        .next()
        .ok_or("usage: execution <machine-reference> <exec|script|spawn|shell|embedded-shell>")?;
    let mode = args.next().ok_or("missing execution mode")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let runtime = Runtime::from_env().await?;
    let machine = runtime.get_machine(&MachineRef::parse(reference)?).await?;
    let code = match mode.as_str() {
        "exec" => {
            let output = machine.exec("/usr/bin/printf", ["%s\n", "$HOME"]).await?;
            print_output(output).await?
        }
        "script" => {
            let output = machine
                .exec_script("printf '%s\\n' \"$HOME\" | /usr/bin/tr a-z A-Z")
                .await?;
            print_output(output).await?
        }
        "spawn" => stream_cat(&machine).await?,
        "shell" => machine.shell().await?.code,
        "embedded-shell" => embedded_shell(&machine).await?,
        _ => return Err(format!("unknown execution mode: {mode}").into()),
    };
    Ok(ExitCode::from(u8::try_from(code)?))
}

async fn print_output(output: ExecutionOutput) -> Result<i32, Box<dyn Error>> {
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    stdout.write_all(output.stdout_bytes()).await?;
    stdout.write_all(output.terminal_output_bytes()).await?;
    stderr.write_all(output.stderr_bytes()).await?;
    stdout.flush().await?;
    stderr.flush().await?;
    result_code(output.result())
}

fn result_code(result: &ExecutionResult) -> Result<i32, Box<dyn Error>> {
    match result {
        ExecutionResult::Exited { code: Some(code) } => Ok(i32::try_from(*code)?),
        ExecutionResult::Signaled {
            signal: Some(signal),
        } => Ok(128_i32
            .checked_add(i32::try_from(*signal)?)
            .ok_or("signal status overflow")?),
        other => Err(format!("execution did not return an exit code: {other:?}").into()),
    }
}

async fn stream_cat(machine: &Machine) -> Result<i32, Box<dyn Error>> {
    let mut session = machine
        .spawn_with("/bin/cat", |options| options.stdin_pipe())
        .await?;
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    loop {
        // This example sends a small finite input. For large bidirectional
        // transfers, drive a cloned input handle concurrently with recv().
        match session.recv().await?.ok_or("missing terminal result")? {
            ExecutionEvent::Started => {
                let input = session.stdin().ok_or("stdin unavailable after Started")?;
                input.write(b"streamed input\n".to_vec()).await?;
                input.close().await?;
            }
            ExecutionEvent::Stdout(bytes) | ExecutionEvent::TerminalOutput(bytes) => {
                stdout.write_all(&bytes).await?;
            }
            ExecutionEvent::Stderr(bytes) => stderr.write_all(&bytes).await?,
            ExecutionEvent::Terminal(result) => {
                stdout.flush().await?;
                stderr.flush().await?;
                return result_code(&result);
            }
            ExecutionEvent::Accepted => {}
        }
    }
}

async fn embedded_shell(machine: &Machine) -> Result<i32, Box<dyn Error>> {
    let cancellation = CancellationToken::new();
    let (controls, receiver) = tokio::sync::mpsc::channel(8);
    let attachment = SshShellAttachment::new(
        std::io::Cursor::new(b"printf 'embedded:%s\\n' \"$USER\"; exit 7\n".to_vec()),
        tokio::io::stdout(),
        tokio::io::stderr(),
        37,
        119,
    )
    .controls(receiver);
    controls
        .send(SshShellControl::Resize {
            rows: 37,
            columns: 119,
        })
        .await?;
    drop(controls);
    let status = machine
        .shell_with(|options| {
            options
                .term("xterm-256color")
                .attachment(attachment)
                .cancellation(cancellation)
        })
        .await?;
    eprintln!("SSH exit code: {}", status.code);
    Ok(status.code)
}
