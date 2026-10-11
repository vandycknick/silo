//! Spawn-backed CLI terminal qualification using real PTYs and guest processes.
#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use libvm::{ImageSource, MachineReadinessOutcome, Runtime, RuntimeConfig};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::pty::{openpty, Winsize};
use nix::sys::signal::{kill, Signal};
use nix::sys::termios::{self, LocalFlags};
use nix::unistd::Pid;

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn resize(fd: &impl AsRawFd, rows: u16, columns: u16) -> std::io::Result<()> {
    let size = Winsize {
        ws_row: rows,
        ws_col: columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // nix has no safe terminal-size setter.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &size) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn terminal_command(
    home: &Path,
    machine: &str,
    argv: &[&str],
    mut on_ready: impl FnMut(&mut File, Pid) -> eyre::Result<()>,
) -> eyre::Result<(ExitStatus, Vec<u8>, bool)> {
    let pty = openpty(
        Some(&Winsize {
            ws_row: 37,
            ws_col: 119,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )?;
    let original = termios::tcgetattr(&pty.slave)?;
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_silo"))
            .env("SILO_HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .args(["exec", machine, "--tty", "--"])
            .args(argv)
            .stdin(Stdio::from(pty.slave.try_clone()?))
            .stdout(Stdio::from(pty.slave.try_clone()?))
            .stderr(Stdio::from(pty.slave.try_clone()?))
            .spawn()?,
    );
    let pid = Pid::from_raw(i32::try_from(child.0.id())?);
    let mut master = File::from(pty.master);
    let flags = OFlag::from_bits_truncate(fcntl(&master, FcntlArg::F_GETFL)?);
    fcntl(&master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut output = Vec::new();
    let mut raw_seen = false;
    let mut action_sent = false;
    let mut exited = None;
    let result = loop {
        let mut bytes = [0; 8192];
        loop {
            match master.read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => output.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        raw_seen |= !termios::tcgetattr(&pty.slave)?
            .local_flags
            .contains(LocalFlags::ICANON);
        if !action_sent && raw_seen && output.windows(5).any(|bytes| bytes == b"READY") {
            on_ready(&mut master, pid)?;
            action_sent = true;
        }
        if let Some(status) = exited {
            break Ok((status, output, raw_seen));
        }
        exited = child.0.try_wait()?;
        if Instant::now() >= deadline {
            break Err(eyre::eyre!(
                "CLI terminal timed out: {}",
                String::from_utf8_lossy(&output)
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    drop(child);
    eyre::ensure!(
        termios::tcgetattr(&pty.slave)? == original,
        "CLI failed to restore host termios"
    );
    result
}

#[tokio::test]
async fn interactive_spawn_real_vm_restores_terminal_and_forwards_controls() {
    if std::env::var("SILO_E2E_KVM").as_deref() != Ok("1") {
        eprintln!("SKIPPED CLI terminal VM: SILO_E2E_KVM=1 is required");
        return;
    }
    assert!(
        Path::new("/dev/kvm").exists(),
        "SILO_E2E_KVM=1 requires /dev/kvm"
    );
    let root = std::env::var_os("SILO_TEST_RUNTIME_ROOT").expect("matching runtime artifacts");
    let image = std::env::var_os("SILO_TEST_DISK_IMAGE").expect("disposable ext4 guest image");
    let home = tempfile::tempdir().unwrap();
    let runtime = Runtime::new(RuntimeConfig::local(home.path()).with_runtime_root(root))
        .await
        .unwrap();
    let machine = runtime
        .machine()
        .name("cli-terminal")
        .image_source(ImageSource::disk(image))
        .vsock(true)
        .create()
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(240), async {
        machine.start().await?;
        let ready = machine.wait_ready(Duration::from_secs(90)).await?;
        eyre::ensure!(ready.outcome == MachineReadinessOutcome::Ready, "guest not ready");
        let home_path = home.path().to_owned();
        let id = machine.id().to_string();
        tokio::task::spawn_blocking(move || -> eyre::Result<()> {
            let (status, output, raw) = terminal_command(&home_path, &id, &["/bin/sh", "-c",
                "sleep .2; stty size; printf 'READY\\n'; IFS= read -r value; printf 'INPUT:%s\\n' \"$value\"; stty size; exit 7"],
                |master, pid| {
                    resize(master, 41, 127)?;
                    kill(pid, Signal::SIGWINCH)?;
                    std::thread::sleep(Duration::from_millis(100));
                    master.write_all(b"literal:$HOME\n")?;
                    Ok(())
                })?;
            eyre::ensure!(raw && status.code() == Some(7), "normal PTY result: {status}");
            let output = String::from_utf8(output)?;
            eyre::ensure!(output.contains("37 119") && output.contains("41 127")
                && output.contains("INPUT:literal:$HOME"), "PTY output: {output}");

            let (status, _, raw) = terminal_command(&home_path, &id, &["/nonexistent-cli-regression"], |_, _| Ok(()))?;
            eyre::ensure!(status.code() == Some(127) && !raw, "launch failure enabled raw input: {status}");

            for (signal, expected) in [(Signal::SIGINT, 42), (Signal::SIGTERM, 43), (Signal::SIGUSR1, 44), (Signal::SIGUSR2, 45)] {
                let (status, output, raw) = terminal_command(&home_path, &id, &["/bin/sh", "-c",
                    "trap 'exit 42' INT; trap 'exit 43' TERM; trap 'exit 44' USR1; trap 'exit 45' USR2; printf 'READY\\n'; while :; do sleep .1; done"],
                    |_, pid| { kill(pid, signal)?; Ok(()) })?;
                eyre::ensure!(raw && status.code() == Some(expected), "signal {signal}: {status}, {}", String::from_utf8_lossy(&output));
            }

            // Host EOF for a PTY must not send pipe CloseStdin or stop event draining.
            let mut child = OwnedChild(Command::new(env!("CARGO_BIN_EXE_silo"))
                .env("SILO_HOME", &home_path).env("XDG_CONFIG_HOME", home_path.join("config"))
                .args(["exec", &id, "--tty", "--", "/bin/sh", "-c", "sleep .2; printf trailing; exit 7"])
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
            let deadline = Instant::now() + Duration::from_secs(15);
            let status = loop {
                if let Some(status) = child.0.try_wait()? { break status; }
                eyre::ensure!(Instant::now() < deadline, "PTY EOF command timed out");
                std::thread::sleep(Duration::from_millis(5));
            };
            let mut output = Vec::new();
            child.0.stdout.take().expect("stdout").read_to_end(&mut output)?;
            eyre::ensure!(status.code() == Some(7) && output == b"trailing", "PTY EOF lost output/status: {status}, {output:?}");
            Ok(())
        }).await??;
        Ok::<(), eyre::Report>(())
    }).await;
    let stopped = machine.stop().await;
    let removed = machine.remove().await;
    result
        .expect("bounded qualification")
        .expect("terminal qualification");
    stopped.expect("stop fixture");
    removed.expect("remove fixture");
}
