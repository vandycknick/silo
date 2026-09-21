//! Real worker client used only by the signed Rosetta qualification harness.

#[path = "../../virt/backend/krun/inherit.rs"]
mod inherit;
#[path = "../../krun_worker/protocol.rs"]
#[allow(dead_code)]
pub(crate) mod protocol;

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub(crate) struct Worker {
    child: Child,
    _keepalive: OwnedFd,
    serial: Option<(File, File)>,
    events: Option<std::thread::JoinHandle<()>>,
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = nix::unistd::pipe()?;
    Ok((inherit::normalize(read)?, inherit::normalize(write)?))
}

impl Worker {
    pub(crate) fn start(vmmon: &Path, config: krun::KrunConfig) -> io::Result<Self> {
        let bytes = protocol::encode(
            &protocol::Launch::from_config(config)?,
            protocol::MAX_REQUEST,
        )?;
        let (request, send) = pipe()?;
        let (receive, events) = pipe()?;
        let (watchdog, keepalive) = pipe()?;
        let pty = nix::pty::openpty(None, None)?;
        let mut termios = nix::sys::termios::tcgetattr(&pty.slave)?;
        nix::sys::termios::cfmakeraw(&mut termios);
        nix::sys::termios::tcsetattr(&pty.slave, nix::sys::termios::SetArg::TCSANOW, &termios)?;
        let console = inherit::normalize(pty.slave)?;
        let master = File::from(pty.master);
        let serial = (master.try_clone()?, master);
        let mut command = Command::new(vmmon);
        command.arg0("krun").arg("__krun");
        for (name, fd) in [
            ("--request-fd", &request),
            ("--events-fd", &events),
            ("--watchdog-fd", &watchdog),
            ("--console-fd", &console),
        ] {
            command.arg(name).arg(fd.as_raw_fd().to_string());
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        inherit::install(&mut command, &[&request, &events, &watchdog, &console]);
        let mut worker = Self {
            child: command.spawn()?,
            _keepalive: keepalive,
            serial: Some(serial),
            events: None,
        };
        drop(command);
        drop(request);
        drop(events);
        worker.events = Some(
            std::thread::Builder::new()
                .name("rprobe-worker-events".to_string())
                .spawn(move || {
                    let mut receiver = File::from(receive);
                    loop {
                        let mut header = [0; 4];
                        if receiver.read_exact(&mut header).is_err() {
                            return;
                        }
                        let Ok(length) = protocol::frame_length(header, protocol::MAX_EVENT) else {
                            return;
                        };
                        let mut frame = vec![0; length];
                        if receiver.read_exact(&mut frame).is_err()
                            || protocol::decode::<protocol::Event>(&frame).is_err()
                        {
                            return;
                        }
                    }
                })?,
        );
        let flags = nix::fcntl::OFlag::from_bits_retain(nix::fcntl::fcntl(
            &send,
            nix::fcntl::FcntlArg::F_GETFL,
        )?);
        nix::fcntl::fcntl(
            &send,
            nix::fcntl::FcntlArg::F_SETFL(flags | nix::fcntl::OFlag::O_NONBLOCK),
        )?;
        let mut sender = File::from(send);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut pending = bytes.as_slice();
        while !pending.is_empty() {
            match sender.write(pending) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => pending = &pending[count..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    let mut poll = [nix::poll::PollFd::new(
                        sender.as_fd(),
                        nix::poll::PollFlags::POLLOUT,
                    )];
                    nix::poll::poll(
                        &mut poll,
                        nix::poll::PollTimeout::try_from(remaining).map_err(io::Error::other)?,
                    )?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline && !pending.is_empty() {
                return Err(io::ErrorKind::TimedOut.into());
            }
        }
        Ok(worker)
    }

    pub(crate) fn serial(&mut self) -> io::Result<(File, File)> {
        self.serial
            .take()
            .ok_or_else(|| io::Error::other("worker console already taken"))
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
    pub(crate) fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }
    pub(crate) fn shutdown(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        let pid = i32::try_from(self.child.id()).map_err(io::Error::other)?;
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGTERM,
        )?;
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(events) = self.events.take() {
            let _ = events.join();
        }
    }
}
