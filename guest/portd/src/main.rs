#![cfg(target_os = "linux")]

mod args;
mod http;
mod status;

use std::io::Read;
use std::os::fd::BorrowedFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
use std::sync::mpsc;
use std::time::Duration;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::prctl;
use nix::sys::signal::{kill, pthread_sigmask, SigSet, SigmaskHow, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::unistd::{getpid, getppid, Pid};

const DEFAULT_ENDPOINT: &str = "http://gateway.containers.internal:80";
const DEFAULT_DOCKER_PROXY: &str = "/usr/bin/docker-proxy";

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            let message = format!("silo-portd: {error}");
            let _ = status::report_failure(&message);
            eprintln!("{message}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32, String> {
    let config = args::parse(std::env::args_os().skip(1))?;
    if config.protocol != "tcp" {
        return Err(format!("{} publication is not supported", config.protocol));
    }
    let endpoint =
        std::env::var("SILO_PORTD_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    let hold = http::expose(&endpoint, config.host_ip, config.host_port)?;
    let mut drain = hold
        .drain_stream()
        .map_err(|error| format!("clone publication hold: {error}"))?;

    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
        .map_err(|error| format!("block stop signals: {error}"))?;
    let signal_fd = SignalFd::with_flags(&signals, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .map_err(|error| format!("create signal descriptor: {error}"))?;

    inherit_fd(status::STATUS_FD)?;
    if config.use_listen_fd {
        inherit_fd(status::LISTENER_FD)?;
    }
    let proxy =
        std::env::var_os("SILO_PORTD_DOCKER_PROXY").unwrap_or_else(|| DEFAULT_DOCKER_PROXY.into());
    let mut command = Command::new(proxy);
    command.args(&config.proxy_args);
    let parent_pid = getpid();
    unsafe {
        command.pre_exec(move || {
            prctl::set_pdeathsig(Signal::SIGTERM).map_err(std::io::Error::other)?;
            if getppid() != parent_pid {
                return Err(std::io::Error::other(
                    "silo-portd exited before docker-proxy supervision was established",
                ));
            }
            pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&stop_signals()), None)
                .map_err(std::io::Error::other)
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("start docker-proxy: {error}"))?;
    let child_pid = Pid::from_raw(
        i32::try_from(child.id()).map_err(|error| format!("invalid docker-proxy PID: {error}"))?,
    );

    enum Event {
        Child(ExitStatus),
        HoldClosed(String),
    }
    let (events, receiver) = mpsc::channel();
    let child_events = events.clone();
    std::thread::spawn(move || {
        let result = child
            .wait()
            .map(Event::Child)
            .unwrap_or_else(|error| Event::HoldClosed(format!("wait for docker-proxy: {error}")));
        let _ = child_events.send(result);
    });
    std::thread::spawn(move || {
        let mut byte = [0; 1];
        let reason = match drain.read(&mut byte) {
            Ok(0) => "publication hold closed unexpectedly".to_string(),
            Ok(_) => "publication endpoint sent unexpected data".to_string(),
            Err(error) => format!("publication hold failed: {error}"),
        };
        let _ = events.send(Event::HoldClosed(reason));
    });

    let status = loop {
        while let Some(info) = signal_fd
            .read_signal()
            .map_err(|error| format!("read stop signal: {error}"))?
        {
            if let Ok(signal) = Signal::try_from(info.ssi_signo as i32) {
                let _ = kill(child_pid, signal);
            }
        }
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Event::Child(status)) => break status,
            Ok(Event::HoldClosed(reason)) => {
                eprintln!("silo-portd: {reason}");
                let _ = kill(child_pid, Signal::SIGTERM);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("docker-proxy supervision stopped unexpectedly".to_string());
            }
        }
    };
    hold.close();
    Ok(exit_code(status))
}

fn inherit_fd(raw_fd: i32) -> Result<(), String> {
    let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    let flags = fcntl(fd, FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_truncate)
        .map_err(|error| format!("inspect inherited fd {raw_fd}: {error}"))?;
    fcntl(fd, FcntlArg::F_SETFD(flags - FdFlag::FD_CLOEXEC))
        .map_err(|error| format!("inherit fd {raw_fd}: {error}"))?;
    Ok(())
}

fn stop_signals() -> SigSet {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    signals
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;

    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}
