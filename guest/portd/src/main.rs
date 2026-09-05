#![cfg(target_os = "linux")]

mod args;
mod http;
mod relay;
mod status;

use std::io::Read;
use std::net::SocketAddr;
use std::os::fd::BorrowedFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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
    inherit_fd(status::STATUS_FD)?;
    if config.use_listen_fd {
        inherit_fd(status::LISTENER_FD)?;
    }
    // Block before creating the relay and hold-reader threads so stop signals
    // are handled by the supervisor, not delivered to an arbitrary worker.
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
        .map_err(|error| format!("block stop signals: {error}"))?;
    let signal_fd = SignalFd::with_flags(&signals, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .map_err(|error| format!("create signal descriptor: {error}"))?;

    let endpoint =
        std::env::var("SILO_PORTD_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    let client = http::PublicationClient::connect(&endpoint)?;
    let (guest, gateway) = client.addresses()?;
    let relay = relay::Relay::start(
        guest,
        gateway,
        SocketAddr::new(config.container_ip, config.container_port),
    )
    .map_err(|error| format!("start publication ingress: {error}"))?;
    let hold = client.expose(config.host_ip, config.host_port, relay.address())?;
    let mut drain = hold
        .drain_stream()
        .map_err(|error| format!("clone publication hold: {error}"))?;
    let mut relay = Some(relay);

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
    let mut child = Proxy(
        command
            .spawn()
            .map_err(|error| format!("start docker-proxy: {error}"))?,
    );
    let child_pid = Pid::from_raw(
        i32::try_from(child.0.id())
            .map_err(|error| format!("invalid docker-proxy PID: {error}"))?,
    );
    let (events, receiver) = mpsc::channel();
    let watcher = std::thread::Builder::new()
        .name("publication-hold".into())
        .spawn(move || {
            let mut byte = [0; 1];
            let reason = match drain.read(&mut byte) {
                Ok(0) => "publication hold closed unexpectedly".to_string(),
                Ok(_) => "publication endpoint sent unexpected data".to_string(),
                Err(error) => format!("publication hold failed: {error}"),
            };
            let _ = events.send(reason);
        })
        .map_err(|error| format!("watch publication hold: {error}"))?;

    let mut stopping = None;
    let mut failure = None;
    let status = loop {
        while let Some(info) = signal_fd
            .read_signal()
            .map_err(|error| format!("read stop signal: {error}"))?
        {
            if let Ok(signal) = Signal::try_from(info.ssi_signo as i32) {
                stop_publication(&hold, &mut relay, child_pid, &mut stopping, signal);
            }
        }
        if let Some(status) = child
            .0
            .try_wait()
            .map_err(|error| format!("wait for docker-proxy: {error}"))?
        {
            break status;
        }
        if stopping.is_none() {
            if relay.as_ref().is_some_and(relay::Relay::is_finished) {
                failure = Some("publication relay stopped unexpectedly".to_string());
                stop_publication(&hold, &mut relay, child_pid, &mut stopping, Signal::SIGTERM);
            } else {
                match receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok(reason) => {
                        failure = Some(reason);
                        stop_publication(
                            &hold,
                            &mut relay,
                            child_pid,
                            &mut stopping,
                            Signal::SIGTERM,
                        );
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        failure = Some("publication hold watcher stopped unexpectedly".to_string());
                        stop_publication(
                            &hold,
                            &mut relay,
                            child_pid,
                            &mut stopping,
                            Signal::SIGTERM,
                        );
                    }
                }
            }
        } else {
            if stopping.is_some_and(|started: Instant| started.elapsed() >= Duration::from_secs(2))
            {
                let _ = kill(child_pid, Signal::SIGKILL);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    hold.close();
    drop(relay);
    let _ = watcher.join();
    match failure {
        Some(reason) => Err(reason),
        None => Ok(exit_code(status)),
    }
}

fn stop_publication(
    hold: &http::PublicationHold,
    relay: &mut Option<relay::Relay>,
    child: Pid,
    stopping: &mut Option<Instant>,
    signal: Signal,
) {
    stopping.get_or_insert_with(Instant::now);
    hold.close();
    drop(relay.take());
    let _ = kill(child, signal);
}

/// Reap the proxy on every error path, including supervisor setup failures.
struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
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
