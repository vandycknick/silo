//! Private process entry point. Never call supervisor startup from this module.

#[cfg(target_os = "macos")]
mod admission;
mod fds;
pub(crate) mod protocol;

use std::io;
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::krun_worker::protocol::StartupStage;
use crate::krun_worker::protocol::{Event, MAX_EVENT};
use clap::Parser;
use krun::engine::{self, ConsoleFds, Resources};

#[derive(Parser)]
#[command(
    name = "worker",
    about = "Run the supervised libkrun process",
    disable_help_subcommand = true
)]
pub(crate) struct Args {
    #[arg(long)]
    request_fd: RawFd,
    #[arg(long)]
    events_fd: RawFd,
    #[arg(long)]
    watchdog_fd: RawFd,
    #[arg(long)]
    console_fd: RawFd,
    #[arg(long)]
    vsock_mux_fd: Option<RawFd>,
}

pub(crate) fn run(args: Args) -> eyre::Result<()> {
    let fds::Bootstrap {
        request,
        events,
        watchdog,
        console,
        mux,
    } = fds::Bootstrap::adopt(
        args.request_fd,
        args.events_fd,
        args.watchdog_fd,
        args.console_fd,
        args.vsock_mux_fd,
    )?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let shutdown_signals = block_shutdown_signal()?;
    // Must precede logging, request reads, payload loading and host admission.
    fds::start_watchdog(watchdog)?;
    fds::nonblocking(events.as_fd())?;
    let events = Arc::new(Mutex::new(EventWriter(events)));
    let mut stage = StartupStage::Request;
    let result = (|| -> eyre::Result<()> {
        emit(&events, &Event::StartupStage { stage })?;
        let config = protocol::read_launch(&mut std::fs::File::from(request))?.into_config()?;
        if config.vsock_mux != mux.is_some() {
            return Err(protocol::invalid("mux role does not match launch request").into());
        }
        engine::init_log(
            None,
            engine::LogLevel::Info,
            engine::LogStyle::Auto,
            engine::LogOptions::empty(),
        )?;
        stage = StartupStage::Admission;
        emit(&events, &Event::StartupStage { stage })?;
        #[cfg(target_os = "linux")]
        krun::check_host()?;
        #[cfg(target_os = "macos")]
        admission::check_hvf()?;
        stage = StartupStage::Build;
        emit(&events, &Event::StartupStage { stage })?;
        engine::run_process(
            &config,
            Resources {
                console: ConsoleFds {
                    stdin: console.as_fd(),
                    stdout: console.as_fd(),
                    stderr: console.as_fd(),
                },
                vsock_mux: mux,
                protected_streams: &[],
            },
            |control| {
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                {
                    let shutdown = control.clone();
                    std::thread::Builder::new()
                        .name("krun-shutdown".to_string())
                        .spawn(move || match shutdown_signals.wait() {
                            Ok(nix::sys::signal::Signal::SIGTERM) => {
                                if let Err(error) = shutdown.request_shutdown() {
                                    eprintln!("krun shutdown failed: {error}");
                                }
                            }
                            Ok(_) => {}
                            Err(error) => eprintln!("krun signal wait failed: {error}"),
                        })?;
                }
                #[cfg(target_os = "macos")]
                start_status_reporter(events.clone(), control)?;
                #[cfg(not(target_os = "macos"))]
                drop(control);
                emit(&events, &Event::BackendStarted {})?;
                stage = StartupStage::Started;
                Ok(())
            },
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        let _ = emit(
            &events,
            &Event::StartupFailed {
                stage,
                diagnostic: protocol::diagnostic(error),
            },
        );
    }
    result
}

struct EventWriter(OwnedFd);

impl EventWriter {
    fn send(&mut self, event: &Event) -> io::Result<()> {
        use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
        let bytes = protocol::encode(event, MAX_EVENT)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut pending = bytes.as_slice();
        while !pending.is_empty() {
            match nix::unistd::write(&self.0, pending) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => pending = &pending[count..],
                Err(nix::errno::Errno::EINTR) => {}
                Err(nix::errno::Errno::EAGAIN) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    let mut ready = [PollFd::new(self.0.as_fd(), PollFlags::POLLOUT)];
                    match poll(
                        &mut ready,
                        PollTimeout::try_from(remaining).map_err(io::Error::other)?,
                    ) {
                        Ok(_) => {}
                        Err(nix::errno::Errno::EINTR) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline && !pending.is_empty() {
                return Err(io::ErrorKind::TimedOut.into());
            }
        }
        Ok(())
    }
}

fn emit(events: &Mutex<EventWriter>, event: &Event) -> io::Result<()> {
    events
        .lock()
        .map_err(|_| io::Error::other("worker event writer poisoned"))?
        .send(event)
}

#[cfg(target_os = "macos")]
fn start_status_reporter(
    events: Arc<Mutex<EventWriter>>,
    control: engine::Control,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("krun-status".to_string())
        .spawn(move || {
            loop {
                // Telemetry never takes the startup writer's lock away from it.
                if let Ok(mut writer) = events.try_lock() {
                    if writer
                        .send(&Event::HostMemoryReclaim {
                            status: control.host_memory_reclaim(),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        })
        .map(drop)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn block_shutdown_signal() -> io::Result<nix::sys::signal::SigSet> {
    use nix::sys::signal::{self, SigSet, SigmaskHow, Signal};
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGTERM);
    signal::pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)?;
    Ok(signals)
}
