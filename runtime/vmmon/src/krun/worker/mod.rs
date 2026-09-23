//! Private process entry point. Never call supervisor startup from this module.

#[cfg(target_os = "macos")]
mod admission;
mod fds;
pub(crate) mod wire;

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::krun::engine::{self, ConsoleFds, Resources};
use crate::krun::worker::wire::{Event, MAX_EVENT};
use crate::virt::exit::StartupStage;

/// argv[0] basename that selects the worker instead of the supervisor.
pub(crate) const WORKER_NAME: &str = "silo-krun";

/// Whether this process was started as the libkrun worker.
pub(crate) fn invoked_as_worker() -> bool {
    std::env::args_os()
        .next()
        .is_some_and(|argv0| std::path::Path::new(&argv0).file_name() == Some(WORKER_NAME.as_ref()))
}

/// Worker entry point. It takes no arguments and no environment: everything it
/// needs arrives on the fixed descriptors described in [`fds`].
pub(crate) fn main() -> eyre::Result<()> {
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_name(c"silo-krun")?;
    let fds::Bootstrap {
        config,
        events,
        watchdog,
        console,
        mux,
    } = fds::Bootstrap::adopt_fixed()?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let shutdown_signals = block_shutdown_signal()?;
    // Must precede logging, config reads, payload loading and host admission.
    fds::start_watchdog(watchdog)?;
    fds::nonblocking(events.as_fd())?;
    let events = Arc::new(Mutex::new(EventWriter(events)));
    let mut stage = StartupStage::Spawned;
    let result = (|| -> eyre::Result<()> {
        let config = wire::read_config(&mut std::fs::File::from(config))?;
        if config.vsock_mux != mux.is_some() {
            return Err(wire::invalid("mux descriptor does not match the worker config").into());
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
        crate::krun::check_host()?;
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
                diagnostic: wire::diagnostic(error),
            },
        );
    }
    result
}

struct EventWriter(OwnedFd);

impl EventWriter {
    fn send(&mut self, event: &Event) -> io::Result<()> {
        use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
        let bytes = wire::encode(event, MAX_EVENT)?;
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
