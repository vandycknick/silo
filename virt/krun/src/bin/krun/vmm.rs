#[cfg(target_os = "macos")]
use std::io;
use std::os::fd::OwnedFd;

use krun::engine::{self, ConsoleFds, Resources};
use krun::KrunConfig;

/// Process policy belongs to the worker, not to the synchronous engine.
pub(crate) fn run(
    config: &KrunConfig,
    vsock_mux: Option<OwnedFd>,
    watchdog_fd: Option<OwnedFd>,
    status_fd: Option<OwnedFd>,
    console: ConsoleFds<'_>,
) -> eyre::Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let shutdown_signals = block_shutdown_signal()?;

    engine::init_log(
        None,
        engine::LogLevel::Info,
        engine::LogStyle::Auto,
        engine::LogOptions::empty(),
    )?;
    if let Some(fd) = watchdog_fd {
        crate::watchdog::start(fd)?;
    }
    engine::run_process(
        config,
        Resources {
            console,
            vsock_mux,
            protected_streams: &[],
        },
        move |control| {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {
                let shutdown = control.clone();
                std::thread::Builder::new()
                    .name("silo-krun-shutdown".to_string())
                    .spawn(move || match shutdown_signals.wait() {
                        Ok(nix::sys::signal::Signal::SIGTERM) => {
                            if let Err(error) = shutdown.request_shutdown() {
                                eprintln!("krun helper failed to request guest shutdown: {error}");
                            }
                        }
                        Ok(signal) => eprintln!("unexpected shutdown signal: {signal:?}"),
                        Err(error) => eprintln!("shutdown signal wait failed: {error}"),
                    })?;
            }
            #[cfg(target_os = "macos")]
            {
                let first = control.host_memory_reclaim();
                eprintln!(
                    "host memory reclaim requested={} effective={} probe={}",
                    if first.requested { "on" } else { "off" },
                    if first.effective { "on" } else { "off" },
                    first.qualification.as_str()
                );
                if let Some(fd) = status_fd {
                    start_status_reporter(fd, control)?;
                }
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (control, status_fd);
            Ok(())
        },
    )?;
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn block_shutdown_signal() -> io::Result<nix::sys::signal::SigSet> {
    use nix::sys::signal::{self, SigSet, SigmaskHow, Signal};
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGTERM);
    signal::pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)?;
    Ok(signals)
}

#[cfg(target_os = "macos")]
fn start_status_reporter(fd: OwnedFd, control: engine::Control) -> io::Result<()> {
    use std::io::Write;
    std::thread::Builder::new()
        .name("silo-krun-status".to_string())
        .spawn(move || {
            let mut channel = std::fs::File::from(fd);
            let mut last = None;
            loop {
                let current = control.host_memory_reclaim();
                if last != Some(current) {
                    if channel.write_all(current.encode().as_bytes()).is_err() {
                        return;
                    }
                    last = Some(current);
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        })
        .map(drop)
}
