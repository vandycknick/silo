//! Private process entry point. Never call supervisor startup from this module.

#[cfg(target_os = "macos")]
mod admission;
pub(crate) mod fds;
#[cfg(all(
    feature = "restore-irq-probe",
    target_os = "linux",
    target_arch = "x86_64"
))]
mod irq_probe;
pub(crate) mod lifecycle;
pub(crate) mod lifecycle_wire;
mod native;
pub(crate) mod restore;
pub(crate) mod wire;

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::krun::engine::{self, ConsoleFds, Resources};
use crate::krun::worker::wire::{Event, MAX_EVENT};
use crate::virt::exit::StartupStage;

/// argv[0] basename that selects the worker instead of the supervisor.
pub(crate) const WORKER_NAME: &str = "krun";

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
    nix::sys::prctl::set_name(c"krun")?;
    let fds::Bootstrap {
        config,
        events,
        watchdog,
        console,
        mux,
        storage_lease,
        raw_handles,
        lifecycle: lifecycle_endpoint,
        state_files,
        lowers,
        standalone: _,
    } = fds::Bootstrap::adopt_fixed()?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let shutdown_signals = block_shutdown_signal()?;
    // Must precede logging, config reads, payload loading and host admission.
    fds::start_watchdog(watchdog)?;
    fds::nonblocking(events.as_fd())?;
    let events = Arc::new(Mutex::new(EventWriter(events)));
    let mut stage = StartupStage::Spawned;
    let result = (|| -> eyre::Result<()> {
        let mut config = wire::read_config(&mut std::fs::File::from(config))?;
        fds::validate_lease(
            storage_lease.as_fd(),
            config.storage_context.storage_lease.file_device,
            config.storage_context.storage_lease.file_inode,
        )?;
        bind_raw_handles(&mut config, &raw_handles)?;
        if config.vsock_mux != mux.is_some() {
            return Err(wire::invalid("mux descriptor does not match the worker config").into());
        }
        let lifecycle_endpoint = lifecycle_endpoint
            .ok_or_else(|| wire::invalid("normal worker lacks its lifecycle endpoint"))?;
        let binding = lifecycle_binding(&config)?;
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
        let request = config.restore.take();
        let state_files = match (request, state_files) {
            (None, None) => None,
            (Some(request), Some(state)) => Some((request, state)),
            _ => {
                return Err(wire::invalid(
                    "restore descriptor roles do not match the worker config",
                )
                .into())
            }
        };
        if let Some((request, state)) = state_files {
            return restore::run(restore::Launch {
                config: &config,
                request,
                state,
                lowers,
                raw_handles: &raw_handles,
                console: &console,
                mux,
                lifecycle: lifecycle_endpoint,
                binding,
                events: &events,
                stage: &mut stage,
            });
        }
        engine::run_process(
            &config,
            Resources {
                console: ConsoleFds {
                    stdin: console.as_fd(),
                    stdout: console.as_fd(),
                    stderr: console.as_fd(),
                },
                vsock_mux: mux,
                console_ports: Vec::new(),
                managed_network: None,
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
                // Serving starts a thread and returns: native dispatch must run
                // before any blocking native lifecycle call can complete.
                let served = lifecycle::serve(
                    lifecycle_endpoint,
                    binding,
                    native::KrunNative::new(control.clone(), &config),
                    None,
                    Box::new(|reason: &str| {
                        eprintln!("krun lifecycle control lost: {reason}");
                        // nix exposes no immediate _exit. A worker that lost its
                        // only lifecycle authority terminates; it never resumes.
                        unsafe { nix::libc::_exit(124) }
                    }),
                )?;
                serve_diagnostics(served, binding)?;
                start_status_reporter(events.clone(), control)?;
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
    if let Err(error) = &result {
        eprintln!("krun worker failed: {error:#}");
    }
    // Native build can already have started detached attachment-owning threads.
    // Keep the lease and retained FD bindings alive until actual process exit,
    // including event-loop/build error paths. Never return and drop them first.
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}

/// The worker's exact launch identity, repeated in the lifecycle Hello.
fn lifecycle_binding(config: &crate::krun::KrunConfig) -> io::Result<lifecycle::Binding> {
    let parse = |value: &str| {
        uuid::Uuid::parse_str(value)
            .ok()
            .filter(|id| !id.is_nil() && id.hyphenated().to_string() == value)
            .ok_or_else(|| wire::invalid("worker launch identity is not a canonical UUID"))
    };
    Ok(lifecycle::Binding {
        machine_id: parse(&config.storage_context.machine_id)?,
        run_id: parse(&config.storage_context.run_id)?,
    })
}

/// A `restore-irq-probe` candidate exposes the run's IRQ witness transport
/// over the lifecycle owner; every other build releases the owner untouched.
fn serve_diagnostics(
    served: Arc<lifecycle::Shared<native::KrunNative>>,
    binding: lifecycle::Binding,
) -> io::Result<()> {
    #[cfg(all(
        feature = "restore-irq-probe",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    {
        irq_probe::serve(served, binding)
    }
    #[cfg(not(all(
        feature = "restore-irq-probe",
        target_os = "linux",
        target_arch = "x86_64"
    )))]
    {
        drop((served, binding));
        Ok(())
    }
}

fn bind_raw_handles(config: &mut crate::krun::KrunConfig, handles: &[OwnedFd]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let bindings = &config.storage_context.raw_handles;
    let raw_count = config
        .disks
        .iter()
        .filter(|disk| disk.format == vm_spec::DiskFormat::Raw)
        .count();
    if handles.len() != bindings.len() || bindings.len() != raw_count {
        return Err(wire::invalid(
            "Raw descriptor coverage differs from the complete disk set",
        ));
    }
    let mut next = 0;
    for (disk_index, disk) in config.disks.iter_mut().enumerate() {
        if disk.format != vm_spec::DiskFormat::Raw {
            continue;
        }
        let binding = &bindings[next];
        let fd = &handles[next];
        if binding.disk_index as usize != disk_index
            || binding.child_fd != 9 + next as i32
            || fd.as_raw_fd() != binding.child_fd
            || binding.read_only != disk.read_only
            || binding.length_bytes != disk.geometry.length
        {
            return Err(wire::invalid("Raw descriptor does not match its disk"));
        }
        let metadata = nix::sys::stat::fstat(fd)?;
        let flags = nix::fcntl::OFlag::from_bits_truncate(nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_GETFL,
        )?);
        let access = flags & nix::fcntl::OFlag::O_ACCMODE;
        if metadata.st_dev as u64 != binding.device
            || metadata.st_ino as u64 != binding.inode
            || (nix::sys::stat::SFlag::from_bits_truncate(metadata.st_mode)
                == nix::sys::stat::SFlag::S_IFREG
                && metadata.st_size as u64 != binding.length_bytes)
            || access
                != if binding.read_only {
                    nix::fcntl::OFlag::O_RDONLY
                } else {
                    nix::fcntl::OFlag::O_RDWR
                }
        {
            return Err(wire::invalid(
                "Raw backing identity, length or access mismatch",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            disk.path = std::path::Path::new("/proc/self/fd").join(binding.child_fd.to_string());
        }
        #[cfg(not(target_os = "linux"))]
        {
            disk.path = std::path::Path::new("/dev/fd").join(binding.child_fd.to_string());
        }
        next += 1;
    }
    Ok(())
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
