//! Process identity helpers for vmmon.
//!
//! libvm treats vmmon pidfiles as discovery artifacts only. A pidfile can be
//! stale, removed early, or point at a reused PID, so lifecycle decisions go
//! through this module instead of checking pidfile existence.
//!
//! Linux uses pidfds when available. Once opened, the fd names a specific
//! process and remains safe across PID reuse while this libvm process holds it.
//! If pidfds are unavailable, we fall back to a kill-probe, matching libpod.
//!
//! This module intentionally does not call vmmon's control socket or inspect
//! API. Liveness is OS process identity plus persisted monitor generation
//! metadata and exit-status files.

use std::io;
use std::time::Duration;

use rustix::process::Pid;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod pid_probe;

#[cfg(target_os = "linux")]
pub(crate) use linux::ProcessIdentity;
#[cfg(target_os = "macos")]
pub(crate) use macos::ProcessIdentity;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use pid_probe::ProcessIdentity;

pub(crate) async fn wait_for_exit(
    identity: &ProcessIdentity,
    machine_name: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if !identity_is_alive(identity)? {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out after {:?} waiting for machine {:?} monitor pid {} to stop",
                    timeout,
                    machine_name,
                    identity.pid()
                ),
            ));
        }

        tokio::time::sleep(poll_interval).await;
    }
}

pub(crate) fn identity_is_alive(identity: &ProcessIdentity) -> io::Result<bool> {
    identity.is_alive()
}

fn rustix_pid(pid: i32) -> Option<Pid> {
    Pid::from_raw(pid)
}

fn pid_exists(pid: i32) -> io::Result<bool> {
    let Some(pid) = rustix_pid(pid) else {
        return Ok(false);
    };

    match rustix::process::test_kill_process(pid) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::SRCH) => Ok(false),
        Err(rustix::io::Errno::PERM) => Ok(true),
        Err(err) => Err(errno_to_io(err)),
    }
}

fn errno_to_io(err: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(err.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::{identity_is_alive, ProcessIdentity};

    #[test]
    fn current_process_identity_matches_itself() {
        let pid = std::process::id() as i32;
        let identity = ProcessIdentity::for_pid(pid)
            .expect("read current process identity")
            .expect("current process should exist");

        assert_eq!(identity.pid(), pid);
        assert!(identity_is_alive(&identity).expect("check current process identity"));
    }

    #[test]
    fn impossible_pid_has_no_identity() {
        let identity =
            ProcessIdentity::for_pid(i32::MAX).expect("read impossible process identity");

        assert!(identity.is_none());
    }
}
