//! Process identity helpers for silo-vmm.
//!
//! libvm treats silo-vmm pidfiles as discovery artifacts only. A pidfile can be
//! stale, removed early, or point at a reused PID, so lifecycle decisions go
//! through this module instead of checking pidfile existence.
//!
//! Linux uses pidfds when available. Once opened, the fd names a specific
//! process across PID reuse, so liveness probes and signals go through it. If
//! pidfds are unavailable, we fall back to a kill-probe and a birth-identity
//! check before numeric signals, matching libpod.
//!
//! This module intentionally does not call silo-vmm's control socket or inspect
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

/// Numeric signal for platforms or kernels without pidfds. Callers check the
/// birth identity first; the number can still be reused before delivery.
fn signal_pid(pid: i32, signal: nix::sys::signal::Signal) -> io::Result<bool> {
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal) {
        Ok(()) => Ok(true),
        Err(nix::errno::Errno::ESRCH) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::supervisor::process::{identity_is_alive, ProcessIdentity};

    #[test]
    fn current_process_identity_matches_itself() {
        let pid = std::process::id() as i32;
        let identity = ProcessIdentity::for_pid(pid)
            .expect("read current process identity")
            .expect("current process should exist");

        assert_eq!(identity.pid(), pid);
        assert!(identity_is_alive(&identity).expect("check current process identity"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn exited_unreaped_child_is_not_alive() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn");
        let pid = i32::try_from(child.id()).expect("pid");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let absent = loop {
            if ProcessIdentity::for_pid(pid)
                .expect("probe child")
                .is_none()
            {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        // kill(pid, 0) still sees the zombie. Reap only after observing it.
        let still_registered = crate::supervisor::process::pid_exists(pid).expect("kill probe");
        child.wait().expect("reap our child");
        assert!(absent, "zombie was treated as a live process");
        assert!(still_registered);
    }

    #[test]
    fn impossible_pid_has_no_identity() {
        let identity =
            ProcessIdentity::for_pid(i32::MAX).expect("read impossible process identity");

        assert!(identity.is_none());
    }

    #[test]
    fn exited_identity_is_never_signaled() {
        use std::os::unix::process::CommandExt;

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("spawn");
        let identity = ProcessIdentity::for_pid(i32::try_from(child.id()).expect("pid"))
            .expect("probe child")
            .expect("live child");
        child.kill().expect("kill child");
        child.wait().expect("reap child");

        // The number is free for reuse now; the retained identity must refuse it.
        assert!(!identity
            .signal(nix::sys::signal::Signal::SIGKILL)
            .expect("signal exited identity"));
        assert!(!identity
            .signal_process_group(nix::sys::signal::Signal::SIGKILL)
            .expect("signal exited group"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn process_group_signal_reaches_members_of_the_exact_leader() {
        use std::io::BufRead;
        use std::os::unix::process::{CommandExt, ExitStatusExt};

        let mut leader = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30 & echo $!; wait"])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn group leader");
        let mut line = String::new();
        std::io::BufReader::new(leader.stdout.take().expect("leader stdout"))
            .read_line(&mut line)
            .expect("read member pid");
        let member = ProcessIdentity::for_pid(line.trim().parse().expect("member pid"))
            .expect("probe member")
            .expect("live member");
        let identity = ProcessIdentity::for_pid(i32::try_from(leader.id()).expect("pid"))
            .expect("probe leader")
            .expect("live leader");

        assert!(identity
            .signal_process_group(nix::sys::signal::Signal::SIGKILL)
            .expect("signal group"));
        assert_eq!(
            leader.wait().expect("reap leader").signal(),
            Some(nix::libc::SIGKILL)
        );
        crate::supervisor::process::wait_for_exit(
            &member,
            "group-member",
            std::time::Duration::from_secs(5),
            std::time::Duration::from_millis(10),
        )
        .await
        .expect("group member received the leader's group signal");
    }

    #[test]
    fn process_group_signal_never_reaches_a_non_leaders_group() {
        // This child shares the test runner's group, which must survive.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn");
        let identity = ProcessIdentity::for_pid(i32::try_from(child.id()).expect("pid"))
            .expect("probe child")
            .expect("live child");

        let signaled = identity
            .signal_process_group(nix::sys::signal::Signal::SIGKILL)
            .expect("signal non-leader group");
        let still_running = child.try_wait().expect("probe child").is_none();
        child.kill().expect("kill child");
        child.wait().expect("reap child");
        assert!(!signaled);
        assert!(still_running);
    }
}
