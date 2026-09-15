use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::{Child, ExitStatus};

use crate::config::KrunConfig;
use crate::error::{KrunBackendError, Result};
use crate::serial::SerialConnection;
use crate::watchdog::Keepalive;

#[derive(Debug)]
pub struct VirtualMachine {
    child: Child,
    krun_binary: PathBuf,
    config: KrunConfig,
    serial: Option<SerialConnection>,
    status_fd: Option<OwnedFd>,
    _watchdog_keepalive: Option<Keepalive>,
}

impl VirtualMachine {
    pub(crate) fn new(
        child: Child,
        krun_binary: PathBuf,
        config: KrunConfig,
        serial: Option<SerialConnection>,
        status_fd: Option<OwnedFd>,
        watchdog_keepalive: Option<Keepalive>,
    ) -> Self {
        Self {
            child,
            krun_binary,
            config,
            serial,
            status_fd,
            _watchdog_keepalive: watchdog_keepalive,
        }
    }

    /// Read end of the helper's status channel: newline-delimited records that
    /// [`crate::HostMemoryReclaimStatus::parse`] decodes. Available once.
    pub fn take_status_fd(&mut self) -> Option<OwnedFd> {
        self.status_fd.take()
    }

    pub fn krun_binary(&self) -> &PathBuf {
        &self.krun_binary
    }

    pub fn config(&self) -> &KrunConfig {
        &self.config
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn serial(&mut self) -> Result<SerialConnection> {
        if !self.config.stdio_console {
            return Err(KrunBackendError::SerialNotConfigured);
        }

        self.serial
            .take()
            .ok_or(KrunBackendError::SerialAlreadyTaken)
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        Ok(self.child.try_wait()?)
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        Ok(self.child.wait()?)
    }

    pub fn shutdown(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            use nix::errno::Errno;
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let pid = i32::try_from(self.child.id()).map_err(|_| {
                KrunBackendError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "krun child PID exceeds i32",
                ))
            })?;
            match kill(Pid::from_raw(pid), Signal::SIGTERM) {
                Ok(()) | Err(Errno::ESRCH) => Ok(()),
                Err(err) => Err(KrunBackendError::Io(std::io::Error::from_raw_os_error(
                    err as i32,
                ))),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.kill()
        }
    }

    pub fn kill(&mut self) -> Result<()> {
        Ok(self.child.kill()?)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    #[cfg(target_os = "macos")]
    use std::io::{BufRead, BufReader};
    use std::process::Command;
    #[cfg(target_os = "macos")]
    use std::process::Stdio;
    #[cfg(target_os = "macos")]
    use std::thread;
    #[cfg(target_os = "macos")]
    use std::time::{Duration, Instant};

    use crate::{KrunBackendError, KrunConfig, SerialConnection, VirtualMachine};

    #[test]
    fn serial_errors_when_stdio_console_is_disabled() {
        let child = Command::new("true").spawn().expect("spawn true");
        let mut vm = VirtualMachine::new(
            child,
            "krun".into(),
            KrunConfig::default(),
            None,
            None,
            None,
        );

        let err = vm.serial().expect_err("serial should be disabled");

        assert!(matches!(err, KrunBackendError::SerialNotConfigured));
    }

    #[test]
    fn serial_can_only_be_taken_once() {
        let config = KrunConfig {
            stdio_console: true,
            ..KrunConfig::default()
        };
        let read = File::open("/dev/null").expect("open /dev/null for read");
        let write = File::options()
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null for write");
        let child = Command::new("true").spawn().expect("spawn true");
        let mut vm = VirtualMachine::new(
            child,
            "krun".into(),
            config,
            Some(SerialConnection::new(read, write)),
            None,
            None,
        );

        let _serial = vm.serial().expect("serial should be configured");
        let err = vm.serial().expect_err("serial should only be taken once");

        assert!(matches!(err, KrunBackendError::SerialAlreadyTaken));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn shutdown_sends_sigterm_to_real_child() {
        let child = Command::new("sh")
            .args(["-c", "trap 'exit 0' TERM; echo ready; while :; do :; done"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn TERM-aware child");
        let mut child = child;
        let stdout = child.stdout.take().expect("capture child stdout");
        let mut ready = String::new();
        BufReader::new(stdout)
            .read_line(&mut ready)
            .expect("read child readiness");
        assert_eq!(ready.trim(), "ready");
        let mut vm = VirtualMachine::new(
            child,
            "krun".into(),
            KrunConfig::default(),
            None,
            None,
            None,
        );

        vm.shutdown().expect("request graceful shutdown");
        let status = wait_for_exit(&mut vm, Duration::from_secs(2));

        assert!(status.success());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn kill_remains_forced_for_real_child() {
        use std::os::unix::process::ExitStatusExt;

        let child = Command::new("sh")
            .args(["-c", "trap '' TERM; while :; do :; done"])
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn TERM-resistant child");
        let mut vm = VirtualMachine::new(
            child,
            "krun".into(),
            KrunConfig::default(),
            None,
            None,
            None,
        );

        vm.kill().expect("force child exit");
        let status = wait_for_exit(&mut vm, Duration::from_secs(2));

        assert_eq!(status.signal(), Some(9));
    }

    #[cfg(target_os = "macos")]
    fn wait_for_exit(vm: &mut VirtualMachine, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = vm.try_wait().expect("poll child") {
                return status;
            }
            assert!(Instant::now() < deadline, "child did not exit in time");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
