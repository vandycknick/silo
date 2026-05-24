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
    _watchdog_keepalive: Option<Keepalive>,
}

impl VirtualMachine {
    pub(crate) fn new(
        child: Child,
        krun_binary: PathBuf,
        config: KrunConfig,
        serial: Option<SerialConnection>,
        watchdog_keepalive: Option<Keepalive>,
    ) -> Self {
        Self {
            child,
            krun_binary,
            config,
            serial,
            _watchdog_keepalive: watchdog_keepalive,
        }
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
        self.kill()
    }

    pub fn kill(&mut self) -> Result<()> {
        Ok(self.child.kill()?)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::process::Command;

    use crate::{KrunBackendError, KrunConfig, SerialConnection, VirtualMachine};

    #[test]
    fn serial_errors_when_stdio_console_is_disabled() {
        let child = Command::new("true").spawn().expect("spawn true");
        let mut vm = VirtualMachine::new(child, "krun".into(), KrunConfig::default(), None, None);

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
        );

        let _serial = vm.serial().expect("serial should be configured");
        let err = vm.serial().expect_err("serial should only be taken once");

        assert!(matches!(err, KrunBackendError::SerialAlreadyTaken));
    }
}
