use std::ffi::OsString;
use std::path::{Path, PathBuf};

use eyre::Context as _;
use libvm::{EgressCredentials, Entrypoint, HostCommand, MachineStartOptions};

/// Launch settings shared by local and daemon management. Host cleanup commands
/// are constructed by the selected backend, never supplied over the wire.
#[derive(Debug, Clone, Default)]
pub(crate) struct AppStartOptions {
    pub(crate) cleanup_on_exit: bool,
    pub(crate) egress_credentials: EgressCredentials,
    pub(crate) entrypoint: Option<Entrypoint>,
}

impl AppStartOptions {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn entrypoint<F>(mut self, program: impl Into<String>, configure: F) -> Self
    where
        F: FnOnce(Entrypoint) -> Entrypoint,
    {
        self.entrypoint = Some(configure(Entrypoint::new(program)));
        self
    }

    pub(in crate::api) fn into_native(
        self,
        home: &Path,
        machine_id: &str,
    ) -> eyre::Result<MachineStartOptions> {
        let mut options = if self.cleanup_on_exit {
            let executable = std::env::current_exe().context("resolve CLI binary path")?;
            cleanup_on_exit_options(executable, home, machine_id)
        } else {
            MachineStartOptions::new()
        };
        options.egress_credentials = self.egress_credentials;
        options.entrypoint = self.entrypoint;
        Ok(options)
    }
}

pub(crate) fn cleanup_on_exit_options(
    executable: PathBuf,
    home: &Path,
    machine_id: &str,
) -> MachineStartOptions {
    MachineStartOptions::new().on_exit(HostCommand::new(executable).args([
        OsString::from("cleanup"),
        OsString::from("--home"),
        home.as_os_str().to_owned(),
        OsString::from("--machine-id"),
        OsString::from(machine_id),
    ]))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use libvm::EgressCredentials;

    use crate::api::start_options::AppStartOptions;

    #[test]
    fn native_translation_preserves_launch_only_settings_without_cleanup() {
        let mut options = AppStartOptions::new().entrypoint("/bin/program", |entrypoint| {
            entrypoint
                .args(["", "two words", "$literal"])
                .cwd("/work")
                .envs([("KEY", "first"), ("KEY", "second")])
                .user("1000:1000")
        });
        options.egress_credentials =
            EgressCredentials::new().secret_bytes("service.token", vec![0, 255, 1]);
        let expected_entrypoint = options.entrypoint.clone();
        let expected_credentials = options.egress_credentials.clone();
        let native = options
            .into_native(Path::new("/unused"), "0123456789abcdef0123456789abcdef")
            .expect("translate start options");

        assert!(native.on_exit.is_none());
        assert_eq!(native.entrypoint, expected_entrypoint);
        assert_eq!(native.egress_credentials, expected_credentials);
    }
}
