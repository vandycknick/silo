use std::ffi::OsString;
use std::path::{Path, PathBuf};

use eyre::Context as _;
use libvm::{HostCommand, Machine, MachineStartOptions, Runtime};

use crate::commands::secret::egress_credentials_from_secret_store;

pub(crate) async fn machine_start_options(
    runtime: &Runtime,
    machine: &Machine,
) -> eyre::Result<MachineStartOptions> {
    let data = machine
        .inspect()
        .await
        .context("inspect machine network policy")?;
    let mut options = MachineStartOptions::new();
    if data.retention == libvm::MachineRetention::Ephemeral {
        let executable = std::env::current_exe().context("resolve CLI binary path")?;
        options = cleanup_on_exit_options(executable, runtime.local_data_dir(), &machine.id());
    }
    if let Some(policy) = data.network.policy() {
        let credentials = egress_credentials_from_secret_store(policy)?;
        options = options.credentials(credentials);
    }
    Ok(options)
}

/// Builds start options for a foreground owner that removes an ephemeral VM itself.
pub(crate) async fn machine_start_options_without_cleanup(
    _runtime: &Runtime,
    machine: &Machine,
) -> eyre::Result<MachineStartOptions> {
    let data = machine
        .inspect()
        .await
        .context("inspect machine network policy")?;
    let mut options = MachineStartOptions::new();
    if let Some(policy) = data.network.policy() {
        let credentials = egress_credentials_from_secret_store(policy)?;
        options = options.credentials(credentials);
    }
    Ok(options)
}

fn cleanup_on_exit_options(
    executable: PathBuf,
    data_dir: &Path,
    machine_id: &str,
) -> MachineStartOptions {
    MachineStartOptions::new().on_exit(HostCommand::new(executable).args([
        OsString::from("cleanup"),
        OsString::from("--data-dir"),
        data_dir.as_os_str().to_owned(),
        OsString::from("--machine-id"),
        OsString::from(machine_id),
    ]))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use crate::commands::start_options::cleanup_on_exit_options;

    #[test]
    fn cleanup_on_exit_uses_current_executable_shape() {
        let options = cleanup_on_exit_options(
            PathBuf::from("/usr/local/bin/silo"),
            Path::new("/tmp/silo"),
            "0123456789abcdef0123456789abcdef",
        );
        let on_exit = options.on_exit.expect("on-exit command");

        assert_eq!(on_exit.command, PathBuf::from("/usr/local/bin/silo"));
        assert_eq!(
            on_exit.args,
            vec![
                OsString::from("cleanup"),
                OsString::from("--data-dir"),
                OsString::from("/tmp/silo"),
                OsString::from("--machine-id"),
                OsString::from("0123456789abcdef0123456789abcdef"),
            ]
        );
    }
}
