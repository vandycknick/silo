use std::ffi::OsString;
use std::path::{Path, PathBuf};

use eyre::Context as _;
use libvm::{Machine, MachineExitCommand, MachineStartOptions, Runtime};

use crate::commands::secret::network_launch_from_secret_store;

pub(crate) async fn machine_start_options(
    runtime: &Runtime,
    machine: &Machine,
) -> eyre::Result<MachineStartOptions> {
    let executable = std::env::current_exe().context("resolve CLI binary path")?;
    let mut options =
        cleanup_exit_command_options(executable, runtime.local_data_dir(), &machine.id());
    let data = machine
        .inspect()
        .await
        .context("inspect machine network policy")?;
    if let Some(policy) = data.network.policy() {
        let launch = network_launch_from_secret_store(policy)?;
        options = options.network(|network| network.apply(launch));
    }
    Ok(options)
}

fn cleanup_exit_command_options(
    executable: PathBuf,
    data_dir: &Path,
    machine_id: &str,
) -> MachineStartOptions {
    MachineStartOptions::new().exit_command(MachineExitCommand::new(
        executable,
        [
            OsString::from("cleanup"),
            OsString::from("--data-dir"),
            data_dir.as_os_str().to_owned(),
            OsString::from("--machine-id"),
            OsString::from(machine_id),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use crate::commands::start_options::cleanup_exit_command_options;

    #[test]
    fn cleanup_exit_command_uses_current_executable_shape() {
        let options = cleanup_exit_command_options(
            PathBuf::from("/usr/local/bin/silo"),
            Path::new("/tmp/silo"),
            "0123456789abcdef0123456789abcdef",
        );
        let exit_command = options.exit_command.expect("exit command");

        assert_eq!(exit_command.command, PathBuf::from("/usr/local/bin/silo"));
        assert_eq!(
            exit_command.args,
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
