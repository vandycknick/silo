use std::ffi::OsString;
use std::path::{Path, PathBuf};

use eyre::Context;
use libvm::{Machine, MachineExitCommand, MachineStartOptions, Runtime};

pub(crate) fn machine_start_options(
    libvm: &Runtime,
    machine: &Machine,
) -> eyre::Result<MachineStartOptions> {
    let data_dir = libvm.local_data_dir();
    let executable = std::env::current_exe().context("resolve CLI binary path")?;
    Ok(cleanup_exit_command_options(
        executable,
        data_dir,
        &machine.id(),
    ))
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
            PathBuf::from("/usr/local/bin/bento"),
            Path::new("/tmp/bento"),
            "0123456789abcdef0123456789abcdef",
        );
        let exit_command = options.exit_command.expect("exit command");

        assert_eq!(exit_command.command, PathBuf::from("/usr/local/bin/bento"));
        assert_eq!(
            exit_command.args,
            vec![
                OsString::from("cleanup"),
                OsString::from("--data-dir"),
                OsString::from("/tmp/bento"),
                OsString::from("--machine-id"),
                OsString::from("0123456789abcdef0123456789abcdef"),
            ]
        );
    }
}
