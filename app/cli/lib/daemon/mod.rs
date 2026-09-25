//! Control of the separate `silod` daemon: locating it, validating what the CLI
//! would ask of it, registering it with the native service manager, and reading
//! what it publishes. The interface is `silod_spec`; no daemon code runs here.
pub(crate) mod config;
pub(crate) mod docker;
pub(crate) mod service;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::Context as _;

/// The silod shipped with this CLI: its sibling in a portable installation, or the
/// bundle helper when the CLI runs from `Silo.app/Contents/MacOS`.
pub(crate) fn executable() -> eyre::Result<PathBuf> {
    let current = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .context("locate the silo executable")?;
    let path = executable_beside(&current)?;
    if !path.is_file() {
        eyre::bail!(
            "silod is missing at {}; install or build silod alongside silo",
            path.display()
        );
    }
    Ok(path.canonicalize()?)
}

fn executable_beside(cli: &Path) -> eyre::Result<PathBuf> {
    let directory = cli
        .parent()
        .ok_or_else(|| eyre::eyre!("executable has no parent directory"))?;
    Ok(
        if directory.file_name().is_some_and(|name| name == "MacOS") {
            directory.join("../Helpers/silod")
        } else {
            directory.join("silod")
        },
    )
}

/// Asks silod whether it would accept `arguments` for this installation, without
/// changing anything, so a bad configuration fails before it is registered.
pub(crate) fn check(executable: &Path, arguments: &[OsString]) -> eyre::Result<()> {
    run_to_completion(
        Command::new(executable).arg("--check").args(arguments),
        "silod rejected the daemon configuration",
    )
}

/// Has silod stop any VM of this installation still running with no daemon
/// supervising it.
pub(crate) fn stop_installation(executable: &Path) -> eyre::Result<()> {
    run_to_completion(
        Command::new(executable).arg("--stop"),
        "silod could not stop the system VM",
    )
}

fn run_to_completion(command: &mut Command, failure: &str) -> eyre::Result<()> {
    let output = command
        .output()
        .with_context(|| format!("run {}", command.get_program().to_string_lossy()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr.trim().trim_start_matches("error: ");
    eyre::bail!("{failure}: {message}")
}

/// Replaces this process with silod in the foreground.
pub(crate) fn foreground(executable: &Path, arguments: &[OsString]) -> eyre::Result<()> {
    use std::os::unix::process::CommandExt as _;
    Err(Command::new(executable).args(arguments).exec()).context("execute silod in foreground")
}

#[cfg(test)]
mod tests {

    use crate::daemon::executable_beside;

    #[test]
    fn silod_is_a_sibling_or_the_bundle_helper() {
        let temp = tempfile::tempdir().expect("installation");
        let bin = temp.path().join("bin");
        assert_eq!(
            executable_beside(&bin.join("silo")).expect("portable"),
            bin.join("silod")
        );
        let macos = temp.path().join("Silo.app/Contents/MacOS");
        assert_eq!(
            executable_beside(&macos.join("silo")).expect("bundle"),
            macos.join("../Helpers/silod")
        );
        assert!(executable_beside(std::path::Path::new("/")).is_err());
    }
}
