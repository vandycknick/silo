use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

const GUEST_CARGO_DIR: &str = "cargo-guest";

#[derive(Debug)]
pub(crate) struct GuestBuildOptions<'a> {
    pub(crate) target: &'a str,
    pub(crate) target_dir: &'a Path,
    pub(crate) workspace_root: &'a Path,
    pub(crate) source_date_epoch: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct GuestBuildResult {
    pub(crate) init: PathBuf,
    pub(crate) agent: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum GuestBuildError {
    #[error("failed to run {command}")]
    RunCommand { command: String, source: io::Error },
    #[error("command failed ({command}): {status}")]
    CommandFailed { command: String, status: String },
    #[error("guest build output is missing: {path}")]
    MissingOutput { path: PathBuf },
}

pub(crate) fn build_guest(
    options: &GuestBuildOptions<'_>,
) -> Result<GuestBuildResult, GuestBuildError> {
    for (package, panic_abort) in [("init", true), ("agent", false)] {
        let cargo_target_dir = options.target_dir.join(GUEST_CARGO_DIR).join(package);
        let mut rustflags = Vec::new();
        if panic_abort {
            rustflags.extend(["-C".to_string(), "panic=abort".to_string()]);
        }
        rustflags.push(format!(
            "--remap-path-prefix={}=/usr/src/silo",
            options.workspace_root.display()
        ));

        let mut command = Command::new("cargo");
        command
            .current_dir(options.workspace_root)
            .env("CARGO_TARGET_DIR", &cargo_target_dir)
            .env_remove("RUSTFLAGS")
            .env("CARGO_ENCODED_RUSTFLAGS", rustflags.join("\x1f"))
            .args(["zigbuild", "--locked", "--release", "--target"])
            .arg(options.target)
            .args(["-p", package]);
        if let Some(epoch) = options.source_date_epoch {
            command.env("SOURCE_DATE_EPOCH", epoch.to_string());
        }
        run(command)?;
    }

    let result = GuestBuildResult {
        init: guest_output_dir(options, "init").join("init"),
        agent: guest_output_dir(options, "agent").join("silo-agent"),
    };
    for path in [&result.init, &result.agent] {
        if !path.is_file() {
            return Err(GuestBuildError::MissingOutput {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(result)
}

fn guest_output_dir(options: &GuestBuildOptions<'_>, package: &str) -> PathBuf {
    options
        .target_dir
        .join(GUEST_CARGO_DIR)
        .join(package)
        .join(options.target)
        .join("release")
}

fn run(mut command: Command) -> Result<(), GuestBuildError> {
    let rendered = format!("{command:?}");
    let status = command
        .status()
        .map_err(|source| GuestBuildError::RunCommand {
            command: rendered.clone(),
            source,
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(GuestBuildError::CommandFailed {
            command: rendered,
            status: status.to_string(),
        })
    }
}
