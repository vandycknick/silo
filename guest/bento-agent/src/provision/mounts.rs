use std::fs;

use bento_core::agent::MountConfig;
use eyre::{eyre, Context};

use crate::provision::{command_exists, format_error_chain, run_command, ProvisionContext};

pub(crate) fn apply(context: &ProvisionContext, mounts: &[MountConfig]) -> eyre::Result<()> {
    let mut failures = Vec::new();

    for mount in mounts {
        if let Err(err) = apply_mount(context, mount) {
            let error = format_error_chain(&err);
            tracing::error!(
                tag = %mount.tag,
                path = %mount.path,
                error = %error,
                "failed to provision mount; continuing"
            );
            failures.push(format!("{} at {}: {error}", mount.tag, mount.path));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(eyre!(
            "failed to provision {} mount(s): {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

fn apply_mount(context: &ProvisionContext, mount: &MountConfig) -> eyre::Result<()> {
    let target = context.guest_path(&mount.path);
    fs::create_dir_all(&target).with_context(|| format!("create {}", target.display()))?;
    if is_mounted(&target) {
        tracing::debug!(path = %mount.path, "mount target already mounted");
        return Ok(());
    }

    let options = mount.options.join(",");
    let target = target.to_string_lossy().to_string();
    run_command(
        "mount",
        [
            "-t",
            mount.fstype.as_str(),
            "-o",
            options.as_str(),
            mount.tag.as_str(),
            target.as_str(),
        ],
    )?;
    tracing::info!(tag = %mount.tag, path = %mount.path, "provisioned mount");

    Ok(())
}

fn is_mounted(path: &std::path::Path) -> bool {
    command_exists("findmnt")
        && std::process::Command::new("findmnt")
            .arg("--target")
            .arg(path)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
}
