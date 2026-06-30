use std::fs;
use std::path::Path;
use std::process::Command;

use agent_spec::MountConfig;
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
    if let Some(current) = current_mount(&target)? {
        if current.matches(mount) {
            tracing::debug!(path = %mount.path, tag = %mount.tag, "mount already reconciled");
            return Ok(());
        }

        tracing::info!(
            path = %mount.path,
            current_source = %current.source,
            current_fstype = %current.fstype,
            current_options = %current.options,
            desired_tag = %mount.tag,
            desired_fstype = %mount.fstype,
            "remounting drifted mount target"
        );
        let target_arg = target.to_string_lossy().to_string();
        run_command("umount", [target_arg.as_str()])?;
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
    tracing::info!(tag = %mount.tag, path = %mount.path, "reconciled mount");

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct MountInfo {
    source: String,
    fstype: String,
    options: String,
}

impl MountInfo {
    fn matches(&self, mount: &MountConfig) -> bool {
        self.source == mount.tag
            && self.fstype == mount.fstype
            && read_only_option(&self.options) == read_only_option(&mount.options.join(","))
    }
}

fn current_mount(path: &Path) -> eyre::Result<Option<MountInfo>> {
    if !command_exists("findmnt") {
        return Ok(None);
    }

    let output = Command::new("findmnt")
        .args(["-n", "-r", "-o", "SOURCE,FSTYPE,OPTIONS", "--mountpoint"])
        .arg(path)
        .output()
        .with_context(|| format!("inspect mount target {}", path.display()))?;
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("decode findmnt output for {}", path.display()))?;
    let mut fields = stdout.split_whitespace();
    let Some(source) = fields.next() else {
        return Ok(None);
    };
    let Some(fstype) = fields.next() else {
        return Ok(None);
    };
    let Some(options) = fields.next() else {
        return Ok(None);
    };

    Ok(Some(MountInfo {
        source: source.to_string(),
        fstype: fstype.to_string(),
        options: options.to_string(),
    }))
}

fn read_only_option(options: &str) -> bool {
    options.split(',').any(|option| option == "ro")
}

#[cfg(test)]
mod tests {
    use agent_spec::MountConfig;

    use crate::provision::mounts::MountInfo;

    #[test]
    fn mount_info_matches_desired_source_type_and_read_only_state() {
        let desired = MountConfig {
            tag: "bento-home".to_string(),
            path: "/mnt/home".to_string(),
            fstype: "virtiofs".to_string(),
            options: vec!["ro".to_string(), "nofail".to_string()],
        };
        let current = MountInfo {
            source: "bento-home".to_string(),
            fstype: "virtiofs".to_string(),
            options: "ro,relatime".to_string(),
        };

        assert!(current.matches(&desired));
    }

    #[test]
    fn mount_info_rejects_different_read_only_state() {
        let desired = MountConfig {
            tag: "bento-home".to_string(),
            path: "/mnt/home".to_string(),
            fstype: "virtiofs".to_string(),
            options: vec!["rw".to_string(), "nofail".to_string()],
        };
        let current = MountInfo {
            source: "bento-home".to_string(),
            fstype: "virtiofs".to_string(),
            options: "ro,relatime".to_string(),
        };

        assert!(!current.matches(&desired));
    }
}
