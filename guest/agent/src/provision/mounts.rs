use std::fs;
use std::path::Path;

use agent_spec::MountConfig;
use eyre::{eyre, Context};

use crate::provision::{
    command_exists, command_output, format_error_chain, run_command, ProvisionContext,
    ProvisionOutcome, Provisioner, ProvisionerId,
};

pub(crate) struct Mounts<'a> {
    mounts: &'a [MountConfig],
}

impl<'a> Provisioner<'a> for Mounts<'a> {
    type Config = [MountConfig];

    fn init(config: &'a Self::Config) -> Self {
        Self { mounts: config }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::MOUNTS
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        if self.mounts.is_empty() {
            return Ok(ProvisionOutcome::skipped("no mounts configured"));
        }

        let mut failures = Vec::new();
        let mut changed = false;

        for mount in self.mounts {
            match apply_mount(context, mount) {
                Ok(mount_changed) => changed |= mount_changed,
                Err(err) => {
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
        }

        if failures.is_empty() {
            Ok(ProvisionOutcome::succeeded(changed))
        } else {
            Err(eyre!(
                "failed to provision {} mount(s): {}",
                failures.len(),
                failures.join("; ")
            ))
        }
    }
}

fn apply_mount(context: &ProvisionContext, mount: &MountConfig) -> eyre::Result<bool> {
    let target = context.guest_path(&mount.path);
    fs::create_dir_all(&target).with_context(|| format!("create {}", target.display()))?;
    if let Some(current) = current_mount(context, &target)? {
        if current.matches(mount) {
            tracing::debug!(path = %mount.path, tag = %mount.tag, "mount already reconciled");
            return Ok(false);
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
        run_command(
            context.process_supervisor(),
            "umount",
            [target_arg.as_str()],
        )?;
    }

    let options = mount.options.join(",");
    let target = target.to_string_lossy().to_string();
    run_command(
        context.process_supervisor(),
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

    Ok(true)
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

fn current_mount(context: &ProvisionContext, path: &Path) -> eyre::Result<Option<MountInfo>> {
    if !command_exists("findmnt") {
        return Ok(None);
    }

    let path_arg = path.to_string_lossy().to_string();
    let output = match command_output(
        context.process_supervisor(),
        "findmnt",
        [
            "-n",
            "-r",
            "-o",
            "SOURCE,FSTYPE,OPTIONS",
            "--mountpoint",
            path_arg.as_str(),
        ],
    ) {
        Ok(output) => output,
        Err(_) => return Ok(None),
    };

    let stdout = output;
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
            tag: "silo-home".to_string(),
            path: "/mnt/home".to_string(),
            fstype: "virtiofs".to_string(),
            options: vec!["ro".to_string(), "nofail".to_string()],
        };
        let current = MountInfo {
            source: "silo-home".to_string(),
            fstype: "virtiofs".to_string(),
            options: "ro,relatime".to_string(),
        };

        assert!(current.matches(&desired));
    }

    #[test]
    fn mount_info_rejects_different_read_only_state() {
        let desired = MountConfig {
            tag: "silo-home".to_string(),
            path: "/mnt/home".to_string(),
            fstype: "virtiofs".to_string(),
            options: vec!["rw".to_string(), "nofail".to_string()],
        };
        let current = MountInfo {
            source: "silo-home".to_string(),
            fstype: "virtiofs".to_string(),
            options: "ro,relatime".to_string(),
        };

        assert!(!current.matches(&desired));
    }
}
