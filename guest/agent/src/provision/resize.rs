use agent_spec::ResizeRootfsConfig;
use eyre::{eyre, Context};

use crate::provision::{
    command_exists, command_output, run_command, ProvisionContext, ProvisionOutcome,
};

const ROOT_MOUNTPOINT: &str = "/";

pub(crate) fn apply(
    context: &ProvisionContext,
    config: &ResizeRootfsConfig,
) -> eyre::Result<ProvisionOutcome> {
    if !config.enabled {
        return Ok(ProvisionOutcome::skipped("root filesystem resize disabled"));
    }

    let source = findmnt(context, "SOURCE", ROOT_MOUNTPOINT)?;
    let fstype = findmnt(context, "FSTYPE", ROOT_MOUNTPOINT)?;
    tracing::info!(source = %source, fstype = %fstype, "resizing root filesystem");
    let outcome = resize_filesystem(context, &source, &fstype)?;
    tracing::info!(source = %source, fstype = %fstype, "reconciled root filesystem size");

    Ok(outcome)
}

fn findmnt(context: &ProvisionContext, field: &str, target: &str) -> eyre::Result<String> {
    let output = command_output(
        context.process_supervisor(),
        "findmnt",
        ["-n", "-o", field, "--target", target],
    )?;
    let value = output.trim();
    if value.is_empty() {
        return Err(eyre!("findmnt returned empty {field} for {target}"));
    }
    Ok(value.to_string())
}

fn resize_filesystem(
    context: &ProvisionContext,
    source: &str,
    fstype: &str,
) -> eyre::Result<ProvisionOutcome> {
    let result: eyre::Result<ProvisionOutcome> = match resize_plan(source, fstype) {
        Some(plan) => {
            if let Some(message) = resize_command_unsupported(plan.program, fstype) {
                return Ok(ProvisionOutcome::unsupported(message));
            }
            run_command(context.process_supervisor(), plan.program, plan.args)?;
            Ok(ProvisionOutcome::succeeded(false))
        }
        None => Ok(ProvisionOutcome::unsupported(format!(
            "unsupported filesystem {fstype:?} for root filesystem resize on {source}"
        ))),
    };
    result.with_context(|| format!("resize root filesystem {fstype} on {source}"))
}

#[derive(Debug, PartialEq, Eq)]
struct ResizePlan<'a> {
    program: &'static str,
    args: Vec<&'a str>,
}

fn resize_plan<'a>(source: &'a str, fstype: &str) -> Option<ResizePlan<'a>> {
    match fstype {
        "ext2" | "ext3" | "ext4" => Some(ResizePlan {
            program: "resize2fs",
            args: vec![source],
        }),
        "btrfs" => Some(ResizePlan {
            program: "btrfs",
            args: vec!["filesystem", "resize", "max", ROOT_MOUNTPOINT],
        }),
        _ => None,
    }
}

fn resize_command_unsupported(program: &str, fstype: &str) -> Option<String> {
    if command_exists(program) {
        return None;
    }

    Some(match program {
        "btrfs" => format!(
            "root filesystem is {fstype} but btrfs-progs is not installed or btrfs is not in PATH"
        ),
        "resize2fs" => {
            format!("root filesystem is {fstype} but resize2fs is not installed or not in PATH")
        }
        _ => format!("root filesystem is {fstype} but {program} is not installed or not in PATH"),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn ext_filesystems_use_resize2fs() {
        assert_eq!(
            crate::provision::resize::resize_plan("/dev/vda", "ext2"),
            Some(crate::provision::resize::ResizePlan {
                program: "resize2fs",
                args: vec!["/dev/vda"],
            })
        );
        assert_eq!(
            crate::provision::resize::resize_plan("/dev/vda", "ext3"),
            Some(crate::provision::resize::ResizePlan {
                program: "resize2fs",
                args: vec!["/dev/vda"],
            })
        );
        assert_eq!(
            crate::provision::resize::resize_plan("/dev/vda", "ext4"),
            Some(crate::provision::resize::ResizePlan {
                program: "resize2fs",
                args: vec!["/dev/vda"],
            })
        );
    }

    #[test]
    fn btrfs_uses_btrfs_filesystem_resize_on_root_mountpoint() {
        assert_eq!(
            crate::provision::resize::resize_plan("/dev/vda", "btrfs"),
            Some(crate::provision::resize::ResizePlan {
                program: "btrfs",
                args: vec!["filesystem", "resize", "max", "/"],
            })
        );
    }

    #[test]
    fn unsupported_filesystems_do_not_have_resize_plan() {
        assert_eq!(
            crate::provision::resize::resize_plan("/dev/vda", "xfs"),
            None
        );
    }
}
