use agent_spec::ResizeRootfsConfig;
use eyre::{eyre, Context};

use crate::pid1::ProcessSupervisor;
use crate::provision::{command_exists, command_output, run_command};

const ROOT_MOUNTPOINT: &str = "/";

pub(crate) fn apply(
    config: &ResizeRootfsConfig,
    process_supervisor: &ProcessSupervisor,
) -> eyre::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let source = findmnt(process_supervisor, "SOURCE", ROOT_MOUNTPOINT)?;
    let fstype = findmnt(process_supervisor, "FSTYPE", ROOT_MOUNTPOINT)?;
    tracing::info!(source = %source, fstype = %fstype, "resizing root filesystem");
    resize_filesystem(process_supervisor, &source, &fstype)?;
    tracing::info!(source = %source, fstype = %fstype, "reconciled root filesystem size");

    Ok(())
}

fn findmnt(
    process_supervisor: &ProcessSupervisor,
    field: &str,
    target: &str,
) -> eyre::Result<String> {
    let output = command_output(
        process_supervisor,
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
    process_supervisor: &ProcessSupervisor,
    source: &str,
    fstype: &str,
) -> eyre::Result<()> {
    match resize_plan(source, fstype) {
        Some(plan) => {
            ensure_resize_command(plan.program, fstype)?;
            run_command(process_supervisor, plan.program, plan.args)
        }
        None => Err(eyre!(
            "unsupported filesystem {fstype:?} for root filesystem resize on {source}"
        )),
    }
    .with_context(|| format!("resize root filesystem {fstype} on {source}"))
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

fn ensure_resize_command(program: &str, fstype: &str) -> eyre::Result<()> {
    if command_exists(program) {
        return Ok(());
    }

    match program {
        "btrfs" => Err(eyre!(
            "root filesystem is {fstype} but btrfs-progs is not installed or btrfs is not in PATH"
        )),
        "resize2fs" => Err(eyre!(
            "root filesystem is {fstype} but resize2fs is not installed or not in PATH"
        )),
        _ => Err(eyre!(
            "root filesystem is {fstype} but {program} is not installed or not in PATH"
        )),
    }
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
