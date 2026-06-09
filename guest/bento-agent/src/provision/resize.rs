use bento_core::agent::ResizeRootfsConfig;
use eyre::{eyre, Context};

use crate::provision::{command_output, run_command};

pub(crate) fn apply(config: &ResizeRootfsConfig) -> eyre::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let source = findmnt("SOURCE", "/")?;
    let fstype = findmnt("FSTYPE", "/")?;
    tracing::info!(source = %source, fstype = %fstype, "resizing root filesystem");
    resize_filesystem(&source, &fstype)?;
    tracing::info!(source = %source, fstype = %fstype, "provisioned root filesystem resize");

    Ok(())
}

fn findmnt(field: &str, target: &str) -> eyre::Result<String> {
    let output = command_output("findmnt", ["-n", "-o", field, "--target", target])?;
    let value = output.trim();
    if value.is_empty() {
        return Err(eyre!("findmnt returned empty {field} for {target}"));
    }
    Ok(value.to_string())
}

fn resize_filesystem(source: &str, fstype: &str) -> eyre::Result<()> {
    match resize_command(fstype) {
        Some(command) => run_command(command, [source]),
        None => Err(eyre!(
            "unsupported filesystem {fstype:?} for root filesystem resize on {source}"
        )),
    }
    .with_context(|| format!("resize root filesystem {fstype} on {source}"))
}

fn resize_command(fstype: &str) -> Option<&'static str> {
    match fstype {
        "ext2" | "ext3" | "ext4" => Some("resize2fs"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ext_filesystems_use_resize2fs() {
        assert_eq!(
            crate::provision::resize::resize_command("ext2"),
            Some("resize2fs")
        );
        assert_eq!(
            crate::provision::resize::resize_command("ext3"),
            Some("resize2fs")
        );
        assert_eq!(
            crate::provision::resize::resize_command("ext4"),
            Some("resize2fs")
        );
        assert_eq!(crate::provision::resize::resize_command("xfs"), None);
    }
}
