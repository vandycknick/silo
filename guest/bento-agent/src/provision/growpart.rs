use bento_core::agent::GrowpartConfig;
use eyre::{eyre, Context};

use crate::provision::{command_output, run_command};

pub(crate) fn apply(config: &GrowpartConfig) -> eyre::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    for device in &config.devices {
        grow_device(device)?;
    }

    Ok(())
}

fn grow_device(device: &str) -> eyre::Result<()> {
    let (source, mountpoint, fstype) = if device == "/" {
        (
            findmnt("SOURCE", "/")?,
            "/".to_string(),
            findmnt("FSTYPE", "/")?,
        )
    } else {
        let fstype = command_output("lsblk", ["-no", "FSTYPE", device])
            .unwrap_or_default()
            .trim()
            .to_string();
        (device.to_string(), device.to_string(), fstype)
    };

    let (disk, partition) = split_partition_device(&source)
        .ok_or_else(|| eyre!("cannot infer parent disk and partition number from {source}"))?;
    run_command("growpart", [disk.as_str(), partition.as_str()])?;
    resize_filesystem(&source, &mountpoint, &fstype)?;
    tracing::info!(device, source, fstype, "provisioned growpart");

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

fn resize_filesystem(source: &str, mountpoint: &str, fstype: &str) -> eyre::Result<()> {
    match fstype {
        "ext2" | "ext3" | "ext4" => run_command("resize2fs", [source]),
        "xfs" => run_command("xfs_growfs", [mountpoint]),
        "btrfs" => run_command("btrfs", ["filesystem", "resize", "max", mountpoint]),
        other => Err(eyre!(
            "unsupported filesystem {other:?} for growpart resize on {source}"
        )),
    }
    .with_context(|| format!("resize filesystem {fstype} on {source}"))
}

fn split_partition_device(source: &str) -> Option<(String, String)> {
    let digits_start = source
        .char_indices()
        .rev()
        .find(|(_, ch)| !ch.is_ascii_digit())?
        .0
        + 1;
    if digits_start == source.len() || digits_start == 0 {
        return None;
    }

    let partition = &source[digits_start..];
    let mut disk = &source[..digits_start];
    if disk.ends_with('p') {
        disk = &disk[..disk.len() - 1];
    }
    if disk.is_empty() || partition.is_empty() {
        return None;
    }

    Some((disk.to_string(), partition.to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn splits_partition_devices() {
        assert_eq!(
            super::split_partition_device("/dev/vda1"),
            Some(("/dev/vda".to_string(), "1".to_string()))
        );
        assert_eq!(
            super::split_partition_device("/dev/nvme0n1p2"),
            Some(("/dev/nvme0n1".to_string(), "2".to_string()))
        );
    }
}
