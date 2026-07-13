use std::fs::{self, File};

use agent_spec::ResizeRootfsConfig;
use eyre::Context;
use nix::sys::statfs::statfs;
use rustix::ioctl::{opcode, Opcode, Setter};

use crate::provision::{
    command_exists, run_command, FailurePolicy, ProvisionContext, ProvisionOutcome, Provisioner,
    ProvisionerId,
};

const ROOT_MOUNTPOINT: &str = "/";
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
const SYS_DEV_BLOCK_PATH: &str = "/sys/dev/block";
const KERNEL_SECTOR_SIZE: u64 = 512;

/// Linux `EXT4_IOC_RESIZE_FS`, equivalent to `_IOW('f', 16, __u64)`.
///
/// The argument is the desired total number of ext4 filesystem blocks, not bytes.
const EXT4_IOC_RESIZE_FS: Opcode = opcode::write::<u64>(b'f', 16);

pub(crate) struct ResizeRootfs<'a> {
    config: &'a ResizeRootfsConfig,
}

impl<'a> Provisioner<'a> for ResizeRootfs<'a> {
    type Config = ResizeRootfsConfig;

    fn init(config: &'a Self::Config) -> Self {
        Self { config }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::RESIZE_ROOTFS
    }

    fn failure_policy(&self) -> FailurePolicy {
        FailurePolicy::FailBoot
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        if !self.config.enabled {
            return Ok(ProvisionOutcome::skipped("root filesystem resize disabled"));
        }

        let mount = root_mount(context)?;
        tracing::info!(source = %mount.source, fstype = %mount.fstype, "resizing root filesystem");
        let outcome = resize_filesystem(context, &mount)?;
        if let ProvisionOutcome::Succeeded { changed, .. } = &outcome {
            tracing::info!(
                source = %mount.source,
                fstype = %mount.fstype,
                changed,
                "reconciled root filesystem size"
            );
        }

        Ok(outcome)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RootMount {
    device_id: String,
    source: String,
    fstype: String,
}

fn root_mount(context: &ProvisionContext) -> eyre::Result<RootMount> {
    let path = context.guest_path(MOUNTINFO_PATH);
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("read mount information from {}", path.display()))?;
    parse_root_mountinfo(&contents)
}

fn parse_root_mountinfo(contents: &str) -> eyre::Result<RootMount> {
    for line in contents.lines() {
        let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
            continue;
        };
        let mut mount_fields = mount_fields.split_whitespace();
        let Some(_mount_id) = mount_fields.next() else {
            continue;
        };
        let Some(_parent_id) = mount_fields.next() else {
            continue;
        };
        let Some(device_id) = mount_fields.next() else {
            continue;
        };
        let Some(_root) = mount_fields.next() else {
            continue;
        };
        let Some(mountpoint) = mount_fields.next() else {
            continue;
        };
        if decode_mountinfo_field(mountpoint) != ROOT_MOUNTPOINT {
            continue;
        }

        let mut filesystem_fields = filesystem_fields.split_whitespace();
        let fstype = filesystem_fields
            .next()
            .ok_or_else(|| eyre::eyre!("root mount entry has no filesystem type"))?;
        let source = filesystem_fields
            .next()
            .ok_or_else(|| eyre::eyre!("root mount entry has no source"))?;
        validate_device_id(device_id)?;
        return Ok(RootMount {
            device_id: device_id.to_string(),
            source: decode_mountinfo_field(source),
            fstype: fstype.to_string(),
        });
    }

    eyre::bail!("root mount is missing from {MOUNTINFO_PATH}")
}

fn decode_mountinfo_field(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn validate_device_id(value: &str) -> eyre::Result<()> {
    let Some((major, minor)) = value.split_once(':') else {
        eyre::bail!("root mount has invalid block device id {value:?}");
    };
    if major.parse::<u32>().is_err() || minor.parse::<u32>().is_err() {
        eyre::bail!("root mount has invalid block device id {value:?}");
    }
    Ok(())
}

fn resize_filesystem(
    context: &ProvisionContext,
    mount: &RootMount,
) -> eyre::Result<ProvisionOutcome> {
    match mount.fstype.as_str() {
        "ext4" => resize_ext4_filesystem(context, mount),
        "btrfs" => resize_btrfs(context, mount),
        fstype => Ok(ProvisionOutcome::unsupported(format!(
            "unsupported filesystem {fstype:?} for root filesystem resize on {}",
            mount.source
        ))),
    }
}

fn resize_ext4_filesystem(
    context: &ProvisionContext,
    mount: &RootMount,
) -> eyre::Result<ProvisionOutcome> {
    let root_path = context.guest_path(ROOT_MOUNTPOINT);
    let filesystem = statfs(&root_path)
        .with_context(|| format!("inspect root filesystem at {}", root_path.display()))?;
    let blocks_before = filesystem.blocks();
    let block_size = u64::try_from(filesystem.block_size())
        .context("root filesystem block size does not fit in u64")?;
    let device_size = block_device_size(context, &mount.device_id)?;
    let target_blocks = target_block_count(device_size, block_size)?;
    let root = File::open(&root_path)
        .with_context(|| format!("open root mount {}", root_path.display()))?;

    // SAFETY: EXT4_IOC_RESIZE_FS reads a u64 filesystem block count, and `root` is an
    // open descriptor on the ext4 filesystem being resized.
    let resize = unsafe {
        rustix::ioctl::ioctl(&root, Setter::<EXT4_IOC_RESIZE_FS, u64>::new(target_blocks))
    };
    resize.with_context(|| {
        format!(
            "resize ext4 filesystem on {} to {target_blocks} blocks",
            mount.source
        )
    })?;

    let blocks_after = filesystem_block_count(&root_path)?;
    Ok(resize_outcome(blocks_before, blocks_after))
}

fn filesystem_block_count(path: &std::path::Path) -> eyre::Result<u64> {
    statfs(path)
        .map(|filesystem| filesystem.blocks())
        .with_context(|| format!("inspect filesystem at {}", path.display()))
}

fn resize_outcome(blocks_before: u64, blocks_after: u64) -> ProvisionOutcome {
    ProvisionOutcome::succeeded(blocks_after > blocks_before)
}

fn block_device_size(context: &ProvisionContext, device_id: &str) -> eyre::Result<u64> {
    let path = context.guest_path(&format!("{SYS_DEV_BLOCK_PATH}/{device_id}/size"));
    let sectors = fs::read_to_string(&path)
        .with_context(|| format!("read block device size from {}", path.display()))?
        .trim()
        .parse::<u64>()
        .with_context(|| format!("parse block device sector count from {}", path.display()))?;
    sectors
        .checked_mul(KERNEL_SECTOR_SIZE)
        .ok_or_else(|| eyre::eyre!("block device {device_id} size overflows u64"))
}

fn target_block_count(device_size: u64, filesystem_block_size: u64) -> eyre::Result<u64> {
    if filesystem_block_size == 0 {
        eyre::bail!("root filesystem reported a zero block size");
    }
    let target_blocks = device_size / filesystem_block_size;
    if target_blocks == 0 {
        eyre::bail!(
            "root block device size {device_size} is smaller than filesystem block size {filesystem_block_size}"
        );
    }
    Ok(target_blocks)
}

fn resize_btrfs(context: &ProvisionContext, mount: &RootMount) -> eyre::Result<ProvisionOutcome> {
    if !command_exists("btrfs") {
        return Ok(ProvisionOutcome::unsupported(format!(
            "root filesystem is {} but btrfs-progs is not installed or btrfs is not in PATH",
            mount.fstype
        )));
    }
    let root_path = context.guest_path(ROOT_MOUNTPOINT);
    let blocks_before = filesystem_block_count(&root_path)?;
    run_command(
        context.process_supervisor(),
        "btrfs",
        ["filesystem", "resize", "max", ROOT_MOUNTPOINT],
    )?;
    let blocks_after = filesystem_block_count(&root_path)?;
    Ok(resize_outcome(blocks_before, blocks_after))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::provision::resize::{
        block_device_size, parse_root_mountinfo, resize_filesystem, resize_outcome,
        target_block_count, RootMount,
    };
    use crate::provision::{ProvisionContext, ProvisionOutcome};

    #[test]
    fn parses_root_mount_from_mountinfo_without_external_tools() {
        let contents = concat!(
            "22 1 0:20 / /proc rw,nosuid,nodev,noexec - proc proc rw\n",
            "31 1 254:0 / / rw,relatime shared:1 - ext4 /dev/vda rw\n",
        );

        let mount = parse_root_mountinfo(contents).expect("parse root mount");

        assert_eq!(
            mount,
            RootMount {
                device_id: "254:0".to_string(),
                source: "/dev/vda".to_string(),
                fstype: "ext4".to_string(),
            }
        );
    }

    #[test]
    fn decodes_escaped_mount_source() {
        let contents = "31 1 8:1 / / rw - ext4 /dev/disk\\040name rw\n";

        let mount = parse_root_mountinfo(contents).expect("parse root mount");

        assert_eq!(mount.source, "/dev/disk name");
    }

    #[test]
    fn rejects_mountinfo_without_root_mount() {
        let error = parse_root_mountinfo("22 1 0:20 / /proc rw - proc proc rw\n")
            .expect_err("missing root mount must fail");

        assert!(error.to_string().contains("root mount is missing"));
    }

    #[test]
    fn calculates_target_filesystem_blocks_from_device_capacity() {
        assert_eq!(
            target_block_count(100 * 1024 * 1024 * 1024, 4096).expect("target blocks"),
            26_214_400
        );
    }

    #[test]
    fn ext2_and_ext3_root_filesystems_are_unsupported() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let context = ProvisionContext::for_test(temp.path());

        for fstype in ["ext2", "ext3"] {
            let mount = RootMount {
                device_id: "8:1".to_string(),
                source: "/dev/vda1".to_string(),
                fstype: fstype.to_string(),
            };

            assert!(matches!(
                resize_filesystem(&context, &mount),
                Ok(ProvisionOutcome::Unsupported { .. })
            ));
        }
    }

    #[test]
    fn reads_block_device_capacity_from_sysfs_sectors() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let size_path = temp.path().join("sys/dev/block/254:0");
        fs::create_dir_all(&size_path).expect("create sysfs device dir");
        fs::write(size_path.join("size"), "209715200\n").expect("write sector count");
        let context = ProvisionContext::for_test(temp.path());

        let bytes = block_device_size(&context, "254:0").expect("read block device size");

        assert_eq!(bytes, 100 * 1024 * 1024 * 1024);
    }

    #[test]
    fn reports_resize_change_only_when_filesystem_capacity_grows() {
        assert_eq!(
            resize_outcome(1_000, 2_000),
            ProvisionOutcome::succeeded(true)
        );
        assert_eq!(
            resize_outcome(2_000, 2_000),
            ProvisionOutcome::succeeded(false)
        );
    }
}
