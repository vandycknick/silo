//! Pure admission of the init-owned Rosetta share, interpreter and
//! binfmt_misc instance, over facts measured from the held descriptors.
//! Registration text and readback live in `rootfs_spec::rosetta`.

/// `statfs` magic of FUSE, which serves virtiofs.
pub const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
/// `statfs` magic of the binfmt_misc filesystem.
pub const BINFMTFS_MAGIC: u64 = 0x4249_4e4d;

// Linux `statfs.f_flags` bits; meaningful only when ST_VALID is reported.
const ST_RDONLY: u64 = 0x0001;
const ST_NOSUID: u64 = 0x0002;
const ST_NODEV: u64 = 0x0004;
const ST_NOEXEC: u64 = 0x0008;
const ST_VALID: u64 = 0x0020;

#[derive(Clone, Copy, Debug)]
pub struct MountFacts {
    pub filesystem_magic: u64,
    pub flags: u64,
    pub device: u64,
}

/// The share must be a fresh read-only, nosuid, nodev virtiofs mount that
/// still permits execution, distinct from the trusted directory beneath it.
pub fn check_share(share: MountFacts, parent_device: u64) -> Result<(), &'static str> {
    if share.filesystem_magic != FUSE_SUPER_MAGIC {
        return Err("rosetta: share is not virtiofs");
    }
    if share.device == parent_device {
        return Err("rosetta: share is not mounted at the trusted mount point");
    }
    let required = ST_VALID | ST_RDONLY | ST_NOSUID | ST_NODEV;
    if share.flags & required != required || share.flags & ST_NOEXEC != 0 {
        return Err("rosetta: share mount options are not ro,nosuid,nodev,exec");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct FileFacts {
    pub mode: u32,
    pub device: u64,
}

/// The interpreter must be an executable regular file served by the share.
pub fn check_interpreter(interpreter: FileFacts, share_device: u64) -> Result<(), &'static str> {
    if interpreter.mode & 0o170000 != 0o100000 {
        return Err("rosetta: interpreter is not a regular file");
    }
    if interpreter.mode & 0o111 == 0 {
        return Err("rosetta: interpreter is not executable");
    }
    if interpreter.device != share_device {
        return Err("rosetta: interpreter is not reached through the trusted share");
    }
    Ok(())
}

pub fn check_binfmt_mount(filesystem_magic: u64) -> Result<(), &'static str> {
    if filesystem_magic != BINFMTFS_MAGIC {
        return Err("rosetta: binfmt_misc is not mounted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::rosetta_checks::{
        check_binfmt_mount, check_interpreter, check_share, FileFacts, MountFacts, BINFMTFS_MAGIC,
        FUSE_SUPER_MAGIC,
    };

    fn share() -> MountFacts {
        MountFacts {
            filesystem_magic: FUSE_SUPER_MAGIC,
            flags: 0x20 | 0x1 | 0x2 | 0x4 | 0x400,
            device: 0x31,
        }
    }

    #[test]
    fn share_requires_virtiofs_mount_with_exact_access_flags() {
        assert_eq!(check_share(share(), 0x16), Ok(()));
        for mutated in [
            MountFacts {
                filesystem_magic: 0x0102_1994,
                ..share()
            },
            MountFacts {
                flags: share().flags | 0x8,
                ..share()
            },
            MountFacts {
                flags: share().flags & !0x1,
                ..share()
            },
            MountFacts {
                flags: share().flags & !0x2,
                ..share()
            },
            MountFacts {
                flags: share().flags & !0x4,
                ..share()
            },
            MountFacts {
                flags: share().flags & !0x20,
                ..share()
            },
        ] {
            assert!(check_share(mutated, 0x16).is_err());
        }
        // Not a mount: the directory and the "share" are the same device.
        assert!(check_share(share(), 0x31).is_err());
    }

    #[test]
    fn interpreter_must_be_an_executable_regular_file_on_the_share() {
        let valid = FileFacts {
            mode: 0o100755,
            device: 0x31,
        };
        assert_eq!(check_interpreter(valid, 0x31), Ok(()));
        assert_eq!(
            check_interpreter(
                FileFacts {
                    mode: 0o100100,
                    ..valid
                },
                0x31
            ),
            Ok(())
        );
        for (mode, device) in [
            (0o100644, 0x31),
            (0o040755, 0x31),
            (0o120777, 0x31),
            (0o020755, 0x31),
            (0o100755, 0x16),
        ] {
            assert!(check_interpreter(FileFacts { mode, device }, 0x31).is_err());
        }
    }

    #[test]
    fn binfmt_instance_must_be_binfmt_misc() {
        assert_eq!(check_binfmt_mount(BINFMTFS_MAGIC), Ok(()));
        assert!(check_binfmt_mount(0x9fa0).is_err());
    }
}
