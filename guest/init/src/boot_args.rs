//! Kernel command-line policy for a Silo direct boot.
//!
//! The launch bootstrap is the sole root authority and `/init` is the sole
//! initial executable. Parameters are read exactly as Linux splits them
//! (`rootfs_spec::kernel_cmdline`), so quoting cannot hide one. Kernel root
//! selectors (`root=`, `rootfstype=`, `rootflags=`) and `rdinit=` are never
//! accepted, and every duplicate of an admitted key is rejected rather than
//! resolved by position. Host admission refuses `rdinit=` before launch; a
//! kernel that honored it would never enter this code, so the check here only
//! refuses a command line the host must not have produced.

use rootfs_spec::kernel_cmdline::{params, Reserved};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootMarker {
    /// `silo.rootfs=linux-flat-overlay-v1`, a consistency guard only.
    FlatOverlay,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootArgs<'a> {
    /// Explicit image init, an execution-policy input, never a device selector.
    pub init: Option<&'a [u8]>,
    pub marker: Option<RootMarker>,
}

pub fn parse(cmdline: &[u8]) -> Result<BootArgs<'_>, &'static str> {
    let mut args = BootArgs::default();
    for param in params(cmdline) {
        match param.reserved() {
            Some(Reserved::RootSelection) => {
                return Err("kernel root selection is not admitted; the bootstrap selects the root")
            }
            Some(Reserved::InitialExecutable) => {
                return Err("rdinit= is not admitted; /init is the trusted initial executable")
            }
            None => {}
        }
        let Some(value) = param.value else {
            continue;
        };
        if param.is(b"init") {
            if args.init.replace(value).is_some() {
                return Err("duplicate init= argument");
            }
        } else if param.is(b"silo.rootfs") {
            if value != b"linux-flat-overlay-v1" {
                return Err("unknown silo.rootfs= root marker");
            }
            if args.marker.replace(RootMarker::FlatOverlay).is_some() {
                return Err("duplicate silo.rootfs= argument");
            }
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use crate::boot_args::{parse, BootArgs, RootMarker};

    #[test]
    fn plain_and_overlay_command_lines_parse_exactly() {
        assert_eq!(parse(b"console=hvc0 loglevel=4\n"), Ok(BootArgs::default()));
        assert_eq!(
            parse(b"loglevel=6 silo.rootfs=linux-flat-overlay-v1 init=/sbin/candidate-init\n"),
            Ok(BootArgs {
                init: Some(b"/sbin/candidate-init".as_slice()),
                marker: Some(RootMarker::FlatOverlay),
            })
        );
        // Similar names and quoted text are unrelated keys, as in the kernel.
        assert_eq!(
            parse(b"rootwait xinit=/x silo.rootfsx=1 rdinit root \"a rdinit=/x\" x=\"rdinit=/x\""),
            Ok(BootArgs::default())
        );
    }

    #[test]
    fn quoted_spellings_are_read_as_the_kernel_reads_them() {
        assert_eq!(
            parse(b"\"silo.rootfs=linux-flat-overlay-v1\" init=\"/sbin/my init\"\n"),
            Ok(BootArgs {
                init: Some(b"/sbin/my init".as_slice()),
                marker: Some(RootMarker::FlatOverlay),
            })
        );
        assert!(parse(b"init=/a \"init=/b\"").is_err());
    }

    #[test]
    fn initial_executable_override_is_rejected_in_every_kernel_spelling() {
        for cmdline in [
            b"rdinit=/agent/silo-agent".as_slice(),
            b"rdinit=/init",
            b"rdinit=",
            b"\"rdinit=/agent/silo-agent\"",
            b"rdinit=\"/agent/silo-agent\"",
            b"console=hvc0\x0brdinit=/agent/silo-agent",
            b"x\xa0rdinit=/agent/silo-agent",
            b"silo.rootfs=linux-flat-overlay-v1 init=/sbin/init rdinit=/agent/silo-agent",
        ] {
            assert_eq!(
                parse(cmdline),
                Err("rdinit= is not admitted; /init is the trusted initial executable"),
                "{cmdline:?}"
            );
        }
    }

    #[test]
    fn kernel_root_selection_is_rejected_for_every_root_kind() {
        for cmdline in [
            b"root=/dev/vda".as_slice(),
            b"console=hvc0 root=PARTUUID=01234567-89ab-cdef-0123-456789abcdef",
            b"rootfstype=ext4",
            b"rootflags=ro",
            b"silo.rootfs=linux-flat-overlay-v1 root=/dev/vdb",
            b"root=",
            b"\"root=/dev/vda\"",
            b"rootflags=\"ro\"",
        ] {
            assert_eq!(
                parse(cmdline),
                Err("kernel root selection is not admitted; the bootstrap selects the root"),
                "{cmdline:?}"
            );
        }
    }

    #[test]
    fn duplicate_or_unknown_admitted_keys_are_not_resolved_by_position() {
        for cmdline in [
            b"init=/a init=/b".as_slice(),
            b"init=/a init=/a",
            b"silo.rootfs=linux-flat-overlay-v1 silo.rootfs=linux-flat-overlay-v1",
            b"silo.rootfs=opaque-raw-v1",
            b"silo.rootfs=",
        ] {
            assert!(
                parse(cmdline).is_err(),
                "{:?}",
                core::str::from_utf8(cmdline)
            );
        }
    }
}
