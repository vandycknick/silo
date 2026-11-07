//! Fixed init-owned Rosetta contract: reserved share, trusted retained mount,
//! the single binfmt_misc registration record and its exact kernel readback.
//!
//! Trusted init mounts the share and registers the handler before the first
//! `switch_root`. The mount lives under `/run`, which init carries across the
//! root handoff. Nothing here is configurable: a caller cannot select another
//! tag, interpreter path, handler name or flag set.

use core::fmt;

/// Virtio-fs tag reserved for the host-provided Rosetta share.
pub const SHARE_TAG: &str = "rosetta";
/// Trusted retained mount of the Rosetta share, owned by init.
pub const MOUNT_PATH: &str = "/run/silo/rosetta";
/// Interpreter registered for x86-64 ELF executables.
pub const INTERPRETER_PATH: &str = "/run/silo/rosetta/rosetta";

pub const BINFMT_MISC_PATH: &str = "/proc/sys/fs/binfmt_misc";
pub const BINFMT_STATUS_PATH: &str = "/proc/sys/fs/binfmt_misc/status";
pub const BINFMT_REGISTER_PATH: &str = "/proc/sys/fs/binfmt_misc/register";
pub const HANDLER_NAME: &str = "rosetta";
pub const HANDLER_PATH: &str = "/proc/sys/fs/binfmt_misc/rosetta";

/// x86-64 ELF header bytes 0..20, as the kernel prints them (unmasked).
pub const MAGIC_HEX: &str = "7f454c4602010100000000000000000002003e00";
pub const MASK_HEX: &str = "fffffffffffefe00fffffffffffffffffeffffff";
/// O passes an opened target fd, C preserves target credentials, and F opens
/// the interpreter at registration so it keeps working after `switch_root`,
/// in chroots and in other mount namespaces.
pub const FLAGS: &str = "OCF";

/// Complete `:name:type:offset:magic:mask:interpreter:flags` record, written
/// with one `write(2)`. binfmt_misc parses registration as text and stops at a
/// raw NUL, so non-printable magic and mask bytes are `\xHH` escape text. This
/// is deliberately a raw byte string: the backslash-x sequences are literal.
pub const REGISTRATION: &[u8] = br":rosetta:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/run/silo/rosetta/rosetta:OCF";

/// Exact `entry_status` rendering of [`REGISTRATION`] by Linux binfmt_misc:
/// enabled state, interpreter, flags in P/O/C/F order, offset, then lowercase
/// unmasked magic and mask hex.
pub const EXPECTED_HANDLER: &[u8] = b"enabled\ninterpreter /run/silo/rosetta/rosetta\nflags: OCF\noffset 0\nmagic 7f454c4602010100000000000000000002003e00\nmask fffffffffffefe00fffffffffffffffffeffffff\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckError {
    /// Global binfmt_misc is disabled; init never re-enables unrelated state.
    GlobalDisabled,
    GlobalStatusUnrecognized,
    /// A handler with the reserved name exists but is disabled.
    HandlerDisabled,
    /// A handler with the reserved name differs from the fixed registration.
    HandlerConflict,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GlobalDisabled => "global binfmt_misc is disabled",
            Self::GlobalStatusUnrecognized => "unrecognized global binfmt_misc status",
            Self::HandlerDisabled => "Rosetta binfmt handler is disabled",
            Self::HandlerConflict => "conflicting Rosetta binfmt handler",
        })
    }
}

impl core::error::Error for CheckError {}

/// Validates `/proc/sys/fs/binfmt_misc/status` without mutating it.
pub fn check_global_status(contents: &[u8]) -> Result<(), CheckError> {
    match contents {
        b"enabled\n" => Ok(()),
        b"disabled\n" => Err(CheckError::GlobalDisabled),
        _ => Err(CheckError::GlobalStatusUnrecognized),
    }
}

/// Validates a reserved-name handler readback against the fixed registration.
/// Any deviation, including extra or reordered lines, is a conflict: the
/// kernel renders exactly one canonical form for this record.
pub fn check_handler(contents: &[u8]) -> Result<(), CheckError> {
    if contents == EXPECTED_HANDLER {
        return Ok(());
    }
    if contents.starts_with(b"disabled\n") {
        return Err(CheckError::HandlerDisabled);
    }
    Err(CheckError::HandlerConflict)
}

#[cfg(test)]
mod tests {
    use crate::rosetta::{
        check_global_status, check_handler, CheckError, BINFMT_MISC_PATH, BINFMT_REGISTER_PATH,
        BINFMT_STATUS_PATH, EXPECTED_HANDLER, FLAGS, HANDLER_NAME, HANDLER_PATH, INTERPRETER_PATH,
        MAGIC_HEX, MASK_HEX, MOUNT_PATH, REGISTRATION,
    };
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    /// Decodes the `\xHH` escape text the kernel unescapes at registration.
    fn unescape(field: &[u8]) -> Vec<u8> {
        let text = core::str::from_utf8(field).unwrap();
        let mut out = Vec::new();
        let mut rest = text;
        while !rest.is_empty() {
            if let Some(hex) = rest.strip_prefix("\\x") {
                out.push(u8::from_str_radix(&hex[..2], 16).unwrap());
                rest = &hex[2..];
            } else {
                let (first, tail) = rest.split_at(1);
                out.extend_from_slice(first.as_bytes());
                rest = tail;
            }
        }
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn fixed_paths_are_under_the_retained_run_subtree() {
        assert_eq!(INTERPRETER_PATH, format!("{MOUNT_PATH}/rosetta"));
        assert!(MOUNT_PATH.starts_with("/run/silo/"));
        assert_eq!(HANDLER_PATH, format!("{BINFMT_MISC_PATH}/{HANDLER_NAME}"));
        assert_eq!(BINFMT_STATUS_PATH, format!("{BINFMT_MISC_PATH}/status"));
        assert_eq!(BINFMT_REGISTER_PATH, format!("{BINFMT_MISC_PATH}/register"));
    }

    #[test]
    fn registration_is_one_nul_free_record_with_escaped_magic_and_ocf() {
        assert!(!REGISTRATION.contains(&0));
        assert!(REGISTRATION.windows(4).any(|window| window == br"\x00"));
        let fields: Vec<&[u8]> = REGISTRATION.split(|byte| *byte == b':').collect();
        // Leading delimiter, then name, type, offset, magic, mask, path, flags.
        assert_eq!(fields.len(), 8);
        assert_eq!(fields[0], b"");
        assert_eq!(fields[1], HANDLER_NAME.as_bytes());
        assert_eq!(fields[2], b"M");
        assert_eq!(fields[3], b"");
        let magic = unescape(fields[4]);
        let mask = unescape(fields[5]);
        assert_eq!(magic.len(), 20);
        assert_eq!(mask.len(), magic.len());
        assert_eq!(hex(&magic), MAGIC_HEX);
        assert_eq!(hex(&mask), MASK_HEX);
        assert_eq!(fields[6], INTERPRETER_PATH.as_bytes());
        assert_eq!(fields[7], FLAGS.as_bytes());
        // x86-64 ELF64 little-endian ET_EXEC/ET_DYN header: e_machine 0x3e.
        assert_eq!(&magic[..4], b"\x7fELF");
        assert_eq!(&magic[18..20], &[0x3e, 0x00]);
    }

    #[test]
    fn expected_readback_is_composed_from_the_registration_facts() {
        let composed = format!(
            "enabled\ninterpreter {INTERPRETER_PATH}\nflags: {FLAGS}\noffset 0\nmagic {MAGIC_HEX}\nmask {MASK_HEX}\n"
        );
        assert_eq!(EXPECTED_HANDLER, composed.as_bytes());
        assert_eq!(check_handler(EXPECTED_HANDLER), Ok(()));
    }

    #[test]
    fn handler_readback_rejects_disabled_and_every_conflicting_field() {
        let expected = core::str::from_utf8(EXPECTED_HANDLER).unwrap();
        assert_eq!(
            check_handler(expected.replacen("enabled", "disabled", 1).as_bytes()),
            Err(CheckError::HandlerDisabled)
        );
        for (before, after) in [
            (
                "interpreter /run/silo/rosetta/rosetta",
                "interpreter /mnt/rosetta/rosetta",
            ),
            ("flags: OCF", "flags: F"),
            ("flags: OCF", "flags: POCF"),
            ("offset 0", "offset 1"),
            ("magic 7f454c46", "magic 7f454c47"),
            ("mask ffffffff", "mask fffffffe"),
            ("magic 7f454c46", "magic 7F454C46"),
        ] {
            let mutated = expected.replacen(before, after, 1);
            assert_ne!(mutated, expected, "{after}");
            assert_eq!(
                check_handler(mutated.as_bytes()),
                Err(CheckError::HandlerConflict),
                "{after}"
            );
        }
        let without_mask = expected.replacen(&format!("mask {MASK_HEX}\n"), "", 1);
        assert_eq!(
            check_handler(without_mask.as_bytes()),
            Err(CheckError::HandlerConflict)
        );
        assert_eq!(
            check_handler(&EXPECTED_HANDLER[..EXPECTED_HANDLER.len() - 1]),
            Err(CheckError::HandlerConflict)
        );
        assert_eq!(check_handler(b""), Err(CheckError::HandlerConflict));
    }

    #[test]
    fn global_status_must_be_exactly_enabled() {
        assert_eq!(check_global_status(b"enabled\n"), Ok(()));
        assert_eq!(
            check_global_status(b"disabled\n"),
            Err(CheckError::GlobalDisabled)
        );
        for status in [b"enabled".as_slice(), b" enabled\n", b"", b"1\n"] {
            assert_eq!(
                check_global_status(status),
                Err(CheckError::GlobalStatusUnrecognized)
            );
        }
    }
}
