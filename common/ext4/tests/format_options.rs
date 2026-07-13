// Tests for `FormatOptions` / `Formatter::with_options` — UUID and label
// propagation into the superblock, label validation.

use ext4::constants::{file_mode, make_mode};
use ext4::error::FormatError;
use ext4::{FormatOptions, Formatter, Reader};
use tempfile::NamedTempFile;
use uuid::Uuid;

const SIZE: u64 = 256 * 1024;

#[test]
fn with_options_writes_explicit_uuid() {
    let tmp = NamedTempFile::new().unwrap();
    let target = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();

    let fmt = Formatter::with_options(tmp.path(), FormatOptions::new(SIZE).uuid(target)).unwrap();
    fmt.close().unwrap();

    let reader = Reader::new(tmp.path()).unwrap();
    assert_eq!(reader.superblock().uuid, *target.as_bytes());
}

#[test]
fn with_options_writes_label() {
    let tmp = NamedTempFile::new().unwrap();

    let fmt =
        Formatter::with_options(tmp.path(), FormatOptions::new(SIZE).label("alpine-boot")).unwrap();
    fmt.close().unwrap();

    let reader = Reader::new(tmp.path()).unwrap();
    let volume_name = reader.superblock().volume_name;
    assert_eq!(&volume_name[..11], b"alpine-boot");
    assert!(volume_name[11..].iter().all(|&b| b == 0));
}

#[test]
fn with_options_rejects_oversize_label() {
    let tmp = NamedTempFile::new().unwrap();

    // 17 ASCII bytes — one over the 16-byte superblock field.
    let result = Formatter::with_options(
        tmp.path(),
        FormatOptions::new(SIZE).label("this-is-17-bytes!"),
    );
    assert!(matches!(result, Err(FormatError::InvalidLabel(_))));
}

#[test]
fn with_options_rejects_nul_in_label() {
    let tmp = NamedTempFile::new().unwrap();
    let result = Formatter::with_options(tmp.path(), FormatOptions::new(SIZE).label("lbl\0bad"));
    assert!(matches!(result, Err(FormatError::InvalidLabel(_))));
}

#[test]
fn with_options_rejects_zero_size_before_truncating() {
    let tmp = NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"keep").unwrap();

    let result = Formatter::with_options(tmp.path(), FormatOptions::new(0));

    assert!(matches!(result, Err(FormatError::InvalidSize { .. })));
    assert_eq!(std::fs::read(tmp.path()).unwrap(), b"keep");
}

#[test]
fn with_options_rejects_size_beyond_32_bit_layout() {
    let tmp = NamedTempFile::new().unwrap();
    let result =
        Formatter::with_options(tmp.path(), FormatOptions::new((u32::MAX as u64 + 1) * 4096));

    assert!(matches!(result, Err(FormatError::InvalidSize { .. })));
}

#[test]
fn formatter_rejects_parent_and_current_directory_entries() {
    let tmp = NamedTempFile::new().unwrap();
    let mut formatter = Formatter::new(tmp.path(), 4096, SIZE).unwrap();

    for path in ["/../escape", "/."] {
        let result = formatter.create(
            path,
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut "invalid".as_bytes()),
            None,
            None,
            None,
        );
        assert!(matches!(result, Err(FormatError::InvalidPathEncoding(_))));
    }
}

#[test]
fn formatter_validates_file_type_before_writing_payload() {
    let tmp = NamedTempFile::new().unwrap();
    let mut formatter = Formatter::new(tmp.path(), 4096, SIZE).unwrap();

    let result = formatter.create(
        "/fifo",
        0x1000 | 0o644,
        None,
        None,
        Some(&mut "invalid".as_bytes()),
        None,
        None,
        None,
    );

    assert!(matches!(result, Err(FormatError::UnsupportedFiletype)));
}
