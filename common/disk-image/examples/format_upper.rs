//! Pure image input generator for independent e2fsprogs and native smoke gates.
//! Never launches a VM or publishes a machine.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use disk_image::ext4::upper::format_upper;
use rootfs_spec::upper_geometry::UpperCapacity;

fn run() -> io::Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let destination = arguments.next().ok_or_else(usage)?;
    let bytes = arguments.next().ok_or_else(usage)?;
    if arguments.next().is_some() {
        return Err(usage());
    }
    let bytes: u64 = bytes
        .to_str()
        .ok_or_else(usage)?
        .parse()
        .map_err(|_| usage())?;
    let capacity = UpperCapacity::new(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let upper = format_upper(Path::new(&destination), capacity).map_err(io::Error::other)?;
    writeln!(
        io::stdout().lock(),
        "{{\"profile\":\"silo-upper-ext4-v1\",\"uuid\":\"{}\",\"backing_bytes\":{},\"filesystem_bytes\":{},\"unusable_tail_bytes\":{},\"initial_free_bytes\":{},\"initial_free_inodes\":{}}}",
        upper.uuid,
        upper.backing_bytes,
        upper.filesystem_bytes,
        upper.unusable_tail_bytes,
        upper.initial_free_bytes,
        upper.initial_free_inodes,
    )
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: format_upper DEST BYTES",
    )
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "format_upper: {error}");
            ExitCode::FAILURE
        }
    }
}
