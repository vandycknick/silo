//! Guest-only qualification utility. Compile for the guest's Linux musl target.

use std::io::{self, Write};

// This standalone test guest has no crate dependencies, including nix. Use the
// musl reboot wrapper rather than architecture-specific raw syscall numbers.
unsafe extern "C" {
    fn sync();
    fn reboot(command: i32) -> i32;
}

fn qualification_guest(cmdline: &str) -> bool {
    cmdline
        .split_whitespace()
        .any(|argument| argument == "silo.qualification=krun-worker")
}

fn main() -> io::Result<()> {
    if !qualification_guest(&std::fs::read_to_string("/proc/cmdline")?) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing reboot outside the native worker qualification guest",
        ));
    }
    let command = match std::env::args_os().nth(1).as_deref() {
        None => 0x0123_4567, // Linux UAPI RB_AUTOBOOT, also used by libkrun's init.
        Some(value) if value == "poweroff" => 0x4321_fedc,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected optional poweroff",
            ));
        }
    };
    // This program is executed only inside the VM.
    unsafe {
        sync();
    }
    io::stdout().write_all(b"SILO_NATIVE_SHUTDOWN\n")?;
    io::stdout().flush()?;
    unsafe {
        reboot(command);
    }
    Err(io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    #[test]
    fn requires_an_exact_guest_qualification_marker() {
        assert!(crate::qualification_guest(
            "console=hvc0 silo.qualification=krun-worker loglevel=4"
        ));
        for cmdline in [
            "",
            "console=ttyS0",
            "silo.qualification=krun-worker-extra",
            "other=silo.qualification=krun-worker",
        ] {
            assert!(!crate::qualification_guest(cmdline));
        }
    }
}
