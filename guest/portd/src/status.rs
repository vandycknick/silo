use std::fs::File;
use std::io::{self, Write};
use std::os::fd::FromRawFd;

pub(crate) const STATUS_FD: i32 = 3;
pub(crate) const LISTENER_FD: i32 = 4;

pub(crate) fn report_failure(message: &str) -> io::Result<()> {
    let mut status = unsafe { File::from_raw_fd(STATUS_FD) };
    write_failure(&mut status, message)
}

fn write_failure(mut writer: impl Write, message: &str) -> io::Result<()> {
    write!(writer, "1\n{message}")
}

#[cfg(test)]
mod tests {
    use crate::status::write_failure;

    #[test]
    fn failure_status_matches_moby_contract_exactly() {
        let mut output = Vec::new();
        write_failure(&mut output, "bind refused").expect("write status");
        assert_eq!(output, b"1\nbind refused");
    }
}
