//! Helper-to-parent status channel.
//!
//! The parent creates a pipe before spawning the `krun` helper and passes the
//! write end through [`ENV_STATUS_FD`]. The helper writes newline-delimited
//! `key=value` records on it whenever something the parent should surface
//! changes. Only host memory reclaim is reported today. Records are additive:
//! parsers ignore unknown keys and unknown record kinds.

#![allow(
    dead_code,
    reason = "the status channel is compiled into both the library parent side and krun child side"
)]

use std::fmt::Write as _;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::libc;
use nix::sys::stat::{fstat, SFlag};
use nix::unistd::pipe;

pub(crate) const ENV_STATUS_FD: &str = "SILO_KRUN_STATUS_FD";

/// Creates the channel. Returns `(parent_read, child_write)`, both close-on-exec.
pub(crate) fn create() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read_fd, write_fd) = pipe()?;
    set_cloexec(read_fd.as_fd(), true)?;
    set_cloexec(write_fd.as_fd(), true)?;
    Ok((read_fd, write_fd))
}

pub(crate) fn fd_env_value(fd: &OwnedFd) -> String {
    fd.as_raw_fd().to_string()
}

/// Child side: takes ownership of the inherited write end named by the environment.
pub(crate) fn take_from_env() -> io::Result<Option<OwnedFd>> {
    let Some(value) = std::env::var_os(ENV_STATUS_FD) else {
        return Ok(None);
    };
    take_from_value(&value).map(Some)
}

fn take_from_value(value: &std::ffi::OsStr) -> io::Result<OwnedFd> {
    let value = value
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "status fd is not UTF-8"))?;
    let fd = value.parse::<RawFd>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid status fd {value:?}: {error}"),
        )
    })?;
    if fd < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "status fd must not alias standard input, output, or error",
        ));
    }
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let stat = fstat(borrowed).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("status fd {fd} is not open: {error}"),
        )
    })?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFIFO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("status fd {fd} is not a pipe"),
        ));
    }
    let flags = OFlag::from_bits_truncate(fcntl(borrowed, FcntlArg::F_GETFL)?);
    if flags.bits() & libc::O_ACCMODE != libc::O_WRONLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("status fd {fd} is not a pipe write end"),
        ));
    }
    // SAFETY: validation above proves this non-stdio descriptor is open, and the
    // launcher transfers its sole ownership through the environment contract.
    let write_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(write_fd.as_fd(), true)?;
    Ok(write_fd)
}

fn set_cloexec(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    let mut flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
    flags.set(FdFlag::FD_CLOEXEC, enabled);
    fcntl(fd, FcntlArg::F_SETFD(flags))?;
    Ok(())
}

/// Outcome of libkrun's per-VM host reclaim qualification probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostMemoryReclaimQualification {
    NotRun,
    Passed,
    Failed,
    Inconclusive,
}

impl HostMemoryReclaimQualification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not-run",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Inconclusive => "inconclusive",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "not-run" => Self::NotRun,
            "passed" => Self::Passed,
            "failed" => Self::Failed,
            "inconclusive" => Self::Inconclusive,
            _ => return None,
        })
    }
}

/// Host memory reclaim state of the running VM, as reported by the helper.
///
/// `effective` is true only while free-page reports are actually released to
/// the host. The counters are cumulative for the VM lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostMemoryReclaimStatus {
    pub requested: bool,
    pub qualification: HostMemoryReclaimQualification,
    pub effective: bool,
    pub released_bytes: u64,
    pub released_extents: u64,
    pub retried_faults: u64,
    pub skipped_reports: u64,
    pub failed_operations: u64,
}

impl HostMemoryReclaimStatus {
    pub const RECORD: &'static str = "host-memory-reclaim";

    /// One newline-terminated record.
    pub fn encode(&self) -> String {
        let mut line = String::from(Self::RECORD);
        let _ = writeln!(
            line,
            " requested={} qualification={} effective={} released_bytes={} released_extents={} retried_faults={} skipped_reports={} failed_operations={}",
            on_off(self.requested),
            self.qualification.as_str(),
            on_off(self.effective),
            self.released_bytes,
            self.released_extents,
            self.retried_faults,
            self.skipped_reports,
            self.failed_operations,
        );
        line
    }

    /// Parses one record line. Returns `None` for other record kinds or
    /// malformed input; unknown keys are ignored.
    pub fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        if fields.next()? != Self::RECORD {
            return None;
        }
        let mut status = Self {
            requested: false,
            qualification: HostMemoryReclaimQualification::NotRun,
            effective: false,
            released_bytes: 0,
            released_extents: 0,
            retried_faults: 0,
            skipped_reports: 0,
            failed_operations: 0,
        };
        let mut seen_effective = false;
        for field in fields {
            let (key, value) = field.split_once('=')?;
            match key {
                "requested" => status.requested = parse_on_off(value)?,
                "qualification" => {
                    status.qualification = HostMemoryReclaimQualification::parse(value)?
                }
                "effective" => {
                    status.effective = parse_on_off(value)?;
                    seen_effective = true;
                }
                "released_bytes" => status.released_bytes = value.parse().ok()?,
                "released_extents" => status.released_extents = value.parse().ok()?,
                "retried_faults" => status.retried_faults = value.parse().ok()?,
                "skipped_reports" => status.skipped_reports = value.parse().ok()?,
                "failed_operations" => status.failed_operations = value.parse().ok()?,
                _ => {}
            }
        }
        seen_effective.then_some(status)
    }
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn parse_on_off(value: &str) -> Option<bool> {
    match value {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{HostMemoryReclaimQualification, HostMemoryReclaimStatus};

    fn sample() -> HostMemoryReclaimStatus {
        HostMemoryReclaimStatus {
            requested: true,
            qualification: HostMemoryReclaimQualification::Passed,
            effective: true,
            released_bytes: 6_291_456,
            released_extents: 3,
            retried_faults: 1,
            skipped_reports: 2,
            failed_operations: 0,
        }
    }

    #[test]
    fn status_round_trips_through_one_line() {
        let line = sample().encode();
        assert!(line.ends_with('\n'));
        assert_eq!(line.lines().count(), 1);
        assert_eq!(HostMemoryReclaimStatus::parse(&line), Some(sample()));
    }

    #[test]
    fn parser_ignores_unknown_keys_and_other_records() {
        let line = "host-memory-reclaim requested=off qualification=failed effective=off future=1 released_bytes=0\n";
        let status = HostMemoryReclaimStatus::parse(line).expect("parse");
        assert!(!status.requested);
        assert_eq!(status.qualification, HostMemoryReclaimQualification::Failed);
        assert!(!status.effective);
        assert_eq!(HostMemoryReclaimStatus::parse("other-record a=b"), None);
        assert_eq!(
            HostMemoryReclaimStatus::parse("host-memory-reclaim requested=on"),
            None,
            "effective is required"
        );
        assert_eq!(
            HostMemoryReclaimStatus::parse("host-memory-reclaim effective=maybe"),
            None
        );
        assert_eq!(
            HostMemoryReclaimStatus::parse("host-memory-reclaim effective=on released_bytes=x"),
            None
        );
    }
}
