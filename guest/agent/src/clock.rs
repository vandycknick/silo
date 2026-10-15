//! Applies host wall time pushed by `silo-vmm`.
//!
//! On macOS hosts the guest counter stops while the Mac sleeps, so after a wake
//! the guest `CLOCK_REALTIME` lags by however long the lid was closed. The host
//! sends its own `CLOCK_REALTIME` and we step only when we are more than
//! [`STEP_THRESHOLD_NANOS`] off, which leaves sub-second slewing to whatever
//! NTP daemon the image runs.

use nix::time::ClockId;

const STEP_THRESHOLD_NANOS: i128 = 1_000_000_000;
const MIN_HOST_UNIX_SECONDS: i64 = 1_704_067_200;
const NANOS_PER_SECOND: i128 = 1_000_000_000;

pub(crate) struct ClockSyncOutcome {
    pub(crate) offset_nanos: i128,
    pub(crate) stepped: bool,
}

#[derive(Debug)]
pub(crate) enum ClockSyncError {
    Missing,
    Invalid(&'static str),
    Read(nix::errno::Errno),
    Set(nix::errno::Errno),
}

impl std::fmt::Display for ClockSyncError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("host_time is required"),
            Self::Invalid(reason) => write!(formatter, "host_time is invalid: {reason}"),
            Self::Read(errno) => write!(formatter, "read guest realtime clock: {errno}"),
            Self::Set(errno) => write!(formatter, "set guest realtime clock: {errno}"),
        }
    }
}

impl std::error::Error for ClockSyncError {}

pub(crate) fn sync_realtime(
    host_time: Option<&prost_types::Timestamp>,
) -> Result<ClockSyncOutcome, ClockSyncError> {
    let host = host_nanos(host_time)?;
    let guest = nix::time::clock_gettime(ClockId::CLOCK_REALTIME).map_err(ClockSyncError::Read)?;
    let guest = i128::from(guest.tv_sec()) * NANOS_PER_SECOND + i128::from(guest.tv_nsec());
    let offset_nanos = host - guest;
    if !should_step(offset_nanos) {
        return Ok(ClockSyncOutcome {
            offset_nanos,
            stepped: false,
        });
    }
    let seconds = u64::try_from(host / NANOS_PER_SECOND)
        .map_err(|_| ClockSyncError::Invalid("seconds out of range"))?;
    let nanos = u32::try_from(host % NANOS_PER_SECOND)
        .map_err(|_| ClockSyncError::Invalid("nanos out of range"))?;
    let target = nix::sys::time::TimeSpec::from(std::time::Duration::new(seconds, nanos));
    nix::time::clock_settime(ClockId::CLOCK_REALTIME, target).map_err(ClockSyncError::Set)?;
    tracing::info!(
        offset_ms = offset_nanos / 1_000_000,
        "stepped realtime clock to host time"
    );
    Ok(ClockSyncOutcome {
        offset_nanos,
        stepped: true,
    })
}

pub(crate) fn offset_duration(offset_nanos: i128) -> prost_types::Duration {
    let seconds = offset_nanos / NANOS_PER_SECOND;
    let nanos = offset_nanos % NANOS_PER_SECOND;
    let seconds = i64::try_from(seconds).unwrap_or(if seconds < 0 { i64::MIN } else { i64::MAX });
    // |nanos| < 1e9 always fits in i32; the fallback is unreachable.
    let nanos = i32::try_from(nanos).unwrap_or(0);
    prost_types::Duration { seconds, nanos }
}

fn host_nanos(host_time: Option<&prost_types::Timestamp>) -> Result<i128, ClockSyncError> {
    let host_time = host_time.ok_or(ClockSyncError::Missing)?;
    if !(0..1_000_000_000).contains(&host_time.nanos) {
        return Err(ClockSyncError::Invalid("nanos out of range"));
    }
    if host_time.seconds < MIN_HOST_UNIX_SECONDS {
        return Err(ClockSyncError::Invalid("before 2024-01-01"));
    }
    Ok(i128::from(host_time.seconds) * NANOS_PER_SECOND + i128::from(host_time.nanos))
}

fn should_step(offset_nanos: i128) -> bool {
    offset_nanos.abs() > STEP_THRESHOLD_NANOS
}

#[cfg(test)]
mod tests {
    use crate::clock::{
        host_nanos, offset_duration, should_step, ClockSyncError, MIN_HOST_UNIX_SECONDS,
        STEP_THRESHOLD_NANOS,
    };

    #[test]
    fn steps_only_beyond_threshold() {
        assert!(!should_step(0));
        assert!(!should_step(STEP_THRESHOLD_NANOS));
        assert!(!should_step(-STEP_THRESHOLD_NANOS));
        assert!(should_step(STEP_THRESHOLD_NANOS + 1));
        assert!(should_step(-(STEP_THRESHOLD_NANOS + 1)));
    }

    #[test]
    fn host_time_is_validated() {
        assert!(matches!(host_nanos(None), Err(ClockSyncError::Missing)));
        for nanos in [-1, 1_000_000_000] {
            let time = prost_types::Timestamp {
                seconds: MIN_HOST_UNIX_SECONDS,
                nanos,
            };
            assert!(matches!(
                host_nanos(Some(&time)),
                Err(ClockSyncError::Invalid("nanos out of range"))
            ));
        }
        let too_old = prost_types::Timestamp {
            seconds: MIN_HOST_UNIX_SECONDS - 1,
            nanos: 0,
        };
        assert!(matches!(
            host_nanos(Some(&too_old)),
            Err(ClockSyncError::Invalid("before 2024-01-01"))
        ));
        let valid = prost_types::Timestamp {
            seconds: MIN_HOST_UNIX_SECONDS,
            nanos: 5,
        };
        assert_eq!(
            host_nanos(Some(&valid)).unwrap(),
            i128::from(MIN_HOST_UNIX_SECONDS) * 1_000_000_000 + 5
        );
    }

    #[test]
    fn offset_duration_keeps_sign_and_saturates() {
        assert_eq!(
            offset_duration(-1_500_000_000),
            prost_types::Duration {
                seconds: -1,
                nanos: -500_000_000
            }
        );
        assert_eq!(
            offset_duration(1_500_000_000),
            prost_types::Duration {
                seconds: 1,
                nanos: 500_000_000
            }
        );
        assert_eq!(offset_duration(i128::MAX).seconds, i64::MAX);
        assert_eq!(offset_duration(i128::MIN).seconds, i64::MIN);
    }
}
