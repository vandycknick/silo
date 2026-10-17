use libvm::LibVmError;

/// Persisted libvm timestamps are seconds; the Go bridge wire contract is milliseconds.
pub(crate) fn unix_ms(seconds: i64, field: &str) -> Result<i64, LibVmError> {
    seconds
        .checked_mul(1000)
        .ok_or_else(|| LibVmError::InvalidCreateRequest {
            name: "timestamp".to_string(),
            reason: format!("{field}: Unix seconds {seconds} overflow signed milliseconds"),
        })
}

pub(crate) fn optional_unix_ms(
    seconds: Option<i64>,
    field: &str,
) -> Result<Option<i64>, LibVmError> {
    seconds.map(|seconds| unix_ms(seconds, field)).transpose()
}

#[cfg(test)]
mod tests {
    use crate::timestamps::{optional_unix_ms, unix_ms};

    #[test]
    fn converts_seconds_with_checked_signed_bounds() {
        for seconds in [0, -1, 1_791_072_000, i64::MIN / 1000, i64::MAX / 1000] {
            assert_eq!(unix_ms(seconds, "created_at").unwrap(), seconds * 1000);
        }
        for seconds in [i64::MIN, i64::MAX, i64::MIN / 1000 - 1, i64::MAX / 1000 + 1] {
            let error = unix_ms(seconds, "created_at").unwrap_err();
            assert_eq!(error.variant(), "InvalidCreateRequest");
            assert!(error.to_string().contains("created_at"));
        }
        assert_eq!(optional_unix_ms(None, "started_at").unwrap(), None);
        assert_eq!(optional_unix_ms(Some(0), "started_at").unwrap(), Some(0));
        assert!(optional_unix_ms(Some(i64::MAX), "started_at").is_err());
    }
}
