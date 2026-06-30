use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct IdentifierPolicy<'a> {
    pub(crate) reserved: &'a [&'a str],
}

pub(crate) fn validate_identifier(name: &str, policy: IdentifierPolicy<'_>) -> Result<(), String> {
    if name.is_empty() {
        return Err("name cannot be empty".to_string());
    }

    if name.starts_with('-') {
        return Err("name cannot start with '-'".to_string());
    }

    if policy.reserved.contains(&name) {
        return Err(format!("{name:?} is reserved"));
    }

    if let Some(ch) = name
        .chars()
        .find(|ch| !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.'))
    {
        return Err(format!("unsupported character {ch:?}"));
    }

    Ok(())
}

/// Returns the current Unix timestamp in seconds.
///
/// libvm stores persistence timestamps as signed SQLite integers. If the host
/// clock is before the Unix epoch, this returns `0` instead of panicking. The
/// result is also clamped to `i64::MAX` before conversion so callers can bind it
/// directly into integer timestamp columns.
pub(crate) fn now_unix() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    seconds.min(i64::MAX as u64) as i64
}
