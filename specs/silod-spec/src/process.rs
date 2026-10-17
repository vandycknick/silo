//! Process identity recorded in [`crate::status::DaemonStatus::process_start`], so a
//! reader can tell the publishing process from a later one that reused its PID.

/// The kernel start time of `pid` as Unix seconds, or `None` when no such
/// process is live.
pub fn start_time(pid: u32) -> std::io::Result<Option<String>> {
    let Ok(pid) = i32::try_from(pid) else {
        return Ok(None);
    };
    utils::process::start_time(pid).map(|value| value.map(|time| time.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::process::start_time;

    #[test]
    fn start_time_identifies_live_processes_only() {
        let own = start_time(std::process::id()).expect("read");
        assert!(own.is_some());
        assert_eq!(start_time(std::process::id()).expect("read"), own);
        assert_eq!(start_time(u32::MAX).expect("missing"), None);
    }
}
