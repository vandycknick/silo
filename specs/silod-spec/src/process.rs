//! Process identity recorded in [`crate::status::DaemonStatus::process_start`], so a
//! reader can tell the publishing process from a later one that reused its PID.

/// The kernel start time of `pid`, or `None` when no such process exists.
#[cfg(target_os = "linux")]
pub fn start_time(pid: u32) -> std::io::Result<Option<String>> {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let invalid = || std::io::Error::other(format!("invalid /proc/{pid}/stat"));
    // The command name may contain spaces and parentheses; fields resume after the
    // last `)`. Start time is field 22, the 20th after the state field.
    let end = stat.rfind(')').ok_or_else(invalid)?;
    let start = stat
        .get(end + 2..)
        .and_then(|fields| fields.split_whitespace().nth(19))
        .ok_or_else(invalid)?;
    Ok(Some(start.to_string()))
}

#[cfg(all(test, target_os = "linux"))]
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
