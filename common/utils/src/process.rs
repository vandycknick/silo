//! Kernel process birth-time queries shared by native supervisors and controllers.
//!
//! Every caller (machine runtime state, netd helper generations, daemon status
//! identity) persists and compares this value, and user-facing surfaces render it
//! as a date. It is therefore always whole Unix seconds, on every platform.
use std::io;

/// Returns the process birth time as whole Unix seconds, or absence for an
/// exited or zombie process.
///
/// Second precision still distinguishes a reused PID: the kernel hands out PIDs
/// sequentially, so the same PID cannot be recycled within the same second.
#[cfg(target_os = "macos")]
pub fn start_time(pid: i32) -> io::Result<Option<i64>> {
    if pid <= 0 {
        return Ok(None);
    }
    const PROC_PIDTBSDINFO: libc::c_int = 3;
    // Darwin's BSD SZOMB state.
    const SZOMB: u32 = 5;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: libc::uid_t,
        pbi_gid: libc::gid_t,
        pbi_ruid: libc::uid_t,
        pbi_rgid: libc::gid_t,
        pbi_svuid: libc::uid_t,
        pbi_svgid: libc::gid_t,
        rfu_1: u32,
        pbi_comm: [libc::c_char; 16],
        pbi_name: [libc::c_char; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    // nix does not expose this Darwin process birth-time query. Kernel birth
    // times prevent a reused PID from adopting another process's identity.
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
    let size = std::mem::size_of::<ProcBsdInfo>();
    let result = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if result == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(err);
    }
    if result < size as libc::c_int {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short proc_pidinfo response; process identity is unavailable",
        ));
    }

    let info = unsafe { info.assume_init() };
    if info.pbi_status == SZOMB {
        return Ok(None);
    }
    // The kernel stamps the wall-clock birth time once at fork, so this is
    // already Unix seconds and never drifts for a live process.
    i64::try_from(info.pbi_start_tvsec).map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process start seconds overflow i64",
        )
    })
}

/// Returns the process birth time as whole Unix seconds, or absence for an
/// exited or zombie process.
///
/// Linux records birth as clock ticks since boot (`/proc/<pid>/stat` field 22),
/// so this adds the boot time from `/proc/stat`. The kernel derives `btime` from
/// the current wall clock, so a wall-clock step (not an NTP slew) shifts the
/// result for processes that were already running.
///
/// Second precision still distinguishes a reused PID: the kernel hands out PIDs
/// sequentially, so the same PID cannot be recycled within the same second.
#[cfg(target_os = "linux")]
pub fn start_time(pid: i32) -> io::Result<Option<i64>> {
    if pid <= 0 {
        return Ok(None);
    }
    let Some(ticks) = start_ticks(pid)? else {
        return Ok(None);
    };
    let ticks_per_second = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .map_err(io::Error::from)?
        .filter(|ticks| *ticks > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid CLK_TCK"))?;
    boot_time()?
        .checked_add(ticks / ticks_per_second)
        .map(Some)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process start time overflow"))
}

#[cfg(target_os = "linux")]
fn start_ticks(pid: i32) -> io::Result<Option<i64>> {
    let path = format!("/proc/{pid}/stat");
    let stat = match std::fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        // The process can exit between open and read.
        Err(err) if err.raw_os_error() == Some(nix::errno::Errno::ESRCH as i32) => return Ok(None),
        Err(err) => return Err(err),
    };
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, format!("invalid {path}"));
    // The command name may contain spaces and parentheses; fields resume after
    // the last `)`. State is field 3 and start time is field 22.
    let (_, fields) = stat.rsplit_once(") ").ok_or_else(invalid)?;
    let mut fields = fields.split_whitespace();
    if matches!(fields.next(), Some("Z" | "X")) {
        return Ok(None);
    }
    fields
        .nth(18)
        .and_then(|ticks| ticks.parse::<i64>().ok())
        .map(Some)
        .ok_or_else(invalid)
}

#[cfg(target_os = "linux")]
fn boot_time() -> io::Result<i64> {
    std::fs::read_to_string("/proc/stat")?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|seconds| seconds.trim().parse::<i64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing btime in /proc/stat"))
}

#[cfg(test)]
mod tests {
    use crate::process::start_time;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unix_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs() as i64
    }

    fn spawn_sleeper() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep")
    }

    #[test]
    fn start_time_is_unix_seconds_of_the_spawn() {
        let before = unix_now();
        let mut child = spawn_sleeper();
        let after = unix_now();

        let started = start_time(child.id() as i32)
            .expect("read start time")
            .expect("live child");
        child.kill().expect("kill child");
        child.wait().expect("reap child");

        // Linux sums two floored values (btime and ticks / CLK_TCK), which can
        // land one second below the true floor.
        assert!(
            (before - 1..=after).contains(&started),
            "start time {started} is not Unix seconds within [{before}, {after}]"
        );
    }

    #[test]
    fn start_time_is_stable_for_a_live_process() {
        let pid = std::process::id() as i32;
        let first = start_time(pid).expect("read").expect("own process is live");
        let second = start_time(pid).expect("read").expect("own process is live");
        assert_eq!(first, second);
        assert!(first <= unix_now());
    }

    #[test]
    fn start_time_distinguishes_separately_started_processes() {
        let mut older = spawn_sleeper();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let mut newer = spawn_sleeper();

        let older_start = start_time(older.id() as i32).expect("read").expect("live");
        let newer_start = start_time(newer.id() as i32).expect("read").expect("live");
        for child in [&mut older, &mut newer] {
            child.kill().expect("kill child");
            child.wait().expect("reap child");
        }

        assert!(newer_start > older_start);
    }

    #[test]
    fn start_time_is_absent_for_zombies() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id() as i32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        // The unreaped child turns into a zombie once it exits.
        while start_time(pid).expect("read").is_some() {
            assert!(std::time::Instant::now() < deadline, "child never exited");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.wait().expect("reap child");
        assert_eq!(start_time(pid).expect("read reaped"), None);
    }

    #[test]
    fn start_time_is_absent_for_missing_and_invalid_pids() {
        assert_eq!(start_time(i32::MAX).expect("missing"), None);
        assert_eq!(start_time(0).expect("zero"), None);
        assert_eq!(start_time(-1).expect("negative"), None);
    }
}
