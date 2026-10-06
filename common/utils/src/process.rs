//! Kernel process birth-time queries shared by native supervisors and controllers.
use std::io;

/// Returns kernel process birth time in microseconds, or absence for an exited process.
pub fn start_time(pid: i32) -> io::Result<Option<i64>> {
    if pid <= 0 {
        return Ok(None);
    }
    const PROC_PIDTBSDINFO: libc::c_int = 3;

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
    // Darwin's BSD SZOMB state. nix does not expose proc_pidinfo/process status.
    if info.pbi_status == 5 {
        return Ok(None);
    }
    let seconds = i64::try_from(info.pbi_start_tvsec).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process start seconds overflow i64",
        )
    })?;
    let micros = i64::try_from(info.pbi_start_tvusec).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process start microseconds overflow i64",
        )
    })?;
    seconds
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(micros))
        .map(Some)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "process start timestamp overflow",
            )
        })
}
