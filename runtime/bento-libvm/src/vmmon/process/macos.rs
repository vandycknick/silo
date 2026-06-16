use std::io;

use crate::vmmon::process::pid_exists;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pid: i32,
    started_at: Option<i64>,
}

impl ProcessIdentity {
    pub(crate) fn for_pid(pid: i32) -> io::Result<Option<Self>> {
        if pid <= 0 || !pid_exists(pid)? {
            return Ok(None);
        }

        Ok(Some(Self {
            pid,
            started_at: process_started_at(pid)?,
        }))
    }

    pub(crate) fn pid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn started_at(&self) -> Option<i64> {
        self.started_at
    }

    pub(crate) fn matches_started_at(&self, expected: Option<i64>) -> bool {
        expected.is_none() || self.started_at == expected
    }

    pub(crate) fn is_alive(&self) -> io::Result<bool> {
        let Some(current) = Self::for_pid(self.pid)? else {
            return Ok(false);
        };
        Ok(current.matches_started_at(self.started_at))
    }
}

fn process_started_at(pid: i32) -> io::Result<Option<i64>> {
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

    // rustix and nix do not expose a macOS pidfd equivalent or this process
    // birth-time query. We use it only to avoid confusing PID reuse with the
    // vmmon process whose generation libvm persisted.
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
        return Ok(None);
    }

    let info = unsafe { info.assume_init() };
    Ok(Some(info.pbi_start_tvsec as i64))
}
