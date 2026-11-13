//! Fail-closed containment observations through the pre-handoff cgroup and procfs handles.

use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read};

use nix::dir::{Dir, Type};
use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
use tonic::Status;

const PF_KTHREAD: u64 = 0x0020_0000;

pub(crate) fn failure(pid: u32, tid: u32, comm: &str, cgroup: &str, detail: &str) -> Status {
    Status::failed_precondition(format!(
        "guest-containment-escaped: pid {pid} tid {tid} comm {comm:?} cgroup {cgroup:?}: {detail}"
    ))
}

pub(crate) fn check(
    root: &File,
    silo: &File,
    control: &File,
    activation: &File,
    procfs: &File,
    activation_running: bool,
) -> Result<(), Status> {
    let agent = std::process::id();
    let structural =
        |error: io::Error| failure(agent, agent, "silo-agent", "unknown", &error.to_string());
    let own = open_directory(procfs, agent.to_string().as_str()).map_err(structural)?;
    let mounts = read_file(&own, "mountinfo").map_err(structural)?;
    if !has_nsdelegate(&mounts) {
        return Err(failure(
            agent,
            agent,
            "silo-agent",
            "/silo/control",
            "cgroup2 mount lacks nsdelegate",
        ));
    }
    check_children(root, &[c"silo"], "/").map_err(structural)?;
    check_children(silo, &[c"control", c"activation", c"workloads"], "/silo")
        .map_err(structural)?;
    if !activation_running && populated(activation).map_err(structural)? {
        return Err(failure(
            0,
            0,
            "unknown",
            "/silo/activation",
            "activation is populated outside activation",
        ));
    }
    let threads = read_file(control, "cgroup.threads").map_err(structural)?;
    for line in threads.lines() {
        let tid = parse_id(line).ok_or_else(|| {
            failure(
                agent,
                0,
                "unknown",
                "/silo/control",
                "malformed cgroup.threads",
            )
        })?;
        let result = open_directory(procfs, line).and_then(|task| {
            let status = read_file(&task, "status")?;
            let tgid = parse_tgid(&status).map_err(invalid_data)?;
            Ok((task, tgid))
        });
        match result {
            Ok((_, tgid)) if tgid == agent => {}
            Err(error) if vanished(&error) => {}
            Ok((task, tgid)) => {
                let stat = match read_file(&task, "stat") {
                    Ok(stat) => stat,
                    Err(error) if vanished(&error) => continue,
                    Err(error) => {
                        return Err(failure(
                            tgid,
                            tid,
                            "unknown",
                            "/silo/control",
                            &error.to_string(),
                        ))
                    }
                };
                let stat = parse_stat(&stat)
                    .map_err(|error| failure(tgid, tid, "unknown", "/silo/control", error))?;
                return Err(failure(
                    tgid,
                    tid,
                    stat.comm,
                    "/silo/control",
                    "control thread does not belong to agent",
                ));
            }
            Err(error) => {
                return Err(failure(
                    0,
                    tid,
                    "unknown",
                    "/silo/control",
                    &error.to_string(),
                ))
            }
        }
    }
    let mut processes = directory_entries(procfs).map_err(structural)?;
    for entry in processes.iter() {
        let entry = entry.map_err(io::Error::from).map_err(structural)?;
        let Some(pid) = numeric_name(entry.file_name()) else {
            continue;
        };
        check_process(procfs, entry.file_name(), pid, agent, activation_running)?;
    }
    Ok(())
}

fn check_process(
    procfs: &File,
    name: &CStr,
    pid: u32,
    agent: u32,
    activation_running: bool,
) -> Result<(), Status> {
    let process = match open_directory(procfs, name) {
        Ok(process) => process,
        Err(error) if vanished(&error) => return Ok(()),
        Err(error) => return Err(failure(pid, pid, "unknown", "unknown", &error.to_string())),
    };
    let tasks = match open_directory(&process, "task") {
        Ok(tasks) => tasks,
        Err(error) if vanished(&error) => return Ok(()),
        Err(error) => return Err(failure(pid, pid, "unknown", "unknown", &error.to_string())),
    };
    let mut entries = directory_entries(&tasks)
        .map_err(|error| failure(pid, pid, "unknown", "unknown", &error.to_string()))?;
    for entry in entries.iter() {
        let entry =
            entry.map_err(|error| failure(pid, pid, "unknown", "unknown", &error.to_string()))?;
        let Some(tid) = numeric_name(entry.file_name()) else {
            continue;
        };
        let task = match open_directory(&tasks, entry.file_name()) {
            Ok(task) => task,
            Err(error) if vanished(&error) => continue,
            Err(error) => return Err(failure(pid, tid, "unknown", "unknown", &error.to_string())),
        };
        check_task(&task, pid, tid, agent, activation_running)?;
    }
    Ok(())
}

fn check_task(
    task: &File,
    pid: u32,
    tid: u32,
    agent: u32,
    activation_running: bool,
) -> Result<(), Status> {
    let stat = match read_file(task, "stat") {
        Ok(stat) => stat,
        Err(error) if vanished(&error) => return Ok(()),
        Err(error) => return Err(failure(pid, tid, "unknown", "unknown", &error.to_string())),
    };
    let stat = parse_stat(&stat).map_err(|error| failure(pid, tid, "unknown", "unknown", error))?;
    if stat.tid != tid {
        return Err(failure(
            pid,
            tid,
            stat.comm,
            "unknown",
            "stat task ID mismatch",
        ));
    }
    if stat.flags & PF_KTHREAD != 0 {
        return Ok(());
    }
    let membership = match read_file(task, "cgroup") {
        Ok(membership) => membership,
        Err(error) if vanished(&error) => return Ok(()),
        Err(error) => return Err(failure(pid, tid, stat.comm, "unknown", &error.to_string())),
    };
    let cgroup = parse_cgroup(&membership)
        .map_err(|error| failure(pid, tid, stat.comm, &membership, error))?;
    let agent_thread = if cgroup == "/silo/control" {
        match read_file(task, "status").and_then(|status| parse_tgid(&status).map_err(invalid_data))
        {
            Ok(tgid) => tgid == agent,
            Err(error) if vanished(&error) => return Ok(()),
            Err(error) => return Err(failure(pid, tid, stat.comm, cgroup, &error.to_string())),
        }
    } else {
        false
    };
    if !allowed_cgroup(cgroup, agent_thread, activation_running) {
        return Err(failure(
            pid,
            tid,
            stat.comm,
            cgroup,
            "task is outside managed containment",
        ));
    }
    Ok(())
}

fn check_children(parent: &File, allowed: &[&CStr], parent_name: &str) -> io::Result<()> {
    let mut entries = directory_entries(parent)?;
    for entry in entries.iter() {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name();
        if name == c"." || name == c".." || allowed.contains(&name) {
            continue;
        }
        if entry
            .file_type()
            .is_some_and(|kind| kind != Type::Directory)
        {
            continue;
        }
        let child = match open_directory(parent, name) {
            Ok(child) => child,
            Err(error)
                if vanished(&error)
                    || error.raw_os_error() == Some(nix::errno::Errno::ENOTDIR as i32) =>
            {
                continue
            }
            Err(error) => return Err(error),
        };
        if populated(&child)? {
            return Err(io::Error::other(format!(
                "unexpected populated cgroup {parent_name}/{}",
                name.to_string_lossy()
            )));
        }
    }
    Ok(())
}

fn populated(directory: &File) -> io::Result<bool> {
    crate::freezer::parse_event(&read_file(directory, "cgroup.events")?, "populated")
}

fn has_nsdelegate(mounts: &str) -> bool {
    mounts.lines().any(|line| {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            return false;
        };
        if mount.split_ascii_whitespace().nth(4) != Some("/sys/fs/cgroup") {
            return false;
        }
        let mut fields = filesystem.split_ascii_whitespace();
        fields.next() == Some("cgroup2")
            && fields.next().is_some()
            && fields
                .next()
                .is_some_and(|options| options.split(',').any(|option| option == "nsdelegate"))
    })
}

struct TaskStat<'a> {
    tid: u32,
    comm: &'a str,
    flags: u64,
}

fn parse_stat(stat: &str) -> Result<TaskStat<'_>, &'static str> {
    let (tid, remainder) = stat.split_once(" (").ok_or("malformed task stat comm")?;
    let tid = parse_id(tid).ok_or("malformed task stat ID")?;
    let (comm, fields) = remainder
        .rsplit_once(") ")
        .ok_or("unterminated task stat comm")?;
    let flags = fields
        .split_ascii_whitespace()
        .nth(6)
        .and_then(|value| value.parse().ok())
        .ok_or("malformed task stat flags")?;
    Ok(TaskStat { tid, comm, flags })
}

pub(crate) fn parse_cgroup(membership: &str) -> Result<&str, &'static str> {
    let mut lines = membership.lines();
    let path = lines
        .next()
        .and_then(|line| line.strip_prefix("0::"))
        .ok_or("missing unified cgroup membership")?;
    if lines.next().is_some()
        || !path.starts_with('/')
        || path.contains('\0')
        || (path != "/"
            && path[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."))
    {
        return Err("malformed unified cgroup membership");
    }
    Ok(path)
}

fn parse_tgid(status: &str) -> Result<u32, &'static str> {
    let mut result = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            let value = parse_id(value.trim()).ok_or("malformed task Tgid")?;
            if result.replace(value).is_some() {
                return Err("duplicate task Tgid");
            }
        }
    }
    result.ok_or("missing task Tgid")
}

fn allowed_cgroup(cgroup: &str, agent_thread: bool, activation_running: bool) -> bool {
    under(cgroup, "/silo/workloads")
        || (cgroup == "/silo/control" && agent_thread)
        || (under(cgroup, "/silo/activation") && activation_running)
}

fn under(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn parse_id(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|id| *id != 0)
}

fn numeric_name(name: &CStr) -> Option<u32> {
    parse_id(name.to_str().ok()?)
}

fn vanished(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == nix::errno::Errno::ENOENT as i32 || code == nix::errno::Errno::ESRCH as i32)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn open_directory<F: std::os::fd::AsFd, P: ?Sized + nix::NixPath>(
    parent: F,
    path: &P,
) -> io::Result<File> {
    openat2(
        parent,
        path,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_NO_XDEV | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map(File::from)
    .map_err(io::Error::from)
}

fn directory_entries<F: std::os::fd::AsFd>(parent: F) -> io::Result<Dir> {
    let directory = open_directory(parent, c".")?;
    Dir::from_fd(directory.into()).map_err(io::Error::from)
}

pub(crate) fn read_file(parent: &File, name: &str) -> io::Result<String> {
    let fd = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_NO_XDEV | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(io::Error::from)?;
    let mut text = String::new();
    File::from(fd).read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use crate::containment::{
        allowed_cgroup, has_nsdelegate, parse_cgroup, parse_id, parse_stat, parse_tgid, vanished,
        PF_KTHREAD,
    };

    #[test]
    fn stat_parser_handles_spaces_and_parentheses_in_comm() {
        let stat = parse_stat("42 (a tricky ) (name)) S 1 2 3 4 5 2097152 7 8\n").unwrap();
        assert_eq!(stat.tid, 42);
        assert_eq!(stat.comm, "a tricky ) (name)");
        assert_eq!(stat.flags & PF_KTHREAD, PF_KTHREAD);
        assert_eq!(parse_stat("9 (user) R 1 2 3 4 5 0").unwrap().flags, 0);
        for invalid in [
            "",
            "42",
            "42 (unterminated",
            "42 (name) S 1",
            "0 (name) S 1 2 3 4 5 0",
            "42 (name) S 1 2 3 4 5 nope",
        ] {
            assert!(parse_stat(invalid).is_err());
        }
    }

    #[test]
    fn unified_membership_requires_one_absolute_canonical_path() {
        for path in ["/", "/silo/control", "/silo/workloads/image/init.scope"] {
            assert_eq!(parse_cgroup(&format!("0::{path}\n")), Ok(path));
        }
        for invalid in [
            "",
            "1:memory:/silo/control",
            "0::relative",
            "0::/a\n0::/b",
            "0::/a/../control",
            "0::/a/./b",
            "0::/a//b",
            "0::/a/",
        ] {
            assert!(parse_cgroup(invalid).is_err());
        }
    }

    #[test]
    fn admission_respects_subtree_boundaries_and_agent_tgid() {
        for path in [
            "/silo/workloads",
            "/silo/workloads/image",
            "/silo/workloads/exec/session",
        ] {
            assert!(allowed_cgroup(path, false, false));
        }
        for path in [
            "/",
            "/silo",
            "/silo/workloads-other",
            "/silo/control/child",
            "/silo/activation-other",
        ] {
            assert!(!allowed_cgroup(path, true, true));
        }
        assert!(allowed_cgroup("/silo/control", true, false));
        assert!(!allowed_cgroup("/silo/control", false, false));
        for path in ["/silo/activation", "/silo/activation/child"] {
            assert!(allowed_cgroup(path, false, true));
            assert!(!allowed_cgroup(path, false, false));
        }
    }

    #[test]
    fn mount_parser_requires_exact_super_option_on_cgroup2_mount() {
        let prefix = "33 22 0:22 /silo/workloads/image /sys/fs/cgroup rw shared:7 - ";
        assert!(has_nsdelegate(&format!(
            "{prefix}cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n"
        )));
        for suffix in [
            "cgroup2 cgroup2 rw",
            "cgroup2 cgroup2 rw,nsdelegate-other",
            "tmpfs tmpfs rw,nsdelegate",
            "cgroup2 cgroup2",
        ] {
            assert!(!has_nsdelegate(&format!("{prefix}{suffix}")));
        }
        assert!(!has_nsdelegate("invalid"));
    }

    #[test]
    fn tgid_and_numeric_ids_reject_ambiguity() {
        assert_eq!(
            parse_tgid("Name:\tsilo-agent\nTgid:\t42\nPid:\t43\n"),
            Ok(42)
        );
        for invalid in ["", "Tgid:\t0", "Tgid:\t42 extra", "Tgid:\t42\nTgid:\t42"] {
            assert!(parse_tgid(invalid).is_err());
        }
        for invalid in ["", "0", "+1", "-1", "1x", "4294967296"] {
            assert_eq!(parse_id(invalid), None);
        }
    }

    #[test]
    fn only_disappearing_tasks_are_ignored() {
        for code in [nix::errno::Errno::ENOENT, nix::errno::Errno::ESRCH] {
            assert!(vanished(&std::io::Error::from_raw_os_error(code as i32)));
        }
        for code in [
            nix::errno::Errno::EXDEV,
            nix::errno::Errno::EACCES,
            nix::errno::Errno::ELOOP,
        ] {
            assert!(!vanished(&std::io::Error::from_raw_os_error(code as i32)));
        }
        let status = crate::containment::failure(12, 13, "escaped", "/", "outside workloads");
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status
            .message()
            .starts_with("guest-containment-escaped: pid 12 tid 13 comm"));
    }
}
