use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eyre::Context;
use nix::fcntl::OFlag;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::signal::{self, SigHandler, SigSet, SigmaskHow, Signal};
use nix::unistd::{execv, fork, pipe2, setsid, ForkResult};
use protocol::v1::{GuestBootMode, GuestBootReport};

use crate::freezer::WorkloadController;

const HANDOFF_AUTO: &str = "auto";
pub(crate) const HANDOFF_AUTO_CANDIDATES: &[&str] = &[
    "/sbin/init",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
];
pub(crate) const AGENT_RUN_BINARY: &str = "/run/agent/silo-agent";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BootMode {
    Standard,
    AgentPid1 {
        requested_init: OsString,
    },
    InitChild {
        requested_init: OsString,
        init_path: PathBuf,
        containment_failure: String,
    },
    ContainedInit {
        requested_init: OsString,
        init_path: PathBuf,
    },
}

impl BootMode {
    pub(crate) fn report(&self) -> GuestBootReport {
        let agent_pid = std::process::id();
        match self {
            Self::Standard => GuestBootReport {
                mode: Some(GuestBootMode::Standard as i32),
                requested_init: None,
                handoff_init_path: None,
                probed_init_paths: Vec::new(),
                agent_path: Some(current_agent_path()),
                agent_pid: Some(agent_pid),
                agent_is_pid1: Some(agent_pid == 1),
                message: Some(String::from("agent started in standard mode")),
            },
            Self::AgentPid1 { requested_init } => GuestBootReport {
                mode: Some(GuestBootMode::AgentPid1 as i32),
                requested_init: Some(os_to_string(requested_init)),
                handoff_init_path: None,
                probed_init_paths: probed_init_paths(requested_init),
                agent_path: Some(current_agent_path()),
                agent_pid: Some(agent_pid),
                agent_is_pid1: Some(agent_pid == 1),
                message: Some(String::from(
                    "no executable init found; agent remains PID 1",
                )),
            },
            Self::InitChild {
                requested_init,
                init_path,
                containment_failure,
            } => GuestBootReport {
                mode: Some(GuestBootMode::InitChild as i32),
                requested_init: Some(os_to_string(requested_init)),
                handoff_init_path: Some(init_path.display().to_string()),
                probed_init_paths: probed_init_paths(requested_init),
                agent_path: Some(current_agent_path()),
                agent_pid: Some(agent_pid),
                agent_is_pid1: Some(false),
                message: Some(format!(
                    "agent handed PID 1 to guest init; containment observation failed: {containment_failure}"
                )),
            },
            Self::ContainedInit {
                requested_init,
                init_path,
            } => GuestBootReport {
                mode: Some(GuestBootMode::ContainedInit as i32),
                requested_init: Some(os_to_string(requested_init)),
                handoff_init_path: Some(init_path.display().to_string()),
                probed_init_paths: probed_init_paths(requested_init),
                agent_path: Some(current_agent_path()),
                agent_pid: Some(agent_pid),
                agent_is_pid1: Some(false),
                message: Some(String::from("agent handed PID 1 to a contained guest init")),
            },
        }
    }
}

fn current_agent_path() -> String {
    std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| String::from(AGENT_RUN_BINARY))
}

fn probed_init_paths(requested_init: &OsStr) -> Vec<String> {
    if requested_init == OsStr::new(HANDOFF_AUTO) {
        return HANDOFF_AUTO_CANDIDATES
            .iter()
            .map(|candidate| (*candidate).to_string())
            .collect();
    }

    if requested_init.is_empty() {
        Vec::new()
    } else {
        vec![os_to_string(requested_init)]
    }
}

fn os_to_string(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

pub(crate) fn maybe_handoff_init(
    requested_init: &OsStr,
    workloads: &WorkloadController,
) -> eyre::Result<BootMode> {
    let Some(target) = resolve_handoff_target(requested_init)? else {
        tracing::info!(
            requested_init = ?requested_init,
            "no executable init found; staying in agent PID1 mode"
        );
        return Ok(BootMode::AgentPid1 {
            requested_init: requested_init.to_os_string(),
        });
    };

    fork_handoff_init(requested_init, &target, workloads)
}

fn resolve_handoff_target(requested_init: &OsStr) -> eyre::Result<Option<PathBuf>> {
    let candidates: Vec<&Path> = HANDOFF_AUTO_CANDIDATES.iter().map(Path::new).collect();
    resolve_handoff_target_with_candidates(requested_init, &candidates, Path::new(AGENT_RUN_BINARY))
}

fn resolve_handoff_target_with_candidates(
    requested_init: &OsStr,
    candidates: &[&Path],
    agent_path: &Path,
) -> eyre::Result<Option<PathBuf>> {
    if requested_init == OsStr::new(HANDOFF_AUTO) {
        for candidate in candidates {
            if init_candidate_is_executable_file(candidate, agent_path)? {
                return Ok(Some((*candidate).to_path_buf()));
            }
        }
        return Ok(None);
    }

    if requested_init.is_empty() {
        return Ok(None);
    }

    let path = PathBuf::from(requested_init);
    if init_candidate_is_executable_file(&path, agent_path)? {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

fn init_candidate_is_executable_file(path: &Path, agent_path: &Path) -> eyre::Result<bool> {
    if is_agent_binary(path, agent_path) {
        return Ok(false);
    }

    match fs::metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            Ok(metadata.file_type().is_file() && mode & 0o111 != 0)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("stat init candidate {}", path.display())),
    }
}

fn is_agent_binary(path: &Path, agent_path: &Path) -> bool {
    if path == agent_path {
        return true;
    }

    match (fs::canonicalize(path), fs::canonicalize(agent_path)) {
        (Ok(path), Ok(agent)) => path == agent,
        _ => false,
    }
}

fn fork_handoff_init(
    requested_init: &OsStr,
    target: &Path,
    workloads: &WorkloadController,
) -> eyre::Result<BootMode> {
    let init = CString::new(target.as_os_str().as_bytes())
        .with_context(|| format!("prepare init path {}", target.display()))?;
    let (reader, writer) = pipe2(OFlag::O_CLOEXEC).context("create init handoff status pipe")?;

    // Fork before constructing the Tokio runtime so the child does not inherit
    // async runtime internals. PID 1 becomes the guest init; the child remains
    // the Silo agent.
    match unsafe { fork() }.context("fork init handoff")? {
        ForkResult::Parent { .. } => {
            drop(reader);
            let result = contain_handoff_parent(workloads);
            if let Err(error) = &result {
                tracing::error!(%error, "image init containment failed; retaining cold boot");
            }
            let status = [u8::from(result.is_err())];
            loop {
                match nix::unistd::write(&writer, &status) {
                    Ok(1) => break,
                    Err(nix::errno::Errno::EINTR) => continue,
                    result => {
                        tracing::error!(?result, "failed to report image init containment");
                        break;
                    }
                }
            }
            exec_handoff_parent(&init, target, writer)
        }
        ForkResult::Child => {
            if let Err(error) = fs::write("/proc/self/oom_score_adj", b"-1000") {
                tracing::warn!(%error, "failed to protect agent child from OOM killer");
            }
            if let Err(error) = nix::sys::prctl::set_dumpable(false) {
                tracing::warn!(%error, "failed to make agent child non-dumpable");
            }
            drop(writer);
            if let Err(err) = setsid() {
                tracing::warn!(error = %err, "failed to isolate agent child session");
            }
            match observe_handoff(&reader) {
                Ok(()) => Ok(BootMode::ContainedInit {
                    requested_init: requested_init.to_os_string(),
                    init_path: target.to_path_buf(),
                }),
                Err(containment_failure) => {
                    tracing::warn!(%containment_failure, "image init containment not established");
                    Ok(BootMode::InitChild {
                        requested_init: requested_init.to_os_string(),
                        init_path: target.to_path_buf(),
                        containment_failure,
                    })
                }
            }
        }
    }
}

fn contain_handoff_parent(workloads: &WorkloadController) -> eyre::Result<()> {
    workloads
        .place_handoff_parent()
        .context("place image PID 1")?;
    unshare(CloneFlags::CLONE_NEWCGROUP).context("unshare image cgroup namespace")?;
    umount2("/sys/fs/cgroup", MntFlags::MNT_DETACH).context("detach initial cgroup mount")?;
    mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount image cgroup namespace")
}

fn read_handoff_status(reader: &OwnedFd) -> io::Result<u8> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut status = None;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "handoff status/EOF deadline",
            ));
        }
        let mut descriptors = [PollFd::new(reader.as_fd(), PollFlags::POLLIN)];
        match poll(&mut descriptors, 10_u16) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
            Ok(_) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
        let mut byte = [0_u8; 1];
        match nix::unistd::read(reader, &mut byte) {
            Ok(0) => {
                return status.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "handoff status missing")
                })
            }
            Ok(_) if status.is_none() => status = Some(byte[0]),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extra handoff status",
                ))
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

fn observe_handoff(reader: &OwnedFd) -> Result<(), String> {
    let status = read_handoff_status(reader).map_err(|error| format!("status pipe: {error}"))?;
    let image_namespace = fs::read_link("/proc/1/ns/cgroup")
        .map_err(|error| format!("PID 1 cgroup namespace: {error}"))?;
    let agent_namespace = fs::read_link("/proc/self/ns/cgroup")
        .map_err(|error| format!("agent cgroup namespace: {error}"))?;
    let membership = fs::read_to_string("/proc/1/cgroup")
        .map_err(|error| format!("PID 1 cgroup membership: {error}"))?;
    let mounts = fs::read_to_string("/proc/1/mountinfo")
        .map_err(|error| format!("PID 1 cgroup mount: {error}"))?;
    qualify_handoff(
        status,
        image_namespace != agent_namespace,
        &membership,
        &mounts,
    )
    .map_err(str::to_owned)
}

fn qualify_handoff(
    status: u8,
    distinct_namespace: bool,
    membership: &str,
    mounts: &str,
) -> Result<(), &'static str> {
    if status != 0 {
        return Err("parent reported cgroup setup failure");
    }
    if !distinct_namespace {
        return Err("PID 1 shares the agent cgroup namespace");
    }
    if crate::containment::parse_cgroup(membership) != Ok("/silo/workloads/image") {
        return Err("PID 1 is not in /silo/workloads/image");
    }
    if cgroup_mount_root(mounts) != Some("/silo/workloads/image") {
        return Err("PID 1 cgroup2 mount root is not /silo/workloads/image");
    }
    Ok(())
}

fn cgroup_mount_root(mounts: &str) -> Option<&str> {
    let mut root = None;
    for line in mounts.lines() {
        let (mount, filesystem) = line.split_once(" - ")?;
        let mut fields = mount.split_ascii_whitespace();
        let candidate = fields.nth(3)?;
        if fields.next()? != "/sys/fs/cgroup" {
            continue;
        }
        if filesystem.split_ascii_whitespace().next()? != "cgroup2" || root.is_some() {
            return None;
        }
        root = Some(candidate);
    }
    root
}

fn exec_handoff_parent(
    init: &std::ffi::CStr,
    target: &Path,
    writer: OwnedFd,
) -> eyre::Result<BootMode> {
    reset_handoff_exec_state();
    if let Err(err) = std::env::set_current_dir("/") {
        tracing::error!(error = %err, "failed to chdir before init handoff exec");
    }

    // nix has no close_range wrapper. PID 1 must not retain agent cgroup/proc handles.
    if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } < 0 {
        tracing::error!(error = %io::Error::last_os_error(), "failed to close inherited init descriptors");
        drop(writer);
    } else {
        // close_range consumed this descriptor along with all other agent handles.
        std::mem::forget(writer);
    }
    let argv = [init];
    loop {
        match execv(init, &argv) {
            Ok(never) => match never {},
            Err(error) => {
                tracing::error!(init = %target.display(), %error, "failed to exec handoff init");
                // Exiting PID 1 panics the kernel; keep it alive if exec becomes unavailable.
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn reset_handoff_exec_state() {
    for signal in Signal::iterator().filter(|signal| should_reset_signal(*signal)) {
        let _ = unsafe { signal::signal(signal, SigHandler::SigDfl) };
    }

    let empty = SigSet::empty();
    let _ = signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&empty), None);
}

fn should_reset_signal(signal: Signal) -> bool {
    !matches!(signal, Signal::SIGKILL | Signal::SIGSTOP)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use nix::sys::signal::Signal;
    use protocol::v1::GuestBootMode;

    use crate::handoff::{
        init_candidate_is_executable_file, resolve_handoff_target_with_candidates,
        should_reset_signal, HANDOFF_AUTO, HANDOFF_AUTO_CANDIDATES,
    };

    static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn auto_handoff_candidates_do_not_include_init() {
        assert_eq!(
            HANDOFF_AUTO_CANDIDATES,
            [
                "/sbin/init",
                "/lib/systemd/systemd",
                "/usr/lib/systemd/systemd"
            ]
        );
    }

    #[test]
    fn agent_pid1_boot_report_includes_auto_probe_paths() {
        let report = crate::handoff::BootMode::AgentPid1 {
            requested_init: OsStr::new(HANDOFF_AUTO).to_os_string(),
        }
        .report();

        assert_eq!(report.mode, Some(GuestBootMode::AgentPid1 as i32));
        assert_eq!(report.requested_init.as_deref(), Some(HANDOFF_AUTO));
        assert_eq!(
            report.probed_init_paths,
            HANDOFF_AUTO_CANDIDATES
                .iter()
                .map(|candidate| (*candidate).to_string())
                .collect::<Vec<_>>()
        );
        assert!(!report.probed_init_paths.iter().any(|path| path == "/init"));
        assert!(report.agent_pid.unwrap_or_default() > 0);
    }

    #[test]
    fn auto_resolution_uses_first_executable_candidate() {
        let dir = temp_dir("candidate-order");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let first = dir.join("sbin-init");
        let second = dir.join("systemd");
        create_executable_file(&first);
        create_executable_file(&second);

        let target = resolve_with_candidates(
            OsStr::new(HANDOFF_AUTO),
            &[first.as_path(), second.as_path()],
        )
        .expect("resolve handoff target");

        assert_eq!(target, Some(first));
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn auto_resolution_skips_non_executable_and_directory_candidates() {
        let dir = temp_dir("candidate-skip");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let non_executable = dir.join("not-executable");
        fs::write(&non_executable, b"").expect("write candidate");
        fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o644))
            .expect("set candidate permissions");
        let directory = dir.join("directory");
        fs::create_dir(&directory).expect("create candidate directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
            .expect("set directory permissions");
        let executable = dir.join("executable");
        create_executable_file(&executable);

        let target = resolve_with_candidates(
            OsStr::new(HANDOFF_AUTO),
            &[
                non_executable.as_path(),
                directory.as_path(),
                executable.as_path(),
            ],
        )
        .expect("resolve handoff target");

        assert_eq!(target, Some(executable));
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn explicit_init_path_can_resolve_outside_auto_candidates() {
        let dir = temp_dir("explicit-init");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let init = dir.join("init");
        create_executable_file(&init);

        let target =
            resolve_with_candidates(init.as_os_str(), &[]).expect("resolve handoff target");

        assert_eq!(target, Some(init));
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn symlink_to_executable_file_is_a_candidate() {
        let dir = temp_dir("candidate-symlink");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let target = dir.join("target-init");
        let link = dir.join("linked-init");
        create_executable_file(&target);
        symlink(&target, &link).expect("create symlink");

        assert!(
            init_candidate_is_executable_file(&link, &dir.join("agent")).expect("stat candidate")
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn candidate_resolving_to_agent_binary_is_skipped() {
        let dir = temp_dir("candidate-agent");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let agent = dir.join("silo-agent");
        let candidate = dir.join("init");
        create_executable_file(&agent);
        symlink(&agent, &candidate).expect("create symlink");

        assert!(!init_candidate_is_executable_file(&candidate, &agent).expect("stat candidate"));
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn reset_signals_excludes_uncatchable_signals() {
        assert!(!should_reset_signal(Signal::SIGKILL));
        assert!(!should_reset_signal(Signal::SIGSTOP));
        assert!(should_reset_signal(Signal::SIGTERM));
        assert!(should_reset_signal(Signal::SIGCHLD));
    }

    #[test]
    fn handoff_qualification_requires_every_observation() {
        let mounts =
            "33 22 0:22 /silo/workloads/image /sys/fs/cgroup rw - cgroup2 cgroup2 rw,nsdelegate\n";
        let membership = "0::/silo/workloads/image\n";
        assert_eq!(
            crate::handoff::qualify_handoff(0, true, membership, mounts),
            Ok(())
        );
        assert!(crate::handoff::qualify_handoff(1, true, membership, mounts).is_err());
        assert!(crate::handoff::qualify_handoff(0, false, membership, mounts).is_err());
        for invalid in ["", "0::/\n", "0::/silo/workloads/image/child\n"] {
            assert!(crate::handoff::qualify_handoff(0, true, invalid, mounts).is_err());
        }
        for invalid in [
            "",
            "invalid",
            "33 22 0:22 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            "33 22 0:22 /silo/workloads/image /sys/fs/cgroup rw - tmpfs tmpfs rw\n",
        ] {
            assert!(crate::handoff::qualify_handoff(0, true, membership, invalid).is_err());
        }
        assert_eq!(
            crate::handoff::cgroup_mount_root(&format!("{mounts}{mounts}")),
            None
        );
    }

    #[test]
    fn contained_boot_report_is_not_agent_pid1() {
        let report = crate::handoff::BootMode::ContainedInit {
            requested_init: OsStr::new("/sbin/init").to_owned(),
            init_path: "/sbin/init".into(),
        }
        .report();
        assert_eq!(report.mode, Some(GuestBootMode::ContainedInit as i32));
        assert_eq!(report.agent_is_pid1, Some(false));
        assert_eq!(
            report.message.as_deref(),
            Some("agent handed PID 1 to a contained guest init")
        );
    }

    #[test]
    fn failed_handoff_report_names_the_observation() {
        let report = crate::handoff::BootMode::InitChild {
            requested_init: OsStr::new("/sbin/init").to_owned(),
            init_path: "/sbin/init".into(),
            containment_failure: "PID 1 shares the agent cgroup namespace".to_owned(),
        }
        .report();
        assert_eq!(report.mode, Some(GuestBootMode::InitChild as i32));
        assert!(report
            .message
            .unwrap()
            .contains("PID 1 shares the agent cgroup namespace"));
    }

    #[test]
    fn handoff_pipe_requires_one_status_byte_and_eof() {
        for status in [0_u8, 1] {
            let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
            nix::unistd::write(&writer, &[status]).unwrap();
            drop(writer);
            assert_eq!(
                crate::handoff::read_handoff_status(&reader).unwrap(),
                status
            );
        }
        let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        drop(writer);
        assert_eq!(
            crate::handoff::read_handoff_status(&reader)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof,
        );
        let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        nix::unistd::write(&writer, &[0, 1]).unwrap();
        drop(writer);
        assert_eq!(
            crate::handoff::read_handoff_status(&reader)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData,
        );
    }

    fn resolve_with_candidates(
        requested_init: &OsStr,
        candidates: &[&Path],
    ) -> eyre::Result<Option<PathBuf>> {
        let agent = temp_dir("agent-path").join("silo-agent");
        resolve_handoff_target_with_candidates(requested_init, candidates, &agent)
    }

    fn create_executable_file(path: &Path) {
        fs::write(path, b"").expect("write executable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("set executable permissions");
    }

    fn temp_dir(name: &str) -> PathBuf {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "silo-agent-{name}-{}-{sequence}",
            std::process::id()
        ))
    }
}
