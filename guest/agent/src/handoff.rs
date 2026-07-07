use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use eyre::Context;
use nix::sys::signal::{self, SigHandler, SigSet, SigmaskHow, Signal};
use nix::unistd::{execv, fork, setsid, ForkResult};
use protocol::v1::{GuestBootMode, GuestBootReport};

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
    },
}

impl BootMode {
    pub(crate) fn report(&self) -> GuestBootReport {
        let agent_pid = std::process::id();
        match self {
            Self::Standard => GuestBootReport {
                mode: GuestBootMode::Standard as i32,
                requested_init: String::new(),
                handoff_init_path: String::new(),
                probed_init_paths: Vec::new(),
                agent_path: current_agent_path(),
                agent_pid,
                agent_is_pid1: agent_pid == 1,
                message: String::from("agent started in standard mode"),
            },
            Self::AgentPid1 { requested_init } => GuestBootReport {
                mode: GuestBootMode::AgentPid1 as i32,
                requested_init: os_to_string(requested_init),
                handoff_init_path: String::new(),
                probed_init_paths: probed_init_paths(requested_init),
                agent_path: current_agent_path(),
                agent_pid,
                agent_is_pid1: agent_pid == 1,
                message: String::from("no executable init found; agent remains PID 1"),
            },
            Self::InitChild {
                requested_init,
                init_path,
            } => GuestBootReport {
                mode: GuestBootMode::InitChild as i32,
                requested_init: os_to_string(requested_init),
                handoff_init_path: init_path.display().to_string(),
                probed_init_paths: probed_init_paths(requested_init),
                agent_path: current_agent_path(),
                agent_pid,
                agent_is_pid1: agent_pid == 1,
                message: String::from("agent handed PID 1 to guest init"),
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

pub(crate) fn maybe_handoff_init(requested_init: &OsStr) -> eyre::Result<BootMode> {
    let Some(target) = resolve_handoff_target(requested_init)? else {
        tracing::info!(
            requested_init = ?requested_init,
            "no executable init found; staying in agent PID1 mode"
        );
        return Ok(BootMode::AgentPid1 {
            requested_init: requested_init.to_os_string(),
        });
    };

    fork_handoff_init(requested_init, &target)
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

fn fork_handoff_init(requested_init: &OsStr, target: &Path) -> eyre::Result<BootMode> {
    let init = CString::new(target.as_os_str().as_bytes())
        .with_context(|| format!("prepare init path {}", target.display()))?;

    // Fork before constructing the Tokio runtime so the child does not inherit
    // async runtime internals. PID 1 becomes the guest init; the child remains
    // the Silo agent.
    match unsafe { fork() }.context("fork init handoff")? {
        ForkResult::Parent { .. } => exec_handoff_parent(&init, target),
        ForkResult::Child => {
            if let Err(err) = setsid() {
                tracing::warn!(error = %err, "failed to isolate agent child session");
            }
            tracing::info!(init = %target.display(), "continuing as agent after init handoff");
            Ok(BootMode::InitChild {
                requested_init: requested_init.to_os_string(),
                init_path: target.to_path_buf(),
            })
        }
    }
}

fn exec_handoff_parent(init: &std::ffi::CStr, target: &Path) -> eyre::Result<BootMode> {
    reset_handoff_exec_state();
    if let Err(err) = std::env::set_current_dir("/") {
        tracing::error!(error = %err, "failed to chdir before init handoff exec");
        std::process::exit(127);
    }

    let argv = [init];
    match execv(init, &argv) {
        Ok(_) => unreachable!("execv returned after replacing the process"),
        Err(err) => {
            tracing::error!(init = %target.display(), error = %err, "failed to exec handoff init");
            std::process::exit(127);
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

        assert_eq!(report.mode, GuestBootMode::AgentPid1 as i32);
        assert_eq!(report.requested_init, HANDOFF_AUTO);
        assert_eq!(
            report.probed_init_paths,
            HANDOFF_AUTO_CANDIDATES
                .iter()
                .map(|candidate| (*candidate).to_string())
                .collect::<Vec<_>>()
        );
        assert!(!report.probed_init_paths.iter().any(|path| path == "/init"));
        assert!(report.agent_pid > 0);
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
