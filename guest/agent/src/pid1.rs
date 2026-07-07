use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use eyre::Context;
use nix::sys::signal::{self, SigSet, SigmaskHow, Signal as NixSignal};
use rustix::io::Errno;
use rustix::mount::{mount_remount, MountFlags};
use rustix::process::{self, Pid, Signal as RustixSignal, WaitOptions, WaitStatus};
use rustix::system::{reboot, RebootCommand};
use tokio::sync::watch;

use crate::handoff::BootMode;

const PROC_DIR: &str = "/proc";
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);
const KILL_ALL_GRACE: Duration = Duration::from_millis(250);

#[derive(Clone, Default)]
pub(crate) struct ProcessSupervisor {
    inner: Option<Arc<Pid1Supervisor>>,
}

impl ProcessSupervisor {
    pub(crate) fn activate(boot_mode: &BootMode) -> eyre::Result<Self> {
        if !matches!(boot_mode, BootMode::AgentPid1 { .. }) {
            return Ok(Self::default());
        }

        let signals = pid1_signal_set();
        signal::pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
            .context("block PID1 signals")?;

        let (shutdown_tx, _) = watch::channel(false);
        let inner = Arc::new(Pid1Supervisor {
            registry: Mutex::new(ChildRegistry::default()),
            spawn_lock: Mutex::new(()),
            shutdown_tx,
            shutting_down: AtomicBool::new(false),
            shutdown_worker_started: AtomicBool::new(false),
        });

        spawn_signal_thread(Arc::clone(&inner), signals)?;
        tracing::info!("PID1 process supervisor active");

        Ok(Self { inner: Some(inner) })
    }

    pub(crate) fn is_active(&self) -> bool {
        self.inner.is_some()
    }

    pub(crate) fn shutdown_receiver(&self) -> Option<watch::Receiver<bool>> {
        self.inner
            .as_ref()
            .map(|inner| inner.shutdown_tx.subscribe())
    }

    pub(crate) async fn shutdown(&self) -> eyre::Result<()> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };

        inner.request_shutdown("agent shutdown".to_string());
        std::future::pending::<eyre::Result<()>>().await
    }

    pub(crate) fn spawn_child(
        &self,
        command: &mut Command,
        label: impl Into<String>,
    ) -> io::Result<(Child, ChildGuard)> {
        let Some(inner) = &self.inner else {
            let child = command.spawn()?;
            return Ok((child, ChildGuard::inactive()));
        };

        inner.spawn_child(command, label.into())
    }

    pub(crate) fn output<I, S>(&self, program: &str, args: I) -> io::Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (child, guard) = self.spawn_child(&mut command, program)?;
        let output = child.wait_with_output();
        drop(guard);
        output
    }

    pub(crate) fn status<I, S>(&self, program: &str, args: I) -> io::Result<ExitStatus>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (mut child, guard) = self.spawn_child(&mut command, program)?;
        let status = child.wait();
        drop(guard);
        status
    }
}

struct Pid1Supervisor {
    registry: Mutex<ChildRegistry>,
    spawn_lock: Mutex<()>,
    shutdown_tx: watch::Sender<bool>,
    shutting_down: AtomicBool,
    shutdown_worker_started: AtomicBool,
}

impl Pid1Supervisor {
    fn spawn_child(
        self: &Arc<Self>,
        command: &mut Command,
        label: String,
    ) -> io::Result<(Child, ChildGuard)> {
        let _spawn = lock_or_recover(&self.spawn_lock);
        if self.is_shutting_down() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "PID1 shutdown is in progress",
            ));
        }

        command.process_group(0);
        // PID1 blocks signals for synchronous delivery through the supervisor.
        // Child processes must not inherit that mask or shutdown signals may be
        // ignored until they explicitly unblock them.
        unsafe {
            command.pre_exec(|| {
                signal::pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
                    .map_err(io::Error::from)
            });
        }
        let child = command.spawn()?;
        let pid = child_pid(&child)?;
        self.register_child(pid, pid, label);
        Ok((
            child,
            ChildGuard {
                inner: Some(Arc::clone(self)),
                pid: Some(pid),
            },
        ))
    }

    fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    fn request_shutdown(self: &Arc<Self>, reason: String) {
        let first = !self.shutting_down.swap(true, Ordering::SeqCst);
        if first {
            tracing::warn!(reason, "PID1 shutdown requested");
            let _ = self.shutdown_tx.send(true);
        }
        self.start_shutdown_worker();
    }

    fn start_shutdown_worker(self: &Arc<Self>) {
        if self.shutdown_worker_started.swap(true, Ordering::SeqCst) {
            return;
        }

        let supervisor = Arc::clone(self);
        if let Err(err) = thread::Builder::new()
            .name("silo-pid1-shutdown".to_string())
            .spawn(move || supervisor.run_shutdown())
        {
            tracing::error!(error = %err, "failed to spawn PID1 shutdown thread");
            poweroff_guest();
        }
    }

    fn run_shutdown(self: Arc<Self>) {
        tracing::warn!("PID1 shutdown sequence starting");
        self.signal_tracked_process_groups(RustixSignal::TERM);

        for _ in 0..shutdown_grace_ticks() {
            self.reap_adopted_children();
            if !self.has_tracked_children() {
                break;
            }
            thread::sleep(SHUTDOWN_POLL);
        }

        if self.has_tracked_children() {
            self.signal_tracked_process_groups(RustixSignal::KILL);
            thread::sleep(SHUTDOWN_POLL);
            self.reap_adopted_children();
        }

        self.kill_all(RustixSignal::TERM);
        thread::sleep(KILL_ALL_GRACE);
        self.reap_adopted_children();
        self.kill_all(RustixSignal::KILL);
        thread::sleep(SHUTDOWN_POLL);
        self.reap_adopted_children();

        poweroff_guest();
    }

    fn register_child(&self, pid: Pid, process_group: Pid, label: String) {
        lock_or_recover(&self.registry).children.insert(
            pid,
            ChildRecord {
                process_group,
                label,
            },
        );
    }

    fn unregister_child(&self, pid: Pid) {
        lock_or_recover(&self.registry).children.remove(&pid);
    }

    fn has_tracked_children(&self) -> bool {
        !lock_or_recover(&self.registry).children.is_empty()
    }

    fn tracked_pids(&self) -> HashSet<Pid> {
        lock_or_recover(&self.registry)
            .children
            .keys()
            .copied()
            .collect()
    }

    fn tracked_process_groups(&self) -> Vec<TrackedProcessGroup> {
        lock_or_recover(&self.registry)
            .children
            .iter()
            .map(|(pid, child)| TrackedProcessGroup {
                pid: *pid,
                process_group: child.process_group,
                label: child.label.clone(),
            })
            .collect()
    }

    fn signal_tracked_process_groups(&self, signal: RustixSignal) {
        for child in self.tracked_process_groups() {
            if let Err(err) = kill_process_group(child.process_group, signal) {
                tracing::debug!(
                    pid = %child.pid,
                    process_group = %child.process_group,
                    label = %child.label,
                    signal = signal.as_raw(),
                    error = %err,
                    "failed to signal tracked process group"
                );
            }
        }
    }

    fn kill_all(&self, signal: RustixSignal) {
        if let Err(err) = kill_process_group(Pid::INIT, signal) {
            tracing::debug!(signal = signal.as_raw(), error = %err, "kill(-1) backstop failed");
        }
    }

    fn reap_adopted_children(&self) {
        let _spawn = lock_or_recover(&self.spawn_lock);
        let tracked = self.tracked_pids();
        let children = match current_child_pids() {
            Ok(children) => children,
            Err(err) => {
                tracing::debug!(error = %err, "failed to scan /proc for adopted children");
                return;
            }
        };

        for pid in children {
            if tracked.contains(&pid) {
                continue;
            }
            reap_child(pid);
        }
    }
}

#[derive(Default)]
struct ChildRegistry {
    children: HashMap<Pid, ChildRecord>,
}

struct ChildRecord {
    process_group: Pid,
    label: String,
}

struct TrackedProcessGroup {
    pid: Pid,
    process_group: Pid,
    label: String,
}

pub(crate) struct ChildGuard {
    inner: Option<Arc<Pid1Supervisor>>,
    pid: Option<Pid>,
}

impl ChildGuard {
    fn inactive() -> Self {
        Self {
            inner: None,
            pid: None,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let (Some(inner), Some(pid)) = (&self.inner, self.pid.take()) {
            inner.unregister_child(pid);
        }
    }
}

fn spawn_signal_thread(supervisor: Arc<Pid1Supervisor>, signals: SigSet) -> eyre::Result<()> {
    thread::Builder::new()
        .name("silo-pid1-signals".to_string())
        .spawn(move || loop {
            match signals.wait() {
                Ok(NixSignal::SIGCHLD) => supervisor.reap_adopted_children(),
                Ok(signal) if is_shutdown_signal(signal) => {
                    supervisor.request_shutdown(format!("received {signal:?}"));
                }
                Ok(signal) => {
                    tracing::debug!(signal = ?signal, "ignoring unexpected PID1 signal");
                }
                Err(err) => {
                    tracing::warn!(error = %err, "PID1 signal wait failed");
                }
            }
        })
        .context("spawn PID1 signal thread")?;
    Ok(())
}

fn pid1_signal_set() -> SigSet {
    let mut signals = SigSet::empty();
    for signal in pid1_signals() {
        signals.add(signal);
    }
    signals
}

fn pid1_signals() -> [NixSignal; 4] {
    [
        NixSignal::SIGCHLD,
        NixSignal::SIGTERM,
        NixSignal::SIGINT,
        NixSignal::SIGPWR,
    ]
}

fn is_shutdown_signal(signal: NixSignal) -> bool {
    matches!(
        signal,
        NixSignal::SIGTERM | NixSignal::SIGINT | NixSignal::SIGPWR
    )
}

fn child_pid(child: &Child) -> io::Result<Pid> {
    Pid::from_raw(child.id() as i32).ok_or_else(|| io::Error::other("child process id was zero"))
}

fn current_child_pids() -> io::Result<Vec<Pid>> {
    let mut children = Vec::new();
    for entry in fs::read_dir(PROC_DIR)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .and_then(Pid::from_raw)
        else {
            continue;
        };

        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        if parse_status_ppid(&status) == Some(1) {
            children.push(pid);
        }
    }
    Ok(children)
}

fn parse_status_ppid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix("PPid:")
            .and_then(|value| value.trim().parse().ok())
    })
}

fn reap_child(pid: Pid) {
    loop {
        match process::waitpid(Some(pid), WaitOptions::NOHANG) {
            Ok(Some((reaped_pid, status))) => log_abnormal_adopted_exit(reaped_pid, status),
            Ok(None) => break,
            Err(Errno::CHILD) => break,
            Err(Errno::INTR) => continue,
            Err(err) => {
                tracing::debug!(pid = %pid, error = %err, "failed to reap adopted child");
                break;
            }
        }
    }
}

fn log_abnormal_adopted_exit(pid: Pid, status: WaitStatus) {
    if let Some(exit_status) = status.exit_status() {
        if should_log_adopted_exit(Some(exit_status), None) {
            tracing::warn!(pid = %pid, exit_status, "adopted child exited unsuccessfully");
        }
    } else if let Some(signal) = status.terminating_signal() {
        if should_log_adopted_exit(None, Some(signal)) {
            tracing::warn!(pid = %pid, signal, "adopted child terminated by signal");
        }
    }
}

fn should_log_adopted_exit(exit_status: Option<i32>, terminating_signal: Option<i32>) -> bool {
    matches!(exit_status, Some(status) if status != 0) || terminating_signal.is_some()
}

fn kill_process_group(process_group: Pid, signal: RustixSignal) -> Result<(), Errno> {
    match process::kill_process_group(process_group, signal) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(err) => Err(err),
    }
}

fn shutdown_grace_ticks() -> u32 {
    (SHUTDOWN_GRACE.as_millis() / SHUTDOWN_POLL.as_millis()) as u32
}

fn poweroff_guest() -> ! {
    tracing::warn!("syncing filesystems before poweroff");
    rustix::fs::sync();
    if let Err(err) = mount_remount("/", MountFlags::RDONLY, "") {
        tracing::warn!(error = %err, "failed to remount root read-only before poweroff");
    }
    rustix::fs::sync();

    match reboot(RebootCommand::PowerOff) {
        Ok(()) => loop {
            thread::park();
        },
        Err(err) => {
            tracing::error!(error = %err, "failed to power off guest");
            std::process::exit(1);
        }
    }
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::signal::Signal;

    use crate::pid1::{
        is_shutdown_signal, parse_status_ppid, pid1_signals, should_log_adopted_exit,
        shutdown_grace_ticks,
    };

    #[test]
    fn pid1_signal_list_contains_shutdown_and_child_signals() {
        let signals = pid1_signals();
        assert!(signals.contains(&Signal::SIGCHLD));
        assert!(signals.contains(&Signal::SIGTERM));
        assert!(signals.contains(&Signal::SIGINT));
        assert!(signals.contains(&Signal::SIGPWR));
    }

    #[test]
    fn shutdown_signal_filter_excludes_child_signal() {
        assert!(is_shutdown_signal(Signal::SIGTERM));
        assert!(is_shutdown_signal(Signal::SIGINT));
        assert!(is_shutdown_signal(Signal::SIGPWR));
        assert!(!is_shutdown_signal(Signal::SIGCHLD));
    }

    #[test]
    fn parses_proc_status_parent_pid() {
        let status = "Name:\tsh\nState:\tZ (zombie)\nPPid:\t1\nPid:\t42\n";
        assert_eq!(parse_status_ppid(status), Some(1));
    }

    #[test]
    fn missing_proc_status_parent_pid_is_none() {
        assert_eq!(parse_status_ppid("Name:\tsh\n"), None);
    }

    #[test]
    fn adopted_exit_logging_only_reports_abnormal_statuses() {
        assert!(!should_log_adopted_exit(Some(0), None));
        assert!(should_log_adopted_exit(Some(1), None));
        assert!(should_log_adopted_exit(None, Some(15)));
    }

    #[test]
    fn shutdown_grace_uses_three_seconds() {
        assert_eq!(shutdown_grace_ticks(), 30);
    }
}
