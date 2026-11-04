use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use eyre::Context;
use nix::sys::signal::{self, SigSet, SigmaskHow, Signal as NixSignal};
use rustix::io::Errno;
use rustix::process::{self, Pid, Signal as RustixSignal, WaitOptions, WaitStatus};
use rustix::system::{reboot, RebootCommand};
use tokio::sync::watch;

use crate::freezer::{SpawnRole, WorkloadController};
use crate::handoff::BootMode;
use crate::root_storage::{ShutdownResult, StorageShutdown};

const PROC_DIR: &str = "/proc";
const DEV_INPUT_DIR: &str = "/dev/input";
const INPUT_EVENT_PREFIX: &str = "event";
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);
const KILL_ALL_GRACE: Duration = Duration::from_millis(250);
const INPUT_DEVICE_SCAN_POLL: Duration = Duration::from_secs(1);
const INPUT_EVENT_TIMEVAL_SIZE: usize = 16;
const INPUT_EVENT_TYPE_OFFSET: usize = INPUT_EVENT_TIMEVAL_SIZE;
const INPUT_EVENT_CODE_OFFSET: usize = INPUT_EVENT_TYPE_OFFSET + 2;
const INPUT_EVENT_VALUE_OFFSET: usize = INPUT_EVENT_CODE_OFFSET + 2;
const INPUT_EVENT_SIZE: usize = INPUT_EVENT_VALUE_OFFSET + 4;
const EV_KEY: u16 = 0x01;
const KEY_POWER: u16 = 116;
const KEY_RESTART: u16 = 408;

#[derive(Clone)]
pub(crate) struct ProcessSupervisor {
    inner: Option<Arc<Pid1Supervisor>>,
    writers: Arc<Mutex<InternalWriters>>,
    writer_shutdown: watch::Sender<bool>,
    workloads: WorkloadController,
    session: Option<crate::lifecycle::SessionLease>,
    retirement: Option<watch::Receiver<u64>>,
}

impl Default for ProcessSupervisor {
    fn default() -> Self {
        let (writer_shutdown, _) = watch::channel(false);
        Self {
            inner: None,
            writers: Arc::default(),
            writer_shutdown,
            workloads: WorkloadController::discover(),
            session: None,
            retirement: None,
        }
    }
}

impl ProcessSupervisor {
    pub(crate) fn activate(
        boot_mode: &BootMode,
        storage: StorageShutdown,
        diagnostics: crate::diagnostics::Diagnostics,
        workloads: WorkloadController,
    ) -> eyre::Result<Self> {
        if !matches!(boot_mode, BootMode::AgentPid1 { .. }) {
            return Ok(Self {
                workloads,
                ..Self::default()
            });
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
            storage: Mutex::new(Some(storage)),
            diagnostics,
        });

        spawn_signal_thread(Arc::clone(&inner), signals)?;
        spawn_power_button_monitor(Arc::clone(&inner))?;
        tracing::info!("PID1 process supervisor active");

        Ok(Self {
            inner: Some(Arc::clone(&inner)),
            writers: Arc::default(),
            writer_shutdown: inner.shutdown_tx.clone(),
            workloads,
            session: None,
            retirement: None,
        })
    }

    pub(crate) fn with_session(
        &self,
        session: crate::lifecycle::SessionLease,
        retirement: watch::Receiver<u64>,
    ) -> Self {
        Self {
            session: Some(session),
            retirement: Some(retirement),
            ..self.clone()
        }
    }

    pub(crate) fn retirement_receiver(&self) -> Option<watch::Receiver<u64>> {
        self.retirement.clone()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.inner.is_some()
    }

    pub(crate) fn shutdown_receiver(&self) -> Option<watch::Receiver<bool>> {
        Some(self.writer_shutdown.subscribe())
    }

    /// Close mutation admissions and send initial TERM before real worker drains.
    /// The final PID1 phase applies the remaining grace/KILL sequence and storage cleanup.
    pub(crate) fn begin_writer_shutdown(&self) -> eyre::Result<()> {
        lock_or_recover(&self.writers).closed = true;
        self.writer_shutdown.send_replace(true);
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        // Serialize against the final admitted spawn, not only the atomic flag.
        let _spawn = lock_or_recover(&inner.spawn_lock);
        inner.request_shutdown("agent draining writers".to_string());
        let mut result = ShutdownResult::default();
        inner.signal_tracked_process_groups(RustixSignal::TERM, &mut result);
        inner.kill_all(RustixSignal::TERM, &mut result);
        result.finish()
    }

    pub(crate) fn admit_internal_writer(&self) -> io::Result<InternalWriterGuard> {
        let mut writers = lock_or_recover(&self.writers);
        if writers.closed {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "agent internal writers are stopping",
            ));
        }
        writers.active = writers
            .active
            .checked_add(1)
            .ok_or_else(|| io::Error::other("internal writer count overflow"))?;
        Ok(InternalWriterGuard {
            _lease: Arc::new(InternalWriterLease {
                writers: Arc::clone(&self.writers),
                _session: self.session.clone(),
            }),
        })
    }

    pub(crate) async fn wait_internal_writers(&self) -> eyre::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if lock_or_recover(&self.writers).active == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| {
            eyre::eyre!("actual agent internal writer workers did not drain before shutdown")
        })
    }

    pub(crate) async fn shutdown(
        &self,
        quiescence: eyre::Result<()>,
        orderly: Arc<crate::orderly_shutdown::OrderlyShutdown>,
    ) -> eyre::Result<()> {
        let Some(inner) = &self.inner else {
            return quiescence;
        };

        inner.request_shutdown("agent shutdown".to_string());
        let mut result = ShutdownResult::default();
        result.record(quiescence);
        inner.start_shutdown_worker(result, orderly);
        std::future::pending::<eyre::Result<()>>().await
    }

    pub(crate) fn request_orderly_shutdown(&self) -> eyre::Result<()> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| eyre::eyre!("agent does not own PID1"))?;
        let _spawn = lock_or_recover(&inner.spawn_lock);
        inner.request_shutdown("run-bound orderly shutdown".to_owned());
        Ok(())
    }

    pub(crate) fn spawn_child(
        &self,
        command: &mut Command,
        label: impl Into<String>,
    ) -> io::Result<(Child, ChildGuard)> {
        self.spawn_child_with(
            command,
            label,
            ChildSpawnMode::NewProcessGroup,
            SpawnRole::Workload,
        )
    }

    pub(crate) fn spawn_session_child(
        &self,
        command: &mut Command,
        label: impl Into<String>,
    ) -> io::Result<(Child, ChildGuard)> {
        self.spawn_child_with(
            command,
            label,
            ChildSpawnMode::SessionLeader,
            SpawnRole::Workload,
        )
    }

    pub(crate) fn spawn_activation_child(
        &self,
        command: &mut Command,
        label: impl Into<String>,
    ) -> io::Result<(Child, ChildGuard)> {
        self.spawn_child_with(
            command,
            label,
            ChildSpawnMode::NewProcessGroup,
            SpawnRole::ActivationHook,
        )
    }

    /// The non-PID1 SSH path retains Tokio's cancellation/kill-on-drop behavior,
    /// but uses the same admission and pre-exec placement as supervised spawns.
    pub(crate) fn spawn_tokio_workload(
        &self,
        command: &mut tokio::process::Command,
    ) -> io::Result<(tokio::process::Child, ChildGuard)> {
        if self.is_active() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PID1 children must use the supervised spawn path",
            ));
        }
        let writer = self.admit_internal_writer()?;
        let child = self.workloads.spawn_tokio_workload(command)?;
        let mut guard = ChildGuard::inactive();
        guard.writer = Some(writer);
        Ok((child, guard))
    }

    fn spawn_child_with(
        &self,
        command: &mut Command,
        label: impl Into<String>,
        mode: ChildSpawnMode,
        role: SpawnRole,
    ) -> io::Result<(Child, ChildGuard)> {
        let writer = self.admit_internal_writer()?;
        let (child, mut guard) = self
            .workloads
            .with_spawn(command, role, |command| match &self.inner {
                Some(inner) => inner.spawn_child(command, label.into(), mode),
                None => {
                    if matches!(mode, ChildSpawnMode::NewProcessGroup) {
                        command.process_group(0);
                    }
                    command.spawn().map(|child| (child, ChildGuard::inactive()))
                }
            })?;
        guard.writer = Some(writer);
        Ok((child, guard))
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
}

/// Retired captured sessions must kill, not TERM and wait on frozen tasks.
/// The direct child remains owned and reaped before its session lease drains.
pub(crate) fn wait_retiring_child(
    child: &mut Child,
    retirement: Option<watch::Receiver<u64>>,
) -> io::Result<std::process::ExitStatus> {
    let Some(retirement) = retirement else {
        return child.wait();
    };
    loop {
        if retirement.has_changed().unwrap_or(true) {
            if let Ok(pid) = i32::try_from(child.id()) {
                let _ = signal::kill(nix::unistd::Pid::from_raw(-pid), NixSignal::SIGKILL);
            }
            let killed = child.kill();
            let status = child.wait();
            if let Err(error) = killed {
                if error.raw_os_error() != Some(nix::errno::Errno::ESRCH as i32) {
                    return Err(error);
                }
            }
            return status;
        }
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Default)]
struct InternalWriters {
    closed: bool,
    active: usize,
}

#[derive(Clone)]
pub(crate) struct InternalWriterGuard {
    _lease: Arc<InternalWriterLease>,
}

struct InternalWriterLease {
    writers: Arc<Mutex<InternalWriters>>,
    _session: Option<crate::lifecycle::SessionLease>,
}

impl Drop for InternalWriterLease {
    fn drop(&mut self) {
        let mut writers = lock_or_recover(&self.writers);
        writers.active = writers.active.saturating_sub(1);
    }
}

struct Pid1Supervisor {
    registry: Mutex<ChildRegistry>,
    spawn_lock: Mutex<()>,
    shutdown_tx: watch::Sender<bool>,
    shutting_down: AtomicBool,
    shutdown_worker_started: AtomicBool,
    storage: Mutex<Option<StorageShutdown>>,
    diagnostics: crate::diagnostics::Diagnostics,
}

impl Pid1Supervisor {
    fn spawn_child(
        self: &Arc<Self>,
        command: &mut Command,
        label: String,
        mode: ChildSpawnMode,
    ) -> io::Result<(Child, ChildGuard)> {
        let _spawn = lock_or_recover(&self.spawn_lock);
        if self.is_shutting_down() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "PID1 shutdown is in progress",
            ));
        }

        if matches!(mode, ChildSpawnMode::NewProcessGroup) {
            command.process_group(0);
        }
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
                writer: None,
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
            self.shutdown_tx.send_replace(true);
        }
    }

    fn start_shutdown_worker(
        self: &Arc<Self>,
        result: ShutdownResult,
        orderly: Arc<crate::orderly_shutdown::OrderlyShutdown>,
    ) {
        if self.shutdown_worker_started.swap(true, Ordering::SeqCst) {
            return;
        }

        let supervisor = Arc::clone(self);
        if let Err(err) = thread::Builder::new()
            .name("silo-pid1-shutdown".to_string())
            .spawn(move || supervisor.run_shutdown(result, orderly))
        {
            tracing::error!(error = %err, "failed to spawn PID1 shutdown thread");
            poweroff_guest();
        }
    }

    fn run_shutdown(
        self: Arc<Self>,
        mut result: ShutdownResult,
        orderly: Arc<crate::orderly_shutdown::OrderlyShutdown>,
    ) {
        tracing::warn!("PID1 shutdown sequence starting after agent writer drain");
        self.signal_tracked_process_groups(RustixSignal::TERM, &mut result);

        for _ in 0..shutdown_grace_ticks() {
            self.reap_adopted_children();
            if !self.has_tracked_children() {
                break;
            }
            thread::sleep(SHUTDOWN_POLL);
        }

        if self.has_tracked_children() {
            self.signal_tracked_process_groups(RustixSignal::KILL, &mut result);
            thread::sleep(SHUTDOWN_POLL);
            self.reap_adopted_children();
        }

        self.kill_all(RustixSignal::TERM, &mut result);
        thread::sleep(KILL_ALL_GRACE);
        self.reap_adopted_children();
        self.kill_all(RustixSignal::KILL, &mut result);
        thread::sleep(SHUTDOWN_POLL);
        self.reap_adopted_children();
        result.record(verify_no_workload_writers());
        result.record(
            self.diagnostics
                .close()
                .context("drain and close agent diagnostic writer"),
        );
        let coverage = match lock_or_recover(&self.storage).take() {
            Some(storage) => {
                let coverage = storage
                    .coverage(&orderly.manifest())
                    .err()
                    .map(|error| error.to_string());
                storage.shutdown(&mut result);
                coverage
            }
            None => {
                result.record(Err(eyre::eyre!("shutdown storage context missing")));
                None
            }
        };
        // No success file or filesystem-backed diagnostic is emitted after
        // this point. Only the retained RPC carries the sticky terminal result.
        orderly.complete_and_wait(result.finish(), coverage);
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

    fn signal_tracked_process_groups(&self, signal: RustixSignal, result: &mut ShutdownResult) {
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
                result.record(Err(eyre::eyre!(
                    "signal tracked process group {}: {err}",
                    child.process_group
                )));
            }
        }
    }

    fn kill_all(&self, signal: RustixSignal, result: &mut ShutdownResult) {
        if let Err(err) = kill_process_group(Pid::INIT, signal) {
            tracing::debug!(signal = signal.as_raw(), error = %err, "kill(-1) backstop failed");
            result.record(Err(eyre::eyre!("kill(-1) with {signal:?}: {err}")));
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

#[derive(Clone, Copy)]
enum ChildSpawnMode {
    NewProcessGroup,
    SessionLeader,
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
    writer: Option<InternalWriterGuard>,
}

impl ChildGuard {
    fn inactive() -> Self {
        Self {
            inner: None,
            pid: None,
            writer: None,
        }
    }

    pub(crate) fn writer(&self) -> Option<InternalWriterGuard> {
        self.writer.clone()
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

fn spawn_power_button_monitor(supervisor: Arc<Pid1Supervisor>) -> eyre::Result<()> {
    thread::Builder::new()
        .name("silo-pid1-power".to_string())
        .spawn(move || monitor_power_button_devices(supervisor))
        .context("spawn PID1 power button monitor")?;
    Ok(())
}

fn monitor_power_button_devices(supervisor: Arc<Pid1Supervisor>) {
    let mut watched = HashSet::new();
    loop {
        if supervisor.is_shutting_down() {
            return;
        }

        match input_event_device_paths() {
            Ok(paths) => {
                for path in paths {
                    if watched.insert(path.clone()) {
                        spawn_power_button_device_reader(Arc::clone(&supervisor), path);
                    }
                }
            }
            Err(err) => {
                tracing::debug!(error = %err, "failed to scan input event devices");
            }
        }

        thread::sleep(INPUT_DEVICE_SCAN_POLL);
    }
}

fn spawn_power_button_device_reader(supervisor: Arc<Pid1Supervisor>, path: PathBuf) {
    let thread_name = power_button_thread_name(&path);
    if let Err(err) = thread::Builder::new()
        .name(thread_name)
        .spawn(move || read_power_button_events(supervisor, path))
    {
        tracing::debug!(error = %err, "failed to spawn PID1 power button reader");
    }
}

fn read_power_button_events(supervisor: Arc<Pid1Supervisor>, path: PathBuf) {
    let mut file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(err) => {
            tracing::debug!(path = %path.display(), error = %err, "failed to open input event device");
            return;
        }
    };

    tracing::debug!(path = %path.display(), "watching input event device for virtual power button");
    let mut bytes = [0u8; INPUT_EVENT_SIZE];
    loop {
        match file.read_exact(&mut bytes) {
            Ok(()) => {
                if let Some(key) =
                    parse_input_event(&bytes).and_then(InputEvent::shutdown_key_press)
                {
                    tracing::warn!(path = %path.display(), ?key, "virtual shutdown key press received");
                    supervisor.request_shutdown(format!("received virtual {key:?} key press"));
                    return;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                tracing::debug!(path = %path.display(), error = %err, "input event device reader stopped");
                return;
            }
        }

        if supervisor.is_shutting_down() {
            return;
        }
    }
}

fn input_event_device_paths() -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(DEV_INPUT_DIR) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry?;
        if is_input_event_device_name(&entry.file_name()) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn is_input_event_device_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(suffix) = name.strip_prefix(INPUT_EVENT_PREFIX) else {
        return false;
    };
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn power_button_thread_name(path: &Path) -> String {
    let device = path.file_name().and_then(OsStr::to_str).unwrap_or("event");
    format!("silo-pid1-{device}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InputEvent {
    event_type: u16,
    code: u16,
    value: i32,
}

impl InputEvent {
    fn shutdown_key_press(self) -> Option<ShutdownKey> {
        if self.event_type != EV_KEY || self.value != 1 {
            return None;
        }
        match self.code {
            KEY_POWER => Some(ShutdownKey::Power),
            KEY_RESTART => Some(ShutdownKey::Restart),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownKey {
    Power,
    Restart,
}

fn parse_input_event(bytes: &[u8]) -> Option<InputEvent> {
    if bytes.len() != INPUT_EVENT_SIZE {
        return None;
    }

    // Linux input_event is timeval + type + code + value on Silo's 64-bit guests.
    let event_type = u16::from_ne_bytes([
        bytes[INPUT_EVENT_TYPE_OFFSET],
        bytes[INPUT_EVENT_TYPE_OFFSET + 1],
    ]);
    let code = u16::from_ne_bytes([
        bytes[INPUT_EVENT_CODE_OFFSET],
        bytes[INPUT_EVENT_CODE_OFFSET + 1],
    ]);
    let value = i32::from_ne_bytes([
        bytes[INPUT_EVENT_VALUE_OFFSET],
        bytes[INPUT_EVENT_VALUE_OFFSET + 1],
        bytes[INPUT_EVENT_VALUE_OFFSET + 2],
        bytes[INPUT_EVENT_VALUE_OFFSET + 3],
    ]);

    Some(InputEvent {
        event_type,
        code,
        value,
    })
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

fn verify_no_workload_writers() -> eyre::Result<()> {
    for entry in fs::read_dir(PROC_DIR)? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid <= 1 {
            continue;
        }
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect remaining workload writer"),
        };
        if !status.lines().any(|line| {
            line.starts_with("State:") && (line.contains("Z (zombie)") || line.contains("X (dead)"))
        }) {
            let stat = match fs::read_to_string(entry.path().join("stat")) {
                Ok(stat) => stat,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("inspect remaining task flags"),
            };
            if is_kernel_task(&stat)? {
                continue;
            }
            eyre::bail!("workload process {pid} remains alive after shutdown");
        }
    }
    Ok(())
}

pub(crate) fn is_kernel_task(stat: &str) -> eyre::Result<bool> {
    // /proc/pid/stat field 9 is Linux task flags. PF_KTHREAD distinguishes
    // kernel workers (which syncfs must finish) from remaining guest workloads.
    // Parse after the final ')' because comm may contain spaces and parentheses.
    let (_, fields) = stat
        .rsplit_once(')')
        .ok_or_else(|| eyre::eyre!("malformed process stat"))?;
    let flags = fields
        .split_whitespace()
        .nth(6)
        .ok_or_else(|| eyre::eyre!("process task flags missing"))?
        .parse::<u64>()?;
    Ok(flags & 0x0020_0000 != 0)
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use nix::sys::signal::Signal;

    use crate::pid1::{
        is_input_event_device_name, is_shutdown_signal, parse_input_event, parse_status_ppid,
        pid1_signals, should_log_adopted_exit, shutdown_grace_ticks, InputEvent, ShutdownKey,
        EV_KEY, INPUT_EVENT_CODE_OFFSET, INPUT_EVENT_SIZE, INPUT_EVENT_TYPE_OFFSET,
        INPUT_EVENT_VALUE_OFFSET, KEY_POWER, KEY_RESTART,
    };

    #[test]
    fn retired_session_kills_and_reaps_a_real_stopped_child() {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
        use nix::unistd::Pid;
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        let mut command = std::process::Command::new("sleep");
        command.arg("60").process_group(0);
        let mut child = command.spawn().unwrap();
        let pid = Pid::from_raw(i32::try_from(child.id()).unwrap());
        nix::sys::signal::kill(pid, Signal::SIGSTOP).unwrap();
        assert!(matches!(
            waitpid(pid, Some(WaitPidFlag::WUNTRACED)).unwrap(),
            WaitStatus::Stopped(_, Signal::SIGSTOP),
        ));
        let (retire, retirement) = tokio::sync::watch::channel(0_u64);
        retire.send_replace(1);
        let status = crate::pid1::wait_retiring_child(&mut child, Some(retirement)).unwrap();
        assert_eq!(status.signal(), Some(Signal::SIGKILL as i32));
        assert_eq!(
            waitpid(pid, Some(WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_tracks_actual_blocking_workers_and_their_reader_clones() {
        let supervisor = crate::pid1::ProcessSupervisor::default();
        let writer = supervisor.admit_internal_writer().unwrap();
        let reader = writer.clone();
        drop(writer);
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _reader = reader;
                started.send(()).unwrap();
                released.recv().unwrap();
            })
            .await
        });
        running.await.unwrap();
        task.abort();
        let _ = task.await;
        supervisor.begin_writer_shutdown().unwrap();
        assert!(supervisor.admit_internal_writer().is_err());
        let incomplete = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            supervisor.wait_internal_writers(),
        )
        .await
        .is_err();
        release.send(()).unwrap();
        supervisor.wait_internal_writers().await.unwrap();
        assert!(incomplete);
    }

    #[test]
    fn remaining_writer_check_distinguishes_kernel_tasks_from_workloads() {
        assert!(crate::pid1::is_kernel_task("2 (kthreadd) S 0 0 0 0 -1 2097152").unwrap());
        assert!(
            !crate::pid1::is_kernel_task("42 (work (with spaces)) S 1 42 42 0 -1 4194304").unwrap()
        );
        assert!(crate::pid1::is_kernel_task("malformed").is_err());
    }

    #[test]
    fn shutdown_request_before_subscription_is_sticky_without_starting_cleanup() {
        use std::sync::{atomic::AtomicBool, Arc, Mutex};
        let (shutdown_tx, receiver) = tokio::sync::watch::channel(false);
        drop(receiver);
        let supervisor = Arc::new(crate::pid1::Pid1Supervisor {
            registry: Mutex::new(crate::pid1::ChildRegistry::default()),
            spawn_lock: Mutex::new(()),
            shutdown_tx,
            shutting_down: AtomicBool::new(false),
            shutdown_worker_started: AtomicBool::new(false),
            storage: Mutex::new(None),
            diagnostics: crate::diagnostics::Diagnostics::new(std::io::stdout()),
        });
        supervisor.request_shutdown("unit shutdown request".to_string());
        assert!(*supervisor.shutdown_tx.subscribe().borrow());
        assert!(!supervisor
            .shutdown_worker_started
            .load(std::sync::atomic::Ordering::SeqCst));
        let mut command = std::process::Command::new("/must-not-run");
        assert!(supervisor
            .spawn_child(
                &mut command,
                "rejected".to_string(),
                crate::pid1::ChildSpawnMode::NewProcessGroup
            )
            .is_err());
    }

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
    fn input_event_device_name_filter() {
        for (name, expected) in [
            ("event0", true),
            ("event12", true),
            ("event", false),
            ("eventx", false),
            ("event0.old", false),
            ("mouse0", false),
        ] {
            assert_eq!(
                is_input_event_device_name(OsStr::new(name)),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn input_event_parser_detects_power_button_press() {
        let bytes = input_event_bytes(EV_KEY, KEY_POWER, 1);
        let event = parse_input_event(&bytes).expect("input event should parse");

        assert_eq!(
            event,
            InputEvent {
                event_type: EV_KEY,
                code: KEY_POWER,
                value: 1,
            }
        );
        assert_eq!(event.shutdown_key_press(), Some(ShutdownKey::Power));
    }

    #[test]
    fn input_event_parser_detects_restart_key_press() {
        let event = parse_input_event(&input_event_bytes(EV_KEY, KEY_RESTART, 1))
            .expect("restart event should parse");

        assert_eq!(event.shutdown_key_press(), Some(ShutdownKey::Restart));
    }

    #[test]
    fn input_event_parser_ignores_releases_repeats_and_unrelated_events() {
        let release = parse_input_event(&input_event_bytes(EV_KEY, KEY_POWER, 0))
            .expect("release event should parse");
        let repeat = parse_input_event(&input_event_bytes(EV_KEY, KEY_RESTART, 2))
            .expect("repeat event should parse");
        let other_key = parse_input_event(&input_event_bytes(EV_KEY, KEY_POWER + 1, 1))
            .expect("other key event should parse");
        let other_type = parse_input_event(&input_event_bytes(EV_KEY + 1, KEY_POWER, 1))
            .expect("other event type should parse");

        assert_eq!(release.shutdown_key_press(), None);
        assert_eq!(repeat.shutdown_key_press(), None);
        assert_eq!(other_key.shutdown_key_press(), None);
        assert_eq!(other_type.shutdown_key_press(), None);
    }

    #[test]
    fn input_event_parser_rejects_incomplete_record() {
        assert_eq!(parse_input_event(&[0u8; INPUT_EVENT_SIZE - 1]), None);
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

    fn input_event_bytes(event_type: u16, code: u16, value: i32) -> [u8; INPUT_EVENT_SIZE] {
        let mut bytes = [0u8; INPUT_EVENT_SIZE];
        bytes[INPUT_EVENT_TYPE_OFFSET..INPUT_EVENT_TYPE_OFFSET + 2]
            .copy_from_slice(&event_type.to_ne_bytes());
        bytes[INPUT_EVENT_CODE_OFFSET..INPUT_EVENT_CODE_OFFSET + 2]
            .copy_from_slice(&code.to_ne_bytes());
        bytes[INPUT_EVENT_VALUE_OFFSET..INPUT_EVENT_VALUE_OFFSET + 4]
            .copy_from_slice(&value.to_ne_bytes());
        bytes
    }
}
