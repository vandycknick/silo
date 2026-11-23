//! Retained cgroup-v2 targets and reversible, pre-exec workload admission.
//!
//! Image init and Silo exec sessions share the workloads freeze switch, in
//! separate image and exec leaves. Retained descriptors survive the image's
//! cgroup namespace remount. Lifecycle owns epochs and rollback; drop never thaws.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};

use eyre::Context;
use nix::fcntl::{open, openat, OFlag};
use nix::sched::{unshare, CloneFlags};
use nix::sys::stat::Mode;
use nix::sys::statfs::{fstatfs, CGROUP2_SUPER_MAGIC};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::handoff::BootMode;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const WORKLOAD_ROOT: &str = "/sys/fs/cgroup/silo/workloads";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DelegationGroup {
    Root,
    Silo,
    Workloads,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequiredController {
    Memory,
    Cpu,
    Pids,
}

impl RequiredController {
    const ALL: [Self; 3] = [Self::Memory, Self::Cpu, Self::Pids];

    fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Cpu => "cpu",
            Self::Pids => "pids",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Protection {
    CgroupTargets,
    AvailableControllers(DelegationGroup),
    Delegation(DelegationGroup, RequiredController),
    SiloMemoryMin,
    ControlMemoryMin,
    ControlCpuWeight,
    WorkloadPidLimit,
    AgentOomScoreAdj,
    AgentDumpable,
}

#[derive(Debug)]
pub(crate) struct ProtectionFailure {
    protection: Protection,
    source: io::Error,
}

impl ProtectionFailure {
    pub(crate) fn new(protection: Protection, source: impl Into<io::Error>) -> Self {
        Self {
            protection,
            source: source.into(),
        }
    }
}

impl std::fmt::Display for ProtectionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.protection, self.source)
    }
}

impl std::error::Error for ProtectionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl Protection {
    pub(crate) fn qualify_value(
        self,
        observed: &str,
        expected: i128,
    ) -> Result<(), ProtectionFailure> {
        let value = observed.trim().parse::<i128>().map_err(|error| {
            ProtectionFailure::new(self, io::Error::new(io::ErrorKind::InvalidData, error))
        })?;
        if value != expected {
            return Err(ProtectionFailure::new(
                self,
                io::Error::other(format!("expected {expected}, observed {value}")),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SpawnRole {
    Workload,
    ActivationHook,
}

#[derive(Clone)]
pub(crate) struct WorkloadController {
    inner: Arc<Controller>,
}

struct Controller {
    targets: Option<Targets>,
    unavailable: Option<String>,
    protection_setup: Result<(), ProtectionFailure>,
    profile: Mutex<Option<String>>,
    // Permits live through Command::spawn's exec-error-pipe acknowledgement.
    // Closing is short and synchronous; waiting for permits is asynchronous.
    spawn_gate: Mutex<SpawnAdmission>,
    spawn_idle: Notify,
}

#[derive(Default)]
struct SpawnAdmission {
    closed: bool,
    active: usize,
}

struct SpawnPermit {
    workload: Option<Arc<Controller>>,
}

impl Drop for SpawnPermit {
    fn drop(&mut self) {
        if let Some(controller) = &self.workload {
            let mut gate = lock(&controller.spawn_gate);
            gate.active = gate.active.saturating_sub(1);
            controller.spawn_idle.notify_waiters();
        }
    }
}

struct Targets {
    root: File,
    silo: File,
    procfs: File,
    control: Group,
    workloads: Group,
    image: Group,
    exec: Group,
    activation: Group,
}

struct Group {
    directory: File,
    procs: File,
    events: File,
    freeze: File,
}

impl WorkloadController {
    pub(crate) fn discover() -> Self {
        let (targets, unavailable, protection_setup) = match Targets::open() {
            Ok(targets) => {
                let protection_setup = targets.configure();
                (Some(targets), None, protection_setup)
            }
            Err(error) => {
                tracing::warn!(%error, "live workload containment unavailable; cold boot retained");
                (
                    None,
                    Some(format!(
                        "cgroup-v2 workload containment unavailable: {error}"
                    )),
                    Err(ProtectionFailure::new(Protection::CgroupTargets, error)),
                )
            }
        };
        Self {
            inner: Arc::new(Controller {
                targets,
                unavailable,
                protection_setup,
                profile: Mutex::new(Some("guest profile not yet qualified".to_owned())),
                spawn_gate: Mutex::default(),
                spawn_idle: Notify::new(),
            }),
        }
    }

    pub(crate) fn qualify_profile(&self, boot: &BootMode) {
        let reason = match boot {
            BootMode::AgentPid1 { .. } | BootMode::ContainedInit { .. } => None,
            BootMode::InitChild { .. } => Some(
                "unsupported guest profile InitChild: image init cgroup containment was not established"
                    .to_owned(),
            ),
            BootMode::Standard => Some(
                "unsupported guest profile Standard: Silo does not own complete process containment"
                    .to_owned(),
            ),
        };
        *lock(&self.inner.profile) = reason;
    }

    pub(crate) fn unsupported_reason(&self) -> Option<String> {
        lock(&self.inner.profile)
            .clone()
            .or_else(|| self.inner.unavailable.clone())
    }

    pub(crate) fn protection_setup(&self) -> Result<(), &ProtectionFailure> {
        self.inner.protection_setup.as_ref().copied()
    }

    pub(crate) fn observe_protections(&self) -> Result<(), ProtectionFailure> {
        let targets = self.inner.targets.as_ref().ok_or_else(|| {
            ProtectionFailure::new(
                Protection::CgroupTargets,
                io::Error::other("retained cgroup targets unavailable"),
            )
        })?;
        targets.observe_protections()
    }

    pub(crate) fn roots(&self) -> Vec<String> {
        vec![WORKLOAD_ROOT.to_owned()]
    }

    fn live_targets(&self) -> eyre::Result<&Targets> {
        if let Some(reason) = self.unsupported_reason() {
            eyre::bail!(reason);
        }
        let targets =
            self.inner.targets.as_ref().ok_or_else(|| {
                eyre::eyre!("retained cgroup-v2 workload targets are unavailable")
            })?;
        targets
            .validate()
            .context("validate retained cgroup targets")?;
        targets
            .validate_control()
            .context("validate agent control membership")?;
        Ok(targets)
    }

    pub(crate) fn close_spawn_admission(&self) -> eyre::Result<()> {
        // Refuse unsupported profiles before changing even local admission.
        self.live_targets()?;
        lock(&self.inner.spawn_gate).closed = true;
        Ok(())
    }

    pub(crate) fn open_spawn_admission(&self) -> eyre::Result<()> {
        if self.is_frozen()? {
            eyre::bail!("cannot reopen workload spawning while cgroup remains frozen");
        }
        lock(&self.inner.spawn_gate).closed = false;
        Ok(())
    }

    pub(crate) async fn freeze(&self, deadline: Instant) -> eyre::Result<()> {
        self.live_targets()?;
        self.wait_for_spawns(deadline).await?;
        self.live_targets()?
            .workloads
            .set_frozen(true, deadline)
            .await?;
        // A task killed while frozen (an exec session torn down by its client)
        // runs only its kernel exit path, but cgroup.events reports frozen 0
        // until it is gone. Wait for the settled state again instead of
        // failing; a target that never re-settles still misses the deadline.
        let workloads = &self.live_targets()?.workloads;
        let events = workloads.subscribe()?;
        workloads
            .wait_event(&events, "frozen", true, deadline)
            .await
            .context("workload cgroup did not stay frozen after completion")?;
        // An empty frozen cgroup can be removed. A notification from a retained
        // but unlinked target must never certify a recreated path.
        self.live_targets()?;
        Ok(())
    }

    pub(crate) async fn thaw(&self, deadline: Instant) -> eyre::Result<()> {
        self.live_targets()?
            .workloads
            .set_frozen(false, deadline)
            .await?;
        if self.is_frozen()? {
            eyre::bail!("workload cgroup regained frozen state after thaw completion");
        }
        Ok(())
    }

    pub(crate) fn is_frozen(&self) -> eyre::Result<bool> {
        Ok(self.live_targets()?.workloads.event("frozen")?)
    }

    pub(crate) fn activation_populated(&self) -> eyre::Result<bool> {
        Ok(self.live_targets()?.activation.event("populated")?)
    }

    pub(crate) fn check_containment(&self) -> Result<(), tonic::Status> {
        let targets = self.live_targets().map_err(|error| {
            crate::containment::failure(0, 0, "unknown", "unknown", &error.to_string())
        })?;
        crate::containment::check(
            &targets.root,
            &targets.silo,
            &targets.control.directory,
            &targets.activation.directory,
            &targets.procfs,
            false,
        )
    }

    pub(crate) fn reclaim_directory(&self) -> io::Result<Option<File>> {
        self.inner
            .targets
            .as_ref()
            .map(|targets| {
                targets.validate()?;
                targets.workloads.directory.try_clone()
            })
            .transpose()
    }

    /// Parent-side placement preparation. No allocation, logging or locking is
    /// done by the closure after fork; writing zero moves the current process.
    pub(crate) fn with_spawn<T>(
        &self,
        command: &mut Command,
        role: SpawnRole,
        spawn: impl FnOnce(&mut Command) -> io::Result<T>,
    ) -> io::Result<T> {
        let _admission = self.admit_spawn(role)?;
        self.prepare_command(command, role)?;
        spawn(command)
    }

    pub(crate) fn spawn_tokio_workload(
        &self,
        command: &mut tokio::process::Command,
    ) -> io::Result<tokio::process::Child> {
        let _admission = self.admit_spawn(SpawnRole::Workload)?;
        self.prepare_command(command.as_std_mut(), SpawnRole::Workload)?;
        command.spawn()
    }

    fn admit_spawn(&self, role: SpawnRole) -> io::Result<SpawnPermit> {
        if role == SpawnRole::ActivationHook {
            return Ok(SpawnPermit { workload: None });
        }
        let mut gate = lock(&self.inner.spawn_gate);
        if gate.closed {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "workload spawning is frozen",
            ));
        }
        gate.active = gate
            .active
            .checked_add(1)
            .ok_or_else(|| io::Error::other("workload spawn admission overflow"))?;
        Ok(SpawnPermit {
            workload: Some(Arc::clone(&self.inner)),
        })
    }

    async fn wait_for_spawns(&self, deadline: Instant) -> eyre::Result<()> {
        loop {
            let notified = self.inner.spawn_idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let gate = lock(&self.inner.spawn_gate);
                if !gate.closed {
                    eyre::bail!("workload spawn admission must remain closed before freeze");
                }
                if gate.active == 0 {
                    return Ok(());
                }
            }
            tokio::time::timeout_at(deadline, notified)
                .await
                .map_err(|_| {
                    eyre::eyre!("parent spawn/exec acknowledgements did not drain before freeze")
                })?;
        }
    }

    fn prepare_command(&self, command: &mut Command, role: SpawnRole) -> io::Result<()> {
        // Only an agent that protected itself (-1000 after handoff) must undo
        // that for children; lowering an inherited positive value needs
        // CAP_SYS_RESOURCE, so never write when there is nothing to undo.
        let reset_oom = agent_oom_protected()?;
        if let Some(targets) = &self.inner.targets {
            targets.validate()?;
            let group = match role {
                SpawnRole::Workload => &targets.exec,
                SpawnRole::ActivationHook => &targets.activation,
            };
            let procs = group.procs.try_clone()?;
            unsafe {
                command.pre_exec(move || {
                    write_current_process(&procs)?;
                    // std applies Command::uid before pre_exec. A non-root
                    // session can neither mount cgroupfs nor migrate tasks,
                    // so its own cgroup namespace would add nothing (and
                    // unshare needs CAP_SYS_ADMIN).
                    if nix::unistd::geteuid().is_root() {
                        unshare(CloneFlags::CLONE_NEWCGROUP).map_err(io::Error::from)?;
                    }
                    if reset_oom {
                        reset_oom_score_adj()?;
                    }
                    Ok(())
                });
            }
        } else if role == SpawnRole::ActivationHook {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "activation cgroup unavailable",
            ));
        } else if reset_oom {
            unsafe {
                command.pre_exec(reset_oom_score_adj);
            }
        }
        Ok(())
    }

    /// The handoff parent is image PID1, not the agent child. This happens
    /// before the runtime exists; never migrate the multithreaded agent.
    pub(crate) fn place_handoff_parent(&self) -> io::Result<()> {
        let targets = self.inner.targets.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "image cgroup unavailable")
        })?;
        targets.validate()?;
        write_current_process(&targets.image.procs)?;
        Ok(())
    }

    pub(crate) async fn kill_activation(&self, deadline: Instant) -> eyre::Result<()> {
        let targets = self.live_targets()?;
        // cgroup.kill atomically kills the whole subtree, including concurrent
        // forks. Reap the direct hook through ProcessSupervisor as usual.
        let kill = open_file(&targets.activation.directory, "cgroup.kill", true)?;
        let events = targets.activation.subscribe()?;
        write_value(&kill, b"1")?;
        targets
            .activation
            .wait_event(&events, "populated", false, deadline)
            .await?;
        if self.activation_populated()? {
            eyre::bail!("activation cgroup repopulated after cleanup completion");
        }
        Ok(())
    }
}

impl Targets {
    fn open() -> io::Result<Self> {
        let root = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
            .open(CGROUP_ROOT)?;
        if fstatfs(&root).map_err(io::Error::from)?.filesystem_type() != CGROUP2_SUPER_MAGIC {
            return Err(io::Error::other("workload mount is not cgroup v2"));
        }
        let silo = open_directory(&root, "silo")?;
        let workloads = Group::open(&silo, "workloads")?;
        let procfs = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
            .open("/proc")?;
        let targets = Self {
            control: Group::open(&silo, "control")?,
            image: Group::open(&workloads.directory, "image")?,
            exec: Group::open(&workloads.directory, "exec")?,
            workloads,
            activation: Group::open(&silo, "activation")?,
            root,
            silo,
            procfs,
        };
        targets.validate()?;
        targets.validate_control()?;
        Ok(targets)
    }

    fn validate(&self) -> io::Result<()> {
        same_object(&self.silo, &open_directory(&self.root, "silo")?)?;
        self.control.validate(&self.silo, "control")?;
        self.workloads.validate(&self.silo, "workloads")?;
        self.activation.validate(&self.silo, "activation")?;
        self.image.validate(&self.workloads.directory, "image")?;
        self.exec.validate(&self.workloads.directory, "exec")
    }

    fn delegation_groups(&self) -> [(DelegationGroup, &File); 3] {
        [
            (DelegationGroup::Root, &self.root),
            (DelegationGroup::Silo, &self.silo),
            (DelegationGroup::Workloads, &self.workloads.directory),
        ]
    }

    fn configure(&self) -> Result<(), ProtectionFailure> {
        // Keep configuring independent protections after a failure, but retain
        // the first required failure for qualification in the agent child.
        let mut result = Ok(());
        for (group, directory) in self.delegation_groups() {
            result = result.and(delegate_controllers(directory, group));
        }
        for (directory, control, value, protection) in [
            (
                &self.silo,
                "memory.min",
                "16777216",
                Protection::SiloMemoryMin,
            ),
            (
                &self.control.directory,
                "memory.min",
                "16777216",
                Protection::ControlMemoryMin,
            ),
            (
                &self.control.directory,
                "cpu.weight",
                "1000",
                Protection::ControlCpuWeight,
            ),
        ] {
            result = result.and(
                configure_value(directory, control, value)
                    .map_err(|error| ProtectionFailure::new(protection, error)),
            );
        }
        result.and(
            fs::read_to_string("/proc/sys/kernel/pid_max")
                .and_then(|value| workload_pid_limit(&value))
                .and_then(|limit| {
                    configure_value(&self.workloads.directory, "pids.max", &limit.to_string())
                })
                .map_err(|error| ProtectionFailure::new(Protection::WorkloadPidLimit, error)),
        )
    }

    fn observe_protections(&self) -> Result<(), ProtectionFailure> {
        self.validate()
            .and_then(|()| self.validate_control())
            .map_err(|error| ProtectionFailure::new(Protection::CgroupTargets, error))?;
        for (group, directory) in self.delegation_groups() {
            let enabled = open_file(directory, "cgroup.subtree_control", false)
                .and_then(io::read_to_string)
                .map_err(|error| {
                    ProtectionFailure::new(Protection::AvailableControllers(group), error)
                })?;
            qualify_controllers(&enabled, group)?;
        }
        let pid_limit = fs::read_to_string("/proc/sys/kernel/pid_max")
            .and_then(|value| workload_pid_limit(&value))
            .map_err(|error| ProtectionFailure::new(Protection::WorkloadPidLimit, error))?;
        for (directory, control, expected, protection) in [
            (
                &self.silo,
                "memory.min",
                16_777_216,
                Protection::SiloMemoryMin,
            ),
            (
                &self.control.directory,
                "memory.min",
                16_777_216,
                Protection::ControlMemoryMin,
            ),
            (
                &self.control.directory,
                "cpu.weight",
                1000,
                Protection::ControlCpuWeight,
            ),
            (
                &self.workloads.directory,
                "pids.max",
                pid_limit,
                Protection::WorkloadPidLimit,
            ),
        ] {
            let observed = open_file(directory, control, false)
                .and_then(io::read_to_string)
                .map_err(|error| ProtectionFailure::new(protection, error))?;
            protection.qualify_value(&observed, i128::from(expected))?;
        }
        Ok(())
    }

    fn validate_control(&self) -> io::Result<()> {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        if !membership.lines().any(|line| line == "0::/silo/control") {
            return Err(io::Error::other("agent is not in /silo/control"));
        }
        Ok(())
    }
}

impl Group {
    fn open(parent: &File, name: &str) -> io::Result<Self> {
        let directory = open_directory(parent, name)?;
        Ok(Self {
            procs: open_file(&directory, "cgroup.procs", true)?,
            events: open_file(&directory, "cgroup.events", false)?,
            freeze: open_file(&directory, "cgroup.freeze", true)?,
            directory,
        })
    }

    fn validate(&self, parent: &File, name: &str) -> io::Result<()> {
        same_object(&self.directory, &open_directory(parent, name)?)?;
        for (retained, name, writable) in [
            (&self.procs, "cgroup.procs", true),
            (&self.events, "cgroup.events", false),
            (&self.freeze, "cgroup.freeze", true),
        ] {
            same_object(retained, &open_file(&self.directory, name, writable)?)?;
        }
        Ok(())
    }

    fn subscribe(&self) -> io::Result<AsyncFd<File>> {
        // dup() would share kernfs's per-open notification cursor with status
        // reads. A status query must not consume a pending freezer wakeup.
        let events = open_file(&self.directory, "cgroup.events", false)?;
        same_object(&self.events, &events)?;
        AsyncFd::with_interest(events, Interest::PRIORITY)
    }

    fn event(&self, key: &str) -> io::Result<bool> {
        Self::read_event(&self.events, key)
    }

    fn read_event(events: &File, key: &str) -> io::Result<bool> {
        let mut bytes = [0_u8; 4096];
        let length = events.read_at(&mut bytes, 0)?;
        if length == bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized cgroup.events",
            ));
        }
        let text = std::str::from_utf8(&bytes[..length])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        parse_event(text, key)
    }

    async fn set_frozen(&self, frozen: bool, deadline: Instant) -> eyre::Result<()> {
        // Subscribe before the request and first observation. The write alone
        // does not certify that any task reached its freezer boundary.
        let events = self.subscribe()?;
        if Instant::now() >= deadline {
            eyre::bail!("cgroup freezer deadline expired before request");
        }
        write_value(&self.freeze, if frozen { b"1" } else { b"0" })?;
        self.wait_event(&events, "frozen", frozen, deadline).await
    }

    async fn wait_event(
        &self,
        events: &AsyncFd<File>,
        key: &str,
        expected: bool,
        deadline: Instant,
    ) -> eyre::Result<()> {
        loop {
            if Instant::now() >= deadline {
                eyre::bail!("cgroup.events {key}={expected} completion deadline expired");
            }
            if Self::read_event(events.get_ref(), key)? == expected {
                return Ok(());
            }
            let mut ready = tokio::time::timeout_at(deadline, events.ready(Interest::PRIORITY))
                .await
                .map_err(|_| {
                    eyre::eyre!("cgroup.events {key}={expected} completion deadline expired")
                })??;
            ready.clear_ready();
        }
    }
}

pub(crate) fn parse_event(text: &str, key: &str) -> io::Result<bool> {
    let mut value = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some(key) {
            continue;
        }
        let parsed = match (fields.next(), fields.next()) {
            (Some("0"), None) => false,
            (Some("1"), None) => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed cgroup event",
                ))
            }
        };
        if value.replace(parsed).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate cgroup event",
            ));
        }
    }
    value.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing cgroup event"))
}

fn open_directory(parent: &File, name: &str) -> io::Result<File> {
    let fd: OwnedFd = openat(
        parent.as_fd(),
        Path::new(name),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    Ok(File::from(fd))
}

pub(crate) fn open_file(parent: &File, name: &str, writable: bool) -> io::Result<File> {
    let access = if writable {
        OFlag::O_WRONLY
    } else {
        OFlag::O_RDONLY
    };
    let fd: OwnedFd = openat(
        parent.as_fd(),
        Path::new(name),
        access | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    Ok(File::from(fd))
}

fn same_object(retained: &File, current: &File) -> io::Result<()> {
    let old = retained.metadata()?;
    let new = current.metadata()?;
    if old.dev() != new.dev() || old.ino() != new.ino() || old.nlink() == 0 {
        return Err(io::Error::other(
            "retained cgroup target was removed or replaced",
        ));
    }
    Ok(())
}

fn workload_pid_limit(value: &str) -> io::Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|maximum| maximum.checked_sub(512))
        .filter(|limit| *limit > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "pid_max cannot reserve 512 agent PIDs",
            )
        })
}

fn qualify_controllers(controllers: &str, group: DelegationGroup) -> Result<(), ProtectionFailure> {
    for controller in RequiredController::ALL {
        if !controllers
            .split_ascii_whitespace()
            .any(|name| name == controller.name())
        {
            return Err(ProtectionFailure::new(
                Protection::Delegation(group, controller),
                io::Error::other("required controller is not delegated"),
            ));
        }
    }
    Ok(())
}

fn delegate_controllers(directory: &File, group: DelegationGroup) -> Result<(), ProtectionFailure> {
    let controllers = open_file(directory, "cgroup.controllers", false)
        .and_then(io::read_to_string)
        .map_err(|error| ProtectionFailure::new(Protection::AvailableControllers(group), error))?;
    let mut result = qualify_controllers(&controllers, group);
    // Delegate optional controllers too, so the image retains its normal
    // resource controls (Docker needs cpuset, for one).
    for controller in controllers.split_ascii_whitespace() {
        if let Err(error) = configure_value(
            directory,
            "cgroup.subtree_control",
            &format!("+{controller}"),
        ) {
            match RequiredController::ALL
                .into_iter()
                .find(|required| required.name() == controller)
            {
                Some(required) => {
                    result = result.and(Err(ProtectionFailure::new(
                        Protection::Delegation(group, required),
                        error,
                    )));
                }
                None => {
                    tracing::warn!(?group, controller, %error, "failed to delegate optional cgroup controller");
                }
            }
        }
    }
    result
}

fn configure_value(directory: &File, control: &str, value: &str) -> io::Result<()> {
    open_file(directory, control, true).and_then(|file| write_value(&file, value.as_bytes()))
}

fn write_value(file: &File, value: &[u8]) -> io::Result<()> {
    if file.write_at(value, 0)? != value.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short cgroup control write",
        ));
    }
    Ok(())
}

fn write_current_process(procs: &File) -> io::Result<()> {
    // nix::write is the async-signal-safe write syscall; no PID formatting,
    // allocation, mutex acquisition or descriptor lookup occurs after fork.
    loop {
        match nix::unistd::write(procs, b"0") {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(io::Error::from_raw_os_error(nix::errno::Errno::EIO as i32)),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}

fn reset_oom_score_adj() -> io::Result<()> {
    // The agent is non-dumpable and a uid change keeps that, which makes
    // /proc/self root-owned; a non-root child could not open its own file.
    // exec recomputes dumpability anyway.
    nix::sys::prctl::set_dumpable(true).map_err(io::Error::from)?;
    let fd = open(
        c"/proc/self/oom_score_adj",
        OFlag::O_WRONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let result = loop {
        match nix::unistd::write(&fd, b"0") {
            Ok(1) => break Ok(()),
            Ok(_) => break Err(io::Error::from_raw_os_error(nix::errno::Errno::EIO as i32)),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => break Err(io::Error::from_raw_os_error(error as i32)),
        }
    };
    result.and(nix::unistd::close(fd).map_err(io::Error::from))
}

/// Parent-side read; the post-fork closure only writes when this is true.
fn agent_oom_protected() -> io::Result<bool> {
    let value = fs::read_to_string("/proc/self/oom_score_adj")?;
    let adjustment = value
        .trim()
        .parse::<i32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(adjustment < 0)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use crate::freezer::{lock, Controller, SpawnRole};
    use crate::freezer::{parse_event, same_object, WorkloadController};
    use crate::handoff::BootMode;
    use std::ffi::OsString;
    use std::fs::{self, File};
    use std::io;
    use std::sync::{Arc, Mutex};

    #[test]
    fn freezer_events_require_exact_unambiguous_kernel_state() {
        assert!(parse_event("populated 1\nfrozen 1\n", "frozen").unwrap());
        assert!(!parse_event("populated 0\nfrozen 0\n", "frozen").unwrap());
        for invalid in [
            "",
            "populated 1\n",
            "frozen 2\n",
            "frozen\n",
            "frozen 1 extra\n",
            "frozen 1\nfrozen 0\n",
        ] {
            assert_eq!(
                parse_event(invalid, "frozen").unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn freezer_descriptor_integrity_rejects_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("target");
        fs::write(&path, b"old").unwrap();
        let retained = File::open(&path).unwrap();
        same_object(&retained, &File::open(&path).unwrap()).unwrap();
        fs::rename(&path, directory.path().join("removed")).unwrap();
        fs::write(&path, b"new").unwrap();
        assert!(same_object(&retained, &File::open(&path).unwrap()).is_err());
    }

    #[test]
    fn freezer_directory_descriptors_reject_symlink_substitution() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", directory.path().join("alias")).unwrap();
        let parent = File::open(directory.path()).unwrap();
        assert!(crate::freezer::open_directory(&parent, "real").is_ok());
        assert!(crate::freezer::open_directory(&parent, "alias").is_err());
    }

    #[test]
    fn freezer_live_admission_names_unsupported_cold_profiles() {
        let controller = WorkloadController::discover();
        controller.qualify_profile(&BootMode::Standard);
        assert!(controller
            .unsupported_reason()
            .unwrap()
            .contains("Standard"));
        assert!(controller.close_spawn_admission().is_err());
        controller.qualify_profile(&BootMode::InitChild {
            requested_init: OsString::from("/sbin/init"),
            init_path: "/sbin/init".into(),
            containment_failure: "test observation failed".to_owned(),
        });
        assert!(controller
            .unsupported_reason()
            .unwrap()
            .contains("image init cgroup containment was not established"));
        for boot in [
            BootMode::AgentPid1 {
                requested_init: OsString::new(),
            },
            BootMode::ContainedInit {
                requested_init: OsString::from("/sbin/init"),
                init_path: "/sbin/init".into(),
            },
        ] {
            controller.qualify_profile(&boot);
            assert!(lock(&controller.inner.profile).is_none());
        }
    }

    #[test]
    fn required_protection_values_reject_missing_malformed_or_changed_observations() {
        use crate::freezer::Protection;

        for (protection, expected) in [
            (Protection::SiloMemoryMin, 16_777_216),
            (Protection::ControlMemoryMin, 16_777_216),
            (Protection::ControlCpuWeight, 1000),
            (Protection::WorkloadPidLimit, 32256),
            (Protection::AgentOomScoreAdj, -1000),
        ] {
            protection
                .qualify_value(&format!("{expected}\n"), expected)
                .unwrap();
            for observed in ["", "invalid", "max", "0", "1000 extra"] {
                let failure = protection.qualify_value(observed, expected).unwrap_err();
                assert_eq!(failure.protection, protection);
            }
            for changed in [expected - 1, expected + 1] {
                assert_eq!(
                    protection
                        .qualify_value(&changed.to_string(), expected)
                        .unwrap_err()
                        .protection,
                    protection,
                );
            }
        }
    }

    #[test]
    fn delegation_requires_memory_cpu_and_pids_at_every_ancestor() {
        use crate::freezer::{
            qualify_controllers, DelegationGroup, Protection, RequiredController,
        };

        for group in [
            DelegationGroup::Root,
            DelegationGroup::Silo,
            DelegationGroup::Workloads,
        ] {
            qualify_controllers("cpuset cpu io memory pids\n", group).unwrap();
            qualify_controllers("memory cpu pids\n", group).unwrap();
            for (controllers, missing) in [
                ("cpu pids\n", RequiredController::Memory),
                ("memory pids\n", RequiredController::Cpu),
                ("memory cpu\n", RequiredController::Pids),
            ] {
                assert_eq!(
                    qualify_controllers(controllers, group)
                        .unwrap_err()
                        .protection,
                    Protection::Delegation(group, missing),
                );
            }
            for invalid in ["", "cpuset io\n", "memory_hugetlb cpuacct pids_extra\n"] {
                assert!(qualify_controllers(invalid, group).is_err());
            }
        }
    }

    #[test]
    fn workload_pid_reserve_requires_positive_capacity() {
        assert_eq!(
            crate::freezer::workload_pid_limit("32768\n").unwrap(),
            32256
        );
        assert_eq!(crate::freezer::workload_pid_limit("513\n").unwrap(), 1);
        for invalid in [
            "",
            "invalid",
            "-1",
            "0",
            "511",
            "512",
            "18446744073709551616",
        ] {
            assert!(crate::freezer::workload_pid_limit(invalid).is_err());
        }
    }

    #[test]
    fn freezer_spawn_gate_is_reversible_and_hook_only_bypasses_workload_gate() {
        // Pure admission state, deliberately no pretend cgroup filesystem.
        let controller = WorkloadController {
            inner: Arc::new(Controller {
                targets: None,
                unavailable: Some("no kernel target in this unit test".to_owned()),
                protection_setup: Ok(()),
                profile: Mutex::new(None),
                spawn_gate: Mutex::default(),
                spawn_idle: tokio::sync::Notify::new(),
            }),
        };
        drop(controller.admit_spawn(SpawnRole::Workload).unwrap());
        lock(&controller.inner.spawn_gate).closed = true;
        assert_eq!(
            controller
                .admit_spawn(SpawnRole::Workload)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock,
        );
        drop(controller.admit_spawn(SpawnRole::ActivationHook).unwrap());
        lock(&controller.inner.spawn_gate).closed = false;
        drop(controller.admit_spawn(SpawnRole::Workload).unwrap());
        assert!(controller.is_frozen().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn freezer_spawn_drain_is_async_and_requires_parent_acknowledgement() {
        let controller = WorkloadController {
            inner: Arc::new(Controller {
                targets: None,
                unavailable: Some("no kernel target in this unit test".to_owned()),
                protection_setup: Ok(()),
                profile: Mutex::new(None),
                spawn_gate: Mutex::default(),
                spawn_idle: tokio::sync::Notify::new(),
            }),
        };
        let admitted = controller.admit_spawn(SpawnRole::Workload).unwrap();
        lock(&controller.inner.spawn_gate).closed = true;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                controller.wait_for_spawns(deadline),
            )
            .await
            .is_err(),
            "waiting for exec acknowledgement must yield the only runtime thread"
        );
        assert!(controller.admit_spawn(SpawnRole::Workload).is_err());
        drop(admitted);
        controller.wait_for_spawns(deadline).await.unwrap();
    }
}
