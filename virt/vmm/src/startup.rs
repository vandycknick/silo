use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::virt::VirtualMachine;
use eyre::Context;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use vm_spec::VmSpec;

use crate::context::{DaemonContext, RuntimeContext};
use crate::ext::VmSpecExt;
use crate::machine::{
    machine_identifier_path_from_dir, vm_spec_machine_config, RuntimeNetwork, VmSpecInputs,
};
use crate::start_request::StartRequestPipe;
use crate::state::{InstanceStore, RunLiveProfile};
use protocol::v1::VmState;

pub const ENV_STARTPIPE: &str = "_VM_STARTPIPE";
pub const ENV_SYNCPIPE: &str = "_VM_SYNCPIPE";
pub const ENV_MACHINE_LOG_DIR: &str = "_VM_MACHINE_LOG_DIR";
pub const ENV_MACHINE_LOCK: &str = "_VM_MACHINE_LOCK";
pub const ENV_NETD_EXIT: &str = "_VM_NETD_EXIT";
pub const ENV_STORAGE_LEASES: &str = "_VM_STORAGE_LEASES";
pub const ENV_RESTORE_OBJECTS: &str = "_VM_RESTORE_OBJECTS";

#[derive(Debug)]
pub struct InheritedPipeFds {
    pub startpipe: Option<RawFd>,
    pub syncpipe: Option<RawFd>,
    pub machine_log_dir: Option<RawFd>,
    pub machine_lock: Option<RawFd>,
    pub netd_exit: Option<RawFd>,
    pub storage_lease: Option<RawFd>,
    /// Restore objects then each lower's descriptor and extents, in request
    /// order. Validated read-only regular files, CLOEXEC from entry on.
    pub restore: Vec<RawFd>,
}

impl InheritedPipeFds {
    pub fn from_env() -> eyre::Result<Self> {
        let fds = Self {
            startpipe: parse_env_fd(ENV_STARTPIPE)?,
            syncpipe: parse_env_fd(ENV_SYNCPIPE)?,
            machine_log_dir: parse_env_fd(ENV_MACHINE_LOG_DIR)?,
            machine_lock: parse_env_fd(ENV_MACHINE_LOCK)?,
            netd_exit: parse_env_fd(ENV_NETD_EXIT)?,
            storage_lease: Some(parse_storage_lease_env()?),
            restore: crate::restore::inputs::parse_env(
                std::env::var_os(ENV_RESTORE_OBJECTS).as_deref(),
            )?,
        };
        let mut seen = std::collections::BTreeSet::new();
        for fd in [
            fds.startpipe,
            fds.syncpipe,
            fds.machine_log_dir,
            fds.machine_lock,
            fds.netd_exit,
            fds.storage_lease,
        ]
        .into_iter()
        .flatten()
        .chain(fds.restore.iter().copied())
        {
            eyre::ensure!(
                fd > 2 && seen.insert(fd),
                "inherited descriptors must be distinct and above stderr"
            );
        }
        fds.validate_set()?;
        crate::restore::inputs::validate_inherited(
            &fds.restore,
            &fds.descriptors().into_iter().flatten().collect::<Vec<_>>(),
        )?;
        for fd in fds
            .descriptors()
            .into_iter()
            .flatten()
            .chain(fds.restore.iter().copied())
        {
            set_cloexec(fd, true)?;
        }
        Ok(fds)
    }

    /// The inherited restore descriptor numbers, taken once.
    pub fn take_restore(&mut self) -> Vec<RawFd> {
        std::mem::take(&mut self.restore)
    }

    pub fn require_for_daemon(self) -> eyre::Result<Self> {
        if self.startpipe.is_none() || self.syncpipe.is_none() || self.machine_lock.is_none() {
            return Err(eyre::eyre!(
                "{ENV_STARTPIPE}, {ENV_SYNCPIPE}, and {ENV_MACHINE_LOCK} are required unless running with --foreground"
            ));
        }
        Ok(self)
    }

    fn descriptors(&self) -> [Option<RawFd>; 6] {
        [
            self.startpipe,
            self.syncpipe,
            self.machine_log_dir,
            self.machine_lock,
            self.netd_exit,
            self.storage_lease,
        ]
    }

    /// Validate every number and resource before any role takes ownership.
    fn validate_set(&self) -> eyre::Result<()> {
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        use nix::sys::stat::{fstat, SFlag};
        let mut identities = Vec::new();
        let mut numbers = Vec::new();
        #[cfg(target_os = "macos")]
        let mut pipes = Vec::new();
        for (index, raw) in self.descriptors().into_iter().enumerate() {
            let Some(raw) = raw else { continue };
            eyre::ensure!(
                raw >= 3 && !numbers.contains(&raw),
                "invalid or duplicated inherited descriptor"
            );
            numbers.push(raw);
            // nix requires a valid FD before constructing a borrow.
            eyre::ensure!(
                unsafe { nix::libc::fcntl(raw, nix::libc::F_GETFD) } >= 0,
                "invalid inherited descriptor {raw}"
            );
            let fd = unsafe { BorrowedFd::borrow_raw(raw) };
            let stat = fstat(fd)?;
            let identity = (stat.st_dev, stat.st_ino);
            eyre::ensure!(
                !identities.contains(&identity),
                "inherited descriptor roles alias a resource"
            );
            identities.push(identity);
            let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
            #[cfg(target_os = "macos")]
            if kind == SFlag::S_IFIFO {
                let identity = crate::krun::worker::fds::pipe_identity(raw)?;
                eyre::ensure!(!pipes.contains(&identity), "inherited roles alias a pipe");
                pipes.push(identity);
            }
            let access =
                OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?) & OFlag::O_ACCMODE;
            let valid = match index {
                0 => kind == SFlag::S_IFIFO && access == OFlag::O_RDONLY,
                1 | 4 => kind == SFlag::S_IFIFO && access == OFlag::O_WRONLY,
                2 => kind == SFlag::S_IFDIR,
                3 => {
                    kind == SFlag::S_IFREG
                        && access == OFlag::O_RDWR
                        && stat.st_uid == nix::unistd::geteuid().as_raw()
                        && stat.st_nlink == 1
                }
                5 => {
                    kind == SFlag::S_IFREG
                        && access == OFlag::O_RDWR
                        && stat.st_uid == nix::unistd::geteuid().as_raw()
                        && stat.st_mode & 0o7777 == 0o600
                        && stat.st_nlink == 1
                }
                _ => false,
            };
            eyre::ensure!(
                valid,
                "inherited descriptor has invalid type, access or ownership"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn configure_reexec(&self, command: &mut std::process::Command) -> io::Result<()> {
        use std::os::unix::process::CommandExt;
        let descriptors = self.descriptors();
        let restore = self.restore.clone();
        let mut ceiling =
            nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)?
                .0
                .min(i32::MAX as u64) as i32;
        let mut directory = nix::dir::Dir::open(
            "/dev/fd",
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?;
        for entry in directory.iter() {
            let entry = entry?;
            if let Some(raw) = entry
                .file_name()
                .to_str()
                .ok()
                .and_then(|name| name.parse::<i32>().ok())
            {
                ceiling = ceiling.max(raw.saturating_add(1));
            }
        }
        drop(directory);
        // SAFETY: fixed numeric allowlist and allocation-free fcntl errors.
        unsafe {
            command.pre_exec(move || {
                // Darwin lacks close_range(CLOEXEC). Scan the precomputed soft
                // limit without allocating or closing pre-exec-only handles.
                for raw in 3..ceiling {
                    let flags = nix::libc::fcntl(raw, nix::libc::F_GETFD);
                    if flags < 0 {
                        if *nix::libc::__error() == nix::libc::EBADF {
                            continue;
                        }
                        return Err(io::Error::last_os_error());
                    }
                    if nix::libc::fcntl(raw, nix::libc::F_SETFD, flags | nix::libc::FD_CLOEXEC) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                for raw in descriptors
                    .into_iter()
                    .flatten()
                    .chain(restore.iter().copied())
                {
                    let fd = BorrowedFd::borrow_raw(raw);
                    let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD)
                        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
                    nix::fcntl::fcntl(
                        fd,
                        nix::fcntl::FcntlArg::F_SETFD(
                            nix::fcntl::FdFlag::from_bits_retain(flags)
                                & !nix::fcntl::FdFlag::FD_CLOEXEC,
                        ),
                    )
                    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
                }
                Ok(())
            });
        }
        Ok(())
    }

    pub fn take_storage_lease(&mut self) -> eyre::Result<Arc<OwnedFd>> {
        let raw = self
            .storage_lease
            .take()
            .ok_or_else(|| eyre::eyre!("required generation lease is missing"))?;
        // SAFETY: the complete set was validated before entry, and this role is
        // adopted exactly once. Closing never unlocks other copies of the OFD.
        Ok(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
    }

    pub fn take_netd_exit(&mut self) -> eyre::Result<Option<File>> {
        let Some(fd) = self.netd_exit.take() else {
            return Ok(None);
        };
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let stat = nix::sys::stat::fstat(borrowed)?;
        eyre::ensure!(
            nix::sys::stat::SFlag::from_bits_truncate(stat.st_mode)
                .contains(nix::sys::stat::SFlag::S_IFIFO),
            "netd lifetime descriptor is not a pipe"
        );
        let flags = nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFL)?;
        eyre::ensure!(
            nix::fcntl::OFlag::from_bits_truncate(flags) & nix::fcntl::OFlag::O_ACCMODE
                == nix::fcntl::OFlag::O_WRONLY,
            "netd lifetime descriptor is not a writer"
        );
        set_cloexec(fd, true)?;
        Ok(Some(unsafe { File::from_raw_fd(fd) }))
    }

    pub fn take_machine_lock(&mut self) -> eyre::Result<Option<File>> {
        let Some(fd) = self.machine_lock.take() else {
            return Ok(None);
        };
        set_cloexec(fd, true)
            .map_err(|err| eyre::eyre!("set CLOEXEC on inherited machine lock fd {fd}: {err}"))?;
        Ok(Some(unsafe { File::from_raw_fd(fd) }))
    }
}

fn parse_storage_lease_env() -> eyre::Result<RawFd> {
    let encoded = std::env::var(ENV_STORAGE_LEASES)
        .map_err(|_| eyre::eyre!("{ENV_STORAGE_LEASES} is required for managed launch"))?;
    parse_storage_lease(&encoded)
}

fn parse_storage_lease(encoded: &str) -> eyre::Result<RawFd> {
    eyre::ensure!(
        encoded.len() <= 64,
        "storage lease environment exceeds 64 bytes"
    );
    let [raw]: [RawFd; 1] = serde_json::from_str(encoded)
        .map_err(|error| eyre::eyre!("invalid storage lease descriptor array: {error}"))?;
    eyre::ensure!(raw >= 3, "storage lease descriptor must be above stderr");
    Ok(raw)
}

pub struct SyncReporter {
    file: Option<File>,
    inherited: bool,
}

pub struct ParentLossMonitor {
    shutdown: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupCommandLaunchFailure<'a> {
    reason: Option<i32>,
    message: Option<&'a str>,
}

impl SyncReporter {
    pub fn from_fd(sync_fd: Option<RawFd>) -> io::Result<Self> {
        match sync_fd {
            Some(fd) => Self::from_sync_fd(fd),
            None => Self::from_stdout(),
        }
    }

    fn from_sync_fd(fd: RawFd) -> io::Result<Self> {
        set_cloexec(fd, true)?;
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self {
            file: Some(file),
            inherited: true,
        })
    }

    fn from_stdout() -> io::Result<Self> {
        let borrowed = unsafe { BorrowedFd::borrow_raw(libc::STDOUT_FILENO) };
        let duplicated = nix::unistd::dup(borrowed).map_err(io::Error::other)?;
        let file = File::from(duplicated);
        Ok(Self {
            file: Some(file),
            inherited: false,
        })
    }

    pub fn report_started(&mut self) -> io::Result<()> {
        self.write_message("started\n")
    }

    pub fn report_failed(&mut self, message: &str) -> io::Result<()> {
        self.write_message(&format!("failed\t{message}\n"))
    }

    pub fn report_startup_command_launch_failed(
        &mut self,
        reason: Option<i32>,
        message: Option<&str>,
    ) -> io::Result<()> {
        let failure = serde_json::to_string(&StartupCommandLaunchFailure { reason, message })
            .map_err(io::Error::other)?;
        self.write_message(&format!("startup-command-launch-failed\t{failure}\n"))
    }

    pub fn monitor_parent_loss(
        &self,
        cancelled: CancellationToken,
    ) -> io::Result<ParentLossMonitor> {
        if !self.inherited {
            return Ok(ParentLossMonitor {
                shutdown: CancellationToken::new(),
                task: None,
            });
        }
        let file = self.file.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "syncpipe reporter is closed")
        })?;
        let fd = nix::unistd::dup(file).map_err(io::Error::other)?;
        let shutdown = CancellationToken::new();
        let monitor_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            use nix::poll::{poll, PollFd, PollFlags, PollTimeout};

            let mut descriptors = [PollFd::new(
                fd.as_fd(),
                PollFlags::POLLERR | PollFlags::POLLHUP,
            )];
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(25));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = monitor_shutdown.cancelled() => return,
                    _ = interval.tick() => {
                        match poll(&mut descriptors, PollTimeout::ZERO) {
                            Ok(_) if descriptors[0].revents().is_some_and(|events| {
                                events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP)
                            }) => {
                                cancelled.cancel();
                                return;
                            }
                            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                            Err(_) => {
                                cancelled.cancel();
                                return;
                            }
                        }
                    }
                }
            }
        });
        Ok(ParentLossMonitor {
            shutdown,
            task: Some(task),
        })
    }

    fn write_message(&mut self, message: &str) -> io::Result<()> {
        let Some(mut file) = self.file.take() else {
            return Ok(());
        };
        file.write_all(message.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

impl ParentLossMonitor {
    pub async fn shutdown(mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// Retains the primary VM even when initialization returns before a context exists.
#[derive(Clone, Default)]
pub(crate) struct PrimaryMachine {
    machine: Arc<std::sync::Mutex<Option<VirtualMachine>>>,
    shutdown: Arc<std::sync::Mutex<Option<Arc<crate::guest::shutdown::ShutdownState>>>>,
}

impl PrimaryMachine {
    pub(crate) fn get(&self) -> Option<VirtualMachine> {
        self.machine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn shutdown_state(
        &self,
    ) -> eyre::Result<Option<Arc<crate::guest::shutdown::ShutdownState>>> {
        self.shutdown
            .lock()
            .map(|state| state.clone())
            .map_err(|_| eyre::eyre!("primary shutdown state poisoned"))
    }

    fn set(
        &self,
        machine: VirtualMachine,
        shutdown: Arc<crate::guest::shutdown::ShutdownState>,
    ) -> eyre::Result<()> {
        *self
            .machine
            .lock()
            .map_err(|_| eyre::eyre!("primary machine state poisoned"))? = Some(machine);
        *self
            .shutdown
            .lock()
            .map_err(|_| eyre::eyre!("primary shutdown state poisoned"))? = Some(shutdown);
        Ok(())
    }
}

pub(crate) struct InitInputs<'a> {
    pub(crate) primary_machine: &'a PrimaryMachine,
    pub(crate) machine_id: &'a str,
    pub(crate) machine_run_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) network_args: &'a [String],
    pub(crate) agent_enabled: bool,
    pub(crate) serial_file: File,
    /// Inherited restore descriptor numbers, validated at entry, not adopted.
    pub(crate) restore_fds: Vec<RawFd>,
}

pub(crate) struct InitResult {
    pub(crate) context: DaemonContext,
    pub(crate) startup_command: Option<crate::start_request::StartupCommand>,
    pub(crate) vsock_surface: Option<crate::vsock::VsockSurface>,
    pub(crate) startup_deadline: tokio::time::Instant,
    pub(crate) startup_cancel: CancellationToken,
    pub(crate) require_guest_ready: bool,
    /// A restored machine is prepared, parked and fenced: services run this
    /// before anything is exposed or `started` is reported.
    pub(crate) activation: Option<crate::restore::activation::Activation>,
}

pub async fn init(
    runtime: &RuntimeContext,
    inputs: InitInputs<'_>,
    start_request: &mut StartRequestPipe,
    startup_cancel: CancellationToken,
) -> eyre::Result<InitResult> {
    let InitInputs {
        machine_id,
        machine_run_id,
        name,
        network_args,
        agent_enabled,
        serial_file,
        primary_machine,
        restore_fds,
    } = inputs;
    let machine_uuid = crate::start_request::parse_uuid("machine ID", machine_id)?;
    let run_uuid = crate::start_request::parse_uuid("machine run ID", machine_run_id)?;
    let storage_lease = start_request.storage_lease()?;
    let mut start_request = tokio::select! {
        biased;
        () = startup_cancel.cancelled() => return Err(eyre::eyre!("startup cancelled before launch request")),
        result = start_request.read(machine_id, machine_run_id) => result?,
    };
    eyre::ensure!(
        start_request.restore.is_some() || restore_fds.is_empty(),
        "inherited restore descriptors require a restore start request"
    );
    let startup_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(start_request.effective_startup_budget_ms());
    let shutdown_state = Arc::new(
        crate::guest::shutdown::ShutdownState::new(start_request.storage_shutdown.clone())
            .map_err(eyre::Report::msg)?,
    );
    let spec = load_spec(runtime)?;
    spec.validate().map_err(|error| {
        eyre::eyre!(
            "validate vm spec at {}: {error}",
            runtime.config().display()
        )
    })?;
    let guest_services_enabled = agent_enabled;
    let network = parse_network_args(network_args)?;
    let backend_selection =
        crate::capabilities::ResolvedSelection::from_start(start_request.virt_backend.as_ref())?;
    let selected_backend = backend_selection.backend_kind()?;
    if let Some(restore) = &start_request.restore {
        validate_restore_destination(
            RestoreDestination {
                configuration: &restore.configuration,
                network: restore.network.as_ref(),
            },
            &spec,
            &network,
            selected_backend,
            guest_services_enabled,
        )?;
    }
    let rosetta_intent = resolve_rosetta_intent(
        &spec,
        selected_backend,
        guest_services_enabled,
        start_request.rosetta_intent,
    )?;
    let prepared_rosetta = prepare_rosetta(
        rosetta_intent,
        start_request.asset_directory.as_deref(),
        startup_deadline,
        startup_cancel.clone(),
    )
    .await?;

    tracing::info!(
        instance = %name,
        machine_id,
        agent_enabled = guest_services_enabled,
        "silo-vmm starting"
    );
    secure_machine_dir(runtime.dir())?;
    secure_machine_dir(runtime.runtime_dir())?;
    remove_stale_socket(runtime.socket())?;

    let vsock_filename = vm_spec::effective_vsock_filename(spec.vsock.as_ref());
    // A restored machine binds its public vsock surface only after Activate.
    let prepared_vsock = vsock_filename
        .filter(|_| start_request.restore.is_none())
        .map(|filename| {
            crate::vsock::PreparedVsockSurface::prepare(runtime.runtime_dir(), filename)
        })
        .transpose()?;
    let mux_filename = vsock_filename.and_then(|path| path.to_str());
    let mut machine_config = vm_spec_machine_config(VmSpecInputs {
        name,
        id: machine_id,
        data_dir: runtime.dir(),
        spec: &spec,
        network: &network,
        guest_services_enabled,
        selected_backend,
        rosetta_intent,
        prepared_rosetta,
    })?;
    machine_config.config = machine_config
        .config
        .with_storage_launch(crate::virt::StorageLaunch {
            machine_id: machine_id.to_string(),
            run_id: machine_run_id.to_string(),
            holder_path: runtime.runtime_dir().join("vm.storage-holder.json"),
            binding: start_request.storage_lease,
            lease: storage_lease,
        });
    let host_live = backend_selection.host_report()?;
    // Adopt the inherited state objects only once every destination check
    // passed; a refusal adopts nothing and no guest instruction runs.
    let activation = match start_request.restore.take() {
        Some(request) => {
            require_restore_capability(&host_live)?;
            let activation = crate::restore::activation::Activation::new(
                request.clone(),
                machine_uuid,
                run_uuid,
                &start_request.storage_shutdown,
                vsock_filename.map(Path::to_path_buf),
            )?;
            let files = crate::restore::inputs::adopt(restore_fds, &request)
                .map_err(|error| eyre::eyre!("adopt inherited restore descriptors: {error}"))?;
            machine_config.config =
                machine_config
                    .config
                    .with_restore(crate::virt::RestoreLaunch {
                        request,
                        files: Arc::new(files),
                    });
            Some(activation)
        }
        None => None,
    };
    #[cfg(feature = "mock-backend")]
    let machine_config = {
        let mut machine_config = machine_config;
        backend_selection.configure_mock(&mut machine_config.config);
        machine_config
    };
    let machine_live = backend_selection.machine_vector(host_live.live, &machine_config.config);
    // The run's capture identity: the same path-free configuration projection
    // libvm computes from this spec, bound to the inherited launch lease.
    let capture_context = machine_config.config.storage_launch().and_then(|launch| {
        crate::capabilities::capture_producer()
            .map_err(|error| error.to_string())
            .and_then(|producer| {
                crate::live::coordinator::capture::CaptureContext::new(
                    runtime.dir().to_path_buf(),
                    &spec,
                    launch,
                    producer,
                    host_live.backend,
                    host_live.lane,
                )
            })
            .map_err(|error| tracing::warn!(%error, "live capture cannot bind plans for this run"))
            .ok()
    });
    let store = Arc::new(InstanceStore::new(
        machine_uuid.hyphenated().to_string(),
        name.to_string(),
        guest_services_enabled,
        RunLiveProfile {
            run_id: run_uuid.hyphenated().to_string(),
            backend: host_live.backend,
            lane: host_live.lane,
            live: machine_live,
        },
    )?);
    let (machine, park_timeout) = create_virtual_machine(selected_backend, machine_config.config)?;
    primary_machine.set(machine.clone(), shutdown_state.clone())?;
    let live_gate = crate::live::gate::LiveGate::new();
    if activation.is_some() {
        // Host admission is closed from the first moment of a restore: no
        // service, listener or session is admitted before the exposure commit.
        live_gate.close();
    }
    let live = crate::live::coordinator::LiveCoordinator::new(
        machine_uuid,
        run_uuid,
        store.clone(),
        machine.clone(),
        live_gate.clone(),
        crate::live::coordinator::LiveTimeouts::default(),
        capture_context,
    )
    .map_err(eyre::Report::msg)?;
    let forwards = if activation.is_some() {
        crate::forward::ForwardTable::prepare_restored_machine(
            &spec.forwards,
            runtime.runtime_dir(),
            mux_filename,
            park_timeout,
            live_gate,
        )
        .await?
    } else {
        crate::forward::ForwardTable::prepare_machine(
            &spec.forwards,
            runtime.runtime_dir(),
            mux_filename,
            park_timeout,
            live_gate,
        )
        .await?
    };
    if !guest_services_enabled {
        forwards.set_agent_availability(crate::forward::GuestHalfAvailability::Unsupported);
    }

    let serial_console = machine.serial();
    serial_console
        .add_sink(tokio::fs::File::from_std(serial_file))
        .await;
    if let Some(machine_identifier) = machine_config.machine_identifier.as_ref() {
        if machine_identifier.was_generated() {
            let machine_identifier_path = machine_identifier_path_from_dir(runtime.dir());
            std::fs::write(machine_identifier_path, machine_identifier.bytes())?;
        }
    }

    if activation.is_some() {
        store.set_vm_state(VmState::Restoring, "vm restoring")?;
    } else {
        store.set_vm_state(VmState::Starting, "vm starting")?;
    }
    let registration = tokio::select! {
        biased;
        () = startup_cancel.cancelled() => Err(eyre::eyre!("forward registration cancelled")),
        () = tokio::time::sleep_until(startup_deadline) => Err(eyre::eyre!("forward registration exceeded startup deadline")),
        result = forwards.register_outbound(&machine) => result,
    };
    if let Err(error) = registration {
        return Err(cleanup_primary_start_failure(&machine, &forwards, error).await);
    }
    tracing::info!(
        event = "primary_vm_spawn",
        "starting primary VM after probe release"
    );
    let start_result = tokio::select! {
        biased;
        () = startup_cancel.cancelled() => Err(eyre::eyre!("primary VM startup cancelled")),
        () = tokio::time::sleep_until(startup_deadline) => Err(eyre::eyre!("primary VM startup deadline expired")),
        result = machine.start() => result.map_err(eyre::Report::from),
    };
    if let Err(error) = start_result {
        return Err(cleanup_primary_start_failure(&machine, &forwards, error).await);
    }
    if let Err(error) = machine.ensure_alive().await {
        return Err(cleanup_primary_start_failure(&machine, &forwards, error.into()).await);
    }
    if let Some(activation) = activation {
        // The backend returned at the native prepared barrier: installed,
        // parked and fenced. Nothing is exposed until activation commits.
        tracing::info!(activation = %activation.activation_id(), "restore prepared");
        publish_host_memory_reclaim(&machine, &store);
        return Ok(InitResult {
            context: DaemonContext {
                machine_id: machine_uuid,
                machine_run_id: run_uuid,
                guest_services_enabled,
                machine,
                serial_console,
                store,
                forwards,
                stop_requested: CancellationToken::new(),
                shutdown: CancellationToken::new(),
                shutdown_state,
                live,
            },
            startup_command: None,
            vsock_surface: None,
            startup_deadline,
            startup_cancel,
            require_guest_ready: false,
            activation: Some(activation),
        });
    }
    let vsock_surface = match prepared_vsock {
        Some(prepared) => {
            let activation = tokio::select! {
                biased;
                exit = machine.wait() => Err(eyre::eyre!("primary VM exited during vsock activation: {exit:?}")),
                () = startup_cancel.cancelled() => Err(eyre::eyre!("vsock activation cancelled")),
                () = tokio::time::sleep_until(startup_deadline) => Err(eyre::eyre!("vsock activation exceeded startup deadline")),
                result = prepared.activate(machine.clone(), forwards.clone()) => result,
            };
            match activation {
                Ok(surface) => Some(surface),
                Err(error) => {
                    return Err(cleanup_primary_start_failure(&machine, &forwards, error).await)
                }
            }
        }
        None => None,
    };
    forwards.activate(machine.clone());
    publish_host_memory_reclaim(&machine, &store);
    if let Err(error) = machine.ensure_alive().await {
        drop(vsock_surface);
        return Err(cleanup_primary_start_failure(&machine, &forwards, error.into()).await);
    }
    if let Err(error) = store.set_vm_state(VmState::Running, "vm running") {
        drop(vsock_surface);
        return Err(cleanup_primary_start_failure(&machine, &forwards, error.into()).await);
    }

    Ok(InitResult {
        context: DaemonContext {
            machine_id: machine_uuid,
            machine_run_id: run_uuid,
            guest_services_enabled,
            machine,
            serial_console,
            store,
            forwards,
            stop_requested: CancellationToken::new(),
            shutdown: CancellationToken::new(),
            shutdown_state,
            live,
        },
        startup_command: start_request.startup_command,
        vsock_surface,
        startup_deadline,
        startup_cancel,
        require_guest_ready: matches!(
            rosetta_intent,
            crate::virt::RosettaIntent::KrunCaptured { .. }
        ),
        activation: None,
    })
}

async fn cleanup_primary_start_failure(
    machine: &VirtualMachine,
    forwards: &crate::forward::ForwardTable,
    primary: eyre::Report,
) -> eyre::Report {
    let forward_result = forwards.shutdown().await;
    let stop_result = machine.stop().await;
    match (forward_result, stop_result) {
        (Ok(()), Ok(())) => primary,
        (Err(forward), Ok(())) => eyre::eyre!("{primary}; forward cleanup failed: {forward}"),
        (Ok(()), Err(stop)) => eyre::eyre!("{primary}; primary VM cleanup failed: {stop}"),
        (Err(forward), Err(stop)) => eyre::eyre!(
            "{primary}; forward cleanup failed: {forward}; primary VM cleanup failed: {stop}"
        ),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
async fn prepare_rosetta(
    intent: crate::virt::RosettaIntent,
    asset_directory: Option<&Path>,
    deadline: tokio::time::Instant,
    cancelled: CancellationToken,
) -> eyre::Result<Option<crate::krun::RosettaLaunchConfig>> {
    match intent {
        crate::virt::RosettaIntent::Disabled | crate::virt::RosettaIntent::VzNative => Ok(None),
        crate::virt::RosettaIntent::KrunCaptured { .. } => {
            let directory = asset_directory.ok_or_else(|| {
                eyre::eyre!("Rosetta acquisition requires the runtime asset directory")
            })?;
            crate::rosetta::acquire(directory.join("rprobe"), deadline, cancelled)
                .await
                .map(|prepared| Some(prepared.launch))
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
async fn prepare_rosetta(
    intent: crate::virt::RosettaIntent,
    _asset_directory: Option<&Path>,
    _deadline: tokio::time::Instant,
    _cancelled: CancellationToken,
) -> eyre::Result<Option<crate::krun::RosettaLaunchConfig>> {
    if !matches!(intent, crate::virt::RosettaIntent::Disabled) {
        return Err(eyre::eyre!("Rosetta requires an Apple silicon macOS host"));
    }
    Ok(None)
}

fn resolve_rosetta_intent(
    spec: &VmSpec,
    backend: crate::virt::BackendKind,
    agent_enabled: bool,
    request: Option<crate::start_request::RosettaIntentRequest>,
) -> eyre::Result<crate::virt::RosettaIntent> {
    use crate::start_request::RosettaIntentRequest;
    use crate::virt::{BackendKind, RosettaIntent, RosettaProfile};

    let requested = spec.rosetta_or_default();
    if !requested {
        return match request {
            None | Some(RosettaIntentRequest::Disabled {}) => Ok(RosettaIntent::Disabled),
            Some(_) => Err(eyre::eyre!(
                "silo-vmm start request enables Rosetta but the durable VM spec disables it"
            )),
        };
    }
    let request = request.ok_or_else(|| {
        eyre::eyre!(
            "Rosetta was requested but the start request does not establish a matching runtime and guest contract"
        )
    })?;
    if !agent_enabled {
        return Err(eyre::eyre!(
            "Rosetta requires the managed guest agent before VM construction"
        ));
    }
    if spec.nested_virtualization_or_default() {
        return Err(eyre::eyre!(
            "Rosetta does not support nested virtualization"
        ));
    }

    if request != (RosettaIntentRequest::Enabled {}) {
        return Err(eyre::eyre!(
            "Rosetta was requested but the start request disables it"
        ));
    }
    match backend {
        BackendKind::Vz => Ok(RosettaIntent::VzNative),
        BackendKind::Krun => Ok(RosettaIntent::KrunCaptured {
            profile: RosettaProfile::CapturedCompatibilityV1,
        }),
        #[cfg(feature = "mock-backend")]
        BackendKind::Mock => Err(eyre::eyre!("Rosetta is not supported by the mock backend")),
    }
}

fn create_virtual_machine(
    kind: crate::virt::BackendKind,
    config: crate::virt::VmConfig,
) -> eyre::Result<(VirtualMachine, std::time::Duration)> {
    let park_timeout = config.park_timeout();
    Ok((VirtualMachine::with_backend(kind, config)?, park_timeout))
}

fn secure_machine_dir(path: &std::path::Path) -> eyre::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .context(format!("secure machine directory {}", path.display()))
}

fn load_spec(runtime: &RuntimeContext) -> eyre::Result<VmSpec> {
    let raw = std::fs::read_to_string(runtime.config())
        .wrap_err_with(|| format!("read vm spec at {}", runtime.config().display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| eyre::eyre!("parse vm spec at {}: {}", runtime.config().display(), err))
}

/// What a restore request pins about the destination launch.
struct RestoreDestination<'a> {
    configuration: &'a vm_spec::capture::CaptureConfiguration,
    network: Option<&'a vm_spec::restore::RestoreNetwork>,
}

/// A restore continues the captured machine: the destination launch keeps
/// every captured execution pin, attaches the network the request
/// authorizes (and only that one) and runs the agent that activates it.
fn validate_restore_destination(
    destination: RestoreDestination<'_>,
    spec: &VmSpec,
    network: &RuntimeNetwork,
    backend: crate::virt::BackendKind,
    agent_enabled: bool,
) -> eyre::Result<()> {
    eyre::ensure!(
        backend == crate::virt::BackendKind::Krun,
        "restore requires the krun backend"
    );
    eyre::ensure!(agent_enabled, "restore activation requires the guest agent");
    let configuration =
        vm_spec::capture::CaptureConfiguration::from_spec(spec).map_err(eyre::Report::msg)?;
    eyre::ensure!(
        &configuration == destination.configuration,
        "destination launch changed the captured execution configuration"
    );
    match (network, destination.network) {
        (RuntimeNetwork::None, None) => Ok(()),
        (RuntimeNetwork::UnixDatagram { mac, .. }, Some(authorized))
            if mac.eq_ignore_ascii_case(&authorized.mac) =>
        {
            Ok(())
        }
        (RuntimeNetwork::UnixDatagram { .. }, Some(_)) => Err(eyre::eyre!(
            "restore destination network MAC differs from the attached network"
        )),
        _ => Err(eyre::eyre!(
            "restore destination network must be attached exactly when the request authorizes it"
        )),
    }
}

/// Same admission the manager applied before allocation, re-evaluated by
/// the executable actually running the restore.
fn require_restore_capability(report: &vm_spec::live::LiveHostReport) -> eyre::Result<()> {
    match &report
        .live
        .get(vm_spec::live::LiveOperation::Restore)
        .availability
    {
        vm_spec::live::LiveAvailability::Supported => Ok(()),
        vm_spec::live::LiveAvailability::Unsupported { reason } => Err(eyre::eyre!(
            "restore is unsupported on this host: {reason:?}"
        )),
    }
}

fn parse_network_args(values: &[String]) -> eyre::Result<RuntimeNetwork> {
    match values {
        [] => Ok(RuntimeNetwork::None),
        [value] => parse_network_arg(value),
        _ => Err(eyre::eyre!(
            "multiple --network attachments are not supported by this virt backend yet"
        )),
    }
}

fn parse_network_arg(value: &str) -> eyre::Result<RuntimeNetwork> {
    let parts = value.split(',').collect::<Vec<_>>();
    match parts.as_slice() {
        ["none"] => Ok(RuntimeNetwork::None),
        ["unixdg", path, mac] => Ok(RuntimeNetwork::UnixDatagram {
            path: PathBuf::from(path),
            mac: parse_key_value(mac, "mac")?.to_string(),
        }),
        _ => Err(eyre::eyre!("invalid --network value {value:?}")),
    }
}

fn parse_key_value<'a>(value: &'a str, key: &str) -> eyre::Result<&'a str> {
    let Some((actual_key, actual_value)) = value.split_once('=') else {
        return Err(eyre::eyre!("expected {key}=... in {value:?}"));
    };
    if actual_key != key || actual_value.is_empty() {
        return Err(eyre::eyre!("expected {key}=... in {value:?}"));
    }
    Ok(actual_value)
}

fn remove_stale_socket(path: &std::path::Path) -> eyre::Result<()> {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err).context(format!("remove stale socket {}", path.display()));
        }
    }

    Ok(())
}

fn parse_env_fd(name: &str) -> eyre::Result<Option<RawFd>> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(None);
    };
    let raw = raw
        .into_string()
        .map_err(|_| eyre::eyre!("{name} is not valid UTF-8"))?;
    if raw.is_empty() {
        return Err(eyre::eyre!("{name} is empty"));
    }
    let fd = raw
        .parse::<RawFd>()
        .map_err(|err| eyre::eyre!("parse {name}={raw:?}: {err}"))?;
    if fd < 0 {
        return Err(eyre::eyre!("{name} must be a non-negative fd"));
    }

    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD)
        .map_err(|err| eyre::eyre!("validate {name} fd {fd}: {err}"))?;

    Ok(Some(fd))
}

pub(crate) fn set_cloexec(fd: RawFd, enabled: bool) -> io::Result<()> {
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags =
        nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD).map_err(io::Error::other)?;
    let mut fd_flags = nix::fcntl::FdFlag::from_bits_retain(flags);
    if enabled {
        fd_flags.insert(nix::fcntl::FdFlag::FD_CLOEXEC);
    } else {
        fd_flags.remove(nix::fcntl::FdFlag::FD_CLOEXEC);
    }
    nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_SETFD(fd_flags))
        .map_err(io::Error::other)?;
    Ok(())
}

/// Mirrors the backend's host memory reclaim reports into the instance store so
/// `GetMetrics` callers see them. Ends when the backend drops its sender.
fn publish_host_memory_reclaim(machine: &VirtualMachine, store: &Arc<InstanceStore>) {
    let Some(mut updates) = machine.host_memory_reclaim_updates() else {
        return;
    };
    let store = Arc::clone(store);
    tokio::spawn(async move {
        loop {
            let report = *updates.borrow_and_update();
            if let Some(report) = report {
                let proto = protocol::v1::HostMemoryReclaim {
                    requested: Some(report.requested),
                    qualification: Some(report.qualification.to_string()),
                    effective: Some(report.effective),
                    released_bytes: Some(report.released_bytes),
                    released_extents: Some(report.released_extents),
                    retried_faults: Some(report.retried_faults),
                    skipped_reports: Some(report.skipped_reports),
                    failed_operations: Some(report.failed_operations),
                    observed_at: Some(prost_types::Timestamp::from(report.observed_at)),
                    backing: Some(report.backing.to_string()),
                    reason: Some(report.reason.to_string()),
                };
                if let Err(error) = store.set_host_memory_reclaim(proto) {
                    tracing::warn!(error = %error, "failed to record host memory reclaim report");
                }
            }
            if updates.changed().await.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use nix::unistd::pipe;

    use crate::machine::RuntimeNetwork;
    use crate::startup::{
        parse_network_arg, resolve_rosetta_intent, secure_machine_dir, SyncReporter,
    };

    #[tokio::test]
    async fn capabilities_nil_identities_fail_before_spec_or_backend_setup() {
        let root = std::env::temp_dir().join(format!("silo-vmm-nil-{}", uuid::Uuid::new_v4()));
        let runtime = crate::context::RuntimeContext::new(
            root.join("data"),
            root.join("run"),
            root.join("missing-config"),
            root.join("socket"),
        );
        let nil = uuid::Uuid::nil().to_string();
        let valid = uuid::Uuid::new_v4().to_string();
        for (machine_id, run_id) in [(&nil, &valid), (&valid, &nil)] {
            let primary = crate::startup::PrimaryMachine::default();
            let mut request =
                crate::start_request::StartRequestPipe::from_fd(None).expect("idle request");
            let result = crate::startup::init(
                &runtime,
                crate::startup::InitInputs {
                    primary_machine: &primary,
                    machine_id,
                    machine_run_id: run_id,
                    name: "nil-identity",
                    network_args: &[],
                    agent_enabled: false,
                    serial_file: std::fs::File::open("/dev/null").expect("null"),
                    restore_fds: Vec::new(),
                },
                &mut request,
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
            let error = match result {
                Ok(_) => panic!("nil identity must fail before startup"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("must not be the nil UUID"),
                "{error}"
            );
            assert!(
                !root.exists(),
                "invalid startup must not create runtime state"
            );
        }
    }

    fn rosetta_spec(enabled: bool) -> vm_spec::VmSpec {
        vm_spec::VmSpec {
            hardware: Some(vm_spec::Hardware {
                cpus: None,
                memory: None,
                nested_virtualization: Some(false),
                rosetta: Some(enabled),
            }),
            ..vm_spec::VmSpec::current()
        }
    }

    #[test]
    fn rosetta_intent_is_strictly_paired_with_spec_backend_and_agent() {
        use crate::start_request::RosettaIntentRequest;
        use crate::virt::{BackendKind, RosettaIntent, RosettaProfile};

        let disabled = rosetta_spec(false);
        assert_eq!(
            resolve_rosetta_intent(&disabled, BackendKind::Krun, false, None)
                .expect("old disabled request"),
            RosettaIntent::Disabled
        );
        assert!(resolve_rosetta_intent(
            &disabled,
            BackendKind::Vz,
            true,
            Some(RosettaIntentRequest::Enabled {})
        )
        .is_err());

        let enabled = rosetta_spec(true);
        for backend in [BackendKind::Vz, BackendKind::Krun] {
            assert!(resolve_rosetta_intent(&enabled, backend, true, None)
                .expect_err("enabled Rosetta requires parent contract metadata")
                .to_string()
                .contains("matching runtime and guest contract"));
        }
        assert_eq!(
            resolve_rosetta_intent(
                &enabled,
                BackendKind::Vz,
                true,
                Some(RosettaIntentRequest::Enabled {}),
            )
            .expect("paired VZ-native intent"),
            RosettaIntent::VzNative
        );
        assert_eq!(
            resolve_rosetta_intent(
                &enabled,
                BackendKind::Krun,
                true,
                Some(RosettaIntentRequest::Enabled {})
            )
            .expect("paired krun capture intent"),
            RosettaIntent::KrunCaptured {
                profile: RosettaProfile::CapturedCompatibilityV1
            }
        );
        assert!(resolve_rosetta_intent(
            &enabled,
            BackendKind::Krun,
            true,
            Some(RosettaIntentRequest::Disabled {})
        )
        .is_err());
        assert!(resolve_rosetta_intent(
            &enabled,
            BackendKind::Vz,
            false,
            Some(RosettaIntentRequest::Enabled {})
        )
        .is_err());
    }

    #[test]
    fn rosetta_rejects_nested_virtualization_before_backend_construction() {
        use crate::start_request::RosettaIntentRequest;
        use crate::virt::BackendKind;

        let mut spec = rosetta_spec(true);
        spec.hardware
            .as_mut()
            .expect("hardware")
            .nested_virtualization = Some(true);
        let error = resolve_rosetta_intent(
            &spec,
            BackendKind::Vz,
            true,
            Some(RosettaIntentRequest::Enabled {}),
        )
        .expect_err("reject nested virtualization");
        assert!(error.to_string().contains("nested virtualization"));
    }

    #[tokio::test]
    async fn malformed_start_request_fails_before_vm_spec_or_vmm_construction() {
        use crate::context::RuntimeContext;
        use crate::start_request::StartRequestPipe;
        use crate::startup::{init, InitInputs};

        let directory =
            std::env::temp_dir().join(format!("silo-vmm-order-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let serial_path = directory.join("serial.log");
        let serial_file = std::fs::File::create(&serial_path).expect("create serial file");
        let (read_fd, write_fd) = pipe().expect("create start pipe");
        let mut writer = std::fs::File::from(write_fd);
        std::io::Write::write_all(&mut writer, b"{invalid}\n").expect("write malformed request");
        drop(writer);
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("operation.lease"))
            .expect("lease");
        #[allow(deprecated)]
        nix::fcntl::flock(lease.as_raw_fd(), nix::fcntl::FlockArg::LockSharedNonblock)
            .expect("SH lease");
        let mut start_request = StartRequestPipe::from_fd(Some(read_fd.into_raw_fd()))
            .expect("open start request pipe")
            .with_storage_lease(std::sync::Arc::new(std::os::fd::OwnedFd::from(lease)));
        let machine_id = uuid::Uuid::new_v4().to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let runtime = RuntimeContext::new(
            directory.clone(),
            directory.clone(),
            directory.join("missing-vm-spec.json"),
            directory.join("vm.sock"),
        );
        let network = vec!["none".to_string()];

        let result = init(
            &runtime,
            InitInputs {
                primary_machine: &crate::startup::PrimaryMachine::default(),
                machine_id: &machine_id,
                machine_run_id: &run_id,
                name: "ordering-test",
                network_args: &network,
                agent_enabled: false,
                serial_file,
                restore_fds: Vec::new(),
            },
            &mut start_request,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("malformed request must fail"),
        };

        assert!(error.to_string().contains("parse silo-vmm start request"));
        assert!(!error.to_string().contains("read vm spec"));
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[tokio::test]
    async fn identity_and_size_boundaries_are_enforced_before_vm_spec_or_vmm_construction() {
        use crate::start_request::{VMM_START_REQUEST_MAX_BYTES, VMM_START_REQUEST_VERSION};

        let machine_id = uuid::Uuid::new_v4().to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let mismatch = encode_start_request(serde_json::json!({
            "version": VMM_START_REQUEST_VERSION,
            "machineId": uuid::Uuid::new_v4().to_string(),
            "machineRunId": run_id,
        }));
        let mismatch_error =
            init_error_for_start_request(mismatch, &machine_id, &run_id, Vec::new()).await;
        assert!(mismatch_error.contains("machineId does not match --id"));
        assert!(!mismatch_error.contains("read vm spec"));

        let base = serde_json::json!({
            "version": VMM_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupCommand": {
                "executionId": uuid::Uuid::new_v4().to_string(),
                "process": {
                    "argv": ["true"],
                    "environment": [{"name": "VALUE", "value": ""}]
                }
            }
        });
        let base_len = encode_start_request(base.clone()).len();
        let mut exact = base.clone();
        exact["startupCommand"]["process"]["environment"][0]["value"] =
            serde_json::json!("x".repeat(VMM_START_REQUEST_MAX_BYTES - base_len));
        let exact_error = init_error_for_start_request(
            encode_start_request(exact),
            &machine_id,
            &run_id,
            Vec::new(),
        )
        .await;
        assert!(exact_error.contains("read vm spec"));

        let mut oversized = base;
        oversized["startupCommand"]["process"]["environment"][0]["value"] =
            serde_json::json!("x".repeat(VMM_START_REQUEST_MAX_BYTES - base_len + 1));
        let oversized_error = init_error_for_start_request(
            encode_start_request(oversized),
            &machine_id,
            &run_id,
            Vec::new(),
        )
        .await;
        assert!(oversized_error.contains("exceeds 16777216 bytes"));
        assert!(!oversized_error.contains("read vm spec"));
    }

    #[tokio::test]
    async fn inherited_restore_descriptors_need_a_restore_request_before_vm_spec() {
        use crate::start_request::VMM_START_REQUEST_VERSION;

        let machine_id = uuid::Uuid::new_v4().to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let idle = encode_start_request(serde_json::json!({
            "version": VMM_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
        }));
        // Numbers only: nothing is adopted, so no descriptor is touched.
        let error = init_error_for_start_request(idle, &machine_id, &run_id, vec![900]).await;
        assert!(
            error.contains("inherited restore descriptors require a restore start request"),
            "{error}"
        );
        assert!(!error.contains("read vm spec"), "{error}");
    }

    #[test]
    fn restore_destination_keeps_captured_pins_and_authorized_network_only() {
        use crate::startup::{validate_restore_destination, RestoreDestination};
        use crate::virt::BackendKind;

        let spec = vm_spec::VmSpec::current();
        let pins = vm_spec::capture::CaptureConfiguration::from_spec(&spec).unwrap();
        let authorized = vm_spec::restore::RestoreNetwork {
            mac: "52:54:00:12:34:56".into(),
            ipv4: "10.0.0.2".parse().unwrap(),
            prefix_length: 24,
            gateway: "10.0.0.1".parse().unwrap(),
            dns_servers: Vec::new(),
            dns_search: Vec::new(),
        };
        let attached = |mac: &str| RuntimeNetwork::UnixDatagram {
            path: PathBuf::from("/run/netd.sock"),
            mac: mac.into(),
        };
        let check = |pins: &vm_spec::capture::CaptureConfiguration,
                     network: Option<&vm_spec::restore::RestoreNetwork>,
                     runtime: &RuntimeNetwork,
                     backend: BackendKind,
                     agent: bool| {
            validate_restore_destination(
                RestoreDestination {
                    configuration: pins,
                    network,
                },
                &spec,
                runtime,
                backend,
                agent,
            )
        };

        check(&pins, None, &RuntimeNetwork::None, BackendKind::Krun, true).unwrap();
        check(
            &pins,
            Some(&authorized),
            &attached("52:54:00:12:34:56"),
            BackendKind::Krun,
            true,
        )
        .unwrap();
        check(
            &pins,
            Some(&authorized),
            &attached("52:54:00:12:34:56".to_uppercase().as_str()),
            BackendKind::Krun,
            true,
        )
        .unwrap();

        let refusals = [
            check(&pins, None, &RuntimeNetwork::None, BackendKind::Vz, true),
            check(&pins, None, &RuntimeNetwork::None, BackendKind::Krun, false),
            check(
                &pins,
                Some(&authorized),
                &attached("52:54:00:12:34:57"),
                BackendKind::Krun,
                true,
            ),
            // Attached but not authorized, and authorized but not attached.
            check(
                &pins,
                None,
                &attached("52:54:00:12:34:56"),
                BackendKind::Krun,
                true,
            ),
            check(
                &pins,
                Some(&authorized),
                &RuntimeNetwork::None,
                BackendKind::Krun,
                true,
            ),
            check(
                &vm_spec::capture::CaptureConfiguration {
                    cpus: pins.cpus.wrapping_add(1),
                    ..pins.clone()
                },
                None,
                &RuntimeNetwork::None,
                BackendKind::Krun,
                true,
            ),
            check(
                &vm_spec::capture::CaptureConfiguration {
                    memory_mib: pins.memory_mib + 1,
                    ..pins.clone()
                },
                None,
                &RuntimeNetwork::None,
                BackendKind::Krun,
                true,
            ),
        ];
        for (index, refusal) in refusals.into_iter().enumerate() {
            assert!(refusal.is_err(), "case {index} was admitted");
        }
    }

    async fn init_error_for_start_request(
        encoded: Vec<u8>,
        machine_id: &str,
        run_id: &str,
        restore_fds: Vec<std::os::fd::RawFd>,
    ) -> String {
        use crate::context::RuntimeContext;
        use crate::start_request::StartRequestPipe;
        use crate::startup::{init, InitInputs};

        let directory = std::env::temp_dir().join(format!(
            "silo-vmm-start-order-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let serial_file =
            std::fs::File::create(directory.join("serial.log")).expect("create serial file");
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("operation.lease"))
            .expect("lease");
        #[allow(deprecated)]
        nix::fcntl::flock(lease.as_raw_fd(), nix::fcntl::FlockArg::LockSharedNonblock)
            .expect("SH lease");
        let stat = nix::sys::stat::fstat(&lease).expect("lease stat");
        let target_len = encoded.len();
        let mut request: serde_json::Value =
            serde_json::from_slice(&encoded).expect("fixture request");
        request["storageLease"]["fileDevice"] = serde_json::json!(stat.st_dev as u64);
        request["storageLease"]["fileInode"] = serde_json::json!(stat.st_ino as u64);
        let mut encoded = serde_json::to_vec(&request).expect("bound fixture request");
        // Keep the framing boundary under test while replacing maximal-width
        // fixture identities with the actual inherited inode.
        assert!(encoded.len() < target_len);
        encoded.resize(target_len - 1, b' ');
        encoded.push(b'\n');
        let lease = std::sync::Arc::new(std::os::fd::OwnedFd::from(lease));
        let (read_fd, write_fd) = pipe().expect("create start pipe");
        let writer = tokio::task::spawn_blocking(move || {
            let mut writer = std::fs::File::from(write_fd);
            std::io::Write::write_all(&mut writer, &encoded).expect("write start request");
        });
        let mut start_request = StartRequestPipe::from_fd(Some(read_fd.into_raw_fd()))
            .expect("open start request pipe")
            .with_storage_lease(lease);
        let runtime = RuntimeContext::new(
            directory.clone(),
            directory.clone(),
            directory.join("missing-vm-spec.json"),
            directory.join("vm.sock"),
        );
        let network = vec!["none".to_string()];
        let result = init(
            &runtime,
            InitInputs {
                primary_machine: &crate::startup::PrimaryMachine::default(),
                machine_id,
                machine_run_id: run_id,
                name: "start-order-test",
                network_args: &network,
                agent_enabled: false,
                serial_file,
                restore_fds,
            },
            &mut start_request,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        writer.await.expect("join start request writer");
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("start request should fail before VM construction"),
        };
        std::fs::remove_dir_all(directory).expect("remove test directory");
        error
    }

    fn encode_start_request(mut value: serde_json::Value) -> Vec<u8> {
        value["storageLease"] = serde_json::json!({
            "operationId":"33333333-3333-4333-8333-333333333333",
            "fileDevice":u64::MAX, "fileInode":u64::MAX
        });
        value["storageShutdown"] = serde_json::json!({
            "version":1, "machineId":value["machineId"], "runId":value["machineRunId"],
            "manifest":{"kind":"unsupported","reason":"startup ordering fixture"}
        });
        let mut encoded = serde_json::to_vec(&value).expect("encode start request");
        encoded.push(b'\n');
        encoded
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inherited_pipes_survive_macos_self_spawn() {
        use std::os::fd::AsRawFd;

        use crate::startup::{set_cloexec, InheritedPipeFds};

        let (start_read, _start_write) = pipe().expect("create start pipe");
        let (_sync_read, sync_write) = pipe().expect("create sync pipe");
        set_cloexec(start_read.as_raw_fd(), true).expect("set start CLOEXEC");
        set_cloexec(sync_write.as_raw_fd(), true).expect("set sync CLOEXEC");

        let inherited = InheritedPipeFds {
            startpipe: Some(start_read.as_raw_fd()),
            syncpipe: Some(sync_write.as_raw_fd()),
            machine_log_dir: None,
            machine_lock: None,
            netd_exit: None,
            storage_lease: None,
            restore: Vec::new(),
        };
        let mut child = std::process::Command::new("/bin/sh");
        child.arg("-c").arg(format!(
            "test -e /dev/fd/{} && test -e /dev/fd/{}",
            start_read.as_raw_fd(),
            sync_write.as_raw_fd()
        ));
        inherited
            .configure_reexec(&mut child)
            .expect("configure daemon child");
        assert!(child.status().expect("daemon reexec inheritance").success());

        for fd in [start_read.as_raw_fd(), sync_write.as_raw_fd()] {
            let flags = nix::fcntl::fcntl(
                unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) },
                nix::fcntl::FcntlArg::F_GETFD,
            )
            .expect("read fd flags");
            assert!(nix::fcntl::FdFlag::from_bits_retain(flags)
                .contains(nix::fcntl::FdFlag::FD_CLOEXEC));
        }
    }

    #[test]
    fn netd_lifetime_writer_is_owned_and_not_inherited_by_exec_children() {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let fd = writer.into_raw_fd();
        let mut inherited = crate::startup::InheritedPipeFds {
            startpipe: None,
            syncpipe: None,
            machine_log_dir: None,
            machine_lock: None,
            netd_exit: Some(fd),
            storage_lease: None,
            restore: Vec::new(),
        };
        let lease = inherited
            .take_netd_exit()
            .expect("validate writer")
            .expect("lease");
        let flags = nix::fcntl::fcntl(&lease, nix::fcntl::FcntlArg::F_GETFD).expect("flags");
        assert!(
            nix::fcntl::FdFlag::from_bits_retain(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC)
        );
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("10")
            .spawn()
            .expect("exec child");
        drop(lease);
        use std::io::Read;
        use std::os::fd::AsFd;
        let mut polls = [nix::poll::PollFd::new(
            reader.as_fd(),
            nix::poll::PollFlags::POLLHUP,
        )];
        nix::poll::poll(&mut polls, 1000u16).expect("poll");
        let closed = polls[0]
            .revents()
            .expect("events")
            .contains(nix::poll::PollFlags::POLLHUP);
        child.kill().expect("kill sleep");
        child.wait().expect("reap sleep");
        assert!(
            closed,
            "exec child retained lifetime writer {}",
            reader.as_raw_fd()
        );
        assert_eq!(reader.read(&mut [0u8; 1]).expect("EOF"), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inherited_pipes_deliver_request_and_sync_across_exec() {
        use std::io::{Read as _, Write as _};
        use std::os::fd::AsRawFd;
        use std::process::{Command, Stdio};

        use crate::startup::InheritedPipeFds;

        let (start_read, start_write) = pipe().expect("create start pipe");
        let (sync_read, sync_write) = pipe().expect("create sync pipe");
        let inherited = InheritedPipeFds {
            startpipe: Some(start_read.as_raw_fd()),
            syncpipe: Some(sync_write.as_raw_fd()),
            machine_log_dir: None,
            machine_lock: None,
            netd_exit: None,
            storage_lease: None,
            restore: Vec::new(),
        };
        let script = format!(
            "IFS= read -r line <&{}; printf 'received:%s\\n' \"$line\" >&{}",
            start_read.as_raw_fd(),
            sync_write.as_raw_fd()
        );
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        inherited
            .configure_reexec(&mut command)
            .expect("configure daemon child");
        let mut child = command.spawn().expect("spawn inherited-fd child");
        drop(start_read);
        drop(sync_write);

        let mut writer = std::fs::File::from(start_write);
        writer
            .write_all(b"{\"version\":1}\n")
            .expect("write start request");
        drop(writer);
        let mut reader = std::fs::File::from(sync_read);
        let mut response = String::new();
        reader
            .read_to_string(&mut response)
            .expect("read sync response");

        assert!(child.wait().expect("wait for child").success());
        assert_eq!(response, "received:{\"version\":1}\n");
    }

    #[test]
    fn machine_directory_is_restricted_to_its_owner() {
        let directory =
            std::env::temp_dir().join(format!("silo-vmm-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test machine directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))
            .expect("make legacy directory permissive");

        secure_machine_dir(&directory).expect("secure machine directory");

        assert_eq!(
            std::fs::metadata(&directory)
                .expect("machine directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::remove_dir(directory).expect("remove test machine directory");
    }

    #[test]
    fn sync_reporter_writes_started_once() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut reporter =
            SyncReporter::from_fd(Some(write_fd.into_raw_fd())).expect("open sync reporter");

        reporter.report_started().expect("report started");

        let mut file = std::fs::File::from(read_fd);
        let mut message = String::new();
        file.read_to_string(&mut message).expect("read message");
        assert_eq!(message, "started\n");
    }

    #[test]
    fn sync_reporter_writes_failed_once() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut reporter =
            SyncReporter::from_fd(Some(write_fd.into_raw_fd())).expect("open sync reporter");

        reporter.report_failed("vz failed").expect("report failure");

        let mut file = std::fs::File::from(read_fd);
        let mut message = String::new();
        file.read_to_string(&mut message).expect("read message");
        assert_eq!(message, "failed\tvz failed\n");
    }

    #[test]
    fn sync_reporter_writes_structured_startup_command_launch_failure() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut reporter =
            SyncReporter::from_fd(Some(write_fd.into_raw_fd())).expect("open sync reporter");

        reporter
            .report_startup_command_launch_failed(Some(1), Some("command was not found"))
            .expect("report startup command launch failure");

        let mut file = std::fs::File::from(read_fd);
        let mut message = String::new();
        file.read_to_string(&mut message).expect("read message");
        assert_eq!(
            message,
            "startup-command-launch-failed\t{\"reason\":1,\"message\":\"command was not found\"}\n"
        );
    }

    #[tokio::test]
    async fn syncpipe_parent_loss_cancels_owned_startup() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let reporter =
            SyncReporter::from_fd(Some(write_fd.into_raw_fd())).expect("open sync reporter");
        let cancelled = tokio_util::sync::CancellationToken::new();
        let monitor = reporter
            .monitor_parent_loss(cancelled.clone())
            .expect("monitor parent loss");

        drop(read_fd);
        tokio::time::timeout(std::time::Duration::from_secs(1), cancelled.cancelled())
            .await
            .expect("parent loss should cancel startup");
        monitor.shutdown().await;
    }

    #[tokio::test]
    async fn shutting_down_parent_monitor_closes_duplicate_without_cancelling_completed_startup() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut reporter =
            SyncReporter::from_fd(Some(write_fd.into_raw_fd())).expect("open sync reporter");
        let cancelled = tokio_util::sync::CancellationToken::new();
        let monitor = reporter
            .monitor_parent_loss(cancelled.clone())
            .expect("monitor parent loss");

        monitor.shutdown().await;
        assert!(!cancelled.is_cancelled());
        reporter.report_started().expect("complete startup");

        let mut file = std::fs::File::from(read_fd);
        let mut message = String::new();
        file.read_to_string(&mut message)
            .expect("monitor duplicate must not retain the writer");
        assert_eq!(message, "started\n");
    }

    #[tokio::test]
    async fn direct_vmm_stdout_reporter_does_not_monitor_parent_loss() {
        let reporter = SyncReporter::from_fd(None).expect("open stdout reporter");
        let cancelled = tokio_util::sync::CancellationToken::new();
        let monitor = reporter
            .monitor_parent_loss(cancelled.clone())
            .expect("direct reporter does not require a syncpipe");

        assert!(monitor.task.is_none());
        monitor.shutdown().await;
        assert!(!cancelled.is_cancelled());
    }

    #[test]
    fn network_parser_rejects_unsupported_runtime_attachments() {
        assert!(parse_network_arg("vznat").is_err());
        assert!(parse_network_arg("unixstream,/tmp/net.sock,mac=02:00:00:00:00:01").is_err());
        assert!(parse_network_arg("tap,tap0,mac=02:00:00:00:00:01").is_err());
    }

    #[test]
    fn network_parser_accepts_supported_runtime_attachments() {
        assert_eq!(parse_network_arg("none").unwrap(), RuntimeNetwork::None);
        assert_eq!(
            parse_network_arg("unixdg,/tmp/net.sock,mac=02:00:00:00:00:01").unwrap(),
            RuntimeNetwork::UnixDatagram {
                path: PathBuf::from("/tmp/net.sock"),
                mac: "02:00:00:00:00:01".to_string()
            }
        );
    }

    #[test]
    fn generation_lease_environment_is_one_bounded_integer_array() {
        use crate::startup::parse_storage_lease;
        assert_eq!(parse_storage_lease("[3]").unwrap(), 3);
        assert_eq!(parse_storage_lease("[2147483647]").unwrap(), i32::MAX);
        assert_eq!(
            parse_storage_lease(&format!("{}[3]", " ".repeat(61))).unwrap(),
            3
        );
        for invalid in [
            "",
            "3",
            "[]",
            "[3,4]",
            "[3,3]",
            "[2]",
            "[-1]",
            "[2147483648]",
            "[3.0]",
            "[3e0]",
            "[\"3\"]",
            "[true]",
            "[null]",
            "[03]",
            "[3]x",
        ] {
            assert!(parse_storage_lease(invalid).is_err(), "{invalid:?}");
        }
        assert!(parse_storage_lease(&format!("{}[3]", " ".repeat(62))).is_err());
    }

    #[test]
    fn inherited_set_rejects_aliases_before_ownership_and_lease_is_taken_once() {
        use crate::startup::InheritedPipeFds;
        use std::os::fd::{AsFd, AsRawFd, IntoRawFd};
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!(
            "monitor-inheritance-{}.lease",
            uuid::Uuid::new_v4()
        ));
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let duplicate = lease.try_clone().unwrap();
        let mut inherited = InheritedPipeFds {
            startpipe: None,
            syncpipe: None,
            machine_log_dir: None,
            machine_lock: Some(duplicate.as_raw_fd()),
            netd_exit: None,
            storage_lease: Some(lease.as_raw_fd()),
            restore: Vec::new(),
        };
        assert!(
            inherited.validate_set().is_err(),
            "distinct numbers alias the same inode"
        );
        nix::fcntl::fcntl(&lease, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        nix::fcntl::fcntl(&duplicate, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        inherited.machine_lock = None;
        inherited.validate_set().unwrap();
        let raw = lease.into_raw_fd();
        assert_eq!(inherited.storage_lease, Some(raw));
        let adopted = inherited.take_storage_lease().unwrap();
        assert!(
            inherited.take_storage_lease().is_err(),
            "cannot double-adopt a raw descriptor"
        );
        nix::fcntl::fcntl(adopted.as_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
        drop(adopted);
        drop(duplicate);
        std::fs::remove_file(path).unwrap();
    }
}
