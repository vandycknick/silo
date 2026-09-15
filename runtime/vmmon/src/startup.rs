use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, RawFd};
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
use crate::state::{new_instance_store_with_backend, InstanceStore};
use protocol::v1::VmState;

pub const ENV_STARTPIPE: &str = "_VM_STARTPIPE";
pub const ENV_SYNCPIPE: &str = "_VM_SYNCPIPE";
pub const ENV_MACHINE_LOG_DIR: &str = "_VM_MACHINE_LOG_DIR";
pub const ENV_MACHINE_LOCK: &str = "_VM_MACHINE_LOCK";

#[derive(Clone, Copy, Debug)]
pub struct InheritedPipeFds {
    pub startpipe: Option<RawFd>,
    pub syncpipe: Option<RawFd>,
    pub machine_log_dir: Option<RawFd>,
    pub machine_lock: Option<RawFd>,
}

impl InheritedPipeFds {
    pub fn from_env() -> eyre::Result<Self> {
        Ok(Self {
            startpipe: parse_env_fd(ENV_STARTPIPE)?,
            syncpipe: parse_env_fd(ENV_SYNCPIPE)?,
            machine_log_dir: parse_env_fd(ENV_MACHINE_LOG_DIR)?,
            machine_lock: parse_env_fd(ENV_MACHINE_LOCK)?,
        })
    }

    pub fn require_for_daemon(self) -> eyre::Result<Self> {
        if self.startpipe.is_none() || self.syncpipe.is_none() || self.machine_lock.is_none() {
            return Err(eyre::eyre!(
                "{ENV_STARTPIPE}, {ENV_SYNCPIPE}, and {ENV_MACHINE_LOCK} are required unless running with --foreground"
            ));
        }
        Ok(self)
    }

    #[cfg(target_os = "macos")]
    pub fn clear_cloexec(self) -> eyre::Result<()> {
        for fd in [
            self.startpipe,
            self.syncpipe,
            self.machine_log_dir,
            self.machine_lock,
        ]
        .into_iter()
        .flatten()
        {
            set_cloexec(fd, false).map_err(|err| eyre::eyre!("clear CLOEXEC on fd {fd}: {err}"))?;
        }
        Ok(())
    }

    pub fn take_machine_lock(self) -> eyre::Result<Option<File>> {
        let Some(fd) = self.machine_lock else {
            return Ok(None);
        };
        set_cloexec(fd, true)
            .map_err(|err| eyre::eyre!("set CLOEXEC on inherited machine lock fd {fd}: {err}"))?;
        Ok(Some(unsafe { File::from_raw_fd(fd) }))
    }
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

pub(crate) struct InitInputs<'a> {
    pub(crate) machine_id: &'a str,
    pub(crate) machine_run_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) network_args: &'a [String],
    pub(crate) agent_enabled: bool,
    pub(crate) krun_path: &'a Path,
    pub(crate) serial_file: File,
}

pub(crate) struct InitResult {
    pub(crate) context: DaemonContext,
    pub(crate) startup_command: Option<crate::start_request::StartupCommand>,
    pub(crate) vsock_surface: Option<crate::vsock::VsockSurface>,
    pub(crate) startup_deadline: tokio::time::Instant,
    pub(crate) startup_cancel: CancellationToken,
    pub(crate) require_guest_ready: bool,
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
        krun_path,
        serial_file,
    } = inputs;
    let start_request = start_request.read(machine_id, machine_run_id).await?;
    let startup_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(start_request.effective_startup_budget_ms());
    let spec = load_spec(runtime)?;
    spec.validate().map_err(|error| {
        eyre::eyre!(
            "validate vm spec at {}: {error}",
            runtime.config().display()
        )
    })?;
    let guest_services_enabled = agent_enabled;
    let network = parse_network_args(network_args)?;
    let selected_backend = resolve_backend(start_request.virt_backend.as_ref())?;
    let rosetta_intent = resolve_rosetta_intent(
        &spec,
        selected_backend,
        guest_services_enabled,
        start_request.rosetta_intent,
    )?;
    let prepared_rosetta = prepare_rosetta(
        rosetta_intent,
        start_request.rosetta_probe_assets.clone(),
        startup_deadline,
        startup_cancel.clone(),
    )
    .await?;

    tracing::info!(
        instance = %name,
        machine_id,
        agent_enabled = guest_services_enabled,
        "vmmon starting"
    );
    secure_machine_dir(runtime.dir())?;
    secure_machine_dir(runtime.runtime_dir())?;
    remove_stale_socket(runtime.socket())?;

    let prepared_vsock = vm_spec::effective_vsock_filename(spec.vsock.as_ref())
        .map(|filename| {
            crate::vsock::PreparedVsockSurface::prepare(runtime.runtime_dir(), filename)
        })
        .transpose()?;
    let mux_filename =
        vm_spec::effective_vsock_filename(spec.vsock.as_ref()).and_then(|path| path.to_str());
    let forwards = crate::forward::ForwardTable::prepare_machine(
        &spec.forwards,
        runtime.runtime_dir(),
        mux_filename,
    )
    .await?;
    if !guest_services_enabled {
        forwards.set_agent_availability(crate::forward::GuestHalfAvailability::Unsupported);
    }

    let machine_config = vm_spec_machine_config(VmSpecInputs {
        name,
        id: machine_id,
        data_dir: runtime.dir(),
        spec: &spec,
        network: &network,
        guest_services_enabled,
        krun_path,
        host_memory_reclaim: match start_request.host_memory_reclaim {
            crate::start_request::HostMemoryReclaimRequest::Auto => {
                crate::virt::HostMemoryReclaim::Auto
            }
            crate::start_request::HostMemoryReclaimRequest::Off => {
                crate::virt::HostMemoryReclaim::Off
            }
        },
        selected_backend,
        rosetta_intent,
        prepared_rosetta,
    })?;
    let machine = create_virtual_machine(
        selected_backend,
        start_request.virt_backend.as_ref(),
        machine_config.config,
    )?;
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

    let machine_id = uuid::Uuid::parse_str(machine_id)
        .map_err(|error| eyre::eyre!("invalid machine UUID {machine_id}: {error}"))?;
    let machine_run_id = uuid::Uuid::parse_str(machine_run_id)
        .map_err(|error| eyre::eyre!("invalid machine run UUID {machine_run_id}: {error}"))?;
    let store = Arc::new(new_instance_store_with_backend(
        machine_id.hyphenated().to_string(),
        name.to_string(),
        guest_services_enabled,
        selected_backend.name().to_string(),
    ));

    store.set_vm_state(VmState::Starting, "vm starting")?;
    forwards.register_outbound(&machine).await?;
    tracing::info!(
        event = "primary_vm_spawn",
        "starting primary VM after probe release"
    );
    let start_result = tokio::select! {
        result = tokio::time::timeout_at(startup_deadline, machine.start()) => {
            match result {
                Ok(result) => result.map_err(eyre::Report::from),
                Err(_) => Err(eyre::eyre!("primary VM startup deadline expired")),
            }
        }
        () = startup_cancel.cancelled() => {
            Err(eyre::eyre!("primary VM startup cancelled"))
        }
    };
    if let Err(error) = start_result {
        return Err(cleanup_primary_start_failure(&machine, &forwards, error).await);
    }
    let vsock_surface = match prepared_vsock {
        Some(prepared) => match prepared.activate(machine.clone(), forwards.clone()).await {
            Ok(surface) => Some(surface),
            Err(error) => {
                return Err(cleanup_primary_start_failure(&machine, &forwards, error).await);
            }
        },
        None => None,
    };
    forwards.activate(machine.clone());
    publish_host_memory_reclaim(&machine, &store);
    if let Err(error) = store.set_vm_state(VmState::Running, "vm running") {
        drop(vsock_surface);
        return Err(cleanup_primary_start_failure(&machine, &forwards, error.into()).await);
    }

    Ok(InitResult {
        context: DaemonContext {
            machine_id,
            machine_run_id,
            guest_services_enabled,
            machine,
            serial_console,
            store,
            forwards,
            stop_requested: CancellationToken::new(),
            shutdown: CancellationToken::new(),
        },
        startup_command: start_request.startup_command,
        vsock_surface,
        startup_deadline,
        startup_cancel,
        require_guest_ready: matches!(
            rosetta_intent,
            crate::virt::RosettaIntent::KrunCaptured { .. }
        ),
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
    assets: Option<crate::start_request::RosettaProbeAssetsRequest>,
    deadline: tokio::time::Instant,
    cancelled: CancellationToken,
) -> eyre::Result<Option<krun::RosettaLaunchConfig>> {
    match intent {
        crate::virt::RosettaIntent::Disabled | crate::virt::RosettaIntent::VzNative => {
            if assets.is_some() {
                return Err(eyre::eyre!(
                    "Rosetta probe assets were supplied for a non-probe start"
                ));
            }
            Ok(None)
        }
        crate::virt::RosettaIntent::KrunCaptured { profile } => {
            let assets =
                assets.ok_or_else(|| eyre::eyre!("KrunCaptured probe assets are missing"))?;
            let profile = match profile {
                crate::virt::RosettaProfile::CapturedCompatibilityV1 => {
                    crate::start_request::RosettaProfileRequest::CapturedCompatibilityV1
                }
            };
            crate::rosetta::acquire(profile, assets, deadline, cancelled)
                .await
                .map(|prepared| Some(prepared.launch))
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
async fn prepare_rosetta(
    intent: crate::virt::RosettaIntent,
    assets: Option<crate::start_request::RosettaProbeAssetsRequest>,
    _deadline: tokio::time::Instant,
    _cancelled: CancellationToken,
) -> eyre::Result<Option<krun::RosettaLaunchConfig>> {
    if !matches!(intent, crate::virt::RosettaIntent::Disabled) || assets.is_some() {
        return Err(eyre::eyre!(
            "captured Rosetta requires an Apple silicon macOS host"
        ));
    }
    Ok(None)
}

/// Construct the machine on the backend the start request selects; absent
/// selection means the platform default. Selecting "mock" in a vmmon built
/// without the mock-backend feature fails cleanly (surfaced on the syncpipe
/// as a start failure).
fn resolve_backend(
    virt_backend: Option<&crate::start_request::VirtBackendRequest>,
) -> eyre::Result<crate::virt::BackendKind> {
    let kind = match virt_backend {
        None => crate::virt::BackendKind::default_for_host()?,
        Some(backend) if backend.kind == "krun" => crate::virt::BackendKind::Krun,
        Some(backend) if backend.kind == "vz" => crate::virt::BackendKind::Vz,
        Some(backend) if backend.kind == "mock" => {
            #[cfg(feature = "mock-backend")]
            {
                crate::virt::BackendKind::Mock
            }
            #[cfg(not(feature = "mock-backend"))]
            {
                return Err(crate::virt::VirtError::UnsupportedBackend {
                    kind: "mock",
                    reason: "vmmon was built without the mock-backend feature".to_string(),
                }
                .into());
            }
        }
        Some(backend) => {
            return Err(eyre::eyre!(
                "start request selected unknown virt backend {:?}",
                backend.kind
            ))
        }
    };
    if !crate::virt::BackendKind::compiled().contains(&kind) {
        return Err(crate::virt::VirtError::UnsupportedBackend {
            kind: kind.name(),
            reason: "backend is not compiled into this vmmon binary".to_string(),
        }
        .into());
    }
    Ok(kind)
}

fn resolve_rosetta_intent(
    spec: &VmSpec,
    backend: crate::virt::BackendKind,
    agent_enabled: bool,
    request: Option<crate::start_request::RosettaIntentRequest>,
) -> eyre::Result<crate::virt::RosettaIntent> {
    use crate::start_request::{RosettaIntentRequest, RosettaProfileRequest};
    use crate::virt::{BackendKind, RosettaIntent, RosettaProfile};

    let requested = spec.rosetta_or_default();
    if !requested {
        return match request {
            None | Some(RosettaIntentRequest::Disabled) => Ok(RosettaIntent::Disabled),
            Some(_) => Err(eyre::eyre!(
                "vmmon start request enables Rosetta but the durable VM spec disables it"
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

    let expected = match backend {
        BackendKind::Vz => RosettaIntentRequest::VzNative,
        BackendKind::Krun => RosettaIntentRequest::KrunCaptured {
            profile: RosettaProfileRequest::CapturedCompatibilityV1,
        },
        #[cfg(feature = "mock-backend")]
        BackendKind::Mock => {
            return Err(eyre::eyre!("Rosetta is not supported by the mock backend"))
        }
    };
    if request != expected {
        return Err(eyre::eyre!(
            "Rosetta start-request intent does not agree with backend {} and the durable VM spec",
            backend.name()
        ));
    }

    match request {
        RosettaIntentRequest::Disabled => Err(eyre::eyre!(
            "Rosetta was requested but the start request disables it"
        )),
        RosettaIntentRequest::VzNative => Ok(RosettaIntent::VzNative),
        RosettaIntentRequest::KrunCaptured {
            profile: RosettaProfileRequest::CapturedCompatibilityV1,
        } => Ok(RosettaIntent::KrunCaptured {
            profile: RosettaProfile::CapturedCompatibilityV1,
        }),
    }
}

fn create_virtual_machine(
    kind: crate::virt::BackendKind,
    request: Option<&crate::start_request::VirtBackendRequest>,
    config: crate::virt::VmConfig,
) -> eyre::Result<VirtualMachine> {
    #[cfg(feature = "mock-backend")]
    let config = {
        let mut config = config;
        if kind == crate::virt::BackendKind::Mock {
            if let Some(scenario) = request.and_then(|request| request.scenario.as_ref()) {
                config.set_mock_scenario(scenario.clone());
            }
        }
        config
    };
    #[cfg(not(feature = "mock-backend"))]
    let _ = request;
    Ok(VirtualMachine::with_backend(kind, config)?)
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
        use crate::start_request::{RosettaIntentRequest, RosettaProfileRequest};
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
            Some(RosettaIntentRequest::VzNative)
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
                Some(RosettaIntentRequest::VzNative),
            )
            .expect("paired VZ-native intent"),
            RosettaIntent::VzNative
        );
        assert_eq!(
            resolve_rosetta_intent(
                &enabled,
                BackendKind::Krun,
                true,
                Some(RosettaIntentRequest::KrunCaptured {
                    profile: RosettaProfileRequest::CapturedCompatibilityV1,
                })
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
            Some(RosettaIntentRequest::VzNative)
        )
        .is_err());
        assert!(resolve_rosetta_intent(
            &enabled,
            BackendKind::Vz,
            false,
            Some(RosettaIntentRequest::VzNative)
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
            Some(RosettaIntentRequest::VzNative),
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
            std::env::temp_dir().join(format!("silo-vmmon-order-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let serial_path = directory.join("serial.log");
        let serial_file = std::fs::File::create(&serial_path).expect("create serial file");
        let (read_fd, write_fd) = pipe().expect("create start pipe");
        let mut writer = std::fs::File::from(write_fd);
        std::io::Write::write_all(&mut writer, b"{invalid}\n").expect("write malformed request");
        drop(writer);
        let mut start_request = StartRequestPipe::from_fd(Some(read_fd.into_raw_fd()))
            .expect("open start request pipe");
        let machine_id = uuid::Uuid::new_v4().to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let runtime = RuntimeContext::new(
            directory.clone(),
            directory.clone(),
            directory.join("missing-vm-spec.json"),
            directory.join("vm.sock"),
        );
        let network = vec!["none".to_string()];
        let krun_path = directory.join("missing-krun");

        let result = init(
            &runtime,
            InitInputs {
                machine_id: &machine_id,
                machine_run_id: &run_id,
                name: "ordering-test",
                network_args: &network,
                agent_enabled: false,
                krun_path: &krun_path,
                serial_file,
            },
            &mut start_request,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("malformed request must fail"),
        };

        assert!(error.to_string().contains("parse vmmon start request"));
        assert!(!error.to_string().contains("read vm spec"));
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[tokio::test]
    async fn identity_and_size_boundaries_are_enforced_before_vm_spec_or_vmm_construction() {
        use crate::start_request::{VMMON_START_REQUEST_MAX_BYTES, VMMON_START_REQUEST_VERSION};

        let machine_id = uuid::Uuid::new_v4().to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let mismatch = encode_start_request(serde_json::json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": uuid::Uuid::new_v4().to_string(),
            "machineRunId": run_id,
        }));
        let mismatch_error = init_error_for_start_request(mismatch, &machine_id, &run_id).await;
        assert!(mismatch_error.contains("machineId does not match --id"));
        assert!(!mismatch_error.contains("read vm spec"));

        let base = serde_json::json!({
            "version": VMMON_START_REQUEST_VERSION,
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
            serde_json::json!("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base_len));
        let exact_error =
            init_error_for_start_request(encode_start_request(exact), &machine_id, &run_id).await;
        assert!(exact_error.contains("read vm spec"));

        let mut oversized = base;
        oversized["startupCommand"]["process"]["environment"][0]["value"] =
            serde_json::json!("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base_len + 1));
        let oversized_error =
            init_error_for_start_request(encode_start_request(oversized), &machine_id, &run_id)
                .await;
        assert!(oversized_error.contains("exceeds 16777216 bytes"));
        assert!(!oversized_error.contains("read vm spec"));
    }

    async fn init_error_for_start_request(
        encoded: Vec<u8>,
        machine_id: &str,
        run_id: &str,
    ) -> String {
        use crate::context::RuntimeContext;
        use crate::start_request::StartRequestPipe;
        use crate::startup::{init, InitInputs};

        let directory = std::env::temp_dir().join(format!(
            "silo-vmmon-start-order-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let serial_file =
            std::fs::File::create(directory.join("serial.log")).expect("create serial file");
        let (read_fd, write_fd) = pipe().expect("create start pipe");
        let writer = tokio::task::spawn_blocking(move || {
            let mut writer = std::fs::File::from(write_fd);
            std::io::Write::write_all(&mut writer, &encoded).expect("write start request");
        });
        let mut start_request = StartRequestPipe::from_fd(Some(read_fd.into_raw_fd()))
            .expect("open start request pipe");
        let runtime = RuntimeContext::new(
            directory.clone(),
            directory.clone(),
            directory.join("missing-vm-spec.json"),
            directory.join("vm.sock"),
        );
        let network = vec!["none".to_string()];
        let krun_path = directory.join("missing-krun");
        let result = init(
            &runtime,
            InitInputs {
                machine_id,
                machine_run_id: run_id,
                name: "start-order-test",
                network_args: &network,
                agent_enabled: false,
                krun_path: &krun_path,
                serial_file,
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

    fn encode_start_request(value: serde_json::Value) -> Vec<u8> {
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

        InheritedPipeFds {
            startpipe: Some(start_read.as_raw_fd()),
            syncpipe: Some(sync_write.as_raw_fd()),
            machine_log_dir: None,
            machine_lock: None,
        }
        .clear_cloexec()
        .expect("preserve inherited pipes");

        for fd in [start_read.as_raw_fd(), sync_write.as_raw_fd()] {
            let flags = nix::fcntl::fcntl(
                unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) },
                nix::fcntl::FcntlArg::F_GETFD,
            )
            .expect("read fd flags");
            assert!(!nix::fcntl::FdFlag::from_bits_retain(flags)
                .contains(nix::fcntl::FdFlag::FD_CLOEXEC));
        }
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
        InheritedPipeFds {
            startpipe: Some(start_read.as_raw_fd()),
            syncpipe: Some(sync_write.as_raw_fd()),
            machine_log_dir: None,
            machine_lock: None,
        }
        .clear_cloexec()
        .expect("preserve inherited pipes");
        let script = format!(
            "IFS= read -r line <&{}; printf 'received:%s\\n' \"$line\" >&{}",
            start_read.as_raw_fd(),
            sync_write.as_raw_fd()
        );
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn inherited-fd child");
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
            std::env::temp_dir().join(format!("silo-vmmon-test-{}", uuid::Uuid::new_v4()));
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
    async fn direct_vmmon_stdout_reporter_does_not_monitor_parent_loss() {
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
}
