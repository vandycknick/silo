use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use agent_spec::{NetworkDnsConfig, NetworkIpv4Config};
use async_trait::async_trait;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use silo_policy::NetworkPolicy;
use tokio::time::sleep;
use utils::format_mac;

use crate::network::secret_transport;
use crate::paths::{
    LocalPaths, NETWORK_AUDIT_LOG_FILE_NAME, NETWORK_SERVICE_LOG_FILE_NAME, PCAP_FILE_NAME,
    PID_FILE_NAME,
};
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, NetworkAttachment, NetworkInstance, NetworkInstanceState,
};
use crate::supervisor::process::{self, ProcessIdentity};
use crate::utils::now_unix;
use crate::LibVmError;

use crate::network::core::{NetworkAttachmentRequest, NetworkDriverBackend, NetworkDriverContext};
use crate::network::{mac_from_machine_id, serialize_json, VmmNetworkAttachment, DRIVER_NETD};

const READY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STDERR_CAPTURE_LIMIT: usize = 64 * 1024;

pub(super) struct NetdDriver;

#[derive(Debug, Serialize, Deserialize)]
struct NetdDriverState {
    helper_pid: i32,
    helper_started_at: i64,
    machine_id: MachineId,
    run_id: String,
    subnet: String,
    pcap: bool,
}

#[derive(Serialize)]
struct PersistedNetworkAttachment {
    mac: String,
    ipv4: NetworkIpv4Config,
    dns: NetworkDnsConfig,
    requires_certificate_authority: bool,
}

#[async_trait]
impl NetworkDriverBackend for NetdDriver {
    fn id(&self) -> &'static str {
        DRIVER_NETD
    }

    fn supports(
        &self,
        reference: &str,
        request: &NetworkAttachmentRequest<'_>,
    ) -> Result<(), LibVmError> {
        validate_policy(reference, self.id(), request.policy())
    }

    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        request: &NetworkAttachmentRequest<'_>,
    ) -> Result<VmmNetworkAttachment, LibVmError> {
        prepare_netd_runtime(ctx, request).await
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn prepare_netd_runtime(
    ctx: &NetworkDriverContext<'_>,
    request: &NetworkAttachmentRequest<'_>,
) -> Result<VmmNetworkAttachment, LibVmError> {
    let paths = ctx.paths;
    let store = ctx.store;
    let metadata = ctx.metadata;
    let config = ctx.config.netd.clone();
    let secret_frame =
        secret_transport::frame(ctx.egress_credentials, request.policy(), &metadata.name)?;
    if !host_uses_user_network_runtime() {
        return Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: "userspace networking is not supported on this host".to_string(),
        });
    }

    let network_id = MachineId::new().to_string();
    let network_paths = paths.network(&network_id)?;
    let machine_paths = paths.machine(metadata.id);
    let runtime_directory = paths.ensure_network_run_dir(&network_id)?;
    let log_directory = paths.ensure_machine_network_logs_dir(metadata.id)?;
    let mut startup = NetdStartupGuard::new(paths.clone(), network_id.clone());
    // std creates non-inheritable pipes on both macOS and Linux, coordinating
    // its pipe+fcntl fallback with concurrent std::process launches.
    let (owner_read, owner_write) = std::io::pipe()?;
    let (owner_read, owner_write) = (OwnedFd::from(owner_read), OwnedFd::from(owner_write));
    let (report_read, report_write) = std::io::pipe()?;
    let (report_read, report_write) = (OwnedFd::from(report_read), OwnedFd::from(report_write));
    let (secret_read, secret_write) = std::io::pipe()?;
    let (secret_read, secret_write) = (OwnedFd::from(secret_read), OwnedFd::from(secret_write));
    nix::fcntl::fcntl(
        &report_read,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )
    .map_err(std::io::Error::other)?;
    startup.owner_write = Some(owner_write);

    let socket_path = network_paths.socket_path();
    let log_path = machine_paths.network_service_log_path();
    let policy_path = if let Some(policy) = request.policy() {
        let path = network_paths.policy_path();
        write_runtime_policy_file(metadata, policy, &runtime_directory, &path)?;
        Some(path)
    } else {
        None
    };
    let requires_certificate_authority = request
        .policy()
        .is_some_and(NetworkPolicy::has_https_interception);
    let mac = format_mac(mac_from_machine_id(metadata.id));
    let (ipv4, dns) = private_ipv4_config(&config.subnet, &metadata.name)?;
    let static_lease = format!("{}={mac}", ipv4.address);
    let log_directory_fd = log_directory.duplicate_inheritable()?;
    let runtime_directory_fd = runtime_directory.duplicate_inheritable()?;

    let mut command = Command::new(ctx.netd_path);
    configure_network_helper_command(
        &mut command,
        &NetworkHelperCommandConfig {
            socket_path: &socket_path,
            subnet: &config.subnet,
            log_directory_fd: log_directory_fd.as_raw_fd(),
            runtime_directory_fd: runtime_directory_fd.as_raw_fd(),
            pcap: config.pcap,
            machine_id: metadata.id,
            run_id: ctx.run_id,
            network_id: &network_id,
            policy_path: policy_path.as_deref(),
            static_lease: &static_lease,
            guest_publish: request.publish().map(|publish| publish.bind.as_str()),
        },
    );
    secret_transport::strip_environment(&mut command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    command
        .arg("--daemonize")
        .arg("--startup-fd")
        .arg(report_write.as_raw_fd().to_string())
        .arg("--exit-fd")
        .arg(owner_read.as_raw_fd().to_string())
        .arg("--secrets-fd")
        .arg(secret_read.as_raw_fd().to_string());
    let owner_fd = owner_read.as_raw_fd();
    let report_fd = report_write.as_raw_fd();
    let secret_fd = secret_read.as_raw_fd();
    let log_fd = log_directory_fd.as_raw_fd();
    let runtime_fd = runtime_directory_fd.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            // Clear CLOEXEC in this child only, never in the multithreaded caller.
            for raw in [owner_fd, report_fd, secret_fd, log_fd, runtime_fd] {
                let fd = std::os::fd::BorrowedFd::borrow_raw(raw);
                nix::fcntl::fcntl(
                    fd,
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
                )
                .map_err(std::io::Error::other)?;
            }
            Ok(())
        });
    }

    let deadline = std::time::Instant::now() + READY_TIMEOUT;
    let child = command.spawn();
    drop(owner_read);
    drop(report_write);
    drop(secret_read);
    drop(log_directory_fd);
    drop(runtime_directory_fd);
    let mut child = child.map_err(|err| LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message: format!("spawn userspace network helper: {err}"),
    })?;
    let stderr_capture = child.stderr.take().map(CapturedStderr::spawn);
    startup.set_child(child, stderr_capture);
    let report = match async {
        secret_transport::write_frame(secret_write, secret_frame, deadline).await?;
        wait_for_netd_startup(
            &report_read,
            &mut startup,
            metadata.id,
            ctx.run_id,
            &network_id,
            deadline,
        )
        .await
    }
    .await
    {
        Ok(report) => report,
        Err(err) => {
            let stderr_lines = startup.rollback_after_startup_failure();
            return Err(LibVmError::NetworkRuntime {
                reference: metadata.name.clone(),
                message: format_netd_startup_failure(&err, &stderr_lines, &log_path),
            });
        }
    };
    let pid = report.pid;
    let identity = ProcessIdentity::for_pid(pid)?.ok_or_else(|| LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message: "netd worker exited after readiness".into(),
    })?;
    let helper_started_at = identity
        .started_at()
        .ok_or_else(|| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!("netd pid {pid} has no stable process generation"),
        })?;
    startup.worker = Some(identity);

    let network = VmmNetworkAttachment::UnixDatagram {
        path: socket_path.clone(),
        mac: mac.clone(),
        ipv4,
        dns,
        requires_certificate_authority,
        exit_writer: None,
    };
    let (ipv4, dns) = match &network {
        VmmNetworkAttachment::UnixDatagram { ipv4, dns, .. } => (ipv4.clone(), dns.clone()),
        VmmNetworkAttachment::None => {
            return Err(LibVmError::NetworkRuntime {
                reference: metadata.name.clone(),
                message: "netd created an invalid network attachment".to_string(),
            });
        }
    };
    let driver_state = NetdDriverState {
        helper_pid: pid,
        helper_started_at,
        machine_id: metadata.id,
        run_id: ctx.run_id.to_string(),
        subnet: config.subnet.clone(),
        pcap: config.pcap,
    };
    let now = now_unix();
    store
        .save_network_instance(&NetworkInstance {
            id: network_id.clone(),
            driver: DRIVER_NETD.to_string(),
            definition_name: None,
            attachment_json: serialize_json(
                &PersistedNetworkAttachment {
                    mac: mac.clone(),
                    ipv4,
                    dns,
                    requires_certificate_authority,
                },
                "network attachment",
            )?,
            driver_state_json: serialize_json(&driver_state, "netd driver state")?,
            state: NetworkInstanceState::Running,
            created_at: now,
            modified_at: now,
        })
        .await?;
    if let Err(err) = store
        .attach_network(&NetworkAttachment {
            machine_id: metadata.id,
            network_instance_id: network_id.clone(),
            guest_mac: mac,
            created_at: now,
            modified_at: now,
        })
        .await
    {
        if let Err(rollback_err) = store.remove_network_instance(&network_id).await {
            return Err(LibVmError::NetworkRuntime {
                reference: metadata.name.clone(),
                message: format!(
                    "attach userspace network runtime failed: {err}; rollback of runtime record {network_id} also failed: {rollback_err}"
                ),
            });
        }
        return Err(err);
    }
    let mut network = network;
    if let crate::network::VmmNetworkAttachment::UnixDatagram { exit_writer, .. } = &mut network {
        *exit_writer = startup.owner_write.take();
    }
    startup.commit();
    Ok(network)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn prepare_netd_runtime(
    _ctx: &NetworkDriverContext<'_>,
    _request: &NetworkAttachmentRequest<'_>,
) -> Result<VmmNetworkAttachment, LibVmError> {
    let metadata = _ctx.metadata;
    Err(LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message: "netd networking is not supported on this host".to_string(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn host_uses_user_network_runtime() -> bool {
    true
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn host_uses_user_network_runtime() -> bool {
    false
}

struct NetworkHelperCommandConfig<'a> {
    socket_path: &'a Path,
    subnet: &'a str,
    log_directory_fd: i32,
    runtime_directory_fd: i32,
    pcap: bool,
    machine_id: MachineId,
    run_id: &'a str,
    network_id: &'a str,
    policy_path: Option<&'a Path>,
    static_lease: &'a str,
    guest_publish: Option<&'a str>,
}

fn configure_network_helper_command(
    command: &mut Command,
    config: &NetworkHelperCommandConfig<'_>,
) {
    command
        .arg("--listen-vfkit")
        .arg(format!("unixgram://{}", config.socket_path.display()))
        .arg("--subnet")
        .arg(config.subnet)
        .arg("--static-lease")
        .arg(config.static_lease)
        .arg("--log-dir-fd")
        .arg(config.log_directory_fd.to_string())
        .arg("--runtime-dir-fd")
        .arg(config.runtime_directory_fd.to_string())
        .arg("--log-file")
        .arg(NETWORK_SERVICE_LOG_FILE_NAME)
        .arg("--audit-log-file")
        .arg(NETWORK_AUDIT_LOG_FILE_NAME)
        .arg("--pid-file")
        .arg(PID_FILE_NAME);
    if config.pcap {
        command.arg("--pcap").arg(PCAP_FILE_NAME);
    }
    command
        .arg("--vm-id")
        .arg(config.machine_id.to_string())
        .arg("--run-id")
        .arg(config.run_id)
        .arg("--network-id")
        .arg(config.network_id);
    if let Some(path) = config.policy_path {
        command.arg("--policy-file").arg(path);
    }
    if let Some(bind) = config.guest_publish {
        command.arg("--guest-publish").arg(bind);
    }
}

fn private_ipv4_config(
    subnet: &str,
    reference: &str,
) -> Result<(NetworkIpv4Config, NetworkDnsConfig), LibVmError> {
    let (address, prefix) = subnet
        .split_once('/')
        .ok_or_else(|| network_config_error(reference, "subnet must use IPv4 CIDR notation"))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|err| network_config_error(reference, format!("parse subnet address: {err}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|err| network_config_error(reference, format!("parse subnet prefix: {err}")))?;
    if !(1..=29).contains(&prefix) {
        return Err(network_config_error(
            reference,
            "subnet prefix must be between 1 and 29",
        ));
    }

    let mask = u32::MAX << (32 - prefix);
    let network = u32::from(address) & mask;
    let gateway = Ipv4Addr::from(network + 1);
    let guest = Ipv4Addr::from(network + 2);
    Ok((
        NetworkIpv4Config {
            address: guest,
            prefix_length: prefix,
            gateway,
        },
        NetworkDnsConfig {
            servers: vec![IpAddr::V4(gateway)],
            search: Vec::new(),
        },
    ))
}

fn network_config_error(reference: &str, message: impl Into<String>) -> LibVmError {
    LibVmError::NetworkRuntime {
        reference: reference.to_string(),
        message: message.into(),
    }
}

fn validate_policy(
    reference: &str,
    driver: &str,
    policy: Option<&silo_policy::NetworkPolicy>,
) -> Result<(), LibVmError> {
    if policy.is_none() {
        return Ok(());
    }
    if driver != DRIVER_NETD {
        return Err(LibVmError::NetworkRuntime {
            reference: reference.to_string(),
            message: format!("resolved driver {driver:?} does not support network policy"),
        });
    }
    Ok(())
}

fn write_runtime_policy_file(
    metadata: &MachineConfig,
    policy: &NetworkPolicy,
    runtime_directory: &crate::paths::OwnedDirectory,
    path: &Path,
) -> Result<(), LibVmError> {
    let normalized = policy.clone().normalized();
    let mut bytes =
        serde_json::to_vec_pretty(&normalized).map_err(|err| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!("serialize generated network policy: {err}"),
        })?;
    bytes.push(b'\n');
    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!(
                "generated network policy path has no filename: {}",
                path.display()
            ),
        })?;
    runtime_directory
        .write_file(file_name, &bytes)
        .map_err(|err| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!("write generated network policy {}: {err}", path.display()),
        })
}

#[derive(Deserialize)]
struct WorkerStartupReport {
    pid: i32,
    vm_id: String,
    run_id: String,
    network_id: String,
    ready: bool,
    #[serde(default)]
    error: String,
}

async fn wait_for_netd_startup(
    report_fd: &OwnedFd,
    startup: &mut NetdStartupGuard,
    machine_id: MachineId,
    run_id: &str,
    network_id: &str,
    deadline: std::time::Instant,
) -> Result<WorkerStartupReport, String> {
    let mut bytes = Vec::new();
    let mut launcher_exited = false;
    let mut eof = false;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for netd worker readiness".into());
        }
        if let Some(child) = startup.child.as_mut() {
            if !launcher_exited {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|err| format!("wait for netd launcher: {err}"))?
                {
                    if !status.success() {
                        return Err(format!("netd launcher exited with {status}"));
                    }
                    launcher_exited = true;
                }
            }
        }
        let mut chunk = [0u8; 4096];
        match nix::unistd::read(report_fd, &mut chunk) {
            Ok(0) => eof = true,
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(format!("read netd worker startup: {error}")),
        }
        if bytes.len() > STDERR_CAPTURE_LIMIT {
            return Err("netd startup report exceeds limit".into());
        }
        if launcher_exited && (bytes.contains(&b'\n') || eof) {
            let report: WorkerStartupReport = serde_json::from_slice(&bytes)
                .map_err(|err| format!("invalid netd worker startup report: {err}"))?;
            if report.pid <= 1
                || report.vm_id != machine_id.to_string()
                || report.run_id != run_id
                || report.network_id != network_id
            {
                return Err("netd startup report does not match requested generation".into());
            }
            if !report.ready {
                return Err(format!("netd worker startup failed: {}", report.error));
            }
            return Ok(report);
        }
        sleep(
            READY_POLL_INTERVAL.min(deadline.saturating_duration_since(std::time::Instant::now())),
        )
        .await;
    }
}

fn format_netd_startup_failure(reason: &str, stderr_lines: &[String], log_path: &Path) -> String {
    let mut message = "netd failed during startup".to_string();
    if let Some(stderr) = render_netd_startup_stderr(stderr_lines) {
        message.push_str("\n\n");
        message.push_str(&stderr);
    } else if !reason.trim().is_empty() {
        message.push_str("\n\n");
        message.push_str(reason.trim());
    }
    message.push_str(&format!("\n\nnetd log: {}", log_path.display()));
    message
}

fn render_netd_startup_stderr(lines: &[String]) -> Option<String> {
    let mut records = Vec::new();
    let mut raw_lines = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<NetdStartupErrorRecord>(trimmed) {
            Ok(record) => records.push(record),
            Err(_) => raw_lines.push(trimmed.to_string()),
        }
    }
    if records.is_empty() && raw_lines.is_empty() {
        return None;
    }

    let mut output = String::new();
    for record in records {
        if !output.is_empty() {
            output.push('\n');
        }
        render_netd_startup_error_record(&mut output, &record);
    }
    for line in raw_lines {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&line);
    }
    Some(output)
}

fn render_netd_startup_error_record(output: &mut String, record: &NetdStartupErrorRecord) {
    if let Some(file) = record.file.as_deref().filter(|file| !file.is_empty()) {
        output.push_str(file);
        if let Some(line) = record.line.filter(|line| *line > 0) {
            let _ = write!(output, ":{line}");
            if let Some(column) = record.column.filter(|column| *column > 0) {
                let _ = write!(output, ":{column}");
            }
        }
        output.push_str(": ");
    }
    output.push_str(record.message.trim());
    let detail = record.detail.trim();
    if detail.is_empty() {
        return;
    }
    for line in detail.lines() {
        output.push('\n');
        output.push_str("  ");
        output.push_str(line);
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct NetdStartupErrorRecord {
    #[serde(rename = "type")]
    _kind: String,
    message: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    column: Option<u32>,
}

struct CapturedStderr {
    lines: Arc<Mutex<CapturedStderrLines>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct CapturedStderrLines {
    lines: VecDeque<String>,
    byte_len: usize,
}

impl CapturedStderr {
    fn spawn(stderr: ChildStderr) -> Self {
        let lines = Arc::new(Mutex::new(CapturedStderrLines::default()));
        let thread_lines = Arc::clone(&lines);
        let handle = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let Ok(line) = line else {
                    break;
                };
                let Ok(mut captured) = thread_lines.lock() else {
                    break;
                };
                append_bounded_stderr_line(&mut captured, line);
            }
        });
        Self {
            lines,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<String> {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let Ok(captured) = self.lines.lock() else {
            return Vec::new();
        };
        captured.lines.iter().cloned().collect()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct NetdStartupGuard {
    paths: LocalPaths,
    network_id: String,
    child: Option<Child>,
    worker: Option<ProcessIdentity>,
    owner_write: Option<OwnedFd>,
    stderr_capture: Option<CapturedStderr>,
    armed: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl NetdStartupGuard {
    fn new(paths: LocalPaths, network_id: String) -> Self {
        Self {
            paths,
            network_id,
            child: None,
            worker: None,
            owner_write: None,
            stderr_capture: None,
            armed: true,
        }
    }

    fn set_child(&mut self, child: Child, stderr_capture: Option<CapturedStderr>) {
        self.child = Some(child);
        self.stderr_capture = stderr_capture;
    }

    fn rollback_after_startup_failure(&mut self) -> Vec<String> {
        self.stop_helper();
        let stderr_lines = self
            .stderr_capture
            .take()
            .map(CapturedStderr::finish)
            .unwrap_or_default();
        self.rollback_files();
        self.armed = false;
        stderr_lines
    }

    fn commit(mut self) {
        self.armed = false;
    }

    fn stop_helper(&mut self) {
        self.owner_write.take();
        if let Some(identity) = self.worker.take() {
            if identity.is_alive().unwrap_or(false) {
                let _ = terminate_helper(&identity);
            }
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn rollback_files(&mut self) {
        let _ = self.paths.remove_network_run_tree(&self.network_id);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for NetdStartupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.stop_helper();
        self.rollback_files();
    }
}

fn append_bounded_stderr_line(captured: &mut CapturedStderrLines, line: String) {
    let line = if line.len() > STDERR_CAPTURE_LIMIT {
        let bytes = line.as_bytes();
        String::from_utf8_lossy(&bytes[bytes.len() - STDERR_CAPTURE_LIMIT..]).to_string()
    } else {
        line
    };
    let line_len = line.len();
    while captured.byte_len.saturating_add(line_len) > STDERR_CAPTURE_LIMIT {
        if captured.lines.is_empty() {
            captured.byte_len = 0;
            break;
        }
        let Some(removed) = captured.lines.pop_front() else {
            captured.byte_len = 0;
            break;
        };
        captured.byte_len = captured.byte_len.saturating_sub(removed.len());
    }
    captured.byte_len = captured.byte_len.saturating_add(line_len);
    captured.lines.push_back(line);
}

pub(super) fn instance_description(instance: &NetworkInstance) -> Result<String, LibVmError> {
    let state = driver_state(instance)?;
    Ok(format!(
        "netd pid {}, started {}, run {}",
        state.helper_pid, state.helper_started_at, state.run_id
    ))
}

pub(super) fn instance_is_alive(instance: &NetworkInstance) -> Result<bool, LibVmError> {
    let Some(identity) = instance_process_identity(instance)? else {
        return Ok(false);
    };
    identity.is_alive().map_err(Into::into)
}

pub(super) async fn terminate_instance(
    instance: &NetworkInstance,
    reference: &str,
) -> Result<(), LibVmError> {
    let identity = match observe_instance_process(instance)? {
        NetdProcess::Absent | NetdProcess::Replaced { .. } => return Ok(()),
        NetdProcess::Running(identity) => identity,
    };
    if !identity.is_alive()? {
        return Ok(());
    }
    terminate_helper(&identity)?;
    process::wait_for_exit(
        &identity,
        reference,
        Duration::from_secs(5),
        Duration::from_millis(50),
    )
    .await?;
    Ok(())
}

pub(super) fn instance_process_identity(
    instance: &NetworkInstance,
) -> Result<Option<ProcessIdentity>, LibVmError> {
    match observe_instance_process(instance)? {
        NetdProcess::Absent => Ok(None),
        NetdProcess::Running(identity) => Ok(Some(identity)),
        NetdProcess::Replaced { pid, expected, observed } => Err(LibVmError::NetworkRuntime {
            reference: instance.id.clone(),
            message: format!("netd pid {pid} belongs to a different process generation (expected {expected}, observed {observed}); no signal will be sent"),
        }),
    }
}

enum NetdProcess {
    Absent,
    Replaced {
        pid: i32,
        expected: i64,
        observed: i64,
    },
    Running(ProcessIdentity),
}

fn observe_instance_process(instance: &NetworkInstance) -> Result<NetdProcess, LibVmError> {
    let state = driver_state(instance)?;
    if state.helper_pid <= 1 {
        return Err(LibVmError::NetworkRuntime {
            reference: instance.id.clone(),
            message: "invalid persisted netd PID; refusing cleanup".into(),
        });
    }
    let Some(identity) = ProcessIdentity::for_pid(state.helper_pid)? else {
        return Ok(NetdProcess::Absent);
    };
    let observed = identity
        .started_at()
        .ok_or_else(|| LibVmError::NetworkRuntime {
            reference: instance.id.clone(),
            message: format!(
                "netd pid {} identity is unavailable; refusing cleanup",
                state.helper_pid
            ),
        })?;
    if observed != state.helper_started_at {
        return Ok(NetdProcess::Replaced {
            pid: state.helper_pid,
            expected: state.helper_started_at,
            observed,
        });
    }
    Ok(NetdProcess::Running(identity))
}

fn driver_state(instance: &NetworkInstance) -> Result<NetdDriverState, LibVmError> {
    serde_json::from_str::<NetdDriverState>(&instance.driver_state_json).map_err(|error| {
        LibVmError::StateDecode {
            field: "network_instances.driver_state_json",
            message: format!("decode netd process identity: {error}"),
        }
    })
}

fn terminate_helper(identity: &ProcessIdentity) -> Result<(), LibVmError> {
    let process_group = Pid::from_raw(-identity.pid());
    match kill(process_group, Signal::SIGTERM) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(std::io::Error::from_raw_os_error(error as i32).into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::network::netd_driver::{
        append_bounded_stderr_line, configure_network_helper_command, format_netd_startup_failure,
        prepare_netd_runtime, private_ipv4_config, CapturedStderrLines, NetworkHelperCommandConfig,
        STDERR_CAPTURE_LIMIT,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::json;
    use silo_policy::NetworkPolicy;
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::process::Command;

    use crate::lock_manager::LockId;
    use crate::machine::{EgressCredentials, SecretProvider};
    use crate::network::core::{NetworkAttachmentRequest, NetworkDriverContext};
    use crate::paths::{LocalPaths, LocalRoots};
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRuntimeState, MachineState,
        NetworkInstance, NetworkInstanceState,
    };
    use crate::store::{MachineStore, NetworkStore, Store};
    use crate::RuntimeNetworkingConfig;

    fn oauth_policy() -> NetworkPolicy {
        NetworkPolicy::from_json_str(
            r#"{
                "version": 1,
                "metadata": {},
                "endpoints": [
                    { "name": "chatgpt", "kind": "https", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["chatgpt.com"] }
                ],
                "credentials": [
                    { "name": "codex", "kind": "openai_codex_oauth", "endpoint": "chatgpt" }
                ]
            }"#,
        )
        .expect("oauth policy")
    }

    #[test]
    fn netd_command_includes_static_lease() {
        let mut command = Command::new("/tmp/netd");
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                socket_path: Path::new("/tmp/silo-net/netd.sock"),
                subnet: "192.168.105.0/24",
                log_directory_fd: 31,
                runtime_directory_fd: 32,
                pcap: false,
                machine_id: MachineId::new(),
                run_id: "run123",
                network_id: "net123",
                policy_path: None,
                static_lease: "192.168.105.2=02:00:00:00:00:02",
                guest_publish: None,
            },
        );

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(args
            .windows(2)
            .any(|window| { window == ["--static-lease", "192.168.105.2=02:00:00:00:00:02",] }));
        assert!(args.iter().all(|arg| arg != "--ssh-port"));
        assert!(args.iter().all(|arg| arg != "--tls-ca-cert"));
        assert!(args.iter().all(|arg| arg != "--tls-ca-key"));
        assert!(args.iter().all(|arg| arg != "--guest-publish"));
    }

    #[test]
    fn netd_command_adds_policy_metadata() {
        let mut command = Command::new("/tmp/netd");
        let machine_id = MachineId::new();
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                socket_path: Path::new("/tmp/silo-net/netd.sock"),
                subnet: "192.168.105.0/24",
                log_directory_fd: 31,
                runtime_directory_fd: 32,
                pcap: false,
                machine_id,
                run_id: "run123",
                network_id: "net123",
                policy_path: Some(Path::new("/tmp/silo-net/network-policy.json")),
                static_lease: "192.168.105.2=02:00:00:00:00:02",
                guest_publish: Some("any"),
            },
        );

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(args
            .windows(2)
            .any(|window| window[0] == "--vm-id" && window[1] == machine_id.to_string()));
        assert!(args
            .windows(2)
            .any(|window| window == ["--run-id", "run123"]));
        assert!(args
            .windows(2)
            .any(|window| window == ["--guest-publish", "any"]));
        assert!(args
            .windows(2)
            .any(|window| window == ["--log-dir-fd", "31"]));
        assert!(args
            .windows(2)
            .any(|window| window == ["--runtime-dir-fd", "32"]));
        assert!(args
            .windows(2)
            .any(|window| window == ["--log-file", "netd.log"]));
        assert!(args
            .windows(2)
            .any(|window| window == ["--audit-log-file", "audit.jsonl"]));
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--network-id" && window[1] == "net123"));
        assert!(args.windows(2).any(|window| window[0] == "--policy-file"
            && window[1] == "/tmp/silo-net/network-policy.json"));
        assert!(args.iter().all(|arg| arg != "--secret-store-file"));
        assert!(args.iter().all(|arg| !arg.starts_with("--tls-ca-")));
    }

    #[test]
    fn netd_payload_contains_credentials_and_single_encoded_grant() {
        let policy = oauth_policy();
        let launch = EgressCredentials::new()
            .secret("codex.oauth.access_token", "token")
            .secret("codex.oauth.expires_at", "2026-07-04T00:00:00Z")
            .oauth_refresh_hook(
                SecretProvider::new("/usr/bin/silo", b"auth".to_vec())
                    .arg("secret")
                    .arg("provide")
                    .timeout_ms(2500)
                    .refresh_skew_seconds(120),
            );
        let frame = crate::network::secret_transport::frame(&launch, Some(&policy), "devbox")
            .expect("frame");
        let body = frame.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let payload: serde_json::Value = serde_json::from_slice(&frame[body..]).unwrap();
        assert_eq!(
            payload["secrets"][0],
            json!({"name":"codex.oauth.access_token", "value":"dG9rZW4="})
        );
        let hook_json = &payload["provider"];
        assert_eq!(
            STANDARD
                .decode(hook_json["grant"].as_str().unwrap())
                .unwrap(),
            b"auth"
        );
        assert_eq!(
            hook_json,
            &json!({
                "version": 2,
                "command": "/usr/bin/silo",
                "args": ["secret", "provide"],
                "timeout_ms": 2500,
                "refresh_skew_seconds": 120,
                "grant": "YXV0aA=="
            })
        );
    }

    #[test]
    fn netd_startup_failure_renders_json_stderr_and_paths() {
        let stderr_lines = vec![
            "{\"type\":\"policy_error\",\"message\":\"Unsupported endpoint kind\",\"detail\":\"unsupported endpoint kind \\\"invalid_endpoint\\\"\",\"file\":\"/tmp/policy.hcl\",\"line\":3,\"column\":10}".to_string(),
            "{\"type\":\"policy_error\",\"message\":\"Invalid rule\",\"detail\":\"rule \\\"deny-private\\\": references unknown endpoint \\\"ip.private\\\"\",\"file\":\"/tmp/policy.hcl\",\"line\":9,\"column\":1}".to_string(),
        ];
        let message = format_netd_startup_failure(
            "userspace network helper exited during startup with status exit status: 1",
            &stderr_lines,
            Path::new("/tmp/silo/netd.log"),
        );

        let expected = "\
netd failed during startup

/tmp/policy.hcl:3:10: Unsupported endpoint kind
  unsupported endpoint kind \"invalid_endpoint\"
/tmp/policy.hcl:9:1: Invalid rule
  rule \"deny-private\": references unknown endpoint \"ip.private\"

netd log: /tmp/silo/netd.log";
        assert_eq!(message, expected);
    }

    #[test]
    fn netd_startup_failure_falls_back_to_raw_stderr() {
        let stderr_lines = vec!["plain old panic".to_string()];
        let message = format_netd_startup_failure(
            "userspace network helper exited during startup with status exit status: 1",
            &stderr_lines,
            Path::new("/tmp/silo/netd.log"),
        );

        let expected = "\
netd failed during startup

plain old panic

netd log: /tmp/silo/netd.log";
        assert_eq!(message, expected);
    }

    #[test]
    fn bounded_stderr_lines_keep_recent_lines() {
        let mut captured = CapturedStderrLines::default();

        append_bounded_stderr_line(&mut captured, "a".repeat(STDERR_CAPTURE_LIMIT - 2));
        append_bounded_stderr_line(&mut captured, "bcdef".to_string());

        assert!(captured.byte_len <= STDERR_CAPTURE_LIMIT);
        let lines = captured.lines.into_iter().collect::<Vec<_>>();
        assert_eq!(lines, vec!["bcdef".to_string()]);
    }

    #[test]
    fn private_ipv4_config_uses_first_two_usable_addresses() {
        let (ipv4, dns) =
            private_ipv4_config("192.168.105.37/24", "devbox").expect("private IPv4 config");

        assert_eq!(ipv4.address.to_string(), "192.168.105.2");
        assert_eq!(ipv4.gateway.to_string(), "192.168.105.1");
        assert_eq!(ipv4.prefix_length, 24);
        assert_eq!(dns.servers[0].to_string(), "192.168.105.1");
    }

    #[test]
    fn private_ipv4_config_rejects_too_small_subnet() {
        let err = private_ipv4_config("192.168.105.0/30", "devbox")
            .expect_err("small subnet should fail");

        assert!(err.to_string().contains("between 1 and 29"));
    }

    #[tokio::test]
    async fn netd_identity_rejects_a_live_reused_generation() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn helper");
        let pid = i32::try_from(child.id()).expect("pid fits i32");
        let started_at = crate::supervisor::process::ProcessIdentity::for_pid(pid)
            .expect("read helper identity")
            .and_then(|identity| identity.started_at())
            .expect("helper has stable generation");
        let instance = NetworkInstance {
            id: "net-stale".to_string(),
            driver: "netd".to_string(),
            definition_name: None,
            attachment_json: "{}".to_string(),
            driver_state_json: serde_json::json!({
                "helper_pid": pid,
                "helper_started_at": started_at.saturating_add(1),
                "machine_id": MachineId::new(),
                "run_id": "old-run",
                "subnet": "192.168.105.0/24",
                "pcap": false
            })
            .to_string(),
            state: NetworkInstanceState::Running,
            created_at: 1,
            modified_at: 1,
        };

        assert!(crate::network::netd_driver::instance_process_identity(&instance).is_err());
        crate::network::netd_driver::terminate_instance(&instance, "stale")
            .await
            .expect("stale generation is safe to detach without signalling replacement");
        assert!(child.try_wait().expect("check helper").is_none());
        child.kill().expect("stop helper");
        child.wait().expect("reap helper");
    }

    #[tokio::test]
    async fn netd_launches_the_resolved_absolute_helper() {
        let temp = tempfile::Builder::new()
            .prefix("netd-")
            .tempdir_in("/tmp")
            .expect("create temp dir");
        let data_root = temp.path().join("data");
        let run_root = temp.path().join("run");
        let paths = LocalPaths::from_roots(LocalRoots::with_roots(&data_root, &run_root));
        let netd = temp.path().join("runtime/bin/netd");
        std::fs::create_dir_all(netd.parent().expect("netd parent")).expect("create netd parent");
        let build = Command::new("go")
            .args(["build", "-o"])
            .arg(&netd)
            .arg("./cmd/netd")
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../net/netd"))
            .output()
            .expect("build real netd");
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let store = Store::new(&paths).await.expect("open store");
        let machine_id = MachineId::new();
        let metadata = MachineConfig {
            id: machine_id,
            lock_id: LockId::from(0),
            name: "netd-resolved-path".to_string(),
            spec: vm_spec::VmSpec::current(),
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            machine_dir: paths.machine(machine_id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: MachineNetworkConfig::Private {
                policy: None,
                publish: None,
            },
            guest: crate::machine::MachineGuestConfig::default(),
        };
        let state = MachineState {
            machine_id,
            status: MachineRuntimeState::Stopped,
            vmm_pid: None,
            started_at: None,
            run_id: None,
            last_error: None,
            updated_at: 1,
        };
        store
            .add_machine(&metadata, &state)
            .await
            .expect("save machine");
        let networking = RuntimeNetworkingConfig::default();
        let launch = crate::secrets::ResolvedSecrets::default();
        let context = NetworkDriverContext {
            paths: &paths,
            store: &store,
            metadata: &metadata,
            run_id: "run-123",
            config: &networking,
            netd_path: &netd,
            egress_credentials: &launch,
        };

        let attachment =
            prepare_netd_runtime(&context, &NetworkAttachmentRequest::private(None, None))
                .await
                .expect("launch resolved netd");

        let log_path = match attachment {
            crate::network::VmmNetworkAttachment::UnixDatagram { .. } => {
                paths.machine(machine_id).network_service_log_path()
            }
            crate::network::VmmNetworkAttachment::None => panic!("netd must attach a socket"),
        };
        assert_eq!(
            log_path,
            data_root
                .join("logs/machines")
                .join(machine_id.to_string())
                .join("network/netd.log")
        );
        assert!(!data_root.join("logs/networks").exists());
        let log = std::fs::read_to_string(&log_path).expect("worker log");
        assert!(log.contains("run-123"));
        let instance = store
            .network_instance(
                &store
                    .network_attachment(machine_id)
                    .await
                    .expect("attachment")
                    .expect("attached")
                    .network_instance_id,
            )
            .await
            .expect("instance")
            .expect("present");
        let identity = crate::network::netd_driver::instance_process_identity(&instance)
            .expect("identity")
            .expect("live worker");
        assert!(matches!(
            nix::sys::wait::waitpid(
                nix::unistd::Pid::from_raw(identity.pid()),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG)
            ),
            Err(nix::errno::Errno::ECHILD)
        ));
        drop(attachment);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while crate::supervisor::process::ProcessIdentity::for_pid(identity.pid())
            .expect("probe")
            .is_some()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "worker not reaped after owner EOF"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        crate::network::reconcile_network_runtime(&paths, &store, &metadata, false)
            .await
            .expect("clean netd runtime");

        // Also cross the actual Go decoder with a policy, binary values and a
        // provider grant, rather than qualifying only the empty frame.
        let policy = oauth_policy();
        let mut credentials = EgressCredentials::new()
            .secret_bytes("codex.oauth.access_token", vec![0, 255, 128])
            .secret("codex.oauth.expires_at", "2099-01-01T00:00:00Z")
            .oauth_refresh_hook(SecretProvider::new(
                "/bin/false",
                b"synthetic-hook-auth".to_vec(),
            ));
        let ca = crate::host::certificates::resolve(
            &silo_secrets::FileStore::new(paths.home()),
            &paths,
            &crate::NetdRuntimeConfig::default(),
        )
        .unwrap();
        credentials.infrastructure.push((
            crate::host::certificates::CERTIFICATE.into(),
            silo_secrets::SecretBytes::new(ca.certificate.into_bytes()),
        ));
        credentials
            .infrastructure
            .push((crate::host::certificates::PRIVATE.into(), ca.private));
        let context = NetworkDriverContext {
            egress_credentials: &credentials,
            ..context
        };
        let attachment = prepare_netd_runtime(
            &context,
            &NetworkAttachmentRequest::private(Some(&policy), None),
        )
        .await
        .expect("actual netd accepts Rust binary/provider frame");
        let network_id = store
            .network_attachment(machine_id)
            .await
            .unwrap()
            .unwrap()
            .network_instance_id;
        let instance = store.network_instance(&network_id).await.unwrap().unwrap();
        let worker = crate::network::netd_driver::instance_process_identity(&instance)
            .unwrap()
            .unwrap();
        assert!(worker.is_alive().unwrap());
        #[cfg(target_os = "linux")]
        {
            let environment = std::fs::read(format!("/proc/{}/environ", worker.pid())).unwrap();
            assert!(environment
                .split(|byte| *byte == 0)
                .all(|entry| !entry.starts_with(b"SILO_NET_")));
            let argv = std::fs::read(format!("/proc/{}/cmdline", worker.pid())).unwrap();
            assert!(!argv
                .windows(b"synthetic-hook-auth".len())
                .any(|value| value == b"synthetic-hook-auth"));
            assert!(!argv
                .windows(b"c3ludGhldGljLWhvb2stYXV0aA==".len())
                .any(|value| value == b"c3ludGhldGljLWhvb2stYXV0aA=="));
        }
        drop(attachment);
        crate::network::reconcile_network_runtime(&paths, &store, &metadata, false)
            .await
            .unwrap();
    }

    // This executable exercises only process transport and startup rollback.
    // Network behavior is covered by the real-netd integration tests.
    #[tokio::test]
    async fn secret_transport_startup_rolls_back_failure_timeout_and_cancellation() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        for mode in ["reject", "epipe", "stall", "cancel", "oversize"] {
            let temp = tempfile::Builder::new()
                .prefix("s2-")
                .tempdir_in("/tmp")
                .unwrap();
            let paths = LocalPaths::from_roots(LocalRoots::with_roots(
                temp.path().join("data"),
                temp.path().join("run"),
            ));
            let store = Store::new(&paths).await.unwrap();
            let machine_id = MachineId::new();
            let policy = oauth_policy();
            let metadata = MachineConfig {
                id: machine_id,
                lock_id: LockId::from(0),
                name: "transport-test".into(),
                spec: vm_spec::VmSpec::current(),
                retention: crate::MachineRetention::Persistent,
                process: crate::ProcessConfig::default(),
                template_name: None,
                agent_mode: None,
                machine_dir: paths.machine(machine_id).dir().to_path_buf(),
                created_at: 1,
                modified_at: 1,
                image_ref: String::new(),
                root_disk_size: None,
                labels: BTreeMap::new(),
                metadata: BTreeMap::new(),
                network: MachineNetworkConfig::Private {
                    policy: Some(policy.clone()),
                    publish: None,
                },
                guest: crate::machine::MachineGuestConfig::default(),
            };
            let launch = EgressCredentials::new()
                .secret_bytes(
                    "codex.oauth.access_token",
                    vec![0xab; if mode == "oversize" { 16384 } else { 12000 }],
                )
                .secret("codex.oauth.expires_at", "2026-09-30T00:00:00Z")
                .into();
            let executable = temp.path().join("transport");
            let marker = temp.path().join("spawned");
            let received = temp.path().join("received");
            let script = format!(
                r#"#!/usr/bin/python3
import os,sys,time,json,fcntl
a=sys.argv[1:]
def flag(name): return a[a.index(name)+1]
open({marker:?},'w').write(str(os.getpid()))
assert not any(k.startswith('SILO_NET_') for k in os.environ)
assert not any('q6ur' in arg for arg in a)
for key in ['--log-dir-fd','--runtime-dir-fd','--secrets-fd']:
 assert fcntl.fcntl(int(flag(key)),fcntl.F_GETFD)==0
fd=int(flag('--secrets-fd'))
mode={mode:?}
if mode=='epipe':
 os.close(fd)
 sys.exit(1)
if mode in ['stall','cancel']:
 time.sleep(30)
data=b''
while True:
 b=os.read(fd,127)
 if not b: break
 data+=b
 time.sleep(.001)
os.close(fd)
h,b=data.split(b'\r\n\r\n',1)
assert h==('Content-Length: '+str(len(b))).encode()
assert len(b)<=16384
p=json.loads(b)
assert p['version']==1 and len(p['secrets'])==2
open({received:?},'wb').write(data)
report={{'pid':os.getpid(),'vm_id':flag('--vm-id'),'run_id':flag('--run-id'),'network_id':flag('--network-id'),'ready':False,'error':'transport-only rejection'}}
os.write(int(flag('--startup-fd')),json.dumps(report).encode()+b'\n')
"#,
                marker = marker.to_str().unwrap(),
                received = received.to_str().unwrap()
            );
            std::fs::write(&executable, script).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let networking = RuntimeNetworkingConfig::default();
            let context = NetworkDriverContext {
                paths: &paths,
                store: &store,
                metadata: &metadata,
                run_id: "transport-run",
                config: &networking,
                netd_path: &executable,
                egress_credentials: &launch,
            };
            let request = NetworkAttachmentRequest::private(Some(&policy), None);
            let start = std::time::Instant::now();
            let future = prepare_netd_runtime(&context, &request);
            if mode == "cancel" {
                assert!(tokio::time::timeout(Duration::from_millis(150), future)
                    .await
                    .is_err());
            } else {
                let error = future
                    .await
                    .expect_err("transport test must reject startup")
                    .to_string();
                match mode {
                    "oversize" => assert!(error.contains("exceeds limit"), "{error}"),
                    "stall" => assert!(error.contains("timed out"), "{error}"),
                    "reject" => assert!(error.contains("transport-only rejection"), "{error}"),
                    "epipe" => assert!(
                        error.contains("EPIPE") || error.contains("launcher exited"),
                        "{error}"
                    ),
                    _ => unreachable!(),
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(6),
                "startup budget reset"
            );
            if mode == "oversize" {
                assert!(!marker.exists(), "oversize payload spawned a process");
            } else {
                let pid: i32 = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
                assert!(
                    crate::supervisor::process::ProcessIdentity::for_pid(pid)
                        .unwrap()
                        .is_none(),
                    "startup child was not reaped"
                );
            }
            if mode == "reject" {
                let bytes = std::fs::read(&received).unwrap();
                assert_eq!(
                    bytes,
                    *crate::network::secret_transport::frame(&launch, Some(&policy), "test")
                        .unwrap()
                );
            }
            let network_root = temp.path().join("run/networks");
            if network_root.exists() {
                assert_eq!(
                    std::fs::read_dir(network_root).unwrap().count(),
                    0,
                    "startup left runtime files"
                );
            }
            assert!(store
                .network_attachment(machine_id)
                .await
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn secret_transport_strips_ambient_environment_in_real_child() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "network::netd_driver::tests::netd_launches_the_resolved_absolute_helper",
            ])
            .env("SILO_NET_SECRET_API_KEY", "ambient-secret")
            .env("SILO_NET_OAUTH_REFRESH_AUTH", "ambient-grant")
            .env("SILO_NET_UNKNOWN_FUTURE_KEY", "ambient-value")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
