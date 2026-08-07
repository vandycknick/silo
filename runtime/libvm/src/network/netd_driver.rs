use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use agent_spec::{NetworkDnsConfig, NetworkIpv4Config};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use silo_policy::NetworkPolicy;
use tokio::time::sleep;
use utils::format_mac;

use crate::host;
use crate::machine::{EgressCredentials, OAuthRefreshHook};
use crate::paths::{
    LocalPaths, NETWORK_AUDIT_LOG_FILE_NAME, NETWORK_SERVICE_LOG_FILE_NAME, PCAP_FILE_NAME,
    PID_FILE_NAME,
};
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, NetworkAttachment, NetworkInstance, NetworkInstanceState,
};
use crate::utils::now_unix;
use crate::vmmon::process::{self, ProcessIdentity};
use crate::{LibVmError, NetdRuntimeConfig};

use super::core::{NetworkAttachmentRequest, NetworkDriverBackend, NetworkDriverContext};
use super::{mac_from_machine_id, serialize_json, DRIVER_NETD};

const READY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STDERR_CAPTURE_LIMIT: usize = 64 * 1024;
const OAUTH_REFRESH_HOOK_ENV: &str = "SILO_NET_OAUTH_REFRESH_HOOK";
const OAUTH_REFRESH_AUTH_ENV: &str = "SILO_NET_OAUTH_REFRESH_AUTH";

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
    ) -> Result<super::VmmonNetworkAttachment, LibVmError> {
        prepare_netd_runtime(ctx, request).await
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn prepare_netd_runtime(
    ctx: &NetworkDriverContext<'_>,
    request: &NetworkAttachmentRequest<'_>,
) -> Result<super::VmmonNetworkAttachment, LibVmError> {
    let paths = ctx.paths;
    let store = ctx.store;
    let metadata = ctx.metadata;
    let config = ctx.config.netd.clone();
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
    let certificate_authority_paths = requires_certificate_authority
        .then(|| resolve_certificate_authority_paths(paths, &config, &metadata.name))
        .transpose()?;
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
            tls_ca_cert_path: certificate_authority_paths
                .as_ref()
                .map(|(certificate, _)| certificate.as_path()),
            tls_ca_key_path: certificate_authority_paths
                .as_ref()
                .map(|(_, private_key)| private_key.as_path()),
            static_lease: &static_lease,
        },
    );
    configure_egress_credentials_environment(
        &mut command,
        ctx.egress_credentials,
        request.policy(),
        &metadata.name,
    )?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    unsafe {
        command.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::other)?;
            Ok(())
        });
    }

    let child = command.spawn();
    drop(log_directory_fd);
    drop(runtime_directory_fd);
    let mut child = child.map_err(|err| LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message: format!("spawn userspace network helper: {err}"),
    })?;
    let stderr_capture = child.stderr.take().map(CapturedStderr::spawn);
    startup.set_child(child, stderr_capture);
    let pid = startup
        .helper_pid()
        .ok_or_else(|| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: "userspace network helper was not started".to_string(),
        })?
        .map_err(|_| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: "userspace network helper pid does not fit in i32".to_string(),
        })?;
    let helper_started_at = ProcessIdentity::for_pid(pid)?
        .and_then(|identity| identity.started_at())
        .ok_or_else(|| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!("netd pid {pid} has no stable process generation"),
        })?;

    let startup_result = {
        let child = startup
            .child_mut()
            .ok_or_else(|| LibVmError::NetworkRuntime {
                reference: metadata.name.clone(),
                message: "userspace network helper was not started".to_string(),
            })?;
        wait_for_netd_startup(&socket_path, child).await
    };
    if let Err(err) = startup_result {
        let stderr_lines = startup.rollback_after_startup_failure();
        return Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format_netd_startup_failure(&err, &stderr_lines, &log_path),
        });
    }

    let network = super::VmmonNetworkAttachment::UnixDatagram {
        path: socket_path.clone(),
        mac: mac.clone(),
        ipv4,
        dns,
        requires_certificate_authority,
    };
    let (ipv4, dns) = match &network {
        super::VmmonNetworkAttachment::UnixDatagram { ipv4, dns, .. } => {
            (ipv4.clone(), dns.clone())
        }
        super::VmmonNetworkAttachment::None => {
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
    startup.commit();
    Ok(network)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn prepare_netd_runtime(
    _ctx: &NetworkDriverContext<'_>,
    _request: &NetworkAttachmentRequest<'_>,
) -> Result<super::VmmonNetworkAttachment, LibVmError> {
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
    tls_ca_cert_path: Option<&'a Path>,
    tls_ca_key_path: Option<&'a Path>,
    static_lease: &'a str,
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
    if let Some(path) = config.tls_ca_cert_path {
        command.arg("--tls-ca-cert").arg(path);
    }
    if let Some(path) = config.tls_ca_key_path {
        command.arg("--tls-ca-key").arg(path);
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

fn configure_egress_credentials_environment(
    command: &mut Command,
    launch: &EgressCredentials,
    policy: Option<&NetworkPolicy>,
    reference: &str,
) -> Result<(), LibVmError> {
    let Some(policy) = policy else {
        if launch.is_empty() {
            return Ok(());
        }
        return Err(LibVmError::NetworkRuntime {
            reference: reference.to_string(),
            message: "network launch material requires a persisted network policy".to_string(),
        });
    };

    for (name, value) in launch.secret_environment(policy, reference)? {
        command.env(name, value);
    }
    if let Some(hook) = &launch.oauth_refresh_hook {
        command.env(
            OAUTH_REFRESH_HOOK_ENV,
            encode_oauth_refresh_hook_config(hook, reference)?,
        );
        command.env(OAUTH_REFRESH_AUTH_ENV, hook.encoded_auth());
    }
    Ok(())
}

#[derive(Serialize)]
struct OAuthRefreshHookConfig<'a> {
    version: u8,
    command: &'a str,
    args: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_skew_seconds: Option<u64>,
}

fn encode_oauth_refresh_hook_config(
    hook: &OAuthRefreshHook,
    reference: &str,
) -> Result<String, LibVmError> {
    let command = hook
        .command
        .to_str()
        .ok_or_else(|| LibVmError::NetworkRuntime {
            reference: reference.to_string(),
            message: "OAuth refresh hook command must be valid UTF-8".to_string(),
        })?;
    let config = OAuthRefreshHookConfig {
        version: 1,
        command,
        args: &hook.args,
        timeout_ms: hook.timeout_ms,
        refresh_skew_seconds: hook.refresh_skew_seconds,
    };
    let bytes = serde_json::to_vec(&config).map_err(|err| LibVmError::NetworkRuntime {
        reference: reference.to_string(),
        message: format!("serialize OAuth refresh hook config: {err}"),
    })?;
    Ok(STANDARD.encode(bytes))
}

fn resolve_certificate_authority_paths(
    paths: &LocalPaths,
    config: &NetdRuntimeConfig,
    reference: &str,
) -> Result<(PathBuf, PathBuf), LibVmError> {
    match (&config.tls_ca_cert, &config.tls_ca_key) {
        (Some(certificate_path), Some(private_key_path)) => {
            Ok((certificate_path.clone(), private_key_path.clone()))
        }
        (None, None) => {
            let authority = host::ensure_certificate_authority_in(paths).map_err(|err| {
                LibVmError::NetworkRuntime {
                    reference: reference.to_string(),
                    message: format!("ensure certificate authority: {err}"),
                }
            })?;
            Ok((authority.certificate_path, authority.private_key_path))
        }
        _ => Err(LibVmError::NetworkRuntime {
            reference: reference.to_string(),
            message:
                "certificate authority certificate and private key must be configured together"
                    .to_string(),
        }),
    }
}

async fn wait_for_netd_startup(path: &Path, child: &mut Child) -> Result<(), String> {
    let deadline = std::time::Instant::now() + READY_TIMEOUT;
    loop {
        if path.exists() {
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "userspace network helper exited during startup with status {status}"
                ));
            }
            Ok(None) => {}
            Err(err) => {
                return Err(format!(
                    "check userspace network helper startup status: {err}"
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "userspace network helper did not create socket {}",
                path.display()
            ));
        }
        sleep(READY_POLL_INTERVAL).await;
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
            stderr_capture: None,
            armed: true,
        }
    }

    fn set_child(&mut self, child: Child, stderr_capture: Option<CapturedStderr>) {
        self.child = Some(child);
        self.stderr_capture = stderr_capture;
    }

    fn helper_pid(&self) -> Option<Result<i32, std::num::TryFromIntError>> {
        self.child.as_ref().map(|child| i32::try_from(child.id()))
    }

    fn child_mut(&mut self) -> Option<&mut Child> {
        self.child.as_mut()
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
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if let Ok(pid) = i32::try_from(child.id()) {
            if let Ok(Some(identity)) = ProcessIdentity::for_pid(pid) {
                let _ = terminate_helper(&identity);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
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
    let Some(identity) = instance_process_identity(instance)? else {
        return Ok(());
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
    let state = driver_state(instance)?;
    let Some(identity) = ProcessIdentity::for_pid(state.helper_pid)? else {
        return Ok(None);
    };
    if !identity.matches_started_at(Some(state.helper_started_at)) {
        return Err(LibVmError::NetworkRuntime {
            reference: instance.id.clone(),
            message: format!(
                "netd pid {} is a different process generation than persisted runtime {}",
                state.helper_pid, instance.id
            ),
        });
    }
    Ok(Some(identity))
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
    let _ = kill(process_group, Signal::SIGTERM);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        append_bounded_stderr_line, configure_network_helper_command,
        configure_egress_credentials_environment, format_netd_startup_failure, prepare_netd_runtime,
        private_ipv4_config, resolve_certificate_authority_paths, CapturedStderrLines,
        NetworkHelperCommandConfig, OAUTH_REFRESH_AUTH_ENV, OAUTH_REFRESH_HOOK_ENV,
        STDERR_CAPTURE_LIMIT,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::json;
    use silo_policy::NetworkPolicy;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::lock_manager::LockId;
    use crate::machine::{EgressCredentials, OAuthRefreshHook};
    use crate::network::core::{NetworkAttachmentRequest, NetworkDriverContext};
    use crate::paths::{LocalPaths, LocalRoots};
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRuntimeState, MachineState,
        NetworkInstance, NetworkInstanceState,
    };
    use crate::store::{MachineStore, Store};
    use crate::{NetdRuntimeConfig, RuntimeNetworkingConfig};

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
                tls_ca_cert_path: None,
                tls_ca_key_path: None,
                static_lease: "192.168.105.2=02:00:00:00:00:02",
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
                tls_ca_cert_path: Some(Path::new("/tmp/silo-net/ca.pem")),
                tls_ca_key_path: Some(Path::new("/tmp/silo-net/ca-key.pem")),
                static_lease: "192.168.105.2=02:00:00:00:00:02",
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
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--tls-ca-cert" && window[1] == "/tmp/silo-net/ca.pem"));
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--tls-ca-key" && window[1] == "/tmp/silo-net/ca-key.pem"));
    }

    #[test]
    fn netd_command_sets_egress_credentials_environment() {
        let policy = oauth_policy();
        let launch = EgressCredentials::new()
            .secret("codex.oauth.access_token", "token")
            .secret("codex.oauth.expires_at", "2026-07-04T00:00:00Z")
            .oauth_refresh_hook(
                OAuthRefreshHook::new("/usr/bin/silo", b"auth".to_vec())
                    .arg("secret")
                    .arg("refresh-oauth")
                    .timeout_ms(2500)
                    .refresh_skew_seconds(120),
            );
        let mut command = Command::new("/tmp/netd");

        configure_egress_credentials_environment(&mut command, &launch, Some(&policy), "devbox")
            .expect("configure launch environment");

        let env = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.expect("env value").to_string_lossy().into_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            env.get("SILO_NET_SECRET_CODEX_OAUTH_ACCESS_TOKEN"),
            Some(&"dG9rZW4=".to_string())
        );
        assert_eq!(
            env.get(OAUTH_REFRESH_AUTH_ENV),
            Some(&"YXV0aA==".to_string())
        );

        let hook_config = env.get(OAUTH_REFRESH_HOOK_ENV).expect("hook config env");
        let hook_json = STANDARD.decode(hook_config).expect("decode hook config");
        let hook_json: serde_json::Value =
            serde_json::from_slice(&hook_json).expect("parse hook config");
        assert_eq!(
            hook_json,
            json!({
                "version": 1,
                "command": "/usr/bin/silo",
                "args": ["secret", "refresh-oauth"],
                "timeout_ms": 2500,
                "refresh_skew_seconds": 120
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
    fn certificate_authority_paths_use_config_overrides() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let config = NetdRuntimeConfig {
            tls_ca_cert: Some(PathBuf::from("/tmp/custom-ca.pem")),
            tls_ca_key: Some(PathBuf::from("/tmp/custom-ca-key.pem")),
            ..NetdRuntimeConfig::default()
        };

        let (certificate_path, private_key_path) =
            resolve_certificate_authority_paths(&paths, &config, "test-machine")
                .expect("resolve configured CA paths");

        assert_eq!(certificate_path, PathBuf::from("/tmp/custom-ca.pem"));
        assert_eq!(private_key_path, PathBuf::from("/tmp/custom-ca-key.pem"));
        assert!(!paths.keys_dir().exists());
    }

    #[test]
    fn certificate_authority_paths_generate_defaults() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("silo"));

        let (certificate_path, private_key_path) = resolve_certificate_authority_paths(
            &paths,
            &NetdRuntimeConfig::default(),
            "test-machine",
        )
        .expect("resolve generated CA paths");

        assert_eq!(certificate_path, paths.keys_dir().join("ca.pem"));
        assert_eq!(private_key_path, paths.keys_dir().join("ca-key.pem"));
        assert!(certificate_path.is_file());
        assert!(private_key_path.is_file());
    }

    #[test]
    fn certificate_authority_paths_reject_partial_config() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let config = NetdRuntimeConfig {
            tls_ca_cert: Some(PathBuf::from("/tmp/custom-ca.pem")),
            ..NetdRuntimeConfig::default()
        };

        let err = resolve_certificate_authority_paths(&paths, &config, "test-machine")
            .expect_err("reject partial CA config");

        assert!(err.to_string().contains(
            "certificate authority certificate and private key must be configured together"
        ));
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

    #[test]
    fn netd_identity_rejects_a_live_reused_generation() {
        let mut child = Command::new("sh")
            .args(["-c", "while :; do sleep 1; done"])
            .spawn()
            .expect("spawn helper");
        let pid = i32::try_from(child.id()).expect("pid fits i32");
        let started_at = crate::vmmon::process::ProcessIdentity::for_pid(pid)
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

        assert!(super::instance_process_identity(&instance).is_err());
        assert!(child.try_wait().expect("check helper").is_none());
        child.kill().expect("stop helper");
        child.wait().expect("reap helper");
    }

    #[tokio::test]
    async fn netd_launches_the_resolved_absolute_helper() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("data");
        let state_root = temp.path().join("state");
        let run_root = temp.path().join("run");
        let paths = LocalPaths::from_roots(LocalRoots::with_roots(
            &data_root,
            &state_root,
            &run_root,
            data_root.join("images"),
        ));
        let netd = temp.path().join("runtime/bin/netd");
        std::fs::create_dir_all(netd.parent().expect("netd parent")).expect("create netd parent");
        std::fs::write(
            &netd,
            "#!/bin/sh\nsocket=\nlog_dir_fd=\nruntime_dir_fd=\nlog=\naudit=\nrun=\nprevious=\nfor arg do\n  if [ \"$previous\" = \"--listen-vfkit\" ]; then socket=\"${arg#unixgram://}\"; fi\n  if [ \"$previous\" = \"--log-dir-fd\" ]; then log_dir_fd=\"$arg\"; fi\n  if [ \"$previous\" = \"--runtime-dir-fd\" ]; then runtime_dir_fd=\"$arg\"; fi\n  if [ \"$previous\" = \"--log-file\" ]; then log=\"$arg\"; fi\n  if [ \"$previous\" = \"--audit-log-file\" ]; then audit=\"$arg\"; fi\n  if [ \"$previous\" = \"--run-id\" ]; then run=\"$arg\"; fi\n  previous=\"$arg\"\ndone\nif [ \"$log\" != netd.log ] || [ \"$audit\" != audit.jsonl ] || [ ! -d \"/dev/fd/$log_dir_fd\" ] || [ ! -d \"/dev/fd/$runtime_dir_fd\" ]; then exit 42; fi\nprintf '%s\\n' \"$0\" > \"$0.program\"\nprintf '%s\\n' \"$log_dir_fd,$runtime_dir_fd\" > \"$0.directories\"\nprintf '%s\\n' \"$run\" > \"$0.run\"\n: > \"$socket\"\nwhile :; do sleep 1; done\n",
        )
        .expect("write netd helper");
        std::fs::set_permissions(&netd, std::fs::Permissions::from_mode(0o755))
            .expect("make netd executable");
        let store = Store::new(&paths).await.expect("open store");
        let machine_id = MachineId::new();
        let metadata = MachineConfig {
            id: machine_id,
            lock_id: LockId::from(0),
            name: "netd-resolved-path".to_string(),
            spec: vm_spec::VmSpec::current(),
            machine_dir: paths.machine(machine_id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: MachineNetworkConfig::Private { policy: None },
            guest: crate::machine::MachineGuestConfig::default(),
        };
        let state = MachineState {
            machine_id,
            status: MachineRuntimeState::Stopped,
            vmmon_pid: None,
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
        let launch = EgressCredentials::default();
        let context = NetworkDriverContext {
            paths: &paths,
            store: &store,
            metadata: &metadata,
            run_id: "run-123",
            config: &networking,
            netd_path: &netd,
            egress_credentials: &launch,
        };

        let attachment = prepare_netd_runtime(&context, &NetworkAttachmentRequest::private(None))
            .await
            .expect("launch resolved netd");

        let log_path = match attachment {
            crate::network::VmmonNetworkAttachment::UnixDatagram { .. } => {
                paths.machine(machine_id).network_service_log_path()
            }
            crate::network::VmmonNetworkAttachment::None => panic!("netd must attach a socket"),
        };
        assert_eq!(
            log_path,
            state_root
                .join("logs/machines")
                .join(machine_id.to_string())
                .join("network/netd.log")
        );
        assert!(!state_root.join("logs/networks").exists());
        let directory_fds = std::fs::read_to_string(netd.with_extension("directories"))
            .expect("read inherited directories");
        let (log_directory_fd, runtime_directory_fd) = directory_fds
            .trim()
            .split_once(',')
            .expect("recorded directory descriptors");
        assert!(log_directory_fd.parse::<i32>().is_ok());
        assert!(runtime_directory_fd.parse::<i32>().is_ok());
        assert_ne!(log_directory_fd, runtime_directory_fd);
        assert_eq!(
            std::fs::read_to_string(netd.with_extension("run"))
                .expect("read netd run id")
                .trim(),
            "run-123"
        );
        assert_eq!(
            std::fs::read_to_string(netd.with_extension("program"))
                .expect("read executed netd path")
                .trim(),
            netd.display().to_string()
        );

        crate::network::reconcile_network_runtime(&paths, &store, &metadata, false)
            .await
            .expect("clean netd runtime");
    }
}
