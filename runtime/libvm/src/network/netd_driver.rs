use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
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
use crate::machine::{NetworkLaunch, OAuthRefreshHook};
use crate::paths::LocalPaths;
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, NetworkAttachment, NetworkInstance, NetworkInstanceState,
};
use crate::utils::now_unix;
use crate::{LibVmError, NetdRuntimeConfig};

use super::core::{NetworkAttachmentRequest, NetworkDriverBackend, NetworkDriverContext};
use super::{
    ensure_instance_network_link, mac_from_machine_id, remove_file_if_exists, remove_runtime_dir,
    serialize_json, DRIVER_NETD,
};

const NETD_BINARY_ENV: &str = "NETD_BIN";
const NETD_BINARY_NAME: &str = "netd";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STDERR_CAPTURE_LIMIT: usize = 64 * 1024;
const OAUTH_REFRESH_HOOK_ENV: &str = "SILO_NET_OAUTH_REFRESH_HOOK";
const OAUTH_REFRESH_AUTH_ENV: &str = "SILO_NET_OAUTH_REFRESH_AUTH";

pub(super) struct NetdDriver;

#[derive(Debug, Serialize, Deserialize)]
struct NetdDriverState {
    helper_pid: i32,
    subnet: String,
    socket_path: PathBuf,
    log_path: PathBuf,
    pid_path: PathBuf,
    pcap_path: Option<PathBuf>,
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
    let network_paths = paths.network(&network_id);
    let runtime_dir = network_paths.dir().to_path_buf();
    fs::create_dir_all(&runtime_dir)?;
    ensure_instance_network_link(paths, metadata.id, &runtime_dir)?;
    let mut startup = NetdStartupGuard::new(paths, metadata.id, runtime_dir.clone());

    let socket_path = network_paths.socket_path();
    let log_path = network_paths.log_path();
    let pid_path = network_paths.pid_path();
    let pcap_path = config.pcap.then(|| network_paths.pcap_path());
    let policy_path = if let Some(policy) = request.policy() {
        let path = network_paths.policy_path();
        write_runtime_policy_file(metadata, policy, &path)?;
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
    remove_file_if_exists(&socket_path)?;
    remove_file_if_exists(&pid_path)?;

    let mac = format_mac(mac_from_machine_id(metadata.id));
    let (ipv4, dns) = private_ipv4_config(&config.subnet, &metadata.name)?;
    let static_lease = format!("{}={mac}", ipv4.address);

    let log = File::options().create(true).append(true).open(&log_path)?;
    let mut command = Command::new(resolve_netd_binary());
    configure_network_helper_command(
        &mut command,
        &NetworkHelperCommandConfig {
            socket_path: &socket_path,
            subnet: &config.subnet,
            log_path: &log_path,
            pid_path: &pid_path,
            pcap_path: pcap_path.as_deref(),
            machine_id: metadata.id,
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
    configure_network_launch_environment(
        &mut command,
        ctx.network_launch,
        request.policy(),
        &metadata.name,
    )?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::piped());

    unsafe {
        command.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::other)?;
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(|err| LibVmError::NetworkRuntime {
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
    let driver_state = NetdDriverState {
        helper_pid: pid,
        subnet: config.subnet.clone(),
        socket_path: socket_path.clone(),
        log_path: log_path.clone(),
        pid_path: pid_path.clone(),
        pcap_path: pcap_path.clone(),
    };
    let now = now_unix();
    store
        .save_network_instance(&NetworkInstance {
            id: network_id.clone(),
            driver: DRIVER_NETD.to_string(),
            definition_name: None,
            runtime_dir: runtime_dir.display().to_string(),
            attachment_json: serialize_json(&network, "network attachment")?,
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
    log_path: &'a Path,
    pid_path: &'a Path,
    pcap_path: Option<&'a Path>,
    machine_id: MachineId,
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
        .arg("--log-file")
        .arg(config.log_path)
        .arg("--pid-file")
        .arg(config.pid_path);
    if let Some(path) = config.pcap_path {
        command.arg("--pcap").arg(path);
    }
    command
        .arg("--vm-id")
        .arg(config.machine_id.to_string())
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
    path: &Path,
) -> Result<(), LibVmError> {
    let normalized = policy.clone().normalized();
    let mut bytes =
        serde_json::to_vec_pretty(&normalized).map_err(|err| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!("serialize generated network policy: {err}"),
        })?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|err| LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message: format!("write generated network policy {}: {err}", path.display()),
    })
}

fn configure_network_launch_environment(
    command: &mut Command,
    launch: &NetworkLaunch,
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
struct NetdStartupGuard<'a> {
    paths: &'a LocalPaths,
    machine_id: MachineId,
    runtime_dir: PathBuf,
    child: Option<Child>,
    stderr_capture: Option<CapturedStderr>,
    armed: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<'a> NetdStartupGuard<'a> {
    fn new(paths: &'a LocalPaths, machine_id: MachineId, runtime_dir: PathBuf) -> Self {
        Self {
            paths,
            machine_id,
            runtime_dir,
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
            let _ = terminate_helper(pid);
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    fn rollback_files(&mut self) {
        let _ = super::remove_instance_network_link(self.paths, self.machine_id);
        let _ = remove_runtime_dir(&self.runtime_dir);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for NetdStartupGuard<'_> {
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

fn resolve_netd_binary() -> String {
    std::env::var(NETD_BINARY_ENV).unwrap_or_else(|_| resolve_sibling_binary(NETD_BINARY_NAME))
}

fn resolve_sibling_binary(name: &str) -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(name)))
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| name.to_string())
}

pub(super) fn instance_is_alive(instance: &NetworkInstance) -> bool {
    driver_state(instance)
        .map(|state| process_is_alive(state.helper_pid))
        .unwrap_or(false)
}

pub(super) fn terminate_instance(instance: &NetworkInstance) -> Result<(), LibVmError> {
    if let Some(state) = driver_state(instance) {
        terminate_helper(state.helper_pid)?;
    }
    Ok(())
}

fn driver_state(instance: &NetworkInstance) -> Option<NetdDriverState> {
    serde_json::from_str(&instance.driver_state_json).ok()
}

fn process_is_alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

fn terminate_helper(pid: i32) -> Result<(), LibVmError> {
    if pid <= 0 || !process_is_alive(pid) {
        return Ok(());
    }
    let process_group = Pid::from_raw(-pid);
    let _ = kill(process_group, Signal::SIGTERM);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        append_bounded_stderr_line, configure_network_helper_command,
        configure_network_launch_environment, format_netd_startup_failure, private_ipv4_config,
        resolve_certificate_authority_paths, CapturedStderrLines, NetworkHelperCommandConfig,
        OAUTH_REFRESH_AUTH_ENV, OAUTH_REFRESH_HOOK_ENV, STDERR_CAPTURE_LIMIT,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::json;
    use silo_policy::NetworkPolicy;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::machine::{NetworkLaunch, OAuthRefreshHook};
    use crate::paths::LocalPaths;
    use crate::store::models::MachineId;
    use crate::NetdRuntimeConfig;

    fn oauth_policy() -> NetworkPolicy {
        NetworkPolicy::from_json_str(
            r#"{
                "version": 1,
                "metadata": {},
                "endpoints": [
                    { "name": "chatgpt", "kind": "https", "hosts": ["chatgpt.com"] }
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
        let mut command = Command::new("netd");
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                socket_path: Path::new("/tmp/silo-net/netd.sock"),
                subnet: "192.168.105.0/24",
                log_path: Path::new("/tmp/silo-net/netd.log"),
                pid_path: Path::new("/tmp/silo-net/netd.pid"),
                pcap_path: None,
                machine_id: MachineId::new(),
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
        let mut command = Command::new("netd");
        let machine_id = MachineId::new();
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                socket_path: Path::new("/tmp/silo-net/netd.sock"),
                subnet: "192.168.105.0/24",
                log_path: Path::new("/tmp/silo-net/netd.log"),
                pid_path: Path::new("/tmp/silo-net/netd.pid"),
                pcap_path: None,
                machine_id,
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
    fn netd_command_sets_network_launch_environment() {
        let policy = oauth_policy();
        let launch = NetworkLaunch::new()
            .secret("codex.oauth.access_token", "token")
            .secret("codex.oauth.expires_at", "2026-07-04T00:00:00Z")
            .oauth_refresh_hook(
                OAuthRefreshHook::new("/usr/bin/silo", b"auth".to_vec())
                    .arg("secret")
                    .arg("refresh-oauth")
                    .timeout_ms(2500)
                    .refresh_skew_seconds(120),
            );
        let mut command = Command::new("netd");

        configure_network_launch_environment(&mut command, &launch, Some(&policy), "devbox")
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
}
