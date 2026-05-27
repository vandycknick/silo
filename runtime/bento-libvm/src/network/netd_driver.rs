use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use bento_core::{MachineId, Network, NetworkPolicyFeature, NetworkPolicySpec};
use bento_utils::format_mac;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::state::{MachineState, NetworkAttachmentState, NetworkInstanceState, StateStore};
use crate::{Layout, LibVmError};

use super::core::{NetworkDriver, NetworkDriverContext, NetworkRequest, PreparedNetwork};
use super::{
    ensure_instance_network_link, mac_from_machine_id, network_attachment_from_instance, now_unix,
    remove_file_if_exists, remove_runtime_dir, serialize_json, write_runtime_file, DRIVER_NETD,
};

const BENTO_NETD_BINARY_ENV: &str = "BENTO_NETD_BIN";
const BENTO_NETD_BINARY_NAME: &str = "bento-netd";
const BENTO_NETD_DISABLE_SSH_PORT: &str = "-1";
const RUNNING_STATE: &str = "running";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);

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

impl NetworkDriver for NetdDriver {
    fn id(&self) -> &'static str {
        DRIVER_NETD
    }

    fn supports(&self, reference: &str, request: &NetworkRequest<'_>) -> Result<(), LibVmError> {
        validate_policy_features(reference, self.id(), request.policy)
    }

    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        request: &NetworkRequest<'_>,
    ) -> Result<PreparedNetwork, LibVmError> {
        prepare_netd_runtime(ctx, request).await
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn prepare_netd_runtime(
    ctx: &NetworkDriverContext<'_>,
    request: &NetworkRequest<'_>,
) -> Result<PreparedNetwork, LibVmError> {
    let layout = ctx.layout;
    let state = ctx.state;
    let metadata = ctx.metadata;
    let config = ctx.config.netd.clone();
    if !host_uses_user_network_runtime() {
        return Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: "userspace networking is not supported on this host".to_string(),
        });
    }

    if let Some(definition_name) = request.definition_name {
        if let Some(instance) = state.get_network_instance_by_definition(definition_name)? {
            if instance_is_alive(&instance) {
                return attach_existing_runtime(layout, state, metadata, &instance);
            }
            state.remove_network_instance(&instance.id)?;
            remove_runtime_dir(Path::new(&instance.runtime_dir))?;
        }
    }

    let network_id = MachineId::new().to_string();
    let runtime_dir = layout.network_instance_dir(&network_id);
    fs::create_dir_all(&runtime_dir)?;
    ensure_instance_network_link(layout, metadata.id, &runtime_dir)?;

    let socket_path = layout.network_socket_path(&network_id);
    let log_path = layout.network_log_path(&network_id);
    let pid_path = layout.network_pid_path(&network_id);
    let policy_path = layout.network_policy_path(&network_id);
    let default_audit_log_path = layout.network_audit_log_path(&network_id);
    let pcap_path = config.pcap.then(|| layout.network_pcap_path(&network_id));
    remove_file_if_exists(&socket_path)?;
    remove_file_if_exists(&layout.network_runtime_path(&network_id))?;
    remove_file_if_exists(&policy_path)?;
    remove_file_if_exists(&default_audit_log_path)?;
    remove_file_if_exists(&pid_path)?;
    let policy_file = write_network_policy_file(request.policy, &policy_path)?;

    let log = File::options().create(true).append(true).open(&log_path)?;
    let mut command = Command::new(resolve_bento_netd_binary());
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
            policy_path: policy_file.as_ref().map(|policy| policy.path.as_path()),
            audit_log_path: policy_file
                .as_ref()
                .and_then(|policy| policy.audit_enabled.then_some(policy.audit_path.as_path())),
        },
    );
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));

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
    let pid = i32::try_from(child.id()).map_err(|_| LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message: "userspace network helper pid does not fit in i32".to_string(),
    })?;

    if let Err(err) = wait_for_socket(&socket_path).await {
        let _ = child.kill();
        let _ = child.wait();
        let _ = super::remove_instance_network_link(layout, metadata.id);
        return Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!("{err} (preserved runtime dir: {})", runtime_dir.display()),
        });
    }

    let mac = mac_from_machine_id(metadata.id);
    let network = Network::UnixDatagram {
        path: socket_path.clone(),
        mac: format_mac(mac),
    };
    write_runtime_file(&runtime_dir, &network)?;
    let driver_state = NetdDriverState {
        helper_pid: pid,
        subnet: config.subnet.clone(),
        socket_path: socket_path.clone(),
        log_path: log_path.clone(),
        pid_path: pid_path.clone(),
        pcap_path: pcap_path.clone(),
    };
    let now = now_unix();
    state.upsert_network_instance(&NetworkInstanceState {
        id: network_id.clone(),
        driver: DRIVER_NETD.to_string(),
        definition_name: request.definition_name.map(str::to_string),
        runtime_dir: runtime_dir.display().to_string(),
        attachment_json: serialize_json(&network, "network attachment")?,
        driver_state_json: serialize_json(&driver_state, "netd driver state")?,
        state: RUNNING_STATE.to_string(),
        created_at: now,
        modified_at: now,
    })?;
    state.upsert_network_attachment(&NetworkAttachmentState {
        machine_id: metadata.id,
        network_instance_id: network_id,
        guest_mac: format_mac(mac),
        created_at: now,
        modified_at: now,
    })?;
    Ok(PreparedNetwork {
        attachment: network,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn prepare_netd_runtime(
    _ctx: &NetworkDriverContext<'_>,
    _request: &NetworkRequest<'_>,
) -> Result<PreparedNetwork, LibVmError> {
    let metadata = _ctx.metadata;
    Err(LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message: "bento-netd networking is not supported on this host".to_string(),
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

fn attach_existing_runtime(
    layout: &Layout,
    state: &StateStore,
    metadata: &MachineState,
    instance: &NetworkInstanceState,
) -> Result<PreparedNetwork, LibVmError> {
    ensure_instance_network_link(layout, metadata.id, Path::new(&instance.runtime_dir))?;
    let now = now_unix();
    let mac = format_mac(mac_from_machine_id(metadata.id));
    let attachment = network_attachment_from_instance(instance, mac.clone())?;
    state.upsert_network_attachment(&NetworkAttachmentState {
        machine_id: metadata.id,
        network_instance_id: instance.id.clone(),
        guest_mac: mac.clone(),
        created_at: now,
        modified_at: now,
    })?;
    Ok(PreparedNetwork { attachment })
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
    audit_log_path: Option<&'a Path>,
}

fn configure_network_helper_command(
    command: &mut Command,
    config: &NetworkHelperCommandConfig<'_>,
) {
    command
        .arg("--listen-vfkit")
        .arg(format!("unixgram://{}", config.socket_path.display()))
        .arg("--ssh-port")
        .arg(BENTO_NETD_DISABLE_SSH_PORT)
        .arg("--subnet")
        .arg(config.subnet)
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
    if let Some(path) = config.audit_log_path {
        command.arg("--audit-log").arg(path);
    }
}

fn write_network_policy_file(
    policy: Option<&NetworkPolicySpec>,
    path: &Path,
) -> Result<Option<NetworkPolicyFile>, LibVmError> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    let raw = serde_json::to_string(policy).map_err(|err| LibVmError::NetworkRuntime {
        reference: path.display().to_string(),
        message: format!("serialize network policy: {err}"),
    })?;
    fs::write(path, &raw)?;
    Ok(Some(network_policy_file(path, &raw)))
}

struct NetworkPolicyFile {
    path: PathBuf,
    audit_enabled: bool,
    audit_path: PathBuf,
}

fn network_policy_file(path: &Path, policy: &str) -> NetworkPolicyFile {
    let parsed = serde_json::from_str::<serde_json::Value>(policy).ok();
    let audit_enabled = parsed
        .as_ref()
        .and_then(|value| value.get("audit_log")?.get("enabled")?.as_bool())
        .unwrap_or(false)
        || parsed
            .as_ref()
            .and_then(|value| value.get("audit_log")?.get("path")?.as_str())
            .is_some();
    let audit_path = parsed
        .as_ref()
        .and_then(|value| value.get("audit_log")?.get("path")?.as_str())
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| path.with_file_name("audit.jsonl"));
    NetworkPolicyFile {
        path: path.to_path_buf(),
        audit_enabled,
        audit_path,
    }
}

fn validate_policy_features(
    reference: &str,
    driver: &str,
    policy: Option<&NetworkPolicySpec>,
) -> Result<(), LibVmError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    for feature in policy.required_features() {
        if !matches!(feature, NetworkPolicyFeature::CidrRules) {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: format!(
                    "resolved driver {:?} does not support requested policy feature {:?}",
                    driver, feature
                ),
            });
        }
    }
    Ok(())
}

async fn wait_for_socket(path: &Path) -> Result<(), String> {
    let deadline = std::time::Instant::now() + READY_TIMEOUT;
    loop {
        if path.exists() {
            return Ok(());
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

fn resolve_bento_netd_binary() -> String {
    std::env::var(BENTO_NETD_BINARY_ENV)
        .unwrap_or_else(|_| resolve_sibling_binary(BENTO_NETD_BINARY_NAME))
}

fn resolve_sibling_binary(name: &str) -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(name)))
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| name.to_string())
}

pub(super) fn instance_is_alive(instance: &NetworkInstanceState) -> bool {
    driver_state(instance)
        .map(|state| process_is_alive(state.helper_pid))
        .unwrap_or(false)
}

pub(super) fn terminate_instance(instance: &NetworkInstanceState) -> Result<(), LibVmError> {
    if let Some(state) = driver_state(instance) {
        terminate_helper(state.helper_pid)?;
    }
    Ok(())
}

fn driver_state(instance: &NetworkInstanceState) -> Option<NetdDriverState> {
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
    use super::{configure_network_helper_command, NetworkHelperCommandConfig};
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn netd_command_disables_default_ssh_forward() {
        let mut command = Command::new("bento-netd");
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                socket_path: Path::new("/tmp/bento-net/bento-netd.sock"),
                subnet: "192.168.105.0/24",
                log_path: Path::new("/tmp/bento-net/bento-netd.log"),
                pid_path: Path::new("/tmp/bento-net/bento-netd.pid"),
                pcap_path: None,
                machine_id: bento_core::MachineId::new(),
                network_id: "net123",
                policy_path: None,
                audit_log_path: None,
            },
        );

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(args.windows(2).any(|window| window == ["--ssh-port", "-1"]));
    }

    #[test]
    fn netd_command_adds_policy_metadata() {
        let mut command = Command::new("bento-netd");
        let machine_id = bento_core::MachineId::new();
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                socket_path: Path::new("/tmp/bento-net/bento-netd.sock"),
                subnet: "192.168.105.0/24",
                log_path: Path::new("/tmp/bento-net/bento-netd.log"),
                pid_path: Path::new("/tmp/bento-net/bento-netd.pid"),
                pcap_path: None,
                machine_id,
                network_id: "net123",
                policy_path: Some(Path::new("/tmp/bento-net/policy.json")),
                audit_log_path: Some(Path::new("/tmp/bento-net/audit.jsonl")),
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
        assert!(args.windows(2).any(
            |window| window[0] == "--policy-file" && window[1] == "/tmp/bento-net/policy.json"
        ));
    }
}
