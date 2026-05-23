use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bento_core::{MachineId, NetworkDriver, VmSpec};
use bento_utils::format_mac;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::Serialize;
use tokio::time::sleep;

use crate::global_config::{GlobalConfig, GvisorHelper};
use crate::state::{MachineState, NetworkAttachmentState, NetworkInstanceState, StateStore};
use crate::{Layout, LibVmError};

const GVPROXY_BINARY_ENV: &str = "GVPROXY_BIN";
const GVPROXY_BINARY_NAME: &str = "gvproxy";
const BENTO_NETD_BINARY_ENV: &str = "BENTO_NETD_BIN";
const BENTO_NETD_BINARY_NAME: &str = "bento-netd";
const GVPROXY_DISABLE_SSH_PORT: &str = "-1";
const GVISOR_DRIVER: &str = "gvisor";
const NETWORK_POLICY_METADATA_KEY: &str = "bento.network.policy";
const RUNNING_STATE: &str = "running";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Serialize)]
struct NetworkRuntimeFile {
    version: u32,
    driver: String,
    subnet: String,
    transport: NetworkTransportFile,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum NetworkTransportFile {
    Unixgram { peer_path: String, mac: String },
}

pub(crate) async fn prepare_network_runtime(
    layout: &Layout,
    state: &StateStore,
    metadata: &MachineState,
    spec: &VmSpec,
) -> Result<(), LibVmError> {
    reconcile_network_runtime(layout, state, metadata, false)?;

    match spec.network.driver {
        NetworkDriver::Gvisor if host_uses_user_network_runtime() => {
            prepare_gvisor_network_runtime(layout, state, metadata).await
        }
        NetworkDriver::None | NetworkDriver::VzNat => {
            remove_attached_network(layout, state, metadata.id)
        }
        NetworkDriver::Gvisor => Ok(()),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn host_uses_user_network_runtime() -> bool {
    true
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn host_uses_user_network_runtime() -> bool {
    false
}

pub(crate) fn reconcile_network_runtime(
    layout: &Layout,
    state: &StateStore,
    metadata: &MachineState,
    monitor_running: bool,
) -> Result<(), LibVmError> {
    let Some(attachment) = state.get_network_attachment(metadata.id)? else {
        return Ok(());
    };
    let Some(instance) = state.get_network_instance(&attachment.network_instance_id)? else {
        remove_instance_network_link(layout, metadata.id)?;
        state.remove_network_attachment(metadata.id)?;
        return Ok(());
    };

    if monitor_running && process_is_alive(instance.helper_pid) {
        ensure_instance_network_link(layout, metadata.id, Path::new(&instance.runtime_dir))?;
        return Ok(());
    }

    terminate_helper(instance.helper_pid)?;
    state.remove_network_attachment(metadata.id)?;
    state.remove_network_instance(&instance.id)?;
    remove_instance_network_link(layout, metadata.id)?;
    remove_runtime_dir(Path::new(&instance.runtime_dir))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn prepare_gvisor_network_runtime(
    layout: &Layout,
    state: &StateStore,
    metadata: &MachineState,
) -> Result<(), LibVmError> {
    let global_config = GlobalConfig::load().map_err(|err| LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message: format!("load gvisor networking defaults: {err}"),
    })?;
    let gvisor = global_config.networking.gvisor;

    let network_id = MachineId::new().to_string();
    let runtime_dir = layout.network_instance_dir(&network_id);
    fs::create_dir_all(&runtime_dir)?;
    ensure_instance_network_link(layout, metadata.id, &runtime_dir)?;

    let socket_path = layout.gvproxy_socket_path(&network_id);
    let log_path = layout.gvproxy_log_path(&network_id);
    let pid_path = layout.gvproxy_pid_path(&network_id);
    let policy_path = layout.network_policy_path(&network_id);
    let default_audit_log_path = layout.network_audit_log_path(&network_id);
    let pcap_path = gvisor.pcap.then(|| layout.gvproxy_pcap_path(&network_id));
    remove_file_if_exists(&socket_path)?;
    remove_file_if_exists(&layout.network_runtime_path(&network_id))?;
    remove_file_if_exists(&policy_path)?;
    remove_file_if_exists(&default_audit_log_path)?;
    remove_file_if_exists(&pid_path)?;
    let policy_file = write_network_policy_file(metadata, &policy_path)?;

    let log = File::options().create(true).append(true).open(&log_path)?;
    let mut command = Command::new(resolve_network_helper_binary(gvisor.helper));
    configure_network_helper_command(
        &mut command,
        &NetworkHelperCommandConfig {
            helper: gvisor.helper,
            socket_path: &socket_path,
            subnet: &gvisor.subnet,
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
        let _ = remove_instance_network_link(layout, metadata.id);
        return Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!("{err} (preserved runtime dir: {})", runtime_dir.display()),
        });
    }

    let mac = mac_from_machine_id(metadata.id);
    write_runtime_file(&runtime_dir, &gvisor.subnet, &socket_path, mac)?;
    let now = now_unix();
    state.upsert_network_instance(&NetworkInstanceState {
        id: network_id.clone(),
        driver: GVISOR_DRIVER.to_string(),
        definition_name: None,
        subnet_cidr: gvisor.subnet,
        runtime_dir: runtime_dir.display().to_string(),
        helper_pid: pid,
        transport_socket_path: socket_path.display().to_string(),
        log_path: log_path.display().to_string(),
        pid_file_path: pid_path.display().to_string(),
        pcap_path: pcap_path.map(|path| path.display().to_string()),
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

    Ok(())
}

struct NetworkHelperCommandConfig<'a> {
    helper: GvisorHelper,
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
        .arg(GVPROXY_DISABLE_SSH_PORT)
        .arg("--subnet")
        .arg(config.subnet)
        .arg("--log-file")
        .arg(config.log_path)
        .arg("--pid-file")
        .arg(config.pid_path);
    if let Some(path) = config.pcap_path {
        command.arg("--pcap").arg(path);
    }
    if config.helper == GvisorHelper::BentoNetd {
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
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn prepare_gvisor_network_runtime(
    _layout: &Layout,
    _state: &StateStore,
    _metadata: &MachineState,
) -> Result<(), LibVmError> {
    Ok(())
}

fn remove_attached_network(
    layout: &Layout,
    state: &StateStore,
    machine_id: MachineId,
) -> Result<(), LibVmError> {
    let Some(attachment) = state.get_network_attachment(machine_id)? else {
        remove_instance_network_link(layout, machine_id)?;
        return Ok(());
    };
    let instance = state.get_network_instance(&attachment.network_instance_id)?;
    state.remove_network_attachment(machine_id)?;
    if let Some(instance) = instance {
        terminate_helper(instance.helper_pid)?;
        state.remove_network_instance(&instance.id)?;
        remove_runtime_dir(Path::new(&instance.runtime_dir))?;
    }
    remove_instance_network_link(layout, machine_id)
}

fn write_runtime_file(
    runtime_dir: &Path,
    subnet: &str,
    socket_path: &Path,
    mac: [u8; 6],
) -> Result<(), LibVmError> {
    let runtime = NetworkRuntimeFile {
        version: 1,
        driver: GVISOR_DRIVER.to_string(),
        subnet: subnet.to_string(),
        transport: NetworkTransportFile::Unixgram {
            peer_path: socket_path.display().to_string(),
            mac: format_mac(mac),
        },
    };
    let bytes = serde_json::to_vec_pretty(&runtime).map_err(|err| LibVmError::NetworkRuntime {
        reference: runtime_dir.display().to_string(),
        message: format!("serialize network runtime: {err}"),
    })?;
    fs::write(runtime_dir.join("runtime.json"), bytes)?;
    Ok(())
}

fn write_network_policy_file(
    metadata: &MachineState,
    path: &Path,
) -> Result<Option<NetworkPolicyFile>, LibVmError> {
    let Some(policy) = metadata.metadata.get(NETWORK_POLICY_METADATA_KEY) else {
        return Ok(None);
    };
    fs::write(path, policy)?;
    Ok(Some(network_policy_file(path, policy)))
}

struct NetworkPolicyFile {
    path: std::path::PathBuf,
    audit_enabled: bool,
    audit_path: std::path::PathBuf,
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
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| path.with_file_name("audit.jsonl"));
    NetworkPolicyFile {
        path: path.to_path_buf(),
        audit_enabled,
        audit_path,
    }
}

pub(crate) fn mac_from_machine_id(machine_id: MachineId) -> [u8; 6] {
    let id = machine_id.to_string();
    let bytes = id.as_bytes();
    let mut mac = [0x02, 0, 0, 0, 0, 0];
    for (index, byte) in mac.iter_mut().enumerate().skip(1) {
        let offset = (index - 1) * 2;
        *byte = hex_byte(bytes.get(offset).copied(), bytes.get(offset + 1).copied());
    }
    mac
}

fn hex_byte(high: Option<u8>, low: Option<u8>) -> u8 {
    let high = high.and_then(hex_nibble).unwrap_or(0);
    let low = low.and_then(hex_nibble).unwrap_or(0);
    (high << 4) | low
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
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

fn resolve_network_helper_binary(helper: GvisorHelper) -> String {
    match helper {
        GvisorHelper::Gvproxy => {
            std::env::var(GVPROXY_BINARY_ENV).unwrap_or_else(|_| GVPROXY_BINARY_NAME.to_string())
        }
        GvisorHelper::BentoNetd => std::env::var(BENTO_NETD_BINARY_ENV)
            .unwrap_or_else(|_| resolve_sibling_binary(BENTO_NETD_BINARY_NAME)),
    }
}

fn resolve_sibling_binary(name: &str) -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(name)))
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| name.to_string())
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

fn ensure_instance_network_link(
    layout: &Layout,
    machine_id: MachineId,
    runtime_dir: &Path,
) -> Result<(), LibVmError> {
    let link = layout.instance_network_link(machine_id);
    remove_instance_network_link(layout, machine_id)?;
    symlink(runtime_dir, link)?;
    Ok(())
}

fn remove_instance_network_link(layout: &Layout, machine_id: MachineId) -> Result<(), LibVmError> {
    let link = layout.instance_network_link(machine_id);
    match fs::remove_file(&link) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn remove_runtime_dir(path: &Path) -> Result<(), LibVmError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<(), LibVmError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::{
        configure_network_helper_command, host_uses_user_network_runtime, write_runtime_file,
        NetworkHelperCommandConfig,
    };
    use crate::global_config::GvisorHelper;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn supported_hosts_use_gvisor_runtime() {
        assert!(host_uses_user_network_runtime());
    }

    #[test]
    fn runtime_file_uses_peer_path_and_readable_mac() {
        let dir = tempfile::tempdir().expect("temp dir");
        let peer_path = dir.path().join("gvproxy.sock");

        write_runtime_file(
            dir.path(),
            "10.0.2.0/24",
            &peer_path,
            [0x02, 0x19, 0xe0, 0x00, 0xe2, 0xe6],
        )
        .expect("write runtime file");

        let raw = std::fs::read_to_string(dir.path().join("runtime.json")).expect("read runtime");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("parse runtime");

        assert_eq!(
            value["transport"]["peer_path"],
            peer_path.display().to_string()
        );
        assert_eq!(value["transport"]["mac"], "02:19:e0:00:e2:e6");
        assert!(value["transport"].get("path").is_none());
    }

    #[test]
    fn gvproxy_command_disables_default_ssh_forward() {
        let mut command = Command::new("gvproxy");
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                helper: GvisorHelper::Gvproxy,
                socket_path: Path::new("/tmp/bento-net/gvproxy.sock"),
                subnet: "192.168.105.0/24",
                log_path: Path::new("/tmp/bento-net/gvproxy.log"),
                pid_path: Path::new("/tmp/bento-net/gvproxy.pid"),
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
    fn bento_netd_command_adds_policy_metadata() {
        let mut command = Command::new("bento-netd");
        let machine_id = bento_core::MachineId::new();
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                helper: GvisorHelper::BentoNetd,
                socket_path: Path::new("/tmp/bento-net/gvproxy.sock"),
                subnet: "192.168.105.0/24",
                log_path: Path::new("/tmp/bento-net/gvproxy.log"),
                pid_path: Path::new("/tmp/bento-net/gvproxy.pid"),
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
        assert!(!args.iter().any(|arg| arg == "--policy-mode"));
        assert!(args.windows(2).any(
            |window| window[0] == "--policy-file" && window[1] == "/tmp/bento-net/policy.json"
        ));
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--audit-log" && window[1] == "/tmp/bento-net/audit.jsonl"));
    }
}
