use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use bento_utils::format_mac;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::certificate_authority;
use crate::global_config::NetdConfig;
use crate::models::{MachineConfig, NetworkAttachment, NetworkInstance};
use crate::paths::{resolve_default_config_dir, LocalPaths};
use crate::store::{Database, Sqlite};
use crate::{LibVmError, MachineId, NetworkPolicyRef};

use super::core::{NetworkDriver, NetworkDriverContext, NetworkRequest, PreparedNetwork};
use super::{
    ensure_instance_network_link, mac_from_machine_id, network_attachment_from_instance, now_unix,
    remove_file_if_exists, remove_runtime_dir, serialize_json, DRIVER_NETD,
};

const NETD_BINARY_ENV: &str = "NETD_BIN";
const NETD_BINARY_NAME: &str = "netd";
const NETD_DISABLE_SSH_PORT: &str = "-1";
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
        validate_policy_ref(reference, self.id(), request.policy_ref)
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
    let paths = ctx.paths;
    let db = ctx.db;
    let metadata = ctx.metadata;
    let config = ctx.config.netd.clone();
    if !host_uses_user_network_runtime() {
        return Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: "userspace networking is not supported on this host".to_string(),
        });
    }

    if let Some(definition_name) = request.definition_name {
        if let Some(instance) = db
            .get_network_instance_by_definition(definition_name)
            .await?
        {
            if instance_is_alive(&instance) {
                return attach_existing_runtime(paths, db, metadata, &instance).await;
            }
            db.remove_network_instance(&instance.id).await?;
            remove_runtime_dir(Path::new(&instance.runtime_dir))?;
        }
    }

    let network_id = MachineId::new().to_string();
    let network_paths = paths.network(&network_id);
    let runtime_dir = network_paths.dir().to_path_buf();
    fs::create_dir_all(&runtime_dir)?;
    ensure_instance_network_link(paths, metadata.id, &runtime_dir)?;

    let socket_path = network_paths.socket_path();
    let log_path = network_paths.log_path();
    let pid_path = network_paths.pid_path();
    let pcap_path = config.pcap.then(|| network_paths.pcap_path());
    let policy_path = resolve_network_policy_path(metadata, request.policy_ref)?;
    let secret_store_path = paths.secret_store_path();
    let (tls_ca_cert_path, tls_ca_key_path) =
        resolve_certificate_authority_paths(paths, &config, &metadata.name)?;
    remove_file_if_exists(&socket_path)?;
    remove_file_if_exists(&pid_path)?;

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
            secret_store_path: secret_store_path.as_path(),
            tls_ca_cert_path: Some(tls_ca_cert_path.as_path()),
            tls_ca_key_path: Some(tls_ca_key_path.as_path()),
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
        let _ = super::remove_instance_network_link(paths, metadata.id);
        return Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!("{err} (preserved runtime dir: {})", runtime_dir.display()),
        });
    }

    let mac = mac_from_machine_id(metadata.id);
    let network = super::RuntimeNetwork::UnixDatagram {
        path: socket_path.clone(),
        mac: format_mac(mac),
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
    db.upsert_network_instance(&NetworkInstance {
        id: network_id.clone(),
        driver: DRIVER_NETD.to_string(),
        definition_name: request.definition_name.map(str::to_string),
        runtime_dir: runtime_dir.display().to_string(),
        attachment_json: serialize_json(&network, "network attachment")?,
        driver_state_json: serialize_json(&driver_state, "netd driver state")?,
        state: RUNNING_STATE.to_string(),
        created_at: now,
        modified_at: now,
    })
    .await?;
    db.upsert_network_attachment(&NetworkAttachment {
        machine_id: metadata.id,
        network_instance_id: network_id,
        guest_mac: format_mac(mac),
        created_at: now,
        modified_at: now,
    })
    .await?;
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

async fn attach_existing_runtime(
    paths: &LocalPaths,
    db: &Sqlite,
    metadata: &MachineConfig,
    instance: &NetworkInstance,
) -> Result<PreparedNetwork, LibVmError> {
    ensure_instance_network_link(paths, metadata.id, Path::new(&instance.runtime_dir))?;
    let now = now_unix();
    let mac = format_mac(mac_from_machine_id(metadata.id));
    let attachment = network_attachment_from_instance(instance, mac.clone())?;
    db.upsert_network_attachment(&NetworkAttachment {
        machine_id: metadata.id,
        network_instance_id: instance.id.clone(),
        guest_mac: mac.clone(),
        created_at: now,
        modified_at: now,
    })
    .await?;
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
    secret_store_path: &'a Path,
    tls_ca_cert_path: Option<&'a Path>,
    tls_ca_key_path: Option<&'a Path>,
}

fn configure_network_helper_command(
    command: &mut Command,
    config: &NetworkHelperCommandConfig<'_>,
) {
    command
        .arg("--listen-vfkit")
        .arg(format!("unixgram://{}", config.socket_path.display()))
        .arg("--ssh-port")
        .arg(NETD_DISABLE_SSH_PORT)
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
    command
        .arg("--secret-store-file")
        .arg(config.secret_store_path);
    if let Some(path) = config.tls_ca_cert_path {
        command.arg("--tls-ca-cert").arg(path);
    }
    if let Some(path) = config.tls_ca_key_path {
        command.arg("--tls-ca-key").arg(path);
    }
}

fn validate_policy_ref(
    reference: &str,
    driver: &str,
    policy_ref: Option<&NetworkPolicyRef>,
) -> Result<(), LibVmError> {
    let Some(policy_ref) = policy_ref else {
        return Ok(());
    };
    if driver != DRIVER_NETD {
        return Err(LibVmError::NetworkRuntime {
            reference: reference.to_string(),
            message: format!("resolved driver {driver:?} does not support network policy_ref"),
        });
    }
    policy_ref
        .resolve(resolve_config_dir_for_policy())
        .map(|_| ())
        .map_err(|message| LibVmError::NetworkRuntime {
            reference: reference.to_string(),
            message,
        })
}

fn resolve_network_policy_path(
    metadata: &MachineConfig,
    policy_ref: Option<&NetworkPolicyRef>,
) -> Result<Option<PathBuf>, LibVmError> {
    policy_ref
        .map(|policy_ref| policy_ref.resolve(resolve_config_dir_for_policy()))
        .transpose()
        .map_err(|message| LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message,
        })
}

fn resolve_certificate_authority_paths(
    paths: &LocalPaths,
    config: &NetdConfig,
    reference: &str,
) -> Result<(PathBuf, PathBuf), LibVmError> {
    match (&config.tls_ca_cert, &config.tls_ca_key) {
        (Some(certificate_path), Some(private_key_path)) => {
            Ok((certificate_path.clone(), private_key_path.clone()))
        }
        (None, None) => {
            let authority =
                certificate_authority::ensure_certificate_authority_in(paths).map_err(|err| {
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

fn resolve_config_dir_for_policy() -> Option<PathBuf> {
    resolve_default_config_dir().ok()
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
        configure_network_helper_command, resolve_certificate_authority_paths,
        NetworkHelperCommandConfig,
    };
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::global_config::NetdConfig;
    use crate::paths::LocalPaths;
    use crate::MachineId;

    #[test]
    fn netd_command_disables_default_ssh_forward() {
        let mut command = Command::new("netd");
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                socket_path: Path::new("/tmp/bento-net/netd.sock"),
                subnet: "192.168.105.0/24",
                log_path: Path::new("/tmp/bento-net/netd.log"),
                pid_path: Path::new("/tmp/bento-net/netd.pid"),
                pcap_path: None,
                machine_id: MachineId::new(),
                network_id: "net123",
                policy_path: None,
                secret_store_path: Path::new("/tmp/bento/secrets.json"),
                tls_ca_cert_path: None,
                tls_ca_key_path: None,
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
        let mut command = Command::new("netd");
        let machine_id = MachineId::new();
        configure_network_helper_command(
            &mut command,
            &NetworkHelperCommandConfig {
                socket_path: Path::new("/tmp/bento-net/netd.sock"),
                subnet: "192.168.105.0/24",
                log_path: Path::new("/tmp/bento-net/netd.log"),
                pid_path: Path::new("/tmp/bento-net/netd.pid"),
                pcap_path: None,
                machine_id,
                network_id: "net123",
                policy_path: Some(Path::new("/tmp/bento-net/policy.hcl")),
                secret_store_path: Path::new("/tmp/bento/secrets.json"),
                tls_ca_cert_path: Some(Path::new("/tmp/bento-net/ca.pem")),
                tls_ca_key_path: Some(Path::new("/tmp/bento-net/ca-key.pem")),
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
        assert!(
            args.windows(2)
                .any(|window| window[0] == "--policy-file"
                    && window[1] == "/tmp/bento-net/policy.hcl")
        );
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--secret-store-file"
                && window[1] == "/tmp/bento/secrets.json"));
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--tls-ca-cert" && window[1] == "/tmp/bento-net/ca.pem"));
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--tls-ca-key" && window[1] == "/tmp/bento-net/ca-key.pem"));
    }

    #[test]
    fn certificate_authority_paths_use_config_overrides() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let config = NetdConfig {
            tls_ca_cert: Some(PathBuf::from("/tmp/custom-ca.pem")),
            tls_ca_key: Some(PathBuf::from("/tmp/custom-ca-key.pem")),
            ..NetdConfig::default()
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
        let paths = LocalPaths::new(temp.path().join("bento"));

        let (certificate_path, private_key_path) =
            resolve_certificate_authority_paths(&paths, &NetdConfig::default(), "test-machine")
                .expect("resolve generated CA paths");

        assert_eq!(certificate_path, paths.keys_dir().join("ca.pem"));
        assert_eq!(private_key_path, paths.keys_dir().join("ca-key.pem"));
        assert!(certificate_path.is_file());
        assert!(private_key_path.is_file());
    }

    #[test]
    fn certificate_authority_paths_reject_partial_config() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let config = NetdConfig {
            tls_ca_cert: Some(PathBuf::from("/tmp/custom-ca.pem")),
            ..NetdConfig::default()
        };

        let err = resolve_certificate_authority_paths(&paths, &config, "test-machine")
            .expect_err("reject partial CA config");

        assert!(err.to_string().contains(
            "certificate authority certificate and private key must be configured together"
        ));
    }
}
