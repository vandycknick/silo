use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

mod api;
mod core;
mod netd_driver;
mod vznat_driver;

pub use api::{
    NamedNetworkMode, NetworkDefinition, NetworkDriverKind, NetworkDriverPreference,
    RequestedNetwork,
};

use serde::{Deserialize, Serialize};

use crate::global_config::GlobalConfig;
use crate::models::{
    MachineConfig, NamedNetworkMode as ModelNamedNetworkMode,
    NetworkDefinition as ModelNetworkDefinition,
    NetworkDriverPreference as ModelNetworkDriverPreference, NetworkInstance,
    RequestedNetwork as ModelRequestedNetwork,
};
use crate::paths::LocalPaths;
use crate::store::{Database, Sqlite};
use crate::{LibVmError, MachineId};

use self::core::{
    NetworkDriver, NetworkDriverContext, NetworkRequest, NetworkScope, PreparedNetwork,
};
use self::netd_driver::NetdDriver;
use self::vznat_driver::VzNatDriver;

const DRIVER_NETD: &str = "netd";
const DRIVER_VZNAT: &str = "vznat";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum RuntimeNetwork {
    None,
    VzNat {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac: Option<String>,
    },
    UnixDatagram {
        path: std::path::PathBuf,
        mac: String,
    },
    UnixStream {
        path: std::path::PathBuf,
        mac: String,
    },
    Tap {
        name: String,
        mac: String,
    },
}

impl RuntimeNetwork {
    pub(crate) fn to_vmmon_arg(&self) -> String {
        match self {
            Self::None => "none".to_string(),
            Self::VzNat { mac: None } => "vznat".to_string(),
            Self::VzNat { mac: Some(mac) } => format!("vznat,mac={mac}"),
            Self::UnixDatagram { path, mac } => format!("unixdg,{},mac={mac}", path.display()),
            Self::UnixStream { path, mac } => format!("unixstream,{},mac={mac}", path.display()),
            Self::Tap { name, mac } => format!("tap,{name},mac={mac}"),
        }
    }
}

pub(crate) async fn prepare_network_runtime(
    paths: &LocalPaths,
    db: &Sqlite,
    metadata: &MachineConfig,
) -> Result<RuntimeNetwork, LibVmError> {
    reconcile_network_runtime(paths, db, metadata, false).await?;

    match metadata.network.clone() {
        ModelRequestedNetwork::None => {
            remove_attached_network(paths, db, metadata.id).await?;
            Ok(RuntimeNetwork::None)
        }
        ModelRequestedNetwork::Private { policy_ref } => {
            let global_config = load_global_config(&metadata.name)?;
            let request = NetworkRequest {
                scope: NetworkScope::Private,
                definition_name: None,
                policy_ref: policy_ref.as_ref(),
            };
            prepare_with_driver(
                selected_private_driver(global_config.networking.private_driver),
                &NetworkDriverContext {
                    paths,
                    db,
                    metadata,
                    config: &global_config.networking,
                },
                &request,
            )
            .await
            .map(|prepared| prepared.attachment)
        }
        ModelRequestedNetwork::Named { name, policy_ref } => {
            if policy_ref.is_some() {
                return Err(LibVmError::NetworkRuntime {
                    reference: metadata.name.clone(),
                    message: format!(
                        "named network {:?} does not support per-machine policy_ref yet",
                        name
                    ),
                });
            }
            let definition = db.get_network_definition(&name).await?.ok_or_else(|| {
                LibVmError::NetworkRuntime {
                    reference: metadata.name.clone(),
                    message: format!("named network {:?} is not defined", name),
                }
            })?;
            resolve_named_network(paths, db, metadata, &definition).await
        }
    }
}

pub(crate) async fn reconcile_network_runtime(
    paths: &LocalPaths,
    db: &Sqlite,
    metadata: &MachineConfig,
    monitor_running: bool,
) -> Result<(), LibVmError> {
    let Some(attachment) = db.get_network_attachment(metadata.id).await? else {
        return Ok(());
    };
    let Some(instance) = db
        .get_network_instance(&attachment.network_instance_id)
        .await?
    else {
        remove_instance_network_link(paths, metadata.id)?;
        db.remove_network_attachment(metadata.id).await?;
        return Ok(());
    };

    if monitor_running && network_instance_is_alive(&instance) {
        ensure_instance_network_link(paths, metadata.id, Path::new(&instance.runtime_dir))?;
        return Ok(());
    }

    db.remove_network_attachment(metadata.id).await?;
    remove_instance_network_link(paths, metadata.id)?;
    if db.count_network_attachments(&instance.id).await? == 0 {
        terminate_network_instance(&instance)?;
        db.remove_network_instance(&instance.id).await?;
        remove_runtime_dir(Path::new(&instance.runtime_dir))?;
    }
    Ok(())
}

async fn resolve_named_network(
    paths: &LocalPaths,
    db: &Sqlite,
    metadata: &MachineConfig,
    definition: &ModelNetworkDefinition,
) -> Result<RuntimeNetwork, LibVmError> {
    let global_config = load_global_config(&metadata.name)?;
    match definition.mode {
        ModelNamedNetworkMode::Nat => {
            let driver = match definition.driver_preference {
                ModelNetworkDriverPreference::Auto | ModelNetworkDriverPreference::Netd => {
                    NetworkDriverKind::Netd
                }
                ModelNetworkDriverPreference::VzNat => NetworkDriverKind::VzNat,
            };
            let request = NetworkRequest {
                scope: NetworkScope::Named,
                definition_name: Some(definition.name.as_str()),
                policy_ref: None,
            };
            prepare_with_driver(
                selected_private_driver(driver),
                &NetworkDriverContext {
                    paths,
                    db,
                    metadata,
                    config: &global_config.networking,
                },
                &request,
            )
            .await
            .map(|prepared| prepared.attachment)
        }
        ModelNamedNetworkMode::Bridge => Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!(
                "named network {:?} uses bridge mode, which is not implemented yet",
                definition.name
            ),
        }),
        ModelNamedNetworkMode::Isolated => Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!(
                "named network {:?} uses isolated mode, which is not implemented yet",
                definition.name
            ),
        }),
    }
}

fn selected_private_driver(kind: NetworkDriverKind) -> impl NetworkDriver {
    match kind {
        NetworkDriverKind::Netd => SelectedNetworkDriver::Netd(NetdDriver),
        NetworkDriverKind::VzNat => SelectedNetworkDriver::VzNat(VzNatDriver),
    }
}

enum SelectedNetworkDriver {
    Netd(NetdDriver),
    VzNat(VzNatDriver),
}

impl NetworkDriver for SelectedNetworkDriver {
    fn id(&self) -> &'static str {
        match self {
            Self::Netd(driver) => driver.id(),
            Self::VzNat(driver) => driver.id(),
        }
    }

    fn supports(&self, reference: &str, request: &NetworkRequest<'_>) -> Result<(), LibVmError> {
        match self {
            Self::Netd(driver) => driver.supports(reference, request),
            Self::VzNat(driver) => driver.supports(reference, request),
        }
    }

    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        request: &NetworkRequest<'_>,
    ) -> Result<PreparedNetwork, LibVmError> {
        match self {
            Self::Netd(driver) => driver.prepare(ctx, request).await,
            Self::VzNat(driver) => driver.prepare(ctx, request).await,
        }
    }
}

async fn prepare_with_driver(
    driver: impl NetworkDriver,
    ctx: &NetworkDriverContext<'_>,
    request: &NetworkRequest<'_>,
) -> Result<PreparedNetwork, LibVmError> {
    driver.supports(&ctx.metadata.name, request)?;
    driver.prepare(ctx, request).await
}

pub(super) async fn remove_attached_network(
    paths: &LocalPaths,
    db: &Sqlite,
    machine_id: MachineId,
) -> Result<(), LibVmError> {
    let Some(attachment) = db.get_network_attachment(machine_id).await? else {
        remove_instance_network_link(paths, machine_id)?;
        return Ok(());
    };
    let instance = db
        .get_network_instance(&attachment.network_instance_id)
        .await?;
    db.remove_network_attachment(machine_id).await?;
    remove_instance_network_link(paths, machine_id)?;
    if let Some(instance) = instance {
        if db.count_network_attachments(&instance.id).await? == 0 {
            terminate_network_instance(&instance)?;
            db.remove_network_instance(&instance.id).await?;
            remove_runtime_dir(Path::new(&instance.runtime_dir))?;
        }
    }
    Ok(())
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

fn network_instance_is_alive(instance: &NetworkInstance) -> bool {
    match instance.driver.as_str() {
        DRIVER_NETD => netd_driver::instance_is_alive(instance),
        _ => false,
    }
}

pub(super) fn network_attachment_from_instance(
    instance: &NetworkInstance,
    mac: String,
) -> Result<RuntimeNetwork, LibVmError> {
    let mut attachment: RuntimeNetwork =
        serde_json::from_str(&instance.attachment_json).map_err(|err| {
            LibVmError::NetworkRuntime {
                reference: instance.id.clone(),
                message: format!("parse network attachment: {err}"),
            }
        })?;
    if let RuntimeNetwork::UnixDatagram { mac: existing, .. }
    | RuntimeNetwork::UnixStream { mac: existing, .. }
    | RuntimeNetwork::Tap { mac: existing, .. } = &mut attachment
    {
        *existing = mac;
    }
    Ok(attachment)
}

fn terminate_network_instance(instance: &NetworkInstance) -> Result<(), LibVmError> {
    if instance.driver == DRIVER_NETD {
        netd_driver::terminate_instance(instance)?;
    }
    Ok(())
}

pub(super) fn serialize_json<T: Serialize>(value: &T, label: &str) -> Result<String, LibVmError> {
    serde_json::to_string(value).map_err(|err| LibVmError::NetworkRuntime {
        reference: label.to_string(),
        message: format!("serialize {label}: {err}"),
    })
}

pub(super) fn ensure_instance_network_link(
    paths: &LocalPaths,
    machine_id: MachineId,
    runtime_dir: &Path,
) -> Result<(), LibVmError> {
    let link = paths.machine(machine_id).network_link();
    remove_instance_network_link(paths, machine_id)?;
    symlink(runtime_dir, link)?;
    Ok(())
}

pub(super) fn remove_instance_network_link(
    paths: &LocalPaths,
    machine_id: MachineId,
) -> Result<(), LibVmError> {
    let link = paths.machine(machine_id).network_link();
    let metadata = match fs::symlink_metadata(&link) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    if metadata.file_type().is_dir() {
        fs::remove_dir_all(&link)?;
    } else {
        fs::remove_file(&link)?;
    }
    Ok(())
}

pub(super) fn remove_runtime_dir(path: &Path) -> Result<(), LibVmError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn remove_file_if_exists(path: &Path) -> Result<(), LibVmError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn load_global_config(reference: &str) -> Result<GlobalConfig, LibVmError> {
    GlobalConfig::load().map_err(|err| LibVmError::NetworkRuntime {
        reference: reference.to_string(),
        message: format!("load networking defaults: {err}"),
    })
}

pub(super) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
