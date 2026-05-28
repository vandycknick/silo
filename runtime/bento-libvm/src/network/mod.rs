use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod config;
mod core;
mod netd_driver;
mod vznat_driver;

use bento_core::{MachineId, Network};
use serde::Serialize;

use crate::global_config::GlobalConfig;
use crate::network::config::{
    NamedNetworkMode, NetworkDefinitionSpec, NetworkDriverKind, NetworkDriverPreference,
    RequestedNetwork,
};
use crate::state::{MachineState, NetworkInstanceState, StateStore};
use crate::{Layout, LibVmError};

use self::core::{
    NetworkDriver, NetworkDriverContext, NetworkRequest, NetworkScope, PreparedNetwork,
};
use self::netd_driver::NetdDriver;
use self::vznat_driver::VzNatDriver;

const DRIVER_NETD: &str = "netd";
const DRIVER_VZNAT: &str = "vznat";

#[derive(Debug, Serialize)]
struct NetworkRuntimeFile {
    version: u32,
    attachment: Network,
}

pub(crate) async fn prepare_network_runtime(
    layout: &Layout,
    state: &StateStore,
    metadata: &MachineState,
) -> Result<Network, LibVmError> {
    reconcile_network_runtime(layout, state, metadata, false)?;

    match metadata.network.clone() {
        RequestedNetwork::None => {
            remove_attached_network(layout, state, metadata.id)?;
            Ok(Network::None)
        }
        RequestedNetwork::Private { policy } => {
            let global_config = load_global_config(&metadata.name)?;
            let request = NetworkRequest {
                scope: NetworkScope::Private,
                definition_name: None,
                policy: policy.as_ref(),
            };
            prepare_with_driver(
                selected_private_driver(global_config.networking.private_driver),
                &NetworkDriverContext {
                    layout,
                    state,
                    metadata,
                    config: &global_config.networking,
                },
                &request,
            )
            .await
            .map(|prepared| prepared.attachment)
        }
        RequestedNetwork::Named { name, policy } => {
            if policy.is_some() {
                return Err(LibVmError::NetworkRuntime {
                    reference: metadata.name.clone(),
                    message: format!(
                        "named network {:?} does not support per-machine policy yet",
                        name
                    ),
                });
            }
            let definition =
                state
                    .get_network_definition(&name)?
                    .ok_or_else(|| LibVmError::NetworkRuntime {
                        reference: metadata.name.clone(),
                        message: format!("named network {:?} is not defined", name),
                    })?;
            resolve_named_network(layout, state, metadata, &definition).await
        }
    }
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

    if monitor_running && network_instance_is_alive(&instance) {
        ensure_instance_network_link(layout, metadata.id, Path::new(&instance.runtime_dir))?;
        return Ok(());
    }

    state.remove_network_attachment(metadata.id)?;
    remove_instance_network_link(layout, metadata.id)?;
    if state.count_network_attachments(&instance.id)? == 0 {
        terminate_network_instance(&instance)?;
        state.remove_network_instance(&instance.id)?;
        remove_runtime_dir(Path::new(&instance.runtime_dir))?;
    }
    Ok(())
}

async fn resolve_named_network(
    layout: &Layout,
    state: &StateStore,
    metadata: &MachineState,
    definition: &NetworkDefinitionSpec,
) -> Result<Network, LibVmError> {
    let global_config = load_global_config(&metadata.name)?;
    match definition.mode {
        NamedNetworkMode::Nat => {
            let driver = match definition.driver_preference {
                NetworkDriverPreference::Auto | NetworkDriverPreference::Netd => {
                    NetworkDriverKind::Netd
                }
                NetworkDriverPreference::VzNat => NetworkDriverKind::VzNat,
            };
            let request = NetworkRequest {
                scope: NetworkScope::Named,
                definition_name: Some(definition.name.as_str()),
                policy: None,
            };
            prepare_with_driver(
                selected_private_driver(driver),
                &NetworkDriverContext {
                    layout,
                    state,
                    metadata,
                    config: &global_config.networking,
                },
                &request,
            )
            .await
            .map(|prepared| prepared.attachment)
        }
        NamedNetworkMode::Bridge => Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!(
                "named network {:?} uses bridge mode, which is not implemented yet",
                definition.name
            ),
        }),
        NamedNetworkMode::Isolated => Err(LibVmError::NetworkRuntime {
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

pub(super) fn remove_attached_network(
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
    remove_instance_network_link(layout, machine_id)?;
    if let Some(instance) = instance {
        if state.count_network_attachments(&instance.id)? == 0 {
            terminate_network_instance(&instance)?;
            state.remove_network_instance(&instance.id)?;
            remove_runtime_dir(Path::new(&instance.runtime_dir))?;
        }
    }
    Ok(())
}

pub(super) fn write_runtime_file(
    runtime_dir: &Path,
    attachment: &Network,
) -> Result<(), LibVmError> {
    let runtime = NetworkRuntimeFile {
        version: 2,
        attachment: attachment.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&runtime).map_err(|err| LibVmError::NetworkRuntime {
        reference: runtime_dir.display().to_string(),
        message: format!("serialize network runtime: {err}"),
    })?;
    fs::write(runtime_dir.join("runtime.json"), bytes)?;
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

fn network_instance_is_alive(instance: &NetworkInstanceState) -> bool {
    match instance.driver.as_str() {
        DRIVER_NETD => netd_driver::instance_is_alive(instance),
        _ => false,
    }
}

pub(super) fn network_attachment_from_instance(
    instance: &NetworkInstanceState,
    mac: String,
) -> Result<Network, LibVmError> {
    let mut attachment: Network =
        serde_json::from_str(&instance.attachment_json).map_err(|err| {
            LibVmError::NetworkRuntime {
                reference: instance.id.clone(),
                message: format!("parse network attachment: {err}"),
            }
        })?;
    if let Network::UnixDatagram { mac: existing, .. }
    | Network::UnixStream { mac: existing, .. }
    | Network::Tap { mac: existing, .. } = &mut attachment
    {
        *existing = mac;
    }
    Ok(attachment)
}

fn terminate_network_instance(instance: &NetworkInstanceState) -> Result<(), LibVmError> {
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
    layout: &Layout,
    machine_id: MachineId,
    runtime_dir: &Path,
) -> Result<(), LibVmError> {
    let link = layout.instance_network_link(machine_id);
    remove_instance_network_link(layout, machine_id)?;
    symlink(runtime_dir, link)?;
    Ok(())
}

pub(super) fn remove_instance_network_link(
    layout: &Layout,
    machine_id: MachineId,
) -> Result<(), LibVmError> {
    let link = layout.instance_network_link(machine_id);
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

#[cfg(test)]
mod tests {
    use super::write_runtime_file;

    #[test]
    fn runtime_file_serializes_resolved_attachment() {
        let dir = tempfile::tempdir().expect("temp dir");
        let attachment = bento_core::Network::UnixDatagram {
            path: dir.path().join("netd.sock"),
            mac: "02:19:e0:00:e2:e6".to_string(),
        };

        write_runtime_file(dir.path(), &attachment).expect("write runtime file");

        let raw = std::fs::read_to_string(dir.path().join("runtime.json")).expect("read runtime");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("parse runtime");

        assert_eq!(value["attachment"]["kind"], "unix_datagram");
        assert_eq!(value["attachment"]["mac"], "02:19:e0:00:e2:e6");
    }
}
