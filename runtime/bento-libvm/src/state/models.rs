use std::collections::BTreeMap;
use std::path::Path;

use bento_core::MachineId;

use crate::network::config::RequestedNetwork;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachineState {
    pub id: MachineId,
    pub name: String,
    pub instance_dir: String,
    pub created_at: i64,
    pub modified_at: i64,
    pub image_ref: String,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub network: RequestedNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkInstanceState {
    pub id: String,
    pub driver: String,
    pub definition_name: Option<String>,
    pub runtime_dir: String,
    pub attachment_json: String,
    pub driver_state_json: String,
    pub state: String,
    pub created_at: i64,
    pub modified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkAttachmentState {
    pub machine_id: MachineId,
    pub network_instance_id: String,
    pub guest_mac: String,
    pub created_at: i64,
    pub modified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkDefinitionState {
    pub name: String,
    pub mode: String,
    pub driver_preference: String,
    pub created_at: i64,
    pub modified_at: i64,
}

#[cfg(test)]
pub(crate) fn machine_state_from_path(
    id: MachineId,
    name: String,
    instance_dir: &Path,
) -> MachineState {
    machine_state_from_path_with_details(
        id,
        name,
        instance_dir,
        String::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        RequestedNetwork::default(),
    )
}

pub(crate) fn machine_state_from_path_with_details(
    id: MachineId,
    name: String,
    instance_dir: &Path,
    image_ref: String,
    labels: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    network: RequestedNetwork,
) -> MachineState {
    let now = now_unix();
    MachineState {
        id,
        name,
        instance_dir: instance_dir.display().to_string(),
        created_at: now,
        modified_at: now,
        image_ref,
        labels,
        metadata,
        network,
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
