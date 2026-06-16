use crate::network::MachineNetworkConfig;

/// Partial settings update for a stopped machine.
///
/// Every field is optional. Use `is_empty` to reject no-op updates before
/// sending the request to a runtime.
#[derive(Debug, Clone, Default)]
pub struct MachineUpdate {
    /// New machine name.
    pub name: Option<String>,
    /// New CPU count.
    pub cpus: Option<u8>,
    /// New memory size in MiB.
    pub memory_mib: Option<u32>,
    /// New desired root disk size in bytes.
    pub root_disk_size: Option<u64>,
    /// New nested virtualization setting.
    pub nested_virtualization: Option<bool>,
    /// New Rosetta setting.
    pub rosetta: Option<bool>,
    /// New durable network config.
    pub network: Option<MachineNetworkConfig>,
}

impl MachineUpdate {
    /// Returns true when no settings are present.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.cpus.is_none()
            && self.memory_mib.is_none()
            && self.root_disk_size.is_none()
            && self.nested_virtualization.is_none()
            && self.rosetta.is_none()
            && self.network.is_none()
    }
}
