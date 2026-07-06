use crate::machine::Memory;
use crate::network::{MachineNetworkBuilder, MachineNetworkConfig};

use bento_policy::NetworkPolicy;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NetworkPolicyUpdate {
    Set(NetworkPolicy),
    Clear,
}

/// Partial settings update for a stopped machine.
///
/// Every field is optional. Use `is_empty` to reject no-op updates before
/// sending the request to a runtime.
///
/// ```rust
/// use libvm::{MachineUpdate, Memory};
///
/// let update = MachineUpdate::new()
///     .cpus(4)
///     .memory(Memory::gibibytes(8));
///
/// assert!(!update.is_empty());
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct MachineUpdate {
    /// New machine name.
    pub name: Option<String>,
    /// New CPU count.
    pub cpus: Option<u8>,
    /// New memory size.
    pub memory: Option<Memory>,
    /// New desired root disk size in bytes.
    pub root_disk_size: Option<u64>,
    /// New nested virtualization setting.
    pub nested_virtualization: Option<bool>,
    /// New Rosetta setting.
    pub rosetta: Option<bool>,
    /// New durable network config.
    pub network: Option<MachineNetworkConfig>,
    pub(crate) network_error: Option<String>,
    /// Policy-only update for the current durable network config.
    pub network_policy: Option<NetworkPolicyUpdate>,
}

impl MachineUpdate {
    /// Creates an empty update request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the machine name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the CPU count.
    pub fn cpus(mut self, cpus: u8) -> Self {
        self.cpus = Some(cpus);
        self
    }

    /// Sets the machine memory.
    pub fn memory(mut self, memory: Memory) -> Self {
        self.memory = Some(memory);
        self
    }

    /// Sets the desired root disk size in bytes.
    pub fn root_disk_size(mut self, root_disk_size: u64) -> Self {
        self.root_disk_size = Some(root_disk_size);
        self
    }

    /// Sets whether nested virtualization is enabled.
    pub fn nested_virtualization(mut self, nested_virtualization: bool) -> Self {
        self.nested_virtualization = Some(nested_virtualization);
        self
    }

    /// Sets whether Rosetta support is enabled.
    pub fn rosetta(mut self, rosetta: bool) -> Self {
        self.rosetta = Some(rosetta);
        self
    }

    /// Configures the durable machine network attachment.
    pub fn network(
        mut self,
        configure: impl FnOnce(MachineNetworkBuilder) -> MachineNetworkBuilder,
    ) -> Self {
        match configure(MachineNetworkBuilder::new()).build() {
            Ok(network) => self.network = Some(network),
            Err(reason) => self.network_error = Some(reason),
        }
        self
    }

    /// Replaces the persisted private-network policy without changing the network attachment.
    pub fn set_network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.network_policy = Some(NetworkPolicyUpdate::Set(policy));
        self
    }

    /// Removes the persisted private-network policy without changing the network attachment.
    pub fn clear_network_policy(mut self) -> Self {
        self.network_policy = Some(NetworkPolicyUpdate::Clear);
        self
    }

    /// Returns true when no settings are present.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.cpus.is_none()
            && self.memory.is_none()
            && self.root_disk_size.is_none()
            && self.nested_virtualization.is_none()
            && self.rosetta.is_none()
            && self.network.is_none()
            && self.network_error.is_none()
            && self.network_policy.is_none()
    }
}
