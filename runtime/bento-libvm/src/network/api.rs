use serde::{Deserialize, Serialize};

use crate::store::models;
use crate::NetworkPolicyRef;

/// Durable network configuration for a machine.
///
/// This is public caller input and inspect output: it says what network a
/// machine should connect to when it starts. It is not a running attachment and
/// it is not the vmmon launch argument. libvm maps this value to private
/// `store::models::MachineNetworkConfig` before writing the machine store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MachineNetworkConfig {
    /// Attach the machine to its private network.
    Private {
        /// Optional policy reference for the private network.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_ref: Option<NetworkPolicyRef>,
    },
    /// Start the machine with no network attachment.
    None,
    /// Attach the machine to a named network definition.
    Named {
        /// Named network definition to attach to.
        name: String,
    },
}

impl Default for MachineNetworkConfig {
    fn default() -> Self {
        Self::Private { policy_ref: None }
    }
}

impl MachineNetworkConfig {
    /// Returns the display name for the machine network config.
    pub fn name(&self) -> String {
        match self {
            Self::Private { .. } => "private".to_string(),
            Self::None => "none".to_string(),
            Self::Named { name } => name.clone(),
        }
    }

    /// Returns the configured private-network policy reference, when present.
    pub fn policy_ref(&self) -> Option<&NetworkPolicyRef> {
        match self {
            Self::Private { policy_ref } => policy_ref.as_ref(),
            Self::None | Self::Named { .. } => None,
        }
    }
}

impl From<MachineNetworkConfig> for models::MachineNetworkConfig {
    fn from(value: MachineNetworkConfig) -> Self {
        match value {
            MachineNetworkConfig::Private { policy_ref } => Self::Private { policy_ref },
            MachineNetworkConfig::None => Self::None,
            MachineNetworkConfig::Named { name } => Self::Named { name },
        }
    }
}

impl From<models::MachineNetworkConfig> for MachineNetworkConfig {
    fn from(value: models::MachineNetworkConfig) -> Self {
        match value {
            models::MachineNetworkConfig::Private { policy_ref } => Self::Private { policy_ref },
            models::MachineNetworkConfig::None => Self::None,
            models::MachineNetworkConfig::Named { name } => Self::Named { name },
        }
    }
}

/// Network driver implementation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDriverKind {
    /// netd-based networking.
    Netd,
    /// Virtualization.framework NAT networking.
    VzNat,
}

/// Connectivity topology for a named network definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTopology {
    /// NAT-backed network.
    Nat,
    /// Bridge-backed network.
    Bridge,
    /// Isolated network.
    Isolated,
}

/// Preferred driver for a named network definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDriverPreference {
    /// Let the runtime choose the best supported driver.
    #[default]
    Auto,
    /// Prefer netd.
    Netd,
    /// Prefer Virtualization.framework NAT.
    VzNat,
}

/// Public configuration for a named network.
///
/// This is the API shape callers pass to `Runtime` when creating or updating a
/// named network. The store persists the same domain data as private
/// `store::models::NetworkDefinition` rows so external callers never depend on
/// libvm's database model module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDefinition {
    /// Unique network name.
    pub name: String,
    /// Network topology.
    pub topology: NetworkTopology,
    /// Preferred network driver.
    pub driver_preference: NetworkDriverPreference,
}

impl NetworkDefinition {
    /// Validates this definition before storing it.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("invalid network name: cannot be empty".to_string());
        }
        if matches!(self.name.as_str(), "private" | "none") {
            return Err(format!("invalid network name: {:?} is reserved", self.name));
        }
        if matches!(self.driver_preference, NetworkDriverPreference::VzNat)
            && !matches!(self.topology, NetworkTopology::Nat)
        {
            return Err("vznat only supports nat networks".to_string());
        }
        Ok(())
    }
}

impl Default for NetworkDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            topology: NetworkTopology::Nat,
            driver_preference: NetworkDriverPreference::default(),
        }
    }
}

impl From<NetworkDefinition> for models::NetworkDefinition {
    fn from(value: NetworkDefinition) -> Self {
        Self {
            name: value.name,
            topology: value.topology.into(),
            driver_preference: value.driver_preference.into(),
            created_at: 0,
            modified_at: 0,
        }
    }
}

impl From<models::NetworkDefinition> for NetworkDefinition {
    fn from(value: models::NetworkDefinition) -> Self {
        Self {
            name: value.name,
            topology: value.topology.into(),
            driver_preference: value.driver_preference.into(),
        }
    }
}

impl From<NetworkTopology> for models::NetworkTopology {
    fn from(value: NetworkTopology) -> Self {
        match value {
            NetworkTopology::Nat => Self::Nat,
            NetworkTopology::Bridge => Self::Bridge,
            NetworkTopology::Isolated => Self::Isolated,
        }
    }
}

impl From<models::NetworkTopology> for NetworkTopology {
    fn from(value: models::NetworkTopology) -> Self {
        match value {
            models::NetworkTopology::Nat => Self::Nat,
            models::NetworkTopology::Bridge => Self::Bridge,
            models::NetworkTopology::Isolated => Self::Isolated,
        }
    }
}

impl From<NetworkDriverPreference> for models::NetworkDriverPreference {
    fn from(value: NetworkDriverPreference) -> Self {
        match value {
            NetworkDriverPreference::Auto => Self::Auto,
            NetworkDriverPreference::Netd => Self::Netd,
            NetworkDriverPreference::VzNat => Self::VzNat,
        }
    }
}

impl From<models::NetworkDriverPreference> for NetworkDriverPreference {
    fn from(value: models::NetworkDriverPreference) -> Self {
        match value {
            models::NetworkDriverPreference::Auto => Self::Auto,
            models::NetworkDriverPreference::Netd => Self::Netd,
            models::NetworkDriverPreference::VzNat => Self::VzNat,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkDefinition, NetworkDriverPreference, NetworkTopology};

    #[test]
    fn vznat_driver_preference_allows_nat_named_networks() {
        let definition = NetworkDefinition {
            name: "devnet".to_string(),
            topology: NetworkTopology::Nat,
            driver_preference: NetworkDriverPreference::VzNat,
        };

        definition
            .validate()
            .expect("vznat should allow nat networks");
    }

    #[test]
    fn vznat_driver_preference_rejects_non_nat_named_networks() {
        let definition = NetworkDefinition {
            name: "devnet".to_string(),
            topology: NetworkTopology::Bridge,
            driver_preference: NetworkDriverPreference::VzNat,
        };

        assert!(definition.validate().is_err());
    }
}
