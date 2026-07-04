use serde::{Deserialize, Serialize};

use bento_policy::NetworkPolicy;

use crate::store::models;
use crate::utils::{validate_identifier, IdentifierPolicy};
use crate::NetworkPolicyRef;

const RESERVED_NETWORK_NAMES: &[&str] = &["private", "none"];

/// Durable network configuration for a machine.
///
/// This is public caller input and inspect output: it says what network a
/// machine should connect to when it starts. It is not a running attachment and
/// it is not the vmmon launch argument. libvm maps this value to private
/// `store::models::MachineNetworkConfig` before writing the machine store.
///
/// ```rust
/// use libvm::MachineNetworkConfig;
///
/// let private = MachineNetworkConfig::private();
/// let named = MachineNetworkConfig::named("devnet");
///
/// assert_eq!(private.name(), "private");
/// assert_eq!(named.name(), "devnet");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum MachineNetworkConfig {
    /// Attach the machine to its private network.
    Private {
        /// Resolved canonical policy for the private network.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<NetworkPolicy>,
        /// Optional policy reference for the private network.
        ///
        /// This is a temporary compatibility field while CLI policy source
        /// resolution moves out of libvm.
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
        Self::Private {
            policy: None,
            policy_ref: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateNetworkPolicy {
    Policy(NetworkPolicy),
    Ref(NetworkPolicyRef),
}

impl From<NetworkPolicy> for PrivateNetworkPolicy {
    fn from(value: NetworkPolicy) -> Self {
        Self::Policy(value)
    }
}

impl From<NetworkPolicyRef> for PrivateNetworkPolicy {
    fn from(value: NetworkPolicyRef) -> Self {
        Self::Ref(value)
    }
}

impl MachineNetworkConfig {
    /// Creates the default private network config.
    pub fn private() -> Self {
        Self::Private {
            policy: None,
            policy_ref: None,
        }
    }

    /// Creates a private network config with a network policy.
    pub fn private_with_policy(policy: impl Into<PrivateNetworkPolicy>) -> Self {
        match policy.into() {
            PrivateNetworkPolicy::Policy(policy) => Self::Private {
                policy: Some(policy),
                policy_ref: None,
            },
            PrivateNetworkPolicy::Ref(policy_ref) => Self::Private {
                policy: None,
                policy_ref: Some(policy_ref),
            },
        }
    }

    /// Creates a private network config with a temporary policy reference.
    pub fn private_with_policy_ref(policy_ref: NetworkPolicyRef) -> Self {
        Self::private_with_policy(policy_ref)
    }

    /// Creates a no-network config.
    pub fn none() -> Self {
        Self::None
    }

    /// Creates a named-network config.
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named { name: name.into() }
    }

    /// Creates a named-network config after validating the network name.
    pub fn try_named(name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        validate_network_name(&name)?;
        Ok(Self::Named { name })
    }

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
            Self::Private { policy_ref, .. } => policy_ref.as_ref(),
            Self::None | Self::Named { .. } => None,
        }
    }

    /// Returns the configured private-network policy, when present.
    pub fn policy(&self) -> Option<&NetworkPolicy> {
        match self {
            Self::Private { policy, .. } => policy.as_ref(),
            Self::None | Self::Named { .. } => None,
        }
    }
}

impl From<MachineNetworkConfig> for models::MachineNetworkConfig {
    fn from(value: MachineNetworkConfig) -> Self {
        match value {
            MachineNetworkConfig::Private { policy, policy_ref } => {
                Self::Private { policy, policy_ref }
            }
            MachineNetworkConfig::None => Self::None,
            MachineNetworkConfig::Named { name } => Self::Named { name },
        }
    }
}

impl From<models::MachineNetworkConfig> for MachineNetworkConfig {
    fn from(value: models::MachineNetworkConfig) -> Self {
        match value {
            models::MachineNetworkConfig::Private { policy, policy_ref } => {
                Self::Private { policy, policy_ref }
            }
            models::MachineNetworkConfig::None => Self::None,
            models::MachineNetworkConfig::Named { name } => Self::Named { name },
        }
    }
}

/// Network driver implementation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkDriverKind {
    /// netd-based networking.
    Netd,
    /// Virtualization.framework NAT networking.
    VzNat,
}

/// Connectivity topology for a named network definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkTopology {
    /// NAT-backed network.
    Nat,
    /// Bridge-backed network.
    Bridge,
    /// Isolated network.
    Isolated,
}

/// Driver selector for a named network definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkDriver {
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
#[non_exhaustive]
pub struct NetworkDefinition {
    /// Unique network name.
    pub name: String,
    /// Network topology.
    pub topology: NetworkTopology,
    /// Preferred network driver.
    pub driver: NetworkDriver,
}

impl NetworkDefinition {
    /// Creates a named network definition with the given topology.
    pub fn new(name: impl Into<String>, topology: NetworkTopology) -> Self {
        Self {
            name: name.into(),
            topology,
            driver: NetworkDriver::Auto,
        }
    }

    /// Creates a NAT named network definition.
    pub fn nat(name: impl Into<String>) -> Self {
        Self::new(name, NetworkTopology::Nat)
    }

    /// Creates a bridge named network definition.
    pub fn bridge(name: impl Into<String>) -> Self {
        Self::new(name, NetworkTopology::Bridge)
    }

    /// Creates an isolated named network definition.
    pub fn isolated(name: impl Into<String>) -> Self {
        Self::new(name, NetworkTopology::Isolated)
    }

    /// Sets the preferred driver for this definition.
    pub fn driver(mut self, driver: NetworkDriver) -> Self {
        self.driver = driver;
        self
    }

    /// Validates this definition before storing it.
    pub fn validate(&self) -> Result<(), String> {
        validate_network_name(&self.name)?;
        if matches!(self.driver, NetworkDriver::VzNat)
            && !matches!(self.topology, NetworkTopology::Nat)
        {
            return Err("vznat only supports nat networks".to_string());
        }
        Ok(())
    }
}

pub(crate) fn validate_network_name(name: &str) -> Result<(), String> {
    validate_identifier(
        name,
        IdentifierPolicy {
            reserved: RESERVED_NETWORK_NAMES,
        },
    )
    .map_err(|reason| format!("invalid network name: {reason}"))
}

impl Default for NetworkDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            topology: NetworkTopology::Nat,
            driver: NetworkDriver::default(),
        }
    }
}

impl From<NetworkDefinition> for models::NetworkDefinition {
    fn from(value: NetworkDefinition) -> Self {
        Self {
            name: value.name,
            topology: value.topology.into(),
            driver_preference: value.driver.into(),
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
            driver: value.driver_preference.into(),
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

impl From<NetworkDriver> for models::NetworkDriverPreference {
    fn from(value: NetworkDriver) -> Self {
        match value {
            NetworkDriver::Auto => Self::Auto,
            NetworkDriver::Netd => Self::Netd,
            NetworkDriver::VzNat => Self::VzNat,
        }
    }
}

impl From<models::NetworkDriverPreference> for NetworkDriver {
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
    use super::{NetworkDefinition, NetworkDriver, NetworkTopology};

    #[test]
    fn vznat_driver_allows_nat_named_networks() {
        let definition = NetworkDefinition {
            name: "devnet".to_string(),
            topology: NetworkTopology::Nat,
            driver: NetworkDriver::VzNat,
        };

        definition
            .validate()
            .expect("vznat should allow nat networks");
    }

    #[test]
    fn vznat_driver_rejects_non_nat_named_networks() {
        let definition = NetworkDefinition {
            name: "devnet".to_string(),
            topology: NetworkTopology::Bridge,
            driver: NetworkDriver::VzNat,
        };

        assert!(definition.validate().is_err());
    }

    #[test]
    fn network_definition_rejects_invalid_names() {
        for name in ["", "-devnet", "private", "none", "dev/net"] {
            let definition = NetworkDefinition::nat(name);

            assert!(definition.validate().is_err(), "{name:?} should fail");
        }
    }
}
