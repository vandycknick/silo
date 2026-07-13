use serde::{Deserialize, Serialize};

use silo_policy::NetworkPolicy;

use crate::store::models;
use crate::utils::{validate_identifier, IdentifierPolicy};

const RESERVED_NETWORK_NAMES: &[&str] = &["private", "none"];

/// Durable network configuration for a machine.
///
/// This is inspect and serialization data: it says what network a machine is
/// configured to connect to when it starts. Configure machine networking through
/// `MachineNetworkBuilder` via `MachineBuilder::network`, `MachineUpdate::network`,
/// or `Machine::set_network`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum MachineNetworkConfig {
    /// Attach the machine to its private network.
    Private {
        /// Resolved canonical policy for the private network.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<NetworkPolicy>,
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
        Self::Private { policy: None }
    }
}

impl MachineNetworkConfig {
    pub(crate) fn private() -> Self {
        Self::Private { policy: None }
    }

    pub(crate) fn none() -> Self {
        Self::None
    }

    pub(crate) fn named(name: impl Into<String>) -> Self {
        Self::Named { name: name.into() }
    }

    /// Returns the display name for the machine network config.
    pub fn name(&self) -> String {
        match self {
            Self::Private { .. } => "private".to_string(),
            Self::None => "none".to_string(),
            Self::Named { name } => name.clone(),
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

/// Fluent builder for a machine's durable network attachment.
#[derive(Debug, Clone)]
pub struct MachineNetworkBuilder {
    config: MachineNetworkConfig,
    error: Option<String>,
}

impl MachineNetworkBuilder {
    pub fn new() -> Self {
        Self {
            config: MachineNetworkConfig::default(),
            error: None,
        }
    }

    pub fn private(mut self) -> Self {
        self.config = MachineNetworkConfig::private();
        self
    }

    pub fn none(mut self) -> Self {
        self.config = MachineNetworkConfig::none();
        self
    }

    pub fn named(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if let Err(reason) = validate_network_name(&name) {
            self.record_error(reason);
        }
        self.config = MachineNetworkConfig::named(name);
        self
    }

    pub fn policy(mut self, policy: NetworkPolicy) -> Self {
        let error = match &self.config {
            MachineNetworkConfig::Private { .. } => None,
            MachineNetworkConfig::None => {
                Some("network policies require a private network attachment".to_string())
            }
            MachineNetworkConfig::Named { name } => Some(format!(
                "network policies require a private network attachment, but named network {name:?} was selected"
            )),
        };
        if let Some(error) = error {
            self.record_error(error);
        } else if let MachineNetworkConfig::Private { policy: existing } = &mut self.config {
            *existing = Some(policy.normalized());
        }
        self
    }

    pub(crate) fn build(self) -> Result<MachineNetworkConfig, String> {
        if let Some(error) = self.error {
            return Err(error);
        }
        Ok(self.config)
    }

    fn record_error(&mut self, reason: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(reason.into());
        }
    }
}

impl Default for MachineNetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl From<MachineNetworkConfig> for models::MachineNetworkConfig {
    fn from(value: MachineNetworkConfig) -> Self {
        match value {
            MachineNetworkConfig::Private { policy } => Self::Private { policy },
            MachineNetworkConfig::None => Self::None,
            MachineNetworkConfig::Named { name } => Self::Named { name },
        }
    }
}

impl From<models::MachineNetworkConfig> for MachineNetworkConfig {
    fn from(value: models::MachineNetworkConfig) -> Self {
        match value {
            models::MachineNetworkConfig::Private { policy } => Self::Private { policy },
            models::MachineNetworkConfig::None => Self::None,
            models::MachineNetworkConfig::Named { name } => Self::Named { name },
        }
    }
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
        validate_network_name(&self.name)
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
        }
    }
}

impl From<models::NetworkDriverPreference> for NetworkDriver {
    fn from(value: models::NetworkDriverPreference) -> Self {
        match value {
            models::NetworkDriverPreference::Auto => Self::Auto,
            models::NetworkDriverPreference::Netd => Self::Netd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkDefinition, NetworkDriver, NetworkTopology};

    #[test]
    fn netd_driver_allows_nat_named_networks() {
        let definition = NetworkDefinition {
            name: "devnet".to_string(),
            topology: NetworkTopology::Nat,
            driver: NetworkDriver::Netd,
        };

        definition
            .validate()
            .expect("netd should allow nat network definitions");
    }

    #[test]
    fn network_definition_rejects_invalid_names() {
        for name in ["", "-devnet", "private", "none", "dev/net"] {
            let definition = NetworkDefinition::nat(name);

            assert!(definition.validate().is_err(), "{name:?} should fail");
        }
    }
}
