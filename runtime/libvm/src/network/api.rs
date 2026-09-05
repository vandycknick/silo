use serde::{Deserialize, Serialize};
use std::str::FromStr;

use silo_policy::NetworkPolicy;

use crate::store::models;
use crate::utils::{validate_identifier, IdentifierPolicy};

const RESERVED_NETWORK_NAMES: &[&str] = &["private", "none"];

/// Guest authority to request host TCP publications through its private network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestPublish {
    /// Host addresses the guest may request netd to bind.
    pub bind: PublishBind,
}

/// Host bind policy for guest-requested publications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishBind {
    /// Permit host loopback listeners only.
    Loopback,
    /// Permit loopback and wildcard host listeners.
    Any,
}

impl PublishBind {
    /// Returns the stable command-line and serialization spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Any => "any",
        }
    }
}

impl FromStr for PublishBind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "loopback" => Ok(Self::Loopback),
            "any" => Ok(Self::Any),
            _ => Err(format!(
                "invalid guest publication bind {value:?}; expected loopback or any"
            )),
        }
    }
}

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
        /// Guest-requested publication authority.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        publish: Option<GuestPublish>,
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
            publish: None,
        }
    }
}

impl MachineNetworkConfig {
    pub(crate) fn private() -> Self {
        Self::Private {
            policy: None,
            publish: None,
        }
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

    /// Returns the guest publication setting, when enabled.
    pub fn publish(&self) -> Option<GuestPublish> {
        match self {
            Self::Private { publish, .. } => *publish,
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
        } else if let MachineNetworkConfig::Private {
            policy: existing, ..
        } = &mut self.config
        {
            *existing = Some(policy.normalized());
        }
        self
    }

    /// Allows the guest to request host TCP publications through netd.
    pub fn publish(mut self, bind: PublishBind) -> Self {
        let error = match &self.config {
            MachineNetworkConfig::Private { .. } => None,
            MachineNetworkConfig::None => {
                Some("guest publications require a private network attachment".to_string())
            }
            MachineNetworkConfig::Named { name } => Some(format!(
                "guest publications require a private network attachment, but named network {name:?} was selected"
            )),
        };
        if let Some(error) = error {
            self.record_error(error);
        } else if let MachineNetworkConfig::Private { publish, .. } = &mut self.config {
            *publish = Some(GuestPublish { bind });
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
            MachineNetworkConfig::Private { policy, publish } => Self::Private {
                policy,
                publish: publish.map(Into::into),
            },
            MachineNetworkConfig::None => Self::None,
            MachineNetworkConfig::Named { name } => Self::Named { name },
        }
    }
}

impl From<models::MachineNetworkConfig> for MachineNetworkConfig {
    fn from(value: models::MachineNetworkConfig) -> Self {
        match value {
            models::MachineNetworkConfig::Private { policy, publish } => Self::Private {
                policy,
                publish: publish.map(Into::into),
            },
            models::MachineNetworkConfig::None => Self::None,
            models::MachineNetworkConfig::Named { name } => Self::Named { name },
        }
    }
}

impl From<GuestPublish> for models::GuestPublish {
    fn from(value: GuestPublish) -> Self {
        Self {
            bind: value.bind.into(),
        }
    }
}

impl From<models::GuestPublish> for GuestPublish {
    fn from(value: models::GuestPublish) -> Self {
        Self {
            bind: value.bind.into(),
        }
    }
}

impl From<PublishBind> for models::PublishBind {
    fn from(value: PublishBind) -> Self {
        match value {
            PublishBind::Loopback => Self::Loopback,
            PublishBind::Any => Self::Any,
        }
    }
}

impl From<models::PublishBind> for PublishBind {
    fn from(value: models::PublishBind) -> Self {
        match value {
            models::PublishBind::Loopback => Self::Loopback,
            models::PublishBind::Any => Self::Any,
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
    use super::{
        GuestPublish, MachineNetworkBuilder, MachineNetworkConfig, NetworkDefinition,
        NetworkDriver, NetworkTopology, PublishBind,
    };

    #[test]
    fn private_network_guest_publish_round_trips_through_json() {
        let network = MachineNetworkConfig::Private {
            policy: None,
            publish: Some(GuestPublish {
                bind: PublishBind::Any,
            }),
        };

        let json = serde_json::to_string(&network).expect("serialize network");
        assert_eq!(json, r#"{"kind":"private","publish":{"bind":"any"}}"#);
        assert_eq!(
            serde_json::from_str::<MachineNetworkConfig>(&json).expect("deserialize network"),
            network
        );
    }

    #[test]
    fn private_network_without_guest_publish_still_deserializes() {
        let network = serde_json::from_str::<MachineNetworkConfig>(r#"{"kind":"private"}"#)
            .expect("deserialize old network config");

        assert_eq!(network, MachineNetworkConfig::default());
    }

    #[test]
    fn guest_publish_requires_private_network() {
        let error = MachineNetworkBuilder::new()
            .none()
            .publish(PublishBind::Loopback)
            .build()
            .expect_err("network none must reject guest publication");

        assert_eq!(
            error,
            "guest publications require a private network attachment"
        );
    }

    #[test]
    fn guest_publish_builder_sets_private_network_authority() {
        let network = MachineNetworkBuilder::new()
            .publish(PublishBind::Loopback)
            .build()
            .expect("private network should allow guest publication");

        assert_eq!(
            network.publish(),
            Some(GuestPublish {
                bind: PublishBind::Loopback
            })
        );
    }

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
