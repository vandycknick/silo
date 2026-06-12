use serde::{Deserialize, Deserializer, Serialize};

use crate::models;
use crate::NetworkPolicyRef;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestedNetwork {
    Private {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_ref: Option<NetworkPolicyRef>,
    },
    None,
    Named {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_ref: Option<NetworkPolicyRef>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawRequestedNetwork {
    Private {
        #[serde(default)]
        policy_ref: Option<NetworkPolicyRef>,
        #[serde(default)]
        policy: Option<serde_json::Value>,
    },
    None,
    Named {
        name: String,
        #[serde(default)]
        policy_ref: Option<NetworkPolicyRef>,
        #[serde(default)]
        policy: Option<serde_json::Value>,
    },
}

impl<'de> Deserialize<'de> for RequestedNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match RawRequestedNetwork::deserialize(deserializer)? {
            RawRequestedNetwork::Private {
                policy: Some(_), ..
            }
            | RawRequestedNetwork::Named {
                policy: Some(_), ..
            } => Err(serde::de::Error::custom(
                "inline network policy is no longer supported; use network.policy_ref with a named policy or absolute .hcl path",
            )),
            RawRequestedNetwork::Private { policy_ref, .. } => Ok(Self::Private { policy_ref }),
            RawRequestedNetwork::None => Ok(Self::None),
            RawRequestedNetwork::Named {
                name, policy_ref, ..
            } => Ok(Self::Named { name, policy_ref }),
        }
    }
}

impl Default for RequestedNetwork {
    fn default() -> Self {
        Self::Private { policy_ref: None }
    }
}

impl RequestedNetwork {
    pub fn name(&self) -> String {
        match self {
            Self::Private { .. } => "private".to_string(),
            Self::None => "none".to_string(),
            Self::Named { name, .. } => name.clone(),
        }
    }

    pub fn policy_ref(&self) -> Option<&NetworkPolicyRef> {
        match self {
            Self::Private { policy_ref } | Self::Named { policy_ref, .. } => policy_ref.as_ref(),
            Self::None => None,
        }
    }

    pub(crate) fn into_model(self) -> models::RequestedNetwork {
        match self {
            Self::Private { policy_ref } => models::RequestedNetwork::Private { policy_ref },
            Self::None => models::RequestedNetwork::None,
            Self::Named { name, policy_ref } => {
                models::RequestedNetwork::Named { name, policy_ref }
            }
        }
    }

    pub(crate) fn from_model(value: &models::RequestedNetwork) -> Self {
        match value {
            models::RequestedNetwork::Private { policy_ref } => Self::Private {
                policy_ref: policy_ref.clone(),
            },
            models::RequestedNetwork::None => Self::None,
            models::RequestedNetwork::Named { name, policy_ref } => Self::Named {
                name: name.clone(),
                policy_ref: policy_ref.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDriverKind {
    Netd,
    VzNat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedNetworkMode {
    Nat,
    Bridge,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDriverPreference {
    #[default]
    Auto,
    Netd,
    VzNat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDefinition {
    pub name: String,
    pub mode: NamedNetworkMode,
    pub driver_preference: NetworkDriverPreference,
}

impl NetworkDefinition {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("invalid network name: cannot be empty".to_string());
        }
        if matches!(self.name.as_str(), "private" | "none") {
            return Err(format!("invalid network name: {:?} is reserved", self.name));
        }
        if matches!(self.driver_preference, NetworkDriverPreference::VzNat)
            && !matches!(self.mode, NamedNetworkMode::Nat)
        {
            return Err("vznat only supports nat networks".to_string());
        }
        Ok(())
    }

    pub(crate) fn into_model(self) -> models::NetworkDefinition {
        models::NetworkDefinition {
            name: self.name,
            mode: self.mode.into(),
            driver_preference: self.driver_preference.into(),
        }
    }

    pub(crate) fn from_model(value: models::NetworkDefinition) -> Self {
        Self {
            name: value.name,
            mode: value.mode.into(),
            driver_preference: value.driver_preference.into(),
        }
    }
}

impl Default for NetworkDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            mode: NamedNetworkMode::Nat,
            driver_preference: NetworkDriverPreference::default(),
        }
    }
}

impl From<NamedNetworkMode> for models::NamedNetworkMode {
    fn from(value: NamedNetworkMode) -> Self {
        match value {
            NamedNetworkMode::Nat => Self::Nat,
            NamedNetworkMode::Bridge => Self::Bridge,
            NamedNetworkMode::Isolated => Self::Isolated,
        }
    }
}

impl From<models::NamedNetworkMode> for NamedNetworkMode {
    fn from(value: models::NamedNetworkMode) -> Self {
        match value {
            models::NamedNetworkMode::Nat => Self::Nat,
            models::NamedNetworkMode::Bridge => Self::Bridge,
            models::NamedNetworkMode::Isolated => Self::Isolated,
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
    use super::{NamedNetworkMode, NetworkDefinition, NetworkDriverPreference};

    #[test]
    fn vznat_driver_preference_allows_nat_named_networks() {
        let definition = NetworkDefinition {
            name: "devnet".to_string(),
            mode: NamedNetworkMode::Nat,
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
            mode: NamedNetworkMode::Bridge,
            driver_preference: NetworkDriverPreference::VzNat,
        };

        assert!(definition.validate().is_err());
    }
}
