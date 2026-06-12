use serde::{Deserialize, Deserializer, Serialize};

use super::MachineId;
use crate::NetworkPolicyRef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkInstance {
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
pub(crate) struct NetworkAttachment {
    pub machine_id: MachineId,
    pub network_instance_id: String,
    pub guest_mac: String,
    pub created_at: i64,
    pub modified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum RequestedNetwork {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NamedNetworkMode {
    Nat,
    Bridge,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NetworkDriverPreference {
    #[default]
    Auto,
    Netd,
    VzNat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NetworkDefinition {
    pub name: String,
    pub mode: NamedNetworkMode,
    pub driver_preference: NetworkDriverPreference,
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
