use serde::{Deserialize, Serialize};

use silo_policy::NetworkPolicy;

use super::MachineId;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Persisted network runtime instance.
///
/// Instances are internal driver-owned records, not public named-network
/// configuration and not the vmmon network argument.
pub(crate) struct NetworkInstance {
    pub id: String,
    pub driver: String,
    pub definition_name: Option<String>,
    pub attachment_json: String,
    pub driver_state_json: String,
    pub state: NetworkInstanceState,
    pub created_at: i64,
    pub modified_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Persisted lifecycle state for a network runtime instance.
pub(crate) enum NetworkInstanceState {
    Running,
}

impl NetworkInstanceState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "running" => Ok(Self::Running),
            other => Err(format!("unknown network instance state {other:?}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Persisted attachment between one machine and one network instance.
pub(crate) struct NetworkAttachment {
    pub machine_id: MachineId,
    pub network_instance_id: String,
    pub guest_mac: String,
    pub created_at: i64,
    pub modified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Persisted network config for a machine.
///
/// Public callers use `crate::network::MachineNetworkConfig`; this model is the
/// private stored shape embedded in `MachineConfig`.
pub(crate) enum MachineNetworkConfig {
    Private {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<NetworkPolicy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        publish: Option<GuestPublish>,
    },
    None,
    Named {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuestPublish {
    pub(crate) bind: PublishBind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PublishBind {
    Loopback,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Persisted connectivity topology for a named network.
pub(crate) enum NetworkTopology {
    Nat,
    Bridge,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
/// Persisted driver preference for a named network.
pub(crate) enum NetworkDriverPreference {
    #[default]
    Auto,
    Netd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Persisted named-network definition.
///
/// Public callers use `NetworkDefinition`; this model remains internal to the store.
pub(crate) struct NetworkDefinition {
    pub name: String,
    pub topology: NetworkTopology,
    pub driver_preference: NetworkDriverPreference,
    pub created_at: i64,
    pub modified_at: i64,
}

impl Default for NetworkDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            topology: NetworkTopology::Nat,
            driver_preference: NetworkDriverPreference::default(),
            created_at: 0,
            modified_at: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::store::models::network::{
        GuestPublish, MachineNetworkConfig, NetworkInstanceState, PublishBind,
    };

    #[test]
    fn network_instance_state_round_trips_through_storage_string() {
        assert_eq!(
            NetworkInstanceState::parse(NetworkInstanceState::Running.as_str())
                .expect("parse network state"),
            NetworkInstanceState::Running
        );
    }

    #[test]
    fn network_instance_state_rejects_unknown_storage_string() {
        let err = NetworkInstanceState::parse("stopped").expect_err("unknown state should fail");

        assert!(err.contains("unknown network instance state"));
    }

    #[test]
    fn persisted_guest_publish_round_trips_through_json() {
        let network = MachineNetworkConfig::Private {
            policy: None,
            publish: Some(GuestPublish {
                bind: PublishBind::Any,
            }),
        };

        let json = serde_json::to_string(&network).expect("serialize stored network");
        assert_eq!(
            serde_json::from_str::<MachineNetworkConfig>(&json)
                .expect("deserialize stored network"),
            network
        );
    }

    #[test]
    fn persisted_private_network_without_publish_still_deserializes() {
        let network = serde_json::from_str::<MachineNetworkConfig>(r#"{"kind":"private"}"#)
            .expect("deserialize old stored network");

        assert_eq!(network, MachineNetworkConfig::default());
    }
}
