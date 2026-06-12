use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use bento_vm_spec::VmSpec;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{looks_like_id_prefix, LibVmError, MachineId, NetworkPolicyRef};

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineConfig {
    pub id: MachineId,
    pub name: String,
    pub spec: VmSpec,
    pub instance_dir: PathBuf,
    pub created_at: i64,
    pub modified_at: i64,
    pub image_ref: String,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub network: RequestedNetwork,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineState {
    pub machine_id: MachineId,
    pub status: MachineRuntimeState,
    pub vmmon_pid: Option<i32>,
    pub started_at: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineInspect {
    pub config: MachineConfig,
    pub state: MachineState,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineRuntimeState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

impl MachineRuntimeState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Error => "error",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "stopped" => Ok(Self::Stopped),
            "starting" => Ok(Self::Starting),
            "running" => Ok(Self::Running),
            "stopping" => Ok(Self::Stopping),
            "error" => Ok(Self::Error),
            other => Err(format!("unknown machine runtime state {other:?}")),
        }
    }

    pub fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MachineRef {
    Id(MachineId),
    IdPrefix(String),
    Name(String),
}

impl MachineRef {
    pub fn parse(input: impl Into<String>) -> Result<Self, LibVmError> {
        let input = input.into();
        if let Ok(id) = MachineId::from_str(&input) {
            return Ok(Self::Id(id));
        }

        if looks_like_id_prefix(&input) {
            return Ok(Self::IdPrefix(input.to_lowercase()));
        }

        validate_machine_name(&input)?;
        Ok(Self::Name(input))
    }
}

pub(crate) fn validate_machine_name(name: &str) -> Result<(), LibVmError> {
    if name.is_empty() {
        return Err(LibVmError::InvalidMachineName {
            name: name.to_string(),
            reason: "name cannot be empty".to_string(),
        });
    }

    if name.starts_with('-') {
        return Err(LibVmError::InvalidMachineName {
            name: name.to_string(),
            reason: "name cannot start with '-'".to_string(),
        });
    }

    if let Some(ch) = name
        .chars()
        .find(|ch| !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.'))
    {
        return Err(LibVmError::InvalidMachineName {
            name: name.to_string(),
            reason: format!("unsupported character {ch:?}"),
        });
    }

    Ok(())
}

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
            RawRequestedNetwork::Private { policy: Some(_), .. }
            | RawRequestedNetwork::Named { policy: Some(_), .. } => Err(
                serde::de::Error::custom(
                    "inline network policy is no longer supported; use network.policy_ref with a named policy or absolute .hcl path",
                ),
            ),
            RawRequestedNetwork::Private { policy_ref, .. } => {
                Ok(Self::Private { policy_ref })
            }
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

#[cfg(test)]
mod tests {
    use crate::models::{MachineRef, NamedNetworkMode, NetworkDefinition, NetworkDriverPreference};
    use crate::MachineId;

    #[test]
    fn parse_treats_full_uuid_as_machine_id() {
        let id = MachineId::new();
        let machine_ref = MachineRef::parse(id.to_string()).expect("parse machine ref");

        assert_eq!(machine_ref, MachineRef::Id(id));
    }

    #[test]
    fn parse_treats_hex_prefix_as_id_prefix() {
        let machine_ref = MachineRef::parse("a1b2c3d4").expect("parse machine ref");

        assert_eq!(machine_ref, MachineRef::IdPrefix("a1b2c3d4".to_string()));
    }

    #[test]
    fn parse_treats_non_hex_as_name() {
        let machine_ref = MachineRef::parse("devbox").expect("parse machine ref");

        assert_eq!(machine_ref, MachineRef::Name("devbox".to_string()));
    }

    #[test]
    fn parse_rejects_invalid_name() {
        let err = MachineRef::parse("bad/name").expect_err("invalid name should fail");

        assert!(err.to_string().contains("unsupported character"));
    }

    #[test]
    fn parse_short_hex_is_name_not_prefix() {
        let machine_ref = MachineRef::parse("ab").expect("parse machine ref");
        assert_eq!(machine_ref, MachineRef::Name("ab".to_string()));
    }

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
