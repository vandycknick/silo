use bento_core::NetworkPolicySpec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestedNetwork {
    Private {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<NetworkPolicySpec>,
    },
    None,
    Named {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<NetworkPolicySpec>,
    },
}

impl Default for RequestedNetwork {
    fn default() -> Self {
        Self::Private { policy: None }
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

    pub fn policy(&self) -> Option<&NetworkPolicySpec> {
        match self {
            Self::Private { policy } | Self::Named { policy, .. } => policy.as_ref(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDriverPreference {
    Auto,
    Netd,
    VzNat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDefinitionSpec {
    pub name: String,
    pub mode: NamedNetworkMode,
    #[serde(default = "default_backend_preference")]
    pub driver_preference: NetworkDriverPreference,
}

impl NetworkDefinitionSpec {
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

impl Default for NetworkDefinitionSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            mode: NamedNetworkMode::Nat,
            driver_preference: default_backend_preference(),
        }
    }
}

fn default_backend_preference() -> NetworkDriverPreference {
    NetworkDriverPreference::Auto
}

#[cfg(test)]
mod tests {
    use super::{NamedNetworkMode, NetworkDefinitionSpec, NetworkDriverPreference};

    #[test]
    fn vznat_driver_preference_allows_nat_named_networks() {
        let spec = NetworkDefinitionSpec {
            name: "devnet".to_string(),
            mode: NamedNetworkMode::Nat,
            driver_preference: NetworkDriverPreference::VzNat,
        };

        spec.validate().expect("vznat should allow nat networks");
    }

    #[test]
    fn vznat_driver_preference_rejects_non_nat_named_networks() {
        let spec = NetworkDefinitionSpec {
            name: "devnet".to_string(),
            mode: NamedNetworkMode::Bridge,
            driver_preference: NetworkDriverPreference::VzNat,
        };

        assert!(spec.validate().is_err());
    }
}
