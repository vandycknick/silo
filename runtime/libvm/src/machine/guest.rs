use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Durable guest settings owned by libvm rather than the VMM specification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineGuestConfig {
    /// Agent executable selection for managed guest startup.
    #[serde(default)]
    pub agent: MachineAgent,
    /// Guest account provisioned by the managed agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<MachineUserConfig>,
}

/// Concrete guest account configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineUserConfig {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

impl MachineUserConfig {
    pub fn new(name: impl Into<String>, uid: u32, gid: u32, home: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            uid,
            gid,
            home: home.into(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if matches!(self.name.as_str(), "root" | "nobody")
            || matches!(self.uid, 0 | 65_534)
            || matches!(self.gid, 0 | 65_534)
        {
            return Err("guest user must not use root or nobody identities".to_string());
        }
        if self.home == "/" {
            return Err("guest user home must not be the filesystem root".to_string());
        }
        let config = agent_spec::AgentConfig {
            provision: agent_spec::ProvisionConfig {
                users: vec![agent_spec::UserConfig {
                    name: self.name.clone(),
                    uid: self.uid,
                    gid: self.gid,
                    gecos: self.name.clone(),
                    home: self.home.clone(),
                    shell: "/bin/bash".to_string(),
                    sudo: String::new(),
                    lock_passwd: true,
                }],
                ..agent_spec::ProvisionConfig::default()
            },
            ..agent_spec::AgentConfig::default()
        };
        config.validate().map_err(|error| error.to_string())
    }
}

impl MachineGuestConfig {
    pub(crate) fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

/// Agent executable selected for a managed machine launch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[non_exhaustive]
pub enum MachineAgent {
    /// Resolve the installed default agent when the machine starts.
    #[default]
    Default,
    /// Inject a caller-provided agent executable.
    Custom { path: PathBuf },
    /// Do not inject an agent or require guest-agent readiness.
    Disabled,
}

impl MachineAgent {
    pub(crate) fn enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Builder for durable guest settings.
#[derive(Debug, Clone, Default)]
pub struct GuestBuilder {
    config: MachineGuestConfig,
}

impl GuestBuilder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Selects a custom agent, or disables agent injection when `path` is `None`.
    pub fn agent(mut self, path: Option<PathBuf>) -> Self {
        self.config.agent = match path {
            Some(path) => MachineAgent::Custom { path },
            None => MachineAgent::Disabled,
        };
        self
    }

    /// Configures a concrete account for managed guest provisioning.
    pub fn user(mut self, user: MachineUserConfig) -> Self {
        self.config.user = Some(user);
        self
    }

    pub(crate) fn build(self) -> MachineGuestConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::machine::{GuestBuilder, MachineAgent, MachineGuestConfig, MachineUserConfig};

    #[test]
    fn guest_builder_defaults_to_installed_agent() {
        assert_eq!(GuestBuilder::new().build(), MachineGuestConfig::default());
    }

    #[test]
    fn guest_builder_selects_custom_or_disabled_agent() {
        let custom = GuestBuilder::new()
            .agent(Some(PathBuf::from("/custom/agent")))
            .build();
        assert_eq!(
            custom.agent,
            MachineAgent::Custom {
                path: PathBuf::from("/custom/agent")
            }
        );

        let disabled = GuestBuilder::new().agent(None).build();
        assert_eq!(disabled.agent, MachineAgent::Disabled);
    }

    #[test]
    fn guest_builder_stores_a_concrete_user() {
        let user = MachineUserConfig::new("alice", 1000, 2000, "/home/alice");
        let guest = GuestBuilder::new().user(user.clone()).build();

        assert_eq!(guest.user, Some(user));
    }

    #[test]
    fn machine_user_validation_rejects_protected_and_invalid_accounts() {
        assert!(MachineUserConfig::new("root", 0, 0, "/root")
            .validate()
            .is_err());
        assert!(MachineUserConfig::new("alice", 1000, 1000, "relative")
            .validate()
            .is_err());
        MachineUserConfig::new("alice", 1000, 2000, "/home/alice")
            .validate()
            .expect("valid user");
    }
}
