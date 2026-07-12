use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Durable guest settings owned by libvm rather than the VMM specification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineGuestConfig {
    /// Agent executable selection for managed guest startup.
    #[serde(default)]
    pub agent: MachineAgent,
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

    pub(crate) fn build(self) -> MachineGuestConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::machine::{GuestBuilder, MachineAgent, MachineGuestConfig};

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
}
