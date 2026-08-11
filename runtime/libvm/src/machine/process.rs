use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Retention policy for a machine after a run completes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineRetention {
    /// Keep durable machine state until it is explicitly removed.
    #[default]
    Persistent,
    /// Allow the lifecycle owner to attempt removal after the run completes.
    Ephemeral,
}

/// Durable process settings for a machine workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessConfig {
    /// OCI entrypoint, where `None`, `Some([])`, and a non-empty vector remain distinct.
    pub entrypoint: Option<Vec<String>>,
    /// OCI command, where `None`, `Some([])`, and a non-empty vector remain distinct.
    pub command: Option<Vec<String>>,
    /// Explicit environment variables, ordered deterministically by variable name.
    pub environment: BTreeMap<String, String>,
    /// Working directory used by the configured process.
    pub working_directory: String,
    /// Optional OCI-style user selector.
    pub user: Option<String>,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            entrypoint: None,
            command: None,
            environment: BTreeMap::new(),
            working_directory: "/".to_string(),
            user: None,
        }
    }
}

impl ProcessConfig {
    /// Creates the default process configuration.
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::ProcessConfig;

    #[test]
    fn process_config_preserves_unset_and_empty_commands() {
        let unset =
            serde_json::to_value(ProcessConfig::default()).expect("serialize unset process");
        let empty = serde_json::to_value(ProcessConfig {
            entrypoint: Some(Vec::new()),
            command: Some(Vec::new()),
            environment: BTreeMap::new(),
            working_directory: "/".to_string(),
            user: None,
        })
        .expect("serialize empty process");

        assert!(unset["entrypoint"].is_null());
        assert!(unset["command"].is_null());
        assert_eq!(empty["entrypoint"], serde_json::json!([]));
        assert_eq!(empty["command"], serde_json::json!([]));
    }
}
