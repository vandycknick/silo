use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use silo_policy::{NetworkPolicy, NetworkSecretKind};

use crate::store::models::MachineNetworkConfig;
use crate::LibVmError;

/// Optional settings for starting a machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MachineStartOptions {
    /// Command executed by the local machine monitor after the runtime exits.
    ///
    /// When unset, no exit command is registered. The command is passed as
    /// structured argv and is never interpreted by a shell.
    pub exit_command: Option<MachineExitCommand>,
    /// Launch-only network material for this run.
    ///
    /// Secret values are never persisted in durable machine config. They are
    /// validated against the persisted network policy before a network runtime
    /// is launched.
    pub network: NetworkLaunch,
}

/// Launch-only network material supplied when starting a machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkLaunch {
    /// Secret values keyed by canonical network secret slot name.
    pub secrets: Vec<NetworkLaunchSecret>,
    /// Optional OAuth refresh hook shared by OAuth credentials in this network.
    pub oauth_refresh_hook: Option<OAuthRefreshHook>,
}

/// Secret value for one canonical network secret slot.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkLaunchSecret {
    /// Canonical slot name, for example `codex.oauth.access_token`.
    pub slot: String,
    /// Raw secret bytes. libvm base64-encodes this before handing it to a
    /// networking component.
    pub value: Vec<u8>,
}

impl fmt::Debug for NetworkLaunchSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkLaunchSecret")
            .field("slot", &self.slot)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Command hook used by a networking component to refresh OAuth access tokens.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OAuthRefreshHook {
    /// Absolute executable path.
    pub command: PathBuf,
    /// Arguments passed directly to the executable, without shell parsing.
    pub args: Vec<String>,
    /// Opaque authorization material passed through to the hook.
    pub auth: Vec<u8>,
    /// Optional hook timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Optional proactive refresh skew in seconds.
    pub refresh_skew_seconds: Option<u64>,
}

impl fmt::Debug for OAuthRefreshHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthRefreshHook")
            .field("command", &self.command)
            .field("args", &self.args)
            .field("auth", &"<redacted>")
            .field("timeout_ms", &self.timeout_ms)
            .field("refresh_skew_seconds", &self.refresh_skew_seconds)
            .finish()
    }
}

/// Structured command to run after the machine runtime exits.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MachineExitCommand {
    /// Executable path or binary name.
    pub command: PathBuf,
    /// Arguments passed to the executable.
    pub args: Vec<OsString>,
}

impl MachineExitCommand {
    /// Creates a structured exit command.
    pub fn new<I, A>(command: impl Into<PathBuf>, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        Self {
            command: command.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

impl NetworkLaunch {
    /// Creates empty network launch material.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a UTF-8 secret value for a canonical network secret slot.
    pub fn secret(self, slot: impl Into<String>, value: impl Into<String>) -> Self {
        self.secret_bytes(slot, value.into().into_bytes())
    }

    /// Adds raw secret bytes for a canonical network secret slot.
    pub fn secret_bytes(mut self, slot: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.secrets.push(NetworkLaunchSecret {
            slot: slot.into(),
            value: value.into(),
        });
        self
    }

    /// Registers the OAuth refresh hook for this network launch.
    pub fn oauth_refresh_hook(mut self, hook: OAuthRefreshHook) -> Self {
        self.oauth_refresh_hook = Some(hook);
        self
    }

    /// Merges prebuilt launch material into this builder.
    pub fn apply(mut self, launch: NetworkLaunch) -> Self {
        self.secrets.extend(launch.secrets);
        if launch.oauth_refresh_hook.is_some() {
            self.oauth_refresh_hook = launch.oauth_refresh_hook;
        }
        self
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.secrets.is_empty() && self.oauth_refresh_hook.is_none()
    }

    pub(crate) fn validate_for_network_config(
        &self,
        network: &MachineNetworkConfig,
        reference: &str,
    ) -> Result<(), LibVmError> {
        match network {
            MachineNetworkConfig::Private { policy, .. } => {
                self.validate_for_policy(policy.as_ref(), reference)
            }
            MachineNetworkConfig::None | MachineNetworkConfig::Named { .. } => {
                if self.is_empty() {
                    Ok(())
                } else {
                    Err(LibVmError::NetworkRuntime {
                        reference: reference.to_string(),
                        message: "network launch material requires a private network policy"
                            .to_string(),
                    })
                }
            }
        }
    }

    pub(crate) fn validate_for_policy(
        &self,
        policy: Option<&NetworkPolicy>,
        reference: &str,
    ) -> Result<(), LibVmError> {
        let Some(policy) = policy else {
            if self.is_empty() {
                return Ok(());
            }
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: "network launch material requires a persisted network policy".to_string(),
            });
        };

        let slots = policy.secret_slots();
        let mut env_names = HashMap::new();
        for slot in &slots {
            let env_name = slot.env_name();
            if let Some(existing) = env_names.get(&env_name) {
                if *existing != slot.name.as_str() {
                    return Err(LibVmError::NetworkRuntime {
                        reference: reference.to_string(),
                        message: format!(
                            "network secret slots {:?} and {:?} both map to {}",
                            existing, slot.name, env_name
                        ),
                    });
                }
            } else {
                env_names.insert(env_name, slot.name.as_str());
            }
        }

        let allowed_slots: HashMap<&str, _> = slots
            .iter()
            .map(|slot| (slot.name.as_str(), slot))
            .collect();
        let mut supplied_slots = HashSet::new();

        for secret in &self.secrets {
            if secret.value.is_empty() {
                return Err(LibVmError::NetworkRuntime {
                    reference: reference.to_string(),
                    message: format!("network secret slot {:?} has an empty value", secret.slot),
                });
            }
            if !allowed_slots.contains_key(secret.slot.as_str()) {
                return Err(LibVmError::NetworkRuntime {
                    reference: reference.to_string(),
                    message: format!(
                        "network secret slot {:?} is not required by the persisted network policy",
                        secret.slot
                    ),
                });
            }
            if !supplied_slots.insert(secret.slot.as_str()) {
                return Err(LibVmError::NetworkRuntime {
                    reference: reference.to_string(),
                    message: format!(
                        "network secret slot {:?} was supplied more than once",
                        secret.slot
                    ),
                });
            }
        }

        for requirement in policy.secret_requirements() {
            if !requirement.alternatives.iter().any(|alternative| {
                alternative
                    .slots
                    .iter()
                    .all(|slot| supplied_slots.contains(slot.as_str()))
            }) {
                return Err(LibVmError::NetworkRuntime {
                    reference: reference.to_string(),
                    message: format!(
                        "required network secret material for {} was not supplied; expected {}",
                        requirement.owner,
                        format_secret_requirement(&requirement.alternatives)
                    ),
                });
            }
        }

        self.validate_oauth_refresh_hook(policy, reference)
    }

    pub(crate) fn secret_environment(
        &self,
        policy: &NetworkPolicy,
        reference: &str,
    ) -> Result<Vec<(String, String)>, LibVmError> {
        self.validate_for_policy(Some(policy), reference)?;
        let policy_slots = policy.secret_slots();
        let slots: HashMap<&str, _> = policy_slots
            .iter()
            .map(|slot| (slot.name.as_str(), slot.env_name()))
            .collect();
        Ok(self
            .secrets
            .iter()
            .map(|secret| {
                let env_name = slots
                    .get(secret.slot.as_str())
                    .expect("validated launch secret slot")
                    .clone();
                (env_name, STANDARD.encode(&secret.value))
            })
            .collect())
    }

    fn validate_oauth_refresh_hook(
        &self,
        policy: &NetworkPolicy,
        reference: &str,
    ) -> Result<(), LibVmError> {
        let Some(hook) = &self.oauth_refresh_hook else {
            return Ok(());
        };
        if hook.auth.is_empty() {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: "OAuth refresh hook auth must not be empty".to_string(),
            });
        }
        if !hook.command.is_absolute() {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: format!(
                    "OAuth refresh hook command must be absolute, got {:?}",
                    hook.command
                ),
            });
        }
        if hook.command.to_str().is_none() {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: "OAuth refresh hook command must be valid UTF-8".to_string(),
            });
        }
        if !policy
            .secret_slots()
            .into_iter()
            .any(|slot| slot.kind == NetworkSecretKind::OAuth)
        {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: "OAuth refresh hook requires at least one OAuth credential in the persisted network policy"
                    .to_string(),
            });
        }
        Ok(())
    }
}

fn format_secret_requirement(alternatives: &[silo_policy::NetworkSecretAlternative]) -> String {
    alternatives
        .iter()
        .map(|alternative| {
            alternative
                .slots
                .iter()
                .map(|slot| format!("{slot:?}"))
                .collect::<Vec<_>>()
                .join(" and ")
        })
        .collect::<Vec<_>>()
        .join(" or ")
}

impl OAuthRefreshHook {
    /// Creates an OAuth refresh hook command with opaque authorization bytes.
    pub fn new(command: impl Into<PathBuf>, auth: impl Into<Vec<u8>>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            auth: auth.into(),
            timeout_ms: None,
            refresh_skew_seconds: None,
        }
    }

    /// Appends one command argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Appends command arguments.
    pub fn args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Overrides the hook timeout in milliseconds.
    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Overrides the proactive refresh skew in seconds.
    pub fn refresh_skew_seconds(mut self, refresh_skew_seconds: u64) -> Self {
        self.refresh_skew_seconds = Some(refresh_skew_seconds);
        self
    }

    pub(crate) fn encoded_auth(&self) -> String {
        STANDARD.encode(&self.auth)
    }
}

impl MachineStartOptions {
    /// Creates start options with no exit command.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a command for vmmon to execute after this machine run exits.
    pub fn exit_command(mut self, exit_command: MachineExitCommand) -> Self {
        self.exit_command = Some(exit_command);
        self
    }

    /// Configures launch-only network material for this machine run.
    pub fn network<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(NetworkLaunch) -> NetworkLaunch,
    {
        self.network = configure(self.network);
        self
    }

    pub(crate) fn validate_network_launch(
        &self,
        network: &MachineNetworkConfig,
        reference: &str,
    ) -> Result<(), LibVmError> {
        self.network.validate_for_network_config(network, reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth_policy() -> NetworkPolicy {
        NetworkPolicy::from_json_str(
            r#"{
                "version": 1,
                "metadata": {},
                "endpoints": [
                    { "name": "chatgpt", "kind": "https", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["chatgpt.com"] }
                ],
                "credentials": [
                    { "name": "codex", "kind": "openai_codex_oauth", "endpoint": "chatgpt" }
                ]
            }"#,
        )
        .expect("oauth policy")
    }

    fn aws_policy() -> NetworkPolicy {
        NetworkPolicy::from_json_str(
            r#"{
                "version": 1,
                "metadata": {},
                "endpoints": [
                    { "name": "aws", "kind": "https", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["sts.amazonaws.com"] }
                ],
                "credentials": [
                    { "name": "prod", "kind": "aws_credential", "endpoint": "aws" }
                ]
            }"#,
        )
        .expect("aws policy")
    }

    fn private_network(policy: NetworkPolicy) -> MachineNetworkConfig {
        MachineNetworkConfig::Private {
            policy: Some(policy),
        }
    }

    #[test]
    fn closure_converts_into_machine_start_options() {
        fn accept<F>(configure: F) -> MachineStartOptions
        where
            F: FnOnce(MachineStartOptions) -> MachineStartOptions,
        {
            configure(MachineStartOptions::default())
        }

        let options = accept(|start| {
            start.network(|network| {
                network
                    .secret("codex.oauth.access_token", "token")
                    .secret("codex.oauth.expires_at", "2026-07-04T00:00:00Z")
            })
        });

        assert_eq!(options.network.secrets.len(), 2);
        assert_eq!(options.network.secrets[0].slot, "codex.oauth.access_token");
        assert_eq!(options.network.secrets[0].value, b"token");
    }

    #[test]
    fn network_launch_requires_required_policy_slots() {
        let policy = oauth_policy();
        let launch = NetworkLaunch::new().secret("codex.oauth.access_token", "token");

        let err = launch
            .validate_for_policy(Some(&policy), "devbox")
            .expect_err("missing expires_at should fail");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref message, .. }
                if message.contains("codex.oauth.expires_at")
        ));
    }

    #[test]
    fn network_launch_accepts_aws_profile_secret() {
        let policy = aws_policy();
        let launch = NetworkLaunch::new().secret("prod.profile", "production-admin");

        launch
            .validate_for_policy(Some(&policy), "devbox")
            .expect("profile should satisfy aws credential requirement");
    }

    #[test]
    fn network_launch_accepts_aws_static_secrets() {
        let policy = aws_policy();
        let launch = NetworkLaunch::new()
            .secret("prod.access_key_id", "AKIAEXAMPLE")
            .secret("prod.secret_access_key", "secret")
            .secret("prod.session_token", "session");

        launch
            .validate_for_policy(Some(&policy), "devbox")
            .expect("static keys should satisfy aws credential requirement");
    }

    #[test]
    fn network_launch_rejects_aws_session_token_without_profile_or_static_keys() {
        let policy = aws_policy();
        let launch = NetworkLaunch::new().secret("prod.session_token", "session");

        let err = launch
            .validate_for_policy(Some(&policy), "devbox")
            .expect_err("session token alone should fail");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref message, .. }
                if message.contains("prod.profile")
                    && message.contains("prod.access_key_id")
                    && message.contains("prod.secret_access_key")
        ));
    }

    #[test]
    fn network_launch_rejects_unknown_secret_slots() {
        let policy = oauth_policy();
        let launch = NetworkLaunch::new()
            .secret("codex.oauth.access_token", "token")
            .secret("codex.oauth.expires_at", "2026-07-04T00:00:00Z")
            .secret("codex.oauth.refresh_token", "nope");

        let err = launch
            .validate_for_policy(Some(&policy), "devbox")
            .expect_err("unknown refresh token slot should fail");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref message, .. }
                if message.contains("codex.oauth.refresh_token")
        ));
    }

    #[test]
    fn network_launch_encodes_secret_environment() {
        let policy = oauth_policy();
        let launch = NetworkLaunch::new()
            .secret("codex.oauth.access_token", "token")
            .secret("codex.oauth.expires_at", "2026-07-04T00:00:00Z");

        let env = launch
            .secret_environment(&policy, "devbox")
            .expect("secret env");

        assert!(env.contains(&(
            "SILO_NET_SECRET_CODEX_OAUTH_ACCESS_TOKEN".to_string(),
            "dG9rZW4=".to_string()
        )));
    }

    #[test]
    fn network_launch_rejects_policy_secret_env_name_collisions() {
        let policy: NetworkPolicy = serde_json::from_str(
            r#"
            {
              "version": 1,
              "endpoints": [
                { "name": "api", "kind": "https", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["api.example.com"] }
              ],
              "credentials": [
                { "name": "api-key", "kind": "bearer_token", "endpoint": "api" },
                { "name": "api_key", "kind": "bearer_token", "endpoint": "api" }
              ]
            }
            "#,
        )
        .expect("deserialize invalid policy fixture");
        let launch = NetworkLaunch::new()
            .secret("api-key.token", "left")
            .secret("api_key.token", "right");

        let err = launch
            .validate_for_policy(Some(&policy), "devbox")
            .expect_err("colliding env names should fail before spawning netd");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref message, .. }
                if message.contains("api-key.token")
                    && message.contains("api_key.token")
                    && message.contains("SILO_NET_SECRET_API_KEY_TOKEN")
        ));
    }

    #[test]
    fn oauth_refresh_hook_requires_absolute_command_and_auth() {
        let policy = oauth_policy();
        let launch = NetworkLaunch::new()
            .secret("codex.oauth.access_token", "token")
            .secret("codex.oauth.expires_at", "2026-07-04T00:00:00Z")
            .oauth_refresh_hook(OAuthRefreshHook::new("silo", Vec::<u8>::new()));

        let err = launch
            .validate_for_policy(Some(&policy), "devbox")
            .expect_err("invalid hook should fail");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref message, .. }
                if message.contains("auth must not be empty")
        ));
    }

    #[test]
    fn network_launch_rejects_material_without_private_policy() {
        let launch = NetworkLaunch::new().secret("codex.oauth.access_token", "token");

        let err = launch
            .validate_for_network_config(&MachineNetworkConfig::None, "devbox")
            .expect_err("network material without policy should fail");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref message, .. }
                if message.contains("requires a private network policy")
        ));
    }

    #[test]
    fn start_options_validate_network_launch_against_private_policy() {
        let policy = oauth_policy();
        let options = MachineStartOptions::new().network(|network| {
            network
                .secret("codex.oauth.access_token", "token")
                .secret("codex.oauth.expires_at", "2026-07-04T00:00:00Z")
                .oauth_refresh_hook(
                    OAuthRefreshHook::new("/usr/bin/silo", b"auth".to_vec()).arg("refresh"),
                )
        });

        options
            .validate_network_launch(&private_network(policy), "devbox")
            .expect("valid launch material");
    }
}
