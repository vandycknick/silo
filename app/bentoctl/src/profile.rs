use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bento_core::Mount;
use bento_core::{NetworkPolicySpec, NetworkProtocol};
use bento_libvm::RequestedNetwork;
use eyre::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::constants::{DEFAULT_PROFILE_IMAGE, DEFAULT_PROFILE_NAME};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NamedProfile {
    pub name: String,
    pub path: Option<PathBuf>,
    pub profile: Profile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub image: ProfileImage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<ProfileMount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<ProfileNetwork>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<ProfileSsh>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileImage {
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileMount {
    pub source: PathBuf,
    pub target: String,
    #[serde(default = "default_mount_mode")]
    pub mode: MountMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileNetworkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ProfileNetworkKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<NetworkPolicySpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<NetworkPolicyRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkPolicyRef {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileNetworkKind {
    Private,
    None,
    Named,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ProfileNetwork {
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

impl<'de> Deserialize<'de> for ProfileNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = ProfileNetworkConfig::deserialize(deserializer)?;
        normalize_network(raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileSsh {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, rename = "githubUsers", skip_serializing_if = "Vec::is_empty")]
    pub github_users: Vec<String>,
    #[serde(
        default,
        rename = "authorizedKeys",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub authorized_keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum MountMode {
    Ro,
    Rw,
}

pub(crate) struct ProfileStore {
    root: PathBuf,
}

impl ProfileStore {
    pub fn from_env() -> eyre::Result<Self> {
        Ok(Self {
            root: profile_dir()?,
        })
    }

    pub fn ensure_dir(&self) -> eyre::Result<()> {
        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("create profile directory {}", self.root.display()))
    }

    pub fn path_for_new_profile(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.yaml"))
    }

    pub fn resolve(&self, name: &str) -> eyre::Result<NamedProfile> {
        match self.find_profile_path(name)? {
            Some(path) => self.load_path(name.to_string(), path),
            None if name == DEFAULT_PROFILE_NAME => Ok(built_in_default_profile()),
            None => bail!(
                "profile `{name}` not found in {}",
                display_profile_dir(&self.root)
            ),
        }
    }

    pub fn load_path(&self, name: String, path: PathBuf) -> eyre::Result<NamedProfile> {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("read profile {}", path.display()))?;
        let profile =
            parse_profile(&raw).with_context(|| format!("parse profile {}", path.display()))?;
        Ok(NamedProfile {
            name,
            path: Some(path),
            profile,
        })
    }

    pub fn list(&self) -> eyre::Result<Vec<NamedProfile>> {
        self.ensure_dir()?;
        let mut profiles = Vec::new();
        let mut seen = BTreeMap::<String, PathBuf>::new();

        for entry in std::fs::read_dir(&self.root)
            .with_context(|| format!("read profile directory {}", self.root.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !is_profile_file(&path) {
                continue;
            }
            let name = profile_name_from_path(&path)?;
            if let Some(existing) = seen.insert(name.clone(), path.clone()) {
                bail!(
                    "duplicate profile `{name}`: found both {} and {}",
                    existing
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<unknown>"),
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<unknown>")
                );
            }
        }

        for (name, path) in seen {
            profiles.push(self.load_path(name, path)?);
        }

        if !profiles
            .iter()
            .any(|profile| profile.name == DEFAULT_PROFILE_NAME)
        {
            profiles.push(built_in_default_profile());
        }

        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(profiles)
    }

    pub fn find_profile_path(&self, name: &str) -> eyre::Result<Option<PathBuf>> {
        let yaml = self.root.join(format!("{name}.yaml"));
        let yml = self.root.join(format!("{name}.yml"));
        match (yaml.exists(), yml.exists()) {
            (true, true) => {
                bail!("duplicate profile `{name}`: found both {name}.yaml and {name}.yml")
            }
            (true, false) => Ok(Some(yaml)),
            (false, true) => Ok(Some(yml)),
            (false, false) => Ok(None),
        }
    }
}

impl Profile {
    pub fn network(&self) -> ProfileNetwork {
        self.network
            .clone()
            .unwrap_or(ProfileNetwork::Private { policy: None })
    }

    pub fn requested_network(&self) -> RequestedNetwork {
        match self.network() {
            ProfileNetwork::Private { policy } => RequestedNetwork::Private { policy },
            ProfileNetwork::None => RequestedNetwork::None,
            ProfileNetwork::Named { name, policy } => RequestedNetwork::Named { name, policy },
        }
    }

    pub fn network_name(&self) -> String {
        match self.network() {
            ProfileNetwork::Private { .. } => "private".to_string(),
            ProfileNetwork::None => "none".to_string(),
            ProfileNetwork::Named { name, .. } => name,
        }
    }

    pub fn resolved_mounts(&self) -> eyre::Result<Vec<Mount>> {
        self.mounts
            .iter()
            .map(|mount| {
                let source = resolve_host_path(&mount.source)?;
                Ok(Mount {
                    source,
                    tag: mount.target.clone(),
                    read_only: mount.mode == MountMode::Ro,
                })
            })
            .collect()
    }
}

pub(crate) fn parse_profile(raw: &str) -> eyre::Result<Profile> {
    let profile: Profile = serde_yaml_ng::from_str(raw).context("deserialize profile yaml")?;
    validate_profile(&profile)?;
    Ok(profile)
}

fn normalize_network(raw: ProfileNetworkConfig) -> eyre::Result<ProfileNetwork> {
    if let Some(name) = raw.name.as_deref() {
        if matches!(name, "private" | "none") {
            bail!(
                "invalid network config: {:?} is a reserved network name",
                name
            );
        }
    }
    if raw.policy.is_some() && raw.policy_ref.is_some() {
        bail!("invalid network config: policy and policy_ref are mutually exclusive");
    }
    if raw.policy_ref.is_some() {
        bail!(
            "invalid network config: policy_ref is reserved for external policy files but is not supported yet"
        );
    }
    match (raw.kind, raw.name) {
        (Some(ProfileNetworkKind::Private), Some(name)) => bail!(
            "invalid network config: kind \"private\" cannot be combined with name {:?}",
            name
        ),
        (Some(ProfileNetworkKind::None), Some(name)) => bail!(
            "invalid network config: kind \"none\" cannot be combined with name {:?}",
            name
        ),
        (Some(ProfileNetworkKind::Named), None) => {
            bail!("invalid network config: kind \"named\" requires field \"name\"")
        }
        (Some(ProfileNetworkKind::Private), None) => {
            Ok(ProfileNetwork::Private { policy: raw.policy })
        }
        (Some(ProfileNetworkKind::None), None) => Ok(ProfileNetwork::None),
        (Some(ProfileNetworkKind::Named), Some(name)) | (None, Some(name)) => {
            Ok(ProfileNetwork::Named {
                name,
                policy: raw.policy,
            })
        }
        (None, None) => Ok(ProfileNetwork::Private { policy: raw.policy }),
    }
}

pub(crate) fn validate_profile(profile: &Profile) -> eyre::Result<()> {
    if profile.version != "1" {
        bail!(
            "unsupported profile version `{}`, supported versions: 1",
            profile.version
        );
    }
    if profile.image.reference.trim().is_empty() {
        bail!("profile image.ref cannot be empty");
    }
    for mount in &profile.mounts {
        if mount.source.as_os_str().is_empty() {
            bail!("mount source cannot be empty");
        }
        if !mount.target.starts_with('/') {
            bail!(
                "mount target must be an absolute guest path: {}",
                mount.target
            );
        }
    }
    if let Some(ssh) = &profile.ssh {
        if !ssh.github_users.is_empty() {
            bail!("ssh.githubUsers is not supported yet; guest agent support is still needed");
        }
        if !ssh.authorized_keys.is_empty() {
            bail!("ssh.authorizedKeys is not supported yet; guest agent support is still needed");
        }
    }
    if let Some(network) = &profile.network {
        if let Some(policy) = match network {
            ProfileNetwork::Private { policy } | ProfileNetwork::Named { policy, .. } => {
                policy.as_ref()
            }
            ProfileNetwork::None => None,
        } {
            validate_network_policy(policy)?;
            if let Some(path) = policy
                .audit_log
                .as_ref()
                .and_then(|audit| audit.path.as_ref())
            {
                if !path.is_absolute() {
                    bail!(
                        "network.policy.audit_log.path must be absolute: {}",
                        path.display()
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_network_policy(policy: &NetworkPolicySpec) -> eyre::Result<()> {
    let mut names = BTreeMap::new();
    for rule in &policy.cidr_rules {
        if rule.name.trim().is_empty() {
            bail!("network.policy.cidr_rules.name cannot be empty");
        }
        if names.insert(rule.name.clone(), ()).is_some() {
            bail!("duplicate network.policy.cidr_rules name `{}`", rule.name);
        }
        if rule.source_cidrs.is_empty() && rule.dest_cidrs.is_empty() {
            bail!(
                "network.policy.cidr_rules `{}` requires source_cidrs or dest_cidrs",
                rule.name
            );
        }
        for protocol in &rule.protocols {
            if matches!(protocol, NetworkProtocol::Any) && rule.protocols.len() > 1 {
                bail!("network.policy.cidr_rules `{}` cannot combine protocol any with other protocols", rule.name);
            }
        }
        for cidr in &rule.source_cidrs {
            validate_cidr(cidr)
                .with_context(|| format!("invalid CIDR in rule `{}`: {cidr}", rule.name))?;
        }
        for cidr in &rule.dest_cidrs {
            validate_cidr(cidr)
                .with_context(|| format!("invalid CIDR in rule `{}`: {cidr}", rule.name))?;
        }
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> eyre::Result<()> {
    let Some((ip, prefix)) = cidr.split_once('/') else {
        bail!("missing prefix length");
    };
    let ip: std::net::IpAddr = ip.parse().context("parse IP address")?;
    let prefix: u8 = prefix.parse().context("parse prefix length")?;
    let max = match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    if prefix > max {
        bail!("prefix length {prefix} exceeds {max}");
    }
    Ok(())
}

pub(crate) fn resolve_host_path(path: &Path) -> eyre::Result<PathBuf> {
    let expanded = expand_tilde(path)?;
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()?.join(expanded)
    };
    Ok(absolute)
}

fn built_in_default_profile() -> NamedProfile {
    NamedProfile {
        name: DEFAULT_PROFILE_NAME.to_string(),
        path: None,
        profile: Profile {
            version: "1".to_string(),
            description: Some("Built-in default BentoBox profile".to_string()),
            image: ProfileImage {
                reference: DEFAULT_PROFILE_IMAGE.to_string(),
            },
            mounts: Vec::new(),
            network: Some(ProfileNetwork::Private { policy: None }),
            ssh: Some(ProfileSsh {
                enabled: true,
                github_users: Vec::new(),
                authorized_keys: Vec::new(),
            }),
            labels: BTreeMap::new(),
        },
    }
}

fn profile_dir() -> eyre::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| eyre::eyre!("could not resolve ~/.config/bento/profiles from HOME"))?;
    Ok(home.join(".config/bento/profiles"))
}

fn display_profile_dir(path: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        if let Ok(stripped) = path.strip_prefix(home) {
            return format!("~/{}", stripped.display());
        }
    }
    path.display().to_string()
}

fn expand_tilde(path: &Path) -> eyre::Result<PathBuf> {
    let raw = path.to_string_lossy();
    if raw == "~" || raw.starts_with("~/") {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| eyre::eyre!("could not expand ~ from HOME"))?;
        if raw == "~" {
            return Ok(home);
        }
        return Ok(home.join(&raw[2..]));
    }
    Ok(path.to_path_buf())
}

fn is_profile_file(path: &Path) -> bool {
    path.is_file()
        && matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yaml" | "yml")
        )
}

fn profile_name_from_path(path: &Path) -> eyre::Result<String> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map(str::to_string)
        .ok_or_else(|| eyre::eyre!("invalid profile file name: {}", path.display()))
}

fn default_mount_mode() -> MountMode {
    MountMode::Rw
}

#[cfg(test)]
mod tests {
    use crate::profile::parse_profile;

    #[test]
    fn parses_private_network_policy() {
        let profile = parse_profile(
            r#"
version: "1"
image:
  ref: "ubuntu:24.04"
network:
  kind: private
  policy:
    default_action: allow
    audit_log:
      enabled: true
    cidr_rules:
      - name: deny-private
        action: deny
        protocols: [tcp, udp]
        dest_cidrs: ["10.0.0.0/8"]
        reason: "private range blocked"
"#,
        )
        .expect("parse profile");

        let policy = profile
            .network
            .as_ref()
            .and_then(|network| match network {
                super::ProfileNetwork::Private { policy }
                | super::ProfileNetwork::Named { policy, .. } => policy.as_ref(),
                super::ProfileNetwork::None => None,
            })
            .expect("network policy");
        assert_eq!(policy.cidr_rules.len(), 1);
        assert!(policy.audit_log.as_ref().is_some_and(|audit| audit.enabled));
    }

    #[test]
    fn rejects_removed_isolated_network_mode() {
        let err = parse_profile(
            r#"
version: "1"
image:
  ref: "ubuntu:24.04"
network:
  kind: isolated
"#,
        )
        .expect_err("isolated should fail");

        assert!(err
            .chain()
            .any(|cause| cause.to_string().contains("isolated")));
    }

    #[test]
    fn rejects_reserved_network_names() {
        let err = parse_profile(
            r#"
version: "1"
image:
  ref: "ubuntu:24.04"
network:
  name: private
"#,
        )
        .expect_err("reserved network name should fail");

        assert!(err
            .chain()
            .any(|cause| cause.to_string().contains("reserved network name")));
    }

    #[test]
    fn parses_named_network_shorthand() {
        let profile = parse_profile(
            r#"
version: "1"
image:
  ref: "ubuntu:24.04"
network:
  name: dev
"#,
        )
        .expect("named network shorthand should parse");

        assert!(matches!(
            profile.network,
            Some(super::ProfileNetwork::Named { ref name, .. }) if name == "dev"
        ));
    }
}
