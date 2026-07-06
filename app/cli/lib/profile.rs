use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{bail, Context as _};
use libvm::{MachineNetworkBuilder, NetworkPolicy};
use serde::{Deserialize, Serialize};
use utils::HumanSize;
use vm_spec::Mount;

use crate::constants::{DEFAULT_PROFILE_IMAGE, DEFAULT_PROFILE_NAME};
use crate::network_policy::resolve_network_policy_source;

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
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ProfileResources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userdata: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<ProfileMount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<ProfileNetwork>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
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
    pub policy: Option<serde_yaml_ng::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
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
        policy_ref: Option<String>,
    },
    None,
    Named {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MachineNetworkSelection {
    Private,
    None,
    Named { name: String },
}

impl MachineNetworkSelection {
    pub(crate) fn parse(input: &str) -> Result<Self, String> {
        match input {
            "private" => Ok(Self::Private),
            "none" => Ok(Self::None),
            other if other.starts_with("name:") => Self::named(other.trim_start_matches("name:")),
            other => Self::named(other),
        }
    }

    pub(crate) fn apply(self, builder: MachineNetworkBuilder) -> MachineNetworkBuilder {
        match self {
            Self::Private => builder.private(),
            Self::None => builder.none(),
            Self::Named { name } => builder.named(name),
        }
    }

    pub(crate) fn into_profile_network(self) -> ProfileNetwork {
        match self {
            Self::Private => ProfileNetwork::Private { policy_ref: None },
            Self::None => ProfileNetwork::None,
            Self::Named { name } => ProfileNetwork::Named { name },
        }
    }

    fn named(name: &str) -> Result<Self, String> {
        if name.is_empty() {
            return Err("network name cannot be empty".to_string());
        }
        if matches!(name, "private" | "none") {
            return Err(format!("{name:?} is a reserved network name"));
        }
        Ok(Self::Named {
            name: name.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedMachineNetwork {
    Private { policy: Option<NetworkPolicy> },
    None,
    Named { name: String },
}

impl ResolvedMachineNetwork {
    pub(crate) fn apply(self, builder: MachineNetworkBuilder) -> MachineNetworkBuilder {
        match self {
            Self::Private { policy } => {
                let builder = builder.private();
                if let Some(policy) = policy {
                    builder.policy(policy)
                } else {
                    builder
                }
            }
            Self::None => builder.none(),
            Self::Named { name } => builder.named(name),
        }
    }
}

impl Default for ResolvedMachineNetwork {
    fn default() -> Self {
        Self::Private { policy: None }
    }
}

impl From<MachineNetworkSelection> for ResolvedMachineNetwork {
    fn from(selection: MachineNetworkSelection) -> Self {
        match selection {
            MachineNetworkSelection::Private => Self::Private { policy: None },
            MachineNetworkSelection::None => Self::None,
            MachineNetworkSelection::Named { name } => Self::Named { name },
        }
    }
}

impl ProfileNetwork {
    pub(crate) fn resolve_machine_network(
        self,
        policy_config_dir: Option<&Path>,
    ) -> eyre::Result<ResolvedMachineNetwork> {
        match self {
            Self::Private { policy_ref } => {
                let policy = policy_ref
                    .as_deref()
                    .map(|source| resolve_network_policy_source(source, policy_config_dir))
                    .transpose()?;
                Ok(ResolvedMachineNetwork::Private { policy })
            }
            Self::None => Ok(ResolvedMachineNetwork::None),
            Self::Named { name } => Ok(ResolvedMachineNetwork::Named { name }),
        }
    }
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
                        .and_then(|name| name.to_str())
                        .unwrap_or("<unknown>"),
                    path.file_name()
                        .and_then(|name| name.to_str())
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
            .unwrap_or(ProfileNetwork::Private { policy_ref: None })
    }

    pub fn machine_network(
        &self,
        policy_config_dir: Option<&Path>,
    ) -> eyre::Result<ResolvedMachineNetwork> {
        self.network().resolve_machine_network(policy_config_dir)
    }

    pub fn cpus(&self) -> Option<u8> {
        self.resources.as_ref().and_then(|resources| resources.cpus)
    }

    pub fn memory_mib(&self) -> eyre::Result<Option<u32>> {
        let Some(memory) = self
            .resources
            .as_ref()
            .and_then(|resources| resources.memory.as_deref())
        else {
            return Ok(None);
        };
        let size = parse_size_config(memory, "resources.memory")?;
        size.memory_mib()
            .map(Some)
            .map_err(|error| eyre::eyre!("profile resources.memory: {error}"))
    }

    pub fn disk_size_bytes(&self) -> eyre::Result<Option<u64>> {
        let Some(disk_size) = self.disk_size.as_deref() else {
            return Ok(None);
        };
        parse_size_config(disk_size, "disk_size")?
            .storage_bytes()
            .map(Some)
            .map_err(|error| eyre::eyre!("profile disk_size: {error}"))
    }

    pub fn network_name(&self) -> String {
        match self.network() {
            ProfileNetwork::Private { .. } => "private".to_string(),
            ProfileNetwork::None => "none".to_string(),
            ProfileNetwork::Named { name } => name,
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

fn parse_size_config(input: &str, field: &str) -> eyre::Result<HumanSize> {
    input
        .parse::<HumanSize>()
        .map_err(|error| eyre::eyre!("profile {field}: {error}"))
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
    if raw.policy.is_some() {
        bail!(
            "invalid network config: inline network.policy is no longer supported; use policy_ref"
        );
    }
    if let Some(policy_ref) = raw.policy_ref.as_deref() {
        if policy_ref.trim().is_empty() {
            bail!("invalid network config: policy_ref cannot be empty");
        }
    }
    match (raw.kind, raw.name, raw.policy_ref) {
        (Some(ProfileNetworkKind::Private), Some(name), _) => bail!(
            "invalid network config: kind \"private\" cannot be combined with name {:?}",
            name
        ),
        (Some(ProfileNetworkKind::None), Some(name), _) => bail!(
            "invalid network config: kind \"none\" cannot be combined with name {:?}",
            name
        ),
        (Some(ProfileNetworkKind::Named), None, _) => {
            bail!("invalid network config: kind \"named\" requires field \"name\"")
        }
        (Some(ProfileNetworkKind::Private), None, policy_ref) => {
            Ok(ProfileNetwork::Private { policy_ref })
        }
        (Some(ProfileNetworkKind::None), None, None) => Ok(ProfileNetwork::None),
        (Some(ProfileNetworkKind::None), None, Some(_)) => {
            bail!("invalid network config: kind \"none\" cannot be combined with policy_ref")
        }
        (Some(ProfileNetworkKind::Named), Some(name), None) | (None, Some(name), None) => {
            Ok(ProfileNetwork::Named { name })
        }
        (Some(ProfileNetworkKind::Named), Some(_), Some(_)) | (None, Some(_), Some(_)) => {
            bail!("invalid network config: named networks do not support policy_ref")
        }
        (None, None, policy_ref) => Ok(ProfileNetwork::Private { policy_ref }),
    }
}

pub(crate) fn validate_profile(profile: &Profile) -> eyre::Result<()> {
    if profile.version != "1" {
        bail!(
            "unsupported profile version `{}`, supported versions: 1",
            profile.version
        );
    }
    if profile.image.trim().is_empty() {
        bail!("profile image cannot be empty");
    }
    let _ = profile.memory_mib()?;
    if let Some(disk_size_bytes) = profile.disk_size_bytes()? {
        if disk_size_bytes == 0 {
            bail!("profile disk_size must be greater than 0");
        }
    }
    if let Some(userdata) = &profile.userdata {
        if userdata.trim().is_empty() {
            bail!("profile userdata cannot be empty");
        }
        if !userdata.starts_with("#!") {
            bail!("profile userdata must start with a shebang (`#!`)");
        }
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
            description: Some("Built-in default Silo profile".to_string()),
            image: DEFAULT_PROFILE_IMAGE.to_string(),
            resources: None,
            disk_size: None,
            userdata: None,
            mounts: Vec::new(),
            network: Some(ProfileNetwork::Private { policy_ref: None }),
            labels: BTreeMap::new(),
        },
    }
}

fn profile_dir() -> eyre::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| eyre::eyre!("could not resolve ~/.config/silo/profiles from HOME"))?;
    Ok(home.join(".config/silo/profiles"))
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
            path.extension().and_then(|extension| extension.to_str()),
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
    fn parses_private_network_policy_source() {
        let profile = parse_profile(
            r#"
version: "1"
image: "ubuntu:24.04"
network:
  kind: private
  policy_ref: github
"#,
        )
        .expect("parse profile");

        let policy_ref = profile
            .network
            .as_ref()
            .and_then(|network| match network {
                crate::profile::ProfileNetwork::Private { policy_ref } => policy_ref.as_ref(),
                crate::profile::ProfileNetwork::Named { .. } => None,
                crate::profile::ProfileNetwork::None => None,
            })
            .expect("network policy ref");
        assert_eq!(policy_ref, "github");
    }

    #[test]
    fn rejects_inline_network_policy() {
        let err = parse_profile(
            r#"
version: "1"
image: "ubuntu:24.04"
network:
  kind: private
  policy:
    default_action: allow
"#,
        )
        .expect_err("inline policy should fail");

        assert!(err
            .chain()
            .any(|cause| cause.to_string().contains("inline network.policy")));
    }

    #[test]
    fn rejects_reserved_network_names() {
        let err = parse_profile(
            r#"
version: "1"
image: "ubuntu:24.04"
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
image: "ubuntu:24.04"
network:
  name: dev
"#,
        )
        .expect("named network shorthand should parse");

        assert!(matches!(
            profile.network,
            Some(crate::profile::ProfileNetwork::Named { ref name }) if name == "dev"
        ));
    }

    #[test]
    fn parses_profile_resources_and_disk_size() {
        let profile = parse_profile(
            r#"
version: "1"
image: "ubuntu:24.04"
resources:
  cpus: 4
  memory: 1gb
disk_size: 40gb
"#,
        )
        .expect("profile resources should parse");

        assert_eq!(profile.cpus(), Some(4));
        assert_eq!(profile.memory_mib().expect("memory mib"), Some(1024));
        assert_eq!(
            profile.disk_size_bytes().expect("disk size bytes"),
            Some(40 * 1024 * 1024 * 1024)
        );
    }

    #[test]
    fn rejects_unitless_profile_size_strings() {
        let err = parse_profile(
            r#"
version: "1"
image: "ubuntu:24.04"
resources:
  memory: "4096"
"#,
        )
        .expect_err("unitless memory should fail");

        assert!(err
            .chain()
            .any(|cause| cause.to_string().contains("missing unit")));
    }

    #[test]
    fn parses_userdata_script() {
        let profile = parse_profile(
            r#"
version: "1"
image: "ubuntu:24.04"
userdata: |
  #!/bin/sh
  set -eu
  echo hello
"#,
        )
        .expect("profile with userdata should parse");

        let userdata = profile.userdata.expect("profile userdata");
        assert!(userdata.starts_with("#!/bin/sh"));
        assert!(userdata.contains("echo hello"));
    }

    #[test]
    fn rejects_userdata_without_shebang() {
        let err = parse_profile(
            r#"
version: "1"
image: "ubuntu:24.04"
userdata: |
  set -eu
  echo hello
"#,
        )
        .expect_err("userdata without shebang should fail");

        assert!(err
            .chain()
            .any(|cause| cause.to_string().contains("must start with a shebang")));
    }
}
