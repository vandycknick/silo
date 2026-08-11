use std::path::{Path, PathBuf};

use eyre::bail;
use libvm::{MachineNetworkBuilder, NetworkPolicy};
use serde::{Deserialize, Serialize};
use utils::HumanSize;
use vm_spec::Mount;

use crate::network_policy::resolve_network_policy_source;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cpus: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) memory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineMount {
    pub(crate) source: PathBuf,
    pub(crate) target: String,
    #[serde(default = "default_mount_mode")]
    pub(crate) mode: MountMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum MountMode {
    Ro,
    Rw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineNetworkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<MachineNetworkKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<serde_yaml_ng::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MachineNetworkKind {
    Private,
    None,
    Named,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum MachineNetwork {
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

    pub(crate) fn into_machine_network(self) -> MachineNetwork {
        match self {
            Self::Private => MachineNetwork::Private { policy_ref: None },
            Self::None => MachineNetwork::None,
            Self::Named { name } => MachineNetwork::Named { name },
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

impl MachineNetwork {
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

impl<'de> Deserialize<'de> for MachineNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = MachineNetworkConfig::deserialize(deserializer)?;
        normalize_network(raw).map_err(serde::de::Error::custom)
    }
}

pub(crate) fn memory_mib(resources: Option<&MachineResources>) -> eyre::Result<Option<u32>> {
    let Some(memory) = resources.and_then(|resources| resources.memory.as_deref()) else {
        return Ok(None);
    };
    let size = parse_size_config(memory, "resources.memory")?;
    size.memory_mib()
        .map(Some)
        .map_err(|error| eyre::eyre!("resources.memory: {error}"))
}

pub(crate) fn disk_size_bytes(disk_size: Option<&str>) -> eyre::Result<Option<u64>> {
    let Some(disk_size) = disk_size else {
        return Ok(None);
    };
    parse_size_config(disk_size, "disk_size")?
        .storage_bytes()
        .map(Some)
        .map_err(|error| eyre::eyre!("disk_size: {error}"))
}

pub(crate) fn resolve_machine_mounts(mounts: &[MachineMount]) -> eyre::Result<Vec<Mount>> {
    mounts
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

pub(crate) fn validate_machine_defaults(
    resources: Option<&MachineResources>,
    disk_size: Option<&str>,
    userdata: Option<&str>,
    mounts: &[MachineMount],
    network: Option<&MachineNetwork>,
) -> eyre::Result<()> {
    if resources.and_then(|resources| resources.cpus) == Some(0) {
        bail!("resources.cpus must be greater than 0");
    }
    let _ = memory_mib(resources)?;
    if let Some(disk_size_bytes) = disk_size_bytes(disk_size)? {
        if disk_size_bytes == 0 {
            bail!("disk_size must be greater than 0");
        }
    }
    if let Some(userdata) = userdata {
        if userdata.trim().is_empty() {
            bail!("userdata cannot be empty");
        }
        if !userdata.starts_with("#!") {
            bail!("userdata must start with a shebang (`#!`)");
        }
    }
    for mount in mounts {
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
    if let Some(network) = network {
        validate_machine_network(network)?;
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

fn parse_size_config(input: &str, field: &str) -> eyre::Result<HumanSize> {
    input
        .parse::<HumanSize>()
        .map_err(|error| eyre::eyre!("{field}: {error}"))
}

fn normalize_network(raw: MachineNetworkConfig) -> eyre::Result<MachineNetwork> {
    if raw.policy.is_some() {
        bail!(
            "invalid network config: inline network.policy is no longer supported; use policy_ref"
        );
    }
    match (raw.kind, raw.name, raw.policy_ref) {
        (Some(MachineNetworkKind::Private), Some(name), _) => bail!(
            "invalid network config: kind \"private\" cannot be combined with name {:?}",
            name
        ),
        (Some(MachineNetworkKind::None), Some(name), _) => bail!(
            "invalid network config: kind \"none\" cannot be combined with name {:?}",
            name
        ),
        (Some(MachineNetworkKind::Named), None, _) => {
            bail!("invalid network config: kind \"named\" requires field \"name\"")
        }
        (Some(MachineNetworkKind::Private), None, policy_ref) => {
            Ok(MachineNetwork::Private { policy_ref })
        }
        (Some(MachineNetworkKind::None), None, None) => Ok(MachineNetwork::None),
        (Some(MachineNetworkKind::None), None, Some(_)) => {
            bail!("invalid network config: kind \"none\" cannot be combined with policy_ref")
        }
        (Some(MachineNetworkKind::Named), Some(name), None) | (None, Some(name), None) => {
            Ok(MachineNetwork::Named { name })
        }
        (Some(MachineNetworkKind::Named), Some(_), Some(_)) | (None, Some(_), Some(_)) => {
            bail!("invalid network config: named networks do not support policy_ref")
        }
        (None, None, policy_ref) => Ok(MachineNetwork::Private { policy_ref }),
    }
}

fn validate_machine_network(network: &MachineNetwork) -> eyre::Result<()> {
    match network {
        MachineNetwork::Private { policy_ref } => {
            if policy_ref
                .as_deref()
                .is_some_and(|policy_ref| policy_ref.trim().is_empty())
            {
                bail!("invalid network config: policy_ref cannot be empty");
            }
        }
        MachineNetwork::Named { name } => {
            if name.is_empty() {
                bail!("invalid network config: network name cannot be empty");
            }
            if matches!(name.as_str(), "private" | "none") {
                bail!(
                    "invalid network config: {:?} is a reserved network name",
                    name
                );
            }
        }
        MachineNetwork::None => {}
    }
    Ok(())
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

fn default_mount_mode() -> MountMode {
    MountMode::Rw
}
