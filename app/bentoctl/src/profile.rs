use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bento_core::Mount;
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
pub(crate) struct ProfileNetwork {
    pub mode: NetworkMode,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NetworkMode {
    Isolated,
    None,
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
    pub fn network_mode(&self) -> NetworkMode {
        self.network
            .as_ref()
            .map(|network| network.mode)
            .unwrap_or(NetworkMode::Isolated)
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

pub(crate) fn network_driver_name(mode: NetworkMode) -> &'static str {
    match mode {
        NetworkMode::Isolated => "gvisor",
        NetworkMode::None => "none",
    }
}

pub(crate) fn network_mode_label(mode: NetworkMode) -> &'static str {
    match mode {
        NetworkMode::Isolated => "isolated",
        NetworkMode::None => "none",
    }
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
            network: Some(ProfileNetwork {
                mode: NetworkMode::Isolated,
            }),
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
