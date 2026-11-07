use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// Default guest readiness timeout used when agent integration is enabled.
pub const DEFAULT_AGENT_TIMEOUT_SECONDS: u64 = 60 * 5;

/// Default guest SSH vsock port exposed by the Silo agent.
pub const SSH_VSOCK_PORT: u32 = 22;

/// Maximum serialized configuration accepted by host composition and the guest agent.
pub const MAX_AGENT_CONFIG_SIZE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    #[serde(default)]
    pub provision: ProvisionConfig,
    #[serde(default)]
    pub ssh: AgentSshConfig,
    /// Trusted per-launch identity and complete attachment inventory.
    /// Required on the wire, never filled from an incoming shutdown request.
    pub storage_shutdown: protocol::shutdown::StorageShutdownContext,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), AgentConfigError> {
        self.validate_provisioning()?;
        self.storage_shutdown
            .validate()
            .map_err(AgentConfigError::new)
    }

    /// Validate reusable provisioning before a run identity has been allocated.
    /// This is not sufficient to admit an injected launch configuration.
    pub fn validate_provisioning(&self) -> Result<(), AgentConfigError> {
        if let Some(ca) = &self.ssh.trusted_ca {
            if ca.trim().contains(['\n', '\r']) {
                return Err(AgentConfigError::new(
                    "ssh.trusted_ca must contain exactly one public key line",
                ));
            }
            let key = ssh_key::PublicKey::from_openssh(ca).map_err(|error| {
                AgentConfigError::new(format!("invalid ssh.trusted_ca: {error}"))
            })?;
            if key.algorithm() != ssh_key::Algorithm::Ed25519 {
                return Err(AgentConfigError::new("ssh.trusted_ca must be Ed25519"));
            }
        }

        if let Some(value) = &self.provision.hostname {
            validate_nonempty(value, "provision.hostname")?;
        }
        validate_unique_nonempty(
            self.provision.users.iter().map(|user| user.name.as_str()),
            "provision user name",
        )?;
        for user in &self.provision.users {
            validate_login_name(&user.name, "provision user name")?;
            if user.uid == u32::MAX {
                return Err(AgentConfigError::new(
                    "provision user uid must not be the reserved maximum value",
                ));
            }
            if user.gid == u32::MAX {
                return Err(AgentConfigError::new(
                    "provision user gid must not be the reserved maximum value",
                ));
            }
            validate_account_field(&user.gecos, "provision user gecos", true)?;
            validate_absolute_path(&user.home, "provision user home")?;
            validate_absolute_path(&user.shell, "provision user shell")?;
            validate_account_field(&user.home, "provision user home", true)?;
            validate_account_field(&user.shell, "provision user shell", true)?;
            validate_account_field(&user.sudo, "provision user sudo", false)?;
        }
        if let Some(authority) = &self.provision.certificate_authority {
            validate_absolute_path(&authority.path, "certificate authority path")?;
            validate_nonempty(&authority.pem, "certificate authority pem")?;
        }
        if let Some(network) = &self.provision.network {
            network.validate()?;
        }
        normalized_mount_plan(&self.provision.mounts)?;
        if let Some(userdata) = &self.provision.userdata {
            validate_nonempty(&userdata.content, "userdata content")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfigError {
    message: String,
}

impl AgentConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AgentConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AgentConfigError {}

fn validate_nonempty(value: &str, field: &str) -> Result<(), AgentConfigError> {
    if value.trim().is_empty() {
        return Err(AgentConfigError::new(format!("{field} must not be empty")));
    }
    Ok(())
}

fn validate_login_name(value: &str, field: &str) -> Result<(), AgentConfigError> {
    validate_nonempty(value, field)?;
    let bytes = value.as_bytes();
    if bytes.len() > 256
        || value == "."
        || value == ".."
        || bytes.first() == Some(&b'-')
        || bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(AgentConfigError::new(format!("{field} is invalid")));
    }

    let body = value.strip_suffix('$').unwrap_or(value);
    if body.is_empty()
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AgentConfigError::new(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_account_field(
    value: &str,
    field: &str,
    reject_colon: bool,
) -> Result<(), AgentConfigError> {
    if value.contains(['\0', '\n', '\r']) || (reject_colon && value.contains(':')) {
        return Err(AgentConfigError::new(format!(
            "{field} contains a character that cannot be serialized safely"
        )));
    }
    Ok(())
}

fn validate_absolute_path(value: &str, field: &str) -> Result<(), AgentConfigError> {
    validate_nonempty(value, field)?;
    if !value.starts_with('/') || value.split('/').any(|part| matches!(part, "." | "..")) {
        return Err(AgentConfigError::new(format!(
            "{field} must be an absolute normalized path"
        )));
    }
    Ok(())
}

fn validate_unique_nonempty<'a>(
    values: impl IntoIterator<Item = &'a str>,
    field: &str,
) -> Result<(), AgentConfigError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        validate_nonempty(value, field)?;
        if !seen.insert(value) {
            return Err(AgentConfigError::new(format!("{field} must be unique")));
        }
    }
    Ok(())
}

fn validate_network_config(network: &NetworkConfig) -> Result<(), AgentConfigError> {
    if network.interfaces.len() != 1 {
        return Err(AgentConfigError::new(
            "provision.network must contain exactly one interface",
        ));
    }

    let interface = &network.interfaces[0];
    let mac = parse_mac_address(&interface.mac_address)?;
    if mac.iter().all(|byte| *byte == 0) || mac[0] & 1 != 0 {
        return Err(AgentConfigError::new(
            "provision.network interface MAC address must be nonzero unicast",
        ));
    }

    let ipv4 = &interface.ipv4;
    if !(1..=30).contains(&ipv4.prefix_length) {
        return Err(AgentConfigError::new(
            "provision.network IPv4 prefix_length must be between 1 and 30",
        ));
    }
    validate_usable_ipv4(ipv4.address, "provision.network IPv4 address")?;
    validate_usable_ipv4(ipv4.gateway, "provision.network IPv4 gateway")?;
    if ipv4.address == ipv4.gateway {
        return Err(AgentConfigError::new(
            "provision.network IPv4 address and gateway must differ",
        ));
    }
    let mask = u32::MAX << (32 - ipv4.prefix_length);
    if u32::from(ipv4.address) & mask != u32::from(ipv4.gateway) & mask {
        return Err(AgentConfigError::new(
            "provision.network IPv4 address and gateway must share a subnet",
        ));
    }

    if interface.dns.servers.is_empty() {
        return Err(AgentConfigError::new(
            "provision.network DNS requires at least one server",
        ));
    }
    for domain in &interface.dns.search {
        validate_nonempty(domain, "provision.network DNS search domain")?;
        if domain.len() > 253
            || domain
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(AgentConfigError::new(
                "provision.network DNS search domain is invalid",
            ));
        }
    }

    Ok(())
}

fn parse_mac_address(value: &str) -> Result<[u8; 6], AgentConfigError> {
    let mut mac = [0_u8; 6];
    let mut parts = value.split(':');
    for byte in &mut mac {
        let part = parts.next().ok_or_else(|| {
            AgentConfigError::new("provision.network interface MAC address is invalid")
        })?;
        if part.len() != 2 {
            return Err(AgentConfigError::new(
                "provision.network interface MAC address is invalid",
            ));
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_| {
            AgentConfigError::new("provision.network interface MAC address is invalid")
        })?;
    }
    if parts.next().is_some() {
        return Err(AgentConfigError::new(
            "provision.network interface MAC address is invalid",
        ));
    }
    Ok(mac)
}

fn validate_usable_ipv4(address: Ipv4Addr, field: &str) -> Result<(), AgentConfigError> {
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
    {
        return Err(AgentConfigError::new(format!(
            "{field} must be a usable unicast address"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentSshConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_ca: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ProvisionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default)]
    pub resize_rootfs: ResizeRootfsConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_authority: Option<CertificateAuthorityConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userdata: Option<UserdataConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ResizeRootfsConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
    pub sudo: String,
    #[serde(default)]
    pub lock_passwd: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertificateAuthorityConfig {
    pub path: String,
    pub pem: String,
    #[serde(default)]
    pub update_trust: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub interfaces: Vec<NetworkInterfaceConfig>,
}

impl NetworkConfig {
    /// Validate the single managed IPv4 attachment for provisioning or activation.
    pub fn validate(&self) -> Result<(), AgentConfigError> {
        validate_network_config(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    pub mac_address: String,
    pub ipv4: NetworkIpv4Config,
    pub dns: NetworkDnsConfig,
}

impl NetworkInterfaceConfig {
    /// Parse the configured Ethernet address without changing its byte order.
    pub fn mac_address_bytes(&self) -> Result<[u8; 6], AgentConfigError> {
        parse_mac_address(&self.mac_address)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkIpv4Config {
    pub address: Ipv4Addr,
    pub prefix_length: u8,
    pub gateway: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkDnsConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MountConfig {
    pub tag: String,
    pub path: String,
    pub fstype: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

/// A mount with a normalized target, ordered before any child target.
#[derive(Debug)]
pub struct PlannedMount<'a> {
    pub config: &'a MountConfig,
    pub target: String,
}

/// Validates the complete plan without touching the guest filesystem.
pub fn normalized_mount_plan(
    mounts: &[MountConfig],
) -> Result<Vec<PlannedMount<'_>>, AgentConfigError> {
    validate_unique_nonempty(mounts.iter().map(|mount| mount.tag.as_str()), "mount tag")?;
    if mounts
        .iter()
        .any(|mount| mount.tag == rootfs_spec::rosetta::SHARE_TAG)
    {
        return Err(AgentConfigError::new(format!(
            "mount tag {:?} is reserved for the init-owned Rosetta share",
            rootfs_spec::rosetta::SHARE_TAG
        )));
    }
    let mut plan = Vec::with_capacity(mounts.len());
    for mount in mounts {
        validate_nonempty(&mount.fstype, "mount fstype")?;
        if mount.fstype != "virtiofs" {
            return Err(AgentConfigError::new(
                "user mount plans support only directory virtiofs shares",
            ));
        }
        validate_unique_nonempty(mount.options.iter().map(String::as_str), "mount option")?;
        if mount.options.iter().any(|option| {
            !matches!(
                option.as_str(),
                "ro" | "rw" | "nofail" | "nosuid" | "nodev" | "noexec"
            )
        }) || (mount.options.iter().any(|option| option == "ro")
            && mount.options.iter().any(|option| option == "rw"))
        {
            return Err(AgentConfigError::new(
                "mount options must select unambiguous virtiofs access and fixed VFS flags",
            ));
        }
        if mount.tag.contains('\0')
            || mount.fstype.contains('\0')
            || mount.options.iter().any(|option| option.contains('\0'))
        {
            return Err(AgentConfigError::new("mount fields must not contain NUL"));
        }
        let target = normalize_mount_target(&mount.path)?;
        plan.push(PlannedMount {
            config: mount,
            target,
        });
    }
    plan.sort_by(|left, right| {
        left.target
            .split('/')
            .count()
            .cmp(&right.target.split('/').count())
            .then_with(|| left.target.cmp(&right.target))
    });
    if plan.windows(2).any(|pair| pair[0].target == pair[1].target) {
        return Err(AgentConfigError::new(
            "normalized mount targets must be unique",
        ));
    }
    Ok(plan)
}

fn normalize_mount_target(value: &str) -> Result<String, AgentConfigError> {
    if !value.starts_with('/') || value.contains('\0') || value.split('/').any(|part| part == "..")
    {
        return Err(AgentConfigError::new(
            "mount target must be absolute without traversal or NUL",
        ));
    }
    let mut target = String::new();
    for part in value
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        target.push('/');
        target.push_str(part);
    }
    if target.is_empty() || paths_overlap(&target, "/run/silo") {
        return Err(AgentConfigError::new(
            "mount target hides protected root maintenance state",
        ));
    }
    Ok(target)
}

fn paths_overlap(left: &str, right: &str) -> bool {
    fn ancestor(parent: &str, child: &str) -> bool {
        child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
    }
    ancestor(left, right) || ancestor(right, left)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserdataConfig {
    pub content: String,
    #[serde(default)]
    pub content_type: UserdataContentType,
    #[serde(default)]
    pub run: UserdataRunPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserdataContentType {
    #[default]
    ShellScript,
    CloudConfig,
    PlainText,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserdataRunPolicy {
    #[default]
    Once,
    Always,
}

#[cfg(test)]
mod tests {
    use crate::{
        AgentConfig, AgentSshConfig, CertificateAuthorityConfig, MountConfig, NetworkConfig,
        NetworkDnsConfig, NetworkInterfaceConfig, NetworkIpv4Config, ProvisionConfig,
        ResizeRootfsConfig, UserConfig, UserdataConfig, UserdataContentType, UserdataRunPolicy,
    };

    fn launch_config() -> AgentConfig {
        AgentConfig {
            storage_shutdown: protocol::shutdown::StorageShutdownContext {
                version: 1,
                machine_id: "11111111-1111-4111-8111-111111111111".into(),
                run_id: "22222222-2222-4222-8222-222222222222".into(),
                manifest: protocol::shutdown::StorageManifest::Unsupported {
                    reason: "unit fixture has no storage attachments".into(),
                },
            },
            ..AgentConfig::default()
        }
    }

    #[test]
    fn launch_identity_is_required_and_not_defaulted() {
        assert!(serde_json::from_str::<AgentConfig>("{}").is_err());
        assert!(AgentConfig::default().validate().is_err());
        let mut config = launch_config();
        config.validate().unwrap();
        config.storage_shutdown.run_id = "00000000-0000-0000-0000-000000000000".into();
        assert!(config.validate().is_err());
        let duplicate = r#"{"storage_shutdown":{"version":1,"version":1,"machineId":"11111111-1111-4111-8111-111111111111","runId":"22222222-2222-4222-8222-222222222222","manifest":{"kind":"unsupported","reason":"fixture"}}}"#;
        assert!(serde_json::from_str::<AgentConfig>(duplicate).is_err());
    }

    fn mount_config(tag: &str, path: &str) -> MountConfig {
        MountConfig {
            tag: tag.to_string(),
            path: path.to_string(),
            fstype: "virtiofs".to_string(),
            options: Vec::new(),
        }
    }

    #[test]
    fn mount_plan_accepts_only_directory_virtiofs_operations() {
        for option in ["bind", "rbind", "move", "remount", "ro,rw", "size=1M"] {
            let mut mount = mount_config("share", "/workspace");
            mount.options.push(option.to_string());
            assert!(crate::normalized_mount_plan(&[mount]).is_err(), "{option}");
        }
        let mut mount = mount_config("share", "/workspace");
        mount.options = vec!["ro".to_string(), "rw".to_string()];
        assert!(crate::normalized_mount_plan(&[mount]).is_err());
        let mut mount = mount_config("share", "/workspace");
        mount.fstype = "ext4".to_string();
        assert!(crate::normalized_mount_plan(&[mount]).is_err());
        let mut mount = mount_config("share", "/workspace");
        mount.options = ["ro", "nofail", "nosuid", "nodev", "noexec"]
            .map(str::to_string)
            .to_vec();
        assert!(crate::normalized_mount_plan(&[mount]).is_ok());
    }

    #[test]
    fn mount_plan_normalizes_and_orders_parents_before_children() {
        let mounts = [
            mount_config("child", "/workspace//./child/"),
            mount_config("parent", "/workspace/"),
            mount_config("other", "/other"),
        ];
        let plan = crate::normalized_mount_plan(&mounts).expect("valid plan");
        let targets: Vec<_> = plan.iter().map(|mount| mount.target.as_str()).collect();
        assert_eq!(targets, ["/other", "/workspace", "/workspace/child"]);
    }

    #[test]
    fn mount_plan_rejects_normalized_duplicates_and_traversal() {
        assert!(crate::normalized_mount_plan(&[
            mount_config("a", "/work"),
            mount_config("b", "//work/./")
        ])
        .is_err());
        for target in [
            "relative",
            "/work/../other",
            "/work/../../run",
            "/nul\0path",
        ] {
            assert!(
                crate::normalized_mount_plan(&[mount_config("a", target)]).is_err(),
                "{target:?}"
            );
        }
    }

    #[test]
    fn mount_plan_protects_root_maintenance_ancestors_and_descendants() {
        for target in [
            "/",
            "//./",
            "/run",
            "/run/",
            "/run/silo",
            "/run//silo/./rootfs",
            "/run/silo/rootfs/upperfs",
        ] {
            assert!(
                crate::normalized_mount_plan(&[mount_config("a", target)]).is_err(),
                "{target:?}"
            );
        }
        for target in ["/run/other", "/runner", "/run/silophone", "/tmp"] {
            assert!(
                crate::normalized_mount_plan(&[mount_config("a", target)]).is_ok(),
                "{target:?}"
            );
        }
    }

    #[test]
    fn mount_plan_validation_applies_even_when_provisioning_is_disabled() {
        let mut config = AgentConfig::default();
        config
            .provision
            .mounts
            .push(mount_config("hidden-state", "/run"));
        assert!(config.validate().is_err());
    }

    #[test]
    fn mount_plan_cannot_hide_the_init_owned_rosetta_mount() {
        for target in [
            "/run/silo/rosetta",
            "/run//silo/rosetta/./",
            "/run/silo/rosetta/child",
        ] {
            assert!(
                crate::normalized_mount_plan(&[mount_config("other", target)]).is_err(),
                "{target:?}"
            );
        }
        assert!(rootfs_spec::rosetta::MOUNT_PATH.starts_with("/run/silo/"));
    }

    #[test]
    fn rosetta_share_tag_is_reserved_without_any_agent_setting() {
        let mut config = AgentConfig::default();
        config.provision.mounts.push(MountConfig {
            tag: rootfs_spec::rosetta::SHARE_TAG.to_string(),
            path: "/workspace".to_string(),
            fstype: "virtiofs".to_string(),
            options: Vec::new(),
        });
        let error = config.validate().expect_err("reject reserved mount tag");
        assert!(error
            .to_string()
            .contains("reserved for the init-owned Rosetta share"));
        config.provision.enabled = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn agent_configuration_has_no_rosetta_setting() {
        let raw = r#"
storage_shutdown:
  version: 1
  machineId: 11111111-1111-4111-8111-111111111111
  runId: 22222222-2222-4222-8222-222222222222
  manifest: {kind: unsupported, reason: fixture}
provision:
  enabled: true
  rosetta:
    enabled: true
"#;
        assert!(serde_yaml_ng::from_str::<AgentConfig>(raw).is_err());
        assert!(
            serde_json::to_value(AgentConfig::default()).expect("encode")["provision"]
                .get("rosetta")
                .is_none()
        );
    }

    #[test]
    fn guest_cache_reclaim_is_not_a_config_option() {
        let config = launch_config();
        config.validate().expect("valid launch");
        assert!(serde_json::to_value(config)
            .expect("encode")
            .get("memory_reclaim")
            .is_none());
        assert!(
            serde_json::from_str::<AgentConfig>(r#"{"memory_reclaim":{"mode":"off"}}"#).is_err()
        );
    }

    #[test]
    fn provision_config_defaults_are_safe() {
        let config = AgentConfig::default();

        assert!(!config.provision.enabled);
        assert!(!config.provision.resize_rootfs.enabled);
        assert!(config.provision.users.is_empty());
        assert!(config.provision.network.is_none());
        assert!(config.ssh.trusted_ca.is_none());
    }

    #[test]
    fn provision_config_deserializes_unprefixed_shape() {
        let raw = r#"
storage_shutdown:
  version: 1
  machineId: 11111111-1111-4111-8111-111111111111
  runId: 22222222-2222-4222-8222-222222222222
  manifest: {kind: unsupported, reason: fixture}
provision:
  enabled: true
  hostname: demo
  resize_rootfs:
    enabled: true
  userdata:
    content: |
      #!/bin/sh
      echo hello
    content_type: shell_script
    run: always
"#;

        let config: AgentConfig = serde_yaml_ng::from_str(raw).expect("decode agent config");

        assert!(config.provision.enabled);
        assert_eq!(config.provision.hostname.as_deref(), Some("demo"));
        assert!(config.provision.resize_rootfs.enabled);
        let userdata = config.provision.userdata.expect("userdata");
        assert_eq!(userdata.content_type, UserdataContentType::ShellScript);
        assert_eq!(userdata.run, UserdataRunPolicy::Always);
    }

    #[test]
    fn userdata_run_defaults_to_once() {
        let raw = r#"
storage_shutdown:
  version: 1
  machineId: 11111111-1111-4111-8111-111111111111
  runId: 22222222-2222-4222-8222-222222222222
  manifest: {kind: unsupported, reason: fixture}
provision:
  enabled: true
  userdata:
    content: |
      #!/bin/sh
      echo hello
    content_type: shell_script
"#;

        let config: AgentConfig = serde_yaml_ng::from_str(raw).expect("decode agent config");
        let userdata = config.provision.userdata.expect("userdata");

        assert_eq!(userdata.run, UserdataRunPolicy::Once);
    }

    #[test]
    fn agent_config_round_trips_through_json() {
        let original = AgentConfig {
            storage_shutdown: launch_config().storage_shutdown,
            provision: ProvisionConfig {
                enabled: true,
                hostname: Some("demo".to_string()),
                timezone: Some("UTC".to_string()),
                locale: Some("en_US.UTF-8".to_string()),
                resize_rootfs: ResizeRootfsConfig { enabled: true },
                users: vec![UserConfig {
                    name: "silo".to_string(),
                    uid: u32::MAX,
                    gid: 2000,
                    gecos: "Silo User".to_string(),
                    home: "/home/silo".to_string(),
                    shell: "/bin/bash".to_string(),
                    sudo: "ALL=(ALL) NOPASSWD:ALL".to_string(),
                    lock_passwd: true,
                }],
                certificate_authority: Some(CertificateAuthorityConfig {
                    path: "/usr/local/share/ca-certificates/silo-ca.crt".to_string(),
                    pem: "-----BEGIN CERTIFICATE-----\nMIISILO\n-----END CERTIFICATE-----\n"
                        .to_string(),
                    update_trust: true,
                }),
                network: Some(NetworkConfig {
                    interfaces: vec![NetworkInterfaceConfig {
                        mac_address: "02:00:00:00:00:01".to_string(),
                        ipv4: NetworkIpv4Config {
                            address: "192.168.105.2".parse().expect("IPv4 address"),
                            prefix_length: 24,
                            gateway: "192.168.105.1".parse().expect("IPv4 gateway"),
                        },
                        dns: NetworkDnsConfig {
                            servers: vec!["192.168.105.1".parse().expect("DNS server")],
                            search: Vec::new(),
                        },
                    }],
                }),
                mounts: vec![MountConfig {
                    tag: "workspace".to_string(),
                    path: "/workspace".to_string(),
                    fstype: "virtiofs".to_string(),
                    options: vec!["rw".to_string(), "nofail".to_string()],
                }],
                userdata: Some(UserdataConfig {
                    content: "#!/bin/sh\necho hello\n".to_string(),
                    content_type: UserdataContentType::ShellScript,
                    run: UserdataRunPolicy::Always,
                }),
            },
            ssh: AgentSshConfig {
                trusted_ca: Some(
                    ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(
                        &[1; 32],
                    ))
                    .public_key()
                    .to_openssh()
                    .unwrap(),
                ),
            },
        };

        let encoded = serde_json::to_vec(&original).expect("serialize agent config");
        let round_tripped: AgentConfig =
            serde_json::from_slice(&encoded).expect("deserialize agent config");

        assert_eq!(round_tripped, original);
    }

    #[test]
    fn validation_accepts_supported_login_names() {
        for name in ["silo", "silo-user", "Silo_2", "machine$"] {
            let config = config_with_user(name);
            config.validate().expect("login name should be valid");
        }
    }

    #[test]
    fn ssh_trust_requires_a_parsed_ed25519_public_key() {
        let mut config = launch_config();
        for invalid in ["", "ssh-ed25519 broken", "ssh-rsa broken", "not a key"] {
            config.ssh.trusted_ca = Some(invalid.into());
            assert!(config.validate().is_err());
        }
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]));
        config.ssh.trusted_ca = Some(key.public_key().to_openssh().unwrap());
        config.validate().unwrap();
        assert!(serde_json::from_str::<AgentSshConfig>(r#"{"authorized_users":[]}"#).is_err());
    }

    #[test]
    fn validation_rejects_invalid_login_names() {
        for name in [
            "",
            "-silo",
            "1234",
            ".",
            "..",
            "silo.user",
            "silo:name",
            "silo\nroot",
        ] {
            let error = config_with_user(name)
                .validate()
                .expect_err("login name must fail")
                .to_string();
            assert!(error.contains("provision user name"));
        }
    }

    #[test]
    fn validation_rejects_account_database_and_sudoers_injection() {
        for update in [
            |user: &mut UserConfig| user.gecos = "Silo:/root:/bin/sh".to_string(),
            |user: &mut UserConfig| user.home = "/home/silo\nroot".to_string(),
            |user: &mut UserConfig| user.shell = "/bin/sh:extra".to_string(),
            |user: &mut UserConfig| user.sudo = "ALL=(ALL) ALL\nroot ALL=(ALL) ALL".to_string(),
        ] {
            let mut config = config_with_user("silo");
            update(&mut config.provision.users[0]);
            config.validate().expect_err("injected field must fail");
        }
    }

    #[test]
    fn validation_rejects_reserved_user_gid() {
        let mut config = config_with_user("silo");
        config.provision.users[0].gid = u32::MAX;

        let error = config.validate().expect_err("reserved gid must fail");

        assert!(error.to_string().contains("gid"));
    }

    #[test]
    fn validation_accepts_absent_network() {
        launch_config()
            .validate()
            .expect("absent networking should be valid");
    }

    #[test]
    fn validation_rejects_empty_network() {
        let config = AgentConfig {
            provision: ProvisionConfig {
                network: Some(NetworkConfig::default()),
                ..ProvisionConfig::default()
            },
            ..AgentConfig::default()
        };

        let error = config.validate().expect_err("empty networking must fail");
        assert!(error.to_string().contains("exactly one interface"));
    }

    #[test]
    fn validation_rejects_gateway_outside_interface_subnet() {
        let config = AgentConfig {
            provision: ProvisionConfig {
                network: Some(NetworkConfig {
                    interfaces: vec![NetworkInterfaceConfig {
                        mac_address: "02:00:00:00:00:01".to_string(),
                        ipv4: NetworkIpv4Config {
                            address: "192.168.105.2".parse().expect("IPv4 address"),
                            prefix_length: 24,
                            gateway: "192.168.106.1".parse().expect("IPv4 gateway"),
                        },
                        dns: NetworkDnsConfig {
                            servers: vec!["192.168.105.1".parse().expect("DNS server")],
                            search: Vec::new(),
                        },
                    }],
                }),
                ..ProvisionConfig::default()
            },
            ..AgentConfig::default()
        };

        let error = config
            .validate()
            .expect_err("gateway outside subnet must fail");
        assert!(error.to_string().contains("share a subnet"));
    }

    #[test]
    fn validation_rejects_invalid_network_mac_prefix_and_search_domain() {
        let mut network = valid_network_config();
        network.interfaces[0].mac_address = "01:00:00:00:00:01".to_string();
        assert!(network_error(network).contains("nonzero unicast"));

        let mut network = valid_network_config();
        network.interfaces[0].ipv4.prefix_length = 31;
        assert!(network_error(network).contains("between 1 and 30"));

        let mut network = valid_network_config();
        network.interfaces[0].dns.search = vec!["bad domain".to_string()];
        assert!(network_error(network).contains("search domain is invalid"));
    }

    #[test]
    fn invalid_agent_config_parse_cases() {
        for (label, result, expected) in [
            (
                "removed_forward",
                serde_yaml_ng::from_str::<AgentConfig>("forward:\n  enabled: true\n  port: 4000\n")
                    .map_err(|err| err.to_string()),
                Some("unknown field `forward`"),
            ),
            (
                "non_ip_dns_server",
                serde_json::from_str::<AgentConfig>(
                    r#"{
            "provision": {
                "network": {
                    "interfaces": [{
                        "mac_address": "02:00:00:00:00:01",
                        "ipv4": {
                            "address": "192.168.105.2",
                            "prefix_length": 24,
                            "gateway": "192.168.105.1"
                        },
                        "dns": { "servers": ["not-an-ip"] }
                    }]
                }
            }
        }"#,
                )
                .map_err(|err| err.to_string()),
                None,
            ),
        ] {
            let message = result.expect_err(label);
            if let Some(text) = expected {
                assert!(message.contains(text), "{label}: {message}");
            }
        }
    }

    fn valid_network_config() -> NetworkConfig {
        NetworkConfig {
            interfaces: vec![NetworkInterfaceConfig {
                mac_address: "02:00:00:00:00:01".to_string(),
                ipv4: NetworkIpv4Config {
                    address: "192.168.105.2".parse().expect("IPv4 address"),
                    prefix_length: 24,
                    gateway: "192.168.105.1".parse().expect("IPv4 gateway"),
                },
                dns: NetworkDnsConfig {
                    servers: vec!["192.168.105.1".parse().expect("DNS server")],
                    search: Vec::new(),
                },
            }],
        }
    }

    fn config_with_user(name: &str) -> AgentConfig {
        AgentConfig {
            provision: ProvisionConfig {
                users: vec![UserConfig {
                    name: name.to_string(),
                    uid: 2000,
                    gid: 2000,
                    gecos: "Silo User".to_string(),
                    home: "/home/silo".to_string(),
                    shell: "/bin/bash".to_string(),
                    sudo: "ALL=(ALL) NOPASSWD:ALL".to_string(),
                    lock_passwd: true,
                }],
                ..ProvisionConfig::default()
            },
            ..launch_config()
        }
    }

    fn network_error(network: NetworkConfig) -> String {
        AgentConfig {
            provision: ProvisionConfig {
                network: Some(network),
                ..ProvisionConfig::default()
            },
            ..AgentConfig::default()
        }
        .validate()
        .expect_err("network config must fail")
        .to_string()
    }
}
