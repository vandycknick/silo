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
    pub forward: AgentForwardConfig,
    #[serde(default)]
    pub provision: ProvisionConfig,
    #[serde(default)]
    pub ssh: AgentSshConfig,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), AgentConfigError> {
        if self.forward.enabled && self.forward.port == 0 {
            return Err(AgentConfigError::new(
                "forward.port must be nonzero when enabled",
            ));
        }
        validate_unique_nonempty(
            self.forward
                .uds
                .iter()
                .map(|entry| entry.guest_path.as_str()),
            "forward.uds guest_path",
        )?;
        for entry in &self.forward.uds {
            validate_absolute_path(&entry.guest_path, "forward.uds guest_path")?;
        }

        validate_unique_nonempty(
            self.ssh
                .authorized_users
                .iter()
                .map(|user| user.name.as_str()),
            "ssh authorized user name",
        )?;
        for user in &self.ssh.authorized_users {
            validate_login_name(&user.name, "ssh authorized user name")?;
            if user.authorized_keys.iter().any(|key| key.trim().is_empty()) {
                return Err(AgentConfigError::new(
                    "ssh authorized key must not be empty",
                ));
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
            validate_network_config(network)?;
        }
        validate_unique_nonempty(
            self.provision.mounts.iter().map(|mount| mount.tag.as_str()),
            "mount tag",
        )?;
        for mount in &self.provision.mounts {
            validate_absolute_path(&mount.path, "mount path")?;
            validate_nonempty(&mount.fstype, "mount fstype")?;
        }
        if self.provision.rosetta.enabled {
            validate_nonempty(&self.provision.rosetta.mount_tag, "rosetta mount tag")?;
            validate_absolute_path(&self.provision.rosetta.mount_path, "rosetta mount path")?;
        }
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_users: Vec<AgentSshAuthorizedUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentSshAuthorizedUser {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_keys: Vec<String>,
    #[serde(default)]
    pub allow_without_auth: bool,
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
    #[serde(default)]
    pub rosetta: AgentRosettaConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentRosettaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rosetta_mount_tag")]
    pub mount_tag: String,
    #[serde(default = "default_rosetta_mount_path")]
    pub mount_path: String,
}

impl Default for AgentRosettaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mount_tag: default_rosetta_mount_tag(),
            mount_path: default_rosetta_mount_path(),
        }
    }
}

fn default_rosetta_mount_tag() -> String {
    "silo-rosetta".to_string()
}

fn default_rosetta_mount_path() -> String {
    "/mnt/silo-rosetta".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    pub mac_address: String,
    pub ipv4: NetworkIpv4Config,
    pub dns: NetworkDnsConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentForwardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub port: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uds: Vec<AgentUdsForwardConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentUdsForwardConfig {
    pub guest_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ForwardStreamRequest {
    Api { request: ForwardApiRequest },
    Tcp { guest_port: u16 },
    Uds { guest_path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ForwardApiRequest {
    ListTcpPorts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ForwardApiResponse {
    TcpPorts { ports: Vec<u16> },
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use crate::{
        AgentConfig, AgentForwardConfig, AgentRosettaConfig, AgentSshAuthorizedUser,
        AgentSshConfig, AgentUdsForwardConfig, CertificateAuthorityConfig, MountConfig,
        NetworkConfig, NetworkDnsConfig, NetworkInterfaceConfig, NetworkIpv4Config,
        ProvisionConfig, ResizeRootfsConfig, UserConfig, UserdataConfig, UserdataContentType,
        UserdataRunPolicy,
    };

    #[test]
    fn provision_config_defaults_are_safe() {
        let config = AgentConfig::default();

        assert!(!config.provision.enabled);
        assert!(!config.provision.resize_rootfs.enabled);
        assert!(!config.provision.rosetta.enabled);
        assert_eq!(config.provision.rosetta.mount_tag, "silo-rosetta");
        assert_eq!(config.provision.rosetta.mount_path, "/mnt/silo-rosetta");
        assert!(config.provision.users.is_empty());
        assert!(config.provision.network.is_none());
        assert!(config.ssh.authorized_users.is_empty());
    }

    #[test]
    fn provision_config_deserializes_unprefixed_shape() {
        let raw = r#"
provision:
  enabled: true
  hostname: demo
  resize_rootfs:
    enabled: true
  rosetta:
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
        assert!(config.provision.rosetta.enabled);
        assert_eq!(config.provision.rosetta.mount_tag, "silo-rosetta");
        assert_eq!(config.provision.rosetta.mount_path, "/mnt/silo-rosetta");
        let userdata = config.provision.userdata.expect("userdata");
        assert_eq!(userdata.content_type, UserdataContentType::ShellScript);
        assert_eq!(userdata.run, UserdataRunPolicy::Always);
    }

    #[test]
    fn userdata_run_defaults_to_once() {
        let raw = r#"
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
            forward: AgentForwardConfig {
                enabled: true,
                port: 65_535,
                uds: vec![AgentUdsForwardConfig {
                    guest_path: "/var/run/docker.sock".to_string(),
                }],
            },
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
                rosetta: AgentRosettaConfig {
                    enabled: true,
                    ..AgentRosettaConfig::default()
                },
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
                authorized_users: vec![AgentSshAuthorizedUser {
                    name: "silo".to_string(),
                    authorized_keys: vec!["ssh-ed25519 AAAAC3NzaSilo".to_string()],
                    allow_without_auth: false,
                }],
            },
        };

        let encoded = serde_json::to_vec(&original).expect("serialize agent config");
        let round_tripped: AgentConfig =
            serde_json::from_slice(&encoded).expect("deserialize agent config");

        assert_eq!(round_tripped, original);
    }

    #[test]
    fn validation_rejects_enabled_forward_without_port() {
        let config = AgentConfig {
            forward: AgentForwardConfig {
                enabled: true,
                ..AgentForwardConfig::default()
            },
            ..AgentConfig::default()
        };

        let error = config.validate().expect_err("invalid forward config");

        assert!(error.to_string().contains("forward.port"));
    }

    #[test]
    fn validation_accepts_supported_login_names() {
        for name in ["silo", "silo-user", "Silo_2", "machine$"] {
            let mut config = config_with_user(name);
            config.ssh.authorized_users.push(AgentSshAuthorizedUser {
                name: name.to_string(),
                authorized_keys: vec!["ssh-ed25519 AAAAC3NzaSilo".to_string()],
                allow_without_auth: false,
            });
            config.validate().expect("login name should be valid");
        }
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
        AgentConfig::default()
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
    fn deserialization_rejects_non_ip_dns_server() {
        let json = r#"{
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
        }"#;

        serde_json::from_str::<AgentConfig>(json).expect_err("invalid DNS server must fail");
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
            ..AgentConfig::default()
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
