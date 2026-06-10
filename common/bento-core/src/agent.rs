use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const DNS_RECORD_HOST_BENTO_INTERNAL: &str = "host.bento.internal";
pub const RESERVED_SHELL_PORT: u32 = 2000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentSshConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentDnsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dns_listen_address")]
    pub listen_address: IpAddr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream_servers: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<AgentDnsZone>,
}

impl Default for AgentDnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_dns_listen_address(),
            upstream_servers: Vec::new(),
            zones: Vec::new(),
        }
    }
}

fn default_dns_listen_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDnsZone {
    pub domain: String,
    #[serde(default)]
    pub authoritative: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<AgentDnsRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDnsRecord {
    pub name: String,
    #[serde(flatten)]
    pub value: AgentDnsRecordValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "UPPERCASE")]
pub enum AgentDnsRecordValue {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub ssh: AgentSshConfig,
    #[serde(default)]
    pub dns: AgentDnsConfig,
    #[serde(default)]
    pub forward: AgentForwardConfig,
    #[serde(default)]
    pub provision: ProvisionConfig,
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
    #[serde(default)]
    pub network: NetworkConfig,
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
    pub gecos: String,
    pub home: String,
    pub shell: String,
    pub sudo: String,
    #[serde(default)]
    pub lock_passwd: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_authorized_keys: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    "bento-rosetta".to_string()
}

fn default_rosetta_mount_path() -> String {
    "/mnt/bento-rosetta".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    pub name: String,
    #[serde(default)]
    pub matches: NetworkMatchConfig,
    #[serde(default)]
    pub dhcp4: bool,
    #[serde(default)]
    pub dhcp6: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkMatchConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
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
pub struct AgentForwardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub port: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uds: Vec<AgentUdsForwardConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    use crate::agent::{AgentConfig, UserdataContentType, UserdataRunPolicy};

    #[test]
    fn provision_config_defaults_are_safe() {
        let config = AgentConfig::default();

        assert!(!config.provision.enabled);
        assert!(!config.provision.resize_rootfs.enabled);
        assert!(!config.provision.rosetta.enabled);
        assert_eq!(config.provision.rosetta.mount_tag, "bento-rosetta");
        assert_eq!(config.provision.rosetta.mount_path, "/mnt/bento-rosetta");
        assert!(config.provision.users.is_empty());
        assert!(config.provision.network.interfaces.is_empty());
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
        assert_eq!(config.provision.rosetta.mount_tag, "bento-rosetta");
        assert_eq!(config.provision.rosetta.mount_path, "/mnt/bento-rosetta");
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
}
