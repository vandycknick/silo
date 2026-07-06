use serde::{Deserialize, Serialize};

/// Default guest readiness timeout used when agent integration is enabled.
pub const DEFAULT_AGENT_TIMEOUT_SECONDS: u64 = 60 * 5;

/// Default guest SSH vsock port exposed by the Silo agent.
pub const SSH_VSOCK_PORT: u32 = 22;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentConfig {
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
    "silo-rosetta".to_string()
}

fn default_rosetta_mount_path() -> String {
    "/mnt/silo-rosetta".to_string()
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
    use crate::{
        AgentConfig, AgentForwardConfig, AgentRosettaConfig, AgentUdsForwardConfig,
        CertificateAuthorityConfig, MountConfig, NetworkConfig, NetworkInterfaceConfig,
        NetworkMatchConfig, ProvisionConfig, ResizeRootfsConfig, UserConfig, UserdataConfig,
        UserdataContentType, UserdataRunPolicy,
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
    fn agent_config_round_trips_through_metadata_struct() {
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
                    gecos: "Silo User".to_string(),
                    home: "/home/silo".to_string(),
                    shell: "/bin/bash".to_string(),
                    sudo: "ALL=(ALL) NOPASSWD:ALL".to_string(),
                    lock_passwd: true,
                    ssh_authorized_keys: vec!["ssh-ed25519 AAAAC3NzaSilo".to_string()],
                }],
                certificate_authority: Some(CertificateAuthorityConfig {
                    path: "/usr/local/share/ca-certificates/silo-ca.crt".to_string(),
                    pem: "-----BEGIN CERTIFICATE-----\nMIISILO\n-----END CERTIFICATE-----\n"
                        .to_string(),
                    update_trust: true,
                }),
                network: NetworkConfig {
                    interfaces: vec![NetworkInterfaceConfig {
                        name: "silo".to_string(),
                        matches: NetworkMatchConfig {
                            driver: Some("virtio_net".to_string()),
                            mac_address: Some("02:00:00:00:00:01".to_string()),
                        },
                        dhcp4: true,
                        dhcp6: true,
                    }],
                },
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
        };

        let value = serde_json::to_value(&original).expect("serialize agent config");
        let encoded =
            protocol::serde_json_to_protobuf_struct(value).expect("encode metadata struct");
        let decoded =
            protocol::protobuf_struct_to_serde_json(encoded).expect("decode metadata struct");
        let round_tripped: AgentConfig =
            serde_json::from_value(decoded).expect("deserialize agent config");

        assert_eq!(round_tripped, original);
    }
}
