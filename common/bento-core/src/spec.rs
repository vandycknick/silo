use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_GUEST_CONTROL_PORT: u32 = 1027;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmSpec {
    pub version: u32,
    pub name: String,
    pub platform: Platform,
    pub resources: Resources,
    pub boot: Boot,
    pub storage: Storage,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub vsock_endpoints: Vec<VsockEndpointSpec>,
    pub settings: Settings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<GuestSpec>,
}

impl VmSpec {
    pub fn guest_agent(&self) -> Option<GuestSpec> {
        self.guest.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestSpec {
    #[serde(default = "default_guest_control_port")]
    pub control_port: u32,
}

impl Default for GuestSpec {
    fn default() -> Self {
        Self {
            control_port: default_guest_control_port(),
        }
    }
}

const fn default_guest_control_port() -> u32 {
    DEFAULT_GUEST_CONTROL_PORT
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsockEndpointSpec {
    pub name: String,
    pub port: u32,
    pub mode: VsockEndpointMode,
    pub plugin: PluginSpec,
    #[serde(default)]
    pub lifecycle: LifecycleSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VsockEndpointMode {
    Connect,
    Listen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSpec {
    pub command: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleSpec {
    #[serde(default = "default_true")]
    pub autostart: bool,
    #[serde(default = "default_startup_timeout_ms")]
    pub startup_timeout_ms: u64,
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default)]
    pub backoff_ms: BackoffSpec,
}

impl Default for LifecycleSpec {
    fn default() -> Self {
        Self {
            autostart: default_true(),
            startup_timeout_ms: default_startup_timeout_ms(),
            restart: RestartPolicy::default(),
            backoff_ms: BackoffSpec::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    Never,
    #[default]
    OnFailure,
    Always,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackoffSpec {
    #[serde(default = "default_backoff_initial")]
    pub initial: u64,
    #[serde(default = "default_backoff_max")]
    pub max: u64,
}

impl Default for BackoffSpec {
    fn default() -> Self {
        Self {
            initial: default_backoff_initial(),
            max: default_backoff_max(),
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_startup_timeout_ms() -> u64 {
    5_000
}

const fn default_backoff_initial() -> u64 {
    200
}

const fn default_backoff_max() -> u64 {
    5_000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub guest_os: GuestOs,
    pub architecture: Architecture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    pub cpus: u8,
    pub memory_mib: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boot {
    pub kernel: Option<PathBuf>,
    pub initramfs: Option<PathBuf>,
    #[serde(default)]
    pub kernel_cmdline: Vec<String>,
    pub bootstrap: Option<Bootstrap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bootstrap {
    pub cloud_init: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Storage {
    #[serde(default)]
    pub disks: Vec<Disk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disk {
    pub path: PathBuf,
    pub kind: DiskKind,
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    Root,
    Data,
    Seed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    pub source: PathBuf,
    pub tag: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Network {
    None,
    VzNat {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac: Option<String>,
    },
    UnixDatagram {
        path: PathBuf,
        mac: String,
    },
    UnixStream {
        path: PathBuf,
        mac: String,
    },
    Tap {
        name: String,
        mac: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicySpec {
    pub default_action: PolicyAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<AuditLogSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidr_rules: Vec<CidrRuleSpec>,
}

impl NetworkPolicySpec {
    pub fn required_features(&self) -> std::collections::BTreeSet<NetworkPolicyFeature> {
        let mut features = std::collections::BTreeSet::new();
        if !self.cidr_rules.is_empty() {
            features.insert(NetworkPolicyFeature::CidrRules);
        }
        features
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogSpec {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CidrRuleSpec {
    pub name: String,
    pub action: PolicyAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<NetworkProtocol>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dest_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkPolicyFeature {
    CidrRules,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub nested_virtualization: bool,
    pub rosetta: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestOs {
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    Aarch64,
    X86_64,
}

#[cfg(test)]
mod tests {
    use super::{
        Architecture, BackoffSpec, Boot, Bootstrap, Disk, DiskKind, GuestOs, GuestSpec,
        LifecycleSpec, Mount, Platform, PluginSpec, Resources, RestartPolicy, Settings, Storage,
        VmSpec, VsockEndpointMode, VsockEndpointSpec,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn sample_vm_spec() -> VmSpec {
        VmSpec {
            version: 1,
            name: "dev".to_string(),
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: Architecture::Aarch64,
            },
            resources: Resources {
                cpus: 4,
                memory_mib: 4096,
            },
            boot: Boot {
                kernel: Some(PathBuf::from("/kernel")),
                initramfs: Some(PathBuf::from("/initramfs")),
                kernel_cmdline: vec!["console=hvc0".to_string(), "panic=-1".to_string()],
                bootstrap: Some(Bootstrap {
                    cloud_init: Some(PathBuf::from("/cloud-init/user-data")),
                }),
            },
            storage: Storage {
                disks: vec![
                    Disk {
                        path: PathBuf::from("/root.img"),
                        kind: DiskKind::Root,
                        read_only: false,
                    },
                    Disk {
                        path: PathBuf::from("/seed.img"),
                        kind: DiskKind::Seed,
                        read_only: true,
                    },
                ],
            },
            mounts: vec![Mount {
                source: PathBuf::from("/Users/nickvd/Projects/bentobox"),
                tag: "workspace".to_string(),
                read_only: false,
            }],
            vsock_endpoints: vec![VsockEndpointSpec {
                name: "api".to_string(),
                port: 8080,
                mode: VsockEndpointMode::Connect,
                plugin: PluginSpec {
                    command: PathBuf::from("/usr/local/bin/bento-endpoint"),
                    args: vec!["--serve".to_string()],
                    env: BTreeMap::from([("RUST_LOG".to_string(), "info".to_string())]),
                    working_dir: Some(PathBuf::from("/tmp")),
                    config: None,
                },
                lifecycle: LifecycleSpec {
                    autostart: true,
                    startup_timeout_ms: 5_000,
                    restart: RestartPolicy::OnFailure,
                    backoff_ms: BackoffSpec {
                        initial: 200,
                        max: 5_000,
                    },
                },
            }],
            settings: Settings {
                nested_virtualization: false,
                rosetta: true,
            },
            guest: Some(GuestSpec::default()),
        }
    }

    #[test]
    fn vm_spec_round_trips_through_yaml() {
        let spec = sample_vm_spec();
        let yaml = serde_yaml_ng::to_string(&spec).expect("serialize vm spec");
        let decoded: VmSpec = serde_yaml_ng::from_str(&yaml).expect("deserialize vm spec");

        assert_eq!(decoded, spec);
    }

    #[test]
    fn vm_spec_yaml_uses_snake_case_enums() {
        let yaml = serde_yaml_ng::to_string(&sample_vm_spec()).expect("serialize vm spec");

        assert!(yaml.contains("guest_os: linux"));
        assert!(yaml.contains("architecture: aarch64"));
        assert!(!yaml.contains("backend:"));
        assert!(yaml.contains("kind: root"));
        assert!(yaml.contains("kind: seed"));
        assert!(yaml.contains("vsock_endpoints:"));
        assert!(yaml.contains("guest:"));
        assert!(yaml.contains("control_port: 1027"));
        assert!(!yaml.contains("network:"));
        assert!(yaml.contains("mode: connect"));
        assert!(!yaml.contains("guest_enabled"));
    }

    #[test]
    fn vm_spec_defaults_missing_vsock_endpoints() {
        let yaml = r#"
version: 1
name: dev
platform:
  guest_os: linux
  architecture: aarch64
resources:
  cpus: 4
  memory_mib: 4096
boot:
  kernel: /kernel
  initramfs: /initramfs
  kernel_cmdline: []
  bootstrap:
    cloud_init: /cloud-init/user-data
storage:
  disks: []
mounts: []
settings:
  nested_virtualization: false
  rosetta: true
guest:
  control_port: 1027
"#;

        let decoded: VmSpec = serde_yaml_ng::from_str(yaml).expect("deserialize vm spec");
        assert!(decoded.vsock_endpoints.is_empty());
        assert_eq!(decoded.guest_agent(), Some(GuestSpec::default()));
    }

    #[test]
    fn vm_spec_rejects_legacy_guest_enabled_setting() {
        let yaml = r#"
version: 1
name: dev
platform:
  guest_os: linux
  architecture: aarch64
resources:
  cpus: 4
  memory_mib: 4096
boot:
  kernel: /kernel
  initramfs: /initramfs
  kernel_cmdline: []
  bootstrap: null
storage:
  disks: []
mounts: []
settings:
  nested_virtualization: false
  rosetta: true
  guest_enabled: true
"#;

        let err = serde_yaml_ng::from_str::<VmSpec>(yaml)
            .expect_err("legacy guest_enabled setting should be rejected");
        assert!(err.to_string().contains("guest_enabled"));
    }

    #[test]
    fn vm_spec_rejects_backend_field() {
        let yaml = r#"
version: 1
name: dev
platform:
  guest_os: linux
  architecture: aarch64
  backend: cloud_hypervisor
resources:
  cpus: 4
  memory_mib: 4096
boot:
  kernel: /kernel
  initramfs: /initramfs
  kernel_cmdline: []
  bootstrap: null
storage:
  disks: []
mounts: []
settings:
  nested_virtualization: false
  rosetta: true
guest:
  control_port: 1027
"#;

        let err = serde_yaml_ng::from_str::<VmSpec>(yaml)
            .expect_err("backend selection should be rejected");
        assert!(err.to_string().contains("backend"));
    }

    #[test]
    fn vm_spec_rejects_legacy_endpoints_field() {
        let yaml = r#"
version: 1
name: dev
platform:
  guest_os: linux
  architecture: aarch64
resources:
  cpus: 4
  memory_mib: 4096
boot:
  kernel: /kernel
  initramfs: /initramfs
  kernel_cmdline: []
  bootstrap: null
storage:
  disks: []
mounts: []
endpoints: []
settings:
  nested_virtualization: false
  rosetta: true
guest:
  control_port: 1027
"#;

        let err = serde_yaml_ng::from_str::<VmSpec>(yaml)
            .expect_err("legacy endpoints field should be rejected");
        assert!(err.to_string().contains("endpoints"));
    }
}
