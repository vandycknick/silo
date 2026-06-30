use std::collections::BTreeMap;
use std::path::PathBuf;

use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level Bento virtual machine specification.
///
/// This type is intentionally permissive for persistence: sections may be
/// absent and are resolved by the runtime boundary that launches the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSpec {
    /// Semantic version of the VM specification format.
    pub spec_version: Version,
    /// Guest operating system information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<Guest>,
    /// Boot-time kernel and userdata configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot: Option<Boot>,
    /// Virtual hardware sizing and hardware feature switches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware: Option<Hardware>,
    /// Ordered disk attachments visible to the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<Storage>,
    /// Host directories mounted into the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    /// Vsock endpoints supervised alongside the VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vsock: Option<Vsock>,
    /// Free-form metadata for callers that need non-standard annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl VmSpec {
    /// Create a minimal spec at the current schema version.
    pub fn current() -> Self {
        Self {
            spec_version: Version::new(0, 1, 0),
            guest: None,
            boot: None,
            hardware: None,
            storage: None,
            mounts: Vec::new(),
            vsock: None,
            annotations: BTreeMap::new(),
        }
    }
}

/// Guest operating system configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Guest {
    /// Operating system expected inside the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<GuestOs>,
}

/// Supported guest operating systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestOs {
    /// Linux guest operating system.
    Linux,
}

/// Boot configuration supplied to the hypervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Boot {
    /// Kernel image and related boot arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<Kernel>,
    /// Optional host-provided userdata content for guest provisioning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userdata: Option<String>,
}

/// Kernel image configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Kernel {
    /// Path to the kernel image on the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Linux kernel command-line arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmdline: Vec<String>,
    /// Optional initramfs image path on the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initramfs: Option<PathBuf>,
}

/// Virtual hardware configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hardware {
    /// Number of virtual CPUs assigned to the VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u8>,
    /// Guest memory size in MiB, using binary mebibytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<u32>,
    /// Enables nested virtualization when supported by the backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested_virtualization: Option<bool>,
    /// Enables Rosetta integration for supported guests and hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rosetta: Option<bool>,
}

/// Ordered disk attachments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Storage {
    /// Disk images attached to the VM in device order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<Disk>,
}

/// Disk image attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Disk {
    /// Path to the disk image on the host.
    pub path: PathBuf,
    /// Mount the disk read-only when supported by the backend.
    #[serde(default)]
    pub read_only: bool,
}

/// Host directory mount exposed to the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mount {
    /// Host path to share with the guest.
    pub source: PathBuf,
    /// Guest mount tag used by the virtualization backend.
    pub tag: String,
    /// Mount the share read-only.
    #[serde(default)]
    pub read_only: bool,
}

/// Vsock endpoint collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vsock {
    /// Endpoints supervised for this VM.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<VsockEndpoint>,
}

/// A host-side service bound to a guest vsock port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VsockEndpoint {
    /// Stable endpoint name.
    pub name: String,
    /// Guest vsock port number.
    pub port: u32,
    /// Direction of the vsock connection from the plugin perspective.
    pub mode: VsockEndpointMode,
    /// Plugin process that implements the endpoint.
    pub plugin: Plugin,
    /// Process lifecycle policy for the plugin.
    #[serde(default)]
    pub lifecycle: Lifecycle,
}

/// Vsock endpoint connection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VsockEndpointMode {
    /// Plugin connects to a listening guest service.
    Connect,
    /// Plugin listens for guest connections.
    Listen,
}

/// Host plugin process definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plugin {
    /// Command to execute for the plugin process.
    pub command: PathBuf,
    /// Command-line arguments passed to the plugin.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Environment variables added for the plugin process.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Optional working directory for the plugin process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<PathBuf>,
    /// Plugin-specific JSON configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
}

/// Supervision policy for a plugin process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lifecycle {
    /// Start the plugin automatically with the VM.
    pub autostart: bool,
    /// Startup timeout in milliseconds.
    pub startup_timeout_ms: u64,
    /// Restart behavior when the process exits.
    #[serde(default)]
    pub restart: RestartPolicy,
    /// Restart backoff timing in milliseconds.
    #[serde(default)]
    pub backoff_ms: Backoff,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            autostart: true,
            startup_timeout_ms: 5_000,
            restart: RestartPolicy::default(),
            backoff_ms: Backoff::default(),
        }
    }
}

/// Plugin restart policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Never restart the plugin.
    Never,
    /// Restart when the plugin exits unsuccessfully.
    #[default]
    OnFailure,
    /// Restart after every plugin exit.
    Always,
}

/// Restart backoff timing in milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Backoff {
    /// Initial restart delay in milliseconds.
    pub initial: u64,
    /// Maximum restart delay in milliseconds.
    pub max: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: 200,
            max: 5_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde_json::json;

    use crate::{
        Backoff, Boot, Disk, Guest, GuestOs, Hardware, Kernel, Lifecycle, Mount, Plugin,
        RestartPolicy, Storage, VmSpec, Vsock, VsockEndpoint, VsockEndpointMode,
    };

    #[test]
    fn minimal_spec_serializes_without_empty_sections() {
        let spec = VmSpec::current();

        let value = serde_json::to_value(&spec).expect("serialize vm spec");

        assert_eq!(value, json!({ "specVersion": "0.1.0" }));
    }

    #[test]
    fn minimal_spec_deserializes_from_version_only() {
        let spec: VmSpec = serde_json::from_value(json!({
            "specVersion": "0.1.0"
        }))
        .expect("deserialize vm spec");

        assert_eq!(spec, VmSpec::current());
    }

    #[test]
    fn full_spec_uses_camel_case_json_fields() {
        let spec = VmSpec {
            guest: Some(Guest {
                os: Some(GuestOs::Linux),
            }),
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: Some(PathBuf::from("/kernel")),
                    cmdline: vec!["console=hvc0".to_string(), "panic=-1".to_string()],
                    initramfs: Some(PathBuf::from("/initramfs")),
                }),
                userdata: Some("#!/bin/sh\necho booted\n".to_string()),
            }),
            hardware: Some(Hardware {
                cpus: Some(4),
                memory: Some(4096),
                nested_virtualization: Some(false),
                rosetta: Some(true),
            }),
            storage: Some(Storage {
                disks: vec![Disk {
                    path: PathBuf::from("/data.img"),
                    read_only: true,
                }],
            }),
            mounts: vec![Mount {
                source: PathBuf::from("/workspace"),
                tag: "workspace".to_string(),
                read_only: false,
            }],
            vsock: Some(Vsock {
                endpoints: vec![VsockEndpoint {
                    name: "api".to_string(),
                    port: 8080,
                    mode: VsockEndpointMode::Connect,
                    plugin: Plugin {
                        command: PathBuf::from("/usr/local/bin/bento-endpoint"),
                        args: vec!["--serve".to_string()],
                        env: BTreeMap::from([("RUST_LOG".to_string(), "info".to_string())]),
                        working_dir: Some(PathBuf::from("/tmp")),
                        config: None,
                    },
                    lifecycle: Lifecycle {
                        autostart: true,
                        startup_timeout_ms: 5_000,
                        restart: RestartPolicy::OnFailure,
                        backoff_ms: Backoff {
                            initial: 200,
                            max: 5_000,
                        },
                    },
                }],
            }),
            annotations: BTreeMap::from([("io.bentobox.demo".to_string(), "true".to_string())]),
            ..VmSpec::current()
        };

        let value = serde_json::to_value(&spec).expect("serialize vm spec");

        assert_eq!(
            value,
            json!({
                "specVersion": "0.1.0",
                "guest": { "os": "linux" },
                "boot": {
                    "kernel": {
                        "path": "/kernel",
                        "cmdline": ["console=hvc0", "panic=-1"],
                        "initramfs": "/initramfs"
                    },
                    "userdata": "#!/bin/sh\necho booted\n"
                },
                "hardware": {
                    "cpus": 4,
                    "memory": 4096,
                    "nestedVirtualization": false,
                    "rosetta": true
                },
                "storage": {
                    "disks": [
                        { "path": "/data.img", "readOnly": true }
                    ]
                },
                "mounts": [
                    { "source": "/workspace", "tag": "workspace", "readOnly": false }
                ],
                "vsock": {
                    "endpoints": [
                        {
                            "name": "api",
                            "port": 8080,
                            "mode": "connect",
                            "plugin": {
                                "command": "/usr/local/bin/bento-endpoint",
                                "args": ["--serve"],
                                "env": { "RUST_LOG": "info" },
                                "workingDir": "/tmp"
                            },
                            "lifecycle": {
                                "autostart": true,
                                "startupTimeoutMs": 5000,
                                "restart": "on_failure",
                                "backoffMs": { "initial": 200, "max": 5000 }
                            }
                        }
                    ]
                },
                "annotations": { "io.bentobox.demo": "true" }
            })
        );
    }

    #[test]
    fn serialization_omits_nulls_and_empty_collections() {
        let spec = VmSpec {
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: Some(PathBuf::from("/kernel")),
                    cmdline: Vec::new(),
                    initramfs: None,
                }),
                userdata: None,
            }),
            storage: Some(Storage { disks: Vec::new() }),
            ..VmSpec::current()
        };

        let encoded = serde_json::to_string(&spec).expect("serialize vm spec");

        assert!(!encoded.contains("null"));
        assert!(!encoded.contains("cmdline"));
        assert!(!encoded.contains("initramfs"));
        assert!(!encoded.contains("mounts"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).expect("decode json"),
            json!({
                "specVersion": "0.1.0",
                "boot": { "kernel": { "path": "/kernel" } },
                "storage": {}
            })
        );
    }
}
