use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use semver::Version;
use serde::de::{Error as _, IgnoredAny, MapAccess, Visitor};
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// Default filename for the public hybrid vsock mux.
pub const DEFAULT_VSOCK_MUX_FILENAME: &str = "vsock.sock";

/// Top-level Silo virtual machine specification.
///
/// This type is intentionally permissive for persistence: sections may be
/// absent and are resolved by the runtime boundary that launches the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// Machine-scoped forwards carried over vsock (ADR 0016).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<forward_spec::Forward>,
    /// Public hybrid vsock host surface.
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
            forwards: Vec::new(),
            vsock: None,
            annotations: BTreeMap::new(),
        }
    }

    /// Validate constraints that span VM specification sections.
    ///
    /// Call this before persisting a programmatically constructed or modified
    /// specification. Deserialization performs the same validation.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(vsock) = &self.vsock {
            vsock.validate().map_err(str::to_owned)?;
        }
        let mux_filename = effective_vsock_filename(self.vsock.as_ref()).and_then(Path::to_str);
        forward_spec::validate_forwards(&self.forwards, mux_filename)
            .map_err(|error| error.to_string())
    }
}

impl<'de> Deserialize<'de> for VmSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VmSpecVisitor)
    }
}

struct VmSpecVisitor;

impl<'de> Visitor<'de> for VmSpecVisitor {
    type Value = VmSpec;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a VM specification map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut spec_version = None;
        let mut guest = None;
        let mut boot = None;
        let mut hardware = None;
        let mut storage = None;
        let mut mounts = None;
        let mut forwards: Option<Vec<forward_spec::Forward>> = None;
        let mut vsock = None;
        let mut annotations = None;
        let mut removed_paths = Vec::new();

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "specVersion" => {
                    if spec_version.is_some() {
                        return Err(A::Error::duplicate_field("specVersion"));
                    }
                    spec_version = Some(map.next_value()?);
                }
                "guest" => {
                    if guest.is_some() {
                        return Err(A::Error::duplicate_field("guest"));
                    }
                    guest = Some(map.next_value()?);
                }
                "boot" => {
                    if boot.is_some() {
                        return Err(A::Error::duplicate_field("boot"));
                    }
                    boot = Some(map.next_value()?);
                }
                "hardware" => {
                    if hardware.is_some() {
                        return Err(A::Error::duplicate_field("hardware"));
                    }
                    hardware = Some(map.next_value()?);
                }
                "storage" => {
                    if storage.is_some() {
                        return Err(A::Error::duplicate_field("storage"));
                    }
                    storage = Some(map.next_value()?);
                }
                "mounts" => {
                    if mounts.is_some() {
                        return Err(A::Error::duplicate_field("mounts"));
                    }
                    mounts = Some(map.next_value()?);
                }
                "forwards" => {
                    if forwards.is_some() {
                        return Err(A::Error::duplicate_field("forwards"));
                    }
                    forwards = Some(map.next_value()?);
                }
                "vsock" => {
                    if vsock.is_some() {
                        return Err(A::Error::duplicate_field("vsock"));
                    }
                    let parsed = map.next_value::<Option<ParsedVsock>>()?;
                    if let Some(parsed) = &parsed {
                        removed_paths.extend(parsed.removed_paths.iter().cloned());
                    }
                    vsock = Some(parsed);
                }
                "annotations" => {
                    if annotations.is_some() {
                        return Err(A::Error::duplicate_field("annotations"));
                    }
                    annotations = Some(map.next_value()?);
                }
                "vsock_endpoints" | "vsockEndpoints" => {
                    let removed = map.next_value::<Value>()?;
                    removed_paths.push(field.clone());
                    collect_removed_paths(&removed, &field, &mut removed_paths);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        if !removed_paths.is_empty() {
            return Err(A::Error::custom(removed_fields_error(&removed_paths)));
        }

        let vsock = vsock.flatten();
        if let Some(parsed) = &vsock {
            if let Some(error) = parsed.validation_error {
                return Err(A::Error::custom(error));
            }
        }

        let forwards = forwards.unwrap_or_default();
        let mux_filename = effective_vsock_filename(vsock.as_ref().map(|parsed| &parsed.value))
            .and_then(Path::to_str);
        forward_spec::validate_forwards(&forwards, mux_filename).map_err(A::Error::custom)?;

        Ok(VmSpec {
            spec_version: spec_version.ok_or_else(|| A::Error::missing_field("specVersion"))?,
            guest: guest.flatten(),
            boot: boot.flatten(),
            hardware: hardware.flatten(),
            storage: storage.flatten(),
            mounts: mounts.unwrap_or_default(),
            forwards,
            vsock: vsock.map(|parsed| parsed.value),
            annotations: annotations.unwrap_or_default(),
        })
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

/// Public hybrid vsock host surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vsock {
    /// Expose the user-facing hybrid vsock Unix-socket surface.
    pub enabled: bool,
    /// Mux socket filename within the machine runtime directory.
    pub uds: Option<PathBuf>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VsockRef<'a> {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    uds: Option<&'a Path>,
}

impl Vsock {
    /// Validate the public vsock configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.enabled && self.uds.is_some() {
            return Err("vsock.uds cannot be configured while vsock.enabled is false");
        }

        if let Some(filename) = &self.uds {
            validate_vsock_filename(filename)?;
        }

        Ok(())
    }
}

impl Serialize for Vsock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(S::Error::custom)?;
        VsockRef {
            enabled: self.enabled,
            uds: self.uds.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Vsock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parsed = ParsedVsock::deserialize(deserializer)?;
        if !parsed.removed_paths.is_empty() {
            return Err(D::Error::custom(removed_fields_error(
                &parsed.removed_paths,
            )));
        }
        if let Some(error) = parsed.validation_error {
            return Err(D::Error::custom(error));
        }
        Ok(parsed.value)
    }
}

struct ParsedVsock {
    value: Vsock,
    removed_paths: Vec<String>,
    validation_error: Option<&'static str>,
}

impl<'de> Deserialize<'de> for ParsedVsock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VsockVisitor)
    }
}

struct VsockVisitor;

impl<'de> Visitor<'de> for VsockVisitor {
    type Value = ParsedVsock;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a vsock configuration map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut enabled = None;
        let mut uds = None;
        let mut removed_paths = Vec::new();

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "enabled" => {
                    if enabled.is_some() {
                        return Err(A::Error::duplicate_field("enabled"));
                    }
                    enabled = Some(map.next_value()?);
                }
                "uds" => {
                    if uds.is_some() {
                        return Err(A::Error::duplicate_field("uds"));
                    }
                    uds = Some(map.next_value()?);
                }
                "endpoints" | "plugin" | "lifecycle" => {
                    let removed = map.next_value::<Value>()?;
                    let path = format!("vsock.{field}");
                    removed_paths.push(path.clone());
                    collect_removed_paths(&removed, &path, &mut removed_paths);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        let value = Vsock {
            enabled: enabled.unwrap_or_default(),
            uds: uds.flatten(),
        };
        let validation_error = value.validate().err();
        Ok(ParsedVsock {
            value,
            removed_paths,
            validation_error,
        })
    }
}

/// Return whether the public vsock surface is effectively enabled.
pub fn effective_vsock_enabled(vsock: Option<&Vsock>) -> bool {
    vsock.is_some_and(|vsock| vsock.enabled)
}

/// Return the effective mux filename when the public vsock surface is enabled.
pub fn effective_vsock_filename(vsock: Option<&Vsock>) -> Option<&Path> {
    let vsock = vsock.filter(|vsock| vsock.enabled)?;
    Some(
        vsock
            .uds
            .as_deref()
            .unwrap_or_else(|| Path::new(DEFAULT_VSOCK_MUX_FILENAME)),
    )
}

fn validate_vsock_filename(filename: &Path) -> Result<(), &'static str> {
    let Some(filename_str) = filename.to_str() else {
        return Err("vsock.uds must be valid UTF-8");
    };

    if filename_str.is_empty() || filename_str.contains(['/', '\\']) || filename_str.contains('\0')
    {
        return Err("vsock.uds must be exactly one normal portable filename component");
    }

    let mut components = filename.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err("vsock.uds must be exactly one normal portable filename component");
    }

    if forward_spec::RESERVED_RUNTIME_FILENAMES.contains(&filename_str) {
        return Err("vsock.uds conflicts with a reserved machine runtime filename");
    }

    Ok(())
}

fn removed_fields_error(paths: &[String]) -> String {
    format!(
        "removed ADR 0005 fields are not supported: {}",
        paths.join(", ")
    )
}

fn collect_removed_paths(value: &Value, path: &str, paths: &mut Vec<String>) {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_removed_paths(value, &format!("{path}[{index}]"), paths);
            }
        }
        Value::Object(fields) => {
            for (field, value) in fields {
                let field_path = format!("{path}.{field}");
                paths.push(field_path.clone());
                collect_removed_paths(value, &field_path, paths);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde_json::json;

    use crate::{
        effective_vsock_enabled, effective_vsock_filename, Boot, Disk, Guest, GuestOs, Hardware,
        Kernel, Mount, Storage, VmSpec, Vsock, DEFAULT_VSOCK_MUX_FILENAME,
    };

    fn forward(listen: &str, connect: &str) -> forward_spec::Forward {
        forward_spec::Forward::new(
            listen.parse().expect("valid listen endpoint"),
            connect.parse().expect("valid connect endpoint"),
        )
    }

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
    fn current_spec_version_remains_0_1_0() {
        assert_eq!(VmSpec::current().spec_version.to_string(), "0.1.0");
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
            forwards: vec![
                forward("host:tcp:127.0.0.1:8080", "guest:tcp:80").with_name("web"),
                forward("vsock:5000", "host:unix:/var/run/service.sock"),
            ],
            vsock: Some(Vsock {
                enabled: true,
                uds: Some(PathBuf::from("custom.sock")),
            }),
            annotations: BTreeMap::from([("io.silo.demo".to_string(), "true".to_string())]),
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
                "forwards": [
                    {
                        "name": "web",
                        "listen": "host:tcp:127.0.0.1:8080",
                        "connect": "guest:tcp:127.0.0.1:80"
                    },
                    {
                        "listen": "vsock:5000",
                        "connect": "host:unix:/var/run/service.sock"
                    }
                ],
                "vsock": {
                    "enabled": true,
                    "uds": "custom.sock"
                },
                "annotations": { "io.silo.demo": "true" }
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
        assert!(!encoded.contains("forwards"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).expect("decode json"),
            json!({
                "specVersion": "0.1.0",
                "boot": { "kernel": { "path": "/kernel" } },
                "storage": {}
            })
        );
    }

    #[test]
    fn omitted_and_disabled_vsock_have_no_effective_surface() {
        let disabled = Vsock {
            enabled: false,
            uds: None,
        };

        assert!(!effective_vsock_enabled(None));
        assert_eq!(effective_vsock_filename(None), None);
        assert!(!effective_vsock_enabled(Some(&disabled)));
        assert_eq!(effective_vsock_filename(Some(&disabled)), None);
        assert_eq!(
            serde_json::to_value(&disabled).expect("serialize disabled vsock"),
            json!({ "enabled": false })
        );
    }

    #[test]
    fn enabled_vsock_uses_default_or_custom_filename() {
        let default = Vsock {
            enabled: true,
            uds: None,
        };
        let custom = Vsock {
            enabled: true,
            uds: Some(PathBuf::from("api.sock")),
        };

        assert!(effective_vsock_enabled(Some(&default)));
        assert_eq!(
            effective_vsock_filename(Some(&default)),
            Some(std::path::Path::new(DEFAULT_VSOCK_MUX_FILENAME))
        );
        assert_eq!(
            effective_vsock_filename(Some(&custom)),
            Some(std::path::Path::new("api.sock"))
        );
        assert_eq!(
            serde_json::from_value::<Vsock>(json!({ "enabled": true }))
                .expect("deserialize default filename"),
            default
        );
        assert_eq!(
            serde_json::from_value::<Vsock>(json!({
                "enabled": true,
                "uds": "api.sock"
            }))
            .expect("deserialize custom filename"),
            custom
        );
    }

    #[test]
    fn dot_prefixed_and_unicode_filenames_are_valid() {
        for filename in [".vsock.sock", "套接字.sock"] {
            let vsock = Vsock {
                enabled: true,
                uds: Some(PathBuf::from(filename)),
            };

            let encoded = serde_json::to_string(&vsock).expect("serialize valid filename");
            assert_eq!(
                serde_json::from_str::<Vsock>(&encoded).expect("deserialize valid filename"),
                vsock
            );
        }
    }

    #[test]
    fn new_vsock_shape_and_validation_work_through_yaml() {
        let yaml = "specVersion: 0.1.0\nfutureTopLevel:\n  nested: true\nvsock:\n  enabled: true\n  uds: custom.sock\n  futureVsockField: 42\n";
        let spec = serde_yaml_ng::from_str::<VmSpec>(yaml).expect("deserialize YAML VM spec");
        assert_eq!(
            spec.vsock,
            Some(Vsock {
                enabled: true,
                uds: Some(PathBuf::from("custom.sock"))
            })
        );

        let encoded = serde_yaml_ng::to_string(&spec).expect("serialize YAML VM spec");
        assert!(encoded.contains("enabled: true"));
        assert!(encoded.contains("uds: custom.sock"));
        assert!(!encoded.contains("futureTopLevel"));
        assert!(!encoded.contains("futureVsockField"));
        assert_eq!(
            serde_yaml_ng::from_str::<VmSpec>(&encoded).expect("round-trip YAML VM spec"),
            spec
        );

        let error = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nvsock:\n  enabled: false\n  uds: ignored.sock\n",
        )
        .expect_err("invalid YAML vsock must fail validation");
        assert!(error.to_string().contains("enabled is false"));
    }

    #[test]
    fn all_four_forward_shapes_round_trip_through_yaml() {
        let yaml = r#"specVersion: 0.1.0
forwards:
  - name: inbound-agent
    listen: host:unix:docker.sock
    connect: guest:unix:/var/run/docker.sock
  - name: inbound-vsock
    listen: host:tcp:127.0.0.1:2222
    connect: vsock:22
  - name: outbound-agent
    listen: guest:tcp:127.0.0.1:5432
    connect: host:tcp:127.0.0.1:5432
  - name: outbound-vsock
    listen: vsock:5000
    connect: host:unix:/var/run/service.sock
"#;
        let spec = serde_yaml_ng::from_str::<VmSpec>(yaml).expect("deserialize forwards");

        assert_eq!(spec.forwards.len(), 4);
        spec.validate().expect("validate forwards");
        let encoded = serde_yaml_ng::to_string(&spec).expect("serialize forwards");
        assert_eq!(
            serde_yaml_ng::from_str::<VmSpec>(&encoded).expect("round-trip forwards"),
            spec
        );
    }

    #[test]
    fn forwards_cannot_conflict_with_default_or_custom_mux_sockets() {
        let default_error = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nforwards:\n  - listen: host:unix:vsock.sock\n    connect: guest:tcp:80\nvsock:\n  enabled: true\n",
        )
        .expect_err("default mux conflict must fail");
        assert!(default_error
            .to_string()
            .contains("conflicts with vsock mux"));

        let custom_error = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nforwards:\n  - listen: host:unix:custom.sock_5000\n    connect: guest:tcp:80\nvsock:\n  enabled: true\n  uds: custom.sock\n",
        )
        .expect_err("custom mux listener conflict must fail");
        assert!(custom_error.to_string().contains("custom.sock"));

        let disabled = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nforwards:\n  - listen: host:unix:vsock.sock\n    connect: guest:tcp:80\nvsock:\n  enabled: false\n",
        )
        .expect("disabled mux has no filename conflict");
        assert_eq!(disabled.forwards.len(), 1);
    }

    #[test]
    fn duplicate_forward_names_and_vsock_listen_ports_are_rejected() {
        let duplicate_name = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nforwards:\n  - name: api\n    listen: host:tcp:80\n    connect: guest:tcp:80\n  - name: api\n    listen: host:tcp:81\n    connect: guest:tcp:81\n",
        )
        .expect_err("duplicate name must fail");
        assert!(duplicate_name
            .to_string()
            .contains("forward name \"api\" is repeated"));

        let duplicate_port = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nforwards:\n  - listen: vsock:5000\n    connect: host:tcp:80\n  - listen: vsock:5000\n    connect: host:tcp:81\n",
        )
        .expect_err("duplicate vsock listen port must fail");
        assert!(duplicate_port
            .to_string()
            .contains("vsock listen port 5000 is repeated"));
    }

    #[test]
    fn forward_entries_reject_unknown_fields_but_top_level_remains_permissive() {
        let error = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nfutureTopLevel: true\nforwards:\n  - listen: host:tcp:80\n    connect: guest:tcp:80\n    nam: typo\n",
        )
        .expect_err("unknown forward field must fail");
        assert!(error.to_string().contains("nam"));

        let spec = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nfutureTopLevel: true\nforwards:\n  - listen: host:tcp:80\n    connect: guest:tcp:80\n",
        )
        .expect("unknown top-level field remains permitted");
        assert_eq!(spec.forwards.len(), 1);
    }

    #[test]
    fn removed_fields_are_reported_before_invalid_forwards() {
        let error = serde_yaml_ng::from_str::<VmSpec>(
            "specVersion: 0.1.0\nvsockEndpoints:\n  - plugin:\n      command: /bin/old\nforwards:\n  - listen: host:tcp:80\n    connect: host:tcp:81\n",
        )
        .expect_err("removed field and invalid forward must fail");
        let message = error.to_string();

        assert!(message.contains("removed ADR 0005 fields"));
        assert!(message.contains("vsockEndpoints[0].plugin.command"));
        assert!(!message.contains("invalid forward sides"));
    }

    #[test]
    fn validate_rejects_programmatically_invalid_forwards() {
        let spec = VmSpec {
            forwards: vec![
                forward("host:tcp:80", "guest:tcp:80").with_name("api"),
                forward("host:tcp:81", "guest:tcp:81").with_name("api"),
            ],
            ..VmSpec::current()
        };

        let error = spec
            .validate()
            .expect_err("invalid spec must fail validation");
        assert!(error.contains("forward name \"api\" is repeated"));
    }

    #[test]
    fn enabled_defaults_to_false() {
        let vsock = serde_json::from_value::<Vsock>(json!({})).expect("deserialize empty vsock");

        assert_eq!(
            vsock,
            Vsock {
                enabled: false,
                uds: None
            }
        );
    }

    #[test]
    fn uds_is_rejected_while_disabled_during_deserialization_and_serialization() {
        let error = serde_json::from_value::<Vsock>(json!({ "uds": "api.sock" }))
            .expect_err("disabled uds must fail deserialization");
        assert!(error.to_string().contains("enabled is false"));

        let invalid = Vsock {
            enabled: false,
            uds: Some(PathBuf::from("api.sock")),
        };
        let invalid_spec = VmSpec {
            vsock: Some(invalid),
            ..VmSpec::current()
        };
        let error = serde_json::to_value(invalid_spec)
            .expect_err("programmatically invalid VM spec must fail serialization");
        assert!(error.to_string().contains("enabled is false"));
    }

    #[test]
    fn invalid_uds_filenames_fail_deserialization_and_serialization() {
        for filename in [
            "",
            ".",
            "..",
            "/absolute.sock",
            "dir/socket",
            "dir\\socket",
            "socket/",
            "socket\\",
            "nul\0socket",
        ] {
            let error = serde_json::from_value::<Vsock>(json!({
                "enabled": true,
                "uds": filename
            }))
            .expect_err("invalid uds must fail deserialization");
            assert!(error.to_string().contains("normal portable filename"));

            let invalid = Vsock {
                enabled: true,
                uds: Some(PathBuf::from(filename)),
            };
            let error =
                serde_json::to_value(invalid).expect_err("invalid uds must fail serialization");
            assert!(error.to_string().contains("normal portable filename"));
        }
    }

    #[test]
    fn runtime_owned_uds_filenames_fail_deserialization_and_serialization() {
        for filename in ["vm.sock", "vm.pid", "vm.lock", "krun.vsock"] {
            let error = serde_json::from_value::<Vsock>(json!({
                "enabled": true,
                "uds": filename
            }))
            .expect_err("runtime-owned uds must fail deserialization");
            assert!(error.to_string().contains("reserved machine runtime"));

            let invalid = Vsock {
                enabled: true,
                uds: Some(PathBuf::from(filename)),
            };
            let error = serde_json::to_value(invalid)
                .expect_err("runtime-owned uds must fail serialization");
            assert!(error.to_string().contains("reserved machine runtime"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_uds_fails_serialization() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let invalid = Vsock {
            enabled: true,
            uds: Some(PathBuf::from(OsString::from_vec(vec![0xff]))),
        };

        let error =
            serde_json::to_value(invalid).expect_err("non-UTF-8 uds must fail serialization");
        assert!(error.to_string().contains("valid UTF-8"));
    }

    #[test]
    fn removed_endpoint_fields_are_reported_comprehensively() {
        let error = serde_json::from_value::<VmSpec>(json!({
            "specVersion": "0.1.0",
            "vsock": {
                "endpoints": [
                    {
                        "name": "first",
                        "plugin": {
                            "command": "/bin/first",
                            "config": { "kind": "one" }
                        },
                        "lifecycle": {
                            "restart": "always",
                            "backoffMs": { "initial": 1, "max": 2 }
                        }
                    },
                    {
                        "name": "second",
                        "plugin": { "command": "/bin/second" },
                        "lifecycle": { "autostart": false }
                    }
                ],
                "plugin": { "command": "/bin/root" },
                "lifecycle": { "restart": "never" }
            }
        }))
        .expect_err("removed endpoint fields must fail");
        let message = error.to_string();

        for path in [
            "vsock.endpoints",
            "vsock.endpoints[0].name",
            "vsock.endpoints[0].plugin",
            "vsock.endpoints[0].plugin.command",
            "vsock.endpoints[0].plugin.config.kind",
            "vsock.endpoints[0].lifecycle.restart",
            "vsock.endpoints[0].lifecycle.backoffMs.initial",
            "vsock.endpoints[0].lifecycle.backoffMs.max",
            "vsock.endpoints[1].name",
            "vsock.endpoints[1].plugin.command",
            "vsock.endpoints[1].lifecycle.autostart",
            "vsock.plugin.command",
            "vsock.lifecycle.restart",
        ] {
            assert!(
                message.contains(path),
                "missing removed path {path}: {message}"
            );
        }
    }

    #[test]
    fn top_level_legacy_endpoint_forms_are_rejected_comprehensively_in_json() {
        for field in ["vsock_endpoints", "vsockEndpoints"] {
            let input = format!(
                r#"{{
                    "specVersion": "0.1.0",
                    "{field}": [
                        {{
                            "name": "first",
                            "plugin": {{ "command": "/bin/first", "config": {{ "kind": "one" }} }},
                            "lifecycle": {{ "restart": "always", "backoffMs": {{ "initial": 1 }} }}
                        }},
                        {{
                            "name": "second",
                            "plugin": {{ "command": "/bin/second" }},
                            "lifecycle": {{ "autostart": false }}
                        }}
                    ]
                }}"#
            );
            let error = serde_json::from_str::<VmSpec>(&input)
                .expect_err("top-level legacy endpoints must fail");
            let message = error.to_string();

            for suffix in [
                "",
                "[0].name",
                "[0].plugin",
                "[0].plugin.command",
                "[0].plugin.config.kind",
                "[0].lifecycle",
                "[0].lifecycle.restart",
                "[0].lifecycle.backoffMs.initial",
                "[1].name",
                "[1].plugin.command",
                "[1].lifecycle.autostart",
            ] {
                let path = format!("{field}{suffix}");
                assert!(
                    message.contains(&path),
                    "missing removed path {path}: {message}"
                );
            }
        }
    }

    #[test]
    fn mixed_legacy_forms_are_aggregated_into_one_error() {
        let error = serde_json::from_value::<VmSpec>(json!({
            "specVersion": "0.1.0",
            "vsock_endpoints": [{
                "plugin": { "command": "/bin/snake" },
                "lifecycle": { "restart": "always" }
            }],
            "vsockEndpoints": [{
                "plugin": { "command": "/bin/camel" },
                "lifecycle": { "autostart": true }
            }],
            "vsock": {
                "endpoints": [{
                    "plugin": { "command": "/bin/nested" },
                    "lifecycle": { "backoffMs": { "max": 5 } }
                }]
            }
        }))
        .expect_err("all legacy forms must fail together");
        let message = error.to_string();

        for path in [
            "vsock_endpoints[0].plugin.command",
            "vsock_endpoints[0].lifecycle.restart",
            "vsockEndpoints[0].plugin.command",
            "vsockEndpoints[0].lifecycle.autostart",
            "vsock.endpoints[0].plugin.command",
            "vsock.endpoints[0].lifecycle.backoffMs.max",
        ] {
            assert!(
                message.contains(path),
                "missing removed path {path}: {message}"
            );
        }
    }

    #[test]
    fn duplicate_vsock_cannot_hide_legacy_json_or_yaml_data() {
        let json = r#"{
            "specVersion": "0.1.0",
            "vsock": { "endpoints": [{ "plugin": { "command": "/bin/old" } }] },
            "vsock": { "enabled": true }
        }"#;
        let json_error = serde_json::from_str::<VmSpec>(json)
            .expect_err("duplicate JSON vsock must not hide old data");
        assert!(json_error.to_string().contains("duplicate field `vsock`"));

        let yaml = "specVersion: 0.1.0\nvsock:\n  endpoints:\n    - plugin:\n        command: /bin/old\nvsock:\n  enabled: true\n";
        let yaml_error = serde_yaml_ng::from_str::<VmSpec>(yaml)
            .expect_err("duplicate YAML vsock must not hide old data");
        assert!(yaml_error.to_string().contains("duplicate field `vsock`"));
    }

    #[test]
    fn duplicate_known_vsock_fields_are_rejected() {
        for json in [
            r#"{"enabled": false, "enabled": true}"#,
            r#"{"enabled": true, "uds": "first.sock", "uds": "second.sock"}"#,
        ] {
            let error = serde_json::from_str::<Vsock>(json)
                .expect_err("duplicate JSON vsock field must fail");
            assert!(error.to_string().contains("duplicate field"));
        }

        for yaml in [
            "enabled: false\nenabled: true\n",
            "enabled: true\nuds: first.sock\nuds: second.sock\n",
        ] {
            let error = serde_yaml_ng::from_str::<Vsock>(yaml)
                .expect_err("duplicate YAML vsock field must fail");
            assert!(error.to_string().contains("duplicate field"));
        }
    }

    #[test]
    fn standalone_vsock_retains_removed_field_diagnostics() {
        let error = serde_json::from_value::<Vsock>(json!({
            "endpoints": [{
                "plugin": { "command": "/bin/old" },
                "lifecycle": { "restart": "always" }
            }]
        }))
        .expect_err("standalone legacy vsock must fail");
        let message = error.to_string();

        for path in [
            "vsock.endpoints[0].plugin.command",
            "vsock.endpoints[0].lifecycle.restart",
        ] {
            assert!(
                message.contains(path),
                "missing removed path {path}: {message}"
            );
        }
    }

    #[test]
    fn top_level_legacy_endpoint_forms_are_rejected_comprehensively_in_yaml() {
        for field in ["vsock_endpoints", "vsockEndpoints"] {
            let input = format!(
                "specVersion: 0.1.0\n{field}:\n{}",
                [
                    "  - name: first",
                    "    plugin:",
                    "      command: /bin/first",
                    "      config:",
                    "        kind: one",
                    "    lifecycle:",
                    "      restart: always",
                    "      backoffMs:",
                    "        initial: 1",
                    "  - name: second",
                    "    plugin:",
                    "      command: /bin/second",
                    "    lifecycle:",
                    "      autostart: false",
                    "",
                ]
                .join("\n")
            );
            let error = serde_yaml_ng::from_str::<VmSpec>(&input)
                .expect_err("top-level legacy YAML endpoints must fail");
            let message = error.to_string();

            for suffix in [
                "",
                "[0].name",
                "[0].plugin",
                "[0].plugin.command",
                "[0].plugin.config.kind",
                "[0].lifecycle",
                "[0].lifecycle.restart",
                "[0].lifecycle.backoffMs.initial",
                "[1].name",
                "[1].plugin.command",
                "[1].lifecycle.autostart",
            ] {
                let path = format!("{field}{suffix}");
                assert!(
                    message.contains(&path),
                    "missing removed path {path}: {message}"
                );
            }
        }
    }

    #[test]
    fn unrelated_unknown_fields_remain_permissive() {
        let spec = serde_json::from_value::<VmSpec>(json!({
            "specVersion": "0.1.0",
            "futureTopLevel": { "nested": true },
            "vsock": { "enabled": true, "futureVsockField": 42 }
        }))
        .expect("unknown fields remain permitted");

        assert_eq!(
            spec.vsock,
            Some(Vsock {
                enabled: true,
                uds: None
            })
        );
    }

    #[test]
    fn non_vsock_sections_still_round_trip() {
        let value = json!({
            "specVersion": "0.1.0",
            "guest": { "os": "linux" },
            "hardware": { "cpus": 2, "memory": 1024 },
            "annotations": { "owner": "test" }
        });
        let spec = serde_json::from_value::<VmSpec>(value.clone()).expect("deserialize vm spec");

        assert_eq!(
            serde_json::to_value(spec).expect("serialize vm spec"),
            value
        );
    }
}
