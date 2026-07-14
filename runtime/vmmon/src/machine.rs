use std::path::{Path, PathBuf};

use agent_spec::SSH_VSOCK_PORT;
use protocol::guest_port_arg;
use thiserror::Error;
use utils::parse_mac;
use virt::{
    DiskImage, MachineIdentifier, SharedDirectory, VirtError, VmConfig, VmConfigBuilder, VsockPort,
    VsockPortMode,
};
use vm_spec::{VmSpec, VsockEndpointMode};

use crate::ext::VmSpecExt;
use crate::guest::GUEST_CONTROL_PORT;

const APPLE_MACHINE_IDENTIFIER_FILE: &str = "apple-machine-id";

#[derive(Debug, Error)]
pub enum MachineSpecError {
    #[error(transparent)]
    Machine(#[from] VirtError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("invalid mount tag for {mount_source}: mount tags must be non-empty")]
    InvalidMountTag { mount_source: String },
}

#[derive(Debug, Clone)]
pub(crate) struct InstanceVmConfig {
    pub config: VmConfig,
    pub machine_identifier: Option<MachineIdentifier>,
}

pub(crate) struct VmSpecInputs<'a> {
    pub name: &'a str,
    pub id: &'a str,
    pub data_dir: &'a Path,
    pub spec: &'a VmSpec,
    pub network: &'a RuntimeNetwork,
    pub guest_services_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeNetwork {
    None,
    UnixDatagram { path: PathBuf, mac: String },
}

pub(crate) fn vm_spec_machine_config(
    inputs: VmSpecInputs<'_>,
) -> Result<InstanceVmConfig, MachineSpecError> {
    let boot_assets = vm_spec_boot_assets(&inputs)?;
    let machine_identifier = load_host_machine_identifier(inputs.data_dir)?;

    let mut builder = VmConfig::builder(inputs.name)
        .vm_id(inputs.id)
        .base_directory(inputs.data_dir.to_path_buf())
        .kernel_cmdline(vm_spec_kernel_cmdline(
            inputs.spec,
            inputs.guest_services_enabled,
        ))
        .nested_virtualization(inputs.spec.nested_virtualization_or_default())
        .rosetta(inputs.spec.rosetta_or_default());

    builder = apply_runtime_network(builder, inputs.network)?;

    if let Some(machine_identifier) = machine_identifier.clone() {
        builder = builder.machine_identifier(machine_identifier);
    }

    builder = builder
        .cpus(inputs.spec.cpus_or_default() as usize)
        .memory(inputs.spec.memory_or_default() as u64)
        .kernel(boot_assets.kernel);

    if let Some(initramfs) = boot_assets.initramfs {
        builder = builder.initramfs(initramfs);
    }

    if let Some(storage) = inputs.spec.storage.as_ref() {
        for disk in &storage.disks {
            let disk_image = DiskImage {
                path: resolve_spec_path(inputs.data_dir, &disk.path),
                read_only: disk.read_only,
            };

            builder = builder.disk(disk_image);
        }
    }

    for mount in &inputs.spec.mounts {
        if mount.tag.trim().is_empty() {
            return Err(MachineSpecError::InvalidMountTag {
                mount_source: mount.source.display().to_string(),
            });
        }
        builder = builder.mount(SharedDirectory {
            host_path: mount.source.clone(),
            tag: mount.tag.clone(),
            read_only: mount.read_only,
        });
    }

    for port in vm_spec_vsock_ports(inputs.spec, inputs.guest_services_enabled) {
        builder = builder.vsock_port(port);
    }

    Ok(InstanceVmConfig {
        config: builder.build(),
        machine_identifier,
    })
}

fn vm_spec_vsock_ports(spec: &VmSpec, guest_services_enabled: bool) -> Vec<VsockPort> {
    let mut ports = Vec::new();
    if let Some(vsock) = spec.vsock.as_ref() {
        for endpoint in &vsock.endpoints {
            ports.push(VsockPort {
                port: endpoint.port,
                mode: map_vsock_endpoint_mode(endpoint.mode),
            });
        }
    }

    if guest_services_enabled {
        ports.push(VsockPort {
            port: GUEST_CONTROL_PORT,
            mode: VsockPortMode::Connect,
        });
        ports.push(VsockPort {
            port: SSH_VSOCK_PORT,
            mode: VsockPortMode::Connect,
        });
    }

    ports
}

fn vm_spec_kernel_cmdline(spec: &VmSpec, guest_services_enabled: bool) -> Vec<String> {
    let mut kernel_cmdline = spec
        .boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
        .map(|kernel| kernel.cmdline.clone())
        .unwrap_or_default();
    if guest_services_enabled {
        kernel_cmdline.push(guest_port_arg(GUEST_CONTROL_PORT));
    }
    kernel_cmdline
}

fn map_vsock_endpoint_mode(mode: VsockEndpointMode) -> VsockPortMode {
    match mode {
        VsockEndpointMode::Connect => VsockPortMode::Connect,
        VsockEndpointMode::Listen => VsockPortMode::Listen,
    }
}

pub(crate) fn machine_identifier_path_from_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(APPLE_MACHINE_IDENTIFIER_FILE)
}

#[cfg(target_os = "macos")]
fn load_machine_identifier_from_dir(
    data_dir: &Path,
) -> Result<MachineIdentifier, MachineSpecError> {
    let path = machine_identifier_path_from_dir(data_dir);
    match std::fs::read(path) {
        Ok(bytes) => Ok(MachineIdentifier::from_bytes(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(MachineIdentifier::new()),
        Err(err) => Err(err.into()),
    }
}

struct BootAssets {
    kernel: PathBuf,
    initramfs: Option<PathBuf>,
}

fn vm_spec_boot_assets(inputs: &VmSpecInputs<'_>) -> Result<BootAssets, MachineSpecError> {
    let kernel = match inputs
        .spec
        .boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
        .and_then(|kernel| kernel.path.as_ref())
    {
        Some(path) => resolve_spec_path(inputs.data_dir, path),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VM spec is missing boot.kernel.path",
            )
            .into())
        }
    };
    let initramfs = inputs
        .spec
        .boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
        .and_then(|kernel| kernel.initramfs.as_ref())
        .map(|path| resolve_spec_path(inputs.data_dir, path));

    if !kernel.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("kernel is not a file: {}", kernel.display()),
        )
        .into());
    }

    if let Some(initramfs) = initramfs.as_ref() {
        if !initramfs.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("initramfs is not a file: {}", initramfs.display()),
            )
            .into());
        }
    }

    Ok(BootAssets { kernel, initramfs })
}

fn resolve_spec_path(data_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        data_dir.join(path)
    }
}

fn apply_runtime_network(
    builder: VmConfigBuilder,
    network: &RuntimeNetwork,
) -> Result<VmConfigBuilder, MachineSpecError> {
    match network {
        RuntimeNetwork::None => Ok(builder.no_network()),
        RuntimeNetwork::UnixDatagram { path, mac } => {
            Ok(builder.unix_datagram_network(path.clone(), parse_mac_str(mac)?))
        }
    }
}

fn parse_mac_str(mac: &str) -> Result<[u8; 6], MachineSpecError> {
    parse_mac(mac).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("parse MAC address: {err}"),
        )
        .into()
    })
}

#[cfg(target_os = "macos")]
fn load_host_machine_identifier(
    data_dir: &Path,
) -> Result<Option<MachineIdentifier>, MachineSpecError> {
    load_machine_identifier_from_dir(data_dir).map(Some)
}

#[cfg(not(target_os = "macos"))]
fn load_host_machine_identifier(
    _data_dir: &Path,
) -> Result<Option<MachineIdentifier>, MachineSpecError> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{apply_runtime_network, vm_spec_machine_config, RuntimeNetwork, VmSpecInputs};
    use agent_spec::SSH_VSOCK_PORT;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use virt::{VmConfig, VsockPortMode};
    use vm_spec::{Boot, Disk, Hardware, Kernel, Storage, VmSpec};

    const DATA_DISK: &str = "data.img";

    fn boot_assets(dir: &std::path::Path) -> Boot {
        let kernel = dir.join("kernel");
        let initramfs = dir.join("initramfs");
        fs::write(&kernel, b"kernel").expect("write kernel");
        fs::write(&initramfs, b"initramfs").expect("write initramfs");

        Boot {
            kernel: Some(Kernel {
                path: Some(PathBuf::from("kernel")),
                cmdline: Vec::new(),
                initramfs: Some(PathBuf::from("initramfs")),
            }),
            userdata: None,
        }
    }

    fn boot_assets_without_initramfs(dir: &std::path::Path) -> Boot {
        let kernel = dir.join("kernel");
        fs::write(&kernel, b"kernel").expect("write kernel");

        Boot {
            kernel: Some(Kernel {
                path: Some(PathBuf::from("kernel")),
                cmdline: Vec::new(),
                initramfs: None,
            }),
            userdata: None,
        }
    }

    fn sample_spec(dir: &std::path::Path) -> VmSpec {
        VmSpec {
            boot: Some(boot_assets(dir)),
            hardware: Some(Hardware {
                cpus: Some(2),
                memory: Some(1024),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            }),
            storage: Some(Storage { disks: Vec::new() }),
            ..VmSpec::current()
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("vmmon-test-{name}-{now}"))
    }

    #[test]
    fn unix_datagram_runtime_attachment_maps_to_network_mode() {
        let config = apply_runtime_network(
            VmConfig::builder("devbox"),
            &RuntimeNetwork::UnixDatagram {
                path: PathBuf::from("/tmp/net.sock"),
                mac: "02:00:00:00:00:01".to_string(),
            },
        )
        .expect("runtime network")
        .build();

        let (peer_path, mac) = config
            .unix_datagram_network()
            .expect("unix datagram network");
        assert_eq!(peer_path, &PathBuf::from("/tmp/net.sock"));
        assert_eq!(mac, [0x02, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn vm_spec_machine_config_forwards_kernel_cmdline() {
        let dir = temp_dir("kernel-cmdline");
        fs::create_dir_all(&dir).expect("create temp dir");
        let mut spec = sample_spec(&dir);
        spec.boot
            .as_mut()
            .and_then(|boot| boot.kernel.as_mut())
            .expect("kernel")
            .cmdline = vec!["console=hvc0".to_string()];

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm123",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
            guest_services_enabled: true,
        })
        .expect("machine config should resolve");

        assert_eq!(
            machine_config.config.kernel_cmdline,
            vec![
                "console=hvc0".to_string(),
                "silo.guest.port=1027".to_string()
            ]
        );
        assert_eq!(machine_config.config.vm_id(), "vm123");
        assert!(machine_config
            .config
            .vsock_ports
            .iter()
            .any(|port| port.port == 1027 && port.mode == VsockPortMode::Connect));
        assert!(machine_config
            .config
            .vsock_ports
            .iter()
            .any(|port| port.port == SSH_VSOCK_PORT && port.mode == VsockPortMode::Connect));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_allows_zero_disks() {
        let dir = temp_dir("zero-disks");
        fs::create_dir_all(&dir).expect("create temp dir");

        let spec = sample_spec(&dir);

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm789",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
            guest_services_enabled: false,
        })
        .expect("machine config should resolve");

        assert!(machine_config.config.disks.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_attaches_spec_disks_in_order() {
        let dir = temp_dir("declared-disks");
        fs::create_dir_all(&dir).expect("create temp dir");

        let mut spec = sample_spec(&dir);
        spec.storage = Some(Storage {
            disks: vec![
                Disk {
                    path: PathBuf::from("rootfs.img"),
                    read_only: false,
                },
                Disk {
                    path: PathBuf::from(DATA_DISK),
                    read_only: true,
                },
            ],
        });

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm790",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
            guest_services_enabled: false,
        })
        .expect("machine config should resolve");

        assert_eq!(machine_config.config.disks.len(), 2);
        assert_eq!(machine_config.config.disks[0].path, dir.join("rootfs.img"));
        assert!(!machine_config.config.disks[0].read_only);
        assert_eq!(machine_config.config.disks[1].path, dir.join(DATA_DISK));
        assert!(machine_config.config.disks[1].read_only);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_parses_unix_datagram_attachment() {
        let dir = temp_dir("unix-datagram-network");
        fs::create_dir_all(&dir).expect("create temp dir");
        let spec = sample_spec(&dir);
        let runtime_network = RuntimeNetwork::UnixDatagram {
            path: PathBuf::from("/tmp/gvproxy.sock"),
            mac: "02:19:e0:00:e2:e6".to_string(),
        };

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm456",
            data_dir: &dir,
            spec: &spec,
            network: &runtime_network,
            guest_services_enabled: false,
        })
        .expect("machine config should resolve");

        let (peer_path, mac) = machine_config
            .config
            .unix_datagram_network()
            .expect("unix datagram network");
        assert_eq!(peer_path, &PathBuf::from("/tmp/gvproxy.sock"));
        assert_eq!(mac, [0x02, 0x19, 0xe0, 0x00, 0xe2, 0xe6]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_defaults_missing_optional_sections() {
        let dir = temp_dir("defaults");
        fs::create_dir_all(&dir).expect("create temp dir");
        let spec = VmSpec {
            boot: Some(boot_assets_without_initramfs(&dir)),
            ..VmSpec::current()
        };

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm-defaults",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
            guest_services_enabled: false,
        })
        .expect("machine config should resolve");

        assert_eq!(machine_config.config.cpus, Some(1));
        assert_eq!(machine_config.config.memory_mib, Some(512));
        assert!(machine_config.config.initramfs_path.is_none());
        assert!(machine_config.config.kernel_cmdline.is_empty());
        assert!(machine_config.config.disks.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_accepts_missing_initramfs() {
        let dir = temp_dir("no-initramfs");
        fs::create_dir_all(&dir).expect("create temp dir");
        let spec = VmSpec {
            boot: Some(boot_assets_without_initramfs(&dir)),
            ..VmSpec::current()
        };

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm-no-initramfs",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
            guest_services_enabled: false,
        })
        .expect("machine config should resolve");

        assert!(machine_config.config.initramfs_path.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_requires_kernel_path() {
        let dir = temp_dir("missing-kernel");
        fs::create_dir_all(&dir).expect("create temp dir");
        let spec = VmSpec::current();

        let err = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm-missing-kernel",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
            guest_services_enabled: false,
        })
        .expect_err("missing kernel path should fail");

        assert!(err.to_string().contains("boot.kernel.path"));

        let _ = fs::remove_dir_all(&dir);
    }
}
