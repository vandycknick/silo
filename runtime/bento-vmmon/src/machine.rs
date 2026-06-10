use std::path::{Path, PathBuf};

use bento_core::{agent::RESERVED_SHELL_PORT, DiskKind, VmSpec, VsockEndpointMode};
use bento_protocol::agent_port_arg;
use bento_utils::parse_mac;
use bento_virt::{
    DiskImage, MachineIdentifier, SharedDirectory, VirtError, VmConfig, VmConfigBuilder, VsockPort,
    VsockPortMode,
};
use thiserror::Error;

use crate::agent::AGENT_CONTROL_PORT;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeNetwork {
    None,
    VzNat { mac: Option<String> },
    UnixDatagram { path: PathBuf, mac: String },
    UnixStream { path: PathBuf, mac: String },
    Tap { name: String, mac: String },
}

pub(crate) fn vm_spec_machine_config(
    inputs: VmSpecInputs<'_>,
) -> Result<InstanceVmConfig, MachineSpecError> {
    let boot_assets = vm_spec_boot_assets(&inputs)?;
    let machine_identifier = load_host_machine_identifier(inputs.data_dir)?;

    let mut builder = VmConfig::builder(inputs.name)
        .vm_id(inputs.id)
        .base_directory(inputs.data_dir.to_path_buf())
        .kernel_cmdline(vm_spec_kernel_cmdline(inputs.spec))
        .nested_virtualization(inputs.spec.settings.nested_virtualization)
        .rosetta(inputs.spec.settings.rosetta);

    builder = apply_runtime_network(builder, inputs.network)?;

    if let Some(machine_identifier) = machine_identifier.clone() {
        builder = builder.machine_identifier(machine_identifier);
    }

    builder = builder
        .cpus(inputs.spec.resources.cpus as usize)
        .memory(inputs.spec.resources.memory_mib as u64)
        .kernel(boot_assets.kernel)
        .initramfs(boot_assets.initramfs);

    for disk in &inputs.spec.storage.disks {
        let disk_image = DiskImage {
            path: resolve_spec_path(inputs.data_dir, &disk.path),
            read_only: disk.read_only,
        };

        match disk.kind {
            DiskKind::Root => builder = builder.root_disk(disk_image),
            DiskKind::Data => builder = builder.disk(disk_image),
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

    for port in vm_spec_vsock_ports(inputs.spec) {
        builder = builder.vsock_port(port);
    }

    Ok(InstanceVmConfig {
        config: builder.build(),
        machine_identifier,
    })
}

fn vm_spec_vsock_ports(spec: &VmSpec) -> Vec<VsockPort> {
    let mut ports = Vec::new();
    for endpoint in &spec.vsock_endpoints {
        ports.push(VsockPort {
            port: endpoint.port,
            mode: map_vsock_endpoint_mode(endpoint.mode),
        });
    }

    if spec.settings.agent {
        ports.push(VsockPort {
            port: AGENT_CONTROL_PORT,
            mode: VsockPortMode::Connect,
        });
        ports.push(VsockPort {
            port: RESERVED_SHELL_PORT,
            mode: VsockPortMode::Connect,
        });
    }

    ports
}

fn vm_spec_kernel_cmdline(spec: &VmSpec) -> Vec<String> {
    let mut kernel_cmdline = spec.boot.kernel_cmdline.clone();
    if spec.settings.agent {
        kernel_cmdline.push(agent_port_arg(AGENT_CONTROL_PORT));
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
    initramfs: PathBuf,
}

fn vm_spec_boot_assets(inputs: &VmSpecInputs<'_>) -> Result<BootAssets, MachineSpecError> {
    let kernel = match inputs.spec.boot.kernel.as_ref() {
        Some(path) => resolve_spec_path(inputs.data_dir, path),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VM spec is missing boot.kernel",
            )
            .into())
        }
    };
    let initramfs = match inputs.spec.boot.initramfs.as_ref() {
        Some(path) => resolve_spec_path(inputs.data_dir, path),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VM spec is missing boot.initramfs",
            )
            .into())
        }
    };

    if !kernel.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("kernel is not a file: {}", kernel.display()),
        )
        .into());
    }

    if !initramfs.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("initramfs is not a file: {}", initramfs.display()),
        )
        .into());
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
        RuntimeNetwork::VzNat { .. } => Ok(builder.vz_nat_network()),
        RuntimeNetwork::UnixDatagram { path, mac } => {
            Ok(builder.unix_datagram_network(path.clone(), parse_mac_str(mac)?))
        }
        RuntimeNetwork::UnixStream { .. } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unixstream network runtime attachments are not supported by the current virt runtime",
        )
        .into()),
        RuntimeNetwork::Tap { .. } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tap network runtime attachments are not supported by the current virt runtime",
        )
        .into()),
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
    use bento_core::{
        agent::RESERVED_SHELL_PORT, Architecture, Boot, Disk, DiskKind, GuestOs, Platform,
        Resources, Settings, Storage, VmSpec,
    };
    use bento_virt::{VmConfig, VsockPortMode};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const DATA_DISK: &str = "data.img";

    fn boot_assets(dir: &std::path::Path) -> Boot {
        let kernel = dir.join("kernel");
        let initramfs = dir.join("initramfs");
        fs::write(&kernel, b"kernel").expect("write kernel");
        fs::write(&initramfs, b"initramfs").expect("write initramfs");

        Boot {
            kernel: Some(PathBuf::from("kernel")),
            initramfs: Some(PathBuf::from("initramfs")),
            kernel_cmdline: Vec::new(),
            bootstrap: None,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("bento-vmmon-test-{name}-{now}"))
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
    fn vznat_network_maps_to_vz_nat_mode() {
        assert_eq!(
            apply_runtime_network(
                VmConfig::builder("devbox"),
                &RuntimeNetwork::VzNat { mac: None }
            )
            .expect("runtime network")
            .build()
            .network,
            bento_virt::NetworkMode::VzNat
        );
    }

    #[test]
    fn vm_spec_machine_config_forwards_kernel_cmdline() {
        let dir = temp_dir("kernel-cmdline");
        fs::create_dir_all(&dir).expect("create temp dir");
        let kernel = dir.join("kernel");
        let initramfs = dir.join("initramfs");
        fs::write(&kernel, b"kernel").expect("write kernel");
        fs::write(&initramfs, b"initramfs").expect("write initramfs");

        let spec = VmSpec {
            version: 1,
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: Architecture::Aarch64,
            },
            resources: Resources {
                cpus: 2,
                memory_mib: 1024,
            },
            boot: Boot {
                kernel: Some(
                    kernel
                        .strip_prefix(&dir)
                        .expect("relative kernel")
                        .to_path_buf(),
                ),
                initramfs: Some(
                    initramfs
                        .strip_prefix(&dir)
                        .expect("relative initramfs")
                        .to_path_buf(),
                ),
                kernel_cmdline: vec!["console=hvc0".to_string()],
                bootstrap: None,
            },
            storage: Storage { disks: Vec::new() },
            mounts: Vec::new(),
            vsock_endpoints: Vec::new(),
            settings: Settings {
                agent: true,
                nested_virtualization: false,
                rosetta: false,
            },
        };

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm123",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
        })
        .expect("machine config should resolve");

        assert_eq!(
            machine_config.config.kernel_cmdline,
            vec![
                "console=hvc0".to_string(),
                "bento.agent.port=1027".to_string()
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
            .any(|port| port.port == RESERVED_SHELL_PORT && port.mode == VsockPortMode::Connect));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_does_not_attach_implicit_data_disk() {
        let dir = temp_dir("implicit-data-disk");
        fs::create_dir_all(&dir).expect("create temp dir");
        fs::write(dir.join(DATA_DISK), b"data disk").expect("write data disk");

        let spec = VmSpec {
            version: 1,
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: Architecture::Aarch64,
            },
            resources: Resources {
                cpus: 2,
                memory_mib: 1024,
            },
            boot: boot_assets(&dir),
            storage: Storage { disks: Vec::new() },
            mounts: Vec::new(),
            vsock_endpoints: Vec::new(),
            settings: Settings {
                agent: false,
                nested_virtualization: false,
                rosetta: false,
            },
        };

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm789",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
        })
        .expect("machine config should resolve");

        assert!(machine_config.config.data_disks.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_attaches_declared_data_disk() {
        let dir = temp_dir("declared-data-disk");
        fs::create_dir_all(&dir).expect("create temp dir");

        let spec = VmSpec {
            version: 1,
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: Architecture::Aarch64,
            },
            resources: Resources {
                cpus: 2,
                memory_mib: 1024,
            },
            boot: boot_assets(&dir),
            storage: Storage {
                disks: vec![Disk {
                    path: PathBuf::from(DATA_DISK),
                    kind: DiskKind::Data,
                    read_only: true,
                }],
            },
            mounts: Vec::new(),
            vsock_endpoints: Vec::new(),
            settings: Settings {
                agent: false,
                nested_virtualization: false,
                rosetta: false,
            },
        };

        let machine_config = vm_spec_machine_config(VmSpecInputs {
            name: "devbox",
            id: "vm790",
            data_dir: &dir,
            spec: &spec,
            network: &RuntimeNetwork::None,
        })
        .expect("machine config should resolve");

        assert_eq!(machine_config.config.data_disks.len(), 1);
        assert_eq!(
            machine_config.config.data_disks[0].path,
            dir.join(DATA_DISK)
        );
        assert!(machine_config.config.data_disks[0].read_only);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vm_spec_machine_config_parses_unix_datagram_attachment() {
        let dir = temp_dir("unix-datagram-network");
        fs::create_dir_all(&dir).expect("create temp dir");
        let kernel = dir.join("kernel");
        let initramfs = dir.join("initramfs");
        fs::write(&kernel, b"kernel").expect("write kernel");
        fs::write(&initramfs, b"initramfs").expect("write initramfs");

        let spec = VmSpec {
            version: 1,
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: Architecture::Aarch64,
            },
            resources: Resources {
                cpus: 2,
                memory_mib: 1024,
            },
            boot: Boot {
                kernel: Some(
                    kernel
                        .strip_prefix(&dir)
                        .expect("relative kernel")
                        .to_path_buf(),
                ),
                initramfs: Some(
                    initramfs
                        .strip_prefix(&dir)
                        .expect("relative initramfs")
                        .to_path_buf(),
                ),
                kernel_cmdline: Vec::new(),
                bootstrap: None,
            },
            storage: Storage { disks: Vec::new() },
            mounts: Vec::new(),
            vsock_endpoints: Vec::new(),
            settings: Settings {
                agent: false,
                nested_virtualization: false,
                rosetta: false,
            },
        };
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
}
