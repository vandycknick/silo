use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::io::{self, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bento_core::agent::{
    AgentConfig, AgentDnsConfig, AgentForwardConfig, AgentSshConfig, AgentUdsForwardConfig,
};
use bento_core::{resolve_mount_location, Disk, DiskKind, InstanceFile, Network, VmSpec};
use bento_utils::format_mac;
use eyre::Context;
use fatfs::{format_volume, FileSystem, FormatVolumeOptions, FsOptions};
use serde::{Deserialize, Serialize};

use crate::global_config::{ensure_guest_binary, GlobalConfig};
use crate::host_user::{self, HostUser};
use crate::ssh_keys;

const GUEST_AGENT_CIDATA_ENTRY: &str = "bento-agent";
const GUEST_AGENT_INSTALL_SCRIPT_ENTRY: &str = "bento-install-guest-agent.sh";
const GUEST_AGENT_CONFIG_ENTRY: &str = "bento-agent.yaml";
const GUEST_AGENT_CONFIG_ENV_ENTRY: &str = "config.env";
const GUEST_AGENT_BOOTSTRAP_SCRIPT: &str = "/var/lib/cloud/scripts/per-boot/00-bento.bootstrap.sh";
const GUEST_BOOTSTRAP_SCRIPT_CONTENT: &str = include_str!("../scripts/guest-bootstrap.sh");
const GUEST_INSTALL_SCRIPT_CONTENT: &str = include_str!("../scripts/guest-install.sh");
const TASK_REGISTER_AGENT_CONTENT: &str = include_str!("../scripts/tasks/10-register-agent.sh");
const TASK_SETUP_ROSETTA_CONTENT: &str = include_str!("../scripts/tasks/20-setup-rosetta.sh");
const FORWARD_ENDPOINT_NAME: &str = "forward";
const CIDATA_VOLUME_LABEL: &str = "CIDATA";
const CIDATA_MIN_SIZE_BYTES: u64 = 16 * 1024 * 1024;
const CIDATA_SIZE_OVERHEAD_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize, Default)]
struct ForwardPluginAgentConfig {
    #[serde(default)]
    uds: Vec<ForwardPluginUdsConfig>,
}

#[derive(Debug, Deserialize)]
struct ForwardPluginUdsConfig {
    guest_path: String,
}

#[derive(Debug, Clone)]
struct CidataEntry {
    name: String,
    contents: Vec<u8>,
}

#[derive(Debug, Clone)]
struct MonitorMount {
    source: PathBuf,
    tag: String,
    writable: bool,
}

pub(crate) fn prepare_instance_runtime(instance_dir: &Path, network: &Network) -> eyre::Result<()> {
    let mut spec = read_vm_spec_from_dir(instance_dir)?;
    let guest_runtime = resolve_guest_runtime_config(&spec, network)?;
    let needs_bootstrap = requires_bootstrap(&spec, &guest_runtime);
    let spec_changed = reconcile_cidata_disk(&mut spec, needs_bootstrap);

    rebuild_bootstrap(
        instance_dir,
        &spec,
        network,
        &guest_runtime,
        needs_bootstrap,
    )?;
    if spec_changed {
        write_vm_spec_to_dir(instance_dir, &spec)?;
    }

    Ok(())
}

fn read_vm_spec_from_dir(instance_dir: &Path) -> eyre::Result<VmSpec> {
    let config_path = instance_dir.join(InstanceFile::Config.as_str());
    let raw = std::fs::read_to_string(&config_path)
        .with_context(|| format!("read vm spec at {}", config_path.display()))?;
    serde_yaml_ng::from_str(&raw)
        .map_err(|err| eyre::eyre!("parse vm spec at {}: {}", config_path.display(), err))
}

fn write_vm_spec_to_dir(instance_dir: &Path, spec: &VmSpec) -> eyre::Result<()> {
    let config_path = instance_dir.join(InstanceFile::Config.as_str());
    let config = serde_yaml_ng::to_string(spec)
        .with_context(|| format!("serialize vm spec at {}", config_path.display()))?;
    std::fs::write(&config_path, config)
        .with_context(|| format!("write vm spec at {}", config_path.display()))
}

fn reconcile_cidata_disk(spec: &mut VmSpec, required: bool) -> bool {
    let cidata_disk = Disk {
        path: PathBuf::from(InstanceFile::CidataDisk.as_str()),
        kind: DiskKind::Data,
        read_only: true,
    };
    let mut disks = Vec::with_capacity(spec.storage.disks.len() + usize::from(required));
    let mut found_cidata = false;
    let mut changed = false;

    for disk in &spec.storage.disks {
        if disk.path != cidata_disk.path {
            disks.push(disk.clone());
            continue;
        }

        if required && !found_cidata {
            if disk != &cidata_disk {
                changed = true;
            }
            disks.push(cidata_disk.clone());
            found_cidata = true;
        } else {
            changed = true;
        }
    }

    if required && !found_cidata {
        disks.push(cidata_disk);
        changed = true;
    }

    if changed {
        spec.storage.disks = disks;
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::{render_network_config_for_instance, resolve_guest_runtime_config};
    use bento_core::{
        Architecture, Boot, Disk, DiskKind, GuestOs, GuestSpec, InstanceFile, LifecycleSpec,
        Network, Platform, PluginSpec, Resources, Settings, Storage, VmSpec, VsockEndpointMode,
        VsockEndpointSpec,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn sample_spec(kernel_cmdline: Vec<String>, guest_configured: bool) -> VmSpec {
        VmSpec {
            version: 1,
            name: "devbox".to_string(),
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: Architecture::Aarch64,
            },
            resources: Resources {
                cpus: 4,
                memory_mib: 4096,
            },
            boot: Boot {
                kernel: None,
                initramfs: None,
                kernel_cmdline,
                bootstrap: None,
            },
            storage: Storage { disks: Vec::new() },
            mounts: Vec::new(),
            vsock_endpoints: Vec::new(),
            settings: Settings {
                nested_virtualization: false,
                rosetta: false,
            },
            guest: guest_configured.then_some(GuestSpec::default()),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn network_config_for_libkrun_attachment_matches_generated_mac() {
        let network = Network::UnixDatagram {
            path: PathBuf::from("/run/bento/net.sock"),
            mac: "02:00:00:00:00:01".to_string(),
        };
        let config = render_network_config_for_instance(&network)
            .expect("network config should render")
            .expect("runtime attachment should configure network");

        assert!(config.contains("version: 2"));
        assert!(config.contains("bento:"));
        assert!(config.contains("match:"));
        assert!(config.contains("macaddress:"));
        assert!(!config.contains("set-name"));
        assert!(!config.contains("eth0"));
        assert!(!config.contains("enp0s1"));
        assert!(config.contains("dhcp4: true"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn network_config_for_vz_attachment_matches_generated_mac() {
        let network = Network::UnixDatagram {
            path: PathBuf::from("/run/bento/net.sock"),
            mac: "02:00:00:00:00:01".to_string(),
        };
        let config = render_network_config_for_instance(&network)
            .expect("network config should render")
            .expect("runtime attachment should configure network");

        assert!(config.contains("version: 2"));
        assert!(config.contains("bento:"));
        assert!(config.contains("match:"));
        assert!(config.contains("macaddress:"));
        assert!(!config.contains("driver:"));
        assert!(!config.contains("set-name"));
        assert!(!config.contains("eth0"));
    }

    #[test]
    fn network_config_for_vznat_matches_virtio_net_driver() {
        let config = render_network_config_for_instance(&Network::VzNat { mac: None })
            .expect("network config should render")
            .expect("vznat should configure network");

        assert!(config.contains("version: 2"));
        assert!(config.contains("en*:"));
        assert!(config.contains("match:"));
        assert!(config.contains("driver: virtio_net"));
        assert!(!config.contains("macaddress:"));
        assert!(!config.contains("set-name"));
        assert!(!config.contains("eth0"));
    }

    fn forward_endpoint(port: u32, config: Option<serde_json::Value>) -> VsockEndpointSpec {
        VsockEndpointSpec {
            name: "forward".to_string(),
            port,
            mode: VsockEndpointMode::Connect,
            plugin: PluginSpec {
                command: PathBuf::from("/usr/local/bin/forward"),
                args: Vec::new(),
                env: BTreeMap::new(),
                working_dir: None,
                config,
            },
            lifecycle: LifecycleSpec::default(),
        }
    }

    #[test]
    fn guest_runtime_defaults_to_ssh_and_dns_when_guest_is_enabled() {
        let runtime = resolve_guest_runtime_config(
            &sample_spec(Vec::new(), true),
            &Network::UnixDatagram {
                path: PathBuf::from("/run/bento/net.sock"),
                mac: "02:00:00:00:00:01".to_string(),
            },
        )
        .expect("runtime config should resolve");

        assert!(runtime.ssh.enabled);
        assert!(runtime.dns.enabled);
        assert!(!runtime.forward.enabled);
    }

    #[test]
    fn guest_runtime_disables_dns_but_keeps_ssh_without_guest_networking() {
        let spec = sample_spec(Vec::new(), true);

        let runtime = resolve_guest_runtime_config(&spec, &Network::None)
            .expect("runtime config should resolve");

        assert!(runtime.ssh.enabled);
        assert!(!runtime.dns.enabled);
        assert!(!runtime.forward.enabled);
    }

    #[test]
    fn guest_runtime_disables_ssh_dns_and_forward_when_guest_is_disabled() {
        let runtime = resolve_guest_runtime_config(&sample_spec(Vec::new(), false), &Network::None)
            .expect("runtime config should resolve");

        assert!(!runtime.ssh.enabled);
        assert!(!runtime.dns.enabled);
        assert!(!runtime.forward.enabled);
    }

    #[test]
    fn guest_runtime_enables_forward_from_named_endpoint() {
        let mut spec = sample_spec(Vec::new(), true);
        spec.vsock_endpoints.push(forward_endpoint(4100, None));

        let runtime = resolve_guest_runtime_config(&spec, &Network::None)
            .expect("runtime config should resolve");

        assert!(runtime.forward.enabled);
        assert_eq!(runtime.forward.port, 4100);
        assert!(runtime.forward.uds.is_empty());
    }

    #[test]
    fn guest_runtime_injects_forward_uds_guest_paths() {
        let mut spec = sample_spec(Vec::new(), true);
        spec.vsock_endpoints.push(forward_endpoint(
            4100,
            Some(json!({
                "tcp": {
                    "auto_discover": true,
                    "ports": [
                        { "guest_port": 8080, "host_port": 8080 }
                    ]
                },
                "uds": [
                    { "guest_path": "/var/run/docker.sock", "host_path": "docker.sock" },
                    { "guest_path": "/tmp/app.sock", "host_path": "app.sock" }
                ]
            })),
        ));

        let runtime = resolve_guest_runtime_config(&spec, &Network::None)
            .expect("runtime config should resolve");

        assert_eq!(
            runtime
                .forward
                .uds
                .iter()
                .map(|uds| uds.guest_path.as_str())
                .collect::<Vec<_>>(),
            vec!["/var/run/docker.sock", "/tmp/app.sock"]
        );
    }

    #[test]
    fn guest_runtime_ignores_forward_endpoint_when_guest_is_disabled() {
        let mut spec = sample_spec(Vec::new(), false);
        spec.vsock_endpoints.push(forward_endpoint(4100, None));

        let runtime = resolve_guest_runtime_config(&spec, &Network::None)
            .expect("runtime config should resolve");

        assert!(!runtime.forward.enabled);
        assert_eq!(runtime.forward.port, 0);
        assert!(runtime.forward.uds.is_empty());
    }

    #[test]
    fn cidata_disk_reconciliation_adds_read_only_data_disk() {
        let mut spec = sample_spec(Vec::new(), true);

        assert!(super::reconcile_cidata_disk(&mut spec, true));
        assert_eq!(
            spec.storage.disks,
            vec![Disk {
                path: PathBuf::from(InstanceFile::CidataDisk.as_str()),
                kind: DiskKind::Data,
                read_only: true,
            }]
        );
        assert!(!super::reconcile_cidata_disk(&mut spec, true));
    }

    #[test]
    fn cidata_disk_reconciliation_removes_managed_disk() {
        let mut spec = sample_spec(Vec::new(), false);
        spec.storage.disks.push(Disk {
            path: PathBuf::from("data.img"),
            kind: DiskKind::Data,
            read_only: false,
        });
        spec.storage.disks.push(Disk {
            path: PathBuf::from(InstanceFile::CidataDisk.as_str()),
            kind: DiskKind::Data,
            read_only: true,
        });

        assert!(super::reconcile_cidata_disk(&mut spec, false));
        assert_eq!(
            spec.storage.disks,
            vec![Disk {
                path: PathBuf::from("data.img"),
                kind: DiskKind::Data,
                read_only: false,
            }]
        );
        assert!(!super::reconcile_cidata_disk(&mut spec, false));
    }
}

fn resolve_guest_runtime_config(spec: &VmSpec, network: &Network) -> eyre::Result<AgentConfig> {
    Ok(AgentConfig {
        ssh: AgentSshConfig {
            enabled: spec.guest_agent().is_some(),
        },
        dns: AgentDnsConfig {
            enabled: spec.guest_agent().is_some() && !matches!(network, Network::None),
            ..AgentDnsConfig::default()
        },
        forward: resolve_forward_runtime_config(spec)?,
    })
}

fn resolve_forward_runtime_config(spec: &VmSpec) -> eyre::Result<AgentForwardConfig> {
    if spec.guest_agent().is_none() {
        return Ok(AgentForwardConfig::default());
    }

    let Some(endpoint) = spec
        .vsock_endpoints
        .iter()
        .find(|endpoint| endpoint.name == FORWARD_ENDPOINT_NAME)
    else {
        return Ok(AgentForwardConfig::default());
    };

    let config = endpoint
        .plugin
        .config
        .clone()
        .map(serde_json::from_value::<ForwardPluginAgentConfig>)
        .transpose()
        .context("decode forward endpoint plugin config")?
        .unwrap_or_default();

    Ok(AgentForwardConfig {
        enabled: true,
        port: endpoint.port,
        uds: config
            .uds
            .into_iter()
            .map(|uds| AgentUdsForwardConfig {
                guest_path: uds.guest_path,
            })
            .collect(),
    })
}

fn requires_bootstrap(spec: &VmSpec, guest_runtime: &AgentConfig) -> bool {
    spec.boot.bootstrap.is_some()
        || guest_runtime.ssh.enabled
        || guest_runtime.dns.enabled
        || guest_runtime.forward.enabled
        || spec.settings.rosetta
}

fn rebuild_bootstrap(
    instance_dir: &Path,
    spec: &VmSpec,
    network: &Network,
    guest_runtime: &AgentConfig,
    required: bool,
) -> eyre::Result<()> {
    let iso_path = instance_dir.join(InstanceFile::CidataDisk.as_str());
    if !required {
        if iso_path.exists() {
            std::fs::remove_file(&iso_path)
                .with_context(|| format!("remove stale cidata {}", iso_path.display()))?;
        }
        return Ok(());
    }

    let host_user = host_user::current_host_user().context("resolve current host user")?;
    let user_keys = ssh_keys::ensure_user_ssh_keys().context("ensure user SSH keys")?;

    build_cidata_disk(
        instance_dir,
        spec,
        &host_user,
        &user_keys.public_key_openssh,
        network,
        guest_runtime,
    )
}

fn build_cidata_disk(
    instance_dir: &Path,
    spec: &VmSpec,
    host_user: &HostUser,
    ssh_public_key: &str,
    network: &Network,
    guest_runtime: &AgentConfig,
) -> eyre::Result<()> {
    let global_config = GlobalConfig::load()?;
    let agent_binary_path = ensure_guest_binary(&global_config)?;
    let guest_agent_binary = std::fs::read(agent_binary_path)
        .with_context(|| format!("read guest agent binary {}", agent_binary_path.display()))?;

    let user_data = render_user_data(spec, host_user, ssh_public_key)?;
    let meta_data = render_meta_data(&spec.name)?;
    let network_config = render_network_config_for_instance(network)?;
    let agent_config = render_agent_config(guest_runtime)?;
    let config_env = render_config_env(spec)?;
    let iso_path = instance_dir.join(InstanceFile::CidataDisk.as_str());

    let mut files = vec![
        CidataEntry {
            name: "user-data".to_string(),
            contents: user_data.into_bytes(),
        },
        CidataEntry {
            name: "meta-data".to_string(),
            contents: meta_data.into_bytes(),
        },
        CidataEntry {
            name: GUEST_AGENT_CIDATA_ENTRY.to_string(),
            contents: guest_agent_binary,
        },
        CidataEntry {
            name: GUEST_AGENT_INSTALL_SCRIPT_ENTRY.to_string(),
            contents: GUEST_INSTALL_SCRIPT_CONTENT.as_bytes().to_vec(),
        },
        CidataEntry {
            name: GUEST_AGENT_CONFIG_ENTRY.to_string(),
            contents: agent_config.into_bytes(),
        },
        CidataEntry {
            name: GUEST_AGENT_CONFIG_ENV_ENTRY.to_string(),
            contents: config_env.into_bytes(),
        },
        CidataEntry {
            name: "tasks/10-register-agent.sh".to_string(),
            contents: TASK_REGISTER_AGENT_CONTENT.as_bytes().to_vec(),
        },
    ];

    if spec.settings.rosetta {
        files.push(CidataEntry {
            name: "tasks/20-setup-rosetta.sh".to_string(),
            contents: TASK_SETUP_ROSETTA_CONTENT.as_bytes().to_vec(),
        });
    }

    if let Some(network_config) = network_config {
        files.push(CidataEntry {
            name: "network-config".to_string(),
            contents: network_config.into_bytes(),
        });
    }

    write_cidata_fat_image(&iso_path, &files)
        .with_context(|| format!("build cidata disk at {}", iso_path.display()))?;

    Ok(())
}

fn write_cidata_fat_image(output_path: &Path, entries: &[CidataEntry]) -> eyre::Result<()> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    if output_path.exists() {
        std::fs::remove_file(output_path)
            .with_context(|| format!("remove existing output {}", output_path.display()))?;
    }

    let mut image = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(output_path)
        .with_context(|| format!("create cidata image {}", output_path.display()))?;
    image
        .set_len(cidata_image_size(entries))
        .with_context(|| format!("size cidata image {}", output_path.display()))?;

    let mut label = [b' '; 11];
    label[..CIDATA_VOLUME_LABEL.len()].copy_from_slice(CIDATA_VOLUME_LABEL.as_bytes());
    format_volume(&mut image, FormatVolumeOptions::new().volume_label(label))
        .context("format cidata FAT volume")?;
    image.rewind().context("rewind cidata image after format")?;

    let fs = FileSystem::new(image, FsOptions::new()).context("mount cidata FAT volume")?;
    let root = fs.root_dir();
    for entry in entries {
        write_cidata_entry(&root, entry)
            .with_context(|| format!("write cidata entry {}", entry.name))?;
    }

    drop(root);
    fs.unmount().context("flush cidata FAT volume")?;
    Ok(())
}

fn cidata_image_size(entries: &[CidataEntry]) -> u64 {
    let payload_bytes = entries
        .iter()
        .map(|entry| entry.contents.len() as u64 + entry.name.len() as u64)
        .sum::<u64>();
    (payload_bytes + CIDATA_SIZE_OVERHEAD_BYTES).max(CIDATA_MIN_SIZE_BYTES)
}

fn write_cidata_entry(
    root: &fatfs::Dir<'_, std::fs::File>,
    entry: &CidataEntry,
) -> eyre::Result<()> {
    let mut parts = entry.name.split('/').peekable();
    let mut current = root.clone();

    while let Some(part) = parts.next() {
        if parts.peek().is_some() {
            current = match current.open_dir(part) {
                Ok(dir) => dir,
                Err(err) if err.kind() == io::ErrorKind::NotFound => current
                    .create_dir(part)
                    .with_context(|| format!("create cidata directory {part}"))?,
                Err(err) => {
                    return Err(err).with_context(|| format!("open cidata directory {part}"))
                }
            };
        } else {
            let mut file = current
                .create_file(part)
                .with_context(|| format!("create cidata file {part}"))?;
            file.truncate().context("truncate cidata file")?;
            file.write_all(&entry.contents)
                .with_context(|| format!("write cidata file {part}"))?;
            file.flush().context("flush cidata file")?;
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct CloudConfig {
    users: Vec<CloudUser>,
    growpart: GrowpartConfig,
    resize_rootfs: bool,
    timezone: String,
    locale: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<[String; 6]>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    write_files: Vec<WriteFile>,
}

#[derive(Serialize)]
struct GrowpartConfig {
    mode: String,
    devices: Vec<String>,
}

#[derive(Serialize)]
struct CloudUser {
    name: String,
    uid: u32,
    gecos: String,
    homedir: String,
    shell: String,
    sudo: String,
    lock_passwd: bool,
    ssh_authorized_keys: Vec<String>,
}

#[derive(Serialize)]
struct WriteFile {
    path: String,
    owner: String,
    permissions: String,
    content: String,
}

#[derive(Serialize)]
struct MetaData {
    #[serde(rename = "instance-id")]
    instance_id: String,
    #[serde(rename = "local-hostname")]
    local_hostname: String,
}

#[derive(Serialize)]
struct NetworkConfigV2 {
    version: u8,
    ethernets: BTreeMap<String, EthernetConfigV2>,
}

#[derive(Serialize)]
struct EthernetConfigV2 {
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    matches: Option<EthernetMatchConfigV2>,
    dhcp4: bool,
    dhcp6: bool,
}

#[derive(Serialize)]
struct EthernetMatchConfigV2 {
    #[serde(skip_serializing_if = "Option::is_none")]
    driver: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    macaddress: Option<String>,
}

fn render_user_data(
    spec: &VmSpec,
    host_user: &HostUser,
    ssh_public_key: &str,
) -> eyre::Result<String> {
    let cloud_config = CloudConfig {
        users: vec![CloudUser {
            name: host_user.name.clone(),
            uid: host_user.uid,
            gecos: host_user.gecos.clone(),
            homedir: format!("/home/{}", host_user.name),
            shell: "/bin/bash".to_string(),
            sudo: "ALL=(ALL) NOPASSWD:ALL".to_string(),
            lock_passwd: true,
            ssh_authorized_keys: vec![ssh_public_key.trim().to_string()],
        }],
        growpart: GrowpartConfig {
            mode: "auto".to_string(),
            devices: vec!["/".to_string()],
        },
        resize_rootfs: true,
        timezone: resolve_host_timezone(),
        locale: resolve_host_locale(),
        mounts: cloud_mount_entries(spec),
        write_files: vec![WriteFile {
            path: GUEST_AGENT_BOOTSTRAP_SCRIPT.to_string(),
            owner: "root:root".to_string(),
            permissions: "0755".to_string(),
            content: GUEST_BOOTSTRAP_SCRIPT_CONTENT.to_string(),
        }],
    };
    let mut bento_yaml = String::from("#cloud-config\n");
    bento_yaml.push_str(
        &serde_yaml_ng::to_string(&cloud_config).context("serialize cloud-init user-data")?,
    );

    if let Some(userdata_path) = spec
        .boot
        .bootstrap
        .as_ref()
        .and_then(|bootstrap| bootstrap.cloud_init.as_deref())
    {
        let user_data = std::fs::read_to_string(userdata_path)
            .with_context(|| format!("read userdata {}", userdata_path.display()))?;
        return Ok(render_multipart_user_data(&bento_yaml, &user_data));
    }

    Ok(bento_yaml)
}

fn render_multipart_user_data(bento_user_data: &str, user_data: &str) -> String {
    let boundary = "===============bento-userdata==";
    format!(
        "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"{boundary}\"\n\n--{boundary}\nContent-Type: text/cloud-config; charset=\"us-ascii\"\n\n{bento_user_data}\n--{boundary}\nContent-Type: {user_content_type}; charset=\"us-ascii\"\n\n{user_data}\n--{boundary}--\n",
        boundary = boundary,
        bento_user_data = bento_user_data.trim_end(),
        user_content_type = detect_userdata_content_type(user_data),
        user_data = user_data.trim_end(),
    )
}

fn detect_userdata_content_type(user_data: &str) -> &'static str {
    let trimmed = user_data.trim_start();
    if trimmed.starts_with("#cloud-config") {
        "text/cloud-config"
    } else if trimmed.starts_with("#!") {
        "text/x-shellscript"
    } else {
        "text/plain"
    }
}

fn render_network_config(interface: GuestNetworkInterface) -> eyre::Result<String> {
    let mut ethernets = BTreeMap::new();
    let (id, matches) = match interface {
        GuestNetworkInterface::Driver { driver } => (
            "en*".to_string(),
            Some(EthernetMatchConfigV2 {
                driver: Some(driver),
                macaddress: None,
            }),
        ),
        GuestNetworkInterface::Mac { mac } => (
            "bento".to_string(),
            Some(EthernetMatchConfigV2 {
                driver: None,
                macaddress: Some(format_mac(mac)),
            }),
        ),
    };
    ethernets.insert(
        id,
        EthernetConfigV2 {
            matches,
            dhcp4: true,
            dhcp6: false,
        },
    );

    let cfg = NetworkConfigV2 {
        version: 2,
        ethernets,
    };
    serde_yaml_ng::to_string(&cfg).context("serialize cloud-init network-config")
}

enum GuestNetworkInterface {
    Driver { driver: &'static str },
    Mac { mac: [u8; 6] },
}

fn render_network_config_for_instance(network: &Network) -> eyre::Result<Option<String>> {
    match network {
        Network::None => Ok(None),
        Network::VzNat { .. } => render_network_config(GuestNetworkInterface::Driver {
            driver: "virtio_net",
        })
        .map(Some),
        Network::UnixDatagram { mac, .. }
        | Network::UnixStream { mac, .. }
        | Network::Tap { mac, .. } => render_network_config(GuestNetworkInterface::Mac {
            mac: parse_mac_string(mac)?,
        })
        .map(Some),
    }
}

fn parse_mac_string(mac: &str) -> eyre::Result<[u8; 6]> {
    bento_utils::parse_mac(mac).map_err(|err| eyre::eyre!("parse MAC address {:?}: {err}", mac))
}

fn render_meta_data(name: &str) -> eyre::Result<String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    nonce.hash(&mut hasher);
    let hash = hasher.finish();

    let metadata = MetaData {
        instance_id: format!("bento-{:08x}", (hash >> 32) as u32),
        local_hostname: name.to_string(),
    };
    serde_yaml_ng::to_string(&metadata).context("serialize cloud-init meta-data")
}

fn cloud_mount_entries(spec: &VmSpec) -> Vec<[String; 6]> {
    mounts(spec)
        .iter()
        .map(|mount| {
            let path = resolve_mount_location(&mount.source)
                .unwrap_or_else(|_| mount.source.clone())
                .to_string_lossy()
                .to_string();
            [
                mount.tag.clone(),
                path,
                "virtiofs".to_string(),
                if mount.writable {
                    "rw,nofail".to_string()
                } else {
                    "ro,nofail".to_string()
                },
                "0".to_string(),
                "0".to_string(),
            ]
        })
        .collect()
}

fn mounts(spec: &VmSpec) -> Vec<MonitorMount> {
    spec.mounts
        .iter()
        .map(|mount| MonitorMount {
            source: mount.source.clone(),
            tag: mount.tag.clone(),
            writable: !mount.read_only,
        })
        .collect()
}

fn render_agent_config(guest_runtime: &AgentConfig) -> eyre::Result<String> {
    serde_yaml_ng::to_string(guest_runtime).context("serialize agent config")
}

fn render_config_env(spec: &VmSpec) -> eyre::Result<String> {
    let mut env = String::new();

    env.push_str(&format!(
        "BENTO_INSTANCE_NAME={}\n",
        shell_quote(&spec.name)
    ));
    env.push_str("BENTO_AGENT_CONFIG_PATH=/etc/bento/agent.yaml\n");
    env.push_str(&format!(
        "BENTO_ROSETTA={}\n",
        if spec.settings.rosetta {
            "true"
        } else {
            "false"
        }
    ));

    Ok(env)
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn resolve_host_timezone() -> String {
    if let Ok(tz) = std::env::var("TZ") {
        let trimmed = tz.trim();
        if !trimmed.is_empty() {
            return trimmed.trim_start_matches(':').to_string();
        }
    }

    if let Ok(localtime_target) = std::fs::read_link("/etc/localtime") {
        let rendered = localtime_target.to_string_lossy();
        if let Some((_, timezone)) = rendered.split_once("zoneinfo/") {
            let timezone = timezone.trim_matches('/');
            if !timezone.is_empty() {
                return timezone.to_string();
            }
        }
    }

    if let Ok(contents) = std::fs::read_to_string("/etc/timezone") {
        if let Some(first_line) = contents.lines().next() {
            let timezone = first_line.trim();
            if !timezone.is_empty() {
                return timezone.to_string();
            }
        }
    }

    "UTC".to_string()
}

fn resolve_host_locale() -> String {
    for var in ["LC_ALL", "LANG"] {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    "en_US.UTF-8".to_string()
}
