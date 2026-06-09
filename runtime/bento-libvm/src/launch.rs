use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bento_core::agent::{
    AgentConfig, AgentDnsConfig, AgentForwardConfig, AgentSshConfig, AgentUdsForwardConfig,
    CertificateAuthorityConfig, MountConfig as ProvisionMountConfig,
    NetworkConfig as ProvisionNetworkConfig, NetworkInterfaceConfig, NetworkMatchConfig,
    ProvisionConfig, ResizeRootfsConfig, UserConfig, UserdataConfig, UserdataContentType,
};
use bento_core::{Disk, DiskKind, VmSpec};
use bento_utils::format_mac;
use eyre::Context;
use fatfs::{format_volume, FileSystem, FormatVolumeOptions, FsOptions};
use serde::{Deserialize, Serialize};

use crate::certificate_authority;
use crate::global_config::{ensure_guest_binary, GlobalConfig};
use crate::host_user::{self, HostUser};
use crate::network::RuntimeNetwork;
use crate::ssh_keys;
use crate::{resolve_mount_location, InstanceFile, Layout};

const GUEST_AGENT_CIDATA_ENTRY: &str = "bento-agent";
const GUEST_AGENT_INSTALL_SCRIPT_ENTRY: &str = "bento-install-guest-agent.sh";
const GUEST_AGENT_CONFIG_ENTRY: &str = "bento-agent.yaml";
const GUEST_AGENT_CONFIG_ENV_ENTRY: &str = "config.env";
const CLOUD_INIT_BOOTSTRAP_SCRIPT_PATH: &str =
    "/var/lib/cloud/scripts/per-boot/00-bento.bootstrap.sh";
const GUEST_BOOTSTRAP_SCRIPT_CONTENT: &str = include_str!("../scripts/guest-bootstrap.sh");
const GUEST_INSTALL_SCRIPT_CONTENT: &str = include_str!("../scripts/guest-install.sh");
const TASK_REGISTER_AGENT_CONTENT: &str = include_str!("../scripts/tasks/10-register-agent.sh");
const TASK_SETUP_ROSETTA_CONTENT: &str = include_str!("../scripts/tasks/20-setup-rosetta.sh");
const FORWARD_ENDPOINT_NAME: &str = "forward";
const CIDATA_VOLUME_LABEL: &str = "CIDATA";
const CIDATA_MIN_SIZE_BYTES: u64 = 16 * 1024 * 1024;
const CIDATA_SIZE_OVERHEAD_BYTES: u64 = 4 * 1024 * 1024;
const GUEST_CERTIFICATE_AUTHORITY_PATH: &str = "/usr/local/share/ca-certificates/bento-ca.crt";

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

pub(crate) fn prepare_instance_runtime(
    layout: &Layout,
    instance_dir: &Path,
    name: &str,
    spec: &mut VmSpec,
    network: &RuntimeNetwork,
) -> eyre::Result<()> {
    let guest_runtime = resolve_guest_runtime_config(spec, network)?;
    ensure_cidata_disk(spec);
    normalize_runtime_mounts(spec)?;

    build_cidata_disk(layout, instance_dir, name, spec, network, &guest_runtime)?;
    write_vm_spec_to_dir(instance_dir, spec)?;

    Ok(())
}

fn normalize_runtime_mounts(spec: &mut VmSpec) -> eyre::Result<()> {
    for mount in &mut spec.mounts {
        let resolved = resolve_mount_location(&mount.source)
            .map_err(eyre::Report::msg)
            .with_context(|| format!("resolve mount source {}", mount.source.display()))?;
        mount.source = if resolved.is_absolute() {
            resolved
        } else {
            std::env::current_dir()
                .context("resolve current directory for relative mount source")?
                .join(resolved)
        };
    }

    Ok(())
}

fn write_vm_spec_to_dir(instance_dir: &Path, spec: &VmSpec) -> eyre::Result<()> {
    let config_path = instance_dir.join(InstanceFile::Config.as_str());
    let config = serde_yaml_ng::to_string(spec)
        .with_context(|| format!("serialize vm spec at {}", config_path.display()))?;
    std::fs::write(&config_path, config)
        .with_context(|| format!("write vm spec at {}", config_path.display()))
}

fn ensure_cidata_disk(spec: &mut VmSpec) -> bool {
    let cidata_disk = Disk {
        path: PathBuf::from(InstanceFile::CidataDisk.as_str()),
        kind: DiskKind::Data,
        read_only: true,
    };
    let mut disks = Vec::with_capacity(spec.storage.disks.len() + 1);
    let mut found_cidata = false;
    let mut changed = false;

    for disk in &spec.storage.disks {
        if disk.path != cidata_disk.path {
            disks.push(disk.clone());
            continue;
        }

        if !found_cidata {
            if disk != &cidata_disk {
                changed = true;
            }
            disks.push(cidata_disk.clone());
            found_cidata = true;
        } else {
            changed = true;
        }
    }

    if !found_cidata {
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
    use super::{
        normalize_runtime_mounts, render_cloud_init_user_data, resolve_guest_runtime_config,
    };
    use bento_core::{
        agent::{AgentConfig, UserdataContentType},
        Architecture, Boot, Bootstrap, Disk, DiskKind, GuestOs, LifecycleSpec, Mount, Platform,
        PluginSpec, Resources, Settings, Storage, VmSpec, VsockEndpointMode, VsockEndpointSpec,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::host_user::HostUser;
    use crate::network::RuntimeNetwork;
    use crate::InstanceFile;

    fn sample_spec(kernel_cmdline: Vec<String>, guest_configured: bool) -> VmSpec {
        VmSpec {
            version: 1,
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
                agent: guest_configured,
            },
        }
    }

    #[test]
    fn normalize_runtime_mounts_resolves_sources() {
        let mut spec = sample_spec(Vec::new(), false);
        spec.mounts = vec![Mount {
            source: PathBuf::from("workspace"),
            tag: "workspace".to_string(),
            read_only: false,
        }];

        normalize_runtime_mounts(&mut spec).expect("normalize runtime mounts");

        assert!(spec.mounts[0].source.is_absolute());
        assert!(spec.mounts[0].source.ends_with("workspace"));
    }

    #[test]
    fn normalize_runtime_mounts_rejects_unsupported_tilde_forms() {
        let mut spec = sample_spec(Vec::new(), false);
        spec.mounts = vec![Mount {
            source: PathBuf::from("~somebody"),
            tag: "bad".to_string(),
            read_only: false,
        }];

        let err =
            normalize_runtime_mounts(&mut spec).expect_err("unsupported tilde form should fail");

        assert!(err
            .root_cause()
            .to_string()
            .contains("only '~' and '~/...'"));
    }

    #[test]
    fn provision_network_for_vznat_matches_virtio_net_driver() {
        let config = super::resolve_provision_network_config(&RuntimeNetwork::VzNat { mac: None })
            .expect("network provision config should render");

        assert_eq!(config.interfaces.len(), 1);
        assert_eq!(config.interfaces[0].name, "en");
        assert_eq!(
            config.interfaces[0].matches.driver.as_deref(),
            Some("virtio_net")
        );
        assert!(config.interfaces[0].matches.mac_address.is_none());
        assert!(config.interfaces[0].dhcp4);
        assert!(!config.interfaces[0].dhcp6);
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
            &RuntimeNetwork::UnixDatagram {
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

        let runtime = resolve_guest_runtime_config(&spec, &RuntimeNetwork::None)
            .expect("runtime config should resolve");

        assert!(runtime.ssh.enabled);
        assert!(!runtime.dns.enabled);
        assert!(!runtime.forward.enabled);
    }

    #[test]
    fn guest_runtime_disables_ssh_dns_and_forward_when_guest_is_disabled() {
        let runtime =
            resolve_guest_runtime_config(&sample_spec(Vec::new(), false), &RuntimeNetwork::None)
                .expect("runtime config should resolve");

        assert!(!runtime.ssh.enabled);
        assert!(!runtime.dns.enabled);
        assert!(!runtime.forward.enabled);
    }

    #[test]
    fn cloud_init_user_data_only_bootstraps_agent_transport() {
        let user_data = render_cloud_init_user_data().expect("render user-data");

        assert!(user_data.contains("#cloud-config"));
        assert!(user_data.contains("/var/lib/cloud/scripts/per-boot/00-bento.bootstrap.sh"));
        assert!(user_data.contains("bento guest agent cidata device not found"));
        assert!(!user_data.contains("users:"));
        assert!(!user_data.contains("growpart:"));
        assert!(!user_data.contains("resize_rootfs:"));
        assert!(!user_data.contains("timezone:"));
        assert!(!user_data.contains("locale:"));
        assert!(!user_data.contains("mounts:"));
        assert!(!user_data.contains("/usr/local/share/ca-certificates/bento-ca.crt"));
        assert!(!user_data.contains("update-ca-certificates"));
    }

    #[test]
    fn provision_config_includes_shell_userdata_script() {
        let host_user = HostUser {
            name: "bento".to_string(),
            uid: 1000,
            gecos: "Bento User".to_string(),
        };
        let mut spec = sample_spec(Vec::new(), false);
        spec.boot.bootstrap = Some(Bootstrap {
            userdata: Some("#!/bin/sh\necho profile\n".to_string()),
        });

        let provision = super::resolve_provision_config(
            "demo",
            &spec,
            &RuntimeNetwork::None,
            &host_user,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBento",
            "-----BEGIN CERTIFICATE-----\nMIIBENTO\n-----END CERTIFICATE-----\n",
        )
        .expect("resolve provision config");

        let userdata = provision.userdata.expect("userdata config");
        assert_eq!(userdata.content_type, UserdataContentType::ShellScript);
        assert!(userdata.content.contains("#!/bin/sh"));
        assert!(userdata.content.contains("echo profile"));
    }

    #[test]
    fn provision_config_rejects_cloud_config_userdata() {
        let host_user = HostUser {
            name: "bento".to_string(),
            uid: 1000,
            gecos: "Bento User".to_string(),
        };
        let mut spec = sample_spec(Vec::new(), false);
        spec.boot.bootstrap = Some(Bootstrap {
            userdata: Some("#cloud-config\nruncmd:\n  - echo external\n".to_string()),
        });

        let err = super::resolve_provision_config(
            "demo",
            &spec,
            &RuntimeNetwork::None,
            &host_user,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBento",
            "-----BEGIN CERTIFICATE-----\nMIIBENTO\n-----END CERTIFICATE-----\n",
        )
        .expect_err("cloud-config userdata should be rejected");

        assert!(err
            .to_string()
            .contains("only supports shell-script userdata"));
    }

    #[test]
    fn provision_config_captures_current_cloud_init_inputs() {
        let host_user = HostUser {
            name: "bento".to_string(),
            uid: 1000,
            gecos: "Bento User".to_string(),
        };
        let mut spec = sample_spec(Vec::new(), true);
        spec.mounts.push(Mount {
            source: PathBuf::from("/workspace"),
            tag: "workspace".to_string(),
            read_only: false,
        });
        spec.boot.bootstrap = Some(Bootstrap {
            userdata: Some("#!/bin/sh\necho profile\n".to_string()),
        });

        let provision = super::resolve_provision_config(
            "demo",
            &spec,
            &RuntimeNetwork::UnixDatagram {
                path: PathBuf::from("/run/bento/net.sock"),
                mac: "02:00:00:00:00:01".to_string(),
            },
            &host_user,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBento",
            "-----BEGIN CERTIFICATE-----\nMIIBENTO\n-----END CERTIFICATE-----\n",
        )
        .expect("resolve provision config");

        assert!(provision.enabled);
        assert_eq!(provision.hostname.as_deref(), Some("demo"));
        assert_eq!(provision.users[0].name, "bento");
        assert_eq!(provision.users[0].ssh_authorized_keys.len(), 1);
        assert!(provision.resize_rootfs.enabled);
        assert_eq!(provision.mounts[0].tag, "workspace");
        assert_eq!(provision.mounts[0].path, "/workspace");
        assert_eq!(provision.network.interfaces[0].name, "bento");
        assert_eq!(
            provision.network.interfaces[0]
                .matches
                .mac_address
                .as_deref(),
            Some("02:00:00:00:00:01")
        );
        assert_eq!(
            provision
                .userdata
                .as_ref()
                .map(|userdata| &userdata.content_type),
            Some(&UserdataContentType::ShellScript)
        );
        assert!(provision
            .certificate_authority
            .as_ref()
            .expect("certificate authority")
            .pem
            .ends_with('\n'));

        let rendered = super::render_agent_config(&AgentConfig {
            provision,
            ..AgentConfig::default()
        })
        .expect("render agent config");
        assert!(rendered.contains("provision:"));
        assert!(rendered.contains("enabled: true"));
        assert!(rendered.contains("resize_rootfs:"));
        assert!(rendered.contains("interfaces:"));
    }

    #[test]
    fn guest_runtime_enables_forward_from_named_endpoint() {
        let mut spec = sample_spec(Vec::new(), true);
        spec.vsock_endpoints.push(forward_endpoint(4100, None));

        let runtime = resolve_guest_runtime_config(&spec, &RuntimeNetwork::None)
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

        let runtime = resolve_guest_runtime_config(&spec, &RuntimeNetwork::None)
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

        let runtime = resolve_guest_runtime_config(&spec, &RuntimeNetwork::None)
            .expect("runtime config should resolve");

        assert!(!runtime.forward.enabled);
        assert_eq!(runtime.forward.port, 0);
        assert!(runtime.forward.uds.is_empty());
    }

    #[test]
    fn cidata_disk_reconciliation_adds_read_only_data_disk() {
        let mut spec = sample_spec(Vec::new(), true);

        assert!(super::ensure_cidata_disk(&mut spec));
        assert_eq!(
            spec.storage.disks,
            vec![Disk {
                path: PathBuf::from(InstanceFile::CidataDisk.as_str()),
                kind: DiskKind::Data,
                read_only: true,
            }]
        );
        assert!(!super::ensure_cidata_disk(&mut spec));
    }

    #[test]
    fn cidata_disk_reconciliation_canonicalizes_existing_managed_disk() {
        let mut spec = sample_spec(Vec::new(), false);
        spec.storage.disks.push(Disk {
            path: PathBuf::from("data.img"),
            kind: DiskKind::Data,
            read_only: false,
        });
        spec.storage.disks.push(Disk {
            path: PathBuf::from(InstanceFile::CidataDisk.as_str()),
            kind: DiskKind::Data,
            read_only: false,
        });
        spec.storage.disks.push(Disk {
            path: PathBuf::from(InstanceFile::CidataDisk.as_str()),
            kind: DiskKind::Data,
            read_only: true,
        });

        assert!(super::ensure_cidata_disk(&mut spec));
        assert_eq!(
            spec.storage.disks,
            vec![
                Disk {
                    path: PathBuf::from("data.img"),
                    kind: DiskKind::Data,
                    read_only: false,
                },
                Disk {
                    path: PathBuf::from(InstanceFile::CidataDisk.as_str()),
                    kind: DiskKind::Data,
                    read_only: true,
                }
            ]
        );
        assert!(!super::ensure_cidata_disk(&mut spec));
    }
}

fn resolve_guest_runtime_config(
    spec: &VmSpec,
    network: &RuntimeNetwork,
) -> eyre::Result<AgentConfig> {
    Ok(AgentConfig {
        ssh: AgentSshConfig {
            enabled: spec.settings.agent,
        },
        dns: AgentDnsConfig {
            enabled: spec.settings.agent && !matches!(network, RuntimeNetwork::None),
            ..AgentDnsConfig::default()
        },
        forward: resolve_forward_runtime_config(spec)?,
        provision: ProvisionConfig::default(),
    })
}

fn resolve_forward_runtime_config(spec: &VmSpec) -> eyre::Result<AgentForwardConfig> {
    if !spec.settings.agent {
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

fn resolve_provision_config(
    name: &str,
    spec: &VmSpec,
    network: &RuntimeNetwork,
    host_user: &HostUser,
    ssh_public_key: &str,
    certificate_authority_pem: &str,
) -> eyre::Result<ProvisionConfig> {
    Ok(ProvisionConfig {
        enabled: true,
        hostname: Some(name.to_string()),
        timezone: Some(resolve_host_timezone()),
        locale: Some(resolve_host_locale()),
        resize_rootfs: ResizeRootfsConfig { enabled: true },
        users: vec![UserConfig {
            name: host_user.name.clone(),
            uid: host_user.uid,
            gecos: host_user.gecos.clone(),
            home: format!("/home/{}", host_user.name),
            shell: "/bin/bash".to_string(),
            sudo: "ALL=(ALL) NOPASSWD:ALL".to_string(),
            lock_passwd: true,
            ssh_authorized_keys: vec![ssh_public_key.trim().to_string()],
        }],
        certificate_authority: Some(CertificateAuthorityConfig {
            path: GUEST_CERTIFICATE_AUTHORITY_PATH.to_string(),
            pem: pem_with_trailing_newline(certificate_authority_pem),
            update_trust: true,
        }),
        network: resolve_provision_network_config(network)?,
        mounts: provision_mount_entries(spec),
        userdata: provision_userdata(spec)?,
        ..ProvisionConfig::default()
    })
}

fn provision_userdata(spec: &VmSpec) -> eyre::Result<Option<UserdataConfig>> {
    let Some(user_data) = spec
        .boot
        .bootstrap
        .as_ref()
        .and_then(|boot| boot.userdata.as_deref())
    else {
        return Ok(None);
    };

    let content_type = match detect_userdata_content_type(user_data) {
        "text/x-shellscript" => UserdataContentType::ShellScript,
        other => {
            eyre::bail!(
                "agent provisioning only supports shell-script userdata right now; got {other}"
            )
        }
    };

    Ok(Some(UserdataConfig {
        content: user_data.to_string(),
        content_type,
    }))
}

fn resolve_provision_network_config(
    network: &RuntimeNetwork,
) -> eyre::Result<ProvisionNetworkConfig> {
    let interfaces = match network {
        RuntimeNetwork::None => Vec::new(),
        RuntimeNetwork::VzNat { .. } => vec![NetworkInterfaceConfig {
            name: "en".to_string(),
            matches: NetworkMatchConfig {
                driver: Some("virtio_net".to_string()),
                mac_address: None,
            },
            dhcp4: true,
            dhcp6: false,
        }],
        RuntimeNetwork::UnixDatagram { mac, .. }
        | RuntimeNetwork::UnixStream { mac, .. }
        | RuntimeNetwork::Tap { mac, .. } => vec![NetworkInterfaceConfig {
            name: "bento".to_string(),
            matches: NetworkMatchConfig {
                driver: None,
                mac_address: Some(format_mac(parse_mac_string(mac)?)),
            },
            dhcp4: true,
            dhcp6: false,
        }],
    };

    Ok(ProvisionNetworkConfig { interfaces })
}

fn provision_mount_entries(spec: &VmSpec) -> Vec<ProvisionMountConfig> {
    spec.mounts
        .iter()
        .map(|mount| ProvisionMountConfig {
            tag: mount.tag.clone(),
            path: mount.source.to_string_lossy().to_string(),
            fstype: "virtiofs".to_string(),
            options: if mount.read_only {
                vec!["ro".to_string(), "nofail".to_string()]
            } else {
                vec!["rw".to_string(), "nofail".to_string()]
            },
        })
        .collect()
}

fn build_cidata_disk(
    layout: &Layout,
    instance_dir: &Path,
    name: &str,
    spec: &VmSpec,
    network: &RuntimeNetwork,
    guest_runtime: &AgentConfig,
) -> eyre::Result<()> {
    let host_user = host_user::current_host_user().context("resolve current host user")?;
    let user_keys = ssh_keys::ensure_user_ssh_keys().context("ensure user SSH keys")?;
    let global_config = GlobalConfig::load()?;
    let agent_binary_path = ensure_guest_binary(&global_config)?;
    let guest_agent_binary = std::fs::read(agent_binary_path)
        .with_context(|| format!("read guest agent binary {}", agent_binary_path.display()))?;
    let certificate_authority_pem = certificate_authority_pem_for_config(layout, &global_config)?;

    let mut guest_runtime = guest_runtime.clone();
    guest_runtime.provision = resolve_provision_config(
        name,
        spec,
        network,
        &host_user,
        &user_keys.public_key_openssh,
        &certificate_authority_pem,
    )?;

    let user_data = render_cloud_init_user_data()?;
    let meta_data = render_meta_data(name)?;
    let agent_config = render_agent_config(&guest_runtime)?;
    let config_env = render_config_env(name, spec)?;
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
struct CloudInitUserData {
    write_files: Vec<CloudInitWriteFile>,
}

#[derive(Serialize)]
struct CloudInitWriteFile {
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

fn render_cloud_init_user_data() -> eyre::Result<String> {
    let cloud_config = CloudInitUserData {
        write_files: vec![CloudInitWriteFile {
            path: CLOUD_INIT_BOOTSTRAP_SCRIPT_PATH.to_string(),
            owner: "root:root".to_string(),
            permissions: "0755".to_string(),
            content: GUEST_BOOTSTRAP_SCRIPT_CONTENT.to_string(),
        }],
    };
    let mut bento_yaml = String::from("#cloud-config\n");
    bento_yaml.push_str(
        &serde_yaml_ng::to_string(&cloud_config).context("serialize cloud-init user-data")?,
    );

    Ok(bento_yaml)
}

fn certificate_authority_pem_for_config(
    layout: &Layout,
    config: &GlobalConfig,
) -> eyre::Result<String> {
    if let Some(path) = config.networking.netd.tls_ca_cert.as_deref() {
        return certificate_authority::read_certificate_authority_certificate(path);
    }

    certificate_authority::ensure_certificate_authority_in(layout)
        .map(|authority| authority.certificate_pem)
}

fn pem_with_trailing_newline(pem: &str) -> String {
    let mut normalized = pem.trim_end().to_string();
    normalized.push('\n');
    normalized
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

fn render_agent_config(guest_runtime: &AgentConfig) -> eyre::Result<String> {
    serde_yaml_ng::to_string(guest_runtime).context("serialize agent config")
}

fn render_config_env(name: &str, spec: &VmSpec) -> eyre::Result<String> {
    let mut env = String::new();

    env.push_str(&format!("BENTO_INSTANCE_NAME={}\n", shell_quote(name)));
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
