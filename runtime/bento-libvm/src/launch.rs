use std::path::{Path, PathBuf};

use bento_core::agent::{
    AgentConfig, AgentDnsConfig, AgentForwardConfig, AgentRosettaConfig, AgentSshConfig,
    AgentUdsForwardConfig, CertificateAuthorityConfig, MountConfig as ProvisionMountConfig,
    NetworkConfig as ProvisionNetworkConfig, NetworkInterfaceConfig, NetworkMatchConfig,
    ProvisionConfig, ResizeRootfsConfig, UserConfig, UserdataConfig, UserdataContentType,
    UserdataRunPolicy,
};
use bento_core::VmSpec;
use bento_initramfs::{write_initramfs, InitramfsFile, InitramfsOptions};
use bento_utils::format_mac;
use eyre::Context;
use serde::Deserialize;

use crate::certificate_authority;
use crate::global_config::GlobalConfig;
use crate::host_user::{self, HostUser};
use crate::network::RuntimeNetwork;
use crate::ssh_keys;
use crate::{resolve_mount_location, InstanceFile, Layout};

const ASSET_INIT_FILENAME: &str = "init";
const ASSET_AGENT_FILENAME: &str = "agent";
const AGENT_BINARY_ARCHIVE_PATH: &str = "agent/bento-agent";
const AGENT_CONFIG_ARCHIVE_PATH: &str = "agent/bento-agent.yaml";
const AGENT_CONFIG_SOURCE_FILENAME: &str = ".bento-agent.yaml";
const FORWARD_ENDPOINT_NAME: &str = "forward";
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

pub(crate) fn prepare_instance_runtime(
    layout: &Layout,
    instance_dir: &Path,
    name: &str,
    spec: &mut VmSpec,
    network: &RuntimeNetwork,
) -> eyre::Result<()> {
    normalize_runtime_mounts(spec)?;
    prepare_runtime_initramfs(layout, instance_dir, name, spec, network)?;
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

fn prepare_runtime_initramfs(
    layout: &Layout,
    instance_dir: &Path,
    name: &str,
    spec: &mut VmSpec,
    network: &RuntimeNetwork,
) -> eyre::Result<()> {
    if spec.boot.initramfs.is_some() {
        if spec.settings.agent {
            eyre::bail!(
                "settings.agent=true requires the Bento-managed initramfs; remove explicit boot.initramfs so /agent can be injected"
            );
        }
        return Ok(());
    }

    let init_binary = asset_path(layout, ASSET_INIT_FILENAME);
    ensure_asset(&init_binary, "init binary")?;

    let output = instance_dir.join(InstanceFile::Initramfs.as_str());
    let mut options = InitramfsOptions::new(&init_binary, &output);
    let agent_config_source = if spec.settings.agent {
        let agent_binary = asset_path(layout, ASSET_AGENT_FILENAME);
        ensure_asset(&agent_binary, "agent binary")?;

        let agent_config = resolve_agent_config(layout, name, spec, network)?;
        let agent_config_source = instance_dir.join(AGENT_CONFIG_SOURCE_FILENAME);
        std::fs::write(&agent_config_source, render_agent_config(&agent_config)?).with_context(
            || {
                format!(
                    "write agent config payload {}",
                    agent_config_source.display()
                )
            },
        )?;

        options = options
            .with_extra_file(InitramfsFile::new(
                AGENT_BINARY_ARCHIVE_PATH,
                agent_binary,
                0o755,
            ))
            .with_extra_file(InitramfsFile::new(
                AGENT_CONFIG_ARCHIVE_PATH,
                &agent_config_source,
                0o644,
            ));
        Some(agent_config_source)
    } else {
        None
    };

    let result = write_initramfs(&options)
        .with_context(|| format!("build runtime initramfs at {}", output.display()));
    if let Some(path) = agent_config_source {
        remove_file_if_exists(&path)
            .with_context(|| format!("remove temporary agent config payload {}", path.display()))?;
    }
    result?;

    spec.boot.initramfs = Some(PathBuf::from(InstanceFile::Initramfs.as_str()));
    Ok(())
}

fn resolve_agent_config(
    layout: &Layout,
    name: &str,
    spec: &VmSpec,
    network: &RuntimeNetwork,
) -> eyre::Result<AgentConfig> {
    let host_user = host_user::current_host_user().context("resolve current host user")?;
    let user_keys = ssh_keys::ensure_user_ssh_keys().context("ensure user SSH keys")?;
    let global_config = GlobalConfig::load()?;
    let certificate_authority_pem = certificate_authority_pem_for_config(layout, &global_config)?;

    let mut guest_runtime = resolve_guest_runtime_config(spec, network)?;
    guest_runtime.provision = resolve_provision_config(
        name,
        spec,
        network,
        &host_user,
        &user_keys.public_key_openssh,
        &certificate_authority_pem,
    )?;
    Ok(guest_runtime)
}

fn asset_path(layout: &Layout, filename: &str) -> PathBuf {
    layout.data_dir().join("assets").join(filename)
}

fn ensure_asset(path: &Path, label: &str) -> eyre::Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        eyre::bail!(
            "missing boot asset: expected {label} at {}; build or copy it there before starting the VM",
            path.display()
        )
    }
}

fn remove_file_if_exists(path: &Path) -> eyre::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
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
        rosetta: AgentRosettaConfig {
            enabled: spec.settings.rosetta,
            ..AgentRosettaConfig::default()
        },
        mounts: provision_mount_entries(spec),
        userdata: provision_userdata(spec)?,
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
        run: UserdataRunPolicy::Once,
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

fn render_agent_config(guest_runtime: &AgentConfig) -> eyre::Result<String> {
    serde_yaml_ng::to_string(guest_runtime).context("serialize agent config")
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

#[cfg(test)]
mod tests {
    use super::{
        normalize_runtime_mounts, prepare_runtime_initramfs, resolve_guest_runtime_config,
    };
    use bento_core::{
        agent::{AgentConfig, UserdataContentType, UserdataRunPolicy},
        Architecture, Boot, Bootstrap, GuestOs, LifecycleSpec, Mount, Platform, PluginSpec,
        Resources, Settings, Storage, VmSpec, VsockEndpointMode, VsockEndpointSpec,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    use crate::host_user::HostUser;
    use crate::network::RuntimeNetwork;
    use crate::InstanceFile;
    use crate::Layout;

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
        assert_eq!(userdata.run, UserdataRunPolicy::Once);
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
    fn provision_config_captures_agent_provisioning_inputs() {
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
                .map(|userdata| (&userdata.content_type, &userdata.run)),
            Some((&UserdataContentType::ShellScript, &UserdataRunPolicy::Once))
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
        assert!(rendered.contains("rosetta:"));
        assert!(rendered.contains("run: once"));
        assert!(rendered.contains("interfaces:"));
    }

    #[test]
    fn provision_config_enables_rosetta_from_vm_settings() {
        let host_user = HostUser {
            name: "bento".to_string(),
            uid: 1000,
            gecos: "Bento User".to_string(),
        };
        let mut spec = sample_spec(Vec::new(), true);
        spec.settings.rosetta = true;

        let provision = super::resolve_provision_config(
            "demo",
            &spec,
            &RuntimeNetwork::None,
            &host_user,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBento",
            "-----BEGIN CERTIFICATE-----\nMIIBENTO\n-----END CERTIFICATE-----\n",
        )
        .expect("resolve provision config");

        assert!(provision.rosetta.enabled);
        assert_eq!(provision.rosetta.mount_tag, "bento-rosetta");
        assert_eq!(provision.rosetta.mount_path, "/mnt/bento-rosetta");
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
    fn runtime_initramfs_packages_init_without_agent() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        write_asset(&data_dir, "init", b"init binary");
        let instance_dir = temp.path().join("instance");
        fs::create_dir_all(&instance_dir).expect("create instance dir");
        let mut spec = sample_spec(Vec::new(), false);

        prepare_runtime_initramfs(
            &Layout::new(data_dir),
            &instance_dir,
            "demo",
            &mut spec,
            &RuntimeNetwork::None,
        )
        .expect("prepare runtime initramfs");

        assert_eq!(
            spec.boot.initramfs,
            Some(PathBuf::from(InstanceFile::Initramfs.as_str()))
        );
        assert!(instance_dir
            .join(InstanceFile::Initramfs.as_str())
            .is_file());
        assert!(spec.storage.disks.is_empty());
    }

    #[test]
    fn runtime_initramfs_rejects_explicit_initramfs_when_agent_enabled() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let instance_dir = temp.path().join("instance");
        fs::create_dir_all(&instance_dir).expect("create instance dir");
        let mut spec = sample_spec(Vec::new(), true);
        spec.boot.initramfs = Some(PathBuf::from("custom-initramfs"));

        let err = prepare_runtime_initramfs(
            &Layout::new(data_dir),
            &instance_dir,
            "demo",
            &mut spec,
            &RuntimeNetwork::None,
        )
        .expect_err("explicit initramfs should fail with agent enabled");

        assert!(err.to_string().contains("Bento-managed initramfs"));
    }

    #[test]
    fn runtime_initramfs_respects_explicit_initramfs_when_agent_disabled() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let instance_dir = temp.path().join("instance");
        fs::create_dir_all(&instance_dir).expect("create instance dir");
        let mut spec = sample_spec(Vec::new(), false);
        spec.boot.initramfs = Some(PathBuf::from("custom-initramfs"));

        prepare_runtime_initramfs(
            &Layout::new(data_dir),
            &instance_dir,
            "demo",
            &mut spec,
            &RuntimeNetwork::None,
        )
        .expect("explicit initramfs should be accepted with agent disabled");

        assert_eq!(spec.boot.initramfs, Some(PathBuf::from("custom-initramfs")));
        assert!(!instance_dir.join(InstanceFile::Initramfs.as_str()).exists());
    }

    fn write_asset(data_dir: &std::path::Path, name: &str, contents: &[u8]) {
        let assets_dir = data_dir.join("assets");
        fs::create_dir_all(&assets_dir).expect("create assets dir");
        fs::write(assets_dir.join(name), contents).expect("write asset");
    }
}
