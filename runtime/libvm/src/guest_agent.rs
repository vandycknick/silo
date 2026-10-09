use agent_spec::{
    AgentConfig, AgentRosettaConfig, AgentSshConfig, CertificateAuthorityConfig,
    MountConfig as ProvisionMountConfig, NetworkConfig as ProvisionNetworkConfig,
    NetworkInterfaceConfig, ProvisionConfig, ResizeRootfsConfig, UserConfig, UserdataConfig,
    UserdataContentType, UserdataRunPolicy,
};
use utils::format_mac;
use vm_spec::VmSpec;

use crate::constants::{
    GUEST_CERTIFICATE_AUTHORITY_PATH, GUEST_USER_SHELL, GUEST_USER_SUDO_RULE, MOUNT_OPTION_NOFAIL,
    MOUNT_OPTION_READ_ONLY, MOUNT_OPTION_READ_WRITE, USERDATA_CONTENT_TYPE_CLOUD_CONFIG,
    USERDATA_CONTENT_TYPE_PLAIN_TEXT, USERDATA_CONTENT_TYPE_SHELL_SCRIPT, VIRTIOFS_FSTYPE,
};
use crate::host;
use crate::machine::MachineUserConfig;
use crate::network::VmmNetworkAttachment;

pub(crate) struct GuestAgentConfigInput<'a> {
    pub(crate) machine_name: &'a str,
    pub(crate) spec: &'a VmSpec,
    pub(crate) network: &'a VmmNetworkAttachment,
    pub(crate) resize_rootfs: bool,
    pub(crate) user: Option<&'a MachineUserConfig>,
    pub(crate) ssh_trusted_ca: &'a str,
    pub(crate) tls_certificate: Option<&'a str>,
}

struct GuestAgentHostContext {
    user: Option<MachineUserConfig>,
    ssh_trusted_ca: String,
    certificate_authority_pem: Option<String>,
    timezone: String,
    locale: String,
}

pub(crate) fn build_config(input: GuestAgentConfigInput<'_>) -> eyre::Result<AgentConfig> {
    let host_context = GuestAgentHostContext {
        user: input.user.cloned(),
        ssh_trusted_ca: input.ssh_trusted_ca.into(),
        certificate_authority_pem: input.tls_certificate.map(str::to_owned),
        timezone: host::current_timezone(),
        locale: host::current_locale(),
    };
    build_config_with_host_context(
        input.machine_name,
        input.spec,
        input.network,
        input.resize_rootfs,
        &host_context,
    )
}

fn build_config_with_host_context(
    machine_name: &str,
    spec: &VmSpec,
    network: &VmmNetworkAttachment,
    resize_rootfs: bool,
    host_context: &GuestAgentHostContext,
) -> eyre::Result<AgentConfig> {
    Ok(AgentConfig {
        provision: build_provision_config(
            machine_name,
            spec,
            network,
            resize_rootfs,
            host_context,
        )?,
        ssh: build_ssh_config(host_context),
    })
}

fn build_provision_config(
    machine_name: &str,
    spec: &VmSpec,
    network: &VmmNetworkAttachment,
    resize_rootfs: bool,
    host_context: &GuestAgentHostContext,
) -> eyre::Result<ProvisionConfig> {
    let certificate_authority = if network.requires_certificate_authority() {
        let pem = host_context
            .certificate_authority_pem
            .as_deref()
            .ok_or_else(|| eyre::eyre!("network requires a certificate authority"))?;
        Some(CertificateAuthorityConfig {
            path: GUEST_CERTIFICATE_AUTHORITY_PATH.to_string(),
            pem: pem_with_trailing_newline(pem),
            update_trust: true,
        })
    } else {
        None
    };

    Ok(ProvisionConfig {
        enabled: true,
        hostname: Some(machine_name.to_string()),
        timezone: Some(host_context.timezone.clone()),
        locale: Some(host_context.locale.clone()),
        resize_rootfs: ResizeRootfsConfig {
            enabled: resize_rootfs,
        },
        users: host_context
            .user
            .iter()
            .map(|user| UserConfig {
                name: user.name.clone(),
                uid: user.uid,
                gid: user.gid,
                gecos: user.name.clone(),
                home: user.home.clone(),
                shell: GUEST_USER_SHELL.to_string(),
                sudo: GUEST_USER_SUDO_RULE.to_string(),
                lock_passwd: true,
            })
            .collect(),
        certificate_authority,
        network: build_provision_network_config(network)?,
        rosetta: AgentRosettaConfig {
            enabled: spec
                .hardware
                .as_ref()
                .and_then(|hardware| hardware.rosetta)
                .unwrap_or(false),
            ..AgentRosettaConfig::default()
        },
        mounts: provision_mount_entries(spec)?,
        userdata: provision_userdata(spec)?,
    })
}

fn build_ssh_config(host_context: &GuestAgentHostContext) -> AgentSshConfig {
    AgentSshConfig {
        trusted_ca: Some(host_context.ssh_trusted_ca.clone()),
    }
}

fn provision_userdata(spec: &VmSpec) -> eyre::Result<Option<UserdataConfig>> {
    let Some(user_data) = spec.boot.as_ref().and_then(|boot| boot.userdata.as_deref()) else {
        return Ok(None);
    };

    let content_type = match detect_userdata_content_type(user_data) {
        USERDATA_CONTENT_TYPE_SHELL_SCRIPT => UserdataContentType::ShellScript,
        other => {
            eyre::bail!(
                "guest provisioning only supports shell-script userdata right now; got {other}"
            )
        }
    };

    Ok(Some(UserdataConfig {
        content: user_data.to_string(),
        content_type,
        run: UserdataRunPolicy::Once,
    }))
}

fn build_provision_network_config(
    network: &VmmNetworkAttachment,
) -> eyre::Result<Option<ProvisionNetworkConfig>> {
    match network {
        VmmNetworkAttachment::None => Ok(None),
        VmmNetworkAttachment::UnixDatagram { mac, ipv4, dns, .. } => {
            Ok(Some(ProvisionNetworkConfig {
                interfaces: vec![NetworkInterfaceConfig {
                    mac_address: format_mac(parse_mac_string(mac)?),
                    ipv4: ipv4.clone(),
                    dns: dns.clone(),
                }],
            }))
        }
    }
}

fn provision_mount_entries(spec: &VmSpec) -> eyre::Result<Vec<ProvisionMountConfig>> {
    Ok(vm_spec::project_mounts(&spec.mounts)
        .map_err(eyre::Report::msg)?
        .into_iter()
        .map(|mount| ProvisionMountConfig {
            tag: mount.backend_tag,
            path: mount.guest_path.to_string_lossy().to_string(),
            fstype: VIRTIOFS_FSTYPE.to_string(),
            options: if mount.read_only {
                vec![
                    MOUNT_OPTION_READ_ONLY.to_string(),
                    MOUNT_OPTION_NOFAIL.to_string(),
                ]
            } else {
                vec![
                    MOUNT_OPTION_READ_WRITE.to_string(),
                    MOUNT_OPTION_NOFAIL.to_string(),
                ]
            },
        })
        .collect())
}

fn pem_with_trailing_newline(pem: &str) -> String {
    let mut normalized = pem.trim_end().to_string();
    normalized.push('\n');
    normalized
}

fn detect_userdata_content_type(user_data: &str) -> &'static str {
    let trimmed = user_data.trim_start();
    if trimmed.starts_with("#cloud-config") {
        USERDATA_CONTENT_TYPE_CLOUD_CONFIG
    } else if trimmed.starts_with("#!") {
        USERDATA_CONTENT_TYPE_SHELL_SCRIPT
    } else {
        USERDATA_CONTENT_TYPE_PLAIN_TEXT
    }
}

fn parse_mac_string(mac: &str) -> eyre::Result<[u8; 6]> {
    utils::parse_mac(mac).map_err(|err| eyre::eyre!("parse MAC address {:?}: {err}", mac))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use agent_spec::{AgentConfig, UserdataContentType, UserdataRunPolicy};
    use vm_spec::{Boot, Guest, GuestOs, Hardware, Kernel, Mount, Storage, VmSpec};

    use crate::guest_agent::{
        build_config_with_host_context, build_provision_config, build_provision_network_config,
        provision_mount_entries, GuestAgentHostContext,
    };
    use crate::machine::MachineUserConfig;
    use crate::network::VmmNetworkAttachment;

    fn sample_spec(kernel_cmdline: Vec<String>) -> VmSpec {
        VmSpec {
            guest: Some(Guest {
                os: Some(GuestOs::Linux),
            }),
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: None,
                    cmdline: kernel_cmdline,
                    initramfs: None,
                }),
                userdata: None,
            }),
            hardware: Some(Hardware {
                cpus: Some(4),
                memory: Some(4096),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            }),
            storage: Some(Storage { disks: Vec::new() }),
            mounts: Vec::new(),
            ..VmSpec::current()
        }
    }

    fn boot_mut(spec: &mut VmSpec) -> &mut Boot {
        spec.boot.as_mut().expect("sample spec boot")
    }

    fn hardware_mut(spec: &mut VmSpec) -> &mut Hardware {
        spec.hardware.as_mut().expect("sample spec hardware")
    }

    fn host_context() -> GuestAgentHostContext {
        GuestAgentHostContext {
            user: Some(MachineUserConfig::new("silo", 1000, 2000, "/home/silo")),
            ssh_trusted_ca: ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(
                &[1u8; 32],
            ))
            .public_key()
            .to_openssh()
            .unwrap(),
            certificate_authority_pem: Some(
                "-----BEGIN CERTIFICATE-----\nMIISILO\n-----END CERTIFICATE-----\n".to_string(),
            ),
            timezone: "Europe/Amsterdam".to_string(),
            locale: "nl_NL.UTF-8".to_string(),
        }
    }

    #[test]
    fn provision_network_is_absent_without_attachment() {
        let config = build_provision_network_config(&VmmNetworkAttachment::None)
            .expect("network provision config should render");

        assert!(config.is_none());
    }

    #[test]
    fn provision_config_includes_shell_userdata_script() {
        let mut spec = sample_spec(Vec::new());
        boot_mut(&mut spec).userdata = Some("#!/bin/sh\necho profile\n".to_string());

        let provision = build_provision_config(
            "demo",
            &spec,
            &VmmNetworkAttachment::None,
            true,
            &host_context(),
        )
        .expect("resolve provision config");

        let userdata = provision.userdata.expect("userdata config");
        assert_eq!(userdata.content_type, UserdataContentType::ShellScript);
        assert_eq!(userdata.run, UserdataRunPolicy::Once);
        assert!(userdata.content.contains("#!/bin/sh"));
        assert!(userdata.content.contains("echo profile"));
    }

    #[test]
    fn guest_agent_omits_unconfigured_user_and_authorizes_root_only() {
        let mut context = host_context();
        context.user = None;

        let config = build_config_with_host_context(
            "demo",
            &sample_spec(Vec::new()),
            &VmmNetworkAttachment::None,
            false,
            &context,
        )
        .expect("build agent config");

        assert!(config.provision.users.is_empty());
        assert_eq!(config.ssh.trusted_ca, Some(context.ssh_trusted_ca));
    }

    #[test]
    fn provision_config_rejects_cloud_config_userdata() {
        let mut spec = sample_spec(Vec::new());
        boot_mut(&mut spec).userdata =
            Some("#cloud-config\nruncmd:\n  - echo external\n".to_string());

        let err = build_provision_config(
            "demo",
            &spec,
            &VmmNetworkAttachment::None,
            true,
            &host_context(),
        )
        .expect_err("cloud-config userdata should be rejected");

        assert!(err
            .to_string()
            .contains("only supports shell-script userdata"));
    }

    #[test]
    fn provision_config_omits_certificate_authority_without_https_interception() {
        let spec = sample_spec(Vec::new());

        let detached = build_provision_config(
            "demo",
            &spec,
            &VmmNetworkAttachment::None,
            true,
            &host_context(),
        )
        .expect("resolve provision config");
        let attached = build_provision_config(
            "demo",
            &spec,
            &VmmNetworkAttachment::UnixDatagram {
                path: PathBuf::from("/run/silo/net.sock"),
                mac: "02:00:00:00:00:01".to_string(),
                ipv4: agent_spec::NetworkIpv4Config {
                    address: "192.168.105.2".parse().expect("IPv4 address"),
                    prefix_length: 24,
                    gateway: "192.168.105.1".parse().expect("IPv4 gateway"),
                },
                dns: agent_spec::NetworkDnsConfig {
                    servers: vec!["192.168.105.1".parse().expect("DNS server")],
                    search: Vec::new(),
                },
                requires_certificate_authority: false,
                exit_writer: None,
            },
            true,
            &host_context(),
        )
        .expect("resolve provision config");

        assert!(detached.certificate_authority.is_none());
        assert!(attached.certificate_authority.is_none());
    }

    #[test]
    fn provision_config_captures_guest_provisioning_inputs() {
        let mut spec = sample_spec(Vec::new());
        spec.mounts.push(Mount {
            source: PathBuf::from("/workspace"),
            tag: "workspace".to_string(),
            read_only: false,
        });
        boot_mut(&mut spec).userdata = Some("#!/bin/sh\necho profile\n".to_string());

        let provision = build_provision_config(
            "demo",
            &spec,
            &VmmNetworkAttachment::UnixDatagram {
                path: PathBuf::from("/run/silo/net.sock"),
                mac: "02:00:00:00:00:01".to_string(),
                ipv4: agent_spec::NetworkIpv4Config {
                    address: "192.168.105.2".parse().expect("IPv4 address"),
                    prefix_length: 24,
                    gateway: "192.168.105.1".parse().expect("IPv4 gateway"),
                },
                dns: agent_spec::NetworkDnsConfig {
                    servers: vec!["192.168.105.1".parse().expect("DNS server")],
                    search: Vec::new(),
                },
                requires_certificate_authority: true,
                exit_writer: None,
            },
            true,
            &host_context(),
        )
        .expect("resolve provision config");

        assert!(provision.enabled);
        assert_eq!(provision.hostname.as_deref(), Some("demo"));
        assert_eq!(provision.timezone.as_deref(), Some("Europe/Amsterdam"));
        assert_eq!(provision.locale.as_deref(), Some("nl_NL.UTF-8"));
        assert_eq!(provision.users[0].name, "silo");
        assert_eq!(provision.users[0].uid, 1000);
        assert_eq!(provision.users[0].gid, 2000);
        assert!(provision.resize_rootfs.enabled);
        assert_eq!(provision.mounts[0].tag, "workspace");
        assert_eq!(provision.mounts[0].path, "/workspace");
        let network = provision.network.as_ref().expect("network config");
        assert_eq!(network.interfaces[0].mac_address, "02:00:00:00:00:01");
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

        let rendered = serde_json::to_string(&AgentConfig {
            provision,
            ..AgentConfig::default()
        })
        .expect("render metadata config");
        let decoded: AgentConfig = serde_json::from_str(&rendered).expect("decode metadata config");
        assert!(decoded.provision.enabled);
        assert!(decoded.provision.resize_rootfs.enabled);
        assert_eq!(
            decoded.provision.rosetta.mount_tag,
            agent_spec::ROSETTA_MOUNT_TAG
        );
        assert_eq!(
            decoded
                .provision
                .network
                .as_ref()
                .map(|network| network.interfaces.len()),
            Some(1)
        );
        assert_eq!(
            decoded
                .provision
                .userdata
                .as_ref()
                .map(|userdata| &userdata.run),
            Some(&UserdataRunPolicy::Once)
        );
    }

    #[test]
    fn provision_mounts_resolve_guest_paths_without_changing_export_tags() {
        let mut spec = sample_spec(Vec::new());
        spec.mounts = vec![
            Mount {
                source: PathBuf::from("/host/project"),
                tag: "/workspace".to_string(),
                read_only: false,
            },
            Mount {
                source: PathBuf::from("/host/cache"),
                tag: "/var/cache/project".to_string(),
                read_only: true,
            },
            Mount {
                source: PathBuf::from("/sdk/worktree"),
                tag: "workspace".to_string(),
                read_only: false,
            },
            Mount {
                source: PathBuf::from("/srv/shared"),
                tag: "/srv/shared".to_string(),
                read_only: true,
            },
        ];

        let mounts = provision_mount_entries(&spec).expect("project provision mounts");

        assert_eq!(mounts[0].tag, "/workspace");
        assert_eq!(mounts[0].path, "/workspace");
        assert_eq!(mounts[0].options, ["rw", "nofail"]);
        assert_eq!(mounts[1].tag, "/var/cache/project");
        assert_eq!(mounts[1].path, "/var/cache/project");
        assert_eq!(mounts[1].options, ["ro", "nofail"]);
        assert_eq!(mounts[2].tag, "workspace");
        assert_eq!(mounts[2].path, "/sdk/worktree");
        assert_eq!(mounts[3].tag, "/srv/shared");
        assert_eq!(mounts[3].path, "/srv/shared");
    }

    #[test]
    fn provision_mounts_use_projected_backend_tags_and_original_guest_paths() {
        let mut spec = sample_spec(Vec::new());
        let destination = "/guest/workspace/destination/that/is/longer/than/virtiofs/allows";
        spec.mounts = vec![Mount {
            source: PathBuf::from("/host/workspace/source/that/must/remain/unchanged"),
            tag: destination.to_string(),
            read_only: false,
        }];

        let mounts = provision_mount_entries(&spec).expect("project provision mounts");

        assert_eq!(mounts[0].tag, "silo-mount-0");
        assert_eq!(mounts[0].path, destination);
        assert_eq!(mounts[0].options, ["rw", "nofail"]);
    }

    #[test]
    fn provision_mounts_propagate_duplicate_original_tag_errors() {
        let mut spec = sample_spec(Vec::new());
        spec.mounts = vec![
            Mount {
                source: PathBuf::from("/one"),
                tag: "workspace".to_string(),
                read_only: false,
            },
            Mount {
                source: PathBuf::from("/two"),
                tag: "workspace".to_string(),
                read_only: false,
            },
        ];

        let error = provision_mount_entries(&spec).expect_err("duplicate tags must fail");

        assert!(error
            .to_string()
            .contains("mount tag \"workspace\" is repeated"));
    }

    #[test]
    fn provision_config_disables_guest_resize_after_offline_completion() {
        let provision = build_provision_config(
            "demo",
            &sample_spec(Vec::new()),
            &VmmNetworkAttachment::None,
            false,
            &host_context(),
        )
        .expect("resolve provision config");

        assert!(!provision.resize_rootfs.enabled);
    }

    #[test]
    fn provision_config_enables_rosetta_from_vm_settings() {
        let mut spec = sample_spec(Vec::new());
        hardware_mut(&mut spec).rosetta = Some(true);

        let provision = build_provision_config(
            "demo",
            &spec,
            &VmmNetworkAttachment::None,
            true,
            &host_context(),
        )
        .expect("resolve provision config");

        assert!(provision.rosetta.enabled);
        assert_eq!(provision.rosetta.mount_tag, agent_spec::ROSETTA_MOUNT_TAG);
        assert_eq!(provision.rosetta.mount_path, agent_spec::ROSETTA_MOUNT_PATH);
    }

    #[test]
    fn build_config_combines_provision_and_ssh_config() {
        let config = build_config_with_host_context(
            "demo",
            &sample_spec(Vec::new()),
            &VmmNetworkAttachment::None,
            true,
            &host_context(),
        )
        .expect("build agent config");

        assert!(config.provision.enabled);
        assert_eq!(config.provision.hostname.as_deref(), Some("demo"));
        assert_eq!(config.ssh.trusted_ca, Some(host_context().ssh_trusted_ca));
    }
}
