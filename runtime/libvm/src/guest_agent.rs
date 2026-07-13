use std::fs;
use std::path::{Path, PathBuf};

use agent_spec::{
    AgentConfig, AgentForwardConfig, AgentRosettaConfig, AgentSshAuthorizedUser, AgentSshConfig,
    AgentUdsForwardConfig, CertificateAuthorityConfig, MountConfig as ProvisionMountConfig,
    NetworkConfig as ProvisionNetworkConfig, NetworkInterfaceConfig, ProvisionConfig,
    ResizeRootfsConfig, UserConfig, UserdataConfig, UserdataContentType, UserdataRunPolicy,
};
use eyre::Context;
use serde::Deserialize;
use ssh_key::PrivateKey;
use utils::format_mac;
use vm_spec::VmSpec;

use crate::constants::{
    FORWARD_ENDPOINT_NAME, GUEST_CERTIFICATE_AUTHORITY_PATH, GUEST_SSH_PRIVATE_KEY_FILE_NAME,
    GUEST_SSH_PUBLIC_KEY_FILE_NAME, GUEST_USER_SHELL, GUEST_USER_SUDO_RULE, MOUNT_OPTION_NOFAIL,
    MOUNT_OPTION_READ_ONLY, MOUNT_OPTION_READ_WRITE, USERDATA_CONTENT_TYPE_CLOUD_CONFIG,
    USERDATA_CONTENT_TYPE_PLAIN_TEXT, USERDATA_CONTENT_TYPE_SHELL_SCRIPT, VIRTIOFS_FSTYPE,
};
use crate::host::{self, HostUser};
use crate::network::VmmonNetworkAttachment;
use crate::paths::LocalPaths;
use crate::RuntimeNetworkingConfig;

pub(crate) struct GuestAgentConfigInput<'a> {
    pub(crate) paths: &'a LocalPaths,
    pub(crate) machine_name: &'a str,
    pub(crate) spec: &'a VmSpec,
    pub(crate) network: &'a VmmonNetworkAttachment,
    pub(crate) networking: &'a RuntimeNetworkingConfig,
}

struct GuestAgentHostContext {
    user: HostUser,
    ssh_public_key_openssh: String,
    certificate_authority_pem: Option<String>,
    timezone: String,
    locale: String,
}

#[derive(Debug, Deserialize, Default)]
struct ForwardPluginConfig {
    #[serde(default)]
    uds: Vec<ForwardPluginUdsConfig>,
}

#[derive(Debug, Deserialize)]
struct ForwardPluginUdsConfig {
    guest_path: String,
}

pub(crate) fn build_config(input: GuestAgentConfigInput<'_>) -> eyre::Result<AgentConfig> {
    let host_context = load_host_context(
        input.paths,
        input.networking,
        input.network.requires_certificate_authority(),
    )?;
    build_config_with_host_context(input.machine_name, input.spec, input.network, &host_context)
}

fn load_host_context(
    paths: &LocalPaths,
    networking: &RuntimeNetworkingConfig,
    requires_certificate_authority: bool,
) -> eyre::Result<GuestAgentHostContext> {
    let user = host::current_host_user().context("resolve current host user")?;
    let ssh_keypair =
        load_or_generate_guest_ssh_keypair(paths).context("load guest SSH keypair")?;
    let certificate_authority_pem = requires_certificate_authority
        .then(|| certificate_authority_pem_for_config(paths, networking))
        .transpose()?;

    Ok(GuestAgentHostContext {
        user,
        ssh_public_key_openssh: ssh_keypair.public_key_openssh,
        certificate_authority_pem,
        timezone: host::current_timezone(),
        locale: host::current_locale(),
    })
}

fn build_config_with_host_context(
    machine_name: &str,
    spec: &VmSpec,
    network: &VmmonNetworkAttachment,
    host_context: &GuestAgentHostContext,
) -> eyre::Result<AgentConfig> {
    Ok(AgentConfig {
        forward: build_forward_config(spec)?,
        provision: build_provision_config(machine_name, spec, network, host_context)?,
        ssh: build_ssh_config(host_context),
    })
}

fn build_forward_config(spec: &VmSpec) -> eyre::Result<AgentForwardConfig> {
    let Some(endpoint) = spec.vsock.as_ref().and_then(|vsock| {
        vsock
            .endpoints
            .iter()
            .find(|endpoint| endpoint.name == FORWARD_ENDPOINT_NAME)
    }) else {
        return Ok(AgentForwardConfig::default());
    };

    let config = endpoint
        .plugin
        .config
        .clone()
        .map(serde_json::from_value::<ForwardPluginConfig>)
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

fn build_provision_config(
    machine_name: &str,
    spec: &VmSpec,
    network: &VmmonNetworkAttachment,
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
        resize_rootfs: ResizeRootfsConfig { enabled: true },
        users: vec![UserConfig {
            name: host_context.user.name.clone(),
            uid: host_context.user.uid,
            gecos: host_context.user.gecos.clone(),
            home: format!("/home/{}", host_context.user.name),
            shell: GUEST_USER_SHELL.to_string(),
            sudo: GUEST_USER_SUDO_RULE.to_string(),
            lock_passwd: true,
        }],
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
        mounts: provision_mount_entries(spec),
        userdata: provision_userdata(spec)?,
    })
}

fn build_ssh_config(host_context: &GuestAgentHostContext) -> AgentSshConfig {
    let public_key = host_context.ssh_public_key_openssh.trim().to_string();
    let mut authorized_users = vec![AgentSshAuthorizedUser {
        name: "root".to_string(),
        authorized_keys: vec![public_key.clone()],
        allow_without_auth: false,
    }];

    if host_context.user.name != "root" {
        authorized_users.push(AgentSshAuthorizedUser {
            name: host_context.user.name.clone(),
            authorized_keys: vec![public_key],
            allow_without_auth: false,
        });
    }

    AgentSshConfig { authorized_users }
}

pub(crate) fn load_or_generate_guest_ssh_keypair(
    paths: &LocalPaths,
) -> eyre::Result<host::SshKeyPair> {
    let (private_key_path, public_key_path) = guest_ssh_key_paths(paths);
    if private_key_path.is_file() && public_key_path.is_file() {
        validate_guest_ssh_keypair(&private_key_path, &public_key_path)
    } else {
        host::generate_ssh_keypair(&private_key_path, &public_key_path, None)
    }
}

fn guest_ssh_key_paths(paths: &LocalPaths) -> (PathBuf, PathBuf) {
    let keys_dir = paths.keys_dir();
    (
        keys_dir.join(GUEST_SSH_PRIVATE_KEY_FILE_NAME),
        keys_dir.join(GUEST_SSH_PUBLIC_KEY_FILE_NAME),
    )
}

fn validate_guest_ssh_keypair(
    private_key_path: &Path,
    public_key_path: &Path,
) -> eyre::Result<host::SshKeyPair> {
    let private_key = PrivateKey::read_openssh_file(private_key_path)
        .with_context(|| format!("read SSH private key {}", private_key_path.display()))?;
    let derived_public_key = private_key
        .public_key()
        .to_openssh()
        .context("encode SSH public key")?;
    let public_key = fs::read_to_string(public_key_path)
        .with_context(|| format!("read SSH public key {}", public_key_path.display()))?;
    let public_key = public_key.trim();
    if public_key != derived_public_key {
        eyre::bail!(
            "SSH public key {} does not match private key {}",
            public_key_path.display(),
            private_key_path.display()
        );
    }

    Ok(host::SshKeyPair {
        private_key_path: private_key_path.to_path_buf(),
        public_key_path: public_key_path.to_path_buf(),
        public_key_openssh: derived_public_key,
    })
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
    network: &VmmonNetworkAttachment,
) -> eyre::Result<Option<ProvisionNetworkConfig>> {
    match network {
        VmmonNetworkAttachment::None => Ok(None),
        VmmonNetworkAttachment::UnixDatagram { mac, ipv4, dns, .. } => {
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

fn provision_mount_entries(spec: &VmSpec) -> Vec<ProvisionMountConfig> {
    spec.mounts
        .iter()
        .map(|mount| ProvisionMountConfig {
            tag: mount.tag.clone(),
            path: mount.source.to_string_lossy().to_string(),
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
        .collect()
}

fn certificate_authority_pem_for_config(
    paths: &LocalPaths,
    config: &RuntimeNetworkingConfig,
) -> eyre::Result<String> {
    if let Some(path) = config.netd.tls_ca_cert.as_deref() {
        return host::read_certificate_authority_certificate(path);
    }

    host::ensure_certificate_authority_in(paths).map(|authority| authority.certificate_pem)
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
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    use agent_spec::{AgentConfig, UserdataContentType, UserdataRunPolicy};
    use serde_json::json;
    use vm_spec::{
        Boot, Guest, GuestOs, Hardware, Kernel, Lifecycle, Mount, Plugin, Storage, VmSpec, Vsock,
        VsockEndpoint, VsockEndpointMode,
    };

    use crate::guest_agent::{
        build_config_with_host_context, build_forward_config, build_provision_config,
        build_provision_network_config, guest_ssh_key_paths, load_or_generate_guest_ssh_keypair,
        GuestAgentHostContext,
    };
    use crate::host::{self, HostUser};
    use crate::network::VmmonNetworkAttachment;
    use crate::paths::LocalPaths;

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

    fn push_vsock_endpoint(spec: &mut VmSpec, endpoint: VsockEndpoint) {
        spec.vsock
            .get_or_insert_with(|| Vsock {
                endpoints: Vec::new(),
            })
            .endpoints
            .push(endpoint);
    }

    fn forward_endpoint(port: u32, config: Option<serde_json::Value>) -> VsockEndpoint {
        VsockEndpoint {
            name: "forward".to_string(),
            port,
            mode: VsockEndpointMode::Connect,
            plugin: Plugin {
                command: PathBuf::from("/usr/local/bin/forward"),
                args: Vec::new(),
                env: BTreeMap::new(),
                working_dir: None,
                config,
            },
            lifecycle: Lifecycle::default(),
        }
    }

    fn host_context() -> GuestAgentHostContext {
        GuestAgentHostContext {
            user: HostUser {
                name: "silo".to_string(),
                uid: 1000,
                gecos: "Silo User".to_string(),
            },
            ssh_public_key_openssh: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISilo".to_string(),
            certificate_authority_pem: Some(
                "-----BEGIN CERTIFICATE-----\nMIISILO\n-----END CERTIFICATE-----\n".to_string(),
            ),
            timezone: "Europe/Amsterdam".to_string(),
            locale: "nl_NL.UTF-8".to_string(),
        }
    }

    #[test]
    fn guest_ssh_key_paths_use_local_keys_dir() {
        let paths = LocalPaths::new("/tmp/silo");

        let (private_key_path, public_key_path) = guest_ssh_key_paths(&paths);

        assert_eq!(private_key_path, PathBuf::from("/tmp/silo/keys/id_ed25519"));
        assert_eq!(
            public_key_path,
            PathBuf::from("/tmp/silo/keys/id_ed25519.pub")
        );
    }

    #[test]
    fn guest_ssh_keypair_generates_missing_keypair() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("silo"));

        let keypair = load_or_generate_guest_ssh_keypair(&paths).expect("load guest SSH keypair");

        assert_eq!(
            keypair.private_key_path,
            paths.keys_dir().join("id_ed25519")
        );
        assert_eq!(
            keypair.public_key_path,
            paths.keys_dir().join("id_ed25519.pub")
        );
        assert!(keypair.private_key_path.is_file());
        assert!(keypair.public_key_path.is_file());
        assert!(keypair.public_key_openssh.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn guest_ssh_keypair_regenerates_when_private_key_is_missing() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let first = load_or_generate_guest_ssh_keypair(&paths).expect("generate guest SSH keypair");
        fs::remove_file(&first.private_key_path).expect("remove private key");

        let second =
            load_or_generate_guest_ssh_keypair(&paths).expect("regenerate guest SSH keypair");

        assert!(second.private_key_path.is_file());
        assert!(second.public_key_path.is_file());
        assert_ne!(second.public_key_openssh, first.public_key_openssh);
    }

    #[test]
    fn guest_ssh_keypair_regenerates_when_public_key_is_missing() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let first = load_or_generate_guest_ssh_keypair(&paths).expect("generate guest SSH keypair");
        fs::remove_file(&first.public_key_path).expect("remove public key");

        let second =
            load_or_generate_guest_ssh_keypair(&paths).expect("regenerate guest SSH keypair");

        assert!(second.private_key_path.is_file());
        assert!(second.public_key_path.is_file());
        assert_ne!(second.public_key_openssh, first.public_key_openssh);
    }

    #[test]
    fn guest_ssh_keypair_reuses_existing_valid_keypair() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let first = load_or_generate_guest_ssh_keypair(&paths).expect("generate guest SSH keypair");

        let second = load_or_generate_guest_ssh_keypair(&paths).expect("reuse guest SSH keypair");

        assert_eq!(second.public_key_openssh, first.public_key_openssh);
    }

    #[test]
    fn guest_ssh_keypair_rejects_mismatched_public_key() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let keys_dir = temp.path().join("keys");
        let private_key_path = keys_dir.join("id_ed25519");
        let public_key_path = keys_dir.join("id_ed25519.pub");
        host::generate_ssh_keypair(&private_key_path, &public_key_path, None)
            .expect("generate first keypair");
        let other = host::generate_ssh_keypair(
            &temp.path().join("other").join("id_ed25519"),
            &temp.path().join("other").join("id_ed25519.pub"),
            None,
        )
        .expect("generate second keypair");
        fs::write(&public_key_path, format!("{}\n", other.public_key_openssh))
            .expect("replace public key");

        let paths = LocalPaths::new(temp.path());
        let err =
            load_or_generate_guest_ssh_keypair(&paths).expect_err("reject mismatched keypair");

        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn provision_network_is_absent_without_attachment() {
        let config = build_provision_network_config(&VmmonNetworkAttachment::None)
            .expect("network provision config should render");

        assert!(config.is_none());
    }

    #[test]
    fn guest_agent_has_no_forward_without_endpoint() {
        let config = build_forward_config(&sample_spec(Vec::new())).expect("forward config");

        assert!(!config.enabled);
    }

    #[test]
    fn provision_config_includes_shell_userdata_script() {
        let mut spec = sample_spec(Vec::new());
        boot_mut(&mut spec).userdata = Some("#!/bin/sh\necho profile\n".to_string());

        let provision = build_provision_config(
            "demo",
            &spec,
            &VmmonNetworkAttachment::None,
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
    fn provision_config_rejects_cloud_config_userdata() {
        let mut spec = sample_spec(Vec::new());
        boot_mut(&mut spec).userdata =
            Some("#cloud-config\nruncmd:\n  - echo external\n".to_string());

        let err = build_provision_config(
            "demo",
            &spec,
            &VmmonNetworkAttachment::None,
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
            &VmmonNetworkAttachment::None,
            &host_context(),
        )
        .expect("resolve provision config");
        let attached = build_provision_config(
            "demo",
            &spec,
            &VmmonNetworkAttachment::UnixDatagram {
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
            },
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
            &VmmonNetworkAttachment::UnixDatagram {
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
            },
            &host_context(),
        )
        .expect("resolve provision config");

        assert!(provision.enabled);
        assert_eq!(provision.hostname.as_deref(), Some("demo"));
        assert_eq!(provision.timezone.as_deref(), Some("Europe/Amsterdam"));
        assert_eq!(provision.locale.as_deref(), Some("nl_NL.UTF-8"));
        assert_eq!(provision.users[0].name, "silo");
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
        assert_eq!(decoded.provision.rosetta.mount_tag, "silo-rosetta");
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
    fn provision_config_enables_rosetta_from_vm_settings() {
        let mut spec = sample_spec(Vec::new());
        hardware_mut(&mut spec).rosetta = Some(true);

        let provision = build_provision_config(
            "demo",
            &spec,
            &VmmonNetworkAttachment::None,
            &host_context(),
        )
        .expect("resolve provision config");

        assert!(provision.rosetta.enabled);
        assert_eq!(provision.rosetta.mount_tag, "silo-rosetta");
        assert_eq!(provision.rosetta.mount_path, "/mnt/silo-rosetta");
    }

    #[test]
    fn guest_agent_enables_forward_from_named_endpoint() {
        let mut spec = sample_spec(Vec::new());
        push_vsock_endpoint(&mut spec, forward_endpoint(4100, None));

        let config = build_forward_config(&spec).expect("forward config should resolve");

        assert!(config.enabled);
        assert_eq!(config.port, 4100);
        assert!(config.uds.is_empty());
    }

    #[test]
    fn guest_agent_injects_forward_uds_guest_paths() {
        let mut spec = sample_spec(Vec::new());
        push_vsock_endpoint(
            &mut spec,
            forward_endpoint(
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
            ),
        );

        let config = build_forward_config(&spec).expect("forward config should resolve");

        assert_eq!(
            config
                .uds
                .iter()
                .map(|uds| uds.guest_path.as_str())
                .collect::<Vec<_>>(),
            vec!["/var/run/docker.sock", "/tmp/app.sock"]
        );
    }

    #[test]
    fn build_config_combines_forward_and_provision_config() {
        let mut spec = sample_spec(Vec::new());
        push_vsock_endpoint(&mut spec, forward_endpoint(4100, None));

        let config = build_config_with_host_context(
            "demo",
            &spec,
            &VmmonNetworkAttachment::None,
            &host_context(),
        )
        .expect("build agent config");

        assert!(config.forward.enabled);
        assert!(config.provision.enabled);
        assert_eq!(config.provision.hostname.as_deref(), Some("demo"));
        assert_eq!(
            config
                .ssh
                .authorized_users
                .iter()
                .map(|user| user.name.as_str())
                .collect::<Vec<_>>(),
            vec!["root", "silo"]
        );
    }
}
