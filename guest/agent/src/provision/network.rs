use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use agent_spec::{NetworkConfig, NetworkDnsConfig, NetworkInterfaceConfig};
use eyre::Context;
use nix::net::if_::if_nametoindex;
use rtnetlink::{LinkUnspec, RouteMessageBuilder};

use crate::provision::{
    write_file, FailurePolicy, ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
};

const LOOPBACK_INTERFACE: &str = "lo";

pub(crate) struct Network<'a> {
    config: Option<&'a NetworkConfig>,
}

impl<'a> Provisioner<'a> for Network<'a> {
    type Config = Option<NetworkConfig>;

    fn init(config: &'a Self::Config) -> Self {
        Self {
            config: config.as_ref(),
        }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::NETWORK
    }

    fn failure_policy(&self) -> FailurePolicy {
        FailurePolicy::FailBoot
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(configure_loopback())
        })?;

        let Some(config) = self.config else {
            tracing::info!("ensured guest loopback interface is up");
            return Ok(ProvisionOutcome::succeeded(true));
        };

        let interface = config
            .interfaces
            .first()
            .ok_or_else(|| eyre::eyre!("static network config has no interface"))?;
        let interface_name = interface_name_for_mac(&interface.mac_address)?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(configure_interface(&interface_name, interface))
        })?;
        replace_resolv_conf(context, &interface.dns)?;

        tracing::info!(
            interface = interface_name,
            address = %interface.ipv4.address,
            gateway = %interface.ipv4.gateway,
            "configured static guest network"
        );
        Ok(ProvisionOutcome::succeeded(true))
    }
}

async fn configure_loopback() -> eyre::Result<()> {
    let index = interface_index(LOOPBACK_INTERFACE)?;
    let (connection, handle, _) =
        rtnetlink::new_connection().context("open rtnetlink connection")?;
    let connection_task = tokio::spawn(connection);

    let result = bring_link_up(&handle, index, LOOPBACK_INTERFACE).await;
    connection_task.abort();
    result
}

async fn configure_interface(
    interface_name: &str,
    interface: &NetworkInterfaceConfig,
) -> eyre::Result<()> {
    let index = interface_index(interface_name)?;
    let (connection, handle, _) =
        rtnetlink::new_connection().context("open rtnetlink connection")?;
    let connection_task = tokio::spawn(connection);

    let result = async {
        bring_link_up(&handle, index, interface_name).await?;

        handle
            .address()
            .add(
                index,
                interface.ipv4.address.into(),
                interface.ipv4.prefix_length,
            )
            .replace()
            .execute()
            .await
            .with_context(|| {
                format!(
                    "configure IPv4 address {}/{} on {interface_name}",
                    interface.ipv4.address, interface.ipv4.prefix_length
                )
            })?;

        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .output_interface(index)
            .gateway(interface.ipv4.gateway)
            .build();
        handle
            .route()
            .add(route)
            .replace()
            .execute()
            .await
            .with_context(|| {
                format!(
                    "configure default IPv4 route via {} on {interface_name}",
                    interface.ipv4.gateway
                )
            })
    }
    .await;

    connection_task.abort();
    result
}

fn interface_index(interface_name: &str) -> eyre::Result<u32> {
    if_nametoindex(interface_name)
        .with_context(|| format!("resolve network interface index for {interface_name}"))
}

async fn bring_link_up(
    handle: &rtnetlink::Handle,
    index: u32,
    interface_name: &str,
) -> eyre::Result<()> {
    handle
        .link()
        .set(link_up_message(index))
        .execute()
        .await
        .with_context(|| format!("bring network interface {interface_name} up"))
}

fn link_up_message(index: u32) -> rtnetlink::packet_route::link::LinkMessage {
    LinkUnspec::new_with_index(index).up().build()
}

fn interface_name_for_mac(mac_address: &str) -> eyre::Result<String> {
    interface_name_for_mac_in(Path::new("/sys/class/net"), mac_address)
}

fn interface_name_for_mac_in(root: &Path, mac_address: &str) -> eyre::Result<String> {
    let expected = mac_address.to_ascii_lowercase();
    let entries = fs::read_dir(root).with_context(|| format!("read {}", root.display()))?;
    let mut matched = None;
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
        let address_path = entry.path().join("address");
        let address = match fs::read_to_string(&address_path) {
            Ok(address) => address,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("read {}", address_path.display()))
            }
        };
        if address.trim().to_ascii_lowercase() != expected {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| eyre::eyre!("network interface name is not valid UTF-8"))?;
        if matched.replace(name).is_some() {
            eyre::bail!("multiple network interfaces have MAC address {mac_address}");
        }
    }

    matched.ok_or_else(|| eyre::eyre!("no network interface has MAC address {mac_address}"))
}

fn replace_resolv_conf(context: &ProvisionContext, dns: &NetworkDnsConfig) -> eyre::Result<()> {
    let path = context.guest_path("/etc/resolv.conf");
    let temporary = temporary_resolv_path(&path)?;
    let result = (|| {
        write_file(&temporary, render_resolv_conf(dns), 0o644)?;
        fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_resolv_path(path: &Path) -> eyre::Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("resolver path has no parent: {}", path.display()))?;
    Ok(parent.join(format!(".resolv.conf.silo-{}", std::process::id())))
}

fn render_resolv_conf(dns: &NetworkDnsConfig) -> String {
    let mut contents = String::new();
    for server in &dns.servers {
        contents.push_str("nameserver ");
        contents.push_str(&server.to_string());
        contents.push('\n');
    }
    if !dns.search.is_empty() {
        contents.push_str("search ");
        contents.push_str(&dns.search.join(" "));
        contents.push('\n');
    }
    contents
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use agent_spec::NetworkDnsConfig;
    use rtnetlink::packet_route::link::LinkFlags;

    use crate::provision::network::{
        interface_name_for_mac_in, link_up_message, render_resolv_conf, replace_resolv_conf,
    };
    use crate::provision::ProvisionContext;

    #[test]
    fn link_up_message_sets_interface_up() {
        let message = link_up_message(7);

        assert_eq!(message.header.index, 7);
        assert_eq!(message.header.flags, LinkFlags::Up);
        assert_eq!(message.header.change_mask, LinkFlags::Up);
    }

    #[test]
    fn finds_interface_by_mac_address() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let interface = temp.path().join("eth7");
        fs::create_dir(&interface).expect("create interface dir");
        fs::write(interface.join("address"), "02:00:00:00:00:07\n")
            .expect("write interface address");

        let name =
            interface_name_for_mac_in(temp.path(), "02:00:00:00:00:07").expect("find interface");

        assert_eq!(name, "eth7");
    }

    #[test]
    fn renders_resolver_servers_and_search_domains() {
        let dns = NetworkDnsConfig {
            servers: vec![
                "192.168.105.1".parse().expect("IPv4 DNS"),
                "2001:db8::53".parse().expect("IPv6 DNS"),
            ],
            search: vec!["example.test".to_string(), "svc.test".to_string()],
        };

        assert_eq!(
            render_resolv_conf(&dns),
            "nameserver 192.168.105.1\nnameserver 2001:db8::53\nsearch example.test svc.test\n"
        );
    }

    #[test]
    fn resolver_replacement_replaces_symlink_without_touching_target() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let etc = temp.path().join("etc");
        fs::create_dir(&etc).expect("create etc");
        let target = temp.path().join("managed-resolv.conf");
        fs::write(&target, "managed\n").expect("write symlink target");
        symlink(&target, etc.join("resolv.conf")).expect("create resolver symlink");
        let context = ProvisionContext::for_test(temp.path());
        let dns = NetworkDnsConfig {
            servers: vec!["192.168.105.1".parse().expect("DNS server")],
            search: Vec::new(),
        };

        replace_resolv_conf(&context, &dns).expect("replace resolver config");

        assert_eq!(
            fs::read_to_string(&target).expect("read target"),
            "managed\n"
        );
        assert_eq!(
            fs::read_to_string(etc.join("resolv.conf")).expect("read resolver"),
            "nameserver 192.168.105.1\n"
        );
        assert!(!fs::symlink_metadata(etc.join("resolv.conf"))
            .expect("stat resolver")
            .file_type()
            .is_symlink());
    }
}
