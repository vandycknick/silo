//! Static cold provisioning and the single fenced live-activation replacement.
//!
//! Cold boot discovers the configured MAC once and retains the actual interface object,
//! network namespace, ifindex and managed IPv4/default-route/DNS identity. Activation
//! never discovers by the destination MAC or invokes an external network manager.
//! It rejects ambiguous aliases/routes, replaces source state on that same object,
//! deletes normal and proxy neighbour entries, and checks local kernel and DNS readback.
//! Automatic IPv6 link-local state is discarded during replacement; configured IPv6
//! attachments remain unsupported. No gateway traffic is sent before host fence release.
//! A failed transaction has no source-identity rollback; lifecycle failure is sticky.

use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_spec::{NetworkConfig, NetworkDnsConfig, NetworkInterfaceConfig};
use eyre::Context;
use futures::TryStreamExt;
use nix::net::if_::if_nametoindex;
use rtnetlink::packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlags, LinkLayerType, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteType},
    AddressFamily,
};
use rtnetlink::{LinkUnspec, RouteMessageBuilder};

use crate::provision::{
    write_file, FailurePolicy, ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
};

const LOOPBACK_INTERFACE: &str = "lo";

/// A cold-provisioned identity, not a MAC-based discovery hint for restore.
#[derive(Debug)]
pub(crate) struct AppliedNetwork {
    index: u32,
    interface: NetworkInterfaceConfig,
    default_route: RouteMessage,
    identity: Arc<LinkIdentity>,
}

#[derive(Debug)]
struct LinkIdentity {
    device: File,
    namespace: File,
}

impl AppliedNetwork {
    pub(crate) fn ifindex(&self) -> u32 {
        self.index
    }

    /// Payload and namespace checks only. Kernel topology is checked again before effects.
    pub(crate) fn validate_activation(&self, target: &NetworkConfig) -> eyre::Result<()> {
        target.validate()?;
        if self.ifindex() == 0 {
            eyre::bail!("retained managed interface has zero ifindex");
        }
        same_file(&self.identity.namespace, Path::new("/proc/self/ns/net"))
            .context("managed network namespace changed")?;
        Ok(())
    }
}

/// Own the connection even when the surrounding lifecycle operation is cancelled.
struct Netlink {
    handle: rtnetlink::Handle,
    task: tokio::task::JoinHandle<()>,
}

impl Netlink {
    fn open() -> eyre::Result<Self> {
        let (connection, handle, _) =
            rtnetlink::new_connection().context("open rtnetlink connection")?;
        Ok(Self {
            handle,
            task: tokio::spawn(connection),
        })
    }
}

impl Drop for Netlink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Replace only the captured managed attachment, while workload and host fences stay closed.
///
/// Failure deliberately leaves partial destination state in place. The caller records sticky
/// activation failure and destroys that restore attempt, never rolls back to the source identity.
pub(crate) async fn activate_network(
    applied: &AppliedNetwork,
    target: &NetworkConfig,
) -> eyre::Result<AppliedNetwork> {
    applied.validate_activation(target)?;
    let interface = target
        .interfaces
        .first()
        .ok_or_else(|| eyre::eyre!("activation network has no interface"))?;
    let netlink = Netlink::open()?;
    let handle = &netlink.handle;
    let before = network_state(handle, applied.index).await?;
    validate_retained_link(applied, &before.link)?;
    // The native restore may already have applied the approved destination MAC override.
    let source_mac = applied.interface.mac_address_bytes()?;
    let target_mac = interface.mac_address_bytes()?;
    let actual_mac = link_mac(&before.link)?;
    if actual_mac != source_mac && actual_mac != target_mac {
        eyre::bail!("managed interface MAC is neither source nor destination identity");
    }
    validate_state(&before, applied.index, &applied.interface, true)?;

    handle
        .link()
        .set(LinkUnspec::new_with_index(applied.index).down().build())
        .execute()
        .await
        .context("bring retained managed interface down for activation")?;
    if let Err(error) = handle
        .route()
        .del(applied.default_route.clone())
        .execute()
        .await
    {
        if !already_absent(&error) {
            return Err(error).context("delete source managed default route");
        }
    }
    for address in before.addresses {
        // The admitted shape includes only the managed IPv4 address and automatic IPv6
        // link-local addresses. Remove both so no MAC-derived source address survives.
        if let Err(error) = handle.address().del(address).execute().await {
            if !already_absent(&error) {
                return Err(error).context("delete source managed interface address");
            }
        }
    }
    let remaining = network_state(handle, applied.index).await?;
    if remaining
        .addresses
        .iter()
        .any(|address| address.header.family == AddressFamily::Inet)
        || !remaining.routes.is_empty()
    {
        eyre::bail!("source managed IPv4 identity remains after deletion");
    }
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(applied.index)
                .address(target_mac.to_vec())
                .build(),
        )
        .execute()
        .await
        .context("set destination MAC on retained managed interface")?;
    bring_link_up(handle, applied.index, "retained managed interface").await?;
    install_ipv4(handle, applied.index, interface).await?;
    flush_neighbours(handle, applied.index).await?;

    let after = network_state(handle, applied.index).await?;
    validate_retained_link(applied, &after.link)?;
    if !after.link.header.flags.contains(LinkFlags::Up) || link_mac(&after.link)? != target_mac {
        eyre::bail!("destination managed link readback differs from requested identity");
    }
    let default_route = validate_state(&after, applied.index, interface, true)?.clone();
    let resolver = Path::new("/etc/resolv.conf");
    replace_resolv_conf_at(resolver, &interface.dns)?;
    verify_resolv_conf_at(resolver, &interface.dns)?;
    Ok(AppliedNetwork {
        index: applied.index,
        interface: interface.clone(),
        default_route,
        identity: Arc::clone(&applied.identity),
    })
}

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

        config.validate()?;
        let applied = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(configure_interface(&interface_name, interface))
        })?;
        replace_resolv_conf(context, &interface.dns)?;
        verify_resolv_conf(context, &interface.dns)?;
        *context
            .applied_network
            .try_borrow_mut()
            .context("retain cold-provisioned managed network")? = Some(applied);

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
    let netlink = Netlink::open()?;
    bring_link_up(&netlink.handle, index, LOOPBACK_INTERFACE).await
}

async fn configure_interface(
    interface_name: &str,
    interface: &NetworkInterfaceConfig,
) -> eyre::Result<AppliedNetwork> {
    let index = interface_index(interface_name)?;
    let netlink = Netlink::open()?;
    bring_link_up(&netlink.handle, index, interface_name).await?;
    install_ipv4(&netlink.handle, index, interface).await?;
    let state = network_state(&netlink.handle, index).await?;
    if link_mac(&state.link)? != interface.mac_address_bytes()? {
        eyre::bail!("cold-provisioned managed interface MAC changed during setup");
    }
    let default_route = validate_state(&state, index, interface, false)?.clone();
    let identity = LinkIdentity {
        device: File::open(device_path(&state.link)?).context("retain managed network device")?,
        namespace: File::open("/proc/self/ns/net").context("retain managed network namespace")?,
    };
    Ok(AppliedNetwork {
        index,
        interface: interface.clone(),
        default_route,
        identity: Arc::new(identity),
    })
}

async fn install_ipv4(
    handle: &rtnetlink::Handle,
    index: u32,
    interface: &NetworkInterfaceConfig,
) -> eyre::Result<()> {
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
        .context("install managed IPv4 address")?;
    handle
        .route()
        .add(
            RouteMessageBuilder::<Ipv4Addr>::new()
                .output_interface(index)
                .gateway(interface.ipv4.gateway)
                .build(),
        )
        .replace()
        .execute()
        .await
        .context("install managed IPv4 default route")
}

struct NetworkState {
    link: LinkMessage,
    addresses: Vec<AddressMessage>,
    routes: Vec<RouteMessage>,
    ipv6_routes: Vec<RouteMessage>,
}

async fn network_state(handle: &rtnetlink::Handle, index: u32) -> eyre::Result<NetworkState> {
    let link = handle
        .link()
        .get()
        .match_index(index)
        .execute()
        .try_next()
        .await
        .context("read retained managed link")?
        .ok_or_else(|| eyre::eyre!("retained managed interface {index} disappeared"))?;
    let addresses = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect()
        .await
        .context("read managed interface addresses")?;
    let all_routes: Vec<RouteMessage> = handle
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute()
        .try_collect()
        .await
        .context("read managed IPv4 routes")?;
    let routes = all_routes
        .into_iter()
        .filter(|route| route_uses_interface(route, index))
        .collect();
    let all_ipv6: Vec<RouteMessage> = handle
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute()
        .try_collect()
        .await
        .context("read managed IPv6 topology")?;
    let ipv6_routes = all_ipv6
        .into_iter()
        .filter(|route| route_uses_interface(route, index))
        .collect();
    Ok(NetworkState {
        link,
        addresses,
        routes,
        ipv6_routes,
    })
}

fn route_uses_interface(route: &RouteMessage, index: u32) -> bool {
    route.attributes.iter().any(|attribute| match attribute {
        RouteAttribute::Oif(output) => *output == index,
        RouteAttribute::MultiPath(hops) => hops.iter().any(|hop| hop.interface_index == index),
        _ => false,
    })
}

fn link_mac(link: &LinkMessage) -> eyre::Result<[u8; 6]> {
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::Address(address) => Some(address.as_slice()),
            _ => None,
        })
        .ok_or_else(|| eyre::eyre!("managed link has no MAC address"))?
        .try_into()
        .map_err(|_| eyre::eyre!("managed link does not have an Ethernet MAC address"))
}

fn device_path(link: &LinkMessage) -> eyre::Result<PathBuf> {
    let name = link
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name),
            _ => None,
        })
        .ok_or_else(|| eyre::eyre!("managed link has no interface name"))?;
    // Names are kernel-provided, but never let a path-shaped name escape sysfs.
    if name.is_empty() || name.contains('/') || matches!(name.as_str(), "." | "..") {
        eyre::bail!("managed link has an invalid interface name");
    }
    Ok(Path::new("/sys/class/net").join(name))
}

fn same_file(retained: &File, current: &Path) -> eyre::Result<()> {
    let retained = retained
        .metadata()
        .context("stat retained network identity")?;
    let current = fs::metadata(current).context("stat current network identity")?;
    if retained.dev() != current.dev() || retained.ino() != current.ino() {
        eyre::bail!("retained network object was replaced");
    }
    Ok(())
}

fn validate_retained_link(applied: &AppliedNetwork, link: &LinkMessage) -> eyre::Result<()> {
    if link.header.index != applied.index || link.header.link_layer_type != LinkLayerType::Ether {
        eyre::bail!("retained managed interface index or Ethernet topology changed");
    }
    if link
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, LinkAttribute::Controller(index) if *index != 0))
    {
        eyre::bail!("managed interface became a bridge/bond port");
    }
    same_file(&applied.identity.device, &device_path(link)?)
        .context("managed interface was deleted or replaced")
}

fn address_is_managed(address: &AddressMessage, interface: &NetworkInterfaceConfig) -> bool {
    address.header.family == AddressFamily::Inet
        && address.header.prefix_len == interface.ipv4.prefix_length
        && address.attributes.iter().any(|attribute| {
            matches!(attribute, AddressAttribute::Local(IpAddr::V4(local))
                if *local == interface.ipv4.address)
        })
        && address.attributes.iter().all(|attribute| match attribute {
            AddressAttribute::Address(IpAddr::V4(peer))
            | AddressAttribute::Local(IpAddr::V4(peer)) => *peer == interface.ipv4.address,
            _ => true,
        })
}

fn automatic_ipv6_link_local(address: &AddressMessage) -> bool {
    address.header.family == AddressFamily::Inet6
        && address.attributes.iter().any(|attribute| {
            matches!(attribute, AddressAttribute::Address(IpAddr::V6(ip))
                if ip.is_unicast_link_local())
        })
}

fn validate_state<'a>(
    state: &'a NetworkState,
    index: u32,
    interface: &NetworkInterfaceConfig,
    strict: bool,
) -> eyre::Result<&'a RouteMessage> {
    let mut addresses = 0;
    for address in &state.addresses {
        if address.header.index != index {
            eyre::bail!("address readback returned a different managed ifindex");
        }
        if address_is_managed(address, interface) {
            addresses += 1;
        } else if strict && !automatic_ipv6_link_local(address) {
            eyre::bail!("unexpected source-facing address on managed interface: {address:?}");
        }
    }
    if addresses != 1 {
        eyre::bail!("managed IPv4 address readback is missing or ambiguous");
    }
    let mut default = None;
    for route in &state.routes {
        if is_managed_default(route, index, interface) {
            if default.replace(route).is_some() {
                eyre::bail!("managed default route readback is ambiguous");
            }
        } else if strict && !is_managed_kernel_route(route, index, interface) {
            eyre::bail!("unexpected source-facing route on managed interface: {route:?}");
        }
    }
    if strict
        && state
            .ipv6_routes
            .iter()
            .any(|route| !automatic_ipv6_route(route, &state.addresses))
    {
        eyre::bail!("managed IPv4 attachment has unsupported IPv6 routes");
    }
    default.ok_or_else(|| eyre::eyre!("managed default route readback is missing"))
}

fn route_table(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(route.header.table))
}

fn basic_managed_route(
    route: &RouteMessage,
    index: u32,
    interface: &NetworkInterfaceConfig,
) -> bool {
    route.header.address_family == AddressFamily::Inet
        && route.header.source_prefix_length == 0
        && route.header.tos == 0
        && route
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, RouteAttribute::Oif(output) if *output == index))
        && route.attributes.iter().all(|attribute| match attribute {
            RouteAttribute::Oif(output) => *output == index,
            RouteAttribute::PrefSource(RouteAddress::Inet(source)) => {
                *source == interface.ipv4.address
            }
            RouteAttribute::Destination(RouteAddress::Inet(_))
            | RouteAttribute::Gateway(RouteAddress::Inet(_))
            | RouteAttribute::Table(_)
            | RouteAttribute::CacheInfo(_) => true,
            _ => false,
        })
}

fn is_managed_default(
    route: &RouteMessage,
    index: u32,
    interface: &NetworkInterfaceConfig,
) -> bool {
    basic_managed_route(route, index, interface)
        && route_table(route) == 254
        && route.header.protocol == RouteProtocol::Static
        && route.header.kind == RouteType::Unicast
        && route.header.destination_prefix_length == 0
        && route.attributes.iter().any(|attribute| {
            matches!(attribute, RouteAttribute::Gateway(RouteAddress::Inet(gateway))
                if *gateway == interface.ipv4.gateway)
        })
        && route.attributes.iter().all(|attribute| {
            !matches!(attribute, RouteAttribute::Destination(RouteAddress::Inet(destination))
                if !destination.is_unspecified())
        })
}

fn is_managed_kernel_route(
    route: &RouteMessage,
    index: u32,
    interface: &NetworkInterfaceConfig,
) -> bool {
    if !basic_managed_route(route, index, interface)
        || route.header.protocol != RouteProtocol::Kernel
        || route
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, RouteAttribute::Gateway(_)))
    {
        return false;
    }
    let mask = u32::MAX << (32 - interface.ipv4.prefix_length);
    let network = Ipv4Addr::from(u32::from(interface.ipv4.address) & mask);
    let broadcast = Ipv4Addr::from(u32::from(network) | !mask);
    let destination = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => Some(*address),
            _ => None,
        });
    match (
        route_table(route),
        route.header.kind,
        route.header.destination_prefix_length,
        destination,
    ) {
        (254, RouteType::Unicast, prefix, Some(address)) => {
            prefix == interface.ipv4.prefix_length && address == network
        }
        (255, RouteType::Local, 32, Some(address)) => address == interface.ipv4.address,
        (255, RouteType::Broadcast, 32, Some(address)) => {
            address == network || address == broadcast
        }
        _ => false,
    }
}

fn automatic_ipv6_route(route: &RouteMessage, addresses: &[AddressMessage]) -> bool {
    if route.header.address_family != AddressFamily::Inet6
        || route.header.protocol != RouteProtocol::Kernel
        || route.header.source_prefix_length != 0
        || route.attributes.iter().any(|attribute| {
            matches!(
                attribute,
                RouteAttribute::Gateway(_) | RouteAttribute::MultiPath(_) | RouteAttribute::Via(_)
            )
        })
    {
        return false;
    }
    let destination = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet6(ip)) => Some(*ip),
            _ => None,
        });
    match (
        route.header.kind,
        route.header.destination_prefix_length,
        destination,
    ) {
        (RouteType::Unicast, 64, Some(ip)) => ip == Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        (RouteType::Multicast, 8, Some(ip)) => ip == Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        (RouteType::Local, 128, Some(ip)) => addresses.iter().any(|address| {
            automatic_ipv6_link_local(address) && address.attributes.iter().any(|attribute| {
                matches!(attribute, AddressAttribute::Address(IpAddr::V6(local)) if *local == ip)
            })
        }),
        _ => false,
    }
}

async fn flush_neighbours(handle: &rtnetlink::Handle, index: u32) -> eyre::Result<()> {
    // RTM_GETNEIGH exposes proxy entries through a separate NTF_PROXY dump.
    for proxies in [false, true] {
        let request = handle.neighbours().get();
        let request = if proxies { request.proxies() } else { request };
        let entries: Vec<_> = request
            .execute()
            .try_collect()
            .await
            .context("enumerate managed interface neighbours")?;
        for entry in entries {
            if entry.header.ifindex != index {
                continue;
            }
            if let Err(error) = handle.neighbours().del(entry).execute().await {
                if !already_absent(&error) {
                    return Err(error).context("delete managed interface neighbour");
                }
            }
        }
        let request = handle.neighbours().get();
        let request = if proxies { request.proxies() } else { request };
        let mut readback = request.execute();
        while let Some(entry) = readback
            .try_next()
            .await
            .context("read back neighbour deletion")?
        {
            if entry.header.ifindex == index {
                eyre::bail!("managed interface neighbour remains after activation flush");
            }
        }
    }
    Ok(())
}

fn already_absent(error: &rtnetlink::Error) -> bool {
    matches!(error, rtnetlink::Error::NetlinkError(message)
        if matches!(message.raw_code(), code if code == -(nix::errno::Errno::ENOENT as i32)
            || code == -(nix::errno::Errno::ESRCH as i32)
            || code == -(nix::errno::Errno::EADDRNOTAVAIL as i32)))
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
    replace_resolv_conf_at(&context.guest_path("/etc/resolv.conf"), dns)
}

fn verify_resolv_conf(context: &ProvisionContext, dns: &NetworkDnsConfig) -> eyre::Result<()> {
    verify_resolv_conf_at(&context.guest_path("/etc/resolv.conf"), dns)
}

fn verify_resolv_conf_at(path: &Path, dns: &NetworkDnsConfig) -> eyre::Result<()> {
    let actual =
        fs::read_to_string(path).with_context(|| format!("read back {}", path.display()))?;
    if actual != render_resolv_conf(dns) {
        eyre::bail!("managed DNS readback differs from destination configuration");
    }
    Ok(())
}

fn replace_resolv_conf_at(path: &Path, dns: &NetworkDnsConfig) -> eyre::Result<()> {
    let temporary = temporary_resolv_path(path)?;
    let result = (|| {
        write_file(&temporary, render_resolv_conf(dns), 0o644)?;
        fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
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
    use std::fs::{self, File};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::fs::symlink;
    use std::sync::Arc;

    use agent_spec::{NetworkConfig, NetworkDnsConfig, NetworkInterfaceConfig, NetworkIpv4Config};
    use rtnetlink::packet_route::{
        link::{LinkAttribute, LinkFlags},
        route::{RouteAttribute, RouteProtocol, RouteType},
    };
    use rtnetlink::{AddressMessageBuilder, LinkUnspec, RouteMessageBuilder, RouteNextHopBuilder};

    use crate::provision::network::{
        interface_name_for_mac_in, link_mac, link_up_message, render_resolv_conf,
        replace_resolv_conf, route_uses_interface, same_file, temporary_resolv_path,
        validate_state, verify_resolv_conf, AppliedNetwork, LinkIdentity, NetworkState,
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

    fn interface() -> NetworkInterfaceConfig {
        NetworkInterfaceConfig {
            mac_address: "02:00:00:00:00:07".into(),
            ipv4: NetworkIpv4Config {
                address: Ipv4Addr::new(192, 168, 105, 7),
                prefix_length: 24,
                gateway: Ipv4Addr::new(192, 168, 105, 1),
            },
            dns: NetworkDnsConfig {
                servers: vec![Ipv4Addr::new(192, 168, 105, 1).into()],
                search: vec!["destination.test".into()],
            },
        }
    }

    fn state(interface: &NetworkInterfaceConfig) -> NetworkState {
        NetworkState {
            link: LinkUnspec::new_with_index(7)
                .name("renamed7".into())
                .address(interface.mac_address_bytes().expect("MAC").to_vec())
                .up()
                .build(),
            addresses: vec![AddressMessageBuilder::<Ipv4Addr>::new()
                .index(7)
                .address(interface.ipv4.address, interface.ipv4.prefix_length)
                .build()],
            routes: vec![
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .output_interface(7)
                    .gateway(interface.ipv4.gateway)
                    .build(),
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .output_interface(7)
                    .protocol(RouteProtocol::Kernel)
                    .destination_prefix(Ipv4Addr::new(192, 168, 105, 0), 24)
                    .build(),
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .output_interface(7)
                    .protocol(RouteProtocol::Kernel)
                    .table_id(255)
                    .kind(RouteType::Local)
                    .destination_prefix(interface.ipv4.address, 32)
                    .build(),
            ],
            ipv6_routes: Vec::new(),
        }
    }

    #[test]
    fn destination_readback_accepts_managed_kernel_routes_and_renamed_link() {
        let interface = interface();
        let state = state(&interface);
        assert!(validate_state(&state, 7, &interface, true).is_ok());
        assert!(validate_state(&state, 8, &interface, true).is_err());
        assert_eq!(link_mac(&state.link).expect("link MAC"), [2, 0, 0, 0, 0, 7]);
    }

    #[test]
    fn activation_readback_rejects_source_alias_even_when_destination_exists() {
        let interface = interface();
        let mut state = state(&interface);
        state.addresses.push(
            AddressMessageBuilder::<Ipv4Addr>::new()
                .index(7)
                .address(Ipv4Addr::new(192, 168, 105, 42), 24)
                .build(),
        );
        assert!(validate_state(&state, 7, &interface, true).is_err());
        // Cold provisioning remains additive; live admission must be stricter.
        assert!(validate_state(&state, 7, &interface, false).is_ok());
    }

    #[test]
    fn activation_readback_rejects_old_default_route_and_unmanaged_subnet() {
        let interface = interface();
        let mut state = state(&interface);
        state.routes.push(
            RouteMessageBuilder::<Ipv4Addr>::new()
                .output_interface(7)
                .gateway(Ipv4Addr::new(192, 168, 105, 254))
                .build(),
        );
        assert!(validate_state(&state, 7, &interface, true).is_err());
        state.routes.pop();
        state.routes.push(
            RouteMessageBuilder::<Ipv4Addr>::new()
                .output_interface(7)
                .protocol(RouteProtocol::Kernel)
                .destination_prefix(Ipv4Addr::new(10, 42, 0, 0), 16)
                .build(),
        );
        assert!(validate_state(&state, 7, &interface, true).is_err());
    }

    #[test]
    fn activation_readback_rejects_missing_or_duplicate_destination_state() {
        let interface = interface();
        let mut state = state(&interface);
        state.routes.remove(0);
        assert!(validate_state(&state, 7, &interface, true).is_err());
        state.addresses.clear();
        assert!(validate_state(&state, 7, &interface, true).is_err());
        let mut state = crate::provision::network::tests::state(&interface);
        state.routes.push(state.routes[0].clone());
        assert!(validate_state(&state, 7, &interface, true).is_err());
    }

    #[test]
    fn activation_readback_detects_multipath_using_retained_interface() {
        let interface = interface();
        let mut state = state(&interface);
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .multipath(vec![RouteNextHopBuilder::new_ipv4()
                .interface(7)
                .via(interface.ipv4.gateway.into())
                .expect("IPv4 next hop")
                .build()])
            .build();
        assert!(route_uses_interface(&route, 7));
        assert!(!route_uses_interface(&route, 8));
        state.routes.push(route);
        assert!(validate_state(&state, 7, &interface, true).is_err());
    }

    #[test]
    fn activation_readback_rejects_global_ipv6_but_allows_automatic_link_local() {
        let interface = interface();
        let mut state = state(&interface);
        state.addresses.push(
            AddressMessageBuilder::<Ipv6Addr>::new()
                .index(7)
                .address("fe80::7".parse().expect("link local"), 64)
                .build(),
        );
        assert!(validate_state(&state, 7, &interface, true).is_ok());
        state.addresses.push(
            AddressMessageBuilder::<Ipv6Addr>::new()
                .index(7)
                .address("2001:db8::7".parse().expect("global IPv6"), 64)
                .build(),
        );
        assert!(validate_state(&state, 7, &interface, true).is_err());
    }

    #[test]
    fn activation_readback_rejects_ipv6_gateway_without_global_address() {
        let interface = interface();
        let mut state = state(&interface);
        state.ipv6_routes.push(
            RouteMessageBuilder::<Ipv6Addr>::new()
                .output_interface(7)
                .gateway("fe80::1".parse().expect("IPv6 gateway"))
                .build(),
        );
        assert!(validate_state(&state, 7, &interface, true).is_err());
    }

    #[test]
    fn retained_network_object_survives_rename_but_rejects_index_replacement() {
        let temp = tempfile::tempdir().expect("fixture");
        let original = temp.path().join("eth7");
        let renamed = temp.path().join("renamed7");
        fs::create_dir(&original).expect("device directory");
        let retained = File::open(&original).expect("retain device");
        fs::rename(&original, &renamed).expect("rename interface");
        same_file(&retained, &renamed).expect("same renamed object");
        fs::create_dir(&original).expect("replacement interface");
        assert!(same_file(&retained, &original).is_err());
    }

    #[test]
    fn activation_payload_validation_reuses_provisioning_bounds_before_effects() {
        let interface = interface();
        let state = state(&interface);
        let applied = AppliedNetwork {
            index: 7,
            interface: interface.clone(),
            default_route: state.routes[0].clone(),
            identity: Arc::new(LinkIdentity {
                device: File::open("/dev/null").expect("retained descriptor"),
                namespace: File::open("/proc/self/ns/net").expect("retained namespace"),
            }),
        };
        assert_eq!(applied.ifindex(), 7);
        let mut target = NetworkConfig {
            interfaces: vec![interface],
        };
        applied.validate_activation(&target).expect("valid payload");
        target.interfaces[0].ipv4.prefix_length = 255;
        assert!(applied.validate_activation(&target).is_err());
        target.interfaces.clear();
        assert!(applied.validate_activation(&target).is_err());
    }

    #[test]
    fn resolver_readback_detects_stale_source_configuration() {
        let temp = tempfile::tempdir().expect("fixture");
        let context = ProvisionContext::for_test(temp.path());
        let dns = interface().dns;
        replace_resolv_conf(&context, &dns).expect("destination DNS");
        verify_resolv_conf(&context, &dns).expect("destination DNS readback");
        fs::write(temp.path().join("etc/resolv.conf"), "nameserver 10.0.0.1\n")
            .expect("source DNS");
        assert!(verify_resolv_conf(&context, &dns).is_err());
    }

    #[test]
    fn failed_resolver_replacement_removes_temporary_file() {
        let temp = tempfile::tempdir().expect("fixture");
        let path = temp.path().join("etc/resolv.conf");
        fs::create_dir_all(&path).expect("non-replaceable resolver directory");
        let context = ProvisionContext::for_test(temp.path());
        assert!(replace_resolv_conf(&context, &interface().dns).is_err());
        assert!(path.is_dir());
        assert!(!temporary_resolv_path(&path)
            .expect("temporary path")
            .exists());
    }

    #[test]
    fn link_mac_rejects_missing_or_non_ethernet_address() {
        let mut link = LinkUnspec::new_with_index(7).build();
        assert!(link_mac(&link).is_err());
        link.attributes.push(LinkAttribute::Address(vec![1, 2, 3]));
        assert!(link_mac(&link).is_err());
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .output_interface(8)
            .build();
        assert!(!route_uses_interface(&route, 7));
        assert!(route.attributes.contains(&RouteAttribute::Oif(8)));
    }
}
