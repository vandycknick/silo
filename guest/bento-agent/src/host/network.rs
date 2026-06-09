use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use futures_util::stream::TryStreamExt;
use netlink_packet_route::{
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourFlags},
    route::{RouteAddress, RouteAttribute},
};
use rtnetlink::{new_connection, IpVersion, RouteMessageBuilder};

/// Usable default gateway addresses discovered from the guest's routing state.
///
/// Callers use this to reach host-facing services without hard-coding network
/// topology. DNS, for example, uses these addresses to build its default list
/// of upstream resolvers when the user did not configure any explicitly.
#[derive(Debug, Clone)]
pub(crate) struct GatewayDiscovery {
    /// IPv4 address of the guest's default gateway, if one is present.
    pub(crate) ipv4: Option<Ipv4Addr>,
    /// Preferred IPv6 address of the guest's default router, if one is present.
    ///
    /// Discovery prefers globally usable or ULA addresses over link-local ones
    /// so callers can use the result directly without carrying interface scope.
    pub(crate) ipv6: Option<Ipv6Addr>,
}

#[derive(Debug, Clone)]
enum RouterV6Target {
    GlobalOrUla(Ipv6Addr),
    LinkLocal,
}

/// Discovers usable default gateway addresses for the current guest.
///
/// This inspects the Linux routing table and neighbour table to find the host-
/// facing routers behind the guest's default routes. The result is intentionally
/// biased toward addresses that other modules can use directly:
///
/// - IPv4 returns the default route gateway as-is.
/// - IPv6 prefers a globally usable or ULA router address when neighbour data
///   exposes one, and drops link-local-only results from the public API.
///
/// The function succeeds when either address family yields a usable gateway. It
/// only returns an error when neither IPv4 nor IPv6 discovery finds one.
pub(crate) async fn discover_gateways() -> eyre::Result<GatewayDiscovery> {
    let ipv4 = get_default_gateway_v4().await.ok();
    let ipv6 = match get_default_gateway_v6().await.ok() {
        Some(RouterV6Target::GlobalOrUla(addr)) => Some(addr),
        Some(RouterV6Target::LinkLocal) | None => None,
    };

    if ipv4.is_none() && ipv6.is_none() {
        eyre::bail!("no usable default gateway found for ipv4 or ipv6")
    }

    Ok(GatewayDiscovery { ipv4, ipv6 })
}

async fn get_default_gateway_v4() -> eyre::Result<Ipv4Addr> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut routes = handle
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute();

    while let Some(route) = routes.try_next().await? {
        if route.header.destination_prefix_length != 0 {
            continue;
        }

        for attr in route.attributes {
            if let RouteAttribute::Gateway(RouteAddress::Inet(addr)) = attr {
                return Ok(addr);
            }
        }
    }

    eyre::bail!("no ipv4 default gateway found")
}

async fn get_default_gateway_v6() -> eyre::Result<RouterV6Target> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut routes = handle
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute();

    let mut gateway = None;
    let mut ifindex = None;

    while let Some(route) = routes.try_next().await? {
        if route.header.destination_prefix_length != 0 {
            continue;
        }

        let mut candidate_gateway = None;
        let mut candidate_oif = None;

        for attr in &route.attributes {
            match attr {
                RouteAttribute::Gateway(RouteAddress::Inet6(addr)) => {
                    candidate_gateway = Some(*addr)
                }
                RouteAttribute::Oif(index) => candidate_oif = Some(*index),
                _ => {}
            }
        }

        if let (Some(addr), Some(index)) = (candidate_gateway, candidate_oif) {
            gateway = Some(addr);
            ifindex = Some(index);
            break;
        }
    }

    let gateway = gateway.ok_or_else(|| eyre::eyre!("no ipv6 default gateway found"))?;
    let ifindex =
        ifindex.ok_or_else(|| eyre::eyre!("no output interface found for ipv6 default route"))?;

    let mut neighs = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();
    let mut ip_to_mac: HashMap<Ipv6Addr, Vec<u8>> = HashMap::new();
    let mut mac_to_ips: HashMap<Vec<u8>, Vec<Ipv6Addr>> = HashMap::new();

    while let Some(neigh) = neighs.try_next().await? {
        if neigh.header.ifindex != ifindex {
            continue;
        }

        let mut ip = None;
        let mut mac = None;

        for attr in &neigh.attributes {
            match attr {
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) => ip = Some(*addr),
                NeighbourAttribute::LinkLayerAddress(bytes) => mac = Some(bytes.clone()),
                _ => {}
            }
        }

        if let (Some(ip), Some(mac)) = (ip, mac) {
            if neigh.header.flags.contains(NeighbourFlags::Router) || ip == gateway {
                ip_to_mac.insert(ip, mac.clone());
                mac_to_ips.entry(mac).or_default().push(ip);
            }
        }
    }

    let router_mac = ip_to_mac
        .get(&gateway)
        .cloned()
        .ok_or_else(|| eyre::eyre!("gateway neighbour entry not present"))?;

    if let Some(ips) = mac_to_ips.get(&router_mac) {
        if let Some(best) = preferred_router_ipv6(ips) {
            return Ok(RouterV6Target::GlobalOrUla(best));
        }
    }

    Ok(RouterV6Target::LinkLocal)
}

fn preferred_router_ipv6(ips: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    ips.iter().copied().find(is_ula).or_else(|| {
        ips.iter()
            .copied()
            .find(|ip| !is_link_local(ip) && !ip.is_multicast() && !ip.is_unspecified())
    })
}

fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ula(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xfe00 == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_router_ipv6_picks_ula_before_global() {
        let ula = "fd00::1".parse().expect("valid ula");
        let global = "2001:db8::1".parse().expect("valid global");
        let link_local = "fe80::1".parse().expect("valid link-local");

        assert_eq!(preferred_router_ipv6(&[link_local, global, ula]), Some(ula));
        assert_eq!(preferred_router_ipv6(&[link_local, global]), Some(global));
        assert_eq!(preferred_router_ipv6(&[link_local]), None);
    }
}
