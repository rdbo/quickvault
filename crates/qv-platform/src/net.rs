// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local unicast addresses for showing a window's endpoints (0013 §8.5; plan
//! 0038 decision 3). They are untrusted hints for the other device, never
//! authentication.
//!
//! For each probe destination an unconnected UDP socket is `connect`ed,
//! which selects a route and sends no packet, and its local address is the
//! one this device would use on that route. The first probes are one address
//! inside each directly attached IPv4 network of the main routing table
//! (`/proc/net/route`, bounded; plan 0042): a VPN that routes everything else
//! through its own table would otherwise hide the LAN address behind the
//! tunnel's. Then fixed probes cover the private IPv4 ranges, shared address
//! space, a documentation address for the default route, and IPv6
//! unique-local and global routes. Where `/proc/net/route` is unreadable
//! (Android restricts it), only the fixed probes run. Loopback, link-local (no scope ID fits an endpoint),
//! unspecified and multicast results are dropped. An empty result means the
//! user types the address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// Most addresses returned (the QR's endpoint limit).
pub const MAX_ADDRESSES: usize = 8;

const PROBES: [IpAddr; 7] = [
    IpAddr::V4(Ipv4Addr::new(10, 255, 255, 254)),
    IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 255, 254)),
    IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254)),
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
];

/// The source address the route to `dest` would use, if there is one.
fn route_source(dest: IpAddr) -> Option<IpAddr> {
    let bind = match dest {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(SocketAddr::new(dest, 9)).ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// Whether `ip` may be shown as an endpoint.
fn showable(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_unicast_link_local(),
    }
}

/// Keeps the showable, distinct addresses in order, at most 8.
fn filter(found: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for ip in found {
        if showable(&ip) && !out.contains(&ip) && out.len() < MAX_ADDRESSES {
            out.push(ip);
        }
    }
    out
}

/// Largest `/proc/net/route` read; a longer table is truncated.
const MAX_ROUTE_TABLE: u64 = 64 * 1024;

/// One probe address inside each directly attached IPv4 network listed in a
/// `/proc/net/route` table: up, no gateway, a prefix of 1–30 bits, not
/// loopback. Fields are hex in the kernel's byte order.
fn attached_probes(table: &str) -> Vec<IpAddr> {
    let hex = |f: &str| u32::from_str_radix(f, 16).ok();
    let mut out = Vec::new();
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(iface), Some(dest), Some(gateway), Some(flags), Some(mask)) = (
            f.first(),
            f.get(1).and_then(|d| hex(d)),
            f.get(2).and_then(|g| hex(g)),
            f.get(3).and_then(|x| hex(x)),
            f.get(7).and_then(|m| hex(m)),
        ) else {
            continue;
        };
        let network = u32::from_be_bytes(dest.to_ne_bytes());
        let mask = u32::from_be_bytes(mask.to_ne_bytes());
        let prefix = mask.leading_ones();
        if *iface == "lo"
            || gateway != 0
            || flags & 1 == 0
            || !(1..=30).contains(&prefix)
            || mask.count_ones() != prefix
        {
            continue;
        }
        let probe = IpAddr::V4(Ipv4Addr::from((network & mask) | 1));
        if !out.contains(&probe) && out.len() < MAX_ADDRESSES {
            out.push(probe);
        }
    }
    out
}

fn route_table() -> String {
    use std::io::Read;
    let mut text = String::new();
    if let Ok(file) = std::fs::File::open("/proc/net/route") {
        let _ = file.take(MAX_ROUTE_TABLE).read_to_string(&mut text);
    }
    text
}

/// Up to 8 local unicast addresses, best first (directly attached networks,
/// then the fixed probes); empty when none is found.
pub fn local_addresses() -> Vec<IpAddr> {
    let attached = attached_probes(&route_table());
    filter(
        attached
            .iter()
            .chain(PROBES.iter())
            .filter_map(|p| route_source(*p)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_filter_drops_unshowable_and_duplicate_addresses() {
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        let found = [
            v4(127, 0, 0, 1),
            v4(0, 0, 0, 0),
            v4(169, 254, 1, 1),
            v4(224, 0, 0, 1),
            v4(255, 255, 255, 255),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            v4(192, 168, 1, 7),
            v4(192, 168, 1, 7),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)),
        ];
        assert_eq!(
            filter(found),
            vec![
                v4(192, 168, 1, 7),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7))
            ]
        );
        let many = (1..=20).map(|i| v4(10, 0, 0, i));
        assert_eq!(filter(many).len(), MAX_ADDRESSES);
    }

    #[test]
    fn net_attached_networks_come_from_the_main_route_table() {
        // A VPN host: the main table keeps only the LAN as attached.
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t010FA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t000FA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
            eth0\t000FA8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
            wg0\t0200020A\t00000000\t0001\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n\
            lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n\
            eth1\t0000000A\t00000000\t0000\t0\t0\t0\t000000FF\t0\t0\t0\n\
            eth2\t0000000A\t00000000\t0001\t0\t0\t0\t0000FF0F\t0\t0\t0\n\
            bad line\n";
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        // The default route (gateway), a /32 tunnel, loopback, a down route
        // and a non-contiguous mask are skipped; duplicates collapse.
        assert_eq!(attached_probes(table), vec![v4(192, 168, 15, 1)]);
        assert!(attached_probes("").is_empty());
    }

    #[test]
    fn net_local_addresses_are_showable_and_bounded() {
        // Whatever this host's routes are, the result obeys the filter.
        let found = local_addresses();
        assert!(found.len() <= MAX_ADDRESSES);
        assert!(found.iter().all(showable));
    }
}
