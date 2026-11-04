// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local unicast addresses for showing a window's endpoints (0013 §8.5; plan
//! 0038 decision 3). They are untrusted hints for the other device, never
//! authentication.
//!
//! No interface list is read. For each fixed probe destination an
//! unconnected UDP socket is `connect`ed, which selects a route and sends no
//! packet, and its local address is the one this device would use on that
//! route. The probes cover the private IPv4 ranges, shared address space, a
//! documentation address for the default route, and IPv6 unique-local and
//! global routes. Loopback, link-local (no scope ID fits an endpoint),
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

/// Up to 8 local unicast addresses, best first; empty when none is found.
pub fn local_addresses() -> Vec<IpAddr> {
    filter(PROBES.iter().filter_map(|p| route_source(*p)))
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
    fn net_local_addresses_are_showable_and_bounded() {
        // Whatever this host's routes are, the result obeys the filter.
        let found = local_addresses();
        assert!(found.len() <= MAX_ADDRESSES);
        assert!(found.iter().all(showable));
    }
}
