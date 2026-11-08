// SPDX-License-Identifier: AGPL-3.0-or-later

//! Endpoint policy (0013 §1.4, §3.1): IP literals and ports only, never
//! trusted. Loopback is allowed only when a test enables it explicitly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Where a pairing window listens (plan 0037 decision 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenScope {
    /// Every interface: `[::]` (dual stack where the OS allows), else
    /// `0.0.0.0`.
    AllInterfaces,
    /// `127.0.0.1` only, for tests. The only way loopback endpoints appear in
    /// a QR payload.
    LoopbackForTests,
}

/// Which endpoints a joining device may contact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointPolicy {
    /// Allow loopback endpoints (tests only; frontends never set it).
    pub allow_loopback: bool,
}

impl EndpointPolicy {
    /// Whether `addr` is a usable endpoint: a unicast address, a non-zero
    /// port, and loopback only when allowed.
    pub fn accepts(&self, addr: &SocketAddr) -> bool {
        if addr.port() == 0 {
            return false;
        }
        let ip = addr.ip().to_canonical();
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        let link_local = match ip {
            IpAddr::V4(a) => a.is_link_local(),
            IpAddr::V6(a) => a.is_unicast_link_local(),
        };
        !(ip.is_unspecified()
            || ip.is_multicast()
            || ip == IpAddr::V4(Ipv4Addr::BROADCAST)
            || link_local)
    }
}

/// Addresses a QR payload may list for a window in `scope`.
pub(crate) fn advertisable(scope: ListenScope, ip: &IpAddr) -> bool {
    match scope {
        ListenScope::LoopbackForTests => ip.to_canonical().is_loopback(),
        ListenScope::AllInterfaces => EndpointPolicy::default().accepts(&SocketAddr::new(*ip, 1)),
    }
}

/// The listener addresses to try for `scope`.
pub(crate) fn bind_addrs(scope: ListenScope, port: u16) -> Vec<SocketAddr> {
    match scope {
        ListenScope::LoopbackForTests => {
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)]
        }
        ListenScope::AllInterfaces => vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        ],
    }
}

/// Parses typed endpoint text (0013 §8.5): `a.b.c.d:port` or `[v6]:port`,
/// IP literals only, port 1–65535, no zone identifier. The result is still
/// subject to the [`EndpointPolicy`] when used.
pub fn parse_endpoint(text: &str) -> Result<SocketAddr, super::LanError> {
    let e = qv_protocol::oob::parse_endpoint(text).map_err(|_| super::LanError::Protocol)?;
    Ok(SocketAddr::new(e.addr, e.port))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // 0012 §1: LAN discovery mistaken for trust
    #[test]
    fn endpoint_policy_classifies_mapped_addresses_and_advertisements_consistently() {
        for ip in [
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "169.254.1.1",
            "fe80::1",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
            "::ffff:169.254.1.1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            for allow_loopback in [false, true] {
                assert!(!EndpointPolicy { allow_loopback }.accepts(&SocketAddr::new(ip, 1234)));
            }
            assert!(!advertisable(ListenScope::AllInterfaces, &ip));
            assert!(!advertisable(ListenScope::LoopbackForTests, &ip));
        }
        for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!EndpointPolicy::default().accepts(&SocketAddr::new(ip, 1234)));
            assert!(
                EndpointPolicy {
                    allow_loopback: true
                }
                .accepts(&SocketAddr::new(ip, 1234))
            );
            assert!(!advertisable(ListenScope::AllInterfaces, &ip));
            assert!(advertisable(ListenScope::LoopbackForTests, &ip));
        }
        for ip in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(EndpointPolicy::default().accepts(&SocketAddr::new(ip, 1234)));
            assert!(!EndpointPolicy::default().accepts(&SocketAddr::new(ip, 0)));
            assert!(advertisable(ListenScope::AllInterfaces, &ip));
            assert!(!advertisable(ListenScope::LoopbackForTests, &ip));
        }
    }
}
