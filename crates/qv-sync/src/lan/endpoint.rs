// SPDX-License-Identifier: AGPL-3.0-or-later

//! Endpoint policy (0013 §1.4, §3.1): IP literals and ports only, never
//! trusted. Loopback is allowed only when a test enables it explicitly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};

/// Where a pairing window listens (plan 0037 decision 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenScope {
    /// Every interface: `[::]` and `0.0.0.0` on one port (see [`listen`]),
    /// else `0.0.0.0` alone.
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

/// Binds the non-blocking listeners of a window in `scope` on `port` (0:
/// OS-chosen); every listener has the same port. `AllInterfaces` binds `[::]`
/// first, then `0.0.0.0` on its port. Where `[::]` is dual stack (Linux by
/// default) that second bind fails and the first socket serves IPv4 too;
/// where it is IPv6-only (Windows, Linux `bindv6only`) the second serves
/// IPv4. Without IPv6, `0.0.0.0` alone.
pub(crate) fn listen(scope: ListenScope, port: u16) -> Result<Vec<TcpListener>, super::LanError> {
    let v4 = |port| TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    let listeners = match scope {
        ListenScope::LoopbackForTests => {
            vec![
                TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
                    .map_err(|_| super::LanError::Io)?,
            ]
        }
        ListenScope::AllInterfaces => {
            match TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)) {
                Ok(v6) => {
                    let port = v6.local_addr().map_err(|_| super::LanError::Io)?.port();
                    let mut both = vec![v6];
                    both.extend(v4(port).ok());
                    both
                }
                Err(_) => vec![v4(port).map_err(|_| super::LanError::Io)?],
            }
        }
    };
    for listener in &listeners {
        listener
            .set_nonblocking(true)
            .map_err(|_| super::LanError::Io)?;
    }
    Ok(listeners)
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

    #[test]
    fn endpoint_all_interfaces_listen_serves_ipv4_and_ipv6_on_one_port() {
        use std::net::TcpStream;
        use std::time::{Duration, Instant};
        let listeners = listen(ListenScope::AllInterfaces, 0).unwrap();
        let port = listeners[0].local_addr().unwrap().port();
        assert!(
            listeners
                .iter()
                .all(|l| l.local_addr().unwrap().port() == port)
        );
        // Windows `[::]` is IPv6-only: IPv4 must still reach the window.
        // IPv6 is checked where this host has `::1`.
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        let limit = Duration::from_secs(5);
        let peers = [
            Some(TcpStream::connect_timeout(&v4, limit).unwrap()),
            TcpStream::connect_timeout(&v6, limit).ok(),
        ];
        for _peer in peers.iter().flatten() {
            let end = Instant::now() + limit;
            while !listeners.iter().any(|l| l.accept().is_ok()) {
                assert!(Instant::now() < end, "a connection was not accepted");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
