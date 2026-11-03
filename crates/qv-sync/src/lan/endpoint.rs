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
        let ip = addr.ip();
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        !(ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST))
    }
}

/// Addresses a QR payload may list for a window in `scope`.
pub(crate) fn advertisable(scope: ListenScope, ip: &IpAddr) -> bool {
    match scope {
        ListenScope::LoopbackForTests => ip.is_loopback(),
        ListenScope::AllInterfaces => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || *ip == IpAddr::V4(Ipv4Addr::BROADCAST))
        }
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
