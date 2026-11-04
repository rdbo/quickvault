// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scanned hints use the existing canonical codecs and production address policy.
use super::{EndpointPolicy, LanError};
use qv_protocol::oob::{decode_addr_qr, decode_qr};
use qv_protocol::registry::LanProfile;
use std::net::{IpAddr, SocketAddr};

/// Which explicit form a scanned code can fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanQrKind {
    /// A secret pairing code; still requires comparison-code approval.
    Pairing,
    /// Address hints for an already linked vault.
    Address,
}

/// Non-secret information from a validated scanned code. Hints grant no trust.
pub struct LanQrInfo {
    /// The expected form.
    pub kind: LanQrKind,
    /// Distinct usable hints, at most eight. Never remembered beyond an action.
    pub endpoints: Vec<SocketAddr>,
}
impl core::fmt::Debug for LanQrInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LanQrInfo(<redacted>)")
    }
}

/// Validate a canonical pairing/address QR and its profile, without network I/O.
pub fn inspect_lan_qr(bytes: &[u8]) -> Result<LanQrInfo, LanError> {
    let (kind, profile, hints) = if let Ok(q) = decode_qr(bytes) {
        (LanQrKind::Pairing, q.profile, q.endpoints)
    } else {
        let q = decode_addr_qr(bytes).map_err(|_| LanError::Protocol)?;
        (LanQrKind::Address, q.profile, q.endpoints)
    };
    LanProfile::from_id(profile).map_err(|_| LanError::Unsupported)?;
    let had_hints = !hints.is_empty();
    let mut endpoints = Vec::new();
    for hint in hints {
        let addr = SocketAddr::new(hint.addr, hint.port);
        let usable = EndpointPolicy::default().accepts(&addr)
            && match hint.addr {
                IpAddr::V4(a) => !a.is_link_local(),
                IpAddr::V6(a) => !a.is_unicast_link_local() && a.to_ipv4_mapped().is_none(),
            };
        if !usable {
            return Err(LanError::Protocol);
        }
        if !endpoints.contains(&addr) {
            endpoints.push(addr);
        }
    }
    if endpoints.is_empty() && (had_hints || kind == LanQrKind::Address) {
        return Err(LanError::Protocol);
    }
    Ok(LanQrInfo { kind, endpoints })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use qv_protocol::oob::{WireEndpoint, encode_addr_qr, encode_qr};
    // 0012 §1: LAN discovery mistaken for trust
    #[test]
    fn qr_inspection_refuses_hostile_profiles_shapes_and_unusable_addresses() {
        let endpoint = |s: &str| WireEndpoint {
            addr: s.parse().unwrap(),
            port: 7777,
        };
        let code = encode_qr(LanProfile::V1, &[7; 16], &[endpoint("192.0.2.10")], "").unwrap();
        let info = inspect_lan_qr(&code).unwrap();
        assert_eq!(info.kind, LanQrKind::Pairing);
        assert_eq!(info.endpoints.len(), 1);
        assert_eq!(format!("{info:?}"), "LanQrInfo(<redacted>)");
        let empty = encode_qr(LanProfile::V1, &[7; 16], &[], "").unwrap();
        assert!(inspect_lan_qr(&empty).unwrap().endpoints.is_empty());
        for ip in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.1.1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            let q = encode_addr_qr(LanProfile::V1, &[endpoint(ip)]).unwrap();
            assert!(inspect_lan_qr(&q).is_err());
        }
        let mut q = encode_addr_qr(LanProfile::V1, &[endpoint("192.0.2.10")]).unwrap();
        let profile = 2 + qv_protocol::oob::ADDR_QR_LABEL.len();
        q[profile] = 2;
        assert_eq!(inspect_lan_qr(&q).err(), Some(LanError::Unsupported));
        assert!(inspect_lan_qr(&[0; 1025]).is_err());
        assert!(inspect_lan_qr(b"https://example.invalid/").is_err());
    }
}
