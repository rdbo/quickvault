// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scanned hints use the existing canonical codecs and production address policy.
use super::{EndpointPolicy, LanError};
use qv_protocol::oob::decode_qr;
use qv_protocol::registry::LanProfile;
use std::net::SocketAddr;

/// Non-secret information from a validated scanned code (0013 §4.2). Hints
/// grant no trust.
pub struct LanQrInfo {
    /// Distinct usable hints, at most eight. Never remembered beyond an action.
    pub endpoints: Vec<SocketAddr>,
}
impl core::fmt::Debug for LanQrInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LanQrInfo(<redacted>)")
    }
}

/// Validate a canonical code QR and its profile, without network I/O.
pub fn inspect_lan_qr(bytes: &[u8]) -> Result<LanQrInfo, LanError> {
    let q = decode_qr(bytes).map_err(|_| LanError::Protocol)?;
    let (profile, hints) = (q.profile, q.endpoints);
    LanProfile::from_id(profile).map_err(|_| LanError::Unsupported)?;
    let had_hints = !hints.is_empty();
    let mut endpoints = Vec::new();
    for hint in hints {
        let addr = SocketAddr::new(hint.addr, hint.port);
        if !EndpointPolicy::default().accepts(&addr) {
            return Err(LanError::Protocol);
        }
        if !endpoints.contains(&addr) {
            endpoints.push(addr);
        }
    }
    if endpoints.is_empty() && had_hints {
        return Err(LanError::Protocol);
    }
    Ok(LanQrInfo { endpoints })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use qv_protocol::oob::{WireEndpoint, encode_qr};
    // 0012 §1: LAN discovery mistaken for trust
    #[test]
    fn qr_inspection_refuses_hostile_profiles_shapes_and_unusable_addresses() {
        let endpoint = |s: &str| WireEndpoint {
            addr: s.parse().unwrap(),
            port: 7777,
        };
        let code = encode_qr(LanProfile::V1, &[7; 16], &[endpoint("192.0.2.10")], "").unwrap();
        let info = inspect_lan_qr(&code).unwrap();
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
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
            "::ffff:169.254.1.1",
        ] {
            let q = encode_qr(LanProfile::V1, &[7; 16], &[endpoint(ip)], "").unwrap();
            assert!(inspect_lan_qr(&q).is_err(), "{ip}");
        }
        let mut q = encode_qr(LanProfile::V1, &[7; 16], &[endpoint("192.0.2.10")], "").unwrap();
        let profile = 2 + qv_protocol::oob::QR_LABEL.len();
        q[profile] = 2;
        assert_eq!(inspect_lan_qr(&q).err(), Some(LanError::Unsupported));
        assert!(inspect_lan_qr(&[0; 1025]).is_err());
        assert!(inspect_lan_qr(b"https://example.invalid/").is_err());
        // The retired address-only QR (0014).
        let old = qv_encoding::encode_array(|a| {
            a.text("qv/lan-addr-qr/v1");
            a.uint(1);
            a.array(|a| {
                a.array(|a| {
                    a.bytes(&[192, 0, 2, 10]);
                    a.uint(7777);
                    Ok(())
                })
            })
        })
        .unwrap();
        assert_eq!(inspect_lan_qr(&old).err(), Some(LanError::Protocol));
    }
}
