// SPDX-License-Identifier: AGPL-3.0-or-later

//! The initiator of a sync round (0013 §5, §7; plan 0038).
//!
//! The candidates are the caller's endpoints, deduplicated, at most 16, and
//! filtered by the [`EndpointPolicy`]. The initiator tries them one at a
//! time with one link (§5.1), a fresh `nonce_I` and a fresh X-Wing pair for
//! each:
//! - a candidate that does not answer with a valid `K_r` tag is skipped;
//! - the first valid accept authenticates the responder, and later
//!   failures abort the round.
//!
//! After the accept, the initiator decapsulates, erases `dk_I` and `ss`,
//! sends `Confirm(th)` and runs one exchange.

use std::net::SocketAddr;

use qv_crypto::lan::{LinkKey, RecordOpener, RecordSealer};
use qv_crypto::{XWingDecapsKey, random_array};
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::Confirm;

use super::endpoint::EndpointPolicy;
use super::exchange::{ExchangeVault, Role, RoundReport, exchange};
use super::session::{check_sync_accept, session_keys, session_th, sync_attempt};
use super::transport::{Channel, Conn, connect, guarded};
use super::{LanError, LanTimeouts, candidates};

/// One round as the initiator with `link` (0013 §5, §7). [`LanError::NoPeer`]
/// when no candidate authenticated: an unreachable device, a closed window,
/// or a removed link or rotated vault on the other side (§12.1).
pub fn sync(
    link: &LinkKey,
    endpoints: &[SocketAddr],
    policy: EndpointPolicy,
    vault: &dyn ExchangeVault,
    timeouts: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<RoundReport, LanError> {
    timeouts.validate()?;
    let auth = link.session_auth().map_err(|_| LanError::Protocol)?;
    for endpoint in candidates(endpoints, policy) {
        if cancelled() {
            return Err(LanError::Cancelled);
        }
        let Some(stream) = connect(endpoint, timeouts.connect, cancelled)? else {
            continue;
        };
        let nonce_i = random_array::<32>().map_err(|_| LanError::Io)?;
        let (dk, ek) = XWingDecapsKey::generate().map_err(|_| LanError::Io)?;
        let attempt = sync_attempt(&auth, &nonce_i, dk, &ek)?;
        let mut conn = Conn::new(stream, cancelled)?;
        conn.within(timeouts.message, None);
        let mut buf = Vec::new();
        let answered = conn
            .send_frame(FramePhase::Handshake, &attempt.hello)
            .and_then(|()| conn.recv_frame(FramePhase::Handshake, &mut buf));
        match answered {
            Err(LanError::Cancelled) => return Err(LanError::Cancelled),
            Err(_) => {
                conn.close();
                continue;
            }
            Ok(()) => {}
        }
        let Ok((ct, accept_hash)) = check_sync_accept(&auth, &attempt.hello_hash, &buf) else {
            conn.close();
            continue;
        };
        // Authenticated: from here every failure aborts.
        let keys = (|| {
            let ss = attempt
                .dk
                .decapsulate(&ct)
                .map_err(|_| LanError::Integrity)?;
            let th = session_th(&attempt.hello_hash, &accept_hash)?;
            let (i2r, r2i) = session_keys(&ss, link, &th)?;
            Ok::<_, LanError>((th, i2r, r2i))
        })();
        drop(attempt);
        let (th, i2r, r2i) = match keys {
            Ok(k) => k,
            Err(e) => {
                conn.close();
                return Err(e);
            }
        };
        let mut ch = Channel::new(conn, RecordSealer::new(i2r), RecordOpener::new(r2i));
        let round = guarded(&mut ch, |ch| {
            ch.send(
                &Confirm::encode(&th).map_err(|_| LanError::Protocol)?,
                timeouts.message,
            )?;
            exchange(ch, Role::Initiator, vault, timeouts)
        });
        ch.conn.close();
        return round;
    }
    Err(LanError::NoPeer)
}
