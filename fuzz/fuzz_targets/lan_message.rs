// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile LAN frames and messages (spec 0013 §1.2–1.3; 0012 §1, "Hostile
//! SQLite/CBOR"). The first byte picks the frame phase; the rest is a byte
//! stream read as up to four frames, each opened as any wire message and read
//! with every typed accessor. Errors are expected; any panic, or a frame body
//! above its phase bound, is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qv_protocol::frame::{FramePhase, read_frame};
use qv_protocol::message::{Label, MessageReader, body_without_last};

fuzz_target!(|data: &[u8]| {
    let Some((&phase, mut stream)) = data.split_first() else {
        return;
    };
    let phase = if phase & 1 == 0 {
        FramePhase::Handshake
    } else {
        FramePhase::Session
    };
    let mut buf = Vec::new();
    for _ in 0..4 {
        if read_frame(&mut stream, phase, &mut buf).is_err() {
            return;
        }
        assert!(!buf.is_empty() && buf.len() <= phase.max());
        let _ = body_without_last(&buf);
        let Ok(mut r) = MessageReader::open_any(&buf, Label::ALL) else {
            continue;
        };
        for i in 0..r.label().arity() {
            let _ = match i % 6 {
                0 => r.uint().map(drop),
                1 => r.bytes_max(1 << 20).map(drop),
                2 => r.bytes_exact::<32>().map(drop),
                3 => r.uint_array_max(64).map(drop),
                4 => r.bytes_array_exact::<16>(4096).map(drop),
                _ => r.bool().map(drop),
            };
        }
        let _ = r.finish();
    }
});
