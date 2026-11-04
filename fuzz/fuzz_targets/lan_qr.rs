// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = qv_core::inspect_lan_qr(data);
    let _ = qv_app::qr::decode_frame(data);
    if data.len() < 2 {
        return;
    }
    if data[0] & 1 == 0 {
        let width = usize::from(data[0]) + 1;
        let height = ((data.len() - 2) / width).min(512);
        if height == 0 {
            return;
        }
        if let Ok(Some(payload)) = qv_app::qr::decode(width, height, &data[2..2 + width * height]) {
            let _ = qv_core::inspect_lan_qr(payload.expose_secret());
        }
    } else {
        // Synthetic binary payloads exercise the decoder with valid grids,
        // including arbitrary non-UTF8/hostile application payloads.
        let input = &data[1..data.len().min(1025)];
        if let Ok(symbol) = qv_app::qr::encode(input) {
            let width = (symbol.size() + 8) * 2;
            let mut image = vec![255; width * width];
            for y in 0..width {
                for x in 0..width {
                    let (mx, my) = (x / 2, y / 2);
                    if mx >= 4 && my >= 4 && symbol.black(mx - 4, my - 4) {
                        image[y * width + x] = 0;
                    }
                }
            }
            if let Ok(Some(payload)) = qv_app::qr::decode(width, width, &image) {
                assert_eq!(payload.expose_secret(), input);
                let _ = qv_core::inspect_lan_qr(payload.expose_secret());
            }
        }
    }
});
