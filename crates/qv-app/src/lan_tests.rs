// SPDX-License-Identifier: AGPL-3.0-or-later

//! Headless LAN tests through two real controllers and cores on loopback
//! (enabled for tests only; plans 0038 step 9, 0042 step 8). The renderer's calls are
//! made directly: answers, typed secrets, cancel and lock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::controller::{Action, AppError, InputField, Mode, Phase};
use crate::lan::{LanView, Question, TEST_LOOPBACK};
use crate::views;
use crate::workspace::{Screen, WsAction, WsField};
use crate::workspace_tests::{Env, KDF, PASSWORD};

fn kdf() -> std::sync::MutexGuard<'static, ()> {
    let guard = KDF.lock().unwrap_or_else(|p| p.into_inner());
    TEST_LOOPBACK.store(true, Ordering::SeqCst);
    guard
}

/// Polls `env`'s LAN view until `f` accepts it.
fn until<T>(env: &Env, what: &str, f: impl Fn(&LanView) -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(v) = env.c.lan_view(env.epoch())
            && let Some(t) = f(&v)
        {
            return t;
        }
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn titles(env: &Env) -> Vec<String> {
    env.read(|s| views::browse(s, None))
        .entries
        .iter()
        .map(|e| e.title.as_str().to_owned())
        .collect()
}

/// A's window shows its code; returns the manual code and first endpoint.
fn offer(a: &Env) -> (String, String) {
    a.c.navigate(a.epoch(), Screen::Devices);
    a.c.act(a.epoch(), WsAction::LanOffer);
    until(a, "the code", |v| {
        let code = v.code.as_ref()?;
        assert!(v.qr.is_some(), "the window displays the binary QR");
        Some((
            String::from_utf8(code.expose_secret().to_vec()).unwrap(),
            v.endpoints.first()?.clone(),
        ))
    })
}

/// B joins A as a new device through the locked screen's Join mode; returns
/// B unlocked. The joiner's first password is wrong when `wrong` is set; a
/// scanned code with endpoints starts the join by itself.
fn join_new(a: &Env, wrong: bool, scanned: bool) -> Env {
    a.c.navigate(a.epoch(), Screen::Devices);
    a.c.act(a.epoch(), WsAction::LanOffer);
    let (code, endpoint) = until(a, "the code", |v| {
        let code = v.code.as_ref()?;
        assert!(v.qr.is_some(), "the window displays the binary QR");
        Some((
            String::from_utf8(code.expose_secret().to_vec()).unwrap(),
            v.endpoints.first()?.clone(),
        ))
    });
    assert!(v_seconds(a) > 0);
    let b = Env::new();
    if scanned {
        b.c.select_mode(b.epoch(), Mode::Join);
        let payload = scanned_payload(a);
        let addressed =
            b.c.accept_qr(
                b.epoch(),
                crate::qr::QrTarget::NewDevice,
                payload.expose_secret(),
            )
            .unwrap();
        assert!(addressed, "the window's QR names its endpoints");
        // What the scan thread does once it releases the camera (after the
        // protection status was acknowledged).
        b.c.acknowledge_protection().unwrap();
        b.c.start_scanned(b.epoch(), crate::qr::QrTarget::NewDevice);
    } else {
        b.fill(InputField::LanCode, &code);
        b.fill(InputField::LanEndpoint, &endpoint);
        b.c.submit(b.epoch(), Action::JoinDevice, true).unwrap();
    }
    // A compares the code; B confirms the vault and gives its password.
    let sas = until(a, "the approval question", |v| match &v.question {
        Some(Question::Approve { sas, vault, .. }) => {
            assert_eq!(vault, "My vault");
            Some(sas.clone())
        }
        _ => None,
    });
    a.c.lan_answer(a.epoch(), true);
    let shown = until(&b, "the vault question", |v| match &v.question {
        Some(Question::JoinVault { vault, sas }) => {
            assert_eq!(vault, "My vault");
            Some(sas.clone())
        }
        _ => None,
    });
    assert_eq!(shown, sas, "both screens show the same comparison code");
    b.c.lan_answer(b.epoch(), true);
    let give = |password: &str, retry: bool| {
        until(&b, "the password question", |v| match v.question {
            Some(Question::Password { retry: r }) if r == retry => Some(()),
            _ => None,
        });
        let mut typed = password.to_owned();
        b.c.lan_secret(b.epoch(), &mut typed);
        assert!(typed.is_empty(), "the framework string is cleared");
        b.c.lan_answer(b.epoch(), true);
    };
    if wrong {
        give("not the password", false);
        give(PASSWORD, true);
    } else {
        give(PASSWORD, false);
    }
    b.wait();
    assert_eq!(b.c.snapshot().phase, Phase::Unlocked);
    a.wait();
    let done = until(a, "the join outcome", |v| v.done.clone());
    assert!(done.error.is_none(), "{done:?}");
    assert_eq!(done.lines[0], "A new device joined this vault.");
    assert!(
        a.c.lan_view(a.epoch()).unwrap().qr.is_none(),
        "finished QR cleared"
    );
    a.c.lan_dismiss(a.epoch());
    assert!(a.c.lan_view(a.epoch()).is_none());
    b
}

fn v_seconds(env: &Env) -> u64 {
    env.c.snapshot().lan_seconds
}

#[test]
fn lan_app_new_device_join_then_sync_with_a_typed_code() {
    let _k = kdf();
    let a = Env::unlocked();
    a.add_entry("Mail", "s3cret-canary-value");
    let b = join_new(&a, true, false);
    assert_eq!(titles(&b), ["Mail"]);
    // A post-commit failure must retain acceptance lines and surface the error.
    for error in [
        qv_core::CoreError::Store(qv_core::StoreError::Io),
        qv_core::CoreError::Lan(qv_core::LanError::Timeout),
    ] {
        let done = crate::lan::round_done(
            &qv_core::SyncReport {
                local: qv_core::LocalAcceptance::Committed,
                conflicts: 2,
                peer_confirmed: true,
                completion_error: Some(error),
            },
            vec!["Synced.".to_owned()],
        );
        assert_eq!(done.error, Some(AppError::from(error)));
        assert_eq!(done.lines[0], "Synced.");
        assert!(done.lines[1].contains("accepted"));
        assert_eq!(done.lines[2], "Unresolved conflicts: 2");
    }

    // A edits and shows a new code; B types it and syncs.
    a.c.navigate(a.epoch(), Screen::Browse(None));
    a.add_entry("Bank", "another-canary");
    let (code, endpoint) = offer(&a);
    b.c.navigate(b.epoch(), Screen::Devices);
    b.put(WsField::LanCode, &code);
    b.put(WsField::LanEndpoint, &endpoint);
    b.act(WsAction::LanSync);
    let done = until(&b, "the sync outcome", |v| v.done.clone());
    assert!(done.error.is_none(), "{done:?}");
    assert_eq!(
        done.lines[0],
        "This device accepted the other device's changes."
    );
    assert!(done.lines[2].contains("confirmed"));
    a.wait();
    let a_done = until(&a, "the window outcome", |v| v.done.clone());
    assert_eq!(
        a_done.lines[0],
        "Synced with a device that holds this vault."
    );
    assert_eq!(a_done.lines[1], "Nothing new from the other device.");
    let mut t = titles(&b);
    t.sort();
    assert_eq!(t, ["Bank", "Mail"]);
    // The code and address were consumed by the action.
    let s = b.c.state();
    let ws = s.workspace.as_ref().unwrap();
    assert!(ws.input(WsField::LanCode).is_empty());
    assert!(ws.input(WsField::LanEndpoint).is_empty());
}

#[test]
fn lan_app_cancel_and_lock_end_windows_and_prompts() {
    let _k = kdf();
    let a = Env::unlocked();
    a.c.navigate(a.epoch(), Screen::Devices);
    // Cancel ends a waiting window.
    a.c.act(a.epoch(), WsAction::LanOffer);
    until(&a, "the code", |v| v.code.as_ref().map(|_| ()));
    // A waiting window counts as activity for the idle lock.
    {
        let mut s = a.c.state();
        s.active = Instant::now()
            .checked_sub(Duration::from_secs(120))
            .unwrap();
    }
    assert_eq!(a.c.snapshot().phase, Phase::Unlocked);
    assert!(a.c.lan_view(a.epoch()).unwrap().code.is_some());
    let started = Instant::now();
    a.c.lan_cancel(a.epoch());
    a.wait();
    assert!(started.elapsed() < Duration::from_secs(3));
    let done = until(&a, "the cancelled outcome", |v| v.done.clone());
    assert!(matches!(done.error, Some(AppError::Core(_))), "{done:?}");
    assert!(
        a.c.lan_view(a.epoch()).unwrap().code.is_none(),
        "the code is gone"
    );
    a.c.lan_dismiss(a.epoch());
    // A lock ends a waiting window and drops its state.
    a.c.act(a.epoch(), WsAction::LanOffer);
    until(&a, "the window", |v| {
        (!v.endpoints.is_empty()).then_some(())
    });
    a.c.lock();
    let end = Instant::now() + Duration::from_secs(5);
    while a.c.snapshot().busy && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!a.c.snapshot().busy);
    assert_eq!(a.c.snapshot().phase, Phase::Locked);
    assert!(a.c.lan_view(a.epoch()).is_none());
    // Input bounds: a missing code or address, or a host name, is refused
    // before any work.
    a.unlock(PASSWORD);
    a.c.navigate(a.epoch(), Screen::Devices);
    a.act(WsAction::LanSync);
    assert_eq!(a.error(), Some(AppError::InvalidInput));
    a.put(WsField::LanCode, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-A");
    a.act(WsAction::LanSync);
    assert_eq!(a.error(), Some(AppError::InvalidInput));
    a.put(WsField::LanCode, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-A");
    a.put(WsField::LanEndpoint, "localhost:80");
    a.act(WsAction::LanSync);
    assert_eq!(a.error(), Some(AppError::InvalidInput));
    assert!(a.c.lan_view(a.epoch()).is_none());
}

#[test]
fn lan_app_join_refused_by_the_approver_creates_nothing() {
    let _k = kdf();
    let a = Env::unlocked();
    let (code, endpoint) = offer(&a);
    let b = Env::new();
    b.fill(InputField::LanCode, &code);
    b.fill(InputField::LanEndpoint, &endpoint);
    b.c.submit(b.epoch(), Action::JoinDevice, true).unwrap();
    until(&a, "the approval question", |v| {
        matches!(v.question, Some(Question::Approve { .. })).then_some(())
    });
    a.c.lan_answer(a.epoch(), false);
    b.wait();
    assert_eq!(b.c.snapshot().phase, Phase::Locked);
    assert!(b.c.snapshot().error.is_some());
    assert!(!b.dir.join("vaults/main.qvault").exists());
    a.wait();
}

/// Synthetic camera luminance from the actual window's protected binary symbol.
fn scanned_payload(env: &Env) -> qv_core::SecretBytes {
    until(env, "QR symbol", |v| {
        let symbol = v.qr.as_ref()?;
        let width = (symbol.size() + 8) * 3;
        let mut pixels = qv_core::SecretBytes::zeroed(width * width);
        pixels.expose_secret_mut().fill(255);
        for y in 0..width {
            for x in 0..width {
                let (mx, my) = (x / 3, y / 3);
                if mx >= 4 && my >= 4 && symbol.black(mx - 4, my - 4) {
                    pixels.expose_secret_mut()[y * width + x] = 0;
                }
            }
        }
        Some(
            crate::qr::decode(width, width, pixels.expose_secret())
                .unwrap()
                .unwrap(),
        )
    })
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_app_scanned_codes_start_the_join_and_the_sync() {
    let _k = kdf();
    // Unlike loopback-only protocol tests, QR inspection enforces production
    // endpoint policy. This host's LAN address is also required by CLI tests.
    TEST_LOOPBACK.store(false, Ordering::SeqCst);
    let a = Env::unlocked();
    a.add_entry("QR initial", "synthetic-password");
    let b = join_new(&a, false, true);
    assert_eq!(titles(&b), ["QR initial"]);
    b.add_entry("QR received", "synthetic-password-2");
    // A shows a new code; B scans it on Devices and the sync starts itself.
    a.c.navigate(a.epoch(), Screen::Devices);
    a.c.act(a.epoch(), WsAction::LanOffer);
    let payload = scanned_payload(&a);
    b.c.navigate(b.epoch(), Screen::Devices);
    let addressed =
        b.c.accept_qr(
            b.epoch(),
            crate::qr::QrTarget::Sync,
            payload.expose_secret(),
        )
        .unwrap();
    assert!(addressed);
    b.c.start_scanned(b.epoch(), crate::qr::QrTarget::Sync);
    b.wait();
    a.wait();
    assert!(
        until(&b, "QR sync result", |v| v.done.clone())
            .error
            .is_none()
    );
    assert!(titles(&a).iter().any(|title| title == "QR received"));
    // Nothing of the scanned code is left for the next action.
    let s = b.c.state();
    let ws = s.workspace.as_ref().unwrap();
    assert!(ws.input(WsField::LanCode).is_empty());
    assert!(!ws.lan_scanned);
}
