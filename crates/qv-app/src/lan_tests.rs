// SPDX-License-Identifier: AGPL-3.0-or-later

//! Headless LAN tests through two real controllers and cores on loopback
//! (enabled for tests only; plan 0038 step 9). The renderer's calls are
//! made directly: answers, typed secrets, cancel and lock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::controller::{Action, AppError, InputField, Mode, Phase};
use crate::lan::{LanView, Question, TEST_LOOPBACK};
use crate::views;
use crate::workspace::{ConfirmKind, Screen, WsAction, WsField};
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

/// A pairs B as a new device through the locked screen's Join mode; returns
/// B unlocked. The joiner's first password is wrong when `wrong` is set.
fn join_new(a: &Env, wrong: bool, scanned: bool) -> Env {
    a.c.navigate(a.epoch(), Screen::Devices);
    a.put(WsField::LanLabel, "phone");
    a.c.act(a.epoch(), WsAction::LanPair);
    let (code, endpoint) = until(a, "the pairing code", |v| {
        let code = v.code.as_ref()?;
        assert!(v.qr.is_some(), "pairing window displays the binary QR");
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
        b.c.accept_qr(
            b.epoch(),
            crate::qr::QrTarget::NewDevice,
            payload.expose_secret(),
        )
        .unwrap();
    } else {
        b.fill(InputField::LanCode, &code);
        b.fill(InputField::LanEndpoint, &endpoint);
    }
    b.fill(InputField::LanLabel, "laptop");
    b.c.submit(b.epoch(), Action::JoinDevice, true).unwrap();
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
    let done = until(a, "the pairing outcome", |v| v.done.clone());
    assert!(done.error.is_none(), "{done:?}");
    assert!(done.lines[0].starts_with("Paired."));
    assert!(done.lines[1].contains("confirmed"));
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
fn lan_app_new_device_join_then_sync_and_remove() {
    let _k = kdf();
    let a = Env::unlocked();
    a.add_entry("Mail", "s3cret-canary-value");
    let b = join_new(&a, true, false);
    assert_eq!(titles(&b), ["Mail"]);
    let links = b.read(views::lan_links);
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].label, "laptop");
    // A post-commit failure must retain acceptance lines and surface the error.
    let link = b.read(|s| Ok(s.lan_links()?.remove(0).handle));
    for error in [
        qv_core::CoreError::Store(qv_core::StoreError::Io),
        qv_core::CoreError::Lan(qv_core::LanError::Timeout),
    ] {
        let done = crate::lan::round_done(
            &qv_core::SyncReport {
                link: link.clone(),
                local: qv_core::LocalAcceptance::Committed,
                conflicts: 2,
                peer_confirmed: true,
                completion_error: Some(error),
            },
            vec!["Paired.".to_owned()],
        );
        assert_eq!(done.error, Some(AppError::from(error)));
        assert_eq!(done.lines[0], "Paired.");
        assert!(done.lines[1].contains("accepted"));
        assert_eq!(done.lines[2], "Unresolved conflicts: 2");
    }

    // A edits, opens a receive window; B syncs with its link.
    a.c.navigate(a.epoch(), Screen::Browse(None));
    a.add_entry("Bank", "another-canary");
    a.c.navigate(a.epoch(), Screen::Devices);
    a.c.act(a.epoch(), WsAction::LanReceive);
    let endpoint = until(&a, "the receive endpoints", |v| {
        v.endpoints.first().cloned()
    });
    b.c.navigate(b.epoch(), Screen::Devices);
    b.put(WsField::LanEndpoint, &endpoint);
    b.act(WsAction::LanSync(links[0].id.clone()));
    let done = until(&b, "the sync outcome", |v| v.done.clone());
    assert!(done.error.is_none(), "{done:?}");
    assert_eq!(
        done.lines[0],
        "This device accepted the other device's changes."
    );
    assert!(done.lines[2].contains("confirmed"));
    a.wait();
    let a_done = until(&a, "the receive outcome", |v| v.done.clone());
    assert_eq!(a_done.lines[0], "Nothing new from the other device.");
    let mut t = titles(&b);
    t.sort();
    assert_eq!(t, ["Bank", "Mail"]);
    // Removing the link asks first.
    b.c.lan_dismiss(b.epoch());
    b.act(WsAction::LanRemove(links[0].id.clone()));
    assert_eq!(b.c.pending(b.epoch()), Some(ConfirmKind::RemoveLink));
    b.act(WsAction::Answer(true));
    assert!(b.read(views::lan_links).is_empty());
    assert!(b.notice().unwrap().contains("not notified"));
}

#[test]
fn lan_app_cancel_and_lock_end_windows_and_prompts() {
    let _k = kdf();
    let a = Env::unlocked();
    a.c.navigate(a.epoch(), Screen::Devices);
    // Cancel ends a waiting pairing window.
    a.put(WsField::LanLabel, "phone");
    a.c.act(a.epoch(), WsAction::LanPair);
    until(&a, "the pairing code", |v| v.code.as_ref().map(|_| ()));
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
    // A lock ends a waiting receive window and drops its state.
    a.c.act(a.epoch(), WsAction::LanReceive);
    until(&a, "the receive window", |v| {
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
    // Input bounds: a missing label or endpoint is refused before any work.
    a.unlock(PASSWORD);
    a.c.navigate(a.epoch(), Screen::Devices);
    a.act(WsAction::LanPair);
    assert_eq!(a.error(), Some(AppError::InvalidInput));
    a.put(WsField::LanEndpoint, "localhost:80");
    a.act(WsAction::LanSync("00".repeat(16)));
    assert_eq!(a.error(), Some(AppError::InvalidInput));
}

#[test]
fn lan_app_join_refused_by_the_approver_creates_nothing() {
    let _k = kdf();
    let a = Env::unlocked();
    a.c.navigate(a.epoch(), Screen::Devices);
    a.put(WsField::LanLabel, "phone");
    a.c.act(a.epoch(), WsAction::LanPair);
    let (code, endpoint) = until(&a, "the pairing code", |v| {
        Some((
            String::from_utf8(v.code.as_ref()?.expose_secret().to_vec()).unwrap(),
            v.endpoints.first()?.clone(),
        ))
    });
    let b = Env::new();
    b.fill(InputField::LanCode, &code);
    b.fill(InputField::LanEndpoint, &endpoint);
    b.fill(InputField::LanLabel, "laptop");
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
    assert!(a.read(views::lan_links).is_empty());
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
fn lan_app_qr_new_device_link_and_address_sync_use_binary_payloads() {
    let _k = kdf();
    // Unlike loopback-only protocol tests, QR inspection enforces production
    // endpoint policy. This host's LAN address is also required by CLI tests.
    TEST_LOOPBACK.store(false, Ordering::SeqCst);
    let a = Env::unlocked();
    a.add_entry("QR initial", "synthetic-password");
    let b = join_new(&a, false, true);
    assert_eq!(titles(&b), ["QR initial"]);
    b.add_entry("QR received", "synthetic-password-2");
    a.c.act(a.epoch(), WsAction::LanReceive);
    let payload = scanned_payload(&a);
    b.c.navigate(b.epoch(), Screen::Devices);
    b.c.accept_qr(
        b.epoch(),
        crate::qr::QrTarget::Sync,
        payload.expose_secret(),
    )
    .unwrap();
    let link = b.read(views::lan_links).remove(0).id;
    b.c.act(b.epoch(), WsAction::LanSync(link));
    b.wait();
    a.wait();
    assert!(
        until(&b, "QR sync result", |v| v.done.clone())
            .error
            .is_none()
    );
    assert!(titles(&a).iter().any(|title| title == "QR received"));
    assert!(
        b.c.state()
            .workspace
            .as_ref()
            .unwrap()
            .lan_endpoints
            .is_empty()
    );
    a.c.lan_dismiss(a.epoch());
    b.c.lan_dismiss(b.epoch());
    a.put(WsField::LanLabel, "second QR link");
    a.c.act(a.epoch(), WsAction::LanPair);
    let payload = scanned_payload(&a);
    b.c.accept_qr(
        b.epoch(),
        crate::qr::QrTarget::Link,
        payload.expose_secret(),
    )
    .unwrap();
    b.put(WsField::LanLabel, "QR approver");
    b.c.act(b.epoch(), WsAction::LanLink);
    let sas = until(&a, "QR approval", |v| match &v.question {
        Some(Question::Approve { sas, .. }) => Some(sas.clone()),
        _ => None,
    });
    let peer = until(&b, "QR comparison", |v| match &v.question {
        Some(Question::Matches { sas }) => Some(sas.clone()),
        _ => None,
    });
    assert_eq!(sas, peer);
    b.c.lan_answer(b.epoch(), true);
    a.c.lan_answer(a.epoch(), true);
    b.wait();
    a.wait();
    assert!(
        until(&b, "QR link result", |v| v.done.clone())
            .error
            .is_none()
    );
    assert_eq!(b.read(views::lan_links).len(), 2);
    assert!(
        b.c.state()
            .workspace
            .as_ref()
            .unwrap()
            .input(WsField::LanCode)
            .is_empty()
    );
}
