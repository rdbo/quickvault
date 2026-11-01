// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real engine ingress/CSP tests use only synthetic values and a private X server.
#![cfg(feature = "validation")]
// Test fixture setup failures must fail the test; all values are synthetic.
#![allow(clippy::expect_used)]
use std::{
    io::BufRead,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
// 0012 §1: Webview exposure
#[test]
fn webview_exposure_real_engine_rejects_active_content_and_privileged_routes() {
    run(env!("CARGO_BIN_EXE_qv-boundary-harness"));
}
// 0012 §1: Ambiguous trust boundary
#[test]
fn real_shared_screens_create_confirm_lock_unlock_and_recover() {
    run(env!("CARGO_BIN_EXE_qv-flow-harness"));
}
// 0012 §1: Ambiguous trust boundary
#[cfg(target_os = "linux")]
#[test]
fn real_linux_services_run_the_shared_local_flows() {
    run_with_platform(env!("CARGO_BIN_EXE_qv-flow-harness"), true);
}
fn run(binary: &str) {
    run_with_platform(binary, false);
}
fn run_with_platform(binary: &str, real_linux: bool) {
    let path = std::env::var_os("QV_TEST_XVFB").unwrap_or_else(|| "Xvfb".into());
    let mut server = Child(
        Command::new(path)
            .args([
                "-displayfd",
                "1",
                "-screen",
                "0",
                "1280x1000x24",
                "-nolisten",
                "tcp",
                "-ac",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("private Xvfb required"),
    );
    let stdout = server.0.stdout.take().expect("fixture stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut display = String::new();
        let result = std::io::BufReader::new(stdout).read_line(&mut display);
        let _ = tx.send((result, display));
    });
    let (result, display) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Xvfb startup deadline");
    result.expect("Xvfb display");
    let mut harness = Child(
        Command::new(binary)
            .env("DISPLAY", format!(":{}", display.trim()))
            .env("WEBKIT_DISABLE_COMPOSITING_MODE", "1")
            .env(
                "QV_TEST_REAL_LINUX_PLATFORM",
                if real_linux { "1" } else { "0" },
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("synthetic engine harness"),
    );
    let end = Instant::now() + Duration::from_secs(65);
    loop {
        if let Some(status) = harness.0.try_wait().expect("harness wait") {
            assert!(status.success(), "synthetic engine checks failed");
            break;
        }
        assert!(Instant::now() < end, "engine deadline");
        std::thread::sleep(Duration::from_millis(50));
    }
}
