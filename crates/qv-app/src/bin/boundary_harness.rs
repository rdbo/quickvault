// SPDX-License-Identifier: AGPL-3.0-or-later
//! Actual WebKit boundary evidence with synthetic input only.
use dioxus::prelude::*;
fn app() -> Element {
    rsx! {
        div { id:"escaped", "<img src=x onerror=window.escapedBad=true>" }
        input { id:"report", oninput:move |event:FormEvent| -> () {
            let value=event.value();
            if value=="PASS" {println!("boundary harness passed");std::process::exit(0)}
            eprintln!("boundary harness failed: synthetic checks");std::process::exit(1)
        }}
    }
}
fn main() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(30));
        eprintln!("boundary harness timeout");
        std::process::exit(2)
    });
    let mut policy = dioxus_desktop::hardened::HardenedWebview::default();
    policy
        .assets
        .insert("/app.css", ("text/css", b"body{font:16px sans-serif}"));
    policy
        .assets
        .insert("/app.js", ("text/javascript", include_bytes!("harness.js")));
    policy.assets.insert(
        "/frame.html",
        ("text/html", br#"<script src="frame.js"></script>"#),
    );
    policy.assets.insert(
        "/frame.js",
        ("text/javascript", b"window.parent.frameBad=true"),
    );
    policy.assets.insert(
        "/cleanup.js",
        ("text/javascript", include_bytes!("../../assets/app.js")),
    );
    dioxus_desktop::launch::launch_virtual_dom(
        VirtualDom::new(app),
        dioxus_desktop::Config::new().with_hardened_webview(policy),
    );
}
