// SPDX-License-Identifier: AGPL-3.0-or-later
// Webview boundary checks for the Tauri app (plan 0071; 0012 §1 "Webview
// exposure"), run in the read-only preview with synthetic input only.
(async () => {
  if (window.__qvBoundary) return; window.__qvBoundary = true;
  const wait = ms => new Promise(r => setTimeout(r, ms));
  const bytes = s => new TextEncoder().encode(s);
  const ask = async body => {
    const r = await window.__TAURI_INTERNALS__.invoke("qv", bytes(body));
    return JSON.parse(new TextDecoder().decode(new Uint8Array(r)));
  };
  const report = v => ask(JSON.stringify({ generation: 0, request: { act: { act: { fixture: "BOUNDARY:" + v } } } }));
  for (let i = 0; i < 150 && !document.querySelector(".qv"); i++) await wait(100);
  const checks = [];
  const copy = new Event("copy", { cancelable: true }); document.dispatchEvent(copy); checks.push(copy.defaultPrevented);
  try { eval("window.evalBad=true") } catch {}
  checks.push(!window.evalBad);
  try { new Function("window.fnBad=true")() } catch {}
  checks.push(!window.fnBad);
  const script = document.createElement("script"); script.textContent = "window.inlineBad=true"; document.body.append(script);
  const remote = document.createElement("script"); remote.src = "https://example.invalid/x.js"; document.body.append(remote);
  await wait(200); checks.push(!window.inlineBad);
  try { await fetch("https://example.invalid/"); checks.push(false) } catch { checks.push(true) }
  try { await fetch("http://127.0.0.1:9/"); checks.push(false) } catch { checks.push(true) }
  for (const [cmd, args] of [["plugin:fs|read_file", { path: "/etc/passwd" }], ["plugin:window|close", {}], ["plugin:event|emit", { event: "x", payload: "y" }], ["plugin:shell|open", { path: "https://example.invalid/" }], ["format_disk", {}]]) {
    try { await window.__TAURI_INTERNALS__.invoke(cmd, args); checks.push(false) } catch { checks.push(true) }
  }
  // The one command refuses oversized, malformed and unknown requests.
  checks.push((await ask(" ".repeat(65537))).error === "too_large");
  checks.push((await ask('{"generation":0,"request":"format_disk"}')).error === "malformed");
  checks.push((await ask('{"generation":0,"request":{"act":{"act":{"go":{"entry":"0123456789abcdef0123456789abcdef"}}}}}')).error === "not_found");
  const media = await fetch("qvmedia://localhost/preview/0123456789abcdef0123456789abcdef").catch(() => null);
  checks.push(!media || media.status === 404);
  const frame = document.createElement("iframe"); frame.src = "https://example.invalid/"; document.body.append(frame);
  await wait(200); checks.push(!window.frameBad);
  checks.push(window.open("https://example.invalid/") === null);
  const old = location.href;
  setTimeout(async () => {
    checks.push(location.href === old);
    const failed = checks.map((ok, i) => ok ? null : i).filter(i => i !== null);
    await report(failed.length ? "FAIL:" + failed.join(",") : "PASS");
  }, 400);
  location.href = "https://example.invalid/";
})();
