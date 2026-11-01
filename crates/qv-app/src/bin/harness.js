// SPDX-License-Identifier: AGPL-3.0-or-later
const wait = ms => new Promise(resolve=>setTimeout(resolve,ms));
for(let i=0;i<150&&!document.querySelector("#report");i++)await wait(100);
const checks=[];
await import("./cleanup.js");
const copy=new Event("copy",{cancelable:true});document.dispatchEvent(copy);checks.push(copy.defaultPrevented);
try{eval("window.evalBad=true")}catch{}
checks.push(!window.evalBad);
const script=document.createElement("script");script.textContent="window.inlineBad=true";document.body.append(script);
await wait(100);checks.push(!window.inlineBad);
checks.push(document.querySelector("#escaped").textContent.includes("<img"));
checks.push(!document.querySelector("#escaped img")&&!window.escapedBad);
checks.push((await fetch("__file_dialog")).status===404);
checks.push((await fetch("/etc/passwd")).status===404);
checks.push((await fetch("__unknown")).status===404);
try{await fetch("https://example.invalid/");checks.push(false)}catch{checks.push(true)}
checks.push((await fetch("__events",{method:"POST",headers:{"dioxus-data":btoa('{"name":"input","name":"click","data":{},"bubbles":true,"element":0}')}})).status===400);
const frame=document.createElement("iframe");frame.src="frame.html";document.body.append(frame);
await wait(200);checks.push(!window.frameBad);
checks.push(window.open("https://example.invalid/")===null);
window.ipc.postMessage('{"method":"browser_open","params":{"href":"https://example.invalid/"}}');
window.ipc.postMessage('{"method":"query","params":{}}');
window.ipc.postMessage(' '.repeat(65537));
const old=location.href;location.href="https://example.invalid/";
await wait(200);checks.push(location.href===old);
const report=document.querySelector("#report");report.value=checks.every(Boolean)?"PASS":"FAIL";report.dispatchEvent(new Event("input",{bubbles:true}));
