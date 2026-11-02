// SPDX-License-Identifier: AGPL-3.0-or-later
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function until(test){for(let i=0;i<400;i++){if(test())return;await pause(100)}throw new Error("synthetic deadline")}
function input(id,value){const el=document.getElementById(id);if(!el)throw new Error("synthetic field absent");el.value=value;el.dispatchEvent(new Event("input",{bubbles:true}))}
function heading(text){return document.querySelector("h2")?.textContent===text}
function headingStarts(text){return (document.querySelector("h2")?.textContent||"").startsWith(text)}
function button(text){return Array.from(document.querySelectorAll("button")).find(b=>b.textContent.trim().startsWith(text)&&!b.disabled)}
function click(text){const b=button(text);if(!b)throw new Error("synthetic button absent");b.click()}
function nav(label){const b=Array.from(document.querySelectorAll(".nav-item")).find(b=>b.querySelector(".nav-label")?.textContent===label);if(!b)throw new Error("synthetic nav absent");b.click()}
async function unlocked(){await until(()=>!!document.querySelector(".ws")&&!document.querySelector(".busy"))}
async function lockVault(){click("Lock");await until(()=>heading("Welcome back"))}
const password="K4L!c8vP2zR9qT7W6nM5";
const hostile="Synthetic <img src=x onerror=window.flowBad=1>";
let passed=false;let stage=0;
try{
 stage=1;await until(()=>document.querySelector("#password"));
 const clipboard=(document.querySelector(".protection")?.textContent||"").includes("Clipboard: true");
 document.querySelectorAll(".tabs button")[1].click();
 stage=2;await until(()=>!!document.querySelector("#vault-name"));
 input("vault-name","Synthetic vault");input("password",password);input("repeat",password);
 document.querySelector(".check input").click();await until(()=>!document.querySelector(".primary").disabled);document.querySelector(".primary").click();
 stage=3;await until(()=>heading("Your recovery phrase"));
 const phrase=document.querySelector(".phrase").textContent.trim();const words=phrase.split(/\s+/);
 if(words.length!==24)throw new Error("synthetic phrase length");
 const positions=Array.from(document.querySelectorAll(".hint")).find(el=>el.textContent.startsWith("Word positions:")).textContent.match(/\d+/g).map(Number);
 positions.forEach((position,index)=>input(`word-${index}`,words[position-1]));document.querySelector(".primary").click();
 stage=4;await unlocked();
 // New entry with a generated protected password and hostile title text.
 click("New entry");await until(()=>!!document.getElementById("ws-title"));
 input("ws-title",hostile);input("ws-field-value-0","alice@example.test");input("ws-field-value-2","https://example.invalid/login");
 click("Generate");await until(()=>Array.from(document.querySelectorAll(".hint")).some(h=>h.textContent.startsWith("A generated value")));
 if(document.getElementById("ws-replacement-1").value)throw new Error("synthetic generated value prefilled");
 click("Save");stage=5;await until(()=>headingStarts("Synthetic <img"));await unlocked();
 stage=51;if(document.querySelector(".ws-main img")||window.flowBad)throw new Error("synthetic markup executed");
 stage=52;if(!Array.from(document.querySelectorAll(".field-value")).some(v=>v.textContent==="••••••••"))throw new Error("synthetic protected value shown");
 stage=53;click("Reveal 30 s");await until(()=>(document.querySelector(".field-value.revealed")?.textContent||"").length>=8);
 stage=54;click("Hide");await until(()=>!document.querySelector(".field-value.revealed"));
 stage=6;click("Copy");
 if(clipboard)await until(()=>!!document.querySelector(".toast"));else await until(()=>!!document.querySelector(".error"));
 stage=7;click("Delete");await until(()=>(document.querySelector(".notice")?.textContent||"").startsWith("Moved to the trash"));
 nav("Trash");await until(()=>heading("Trash"));await until(()=>!!button("Restore"));click("Restore");
 await until(()=>!!Array.from(document.querySelectorAll(".muted")).find(m=>m.textContent==="The trash is empty."));
 stage=8;nav("Generator");await until(()=>heading("Password generator"));
 Array.from(document.querySelectorAll(".primary-small")).find(b=>b.textContent==="Generate").click();
 await until(()=>(document.querySelector(".phrase.revealed")?.textContent||"").length>=8);
 stage=9;await lockVault();
 if(document.querySelector(".phrase")||document.querySelector(".revealed"))throw new Error("synthetic reveal remained");
 input("password","incorrect");document.querySelector(".check input").click();await until(()=>!document.querySelector(".primary").disabled);document.querySelector(".primary").click();
 await until(()=>!!document.querySelector(".error"));
 if(document.querySelector("#password").value)throw new Error("synthetic input remained");
 input("password",password);document.querySelector(".check input").click();await until(()=>!document.querySelector(".primary").disabled);document.querySelector(".primary").click();
 stage=10;await unlocked();
 nav("Vault");await until(()=>!!document.querySelector(".row-title"));
 if(!Array.from(document.querySelectorAll(".row-title")).some(t=>t.textContent===hostile))throw new Error("synthetic entry missing after reopen");
 await lockVault();
 document.querySelectorAll(".tabs button")[2].click();await until(()=>!!document.querySelector("#phrase"));
 input("phrase",phrase);document.querySelector(".check input").click();await until(()=>!document.querySelector(".primary").disabled);document.querySelector(".primary").click();
 stage=11;await unlocked();
 await until(()=>(document.querySelector(".notice")?.textContent||"").includes("recovery phrase"));
 await lockVault();
 passed=true;
}catch{}
await until(()=>!!document.getElementById("validation-result"));input("validation-result",passed?"PASS":`FAIL:${stage}`);
