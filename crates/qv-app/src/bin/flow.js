// SPDX-License-Identifier: AGPL-3.0-or-later
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function until(test){for(let i=0;i<400;i++){if(test())return;await pause(100)}throw new Error("synthetic deadline")}
function input(id,value){const el=document.getElementById(id);if(!el)throw new Error("synthetic field absent");el.value=value;el.dispatchEvent(new Event("input",{bubbles:true}))}
const $=s=>document.querySelector(s);
function byId(id){const el=document.getElementById(id);if(!el)throw new Error("synthetic control absent");return el}
function title(){return ($(".detail h1, .page h1")?.textContent||"")}
function button(text){return Array.from(document.querySelectorAll("button")).find(b=>b.textContent.trim().startsWith(text)&&!b.disabled)}
// Clicks go only where a real pointer could: an enabled control that is not
// inert, has a box, and is the topmost element at its centre. Plain .click()
// alone reaches covered or inert controls that a person cannot.
function reachable(el){if(el.disabled||el.closest("[inert]"))return false;el.scrollIntoView({block:"center",inline:"center"});const r=el.getBoundingClientRect();if(r.width<1||r.height<1)return false;const hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);return !!hit&&(hit===el||el.contains(hit))}
async function press(find,what){let el;try{await until(()=>{el=find();return !!el&&reachable(el)})}catch{throw new Error("synthetic control unreachable: "+what)}el.click()}
async function tap(id){await press(()=>document.getElementById(id),id)}
async function click(text){await press(()=>button(text),text)}
function notice(){return Array.from(document.querySelectorAll(".notice")).map(n=>n.textContent).join("|")}
async function unlocked(){await until(()=>!!$(".shell")&&!$(".busy-toast"))}
async function lockVault(){await tap("lock");await until(()=>!!$("#password"))}
async function openItem(text){await tap("nav-all");await until(()=>Array.from(document.querySelectorAll(".row")).some(r=>r.querySelector(".row-title")?.textContent.includes(text)));
 await press(()=>Array.from(document.querySelectorAll(".row")).find(r=>r.querySelector(".row-title")?.textContent.includes(text))?.querySelector(".item-open"),"item row");await until(()=>title().includes(text))}
async function dismissErrors(){for(const t of document.querySelectorAll(".toast.bad")){const b=Array.from(t.querySelectorAll("button")).find(b=>b.textContent==="Dismiss");if(b)await press(()=>b,"Dismiss")}await until(()=>!$(".toast.bad"))}
const password="K4L!c8vP2zR9qT7W6nM5";
const hostile="Synthetic <img src=x onerror=window.flowBad=1>";
let passed=false;let stage=0;
try{
 // First run: protection review and the explicit reduced-protection acknowledgement.
 stage=1;await until(()=>!!$("#welcome-create"));
 await tap("protection-chip");await until(()=>!!$("#protection-status"));
 const clipboard=byId("protection-status").textContent.includes("Clipboard clearingAvailable");
 if($("#protection-ack"))await tap("protection-ack");else await click("Done");
 await until(()=>!$("#protection-status"));
 await tap("welcome-create");
 stage=2;await until(()=>!!$("#vault-name"));
 input("vault-name","Synthetic vault");await tap("create-next");input("password",password);input("repeat",password);await tap("create-submit");
 stage=3;await until(()=>!!$("#phrase-show"));await tap("phrase-show");
 const words=Array.from(document.querySelectorAll(".phrase .w")).map(w=>w.textContent.trim());
 if(words.length!==24)throw new Error("synthetic phrase length");
 await until(()=>!byId("phrase-written").disabled);await tap("phrase-written");await until(()=>!!$("#word-0"));
 const positions=Array.from(document.querySelectorAll(".hint")).find(el=>el.textContent.startsWith("Word positions:")).textContent.match(/\d+/g).map(Number);
 positions.forEach((position,index)=>input(`word-${index}`,words[position-1]));await tap("phrase-confirm");
 stage=4;await unlocked();
 // New entry with a generated protected password and hostile title text.
 await tap("list-new");await until(()=>!!$("#start-login"));await tap("start-login");await until(()=>!!$("#ws-title"));
 input("ws-title",hostile);input("ws-field-value-0","alice@example.test");input("ws-field-value-2","https://example.invalid/login");
 await tap("gen-1");await until(()=>($("#gen-value")?.textContent||"").length>=8&&!byId("gen-use").disabled);
 const generated=byId("gen-value").textContent;await tap("gen-use");await until(()=>!!$(".ie-saved.generated")&&!$("#gen-value"));
 if($("#ws-replacement-1")?.value||Array.from(document.querySelectorAll("input,textarea")).some(i=>i.value.includes(generated)))throw new Error("synthetic generated value prefilled");
 if(document.body.textContent.includes(generated))throw new Error("synthetic generated value shown");
 await tap("entry-save");stage=5;await until(()=>title().startsWith("Synthetic <img"));await unlocked();
 stage=51;if($(".shell img")||window.flowBad)throw new Error("synthetic markup executed");
 stage=52;if(!Array.from(document.querySelectorAll(".fld .masked")).some(v=>v.textContent==="••••••••"))throw new Error("synthetic protected value shown");
 stage=53;await press(()=>$('[aria-label="Reveal for 30 seconds"]'),"reveal");await until(()=>($(".field-value.revealed")?.textContent||"").length>=8);
 stage=54;await press(()=>$('.fld [aria-label="Hide"]'),"hide");await until(()=>!$(".field-value.revealed"));
 stage=6;await press(()=>$('.fld [aria-label="Copy"]'),"copy");
 if(clipboard)await until(()=>Array.from(document.querySelectorAll(".toast")).some(t=>t.textContent.startsWith("Copied")));else await until(()=>!!$(".error"));
 await dismissErrors();
 stage=61;await tap("entry-edit");await until(()=>!!$("#ws-title"));input("ws-title","Edited engine entry");await tap("entry-save");await until(()=>title()==="Edited engine entry");await unlocked();
 await tap("entry-history");await until(()=>!!$(".history-row"));await press(()=>$(".history-row"),"history row");await until(()=>!!$("#restore-version"));await tap("restore-version");
 await until(()=>notice().includes("Restored as a new version."));await until(()=>title().startsWith("Synthetic <img"));await unlocked();
 // Attachments through the typed fallback (fixtures never open a desktop dialog).
 stage=62;const root=byId("validation-result").getAttribute("data-fixture-root");
 await tap("entry-menu");await until(()=>!!$("#menu-attachments"));await tap("menu-attachments");await until(()=>title()==="Attachments");
 await until(()=>!!$("#ws-path"));input("ws-path",root+"/source.bin");input("ws-attach-name","engine-canary.bin");await tap("add-attachment");
 await until(()=>!!$(".notice")||!!$(".error"));
 const filesSafe=!$(".error");
 if(filesSafe){await until(()=>!!button("Save…"));input("ws-path",root+"/output.bin");await click("Save…");await until(()=>!!$("#confirm-continue"));await tap("confirm-continue");await until(()=>notice().includes("Attachment saved."))}
 await dismissErrors();
 stage=63;await tap("nav-settings");await until(()=>!!$("#settings-archives"));await tap("settings-archives");await until(()=>title()==="Archives");
 input("ws-path",root+"/exports");await tap("export-archive");await until(()=>($(".report")?.textContent||"").includes("Archive published:"));
 const archive=$(".report").textContent.match(/Archive published: ([a-f0-9]+)/)?.[1];if(!archive)throw new Error("synthetic archive id");
 input("ws-path",root+"/exports/"+archive+".qvsnap");await tap("merge-archive");await until(()=>/Archive merged|already accepted/.test($(".report")?.textContent||""));
 // LAN pairing window: code, QR, navigation locked, cancel clears secrets.
 stage=64;await tap("nav-devices");await until(()=>title()==="Devices");await tap("pair-device");await until(()=>!!$("#ws-lan-label"));
 input("ws-lan-label","engine phone");await tap("show-pairing-code");
 await until(()=>(byIdOpt("lan-code")?.textContent||"").length===31);
 if(!$("#lan-qr path")||$("#lan-qr rect")?.getAttribute("fill")!=="white")throw new Error("synthetic pairing QR absent");
 if($(".side .nav:not([disabled])")||$(".tabbar button:not([disabled])"))throw new Error("synthetic nav enabled during a window");
 await tap("lan-cancel");await until(()=>!!$("#lan-dismiss"));
 if($("#lan-code"))throw new Error("synthetic pairing code remained");
 if($("#lan-qr"))throw new Error("synthetic pairing QR remained");
 await tap("lan-dismiss");await until(()=>!$(".lan"));
 stage=65;await until(()=>!!$("#pair-device")&&!$("#pair-device").disabled);await tap("pair-device");await until(()=>!!$("#ws-lan-label"));
 input("ws-lan-label","engine core peer");await tap("show-pairing-code");
 await until(()=>(byIdOpt("lan-code")?.textContent||"").length===31);
 input("validation-result","LAN-PEER");
 stage=66;
 await until(()=>!!$("#lan-codes-match")&&$(".lan .notice")?.textContent==="Synthetic peer compared the code.");
 if(!/^\d{3} \d{3}$/.test(byIdOpt("lan-sas")?.textContent||""))throw new Error("synthetic comparison code absent");
 await tap("lan-codes-match");
 stage=67;
 await until(()=>!!$("#lan-dismiss"));
 if($(".lan .error")||!$(".lan")?.textContent.includes("The other device confirmed the pairing."))throw new Error("synthetic pairing failed");
 if($("#lan-code")||$("#lan-sas"))throw new Error("synthetic pairing secrets remained");
 stage=68;
 await until(()=>$(".lan .notice")?.textContent==="Synthetic peer opened the vault.");
 await tap("lan-dismiss");await until(()=>!$(".lan"));
 // Trash and restore.
 await openItem("Synthetic <img");
 stage=7;await tap("entry-menu");await until(()=>!!$("#menu-delete"));await tap("menu-delete");await until(()=>notice().startsWith("Moved to the trash"));
 if(!$("#toast-undo"))throw new Error("synthetic undo absent");
 await tap("nav-trash");await until(()=>title()==="Trash");await until(()=>!!button("Restore"));await click("Restore");
 await until(()=>!!Array.from(document.querySelectorAll(".muted")).find(m=>m.textContent==="The trash is empty."));
 stage=8;await tap("nav-generator");await until(()=>title()==="Generator");await tap("generate");
 await until(()=>($("#generated")?.textContent||"").length>=8);
 // The lock control and Settings agree on screen-lock detection; neither
 // advertises it when unavailable (0008 §1.4), and there is no banner.
 stage=82;await tap("nav-settings");await until(()=>!!$("#settings-autolock"));
 {const idle=!!$("#lock.idle-only"),row=byId("settings-autolock").textContent;
  if(idle!==row.includes("Idle only")||(idle&&row.includes("when the screen locks"))||Array.from(document.querySelectorAll(".banner")).some(b=>b.textContent.includes("Automatic locking")))throw new Error("synthetic lock capability misreported")}
 // A save racing a lock never leaves revealed or phrase text behind.
 stage=81;await openItem("Synthetic <img");await tap("entry-edit");await until(()=>!!$("#add-note")||!!$("#ws-notes"));if(!$("#ws-notes"))await tap("add-note");await until(()=>!!$("#ws-notes"));input("ws-notes","synthetic save-lock race");await tap("entry-save");await tap("lock");
 stage=9;await until(()=>!!$("#password"));
 if($(".phrase")||$(".revealed"))throw new Error("synthetic reveal remained");
 await until(()=>!byId("unlock-submit").disabled&&!byId("password").disabled);
 input("password","incorrect");await tap("unlock-submit");
 await until(()=>!!$(".err"));
 if($("#password").value)throw new Error("synthetic input remained");
 await until(()=>!byId("unlock-submit").disabled);input("password",password);await tap("unlock-submit");
 stage=10;await unlocked();
 await tap("nav-all");await until(()=>!!$(".row-title"));
 if(!Array.from(document.querySelectorAll(".row-title")).some(t=>t.textContent===hostile))throw new Error("synthetic entry missing after reopen");
 await lockVault();
 await tap("vault-menu");await until(()=>!!$("#menu-recover"));await tap("menu-recover");await until(()=>!!$("#phrase"));
 input("phrase",words.join(" "));await tap("recover-submit");
 stage=11;await unlocked();
 await until(()=>notice().includes("recovery phrase"));
 await lockVault();
 passed=true;
}catch{}
function byIdOpt(id){return document.getElementById(id)}
await until(()=>!!document.getElementById("validation-result"));input("validation-result",passed?"PASS":`FAIL:${stage}`);
