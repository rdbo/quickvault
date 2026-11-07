// SPDX-License-Identifier: AGPL-3.0-or-later
// Compiled local cleanup policy; no dynamic code, input logging or secret cache.
function clearControls(){
    for(const input of document.querySelectorAll("input,textarea")){
        // Consent is controlled by the Rust epoch; do not silently change it.
        // Controlled fields mirror Rust state and are re-rendered from it.
        if(input.type==="checkbox"||input.type==="radio")continue;
        if(input.getAttribute("data-qv-controlled")==="true")continue;
        input.value="";
    }
    clearCardMirror();
}
function clearRevealed(){
    for(const node of document.querySelectorAll(".phrase,.revealed"))node.textContent="";
}
// Dioxus can reuse a control's DOM node across a Rust form reset. Observe the
// Rust epoch explicitly rather than assuming a virtual-DOM key wipes its value.
let currentFormEpoch;
// HTML autofocus only applies at page load, and Rust-side focus needs eval,
// which the policy forbids: focus newly inserted autofocus controls here, and
// keep keyboard shortcuts working by focusing the app root when nothing is.
function focusInserted(records){
    for(const record of records)for(const node of record.addedNodes){
        if(!(node instanceof Element))continue;
        const target=node.matches("[autofocus]")?node:node.querySelector("[autofocus]");
        if(target&&!target.disabled){target.focus();return;}
    }
    if(document.activeElement===document.body)document.querySelector("[data-qv-epoch]")?.focus();
}
const forms=new MutationObserver(records=>{
    const epoch=document.querySelector("[data-qv-epoch]")?.getAttribute("data-qv-epoch");
    if(epoch!==currentFormEpoch){currentFormEpoch=epoch;clearControls();}
    focusInserted(records);
});
forms.observe(document,{subtree:true,childList:true,attributes:true,attributeFilter:["data-qv-epoch"]});
document.addEventListener("click",event=>{
    if(event.target instanceof Element&&event.target.closest("[data-qv-clear='true']"))clearControls();
},true);
document.addEventListener("visibilitychange",()=>{
    if(document.hidden){clearControls();clearRevealed();}
});
// A card number groups as it is typed (4-4-4-4, Amex 4-6-5), keeping the
// caret after the same digit. It runs before Rust reads the input; Rust
// ignores the spaces. Formatting only; nothing is kept here.
function groupCard(digits){
    const sizes=/^3[47]/.test(digits)?[4,6,5]:[4,4,4,4,3];
    const parts=[];let at=0;
    for(const n of sizes){if(at>=digits.length)break;parts.push(digits.slice(at,at+n));at+=n;}
    return parts.join(" ");
}
// While the card-number input has focus, the editor's card preview shows
// the same typed digits in place, the rest as dots. The copy comes from the
// input, never from Rust, and is wiped on blur, lock and hiding (0009 §1.8).
function cardMirror(el){
    return el.closest(".ie")?.querySelector(".ie-card .num.live")??null;
}
function clearCardMirror(){
    for(const node of document.querySelectorAll(".ie-card .num.live"))node.textContent="";
}
function showCardMirror(el){
    const live=cardMirror(el);
    if(!live)return;
    const digits=el.value.replace(/\D/g,"").slice(0,19);
    if(!digits){live.textContent="";return;}
    const total=Math.max(/^3[47]/.test(digits)?15:16,digits.length);
    live.textContent=groupCard(digits.padEnd(total,"\u2022"));
}
function isCardInput(el){
    return el instanceof HTMLInputElement&&el.getAttribute("data-qv-format")==="card";
}
document.addEventListener("focusin",event=>{if(isCardInput(event.target))showCardMirror(event.target);});
document.addEventListener("focusout",event=>{if(isCardInput(event.target))clearCardMirror();});
document.addEventListener("input",event=>{
    const el=event.target;
    if(!isCardInput(el))return;
    showCardMirror(el);
    const before=el.value.slice(0,el.selectionStart??el.value.length).replace(/\D/g,"").length;
    const formatted=groupCard(el.value.replace(/\D/g,"").slice(0,19));
    if(formatted===el.value)return;
    el.value=formatted;
    let caret=0,seen=0;
    while(caret<formatted.length&&seen<before){if(/\d/.test(formatted[caret]))seen++;caret++;}
    el.setSelectionRange(caret,caret);
},true);
// Pointer movement and scrolling count as activity for the inactivity lock.
// The webview bridge forwards only click, input, change, key and focus
// events, so report them as an empty input event on a hidden control, at
// most once a second. Nothing about the pointer (no position) is sent.
let lastActivity=0;
function activity(){
    const now=Date.now();
    if(now-lastActivity<1000)return;
    lastActivity=now;
    document.getElementById("qv-activity")?.dispatchEvent(new Event("input",{bubbles:true}));
}
for(const name of ["pointermove","wheel","scroll","touchstart"])document.addEventListener(name,activity,{capture:true,passive:true});
// Clipboard commands must go from Rust to the OS with bounded ownership.
for(const name of ["copy","cut"])document.addEventListener(name,event=>event.preventDefault());
