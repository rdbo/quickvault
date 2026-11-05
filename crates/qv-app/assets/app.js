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
    if(event.target instanceof Element&&event.target.closest("[data-qv-clear]"))clearControls();
},true);
document.addEventListener("visibilitychange",()=>{
    if(document.hidden){clearControls();clearRevealed();}
});
// Clipboard commands must go from Rust to the OS with bounded ownership.
for(const name of ["copy","cut"])document.addEventListener(name,event=>event.preventDefault());
