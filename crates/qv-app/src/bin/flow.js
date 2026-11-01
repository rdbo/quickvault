// SPDX-License-Identifier: AGPL-3.0-or-later
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function until(test){for(let i=0;i<400;i++){if(test())return;await pause(100)}throw new Error("synthetic deadline")}
function input(id,value){const el=document.getElementById(id);if(!el)throw new Error("synthetic field absent");el.value=value;el.dispatchEvent(new Event("input",{bubbles:true}))}
function heading(text){return document.querySelector("h2")?.textContent===text}
const password="K4L!c8vP2zR9qT7W6nM5";
let passed=false;let stage=0;
try{
 stage=1;await until(()=>document.querySelector("#password"));
 document.querySelectorAll(".tabs button")[1].click();
 stage=2;await until(()=>!!document.querySelector("#vault-name"));
 input("vault-name","Synthetic vault");input("password",password);input("repeat",password);
 document.querySelector(".check input").click();await until(()=>!document.querySelector(".primary").disabled);document.querySelector(".primary").click();
 stage=3;await until(()=>heading("Your recovery phrase"));
 const phrase=document.querySelector(".phrase").textContent.trim();const words=phrase.split(/\s+/);
 if(words.length!==24)throw new Error("synthetic phrase length");
 const positions=Array.from(document.querySelectorAll(".hint")).find(el=>el.textContent.startsWith("Word positions:")).textContent.match(/\d+/g).map(Number);
 positions.forEach((position,index)=>input(`word-${index}`,words[position-1]));document.querySelector(".primary").click();
 stage+=1;await until(()=>heading("Your vault is open"));
 document.querySelector(".primary").click();await until(()=>heading("Welcome back"));
 if(document.querySelector(".phrase"))throw new Error("synthetic reveal remained");
 input("password","incorrect");document.querySelector(".check input").click();await until(()=>!document.querySelector(".primary").disabled);document.querySelector(".primary").click();
 stage=6;await until(()=>!!document.querySelector(".error"));
 if(document.querySelector("#password").value)throw new Error("synthetic input remained");
 input("password",password);document.querySelector(".check input").click();await until(()=>!document.querySelector(".primary").disabled);document.querySelector(".primary").click();
 stage+=1;await until(()=>heading("Your vault is open"));document.querySelector(".primary").click();await until(()=>heading("Welcome back"));
 document.querySelectorAll(".tabs button")[2].click();await until(()=>!!document.querySelector("#phrase"));
 input("phrase",phrase);document.querySelector(".check input").click();await until(()=>!document.querySelector(".primary").disabled);document.querySelector(".primary").click();
 stage+=1;await until(()=>heading("Your vault is open"));document.querySelector(".primary").click();await until(()=>heading("Welcome back"));
 passed=true;
}catch{}
await until(()=>!!document.getElementById("validation-result"));input("validation-result",passed?"PASS":`FAIL:${stage}`);
