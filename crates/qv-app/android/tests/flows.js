// SPDX-License-Identifier: AGPL-3.0-or-later
// Instrumentation-only driver for the shared UI (plan 0040). Java polls these
// helpers; steppers return true once their step is done. Recovery words remain
// in this closure and never enter native test output.
window.qvDeviceFixture=(()=>{
 const password='K4L!c8vP2zR9qT7W6nM5';let phrase='',words=[];
 const q=s=>document.querySelector(s);
 function input(id,value){const el=document.getElementById(id);el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}))}
 // Only where a real finger could: not inert, has a box, topmost at its centre.
 function reachable(el){if(el.disabled||el.closest('[inert]'))return false;el.scrollIntoView({block:'center',inline:'center'});const r=el.getBoundingClientRect();if(r.width<1||r.height<1)return false;const hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);return !!hit&&(hit===el||el.contains(hit))}
 function click(id){const el=document.getElementById(id);if(!el||!reachable(el))return false;el.click();return true}
 function title(){return (q('.detail:not(.closed) h1, .page h1')?.textContent||'').trim()}
 // The old screen names, mapped onto the new screens.
 function at(name){
  switch(name){
   case 'Welcome back':return !!q('#password')&&!q('.shell')&&!q('#create-submit');
   case 'Your recovery phrase':return !!q('#phrase-show')||!!q('#phrase-written')||(!!q('#phrase-confirm'));
   case 'Edit entry':return !!q('#entry-save');
   case 'Archive exchange':return title()==='Archives';
   default:return title()===name;
  }
 }
 // 0 unlock, 1 create, 2 recover, 3 join.
 function tab(index){
  const done=[()=>!!q('#password')&&!q('#create-submit')&&!q('#recover-submit')&&!q('#join-submit'),()=>!!q('#vault-name'),()=>!!q('#phrase:not([type=hidden])')&&!!q('#recover-submit'),()=>!!q('#lan-join-code')][index];
  if(done())return true;
  if(index===0){const b=Array.from(document.querySelectorAll('button')).find(b=>['Back','Cancel'].includes(b.textContent.trim()));if(b)b.click();return false}
  const ids=[null,['welcome-create','menu-create'],['welcome-recover','menu-recover'],['welcome-join','menu-join']][index];
  for(const id of ids)if(click(id))return false;
  click('vault-menu');return false;
 }
 return {
  at,tab,
  create:skip=>{input('vault-path',(skip?window.qvDeviceFixturePath.replace(/\.qvault$/,'-skip.qvault'):window.qvDeviceFixturePath));input('vault-name','Synthetic phone fixture');input('password',password);input('repeat',password)},
  // The explicit reduced-protection acknowledgement, once per status.
  consent:()=>{
   if(click('protection-ack'))return false;
   const chip=q('#protection-chip');
   if(!chip||!chip.textContent.includes('review')){const done=Array.from(document.querySelectorAll('.dialog button')).find(b=>b.textContent.trim()==='Done');if(done){done.click();return false}return true}
   if(!q('#protection-status'))chip.click();
   return false;
  },
  ready:()=>!!['unlock-submit','create-submit','recover-submit','join-submit'].map(id=>document.getElementById(id)).find(b=>b&&!b.disabled),
  opening:()=>Array.from(document.querySelectorAll('button,p')).some(e=>/Opening…|Creating…|Joining…/.test(e.textContent)),
  submit:()=>{for(const id of ['lock','phrase-confirm','create-submit','recover-submit','join-submit','unlock-submit'])if(click(id))return true;return false},
  capture:()=>{words=Array.from(document.querySelectorAll('.phrase .w')).map(w=>w.textContent.trim());phrase=words.join(' ');return words.length===24},
  // Show the words, continue, then type the requested ones.
  confirm:()=>{
   if(!q('#word-0')){if(!click('phrase-written'))click('phrase-show');return false}
   const positions=Array.from(document.querySelectorAll('.hint')).find(el=>el.textContent.startsWith('Word positions:')).textContent.match(/\d+/g).map(Number);
   positions.forEach((position,index)=>input(`word-${index}`,words[position-1]));return true;
  },
  unlock:wrong=>{input('vault-path',window.qvDeviceFixturePath);input('password',wrong?'incorrect':password)},
  recover:()=>{input('vault-path',window.qvDeviceFixturePath);input('phrase',phrase)},
  chooseSkip:()=>{
   if(!q('#word-0')){if(!click('phrase-written'))click('phrase-show');return false}
   const details=Array.from(document.querySelectorAll('details')).find(el=>el.querySelector('summary').textContent==='Skip phrase confirmation');
   details.open=true;const box=details.querySelector('input');if(!box.checked)box.click();return true;
  },
  skip:()=>Array.from(document.querySelectorAll('details')).find(el=>el.querySelector('summary').textContent==='Skip phrase confirmation').querySelector('button').click(),
  clear:()=>{phrase='';words.fill('');window.qvDeviceFixturePath=''},
  // Unlocked workspace helpers; values are synthetic canaries. Buttons match
  // their text, their accessible name, or the item row they open.
  button:text=>{const b=Array.from(document.querySelectorAll('button')).find(b=>!b.disabled&&(b.textContent.trim().startsWith(text)||(b.getAttribute('aria-label')||'').startsWith(text)||b.getAttribute('aria-label')==='Open '+text));if(!b||!reachable(b))return false;b.click();return true},
  nav:label=>{
   const ids={Vault:'nav-all',Settings:'nav-settings',Generator:'nav-generator',Devices:'nav-devices',Trash:'nav-trash'};
   if(ids[label])return click(ids[label]);
   if(label==='Archives'){if(click('settings-archives'))return true;click('nav-settings');return false}
   return false;
  },
  lock:()=>click('lock'),
  // The new-item start step: choose Login, then the form appears.
  startLogin:()=>{if(q('#ws-title'))return true;click('start-login');return false},
  entryForm:()=>{input('ws-title','Synthetic phone entry');input('ws-field-value-0','phone@example.test')},
  // Bounded failure context: headings, flags and button labels only, never
  // field values or the recovery phrase.
  summary:()=>{const t=s=>(s||'').trim().slice(0,40);return JSON.stringify({title:t(title()),locked:!!q('#password'),busy:!!q('.busy-toast'),notice:t(q('.notice')?.textContent),buttons:Array.from(document.querySelectorAll('button')).filter(b=>!b.closest('.phrase')).slice(0,14).map(b=>t(b.textContent||b.getAttribute('aria-label')).slice(0,24))})},
  attachmentFields:()=>{input('ws-attach-name','phone-canary.bin');input('ws-attach-mime','application/test')}
 };
})();
