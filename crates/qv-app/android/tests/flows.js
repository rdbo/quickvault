// SPDX-License-Identifier: AGPL-3.0-or-later
// Instrumentation-only synchronous driver. Java waits on observable DOM state;
// recovery words remain in this closure and never enter native test output.
window.qvDeviceFixture=(()=>{
 const password='K4L!c8vP2zR9qT7W6nM5';let phrase='',words=[];
 function input(id,value){const el=document.getElementById(id);el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}))}
 return {
  tab:index=>document.querySelectorAll('.tabs button')[index].click(),
  create:skip=>{input('vault-path',(skip?window.qvDeviceFixturePath.replace(/\.qvault$/,'-skip.qvault'):window.qvDeviceFixturePath));input('vault-name','Synthetic phone fixture');input('password',password);input('repeat',password)},
  consent:()=>{const checkbox=document.querySelector('.check input');if(!checkbox.checked)checkbox.click()},
  submit:()=>document.querySelector('.primary').click(),
  capture:()=>{phrase=document.querySelector('.phrase').textContent.trim();words=phrase.split(/\s+/);return words.length===24},
  confirm:()=>{const positions=Array.from(document.querySelectorAll('.hint')).find(el=>el.textContent.startsWith('Word positions:')).textContent.match(/\d+/g).map(Number);positions.forEach((position,index)=>input(`word-${index}`,words[position-1]))},
  unlock:wrong=>{input('vault-path',window.qvDeviceFixturePath);input('password',wrong?'incorrect':password)},
  recover:()=>{input('vault-path',window.qvDeviceFixturePath);input('phrase',phrase)},
  chooseSkip:()=>{const details=Array.from(document.querySelectorAll('details')).find(el=>el.querySelector('summary').textContent==='Skip phrase confirmation');details.open=true;details.querySelector('input').click()},
  skip:()=>Array.from(document.querySelectorAll('details')).find(el=>el.querySelector('summary').textContent==='Skip phrase confirmation').querySelector('button').click(),
  clear:()=>{phrase='';words.fill('');window.qvDeviceFixturePath=''}
 };
})();
