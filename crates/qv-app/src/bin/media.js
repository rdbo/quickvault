// SPDX-License-Identifier: AGPL-3.0-or-later
// Native-engine test driver. All media and vault data are synthetic; never log URLs.
(async()=>{
const wait=async test=>{const end=performance.now()+60000;while(performance.now()<end){if(test())return;await new Promise(r=>setTimeout(r,100));}throw new Error("synthetic media deadline")};
const tap=async id=>{await wait(()=>!!document.getElementById(id)&&!document.getElementById(id).disabled);document.getElementById(id).click()};
const open=async name=>{await wait(()=>!!document.querySelector(`[aria-label="Preview ${name}"]`));document.querySelector(`[aria-label="Preview ${name}"]`).click()};
// currentSrc can retain a stale URL after load() without a source (WHATWG
// html#10410). Assert the decoder/network reset, not that reporting quirk.
const reset=media=>media.paused&&!media.hasAttribute("src")&&media.readyState===0&&
 (media.networkState===0||media.networkState===3)&&media.currentTime===0&&!media.isConnected;
const refused=async url=>{const late=new Audio();late.muted=true;late.preload="auto";late.src=url;late.load();try{await wait(()=>!!late.error);}finally{late.removeAttribute("src");late.load();}};
// The player's own controls are ready once the media has its metadata (player.js).
const ready=media=>wait(()=>media.closest(".v-player")?.hasAttribute("data-qv-ready"));
const point=control=>control.dispatchEvent(new PointerEvent("pointermove",{bubbles:true,pointerType:"mouse"}));
const press=(media,selector)=>{const control=media.closest(".v-player").querySelector(selector);point(control);control.click();};
const playing=media=>media.closest(".v-player").getAttribute("data-state")==="playing";
// A running clock does not establish that the decoder presents frames. Count
// new presented frames near the start, before the next keyframe at 8.33 s.
const moving=async(media,from=0.1,to=4)=>{
 await wait(()=>!media.paused&&media.currentTime>from&&media.currentTime<to);
 const start=media.currentTime;let frames=0,callback=0,last=-1;
 const frame=(_now,meta)=>{if(meta.mediaTime>last){last=meta.mediaTime;frames++;}callback=media.requestVideoFrameCallback(frame);};
 const presented=()=>{const q=media.getVideoPlaybackQuality();return q.totalVideoFrames-q.droppedVideoFrames;};
 // The software path can reset its statistics asynchronously on resume.
 // Accumulate actual frame increments across resets, not a single subtraction
 // spanning two decoder counter lifetimes. A frozen decoder adds no frames.
 let previous=presented(),rendered=0,resets=0;
 const sample=()=>{const next=presented();if(next<previous){resets++;rendered+=next;}else rendered+=next-previous;previous=next;};
 const sampling=setInterval(sample,50);
 if(media.requestVideoFrameCallback)callback=media.requestVideoFrameCallback(frame);
 try{
  await new Promise(r=>setTimeout(r,1200));
  // WebKit's non-composited path exposes the callback API without delivering
  // callbacks; its presented-frame counter still advances. Neither is a clock.
  sample();const shown=frames||rendered;
  const result=document.getElementById("validation-result");
  if(result){result.value="MEDIA-FRAMES:"+[frames,rendered,resets,Math.round(start*1000),Math.round(media.currentTime*1000)].join(",");result.dispatchEvent(new Event("input",{bubbles:true}));}
  if(shown<6||media.currentTime<=start+0.5||media.currentTime>=to)throw new Error("video frames stalled");
 }finally{clearInterval(sampling);if(callback)media.cancelVideoFrameCallback(callback);}
};
// Check the frame chosen by a paused seek, including a seek after EOS. The
// composited engine reports its presented timestamp; software readiness still
// requires a decoded frame. Subsequent Play is checked by moving() too.
const select=async(media,position)=>{
 let shown=null,callback=0;
 const frame=(_now,meta)=>{shown=meta.mediaTime;callback=media.requestVideoFrameCallback(frame);};
 if(media.requestVideoFrameCallback)callback=media.requestVideoFrameCallback(frame);
 try{
  const slider=media.closest(".v-player").querySelector(".v-seek");point(slider);slider.value=String(position);
  slider.dispatchEvent(new Event("input",{bubbles:true}));slider.dispatchEvent(new Event("change",{bubbles:true}));
  await wait(()=>media.readyState>=2&&!media.seeking&&Math.abs(media.currentTime-position)<0.25);
  await new Promise(r=>setTimeout(r,300));
  if(!media.paused||(shown!==null&&Math.abs(shown-position)>0.25))throw new Error("paused seek frame");
 }finally{if(callback)media.cancelVideoFrameCallback(callback);}
};
let stage=1,passed=false,lastMedia=null;
const mark=n=>{stage=n;const result=document.getElementById("validation-result");if(result){result.value=`MEDIA-STAGE:${n}`;result.dispatchEvent(new Event("input",{bubbles:true}));}};
try{
 await wait(()=>!!document.querySelector(".shelf"));
 // The list scrolls as one window (plan 0072): 41 rows arrive as two pages,
 // the second when the list's end comes into view; no Previous/Next.
 mark(60);const rowCount=()=>document.querySelectorAll("#rows .row").length;
 await wait(()=>rowCount()===32&&!!document.querySelector("[data-qv-more]"));
 if([...document.querySelectorAll("button")].some(b=>["Next","Previous"].includes(b.textContent.trim())))throw new Error("paging buttons");
 document.querySelector("[data-qv-more]").scrollIntoView({block:"end"});
 await wait(()=>rowCount()===41&&!document.querySelector("[data-qv-more]"));
 mark(2);await open("a-audio.wav");await wait(()=>!!document.querySelector(".viewer audio"));
 const audio=document.querySelector(".viewer audio");lastMedia=audio;
 // Linux plays verified media from memory (WebKitGTK buffers HTTP media to disk; plan 0057).
 const blobbed=audio.hasAttribute("data-qv-src");const audioURL=blobbed?audio.getAttribute("data-qv-src"):audio.src;
 await ready(audio);const audioSrc=audio.src;
 if(blobbed!==audioSrc.startsWith("blob:"))throw new Error("media source");
 if(audio.autoplay||!audio.paused||audio.controls)throw new Error("eager media");
 audio.muted=true;press(audio,".v-play");await wait(()=>audio.currentTime>0.3&&playing(audio));
 mark(3);audio.currentTime=31;await wait(()=>!audio.seeking&&audio.currentTime>31.2);
 mark(4);await tap("viewer-close");await wait(()=>!document.querySelector(".viewer"));
 await wait(()=>reset(audio));mark(40);await refused(audioURL);if(blobbed)await refused(audioSrc);mark(41);
 mark(5);await open("b-video.mp4");await wait(()=>!!document.querySelector(".viewer video"));
 const video=document.querySelector(".viewer video");lastMedia=video;
 if(video.preload!=="auto"||video.autoplay)throw new Error("video preload");
 await ready(video);if(blobbed!==video.src.startsWith("blob:"))throw new Error("media source");
 // An MP4 plays through Media Source Extensions, not WebKit's blob playback.
 if(blobbed&&video.getAttribute("data-qv-playback")!=="stream")throw new Error("media stream");
 // It streams in ranges around the playback position, never whole (plan 0059).
 if(blobbed&&!video.hasAttribute("data-qv-ranges"))throw new Error("media ranges");
 // The first frame is ready before play, and the player fills the stage (plan 0057).
 await wait(()=>video.readyState>=2&&video.videoWidth===128);
 if(!video.paused||video.currentTime!==0||video.clientWidth<=300)throw new Error("video idle");
 video.muted=true;press(video,".v-play");await wait(()=>video.currentTime>0.3&&playing(video));
 mark(6);video.currentTime=2;await wait(()=>!video.seeking&&video.currentTime>2.2);
 // Play again after the end starts over and advances (plan 0057).
 await wait(()=>video.ended&&!playing(video));press(video,".v-play");
 await moving(video);
 // Full screen is the player's own control (desktop).
 if(document.getElementById("viewer-full")){
  await tap("viewer-full");await wait(()=>!!document.querySelector(".viewer.full"));
  await tap("viewer-full");await wait(()=>!document.querySelector(".viewer.full"));
 }
 mark(7);await tap("viewer-close");await wait(()=>reset(video));
 // Sparse keyframes plus B-frames reproduce the EOS replay fault hidden by
 // the original fixture's one-second keyframe interval. Never use user data.
 mark(70);await open("e-long-gop.mp4");await wait(()=>!!document.querySelector(".viewer video"));
 const sparse=document.querySelector(".viewer video");lastMedia=sparse;await ready(sparse);sparse.muted=true;
 press(sparse,".v-play");await moving(sparse);
 for(let replay=0;replay<2;replay++){
  await wait(()=>sparse.ended&&!playing(sparse));mark(71+replay);
  press(sparse,".v-play");await moving(sparse);
 }
 // Pause/resume and a seek inside the first GOP still present frames.
 press(sparse,".v-play");await wait(()=>sparse.paused);
 press(sparse,".v-play");await moving(sparse);
 sparse.currentTime=1;await wait(()=>!sparse.seeking);await moving(sparse);
 // A control press released on the backdrop produces a retargeted click.
 // It must be consumed before the native close handler sees it.
 mark(73);const control=sparse.closest(".v-player").querySelector(".v-seek");
 const backdrop=sparse.closest(".viewer").querySelector(".v-stage");
 control.dispatchEvent(new PointerEvent("pointerdown",{bubbles:true,pointerId:1}));
 backdrop.dispatchEvent(new PointerEvent("pointerup",{bubbles:true,pointerId:1}));
 backdrop.dispatchEvent(new MouseEvent("click",{bubbles:true,cancelable:true,detail:1}));
 await new Promise(r=>setTimeout(r,100));
 if(!sparse.isConnected||!document.querySelector(".viewer"))throw new Error("control drag closed viewer");
 // Close a pending replay by an ordinary background click.
 mark(74);sparse.currentTime=sparse.duration-0.2;await wait(()=>sparse.ended);
 // The slider must recover an exhausted source too, keeping the selected
 // frame paused until Play. Check both a nonzero target and the start.
 for(const position of [1,0]){
  mark(78+position);await select(sparse,position);press(sparse,".v-play");await moving(sparse);
  await wait(()=>sparse.ended&&!playing(sparse));
 }
 mark(75);press(sparse,".v-play");
 backdrop.dispatchEvent(new PointerEvent("pointerdown",{bubbles:true,pointerId:2}));
 backdrop.dispatchEvent(new PointerEvent("pointerup",{bubbles:true,pointerId:2}));
 backdrop.dispatchEvent(new MouseEvent("click",{bubbles:true,cancelable:true,detail:1}));
 mark(76);await wait(()=>reset(sparse));mark(77);await new Promise(r=>setTimeout(r,300));
 if(!reset(sparse))throw new Error("late replay after close");
 // A long clip streams around the playback position (plan 0059): about 30 s
 // ahead is buffered, a seek far ahead restarts there with moving frames,
 // and what lies far behind is dropped.
 mark(90);await open("f-long.mp4");await wait(()=>!!document.querySelector(".viewer video"));
 const long=document.querySelector(".viewer video");lastMedia=long;await ready(long);long.muted=true;
 const ahead=()=>long.buffered.length?long.buffered.end(long.buffered.length-1):0;
 if(blobbed){await wait(()=>ahead()>=20);if(ahead()>45)throw new Error("buffered too far ahead");}
 press(long,".v-play");await moving(long,0.1,10);
 // Far seeks append at the target in the same source: no reload, so the
 // picture is never blanked (plan 0072).
 let emptied=0;const count=()=>emptied++;long.addEventListener("emptied",count);
 mark(91);long.currentTime=70;await wait(()=>!long.seeking);mark(93);await moving(long,70,80);
 if(blobbed&&(!long.buffered.length||long.buffered.start(0)<60))throw new Error("stale data kept");
 // A paused jump far back (the data there was dropped) shows the chosen
 // frame before Play, again without a reload.
 if(blobbed){
  mark(95);press(long,".v-play");await wait(()=>long.paused);
  await select(long,10);press(long,".v-play");await moving(long,10,14);
 }
 long.removeEventListener("emptied",count);
 if(blobbed&&emptied)throw new Error("far seek reloaded the source");
 mark(92);await tap("viewer-close");await wait(()=>reset(long));
 mark(8);await open("c-image.png");await wait(()=>!!document.querySelector(".viewer img"));
 await wait(()=>document.querySelector(".viewer img").naturalWidth===64);
 await tap("viewer-close");await wait(()=>!document.querySelector(".viewer"));
 mark(9);await open("d-large.png");await wait(()=>!!document.getElementById("viewer-load-image"));
 if(document.querySelector(".viewer img")||!document.querySelector(".viewer").textContent.includes("5000 × 4000"))throw new Error("implicit large decode");
 // Consent loads it: over 64 KiB, so it arrives range by range as a blob
 // image (plan 0072); closing drops the blob.
 mark(94);await tap("viewer-load-image");await wait(()=>!!document.querySelector(".viewer img"));
 const big=document.querySelector(".viewer img");await wait(()=>big.naturalWidth===5000&&big.naturalHeight===4000);
 if(!big.src.startsWith("blob:"))throw new Error("image not from memory");
 await tap("viewer-close");await wait(()=>!document.querySelector(".viewer"));
 if(big.hasAttribute("src"))throw new Error("image source kept");
 mark(10);await open("a-audio.wav");await wait(()=>!!document.querySelector(".viewer audio"));
 const lockedAudio=document.querySelector(".viewer audio");lastMedia=lockedAudio;await ready(lockedAudio);lockedAudio.muted=true;press(lockedAudio,".v-play");await wait(()=>lockedAudio.currentTime>0.2);
 document.querySelector("[data-qv-epoch]").dispatchEvent(new KeyboardEvent("keydown",{key:"l",ctrlKey:true,bubbles:true}));
 await wait(()=>!document.querySelector(".shell"));await wait(()=>reset(lockedAudio));
 // A new media request cannot reuse a capability after close/lock.
 mark(11);await refused(audioURL);
 passed=true;
}catch{
 const result=document.getElementById("validation-result");
 if(result&&lastMedia){const b=lastMedia.buffered,ms=t=>Math.round(t*1000);result.value="MEDIA-FACTS:"+[Number(lastMedia.paused),Number(lastMedia.hasAttribute("src")),lastMedia.readyState,lastMedia.networkState,Number(!lastMedia.currentSrc),Number(lastMedia.isConnected),Number(lastMedia.seeking),ms(lastMedia.currentTime),b.length,b.length?ms(b.start(0)):0,b.length?ms(b.end(b.length-1)):0].join(",");result.dispatchEvent(new Event("input",{bubbles:true}));}
 /* Fixed numeric facts only; media URLs and platform messages stay out of logs. */
}
finally{
 const result=document.getElementById("validation-result");
 if(result){result.value=passed?"PASS":`FAIL:${stage}`;result.dispatchEvent(new Event("input",{bubbles:true}));}
}
})();
