/* A disposable presentation controller. Hosts own navigation and authorization. */
"use strict";
window.RADTTour = (() => {
  let sequence=0;
  function create({steps,onStep=async()=>{},onClose=()=>{},returnFocus=()=>document.activeElement}) {
    if(!Array.isArray(steps)||!steps.length||steps.length>20||steps.some(step=>!step||typeof step.title!=="string"||typeof step.body!=="string"))throw new Error("Invalid tour steps");
    if([onStep,onClose,returnFocus].some(value=>typeof value!=="function"))throw new Error("Invalid tour callbacks");
    const entries=steps.map(step=>({...step})),dialog=document.createElement("dialog"),controller=new AbortController();
    const identifier=`radt-tour-${++sequence}`;
    let index=0,busy=false,failed=false,closed=false,started=false;
    const original=document.activeElement;
    dialog.className="radt-tour";dialog.setAttribute("aria-labelledby",identifier);
    dialog.innerHTML=`<div class="radt-tour-top"><span class="radt-tour-progress"></span><button type="button" data-tour="close" aria-label="Close walkthrough">×</button></div><h2 id="${identifier}" tabindex="-1"></h2><p class="radt-tour-body"></p><p class="radt-tour-status" role="status" aria-live="polite"></p><div class="radt-tour-controls"><button type="button" data-tour="back">Back</button><button type="button" data-tour="next">Next</button></div>`;
    const heading=dialog.querySelector("h2"),body=dialog.querySelector(".radt-tour-body"),status=dialog.querySelector(".radt-tour-status");
    const back=dialog.querySelector('[data-tour="back"]'),next=dialog.querySelector('[data-tour="next"]');
    function paint() {
      dialog.querySelector(".radt-tour-progress").textContent=`QUICK WALKTHROUGH · ${index+1} / ${entries.length}`;
      heading.textContent=entries[index].title;body.textContent=entries[index].body;
      back.disabled=busy||index===0;next.disabled=busy;
      next.textContent=busy?"Opening…":failed?"Try again":index===entries.length-1?"Finish":"Next";
      status.textContent=busy?"Opening this step…":failed?"This step could not be opened. Try again, or close the walkthrough and refresh.":"";
      dialog.setAttribute("aria-busy",String(busy));
    }
    async function move(target) {
      if(closed||busy)return;
      index=target;busy=true;failed=false;paint();
      try {await onStep(entries[index],{index,signal:controller.signal});}
      catch {if(!closed)failed=true;}
      if(closed)return;
      busy=false;paint();heading.focus({preventScroll:true});
    }
    function close({restoreFocus=true}={}) {
      if(closed)return;
      closed=true;controller.abort();dialog.close();dialog.remove();
      try {onClose();}
      finally {
        if(restoreFocus){const target=returnFocus();(target?.isConnected?target:original?.isConnected?original:null)?.focus({preventScroll:true});}
      }
    }
    dialog.addEventListener("cancel",event=>{event.preventDefault();close();});
    dialog.addEventListener("close",()=>close());
    dialog.addEventListener("click",event=>{
      const action=event.target.closest("[data-tour]")?.dataset.tour;
      if(action==="close")close();
      else if(action==="back"&&!busy&&index>0)void move(index-1);
      else if(action==="next"&&!busy){if(failed)void move(index);else if(index===entries.length-1)close();else void move(index+1);}
    });
    async function start() {
      if(started||closed)throw new Error("Create a new tour to restart");
      started=true;document.body.append(dialog);dialog.showModal();await move(0);
    }
    return Object.freeze({start,close});
  }
  return Object.freeze({create});
})();
