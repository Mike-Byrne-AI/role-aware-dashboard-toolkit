"use strict";
const presets = {
  field: {records:[
    {id:"riverside",title:"Riverside seasonal service",lane:"scheduled",description:"Riverside estate",meta:"Mon, 9:00 AM",people:[{id:"alex",name:"Alex Morgan"}]},
    {id:"oak",title:"Oak Street site visit",lane:"scheduled",description:"Oak Street",meta:"Tue, 10:00 AM",people:[{id:"sam",name:"Sam Rivera"}]},
    {id:"willow",title:"Willow courtyard restoration",lane:"in_progress",description:"Willow House",meta:"Work underway",people:[{id:"alex",name:"Alex Morgan"}]},
    {id:"meadow",title:"Meadow garden handover",lane:"completed",description:"Meadow Gardens",meta:"Handover recorded",people:[{id:"sam",name:"Sam Rivera"}]}
  ]},
  studio: {records:[
    {id:"common",title:"Common Ground discovery",lane:"scheduled",description:"Discovery workshop",meta:"Mon, 9:00 AM",people:[{id:"jules",name:"Jules Chen"}]},
    {id:"fieldwork",title:"Fieldwork launch workshop",lane:"scheduled",description:"Launch planning",meta:"Tue, 10:00 AM",people:[{id:"riley",name:"Riley Park"}]},
    {id:"atlas",title:"Atlas digital experience",lane:"in_progress",description:"Design and build",meta:"Work underway",people:[{id:"jules",name:"Jules Chen"}]},
    {id:"northbank",title:"Northbank brand delivery",lane:"completed",description:"Brand system",meta:"Handover recorded",people:[{id:"riley",name:"Riley Park"}]}
  ]}
};
const lanes=[{id:"scheduled",label:"Scheduled",description:"Ready for a good start"},{id:"in_progress",label:"In progress",description:"Good work in motion"},{id:"completed",label:"Completed",description:"Handed over, with a record"}];
let filter = "all";
let presentation=window.RADTBranding.validate(window.RADTWebConfig);
let studioTour=null;
let presentationRevision=0;
document.querySelector("#preset").value=presentation.preset;
function selectedPreset(){return {...presets[presentation.preset],brand:presentation.brand,title:presentation.headline};}
function renderRecords() {
  const preset=selectedPreset(),ui=window.RADTWeb;
  const records=ui.filterItems(preset.records,{query:document.querySelector("#studio-search").value,lane:filter==="all"?"":filter});
  document.querySelector("#records").innerHTML=records.length?ui.board({lanes:lanes.filter(lane=>filter==="all"||lane.id===filter),items:records.map(item=>({...item,eyebrow:preset.brand})),label:"Sample delivery board"}):ui.empty({title:"No matching work",description:"Try another search or stage."});
  document.querySelector("#studio-count").textContent=`${records.length} of ${preset.records.length} fictional work items`;
  document.querySelectorAll("[data-filter]").forEach(button=>button.setAttribute("aria-pressed",String(button.dataset.filter===filter)));
}
function render() {
  const preset = selectedPreset();
  const ui = window.RADTWeb;
  for(const [name,value] of Object.entries(presentation.theme))document.documentElement.style.setProperty("--radt-"+name.replaceAll("_","-"),value);
  document.querySelector("#brand").textContent = preset.brand + " / Component studio";
  document.title=preset.brand+" / Component studio";
  document.querySelector("#title").textContent = preset.title;
  document.querySelector("#metrics").innerHTML = lanes.map((lane,index)=>ui.metric({label:lane.label,value:preset.records.filter(item=>item.lane===lane.id).length,note:"Fictional work \u00b7 this week",action:"show-"+lane.id.replace("_","-"),tone:index===0?"accent":"default"})).join("");
  document.querySelector("#actions").innerHTML = ui.action({title:"Review scheduled work",description:"Open the two upcoming assignments",count:2,action:"show-scheduled"})+ui.action({title:"View completed work",description:"See the handover record",count:1,action:"show-completed"})+ui.action({title:"Restricted action",description:"Presentation state only; hosts must enforce permissions",action:"restricted",disabled:true});
  document.querySelector("#steps").innerHTML = ui.steps(["Scheduled","In progress","Completed"],1);
  renderRecords();
}
document.querySelector("#preset").addEventListener("change",()=>{presentationRevision++;document.querySelector("#brand-status").textContent="Preset applied. Export the configuration to use it again.";presentation=window.RADTBranding.preset(document.querySelector("#preset").value);syncBrandFields();filter="all";document.querySelector("#studio-search").value="";document.querySelector("#result").textContent="Preset updated. Both brands use the same components.";render();});
document.querySelector("#studio-search").addEventListener("input",renderRecords);
document.addEventListener("click",event=>{
  const button=event.target.closest("button");if(!button)return;
  if(button.dataset.filter)filter=button.dataset.filter;
  else if(button.dataset.action?.startsWith("show-"))filter=button.dataset.action.slice(5).replace("-","_");
  else return;
  renderRecords();document.querySelector("#result").textContent=`Showing ${filter.replace("_"," ")} work.`;
});
const colorLabels={ink:"Text",muted:"Secondary text",canvas:"Page background",surface:"Card background",accent:"Accent",accent_soft:"Soft accent",line:"Borders",dark:"Dark surface"};
document.querySelector("#brand-colors").innerHTML=Object.entries(colorLabels).map(([name,label])=>`<label>${label}<input name="${name}" pattern="#[0-9a-fA-F]{6}" maxlength="7" required spellcheck="false" aria-label="${label} color"></label>`).join("");
function syncBrandFields(){
  const form=document.querySelector("#brand-form");
  form.elements.brand.value=presentation.brand;form.elements.headline.value=presentation.headline;
  for(const [name,value] of Object.entries(presentation.theme))form.elements[name].value=value;
  document.querySelector("#brand-error").textContent="";
}
function applyPresentation(value){
  presentationRevision++;presentation=value;filter="all";document.querySelector("#preset").value=value.preset;
  document.querySelector("#studio-search").value="";syncBrandFields();render();
  document.querySelector("#brand-status").textContent="Brand applied. Export the configuration to use it again.";
}
document.querySelector("#brand-form").addEventListener("input",()=>{presentationRevision++;});
document.querySelector("#brand-form").addEventListener("submit",event=>{
  event.preventDefault();
  const fields=new FormData(event.currentTarget);
  try{applyPresentation(window.RADTBranding.validate({schema_version:1,preset:presentation.preset,brand:fields.get("brand"),headline:fields.get("headline"),theme:Object.fromEntries(Object.keys(colorLabels).map(name=>[name,fields.get(name)]))}));}
  catch(error){document.querySelector("#brand-error").textContent=error.message;document.querySelector("#brand-status").textContent="The applied brand is unchanged.";}
});
document.querySelector("#brand-reset").addEventListener("click",()=>applyPresentation(window.RADTBranding.preset(presentation.preset)));
document.querySelector("#brand-export").addEventListener("click",()=>{
  const url=URL.createObjectURL(new Blob([JSON.stringify(presentation,null,2)+"\n"],{type:"application/json"}));
  const link=document.createElement("a");link.href=url;link.download="web-presentation.json";link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  document.querySelector("#brand-status").textContent="Configuration exported. Use it with init --web --web-config.";
});
document.querySelector("#brand-import").addEventListener("change",async event=>{
  const file=event.target.files[0];if(!file)return;
  const revision=++presentationRevision;
  try{
    if(file.size>65536)throw new Error("Web configuration must be at most 64 KiB");
    const text=await file.text();if(revision!==presentationRevision)return;
    applyPresentation(window.RADTBranding.parse(text));
  }catch(error){if(revision!==presentationRevision)return;document.querySelector("#brand-error").textContent=error instanceof SyntaxError?"Configuration must be valid JSON.":error.message;document.querySelector("#brand-status").textContent="The applied brand is unchanged.";}
  finally{event.target.value="";}
});
document.querySelector("#studio-tour").addEventListener("click",async()=>{
  if(studioTour)return;
  const tour=window.RADTTour.create({steps:[
    {target:"#title",title:"One toolkit, your brand",body:"Choose a field-services or professional-services scenario. Both use the same reusable presentation components."},
    {target:"#metrics",title:"Connect the numbers to the work",body:"Metrics are actionable. Close the walkthrough and choose a stage to see the fictional assignments behind its count."},
    {target:"#list-title",title:"See the whole delivery",body:"Search across projects and people, then narrow by stage. The board reflows for smaller screens."},
    {target:"#brand-studio",title:"Make the next demo repeatable",body:"Apply your brand text and colors, then export a configuration. Generate a fresh studio from that file whenever you need it."}
  ],onStep:async step=>{
    if(step.target==="#brand-studio")document.querySelector(step.target).open=true;
    document.querySelector(step.target).scrollIntoView({block:"start",behavior:"instant"});
  },returnFocus:()=>document.querySelector("#studio-tour"),onClose:()=>{if(studioTour===tour)studioTour=null;}});
  studioTour=tour;await tour.start();
});
syncBrandFields();render();
