/* Plain-data configuration, shared by generated studios. No persistence or fetch. */
"use strict";
window.RADTBranding = (() => {
  const base={ink:"#203D3A",muted:"#596C68",canvas:"#F4F5F0",surface:"#FFFFFF",accent:"#236354",accent_soft:"#E8F1E9",line:"#D9E2DB",dark:"#163B35"};
  const presets={field:{brand:"Fieldwork",headline:"A good day starts with a plan.",theme:{...base,accent:"#315C83",dark:"#18364F",accent_soft:"#E8EFF7"}},studio:{brand:"Northline Studio",headline:"Make room for your best work.",theme:base}};
  function luminance(color){return [1,3,5].map(index=>parseInt(color.slice(index,index+2),16)/255).map(value=>value<=.04045?value/12.92:((value+.055)/1.055)**2.4).reduce((sum,value,index)=>sum+value*[.2126,.7152,.0722][index],0);}
  function contrast(first,second){const values=[luminance(first),luminance(second)].sort((a,b)=>a-b);return (values[1]+.05)/(values[0]+.05);}
  function validate(data) {
    if(!data||typeof data!=="object"||Array.isArray(data)||Object.keys(data).some(key=>!["schema_version","preset","brand","headline","theme"].includes(key)))throw new Error("Unknown web configuration fields");
    if(data.schema_version!==1)throw new Error("Web configuration requires schema_version 1");
    const preset=data.preset===undefined?"field":data.preset;
    if(typeof preset!=="string"||!Object.hasOwn(presets,preset))throw new Error("Choose the field or studio preset");
    const defaults=presets[preset],result={schema_version:1,preset};
    for(const [name,limit] of [["brand",80],["headline",160]]){
      const value=data[name]??defaults[name];
      if(typeof value!=="string"||!value.trim()||[...value].length>limit||/[\p{C}\p{Zl}\p{Zp}\p{Zs}]/u.test(value.replaceAll(" ","")))throw new Error(`${name} must be printable text of 1 to ${limit} characters`);
      result[name]=value.trim();
    }
    const theme=data.theme===undefined?defaults.theme:data.theme;
    if(!theme||typeof theme!=="object"||Array.isArray(theme)||Object.keys(theme).length!==8||Object.keys(base).some(key=>!Object.hasOwn(theme,key)||typeof theme[key]!=="string"||!/^#[0-9a-fA-F]{6}$/.test(theme[key])))throw new Error("theme must contain exactly eight six-digit hex colors");
    for(const [foreground,background] of [["ink","canvas"],["ink","surface"],["ink","accent_soft"],["muted","canvas"],["muted","surface"],["muted","accent_soft"],["accent","surface"],["accent","canvas"],["accent","accent_soft"],["surface","dark"]]){
      if(contrast(theme[foreground],theme[background])<4.5)throw new Error(`Theme contrast below 4.5:1 for ${foreground} on ${background}`);
    }
    result.theme={...theme};return result;
  }
  function preset(name){return validate({schema_version:1,preset:name});}
  function parse(text){
    if(typeof text!=="string"||new TextEncoder().encode(text).length>65536)throw new Error("Web configuration must be at most 64 KiB");
    const data=JSON.parse(text),stack=[];
    // JSON.parse checks syntax first. Token scanning only rejects duplicate keys,
    // including escaped spellings, so browser and CLI imports have the same rule.
    const tokens=text.match(/"(?:[^"\\]|\\.)*"|[{}\[\],:]|[^{}\[\],:\s]+/g)||[];
    for(const token of tokens){
      if(token==="{"||token==="[")stack.push({object:token==="{",keys:new Set(),key:true});
      else if(token==="}"||token==="]")stack.pop();
      else if(token===","){if(stack.at(-1)?.object)stack.at(-1).key=true;}
      else if(token.startsWith('"')&&stack.at(-1)?.object&&stack.at(-1).key){
        const context=stack.at(-1),name=JSON.parse(token);
        if(context.keys.has(name))throw new Error("Duplicate web configuration key");
        context.keys.add(name);context.key=false;
      }
    }
    return validate(data);
  }
  return Object.freeze({validate,preset,parse});
})();
