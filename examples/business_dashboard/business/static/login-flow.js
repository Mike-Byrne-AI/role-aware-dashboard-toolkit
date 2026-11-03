"use strict";

// The HttpOnly flow cookie is deliberately invisible here. Web Locks only
// coordinate cooperating tabs; the server owns generation and expiry checks.
window.WestbridgeLoginFlow=Object.freeze({create({request,currentSession,busyChanged}) {
  let active=null;
  const changed=()=>Object.assign(new Error("Sign-in changed or expired. Start sign-in again."),{status:409});
  const cancelled=()=>new DOMException("Sign-in view changed.","AbortError");
  const same=(left,right)=>Boolean(left?.user?.id)&&left.user.id===right?.user?.id&&
    typeof left.csrf==="string"&&Boolean(left.csrf)&&left.csrf===right.csrf&&
    typeof left.session_id==="string"&&Boolean(left.session_id)&&left.session_id===right.session_id;
  async function context({signal,owns=()=>true}={}) {
    const before={...currentSession()},account=before.user?.id,csrf=before.csrf||"";
    let installedCsrf="";
    const current=()=>owns()&&currentSession().user?.id===account&&(currentSession().csrf||"")===csrf;
    const fetchContext=async()=>{
      if(!current())throw cancelled();
      const result=await request("/api/login/context","POST",{},{signal,sessionCsrf:installedCsrf});
      if(!current())throw cancelled();
      if(typeof result?.csrf!=="string"||!result.csrf||!Number.isSafeInteger(result.expires_at)||!Number.isSafeInteger(result.flow_expires_at))throw changed();
      return result;
    };
    const confirm=async()=>{
      if(!current())throw cancelled();
      const installed=await request("/api/session","GET",undefined,{signal});
      if(!current())throw cancelled();
      // Another tab may have signed in since this anonymous view was rendered.
      // A signed-in view must still own its exact captured authority.
      if(account&&!same(before,installed))throw changed();
      if(installed.user) {
        if(typeof installed.csrf!=="string"||!installed.csrf)throw changed();
        installedCsrf=installed.csrf;
      }
      await fetchContext();return fetchContext();
    };
    // Confirm the installed cookie after bootstrap without replaying credentials.
    return navigator.locks?.request
      ? navigator.locks.request("westbridge.login-context",{mode:"exclusive",...(signal?{signal}:{})},confirm)
      : confirm();
  }
  return Object.freeze({
    get busy(){return active!==null;},
    context,
    cancelPreparation(){if(active&&!active.dispatched)active.controller.abort();},
    async run({owns,started},prove) {
      if(active)return null;
      const operation={controller:new AbortController(),dispatched:false};
      active=operation;busyChanged();
      try {
        const snapshot=await context({signal:operation.controller.signal,owns});
        if(!owns())throw cancelled();
        started(snapshot);
        const result=await prove({context:snapshot,signal:operation.controller.signal,
          dispatch(){if(!owns())throw cancelled();operation.dispatched=true;}});
        // The final request has no abort signal: dismissal cannot undo commit.
        if(!owns())return null;
        const installed=await request("/api/session");
        if(!owns())return null;
        if(!same(result,installed))throw changed();
        return installed;
      } finally {
        if(active===operation){active=null;busyChanged();}
      }
    },
  });
}});
