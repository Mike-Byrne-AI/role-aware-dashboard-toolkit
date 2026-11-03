"use strict";

// Enrollment uses its own cookie and CSRF proof. It never installs a session.
window.WestbridgeEnrollment = (() => {
  function create({captureSession, completed, escapeHTML}) {
    const dialog=document.createElement("dialog");
    dialog.id="enrollment-dialog";
    dialog.setAttribute("aria-labelledby","enrollment-title");
    document.body.append(dialog);
    let view=null, expiryTimer=null;
    const e=escapeHTML;

    function close() {
      clearTimeout(expiryTimer);
      view=null;
      dialog.querySelectorAll("form").forEach(form=>form.reset());
      dialog.close();dialog.replaceChildren();
    }
    function current(item) {return view===item&&dialog.open&&item.sameSession();}
    function message(item,text) {
      if(!current(item))return;
      const target=dialog.querySelector('[role="alert"]');
      target.textContent=text;target.hidden=false;target.focus();
    }
    function expire(item) {
      if(!current(item)||item.expired)return;
      item.csrf="";item.expired=true;
      dialog.querySelector("form")?.reset();
      dialog.innerHTML=frame('<div class="dialog-body"><p class="error" role="alert" tabindex="-1"></p></div>');
      message(item,"This setup attempt has expired. Close this window and request a new enrollment code from your operator.");
    }
    function frame(body) {
      return `<div class="dialog-header"><div><h2 id="enrollment-title">Set up your account</h2><p>Choose a password and connect your authenticator.</p></div><button class="button" type="button" data-enrollment-close>Close</button></div>${body}`;
    }
    function open(username="") {
      close();
      view={sameSession:captureSession(),csrf:"",username:"",busy:false};
      dialog.innerHTML=frame(`<form id="enrollment-start-form"><div class="dialog-body"><p class="dialog-copy">Use the private enrollment code supplied by your operator. For account recovery, contact your operator to verify your identity and receive a new code.</p><div class="error" role="alert" tabindex="-1" hidden></div><label class="field"><span>Username</span><input name="username" value="${e(username)}" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required></label><label class="field"><span>Enrollment code</span><input name="enrollment_secret" type="password" autocomplete="off" maxlength="128" required></label><p class="field-hint">The code expires after 24 hours and starts one setup attempt. Allow ten minutes to finish. Closing or reloading after you start requires a new code from your operator.</p></div><div class="dialog-footer"><button class="button primary" type="submit">Start account setup</button></div></form>`);
      dialog.showModal();dialog.querySelector("input")?.focus();
    }
    function showSetup(item,data) {
      if(typeof data.csrf!=="string"||typeof data.secret!=="string"||typeof data.username!=="string"||
          !Number.isFinite(data.expires_at)||data.expires_at*1000<=Date.now()) {
        throw new Error("Setup could not be confirmed. Request a new enrollment code from your operator.");
      }
      item.csrf=data.csrf;item.username=data.username;item.expiresAt=data.expires_at*1000;
      dialog.innerHTML=frame(`<form id="enrollment-complete-form"><div class="dialog-body"><p class="dialog-copy">Setting up <strong>${e(data.username)}</strong>. In your authenticator, add a time-based account named Westbridge and enter this setup key.</p><div class="error" role="alert" tabindex="-1" hidden></div><label class="field"><span>Authenticator setup key</span><input name="setup_key" value="${e(data.secret)}" readonly autocomplete="off" spellcheck="false"></label><p class="field-hint">Keep the key private. Anyone with a copy can generate your codes. Use six-digit codes that change every 30 seconds.</p><label class="field"><span>New password</span><input name="new_password" aria-label="New password" aria-describedby="enrollment-password-hint" type="password" autocomplete="new-password" minlength="15" maxlength="128" required><small id="enrollment-password-hint">Use 15–128 characters. A password manager can generate one. Choose a new password distinct from the enrollment code and your previous password.</small></label><label class="field"><span>Confirm new password</span><input name="confirm_password" type="password" autocomplete="new-password" minlength="15" maxlength="128" required></label><label class="field"><span>Authenticator code</span><input name="otp" aria-label="Authenticator code" aria-describedby="enrollment-code-hint" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required><small id="enrollment-code-hint">Enter the current code from your newly configured authenticator.</small></label><p class="field-hint">Setup expires at ${e(new Date(data.expires_at*1000).toLocaleTimeString())}. Finishing replaces your sign-in details and signs out existing sessions. You will then sign in with your new password and a new authenticator code.</p></div><div class="dialog-footer"><button class="button primary" type="submit">Finish account setup</button></div></form>`);
      expiryTimer=setTimeout(()=>expire(item),Math.max(0,item.expiresAt-Date.now()));
      dialog.querySelector('[name="new_password"]').focus();
    }
    async function send(path,body,csrf) {
      const headers={"Content-Type":"application/json","Accept":"application/json"};
      if(csrf)headers["X-Enrollment-CSRF"]=csrf;
      let response,data;
      try {
        response=await fetch(path,{method:"POST",headers,credentials:"same-origin",cache:"no-store",body:JSON.stringify(body)});
        data=await response.json();
      } catch (_) {
        throw new Error("The setup result could not be confirmed. If you submitted the final step, try signing in with the new password and a new code. Otherwise request a new enrollment code from your operator.");
      }
      if(!response.ok)throw new Error(typeof data.detail==="string"?data.detail:"Account setup could not be completed.");
      return data;
    }
    dialog.addEventListener("submit",async event=>{
      event.preventDefault();
      const item=view,form=event.target;
      if(!item||!current(item)||item.busy)return;
      const values=new FormData(form),finishing=form.id==="enrollment-complete-form";
      const body=finishing?{new_password:String(values.get("new_password")||""),otp:String(values.get("otp")||"")}:
        {username:String(values.get("username")||"").trim(),enrollment_secret:String(values.get("enrollment_secret")||"")};
      try {
        if(finishing&&body.new_password!==values.get("confirm_password"))throw new Error("The new passwords do not match.");
        item.busy=true;
        form.querySelectorAll("input,button").forEach(control=>{control.disabled=true;});
        dialog.querySelector('[role="alert"]').hidden=true;
        const data=await send(finishing?"/api/enrollment/complete":"/api/enrollment/start",body,item.csrf);
        // Keep observing a committed completion after Close, but never displace
        // a newer signed-in account or rotated session in this tab.
        if(finishing) {
          if(data.ok!==true||data.sign_in_required!==true)throw new Error("Setup could not be confirmed. Try signing in with your new details before requesting recovery.");
          if(item.sameSession()&&(view===item||view===null))completed(item.username);
        } else if(current(item))showSetup(item,data);
        if(data&&typeof data==="object"){data.secret="";data.uri="";data.csrf="";}
      } catch(error) {message(item,error.message);}
      finally {
        for(const key of Object.keys(body))body[key]="";
        for(const key of [...values.keys()])values.delete(key);
        item.busy=false;
        if(current(item)&&form.isConnected)form.querySelectorAll("input,button").forEach(control=>{control.disabled=false;});
        if(item.expiresAt<=Date.now())expire(item);
      }
    });
    dialog.addEventListener("click",event=>{if(event.target.closest("[data-enrollment-close]"))close();});
    dialog.addEventListener("cancel",event=>{event.preventDefault();close();});
    dialog.addEventListener("close",()=>{if(!dialog.open)close();});
    window.addEventListener("pagehide",close);
    return {open,close};
  }
  return {create};
})();
