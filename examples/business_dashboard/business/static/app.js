"use strict";

const app = document.querySelector("#app");
const editor = document.querySelector("#editor");
const toastElement = document.querySelector("#toast");
const state = { user: null, csrf: "", frozen: false, freeze_revision: 0, page: "", guest: false, submissionReceipt: false, data: {} };
let navigation = 0;
let dialogState = null;
let toastTimer;
let turnstileScript;
let turnstileLoadSequence=0;
let submissionChallenge = null;
const sessionDialog=document.createElement("dialog");
sessionDialog.id="session-dialog";sessionDialog.setAttribute("aria-labelledby","session-dialog-title");
const verificationDialog=document.createElement("dialog");
verificationDialog.id="verification-dialog";verificationDialog.setAttribute("aria-labelledby","verification-dialog-title");
const passkeyDialog=document.createElement("dialog");
passkeyDialog.id="passkey-dialog";passkeyDialog.setAttribute("aria-labelledby","passkey-dialog-title");
document.body.append(sessionDialog,verificationDialog,passkeyDialog);
let sessionView=null,verificationView=null,passkeyView=null,passkeyLogin=null;
const BOARD_POLL_MS = 10000;
let boardTimer;
let boardRequest = null;
let boardGeneration = 0;
let boardRetryDelay = BOARD_POLL_MS;
const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const paths = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18M8 15h2M14 15h2"/>',
  message: '<path d="M21 11.5a8.4 8.4 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.7A8.4 8.4 0 0 1 4 11.5a8.5 8.5 0 0 1 4.7-7.6 8.4 8.4 0 0 1 3.8-.9h.5a8.5 8.5 0 0 1 8 8v.5z"/><path d="M8 10h9M8 14h6"/>',
  outreach: '<path d="m21 3-6.5 18-4-7.5L3 9.5 21 3zM21 3 10.5 13.5"/>',
  board: '<path d="m3 11 18-6v14L3 13v-2zM7 14v6h4l-2-5M21 9h1M21 15h1"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5M6.1 7a7 7 0 0 1 11.6-1l2.3 3M4 15l2.3 3A7 7 0 0 0 18 17"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  location: '<path d="M20 10c0 6-8 11-8 11S4 16 4 10a8 8 0 0 1 16 0z"/><circle cx="12" cy="10" r="2.5"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/><circle cx="9" cy="7" r="4"/>',
  money: '<rect x="2" y="5" width="20" height="14" rx="2"/><circle cx="12" cy="12" r="3"/><path d="M6 12h.01M18 12h.01"/>',
  trend: '<path d="m3 17 6-6 4 4 8-11M15 4h6v6"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  settings: '<path d="M4 7h16M4 17h16"/><circle cx="8" cy="7" r="3" fill="currentColor" stroke="none"/><circle cx="16" cy="17" r="3" fill="currentColor" stroke="none"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3z"/><path d="m8 12 3 3 5-6"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',
};
const icon = (name, extra = "") => `<svg class="icon ${extra}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.grid}</svg>`;
const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const e = escapeHTML;
const isAdmin = () => state.user?.role === "admin";
const money = (value) => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(Number(value) || 0);
const number = (value) => new Intl.NumberFormat("en-US", {maximumFractionDigits: 1}).format(Number(value) || 0);
const date = (value, options = {}) => value ? new Date(value).toLocaleDateString("en-US", options) : "Not published";
const time = (value) => new Date(value).toLocaleTimeString("en-US", {hour: "numeric", minute: "2-digit"});
const stamp = (value) => value ? `${date(value, {month:"short",day:"numeric"})} at ${time(value)}` : "Not published";
const initials = (name) => String(name || "W").trim().split(/\s+/).slice(0, 2).map(part => part[0] || "").join("").toUpperCase();
const avatar = (name, extra = "") => `<span class="avatar ${extra}" aria-hidden="true">${e(initials(name))}</span>`;
const mark = () => '<span class="brand-mark" aria-hidden="true"><svg width="23" height="23" viewBox="0 0 28 28" fill="none"><path d="m3 6 5 16 6-12 6 12 5-16" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg></span>';
const brand = () => `<div class="brand-lockup">${mark()}<span class="brand-word">Westbridge<span class="brand-dot">.</span></span></div>`;
const disabled = () => state.frozen ? " disabled" : "";
const roleName = () => isAdmin() ? "Administrator" : "Employee";
const empty = (title, body, name = "calendar") => `<div class="empty">${icon(name)}<strong>${e(title)}</strong><p>${e(body)}</p></div>`;

async function api(path, method = "GET", body, options = {}) {
  const headers = { "Accept": "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && state.csrf) headers["X-CSRF-Token"] = state.csrf;
  if (options.idempotencyKey) headers["Idempotency-Key"] = options.idempotencyKey;
  if (options.passkeyCsrf) headers["X-Passkey-CSRF"] = options.passkeyCsrf;
  let response;
  try {
    response = await fetch(path, {method, headers, credentials:"same-origin", cache:"no-store", signal:options.signal, ...(body === undefined ? {} : {body:JSON.stringify(body)})});
  } catch (error) {
    if(error.name === "AbortError")throw error;
    throw new Error(method === "GET" ? "Unable to reach the workspace. Check your connection and try again." : "The save could not be confirmed. Check your connection, then refresh and check the saved records before submitting again.");
  }
  let data;
  try {data=await response.json();}
  catch(error) {
    if(error.name === "AbortError")throw error;
    if(response.ok)throw new Error(method === "GET" ? "The workspace reply could not be read. Refresh and try again." : "The save could not be confirmed. Refresh and check the saved records before submitting again.");
    data={};
  }
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "This request could not be completed. Check your entries and try again.";
    const error = new Error(detail); error.status = response.status;
    error.retryAfter = Number(response.headers.get("Retry-After")) || 0;
    error.reauthenticationRequired=response.headers.get("X-Reauthentication-Required")==="true";
    throw error;
  }
  return data;
}

const CREATE_RETRIES_STORAGE="westbridge.create-retries.v1";
const CREATE_RETRY_MS=23*60*60*1000;
const CREATE_IN_FLIGHT=new Map();
function readCreateRetries() {
  try {
    const raw=sessionStorage.getItem(CREATE_RETRIES_STORAGE);
    if(raw && raw.length>100000)throw new Error();
    const entries=raw?JSON.parse(raw):[];
    if(!Array.isArray(entries)||entries.length>256||entries.some(item=>
      !item || !/^[a-f0-9]{64}$/.test(item.fingerprint) ||
      !/^[a-f0-9-]{36}$/.test(item.key) || !Number.isFinite(item.created)))throw new Error();
    return entries;
  } catch {
    throw new Error("Safe saving is unavailable. Allow site storage or use another browser, then try again.");
  }
}
function writeCreateRetries(entries) {
  try {sessionStorage.setItem(CREATE_RETRIES_STORAGE,JSON.stringify(entries));}
  catch {throw new Error("Safe saving is unavailable. Allow site storage or use another browser, then try again.");}
}
async function createRecord(form,path,body,field) {
  const account=state.user?.id,csrf=state.csrf;
  const ownsSession=()=>state.user?.id===account&&state.csrf===csrf;
  // Store only opaque retry keys and fingerprints, never form text or passwords.
  // This per-tab record survives refreshes; it is not a saved business draft.
  const bytes=new TextEncoder().encode(JSON.stringify([account,path,body]));
  const digest=await crypto.subtle.digest("SHA-256",bytes);
  if(!ownsSession())throw new Error("Your sign-in changed. Refresh before saving.");
  const fingerprint=Array.from(new Uint8Array(digest),value=>value.toString(16).padStart(2,"0")).join("");
  let pending=CREATE_IN_FLIGHT.get(fingerprint);
  if(pending && pending.csrf!==csrf)throw new Error("A save from your previous sign-in is still waiting for a reply. Keep these details unchanged and try again after it finishes.");
  const entries=readCreateRetries();
  let entry=pending?.entry || entries.find(item=>item.fingerprint===fingerprint);
  if(entry && (Date.now()-entry.created>=CREATE_RETRY_MS || entry.created>Date.now())) {
    if(!form.querySelector("[data-expired-retry]")) {
      const separate=document.createElement("button");
      separate.type="button";separate.className="button";separate.dataset.expiredRetry="true";
      separate.textContent="I checked the records — start a separate save";
      separate.addEventListener("click",()=>{
        try {
          writeCreateRetries(readCreateRetries().filter(item=>item.fingerprint!==fingerprint));
          separate.remove();toast("You can now submit a separate save.");
        } catch(error) {errorAt(error,form.querySelector('[role="alert"]'));}
      });
      form.querySelector('[role="alert"]').after(separate);
    }
    throw new Error("This save is too old to retry safely. Check whether it already exists before starting a separate save.");
  }
  if(!entry) {
    if(entries.length>=256)throw new Error("There are too many unconfirmed saves in this tab. Check saved records before clearing this site's storage and trying again.");
    entry={fingerprint,key:crypto.randomUUID(),created:Date.now()};
    entries.push(entry);writeCreateRetries(entries);
  }
  if(!pending) {
    // Reopened forms can submit the same intent while an earlier reply is still
    // outstanding. Share that reply so one caller cannot erase another's key.
    pending={csrf,entry,promise:null};
    pending.promise=(async()=>{
      try {
        const result=await api(path,"POST",body,{idempotencyKey:entry.key});
        if(typeof result?.[field]?.id!=="string")throw new Error("The save reply could not be confirmed. Keep these details unchanged and try again.");
        return result;
      } catch(error) {
        if(!error.status || (error.status>=500 && error.status!==507))error.message="The save could not be confirmed. Keep these details unchanged and submit again in this tab to check the same save.";
        if(error.status===429 && error.retryAfter)error.message+=` Try again in ${Math.ceil(error.retryAfter)} seconds.`;
        throw error;
      }
    })();
    CREATE_IN_FLIGHT.set(fingerprint,pending);
  }
  let result;
  try {result=await pending.promise;}
  finally {
    if(CREATE_IN_FLIGHT.get(fingerprint)===pending)CREATE_IN_FLIGHT.delete(fingerprint);
  }
  // A confirmed write stays a success even if browser storage becomes blocked
  // afterwards. Keep its key when the submitted form cannot acknowledge it:
  // returning to those unchanged details must retrieve the same saved record.
  if(ownsSession() && form.isConnected && (form.id!=="dialog-form" || (editor.open && editor.contains(form)))) {
    try {writeCreateRetries(readCreateRetries().filter(item=>item.key!==entry.key));}
    catch {toast("Saved. This browser could not clear the retry record; check saved records before posting identical details again.");}
  }
  return result;
}

function publicBoardActive() {
  return state.page === "public" && !isAdmin() && Boolean(document.querySelector("#public-board-content"));
}

function boardStatus(message, status = "live") {
  const element = document.querySelector("#board-status");
  if(element) {element.textContent = message; element.dataset.state = status;}
}

function stopBoardUpdates() {
  boardGeneration++;
  clearTimeout(boardTimer);
  const request = boardRequest;
  boardRequest = null;
  request?.abort();
}

function scheduleBoardUpdate(delay = BOARD_POLL_MS) {
  clearTimeout(boardTimer);
  if(publicBoardActive() && !document.hidden && navigator.onLine) {
    boardTimer = setTimeout(refreshPublicBoard, delay);
  }
}

function startBoardUpdates(immediate = false) {
  stopBoardUpdates();
  boardRetryDelay = BOARD_POLL_MS;
  if(!publicBoardActive())return;
  if(!navigator.onLine) {boardStatus("Offline. Showing previously loaded posts.", "offline");return;}
  if(document.hidden)return;
  scheduleBoardUpdate(immediate ? 0 : BOARD_POLL_MS);
}

async function refreshPublicBoard() {
  clearTimeout(boardTimer);
  if(!publicBoardActive() || document.hidden || !navigator.onLine || boardRequest)return;
  const generation = boardGeneration;
  const request = new AbortController();
  boardRequest = request;
  const timeout = setTimeout(() => request.abort(), 12000);
  try {
    // Public reads never authenticate or extend a staff session's idle timeout.
    const data = await api("/api/public/posts", "GET", undefined, {signal:request.signal});
    if(generation !== boardGeneration || !publicBoardActive())return;
    if(!Array.isArray(data.posts) || typeof data.accepting_submissions !== "boolean")throw new Error("The board response was incomplete.");
    if(JSON.stringify(data) !== JSON.stringify(state.data)) {
      const region = document.querySelector("#public-board-content");
      const content = renderPublicContent(data);
      region.innerHTML = content;
      state.data = data;
      const submit = document.querySelector('[data-action="submission-new"]');
      if(submit)submit.disabled = data.accepting_submissions !== true;
      updateSubmissionButton();
    }
    boardRetryDelay = BOARD_POLL_MS;
    boardStatus("Updates automatically every 10 seconds.");
  } catch(error) {
    if(generation !== boardGeneration || !publicBoardActive())return;
    boardRetryDelay = Math.max(Math.min(boardRetryDelay * 2, 60000), Math.min(error.retryAfter * 1000 || 0, 300000));
    boardStatus("Updates delayed. Showing previously loaded posts; retrying automatically.", "retrying");
  } finally {
    clearTimeout(timeout);
    if(boardRequest === request)boardRequest = null;
    if(generation === boardGeneration)scheduleBoardUpdate(boardRetryDelay);
  }
}

document.addEventListener("visibilitychange", () => startBoardUpdates(true));
window.addEventListener("online", () => startBoardUpdates(true));
window.addEventListener("offline", () => startBoardUpdates());
window.addEventListener("pagehide", stopBoardUpdates);
window.addEventListener("pageshow", event => {if(event.persisted)startBoardUpdates(true);});

function setSession(session) {
  if(state.user?.id!==session.user?.id || state.csrf!==(session.csrf||""))closeSecurityDialogs();
  state.user = session.user || null;
  state.csrf = session.csrf || "";
  state.frozen = Boolean(session.frozen);
  state.freeze_revision = session.freeze_revision ?? 0;
}

function toast(message) {
  clearTimeout(toastTimer);
  toastElement.textContent = message;
  toastElement.hidden = false;
  toastTimer = setTimeout(() => {toastElement.hidden = true;}, 5000);
}

function errorAt(error, target) {
  if (error.status === 401 && state.user) {
    setSession({}); state.data = {}; state.guest = false; editor.close(); renderLogin();
    const loginError = document.querySelector("#login-error");
    loginError.textContent = "Your session has ended. Sign in again to continue.";
    loginError.hidden = false;
    return;
  }
  if (target) {target.textContent = error.message; target.hidden = false; target.focus();}
  else toast(error.message);
  if(error.reauthenticationRequired && state.user)openVerification(target);
}

function securityOwner() {
  const account=state.user?.id,csrf=state.csrf,ticket=navigation;
  return ()=>Boolean(account)&&state.user?.id===account&&state.csrf===csrf&&navigation===ticket;
}

function closeVerification() {
  verificationView?.controller?.abort();
  verificationView=null;
  verificationDialog.querySelector("form")?.reset();
  verificationDialog.close();verificationDialog.replaceChildren();
}

function closeSecurityDialogs() {
  closeVerification();sessionView=null;
  sessionDialog.close();sessionDialog.replaceChildren();
  passkeyView?.controller?.abort();passkeyView=null;
  passkeyDialog.close();passkeyDialog.replaceChildren();
  passkeyLogin?.controller.abort();passkeyLogin=null;
}

verificationDialog.addEventListener("close",()=>{if(!verificationDialog.open)closeVerification();});
sessionDialog.addEventListener("close",()=>{if(!sessionDialog.open){sessionView=null;sessionDialog.replaceChildren();}});
passkeyDialog.addEventListener("close",()=>{if(!passkeyDialog.open){passkeyView?.controller?.abort();passkeyView=null;passkeyDialog.replaceChildren();}});

function openVerification(target=null) {
  if(!state.user)return;
  closeVerification();
  const view={owns:securityOwner(),target};verificationView=view;
  verificationDialog.innerHTML=`<div class="dialog-header"><div><h2 id="verification-dialog-title">Verify your identity</h2><p>Confirm your identity to continue with sensitive changes. Your draft stays open.</p></div><button class="icon-button" data-action="verification-close" aria-label="Close identity verification">${icon("close")}</button></div><form id="verification-form"><div class="dialog-body"><p class="dialog-copy">Verification lasts five minutes. After it succeeds, choose your original action again. Nothing is saved automatically.</p><div class="error" role="alert" tabindex="-1" hidden></div><label class="field"><span>Current password</span><input type="password" name="current_password" autocomplete="current-password" maxlength="128" required></label>${isAdmin()?'<label class="field"><span>Authenticator code</span><input name="otp" aria-label="Authenticator code" aria-describedby="fresh-code-hint" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required><small id="fresh-code-hint">Use a fresh code. A code accepted at sign-in cannot be used again.</small></label>':""}</div><div class="dialog-footer"><button type="button" class="button" data-action="verification-close">Cancel verification</button><button type="submit" class="button primary">Verify identity</button></div></form>`;
  verificationDialog.showModal();verificationDialog.querySelector("input")?.focus();
  const passkeyButton=document.createElement("button");
  passkeyButton.type="button";passkeyButton.className="button";passkeyButton.dataset.action="verification-passkey";
  passkeyButton.textContent="Use a passkey instead";verificationDialog.querySelector(".dialog-body").prepend(passkeyButton);
}

function passkeysSupported() {return window.isSecureContext&&Boolean(window.PublicKeyCredential&&navigator.credentials);}
function passkeyBytes(value) {return Uint8Array.from(atob(value.replace(/-/g,"+").replace(/_/g,"/")),char=>char.charCodeAt(0));}
function passkeyBase64(value) {return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");}
function passkeyOptions(options,create) {
  const parse=create?PublicKeyCredential.parseCreationOptionsFromJSON:PublicKeyCredential.parseRequestOptionsFromJSON;
  if(parse)return parse.call(PublicKeyCredential,options);
  const result={...options,challenge:passkeyBytes(options.challenge)};
  if(create)result.user={...options.user,id:passkeyBytes(options.user.id)};
  for(const field of ["allowCredentials","excludeCredentials"])if(options[field])result[field]=options[field].map(value=>({...value,id:passkeyBytes(value.id)}));
  return result;
}
function passkeyJSON(credential) {
  if(credential.toJSON)return credential.toJSON();
  const response={clientDataJSON:passkeyBase64(credential.response.clientDataJSON)};
  for(const field of ["attestationObject","authenticatorData","signature","userHandle"])
    if(credential.response[field])response[field]=passkeyBase64(credential.response[field]);
  if(credential.response.getTransports)response.transports=credential.response.getTransports();
  return {id:credential.id,rawId:passkeyBase64(credential.rawId),type:credential.type,response,
    authenticatorAttachment:credential.authenticatorAttachment,clientExtensionResults:credential.getClientExtensionResults()};
}
async function passkeyCeremony(endpoint,create,controller) {
  if(!passkeysSupported())throw new Error("Passkeys require a supported browser on HTTPS or this local demonstration.");
  const challenge=await api(endpoint+"/options","POST",{}, {signal:controller.signal});
  const publicKey=passkeyOptions(challenge.options,create);
  const credential=await navigator.credentials[create?"create":"get"]({publicKey,signal:controller.signal});
  if(!credential)throw new Error("The passkey request was not completed.");
  return {request_id:challenge.request_id,credential:passkeyJSON(credential),csrf:challenge.csrf};
}
function passkeyError(error) {
  if(error.name==="NotAllowedError"||error.name==="AbortError")return new Error("The passkey request was cancelled or could not be completed. Try again when you are ready.");
  if(error.name==="InvalidStateError")return new Error("This authenticator may already have a passkey for your account. Use that passkey or choose another authenticator.");
  return error;
}
function finishVerification(view) {
  const original=view.target;
  closeVerification();
  const message="Identity verified. Choose your original action again when you are ready.";
  if(original?.isConnected){original.textContent=message;original.hidden=false;original.focus();}
  toast(message);
  if(sessionView?.owns()&&sessionDialog.open)loadSessions(sessionView);
}
async function verifyWithPasskey(button) {
  const view=verificationView;
  if(!view||!view.owns()||view.busy||verificationDialog.querySelector("form")?.dataset.submitting==="true")return;
  const current=()=>verificationView===view&&view.owns()&&verificationDialog.open;
  view.busy=true;view.controller=new AbortController();
  const form=verificationDialog.querySelector("form"),controls=[...form.querySelectorAll("input,button:not([data-action=verification-close])")];
  form.reset();controls.forEach(control=>{control.disabled=true;});
  try {
    const {request_id,credential}=await passkeyCeremony("/api/security/passkeys/reauth",false,view.controller);
    if(!current())return;
    const result=await api("/api/security/passkeys/reauth/verify","POST",{request_id,credential},{signal:view.controller.signal});
    if(!current())return;
    if(result?.ok!==true)throw new Error("Passkey verification could not be confirmed. Try again.");
    finishVerification(view);
  } catch(error){if(current())errorAt(passkeyError(error),form.querySelector('[role="alert"]'));}
  finally {if(current()){view.busy=false;controls.forEach(control=>{control.disabled=false;});}}
}
async function signInWithPasskey(button) {
  if(state.user||passkeyLogin)return;
  const ticket=navigation,form=document.querySelector("#login-form"),controller=new AbortController();
  const operation={controller};passkeyLogin=operation;
  const current=()=>passkeyLogin===operation&&navigation===ticket&&!state.user&&form.isConnected;
  const controls=[...form.querySelectorAll("input,button")];controls.forEach(control=>{control.disabled=true;});
  form.reset();
  try {
    const {request_id,credential,csrf}=await passkeyCeremony("/api/passkeys/login",false,controller);
    if(!current())return;
    const session=await api("/api/passkeys/login/verify","POST",{request_id,credential},{signal:controller.signal,passkeyCsrf:csrf});
    if(!current())return;
    if(!session?.user||typeof session.csrf!=="string")throw new Error("Passkey sign-in could not be confirmed. Try again.");
    setSession(session);state.guest=false;await navigate(isAdmin()?"overview":"schedule");
  } catch(error){if(current())errorAt(passkeyError(error),form.querySelector('[role="alert"]'));}
  finally {if(current()){passkeyLogin=null;controls.forEach(control=>{control.disabled=false;});}}
}
async function loadPasskeys(view) {
  const sequence=view.sequence=(view.sequence||0)+1;
  try {
    const data=await api("/api/security/passkeys");
    if(passkeyView!==view||view.sequence!==sequence||!view.owns()||!passkeyDialog.open)return;
    if(!Array.isArray(data.passkeys))throw new Error("The passkey list could not be read. Refresh it before changing anything.");
    view.rows=data.passkeys;
    passkeyDialog.querySelector("#passkey-list").innerHTML=data.passkeys.map(row=>`<article class="session-card"><div><h3>${e(row.name)}</h3><p class="dialog-copy">Added ${e(sessionTime(row.created_at))}<br>Last used ${row.last_used_at?e(sessionTime(row.last_used_at)):"Not used yet"}</p></div><button class="button small danger" data-action="passkey-remove" data-id="${e(row.id)}">Remove passkey</button></article>`).join("")||'<p class="dialog-copy">No passkeys are registered for your account.</p>';
    passkeyDialog.querySelector("#passkey-status").textContent=`${data.passkeys.length} of ${data.max_credentials} passkeys registered for ${data.rp_id}.`;
  } catch(error){if(passkeyView===view&&view.sequence===sequence&&view.owns())errorAt(error,passkeyDialog.querySelector('[role="alert"]'));}
}
function openPasskeys() {
  if(!state.user)return;
  closeSecurityDialogs();
  const view={owns:securityOwner(),rows:[],busy:false};passkeyView=view;
  passkeyDialog.innerHTML=`<div class="dialog-header"><div><h2 id="passkey-dialog-title">Your passkeys</h2><p>Use your device's screen lock or a security key to sign in and verify sensitive changes.</p></div><button class="icon-button" data-action="passkeys-close" aria-label="Close passkeys">${icon("close")}</button></div><div class="dialog-body"><p class="dialog-copy">Keep another sign-in method available. Removing a passkey signs out sessions that used it. Removing it here does not delete the copy on your device.</p><div class="error" role="alert" tabindex="-1" hidden></div><p id="passkey-status" class="dialog-copy" role="status">Checking registered passkeys…</p><div id="passkey-list" class="session-list"></div><form id="passkey-register-form"><label class="field"><span>Passkey name</span><input name="name" maxlength="64" placeholder="For example, personal laptop" required autocomplete="off"></label><button type="submit" class="button primary">Add a passkey</button></form></div><div class="dialog-footer"><button class="button" data-action="passkeys-refresh">Refresh passkeys</button><button class="button" data-action="passkeys-close">Done</button></div>`;
  passkeyDialog.showModal();loadPasskeys(view);
}
document.addEventListener("submit",async(event)=>{
  if(event.target.id!=="passkey-register-form")return;
  event.preventDefault();
  const view=passkeyView,form=event.target;
  if(!view||view.busy||!view.owns())return;
  const current=()=>passkeyView===view&&view.owns()&&passkeyDialog.open;
  const name=new FormData(form).get("name").trim();
  view.busy=true;view.controller=new AbortController();
  const controls=[...passkeyDialog.querySelectorAll("input,button:not([data-action=passkeys-close])")];controls.forEach(control=>{control.disabled=true;});
  try {
    const {request_id,credential}=await passkeyCeremony("/api/security/passkeys/register",true,view.controller);
    if(!current())return;
    const result=await api("/api/security/passkeys/register/verify","POST",{request_id,credential,name},{signal:view.controller.signal});
    if(!current())return;
    if(result?.ok!==true)throw new Error("The passkey registration could not be confirmed. Refresh the list before trying again.");
    form.reset();toast("Your passkey is registered.");await loadPasskeys(view);
  } catch(error){if(current())errorAt(passkeyError(error),passkeyDialog.querySelector('[role="alert"]'));}
  finally{if(current()){view.busy=false;controls.forEach(control=>{control.disabled=false;});}}
});

function sessionTime(value) {
  return Number.isFinite(value)?new Date(value*1000).toLocaleString():"Unavailable";
}

async function loadSessions(view) {
  const sequence=view.sequence=(view.sequence||0)+1;
  try {
    const data=await api("/api/security/sessions");
    if(sessionView!==view||view.sequence!==sequence||!view.owns()||!sessionDialog.open)return;
    if(!Array.isArray(data.sessions)||data.sessions.some(row=>!/^[a-f0-9]{32}$/.test(row.id)))throw new Error("The session list could not be read. Refresh and try again.");
    view.rows=data.sessions;
    sessionDialog.querySelector("#session-list").innerHTML=data.sessions.map(row=>`<article class="session-card"><div><h3>${row.current?"This session":"Other session"}</h3><span class="badge ${row.current?"green":"gray"}">${e(row.method==="totp"?"Password + authenticator":row.method==="passkey"?"Passkey":"Password")}</span><dl><dt>Signed in</dt><dd>${e(sessionTime(row.created_at))}</dd><dt>Last active</dt><dd>${e(sessionTime(row.last_seen))}</dd><dt>Expires</dt><dd>${e(sessionTime(row.expires_at))}</dd></dl></div><button class="button small danger" data-action="session-revoke" data-id="${e(row.id)}">${row.current?"Sign out this session":"Sign out other session"}</button></article>`).join("")||'<p class="dialog-copy">No active sessions were returned.</p>';
    sessionDialog.querySelector("#session-status").textContent=data.verification_expires_at>Date.now()/1000?`Sensitive changes verified until ${sessionTime(data.verification_expires_at)}.`:"Fresh identity verification is required before signing out another session.";
  } catch(error) {
    if(sessionView===view&&view.sequence===sequence&&view.owns()&&sessionDialog.open)errorAt(error,sessionDialog.querySelector('[role="alert"]'));
  }
}

function openSessions() {
  if(!state.user)return;
  closeSecurityDialogs();
  const view={owns:securityOwner(),rows:[]};sessionView=view;
  sessionDialog.innerHTML=`<div class="dialog-header"><div><h2 id="session-dialog-title">Your active sessions</h2><p>Only sessions belonging to ${e(state.user.username)} are shown. Times use your device's time zone.</p></div><button class="icon-button" data-action="sessions-close" aria-label="Close sessions">${icon("close")}</button></div><div class="dialog-body"><div class="error" role="alert" tabindex="-1" hidden></div><p id="session-status" class="dialog-copy" role="status">Checking your sessions…</p><div id="session-list" class="session-list"></div></div><div class="dialog-footer"><button class="button" data-action="sessions-refresh">Refresh sessions</button><button class="button primary" data-action="sessions-close">Done</button></div>`;
  sessionDialog.showModal();loadSessions(view);
}

document.addEventListener("submit",async(event)=>{
  const form=event.target;
  if(form.id!=="verification-form")return;
  event.preventDefault();
  if(form.dataset.submitting==="true"||verificationView?.busy)return;
  const view=verificationView,values=new FormData(form);
  const current=()=>verificationView===view&&view?.owns()&&verificationDialog.open&&form.isConnected;
  const controls=[...form.querySelectorAll("input,button[type=submit],[data-action=verification-passkey]")];
  const target=form.querySelector('[role="alert"]');
  const body={current_password:values.get("current_password"),...(values.has("otp")?{otp:values.get("otp")}: {})};
  form.reset();form.dataset.submitting="true";controls.forEach(control=>{control.disabled=true;});target.hidden=true;
  try {
    const data=await api("/api/security/reauthenticate","POST",body);
    if(!current())return;
    if(data?.ok!==true)throw new Error("Verification could not be confirmed. Try again with a fresh code.");
    finishVerification(view);
  } catch(error) {
    if(current()) {
      // Incorrect credentials keep this form usable. Only an expired session
      // returns the whole workspace to sign-in.
      errorAt(error,target);
    }
  } finally {
    body.current_password="";if("otp" in body)body.otp="";
    values.delete("current_password");values.delete("otp");
    if(current()){form.reset();delete form.dataset.submitting;controls.forEach(control=>{control.disabled=false;});}
  }
});

function renderLogin() {
  closeSecurityDialogs();
  stopBoardUpdates();
  removeSubmissionChallenge();
  editor.close();editor.replaceChildren();dialogState=null;
  if(location.pathname === "/board" || location.hash === "#board")history.replaceState(null, "", "/");
  navigation++;
  state.page = "";
  state.submissionReceipt = false;
  document.title = "Sign in · Westbridge";
  app.innerHTML = `<main id="main" class="login">
    <section class="login-story" aria-label="Westbridge business workspace">
      ${brand()}
      <div class="story-main"><div class="story-kicker">A little more connected</div><h1>Good work starts<br>with <span>a clear picture.</span></h1><p>One place for your people, your plans, and the work that moves your business forward.</p>
        <div class="story-preview" aria-hidden="true"><div class="preview-head"><span>Your working day, together.</span><span>TEAM WORKSPACE</span></div><div class="preview-event"><span class="preview-time">09:00 AM</span><span class="preview-rule"></span><div><strong>Start with a shared plan</strong><small>Team schedules · Clear responsibilities</small></div></div><div class="preview-event"><span class="preview-time">11:30 AM</span><span class="preview-rule tan"></span><div><strong>Keep the conversation moving</strong><small>Company updates · Team messages</small></div></div><div class="preview-footer"><span>Built around the people doing the work.</span><div class="preview-avatars"><i>AM</i><i>BC</i><i>CR</i><i>+2</i></div></div></div>
      </div><div class="story-footer"><span>WESTBRIDGE BUSINESS GROUP</span><span>Clarity. Every working day.</span></div>
    </section>
    <section class="login-panel" aria-labelledby="login-heading"><div class="login-top">Your business, in good company.</div><div class="login-form-wrap"><div class="eyebrow">The team workspace</div><h2 id="login-heading">Welcome back.</h2><p>Sign in to pick up where your team left off.</p><form id="login-form" class="login-form"><div id="login-error" class="error" role="alert" tabindex="-1" hidden></div><label class="field"><span>Username</span><input name="username" id="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="64" placeholder="Your username"></label><label class="field"><span>Password</span><span class="password-wrap"><input name="password" id="password" type="password" autocomplete="current-password" required maxlength="128" placeholder="Your password"><button type="button" class="icon-button" data-action="toggle-password" aria-label="Show password" aria-pressed="false">${icon("eye")}</button></span></label><label class="field"><span>Authenticator code</span><input name="otp" aria-label="Authenticator code" type="text" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" autocomplete="one-time-code" aria-describedby="otp-hint" placeholder="6-digit code"><small id="otp-hint">Administrators use the code from their authenticator app. Employees can leave this blank.</small></label><button class="button primary" type="submit">Sign in ${icon("arrow")}</button></form><div class="login-separator">OR VISIT OUR PUBLIC BOARD</div><button class="button guest-button" data-action="guest">Continue as guest ${icon("arrow")}</button><p class="guest-caption">Company news and announcements. No account needed.</p></div><footer class="login-footer">© ${new Date().getFullYear()} Westbridge Business Group.<br>A place for good work.</footer></section>
  </main>`;
  const passkeyButton=document.createElement("button");passkeyButton.type="button";passkeyButton.className="button";
  passkeyButton.dataset.action="passkey-login";passkeyButton.textContent="Sign in with a passkey";
  document.querySelector("#login-form").append(passkeyButton);
}

const pages = {overview:{label:"Overview",icon:"grid"},schedule:{label:"Schedule",icon:"calendar"},messages:{label:"Team board",icon:"message"},outreach:{label:"Outreach",icon:"outreach"},public:{label:"Public board",icon:"board"},security:{label:"Security & recovery",icon:"shield"}};

function shell(content) {
  const title = pages[state.page]?.label || "Workspace";
  const guest = !state.user;
  const allowed = isAdmin() ? ["overview","schedule","messages","outreach","public","security"] : ["schedule","messages","public"];
  const sidebar = `<aside class="sidebar" id="sidebar" aria-label="Workspace navigation"><div class="row">${brand()}<button class="icon-button mobile-close" aria-label="Close navigation" data-action="menu-close">${icon("close")}</button></div><p class="workspace-label">Your workspace</p><nav>${allowed.map(key=>`<button class="nav-link${state.page===key?" active":""}" data-page="${key}"${state.page===key?' aria-current="page"':""}>${icon(pages[key].icon)}<span>${pages[key].label}</span></button>`).join("")}</nav><div class="sidebar-bottom"><div class="sidebar-note"><strong>Westbridge Business Group</strong>Good people. Thoughtful work.</div></div></aside>`;
  const header = guest ? `${brand()}<div class="row"><span class="guest-label">Public workspace</span><button class="button" data-action="signin">Team sign in ${icon("arrow")}</button></div>` : `<button class="icon-button mobile-menu" data-action="menu-open" aria-label="Open navigation" aria-expanded="false" aria-controls="sidebar">${icon("menu")}</button><div class="breadcrumb"><span>Workspace</span>${icon("chevron")}<strong>${e(title)}</strong></div><div class="topbar-actions"><span class="topbar-date">${e(date(new Date(),{weekday:"short",month:"short",day:"numeric",year:"numeric"}))}</span><button class="icon-button" data-action="refresh" aria-label="Refresh workspace" title="Refresh workspace">${icon("refresh")}</button><span class="header-divider"></span><button class="user-control" data-action="profile" aria-label="Your profile">${avatar(state.user.name)}<span class="user-text"><strong>${e(state.user.name)}</strong><small>${roleName()}</small></span></button><button class="icon-button" data-action="logout" aria-label="Sign out" title="Sign out">${icon("logout")}</button></div>`;
  app.innerHTML = `<div class="workspace${guest?" guest-workspace":""}">${guest?"":sidebar}<div class="workspace-main"><header class="topbar">${header}</header><main id="main" class="content">${!guest && state.frozen ? `<div class="notice frozen-banner" role="status">${icon("lock")}<span>Workspace changes are paused. You can continue to view schedules, messages, and updates.${isAdmin()?" You can still unpublish posts and pause employee access.":""}</span></div>`:""}${content}<footer class="workspace-footer"><span>© ${new Date().getFullYear()} Westbridge Business Group</span><span>${guest?"Company news & community":"A clearer view of your working day."}</span></footer></main></div></div>`;
  document.title = `${title} · Westbridge`;
}

function heading(eyebrow, title, description, action = "", extra = "") {
  return `<div class="page-heading ${e(extra)}"><div><div class="eyebrow">${e(eyebrow)}</div><h1>${e(title)}</h1><p>${e(description)}</p></div><div class="page-actions">${action}</div></div>`;
}

async function navigate(page, options = {}) {
  closeSecurityDialogs();
  stopBoardUpdates();
  const ticket = ++navigation;
  if (!Object.hasOwn(pages,page)) page = isAdmin() ? "overview" : "schedule";
  if (!state.user && page !== "public") {renderLogin(); return;}
  if (state.user && !isAdmin() && ["overview","outreach","security"].includes(page)) page = "schedule";
  state.page = page;
  shell(heading("Workspace", pages[page].label, "") + '<div class="panel empty" role="status" aria-busy="true">Loading your workspace…</div>');
  try {
    let data;
    if (page === "overview") {
      const [overview,schedule,users] = await Promise.all([api("/api/admin/overview"),api("/api/schedule"),api("/api/admin/users")]);
      data = {...overview,...schedule,...users};
    } else if (page === "schedule") data = await api("/api/schedule");
    else if (page === "messages") data = await api("/api/messages");
    else if (page === "outreach") data = await api("/api/admin/contacts");
    else if (page === "security") {
      data = await api("/api/session");
      if (ticket !== navigation) return;
      if (!data.user) {const error=new Error("Your session has ended.");error.status=401;throw error;}
      setSession(data);
      if (!isAdmin()) {await navigate("schedule");return;}
    }
    else if (isAdmin()) {
      const [posts,submissions] = await Promise.all([api("/api/admin/posts"),api("/api/admin/submissions")]);
      data = {...posts,...submissions};
    } else data = await api("/api/public/posts");
    if (ticket !== navigation) return;
    state.data = data;
    if (data.frozen !== undefined) {state.frozen=Boolean(data.frozen);state.freeze_revision=data.freeze_revision;}
    const render = {overview:renderOverview,schedule:renderSchedule,messages:renderMessages,outreach:renderOutreach,public:renderPublic,security:renderSecurity};
    shell(render[page](data));
    history.replaceState(null, "", page === "public" ? "/board" : "/");
    if(page === "public")startBoardUpdates();
    const pageTitle = document.querySelector("#main h1");
    pageTitle?.setAttribute("tabindex", "-1");
    pageTitle?.focus({preventScroll:true});
    if (!options.keepScroll) window.scrollTo({top:0,behavior:"instant"});
  } catch (error) {
    if (ticket !== navigation) return;
    if (error.status === 401) {errorAt(error); return;}
    shell(heading("Workspace",pages[page].label,"")+`<div class="panel"><div class="empty"><strong>We couldn’t load this page.</strong><p>${e(error.message)}</p><button class="button" data-action="refresh">Try again ${icon("refresh")}</button></div></div>`);
  }
}

function financialChart(rows) {
  if (!rows.length) return empty("No financial figures yet", "Monthly figures will appear here.", "trend");
  const maximum = Math.max(1,...rows.flatMap(row=>[Number(row.revenue)||0,Number(row.cost)||0]));
  const ceiling = Math.ceil(maximum / 10000) * 10000;
  const plotWidth = 480, top = 10, bottom = 180, height = bottom - top;
  const axis = Array.from({length:5},(_,index)=>{const y=top+index*height/4;return `<line x1="43" x2="535" y1="${y}" y2="${y}" class="chart-grid-line"/><text x="0" y="${y+3}" class="chart-svg-label">$${number(ceiling*(4-index)/4/1000)}k</text>`;}).join("");
  const bars=rows.map((row,index)=>{const step=plotWidth/rows.length;const center=52+step*(index+.5);const width=Math.min(22,step*.24);const revenue=Math.max(0,Number(row.revenue)||0)/ceiling*height;const cost=Math.max(0,Number(row.cost)||0)/ceiling*height;const month=String(row.month).slice(0,7);let label=month;const parsed=new Date(`${month}-15T12:00:00`);if(!Number.isNaN(parsed.valueOf()))label=date(parsed,{month:"short"});return `<g><title>${e(label)}: revenue ${e(money(row.revenue))}, costs ${e(money(row.cost))}</title><rect x="${center-width-2}" y="${bottom-revenue}" width="${width}" height="${revenue}" rx="3" class="chart-revenue"/><rect x="${center+2}" y="${bottom-cost}" width="${width}" height="${cost}" rx="3" class="chart-cost"/><text x="${center}" y="203" text-anchor="middle" class="chart-svg-label">${e(label)}</text></g>`;}).join("");
  return `<svg class="revenue-chart" viewBox="0 0 545 213" role="img" aria-labelledby="financial-chart-title"><title id="financial-chart-title">Sample financials: monthly revenue and costs. Exact amounts follow in the accessible table.</title>${axis}${bars}</svg><table class="sr-only"><caption>Sample financials</caption><thead><tr><th>Month</th><th>Revenue</th><th>Costs</th></tr></thead><tbody>${rows.map(row=>`<tr><th>${e(row.month)}</th><td>${e(money(row.revenue))}</td><td>${e(money(row.cost))}</td></tr>`).join("")}</tbody></table>`;
}

function renderOverview(data) {
  const metrics = data.metrics;
  const nextEvents = (data.events || []).filter(event=>new Date(event.ends_at)>=new Date()).sort((a,b)=>a.starts_at.localeCompare(b.starts_at)).slice(0,3);
  const team = (data.users || []).filter(user=>user.role === "employee");
  const activity = (data.activity || []).slice(0,4);
  const firstName=state.user.name.split(" ")[0];
  const metric=(label,value,note,name)=>`<div class="panel metric"><div class="metric-label">${e(label)}${icon(name)}</div><div class="metric-value">${e(value)}</div><div class="metric-note">${note}</div></div>`;
  return heading("Business at a glance",`A clear view, ${firstName}.`,"Your people, your plans, and the progress behind them.",'<span class="section-label"><span class="status-dot"></span>Workspace overview</span>')+
    `<section class="quick-actions" aria-label="Workspace quick actions"><button class="quick-action" aria-label="Plan an event" data-action="event-new"${disabled()}>${icon("calendar")}<span><strong>Plan an event</strong><small>Bring your team together</small></span>${icon("plus")}</button><button class="quick-action" aria-label="Add a contact" data-action="contact-new"${disabled()}>${icon("outreach")}<span><strong>Add a contact</strong><small>Keep an opportunity moving</small></span>${icon("plus")}</button><button class="quick-action" aria-label="Review public posts" data-page="public">${icon("board")}<span><strong>Review public posts</strong><small>See what your community shares</small></span>${icon("arrow")}</button><button class="quick-action" aria-label="Open recovery guide" data-page="security">${icon("shield")}<span><strong>Open recovery guide</strong><small>Keep a private recovery copy</small></span>${icon("arrow")}</button></section>`+
    `<section class="metrics" aria-label="Business metrics">${metric("Monthly revenue",money(metrics.monthly_revenue),"Sample financials · latest month","money")}${metric("Operating profit",money((metrics.monthly_revenue||0)-(metrics.monthly_cost||0)),"Sample revenue less sample costs","trend")}${metric("Open pipeline",money(metrics.pipeline_value),`<strong>${e(number(metrics.open_leads))}</strong> open opportunities`,"outreach")}${metric("Scheduled team-hours",number(metrics.scheduled_hours),"Upcoming work · all assignments","clock")}</section>
    <div class="overview-grid"><section class="panel chart-panel"><div class="panel-heading"><div><h2>Business performance</h2><p>Revenue and operating costs</p></div><div class="legend"><span><i></i>Revenue</span><span><i class="cost"></i>Costs</span></div></div><div class="panel-body">${financialChart(data.revenue || [])}<div class="chart-caption">${icon("info")}Sample financials · USD · illustrative figures</div></div></section>
    <section class="panel"><div class="panel-heading"><div><h2>Coming up next</h2><p>Ahead on the team calendar</p></div>${icon("calendar")}</div><div class="panel-body">${nextEvents.length?nextEvents.map(event=>`<div class="agenda-item"><div class="date-tile"><span>${e(date(event.starts_at,{month:"short"}))}</span><strong>${e(date(event.starts_at,{day:"numeric"}))}</strong></div><div class="agenda-detail"><strong>${e(event.title)}</strong><p>${e(time(event.starts_at))} – ${e(time(event.ends_at))}${event.location?` · ${e(event.location)}`:""}</p></div></div>`).join(""):empty("A little room on the calendar","Add an event to plan your next working day.")}</div><div class="panel-footer"><span>${e(zone)}</span><button class="button subtle" data-page="schedule">View schedule ${icon("arrow")}</button></div></section>
    <section class="panel activity-panel"><div class="panel-heading"><div><h2>Recent activity</h2><p>The latest changes across your workspace</p></div><span class="badge gray">Activity log</span></div><div class="panel-body">${activity.length?activityRows(activity):empty("All set for a fresh start","Schedule and account changes appear here.","check")}</div><div class="panel-footer"><span>Up to 50 recent changes</span><button class="button subtle" data-action="activity">Explore recent activity ${icon("arrow")}</button></div></section>
    <section class="panel"><div class="panel-heading"><div><h2>Your team</h2><p>People with access to the workspace</p></div><span class="badge green">${team.filter(user=>user.active).length} active</span></div><div class="panel-body">${team.map(user=>`<div class="team-row">${avatar(user.name)}<div class="team-info"><strong>${e(user.name)}</strong><small>${user.active?"Employee":"Access paused"}</small></div><button class="button small subtle" data-action="user-toggle" data-id="${e(user.id)}" aria-label="${user.active?"Pause":"Restore"} access for ${e(user.name)}"${!user.active&&state.frozen?" disabled":""}>${user.active?"Pause access":"Restore access"}</button></div>`).join("")}</div></section></div>
    <section class="panel tools-panel"><div class="tools-content"><div class="tools-heading"><span class="tool-icon">${icon("settings")}</span><div class="tools-copy"><h2>Workspace controls</h2><p>Pause changes while you review the schedule and team activity.</p></div></div><button class="switch-control" role="switch" aria-checked="${state.frozen}" data-action="freeze"><span class="switch-track" aria-hidden="true"></span>Pause workspace changes</button></div></section>`;
}

function activityRows(rows) {
  return rows.map(item=>`<div class="activity-item"><span class="activity-dot">${icon("check")}</span><div class="activity-detail"><strong>${e(item.actor)}</strong> · ${e(String(item.action).replaceAll("_"," ").replaceAll("."," "))}${item.target?`<span> · ${e(item.target)}</span>`:""}<small>${e(date(item.created_at,{month:"short",day:"numeric",year:"numeric"}))} · ${e(time(item.created_at))}</small></div></div>`).join("");
}

function activityDialog() {
  const rows=(state.data.activity||[]).slice(0,50);
  openDialog("activity","Recent workspace activity","Search the latest 50 changes returned by this workspace. This is not a complete audit history.",
    `<label class="search-wrap activity-search">${icon("search")}<input type="search" id="activity-search" aria-label="Search recent activity" placeholder="Search people, actions, or records…" maxlength="200"></label><p id="activity-count" class="field-hint" role="status">${rows.length} of ${rows.length} recent changes</p><div id="activity-results">${rows.length?activityRows(rows):empty("No recent changes","Workspace activity will appear here.","clock")}</div>`,
    '<button type="button" class="button" data-action="dialog-close">Close activity</button>',rows);
}

function filterActivity() {
  if(dialogState?.type!=="activity"||!editor.open)return;
  const query=editor.querySelector("#activity-search").value.trim().toLowerCase();
  const rows=dialogState.record;
  const matching=rows.filter(item=>`${item.actor} ${item.action} ${String(item.action).replaceAll("_"," ").replaceAll("."," ")} ${item.target||""}`.toLowerCase().includes(query));
  editor.querySelector("#activity-count").textContent=`${matching.length} of ${rows.length} recent changes`;
  editor.querySelector("#activity-results").innerHTML=matching.length?activityRows(matching):empty("No matching activity","Try a person's name, an action, or a record name.","search");
}

function recoveryCommand(operation,platform) {
  const python=platform==="windows"?".\\.venv\\Scripts\\python.exe":".venv/bin/python";
  const commands={encrypt:'encrypt "PRIVATE_RECOVERY_SHEET" --output "PRIVATE_ENCRYPTED_COPY.age"',verify:'verify "PRIVATE_ENCRYPTED_COPY.age" --original "PRIVATE_RECOVERY_SHEET"',restore:'restore "PRIVATE_ENCRYPTED_COPY.age" --output "NEW_PRIVATE_RESTORED_SHEET"'};
  return `${python} -B examples/business_dashboard/recovery.py ${commands[operation]}`;
}

function renderSecurity() {
  const step=(operation,index,title,body)=>`<section class="recovery-step"><div class="recovery-step-heading"><span class="step-number" aria-hidden="true">${index}</span><h3>${title}</h3><button class="button small subtle" data-action="recovery-copy" data-command="${operation}" aria-label="Copy ${operation} command">Copy command</button></div><p>${body}</p><pre><code id="recovery-${operation}" tabindex="0">${e(recoveryCommand(operation,"windows"))}</code></pre></section>`;
  return heading("Security & recovery","Keep access in your hands.","Manage your sign-in and prepare a private recovery copy.",'<button class="button" data-action="sessions-open">Manage your sessions</button><button class="button" data-action="passkeys-open">Manage your passkeys</button>',"security-heading")+
    `<div class="security-status-grid"><section class="panel security-status"><span class="security-icon">${icon("shield")}</span><div><div class="eyebrow">Current session</div><h2>Signed in as ${e(state.user.name)}</h2><p>${e(state.user.username)} · Administrator<br>Authenticator verified for this session.</p><button class="button small" data-action="profile">Change password ${icon("arrow")}</button></div></section><section class="panel security-status"><span class="security-icon">${icon("settings")}</span><div><div class="eyebrow">Workspace editing</div><h2>${state.frozen?"Changes are paused":"Changes are enabled"}</h2><p>Pause routine edits while you review work. This does not sign people out.</p><button class="button small" data-action="freeze">${state.frozen?"Resume workspace changes":"Pause workspace changes"}</button></div></section></div>
    <section id="security-metrics" class="panel security-metrics" aria-labelledby="security-metrics-heading"><div class="panel-heading"><div><h2 id="security-metrics-heading">Security activity</h2><p>Decision counts for this running application instance. They reset on restart.</p></div><button class="button small" data-action="metrics-refresh">Load security activity</button></div><div class="panel-body"><p id="metrics-status" class="dialog-copy" role="status">Load a snapshot when you need it. This page does not poll in the background.</p><div id="metrics-error" class="error" role="alert" tabindex="-1" hidden></div><div id="metrics-counts"></div><p class="field-hint">One request can increment several counters. These counts are not request rates, unique visitors, an alert system, or a complete audit history.</p></div></section>
    <div class="recovery-layout"><section class="panel recovery-guide" aria-labelledby="recovery-heading"><div class="panel-heading"><div><div class="eyebrow">On your computer</div><h2 id="recovery-heading">Local recovery-file tool</h2><p>Encrypt a small recovery sheet with a separate passphrase.</p></div>${icon("lock")}</div><div class="recovery-intro"><p>Run these commands in a private terminal, from your source checkout, with its Python environment and the <a href="https://github.com/FiloSottile/age#installation" target="_blank" rel="noopener noreferrer">age tool installed</a>. Nothing runs when you copy a command.</p><p>Replace every quoted placeholder with a full path in a private folder <strong>outside Git repositories</strong>. The folder must already exist. Use a new output filename; the tool will not overwrite a file.</p><label class="recovery-platform"><span>Terminal platform</span><select id="recovery-platform" class="filter-select" aria-label="Terminal platform"><option value="windows">Windows PowerShell</option><option value="posix">macOS / Linux</option></select></label></div>
    ${step("encrypt","01","Make an encrypted copy","Age asks for a strong, unique passphrase in your terminal. Enter a nonempty passphrase and save it separately. The tool decrypts and compares the result before saving the encrypted copy; it keeps your original.")}
    ${step("verify","02","Check the copy you will keep","Use the actual encrypted copy in your backup location. Verification compares its decrypted contents with the original without writing another plaintext file. Keep the original until verification succeeds and the passphrase is safely saved.")}
    ${step("restore","03","Restore only when needed","Choose a new file in a private folder. Restoration writes a readable copy of the sheet; protect that copy afterward. It does not reset an account or enroll an authenticator.")}
    <div class="recovery-reference"><strong>Full setup and storage guidance</strong><p>Open <code>examples/business_dashboard/RECOVERY.md</code> in your checkout for folder permissions, installation, and recovery instructions.</p></div></section>
    <aside class="recovery-aside"><section class="panel recovery-note"><span class="security-icon">${icon("eye")}</span><h2>Stays on your computer</h2><p>This page is a guide. Your recovery file and passphrase stay in your local tool; this dashboard does not upload or collect them.</p><p class="recovery-scope">Recovery copies are managed on your computer. This dashboard cannot confirm whether you have one.</p></section><section class="panel recovery-note"><h2>What to keep separate</h2><ul><li>Your sign-in password</li><li>Your authenticator app</li><li>Your encrypted recovery copy and its passphrase</li></ul><p>Keep the recovery passphrase separate from the encrypted file. Losing it means this tool cannot recover that file.</p></section><section class="recovery-boundary"><h2>One part of recovery</h2><p>This tool protects small recovery files, up to 1 MiB. It does not encrypt the running database or replace application backups.</p><p>A copied authenticator setup QR or seed can generate valid codes. Treat it like a password.</p></section></aside></div>`;
}

const metricLabels=[
  ["Sign-in and password changes",{
    auth_lookup_started:"Account lookups started",auth_lookup_busy:"Account lookups denied at capacity",
    auth_known_started:"Known-account authentication jobs started",auth_known_busy:"Known-account authentication denied at capacity",
    auth_unknown_started:"Unknown-account authentication jobs started",auth_unknown_busy:"Unknown-account authentication denied at capacity",
    login_budget_denied:"Sign-ins denied by account attempt limit",login_reservation_expired:"Sign-in attempt reservations expired",
    login_identity_changed:"Sign-ins rejected after account changes",login_rejected:"Sign-in credentials rejected",login_succeeded:"Sign-ins completed",
    password_budget_denied:"Password changes denied by attempt limit",password_reservation_expired:"Password-change attempt reservations expired",
    password_identity_changed:"Password changes rejected after account changes",password_rejected:"Current passwords rejected",
    password_policy_rejected:"New password choices rejected",password_changed:"Passwords changed",
  }],
  ["Fresh identity verification",{
    reauth_started:"Verification jobs started",reauth_busy:"Verification denied at capacity",reauth_budget_denied:"Verification denied by attempt limit",
    reauth_rejected:"Verification credentials rejected",reauth_succeeded:"Verifications completed",reauth_identity_changed:"Verification rejected after account changes",
    reauth_reservation_expired:"Verification attempt reservations expired",
  }],
  ["Request intake",{body_capacity_denied:"Request bodies denied at capacity",body_timeout:"Request bodies timed out",body_oversized:"Oversized request bodies rejected"}],
  ["Passkeys",{
    passkey_options_started:"Passkey challenges requested",passkey_options_busy:"Passkey challenge work denied at capacity",
    passkey_verification_started:"Passkey verification jobs started",passkey_verification_busy:"Passkey verification denied at capacity",
    passkey_challenge_capacity_denied:"Passkey challenge storage full",passkey_credential_capacity_denied:"Passkey credential limit reached",
    passkey_rejected:"Passkey responses rejected",passkey_registered:"Passkeys registered",passkey_login_succeeded:"Passkey sign-ins completed",
    passkey_reauth_succeeded:"Fresh passkey verifications completed",passkey_removed:"Passkeys removed",
  }],
  ["Public submissions and team messages",{
    public_verification_started:"Public verification jobs started",public_verification_busy:"Public verification denied at capacity",
    public_verification_budget_denied:"Public verification denied by attempt limit",public_verification_rejected:"Public verification rejected",
    public_verification_unavailable:"Public verification provider unavailable",public_submission_quota_denied:"Public submissions denied by quota",
    public_submission_paused:"Public submissions denied while paused",public_submission_accepted:"Public submissions accepted for review",
    message_quota_denied:"Team messages denied by posting quota",message_capacity_denied:"Team messages denied at storage capacity",
  }],
];

async function refreshSecurityMetrics(button) {
  const owns=securityOwner(),region=document.querySelector("#security-metrics");
  if(!isAdmin()||state.page!=="security"||!region)return;
  const current=()=>owns()&&region.isConnected&&state.page==="security";
  button.disabled=true;region.querySelector("#metrics-error").hidden=true;
  try {
    const data=await api("/api/admin/security-metrics");
    if(!current())return;
    const started=new Date(data.started_at);
    if(data.scope!=="application_instance"||data.resets_on_restart!==true||!Number.isFinite(started.valueOf())||
       metricLabels.some(([,labels])=>Object.keys(labels).some(key=>!Number.isInteger(data.counters?.[key])||data.counters[key]<0)))throw new Error("The security activity snapshot could not be read. Try refreshing it.");
    const count=value=>value>=Number.MAX_SAFE_INTEGER?"At least 9,007,199,254,740,991":new Intl.NumberFormat("en-US").format(value);
    region.querySelector("#metrics-counts").innerHTML=metricLabels.map(([group,labels])=>`<details class="metric-group"><summary>${e(group)}</summary><dl>${Object.entries(labels).map(([key,label])=>`<div><dt>${e(label)}</dt><dd>${e(count(data.counters[key]))}</dd></div>`).join("")}</dl></details>`).join("");
    region.querySelector("#metrics-status").textContent=`Counts since ${started.toLocaleString()}. Snapshot loaded ${new Date().toLocaleTimeString()}; resets when this application instance restarts.`;
    button.textContent="Refresh security activity";
  } catch(error) {if(current())errorAt(error,region.querySelector("#metrics-error"));}
  finally {if(current())button.disabled=false;}
}

function renderSchedule(data) {
  const action=isAdmin()?`<button class="button primary" data-action="event-new"${disabled()}>${icon("plus")}Add event</button>`:"";
  return heading("Plans & people","The team schedule.","A shared plan for the days ahead.",action)+`<section class="panel"><div class="schedule-toolbar"><div><h2>Team calendar</h2><p>All times in ${e(zone)}</p></div><label><span class="sr-only">Filter by employee</span><select id="schedule-filter" class="filter-select"><option value="">All employees</option>${(data.employees||[]).map(user=>`<option value="${e(user.id)}">${e(user.name)}</option>`).join("")}</select></label></div><div id="schedule-events">${scheduleEvents(data.events||[])}</div></section>`;
}

function scheduleEvents(events) {
  const employees = state.data.employees || [];
  if (!events.length) return empty("Nothing on the calendar yet",isAdmin()?"Add an event and bring the right people together.":"Your next team assignment will appear here.");
  const groups=new Map();
  [...events].sort((a,b)=>a.starts_at.localeCompare(b.starts_at)).forEach(event=>{const key=date(event.starts_at,{year:"numeric",month:"2-digit",day:"2-digit"});if(!groups.has(key))groups.set(key,[]);groups.get(key).push(event);});
  return [...groups.values()].map(day=>`<section class="schedule-day"><div class="day-heading"><div class="eyebrow">${e(date(day[0].starts_at,{weekday:"short"}))}</div><strong>${e(date(day[0].starts_at,{day:"numeric"}))}</strong><small>${e(date(day[0].starts_at,{month:"short",year:"numeric"}))}</small></div><div class="day-events">${day.map(event=>`<article class="schedule-event"><div><h3>${e(event.title)}</h3><div class="event-meta"><span>${icon("clock")}${e(time(event.starts_at))} – ${date(event.starts_at)!==date(event.ends_at)?`${e(date(event.ends_at,{month:"short",day:"numeric"}))} `:""}${e(time(event.ends_at))}</span>${event.location?`<span>${icon("location")}${e(event.location)}</span>`:""}</div>${event.notes?`<p class="event-notes">${e(event.notes)}</p>`:""}<div class="event-employees">${event.employee_ids.map(id=>`<span class="employee-chip">${e(employees.find(user=>user.id===id)?.name || id)}</span>`).join("")}</div></div>${isAdmin()?`<button class="button small" data-action="event-edit" data-id="${e(event.id)}" aria-label="Edit ${e(event.title)}"${disabled()}>Edit</button>`:""}</article>`).join("")}</div></section>`).join("");
}

function renderMessages(data) {
  const messages=[...(data.messages||[])].sort((a,b)=>b.created_at.localeCompare(a.created_at));
  return heading("In good company","The team board.","Keep everyone in the conversation.",`<span class="badge green">${icon("lock")}Team only</span>`)+`<div class="board-layout"><section class="board-feed" aria-label="Team messages">${messages.length?messages.map(message=>`<article class="panel message-card"><div class="message-head">${avatar(typeof message.author === "object" ? message.author.name : message.author)}<div><strong>${e(typeof message.author === "object" ? message.author.name : message.author)}</strong><small>${e(stamp(message.created_at))}</small></div></div><p class="message-body">${e(message.body)}</p></article>`).join(""):`<div class="panel">${empty("Start the conversation","Share an update, a useful note, or a thank-you with the team.","message")}</div>`}</section><aside class="board-aside"><div class="panel compose-panel"><h2>Share with the team</h2><p>A note for the people you work with.</p><form id="message-form"><div id="message-error" class="error" role="alert" tabindex="-1" hidden></div><label class="field"><span>Your message</span><textarea name="body" placeholder="What would you like the team to know?" aria-label="Your message" maxlength="4000" required${disabled()}></textarea></label><button class="button primary" type="submit"${disabled()}>Post message ${icon("arrow")}</button></form></div><p class="board-side-note">Visible to signed-in employees and administrators. Up to 10 posts per minute and 100 per hour per account. Public announcements have their own board.</p></aside></div>`;
}

function renderPublic(data) {
  const admin = isAdmin();
  const guest = !state.user;
  const action = admin ? `<button class="button primary" data-action="post-new"${disabled()}>${icon("plus")}New post</button>` : guest ? `<button class="button primary" data-action="submission-new"${data.accepting_submissions === true ? "" : " disabled"}>${icon("plus")}Submit a post</button>` : '<span class="badge green">Open to everyone</span>';
  const status = admin ? "Refresh to check for new submissions." : "Updates automatically every 10 seconds.";
  const toolbar = `<div class="board-live-bar"><p id="board-status" role="status" data-state="live">${status}</p><div class="board-live-actions"><button class="button small" data-action="${admin ? "refresh" : "board-refresh"}">${icon("refresh")}Refresh board</button><button class="button small" data-action="board-share">Share board ${icon("arrow")}</button></div></div>`;
  return heading("News & community", "The public board.", admin ? "Publish updates and review messages from your guests." : "Messages, notices, and opportunities from our community.", action) + toolbar + `<div id="public-board-content">${renderPublicContent(data)}</div>`;
}

function renderPublicContent(data) {
  const admin=isAdmin();
  const guest=!state.user;
  const posts=data.posts||[];
  const accepting=data.accepting_submissions===true;
  const receipt=guest&&state.submissionReceipt?'<p class="notice submission-notice" role="status">Submitted for review. Your post will appear here if approved.</p>':"";
  const paused=guest&&!accepting?'<p class="notice submission-notice" role="status">Guest submissions are currently paused. You can still read the public board.</p>':"";
  return receipt+paused+`<section class="public-intro"><div><div class="eyebrow">A word from Westbridge</div><h2>Good work reaches beyond the office.</h2><p>Stay connected with our business, find out what’s coming up, and discover new ways to work together.</p></div>${icon("board","intro-icon")}</section>${admin?renderSubmissions(data.submissions||[],data.posting_rules):""}<section class="posting-grid" aria-label="Public announcements">${posts.length?posts.map(post=>`<article class="panel post-card"><div class="post-top"><span class="badge ${post.category?.toLowerCase().includes("opportun")?"amber":"green"}">${e(post.category||"Company news")}</span><time${post.published_at?` datetime="${e(post.published_at)}"`:""}>${e(post.published_at?date(post.published_at,{month:"short",day:"numeric",year:"numeric"}):"Draft")}</time></div><h2>${e(post.title)}</h2><p class="post-body">${e(post.body)}</p><div class="post-bottom"><span>${admin?`<span class="badge ${post.published?"green":"gray"}">${post.published?"Published":"Draft"}</span>`:post.category==="Community"?"Community contribution":"Westbridge Business Group"}</span>${admin?`<div class="post-actions">${post.published?`<button class="button small danger" data-action="post-unpublish" data-id="${e(post.id)}" aria-label="Unpublish ${e(post.title)}">Unpublish</button>`:""}<button class="button small subtle" data-action="post-edit" data-id="${e(post.id)}" aria-label="Edit ${e(post.title)}"${disabled()}>Edit post ${icon("arrow")}</button></div>`:""}</div></article>`).join(""):`<div class="panel span-2">${empty("More to share, soon",admin?"Create a post to welcome your community.":"Company announcements will appear here.","board")}</div>`}</section>`;
}

function renderSubmissions(submissions,rules) {
  const reviewRules=Array.isArray(rules?.rules)?`<details class="review-rules"><summary>Posting rules for review</summary><ul>${rules.rules.map(rule=>`<li>${e(rule)}</li>`).join("")}</ul></details>`:"";
  return `<section class="panel submissions-panel" aria-labelledby="submissions-heading"><div class="panel-heading"><div><div class="review-kicker">Administrator review · Private</div><h2 id="submissions-heading">Guest submissions</h2><p>Review community posts before they appear on the public board.</p></div><span class="badge amber">${submissions.length} pending</span></div>${reviewRules}${submissions.length?`<div class="submission-list">${submissions.map(submission=>`<article class="submission-card"><div class="submission-meta"><span class="badge gray">Guest submission</span><time datetime="${e(submission.submitted_at)}">${e(stamp(submission.submitted_at))}</time></div><h3>${e(submission.title)}</h3><p>${e(submission.body)}</p><div class="submission-actions"><button class="button small" data-action="submission-reject" data-id="${e(submission.id)}" aria-label="Reject ${e(submission.title)}"${disabled()}>${icon("close")}Reject</button><button class="button small primary" data-action="submission-approve" data-id="${e(submission.id)}" aria-label="Approve ${e(submission.title)}"${disabled()}>${icon("check")}Approve</button></div></article>`).join("")}</div>`:empty("No posts waiting for review","New guest submissions will appear here. Only approved posts are public.","check")}</section>`;
}

const stages=["New","Contacted","Proposal","Won"];
const stageColor={New:"gray",Contacted:"blue",Proposal:"amber",Won:"green"};
function renderOutreach(data) {
  const contacts=data.contacts||[];
  return heading("Relationships & opportunities","Make the next connection.","A considered approach to your business pipeline.",`<button class="button primary" data-action="contact-new"${disabled()}>${icon("plus")}New contact</button>`)+`<section class="outreach-metrics" aria-label="Opportunity stages">${stages.map(stage=>{const matching=contacts.filter(contact=>contact.stage===stage);return `<div class="panel pipeline-stage"><div class="stage-top"><span class="badge ${stageColor[stage]}">${stage}</span><span>${matching.length}</span></div><strong>${e(money(matching.reduce((sum,contact)=>sum+Number(contact.value),0)))}</strong><small>potential value</small></div>`;}).join("")}</section><section class="panel"><div class="contacts-toolbar"><label class="search-wrap">${icon("search")}<input type="search" id="contact-search" aria-label="Search contacts" placeholder="Search people or companies…" maxlength="200"></label><label><span class="sr-only">Filter by stage</span><select id="contact-filter" class="filter-select"><option value="">All stages</option>${stages.map(stage=>`<option>${stage}</option>`).join("")}</select></label></div><div class="table-wrap"><table><caption class="sr-only">Outreach contacts and opportunities</caption><thead><tr><th>Contact</th><th>Company</th><th>Stage</th><th class="money">Value</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody id="contact-rows">${contactRows(contacts)}</tbody></table></div><div class="panel-footer"><span>Relationship notes and opportunity tracking</span><span>No messages are sent from this page.</span></div></section>`;
}

function contactRows(contacts) {
  return contacts.length?contacts.map(contact=>`<tr><td><strong>${e(contact.name)}</strong><small>${e(contact.email)}</small></td><td>${e(contact.company)}</td><td><span class="badge ${stageColor[contact.stage]||"gray"}">${e(contact.stage)}</span></td><td class="money">${e(money(contact.value))}</td><td><button class="button small subtle" data-action="contact-edit" data-id="${e(contact.id)}" aria-label="Edit ${e(contact.name)}"${disabled()}>View / edit ${icon("chevron")}</button></td></tr>`).join(""):'<tr><td colspan="5">'+empty("No contacts found","Add a contact or try a different search.","users")+'</td></tr>';
}

function filterContacts() {
  const search=document.querySelector("#contact-search").value.trim().toLowerCase();
  const stage=document.querySelector("#contact-filter").value;
  const contacts=(state.data.contacts||[]).filter(contact=>(!stage||contact.stage===stage)&&(!search||`${contact.name} ${contact.company} ${contact.email}`.toLowerCase().includes(search)));
  document.querySelector("#contact-rows").innerHTML=contactRows(contacts);
}

function openDialog(type,title,subtitle,body,footer,record=null) {
  removeSubmissionChallenge();
  if(editor.open)editor.close();
  dialogState={type,record};
  editor.innerHTML=`<div class="dialog-header"><div><h2 id="dialog-title">${e(title)}</h2><p>${e(subtitle)}</p></div><button class="icon-button" data-action="dialog-close" aria-label="Close dialog">${icon("close")}</button></div><form id="dialog-form"><div class="dialog-body"><div id="dialog-error" class="error" role="alert" tabindex="-1" hidden></div>${body}</div><div class="dialog-footer">${footer}</div></form>`;
  editor.showModal();
  (editor.querySelector("input:not([type=hidden]), textarea, select") || editor.querySelector('[data-action="dialog-close"]'))?.focus();
}

function shareBoardDialog() {
  const link = new URL("/board", location.origin).href;
  openDialog("board-share", "Share the public board", "Anyone with this link can read approved posts and submit a post for review.",
    `<label class="field"><span>Board link</span><input type="url" id="board-link" value="${e(link)}" readonly></label><p class="field-hint">Guests do not need an account. The team workspace stays private.</p>`,
    '<button type="button" class="button" data-action="dialog-close">Done</button><button type="button" class="button primary" data-action="board-copy">Copy link</button>');
  document.querySelector("#board-link").select();
}
const cancelButton=()=>'<button type="button" class="button" data-action="dialog-close">Cancel</button>';
const saveButton=(label="Save changes")=>`<button type="submit" class="button primary">${e(label)}</button>`;
const inputField=(label,name,value="",options={})=>`<label class="field${options.full?" span-2":""}"><span>${e(label)}</span><input name="${e(name)}" type="${e(options.type||"text")}" value="${e(value)}" ${options.required===false?"":"required"} ${options.max?`maxlength="${Number(options.max)}"`:""} ${options.min!==undefined?`min="${Number(options.min)}"`:""} ${options.step?`step="${e(options.step)}"`:""} ${options.autocomplete?`autocomplete="${e(options.autocomplete)}"`:""}>${options.hint?`<small>${e(options.hint)}</small>`:""}</label>`;
const textareaField=(label,name,value="",options={})=>`<label class="field${options.full?" span-2":""}"><span>${e(label)}</span><textarea name="${e(name)}" maxlength="4000" ${options.required?"required":""}>${e(value)}</textarea></label>`;
const localDate=(value)=>{const parsed=new Date(value);return `${parsed.getFullYear()}-${String(parsed.getMonth()+1).padStart(2,"0")}-${String(parsed.getDate()).padStart(2,"0")}T${String(parsed.getHours()).padStart(2,"0")}:${String(parsed.getMinutes()).padStart(2,"0")}`;};

function eventDialog(record) {
  const tomorrow=new Date();tomorrow.setDate(tomorrow.getDate()+1);tomorrow.setHours(9,0,0,0);
  const end=new Date(tomorrow);end.setHours(10);
  const values=record||{title:"",starts_at:tomorrow,ends_at:end,location:"",notes:"",employee_ids:[]};
  const employees=[...(state.data.employees||[])];
  const unavailable=values.employee_ids.filter(id=>!employees.some(user=>user.id===id));
  unavailable.forEach(id=>employees.push({id,name:`${id} (access paused)`}));
  const fields=`<div class="form-grid">${inputField("Event title","title",values.title,{full:true,max:120})}${inputField("Starts","starts_at",localDate(values.starts_at),{type:"datetime-local"})}${inputField("Ends","ends_at",localDate(values.ends_at),{type:"datetime-local"})}<p class="field-hint span-2">All times in ${e(zone)}. Employees cannot be assigned to overlapping events.</p>${inputField("Location","location",values.location,{full:true,max:160,required:false})}<fieldset class="field span-2 employee-fieldset"><legend>Assign employees</legend><div class="employee-list">${employees.map(user=>`<label class="check-label"><input type="checkbox" name="employee_ids" value="${e(user.id)}"${values.employee_ids.includes(user.id)?" checked":""}>${e(user.name)}</label>`).join("")}</div>${unavailable.length?'<small>Remove assignments for employees with paused access before saving this event.</small>':""}</fieldset>${textareaField("Notes","notes",values.notes,{full:true})}</div>`;
  openDialog("event",record?"Edit event":"Plan a team event","Give the team a clear time, place, and plan.",fields,(record?'<button type="button" class="button danger push-left" data-action="event-archive">Archive</button>':"")+cancelButton()+saveButton(record?"Save event":"Create event"),record);
}

function contactDialog(record) {
  const values=record||{name:"",company:"",email:"",stage:"New",value:0,notes:""};
  openDialog("contact",record?"Edit contact":"A new connection","Keep the details and the next step in one place.",`<div class="form-grid">${inputField("Contact name","name",values.name,{full:true,max:120})}${inputField("Company","company",values.company,{max:120})}${inputField("Email","email",values.email,{type:"email",max:254})}<label class="field"><span>Stage</span><select name="stage">${stages.map(stage=>`<option${stage===values.stage?" selected":""}>${stage}</option>`).join("")}</select></label>${inputField("Opportunity value (USD)","value",values.value,{type:"number",min:0,step:"0.01"})}${textareaField("Relationship notes","notes",values.notes,{full:true})}</div>`,cancelButton()+saveButton(record?"Save contact":"Create contact"),record);
}

function postDialog(record) {
  const values=record||{title:"",body:"",category:"Company news",published:false};
  openDialog("post",record?"Edit announcement":"A word for the community","Published announcements are visible to everyone, including guests.",`<div class="form-grid">${inputField("Title","title",values.title,{full:true,max:120})}${inputField("Category","category",values.category,{full:true,max:40})}${textareaField("Announcement","body",values.body,{full:true,required:true})}<label class="checkbox-line span-2"><input type="checkbox" name="published"${values.published?" checked":""}>Publish to the public board</label></div>`,cancelButton()+saveButton("Save post"),record);
}

function submissionDialog() {
  const rules=state.data.posting_rules;
  if(!rules || typeof rules.version!=="string" || !Array.isArray(rules.rules) || !rules.rules.length) {
    toast("Posting rules are unavailable. Refresh the board before trying again.");return;
  }
  const challenge=state.data.submission_challenge || {required:false};
  const fields=`<p class="notice">Your post will be public only after administrator approval.</p><p id="submission-pause" class="notice" role="status" hidden>Guest submissions are paused. Your draft is kept here.</p><section class="posting-rules" aria-labelledby="posting-rules-heading"><h3 id="posting-rules-heading">Posting rules</h3><ul>${rules.rules.map(rule=>`<li>${e(rule)}</li>`).join("")}</ul></section><div class="form-grid">${inputField("Title","title","",{full:true,max:120})}${textareaField("Message","body","",{full:true,required:true})}<label class="checkbox-line span-2 rules-agreement"><input type="checkbox" name="accept_rules" required>I agree to the posting rules</label></div>${challenge.required?'<section class="submission-verification" aria-label="Visitor verification"><div id="submission-verification-widget"></div><p id="verification-status" class="field-hint" role="status">Preparing verification…</p><button type="button" class="button small" data-action="verification-retry" hidden>Retry verification</button></section>':""}`;
  openDialog("submission","Submit a post","Share a notice with the Westbridge community.",fields,cancelButton()+saveButton("Send for approval"),{rules_version:rules.version});
  submissionChallenge={dialog:dialogState,required:challenge.required===true,provider:challenge.provider,siteKey:challenge.site_key,token:"",widget:null,saving:false};
  updateSubmissionButton();
  if(submissionChallenge.required)startSubmissionChallenge(submissionChallenge);
}

function updateSubmissionButton() {
  const challenge=submissionChallenge;
  if(!challenge || challenge.dialog!==dialogState || !editor.open)return;
  const agreed=editor.querySelector('[name="accept_rules"]')?.checked;
  const submit=editor.querySelector('[type="submit"]');
  const paused=state.data.accepting_submissions!==true;
  const notice=editor.querySelector("#submission-pause");
  if(notice)notice.hidden=!paused;
  const submitting=editor.querySelector("#dialog-form")?.dataset.submitting==="true";
  if(submit)submit.disabled=paused || submitting || challenge.saving || !agreed || (challenge.required && !challenge.token);
}

function setChallengeStatus(challenge,message,retry=false) {
  if(submissionChallenge!==challenge || !editor.open)return;
  const status=editor.querySelector("#verification-status");
  if(status)status.textContent=message;
  const button=editor.querySelector('[data-action="verification-retry"]');
  if(button)button.hidden=!retry;
  updateSubmissionButton();
}

function loadTurnstile() {
  if(turnstileScript)return turnstileScript;
  const callbackName=`westbridgeTurnstileLoaded${++turnstileLoadSequence}`;
  const loading=new Promise((resolve,reject)=>{
    const script=document.createElement("script");
    let settled=false;
    const cleanup=()=>{clearTimeout(timeout);script.removeEventListener("error",fail);delete window[callbackName];};
    const fail=()=>{
      if(settled)return;
      settled=true;cleanup();script.remove();
      reject(new Error("Verification could not load. Please try again."));
    };
    const timeout=setTimeout(fail,15000);
    // Async scripts use the provider's onload callback, not turnstile.ready().
    window[callbackName]=()=>{
      if(settled)return;
      if(typeof window.turnstile?.render!=="function"){fail();return;}
      settled=true;cleanup();resolve(window.turnstile);
    };
    try {
      script.src=`https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=${callbackName}`;
      script.async=true;
      script.addEventListener("error",fail,{once:true});
      document.head.append(script);
    } catch(_) {fail();}
  });
  turnstileScript=loading;
  loading.catch(()=>{if(turnstileScript===loading)turnstileScript=null;});
  return loading;
}

async function startSubmissionChallenge(challenge) {
  challenge.token="";
  setChallengeStatus(challenge,"Preparing verification…");
  try {
    if(challenge.provider!=="turnstile" || typeof challenge.siteKey!=="string" || !challenge.siteKey)throw new Error("Verification is unavailable.");
    const turnstile=await loadTurnstile();
    if(submissionChallenge!==challenge || !editor.open)return;
    if(challenge.widget!==null)turnstile.remove(challenge.widget);
    challenge.widget=turnstile.render(editor.querySelector("#submission-verification-widget"),{
      sitekey:challenge.siteKey,action:"guest_submission",theme:"light",size:window.innerWidth<390?"compact":"flexible","response-field":false,retry:"never","refresh-expired":"manual",
      callback:(token)=>{if(submissionChallenge!==challenge)return;challenge.token=token;setChallengeStatus(challenge,"Verification complete.");},
      "expired-callback":()=>{challenge.token="";setChallengeStatus(challenge,"Verification expired. Please verify again.",true);},
      "timeout-callback":()=>{challenge.token="";setChallengeStatus(challenge,"Verification timed out. Please try again.",true);},
      "error-callback":()=>{challenge.token="";setChallengeStatus(challenge,"Verification could not complete. Please try again.",true);},
    });
  } catch(_) {
    challenge.token="";
    setChallengeStatus(challenge,"Verification could not load. Check your connection and try again.",true);
  }
}

function resetSubmissionChallenge(challenge) {
  if(submissionChallenge!==challenge || !challenge.required || !editor.open)return;
  challenge.token="";
  setChallengeStatus(challenge,"Please complete verification again.");
  if(challenge.widget!==null && window.turnstile) {
    try {window.turnstile.reset(challenge.widget);}
    catch(_) {setChallengeStatus(challenge,"Verification could not restart. Please try again.",true);}
  } else startSubmissionChallenge(challenge);
}

function removeSubmissionChallenge() {
  const challenge=submissionChallenge;
  submissionChallenge=null;
  if(challenge?.widget!==null && challenge?.widget!==undefined && window.turnstile)window.turnstile.remove(challenge.widget);
}

editor.addEventListener("close",()=>{if(!editor.open)removeSubmissionChallenge();});
editor.addEventListener("cancel",removeSubmissionChallenge);

function profileDialog() {
  openDialog("password","Your profile","Your account and sign-in details.",`<div class="profile-summary">${avatar(state.user.name,"large")}<div><strong>${e(state.user.name)}</strong><small>${e(state.user.username)} · ${roleName()}</small></div></div><button type="button" class="button" data-action="sessions-open">Manage your sessions ${icon("shield")}</button><h3 class="password-title">Change your password</h3>${inputField("Current password","current_password","",{type:"password",max:128,autocomplete:"current-password"})}${inputField("New password","new_password","",{type:"password",max:128,autocomplete:"new-password",hint:"Avoid common passwords; a password manager can generate one. Use 15–128 characters. You’ll sign in again after changing it."})}${inputField("Confirm new password","confirm_password","",{type:"password",max:128,autocomplete:"new-password"})}`,cancelButton()+saveButton("Change password"));
  const button=document.createElement("button");button.type="button";button.className="button";
  button.dataset.action="passkeys-open";button.textContent="Manage your passkeys";
  editor.querySelector('[data-action="sessions-open"]').after(button);
}

function confirmation(type,title,body,record,label) {
  openDialog(type,title,"Please confirm this change.",`<p class="dialog-copy">${e(body)}</p>`,cancelButton()+saveButton(label),record);
}

document.addEventListener("click",async(event)=>{
  const button=event.target.closest("button");
  if(!button||button.disabled)return;
  if(button.dataset.page){navigate(button.dataset.page);return;}
  const action=button.dataset.action;
  if(!action)return;
  if(action==="passkey-login"){await signInWithPasskey(button);return;}
  if(action==="verification-passkey"){await verifyWithPasskey(button);return;}
  if(action==="passkeys-open"){openPasskeys();return;}
  if(action==="passkeys-close"){passkeyView?.controller?.abort();passkeyView=null;passkeyDialog.close();passkeyDialog.replaceChildren();return;}
  if(action==="passkeys-refresh"){if(passkeyView?.owns()&&!passkeyView.busy)await loadPasskeys(passkeyView);return;}
  if(action==="passkey-remove") {
    const view=passkeyView,row=view?.rows.find(item=>item.id===button.dataset.id);
    if(!row||!view.owns()||view.busy)return;
    const current=()=>passkeyView===view&&view.owns()&&passkeyDialog.open;
    view.busy=true;button.disabled=true;
    try {
      const result=await api(`/api/security/passkeys/${encodeURIComponent(row.id)}/remove`,"POST",{});
      if(!current())return;
      if(result?.ok!==true)throw new Error("The passkey removal could not be confirmed. Refresh the list before trying again.");
      if(result.current_session_revoked){setSession({});state.data={};state.guest=false;renderLogin();toast("Passkey removed. Sign in with another method.");return;}
      toast("Passkey removed.");await loadPasskeys(view);
    } catch(error){if(current())errorAt(error,passkeyDialog.querySelector('[role="alert"]'));}
    finally{if(current()){view.busy=false;button.disabled=false;}}
    return;
  }
  if(action==="metrics-refresh"){await refreshSecurityMetrics(button);return;}
  if(action==="verification-close"){closeVerification();return;}
  if(action==="sessions-open"){openSessions();return;}
  if(action==="sessions-close"){closeSecurityDialogs();return;}
  if(action==="sessions-refresh"){if(sessionView?.owns())await loadSessions(sessionView);return;}
  if(action==="session-revoke") {
    const view=sessionView,row=view?.rows.find(item=>item.id===button.dataset.id);
    if(!row||!view.owns()||!sessionDialog.open)return;
    const current=()=>sessionView===view&&view.owns()&&sessionDialog.open;
    button.disabled=true;
    try {
      const result=await api(`/api/security/sessions/${encodeURIComponent(row.id)}/revoke`,"POST",{});
      if(!current())return;
      if(result?.ok!==true)throw new Error("The session change could not be confirmed. Refresh sessions before trying again.");
      if(result.current_session_revoked){setSession({});state.data={};state.guest=false;renderLogin();toast("This session has been signed out.");return;}
      toast("The selected session has been signed out.");await loadSessions(view);
    } catch(error) {if(current())errorAt(error,sessionDialog.querySelector('[role="alert"]'));}
    finally {if(current())button.disabled=false;}
    return;
  }
  if(action==="toggle-password") {const field=document.querySelector("#password");const show=field.type==="password";field.type=show?"text":"password";button.setAttribute("aria-label",show?"Hide password":"Show password");button.setAttribute("aria-pressed",String(show));return;}
  if(action==="guest"){state.guest=true;await navigate("public");return;}
  if(action==="board-refresh"){await refreshPublicBoard();return;}
  if(action==="board-share"){shareBoardDialog();return;}
  if(action==="board-copy"){
    const field=editor.querySelector("#board-link");
    if(!field)return;
    try {await navigator.clipboard.writeText(field.value);toast("Board link copied.");}
    catch(_) {field.focus();field.select();toast("Select and copy the board link shown above.");}
    return;
  }
  if(action==="signin"){state.guest=false;renderLogin();document.querySelector("#username").focus();return;}
  if(action==="dialog-close"){editor.close();return;}
  if(action==="menu-open"){document.querySelector("#sidebar").classList.add("open");button.setAttribute("aria-expanded","true");document.querySelector(".workspace-main").inert=true;const scrim=document.createElement("div");scrim.className="mobile-scrim";scrim.addEventListener("click",closeMenu);app.append(scrim);document.querySelector(".mobile-close").focus();return;}
  if(action==="menu-close"){closeMenu();return;}
  if(action==="profile"){profileDialog();return;}
  if(action==="activity"&&isAdmin()&&state.page==="overview"){activityDialog();return;}
  if(action==="recovery-copy"&&isAdmin()&&state.page==="security"){
    const code=document.querySelector(`#recovery-${button.dataset.command}`);
    if(!code)return;
    const ticket=navigation;
    try {await navigator.clipboard.writeText(code.textContent);if(ticket===navigation)toast("Command copied. Replace the path placeholders before running it.");}
    catch(_) {
      if(ticket!==navigation)return;
      code.focus();const range=document.createRange();range.selectNodeContents(code);const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);
      toast("Copy the selected command, then replace its path placeholders.");
    }
    return;
  }
  if(action==="event-new"){eventDialog(null);return;}
  if(action==="event-edit"){eventDialog(state.data.events.find(item=>item.id===button.dataset.id));return;}
  if(action==="contact-new"){contactDialog(null);return;}
  if(action==="contact-edit"){contactDialog(state.data.contacts.find(item=>item.id===button.dataset.id));return;}
  if(action==="post-new"){postDialog(null);return;}
  if(action==="post-edit"){postDialog(state.data.posts.find(item=>item.id===button.dataset.id));return;}
  if(action==="post-unpublish"){
    const post=state.data.posts.find(item=>item.id===button.dataset.id);
    confirmation("post-unpublish","Unpublish this post?",`“${post.title}” will be removed from the public board and kept as a private draft.`,post,"Unpublish post");return;
  }
  if(action==="submission-new"){submissionDialog();return;}
  if(action==="verification-retry"){if(submissionChallenge)startSubmissionChallenge(submissionChallenge);return;}
  if(action==="submission-approve"||action==="submission-reject"){
    const submission=state.data.submissions.find(item=>item.id===button.dataset.id);
    const decision=action==="submission-approve"?"approve":"reject";
    confirmation("submission-review",decision==="approve"?"Approve this guest post?":"Reject this guest post?",decision==="approve"?`“${submission.title}” will be published on the public board for everyone to read.`:`“${submission.title}” will leave the review queue without being published.`,{...submission,decision},decision==="approve"?"Approve post":"Reject post");return;
  }
  if(action==="event-archive"){const record=dialogState.record;confirmation("archive","Archive this event?",`“${record.title}” will be removed from the active schedule. Its history will be retained.`,record,"Archive event");return;}
  if(action==="freeze"){confirmation("freeze",state.frozen?"Resume workspace changes?":"Pause workspace changes?",state.frozen?"Employees and administrators will be able to update the workspace again.":"Scheduling, messages, outreach, publishing, and guest submissions will be paused. You can still unpublish posts and pause employee access.",{frozen:!state.frozen,revision:state.freeze_revision},state.frozen?"Resume changes":"Pause changes");return;}
  if(action==="user-toggle"){const user=state.data.users.find(item=>item.id===button.dataset.id);confirmation("user",user.active?"Pause employee access?":"Restore employee access?",user.active?`${user.name} will be signed out and will not be able to access the team workspace until access is restored.`:`${user.name} will be able to sign in to the team workspace again.`,user,user.active?"Pause access":"Restore access");return;}
  if(action==="refresh") {
    const ticket=navigation;
    button.disabled=true;
    try{if(state.user){const session=await api("/api/session");if(ticket!==navigation)return;if(!session.user){const error=new Error("Your session has ended.");error.status=401;throw error;}setSession(session);}await navigate(state.page,{keepScroll:true});}
    catch(error){if(ticket===navigation){errorAt(error);button.disabled=false;}}
    return;
  }
  if(action==="logout") {
    const account=state.user?.id,csrf=state.csrf;
    const ownsSession=()=>state.user?.id===account&&state.csrf===csrf;
    button.disabled=true;
    try{await api("/api/logout","POST",{});if(!ownsSession())return;setSession({});state.data={};state.guest=false;renderLogin();toast("You’ve signed out.");}
    catch(error){if(ownsSession()){errorAt(error);button.disabled=false;}}
  }
});

function closeMenu(){document.querySelector("#sidebar")?.classList.remove("open");document.querySelector(".mobile-scrim")?.remove();const main=document.querySelector(".workspace-main");if(main)main.inert=false;const trigger=document.querySelector('[data-action="menu-open"]');trigger?.setAttribute("aria-expanded","false");trigger?.focus();}
// Clear the mobile overlay when the sidebar becomes permanent at the CSS breakpoint.
window.matchMedia("(max-width:700px)").addEventListener("change",event=>{
  if(event.matches||!document.querySelector(".sidebar.open"))return;
  closeMenu();
  document.querySelector(".sidebar .nav-link.active")?.focus();
});
document.addEventListener("keydown",event=>{
  const openMenu=document.querySelector(".sidebar.open");
  if(event.key==="Escape"&&!editor.open&&openMenu){event.preventDefault();closeMenu();}
  if(event.key==="Tab"&&openMenu){const links=[...openMenu.querySelectorAll("button")].filter(button=>button.offsetParent!==null);const first=links[0],last=links.at(-1);if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}}
});
document.addEventListener("change",event=>{
  if(event.target.id==="schedule-filter") {const employee=event.target.value;document.querySelector("#schedule-events").innerHTML=scheduleEvents((state.data.events||[]).filter(item=>!employee||item.employee_ids.includes(employee)));}
  if(event.target.id==="contact-filter")filterContacts();
  if(event.target.id==="recovery-platform")for(const operation of ["encrypt","verify","restore"])document.querySelector(`#recovery-${operation}`).textContent=recoveryCommand(operation,event.target.value);
  if(event.target.name==="accept_rules")updateSubmissionButton();
});
document.addEventListener("input",event=>{if(event.target.id==="contact-search")filterContacts();if(event.target.id==="activity-search")filterActivity();});

function beginSubmission(form) {
  // Disabled inputs are omitted by FormData, so capture the submitted values first.
  const values=new FormData(form);
  const ticket=navigation;
  const inDialog=form.id==="dialog-form";
  const dialog=dialogState;
  const ownsForm=()=>navigation===ticket && form.isConnected;
  const isCurrent=()=>ownsForm() &&
    (inDialog ? dialogState===dialog && editor.open && editor.contains(form) : !editor.open);
  const controls=[...form.querySelectorAll("input, textarea, select, button")]
    .filter(control=>control.dataset.action!=="dialog-close")
    .map(control=>[control,control.disabled]);
  const closeButtons=[...form.querySelectorAll('[data-action="dialog-close"]')]
    .map(button=>[button,button.textContent]);
  form.dataset.submitting="true";
  controls.forEach(([control])=>{control.disabled=true;});
  let notice;
  if(inDialog) {
    closeButtons.forEach(([button])=>{button.textContent="Close";});
    notice=document.createElement("p");
    notice.className="field-hint";
    notice.setAttribute("role","status");
    notice.textContent="Saving your changes. Closing this window won't cancel the save.";
    form.querySelector(".dialog-body").prepend(notice);
  }
  return {values,isCurrent,ownsForm,restore:()=>{
    delete form.dataset.submitting;
    // Restore captured elements even if another dialog owns the foreground.
    // Never look up replacement controls or update a newer verification widget.
    controls.forEach(([control,wasDisabled])=>{control.disabled=wasDisabled;});
    closeButtons.forEach(([button,label])=>{button.textContent=label;});
    notice?.remove();
    if(isCurrent())updateSubmissionButton();
  }};
}

document.addEventListener("submit",async(event)=>{
  const form=event.target;
  if(!["login-form","message-form","dialog-form"].includes(form.id))return;
  event.preventDefault();
  if(form.id==="dialog-form" && ["board-share","activity"].includes(dialogState?.type))return;
  if(form.dataset.submitting==="true")return;
  const submission=beginSubmission(form);
  const {values,isCurrent}=submission;
  const showSaved=async(page,message)=>{
    if(!isCurrent())return;
    if(form.id==="dialog-form")editor.close();
    const ticket=navigation+1;
    await navigate(page,{keepScroll:true});
    if(navigation===ticket && !editor.open)toast(message);
  };
  const submit=form.querySelector('[type="submit"]');
  const original=submit.textContent;
  const target=form.querySelector('[role="alert"]');
  target.hidden=true;
  submit.disabled=true;submit.textContent="Saving…";
  try {
    if(form.id==="login-form") {
      submit.textContent="Signing in…";
      const otp=String(values.get("otp")||"").trim();
      const session=await api("/api/login","POST",{username:values.get("username").trim(),password:values.get("password"),...(otp?{otp}:{})});
      if(!isCurrent())return;
      setSession(session);state.guest=false;await navigate(isAdmin()?"overview":"schedule");return;
    }
    if(form.id==="message-form") {
      const body=values.get("body").trim();if(!body)throw new Error("Write a message before posting.");
      await createRecord(form,"/api/messages",{body},"message");
      if(!isCurrent()) {
        // A profile dialog may cover this form; acknowledge the saved message
        // without replacing that dialog or leaving a submitted draft to repost.
        if(submission.ownsForm()){form.reset();toast("Your message is on the team board.");}
        return;
      }
      await showSaved("messages","Your message is on the team board.");return;
    }
    const {type,record}=dialogState;
    const text=(key)=>String(values.get(key)||"").trim();
    if(type==="event") {
      const starts=new Date(values.get("starts_at")),ends=new Date(values.get("ends_at"));
      if(Number.isNaN(starts.valueOf())||Number.isNaN(ends.valueOf()))throw new Error("Enter a valid start and end time.");
      if(ends<=starts)throw new Error("The event must end after it starts.");
      // A saved create may be retried after its event ended. The server checks
      // the receipt first, then rejects past times for a genuinely new event.
      if(record && ends<=new Date())throw new Error("Choose an event that ends in the future.");
      if(ends-starts>7*24*60*60*1000)throw new Error("An event can be no longer than seven days.");
      const employee_ids=values.getAll("employee_ids");if(!employee_ids.length)throw new Error("Assign at least one employee to this event.");
      const body={title:text("title"),starts_at:starts.toISOString(),ends_at:ends.toISOString(),location:text("location"),notes:text("notes"),employee_ids,...(record?{revision:record.revision}:{})};
      if(record)await api(`/api/schedule/${encodeURIComponent(record.id)}`,"PUT",body);
      else await createRecord(form,"/api/schedule",body,"event");
      if(!isCurrent())return;
      await showSaved("schedule",record?"The event has been updated.":"The event has been added to the schedule.");
    } else if(type==="archive") {
      await api(`/api/schedule/${encodeURIComponent(record.id)}/archive`,"POST",{revision:record.revision});
      if(!isCurrent())return;
      await showSaved("schedule","The event has been archived.");
    } else if(type==="contact") {
      const amount=Number(values.get("value"));if(!Number.isFinite(amount)||amount<0||amount>100000000)throw new Error("Enter an opportunity value between $0 and $100,000,000.");
      const body={name:text("name"),company:text("company"),email:text("email"),stage:text("stage"),value:amount,notes:text("notes"),...(record?{revision:record.revision}:{})};
      if(record)await api(`/api/admin/contacts/${encodeURIComponent(record.id)}`,"PUT",body);
      else await createRecord(form,"/api/admin/contacts",body,"contact");
      if(!isCurrent())return;
      await showSaved("outreach","The contact has been saved.");
    } else if(type==="post") {
      const body={title:text("title"),body:text("body"),category:text("category"),published:values.has("published"),...(record?{revision:record.revision}:{})};
      if(record)await api(`/api/admin/posts/${encodeURIComponent(record.id)}`,"PUT",body);
      else await createRecord(form,"/api/admin/posts",body,"post");
      if(!isCurrent())return;
      await showSaved("public",body.published?"Your announcement is published.":"Your announcement is saved as a draft.");
    } else if(type==="post-unpublish") {
      await api(`/api/admin/posts/${encodeURIComponent(record.id)}/unpublish`,"POST",{revision:record.revision});
      if(!isCurrent())return;
      await showSaved("public","The post is now a private draft.");
    } else if(type==="submission") {
      const challenge=submissionChallenge;
      if(!values.has("accept_rules"))throw new Error("Please agree to the posting rules before submitting.");
      if(!challenge || (challenge.required && !challenge.token))throw new Error("Complete verification before submitting your post.");
      const body={title:text("title"),body:text("body"),rules_version:record.rules_version,accept_rules:true,turnstile_token:challenge.token};
      if(!body.title||!body.body)throw new Error("Add a title and message before submitting your post.");
      challenge.saving=true;
      try {await api("/api/public/submissions","POST",body);}
      catch(error) {if(isCurrent())resetSubmissionChallenge(challenge);throw error;}
      finally {challenge.saving=false;}
      if(!isCurrent())return;
      editor.close();state.submissionReceipt=true;await navigate("public");
    } else if(type==="submission-review") {
      await api(`/api/admin/submissions/${encodeURIComponent(record.id)}/review`,"POST",{decision:record.decision,revision:record.revision});
      if(!isCurrent())return;
      await showSaved("public",record.decision==="approve"?"The guest post is now published.":"The guest post was rejected.");
    } else if(type==="freeze") {
      const result=await api("/api/admin/freeze","POST",record);
      if(!isCurrent())return;
      state.frozen=result.frozen;state.freeze_revision=result.freeze_revision;
      await showSaved(state.page==="security"?"security":"overview",state.frozen?"Workspace changes are paused.":"Workspace changes have resumed.");
    } else if(type==="user") {
      await api(`/api/admin/users/${encodeURIComponent(record.id)}`,"PUT",{active:!record.active,revision:record.revision});
      if(!isCurrent())return;
      await showSaved("overview",record.active?"Employee access has been paused.":"Employee access has been restored.");
    } else if(type==="password") {
      const newPassword=values.get("new_password");
      if([...newPassword].length<15)throw new Error("Choose a password with at least 15 characters.");
      if(newPassword!==values.get("confirm_password"))throw new Error("The new passwords don’t match.");
      const account=state.user.id,csrf=state.csrf;
      // A password change revokes this session even if its dialog was closed.
      // Navigation is independent of session ownership; a newer login wins.
      const ownsSession=()=>state.user?.id===account&&state.csrf===csrf;
      const finishPassword=(message,succeeded=false)=>{
        if(!ownsSession())return;
        form.reset();editor.close();editor.replaceChildren();dialogState=null;
        setSession({});state.data={};state.guest=false;renderLogin();
        const notice=document.querySelector("#login-error");
        if(succeeded){notice.className="notice";notice.setAttribute("role","status");}
        notice.textContent=message;notice.hidden=false;notice.focus();
      };
      try {
        const result=await api("/api/password","POST",{current_password:values.get("current_password"),new_password:newPassword});
        if(result?.ok!==true)throw new Error("The password change reply could not be confirmed.");
      } catch(error) {
        if(!ownsSession())return;
        if(!error.status||error.status>=500){
          finishPassword("We couldn’t confirm the password change. Try signing in with your new password first. If it is not accepted, try your previous password.");return;
        }
        if(error.status===401){finishPassword("Your session has ended. Sign in again to continue.");return;}
        throw error;
      }
      finishPassword("Your password has changed. Sign in with your new password.",true);
    }
  } catch(error) {if(isCurrent())errorAt(error,target);}
  finally{
    submit.textContent=original;
    submission.restore();
  }
});

async function start() {
  const boardLanding=location.pathname==="/board" || location.hash==="#board";
  try {const session=await api("/api/session");setSession(session);if(boardLanding){state.guest=!state.user;await navigate("public");}else if(state.user)await navigate(isAdmin()?"overview":"schedule");else renderLogin();}
  catch(error){renderLogin();errorAt(error,document.querySelector("#login-error"));}
}
start();
