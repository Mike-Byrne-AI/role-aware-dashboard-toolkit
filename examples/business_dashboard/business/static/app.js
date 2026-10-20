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
  let response;
  try {
    response = await fetch(path, {method, headers, credentials:"same-origin", cache:"no-store", signal:options.signal, ...(body === undefined ? {} : {body:JSON.stringify(body)})});
  } catch (error) {
    if(error.name === "AbortError")throw error;
    throw new Error("Unable to reach the workspace. Check your connection and try again.");
  }
  const data = await response.json().catch(error => {if(error.name === "AbortError")throw error;return {};});
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "This request could not be completed. Check your entries and try again.";
    const error = new Error(detail); error.status = response.status;
    error.retryAfter = Number(response.headers.get("Retry-After")) || 0;
    throw error;
  }
  return data;
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
}

function renderLogin() {
  stopBoardUpdates();
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
}

const pages = {overview:{label:"Overview",icon:"grid"},schedule:{label:"Schedule",icon:"calendar"},messages:{label:"Team board",icon:"message"},outreach:{label:"Outreach",icon:"outreach"},public:{label:"Public board",icon:"board"}};

function shell(content) {
  const title = pages[state.page]?.label || "Workspace";
  const guest = !state.user;
  const allowed = isAdmin() ? ["overview","schedule","messages","outreach","public"] : ["schedule","messages","public"];
  const sidebar = `<aside class="sidebar" id="sidebar" aria-label="Workspace navigation"><div class="row">${brand()}<button class="icon-button mobile-close" aria-label="Close navigation" data-action="menu-close">${icon("close")}</button></div><p class="workspace-label">Your workspace</p><nav>${allowed.map(key=>`<button class="nav-link${state.page===key?" active":""}" data-page="${key}"${state.page===key?' aria-current="page"':""}>${icon(pages[key].icon)}<span>${pages[key].label}</span></button>`).join("")}</nav><div class="sidebar-bottom"><div class="sidebar-note"><strong>Westbridge Business Group</strong>Good people. Thoughtful work.</div></div></aside>`;
  const header = guest ? `${brand()}<div class="row"><span class="guest-label">Public workspace</span><button class="button" data-action="signin">Team sign in ${icon("arrow")}</button></div>` : `<button class="icon-button mobile-menu" data-action="menu-open" aria-label="Open navigation" aria-expanded="false" aria-controls="sidebar">${icon("menu")}</button><div class="breadcrumb"><span>Workspace</span>${icon("chevron")}<strong>${e(title)}</strong></div><div class="topbar-actions"><span class="topbar-date">${e(date(new Date(),{weekday:"short",month:"short",day:"numeric",year:"numeric"}))}</span><button class="icon-button" data-action="refresh" aria-label="Refresh workspace" title="Refresh workspace">${icon("refresh")}</button><span class="header-divider"></span><button class="user-control" data-action="profile" aria-label="Your profile">${avatar(state.user.name)}<span class="user-text"><strong>${e(state.user.name)}</strong><small>${roleName()}</small></span></button><button class="icon-button" data-action="logout" aria-label="Sign out" title="Sign out">${icon("logout")}</button></div>`;
  app.innerHTML = `<div class="workspace${guest?" guest-workspace":""}">${guest?"":sidebar}<div class="workspace-main"><header class="topbar">${header}</header><main id="main" class="content">${!guest && state.frozen ? `<div class="notice frozen-banner" role="status">${icon("lock")}<span>Workspace changes are paused. You can continue to view schedules, messages, and updates.${isAdmin()?" You can still unpublish posts and pause employee access.":""}</span></div>`:""}${content}<footer class="workspace-footer"><span>© ${new Date().getFullYear()} Westbridge Business Group</span><span>${guest?"Company news & community":"A clearer view of your working day."}</span></footer></main></div></div>`;
  document.title = `${title} · Westbridge`;
}

function heading(eyebrow, title, description, action = "") {
  return `<div class="page-heading"><div><div class="eyebrow">${e(eyebrow)}</div><h1>${e(title)}</h1><p>${e(description)}</p></div><div class="page-actions">${action}</div></div>`;
}

async function navigate(page, options = {}) {
  stopBoardUpdates();
  const ticket = ++navigation;
  if (!state.user && page !== "public") {renderLogin(); return;}
  if (state.user && !isAdmin() && ["overview","outreach"].includes(page)) page = "schedule";
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
    else if (isAdmin()) {
      const [posts,submissions] = await Promise.all([api("/api/admin/posts"),api("/api/admin/submissions")]);
      data = {...posts,...submissions};
    } else data = await api("/api/public/posts");
    if (ticket !== navigation) return;
    state.data = data;
    if (data.frozen !== undefined) {state.frozen=Boolean(data.frozen);state.freeze_revision=data.freeze_revision;}
    const render = {overview:renderOverview,schedule:renderSchedule,messages:renderMessages,outreach:renderOutreach,public:renderPublic};
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
    `<section class="metrics" aria-label="Business metrics">${metric("Monthly revenue",money(metrics.monthly_revenue),"Sample financials · latest month","money")}${metric("Operating profit",money((metrics.monthly_revenue||0)-(metrics.monthly_cost||0)),"Sample revenue less sample costs","trend")}${metric("Open pipeline",money(metrics.pipeline_value),`<strong>${e(number(metrics.open_leads))}</strong> open opportunities`,"outreach")}${metric("Scheduled team-hours",number(metrics.scheduled_hours),"Upcoming work · all assignments","clock")}</section>
    <div class="overview-grid"><section class="panel chart-panel"><div class="panel-heading"><div><h2>Business performance</h2><p>Revenue and operating costs</p></div><div class="legend"><span><i></i>Revenue</span><span><i class="cost"></i>Costs</span></div></div><div class="panel-body">${financialChart(data.revenue || [])}<div class="chart-caption">${icon("info")}Sample financials · USD · illustrative figures</div></div></section>
    <section class="panel"><div class="panel-heading"><div><h2>Coming up next</h2><p>Ahead on the team calendar</p></div>${icon("calendar")}</div><div class="panel-body">${nextEvents.length?nextEvents.map(event=>`<div class="agenda-item"><div class="date-tile"><span>${e(date(event.starts_at,{month:"short"}))}</span><strong>${e(date(event.starts_at,{day:"numeric"}))}</strong></div><div class="agenda-detail"><strong>${e(event.title)}</strong><p>${e(time(event.starts_at))} – ${e(time(event.ends_at))}${event.location?` · ${e(event.location)}`:""}</p></div></div>`).join(""):empty("A little room on the calendar","Add an event to plan your next working day.")}</div><div class="panel-footer"><span>${e(zone)}</span><button class="button subtle" data-page="schedule">View schedule ${icon("arrow")}</button></div></section>
    <section class="panel"><div class="panel-heading"><div><h2>Recent activity</h2><p>The latest changes across your workspace</p></div><span class="badge gray">Activity log</span></div><div class="panel-body">${activity.length?activity.map(item=>`<div class="activity-item"><span class="activity-dot">${icon("check")}</span><div class="activity-detail"><strong>${e(item.actor)}</strong> · ${e(String(item.action).replaceAll("_"," ").replaceAll("."," "))}${item.target?`<span> · ${e(item.target)}</span>`:""}<small>${e(stamp(item.created_at))}</small></div></div>`).join(""):empty("All set for a fresh start","Schedule and account changes appear here.","check")}</div></section>
    <section class="panel"><div class="panel-heading"><div><h2>Your team</h2><p>People with access to the workspace</p></div><span class="badge green">${team.filter(user=>user.active).length} active</span></div><div class="panel-body">${team.map(user=>`<div class="team-row">${avatar(user.name)}<div class="team-info"><strong>${e(user.name)}</strong><small>${user.active?"Employee":"Access paused"}</small></div><button class="button small subtle" data-action="user-toggle" data-id="${e(user.id)}" aria-label="${user.active?"Pause":"Restore"} access for ${e(user.name)}"${!user.active&&state.frozen?" disabled":""}>${user.active?"Pause access":"Restore access"}</button></div>`).join("")}</div></section></div>
    <section class="panel tools-panel"><div class="tools-content"><div class="tools-heading"><span class="tool-icon">${icon("settings")}</span><div class="tools-copy"><h2>Workspace controls</h2><p>Pause changes while you review the schedule and team activity.</p></div></div><button class="switch-control" role="switch" aria-checked="${state.frozen}" data-action="freeze"><span class="switch-track" aria-hidden="true"></span>Pause workspace changes</button></div></section>`;
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
  return heading("In good company","The team board.","Keep everyone in the conversation.",`<span class="badge green">${icon("lock")}Team only</span>`)+`<div class="board-layout"><section class="board-feed" aria-label="Team messages">${messages.length?messages.map(message=>`<article class="panel message-card"><div class="message-head">${avatar(typeof message.author === "object" ? message.author.name : message.author)}<div><strong>${e(typeof message.author === "object" ? message.author.name : message.author)}</strong><small>${e(stamp(message.created_at))}</small></div></div><p class="message-body">${e(message.body)}</p></article>`).join(""):`<div class="panel">${empty("Start the conversation","Share an update, a useful note, or a thank-you with the team.","message")}</div>`}</section><aside class="board-aside"><div class="panel compose-panel"><h2>Share with the team</h2><p>A note for the people you work with.</p><form id="message-form"><div id="message-error" class="error" role="alert" tabindex="-1" hidden></div><label class="field"><span>Your message</span><textarea name="body" placeholder="What would you like the team to know?" aria-label="Your message" maxlength="4000" required${disabled()}></textarea></label><button class="button primary" type="submit"${disabled()}>Post message ${icon("arrow")}</button></form></div><p class="board-side-note">Visible to signed-in employees and administrators. Public announcements have their own board.</p></aside></div>`;
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
  if(submit)submit.disabled=paused || challenge.saving || !agreed || (challenge.required && !challenge.token);
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
  openDialog("password","Your profile","Your account and sign-in details.",`<div class="profile-summary">${avatar(state.user.name,"large")}<div><strong>${e(state.user.name)}</strong><small>${e(state.user.username)} · ${roleName()}</small></div></div><h3 class="password-title">Change your password</h3>${inputField("Current password","current_password","",{type:"password",max:128,autocomplete:"current-password"})}${inputField("New password","new_password","",{type:"password",max:128,autocomplete:"new-password",hint:"Use 12–128 characters. You’ll sign in again after changing it."})}${inputField("Confirm new password","confirm_password","",{type:"password",max:128,autocomplete:"new-password"})}`,cancelButton()+saveButton("Change password"));
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
    button.disabled=true;
    try{if(state.user){const session=await api("/api/session");if(!session.user){const error=new Error("Your session has ended.");error.status=401;throw error;}setSession(session);}await navigate(state.page,{keepScroll:true});}
    catch(error){errorAt(error);button.disabled=false;}
    return;
  }
  if(action==="logout") {
    button.disabled=true;
    try{await api("/api/logout","POST",{});setSession({});state.data={};state.guest=false;renderLogin();toast("You’ve signed out.");}
    catch(error){errorAt(error);button.disabled=false;}
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
  if(event.target.name==="accept_rules")updateSubmissionButton();
});
document.addEventListener("input",event=>{if(event.target.id==="contact-search")filterContacts();});

document.addEventListener("submit",async(event)=>{
  const form=event.target;
  if(!["login-form","message-form","dialog-form"].includes(form.id))return;
  event.preventDefault();
  if(form.id==="dialog-form" && dialogState?.type==="board-share")return;
  if(form.dataset.submitting==="true")return;
  form.dataset.submitting="true";
  const values=new FormData(form);
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
      setSession(session);state.guest=false;await navigate(isAdmin()?"overview":"schedule");return;
    }
    if(form.id==="message-form") {
      const body=values.get("body").trim();if(!body)throw new Error("Write a message before posting.");
      await api("/api/messages","POST",{body});await navigate("messages",{keepScroll:true});toast("Your message is on the team board.");return;
    }
    const {type,record}=dialogState;
    const text=(key)=>String(values.get(key)||"").trim();
    if(type==="event") {
      const starts=new Date(values.get("starts_at")),ends=new Date(values.get("ends_at"));
      if(Number.isNaN(starts.valueOf())||Number.isNaN(ends.valueOf()))throw new Error("Enter a valid start and end time.");
      if(ends<=starts)throw new Error("The event must end after it starts.");
      if(ends<=new Date())throw new Error("Choose an event that ends in the future.");
      if(ends-starts>7*24*60*60*1000)throw new Error("An event can be no longer than seven days.");
      const employee_ids=values.getAll("employee_ids");if(!employee_ids.length)throw new Error("Assign at least one employee to this event.");
      const body={title:text("title"),starts_at:starts.toISOString(),ends_at:ends.toISOString(),location:text("location"),notes:text("notes"),employee_ids,...(record?{revision:record.revision}:{})};
      await api(record?`/api/schedule/${encodeURIComponent(record.id)}`:"/api/schedule",record?"PUT":"POST",body);
      editor.close();await navigate("schedule",{keepScroll:true});toast(record?"The event has been updated.":"The event has been added to the schedule.");
    } else if(type==="archive") {
      await api(`/api/schedule/${encodeURIComponent(record.id)}/archive`,"POST",{revision:record.revision});editor.close();await navigate("schedule",{keepScroll:true});toast("The event has been archived.");
    } else if(type==="contact") {
      const amount=Number(values.get("value"));if(!Number.isFinite(amount)||amount<0||amount>100000000)throw new Error("Enter an opportunity value between $0 and $100,000,000.");
      const body={name:text("name"),company:text("company"),email:text("email"),stage:text("stage"),value:amount,notes:text("notes"),...(record?{revision:record.revision}:{})};
      await api(record?`/api/admin/contacts/${encodeURIComponent(record.id)}`:"/api/admin/contacts",record?"PUT":"POST",body);editor.close();await navigate("outreach",{keepScroll:true});toast("The contact has been saved.");
    } else if(type==="post") {
      const body={title:text("title"),body:text("body"),category:text("category"),published:values.has("published"),...(record?{revision:record.revision}:{})};
      await api(record?`/api/admin/posts/${encodeURIComponent(record.id)}`:"/api/admin/posts",record?"PUT":"POST",body);editor.close();await navigate("public",{keepScroll:true});toast(body.published?"Your announcement is published.":"Your announcement is saved as a draft.");
    } else if(type==="post-unpublish") {
      await api(`/api/admin/posts/${encodeURIComponent(record.id)}/unpublish`,"POST",{revision:record.revision});editor.close();await navigate("public",{keepScroll:true});toast("The post is now a private draft.");
    } else if(type==="submission") {
      const challenge=submissionChallenge;
      if(!values.has("accept_rules"))throw new Error("Please agree to the posting rules before submitting.");
      if(!challenge || (challenge.required && !challenge.token))throw new Error("Complete verification before submitting your post.");
      const body={title:text("title"),body:text("body"),rules_version:record.rules_version,accept_rules:true,turnstile_token:challenge.token};
      if(!body.title||!body.body)throw new Error("Add a title and message before submitting your post.");
      challenge.saving=true;
      try {await api("/api/public/submissions","POST",body);}
      catch(error) {resetSubmissionChallenge(challenge);throw error;}
      finally {challenge.saving=false;}
      editor.close();state.submissionReceipt=true;await navigate("public");
    } else if(type==="submission-review") {
      await api(`/api/admin/submissions/${encodeURIComponent(record.id)}/review`,"POST",{decision:record.decision,revision:record.revision});editor.close();await navigate("public",{keepScroll:true});toast(record.decision==="approve"?"The guest post is now published.":"The guest post was rejected.");
    } else if(type==="freeze") {
      const result=await api("/api/admin/freeze","POST",record);state.frozen=result.frozen;state.freeze_revision=result.freeze_revision;editor.close();await navigate("overview",{keepScroll:true});toast(state.frozen?"Workspace changes are paused.":"Workspace changes have resumed.");
    } else if(type==="user") {
      await api(`/api/admin/users/${encodeURIComponent(record.id)}`,"PUT",{active:!record.active,revision:record.revision});editor.close();await navigate("overview",{keepScroll:true});toast(record.active?"Employee access has been paused.":"Employee access has been restored.");
    } else if(type==="password") {
      const newPassword=values.get("new_password");
      if(newPassword.length<12)throw new Error("Choose a password with at least 12 characters.");
      if(newPassword!==values.get("confirm_password"))throw new Error("The new passwords don’t match.");
      await api("/api/password","POST",{current_password:values.get("current_password"),new_password:newPassword});editor.close();setSession({});state.data={};state.guest=false;renderLogin();toast("Your password has changed. Sign in with your new password.");
    }
  } catch(error) {errorAt(error,target);}
  finally{delete form.dataset.submitting;submit.disabled=false;submit.textContent=original;updateSubmissionButton();}
});

async function start() {
  const boardLanding=location.pathname==="/board" || location.hash==="#board";
  try {const session=await api("/api/session");setSession(session);if(boardLanding){state.guest=!state.user;await navigate("public");}else if(state.user)await navigate(isAdmin()?"overview":"schedule");else renderLogin();}
  catch(error){renderLogin();errorAt(error,document.querySelector("#login-error"));}
}
start();
