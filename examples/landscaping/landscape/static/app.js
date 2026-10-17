'use strict';

// This client only requests the current account's permitted data. The server
// independently authenticates and authorizes every operation.
const root = document.getElementById('app');
const dialog = document.getElementById('dialog');
const toastElement = document.getElementById('toast');
const SERVICES = ['mowing', 'pruning', 'planting', 'cleanup', 'irrigation'];
const STAGES = ['Lead', 'Contacted', 'Booked', 'Completed'];
const state = { session: null, workers: [], sort: 'starts_at', direction: 'asc', service: '', view: 'all', date: '', messageDraft: '', messagePosting: false, teamOpen: false, archivedOpen: false, generation: 0, authEpoch: 0 };
let toastTimer;
let dialogReturnFocus;
let lastInteraction = Date.now();
for (const eventName of ['pointerdown', 'keydown', 'wheel']) {
  window.addEventListener(eventName, event => { if (event.isTrusted) lastInteraction = Date.now(); }, { passive: true });
}

function node(tag, attrs = {}, ...children) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') element.className = value;
    else if (key === 'text') element.textContent = String(value);
    else if (key.startsWith('on') && typeof value === 'function') element.addEventListener(key.slice(2), value);
    else if (key === 'disabled' || key === 'required' || key === 'hidden' || key === 'selected') element[key] = Boolean(value);
    else element.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false) element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}
const text = (tag, content, className = '') => node(tag, { class: className, text: content });
const money = value => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 0, maximumFractionDigits: 2 }).format(Number(value) || 0);
const number = value => new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 }).format(Number(value) || 0);
const titleCase = value => String(value).charAt(0).toUpperCase() + String(value).slice(1);
const initials = value => String(value).split(/\s+/).map(part => part[0]).slice(0, 2).join('').toUpperCase();
const isAdmin = () => state.session?.user.role === 'admin';
const isFrozen = () => Boolean(state.session?.frozen);
const dateLabel = value => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
const timeLabel = value => new Date(value).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });

function button(label, onClick, style = '', extra = {}) {
  return node('button', { type: 'button', class: `button ${style}`, onclick: onClick, ...extra }, label);
}
function field(label, name, options = {}) {
  const id = options.id || name;
  let input;
  const attrs = { id, name, ...options };
  delete attrs.options;
  delete attrs.help;
  delete attrs.multiline;
  if (options.options) {
    delete attrs.type;
    input = node('select', attrs, options.options.map(option => {
      const [value, display] = Array.isArray(option) ? option : [option, titleCase(option)];
      return node('option', { value, selected: String(options.value ?? '') === String(value) }, display);
    }));
  } else if (options.multiline) {
    delete attrs.type;
    delete attrs.value;
    input = node('textarea', attrs);
    input.value = options.value || '';
  } else input = node('input', { type: 'text', ...attrs });
  const helper = options.help ? text('span', options.help, 'field-help') : null;
  if (helper) { helper.id = `${id}-help`; input.setAttribute('aria-describedby', helper.id); }
  return { wrapper: node('div', { class: 'field' }, node('label', { for: id }, label), input, helper), input };
}
function errorBox() { return node('div', { class: 'error', role: 'alert', tabindex: '-1' }); }
function showError(box, error) {
  if (error.stale) return;
  box.textContent = error.message || 'Something went wrong. Please try again.';
  box.focus();
}
function toast(message) {
  if (!message) return;
  clearTimeout(toastTimer);
  toastElement.textContent = message;
  toastElement.hidden = false;
  toastTimer = setTimeout(() => { toastElement.hidden = true; }, 5500);
}
function clearPrivateState() {
  state.authEpoch += 1;
  state.generation += 1;
  state.session = null;
  state.workers = [];
  state.view = 'all';
  state.date = '';
  state.messageDraft = '';
  state.messagePosting = false;
  state.teamOpen = false;
  state.archivedOpen = false;
  state.sort = 'starts_at';
  state.direction = 'asc';
  state.service = '';
  if (dialog.open) dialog.close();
  dialog.replaceChildren();
}
async function api(path, options = {}) {
  const authEpoch = state.authEpoch;
  const ensureCurrent = () => {
    if (authEpoch !== state.authEpoch) {
      const error = new Error('');
      error.stale = true;
      throw error;
    }
  };
  const method = options.method || 'GET';
  const headers = { Accept: 'application/json' };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && state.session?.csrf_token) headers['X-CSRF-Token'] = state.session.csrf_token;
  let response;
  try {
    response = await fetch(path, { method, headers, credentials: 'same-origin', cache: 'no-store', body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  } catch (_) { ensureCurrent(); throw new Error('Unable to reach the field office. Check your connection and try again.'); }
  ensureCurrent();
  let payload;
  try { payload = await response.json(); } catch (_) { payload = {}; }
  ensureCurrent();
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/login') {
      clearPrivateState();
      history.replaceState(null, '', '/');
      renderLogin('Your session has ended. Please sign in again.');
    }
    const error = new Error(typeof payload.detail === 'string' ? payload.detail : 'This request could not be completed. Check your entries and try again.');
    error.status = response.status;
    error.code = typeof payload.code === 'string' ? payload.code : '';
    throw error;
  }
  if (state.session && typeof payload.frozen === 'boolean') {
    state.session.frozen = payload.frozen;
    if (Number.isInteger(payload.freeze_revision)) state.session.freeze_revision = payload.freeze_revision;
    updateFreezeNotice();
  }
  return payload;
}
function brand() {
  return node('div', { class: 'brand' }, node('span', { class: 'brand-mark', 'aria-hidden': 'true' }, 'c', text('span', '↟'), 's'),
    node('div', {}, text('div', 'Cedar & Stone', 'brand-name'), text('div', 'Landscaping collective', 'brand-tag')));
}
function renderLogin(message = '') {
  document.title = 'Sign in · Cedar & Stone';
  const error = errorBox();
  if (message) error.textContent = message;
  const username = field('Username', 'username', { required: true, autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', maxlength: 32 });
  const password = field('Password', 'password', { type: 'password', required: true, autocomplete: 'current-password', maxlength: 128 });
  const submit = node('button', { type: 'submit', class: 'button', 'aria-label': 'Sign in' }, 'Sign in', text('span', '→', 'arrow'));
  const form = node('form', { onsubmit: async event => {
    event.preventDefault();
    error.textContent = '';
    submit.disabled = true;
    submit.textContent = 'Signing in…';
    try {
      const session = await api('/api/login', { method: 'POST', body: { username: username.input.value.trim(), password: password.input.value } });
      password.input.value = '';
      state.authEpoch += 1;
      state.session = session;
      navigate('/schedule', true);
    } catch (err) {
      if (err.stale) return;
      password.input.value = '';
      showError(error, err);
    } finally { submit.disabled = false; submit.replaceChildren('Sign in', text('span', '→', 'arrow')); }
  } }, error, username.wrapper, password.wrapper, submit);
  const story = node('section', { class: 'login-story', 'aria-label': 'Cedar and Stone Landscaping' }, brand(),
    node('div', { class: 'login-copy' }, text('div', 'Cedar & Stone field office', 'eyebrow'), node('h1', {}, 'Your crew.', node('br'), 'One schedule.'), text('p', 'View upcoming work, see who’s joining, and keep the crew informed.')),
    node('div', { class: 'landscape-art', 'aria-hidden': 'true' }, node('div', { class: 'sun' }), node('div', { class: 'hill' }), node('div', { class: 'tree one' }), node('div', { class: 'tree two' }), node('div', { class: 'hill hill-two' }), node('div', { class: 'path' }), node('div', { class: 'tree three' }), node('div', { class: 'hill hill-three' })),
    text('div', 'LANDSCAPING · FICTIONAL COMPANY TRIAL', 'login-foot'));
  const card = node('div', { class: 'login-card' }, text('div', 'The field office', 'eyebrow'), text('h2', 'Sign in'), text('p', 'Access the crew schedule and shared message board.', 'muted'), form,
    node('div', { class: 'login-note' }, node('strong', {}, 'A fictional company. A working dashboard.'), node('br'), 'Use the account details provided privately by your administrator. Need a password reset? Contact your admin.'));
  root.replaceChildren(node('main', { class: 'login', id: 'main-content' }, story, node('section', { class: 'login-form-side', 'aria-label': 'Sign in' }, card)));
}

function currentPage() {
  if (location.pathname === '/admin/customers') return 'customers';
  if (location.pathname === '/admin/health') return 'health';
  if (location.pathname === '/admin/metrics') return 'metrics';
  return 'work';
}
function navigate(path, replace = false) {
  if (replace) history.replaceState(null, '', path);
  else if (location.pathname !== path) history.pushState(null, '', path);
  renderApp();
}
window.addEventListener('popstate', () => { if (state.session) renderApp(); else renderLogin(); });
function navItem(label, symbol, path, active) {
  return node('a', { href: path, class: active ? 'active' : '', 'aria-current': active ? 'page' : undefined,
    onclick: event => { if (!event.ctrlKey && !event.metaKey && !event.shiftKey && event.button === 0) { event.preventDefault(); navigate(path); } } }, node('span', { class: 'nav-symbol', 'aria-hidden': 'true' }, symbol), label);
}
function updateFreezeNotice() {
  const notice = document.getElementById('freeze-notice');
  if (notice) notice.hidden = !isFrozen();
  const toggle = document.getElementById('freeze-toggle');
  if (toggle) toggle.textContent = isFrozen() ? 'Resume work' : 'Freeze work';
}
async function toggleFreeze() {
  const toggle = document.getElementById('freeze-toggle');
  if (toggle) toggle.disabled = true;
  try {
    const frozen = !isFrozen();
    await api('/api/admin/freeze', { method: 'POST', body: { frozen, expected_revision: state.session.freeze_revision } });
    toast(frozen ? 'Work is frozen. Account recovery remains available.' : 'Work resumed for the whole crew.');
    await renderApp();
  } catch (error) {
    if (error.status === 409 && state.session) {
      try { state.session = await api('/api/session'); await renderApp(); } catch (_) { /* Session handler renders sign-in. */ }
    }
    toast(error.message);
  } finally { if (toggle) toggle.disabled = false; }
}
function shell(page) {
  const admin = isAdmin();
  const user = state.session.user;
  const names = { work: 'Schedule', customers: 'Customers & outreach', health: 'Dashboard health', metrics: 'Business metrics' };
  const nav = node('nav', { class: 'nav', 'aria-label': 'Main navigation' }, navItem(names.work, '▦', '/schedule', page === 'work'));
  if (admin) nav.append(navItem(names.customers, '♧', '/admin/customers', page === 'customers'), navItem(names.health, '◷', '/admin/health', page === 'health'), navItem(names.metrics, '▥', '/admin/metrics', page === 'metrics'));
  const sidebar = node('aside', { class: 'sidebar' }, brand(), text('div', 'Your workspace', 'nav-label'), nav,
    node('div', { class: 'sidebar-bottom' }, text('div', 'FICTIONAL COMPANY TRIAL', 'sidebar-version')));
  const account = node('div', { class: 'account' }, text('span', initials(user.display_name), 'avatar'), node('div', {}, text('div', user.display_name, 'account-name'), text('div', admin ? 'Administrator' : 'Crew member', 'account-role')));
  const topbar = node('header', { class: 'topbar' }, node('div', { class: 'breadcrumb' }, 'Field office', text('span', '/'), text('strong', names[page])),
    node('div', { class: 'account-tools' }, account, button('Password', openOwnPassword, 'ghost password-button', { 'aria-label': 'Change my password' }), button('Sign out', logout, 'secondary')));
  const notice = node('div', { class: 'notice', id: 'freeze-notice', hidden: !isFrozen(), role: 'status' }, text('span', 'Work is paused. The schedule and messages remain visible; joining jobs and other business changes are temporarily unavailable.'));
  const content = node('div', { id: 'page-content' });
  const main = node('main', { class: 'page', id: 'main-content' }, notice, content, node('footer', { class: 'page-footer' }, text('span', 'Cedar & Stone · Fictional company trial'), text('span', 'Schedule times use America/New_York')));
  root.replaceChildren(node('div', { class: 'app-shell' }, sidebar, node('div', { class: 'app-body' }, topbar, main)));
  document.title = `${names[page]} · Cedar & Stone`;
  return content;
}
function heading(eyebrow, title, description, actions = []) {
  return node('div', { class: 'page-heading', 'data-testid': 'page-heading' }, node('div', {}, text('div', eyebrow, 'eyebrow'), text('h1', title), text('p', description)), node('div', { class: 'heading-actions' }, actions));
}
function stat(label, value, note, symbol = '→', featured = false) {
  return node('div', { class: `stat${featured ? ' featured' : ''}` }, text('div', label, 'stat-label'), text('div', value, 'stat-value'), text('div', note, 'stat-note'), text('span', symbol, 'stat-symbol'));
}
function panel(title, description, body, action = null, className = '') {
  return node('section', { class: `panel ${className}` }, node('div', { class: 'panel-head' }, node('div', {}, text('h2', title), description ? text('p', description) : null), action), body);
}
function empty(title, description) { return node('div', { class: 'empty' }, text('strong', title), description); }
function loading() { return node('div', { class: 'loading', role: 'status' }, node('div', { class: 'spinner', 'aria-hidden': 'true' }), 'Loading…'); }
async function renderApp() {
  if (!state.session) return renderLogin();
  const page = currentPage();
  const generation = ++state.generation;
  const content = shell(page);
  if (page !== 'work' && !isAdmin()) {
    content.append(heading('Access restricted', 'This page isn’t available.', 'This page is reserved for administrators.'), button('Go to schedule', () => navigate('/schedule')));
    return;
  }
  content.append(loading());
  try {
    let view;
    if (page === 'work') view = await workPage();
    else if (page === 'customers') view = await customersPage();
    else if (page === 'health') view = await healthPage();
    else view = await metricsPage();
    if (state.session && generation === state.generation) content.replaceChildren(...view);
  } catch (error) {
    if (state.session && generation === state.generation) {
      const box = errorBox();
      box.textContent = error.message;
      content.replaceChildren(heading('Field office', 'We couldn’t load this page.', 'Try again to get the latest information.'), box, button('Try again', renderApp));
    }
  }
}

const BUSINESS_ZONE = 'America/New_York';
let scheduleRefreshing = false;
const jobDate = value => new Date(value).toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', timeZone: BUSINESS_ZONE });
const jobTime = value => new Date(value).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', timeZone: BUSINESS_ZONE, timeZoneName: 'short' });
const businessParts = new Intl.DateTimeFormat('en-CA', { timeZone: BUSINESS_ZONE, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
function jobInputTime(value) {
  const parts = Object.fromEntries(businessParts.formatToParts(new Date(value)).map(part => [part.type, part.value]));
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}`;
}
function parseJobStart(value) {
  // datetime-local contains wall-clock text, not a timezone. Resolve it explicitly
  // in the business timezone, including rejecting repeated or skipped DST times.
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) throw new Error('Enter a complete start date and time in New York time.');
  const wall = new Date(`${value}:00Z`);
  if (!Number.isFinite(wall.getTime()) || wall.toISOString().slice(0, 16) !== value) throw new Error('Enter a valid start date and time.');
  const matches = [];
  for (let offset = -14 * 60; offset <= 14 * 60; offset += 15) {
    const candidate = new Date(wall.getTime() + offset * 60000);
    if (jobInputTime(candidate) === value) matches.push(candidate);
  }
  if (!matches.length) throw new Error('That New York time does not exist because the clocks move forward. Choose another time.');
  if (matches.length > 1) throw new Error('That New York time occurs twice when the clocks move back. Choose an unambiguous time before or after the repeated hour.');
  if (matches[0] <= new Date()) throw new Error('Choose a future start date and time.');
  return matches[0];
}
function jobStartField(label, name, value = '') {
  const start = field(label, name, { type: 'datetime-local', required: true, value, help: 'Enter New York time, even if your device is in another timezone.' });
  const preview = text('span', '', 'field-help date-preview');
  preview.setAttribute('aria-live', 'polite');
  start.wrapper.append(preview);
  start.input.setAttribute('aria-describedby', `${name}-help ${name}-preview`);
  preview.id = `${name}-preview`;
  const update = () => {
    if (!start.input.value) { preview.textContent = ''; return; }
    try { const instant = parseJobStart(start.input.value); preview.textContent = `Schedule: ${jobDate(instant)} · ${jobTime(instant)}`; }
    catch (error) { preview.textContent = error.message; }
  };
  start.input.addEventListener('input', update);
  update();
  return start;
}
function scheduleQuery() {
  const query = new URLSearchParams({ sort: state.sort, direction: state.direction, view: state.view });
  if (state.service) query.set('service', state.service);
  if (state.date) query.set('date', state.date);
  return query;
}
async function scheduleData() {
  const [data, board, team, archived] = await Promise.all([
    api(`/api/jobs?${scheduleQuery()}`), api('/api/messages'),
    isAdmin() ? api('/api/workers') : Promise.resolve(null),
    isAdmin() ? api('/api/admin/jobs?view=archived') : Promise.resolve(null),
  ]);
  return { data, board, team, archived };
}
function scheduleStats(summary) {
  return node('div', { class: 'stats', id: 'schedule-summary' },
    stat('Upcoming jobs', number(summary.total_jobs), 'Across the shared schedule', '▦', true),
    stat('Open spots', number(summary.open_spots), 'Available for crew members', '＋'),
    stat('My jobs', number(summary.my_jobs), isAdmin() ? 'Workers join jobs; admins manage' : 'Your upcoming signups', '✓'),
    stat('My hours', `${number(summary.my_hours)}h`, isAdmin() ? 'Workers join jobs; admins manage' : 'Your upcoming work hours', '◷'));
}
async function workPage() {
  const { data, board, team, archived } = await scheduleData();
  if (!state.session) return [];
  if (team) state.workers = team.workers.filter(worker => worker.role === 'worker');
  const actions = [button('Refresh', () => refreshSchedule(), 'secondary', { id: 'schedule-refresh' })];
  if (isAdmin()) actions.push(button(isFrozen() ? 'Resume work' : 'Freeze work', toggleFreeze, 'secondary', { id: 'freeze-toggle' }));
  const top = heading('Cedar & Stone', 'Crew schedule', isAdmin() ? 'Plan the work, assign the crew, and keep everyone informed.' : 'See who’s working and join a job.', actions);
  const workspace = node('div', { class: 'workspace-grid' },
    node('div', {}, jobPanel(data.jobs), isAdmin() ? archivedPanel(archived.jobs) : null, isAdmin() ? teamPanel() : null),
    node('div', { class: 'work-aside' }, messagePanel(board.messages)));
  return [top, scheduleStats(data.summary), workspace];
}
async function refreshSchedule({ automatic = false } = {}) {
  if (!state.session || currentPage() !== 'work' || scheduleRefreshing || dialog.open || state.messagePosting) return;
  // Updating data never replaces the compose form. While someone edits a form
  // or uses team controls, wait for the next refresh to avoid disrupting focus.
  if (automatic && (document.hidden || Date.now() - lastInteraction > 120000 || document.activeElement?.matches('input,textarea,select') || document.activeElement?.closest('#team-panel, #archived-jobs-panel'))) return;
  const generation = state.generation;
  const authEpoch = state.authEpoch;
  scheduleRefreshing = true;
  const refreshButton = document.getElementById('schedule-refresh');
  if (refreshButton) { refreshButton.disabled = true; refreshButton.textContent = 'Refreshing…'; }
  try {
    const { data, board, team, archived } = await scheduleData();
    if (generation !== state.generation || authEpoch !== state.authEpoch || !state.session || currentPage() !== 'work' || dialog.open || state.messagePosting) return;
    document.getElementById('schedule-summary')?.replaceWith(scheduleStats(data.summary));
    document.getElementById('job-results')?.replaceWith(jobResults(data.jobs));
    const messages = document.getElementById('message-list');
    if (messages) messages.replaceChildren(...messageItems(board.messages));
    if (team) {
      state.workers = team.workers.filter(worker => worker.role === 'worker');
      document.getElementById('team-panel')?.replaceWith(teamPanel());
    }
    if (archived) document.getElementById('archived-jobs-panel')?.replaceWith(archivedPanel(archived.jobs));
    const compose = document.getElementById('message-body');
    if (compose) compose.disabled = isFrozen();
    const post = document.getElementById('message-submit');
    if (post) post.disabled = isFrozen();
    document.querySelectorAll('[data-business-write]').forEach(control => { control.disabled = isFrozen(); });
    const updated = document.getElementById('schedule-updated');
    if (updated) updated.textContent = `Updated ${new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })} · Refreshes every 30 seconds while active`;
    if (!automatic) toast('Schedule refreshed.');
  } catch (error) {
    if (!error.stale && state.session && generation === state.generation) {
      if (automatic) {
        const updated = document.getElementById('schedule-updated');
        if (updated) updated.textContent = 'Couldn’t update. Use Refresh to try again.';
      } else toast(error.message);
    }
  } finally {
    scheduleRefreshing = false;
    if (refreshButton?.isConnected) { refreshButton.disabled = false; refreshButton.textContent = 'Refresh'; }
  }
}
setInterval(() => { refreshSchedule({ automatic: true }); }, 30000);
function jobPanel(jobs) {
  const views = [['all', 'All jobs'], ['open', 'Open jobs']];
  if (!isAdmin()) views.push(['mine', 'My jobs']);
  views.push(['history', 'Completed & cancelled']);
  const tabs = node('div', { class: 'schedule-tabs', role: 'group', 'aria-label': 'Schedule view' },
    views.map(([value, label]) =>
      button(label, () => { state.view = value; renderApp(); }, state.view === value ? 'tab active' : 'tab', { 'aria-pressed': String(state.view === value) })));
  const toolbar = node('div', { class: 'toolbar schedule-toolbar' });
  const service = field('Service', 'service-filter', { options: [['', 'All services'], ...SERVICES], value: state.service });
  service.input.addEventListener('change', () => { state.service = service.input.value; renderApp(); });
  const date = field('Date (New York)', 'date-filter', { type: 'date', value: state.date });
  date.input.addEventListener('change', () => { state.date = date.input.value; renderApp(); });
  const sort = field('Sort by', 'sort-jobs', { options: [['starts_at', 'Start date & time'], ['hours', 'Hours · number'], ['pay', 'Pay · currency'], ['service', 'Service · text'], ['customer', 'Customer · text'], ['status', 'Availability']], value: state.sort });
  sort.input.addEventListener('change', () => { state.sort = sort.input.value; renderApp(); });
  const direction = field('Order', 'sort-direction', { options: [['asc', 'Ascending ↑'], ['desc', 'Descending ↓']], value: state.direction });
  direction.input.addEventListener('change', () => { state.direction = direction.input.value; renderApp(); });
  toolbar.append(service.wrapper, date.wrapper, sort.wrapper, direction.wrapper);
  const body = node('div', {}, tabs, toolbar, jobResults(jobs), text('div', 'Refreshes every 30 seconds while active · Drafts are kept', 'schedule-updated'));
  body.lastChild.id = 'schedule-updated';
  return panel('Shared work', isAdmin() ? 'Manage crew, dates and job status. Completed and cancelled work stays in its own view.' : 'All crew members see the same jobs, signups and job status.', body,
    isAdmin() ? button('+ Schedule job', openScheduleJob, 'small', { disabled: isFrozen(), 'data-business-write': 'true' }) : null);
}
function jobResults(jobs) {
  const admin = isAdmin();
  const table = node('table', { class: 'job-table shared-jobs', role: 'table', 'aria-label': 'Shared crew schedule', 'data-testid': 'job-table' },
    node('thead', {}, node('tr', {}, ['When', 'Job / location', 'Enrolled crew', 'Hours / pay', 'Availability'].map(label => text('th', label)))),
    node('tbody', {}, jobs.map(job => {
      const started = job.status === 'started';
      const closed = ['completed', 'cancelled'].includes(job.lifecycle);
      const full = job.remaining_spots === 0;
      const status = closed ? titleCase(job.lifecycle) : started ? 'Started' : full ? 'Full' : `${job.remaining_spots} ${job.remaining_spots === 1 ? 'spot' : 'spots'} open`;
      const availability = node('div', { class: 'job-availability' }, text('span', status, `badge ${closed ? (job.lifecycle === 'completed' ? 'success' : 'gray') : started ? 'gray' : full ? 'warm' : 'success'}`));
      if (admin) {
        availability.append(button('Manage job', () => openManageJob(job.id), 'secondary small', { 'aria-label': `Manage job: ${titleCase(job.service)} at ${job.customer}` }));
      } else if (!closed) {
        const action = button(job.joined ? 'Leave job' : 'Join job', async () => {
          action.disabled = true;
          try {
            await api(`/api/jobs/${encodeURIComponent(job.id)}/signup`, job.joined ? { method: 'DELETE' } : { method: 'POST', body: {} });
            toast(job.joined ? 'You left the job. Other crew signups are unchanged.' : 'You joined the job.');
            await renderApp();
          } catch (error) { toast(error.message); if (!error.stale && state.session) await renderApp(); }
          finally { action.disabled = isFrozen() || started || (full && !job.joined); }
        }, job.joined ? 'secondary small' : 'small', {
          disabled: isFrozen() || started || (full && !job.joined),
          'aria-label': `${job.joined ? 'Leave job' : 'Join job'}: ${titleCase(job.service)} at ${job.customer}`,
        });
        availability.append(action);
      }
      const crew = node('div', { class: 'job-crew' }, text('div', `${job.signup_count} of ${job.capacity} signed up`, 'crew-count'),
        job.crew.length ? job.crew.map(person => node('div', { class: 'crew-person' }, text('span', initials(person.display_name), 'avatar'), text('span', person.display_name))) : text('div', 'No one yet', 'cell-sub'),
        job.joined ? text('div', 'You’re on this job', 'your-job-label') : null);
      return node('tr', { 'data-job-id': job.id, class: job.joined ? 'joined-row' : '' },
        node('td', { 'data-label': 'When', class: 'job-when' }, text('div', jobDate(job.starts_at), 'cell-main'), text('div', jobTime(job.starts_at), 'cell-sub')),
        node('td', { class: 'job-info' }, node('div', { class: 'job-title' }, text('span', job.service === 'irrigation' ? '◌' : '♧', 'service-icon'), node('div', {}, text('div', titleCase(job.service), 'cell-main'), text('div', job.customer, 'cell-sub'), text('div', job.site, 'cell-sub')))),
        node('td', { 'data-label': 'Enrolled crew', class: 'job-roster' }, crew),
        node('td', { 'data-label': 'Hours / pay', class: 'job-compensation' }, text('div', `${number(job.hours)}h`, 'cell-main'), text('div', `${money(job.pay)} per person`, 'cell-sub')),
        node('td', { class: 'job-actions' }, availability));
    })));
  for (const [selector, role] of [['thead,tbody', 'rowgroup'], ['tr', 'row'], ['th', 'columnheader'], ['td', 'cell']]) {
    table.querySelectorAll(selector).forEach(element => element.setAttribute('role', role));
  }
  return node('div', { id: 'job-results' }, jobs.length ? node('div', { class: 'table-wrap' }, table) : empty('No jobs in this view.', 'Try All jobs, choose another date, or clear the service filter.'),
    node('div', { class: 'table-foot' }, text('span', `${jobs.length} ${jobs.length === 1 ? 'job' : 'jobs'} shown`), text('span', 'All times: America/New_York')));
}
function archivedPanel(jobs) {
  const details = node('details', { id: 'archived-jobs-panel', class: 'panel team-details archived-jobs' },
    node('summary', {}, text('span', 'Archived jobs'), text('span', number(jobs.length), 'badge gray')),
    node('div', { class: 'team-intro' }, text('p', 'Removed from the shared schedule. Details, status and previous crew are kept here. Restoring starts with an empty crew and keeps the job’s status.')),
    jobs.length ? jobs.map(job => node('article', { class: 'archived-job', 'data-archived-job-id': job.id },
      node('div', {}, text('h3', `${titleCase(job.service)} · ${job.customer}`), text('p', `${jobDate(job.starts_at)} · ${jobTime(job.starts_at)}`), text('p', job.site), text('p', job.crew.length ? `Previous crew: ${job.crew.map(person => person.display_name).join(', ')}` : 'Previous crew: none', 'archived-crew')),
      node('div', { class: 'archived-job-actions' }, button('History', () => openManageJob(job.id), 'secondary small', { 'aria-label': `Job history: ${titleCase(job.service)} at ${job.customer}` }),
        button('Restore job', () => openRestoreJob(job.id), 'secondary small', { disabled: isFrozen(), 'data-business-write': 'true', 'aria-label': `Restore job: ${titleCase(job.service)} at ${job.customer}` })))) : empty('No archived jobs.', 'Jobs you remove from the shared schedule will appear here.'));
  details.open = state.archivedOpen;
  details.addEventListener('toggle', () => { if (details.isConnected) state.archivedOpen = details.open; });
  return details;
}
function jobDetails(job) {
  return node('div', { class: 'managed-job-details' }, text('strong', `${titleCase(job.service)} · ${job.customer}`),
    text('p', job.site), text('p', `${jobDate(job.starts_at)} · ${jobTime(job.starts_at)}`),
    text('p', `${number(job.hours)} hours · ${money(job.pay)} per person`),
    text('span', titleCase(job.lifecycle || 'scheduled'), `badge ${job.lifecycle === 'cancelled' ? 'gray' : 'success'}`));
}
function jobChangeSection({ summary, description, fields, reviewLabel, confirmLabel, prepare, submit, current, disabled, draftError }) {
  const error = errorBox();
  const preview = node('div', { class: 'job-change-preview', hidden: true, 'aria-live': 'polite' });
  const overlap = node('input', { type: 'checkbox', id: `${fields[0].input.id}-overlap` });
  const warning = node('div', { class: 'job-overlap-warning', hidden: true },
    text('strong', 'Crew schedule overlap'), text('p', '', 'overlap-description'),
    node('label', { class: 'overlap-choice', for: overlap.id }, overlap, text('span', 'I reviewed the crew schedule and accept overlapping assignments for this change.')));
  const save = node('button', { type: 'submit', class: 'button' }, reviewLabel);
  const edit = button('Edit details', () => { reset(); fields[0].input.focus(); }, 'secondary', { hidden: true });
  let prepared = null;
  let conflict = false;
  const sync = () => {
    const unavailable = disabled();
    fields.forEach(item => { item.input.disabled = unavailable; });
    overlap.disabled = unavailable;
    save.disabled = unavailable || (conflict && !overlap.checked);
    edit.disabled = unavailable;
    save.textContent = conflict ? 'Save despite overlap' : prepared ? confirmLabel : reviewLabel;
    edit.hidden = !prepared;
  };
  const reset = () => {
    prepared = null;
    conflict = false;
    overlap.checked = false;
    warning.hidden = true;
    preview.hidden = true;
    error.textContent = '';
    sync();
  };
  for (const item of fields) item.input.addEventListener('input', reset);
  overlap.addEventListener('change', sync);
  const form = node('form', { onsubmit: async event => {
    event.preventDefault();
    if (!current() || disabled()) return;
    try {
      const pending = draftError();
      if (pending) throw new Error(pending);
      if (!prepared) {
        const next = prepare();
        prepared = next.body;
        error.textContent = '';
        preview.replaceChildren(text('strong', next.summary), text('p', `Reason: ${next.body.reason}`));
        preview.hidden = false;
        sync();
        save.focus();
        return;
      }
      if (conflict && !overlap.checked) return;
      await submit({ ...prepared, acknowledge_conflicts: conflict && overlap.checked }, err => {
        conflict = true;
        overlap.checked = false;
        warning.querySelector('p').textContent = err.message;
        warning.hidden = false;
        error.textContent = '';
        sync();
        queueMicrotask(() => { if (current()) overlap.focus(); });
      }, error);
    } catch (err) { if (current()) showError(error, err); }
  } }, error, text('p', description, 'workflow-help'), fields.map(item => item.wrapper), preview, warning,
  node('div', { class: 'dialog-actions' }, edit, save));
  return { element: node('details', { class: 'job-workflow-section' }, node('summary', {}, summary), form), sync };
}
function jobHistorySection(jobId, current) {
  const content = node('div', { class: 'job-history-content', id: 'job-history-content' });
  let loaded = false;
  let busy = false;
  const details = node('details', { class: 'job-workflow-section job-history' }, node('summary', {}, 'Job history'), content);
  const formatStart = value => value ? `${new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: BUSINESS_ZONE })} · ${jobTime(value)}` : 'Not recorded';
  const load = async () => {
    if (!current() || busy) return;
    busy = true;
    content.replaceChildren(loading());
    try {
      const { history: events } = await api(`/api/admin/jobs/${encodeURIComponent(jobId)}/history`);
      if (!current()) return;
      const rows = events.map(event => {
        const before = event.before || {};
        const after = event.after || {};
        let label = 'Job updated';
        const changes = [];
        if (!event.before) label = 'Job created';
        if (before.starts_at !== after.starts_at && event.before) {
          label = 'Rescheduled';
          changes.push(`Previous start: ${formatStart(before.starts_at)}`, `New start: ${formatStart(after.starts_at)}`);
        }
        if (before.lifecycle !== after.lifecycle && event.before) {
          label = after.lifecycle === 'scheduled' ? 'Reopened' : titleCase(after.lifecycle);
          changes.push(`${titleCase(before.lifecycle || 'scheduled')} → ${titleCase(after.lifecycle)}`);
        }
        if (before.archived !== after.archived && event.before) {
          label = after.archived ? 'Archived' : 'Restored';
          changes.push(after.archived ? 'Removed from the shared schedule.' : 'Returned to the schedule.');
        }
        const names = snapshot => (snapshot.crew || []).map(person => person.display_name).join(', ') || 'None';
        if (names(before) !== names(after) && event.before) {
          if (label === 'Job updated') label = 'Crew updated';
          changes.push(`Previous crew: ${names(before)}`, `New crew: ${names(after)}`);
        }
        if (before.capacity !== after.capacity && event.before) changes.push(`Crew capacity: ${before.capacity} → ${after.capacity}`);
        if (event.action.endsWith('.overlap_acknowledged')) changes.push('The administrator reviewed and accepted a crew schedule overlap.');
        return node('li', { class: 'job-history-entry' },
          node('div', { class: 'job-history-heading' }, text('strong', label), node('time', { datetime: event.created_at }, formatStart(event.created_at))),
          text('p', `By ${event.actor}`, 'history-actor'), changes.map(change => text('p', change)),
          event.reason ? text('p', `Reason: ${event.reason}`, 'history-reason') : null);
      });
      content.replaceChildren(rows.length ? node('ol', { class: 'job-history-list' }, rows) : text('p', 'No detailed changes recorded yet. New job changes will appear here.', 'workflow-help'));
      loaded = true;
    } catch (err) {
      if (!current() || err.stale) return;
      const error = errorBox();
      content.replaceChildren(error, button('Retry history', load, 'secondary small'));
      showError(error, err);
    } finally { busy = false; }
  };
  details.addEventListener('toggle', () => { if (details.open && !loaded) load(); });
  return details;
}
function openManageJob(jobId) {
  if (!isAdmin()) return;
  const authEpoch = state.authEpoch;
  openDialog('Manage job', 'Manage the saved crew, dates and status. Save one change at a time; each change is checked again before it is applied.', container => {
    const current = () => authEpoch === state.authEpoch && isAdmin() && dialog.open && container.isConnected;
    const load = async () => {
      if (authEpoch !== state.authEpoch || !isAdmin() || !container.isConnected) return;
      container.replaceChildren(loading());
      try {
        const [data, team] = await Promise.all([api(`/api/admin/jobs/${encodeURIComponent(jobId)}`), api('/api/workers')]);
        if (!current()) return;
        const job = data.job;
        state.workers = team.workers.filter(worker => worker.role === 'worker');
        if (job.archived) {
          const history = jobHistorySection(jobId, current);
          container.replaceChildren(jobDetails(job), text('p', 'This job has been archived. Close this window and open Archived jobs to restore it.', 'dialog-copy'), history, button('Close', () => dialog.close(), 'secondary'));
          history.open = true;
          container.querySelector('button').focus();
          return;
        }
        const assigned = new Set(job.crew.map(person => person.id));
        const error = errorBox();
        let busy = false;
        let blocked = false;
        let confirmingRemoval = false;
        const workflows = [];
        const capacity = field('Crew capacity', 'manage-job-capacity', { type: 'number', min: 1, max: 10, step: 1, required: true, value: job.capacity, help: '1–10 people. Capacity must cover everyone selected.' });
        const selectedCount = text('p', '', 'crew-selection-count');
        selectedCount.setAttribute('aria-live', 'polite');
        const checkboxes = [];
        const crew = node('fieldset', { class: 'crew-picker', 'aria-describedby': 'crew-picker-help' }, node('legend', {}, 'Assigned employees'),
          text('p', 'Check to assign; uncheck to remove. You can correct a crew even after the job has started.', 'field-help'));
        crew.querySelector('p').id = 'crew-picker-help';
        for (const worker of state.workers) {
          if (!worker.active && !assigned.has(worker.id)) continue;
          const checkbox = node('input', { type: 'checkbox', id: `crew-worker-${worker.id}`, name: 'worker_ids', value: worker.id, 'aria-label': worker.display_name });
          checkbox.checked = assigned.has(worker.id);
          checkbox.dataset.active = String(worker.active);
          checkboxes.push(checkbox);
          crew.append(node('label', { class: 'crew-choice', for: checkbox.id }, checkbox, text('span', initials(worker.display_name), 'avatar'),
            node('span', {}, text('strong', worker.display_name), !worker.active ? text('small', 'Account disabled · uncheck before saving') : null)));
        }
        if (!checkboxes.length) crew.append(text('p', 'No active worker accounts. Create an account in Team accounts to assign someone.', 'field-help'));
        crew.append(selectedCount);
        const reload = button('Reload job', load, 'secondary', { hidden: true });
        const submit = node('button', { type: 'submit', class: 'button' }, 'Save crew');
        const remove = button('Remove job…', () => { confirmingRemoval = true; sync(); keep.focus(); }, 'danger');
        const keep = button('Keep job', () => { confirmingRemoval = false; sync(); remove.focus(); }, 'secondary');
        const confirm = button('Remove job', async () => {
          if (!current() || busy || blocked || isFrozen()) return;
          busy = true;
          error.textContent = '';
          sync();
          try {
            await api(`/api/admin/jobs/${encodeURIComponent(jobId)}/archive`, { method: 'POST', body: { expected_revision: job.revision } });
            if (!current()) return;
            dialog.close();
            state.archivedOpen = true;
            toast('Job removed from the schedule. You can restore it from Archived jobs.');
            await renderApp();
          } catch (err) { handleError(err); }
          finally { busy = false; if (current()) sync(); }
        }, 'danger');
        const confirmation = node('section', { class: 'job-removal-confirmation', hidden: true, 'aria-labelledby': 'remove-job-heading' },
          text('h3', 'Remove this job from the schedule?'), text('p', 'Workers will no longer see this job. The job and previous crew stay in Archived jobs. Changes remain in the audit log. You can restore it later with an empty crew. Unsaved crew changes will be discarded.'),
          node('div', { class: 'dialog-actions' }, keep, confirm));
        confirmation.querySelector('h3').id = 'remove-job-heading';
        const pause = text('p', 'Work is paused. Resume work from the schedule before changing this job.', 'job-pause-notice');
        pause.hidden = !isFrozen();
        function sync() {
          const disabled = busy || blocked || isFrozen();
          capacity.input.disabled = disabled || confirmingRemoval;
          checkboxes.forEach(checkbox => { checkbox.disabled = disabled || confirmingRemoval; });
          submit.disabled = disabled || confirmingRemoval;
          remove.disabled = disabled;
          reload.disabled = busy;
          keep.disabled = busy;
          confirm.disabled = disabled;
          remove.hidden = confirmingRemoval;
          confirmation.hidden = !confirmingRemoval;
          pause.hidden = !isFrozen();
          submit.textContent = busy && !confirmingRemoval ? 'Saving…' : 'Save crew';
          confirm.textContent = busy ? 'Removing…' : 'Remove job';
          selectedCount.textContent = `${checkboxes.filter(checkbox => checkbox.checked).length} selected · ${capacity.input.value || '0'} spots`;
          workflows.forEach(workflow => workflow.sync());
        }
        function handleError(err, box = error) {
          if (!current() || err.stale) return;
          if ([403, 404, 409, 423].includes(err.status)) {
            blocked = true;
            reload.hidden = false;
            if (err.status === 423 && state.session) { state.session.frozen = true; updateFreezeNotice(); }
            err.message += ' Reload job to review the latest information before trying again. Your entries are kept until you reload.';
          }
          showError(box, err);
        }
        async function commitChange(path, body, success, onConflict, box) {
          if (!current() || busy || blocked || isFrozen() || confirmingRemoval) return;
          busy = true;
          box.textContent = '';
          sync();
          try {
            await api(`/api/admin/jobs/${encodeURIComponent(jobId)}/${path}`, { method: path === 'schedule' ? 'PUT' : 'POST', body: { ...body, expected_revision: job.revision } });
            if (!current()) return;
            dialog.close();
            toast(success);
            if (path === 'status') state.view = body.status === 'scheduled' ? 'all' : 'history';
            if (path === 'schedule') state.date = '';
            await renderApp();
          } catch (err) {
            if (!current() || err.stale) return;
            if (err.status === 409 && err.code === 'schedule_conflict') onConflict(err);
            else handleError(err, box);
          } finally { busy = false; if (current()) sync(); }
        }
        checkboxes.forEach(checkbox => checkbox.addEventListener('change', sync));
        capacity.input.addEventListener('input', sync);
        const form = node('form', { onsubmit: async event => {
          event.preventDefault();
          if (!current() || busy || blocked || isFrozen() || confirmingRemoval) return;
          const selected = checkboxes.filter(checkbox => checkbox.checked);
          if (selected.some(checkbox => checkbox.dataset.active !== 'true')) {
            showError(error, new Error('Uncheck disabled employees before saving. Their accounts must be enabled in Team accounts before they can be assigned again.'));
            return;
          }
          const nextCapacity = Number(capacity.input.value);
          if (!Number.isInteger(nextCapacity) || nextCapacity < 1 || nextCapacity > 10 || nextCapacity < selected.length) {
            showError(error, new Error('Choose a capacity from 1 to 10 that covers everyone selected.'));
            return;
          }
          busy = true;
          error.textContent = '';
          sync();
          try {
            await api(`/api/admin/jobs/${encodeURIComponent(jobId)}/crew`, { method: 'PUT', body: { worker_ids: selected.map(checkbox => checkbox.value), capacity: nextCapacity, expected_revision: job.revision } });
            if (!current()) return;
            dialog.close();
            toast('Crew updated. Everyone sees the new assignments on the shared schedule.');
            await renderApp();
          } catch (err) { handleError(err); }
          finally { busy = false; if (current()) sync(); }
        } }, error, reload, jobDetails(job), pause, capacity.wrapper, crew,
        node('div', { class: 'dialog-actions' }, button('Cancel', () => dialog.close(), 'secondary'), submit));
        const changeReason = (label, id) => field(label, id, { multiline: true, required: true, maxlength: 500, rows: 3, help: 'Record why this change is needed. It will be kept in the job history.' });
        const disabled = () => busy || blocked || isFrozen() || confirmingRemoval;
        const draftError = () => {
          const selected = checkboxes.filter(checkbox => checkbox.checked).map(checkbox => checkbox.value);
          return Number(capacity.input.value) !== job.capacity || selected.length !== assigned.size || selected.some(id => !assigned.has(id))
            ? 'Save your crew changes first, or reload the job to discard them, before changing its date or status.' : '';
        };
        if ((job.lifecycle || 'scheduled') === 'scheduled') {
          const start = jobStartField('New start (New York)', 'reschedule-start', jobInputTime(job.starts_at));
          const reason = changeReason('Reason for rescheduling', 'reschedule-reason');
          workflows.push(jobChangeSection({ summary: 'Reschedule job', description: 'Move the job to a future time. Its saved crew stays assigned. We will warn if that time overlaps another job for a crew member.',
            fields: [start, reason], reviewLabel: 'Review new schedule', confirmLabel: 'Confirm reschedule', current, disabled, draftError,
            prepare: () => {
              const instant = parseJobStart(start.input.value);
              if (start.input.value === jobInputTime(job.starts_at)) throw new Error('Choose a different start time.');
              if (!reason.input.value.trim()) throw new Error('Enter a reason for rescheduling.');
              return { body: { starts_at: instant.toISOString(), reason: reason.input.value.trim() }, summary: `Move ${jobDate(job.starts_at)} at ${jobTime(job.starts_at)} to ${jobDate(instant)} at ${jobTime(instant)}. The saved crew stays assigned.` };
            },
            submit: (body, conflict, box) => commitChange('schedule', body, 'Job rescheduled. The shared schedule shows the new time.', conflict, box),
          }));
        }
        const closed = ['completed', 'cancelled'].includes(job.lifecycle);
        const statusOptions = closed ? [['scheduled', 'Reopen as scheduled']] : [['cancelled', 'Cancel job'], ['completed', 'Mark completed']];
        const nextStatus = field('New job status', 'job-status-choice', { options: statusOptions });
        if (!closed && new Date(job.starts_at) > new Date()) nextStatus.input.querySelector('option[value="completed"]').disabled = true;
        const statusReason = changeReason('Reason for status change', 'job-status-reason');
        workflows.push(jobChangeSection({ summary: closed ? 'Reopen job' : 'Complete or cancel job',
          description: closed ? 'Reopen to correct the schedule. The saved crew remains assigned; review it before reopening. Reopened past jobs remain unavailable for worker signups.' : 'Completed and cancelled jobs remain visible to the crew in Completed & cancelled. Completion is available once the job has started. Crew assignments and history are kept.',
          fields: [nextStatus, statusReason], reviewLabel: 'Review status change', confirmLabel: 'Confirm status change', current, disabled, draftError,
          prepare: () => {
            if (!statusReason.input.value.trim()) throw new Error('Enter a reason for this status change.');
            if (nextStatus.input.value === 'completed' && new Date(job.starts_at) > new Date()) throw new Error('A future job cannot be marked completed.');
            const summaries = { completed: 'Mark this job completed and close worker signups.', cancelled: 'Cancel this job and close worker signups.', scheduled: 'Reopen this job as scheduled with its saved crew.' };
            return { body: { status: nextStatus.input.value, reason: statusReason.input.value.trim() }, summary: summaries[nextStatus.input.value] };
          },
          submit: (body, conflict, box) => commitChange('status', body, body.status === 'scheduled' ? 'Job reopened on the shared schedule.' : `Job ${body.status}. It remains visible in Completed & cancelled.`, conflict, box),
        }));
        container.replaceChildren(form, ...workflows.map(workflow => workflow.element), jobHistorySection(jobId, current), node('div', { class: 'job-removal' }, remove, confirmation));
        sync();
        const focus = isFrozen() ? form.querySelector('button:not([hidden]):not(:disabled)') : capacity.input;
        focus?.focus();
      } catch (err) {
        if (!current() || err.stale) return;
        const error = errorBox();
        container.replaceChildren(error, button('Reload job', load, 'secondary'));
        showError(error, err);
      }
    };
    load();
  });
}
function openRestoreJob(jobId) {
  if (!isAdmin()) return;
  const authEpoch = state.authEpoch;
  openDialog('Restore job?', 'This returns the job to the shared schedule with an empty crew. Assign employees again after restoring.', container => {
    const current = () => authEpoch === state.authEpoch && isAdmin() && dialog.open && container.isConnected;
    const load = async () => {
      if (authEpoch !== state.authEpoch || !isAdmin() || !container.isConnected) return;
      container.replaceChildren(loading());
      try {
        const { job } = await api(`/api/admin/jobs/${encodeURIComponent(jobId)}`);
        if (!current()) return;
        const error = errorBox();
        const reload = button('Reload job', load, 'secondary', { hidden: true });
        let busy = false;
        const submit = button('Restore job', async () => {
          if (!current() || busy || isFrozen() || !job.archived) return;
          busy = true;
          submit.disabled = true;
          submit.textContent = 'Restoring…';
          error.textContent = '';
          try {
            await api(`/api/admin/jobs/${encodeURIComponent(jobId)}/restore`, { method: 'POST', body: { expected_revision: job.revision } });
            if (!current()) return;
            dialog.close();
            state.view = ['completed', 'cancelled'].includes(job.lifecycle) ? 'history' : 'all';
            state.date = '';
            state.service = '';
            toast(`Job restored with an empty crew. Its status remains ${job.lifecycle || 'scheduled'}. Use Manage job to make changes.`);
            await renderApp();
          } catch (err) {
            if (!current() || err.stale) return;
            reload.hidden = false;
            showError(error, err);
          } finally { submit.textContent = 'Restore job'; }
        }, '', { disabled: isFrozen() || !job.archived });
        container.replaceChildren(error, reload, jobDetails(job),
          !job.archived ? text('p', 'This job is already on the shared schedule.', 'dialog-copy') : null,
          isFrozen() ? text('p', 'Work is paused. Resume work from the schedule before restoring this job.', 'job-pause-notice') : null,
          node('div', { class: 'dialog-actions' }, button('Cancel', () => dialog.close(), 'secondary'), submit));
        container.querySelector('.dialog-actions button').focus();
      } catch (err) {
        if (!current() || err.stale) return;
        const error = errorBox();
        container.replaceChildren(error, button('Reload job', load, 'secondary'));
        showError(error, err);
      }
    };
    load();
  });
}
function messageItems(messages) {
  if (!messages.length) return [empty('No messages yet.', 'Share an update with the crew.')];
  return messages.map(message => node('article', { class: 'message' }, node('div', { class: 'message-heading' }, text('span', initials(message.author), 'avatar'), text('span', message.author, 'message-author'), node('time', { datetime: message.created_at, title: new Date(message.created_at).toLocaleString() }, dateLabel(message.created_at))), text('p', message.body)));
}
function messagePanel(messages) {
  const list = node('div', { class: 'messages', id: 'message-list', 'data-testid': 'message-list' }, messageItems(messages));
  const error = errorBox();
  const body = field('Message to the crew', 'message-body', { multiline: true, required: true, maxlength: 1000, placeholder: 'Write an update or ask a question…', disabled: isFrozen() || state.messagePosting, value: state.messageDraft });
  const count = text('span', `${number(state.messageDraft.length)} / 1,000`);
  body.input.addEventListener('input', () => { state.messageDraft = body.input.value; count.textContent = `${number(body.input.value.length)} / 1,000`; });
  const submit = node('button', { type: 'submit', class: 'button small', id: 'message-submit', disabled: isFrozen() || state.messagePosting, 'aria-label': 'Post message' }, 'Post message');
  const compose = node('form', { class: 'message-compose', onsubmit: async event => {
    event.preventDefault();
    if (state.messagePosting) return;
    if (!body.input.value.trim()) { showError(error, new Error('Write a message before posting.')); return; }
    const authEpoch = state.authEpoch;
    state.messagePosting = true;
    submit.disabled = true;
    body.input.disabled = true;
    error.textContent = '';
    try {
      await api('/api/messages', { method: 'POST', body: { body: body.input.value.trim() } });
      state.messagePosting = false;
      state.messageDraft = '';
      toast('Message shared with the crew.');
      await renderApp();
    } catch (err) { showError(error, err); }
    finally {
      if (authEpoch === state.authEpoch) {
        state.messagePosting = false;
        const currentBody = document.getElementById('message-body');
        const currentSubmit = document.getElementById('message-submit');
        if (currentBody) currentBody.disabled = isFrozen();
        if (currentSubmit) currentSubmit.disabled = isFrozen();
      }
    }
  } }, error, body.wrapper, node('div', { class: 'compose-actions' }, count, submit));
  return panel('Crew board', 'Shared with everyone on the team.', node('div', {}, list, compose));
}
function teamPanel() {
  const rows = state.workers.map(worker => node('div', { class: 'account-row' }, node('div', { class: 'account-person' }, text('span', initials(worker.display_name), 'avatar'), node('div', {}, text('strong', worker.display_name), text('small', `@${worker.username}`))),
    node('div', { class: 'row-actions' }, text('span', worker.active ? 'Active' : 'Disabled', `badge ${worker.active ? 'success' : 'gray'}`),
      button('Reset password', () => openResetPassword(worker), 'secondary small', { 'aria-label': `Reset password for ${worker.display_name}` }),
      button(worker.active ? 'Disable' : 'Enable', () => openAccountStatus(worker), worker.active ? 'danger small' : 'secondary small', { 'aria-label': `${worker.active ? 'Disable' : 'Enable'} ${worker.display_name}` }))));
  const details = node('details', { id: 'team-panel', class: 'panel team-details' },
    node('summary', {}, text('span', 'Team accounts'), text('span', `${state.workers.length} workers`, 'badge gray')),
    node('div', { class: 'team-intro' }, text('p', 'Create worker accounts, reset passwords, or manage access.'), button('+ Create account', openCreateAccount, 'small', { disabled: isFrozen(), 'data-business-write': 'true' })),
    rows.length ? rows : empty('No worker accounts.', 'Create an account to add a crew member.'));
  details.open = state.teamOpen;
  details.addEventListener('toggle', () => { if (details.isConnected) state.teamOpen = details.open; });
  return details;
}

function openDialog(title, description, build) {
  if (!dialog.open) dialogReturnFocus = document.activeElement;
  dialog.replaceChildren();
  const close = button('×', () => dialog.close(), '', { class: 'dialog-close', 'aria-label': 'Close dialog' });
  const content = node('div');
  dialog.append(node('div', { class: 'dialog-header' }, node('h2', { id: 'dialog-title' }, title), close), text('p', description, 'dialog-copy'), content);
  build(content);
  dialog.showModal();
  const focusable = content.querySelector('input:not([type=hidden]):not(:disabled), select:not(:disabled), textarea:not(:disabled), button:not([hidden]):not(:disabled)');
  if (focusable) focusable.focus();
}
dialog.addEventListener('close', () => {
  dialog.querySelectorAll('input[type=password]').forEach(input => { input.value = ''; });
  dialog.replaceChildren();
  if (dialogReturnFocus?.isConnected) dialogReturnFocus.focus();
});
function modalForm(container, fields, submitLabel, onSubmit) {
  const error = errorBox();
  const submit = node('button', { type: 'submit', class: 'button' }, submitLabel);
  const cancel = button('Cancel', () => dialog.close(), 'secondary');
  const form = node('form', { onsubmit: async event => {
    event.preventDefault();
    error.textContent = '';
    submit.disabled = true;
    submit.textContent = 'Saving…';
    try { await onSubmit(); }
    catch (err) { if (dialog.open) showError(error, err); else toast(err.message); }
    finally { submit.disabled = false; submit.textContent = submitLabel; }
  } }, error, fields.map(item => item.wrapper || item), node('div', { class: 'dialog-actions' }, cancel, submit));
  container.append(form);
}
function passwordField(label, name, current = false) {
  return field(label, name, { type: 'password', required: true, minlength: current ? undefined : 12, maxlength: 128, autocomplete: current ? 'current-password' : 'new-password', help: current ? undefined : 'Use 12–128 characters. Share this password privately.' });
}
function openOwnPassword() {
  openDialog('Change your password', 'Changing your password signs you out on every device, including this one.', container => {
    const current = passwordField('Current password', 'current-password', true);
    const next = passwordField('New password', 'new-password');
    modalForm(container, [current, next], 'Change password', async () => {
      await api('/api/password', { method: 'POST', body: { current_password: current.input.value, new_password: next.input.value } });
      clearPrivateState();
      history.replaceState(null, '', '/');
      renderLogin('Password changed. Sign in with your new password.');
    });
  });
}
function openCreateAccount() {
  openDialog('Create worker account', 'New workers can view the shared schedule, join available jobs, and post to the crew board.', container => {
    const display = field('Full name', 'account-name', { required: true, maxlength: 80, autocomplete: 'off' });
    const username = field('Username', 'account-username', { required: true, minlength: 3, maxlength: 32, pattern: '[a-z][a-z0-9_]{2,31}', autocapitalize: 'none', spellcheck: 'false', autocomplete: 'off', help: '3–32 lowercase letters, numbers, or underscores. Start with a letter.' });
    const password = passwordField('Initial password', 'account-password');
    modalForm(container, [display, username, password], 'Create account', async () => {
      await api('/api/admin/users', { method: 'POST', body: { username: username.input.value.trim(), display_name: display.input.value.trim(), password: password.input.value } });
      dialog.close();
      state.teamOpen = true;
      toast('Account created. Share the password privately. The worker can now access the shared schedule.');
      await renderApp();
    });
  });
}
function openResetPassword(worker) {
  openDialog(`Reset ${worker.display_name.split(' ')[0]}’s password`, 'Every existing session for this worker ends immediately. Share the replacement password privately.', container => {
    const password = passwordField('Replacement password', 'replacement-password');
    modalForm(container, [password], 'Reset password', async () => {
      await api(`/api/admin/users/${encodeURIComponent(worker.id)}/password`, { method: 'POST', body: { password: password.input.value } });
      dialog.close();
      toast(`Password reset for ${worker.display_name}. Existing sessions are signed out.`);
    });
  });
}
function openAccountStatus(worker) {
  openDialog(`${worker.active ? 'Disable' : 'Enable'} ${worker.display_name}?`, worker.active ? 'This signs the worker out and prevents new sign-ins. Their upcoming job signups are removed to free those spots. Past work and messages are retained.' : 'This worker will be able to sign in again with their current password.', container => {
    modalForm(container, [], worker.active ? 'Disable account' : 'Enable account', async () => {
      await api(`/api/admin/users/${encodeURIComponent(worker.id)}`, { method: 'PATCH', body: { active: !worker.active } });
      dialog.close();
      toast(`${worker.display_name}’s account is ${worker.active ? 'disabled' : 'enabled'}.`);
      await renderApp();
    });
  });
}
function openScheduleJob() {
  openDialog('Schedule a job', 'The whole crew will see this job. Workers can join until its crew is full.', container => {
    const customer = field('Customer', 'job-customer', { required: true, maxlength: 80 });
    const site = field('Work location', 'job-site', { required: true, maxlength: 200 });
    const service = field('Service', 'job-service', { required: true, options: SERVICES });
    const start = jobStartField('Start date & time (New York)', 'job-start');
    const capacity = field('Crew size', 'job-capacity', { required: true, type: 'number', min: 1, max: 10, step: 1, value: 2, help: '1–10 workers may join this job.' });
    const hours = field('Hours', 'job-hours', { required: true, type: 'number', min: 0.25, max: 24, step: 0.25, value: 2 });
    const pay = field('Pay per person ($)', 'job-pay', { required: true, type: 'number', min: 0, max: 100000, step: 0.01, value: 60 });
    modalForm(container, [customer, site, service, start, capacity, node('div', { class: 'form-grid' }, hours.wrapper, pay.wrapper)], 'Schedule job', async () => {
      const instant = parseJobStart(start.input.value);
      await api('/api/admin/jobs', { method: 'POST', body: { customer: customer.input.value.trim(), site: site.input.value.trim(), service: service.input.value, starts_at: instant.toISOString(), hours: Number(hours.input.value), pay: Number(pay.input.value), capacity: Number(capacity.input.value) } });
      dialog.close();
      toast('Job added to the shared schedule.');
      state.service = '';
      state.date = '';
      state.view = 'all';
      await renderApp();
    });
  });
}
async function logout() {
  try {
    await api('/api/logout', { method: 'POST', body: {} });
    clearPrivateState();
    history.replaceState(null, '', '/');
    renderLogin();
    toast('You’re signed out. See you in the field.');
  } catch (error) { if (state.session) toast(error.message); }
}

async function customersPage() {
  const { customers } = await api('/api/admin/customers');
  if (!state.session) return [];
  const totalValue = customers.reduce((sum, customer) => sum + customer.value, 0);
  const cards = node('div', { class: 'customer-grid' }, customers.map(customer => {
    const stage = field('Outreach stage', `customer-stage-${customer.id}`, { options: STAGES, value: customer.stage, disabled: isFrozen() });
    const notes = field('Follow-up notes', `customer-notes-${customer.id}`, { multiline: true, maxlength: 2000, value: customer.notes, disabled: isFrozen() });
    const error = errorBox();
    const save = node('button', { type: 'submit', class: 'button secondary', disabled: isFrozen() }, 'Save follow-up');
    return node('article', { class: 'customer-card' }, node('div', { class: 'customer-top' }, node('div', {}, text('div', titleCase(customer.service), 'eyebrow'), text('h3', customer.name)), text('span', customer.stage, `badge ${customer.stage === 'Booked' ? 'success' : 'warm'}`)),
      text('p', customer.contact), text('div', money(customer.value), 'customer-value'),
      node('form', { onsubmit: async event => {
        event.preventDefault(); save.disabled = true; error.textContent = '';
        try { await api(`/api/admin/customers/${encodeURIComponent(customer.id)}`, { method: 'PATCH', body: { stage: stage.input.value, notes: notes.input.value } }); toast('Customer follow-up saved.'); await renderApp(); }
        catch (err) { showError(error, err); }
        finally { save.disabled = isFrozen(); }
      } }, error, stage.wrapper, notes.wrapper, save));
  }));
  return [heading('Administration', 'Customers & outreach', 'Manage customer details, outreach stages, and follow-ups.', [button('+ Add customer', openCustomer, '', { disabled: isFrozen() })]),
    node('div', { class: 'stats' }, stat('Customer relationships', customers.length, 'Fictional trial customer data', '♧', true), stat('New leads', customers.filter(customer => customer.stage === 'Lead').length, 'Awaiting initial contact', '→'), stat('Booked customers', customers.filter(customer => customer.stage === 'Booked').length, 'Customers with booked work', '✓'), stat('Total customer value', money(totalValue), 'All customer stages', '$')),
    customers.length ? cards : empty('No customers yet.', 'Add a customer to track outreach.')];
}
function openCustomer() {
  openDialog('Add customer', 'Add a fictional customer to this trial. Contact details stay in the administrator workspace.', container => {
    const name = field('Customer name', 'customer-name', { required: true, maxlength: 80 });
    const contact = field('Contact details', 'customer-contact', { required: true, maxlength: 200 });
    const service = field('Service', 'customer-service', { required: true, options: SERVICES });
    const stage = field('Outreach stage', 'customer-stage', { required: true, options: STAGES });
    const value = field('Estimated value ($)', 'customer-value', { required: true, type: 'number', min: 0, max: 10000000, step: 0.01, value: 0 });
    const notes = field('Follow-up notes', 'customer-notes', { multiline: true, maxlength: 2000 });
    modalForm(container, [name, contact, node('div', { class: 'form-grid' }, service.wrapper, stage.wrapper), value, notes], 'Add customer', async () => {
      await api('/api/admin/customers', { method: 'POST', body: { name: name.input.value.trim(), contact: contact.input.value.trim(), service: service.input.value, stage: stage.input.value, value: Number(value.input.value), notes: notes.input.value } });
      dialog.close(); toast('Customer added.'); await renderApp();
    });
  });
}
async function healthPage() {
  const data = await api('/api/admin/health');
  if (!state.session) return [];
  const telemetry = data.telemetry;
  const audit = node('table', { 'aria-label': 'Security and activity audit' }, node('thead', {}, node('tr', {}, ['Time', 'Account', 'Action', 'Target', 'Outcome'].map(label => text('th', label)))),
    node('tbody', {}, data.audit.map(event => node('tr', {}, node('td', {}, text('div', dateLabel(event.created_at), 'cell-main'), text('div', timeLabel(event.created_at), 'cell-sub')), text('td', event.actor), text('td', event.action), text('td', event.target), node('td', {}, text('span', event.outcome, `badge ${['denied', 'failure', 'failed'].includes(event.outcome) ? 'red' : 'success'}`))))));
  const about = node('div', { class: 'panel-body evidence' }, text('p', 'These counters measure this running trial app. Audit entries are recorded by the server; the browser does not supply the acting account.'),
    node('p', {}, text('strong', 'Toolkit version: '), data.toolkit.version, node('br'), text('strong', 'Toolkit example: '), text('span', data.toolkit.integration, 'mono')), text('p', 'This is a local trial with fictional business data. It is not a production monitoring or identity-provider deployment.'));
  return [heading('Administration', 'Dashboard health', 'Live telemetry and server-recorded account activity.', [button(isFrozen() ? 'Resume work' : 'Freeze work', toggleFreeze, 'secondary', { id: 'freeze-toggle' }), button('Refresh', renderApp, 'secondary')]),
    node('div', { class: 'stats' }, stat('Requests handled', number(telemetry.requests), 'Recorded in this trial', '→', true), stat('Requests denied', number(telemetry.denied_requests), 'Access boundaries enforced', '⊘'), stat('Active sessions', number(telemetry.active_sessions), 'Current server sessions', '♧'), stat('Response time · p95', `${number(telemetry.p95_ms)}ms`, 'Measured request latency', '◷')),
    node('div', { class: 'two-columns' }, panel('At a glance', 'Actual runtime counters, not fictional business metrics.', node('div', { class: 'panel-body' }, node('div', { class: 'pipeline-row' }, text('span', 'App uptime'), text('strong', `${number(telemetry.uptime_seconds / 60)} min`)), node('div', { class: 'pipeline-row' }, text('span', 'Failed sign-ins'), text('strong', number(telemetry.failed_logins))), node('div', { class: 'pipeline-row' }, text('span', 'Business writes'), text('span', isFrozen() ? 'Paused by admin' : 'Open for the crew', `badge ${isFrozen() ? 'warm' : 'success'}`)))), panel('Built on explicit access', 'The app checks permissions for every protected operation.', about)),
    panel('Activity audit', 'Recent bounded audit entries. Passwords and session tokens never belong here.', data.audit.length ? node('div', { class: 'table-wrap' }, audit) : empty('No activity recorded yet.', 'Protected actions will appear here.'))];
}
async function metricsPage() {
  const { metrics, by_service: services, pipeline } = await api('/api/admin/metrics');
  if (!state.session) return [];
  const maxRevenue = Math.max(1, ...services.map(service => service.revenue));
  const serviceRows = node('div', { class: 'panel-body' }, services.map(service => {
    const meter = node('meter', { min: 0, max: maxRevenue, value: service.revenue, 'aria-label': `${titleCase(service.service)} revenue`, class: 'revenue-meter' });
    return node('div', { class: 'chart-row' }, text('span', titleCase(service.service)), meter, text('span', money(service.revenue), 'chart-value'));
  }), text('p', 'Booked and completed customer value by service, from current trial records.', 'evidence'));
  const pipelineRows = node('div', { class: 'panel-body' }, pipeline.map(stage => node('div', { class: 'pipeline-row' }, node('div', {}, text('span', stage.stage), text('small', `${stage.count} ${stage.count === 1 ? 'customer' : 'customers'}`)), text('strong', money(stage.value)))));
  return [heading('Administration', 'Business metrics', 'Calculated from the fictional company’s current records.', [button('Refresh', renderApp, 'secondary')]),
    node('div', { class: 'stats' }, stat('Pipeline value', money(metrics.pipeline_value), 'Lead and contacted customers', '$', true), stat('Booked revenue', money(metrics.booked_revenue), 'Booked and completed customers', '→'), stat('Scheduled hours', `${number(metrics.scheduled_hours)}h`, 'Scheduled jobs only', '◷'), stat('Signup rate', `${number(metrics.signup_rate * 100)}%`, 'Occupied spots on scheduled jobs', '✓')),
    node('div', { class: 'two-columns' }, panel('Booked revenue, by service', 'Value of booked and completed customer work.', serviceRows), panel('Customer pipeline', 'Customer counts and value by stage.', pipelineRows)),
    panel('Workforce & schedule', 'Current crew and job counts. Archived jobs are excluded.', node('div', { class: 'panel-body' }, node('div', { class: 'pipeline-row' }, text('span', 'Active crew members'), text('strong', number(metrics.active_workers))), node('div', { class: 'pipeline-row' }, text('span', 'Scheduled jobs'), text('strong', number(metrics.total_jobs))), node('div', { class: 'pipeline-row' }, text('span', 'Completed jobs'), text('strong', number(metrics.completed_jobs))), node('div', { class: 'pipeline-row' }, text('span', 'Cancelled jobs'), text('strong', number(metrics.cancelled_jobs))), text('p', 'Job completion updates the job counts; customer values remain separate from job status. These are trial records, not invoiced or collected revenue.', 'evidence')))];
}

async function start() {
  try {
    state.session = await api('/api/session');
    if (location.pathname === '/' || location.pathname.startsWith('/work/')) history.replaceState(null, '', '/schedule');
    await renderApp();
  } catch (error) {
    if (error.stale) return;
    if (error.status === 401) renderLogin();
    else renderLogin(error.message);
  }
}
start();
