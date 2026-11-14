# Reusable web presentation and delivery workflows

Generate a standalone component studio from the installed wheel:

```powershell
python -m role_aware_dashboard_toolkit init ./client-studio --web
cd client-studio
python -m http.server 8092 --bind 127.0.0.1
```

Open http://127.0.0.1:8092. Two fictional presets demonstrate the same metric,
action, progress, delivery-board and empty-state components with different brands. The studio
is browser-only presentation, not an authenticated application. `init --web`
refuses existing destinations and is mutually exclusive with `--auth`.
Use `example web --format json` to inspect files without writing them.

## Repeat a client presentation

Open **Make it your own** in the studio. Apply a brand name, headline and colors,
then choose **Export configuration**. Export saves the applied configuration,
not an unvalidated draft. Import validates a selected local JSON file without
writing to a server or changing the generated source files. Keep the exported
file to reuse the presentation:

```powershell
python -m role_aware_dashboard_toolkit init ./client-studio-branded --web --web-config ./web-presentation.json
```

The destination must be new. Configuration is validated before creating it;
`--dry-run` reports the intended files without writing them. Unknown and
duplicate fields, unsupported versions, oversized files, invalid text and
unsafe colors are rejected. The version-one file accepts `schema_version: 1`,
`preset` (`field` or `studio`), `brand`, `headline`, and all eight `theme` colors.
Omitted optional values use the selected preset's defaults. It contains no
accounts, credentials or business records. Scenario records remain fictional.

The new `WebPresentation` contract checks ten declared text/background pairs
at a minimum contrast ratio of 4.5:1. This is a bounded palette check, not a full
accessibility certification. `WebTheme` retains its existing hex-color contract.
Verify the finished application's content, focus, states and screen-reader flow.

```python
from role_aware_dashboard_toolkit.web import WebPresentation, read_web_starter

presentation = WebPresentation(preset="studio", brand="Harbor & Co.",
                               headline="A clearer day for your team.")
configuration = presentation.to_json()
same_presentation = WebPresentation.from_json(configuration)
files = read_web_starter(same_presentation)
```

The generated `web-config.js`, `web-presentation.json` and `theme.css` derive
from that configuration. Load `presentation.js` for `RADTBranding.validate`,
`parse` and `preset` in another browser host. Both Python and browser imports
validate the same fields and declared color pairs. Browser import/export and
CLI regeneration are exercised together by the disposable browser runner.

## Integrate with an existing host

```python
from role_aware_dashboard_toolkit.web import WebTheme, read_web_asset

theme = WebTheme(accent="#315C83", dark="#18364F", accent_soft="#E8EFF7")
css = theme.css()
streamlit_config = theme.streamlit_toml()
components_js = read_web_asset("components.js")
components_css = read_web_asset("components.css")
```

Serve these fixed resources through your own host. Load the theme and component
CSS, then the component JavaScript, before your application code. The Python
module requires no optional UI/server dependency. Asset names are allowlisted;
themes accept only six-digit hex colors. Contrast still requires verification.

`window.RADTWeb` exposes these HTML-producing functions:

- `metric({label, value, note, action?, tone?})`: a metric; `action` makes it a
  button. `tone: "accent"` emphasizes a primary metric.
- `action({title, description, action, count?, disabled?})`: an attention item.
- `steps(labels, current?)`: a nonempty list and zero-based current step;
  omit `current` for a neutral overview of the journey.
- `empty({title, description})`: an empty-state explanation.
- `escape(value)`: plain-text HTML escaping.
- `board({label?, lanes, items})`: responsive stage columns with counts and
  escaped cards. Lanes have unique string `id`, `label`, `description?` and
  `emptyDescription?`. Items have unique string `id`, a declared `lane`, `title`,
  `eyebrow?`, `description?`, `meta?`, `people?: [{id, name}]` and
  `actions?: [{action, label, disabled?}]`. Unknown lanes and duplicate IDs
  throw instead of silently omitting records. Actions emit `data-action` and
  `data-id`; labels include the card title for assistive technology.
- `filterItems(items, {query?, lane?, owner?})`: return a new filtered array
  without changing records. All query words must match the combined title,
  eyebrow, description, meta or people names, ignoring case. Lane and person ID
  filters are exact; empty strings disable them. This is presentation filtering,
  not authorization: only pass records the server already allows this user to see.

For example, render a client-facing work board with the same installed assets:

```javascript
const items = [{id: "job-1", lane: "scheduled", title: "Client onboarding",
  people: [{id: "alex", name: "Alex Morgan"}],
  actions: [{action: "open-work", label: "View details"}]}];
const visible = RADTWeb.filterItems(items, {query: "onboarding alex"});
document.querySelector("#board").innerHTML = RADTWeb.board({
  lanes: [{id: "scheduled", label: "Scheduled"}], items: visible
});
```

Keep search and filter controls mounted while replacing board results; this
preserves keyboard focus and input composition. Announce the result count in a
separate live region. The board reflows into stacked lanes on mobile. Explicit
action buttons let hosts collect notes and confirm transitions through their
existing protected workflow; the component supplies no drag-to-save behavior.

Components escape their text and accept only simple action identifiers. They
never fetch records or register business handlers. Handle `data-action` in the
host. Supply the metric's units, period, source and freshness in its labels and
note; do not manufacture trend comparisons. A rendered value is not evidence of
an authorized write. Disabled buttons and hidden pages confer no security.

## Guided walkthroughs

Load the shared `tour.js` resource with `components.css`. A host can introduce
its existing pages without creating an alternative sign-in path:

```javascript
const tour = RADTTour.create({
  steps: [
    {page: "overview", title: "See the outcome", body: "Open the work behind a metric."},
    {page: "work", title: "Follow through", body: "Inspect progress and handover notes."}
  ],
  onStep: async (step, {signal}) => {
    if (signal.aborted) return;
    await openAuthorizedPage(step.page);
  },
  returnFocus: () => document.querySelector("#walkthrough-button")
});
await tour.start();
// When the account changes or the host is removed:
tour.close({restoreFocus: false});
```

`create` returns a single-use `start`/`close` controller. It uses a native modal
dialog, text-only titles/bodies, keyboard focus containment, Escape dismissal,
step progress and focus restoration. The host supplies one to twenty steps,
an optional asynchronous `onStep`, optional `onClose`, and optional
`returnFocus`. Failed callbacks show a retry state without advancing. Closing
aborts the supplied signal and ignores late completion; the host must honor
that signal for its own pending effects. Create a new controller to restart.

This controller registers presentation handlers; it does not fetch, authenticate
or perform business writes. Hosts choose steps from current server-authorized
roles and enforce access again when loading pages. Close the controller on
account or session changes. Westbridge's administrator and employee sequences
use their respective existing pages. The standalone studio consumes the same
controller for its own presentation sequence.

## Source example: opportunity to delivery

Westbridge in the source distribution composes these assets with its existing
FastAPI host. The wheel includes the studio and guide, not Westbridge's host.

1. An administrator marks an outreach opportunity Won.
2. Schedule work with a time, location and active employees. The contact
   revision, schedule constraints, retry receipt, work record, assignments and
   history are checked or written within one authorized transaction.
3. Assigned employees or administrators start work with a progress note, then
   complete it with a handover note. Both work and schedule revisions must match.
4. The overview counts saved delivery states; completed work no longer adds
   upcoming team-hours or blocks new scheduling. Illustrative financials remain
   separate. Completion is a reported handover, not an invoice or payment.
5. Work opens as a stage board. Search combines project, company, place, date and
   assignee text; stage and person filters combine with it. Counts on stage
   controls describe all records returned for this user; the result line and
   lane counts describe the current filtered selection. Cards exposes the full
   handover history. Filters reset on account or role change, and overview metric
   drilldowns clear earlier search/person filters. Reloading work also clears a
   person filter when that person is no longer assigned to any returned work.
   Nothing is stored in the browser.

One opportunity has one delivery record in this first recipe. Completed work is
terminal; linked events cannot be archived, and completed schedules cannot be
edited. Employees see only their assigned work, without contact IDs, company
details, outreach notes or financial values. The existing shared team calendar
keeps its existing visibility. Extend these business rules deliberately rather
than assuming a generic CRM or multi-tenant service.

Use the existing protected workflow recipe (`guide workflows`) when adapting
these transitions. Host business policy, identity, current grants, freeze,
record scope, durable history and database transactions remain host-owned.

## Acceptance

Test both presets, keyboard controls, mobile reflow, long/untrusted text, empty
states and color contrast. Use the source runner `tools/business_delivery_browser.py`
for the real Westbridge conversion, mobile employee completion, overview drill
down, role-specific walkthroughs, branding import/export/regeneration and
component-studio reuse. It owns disposable fictional data and writes
receipts outside the checkout. It does not establish hosted or device acceptance.
