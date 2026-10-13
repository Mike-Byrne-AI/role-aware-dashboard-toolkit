# Dashboard tools

Role-Aware Dashboard Toolkit separates dashboard state from dashboard rendering. You can define and
test controls, roles, profiles, audit behavior, and configuration with the core
install; Streamlit is imported only when `render()` is called.

## Install

For the local source candidate:

```powershell
python -m pip install -e ".[workbench,dev]"
```

Only after a separate PyPI release, install the core library or the Streamlit extra:

```powershell
python -m pip install role-aware-dashboard-toolkit
python -m pip install "role-aware-dashboard-toolkit[workbench]"
```

## Define controls

```python
import role_aware_dashboard_toolkit as radt

registry = radt.ControlRegistry()
registry.register(
    "Request timeout",
    kind="slider",
    key="request_timeout_seconds",
    group="Operations",
    min_value=1,
    max_value=120,
    step=1,
    default=30,
)
registry.register(
    "Maintenance mode",
    kind="toggle",
    key="maintenance_mode",
    group="Safeguards",
    default=False,
)
```

Supported control kinds are `slider`, `toggle`, `number`, `select`, `text`, and
`color`. Keys must be unique. Numeric bounds, select options, defaults, and
callbacks live on the `ControlDef`, not in the renderer.

Controls whose name or key looks sensitive are marked sensitive automatically;
you can also pass `sensitive=True`. Sensitive values are omitted from durable
profiles and redacted from audit and API response surfaces.
For a nonsecret field matched by this heuristic, such as `max_tokens`, explicitly
pass `sensitive=False` to retain its ordinary widget and profile values.
Sensitive UI fields use a blank replacement form, including non-text kinds;
read-only users see only `Hidden`. Stored values and select options are never
prefilled or sent to the browser. See the installed
[controls guide](../role_aware_dashboard_toolkit/resources/guides/controls.md)
for replacement formats and explicit text clearing.

## Configure the dashboard

```python
config = radt.DashboardConfig(
    auth_mode="demo",
    title="Service controls",
    subtitle="Changes are explicit and auditable.",
    registry=registry,
    audit=radt.AuditLog(),
    layout="columns",
    columns_per_row=2,
)

context = radt.render(config)
```

`render()` returns a `SecurityContext` containing the active role, permissions,
and current write-policy state.

Useful `DashboardConfig` collaborators include:

- `profile_store` for custom profile persistence
- `plugins` for trusted sidebar and panel hooks
- `observability` for telemetry sampling
- `run_store` for run/checkpoint panels
- explicit team, decision, memory, case, and governance stores
- `auth_mode="demo"` for the local demo where each user picks a role; it is
  required when neither `access` nor `auth_hook` is given, so a missing access
  policy never falls back to the demo
- `access` and `auth_mode="authenticated"` for verified identity, assigned roles,
  and shared freeze
- `auth_hook` for existing host-managed role integrations

The optional record stores are module-level APIs; see
[the public API reference](public_api.md).

## Roles and write policy

Each control declares a permission key, defaulting to
`can_edit_controls`. A write requires both:

1. the active role grants the control's permission; and
2. the dashboard write-policy switch is enabled.

```python
custom_roles = {
    "Release Lead": radt.RoleDef(
        name="Release Lead",
        description="Can update controls and manage profiles.",
        perms={
            "can_edit_controls": True,
            "can_view_audit": True,
            "can_save_profiles": True,
            "can_load_profiles": True,
            "can_view_metrics": True,
        },
    )
}
```

Demo mode permits self-selected roles and does not authenticate users. A new
demo session starts in its least-privileged role (Viewer for the built-in
roles); pick another role in the sidebar. Only a role with `can_manage_freeze`
can change Controls Writable. For a shared dashboard, start with `init shared-dashboard --auth` and follow the
[authentication guide](../role_aware_dashboard_toolkit/resources/guides/authentication.md).
Verified users can select only server-assigned roles, and protected writes
recheck identity, grants and shared freeze. Call the module-level
`dashboard.prepare_access(config)` before loading protected host data. Existing
`auth_hook` integrations remain supported; deployment credentials, TLS, filesystem
permissions and authorization of custom host operations remain host duties.

## Profiles

Profiles persist the registry's non-sensitive values. Use in-memory stores for
tests and embedded applications, or a file store for trusted local storage.

```python
store = radt.InMemoryProfileStore()
state: dict[str, object] = {}
registry.ensure_defaults(state)

radt.save_profile(
    "baseline",
    registry,
    state,
    role="Release Lead",
    store=store,
)

loaded = radt.load_profile("baseline", registry, state, store=store)
```

Loading a profile restores only registered, persistable values and reports how
many stale or out-of-range values were corrected. Missing profile fields retain
their existing live values. Sensitive values remain in memory and are never
restored from a profile. A saved role is provenance only: loading cannot change
the active role, grant permissions, or override an auth hook.

Selecting a profile previews it; only a successful load marks it active. Runs
record the loaded profile as their source at start and refresh the active
profile identifier at checkpoint capture and completion.

Native profile saves use the selected profile as a parent. Before deriving the
parent diff, they omit historically sensitive fields and values containing nested
secret fields, as well as currently sensitive controls. The parent record is
unchanged unless the operator explicitly confirms replacing it.

Profile store I/O and path-security failures appear inline without resetting
controls or recording a successful load/save/delete. File-store read diagnostics
also remain visible; unreadable records are not silently overwritten.
Dashboard profile loading requires `can_load_profiles`, an enabled write-policy
switch, and each restored control's declared permission. All controls are checked
before any live value changes; a denied control rejects the entire load.
Checkpoint replay follows the same rule with `can_replay_runs` as its action
permission. In Streamlit, replay is staged after the current widgets render and
applied before control creation on the following render. That application
rechecks the current role, writable switch, and every affected control permission.
Native sidebar reruns retain all registered live values, including sensitive,
hidden, and frozen controls.

Packet export does not override visibility permissions. Full run and checkpoint
packet previews require `can_export_packets`, `can_view_metrics`, and
`can_view_audit`; replay previews require export and metrics access.
Native historical output also reapplies current and recorded control sensitivity
before building summaries or comparisons. Read/export permission never makes a
sensitive historical value public, and projection does not rewrite the evidence.

## Audit

`AuditLog` always keeps bounded in-memory history. It can also use the
file-backed audit store for JSONL persistence.

Audit permissions are intentionally split: `can_view_audit` permits inspection,
while `can_manage_audit` permits clearing the in-memory log and changing the
JSONL writer lifecycle. The built-in `Admin` role is the only role granted
`can_manage_audit`; custom roles must opt in explicitly.

The JSONL file is append-only; the in-memory view is bounded and clearable.
`AuditLog.clear()` records an `audit_cleared` event (`old` holds the number of
events cleared) as the view's first entry and sends it to a running writer, so
the file shows who cleared the view and when. The file is never truncated.

The audit CSV download is a spreadsheet-oriented view: fields are quoted and
formula-like text is prefixed with an apostrophe, including formula prefixes
after whitespace or Unicode formatting characters. This formula escaping changes
only the CSV view. The Timeline table shows the same protected cells, so its
built-in CSV download carries the same protection. Both native downloads first
redact currently sensitive historical values; the stored audit events remain
unchanged.
NUL characters are displayed as literal `\x00` text so CSV readers, including
Python 3.10's reader, can import the download. Use JSONL for faithful
machine-readable evidence. Spreadsheet applications and
subsequent CSV re-exports can remove text protection, so downstream exports must
apply their own spreadsheet policy.

```python
audit = radt.AuditLog()
audit.log_control_change(
    "maintenance_mode",
    False,
    True,
    role="Release Lead",
)
print(audit.recent(10))
```

Persistence failures remain visible through writer status and runtime
diagnostics; in-memory events stay available. If an append fails partway (a
full disk) or a process dies mid-append, the next event starts on a new line;
`FileAuditStore.read_all()` skips the torn line and reports it in
`read_errors`.

### Persist every session's events

The JSONL writer belongs to one `AuditLog` object and persists only the events
logged to that object. To get every session's and every role's events on disk,
share one `AuditLog` per process and start its writer where you create it:

```python
import streamlit as st
import role_aware_dashboard_toolkit as radt


@st.cache_resource
def shared_audit() -> radt.AuditLog:
    audit = radt.AuditLog()
    audit.start_writer("audit_logs/audit.jsonl")
    return audit


config = radt.DashboardConfig(auth_mode="demo", registry=registry, audit=shared_audit(), audit_dir="audit_logs")
```

A dashboard render never starts or stops the writer: not when the writer form
is hidden, not for a role without `can_manage_audit`, and not because another
session's form last showed a different value. The form shows the writer's live
state to every role. Only an explicit change by a role with `can_manage_audit`
starts, stops or moves it: turning the toggle, or editing the path while the
writer runs. A path outside `audit_dir` is refused and a running writer keeps
running. `start_writer()` and `stop_writer()` record `audit_writer_start` and
`audit_writer_stop` events (the path in `detail`, local paths redacted), so the
file shows who changed persistence and when. Pass `role`, `source`, `user_id`
and `session_id` to attribute a host-initiated change; the default source is
`host`.

A shared log also shares its in-memory history: every role with
`can_view_audit` sees every session's events. With one `AuditLog` per browser
session, as in the minimal README dashboard, the toggle governs only that
session's log and other sessions' events do not reach the file. Start each
session's writer where you create its log if those sessions must be persisted.

### Shut down the writer

Call `audit.stop_writer()` or `cleanup_runtime(audit=audit)` when the host
shuts down. It drains the queued events, then records `audit_writer_stop` as
the file's last line. A writer still running at a normal interpreter exit is
drained the same way, bounded to three seconds, and its stop record has the
source `atexit`. A killed process (`SIGKILL`, `os._exit`, power loss) loses
events still queued. When a host drops an `AuditLog` with a running writer,
the log is collected and its writer drains and exits without a stop record.
Events logged faster than the writer persists them are queued up to
`queue_size` (1000 by default); beyond that they are dropped and counted in
`writer_status()["dropped_events"]`.

## Plugins

Plugins are trusted in-process Python:

```python
plugins = radt.PluginRegistry()
plugins.register(
    radt.DashboardPlugin(
        name="status-card",
        version="1.0.0",
        capabilities=["panel"],
        render_panel=lambda context: context["st"].success("Service ready"),
    )
)
```

See [plugins.md](plugins.md) for discovery, lifecycle, and failure isolation.

## Observability

An `ObservabilityConfig` samples an application callback and keeps bounded
history in session state:

```python
observability = radt.ObservabilityConfig(
    enabled=True,
    telemetry_hook=lambda: {
        "metrics": {"queue_depth": 2, "latency_ms": 18.4},
        "health": {"status": "ok"},
        "source": "service",
    },
    history_limit=30,
)
```

Install `role-aware-dashboard-toolkit[pandas]` only if you want dataframe-backed history tables.
The telemetry contract is documented in
[telemetry_contract.md](telemetry_contract.md).

## Run the complete example

```bash
python -m streamlit run examples/dashboard_admin_controls_app.py
```

That example is the canonical visual smoke test for controls, roles, profiles,
audit history, and plugins.


## Customize colors

Page, input, text and accent colors use Streamlit's official project theme.
The toolkit can produce a validated configuration snippet without changing files:

```python
from role_aware_dashboard_toolkit.appearance import build_streamlit_theme_toml

print(build_streamlit_theme_toml(
    base="dark",
    background_color="#0F172A",
    secondary_background_color="#334155",
    text_color="#F8FAFC",
    primary_color="#38BDF8",
    sidebar_background_color="#1E293B",
))
```

Merge that snippet into your project's `.streamlit/config.toml` before starting
Streamlit. Preserve unrelated existing settings. Color changes can also be
applied while the app is running by saving the config and rerunning the app;
see [Streamlit configuration](https://docs.streamlit.io/develop/concepts/configuration/options).
`build_streamlit_theme_toml` returns text only; imports never change theme files.

Group cards have explicit Python options:

```python
config = radt.DashboardConfig(
    auth_mode="demo",
    registry=registry,
    layout="columns",
    card_background_color="#172554",
    group_background_colors={"Operations": "#134E4A"},
)
```

Use six-digit hexadecimal colors (`#RRGGBB`). Per-group fills override the
shared card fill; unknown group names fail before widget rendering. Hidden
registered groups are valid override targets. Plugin setup may register groups
before the names are checked. Card fills use Streamlit's documented keyed
containers in both stacked and column layouts. With no fill options, default
rendering is preserved. All workbench layouts use the supported Streamlit
baseline, 1.65.0 or newer. See the
[appearance guide](../role_aware_dashboard_toolkit/resources/guides/appearance.md)
for theme setup and visual checks.

## Choose built-in panels and menus

```python
config = radt.DashboardConfig(
    auth_mode="demo",
    registry=registry,
    sections=radt.DashboardSections(
        profiles=False,
        audit_writer=False,
        plugin_details=False,
        governance=False,
    ),
)
```

Every section defaults to `True`. Values must be actual booleans; unknown names
fail immediately. These options control presentation and do not grant permission.
Role/authentication resolution and the writable switch remain active.

| Option | Visible content |
|---|---|
| `controls` | Registered control groups |
| `profiles` | Profile sidebar menu |
| `runbook` | Run sidebar, runbook panel and all its child sections |
| `audit_writer` | Audit writer configuration form |
| `audit_log` | Main audit log panel |
| `observability` | Telemetry panel and sampling |
| `plugin_details` | Plugin metadata expander |
| `plugin_sidebar` | Registered sidebar callbacks |
| `plugin_panels` | Registered main panel callbacks |
| `team_ops` | Team sidebar and panel |
| `decisions` | Decision panel |
| `operator_memory` | Memory sidebar and timeline |
| `caseboard` | Caseboard panel |
| `governance` | Governance panel |

A hidden runbook suppresses its entire subtree. Visible children still require
an appropriate store and permission. Hidden controls retain registered state;
hidden observability does not sample. Hiding the audit writer form never
starts or stops the writer, and failures remain visible. Hiding plugin details
or callbacks does not undo plugin setup or suppress setup/discovery errors.

## Add and remove fields and custom content

Add fields with `registry.register(...)` or `register_many(...)`. Set a control's
`visible` flag to hide it while keeping its definition; use `group` to choose its
box. Remove its definition explicitly with `registry.unregister(key)`. The method
returns the removed `ControlDef` and raises `KeyError` for an unknown key. It does
not migrate or delete persisted profiles or run records. A re-registered field
appears at the end of registration order.

Custom panels and sidebar menus use the existing plugin callbacks:

```python
def project_panel(context):
    if radt.has_perm(context["ctx"], "can_view_metrics"):
        context["st"].subheader("Project overview")
        context["st"].write("Your application-specific content goes here.")

def project_menu(context):
    context["st"].selectbox("View", ["This week", "Next week"], key="project_view")

plugins = radt.PluginRegistry()
plugins.register(radt.DashboardPlugin(
    name="project-overview",
    render_panel=project_panel,
    render_sidebar=project_menu,
))
config = radt.DashboardConfig(auth_mode="demo", registry=registry, plugins=plugins)
```

Pass `plugins` to the configuration you render. Call
`plugins.unregister("project-overview")` to remove that registration; it returns
the removed plugin and raises `KeyError` if absent. Removal stops future callbacks
but does not undo setup effects. Setup runs once per registration in each registry;
re-registering a removed plugin starts a fresh registration. Trusted callbacks
must check the permissions needed for their own data and actions.
