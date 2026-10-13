# Role-Aware Dashboard Toolkit Plugin Guide

Role-Aware Dashboard Toolkit plugins are local extension hooks for panels and sidebar sections.

## Plugin contract

A plugin is a `DashboardPlugin` with:

- `name`
- `version`
- `description`
- `capabilities`
- optional `setup(context)`
- optional `render_sidebar(context)`
- optional `render_panel(context)`

## Current capability flags

- `sidebar`
- `panel`
- `setup`

## Rules

- plugins must fail loudly enough for operators to diagnose problems
- plugins should not auto-install or fetch remote code
- plugins should not hide mutations from the host dashboard
- plugins run as trusted in-process Python code (not a sandbox)
- declared capability flags should match provided hooks (`setup`, `sidebar`, and
  `panel`)

## Trust boundary

`PluginRegistry.discover()` loads Python entry points directly into the running
process. Treat discovered plugins as fully trusted code with the same filesystem
and network permissions as the host app.

Discovery is explicit trust opt-in:

- `discover(trusted_entry_points=["acme-dashboard-plugins:role_aware_dashboard_toolkit.panels:my_plugin"])`
  to load only an allowlisted entry-point set
- `discover(allow_untrusted=True)` only for controlled local development when
  you intentionally trust every discovered entry point

Each allowlist entry is `distribution:group:name`: the installed distribution
(project) name as `pip show` reports it, the entry-point group
(`role_aware_dashboard_toolkit.panels` or `role_aware_dashboard_toolkit.sidebar`)
and the entry-point name. An entry point is imported only when its own
distribution, group and name all match an entry; distribution names compare
case-insensitively, with `-`, `_` and `.` treated alike. A same-named entry
point published by another installed distribution is never imported. An entry
point whose distribution metadata is missing or unreadable is not trusted by an
allowlist.

Since 0.2.0 a `group:name` entry (the 0.1.0 form) is refused: `discover()`
raises `ValueError` naming the entry before importing anything, as it does for
any other malformed entry or unknown group. Prefix each old entry with the
distribution that should provide it.

`PluginRegistry.describe()` and `PluginRegistry.describe_sources()` expose loaded
plugin source metadata (manual registration vs entry point, group/ref, and
distribution name when available).

## Error diagnostics

`PluginRegistry.initialize()`, `render_sidebar()`, and `render_panels()` return
`PluginErrorRecord` objects when plugin setup or render hooks fail.
Records retain the `plugin: message` prefix, followed by a stable diagnostic
code, possible effects and an installed guide command. Generated records omit
raw exception messages to avoid copying secrets from trusted callback failures.
They expose:

- `plugin_name`
- `stage`
- `source`
- `exception_type`
- `message` (fixed safe summary for library-generated failures)
- `.diagnostic` and a nested `diagnostic` in `to_dict()` (version, code,
  operation, effect and offline help command)

If `setup(context)` fails, the plugin is not marked initialized and its render
hooks are skipped. A dashboard render attempts setup once and does not retry it
during sidebar or panel phases; the sanitized setup diagnostic remains visible
once the dashboard authenticates and passes configuration preflight. If
appearance validation stops rendering before authentication, its error reports
only the setup failure count and an action to check setup callbacks; plugin
names and exception messages are not disclosed before authentication.
A later dashboard rerun or direct initialize/render call retries setup.
Hosts that call `initialize()` explicitly can pass `initialize_plugins=False`
to render methods so one explicit initialization owns that cycle.

## Shared registries and setup

Each registration owns its initialization state, even when the same plugin object
appears in multiple registries. Concurrent sessions share one setup attempt and
wait for that attempt to finish before invoking render hooks. A failed attempt
returns the same sanitized diagnostic to its waiting callers; a later call can
retry. Control-flow exits such as a Streamlit rerun also release waiting callers
without marking the registration initialized. They still propagate to the caller
that ran setup.

Registry state changes are synchronized, but setup, render and metadata callbacks
run outside the registry lock. Setup may register or remove plugins. Reentrant
initialize/render calls made from setup skip registrations already being set up,
including in another registry, to avoid circular waits. Such nested calls must
not assume every plugin is initialized when they return. A setup callback must
not wait for another thread to finish initializing that same registration.

Unregistering releases callers waiting on that registration and excludes it from
later dispatches. Already selected callbacks may finish; removing a registration
does not cancel or roll back host work. Re-registering creates new initialization
state, including when reusing the same plugin object. Old setup completion cannot
initialize or dispatch the replacement. Hosts must coordinate old and new setup
effects if those effects cannot overlap, and must protect shared resources used
by concurrent render hooks. Keep plugin names stable while registered. Setup is
shared across sessions: do not cache identities, user data or authorization
decisions in it; inspect each render callback's current security context.

## Discovery diagnostics

Discovery failures are isolated per entry point. `PluginRegistry.discover()`
skips broken plugins, emits a `RuntimeWarning`, and stores structured records in
`PluginRegistry.discovery_errors()` for callers that want exact diagnostics.
Dashboard rendering surfaces stored discovery records alongside setup and panel
hook warnings using this shape:

```text
Plugin discovery error: <plugin>: <message>
```

## Template

See `examples/plugin_template.py`. The template is fixture-free and shipped in
source checkouts and public source distributions.


## Supported path today

Manual registration is the primary supported plugin path in this snapshot.
`PluginRegistry.discover()` exists for local entry-point discovery, but it is still an experimental convenience rather than the main documented product path.
