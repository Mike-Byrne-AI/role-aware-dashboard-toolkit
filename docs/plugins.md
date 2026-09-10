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

- `discover(trusted_entry_points=["role_aware_dashboard_toolkit.panels:my_plugin"])` to load only
  an allowlisted entry-point set
- `discover(allow_untrusted=True)` only for controlled local development when
  you intentionally trust every discovered entry point

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
