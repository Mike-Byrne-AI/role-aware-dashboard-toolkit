# Add or remove custom panels and menus

Manual registration is the normal path. Callbacks receive `st`, `config` and
the current security `ctx`. In the starter, edit `render_view_menu()` and
`render_project_panel()`.

```python
def overview(context):
    if not radt.has_perm(context["ctx"], "can_view_metrics"):
        return
    context["st"].subheader("Overview")
    context["st"].write("Authorized project data goes here.")

plugins = radt.PluginRegistry()
plugins.register(radt.DashboardPlugin(name="overview", render_panel=overview))
config = radt.DashboardConfig(registry=registry, plugins=plugins)
```

Use `render_sidebar=` for a custom menu. Give widgets stable host-owned keys.
Check `has_perm` before displaying protected data; use `can_write` for actions
that also require the writable switch. In authenticated mode, setup receives
the prepared access context; other modes pass `ctx=None`. Setup runs once per
registration and can be shared across sessions: never cache user data,
identities or authorization decisions there. Keep user-specific reads and
actions in callbacks that check the current render context at the boundary.

Concurrent sessions share one setup attempt for a registration and wait for its
completion before rendering its hooks. If that attempt fails, waiting sessions
receive its diagnostic; a later call can retry. Setup and render callbacks run
outside the registry lock. Reentrant calls made from setup skip registrations
whose setup is already running, so they must not assume every plugin is ready.
Render hooks can run concurrently; protect any shared host resources they use.

`plugins.unregister("overview")` removes a registration and returns it;
an unknown name raises `KeyError`. Future dispatches skip removed callbacks;
callbacks already selected for dispatch may finish.
Removal does not undo setup effects or delete records. Setup runs once per
registration in each registry; re-registering starts a fresh registration.
Removing an in-progress registration releases waiting callers. Its old setup
may finish, but cannot initialize or render the replacement, even when the same
plugin object is registered again. Coordinate host effects if old and new setup
callbacks must not overlap. Keep plugin names stable while registered.

Plugins execute as trusted Python in the host process. Entry-point discovery
is explicit opt-in; allowlist reviewed entry points rather than assuming that
installation grants trust. Each allowlist entry names
`distribution:group:name`, so a same-named entry point from another installed
distribution is never imported; a `group:name` entry raises `ValueError`:

```python
registry.discover(trusted_entry_points=[
    "acme-dashboard-plugins:role_aware_dashboard_toolkit.panels:my_plugin",
])
```

Verify the panel/menu appears, actually changes its intended view, respects
permissions, and disappears after unregistering. A failing setup skips its render
callbacks and remains visible as a diagnostic. Avoid catching and discarding
errors merely to make the dashboard appear healthy.
