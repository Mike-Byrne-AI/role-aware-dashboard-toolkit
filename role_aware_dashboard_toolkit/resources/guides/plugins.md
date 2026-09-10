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
that also require the writable switch. Setup receives `ctx=None`, so do not
expose user data or make user-authorized changes from setup.

`plugins.unregister("overview")` removes a registration and returns it;
an unknown name raises `KeyError`. Future dispatches skip removed callbacks.
Removal does not undo setup effects or delete records. Setup runs once per
registration in each registry; re-registering starts a fresh registration.

Plugins execute as trusted Python in the host process. Entry-point discovery
is explicit opt-in; allowlist reviewed entry points rather than assuming that
installation grants trust.

Verify the panel/menu appears, actually changes its intended view, respects
permissions, and disappears after unregistering. A failing setup skips its render
callbacks and remains visible as a diagnostic. Avoid catching and discarding
errors merely to make the dashboard appear healthy.
