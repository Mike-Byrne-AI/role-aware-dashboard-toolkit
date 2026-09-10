# Choose built-in boxes and menus

Use `DashboardSections` when constructing the configuration:

```python
config = radt.DashboardConfig(
    registry=registry,
    sections=radt.DashboardSections(
        profiles=False, audit_writer=False, plugin_details=False,
        runbook=False,
    ),
)
```

All flags default to `True`. Values must be actual booleans; misspelled flag
names fail rather than silently doing nothing.

Available names are `controls`, `profiles`, `runbook`, `audit_writer`,
`audit_log`, `observability`, `plugin_details`, `plugin_sidebar`,
`plugin_panels`, `team_ops`, `decisions`, `operator_memory`, `caseboard`
and `governance`.

A hidden runbook hides all its child sections. Showing a child still requires
its store and permission. Hiding controls preserves registered values.
Hiding observability also stops sampling. Hiding the audit-writer form preserves
its existing settings and lifecycle; it does not stop an active writer.
Plugin visibility does not disable setup or suppress setup/discovery failures.

Role/auth resolution and the writable switch remain active. Visibility never
grants permissions; hiding a button is not an authorization check.

In the starter, set `runbook=True` in `build_dashboard_config()` to expose the
already retained in-memory run store. Add custom panels/menus with plugin
callbacks; read `guide plugins`.

Verify that the requested section disappears and its siblings still function.
After hiding then showing controls, confirm their values survive and role/freeze
restrictions still apply.
