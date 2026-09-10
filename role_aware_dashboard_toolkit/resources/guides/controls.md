# Add, change, hide or remove fields

Use `ControlRegistry.register()`; the six kinds are `slider`, `number`,
`select`, `toggle`, `text` and `color`. In the starter, edit
`build_controls()` before the dashboard renders.

```python
registry.register(
    "Daily target", kind="number", key="daily_target", group="Plan",
    default=8, min_value=1, max_value=40, step=1,
    permission="can_edit_controls",
)
registry.register(
    "Mode", kind="select", key="mode", group="Plan",
    options=["Steady", "Fast"], default="Steady",
)
```

A field's `group` chooses its box. Keep its key stable when changing the visible
label; a different key creates a different state identity. Numeric bounds and
step must be finite, bounds ordered and step positive. Pick a select default
from its options. A color field stores a value; connect that value to a chart or
other supported appearance API if it should affect presentation.

```python
registry.get("mode").visible = False  # Hide; retain its definition and state.
removed = registry.unregister("mode")  # Remove definition; unknown key raises KeyError.
```

Removal does not delete old session values or migrate saved profiles/runs.
Unknown profile fields are ignored during restore. Update matching group-color
overrides when the last field in a group is removed.

Set `sensitive=True` for secrets; sensitive-looking names are also detected.
Sensitive values are omitted from profiles and redacted in audit/API output.
Do not dump raw session state to debug a dashboard.

Verify every added field in the UI, its bounds/options, its role restriction,
and the freeze switch. Avoid assigning registered session keys after their
widgets render; native profile/replay actions handle that lifecycle.
