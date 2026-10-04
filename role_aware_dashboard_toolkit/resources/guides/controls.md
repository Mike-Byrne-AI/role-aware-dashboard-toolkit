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
label; a different key creates a different state identity. Keys beginning with
`_radt_` are reserved for toolkit widgets and state and are rejected, including
automatically derived keys. Numeric bounds and step must be finite, bounds
ordered and step positive. Sliders use `0.0` for an omitted minimum and `1.0`
for an omitted maximum; the effective minimum must be strictly less than the
effective maximum. These same bounds apply when restoring saved values. Pick a select default
from its options. A color field stores a value; connect that value to a chart or
other supported appearance API if it should affect presentation.

Streamlit integer number widgets additionally require their default, minimum,
maximum and step within `-(2**53 - 1)` through `2**53 - 1`. Dashboard rendering
checks existing visible controls before authentication UI, widgets or plugin
callbacks run, and checks plugin-added controls immediately after setup. An
unsupported definition stops rendering with `RADT-CONTROL-RENDER` guidance;
plugin setup effects are not rolled back. The core registry and API retain
wider numeric domains. Sensitive replacement forms send text and are not
subject to this browser integer restriction. Use text controls for large exact
integer identifiers; numeric controls use floating-point sanitation.

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

When `sensitive` is omitted, detection checks both the name and key for words
such as `token`, `secret`, `password` and `credential`, for every control kind.
It intentionally errs toward protection. For a nonsecret field that matches,
such as a token-count limit, explicitly use `sensitive=False` to retain its
ordinary widget and profile values:

```python
registry.register(
    "Max tokens", kind="number", key="max_tokens", default=256,
    min_value=1, max_value=4096, step=1, sensitive=False,
)
```

Sensitive controls use a blank password replacement form for all six kinds;
their stored values, defaults and select options stay on the server. A Viewer
or frozen dashboard shows only `Hidden`. Editable fields change only when
`Replace` is submitted. A blank text replacement explicitly clears the value;
an ordinary rerun preserves it. Invalid replacements leave the stored value
unchanged. Drafts clear after submission, including denied or invalid attempts.
Permission and freeze are checked again at submission. Successful changes use
the existing callbacks and redacted audit events.

Enter text literally, numbers as finite decimal numbers, toggles as `true` or
`false`, and colors as `#RRGGBB`. Numeric replacements use the normal bounds
and numeric conversion. For sensitive select controls, enter a JSON value that
exactly matches a configured option and its type: `"1"` selects a string,
`1` a number, `true` a boolean, `[1]` an array, and `{"mode": "quiet"}` an
object. Options are never listed. Non-JSON Python objects must be set by trusted
host code. This intentionally replaces the previous prefilled sensitive widgets;
the registered control keys and callback signatures are unchanged. Hosts must
also avoid exposing secrets in labels, help text, callbacks or custom panels.

Verify every added field in the UI, its bounds/options, its role restriction,
and the freeze switch. Avoid assigning registered session keys after their
widgets render; native profile/replay actions handle that lifecycle.
