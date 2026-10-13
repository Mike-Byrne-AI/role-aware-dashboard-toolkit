from __future__ import annotations

import csv
from contextlib import nullcontext
from copy import deepcopy
from io import StringIO
import math
from typing import Any
import unicodedata

from ._json_safety import strict_json_loads
from ._optional_pandas import load_optional_pandas
from ._record_projection import project_audit_events, project_record
from ._ui_state import last_authorized_control_value, remember_authorized_control_values
from .appearance import group_background_color, styled_group_container
from .audit import _ui_attribution, audit_event_view
from .controls import ControlDef, _looks_like_hex_color, _looks_like_int, _numeric_bounds, _validate_numeric_configuration
from .diagnostics import attach_diagnostic, diagnostic_text
from .security import SecurityContext, can_write, can_mutate

pd = None
PANDAS_AVAILABLE: bool | None = None
_PREVIOUS_CONTROL_VALUES_KEY = "_radt_previous_control_values"
_READ_ONLY_CONTROL_KEY_PREFIX = "_radt_read_only_control__"
_SENSITIVE_INPUT_PREFIX = "_radt_sensitive_replacement__"


def _validate_control_widgets(registry: Any) -> None:
    """Reject unsupported widget definitions before the dashboard draws UI.

    The dependency-free registry can retain wider numeric domains. Sensitive
    replacements serialize text, so browser numeric bounds do not apply to them.
    """
    for ctrl in registry.all():
        if not ctrl.visible or ctrl.sensitive or ctrl.kind not in {"slider", "number"}:
            continue
        try:
            _validate_numeric_configuration(ctrl)
        except ValueError:
            raise attach_diagnostic(ValueError(
                "A numeric control has invalid bounds or step for rendering"
            ), "RADT-CONTROL-RENDER") from None
        if ctrl.kind == "number" and _integer_widget_mode(ctrl):
            maximum = (1 << 53) - 1
            if any(abs(int(value)) > maximum for value in (
                ctrl.default, ctrl.min_value, ctrl.max_value, ctrl.step,
            )):
                raise attach_diagnostic(ValueError(
                    "Integer number widgets require default, bounds and step within "
                    "-(2**53 - 1) through 2**53 - 1; choose smaller bounds or a text control"
                ), "RADT-CONTROL-RENDER")


def _integer_widget_mode(ctrl: ControlDef) -> bool:
    return all(_looks_like_int(value) for value in (
        ctrl.default, ctrl.step, ctrl.min_value, ctrl.max_value,
    ))


def _previous_control_values(session_state: Any) -> dict[str, Any]:
    previous = session_state.get(_PREVIOUS_CONTROL_VALUES_KEY)
    if not isinstance(previous, dict):
        previous = {}
        session_state[_PREVIOUS_CONTROL_VALUES_KEY] = previous
    return previous


def render_groups(st: Any, groups: list[tuple], ctx: SecurityContext, config: Any) -> None:
    if config.layout == "columns" and len(groups) > 1:
        _render_columns(st, groups, ctx, config)
    else:
        _render_stacked(st, groups, ctx, config)



def render_audit_panel(
    st: Any,
    audit: Any,
    ctx: SecurityContext | None = None,
    *,
    registry: Any = None,
) -> None:
    can_clear = can_mutate(ctx, "can_manage_audit")
    st.divider()
    with st.expander("Audit Log", expanded=False):
        events = project_audit_events(audit.recent(100), registry)
        if not events:
            st.caption("No audit events yet.")
            clear_requested = st.button(
                "Clear audit log",
                key="_radt_audit_clear",
                disabled=not can_clear,
            )
            if clear_requested and can_mutate(ctx, "can_manage_audit"):
                audit.clear(**_ui_attribution(audit, ctx))
                st.rerun()
            return

        col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
        with col1:
            search = st.text_input("Search", placeholder="type, key, role, or detail", key="_radt_audit_search")
        with col2:
            all_types = sorted({_audit_event_type(event) for event in events})
            selected_types = st.multiselect("Event Type", options=all_types, default=all_types, key="_radt_audit_types")
        with col3:
            replay_limit = int(st.number_input("Replay Preview Size", value=10, min_value=1, max_value=100, key="_radt_replay_limit"))
        with col4:
            clear_requested = st.button(
                "Clear log",
                key="_radt_audit_clear_btn",
                disabled=not can_clear,
            )
            if clear_requested and can_mutate(ctx, "can_manage_audit"):
                audit.clear(**_ui_attribution(audit, ctx))
                st.rerun()

        source_events = project_audit_events(audit.all_events(), registry) if hasattr(audit, "all_events") else events
        filtered = _filter_audit_panel_events(source_events, event_types=selected_types, text=search, limit=100)
        if not filtered:
            st.info("No matching events.")
            return

        st.subheader("Timeline")
        pandas = _load_pandas()
        if pandas is None:
            st.json(filtered[:50])
        else:
            # Mixed control kinds share these columns. Convert only display cells;
            # the audit records, replay preview, and exports keep their original types.
            # The table's built-in CSV download exports these cells, so they get
            # the same formula protection as the dedicated audit.csv view.
            display_events = [
                {key: _spreadsheet_safe_cell(
                    str(value) if key in {"old", "new"} and value is not None else value
                 ) for key, value in event.items()}
                for event in filtered
            ]
            radt = pandas.DataFrame(display_events)
            display_cols = [c for c in ["ts", "type", "key", "old", "new", "role", "detail", "source"] if c in radt.columns]
            st.dataframe(radt[display_cols], width="stretch", hide_index=True)

        st.subheader("Replay Preview")
        st.json(project_record(audit.replay_plan(limit=replay_limit), registry))

        c_exp1, c_exp2 = st.columns(2)
        with c_exp1:
            payload = _spreadsheet_safe_audit_csv(filtered)
            st.download_button("Download audit.csv", payload, "audit.csv", "text/csv", key="_radt_audit_csv")
        with c_exp2:
            st.download_button(
                "Download audit.jsonl",
                audit.export_jsonl(filtered),
                "audit.jsonl",
                "application/json",
                key="_radt_audit_jsonl",
            )



def _spreadsheet_safe_audit_csv(events: list[dict[str, Any]]) -> str:
    """Build a spreadsheet-oriented view without changing the audit evidence.

    Quoting protects field boundaries; an apostrophe makes formula-like text
    explicit text on initial import. NULs become visible backslash escapes for
    CSV-reader compatibility. JSONL remains the lossless format and downstream
    re-export needs its own policy.
    """
    fields = list(dict.fromkeys(key for event in events for key in event))
    output = StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow([_spreadsheet_safe_cell(str(key)) for key in fields])
    for event in events:
        writer.writerow([_spreadsheet_safe_cell(event.get(key)) for key in fields])
    return output.getvalue()


def _spreadsheet_safe_cell(value: Any) -> Any:
    """Make formula-like text explicit text; leave other values unchanged."""
    if not isinstance(value, str):
        return value
    probe = unicodedata.normalize("NFKC", value)
    while probe and (probe[0].isspace() or unicodedata.category(probe[0]) in {"Cc", "Cf"}):
        probe = probe[1:]
    # Python 3.10's CSV reader rejects NULs even inside quoted fields.
    # Inspect the original prefix first, preserving formula protection.
    display = value.replace("\x00", "\\x00")
    if probe.startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + display
    return display


def _sensitive_replacement(ctrl: ControlDef, value: str, registry: Any) -> Any:
    """Validate blank-entry replacements without falling back to stored secrets."""
    if ctrl.kind == "text":
        return value
    if ctrl.kind in {"number", "slider"}:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Invalid replacement")
        return registry.sanitize_value(ctrl.key, number)
    if ctrl.kind == "toggle":
        normalized = value.strip().lower()
        if normalized not in {"true", "false"}:
            raise ValueError("Invalid replacement")
        return normalized == "true"
    if ctrl.kind == "color":
        if not _looks_like_hex_color(value.strip()):
            raise ValueError("Invalid replacement")
        return value.strip()
    if ctrl.kind == "select":
        # JSON keeps string/number/boolean/structured choices distinct without
        # putting the private option list in any widget or error message.
        candidate = strict_json_loads(value)
        for option in ctrl.options or []:
            if _same_typed_value(candidate, option):
                return deepcopy(option)
    raise ValueError("Invalid replacement")


def _same_typed_value(candidate: Any, option: Any) -> bool:
    if type(candidate) is not type(option):
        return False
    if isinstance(candidate, list):
        return len(candidate) == len(option) and all(
            _same_typed_value(left, right) for left, right in zip(candidate, option)
        )
    if isinstance(candidate, dict):
        return candidate.keys() == option.keys() and all(
            _same_typed_value(candidate[key], option[key]) for key in candidate
        )
    return candidate == option


def _render_sensitive_control(st: Any, ctrl: ControlDef, ctx: SecurityContext, config: Any) -> None:
    """Keep stored values server-side; every kind uses explicit blank replacement."""
    previous = _previous_control_values(st.session_state)
    current = st.session_state.get(ctrl.key, ctrl.default)
    editable = can_write(ctx, ctrl.permission)
    input_key = f"{_SENSITIVE_INPUT_PREFIX}{ctrl.key}"
    # Capture only this submission, then clear BEFORE the widget is serialized.
    # The input key is separate from the server-owned control key and no default,
    # option, range or widget identity is derived from the stored value.
    replacement = st.session_state.pop(input_key, "")
    if not editable:
        if ctx.authenticated:
            current = last_authorized_control_value(st.session_state, ctrl.key, ctrl.default)
        else:
            current = previous.get(ctrl.key, current)
        st.session_state[ctrl.key] = current
        previous[ctrl.key] = deepcopy(current)
        st.caption(f"{ctrl.name}: Hidden")
        return

    previous.setdefault(ctrl.key, deepcopy(current))
    if ctx.authenticated:
        remember_authorized_control_values(st.session_state, {ctrl.key: current})
    st.session_state[input_key] = ""
    with st.form(f"_radt_sensitive_form__{ctrl.key}", clear_on_submit=True):
        st.text_input(
            f"Replace {ctrl.name}", key=input_key, type="password",
            help=("Stored value is never displayed. Submit an empty replacement to clear text."
                  if ctrl.kind == "text" else
                  "Stored value and choices are never displayed. Enter a valid replacement."),
        )
        submitted = st.form_submit_button(
            f"Replace {ctrl.name}", key=f"_radt_sensitive_submit__{ctrl.key}",
        )
    if not submitted:
        return
    if not can_write(ctx, ctrl.permission):
        st.warning("Replacement denied: current permission and writable state are required.")
        return
    try:
        if not isinstance(replacement, str):
            raise ValueError("Invalid replacement")
        updated = _sensitive_replacement(ctrl, replacement, config.registry)
    except (ValueError, TypeError, OverflowError, RecursionError):
        st.error("Replacement is invalid; the stored value was preserved.")
        return
    st.session_state[ctrl.key] = updated
    previous[ctrl.key] = deepcopy(updated)
    if ctx.authenticated:
        remember_authorized_control_values(st.session_state, {ctrl.key: updated})
    if not _same_typed_value(updated, current):
        _record_control_change(st, ctrl, ctx, config, current, updated)
    st.toast("Replacement saved.")


def _render_control(st: Any, ctrl: ControlDef, ctx: SecurityContext, config: Any) -> None:
    if ctrl.sensitive:
        _render_sensitive_control(st, ctrl, ctx, config)
        return
    editable = can_write(ctx, ctrl.permission)
    previous_values = _previous_control_values(st.session_state)
    current_value = st.session_state.get(ctrl.key, ctrl.default)
    old_value = previous_values.get(ctrl.key, current_value)
    widget_key = ctrl.key
    has_widget_value = ctrl.key in st.session_state
    read_only_widget_key = f"{_READ_ONLY_CONTROL_KEY_PREFIX}{ctrl.key}"
    st.session_state.pop(read_only_widget_key, None)
    if not editable:
        if getattr(ctx, "authenticated", False):
            current_value = last_authorized_control_value(st.session_state, ctrl.key, ctrl.default)
            old_value = current_value
            previous_values[ctrl.key] = current_value
        elif ctrl.key in previous_values:
            current_value = previous_values[ctrl.key]
            old_value = current_value
        else:
            previous_values[ctrl.key] = current_value
        st.session_state[ctrl.key] = current_value
        widget_key = read_only_widget_key
        has_widget_value = False

    if ctrl.kind == "slider":
        minimum, maximum = _numeric_bounds(ctrl.kind, ctrl.min_value, ctrl.max_value)
        slider_kwargs = {
            "min_value": minimum,
            "max_value": maximum,
            "step": float(ctrl.step if ctrl.step is not None else 0.01),
            "key": widget_key,
            "disabled": not editable,
            "help": ctrl.help or None,
        }
        if not has_widget_value:
            slider_kwargs["value"] = float(current_value)
        st.slider(ctrl.name, **slider_kwargs)
    elif ctrl.kind == "toggle":
        toggle_kwargs = {
            "key": widget_key,
            "disabled": not editable,
            "help": ctrl.help or None,
        }
        if not has_widget_value:
            toggle_kwargs["value"] = bool(current_value)
        st.toggle(ctrl.name, **toggle_kwargs)
    elif ctrl.kind == "number":
        kwargs: dict[str, Any] = {}
        integer_mode = _integer_widget_mode(ctrl)
        cast = int if integer_mode else float
        if ctrl.min_value is not None:
            kwargs["min_value"] = cast(ctrl.min_value)
        if ctrl.max_value is not None:
            kwargs["max_value"] = cast(ctrl.max_value)
        if ctrl.step is not None:
            kwargs["step"] = cast(ctrl.step)
        if not has_widget_value:
            kwargs["value"] = cast(config.registry.sanitize_value(ctrl.key, current_value))
        st.number_input(
            ctrl.name,
            key=widget_key,
            disabled=not editable,
            help=ctrl.help or None,
            **kwargs,
        )
    elif ctrl.kind == "select":
        options = ctrl.options or []
        current = current_value
        try:
            idx = options.index(current) if current in options and options else 0
        except (ValueError, TypeError):
            idx = 0
        st.selectbox(
            ctrl.name,
            options=options,
            key=widget_key,
            disabled=not editable,
            help=ctrl.help or None,
            **({"index": idx} if not has_widget_value else {}),
        )
    elif ctrl.kind == "text":
        text_kwargs = {
            "key": widget_key,
            "disabled": not editable,
            "help": ctrl.help or None,
            "type": "default",
        }
        if not has_widget_value:
            text_kwargs["value"] = str(current_value)
        st.text_input(ctrl.name, **text_kwargs)
    elif ctrl.kind == "color":
        color_kwargs = {
            "key": widget_key,
            "disabled": not editable,
            "help": ctrl.help or None,
        }
        if not has_widget_value:
            color_kwargs["value"] = str(current_value)
        st.color_picker(ctrl.name, **color_kwargs)

    new_value = st.session_state.get(ctrl.key)
    if not editable:
        return

    # The authority may change while a widget is rendered (other session,
    # expiry, or grant revocation). Do not run a callback on stale permission.
    if new_value != old_value and not can_write(ctx, ctrl.permission):
        previous_values[ctrl.key] = old_value
        # Widgets already exist; restore before their next creation, without
        # invoking the application callback or recording a successful write.
        st.session_state.setdefault("_radt_denied_control_restore", {})[ctrl.key] = old_value
        st.rerun()

    previous_values[ctrl.key] = new_value
    if getattr(ctx, "authenticated", False):
        remember_authorized_control_values(st.session_state, {ctrl.key: new_value})
    if new_value != old_value:
        _record_control_change(st, ctrl, ctx, config, old_value, new_value)


def _record_control_change(st: Any, ctrl: ControlDef, ctx: SecurityContext, config: Any,
                           old_value: Any, new_value: Any) -> None:
    audit = config.audit
    config.registry.mark_user_set(ctrl.key, st.session_state)
    audit.log_control_change(
        ctrl.key,
        old_value,
        new_value,
        role=ctx.role,
        sensitive=config.registry._audit_sensitivity(ctrl),
    )
    if ctrl.callback is not None:
        try:
            ctrl.callback(ctrl.key, new_value)
        except Exception as exc:
            detail = _callback_error_detail(exc)
            st.error(f"Callback error on {ctrl.key}: {detail}")
            audit.log("callback_error", key=ctrl.key, detail=detail, role=ctx.role)
    if config.on_change is not None:
        try:
            config.on_change(ctrl.key, old_value, new_value)
        except Exception as exc:
            detail = _callback_error_detail(exc)
            st.error(f"Global on_change error on {ctrl.key}: {detail}")
            audit.log("callback_error", key=ctrl.key, detail=detail, role=ctx.role)



def _callback_error_detail(exc: Exception) -> str:
    return f"{type(exc).__name__}. {diagnostic_text('RADT-CALLBACK')}"


def _audit_event_type(event: Any) -> str:
    value = audit_event_view(event).get("type")
    return str(value or "").strip() or "unknown"


def _filter_audit_panel_events(
    events: list[Any],
    *,
    event_types: list[str] | None,
    text: str,
    limit: int,
) -> list[dict[str, Any]]:
    selected_types = {str(event_type or "").strip() or "unknown" for event_type in event_types or []}
    text_lower = str(text or "").strip().lower()
    filtered: list[dict[str, Any]] = []
    for event in events:
        event_record = audit_event_view(event)
        if selected_types and _audit_event_type(event_record) not in selected_types:
            continue
        if text_lower and not any(text_lower in str(value).lower() for value in event_record.values()):
            continue
        filtered.append(event_record)
    return filtered[-max(0, int(limit)) :]


def _render_stacked(st: Any, groups: list[tuple], ctx: SecurityContext, config: Any) -> None:
    for group_name, controls in groups:
        color = group_background_color(config, group_name)
        wrapper = (
            styled_group_container(st, group_name, color, border=False)
            if color is not None else nullcontext()
        )
        with wrapper, st.expander(f"{group_name}", expanded=True):
            for ctrl in controls:
                _render_control(st, ctrl, ctx, config)



def _render_columns(st: Any, groups: list[tuple], ctx: SecurityContext, config: Any) -> None:
    n = config.columns_per_row
    for i in range(0, len(groups), n):
        chunk = groups[i : i + n]
        cols = st.columns(len(chunk))
        for col, (group_name, controls) in zip(cols, chunk, strict=False):
            with col:
                color = group_background_color(config, group_name)
                card = (
                    styled_group_container(st, group_name, color, border=True)
                    if color is not None else st.container(border=True)
                )
                with card:
                    st.markdown(f"**{group_name}**")
                    for ctrl in controls:
                        _render_control(st, ctrl, ctx, config)


def _load_pandas():
    global pd, PANDAS_AVAILABLE
    pd, PANDAS_AVAILABLE, _checked = load_optional_pandas(pd, PANDAS_AVAILABLE)
    return pd


__all__ = ["render_audit_panel", "render_groups"]
