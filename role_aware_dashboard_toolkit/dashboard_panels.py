from __future__ import annotations

from contextlib import nullcontext
from typing import Any

from ._optional_pandas import load_optional_pandas
from .appearance import group_background_color, styled_group_container
from .audit import audit_event_view
from .controls import ControlDef, _looks_like_int
from .diagnostics import diagnostic_text
from .security import SecurityContext, can_write, has_perm

pd = None
PANDAS_AVAILABLE: bool | None = None
_PREVIOUS_CONTROL_VALUES_KEY = "_radt_previous_control_values"
_READ_ONLY_CONTROL_KEY_PREFIX = "_radt_read_only_control__"


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
) -> None:
    can_clear = has_perm(ctx, "can_manage_audit")
    st.divider()
    with st.expander("Audit Log", expanded=False):
        events = audit.recent(100)
        if not events:
            st.caption("No audit events yet.")
            clear_requested = st.button(
                "Clear audit log",
                key="_radt_audit_clear",
                disabled=not can_clear,
            )
            if clear_requested and can_clear:
                audit.clear()
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
            if clear_requested and can_clear:
                audit.clear()
                st.rerun()

        source_events = audit.all_events() if hasattr(audit, "all_events") else events
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
            display_events = [
                {key: str(value) if key in {"old", "new"} and value is not None else value
                 for key, value in event.items()}
                for event in filtered
            ]
            radt = pandas.DataFrame(display_events)
            display_cols = [c for c in ["ts", "type", "key", "old", "new", "role", "detail", "source"] if c in radt.columns]
            st.dataframe(radt[display_cols], use_container_width=True, hide_index=True)

        st.subheader("Replay Preview")
        st.json(audit.replay_plan(limit=replay_limit))

        c_exp1, c_exp2 = st.columns(2)
        with c_exp1:
            payload = pandas.DataFrame(filtered).to_csv(index=False) if pandas is not None else ""
            st.download_button("Download audit.csv", payload, "audit.csv", "text/csv", key="_radt_audit_csv")
        with c_exp2:
            st.download_button(
                "Download audit.jsonl",
                audit.export_jsonl(filtered),
                "audit.jsonl",
                "application/json",
                key="_radt_audit_jsonl",
            )



def _render_control(st: Any, ctrl: ControlDef, ctx: SecurityContext, config: Any) -> None:
    editable = can_write(ctx, ctrl.permission)
    audit = config.audit
    previous_values = _previous_control_values(st.session_state)
    current_value = st.session_state.get(ctrl.key, ctrl.default)
    old_value = previous_values.get(ctrl.key, current_value)
    widget_key = ctrl.key
    has_widget_value = ctrl.key in st.session_state
    read_only_widget_key = f"{_READ_ONLY_CONTROL_KEY_PREFIX}{ctrl.key}"
    st.session_state.pop(read_only_widget_key, None)
    if not editable:
        if ctrl.key in previous_values:
            current_value = previous_values[ctrl.key]
            old_value = current_value
        else:
            previous_values[ctrl.key] = current_value
        st.session_state[ctrl.key] = current_value
        widget_key = read_only_widget_key
        has_widget_value = False

    if ctrl.kind == "slider":
        slider_kwargs = {
            "min_value": float(ctrl.min_value if ctrl.min_value is not None else 0.0),
            "max_value": float(ctrl.max_value if ctrl.max_value is not None else 1.0),
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
        integer_mode = all(_looks_like_int(candidate) for candidate in (ctrl.default, ctrl.step, ctrl.min_value, ctrl.max_value))
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
            "type": "password" if ctrl.sensitive else "default",
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

    previous_values[ctrl.key] = new_value
    if new_value != old_value:
        config.registry.mark_user_set(ctrl.key, st.session_state)
        audit.log_control_change(
            ctrl.key,
            old_value,
            new_value,
            role=ctx.role,
            sensitive=ctrl.sensitive,
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
