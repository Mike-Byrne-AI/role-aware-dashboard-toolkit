# role_aware_dashboard_toolkit/controls.py
# Control Registry
#
# Controls are the building blocks of a Role-Aware Dashboard Toolkit dashboard. Each control has
# a kind (slider, toggle, number, select, text, color), a session-state key,
# default values, an RBAC permission gate, a display group, and an optional
# callback.
#
# The registry stores definitions. The renderer (dashboard.py) reads the
# registry and draws Streamlit widgets, respecting RBAC and the
# controls_writable master switch.

from __future__ import annotations

from .diagnostics import attach_diagnostic

import math
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable, Sequence
from .sensitive_values import REDACTED_SECRET, is_sensitive_name


VALID_KINDS = ("slider", "toggle", "number", "select", "text", "color")
_USER_SET_PREFIX = "_radt_user_set__"


@dataclass
class ControlDef:
    """
    One dashboard control.

    Attributes:
        name:       Display label.
        kind:       Widget type - one of VALID_KINDS.
        key:        Unique Streamlit session_state key; '_radt_' is reserved.
        group:      Logical group name (renders as a card / expander).
        permission: RBAC permission key required to edit this control.
        default:    Default value when the control first appears.
        min_value:  (slider / number) Minimum allowed value.
        max_value:  (slider / number) Maximum allowed value.
        step:       (slider / number) Step increment.
        options:    (select) List of selectable options.
        help:       Tooltip text shown next to the control.
        callback:   Optional callable invoked when the value changes.
        order:      Sort order within its group (lower = higher).
        visible:    If False the control is registered but not rendered.
        sensitive:  If True, redact displays and omit the value from durable profiles.
    """

    name: str
    kind: str
    key: str
    group: str = "Controls"
    permission: str = "can_edit_controls"
    default: Any = None
    min_value: float | None = None
    max_value: float | None = None
    step: float | None = None
    options: list[Any] | None = None
    help: str = ""
    callback: Callable | None = None
    order: int = 0
    visible: bool = True
    sensitive: bool = False


class ControlRegistry:
    """Stores control definitions and provides grouped iteration for rendering."""

    def __init__(self) -> None:
        self._controls: dict[str, ControlDef] = {}
        self._order_counter: int = 0

    def register(
        self,
        name: str,
        *,
        kind: str = "slider",
        key: str | None = None,
        group: str = "Controls",
        permission: str = "can_edit_controls",
        default: Any = None,
        min_value: float | None = None,
        max_value: float | None = None,
        step: float | None = None,
        options: list[Any] | None = None,
        help: str = "",
        callback: Callable | None = None,
        sensitive: bool | None = None,
        visible: bool = True,
    ) -> ControlDef:
        """Register a control. Returns the ControlDef for chaining."""
        if kind not in VALID_KINDS:
            raise attach_diagnostic(ValueError(f"Invalid kind. Must be one of {VALID_KINDS}"), "RADT-CONTROL-DEFINITION")

        if key is None:
            key = name.lower().replace(" ", "_")
        if isinstance(key, str) and key.startswith("_radt_"):
            raise attach_diagnostic(ValueError(
                "Control keys beginning with '_radt_' are reserved for toolkit state"
            ), "RADT-CONTROL-DEFINITION")
        if not isinstance(permission, str) or not permission.strip():
            # The API and UI must agree: an unnamed permission is never "no check".
            raise attach_diagnostic(ValueError(
                f"Control '{key}' permission must be a nonempty permission name, "
                "for example 'can_edit_controls'"
            ), "RADT-CONTROL-DEFINITION")
        if sensitive is None:
            sensitive = is_sensitive_name(name) or is_sensitive_name(key)

        if key in self._controls:
            raise attach_diagnostic(KeyError(f"Control key '{key}' already registered"), "RADT-CONTROL-DEFINITION")

        if default is None:
            default = _default_for_kind(kind, min_value, max_value, options)

        ctrl = ControlDef(
            name=name,
            kind=kind,
            key=key,
            group=group,
            permission=permission,
            default=default,
            min_value=min_value,
            max_value=max_value,
            step=step,
            options=options,
            help=help,
            callback=callback,
            sensitive=bool(sensitive),
            order=self._order_counter,
            visible=visible,
        )
        if ctrl.kind in {"slider", "number"}:
            _validate_numeric_configuration(ctrl)
            ctrl.default = _sanitize_numeric(ctrl, ctrl.default)
        self._controls[key] = ctrl
        self._order_counter += 1
        return ctrl

    def register_many(self, defs: Sequence[dict[str, Any]]) -> list[ControlDef]:
        """Register multiple controls from a list of kwarg dicts."""
        return [self.register(**d) for d in defs]

    def unregister(self, key: str) -> ControlDef:
        """Remove and return a definition, raising KeyError for an unknown key.

        Existing session values and persisted profiles/runs are not deleted.
        Re-registering this key creates a new definition at the end of the order.
        """
        return self._controls.pop(key)

    def get(self, key: str) -> ControlDef | None:
        return self._controls.get(key)

    def keys(self) -> list[str]:
        return list(self._controls.keys())

    def all(self) -> list[ControlDef]:
        return sorted(self._controls.values(), key=lambda c: c.order)

    def iter_groups(self) -> list[tuple]:
        """Yield ``(group_name, [ControlDef, ...])`` pairs in registration order."""
        groups: dict[str, list[ControlDef]] = {}
        for ctrl in self.all():
            if not ctrl.visible:
                continue
            groups.setdefault(ctrl.group, []).append(ctrl)
        return list(groups.items())

    def snapshot(self, session_state: dict[str, Any]) -> dict[str, Any]:
        """Extract current values of all registered controls from session state."""
        snap = {}
        for key, ctrl in self._controls.items():
            snap[key] = session_state.get(key, ctrl.default)
        return snap

    def persistable_snapshot(self, session_state: dict[str, Any]) -> dict[str, Any]:
        """Return registered non-sensitive values suitable for durable storage."""
        return {
            key: session_state.get(key, ctrl.default)
            for key, ctrl in self._controls.items()
            if not ctrl.sensitive
        }

    def filter_persistable_values(self, values: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive registered values and secret-like unknown keys."""
        filtered: dict[str, Any] = {}
        for key, value in dict(values or {}).items():
            text_key = str(key)
            ctrl = self.get(text_key)
            if ctrl is not None and ctrl.sensitive:
                continue
            if ctrl is None and is_sensitive_name(text_key):
                continue
            filtered[text_key] = value
        return filtered

    def restore(self, session_state: dict[str, Any], values: dict[str, Any], *, include_sensitive: bool = True) -> int:
        """Restore saved values into session state and sanitize them.

        Returns the number of corrected values.
        """
        for key, val in values.items():
            ctrl = self._controls.get(key)
            if ctrl is not None and (include_sensitive or not ctrl.sensitive):
                session_state[key] = val
        return self.sanitize_session_state(session_state)

    def export_metadata(self) -> list[dict[str, Any]]:
        """Export control definitions (without callbacks) for serialization."""
        out = []
        for ctrl in self.all():
            out.append({
                "name": ctrl.name,
                "kind": ctrl.kind,
                "key": ctrl.key,
                "group": ctrl.group,
                "permission": ctrl.permission,
                "default": REDACTED_SECRET if ctrl.sensitive else ctrl.default,
                "min_value": ctrl.min_value,
                "max_value": ctrl.max_value,
                "step": ctrl.step,
                "options": None if ctrl.sensitive else ctrl.options,
                "help": ctrl.help,
                "order": ctrl.order,
                "visible": ctrl.visible,
                "sensitive": ctrl.sensitive,
            })
        return out

    def ensure_defaults(self, session_state: dict[str, Any]) -> int:
        """Populate missing control keys with defaults. Returns keys written."""
        added = 0
        for ctrl in self.all():
            if ctrl.key not in session_state:
                session_state[ctrl.key] = ctrl.default
                added += 1
        return added

    def sanitize_session_state(self, session_state: dict[str, Any]) -> int:
        """Clamp/coerce registered control values into widget-safe ranges.

        This is a generic pre-render hardening step that prevents stale or
        profile-loaded session values from crashing widgets or leaving them in an
        invalid state.
        """
        corrected = 0
        for ctrl in self.all():
            before = session_state.get(ctrl.key, ctrl.default)
            after = self.sanitize_value(ctrl.key, before)
            if ctrl.key not in session_state or before != after:
                session_state[ctrl.key] = after
            if before != after:
                corrected += 1
        return corrected

    def sanitize_value(self, key: str, value: Any) -> Any:
        ctrl = self.get(key)
        if ctrl is None:
            return value
        return _sanitize_control_value(ctrl, value)

    def mark_user_set(self, key: str, session_state: dict[str, Any]) -> None:
        session_state[f"{_USER_SET_PREFIX}{key}"] = True

    def is_user_set(self, key: str, session_state: dict[str, Any]) -> bool:
        return bool(session_state.get(f"{_USER_SET_PREFIX}{key}", False))

    def clear_user_set(self, key: str, session_state: dict[str, Any]) -> None:
        session_state.pop(f"{_USER_SET_PREFIX}{key}", None)

    def clear_all_user_set(self, session_state: dict[str, Any]) -> int:
        removed = 0
        for key in list(session_state.keys()):
            if str(key).startswith(_USER_SET_PREFIX):
                session_state.pop(key, None)
                removed += 1
        return removed

    def __len__(self) -> int:
        return len(self._controls)

    def __contains__(self, key: str) -> bool:
        return key in self._controls

    def __iter__(self):
        return iter(self._controls)


def _default_for_kind(
    kind: str,
    min_value: float | None,
    max_value: float | None,
    options: list[Any] | None,
) -> Any:
    if kind == "slider":
        lo, hi = _numeric_bounds(kind, min_value, max_value)
        # Registration will reject invalid configured bounds with guidance.
        return round(lo / 2 + hi / 2, 4) if lo is not None and hi is not None else 0.0
    if kind == "toggle":
        return False
    if kind == "number":
        minimum = _finite_float(min_value)
        return minimum if minimum is not None else 0.0
    if kind == "select":
        return options[0] if options else None
    if kind == "text":
        return ""
    if kind == "color":
        return "#3b82f6"
    return None


def _sanitize_control_value(ctrl: ControlDef, value: Any) -> Any:
    if ctrl.kind in {"slider", "number"}:
        return _sanitize_numeric(ctrl, value)
    if ctrl.kind == "toggle":
        return _sanitize_toggle(ctrl, value)
    if ctrl.kind == "select":
        return _sanitize_select(ctrl, value)
    if ctrl.kind == "text":
        if value is None:
            return str(ctrl.default if ctrl.default is not None else "")
        return str(value)
    if ctrl.kind == "color":
        value = str(value or ctrl.default or "#3b82f6").strip()
        return value if _looks_like_hex_color(value) else str(ctrl.default or "#3b82f6")
    return value


def _sanitize_numeric(ctrl: ControlDef, value: Any) -> Any:
    num = _finite_float(value)
    if num is None:
        # The literal 0.0 fallback is always finite. The explicit check below
        # states that without an assert, which python -O would remove.
        for fallback in (ctrl.default, ctrl.min_value, ctrl.max_value, 0.0):
            num = _finite_float(fallback)
            if num is not None:
                break
    if num is None:
        num = 0.0
    min_value, max_value = _numeric_bounds(ctrl.kind, ctrl.min_value, ctrl.max_value)
    if min_value is not None and num < min_value:
        num = min_value
    if max_value is not None and num > max_value:
        num = max_value

    if ctrl.kind == "number":
        if _looks_like_int(ctrl.default) and _looks_like_int(ctrl.step) and _looks_like_int(ctrl.min_value) and _looks_like_int(ctrl.max_value):
            return round(num)
        return float(num)
    return float(num)


def _validate_numeric_configuration(ctrl: ControlDef) -> None:
    for field_name in ("min_value", "max_value", "step"):
        configured = getattr(ctrl, field_name)
        if configured is not None and _finite_float(configured) is None:
            raise attach_diagnostic(ValueError(
                f"Numeric control '{ctrl.key}' {field_name} must be a finite number"
            ), "RADT-CONTROL-DEFINITION")

    min_value, max_value = _numeric_bounds(ctrl.kind, ctrl.min_value, ctrl.max_value)
    step = _finite_float(ctrl.step)
    if min_value is not None and max_value is not None and min_value > max_value:
        raise attach_diagnostic(ValueError(
            f"Numeric control '{ctrl.key}' min_value must be less than or equal to max_value"
        ), "RADT-CONTROL-DEFINITION")
    if ctrl.kind == "slider" and min_value == max_value:
        raise attach_diagnostic(ValueError(
            f"Slider control '{ctrl.key}' min_value must be strictly less than max_value"
        ), "RADT-CONTROL-DEFINITION")
    if step is not None and step <= 0:
        raise attach_diagnostic(ValueError(
            f"Numeric control '{ctrl.key}' step must be greater than zero"
        ), "RADT-CONTROL-DEFINITION")


def _numeric_bounds(kind: str, min_value: Any, max_value: Any) -> tuple[float | None, float | None]:
    """Use the same implicit slider range for defaults, validation and values."""
    if kind == "slider":
        min_value = 0.0 if min_value is None else min_value
        max_value = 1.0 if max_value is None else max_value
    return _finite_float(min_value), _finite_float(max_value)


def _finite_float(value: Any) -> float | None:
    try:
        candidate = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return candidate if math.isfinite(candidate) else None


def _sanitize_toggle(ctrl: ControlDef, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    return bool(ctrl.default)


def _sanitize_select(ctrl: ControlDef, value: Any) -> Any:
    options = list(ctrl.options or [])
    if not options:
        return None
    if value in options:
        return value
    return ctrl.default if ctrl.default in options else options[0]


def _looks_like_int(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return float(value).is_integer()
    return False


def _looks_like_hex_color(value: str) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) != 7 or not value.startswith("#"):
        return False
    return all(ch.lower() in "0123456789abcdef" for ch in value[1:])
