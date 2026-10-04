"""Read-only, redacted explanation of a native profile restore."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit_store import redact_audit_event
from .controls import ControlRegistry
from .profiles import _InvalidProfileError, _require_profile_shape
from .security import SecurityContext, can_write, has_perm


class InvalidProfilePreviewValues(ValueError):
    """A selected profile has values that cannot be staged for preview."""


@dataclass(frozen=True)
class ProfileRestorePreview:
    rows: list[dict[str, str]]
    blocked_reasons: list[str]
    corrected_count: int
    unknown_count: int
    sensitive_omitted_count: int
    values_visible: bool


def build_profile_restore_preview(
    profile: dict[str, Any],
    registry: ControlRegistry,
    session_state: Any,
    ctx: SecurityContext,
) -> ProfileRestorePreview:
    """Stage the existing restore semantics without changing state or records.

    The result contains display text only, never the raw staging dictionary.
    Load remains responsible for rereading the profile and checking permission
    at action time; this preview is not an authorization token.
    """
    try:
        _require_profile_shape(profile)
        raw_values = dict(profile.get("values") or {})
    except _InvalidProfileError:
        # Stored records are not necessarily schema-validated. Selection must
        # not expose their contents through conversion errors or crash the UI.
        raise InvalidProfilePreviewValues("Profile values are invalid.") from None
    values = registry.filter_persistable_values(raw_values)
    staged = dict(session_state)
    corrected = registry.restore(staged, values, include_sensitive=False)
    reasons = []
    if not ctx.controls_writable:
        reasons.append("Controls are frozen.")
    if not has_perm(ctx, "can_load_profiles"):
        reasons.append("Loading requires can_load_profiles.")
    visible = has_perm(ctx, "can_view_metrics") and has_perm(ctx, "can_load_profiles")
    metadata = profile.get("control_meta")
    historical_sensitive = {
        item.get("key") for item in (metadata if isinstance(metadata, list) else [])
        if isinstance(item, dict) and item.get("sensitive")
        and isinstance(item.get("key"), str)
    }
    rows = []
    for ctrl in registry.all():
        current = session_state.get(ctrl.key, ctrl.default)
        effective = staged[ctrl.key]
        restored = not ctrl.sensitive and ctrl.key in values
        changed = ctrl.key not in session_state or effective != session_state[ctrl.key]
        # Match the native Load preflight, including sanitation-only changes.
        if (restored or changed) and not can_write(ctx, ctrl.permission):
            if ctx.controls_writable:
                reason = f"{ctrl.name} requires {ctrl.permission}."
                if reason not in reasons:
                    reasons.append(reason)
        if not visible:
            continue
        hidden = ctrl.sensitive or ctrl.key in historical_sensitive
        candidate = values[ctrl.key] if restored else current
        corrected_value = candidate != effective
        if ctrl.sensitive:
            outcome = "Sensitive value not restored"
        elif restored:
            outcome = "Restored" if changed else "Already matches"
        else:
            outcome = "Current value retained" if ctrl.key in session_state else "Default added"
        if corrected_value:
            outcome += "; corrected"
        rows.append({
            "Control": ctrl.name,
            "Current": "Hidden" if hidden else _display_value(current),
            "Saved": "Hidden" if hidden else (
                _display_value(values[ctrl.key]) if restored else "Not saved"
            ),
            "Effective": "Hidden" if hidden else _display_value(effective, source=candidate),
            "Result": outcome,
        })
    return ProfileRestorePreview(
        rows=rows,
        blocked_reasons=reasons,
        corrected_count=corrected,
        # Unknown values may belong to removed sensitive controls. Never display
        # either their values or their untrusted names, even in diagnostics.
        unknown_count=sum(registry.get(str(key)) is None for key in raw_values),
        sensitive_omitted_count=sum(
            ctrl.sensitive and ctrl.key in raw_values for ctrl in registry.all()
        ),
        values_visible=visible,
    )


def _display_value(value: Any, *, source: Any = None) -> str:
    # Reuse the established nested-secret and local-path display redaction.
    # A text control can stringify a legacy structured value while restoring.
    # Do not reveal nested secrets that lost their field names during coercion.
    if isinstance(source, (dict, list, tuple)):
        safe_source = redact_audit_event({"value": source})["value"]
        if str(safe_source) != str(source):
            return "Hidden"
    safe = redact_audit_event({"value": value})["value"]
    return str(safe)
