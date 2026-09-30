"""Private Streamlit lifecycle support; never apply bulk edits after widgets exist."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .diagnostics import diagnostic_text

from .replay import apply_replay_packet
from .security import can_write

_PENDING_REPLAY = "_radt_pending_replay"
_ACCEPTED_CONTROL_VALUES = "_radt_accepted_control_values"


def retain_control_state(registry: Any, session_state: Any) -> None:
    """Detach registered values from widget cleanup before any early sidebar rerun.

    Streamlit deletes state for widgets omitted by a rerun. Explicit assignment
    before widget creation preserves values, including hidden and frozen controls.
    """
    denied = session_state.pop("_radt_denied_control_restore", {})
    for key, value in denied.items():
        if key in registry:
            session_state[key] = value
    for key in registry.keys():
        if key in session_state:
            session_state[key] = session_state[key]


def remember_authorized_control_values(session_state: Any, values: dict[str, Any]) -> None:
    """Capture accepted values without suppressing subsequent widget callbacks.

    Bulk profile/replay writes can affect controls that have never rendered.
    Keep their trusted baseline separate from the renderer's previous values,
    which are still needed to report control changes and invoke callbacks.
    Call only after the operation has passed its mutation authorization checks.
    """
    accepted = session_state.get(_ACCEPTED_CONTROL_VALUES)
    if not isinstance(accepted, dict):
        accepted = {}
        session_state[_ACCEPTED_CONTROL_VALUES] = accepted
    accepted.update(deepcopy(values))


def last_authorized_control_value(session_state: Any, key: str, default: Any) -> Any:
    """Return a detached trusted value, never a newly submitted widget value."""
    for state_key in (_ACCEPTED_CONTROL_VALUES, "_radt_previous_control_values"):
        values = session_state.get(state_key)
        if isinstance(values, dict) and key in values:
            return deepcopy(values[key])
    return deepcopy(default)


def restore_unauthorized_control_state(registry: Any, session_state: Any, ctx: Any) -> None:
    """Restore denied browser edits before native actions can snapshot them.

    Streamlit receives submitted widget values before rendering the sidebar.
    A role change or shared freeze can therefore leave an unauthorized value
    in state before the disabled control is drawn. Authenticated actions must
    see the last accepted value, or the trusted default for an unseen control.
    Call before protected callbacks and again after plugin control registration.
    """
    if not getattr(ctx, "authenticated", False):
        return
    for ctrl in registry.all():
        if not can_write(ctx, ctrl.permission):
            session_state[ctrl.key] = last_authorized_control_value(session_state, ctrl.key, ctrl.default)


def stage_replay(config: Any, session_state: Any, ctx: Any, packet: dict) -> tuple[dict, dict] | None:
    if not can_write(ctx, "can_replay_runs"):
        return None
    staged = dict(session_state)
    result = apply_replay_packet(packet, config.registry, staged)
    required = set(result["touched_keys"])
    required.update(
        ctrl.key for ctrl in config.registry.all()
        if ctrl.key not in session_state or staged[ctrl.key] != session_state[ctrl.key]
    )
    if any(not can_write(ctx, config.registry.get(key).permission) for key in required):
        return None
    return {key: deepcopy(staged[key]) for key in required}, result


def queue_replay(session_state: Any, packet: dict, checkpoint_id: str) -> None:
    session_state[_PENDING_REPLAY] = {
        "packet": deepcopy(packet), "checkpoint_id": checkpoint_id,
        "principal_id": session_state["_radt_authenticated_principal"] if "_radt_authenticated_principal" in session_state else None,
        "role": session_state["_radt_role"] if "_radt_role" in session_state else None,
    }


def apply_pending_replay(st: Any, config: Any, ctx: Any) -> None:
    """Re-authorize against this render's auth role/freeze before live writes."""
    pending = st.session_state.pop(_PENDING_REPLAY, None)
    if pending is None:
        return
    if getattr(ctx, "authenticated", False) and (
        pending.get("principal_id") != ctx.user_id or pending.get("role") != ctx.role
    ):
        st.warning("Replay denied: the authenticated account or active role has changed.")
        return
    staged = stage_replay(config, st.session_state, ctx, pending["packet"])
    if staged is None:
        st.warning("Replay denied: current role and writable state must permit every affected control. No replay values were applied. " + diagnostic_text("RADT-PERMISSION"))
        return
    values, result = staged
    for key, value in values.items():
        st.session_state[key] = value
    if getattr(ctx, "authenticated", False):
        remember_authorized_control_values(st.session_state, values)
    checkpoint_id = pending["checkpoint_id"]
    config.audit.log("checkpoint_replay", detail=checkpoint_id, role=ctx.role, source="ui")
    st.toast(f"Replayed checkpoint: {checkpoint_id} ({result['applied']} values)")
