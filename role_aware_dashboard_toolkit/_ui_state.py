"""Private Streamlit lifecycle support; never apply bulk edits after widgets exist."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .replay import apply_replay_packet
from .security import can_write

_PENDING_REPLAY = "_radt_pending_replay"


def retain_control_state(registry: Any, session_state: Any) -> None:
    """Detach registered values from widget cleanup before any early sidebar rerun.

    Streamlit deletes state for widgets omitted by a rerun. Explicit assignment
    before widget creation preserves values, including hidden and frozen controls.
    """
    for key in registry.keys():
        if key in session_state:
            session_state[key] = session_state[key]


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
    }


def apply_pending_replay(st: Any, config: Any, ctx: Any) -> None:
    """Re-authorize against this render's auth role/freeze before live writes."""
    pending = st.session_state.pop(_PENDING_REPLAY, None)
    if pending is None:
        return
    staged = stage_replay(config, st.session_state, ctx, pending["packet"])
    if staged is None:
        st.warning("Replay denied: current role and writable state must permit every affected control. No replay values were applied.")
        return
    values, result = staged
    for key, value in values.items():
        st.session_state[key] = value
    checkpoint_id = pending["checkpoint_id"]
    config.audit.log("checkpoint_replay", detail=checkpoint_id, role=ctx.role, source="ui")
    st.toast(f"Replayed checkpoint: {checkpoint_id} ({result['applied']} values)")
