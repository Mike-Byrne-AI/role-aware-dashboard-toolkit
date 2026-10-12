from __future__ import annotations

from copy import deepcopy
from collections.abc import Callable
from typing import Any

from .._optional_pandas import load_optional_pandas
from .._record_projection import project_record
from ..security import has_perm

pd = None
PANDAS_AVAILABLE: bool | None = None


def _save_record(st: Any, save: Callable[[dict[str, Any]], Any], record: dict[str, Any]) -> bool:
    """Report uncertain storage completion without leaking provider details.

    Only the storage call is caught. Callers keep rendering their widgets on
    failure, and emit success events or rerun only after a confirmed return.
    Never retry here: a provider can commit a write before raising an error.
    """
    try:
        save(record)
    except Exception:
        st.warning(
            "Record storage could not confirm this save. It may have completed partially. "
            "Check the saved records and storage before retrying. "
            "Help: python -m role_aware_dashboard_toolkit guide runs"
        )
        return False
    return True


def _render_table(st: Any, rows: Any) -> None:
    pandas = _load_pandas()
    if pandas is None:
        st.json(rows)
        return
    st.dataframe(pandas.DataFrame(rows), width="stretch", hide_index=True)


def _parse_tags(raw: Any) -> list[str]:
    parts = [str(part).strip() for part in str(raw or "").split(",")]
    return [part for part in parts if part]


def _selected_profile_id(session_state: dict[str, Any]) -> str:
    for key in ("_radt_active_profile_id", "_radt_selected_profile_id", "_radt_last_profile_id"):
        value = str(session_state.get(key, "") or "")
        if value:
            return value
    return ""


def _record_actor(ctx: Any, session_state: Any) -> str:
    """Use the authenticated principal instead of mutable session metadata."""
    if getattr(ctx, "authenticated", False):
        return str(ctx.user_id)
    return str(session_state.get("_radt_user_id", ""))


def _record_session(ctx: Any, session_state: Any) -> str:
    if getattr(ctx, "authenticated", False):
        return str(ctx.session_id)
    return str(session_state.get("_radt_session_id", ""))


def _record_summary_view(
    record: dict[str, Any], ctx: Any, registry: Any = None, *, source: Any = None,
) -> dict[str, Any]:
    """Filter native saved-control summaries at display time, without editing evidence."""
    can_view_values = has_perm(ctx, "can_view_metrics", default=False)
    view = project_record(
        {"source": source, "record": record}, registry,
        include_control_metadata_values=can_view_values,
    )["record"]
    if not can_view_values:
        summary = view.get("summary")
        if isinstance(summary, dict):
            summary.pop("latest_controls", None)
    return view


def _current_approval_state(ctx: Any, *, can_approve: bool) -> str:
    if can_approve:
        return "approved"
    if has_perm(ctx, "can_edit_controls", default=False):
        return "proposed"
    return "replay_only"


def _latest_telemetry(session_state: dict[str, Any]) -> dict[str, Any]:
    latest = session_state.get("_radt_last_telemetry")
    if isinstance(latest, dict):
        return deepcopy(latest)
    return {}


def _load_pandas():
    global pd, PANDAS_AVAILABLE
    pd, PANDAS_AVAILABLE, _checked = load_optional_pandas(pd, PANDAS_AVAILABLE)
    return pd


__all__ = [
    "PANDAS_AVAILABLE",
    "_current_approval_state",
    "_latest_telemetry",
    "_parse_tags",
    "_record_actor",
    "_record_session",
    "_record_summary_view",
    "_render_table",
    "_save_record",
    "_selected_profile_id",
    "pd",
]
