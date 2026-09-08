from __future__ import annotations

from typing import Any

from .._optional_pandas import load_optional_pandas
from ..security import has_perm

pd = None
PANDAS_AVAILABLE: bool | None = None


def _render_table(st: Any, rows: Any) -> None:
    pandas = _load_pandas()
    if pandas is None:
        st.json(rows)
        return
    st.dataframe(pandas.DataFrame(rows), use_container_width=True, hide_index=True)


def _parse_tags(raw: Any) -> list[str]:
    parts = [str(part).strip() for part in str(raw or "").split(",")]
    return [part for part in parts if part]


def _selected_profile_id(session_state: dict[str, Any]) -> str:
    for key in ("_radt_selected_profile_id", "_radt_last_profile_id", "_radt_active_profile_id"):
        value = str(session_state.get(key, "") or "")
        if value:
            return value
    return ""


def _current_approval_state(ctx: Any, *, can_approve: bool) -> str:
    if can_approve:
        return "approved"
    if has_perm(ctx, "can_edit_controls", default=False):
        return "proposed"
    return "replay_only"


def _latest_telemetry(session_state: dict[str, Any]) -> dict[str, Any]:
    latest = session_state.get("_radt_last_telemetry")
    if isinstance(latest, dict):
        return dict(latest)
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
    "_render_table",
    "_selected_profile_id",
    "pd",
]
