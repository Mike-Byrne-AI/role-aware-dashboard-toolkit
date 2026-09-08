from __future__ import annotations

from typing import Any

from ..governance import governance_summary, summarize_governance
from ..security import has_perm
from .review_models import build_governance_panel_preview


def _render_governance_panel(st: Any, config: Any, ctx: Any, runs: list[dict[str, Any]]) -> None:
    governance_store = getattr(config, "governance_store", None)
    case_store = getattr(config, "case_store", None)
    can_view = has_perm(ctx, "can_view_governance", default=False)
    if governance_store is None or case_store is None or not can_view:
        return

    cases = case_store.list_cases()
    if not cases:
        return

    selected_case_id = str(st.session_state.get("_radt_selected_case_id", "") or "")
    selected_case = next((item for item in cases if str(item.get("case_id") or "") == selected_case_id), cases[-1])
    preview = build_governance_panel_preview(
        config,
        selected_case,
        actor=str(st.session_state.get("_radt_user_id", "")),
        role=ctx.role,
    )
    if preview is None:
        return
    selected_case_id = str(preview["selected_case_id"])
    governance = dict(preview["governance"])
    existing = preview.get("existing")

    records = governance_store.list_records()
    can_save = has_perm(ctx, "can_manage_governance", default=False)
    st.subheader(getattr(config, "governance_title", "Governance"))
    st.caption("Preview, validate, then explicitly save governance records. Rendering the panel does not persist state.")
    st.json(governance_summary(governance))
    if can_save and st.button("Save governance snapshot", key=f"_radt_governance_save::{selected_case_id}"):
        governance_store.save(governance)
        records = governance_store.list_records()
        if hasattr(st, "toast"):
            st.toast("Saved governance snapshot.")
    with st.expander("Governance portfolio", expanded=False):
        st.json(summarize_governance(records))
    with st.expander("Policy checks", expanded=False):
        st.json(list(governance.get("policy_checks") or []))
    with st.expander("Governance preview", expanded=False):
        st.json(governance)
    if existing is not None:
        with st.expander("Last saved governance record", expanded=False):
            st.json(existing)


__all__ = ["_render_governance_panel"]
