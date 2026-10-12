from __future__ import annotations

from typing import Any

from ..governance import governance_summary, summarize_governance
from .._evidence_reads import EvidenceUnavailable, read_records, require_evidence_permissions, warn_incomplete_evidence
from .._record_projection import project_record
from ..security import can_mutate, has_perm
from .review_models import build_governance_panel_preview
from .shared import _record_actor, _save_record


def _render_governance_panel(st: Any, config: Any, ctx: Any, runs: list[dict[str, Any]]) -> None:
    governance_store = getattr(config, "governance_store", None)
    case_store = getattr(config, "case_store", None)
    can_view = has_perm(ctx, "can_view_governance", default=False)
    if governance_store is None or case_store is None or not can_view:
        return

    try:
        # Saved governance also contains derived decision details. Do not read
        # or expose those records through a weaker source permission boundary.
        if not has_perm(ctx, "can_view_decisions"):
            raise EvidenceUnavailable()
        cases = read_records(case_store, "list_cases", record_type="case", ctx=ctx, permission="can_view_team_ops")
        if not cases:
            return
        selected_case_id = str(st.session_state.get("_radt_selected_case_id", "") or "")
        selected_case = next((item for item in cases if str(item.get("case_id") or "") == selected_case_id), cases[-1])
        preview = build_governance_panel_preview(
            config, selected_case, actor=_record_actor(ctx, st.session_state), role=ctx.role, ctx=ctx, runs=runs,
        )
        records = read_records(governance_store, "list_records", record_type="governance", ctx=ctx,
                               permission="can_view_governance")
        require_evidence_permissions(ctx, "can_view_team_ops", "can_view_decisions", "can_view_governance")
    except EvidenceUnavailable:
        warn_incomplete_evidence(st)
        return
    if preview is None:
        return
    selected_case_id = str(preview["selected_case_id"])
    governance = dict(preview["governance"])
    existing = preview.get("existing")

    can_save = can_mutate(ctx, "can_manage_governance", default=False)
    st.subheader(getattr(config, "governance_title", "Governance"))
    st.caption("Preview, validate, then explicitly save governance records. Rendering the panel does not persist state.")
    st.json(governance_summary(governance))
    if (can_save and st.button("Save governance snapshot", key=f"_radt_governance_save::{selected_case_id}")
            and can_mutate(ctx, "can_manage_governance")
            and _save_record(st, governance_store.save, governance)):
        try:
            records = read_records(governance_store, "list_records", record_type="governance", ctx=ctx,
                                   permission="can_view_governance")
            require_evidence_permissions(ctx, "can_view_team_ops", "can_view_decisions", "can_view_governance")
        except EvidenceUnavailable:
            warn_incomplete_evidence(st)
            return
        if hasattr(st, "toast"):
            st.toast("Saved governance snapshot.")
    with st.expander("Governance portfolio", expanded=False):
        st.json(summarize_governance(records))
    with st.expander("Policy checks", expanded=False):
        st.json(project_record(list(governance.get("policy_checks") or []), getattr(config, "registry", None)))
    with st.expander("Governance preview", expanded=False):
        st.json(project_record(governance, getattr(config, "registry", None)))
    if existing is not None:
        with st.expander("Last saved governance record", expanded=False):
            st.json(project_record(existing, getattr(config, "registry", None)))


__all__ = ["_render_governance_panel"]
