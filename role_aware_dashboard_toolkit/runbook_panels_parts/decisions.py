from __future__ import annotations

from typing import Any

from ..decisions import decision_summary
from .._evidence_reads import EvidenceUnavailable, warn_incomplete_evidence
from ..security import can_mutate, has_perm
from .review_models import build_decision_panel_preview
from .shared import _record_actor, _record_summary_view, _render_table


def _render_decision_panel(st: Any, config: Any, ctx: Any, run: dict[str, Any], checkpoint: dict[str, Any]) -> None:
    decision_store = getattr(config, "decision_store", None)
    if decision_store is None or not has_perm(ctx, "can_view_decisions", default=False):
        return

    try:
        preview = build_decision_panel_preview(
            config, run, checkpoint, actor=_record_actor(ctx, st.session_state), role=ctx.role, ctx=ctx,
        )
    except EvidenceUnavailable:
        warn_incomplete_evidence(st)
        return
    if preview is None:
        return

    run_id = str(preview["run_id"])
    checkpoint_id = str(preview["checkpoint_id"])
    decision = dict(preview["decision"])

    can_save = can_mutate(ctx, "can_manage_decisions", default=False)
    st.subheader(getattr(config, "decision_title", "Decision Layer"))
    st.caption("Preview, validate, then explicitly save decision records. Rendering the panel does not persist state.")
    st.json(decision_summary(decision))
    if can_save and st.button("Save decision snapshot", key=f"_radt_decision_save::{run_id}::{checkpoint_id}") and can_mutate(ctx, "can_manage_decisions"):
        decision_store.save(decision)
        if hasattr(st, "toast"):
            st.toast("Saved decision snapshot.")
    if decision.get("blockers"):
        st.caption("Blockers")
        st.json(decision.get("blockers", []))

    with st.expander("Decision Case", expanded=False):
        st.json(_record_summary_view(
            decision, ctx, getattr(config, "registry", None), source=[run, checkpoint],
        ))

    if decision.get("history"):
        rows = [
            {
                "ts": item.get("ts", ""),
                "event_type": item.get("event_type", ""),
                "from_state": item.get("from_state", ""),
                "to_state": item.get("to_state", ""),
                "actor": item.get("actor", ""),
                "role": item.get("role", ""),
                "ref_id": item.get("ref_id", ""),
            }
            for item in decision.get("history", [])
        ]
        with st.expander("Decision History", expanded=False):
            _render_table(st, rows)


__all__ = ["_render_decision_panel"]
