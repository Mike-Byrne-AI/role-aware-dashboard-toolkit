from __future__ import annotations

from typing import Any

from ..caseboard import (
    add_case_notes,
    build_case_from_records,
    case_summary,
    close_case,
    compare_cases,
    link_case_records,
    reopen_case,
    summarize_caseboard,
)
from ..security import can_mutate, has_perm
from .._evidence_reads import EvidenceUnavailable, read_records, warn_incomplete_evidence
from .._record_projection import project_record
from .review_models import build_governance_panel_preview
from .shared import _record_actor, _render_table, _save_record


def _close_case_block(st: Any, config: Any, ctx: Any, case: dict[str, Any], runs: list[dict[str, Any]]) -> str | None:
    """Return why governance blocks closing ``case`` now, or None when it does not.

    With a governance store configured, the case is evaluated as the governance
    panel would preview it. If that evaluation cannot run for this user or its
    evidence cannot be read, closing is refused rather than allowed blind.
    """
    if getattr(config, "governance_store", None) is None:
        return None
    try:
        preview = build_governance_panel_preview(
            config, case, actor=_record_actor(ctx, st.session_state), role=ctx.role, ctx=ctx, runs=runs,
        )
    except EvidenceUnavailable:
        return (
            "Close case is unavailable: governance could not be evaluated for this case with your access. "
            "Check access and the linked evidence, then retry."
        )
    if preview is None:
        return None
    governance = preview["governance"]
    if "close_case" not in list(governance.get("blocked_actions") or []):
        return None
    return f"Governance blocks closing this case. {governance.get('summary_text') or ''}".strip()


def _render_caseboard_panel(st: Any, config: Any, ctx: Any, runs: list[dict[str, Any]], selected_run: dict[str, Any]) -> None:
    case_store = getattr(config, "case_store", None)
    if case_store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    memory_store = getattr(config, "operator_memory_store", None)
    try:
        cases = read_records(case_store, "list_cases", record_type="case", ctx=ctx, permission="can_view_team_ops")
        incidents = read_records(memory_store, "list_incidents", record_type="incident", ctx=ctx,
                                 permission="can_view_team_ops")
        narratives = read_records(memory_store, "list_narratives", record_type="narrative_handoff", ctx=ctx,
                                  permission="can_view_team_ops")
        notes = read_records(memory_store, "list_notes", record_type="operator_note", ctx=ctx,
                             permission="can_view_team_ops")
    except EvidenceUnavailable:
        warn_incomplete_evidence(st)
        return
    summary = summarize_caseboard(cases)
    run_options = [str(run.get("run_id") or "") for run in runs if str(run.get("run_id") or "")]
    selected_run_id = str(selected_run.get("run_id") or "")

    st.subheader(getattr(config, "caseboard_title", "Caseboard"))
    st.json(summary)

    default_run_selection = [selected_run_id] if selected_run_id else []
    st.text_input("Case title", key="_radt_case_title")
    st.text_area("Case summary", key="_radt_case_summary", height=80)
    st.selectbox("Case priority", options=["low", "normal", "high", "critical"], index=1, key="_radt_case_priority")
    st.multiselect("Linked runs", options=run_options, default=default_run_selection, key="_radt_case_run_ids")
    incident_options = [str(item.get("incident_id") or "") for item in incidents if str(item.get("incident_id") or "")]
    narrative_options = [str(item.get("narrative_id") or "") for item in narratives if str(item.get("narrative_id") or "")]
    st.multiselect("Linked incidents", options=incident_options, key="_radt_case_incident_ids")
    st.multiselect("Linked narratives", options=narrative_options, key="_radt_case_narrative_ids")
    st.text_area("Case finding / note", key="_radt_case_note_body", height=70)

    can_manage_runs = can_mutate(ctx, "can_manage_runs", default=False)
    if st.button("Create case", key="_radt_case_create_btn", disabled=not can_manage_runs) and can_mutate(ctx, "can_manage_runs"):
        selected_incidents = [item for item in incidents if str(item.get("incident_id") or "") in set(st.session_state.get("_radt_case_incident_ids", []))]
        selected_narratives = [item for item in narratives if str(item.get("narrative_id") or "") in set(st.session_state.get("_radt_case_narrative_ids", []))]
        selected_notes = [item for item in notes if str(item.get("run_id") or "") in set(st.session_state.get("_radt_case_run_ids", []))][-3:]
        case = build_case_from_records(
            str(st.session_state.get("_radt_case_title", "")),
            incidents=selected_incidents,
            narratives=selected_narratives,
            notes=selected_notes,
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            source="ui",
            priority=str(st.session_state.get("_radt_case_priority", "normal")),
        )
        if str(st.session_state.get("_radt_case_summary", "") or "").strip():
            case["summary"] = str(st.session_state.get("_radt_case_summary", "")).strip()
        case = link_case_records(
            case,
            run_ids=list(st.session_state.get("_radt_case_run_ids", [])),
            incident_ids=list(st.session_state.get("_radt_case_incident_ids", [])),
            narrative_ids=list(st.session_state.get("_radt_case_narrative_ids", [])),
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            source="ui",
        )
        note_body = str(st.session_state.get("_radt_case_note_body", "") or "").strip()
        if note_body:
            case = add_case_notes(case, [note_body], actor=_record_actor(ctx, st.session_state), role=ctx.role, source="ui")
        if _save_record(st, case_store.save, case):
            config.audit.log("case_create", detail=case["case_id"], role=ctx.role, source="ui")
            st.toast(f"Case created: {case['case_id']}")
            st.rerun()

    if not cases:
        st.caption("No cross-run cases recorded yet.")
        return

    case_rows = [case_summary(item) for item in cases]
    with st.expander("Cases", expanded=False):
        _render_table(st, case_rows)

    case_ids = [row["case_id"] for row in case_rows]
    default_case_id = case_ids[-1]
    selected_case_id = st.selectbox("Case detail", options=case_ids, index=case_ids.index(default_case_id), key="_radt_selected_case_id")
    selected_case = next(case for case in cases if case.get("case_id") == selected_case_id)
    st.json(case_summary(selected_case))
    with st.expander("Case record", expanded=False):
        st.json(project_record(selected_case, getattr(config, "registry", None)))

    if st.button("Reopen case", key=f"_radt_reopen_case_{selected_case_id}", disabled=not can_manage_runs) and can_mutate(ctx, "can_manage_runs"):
        updated = reopen_case(
            selected_case,
            reason="Reopened from caseboard UI.",
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            source="ui",
        )
        if _save_record(st, case_store.save, updated):
            config.audit.log("case_reopen", detail=updated["case_id"], role=ctx.role, source="ui")
            st.toast(f"Case reopened: {updated['case_id']}")
            st.rerun()

    close_block = _close_case_block(st, config, ctx, selected_case, runs) if can_manage_runs else None
    if close_block is not None:
        st.caption(close_block)
    if (
        st.button("Close case", key=f"_radt_close_case_{selected_case_id}",
                  disabled=not can_manage_runs or close_block is not None)
        and close_block is None
        and can_mutate(ctx, "can_manage_runs")
    ):
        updated = close_case(
            selected_case,
            reason="Closed from caseboard UI.",
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            source="ui",
        )
        if _save_record(st, case_store.save, updated):
            config.audit.log("case_close", detail=updated["case_id"], role=ctx.role, source="ui")
            st.toast(f"Case closed: {updated['case_id']}")
            st.rerun()

    note_body = str(st.session_state.get("_radt_case_note_body", "") or "").strip()
    can_comment = bool(note_body) and can_mutate(ctx, "can_comment_runs", default=False)
    if st.button("Append finding to selected case", key=f"_radt_case_append_note_{selected_case_id}", disabled=not can_comment) and note_body and can_mutate(ctx, "can_comment_runs"):
        updated = add_case_notes(
            selected_case,
            [note_body],
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            source="ui",
        )
        if _save_record(st, case_store.save, updated):
            config.audit.log("case_note", detail=updated["case_id"], role=ctx.role, source="ui")
            st.toast(f"Case updated: {updated['case_id']}")
            st.rerun()

    if len(cases) >= 2:
        left_id = st.selectbox("Compare left case", options=case_ids, index=max(0, len(case_ids) - 2), key="_radt_compare_case_left")
        right_id = st.selectbox("Compare right case", options=case_ids, index=len(case_ids) - 1, key="_radt_compare_case_right")
        left_case = next(case for case in cases if case.get("case_id") == left_id)
        right_case = next(case for case in cases if case.get("case_id") == right_id)
        with st.expander("Case compare", expanded=False):
            st.json(project_record(compare_cases(left_case, right_case), getattr(config, "registry", None)))


__all__ = ["_render_caseboard_panel"]
