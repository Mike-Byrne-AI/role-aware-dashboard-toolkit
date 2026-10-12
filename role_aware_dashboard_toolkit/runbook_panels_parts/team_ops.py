from __future__ import annotations

from typing import Any

from ..security import can_mutate, has_perm
from .._evidence_reads import EvidenceUnavailable, read_records, warn_incomplete_evidence
from .._record_projection import preserve_sensitivity_metadata, project_record
from ..team_ops import (
    build_handoff_summary,
    build_review_assignment,
    build_signoff_record,
    build_team_comment,
    summarize_team_ops,
)
from .shared import _record_actor, _record_summary_view, _render_table, _save_record


def _render_team_ops_sidebar(st: Any, config: Any, ctx: Any, active_run: dict[str, Any]) -> None:
    team_store = getattr(config, "team_store", None)
    if team_store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    st.divider()
    st.subheader(getattr(config, "team_ops_title", "Team Ops"))
    latest_checkpoint_id = str(active_run.get("last_checkpoint_id", "") or "")

    st.text_input("Team comment", key="_radt_team_comment_body")
    st.text_input("Reviewer", key="_radt_review_assignee")
    st.text_input("Reviewer role", key="_radt_review_assignee_role")
    st.text_input("Review title", key="_radt_review_title")
    st.text_input("Handoff to", key="_radt_handoff_to")
    st.text_input("Handoff role", key="_radt_handoff_role")

    can_comment = can_mutate(ctx, "can_comment_runs", default=False)
    if st.button("Add comment", key="_radt_team_comment_btn", disabled=not can_comment) and can_mutate(ctx, "can_comment_runs"):
        comment = build_team_comment(
            str(st.session_state.get("_radt_team_comment_body", "")),
            run_id=str(active_run.get("run_id", "")),
            checkpoint_id=latest_checkpoint_id,
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
        )
        if _save_record(st, team_store.save_comment, comment):
            config.audit.log("team_comment", detail=comment["comment_id"], role=ctx.role, source="ui")
            st.toast(f"Comment added: {comment['comment_id']}")
            st.rerun()

    can_assign = can_mutate(ctx, "can_assign_reviews", default=False)
    if st.button("Assign review", key="_radt_assign_review_btn", disabled=not can_assign) and can_mutate(ctx, "can_assign_reviews"):
        assignment = build_review_assignment(
            str(active_run.get("run_id", "")),
            checkpoint_id=latest_checkpoint_id,
            title=str(st.session_state.get("_radt_review_title", "") or "") or "Review latest checkpoint",
            assignee=str(st.session_state.get("_radt_review_assignee", "")),
            assignee_role=str(st.session_state.get("_radt_review_assignee_role", "")),
            assigned_by=_record_actor(ctx, st.session_state),
            assigned_role=ctx.role,
            instructions=str(st.session_state.get("_radt_checkpoint_reason", "")),
        )
        if _save_record(st, team_store.save_assignment, assignment):
            config.audit.log("review_assignment", detail=assignment["assignment_id"], role=ctx.role, source="ui")
            st.toast(f"Assigned review: {assignment['assignment_id']}")
            st.rerun()

    can_signoff = bool(latest_checkpoint_id) and can_mutate(ctx, "can_signoff_runs", default=False)
    if st.button("Sign off latest checkpoint", key="_radt_signoff_btn", disabled=not can_signoff) and latest_checkpoint_id and can_mutate(ctx, "can_signoff_runs"):
        signoff = build_signoff_record(
            str(active_run.get("run_id", "")),
            "approved",
            checkpoint_id=latest_checkpoint_id,
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            reason=str(st.session_state.get("_radt_checkpoint_reason", "")),
            summary=str(st.session_state.get("_radt_run_outcome", "")),
        )
        if _save_record(st, team_store.save_signoff, signoff):
            config.audit.log("checkpoint_signoff", detail=signoff["signoff_id"], role=ctx.role, source="ui")
            st.toast(f"Signoff saved: {signoff['signoff_id']}")
            st.rerun()

    can_manage_runs = can_mutate(ctx, "can_manage_runs", default=False)
    if st.button("Create handoff", key="_radt_handoff_btn", disabled=not can_manage_runs) and can_mutate(ctx, "can_manage_runs"):
        try:
            comments = read_records(team_store, "list_comments", str(active_run.get("run_id", "")),
                                   record_type="comment", ctx=ctx, permission="can_view_team_ops")
            assignments = read_records(team_store, "list_assignments", str(active_run.get("run_id", "")),
                                      record_type="assignment", ctx=ctx, permission="can_view_team_ops")
            signoffs = read_records(team_store, "list_signoffs", str(active_run.get("run_id", "")),
                                   record_type="signoff", ctx=ctx, permission="can_view_team_ops")
        except EvidenceUnavailable:
            warn_incomplete_evidence(st)
            return
        handoff = build_handoff_summary(
            active_run,
            handoff_to=str(st.session_state.get("_radt_handoff_to", "")),
            handoff_role=str(st.session_state.get("_radt_handoff_role", "")),
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            notes=str(st.session_state.get("_radt_run_notes", "")),
            comments=comments,
            assignments=assignments,
            signoffs=signoffs,
        )
        registry = getattr(config, "registry", None)
        handoff = preserve_sensitivity_metadata(
            handoff, active_run,
            {"control_meta": registry.export_metadata()} if registry is not None else {},
        )
        if not can_mutate(ctx, "can_manage_runs"):
            st.warning("Handoff creation is no longer permitted. Check access and freeze state, then retry.")
            return
        if _save_record(st, team_store.save_handoff, handoff):
            config.audit.log("run_handoff", detail=handoff["handoff_id"], role=ctx.role, source="ui")
            st.toast(f"Handoff created: {handoff['handoff_id']}")
            st.rerun()


def _render_team_ops_panel(st: Any, config: Any, ctx: Any, run: dict[str, Any]) -> None:
    team_store = getattr(config, "team_store", None)
    if team_store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    run_id = str(run.get("run_id", ""))
    try:
        comments = read_records(team_store, "list_comments", run_id, record_type="comment", ctx=ctx,
                               permission="can_view_team_ops")
        assignments = read_records(team_store, "list_assignments", run_id, record_type="assignment", ctx=ctx,
                                  permission="can_view_team_ops")
        signoffs = read_records(team_store, "list_signoffs", run_id, record_type="signoff", ctx=ctx,
                               permission="can_view_team_ops")
        handoffs = read_records(team_store, "list_handoffs", run_id, record_type="handoff", ctx=ctx,
                               permission="can_view_team_ops")
    except EvidenceUnavailable:
        warn_incomplete_evidence(st)
        return
    summary = summarize_team_ops(assignments, comments, signoffs)

    st.subheader(getattr(config, "team_ops_title", "Team Ops"))
    st.json(summary)

    if assignments:
        rows = [
            {
                "assignment_id": item.get("assignment_id", ""),
                "ts": item.get("ts", ""),
                "title": item.get("title", ""),
                "assignee": item.get("assignee", ""),
                "assignee_role": item.get("assignee_role", ""),
                "status": item.get("status", ""),
                "priority": item.get("priority", ""),
            }
            for item in assignments
        ]
        with st.expander("Assignments", expanded=False):
            _render_table(st, rows)

    if comments:
        with st.expander("Comments", expanded=False):
            st.json(project_record(comments[-10:], getattr(config, "registry", None)))

    if signoffs:
        with st.expander("Signoffs", expanded=False):
            st.json(project_record(signoffs[-10:], getattr(config, "registry", None)))

    if handoffs:
        with st.expander("Latest handoff", expanded=False):
            st.json(_record_summary_view(handoffs[-1], ctx, getattr(config, "registry", None), source=run))


__all__ = ["_render_team_ops_panel", "_render_team_ops_sidebar"]
