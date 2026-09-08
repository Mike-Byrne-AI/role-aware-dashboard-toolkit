from __future__ import annotations

from typing import Any

from ..operator_memory import (
    VALID_INCIDENT_SEVERITIES,
    build_incident_record,
    build_incident_timeline,
    build_narrative_handoff_packet,
    build_operator_note,
    build_operator_summary,
)
from ..security import has_perm
from .shared import _render_table


def _render_operator_memory_sidebar(st: Any, config: Any, ctx: Any, active_run: dict[str, Any]) -> None:
    memory_store = getattr(config, "operator_memory_store", None)
    if memory_store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    st.divider()
    st.subheader(getattr(config, "timeline_title", "Incident Timeline"))
    latest_checkpoint_id = str(active_run.get("last_checkpoint_id", "") or "")
    st.text_area("Operator note", key="_radt_operator_note_body", height=90)
    st.selectbox("Note type", options=["note", "annotation"], key="_radt_operator_note_type")
    st.selectbox("Incident severity", options=list(VALID_INCIDENT_SEVERITIES), index=2, key="_radt_incident_severity")
    st.text_input("Incident title", key="_radt_incident_title")
    st.text_input("Incident summary", key="_radt_incident_summary")
    st.text_input("Suspected cause", key="_radt_incident_cause")

    can_comment = has_perm(ctx, "can_comment_runs", default=False)
    if st.button("Add operator note", key="_radt_operator_note_btn", disabled=not can_comment) and can_comment:
        note = build_operator_note(
            str(st.session_state.get("_radt_operator_note_body", "")),
            run_id=str(active_run.get("run_id", "")),
            checkpoint_id=latest_checkpoint_id,
            actor=str(st.session_state.get("_radt_user_id", "")),
            role=ctx.role,
            event_type=str(st.session_state.get("_radt_operator_note_type", "note")),
        )
        memory_store.save_note(note)
        config.audit.log("operator_note", detail=note["note_id"], role=ctx.role, source="ui")
        st.toast(f"Operator note saved: {note['note_id']}")
        st.rerun()

    can_manage_runs = has_perm(ctx, "can_manage_runs", default=False)
    if st.button("Open incident", key="_radt_operator_incident_btn", disabled=not can_manage_runs) and can_manage_runs:
        incident = build_incident_record(
            str(active_run.get("run_id", "")),
            str(st.session_state.get("_radt_incident_title", "")),
            checkpoint_id=latest_checkpoint_id,
            actor=str(st.session_state.get("_radt_user_id", "")),
            role=ctx.role,
            severity=str(st.session_state.get("_radt_incident_severity", "medium")),
            summary=str(st.session_state.get("_radt_incident_summary", "")),
            suspected_cause=str(st.session_state.get("_radt_incident_cause", "")),
        )
        memory_store.save_incident(incident)
        config.audit.log("incident_open", detail=incident["incident_id"], role=ctx.role, source="ui")
        st.toast(f"Incident opened: {incident['incident_id']}")
        st.rerun()


def _render_operator_memory_panel(st: Any, config: Any, ctx: Any, run: dict[str, Any], checkpoint: dict[str, Any]) -> None:
    memory_store = getattr(config, "operator_memory_store", None)
    if memory_store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    run_id = str(run.get("run_id", ""))
    checkpoint_id = str(checkpoint.get("checkpoint_id", "") or run.get("last_checkpoint_id", ""))
    team_store = getattr(config, "team_store", None)
    decision_store = getattr(config, "decision_store", None)
    notes = memory_store.list_notes(run_id, checkpoint_id=checkpoint_id)
    incidents = memory_store.list_incidents(run_id)
    narratives = memory_store.list_narratives(run_id)
    decisions = (
        decision_store.list_by_run(run_id)
        if decision_store is not None and has_perm(ctx, "can_view_decisions", default=False)
        else []
    )
    handoffs = team_store.list_handoffs(run_id) if team_store is not None else []
    telemetry_history = (
        list(st.session_state.get("_radt_observability_history", []))
        if has_perm(ctx, "can_view_metrics", default=False)
        else []
    )
    audit_events = (
        config.audit.recent(50)
        if has_perm(ctx, "can_view_audit", default=False)
        else []
    )

    timeline = build_incident_timeline(
        run,
        checkpoints=list(run.get("checkpoints") or []),
        decisions=decisions,
        notes=notes,
        incidents=incidents,
        audit_events=audit_events,
        telemetry_history=telemetry_history,
        handoffs=handoffs,
    )
    summary = build_operator_summary(run, timeline=timeline, decisions=decisions, incidents=incidents)

    st.subheader(getattr(config, "timeline_title", "Incident Timeline"))
    st.json(timeline.get("summary", {}))
    st.caption(summary.get("disclaimer", ""))
    st.write(summary.get("narrative", ""))

    rows = [
        {
            "ts": item.get("ts", ""),
            "event_type": item.get("event_type", ""),
            "title": item.get("title", ""),
            "severity": item.get("severity", "info"),
            "detail": item.get("detail", ""),
        }
        for item in list(reversed(list(timeline.get("events") or [])))
    ]
    with st.expander("Timeline events", expanded=False):
        _render_table(st, rows)

    if notes:
        with st.expander("Operator notes", expanded=False):
            st.json(notes[-10:])

    if incidents:
        with st.expander("Incidents", expanded=False):
            st.json(incidents[-10:])

    if has_perm(ctx, "can_export_packets", default=False):
        narrative = build_narrative_handoff_packet(
            run,
            timeline=timeline,
            decisions=decisions,
            incidents=incidents,
            handoff_to=str(st.session_state.get("_radt_handoff_to", "")),
            actor=str(st.session_state.get("_radt_user_id", "")),
            role=ctx.role,
            source="ui",
            source_version=getattr(config, "version", ""),
        )
        with st.expander("Narrative handoff packet", expanded=False):
            st.json(narrative)
            can_manage_runs = has_perm(ctx, "can_manage_runs", default=False)
            if (
                st.button(
                    "Save narrative handoff packet",
                    key=f"_radt_save_narrative_{run_id}",
                    disabled=not can_manage_runs,
                )
                and can_manage_runs
            ):
                memory_store.save_narrative(narrative)
                config.audit.log("narrative_handoff_save", detail=narrative["narrative_id"], role=ctx.role, source="ui")
                st.toast(f"Narrative handoff saved: {narrative['narrative_id']}")
                st.rerun()
    if narratives:
        st.caption(f"Narrative packets recorded: {len(narratives)}")


__all__ = ["_render_operator_memory_panel", "_render_operator_memory_sidebar"]
