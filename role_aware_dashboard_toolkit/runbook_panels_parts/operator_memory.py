from __future__ import annotations

import json
from typing import Any

from ..operator_memory import (
    VALID_INCIDENT_SEVERITIES,
    build_incident_record,
    build_incident_timeline,
    build_narrative_handoff_packet,
    build_operator_note,
    build_operator_summary,
)
from ..security import can_mutate, has_perm
from .._evidence_reads import EvidenceUnavailable, read_records, require_evidence_permissions, warn_incomplete_evidence
from .._record_projection import project_record
from .shared import _record_actor, _render_table, _save_record


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

    can_comment = can_mutate(ctx, "can_comment_runs", default=False)
    if st.button("Add operator note", key="_radt_operator_note_btn", disabled=not can_comment) and can_mutate(ctx, "can_comment_runs"):
        note = build_operator_note(
            str(st.session_state.get("_radt_operator_note_body", "")),
            run_id=str(active_run.get("run_id", "")),
            checkpoint_id=latest_checkpoint_id,
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            event_type=str(st.session_state.get("_radt_operator_note_type", "note")),
        )
        if _save_record(st, memory_store.save_note, note):
            config.audit.log("operator_note", detail=note["note_id"], role=ctx.role, source="ui")
            st.toast(f"Operator note saved: {note['note_id']}")
            st.rerun()

    can_manage_runs = can_mutate(ctx, "can_manage_runs", default=False)
    if st.button("Open incident", key="_radt_operator_incident_btn", disabled=not can_manage_runs) and can_mutate(ctx, "can_manage_runs"):
        incident = build_incident_record(
            str(active_run.get("run_id", "")),
            str(st.session_state.get("_radt_incident_title", "")),
            checkpoint_id=latest_checkpoint_id,
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            severity=str(st.session_state.get("_radt_incident_severity", "medium")),
            summary=str(st.session_state.get("_radt_incident_summary", "")),
            suspected_cause=str(st.session_state.get("_radt_incident_cause", "")),
        )
        if _save_record(st, memory_store.save_incident, incident):
            config.audit.log("incident_open", detail=incident["incident_id"], role=ctx.role, source="ui")
            st.toast(f"Incident opened: {incident['incident_id']}")
            st.rerun()


def _captured_records(checkpoints: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    """Keep distinct captured records when checkpoints have overlapping slices."""
    records = []
    seen = set()
    for checkpoint in checkpoints:
        captured = checkpoint.get(field)
        candidates = captured if isinstance(captured, list) else [captured]
        for record in candidates:
            if not isinstance(record, dict) or not record:
                continue
            identity = json.dumps(record, sort_keys=True, separators=(",", ":"))
            if identity not in seen:
                seen.add(identity)
                records.append(record)
    return records


def _render_operator_memory_panel(st: Any, config: Any, ctx: Any, run: dict[str, Any], checkpoint: dict[str, Any]) -> None:
    memory_store = getattr(config, "operator_memory_store", None)
    if memory_store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    run_id = str(run.get("run_id", ""))
    checkpoint_id = str(checkpoint.get("checkpoint_id", "") or run.get("last_checkpoint_id", ""))
    team_store = getattr(config, "team_store", None)
    decision_store = getattr(config, "decision_store", None)
    try:
        notes = read_records(memory_store, "list_notes", run_id, checkpoint_id=checkpoint_id,
                             record_type="operator_note", ctx=ctx, permission="can_view_team_ops")
        incidents = read_records(memory_store, "list_incidents", run_id, record_type="incident", ctx=ctx,
                                 permission="can_view_team_ops")
        narratives = read_records(memory_store, "list_narratives", run_id, record_type="narrative_handoff", ctx=ctx,
                                  permission="can_view_team_ops")
        decisions = read_records(decision_store, "list_by_run", run_id, record_type="decision", ctx=ctx,
                                 permission="can_view_decisions")
        handoffs = read_records(team_store, "list_handoffs", run_id, record_type="handoff", ctx=ctx,
                                permission="can_view_team_ops")
        require_evidence_permissions(ctx, "can_view_team_ops")
        if decision_store is not None:
            require_evidence_permissions(ctx, "can_view_decisions")
    except EvidenceUnavailable:
        warn_incomplete_evidence(st)
        return
    can_view_metrics = has_perm(ctx, "can_view_metrics", default=False)
    can_view_audit = has_perm(ctx, "can_view_audit", default=False)
    checkpoints = list(run.get("checkpoints") or [])
    # A selected run owns its captured checkpoint context, not the current
    # session's audit log or telemetry history. Deduplicate before projection,
    # then redact before timeline builders can embed values in ordinary text.
    captured = {
        "audit_events": _captured_records(checkpoints, "audit_slice") if can_view_audit else [],
        "telemetry_history": _captured_records(checkpoints, "telemetry_slice") if can_view_metrics else [],
    }
    captured_view = project_record(
        {"source": run, "captured": captured}, getattr(config, "registry", None),
    )["captured"]

    timeline = build_incident_timeline(
        run,
        checkpoints=checkpoints,
        decisions=decisions,
        notes=notes,
        incidents=incidents,
        audit_events=captured_view["audit_events"],
        telemetry_history=captured_view["telemetry_history"],
        handoffs=handoffs,
    )
    summary = build_operator_summary(run, timeline=timeline, decisions=decisions, incidents=incidents)
    try:
        require_evidence_permissions(
            ctx, "can_view_team_ops",
            *(["can_view_decisions"] if decision_store is not None else []),
            *(["can_view_metrics"] if can_view_metrics else []),
            *(["can_view_audit"] if can_view_audit else []),
        )
    except EvidenceUnavailable:
        warn_incomplete_evidence(st)
        return

    st.subheader(getattr(config, "timeline_title", "Incident Timeline"))
    st.json(timeline.get("summary", {}))
    st.caption(summary.get("disclaimer", ""))
    st.text(summary.get("narrative", ""))

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
            st.json(project_record(notes[-10:], getattr(config, "registry", None)))

    if incidents:
        with st.expander("Incidents", expanded=False):
            st.json(project_record(incidents[-10:], getattr(config, "registry", None)))

    if has_perm(ctx, "can_export_packets", default=False):
        narrative = build_narrative_handoff_packet(
            run,
            timeline=timeline,
            decisions=decisions,
            incidents=incidents,
            handoff_to=str(st.session_state.get("_radt_handoff_to", "")),
            actor=_record_actor(ctx, st.session_state),
            role=ctx.role,
            source="ui",
            source_version=getattr(config, "version", ""),
        )
        with st.expander("Narrative handoff packet", expanded=False):
            st.json(project_record(narrative, getattr(config, "registry", None)))
            can_manage_runs = can_mutate(ctx, "can_manage_runs", default=False)
            if (
                st.button(
                    "Save narrative handoff packet",
                    key=f"_radt_save_narrative_{run_id}",
                    disabled=not can_manage_runs,
                )
                and can_mutate(ctx, "can_manage_runs")
            ):
                if _save_record(st, memory_store.save_narrative, narrative):
                    config.audit.log("narrative_handoff_save", detail=narrative["narrative_id"], role=ctx.role, source="ui")
                    st.toast(f"Narrative handoff saved: {narrative['narrative_id']}")
                    st.rerun()
    if narratives:
        st.caption(f"Narrative packets recorded: {len(narratives)}")


__all__ = ["_render_operator_memory_panel", "_render_operator_memory_sidebar"]
