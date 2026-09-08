from __future__ import annotations

from typing import Any
from collections.abc import Mapping

from ..decisions import build_decision_case_from_run
from ..governance import build_governance_record


def build_decision_panel_preview(
    config: Any,
    run: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    *,
    actor: str,
    role: str,
) -> dict[str, Any] | None:
    decision_store = getattr(config, "decision_store", None)
    if decision_store is None:
        return None

    team_store = getattr(config, "team_store", None)
    run_id = str(run.get("run_id", ""))
    checkpoint_id = str(checkpoint.get("checkpoint_id", "") or run.get("last_checkpoint_id", ""))
    existing_cases = decision_store.list_by_run(run_id, checkpoint_id=checkpoint_id) if run_id else []
    existing = existing_cases[-1] if existing_cases else None
    comments = team_store.list_comments(run_id, checkpoint_id=checkpoint_id) if team_store is not None else []
    assignments = team_store.list_assignments(run_id, checkpoint_id=checkpoint_id) if team_store is not None else []
    signoffs = team_store.list_signoffs(run_id, checkpoint_id=checkpoint_id) if team_store is not None else []
    handoffs = team_store.list_handoffs(run_id, checkpoint_id=checkpoint_id) if team_store is not None else []
    decision = build_decision_case_from_run(
        run,
        checkpoint=checkpoint,
        assignments=assignments,
        comments=comments,
        signoffs=signoffs,
        handoffs=handoffs,
        existing=existing,
        actor=actor,
        role=role,
        source="ui",
    )
    return {"run_id": run_id, "checkpoint_id": checkpoint_id, "decision": decision}


def build_governance_panel_preview(
    config: Any,
    selected_case: Mapping[str, Any],
    *,
    actor: str,
    role: str,
) -> dict[str, Any] | None:
    governance_store = getattr(config, "governance_store", None)
    if governance_store is None:
        return None

    selected_case_id = str(selected_case.get("case_id") or "")
    decision_store = getattr(config, "decision_store", None)
    memory_store = getattr(config, "operator_memory_store", None)
    team_store = getattr(config, "team_store", None)

    linked_run_ids = list(selected_case.get("linked_run_ids") or [])
    linked_incident_ids = set(str(item) for item in list(selected_case.get("linked_incident_ids") or []))
    linked_decision_ids = set(str(item) for item in list(selected_case.get("linked_decision_ids") or []))

    decisions: list[dict[str, Any]] = []
    signoffs: list[dict[str, Any]] = []
    for run_id in linked_run_ids:
        if decision_store is not None:
            decisions.extend(decision_store.list_by_run(run_id))
        if team_store is not None:
            signoffs.extend(team_store.list_signoffs(run_id))
    if linked_decision_ids:
        decisions = [item for item in decisions if str(item.get("decision_id") or "") in linked_decision_ids or not linked_decision_ids]

    if memory_store is not None:
        incidents = [item for item in memory_store.list_incidents() if str(item.get("incident_id") or "") in linked_incident_ids or not linked_incident_ids]
    else:
        incidents = []

    existing_records = governance_store.list_by_case(selected_case_id)
    existing = existing_records[-1] if existing_records else None
    governance = build_governance_record(
        selected_case,
        decisions=decisions,
        incidents=incidents,
        signoffs=signoffs,
        existing=existing,
        actor=actor,
        role=role,
        source="ui_preview",
    )
    return {
        "selected_case_id": selected_case_id,
        "existing": existing,
        "governance": governance,
    }

