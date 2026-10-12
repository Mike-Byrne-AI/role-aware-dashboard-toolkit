from __future__ import annotations

from typing import Any
from collections.abc import Mapping

from ..decisions import build_decision_case_from_run
from ..governance import build_governance_record
from .._evidence_reads import EvidenceUnavailable, read_record, read_records, require_evidence_permissions
from .._record_projection import preserve_sensitivity_metadata
from ..security import has_perm
from ..validators import validate_record


def _linked_ids(record: Mapping[str, Any], field: str) -> list[str]:
    values = record.get(field, [])
    if not isinstance(values, list) or any(not isinstance(item, str) or not item.strip() for item in values):
        raise EvidenceUnavailable()
    return values


def build_decision_panel_preview(
    config: Any,
    run: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    *,
    actor: str,
    role: str,
    ctx: Any = None,
) -> dict[str, Any] | None:
    decision_store = getattr(config, "decision_store", None)
    if decision_store is None:
        return None
    require_evidence_permissions(ctx, "can_view_team_ops", "can_view_decisions")

    team_store = getattr(config, "team_store", None)
    run_id = str(run.get("run_id", ""))
    checkpoint_id = str(checkpoint.get("checkpoint_id", "") or run.get("last_checkpoint_id", ""))
    existing_cases = read_records(decision_store, "list_by_run", run_id, checkpoint_id=checkpoint_id,
                                  record_type="decision", ctx=ctx, permission="can_view_decisions") if run_id else []
    existing = existing_cases[-1] if existing_cases else None
    def team_records(method: str, record_type: str) -> list[dict[str, Any]]:
        return read_records(team_store, method, run_id, checkpoint_id=checkpoint_id,
                            record_type=record_type, ctx=ctx, permission="can_view_team_ops")

    comments = team_records("list_comments", "comment")
    assignments = team_records("list_assignments", "assignment")
    signoffs = team_records("list_signoffs", "signoff")
    handoffs = team_records("list_handoffs", "handoff")
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
    registry = getattr(config, "registry", None)
    decision = preserve_sensitivity_metadata(
        decision, run, checkpoint, existing,
        {"control_meta": registry.export_metadata()} if registry is not None else {},
    )
    require_evidence_permissions(ctx, "can_view_team_ops", "can_view_decisions")
    return {"run_id": run_id, "checkpoint_id": checkpoint_id, "decision": decision}


def build_governance_panel_preview(
    config: Any,
    selected_case: Mapping[str, Any],
    *,
    actor: str,
    role: str,
    ctx: Any = None,
    runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    governance_store = getattr(config, "governance_store", None)
    if governance_store is None:
        return None
    # This view and its retained history contain decision-derived information,
    # even when the current host has removed the optional decision store.
    require_evidence_permissions(ctx, "can_view_team_ops", "can_view_decisions", "can_view_governance")

    selected_case_id = str(selected_case.get("case_id") or "")
    decision_store = getattr(config, "decision_store", None)
    memory_store = getattr(config, "operator_memory_store", None)
    team_store = getattr(config, "team_store", None)

    linked_run_ids = _linked_ids(selected_case, "linked_run_ids")
    linked_checkpoint_ids = set(_linked_ids(selected_case, "linked_checkpoint_ids"))
    linked_incident_ids = set(_linked_ids(selected_case, "linked_incident_ids"))
    linked_decision_ids = set(_linked_ids(selected_case, "linked_decision_ids"))

    # Explicit references are claims about required evidence, unlike an
    # optional source that was intentionally never configured. Resolve them
    # before allowing a passing evaluation or a new saved snapshot.
    run_store = getattr(config, "run_store", None)
    resolved_runs: dict[str, dict[str, Any]] = {}

    def resolve_run(run_id: str) -> None:
        if not isinstance(run_id, str) or not run_id:
            raise EvidenceUnavailable()
        if run_id in resolved_runs:
            return
        if run_store is not None:
            linked_run = read_record(run_store, "load", run_id, record_type="run", ctx=ctx,
                                     permission="can_view_team_ops")
        else:
            if ctx is not None and not has_perm(ctx, "can_view_team_ops"):
                raise EvidenceUnavailable()
            linked_run = next((item for item in runs or [] if isinstance(item, dict) and item.get("run_id") == run_id), None)
            if linked_run is None or not validate_record("run", linked_run)["ok"]:
                raise EvidenceUnavailable()
        if linked_run.get("run_id") != run_id:
            raise EvidenceUnavailable()
        resolved_runs[run_id] = linked_run

    for run_id in linked_run_ids:
        resolve_run(run_id)
    if linked_checkpoint_ids:
        # Checkpoint-only links must resolve too. Available runs are locators;
        # a configured run store is still authoritative over a stale UI copy.
        for candidate in runs or []:
            if not isinstance(candidate, dict) or not isinstance(candidate.get("checkpoints"), list):
                continue
            if any(isinstance(item, dict) and isinstance(item.get("checkpoint_id"), str)
                   and item["checkpoint_id"] in linked_checkpoint_ids
                   for item in candidate["checkpoints"]):
                resolve_run(candidate.get("run_id"))
        resolved_checkpoint_ids = {
            checkpoint.get("checkpoint_id")
            for item in resolved_runs.values() for checkpoint in item.get("checkpoints", [])
            if isinstance(checkpoint, dict) and isinstance(checkpoint.get("checkpoint_id"), str)
            and validate_record("checkpoint", checkpoint)["ok"]
        }
        if not linked_checkpoint_ids.issubset(resolved_checkpoint_ids):
            raise EvidenceUnavailable()

    decisions: list[dict[str, Any]] = []
    signoffs: list[dict[str, Any]] = []
    evidence_scopes = {(run_id, "") for run_id in linked_run_ids}
    for run_id, linked_run in resolved_runs.items():
        if run_id not in linked_run_ids:
            evidence_scopes.update(
                (run_id, checkpoint["checkpoint_id"])
                for checkpoint in linked_run.get("checkpoints", [])
                if isinstance(checkpoint, dict) and isinstance(checkpoint.get("checkpoint_id"), str)
                and checkpoint["checkpoint_id"] in linked_checkpoint_ids
            )
    # Links are additive: an explicitly linked run contributes its complete
    # decision scope; a checkpoint-only link contributes that checkpoint's
    # evidence. Adding a narrower link must never discard an existing blocker.
    for run_id, checkpoint_id in sorted(evidence_scopes):
        filters = {"checkpoint_id": checkpoint_id} if checkpoint_id else {}
        if decision_store is not None:
            decisions.extend(read_records(decision_store, "list_by_run", run_id, **filters,
                                           record_type="decision", ctx=ctx, permission="can_view_decisions"))
        if team_store is not None:
            signoffs.extend(read_records(team_store, "list_signoffs", run_id, **filters,
                                          record_type="signoff", ctx=ctx, permission="can_view_team_ops"))
    if linked_decision_ids:
        for decision_id in sorted(linked_decision_ids):
            decision = read_record(decision_store, "load", decision_id, record_type="decision", ctx=ctx,
                                   permission="can_view_decisions")
            if decision.get("decision_id") != decision_id:
                raise EvidenceUnavailable()
            decisions.append(decision)
    decisions_by_id: dict[str, dict[str, Any]] = {}
    for decision in decisions:
        decision_id = decision.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            raise EvidenceUnavailable()
        decisions_by_id[decision_id] = decision
    decisions = list(decisions_by_id.values())

    if memory_store is not None:
        incidents = read_records(memory_store, "list_incidents", record_type="incident",
                                  ctx=ctx, permission="can_view_team_ops")
    else:
        incidents = []
    if linked_incident_ids:
        if not linked_incident_ids.issubset({item.get("incident_id") for item in incidents}):
            raise EvidenceUnavailable()
    # Apply the same additive run/checkpoint scope as decisions and signoffs.
    # Explicit incident links can add evidence, never hide a scoped blocker.
    incidents = [
        item for item in incidents
        if item.get("incident_id") in linked_incident_ids
        or any(item.get("run_id") == run_id
               and (not checkpoint_id or item.get("checkpoint_id") == checkpoint_id)
               for run_id, checkpoint_id in evidence_scopes)
    ]
    for field, method, record_type, id_field in (
        ("linked_note_ids", "list_notes", "operator_note", "note_id"),
        ("linked_narrative_ids", "list_narratives", "narrative_handoff", "narrative_id"),
    ):
        required_ids = set(_linked_ids(selected_case, field))
        if required_ids:
            records = read_records(memory_store, method, record_type=record_type, ctx=ctx,
                                   permission="can_view_team_ops")
            if not required_ids.issubset({item.get(id_field) for item in records}):
                raise EvidenceUnavailable()

    existing_records = read_records(governance_store, "list_by_case", selected_case_id,
                                    record_type="governance", ctx=ctx, permission="can_view_governance")
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
    require_evidence_permissions(ctx, "can_view_team_ops", "can_view_decisions", "can_view_governance")
    return {
        "selected_case_id": selected_case_id,
        "existing": existing,
        "governance": governance,
    }
